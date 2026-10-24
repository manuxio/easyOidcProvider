/**
 * Phase 4-bis: TOTP seeds read from SQL (src/twofactor/sqlSeedSource.ts), on
 * the fake driver. mysqlIntegration.test.ts runs it against a real MySQL when
 * one is configured; this file holds the contract without a database.
 *
 * The contract of the file header, mirroring the group check on purpose:
 *
 *   1. exactly ONE placeholder, validated at startup as TWO_FACTOR_SQL_QUERY;
 *   2. the username BOUND, never interpolated;
 *   3. the seed is the FIRST COLUMN of the single row, whatever it is called;
 *      zero rows, NULL or blank = not enrolled (undefined).
 *
 * More than one row, a driver error and the deadline are all
 * TwoFactorSeedUnavailable: an outage, never "no seed".
 */
import { describe, expect, it } from 'vitest';

import { createSilentLogger } from '../../src/logger.js';
import { SqlGroupCheckConfigError, type SqlRow } from '../../src/sqlcheck/index.js';
import { createSqlSeedSource, TwoFactorSeedUnavailable } from '../../src/twofactor/index.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';
import { FakeSqlDriver } from '../helpers/fakeSqlDriver.js';

const MARIO = 'mario.rossi';
const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const QUERY = 'SELECT totpsecret FROM users WHERE username = ?';

function sourceFor(rows: SqlRow[] | undefined, options: { timeoutMs?: number } = {}) {
  const driver = new FakeSqlDriver({ rows: new Map(rows === undefined ? [] : [[MARIO, rows]]) });
  const capture = createCapturingLogger();
  const source = createSqlSeedSource({
    query: QUERY,
    driver,
    timeoutMs: options.timeoutMs ?? 2000,
    logger: capture.logger,
  });
  return { driver, capture, source };
}

describe('startup', () => {
  it('is named after the driver', () => {
    expect(sourceFor([]).source.name).toBe('sql:fake');
  });

  it('refuses a query that does not bind the username, naming TWO_FACTOR_SQL_QUERY', () => {
    const build = () => createSqlSeedSource({
      query: 'SELECT totpsecret FROM users',
      driver: new FakeSqlDriver(),
      timeoutMs: 1000,
      logger: createSilentLogger(),
    });
    expect(build).toThrow(SqlGroupCheckConfigError);
    expect(build).toThrow(/^TWO_FACTOR_SQL_QUERY must contain exactly one "\?" placeholder/);
  });

  it('follows the placeholder of the driver it is given', () => {
    expect(() => createSqlSeedSource({
      query: 'SELECT totpsecret FROM users WHERE username = @username',
      driver: new FakeSqlDriver({ name: 'mssql', placeholder: '@username' }),
      timeoutMs: 1000,
      logger: createSilentLogger(),
    })).not.toThrow();
  });
});

describe('the seed', () => {
  it('binds the username and sends the query untouched', async () => {
    const { source, driver } = sourceFor([{ totpsecret: SEED }]);
    const hostile = "' OR 1=1 --";
    await source.lookup(hostile);
    expect(driver.calls).toEqual([{ sql: QUERY, params: { username: hostile } }]);
  });

  it('is the first column of the row, whatever it is called', async () => {
    const { source } = sourceFor([{ anything_at_all: SEED, second: 'ignored' }]);
    await expect(source.lookup(MARIO)).resolves.toBe(SEED);
  });

  it('is trimmed, and read as UTF-8 text from a BLOB', async () => {
    const { source } = sourceFor([{ seed: Buffer.from(`  ${SEED}\n`, 'utf8') }]);
    await expect(source.lookup(MARIO)).resolves.toBe(SEED);
  });

  it('never appears in the log', async () => {
    const { source, capture } = sourceFor([{ seed: SEED }]);
    await source.lookup(MARIO);
    expect(capture.matching('two-factor seed lookup completed')[0]).toMatchObject({
      level: 'debug',
      component: 'two-factor.sql',
      driver: 'fake',
      username: MARIO,
      found: true,
    });
    expect(capture.text()).not.toContain(SEED);
  });
});

describe('not enrolled', () => {
  it('answers undefined for zero rows', async () => {
    const { source, capture } = sourceFor(undefined);
    await expect(source.lookup(MARIO)).resolves.toBeUndefined();
    expect(capture.matching('no row for this user')).toHaveLength(1);
  });

  it.each([
    ['NULL', null],
    ['undefined', undefined],
    ['an empty string', ''],
    ['blanks', '  \t '],
  ])('answers undefined for a first column that is %s', async (_label, value) => {
    const { source } = sourceFor([{ seed: value }]);
    await expect(source.lookup(MARIO)).resolves.toBeUndefined();
  });

  it('answers undefined for a row with no columns', async () => {
    const { source } = sourceFor([{}]);
    await expect(source.lookup(MARIO)).resolves.toBeUndefined();
  });
});

describe('outages are never "no seed"', () => {
  it('refuses two rows for one user instead of choosing a seed', async () => {
    const { source } = sourceFor([{ seed: SEED }, { seed: SEED }]);
    const failure = await source.lookup(MARIO).catch((error: unknown) => error) as TwoFactorSeedUnavailable;
    expect(failure).toBeInstanceOf(TwoFactorSeedUnavailable);
    expect(failure.source).toBe('fake');
    expect(failure.message).toBe(`TWO_FACTOR_SQL_QUERY returned 2 rows for ${MARIO}: it must return at most one`);
  });

  it('wraps a driver error, keeping the message and the cause', async () => {
    const { source, driver } = sourceFor([{ seed: SEED }]);
    const original = new Error('ER_NO_SUCH_TABLE');
    driver.failWith = original;
    const failure = await source.lookup(MARIO).catch((error: unknown) => error) as TwoFactorSeedUnavailable;
    expect(failure).toBeInstanceOf(TwoFactorSeedUnavailable);
    expect(failure.message).toBe('ER_NO_SUCH_TABLE');
    expect(failure.cause).toBe(original);
  });

  it('passes a TwoFactorSeedUnavailable from below through untouched', async () => {
    const { source, driver } = sourceFor([{ seed: SEED }]);
    const original = new TwoFactorSeedUnavailable('fake', 'already wrapped');
    driver.failWith = original;
    await expect(source.lookup(MARIO)).rejects.toBe(original);
  });

  it('honours the deadline when the database never answers', async () => {
    const { source, driver } = sourceFor([{ seed: SEED }], { timeoutMs: 50 });
    driver.hangForever = true;
    const started = Date.now();
    await expect(source.lookup(MARIO)).rejects.toThrow(`two-factor seed lookup timed out after 50 ms for ${MARIO}`);
    expect(Date.now() - started).toBeLessThan(2000);
  });
});

describe('close', () => {
  it('closes the driver', async () => {
    const { source, driver } = sourceFor([]);
    await source.close();
    expect(driver.closed).toBe(true);
  });
});
