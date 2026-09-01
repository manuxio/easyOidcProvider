/**
 * Phase 4-ter, second half of the enforcement: what the source does with the
 * row that actually comes back.
 *
 * The driver is fake, so every scenario is a shape rather than a database
 * state: one row, no row, two rows, a NULL, a column nobody declared, a column
 * named like a registered claim, a connection that throws, a query that hangs
 * past the deadline. `mysqlIntegration.test.ts` runs the same contract against
 * a real MySQL, which is the only thing that proves the driver.
 */
import { describe, expect, it } from 'vitest';

import {
  createSqlClaimsSource,
  EXTRA_CLAIMS_REASONS,
  ExtraClaimsUnavailable,
  ExtraClaimsUserNotFound,
} from '../../src/claims/index.js';
import { createSilentLogger } from '../../src/logger.js';
import type { SqlRow } from '../../src/sqlcheck/index.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';
import { CUSTOMER_CLAIMS_QUERY } from '../helpers/claimsQuery.js';
import { FakeSqlDriver } from '../helpers/fakeSqlDriver.js';

const MARIO = 'mario.rossi';

function sourceFor(rows: SqlRow[] | undefined, options: { timeoutMs?: number } = {}) {
  const driver = new FakeSqlDriver({
    rows: new Map(rows === undefined ? [] : [[MARIO, rows]]),
  });
  const capture = createCapturingLogger();
  const source = createSqlClaimsSource({
    query: CUSTOMER_CLAIMS_QUERY,
    driver,
    timeoutMs: options.timeoutMs ?? 2000,
    logger: capture.logger,
  });
  return { driver, capture, source };
}

describe('the row becomes the claims', () => {
  it('uses the column names as claim names and the values as they came', async () => {
    const { source, driver } = sourceFor([{ remoteId: 4217, name: 'Mario Rossi' }]);
    await expect(source.lookup(MARIO)).resolves.toEqual({ remoteId: 4217, name: 'Mario Rossi' });

    // One query, the username bound, the text untouched.
    expect(driver.calls).toHaveLength(1);
    expect(driver.calls[0]!.sql).toBe(CUSTOMER_CLAIMS_QUERY);
    expect(driver.calls[0]!.params).toEqual({ username: MARIO });
  });

  it('omits a NULL column entirely — not null, not an empty string', async () => {
    const { source } = sourceFor([{ remoteId: 4217, name: null }]);
    const claims = await source.lookup(MARIO);
    expect(claims).toEqual({ remoteId: 4217 });
    expect('name' in claims).toBe(false);
  });

  it('omits every column when they are all NULL, and still calls it a row', async () => {
    const { source } = sourceFor([{ remoteId: null, name: null }]);
    await expect(source.lookup(MARIO)).resolves.toEqual({});
  });

  it('reads a BLOB column as text, the way the driver hands it over', async () => {
    const { source } = sourceFor([{ remoteId: 1, name: Buffer.from('Mario Rossi', 'utf8') }]);
    await expect(source.lookup(MARIO)).resolves.toEqual({ remoteId: 1, name: 'Mario Rossi' });
  });
});

describe('zero rows is a refusal, not an empty claim set', () => {
  it('throws ExtraClaimsUserNotFound with the stable reason', async () => {
    const { source, capture } = sourceFor([]);
    const failure = await source.lookup(MARIO).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ExtraClaimsUserNotFound);
    expect((failure as ExtraClaimsUserNotFound).reason)
      .toBe(EXTRA_CLAIMS_REASONS.userNotFound);
    expect(capture.withReason(EXTRA_CLAIMS_REASONS.userNotFound)).toHaveLength(1);
  });

  it('never degrades into "no extra claims"', async () => {
    const { source } = sourceFor([]);
    await expect(source.lookup(MARIO)).rejects.not.toBeInstanceOf(ExtraClaimsUnavailable);
  });
});

describe('anything the source cannot interpret fails closed', () => {
  it('refuses two rows instead of choosing an identity', async () => {
    const { source, capture } = sourceFor([{ remoteId: 1, name: 'A' }, { remoteId: 2, name: 'B' }]);
    const failure = await source.lookup(MARIO).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ExtraClaimsUnavailable);
    expect((failure as ExtraClaimsUnavailable).reason)
      .toBe(EXTRA_CLAIMS_REASONS.ambiguousRows);
    expect(capture.withReason(EXTRA_CLAIMS_REASONS.ambiguousRows)).toHaveLength(1);
  });

  it('refuses a reserved column name that only the database could produce', async () => {
    // The startup analysis of CLAIMS_SQL_QUERY saw `remoteId` and `name`; a
    // `sub` here means the real result set does not match the query text.
    const { source, capture } = sourceFor([{ remoteId: 1, sub: 'someone.else' }]);
    const failure = await source.lookup(MARIO).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ExtraClaimsUnavailable);
    expect((failure as ExtraClaimsUnavailable).reason)
      .toBe(EXTRA_CLAIMS_REASONS.reservedName);
    const [line] = capture.withReason(EXTRA_CLAIMS_REASONS.reservedName);
    expect(line).toBeDefined();
    expect(line!.column).toBe('sub');
    expect(line!.level).toBe('error');
  });

  it('refuses an undeclared column rather than dropping the claim in silence', async () => {
    const { source, capture } = sourceFor([{ remoteId: 1, name: 'Mario Rossi', extra: 'x' }]);
    const failure = await source.lookup(MARIO).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ExtraClaimsUnavailable);
    expect((failure as ExtraClaimsUnavailable).reason)
      .toBe(EXTRA_CLAIMS_REASONS.undeclaredColumn);
    expect(capture.withReason(EXTRA_CLAIMS_REASONS.undeclaredColumn)[0]!.column).toBe('extra');
  });

  it('turns a driver error into ExtraClaimsUnavailable and logs it loudly', async () => {
    const { source, driver, capture } = sourceFor([{ remoteId: 1, name: 'x' }]);
    driver.failWith = new Error('ECONNREFUSED connect 127.0.0.1:3306');

    const failure = await source.lookup(MARIO).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ExtraClaimsUnavailable);
    expect((failure as ExtraClaimsUnavailable).reason).toBe(EXTRA_CLAIMS_REASONS.unavailable);
    const [line] = capture.withReason(EXTRA_CLAIMS_REASONS.unavailable);
    expect(line!.level).toBe('error');
    expect(String(line!.msg)).toMatch(/chain left intact/);
  });

  it('honours the SQL_TIMEOUT_MS deadline when the database never answers', async () => {
    const { source, driver } = sourceFor([{ remoteId: 1, name: 'x' }], { timeoutMs: 80 });
    driver.hangForever = true;

    const started = Date.now();
    const failure = await source.lookup(MARIO).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ExtraClaimsUnavailable);
    expect((failure as Error).message).toMatch(/timed out after 80 ms/);
    expect(Date.now() - started).toBeLessThan(2000);
  });
});
