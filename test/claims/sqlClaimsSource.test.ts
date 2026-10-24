/**
 * Phase 4-ter: the SQL claims source (src/claims/sqlClaimsSource.ts) and the
 * failure types it throws (src/claims/types.ts), on the cases source.test.ts
 * does not reach.
 *
 *  - startup order: the placeholder rule (shared validateQuery, by parameter
 *    name) runs BEFORE the SELECT-list analysis;
 *  - the values a driver can hand back that JSON cannot carry (Date, bigint,
 *    a JSON column) and the ones that pass through untouched;
 *  - the runtime half of the blacklist is case-insensitive, the declaration
 *    is not, and a declared column that does not come back is simply absent;
 *  - the late-settlement line of an abandoned lookup, and the error wrapping;
 *  - name, claim names and close.
 */
import { describe, expect, it } from 'vitest';

import {
  CLAIMS_QUERY_PARAMETER,
  createSqlClaimsSource,
  EXTRA_CLAIMS_REASONS,
  ExtraClaimsConfigError,
  ExtraClaimsUnavailable,
  ExtraClaimsUserNotFound,
} from '../../src/claims/index.js';
import { createSilentLogger } from '../../src/logger.js';
import { SqlGroupCheckConfigError, type SqlQueryParams, type SqlRow } from '../../src/sqlcheck/index.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';
import { CUSTOMER_CLAIMS_QUERY } from '../helpers/claimsQuery.js';
import { FakeSqlDriver } from '../helpers/fakeSqlDriver.js';

const MARIO = 'mario.rossi';
const QUERY = 'SELECT ID AS remoteId, nome AS name, created AS since, prefs AS prefs, big AS big, ok AS ok FROM t WHERE userid = ?';

function sourceFor(rows: SqlRow[], query = QUERY) {
  const driver = new FakeSqlDriver({ rows: new Map([[MARIO, rows]]) });
  const capture = createCapturingLogger();
  const source = createSqlClaimsSource({ query, driver, timeoutMs: 2000, logger: capture.logger });
  return { driver, capture, source };
}

/**
 * A FakeSqlDriver whose answer the test releases by hand, after the deadline
 * has already fired: the instrument for the late-settlement log line.
 */
class DeferredSqlDriver extends FakeSqlDriver {
  release!: (rows: SqlRow[]) => void;
  fail!: (error: unknown) => void;

  override async query(sql: string, params: SqlQueryParams): Promise<SqlRow[]> {
    this.calls.push({ sql, params });
    return new Promise<SqlRow[]>((resolve, reject) => {
      this.release = resolve;
      this.fail = reject;
    });
  }
}

/** Lets the abandoned promise's handlers run. */
const settle = () => new Promise<void>((resolve) => { setImmediate(resolve); });

describe('startup', () => {
  it('names the source after the driver and declares the claims in SELECT-list order', () => {
    const { source } = sourceFor([]);
    expect(source.name).toBe('sql:fake');
    expect(source.claimNames).toEqual(['remoteId', 'name', 'since', 'prefs', 'big', 'ok']);
  });

  it('checks the placeholder before the SELECT list, naming CLAIMS_SQL_QUERY', () => {
    // Both rules are broken here; the placeholder one is the first to speak.
    const build = () => createSqlClaimsSource({
      query: 'SELECT * FROM t',
      driver: new FakeSqlDriver(),
      timeoutMs: 1000,
      logger: createSilentLogger(),
    });
    expect(build).toThrow(SqlGroupCheckConfigError);
    expect(build).toThrow(new RegExp(`^${CLAIMS_QUERY_PARAMETER} must contain exactly one "\\?" placeholder`));
  });

  it('runs the SELECT-list analysis once the placeholder is right', () => {
    expect(() => createSqlClaimsSource({
      query: 'SELECT * FROM t WHERE userid = ?',
      driver: new FakeSqlDriver(),
      timeoutMs: 1000,
      logger: createSilentLogger(),
    })).toThrow(ExtraClaimsConfigError);
  });

  it('follows the placeholder of the driver it is given', () => {
    const driver = new FakeSqlDriver({ name: 'mssql', placeholder: '@username' });
    const source = createSqlClaimsSource({
      query: 'SELECT ID AS remoteId FROM t WHERE userid = @username',
      driver,
      timeoutMs: 1000,
      logger: createSilentLogger(),
    });
    expect(source.name).toBe('sql:mssql');
    expect(source.claimNames).toEqual(['remoteId']);
  });
});

describe('the values become JSON', () => {
  it('passes numbers, strings and booleans through untouched', async () => {
    const { source } = sourceFor([{ remoteId: 0, name: '', ok: false }]);
    // 0, '' and false are values, not NULL: they stay in the token.
    await expect(source.lookup(MARIO)).resolves.toEqual({ remoteId: 0, name: '', ok: false });
  });

  it('writes a DATETIME as an ISO string', async () => {
    const { source } = sourceFor([{ remoteId: 1, since: new Date('2026-10-23T08:30:00.000Z') }]);
    await expect(source.lookup(MARIO)).resolves.toEqual({ remoteId: 1, since: '2026-10-23T08:30:00.000Z' });
  });

  it('writes a BIGINT as its decimal string, without losing digits', async () => {
    const { source } = sourceFor([{ remoteId: 1, big: 9_007_199_254_740_993n }]);
    await expect(source.lookup(MARIO)).resolves.toEqual({ remoteId: 1, big: '9007199254740993' });
  });

  it('copies a JSON column as plain data, dates inside it turned into strings', async () => {
    const prefs = { theme: 'dark', seen: new Date('2026-01-02T03:04:05.000Z'), list: [1, 'a', null] };
    const { source } = sourceFor([{ remoteId: 1, prefs }]);
    const claims = await source.lookup(MARIO);
    expect(claims.prefs).toEqual({ theme: 'dark', seen: '2026-01-02T03:04:05.000Z', list: [1, 'a', null] });
    // A copy, not the driver's own object.
    expect(claims.prefs).not.toBe(prefs);
  });

  it('omits an undefined column exactly like a NULL one', async () => {
    const { source } = sourceFor([{ remoteId: 1, name: undefined }]);
    const claims = await source.lookup(MARIO);
    expect(claims).toEqual({ remoteId: 1 });
    expect('name' in claims).toBe(false);
  });

  it('leaves out a declared claim the row does not carry, without refusing', async () => {
    // Only an EXTRA column is refused; a missing one is the same as a NULL.
    const { source } = sourceFor([{ remoteId: 1 }]);
    await expect(source.lookup(MARIO)).resolves.toEqual({ remoteId: 1 });
  });
});

describe('the runtime half of the blacklist', () => {
  it('recognises a reserved column whatever its case, before the undeclared check', async () => {
    const { source, capture } = sourceFor([{ remoteId: 1, SUB: 'someone.else' }], CUSTOMER_CLAIMS_QUERY);
    const failure = await source.lookup(MARIO).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ExtraClaimsUnavailable);
    expect((failure as ExtraClaimsUnavailable).reason).toBe(EXTRA_CLAIMS_REASONS.reservedName);
    expect((failure as ExtraClaimsUnavailable).source).toBe('fake');
    expect((failure as Error).message).toContain('returned the column "SUB", which is a reserved claim name');
    expect(capture.withReason(EXTRA_CLAIMS_REASONS.undeclaredColumn)).toHaveLength(0);
  });

  it('compares the declaration case-sensitively: a column renamed by case is undeclared', async () => {
    const { source, capture } = sourceFor([{ remoteid: 1, name: 'Mario Rossi' }], CUSTOMER_CLAIMS_QUERY);
    const failure = await source.lookup(MARIO).catch((error: unknown) => error);
    expect((failure as ExtraClaimsUnavailable).reason).toBe(EXTRA_CLAIMS_REASONS.undeclaredColumn);
    expect((failure as Error).message).toContain('(declared: remoteId, name)');
    const [line] = capture.withReason(EXTRA_CLAIMS_REASONS.undeclaredColumn);
    expect(line!.declared).toEqual(['remoteId', 'name']);
    expect(line!.level).toBe('error');
  });

  it('refuses on the first bad column, before shaping the rest of the row', async () => {
    const { source } = sourceFor([{ extra: 'x', remoteId: 1 }], CUSTOMER_CLAIMS_QUERY);
    await expect(source.lookup(MARIO)).rejects.toMatchObject({
      reason: EXTRA_CLAIMS_REASONS.undeclaredColumn,
    });
  });
});

describe('errors and the deadline', () => {
  it('passes an ExtraClaimsUnavailable from below through untouched', async () => {
    const { source, driver } = sourceFor([]);
    const original = new ExtraClaimsUnavailable('fake', EXTRA_CLAIMS_REASONS.unavailable, 'already wrapped');
    driver.failWith = original;
    await expect(source.lookup(MARIO)).rejects.toBe(original);
  });

  it('wraps any other error, keeping it as the cause', async () => {
    const { source, driver } = sourceFor([]);
    const original = new Error('ER_PARSE_ERROR near FROM');
    driver.failWith = original;
    const failure = await source.lookup(MARIO).catch((error: unknown) => error) as ExtraClaimsUnavailable;
    expect(failure).toBeInstanceOf(ExtraClaimsUnavailable);
    expect(failure.name).toBe('ExtraClaimsUnavailable');
    expect(failure.message).toBe('ER_PARSE_ERROR near FROM');
    expect(failure.cause).toBe(original);
    expect(failure.source).toBe('fake');
  });

  it('logs the eventual fate of a lookup abandoned by the deadline: fulfilled', async () => {
    const driver = new DeferredSqlDriver();
    const capture = createCapturingLogger();
    const source = createSqlClaimsSource({ query: QUERY, driver, timeoutMs: 20, logger: capture.logger });

    await expect(source.lookup(MARIO)).rejects.toThrow(/timed out after 20 ms for mario\.rossi/);
    expect(capture.matching('has now settled')).toHaveLength(0);

    driver.release([{ remoteId: 1 }]);
    await settle();
    const [line] = capture.matching('has now settled');
    expect(line).toMatchObject({ level: 'warn', username: MARIO, lateOutcome: 'fulfilled' });
    expect(typeof line!.lateElapsedMs).toBe('number');
    expect(line).not.toHaveProperty('err');
  });

  it('logs the eventual fate of a lookup abandoned by the deadline: rejected, with the message', async () => {
    const driver = new DeferredSqlDriver();
    const capture = createCapturingLogger();
    const source = createSqlClaimsSource({ query: QUERY, driver, timeoutMs: 20, logger: capture.logger });

    await expect(source.lookup(MARIO)).rejects.toBeInstanceOf(ExtraClaimsUnavailable);
    driver.fail('socket hang up');
    await settle();
    const [line] = capture.matching('has now settled');
    expect(line).toMatchObject({ lateOutcome: 'rejected', err: { message: 'socket hang up' } });
  });

  it('logs the timeout itself as the fail-closed line, with the deadline', async () => {
    const driver = new FakeSqlDriver();
    driver.hangForever = true;
    const capture = createCapturingLogger();
    const source = createSqlClaimsSource({ query: QUERY, driver, timeoutMs: 20, logger: capture.logger });

    await source.lookup(MARIO).catch(() => undefined);
    const [line] = capture.withReason(EXTRA_CLAIMS_REASONS.unavailable);
    expect(line).toMatchObject({ level: 'error', username: MARIO, timeoutMs: 20, driver: 'fake' });
    expect(line!.component).toBe('extra-claims.sql');
  });
});

describe('the other outcomes, as types', () => {
  it('names the user in ExtraClaimsUserNotFound and the query in its message', async () => {
    const { source } = sourceFor([]);
    const failure = await source.lookup(MARIO).catch((error: unknown) => error) as ExtraClaimsUserNotFound;
    expect(failure.name).toBe('ExtraClaimsUserNotFound');
    expect(failure.username).toBe(MARIO);
    expect(failure.message).toBe(`${CLAIMS_QUERY_PARAMETER} returned no row for ${MARIO}`);
  });

  it('says how many rows came back when the answer is ambiguous', async () => {
    const { source } = sourceFor([{ remoteId: 1 }, { remoteId: 2 }, { remoteId: 3 }]);
    await expect(source.lookup(MARIO)).rejects.toThrow(
      `${CLAIMS_QUERY_PARAMETER} returned 3 rows for ${MARIO}: it must return exactly one`,
    );
  });

  it('keeps the reason vocabulary stable: these strings are what the logs are searched for', () => {
    expect(Object.values(EXTRA_CLAIMS_REASONS).sort()).toEqual([
      'claims_ambiguous_rows',
      'claims_reserved_name',
      'claims_source_unavailable',
      'claims_undeclared_column',
      'claims_user_not_found',
    ]);
  });

  it('logs a successful read at debug, naming the claims and not their values', async () => {
    const { source, capture } = sourceFor([{ remoteId: 4217, name: 'Mario Rossi' }]);
    await source.lookup(MARIO);
    const [line] = capture.matching('extra claims read');
    expect(line).toMatchObject({ level: 'debug', username: MARIO, claims: ['remoteId', 'name'] });
    expect(JSON.stringify(line)).not.toContain('Mario Rossi');
  });
});

describe('close', () => {
  it('closes the driver it was given', async () => {
    const { source, driver } = sourceFor([]);
    await source.close();
    expect(driver.closed).toBe(true);
  });
});
