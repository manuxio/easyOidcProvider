/**
 * The transport retry of the mysql2 driver, against a mocked mysql2.
 *
 * The contract under test:
 *
 *   - every attempt on the wire is capped at half the caller's deadline;
 *   - a TRANSPORT error (connection reset, timeout, dead socket) gets exactly
 *     one retry, on a FRESH pool — never the same possibly-poisoned socket;
 *   - a SEMANTIC error (broken SQL, no result set) is deterministic and is
 *     never retried;
 *   - the optional keepalive pings through the pool and swaps it when the
 *     path is down, so the next login starts clean.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { withDeadline, type LateSettlement } from '../../src/deadline.js';
import { createSilentLogger } from '../../src/logger.js';
import {
  attemptTimeoutMs,
  createMysqlDriver,
} from '../../src/sqlcheck/mysql.js';
import { SqlGroupCheckUnavailable } from '../../src/sqlcheck/types.js';

interface QueryCall { sql: string; timeout?: number; values: unknown[] }

/**
 * One scripted pool: each query() consumes the next behaviour in the list.
 * An Error is thrown; anything else is returned as the rows value verbatim
 * (an array reads as a result set, an object as a ResultSetHeader).
 */
function scriptedMysql(behaviours: unknown[]) {
  const calls: QueryCall[] = [];
  const pools: Array<{ ended: boolean }> = [];
  const createPool = vi.fn(() => {
    const state = { ended: false };
    pools.push(state);
    return {
      query: vi.fn(async (sqlOrOptions: string | { sql: string; timeout?: number }, values: unknown[]) => {
        const options = typeof sqlOrOptions === 'string' ? { sql: sqlOrOptions } : sqlOrOptions;
        calls.push({ sql: options.sql, ...(options.timeout !== undefined ? { timeout: options.timeout } : {}), values });
        const next = behaviours.shift();
        if (next === undefined) throw new Error('scripted mysql exhausted');
        if (next instanceof Error) throw next;
        return [next, undefined];
      }),
      end: vi.fn(async () => { state.ended = true; }),
    };
  });
  return { createPool, calls, pools };
}

function transportError(code: string): Error {
  const error = new Error(`scripted ${code}`) as NodeJS.ErrnoException;
  error.code = code;
  return error;
}

const ROW = [{ ok: 1 }];

let script: ReturnType<typeof scriptedMysql>;

vi.mock('mysql2/promise', () => ({
  get createPool() { return script.createPool; },
}));

describe('mysql driver transport retry', () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it('caps every attempt at half the deadline', async () => {
    script = scriptedMysql([[...ROW]]);
    const driver = createMysqlDriver({ connectionString: 'mysql://u:p@h/db', timeoutMs: 5000 });
    await driver.query('SELECT 1 FROM t WHERE u = ?', { username: 'x' });
    expect(script.calls[0]?.timeout).toBe(2500);
    expect(attemptTimeoutMs(5000)).toBe(2500);
    // A tiny deadline still leaves a usable attempt window.
    expect(attemptTimeoutMs(300)).toBe(250);
    await driver.close();
  });

  it('retries a transport error once, on a fresh pool, and succeeds', async () => {
    script = scriptedMysql([transportError('ECONNRESET'), [...ROW]]);
    const driver = createMysqlDriver({
      connectionString: 'mysql://u:p@h/db',
      timeoutMs: 5000,
      logger: createSilentLogger(),
    });
    const rows = await driver.query('SELECT 1 FROM t WHERE u = ?', { username: 'x' });
    expect(rows).toEqual(ROW);
    // Two pools: the poisoned one was swapped out, not reused.
    expect(script.createPool).toHaveBeenCalledTimes(2);
    expect(script.pools[0]?.ended).toBe(true);
    await driver.close();
  });

  it('fails unavailable when the transport error survives the retry', async () => {
    script = scriptedMysql([transportError('ETIMEDOUT'), transportError('ETIMEDOUT')]);
    const driver = createMysqlDriver({ connectionString: 'mysql://u:p@h/db', timeoutMs: 5000 });
    await expect(driver.query('SELECT 1 FROM t WHERE u = ?', { username: 'x' }))
      .rejects.toBeInstanceOf(SqlGroupCheckUnavailable);
    expect(script.createPool).toHaveBeenCalledTimes(2);
    await driver.close();
  });

  it('never retries a semantic error', async () => {
    const semantic = new Error('Table does not exist') as NodeJS.ErrnoException;
    semantic.code = 'ER_NO_SUCH_TABLE';
    script = scriptedMysql([semantic]);
    const driver = createMysqlDriver({ connectionString: 'mysql://u:p@h/db', timeoutMs: 5000 });
    await expect(driver.query('SELECT 1 FROM t WHERE u = ?', { username: 'x' }))
      .rejects.toBeInstanceOf(SqlGroupCheckUnavailable);
    expect(script.createPool).toHaveBeenCalledTimes(1);
    expect(script.calls).toHaveLength(1);
    await driver.close();
  });

  it('never retries a non-SELECT result either', async () => {
    script = scriptedMysql([{ affectedRows: 1 }]);
    const driver = createMysqlDriver({ connectionString: 'mysql://u:p@h/db', timeoutMs: 5000 });
    await expect(driver.query('UPDATE t SET a = 1', { username: 'x' }))
      .rejects.toThrow(/no result set/);
    expect(script.calls).toHaveLength(1);
    await driver.close();
  });

  it('keepalive pings through the pool and swaps it on failure', async () => {
    script = scriptedMysql([[...ROW], transportError('ETIMEDOUT'), [...ROW]]);
    const driver = createMysqlDriver({
      connectionString: 'mysql://u:p@h/db',
      timeoutMs: 5000,
      logger: createSilentLogger(),
      keepaliveIntervalMs: 45_000,
    });

    await vi.advanceTimersByTimeAsync(45_000);
    expect(script.calls[0]?.sql).toBe('SELECT 1');

    // Tick 2 fails: the pool must be swapped so tick 3 (and any login in
    // between) starts on a fresh one.
    await vi.advanceTimersByTimeAsync(45_000);
    expect(script.pools[0]?.ended).toBe(true);

    await vi.advanceTimersByTimeAsync(45_000);
    expect(script.createPool).toHaveBeenCalledTimes(2);
    expect(script.calls).toHaveLength(3);

    await driver.close();
  });
});

describe('withDeadline late settlement', () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it('reports the abandoned promise settling after the deadline fired', async () => {
    const late: LateSettlement[] = [];
    let rejectWork!: (error: Error) => void;
    const work = new Promise<never>((_resolve, reject) => { rejectWork = reject; });

    const racing = withDeadline(work, 1000, () => new Error('deadline'), (s) => late.push(s));
    const rejected = expect(racing).rejects.toThrow('deadline');
    await vi.advanceTimersByTimeAsync(1000);
    await rejected;
    expect(late).toHaveLength(0);

    await vi.advanceTimersByTimeAsync(2000);
    rejectWork(Object.assign(new Error('late failure'), { code: 'ETIMEDOUT' }));
    await vi.runAllTicks();
    await Promise.resolve();

    expect(late).toHaveLength(1);
    expect(late[0]?.outcome).toBe('rejected');
    expect(late[0]?.elapsedMs).toBeGreaterThanOrEqual(3000);
    expect((late[0]?.error as Error).message).toBe('late failure');
  });

  it('stays silent when the work wins the race', async () => {
    const late: LateSettlement[] = [];
    await expect(
      withDeadline(Promise.resolve('fast'), 1000, () => new Error('deadline'), (s) => late.push(s)),
    ).resolves.toBe('fast');
    await vi.runAllTicks();
    expect(late).toHaveLength(0);
  });
});
