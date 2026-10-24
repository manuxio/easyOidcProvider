/**
 * The SQL Server driver (src/sqlcheck/mssql.ts) against a mocked `mssql`
 * library: no SQL Server is reached. mssqlIntegration.test.ts runs the same
 * driver against a real one, when MSSQL_TEST_URL is set.
 *
 * The contract, from the driver's header and the SqlDriver interface:
 *
 *  - the library is loaded and the pool built LAZILY, on the first query, and
 *    the pool is reused afterwards;
 *  - the username is a NAMED bind parameter (`@username`), never in the text;
 *  - a pool that cannot be created is SqlGroupCheckUnavailable, and the next
 *    query tries again instead of reusing the failure;
 *  - a query error, or a statement that returns no recordset, is
 *    SqlGroupCheckUnavailable — an outage, never "no row";
 *  - close is safe with nothing open, swallows a failing close, and the next
 *    query opens a fresh pool.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { createMssqlDriver, MSSQL_PLACEHOLDER } from '../../src/sqlcheck/mssql.js';
import { SqlGroupCheckUnavailable } from '../../src/sqlcheck/types.js';

interface PoolRecord {
  connectionString: string;
  connects: number;
  closes: number;
  inputs: Array<[string, unknown]>;
  queries: string[];
}

interface MssqlScript {
  pools: PoolRecord[];
  /** Errors thrown by connect(), consumed one per pool. */
  connectErrors: Error[];
  /** Results of query(), consumed one per query: an Error is thrown, anything else returned. */
  results: unknown[];
  closeError?: Error;
}

let script: MssqlScript;

vi.mock('mssql', () => ({
  ConnectionPool: class {
    readonly #record: PoolRecord;

    constructor(connectionString: string) {
      this.#record = { connectionString, connects: 0, closes: 0, inputs: [], queries: [] };
      script.pools.push(this.#record);
    }

    async connect() {
      this.#record.connects += 1;
      const error = script.connectErrors.shift();
      if (error) throw error;
      return this;
    }

    request() {
      const record = this.#record;
      const request = {
        input(name: string, value: unknown) {
          record.inputs.push([name, value]);
          return request;
        },
        async query(sql: string) {
          record.queries.push(sql);
          const next = script.results.shift();
          if (next instanceof Error) throw next;
          return next;
        },
      };
      return request;
    }

    async close() {
      this.#record.closes += 1;
      if (script.closeError) throw script.closeError;
    }
  },
}));

const CONNECTION = 'mssql://svc:pw@sql.example.local/backoffice';
const QUERY = 'SELECT 1 FROM authorized_users WHERE username = @username';

function driver() {
  return createMssqlDriver({ connectionString: CONNECTION, timeoutMs: 5000 });
}

function coded(message: string, code: string): Error {
  return Object.assign(new Error(message), { code });
}

beforeEach(() => {
  script = { pools: [], connectErrors: [], results: [] };
});

describe('identity and laziness', () => {
  it('is mssql, binding @username', () => {
    const created = driver();
    expect(created.name).toBe('mssql');
    expect(created.placeholder).toBe(MSSQL_PLACEHOLDER);
    expect(MSSQL_PLACEHOLDER).toBe('@username');
  });

  it('builds no pool until the first query', () => {
    driver();
    expect(script.pools).toHaveLength(0);
  });

  it('builds one pool on the connection string and reuses it', async () => {
    const created = driver();
    script.results.push({ recordset: [{ ok: 1 }] }, { recordset: [] });

    await expect(created.query(QUERY, { username: 'mario.rossi' })).resolves.toEqual([{ ok: 1 }]);
    await expect(created.query(QUERY, { username: 'luigi.verdi' })).resolves.toEqual([]);

    expect(script.pools).toHaveLength(1);
    expect(script.pools[0]!.connectionString).toBe(CONNECTION);
    expect(script.pools[0]!.connects).toBe(1);
  });
});

describe('binding', () => {
  it('sends the SQL verbatim and the username as the named parameter', async () => {
    const created = driver();
    const hostile = "' OR 1=1 --";
    script.results.push({ recordset: [] });

    await created.query(QUERY, { username: hostile });
    const [pool] = script.pools;
    expect(pool!.queries).toEqual([QUERY]);
    expect(pool!.inputs).toEqual([['username', hostile]]);
  });
});

describe('failures are outages, never answers', () => {
  it('reports a pool that cannot connect, with the error code, and keeps the cause', async () => {
    const created = driver();
    const original = coded('Failed to connect to sql.example.local:1433', 'ESOCKET');
    script.connectErrors.push(original);

    const failure = await created.query(QUERY, { username: 'mario.rossi' }).catch((error: unknown) => error) as SqlGroupCheckUnavailable;
    expect(failure).toBeInstanceOf(SqlGroupCheckUnavailable);
    expect(failure.driver).toBe('mssql');
    expect(failure.message).toBe('mssql pool could not be created: ESOCKET Failed to connect to sql.example.local:1433');
    expect(failure.cause).toBe(original);
  });

  it('tries a fresh pool on the next query after a failed connect', async () => {
    const created = driver();
    script.connectErrors.push(new Error('login failed'));
    script.results.push({ recordset: [{ ok: 1 }] });

    await expect(created.query(QUERY, { username: 'mario.rossi' })).rejects.toBeInstanceOf(SqlGroupCheckUnavailable);
    await expect(created.query(QUERY, { username: 'mario.rossi' })).resolves.toEqual([{ ok: 1 }]);
    expect(script.pools).toHaveLength(2);
  });

  it('reports a query error, with the code when there is one', async () => {
    const created = driver();
    const original = coded("Invalid object name 'authorized_users'.", 'EREQUEST');
    script.results.push(original);

    const failure = await created.query(QUERY, { username: 'mario.rossi' }).catch((error: unknown) => error) as SqlGroupCheckUnavailable;
    expect(failure).toBeInstanceOf(SqlGroupCheckUnavailable);
    expect(failure.message).toBe("mssql query failed: EREQUEST Invalid object name 'authorized_users'.");
    expect(failure.cause).toBe(original);
  });

  it('reports a query error without a code by its message alone', async () => {
    const created = driver();
    script.results.push(new Error('Timeout: Request failed to complete in 5000ms'));
    await expect(created.query(QUERY, { username: 'mario.rossi' }))
      .rejects.toThrow('mssql query failed: Timeout: Request failed to complete in 5000ms');
  });

  it('refuses a statement that returns no recordset: it must be a SELECT', async () => {
    const created = driver();
    script.results.push({ rowsAffected: [1] });
    // NOTE: the message names SQL_GROUP_QUERY whichever feature ran the query
    // (two-factor seed, extra claims and credentials use this driver too);
    // expected per docs: the parameter of the feature; current code may differ.
    await expect(created.query(QUERY, { username: 'mario.rossi' }))
      .rejects.toThrow(/returned no recordset: it must be a SELECT/);
  });

  it('refuses a missing result just the same', async () => {
    const created = driver();
    script.results.push(undefined);
    await expect(created.query(QUERY, { username: 'mario.rossi' }))
      .rejects.toBeInstanceOf(SqlGroupCheckUnavailable);
  });

  it('keeps the pool after a query error: only the connect failure drops it', async () => {
    const created = driver();
    script.results.push(new Error('deadlock victim'), { recordset: [] });
    await created.query(QUERY, { username: 'mario.rossi' }).catch(() => undefined);
    await created.query(QUERY, { username: 'mario.rossi' });
    expect(script.pools).toHaveLength(1);
  });
});

describe('close', () => {
  it('does nothing when no pool was ever opened', async () => {
    await expect(driver().close()).resolves.toBeUndefined();
    expect(script.pools).toHaveLength(0);
  });

  it('closes the open pool, and the next query opens a new one', async () => {
    const created = driver();
    script.results.push({ recordset: [] }, { recordset: [] });
    await created.query(QUERY, { username: 'mario.rossi' });

    await created.close();
    expect(script.pools[0]!.closes).toBe(1);

    await created.query(QUERY, { username: 'mario.rossi' });
    expect(script.pools).toHaveLength(2);
  });

  it('is safe to call twice', async () => {
    const created = driver();
    script.results.push({ recordset: [] });
    await created.query(QUERY, { username: 'mario.rossi' });
    await created.close();
    await created.close();
    expect(script.pools[0]!.closes).toBe(1);
  });

  it('swallows a pool that fails to close', async () => {
    const created = driver();
    script.results.push({ recordset: [] });
    await created.query(QUERY, { username: 'mario.rossi' });
    script.closeError = new Error('already closed');
    await expect(created.close()).resolves.toBeUndefined();
  });
});
