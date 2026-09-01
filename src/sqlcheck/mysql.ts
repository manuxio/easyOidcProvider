/**
 * MySQL / MariaDB driver, on `mysql2`. This is the engine the current customer
 * runs.
 *
 * Deliberate choices:
 *
 *  - `mysql2` is loaded with a dynamic import on the first query, not at module
 *    load. With every SQL feature off the driver is never constructed at all,
 *    but even when it is constructed the pool — and the library itself — only
 *    materialize when a login (or the first keepalive tick) needs an answer.
 *  - the pool is small. This gate runs once per login and once per refresh, it
 *    is not a data path; a large pool would only widen the blast radius of a
 *    slow database.
 *  - every attempt on the wire (connect AND query) is capped at HALF the
 *    caller's deadline, so a transport failure surfaces as the driver's own
 *    error — with its code — while there is still time for ONE retry on a
 *    fresh pool within the same deadline. Without the cap, a socket silently
 *    killed by a middlebox eats the whole deadline and the caller's timeout
 *    fires with no diagnosis and no second chance. (Incident of 2026-09-01:
 *    one claims lookup hung for the full 5 s and became a rejected SSO login;
 *    the very next connection answered in 23 ms.)
 *  - the retry is TRANSPORT-ONLY. A semantic answer — zero rows, a broken
 *    query, a result that is not a result set — is deterministic and is never
 *    retried.
 */
import type { SqlDriver, SqlDriverOptions, SqlQueryParams, SqlRow } from './types.js';
import { SqlGroupCheckUnavailable } from './types.js';

/** mysql2 binds positionally. One placeholder, one value. */
export const MYSQL_PLACEHOLDER = '?';

const POOL_SIZE = 2;

/** Longest a single connect or query attempt may take, leaving room to retry. */
export function attemptTimeoutMs(timeoutMs: number): number {
  return Math.max(250, Math.min(2500, Math.floor(timeoutMs / 2)));
}

/**
 * Error codes that mean "the path or the connection failed", where a second
 * attempt on a fresh connection is worth its cost. Everything else — SQL
 * errors, auth errors, shape errors — is deterministic and must not be retried.
 */
const TRANSPORT_ERROR_CODES = new Set([
  'ETIMEDOUT',
  'ECONNRESET',
  'ECONNREFUSED',
  'EPIPE',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EAI_AGAIN',
  'PROTOCOL_CONNECTION_LOST',
  'PROTOCOL_SEQUENCE_TIMEOUT', // mysql2's per-query `timeout` firing
]);

/** The shape of `mysql2/promise` we use, kept narrow so the import stays lazy. */
interface MysqlPool {
  query(sql: string | { sql: string; timeout?: number }, values: unknown[]): Promise<[unknown, unknown]>;
  end(): Promise<void>;
  /** The underlying callback pool, only used to count its lifecycle events. */
  pool?: { on(event: string, listener: (...args: unknown[]) => void): void };
}

export function createMysqlDriver(options: SqlDriverOptions): SqlDriver {
  const log = options.logger?.child({ component: 'sqlcheck.mysql' });
  const perAttemptMs = attemptTimeoutMs(options.timeoutMs);

  let pool: Promise<MysqlPool> | undefined;
  let closed = false;

  // Cumulative across pool swaps: on a failure these say whether the socket
  // that misbehaved was a recycled one or one that never finished connecting.
  const counters = { connectionsCreated: 0, acquired: 0, released: 0, poolSwaps: 0 };

  async function getPool(): Promise<MysqlPool> {
    if (!pool) {
      pool = (async () => {
        const mysql = await import('mysql2/promise');
        const created = mysql.createPool({
          uri: options.connectionString,
          connectionLimit: POOL_SIZE,
          waitForConnections: true,
          // Cap the wait for a free connection too: without it a stuck pool
          // queues logins forever instead of failing closed.
          connectTimeout: perAttemptMs,
          maxIdle: POOL_SIZE,
          idleTimeout: 60_000,
          enableKeepAlive: true,
        }) as unknown as MysqlPool;
        created.pool?.on('connection', () => { counters.connectionsCreated += 1; });
        created.pool?.on('acquire', () => { counters.acquired += 1; });
        created.pool?.on('release', () => { counters.released += 1; });
        return created;
      })().catch((error: unknown) => {
        // Do not memoize a failed construction: the next login retries.
        pool = undefined;
        throw new SqlGroupCheckUnavailable(
          'mysql',
          `mysql2 pool could not be created: ${errorMessage(error)}`,
          error,
        );
      });
    }
    return pool;
  }

  /**
   * Drops the current pool so the next attempt materializes a fresh one. The
   * old pool is ended in the background, best effort: the whole point is that
   * something in it stopped answering.
   */
  function swapPool(): void {
    const stale = pool;
    pool = undefined;
    counters.poolSwaps += 1;
    void stale?.then((p) => p.end()).catch(() => undefined);
  }

  async function attempt(sql: string, params: SqlQueryParams): Promise<SqlRow[]> {
    const connectionPool = await getPool();
    // The username is the sole bound value. It never touches the SQL text.
    const [rows] = await connectionPool.query({ sql, timeout: perAttemptMs }, [params.username]);
    return normalizeRows(rows);
  }

  // --- optional keepalive ----------------------------------------------------
  // `undefined` = never answered yet, so the first success logs once ("path
  // established") and every later line is a transition. Steady states are
  // silent: the value of this log is the exact timestamp a path broke or came
  // back, not a heartbeat.
  let keepaliveHealthy: boolean | undefined;
  let keepaliveTimer: NodeJS.Timeout | undefined;

  async function keepaliveTick(): Promise<void> {
    const startedAt = Date.now();
    try {
      const connectionPool = await getPool();
      await connectionPool.query({ sql: 'SELECT 1', timeout: perAttemptMs }, []);
      if (keepaliveHealthy === undefined) {
        log?.info({ durationMs: Date.now() - startedAt }, 'sql keepalive established');
      } else if (!keepaliveHealthy) {
        log?.info({ durationMs: Date.now() - startedAt, ...counters }, 'sql keepalive recovered');
      }
      keepaliveHealthy = true;
    } catch (error) {
      if (keepaliveHealthy !== false) {
        log?.error(
          { err: { message: errorMessage(error) }, durationMs: Date.now() - startedAt, ...counters },
          'sql keepalive failed: the database path is down right now',
        );
      }
      keepaliveHealthy = false;
      // A dead pool must not greet the next login: the next tick (or query)
      // starts clean.
      swapPool();
    }
  }

  if (options.keepaliveIntervalMs) {
    keepaliveTimer = setInterval(() => { void keepaliveTick(); }, options.keepaliveIntervalMs);
    // The ping must never be what keeps the process alive.
    keepaliveTimer.unref?.();
  }
  // --- end keepalive -----------------------------------------------------------

  return {
    name: 'mysql',
    placeholder: MYSQL_PLACEHOLDER,

    async query(sql: string, params: SqlQueryParams): Promise<SqlRow[]> {
      try {
        return await attempt(sql, params);
      } catch (error) {
        if (!isTransportError(error)) {
          throw toUnavailable(error);
        }
        log?.warn(
          { err: { message: errorMessage(error) }, attemptTimeoutMs: perAttemptMs, ...counters },
          'mysql transport error: swapping the pool and retrying once',
        );
        swapPool();
        try {
          return await attempt(sql, params);
        } catch (retryError) {
          log?.error(
            { err: { message: errorMessage(retryError) }, retried: true, ...counters },
            'mysql transport error persisted through the retry on a fresh pool',
          );
          throw toUnavailable(retryError);
        }
      }
    },

    async close(): Promise<void> {
      closed = true;
      if (keepaliveTimer) clearInterval(keepaliveTimer);
      keepaliveTimer = undefined;
      const pending = pool;
      pool = undefined;
      if (!pending) return;
      // A pool that never finished connecting has nothing to release.
      await pending.then((p) => p.end()).catch(() => undefined);
    },
  };

  function isTransportError(error: unknown): boolean {
    if (closed) return false;
    if (!(error instanceof Error)) return false;
    // Pool construction failures come wrapped: a bad URI is configuration, not
    // transport, and getPool already un-memoizes so the next login retries.
    if (error instanceof SqlGroupCheckUnavailable) return false;
    const code = (error as NodeJS.ErrnoException).code;
    return typeof code === 'string' && TRANSPORT_ERROR_CODES.has(code);
  }
}

function toUnavailable(error: unknown): SqlGroupCheckUnavailable {
  if (error instanceof SqlGroupCheckUnavailable) return error;
  return new SqlGroupCheckUnavailable(
    'mysql',
    `mysql query failed: ${errorMessage(error)}`,
    error,
  );
}

/**
 * mysql2 returns rows for a SELECT and a ResultSetHeader for anything else.
 * A query that returns no result set is a configuration mistake, not an empty
 * answer, so it must not read as "user not authorized".
 */
function normalizeRows(rows: unknown): SqlRow[] {
  if (Array.isArray(rows)) return rows as SqlRow[];
  throw new SqlGroupCheckUnavailable(
    'mysql',
    'SQL_GROUP_QUERY returned no result set: it must be a SELECT',
  );
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    const code = (error as NodeJS.ErrnoException).code;
    return code ? `${code} ${error.message}` : error.message;
  }
  return String(error);
}
