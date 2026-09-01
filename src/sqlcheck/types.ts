/**
 * The SQL group check: a second authorization gate against a database that is
 * not Active Directory (typically the customer's back-office).
 *
 * The contract is deliberately thin, because the query text arrives from the
 * customer and lives only in `SQL_GROUP_QUERY`. The code assumes exactly two
 * things and nothing more:
 *
 *   1. the query takes ONE bound parameter, the normalized username;
 *   2. at least one row returned  =  authorized;  zero rows  =  not authorized.
 *
 * No column names, no result shape, no schema. Anything else would be a guess
 * about a database we have never seen.
 *
 * A driver is the only place that knows a database engine. Adding `pg` later is
 * one more file implementing `SqlDriver` plus one `case` in `createSqlDriver`:
 * the checker, the gate and the configuration do not move.
 */
import type { Logger } from '../logger.js';

export type SqlRow = Record<string, unknown>;

/**
 * Everything the query may bind. One field today, and on purpose: a single
 * value that is always bound is a value that can never be interpolated.
 */
export interface SqlQueryParams {
  /** sAMAccountName lowercased — the same string as the `sub` claim. */
  username: string;
}

export interface SqlDriver {
  readonly name: string;

  /**
   * The placeholder `SQL_GROUP_QUERY` must carry for the username, in this
   * engine's syntax: `?` for mysql2, `@username` for mssql, `$1` for a future
   * `pg`. The checker validates the query against it at startup.
   */
  readonly placeholder: string;

  /**
   * Runs the query with the username BOUND, never interpolated, and returns the
   * rows. Throws when the database cannot answer — the caller turns that into a
   * rejection, never into a pass.
   */
  query(sql: string, params: SqlQueryParams): Promise<SqlRow[]>;

  /** Releases the connection pool. Safe to call when nothing was ever opened. */
  close(): Promise<void>;
}

export interface SqlDriverOptions {
  connectionString: string;
  /** Connection/query deadline in milliseconds. */
  timeoutMs: number;
  /**
   * When set, the driver logs its own transport events: the one retry it is
   * allowed, the pool counters on a failure, the keepalive transitions. The
   * callers keep logging the decision (rejected login, refused seed); this is
   * the layer below, the one that says WHY the database did not answer.
   */
  logger?: Logger;
  /**
   * When set, the driver pings the database (`SELECT 1`) at this interval.
   * Two jobs: it keeps the path warm through stateful middleboxes that silently
   * drop idle flows, and it turns a broken path into a timestamped log line
   * instead of a rejected login. Only transitions are logged.
   */
  keepaliveIntervalMs?: number;
}

/**
 * Configuration is wrong: the query does not carry the placeholder this driver
 * binds to, the driver name is unknown, a parameter is missing. Raised at
 * startup, so a misconfigured deployment never reaches a login.
 */
export class SqlGroupCheckConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SqlGroupCheckConfigError';
  }
}

/**
 * The database could not answer: unreachable, timed out, bad credentials, SQL
 * syntax rejected. Distinct from "the user is not in the table", which is an
 * answer. This one means FAIL CLOSED — reject, log loudly, but do not revoke
 * the user's grant chain: an outage of ours must not log the whole floor out.
 */
export class SqlGroupCheckUnavailable extends Error {
  readonly driver: string;

  constructor(driver: string, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'SqlGroupCheckUnavailable';
    this.driver = driver;
  }
}
