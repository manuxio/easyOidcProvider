/**
 * A SqlDriver that answers from an in-memory set of usernames and records every
 * call. It is the instrument for two different claims:
 *
 *  - the gate behaves correctly for row present / row absent / database silent;
 *  - with the check disabled, `calls` stays empty and `closed` stays false —
 *    proof by construction that nothing was queried and no pool was opened,
 *    because the driver was never handed to anybody.
 */
import type { SqlDriver, SqlQueryParams, SqlRow } from '../../src/sqlcheck/index.js';

export interface FakeSqlCall {
  sql: string;
  params: SqlQueryParams;
}

export interface FakeSqlDriverOptions {
  name?: string;
  /** `?` (mysql) unless a test is exercising another engine's syntax. */
  placeholder?: string;
  /** Usernames the query "finds". Case-sensitive on purpose: the gate lowercases. */
  authorized?: Iterable<string>;
  /** Row shape returned for an authorized user; the code must not care. */
  row?: SqlRow;
  /**
   * Phase 4-ter: exact rows per username, which is what the extra-claims tests
   * need (their whole subject is the SHAPE of the row, not its presence).
   * When present it wins over `authorized`, and an unknown username gets zero
   * rows — the same "no such user" the other features read.
   */
  rows?: Map<string, SqlRow[]>;
}

export class FakeSqlDriver implements SqlDriver {
  readonly name: string;
  readonly placeholder: string;
  readonly calls: FakeSqlCall[] = [];
  readonly authorized: Set<string>;

  /** Set to make the next query throw, the way an unreachable database does. */
  failWith?: Error;
  /** Set to make the next query hang, so the checker's deadline has to fire. */
  hangForever = false;
  closed = false;

  /** Phase 4-ter: exact rows per username, writable so a test can change them mid-flight. */
  readonly rows: Map<string, SqlRow[]> | undefined;

  private readonly row: SqlRow;

  constructor(options: FakeSqlDriverOptions = {}) {
    this.name = options.name ?? 'fake';
    this.placeholder = options.placeholder ?? '?';
    this.authorized = new Set(options.authorized ?? []);
    this.row = options.row ?? { ok: 1 };
    this.rows = options.rows;
  }

  async query(sql: string, params: SqlQueryParams): Promise<SqlRow[]> {
    this.calls.push({ sql, params });
    if (this.failWith) throw this.failWith;
    if (this.hangForever) return new Promise<SqlRow[]>(() => undefined);
    if (this.rows) return this.rows.get(params.username) ?? [];
    return this.authorized.has(params.username) ? [this.row] : [];
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  /** The usernames this driver was asked about, in order. */
  get queriedUsernames(): string[] {
    return this.calls.map((call) => call.params.username);
  }
}
