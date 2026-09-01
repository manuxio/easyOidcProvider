/**
 * Credentials read from a SQL database, on the drivers of `src/sqlcheck/` —
 * the same shared pool (and the same transport retry and keepalive) as the
 * group check, the TOTP seed and the extra claims.
 *
 * The contract of AUTH_SQL_QUERY mirrors the other customer-written queries:
 *
 *   1. exactly ONE bind placeholder for the username, validated at startup;
 *   2. the username is BOUND, never interpolated — not configurable;
 *   3. the FIRST column of the single row is the password hash. Optional
 *      extra columns, recognized BY NAME (case-insensitive): `salt` for the
 *      digest schemes, `totpsecret` for a TOTP seed living in the same row.
 *   4. zero rows = unknown OR disabled user: the query IS the activation
 *      policy (put the `attivo = 1` in its WHERE), which is why the record it
 *      returns is always `active: true`.
 */
import { withDeadline } from '../../deadline.js';
import type { Logger } from '../../logger.js';
import { validateQuery, type SqlDriver, type SqlRow } from '../../sqlcheck/index.js';
import {
  CredentialStoreUnavailable,
  type CredentialRecord,
  type CredentialStore,
} from './store.js';

export const AUTH_SQL_QUERY_PARAMETER = 'AUTH_SQL_QUERY';

export interface SqlCredentialStoreOptions {
  /** Raw AUTH_SQL_QUERY. Never rewritten, never concatenated with anything. */
  query: string;
  driver: SqlDriver;
  /** The shared SQL_TIMEOUT_MS deadline: this runs inside every login and refresh. */
  timeoutMs: number;
  logger: Logger;
}

export function createSqlCredentialStore(options: SqlCredentialStoreOptions): CredentialStore {
  const { query, driver, timeoutMs } = options;
  validateQuery(query, driver, options.logger, AUTH_SQL_QUERY_PARAMETER);
  const log = options.logger.child({ component: 'identity.database.sql', driver: driver.name });

  return {
    name: `sql:${driver.name}`,

    async lookup(username: string): Promise<CredentialRecord | undefined> {
      const startedAt = Date.now();
      let rows: SqlRow[];
      try {
        rows = await withDeadline(
          driver.query(query, { username }),
          timeoutMs,
          () => new CredentialStoreUnavailable(
            driver.name,
            `credential lookup timed out after ${timeoutMs} ms for ${username}`,
          ),
        );
      } catch (error) {
        throw error instanceof CredentialStoreUnavailable
          ? error
          : new CredentialStoreUnavailable(driver.name, describe(error), error);
      }

      if (rows.length === 0) {
        log.debug(
          { username, durationMs: Date.now() - startedAt },
          'credential lookup: no row for this user',
        );
        return undefined;
      }
      if (rows.length > 1) {
        // Two rows for one username means we would be guessing which identity
        // is theirs. The query is the customer's, so this is their bug — say
        // so loudly and refuse rather than pick one.
        throw new CredentialStoreUnavailable(
          driver.name,
          `${AUTH_SQL_QUERY_PARAMETER} returned ${rows.length} rows for ${username}: `
          + 'it must return at most one',
        );
      }

      const row = rows[0]!;
      const passwordHash = firstColumnText(row);
      if (passwordHash === undefined) {
        // A row with an empty hash is an account nobody can log into — that is
        // an answer about the user, not an outage of ours.
        log.warn(
          { username, durationMs: Date.now() - startedAt },
          'credential lookup: the row has an empty password hash, treating the user as unknown',
        );
        return undefined;
      }

      const salt = namedColumnText(row, 'salt');
      const totpSeed = namedColumnText(row, 'totpsecret');
      log.debug(
        { username, durationMs: Date.now() - startedAt },
        'credential lookup completed',
      );
      return {
        passwordHash,
        // The query already filtered on whatever "active" means to the customer.
        active: true,
        ...(salt !== undefined ? { salt } : {}),
        ...(totpSeed !== undefined ? { totpSeed } : {}),
      };
    },

    async close(): Promise<void> {
      await driver.close();
    },
  };
}

/** The first column of the row, whatever it is called. Empty reads as absent. */
function firstColumnText(row: SqlRow): string | undefined {
  const values = Object.values(row);
  if (values.length === 0) return undefined;
  return asText(values[0]);
}

/** A column recognized by (case-insensitive) name, beyond the first one. */
function namedColumnText(row: SqlRow, name: string): string | undefined {
  const entries = Object.entries(row);
  for (const [column, value] of entries.slice(1)) {
    if (column.toLowerCase() === name) return asText(value);
  }
  return undefined;
}

function asText(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  const text = Buffer.isBuffer(value) ? value.toString('utf8') : String(value);
  return text.trim() === '' ? undefined : text.trim();
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
