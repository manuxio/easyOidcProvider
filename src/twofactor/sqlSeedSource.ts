/**
 * TOTP seeds read from a SQL database, on the drivers of `src/sqlcheck/`.
 *
 * The contract mirrors the group check's, deliberately, because the customer
 * writes both queries and should only have to learn one set of rules:
 *
 *   1. exactly ONE bind placeholder for the username (`?` mysql, `@username`
 *      mssql), validated at startup by the same `validateQuery`;
 *   2. the username is BOUND, never interpolated — that is not configurable;
 *   3. the seed is the FIRST COLUMN OF THE FIRST ROW. No column name, no schema.
 *      Zero rows = the user is not enrolled.
 *
 * The driver is shared with the group check when both are on (one pool, one
 * connection string), and each feature works perfectly well with the other off.
 */
import { withDeadline } from '../deadline.js';
import type { Logger } from '../logger.js';
import { validateQuery, type SqlDriver, type SqlRow } from '../sqlcheck/index.js';
import { TwoFactorSeedUnavailable, type TwoFactorSeedSource } from './types.js';

export interface SqlSeedSourceOptions {
  /** Raw TWO_FACTOR_SQL_QUERY. Never rewritten, never concatenated with anything. */
  query: string;
  driver: SqlDriver;
  timeoutMs: number;
  logger: Logger;
}

export function createSqlSeedSource(options: SqlSeedSourceOptions): TwoFactorSeedSource {
  const { query, driver, timeoutMs } = options;
  // Same startup validation as the group check: a query that does not bind the
  // username stops the server here, not at the first login.
  validateQuery(query, driver, options.logger, 'TWO_FACTOR_SQL_QUERY');
  const log = options.logger.child({ component: 'two-factor.sql', driver: driver.name });

  return {
    name: `sql:${driver.name}`,

    async lookup(username: string): Promise<string | undefined> {
      const startedAt = Date.now();
      let rows: SqlRow[];
      try {
        rows = await withDeadline(
          driver.query(query, { username }),
          timeoutMs,
          () => new TwoFactorSeedUnavailable(
            driver.name,
            `two-factor seed lookup timed out after ${timeoutMs} ms for ${username}`,
          ),
        );
      } catch (error) {
        throw error instanceof TwoFactorSeedUnavailable
          ? error
          : new TwoFactorSeedUnavailable(driver.name, describe(error), error);
      }

      if (rows.length === 0) {
        log.debug(
          { username, durationMs: Date.now() - startedAt },
          'two-factor seed lookup: no row for this user',
        );
        return undefined;
      }
      if (rows.length > 1) {
        // Two seeds for one user means we would be guessing which one is theirs.
        // The query is the customer's, so this is their bug — say so loudly and
        // refuse rather than pick one.
        throw new TwoFactorSeedUnavailable(
          driver.name,
          `TWO_FACTOR_SQL_QUERY returned ${rows.length} rows for ${username}: it must return at most one`,
        );
      }

      const seed = firstColumn(rows[0]!);
      log.debug(
        { username, found: seed !== undefined, durationMs: Date.now() - startedAt },
        'two-factor seed lookup completed',
      );
      return seed;
    },

    async close(): Promise<void> {
      await driver.close();
    },
  };
}

/**
 * The first column of the row, whatever it is called. A NULL or an empty string
 * reads the same as no row at all: the user is not enrolled.
 */
function firstColumn(row: SqlRow): string | undefined {
  const values = Object.values(row);
  if (values.length === 0) return undefined;
  const value = values[0];
  if (value === null || value === undefined) return undefined;
  const text = Buffer.isBuffer(value) ? value.toString('utf8') : String(value);
  return text.trim() === '' ? undefined : text.trim();
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
