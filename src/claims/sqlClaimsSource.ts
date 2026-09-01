/**
 * Extra token claims read from a SQL database, on the drivers of `src/sqlcheck/`.
 *
 * Third feature on that seam — group check, TOTP seed, and now these claims —
 * and it shares the SAME pool when more than one of them is on, because they
 * share SQL_DRIVER and SQL_CONNECTION_STRING. Each one works with the others
 * off; none of them owns the connection.
 *
 * The contract with the customer's query, in full:
 *
 *   1. exactly ONE bind placeholder for the username (`?` mysql, `@username`
 *      mssql), validated at startup by the same `validateQuery` as the other
 *      two features;
 *   2. the username is BOUND, never interpolated — not configurable;
 *   3. EXACTLY ONE ROW is expected. Zero rows means the AD account is not tied
 *      to a back-office user, which is a refusal, not an empty claim set;
 *   4. the COLUMN NAMES (the aliases) are the claim names. No column name is
 *      hardcoded anywhere in this folder;
 *   5. a NULL value omits that claim entirely — not `null`, not `""`.
 *
 * THE SECOND HALF OF THE BLACKLIST. The startup analysis (`selectList.ts`) said
 * which columns this query will produce. The first execution — and every one
 * after it, because the cost is a set lookup — checks what actually came back
 * against that declaration. A reserved name or an undeclared column is a hard,
 * loud failure, never a silently dropped claim: the alternative is a token that
 * is missing the back-office identity and a log that says everything is fine.
 */
import { withDeadline } from '../deadline.js';
import type { Logger } from '../logger.js';
import { validateQuery, type SqlDriver, type SqlRow } from '../sqlcheck/index.js';
import { isReservedClaimName, RESERVED_CLAIM_NAMES } from './reserved.js';
import { parseClaimNames } from './selectList.js';
import {
  EXTRA_CLAIMS_REASONS,
  ExtraClaimsUnavailable,
  ExtraClaimsUserNotFound,
  type ExtraClaims,
  type ExtraClaimsSource,
} from './types.js';

/** The parameter that carries the query, named in every message the operator reads. */
export const CLAIMS_QUERY_PARAMETER = 'CLAIMS_SQL_QUERY';

export interface SqlClaimsSourceOptions {
  /** Raw CLAIMS_SQL_QUERY. Never rewritten, never concatenated with anything. */
  query: string;
  driver: SqlDriver;
  /** The shared SQL_TIMEOUT_MS deadline: this runs inside every login and refresh. */
  timeoutMs: number;
  logger: Logger;
}

export function createSqlClaimsSource(options: SqlClaimsSourceOptions): ExtraClaimsSource {
  const { query, driver, timeoutMs } = options;

  // Startup, in order: the username must be bound (same rule as the group check
  // and the seed lookup), and the output column names must be knowable.
  validateQuery(query, driver, options.logger, CLAIMS_QUERY_PARAMETER);
  const claimNames = parseClaimNames(query);
  const declared = new Set(claimNames);

  const log = options.logger.child({ component: 'extra-claims.sql', driver: driver.name });

  return {
    name: `sql:${driver.name}`,
    claimNames,

    async lookup(username: string): Promise<ExtraClaims> {
      const startedAt = Date.now();
      let rows: SqlRow[];
      try {
        rows = await withDeadline(
          driver.query(query, { username }),
          timeoutMs,
          () => new ExtraClaimsUnavailable(
            driver.name,
            EXTRA_CLAIMS_REASONS.unavailable,
            `extra claims lookup timed out after ${timeoutMs} ms for ${username}`,
          ),
          // The login is already rejected when this fires; the line exists
          // because the eventual fate of the abandoned query is the diagnosis —
          // it says whether the wire was hanging, erroring or just slow.
          (late) => log.warn(
            {
              username,
              lateOutcome: late.outcome,
              lateElapsedMs: late.elapsedMs,
              ...(late.outcome === 'rejected' ? { err: { message: describe(late.error) } } : {}),
            },
            'the claims lookup abandoned by the deadline has now settled',
          ),
        );
      } catch (error) {
        const unavailable = error instanceof ExtraClaimsUnavailable
          ? error
          : new ExtraClaimsUnavailable(
            driver.name,
            EXTRA_CLAIMS_REASONS.unavailable,
            describe(error),
            error,
          );
        log.error(
          {
            username,
            reason: unavailable.reason,
            durationMs: Date.now() - startedAt,
            timeoutMs,
            err: { name: unavailable.name, message: unavailable.message },
          },
          'the extra claims could not be read: rejecting (fail closed), grant chain left intact',
        );
        throw unavailable;
      }

      if (rows.length === 0) {
        log.warn(
          { username, reason: EXTRA_CLAIMS_REASONS.userNotFound, durationMs: Date.now() - startedAt },
          'no back-office row for this account: refusing, the token would carry no back-office identity',
        );
        throw new ExtraClaimsUserNotFound(
          username,
          `${CLAIMS_QUERY_PARAMETER} returned no row for ${username}`,
        );
      }

      if (rows.length > 1) {
        // Two identities for one account means we would be picking one. The
        // query is the customer's, so this is their bug: say it and refuse.
        const ambiguous = new ExtraClaimsUnavailable(
          driver.name,
          EXTRA_CLAIMS_REASONS.ambiguousRows,
          `${CLAIMS_QUERY_PARAMETER} returned ${rows.length} rows for ${username}: `
          + 'it must return exactly one',
        );
        log.error(
          { username, reason: ambiguous.reason, rows: rows.length },
          'the extra claims query is ambiguous: refusing rather than choosing an identity',
        );
        throw ambiguous;
      }

      const claims = shapeRow(rows[0]!, username, declared, driver.name, log);
      log.debug(
        {
          username,
          claims: Object.keys(claims),
          durationMs: Date.now() - startedAt,
        },
        'extra claims read',
      );
      return claims;
    },

    async close(): Promise<void> {
      await driver.close();
    },
  };
}

/**
 * Turns the single row into claims, enforcing the runtime half of the blacklist
 * and dropping the NULL columns.
 */
function shapeRow(
  row: SqlRow,
  username: string,
  declared: ReadonlySet<string>,
  driverName: string,
  log: Logger,
): ExtraClaims {
  const claims: ExtraClaims = {};

  for (const [column, value] of Object.entries(row)) {
    if (isReservedClaimName(column)) {
      // The startup analysis should have caught this. Reaching it means the
      // database produced a column name the query text did not show — an alias
      // from a view, a `SELECT *` expanded by a driver, a query changed under
      // us. Refuse loudly: this is the case the blacklist exists for.
      const refusal = new ExtraClaimsUnavailable(
        driverName,
        EXTRA_CLAIMS_REASONS.reservedName,
        `${CLAIMS_QUERY_PARAMETER} returned the column ${JSON.stringify(column)}, which is a `
        + `reserved claim name (${RESERVED_CLAIM_NAMES.join(', ')})`,
      );
      log.error(
        { username, reason: refusal.reason, column, reserved: RESERVED_CLAIM_NAMES },
        'the extra claims query returned a RESERVED claim name: refusing every token until the query is fixed',
      );
      throw refusal;
    }

    if (!declared.has(column)) {
      // An undeclared column could never reach the id_token anyway — its name
      // was not in the `claims` configuration when the Provider was built — so
      // emitting a token would mean silently losing a claim the customer asked
      // for. Refusing is the only honest answer.
      const refusal = new ExtraClaimsUnavailable(
        driverName,
        EXTRA_CLAIMS_REASONS.undeclaredColumn,
        `${CLAIMS_QUERY_PARAMETER} returned the column ${JSON.stringify(column)}, which its `
        + `SELECT list did not declare (declared: ${[...declared].join(', ') || 'none'}); `
        + 'the claim could not be put into a token, so no token is issued',
      );
      log.error(
        { username, reason: refusal.reason, column, declared: [...declared] },
        'the extra claims query returned an undeclared column: refusing rather than dropping a claim in silence',
      );
      throw refusal;
    }

    // NULL means "this user has no such attribute": the claim is ABSENT from
    // the token. Not null, not an empty string — absent.
    if (value === null || value === undefined) continue;

    claims[column] = normalize(value);
  }

  return claims;
}

/**
 * JSON-safe value, with as little opinion as possible: numbers, booleans and
 * strings pass through untouched, and the three shapes a driver can hand back
 * that JSON cannot carry are converted the only way they can be.
 */
function normalize(value: unknown): unknown {
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'object') return JSON.parse(JSON.stringify(value)) as unknown;
  return value;
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
