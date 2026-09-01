/**
 * SqlGroupChecker: runs SQL_GROUP_QUERY for one username and answers
 * authorized / not authorized, or throws when the database cannot answer.
 *
 * It owns the three things that must not be left to a driver:
 *
 *  - the placeholder contract (validated once, at startup, not at first login);
 *  - the deadline, so a hung database rejects instead of hanging every login;
 *  - the loud structured log on the fail-closed path.
 */
import { withDeadline } from '../deadline.js';
import type { Logger } from '../logger.js';
import type { SqlDriver } from './types.js';
import { SqlGroupCheckConfigError, SqlGroupCheckUnavailable } from './types.js';

export interface SqlGroupCheckerOptions {
  /** Raw SQL_GROUP_QUERY. Never rewritten, never concatenated with anything. */
  query: string;
  driver: SqlDriver;
  timeoutMs: number;
  logger: Logger;
}

export class SqlGroupChecker {
  private readonly query: string;
  private readonly driver: SqlDriver;
  private readonly timeoutMs: number;
  private readonly log: Logger;

  constructor(options: SqlGroupCheckerOptions) {
    validateQuery(options.query, options.driver, options.logger);
    this.query = options.query;
    this.driver = options.driver;
    this.timeoutMs = options.timeoutMs;
    this.log = options.logger.child({ component: 'sql-group-check', driver: options.driver.name });
  }

  /**
   * True when the query returned at least one row. That is the whole contract:
   * the customer's query decides what "authorized" means, this code only counts.
   *
   * Throws SqlGroupCheckUnavailable when the database could not answer — the
   * caller must reject (fail closed), never pass.
   */
  async isAuthorized(username: string): Promise<boolean> {
    const startedAt = Date.now();
    try {
      const rows = await withDeadline(
        this.driver.query(this.query, { username }),
        this.timeoutMs,
        () => new SqlGroupCheckUnavailable(
          this.driver.name,
          `SQL group check timed out after ${this.timeoutMs} ms for ${username}`,
        ),
      );
      const authorized = rows.length > 0;
      this.log.debug(
        { username, rows: rows.length, authorized, durationMs: Date.now() - startedAt },
        authorized
          ? 'sql group check: user found'
          : 'sql group check: no row for this user',
      );
      return authorized;
    } catch (error) {
      const unavailable = error instanceof SqlGroupCheckUnavailable
        ? error
        : new SqlGroupCheckUnavailable(this.driver.name, describe(error), error);
      this.log.error(
        {
          username,
          reason: 'sql_group_check_unavailable',
          durationMs: Date.now() - startedAt,
          timeoutMs: this.timeoutMs,
          err: { name: unavailable.name, message: unavailable.message },
        },
        'SQL group check could not be evaluated: rejecting (fail closed)',
      );
      throw unavailable;
    }
  }

  async close(): Promise<void> {
    await this.driver.close();
  }
}

/**
 * The query must carry exactly one occurrence of this driver's placeholder.
 *
 * Zero means the username is not bound at all — either the query ignores it, or
 * (much worse) somebody wrote it into the SQL by hand. More than one means the
 * binding would be ambiguous: mysql2 binds positionally, so a second `?` would
 * silently take a value that does not exist. Both stop the server at startup.
 *
 * `parameterName` is the env variable the text came from, so the operator reads
 * the name of the line they have to fix. Three features share this rule now:
 * SQL_GROUP_QUERY, TWO_FACTOR_SQL_QUERY and CLAIMS_SQL_QUERY.
 */
export function validateQuery(
  query: string,
  driver: SqlDriver,
  logger: Logger,
  parameterName = 'SQL_GROUP_QUERY',
): void {
  const trimmed = query.trim();
  if (trimmed === '') {
    throw new SqlGroupCheckConfigError(`${parameterName} is empty`);
  }

  const occurrences = countOccurrences(trimmed, driver.placeholder);
  if (occurrences !== 1) {
    throw new SqlGroupCheckConfigError(
      `${parameterName} must contain exactly one ${JSON.stringify(driver.placeholder)} placeholder `
      + `for the username with SQL_DRIVER=${driver.name}, found ${occurrences}`,
    );
  }

  // A query written for the other engine is a common paste mistake and the
  // symptom (everybody denied) looks nothing like the cause. Say it out loud,
  // but do not refuse: only the customer knows what their SQL legitimately says.
  for (const foreign of FOREIGN_PLACEHOLDERS[driver.name] ?? []) {
    if (trimmed.includes(foreign)) {
      logger.warn(
        { driver: driver.name, parameter: parameterName, foreignPlaceholder: foreign },
        `${parameterName} contains a placeholder of another engine: check SQL_DRIVER`,
      );
    }
  }
}

/** Placeholders that belong to a different engine than the configured one. */
const FOREIGN_PLACEHOLDERS: Record<string, string[]> = {
  mysql: ['@username', ':username', '$1'],
  mssql: [':username', '$1'],
  pg: ['@username', ':username'],
};

function countOccurrences(haystack: string, needle: string): number {
  let count = 0;
  let index = haystack.indexOf(needle);
  while (index !== -1) {
    count += 1;
    index = haystack.indexOf(needle, index + needle.length);
  }
  return count;
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
