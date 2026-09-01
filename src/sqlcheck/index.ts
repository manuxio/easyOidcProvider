/**
 * Entry point of the optional SQL group check.
 *
 * NOTHING in this folder is imported at process start: `src/gates/index.ts`
 * reaches `createSqlGroupChecker` only when SQL_GROUP_CHECK_ENABLED is true, and
 * even then the database library itself is loaded lazily by the driver on the
 * first query. With the switch off, no pool exists and no connection is opened.
 */
import type { SqlGroupCheckConfig, SqlDriverName } from '../config.js';
import type { Logger } from '../logger.js';
import { SqlGroupChecker } from './checker.js';
import { createMssqlDriver } from './mssql.js';
import { createMysqlDriver } from './mysql.js';
import type { SqlDriver, SqlDriverOptions } from './types.js';
import { SqlGroupCheckConfigError } from './types.js';

export * from './types.js';
export { SqlGroupChecker, validateQuery } from './checker.js';
export { createMysqlDriver, MYSQL_PLACEHOLDER } from './mysql.js';
export { createMssqlDriver, MSSQL_PLACEHOLDER } from './mssql.js';

/**
 * Builds the driver for a configured engine. A new engine — `pg` is the obvious
 * next one — is a new file plus a `case` here; nothing else in the application
 * changes.
 */
export function createSqlDriver(
  driver: SqlDriverName,
  options: SqlDriverOptions,
): SqlDriver {
  switch (driver) {
    case 'mysql':
      return createMysqlDriver(options);
    case 'mssql':
      return createMssqlDriver(options);
    default: {
      const exhaustive: never = driver;
      throw new SqlGroupCheckConfigError(`unknown SQL_DRIVER ${String(exhaustive)}`);
    }
  }
}

export interface CreateSqlGroupCheckerOptions {
  /** Injected by the unit tests to observe the driver without a database. */
  driver?: SqlDriver;
}

/**
 * Turns the validated configuration into a checker. Throws
 * SqlGroupCheckConfigError when the query does not fit the driver's placeholder,
 * which stops the server at startup rather than at the first login.
 */
export function createSqlGroupChecker(
  config: SqlGroupCheckConfig,
  logger: Logger,
  options: CreateSqlGroupCheckerOptions = {},
): SqlGroupChecker {
  if (!config.query) {
    throw new SqlGroupCheckConfigError(
      'SQL_GROUP_QUERY is required when SQL_GROUP_CHECK_ENABLED=true',
    );
  }

  const driver = options.driver ?? buildDriverFromConfig(config);

  return new SqlGroupChecker({
    query: config.query,
    driver,
    timeoutMs: config.timeoutMs,
    logger,
  });
}

function buildDriverFromConfig(config: SqlGroupCheckConfig): SqlDriver {
  if (!config.connectionString) {
    throw new SqlGroupCheckConfigError(
      'SQL_CONNECTION_STRING is required when SQL_GROUP_CHECK_ENABLED=true',
    );
  }
  return createSqlDriver(config.driver, {
    connectionString: config.connectionString,
    timeoutMs: config.timeoutMs,
  });
}
