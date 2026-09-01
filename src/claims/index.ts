/**
 * Entry point of the optional SQL-sourced extra token claims.
 *
 * NOTHING in this folder is reached at process start unless CLAIMS_SQL_ENABLED
 * is true: with the switch off no source is constructed, no pool is asked for,
 * and the database library is never loaded (the drivers import it lazily, on
 * the first query). That is the same discipline the group check proves from the
 * `Connections` counter of a real MySQL, and the reason `app.ts` builds ONE
 * driver for whichever of the three features happen to be on.
 */
import type { Config } from '../config.js';
import type { Logger } from '../logger.js';
import type { SqlDriver } from '../sqlcheck/index.js';
import { createSqlClaimsSource } from './sqlClaimsSource.js';
import { ExtraClaimsConfigError, type ExtraClaimsSource } from './types.js';

export * from './types.js';
export { RESERVED_CLAIM_NAMES, isReservedClaimName, assertClaimNameAllowed } from './reserved.js';
export { parseClaimNames } from './selectList.js';
export { createSqlClaimsSource, CLAIMS_QUERY_PARAMETER } from './sqlClaimsSource.js';

export interface BuildExtraClaimsOptions {
  /**
   * The SQL driver. `app.ts` builds it once and hands the SAME instance to the
   * group check and to the two-factor seed source when those are on too, so all
   * three share one pool — while each works with the others disabled.
   */
  sqlDriver?: SqlDriver;
  /** Injected whole by the unit tests, in place of the SQL source. */
  source?: ExtraClaimsSource;
}

/**
 * Builds the claims source, or returns undefined when the feature is off.
 *
 * Throws ExtraClaimsConfigError when the switch is on and the wiring or the
 * query is wrong — a missing connection string, a query that does not bind the
 * username, a query whose output columns cannot be named, an alias that is a
 * reserved claim. All of those stop the server at STARTUP, never at a login.
 */
export function buildExtraClaims(
  config: Config,
  logger: Logger,
  options: BuildExtraClaimsOptions = {},
): ExtraClaimsSource | undefined {
  if (!config.extraClaims.enabled) return undefined;

  const source = options.source ?? buildSqlSource(config, logger, options);

  logger.info(
    { source: source.name, claims: source.claimNames, timeoutMs: config.sqlGroupCheck.timeoutMs },
    'extra token claims enabled: every id token — and every JWT access token when API_AUDIENCE is set — '
    + 'carries these claims, by server policy, whatever the client asks for',
  );

  return source;
}

function buildSqlSource(
  config: Config,
  logger: Logger,
  options: BuildExtraClaimsOptions,
): ExtraClaimsSource {
  const { query } = config.extraClaims;
  if (!query) {
    throw new ExtraClaimsConfigError('CLAIMS_SQL_QUERY is required when CLAIMS_SQL_ENABLED=true');
  }
  if (!options.sqlDriver) {
    throw new ExtraClaimsConfigError(
      'CLAIMS_SQL_ENABLED=true needs a SQL driver: check SQL_DRIVER and SQL_CONNECTION_STRING',
    );
  }
  return createSqlClaimsSource({
    query,
    driver: options.sqlDriver,
    // The same deadline as the group check and the seed lookup: one knob for
    // "how long may the customer's database hold a login open".
    timeoutMs: config.sqlGroupCheck.timeoutMs,
    logger,
  });
}
