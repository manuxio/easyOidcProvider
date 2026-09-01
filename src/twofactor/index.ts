/**
 * Entry point of the optional TOTP second factor.
 *
 * NOTHING here is constructed at process start unless TWO_FACTOR_ENABLED is
 * true: with the switch off no verifier exists, no seed source exists, and the
 * SQL pool the seed source would have shared is never asked for.
 */
import type { Config } from '../config.js';
import type { CredentialStore } from '../identity/database/index.js';
import type { LdapDirectory } from '../identity/ldap.js';
import type { Logger } from '../logger.js';
import type { SqlDriver } from '../sqlcheck/index.js';
import { createLdapSeedSource } from './ldapSeedSource.js';
import { createSqlSeedSource } from './sqlSeedSource.js';
import { createStoreSeedSource } from './storeSeedSource.js';
import { TwoFactorConfigError, type TwoFactorSeedSource } from './types.js';
import { TwoFactorVerifier } from './verifier.js';

export * from './types.js';
export { LoginRateLimiter, type RateLimitState } from './rateLimit.js';
export { createLdapSeedSource } from './ldapSeedSource.js';
export { createSqlSeedSource } from './sqlSeedSource.js';
export { createStoreSeedSource } from './storeSeedSource.js';
export {
  TwoFactorVerifier,
  TWO_FACTOR_DIGITS,
  TWO_FACTOR_STEP_SECONDS,
  TWO_FACTOR_WINDOW_STEPS,
} from './verifier.js';

export interface BuildTwoFactorOptions {
  /**
   * The SQL driver for TWO_FACTOR_SOURCE=sql. The caller builds it once and
   * hands the SAME instance to the group check when that is on too, so the two
   * features share one pool — while either works with the other disabled.
   */
  sqlDriver?: SqlDriver;
  /** The directory for TWO_FACTOR_SOURCE=ldap: the spnego provider's own. */
  directory?: LdapDirectory;
  /** The credential store for TWO_FACTOR_SOURCE=mongo: the database provider's own. */
  credentialStore?: CredentialStore;
  /** Injected whole by the unit tests, in place of any of the above. */
  seedSource?: TwoFactorSeedSource;
}

/**
 * Builds the verifier, or returns undefined when the second factor is off.
 * Throws TwoFactorConfigError when the switch is on and the wiring is missing,
 * which stops the server at startup rather than at the first login.
 */
export function buildTwoFactor(
  config: Config,
  logger: Logger,
  options: BuildTwoFactorOptions = {},
): TwoFactorVerifier | undefined {
  if (!config.twoFactor.enabled) return undefined;

  const source = options.seedSource ?? buildSeedSource(config, logger, options);

  logger.info(
    {
      source: source.name,
      formPathOnly: true,
    },
    'two-factor authentication enabled: the password form asks for a TOTP code (the Kerberos SSO path never does)',
  );

  return new TwoFactorVerifier({ source, logger });
}

function buildSeedSource(
  config: Config,
  logger: Logger,
  options: BuildTwoFactorOptions,
): TwoFactorSeedSource {
  const { source, sqlQuery, ldapAttribute } = config.twoFactor;

  if (source === 'sql') {
    if (!sqlQuery) {
      throw new TwoFactorConfigError('TWO_FACTOR_SQL_QUERY is required when TWO_FACTOR_SOURCE=sql');
    }
    if (!options.sqlDriver) {
      throw new TwoFactorConfigError(
        'TWO_FACTOR_SOURCE=sql needs a SQL driver: check SQL_DRIVER and SQL_CONNECTION_STRING',
      );
    }
    return createSqlSeedSource({
      query: sqlQuery,
      driver: options.sqlDriver,
      timeoutMs: config.sqlGroupCheck.timeoutMs,
      logger,
    });
  }

  if (source === 'mongo') {
    if (!options.credentialStore) {
      throw new TwoFactorConfigError(
        'TWO_FACTOR_SOURCE=mongo needs the credential store: it is only available with '
        + 'IDENTITY_PROVIDER=database and AUTH_DB_SOURCE=mongo',
      );
    }
    return createStoreSeedSource({ store: options.credentialStore, logger });
  }

  if (!ldapAttribute) {
    throw new TwoFactorConfigError(
      'TWO_FACTOR_LDAP_ATTRIBUTE is required when TWO_FACTOR_SOURCE=ldap',
    );
  }
  if (!options.directory) {
    throw new TwoFactorConfigError(
      'TWO_FACTOR_SOURCE=ldap needs the LDAP directory: it is only available with IDENTITY_PROVIDER=spnego',
    );
  }
  return createLdapSeedSource({
    directory: options.directory,
    attribute: ldapAttribute,
    logger,
  });
}
