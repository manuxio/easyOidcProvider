/**
 * TOTP seeds read from an attribute of the user's Active Directory record.
 *
 * It adds no connection logic of its own: `LdapDirectory.readUserAttribute`
 * does the service bind, the TLS, the timeouts and the fail-closed discipline,
 * which is the same code path the liveness gate already trusts.
 *
 * The attribute is named by TWO_FACTOR_LDAP_ATTRIBUTE. Its value must be the
 * user's base32 TOTP seed; anything else is refused by the verifier as an
 * unusable enrolment. This server never WRITES the attribute — enrolment belongs
 * to whoever administers the directory.
 */
import { LdapUnavailableError, type LdapDirectory } from '../identity/ldap.js';
import type { Logger } from '../logger.js';
import { TwoFactorSeedUnavailable, type TwoFactorSeedSource } from './types.js';

export interface LdapSeedSourceOptions {
  directory: LdapDirectory;
  /** TWO_FACTOR_LDAP_ATTRIBUTE, e.g. `pager` or a custom schema attribute. */
  attribute: string;
  logger: Logger;
}

export function createLdapSeedSource(options: LdapSeedSourceOptions): TwoFactorSeedSource {
  const { directory, attribute } = options;
  const log = options.logger.child({ component: 'two-factor.ldap', attribute });

  return {
    name: `ldap:${attribute}`,

    async lookup(username: string): Promise<string | undefined> {
      const startedAt = Date.now();
      try {
        const value = await directory.readUserAttribute(username, attribute);
        log.debug(
          { username, found: value !== undefined, durationMs: Date.now() - startedAt },
          'two-factor seed lookup completed',
        );
        return value;
      } catch (error) {
        // An LdapUnavailableError is exactly "the directory could not answer",
        // which upstream must never read as "the user has no seed".
        throw new TwoFactorSeedUnavailable(
          'ldap',
          error instanceof LdapUnavailableError || error instanceof Error
            ? error.message
            : String(error),
          error,
        );
      }
    },

    async close(): Promise<void> {
      // LdapDirectory opens a client per operation and owns nothing between
      // calls; the identity provider that built it stays its owner.
    },
  };
}
