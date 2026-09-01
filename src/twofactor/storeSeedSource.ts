/**
 * TOTP seeds read from the credential store of the `database` identity
 * provider (TWO_FACTOR_SOURCE=mongo): the seed lives in the SAME document as
 * the password hash, in the field AUTH_MONGO_TOTP_FIELD names.
 *
 * The store is shared with the provider, not owned: close() is a no-op here
 * because the provider's close() releases the store, exactly like the sql
 * seed source shares the SQL pool without owning it... except that one closes
 * the driver too — both closes are idempotent, which is what makes any
 * sharing in this server safe.
 */
import type { CredentialStore } from '../identity/database/index.js';
import { CredentialStoreUnavailable } from '../identity/database/index.js';
import type { Logger } from '../logger.js';
import { TwoFactorSeedUnavailable, type TwoFactorSeedSource } from './types.js';

export interface StoreSeedSourceOptions {
  store: CredentialStore;
  logger: Logger;
}

export function createStoreSeedSource(options: StoreSeedSourceOptions): TwoFactorSeedSource {
  const { store } = options;
  const log = options.logger.child({ component: 'two-factor.store', store: store.name });

  return {
    name: `store:${store.name}`,

    async lookup(username: string): Promise<string | undefined> {
      const startedAt = Date.now();
      let record;
      try {
        record = await store.lookup(username);
      } catch (error) {
        throw new TwoFactorSeedUnavailable(
          store.name,
          error instanceof CredentialStoreUnavailable ? error.message : describe(error),
          error,
        );
      }
      log.debug(
        { username, found: record?.totpSeed !== undefined, durationMs: Date.now() - startedAt },
        'two-factor seed lookup completed',
      );
      return record?.totpSeed;
    },

    async close(): Promise<void> {
      // Shared with the identity provider, which owns it.
    },
  };
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
