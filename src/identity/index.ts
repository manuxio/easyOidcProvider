import type { Config } from '../config.js';
import type { Logger } from '../logger.js';
import { DatabaseIdentityProvider, type CredentialStore } from './database/index.js';
import { DevStubIdentityProvider } from './devStub.js';
import { SpnegoIdentityProvider } from './spnego/index.js';
import type { IdentityProvider } from './types.js';

export * from './types.js';
export { DevStubIdentityProvider } from './devStub.js';
export { SpnegoIdentityProvider } from './spnego/index.js';
export { LdapDirectory, LdapUnavailableError } from './ldap.js';
export {
  DatabaseIdentityProvider,
  createSqlCredentialStore,
  createMongoCredentialStore,
  CredentialStoreUnavailable,
  type CredentialStore,
  type CredentialRecord,
} from './database/index.js';

export interface CreateIdentityProviderOptions {
  /**
   * The credential store for IDENTITY_PROVIDER=database. The caller builds it
   * (app.ts: on the shared SQL driver, or on the external Mongo) and hands the
   * SAME instance to the two-factor seed source when TWO_FACTOR_SOURCE=mongo.
   */
  credentialStore?: CredentialStore;
}

export function createIdentityProvider(
  config: Config,
  logger: Logger,
  options: CreateIdentityProviderOptions = {},
): IdentityProvider {
  switch (config.identityProvider) {
    case 'dev-stub':
      return new DevStubIdentityProvider(config, logger);
    case 'spnego':
      return new SpnegoIdentityProvider({ config, logger });
    case 'database': {
      if (!options.credentialStore) {
        throw new Error(
          'IDENTITY_PROVIDER=database needs a credential store: check AUTH_DB_SOURCE and its parameters',
        );
      }
      return new DatabaseIdentityProvider({ config, logger, store: options.credentialStore });
    }
    default: {
      const exhaustive: never = config.identityProvider;
      throw new Error(`unknown IDENTITY_PROVIDER ${String(exhaustive)}`);
    }
  }
}
