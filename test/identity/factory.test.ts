/**
 * The identity provider factory (src/identity/index.ts): which implementation
 * IDENTITY_PROVIDER selects, and the one wiring rule it enforces itself —
 * `database` needs the credential store the caller (app.ts) built, because
 * the same store is shared with the two-factor seed source.
 *
 * Nothing here authenticates anybody: the providers' behaviour is covered by
 * spnego.test.ts, databaseProvider.test.ts and the e2e suites. Constructing
 * the spnego provider opens no connection (the LDAP client is per operation
 * and the Kerberos library loads on the first ticket).
 */
import { describe, expect, it } from 'vitest';

import { loadConfig, type Config } from '../../src/config.js';
import {
  createIdentityProvider,
  DatabaseIdentityProvider,
  DevStubIdentityProvider,
  SpnegoIdentityProvider,
  type CredentialStore,
} from '../../src/identity/index.js';
import { createSilentLogger } from '../../src/logger.js';

const CLIENTS_JSON = JSON.stringify([{ client_id: 'desktop-app', redirect_uris: ['http://127.0.0.1/callback'] }]);

function configWith(env: Record<string, string>): Config {
  return loadConfig({ ISSUER_URL: 'http://127.0.0.1:3000', DATA_DIR: '', CLIENTS_JSON, ...env });
}

const DEV_STUB = {
  IDENTITY_PROVIDER: 'dev-stub',
  DEV_STUB_USERS: JSON.stringify([{ username: 'mario.rossi', password: 'x', active: true }]),
};

const SPNEGO = {
  IDENTITY_PROVIDER: 'spnego',
  REALM: 'EXAMPLE.LOCAL',
  LDAP_URL: 'ldaps://dc1.example.local',
  LDAP_BIND_DN: 'svc-auth@EXAMPLE.LOCAL',
  LDAP_BIND_PASSWORD: 'Svc.Passw0rd!',
  LDAP_BASE_DN: 'DC=example,DC=local',
};

const DATABASE = {
  IDENTITY_PROVIDER: 'database',
  AUTH_DB_SOURCE: 'sql',
  AUTH_SQL_QUERY: 'SELECT passwordhash FROM users WHERE username = ?',
  SQL_CONNECTION_STRING: 'mysql://user:pass@db.invalid:3306/users',
};

/** A store nobody asks anything of: the factory only hands it over. */
const idleStore: CredentialStore = {
  name: 'idle',
  async lookup() {
    throw new Error('the factory must not look anything up');
  },
  async close() {},
};

describe('createIdentityProvider', () => {
  it('builds the dev-stub provider for IDENTITY_PROVIDER=dev-stub', () => {
    const provider = createIdentityProvider(configWith(DEV_STUB), createSilentLogger());
    expect(provider).toBeInstanceOf(DevStubIdentityProvider);
    expect(provider.name).toBe('dev-stub');
  });

  it('builds the spnego provider for IDENTITY_PROVIDER=spnego, without touching the network', () => {
    const provider = createIdentityProvider(configWith(SPNEGO), createSilentLogger());
    expect(provider).toBeInstanceOf(SpnegoIdentityProvider);
    expect(provider.name).toBe('spnego');
  });

  it('builds the database provider on the store it is handed', () => {
    const provider = createIdentityProvider(configWith(DATABASE), createSilentLogger(), {
      credentialStore: idleStore,
    });
    expect(provider).toBeInstanceOf(DatabaseIdentityProvider);
    expect(provider.name).toBe('database');
  });

  it('refuses IDENTITY_PROVIDER=database without a credential store, pointing at AUTH_DB_SOURCE', () => {
    expect(() => createIdentityProvider(configWith(DATABASE), createSilentLogger()))
      .toThrow('IDENTITY_PROVIDER=database needs a credential store: check AUTH_DB_SOURCE and its parameters');
  });

  it('ignores a credential store offered to another provider', () => {
    const provider = createIdentityProvider(configWith(DEV_STUB), createSilentLogger(), {
      credentialStore: idleStore,
    });
    expect(provider).toBeInstanceOf(DevStubIdentityProvider);
  });

  it('refuses an identity provider it does not know, should a Config bypass validation', () => {
    const forged = { ...configWith(DEV_STUB), identityProvider: 'kerberos-only' } as unknown as Config;
    expect(() => createIdentityProvider(forged, createSilentLogger()))
      .toThrow('unknown IDENTITY_PROVIDER kerberos-only');
  });
});
