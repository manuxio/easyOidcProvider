/**
 * Test harness: an auth-server on a free loopback port, entirely in-process.
 *
 * Everything is self-contained — the in-memory oidc store, an in-memory secret
 * store, and dev-stub users declared per test — so the suite touches no Mongo,
 * no filesystem, and no other test's state.
 */
import { createServer, type Server } from 'node:http';
import { createServer as createProbe } from 'node:net';
import type { AddressInfo } from 'node:net';
import type { AdapterFactory } from 'oidc-provider';

import { createAuthServer, type AuthServer } from '../../src/app.js';
import { loadConfig, type Config } from '../../src/config.js';
import type { DevStubIdentityProvider } from '../../src/identity/devStub.js';
import type { IdentityProvider } from '../../src/identity/types.js';
import { createSilentLogger, type Logger } from '../../src/logger.js';
import type { ExtraClaimsSource } from '../../src/claims/index.js';
import type { SqlDriver } from '../../src/sqlcheck/index.js';
import type { TwoFactorSeedSource } from '../../src/twofactor/index.js';

export const CLIENT_ID = 'desktop-app';
/** Registered without a port: RFC 8252 lets a native client use any loopback port. */
export const REGISTERED_REDIRECT = 'http://127.0.0.1/callback';

export interface TestUser {
  username: string;
  password: string;
  active?: boolean;
}

export interface TestServerOptions {
  users?: TestUser[];
  /** Extra environment entries, merged last so a test can override anything. */
  env?: Record<string, string>;
  /**
   * Phase 4: a fake SQL driver in place of a real database. Only reaches the
   * gate when the env also sets SQL_GROUP_CHECK_ENABLED=true.
   */
  sqlDriver?: SqlDriver;
  /** Phase 4: a capturing logger, when a test asserts on what was logged. */
  logger?: Logger;
  /**
   * Phase 4-bis: a seed source in place of SQL or LDAP. Only reaches the
   * verifier when the env also sets TWO_FACTOR_ENABLED=true.
   */
  twoFactorSeedSource?: TwoFactorSeedSource;
  /**
   * Phase 4-ter: an extra-claims source in place of the SQL one. Only reaches
   * the provider when the env also sets CLAIMS_SQL_ENABLED=true.
   */
  extraClaimsSource?: ExtraClaimsSource;
  /** An oidc state store in place of oidc-provider's in-memory one (see test/helpers/memoryAdapter.ts). */
  adapterFactory?: AdapterFactory;
  /**
   * 1.3.0: builds the identity provider from the loaded config, in place of
   * the configured one (e.g. spnego over a fake directory). `stub` is then
   * whatever this returns, not a dev-stub.
   */
  identity?: (config: Config, logger: Logger) => IdentityProvider;
}

export interface TestServer {
  baseUrl: string;
  port: number;
  auth: AuthServer;
  stub: DevStubIdentityProvider;
  close(): Promise<void>;
}

/** Asks the OS for a free port and gives it straight back. */
async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createProbe();
    probe.on('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address() as AddressInfo;
      probe.close(() => resolve(port));
    });
  });
}

export async function startTestServer(options: TestServerOptions = {}): Promise<TestServer> {
  const users = options.users ?? [
    { username: 'mario.rossi', password: 'Password1!', active: true },
  ];
  const port = await freePort();
  const issuer = `http://127.0.0.1:${port}`;

  const config = loadConfig({
    ISSUER_URL: issuer,
    PORT: String(port),
    HOST: '127.0.0.1',
    LOG_LEVEL: 'silent',
    // Empty DATA_DIR and no MONGO_URL: nothing is persisted anywhere.
    DATA_DIR: '',
    IDENTITY_PROVIDER: 'dev-stub',
    DEV_STUB_REALM: 'TEST.LOCAL',
    DEV_STUB_USERS: JSON.stringify(
      users.map((user) => ({ ...user, active: user.active ?? true })),
    ),
    CLIENTS_JSON: JSON.stringify([
      { client_id: CLIENT_ID, redirect_uris: [REGISTERED_REDIRECT] },
    ]),
    ...options.env,
  });

  const logger = options.logger ?? createSilentLogger();
  const auth = await createAuthServer({
    config,
    logger,
    ...(options.identity ? { identity: options.identity(config, logger) } : {}),
    ...(options.sqlDriver ? { sqlDriver: options.sqlDriver } : {}),
    ...(options.twoFactorSeedSource ? { twoFactorSeedSource: options.twoFactorSeedSource } : {}),
    ...(options.extraClaimsSource ? { extraClaimsSource: options.extraClaimsSource } : {}),
    ...(options.adapterFactory ? { adapterFactory: options.adapterFactory } : {}),
  });
  const http: Server = createServer(auth.app);
  await new Promise<void>((resolve) => http.listen(port, '127.0.0.1', resolve));

  return {
    baseUrl: issuer,
    port,
    auth,
    stub: auth.identity as DevStubIdentityProvider,
    async close() {
      await new Promise<void>((resolve, reject) => {
        http.close((error) => (error ? reject(error) : resolve()));
      });
      await auth.close();
    },
  };
}
