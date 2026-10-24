/**
 * The assembly of the whole server (src/app.ts): which pieces createAuthServer
 * builds from the Config, the test seams it accepts, and what close() releases.
 *
 * Covered here, on in-process servers (test/helpers/server.ts):
 *   - the 1.3.0 `identity` seam and the `adapterFactory` seam: the object
 *     handed in is the one the server uses, end to end;
 *   - the startup warnings that say a deployment is not production-shaped
 *     (no Mongo, no secret persistence, a second factor nobody can reach);
 *   - express details: no x-powered-by, trust proxy only on request, the
 *     16 kB cap on the login form body;
 *   - ONE SQL driver shared by the features that need one, and none used when
 *     none does;
 *   - close(): the identity provider, the seed source and the claims source
 *     are released, and one that fails to close does not stop the others.
 */
import type { Request, Response } from 'express';
import { afterEach, describe, expect, it } from 'vitest';

import { DevStubIdentityProvider } from '../../src/identity/devStub.js';
import type { AuthenticationResult, ChallengeOptions, IdentityProvider } from '../../src/identity/types.js';
import type { ExtraClaims, ExtraClaimsSource } from '../../src/claims/index.js';
import { createCapturingLogger, type CapturingLogger } from '../helpers/captureLogger.js';
import { CUSTOMER_CLAIMS_QUERY } from '../helpers/claimsQuery.js';
import { FakeSeedSource } from '../helpers/fakeSeedSource.js';
import { FakeSqlDriver } from '../helpers/fakeSqlDriver.js';
import { decodeJwtPayload, discover, exchange, login } from '../helpers/flow.js';
import { createInspectableStore } from '../helpers/memoryAdapter.js';
import { startTestServer, type TestServer, type TestServerOptions } from '../helpers/server.js';

const MARIO = { username: 'mario.rossi', password: 'Password1!' };

const SQL_BASE = {
  SQL_DRIVER: 'mysql',
  SQL_CONNECTION_STRING: 'mysql://user:pw@127.0.0.1:3306/backoffice',
  SQL_TIMEOUT_MS: '2000',
};
const GROUP_QUERY = 'SELECT 1 FROM authorized_users WHERE username = ?';
const GROUP_CHECK_ON = { ...SQL_BASE, SQL_GROUP_CHECK_ENABLED: 'true', SQL_GROUP_QUERY: GROUP_QUERY };
const CLAIMS_ON = { ...SQL_BASE, CLAIMS_SQL_ENABLED: 'true', CLAIMS_SQL_QUERY: CUSTOMER_CLAIMS_QUERY };
const TWO_FACTOR_ON = {
  ...SQL_BASE,
  TWO_FACTOR_ENABLED: 'true',
  TWO_FACTOR_SOURCE: 'sql',
  TWO_FACTOR_SQL_QUERY: 'SELECT seed FROM totp_seeds WHERE username = ?',
};
const SPNEGO_ENV = {
  IDENTITY_PROVIDER: 'spnego',
  REALM: 'EXAMPLE.LOCAL',
  LDAP_URL: 'ldaps://dc1.example.local',
  LDAP_BIND_DN: 'svc-auth@EXAMPLE.LOCAL',
  LDAP_BIND_PASSWORD: 'Svc.Passw0rd!',
  LDAP_BASE_DN: 'DC=example,DC=local',
};

const running: TestServer[] = [];
afterEach(async () => {
  while (running.length > 0) await running.pop()!.close();
});

async function server(options: TestServerOptions = {}): Promise<{ s: TestServer; capture: CapturingLogger }> {
  const capture = createCapturingLogger();
  const s = await startTestServer({ users: [MARIO], logger: capture.logger, ...options });
  running.push(s);
  return { s, capture };
}

/** Started and closed by the test itself, for the assertions on close(). */
async function unmanaged(options: TestServerOptions = {}): Promise<{ s: TestServer; capture: CapturingLogger }> {
  const capture = createCapturingLogger();
  const s = await startTestServer({ users: [MARIO], logger: capture.logger, ...options });
  return { s, capture };
}

/** An identity provider of its own name, delegating to a dev-stub and counting close(). */
class SeamIdentity implements IdentityProvider {
  readonly name = 'seam-identity';
  closed = 0;

  constructor(private readonly inner: IdentityProvider) {}

  authenticate(req: Request, res: Response): Promise<AuthenticationResult> {
    return this.inner.authenticate(req, res);
  }

  isAccountActive(principal: string): Promise<boolean> {
    return this.inner.isAccountActive(principal);
  }

  challenge(req: Request, res: Response, options: ChallengeOptions): Promise<void> {
    return this.inner.challenge(req, res, options);
  }

  async close(): Promise<void> {
    this.closed += 1;
  }
}

class ClaimsSourceStub implements ExtraClaimsSource {
  readonly name = 'stub-claims';
  readonly claimNames = ['remoteId'] as const;
  closed = 0;
  closeFailure?: Error;

  async lookup(): Promise<ExtraClaims> {
    return { remoteId: 4217 };
  }

  async close(): Promise<void> {
    this.closed += 1;
    if (this.closeFailure) throw this.closeFailure;
  }
}

class FailingCloseSeedSource extends FakeSeedSource {
  override async close(): Promise<void> {
    await super.close();
    throw new Error('seed pool already gone (test)');
  }
}

describe('the identity seam (1.3.0)', () => {
  it('uses the identity provider it is handed, for the login, the health check and the gates', async () => {
    let seam: SeamIdentity | undefined;
    const { s, capture } = await server({
      identity: (config, logger) => {
        seam = new SeamIdentity(new DevStubIdentityProvider(config, logger));
        return seam;
      },
    });
    expect(s.auth.identity).toBe(seam);

    const health = (await (await fetch(`${s.baseUrl}/health`)).json()) as { checks: Record<string, string> };
    expect(health.checks.identityProvider).toBe('seam-identity');

    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, MARIO));
    expect(decodeJwtPayload(tokens.id_token!).sub).toBe('mario.rossi');
    expect(capture.matching('login accepted')).toHaveLength(1);
  });

  it('closes the identity provider it was handed, once', async () => {
    let seam: SeamIdentity | undefined;
    const { s } = await unmanaged({
      identity: (config, logger) => {
        seam = new SeamIdentity(new DevStubIdentityProvider(config, logger));
        return seam;
      },
    });
    await s.close();
    expect(seam!.closed).toBe(1);
  });
});

describe('the adapterFactory seam', () => {
  it('keeps the oidc state in the store it is handed when MONGO_URL is unset', async () => {
    const store = createInspectableStore();
    const { s } = await server({ adapterFactory: store.adapterFactory });
    const config = await discover(s);
    await exchange(config, await login(s, config, MARIO));

    expect(store.entries('Session').size).toBeGreaterThanOrEqual(1);
    expect(store.entries('Grant').size).toBeGreaterThanOrEqual(1);
    expect(store.entries('RefreshToken').size).toBe(1);
    expect(s.auth.db).toBeUndefined();
  });
});

describe('startup warnings', () => {
  it('says, once each, that without Mongo the oidc state and the signing key live in memory', async () => {
    const { capture } = await server();
    const noMongo = capture.withReason('no_mongo_url');
    expect(noMongo).toHaveLength(1);
    expect(noMongo[0]!.level).toBe('warn');
    expect(capture.withReason('no_secret_persistence')).toHaveLength(1);
    expect(capture.matching('server signing key ready')[0]).toMatchObject({ store: 'memory' });
  });

  it('warns that a second factor on the form path cannot be reached with the form switched off', async () => {
    const seam: IdentityProvider = {
      name: 'sso-only',
      async authenticate() {
        return { status: 'no-credentials' };
      },
      async isAccountActive() {
        return true;
      },
      async challenge(_req, res) {
        res.status(401).send('');
      },
    };
    const { s, capture } = await server({
      env: { ...SPNEGO_ENV, ...TWO_FACTOR_ON, FALLBACK_FORM_ENABLED: 'false' },
      identity: () => seam,
      twoFactorSeedSource: new FakeSeedSource(),
    });
    expect(s.auth.twoFactor).toBeDefined();
    const unreachable = capture.withReason('two_factor_unreachable');
    expect(unreachable).toHaveLength(1);
    expect(unreachable[0]!.level).toBe('warn');
  });

  it('does not warn about the second factor while the form is on', async () => {
    const { capture } = await server({ env: TWO_FACTOR_ON, twoFactorSeedSource: new FakeSeedSource() });
    expect(capture.withReason('two_factor_unreachable')).toHaveLength(0);
  });
});

describe('what the server exposes of itself', () => {
  it('never sends x-powered-by', async () => {
    const { s } = await server();
    for (const path of ['/health', '/.well-known/openid-configuration', '/jwks']) {
      const response = await fetch(`${s.baseUrl}${path}`);
      expect(response.status, path).toBe(200);
      expect(response.headers.get('x-powered-by'), path).toBeNull();
    }
  });

  it('trusts a reverse proxy only when TRUST_PROXY=true, in express and in oidc-provider alike', async () => {
    const { s: direct } = await server();
    expect(direct.auth.app.get('trust proxy')).toBe(false);
    expect(direct.auth.provider.proxy).toBe(false);

    const { s: proxied } = await server({ env: { TRUST_PROXY: 'true' } });
    expect(proxied.auth.app.get('trust proxy')).toBe(true);
    expect(proxied.auth.provider.proxy).toBe(true);
  });

  it('refuses a login form body above 16 kB before any credential is read', async () => {
    const { s, capture } = await server();
    const post = (size: number) =>
      fetch(`${s.baseUrl}/interaction/no-such-uid/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ username: MARIO.username, password: 'x'.repeat(size) }).toString(),
      });

    const fromRouter = () => capture.records.filter((record) => record.component === 'interaction').length;
    const before = fromRouter();
    expect((await post(17 * 1024)).status).toBe(413);
    expect(fromRouter()).toBe(before);
    // Under the cap the body reaches the router, which answers for the missing session.
    expect((await post(8 * 1024)).status).not.toBe(413);
  });
});

describe('one SQL driver for every feature that needs one', () => {
  it('the group check and the extra claims read through the same driver, and close() releases it', async () => {
    const driver = new FakeSqlDriver({ rows: new Map([[MARIO.username, [{ remoteId: 4217, name: 'Mario Rossi' }]]]) });
    const { s } = await unmanaged({ env: { ...GROUP_CHECK_ON, ...CLAIMS_ON }, sqlDriver: driver });
    expect(s.auth.extraClaims).toBeDefined();

    const config = await discover(s);
    await exchange(config, await login(s, config, MARIO));
    const statements = new Set(driver.calls.map((call) => call.sql));
    expect(statements.size).toBe(2);
    expect([...statements].some((sql) => sql.includes('authorized_users'))).toBe(true);
    expect(driver.queriedUsernames.every((username) => username === MARIO.username)).toBe(true);

    expect(driver.closed).toBe(false);
    await s.close();
    expect(driver.closed).toBe(true);
  });

  it('never touches a driver when no feature needs SQL', async () => {
    const driver = new FakeSqlDriver({ authorized: [MARIO.username] });
    const { s } = await unmanaged({ sqlDriver: driver });
    expect(s.auth.twoFactor).toBeUndefined();
    expect(s.auth.extraClaims).toBeUndefined();

    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, MARIO));
    await fetch(`${s.baseUrl}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: 'desktop-app',
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token!,
      }).toString(),
    });
    await s.close();
    expect(driver.calls).toEqual([]);
    expect(driver.closed).toBe(false);
  });

  it('does not build one for a second factor whose seed source is handed in', async () => {
    const driver = new FakeSqlDriver();
    const source = new FakeSeedSource();
    const { s } = await unmanaged({ env: TWO_FACTOR_ON, sqlDriver: driver, twoFactorSeedSource: source });
    expect(s.auth.twoFactor).toBeDefined();
    await s.close();
    expect(driver.closed).toBe(false);
    expect(source.closed).toBe(true);
  });
});

describe('close()', () => {
  it('releases the seed source and the claims source', async () => {
    const seeds = new FakeSeedSource();
    const claims = new ClaimsSourceStub();
    const { s } = await unmanaged({
      env: { ...TWO_FACTOR_ON, ...CLAIMS_ON },
      twoFactorSeedSource: seeds,
      extraClaimsSource: claims,
    });
    expect(s.auth.extraClaims).toBe(claims);
    await s.close();
    expect(seeds.closed).toBe(true);
    expect(claims.closed).toBe(1);
  });

  it('logs a source that does not close cleanly, and still closes the rest', async () => {
    const seeds = new FailingCloseSeedSource();
    const claims = new ClaimsSourceStub();
    claims.closeFailure = new Error('claims pool already gone (test)');
    let seam: SeamIdentity | undefined;
    const { s, capture } = await unmanaged({
      env: { ...TWO_FACTOR_ON, ...CLAIMS_ON },
      twoFactorSeedSource: seeds,
      extraClaimsSource: claims,
      identity: (config, logger) => {
        seam = new SeamIdentity(new DevStubIdentityProvider(config, logger));
        return seam;
      },
    });

    await expect(s.close()).resolves.toBeUndefined();
    expect(seam!.closed).toBe(1);
    expect(seeds.closed).toBe(true);
    expect(claims.closed).toBe(1);
    expect(capture.matching('the two-factor seed source did not close cleanly')).toHaveLength(1);
    expect(capture.matching('the extra claims source did not close cleanly')).toHaveLength(1);
  });
});
