/**
 * Per-client LDAP group restriction (1.3.0): `required_ldap_groups` on a user
 * client of CLIENTS_JSON.
 *
 * The configuration contract first, then every path that hands a restricted
 * client's tokens to a person, end to end on the real provider, with the
 * spnego identity provider over a fake directory (no domain controller):
 *
 *   a. the login form of the restricted client itself;
 *   b. SSO reuse: a session opened by another client (crm-web), then the
 *      restricted client (dbsync-web) on the same browser — interactive and
 *      with prompt=none, first authorization and an existing grant;
 *   c. the refresh grant;
 *   d. the token exchange of a subject token issued to the restricted client.
 *
 * And throughout: a person refused for dbsync-web keeps using crm-web.
 */
import * as client from 'openid-client';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import { ConfigError, loadConfig, type Config } from '../src/config.js';
import { LdapUnavailableError, type LdapDirectory } from '../src/identity/ldap.js';
import { SpnegoIdentityProvider } from '../src/identity/spnego/index.js';
import type { Logger } from '../src/logger.js';
import { Browser } from './helpers/browser.js';
import { createCapturingLogger, type CapturingLogger } from './helpers/captureLogger.js';
import { decodeJwtPayload, exchange, login, LoginRejected, tokenRequest, type LoginResult } from './helpers/flow.js';
import { startTestServer, type TestServer } from './helpers/server.js';
import {
  agentClient,
  agentKeys,
  assertion,
  contractRule,
  exchangeFields,
  exchangeRequest,
  type AgentKeys,
} from './helpers/tokenExchange.js';

const REALM = 'EXAMPLE.LOCAL';
const DB_ADMINS = 'CN=DB Admins,DC=example,DC=local';
const OTHER_GROUP = 'CN=Operatori,OU=Gruppi,DC=example,DC=local';

const SPNEGO_ENV = {
  IDENTITY_PROVIDER: 'spnego',
  REALM,
  LDAP_URL: 'ldaps://dc1.example.local',
  LDAP_BIND_DN: `svc-auth@${REALM}`,
  LDAP_BIND_PASSWORD: 'Svc.Passw0rd!',
  LDAP_BASE_DN: 'DC=example,DC=local',
};

// ---------------------------------------------------------------------------
describe('required_ldap_groups in CLIENTS_JSON', () => {
  function load(clients: unknown[], env: Record<string, string> = SPNEGO_ENV): Config {
    return loadConfig({
      ISSUER_URL: 'https://auth.example.local',
      DATA_DIR: '',
      ...env,
      CLIENTS_JSON: JSON.stringify(clients),
    });
  }

  function problemsOf(clients: unknown[], env: Record<string, string> = SPNEGO_ENV): string[] {
    try {
      load(clients, env);
    } catch (error) {
      if (error instanceof ConfigError) return error.problems;
      throw error;
    }
    throw new Error('the configuration was accepted');
  }

  const user = (extra: Record<string, unknown>) => ({
    client_id: 'dbsync-web',
    application_type: 'web',
    redirect_uris: ['https://dbsync.example.local/callback'],
    ...extra,
  });

  it('keeps the groups in Config.clientRequiredGroups, trimmed, and strips them from the oidc-provider metadata', () => {
    const config = load([
      user({ required_ldap_groups: [`  ${DB_ADMINS} `, OTHER_GROUP] }),
      { client_id: 'crm-web', redirect_uris: ['https://crm.example.local/callback'] },
    ]);
    expect(config.clientRequiredGroups.get('dbsync-web')).toEqual([DB_ADMINS, OTHER_GROUP]);
    expect(config.clientRequiredGroups.has('crm-web')).toBe(false);
    expect(config.clients.find((c) => c.client_id === 'dbsync-web')).not.toHaveProperty('required_ldap_groups');
    expect(config.clients).toHaveLength(2);
  });

  it('no client declares it -> an empty map', () => {
    expect(load([user({})]).clientRequiredGroups.size).toBe(0);
  });

  it.each([
    ['an empty array', []],
    ['a string', DB_ADMINS],
    ['an empty string inside', [DB_ADMINS, '']],
    ['a blank string inside', ['   ']],
    ['a non-string inside', [42]],
    ['null', null],
  ])('refuses %s', (_label, value) => {
    const problems = problemsOf([user({ required_ldap_groups: value })]);
    expect(problems.join('\n')).toMatch(
      /CLIENTS_JSON\[0\]\.required_ldap_groups must be a non-empty array of group DNs/,
    );
  });

  it('refuses it on a machine-to-machine client', () => {
    const problems = problemsOf([
      {
        client_id: 'machine',
        client_secret: 'b4e2d1ef0c9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a392817060504',
        grant_types: ['client_credentials'],
        response_types: [],
        token_endpoint_auth_method: 'client_secret_basic',
        required_ldap_groups: [DB_ADMINS],
      },
    ]);
    expect(problems.join('\n')).toMatch(/CLIENTS_JSON\[0\]\.required_ldap_groups is only allowed on a user client/);
  });

  it('refuses it on a token exchange client', () => {
    const problems = problemsOf([
      user({}),
      {
        client_id: 'agent-service',
        grant_types: ['urn:ietf:params:oauth:grant-type:token-exchange'],
        response_types: [],
        token_endpoint_auth_method: 'private_key_jwt',
        required_ldap_groups: [DB_ADMINS],
      },
    ]);
    expect(problems.join('\n')).toMatch(/CLIENTS_JSON\[1\]\.required_ldap_groups is only allowed on a user client/);
  });

  it.each([
    ['dev-stub', { IDENTITY_PROVIDER: 'dev-stub', DEV_STUB_USERS: JSON.stringify([{ username: 'a', password: 'b' }]) }],
    [
      'database',
      {
        IDENTITY_PROVIDER: 'database',
        AUTH_DB_SOURCE: 'sql',
        AUTH_SQL_QUERY: 'SELECT password FROM users WHERE username = ?',
        SQL_CONNECTION_STRING: 'mysql://u:p@127.0.0.1/db',
      },
    ],
  ])('refuses it at startup with IDENTITY_PROVIDER=%s (no AD groups to read)', (provider, env) => {
    const problems = problemsOf([user({ required_ldap_groups: [DB_ADMINS] })], env);
    expect(problems.join('\n')).toContain(
      `CLIENTS_JSON[0].required_ldap_groups requires IDENTITY_PROVIDER=spnego: with ${provider}`,
    );
  });
});

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

/** The AD as the tests see it: passwords, memberOf, and a switch to make it unreachable. */
class FakeDirectory {
  readonly users = new Map<string, { password: string; memberOf: string[] }>();
  /** Every inspectAccount call, by account name: the round-trip counter. */
  readonly inspected: string[] = [];
  down = false;

  async verifyCredentials(bindIdentity: string, password: string) {
    const name = bindIdentity.split('@')[0]!.toLowerCase();
    const user = this.users.get(name);
    if (!user || user.password !== password) return { ok: false as const, reason: 'invalid_credentials' as const };
    return { ok: true as const, sAMAccountName: name };
  }

  async inspectAccount(name: string) {
    this.inspected.push(name);
    if (this.down) throw new LdapUnavailableError('account search', new Error('connect ETIMEDOUT'));
    const user = this.users.get(name);
    if (!user) return { active: false as const, reason: 'account_not_found' as const };
    return { active: true as const, dn: `CN=${name},CN=Users,DC=example,DC=local`, memberOf: [...user.memberOf] };
  }

  async readUserAttribute(): Promise<undefined> {
    return undefined;
  }
}

const AUDIENCE = 'https://easyoidc.test/api';
const CRM = { scope: 'crm', audience: 'crm', grants: ['authorization_code', 'token-exchange'], exchange_scopes: ['llm'] };
const AGENT = { scope: 'agent', audience: 'agent-service', grants: ['authorization_code'] };

const CRM_REDIRECT = 'http://127.0.0.1:4000/callback';
const DBSYNC_REDIRECT = 'http://127.0.0.1:4001/callback';
const CRM_WEB = { client_id: 'crm-web', application_type: 'web', redirect_uris: [CRM_REDIRECT], scope: 'openid crm agent' };
const DBSYNC_WEB = {
  client_id: 'dbsync-web',
  application_type: 'web',
  redirect_uris: [DBSYNC_REDIRECT],
  scope: 'openid crm agent',
  // Spelled differently from the directory on purpose: sameDn is case- and
  // whitespace-tolerant, exactly like LDAP_REQUIRED_GROUP.
  required_ldap_groups: ['cn=db admins, dc=example, dc=local'],
};

/** In DB Admins (and something else). */
const ADMIN = { username: 'anna.admin', password: 'Admin.Pass1' };
/** In another group only. */
const LUIGI = { username: 'luigi.verdi', password: 'Luigi.Pass1' };

let keys: AgentKeys;
beforeAll(async () => {
  keys = await agentKeys('agent-groups');
});

interface Started {
  s: TestServer;
  directory: FakeDirectory;
  capture: CapturingLogger;
}

const running: TestServer[] = [];
afterEach(async () => {
  while (running.length > 0) await running.pop()!.close();
});

async function server(): Promise<Started> {
  const directory = new FakeDirectory();
  directory.users.set(ADMIN.username, { password: ADMIN.password, memberOf: [OTHER_GROUP, DB_ADMINS] });
  directory.users.set(LUIGI.username, { password: LUIGI.password, memberOf: [OTHER_GROUP] });
  const capture = createCapturingLogger();
  const s = await startTestServer({
    logger: capture.logger,
    env: {
      ...SPNEGO_ENV,
      API_AUDIENCE: AUDIENCE,
      DEFAULT_RESOURCE_JSON: JSON.stringify({ scope: 'api', grants: ['client_credentials'] }),
      RESOURCE_SERVERS_JSON: JSON.stringify([CRM, AGENT]),
      CLIENTS_JSON: JSON.stringify([
        CRM_WEB,
        DBSYNC_WEB,
        agentClient([keys.publicJwk], [contractRule(['crm-web', 'dbsync-web'])]),
      ]),
    },
    identity: (config: Config, logger: Logger) =>
      new SpnegoIdentityProvider({
        config,
        logger,
        gss: { async accept() { return { status: 'rejected', detail: 'no Kerberos in the tests' }; } },
        directory: directory as unknown as LdapDirectory,
      }),
  });
  running.push(s);
  return { s, directory, capture };
}

async function discoverFor(s: TestServer, clientId: string): Promise<client.Configuration> {
  return client.discovery(
    new URL(s.baseUrl),
    clientId,
    { token_endpoint_auth_method: 'none' },
    client.None(),
    { execute: [client.allowInsecureRequests] },
  );
}

/** One `/auth` hop on an existing browser session (no form expected), optionally with prompt=none. */
async function authorizeOnSession(
  s: TestServer,
  config: client.Configuration,
  browser: Browser,
  redirectUri: string,
  options: { scope?: string; prompt?: 'none' } = {},
): Promise<LoginResult & { callback: URL }> {
  const codeVerifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri,
    scope: options.scope ?? 'openid',
    ...(options.prompt ? { prompt: options.prompt } : {}),
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    state,
  });
  const { callbackUrl, visited } = await browser.follow(url.toString(), s.baseUrl);
  if (!callbackUrl) throw new Error(`the authorization did not redirect back: ${visited.join(' -> ')}`);
  return { callbackUrl, codeVerifier, state, redirectUri, browser, callback: new URL(callbackUrl) };
}

async function refresh(s: TestServer, clientId: string, refreshToken: string) {
  return tokenRequest(s, { client_id: clientId, grant_type: 'refresh_token', refresh_token: refreshToken });
}

function lastGroupRefusal(capture: CapturingLogger) {
  // The gate's own line (the only one carrying memberOf), the latest one.
  return capture.withReason('client_group_not_allowed').filter((record) => Array.isArray(record.memberOf)).at(-1);
}

// ---------------------------------------------------------------------------
describe('a. the login form of the restricted client', () => {
  it('a member of a required group gets tokens, with ONE directory lookup for liveness and groups together', async () => {
    const { s, directory } = await server();
    const config = await discoverFor(s, 'dbsync-web');
    const result = await login(s, config, { ...ADMIN, redirectUri: DBSYNC_REDIRECT });
    const tokens = await exchange(config, result);
    expect(decodeJwtPayload(tokens.id_token!)).toMatchObject({ sub: ADMIN.username, aud: 'dbsync-web' });
    // The login gates, the resume after login and the resume after consent:
    // the per-client gate reads the memberOf account_active already fetched.
    expect(directory.inspected).toEqual([ADMIN.username]);
  });

  it('a non-member is refused on the form with the Italian message, and the log carries the raw memberOf', async () => {
    const { s, capture } = await server();
    const config = await discoverFor(s, 'dbsync-web');
    const rejected = await login(s, config, { ...LUIGI, redirectUri: DBSYNC_REDIRECT }).catch((error: unknown) => error);
    expect(rejected).toBeInstanceOf(LoginRejected);
    const { status, body } = rejected as LoginRejected;
    console.log('form refusal for dbsync-web ->', status, body.match(/<p class="alert"[^<]*<\/p>/)?.[0]);
    expect(status).toBe(401);
    expect(body).toContain('class="alert"');
    expect(body).toContain('gruppi di dominio abilitati a questa applicazione');

    expect(lastGroupRefusal(capture)).toMatchObject({
      stage: 'login',
      username: LUIGI.username,
      clientId: 'dbsync-web',
      requiredGroups: ['cn=db admins, dc=example, dc=local'],
      memberOf: [OTHER_GROUP],
    });
  });

  it('the same non-member logs into crm-web normally (the restriction is per client)', async () => {
    const { s } = await server();
    const config = await discoverFor(s, 'crm-web');
    const tokens = await exchange(config, await login(s, config, { ...LUIGI, redirectUri: CRM_REDIRECT }));
    expect(decodeJwtPayload(tokens.id_token!)).toMatchObject({ sub: LUIGI.username, aud: 'crm-web' });
  });

  it('directory unreachable during the login -> temporarily unavailable on the form, never a pass', async () => {
    const { s, directory } = await server();
    directory.down = true;
    const config = await discoverFor(s, 'dbsync-web');
    const rejected = await login(s, config, { ...ADMIN, redirectUri: DBSYNC_REDIRECT }).catch((error: unknown) => error);
    expect(rejected).toBeInstanceOf(LoginRejected);
    expect((rejected as LoginRejected).body).toContain('il servizio di dominio non risponde');
  });
});

// ---------------------------------------------------------------------------
describe('b. SSO reuse: a session opened by crm-web, then dbsync-web', () => {
  it('a non-member: access_denied back to dbsync-web (interactive and prompt=none), crm-web keeps working', async () => {
    const { s, capture } = await server();
    const crm = await discoverFor(s, 'crm-web');
    const first = await login(s, crm, { ...LUIGI, redirectUri: CRM_REDIRECT });
    const crmTokens = await exchange(crm, first);

    const dbsync = await discoverFor(s, 'dbsync-web');
    const interactive = await authorizeOnSession(s, dbsync, first.browser, DBSYNC_REDIRECT);
    console.log('SSO reuse, non-member ->', interactive.callbackUrl);
    expect(interactive.callback.searchParams.get('error')).toBe('access_denied');
    expect(interactive.callback.searchParams.get('error_description')).toBe(
      'the account is not a member of any AD group allowed for this client',
    );
    expect(interactive.callback.searchParams.get('code')).toBeNull();
    expect(interactive.callback.searchParams.get('state')).toBe(interactive.state);

    const silent = await authorizeOnSession(s, dbsync, first.browser, DBSYNC_REDIRECT, { prompt: 'none' });
    console.log('SSO reuse, non-member, prompt=none ->', silent.callbackUrl);
    expect(silent.callback.searchParams.get('error')).toBe('access_denied');
    expect(silent.callback.searchParams.get('code')).toBeNull();

    expect(lastGroupRefusal(capture)).toMatchObject({
      stage: 'authorization',
      username: LUIGI.username,
      clientId: 'dbsync-web',
      memberOf: [OTHER_GROUP],
    });

    // The shared session survived: crm-web gets a new code silently, and its
    // refresh token still works.
    const again = await authorizeOnSession(s, crm, first.browser, CRM_REDIRECT, { prompt: 'none', scope: 'openid crm' });
    expect(again.callback.searchParams.get('error')).toBeNull();
    expect((await exchange(crm, again)).access_token).toBeTruthy();
    const refreshed = await refresh(s, 'crm-web', crmTokens.refresh_token!);
    expect(refreshed.status).toBe(200);
  });

  it('a member: a code for dbsync-web without a form; dropped from the group later -> access_denied on the existing grant', async () => {
    const { s, directory } = await server();
    const crm = await discoverFor(s, 'crm-web');
    const first = await login(s, crm, { ...ADMIN, redirectUri: CRM_REDIRECT });
    await exchange(crm, first);

    const dbsync = await discoverFor(s, 'dbsync-web');
    const granted = await authorizeOnSession(s, dbsync, first.browser, DBSYNC_REDIRECT);
    expect(granted.callback.searchParams.get('error')).toBeNull();
    const tokens = await exchange(dbsync, granted);
    expect(decodeJwtPayload(tokens.id_token!)).toMatchObject({ sub: ADMIN.username, aud: 'dbsync-web' });

    // Now dbsync-web has a grant on the session: the silent path that skips
    // even the consent interaction is the one being checked.
    directory.users.get(ADMIN.username)!.memberOf = [OTHER_GROUP];
    const silent = await authorizeOnSession(s, dbsync, first.browser, DBSYNC_REDIRECT, { prompt: 'none' });
    console.log('SSO reuse with an existing grant, after removal ->', silent.callbackUrl);
    expect(silent.callback.searchParams.get('error')).toBe('access_denied');
    expect(silent.callback.searchParams.get('code')).toBeNull();
  });

  it('directory unreachable -> temporarily_unavailable back to dbsync-web, never a code', async () => {
    const { s, directory } = await server();
    const crm = await discoverFor(s, 'crm-web');
    const first = await login(s, crm, { ...ADMIN, redirectUri: CRM_REDIRECT });
    directory.down = true;
    const dbsync = await discoverFor(s, 'dbsync-web');
    const result = await authorizeOnSession(s, dbsync, first.browser, DBSYNC_REDIRECT, { prompt: 'none' });
    expect(result.callback.searchParams.get('error')).toBe('temporarily_unavailable');
    expect(result.callback.searchParams.get('code')).toBeNull();
  });

  it('an unrestricted client reusing the session costs no directory lookup', async () => {
    const { s, directory } = await server();
    const crm = await discoverFor(s, 'crm-web');
    const first = await login(s, crm, { ...LUIGI, redirectUri: CRM_REDIRECT });
    const before = directory.inspected.length;
    const again = await authorizeOnSession(s, crm, first.browser, CRM_REDIRECT, { prompt: 'none' });
    expect(again.callback.searchParams.get('code')).not.toBeNull();
    expect(directory.inspected.length).toBe(before);
  });
});

// ---------------------------------------------------------------------------
describe('c. the refresh grant of the restricted client', () => {
  it('dropped from the group -> invalid_grant, the dbsync-web chain is revoked, crm-web is untouched', async () => {
    const { s, directory, capture } = await server();
    const crm = await discoverFor(s, 'crm-web');
    const first = await login(s, crm, { ...ADMIN, redirectUri: CRM_REDIRECT });
    const crmTokens = await exchange(crm, first);
    const dbsync = await discoverFor(s, 'dbsync-web');
    const tokens = await exchange(dbsync, await authorizeOnSession(s, dbsync, first.browser, DBSYNC_REDIRECT));

    const ok = await refresh(s, 'dbsync-web', tokens.refresh_token!);
    expect(ok.status).toBe(200);
    const rotated = ok.body.refresh_token as string;
    const grantId = (await s.auth.provider.RefreshToken.find(rotated))!.grantId!;

    directory.users.get(ADMIN.username)!.memberOf = [OTHER_GROUP];
    const refused = await refresh(s, 'dbsync-web', rotated);
    console.log('refresh after removal ->', refused.status, JSON.stringify(refused.body));
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('invalid_grant');
    expect(refused.body.access_token).toBeUndefined();
    expect(await s.auth.provider.Grant.find(grantId)).toBeUndefined();
    expect(lastGroupRefusal(capture)).toMatchObject({ stage: 'refresh', clientId: 'dbsync-web', memberOf: [OTHER_GROUP] });

    // The crm-web grant is another grant: its refresh goes on.
    const crmRefresh = await refresh(s, 'crm-web', crmTokens.refresh_token!);
    expect(crmRefresh.status).toBe(200);
  });

  it('directory unreachable -> temporarily_unavailable, chain intact, and the next refresh works', async () => {
    const { s, directory } = await server();
    const dbsync = await discoverFor(s, 'dbsync-web');
    const tokens = await exchange(dbsync, await login(s, dbsync, { ...ADMIN, redirectUri: DBSYNC_REDIRECT }));

    directory.down = true;
    const refused = await refresh(s, 'dbsync-web', tokens.refresh_token!);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('temporarily_unavailable');

    directory.down = false;
    const ok = await refresh(s, 'dbsync-web', tokens.refresh_token!);
    expect(ok.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
describe('d. the token exchange of a dbsync-web subject token', () => {
  it('dropped from the group -> the exchange is refused with the gate reason', async () => {
    const { s, directory, capture } = await server();
    const dbsync = await discoverFor(s, 'dbsync-web');
    const tokens = await exchange(
      dbsync,
      await login(s, dbsync, { ...ADMIN, scope: 'openid agent', redirectUri: DBSYNC_REDIRECT }),
    );
    expect(decodeJwtPayload(tokens.access_token)).toMatchObject({ aud: 'agent-service', client_id: 'dbsync-web' });

    const allowed = await exchangeRequest(s, exchangeFields(tokens.access_token), { assertion: await assertion(s, keys) });
    expect(allowed.status).toBe(200);

    directory.users.get(ADMIN.username)!.memberOf = [OTHER_GROUP];
    const refused = await exchangeRequest(s, exchangeFields(tokens.access_token), { assertion: await assertion(s, keys) });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('invalid_grant');
    expect(capture.matching('token exchange refused').at(-1)).toMatchObject({ reason: 'client_group_not_allowed' });
    expect(lastGroupRefusal(capture)).toMatchObject({
      stage: 'token_exchange',
      clientId: 'dbsync-web',
      requestingClientId: 'agent-service',
    });
  });
});
