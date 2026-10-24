/**
 * Several resource servers, each chosen by the scope a client requests.
 *
 * RESOURCE_SERVERS_JSON maps a scope to an audience: `scope=crm` gets a token
 * with `aud` = "crm", and so on. A request that names none of those scopes
 * keeps the API_AUDIENCE, exactly as before. Internally each one has a URN
 * resource indicator (oidc-provider wants absolute URIs); the `aud` is the
 * short audience, never the indicator.
 */
import { afterEach, describe, expect, it } from 'vitest';

import { ConfigError, loadConfig } from '../src/config.js';
import { Browser } from './helpers/browser.js';
import { decodeJwtPayload, discover, exchange, login, tokenRequest } from './helpers/flow.js';
import { CLIENT_ID, REGISTERED_REDIRECT, startTestServer, type TestServer } from './helpers/server.js';

const AUDIENCE = 'https://easyoidc.test/api';
const BOTH = ['client_credentials', 'authorization_code'];
// The default (API_AUDIENCE) resource: scope `api`, machines only.
const DEFAULT_RESOURCE = { scope: 'api', grants: ['client_credentials'] };
const RESOURCE_SERVERS = [
  { scope: 'crm', audience: 'crm', grants: BOTH },
  { scope: 'analisys', audience: 'analisys', grants: BOTH },
  // The dialer api-server: machines only, never a person.
  { scope: 'predictive', audience: 'predictive', grants: ['client_credentials'] },
];
const MACHINE_ID = 'easyoidc-crm';
// 64 hex characters, the shape `openssl rand -hex 32` produces. Test-only value.
const MACHINE_SECRET = 'b4e2d1ef0c9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a392817060504';
const MARIO = { username: 'mario.rossi', password: 'Password1!' };

function machineClient(scope: string): Record<string, unknown> {
  return {
    client_id: MACHINE_ID,
    client_secret: MACHINE_SECRET,
    grant_types: ['client_credentials'],
    response_types: [],
    token_endpoint_auth_method: 'client_secret_basic',
    scope,
  };
}

const running: TestServer[] = [];

async function server(clients: Record<string, unknown>[]): Promise<TestServer> {
  const started = await startTestServer({
    users: [MARIO],
    env: {
      API_AUDIENCE: AUDIENCE,
      DEFAULT_RESOURCE_JSON: JSON.stringify(DEFAULT_RESOURCE),
      RESOURCE_SERVERS_JSON: JSON.stringify(RESOURCE_SERVERS),
      CLIENTS_JSON: JSON.stringify(clients),
    },
  });
  running.push(started);
  return started;
}

afterEach(async () => {
  while (running.length > 0) await running.pop()!.close();
});

async function machineToken(
  s: TestServer,
  fields: Record<string, string>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetch(`${s.baseUrl}/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`${MACHINE_ID}:${MACHINE_SECRET}`).toString('base64')}`,
    },
    body: new URLSearchParams({ grant_type: 'client_credentials', ...fields }).toString(),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

const USER_CLIENT = { client_id: CLIENT_ID, redirect_uris: [REGISTERED_REDIRECT] };

describe('client_credentials: the scope chooses the audience', () => {
  for (const { scope, audience } of RESOURCE_SERVERS) {
    it(`scope=${scope} gets aud=${JSON.stringify(audience)} and scope=${JSON.stringify(scope)}`, async () => {
      const s = await server([USER_CLIENT, machineClient('api crm analisys predictive')]);
      const { status, body } = await machineToken(s, { scope });
      expect(status).toBe(200);
      expect(body.scope).toBe(scope);

      const payload = decodeJwtPayload(body.access_token as string);
      console.log(`claims of a client_credentials token for scope=${scope}:`, JSON.stringify(payload));
      expect(payload).toMatchObject({
        aud: audience,
        scope,
        iss: s.baseUrl,
        sub: MACHINE_ID,
        client_id: MACHINE_ID,
      });

      // Verifiable through the JWKS with the short audience.
      const { createLocalJWKSet, jwtVerify } = await import('jose');
      const jwks = await (await fetch(`${s.baseUrl}/jwks`)).json();
      await expect(jwtVerify(body.access_token as string, createLocalJWKSet(jwks), {
        issuer: s.baseUrl,
        audience,
        algorithms: ['RS256'],
      })).resolves.toBeDefined();
    });
  }

  it('without a resource scope keeps the API_AUDIENCE', async () => {
    const s = await server([USER_CLIENT, machineClient('api crm')]);
    for (const fields of [{ scope: 'api' }, {}]) {
      const { status, body } = await machineToken(s, fields);
      expect(status).toBe(200);
      expect(decodeJwtPayload(body.access_token as string).aud).toBe(AUDIENCE);
    }
  });

  it('refuses two audiences in one request', async () => {
    const s = await server([USER_CLIENT, machineClient('crm analisys')]);
    const { status, body } = await machineToken(s, { scope: 'crm analisys' });
    expect(status).toBe(400);
    expect(body.error).toBe('invalid_scope');
    expect(body.error_description).toContain('one access token has one audience');
    expect(body.access_token).toBeUndefined();
  });

  it('refuses api together with a resource scope', async () => {
    const s = await server([USER_CLIENT, machineClient('api crm')]);
    const { status, body } = await machineToken(s, { scope: 'api crm' });
    expect(status).toBe(400);
    expect(body.error).toBe('invalid_scope');
  });

  it('refuses a scope the client is not registered for', async () => {
    const s = await server([USER_CLIENT, machineClient('crm')]);
    const { status, body } = await machineToken(s, { scope: 'analisys' });
    expect(status).toBe(400);
    expect(body.error).toBe('invalid_scope');
    expect(body.access_token).toBeUndefined();
  });

  it('accepts the URN resource indicator explicitly, and refuses one that contradicts the scope', async () => {
    const s = await server([USER_CLIENT, machineClient('crm analisys')]);
    const ok = await machineToken(s, { resource: 'urn:easyoidc:crm', scope: 'crm' });
    expect(ok.status).toBe(200);
    expect(decodeJwtPayload(ok.body.access_token as string).aud).toBe('crm');

    const contradicted = await machineToken(s, { resource: 'urn:easyoidc:crm', scope: 'analisys' });
    expect(contradicted.status).toBe(400);
    expect(contradicted.body.error).toBe('invalid_target');

    const unknown = await machineToken(s, { resource: 'urn:easyoidc:other', scope: 'crm' });
    expect(unknown.status).toBe(400);
    expect(unknown.body.error).toBe('invalid_target');
  });

  it('advertises the resource scopes in discovery', async () => {
    const s = await server([USER_CLIENT, machineClient('crm')]);
    const doc = (await (await fetch(`${s.baseUrl}/.well-known/openid-configuration`)).json()) as {
      scopes_supported: string[];
    };
    expect(doc.scopes_supported).toEqual(expect.arrayContaining(['api', 'crm', 'analisys', 'predictive']));
  });
});

describe('authorization_code: openid plus a resource scope', () => {
  it('scope "openid crm" -> a normal id token and an access token with aud "crm"', async () => {
    const s = await server([{ ...USER_CLIENT, scope: 'openid crm' }]);
    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, { ...MARIO, scope: 'openid crm' }));

    const access = decodeJwtPayload(tokens.access_token);
    console.log('claims of an authorization_code access token for scope="openid crm":', JSON.stringify(access));
    expect(access).toMatchObject({
      aud: 'crm',
      scope: 'crm',
      sub: 'mario.rossi',
      preferred_username: 'mario.rossi',
      realm: 'TEST.LOCAL',
      client_id: CLIENT_ID,
    });

    const id = decodeJwtPayload(tokens.id_token!);
    expect(id).toMatchObject({ aud: CLIENT_ID, sub: 'mario.rossi', preferred_username: 'mario.rossi' });

    // The refreshed access token keeps the same audience.
    const { refreshTokenGrant } = await import('openid-client');
    const refreshed = await refreshTokenGrant(config, tokens.refresh_token!);
    expect(decodeJwtPayload(refreshed.access_token)).toMatchObject({ aud: 'crm', scope: 'crm' });
  });

  it('scope "openid" alone still gets the API_AUDIENCE', async () => {
    const s = await server([{ ...USER_CLIENT, scope: 'openid crm' }]);
    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, MARIO));
    expect(decodeJwtPayload(tokens.access_token)).toMatchObject({ aud: AUDIENCE, scope: 'openid' });
  });

  it('openid predictive and openid api are refused to a person, even from a client with no scope allow-list', async () => {
    const s = await server([USER_CLIENT]);
    const config = await discover(s);
    for (const reserved of ['predictive', 'api']) {
      const result = await login(s, config, { ...MARIO, scope: `openid ${reserved}` });
      const callback = new URL(result.callbackUrl);
      expect(callback.searchParams.get('error'), reserved).toBe('invalid_scope');
      expect(callback.searchParams.get('error_description'), reserved)
        .toBe(`scope ${reserved} is reserved to machine-to-machine clients`);
      expect(callback.searchParams.get('code'), reserved).toBeNull();
    }
  });

  it('refuses a person the predictive resource asked for by its URN indicator', async () => {
    const s = await server([USER_CLIENT]);
    const browser = new Browser();
    const url = new URL(`${s.baseUrl}/auth`);
    url.search = new URLSearchParams({
      client_id: CLIENT_ID,
      response_type: 'code',
      scope: 'openid',
      resource: 'urn:easyoidc:predictive',
      redirect_uri: 'http://127.0.0.1:4000/callback',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
      state: 'xyz',
    }).toString();
    const response = await browser.fetch(url.toString());
    const callback = new URL(response.headers.get('location')!);
    expect(callback.searchParams.get('error')).toBe('invalid_scope');
    expect(callback.searchParams.get('error_description'))
      .toBe('scope predictive is reserved to machine-to-machine clients');
  });

  it('refuses a refresh that asks for predictive, by scope or by resource', async () => {
    const s = await server([{ ...USER_CLIENT, scope: 'openid crm' }]);
    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, { ...MARIO, scope: 'openid crm' }));
    for (const fields of [
      { scope: 'openid predictive' },
      { resource: 'urn:easyoidc:predictive' },
      { scope: 'openid api' },
    ]) {
      const { status, body } = await tokenRequest(s, {
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token!,
        ...fields,
      });
      console.log(`refresh with ${JSON.stringify(fields)}:`, status, JSON.stringify(body));
      expect(status, JSON.stringify(fields)).toBe(400);
      expect(['invalid_scope', 'invalid_target']).toContain(body.error);
      expect(body.access_token).toBeUndefined();
    }
  });

  it('a user client without the resource scope in its registration cannot reach it', async () => {
    const s = await server([USER_CLIENT]);
    const config = await discover(s);
    const result = await login(s, config, { ...MARIO, scope: 'openid crm' });
    const callback = new URL(result.callbackUrl);
    expect(callback.searchParams.get('error')).toBe('invalid_scope');
    expect(callback.searchParams.get('code')).toBeNull();
  });
});

describe('the default resource follows DEFAULT_RESOURCE_JSON, no built-in names', () => {
  async function serverWith(defaultResource: unknown, clients: Record<string, unknown>[]): Promise<TestServer> {
    const started = await startTestServer({
      users: [MARIO],
      env: {
        API_AUDIENCE: AUDIENCE,
        DEFAULT_RESOURCE_JSON: JSON.stringify(defaultResource),
        CLIENTS_JSON: JSON.stringify(clients),
      },
    });
    running.push(started);
    return started;
  }

  it('a renamed default scope works for machines and the old name means nothing', async () => {
    const s = await serverWith({ scope: 'agents', grants: ['client_credentials'] }, [USER_CLIENT, machineClient('agents')]);
    const ok = await machineToken(s, { scope: 'agents' });
    expect(ok.status).toBe(200);
    expect(decodeJwtPayload(ok.body.access_token as string)).toMatchObject({ aud: AUDIENCE, scope: 'agents' });
    const doc = (await (await fetch(`${s.baseUrl}/.well-known/openid-configuration`)).json()) as { scopes_supported: string[] };
    expect(doc.scopes_supported).toContain('agents');
    expect(doc.scopes_supported).not.toContain('api');
  });

  it('a default resource open to people too: the person token carries openid plus its scope', async () => {
    const s = await serverWith({ scope: 'api', grants: BOTH }, [USER_CLIENT]);
    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, { ...MARIO, scope: 'openid api' }));
    expect(decodeJwtPayload(tokens.access_token)).toMatchObject({ aud: AUDIENCE, scope: 'openid api' });
  });

  it('a default resource closed to machines: people still reach it with openid', async () => {
    const s = await serverWith({ scope: 'api', grants: ['authorization_code'] }, [USER_CLIENT]);
    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, MARIO));
    expect(decodeJwtPayload(tokens.access_token)).toMatchObject({ aud: AUDIENCE, scope: 'openid' });
  });
});

describe('RESOURCE_SERVERS_JSON validation', () => {
  const BASE_ENV = {
    ISSUER_URL: 'http://127.0.0.1:3000',
    DEV_STUB_USERS: '[{"username":"mario.rossi","password":"x","active":true}]',
    DATA_DIR: '',
    API_AUDIENCE: AUDIENCE,
    DEFAULT_RESOURCE_JSON: JSON.stringify(DEFAULT_RESOURCE),
    CLIENTS_JSON: JSON.stringify([USER_CLIENT]),
  };

  function problemsFor(env: Record<string, string>): string[] {
    try {
      loadConfig({ ...BASE_ENV, ...env });
      return [];
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      return (error as ConfigError).problems;
    }
  }

  const servers = (value: unknown): Record<string, string> => ({ RESOURCE_SERVERS_JSON: JSON.stringify(value) });

  it('accepts the three resource servers and exposes them in the config', () => {
    expect(problemsFor(servers(RESOURCE_SERVERS))).toEqual([]);
    expect(loadConfig({ ...BASE_ENV, ...servers(RESOURCE_SERVERS) }).resourceServers).toEqual(RESOURCE_SERVERS);
    expect(loadConfig(BASE_ENV).resourceServers).toEqual([]);
  });

  it('refuses duplicate scopes and duplicate audiences', () => {
    expect(problemsFor(servers([
      { scope: 'crm', audience: 'crm', grants: BOTH },
      { scope: 'crm', audience: 'other', grants: BOTH },
      { scope: 'analisys', audience: 'crm', grants: BOTH },
      { scope: 'predictive', audience: AUDIENCE, grants: BOTH },
    ]))).toEqual([
      'RESOURCE_SERVERS_JSON[1].scope "crm" is already used by another resource (DEFAULT_RESOURCE_JSON or RESOURCE_SERVERS_JSON)',
      'RESOURCE_SERVERS_JSON[2].audience "crm" is already used (by another resource server or by API_AUDIENCE): one audience, one resource server',
      `RESOURCE_SERVERS_JSON[3].audience "${AUDIENCE}" is already used (by another resource server or by API_AUDIENCE): one audience, one resource server`,
    ]);
  });

  it('refuses an empty audience, a missing scope and unknown fields', () => {
    expect(problemsFor(servers([
      { scope: 'crm', audience: '  ', grants: BOTH },
      { audience: 'x', grants: BOTH },
      { scope: 'analisys', audience: 'analisys', grants: BOTH, resource: 'https://x' },
    ]))).toEqual([
      'RESOURCE_SERVERS_JSON[0].audience is required',
      'RESOURCE_SERVERS_JSON[1].scope is required',
      'RESOURCE_SERVERS_JSON[2] has unknown fields: resource (only scope, audience, grants and exchange_scopes)',
    ]);
  });

  it('requires grants: a non-empty list of the three known grants, without repeats', () => {
    expect(problemsFor(servers([
      { scope: 'crm', audience: 'crm' },
      { scope: 'analisys', audience: 'analisys', grants: [] },
      { scope: 'predictive', audience: 'predictive', grants: ['client_credentials', 'refresh_token'] },
      { scope: 'other', audience: 'other', grants: ['client_credentials', 'client_credentials'] },
    ]))).toEqual([
      'RESOURCE_SERVERS_JSON[0].grants is required: a non-empty list of "client_credentials", "authorization_code", "token-exchange" without repeats, got undefined',
      'RESOURCE_SERVERS_JSON[1].grants is required: a non-empty list of "client_credentials", "authorization_code", "token-exchange" without repeats, got []',
      'RESOURCE_SERVERS_JSON[2].grants is required: a non-empty list of "client_credentials", "authorization_code", "token-exchange" without repeats, got ["client_credentials","refresh_token"]',
      'RESOURCE_SERVERS_JSON[3].grants is required: a non-empty list of "client_credentials", "authorization_code", "token-exchange" without repeats, got ["client_credentials","client_credentials"]',
    ]);
  });

  it('refuses OIDC scope names, the default resource scope and multi-token scopes', () => {
    expect(problemsFor(servers([
      { scope: 'openid', audience: 'a', grants: BOTH },
      { scope: 'api', audience: 'b', grants: BOTH },
      { scope: 'crm analisys', audience: 'c', grants: BOTH },
    ]))).toEqual([
      'RESOURCE_SERVERS_JSON[0].scope "openid" is reserved (openid, offline_access, profile belong to OpenID Connect and cannot name a resource)',
      'RESOURCE_SERVERS_JSON[1].scope "api" is already used by another resource (DEFAULT_RESOURCE_JSON or RESOURCE_SERVERS_JSON)',
      'RESOURCE_SERVERS_JSON[2].scope must be a single scope token (letters, digits, "_", ".", "-"), got "crm analisys"',
    ]);
  });

  it('requires DEFAULT_RESOURCE_JSON with API_AUDIENCE and refuses it without', () => {
    expect(problemsFor({ DEFAULT_RESOURCE_JSON: '' })).toEqual([
      'DEFAULT_RESOURCE_JSON is required when API_AUDIENCE is set: {"scope":"<scope that selects the API_AUDIENCE resource>","grants":[<"client_credentials" and/or "authorization_code" and/or "token-exchange" that may ask for it>]}',
    ]);
    expect(problemsFor({ API_AUDIENCE: '' })).toEqual([
      'DEFAULT_RESOURCE_JSON requires API_AUDIENCE (it describes the API_AUDIENCE resource)',
    ]);
    expect(loadConfig(BASE_ENV).defaultResource).toEqual(DEFAULT_RESOURCE);
  });

  it('validates DEFAULT_RESOURCE_JSON with the same rules as the other resources', () => {
    expect(problemsFor({ DEFAULT_RESOURCE_JSON: '[]' })).toEqual([
      'DEFAULT_RESOURCE_JSON must be a JSON object {"scope","grants"}',
    ]);
    expect(problemsFor({ DEFAULT_RESOURCE_JSON: JSON.stringify({ scope: 'api', audience: 'x', grants: [] }) })).toEqual([
      'DEFAULT_RESOURCE_JSON has unknown fields: audience (only scope, grants and exchange_scopes; the audience is API_AUDIENCE)',
      'DEFAULT_RESOURCE_JSON.grants is required: a non-empty list of "client_credentials", "authorization_code", "token-exchange" without repeats, got []',
    ]);
    expect(problemsFor({ DEFAULT_RESOURCE_JSON: JSON.stringify({ scope: 'openid', grants: BOTH }) })).toEqual([
      'DEFAULT_RESOURCE_JSON.scope "openid" is reserved (openid, offline_access, profile belong to OpenID Connect and cannot name a resource)',
    ]);
  });

  it('refuses a non-array, an empty array, and a missing API_AUDIENCE', () => {
    expect(problemsFor({ RESOURCE_SERVERS_JSON: '{"scope":"crm"}' })).toEqual([
      'RESOURCE_SERVERS_JSON must be a non-empty JSON array of {"scope","audience","grants"} objects',
    ]);
    expect(problemsFor({ RESOURCE_SERVERS_JSON: '[]' })).toEqual([
      'RESOURCE_SERVERS_JSON must be a non-empty JSON array of {"scope","audience","grants"} objects',
    ]);
    expect(problemsFor({ ...servers(RESOURCE_SERVERS), API_AUDIENCE: '', DEFAULT_RESOURCE_JSON: '' })).toEqual([
      'RESOURCE_SERVERS_JSON requires API_AUDIENCE (the default resource for a request that names none of these scopes)',
    ]);
  });

  it('lets a machine client list several resource scopes, and refuses one not configured', () => {
    const client = (scope: string) => JSON.stringify([USER_CLIENT, machineClient(scope)]);
    expect(problemsFor({ ...servers(RESOURCE_SERVERS), CLIENTS_JSON: client('crm analisys predictive') })).toEqual([]);
    expect(problemsFor({ ...servers(RESOURCE_SERVERS), CLIENTS_JSON: client('crm billing') })).toEqual([
      'CLIENTS_JSON[1].scope must list one or more of "api", "crm", "analisys", "predictive" (space-separated, no repeats) for a machine-to-machine client, got "crm billing"',
    ]);
  });

  it('checks the optional scope of a user client against the configured scopes', () => {
    const user = (scope: string) => JSON.stringify([{ ...USER_CLIENT, scope }]);
    expect(problemsFor({ ...servers(RESOURCE_SERVERS), CLIENTS_JSON: user('openid crm') })).toEqual([]);
    expect(problemsFor({ ...servers(RESOURCE_SERVERS), CLIENTS_JSON: user('openid crn') })).toEqual([
      'CLIENTS_JSON[0].scope must list scopes among "openid", "offline_access", "profile", "crm", "analisys" (space-separated), got "openid crn"',
    ]);
  });

  it('refuses a user client whose scope lists a machine-only scope', () => {
    const user = (scope: string) => JSON.stringify([{ ...USER_CLIENT, scope }]);
    expect(problemsFor({ ...servers(RESOURCE_SERVERS), CLIENTS_JSON: user('openid crm predictive') })).toEqual([
      'CLIENTS_JSON[0].scope lists "predictive", not open to authorization_code: a user client can never obtain it',
    ]);
    expect(problemsFor({ ...servers(RESOURCE_SERVERS), CLIENTS_JSON: user('openid api') })).toEqual([
      'CLIENTS_JSON[0].scope lists "api", not open to authorization_code: a user client can never obtain it',
    ]);
  });

  it('refuses a machine client whose scope lists a resource closed to client_credentials', () => {
    const peopleOnly = [...RESOURCE_SERVERS, { scope: 'portal', audience: 'portal', grants: ['authorization_code'] }];
    expect(problemsFor({
      ...servers(peopleOnly),
      CLIENTS_JSON: JSON.stringify([USER_CLIENT, machineClient('crm portal')]),
    })).toEqual([
      'CLIENTS_JSON[1].scope must list one or more of "api", "crm", "analisys", "predictive" (space-separated, no repeats) for a machine-to-machine client, got "crm portal"',
    ]);
  });
});
