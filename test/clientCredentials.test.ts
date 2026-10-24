/**
 * Machine-to-machine access: the OAuth2 client_credentials grant.
 *
 * A confidential client registered in CLIENTS_JSON gets an RS256 JWT for the
 * API_AUDIENCE, with no user behind it. The claims below are what oidc-provider
 * writes for a token without an account (RFC 9068): `sub` is the client_id.
 */
import { afterEach, describe, expect, it } from 'vitest';

import { ConfigError, loadConfig } from '../src/config.js';
import { createCapturingLogger } from './helpers/captureLogger.js';
import { decodeJwtPayload, tokenRequest } from './helpers/flow.js';
import { CLIENT_ID, REGISTERED_REDIRECT, startTestServer, type TestServer } from './helpers/server.js';

const AUDIENCE = 'https://easyoidc.test/api';
// The default resource as the deployments declare it: `api`, machines only.
const DEFAULT_RESOURCE_JSON = '{"scope":"api","grants":["client_credentials"]}';
const MACHINE_ID = 'erp-sync';
// 64 hex characters, the shape `openssl rand -hex 32` produces. Test-only value.
const MACHINE_SECRET = 'a3f1c0de9b8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a392817060504';

const PHONE_BAR = { client_id: CLIENT_ID, redirect_uris: [REGISTERED_REDIRECT] };

function machineClient(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    client_id: MACHINE_ID,
    client_secret: MACHINE_SECRET,
    grant_types: ['client_credentials'],
    response_types: [],
    token_endpoint_auth_method: 'client_secret_basic',
    scope: 'api',
    ...overrides,
  };
}

const running: TestServer[] = [];

async function server(
  clients: Record<string, unknown>[],
  logger?: ReturnType<typeof createCapturingLogger>,
): Promise<TestServer> {
  const started = await startTestServer({
    env: { API_AUDIENCE: AUDIENCE, DEFAULT_RESOURCE_JSON, CLIENTS_JSON: JSON.stringify(clients) },
    ...(logger ? { logger: logger.logger } : {}),
  });
  running.push(started);
  return started;
}

afterEach(async () => {
  while (running.length > 0) await running.pop()!.close();
});

function basic(id: string, secret: string): string {
  return `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')}`;
}

async function machineToken(
  s: TestServer,
  headers: Record<string, string>,
  fields: Record<string, string>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetch(`${s.baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams({ grant_type: 'client_credentials', ...fields }).toString(),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

describe('client_credentials: the token', () => {
  it('issues an RS256 JWT for the API_AUDIENCE with client_secret_basic', async () => {
    const capture = createCapturingLogger();
    const s = await server([PHONE_BAR, machineClient()], capture);

    const { status, body } = await machineToken(
      s,
      { authorization: basic(MACHINE_ID, MACHINE_SECRET) },
      { scope: 'api' },
    );
    expect(status).toBe(200);
    expect(body).toMatchObject({ token_type: 'Bearer', scope: 'api', expires_in: 3600 });
    expect(body.refresh_token).toBeUndefined();
    expect(body.id_token).toBeUndefined();

    const token = body.access_token as string;
    const header = JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString('utf8'));
    expect(header).toMatchObject({ alg: 'RS256', typ: 'at+jwt' });

    const payload = decodeJwtPayload(token);
    expect(Object.keys(payload).sort()).toEqual(
      ['aud', 'client_id', 'exp', 'iat', 'iss', 'jti', 'scope', 'sub'],
    );
    expect(payload).toMatchObject({
      aud: AUDIENCE,
      iss: s.baseUrl,
      client_id: MACHINE_ID,
      // RFC 9068 §2.2: with no resource owner, sub is the client identifier.
      sub: MACHINE_ID,
      scope: 'api',
    });
    expect(payload.preferred_username).toBeUndefined();
    expect(payload.realm).toBeUndefined();

    const issued = capture.matching('machine-to-machine access token issued');
    expect(issued).toHaveLength(1);
    expect(issued[0]).toMatchObject({
      clientId: MACHINE_ID,
      grantType: 'client_credentials',
      audience: AUDIENCE,
      scope: 'api',
    });
    expect(capture.text()).not.toContain(MACHINE_SECRET);
    expect(capture.text()).not.toContain(token);
  });

  it('verifies against the published JWKS', async () => {
    const { createLocalJWKSet, jwtVerify } = await import('jose');
    const s = await server([PHONE_BAR, machineClient()]);
    const { body } = await machineToken(
      s,
      { authorization: basic(MACHINE_ID, MACHINE_SECRET) },
      { scope: 'api' },
    );
    const jwks = await (await fetch(`${s.baseUrl}/jwks`)).json();
    const { payload } = await jwtVerify(body.access_token as string, createLocalJWKSet(jwks), {
      issuer: s.baseUrl,
      audience: AUDIENCE,
      algorithms: ['RS256'],
    });
    expect(payload.client_id).toBe(MACHINE_ID);
  });

  it('also accepts client_secret_post when the client is registered for it', async () => {
    const s = await server([
      PHONE_BAR,
      machineClient({ token_endpoint_auth_method: 'client_secret_post' }),
    ]);
    const { status, body } = await machineToken(s, {}, {
      client_id: MACHINE_ID,
      client_secret: MACHINE_SECRET,
      scope: 'api',
    });
    expect(status).toBe(200);
    expect(decodeJwtPayload(body.access_token as string)).toMatchObject({
      aud: AUDIENCE,
      client_id: MACHINE_ID,
    });
  });

  it('carries no scope when none is requested', async () => {
    const s = await server([PHONE_BAR, machineClient()]);
    const { status, body } = await machineToken(
      s,
      { authorization: basic(MACHINE_ID, MACHINE_SECRET) },
      {},
    );
    expect(status).toBe(200);
    expect(body.scope).toBeUndefined();
    expect(decodeJwtPayload(body.access_token as string).scope).toBeUndefined();
  });

  it('refuses openid, which is not a machine scope', async () => {
    const s = await server([PHONE_BAR, machineClient()]);
    const { status, body } = await machineToken(
      s,
      { authorization: basic(MACHINE_ID, MACHINE_SECRET) },
      { scope: 'openid api' },
    );
    expect(status).toBe(400);
    expect(body.error).toBe('invalid_scope');
  });

  it('refuses a resource other than the API_AUDIENCE', async () => {
    const s = await server([PHONE_BAR, machineClient()]);
    const { status, body } = await machineToken(
      s,
      { authorization: basic(MACHINE_ID, MACHINE_SECRET) },
      { scope: 'api', resource: 'https://elsewhere.test/api' },
    );
    expect(status).toBe(400);
    expect(body.error).toBe('invalid_target');
  });
});

describe('client_credentials: who may use it', () => {
  it('answers 401 invalid_client to a wrong secret', async () => {
    const capture = createCapturingLogger();
    const s = await server([PHONE_BAR, machineClient()], capture);
    const { status, body } = await machineToken(
      s,
      { authorization: basic(MACHINE_ID, `${MACHINE_SECRET}x`) },
      { scope: 'api' },
    );
    expect(status).toBe(401);
    expect(body.error).toBe('invalid_client');
    expect(body.access_token).toBeUndefined();
    expect(capture.matching('grant error')[0]).toMatchObject({ grantType: 'client_credentials' });
  });

  it('refuses the grant to the public desktop client client', async () => {
    const s = await server([PHONE_BAR, machineClient()]);
    const { status, body } = await tokenRequest(s, { grant_type: 'client_credentials', scope: 'api' });
    expect(status).toBe(400);
    // oidc-provider's own answer for a grant the client is not registered for.
    expect(body).toMatchObject({
      error: 'invalid_request',
      error_description: 'requested grant type is not allowed for this client',
    });
    expect(body.access_token).toBeUndefined();
  });

  it('does not offer the grant at all without API_AUDIENCE', async () => {
    const s = await startTestServer();
    running.push(s);
    const doc = (await (await fetch(`${s.baseUrl}/.well-known/openid-configuration`)).json()) as {
      grant_types_supported: string[];
      scopes_supported: string[];
    };
    expect(doc.grant_types_supported).not.toContain('client_credentials');
    expect(doc.scopes_supported).not.toContain('api');
  });

  it('advertises the grant and the api scope with API_AUDIENCE', async () => {
    const s = await server([PHONE_BAR, machineClient()]);
    const doc = (await (await fetch(`${s.baseUrl}/.well-known/openid-configuration`)).json()) as {
      grant_types_supported: string[];
      scopes_supported: string[];
    };
    expect(doc.grant_types_supported).toContain('client_credentials');
    expect(doc.scopes_supported).toContain('api');
  });
});

describe('client_credentials: CLIENTS_JSON validation', () => {
  const BASE_ENV = {
    ISSUER_URL: 'http://127.0.0.1:3000',
    DEV_STUB_USERS: '[{"username":"mario.rossi","password":"x","active":true}]',
    DATA_DIR: '',
    API_AUDIENCE: AUDIENCE,
    DEFAULT_RESOURCE_JSON,
  };

  function problemsFor(clients: unknown[], env: Record<string, string> = {}): string[] {
    try {
      loadConfig({ ...BASE_ENV, CLIENTS_JSON: JSON.stringify(clients), ...env });
      return [];
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      return (error as ConfigError).problems;
    }
  }

  it('accepts a complete machine client next to the desktop client, without redirect_uris', () => {
    expect(problemsFor([PHONE_BAR, machineClient()])).toEqual([]);
  });

  it('refuses a machine client without a secret', () => {
    const { client_secret: _omitted, ...withoutSecret } = machineClient();
    expect(problemsFor([PHONE_BAR, withoutSecret])).toEqual([
      'CLIENTS_JSON[1].client_secret is required for a machine-to-machine client',
    ]);
  });

  it('refuses a short secret and says how to generate one', () => {
    expect(problemsFor([machineClient({ client_secret: 'short' })])).toEqual([
      'CLIENTS_JSON[0].client_secret must be at least 32 characters (generate one with: openssl rand -hex 32)',
    ]);
  });

  it('refuses the public auth method, a mixed grant list, response types and redirects', () => {
    expect(problemsFor([machineClient({
      token_endpoint_auth_method: 'none',
      grant_types: ['client_credentials', 'authorization_code'],
      response_types: ['code'],
      redirect_uris: ['http://127.0.0.1/callback'],
      scope: 'openid',
    })])).toEqual([
      'CLIENTS_JSON[0].grant_types must be exactly ["client_credentials"] for a machine-to-machine client',
      'CLIENTS_JSON[0].token_endpoint_auth_method must be one of client_secret_basic, client_secret_post for a machine-to-machine client, got "none"',
      'CLIENTS_JSON[0].response_types must be [] for a machine-to-machine client',
      'CLIENTS_JSON[0].redirect_uris must be absent or [] for a machine-to-machine client',
      'CLIENTS_JSON[0].scope must list one or more of "api" (space-separated, no repeats) for a machine-to-machine client, got "openid"',
    ]);
  });

  it('refuses omitted fields instead of taking the desktop client defaults', () => {
    expect(problemsFor([{
      client_id: MACHINE_ID,
      client_secret: MACHINE_SECRET,
      grant_types: ['client_credentials'],
    }])).toEqual([
      'CLIENTS_JSON[0].token_endpoint_auth_method must be one of client_secret_basic, client_secret_post for a machine-to-machine client, got undefined',
      'CLIENTS_JSON[0].response_types must be [] for a machine-to-machine client',
      'CLIENTS_JSON[0].scope must list one or more of "api" (space-separated, no repeats) for a machine-to-machine client, got undefined',
    ]);
  });

  it('refuses a machine client when API_AUDIENCE is not configured', () => {
    expect(problemsFor([PHONE_BAR, machineClient()], { API_AUDIENCE: '', DEFAULT_RESOURCE_JSON: '' })).toEqual([
      'CLIENTS_JSON[1] uses grant_types client_credentials, which requires API_AUDIENCE (without an audience the token would be usable by no API)',
    ]);
  });

  it('still requires redirect_uris for a user client', () => {
    expect(problemsFor([{ client_id: CLIENT_ID }])).toEqual([
      'CLIENTS_JSON[0].redirect_uris must be a non-empty array of strings',
    ]);
  });
});
