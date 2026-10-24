/**
 * RFC 8693 token exchange, end to end: the GUI logs in and gets A′ (aud
 * agent-service), the agent-service trades it for B (aud crm, `act`), and
 * every way of asking for something else is refused without a token.
 *
 * Follows the token-exchange design notes (RFC 8693).
 */
import { randomUUID } from 'node:crypto';

import * as client from 'openid-client';
import { createRemoteJWKSet, generateKeyPair, jwtVerify, SignJWT } from 'jose';
import type { AdapterFactory } from 'oidc-provider';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import { ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from '../src/config.js';
import { Browser } from './helpers/browser.js';
import { createCapturingLogger, type CapturingLogger } from './helpers/captureLogger.js';
import { decodeJwtPayload, discover, exchange, login, randomLoopbackRedirect } from './helpers/flow.js';
import { createInspectableStore } from './helpers/memoryAdapter.js';
import { CLIENT_ID, REGISTERED_REDIRECT, startTestServer, type TestServer } from './helpers/server.js';
import {
  AGENT_CLIENT_ID,
  agentClient,
  agentKeys,
  assertion,
  contractRule,
  exchangeFields,
  exchangeRequest,
  type AgentKeys,
} from './helpers/tokenExchange.js';

const AUDIENCE = 'https://easyoidc.test/api';
const DEFAULT_RESOURCE = { scope: 'api', grants: ['client_credentials'] };
const CRM = {
  scope: 'crm',
  audience: 'crm',
  grants: ['authorization_code', 'token-exchange'],
  exchange_scopes: ['llm'],
};
const AGENT = { scope: 'agent', audience: 'agent-service', grants: ['authorization_code'] };
const MARIO = { username: 'mario.rossi', password: 'Password1!' };
const USER_CLIENT = { client_id: CLIENT_ID, redirect_uris: [REGISTERED_REDIRECT], scope: 'openid crm agent' };
const RULE_WHERE = 'CLIENTS_JSON[1].token_exchange[0]';

const MACHINE_ID = 'easyoidc-crm';
// 64 hex characters, the shape `openssl rand -hex 32` produces. Test-only value.
const MACHINE_SECRET = 'b4e2d1ef0c9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a392817060504';

let keys: AgentKeys;
beforeAll(async () => {
  keys = await agentKeys('agent-2026-10');
});

interface Started {
  s: TestServer;
  capture: CapturingLogger;
}

const running: TestServer[] = [];
afterEach(async () => {
  while (running.length > 0) await running.pop()!.close();
});

async function server(options: {
  clients?: Record<string, unknown>[];
  resources?: Record<string, unknown>[];
  env?: Record<string, string>;
  adapterFactory?: AdapterFactory;
} = {}): Promise<Started> {
  const capture = createCapturingLogger();
  const s = await startTestServer({
    users: [MARIO],
    logger: capture.logger,
    ...(options.adapterFactory ? { adapterFactory: options.adapterFactory } : {}),
    env: {
      API_AUDIENCE: AUDIENCE,
      DEFAULT_RESOURCE_JSON: JSON.stringify(DEFAULT_RESOURCE),
      RESOURCE_SERVERS_JSON: JSON.stringify(options.resources ?? [CRM, AGENT]),
      CLIENTS_JSON: JSON.stringify(
        options.clients ?? [USER_CLIENT, agentClient([keys.publicJwk], [contractRule([CLIENT_ID])])],
      ),
      ...options.env,
    },
  });
  running.push(s);
  return { s, capture };
}

/** A person's login on `browser` (a new one if absent) and the code exchange. */
async function personTokens(s: TestServer, scope: string, browser?: Browser, config?: client.Configuration) {
  const configuration = config ?? await discover(s);
  const result = await login(s, configuration, { ...MARIO, scope, ...(browser ? { browser } : {}) });
  const tokens = await exchange(configuration, result);
  return { tokens, browser: result.browser, config: configuration };
}

/** A′: scope `openid agent`, aud agent-service. */
async function aPrime(s: TestServer) {
  return personTokens(s, 'openid agent');
}

async function exchangeAs(s: TestServer, fields: Record<string, string | undefined>, signer: AgentKeys = keys) {
  return exchangeRequest(s, fields, { assertion: await assertion(s, signer) });
}

/** A refusal: status, error code, no token, and the stable reason in the log. */
function expectRefused(
  result: { status: number; body: Record<string, unknown> },
  status: number,
  error: string,
  capture?: CapturingLogger,
  reason?: string,
): void {
  expect(result.status).toBe(status);
  expect(result.body.error).toBe(error);
  expect(result.body.access_token).toBeUndefined();
  expect(result.body.refresh_token).toBeUndefined();
  if (capture && reason) {
    const refused = capture.matching('token exchange refused');
    expect(refused.at(-1)).toMatchObject({ reason, clientId: AGENT_CLIENT_ID });
  }
}

async function machineToken(s: TestServer, scope: string): Promise<string> {
  const response = await fetch(`${s.baseUrl}/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`${MACHINE_ID}:${MACHINE_SECRET}`).toString('base64')}`,
    },
    body: new URLSearchParams({ grant_type: 'client_credentials', scope }).toString(),
  });
  const body = (await response.json()) as Record<string, unknown>;
  expect(response.status).toBe(200);
  return body.access_token as string;
}

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

const AGENT_WITH_MACHINES = { ...AGENT, grants: ['authorization_code', 'client_credentials'] };

describe('token exchange: the subject token registry (D1)', () => {
  it('records A′, and neither A, nor a client_credentials token, nor B', async () => {
    const store = createInspectableStore();
    const { s } = await server({
      adapterFactory: store.adapterFactory,
      resources: [CRM, AGENT_WITH_MACHINES],
      clients: [
        USER_CLIENT,
        agentClient([keys.publicJwk], [contractRule([CLIENT_ID])]),
        machineClient('agent'),
      ],
    });
    const records = () => store.entries('SubjectTokenRecord');

    const { tokens: primeTokens, browser, config } = await aPrime(s);
    const prime = decodeJwtPayload(primeTokens.access_token);
    expect(prime.aud).toBe('agent-service');
    expect([...records().keys()]).toEqual([prime.jti]);
    const record = records().get(prime.jti as string)!;
    expect(record).toEqual({
      accountId: 'mario.rossi',
      clientId: CLIENT_ID,
      grantId: expect.any(String),
      gty: 'authorization_code',
      aud: 'agent-service',
      exp: prime.exp,
    });

    // A, on the same browser session: aud crm is no subject audience.
    const { tokens: aTokens } = await personTokens(s, 'openid crm', browser, config);
    expect(decodeJwtPayload(aTokens.access_token).aud).toBe('crm');
    // A client_credentials token for agent-service: no person behind it.
    const machine = decodeJwtPayload(await machineToken(s, 'agent'));
    expect(machine.aud).toBe('agent-service');
    // B.
    const b = await exchangeAs(s, exchangeFields(primeTokens.access_token));
    expect(b.status).toBe(200);

    expect([...records().keys()]).toEqual([prime.jti]);
  });

  it('registers the grant before any client is validated: the exchange client is a valid static client', async () => {
    const { s } = await server();
    const found = await s.auth.provider.Client.find(AGENT_CLIENT_ID);
    expect(found).toBeDefined();
    expect(found!.grantTypes).toEqual([TOKEN_EXCHANGE_GRANT_TYPE]);
    expect(found!.tokenEndpointAuthMethod).toBe('private_key_jwt');
  });
});

describe('token exchange: issuing B', () => {
  it('1. issues B with act, aud crm, scope, 900 s and no refresh token', async () => {
    const { s } = await server();
    const { tokens } = await aPrime(s);
    const prime = decodeJwtPayload(tokens.access_token);
    expect(prime).toMatchObject({ aud: 'agent-service', scope: 'agent', sub: 'mario.rossi' });

    const { status, body } = await exchangeAs(s, exchangeFields(tokens.access_token));
    expect(status).toBe(200);
    expect(Object.keys(body).sort()).toEqual(['access_token', 'expires_in', 'issued_token_type', 'scope', 'token_type']);
    expect(body).toMatchObject({
      issued_token_type: ACCESS_TOKEN_TYPE,
      token_type: 'Bearer',
      expires_in: 900,
      scope: 'crm llm',
    });

    const b = body.access_token as string;
    const jwks = createRemoteJWKSet(new URL(`${s.baseUrl}/jwks`));
    const { payload, protectedHeader } = await jwtVerify(b, jwks, {
      issuer: s.baseUrl,
      audience: 'crm',
      typ: 'at+jwt',
      algorithms: ['RS256'],
    });
    expect(protectedHeader.typ).toBe('at+jwt');
    expect(payload).toMatchObject({
      sub: 'mario.rossi',
      aud: 'crm',
      scope: 'crm llm',
      client_id: AGENT_CLIENT_ID,
      act: { sub: AGENT_CLIENT_ID },
      preferred_username: 'mario.rossi',
      realm: 'TEST.LOCAL',
    });
    expect(payload.exp! - payload.iat!).toBe(900);
    expect(payload.jti).not.toBe(prime.jti);
  });

  it('16. logs the exchange, and never a token value', async () => {
    const { s, capture } = await server();
    const { tokens } = await aPrime(s);
    const prime = decodeJwtPayload(tokens.access_token);
    const { body } = await exchangeAs(s, exchangeFields(tokens.access_token));
    const b = decodeJwtPayload(body.access_token as string);

    const issued = capture.matching('token exchange: delegated access token issued');
    expect(issued).toHaveLength(1);
    expect(issued[0]).toMatchObject({
      level: 'info',
      clientId: AGENT_CLIENT_ID,
      grantType: TOKEN_EXCHANGE_GRANT_TYPE,
      username: 'mario.rossi',
      rule: RULE_WHERE,
      subjectJti: prime.jti,
      subjectClientId: CLIENT_ID,
      jti: b.jti,
      audience: 'crm',
      scope: 'crm llm',
      expiresIn: 900,
    });
    expect(capture.text()).not.toContain(tokens.access_token);
    expect(capture.text()).not.toContain(body.access_token as string);
  });

  it('21. exchanges a renewed A′ (gty authorization_code refresh_token)', async () => {
    const store = createInspectableStore();
    const { s } = await server({ adapterFactory: store.adapterFactory });
    const { tokens, config } = await aPrime(s);
    const renewed = await client.refreshTokenGrant(config, tokens.refresh_token!);
    const payload = decodeJwtPayload(renewed.access_token);
    expect(payload.aud).toBe('agent-service');
    expect(store.entries('SubjectTokenRecord').get(payload.jti as string)?.gty)
      .toBe('authorization_code refresh_token');

    const { status, body } = await exchangeAs(s, exchangeFields(renewed.access_token));
    expect(status).toBe(200);
    expect(decodeJwtPayload(body.access_token as string)).toMatchObject({ aud: 'crm', act: { sub: AGENT_CLIENT_ID } });
  });

  it('17. advertises the grant in discovery only when a client has rules', async () => {
    const discovery = async (s: TestServer) =>
      ((await (await fetch(`${s.baseUrl}/.well-known/openid-configuration`)).json()) as {
        grant_types_supported: string[];
      }).grant_types_supported;

    const { s: withRules } = await server();
    expect(await discovery(withRules)).toContain(TOKEN_EXCHANGE_GRANT_TYPE);

    // 25. Regression: without an exchange client nothing changes.
    const { s: without } = await server({ clients: [USER_CLIENT] });
    expect(await discovery(without)).not.toContain(TOKEN_EXCHANGE_GRANT_TYPE);
    const asked = await exchangeRequest(without, { ...exchangeFields('x'), client_id: CLIENT_ID });
    expect(asked.status).toBe(400);
    expect(asked.body.error).toBe('unsupported_grant_type');
  });
});

describe('token exchange: refused subjects', () => {
  it('2. refuses A (aud crm) as subject', async () => {
    const { s, capture } = await server();
    const { tokens } = await personTokens(s, 'openid crm');
    expect(decodeJwtPayload(tokens.access_token).aud).toBe('crm');
    const refused = await exchangeAs(s, exchangeFields(tokens.access_token));
    expectRefused(refused, 400, 'invalid_grant', capture, 'subject_audience');
    expect(refused.body.error_description).toBe('subject_token audience is not accepted by this rule');
  });

  it('3. refuses B as subject; with a rule whose subject audience is crm the reason is subject_delegated', async () => {
    const AGENT2 = { scope: 'agent2', audience: 'agent2', grants: ['token-exchange'], exchange_scopes: ['llm'] };
    const crmToAgent2 = {
      subject: {
        token_type: ACCESS_TOKEN_TYPE,
        audience: 'crm',
        client_ids: [AGENT_CLIENT_ID],
        issued_by_grants: ['authorization_code', 'refresh_token'],
      },
      issue: { token_type: ACCESS_TOKEN_TYPE, audience: 'agent2', scope: 'agent2 llm', ttl_seconds: 900, refresh_token: false },
    };
    const store = createInspectableStore();
    const { s, capture } = await server({
      adapterFactory: store.adapterFactory,
      resources: [CRM, AGENT, AGENT2],
      clients: [USER_CLIENT, agentClient([keys.publicJwk], [contractRule([CLIENT_ID]), crmToAgent2])],
    });
    const { tokens } = await aPrime(s);
    const issued = await exchangeAs(s, exchangeFields(tokens.access_token));
    expect(issued.status).toBe(200);
    const b = issued.body.access_token as string;
    // aud crm is a subject audience here, yet B is never recorded: it carries `act`.
    expect(store.entries('SubjectTokenRecord').has(decodeJwtPayload(b).jti as string)).toBe(false);
    expect(store.entries('SubjectTokenRecord').has(decodeJwtPayload(tokens.access_token).jti as string)).toBe(true);

    // Through the contract rule: B has aud crm, not agent-service.
    expectRefused(await exchangeAs(s, exchangeFields(b)), 400, 'invalid_grant', capture, 'subject_audience');

    // Through the crm -> agent2 rule: the audience fits, `act` does not.
    const again = await exchangeAs(s, { ...exchangeFields(b), audience: 'agent2' });
    expectRefused(again, 400, 'invalid_grant', capture, 'subject_delegated');
    expect(again.body.error_description).toBe('a delegated token cannot be exchanged again');
    expect(capture.matching('token exchange refused').at(-1)).toMatchObject({
      rule: 'CLIENTS_JSON[1].token_exchange[1]',
      subjectJti: decodeJwtPayload(b).jti,
    });
  });

  it('4. refuses a client_credentials token as subject', async () => {
    const { s, capture } = await server({
      resources: [CRM, AGENT_WITH_MACHINES],
      clients: [USER_CLIENT, agentClient([keys.publicJwk], [contractRule([CLIENT_ID])]), machineClient('agent')],
    });
    const machine = await machineToken(s, 'agent');
    expect(decodeJwtPayload(machine)).toMatchObject({ aud: 'agent-service', sub: MACHINE_ID });
    const refused = await exchangeAs(s, exchangeFields(machine));
    expectRefused(refused, 400, 'invalid_grant', capture, 'subject_not_person');
    expect(refused.body.error_description).toBe('subject_token was not issued to a person');
  });

  it('9. refuses the exchange once the account is disabled after the login, without revoking the chain', async () => {
    const { s, capture } = await server();
    const { tokens } = await aPrime(s);

    s.stub.setActive('mario.rossi', false);
    expectRefused(await exchangeAs(s, exchangeFields(tokens.access_token)), 400, 'invalid_grant', capture, 'account_disabled');
    expect(capture.matching('token exchange rejected by an account gate')[0]).toMatchObject({
      reason: 'account_disabled',
      revoked: false,
    });

    // D6: nothing of the person's chain was revoked.
    s.stub.setActive('mario.rossi', true);
    expect((await exchangeAs(s, exchangeFields(tokens.access_token))).status).toBe(200);
  });

  it('10. refuses an expired subject', async () => {
    const { s, capture } = await server({ env: { ACCESS_TOKEN_TTL: '1' } });
    const { tokens } = await aPrime(s);
    await new Promise((resolve) => setTimeout(resolve, 2100));
    const refused = await exchangeAs(s, exchangeFields(tokens.access_token));
    expectRefused(refused, 400, 'invalid_grant', capture, 'subject_expired');
    expect(refused.body.error_description).toBe('subject_token is expired');
  });

  it('11. refuses a revoked subject', async () => {
    const { s, capture } = await server();
    const { tokens } = await aPrime(s);
    const revocation = await fetch(`${s.baseUrl}/token/revocation`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        token: tokens.refresh_token!,
        token_type_hint: 'refresh_token',
      }).toString(),
    });
    expect(revocation.status).toBe(200);

    const refused = await exchangeAs(s, exchangeFields(tokens.access_token));
    expectRefused(refused, 400, 'invalid_grant', capture, 'subject_revoked');
    expect(refused.body.error_description).toBe('subject_token has been revoked');
  });

  it('20. refuses a subject with a tampered signature or another issuer', async () => {
    const { s, capture } = await server();
    const { tokens } = await aPrime(s);

    const [header, body, signature] = tokens.access_token.split('.') as [string, string, string];
    const middle = Math.floor(signature.length / 2);
    const flipped = signature[middle] === 'A' ? 'B' : 'A';
    const tampered = `${header}.${body}.${signature.slice(0, middle)}${flipped}${signature.slice(middle + 1)}`;
    expectRefused(await exchangeAs(s, exchangeFields(tampered)), 400, 'invalid_grant', capture, 'subject_invalid');

    // A JWT of the right shape, signed by a stranger and naming the server's kid.
    const { keys: serverKeys } = (await (await fetch(`${s.baseUrl}/jwks`)).json()) as { keys: { kid: string }[] };
    const stranger = await generateKeyPair('RS256');
    const prime = decodeJwtPayload(tokens.access_token);
    const forged = await new SignJWT({ client_id: CLIENT_ID, scope: 'agent' })
      .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: serverKeys[0]!.kid })
      .setIssuer('https://evil.test')
      .setSubject('mario.rossi')
      .setAudience('agent-service')
      .setJti(prime.jti as string)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(stranger.privateKey);
    const refused = await exchangeAs(s, exchangeFields(forged));
    expectRefused(refused, 400, 'invalid_grant', capture, 'subject_invalid');
    expect(refused.body.error_description).toBe('subject_token is invalid');
  });

  it('22. fails closed when the subject token registry is unavailable', async () => {
    const store = createInspectableStore();
    const { s, capture } = await server({ adapterFactory: store.adapterFactory });
    const { tokens } = await aPrime(s);
    store.failFind('SubjectTokenRecord');

    const refused = await exchangeAs(s, exchangeFields(tokens.access_token));
    expectRefused(refused, 400, 'temporarily_unavailable', capture, 'registry_unavailable');
    expect(capture.matching('the subject token registry could not be read')).toHaveLength(1);
    expect(capture.matching('delegated access token issued')).toHaveLength(0);
  });

  it('24. refuses a subject obtained by a client outside subject.client_ids', async () => {
    const OTHER = { client_id: 'other-ui', redirect_uris: [REGISTERED_REDIRECT], scope: 'openid agent' };
    const { s, capture } = await server({
      clients: [USER_CLIENT, agentClient([keys.publicJwk], [contractRule([CLIENT_ID])]), OTHER],
    });
    const config = await client.discovery(
      new URL(s.baseUrl),
      'other-ui',
      { token_endpoint_auth_method: 'none' },
      client.None(),
      { execute: [client.allowInsecureRequests] },
    );
    const result = await login(s, config, { ...MARIO, scope: 'openid agent', redirectUri: randomLoopbackRedirect() });
    const tokens = await exchange(config, result);
    expect(decodeJwtPayload(tokens.access_token)).toMatchObject({ aud: 'agent-service', client_id: 'other-ui' });

    expectRefused(await exchangeAs(s, exchangeFields(tokens.access_token)), 400, 'invalid_grant', capture, 'subject_client');
  });
});

describe('token exchange: refused requests', () => {
  it('5. refuses a scope outside the rule, and a request without scope', async () => {
    const { s, capture } = await server();
    const { tokens } = await aPrime(s);
    const beyond = await exchangeAs(s, { ...exchangeFields(tokens.access_token), scope: 'llm admin' });
    expectRefused(beyond, 400, 'invalid_target', capture, 'no_rule_scope');
    expect(beyond.body.error_description).toBe('scope admin exceeds the token exchange rule');

    const none = await exchangeAs(s, { ...exchangeFields(tokens.access_token), scope: undefined });
    expectRefused(none, 400, 'invalid_target', capture, 'scope_missing');
    expect(none.body.error_description).toBe('scope is required');
  });

  it('6. refuses an audience outside the rule', async () => {
    const { s, capture } = await server();
    const { tokens } = await aPrime(s);
    const refused = await exchangeAs(s, { ...exchangeFields(tokens.access_token), audience: 'analisys' });
    expectRefused(refused, 400, 'invalid_target', capture, 'no_rule_audience');
    expect(refused.body.error_description).toBe('audience analisys is not allowed for this client');
  });

  it('19. refuses a request that carries resource', async () => {
    const { s, capture } = await server();
    const { tokens } = await aPrime(s);
    const refused = await exchangeAs(s, { ...exchangeFields(tokens.access_token), resource: 'urn:easyoidc:crm' });
    expectRefused(refused, 400, 'invalid_target', capture, 'resource_parameter');
    expect(refused.body.error_description).toBe('resource is not supported by this grant: use audience');
  });

  it('12. refuses subject_token_type other than access_token', async () => {
    const { s, capture } = await server();
    const { tokens } = await aPrime(s);
    const refused = await exchangeAs(s, {
      ...exchangeFields(tokens.access_token),
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    });
    expectRefused(refused, 400, 'invalid_request', capture, 'token_type');
    expect(refused.body.error_description).toBe(`subject_token_type must be ${ACCESS_TOKEN_TYPE}`);
  });

  it('13. refuses requested_token_type other than access_token, or absent', async () => {
    const { s, capture } = await server();
    const { tokens } = await aPrime(s);
    const other = await exchangeAs(s, {
      ...exchangeFields(tokens.access_token),
      requested_token_type: 'urn:ietf:params:oauth:token-type:refresh_token',
    });
    expectRefused(other, 400, 'invalid_request', capture, 'token_type');

    const absent = await exchangeAs(s, { ...exchangeFields(tokens.access_token), requested_token_type: undefined });
    expectRefused(absent, 400, 'invalid_request', capture, 'parameter_missing');
    expect(absent.body.error_description).toBe('requested_token_type is required');

    const noSubject = await exchangeAs(s, { ...exchangeFields(tokens.access_token), subject_token: undefined });
    expectRefused(noSubject, 400, 'invalid_request', capture, 'parameter_missing');
    expect(noSubject.body.error_description).toBe('subject_token is required');
  });

  it('14. refuses actor_token', async () => {
    const { s, capture } = await server();
    const { tokens } = await aPrime(s);
    const refused = await exchangeAs(s, {
      ...exchangeFields(tokens.access_token),
      actor_token: tokens.access_token,
      actor_token_type: ACCESS_TOKEN_TYPE,
    });
    expectRefused(refused, 400, 'invalid_request', capture, 'actor_token');
    expect(refused.body.error_description).toBe('actor tokens are not supported');
  });
});

describe('token exchange: client authentication', () => {
  it('7. refuses the grant to a client without rules', async () => {
    const { s } = await server({
      resources: [CRM, AGENT_WITH_MACHINES],
      clients: [USER_CLIENT, agentClient([keys.publicJwk], [contractRule([CLIENT_ID])]), machineClient('agent')],
    });
    const { tokens } = await aPrime(s);
    const refused = await exchangeRequest(s, exchangeFields(tokens.access_token), {
      headers: { authorization: `Basic ${Buffer.from(`${MACHINE_ID}:${MACHINE_SECRET}`).toString('base64')}` },
    });
    expectRefused(refused, 400, 'invalid_request');
    expect(refused.body.error_description).toBe('requested grant type is not allowed for this client');
  });

  it('8. refuses an agent-service authenticating with a secret', async () => {
    const { s } = await server();
    const { tokens } = await aPrime(s);
    const refused = await exchangeRequest(s, exchangeFields(tokens.access_token), {
      headers: { authorization: `Basic ${Buffer.from(`${AGENT_CLIENT_ID}:${MACHINE_SECRET}`).toString('base64')}` },
    });
    expectRefused(refused, 401, 'invalid_client');
  });

  it('15. refuses a replayed client assertion', async () => {
    const { s } = await server();
    const { tokens } = await aPrime(s);
    const once = await assertion(s, keys);
    expect((await exchangeRequest(s, exchangeFields(tokens.access_token), { assertion: once })).status).toBe(200);
    expectRefused(await exchangeRequest(s, exchangeFields(tokens.access_token), { assertion: once }), 401, 'invalid_client');
  });

  it('23. accepts an assertion signed with the new kid during rotation and refuses the old kid once removed', async () => {
    const oldKeys = keys;
    const newKeys = await agentKeys(`agent-${randomUUID()}`);

    // During the rotation both kids are in `jwks`.
    const { s: rotating } = await server({
      clients: [USER_CLIENT, agentClient([oldKeys.publicJwk, newKeys.publicJwk], [contractRule([CLIENT_ID])])],
    });
    const { tokens: duringRotation } = await aPrime(rotating);
    expect((await exchangeAs(rotating, exchangeFields(duringRotation.access_token), newKeys)).status).toBe(200);
    expect((await exchangeAs(rotating, exchangeFields(duringRotation.access_token), oldKeys)).status).toBe(200);

    // After it, only the new kid is left.
    const { s: rotated } = await server({
      clients: [USER_CLIENT, agentClient([newKeys.publicJwk], [contractRule([CLIENT_ID])])],
    });
    const { tokens } = await aPrime(rotated);
    expectRefused(await exchangeAs(rotated, exchangeFields(tokens.access_token), oldKeys), 401, 'invalid_client');
    expect((await exchangeAs(rotated, exchangeFields(tokens.access_token), newKeys)).status).toBe(200);
  });
});
