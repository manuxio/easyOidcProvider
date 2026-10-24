/**
 * The oidc-provider wiring (src/provider/index.ts) seen from outside, for what
 * the other suites leave implicit:
 *
 *   - the resource indicator naming of RESOURCE_SERVERS_JSON entries;
 *   - renderError: the Italian error page, never a stack trace;
 *   - WHICH requests run the account gates, and with which stage (gateStageOf,
 *     principalOf): the login, every refresh and every token exchange do, the
 *     code exchange and userinfo do not — by design, see the comment on
 *     gateStageOf (a code lives 60 s and is minted right after the gates ran).
 *
 * The gates are observed by wrapping the first gate's check, the same seam
 * test/e2e.test.ts uses to make a gate fail.
 */
import * as client from 'openid-client';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import type { AccountGateContext } from '../../src/gates/index.js';
import { resourceIndicatorFor } from '../../src/provider/index.js';
import { Browser } from '../helpers/browser.js';
import { discover, exchange, login, tokenRequest } from '../helpers/flow.js';
import { CLIENT_ID, REGISTERED_REDIRECT, startTestServer, type TestServer } from '../helpers/server.js';
import {
  AGENT_CLIENT_ID,
  agentClient,
  agentKeys,
  assertion,
  contractRule,
  exchangeFields,
  exchangeRequest,
  type AgentKeys,
} from '../helpers/tokenExchange.js';

const MARIO = { username: 'mario.rossi', password: 'Password1!' };
const REALM = 'TEST.LOCAL';

const running: TestServer[] = [];
afterEach(async () => {
  while (running.length > 0) await running.pop()!.close();
});

async function server(env?: Record<string, string>): Promise<TestServer> {
  const s = await startTestServer({ users: [MARIO], ...(env ? { env } : {}) });
  running.push(s);
  return s;
}

/** Records every context the first gate is asked about, and still lets it decide. */
function watchGates(s: TestServer): AccountGateContext[] {
  const seen: AccountGateContext[] = [];
  const gate = s.auth.gates[0]!;
  const original = gate.check.bind(gate);
  (gate as { check: unknown }).check = async (context: AccountGateContext) => {
    seen.push({ ...context });
    return original(context);
  };
  return seen;
}

describe('resourceIndicatorFor', () => {
  it('turns a resource scope into an absolute URN, as RFC 8707 indicators must be', () => {
    expect(resourceIndicatorFor('crm')).toBe('urn:easyoidc:crm');
    expect(resourceIndicatorFor('agent')).toBe('urn:easyoidc:agent');
    expect(resourceIndicatorFor('crm')).not.toBe(resourceIndicatorFor('agent'));
  });
});

describe('renderError', () => {
  it('answers a refused authorization request with the Italian error page', async () => {
    const s = await server();
    const url = new URL(`${s.baseUrl}/auth`);
    url.search = new URLSearchParams({
      client_id: CLIENT_ID,
      response_type: 'code',
      scope: 'openid',
      redirect_uri: 'http://evil.example.com/callback',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
    }).toString();

    const response = await new Browser().fetch(url.toString());
    expect(response.status).toBe(400);
    expect(response.headers.get('content-type')).toMatch(/text\/html/);
    const html = await response.text();
    expect(html).toContain('<html lang="it">');
    expect(html).toContain('<h1>Accesso non riuscito</h1>');
    expect(html).toContain('<dt>error</dt><dd>invalid_redirect_uri</dd>');
    expect(html).toContain('<dt>error_description</dt>');
    expect(html).not.toMatch(/\bat \S+ \(/);
  });

  it('uses the same page for an unknown client', async () => {
    const s = await server();
    const url = new URL(`${s.baseUrl}/auth`);
    url.search = new URLSearchParams({
      client_id: 'no-such-client',
      response_type: 'code',
      scope: 'openid',
      redirect_uri: REGISTERED_REDIRECT,
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
    }).toString();

    const response = await new Browser().fetch(url.toString());
    expect(response.status).toBe(400);
    expect(response.headers.get('location')).toBeNull();
    const html = await response.text();
    expect(html).toContain('<h1>Accesso non riuscito</h1>');
    expect(html).toContain('<dd>invalid_client</dd>');
  });
});

describe('which requests run the account gates', () => {
  it('login: stage login, with the client; the code exchange: no gate at all', async () => {
    const s = await server();
    const seen = watchGates(s);
    const config = await discover(s);
    const result = await login(s, config, MARIO);
    expect(seen.map((context) => context.stage)).toEqual(['login']);
    expect(seen[0]).toMatchObject({ username: 'mario.rossi', clientId: CLIENT_ID });

    await exchange(config, result);
    expect(seen.map((context) => context.stage)).toEqual(['login']);
  });

  it('every refresh: stage refresh, with the principal built from the realm', async () => {
    const s = await server();
    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, MARIO));
    const seen = watchGates(s);

    const first = await client.refreshTokenGrant(config, tokens.refresh_token!);
    await client.refreshTokenGrant(config, first.refresh_token!);
    expect(seen).toEqual([
      { principal: `mario.rossi@${REALM}`, username: 'mario.rossi', stage: 'refresh', clientId: CLIENT_ID },
      { principal: `mario.rossi@${REALM}`, username: 'mario.rossi', stage: 'refresh', clientId: CLIENT_ID },
    ]);
  });

  it('userinfo runs no gate: it mints nothing', async () => {
    const s = await server();
    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, MARIO));
    const seen = watchGates(s);

    const response = await fetch(`${s.baseUrl}/me`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
    expect(response.status).toBe(200);
    expect(seen).toEqual([]);
  });

  it('a code minted before the account was disabled is still exchanged: the refresh is the enforcement point', async () => {
    const s = await server();
    const config = await discover(s);
    const result = await login(s, config, MARIO);
    s.stub.setActive('mario.rossi', false);

    const tokens = await exchange(config, result);
    expect(tokens.access_token).toBeTypeOf('string');

    const refused = await tokenRequest(s, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token! });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('invalid_grant');
  });
});

describe('the token exchange runs the gates too', () => {
  let keys: AgentKeys;
  beforeAll(async () => {
    keys = await agentKeys('agent-provider-gates');
  });

  it('stage token_exchange, the exchanging client, and the client the subject was issued to', async () => {
    const s = await server({
      API_AUDIENCE: 'https://easyoidc.test/api',
      DEFAULT_RESOURCE_JSON: JSON.stringify({ scope: 'api', grants: ['client_credentials'] }),
      RESOURCE_SERVERS_JSON: JSON.stringify([
        { scope: 'crm', audience: 'crm', grants: ['authorization_code', 'token-exchange'], exchange_scopes: ['llm'] },
        { scope: 'agent', audience: 'agent-service', grants: ['authorization_code'] },
      ]),
      CLIENTS_JSON: JSON.stringify([
        { client_id: CLIENT_ID, redirect_uris: [REGISTERED_REDIRECT], scope: 'openid crm agent' },
        agentClient([keys.publicJwk], [contractRule([CLIENT_ID])]),
      ]),
    });
    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, { ...MARIO, scope: 'openid agent' }));
    const seen = watchGates(s);

    const exchanged = await exchangeRequest(s, exchangeFields(tokens.access_token), {
      assertion: await assertion(s, keys),
    });
    expect(exchanged.status).toBe(200);
    expect(seen).toEqual([
      {
        principal: `mario.rossi@${REALM}`,
        username: 'mario.rossi',
        stage: 'token_exchange',
        clientId: AGENT_CLIENT_ID,
        subjectClientId: CLIENT_ID,
      },
    ]);
  });
});
