/**
 * A second resource on the same session, asked for with prompt=none.
 *
 * One access token has one audience (RFC 8707, resourceFromScope), so crm-web
 * logs in with `openid crm` and then gets the agent-service token with a
 * silent `/auth?prompt=none&scope=openid agent` on the same browser session
 * (oidc-client-ts signinSilent). loadExistingGrant widens the session's grant
 * with the scopes the client is registered for; anything else is refused as
 * before.
 */
import * as client from 'openid-client';
import { afterEach, describe, expect, it } from 'vitest';

import { Browser } from './helpers/browser.js';
import { decodeJwtPayload, discover, exchange, login, type LoginResult } from './helpers/flow.js';
import { CLIENT_ID, startTestServer, type TestServer } from './helpers/server.js';

const AUDIENCE = 'https://easyoidc.test/api';
const BOTH = ['client_credentials', 'authorization_code'];
const RESOURCE_SERVERS = [
  { scope: 'crm', audience: 'crm', grants: BOTH },
  { scope: 'agent', audience: 'agent-service', grants: ['authorization_code'] },
  { scope: 'analisys', audience: 'analisys', grants: BOTH },
];
const MARIO = { username: 'mario.rossi', password: 'Password1!' };
// A web client like crm-web: exact redirect URI, no native_client_prompt.
const REDIRECT = 'http://127.0.0.1:4000/callback';
const WEB_CLIENT = {
  client_id: CLIENT_ID,
  application_type: 'web',
  redirect_uris: [REDIRECT],
  scope: 'openid crm agent',
};

const running: TestServer[] = [];

async function server(clients: Record<string, unknown>[] = [WEB_CLIENT]): Promise<TestServer> {
  const started = await startTestServer({
    users: [MARIO],
    env: {
      API_AUDIENCE: AUDIENCE,
      DEFAULT_RESOURCE_JSON: JSON.stringify({ scope: 'api', grants: ['client_credentials'] }),
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

/** One `/auth?prompt=none` hop, as the hidden iframe of signinSilent makes it. */
async function silent(
  s: TestServer,
  config: client.Configuration,
  browser: Browser,
  scope: string,
  redirectUri = REDIRECT,
): Promise<LoginResult & { callback: URL }> {
  const codeVerifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri,
    scope,
    prompt: 'none',
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    state,
  });
  const { callbackUrl, visited } = await browser.follow(url.toString(), s.baseUrl);
  if (!callbackUrl) throw new Error(`prompt=none did not redirect back: ${visited.join(' -> ')}`);
  return { callbackUrl, codeVerifier, state, redirectUri, browser, callback: new URL(callbackUrl) };
}

describe('prompt=none for a second resource on the same session', () => {
  it('login with openid crm, then openid agent silently -> a code, a token for agent-service, both scopes in the grant', async () => {
    const s = await server();
    const config = await discover(s);
    const first = await login(s, config, { ...MARIO, scope: 'openid crm', redirectUri: REDIRECT });
    const crm = await exchange(config, first);
    expect(decodeJwtPayload(crm.access_token)).toMatchObject({ aud: 'crm', scope: 'crm' });

    const second = await silent(s, config, first.browser, 'openid agent');
    console.log('prompt=none openid agent ->', second.callbackUrl);
    expect(second.callback.searchParams.get('error')).toBeNull();
    expect(second.callback.searchParams.get('code')).not.toBeNull();

    const agent = await exchange(config, second);
    const access = decodeJwtPayload(agent.access_token);
    expect(access).toMatchObject({ aud: 'agent-service', scope: 'agent', sub: 'mario.rossi', client_id: CLIENT_ID });

    // The same grant now holds both resources.
    const provider = s.auth.provider;
    const refresh = await provider.RefreshToken.find(agent.refresh_token!);
    const grant = await provider.Grant.find(refresh!.grantId!);
    expect(grant!.getResourceScopeEncountered('urn:easyoidc:crm').split(' ')).toContain('crm');
    expect(grant!.getResourceScopeEncountered('urn:easyoidc:agent').split(' ')).toContain('agent');
    const crmRefresh = await provider.RefreshToken.find(crm.refresh_token!);
    expect(crmRefresh!.grantId).toBe(refresh!.grantId);

    // The A' refresh keeps working on that grant, and so does the crm one.
    const refreshedAgent = await client.refreshTokenGrant(config, agent.refresh_token!);
    expect(decodeJwtPayload(refreshedAgent.access_token)).toMatchObject({ aud: 'agent-service', scope: 'agent' });
    const refreshedCrm = await client.refreshTokenGrant(config, crm.refresh_token!);
    expect(decodeJwtPayload(refreshedCrm.access_token)).toMatchObject({ aud: 'crm', scope: 'crm' });
  });

  it('a resource scope the client is not registered for -> invalid_scope, no code', async () => {
    const s = await server();
    const config = await discover(s);
    const first = await login(s, config, { ...MARIO, scope: 'openid crm', redirectUri: REDIRECT });
    const second = await silent(s, config, first.browser, 'openid analisys');
    console.log('prompt=none openid analisys ->', second.callbackUrl);
    expect(second.callback.searchParams.get('error')).toBe('invalid_scope');
    expect(second.callback.searchParams.get('code')).toBeNull();
  });

  it('without a session -> login_required', async () => {
    const s = await server();
    const config = await discover(s);
    const result = await silent(s, config, new Browser(), 'openid agent');
    console.log('prompt=none without a session ->', result.callbackUrl);
    expect(result.callback.searchParams.get('error')).toBe('login_required');
    expect(result.callback.searchParams.get('code')).toBeNull();
  });

  it('a native client still gets interaction_required (native_client_prompt is untouched)', async () => {
    const native = { ...WEB_CLIENT, application_type: 'native', redirect_uris: ['http://127.0.0.1/callback'] };
    const s = await server([native]);
    const config = await discover(s);
    const redirectUri = 'http://127.0.0.1:4100/callback';
    const first = await login(s, config, { ...MARIO, scope: 'openid crm', redirectUri });
    const second = await silent(s, config, first.browser, 'openid agent', redirectUri);
    expect(second.callback.searchParams.get('error')).toBe('interaction_required');
  });
});
