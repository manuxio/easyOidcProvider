/**
 * Phase 1 acceptance suite: the OIDC core end to end against the dev-stub.
 *
 * Every test starts its own server on its own port with its own users, so the
 * suite is order-independent and leaves nothing behind.
 */
import * as client from 'openid-client';
import { afterEach, describe, expect, it } from 'vitest';

import { Browser } from './helpers/browser.js';
import {
  decodeJwtPayload,
  discover,
  exchange,
  login,
  LoginRejected,
  tokenRequest,
} from './helpers/flow.js';
import { CLIENT_ID, startTestServer, type TestServer } from './helpers/server.js';

const MARIO = { username: 'mario.rossi', password: 'Password1!' };

const running: TestServer[] = [];

async function server(users = [MARIO], env?: Record<string, string>): Promise<TestServer> {
  const started = await startTestServer({ users, ...(env ? { env } : {}) });
  running.push(started);
  return started;
}

afterEach(async () => {
  while (running.length > 0) await running.pop()!.close();
});

describe('discovery', () => {
  it('publishes the configured issuer, S256-only PKCE and RS256 id tokens', async () => {
    const s = await server();
    const response = await fetch(`${s.baseUrl}/.well-known/openid-configuration`);
    expect(response.status).toBe(200);
    const doc = (await response.json()) as Record<string, unknown>;

    expect(doc.issuer).toBe(s.baseUrl);
    expect(doc.authorization_endpoint).toBe(`${s.baseUrl}/auth`);
    expect(doc.token_endpoint).toBe(`${s.baseUrl}/token`);
    expect(doc.jwks_uri).toBe(`${s.baseUrl}/jwks`);
    expect(doc.code_challenge_methods_supported).toEqual(['S256']);
    expect(doc.id_token_signing_alg_values_supported).toEqual(['RS256']);
    expect(doc.grant_types_supported).toContain('refresh_token');
    expect(doc.claims_supported).toEqual(
      expect.arrayContaining(['sub', 'preferred_username', 'realm', 'auth_time']),
    );
  });

  it('serves a JWKS with exactly one public RS256 key and no private material', async () => {
    const s = await server();
    const jwks = (await (await fetch(`${s.baseUrl}/jwks`)).json()) as {
      keys: Record<string, unknown>[];
    };
    expect(jwks.keys).toHaveLength(1);
    const key = jwks.keys[0]!;
    expect(key.alg).toBe('RS256');
    expect(key.kty).toBe('RSA');
    expect(key.d).toBeUndefined();
    expect(key.p).toBeUndefined();
  });

  it('answers /health', async () => {
    const s = await server();
    const response = await fetch(`${s.baseUrl}/health`);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      status: 'ok',
      checks: { identityProvider: 'dev-stub', storage: 'memory' },
    });
  });
});

describe('happy path: authorize -> code -> token -> refresh -> refresh', () => {
  it('issues tokens with the agreed claims and rotates the refresh token', async () => {
    const s = await server();
    const config = await discover(s);

    const result = await login(s, config, MARIO);
    expect(result.callbackUrl).toContain('code=');

    const tokens = await exchange(config, result);
    expect(tokens.token_type.toLowerCase()).toBe('bearer');
    expect(tokens.expires_in).toBe(3600);
    expect(tokens.refresh_token).toBeTypeOf('string');

    // sub is the sAMAccountName lowercased: the platform username.
    const claims = tokens.claims()!;
    expect(claims.sub).toBe('mario.rossi');
    const idToken = decodeJwtPayload(tokens.id_token!);
    expect(idToken).toMatchObject({
      sub: 'mario.rossi',
      preferred_username: 'mario.rossi',
      realm: 'TEST.LOCAL',
      iss: s.baseUrl,
      aud: CLIENT_ID,
    });
    expect(idToken.auth_time).toBeTypeOf('number');

    // First refresh.
    const first = await client.refreshTokenGrant(config, tokens.refresh_token!);
    expect(first.access_token).toBeTypeOf('string');
    expect(first.refresh_token).toBeTypeOf('string');
    expect(first.refresh_token).not.toBe(tokens.refresh_token);

    // Second refresh, with the token the first one handed out.
    const second = await client.refreshTokenGrant(config, first.refresh_token!);
    expect(second.refresh_token).not.toBe(first.refresh_token);
    expect(decodeJwtPayload(second.id_token!)).toMatchObject({
      sub: 'mario.rossi',
      realm: 'TEST.LOCAL',
    });

    // The rotated-out token is dead, and using it kills the whole chain.
    const replay = await tokenRequest(s, {
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token!,
    });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_grant');

    const afterReplay = await tokenRequest(s, {
      grant_type: 'refresh_token',
      refresh_token: second.refresh_token!,
    });
    expect(afterReplay.status).toBe(400);
    expect(afterReplay.body.error).toBe('invalid_grant');
  });

  it('returns the identity claims from the userinfo endpoint', async () => {
    const s = await server();
    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, MARIO));

    const userinfo = await client.fetchUserInfo(config, tokens.access_token, 'mario.rossi');
    expect(userinfo).toMatchObject({
      sub: 'mario.rossi',
      preferred_username: 'mario.rossi',
      realm: 'TEST.LOCAL',
    });
  });
});

describe('the refresh is the enforcement point', () => {
  it('rejects the next refresh with invalid_grant once the account is disabled', async () => {
    const s = await server();
    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, MARIO));

    // A refresh still works while the account is active.
    const good = await client.refreshTokenGrant(config, tokens.refresh_token!);
    expect(good.refresh_token).toBeTypeOf('string');

    // The account is disabled in the directory (here: in the stub).
    s.stub.setActive('mario.rossi', false);

    const refused = await tokenRequest(s, {
      grant_type: 'refresh_token',
      refresh_token: good.refresh_token!,
    });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('invalid_grant');

    // The chain was revoked, so re-enabling the account does not resurrect it:
    // the user has to log in again.
    s.stub.setActive('mario.rossi', true);
    const stillDead = await tokenRequest(s, {
      grant_type: 'refresh_token',
      refresh_token: good.refresh_token!,
    });
    expect(stillDead.status).toBe(400);
    expect(stillDead.body.error).toBe('invalid_grant');

    // ...and logging in again works.
    const fresh = await exchange(config, await login(s, config, MARIO));
    expect(fresh.access_token).toBeTypeOf('string');
  });

  it('refuses the login of a disabled account, and says so in Italian', async () => {
    const s = await server([{ ...MARIO, active: false }]);
    const config = await discover(s);

    const failure = await login(s, config, MARIO).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LoginRejected);
    const rejection = failure as LoginRejected;
    expect(rejection.status).toBe(401);
    // The apostrophe is HTML-escaped in the rendered page.
    expect(rejection.body).toContain('account non è più attivo sul dominio');
  });

  it('rejects a wrong password without leaking whether the user exists', async () => {
    const s = await server();
    const config = await discover(s);

    for (const attempt of [
      { username: 'mario.rossi', password: 'wrong' },
      { username: 'nessuno', password: 'wrong' },
    ]) {
      const failure = await login(s, config, attempt).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(LoginRejected);
      expect((failure as LoginRejected).status).toBe(401);
      expect((failure as LoginRejected).body).toContain('Nome utente o password non corretti');
    }
  });

  it('fails closed when a gate cannot answer: rejection, not a pass', async () => {
    const s = await server();
    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, MARIO));

    // Simulate the directory being unreachable, which is what phase 3's LDAP
    // gate does when the DC does not answer.
    const gate = s.auth.gates[0]!;
    const original = gate.check;
    (gate as { check: unknown }).check = async () => {
      throw new Error('LDAP connection timed out');
    };

    const refused = await tokenRequest(s, {
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token!,
    });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('temporarily_unavailable');

    // The chain was NOT revoked: an outage of ours must not log the user out.
    (gate as { check: unknown }).check = original;
    const recovered = await client.refreshTokenGrant(config, tokens.refresh_token!);
    expect(recovered.access_token).toBeTypeOf('string');
  });
});

describe('PKCE is mandatory and S256 only', () => {
  it('rejects an authorization request with no code_challenge', async () => {
    const s = await server();
    const browser = new Browser();
    const url = new URL(`${s.baseUrl}/auth`);
    url.search = new URLSearchParams({
      client_id: CLIENT_ID,
      response_type: 'code',
      scope: 'openid',
      redirect_uri: 'http://127.0.0.1:41234/callback',
    }).toString();

    const response = await browser.fetch(url.toString());
    expect(response.status).toBe(303);
    const location = response.headers.get('location')!;
    expect(location).toContain('error=invalid_request');
    expect(location).toContain('PKCE');
    expect(location).not.toContain('code=');
  });

  it('rejects code_challenge_method=plain', async () => {
    const s = await server();
    const browser = new Browser();
    const url = new URL(`${s.baseUrl}/auth`);
    url.search = new URLSearchParams({
      client_id: CLIENT_ID,
      response_type: 'code',
      scope: 'openid',
      redirect_uri: 'http://127.0.0.1:41234/callback',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'plain',
    }).toString();

    const response = await browser.fetch(url.toString());
    const location = response.headers.get('location')!;
    expect(location).toContain('error=invalid_request');
    expect(location).toContain('code_challenge_method');
  });

  it('rejects the code exchange when the verifier is missing', async () => {
    const s = await server();
    const config = await discover(s);
    const result = await login(s, config, MARIO);

    const code = new URL(result.callbackUrl).searchParams.get('code')!;
    const response = await tokenRequest(s, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: result.redirectUri,
    });
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_grant');
  });

  it('rejects the code exchange when the verifier is wrong', async () => {
    const s = await server();
    const config = await discover(s);
    const result = await login(s, config, MARIO);

    const code = new URL(result.callbackUrl).searchParams.get('code')!;
    const response = await tokenRequest(s, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: result.redirectUri,
      code_verifier: client.randomPKCECodeVerifier(),
    });
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('invalid_grant');
  });
});

describe('redirect URIs (RFC 8252)', () => {
  it('accepts a loopback callback on a random port that was never registered', async () => {
    const s = await server();
    const config = await discover(s);

    for (const port of [1024, 34517, 65535]) {
      const redirectUri = `http://127.0.0.1:${port}/callback`;
      const tokens = await exchange(
        config,
        await login(s, config, { ...MARIO, redirectUri }),
      );
      expect(tokens.access_token).toBeTypeOf('string');
    }
  });

  it('rejects a redirect URI that is not loopback', async () => {
    const s = await server();
    const browser = new Browser();
    const url = new URL(`${s.baseUrl}/auth`);
    url.search = new URLSearchParams({
      client_id: CLIENT_ID,
      response_type: 'code',
      scope: 'openid',
      redirect_uri: 'http://evil.example.com/callback',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
    }).toString();

    const response = await browser.fetch(url.toString());
    // No redirect at all: an unregistered redirect_uri must never be redirected to.
    expect(response.status).toBe(400);
    expect(response.headers.get('location')).toBeNull();
    expect(await response.text()).toContain('invalid_redirect_uri');
  });

  it('rejects a loopback URI whose host or path differs from the registered one', async () => {
    const s = await server();
    const browser = new Browser();

    for (const redirectUri of [
      'http://localhost:4000/callback', // different host
      'http://127.0.0.1:4000/altro', // different path
      'https://127.0.0.1:4000/callback', // different scheme
    ]) {
      const url = new URL(`${s.baseUrl}/auth`);
      url.search = new URLSearchParams({
        client_id: CLIENT_ID,
        response_type: 'code',
        scope: 'openid',
        redirect_uri: redirectUri,
        code_challenge: 'a'.repeat(43),
        code_challenge_method: 'S256',
      }).toString();

      const response = await browser.fetch(url.toString());
      expect(response.status, redirectUri).toBe(400);
      expect(await response.text()).toContain('invalid_redirect_uri');
    }
  });
});

describe('JWT access tokens for the resource API', () => {
  it('carries sub, realm and preferred_username when API_AUDIENCE is configured', async () => {
    const s = await server([MARIO], { API_AUDIENCE: 'https://easyoidc.test/api' });
    const config = await discover(s);
    const tokens = await exchange(config, await login(s, config, MARIO));

    const payload = decodeJwtPayload(tokens.access_token);
    expect(payload).toMatchObject({
      sub: 'mario.rossi',
      preferred_username: 'mario.rossi',
      realm: 'TEST.LOCAL',
      aud: 'https://easyoidc.test/api',
      iss: s.baseUrl,
    });
  });
});
