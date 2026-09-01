/**
 * Phase 4-bis: the fallback form switch, end to end on a running server.
 *
 * FALLBACK_FORM_ENABLED=false is only meaningful with the spnego provider, so
 * that is what these tests start. Nothing here reaches Kerberos or LDAP: the
 * challenge and the POST refusal are both decided before any credential is
 * looked at, and the native GSSAPI binding is imported lazily, so the suite
 * still runs on a machine with no krb5 runtime and no domain controller.
 */
import { afterEach, describe, expect, it } from 'vitest';

import { ConfigError, loadConfig } from '../../src/config.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';
import { Browser } from '../helpers/browser.js';
import { discover, randomLoopbackRedirect } from '../helpers/flow.js';
import { startTestServer, CLIENT_ID, type TestServer } from '../helpers/server.js';
import * as client from 'openid-client';

const REALM = 'LAB.EASYOIDC.LOCAL';

const SPNEGO_ENV = {
  IDENTITY_PROVIDER: 'spnego',
  REALM,
  LDAP_URL: 'ldaps://dc1.lab.easyoidc.local',
  LDAP_BIND_DN: `svc-auth@${REALM}`,
  LDAP_BIND_PASSWORD: 'Svc.Passw0rd!',
  LDAP_BASE_DN: 'DC=lab,DC=easyoidc,DC=local',
} as const;

let server: TestServer | undefined;

afterEach(async () => {
  await server?.close();
  server = undefined;
});

/**
 * Walks the authorization request up to the interaction, and returns the
 * challenge response together with the interaction uid the form would post to.
 */
async function reachChallenge(
  target: TestServer,
): Promise<{ response: Response; body: string; uid: string; browser: Browser }> {
  const config = await discover(target);
  const browser = new Browser();
  const authorizationUrl = client.buildAuthorizationUrl(config, {
    redirect_uri: randomLoopbackRedirect(),
    scope: 'openid',
    code_challenge: await client.calculatePKCECodeChallenge(client.randomPKCECodeVerifier()),
    code_challenge_method: 'S256',
    state: client.randomState(),
  });

  const hop = await browser.follow(authorizationUrl.toString(), target.baseUrl);
  const uid = hop.visited.at(-1)!.split('/').pop()!;
  return { response: hop.response, body: await hop.response.text(), uid, browser };
}

describe('FALLBACK_FORM_ENABLED=false (SSO only)', () => {
  it('answers the challenge with Negotiate and NO form in the body', async () => {
    server = await startTestServer({
      env: { ...SPNEGO_ENV, FALLBACK_FORM_ENABLED: 'false' },
    });

    const { response, body } = await reachChallenge(server);

    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toBe('Negotiate');
    expect(body).not.toContain('<form');
    expect(body).not.toContain('name="password"');
    expect(body).not.toContain('name="username"');
    // What is there instead: an Italian explanation of why nothing can be typed.
    expect(body).toContain('Accesso automatico richiesto');
  });

  it('refuses a hand-crafted POST to the form endpoint, and logs the reason', async () => {
    const capture = createCapturingLogger();
    server = await startTestServer({
      env: { ...SPNEGO_ENV, FALLBACK_FORM_ENABLED: 'false' },
      logger: capture.logger,
    });

    const { uid, browser } = await reachChallenge(server);
    const posted = await browser.postForm(`${server.baseUrl}/interaction/${uid}/login`, {
      username: 'mario.rossi',
      password: 'Lab.Passw0rd!',
    });

    expect(posted.status).toBe(403);
    expect(posted.headers.get('location')).toBeNull();
    expect(await posted.text()).toContain('Accesso con password disattivato');

    const refusals = capture.withReason('fallback_form_disabled');
    expect(refusals.length).toBeGreaterThanOrEqual(1);
    expect(refusals.some((record) => record.level === 'warn')).toBe(true);
  });
});

describe('FALLBACK_FORM_ENABLED=true (the default)', () => {
  it('carries Negotiate AND the form, so both kinds of client have a way in', async () => {
    server = await startTestServer({ env: SPNEGO_ENV });

    const { response, body } = await reachChallenge(server);

    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toBe('Negotiate');
    expect(body).toContain('<form');
    expect(body).toContain('name="username"');
    expect(body).toContain('name="password"');
    // No second factor unless it is switched on.
    expect(body).not.toContain('name="otp"');
    expect(body).not.toContain('Codice di verifica');
  });

  it('adds the verification code field when the second factor is on', async () => {
    server = await startTestServer({
      env: {
        ...SPNEGO_ENV,
        TWO_FACTOR_ENABLED: 'true',
        TWO_FACTOR_SOURCE: 'ldap',
        TWO_FACTOR_LDAP_ATTRIBUTE: 'pager',
      },
    });

    const { body } = await reachChallenge(server);

    expect(body).toContain('name="otp"');
    expect(body).toContain('Codice di verifica');
    expect(body).toContain('data-two-factor="required"');
  });
});

describe('configuration', () => {
  const base = {
    ISSUER_URL: 'http://127.0.0.1:3000',
    DATA_DIR: '',
    CLIENTS_JSON: JSON.stringify([
      { client_id: CLIENT_ID, redirect_uris: ['http://127.0.0.1/callback'] },
    ]),
  };

  it('refuses to switch the form off with dev-stub, where it is the only door', () => {
    expect(() => loadConfig({
      ...base,
      IDENTITY_PROVIDER: 'dev-stub',
      DEV_STUB_USERS: '[{"username":"a","password":"b"}]',
      FALLBACK_FORM_ENABLED: 'false',
    })).toThrow(ConfigError);
  });

  it('demands a source when the second factor is switched on', () => {
    expect(() => loadConfig({
      ...base,
      IDENTITY_PROVIDER: 'dev-stub',
      DEV_STUB_USERS: '[{"username":"a","password":"b"}]',
      TWO_FACTOR_ENABLED: 'true',
    })).toThrow(/TWO_FACTOR_SOURCE is required/);
  });

  it('demands the query AND a connection string for TWO_FACTOR_SOURCE=sql, group check or not', () => {
    let problems: string[] = [];
    try {
      loadConfig({
        ...base,
        IDENTITY_PROVIDER: 'dev-stub',
        DEV_STUB_USERS: '[{"username":"a","password":"b"}]',
        TWO_FACTOR_ENABLED: 'true',
        TWO_FACTOR_SOURCE: 'sql',
        SQL_GROUP_CHECK_ENABLED: 'false',
      });
    } catch (error) {
      problems = (error as ConfigError).problems;
    }
    expect(problems).toContain('TWO_FACTOR_SQL_QUERY is required when TWO_FACTOR_SOURCE=sql');
    expect(problems).toContain('SQL_CONNECTION_STRING is required when TWO_FACTOR_SOURCE=sql');
  });

  it('demands the attribute and the spnego provider for TWO_FACTOR_SOURCE=ldap', () => {
    let problems: string[] = [];
    try {
      loadConfig({
        ...base,
        IDENTITY_PROVIDER: 'dev-stub',
        DEV_STUB_USERS: '[{"username":"a","password":"b"}]',
        TWO_FACTOR_ENABLED: 'true',
        TWO_FACTOR_SOURCE: 'ldap',
      });
    } catch (error) {
      problems = (error as ConfigError).problems;
    }
    expect(problems).toContain('TWO_FACTOR_LDAP_ATTRIBUTE is required when TWO_FACTOR_SOURCE=ldap');
    expect(problems.some((problem) => problem.includes('requires IDENTITY_PROVIDER=spnego'))).toBe(true);
  });

  it('leaves the second factor off, and the form on, by default', () => {
    const config = loadConfig({
      ...base,
      IDENTITY_PROVIDER: 'dev-stub',
      DEV_STUB_USERS: '[{"username":"a","password":"b"}]',
    });
    expect(config.fallbackFormEnabled).toBe(true);
    expect(config.twoFactor.enabled).toBe(false);
    expect(config.loginRateLimit).toEqual({ maxFailedAttempts: 5, lockoutSeconds: 300 });
  });
});
