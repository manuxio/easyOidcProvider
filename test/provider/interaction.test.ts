/**
 * The login interaction (src/routes/interaction.ts), for the branches the
 * flow suites do not look at:
 *
 *   - an expired or unknown interaction session gets its own Italian answer,
 *     not a stack trace (asyncRoute);
 *   - the cool-down answer carries Retry-After and never reaches the identity
 *     provider;
 *   - an empty form is a fresh challenge, not a failed attempt;
 *   - a gate that cannot answer refuses the login as "riprovare", and an
 *     outage of ours never counts towards a user's cool-down;
 *   - a successful login clears the user's failure history;
 *   - the user name is echoed back escaped.
 *
 * The happy path, the second factor and the cool-down itself are in
 * test/e2e.test.ts and test/twofactor/; the AD group gate at login in
 * test/clientGroups.test.ts.
 */
import * as client from 'openid-client';
import { afterEach, describe, expect, it } from 'vitest';

import { FORM_FIELD_PASSWORD, FORM_FIELD_USERNAME } from '../../src/views/login.js';
import { Browser } from '../helpers/browser.js';
import { createCapturingLogger, type CapturingLogger } from '../helpers/captureLogger.js';
import { discover, exchange, login, randomLoopbackRedirect } from '../helpers/flow.js';
import { startTestServer, type TestServer } from '../helpers/server.js';

const MARIO = { username: 'mario.rossi', password: 'Password1!' };
const EXPIRED_TEXT = 'La sessione di accesso è scaduta';

const running: TestServer[] = [];
afterEach(async () => {
  while (running.length > 0) await running.pop()!.close();
});

async function server(env?: Record<string, string>): Promise<{ s: TestServer; capture: CapturingLogger }> {
  const capture = createCapturingLogger();
  const s = await startTestServer({ users: [MARIO], logger: capture.logger, ...(env ? { env } : {}) });
  running.push(s);
  return { s, capture };
}

/** Starts an authorization request and stops on the login form: the browser and the interaction uid. */
async function openInteraction(s: TestServer, config: client.Configuration) {
  const browser = new Browser();
  const codeVerifier = client.randomPKCECodeVerifier();
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: randomLoopbackRedirect(),
    scope: 'openid',
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    state: client.randomState(),
  });
  const first = await browser.follow(url.toString(), s.baseUrl);
  const interactionUrl = first.visited.at(-1)!;
  expect(interactionUrl).toContain('/interaction/');
  return { browser, uid: interactionUrl.split('/').pop()!, form: first.response };
}

async function postCredentials(s: TestServer, config: client.Configuration, fields: Record<string, string>) {
  const { browser, uid } = await openInteraction(s, config);
  return browser.postForm(`${s.baseUrl}/interaction/${uid}/login`, fields);
}

/** Wrong password for mario.rossi on a fresh interaction. */
async function failOnce(s: TestServer, config: client.Configuration): Promise<Response> {
  return postCredentials(s, config, { [FORM_FIELD_USERNAME]: MARIO.username, [FORM_FIELD_PASSWORD]: 'wrong' });
}

describe('an interaction session that is gone', () => {
  // NOTE: oidc-provider's SessionNotFound (a subclass of InvalidRequest) has
  // message 'invalid_request' and keeps "interaction session ..." in
  // error_description; asyncRoute in src/routes/interaction.ts recognises it by
  // its name or by that text in either field, so the answer is the 400 below,
  // never the 500 "Errore interno".
  it('GET without the interaction cookie: 400 and the Italian "session expired" text', async () => {
    const { s, capture } = await server();
    const response = await fetch(`${s.baseUrl}/interaction/no-such-uid`);
    expect(response.status).toBe(400);
    expect(response.headers.get('content-type')).toMatch(/text\/plain/);
    expect(await response.text()).toContain(EXPIRED_TEXT);
    expect(capture.matching('interaction session no longer valid')[0]).toMatchObject({
      level: 'warn',
      expired: true,
      path: '/interaction/no-such-uid',
    });
  });

  // NOTE: the POST route goes through the same asyncRoute (see above).
  it('POST of the form without the interaction cookie: the same answer, and no credential is checked', async () => {
    const { s, capture } = await server();
    const response = await fetch(`${s.baseUrl}/interaction/no-such-uid/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ [FORM_FIELD_USERNAME]: MARIO.username, [FORM_FIELD_PASSWORD]: MARIO.password }).toString(),
    });
    expect(response.status).toBe(400);
    expect(await response.text()).toContain(EXPIRED_TEXT);
    expect(capture.matching('login accepted')).toHaveLength(0);
  });

  it('never shows a stack trace, whatever the failure', async () => {
    const { s } = await server();
    const response = await fetch(`${s.baseUrl}/interaction/no-such-uid`);
    const text = await response.text();
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(text).not.toMatch(/\bat \S+ \(/);
    expect(text).not.toContain('SessionNotFound');
  });
});

describe('the form', () => {
  it('GET of the interaction shows the empty form with no alert', async () => {
    const { s } = await server();
    const { form, uid } = await openInteraction(s, await discover(s));
    expect(form.status).toBe(200);
    const html = await form.text();
    expect(html).toContain(`action="/interaction/${uid}/login"`);
    expect(html).not.toContain('role="alert"');
  });

  it('a form without password is a fresh challenge, not a failed attempt', async () => {
    const { s } = await server({ FORM_MAX_FAILED_ATTEMPTS: '2', FORM_LOCKOUT_SECONDS: '60' });
    const config = await discover(s);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await postCredentials(s, config, { [FORM_FIELD_USERNAME]: MARIO.username });
      expect(response.status).toBe(200);
      expect(await response.text()).not.toContain('role="alert"');
    }
    expect(s.auth.rateLimiter.failures(MARIO.username)).toBe(0);
  });

  it('echoes the submitted user name back escaped after a failure', async () => {
    const { s } = await server();
    const config = await discover(s);
    const response = await postCredentials(s, config, {
      [FORM_FIELD_USERNAME]: 'mario"><b>x',
      [FORM_FIELD_PASSWORD]: 'wrong',
    });
    expect(response.status).toBe(401);
    const html = await response.text();
    expect(html).toContain('value="mario&quot;&gt;&lt;b&gt;x"');
    expect(html).not.toContain('<b>x');
  });

  it('logs a rejected login with the interaction, the client and the reason, never the password', async () => {
    const { s, capture } = await server();
    const config = await discover(s);
    await failOnce(s, config);
    const rejected = capture.matching('login rejected').filter((record) => record.component === 'interaction');
    expect(rejected).toHaveLength(1);
    expect(rejected[0]).toMatchObject({
      level: 'warn',
      uid: expect.any(String),
      clientId: 'desktop-app',
      username: MARIO.username,
      reason: 'invalid_credentials',
    });
    expect(capture.text()).not.toContain('"wrong"');
  });
});

describe('the cool-down answer', () => {
  it('carries Retry-After and does not even ask the identity provider', async () => {
    const { s, capture } = await server({ FORM_MAX_FAILED_ATTEMPTS: '2', FORM_LOCKOUT_SECONDS: '60' });
    const config = await discover(s);
    await failOnce(s, config);
    await failOnce(s, config);

    const askedBefore = capture.records.filter((record) => record.component === 'identity.dev-stub').length;
    // The right password, during the cool-down.
    const locked = await postCredentials(s, config, {
      [FORM_FIELD_USERNAME]: MARIO.username,
      [FORM_FIELD_PASSWORD]: MARIO.password,
    });
    expect(locked.status).toBe(401);
    const retryAfter = Number(locked.headers.get('retry-after'));
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(60);
    expect(await locked.text()).toContain('Troppi tentativi non riusciti');
    expect(locked.headers.get('location')).toBeNull();

    expect(capture.records.filter((record) => record.component === 'identity.dev-stub')).toHaveLength(askedBefore);
    expect(capture.withReason('login_rate_limited').at(-1)).toMatchObject({
      username: MARIO.username,
      retryAfterSeconds: retryAfter,
    });
  });

  it('keys the cool-down on the user name whatever its case', async () => {
    const { s } = await server({ FORM_MAX_FAILED_ATTEMPTS: '2', FORM_LOCKOUT_SECONDS: '60' });
    const config = await discover(s);
    await failOnce(s, config);
    await failOnce(s, config);
    const locked = await postCredentials(s, config, {
      [FORM_FIELD_USERNAME]: 'Mario.Rossi',
      [FORM_FIELD_PASSWORD]: MARIO.password,
    });
    expect(locked.status).toBe(401);
    expect(locked.headers.get('retry-after')).not.toBeNull();
  });
});

describe('the failure history of a user', () => {
  it('is cleared by a successful login', async () => {
    const { s } = await server({ FORM_MAX_FAILED_ATTEMPTS: '3', FORM_LOCKOUT_SECONDS: '60' });
    const config = await discover(s);
    await failOnce(s, config);
    await failOnce(s, config);

    await exchange(config, await login(s, config, MARIO));

    expect(s.auth.rateLimiter.failures(MARIO.username)).toBe(0);

    // Without the reset these two would be the 3rd and 4th failure in a row.
    await failOnce(s, config);
    await failOnce(s, config);
    expect(s.auth.rateLimiter.failures(MARIO.username)).toBe(2);
    expect(s.auth.rateLimiter.check(MARIO.username).locked).toBe(false);
  });

  it('does not grow while a gate cannot answer: an outage of ours locks nobody out', async () => {
    const { s, capture } = await server({ FORM_MAX_FAILED_ATTEMPTS: '2', FORM_LOCKOUT_SECONDS: '60' });
    const config = await discover(s);
    const gate = s.auth.gates[0]!;
    const original = gate.check;
    (gate as { check: unknown }).check = async () => {
      throw new Error('LDAP connection timed out (test)');
    };

    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await postCredentials(s, config, {
        [FORM_FIELD_USERNAME]: MARIO.username,
        [FORM_FIELD_PASSWORD]: MARIO.password,
      });
      expect(response.status).toBe(401);
      expect(response.headers.get('location')).toBeNull();
      expect(await response.text()).toContain('il servizio di dominio non risponde');
    }
    expect(capture.matching('login rejected by an account gate').at(-1)).toMatchObject({
      reason: 'gate_unavailable',
      unavailable: true,
    });
    expect(s.auth.rateLimiter.failures(MARIO.username)).toBe(0);

    // The directory is back: the same user signs in at once.
    (gate as { check: unknown }).check = original;
    await expect(exchange(config, await login(s, config, MARIO))).resolves.toBeDefined();
  });
});
