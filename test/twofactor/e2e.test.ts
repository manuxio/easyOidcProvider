/**
 * Phase 4-bis end to end: a real auth-server, the real OAuth2 exchange, and the
 * second factor on the form path.
 *
 * The seed source is a fake (an in-memory table); the TOTP itself is real, the
 * form is real, the code exchange is real. The same flow against a REAL MySQL
 * lives in mysqlIntegration.test.ts, and against the AD lab in
 * lab/test-two-factor.sh.
 */
import { generateSync } from 'otplib';
import { afterEach, describe, expect, it } from 'vitest';

import { createCapturingLogger } from '../helpers/captureLogger.js';
import { FakeSeedSource } from '../helpers/fakeSeedSource.js';
import { discover, exchange, login, LoginRejected } from '../helpers/flow.js';
import { startTestServer, type TestServer } from '../helpers/server.js';

const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const USER = 'mario.rossi';
const PASSWORD = 'Password1!';
/** Enrolled in the source, but with a seed the library will not accept. */
const NOT_ENROLLED = 'luigi.verdi';
const NOT_ENROLLED_PASSWORD = 'Password2!';

const TWO_FACTOR_ENV = {
  TWO_FACTOR_ENABLED: 'true',
  TWO_FACTOR_SOURCE: 'sql',
  TWO_FACTOR_SQL_QUERY: 'SELECT seed FROM totp_seeds WHERE username = ?',
  SQL_CONNECTION_STRING: 'mysql://unused@127.0.0.1:1/unused',
} as const;

const USERS = [
  { username: USER, password: PASSWORD },
  { username: NOT_ENROLLED, password: NOT_ENROLLED_PASSWORD },
];

function currentCode(secret = SEED): string {
  return generateSync({ secret, epoch: Math.floor(Date.now() / 1000) });
}

/** The text of the error banner on the login page, or undefined when there is none. */
function alertText(html: string): string | undefined {
  return /<p class="alert" role="alert">([^<]*)<\/p>/.exec(html)?.[1];
}

let server: TestServer | undefined;

afterEach(async () => {
  await server?.close();
  server = undefined;
});

describe('the form with a second factor', () => {
  it('completes authorize -> form(user+password+code) -> code -> token', async () => {
    const source = new FakeSeedSource({ [USER]: SEED });
    server = await startTestServer({
      users: USERS,
      env: TWO_FACTOR_ENV,
      twoFactorSeedSource: source,
    });

    const config = await discover(server);
    const result = await login(server, config, {
      username: USER,
      password: PASSWORD,
      otp: currentCode(),
    });
    const tokens = await exchange(config, result);

    expect(tokens.access_token).toBeTypeOf('string');
    expect(tokens.refresh_token).toBeTypeOf('string');
    const claims = tokens.claims()!;
    expect(claims.sub).toBe(USER);
    // The seed was fetched exactly once, for exactly this user.
    expect(source.lookups).toEqual([USER]);
  });

  it('hands out no code for a wrong verification code, and does not say which factor failed', async () => {
    const capture = createCapturingLogger();
    server = await startTestServer({
      users: USERS,
      env: TWO_FACTOR_ENV,
      twoFactorSeedSource: new FakeSeedSource({ [USER]: SEED }),
      logger: capture.logger,
    });

    const config = await discover(server);
    const failure = await login(server, config, {
      username: USER,
      password: PASSWORD,
      otp: '000000',
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(LoginRejected);
    const rejection = failure as LoginRejected;
    expect(rejection.status).toBe(401);
    // The page says the same thing a wrong password says: the message shown to
    // the user must not name the factor that failed.
    expect(alertText(rejection.body)).toBe('Nome utente o password non corretti. Riprovare.');
    // ...while still offering the code field, so the user can simply retype it.
    expect(rejection.body).toContain('name="otp"');
    expect(rejection.body).toContain('data-two-factor="required"');

    // The log, on the other hand, names the factor exactly.
    expect(capture.withReason('two_factor_failed').length).toBeGreaterThanOrEqual(1);
  });

  it('hands out no code when no verification code is submitted at all', async () => {
    server = await startTestServer({
      users: USERS,
      env: TWO_FACTOR_ENV,
      twoFactorSeedSource: new FakeSeedSource({ [USER]: SEED }),
    });

    const config = await discover(server);
    const failure = await login(server, config, { username: USER, password: PASSWORD })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(LoginRejected);
    expect((failure as LoginRejected).status).toBe(401);
  });

  it('refuses a replayed code even though the password is right', async () => {
    server = await startTestServer({
      users: USERS,
      env: TWO_FACTOR_ENV,
      twoFactorSeedSource: new FakeSeedSource({ [USER]: SEED }),
    });

    const config = await discover(server);
    const code = currentCode();

    const first = await login(server, config, { username: USER, password: PASSWORD, otp: code });
    await expect(exchange(config, first)).resolves.toBeDefined();

    const failure = await login(server, config, { username: USER, password: PASSWORD, otp: code })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LoginRejected);
    expect((failure as LoginRejected).body).toContain('Nome utente o password non corretti');
  });

  it('refuses a user with no seed, and tells them it is an enrolment problem', async () => {
    const capture = createCapturingLogger();
    server = await startTestServer({
      users: USERS,
      env: TWO_FACTOR_ENV,
      twoFactorSeedSource: new FakeSeedSource({ [USER]: SEED }),
      logger: capture.logger,
    });

    const config = await discover(server);
    const failure = await login(server, config, {
      username: NOT_ENROLLED,
      password: NOT_ENROLLED_PASSWORD,
      otp: currentCode(),
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(LoginRejected);
    expect((failure as LoginRejected).body).toContain('non è configurato il codice di verifica');
    expect(capture.withReason('two_factor_not_enrolled').length).toBeGreaterThanOrEqual(1);
  });

  it('refuses with "try again later" when the seed source is down', async () => {
    const capture = createCapturingLogger();
    const source = new FakeSeedSource({ [USER]: SEED });
    source.failWith = new Error('ECONNREFUSED 127.0.0.1:3306');
    server = await startTestServer({
      users: USERS,
      env: TWO_FACTOR_ENV,
      twoFactorSeedSource: source,
      logger: capture.logger,
    });

    const config = await discover(server);
    const failure = await login(server, config, {
      username: USER,
      password: PASSWORD,
      otp: currentCode(),
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(LoginRejected);
    expect((failure as LoginRejected).body).toContain('Riprovare tra qualche minuto');
    expect(capture.withReason('two_factor_unavailable').length).toBeGreaterThanOrEqual(1);
  });
});

describe('with the second factor off', () => {
  it('never asks for a code and never touches the seed source', async () => {
    const source = new FakeSeedSource({ [USER]: SEED });
    server = await startTestServer({ users: USERS, twoFactorSeedSource: source });

    const config = await discover(server);
    const result = await login(server, config, { username: USER, password: PASSWORD });
    await expect(exchange(config, result)).resolves.toBeDefined();

    expect(source.lookups).toEqual([]);
    expect(server.auth.twoFactor).toBeUndefined();
  });
});

describe('the cool-down on failed form attempts', () => {
  it('stops answering after the configured number of failures, then lets the user back in', async () => {
    const capture = createCapturingLogger();
    server = await startTestServer({
      users: USERS,
      env: { ...TWO_FACTOR_ENV, FORM_MAX_FAILED_ATTEMPTS: '3', FORM_LOCKOUT_SECONDS: '60' },
      twoFactorSeedSource: new FakeSeedSource({ [USER]: SEED }),
      logger: capture.logger,
    });

    const config = await discover(server);

    // Three wrong codes: the third one arms the cool-down.
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const failure = await login(server, config, {
        username: USER,
        password: PASSWORD,
        otp: '000000',
      }).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(LoginRejected);
    }

    const tripped = capture.withReason('login_rate_limited');
    expect(tripped.length).toBeGreaterThanOrEqual(1);
    expect(tripped[0]!.username).toBe(USER);

    // Now even the RIGHT credentials are refused, and the page says why.
    const lockedOut = await login(server, config, {
      username: USER,
      password: PASSWORD,
      otp: currentCode(),
    }).catch((error: unknown) => error);
    expect(lockedOut).toBeInstanceOf(LoginRejected);
    expect((lockedOut as LoginRejected).body).toContain('Troppi tentativi non riusciti');

    // Another user is untouched by it.
    const other = await login(server, config, {
      username: NOT_ENROLLED,
      password: 'wrong',
    }).catch((error: unknown) => error);
    expect((other as LoginRejected).body).toContain('Nome utente o password non corretti');

    // Clearing the cool-down by hand is the same thing the clock does after
    // FORM_LOCKOUT_SECONDS; the point here is that it is a cool-down and not a
    // permanent lock.
    server.auth.rateLimiter.reset(USER);
    const recovered = await login(server, config, {
      username: USER,
      password: PASSWORD,
      otp: currentCode(),
    });
    await expect(exchange(config, recovered)).resolves.toBeDefined();
  });

  it('counts wrong passwords too, not only wrong codes', async () => {
    const capture = createCapturingLogger();
    server = await startTestServer({
      users: USERS,
      env: { FORM_MAX_FAILED_ATTEMPTS: '2', FORM_LOCKOUT_SECONDS: '60' },
      logger: capture.logger,
    });

    const config = await discover(server);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await login(server, config, { username: USER, password: 'wrong' })
        .catch(() => undefined);
    }

    expect(capture.withReason('login_rate_limited').length).toBeGreaterThanOrEqual(1);
    const lockedOut = await login(server, config, { username: USER, password: PASSWORD })
      .catch((error: unknown) => error);
    expect((lockedOut as LoginRejected).body).toContain('Troppi tentativi non riusciti');
  });
});
