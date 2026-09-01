/**
 * Phase 4-ter acceptance suite: the extra token claims seen from outside,
 * through the real OAuth2 flow, with a fake driver standing in for the
 * customer's database.
 *
 * The claims are in the tokens BY SERVER POLICY. Every login here asks for
 * `openid` and nothing else, and never sends a `claims` request parameter —
 * that is the point of the first describe block, not an oversight.
 *
 * The scenarios are the decided failure matrix:
 *   row present   ⇒ claims in the id token and in the JWT access token;
 *   NULL column   ⇒ that claim absent, the others there;
 *   no row        ⇒ Italian page at login, invalid_grant + chain REVOKED at
 *                   refresh, reason `claims_user_not_found`;
 *   DB silent     ⇒ temporarily_unavailable, chain INTACT (the same refresh
 *                   token still works once the database is back);
 *   switch off    ⇒ no query at all and no extra claim anywhere.
 *
 * The same claims are read from a real MySQL in `mysqlIntegration.test.ts`, and
 * proved end to end through nginx in the prod-like stack (see the README).
 */
import * as client from 'openid-client';
import { afterEach, describe, expect, it } from 'vitest';

import { createCapturingLogger, type CapturingLogger } from '../helpers/captureLogger.js';
import { CUSTOMER_CLAIMS_QUERY } from '../helpers/claimsQuery.js';
import { FakeSqlDriver } from '../helpers/fakeSqlDriver.js';
import { decodeJwtPayload, discover, exchange, login, LoginRejected, tokenRequest } from '../helpers/flow.js';
import { startTestServer, type TestServer } from '../helpers/server.js';
import type { SqlRow } from '../../src/sqlcheck/index.js';

const MARIO = { username: 'mario.rossi', password: 'Password1!' };
const LUIGI = { username: 'luigi.verdi', password: 'Password2!' };
const USERS = [MARIO, LUIGI];

const API_AUDIENCE = 'https://easyoidc.test/api';

const CLAIMS_ON = {
  CLAIMS_SQL_ENABLED: 'true',
  SQL_DRIVER: 'mysql',
  SQL_CONNECTION_STRING: 'mysql://user:pw@127.0.0.1:3306/backoffice',
  CLAIMS_SQL_QUERY: CUSTOMER_CLAIMS_QUERY,
  SQL_TIMEOUT_MS: '2000',
};

/** What the customer's row looks like for mario.rossi. */
const MARIO_ROW: SqlRow = { remoteId: 4217, name: 'Mario Rossi' };

const running: TestServer[] = [];

interface Harness {
  server: TestServer;
  driver: FakeSqlDriver;
  capture: CapturingLogger;
}

async function harness(
  options: { enabled?: boolean; apiAudience?: boolean; rows?: Array<[string, SqlRow[]]> } = {},
): Promise<Harness> {
  const driver = new FakeSqlDriver({
    rows: new Map(options.rows ?? [[MARIO.username, [MARIO_ROW]]]),
  });
  const capture = createCapturingLogger();
  const server = await startTestServer({
    users: USERS,
    env: {
      ...CLAIMS_ON,
      ...(options.enabled === false ? { CLAIMS_SQL_ENABLED: 'false' } : {}),
      ...(options.apiAudience === false ? {} : { API_AUDIENCE }),
    },
    sqlDriver: driver,
    logger: capture.logger,
  });
  running.push(server);
  return { server, driver, capture };
}

afterEach(async () => {
  while (running.length > 0) await running.pop()!.close();
});

describe('the claims ride in both tokens, whatever the client asks for', () => {
  it('puts remoteId and name in the id token and in the JWT access token', async () => {
    const { server, driver } = await harness();
    const config = await discover(server);

    // scope: openid only, and no `claims` request parameter anywhere.
    const tokens = await exchange(config, await login(server, config, MARIO));

    const idToken = decodeJwtPayload(tokens.id_token!);
    expect(idToken).toMatchObject({
      sub: MARIO.username,
      preferred_username: MARIO.username,
      realm: 'TEST.LOCAL',
      remoteId: 4217,
      name: 'Mario Rossi',
    });

    const accessToken = decodeJwtPayload(tokens.access_token);
    expect(accessToken).toMatchObject({
      sub: MARIO.username,
      aud: API_AUDIENCE,
      remoteId: 4217,
      name: 'Mario Rossi',
    });

    // The query text is the customer's, untouched, with the username bound.
    expect(driver.calls.every((call) => call.sql === CUSTOMER_CLAIMS_QUERY)).toBe(true);
    expect(driver.queriedUsernames.every((name) => name === MARIO.username)).toBe(true);
  });

  it('advertises them in the discovery document, so a client can see what it gets', async () => {
    const { server } = await harness();
    const discovery = await (await fetch(`${server.baseUrl}/.well-known/openid-configuration`)).json() as
      { claims_supported: string[] };
    expect(discovery.claims_supported).toEqual(expect.arrayContaining(['remoteId', 'name']));
  });

  it('keeps them across a refresh, re-reading the row each time', async () => {
    const { server, driver } = await harness();
    const config = await discover(server);
    const tokens = await exchange(config, await login(server, config, MARIO));

    const before = driver.calls.length;
    const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token!);

    expect(decodeJwtPayload(refreshed.id_token!)).toMatchObject({ remoteId: 4217, name: 'Mario Rossi' });
    expect(decodeJwtPayload(refreshed.access_token)).toMatchObject({ remoteId: 4217 });

    // ONE query for the whole refresh: findAccount and extraTokenClaims share
    // the same lookup, memoised on the request context.
    expect(driver.calls.length - before).toBe(1);
  });

  it('follows the row when the back office changes it', async () => {
    const { server, driver } = await harness();
    const config = await discover(server);
    const tokens = await exchange(config, await login(server, config, MARIO));

    driver.rows!.set(MARIO.username, [{ remoteId: 9001, name: 'Mario Rossi Junior' }]);
    const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token!);

    expect(decodeJwtPayload(refreshed.id_token!)).toMatchObject({
      remoteId: 9001,
      name: 'Mario Rossi Junior',
    });
  });

  it('omits a NULL column instead of emitting null or an empty string', async () => {
    const { server } = await harness({
      rows: [[MARIO.username, [{ remoteId: 4217, name: null }]]],
    });
    const config = await discover(server);
    const tokens = await exchange(config, await login(server, config, MARIO));

    const idToken = decodeJwtPayload(tokens.id_token!);
    expect(idToken.remoteId).toBe(4217);
    expect('name' in idToken).toBe(false);
    expect('name' in decodeJwtPayload(tokens.access_token)).toBe(false);
  });
});

describe('an account with no row in the back office', () => {
  it('is refused at login, in Italian, without blaming the password', async () => {
    const { server, driver } = await harness();
    const config = await discover(server);

    const failure = await login(server, config, LUIGI).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LoginRejected);
    const rejection = failure as LoginRejected;
    expect(rejection.status).toBe(401);
    // The apostrophes are HTML-escaped in the rendered page.
    expect(rejection.body).toContain('non risulta agganciata a nessun utente del gestionale');
    expect(rejection.body).not.toContain('Nome utente o password non corretti');

    expect(driver.queriedUsernames).toEqual([LUIGI.username]);
  });

  it('loses the next refresh with invalid_grant, and the whole chain with it', async () => {
    const { server, driver, capture } = await harness();
    const config = await discover(server);

    const tokens = await exchange(config, await login(server, config, MARIO));
    const good = await client.refreshTokenGrant(config, tokens.refresh_token!);

    // The back office unlinks the account.
    driver.rows!.delete(MARIO.username);

    const refused = await tokenRequest(server, {
      grant_type: 'refresh_token',
      refresh_token: good.refresh_token!,
    });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('invalid_grant');

    const [rejection] = capture.withReason('claims_user_not_found')
      .filter((record) => record.revoked === true);
    expect(rejection).toBeDefined();
    expect(rejection!.username).toBe(MARIO.username);

    // The chain is GONE, not merely refused: putting the row back does not
    // bring the refresh token back to life. This is the exact opposite of the
    // "database was down" case below, where the same token keeps working.
    driver.rows!.set(MARIO.username, [MARIO_ROW]);
    const stillDead = await tokenRequest(server, {
      grant_type: 'refresh_token',
      refresh_token: good.refresh_token!,
    });
    expect(stillDead.status).toBe(400);
    expect(stillDead.body.error).toBe('invalid_grant');
  });
});

describe('a database that cannot answer', () => {
  it('refuses the login with "riprovare tra qualche minuto"', async () => {
    const { server, driver } = await harness();
    driver.failWith = new Error('ECONNREFUSED connect 127.0.0.1:3306');
    const config = await discover(server);

    const failure = await login(server, config, MARIO).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LoginRejected);
    expect((failure as LoginRejected).body).toContain('Riprovare tra qualche minuto');
  });

  it('refuses the refresh with temporarily_unavailable and leaves the chain intact', async () => {
    const { server, driver, capture } = await harness();
    const config = await discover(server);
    const tokens = await exchange(config, await login(server, config, MARIO));

    driver.failWith = new Error('ETIMEDOUT the database is not answering');
    const refused = await tokenRequest(server, {
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token!,
    });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('temporarily_unavailable');

    expect(capture.withReason('claims_source_unavailable')
      .some((record) => record.revoked === false)).toBe(true);
    expect(capture.withReason('claims_user_not_found')).toHaveLength(0);

    // The database comes back: the SAME refresh token still works, because
    // nothing was revoked over an outage of ours.
    driver.failWith = undefined;
    const recovered = await client.refreshTokenGrant(config, tokens.refresh_token!);
    expect(decodeJwtPayload(recovered.id_token!)).toMatchObject({ remoteId: 4217 });
  });
});

describe('with the switch off the feature does not exist', () => {
  it('runs no query and puts no extra claim in either token', async () => {
    const { server, driver, capture } = await harness({ enabled: false });
    const config = await discover(server);

    const tokens = await exchange(config, await login(server, config, MARIO));
    const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token!);

    for (const jwt of [tokens.id_token!, tokens.access_token, refreshed.id_token!]) {
      const payload = decodeJwtPayload(jwt);
      expect('remoteId' in payload).toBe(false);
      expect('name' in payload).toBe(false);
    }

    // No query, no pool, and nothing about the claims in the log at all.
    expect(driver.calls).toHaveLength(0);
    expect(capture.matching('extra token claims')).toHaveLength(0);
    expect(capture.matching('extra claims')).toHaveLength(0);
  });

  it('leaves them out of the discovery document too', async () => {
    const { server } = await harness({ enabled: false });
    const discovery = await (await fetch(`${server.baseUrl}/.well-known/openid-configuration`)).json() as
      { claims_supported: string[] };
    expect(discovery.claims_supported).not.toContain('remoteId');
  });
});

describe('with API_AUDIENCE unset the id token still carries them', () => {
  it('keeps the access token opaque and the id token complete', async () => {
    const { server } = await harness({ apiAudience: false });
    const config = await discover(server);
    const tokens = await exchange(config, await login(server, config, MARIO));

    expect(tokens.access_token.includes('.')).toBe(false);
    expect(decodeJwtPayload(tokens.id_token!)).toMatchObject({ remoteId: 4217, name: 'Mario Rossi' });
  });
});
