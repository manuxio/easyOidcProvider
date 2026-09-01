/**
 * Phase 4 acceptance suite: the SQL group check seen from outside, through the
 * real OAuth2 flow, with a fake driver standing in for the customer database.
 *
 * The scenarios are the ones the plan asks for:
 *   present  ⇒ login and refresh work;
 *   absent   ⇒ access denied at login (Italian message) and invalid_grant at
 *              refresh, with the grant chain revoked;
 *   DB down  ⇒ temporarily_unavailable, chain intact;
 *   disabled ⇒ no query, no SQL line in the log at all.
 *
 * The same scenarios run against a real MySQL in `mysqlIntegration.test.ts`.
 */
import * as client from 'openid-client';
import { afterEach, describe, expect, it } from 'vitest';

import { discover, exchange, login, LoginRejected, tokenRequest } from '../helpers/flow.js';
import { createCapturingLogger, type CapturingLogger } from '../helpers/captureLogger.js';
import { FakeSqlDriver } from '../helpers/fakeSqlDriver.js';
import { startTestServer, type TestServer } from '../helpers/server.js';

const MARIO = { username: 'mario.rossi', password: 'Password1!' };
const LUIGI = { username: 'luigi.verdi', password: 'Password2!' };
const USERS = [MARIO, LUIGI];

const QUERY = 'SELECT 1 FROM authorized_users WHERE username = ?';

const SQL_ON = {
  SQL_GROUP_CHECK_ENABLED: 'true',
  SQL_DRIVER: 'mysql',
  SQL_CONNECTION_STRING: 'mysql://user:pw@127.0.0.1:3306/backoffice',
  SQL_GROUP_QUERY: QUERY,
  SQL_TIMEOUT_MS: '2000',
};

const running: TestServer[] = [];

interface Harness {
  server: TestServer;
  driver: FakeSqlDriver;
  capture: CapturingLogger;
}

async function harness(
  options: { enabled?: boolean; authorized?: string[] } = {},
): Promise<Harness> {
  const driver = new FakeSqlDriver({ authorized: options.authorized ?? [MARIO.username] });
  const capture = createCapturingLogger();
  const server = await startTestServer({
    users: USERS,
    env: options.enabled === false
      ? { ...SQL_ON, SQL_GROUP_CHECK_ENABLED: 'false' }
      : SQL_ON,
    sqlDriver: driver,
    logger: capture.logger,
  });
  running.push(server);
  return { server, driver, capture };
}

afterEach(async () => {
  while (running.length > 0) await running.pop()!.close();
});

describe('a user the database knows', () => {
  it('logs in, gets tokens, and refreshes', async () => {
    const { server, driver } = await harness();
    const config = await discover(server);

    const tokens = await exchange(config, await login(server, config, MARIO));
    expect(tokens.access_token).toBeTypeOf('string');

    const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token!);
    expect(refreshed.access_token).toBeTypeOf('string');

    // Once at login, once at the refresh: the gate really does run at both.
    expect(driver.queriedUsernames).toEqual([MARIO.username, MARIO.username]);
    expect(driver.calls.every((call) => call.sql === QUERY)).toBe(true);
  });
});

describe('a user the database does not know', () => {
  it('is refused at login, in Italian, without blaming the password', async () => {
    const { server, driver } = await harness();
    const config = await discover(server);

    const failure = await login(server, config, LUIGI).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LoginRejected);
    const rejection = failure as LoginRejected;
    expect(rejection.status).toBe(401);
    // The apostrophes are HTML-escaped in the rendered page.
    expect(rejection.body).toContain('non risulta abilitata all');
    expect(rejection.body).toContain('uso di questa applicazione');
    expect(rejection.body).not.toContain('Nome utente o password non corretti');

    expect(driver.queriedUsernames).toEqual([LUIGI.username]);
  });

  it('loses the next refresh with invalid_grant when the row is removed mid-session', async () => {
    const { server, driver, capture } = await harness();
    const config = await discover(server);

    const tokens = await exchange(config, await login(server, config, MARIO));
    const good = await client.refreshTokenGrant(config, tokens.refresh_token!);

    // The customer revokes the authorization in their own database.
    driver.authorized.delete(MARIO.username);

    const refused = await tokenRequest(server, {
      grant_type: 'refresh_token',
      refresh_token: good.refresh_token!,
    });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('invalid_grant');

    // The reason is in the log, with the gate that produced it.
    const [rejection] = capture.withReason('sql_group_check_failed')
      .filter((record) => record.gate === 'sql_group' && record.revoked === true);
    expect(rejection).toBeDefined();
    expect(rejection!.username).toBe(MARIO.username);

    // The chain is gone: putting the row back does not resurrect the token.
    driver.authorized.add(MARIO.username);
    const replay = await tokenRequest(server, {
      grant_type: 'refresh_token',
      refresh_token: good.refresh_token!,
    });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_grant');
  });
});

describe('a database that cannot answer', () => {
  it('rejects the refresh with temporarily_unavailable and keeps the chain', async () => {
    const { server, driver, capture } = await harness();
    const config = await discover(server);
    const tokens = await exchange(config, await login(server, config, MARIO));

    driver.failWith = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:3306'), {
      code: 'ECONNREFUSED',
    });

    const refused = await tokenRequest(server, {
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token!,
    });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('temporarily_unavailable');
    expect(capture.withReason('sql_group_check_unavailable').length).toBeGreaterThan(0);

    // An outage of ours does not log the floor out: the same token works again
    // as soon as the database comes back.
    delete driver.failWith;
    const recovered = await client.refreshTokenGrant(config, tokens.refresh_token!);
    expect(recovered.access_token).toBeTypeOf('string');
  });

  it('refuses the login with the "try again later" message, not "not authorized"', async () => {
    const { server, driver } = await harness();
    const config = await discover(server);
    driver.failWith = new Error('ETIMEDOUT');

    const failure = await login(server, config, MARIO).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LoginRejected);
    expect((failure as LoginRejected).body).toContain('Riprovare tra qualche minuto');
  });
});

describe('with the check disabled, no SQL happens at all', () => {
  it('completes login and refresh without a single query or SQL log line', async () => {
    const { server, driver, capture } = await harness({ enabled: false, authorized: [] });
    const config = await discover(server);

    // luigi is in nobody's table, and gets in anyway: the gate does not exist.
    const tokens = await exchange(config, await login(server, config, LUIGI));
    const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token!);
    expect(refreshed.access_token).toBeTypeOf('string');

    expect(driver.calls).toHaveLength(0);
    expect(driver.closed).toBe(false);
    expect(server.auth.gates.map((gate) => gate.name)).toEqual(['account_active']);
    expect(capture.matching('sql')).toHaveLength(0);
    expect(capture.records.some((record) => record.component === 'sql-group-check')).toBe(false);
  });
});
