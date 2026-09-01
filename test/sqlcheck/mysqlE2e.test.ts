/**
 * Phase 4 acceptance, end to end, on the wire: the whole OAuth2 flow with the
 * dev-stub identity provider and the SQL group check pointed at a REAL MySQL.
 *
 * This is the file that answers the plan's acceptance criteria with evidence
 * rather than with a fake:
 *   - a user present in `authorized_users` logs in and refreshes;
 *   - DELETE the row, and the next refresh is invalid_grant / sql_group_check_failed;
 *   - with the check off the server never opens a SQL connection — proved by
 *     MySQL's own `Connections` counter, not only by our log.
 *
 * Skipped unless AUTH_SQL_IT=1. See the README for the container.
 */
import * as client from 'openid-client';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import {
  createMysqlDriver,
  SqlGroupCheckUnavailable,
  type SqlDriver,
} from '../../src/sqlcheck/index.js';
import { createCapturingLogger, type CapturedLog } from '../helpers/captureLogger.js';
import { discover, exchange, login, LoginRejected, tokenRequest } from '../helpers/flow.js';
import { startTestServer, type TestServer } from '../helpers/server.js';

const ENABLED = process.env.AUTH_SQL_IT === '1';

const CONNECTION_STRING = process.env.AUTH_SQL_IT_URL
  ?? 'mysql://authcheck:authcheckpw@127.0.0.1:33061/backoffice';
/** Nothing listens here: used to show the disabled path never dials out. */
const DEAD_STRING = 'mysql://authcheck:authcheckpw@127.0.0.1:33099/backoffice';

const QUERY = 'SELECT username FROM authorized_users WHERE username = ?';

const MARIO = { username: 'mario.rossi', password: 'Password1!' };
const LUIGI = { username: 'luigi.verdi', password: 'Password2!' };

const suite = ENABLED ? describe : describe.skip;

const running: TestServer[] = [];

suite('the OAuth2 flow with a real MySQL behind the gate', () => {
  /** A pool of our own, used to seed and to read MySQL's status counters. */
  let admin: SqlDriver;

  beforeAll(async () => {
    admin = createMysqlDriver({ connectionString: CONNECTION_STRING, timeoutMs: 5000 });
    await exec(admin, 'DROP TABLE IF EXISTS authorized_users');
    await exec(
      admin,
      'CREATE TABLE authorized_users (username VARCHAR(64) NOT NULL PRIMARY KEY)',
    );
    await exec(admin, `INSERT INTO authorized_users (username) VALUES ('${MARIO.username}')`);
  });

  afterEach(async () => {
    while (running.length > 0) await running.pop()!.close();
  });

  afterAll(async () => {
    await admin?.close();
  });

  async function serverWith(
    env: Record<string, string>,
  ): Promise<{ server: TestServer; capture: ReturnType<typeof createCapturingLogger> }> {
    const capture = createCapturingLogger();
    const server = await startTestServer({
      users: [MARIO, LUIGI],
      env,
      logger: capture.logger,
    });
    running.push(server);
    return { server, capture };
  }

  const SQL_ON = {
    SQL_GROUP_CHECK_ENABLED: 'true',
    SQL_DRIVER: 'mysql',
    SQL_CONNECTION_STRING: CONNECTION_STRING,
    SQL_GROUP_QUERY: QUERY,
    SQL_TIMEOUT_MS: '4000',
  };

  it('lets in the user who has a row, and keeps letting them refresh', async () => {
    const { server } = await serverWith(SQL_ON);
    const config = await discover(server);

    const tokens = await exchange(config, await login(server, config, MARIO));
    expect(tokens.access_token).toBeTypeOf('string');

    const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token!);
    expect(refreshed.access_token).toBeTypeOf('string');
  });

  it('refuses the login of a user with no row, with the Italian message', async () => {
    const { server, capture } = await serverWith(SQL_ON);
    const config = await discover(server);

    const failure = await login(server, config, LUIGI).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LoginRejected);
    expect((failure as LoginRejected).body).toContain('non risulta abilitata all');

    const denial = capture.withReason('sql_group_check_failed')
      .find((record) => record.gate === 'sql_group');
    expect(denial).toBeDefined();
    report('login denied — structured log line', denial!);
  });

  it('rejects the next refresh once the row is deleted mid-session', async () => {
    const { server, capture } = await serverWith(SQL_ON);
    const config = await discover(server);

    const tokens = await exchange(config, await login(server, config, MARIO));
    const good = await client.refreshTokenGrant(config, tokens.refresh_token!);
    expect(good.refresh_token).toBeTypeOf('string');

    // The customer takes the authorization away in their own database.
    await exec(admin, `DELETE FROM authorized_users WHERE username = '${MARIO.username}'`);
    try {
      const refused = await tokenRequest(server, {
        grant_type: 'refresh_token',
        refresh_token: good.refresh_token!,
      });
      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe('invalid_grant');
      // oidc-provider deliberately flattens the description of an invalid_grant
      // on the wire ("grant request is invalid"): a client must not learn WHY a
      // grant died. The reason lives in our log, which is where it belongs.
      expect(refused.body.error_description).toBe('grant request is invalid');

      const revocation = capture.withReason('sql_group_check_failed')
        .find((record) => record.revoked === true);
      expect(revocation).toBeDefined();
      report('refresh rejected — structured log line', revocation!);

      // The chain is revoked: putting the row back does not bring the token back.
      await exec(admin, `INSERT INTO authorized_users (username) VALUES ('${MARIO.username}')`);
      const replay = await tokenRequest(server, {
        grant_type: 'refresh_token',
        refresh_token: good.refresh_token!,
      });
      expect(replay.body.error).toBe('invalid_grant');
    } finally {
      await exec(
        admin,
        `INSERT IGNORE INTO authorized_users (username) VALUES ('${MARIO.username}')`,
      );
    }
  });

  it('never opens a SQL connection when the check is disabled', async () => {
    // Even pointed at a dead port. If the server dialled at all, the gate would
    // fail closed and this login would not happen.
    const { server, capture } = await serverWith({
      ...SQL_ON,
      SQL_GROUP_CHECK_ENABLED: 'false',
      SQL_CONNECTION_STRING: DEAD_STRING,
    });

    const before = await connectionCount(admin);
    const config = await discover(server);
    const tokens = await exchange(config, await login(server, config, LUIGI));
    await client.refreshTokenGrant(config, tokens.refresh_token!);
    const after = await connectionCount(admin);

    expect(server.auth.gates.map((gate) => gate.name)).toEqual(['account_active']);
    // MySQL counts every connection attempt it accepts. Nothing was added.
    expect(after).toBe(before);
    expect(capture.matching('sql')).toHaveLength(0);
    report('check disabled — MySQL Connections counter', { before, after });
  });

  it('fails closed at refresh when the database has gone away', async () => {
    const { server, capture } = await serverWith({
      ...SQL_ON,
      SQL_CONNECTION_STRING: DEAD_STRING,
      SQL_TIMEOUT_MS: '2000',
    });
    const config = await discover(server);

    // Even the login cannot happen: the gate rejects rather than passing.
    const failure = await login(server, config, MARIO).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(LoginRejected);
    expect((failure as LoginRejected).body).toContain('Riprovare tra qualche minuto');

    const outage = capture.withReason('sql_group_check_unavailable')[0];
    expect(outage).toBeDefined();
    report('database unreachable — structured log line', outage!);
  });
});

/** MySQL's own count of accepted connections since it started. */
async function connectionCount(driver: SqlDriver): Promise<number> {
  const rows = await driver.query(
    "SHOW GLOBAL STATUS LIKE 'Connections'",
    { username: '' },
  );
  return Number((rows[0] as { Value?: string } | undefined)?.Value ?? -1);
}

/** DDL/seed through the pool; only usernames ever travel as bind parameters. */
async function exec(driver: SqlDriver, sql: string): Promise<void> {
  try {
    await driver.query(sql, { username: '' });
  } catch (error) {
    if (!(error instanceof SqlGroupCheckUnavailable) || !/no result set/.test(error.message)) {
      throw error;
    }
  }
}

/** Prints the evidence the phase report has to carry, verbatim. */
function report(label: string, record: CapturedLog | Record<string, unknown>): void {
  console.log(`\n[phase4] ${label}\n${JSON.stringify(record)}`);
}
