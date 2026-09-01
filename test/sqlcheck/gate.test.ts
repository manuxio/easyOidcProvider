/**
 * Phase 4 unit suite: the SQL group gate, with a fake driver instead of a
 * database. What is being pinned down here:
 *
 *  - the switch: off means nothing is built and nothing is queried;
 *  - the three outcomes (row / no row / database silent);
 *  - the username reaches SQL as a BIND PARAMETER and never as text;
 *  - the placeholder contract is checked at build time, not at first login.
 */
import { describe, expect, it } from 'vitest';

import { loadConfig, type Config } from '../../src/config.js';
import {
  buildAccountGates,
  closeAccountGates,
  runAccountGates,
  SQL_GROUP_GATE_NAME,
  type AccountGate,
} from '../../src/gates/index.js';
import type { IdentityProvider } from '../../src/identity/types.js';
import { createSilentLogger } from '../../src/logger.js';
import {
  createSqlGroupChecker,
  MSSQL_PLACEHOLDER,
  MYSQL_PLACEHOLDER,
  SqlGroupChecker,
  SqlGroupCheckConfigError,
  SqlGroupCheckUnavailable,
} from '../../src/sqlcheck/index.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';
import { FakeSqlDriver } from '../helpers/fakeSqlDriver.js';

const QUERY = 'SELECT 1 FROM authorized_users WHERE username = ?';

/** An identity provider that always says "alive": this suite is about SQL. */
const alwaysActiveIdentity = {
  name: 'test-stub',
  async authenticate() {
    return { status: 'no-credentials' as const };
  },
  async isAccountActive() {
    return true;
  },
  async challenge() {
    /* no challenge in these tests */
  },
} satisfies IdentityProvider;

function configWith(env: Record<string, string>): Config {
  return loadConfig({
    ISSUER_URL: 'http://127.0.0.1:3000',
    DATA_DIR: '',
    IDENTITY_PROVIDER: 'dev-stub',
    DEV_STUB_USERS: '[{"username":"mario.rossi","password":"x","active":true}]',
    CLIENTS_JSON: '[{"client_id":"desktop-app","redirect_uris":["http://127.0.0.1/callback"]}]',
    ...env,
  });
}

const ENABLED = {
  SQL_GROUP_CHECK_ENABLED: 'true',
  SQL_DRIVER: 'mysql',
  SQL_CONNECTION_STRING: 'mysql://user:pw@127.0.0.1:3306/backoffice',
  SQL_GROUP_QUERY: QUERY,
};

async function verdictFor(gates: readonly AccountGate[], username: string) {
  return runAccountGates(
    gates,
    { principal: `${username}@TEST.LOCAL`, username, stage: 'login' },
    createSilentLogger(),
  );
}

describe('the switch decides whether anything exists at all', () => {
  it('builds no SQL gate and runs no query when SQL_GROUP_CHECK_ENABLED is false', async () => {
    const driver = new FakeSqlDriver({ authorized: ['mario.rossi'] });
    const capture = createCapturingLogger();

    const gates = buildAccountGates(
      configWith({ ...ENABLED, SQL_GROUP_CHECK_ENABLED: 'false' }),
      alwaysActiveIdentity,
      capture.logger,
      // Offered and deliberately ignored: with the switch off, the seam is dead.
      { sqlDriver: driver },
    );

    expect(gates.map((gate) => gate.name)).toEqual(['account_active']);

    const verdict = await verdictFor(gates, 'mario.rossi');
    expect(verdict.ok).toBe(true);

    // The whole claim of "no pool, no connection", in three assertions.
    expect(driver.calls).toHaveLength(0);
    expect(driver.closed).toBe(false);
    expect(capture.matching('sql')).toHaveLength(0);
  });

  it('appends the gate and announces it when the switch is on', () => {
    const capture = createCapturingLogger();
    const gates = buildAccountGates(
      configWith(ENABLED),
      alwaysActiveIdentity,
      capture.logger,
      { sqlDriver: new FakeSqlDriver() },
    );

    expect(gates.map((gate) => gate.name)).toEqual(['account_active', SQL_GROUP_GATE_NAME]);
    expect(capture.matching('SQL group check enabled')).toHaveLength(1);
  });

  it('leaves the SQL gate last: the cheap local check runs first', () => {
    const gates = buildAccountGates(
      configWith(ENABLED),
      alwaysActiveIdentity,
      createSilentLogger(),
      { sqlDriver: new FakeSqlDriver() },
    );
    expect(gates.at(-1)!.name).toBe(SQL_GROUP_GATE_NAME);
  });
});

describe('the three outcomes', () => {
  it('passes when the query returns a row', async () => {
    const driver = new FakeSqlDriver({ authorized: ['mario.rossi'] });
    const gates = buildAccountGates(
      configWith(ENABLED),
      alwaysActiveIdentity,
      createSilentLogger(),
      { sqlDriver: driver },
    );

    const verdict = await verdictFor(gates, 'mario.rossi');
    expect(verdict.ok).toBe(true);
    expect(driver.queriedUsernames).toEqual(['mario.rossi']);
  });

  it('denies with sql_group_check_failed when the query returns nothing', async () => {
    const driver = new FakeSqlDriver({ authorized: ['mario.rossi'] });
    const gates = buildAccountGates(
      configWith(ENABLED),
      alwaysActiveIdentity,
      createSilentLogger(),
      { sqlDriver: driver },
    );

    const verdict = await verdictFor(gates, 'luigi.verdi');
    expect(verdict).toMatchObject({
      ok: false,
      reason: 'sql_group_check_failed',
      gate: SQL_GROUP_GATE_NAME,
      // A real answer, not an outage: the caller may revoke the grant chain.
      unavailable: false,
    });
  });

  it('fails closed, and marks the verdict unavailable, when the database is silent', async () => {
    const driver = new FakeSqlDriver({ authorized: ['mario.rossi'] });
    driver.failWith = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:3306'), {
      code: 'ECONNREFUSED',
    });
    const gates = buildAccountGates(
      configWith(ENABLED),
      alwaysActiveIdentity,
      createSilentLogger(),
      { sqlDriver: driver },
    );

    // Even the user who IS in the table is rejected: never fail open.
    const verdict = await verdictFor(gates, 'mario.rossi');
    expect(verdict).toMatchObject({
      ok: false,
      gate: SQL_GROUP_GATE_NAME,
      // An outage of ours: the caller must NOT revoke the chain.
      unavailable: true,
    });
  });

  it('logs the fail-closed path loudly, with the fields an operator needs', async () => {
    const capture = createCapturingLogger();
    const driver = new FakeSqlDriver();
    driver.failWith = new Error('Access denied for user');
    const checker = createSqlGroupChecker(
      configWith(ENABLED).sqlGroupCheck,
      capture.logger,
      { driver },
    );

    await expect(checker.isAuthorized('mario.rossi')).rejects.toBeInstanceOf(
      SqlGroupCheckUnavailable,
    );

    const [record] = capture.withReason('sql_group_check_unavailable');
    expect(record).toBeDefined();
    expect(record!.level).toBe('error');
    expect(record!.username).toBe('mario.rossi');
    expect(record!.driver).toBe('fake');
    expect(record!.msg).toContain('fail closed');
  });
});

describe('the username is bound, never interpolated', () => {
  it('sends the query verbatim and the username as a parameter', async () => {
    const driver = new FakeSqlDriver({ authorized: ["o'brien"] });
    const gates = buildAccountGates(
      configWith(ENABLED),
      alwaysActiveIdentity,
      createSilentLogger(),
      { sqlDriver: driver },
    );

    // A username carrying the classic injection payload. It must come back
    // untouched in `params` and be absent from the SQL text.
    const hostile = "' OR 1=1 --";
    await verdictFor(gates, hostile);

    const call = driver.calls.at(-1)!;
    expect(call.sql).toBe(QUERY);
    expect(call.sql).not.toContain(hostile);
    expect(call.params).toEqual({ username: hostile });
  });

  it('asks about the platform username, not the full principal', async () => {
    const driver = new FakeSqlDriver({ authorized: ['mario.rossi'] });
    const gates = buildAccountGates(
      configWith(ENABLED),
      alwaysActiveIdentity,
      createSilentLogger(),
      { sqlDriver: driver },
    );

    await runAccountGates(
      gates,
      {
        principal: 'mario.rossi@LAB.EASYOIDC.LOCAL',
        username: 'mario.rossi',
        stage: 'refresh',
      },
      createSilentLogger(),
    );

    expect(driver.queriedUsernames).toEqual(['mario.rossi']);
  });
});

describe('the placeholder contract is checked at startup', () => {
  const build = (query: string, placeholder: string) =>
    createSqlGroupChecker(
      configWith({ ...ENABLED, SQL_GROUP_QUERY: query }).sqlGroupCheck,
      createSilentLogger(),
      { driver: new FakeSqlDriver({ placeholder }) },
    );

  it('accepts exactly one placeholder', () => {
    expect(build(QUERY, MYSQL_PLACEHOLDER)).toBeInstanceOf(SqlGroupChecker);
  });

  it('refuses a query with no placeholder: the username would not be bound at all', () => {
    expect(() => build('SELECT 1 FROM authorized_users', MYSQL_PLACEHOLDER))
      .toThrow(SqlGroupCheckConfigError);
  });

  it('refuses a query with two placeholders: the binding would be ambiguous', () => {
    expect(() => build('SELECT 1 FROM u WHERE a = ? OR b = ?', MYSQL_PLACEHOLDER))
      .toThrow(/exactly one/);
  });

  it('refuses an empty query — at the config layer, by parameter name', () => {
    expect(() => build('   ', MYSQL_PLACEHOLDER)).toThrow(/SQL_GROUP_QUERY is required/);
  });

  it('refuses a whitespace-only query at the checker too, in case config is bypassed', () => {
    expect(() => new SqlGroupChecker({
      query: '   ',
      driver: new FakeSqlDriver({ placeholder: MYSQL_PLACEHOLDER }),
      timeoutMs: 1000,
      logger: createSilentLogger(),
    })).toThrow(SqlGroupCheckConfigError);
  });

  it('uses the mssql placeholder when the driver is mssql', () => {
    const mssqlQuery = 'SELECT 1 FROM authorized_users WHERE username = @username';
    expect(build(mssqlQuery, MSSQL_PLACEHOLDER)).toBeInstanceOf(SqlGroupChecker);
    // The mysql query, handed to the mssql driver, binds nothing.
    expect(() => build(QUERY, MSSQL_PLACEHOLDER)).toThrow(/@username/);
  });

  it('warns when the query carries another engine placeholder', () => {
    const capture = createCapturingLogger();
    createSqlGroupChecker(
      configWith({
        ...ENABLED,
        SQL_GROUP_QUERY: 'SELECT 1 FROM u WHERE username = ? AND tenant = :username',
      }).sqlGroupCheck,
      capture.logger,
      { driver: new FakeSqlDriver({ name: 'mysql', placeholder: MYSQL_PLACEHOLDER }) },
    );
    expect(capture.matching('placeholder of another engine')).toHaveLength(1);
  });

  it('stops the whole build, not just the gate, when the query is wrong', () => {
    expect(() => buildAccountGates(
      configWith({ ...ENABLED, SQL_GROUP_QUERY: 'SELECT 1 FROM authorized_users' }),
      alwaysActiveIdentity,
      createSilentLogger(),
      { sqlDriver: new FakeSqlDriver() },
    )).toThrow(SqlGroupCheckConfigError);
  });
});

describe('the deadline', () => {
  it('rejects rather than hanging when the database never answers', async () => {
    const driver = new FakeSqlDriver({ authorized: ['mario.rossi'] });
    driver.hangForever = true;
    const capture = createCapturingLogger();
    const checker = createSqlGroupChecker(
      configWith({ ...ENABLED, SQL_TIMEOUT_MS: '80' }).sqlGroupCheck,
      capture.logger,
      { driver },
    );

    const started = Date.now();
    await expect(checker.isAuthorized('mario.rossi')).rejects.toThrow(/timed out after 80 ms/);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(capture.withReason('sql_group_check_unavailable')).toHaveLength(1);
  });

  it('defaults to 5 seconds and takes SQL_TIMEOUT_MS when given', () => {
    expect(configWith(ENABLED).sqlGroupCheck.timeoutMs).toBe(5000);
    expect(configWith({ ...ENABLED, SQL_TIMEOUT_MS: '1500' }).sqlGroupCheck.timeoutMs).toBe(1500);
  });
});

describe('configuration', () => {
  it('requires the SQL parameters only when the check is enabled', () => {
    // Off: the connection string and the query may be absent.
    expect(() => configWith({ SQL_GROUP_CHECK_ENABLED: 'false' })).not.toThrow();

    // On: both are demanded, by name.
    expect(() => configWith({ SQL_GROUP_CHECK_ENABLED: 'true' }))
      .toThrow(/SQL_CONNECTION_STRING is required.*SQL_GROUP_QUERY is required/s);
  });

  it('rejects an unknown SQL_DRIVER by name', () => {
    expect(() => configWith({ ...ENABLED, SQL_DRIVER: 'oracle' })).toThrow(/SQL_DRIVER/);
  });

  it('rejects a non-numeric SQL_TIMEOUT_MS by name', () => {
    expect(() => configWith({ ...ENABLED, SQL_TIMEOUT_MS: 'soon' })).toThrow(/SQL_TIMEOUT_MS/);
  });
});

describe('shutdown', () => {
  it('closes the SQL pool through the gate list', async () => {
    const driver = new FakeSqlDriver();
    const gates = buildAccountGates(
      configWith(ENABLED),
      alwaysActiveIdentity,
      createSilentLogger(),
      { sqlDriver: driver },
    );

    await closeAccountGates(gates, createSilentLogger());
    expect(driver.closed).toBe(true);
  });

  it('survives a gate that refuses to close', async () => {
    const capture = createCapturingLogger();
    const gates: AccountGate[] = [{
      name: 'stubborn',
      async check() {
        return { allowed: true };
      },
      async close() {
        throw new Error('pool is stuck');
      },
    }];

    await expect(closeAccountGates(gates, capture.logger)).resolves.toBeUndefined();
    expect(capture.matching('did not close cleanly')).toHaveLength(1);
  });
});
