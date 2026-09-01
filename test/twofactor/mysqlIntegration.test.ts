/**
 * Phase 4-bis integration suite: TOTP seeds out of a REAL MySQL.
 *
 * The fake seed source proves the verifier; only a real database proves the SQL
 * source — the bind parameter really is a bind parameter, an absent row really
 * is `undefined` and not an exception, and a login really does complete with a
 * seed that never existed in the process before the query ran.
 *
 * Skipped unless AUTH_SQL_IT=1, so `npm test` stays green on a machine with no
 * container. It reuses the same container as the phase 4 suite — see the README.
 */
import { generateSync } from 'otplib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createSilentLogger } from '../../src/logger.js';
import {
  createMysqlDriver,
  SqlGroupCheckUnavailable,
  type SqlDriver,
} from '../../src/sqlcheck/index.js';
import {
  createSqlSeedSource,
  TwoFactorSeedUnavailable,
  type TwoFactorSeedSource,
} from '../../src/twofactor/index.js';
import { discover, exchange, login, LoginRejected } from '../helpers/flow.js';
import { startTestServer, type TestServer } from '../helpers/server.js';

const ENABLED = process.env.AUTH_SQL_IT === '1';

/** Published on loopback only: docker here is rootless, container IPs are unreachable. */
const CONNECTION_STRING = process.env.AUTH_SQL_IT_URL
  ?? 'mysql://authcheck:authcheckpw@127.0.0.1:33061/backoffice';

const SEED_QUERY = 'SELECT seed FROM totp_seeds WHERE username = ?';

const USER = 'mario.rossi';
const PASSWORD = 'Password1!';
const NOT_ENROLLED = 'luigi.verdi';
const NOT_ENROLLED_PASSWORD = 'Password2!';
/** 20 bytes of base32: what an enrolment record actually looks like. */
const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

const suite = ENABLED ? describe : describe.skip;

suite('TOTP seeds from a real MySQL', () => {
  let driver: SqlDriver;
  let source: TwoFactorSeedSource;
  let server: TestServer | undefined;

  beforeAll(async () => {
    driver = createMysqlDriver({ connectionString: CONNECTION_STRING, timeoutMs: 5000 });
    await rawExec(driver, 'DROP TABLE IF EXISTS totp_seeds');
    await rawExec(driver, `
      CREATE TABLE totp_seeds (
        username VARCHAR(64) NOT NULL PRIMARY KEY,
        seed VARCHAR(128) NULL
      )`);
    await rawExec(driver, `INSERT INTO totp_seeds (username, seed) VALUES
      ('${USER}', '${SEED}'),
      ('anna.bianchi', NULL)`);

    source = createSqlSeedSource({
      query: SEED_QUERY,
      driver,
      timeoutMs: 5000,
      logger: createSilentLogger(),
    });
  });

  afterAll(async () => {
    await server?.close();
    await driver?.close();
  });

  it('reads the seed of an enrolled user', async () => {
    await expect(source.lookup(USER)).resolves.toBe(SEED);
  });

  it('returns undefined for a user with no row', async () => {
    await expect(source.lookup(NOT_ENROLLED)).resolves.toBeUndefined();
  });

  it('reads a NULL seed as "not enrolled", not as an empty secret', async () => {
    await expect(source.lookup('anna.bianchi')).resolves.toBeUndefined();
  });

  it('binds the username instead of interpolating it', async () => {
    await expect(source.lookup("' OR '1'='1")).resolves.toBeUndefined();
    await expect(source.lookup("mario.rossi'; DROP TABLE totp_seeds; --"))
      .resolves.toBeUndefined();
    // The table survived, and still answers for the real user.
    await expect(source.lookup(USER)).resolves.toBe(SEED);
  });

  it('reports a broken query as unavailable, never as "not enrolled"', async () => {
    const broken = createSqlSeedSource({
      query: 'SELECT seed FROM table_that_does_not_exist WHERE username = ?',
      driver,
      timeoutMs: 5000,
      logger: createSilentLogger(),
    });
    await expect(broken.lookup(USER)).rejects.toBeInstanceOf(TwoFactorSeedUnavailable);
  });

  it('fails closed when nothing is listening on the port', async () => {
    const dead = createMysqlDriver({
      connectionString: 'mysql://authcheck:authcheckpw@127.0.0.1:33099/backoffice',
      timeoutMs: 2000,
    });
    const deadSource = createSqlSeedSource({
      query: SEED_QUERY,
      driver: dead,
      timeoutMs: 2000,
      logger: createSilentLogger(),
    });
    try {
      await expect(deadSource.lookup(USER)).rejects.toBeInstanceOf(TwoFactorSeedUnavailable);
    } finally {
      await dead.close();
    }
  });

  it('completes a whole login with the seed coming out of the database', async () => {
    server = await startTestServer({
      users: [
        { username: USER, password: PASSWORD },
        { username: NOT_ENROLLED, password: NOT_ENROLLED_PASSWORD },
      ],
      env: {
        TWO_FACTOR_ENABLED: 'true',
        TWO_FACTOR_SOURCE: 'sql',
        TWO_FACTOR_SQL_QUERY: SEED_QUERY,
        SQL_CONNECTION_STRING: CONNECTION_STRING,
      },
    });

    const config = await discover(server);
    const code = generateSync({ secret: SEED, epoch: Math.floor(Date.now() / 1000) });
    const result = await login(server, config, { username: USER, password: PASSWORD, otp: code });
    const tokens = await exchange(config, result);
    expect(tokens.claims()!.sub).toBe(USER);

    // ...and the user with no row in the table cannot get in at all.
    const refused = await login(server, config, {
      username: NOT_ENROLLED,
      password: NOT_ENROLLED_PASSWORD,
      otp: generateSync({ secret: SEED, epoch: Math.floor(Date.now() / 1000) }),
    }).catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(LoginRejected);
    expect((refused as LoginRejected).body).toContain('non è configurato il codice di verifica');
  });
});

/**
 * DDL and seed statements go through the driver's own pool but bypass the
 * bind-parameter path, which only ever carries a username. Test-only.
 */
async function rawExec(driver: SqlDriver, sql: string): Promise<void> {
  try {
    await driver.query(sql, { username: '' });
  } catch (error) {
    // CREATE/INSERT/DROP return a ResultSetHeader, which the driver rightly
    // refuses to read as rows. The statement still ran.
    if (!(error instanceof SqlGroupCheckUnavailable) || !/no result set/.test(error.message)) {
      throw error;
    }
  }
}
