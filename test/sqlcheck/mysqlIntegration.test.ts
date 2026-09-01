/**
 * Phase 4 integration suite: the mysql2 driver against a REAL MySQL.
 *
 * A fake driver proves the gate; only a real database proves the driver — the
 * bind parameter really is a bind parameter, an empty result set really is an
 * empty array, and a stopped server really does surface as an error instead of
 * hanging forever.
 *
 * Skipped unless AUTH_SQL_IT=1, so `npm test` stays green on a machine with no
 * container. See the README for the two commands that set it up.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createSilentLogger } from '../../src/logger.js';
import {
  createMysqlDriver,
  SqlGroupChecker,
  SqlGroupCheckUnavailable,
  type SqlDriver,
} from '../../src/sqlcheck/index.js';

const ENABLED = process.env.AUTH_SQL_IT === '1';

/** Published on loopback only: docker here is rootless, container IPs are unreachable. */
const CONNECTION_STRING = process.env.AUTH_SQL_IT_URL
  ?? 'mysql://authcheck:authcheckpw@127.0.0.1:33061/backoffice';

/** A dead port on loopback: nothing listens, connect fails at once. */
const UNREACHABLE = 'mysql://authcheck:authcheckpw@127.0.0.1:33099/backoffice';

const QUERY = 'SELECT username FROM authorized_users WHERE username = ?';

const AUTHORIZED = 'mario.rossi';
const NOT_AUTHORIZED = 'luigi.verdi';

const suite = ENABLED ? describe : describe.skip;

suite('mysql2 driver against a real MySQL', () => {
  let driver: SqlDriver;
  let checker: SqlGroupChecker;

  beforeAll(async () => {
    driver = createMysqlDriver({ connectionString: CONNECTION_STRING, timeoutMs: 5000 });
    // The seeding runs through the driver itself, which is also the first proof
    // that the connection string in the README actually connects.
    await driver.query('DROP TABLE IF EXISTS authorized_users', { username: '' })
      .catch(() => undefined);
    await rawExec(driver, `
      CREATE TABLE authorized_users (
        username VARCHAR(64) NOT NULL PRIMARY KEY,
        note VARCHAR(255) NULL
      )`);
    await rawExec(driver, `INSERT INTO authorized_users (username, note) VALUES
      ('${AUTHORIZED}', 'abilitato'),
      ('anna.bianchi', 'abilitata')`);

    checker = new SqlGroupChecker({
      query: QUERY,
      driver,
      timeoutMs: 5000,
      logger: createSilentLogger(),
    });
  });

  afterAll(async () => {
    await driver?.close();
  });

  it('authorizes a username that has a row', async () => {
    await expect(checker.isAuthorized(AUTHORIZED)).resolves.toBe(true);
  });

  it('denies a username that has no row', async () => {
    await expect(checker.isAuthorized(NOT_AUTHORIZED)).resolves.toBe(false);
  });

  it('binds the username instead of interpolating it', async () => {
    // If the value were concatenated into the SQL, this payload would turn the
    // WHERE into a tautology and the answer would be `true`.
    await expect(checker.isAuthorized("' OR '1'='1")).resolves.toBe(false);
    // And it would break the statement outright here.
    await expect(checker.isAuthorized("mario.rossi'; DROP TABLE authorized_users; --"))
      .resolves.toBe(false);
    // The table is still there, and still says yes to the real user.
    await expect(checker.isAuthorized(AUTHORIZED)).resolves.toBe(true);
  });

  it('reports a syntactically wrong query as unavailable, not as "not authorized"', async () => {
    const broken = new SqlGroupChecker({
      query: 'SELECT 1 FROM table_that_does_not_exist WHERE username = ?',
      driver,
      timeoutMs: 5000,
      logger: createSilentLogger(),
    });
    await expect(broken.isAuthorized(AUTHORIZED)).rejects.toBeInstanceOf(SqlGroupCheckUnavailable);
  });

  it('fails closed when nothing is listening on the port', async () => {
    const dead = createMysqlDriver({ connectionString: UNREACHABLE, timeoutMs: 2000 });
    const deadChecker = new SqlGroupChecker({
      query: QUERY,
      driver: dead,
      timeoutMs: 2000,
      logger: createSilentLogger(),
    });
    try {
      await expect(deadChecker.isAuthorized(AUTHORIZED)).rejects.toBeInstanceOf(
        SqlGroupCheckUnavailable,
      );
    } finally {
      await dead.close();
    }
  });

  it('closes the pool without complaining, twice', async () => {
    const spare = createMysqlDriver({ connectionString: CONNECTION_STRING, timeoutMs: 5000 });
    await spare.close();
    await expect(spare.close()).resolves.toBeUndefined();
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
    // CREATE/INSERT return a ResultSetHeader, which the driver rightly refuses
    // to read as rows. The statement still ran; anything else is a real failure.
    if (!(error instanceof SqlGroupCheckUnavailable) || !/no result set/.test(error.message)) {
      throw error;
    }
  }
}
