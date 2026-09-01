/**
 * Phase 4 smoke suite: the mssql driver against a REAL SQL Server.
 *
 * The current customer runs MySQL, so this is a bonus rather than a requirement
 * — but the mssql driver exists precisely because the next installations will
 * not, and a driver nobody has ever run against its engine is a guess. It has
 * its own skip flag because the image is 2.3 GB and may not be pullable
 * everywhere.
 *
 * Skipped unless AUTH_MSSQL_IT=1. See the README for the container.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createSilentLogger } from '../../src/logger.js';
import {
  createMssqlDriver,
  MSSQL_PLACEHOLDER,
  SqlGroupChecker,
  SqlGroupCheckUnavailable,
  type SqlDriver,
} from '../../src/sqlcheck/index.js';

const ENABLED = process.env.AUTH_MSSQL_IT === '1';

/** Loopback-published port; Encrypt=false because the lab cert is self-signed. */
const CONNECTION_STRING = process.env.AUTH_MSSQL_IT_URL
  ?? 'Server=127.0.0.1,14330;Database=master;User Id=sa;Password=Str0ng!Passw0rd;'
    + 'Encrypt=false;TrustServerCertificate=true';

const UNREACHABLE = 'Server=127.0.0.1,14399;Database=master;User Id=sa;Password=Str0ng!Passw0rd;'
  + 'Encrypt=false;TrustServerCertificate=true;Connection Timeout=2';

const QUERY = `SELECT username FROM authorized_users WHERE username = ${MSSQL_PLACEHOLDER}`;

const AUTHORIZED = 'mario.rossi';
const NOT_AUTHORIZED = 'luigi.verdi';

const suite = ENABLED ? describe : describe.skip;

suite('mssql driver against a real SQL Server', () => {
  let driver: SqlDriver;
  let checker: SqlGroupChecker;

  beforeAll(async () => {
    driver = createMssqlDriver({ connectionString: CONNECTION_STRING, timeoutMs: 15_000 });
    await exec(driver, "IF OBJECT_ID('authorized_users','U') IS NOT NULL DROP TABLE authorized_users");
    await exec(driver, 'CREATE TABLE authorized_users (username NVARCHAR(64) NOT NULL PRIMARY KEY)');
    await exec(driver, `INSERT INTO authorized_users (username) VALUES ('${AUTHORIZED}')`);

    checker = new SqlGroupChecker({
      query: QUERY,
      driver,
      timeoutMs: 15_000,
      logger: createSilentLogger(),
    });
  }, 60_000);

  afterAll(async () => {
    await driver?.close();
  });

  it('authorizes a username that has a row', async () => {
    await expect(checker.isAuthorized(AUTHORIZED)).resolves.toBe(true);
  });

  it('denies a username that has no row', async () => {
    await expect(checker.isAuthorized(NOT_AUTHORIZED)).resolves.toBe(false);
  });

  it('binds @username instead of interpolating it', async () => {
    await expect(checker.isAuthorized("' OR '1'='1")).resolves.toBe(false);
    await expect(checker.isAuthorized("x'; DROP TABLE authorized_users; --")).resolves.toBe(false);
    await expect(checker.isAuthorized(AUTHORIZED)).resolves.toBe(true);
  });

  it('fails closed when nothing is listening on the port', async () => {
    const dead = createMssqlDriver({ connectionString: UNREACHABLE, timeoutMs: 4000 });
    const deadChecker = new SqlGroupChecker({
      query: QUERY,
      driver: dead,
      timeoutMs: 4000,
      logger: createSilentLogger(),
    });
    try {
      await expect(deadChecker.isAuthorized(AUTHORIZED)).rejects.toBeInstanceOf(
        SqlGroupCheckUnavailable,
      );
    } finally {
      await dead.close();
    }
  }, 20_000);
});

/** DDL/seed through the pool; only usernames ever travel as bind parameters. */
async function exec(driver: SqlDriver, sql: string): Promise<void> {
  try {
    await driver.query(sql, { username: '' });
  } catch (error) {
    if (!(error instanceof SqlGroupCheckUnavailable) || !/no recordset/.test(error.message)) {
      throw error;
    }
  }
}
