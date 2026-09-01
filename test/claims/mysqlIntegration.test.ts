/**
 * Phase 4-ter integration suite: the extra claims against a REAL MySQL, with
 * the customer's OWN query, verbatim, against a table shaped like theirs.
 *
 * A fake driver proves the policy; only a real database proves that the
 * contract survives contact with mysql2 — that an alias really does come back
 * as the result column name, that an INT really does arrive as a JS number,
 * that a NULL really does arrive as `null` and not as an empty string, and that
 * the username really is bound rather than pasted into the SQL.
 *
 * Skipped unless AUTH_SQL_IT=1, so `npm test` stays green on a machine with no
 * container. Same switch and same container as the phase-4 suite; see the
 * README for the two commands that set it up.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createSqlClaimsSource,
  EXTRA_CLAIMS_REASONS,
  ExtraClaimsUnavailable,
  ExtraClaimsUserNotFound,
  type ExtraClaimsSource,
} from '../../src/claims/index.js';
import { createSilentLogger } from '../../src/logger.js';
import {
  createMysqlDriver,
  SqlGroupCheckUnavailable,
  type SqlDriver,
} from '../../src/sqlcheck/index.js';
import { CUSTOMER_CLAIMS_QUERY } from '../helpers/claimsQuery.js';

const ENABLED = process.env.AUTH_SQL_IT === '1';

/** Published on loopback only: docker here is rootless, container IPs are unreachable. */
const CONNECTION_STRING = process.env.AUTH_SQL_IT_URL
  ?? 'mysql://authcheck:authcheckpw@127.0.0.1:33061/backoffice';

/** A dead port on loopback: nothing listens, connect fails at once. */
const UNREACHABLE = 'mysql://authcheck:authcheckpw@127.0.0.1:33099/backoffice';

const MARIO = 'mario.rossi';
const ANNA = 'anna.bianchi';
const UNKNOWN = 'luigi.verdi';

const suite = ENABLED ? describe : describe.skip;

suite('extra claims against a real MySQL', () => {
  let driver: SqlDriver;
  let source: ExtraClaimsSource;

  beforeAll(async () => {
    driver = createMysqlDriver({ connectionString: CONNECTION_STRING, timeoutMs: 5000 });

    await rawExec(driver, 'DROP TABLE IF EXISTS users');
    // The customer's shape, as far as their query touches it. `nome` is
    // nullable on purpose: it is how the NULL rule gets a real NULL.
    await rawExec(driver, `
      CREATE TABLE users (
        ID INT NOT NULL PRIMARY KEY,
        userid VARCHAR(64) NOT NULL UNIQUE,
        nome VARCHAR(64) NULL,
        cognome VARCHAR(64) NULL
      )`);
    // Deliberately ugly casing: the prettifying is the CUSTOMER's business,
    // written into their query, and this proves we do none of it ourselves.
    await rawExec(driver, `INSERT INTO users (ID, userid, nome, cognome) VALUES
      (4217, '${MARIO}', 'MARIO', 'rossi'),
      (4218, '${ANNA}', NULL, NULL)`);

    source = createSqlClaimsSource({
      query: CUSTOMER_CLAIMS_QUERY,
      driver,
      timeoutMs: 5000,
      logger: createSilentLogger(),
    });
  });

  afterAll(async () => {
    await driver?.close();
  });

  it('declares the claim names the query aliases, before touching the database', () => {
    expect(source.claimNames).toEqual(['remoteId', 'name']);
  });

  it('reads the row and gives the columns their own names', async () => {
    // `Mario Rossi` is the customer's CONCAT/UPPER/LOWER at work on
    // ('MARIO', 'rossi'): no cosmetics of ours anywhere on this path.
    await expect(source.lookup(MARIO)).resolves.toEqual({
      remoteId: 4217,
      name: 'Mario Rossi',
    });
  });

  it('keeps an INT an integer, not a string', async () => {
    const claims = await source.lookup(MARIO);
    expect(typeof claims.remoteId).toBe('number');
  });

  it('refuses a username with no row, and calls it "not found", not "unavailable"', async () => {
    const failure = await source.lookup(UNKNOWN).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ExtraClaimsUserNotFound);
    expect((failure as ExtraClaimsUserNotFound).reason).toBe(EXTRA_CLAIMS_REASONS.userNotFound);
  });

  it('omits a NULL column instead of emitting null', async () => {
    // CONCAT_WS skips NULLs, so the customer's query turns two NULL names into
    // an empty string; a query that selects the column straight gives a real
    // NULL, which is the case the rule is about.
    const plain = createSqlClaimsSource({
      query: 'SELECT ID AS remoteId, nome AS name FROM users WHERE userid = ?',
      driver,
      timeoutMs: 5000,
      logger: createSilentLogger(),
    });
    const claims = await plain.lookup(ANNA);
    expect(claims).toEqual({ remoteId: 4218 });
    expect('name' in claims).toBe(false);
  });

  it('binds the username instead of interpolating it', async () => {
    // Concatenated, this payload would turn the WHERE into a tautology and the
    // lookup would return every row; bound, it simply matches nothing.
    await expect(source.lookup("' OR '1'='1")).rejects.toBeInstanceOf(ExtraClaimsUserNotFound);
    await expect(source.lookup(`${MARIO}'; DROP TABLE users; --`))
      .rejects.toBeInstanceOf(ExtraClaimsUserNotFound);
    // The table is still there, and still answers for the real user.
    await expect(source.lookup(MARIO)).resolves.toMatchObject({ remoteId: 4217 });
  });

  it('refuses more than one row rather than choosing an identity', async () => {
    const ambiguous = createSqlClaimsSource({
      query: 'SELECT ID AS remoteId FROM users WHERE userid <> ?',
      driver,
      timeoutMs: 5000,
      logger: createSilentLogger(),
    });
    const failure = await ambiguous.lookup('nobody').catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ExtraClaimsUnavailable);
    expect((failure as ExtraClaimsUnavailable).reason).toBe(EXTRA_CLAIMS_REASONS.ambiguousRows);
  });

  it('reports a syntactically wrong query as unavailable, not as "no row"', async () => {
    const broken = createSqlClaimsSource({
      query: 'SELECT ID AS remoteId FROM table_that_does_not_exist WHERE userid = ?',
      driver,
      timeoutMs: 5000,
      logger: createSilentLogger(),
    });
    await expect(broken.lookup(MARIO)).rejects.toBeInstanceOf(ExtraClaimsUnavailable);
  });

  it('fails closed when nothing is listening on the port', async () => {
    const dead = createMysqlDriver({ connectionString: UNREACHABLE, timeoutMs: 2000 });
    const deadSource = createSqlClaimsSource({
      query: CUSTOMER_CLAIMS_QUERY,
      driver: dead,
      timeoutMs: 2000,
      logger: createSilentLogger(),
    });
    try {
      const failure = await deadSource.lookup(MARIO).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(ExtraClaimsUnavailable);
      expect((failure as ExtraClaimsUnavailable).reason).toBe(EXTRA_CLAIMS_REASONS.unavailable);
    } finally {
      await dead.close();
    }
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
    // refuses to read as rows. The statement still ran; anything else is real.
    if (!(error instanceof SqlGroupCheckUnavailable) || !/no result set/.test(error.message)) {
      throw error;
    }
  }
}
