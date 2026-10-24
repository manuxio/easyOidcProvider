/**
 * Phase 4: SqlGroupChecker and the shared placeholder rule (src/sqlcheck/checker.ts),
 * on the fake driver, for what gate.test.ts does not already pin.
 *
 * validateQuery is the startup rule of FOUR customer-written queries now
 * (SQL_GROUP_QUERY, TWO_FACTOR_SQL_QUERY, CLAIMS_SQL_QUERY, AUTH_SQL_QUERY):
 * exactly one occurrence of the driver's placeholder, the operator told by
 * parameter name, and a warning — not a refusal — for another engine's
 * placeholder. The checker counts rows, owns the deadline and the loud
 * fail-closed log, and wraps whatever the driver throws.
 */
import { describe, expect, it } from 'vitest';

import { createSilentLogger } from '../../src/logger.js';
import {
  MSSQL_PLACEHOLDER,
  SqlGroupChecker,
  SqlGroupCheckConfigError,
  SqlGroupCheckUnavailable,
  validateQuery,
} from '../../src/sqlcheck/index.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';
import { FakeSqlDriver } from '../helpers/fakeSqlDriver.js';

const QUERY = 'SELECT 1 FROM authorized_users WHERE username = ?';

function failureOf(run: () => void): SqlGroupCheckConfigError {
  try {
    run();
  } catch (error) {
    if (error instanceof SqlGroupCheckConfigError) return error;
    throw error;
  }
  throw new Error('the query was accepted');
}

describe('validateQuery: exactly one placeholder, by parameter name', () => {
  const mysql = new FakeSqlDriver({ name: 'mysql' });
  const mssql = new FakeSqlDriver({ name: 'mssql', placeholder: MSSQL_PLACEHOLDER });

  it('names SQL_GROUP_QUERY when no parameter name is given', () => {
    expect(failureOf(() => validateQuery('  ', mysql, createSilentLogger())).message)
      .toBe('SQL_GROUP_QUERY is empty');
  });

  it('names the parameter it is given', () => {
    expect(failureOf(() => validateQuery('', mysql, createSilentLogger(), 'TWO_FACTOR_SQL_QUERY')).message)
      .toBe('TWO_FACTOR_SQL_QUERY is empty');
  });

  it('says which placeholder, which driver and how many it found', () => {
    expect(failureOf(() => validateQuery('SELECT 1 FROM t WHERE a = ? OR b = ?', mysql, createSilentLogger(), 'AUTH_SQL_QUERY')).message)
      .toBe('AUTH_SQL_QUERY must contain exactly one "?" placeholder for the username with SQL_DRIVER=mysql, found 2');
    expect(failureOf(() => validateQuery('SELECT 1 FROM t', mssql, createSilentLogger())).message)
      .toBe('SQL_GROUP_QUERY must contain exactly one "@username" placeholder for the username with SQL_DRIVER=mssql, found 0');
  });

  it('counts the text, so a ? inside a string literal counts too, and the query is refused', () => {
    // The rule is textual on purpose: it never tries to parse SQL. A literal
    // question mark has to be written some other way (CHAR(63)).
    expect(failureOf(() => validateQuery("SELECT 1 FROM t WHERE note = 'why?' AND u = ?", mysql, createSilentLogger())).message)
      .toMatch(/found 2$/);
  });

  it('counts a longer name that starts with @username as an occurrence', () => {
    expect(failureOf(() => validateQuery('SELECT 1 FROM t WHERE a = @username AND b = @usernames', mssql, createSilentLogger())).message)
      .toMatch(/found 2$/);
  });

  it('accepts the query once trimmed, without returning anything', () => {
    expect(validateQuery(`\n  ${QUERY}  \n`, mysql, createSilentLogger())).toBeUndefined();
  });
});

describe('validateQuery: another engine placeholder is a warning, not a refusal', () => {
  it.each([
    ['mysql', '?', 'SELECT 1 FROM t WHERE u = ? AND x = $1', '$1'],
    ['mysql', '?', 'SELECT 1 FROM t WHERE u = ? AND x = @username', '@username'],
    ['mssql', MSSQL_PLACEHOLDER, 'SELECT 1 FROM t WHERE u = @username AND x = :username', ':username'],
    ['mssql', MSSQL_PLACEHOLDER, 'SELECT 1 FROM t WHERE u = @username AND x = $1', '$1'],
  ])('warns for %s when the query also carries %s… (%s)', (name, placeholder, query, foreign) => {
    const capture = createCapturingLogger();
    validateQuery(query, new FakeSqlDriver({ name, placeholder }), capture.logger, 'CLAIMS_SQL_QUERY');
    const lines = capture.matching('placeholder of another engine');
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({
      level: 'warn',
      driver: name,
      parameter: 'CLAIMS_SQL_QUERY',
      foreignPlaceholder: foreign,
    });
    expect(String(lines[0]!.msg)).toMatch(/^CLAIMS_SQL_QUERY contains a placeholder/);
  });

  it('warns once per foreign placeholder found', () => {
    const capture = createCapturingLogger();
    validateQuery(
      'SELECT 1 FROM t WHERE u = ? AND a = :username AND b = $1',
      new FakeSqlDriver({ name: 'mysql' }),
      capture.logger,
    );
    expect(capture.matching('placeholder of another engine').map((line) => line.foreignPlaceholder))
      .toEqual([':username', '$1']);
  });

  it('does not warn for a ? in an mssql query: it is not on the list for that engine', () => {
    const capture = createCapturingLogger();
    validateQuery(
      "SELECT 1 FROM t WHERE u = @username AND note <> '?'",
      new FakeSqlDriver({ name: 'mssql', placeholder: MSSQL_PLACEHOLDER }),
      capture.logger,
    );
    expect(capture.matching('placeholder of another engine')).toHaveLength(0);
  });

  it('knows no foreign placeholders for an engine it has no list for', () => {
    const capture = createCapturingLogger();
    validateQuery('SELECT 1 FROM t WHERE u = ? AND x = $1', new FakeSqlDriver({ name: 'fake' }), capture.logger);
    expect(capture.records).toHaveLength(0);
  });
});

describe('SqlGroupChecker', () => {
  function checkerOver(driver: FakeSqlDriver, logger = createSilentLogger()) {
    return new SqlGroupChecker({ query: QUERY, driver, timeoutMs: 1000, logger });
  }

  it('validates at construction, under the SQL_GROUP_QUERY name', () => {
    expect(() => new SqlGroupChecker({
      query: 'SELECT 1 FROM t',
      driver: new FakeSqlDriver(),
      timeoutMs: 1000,
      logger: createSilentLogger(),
    })).toThrow(/^SQL_GROUP_QUERY must contain exactly one/);
  });

  it('counts any number of rows as authorized, whatever their shape', async () => {
    const driver = new FakeSqlDriver({ rows: new Map([['mario.rossi', [{}, { anything: null }]]]) });
    await expect(checkerOver(driver).isAuthorized('mario.rossi')).resolves.toBe(true);
    await expect(checkerOver(driver).isAuthorized('luigi.verdi')).resolves.toBe(false);
  });

  it('logs every answer at debug, with the row count', async () => {
    const capture = createCapturingLogger();
    const driver = new FakeSqlDriver({ authorized: ['mario.rossi'] });
    const checker = checkerOver(driver, capture.logger);
    await checker.isAuthorized('mario.rossi');
    await checker.isAuthorized('luigi.verdi');

    expect(capture.matching('sql group check: user found')[0]).toMatchObject({
      level: 'debug', username: 'mario.rossi', rows: 1, authorized: true, component: 'sql-group-check', driver: 'fake',
    });
    expect(capture.matching('sql group check: no row for this user')[0]).toMatchObject({
      username: 'luigi.verdi', rows: 0, authorized: false,
    });
  });

  it('passes a SqlGroupCheckUnavailable from the driver through untouched', async () => {
    const driver = new FakeSqlDriver();
    const original = new SqlGroupCheckUnavailable('fake', 'pool exhausted');
    driver.failWith = original;
    await expect(checkerOver(driver).isAuthorized('mario.rossi')).rejects.toBe(original);
  });

  it('wraps any other error, keeping the message and the cause', async () => {
    const driver = new FakeSqlDriver({ name: 'mysql' });
    const original = new Error('ER_ACCESS_DENIED_ERROR');
    driver.failWith = original;
    const failure = await checkerOver(driver).isAuthorized('mario.rossi').catch((error: unknown) => error) as SqlGroupCheckUnavailable;
    expect(failure).toBeInstanceOf(SqlGroupCheckUnavailable);
    expect(failure.name).toBe('SqlGroupCheckUnavailable');
    expect(failure.driver).toBe('mysql');
    expect(failure.message).toBe('ER_ACCESS_DENIED_ERROR');
    expect(failure.cause).toBe(original);
  });

  it('wraps a thrown non-Error with its string form', async () => {
    const driver = new FakeSqlDriver();
    (driver as { failWith?: unknown }).failWith = 'socket closed';
    await expect(checkerOver(driver).isAuthorized('mario.rossi')).rejects.toThrow('socket closed');
  });

  it('closes the driver', async () => {
    const driver = new FakeSqlDriver();
    await checkerOver(driver).close();
    expect(driver.closed).toBe(true);
  });
});
