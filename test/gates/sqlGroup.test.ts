/**
 * Phase 4: the SQL group gate on its own (src/gates/sqlGroup.ts), on a real
 * SqlGroupChecker over the fake driver.
 *
 * test/sqlcheck/gate.test.ts proves the gate through buildAccountGates; this
 * file pins the adapter between checker and gate contract, from the header of
 * sqlGroup.ts:
 *
 *   row present  ⇒ { allowed: true }
 *   no row       ⇒ { allowed: false, reason: 'sql_group_check_failed' }
 *   DB silent    ⇒ throw (runAccountGates makes it `unavailable`)
 *
 * and that it asks about the USERNAME, never the principal, and closes the
 * checker's pool.
 */
import { describe, expect, it } from 'vitest';

import {
  runAccountGates,
  SQL_GROUP_CHECK_FAILED,
  SQL_GROUP_GATE_NAME,
  sqlGroupGate,
  type AccountGateContext,
} from '../../src/gates/index.js';
import { createSilentLogger } from '../../src/logger.js';
import { SqlGroupChecker, SqlGroupCheckUnavailable } from '../../src/sqlcheck/index.js';
import { FakeSqlDriver } from '../helpers/fakeSqlDriver.js';

const QUERY = 'SELECT 1 FROM authorized_users WHERE username = ?';

function gateOver(driver: FakeSqlDriver) {
  const checker = new SqlGroupChecker({ query: QUERY, driver, timeoutMs: 1000, logger: createSilentLogger() });
  return sqlGroupGate(checker);
}

const context = (username: string): AccountGateContext => ({
  principal: `${username}@EXAMPLE.LOCAL`,
  username,
  stage: 'refresh',
  clientId: 'client-x',
});

describe('the SQL group gate', () => {
  it('is named sql_group and refuses with sql_group_check_failed', () => {
    expect(SQL_GROUP_GATE_NAME).toBe('sql_group');
    expect(SQL_GROUP_CHECK_FAILED).toBe('sql_group_check_failed');
    expect(gateOver(new FakeSqlDriver()).name).toBe(SQL_GROUP_GATE_NAME);
  });

  it('allows a username the query finds', async () => {
    const gate = gateOver(new FakeSqlDriver({ authorized: ['mario.rossi'] }));
    await expect(gate.check(context('mario.rossi'))).resolves.toEqual({ allowed: true });
  });

  it('refuses a username the query does not find', async () => {
    const gate = gateOver(new FakeSqlDriver({ authorized: ['mario.rossi'] }));
    await expect(gate.check(context('luigi.verdi'))).resolves.toEqual({
      allowed: false,
      reason: SQL_GROUP_CHECK_FAILED,
    });
  });

  it('asks about the username, never the principal', async () => {
    const driver = new FakeSqlDriver({ authorized: ['mario.rossi'] });
    await gateOver(driver).check(context('mario.rossi'));
    expect(driver.queriedUsernames).toEqual(['mario.rossi']);
  });

  it('throws when the database is silent, which runAccountGates reads as unavailable', async () => {
    const driver = new FakeSqlDriver({ authorized: ['mario.rossi'] });
    driver.failWith = new Error('connect ECONNREFUSED 127.0.0.1:3306');
    const gate = gateOver(driver);

    await expect(gate.check(context('mario.rossi'))).rejects.toBeInstanceOf(SqlGroupCheckUnavailable);
    await expect(runAccountGates([gate], context('mario.rossi'), createSilentLogger())).resolves.toEqual({
      ok: false,
      reason: 'gate_unavailable',
      gate: SQL_GROUP_GATE_NAME,
      unavailable: true,
    });
  });

  it('closes the pool through the checker', async () => {
    const driver = new FakeSqlDriver();
    const gate = gateOver(driver);
    await gate.close?.();
    expect(driver.closed).toBe(true);
  });
});
