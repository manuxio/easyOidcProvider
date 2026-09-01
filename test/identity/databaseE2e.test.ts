/**
 * IDENTITY_PROVIDER=database end to end: the real OIDC flow (form, code,
 * token) with the credentials answered by a fake SQL driver standing in for
 * the customer database. What is fake is only the wire to MySQL; the form is
 * real, the PKCE exchange is real, the provider chain is real.
 */
import bcrypt from 'bcryptjs';
import { generateSync } from 'otplib';
import { afterEach, describe, expect, it } from 'vitest';

import type { SqlDriver, SqlQueryParams, SqlRow } from '../../src/sqlcheck/index.js';
import {
  decodeJwtPayload,
  discover,
  exchange,
  login,
  LoginRejected,
} from '../helpers/flow.js';
import { startTestServer, type TestServer } from '../helpers/server.js';

const PASSWORD = 'Password1!';
const HASH = bcrypt.hashSync(PASSWORD, 10);
const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

const AUTH_QUERY = 'SELECT passwordhash, totpsecret FROM users WHERE username = ? AND active = 1';
const SEED_QUERY = 'SELECT totpsecret FROM users WHERE username = ?';

/** One table, two queries: credentials for the provider, seed for the 2FA. */
function fakeCustomerDatabase(rows: Record<string, SqlRow>): SqlDriver {
  return {
    name: 'mysql',
    placeholder: '?',
    async query(sql: string, params: SqlQueryParams): Promise<SqlRow[]> {
      const row = rows[params.username];
      if (!row) return [];
      if (sql === AUTH_QUERY) return [row];
      if (sql === SEED_QUERY) return [{ totpsecret: row.totpsecret ?? null }];
      throw new Error(`unexpected query: ${sql}`);
    },
    async close() {},
  };
}

const DATABASE_ENV = {
  IDENTITY_PROVIDER: 'database',
  AUTH_DB_SOURCE: 'sql',
  AUTH_SQL_QUERY: AUTH_QUERY,
  SQL_CONNECTION_STRING: 'mysql://user:pass@db.invalid:3306/users',
};

const running: TestServer[] = [];

async function server(rows: Record<string, SqlRow>, env: Record<string, string> = {}): Promise<TestServer> {
  const started = await startTestServer({
    env: { ...DATABASE_ENV, ...env },
    sqlDriver: fakeCustomerDatabase(rows),
  });
  running.push(started);
  return started;
}

afterEach(async () => {
  while (running.length > 0) await running.pop()!.close();
});

describe('database identity provider, end to end', () => {
  it('logs in through the form and issues tokens with the database identity', async () => {
    const s = await server({ 'mario.rossi': { passwordhash: HASH } });
    const config = await discover(s);
    const result = await login(s, config, { username: 'Mario.Rossi', password: PASSWORD });
    const tokens = await exchange(config, result);

    const idToken = decodeJwtPayload(tokens.id_token!);
    expect(idToken.sub).toBe('mario.rossi');
    // No REALM configured: the claim says so instead of inventing a domain.
    expect(idToken.realm).toBe('');
  });

  it('rejects a wrong password and an unknown user the same way', async () => {
    const s = await server({ 'mario.rossi': { passwordhash: HASH } });
    const config = await discover(s);
    await expect(login(s, config, { username: 'mario.rossi', password: 'wrong' }))
      .rejects.toBeInstanceOf(LoginRejected);
    await expect(login(s, config, { username: 'nessuno', password: PASSWORD }))
      .rejects.toBeInstanceOf(LoginRejected);
  });

  it('asks for the TOTP code when the second factor is on, seed from the same database', async () => {
    const rows = { 'mario.rossi': { passwordhash: HASH, totpsecret: SEED } };
    const s = await server(rows, {
      TWO_FACTOR_ENABLED: 'true',
      TWO_FACTOR_SOURCE: 'sql',
      TWO_FACTOR_SQL_QUERY: SEED_QUERY,
    });
    const config = await discover(s);

    // Right password, no code: refused.
    await expect(login(s, config, { username: 'mario.rossi', password: PASSWORD }))
      .rejects.toBeInstanceOf(LoginRejected);

    // Right password, right code: in.
    const result = await login(s, config, {
      username: 'mario.rossi',
      password: PASSWORD,
      otp: generateSync({ secret: SEED, epoch: Math.floor(Date.now() / 1000) }),
    });
    const tokens = await exchange(config, result);
    expect(decodeJwtPayload(tokens.id_token!).sub).toBe('mario.rossi');
  });
});
