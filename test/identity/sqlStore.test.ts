/**
 * IDENTITY_PROVIDER=database, AUTH_DB_SOURCE=sql: the SQL credential store
 * (src/identity/database/sqlStore.ts) on the fake driver.
 *
 * databaseE2e.test.ts walks the whole login over it; this file pins the
 * AUTH_SQL_QUERY contract of the store's header, one clause at a time:
 *
 *   1. exactly one placeholder, validated at startup by name;
 *   2. the username bound, never interpolated;
 *   3. the FIRST column is the hash whatever it is called, and `salt` /
 *      `totpsecret` are recognised by name (case-insensitive) among the others;
 *   4. zero rows = unknown or disabled user, and the record is always active.
 *
 * Plus the failure discipline: more than one row and every driver error are
 * CredentialStoreUnavailable (an outage, never "wrong password"), an empty
 * hash is an unknown user, and the deadline holds.
 */
import { describe, expect, it } from 'vitest';

import {
  AUTH_SQL_QUERY_PARAMETER,
  createSqlCredentialStore,
  CredentialStoreUnavailable,
} from '../../src/identity/database/index.js';
import { createSilentLogger } from '../../src/logger.js';
import { SqlGroupCheckConfigError, type SqlRow } from '../../src/sqlcheck/index.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';
import { FakeSqlDriver } from '../helpers/fakeSqlDriver.js';

const MARIO = 'mario.rossi';
const QUERY = 'SELECT passwordhash, salt, totpsecret FROM users WHERE username = ? AND active = 1';

function storeFor(rows: SqlRow[] | undefined, options: { timeoutMs?: number; query?: string } = {}) {
  const driver = new FakeSqlDriver({ rows: new Map(rows === undefined ? [] : [[MARIO, rows]]) });
  const capture = createCapturingLogger();
  const store = createSqlCredentialStore({
    query: options.query ?? QUERY,
    driver,
    timeoutMs: options.timeoutMs ?? 2000,
    logger: capture.logger,
  });
  return { driver, capture, store };
}

describe('startup', () => {
  it('is named after the driver', () => {
    expect(storeFor([]).store.name).toBe('sql:fake');
  });

  it('refuses a query that does not bind the username, naming AUTH_SQL_QUERY', () => {
    expect(AUTH_SQL_QUERY_PARAMETER).toBe('AUTH_SQL_QUERY');
    const build = () => createSqlCredentialStore({
      query: 'SELECT passwordhash FROM users',
      driver: new FakeSqlDriver(),
      timeoutMs: 1000,
      logger: createSilentLogger(),
    });
    expect(build).toThrow(SqlGroupCheckConfigError);
    expect(build).toThrow(/^AUTH_SQL_QUERY must contain exactly one "\?" placeholder/);
  });

  it('refuses an empty query by name', () => {
    expect(() => createSqlCredentialStore({
      query: '   ',
      driver: new FakeSqlDriver(),
      timeoutMs: 1000,
      logger: createSilentLogger(),
    })).toThrow('AUTH_SQL_QUERY is empty');
  });
});

describe('the row becomes a credential record', () => {
  it('binds the username and sends the query untouched', async () => {
    const { store, driver } = storeFor([{ passwordhash: '$2b$10$abc' }]);
    const hostile = "' OR 1=1 --";
    await store.lookup(hostile);
    expect(driver.calls).toEqual([{ sql: QUERY, params: { username: hostile } }]);
  });

  it('takes the FIRST column as the hash, whatever it is called, and marks the record active', async () => {
    const { store } = storeFor([{ pwd_bcrypt: '$2b$10$abc' }]);
    await expect(store.lookup(MARIO)).resolves.toEqual({ passwordHash: '$2b$10$abc', active: true });
  });

  it('reads salt and totpsecret by name, ignoring case', async () => {
    const { store } = storeFor([{ hash: 'deadbeef', SALT: 'pepper', TotpSecret: 'JBSWY3DPEHPK3PXP' }]);
    await expect(store.lookup(MARIO)).resolves.toEqual({
      passwordHash: 'deadbeef',
      salt: 'pepper',
      totpSeed: 'JBSWY3DPEHPK3PXP',
      active: true,
    });
  });

  it('never reads salt or totpsecret from the first column', async () => {
    // A query whose first column is literally named `salt` still hands the
    // value over as the hash, and there is no salt.
    const { store } = storeFor([{ salt: 'the-hash', other: 'x' }]);
    await expect(store.lookup(MARIO)).resolves.toEqual({ passwordHash: 'the-hash', active: true });
  });

  it('ignores any other column', async () => {
    const { store } = storeFor([{ hash: 'h', email: 'mario.rossi@example.local', attivo: 1 }]);
    await expect(store.lookup(MARIO)).resolves.toEqual({ passwordHash: 'h', active: true });
  });

  it('trims the values and reads a BLOB as UTF-8 text', async () => {
    const { store } = storeFor([{ hash: Buffer.from('  $argon2id$v=19$x  ', 'utf8'), salt: ' s ' }]);
    await expect(store.lookup(MARIO)).resolves.toEqual({
      passwordHash: '$argon2id$v=19$x',
      salt: 's',
      active: true,
    });
  });

  it('stringifies a numeric column instead of dropping it', async () => {
    const { store } = storeFor([{ hash: 'h', salt: 1234 }]);
    await expect(store.lookup(MARIO)).resolves.toMatchObject({ salt: '1234' });
  });

  it('leaves salt and totpSeed out when they are NULL or blank', async () => {
    const { store } = storeFor([{ hash: 'h', salt: null, totpsecret: '   ' }]);
    const record = await store.lookup(MARIO);
    expect(record).toEqual({ passwordHash: 'h', active: true });
    expect(record).not.toHaveProperty('salt');
    expect(record).not.toHaveProperty('totpSeed');
  });
});

describe('who is unknown', () => {
  it('answers undefined for zero rows: the query is the activation policy', async () => {
    const { store, capture } = storeFor(undefined);
    await expect(store.lookup(MARIO)).resolves.toBeUndefined();
    expect(capture.matching('no row for this user')[0]).toMatchObject({ level: 'debug', username: MARIO });
  });

  it.each([
    ['NULL', null],
    ['an empty string', ''],
    ['blanks', '   '],
  ])('treats a row whose hash is %s as an unknown user, with a warning', async (_label, hash) => {
    const { store, capture } = storeFor([{ hash, salt: 's' }]);
    await expect(store.lookup(MARIO)).resolves.toBeUndefined();
    expect(capture.matching('empty password hash')[0]).toMatchObject({ level: 'warn', username: MARIO });
  });

  it('treats a row with no columns at all as an unknown user', async () => {
    const { store } = storeFor([{}]);
    await expect(store.lookup(MARIO)).resolves.toBeUndefined();
  });
});

describe('outages are never "wrong password"', () => {
  it('refuses two rows for one username instead of choosing', async () => {
    const { store } = storeFor([{ hash: 'a' }, { hash: 'b' }]);
    const failure = await store.lookup(MARIO).catch((error: unknown) => error) as CredentialStoreUnavailable;
    expect(failure).toBeInstanceOf(CredentialStoreUnavailable);
    expect(failure.store).toBe('fake');
    expect(failure.message).toBe(`AUTH_SQL_QUERY returned 2 rows for ${MARIO}: it must return at most one`);
  });

  it('wraps a driver error, keeping the message and the cause', async () => {
    const { store, driver } = storeFor([{ hash: 'h' }]);
    const original = new Error('ECONNREFUSED 127.0.0.1:3306');
    driver.failWith = original;
    const failure = await store.lookup(MARIO).catch((error: unknown) => error) as CredentialStoreUnavailable;
    expect(failure).toBeInstanceOf(CredentialStoreUnavailable);
    expect(failure.name).toBe('CredentialStoreUnavailable');
    expect(failure.message).toBe('ECONNREFUSED 127.0.0.1:3306');
    expect(failure.cause).toBe(original);
  });

  it('passes a CredentialStoreUnavailable from below through untouched', async () => {
    const { store, driver } = storeFor([{ hash: 'h' }]);
    const original = new CredentialStoreUnavailable('fake', 'already wrapped');
    driver.failWith = original;
    await expect(store.lookup(MARIO)).rejects.toBe(original);
  });

  it('honours the deadline when the database never answers', async () => {
    const { store, driver } = storeFor([{ hash: 'h' }], { timeoutMs: 50 });
    driver.hangForever = true;
    const started = Date.now();
    await expect(store.lookup(MARIO)).rejects.toThrow(`credential lookup timed out after 50 ms for ${MARIO}`);
    expect(Date.now() - started).toBeLessThan(2000);
  });
});

describe('close', () => {
  it('closes the driver', async () => {
    const { store, driver } = storeFor([]);
    await store.close();
    expect(driver.closed).toBe(true);
  });
});
