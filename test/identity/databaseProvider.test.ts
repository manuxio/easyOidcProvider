/**
 * The `database` identity provider against a fake credential store: the
 * outcome discipline (invalid_credentials / account_disabled /
 * temporarily_unavailable), the refresh-time liveness, and the store-backed
 * TOTP seed source.
 */
import type { Request } from 'express';
import bcrypt from 'bcryptjs';
import { describe, expect, it } from 'vitest';

import { loadConfig, type Config } from '../../src/config.js';
import {
  CredentialStoreUnavailable,
  DatabaseIdentityProvider,
  type CredentialRecord,
  type CredentialStore,
} from '../../src/identity/database/index.js';
import { createStoreSeedSource } from '../../src/twofactor/storeSeedSource.js';
import { createSilentLogger } from '../../src/logger.js';

const PASSWORD = 'Password1!';
const HASH = bcrypt.hashSync(PASSWORD, 10);

function fakeStore(records: Record<string, CredentialRecord>, options?: { down?: boolean }): CredentialStore {
  return {
    name: 'fake',
    async lookup(username: string) {
      if (options?.down) throw new CredentialStoreUnavailable('fake', 'store is down');
      return records[username];
    },
    async close() {},
  };
}

function config(overrides: Record<string, string> = {}): Config {
  return loadConfig({
    ISSUER_URL: 'http://127.0.0.1:3000',
    DATA_DIR: '',
    IDENTITY_PROVIDER: 'database',
    AUTH_DB_SOURCE: 'sql',
    AUTH_SQL_QUERY: 'SELECT passwordhash FROM users WHERE username = ?',
    SQL_CONNECTION_STRING: 'mysql://user:pass@db.invalid:3306/users',
    CLIENTS_JSON: JSON.stringify([
      { client_id: 'test', redirect_uris: ['http://127.0.0.1/callback'] },
    ]),
    ...overrides,
  });
}

function provider(store: CredentialStore, overrides: Record<string, string> = {}) {
  return new DatabaseIdentityProvider({
    config: config(overrides),
    store,
    logger: createSilentLogger(),
  });
}

function formRequest(username: string, password: string): Request {
  return { body: { username, password } } as unknown as Request;
}

describe('DatabaseIdentityProvider', () => {
  it('authenticates a known active user, via the form, with the bare username as principal', async () => {
    const identity = provider(fakeStore({ 'mario.rossi': { passwordHash: HASH, active: true } }));
    const outcome = await identity.authenticate(formRequest('Mario.Rossi', PASSWORD));
    expect(outcome).toEqual({ status: 'authenticated', principal: 'mario.rossi', via: 'form' });
  });

  it('appends REALM to the principal when one is configured', async () => {
    const identity = provider(
      fakeStore({ 'mario.rossi': { passwordHash: HASH, active: true } }),
      { REALM: 'clienti.example' },
    );
    const outcome = await identity.authenticate(formRequest('mario.rossi', PASSWORD));
    expect(outcome).toMatchObject({ principal: 'mario.rossi@CLIENTI.EXAMPLE' });
  });

  it('answers invalid_credentials alike for wrong password and unknown user', async () => {
    const identity = provider(fakeStore({ 'mario.rossi': { passwordHash: HASH, active: true } }));
    expect(await identity.authenticate(formRequest('mario.rossi', 'wrong')))
      .toMatchObject({ status: 'failed', reason: 'invalid_credentials' });
    expect(await identity.authenticate(formRequest('nessuno', PASSWORD)))
      .toMatchObject({ status: 'failed', reason: 'invalid_credentials' });
  });

  it('says account_disabled only AFTER the password was verified', async () => {
    const identity = provider(fakeStore({ 'mario.rossi': { passwordHash: HASH, active: false } }));
    expect(await identity.authenticate(formRequest('mario.rossi', PASSWORD)))
      .toMatchObject({ status: 'failed', reason: 'account_disabled' });
    // Wrong password on a disabled account must NOT reveal the disablement.
    expect(await identity.authenticate(formRequest('mario.rossi', 'wrong')))
      .toMatchObject({ status: 'failed', reason: 'invalid_credentials' });
  });

  it('fails closed as temporarily_unavailable when the store cannot answer', async () => {
    const identity = provider(fakeStore({}, { down: true }));
    expect(await identity.authenticate(formRequest('mario.rossi', PASSWORD)))
      .toMatchObject({ status: 'failed', reason: 'temporarily_unavailable' });
  });

  it('challenges with the form when the POST carries no credentials', async () => {
    const identity = provider(fakeStore({}));
    expect(await identity.authenticate(formRequest('', '')))
      .toEqual({ status: 'no-credentials' });
  });

  it('enforces liveness at refresh time through the same store', async () => {
    const records: Record<string, CredentialRecord> = {
      'mario.rossi': { passwordHash: HASH, active: true },
    };
    const identity = provider(fakeStore(records));
    expect(await identity.isAccountActive('mario.rossi')).toBe(true);
    records['mario.rossi']!.active = false;
    expect(await identity.isAccountActive('mario.rossi')).toBe(false);
    delete records['mario.rossi'];
    expect(await identity.isAccountActive('mario.rossi')).toBe(false);
  });

  it('propagates a store outage from isAccountActive: "cannot tell" is never a pass', async () => {
    const identity = provider(fakeStore({}, { down: true }));
    await expect(identity.isAccountActive('mario.rossi'))
      .rejects.toBeInstanceOf(CredentialStoreUnavailable);
  });
});

describe('store-backed TOTP seed source (TWO_FACTOR_SOURCE=mongo)', () => {
  it('reads the seed from the credential record and reports outages as unavailable', async () => {
    const source = createStoreSeedSource({
      store: fakeStore({
        enrolled: { passwordHash: HASH, active: true, totpSeed: 'JBSWY3DPEHPK3PXP' },
        bare: { passwordHash: HASH, active: true },
      }),
      logger: createSilentLogger(),
    });
    expect(await source.lookup('enrolled')).toBe('JBSWY3DPEHPK3PXP');
    expect(await source.lookup('bare')).toBeUndefined();
    expect(await source.lookup('nessuno')).toBeUndefined();

    const downSource = createStoreSeedSource({
      store: fakeStore({}, { down: true }),
      logger: createSilentLogger(),
    });
    await expect(downSource.lookup('enrolled')).rejects.toMatchObject({
      name: 'TwoFactorSeedUnavailable',
    });
  });
});
