/**
 * The external-Mongo credential store against a mocked mongodb driver: field
 * mapping, the strict activeField contract, lazy connection, timeout and
 * outage discipline.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createMongoCredentialStore } from '../../src/identity/database/mongoStore.js';
import { CredentialStoreUnavailable } from '../../src/identity/database/store.js';
import { createSilentLogger } from '../../src/logger.js';

interface FakeState {
  documents: Record<string, Record<string, unknown>>;
  connectError?: Error;
  findDelayMs?: number;
  connects: number;
  closes: number;
  findOneFilters: Record<string, unknown>[];
}

let state: FakeState;

vi.mock('mongodb', () => ({
  MongoClient: class {
    async connect() {
      state.connects += 1;
      if (state.connectError) throw state.connectError;
      return this;
    }

    db() {
      return {
        collection: () => ({
          findOne: async (filter: Record<string, unknown>) => {
            state.findOneFilters.push(filter);
            if (state.findDelayMs) {
              await new Promise((resolve) => { setTimeout(resolve, state.findDelayMs); });
            }
            const username = Object.values(filter)[0] as string;
            return state.documents[username] ?? null;
          },
        }),
      };
    }

    async close() {
      state.closes += 1;
    }
  },
}));

function store(options: { activeField?: string; totpField?: string; saltField?: string } = {}) {
  return createMongoCredentialStore({
    url: 'mongodb://fake.invalid:27017',
    dbName: 'customers',
    collection: 'users',
    usernameField: 'login',
    passwordField: 'pwd',
    ...options,
    timeoutMs: 500,
    logger: createSilentLogger(),
  });
}

beforeEach(() => {
  state = { documents: {}, connects: 0, closes: 0, findOneFilters: [] };
});

afterEach(() => {
  vi.useRealTimers();
});

describe('mongo credential store', () => {
  it('maps the configured fields into the record and filters on the username field', async () => {
    state.documents['mario.rossi'] = {
      login: 'mario.rossi', pwd: '$2b$10$hash', otp: 'JBSWY3DPEHPK3PXP', sale: 'pepe',
    };
    const s = store({ totpField: 'otp', saltField: 'sale' });
    const record = await s.lookup('mario.rossi');
    expect(record).toEqual({
      passwordHash: '$2b$10$hash',
      active: true,
      totpSeed: 'JBSWY3DPEHPK3PXP',
      salt: 'pepe',
    });
    expect(state.findOneFilters[0]).toEqual({ login: 'mario.rossi' });
    await s.close();
    expect(state.closes).toBe(1);
  });

  it('connects lazily, once', async () => {
    const s = store();
    expect(state.connects).toBe(0);
    state.documents.a = { login: 'a', pwd: 'x' };
    await s.lookup('a');
    await s.lookup('a');
    expect(state.connects).toBe(1);
    await s.close();
  });

  it('treats a missing document, and a document with no usable hash, as unknown', async () => {
    state.documents.empty = { login: 'empty', pwd: '   ' };
    const s = store();
    expect(await s.lookup('nessuno')).toBeUndefined();
    expect(await s.lookup('empty')).toBeUndefined();
    await s.close();
  });

  it('with an activeField configured, only EXACTLY true means active', async () => {
    state.documents.yes = { login: 'yes', pwd: 'h', enabled: true };
    state.documents.no = { login: 'no', pwd: 'h', enabled: false };
    state.documents.sloppy = { login: 'sloppy', pwd: 'h', enabled: 1 };
    state.documents.absent = { login: 'absent', pwd: 'h' };
    const s = store({ activeField: 'enabled' });
    expect((await s.lookup('yes'))?.active).toBe(true);
    expect((await s.lookup('no'))?.active).toBe(false);
    expect((await s.lookup('sloppy'))?.active).toBe(false);
    expect((await s.lookup('absent'))?.active).toBe(false);
    await s.close();
  });

  it('reports a connection failure as unavailable and retries on the next lookup', async () => {
    state.connectError = new Error('ECONNREFUSED fake.invalid');
    const s = store();
    await expect(s.lookup('a')).rejects.toBeInstanceOf(CredentialStoreUnavailable);
    // The failed client was not memoized: the recovered store answers.
    delete state.connectError;
    state.documents.a = { login: 'a', pwd: 'h' };
    expect((await s.lookup('a'))?.passwordHash).toBe('h');
    expect(state.connects).toBe(2);
    await s.close();
  });

  it('bounds the lookup with its deadline', async () => {
    state.findDelayMs = 5_000;
    state.documents.a = { login: 'a', pwd: 'h' };
    const s = store();
    await expect(s.lookup('a')).rejects.toMatchObject({
      name: 'CredentialStoreUnavailable',
      message: expect.stringContaining('timed out'),
    });
    await s.close();
  });
});
