/**
 * Server secrets (src/secrets.ts): the RS256 signing key and the cookie keys,
 * generated once and then persisted, because a restart that changes them
 * invalidates every token in circulation.
 *
 * Checked here, without Mongo and without the real DATA_DIR: the shape of the
 * generated secrets; each store returning the SAME secrets on every later
 * start; the file store adopting a winner's file instead of clobbering it, and
 * refusing a corrupt one; the Mongo store's first-writer-wins upsert, on a
 * fake collection; and the choice of store, which warns loudly when nothing
 * would survive a restart.
 */
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { calculateJwkThumbprint } from 'jose';
import type { Db } from 'mongodb';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  chooseSecretStore,
  fileSecretStore,
  generateServerSecrets,
  loadServerSecrets,
  memorySecretStore,
  mongoSecretStore,
  type SecretStore,
  type ServerSecrets,
} from '../../src/secrets.js';
import { createSilentLogger } from '../../src/logger.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';

const SECRETS_FILENAME = 'server-secrets.json';

/** Small, fixed secrets: the stores must not care what is inside. */
function fixedSecrets(tag: string): ServerSecrets {
  return {
    jwks: { keys: [{ kty: 'RSA', kid: `kid-${tag}`, n: 'AQAB', e: 'AQAB' }] },
    cookieKeys: [`cookie-${tag}-1`, `cookie-${tag}-2`],
    createdAt: '2026-10-23T08:00:00.000Z',
  };
}

const temporaryDirs: string[] = [];
async function temporaryDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'auth-server-secrets-'));
  temporaryDirs.push(dir);
  return dir;
}

afterEach(async () => {
  while (temporaryDirs.length > 0) await rm(temporaryDirs.pop()!, { recursive: true, force: true });
});

describe('generateServerSecrets', () => {
  it('produces one private RS256 signing key whose kid is its RFC 7638 thumbprint', async () => {
    const secrets = await generateServerSecrets();
    expect(secrets.jwks.keys).toHaveLength(1);
    const key = secrets.jwks.keys[0]!;
    expect(key).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig' });
    // oidc-provider signs with it, so the private half has to be there.
    expect(typeof key.d).toBe('string');
    expect(key.kid).toBe(await calculateJwkThumbprint(key, 'sha256'));
    // 2048-bit modulus: 256 bytes, base64url without padding.
    expect(Buffer.from(key.n!, 'base64url')).toHaveLength(256);
  });

  it('produces two distinct 32-byte cookie keys and an ISO creation date', async () => {
    const secrets = await generateServerSecrets();
    expect(secrets.cookieKeys).toHaveLength(2);
    expect(new Set(secrets.cookieKeys).size).toBe(2);
    for (const cookieKey of secrets.cookieKeys) {
      expect(Buffer.from(cookieKey, 'base64url')).toHaveLength(32);
    }
    expect(new Date(secrets.createdAt).toISOString()).toBe(secrets.createdAt);
  });

  it('never produces the same key twice', async () => {
    const [a, b] = await Promise.all([generateServerSecrets(), generateServerSecrets()]);
    expect(a.jwks.keys[0]!.kid).not.toBe(b.jwks.keys[0]!.kid);
    expect(a.cookieKeys).not.toEqual(b.cookieKeys);
  });
});

describe('memorySecretStore', () => {
  it('generates once and hands back the same secrets afterwards', async () => {
    const store = memorySecretStore();
    const generate = vi.fn(async () => fixedSecrets('memory'));
    const first = await store.loadOrCreate(generate);
    const second = await store.loadOrCreate(generate);
    expect(store.kind).toBe('memory');
    expect(second).toBe(first);
    expect(generate).toHaveBeenCalledTimes(1);
  });

  it('shares nothing between two stores', async () => {
    const a = await memorySecretStore().loadOrCreate(async () => fixedSecrets('a'));
    const b = await memorySecretStore().loadOrCreate(async () => fixedSecrets('b'));
    expect(a.cookieKeys).not.toEqual(b.cookieKeys);
  });
});

describe('fileSecretStore', () => {
  it('writes the file on first start, owner-only, and reads it back on the next one', async () => {
    const dir = await temporaryDir();
    const created = fixedSecrets('file');
    const first = await fileSecretStore(dir).loadOrCreate(async () => created);
    expect(first).toEqual(created);

    const path = join(dir, SECRETS_FILENAME);
    expect(JSON.parse(await readFile(path, 'utf8'))).toEqual(created);
    expect((await stat(path)).mode & 0o777).toBe(0o600);

    // A restart: a new store, a generator that must not be called.
    const generate = vi.fn(async () => fixedSecrets('other'));
    const second = await fileSecretStore(dir).loadOrCreate(generate);
    expect(second).toEqual(created);
    expect(generate).not.toHaveBeenCalled();
  });

  it('creates a missing DATA_DIR, nested directories included', async () => {
    const dir = join(await temporaryDir(), 'a', 'b');
    await fileSecretStore(dir).loadOrCreate(async () => fixedSecrets('nested'));
    expect(await readdir(dir)).toEqual([SECRETS_FILENAME]);
  });

  it('leaves no temporary file behind', async () => {
    const dir = await temporaryDir();
    await fileSecretStore(dir).loadOrCreate(async () => fixedSecrets('tmp'));
    expect(await readdir(dir)).toEqual([SECRETS_FILENAME]);
  });

  it('adopts the file a concurrent start wrote while this one was generating', async () => {
    const dir = await temporaryDir();
    const winner = fixedSecrets('winner');
    const loser = fixedSecrets('loser');
    const result = await fileSecretStore(dir).loadOrCreate(async () => {
      // The other container finished first.
      await writeFile(join(dir, SECRETS_FILENAME), JSON.stringify(winner));
      return loser;
    });
    expect(result).toEqual(winner);
    expect(JSON.parse(await readFile(join(dir, SECRETS_FILENAME), 'utf8'))).toEqual(winner);
    expect(await readdir(dir)).toEqual([SECRETS_FILENAME]);
  });

  it('refuses a file that holds no usable secrets instead of silently replacing the key', async () => {
    const dir = await temporaryDir();
    const path = join(dir, SECRETS_FILENAME);
    const generate = vi.fn(async () => fixedSecrets('new'));

    await writeFile(path, JSON.stringify({ jwks: { keys: [] }, cookieKeys: ['x'] }));
    await expect(fileSecretStore(dir).loadOrCreate(generate)).rejects.toThrow(/does not contain usable server secrets/);

    await writeFile(path, JSON.stringify({ jwks: { keys: [{ kty: 'RSA' }] }, cookieKeys: [] }));
    await expect(fileSecretStore(dir).loadOrCreate(generate)).rejects.toThrow(/does not contain usable server secrets/);

    await writeFile(path, '{ not json');
    await expect(fileSecretStore(dir).loadOrCreate(generate)).rejects.toThrow(SyntaxError);

    expect(generate).not.toHaveBeenCalled();
  });

  it('surfaces a read error other than "no such file"', async () => {
    const dir = await temporaryDir();
    // The path of the secrets file is a directory: EISDIR, not ENOENT.
    await mkdir(join(dir, SECRETS_FILENAME));
    const generate = vi.fn(async () => fixedSecrets('new'));
    await expect(fileSecretStore(dir).loadOrCreate(generate)).rejects.toMatchObject({ code: 'EISDIR' });
    expect(generate).not.toHaveBeenCalled();
  });
});

/** A Db with one collection, recording what the store asks of it. */
function fakeDb(options: {
  existing?: Record<string, unknown> | null;
  afterUpsert?: Record<string, unknown> | null;
}) {
  const calls = {
    collection: [] as string[],
    findOne: [] as unknown[],
    findOneAndUpdate: [] as Array<{ filter: unknown; update: unknown; options: unknown }>,
  };
  const db = {
    collection(name: string) {
      calls.collection.push(name);
      return {
        async findOne(filter: unknown) {
          calls.findOne.push(filter);
          return options.existing ?? null;
        },
        async findOneAndUpdate(filter: unknown, update: unknown, updateOptions: unknown) {
          calls.findOneAndUpdate.push({ filter, update, options: updateOptions });
          return options.afterUpsert ?? null;
        },
      };
    },
  } as unknown as Db;
  return { db, calls };
}

describe('mongoSecretStore', () => {
  it('returns the stored secrets, without the _id and without generating', async () => {
    const stored = fixedSecrets('stored');
    const { db, calls } = fakeDb({ existing: { _id: 'server-secrets', ...stored } });
    const generate = vi.fn(async () => fixedSecrets('new'));

    const store = mongoSecretStore(db);
    expect(store.kind).toBe('mongo');
    expect(await store.loadOrCreate(generate)).toEqual(stored);
    expect(generate).not.toHaveBeenCalled();
    expect(calls.collection).toEqual(['server_secrets']);
    expect(calls.findOne).toEqual([{ _id: 'server-secrets' }]);
    expect(calls.findOneAndUpdate).toEqual([]);
  });

  it('inserts with $setOnInsert and upsert, and returns what the database kept (first writer wins)', async () => {
    const winner = fixedSecrets('winner');
    const { db, calls } = fakeDb({ existing: null, afterUpsert: { _id: 'server-secrets', ...winner } });
    const created = fixedSecrets('mine');

    const result = await mongoSecretStore(db).loadOrCreate(async () => created);
    expect(result).toEqual(winner);
    expect(calls.findOneAndUpdate).toEqual([
      {
        filter: { _id: 'server-secrets' },
        update: { $setOnInsert: created },
        options: { upsert: true, returnDocument: 'after' },
      },
    ]);
  });

  it('falls back to its own secrets when the upsert returns nothing usable', async () => {
    const created = fixedSecrets('mine');
    const { db } = fakeDb({ existing: null, afterUpsert: null });
    expect(await mongoSecretStore(db).loadOrCreate(async () => created)).toEqual(created);
  });

  it('regenerates when the stored document is not usable', async () => {
    const created = fixedSecrets('mine');
    const { db, calls } = fakeDb({
      existing: { _id: 'server-secrets', jwks: { keys: [] }, cookieKeys: [] },
      afterUpsert: { _id: 'server-secrets', ...created },
    });
    expect(await mongoSecretStore(db).loadOrCreate(async () => created)).toEqual(created);
    expect(calls.findOneAndUpdate).toHaveLength(1);
  });
});

describe('chooseSecretStore', () => {
  it('prefers Mongo when a database is configured, even with a DATA_DIR', async () => {
    const { db } = fakeDb({});
    const store = chooseSecretStore({ db, dataDir: '/var/lib/auth-server' }, createSilentLogger());
    expect(store.kind).toBe('mongo');
  });

  it('uses the file under DATA_DIR without Mongo', async () => {
    const dir = await temporaryDir();
    expect(chooseSecretStore({ dataDir: dir }, createSilentLogger()).kind).toBe('file');
  });

  it('falls back to memory with neither, and warns that a restart invalidates the tokens', () => {
    const capture = createCapturingLogger();
    const store = chooseSecretStore({ dataDir: '' }, capture.logger);
    expect(store.kind).toBe('memory');
    const warning = capture.withReason('no_secret_persistence');
    expect(warning).toHaveLength(1);
    expect(warning[0]!.level).toBe('warn');
    expect(warning[0]!.msg).toContain('every restart invalidates the tokens');
  });

  it('does not warn when the secrets are persisted', async () => {
    const capture = createCapturingLogger();
    chooseSecretStore({ dataDir: await temporaryDir() }, capture.logger);
    expect(capture.withReason('no_secret_persistence')).toHaveLength(0);
  });
});

describe('loadServerSecrets', () => {
  it('loads through the store with the real generator, and logs the store and the kid (never the key)', async () => {
    const capture = createCapturingLogger();
    const store = memorySecretStore();
    const secrets = await loadServerSecrets(store, capture.logger);

    const key = secrets.jwks.keys[0]!;
    expect(key.alg).toBe('RS256');
    const ready = capture.matching('server signing key ready');
    expect(ready).toHaveLength(1);
    expect(ready[0]).toMatchObject({ store: 'memory', kid: key.kid, createdAt: secrets.createdAt });
    expect(capture.text()).not.toContain(key.d!);
    expect(capture.text()).not.toContain(secrets.cookieKeys[0]!);

    // Same store, second call: same secrets.
    expect(await loadServerSecrets(store, createSilentLogger())).toBe(secrets);
  });

  it('passes a store failure through: no server starts on an unreadable key', async () => {
    const failing: SecretStore = {
      kind: 'file',
      async loadOrCreate() {
        throw new Error('disk on fire (test)');
      },
    };
    await expect(loadServerSecrets(failing, createSilentLogger())).rejects.toThrow('disk on fire (test)');
  });
});
