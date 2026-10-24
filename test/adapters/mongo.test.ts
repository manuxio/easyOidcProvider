/**
 * The MongoDB adapter of the oidc-provider state (src/adapters/mongo.ts),
 * against a mocked mongodb driver: no Mongo is ever reached.
 *
 * What is pinned down, from the adapter's own header and from the shape of
 * oidc-provider's example adapter it follows:
 *
 *  - one collection per model, snake_cased (`AccessToken` -> `access_token`,
 *    and our own `SubjectTokenRecord` -> `subject_token_record`);
 *  - the payload is stored untouched, under `payload`, keyed by `_id`;
 *  - expiry is a Date in `expiresAt` (read by the TTL index), only when an
 *    `expiresIn` is given;
 *  - the lookups by uid / userCode / grantId go through the payload fields;
 *  - `ensureMongoIndexes` creates the TTL index on every model and the lookup
 *    indexes only where the adapter queries by them;
 *  - `connectMongo` connects once, picks the named database (or the URL's),
 *    builds the indexes before handing out the factory, and closes the client.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { connectMongo, ensureMongoIndexes, MongoAdapter } from '../../src/adapters/mongo.js';

interface StoredDocument {
  _id: string;
  payload: Record<string, unknown>;
  expiresAt?: Date;
}

interface IndexSpec {
  key: Record<string, number>;
  name: string;
  expireAfterSeconds?: number;
}

interface FakeMongoState {
  /** collection name -> _id -> document */
  collections: Map<string, Map<string, StoredDocument>>;
  /** collection name -> every index spec handed to createIndexes */
  indexes: Map<string, IndexSpec[]>;
  /** Every operation, in order, with its collection, filter and options. */
  operations: Array<{ op: string; collection: string; filter?: unknown; update?: unknown; options?: unknown }>;
  connects: number;
  closes: number;
  dbNames: Array<string | undefined>;
  urls: string[];
}

let state: FakeMongoState;

function freshState(): FakeMongoState {
  return {
    collections: new Map(),
    indexes: new Map(),
    operations: [],
    connects: 0,
    closes: 0,
    dbNames: [],
    urls: [],
  };
}

/** Reads a dotted path (`payload.uid`) out of a stored document. */
function valueAt(document: StoredDocument, path: string): unknown {
  return path.split('.').reduce<unknown>(
    (current, part) => (current === undefined || current === null ? undefined : (current as Record<string, unknown>)[part]),
    document,
  );
}

function matches(document: StoredDocument, filter: Record<string, unknown>): boolean {
  return Object.entries(filter).every(([path, expected]) => valueAt(document, path) === expected);
}

/** Writes a dotted path (`payload.consumed`) into a stored document. */
function setAt(document: StoredDocument, path: string, value: unknown): void {
  const parts = path.split('.');
  let target = document as unknown as Record<string, unknown>;
  for (const part of parts.slice(0, -1)) {
    target[part] ??= {};
    target = target[part] as Record<string, unknown>;
  }
  target[parts.at(-1)!] = value;
}

function fakeCollection(name: string) {
  const table = (): Map<string, StoredDocument> => {
    let found = state.collections.get(name);
    if (!found) {
      found = new Map();
      state.collections.set(name, found);
    }
    return found;
  };
  return {
    async updateOne(filter: Record<string, unknown>, update: { $set: Record<string, unknown> }, options?: { upsert?: boolean }) {
      state.operations.push({ op: 'updateOne', collection: name, filter, update, options });
      const id = filter._id as string;
      let document = table().get(id);
      if (!document) {
        if (!options?.upsert) return { matchedCount: 0 };
        document = { _id: id, payload: {} };
        table().set(id, document);
      }
      for (const [path, value] of Object.entries(update.$set)) setAt(document, path, value);
      return { matchedCount: 1 };
    },
    async findOne(filter: Record<string, unknown>, options?: unknown) {
      state.operations.push({ op: 'findOne', collection: name, filter, options });
      for (const document of table().values()) {
        if (matches(document, filter)) return { _id: document._id, payload: document.payload };
      }
      return null;
    },
    async deleteOne(filter: Record<string, unknown>) {
      state.operations.push({ op: 'deleteOne', collection: name, filter });
      for (const [id, document] of table()) {
        if (matches(document, filter)) {
          table().delete(id);
          return { deletedCount: 1 };
        }
      }
      return { deletedCount: 0 };
    },
    async deleteMany(filter: Record<string, unknown>) {
      state.operations.push({ op: 'deleteMany', collection: name, filter });
      let deletedCount = 0;
      for (const [id, document] of table()) {
        if (matches(document, filter)) {
          table().delete(id);
          deletedCount += 1;
        }
      }
      return { deletedCount };
    },
    async createIndexes(specs: IndexSpec[]) {
      state.operations.push({ op: 'createIndexes', collection: name });
      state.indexes.set(name, [...(state.indexes.get(name) ?? []), ...specs]);
      return specs.map((spec) => spec.name);
    },
  };
}

function fakeDb() {
  return { collection: (name: string) => fakeCollection(name) };
}

vi.mock('mongodb', () => ({
  MongoClient: class {
    constructor(url: string) {
      state.urls.push(url);
    }

    async connect() {
      state.connects += 1;
      return this;
    }

    db(name?: string) {
      state.dbNames.push(name);
      return fakeDb();
    }

    async close() {
      state.closes += 1;
    }
  },
}));

/** The adapter only touches `db.collection()`, so the fake Db is enough for it. */
type AdapterDb = ConstructorParameters<typeof MongoAdapter>[0];
const db = (): AdapterDb => fakeDb() as unknown as AdapterDb;

beforeEach(() => {
  state = freshState();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('one collection per model, snake_cased', () => {
  it.each([
    ['AccessToken', 'access_token'],
    ['Grant', 'grant'],
    ['BackchannelAuthenticationRequest', 'backchannel_authentication_request'],
    ['SubjectTokenRecord', 'subject_token_record'],
  ])('stores %s in %s', async (model, collection) => {
    const adapter = new MongoAdapter(db(), model);
    await adapter.upsert('id-1', { jti: 'id-1' });
    expect(adapter.model).toBe(model);
    expect(state.operations.at(-1)).toMatchObject({ op: 'updateOne', collection });
  });
});

describe('upsert and find', () => {
  it('stores the payload untouched under `payload`, keyed by _id, as an upsert', async () => {
    const adapter = new MongoAdapter(db(), 'Session');
    const payload = { uid: 'uid-1', accountId: 'mario.rossi', nested: { a: [1, 2] } };
    await adapter.upsert('session-1', payload);

    const [operation] = state.operations;
    expect(operation).toMatchObject({
      op: 'updateOne',
      filter: { _id: 'session-1' },
      options: { upsert: true },
    });
    expect((operation!.update as { $set: Record<string, unknown> }).$set.payload).toEqual(payload);
    await expect(adapter.find('session-1')).resolves.toEqual(payload);
  });

  it('writes expiresAt as now + expiresIn seconds, for the TTL index', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-23T08:00:00.000Z'));
    const adapter = new MongoAdapter(db(), 'AccessToken');
    await adapter.upsert('at-1', { grantId: 'g-1' }, 900);

    const stored = state.collections.get('access_token')!.get('at-1')!;
    expect(stored.expiresAt).toBeInstanceOf(Date);
    expect(stored.expiresAt!.toISOString()).toBe('2026-10-23T08:15:00.000Z');
  });

  it('writes no expiresAt when no expiresIn is given', async () => {
    const adapter = new MongoAdapter(db(), 'Grant');
    await adapter.upsert('grant-1', { accountId: 'mario.rossi' });
    const update = state.operations[0]!.update as { $set: Record<string, unknown> };
    expect(update.$set).not.toHaveProperty('expiresAt');
  });

  it('treats expiresIn 0 like no expiry at all', async () => {
    // `expiresIn ? … : {}`: zero is falsy, so the document gets no TTL.
    const adapter = new MongoAdapter(db(), 'Grant');
    await adapter.upsert('grant-0', { accountId: 'mario.rossi' }, 0);
    const update = state.operations[0]!.update as { $set: Record<string, unknown> };
    expect(update.$set).not.toHaveProperty('expiresAt');
  });

  it('projects only the payload on find, and returns undefined for an unknown id', async () => {
    const adapter = new MongoAdapter(db(), 'Session');
    await expect(adapter.find('nobody')).resolves.toBeUndefined();
    expect(state.operations.at(-1)).toMatchObject({
      op: 'findOne',
      filter: { _id: 'nobody' },
      options: { projection: { payload: 1 } },
    });
  });

  it('replaces the payload on a second upsert of the same id', async () => {
    const adapter = new MongoAdapter(db(), 'Session');
    await adapter.upsert('session-1', { uid: 'first' });
    await adapter.upsert('session-1', { uid: 'second' });
    await expect(adapter.find('session-1')).resolves.toEqual({ uid: 'second' });
    expect(state.collections.get('session')!.size).toBe(1);
  });
});

describe('lookups through the payload fields', () => {
  it('finds by uid on payload.uid', async () => {
    const adapter = new MongoAdapter(db(), 'Interaction');
    await adapter.upsert('i-1', { uid: 'uid-abc', prompt: 'login' });
    await expect(adapter.findByUid('uid-abc')).resolves.toEqual({ uid: 'uid-abc', prompt: 'login' });
    expect(state.operations.at(-1)).toMatchObject({
      op: 'findOne',
      filter: { 'payload.uid': 'uid-abc' },
      options: { projection: { payload: 1 } },
    });
    await expect(adapter.findByUid('uid-missing')).resolves.toBeUndefined();
  });

  it('finds by user code on payload.userCode', async () => {
    const adapter = new MongoAdapter(db(), 'DeviceCode');
    await adapter.upsert('dc-1', { userCode: 'ABCD-EFGH' });
    await expect(adapter.findByUserCode('ABCD-EFGH')).resolves.toEqual({ userCode: 'ABCD-EFGH' });
    expect(state.operations.at(-1)).toMatchObject({
      op: 'findOne',
      filter: { 'payload.userCode': 'ABCD-EFGH' },
    });
    await expect(adapter.findByUserCode('ZZZZ-ZZZZ')).resolves.toBeUndefined();
  });
});

describe('consume, destroy, revokeByGrantId', () => {
  it('marks the payload consumed with the current epoch second, keeping the rest', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-23T08:00:00.500Z'));
    const adapter = new MongoAdapter(db(), 'AuthorizationCode');
    await adapter.upsert('code-1', { grantId: 'g-1', accountId: 'mario.rossi' });
    await adapter.consume('code-1');

    expect(state.operations.at(-1)).toMatchObject({
      op: 'updateOne',
      filter: { _id: 'code-1' },
      update: { $set: { 'payload.consumed': Math.floor(Date.parse('2026-10-23T08:00:00.500Z') / 1000) } },
    });
    // consume is not an upsert: it never creates a document.
    expect(state.operations.at(-1)!.options).toBeUndefined();
    await expect(adapter.find('code-1')).resolves.toEqual({
      grantId: 'g-1',
      accountId: 'mario.rossi',
      consumed: Math.floor(Date.parse('2026-10-23T08:00:00.500Z') / 1000),
    });
  });

  it('destroys one document by _id', async () => {
    const adapter = new MongoAdapter(db(), 'Session');
    await adapter.upsert('s-1', { uid: 'a' });
    await adapter.upsert('s-2', { uid: 'b' });
    await adapter.destroy('s-1');
    expect(state.operations.at(-1)).toMatchObject({ op: 'deleteOne', filter: { _id: 's-1' } });
    await expect(adapter.find('s-1')).resolves.toBeUndefined();
    await expect(adapter.find('s-2')).resolves.toEqual({ uid: 'b' });
  });

  it('revokes every document of one grant, and only that grant', async () => {
    const adapter = new MongoAdapter(db(), 'RefreshToken');
    await adapter.upsert('rt-1', { grantId: 'g-1' });
    await adapter.upsert('rt-2', { grantId: 'g-1' });
    await adapter.upsert('rt-3', { grantId: 'g-2' });

    await adapter.revokeByGrantId('g-1');
    expect(state.operations.at(-1)).toMatchObject({
      op: 'deleteMany',
      filter: { 'payload.grantId': 'g-1' },
    });
    expect([...state.collections.get('refresh_token')!.keys()]).toEqual(['rt-3']);
  });
});

describe('ensureMongoIndexes', () => {
  async function built(): Promise<Map<string, IndexSpec[]>> {
    await ensureMongoIndexes(db());
    return state.indexes;
  }

  it('puts the TTL index on expiresAt on every model, our subject token registry included', async () => {
    const indexes = await built();
    for (const collection of [
      'grant', 'session', 'access_token', 'authorization_code', 'refresh_token',
      'client_credentials', 'client', 'initial_access_token', 'registration_access_token',
      'device_code', 'interaction', 'replay_detection', 'backchannel_authentication_request',
      'pushed_authorization_request', 'pre_authorized_code', 'subject_token_record',
    ]) {
      expect(indexes.get(collection), collection).toContainEqual({
        key: { expiresAt: 1 },
        expireAfterSeconds: 0,
        name: 'expiresAt_ttl',
      });
    }
    expect(indexes.size).toBe(16);
  });

  it('indexes payload.grantId exactly on the models revoked as a chain', async () => {
    const indexes = await built();
    const withGrantId = [...indexes]
      .filter(([, specs]) => specs.some((spec) => spec.name === 'payload_grantId'))
      .map(([collection]) => collection)
      .sort();
    expect(withGrantId).toEqual([
      'access_token',
      'authorization_code',
      'backchannel_authentication_request',
      'device_code',
      'pre_authorized_code',
      'refresh_token',
    ]);
    expect(indexes.get('access_token')).toContainEqual({ key: { 'payload.grantId': 1 }, name: 'payload_grantId' });
  });

  it('indexes payload.uid on Session and Interaction, payload.userCode on DeviceCode only', async () => {
    const indexes = await built();
    const named = (name: string) => [...indexes]
      .filter(([, specs]) => specs.some((spec) => spec.name === name))
      .map(([collection]) => collection)
      .sort();
    expect(named('payload_uid')).toEqual(['interaction', 'session']);
    expect(named('payload_userCode')).toEqual(['device_code']);
    expect(indexes.get('grant')).toHaveLength(1);
    expect(indexes.get('subject_token_record')).toHaveLength(1);
  });
});

describe('connectMongo', () => {
  it('connects once, uses the named database, builds the indexes, then hands out adapters', async () => {
    const storage = await connectMongo('mongodb://fake.invalid:27017', 'auth');
    expect(state.urls).toEqual(['mongodb://fake.invalid:27017']);
    expect(state.connects).toBe(1);
    expect(state.dbNames).toEqual(['auth']);
    // The indexes exist before the first adapter is ever used.
    expect(state.indexes.size).toBe(16);

    const adapter = storage.adapterFactory('AccessToken');
    expect(adapter).toBeInstanceOf(MongoAdapter);
    expect((adapter as MongoAdapter).model).toBe('AccessToken');
  });

  it("falls back to the URL's own database when no name is given", async () => {
    await connectMongo('mongodb://fake.invalid:27017/from-url');
    expect(state.dbNames).toEqual([undefined]);
  });

  it('closes the client', async () => {
    const storage = await connectMongo('mongodb://fake.invalid:27017', 'auth');
    await storage.close();
    expect(state.closes).toBe(1);
  });
});
