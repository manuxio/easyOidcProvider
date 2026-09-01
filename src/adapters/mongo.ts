/**
 * MongoDB adapter for oidc-provider state (grants, sessions, codes, tokens),
 * following the shape of the official example adapter.
 *
 * One collection per model, snake_cased. Expiry is delegated to a TTL index on
 * `expiresAt`; the payload itself is stored untouched so a schema change in
 * oidc-provider does not need a migration here.
 */
import { MongoClient, type Collection, type Db } from 'mongodb';
import type { Adapter, AdapterFactory, AdapterPayload } from 'oidc-provider';

/** Models whose payloads carry a grantId and are revoked as a chain. */
const GRANTABLE = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest',
  'PreAuthorizedCode',
]);

interface StoredDocument {
  _id: string;
  payload: AdapterPayload;
  expiresAt?: Date;
}

function collectionName(model: string): string {
  return model.replace(/[A-Z]/g, (char, index: number) =>
    index === 0 ? char.toLowerCase() : `_${char.toLowerCase()}`,
  );
}

export class MongoAdapter implements Adapter {
  readonly #collection: Collection<StoredDocument>;
  readonly #model: string;

  constructor(db: Db, model: string) {
    this.#model = model;
    this.#collection = db.collection<StoredDocument>(collectionName(model));
  }

  async upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<void> {
    await this.#collection.updateOne(
      { _id: id },
      {
        $set: {
          payload,
          ...(expiresIn ? { expiresAt: new Date(Date.now() + expiresIn * 1000) } : {}),
        },
      },
      { upsert: true },
    );
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    const found = await this.#collection.findOne({ _id: id }, { projection: { payload: 1 } });
    return found?.payload;
  }

  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    const found = await this.#collection.findOne(
      { 'payload.userCode': userCode },
      { projection: { payload: 1 } },
    );
    return found?.payload;
  }

  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    const found = await this.#collection.findOne(
      { 'payload.uid': uid },
      { projection: { payload: 1 } },
    );
    return found?.payload;
  }

  async consume(id: string): Promise<void> {
    await this.#collection.updateOne(
      { _id: id },
      { $set: { 'payload.consumed': Math.floor(Date.now() / 1000) } },
    );
  }

  async destroy(id: string): Promise<void> {
    await this.#collection.deleteOne({ _id: id });
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    await this.#collection.deleteMany({ 'payload.grantId': grantId });
  }

  get model(): string {
    return this.#model;
  }
}

/** Every model oidc-provider may ask for; used to create indexes up front. */
const MODELS = [
  'Grant',
  'Session',
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'ClientCredentials',
  'Client',
  'InitialAccessToken',
  'RegistrationAccessToken',
  'DeviceCode',
  'Interaction',
  'ReplayDetection',
  'BackchannelAuthenticationRequest',
  'PushedAuthorizationRequest',
  'PreAuthorizedCode',
] as const;

export async function ensureMongoIndexes(db: Db): Promise<void> {
  await Promise.all(
    MODELS.map(async (model) => {
      const collection = db.collection(collectionName(model));
      const indexes: Parameters<typeof collection.createIndexes>[0] = [
        { key: { expiresAt: 1 }, expireAfterSeconds: 0, name: 'expiresAt_ttl' },
      ];
      if (GRANTABLE.has(model)) {
        indexes.push({ key: { 'payload.grantId': 1 }, name: 'payload_grantId' });
      }
      if (model === 'Session' || model === 'Interaction') {
        indexes.push({ key: { 'payload.uid': 1 }, name: 'payload_uid' });
      }
      if (model === 'DeviceCode') {
        indexes.push({ key: { 'payload.userCode': 1 }, name: 'payload_userCode' });
      }
      await collection.createIndexes(indexes);
    }),
  );
}

export interface MongoStorage {
  db: Db;
  client: MongoClient;
  adapterFactory: AdapterFactory;
  close(): Promise<void>;
}

export async function connectMongo(url: string, dbName?: string): Promise<MongoStorage> {
  const client = new MongoClient(url);
  await client.connect();
  const db = dbName ? client.db(dbName) : client.db();
  await ensureMongoIndexes(db);

  return {
    db,
    client,
    adapterFactory: (model: string) => new MongoAdapter(db, model),
    close: () => client.close(),
  };
}
