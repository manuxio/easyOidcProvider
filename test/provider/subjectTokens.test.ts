/**
 * The subject token registry (src/provider/subjectTokens.ts, plan D1 in
 * the token-exchange design notes): one record per person's access
 * token that a token exchange rule may later accept as its subject, stored on
 * the adapter oidc-provider itself was configured with.
 *
 * On a real Provider over the inspectable in-memory store: the model name is
 * pinned (it is the Mongo collection), the TTL handed to the adapter is the
 * one asked for, a record comes back exactly as written, an unknown jti is
 * "no record", and a malformed record or a store that cannot answer THROWS —
 * the exchange fails closed on it. The registry seen through the token
 * endpoint is in test/tokenExchange.test.ts.
 */
import Provider, { type Adapter, type AdapterFactory, type Configuration } from 'oidc-provider';
import { beforeAll, describe, expect, it } from 'vitest';

import {
  createSubjectTokenRegistry,
  SUBJECT_TOKEN_RECORD_MODEL,
  type SubjectTokenRecord,
} from '../../src/provider/subjectTokens.js';
import { generateServerSecrets, type ServerSecrets } from '../../src/secrets.js';
import { createInspectableStore, type InspectableStore } from '../helpers/memoryAdapter.js';

const RECORD: SubjectTokenRecord = {
  accountId: 'mario.rossi',
  clientId: 'desktop-app',
  grantId: 'grant-1',
  gty: 'authorization_code refresh_token',
  aud: 'agent-service',
  exp: 1_900_000_000,
};

let secrets: ServerSecrets;
beforeAll(async () => {
  secrets = await generateServerSecrets();
});

interface Harness {
  store: InspectableStore;
  /** Every model name the provider asked the factory for. */
  models: string[];
  /** Every upsert on the registry's model: id and expiresIn. */
  upserts: Array<{ id: string; expiresIn: number }>;
  provider: Provider;
}

/** The inspectable store, wrapped to also record which models are built and the TTLs written. */
function harness(): Harness {
  const store = createInspectableStore();
  const models: string[] = [];
  const upserts: Array<{ id: string; expiresIn: number }> = [];
  const adapterFactory: AdapterFactory = (model: string): Adapter => {
    models.push(model);
    const inner = store.adapterFactory(model) as Adapter;
    if (model !== SUBJECT_TOKEN_RECORD_MODEL) return inner;
    return {
      ...inner,
      async upsert(id, payload, expiresIn) {
        upserts.push({ id, expiresIn });
        return inner.upsert(id, payload, expiresIn);
      },
    };
  };
  const provider = new Provider('http://127.0.0.1:1', {
    adapter: adapterFactory,
    jwks: secrets.jwks as Configuration['jwks'],
    cookies: { keys: secrets.cookieKeys },
  });
  return { store, models, upserts, provider };
}

describe('the subject token registry', () => {
  it('pins the model name: the Mongo collection is subject_token_record', async () => {
    expect(SUBJECT_TOKEN_RECORD_MODEL).toBe('SubjectTokenRecord');
    const { store, models, provider } = harness();
    await createSubjectTokenRegistry(provider).record('jti-1', RECORD, 60);
    expect(models).toContain(SUBJECT_TOKEN_RECORD_MODEL);
    // A subclass of ReplayDetection, but never stored under that model's name.
    expect(store.entries('ReplayDetection').size).toBe(0);
    expect(store.entries(SUBJECT_TOKEN_RECORD_MODEL).size).toBe(1);
  });

  it('writes the record under the jti, with the TTL it is given', async () => {
    const { store, upserts, provider } = harness();
    const registry = createSubjectTokenRegistry(provider);

    await registry.record('jti-1', RECORD, 600);
    expect(upserts).toEqual([{ id: 'jti-1', expiresIn: 600 }]);
    expect(store.entries(SUBJECT_TOKEN_RECORD_MODEL).get('jti-1')).toEqual(RECORD);
  });

  it('stores a copy: changing the caller object afterwards changes nothing', async () => {
    const { store, provider } = harness();
    const registry = createSubjectTokenRegistry(provider);
    const mine = { ...RECORD };
    await registry.record('jti-1', mine, 60);
    mine.accountId = 'someone.else';
    expect(store.entries(SUBJECT_TOKEN_RECORD_MODEL).get('jti-1')).toEqual(RECORD);
  });

  it('finds a record exactly as written', async () => {
    const { provider } = harness();
    const registry = createSubjectTokenRegistry(provider);
    await registry.record('jti-1', RECORD, 60);
    expect(await registry.find('jti-1')).toEqual(RECORD);
  });

  it('hands back only the six fields of the record, whatever else the store holds', async () => {
    const { store, provider } = harness();
    const registry = createSubjectTokenRegistry(provider);
    // Written behind the registry's back, with a field it does not know.
    await store.adapterFactory(SUBJECT_TOKEN_RECORD_MODEL).upsert('jti-1', { ...RECORD, extra: 'x' }, 60);
    expect(await registry.find('jti-1')).toEqual(RECORD);
  });

  it('answers undefined for a jti it never recorded', async () => {
    const { provider } = harness();
    const registry = createSubjectTokenRegistry(provider);
    await registry.record('jti-1', RECORD, 60);
    expect(await registry.find('jti-2')).toBeUndefined();
  });

  it('forgets a record once its TTL has run out', async () => {
    const { provider } = harness();
    const registry = createSubjectTokenRegistry(provider);
    await registry.record('jti-1', RECORD, 1);
    await new Promise((resolve) => setTimeout(resolve, 1100));
    expect(await registry.find('jti-1')).toBeUndefined();
  });

  it.each([
    ['accountId'],
    ['clientId'],
    ['grantId'],
    ['gty'],
    ['aud'],
    ['exp'],
  ] as const)('throws on a record without %s, naming the jti (the exchange fails closed)', async (field) => {
    const { store, provider } = harness();
    const registry = createSubjectTokenRegistry(provider);
    const broken: Record<string, unknown> = { ...RECORD };
    delete broken[field];
    await store.adapterFactory(SUBJECT_TOKEN_RECORD_MODEL).upsert('jti-broken', broken, 60);
    await expect(registry.find('jti-broken')).rejects.toThrow('subject token record jti-broken is malformed');
  });

  it('throws on a record with a field of the wrong type', async () => {
    const { store, provider } = harness();
    const registry = createSubjectTokenRegistry(provider);
    await store.adapterFactory(SUBJECT_TOKEN_RECORD_MODEL).upsert('jti-1', { ...RECORD, exp: String(RECORD.exp) }, 60);
    await expect(registry.find('jti-1')).rejects.toThrow(/malformed/);
  });

  it('lets a store that cannot answer throw through to the caller', async () => {
    const { store, provider } = harness();
    const registry = createSubjectTokenRegistry(provider);
    store.failFind(SUBJECT_TOKEN_RECORD_MODEL);
    await expect(registry.find('jti-1')).rejects.toThrow(/unreachable/);
  });

  it('keeps two providers apart: each registry writes to its own provider adapter', async () => {
    const first = harness();
    const second = harness();
    await createSubjectTokenRegistry(first.provider).record('jti-1', RECORD, 60);
    expect(first.store.entries(SUBJECT_TOKEN_RECORD_MODEL).size).toBe(1);
    expect(second.store.entries(SUBJECT_TOKEN_RECORD_MODEL).size).toBe(0);
    expect(await createSubjectTokenRegistry(second.provider).find('jti-1')).toBeUndefined();
  });
});
