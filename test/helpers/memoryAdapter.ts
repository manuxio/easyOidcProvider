/**
 * An inspectable in-memory oidc-provider adapter, for the tests that need to
 * look inside the store (is a subject token recorded?) or to make one model
 * fail (the registry is down). oidc-provider's own memory adapter is not
 * reachable from its public entry point, so this mirrors its behaviour: one
 * map per model, expiry honoured on read, grant-scoped revocation for the
 * grantable models.
 */
import type { Adapter, AdapterFactory, AdapterPayload } from 'oidc-provider';

const GRANTABLE = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest',
  'PreAuthorizedCode',
]);

interface Entry {
  payload: AdapterPayload;
  expiresAt: number | undefined;
}

export interface InspectableStore {
  adapterFactory: AdapterFactory;
  /** The live payloads of one model, keyed by id. */
  entries(model: string): Map<string, AdapterPayload>;
  /** From now on, `find` on this model throws. */
  failFind(model: string): void;
}

export function createInspectableStore(): InspectableStore {
  const models = new Map<string, Map<string, Entry>>();
  const failing = new Set<string>();

  const tableOf = (model: string): Map<string, Entry> => {
    let table = models.get(model);
    if (!table) {
      table = new Map();
      models.set(model, table);
    }
    return table;
  };

  const live = (entry: Entry | undefined): AdapterPayload | undefined =>
    entry && (entry.expiresAt === undefined || entry.expiresAt > Date.now()) ? entry.payload : undefined;

  const adapterFactory: AdapterFactory = (model: string): Adapter => {
    const table = tableOf(model);
    const findBy = (field: string, value: string): AdapterPayload | undefined => {
      for (const entry of table.values()) {
        if ((entry.payload as Record<string, unknown>)[field] === value) return live(entry);
      }
      return undefined;
    };
    return {
      async upsert(id, payload, expiresIn) {
        table.set(id, {
          payload: structuredClone(payload),
          expiresAt: typeof expiresIn === 'number' ? Date.now() + expiresIn * 1000 : undefined,
        });
      },
      async find(id) {
        if (failing.has(model)) throw new Error(`${model} store is unreachable (test)`);
        const payload = live(table.get(id));
        return payload === undefined ? undefined : structuredClone(payload);
      },
      async findByUid(uid) {
        return findBy('uid', uid);
      },
      async findByUserCode(userCode) {
        return findBy('userCode', userCode);
      },
      async consume(id) {
        const entry = table.get(id);
        if (entry) (entry.payload as Record<string, unknown>).consumed = Math.floor(Date.now() / 1000);
      },
      async destroy(id) {
        table.delete(id);
      },
      async revokeByGrantId(grantId) {
        if (!GRANTABLE.has(model)) return;
        for (const [id, entry] of table) {
          if (entry.payload.grantId === grantId) table.delete(id);
        }
      },
    };
  };

  return {
    adapterFactory,
    entries(model) {
      const out = new Map<string, AdapterPayload>();
      for (const [id, entry] of tableOf(model)) {
        const payload = live(entry);
        if (payload !== undefined) out.set(id, payload);
      }
      return out;
    },
    failFind(model) {
      failing.add(model);
    },
  };
}
