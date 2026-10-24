/**
 * The subject token registry (plan D1): one record per person's access token
 * that a token exchange rule may later accept as its subject.
 *
 * A JWT access token is not stored by oidc-provider and carries neither the
 * grant it was born from nor its grant type (lib/models/formats/jwt.js builds
 * the payload without `grantId`/`gty` and returns only `{ value }`, so
 * base_model.js never upserts it). The exchange needs both: the grant to tell
 * "still alive" from "revoked", the grant type to apply `issued_by_grants`.
 * So the formats.customizers.jwt hook writes them here, keyed by `jti`, with
 * the remaining life of the token as TTL.
 */
import type { Adapter, AdapterPayload } from 'oidc-provider';
import type Provider from 'oidc-provider';

/** The model name handed to the adapter: the Mongo collection is `subject_token_record`. */
export const SUBJECT_TOKEN_RECORD_MODEL = 'SubjectTokenRecord';

export interface SubjectTokenRecord {
  accountId: string;
  clientId: string;
  grantId: string;
  /** Space-separated, as oidc-provider writes it: `authorization_code refresh_token` after a refresh. */
  gty: string;
  aud: string;
  exp: number;
}

export interface SubjectTokenRegistry {
  /** `ttlSeconds` is the remaining life of the token, at least 1. */
  record(jti: string, record: SubjectTokenRecord, ttlSeconds: number): Promise<void>;
  /** Throws when the store cannot answer: the caller fails closed. */
  find(jti: string): Promise<SubjectTokenRecord | undefined>;
}

/**
 * Builds the registry on the adapter oidc-provider itself was configured with
 * (the in-memory store in tests, Mongo in production).
 *
 * How the adapter is obtained: oidc-provider exposes no factory for a model of
 * our own, but every model class it hands out has a static `adapter` getter
 * (lib/models/base_model.js), which builds — once per class, cached in a
 * WeakMap — `new Adapter(Class.name)` or `Adapter(Class.name)` from the
 * configured adapter. A subclass of a public model therefore gets the
 * configured adapter under ITS OWN name. ReplayDetection is used because it is
 * the plainest model (no format of its own beyond opaque, no grant index); the
 * subclass is never instantiated, only its `adapter` is read, and its `name`
 * is pinned explicitly so nothing can rename the collection.
 */
export function createSubjectTokenRegistry(provider: Provider): SubjectTokenRegistry {
  class SubjectTokenRecordModel extends provider.ReplayDetection {}
  Object.defineProperty(SubjectTokenRecordModel, 'name', { value: SUBJECT_TOKEN_RECORD_MODEL });
  const adapter: Adapter = SubjectTokenRecordModel.adapter;

  return {
    async record(jti, record, ttlSeconds) {
      await adapter.upsert(jti, { ...record } as AdapterPayload, ttlSeconds);
    },
    async find(jti) {
      const stored = (await adapter.find(jti)) as Partial<SubjectTokenRecord> | undefined;
      if (stored === undefined || stored === null) return undefined;
      const { accountId, clientId, grantId, gty, aud, exp } = stored;
      if (
        typeof accountId !== 'string'
        || typeof clientId !== 'string'
        || typeof grantId !== 'string'
        || typeof gty !== 'string'
        || typeof aud !== 'string'
        || typeof exp !== 'number'
      ) {
        throw new Error(`subject token record ${jti} is malformed`);
      }
      return { accountId, clientId, grantId, gty, aud, exp };
    },
  };
}
