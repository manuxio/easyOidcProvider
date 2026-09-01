/**
 * Credentials read from an EXTERNAL MongoDB — external as in: not this
 * server's own state database (MONGO_URL), but the customer's user store,
 * reached through its own AUTH_MONGO_URL. The two must be free to differ in
 * host, credentials and lifecycle, which is why nothing here touches the
 * storage layer.
 *
 * Field names come from configuration (AUTH_MONGO_*_FIELD): the collection is
 * the customer's, and the code assumes nothing about its shape beyond what
 * the configuration declares. Username matching is EXACT on the lowercased
 * username — the same normalization the whole server applies (`sub` claim).
 *
 * The client is created lazily on the first lookup — with the feature
 * configured but the server idle, no connection exists — and every lookup is
 * bounded by the same deadline discipline as the SQL stores.
 */
import { withDeadline } from '../../deadline.js';
import type { Logger } from '../../logger.js';
import {
  CredentialStoreUnavailable,
  type CredentialRecord,
  type CredentialStore,
} from './store.js';

export interface MongoCredentialStoreOptions {
  url: string;
  dbName: string;
  collection: string;
  usernameField: string;
  passwordField: string;
  /** Optional: boolean field; absent config = existing user is active. */
  activeField?: string;
  /** Optional: per-user salt for the digest schemes. */
  saltField?: string;
  /** Optional: base32 TOTP seed, enables TWO_FACTOR_SOURCE=mongo. */
  totpField?: string;
  timeoutMs: number;
  logger: Logger;
}

/** The slice of the mongodb driver this store uses, narrow to stay mockable. */
interface MongoLikeClient {
  db(name: string): {
    collection(name: string): {
      findOne(filter: Record<string, unknown>): Promise<Record<string, unknown> | null>;
    };
  };
  close(): Promise<void>;
}

export function createMongoCredentialStore(options: MongoCredentialStoreOptions): CredentialStore {
  const log = options.logger.child({ component: 'identity.database.mongo' });

  let client: Promise<MongoLikeClient> | undefined;
  let closed = false;

  async function getClient(): Promise<MongoLikeClient> {
    if (!client) {
      client = (async () => {
        const { MongoClient } = await import('mongodb');
        const created = new MongoClient(options.url, {
          // Fail within the login deadline, not after the driver's 30 s default.
          serverSelectionTimeoutMS: options.timeoutMs,
          connectTimeoutMS: options.timeoutMs,
        });
        await created.connect();
        return created as unknown as MongoLikeClient;
      })().catch((error: unknown) => {
        // Do not memoize a failed connection: the next login retries.
        client = undefined;
        throw new CredentialStoreUnavailable(
          'mongo',
          `mongo credential store could not connect: ${describe(error)}`,
          error,
        );
      });
    }
    return client;
  }

  return {
    name: 'mongo',

    async lookup(username: string): Promise<CredentialRecord | undefined> {
      if (closed) throw new CredentialStoreUnavailable('mongo', 'store is closed');
      const startedAt = Date.now();
      let document: Record<string, unknown> | null;
      try {
        document = await withDeadline(
          (async () => {
            const connected = await getClient();
            return connected
              .db(options.dbName)
              .collection(options.collection)
              .findOne({ [options.usernameField]: username });
          })(),
          options.timeoutMs,
          () => new CredentialStoreUnavailable(
            'mongo',
            `credential lookup timed out after ${options.timeoutMs} ms for ${username}`,
          ),
        );
      } catch (error) {
        throw error instanceof CredentialStoreUnavailable
          ? error
          : new CredentialStoreUnavailable('mongo', describe(error), error);
      }

      if (!document) {
        log.debug(
          { username, durationMs: Date.now() - startedAt },
          'credential lookup: no document for this user',
        );
        return undefined;
      }

      const passwordHash = asText(document[options.passwordField]);
      if (passwordHash === undefined) {
        log.warn(
          { username, passwordField: options.passwordField, durationMs: Date.now() - startedAt },
          'credential lookup: the document has no usable password hash, treating the user as unknown',
        );
        return undefined;
      }

      const salt = options.saltField ? asText(document[options.saltField]) : undefined;
      const totpSeed = options.totpField ? asText(document[options.totpField]) : undefined;
      // With no activeField configured, existing = active. With one configured
      // the value must be EXACTLY true: a disabled flag mis-typed as "yes" or 1
      // must fail toward "cannot log in", never toward "active".
      const active = options.activeField === undefined
        ? true
        : document[options.activeField] === true;

      log.debug({ username, active, durationMs: Date.now() - startedAt }, 'credential lookup completed');
      return {
        passwordHash,
        active,
        ...(salt !== undefined ? { salt } : {}),
        ...(totpSeed !== undefined ? { totpSeed } : {}),
      };
    },

    async close(): Promise<void> {
      closed = true;
      const pending = client;
      client = undefined;
      if (!pending) return;
      await pending.then((c) => c.close()).catch(() => undefined);
    },
  };
}

function asText(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  const text = typeof value === 'string' ? value : String(value);
  return text.trim() === '' ? undefined : text.trim();
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
