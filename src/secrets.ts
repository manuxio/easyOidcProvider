/**
 * Server secrets: the RS256 signing key and the cookie signing keys.
 *
 * Both are generated on first start and persisted, because a restart that
 * changes them invalidates every token in circulation — the exact thing
 * `docker compose down/up` must not do.
 *
 * Order of preference: MongoDB when configured, otherwise a file under DATA_DIR.
 * A memory store exists for tests only and says so, loudly.
 */
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { exportJWK, generateKeyPair, calculateJwkThumbprint, type JWK } from 'jose';
import type { Db } from 'mongodb';

import type { Logger } from './logger.js';

export interface ServerSecrets {
  /** Private JWKS handed to oidc-provider for signing. */
  jwks: { keys: JWK[] };
  /** Koa cookie signing keys, newest first. */
  cookieKeys: string[];
  createdAt: string;
}

export interface SecretStore {
  readonly kind: 'mongo' | 'file' | 'memory';
  /**
   * Returns the stored secrets, or stores and returns the ones produced by
   * `generate` if there are none. Must be atomic against a concurrent start.
   */
  loadOrCreate(generate: () => Promise<ServerSecrets>): Promise<ServerSecrets>;
}

const SECRETS_ID = 'server-secrets';
const SECRETS_COLLECTION = 'server_secrets';
const SECRETS_FILENAME = 'server-secrets.json';

export async function generateServerSecrets(): Promise<ServerSecrets> {
  const { privateKey } = await generateKeyPair('RS256', {
    modulusLength: 2048,
    extractable: true,
  });
  const jwk = await exportJWK(privateKey);
  jwk.use = 'sig';
  jwk.alg = 'RS256';
  jwk.kid = await calculateJwkThumbprint(jwk, 'sha256');

  return {
    jwks: { keys: [jwk] },
    cookieKeys: [randomBytes(32).toString('base64url'), randomBytes(32).toString('base64url')],
    createdAt: new Date().toISOString(),
  };
}

function isServerSecrets(value: unknown): value is ServerSecrets {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<ServerSecrets>;
  return (
    typeof candidate.jwks === 'object'
    && candidate.jwks !== null
    && Array.isArray(candidate.jwks.keys)
    && candidate.jwks.keys.length > 0
    && Array.isArray(candidate.cookieKeys)
    && candidate.cookieKeys.length > 0
  );
}

/**
 * Mongo store. `$setOnInsert` with upsert makes the first writer win, so two
 * containers starting at the same second agree on one key.
 */
export function mongoSecretStore(db: Db): SecretStore {
  return {
    kind: 'mongo',
    async loadOrCreate(generate) {
      const collection = db.collection<{ _id: string } & ServerSecrets>(SECRETS_COLLECTION);
      const existing = await collection.findOne({ _id: SECRETS_ID });
      if (existing && isServerSecrets(existing)) {
        return { jwks: existing.jwks, cookieKeys: existing.cookieKeys, createdAt: existing.createdAt };
      }

      const created = await generate();
      const result = await collection.findOneAndUpdate(
        { _id: SECRETS_ID },
        { $setOnInsert: { ...created } },
        { upsert: true, returnDocument: 'after' },
      );
      if (result && isServerSecrets(result)) {
        return { jwks: result.jwks, cookieKeys: result.cookieKeys, createdAt: result.createdAt };
      }
      return created;
    },
  };
}

/**
 * File store. The write goes to a temporary file and is then renamed, and the
 * rename loser re-reads the winner's file, so a race ends with one key, not two.
 */
export function fileSecretStore(dataDir: string): SecretStore {
  const path = resolve(join(dataDir, SECRETS_FILENAME));

  return {
    kind: 'file',
    async loadOrCreate(generate) {
      try {
        const raw = await readFile(path, 'utf8');
        const parsed: unknown = JSON.parse(raw);
        if (isServerSecrets(parsed)) return parsed;
        throw new Error(`${path} exists but does not contain usable server secrets`);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }

      const created = await generate();
      await mkdir(dirname(path), { recursive: true });
      const temporary = `${path}.${process.pid}.tmp`;
      await writeFile(temporary, JSON.stringify(created, null, 2), { mode: 0o600 });
      try {
        // `rename` would clobber a winner, so look again first and adopt its file.
        const raw = await readFile(path, 'utf8').catch(() => undefined);
        if (raw !== undefined) {
          const parsed: unknown = JSON.parse(raw);
          if (isServerSecrets(parsed)) return parsed;
        }
        await rename(temporary, path);
        return created;
      } finally {
        await rm(temporary, { force: true }).catch(() => undefined);
      }
    },
  };
}

/** Tests only: nothing survives the process. */
export function memorySecretStore(): SecretStore {
  let cached: ServerSecrets | undefined;
  return {
    kind: 'memory',
    async loadOrCreate(generate) {
      cached ??= await generate();
      return cached;
    },
  };
}

export function chooseSecretStore(
  options: { db?: Db; dataDir: string },
  logger: Logger,
): SecretStore {
  if (options.db) return mongoSecretStore(options.db);
  if (options.dataDir !== '') return fileSecretStore(options.dataDir);

  logger.warn(
    { reason: 'no_secret_persistence' },
    'neither MONGO_URL nor DATA_DIR is set: the RS256 signing key lives in memory and every restart invalidates the tokens already issued',
  );
  return memorySecretStore();
}

export async function loadServerSecrets(
  store: SecretStore,
  logger: Logger,
): Promise<ServerSecrets> {
  const secrets = await store.loadOrCreate(generateServerSecrets);
  logger.info(
    {
      store: store.kind,
      kid: secrets.jwks.keys[0]?.kid,
      createdAt: secrets.createdAt,
    },
    'server signing key ready',
  );
  return secrets;
}
