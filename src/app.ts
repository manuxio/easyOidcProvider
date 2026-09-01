/**
 * Assembles the whole server from a Config, and hands back everything a caller
 * needs to drive it: the express app, the provider, the identity provider (so a
 * test can flip a dev-stub user), and a close() that releases Mongo.
 *
 * Nothing here reads process.env: the configuration arrives as an argument, so a
 * test can build three servers in one process without them colliding.
 */
import express, { type Express } from 'express';
import type { Db } from 'mongodb';
import type Provider from 'oidc-provider';
import type { AdapterFactory } from 'oidc-provider';

import { connectMongo, type MongoStorage } from './adapters/mongo.js';
import { buildExtraClaims, type ExtraClaimsSource } from './claims/index.js';
import type { Config } from './config.js';
import { buildAccountGates, closeAccountGates, type AccountGate } from './gates/index.js';
import {
  createIdentityProvider,
  createMongoCredentialStore,
  createSqlCredentialStore,
  type CredentialStore,
  type IdentityProvider,
} from './identity/index.js';
import { SpnegoIdentityProvider } from './identity/spnego/index.js';
import { createLogger, type Logger } from './logger.js';
import { createProvider } from './provider/index.js';
import { createSqlDriver, type SqlDriver } from './sqlcheck/index.js';
import { createHealthRouter } from './routes/health.js';
import { createInteractionRouter } from './routes/interaction.js';
import { chooseSecretStore, loadServerSecrets } from './secrets.js';
import {
  buildTwoFactor,
  LoginRateLimiter,
  type TwoFactorSeedSource,
  type TwoFactorVerifier,
} from './twofactor/index.js';

export interface AuthServer {
  app: Express;
  provider: Provider;
  identity: IdentityProvider;
  gates: readonly AccountGate[];
  config: Config;
  logger: Logger;
  db?: Db;
  /** Phase 4-bis: present only when TWO_FACTOR_ENABLED=true. */
  twoFactor?: TwoFactorVerifier;
  /** Phase 4-ter: present only when CLAIMS_SQL_ENABLED=true. */
  extraClaims?: ExtraClaimsSource;
  /** Phase 4-bis: always present; inert when FORM_MAX_FAILED_ATTEMPTS=0. */
  rateLimiter: LoginRateLimiter;
  close(): Promise<void>;
}

export interface CreateAuthServerOptions {
  config: Config;
  /** Supply one to keep the app quiet in tests. */
  logger?: Logger;
  /**
   * Phase 4 test seam: a fake SQL driver used in place of the configured engine.
   * Ignored when neither the group check nor a SQL two-factor seed source is on
   * — nothing is built then.
   */
  sqlDriver?: SqlDriver;
  /** Phase 4-bis test seam: a seed source in place of SQL or LDAP. */
  twoFactorSeedSource?: TwoFactorSeedSource;
  /** Phase 4-ter test seam: an extra-claims source in place of the SQL one. */
  extraClaimsSource?: ExtraClaimsSource;
}

export async function createAuthServer(options: CreateAuthServerOptions): Promise<AuthServer> {
  const { config } = options;
  const logger = options.logger ?? createLogger(config.logLevel);

  let storage: MongoStorage | undefined;
  let adapterFactory: AdapterFactory | undefined;

  if (config.mongoUrl) {
    storage = await connectMongo(config.mongoUrl, config.mongoDbName);
    adapterFactory = storage.adapterFactory;
    logger.info({ db: storage.db.databaseName }, 'oidc state stored in mongodb');
  } else {
    logger.warn(
      { reason: 'no_mongo_url' },
      'MONGO_URL is not set: oidc state is kept in memory, a restart drops every session and token (development only)',
    );
  }

  const secrets = await loadServerSecrets(
    chooseSecretStore({ db: storage?.db, dataDir: config.dataDir }, logger),
    logger,
  );

  // --- one SQL driver, shared by every feature that needs one ---------------
  // The group check (phase 4), the two-factor seed source (phase 4-bis), the
  // extra token claims (phase 4-ter) and the database identity provider's SQL
  // credential store read the same database through the same SQL_DRIVER /
  // SQL_CONNECTION_STRING, so they get ONE pool. Each works with the others
  // disabled; with all of them off the driver is never built and the database
  // library is never even loaded. Built BEFORE the identity provider because
  // the credential store rides on it.
  const databaseIdentity = config.identityProvider === 'database';
  const needsSql =
    config.sqlGroupCheck.enabled
    || (config.twoFactor.enabled && config.twoFactor.source === 'sql' && !options.twoFactorSeedSource)
    || (config.extraClaims.enabled && !options.extraClaimsSource)
    || (databaseIdentity && config.databaseAuth.source === 'sql');
  const sqlDriver = needsSql
    ? options.sqlDriver ?? createSqlDriver(config.sqlGroupCheck.driver, {
      connectionString: config.sqlGroupCheck.connectionString ?? '',
      timeoutMs: config.sqlGroupCheck.timeoutMs,
      logger,
      // 45 s sits under the pool's own 60 s idle eviction, so the warm
      // connection the ping maintains is never the one being evicted.
      ...(config.sqlGroupCheck.keepaliveEnabled ? { keepaliveIntervalMs: 45_000 } : {}),
    })
    : undefined;
  // --- end shared SQL driver -----------------------------------------------

  // The credential store of the database identity provider. Shared with the
  // two-factor seed source when TWO_FACTOR_SOURCE=mongo; owned (and closed) by
  // the provider.
  const credentialStore = databaseIdentity
    ? buildCredentialStore(config, logger, sqlDriver)
    : undefined;

  const identity = createIdentityProvider(
    config,
    logger,
    credentialStore ? { credentialStore } : {},
  );

  const gates = buildAccountGates(
    config,
    identity,
    logger,
    sqlDriver ? { sqlDriver } : {},
  );

  // --- phase 4-bis: the optional second factor and the form cool-down -------
  const twoFactor = buildTwoFactor(config, logger, {
    ...(sqlDriver ? { sqlDriver } : {}),
    ...(identity instanceof SpnegoIdentityProvider ? { directory: identity.directory } : {}),
    ...(credentialStore ? { credentialStore } : {}),
    ...(options.twoFactorSeedSource ? { seedSource: options.twoFactorSeedSource } : {}),
  });

  if (config.twoFactor.enabled && !config.fallbackFormEnabled) {
    logger.warn(
      { reason: 'two_factor_unreachable' },
      'TWO_FACTOR_ENABLED=true with FALLBACK_FORM_ENABLED=false: the second factor lives on the form path only, so with the form off it can never be asked for',
    );
  }

  const rateLimiter = new LoginRateLimiter({
    maxFailedAttempts: config.loginRateLimit.maxFailedAttempts,
    lockoutMs: config.loginRateLimit.lockoutSeconds * 1000,
    logger,
  });
  // --- end phase 4-bis -----------------------------------------------------

  // --- phase 4-ter: the optional SQL-sourced extra token claims -------------
  // Built BEFORE the provider on purpose: the claim names it declares have to
  // be in the `claims` configuration when the Provider is constructed, or
  // oidc-provider filters them out of the id token (see src/claims/selectList.ts).
  const extraClaims = buildExtraClaims(config, logger, {
    ...(sqlDriver ? { sqlDriver } : {}),
    ...(options.extraClaimsSource ? { source: options.extraClaimsSource } : {}),
  });
  // --- end phase 4-ter -----------------------------------------------------

  const provider = createProvider({
    config,
    secrets,
    gates,
    logger,
    adapterFactory,
    ...(extraClaims ? { extraClaims } : {}),
  });

  const app = express();
  app.disable('x-powered-by');
  if (config.trustProxy) app.set('trust proxy', true);

  app.use(createHealthRouter({
    db: storage?.db,
    identityProviderName: identity.name,
    logger,
  }));

  // The login form posts urlencoded; nothing here accepts JSON bodies. Scoped
  // to the interaction routes: oidc-provider parses the bodies of ITS
  // endpoints (/token, /auth, …) itself, and a body already parsed upstream
  // makes it warn and fall back to req.body.
  app.use('/interaction', express.urlencoded({ extended: false, limit: '16kb' }));

  app.use(createInteractionRouter({
    provider,
    identity,
    gates,
    config,
    logger,
    ...(twoFactor ? { twoFactor } : {}),
    ...(extraClaims ? { extraClaims } : {}),
    rateLimiter,
  }));

  // Everything else — discovery, jwks, authorize, token, userinfo, revocation —
  // belongs to oidc-provider.
  app.use(provider.callback());

  return {
    app,
    provider,
    identity,
    gates,
    config,
    logger,
    db: storage?.db,
    ...(twoFactor ? { twoFactor } : {}),
    ...(extraClaims ? { extraClaims } : {}),
    rateLimiter,
    async close() {
      await identity.close?.();
      // Phase 4: releases the SQL pool when the group check is on.
      await closeAccountGates(gates, logger);
      // Phase 4-bis: closing the seed source closes the same shared pool a
      // second time when both features are on. Every driver's close() is
      // idempotent, which is what makes the sharing safe.
      await twoFactor?.close().catch((error: unknown) => {
        logger.warn({ err: error }, 'the two-factor seed source did not close cleanly');
      });
      // Phase 4-ter: same story — the extra claims source closes the shared
      // pool a third time, and every driver's close() is idempotent.
      await extraClaims?.close().catch((error: unknown) => {
        logger.warn({ err: error }, 'the extra claims source did not close cleanly');
      });
      await sqlDriver?.close().catch(() => undefined);
      // The credential store: identity.close() above already released it (the
      // provider owns it), and like everything on this seam close() is
      // idempotent, so the belt costs nothing.
      await credentialStore?.close().catch(() => undefined);
      await storage?.close();
    },
  };
}

/**
 * The credential store for IDENTITY_PROVIDER=database. config.ts has already
 * validated the parameters of the chosen source; what is enforced here is only
 * the wiring the validation cannot see (the shared driver instance).
 */
function buildCredentialStore(
  config: Config,
  logger: Logger,
  sqlDriver: SqlDriver | undefined,
): CredentialStore {
  if (config.databaseAuth.source === 'sql') {
    if (!config.databaseAuth.sqlQuery || !sqlDriver) {
      throw new Error(
        'AUTH_DB_SOURCE=sql needs AUTH_SQL_QUERY and a SQL driver: check SQL_DRIVER and SQL_CONNECTION_STRING',
      );
    }
    return createSqlCredentialStore({
      query: config.databaseAuth.sqlQuery,
      driver: sqlDriver,
      timeoutMs: config.sqlGroupCheck.timeoutMs,
      logger,
    });
  }
  const mongo = config.databaseAuth.mongo;
  if (!mongo) {
    throw new Error(
      'AUTH_DB_SOURCE=mongo needs AUTH_MONGO_URL and AUTH_MONGO_COLLECTION',
    );
  }
  return createMongoCredentialStore({
    ...mongo,
    timeoutMs: config.sqlGroupCheck.timeoutMs,
    logger,
  });
}
