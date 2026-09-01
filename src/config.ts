/**
 * Configuration contract for auth-server.
 *
 * Every knob comes from the environment. Nothing is read from the environment
 * outside this module, so the whole configuration surface is visible here and a
 * test can build a Config object without touching `process.env`.
 *
 * Validation is strict and eager: a missing or malformed required parameter
 * raises a ConfigError listing every offending parameter by name. The process
 * entry point turns that into an exit(1) with the parameter names in the log.
 */
import { isPasswordScheme, PASSWORD_SCHEMES, type PasswordScheme } from './identity/database/passwords.js';

export type IdentityProviderName = 'dev-stub' | 'spnego' | 'database';
export type SqlDriverName = 'mysql' | 'mssql';
/** Phase 4-bis: where the per-user TOTP seed is read from. */
export type TwoFactorSourceName = 'sql' | 'ldap' | 'mongo';
/** Where the `database` identity provider reads its credentials from. */
export type DatabaseAuthSourceName = 'sql' | 'mongo';

/** A client registration as accepted in CLIENTS_JSON (oidc-provider metadata). */
export interface ClientConfig {
  client_id: string;
  redirect_uris: string[];
  [metadata: string]: unknown;
}

export interface DevStubUser {
  username: string;
  password: string;
  /** When false, isAccountActive() rejects: used by the tests to disable a user. */
  active: boolean;
}

/** Parameters consumed from phase 3 (Kerberos/SPNEGO + LDAP) onwards. */
export interface KerberosConfig {
  /** Path to the service keytab, exported to the KRB5_KTNAME env var for the native lib. */
  keytabPath?: string;
  /** Expected SPN, e.g. HTTP/auth.example.com. Derived from ISSUER_URL when unset. */
  serviceName: string;
}

/** Parameters consumed from phase 3 (LDAP account liveness) onwards. */
export interface LdapConfig {
  url?: string;
  bindDn?: string;
  bindPassword?: string;
  baseDn?: string;
  /** Optional AD group the account must belong to. Empty = no group requirement. */
  requiredGroup?: string;
  /** Per-operation deadline, ms. Short on purpose: a gate must answer fast. */
  timeoutMs: number;
  /** TCP/TLS connect deadline, ms. */
  connectTimeoutMs: number;
  /** PEM bundle used to verify the directory certificate on ldaps://. */
  tlsCaFile?: string;
  /** Overrides the SNI/hostname checked in the certificate. Rarely needed. */
  tlsServername?: string;
  /** Laboratory escape hatch: skip certificate verification. Logged loudly. */
  tlsInsecure: boolean;
}

/** Parameters consumed from phase 4 (optional non-AD SQL group check). */
export interface SqlGroupCheckConfig {
  enabled: boolean;
  driver: SqlDriverName;
  connectionString?: string;
  /** One row returned = authorized. Username is always passed as a bind parameter. */
  query?: string;
  /** Deadline for connect+query, milliseconds. Short on purpose: it gates a login. */
  timeoutMs: number;
  /**
   * Periodic `SELECT 1` on the shared pool (any SQL feature on). Keeps the
   * path warm through stateful middleboxes and turns a broken path into a
   * timestamped log line instead of a rejected login. On by default.
   */
  keepaliveEnabled: boolean;
}

/**
 * Parameters of the optional SQL-sourced extra token claims (phase 4-ter).
 *
 * Its own switch, its own query, and the SHARED connection: SQL_DRIVER,
 * SQL_CONNECTION_STRING and SQL_TIMEOUT_MS are the same three the group check
 * and the TOTP seed use, because there is one customer database and there
 * should be one pool.
 */
export interface ExtraClaimsConfig {
  enabled: boolean;
  /**
   * The claims query. EXACTLY ONE row expected; its column names/aliases become
   * the claim names. Same placeholder rule as the other two queries: one bind
   * for the username, never interpolated.
   */
  query?: string;
}

// --- phase 4-bis: optional fallback form + optional TOTP second factor -------

/** Parameters of the optional TOTP second factor. Form path only. */
export interface TwoFactorConfig {
  enabled: boolean;
  /** Where the per-user base32 seed is read from. */
  source: TwoFactorSourceName;
  /**
   * Seed query when source=sql. Same contract as SQL_GROUP_QUERY: exactly one
   * bind placeholder, username always bound; the seed is the first column of the
   * first row, and zero rows means "not enrolled".
   */
  sqlQuery?: string;
  /** Attribute holding the seed when source=ldap, read with the service bind. */
  ldapAttribute?: string;
}

/**
 * Parameters of the `database` identity provider: credentials verified against
 * a customer database — SQL (through the shared SQL_DRIVER/SQL_CONNECTION_STRING
 * pool) or an EXTERNAL MongoDB with its own connection, distinct from the
 * server's state database.
 */
export interface DatabaseAuthConfig {
  source: DatabaseAuthSourceName;
  /**
   * How the stored password is verified. `auto` recognizes only the
   * self-describing formats (bcrypt/argon2id/scrypt/pbkdf2); the bare digest
   * schemes and `plain` must be declared explicitly.
   */
  passwordScheme: PasswordScheme;
  /**
   * Credential query when source=sql. One bind for the username; first column
   * of the single row = password hash; optional columns BY NAME: `salt`,
   * `totpsecret`. Zero rows = unknown or disabled (the query is the policy).
   */
  sqlQuery?: string;
  /** Connection and shape when source=mongo. */
  mongo?: {
    url: string;
    dbName: string;
    collection: string;
    usernameField: string;
    passwordField: string;
    activeField?: string;
    saltField?: string;
    totpField?: string;
  };
}

/** Cool-down on failed FORM attempts, per username. In-memory, single-instance. */
export interface LoginRateLimitConfig {
  /** Failures allowed before the cool-down starts. 0 disables the limiter. */
  maxFailedAttempts: number;
  /** Cool-down length in seconds; also the window in which failures decay. */
  lockoutSeconds: number;
}

// --- end phase 4-bis ---------------------------------------------------------

export interface Config {
  /** Single source of the public name. Never derived from the incoming request. */
  issuerUrl: string;
  port: number;
  host: string;
  logLevel: string;
  /** Express "trust proxy": on behind the TLS-terminating nginx. */
  trustProxy: boolean;

  /** Absent => in-memory adapter + no persisted secrets (development only). */
  mongoUrl?: string;
  mongoDbName?: string;

  /**
   * Directory for persisted server secrets when Mongo is not configured.
   * Empty string => secrets stay in memory (tests only; restarts invalidate tokens).
   */
  dataDir: string;

  identityProvider: IdentityProviderName;
  devStubUsers: DevStubUser[];
  /** Realm appended to dev-stub usernames so the principal has the AD shape. */
  devStubRealm: string;
  /**
   * Kerberos realm of the deployment, uppercased. It is one per installation, so
   * it is not carried inside the token: it is the `realm` claim and the half of
   * the principal that `sub` deliberately leaves out.
   */
  realm: string;

  clients: ClientConfig[];

  accessTokenTtl: number;
  refreshTokenTtl: number;

  /**
   * Optional audience for JWT access tokens (the resource API, phase 7).
   * Unset => opaque access tokens, which is the oidc-provider default.
   */
  apiAudience?: string;

  kerberos: KerberosConfig;
  ldap: LdapConfig;
  sqlGroupCheck: SqlGroupCheckConfig;
  databaseAuth: DatabaseAuthConfig;

  // --- phase 4-ter ---------------------------------------------------------
  /** Optional extra token claims read from the customer database. */
  extraClaims: ExtraClaimsConfig;
  // --- end phase 4-ter -----------------------------------------------------

  // --- phase 4-bis ---------------------------------------------------------
  /**
   * When false the credential form disappears: the 401 carries only
   * `WWW-Authenticate: Negotiate`, and the form POST endpoint refuses.
   * SSO-only deployment.
   */
  fallbackFormEnabled: boolean;
  twoFactor: TwoFactorConfig;
  loginRateLimit: LoginRateLimitConfig;
  // --- end phase 4-bis -----------------------------------------------------
}

export class ConfigError extends Error {
  readonly problems: string[];

  constructor(problems: string[]) {
    super(`invalid configuration: ${problems.join('; ')}`);
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

type Env = Record<string, string | undefined>;

function trimmed(env: Env, name: string): string | undefined {
  const raw = env[name];
  if (raw === undefined) return undefined;
  const value = raw.trim();
  return value === '' ? undefined : value;
}

function requireString(env: Env, name: string, problems: string[]): string {
  const value = trimmed(env, name);
  if (value === undefined) {
    problems.push(`${name} is required`);
    return '';
  }
  return value;
}

function optionalInteger(
  env: Env,
  name: string,
  fallback: number,
  problems: string[],
): number {
  const value = trimmed(env, name);
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    problems.push(`${name} must be a positive integer, got ${JSON.stringify(value)}`);
    return fallback;
  }
  return parsed;
}

/** Like optionalInteger, but 0 is a legal value (it means "off" for a counter). */
function optionalNonNegativeInteger(
  env: Env,
  name: string,
  fallback: number,
  problems: string[],
): number {
  const value = trimmed(env, name);
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    problems.push(`${name} must be an integer >= 0, got ${JSON.stringify(value)}`);
    return fallback;
  }
  return parsed;
}

function optionalBoolean(
  env: Env,
  name: string,
  fallback: boolean,
  problems: string[],
): boolean {
  const value = trimmed(env, name);
  if (value === undefined) return fallback;
  const lowered = value.toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(lowered)) return true;
  if (['0', 'false', 'no', 'off'].includes(lowered)) return false;
  problems.push(`${name} must be a boolean (true/false), got ${JSON.stringify(value)}`);
  return fallback;
}

function parseJson(env: Env, name: string, problems: string[]): unknown {
  const value = trimmed(env, name);
  if (value === undefined) return undefined;
  try {
    return JSON.parse(value);
  } catch (error) {
    problems.push(`${name} is not valid JSON: ${(error as Error).message}`);
    return undefined;
  }
}

function parseClients(env: Env, problems: string[]): ClientConfig[] {
  const parsed = parseJson(env, 'CLIENTS_JSON', problems);
  if (parsed === undefined) {
    if (!problems.some((p) => p.startsWith('CLIENTS_JSON'))) {
      problems.push('CLIENTS_JSON is required (JSON array of client registrations)');
    }
    return [];
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    problems.push('CLIENTS_JSON must be a non-empty JSON array');
    return [];
  }

  const clients: ClientConfig[] = [];
  parsed.forEach((entry, index) => {
    const where = `CLIENTS_JSON[${index}]`;
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      problems.push(`${where} must be an object`);
      return;
    }
    const candidate = entry as Record<string, unknown>;
    if (typeof candidate.client_id !== 'string' || candidate.client_id.trim() === '') {
      problems.push(`${where}.client_id is required`);
      return;
    }
    const redirectUris = candidate.redirect_uris;
    if (
      !Array.isArray(redirectUris)
      || redirectUris.length === 0
      || redirectUris.some((uri) => typeof uri !== 'string')
    ) {
      problems.push(`${where}.redirect_uris must be a non-empty array of strings`);
      return;
    }
    clients.push(candidate as unknown as ClientConfig);
  });
  return clients;
}

function parseDevStubUsers(
  env: Env,
  identityProvider: IdentityProviderName,
  problems: string[],
): DevStubUser[] {
  const parsed = parseJson(env, 'DEV_STUB_USERS', problems);
  if (parsed === undefined) {
    if (identityProvider === 'dev-stub' && !problems.some((p) => p.startsWith('DEV_STUB_USERS'))) {
      problems.push('DEV_STUB_USERS is required when IDENTITY_PROVIDER=dev-stub');
    }
    return [];
  }
  if (!Array.isArray(parsed)) {
    problems.push('DEV_STUB_USERS must be a JSON array');
    return [];
  }

  const users: DevStubUser[] = [];
  parsed.forEach((entry, index) => {
    const where = `DEV_STUB_USERS[${index}]`;
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      problems.push(`${where} must be an object`);
      return;
    }
    const candidate = entry as Record<string, unknown>;
    if (typeof candidate.username !== 'string' || candidate.username.trim() === '') {
      problems.push(`${where}.username is required`);
      return;
    }
    if (typeof candidate.password !== 'string') {
      problems.push(`${where}.password is required`);
      return;
    }
    if (candidate.active !== undefined && typeof candidate.active !== 'boolean') {
      problems.push(`${where}.active must be a boolean`);
      return;
    }
    users.push({
      username: candidate.username.trim(),
      password: candidate.password,
      active: candidate.active === undefined ? true : candidate.active,
    });
  });

  if (identityProvider === 'dev-stub' && users.length === 0 && problems.length === 0) {
    problems.push('DEV_STUB_USERS must define at least one user when IDENTITY_PROVIDER=dev-stub');
  }
  return users;
}

/**
 * Derives the expected SPN from the public name, as agreed: the SPN lives on the
 * name nginx serves, not on the container host.
 */
export function deriveServiceName(issuerUrl: string): string {
  try {
    return `HTTP/${new URL(issuerUrl).hostname}`;
  } catch {
    return '';
  }
}

function parseMongoDbName(mongoUrl: string | undefined, explicit: string | undefined): string | undefined {
  if (explicit) return explicit;
  if (!mongoUrl) return undefined;
  try {
    const path = new URL(mongoUrl).pathname.replace(/^\//, '');
    return path === '' ? undefined : decodeURIComponent(path);
  } catch {
    return undefined;
  }
}

export function loadConfig(env: Env = process.env): Config {
  const problems: string[] = [];

  const issuerUrl = requireString(env, 'ISSUER_URL', problems);
  if (issuerUrl !== '') {
    try {
      const parsed = new URL(issuerUrl);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        problems.push('ISSUER_URL must be an http(s) URL');
      }
      if (issuerUrl.endsWith('/')) {
        problems.push('ISSUER_URL must not end with a trailing slash');
      }
    } catch {
      problems.push(`ISSUER_URL is not a valid URL: ${JSON.stringify(issuerUrl)}`);
    }
  }

  const identityProviderRaw = trimmed(env, 'IDENTITY_PROVIDER') ?? 'dev-stub';
  if (identityProviderRaw !== 'dev-stub' && identityProviderRaw !== 'spnego' && identityProviderRaw !== 'database') {
    problems.push(
      `IDENTITY_PROVIDER must be one of dev-stub|spnego|database, got ${JSON.stringify(identityProviderRaw)}`,
    );
  }
  const identityProvider = (
    identityProviderRaw === 'spnego' || identityProviderRaw === 'database'
      ? identityProviderRaw
      : 'dev-stub'
  ) as IdentityProviderName;

  const sqlDriverRaw = trimmed(env, 'SQL_DRIVER') ?? 'mysql';
  if (sqlDriverRaw !== 'mysql' && sqlDriverRaw !== 'mssql') {
    problems.push(`SQL_DRIVER must be one of mysql|mssql, got ${JSON.stringify(sqlDriverRaw)}`);
  }

  const sqlGroupCheckEnabled = optionalBoolean(env, 'SQL_GROUP_CHECK_ENABLED', false, problems);
  const sqlConnectionString = trimmed(env, 'SQL_CONNECTION_STRING');
  const sqlQuery = trimmed(env, 'SQL_GROUP_QUERY');
  // Short by design: this runs inside a login and inside every refresh, so the
  // deadline is what stops a hung database from hanging the whole floor.
  const sqlTimeoutMs = optionalInteger(env, 'SQL_TIMEOUT_MS', 5000, problems);
  const sqlKeepaliveEnabled = optionalBoolean(env, 'SQL_KEEPALIVE_ENABLED', true, problems);
  if (sqlGroupCheckEnabled) {
    if (!sqlConnectionString) {
      problems.push('SQL_CONNECTION_STRING is required when SQL_GROUP_CHECK_ENABLED=true');
    }
    if (!sqlQuery) {
      problems.push('SQL_GROUP_QUERY is required when SQL_GROUP_CHECK_ENABLED=true');
    }
  }

  // --- phase 4-ter: optional SQL-sourced extra token claims ------------------
  // Its own switch, the shared connection. The rule is the same as
  // TWO_FACTOR_SOURCE=sql: turning this on without a connection string stops
  // the server by parameter name, because the features share the database, not
  // each other's switch.
  const claimsSqlEnabled = optionalBoolean(env, 'CLAIMS_SQL_ENABLED', false, problems);
  const claimsSqlQuery = trimmed(env, 'CLAIMS_SQL_QUERY');
  if (claimsSqlEnabled) {
    if (!claimsSqlQuery) {
      problems.push('CLAIMS_SQL_QUERY is required when CLAIMS_SQL_ENABLED=true');
    }
    if (!sqlConnectionString) {
      problems.push('SQL_CONNECTION_STRING is required when CLAIMS_SQL_ENABLED=true');
    }
  }
  // --- end phase 4-ter -------------------------------------------------------

  const mongoUrl = trimmed(env, 'MONGO_URL');
  const devStubRealm = (trimmed(env, 'DEV_STUB_REALM') ?? 'DEV.LOCAL').toUpperCase();
  const realm = (
    trimmed(env, 'REALM') ?? (identityProvider === 'dev-stub' ? devStubRealm : undefined)
  )?.toUpperCase();
  if (realm === undefined && identityProvider === 'spnego') {
    problems.push('REALM is required when IDENTITY_PROVIDER=spnego');
  }
  // With IDENTITY_PROVIDER=database the realm is optional decoration: unset,
  // the principal is the bare lowercased username and the realm claim is ''.

  // --- phase 3: parameters the spnego provider cannot start without ---------
  const kerberosServiceName = trimmed(env, 'KERBEROS_SERVICE_NAME') ?? deriveServiceName(issuerUrl);
  if (identityProvider === 'spnego') {
    if (kerberosServiceName === '') {
      problems.push(
        'KERBEROS_SERVICE_NAME is required when IDENTITY_PROVIDER=spnego and ISSUER_URL has no usable hostname',
      );
    }
    for (const name of ['LDAP_URL', 'LDAP_BIND_DN', 'LDAP_BIND_PASSWORD', 'LDAP_BASE_DN']) {
      if (trimmed(env, name) === undefined) {
        problems.push(`${name} is required when IDENTITY_PROVIDER=spnego`);
      }
    }
    const ldapUrl = trimmed(env, 'LDAP_URL');
    if (ldapUrl !== undefined && !/^ldaps?:\/\//i.test(ldapUrl)) {
      problems.push(`LDAP_URL must start with ldap:// or ldaps://, got ${JSON.stringify(ldapUrl)}`);
    }
  }
  // --- end phase 3 ---------------------------------------------------------

  // --- database identity provider: credentials from a customer database ------
  const databaseSourceRaw = trimmed(env, 'AUTH_DB_SOURCE');
  if (databaseSourceRaw !== undefined && databaseSourceRaw !== 'sql' && databaseSourceRaw !== 'mongo') {
    problems.push(`AUTH_DB_SOURCE must be one of sql|mongo, got ${JSON.stringify(databaseSourceRaw)}`);
  }
  const databaseSource = (databaseSourceRaw === 'mongo' ? 'mongo' : 'sql') as DatabaseAuthSourceName;

  const passwordSchemeRaw = trimmed(env, 'AUTH_PASSWORD_SCHEME') ?? 'auto';
  if (!isPasswordScheme(passwordSchemeRaw)) {
    problems.push(
      `AUTH_PASSWORD_SCHEME must be one of ${PASSWORD_SCHEMES.join('|')}, got ${JSON.stringify(passwordSchemeRaw)}`,
    );
  }
  const passwordScheme: PasswordScheme = isPasswordScheme(passwordSchemeRaw) ? passwordSchemeRaw : 'auto';

  const authSqlQuery = trimmed(env, 'AUTH_SQL_QUERY');
  const authMongoUrl = trimmed(env, 'AUTH_MONGO_URL');
  const authMongoCollection = trimmed(env, 'AUTH_MONGO_COLLECTION');
  const authMongoDbName = parseMongoDbName(authMongoUrl, trimmed(env, 'AUTH_MONGO_DB'));
  const authMongoTotpField = trimmed(env, 'AUTH_MONGO_TOTP_FIELD');

  if (identityProvider === 'database') {
    if (databaseSourceRaw === undefined) {
      problems.push('AUTH_DB_SOURCE is required when IDENTITY_PROVIDER=database (sql|mongo)');
    }
    if (databaseSource === 'sql' && databaseSourceRaw !== undefined) {
      if (!authSqlQuery) {
        problems.push('AUTH_SQL_QUERY is required when AUTH_DB_SOURCE=sql');
      }
      // The credential lookup shares the pool of the other SQL features, and
      // like them it shares the connection, not their switches.
      if (!sqlConnectionString) {
        problems.push('SQL_CONNECTION_STRING is required when AUTH_DB_SOURCE=sql');
      }
    }
    if (databaseSource === 'mongo' && databaseSourceRaw !== undefined) {
      if (!authMongoUrl) {
        problems.push('AUTH_MONGO_URL is required when AUTH_DB_SOURCE=mongo');
      }
      if (!authMongoCollection) {
        problems.push('AUTH_MONGO_COLLECTION is required when AUTH_DB_SOURCE=mongo');
      }
      if (authMongoUrl && authMongoDbName === undefined) {
        problems.push('AUTH_MONGO_DB is required when AUTH_MONGO_URL carries no database name');
      }
    }
  }
  // --- end database identity provider ----------------------------------------

  // --- phase 4-bis: optional form + optional TOTP second factor -------------
  const fallbackFormEnabled = optionalBoolean(env, 'FALLBACK_FORM_ENABLED', true, problems);
  if (!fallbackFormEnabled && identityProvider !== 'spnego') {
    // With dev-stub and database the form is the ONLY door: there is no
    // Kerberos handshake to fall back FROM. Turning it off would build a server
    // nobody can log into, so it is refused here rather than discovered at the
    // first login.
    problems.push(
      'FALLBACK_FORM_ENABLED=false is only meaningful with IDENTITY_PROVIDER=spnego: '
      + `with ${identityProvider} the form is the only way in`,
    );
  }

  const twoFactorEnabled = optionalBoolean(env, 'TWO_FACTOR_ENABLED', false, problems);
  const twoFactorSourceRaw = trimmed(env, 'TWO_FACTOR_SOURCE');
  const twoFactorSqlQuery = trimmed(env, 'TWO_FACTOR_SQL_QUERY');
  const twoFactorLdapAttribute = trimmed(env, 'TWO_FACTOR_LDAP_ATTRIBUTE');

  if (
    twoFactorSourceRaw !== undefined
    && twoFactorSourceRaw !== 'sql' && twoFactorSourceRaw !== 'ldap' && twoFactorSourceRaw !== 'mongo'
  ) {
    problems.push(
      `TWO_FACTOR_SOURCE must be one of sql|ldap|mongo, got ${JSON.stringify(twoFactorSourceRaw)}`,
    );
  }
  const twoFactorSource = (
    twoFactorSourceRaw === 'ldap' || twoFactorSourceRaw === 'mongo' ? twoFactorSourceRaw : 'sql'
  ) as TwoFactorSourceName;

  if (twoFactorEnabled) {
    if (twoFactorSourceRaw === undefined) {
      problems.push('TWO_FACTOR_SOURCE is required when TWO_FACTOR_ENABLED=true (sql|ldap|mongo)');
    }
    if (twoFactorSource === 'sql' && twoFactorSourceRaw !== undefined) {
      if (!twoFactorSqlQuery) {
        problems.push('TWO_FACTOR_SQL_QUERY is required when TWO_FACTOR_SOURCE=sql');
      }
      // The seed lookup needs a database even when the group check is off: the
      // two features share the connection, not each other's switch.
      if (!sqlConnectionString) {
        problems.push('SQL_CONNECTION_STRING is required when TWO_FACTOR_SOURCE=sql');
      }
    }
    if (twoFactorSource === 'ldap' && twoFactorSourceRaw !== undefined) {
      if (!twoFactorLdapAttribute) {
        problems.push('TWO_FACTOR_LDAP_ATTRIBUTE is required when TWO_FACTOR_SOURCE=ldap');
      }
      if (identityProvider !== 'spnego') {
        // The seed is read through the same LdapDirectory the spnego provider
        // owns. dev-stub has no directory at all, so there would be nothing to
        // read from.
        problems.push(
          'TWO_FACTOR_SOURCE=ldap requires IDENTITY_PROVIDER=spnego: the seed is read '
          + 'through the same LDAP service bind as the account liveness check',
        );
      }
    }
    if (twoFactorSource === 'mongo' && twoFactorSourceRaw !== undefined) {
      // The seed is read from the SAME document as the credentials, through the
      // same store: the source exists only where that store exists.
      if (identityProvider !== 'database' || databaseSource !== 'mongo') {
        problems.push(
          'TWO_FACTOR_SOURCE=mongo requires IDENTITY_PROVIDER=database with AUTH_DB_SOURCE=mongo: '
          + 'the seed is read from the same credential store',
        );
      }
      if (!authMongoTotpField) {
        problems.push('AUTH_MONGO_TOTP_FIELD is required when TWO_FACTOR_SOURCE=mongo');
      }
    }
  }
  // --- end phase 4-bis -----------------------------------------------------

  const config: Config = {
    issuerUrl,
    port: optionalInteger(env, 'PORT', 3000, problems),
    host: trimmed(env, 'HOST') ?? '0.0.0.0',
    logLevel: trimmed(env, 'LOG_LEVEL') ?? 'info',
    trustProxy: optionalBoolean(env, 'TRUST_PROXY', false, problems),

    mongoUrl,
    mongoDbName: parseMongoDbName(mongoUrl, trimmed(env, 'MONGO_DB_NAME')),

    dataDir: env.DATA_DIR === undefined ? './data' : env.DATA_DIR.trim(),

    identityProvider,
    devStubUsers: parseDevStubUsers(env, identityProvider, problems),
    devStubRealm,
    realm: realm ?? '',

    clients: parseClients(env, problems),

    accessTokenTtl: optionalInteger(env, 'ACCESS_TOKEN_TTL', 3600, problems),
    refreshTokenTtl: optionalInteger(env, 'REFRESH_TOKEN_TTL', 43200, problems),

    apiAudience: trimmed(env, 'API_AUDIENCE'),

    kerberos: {
      keytabPath: trimmed(env, 'KRB5_KTNAME'),
      serviceName: kerberosServiceName,
    },
    ldap: {
      url: trimmed(env, 'LDAP_URL'),
      bindDn: trimmed(env, 'LDAP_BIND_DN'),
      bindPassword: trimmed(env, 'LDAP_BIND_PASSWORD'),
      baseDn: trimmed(env, 'LDAP_BASE_DN'),
      requiredGroup: trimmed(env, 'LDAP_REQUIRED_GROUP'),
      // --- phase 3 additions ---------------------------------------------
      timeoutMs: optionalInteger(env, 'LDAP_TIMEOUT_MS', 5000, problems),
      connectTimeoutMs: optionalInteger(env, 'LDAP_CONNECT_TIMEOUT_MS', 5000, problems),
      tlsCaFile: trimmed(env, 'LDAP_TLS_CA_FILE'),
      tlsServername: trimmed(env, 'LDAP_TLS_SERVERNAME'),
      tlsInsecure: optionalBoolean(env, 'LDAP_TLS_INSECURE', false, problems),
      // --- end phase 3 additions -----------------------------------------
    },
    sqlGroupCheck: {
      enabled: sqlGroupCheckEnabled,
      driver: (sqlDriverRaw === 'mssql' ? 'mssql' : 'mysql') as SqlDriverName,
      connectionString: sqlConnectionString,
      query: sqlQuery,
      timeoutMs: sqlTimeoutMs,
      keepaliveEnabled: sqlKeepaliveEnabled,
    },

    databaseAuth: {
      source: databaseSource,
      passwordScheme,
      ...(authSqlQuery !== undefined ? { sqlQuery: authSqlQuery } : {}),
      ...(authMongoUrl !== undefined && authMongoCollection !== undefined ? {
        mongo: {
          url: authMongoUrl,
          dbName: authMongoDbName ?? '',
          collection: authMongoCollection,
          usernameField: trimmed(env, 'AUTH_MONGO_USERNAME_FIELD') ?? 'username',
          passwordField: trimmed(env, 'AUTH_MONGO_PASSWORD_FIELD') ?? 'password',
          ...(trimmed(env, 'AUTH_MONGO_ACTIVE_FIELD') !== undefined
            ? { activeField: trimmed(env, 'AUTH_MONGO_ACTIVE_FIELD')! } : {}),
          ...(trimmed(env, 'AUTH_MONGO_SALT_FIELD') !== undefined
            ? { saltField: trimmed(env, 'AUTH_MONGO_SALT_FIELD')! } : {}),
          ...(authMongoTotpField !== undefined ? { totpField: authMongoTotpField } : {}),
        },
      } : {}),
    },

    // --- phase 4-ter ------------------------------------------------------
    extraClaims: {
      enabled: claimsSqlEnabled,
      query: claimsSqlQuery,
    },
    // --- end phase 4-ter --------------------------------------------------

    // --- phase 4-bis ------------------------------------------------------
    fallbackFormEnabled,
    twoFactor: {
      enabled: twoFactorEnabled,
      source: twoFactorSource,
      sqlQuery: twoFactorSqlQuery,
      ldapAttribute: twoFactorLdapAttribute,
    },
    loginRateLimit: {
      maxFailedAttempts: optionalNonNegativeInteger(env, 'FORM_MAX_FAILED_ATTEMPTS', 5, problems),
      lockoutSeconds: optionalInteger(env, 'FORM_LOCKOUT_SECONDS', 300, problems),
    },
    // --- end phase 4-bis --------------------------------------------------
  };

  if (problems.length > 0) {
    throw new ConfigError(problems);
  }
  return config;
}
