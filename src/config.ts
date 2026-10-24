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
  /** Required for the user clients; absent or empty for a machine-to-machine client. */
  redirect_uris?: string[];
  [metadata: string]: unknown;
}

/**
 * Scope names that belong to OpenID Connect itself. They never select a
 * resource: a person reaches the API_AUDIENCE resource through `openid`.
 */
export const OIDC_SCOPES: readonly string[] = ['openid', 'offline_access', 'profile'];

/** The OAuth 2.0 Token Exchange grant (RFC 8693 §2.1). */
export const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';

/** RFC 8693 §3 token type of an access token: the only one exchanged, the only one issued. */
export const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

/**
 * The three kinds of caller a resource can be opened to: `client_credentials`
 * = machines, `authorization_code` = people (and the refresh_token grant that
 * follows a login), `token-exchange` = a token delegated by a person to a
 * service through RFC 8693.
 */
export const RESOURCE_GRANTS = ['client_credentials', 'authorization_code', 'token-exchange'] as const;
export type ResourceGrant = (typeof RESOURCE_GRANTS)[number];

/**
 * The grants a subject token may have been born from. A person is behind
 * both; a client_credentials token has no person and a token-exchange token
 * is already delegated, so neither is ever exchangeable.
 */
export const SUBJECT_GRANTS = ['authorization_code', 'refresh_token'] as const;
export type SubjectGrant = (typeof SUBJECT_GRANTS)[number];

/**
 * Token-endpoint authentication methods accepted for a token exchange client:
 * the private key stays with the client, this server only knows the public one.
 */
export const EXCHANGE_AUTH_METHODS: readonly string[] = ['private_key_jwt'];

/** Ceiling on the life of an exchanged token: a limit, never a default. */
export const MAX_EXCHANGE_TTL_SECONDS = 900;

/** A resource as its selecting scope and the grants allowed to ask for it. */
export interface ResourceScopeConfig {
  scope: string;
  grants: ResourceGrant[];
  /**
   * Present exactly when `grants` lists `token-exchange`: the scopes an
   * exchanged token may carry besides the selecting one.
   */
  exchange_scopes?: string[];
}

/**
 * One RFC 8693 exchange a client may ask for, from CLIENTS_JSON[i].token_exchange.
 * A request is served only when it matches exactly one rule.
 */
export interface TokenExchangeRule {
  subject: {
    token_type: typeof ACCESS_TOKEN_TYPE;
    /** The audience the subject token must carry. */
    audience: string;
    /** The clients that may have obtained the subject token. */
    client_ids: string[];
    /** Every word of the subject token's grant type must be in this list. */
    issued_by_grants: SubjectGrant[];
  };
  issue: {
    token_type: typeof ACCESS_TOKEN_TYPE;
    /** A declared resource audience that lists `token-exchange`. */
    audience: string;
    /** Space-separated: the most the issued token may carry, selector included. */
    scope: string;
    ttl_seconds: number;
    refresh_token: false;
  };
  /** `CLIENTS_JSON[i].token_exchange[j]`, for the logs. */
  where: string;
}

/**
 * The API_AUDIENCE resource, declared in DEFAULT_RESOURCE_JSON. Its audience
 * is API_AUDIENCE; `scope` selects it explicitly, `grants` says who may ask
 * for it with that scope. A person always reaches it through `openid` too:
 * that is plain OIDC, not a reservation.
 */
export type DefaultResourceConfig = ResourceScopeConfig;

/**
 * One more resource server, declared in RESOURCE_SERVERS_JSON: a token asked
 * for with `scope` gets `aud` = `audience`.
 */
export interface ResourceServerConfig extends ResourceScopeConfig {
  audience: string;
}

/** A scope token as RFC 6749 allows it, narrowed to what reads well in a config file. */
const RESOURCE_SCOPE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;

/** Token-endpoint authentication methods accepted for a machine-to-machine client. */
export const MACHINE_AUTH_METHODS: readonly string[] = ['client_secret_basic', 'client_secret_post'];

/** Shortest client_secret accepted: `openssl rand -hex 32` gives 64 characters. */
export const MACHINE_SECRET_MIN_LENGTH = 32;

/** A CLIENTS_JSON entry is machine-to-machine when it asks for client_credentials. */
export function isMachineClient(client: { grant_types?: unknown }): boolean {
  return Array.isArray(client.grant_types) && client.grant_types.includes('client_credentials');
}

/** A CLIENTS_JSON entry is a token exchange client when it asks for the RFC 8693 grant. */
export function isExchangeClient(client: { grant_types?: unknown }): boolean {
  return Array.isArray(client.grant_types) && client.grant_types.includes(TOKEN_EXCHANGE_GRANT_TYPE);
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

  /**
   * client_id → its RFC 8693 rules, for every token exchange client. The
   * rules are kept here because oidc-provider strips unknown client metadata:
   * the entries in `clients` carry no `token_exchange`.
   */
  tokenExchange: ReadonlyMap<string, TokenExchangeRule[]>;

  /**
   * client_id → the AD groups a person must be a direct member of (any one of
   * them) to obtain tokens for that user client: its `required_ldap_groups`.
   * Kept here for the same reason as `tokenExchange`: oidc-provider strips
   * unknown client metadata, so the entries in `clients` carry no such field.
   * A client absent from the map has no per-client restriction; the global
   * LDAP_REQUIRED_GROUP applies to every client regardless.
   */
  clientRequiredGroups: ReadonlyMap<string, readonly string[]>;

  accessTokenTtl: number;
  refreshTokenTtl: number;

  /**
   * Optional audience for JWT access tokens (the resource API, phase 7).
   * Unset => opaque access tokens, which is the oidc-provider default.
   */
  apiAudience?: string;

  /**
   * Additional resource servers from RESOURCE_SERVERS_JSON, each selected by
   * its scope. Empty => the API_AUDIENCE is the only resource, as before.
   */
  resourceServers: ResourceServerConfig[];

  /**
   * DEFAULT_RESOURCE_JSON: set exactly when apiAudience is (the validator
   * refuses one without the other).
   */
  defaultResource?: DefaultResourceConfig;

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

/**
 * A machine-to-machine client: confidential, client_credentials only, no
 * redirect. Every field oidc-provider would otherwise fill from clientDefaults
 * (which describe the public desktop client client) must be stated explicitly, so a
 * missing line is a startup error and never a silently different client.
 * Returns false when the entry has to be dropped.
 */
function validateMachineClient(
  candidate: Record<string, unknown>,
  where: string,
  apiAudience: string | undefined,
  resourceScopes: readonly ResourceScopeConfig[],
  problems: string[],
): boolean {
  const before = problems.length;

  if (apiAudience === undefined) {
    problems.push(
      `${where} uses grant_types client_credentials, which requires API_AUDIENCE `
      + '(without an audience the token would be usable by no API)',
    );
  }

  const grantTypes = candidate.grant_types as unknown[];
  if (grantTypes.length !== 1) {
    problems.push(
      `${where}.grant_types must be exactly ["client_credentials"] for a machine-to-machine client`,
    );
  }

  const method = candidate.token_endpoint_auth_method;
  if (typeof method !== 'string' || !MACHINE_AUTH_METHODS.includes(method)) {
    problems.push(
      `${where}.token_endpoint_auth_method must be one of ${MACHINE_AUTH_METHODS.join(', ')} `
      + `for a machine-to-machine client, got ${JSON.stringify(method)}`,
    );
  }

  const secret = candidate.client_secret;
  if (typeof secret !== 'string' || secret.trim() === '') {
    problems.push(`${where}.client_secret is required for a machine-to-machine client`);
  } else if (secret.length < MACHINE_SECRET_MIN_LENGTH) {
    problems.push(
      `${where}.client_secret must be at least ${MACHINE_SECRET_MIN_LENGTH} characters `
      + '(generate one with: openssl rand -hex 32)',
    );
  }

  const responseTypes = candidate.response_types;
  if (!Array.isArray(responseTypes) || responseTypes.length !== 0) {
    problems.push(`${where}.response_types must be [] for a machine-to-machine client`);
  }

  const redirectUris = candidate.redirect_uris;
  if (redirectUris !== undefined && !(Array.isArray(redirectUris) && redirectUris.length === 0)) {
    problems.push(`${where}.redirect_uris must be absent or [] for a machine-to-machine client`);
  }

  // Every configured resource scope open to client_credentials. Several may
  // be listed: the client asks for one per request.
  const allowed = resourceScopes
    .filter((resource) => resource.grants.includes('client_credentials'))
    .map((resource) => resource.scope);
  const scope = candidate.scope;
  const tokens = typeof scope === 'string' ? scope.split(' ') : [];
  // Without API_AUDIENCE there are no resources at all: already reported above.
  if (
    apiAudience !== undefined
    && (
      tokens.length === 0
      || tokens.some((token) => !allowed.includes(token))
      || new Set(tokens).size !== tokens.length
    )
  ) {
    const choices = allowed.length > 0
      ? allowed.map((a) => JSON.stringify(a)).join(', ')
      : '(none: no configured resource is open to client_credentials)';
    problems.push(
      `${where}.scope must list one or more of ${choices} `
      + `(space-separated, no repeats) for a machine-to-machine client, got ${JSON.stringify(scope)}`,
    );
  }

  return problems.length === before;
}

/** A declared resource as the token exchange rules see it: found by its audience. */
interface AudienceResource extends ResourceScopeConfig {
  audience: string;
}

/** JWK members that only a private (or symmetric) key carries. */
const PRIVATE_JWK_MEMBERS: readonly string[] = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'];

/** Key types accepted in the jwks of a token exchange client: asymmetric only. */
const PUBLIC_JWK_TYPES: readonly string[] = ['RSA', 'EC', 'OKP'];

/** Fields of a token exchange rule and of its two halves. */
const RULE_FIELDS: readonly string[] = ['subject', 'issue'];
const SUBJECT_FIELDS: readonly string[] = ['token_type', 'audience', 'client_ids', 'issued_by_grants'];
const ISSUE_FIELDS: readonly string[] = ['token_type', 'audience', 'scope', 'ttl_seconds', 'refresh_token'];

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * One rule of CLIENTS_JSON[i].token_exchange. Every field is required and
 * checked against the declared resources and clients; returns undefined when
 * the rule has to be dropped.
 */
function parseTokenExchangeRule(
  entry: unknown,
  where: string,
  resources: readonly AudienceResource[],
  clientIds: ReadonlySet<string>,
  problems: string[],
): TokenExchangeRule | undefined {
  if (!isPlainObject(entry)) {
    problems.push(`${where} must be an object {"subject","issue"}`);
    return undefined;
  }
  const before = problems.length;

  const unknown = Object.keys(entry).filter((key) => !RULE_FIELDS.includes(key));
  if (unknown.length > 0) {
    problems.push(`${where} has unknown fields: ${unknown.join(', ')} (only subject and issue)`);
  }
  const subject = entry.subject;
  const issue = entry.issue;
  if (!isPlainObject(subject)) {
    problems.push(`${where}.subject is required: {${SUBJECT_FIELDS.map((f) => JSON.stringify(f)).join(',')}}`);
  }
  if (!isPlainObject(issue)) {
    problems.push(`${where}.issue is required: {${ISSUE_FIELDS.map((f) => JSON.stringify(f)).join(',')}}`);
  }
  if (!isPlainObject(subject) || !isPlainObject(issue)) return undefined;

  const unknownSubject = Object.keys(subject).filter((key) => !SUBJECT_FIELDS.includes(key));
  if (unknownSubject.length > 0) {
    problems.push(
      `${where}.subject has unknown fields: ${unknownSubject.join(', ')} (only ${SUBJECT_FIELDS.join(', ')})`,
    );
  }
  const unknownIssue = Object.keys(issue).filter((key) => !ISSUE_FIELDS.includes(key));
  if (unknownIssue.length > 0) {
    problems.push(
      `${where}.issue has unknown fields: ${unknownIssue.join(', ')} (only ${ISSUE_FIELDS.join(', ')})`,
    );
  }

  // --- subject: the token that comes in ---------------------------------------
  if (subject.token_type !== ACCESS_TOKEN_TYPE) {
    problems.push(
      `${where}.subject.token_type must be "${ACCESS_TOKEN_TYPE}" (the only subject token type accepted)`,
    );
  }

  const subjectAudience = subject.audience;
  const subjectResource = resources.find((resource) => resource.audience === subjectAudience);
  if (subjectResource === undefined) {
    problems.push(
      `${where}.subject.audience ${JSON.stringify(subjectAudience)} is not a declared resource audience `
      + '(API_AUDIENCE or RESOURCE_SERVERS_JSON)',
    );
  }

  const subjectClients = subject.client_ids;
  if (
    !Array.isArray(subjectClients)
    || subjectClients.length === 0
    || subjectClients.some((id) => typeof id !== 'string' || id.trim() === '')
  ) {
    problems.push(`${where}.subject.client_ids is required: a non-empty list of client ids declared in CLIENTS_JSON`);
  } else {
    for (const id of subjectClients as string[]) {
      if (!clientIds.has(id)) {
        problems.push(`${where}.subject.client_ids names an unknown client ${JSON.stringify(id)}`);
      }
    }
  }

  const issuedBy = subject.issued_by_grants;
  if (
    !Array.isArray(issuedBy)
    || issuedBy.length === 0
    || issuedBy.some((grant) => !(SUBJECT_GRANTS as readonly unknown[]).includes(grant))
    || new Set(issuedBy).size !== issuedBy.length
  ) {
    problems.push(
      `${where}.subject.issued_by_grants must be a non-empty list of `
      + `${SUBJECT_GRANTS.map((g) => JSON.stringify(g)).join(', ')} without repeats `
      + '(client_credentials and token-exchange tokens are never exchangeable)',
    );
  }

  // --- issue: the token that goes out -----------------------------------------
  if (issue.token_type !== ACCESS_TOKEN_TYPE) {
    problems.push(`${where}.issue.token_type must be "${ACCESS_TOKEN_TYPE}"`);
  }

  const issueAudience = issue.audience;
  const issueResource = resources.find((resource) => resource.audience === issueAudience);
  if (issueResource === undefined) {
    problems.push(
      `${where}.issue.audience ${JSON.stringify(issueAudience)} is not a declared resource audience `
      + '(API_AUDIENCE or RESOURCE_SERVERS_JSON)',
    );
  }
  if (subjectResource !== undefined && issueResource !== undefined) {
    if (subjectResource === issueResource) {
      problems.push(`${where}: subject.audience and issue.audience must differ`);
    } else if (!issueResource.grants.includes('token-exchange')) {
      problems.push(
        `${where}.issue.audience ${JSON.stringify(issueResource.audience)}: `
        + 'the resource does not list "token-exchange" in its grants',
      );
    }
  }

  const scope = issue.scope;
  const scopeTokens = typeof scope === 'string' ? scope.split(' ') : [];
  if (
    scopeTokens.length === 0
    || scopeTokens.some((token) => !RESOURCE_SCOPE_PATTERN.test(token))
    || new Set(scopeTokens).size !== scopeTokens.length
  ) {
    problems.push(`${where}.issue.scope is required: space-separated scope tokens, no repeats`);
  } else if (issueResource !== undefined) {
    if (!scopeTokens.includes(issueResource.scope)) {
      problems.push(
        `${where}.issue.scope must contain ${JSON.stringify(issueResource.scope)}, the scope that selects the resource`,
      );
    }
    // A resource without token-exchange has no exchange_scopes: already
    // reported above, not repeated per scope.
    if (issueResource.grants.includes('token-exchange')) {
      const allowed = issueResource.exchange_scopes ?? [];
      for (const token of scopeTokens) {
        if (token !== issueResource.scope && !allowed.includes(token)) {
          problems.push(
            `${where}.issue.scope lists ${JSON.stringify(token)}, which is not in the exchange_scopes `
            + `of the resource ${JSON.stringify(issueResource.audience)}`,
          );
        }
      }
    }
  }

  const ttl = issue.ttl_seconds;
  if (typeof ttl !== 'number' || !Number.isInteger(ttl) || ttl <= 0 || ttl > MAX_EXCHANGE_TTL_SECONDS) {
    problems.push(`${where}.issue.ttl_seconds must be a positive integer not above ${MAX_EXCHANGE_TTL_SECONDS}`);
  }

  if (issue.refresh_token !== false) {
    problems.push(`${where}.issue.refresh_token must be false: exchanged tokens carry no refresh token`);
  }

  if (problems.length !== before) return undefined;
  return {
    subject: {
      token_type: ACCESS_TOKEN_TYPE,
      audience: subjectAudience as string,
      client_ids: [...(subjectClients as string[])],
      issued_by_grants: [...(issuedBy as SubjectGrant[])],
    },
    issue: {
      token_type: ACCESS_TOKEN_TYPE,
      audience: issueAudience as string,
      scope: scope as string,
      ttl_seconds: ttl as number,
      refresh_token: false,
    },
    where,
  };
}

/**
 * A token exchange client (RFC 8693): confidential through private_key_jwt,
 * the exchange grant only, no redirect, no secret, and at least one rule.
 * There is no default exchange: what the client may trade for what is all in
 * its `token_exchange` rules. Returns the rules, or undefined when the entry
 * has to be dropped.
 */
function validateExchangeClient(
  candidate: Record<string, unknown>,
  where: string,
  apiAudience: string | undefined,
  resources: readonly AudienceResource[],
  clientIds: ReadonlySet<string>,
  problems: string[],
): TokenExchangeRule[] | undefined {
  const before = problems.length;

  if (apiAudience === undefined) {
    problems.push(`${where} uses grant_types ${TOKEN_EXCHANGE_GRANT_TYPE}, which requires API_AUDIENCE`);
  }

  const grantTypes = candidate.grant_types as unknown[];
  if (grantTypes.length !== 1 || grantTypes[0] !== TOKEN_EXCHANGE_GRANT_TYPE) {
    problems.push(
      `${where}.grant_types must be exactly ["${TOKEN_EXCHANGE_GRANT_TYPE}"] for a token exchange client`,
    );
  }

  const method = candidate.token_endpoint_auth_method;
  if (typeof method !== 'string' || !EXCHANGE_AUTH_METHODS.includes(method)) {
    problems.push(
      `${where}.token_endpoint_auth_method must be ${EXCHANGE_AUTH_METHODS.join(', ')} `
      + `for a token exchange client, got ${JSON.stringify(method)}`,
    );
  }

  const jwks = candidate.jwks;
  const keys = isPlainObject(jwks) ? jwks.keys : undefined;
  if (
    Array.isArray(keys)
    && keys.some((key) => isPlainObject(key) && PRIVATE_JWK_MEMBERS.some((member) => member in key))
  ) {
    problems.push(`${where}.jwks must hold public keys only: the private key stays with the client`);
  } else if (
    !Array.isArray(keys)
    || keys.length === 0
    || keys.some((key) => !isPlainObject(key) || !PUBLIC_JWK_TYPES.includes(key.kty as string))
  ) {
    problems.push(`${where}.jwks is required for a token exchange client: {"keys":[<public JWK>]}`);
  }

  if (candidate.client_secret !== undefined) {
    problems.push(`${where}.client_secret is not allowed for a token exchange client`);
  }

  const responseTypes = candidate.response_types;
  if (!Array.isArray(responseTypes) || responseTypes.length !== 0) {
    problems.push(`${where}.response_types must be [] for a token exchange client`);
  }

  const redirectUris = candidate.redirect_uris;
  if (redirectUris !== undefined && !(Array.isArray(redirectUris) && redirectUris.length === 0)) {
    problems.push(`${where}.redirect_uris must be absent or [] for a token exchange client`);
  }

  const entries = candidate.token_exchange;
  const rules: TokenExchangeRule[] = [];
  if (!Array.isArray(entries) || entries.length === 0) {
    problems.push(`${where} has the token exchange grant but no token_exchange rules: there is no default exchange`);
  } else {
    entries.forEach((entry, index) => {
      const rule = parseTokenExchangeRule(entry, `${where}.token_exchange[${index}]`, resources, clientIds, problems);
      if (rule !== undefined) rules.push(rule);
    });
    // A request must match exactly one rule: two rules for the same pair of
    // audiences would make that impossible, so it is refused here already.
    const seen = new Set<string>();
    for (const rule of rules) {
      const pair = JSON.stringify([rule.subject.audience, rule.issue.audience]);
      if (seen.has(pair)) {
        problems.push(
          `${where}.token_exchange has two rules for subject.audience ${JSON.stringify(rule.subject.audience)} `
          + `and issue.audience ${JSON.stringify(rule.issue.audience)}: a request must match exactly one`,
        );
      }
      seen.add(pair);
    }
  }

  return problems.length === before ? rules : undefined;
}

/**
 * The `scope` and `grants` of a resource entry, shared by DEFAULT_RESOURCE_JSON
 * and RESOURCE_SERVERS_JSON. Pushes a problem for each defect; the caller
 * keeps the entry only when none was added.
 */
function parseScopeAndGrants(
  candidate: Record<string, unknown>,
  where: string,
  takenScopes: ReadonlySet<string>,
  problems: string[],
): ResourceScopeConfig {
  const scope = typeof candidate.scope === 'string' ? candidate.scope.trim() : '';
  if (scope === '') {
    problems.push(`${where}.scope is required`);
  } else if (!RESOURCE_SCOPE_PATTERN.test(scope)) {
    problems.push(
      `${where}.scope must be a single scope token (letters, digits, "_", ".", "-"), got ${JSON.stringify(candidate.scope)}`,
    );
  } else if (OIDC_SCOPES.includes(scope)) {
    problems.push(
      `${where}.scope ${JSON.stringify(scope)} is reserved (${OIDC_SCOPES.join(', ')} belong to OpenID Connect and cannot name a resource)`,
    );
  } else if (takenScopes.has(scope)) {
    problems.push(
      `${where}.scope ${JSON.stringify(scope)} is already used by another resource (DEFAULT_RESOURCE_JSON or RESOURCE_SERVERS_JSON)`,
    );
  }

  const grants = candidate.grants;
  const grantsValid = Array.isArray(grants)
    && grants.length > 0
    && grants.every((grant) => (RESOURCE_GRANTS as readonly unknown[]).includes(grant))
    && new Set(grants).size === grants.length;
  if (!grantsValid) {
    problems.push(
      `${where}.grants is required: a non-empty list of ${RESOURCE_GRANTS.map((g) => JSON.stringify(g)).join(', ')} `
      + `without repeats, got ${JSON.stringify(grants)}`,
    );
  }

  // Required with the token-exchange grant, refused without it: which scopes
  // a delegated token may carry is a decision, never a built-in default.
  // Not judged against a grants list that is already wrong.
  const exchangeScopes = candidate.exchange_scopes;
  const exchangeable = grantsValid && (grants as unknown[]).includes('token-exchange');
  let parsedExchangeScopes: string[] | undefined;
  if (!grantsValid) {
    // Reported above.
  } else if (!exchangeable) {
    if (exchangeScopes !== undefined) {
      problems.push(`${where}.exchange_scopes is only allowed when grants lists "token-exchange"`);
    }
  } else if (!Array.isArray(exchangeScopes) || exchangeScopes.length === 0) {
    problems.push(
      `${where}.exchange_scopes is required when grants lists "token-exchange": `
      + `the scopes an exchanged token may carry besides ${JSON.stringify(scope)}`,
    );
  } else if (
    exchangeScopes.some((token) => typeof token !== 'string' || !RESOURCE_SCOPE_PATTERN.test(token))
    || new Set(exchangeScopes).size !== exchangeScopes.length
  ) {
    problems.push(
      `${where}.exchange_scopes must be a list of scope tokens (letters, digits, "_", ".", "-") `
      + `without repeats, got ${JSON.stringify(exchangeScopes)}`,
    );
  } else if (exchangeScopes.includes(scope)) {
    problems.push(
      `${where}.exchange_scopes must not list ${JSON.stringify(scope)}: `
      + 'the scope that selects the resource is always carried',
    );
  } else if (exchangeScopes.some((token) => OIDC_SCOPES.includes(token as string))) {
    problems.push(
      `${where}.exchange_scopes must not list ${OIDC_SCOPES.join(', ')}: `
      + 'they belong to OpenID Connect, not to an exchanged token',
    );
  } else {
    parsedExchangeScopes = [...(exchangeScopes as string[])];
  }

  return {
    scope,
    grants: Array.isArray(grants) ? [...(grants as ResourceGrant[])] : [],
    ...(parsedExchangeScopes === undefined ? {} : { exchange_scopes: parsedExchangeScopes }),
  };
}

/**
 * DEFAULT_RESOURCE_JSON: `{"scope":"…","grants":[…]}`, the API_AUDIENCE
 * resource. Required with API_AUDIENCE and refused without it: who may ask
 * for that resource by its scope is a decision, never a built-in default.
 */
function parseDefaultResource(
  env: Env,
  problems: string[],
  apiAudience: string | undefined,
): DefaultResourceConfig | undefined {
  const name = 'DEFAULT_RESOURCE_JSON';
  const parsed = parseJson(env, name, problems);
  if (apiAudience === undefined) {
    if (parsed !== undefined) {
      problems.push(`${name} requires API_AUDIENCE (it describes the API_AUDIENCE resource)`);
    }
    return undefined;
  }
  if (parsed === undefined) {
    if (!problems.some((p) => p.startsWith(name))) {
      problems.push(
        `${name} is required when API_AUDIENCE is set: {"scope":"<scope that selects the API_AUDIENCE resource>",`
        + `"grants":[<${RESOURCE_GRANTS.map((g) => JSON.stringify(g)).join(' and/or ')} that may ask for it>]}`,
      );
    }
    return undefined;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    problems.push(`${name} must be a JSON object {"scope","grants"}`);
    return undefined;
  }
  const candidate = parsed as Record<string, unknown>;
  const before = problems.length;
  const unknown = Object.keys(candidate).filter(
    (key) => key !== 'scope' && key !== 'grants' && key !== 'exchange_scopes',
  );
  if (unknown.length > 0) {
    problems.push(
      `${name} has unknown fields: ${unknown.join(', ')} `
      + '(only scope, grants and exchange_scopes; the audience is API_AUDIENCE)',
    );
  }
  const resource = parseScopeAndGrants(candidate, name, new Set(), problems);
  return problems.length === before ? resource : undefined;
}

/**
 * RESOURCE_SERVERS_JSON: `[{"scope","audience","grants"}, ...]`. Absent =>
 * none, and the API_AUDIENCE is the only resource exactly as before. Every
 * entry must be complete: there is no default scope or audience.
 */
function parseResourceServers(
  env: Env,
  problems: string[],
  apiAudience: string | undefined,
  defaultResource: DefaultResourceConfig | undefined,
): ResourceServerConfig[] {
  const name = 'RESOURCE_SERVERS_JSON';
  const parsed = parseJson(env, name, problems);
  if (parsed === undefined) return [];
  if (!Array.isArray(parsed) || parsed.length === 0) {
    problems.push(`${name} must be a non-empty JSON array of {"scope","audience","grants"} objects`);
    return [];
  }
  if (apiAudience === undefined) {
    problems.push(
      `${name} requires API_AUDIENCE (the default resource for a request that names none of these scopes)`,
    );
  }

  const servers: ResourceServerConfig[] = [];
  const scopes = new Set<string>(defaultResource === undefined ? [] : [defaultResource.scope]);
  const audiences = new Set<string>(apiAudience === undefined ? [] : [apiAudience]);
  parsed.forEach((entry, index) => {
    const where = `${name}[${index}]`;
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      problems.push(`${where} must be an object`);
      return;
    }
    const candidate = entry as Record<string, unknown>;
    const before = problems.length;

    const unknown = Object.keys(candidate).filter(
      (key) => key !== 'scope' && key !== 'audience' && key !== 'grants' && key !== 'exchange_scopes',
    );
    if (unknown.length > 0) {
      problems.push(
        `${where} has unknown fields: ${unknown.join(', ')} (only scope, audience, grants and exchange_scopes)`,
      );
    }

    const { scope, grants, exchange_scopes } = parseScopeAndGrants(candidate, where, scopes, problems);

    const audience = typeof candidate.audience === 'string' ? candidate.audience.trim() : '';
    if (audience === '') {
      problems.push(`${where}.audience is required`);
    } else if (audiences.has(audience)) {
      problems.push(
        `${where}.audience ${JSON.stringify(audience)} is already used `
        + `(by another resource server or by API_AUDIENCE): one audience, one resource server`,
      );
    }

    if (problems.length === before) {
      scopes.add(scope);
      audiences.add(audience);
      servers.push({ scope, audience, grants, ...(exchange_scopes === undefined ? {} : { exchange_scopes }) });
    }
  });
  return servers;
}

interface ParsedClients {
  clients: ClientConfig[];
  tokenExchange: Map<string, TokenExchangeRule[]>;
  clientRequiredGroups: Map<string, readonly string[]>;
}

/** The CLIENTS_JSON field that restricts a user client to members of some AD groups. */
export const REQUIRED_LDAP_GROUPS_FIELD = 'required_ldap_groups';

/**
 * Identity providers able to read a person's AD group membership. Only spnego
 * talks to a directory; dev-stub and database have no notion of an AD group,
 * so a client restricted to groups would be either unreachable or — far worse
 * — silently unrestricted under them. Neither is acceptable: refused at start.
 */
const GROUP_AWARE_IDENTITY_PROVIDERS: readonly IdentityProviderName[] = ['spnego'];

/**
 * `required_ldap_groups` of a user client: a non-empty array of group DNs,
 * each a non-empty string once trimmed. Returns the trimmed DNs, or undefined
 * after pushing the problem.
 */
function parseRequiredLdapGroups(
  value: unknown,
  where: string,
  problems: string[],
): readonly string[] | undefined {
  const field = `${where}.${REQUIRED_LDAP_GROUPS_FIELD}`;
  if (
    !Array.isArray(value)
    || value.length === 0
    || value.some((group) => typeof group !== 'string' || group.trim() === '')
  ) {
    problems.push(
      `${field} must be a non-empty array of group DNs (non-empty strings), got ${JSON.stringify(value)}`,
    );
    return undefined;
  }
  return value.map((group) => (group as string).trim());
}

function parseClients(
  env: Env,
  problems: string[],
  apiAudience: string | undefined,
  resources: readonly AudienceResource[],
  identityProvider: IdentityProviderName,
): ParsedClients {
  const resourceScopes: readonly ResourceScopeConfig[] = resources;
  const tokenExchange = new Map<string, TokenExchangeRule[]>();
  const clientRequiredGroups = new Map<string, readonly string[]>();
  const parsed = parseJson(env, 'CLIENTS_JSON', problems);
  if (parsed === undefined) {
    if (!problems.some((p) => p.startsWith('CLIENTS_JSON'))) {
      problems.push('CLIENTS_JSON is required (JSON array of client registrations)');
    }
    return { clients: [], tokenExchange, clientRequiredGroups };
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    problems.push('CLIENTS_JSON must be a non-empty JSON array');
    return { clients: [], tokenExchange, clientRequiredGroups };
  }

  // Every declared client id, for subject.client_ids of the exchange rules.
  const clientIds = new Set<string>(
    parsed
      .filter((entry) => isPlainObject(entry) && typeof entry.client_id === 'string' && entry.client_id.trim() !== '')
      .map((entry) => (entry as { client_id: string }).client_id),
  );

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
    if (candidate.token_exchange !== undefined && !isExchangeClient(candidate)) {
      problems.push(`${where}.token_exchange requires grant_types ["${TOKEN_EXCHANGE_GRANT_TYPE}"]`);
      return;
    }
    // A machine (client_credentials) or a service (token exchange) has no
    // person behind its own login: a group restriction there would restrict
    // nobody, which is a misreading of the configuration, never a choice.
    if (
      candidate[REQUIRED_LDAP_GROUPS_FIELD] !== undefined
      && (isMachineClient(candidate) || isExchangeClient(candidate))
    ) {
      problems.push(
        `${where}.${REQUIRED_LDAP_GROUPS_FIELD} is only allowed on a user client (redirect_uris): `
        + 'a machine-to-machine or token exchange client has no person to check',
      );
      return;
    }
    if (isMachineClient(candidate)) {
      if (validateMachineClient(candidate, where, apiAudience, resourceScopes, problems)) {
        clients.push(candidate as unknown as ClientConfig);
      }
      return;
    }
    if (isExchangeClient(candidate)) {
      const rules = validateExchangeClient(candidate, where, apiAudience, resources, clientIds, problems);
      if (rules !== undefined) {
        // oidc-provider would strip it anyway; the rules live in Config.tokenExchange.
        const { token_exchange: _rules, ...metadata } = candidate;
        clients.push(metadata as unknown as ClientConfig);
        tokenExchange.set(candidate.client_id as string, rules);
      }
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
    // Optional for a user client; when present it is the allow-list
    // oidc-provider enforces, and the only way to reach a resource server.
    if (candidate.scope !== undefined) {
      const tokens = typeof candidate.scope === 'string' ? candidate.scope.split(' ') : [];
      // Scopes a person can never obtain: every resource not open to
      // authorization_code.
      const machineOnly = resourceScopes
        .filter((resource) => !resource.grants.includes('authorization_code'))
        .map((resource) => resource.scope);
      const reserved = tokens.filter((token) => machineOnly.includes(token));
      if (reserved.length > 0) {
        problems.push(
          `${where}.scope lists ${reserved.map((r) => JSON.stringify(r)).join(', ')}, `
          + 'not open to authorization_code: a user client can never obtain it',
        );
        return;
      }
      const allowed = [
        ...OIDC_SCOPES,
        ...resourceScopes
          .filter((resource) => resource.grants.includes('authorization_code'))
          .map((resource) => resource.scope),
      ];
      if (tokens.length === 0 || tokens.some((token) => !allowed.includes(token))) {
        problems.push(
          `${where}.scope must list scopes among ${allowed.map((a) => JSON.stringify(a)).join(', ')} `
          + `(space-separated), got ${JSON.stringify(candidate.scope)}`,
        );
        return;
      }
    }
    // --- per-client LDAP group restriction (1.3.0) -------------------------
    if (candidate[REQUIRED_LDAP_GROUPS_FIELD] !== undefined) {
      const groups = parseRequiredLdapGroups(candidate[REQUIRED_LDAP_GROUPS_FIELD], where, problems);
      if (groups === undefined) return;
      if (!GROUP_AWARE_IDENTITY_PROVIDERS.includes(identityProvider)) {
        problems.push(
          `${where}.${REQUIRED_LDAP_GROUPS_FIELD} requires IDENTITY_PROVIDER=spnego: `
          + `with ${identityProvider} no AD group membership can be read, and the restriction `
          + 'would otherwise be silently ignored',
        );
        return;
      }
      // oidc-provider would strip it anyway; the groups live in
      // Config.clientRequiredGroups, read by the client_ldap_group gate.
      const { [REQUIRED_LDAP_GROUPS_FIELD]: _groups, ...metadata } = candidate;
      clients.push(metadata as unknown as ClientConfig);
      clientRequiredGroups.set(candidate.client_id as string, groups);
      return;
    }
    // --- end per-client LDAP group restriction -----------------------------
    clients.push(candidate as unknown as ClientConfig);
  });
  return { clients, tokenExchange, clientRequiredGroups };
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

  const defaultResource = parseDefaultResource(env, problems, trimmed(env, 'API_AUDIENCE'));
  const resourceServers = parseResourceServers(
    env,
    problems,
    trimmed(env, 'API_AUDIENCE'),
    defaultResource,
  );
  const apiAudience = trimmed(env, 'API_AUDIENCE');
  // Resources first, clients after: a client is checked against what was declared.
  const resources: AudienceResource[] = [
    ...(defaultResource === undefined || apiAudience === undefined
      ? []
      : [{ ...defaultResource, audience: apiAudience }]),
    ...resourceServers,
  ];
  // Parsed in its place inside the literal below, so the order of the
  // problems in a ConfigError stays the order of the parameters.
  let parsedClients: ParsedClients | undefined;

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

    clients: (parsedClients = parseClients(env, problems, apiAudience, resources, identityProvider)).clients,
    tokenExchange: parsedClients.tokenExchange,
    clientRequiredGroups: parsedClients.clientRequiredGroups,

    accessTokenTtl: optionalInteger(env, 'ACCESS_TOKEN_TTL', 3600, problems),
    refreshTokenTtl: optionalInteger(env, 'REFRESH_TOKEN_TTL', 43200, problems),

    apiAudience: trimmed(env, 'API_AUDIENCE'),
    resourceServers,
    ...(defaultResource === undefined ? {} : { defaultResource }),

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
