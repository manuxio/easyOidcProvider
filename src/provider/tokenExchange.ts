/**
 * The OAuth 2.0 Token Exchange grant (RFC 8693) for the agent-service.
 *
 * oidc-provider 9.12 has no such grant: this is the handler registered with
 * `provider.registerGrantType`. By the time it runs oidc-provider has already
 * authenticated the client (private_key_jwt, with replay detection), checked
 * that the client has the grant, refused repeated parameters and dropped every
 * parameter not declared for the grant (which is why `resource` and the actor
 * parameters ARE declared: so they arrive here and are refused, never ignored).
 *
 * Order of the checks (contract, LLM-IN-CRM.md «Fase 0», point 4):
 *   1. parameters: subject_token, the two token types, no actor token;
 *   2. the rule: `resource` refused, audience and scope within exactly one rule;
 *   3. the subject token: signature, issuer, expiry, audience of the rule, no
 *      `act`, a record in the subject token registry that matches it, a client
 *      among `subject.client_ids`, a grant type within `issued_by_grants`,
 *      and the grant that issued it still alive;
 *   4. the account: the same findAccount as everywhere, gates included;
 *   5. issuance of the delegated token B, without a refresh token.
 *
 * Every refusal issues nothing and writes one `token exchange refused` line
 * with a stable reason; the response body carries a generic description.
 */
import { createLocalJWKSet, errors as joseErrors, jwtVerify, type JSONWebKeySet, type JWK, type JWTPayload } from 'jose';
import { errors, type Account, type KoaContextWithOIDC } from 'oidc-provider';

import {
  ACCESS_TOKEN_TYPE,
  type ResourceGrant,
  type TokenExchangeRule,
} from '../config.js';
import type { Logger } from '../logger.js';
import { TemporarilyUnavailable } from './errors.js';
import type { SubjectTokenRegistry } from './subjectTokens.js';

/** Every parameter the grant accepts, declared so that none is silently dropped (token.js:31-41). */
export const TOKEN_EXCHANGE_PARAMETERS: readonly string[] = [
  'subject_token',
  'subject_token_type',
  'requested_token_type',
  'audience',
  'resource',
  'scope',
  'actor_token',
  'actor_token_type',
];

/** The `gty` of a delegated token: never an accepted subject grant (SUBJECT_GRANTS). */
export const TOKEN_EXCHANGE_GTY = 'token-exchange';

/** The resource a rule issues for, as the provider knows it. */
export interface ExchangeResource {
  indicator: string;
  audience: string;
  /** The scope that selects the resource: always in the issued token. */
  scope: string;
  grants: readonly ResourceGrant[];
  /** The scopes an exchanged token may carry besides `scope`. */
  exchangeScopes: readonly string[];
}

/** What the handler hands to grant.success through ctx.oidc.entity('SubjectToken', …). */
export interface ExchangedSubject {
  jti: string;
  sub: string;
  clientId: string;
}

export interface TokenExchangeDeps {
  issuerUrl: string;
  rules: ReadonlyMap<string, readonly TokenExchangeRule[]>;
  resourceByAudience(audience: string): ExchangeResource | undefined;
  /** The issuer's signing keys; the private members are dropped here. */
  signingJwks: { keys: JWK[] };
  registry: SubjectTokenRegistry;
  /**
   * The provider's own findAccount, gates included. It is called WITHOUT a
   * token, so no grantId reaches it and a refusal never revokes the person's
   * chain (plan D6).
   *
   * `subjectClientId` (1.3.0) is the client the subject token was issued to,
   * so the gates also apply that client's `required_ldap_groups` to the trade.
   */
  findAccount(ctx: KoaContextWithOIDC, sub: string, subjectClientId: string): Promise<Account | undefined>;
  logger: Logger;
}

/** RSA, EC and OKP private members: none of them may reach the verification key set. */
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const;

export function publicJwksOf(jwks: { keys: JWK[] }): JSONWebKeySet {
  return {
    keys: jwks.keys.map((key) => {
      const copy: Record<string, unknown> = { ...key };
      for (const member of PRIVATE_JWK_MEMBERS) delete copy[member];
      return copy as JWK;
    }),
  };
}

/** A refusal: the error the client sees, and the reason the log keeps. */
class Refusal extends Error {
  constructor(
    readonly error: Error,
    readonly reason: string,
  ) {
    super(reason);
  }
}

function invalidRequest(description: string, reason: string): Refusal {
  return new Refusal(new errors.InvalidRequest(description), reason);
}

function invalidTarget(description: string, reason: string): Refusal {
  return new Refusal(new errors.InvalidTarget(description), reason);
}

/** invalid_grant with a generic description; the precise reason stays in error_detail and the log. */
function invalidGrant(description: string, reason: string): Refusal {
  const error = new errors.InvalidGrant(reason);
  error.error_description = description;
  return new Refusal(error, reason);
}

function unavailable(reason: string): Refusal {
  return new Refusal(new TemporarilyUnavailable('the subject token could not be verified; try again later'), reason);
}

function stringParam(ctx: KoaContextWithOIDC, name: string): string | undefined {
  const value = ctx.oidc.params?.[name];
  return typeof value === 'string' && value !== '' ? value : undefined;
}

export function createTokenExchangeHandler(deps: TokenExchangeDeps): (ctx: KoaContextWithOIDC) => Promise<void> {
  const log = deps.logger.child({ component: 'token-exchange' });
  const keySet = createLocalJWKSet(publicJwksOf(deps.signingJwks));

  return async function tokenExchangeHandler(ctx) {
    const client = ctx.oidc.client!;
    const state: { rule?: TokenExchangeRule; subjectJti?: string } = {};

    try {
      await exchange(ctx, state);
    } catch (error) {
      if (!(error instanceof Refusal)) throw error;
      log.warn(
        {
          clientId: client.clientId,
          ...(state.rule ? { rule: state.rule.where } : {}),
          reason: error.reason,
          ...(state.subjectJti ? { subjectJti: state.subjectJti } : {}),
        },
        'token exchange refused',
      );
      throw error.error;
    }
  };

  async function exchange(
    ctx: KoaContextWithOIDC,
    state: { rule?: TokenExchangeRule; subjectJti?: string },
  ): Promise<void> {
    const client = ctx.oidc.client!;
    const { provider } = ctx.oidc;

    // --- 1. parameters ------------------------------------------------------
    const subjectToken = stringParam(ctx, 'subject_token');
    if (subjectToken === undefined) {
      throw invalidRequest('subject_token is required', 'parameter_missing');
    }
    const subjectTokenType = stringParam(ctx, 'subject_token_type');
    if (subjectTokenType === undefined) {
      throw invalidRequest('subject_token_type is required', 'parameter_missing');
    }
    if (subjectTokenType !== ACCESS_TOKEN_TYPE) {
      throw invalidRequest(`subject_token_type must be ${ACCESS_TOKEN_TYPE}`, 'token_type');
    }
    const requestedTokenType = stringParam(ctx, 'requested_token_type');
    if (requestedTokenType === undefined) {
      throw invalidRequest('requested_token_type is required', 'parameter_missing');
    }
    if (requestedTokenType !== ACCESS_TOKEN_TYPE) {
      throw invalidRequest(`requested_token_type must be ${ACCESS_TOKEN_TYPE}`, 'token_type');
    }
    if (ctx.oidc.params?.actor_token !== undefined || ctx.oidc.params?.actor_token_type !== undefined) {
      throw invalidRequest('actor tokens are not supported', 'actor_token');
    }

    // --- 2. the rule --------------------------------------------------------
    if (ctx.oidc.params?.resource !== undefined) {
      throw invalidTarget('resource is not supported by this grant: use audience', 'resource_parameter');
    }
    const audience = stringParam(ctx, 'audience');
    if (audience === undefined) {
      throw invalidTarget('audience is required', 'no_rule_audience');
    }
    const ofClient = deps.rules.get(client.clientId) ?? [];
    const forAudience = ofClient.filter(
      (rule) =>
        rule.subject.token_type === subjectTokenType
        && rule.issue.token_type === requestedTokenType
        && rule.issue.audience === audience,
    );
    if (forAudience.length === 0) {
      throw invalidTarget(`audience ${audience} is not allowed for this client`, 'no_rule_audience');
    }
    const rawScope = stringParam(ctx, 'scope');
    if (rawScope === undefined) {
      throw invalidTarget('scope is required', 'scope_missing');
    }
    const requested = [...new Set(rawScope.split(' ').filter((token) => token !== ''))];
    const candidates = forAudience.filter((rule) => {
      const allowed = rule.issue.scope.split(' ');
      return requested.every((scope) => allowed.includes(scope));
    });
    if (candidates.length === 0) {
      const allowed = new Set(forAudience.flatMap((rule) => rule.issue.scope.split(' ')));
      const beyond = requested.filter((scope) => !allowed.has(scope));
      throw invalidTarget(
        `scope ${(beyond.length > 0 ? beyond : requested).join(' ')} exceeds the token exchange rule`,
        'no_rule_scope',
      );
    }

    // --- 3. the subject token -----------------------------------------------
    // The candidates share the issued audience, and the startup check makes
    // (subject.audience, issue.audience) unique per client: the subject's own
    // audience picks at most one of them.
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(subjectToken, keySet, {
        algorithms: ['RS256'],
        typ: 'at+jwt',
        issuer: deps.issuerUrl,
        audience: candidates.map((rule) => rule.subject.audience),
        requiredClaims: ['exp', 'jti', 'sub', 'client_id'],
        clockTolerance: 0,
      }));
    } catch (error) {
      if (error instanceof joseErrors.JWTExpired) {
        throw invalidGrant('subject_token is expired', 'subject_expired');
      }
      if (error instanceof joseErrors.JWTClaimValidationFailed && error.claim === 'aud') {
        throw invalidGrant('subject_token audience is not accepted by this rule', 'subject_audience');
      }
      throw invalidGrant('subject_token is invalid', 'subject_invalid');
    }

    const { jti, sub, aud } = payload;
    const subjectClientId = payload.client_id;
    if (
      typeof jti !== 'string'
      || typeof sub !== 'string'
      || typeof subjectClientId !== 'string'
      || typeof aud !== 'string'
    ) {
      throw invalidGrant('subject_token is invalid', 'subject_invalid');
    }
    state.subjectJti = jti;

    const matching = candidates.filter((rule) => rule.subject.audience === aud);
    if (matching.length !== 1) {
      // Zero cannot happen after the audience check; two cannot pass the
      // startup check. Either way the request does not match exactly one rule.
      throw invalidTarget('the request does not match exactly one token exchange rule', 'rule_ambiguous');
    }
    const rule = matching[0]!;
    state.rule = rule;

    if (payload.act !== undefined) {
      throw invalidGrant('a delegated token cannot be exchanged again', 'subject_delegated');
    }

    let record;
    try {
      record = await deps.registry.find(jti);
    } catch (error) {
      log.error(
        { clientId: client.clientId, rule: rule.where, subjectJti: jti, err: describe(error) },
        'token exchange: the subject token registry could not be read (fail closed)',
      );
      throw unavailable('registry_unavailable');
    }
    if (record === undefined) {
      throw invalidGrant('subject_token was not issued to a person', 'subject_not_person');
    }
    if (record.accountId !== sub || record.clientId !== subjectClientId || record.aud !== aud) {
      throw invalidGrant('subject_token is invalid', 'subject_record_mismatch');
    }
    if (!rule.subject.client_ids.includes(record.clientId)) {
      throw invalidGrant('subject_token was obtained by a client this rule does not accept', 'subject_client');
    }
    const grantTypes = record.gty.split(' ').filter((word) => word !== '');
    const allowedGrants: readonly string[] = rule.subject.issued_by_grants;
    if (grantTypes.length === 0 || grantTypes.some((word) => !allowedGrants.includes(word))) {
      throw invalidGrant('subject_token was issued by a grant this rule does not accept', 'subject_grant_not_allowed');
    }

    let grant;
    try {
      grant = await provider.Grant.find(record.grantId);
    } catch (error) {
      log.error(
        { clientId: client.clientId, rule: rule.where, subjectJti: jti, err: describe(error) },
        'token exchange: the grant of the subject token could not be read (fail closed)',
      );
      throw unavailable('grant_unavailable');
    }
    // A Grant expired or destroyed (logout, revocation of the refresh token,
    // a gate refusing a refresh) is gone: the subject is revoked with it.
    if (!grant || grant.isExpired || grant.accountId !== sub || grant.clientId !== subjectClientId) {
      throw invalidGrant('subject_token has been revoked', 'subject_revoked');
    }

    // --- 4. the account -----------------------------------------------------
    let account: Account | undefined;
    try {
      account = await deps.findAccount(ctx, sub, record.clientId);
    } catch (error) {
      const code = (error as { error?: string }).error;
      if (code === 'invalid_grant') {
        const reason = (error as { error_detail?: string }).error_detail ?? 'account_refused';
        throw new Refusal(error as Error, reason);
      }
      if (code === 'temporarily_unavailable') {
        throw new Refusal(error as Error, 'account_unavailable');
      }
      throw error;
    }
    if (!account) {
      throw invalidGrant('the account of the subject_token is not available', 'account_not_found');
    }

    // --- 5. issuance --------------------------------------------------------
    const resource = deps.resourceByAudience(rule.issue.audience);
    if (!resource || !resource.grants.includes('token-exchange')) {
      // The startup check already refuses such a rule: second lock.
      throw invalidTarget(`audience ${audience} does not accept exchanged tokens`, 'resource_not_exchangeable');
    }
    const issueScopes = rule.issue.scope.split(' ');
    if (issueScopes.some((scope) => scope !== resource.scope && !resource.exchangeScopes.includes(scope))) {
      throw invalidTarget(`audience ${audience} does not accept the scope of this rule`, 'resource_not_exchangeable');
    }
    // D5: the requested scopes plus the selector, in the order of issue.scope.
    const wanted = new Set([...requested, resource.scope]);
    const scope = issueScopes.filter((token) => wanted.has(token)).join(' ');
    const ttl = rule.issue.ttl_seconds;

    // No grantId: B belongs to no grant of the agent-service, and a JWT is
    // never stored anyway. The constructor type of @types/oidc-provider
    // demands one, hence the cast; base_token.js accepts its absence.
    const at = new provider.AccessToken({
      accountId: account.accountId,
      client,
      gty: TOKEN_EXCHANGE_GTY,
      expiresIn: ttl,
      resourceServer: new provider.ResourceServer(resource.indicator, {
        audience: resource.audience,
        scope,
        accessTokenFormat: 'jwt',
        accessTokenTTL: ttl,
        jwt: { sign: { alg: 'RS256' } },
      }),
    } as unknown as ConstructorParameters<typeof provider.AccessToken>[0]);
    at.scope = scope;

    const subject: ExchangedSubject = { jti, sub, clientId: record.clientId };
    ctx.oidc.entity('TokenExchangeRule', rule);
    ctx.oidc.entity('SubjectToken', subject);
    ctx.oidc.entity('AccessToken', at);
    const value = await at.save();

    // RFC 8693 §2.2.1, built here: buildTokenResponse is internal to oidc-provider.
    ctx.body = {
      access_token: value,
      issued_token_type: ACCESS_TOKEN_TYPE,
      token_type: 'Bearer',
      expires_in: ttl,
      scope,
    };
  }
}

function describe(error: unknown): unknown {
  return error instanceof Error ? { name: error.name, message: error.message } : error;
}
