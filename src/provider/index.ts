/**
 * oidc-provider wiring.
 *
 * Everything policy-shaped lives here: the client contract (public client, PKCE
 * S256, loopback redirect URIs), the token claims, the machine-to-machine
 * client_credentials grant, the RFC 8693 token exchange for the agent-service,
 * and — the point of the whole design — the account gates re-run on every
 * refresh grant and on every token exchange.
 */
import Provider, {
  errors,
  type Account,
  type AdapterFactory,
  type Configuration,
  type KoaContextWithOIDC,
} from 'oidc-provider';

import {
  EXTRA_CLAIMS_REASONS,
  ExtraClaimsUserNotFound,
  type ExtraClaims,
  type ExtraClaimsSource,
} from '../claims/index.js';
import { TOKEN_EXCHANGE_GRANT_TYPE, type Config, type ResourceGrant } from '../config.js';

/**
 * Internal resource indicator of a RESOURCE_SERVERS_JSON entry. oidc-provider
 * requires indicators to be absolute URIs, while the audience the APIs check is
 * a short string: the JWT `aud` comes from getResourceServerInfo's `audience`,
 * never from the indicator, so the two can differ.
 */
export function resourceIndicatorFor(scope: string): string {
  return `urn:easyoidc:${scope}`;
}

import {
  CLIENT_GROUP_NOT_ALLOWED,
  runAccountGates,
  type AccountGate,
  type GateStage,
} from '../gates/index.js';
import type { Logger } from '../logger.js';
import type { ServerSecrets } from '../secrets.js';
import { renderErrorPage } from '../views/error.js';
import { TemporarilyUnavailable } from './errors.js';
import { createSubjectTokenRegistry, type SubjectTokenRegistry } from './subjectTokens.js';
import {
  createTokenExchangeHandler,
  TOKEN_EXCHANGE_PARAMETERS,
  type ExchangedSubject,
  type ExchangeResource,
} from './tokenExchange.js';

export interface CreateProviderOptions {
  config: Config;
  secrets: ServerSecrets;
  gates: readonly AccountGate[];
  logger: Logger;
  /** Absent => oidc-provider's own in-memory adapter (development only). */
  adapterFactory?: AdapterFactory;
  /**
   * Phase 4-ter: absent unless CLAIMS_SQL_ENABLED=true. Its `claimNames` are
   * declared in the `claims` configuration below, which is what lets them
   * survive oidc-provider's id-token claim mask.
   */
  extraClaims?: ExtraClaimsSource;
}

/**
 * Revokes the whole grant chain: access tokens, refresh tokens, codes and the
 * grant itself. Same effect as the provider's internal `revoke` helper, built
 * only from the public model API so an internal move does not break us.
 */
async function revokeGrantChain(provider: Provider, grantId: string): Promise<void> {
  await Promise.all([
    provider.AccessToken.revokeByGrantId(grantId),
    provider.RefreshToken.revokeByGrantId(grantId),
    provider.AuthorizationCode.revokeByGrantId(grantId),
    provider.Grant.adapter.destroy(grantId),
  ]);
}

/**
 * Which gated stage of the flow a findAccount call belongs to: a refresh, a
 * token exchange, or neither (the code exchange and userinfo, where the login
 * has just run the gates or no token is minted for a new holder).
 *
 * 1.3.0 — why the code exchange (grant_type=authorization_code) still needs no
 * gate, `required_ldap_groups` included: a code is minted only by the
 * authorization endpoint, in the same request that just ran either the login
 * interaction (gates with this clientId, src/routes/interaction.ts) or
 * loadExistingGrant below (gates with this clientId on SSO reuse). The code
 * lives 60 seconds and is single-use, so a second check would re-ask the
 * directory the same question one second later. Userinfo mints nothing.
 */
function gateStageOf(ctx: KoaContextWithOIDC): Extract<GateStage, 'refresh' | 'token_exchange'> | undefined {
  if (ctx.oidc.route !== 'token') return undefined;
  const grantType = ctx.oidc.params?.grant_type;
  if (grantType === 'refresh_token') return 'refresh';
  if (grantType === TOKEN_EXCHANGE_GRANT_TYPE) return 'token_exchange';
  return undefined;
}

export function createProvider(options: CreateProviderOptions): Provider {
  const { config, secrets, gates, logger, extraClaims } = options;
  const log = logger.child({ component: 'provider' });

  /**
   * Machine-to-machine access needs somewhere to point the token at: without
   * API_AUDIENCE the client_credentials grant would mint opaque tokens no API
   * can verify, so the feature follows resourceIndicators exactly. The config
   * validator already refuses a client_credentials client without it.
   */
  const apiTokensEnabled = config.apiAudience !== undefined;

  /**
   * Every resource a token can be minted for, keyed by indicator, and the scope
   * that selects each one. The API_AUDIENCE is the default resource
   * (DEFAULT_RESOURCE_JSON); RESOURCE_SERVERS_JSON adds the others. Every
   * scope name and audience comes from the configuration.
   */
  interface Resource {
    indicator: string;
    audience: string;
    /** The scope that selects it, and the only resource scope its tokens carry. */
    scope: string;
    /** Grants that may ask for it through its scope (or its explicit indicator). */
    grants: readonly ResourceGrant[];
    /** The scopes an exchanged token may carry besides `scope`; empty without token-exchange. */
    exchangeScopes: readonly string[];
    isDefault: boolean;
  }
  const resources = new Map<string, Resource>();
  const resourceByScope = new Map<string, Resource>();
  if (config.apiAudience !== undefined) {
    // The validator never lets API_AUDIENCE through without DEFAULT_RESOURCE_JSON.
    if (!config.defaultResource) {
      throw new Error('API_AUDIENCE is set but DEFAULT_RESOURCE_JSON is not: the configuration was not validated');
    }
    const api: Resource = {
      indicator: config.apiAudience,
      audience: config.apiAudience,
      scope: config.defaultResource.scope,
      grants: config.defaultResource.grants,
      exchangeScopes: config.defaultResource.exchange_scopes ?? [],
      isDefault: true,
    };
    resources.set(api.indicator, api);
    resourceByScope.set(api.scope, api);
    for (const server of config.resourceServers) {
      const resource: Resource = {
        indicator: resourceIndicatorFor(server.scope),
        audience: server.audience,
        scope: server.scope,
        grants: server.grants,
        exchangeScopes: server.exchange_scopes ?? [],
        isDefault: false,
      };
      resources.set(resource.indicator, resource);
      resourceByScope.set(resource.scope, resource);
    }
  }

  /**
   * The resource the request's `scope` names, if any. One token has one
   * audience, so two resource scopes in the same request are refused here
   * rather than one of them being silently dropped.
   */
  function resourceFromScope(ctx: KoaContextWithOIDC): Resource | undefined {
    const raw = ctx.oidc.params?.scope;
    if (typeof raw !== 'string') return undefined;
    const named = [...new Set(raw.split(' '))]
      .map((scope) => resourceByScope.get(scope))
      .filter((resource): resource is Resource => resource !== undefined);
    if (named.length > 1) {
      throw new errors.InvalidScope(
        `one access token has one audience: request only one of ${named.map((r) => r.scope).join(', ')} per token`,
        named.map((r) => r.scope).join(' '),
      );
    }
    return named[0];
  }

  /** The resource whose audience is `audience`, for the token exchange rules. */
  function resourceByAudience(audience: string): ExchangeResource | undefined {
    for (const resource of resources.values()) {
      if (resource.audience === audience) return resource;
    }
    return undefined;
  }

  /**
   * Who is asking: a machine on the client_credentials grant, a service on the
   * token exchange grant, or a person — the authorization endpoint, the code
   * exchange and every refresh after it. Decided by the request, never by what
   * the client registration says.
   */
  function grantOf(ctx: KoaContextWithOIDC): ResourceGrant {
    if (ctx.oidc.route !== 'token') return 'authorization_code';
    const grantType = ctx.oidc.params?.grant_type;
    switch (grantType) {
      case 'client_credentials':
        return 'client_credentials';
      case TOKEN_EXCHANGE_GRANT_TYPE:
        return 'token-exchange';
      case 'authorization_code':
      case 'refresh_token':
        return 'authorization_code';
      default:
        // The token endpoint serves no other grant: supportedGrantTypeCheck
        // (token.js) has already refused anything else.
        throw new Error(`grantOf: unexpected grant_type ${JSON.stringify(grantType)}`);
    }
  }

  function reservedError(scope: string, grant: ResourceGrant): InstanceType<typeof errors.InvalidScope> {
    return new errors.InvalidScope(
      grant === 'authorization_code'
        ? `scope ${scope} is reserved to machine-to-machine clients`
        : `scope ${scope} is not open to machine-to-machine clients`,
      scope,
    );
  }

  /**
   * Refuses a requested resource scope the caller's grant may not obtain
   * (its `grants` in the configuration), whatever the client's own `scope`
   * says. The default resource stays open to people through `openid`.
   */
  function assertScopesForGrant(ctx: KoaContextWithOIDC): void {
    const raw = ctx.oidc.params?.scope;
    if (typeof raw !== 'string') return;
    const grant = grantOf(ctx);
    for (const scope of raw.split(' ')) {
      const resource = resourceByScope.get(scope);
      if (resource && !resource.grants.includes(grant)) throw reservedError(scope, grant);
    }
  }

  /** A resource server other than the default must be listed in the client's own scope. */
  function clientMayUse(client: { scope?: string }, resource: Resource): boolean {
    if (resource.isDefault) return true;
    return typeof client.scope === 'string' && client.scope.split(' ').includes(resource.scope);
  }

  /** sub is the sAMAccountName; the realm is fixed per deployment. */
  const principalOf = (sub: string): string =>
    config.realm === '' ? sub : `${sub}@${config.realm}`;

  const accountFor = (sub: string, extra: ExtraClaims): Account => ({
    accountId: sub,
    async claims() {
      // The extra claims are spread FIRST so the server's own claims always
      // win. The reserved-name blacklist already makes a collision impossible
      // at startup; this is the second lock on the same door.
      return {
        ...extra,
        sub,
        preferred_username: sub,
        realm: config.realm,
      };
    },
  });

  // --- phase 4-ter: one claims lookup per token request ---------------------
  // findAccount and extraTokenClaims both need the same row, and oidc-provider
  // calls them in that order within one request (grant_common.js validates the
  // account, then AccessToken.save() computes the extra claims). Memoising on
  // the koa context — the very object `als.getStore()` hands the second hook —
  // keeps the promise the plan asks for: ONE query per login and ONE per
  // refresh, no matter how many places need the values.
  const perRequest = new WeakMap<object, Promise<ExtraClaims>>();

  function claimsFor(ctx: KoaContextWithOIDC, sub: string): Promise<ExtraClaims> {
    if (!extraClaims) return Promise.resolve({});
    const key = ctx as unknown as object;
    let pending = perRequest.get(key);
    if (!pending) {
      pending = extraClaims.lookup(sub);
      // Nobody may see this as an unhandled rejection while the other hook is
      // still on its way to awaiting it.
      void pending.catch(() => undefined);
      perRequest.set(key, pending);
    }
    return pending;
  }

  /**
   * Turns a claims-lookup failure into the decided answer.
   *
   *   no row   the account is not tied to a back-office user: invalid_grant, and
   *            the whole grant chain goes — exactly like a gate saying no;
   *   silent   database unreachable, in error, past the deadline, ambiguous, or
   *            shaped differently from the startup declaration:
   *            temporarily_unavailable, chain INTACT.
   */
  async function refuseForClaims(
    ctx: KoaContextWithOIDC,
    sub: string,
    grantId: string | undefined,
    error: unknown,
  ): Promise<never> {
    const notFound = error instanceof ExtraClaimsUserNotFound;
    const reason = notFound
      ? EXTRA_CLAIMS_REASONS.userNotFound
      : (error as { reason?: string }).reason ?? EXTRA_CLAIMS_REASONS.unavailable;

    const revoked = notFound && grantId !== undefined;
    if (revoked) {
      await revokeGrantChain(ctx.oidc.provider, grantId!).catch((failure: unknown) => {
        log.error(
          { grantId, err: failure },
          'could not revoke the grant chain after a failed extra-claims lookup',
        );
      });
    }

    log[notFound ? 'warn' : 'error'](
      {
        username: sub,
        clientId: ctx.oidc.client?.clientId,
        route: ctx.oidc.route,
        reason,
        grantId,
        revoked,
        err: error instanceof Error ? { name: error.name, message: error.message } : error,
      },
      notFound
        ? 'token refused: this account has no row in the back office'
        : 'token refused: the extra claims could not be read (fail closed, chain intact)',
    );

    throw notFound
      ? new errors.InvalidGrant(reason)
      : new TemporarilyUnavailable('the account could not be verified; try again later');
  }
  /**
   * THE ENFORCEMENT POINT.
   *
   * oidc-provider calls findAccount on every refresh grant before it rotates
   * anything, and the token exchange handler calls it before it issues a
   * delegated token. A gate that says no ends the chain right here on a
   * refresh: `invalid_grant` plus revocation of the whole chain, so the client
   * cannot keep trying with an older token. A gate that cannot answer
   * (directory unreachable) rejects too — never fail open — but without
   * revoking: an outage of ours must not log the whole floor out for good.
   *
   * The token exchange calls it WITHOUT a token: no grantId, so a refusal
   * there never revokes the person's own chain (plan D6).
   */
  const findAccount = async (
    ctx: KoaContextWithOIDC,
    sub: string,
    token: unknown,
    /** Token exchange only: the client the subject token was issued to. */
    subjectClientId?: string,
  ): Promise<Account> => {
    const grantId = (token as { grantId?: string } | undefined)?.grantId;

    /**
     * Phase 4-ter: the back-office claims, on EVERY path that mints a token —
     * the code exchange, every refresh, every token exchange, and userinfo.
     * One query per request, memoised on the context and reused by
     * extraTokenClaims below.
     */
    const withClaims = async (): Promise<Account> => {
      try {
        return accountFor(sub, await claimsFor(ctx, sub));
      } catch (error) {
        return await refuseForClaims(ctx, sub, grantId, error);
      }
    };

    const stage = gateStageOf(ctx);
    if (stage === undefined) {
      return withClaims();
    }

    const clientId = ctx.oidc.client?.clientId;
    const verdict = await runAccountGates(
      gates,
      {
        principal: principalOf(sub),
        username: sub,
        stage,
        clientId,
        ...(subjectClientId === undefined ? {} : { subjectClientId }),
      },
      log,
    );

    if (verdict.ok) {
      return withClaims();
    }

    const revoked = !verdict.unavailable && grantId !== undefined;
    if (revoked) {
      await revokeGrantChain(ctx.oidc.provider, grantId!).catch((error: unknown) => {
        log.error(
          { grantId, err: error },
          'could not revoke the grant chain after a failed account gate',
        );
      });
    }

    log.warn(
      {
        username: sub,
        principal: principalOf(sub),
        clientId,
        gate: verdict.gate,
        reason: verdict.reason,
        grantId,
        revoked,
      },
      stage === 'refresh'
        ? 'refresh rejected by an account gate'
        : 'token exchange rejected by an account gate',
    );

    throw verdict.unavailable
      ? new TemporarilyUnavailable(
        // Phase 4: it may be the directory OR the SQL group check that is
        // down, and the client has no business knowing which.
        'the account could not be verified; try again later',
      )
      : new errors.InvalidGrant(verdict.reason);
  };
  // --- end phase 4-ter -----------------------------------------------------

  // --- 1.3.0: required_ldap_groups on SSO reuse -----------------------------
  /**
   * The gates for a client restricted by `required_ldap_groups`, when the
   * authorization endpoint is about to hand it a code on a session it did not
   * open itself.
   *
   * The hole this closes: a person signs in to crm-web, then dbsync-web sends
   * them to /auth. The session already has an account, so oidc-provider raises
   * no login prompt and the interaction in src/routes/interaction.ts — the only
   * place the gates ran at authorization time — never sees them: either the
   * consent prompt is approved silently, or (a web client whose grant already
   * covers the request) there is no interaction at all and the code comes
   * straight back. Both go through lib/actions/authorization/load_grant.js,
   * which calls loadExistingGrant on EVERY authorization with an account, on
   * the first request and on every resume, and before the `interactions` step,
   * so before `prompt=none` could answer anything. That is where this runs.
   *
   * Skipped when the interaction result of this very flow carries a login:
   * the login has just run every gate with this clientId (interaction.ts), and
   * the person has not gone anywhere since.
   *
   * Only for restricted clients: every other client keeps the plain session
   * reuse it had, with no directory round trip. For a restricted one the
   * WHOLE gate list runs, so liveness and the SQL check come with it.
   *
   * A refusal throws from inside the authorization request, after the
   * redirect_uri was verified: oidc-provider answers the client with
   * `error=access_denied` (or `temporarily_unavailable` when the directory is
   * silent) on its redirect URI. Nothing is destroyed: the browser session and
   * the grants of the other clients stay as they are, so crm-web keeps
   * working, and this client simply gets no grant.
   */
  async function gateSessionReuse(ctx: KoaContextWithOIDC): Promise<void> {
    const { oidc } = ctx;
    const clientId = oidc.client!.clientId;
    if (!config.clientRequiredGroups.has(clientId)) return;
    if (oidc.result?.login) return;

    const sub = oidc.account!.accountId;
    const verdict = await runAccountGates(
      gates,
      { principal: principalOf(sub), username: sub, stage: 'authorization', clientId },
      log,
    );
    if (verdict.ok) return;

    log.warn(
      {
        username: sub,
        principal: principalOf(sub),
        clientId,
        gate: verdict.gate,
        reason: verdict.reason,
        unavailable: verdict.unavailable,
        prompt: oidc.params?.prompt,
      },
      'authorization on an existing session rejected by an account gate: no code for this client, the session is kept',
    );

    if (verdict.unavailable) {
      throw new TemporarilyUnavailable('the account could not be verified; try again later');
    }
    throw new errors.AccessDenied(
      verdict.reason === CLIENT_GROUP_NOT_ALLOWED
        ? 'the account is not a member of any AD group allowed for this client'
        : 'the account is not allowed to sign in',
    );
  }
  // --- end 1.3.0 ------------------------------------------------------------

  // --- RFC 8693: the subject token registry ---------------------------------
  // Every audience a token exchange rule accepts as its subject. Only a
  // person's access token for one of them is recorded (plan D1).
  const subjectAudiences = new Set(
    [...config.tokenExchange.values()].flatMap((rules) => rules.map((rule) => rule.subject.audience)),
  );
  // Built on the provider's own adapter right after the Provider exists; the
  // customizer below only runs inside a request, long after that.
  let subjectTokens: SubjectTokenRegistry | undefined;
  // --- end RFC 8693 registry ------------------------------------------------

  const configuration: Configuration = {
    adapter: options.adapterFactory,
    clients: config.clients as unknown as Configuration['clients'],

    /**
     * Sensible defaults so CLIENTS_JSON only carries what is specific to a
     * client. `native` is what unlocks RFC 8252 loopback redirect URIs with a
     * variable port; `none` is what makes PKCE mandatory.
     */
    clientDefaults: {
      application_type: 'native',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      id_token_signed_response_alg: 'RS256',
      // `auth_time` is one of the claims the plan asks for; without this it only
      // appears when the client sends max_age.
      require_auth_time: true,
    },

    jwks: secrets.jwks as Configuration['jwks'],
    cookies: {
      keys: secrets.cookieKeys,
      long: { signed: true, sameSite: 'lax' },
      short: { signed: true, sameSite: 'lax' },
    },

    /** S256 only: oidc-provider v9 rejects `plain` outright. */
    pkce: { required: () => true },

    // The resource scopes must be declared here too: oidc-provider checks a
    // client's `scope` allow-list only against declared scopes, so an
    // undeclared resource scope would slip past a client not registered for it.
    scopes: apiTokensEnabled
      ? ['openid', 'offline_access', ...resourceByScope.keys()]
      : ['openid', 'offline_access'],
    /**
     * Declared under `openid`, which every request that gets an id token has
     * granted by definition — that is what makes the extra claims UNCONDITIONAL
     * rather than something a client opts into. oidc-provider v9 builds its
     * `claimsSupported` set from exactly this map at construction time, and
     * `Claims.result()` drops any account claim whose name is not in it, so a
     * name discovered later would never reach a token. Hence the startup
     * analysis of CLAIMS_SQL_QUERY in src/claims/selectList.ts.
     */
    claims: {
      openid: ['sub', 'preferred_username', 'realm', ...(extraClaims?.claimNames ?? [])],
      profile: ['preferred_username'],
    },
    /**
     * The desktop client is a first-party client and reads the identity straight from
     * the ID token, so the conformance-mode stripping of non-`sub` claims is off.
     */
    conformIdTokenClaims: false,

    ttl: {
      AccessToken: config.accessTokenTtl,
      RefreshToken: config.refreshTokenTtl,
      IdToken: config.accessTokenTtl,
      Session: config.refreshTokenTtl,
      Grant: config.refreshTokenTtl,
      // The machine-to-machine access token lives exactly as long as a user one.
      ClientCredentials: config.accessTokenTtl,
      Interaction: 900,
      AuthorizationCode: 60,
    },

    /** Refresh token rotation, per the plan. The rotated-out token is one-shot. */
    rotateRefreshToken: true,

    /**
     * A first-party desktop client always needs a refresh token, and it has to
     * outlive the browser session that created it: the enforcement is the gate
     * check at refresh time, not the lifetime of an interaction cookie.
     * That is why neither of these defers to the `offline_access` scope.
     */
    issueRefreshToken: async (_ctx, client) => client.grantTypeAllowed('refresh_token'),
    expiresWithSession: async () => false,

    /**
     * Implicit consent on an existing session, for our first-party clients.
     *
     * RFC 8707 and resourceFromScope above: one access token has one audience,
     * so a client cannot log in with `openid crm` and `openid agent` at once.
     * The second resource is asked for afterwards, on the same session, with
     * `prompt=none` (crm-web does it with oidc-client-ts `signinSilent`). The
     * session's Grant only holds what the first login granted, so oidc-provider's
     * consent prompt (lib/helpers/interaction_policy/prompts/consent.js,
     * `op_scopes_missing` / `rs_scopes_missing`) asks for consent, and with
     * `prompt=none` lib/actions/authorization/interactions.js answers
     * `consent_required`. The library default (lib/helpers/defaults.js,
     * loadExistingGrant) returns the grant as it is.
     *
     * There is no consent screen here anyway (src/routes/interaction.ts approves
     * every grant silently), so the grant of the session is widened in place
     * with the scopes the request is entitled to:
     * - the OIDC-level scopes (oidc-provider counts every declared scope there,
     *   resource scopes included), a resource scope only under the rule below;
     * - every resource scope, only when the client lists the resource in its
     *   own `scope` (clientMayUse) and people may obtain it (`authorization_code`
     *   among its grants; the default resource is always open to people through
     *   `openid`, exactly as getResourceServerInfo decides).
     * A scope the client is not registered for never gets here: checkScope
     * (lib/actions/authorization/check_scope.js) refuses it first with
     * invalid_scope.
     *
     * No grant on the session (first login) => undefined: the library creates
     * a new Grant and the interaction in src/routes/interaction.ts runs as
     * before. Machine clients have no session and never reach this hook
     * (lib/actions/authorization/load_grant.js runs it only with an account).
     * Native clients still get `interaction_required` on `prompt=none`: that is
     * the `native_client_prompt` check, untouched.
     */
    loadExistingGrant: async (ctx) => {
      // 1.3.0: before anything else, and before the "no grant yet" early
      // return, so a first authorization of the client on a reused session is
      // covered too (see gateSessionReuse).
      await gateSessionReuse(ctx);

      const { oidc } = ctx;
      const client = oidc.client!;
      const grantId = oidc.result?.consent?.grantId || oidc.session!.grantIdFor(client.clientId);
      if (!grantId) return undefined;
      const grant = await oidc.provider.Grant.find(grantId);
      if (!grant) return undefined;

      const personMay = (resource: Resource): boolean =>
        clientMayUse(client, resource)
        && (resource.isDefault || resource.grants.includes('authorization_code'));

      const oidcScopes = [...oidc.requestParamOIDCScopes].filter((scope) => {
        const resource = resourceByScope.get(scope);
        return resource === undefined || personMay(resource);
      });
      if (oidcScopes.length > 0) grant.addOIDCScope(oidcScopes);

      const requested = oidc.requestParamScopes;
      for (const [indicator, server] of Object.entries(oidc.resourceServers ?? {})) {
        const resource = resources.get(indicator);
        if (!resource || !personMay(resource)) continue;
        const scopes = [...requested].filter((scope) => server.scopes.has(scope));
        if (scopes.length > 0) grant.addResourceScope(indicator, scopes);
      }

      await grant.save();
      return grant;
    },

    features: {
      devInteractions: { enabled: false },
      revocation: { enabled: true },
      introspection: { enabled: true },
      userinfo: { enabled: true },
      /**
       * client_credentials: a confidential client (see the CLIENTS_JSON
       * validator) gets an RS256 JWT for the API with no user behind it.
       * oidc-provider resolves the `resource` through resourceIndicators
       * below — defaultResource when the client sends none — and writes
       * `sub` = `client_id` into the token (RFC 9068 §2.2): there is no
       * account, so findAccount and the account gates never run.
       */
      clientCredentials: { enabled: apiTokensEnabled },
      resourceIndicators: {
        // Off unless an API audience is configured; with it on, access tokens
        // become RS256 JWTs the resource API can verify through the JWKS
        // without calling back here (phase 7).
        enabled: apiTokensEnabled,
        /**
         * The resource is chosen by the scope: a resource scope -> that resource
         * server, and so on; no resource scope -> the API_AUDIENCE, as before.
         * `oneOf` is only passed when the client sent several explicit
         * `resource` values: handing them back makes oidc-provider refuse
         * with invalid_target (one resource per token).
         */
        defaultResource: async (ctx, _client, oneOf) => {
          assertScopesForGrant(ctx);
          if (oneOf !== undefined) return oneOf;
          return (resourceFromScope(ctx) ?? resources.get(config.apiAudience!)!).indicator;
        },
        useGrantedResource: async () => true,
        getResourceServerInfo: async (ctx, resourceIndicator, client) => {
          const resource = resources.get(resourceIndicator);
          // Any other indicator would otherwise come back as a token for the
          // default resource all the same.
          if (!resource) {
            throw new errors.InvalidTarget(
              `unknown resource; served: ${[...resources.keys()].join(', ')}`,
            );
          }
          assertScopesForGrant(ctx);
          // Also on the code exchange and on every refresh, where no scope is
          // sent, and for an explicit `resource`: the default resource is the
          // only one a grant reaches without its scope (people via `openid`).
          const grant = grantOf(ctx);
          const person = grant === 'authorization_code';
          if (!resource.grants.includes(grant)) {
            // People always reach the default resource through `openid`.
            if (!(resource.isDefault && person)) {
              if (resource.isDefault) {
                throw new errors.InvalidTarget(
                  `the default resource is not open to machine-to-machine clients; request one of: ${
                    [...resourceByScope.values()]
                      .filter((r) => r.grants.includes(grant))
                      .map((r) => r.scope)
                      .join(', ') || '(none configured)'}`,
                );
              }
              throw reservedError(resource.scope, grant);
            }
          }
          // An explicit RFC 8707 `resource` that contradicts the scope.
          const fromScope = resourceFromScope(ctx);
          if (fromScope && fromScope !== resource) {
            throw new errors.InvalidTarget(
              `scope ${fromScope.scope} selects ${fromScope.indicator}, not ${resource.indicator}`,
            );
          }
          if (!clientMayUse(client, resource)) {
            throw new errors.InvalidScope('requested scope is not allowed', resource.scope);
          }
          // The default resource carries `openid` on a person's token (plus its
          // own scope only when people are among its grants) and its own scope
          // on a machine token. Any other resource carries just its own scope.
          let scope = resource.scope;
          if (resource.isDefault && person) {
            scope = resource.grants.includes('authorization_code') ? `openid ${resource.scope}` : 'openid';
          }
          return {
            scope,
            audience: resource.audience,
            accessTokenFormat: 'jwt',
            accessTokenTTL: config.accessTokenTtl,
            jwt: { sign: { alg: 'RS256' } },
          };
        },
      },
    },

    interactions: {
      url: (_ctx, interaction) => `/interaction/${interaction.uid}`,
    },

    findAccount: (ctx, sub, token) => findAccount(ctx, sub, token),

    /**
     * Claims carried by a JWT access token, when one is issued (see apiAudience).
     *
     * This is the second half of the unconditional inclusion: the id token gets
     * the claims through findAccount, the resource-server access token gets
     * them here. oidc-provider stores the result as `payload.extra` and the JWT
     * format spreads it FIRST into the token body, so the registered claims it
     * writes itself always win — which is the same guarantee the reserved-name
     * blacklist gives, arrived at from the other side.
     */
    extraTokenClaims: async (ctx, token) => {
      const accountId = (token as { accountId?: string }).accountId;
      // A client_credentials token has no account: no user claims to add.
      if (!accountId) return undefined;

      let extra: ExtraClaims = {};
      if (extraClaims) {
        const grantId = (token as { grantId?: string }).grantId;
        try {
          // Already resolved by findAccount within this same request: this is a
          // memo hit, not a second query.
          extra = await claimsFor(ctx, accountId);
        } catch (error) {
          await refuseForClaims(ctx, accountId, grantId, error);
        }
      }

      // RFC 8693 §4.1: a token from the exchange grant names the client acting
      // for the user. Written here and nowhere else, because opaque.js
      // OVERWRITES token.extra with what this hook returns; after `...extra`,
      // although the reserved-name blacklist already keeps `act` out of it.
      if (ctx.oidc.route === 'token' && ctx.oidc.params?.grant_type === TOKEN_EXCHANGE_GRANT_TYPE) {
        return {
          ...extra,
          preferred_username: accountId,
          realm: config.realm,
          act: { sub: ctx.oidc.client!.clientId },
        };
      }

      return { ...extra, preferred_username: accountId, realm: config.realm };
    },

    formats: {
      customizers: {
        /**
         * The subject token registry (plan D1). oidc-provider awaits this hook
         * before signing every JWT access token (formats/jwt.js:140-143), and
         * it is the only place where the token's grantId and grant type are
         * still known: the JWT carries neither and is never stored.
         *
         * Recorded: a person's access token (it has an accountId) whose `aud`
         * is the subject audience of some exchange rule. Not recorded: a
         * client_credentials token (another model, no account), a token for
         * any other audience, and a delegated token (it carries `act`).
         */
        jwt: async (_ctx, token, structured) => {
          if (subjectAudiences.size === 0 || token.kind !== 'AccessToken') return structured;
          const accessToken = token as typeof token & { accountId?: string; grantId?: string; gty?: string };
          const { payload } = structured;
          const aud = payload.aud;
          if (
            !accessToken.accountId
            || payload.act !== undefined
            || typeof aud !== 'string'
            || !subjectAudiences.has(aud)
          ) {
            return structured;
          }
          const jti = payload.jti as string;
          const exp = payload.exp as number;
          if (typeof accessToken.grantId !== 'string' || typeof accessToken.gty !== 'string') {
            // Without them the exchange could not tell a live subject from a
            // revoked one: left unrecorded, the token is never exchangeable.
            log.error(
              { jti, aud, clientId: accessToken.clientId },
              'subject token not recorded: the access token has no grantId or grant type',
            );
            return structured;
          }
          const ttl = Math.max(1, exp - Math.floor(Date.now() / 1000));
          await subjectTokens!.record(jti, {
            accountId: accessToken.accountId,
            clientId: accessToken.clientId!,
            grantId: accessToken.grantId,
            gty: accessToken.gty,
            aud,
            exp,
          }, ttl);
          return structured;
        },
      },
    },

    renderError: async (ctx, out) => {
      ctx.type = 'html';
      ctx.body = renderErrorPage({
        error: out.error ?? 'server_error',
        error_description: out.error_description,
      });
    },
  };

  const provider = new Provider(config.issuerUrl, configuration);
  provider.proxy = config.trustProxy;

  subjectTokens = createSubjectTokenRegistry(provider);

  // RFC 8693, registered only when some client has rules: otherwise the grant
  // does not even appear in the discovery. Static clients are validated when
  // first looked up, so registering here, before the first request, is what
  // makes a client with this grant type valid.
  if ([...config.tokenExchange.values()].some((rules) => rules.length > 0)) {
    provider.registerGrantType(
      TOKEN_EXCHANGE_GRANT_TYPE,
      createTokenExchangeHandler({
        issuerUrl: config.issuerUrl,
        rules: config.tokenExchange,
        resourceByAudience,
        signingJwks: secrets.jwks,
        registry: subjectTokens,
        findAccount: (ctx, sub, subjectClientId) => findAccount(ctx, sub, undefined, subjectClientId),
        logger,
      }),
      TOKEN_EXCHANGE_PARAMETERS,
    );
  }

  provider.on('grant.error', (ctx, error) => {
    log.warn(
      {
        clientId: ctx.oidc?.client?.clientId,
        grantType: ctx.oidc?.params?.grant_type,
        err: {
          name: error.name,
          message: error.message,
          description: (error as { error_description?: string }).error_description,
        },
      },
      'grant error',
    );
  });

  // Machine-to-machine issuance has no login to show up in the logs, so the
  // token itself is logged (never its value).
  provider.on('grant.success', (ctx) => {
    if (ctx.oidc.params?.grant_type === TOKEN_EXCHANGE_GRANT_TYPE) {
      const entities = ctx.oidc.entities as Record<string, unknown>;
      const token = ctx.oidc.entities.AccessToken;
      const rule = entities.TokenExchangeRule as { where: string } | undefined;
      const subject = entities.SubjectToken as ExchangedSubject | undefined;
      log.info(
        {
          clientId: ctx.oidc.client?.clientId,
          grantType: TOKEN_EXCHANGE_GRANT_TYPE,
          username: token?.accountId,
          rule: rule?.where,
          subjectJti: subject?.jti,
          subjectClientId: subject?.clientId,
          jti: token?.jti,
          audience: token?.aud,
          scope: token?.scope,
          expiresIn: token?.expiration,
        },
        'token exchange: delegated access token issued',
      );
      return;
    }
    if (ctx.oidc.params?.grant_type !== 'client_credentials') return;
    const token = ctx.oidc.entities.ClientCredentials;
    log.info(
      {
        clientId: ctx.oidc.client?.clientId,
        grantType: 'client_credentials',
        jti: token?.jti,
        audience: token?.aud,
        scope: token?.scope,
        expiresIn: token?.expiration,
      },
      'machine-to-machine access token issued',
    );
  });
  provider.on('server_error', (_ctx, error) => {
    log.error({ err: { message: error.message, stack: error.stack } }, 'provider server error');
  });

  return provider;
}
