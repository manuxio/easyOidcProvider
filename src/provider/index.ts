/**
 * oidc-provider wiring.
 *
 * Everything policy-shaped lives here: the client contract (public client, PKCE
 * S256, loopback redirect URIs), the token claims, and — the point of the whole
 * design — the account gates re-run on every refresh grant.
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
import type { Config } from '../config.js';
import { runAccountGates, type AccountGate } from '../gates/index.js';
import type { Logger } from '../logger.js';
import type { ServerSecrets } from '../secrets.js';
import { renderErrorPage } from '../views/error.js';

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
 * Custom token-endpoint error for "we could not verify the account".
 * Rejecting is the decided policy: never fail open, and always say why.
 */
class TemporarilyUnavailable extends errors.CustomOIDCProviderError {
  constructor(description: string) {
    super('temporarily_unavailable', description);
  }
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

/** Which stage of the flow a findAccount call belongs to. */
function isRefreshGrant(ctx: KoaContextWithOIDC): boolean {
  return ctx.oidc.route === 'token' && ctx.oidc.params?.grant_type === 'refresh_token';
}

export function createProvider(options: CreateProviderOptions): Provider {
  const { config, secrets, gates, logger, extraClaims } = options;
  const log = logger.child({ component: 'provider' });

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
  // --- end phase 4-ter -----------------------------------------------------

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

    scopes: ['openid', 'offline_access'],
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

    features: {
      devInteractions: { enabled: false },
      revocation: { enabled: true },
      introspection: { enabled: true },
      userinfo: { enabled: true },
      resourceIndicators: {
        // Off unless an API audience is configured; with it on, access tokens
        // become RS256 JWTs the resource API can verify through the JWKS
        // without calling back here (phase 7).
        enabled: config.apiAudience !== undefined,
        defaultResource: async () => config.apiAudience,
        useGrantedResource: async () => true,
        getResourceServerInfo: async () => ({
          scope: 'openid',
          audience: config.apiAudience!,
          accessTokenFormat: 'jwt',
          accessTokenTTL: config.accessTokenTtl,
          jwt: { sign: { alg: 'RS256' } },
        }),
      },
    },

    interactions: {
      url: (_ctx, interaction) => `/interaction/${interaction.uid}`,
    },

    /**
     * THE ENFORCEMENT POINT.
     *
     * oidc-provider calls findAccount on every refresh grant before it rotates
     * anything. A gate that says no ends the chain right here: `invalid_grant`
     * plus revocation of the whole chain, so the client cannot keep trying with
     * an older token. A gate that cannot answer (directory unreachable) rejects
     * too — never fail open — but without revoking: an outage of ours must not
     * log the whole floor out for good.
     */
    findAccount: async (ctx, sub, token) => {
      const grantId = (token as { grantId?: string } | undefined)?.grantId;

      /**
       * Phase 4-ter: the back-office claims, on EVERY path that mints a token —
       * the code exchange, every refresh, and userinfo. One query per request,
       * memoised on the context and reused by extraTokenClaims below.
       */
      const withClaims = async (): Promise<Account> => {
        try {
          return accountFor(sub, await claimsFor(ctx, sub));
        } catch (error) {
          return await refuseForClaims(ctx, sub, grantId, error);
        }
      };

      if (!isRefreshGrant(ctx)) {
        return withClaims();
      }

      const clientId = ctx.oidc.client?.clientId;
      const verdict = await runAccountGates(
        gates,
        { principal: principalOf(sub), username: sub, stage: 'refresh', clientId },
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
        'refresh rejected by an account gate',
      );

      throw verdict.unavailable
        ? new TemporarilyUnavailable(
          // Phase 4: it may be the directory OR the SQL group check that is
          // down, and the client has no business knowing which.
          'the account could not be verified; try again later',
        )
        : new errors.InvalidGrant(verdict.reason);
    },

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

      return { ...extra, preferred_username: accountId, realm: config.realm };
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

  provider.on('grant.error', (_ctx, error) => {
    log.warn({ err: { name: error.name, message: error.message } }, 'grant error');
  });
  provider.on('server_error', (_ctx, error) => {
    log.error({ err: { message: error.message, stack: error.stack } }, 'provider server error');
  });

  return provider;
}
