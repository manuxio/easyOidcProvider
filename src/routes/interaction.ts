/**
 * The login interaction.
 *
 * oidc-provider redirects here whenever the authorization request needs a human
 * (or, from phase 3, a Kerberos handshake). The route delegates the credential
 * work to the configured IdentityProvider, then runs the account gates — the
 * same gates the refresh grant runs — before handing the session back.
 *
 * Phase 4-bis adds two things that live HERE rather than inside a provider,
 * because both providers share the same form:
 *
 *  - the optional second factor, asked for on the FORM path only (an
 *    `authenticated` result carries `via`, so the Kerberos path is never asked);
 *  - the per-username cool-down on failed form attempts.
 */
import { Router, type Request, type Response } from 'express';
import type Provider from 'oidc-provider';

import { ExtraClaimsUserNotFound, type ExtraClaimsSource } from '../claims/index.js';
import type { Config } from '../config.js';
import { runAccountGates, type AccountGate } from '../gates/index.js';
import {
  asChallengeReason,
  usernameFromPrincipal,
  type ChallengeReason,
  type IdentityProvider,
} from '../identity/types.js';
import type { Logger } from '../logger.js';
import type { LoginRateLimiter, TwoFactorVerifier } from '../twofactor/index.js';
import { FORM_FIELD_OTP, FORM_FIELD_USERNAME, renderFormDisabledPage } from '../views/login.js';

export interface InteractionRouterOptions {
  provider: Provider;
  identity: IdentityProvider;
  gates: readonly AccountGate[];
  config: Config;
  logger: Logger;
  // --- phase 4-bis -------------------------------------------------------
  /** Absent when TWO_FACTOR_ENABLED=false: then no second factor is ever asked. */
  twoFactor?: TwoFactorVerifier;
  rateLimiter: LoginRateLimiter;
  // --- end phase 4-bis ---------------------------------------------------
  /**
   * Phase 4-ter: absent when CLAIMS_SQL_ENABLED=false. It is consulted HERE, at
   * login, only so that "no back-office row" can be told to the user as an
   * Italian page instead of as an OAuth error at the token endpoint. The value
   * is thrown away; the provider reads the row again when it mints the tokens.
   */
  extraClaims?: ExtraClaimsSource;
}

export function createInteractionRouter(options: InteractionRouterOptions): Router {
  const {
    provider, identity, gates, config, logger, twoFactor, rateLimiter, extraClaims,
  } = options;
  const log = logger.child({ component: 'interaction' });
  const router = Router();

  /**
   * Auto-approves the grant. There is no consent screen and there will not be
   * one: the same operator owns both ends of this exchange, so asking the agent to
   * approve the platform reading their own identity would be theatre.
   *
   * The consent prompt still happens, because oidc-provider's default policy
   * demands an interaction for every `native` client (the `native_client_prompt`
   * check, which is exactly what makes loopback redirect URIs legal). It costs
   * one silent redirect and keeps the standard policy intact.
   */
  async function grantConsent(
    req: Request,
    res: Response,
    details: Awaited<ReturnType<Provider['interactionDetails']>>,
  ): Promise<void> {
    const { prompt, params, session, grantId } = details;
    const clientId = params.client_id as string;

    const grant = grantId
      ? await provider.Grant.find(grantId)
      : new provider.Grant({ accountId: session?.accountId, clientId });

    if (!grant) {
      throw new Error(`grant ${grantId} referenced by the interaction is gone`);
    }

    const missingScope = prompt.details.missingOIDCScope as string[] | undefined;
    if (missingScope?.length) grant.addOIDCScope(missingScope.join(' '));

    const missingClaims = prompt.details.missingOIDCClaims as string[] | undefined;
    if (missingClaims?.length) grant.addOIDCClaims(missingClaims);

    const missingResourceScopes = prompt.details.missingResourceScopes as
      | Record<string, string[]>
      | undefined;
    for (const [indicator, scopes] of Object.entries(missingResourceScopes ?? {})) {
      grant.addResourceScope(indicator, scopes.join(' '));
    }

    const savedGrantId = await grant.save();
    log.debug(
      { uid: details.uid, clientId, grantId: savedGrantId, missingScope },
      'grant approved without a consent screen (first-party client)',
    );

    await provider.interactionFinished(
      req,
      res,
      { consent: { grantId: savedGrantId } },
      { mergeWithLastSubmission: true },
    );
  }

  async function handle(req: Request, res: Response, fromForm: boolean): Promise<void> {
    const details = await provider.interactionDetails(req, res);
    const { uid, prompt, params } = details;
    const clientId = typeof params.client_id === 'string' ? params.client_id : undefined;

    if (prompt.name === 'consent') {
      await grantConsent(req, res, details);
      return;
    }

    if (prompt.name !== 'login') {
      // `login` and `consent` are the only prompts the default policy can raise
      // for our clients. Anything else means the policy moved under us: say so
      // rather than guessing.
      log.error({ uid, prompt: prompt.name, clientId }, 'unexpected interaction prompt');
      res.status(500).type('text').send('interaction non supportata');
      return;
    }

    // --- phase 4-bis: the form can be switched off entirely ----------------
    if (fromForm && !config.fallbackFormEnabled) {
      log.warn(
        { uid, clientId, reason: 'fallback_form_disabled', remote: req.ip },
        'a credential form was posted while FALLBACK_FORM_ENABLED=false: refusing (this server is SSO only)',
      );
      res.status(403).type('html').send(renderFormDisabledPage());
      return;
    }

    // --- phase 4-bis: per-username cool-down on failed form attempts -------
    const submitted = fromForm ? readField(req, FORM_FIELD_USERNAME) : '';
    if (fromForm && submitted !== '') {
      const state = rateLimiter.check(submitted);
      if (state.locked) {
        log.warn(
          {
            uid,
            clientId,
            username: submitted.toLowerCase(),
            reason: 'login_rate_limited',
            retryAfterSeconds: state.retryAfterSeconds,
          },
          'refusing a form attempt while the cool-down for this user name is running',
        );
        res.setHeader('Retry-After', String(state.retryAfterSeconds));
        await identity.challenge(req, res, {
          interactionUid: uid,
          reason: 'too_many_attempts',
          username: submitted,
        });
        return;
      }
    }

    const outcome = await identity.authenticate(req, res);

    if (outcome.status === 'no-credentials') {
      log.debug({ uid, clientId }, 'no usable credentials: sending the challenge');
      await identity.challenge(req, res, { interactionUid: uid });
      return;
    }

    if (outcome.status === 'failed') {
      const username = outcome.username ?? submitted;
      log.warn({ uid, clientId, username, reason: outcome.reason }, 'login rejected');
      if (fromForm && username !== '') {
        rateLimiter.recordFailure(username, { uid, clientId, stage: 'credentials' });
      }
      await identity.challenge(req, res, {
        interactionUid: uid,
        reason: asChallengeReason(outcome.reason),
        username: outcome.username,
      });
      return;
    }

    const username = usernameFromPrincipal(outcome.principal);

    // --- phase 4-bis: the second factor, FORM PATH ONLY --------------------
    // A Kerberos ticket already proves possession of the domain credentials to
    // the KDC; the password form is the door that a stolen password opens, and
    // it is the only one asked for a code.
    if (twoFactor && outcome.via === 'form') {
      const verdict = await twoFactor.verify(username, readField(req, FORM_FIELD_OTP));

      if (verdict.status !== 'ok') {
        rateLimiter.recordFailure(username, { uid, clientId, stage: 'two_factor' });
        // What the page says is coarser than what the log says, on purpose: the
        // user is told "credentials are wrong" without learning WHICH factor
        // failed, while `reason` in the log names it exactly.
        const reason: ChallengeReason =
          verdict.status === 'unavailable'
            ? 'temporarily_unavailable'
            : verdict.status === 'not-enrolled'
              ? 'two_factor_not_enrolled'
              : 'invalid_credentials';
        log.warn(
          { uid, clientId, username, reason: verdict.reason, shownAs: reason },
          'login rejected by the second factor',
        );
        await identity.challenge(req, res, {
          interactionUid: uid,
          reason,
          username: submitted === '' ? username : submitted,
        });
        return;
      }
    }
    // --- end phase 4-bis ---------------------------------------------------

    const verdict = await runAccountGates(
      gates,
      { principal: outcome.principal, username, stage: 'login', clientId },
      log,
    );

    if (!verdict.ok) {
      log.warn(
        {
          uid,
          clientId,
          username,
          gate: verdict.gate,
          reason: verdict.reason,
          unavailable: verdict.unavailable,
        },
        'login rejected by an account gate',
      );
      await identity.challenge(req, res, {
        interactionUid: uid,
        reason: verdict.unavailable
          ? 'temporarily_unavailable'
          : asChallengeReason(verdict.reason),
        username,
      });
      return;
    }

    // --- phase 4-ter: the back-office identity has to exist ------------------
    // The claims themselves are read again by the provider when it mints the
    // tokens; this call is here for the refusal, which at login has to be a
    // page in Italian rather than an `invalid_grant` on the token endpoint.
    if (extraClaims) {
      try {
        await extraClaims.lookup(username);
      } catch (error) {
        const notFound = error instanceof ExtraClaimsUserNotFound;
        const reason: ChallengeReason = notFound
          ? 'claims_user_not_found'
          : 'temporarily_unavailable';
        log.warn(
          {
            uid,
            clientId,
            username,
            reason: notFound
              ? 'claims_user_not_found'
              : (error as { reason?: string }).reason ?? 'claims_source_unavailable',
            shownAs: reason,
          },
          notFound
            ? 'login rejected: this account has no row in the back office'
            : 'login rejected: the extra claims could not be read (fail closed)',
        );
        await identity.challenge(req, res, {
          interactionUid: uid,
          reason,
          username: submitted === '' ? username : submitted,
        });
        return;
      }
    }
    // --- end phase 4-ter ----------------------------------------------------

    // Everything passed: the user's failure history stops being interesting.
    rateLimiter.reset(username);

    log.info(
      { uid, clientId, username, principal: outcome.principal, via: outcome.via },
      'login accepted',
    );

    await provider.interactionFinished(
      req,
      res,
      {
        login: {
          accountId: username,
          remember: false,
        },
      },
      { mergeWithLastSubmission: false },
    );
  }

  // GET is where a silent SSO succeeds (phase 3: the Negotiate header rides on
  // this request); POST is the credential form coming back.
  router.get('/interaction/:uid', asyncRoute((req, res) => handle(req, res, false), log));
  router.post('/interaction/:uid/login', asyncRoute((req, res) => handle(req, res, true), log));

  return router;
}

/** One trimmed string field out of the urlencoded body. Never throws. */
function readField(req: Request, name: string): string {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const value = body[name];
  return typeof value === 'string' ? value.trim() : '';
}

/**
 * Express 5 forwards a rejected promise to the error handler on its own, but an
 * expired or replayed interaction cookie is an ordinary event, not a fault:
 * it gets its own answer instead of a stack trace.
 */
function asyncRoute(
  handler: (req: Request, res: Response) => Promise<void>,
  log: Logger,
) {
  return async (req: Request, res: Response): Promise<void> => {
    try {
      await handler(req, res);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const expired = /interaction session/i.test(message);
      log.warn(
        { err: { message }, expired, path: req.path },
        expired ? 'interaction session no longer valid' : 'interaction failed',
      );
      if (res.headersSent) return;
      res
        .status(expired ? 400 : 500)
        .type('text')
        .send(
          expired
            ? "La sessione di accesso è scaduta. Chiudere questa finestra e ripetere l'accesso dall'applicazione."
            : "Errore interno durante l'accesso.",
        );
    }
  };
}
