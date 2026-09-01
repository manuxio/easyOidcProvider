/**
 * Identity provider contract.
 *
 * Three implementations exist:
 *  - `dev-stub` (phase 1): fixed users from DEV_STUB_USERS, minimal login form;
 *  - `spnego`   (phase 3): Kerberos/SPNEGO against Active Directory, with an
 *                          LDAP simple-bind form as the out-of-domain fallback;
 *  - `database`          : username/password form against a customer database
 *                          (SQL or external Mongo), for deployments with no AD.
 *
 * The plan sketches `authenticate(): Promise<{ principal } | null>`. The null is
 * split here into two outcomes — `no-credentials` and `failed` — because the two
 * demand different answers: the first sends the challenge (401 Negotiate / login
 * form), the second re-renders the form with an error and must be logged with a
 * reason. `authenticated` carries the same `principal` the plan asks for.
 */
import type { Request, Response } from 'express';

/**
 * Which door the credentials came through. It is not decoration: phase 4-bis
 * asks for the second factor on the FORM path only, and the Kerberos path must
 * never be told to produce a TOTP code.
 */
export type AuthenticationChannel = 'form' | 'sso';

export type AuthenticationResult =
  /** Credentials accepted. `principal` is the AD principal, user@REALM. */
  | { status: 'authenticated'; principal: string; via: AuthenticationChannel }
  /** No usable credentials in the request: the caller sends the challenge. */
  | { status: 'no-credentials' }
  /** Credentials present but rejected. `reason` is a stable, loggable token. */
  | { status: 'failed'; reason: string; username?: string };

/**
 * Every reason a credential challenge can carry. It is one list, exported, so
 * the view that translates it into Italian and the router that validates an
 * incoming reason cannot drift apart.
 */
export const CHALLENGE_REASONS = [
  'invalid_credentials',
  /** Deliberately shown as "wrong credentials": no account enumeration. */
  'account_not_found',
  'account_disabled',
  'account_expired',
  'account_locked',
  'password_expired',
  /** Not a member of LDAP_REQUIRED_GROUP (phase 3, off by default). */
  'group_not_allowed',
  'temporarily_unavailable',
  'ntlm_not_supported',
  /** The Kerberos handshake itself failed; the password form is the way out. */
  'sso_failed',
  /** Phase 4: credentials were fine, the external SQL check said no. */
  'sql_group_check_failed',
  // --- phase 4-bis ---------------------------------------------------------
  /**
   * Phase 4-bis: the password was right, but the user has no usable TOTP seed
   * in the configured source while TWO_FACTOR_ENABLED is on. Fail closed.
   *
   * There is deliberately NO reason for "wrong TOTP code": a wrong, expired or
   * replayed code degrades to `invalid_credentials`, so the page never says
   * which of the two factors failed. The precise token stays in the log.
   */
  'two_factor_not_enrolled',
  /** Phase 4-bis: the per-username cool-down on failed form attempts is running. */
  'too_many_attempts',
  // --- end phase 4-bis -----------------------------------------------------
  // --- phase 4-ter ---------------------------------------------------------
  /**
   * Phase 4-ter: credentials and gates were fine, but the extra-claims query
   * returned no row — the domain account is not tied to any back-office user, so
   * the token would carry no `remoteId` and the API could not place the person.
   * Said openly for the same reason as `two_factor_not_enrolled`: it is only
   * ever shown AFTER the password was accepted, so it enumerates nothing.
   */
  'claims_user_not_found',
  // --- end phase 4-ter -----------------------------------------------------
] as const;

export type ChallengeReason = (typeof CHALLENGE_REASONS)[number];

const CHALLENGE_REASON_SET: ReadonlySet<string> = new Set(CHALLENGE_REASONS);

/**
 * Narrows a free-form rejection token to a reason the login page can render.
 * Anything unknown degrades to `invalid_credentials`, which is the answer that
 * tells the user least — the precise token stays in the log.
 */
export function asChallengeReason(reason: string): ChallengeReason {
  return CHALLENGE_REASON_SET.has(reason)
    ? (reason as ChallengeReason)
    : 'invalid_credentials';
}

/**
 * Richer sibling of `isAccountActive`: lets a provider name *why* an account is
 * not usable, so the gate can log `account_expired` instead of flattening every
 * refusal into `account_disabled`.
 */
export type IdentityAccountStatus =
  | { active: true }
  | { active: false; reason: string };

export interface ChallengeOptions {
  /** The oidc-provider interaction uid; the form posts back to it. */
  interactionUid: string;
  /** Set when re-rendering after a rejection, so the user is told what happened. */
  reason?: ChallengeReason;
  /** Echoed back into the form so the user does not retype it. */
  username?: string;
}

export interface IdentityProvider {
  readonly name: string;

  /**
   * Returns the AD principal (user@REALM) when the request carries usable
   * credentials. Never throws for a wrong password: that is a `failed` result.
   * It may throw when the directory itself is unreachable — the caller turns
   * that into a rejection, never into a pass.
   */
  authenticate(req: Request, res: Response): Promise<AuthenticationResult>;

  /**
   * Account liveness re-check. Used at login AND at every refresh.
   * Throwing means "cannot tell" and is treated as a rejection, never as a pass.
   */
  isAccountActive(principal: string): Promise<boolean>;

  /**
   * Optional, and preferred by the `account_active` gate when a provider offers
   * it: the same check as `isAccountActive`, but able to say why. Same contract
   * about throwing — "cannot tell" is a rejection, never a pass.
   */
  inspectAccount?(principal: string): Promise<IdentityAccountStatus>;

  /**
   * Writes the credential challenge for this provider: the login form for
   * `dev-stub`, a 401 `WWW-Authenticate: Negotiate` carrying the fallback form
   * for `spnego` (phase 3).
   */
  challenge(req: Request, res: Response, options: ChallengeOptions): Promise<void>;

  /** Releases whatever the provider holds open (LDAP pools, from phase 3). */
  close?(): Promise<void>;
}

/**
 * The platform username is the AD sAMAccountName without the realm, lowercased.
 * That is the `sub` claim and the matching key against the platform user list.
 */
export function usernameFromPrincipal(principal: string): string {
  const at = principal.indexOf('@');
  const local = at === -1 ? principal : principal.slice(0, at);
  return local.toLowerCase();
}

/** The realm half of the principal, uppercased; empty when the principal has none. */
export function realmFromPrincipal(principal: string): string {
  const at = principal.indexOf('@');
  return at === -1 ? '' : principal.slice(at + 1).toUpperCase();
}
