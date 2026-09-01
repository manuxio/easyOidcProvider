/**
 * Phase 4-bis: optional TOTP second factor on the FORM PATH ONLY.
 *
 * The Kerberos path never asks for a second factor, and that is a decision, not
 * an omission: a domain-joined machine has already proved possession of the
 * user's Kerberos credentials to the KDC, while the password form is precisely
 * the door that can be walked through from anywhere with a stolen password.
 *
 * The seed ("master key") is a per-user base32 TOTP secret that this server only
 * ever READS, from one of two places — a SQL table or an LDAP attribute. It is
 * never generated, never written and never stored here: enrolment belongs to
 * whoever owns the source.
 */

/**
 * A place per-user TOTP seeds are read from. Two implementations exist: `sql`
 * (reusing the drivers of src/sqlcheck) and `ldap` (reusing the service bind of
 * LdapDirectory).
 */
export interface TwoFactorSeedSource {
  readonly name: string;

  /**
   * The user's base32 seed, or `undefined` when the source has no seed for them
   * — which means NOT ENROLLED and, with 2FA on, a refusal.
   *
   * Throws TwoFactorSeedUnavailable when the source could not answer at all.
   * "Could not answer" is never "no seed": the first is an outage of ours, the
   * second is a fact about the user.
   */
  lookup(username: string): Promise<string | undefined>;

  /** Releases whatever the source holds open. Safe to call twice. */
  close(): Promise<void>;
}

/**
 * The seed source could not answer: database unreachable, query rejected,
 * directory down, deadline hit. Fails closed upstream, as `temporarily_
 * unavailable`, exactly like the LDAP and SQL gates.
 */
export class TwoFactorSeedUnavailable extends Error {
  readonly source: string;

  constructor(source: string, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'TwoFactorSeedUnavailable';
    this.source = source;
  }
}

/** Configuration of the second factor is wrong. Raised at startup, never at a login. */
export class TwoFactorConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TwoFactorConfigError';
  }
}

/**
 * Stable log tokens. The user-facing message is deliberately coarser than these:
 * a wrong, expired or replayed code all read as "credenziali non corrette" on
 * the page, so the form never says WHICH factor failed, while the log says
 * exactly which one and why.
 */
export const TWO_FACTOR_REASONS = {
  /** No code typed at all while the second factor is required. */
  missingCode: 'two_factor_missing_code',
  /** Wrong shape (not exactly N digits) — refused before any HMAC is computed. */
  malformedCode: 'two_factor_malformed_code',
  /** Correct shape, wrong or expired value. */
  failed: 'two_factor_failed',
  /** A code already accepted for this user in the same or an earlier time step. */
  replayed: 'two_factor_replayed',
  /** The source has no seed for this user. */
  notEnrolled: 'two_factor_not_enrolled',
  /** The source has a seed, but it is not a usable base32 TOTP secret. */
  seedInvalid: 'two_factor_seed_invalid',
  /** The source could not answer. */
  unavailable: 'two_factor_unavailable',
} as const;

export type TwoFactorReason = (typeof TWO_FACTOR_REASONS)[keyof typeof TWO_FACTOR_REASONS];

/**
 * Outcome of checking one code.
 *
 * The three failing shapes exist because the caller answers them differently:
 * `failed` is an ordinary authentication error (generic Italian message),
 * `not-enrolled` is an administrative state worth naming to the user, and
 * `unavailable` is an outage of ours and must read as "try again later".
 */
export type TwoFactorOutcome =
  | { status: 'ok'; timeStep: number }
  | { status: 'failed'; reason: TwoFactorReason }
  | { status: 'not-enrolled'; reason: TwoFactorReason }
  | { status: 'unavailable'; reason: TwoFactorReason };
