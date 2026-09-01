/**
 * Optional SQL-sourced extra token claims.
 *
 * A third feature on the same `SqlDriver` seam as the group check and the TOTP
 * seed: one query, one bound parameter (the platform username), ONE row
 * expected, and the row's COLUMN NAMES become the claim names. Nothing else is
 * assumed about the query — the customer writes it, it lives only in
 * CLAIMS_SQL_QUERY, and no column name is hardcoded anywhere in this folder.
 *
 * The claims ride in the id_token and — when API_AUDIENCE is set — in the JWT
 * access token, by SERVER POLICY: no scope and no `claims` request parameter
 * can ask for them or turn them off. the same operator owns both ends of the exchange
 * and the API needs the back-office identity on every call.
 *
 * Failure policy, decided and not negotiable:
 *
 *   zero rows        the user exists in AD but is not tied to the back office.
 *                    Login: Italian refusal page. Refresh: invalid_grant WITH
 *                    the grant chain revoked. reason `claims_user_not_found`.
 *   database silent  unreachable, in error, past SQL_TIMEOUT_MS, ambiguous
 *                    (more than one row), or a row shaped differently from what
 *                    the startup analysis declared. Login and refresh alike:
 *                    temporarily_unavailable, chain INTACT — an outage of ours
 *                    must never log the whole floor out for good.
 *   NULL value       that one claim is omitted. Not `null`, not `""`: absent.
 */

/** Claim name → value, exactly as the row came back (minus the NULL columns). */
export type ExtraClaims = Record<string, unknown>;

/**
 * Where the extra claims come from. One implementation today (SQL); the shape
 * is an interface because the next customer may well read them from LDAP, and
 * then only this folder moves.
 */
export interface ExtraClaimsSource {
  readonly name: string;

  /**
   * The claim names this source will produce, known at STARTUP.
   *
   * They have to be known that early for two independent reasons: the reserved
   * name blacklist must stop the server before it ever serves a token, and
   * oidc-provider only lets a claim into an id_token if its name was declared
   * in the `claims` configuration when the Provider was constructed. Both are
   * satisfied by reading the aliases out of the SELECT list at startup.
   */
  readonly claimNames: readonly string[];

  /**
   * The user's extra claims. Throws ExtraClaimsUserNotFound when the source has
   * no row for them, and ExtraClaimsUnavailable when it could not answer at
   * all. "Could not answer" is never "no row": the first is an outage of ours,
   * the second is a fact about the user, and they get opposite treatments.
   */
  lookup(username: string): Promise<ExtraClaims>;

  /** Releases whatever the source holds open. Safe to call twice. */
  close(): Promise<void>;
}

/** Stable log tokens for everything this feature can refuse. */
export const EXTRA_CLAIMS_REASONS = {
  /** Zero rows: the AD account is not tied to a back-office user. */
  userNotFound: 'claims_user_not_found',
  /** The database could not answer, or answered past the deadline. */
  unavailable: 'claims_source_unavailable',
  /** More than one row: we would be guessing which identity is theirs. */
  ambiguousRows: 'claims_ambiguous_rows',
  /** A column came back named like a registered JWT/OIDC claim we own. */
  reservedName: 'claims_reserved_name',
  /** A column came back that the startup analysis of the query did not predict. */
  undeclaredColumn: 'claims_undeclared_column',
} as const;

export type ExtraClaimsReason =
  (typeof EXTRA_CLAIMS_REASONS)[keyof typeof EXTRA_CLAIMS_REASONS];

/**
 * Configuration of the extra claims is wrong: the query does not bind the
 * username, its output column names cannot be determined, one of them is a
 * reserved claim name, two of them collide. Raised at STARTUP, so a
 * misconfigured deployment never reaches a login.
 */
export class ExtraClaimsConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ExtraClaimsConfigError';
  }
}

/**
 * The source answered, and the answer is "this user has no row". An explicit
 * refusal, never a pass and never an empty claim set: an access token without
 * the back-office identity is a token the API cannot use.
 */
export class ExtraClaimsUserNotFound extends Error {
  readonly username: string;
  readonly reason: ExtraClaimsReason = EXTRA_CLAIMS_REASONS.userNotFound;

  constructor(username: string, message: string) {
    super(message);
    this.name = 'ExtraClaimsUserNotFound';
    this.username = username;
  }
}

/**
 * The source could not answer, or answered something we refuse to interpret.
 * Fails closed upstream as `temporarily_unavailable`, exactly like the LDAP and
 * SQL gates, and — like them — WITHOUT revoking the grant chain.
 */
export class ExtraClaimsUnavailable extends Error {
  readonly source: string;
  readonly reason: ExtraClaimsReason;

  constructor(
    source: string,
    reason: ExtraClaimsReason,
    message: string,
    cause?: unknown,
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'ExtraClaimsUnavailable';
    this.source = source;
    this.reason = reason;
  }
}
