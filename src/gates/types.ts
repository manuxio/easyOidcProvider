/**
 * Account gates: the authorization checks re-run at login AND at every refresh.
 *
 * The refresh is the enforcement point of the whole design. A Kerberos ticket
 * only proves the user *was* valid when the browser cached it (up to ~10 h), so
 * every gate has to run again on each refresh grant.
 *
 * Phase 1 registers one gate (account liveness through the IdentityProvider).
 * Phase 3 swaps in the LDAP-backed liveness gate; phase 4 appends the optional
 * SQL group gate. Nothing else in the codebase needs to change: the gate list is
 * the seam.
 */

export type GateStage = 'login' | 'refresh';

export interface AccountGateContext {
  /** The AD principal, user@REALM. */
  principal: string;
  /** sAMAccountName lowercased: the `sub` claim and the platform username. */
  username: string;
  stage: GateStage;
  clientId?: string;
}

export type AccountGateResult =
  | { allowed: true }
  /** `reason` is a stable token that ends up in the logs, e.g. `account_disabled`. */
  | { allowed: false; reason: string };

export interface AccountGate {
  readonly name: string;
  check(context: AccountGateContext): Promise<AccountGateResult>;
  /**
   * Releases whatever the gate holds open — the SQL connection pool of the
   * phase-4 gate, an LDAP pool later. Optional: most gates hold nothing.
   */
  close?(): Promise<void>;
}

export type AccountGateVerdict =
  | { ok: true }
  /**
   * `unavailable` distinguishes "we know the account is not allowed" from
   * "we could not find out". Both reject — never fail open — but the second
   * must not revoke the user's grant chain over an outage of ours.
   */
  | { ok: false; reason: string; gate: string; unavailable: boolean };
