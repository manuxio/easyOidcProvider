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

/**
 * `token_exchange`: the gates run again before a person's token is traded for
 * a delegated one (RFC 8693), exactly as before a refresh.
 *
 * `authorization` (1.3.0): the authorization endpoint hands a code to a client
 * restricted by `required_ldap_groups` on a session opened by ANOTHER client
 * (SSO reuse), so no login — and so no gate — ran for this client. See
 * loadExistingGrant in src/provider/index.ts.
 */
export type GateStage = 'login' | 'refresh' | 'token_exchange' | 'authorization';

export interface AccountGateContext {
  /** The AD principal, user@REALM. */
  principal: string;
  /** sAMAccountName lowercased: the `sub` claim and the platform username. */
  username: string;
  stage: GateStage;
  clientId?: string;
  /**
   * `token_exchange` only: the client the person's subject token was issued
   * to. `clientId` is then the exchanging service, which has no person of its
   * own, while the authority being traded in is what the person obtained
   * through THIS client — so its restrictions apply to the trade too.
   */
  subjectClientId?: string;
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
