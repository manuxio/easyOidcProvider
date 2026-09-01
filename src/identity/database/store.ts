/**
 * Where the `database` identity provider reads its credentials from.
 *
 * The contract is one lookup: the record for a username, or undefined when the
 * store has never heard of them. What "active" means is the STORE's business —
 * for SQL the customer's query embodies the policy (a WHERE clause decides who
 * exists), for Mongo an optional boolean field does — so the provider never
 * interprets raw data, it reads a verdict.
 */

export interface CredentialRecord {
  /** The stored password verifier, in whatever scheme AUTH_PASSWORD_SCHEME says. */
  passwordHash: string;
  /** Per-user salt for the digest schemes; undefined for self-describing ones. */
  salt?: string;
  /** Account usable right now. Checked at login AND at every refresh. */
  active: boolean;
  /** Base32 TOTP seed, when the store also carries the second factor. */
  totpSeed?: string;
}

export interface CredentialStore {
  readonly name: string;

  /**
   * The record, or undefined when the username is unknown. Throws
   * CredentialStoreUnavailable when the store cannot answer — the caller turns
   * that into `temporarily_unavailable`, never into a pass and never into
   * "wrong password".
   */
  lookup(username: string): Promise<CredentialRecord | undefined>;

  /** Releases whatever the store holds open. Safe to call twice. */
  close(): Promise<void>;
}

/** The store could not answer: unreachable, timed out, query refused. */
export class CredentialStoreUnavailable extends Error {
  readonly store: string;

  constructor(store: string, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'CredentialStoreUnavailable';
    this.store = store;
  }
}
