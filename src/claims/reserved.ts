/**
 * The reserved claim names.
 *
 * A claim is reserved when something other than the customer's query decides
 * what it means. Three groups, and each one is here for its own reason:
 *
 *  - the registered JWT claims (RFC 7519 §4.1): `sub`, `iss`, `aud`, `exp`,
 *    `nbf`, `iat`, `jti`. A column aliased `sub` would be an attempt — deliberate
 *    or accidental — to say who the token is about;
 *  - the OIDC/OAuth claims this server or oidc-provider puts in a token on its
 *    own: `auth_time`, `azp`, `client_id`, `scope`, `sid`;
 *  - the two claims that are OURS: `realm` and `preferred_username`, both
 *    emitted from the AD identity, both documented in the claim catalogue.
 *
 * `name` is NOT reserved. It is a registered OIDC claim (Core §5.1, "End-User's
 * full name in displayable form") and the customer's query uses it in exactly
 * that meaning, so letting it through is using the standard, not shadowing it.
 *
 * The comparison is case-insensitive. `SUB` and `sub` are two different JSON
 * keys, so a column aliased `SUB` would not actually shadow anything — but
 * nobody writes that on purpose, and a claim catalogue with both in it is a
 * catalogue nobody can read.
 */
import { ExtraClaimsConfigError } from './types.js';

export const RESERVED_CLAIM_NAMES: readonly string[] = [
  // RFC 7519 §4.1 registered claim names.
  'sub',
  'iss',
  'aud',
  'exp',
  'nbf',
  'iat',
  'jti',
  // Emitted by oidc-provider itself in id tokens and JWT access tokens.
  'auth_time',
  'azp',
  'client_id',
  'scope',
  'sid',
  // This server's own claims, from the Active Directory identity.
  'realm',
  'preferred_username',
];

const RESERVED_LOWERCASE: ReadonlySet<string> = new Set(
  RESERVED_CLAIM_NAMES.map((claim) => claim.toLowerCase()),
);

export function isReservedClaimName(name: string): boolean {
  return RESERVED_LOWERCASE.has(name.trim().toLowerCase());
}

/**
 * Throws ExtraClaimsConfigError naming the offending claim.
 *
 * `where` says which half of the enforcement caught it, because the two are
 * genuinely different events: at startup it is a query nobody has run yet, at
 * first execution it is a database that returned a column the query text did
 * not predict.
 */
export function assertClaimNameAllowed(name: string, where: string): void {
  if (isReservedClaimName(name)) {
    throw new ExtraClaimsConfigError(
      `CLAIMS_SQL_QUERY produces the claim ${JSON.stringify(name)}, which is reserved `
      + `(${RESERVED_CLAIM_NAMES.join(', ')}); rename the column with a different alias `
      + `[${where}]`,
    );
  }
}
