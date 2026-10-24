/**
 * Phase 4-ter: the reserved claim names themselves (src/claims/reserved.ts).
 *
 * query.test.ts proves the blacklist stops the server through the startup
 * parse of CLAIMS_SQL_QUERY; this file pins the list and the two helpers on
 * their own:
 *
 *  - the four groups of the header (RFC 7519 §4.1, what oidc-provider writes,
 *    our own AD claims, the RFC 8693 delegation claims) are all in the list;
 *  - `name` is NOT reserved (OIDC Core §5.1, used in its own meaning);
 *  - the comparison ignores case and surrounding blanks;
 *  - the refusal names the claim, the whole list and where it was caught.
 */
import { describe, expect, it } from 'vitest';

import {
  assertClaimNameAllowed,
  ExtraClaimsConfigError,
  isReservedClaimName,
  RESERVED_CLAIM_NAMES,
} from '../../src/claims/index.js';

describe('the reserved list', () => {
  it('holds the registered JWT claims of RFC 7519 §4.1', () => {
    expect(RESERVED_CLAIM_NAMES).toEqual(
      expect.arrayContaining(['sub', 'iss', 'aud', 'exp', 'nbf', 'iat', 'jti']),
    );
  });

  it('holds the claims oidc-provider writes on its own', () => {
    expect(RESERVED_CLAIM_NAMES).toEqual(
      expect.arrayContaining(['auth_time', 'azp', 'client_id', 'scope', 'sid']),
    );
  });

  it("holds this server's own AD claims and the RFC 8693 delegation claims", () => {
    expect(RESERVED_CLAIM_NAMES).toEqual(
      expect.arrayContaining(['realm', 'preferred_username', 'act', 'may_act']),
    );
  });

  it('has no duplicates, whatever the case', () => {
    const lowered = RESERVED_CLAIM_NAMES.map((claim) => claim.toLowerCase());
    expect(new Set(lowered).size).toBe(lowered.length);
  });

  it('leaves `name` out: it is a standard OIDC claim used in its own meaning', () => {
    expect(RESERVED_CLAIM_NAMES).not.toContain('name');
    expect(isReservedClaimName('name')).toBe(false);
  });
});

describe('isReservedClaimName', () => {
  it('recognises every entry of the list', () => {
    for (const claim of RESERVED_CLAIM_NAMES) {
      expect(isReservedClaimName(claim), claim).toBe(true);
    }
  });

  it('ignores case and surrounding blanks', () => {
    expect(isReservedClaimName('SUB')).toBe(true);
    expect(isReservedClaimName('  Preferred_Username ')).toBe(true);
    expect(isReservedClaimName('\tMay_Act\n')).toBe(true);
  });

  it('does not match a name that merely contains a reserved one', () => {
    for (const claim of ['subject', 'sub_id', 'issuer', 'remoteId', 'actor', 'scopes', 'my_realm', '']) {
      expect(isReservedClaimName(claim), claim).toBe(false);
    }
  });
});

describe('assertClaimNameAllowed', () => {
  it('lets an ordinary claim name through', () => {
    expect(() => assertClaimNameAllowed('remoteId', 'startup')).not.toThrow();
    expect(() => assertClaimNameAllowed('name', 'startup')).not.toThrow();
  });

  it('throws ExtraClaimsConfigError naming the claim, the list and where it was caught', () => {
    let failure: unknown;
    try {
      assertClaimNameAllowed('Sub', 'first execution');
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(ExtraClaimsConfigError);
    const message = (failure as Error).message;
    expect((failure as Error).name).toBe('ExtraClaimsConfigError');
    // The claim exactly as written, so the operator finds it in the query.
    expect(message).toContain('the claim "Sub", which is reserved');
    expect(message).toContain(`(${RESERVED_CLAIM_NAMES.join(', ')})`);
    expect(message).toMatch(/\[first execution\]$/);
    expect(message).toContain('CLAIMS_SQL_QUERY');
  });
});
