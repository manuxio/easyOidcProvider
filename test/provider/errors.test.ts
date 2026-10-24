/**
 * TemporarilyUnavailable (src/provider/errors.ts): the token-endpoint error for
 * "the account (or the subject token) could not be verified". Rejecting is the
 * decided policy — never fail open, and always say why — so the error has to
 * reach the client as a proper OAuth error body, not as a 500.
 *
 * The end-to-end answers that carry it are in test/e2e.test.ts (gate silent at
 * refresh) and test/tokenExchange.test.ts (registry silent).
 */
import { errors } from 'oidc-provider';
import { describe, expect, it } from 'vitest';

import { TemporarilyUnavailable } from '../../src/provider/errors.js';

describe('TemporarilyUnavailable', () => {
  it('is an oidc-provider error with the temporarily_unavailable code and the given description', () => {
    const error = new TemporarilyUnavailable('the account could not be verified; try again later');
    expect(error).toBeInstanceOf(errors.CustomOIDCProviderError);
    expect(error).toBeInstanceOf(errors.OIDCProviderError);
    expect(error).toBeInstanceOf(Error);
    expect(error.error).toBe('temporarily_unavailable');
    expect(error.message).toBe('temporarily_unavailable');
    expect(error.error_description).toBe('the account could not be verified; try again later');
    expect(error.name).toBe('TemporarilyUnavailable');
  });

  it('answers 400 and is exposed to the client (not a server error)', () => {
    const error = new TemporarilyUnavailable('x');
    expect(error.status).toBe(400);
    expect(error.statusCode).toBe(400);
    expect(error.expose).toBe(true);
  });

  it('keeps each description to itself', () => {
    const a = new TemporarilyUnavailable('a');
    const b = new TemporarilyUnavailable('b');
    expect([a.error_description, b.error_description]).toEqual(['a', 'b']);
  });
});
