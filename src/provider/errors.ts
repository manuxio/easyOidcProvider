/**
 * Token-endpoint errors of our own, shared by the provider wiring and the
 * token exchange handler.
 */
import { errors } from 'oidc-provider';

/**
 * Custom token-endpoint error for "we could not verify the account" (or the
 * subject token registry could not answer). Rejecting is the decided policy:
 * never fail open, and always say why.
 */
export class TemporarilyUnavailable extends errors.CustomOIDCProviderError {
  constructor(description: string) {
    super('temporarily_unavailable', description);
  }
}
