/**
 * Development identity provider: fixed users from DEV_STUB_USERS, a plain login
 * form, and an `active` flag so tests (and manual demos) can disable an account
 * and watch the next refresh get rejected.
 *
 * Never wire this in production: IDENTITY_PROVIDER=spnego is the real one (phase 3).
 */
import { timingSafeEqual } from 'node:crypto';
import type { Request, Response } from 'express';

import type { Config, DevStubUser } from '../config.js';
import type { Logger } from '../logger.js';
import { renderLoginPage } from '../views/login.js';
import {
  type AuthenticationResult,
  type ChallengeOptions,
  type IdentityProvider,
  usernameFromPrincipal,
} from './types.js';

function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) {
    // Still burn a comparison so a length mismatch is not measurably faster.
    timingSafeEqual(left, left);
    return false;
  }
  return timingSafeEqual(left, right);
}

export class DevStubIdentityProvider implements IdentityProvider {
  readonly name = 'dev-stub';

  readonly #users = new Map<string, DevStubUser>();
  readonly #realm: string;
  readonly #logger: Logger;
  /** Phase 4-bis: whether the form carries the "Codice di verifica" field. */
  readonly #twoFactorEnabled: boolean;

  constructor(config: Config, logger: Logger) {
    this.#realm = config.devStubRealm;
    this.#twoFactorEnabled = config.twoFactor.enabled;
    this.#logger = logger.child({ component: 'identity.dev-stub' });
    for (const user of config.devStubUsers) {
      this.#users.set(user.username.toLowerCase(), { ...user });
    }
    this.#logger.warn(
      { users: [...this.#users.keys()], realm: this.#realm },
      'dev-stub identity provider active: passwords come from DEV_STUB_USERS, not from Active Directory',
    );
  }

  async authenticate(req: Request): Promise<AuthenticationResult> {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';

    if (username === '' || password === '') {
      return { status: 'no-credentials' };
    }

    const user = this.#users.get(username.toLowerCase());
    if (!user || !constantTimeEquals(user.password, password)) {
      this.#logger.warn({ username, reason: 'invalid_credentials' }, 'login rejected');
      return { status: 'failed', reason: 'invalid_credentials', username };
    }
    if (!user.active) {
      this.#logger.warn({ username, reason: 'account_disabled' }, 'login rejected');
      return { status: 'failed', reason: 'account_disabled', username };
    }

    // dev-stub has one door and it is the form, so the second factor (which is
    // form-only) always applies here.
    return {
      status: 'authenticated',
      principal: `${user.username.toLowerCase()}@${this.#realm}`,
      via: 'form',
    };
  }

  async isAccountActive(principal: string): Promise<boolean> {
    const user = this.#users.get(usernameFromPrincipal(principal));
    return user !== undefined && user.active;
  }

  async challenge(_req: Request, res: Response, options: ChallengeOptions): Promise<void> {
    res
      .status(options.reason ? 401 : 200)
      .type('html')
      .send(
        renderLoginPage({
          action: `/interaction/${encodeURIComponent(options.interactionUid)}/login`,
          reason: options.reason,
          username: options.username,
          // Phase 4-bis: config.ts refuses FALLBACK_FORM_ENABLED=false with
          // dev-stub, so the form is always rendered here; only the second
          // factor field is conditional.
          twoFactor: this.#twoFactorEnabled,
        }),
      );
  }

  /**
   * Development/test affordance, not part of IdentityProvider: flips the `active`
   * flag so the refresh-time enforcement can be exercised without an AD.
   */
  setActive(username: string, active: boolean): void {
    const user = this.#users.get(username.toLowerCase());
    if (!user) {
      throw new Error(`dev-stub has no user ${JSON.stringify(username)}`);
    }
    user.active = active;
    this.#logger.warn({ username, active }, 'dev-stub account flag changed');
  }
}
