/**
 * `database` identity provider: username and password verified against a
 * customer database — SQL through the shared driver, or an external MongoDB.
 * The third alternative next to `spnego` (Kerberos/AD) and `dev-stub`.
 *
 * One door only, the form. That has two structural consequences:
 *  - the optional TOTP second factor applies here whenever it is enabled,
 *    because the interaction router keys it to `via: 'form'`, not to the
 *    provider;
 *  - FALLBACK_FORM_ENABLED=false is refused at startup (config.ts): with no
 *    SSO to fall back FROM, the form is the only way in.
 *
 * Failure discipline, in order of what the user learns:
 *  - unknown user            → one dummy verification of the SAME scheme is
 *                              burned (no timing enumeration), then
 *                              `invalid_credentials`;
 *  - wrong password, wrong or missing hash format
 *                            → `invalid_credentials` (the log says which);
 *  - right password, inactive account
 *                            → `account_disabled` — only ever said AFTER the
 *                              password was verified, so it enumerates nothing;
 *  - store unreachable       → `temporarily_unavailable`, fail closed.
 */
import type { Request, Response } from 'express';

import type { Config } from '../../config.js';
import type { Logger } from '../../logger.js';
import { renderLoginPage } from '../../views/login.js';
import {
  usernameFromPrincipal,
  type AuthenticationResult,
  type ChallengeOptions,
  type IdentityProvider,
} from '../types.js';
import { dummyVerify, verifyPassword, type PasswordScheme } from './passwords.js';
import { CredentialStoreUnavailable, type CredentialStore } from './store.js';

export { PASSWORD_SCHEMES, isPasswordScheme, type PasswordScheme } from './passwords.js';
export {
  CredentialStoreUnavailable,
  type CredentialRecord,
  type CredentialStore,
} from './store.js';
export { createSqlCredentialStore, AUTH_SQL_QUERY_PARAMETER } from './sqlStore.js';
export { createMongoCredentialStore } from './mongoStore.js';

export interface DatabaseIdentityProviderOptions {
  config: Config;
  store: CredentialStore;
  logger: Logger;
}

export class DatabaseIdentityProvider implements IdentityProvider {
  readonly name = 'database';

  readonly #store: CredentialStore;
  readonly #scheme: PasswordScheme;
  readonly #realm: string;
  readonly #twoFactorEnabled: boolean;
  readonly #logger: Logger;

  constructor(options: DatabaseIdentityProviderOptions) {
    this.#store = options.store;
    this.#scheme = options.config.databaseAuth.passwordScheme;
    this.#realm = options.config.realm;
    this.#twoFactorEnabled = options.config.twoFactor.enabled;
    this.#logger = options.logger.child({ component: 'identity.database' });
    this.#logger.info(
      { store: this.#store.name, passwordScheme: this.#scheme, realm: this.#realm || '(none)' },
      'database identity provider active: credentials come from the configured store, form path only',
    );
    if (this.#scheme === 'plain') {
      this.#logger.warn(
        {},
        'AUTH_PASSWORD_SCHEME=plain: the store holds passwords in CLEAR TEXT — every layer of this server treats that as a temporary state, not a design',
      );
    }
  }

  async authenticate(req: Request): Promise<AuthenticationResult> {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';

    if (username === '' || password === '') {
      return { status: 'no-credentials' };
    }

    const normalized = username.toLowerCase();

    let record;
    try {
      record = await this.#store.lookup(normalized);
    } catch (error) {
      const unavailable = error instanceof CredentialStoreUnavailable;
      this.#logger.error(
        { username: normalized, err: { message: describe(error) } },
        unavailable
          ? 'credential store unavailable: rejecting (fail closed)'
          : 'credential lookup failed unexpectedly: rejecting (fail closed)',
      );
      return { status: 'failed', reason: 'temporarily_unavailable', username };
    }

    if (!record) {
      // Same time, same answer as a wrong password: burn one verification.
      await dummyVerify(this.#scheme);
      this.#logger.warn(
        { username: normalized, reason: 'account_not_found' },
        'login rejected',
      );
      return { status: 'failed', reason: 'invalid_credentials', username };
    }

    const verdict = await verifyPassword(password, record.passwordHash, this.#scheme, {
      ...(record.salt !== undefined ? { salt: record.salt } : {}),
    });
    if (!verdict.ok) {
      // scheme_mismatch and malformed_hash are OUR data problems and get said
      // plainly in the log; the page still answers "credenziali non corrette".
      this.#logger.warn(
        { username: normalized, reason: verdict.reason, passwordScheme: this.#scheme },
        'login rejected',
      );
      return { status: 'failed', reason: 'invalid_credentials', username };
    }

    if (!record.active) {
      this.#logger.warn({ username: normalized, reason: 'account_disabled' }, 'login rejected');
      return { status: 'failed', reason: 'account_disabled', username };
    }

    return {
      status: 'authenticated',
      principal: this.#realm === '' ? normalized : `${normalized}@${this.#realm}`,
      via: 'form',
    };
  }

  async isAccountActive(principal: string): Promise<boolean> {
    // Called at login AND at every refresh. A store that cannot answer throws,
    // and the gate treats "cannot tell" as a rejection, never as a pass.
    const record = await this.#store.lookup(usernameFromPrincipal(principal));
    return record !== undefined && record.active;
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
          twoFactor: this.#twoFactorEnabled,
        }),
      );
  }

  async close(): Promise<void> {
    await this.#store.close();
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
