/**
 * The production identity provider: Kerberos/SPNEGO single sign-on against
 * Active Directory, with an LDAP simple-bind password form for machines that
 * are not in the domain.
 *
 * Three decisions are worth reading before the code:
 *
 *  - **Kerberos only, never NTLM.** An NTLM token is refused outright, with the
 *    reason logged, and the challenge is *not* continued: NTLM is per-connection
 *    and breaks behind any proxy, so half-answering it would produce a
 *    handshake that can only fail later and less legibly.
 *  - **One leg.** No security context is kept between HTTP requests. Kerberos
 *    over SPNEGO completes in a single leg from every client that matters
 *    (Chromium, Edge, curl --negotiate); a GSSAPI continuation request is
 *    therefore reported and refused rather than stored.
 *  - **The form is the same door.** Once the password is verified with a simple
 *    bind as the user, the flow rejoins the SSO path exactly: same principal
 *    shape, same account gates, same claims.
 */
import type { Request, Response } from 'express';

import type { Config } from '../../config.js';
import type { Logger } from '../../logger.js';
import { renderLoginPage, renderSsoOnlyPage } from '../../views/login.js';
import { LdapDirectory, LdapUnavailableError } from '../ldap.js';
import {
  usernameFromPrincipal,
  type AuthenticationResult,
  type ChallengeOptions,
  type IdentityAccountStatus,
  type IdentityProvider,
} from '../types.js';
import { NativeGssAcceptor, type GssAcceptor } from './gss.js';
import {
  isNtlmToken,
  looksLikeBase64Token,
  parseAuthorization,
  sAMAccountNameOf,
  toBindIdentity,
  toHostBasedServiceName,
} from './negotiate.js';

export * from './negotiate.js';
export { NativeGssAcceptor, type GssAcceptor, type GssAcceptResult } from './gss.js';

export interface SpnegoIdentityProviderOptions {
  config: Config;
  logger: Logger;
  /** Injectable so the unit tests can exercise the handshake branches. */
  gss?: GssAcceptor;
  /** Injectable for the same reason. */
  directory?: LdapDirectory;
}

export class SpnegoIdentityProvider implements IdentityProvider {
  readonly name = 'spnego';

  readonly #logger: Logger;
  readonly #realm: string;
  readonly #serviceName: string;
  readonly #gss: GssAcceptor;
  readonly #directory: LdapDirectory;
  // --- phase 4-bis ---------------------------------------------------------
  /** FALLBACK_FORM_ENABLED. False = SSO-only: the challenge carries no form. */
  readonly #formEnabled: boolean;
  /** TWO_FACTOR_ENABLED. Only ever reaches the form path. */
  readonly #twoFactorEnabled: boolean;
  // --- end phase 4-bis -----------------------------------------------------

  constructor(options: SpnegoIdentityProviderOptions) {
    const { config } = options;
    this.#logger = options.logger.child({ component: 'identity.spnego' });
    this.#realm = config.realm;
    this.#serviceName = toHostBasedServiceName(config.kerberos.serviceName);
    this.#formEnabled = config.fallbackFormEnabled;
    this.#twoFactorEnabled = config.twoFactor.enabled;

    /**
     * The native krb5 library reads KRB5_KTNAME out of the process environment,
     * not from any argument we can pass it. config.ts already read the same
     * variable, so this only matters when a Config was built by hand (tests, or
     * an embedder): it keeps the two in step instead of letting the library
     * silently fall back to /etc/krb5.keytab.
     */
    if (config.kerberos.keytabPath && process.env.KRB5_KTNAME !== config.kerberos.keytabPath) {
      process.env.KRB5_KTNAME = config.kerberos.keytabPath;
    }

    this.#gss = options.gss ?? new NativeGssAcceptor(config.kerberos.serviceName, this.#logger);
    this.#directory =
      options.directory
      ?? new LdapDirectory({ config: config.ldap, realm: config.realm, logger: options.logger });

    this.#logger.info(
      {
        realm: this.#realm,
        serviceName: this.#serviceName,
        keytab: config.kerberos.keytabPath ?? process.env.KRB5_KTNAME ?? '(krb5 default)',
        ldapUrl: config.ldap.url,
        ldapBaseDn: config.ldap.baseDn,
        requiredGroup: config.ldap.requiredGroup ?? '(none)',
        fallbackForm: this.#formEnabled ? 'enabled' : 'disabled (SSO only)',
        twoFactor: this.#twoFactorEnabled ? 'enabled (form path only)' : 'disabled',
      },
      'spnego identity provider active',
    );

    if (!this.#formEnabled) {
      this.#logger.warn(
        { reason: 'fallback_form_disabled' },
        'FALLBACK_FORM_ENABLED=false: only Kerberos SSO can sign a user in, and a machine outside the domain has no way to log in at all',
      );
    }
  }

  /**
   * The directory this provider talks to. Exposed so the two-factor seed source
   * (TWO_FACTOR_SOURCE=ldap) reads the seed over the SAME service bind, with the
   * same TLS options and the same timeouts, instead of opening its own.
   */
  get directory(): LdapDirectory {
    return this.#directory;
  }

  async authenticate(req: Request, res: Response): Promise<AuthenticationResult> {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const formUsername = typeof body.username === 'string' ? body.username.trim() : '';
    const formPassword = typeof body.password === 'string' ? body.password : '';

    // The password form wins over any header: a user who deliberately typed
    // credentials is not silently logged in as whoever the ticket names.
    if (formUsername !== '' || formPassword !== '') {
      if (!this.#formEnabled) {
        // Belt and braces: the interaction router already refuses the POST when
        // the form is off, so reaching here means somebody hand-crafted a
        // request. It is refused here too rather than trusted upstream.
        this.#logger.warn(
          { username: formUsername, reason: 'fallback_form_disabled' },
          'password credentials were submitted while FALLBACK_FORM_ENABLED=false: refusing',
        );
        return { status: 'failed', reason: 'invalid_credentials', username: formUsername };
      }
      return this.#authenticateWithPassword(formUsername, formPassword);
    }

    return this.#authenticateWithNegotiate(req, res);
  }

  async #authenticateWithNegotiate(req: Request, res: Response): Promise<AuthenticationResult> {
    const parsed = parseAuthorization(req.get('authorization'));

    if (parsed === undefined) {
      return { status: 'no-credentials' };
    }
    if (parsed.scheme !== 'negotiate') {
      this.#logger.debug(
        { scheme: parsed.scheme, reason: 'unsupported_authorization_scheme' },
        'ignoring an Authorization header that is not Negotiate',
      );
      return { status: 'no-credentials' };
    }
    if (parsed.token === '') {
      this.#logger.debug({ reason: 'empty_negotiate_token' }, 'bare Negotiate header');
      return { status: 'no-credentials' };
    }

    if (isNtlmToken(parsed.token)) {
      this.#logger.warn(
        { reason: 'ntlm_not_supported', remote: req.ip },
        'the client offered NTLM; this server speaks Kerberos only, and the handshake is not continued',
      );
      return { status: 'failed', reason: 'ntlm_not_supported' };
    }

    if (!looksLikeBase64Token(parsed.token)) {
      this.#logger.warn(
        { reason: 'malformed_negotiate_token', remote: req.ip },
        'the Negotiate header did not carry a decodable token',
      );
      return { status: 'failed', reason: 'sso_failed' };
    }

    const result = await this.#gss.accept(parsed.token);

    switch (result.status) {
      case 'complete': {
        if (result.responseToken !== '') {
          // Mutual authentication: the client asked to be able to verify us.
          res.setHeader('WWW-Authenticate', `Negotiate ${result.responseToken}`);
        }
        this.#logger.info(
          { principal: result.principal, serviceName: this.#serviceName },
          'SPNEGO handshake completed',
        );
        return { status: 'authenticated', principal: result.principal, via: 'sso' };
      }

      case 'continue': {
        this.#logger.warn(
          { reason: 'spnego_multi_leg_unsupported', serviceName: this.#serviceName },
          'GSSAPI asked for another handshake leg; this server does not keep a context between requests, so the password form is offered instead',
        );
        return { status: 'failed', reason: 'sso_failed' };
      }

      case 'rejected': {
        this.#logger.warn(
          { reason: 'spnego_rejected', serviceName: this.#serviceName, detail: result.detail },
          'the Kerberos ticket was refused',
        );
        return { status: 'failed', reason: 'sso_failed' };
      }

      case 'unavailable': {
        this.#logger.error(
          {
            reason: 'spnego_acceptor_unavailable',
            serviceName: this.#serviceName,
            keytab: process.env.KRB5_KTNAME ?? '(krb5 default)',
            detail: result.detail,
          },
          'this server cannot act as the Kerberos acceptor: check the keytab, the SPN and KRB5_KTNAME',
        );
        return { status: 'failed', reason: 'temporarily_unavailable' };
      }

      default: {
        const exhaustive: never = result;
        throw new Error(`unhandled GSS result ${JSON.stringify(exhaustive)}`);
      }
    }
  }

  async #authenticateWithPassword(
    username: string,
    password: string,
  ): Promise<AuthenticationResult> {
    if (username === '' || password === '') {
      return { status: 'failed', reason: 'invalid_credentials', username };
    }

    const bindIdentity = toBindIdentity(username, this.#realm);
    if (bindIdentity === undefined) {
      this.#logger.warn(
        { username, reason: 'malformed_username' },
        'the submitted user name cannot be a domain account name',
      );
      return { status: 'failed', reason: 'invalid_credentials', username };
    }

    let check;
    try {
      check = await this.#directory.verifyCredentials(bindIdentity, password);
    } catch (error) {
      this.#logger.error(
        {
          username,
          bindIdentity,
          reason: 'ldap_unavailable',
          err: error instanceof Error ? { message: error.message } : error,
        },
        'the directory could not be reached to verify the password: refusing (fail closed)',
      );
      return { status: 'failed', reason: 'temporarily_unavailable', username };
    }

    if (!check.ok) {
      return { status: 'failed', reason: check.reason, username };
    }

    // The directory's own spelling of the account name wins over what was typed:
    // `sub` is the sAMAccountName, and in AD it may differ from the UPN prefix.
    const accountName = (check.sAMAccountName ?? sAMAccountNameOf(username)).toLowerCase();
    const principal = `${accountName}@${this.#realm}`;
    this.#logger.info({ username, bindIdentity, principal }, 'password fallback accepted');
    return { status: 'authenticated', principal, via: 'form' };
  }

  /**
   * The account-liveness half of the contract. Runs at login and, crucially, at
   * every refresh. `LdapUnavailableError` is rethrown on purpose: the gate
   * runner turns a throw into `temporarily_unavailable` without revoking the
   * grant chain, which is exactly the decided policy for a directory outage.
   */
  async inspectAccount(principal: string): Promise<IdentityAccountStatus> {
    const username = usernameFromPrincipal(principal);
    const status = await this.#directory.inspectAccount(username);
    return status.active ? { active: true } : { active: false, reason: status.reason };
  }

  async isAccountActive(principal: string): Promise<boolean> {
    const status = await this.inspectAccount(principal);
    return status.active;
  }

  async challenge(_req: Request, res: Response, options: ChallengeOptions): Promise<void> {
    /**
     * The bare challenge — no credentials seen yet — carries `Negotiate`, so a
     * domain-joined browser signs in without showing anything, plus the form in
     * the body for everyone else. A challenge that carries a *reason* does not:
     * the handshake has already been tried and answered, and repeating the
     * header would send a Kerberos client round the same failing loop instead
     * of letting the user type a password.
     */
    if (options.reason === undefined) {
      res.setHeader('WWW-Authenticate', 'Negotiate');
    }

    // --- phase 4-bis: FALLBACK_FORM_ENABLED=false => no form in the body ----
    if (!this.#formEnabled) {
      // The Negotiate header above is the ONLY thing a client can act on now.
      // A domain-joined browser answers it and never renders this body.
      res.status(401).type('html').send(renderSsoOnlyPage({ reason: options.reason }));
      return;
    }
    // --- end phase 4-bis ---------------------------------------------------

    res
      .status(401)
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
}

export { LdapDirectory, LdapUnavailableError };
