/**
 * Active Directory over LDAPS: the password fallback and the account-liveness
 * check that every login and every refresh has to pass.
 *
 * Two rules shape the whole module:
 *
 *  1. **Never fail open.** A definite "no" is returned as a value; anything we
 *     could not determine — connection refused, TLS failure, timeout, service
 *     bind rejected — is *thrown*. The gate runner turns a throw into
 *     `temporarily_unavailable` without revoking the user's grant chain, and a
 *     returned "no" into `invalid_grant` with revocation. Getting that
 *     distinction wrong is the difference between a five-minute DC outage and
 *     logging the whole floor out for good.
 *  2. **Never interpolate user input into a filter.** Searches are built from
 *     ldapts Filter objects, so a username can only ever be a value.
 *
 * A client is created per operation instead of pooled. Liveness runs once per
 * login and once per refresh (so, per user, about once an hour), and a fresh
 * LDAPS handshake costs far less than the class of bugs that comes with a
 * long-lived connection silently dropped by a firewall.
 */
import { readFile } from 'node:fs/promises';

import {
  AndFilter,
  Client,
  EqualityFilter,
  InvalidCredentialsError,
  OrFilter,
  type ClientOptions,
  type Entry,
} from 'ldapts';

import type { LdapConfig } from '../config.js';
import type { Logger } from '../logger.js';

/**
 * Outcome of checking a user's own password with a simple bind.
 *
 * `sAMAccountName` is the canonical account name read back from the directory
 * on the same connection. It matters because in Active Directory the UPN prefix
 * and the sAMAccountName are allowed to differ, and `sub` is the sAMAccountName:
 * trusting what the user typed would mint a token under the wrong name. When
 * the directory does not let the user read their own entry the field is absent
 * and the caller falls back to the typed name, which the liveness gate then
 * checks anyway.
 */
export type CredentialCheck =
  | { ok: true; sAMAccountName?: string }
  | { ok: false; reason: LdapRejectionReason };

/** Outcome of the liveness check. `reason` is a stable token for the logs. */
export type AccountStatus =
  | { active: true; dn: string }
  | { active: false; reason: LdapRejectionReason };

export type LdapRejectionReason =
  | 'invalid_credentials'
  | 'account_not_found'
  | 'account_disabled'
  | 'account_expired'
  | 'account_locked'
  | 'password_expired'
  | 'group_not_allowed';

/** ACCOUNTDISABLE, bit 2 of userAccountControl (MS-ADTS 2.2.16). */
const UF_ACCOUNTDISABLE = 0x0002;
/** LOCKOUT, bit 5. Not fatal on its own — AD clears it on its own schedule. */
const UF_LOCKOUT = 0x0010;

/** accountExpires "never" sentinels: unset, zero, or the maximum FILETIME. */
const FILETIME_NEVER = 0x7fffffffffffffffn;
/** 100-nanosecond intervals between 1601-01-01 and the Unix epoch. */
const FILETIME_EPOCH_OFFSET = 116444736000000000n;

/**
 * AD spells the real reason for a failed bind inside the diagnostic message of
 * LDAP result 49, as `data <hex>` (MS-ERREF 2.2.1 / the AcceptSecurityContext
 * sub-codes). Without this a disabled user is told "wrong password", which is
 * both untrue and the exact case phase 3 has to demonstrate.
 */
const BIND_SUBCODES: Record<string, LdapRejectionReason> = {
  '525': 'account_not_found',
  '52e': 'invalid_credentials',
  '530': 'invalid_credentials', // not permitted to log on at this time
  '531': 'invalid_credentials', // not permitted to log on at this workstation
  '532': 'password_expired',
  '533': 'account_disabled',
  '701': 'account_expired',
  '773': 'password_expired', // must change password at next logon
  '775': 'account_locked',
};

function bindRejectionReason(message: string): LdapRejectionReason {
  const match = /\bdata\s+([0-9a-f]{2,4})\b/i.exec(message);
  const code = match?.[1]?.toLowerCase().replace(/^0+(?=.)/, '');
  return (code && BIND_SUBCODES[code]) || 'invalid_credentials';
}

function firstValue(entry: Entry, attribute: string): string | undefined {
  const value = entry[attribute];
  if (value === undefined) return undefined;
  if (Array.isArray(value)) {
    const first = value[0];
    return first === undefined ? undefined : String(first);
  }
  return String(value);
}

function allValues(entry: Entry, attribute: string): string[] {
  const value = entry[attribute];
  if (value === undefined) return [];
  return (Array.isArray(value) ? value : [value]).map((item) => String(item));
}

/** True when accountExpires names a moment that has already passed. */
export function accountExpired(raw: string | undefined, now: number = Date.now()): boolean {
  if (raw === undefined || raw === '') return false;
  let filetime: bigint;
  try {
    filetime = BigInt(raw);
  } catch {
    // An unparsable value is not evidence of expiry; the caller keeps a loud log
    // of the raw attribute so a malformed directory shows up in the record.
    return false;
  }
  if (filetime <= 0n || filetime >= FILETIME_NEVER) return false;
  const epochMs = Number((filetime - FILETIME_EPOCH_OFFSET) / 10000n);
  return epochMs <= now;
}

/** Case-insensitive, whitespace-tolerant DN comparison. Good enough for memberOf. */
function sameDn(a: string, b: string): boolean {
  const normalise = (dn: string): string =>
    dn
      .split(',')
      .map((part) => part.trim().toLowerCase())
      .join(',');
  return normalise(a) === normalise(b);
}

export interface LdapDirectoryOptions {
  config: LdapConfig;
  realm: string;
  logger: Logger;
}

/** Thrown when the directory could not answer. Always fails closed upstream. */
export class LdapUnavailableError extends Error {
  constructor(operation: string, cause: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    super(`LDAP ${operation} failed: ${detail}`);
    this.name = 'LdapUnavailableError';
    this.cause = cause;
  }
}

export class LdapDirectory {
  readonly #config: LdapConfig;
  readonly #logger: Logger;
  /** Read once and cached: the CA bundle for LDAP_TLS_CA_FILE. */
  #caPromise?: Promise<Buffer | undefined>;

  constructor(options: LdapDirectoryOptions) {
    this.#config = options.config;
    this.#logger = options.logger.child({ component: 'identity.ldap' });

    if (this.#config.tlsInsecure) {
      this.#logger.warn(
        { url: this.#config.url, reason: 'ldap_tls_insecure' },
        'LDAP_TLS_INSECURE=true: the directory certificate is NOT verified. Laboratory only — in production set LDAP_TLS_CA_FILE to the domain CA instead',
      );
    }
  }

  async #ca(): Promise<Buffer | undefined> {
    const file = this.#config.tlsCaFile;
    if (file === undefined) return undefined;
    this.#caPromise ??= readFile(file).catch((error: unknown) => {
      // A CA file that cannot be read is a configuration fault, and silently
      // continuing would mean verifying against the system store instead.
      throw new Error(`LDAP_TLS_CA_FILE ${file} could not be read: ${String(error)}`);
    });
    return this.#caPromise;
  }

  async #clientOptions(): Promise<ClientOptions> {
    const ca = await this.#ca();
    return {
      url: this.#config.url ?? '',
      timeout: this.#config.timeoutMs,
      connectTimeout: this.#config.connectTimeoutMs,
      tlsOptions: {
        rejectUnauthorized: !this.#config.tlsInsecure,
        ...(ca ? { ca } : {}),
        ...(this.#config.tlsServername ? { servername: this.#config.tlsServername } : {}),
      },
    };
  }

  /** Runs `work` against a freshly connected client and always unbinds. */
  async #withClient<T>(operation: string, work: (client: Client) => Promise<T>): Promise<T> {
    let client: Client;
    try {
      client = new Client(await this.#clientOptions());
    } catch (error) {
      throw new LdapUnavailableError(operation, error);
    }
    try {
      return await work(client);
    } finally {
      await client.unbind().catch((error: unknown) => {
        this.#logger.debug({ operation, err: { message: String(error) } }, 'LDAP unbind failed');
      });
    }
  }

  /**
   * Verifies a user's own password with a simple bind, as the user. This is the
   * out-of-domain fallback: no kinit on the server, no keytab involvement, and
   * the same yes/no the KDC would have given.
   */
  async verifyCredentials(bindIdentity: string, password: string): Promise<CredentialCheck> {
    if (password === '') {
      // An LDAP bind with an empty password is an *anonymous* bind and succeeds.
      // It must never be mistaken for a correct password.
      return { ok: false, reason: 'invalid_credentials' };
    }

    return this.#withClient('simple bind', async (client) => {
      try {
        await client.bind(bindIdentity, password);
      } catch (error) {
        if (error instanceof InvalidCredentialsError) {
          const reason = bindRejectionReason(error.message);
          this.#logger.warn(
            { bindIdentity, reason, ldapMessage: error.message },
            'LDAP simple bind refused the credentials',
          );
          return { ok: false, reason };
        }
        throw new LdapUnavailableError('simple bind', error);
      }

      return { ok: true, sAMAccountName: await this.#readOwnAccountName(client, bindIdentity) };
    });
  }

  /**
   * Reads the canonical sAMAccountName of the account that just bound, on the
   * connection it bound with. A failure here is not fatal: it only costs the
   * caller the fallback to the typed name.
   */
  async #readOwnAccountName(client: Client, bindIdentity: string): Promise<string | undefined> {
    const at = bindIdentity.indexOf('@');
    const local = at === -1 ? bindIdentity : bindIdentity.slice(0, at);
    try {
      const { searchEntries } = await client.search(this.#config.baseDn ?? '', {
        scope: 'sub',
        sizeLimit: 2,
        filter: new AndFilter({
          filters: [
            new EqualityFilter({ attribute: 'objectClass', value: 'user' }),
            new OrFilter({
              filters: [
                new EqualityFilter({ attribute: 'userPrincipalName', value: bindIdentity }),
                new EqualityFilter({ attribute: 'sAMAccountName', value: local }),
              ],
            }),
          ],
        }),
        attributes: ['sAMAccountName'],
      });
      if (searchEntries.length !== 1) return undefined;
      return firstValue(searchEntries[0]!, 'sAMAccountName');
    } catch (error) {
      this.#logger.debug(
        { bindIdentity, err: { message: String(error) } },
        'could not read back the canonical sAMAccountName after the user bind',
      );
      return undefined;
    }
  }

  /**
   * Binds as the service account. Its own credentials being wrong is a
   * configuration fault of ours, never a verdict about the user: fail closed,
   * loudly, on every operation that needs the service bind.
   */
  async #serviceBind(client: Client): Promise<void> {
    const { bindDn, bindPassword } = this.#config;
    try {
      await client.bind(bindDn ?? '', bindPassword ?? '');
    } catch (error) {
      this.#logger.error(
        { bindDn, reason: 'service_bind_failed', err: { message: String(error) } },
        'the LDAP service account could not bind: every account check will fail closed until this is fixed',
      );
      throw new LdapUnavailableError('service bind', error);
    }
  }

  /** One user entry by sAMAccountName under LDAP_BASE_DN. Throws when unreachable. */
  async #searchUser(
    client: Client,
    sAMAccountName: string,
    attributes: string[],
    operation: string,
  ): Promise<Entry[]> {
    try {
      const result = await client.search(this.#config.baseDn ?? '', {
        scope: 'sub',
        sizeLimit: 2,
        filter: new AndFilter({
          filters: [
            new EqualityFilter({ attribute: 'objectClass', value: 'user' }),
            new EqualityFilter({ attribute: 'sAMAccountName', value: sAMAccountName }),
          ],
        }),
        attributes,
      });
      return result.searchEntries;
    } catch (error) {
      throw new LdapUnavailableError(operation, error);
    }
  }

  /**
   * Phase 4-bis: reads ONE attribute off a user's record with the service bind.
   *
   * It exists so the two-factor seed source does not open its own connection to
   * the same directory with the same credentials — the connection, the TLS
   * options, the timeouts and the fail-closed discipline all stay in this class.
   *
   * `undefined` means the entry has no such attribute (or there is no entry);
   * a directory that cannot answer throws, as everywhere else here.
   */
  async readUserAttribute(
    sAMAccountName: string,
    attribute: string,
  ): Promise<string | undefined> {
    return this.#withClient('attribute lookup', async (client) => {
      await this.#serviceBind(client);
      const entries = await this.#searchUser(
        client,
        sAMAccountName,
        // distinguishedName is asked for only so the log can name the entry.
        ['distinguishedName', attribute],
        'attribute search',
      );

      if (entries.length !== 1) {
        this.#logger.warn(
          {
            username: sAMAccountName,
            baseDn: this.#config.baseDn,
            attribute,
            matches: entries.length,
            reason: entries.length === 0 ? 'account_not_found' : 'ambiguous_account',
          },
          'the attribute could not be read: the account name does not match exactly one entry',
        );
        return undefined;
      }

      const entry = entries[0]!;
      const value = firstValue(entry, attribute);
      this.#logger.debug(
        {
          username: sAMAccountName,
          dn: firstValue(entry, 'distinguishedName') ?? String(entry.dn ?? ''),
          attribute,
          present: value !== undefined,
        },
        'read a user attribute with the service bind',
      );
      return value;
    });
  }

  /**
   * Account liveness, by sAMAccountName, under LDAP_BASE_DN, with the service
   * credentials. Returns a verdict; throws when it could not reach a verdict.
   */
  async inspectAccount(sAMAccountName: string): Promise<AccountStatus> {
    const { baseDn, requiredGroup } = this.#config;

    return this.#withClient('account lookup', async (client) => {
      await this.#serviceBind(client);

      const entries = await this.#searchUser(
        client,
        sAMAccountName,
        [
          'distinguishedName',
          'sAMAccountName',
          'userPrincipalName',
          'userAccountControl',
          'accountExpires',
          'memberOf',
        ],
        'account search',
      );

      if (entries.length === 0) {
        this.#logger.warn(
          { username: sAMAccountName, baseDn, reason: 'account_not_found' },
          'no directory entry for the account',
        );
        return { active: false, reason: 'account_not_found' };
      }
      if (entries.length > 1) {
        // Two accounts with the same sAMAccountName cannot happen in one domain;
        // if it does, we do not get to guess which one the token belongs to.
        this.#logger.error(
          { username: sAMAccountName, baseDn, matches: entries.length },
          'more than one directory entry matches the account name: refusing',
        );
        return { active: false, reason: 'account_not_found' };
      }

      const entry = entries[0]!;
      const dn = firstValue(entry, 'distinguishedName') ?? String(entry.dn ?? '');
      const uacRaw = firstValue(entry, 'userAccountControl');
      const uac = Number(uacRaw ?? '0');
      const expiresRaw = firstValue(entry, 'accountExpires');

      if (!Number.isFinite(uac)) {
        this.#logger.error(
          { username: sAMAccountName, dn, userAccountControl: uacRaw },
          'userAccountControl is not a number: refusing',
        );
        return { active: false, reason: 'account_disabled' };
      }

      if ((uac & UF_ACCOUNTDISABLE) !== 0) {
        this.#logger.warn(
          { username: sAMAccountName, dn, userAccountControl: uac, reason: 'account_disabled' },
          'the directory reports the account as disabled',
        );
        return { active: false, reason: 'account_disabled' };
      }

      if (accountExpired(expiresRaw)) {
        this.#logger.warn(
          { username: sAMAccountName, dn, accountExpires: expiresRaw, reason: 'account_expired' },
          'the directory reports the account as expired',
        );
        return { active: false, reason: 'account_expired' };
      }

      if ((uac & UF_LOCKOUT) !== 0) {
        // Reported, not enforced: AD leaves this bit set until the lockout
        // window elapses, so treating it as fatal would lock users out longer
        // than the domain policy says.
        this.#logger.info(
          { username: sAMAccountName, dn, userAccountControl: uac },
          'the LOCKOUT bit is set on the account (not enforced here)',
        );
      }

      if (requiredGroup !== undefined) {
        const groups = allValues(entry, 'memberOf');
        if (!groups.some((group) => sameDn(group, requiredGroup))) {
          this.#logger.warn(
            {
              username: sAMAccountName,
              dn,
              requiredGroup,
              memberOf: groups,
              reason: 'group_not_allowed',
            },
            'the account is not a member of LDAP_REQUIRED_GROUP',
          );
          return { active: false, reason: 'group_not_allowed' };
        }
      }

      this.#logger.debug(
        { username: sAMAccountName, dn, userAccountControl: uac, accountExpires: expiresRaw },
        'the directory reports the account as active',
      );
      return { active: true, dn };
    });
  }
}
