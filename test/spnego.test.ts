/**
 * Unit tests for everything the SPNEGO provider decides *before* it reaches the
 * native GSSAPI binding or the directory: header parsing, NTLM detection, SPN
 * normalisation, principal mapping, the challenge shape, and the two policies
 * that must not regress — NTLM is refused without continuing the handshake, and
 * a directory outage is a rejection, never a pass.
 *
 * The GSS acceptor and the LDAP directory are injected as fakes, so this file
 * runs on a machine with no Kerberos runtime and no domain controller. The real
 * handshake is proved on the wire by `lab/test-sso.sh`.
 */
import { describe, expect, it } from 'vitest';

import { loadConfig, type Config } from '../src/config.js';
import type { LdapDirectory } from '../src/identity/ldap.js';
import { accountExpired } from '../src/identity/ldap.js';
import { SpnegoIdentityProvider } from '../src/identity/spnego/index.js';
import type { GssAcceptResult, GssAcceptor } from '../src/identity/spnego/gss.js';
import {
  isNtlmToken,
  looksLikeBase64Token,
  parseAuthorization,
  sAMAccountNameOf,
  toBindIdentity,
  toHostBasedServiceName,
} from '../src/identity/spnego/negotiate.js';
import { asChallengeReason, realmFromPrincipal, usernameFromPrincipal } from '../src/identity/types.js';
import { createSilentLogger } from '../src/logger.js';

const REALM = 'LAB.EASYOIDC.LOCAL';

function spnegoConfig(overrides: Record<string, string> = {}): Config {
  return loadConfig({
    ISSUER_URL: 'http://auth.lab.easyoidc.local:3000',
    DATA_DIR: '',
    IDENTITY_PROVIDER: 'spnego',
    REALM,
    LDAP_URL: 'ldaps://dc1.lab.easyoidc.local',
    LDAP_BIND_DN: `svc-auth@${REALM}`,
    LDAP_BIND_PASSWORD: 'Svc.Passw0rd!',
    LDAP_BASE_DN: 'DC=lab,DC=easyoidc,DC=local',
    CLIENTS_JSON: JSON.stringify([
      { client_id: 'desktop-app', redirect_uris: ['http://127.0.0.1/callback'] },
    ]),
    ...overrides,
  });
}

/** Minimal express Request/Response doubles: only what the provider touches. */
function fakeRequest(options: { authorization?: string; body?: unknown } = {}) {
  return {
    ip: '203.0.113.7',
    body: options.body,
    get(name: string): string | undefined {
      return name.toLowerCase() === 'authorization' ? options.authorization : undefined;
    },
  } as never;
}

function fakeResponse() {
  const headers = new Map<string, string>();
  const state = { status: 0, contentType: '', body: '' };
  const res = {
    headers,
    state,
    setHeader(name: string, value: string) {
      headers.set(name.toLowerCase(), value);
    },
    status(code: number) {
      state.status = code;
      return res;
    },
    type(value: string) {
      state.contentType = value;
      return res;
    },
    send(value: string) {
      state.body = value;
      return res;
    },
  };
  return res;
}

function gssReturning(result: GssAcceptResult): GssAcceptor & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async accept(token: string) {
      calls.push(token);
      return result;
    },
  };
}

/** A directory that must never be consulted in the test that installs it. */
const forbiddenDirectory = {
  async verifyCredentials(): Promise<never> {
    throw new Error('the directory must not be consulted on this path');
  },
  async inspectAccount(): Promise<never> {
    throw new Error('the directory must not be consulted on this path');
  },
} as unknown as LdapDirectory;

function provider(options: {
  gss?: GssAcceptor;
  directory?: LdapDirectory;
  config?: Config;
} = {}): SpnegoIdentityProvider {
  return new SpnegoIdentityProvider({
    config: options.config ?? spnegoConfig(),
    logger: createSilentLogger(),
    gss: options.gss ?? gssReturning({ status: 'rejected', detail: 'not configured' }),
    directory: options.directory ?? forbiddenDirectory,
  });
}

// ---------------------------------------------------------------------------
describe('Authorization header parsing', () => {
  it('splits scheme and token, and lowercases only the scheme', () => {
    expect(parseAuthorization('Negotiate YIIC+g==')).toEqual({
      scheme: 'negotiate',
      token: 'YIIC+g==',
    });
  });

  it('treats an absent, empty or whitespace header as no header at all', () => {
    expect(parseAuthorization(undefined)).toBeUndefined();
    expect(parseAuthorization('')).toBeUndefined();
    expect(parseAuthorization('   ')).toBeUndefined();
  });

  it('reports a bare scheme with an empty token', () => {
    expect(parseAuthorization('Negotiate')).toEqual({ scheme: 'negotiate', token: '' });
  });
});

// ---------------------------------------------------------------------------
describe('NTLM detection', () => {
  const ntlmType1 = Buffer.concat([
    Buffer.from('NTLMSSP\0', 'latin1'),
    Buffer.from([0x01, 0x00, 0x00, 0x00]),
  ]).toString('base64');

  it('recognises an NTLM message from the base64 prefix documented in the plan', () => {
    expect(ntlmType1.startsWith('TlRMTVNT')).toBe(true);
    expect(isNtlmToken(ntlmType1)).toBe(true);
  });

  it('does not mistake a SPNEGO/Kerberos token for NTLM', () => {
    // A NegTokenInit starts with the 0x60 application tag, never with NTLMSSP.
    const spnego = Buffer.from([0x60, 0x82, 0x02, 0xfa, 0x06, 0x06, 0x2b]).toString('base64');
    expect(isNtlmToken(spnego)).toBe(false);
  });

  it('accepts only decodable base64 as a usable token', () => {
    expect(looksLikeBase64Token('YIIC+g==')).toBe(true);
    expect(looksLikeBase64Token('')).toBe(false);
    expect(looksLikeBase64Token('not a token!')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
describe('SPN normalisation', () => {
  it('turns every accepted spelling into the GSSAPI host-based form', () => {
    expect(toHostBasedServiceName('HTTP/auth.lab.easyoidc.local')).toBe(
      'HTTP@auth.lab.easyoidc.local',
    );
    expect(toHostBasedServiceName('HTTP/auth.lab.easyoidc.local@LAB.EASYOIDC.LOCAL')).toBe(
      'HTTP@auth.lab.easyoidc.local',
    );
    expect(toHostBasedServiceName('HTTP@auth.lab.easyoidc.local')).toBe(
      'HTTP@auth.lab.easyoidc.local',
    );
    expect(toHostBasedServiceName('  ')).toBe('');
  });

  it('derives the SPN from ISSUER_URL when KERBEROS_SERVICE_NAME is unset', () => {
    expect(spnegoConfig().kerberos.serviceName).toBe('HTTP/auth.lab.easyoidc.local');
  });

  it('lets KERBEROS_SERVICE_NAME override the derivation', () => {
    const config = spnegoConfig({ KERBEROS_SERVICE_NAME: 'HTTP/sso.example.com' });
    expect(config.kerberos.serviceName).toBe('HTTP/sso.example.com');
  });
});

// ---------------------------------------------------------------------------
describe('principal mapping', () => {
  it('sub is the sAMAccountName, lowercased, and the realm stays apart', () => {
    expect(usernameFromPrincipal('Mario.Rossi@LAB.EASYOIDC.LOCAL')).toBe('mario.rossi');
    expect(realmFromPrincipal('mario.rossi@lab.easyoidc.local')).toBe('LAB.EASYOIDC.LOCAL');
  });

  it('builds the UPN bind identity from every shape a user may type', () => {
    expect(toBindIdentity('mario.rossi', REALM)).toBe(`mario.rossi@${REALM}`);
    expect(toBindIdentity('LAB\\mario.rossi', REALM)).toBe(`mario.rossi@${REALM}`);
    expect(toBindIdentity('mario.rossi@LAB.EASYOIDC.LOCAL', REALM)).toBe(
      'mario.rossi@LAB.EASYOIDC.LOCAL',
    );
  });

  it('refuses anything that could not be an account name', () => {
    // DN punctuation, spaces and control characters never reach a bind.
    expect(toBindIdentity('cn=admin,dc=lab', REALM)).toBeUndefined();
    expect(toBindIdentity('mario rossi', REALM)).toBeUndefined();
    expect(toBindIdentity('mario*', REALM)).toBeUndefined();
    expect(toBindIdentity('a@b@c', REALM)).toBeUndefined();
    expect(toBindIdentity('', REALM)).toBeUndefined();
  });

  it('extracts the sAMAccountName from any of those shapes', () => {
    expect(sAMAccountNameOf('LAB\\Mario.Rossi')).toBe('mario.rossi');
    expect(sAMAccountNameOf('Mario.Rossi@LAB.EASYOIDC.LOCAL')).toBe('mario.rossi');
  });
});

// ---------------------------------------------------------------------------
describe('accountExpires', () => {
  it('treats unset, zero and the maximum FILETIME as "never expires"', () => {
    expect(accountExpired(undefined)).toBe(false);
    expect(accountExpired('0')).toBe(false);
    expect(accountExpired('9223372036854775807')).toBe(false);
  });

  it('compares a real FILETIME against now', () => {
    const toFiletime = (ms: number): string => String(BigInt(ms) * 10000n + 116444736000000000n);
    expect(accountExpired(toFiletime(Date.now() - 60_000))).toBe(true);
    expect(accountExpired(toFiletime(Date.now() + 86_400_000))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
describe('SpnegoIdentityProvider.authenticate', () => {
  it('asks for the challenge when the request carries no credentials', async () => {
    const result = await provider().authenticate(fakeRequest(), fakeResponse() as never);
    expect(result).toEqual({ status: 'no-credentials' });
  });

  it('ignores an Authorization header of another scheme instead of failing on it', async () => {
    const result = await provider().authenticate(
      fakeRequest({ authorization: 'Basic bWFyaW86c2VncmV0bw==' }),
      fakeResponse() as never,
    );
    expect(result).toEqual({ status: 'no-credentials' });
  });

  it('refuses NTLM outright and never hands the token to GSSAPI', async () => {
    const gss = gssReturning({ status: 'complete', principal: 'x@Y', responseToken: '' });
    const ntlm = Buffer.from('NTLMSSP\0\0\0\0', 'latin1').toString('base64');

    const result = await provider({ gss }).authenticate(
      fakeRequest({ authorization: `Negotiate ${ntlm}` }),
      fakeResponse() as never,
    );

    expect(result).toEqual({ status: 'failed', reason: 'ntlm_not_supported' });
    expect(gss.calls).toEqual([]);
  });

  it('returns the principal and the mutual-auth token on a completed handshake', async () => {
    const gss = gssReturning({
      status: 'complete',
      principal: `mario.rossi@${REALM}`,
      responseToken: 'oYG3MIG0oAMK',
    });
    const res = fakeResponse();

    const result = await provider({ gss }).authenticate(
      fakeRequest({ authorization: 'Negotiate YIIC+g==' }),
      res as never,
    );

    expect(result).toEqual({ status: 'authenticated', principal: `mario.rossi@${REALM}`, via: 'sso' });
    expect(res.headers.get('www-authenticate')).toBe('Negotiate oYG3MIG0oAMK');
  });

  it('falls back to the form when GSSAPI refuses the ticket', async () => {
    const gss = gssReturning({ status: 'rejected', detail: 'Clock skew too great' });
    const result = await provider({ gss }).authenticate(
      fakeRequest({ authorization: 'Negotiate YIIC+g==' }),
      fakeResponse() as never,
    );
    expect(result).toEqual({ status: 'failed', reason: 'sso_failed' });
  });

  it('reports a broken acceptor as temporarily unavailable, not as a bad password', async () => {
    const gss = gssReturning({ status: 'unavailable', detail: 'keytab not found' });
    const result = await provider({ gss }).authenticate(
      fakeRequest({ authorization: 'Negotiate YIIC+g==' }),
      fakeResponse() as never,
    );
    expect(result).toEqual({ status: 'failed', reason: 'temporarily_unavailable' });
  });

  it('does not keep a half-finished context across requests', async () => {
    const gss = gssReturning({ status: 'continue', responseToken: 'oRswGaADCgEB' });
    const result = await provider({ gss }).authenticate(
      fakeRequest({ authorization: 'Negotiate YIIC+g==' }),
      fakeResponse() as never,
    );
    expect(result).toEqual({ status: 'failed', reason: 'sso_failed' });
  });
});

// ---------------------------------------------------------------------------
describe('SpnegoIdentityProvider password fallback', () => {
  it('binds as the user and rejoins the SSO path with the directory spelling of the name', async () => {
    const seen: string[] = [];
    const directory = {
      async verifyCredentials(bindIdentity: string, password: string) {
        seen.push(`${bindIdentity}/${password}`);
        return { ok: true as const, sAMAccountName: 'Mario.Rossi' };
      },
    } as unknown as LdapDirectory;

    const result = await provider({ directory }).authenticate(
      fakeRequest({ body: { username: 'LAB\\mario.rossi', password: 'Lab.Passw0rd!' } }),
      fakeResponse() as never,
    );

    expect(seen).toEqual([`mario.rossi@${REALM}/Lab.Passw0rd!`]);
    expect(result).toEqual({ status: 'authenticated', principal: `mario.rossi@${REALM}`, via: 'form' });
  });

  it('passes the directory rejection reason through unflattened', async () => {
    const directory = {
      async verifyCredentials() {
        return { ok: false as const, reason: 'account_disabled' as const };
      },
    } as unknown as LdapDirectory;

    const result = await provider({ directory }).authenticate(
      fakeRequest({ body: { username: 'luigi.verdi', password: 'Lab.Passw0rd!' } }),
      fakeResponse() as never,
    );

    expect(result).toMatchObject({ status: 'failed', reason: 'account_disabled' });
  });

  it('turns a directory outage into temporarily_unavailable, never into a pass', async () => {
    const directory = {
      async verifyCredentials(): Promise<never> {
        throw new Error('connect ECONNREFUSED 172.28.10.10:636');
      },
    } as unknown as LdapDirectory;

    const result = await provider({ directory }).authenticate(
      fakeRequest({ body: { username: 'mario.rossi', password: 'Lab.Passw0rd!' } }),
      fakeResponse() as never,
    );

    expect(result).toMatchObject({ status: 'failed', reason: 'temporarily_unavailable' });
  });

  it('never binds with an empty password, which LDAP would accept as anonymous', async () => {
    const result = await provider().authenticate(
      fakeRequest({ body: { username: 'mario.rossi', password: '' } }),
      fakeResponse() as never,
    );
    expect(result).toMatchObject({ status: 'failed', reason: 'invalid_credentials' });
  });

  it('prefers a submitted form over any Negotiate header on the same request', async () => {
    const gss = gssReturning({ status: 'complete', principal: `intruso@${REALM}`, responseToken: '' });
    const directory = {
      async verifyCredentials() {
        return { ok: true as const, sAMAccountName: 'mario.rossi' };
      },
    } as unknown as LdapDirectory;

    const result = await provider({ gss, directory }).authenticate(
      fakeRequest({
        authorization: 'Negotiate YIIC+g==',
        body: { username: 'mario.rossi', password: 'Lab.Passw0rd!' },
      }),
      fakeResponse() as never,
    );

    expect(result).toEqual({ status: 'authenticated', principal: `mario.rossi@${REALM}`, via: 'form' });
    expect(gss.calls).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
describe('SpnegoIdentityProvider.challenge', () => {
  it('offers Negotiate and the Italian form when nothing has been tried yet', async () => {
    const res = fakeResponse();
    await provider().challenge(fakeRequest(), res as never, { interactionUid: 'abc123' });

    expect(res.state.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe('Negotiate');
    expect(res.state.body).toContain('/interaction/abc123/login');
    expect(res.state.body).toContain('Nome utente');
  });

  it('stops offering Negotiate once a handshake has already been answered', async () => {
    const res = fakeResponse();
    await provider().challenge(fakeRequest(), res as never, {
      interactionUid: 'abc123',
      reason: 'ntlm_not_supported',
    });

    expect(res.state.status).toBe(401);
    expect(res.headers.has('www-authenticate')).toBe(false);
    expect(res.state.body).toContain('NTLM');
  });

  it('has Italian text for every challenge reason the code can produce', async () => {
    for (const reason of [
      'invalid_credentials',
      'account_not_found',
      'account_disabled',
      'account_expired',
      'account_locked',
      'password_expired',
      'group_not_allowed',
      'temporarily_unavailable',
      'ntlm_not_supported',
      'sso_failed',
    ] as const) {
      const res = fakeResponse();
      await provider().challenge(fakeRequest(), res as never, {
        interactionUid: 'u',
        reason,
      });
      expect(res.state.body, reason).toContain('class="alert"');
      expect(asChallengeReason(reason), reason).toBe(reason);
    }
  });
});

// ---------------------------------------------------------------------------
describe('spnego configuration contract', () => {
  it('refuses to start without the LDAP parameters the gate needs', () => {
    expect(() =>
      loadConfig({
        ISSUER_URL: 'http://auth.lab.easyoidc.local:3000',
        DATA_DIR: '',
        IDENTITY_PROVIDER: 'spnego',
        REALM,
        CLIENTS_JSON: JSON.stringify([
          { client_id: 'desktop-app', redirect_uris: ['http://127.0.0.1/callback'] },
        ]),
      }),
    ).toThrowError(/LDAP_URL is required.*|LDAP_BIND_DN is required/s);
  });

  it('rejects an LDAP_URL that is not an LDAP URL', () => {
    expect(() => spnegoConfig({ LDAP_URL: 'https://dc1.lab.easyoidc.local' })).toThrowError(
      /LDAP_URL must start with ldap/,
    );
  });

  it('keeps the LDAP deadlines short by default', () => {
    const { ldap } = spnegoConfig();
    expect(ldap.timeoutMs).toBe(5000);
    expect(ldap.connectTimeoutMs).toBe(5000);
    expect(ldap.tlsInsecure).toBe(false);
  });
});

// ---------------------------------------------------------------------------
describe('the account_active gate reads the spnego verdict', () => {
  it('names the reason instead of flattening it to account_disabled', async () => {
    const directory = {
      async inspectAccount() {
        return { active: false as const, reason: 'group_not_allowed' as const };
      },
    } as unknown as LdapDirectory;

    const status = await provider({ directory }).inspectAccount(`mario.rossi@${REALM}`);
    expect(status).toEqual({ active: false, reason: 'group_not_allowed' });
  });

  it('lets a directory outage propagate as a throw, so the gate fails closed', async () => {
    const directory = {
      async inspectAccount(): Promise<never> {
        throw new Error('LDAP account search failed: timeout');
      },
    } as unknown as LdapDirectory;

    await expect(provider({ directory }).isAccountActive(`mario.rossi@${REALM}`)).rejects.toThrow(
      /LDAP account search failed/,
    );
  });
});
