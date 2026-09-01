/**
 * Pure parsing helpers for the HTTP Negotiate exchange (RFC 4559).
 *
 * Everything in here is deliberately free of the native GSSAPI binding so it can
 * be unit tested on any machine, with or without a Kerberos runtime.
 */

/** NTLMSSP signature, the first eight bytes of every NTLM message. */
const NTLM_SIGNATURE = 'NTLMSSP\0';

/**
 * Base64 of the first six bytes of that signature. An NTLM token is recognised
 * from the encoded form alone, before any decoding, because base64 of a fixed
 * prefix is itself a fixed prefix.
 */
export const NTLM_BASE64_PREFIX = 'TlRMTVNT';

export interface ParsedAuthorization {
  /** Lowercased auth scheme, e.g. `negotiate`. */
  scheme: string;
  /** Everything after the first space, trimmed. Empty when the header is bare. */
  token: string;
}

/**
 * Splits an `Authorization` header into scheme and credentials. Returns
 * undefined for an absent or malformed header — the caller then treats the
 * request as carrying no credentials and sends the challenge.
 */
export function parseAuthorization(header: string | undefined): ParsedAuthorization | undefined {
  if (typeof header !== 'string') return undefined;
  const trimmed = header.trim();
  if (trimmed === '') return undefined;

  const space = trimmed.indexOf(' ');
  if (space === -1) return { scheme: trimmed.toLowerCase(), token: '' };

  return {
    scheme: trimmed.slice(0, space).toLowerCase(),
    token: trimmed.slice(space + 1).trim(),
  };
}

/** True when the base64 blob is an NTLM message rather than a Kerberos/SPNEGO one. */
export function isNtlmToken(token: string): boolean {
  if (token.startsWith(NTLM_BASE64_PREFIX)) return true;
  // Cheap prefix test first; the decode is the belt to that pair of braces.
  try {
    const decoded = Buffer.from(token, 'base64');
    return decoded.subarray(0, 8).toString('latin1') === NTLM_SIGNATURE;
  } catch {
    return false;
  }
}

/** True when the token is syntactically usable base64 of a non-empty blob. */
export function looksLikeBase64Token(token: string): boolean {
  if (token === '' || !/^[A-Za-z0-9+/=\r\n]+$/.test(token)) return false;
  return Buffer.from(token, 'base64').length > 0;
}

/**
 * GSSAPI imports the acceptor name as GSS_C_NT_HOSTBASED_SERVICE, whose syntax
 * is `service@host` — not the `service/host` spelling used in keytabs, SPN
 * attributes and `kvno` output. Configuration is allowed to use either, and both
 * land here:
 *
 *   HTTP/auth.example.com                 -> HTTP@auth.example.com
 *   HTTP/auth.example.com@EXAMPLE.COM     -> HTTP@auth.example.com
 *   HTTP@auth.example.com                 -> HTTP@auth.example.com
 *
 * An empty result means "no acceptor name": GSSAPI then accepts with whatever
 * the keytab holds, which is a legitimate deployment choice for a keytab with a
 * single service key.
 */
export function toHostBasedServiceName(serviceName: string): string {
  const value = serviceName.trim();
  if (value === '') return '';

  const slash = value.indexOf('/');
  if (slash === -1) {
    // Already `service@host`; drop a trailing realm only if there are two @.
    const parts = value.split('@');
    return parts.length > 2 ? `${parts[0]}@${parts[1]}` : value;
  }

  const service = value.slice(0, slash);
  const rest = value.slice(slash + 1);
  const at = rest.indexOf('@');
  const host = at === -1 ? rest : rest.slice(0, at);
  return `${service}@${host}`;
}

/**
 * Builds the bind identity for the LDAP simple-bind fallback.
 *
 * The user is allowed to type any of the three shapes a domain user knows, and
 * all of them become the userPrincipalName form, which is the one AD accepts
 * without knowing the account's DN:
 *
 *   mario.rossi           -> mario.rossi@LAB.EASYOIDC.LOCAL
 *   LAB\mario.rossi       -> mario.rossi@LAB.EASYOIDC.LOCAL
 *   mario.rossi@LAB.…     -> unchanged
 *
 * Returns undefined when the input cannot be a username: that is a rejection,
 * never a bind attempt with a mangled identity.
 */
export function toBindIdentity(rawUsername: string, realm: string): string | undefined {
  const value = rawUsername.trim();
  if (value === '' || value.length > 256) return undefined;
  // No control characters and no whitespace anywhere, including the NETBIOS half.
  if (/[\u0000-\u001f\u007f\s]/.test(value)) return undefined;

  // The one backslash a user is allowed to type is the NETBIOS separator, and
  // only the part after it survives: everything downstream is a UPN.
  const backslash = value.lastIndexOf('\\');
  const local = backslash === -1 ? value : value.slice(backslash + 1);
  if (local === '') return undefined;
  // LDAP DN punctuation cannot appear in an account name; refusing it here is
  // what keeps a typed value from ever being read as a DN.
  if (/[,+"\\<>;=*()]/.test(local)) return undefined;

  if (local.includes('@')) {
    // Already a UPN. Exactly one @, and something on both sides.
    const parts = local.split('@');
    if (parts.length !== 2 || parts[0] === '' || parts[1] === '') return undefined;
    return local;
  }

  if (realm === '') return undefined;
  return `${local}@${realm}`;
}

/**
 * The sAMAccountName half of whatever the user typed, lowercased. Used for the
 * LDAP search and, once authenticated, as the `sub` claim.
 */
export function sAMAccountNameOf(rawUsername: string): string {
  const value = rawUsername.trim();
  const backslash = value.lastIndexOf('\\');
  const local = backslash === -1 ? value : value.slice(backslash + 1);
  const at = local.indexOf('@');
  return (at === -1 ? local : local.slice(0, at)).toLowerCase();
}
