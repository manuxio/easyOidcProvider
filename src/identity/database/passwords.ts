/**
 * Password verification for the `database` identity provider, against the hash
 * formats commonly found in customer databases.
 *
 * One rule shapes everything here: the SERVER never chooses weaker than the
 * data. `AUTH_PASSWORD_SCHEME=auto` (the default) recognizes only the
 * self-describing formats — the ones that carry their own name, salt and
 * parameters inside the stored string — because those cannot be confused with
 * one another:
 *
 *   bcrypt     $2a$ / $2b$ / $2y$…             (bcryptjs)
 *   argon2id   $argon2id$v=19$m=…,t=…,p=…$…$…  (PHC, @noble/hashes — pure JS)
 *   scrypt     $scrypt$ln=…,r=…,p=…$…$…        (PHC, node:crypto)
 *   pbkdf2     pbkdf2_sha256$iter$salt$b64     (Django style, node:crypto)
 *
 * A bare hex digest (md5/sha1/sha256, optionally salted) or a plaintext column
 * is ambiguous — 32 hex characters could be an md5 or half a token — so those
 * schemes must be DECLARED explicitly, and `plain` additionally warns at
 * startup: it exists because such databases exist, not because it is fine.
 *
 * Anti-enumeration: when the username does not exist the provider still burns
 * one verification against a fixed dummy hash of the SAME scheme, so "no such
 * user" and "wrong password" cost the same time and give the same answer.
 */
import {
  createHash,
  pbkdf2 as pbkdf2Callback,
  scrypt as scryptCallback,
  timingSafeEqual,
} from 'node:crypto';
import { argon2id } from '@noble/hashes/argon2.js';
import bcrypt from 'bcryptjs';

// promisify() flattens the overloads of scrypt and pbkdf2 onto their shortest
// shapes; manual wrappers keep the arguments the verification needs.
function scryptAsync(
  password: string,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keylen, options, (error, derived) => {
      if (error) reject(error);
      else resolve(derived);
    });
  });
}

function pbkdf2Async(
  password: string,
  salt: string,
  iterations: number,
  keylen: number,
  digest: string,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    pbkdf2Callback(password, salt, iterations, keylen, digest, (error, derived) => {
      if (error) reject(error);
      else resolve(derived);
    });
  });
}

export const PASSWORD_SCHEMES = [
  'auto',
  'bcrypt',
  'argon2id',
  'scrypt',
  'pbkdf2',
  'sha256',
  'sha1',
  'md5',
  'plain',
] as const;

export type PasswordScheme = (typeof PASSWORD_SCHEMES)[number];

/** The schemes whose stored form names itself; `auto` resolves among these. */
export type SelfDescribingScheme = 'bcrypt' | 'argon2id' | 'scrypt' | 'pbkdf2';

export function isPasswordScheme(value: string): value is PasswordScheme {
  return (PASSWORD_SCHEMES as readonly string[]).includes(value);
}

/** Recognizes a stored hash by its own format, or undefined when it is mute. */
export function detectScheme(stored: string): SelfDescribingScheme | undefined {
  if (/^\$2[aby]\$/.test(stored)) return 'bcrypt';
  if (stored.startsWith('$argon2id$')) return 'argon2id';
  if (stored.startsWith('$scrypt$')) return 'scrypt';
  if (/^pbkdf2_(sha1|sha256|sha512)\$/.test(stored)) return 'pbkdf2';
  return undefined;
}

export type VerificationOutcome =
  | { ok: true }
  /**
   * The three failures the caller logs apart but answers alike
   * (`invalid_credentials` — the page never says which):
   *   wrong_password  — well-formed hash, wrong password;
   *   scheme_mismatch — the stored value is not in the declared/detected format;
   *   malformed_hash  — the format was right but its content is not decodable.
   */
  | { ok: false; reason: 'wrong_password' | 'scheme_mismatch' | 'malformed_hash' };

export interface VerifyOptions {
  /** Per-user salt for the digest schemes (md5/sha1/sha256): hash(salt+password). */
  salt?: string;
}

export async function verifyPassword(
  password: string,
  stored: string,
  scheme: PasswordScheme,
  options: VerifyOptions = {},
): Promise<VerificationOutcome> {
  const detected = detectScheme(stored);

  if (scheme === 'auto') {
    if (!detected) return { ok: false, reason: 'scheme_mismatch' };
    return verifyPassword(password, stored, detected, options);
  }

  // A declared self-describing scheme must find its own format on the wire:
  // an md5 column suddenly holding "$2b$…" (or vice versa) is a data problem
  // to surface, not something to silently try both ways.
  if (isSelfDescribing(scheme) && detected !== scheme) {
    return { ok: false, reason: 'scheme_mismatch' };
  }
  if (!isSelfDescribing(scheme) && detected !== undefined) {
    return { ok: false, reason: 'scheme_mismatch' };
  }

  switch (scheme) {
    case 'bcrypt':
      return (await bcrypt.compare(password, stored))
        ? { ok: true }
        : { ok: false, reason: 'wrong_password' };
    case 'argon2id':
      return verifyArgon2id(password, stored);
    case 'scrypt':
      return verifyScrypt(password, stored);
    case 'pbkdf2':
      return verifyPbkdf2(password, stored);
    case 'sha256':
    case 'sha1':
    case 'md5':
      return verifyDigest(password, stored, scheme, options.salt);
    case 'plain':
      return constantTimeEquals(Buffer.from(password, 'utf8'), Buffer.from(stored, 'utf8'))
        ? { ok: true }
        : { ok: false, reason: 'wrong_password' };
    default: {
      const exhaustive: never = scheme;
      throw new Error(`unknown password scheme ${String(exhaustive)}`);
    }
  }
}

/**
 * Burns one verification of the configured scheme against a fixed dummy, for
 * usernames that do not exist. The dummies are built lazily, once, so the
 * per-login cost is exactly one ordinary verification.
 */
export async function dummyVerify(scheme: PasswordScheme): Promise<void> {
  const effective: PasswordScheme = scheme === 'auto' ? 'bcrypt' : scheme;
  const stored = await dummyStoredHash(effective);
  await verifyPassword('not-the-dummy-password', stored, effective, { salt: 'dummy-salt' });
}

// --- scheme implementations --------------------------------------------------

function verifyArgon2id(password: string, stored: string): VerificationOutcome {
  // $argon2id$v=19$m=65536,t=3,p=4$<b64salt>$<b64hash>  (PHC, unpadded base64)
  const match = /^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/
    .exec(stored);
  if (!match) return { ok: false, reason: 'malformed_hash' };
  const [, version, m, t, p, saltB64, hashB64] = match;
  if (version !== '19') return { ok: false, reason: 'malformed_hash' };
  const salt = Buffer.from(saltB64!, 'base64');
  const expected = Buffer.from(hashB64!, 'base64');
  if (salt.length === 0 || expected.length === 0) return { ok: false, reason: 'malformed_hash' };
  const actual = Buffer.from(argon2id(password, salt, {
    m: Number(m),
    t: Number(t),
    p: Number(p),
    dkLen: expected.length,
  }));
  return constantTimeEquals(actual, expected)
    ? { ok: true }
    : { ok: false, reason: 'wrong_password' };
}

async function verifyScrypt(password: string, stored: string): Promise<VerificationOutcome> {
  // $scrypt$ln=17,r=8,p=1$<b64salt>$<b64hash>  (PHC, unpadded base64)
  const match = /^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/
    .exec(stored);
  if (!match) return { ok: false, reason: 'malformed_hash' };
  const [, ln, r, p, saltB64, hashB64] = match;
  const salt = Buffer.from(saltB64!, 'base64');
  const expected = Buffer.from(hashB64!, 'base64');
  if (salt.length === 0 || expected.length === 0) return { ok: false, reason: 'malformed_hash' };
  const N = 2 ** Number(ln);
  const actual = await scryptAsync(password, salt, expected.length, {
    N,
    r: Number(r),
    p: Number(p),
    // node's default maxmem (32 MB) refuses ln>=15 with r=8; size it to the
    // parameters instead of failing on stronger-than-default hashes.
    maxmem: 256 * N * Number(r),
  });
  return constantTimeEquals(actual, expected)
    ? { ok: true }
    : { ok: false, reason: 'wrong_password' };
}

async function verifyPbkdf2(password: string, stored: string): Promise<VerificationOutcome> {
  // pbkdf2_sha256$600000$<salt-text>$<b64hash>  (Django style; salt is plain text)
  const match = /^pbkdf2_(sha1|sha256|sha512)\$(\d+)\$([^$]+)\$([A-Za-z0-9+/=]+)$/.exec(stored);
  if (!match) return { ok: false, reason: 'malformed_hash' };
  const [, digest, iterations, salt, hashB64] = match;
  const expected = Buffer.from(hashB64!, 'base64');
  if (expected.length === 0) return { ok: false, reason: 'malformed_hash' };
  const actual = await pbkdf2Async(password, salt!, Number(iterations), expected.length, digest!);
  return constantTimeEquals(actual, expected)
    ? { ok: true }
    : { ok: false, reason: 'wrong_password' };
}

function verifyDigest(
  password: string,
  stored: string,
  algorithm: 'sha256' | 'sha1' | 'md5',
  salt: string | undefined,
): VerificationOutcome {
  const expectedLength = { sha256: 64, sha1: 40, md5: 32 }[algorithm];
  const normalized = stored.trim().toLowerCase();
  if (!new RegExp(`^[0-9a-f]{${expectedLength}}$`).test(normalized)) {
    return { ok: false, reason: 'malformed_hash' };
  }
  const actual = createHash(algorithm).update(`${salt ?? ''}${password}`, 'utf8').digest('hex');
  return constantTimeEquals(Buffer.from(actual, 'utf8'), Buffer.from(normalized, 'utf8'))
    ? { ok: true }
    : { ok: false, reason: 'wrong_password' };
}

// --- helpers ------------------------------------------------------------------

function isSelfDescribing(scheme: PasswordScheme): scheme is SelfDescribingScheme {
  return scheme === 'bcrypt' || scheme === 'argon2id' || scheme === 'scrypt' || scheme === 'pbkdf2';
}

function constantTimeEquals(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    // Still burn a comparison so a length mismatch is not measurably faster.
    timingSafeEqual(a, a);
    return false;
  }
  return timingSafeEqual(a, b);
}

const DUMMY_PASSWORD = 'dummy-password-never-issued';
const dummyCache = new Map<PasswordScheme, Promise<string>>();

function dummyStoredHash(scheme: Exclude<PasswordScheme, 'auto'>): Promise<string> {
  let cached = dummyCache.get(scheme);
  if (!cached) {
    cached = buildDummy(scheme);
    dummyCache.set(scheme, cached);
  }
  return cached;
}

async function buildDummy(scheme: Exclude<PasswordScheme, 'auto'>): Promise<string> {
  switch (scheme) {
    case 'bcrypt':
      return bcrypt.hash(DUMMY_PASSWORD, 10);
    case 'argon2id': {
      const salt = Buffer.from('fixed-dummy-salt');
      const hash = Buffer.from(argon2id(DUMMY_PASSWORD, salt, { m: 19_456, t: 2, p: 1, dkLen: 32 }));
      return `$argon2id$v=19$m=19456,t=2,p=1$${unpadded(salt)}$${unpadded(hash)}`;
    }
    case 'scrypt': {
      const salt = Buffer.from('fixed-dummy-salt');
      const hash = await scryptAsync(DUMMY_PASSWORD, salt, 32, {
        N: 2 ** 15, r: 8, p: 1, maxmem: 256 * 2 ** 15 * 8,
      });
      return `$scrypt$ln=15,r=8,p=1$${unpadded(salt)}$${unpadded(hash)}`;
    }
    case 'pbkdf2': {
      const hash = await pbkdf2Async(DUMMY_PASSWORD, 'fixed-dummy-salt', 260_000, 32, 'sha256');
      return `pbkdf2_sha256$260000$fixed-dummy-salt$${hash.toString('base64')}`;
    }
    case 'sha256':
    case 'sha1':
    case 'md5':
      return createHash(scheme).update(`dummy-salt${DUMMY_PASSWORD}`, 'utf8').digest('hex');
    case 'plain':
      return DUMMY_PASSWORD;
    default: {
      const exhaustive: never = scheme;
      throw new Error(`unknown password scheme ${String(exhaustive)}`);
    }
  }
}

function unpadded(buffer: Buffer): string {
  return buffer.toString('base64').replace(/=+$/, '');
}
