/**
 * The password verification module of the `database` identity provider: every
 * supported scheme against vectors generated in the test itself, the
 * cross-scheme refusals, and the anti-enumeration dummy.
 */
import { createHash, pbkdf2Sync, randomBytes, scryptSync } from 'node:crypto';

import { argon2id } from '@noble/hashes/argon2.js';
import bcrypt from 'bcryptjs';
import { describe, expect, it } from 'vitest';

import {
  detectScheme,
  dummyVerify,
  verifyPassword,
} from '../../src/identity/database/passwords.js';

const PASSWORD = 'Corretta-Battaglia-Cavallo-Graffetta-9';
const WRONG = 'not-the-password';

function unpadded(buffer: Buffer): string {
  return buffer.toString('base64').replace(/=+$/, '');
}

describe('self-describing schemes', () => {
  it('verifies and refuses bcrypt', async () => {
    const stored = await bcrypt.hash(PASSWORD, 10);
    expect(detectScheme(stored)).toBe('bcrypt');
    expect(await verifyPassword(PASSWORD, stored, 'bcrypt')).toEqual({ ok: true });
    expect(await verifyPassword(WRONG, stored, 'bcrypt'))
      .toEqual({ ok: false, reason: 'wrong_password' });
    // auto resolves it by its own prefix.
    expect(await verifyPassword(PASSWORD, stored, 'auto')).toEqual({ ok: true });
  });

  it('verifies and refuses argon2id (PHC format)', async () => {
    const salt = randomBytes(16);
    const hash = Buffer.from(argon2id(PASSWORD, salt, { m: 19_456, t: 2, p: 1, dkLen: 32 }));
    const stored = `$argon2id$v=19$m=19456,t=2,p=1$${unpadded(salt)}$${unpadded(hash)}`;
    expect(detectScheme(stored)).toBe('argon2id');
    expect(await verifyPassword(PASSWORD, stored, 'argon2id')).toEqual({ ok: true });
    expect(await verifyPassword(WRONG, stored, 'auto'))
      .toEqual({ ok: false, reason: 'wrong_password' });
  });

  it('verifies and refuses scrypt (PHC format), including above-default parameters', async () => {
    const salt = randomBytes(16);
    const hash = scryptSync(PASSWORD, salt, 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 256 * 2 ** 15 * 8 });
    const stored = `$scrypt$ln=15,r=8,p=1$${unpadded(salt)}$${unpadded(hash)}`;
    expect(detectScheme(stored)).toBe('scrypt');
    expect(await verifyPassword(PASSWORD, stored, 'scrypt')).toEqual({ ok: true });
    expect(await verifyPassword(WRONG, stored, 'auto'))
      .toEqual({ ok: false, reason: 'wrong_password' });
  });

  it('verifies and refuses Django-style pbkdf2', async () => {
    const hash = pbkdf2Sync(PASSWORD, 'salty-text', 260_000, 32, 'sha256');
    const stored = `pbkdf2_sha256$260000$salty-text$${hash.toString('base64')}`;
    expect(detectScheme(stored)).toBe('pbkdf2');
    expect(await verifyPassword(PASSWORD, stored, 'pbkdf2')).toEqual({ ok: true });
    expect(await verifyPassword(WRONG, stored, 'auto'))
      .toEqual({ ok: false, reason: 'wrong_password' });
  });
});

describe('declared-only schemes', () => {
  it('verifies the bare digests, salted and unsalted', async () => {
    for (const algorithm of ['md5', 'sha1', 'sha256'] as const) {
      const unsalted = createHash(algorithm).update(PASSWORD, 'utf8').digest('hex');
      expect(await verifyPassword(PASSWORD, unsalted, algorithm)).toEqual({ ok: true });
      expect(await verifyPassword(WRONG, unsalted, algorithm))
        .toEqual({ ok: false, reason: 'wrong_password' });

      const salted = createHash(algorithm).update(`pepe${PASSWORD}`, 'utf8').digest('hex');
      expect(await verifyPassword(PASSWORD, salted, algorithm, { salt: 'pepe' }))
        .toEqual({ ok: true });
      expect(await verifyPassword(PASSWORD, salted, algorithm))
        .toEqual({ ok: false, reason: 'wrong_password' });
    }
  });

  it('accepts uppercase hex digests as stored by some databases', async () => {
    const stored = createHash('md5').update(PASSWORD, 'utf8').digest('hex').toUpperCase();
    expect(await verifyPassword(PASSWORD, stored, 'md5')).toEqual({ ok: true });
  });

  it('verifies plain text in constant time', async () => {
    expect(await verifyPassword(PASSWORD, PASSWORD, 'plain')).toEqual({ ok: true });
    expect(await verifyPassword(WRONG, PASSWORD, 'plain'))
      .toEqual({ ok: false, reason: 'wrong_password' });
  });

  it('never resolves a bare digest or plain text from auto', async () => {
    const md5 = createHash('md5').update(PASSWORD, 'utf8').digest('hex');
    expect(detectScheme(md5)).toBeUndefined();
    expect(await verifyPassword(PASSWORD, md5, 'auto'))
      .toEqual({ ok: false, reason: 'scheme_mismatch' });
    expect(await verifyPassword(PASSWORD, PASSWORD, 'auto'))
      .toEqual({ ok: false, reason: 'scheme_mismatch' });
  });
});

describe('cross-scheme discipline', () => {
  it('refuses a stored value that does not match the declared scheme', async () => {
    const bcryptHash = await bcrypt.hash(PASSWORD, 10);
    const md5 = createHash('md5').update(PASSWORD, 'utf8').digest('hex');

    // Declared self-describing, stored something else.
    expect(await verifyPassword(PASSWORD, md5, 'bcrypt'))
      .toEqual({ ok: false, reason: 'scheme_mismatch' });
    // Declared digest, stored a self-describing hash.
    expect(await verifyPassword(PASSWORD, bcryptHash, 'md5'))
      .toEqual({ ok: false, reason: 'scheme_mismatch' });
    // Declared one self-describing scheme, stored another.
    expect(await verifyPassword(PASSWORD, bcryptHash, 'argon2id'))
      .toEqual({ ok: false, reason: 'scheme_mismatch' });
  });

  it('reports a malformed value of the right family as malformed', async () => {
    expect(await verifyPassword(PASSWORD, '$argon2id$v=19$broken', 'argon2id'))
      .toEqual({ ok: false, reason: 'malformed_hash' });
    expect(await verifyPassword(PASSWORD, 'deadbeef', 'md5'))
      .toEqual({ ok: false, reason: 'malformed_hash' });
  });
});

describe('anti-enumeration dummy', () => {
  it('burns one verification per scheme without throwing', async () => {
    for (const scheme of ['auto', 'bcrypt', 'md5', 'plain', 'pbkdf2'] as const) {
      await expect(dummyVerify(scheme)).resolves.toBeUndefined();
    }
  });
});
