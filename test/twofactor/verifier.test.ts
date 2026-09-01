/**
 * Phase 4-bis unit tests: the TOTP verifier.
 *
 * The codes are generated with otplib itself, at chosen epochs, so the window
 * assertions are about the verifier's configuration (±1 step of 30 s) and not
 * about a hand-copied constant that would silently rot.
 *
 * The clock is injected, so nothing here waits for real time to pass.
 */
import { createGuardrails, generateSync } from 'otplib';
import { describe, expect, it } from 'vitest';

import { createSilentLogger } from '../../src/logger.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';
import { FakeSeedSource } from '../helpers/fakeSeedSource.js';
import {
  TWO_FACTOR_REASONS,
  TwoFactorSeedUnavailable,
  TwoFactorVerifier,
} from '../../src/twofactor/index.js';

/** 32 base32 characters = 20 bytes = the 160 bits RFC 4226 recommends. */
const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
/** A different one, to make a "wrong but well-formed" code without guessing. */
const OTHER_SEED = 'KRSXG5DJNZTSA43FMNZGK5BANFXHA33S';

const USER = 'mario.rossi';
/** A round number well inside a step, so ±30 s never crosses two boundaries. */
const NOW_SECONDS = 1_770_000_015;

function codeAt(epoch: number, secret = SEED): string {
  // Same floor as the verifier: codes must be generable for the customer's
  // legacy 80-bit seeds too (see TWO_FACTOR_MIN_SECRET_BYTES).
  return generateSync({ secret, epoch, guardrails: createGuardrails({ MIN_SECRET_BYTES: 10 }) });
}

interface Harness {
  verifier: TwoFactorVerifier;
  source: FakeSeedSource;
  setNow(seconds: number): void;
}

function harness(seeds: Record<string, string> = { [USER]: SEED }): Harness {
  const source = new FakeSeedSource(seeds);
  let nowSeconds = NOW_SECONDS;
  const verifier = new TwoFactorVerifier({
    source,
    logger: createSilentLogger(),
    now: () => nowSeconds * 1000,
  });
  return {
    verifier,
    source,
    setNow(seconds: number) {
      nowSeconds = seconds;
    },
  };
}

describe('TOTP window', () => {
  it('accepts the code of the current step', async () => {
    const { verifier } = harness();
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS)))
      .resolves.toMatchObject({ status: 'ok' });
  });

  it('accepts the code of the previous step (client clock 30 s behind)', async () => {
    const { verifier } = harness();
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS - 30)))
      .resolves.toMatchObject({ status: 'ok' });
  });

  it('accepts the code of the next step (client clock 30 s ahead)', async () => {
    const { verifier } = harness();
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS + 30)))
      .resolves.toMatchObject({ status: 'ok' });
  });

  it('refuses a code three steps old (t-90)', async () => {
    const { verifier } = harness();
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS - 90))).resolves.toEqual({
      status: 'failed',
      reason: TWO_FACTOR_REASONS.failed,
    });
  });

  it('tolerates the spaces an authenticator app shows between the digit groups', async () => {
    const { verifier } = harness();
    const code = codeAt(NOW_SECONDS);
    const spaced = `${code.slice(0, 3)} ${code.slice(3)}`;
    await expect(verifier.verify(USER, spaced)).resolves.toMatchObject({ status: 'ok' });
  });
});

describe('a code that does not match', () => {
  it('refuses a well-formed code computed from another seed', async () => {
    const { verifier } = harness();
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS, OTHER_SEED))).resolves.toEqual({
      status: 'failed',
      reason: TWO_FACTOR_REASONS.failed,
    });
  });

  it('refuses an empty code without asking the seed source', async () => {
    const { verifier, source } = harness();
    await expect(verifier.verify(USER, '')).resolves.toEqual({
      status: 'failed',
      reason: TWO_FACTOR_REASONS.missingCode,
    });
    expect(source.lookups).toEqual([]);
  });

  it('refuses a code that is not six digits without asking the seed source', async () => {
    const { verifier, source } = harness();
    for (const bad of ['1234', '1234567', 'abcdef', '12 34']) {
      await expect(verifier.verify(USER, bad)).resolves.toEqual({
        status: 'failed',
        reason: TWO_FACTOR_REASONS.malformedCode,
      });
    }
    expect(source.lookups).toEqual([]);
  });
});

describe('replay', () => {
  it('refuses the same code a second time', async () => {
    const { verifier } = harness();
    const code = codeAt(NOW_SECONDS);

    await expect(verifier.verify(USER, code)).resolves.toMatchObject({ status: 'ok' });
    await expect(verifier.verify(USER, code)).resolves.toEqual({
      status: 'failed',
      reason: TWO_FACTOR_REASONS.replayed,
    });
  });

  it('refuses a code from an earlier step once a later one has been accepted', async () => {
    const { verifier } = harness();
    // The previous step is still inside the tolerance window, so without the
    // replay table this second code would be perfectly valid.
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS))).resolves.toMatchObject({ status: 'ok' });
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS - 30))).resolves.toEqual({
      status: 'failed',
      reason: TWO_FACTOR_REASONS.replayed,
    });
  });

  it('accepts the next step, and remembers it', async () => {
    const { verifier, setNow } = harness();
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS))).resolves.toMatchObject({ status: 'ok' });
    const firstStep = verifier.lastAcceptedStep(USER)!;

    setNow(NOW_SECONDS + 30);
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS + 30)))
      .resolves.toMatchObject({ status: 'ok' });
    expect(verifier.lastAcceptedStep(USER)).toBe(firstStep + 1);
  });

  it('keeps one table per user: a replay for one does not lock the other out', async () => {
    const { verifier } = harness({ [USER]: SEED, 'anna.bianchi': SEED });
    const code = codeAt(NOW_SECONDS);

    await expect(verifier.verify(USER, code)).resolves.toMatchObject({ status: 'ok' });
    await expect(verifier.verify('anna.bianchi', code)).resolves.toMatchObject({ status: 'ok' });
  });
});

describe('the seed source', () => {
  it('refuses a user with no seed, and says so in the log', async () => {
    const capture = createCapturingLogger();
    const source = new FakeSeedSource({});
    const verifier = new TwoFactorVerifier({
      source,
      logger: capture.logger,
      now: () => NOW_SECONDS * 1000,
    });

    await expect(verifier.verify(USER, codeAt(NOW_SECONDS))).resolves.toEqual({
      status: 'not-enrolled',
      reason: TWO_FACTOR_REASONS.notEnrolled,
    });
    expect(capture.withReason(TWO_FACTOR_REASONS.notEnrolled)).toHaveLength(1);
    expect(capture.withReason(TWO_FACTOR_REASONS.notEnrolled)[0]!.level).toBe('error');
  });

  it('treats an empty stored seed exactly like a missing one', async () => {
    const { verifier } = harness({ [USER]: '   ' });
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS))).resolves.toEqual({
      status: 'not-enrolled',
      reason: TWO_FACTOR_REASONS.notEnrolled,
    });
  });

  it('refuses a stored seed that is not usable base32, as a fault of the source', async () => {
    const { verifier } = harness({ [USER]: 'not a base32 secret!!' });
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS))).resolves.toEqual({
      status: 'not-enrolled',
      reason: TWO_FACTOR_REASONS.seedInvalid,
    });
  });

  it('accepts the legacy 80-bit (16 base32 chars) seed format the customer uses', async () => {
    // 'JBSWY3DPEHPK3PXP' is the classic 80-bit Google-Authenticator secret.
    // Legacy installed-base totpsecret columns carry
    // this format, so the RFC's 128-bit floor is lowered to 80 bits.
    const seed = 'JBSWY3DPEHPK3PXP';
    const { verifier } = harness({ [USER]: seed });
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS, seed))).resolves.toMatchObject({
      status: 'ok',
    });
  });

  it('still refuses a seed shorter than 80 bits', async () => {
    // 8 base32 characters = 40 bits: below even the legacy floor.
    const { verifier } = harness({ [USER]: 'JBSWY3DP' });
    await expect(verifier.verify(USER, '123456')).resolves.toEqual({
      status: 'not-enrolled',
      reason: TWO_FACTOR_REASONS.seedInvalid,
    });
  });

  it('reports an unreachable source as unavailable, never as a wrong code', async () => {
    const capture = createCapturingLogger();
    const source = new FakeSeedSource({ [USER]: SEED });
    source.failWith = new TwoFactorSeedUnavailable('fake', 'ECONNREFUSED');
    const verifier = new TwoFactorVerifier({
      source,
      logger: capture.logger,
      now: () => NOW_SECONDS * 1000,
    });

    await expect(verifier.verify(USER, codeAt(NOW_SECONDS))).resolves.toEqual({
      status: 'unavailable',
      reason: TWO_FACTOR_REASONS.unavailable,
    });
    expect(capture.text()).toContain('fail closed');
  });

  it('closes the source when the verifier closes', async () => {
    const { verifier, source } = harness();
    await verifier.close();
    expect(source.closed).toBe(true);
  });
});
