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
  TWO_FACTOR_DIGITS,
  TWO_FACTOR_REASONS,
  TWO_FACTOR_STEP_SECONDS,
  TWO_FACTOR_WINDOW_STEPS,
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

// ---------------------------------------------------------------------------
// The fixed parameters, the window edges and the replay table's bookkeeping
// (verifier.ts header: 6 digits, 30 s, ±1 step, in-memory and bounded).
// ---------------------------------------------------------------------------

describe('the fixed RFC 6238 parameters', () => {
  it('are 6 digits, 30-second steps and one step of tolerance', () => {
    expect(TWO_FACTOR_DIGITS).toBe(6);
    expect(TWO_FACTOR_STEP_SECONDS).toBe(30);
    expect(TWO_FACTOR_WINDOW_STEPS).toBe(1);
  });

  it('refuses the code two steps behind and two steps ahead', async () => {
    const { verifier } = harness();
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS - 60))).resolves.toEqual({
      status: 'failed',
      reason: TWO_FACTOR_REASONS.failed,
    });
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS + 60))).resolves.toEqual({
      status: 'failed',
      reason: TWO_FACTOR_REASONS.failed,
    });
  });

  it('returns the time step of the accepted code', async () => {
    const { verifier } = harness();
    const currentStep = Math.floor(NOW_SECONDS / TWO_FACTOR_STEP_SECONDS);
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS - 30))).resolves.toEqual({
      status: 'ok',
      timeStep: currentStep - 1,
    });
    expect(verifier.lastAcceptedStep(USER)).toBe(currentStep - 1);
  });

  it('tolerates a dash between the digit groups too', async () => {
    const { verifier } = harness();
    const code = codeAt(NOW_SECONDS);
    await expect(verifier.verify(USER, `${code.slice(0, 3)}-${code.slice(3)}`))
      .resolves.toMatchObject({ status: 'ok' });
  });

  it('treats a code of blanks only as no code at all', async () => {
    const { verifier, source } = harness();
    await expect(verifier.verify(USER, '  - ')).resolves.toEqual({
      status: 'failed',
      reason: TWO_FACTOR_REASONS.missingCode,
    });
    expect(source.lookups).toEqual([]);
  });

  it('asks the source exactly once per well-formed code, for that user', async () => {
    const { verifier, source } = harness();
    await verifier.verify(USER, codeAt(NOW_SECONDS, OTHER_SEED));
    expect(source.lookups).toEqual([USER]);
  });

  it('trims the blanks around a stored seed', async () => {
    const { verifier } = harness({ [USER]: `  ${SEED}\n` });
    await expect(verifier.verify(USER, codeAt(NOW_SECONDS))).resolves.toMatchObject({ status: 'ok' });
  });
});

describe('failures of the source, whatever they throw', () => {
  it('reports a plain Error from the source as unavailable as well', async () => {
    const capture = createCapturingLogger();
    const source = new FakeSeedSource({ [USER]: SEED });
    source.failWith = new Error('ETIMEDOUT');
    const verifier = new TwoFactorVerifier({ source, logger: capture.logger, now: () => NOW_SECONDS * 1000 });

    await expect(verifier.verify(USER, codeAt(NOW_SECONDS))).resolves.toEqual({
      status: 'unavailable',
      reason: TWO_FACTOR_REASONS.unavailable,
    });
    const [line] = capture.withReason(TWO_FACTOR_REASONS.unavailable);
    expect(line).toMatchObject({ level: 'error', err: { name: 'TwoFactorSeedUnavailable', message: 'ETIMEDOUT' } });
  });
});

describe('what the verifier logs', () => {
  it('logs an accepted code at info with its time step, and never the code or the seed', async () => {
    const capture = createCapturingLogger();
    const source = new FakeSeedSource({ [USER]: SEED });
    const verifier = new TwoFactorVerifier({ source, logger: capture.logger, now: () => NOW_SECONDS * 1000 });
    const code = codeAt(NOW_SECONDS);

    await verifier.verify(USER, code);
    const [line] = capture.matching('second factor accepted');
    expect(line).toMatchObject({ level: 'info', username: USER, source: 'fake', component: 'two-factor' });
    expect(typeof line!.timeStep).toBe('number');
    // Quoted: the bare digits could legitimately occur inside the numeric timeStep.
    expect(capture.text()).not.toContain(`"${code}"`);
    expect(capture.text()).not.toContain(SEED);
  });

  it('logs a replay with the step it collided with', async () => {
    const capture = createCapturingLogger();
    const source = new FakeSeedSource({ [USER]: SEED });
    const verifier = new TwoFactorVerifier({ source, logger: capture.logger, now: () => NOW_SECONDS * 1000 });
    const code = codeAt(NOW_SECONDS);

    await verifier.verify(USER, code);
    await verifier.verify(USER, code);
    const [line] = capture.withReason(TWO_FACTOR_REASONS.replayed);
    expect(line).toMatchObject({ level: 'warn' });
    expect(line!.timeStep).toBe(line!.lastAcceptedStep);
  });

  it('exposes the name of its source', () => {
    expect(harness().verifier.sourceName).toBe('fake');
  });
});

describe('the replay table is bounded and in memory', () => {
  it('evicts the least recently seen user past the ceiling, and says so', async () => {
    const capture = createCapturingLogger();
    const users = ['user-a', 'user-b', 'user-c'];
    const source = new FakeSeedSource(Object.fromEntries(users.map((user) => [user, SEED])));
    let nowMs = NOW_SECONDS * 1000;
    const verifier = new TwoFactorVerifier({
      source,
      logger: capture.logger,
      now: () => nowMs,
      maxTrackedUsers: 2,
    });
    const code = codeAt(NOW_SECONDS);

    for (const user of users) {
      await expect(verifier.verify(user, code)).resolves.toMatchObject({ status: 'ok' });
      // Still the same step: only `seenAt` moves.
      nowMs += 1000;
    }

    expect(verifier.lastAcceptedStep('user-a')).toBeUndefined();
    expect(verifier.lastAcceptedStep('user-b')).toBeDefined();
    expect(verifier.lastAcceptedStep('user-c')).toBeDefined();
    const [line] = capture.matching('replay table hit its ceiling');
    expect(line).toMatchObject({ level: 'warn', evicted: 1, tracked: 2 });

    // The cost of an eviction is the replay protection of that one user for
    // the current step, never their access.
    await expect(verifier.verify('user-a', code)).resolves.toMatchObject({ status: 'ok' });
  });

  it('forgets every accepted step on close', async () => {
    const { verifier } = harness();
    await verifier.verify(USER, codeAt(NOW_SECONDS));
    expect(verifier.lastAcceptedStep(USER)).toBeDefined();
    await verifier.close();
    expect(verifier.lastAcceptedStep(USER)).toBeUndefined();
  });

  it('does not remember a refused code', async () => {
    const { verifier } = harness();
    await verifier.verify(USER, codeAt(NOW_SECONDS, OTHER_SEED));
    expect(verifier.lastAcceptedStep(USER)).toBeUndefined();
  });
});
