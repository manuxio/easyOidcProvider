/**
 * Phase 4-bis unit tests: the cool-down on failed form attempts.
 *
 * The clock is injected, so the cool-down is exercised without waiting for it.
 */
import { describe, expect, it } from 'vitest';

import { createSilentLogger } from '../../src/logger.js';
import { LoginRateLimiter } from '../../src/twofactor/index.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';

const USER = 'mario.rossi';
const LOCKOUT_MS = 300_000;

function limiter(options: { max?: number; logger?: ReturnType<typeof createSilentLogger> } = {}) {
  let now = 1_770_000_000_000;
  const instance = new LoginRateLimiter({
    maxFailedAttempts: options.max ?? 3,
    lockoutMs: LOCKOUT_MS,
    logger: options.logger ?? createSilentLogger(),
    now: () => now,
  });
  return {
    instance,
    advance(ms: number) {
      now += ms;
    },
  };
}

describe('the per-username cool-down', () => {
  it('lets the first attempts through and trips on the configured one', () => {
    const { instance } = limiter({ max: 3 });

    expect(instance.check(USER).locked).toBe(false);
    expect(instance.recordFailure(USER).locked).toBe(false);
    expect(instance.recordFailure(USER).locked).toBe(false);

    const third = instance.recordFailure(USER);
    expect(third.locked).toBe(true);
    expect(third.failures).toBe(3);
    expect(instance.check(USER).locked).toBe(true);
    expect(instance.check(USER).retryAfterSeconds).toBe(300);
  });

  it('says so in the log the moment it trips', () => {
    const capture = createCapturingLogger();
    const { instance } = limiter({ max: 2, logger: capture.logger });

    instance.recordFailure(USER, { stage: 'credentials' });
    expect(capture.withReason('login_rate_limited')).toHaveLength(0);

    instance.recordFailure(USER, { stage: 'two_factor' });
    const tripped = capture.withReason('login_rate_limited');
    expect(tripped).toHaveLength(1);
    expect(tripped[0]!.level).toBe('warn');
    expect(tripped[0]!.username).toBe(USER);
    expect(tripped[0]!.stage).toBe('two_factor');
  });

  it('lets the user back in once the cool-down has elapsed', () => {
    const { instance, advance } = limiter({ max: 2 });

    instance.recordFailure(USER);
    instance.recordFailure(USER);
    expect(instance.check(USER).locked).toBe(true);

    advance(LOCKOUT_MS - 1);
    expect(instance.check(USER).locked).toBe(true);

    advance(2);
    expect(instance.check(USER).locked).toBe(false);
    expect(instance.failures(USER)).toBe(0);
  });

  it('forgets failures that are older than the window, without ever locking', () => {
    const { instance, advance } = limiter({ max: 3 });

    instance.recordFailure(USER);
    advance(LOCKOUT_MS + 1);
    instance.recordFailure(USER);
    expect(instance.failures(USER)).toBe(1);
    expect(instance.check(USER).locked).toBe(false);
  });

  it('counts each user name separately, and normalises case and spaces', () => {
    const { instance } = limiter({ max: 2 });

    instance.recordFailure('  MARIO.ROSSI ');
    instance.recordFailure('mario.rossi');
    expect(instance.check('Mario.Rossi').locked).toBe(true);
    expect(instance.check('luigi.verdi').locked).toBe(false);
  });

  it('wipes the history on a successful login', () => {
    const { instance } = limiter({ max: 3 });

    instance.recordFailure(USER);
    instance.recordFailure(USER);
    instance.reset(USER);

    expect(instance.failures(USER)).toBe(0);
    expect(instance.recordFailure(USER).locked).toBe(false);
  });

  it('is inert when FORM_MAX_FAILED_ATTEMPTS is 0', () => {
    const { instance } = limiter({ max: 0 });

    expect(instance.enabled).toBe(false);
    for (let attempt = 0; attempt < 50; attempt += 1) instance.recordFailure(USER);
    expect(instance.check(USER).locked).toBe(false);
  });
});
