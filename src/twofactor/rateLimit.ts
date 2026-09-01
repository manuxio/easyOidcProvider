/**
 * Rate limit on FAILED FORM ATTEMPTS, per username.
 *
 * It counts every rejected credential submission on the password form — wrong
 * password and wrong verification code alike — because from the outside they are
 * the same thing: somebody guessing. The Kerberos path is not counted: it does
 * not carry a username to key on, and a bad ticket is refused by the KDC long
 * before it reaches us.
 *
 * IN-MEMORY, THEREFORE SINGLE-INSTANCE, exactly like the replay table in
 * verifier.ts: one auth-server process holds one counter table. A second replica
 * would double the effective budget. It is a brake on guessing, not a lockout
 * policy — Active Directory's own lockout is still the authority on the password
 * half, and this never disables an account, it only refuses to ask the directory
 * for a while.
 */
import type { Logger } from '../logger.js';

export interface LoginRateLimiterOptions {
  /** Failures allowed before the cool-down starts. 0 disables the limiter. */
  maxFailedAttempts: number;
  /** Cool-down length, milliseconds. Also the window in which failures decay. */
  lockoutMs: number;
  logger: Logger;
  /** Unix milliseconds. A test seam. */
  now?: () => number;
}

export interface RateLimitState {
  locked: boolean;
  /** Whole seconds left in the cool-down; 0 when not locked. */
  retryAfterSeconds: number;
  failures: number;
}

interface Entry {
  failures: number;
  lastFailureAt: number;
  lockedUntil: number;
}

export class LoginRateLimiter {
  readonly #max: number;
  readonly #lockoutMs: number;
  readonly #now: () => number;
  readonly #log: Logger;
  readonly #entries = new Map<string, Entry>();

  constructor(options: LoginRateLimiterOptions) {
    this.#max = options.maxFailedAttempts;
    this.#lockoutMs = options.lockoutMs;
    this.#now = options.now ?? (() => Date.now());
    this.#log = options.logger.child({ component: 'login-rate-limit' });
  }

  get enabled(): boolean {
    return this.#max > 0;
  }

  /** Current state for a username, without recording anything. */
  check(username: string): RateLimitState {
    if (!this.enabled) return { locked: false, retryAfterSeconds: 0, failures: 0 };

    const key = normalize(username);
    const entry = this.#entries.get(key);
    if (entry === undefined) return { locked: false, retryAfterSeconds: 0, failures: 0 };

    const now = this.#now();
    if (entry.lockedUntil > now) {
      return {
        locked: true,
        retryAfterSeconds: Math.ceil((entry.lockedUntil - now) / 1000),
        failures: entry.failures,
      };
    }

    // The cool-down has elapsed, or the failures are older than the window:
    // either way the slate is clean again.
    if (entry.lockedUntil !== 0 || now - entry.lastFailureAt >= this.#lockoutMs) {
      this.#entries.delete(key);
      return { locked: false, retryAfterSeconds: 0, failures: 0 };
    }

    return { locked: false, retryAfterSeconds: 0, failures: entry.failures };
  }

  /**
   * Records one rejected form submission. Returns the state AFTER the failure,
   * so the caller can see the moment the cool-down starts.
   */
  recordFailure(username: string, context: Record<string, unknown> = {}): RateLimitState {
    if (!this.enabled) return { locked: false, retryAfterSeconds: 0, failures: 0 };

    const key = normalize(username);
    const now = this.#now();
    // check() clears an expired entry, so what is left here is a live one.
    this.check(username);
    const entry = this.#entries.get(key) ?? { failures: 0, lastFailureAt: now, lockedUntil: 0 };

    entry.failures += 1;
    entry.lastFailureAt = now;

    if (entry.failures >= this.#max) {
      entry.lockedUntil = now + this.#lockoutMs;
      this.#entries.set(key, entry);
      this.#log.warn(
        {
          ...context,
          username: key,
          reason: 'login_rate_limited',
          failures: entry.failures,
          lockoutSeconds: Math.round(this.#lockoutMs / 1000),
        },
        'too many failed form attempts for this user name: further attempts are refused until the cool-down elapses',
      );
      return {
        locked: true,
        retryAfterSeconds: Math.ceil(this.#lockoutMs / 1000),
        failures: entry.failures,
      };
    }

    this.#entries.set(key, entry);
    this.#log.debug(
      { ...context, username: key, failures: entry.failures, allowed: this.#max },
      'failed form attempt recorded',
    );
    return { locked: false, retryAfterSeconds: 0, failures: entry.failures };
  }

  /** A successful login wipes the user's history. */
  reset(username: string): void {
    if (!this.enabled) return;
    this.#entries.delete(normalize(username));
  }

  /** Test seam. */
  failures(username: string): number {
    return this.#entries.get(normalize(username))?.failures ?? 0;
  }
}

/** The same normalization the rest of the server applies to a user name. */
function normalize(username: string): string {
  return username.trim().toLowerCase();
}
