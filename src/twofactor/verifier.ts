/**
 * TOTP verification, RFC 6238, on `otplib`.
 *
 * Fixed parameters, by decision of the plan and NOT configurable: 6 digits,
 * 30-second step, tolerance ±1 step. They are constructor options only so the
 * unit tests can move the clock and the window; no environment variable reaches
 * them, because a deployment that quietly widens its own TOTP window is a
 * deployment nobody can reason about.
 *
 * REPLAY PROTECTION IS IN-MEMORY AND THEREFORE SINGLE-INSTANCE. The last time
 * step accepted for a user is kept in a Map in this process. One auth-server
 * container behind nginx — which is what phase 5 deploys — is exactly covered;
 * two replicas would each hold their own map, and a code replayed against the
 * *other* replica inside the same 30-second step would be accepted. Should the
 * deployment ever grow a second replica, this map is the piece that must move
 * to Mongo (it is one small document per user: username, step, seenAt).
 */
import { createGuardrails, verifySync, type VerifyResult as TotpVerifyResult } from 'otplib';

import type { Logger } from '../logger.js';
import {
  TWO_FACTOR_REASONS,
  TwoFactorSeedUnavailable,
  type TwoFactorOutcome,
  type TwoFactorSeedSource,
} from './types.js';

/** RFC 6238 defaults, and the plan's decision. */
export const TWO_FACTOR_DIGITS = 6;
export const TWO_FACTOR_STEP_SECONDS = 30;
/** ±1 step: one step of clock drift in each direction, no more. */
export const TWO_FACTOR_WINDOW_STEPS = 1;

/**
 * Minimum seed length: 10 bytes = 80 bits = 16 base32 characters.
 *
 * RFC 4226 §4 R6 asks for 128 bits and otplib enforces that by default, but the
 * customer's installed base (legacy `totpsecret` columns)
 * carries the classic 80-bit Google-Authenticator format, and re-enrolling
 * every user was not on the table. 80 bits is the historical de-facto floor of
 * the TOTP ecosystem; anything shorter stays refused as `seed_invalid`.
 * New enrolments should still be issued at 160 bits (32 base32 characters).
 */
export const TWO_FACTOR_MIN_SECRET_BYTES = 10;

const SEED_GUARDRAILS = createGuardrails({ MIN_SECRET_BYTES: TWO_FACTOR_MIN_SECRET_BYTES });

/**
 * Ceiling on the replay map. A login floor has hundreds of agents, not tens of
 * thousands, so this is never reached in practice; it exists so that a stream of
 * logins for made-up usernames cannot grow the map without bound.
 */
const DEFAULT_MAX_TRACKED_USERS = 10_000;

export interface TwoFactorVerifierOptions {
  source: TwoFactorSeedSource;
  logger: Logger;
  /** Test seams. Production uses the constants above. */
  digits?: number;
  stepSeconds?: number;
  windowSteps?: number;
  /** Unix milliseconds. Injected by the unit tests to sit on a chosen step. */
  now?: () => number;
  maxTrackedUsers?: number;
}

interface AcceptedStep {
  step: number;
  seenAt: number;
}

export class TwoFactorVerifier {
  readonly #source: TwoFactorSeedSource;
  readonly #log: Logger;
  readonly #digits: number;
  readonly #stepSeconds: number;
  readonly #windowSeconds: number;
  readonly #now: () => number;
  readonly #maxTrackedUsers: number;
  /** username -> the last time step accepted for them. See the file header. */
  readonly #accepted = new Map<string, AcceptedStep>();

  constructor(options: TwoFactorVerifierOptions) {
    this.#source = options.source;
    this.#digits = options.digits ?? TWO_FACTOR_DIGITS;
    this.#stepSeconds = options.stepSeconds ?? TWO_FACTOR_STEP_SECONDS;
    this.#windowSeconds = (options.windowSteps ?? TWO_FACTOR_WINDOW_STEPS) * this.#stepSeconds;
    this.#now = options.now ?? (() => Date.now());
    this.#maxTrackedUsers = options.maxTrackedUsers ?? DEFAULT_MAX_TRACKED_USERS;
    this.#log = options.logger.child({ component: 'two-factor', source: options.source.name });
  }

  get sourceName(): string {
    return this.#source.name;
  }

  /**
   * Checks one code for one user. Never throws: an unreachable seed source comes
   * back as `unavailable`, which the caller turns into a refusal.
   */
  async verify(username: string, rawCode: string): Promise<TwoFactorOutcome> {
    // Users type the code out of an authenticator app, which shows it as two
    // groups of three; a space in the middle is a typing habit, not a wrong code.
    const code = rawCode.replace(/[\s-]/g, '');

    if (code === '') {
      this.#log.warn(
        { username, reason: TWO_FACTOR_REASONS.missingCode },
        'the second factor is required and no verification code was submitted',
      );
      return { status: 'failed', reason: TWO_FACTOR_REASONS.missingCode };
    }

    if (!new RegExp(`^\\d{${this.#digits}}$`).test(code)) {
      // Refused before the seed is even fetched: a malformed code cannot become
      // a valid one, and not fetching keeps a keyboard-mashing client off the
      // database.
      this.#log.warn(
        { username, reason: TWO_FACTOR_REASONS.malformedCode, length: code.length },
        `the verification code is not ${this.#digits} digits`,
      );
      return { status: 'failed', reason: TWO_FACTOR_REASONS.malformedCode };
    }

    let seed: string | undefined;
    const startedAt = Date.now();
    try {
      seed = await this.#source.lookup(username);
    } catch (error) {
      const unavailable = error instanceof TwoFactorSeedUnavailable
        ? error
        : new TwoFactorSeedUnavailable(this.#source.name, describe(error), error);
      this.#log.error(
        {
          username,
          reason: TWO_FACTOR_REASONS.unavailable,
          durationMs: Date.now() - startedAt,
          err: { name: unavailable.name, message: unavailable.message },
        },
        'the two-factor seed source could not be read: refusing the login (fail closed)',
      );
      return { status: 'unavailable', reason: TWO_FACTOR_REASONS.unavailable };
    }

    if (seed === undefined || seed.trim() === '') {
      this.#log.error(
        { username, reason: TWO_FACTOR_REASONS.notEnrolled },
        'two-factor authentication is on but this user has no seed in the configured source: refusing the login (fail closed)',
      );
      return { status: 'not-enrolled', reason: TWO_FACTOR_REASONS.notEnrolled };
    }

    const epoch = Math.floor(this.#now() / 1000);
    let result: TotpVerifyResult;
    try {
      /**
       * The cast narrows otplib's TOTP|HOTP union to the TOTP half. It is safe
       * because `strategy` is fixed to 'totp' right here, and it is needed
       * because only the TOTP result carries `timeStep` — the number the replay
       * check below is built on.
       */
      result = verifySync({
        strategy: 'totp',
        secret: seed.trim(),
        token: code,
        epoch,
        // otplib takes the tolerance in SECONDS, not in steps.
        epochTolerance: this.#windowSeconds,
        period: this.#stepSeconds,
        digits: this.#digits as 6,
        // Accepts the customer's legacy 80-bit seeds; see the constant above.
        guardrails: SEED_GUARDRAILS,
      }) as TotpVerifyResult;
    } catch (error) {
      // otplib refuses a secret that is not base32, or shorter than the floor
      // set above. Either way the enrolment record is unusable, which is a
      // fault in the source, not a wrong code — so it is logged as one.
      this.#log.error(
        {
          username,
          reason: TWO_FACTOR_REASONS.seedInvalid,
          err: { message: describe(error) },
        },
        'the seed stored for this user is not a usable base32 TOTP secret: refusing the login (fail closed)',
      );
      return { status: 'not-enrolled', reason: TWO_FACTOR_REASONS.seedInvalid };
    }

    if (!result.valid) {
      this.#log.warn(
        { username, reason: TWO_FACTOR_REASONS.failed },
        'the verification code did not match inside the tolerance window',
      );
      return { status: 'failed', reason: TWO_FACTOR_REASONS.failed };
    }

    const previous = this.#accepted.get(username);
    if (previous !== undefined && result.timeStep <= previous.step) {
      // A code stays mathematically valid for the whole step plus the tolerance
      // window, so without this a code read over somebody's shoulder could be
      // used a second time within the minute.
      this.#log.warn(
        {
          username,
          reason: TWO_FACTOR_REASONS.replayed,
          timeStep: result.timeStep,
          lastAcceptedStep: previous.step,
        },
        'this verification code was already used: refusing the replay',
      );
      return { status: 'failed', reason: TWO_FACTOR_REASONS.replayed };
    }

    this.#remember(username, result.timeStep);
    this.#log.info(
      { username, timeStep: result.timeStep, delta: result.delta },
      'second factor accepted',
    );
    return { status: 'ok', timeStep: result.timeStep };
  }

  /** Exposed for the tests and for a future move of this state into Mongo. */
  lastAcceptedStep(username: string): number | undefined {
    return this.#accepted.get(username)?.step;
  }

  async close(): Promise<void> {
    this.#accepted.clear();
    await this.#source.close();
  }

  #remember(username: string, step: number): void {
    this.#accepted.set(username, { step, seenAt: this.#now() });
    if (this.#accepted.size <= this.#maxTrackedUsers) return;

    // Evict the least recently seen entries. Dropping one only costs the user
    // their replay protection for the current step, never their access.
    const oldest = [...this.#accepted.entries()]
      .sort((a, b) => a[1].seenAt - b[1].seenAt)
      .slice(0, this.#accepted.size - this.#maxTrackedUsers);
    for (const [name] of oldest) this.#accepted.delete(name);
    this.#log.warn(
      { evicted: oldest.length, tracked: this.#accepted.size },
      'the two-factor replay table hit its ceiling and the oldest entries were dropped',
    );
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
