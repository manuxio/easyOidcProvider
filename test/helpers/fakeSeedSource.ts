/**
 * A TwoFactorSeedSource answering from an in-memory table, and recording every
 * lookup. It is the instrument for three separate claims:
 *
 *  - the verifier asks the source exactly once per submitted code, and does not
 *    ask at all for a code that cannot possibly be valid;
 *  - a user with no row is refused as "not enrolled", never let through;
 *  - a source that throws is an outage, not a verdict.
 */
import type { TwoFactorSeedSource } from '../../src/twofactor/index.js';

export class FakeSeedSource implements TwoFactorSeedSource {
  readonly name: string;
  readonly lookups: string[] = [];
  readonly seeds = new Map<string, string>();
  /** Set to make the next lookup throw, the way an unreachable source does. */
  failWith?: Error;
  closed = false;

  constructor(seeds: Record<string, string> = {}, name = 'fake') {
    this.name = name;
    for (const [username, seed] of Object.entries(seeds)) {
      this.seeds.set(username.toLowerCase(), seed);
    }
  }

  async lookup(username: string): Promise<string | undefined> {
    this.lookups.push(username);
    if (this.failWith) throw this.failWith;
    return this.seeds.get(username.toLowerCase());
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}
