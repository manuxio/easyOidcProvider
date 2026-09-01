/**
 * A deadline the callee cannot opt out of.
 *
 * Every remote gate in this server — the SQL group check, the two-factor seed
 * lookup — runs inside a login, so a database or a directory that stops
 * answering must turn into a rejection quickly instead of holding the request
 * open. Client-side timeouts are configured too, but they are the driver's
 * promise; this is ours.
 *
 * The losing promise keeps whatever resource it holds until the server hangs up.
 * That is acceptable for work that runs once per login, and it is the reason the
 * connection pools behind these calls are deliberately tiny.
 */

/** How the promise abandoned by a fired deadline eventually ended. */
export interface LateSettlement {
  outcome: 'fulfilled' | 'rejected';
  /** Milliseconds from the withDeadline call to the late settlement. */
  elapsedMs: number;
  /** The rejection reason, when outcome is 'rejected'. */
  error?: unknown;
}

export async function withDeadline<T>(
  work: Promise<T>,
  timeoutMs: number,
  onTimeout: () => Error,
  onLateSettle?: (settlement: LateSettlement) => void,
): Promise<T> {
  const startedAt = Date.now();
  let timer: NodeJS.Timeout | undefined;
  let timedOut = false;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      reject(onTimeout());
    }, timeoutMs);
    timer.unref?.();
  });
  try {
    return await Promise.race([work, deadline]);
  } finally {
    if (timer) clearTimeout(timer);
    // The losing promise must not surface as an unhandled rejection — and when
    // the deadline is what won, its eventual outcome is the diagnosis (which
    // step was hanging, for how long, with which error), so it is handed to the
    // caller instead of being dropped.
    work.then(
      () => {
        if (timedOut) onLateSettle?.({ outcome: 'fulfilled', elapsedMs: Date.now() - startedAt });
      },
      (error: unknown) => {
        if (timedOut) onLateSettle?.({ outcome: 'rejected', elapsedMs: Date.now() - startedAt, error });
      },
    ).catch(() => undefined);
  }
}
