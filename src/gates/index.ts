import type { Config } from '../config.js';
import type { IdentityProvider } from '../identity/types.js';
import type { Logger } from '../logger.js';
// --- phase 4: optional SQL group check ---
import { createSqlGroupChecker, type SqlDriver } from '../sqlcheck/index.js';
import { sqlGroupGate } from './sqlGroup.js';
// --- end phase 4 ---
import type {
  AccountGate,
  AccountGateContext,
  AccountGateVerdict,
} from './types.js';

export * from './types.js';
export { sqlGroupGate, SQL_GROUP_CHECK_FAILED, SQL_GROUP_GATE_NAME } from './sqlGroup.js';

/**
 * Liveness of the account as the identity provider sees it.
 * dev-stub reads the `active` flag; phase 3 reads userAccountControl /
 * accountExpires over LDAP behind the same method.
 */
export function accountActiveGate(identity: IdentityProvider): AccountGate {
  return {
    name: 'account_active',
    async check(context) {
      // --- phase 3 addition ------------------------------------------------
      // A provider that can name the reason (spnego reads userAccountControl,
      // accountExpires and LDAP_REQUIRED_GROUP) gets to say it, instead of
      // having every refusal flattened into `account_disabled`.
      if (identity.inspectAccount) {
        const status = await identity.inspectAccount(context.principal);
        return status.active
          ? { allowed: true }
          : { allowed: false, reason: status.reason };
      }
      // --- end phase 3 addition --------------------------------------------
      const active = await identity.isAccountActive(context.principal);
      return active ? { allowed: true } : { allowed: false, reason: 'account_disabled' };
    },
  };
}

/** Seams the tests use to observe the gates without a database. */
export interface BuildAccountGatesOptions {
  /** Injected in place of the configured engine; ignored when the check is off. */
  sqlDriver?: SqlDriver;
}

/**
 * Builds the ordered gate list. Cheap and local checks first, remote ones last.
 */
export function buildAccountGates(
  config: Config,
  identity: IdentityProvider,
  logger: Logger,
  options: BuildAccountGatesOptions = {},
): AccountGate[] {
  const gates: AccountGate[] = [accountActiveGate(identity)];

  // --- phase 4: optional SQL group check ---
  // The switch is the whole contract: with it off nothing here is constructed,
  // so no checker exists, no pool exists, and the database library is never even
  // loaded (the drivers import it lazily, on the first query).
  if (config.sqlGroupCheck.enabled) {
    const checker = createSqlGroupChecker(
      config.sqlGroupCheck,
      logger,
      options.sqlDriver ? { driver: options.sqlDriver } : {},
    );
    gates.push(sqlGroupGate(checker));
    logger.info(
      { driver: config.sqlGroupCheck.driver, timeoutMs: config.sqlGroupCheck.timeoutMs },
      'SQL group check enabled: a second authorization gate runs at login and at every refresh',
    );
  }
  // --- end phase 4 ---

  return gates;
}

/** Releases every gate that holds something open. Never throws. */
export async function closeAccountGates(
  gates: readonly AccountGate[],
  logger: Logger,
): Promise<void> {
  for (const gate of gates) {
    try {
      await gate.close?.();
    } catch (error) {
      logger.warn({ gate: gate.name, err: error }, 'gate did not close cleanly');
    }
  }
}

/**
 * Runs every gate in order. Never throws and never fails open: a gate that
 * blows up (directory unreachable, query timeout) is a rejection, loudly logged.
 */
export async function runAccountGates(
  gates: readonly AccountGate[],
  context: AccountGateContext,
  logger: Logger,
): Promise<AccountGateVerdict> {
  for (const gate of gates) {
    let result;
    try {
      result = await gate.check(context);
    } catch (error) {
      logger.error(
        {
          gate: gate.name,
          stage: context.stage,
          username: context.username,
          clientId: context.clientId,
          reason: 'gate_unavailable',
          err: error instanceof Error ? { message: error.message, stack: error.stack } : error,
        },
        'account gate could not be evaluated: rejecting (fail closed)',
      );
      return {
        ok: false,
        reason: 'gate_unavailable',
        gate: gate.name,
        unavailable: true,
      };
    }

    if (!result.allowed) {
      logger.warn(
        {
          gate: gate.name,
          stage: context.stage,
          username: context.username,
          clientId: context.clientId,
          reason: result.reason,
        },
        'account gate rejected the request',
      );
      return { ok: false, reason: result.reason, gate: gate.name, unavailable: false };
    }
  }

  logger.debug(
    { stage: context.stage, username: context.username, clientId: context.clientId },
    'all account gates passed',
  );
  return { ok: true };
}
