/**
 * The optional SQL group gate (phase 4).
 *
 * Second cancello di autorizzazione: after the account is known to be alive in
 * the directory, an external non-AD database gets to say whether this user may
 * use the platform at all. It runs at login AND at every refresh, like every
 * other gate, because that is the whole point of the design.
 *
 * Three outcomes, and the gate contract already carries all of them:
 *   row present  ⇒ { allowed: true }
 *   no row       ⇒ { allowed: false, reason: 'sql_group_check_failed' }
 *                  login: access denied; refresh: invalid_grant + chain revoked
 *   DB silent    ⇒ throw ⇒ runAccountGates marks it `unavailable`
 *                  login and refresh: temporarily_unavailable, chain NOT revoked
 */
import type { SqlGroupChecker } from '../sqlcheck/index.js';
import type { AccountGate } from './types.js';

/** Stable reason token, logged and mapped to the Italian message on the form. */
export const SQL_GROUP_CHECK_FAILED = 'sql_group_check_failed';

export const SQL_GROUP_GATE_NAME = 'sql_group';

export function sqlGroupGate(checker: SqlGroupChecker): AccountGate {
  return {
    name: SQL_GROUP_GATE_NAME,

    async check(context) {
      // The username, not the principal: the query keys on the platform
      // username, which is the sAMAccountName lowercased without the realm.
      // It goes down as a bind parameter — the checker has no other way in.
      const authorized = await checker.isAuthorized(context.username);
      return authorized
        ? { allowed: true }
        : { allowed: false, reason: SQL_GROUP_CHECK_FAILED };
    },

    async close() {
      await checker.close();
    },
  };
}
