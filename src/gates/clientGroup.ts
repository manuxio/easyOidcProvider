/**
 * The per-client LDAP group gate (1.3.0).
 *
 * A user client in CLIENTS_JSON may carry `required_ldap_groups`: the person
 * obtains tokens for THAT client only when their AD `memberOf` holds at least
 * one of those DNs. Direct membership only, compared exactly like
 * LDAP_REQUIRED_GROUP (sameDn in src/identity/ldap.ts). LDAP_REQUIRED_GROUP is
 * untouched and still applies to everybody, through the account_active gate;
 * this gate comes on top, and only for the clients that declare groups.
 *
 * It reads no directory of its own. The account_active gate has just read the
 * whole entry for the liveness check, memberOf included, and the two share that
 * read through `inspect` (one memoised lookup per gate run): one LDAPS round
 * trip per login, per refresh, per SSO reuse, whatever the gate count.
 *
 * Three outcomes, on the same contract as every other gate:
 *   member of one group     ⇒ { allowed: true }
 *   member of none          ⇒ { allowed: false, reason: 'client_group_not_allowed' }
 *                              login: the form says so; authorization: access_denied;
 *                              refresh: invalid_grant + THIS client's chain revoked
 *   directory silent        ⇒ throw ⇒ runAccountGates marks it `unavailable`
 *                              (never fail open), chain NOT revoked
 *
 * A refusal concerns one client. The shared browser session is never touched,
 * so the same person keeps using every client they are allowed on.
 */
import { sameDn } from '../identity/ldap.js';
import type { IdentityAccountStatus } from '../identity/types.js';
import type { Logger } from '../logger.js';
import type { AccountGate, AccountGateContext } from './types.js';

/** Stable reason token, logged and mapped to the Italian message on the form. */
export const CLIENT_GROUP_NOT_ALLOWED = 'client_group_not_allowed';

export const CLIENT_GROUP_GATE_NAME = 'client_ldap_group';

export function clientGroupGate(
  requiredGroups: ReadonlyMap<string, readonly string[]>,
  inspect: (context: AccountGateContext) => Promise<IdentityAccountStatus>,
  logger: Logger,
): AccountGate {
  const log = logger.child({ component: 'gate.client_ldap_group' });

  return {
    name: CLIENT_GROUP_GATE_NAME,

    async check(context) {
      // The client asking, and — on a token exchange — the client the traded
      // subject token was issued to: a person refused for dbsync-web must not
      // reach the same authority through a service that exchanges a
      // dbsync-web token. In practice the exchanging service can never declare
      // groups itself (config.ts refuses it), so the second id is the one that
      // matters there.
      const clientIds = [context.clientId, context.subjectClientId].filter(
        (id, index, all): id is string => id !== undefined && all.indexOf(id) === index,
      );
      const restricted = clientIds.filter((id) => requiredGroups.has(id));
      if (restricted.length === 0) return { allowed: true };

      const status = await inspect(context);
      if (!status.active) {
        // The account_active gate runs first and has already refused this; the
        // gate stays correct on its own anyway, with the provider's own reason.
        return { allowed: false, reason: status.reason };
      }
      if (status.memberOf === undefined) {
        // config.ts refuses required_ldap_groups unless the identity provider
        // reads groups, so this is a wiring fault. Thrown, so it is a loud
        // `gate_unavailable` rejection, never a silent pass.
        throw new Error(
          `client ${restricted.join(', ')} requires LDAP groups, but the identity provider returned no memberOf`,
        );
      }
      const memberOf = status.memberOf;

      for (const clientId of restricted) {
        const groups = requiredGroups.get(clientId)!;
        const matched = groups.find((group) => memberOf.some((dn) => sameDn(dn, group)));
        if (matched === undefined) {
          log.warn(
            {
              stage: context.stage,
              username: context.username,
              clientId,
              ...(clientId === context.clientId ? {} : { requestingClientId: context.clientId }),
              requiredGroups: groups,
              memberOf,
              reason: CLIENT_GROUP_NOT_ALLOWED,
            },
            'the account is not a direct member of any required_ldap_groups of the client',
          );
          return { allowed: false, reason: CLIENT_GROUP_NOT_ALLOWED };
        }
        log.debug(
          { stage: context.stage, username: context.username, clientId, matchedGroup: matched },
          'the account is a member of a required_ldap_groups entry of the client',
        );
      }
      return { allowed: true };
    },
  };
}
