/**
 * 1.3.0: the per-client LDAP group gate on its own (src/gates/clientGroup.ts),
 * with a scripted `inspect` in place of the directory.
 *
 * clientGroups.test.ts drives it end to end through the provider; this file
 * pins the decision table of the gate's header, case by case:
 *
 *   unrestricted client                 ⇒ allowed, and NO directory read
 *   member of one required group        ⇒ allowed (direct membership, sameDn)
 *   member of none                      ⇒ client_group_not_allowed
 *   account not active                  ⇒ the provider's own reason
 *   provider that returns no memberOf   ⇒ throws (a wiring fault, never a pass)
 *   directory silent                    ⇒ the rejection propagates (fail closed upstream)
 *
 * plus the token-exchange rule: the client the subject token was issued to is
 * checked too (`subjectClientId`), so a restriction cannot be bypassed through
 * an exchanging service.
 */
import { describe, expect, it } from 'vitest';

import {
  CLIENT_GROUP_GATE_NAME,
  CLIENT_GROUP_NOT_ALLOWED,
  clientGroupGate,
  type AccountGateContext,
} from '../../src/gates/index.js';
import type { IdentityAccountStatus } from '../../src/identity/types.js';
import { createSilentLogger } from '../../src/logger.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';

const DB_ADMINS = 'CN=DB Admins,DC=example,DC=local';
const AUDITORS = 'CN=Auditors,OU=Groups,DC=example,DC=local';
const OPERATORS = 'CN=Operators,OU=Groups,DC=example,DC=local';

const REQUIRED = new Map<string, readonly string[]>([
  ['client-x', [DB_ADMINS, AUDITORS]],
  ['client-y', [OPERATORS]],
]);

function context(overrides: Partial<AccountGateContext> = {}): AccountGateContext {
  return {
    principal: 'mario.rossi@EXAMPLE.LOCAL',
    username: 'mario.rossi',
    stage: 'login',
    clientId: 'client-x',
    ...overrides,
  };
}

/** A scripted directory read that counts its calls. */
function inspector(answer: IdentityAccountStatus | Error) {
  const calls: AccountGateContext[] = [];
  const inspect = async (ctx: AccountGateContext): Promise<IdentityAccountStatus> => {
    calls.push(ctx);
    if (answer instanceof Error) throw answer;
    return answer;
  };
  return { inspect, calls };
}

describe('which clients the gate looks at', () => {
  it('lets an unrestricted client through without reading the directory', async () => {
    const { inspect, calls } = inspector({ active: true, memberOf: [] });
    const gate = clientGroupGate(REQUIRED, inspect, createSilentLogger());
    await expect(gate.check(context({ clientId: 'client-free' }))).resolves.toEqual({ allowed: true });
    expect(calls).toHaveLength(0);
  });

  it('lets a context with no client at all through without reading the directory', async () => {
    const { inspect, calls } = inspector({ active: true, memberOf: [] });
    const gate = clientGroupGate(REQUIRED, inspect, createSilentLogger());
    await expect(gate.check(context({ clientId: undefined }))).resolves.toEqual({ allowed: true });
    expect(calls).toHaveLength(0);
  });

  it('is named client_ldap_group', () => {
    const { inspect } = inspector({ active: true, memberOf: [] });
    expect(clientGroupGate(REQUIRED, inspect, createSilentLogger()).name).toBe(CLIENT_GROUP_GATE_NAME);
    expect(CLIENT_GROUP_GATE_NAME).toBe('client_ldap_group');
  });
});

describe('membership', () => {
  it('allows a direct member of any one of the required groups', async () => {
    const { inspect, calls } = inspector({ active: true, memberOf: [OPERATORS, AUDITORS] });
    const gate = clientGroupGate(REQUIRED, inspect, createSilentLogger());
    await expect(gate.check(context())).resolves.toEqual({ allowed: true });
    expect(calls).toHaveLength(1);
  });

  it('compares DNs ignoring case and the blanks around the commas', async () => {
    const { inspect } = inspector({ active: true, memberOf: ['cn=db admins, dc=example ,DC=LOCAL'] });
    const gate = clientGroupGate(REQUIRED, inspect, createSilentLogger());
    await expect(gate.check(context())).resolves.toEqual({ allowed: true });
  });

  it('does not take a DN that only shares a prefix with the required one', async () => {
    const { inspect } = inspector({ active: true, memberOf: ['CN=DB Admins,OU=Old,DC=example,DC=local'] });
    const gate = clientGroupGate(REQUIRED, inspect, createSilentLogger());
    await expect(gate.check(context())).resolves.toEqual({
      allowed: false,
      reason: CLIENT_GROUP_NOT_ALLOWED,
    });
  });

  it('refuses a member of none with client_group_not_allowed, logging the raw memberOf', async () => {
    const capture = createCapturingLogger();
    const { inspect } = inspector({ active: true, memberOf: [OPERATORS] });
    const gate = clientGroupGate(REQUIRED, inspect, capture.logger);

    await expect(gate.check(context({ stage: 'refresh' }))).resolves.toEqual({
      allowed: false,
      reason: CLIENT_GROUP_NOT_ALLOWED,
    });
    const [line] = capture.withReason(CLIENT_GROUP_NOT_ALLOWED);
    expect(line).toMatchObject({
      level: 'warn',
      component: 'gate.client_ldap_group',
      stage: 'refresh',
      username: 'mario.rossi',
      clientId: 'client-x',
      requiredGroups: [DB_ADMINS, AUDITORS],
      memberOf: [OPERATORS],
    });
    // The asking client IS the restricted one: no second id in the line.
    expect(line).not.toHaveProperty('requestingClientId');
  });

  it('refuses an account with no group at all', async () => {
    const { inspect } = inspector({ active: true, memberOf: [] });
    const gate = clientGroupGate(REQUIRED, inspect, createSilentLogger());
    await expect(gate.check(context())).resolves.toMatchObject({ allowed: false, reason: CLIENT_GROUP_NOT_ALLOWED });
  });

  it('logs the matched group at debug when it lets a member through', async () => {
    const capture = createCapturingLogger();
    const { inspect } = inspector({ active: true, memberOf: [AUDITORS] });
    await clientGroupGate(REQUIRED, inspect, capture.logger).check(context());
    const [line] = capture.matching('is a member of a required_ldap_groups entry');
    expect(line).toMatchObject({ level: 'debug', clientId: 'client-x', matchedGroup: AUDITORS });
  });
});

describe('what the directory says besides groups', () => {
  it("returns the provider's own reason for an account that is not active", async () => {
    const { inspect } = inspector({ active: false, reason: 'account_expired' });
    const gate = clientGroupGate(REQUIRED, inspect, createSilentLogger());
    await expect(gate.check(context())).resolves.toEqual({ allowed: false, reason: 'account_expired' });
  });

  it('throws when the provider returns no memberOf: a wiring fault, never a silent pass', async () => {
    const { inspect } = inspector({ active: true });
    const gate = clientGroupGate(REQUIRED, inspect, createSilentLogger());
    await expect(gate.check(context())).rejects.toThrow(
      'client client-x requires LDAP groups, but the identity provider returned no memberOf',
    );
  });

  it('lets a directory outage propagate, for runAccountGates to mark unavailable', async () => {
    const outage = new Error('LDAP account search failed: connect ETIMEDOUT');
    const { inspect } = inspector(outage);
    const gate = clientGroupGate(REQUIRED, inspect, createSilentLogger());
    await expect(gate.check(context())).rejects.toBe(outage);
  });
});

describe('the token exchange: the subject token client counts too', () => {
  it('refuses when the subject token was issued to a restricted client the person is not allowed on', async () => {
    const capture = createCapturingLogger();
    const { inspect } = inspector({ active: true, memberOf: [AUDITORS] });
    const gate = clientGroupGate(REQUIRED, inspect, capture.logger);

    await expect(gate.check(context({
      stage: 'token_exchange',
      clientId: 'exchanging-service',
      subjectClientId: 'client-y',
    }))).resolves.toEqual({ allowed: false, reason: CLIENT_GROUP_NOT_ALLOWED });

    const [line] = capture.withReason(CLIENT_GROUP_NOT_ALLOWED);
    // The refused client, and separately the one that asked.
    expect(line).toMatchObject({ clientId: 'client-y', requestingClientId: 'exchanging-service' });
  });

  it('allows the exchange when the person is allowed on the subject token client', async () => {
    const { inspect } = inspector({ active: true, memberOf: [OPERATORS] });
    const gate = clientGroupGate(REQUIRED, inspect, createSilentLogger());
    await expect(gate.check(context({
      stage: 'token_exchange',
      clientId: 'exchanging-service',
      subjectClientId: 'client-y',
    }))).resolves.toEqual({ allowed: true });
  });

  it('checks both clients when both are restricted, and refuses on the first one that fails', async () => {
    const capture = createCapturingLogger();
    // Allowed on client-x (DB Admins), not on client-y (Operators).
    const { inspect, calls } = inspector({ active: true, memberOf: [DB_ADMINS] });
    const gate = clientGroupGate(REQUIRED, inspect, capture.logger);

    await expect(gate.check(context({ clientId: 'client-x', subjectClientId: 'client-y' })))
      .resolves.toEqual({ allowed: false, reason: CLIENT_GROUP_NOT_ALLOWED });
    // One directory read for both clients.
    expect(calls).toHaveLength(1);
    expect(capture.withReason(CLIENT_GROUP_NOT_ALLOWED)[0]).toMatchObject({ clientId: 'client-y' });
  });

  it('checks a client once when the subject token was issued to the asking client itself', async () => {
    const capture = createCapturingLogger();
    const { inspect } = inspector({ active: true, memberOf: [DB_ADMINS] });
    await clientGroupGate(REQUIRED, inspect, capture.logger)
      .check(context({ clientId: 'client-x', subjectClientId: 'client-x' }));
    expect(capture.matching('is a member of a required_ldap_groups entry')).toHaveLength(1);
  });

  it('names every restricted client in the wiring-fault message', async () => {
    const { inspect } = inspector({ active: true });
    const gate = clientGroupGate(REQUIRED, inspect, createSilentLogger());
    await expect(gate.check(context({ clientId: 'client-x', subjectClientId: 'client-y' })))
      .rejects.toThrow('client client-x, client-y requires LDAP groups');
  });
});
