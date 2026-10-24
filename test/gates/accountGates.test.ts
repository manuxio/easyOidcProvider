/**
 * The gate list itself (src/gates/index.ts), with scripted identity providers:
 * what 1.3.0 changed and what runAccountGates promises on every stage.
 *
 *  - accountActiveGate: `inspectAccount` preferred when the provider has it
 *    (its own reason comes through), `isAccountActive` otherwise
 *    (`account_disabled`); the shared lookup of buildAccountGates wins over a
 *    direct call;
 *  - the memoised inspector: ONE directory read per gate run, keyed on the
 *    context object, shared by account_active and client_ldap_group, forgotten
 *    with the run, and a rejection memoised too;
 *  - buildAccountGates: client_ldap_group right after liveness and only when
 *    some client declares required_ldap_groups, the SQL gate last, and a loud
 *    wiring fault when groups are configured on a provider that cannot read them;
 *  - runAccountGates: in order, first refusal wins, a throw is
 *    `gate_unavailable` with `unavailable: true`, never fail open.
 *
 * test/sqlcheck/gate.test.ts covers the SQL half and closeAccountGates.
 */
import { describe, expect, it } from 'vitest';

import { loadConfig, type Config } from '../../src/config.js';
import {
  accountActiveGate,
  buildAccountGates,
  CLIENT_GROUP_GATE_NAME,
  CLIENT_GROUP_NOT_ALLOWED,
  runAccountGates,
  SQL_GROUP_GATE_NAME,
  type AccountGate,
  type AccountGateContext,
  type GateStage,
} from '../../src/gates/index.js';
import type { IdentityAccountStatus, IdentityProvider } from '../../src/identity/types.js';
import { createSilentLogger } from '../../src/logger.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';
import { FakeSqlDriver } from '../helpers/fakeSqlDriver.js';

const REALM = 'EXAMPLE.LOCAL';
const DB_ADMINS = 'CN=DB Admins,DC=example,DC=local';
const OPERATORS = 'CN=Operators,DC=example,DC=local';

const SPNEGO_ENV = {
  IDENTITY_PROVIDER: 'spnego',
  REALM,
  LDAP_URL: 'ldaps://dc1.example.local',
  LDAP_BIND_DN: `svc-auth@${REALM}`,
  LDAP_BIND_PASSWORD: 'Svc.Passw0rd!',
  LDAP_BASE_DN: 'DC=example,DC=local',
};

const RESTRICTED_CLIENT = {
  client_id: 'client-x',
  application_type: 'web',
  redirect_uris: ['https://client-x.example.local/callback'],
  required_ldap_groups: [DB_ADMINS],
};
const FREE_CLIENT = { client_id: 'client-y', redirect_uris: ['http://127.0.0.1/callback'] };

function configWith(clients: unknown[], env: Record<string, string> = {}): Config {
  return loadConfig({
    ISSUER_URL: 'https://auth.example.local',
    DATA_DIR: '',
    ...SPNEGO_ENV,
    CLIENTS_JSON: JSON.stringify(clients),
    ...env,
  });
}

/** A provider that can only say yes or no: dev-stub and database behave like this. */
function livenessOnly(answer: boolean | Error) {
  const asked: string[] = [];
  const identity: IdentityProvider = {
    name: 'liveness-only',
    async authenticate() {
      return { status: 'no-credentials' };
    },
    async isAccountActive(principal: string) {
      asked.push(principal);
      if (answer instanceof Error) throw answer;
      return answer;
    },
    async challenge() {
      /* no challenge in these tests */
    },
  };
  return { identity, asked };
}

/** A provider that reads the whole entry, groups included: spnego behaves like this. */
function inspecting(answer: IdentityAccountStatus | Error) {
  const inspected: string[] = [];
  const liveness: string[] = [];
  const identity: IdentityProvider = {
    name: 'inspecting',
    async authenticate() {
      return { status: 'no-credentials' };
    },
    async isAccountActive(principal: string) {
      liveness.push(principal);
      return true;
    },
    async inspectAccount(principal: string) {
      inspected.push(principal);
      if (answer instanceof Error) throw answer;
      return answer;
    },
    async challenge() {
      /* no challenge in these tests */
    },
  };
  return { identity, inspected, liveness };
}

function context(stage: GateStage = 'login', clientId = 'client-x'): AccountGateContext {
  return { principal: `mario.rossi@${REALM}`, username: 'mario.rossi', stage, clientId };
}

describe('accountActiveGate', () => {
  it('asks isAccountActive when the provider cannot name a reason', async () => {
    const { identity, asked } = livenessOnly(true);
    await expect(accountActiveGate(identity).check(context())).resolves.toEqual({ allowed: true });
    expect(asked).toEqual([`mario.rossi@${REALM}`]);
  });

  it('flattens a "no" from isAccountActive into account_disabled', async () => {
    const { identity } = livenessOnly(false);
    await expect(accountActiveGate(identity).check(context())).resolves.toEqual({
      allowed: false,
      reason: 'account_disabled',
    });
  });

  it("prefers inspectAccount and passes the provider's own reason through", async () => {
    const { identity, inspected, liveness } = inspecting({ active: false, reason: 'account_locked' });
    await expect(accountActiveGate(identity).check(context())).resolves.toEqual({
      allowed: false,
      reason: 'account_locked',
    });
    expect(inspected).toEqual([`mario.rossi@${REALM}`]);
    expect(liveness).toEqual([]);
  });

  it('uses the shared lookup it is given instead of calling the provider itself', async () => {
    const { identity, inspected } = inspecting({ active: false, reason: 'never_used' });
    const handed: AccountGateContext[] = [];
    const gate = accountActiveGate(identity, async (ctx) => {
      handed.push(ctx);
      return { active: true, memberOf: [] };
    });
    const ctx = context();
    await expect(gate.check(ctx)).resolves.toEqual({ allowed: true });
    expect(handed).toEqual([ctx]);
    expect(inspected).toEqual([]);
  });

  it('lets the provider exception through: "cannot tell" is decided by runAccountGates', async () => {
    const { identity } = livenessOnly(new Error('directory down'));
    await expect(accountActiveGate(identity).check(context())).rejects.toThrow('directory down');
  });
});

describe('buildAccountGates with required_ldap_groups', () => {
  it('appends client_ldap_group right after account_active, and announces it', () => {
    const capture = createCapturingLogger();
    const { identity } = inspecting({ active: true, memberOf: [DB_ADMINS] });
    const gates = buildAccountGates(configWith([RESTRICTED_CLIENT, FREE_CLIENT]), identity, capture.logger);

    expect(gates.map((gate) => gate.name)).toEqual(['account_active', CLIENT_GROUP_GATE_NAME]);
    const [line] = capture.matching('per-client LDAP group restriction enabled');
    expect(line).toMatchObject({ level: 'info', clientRequiredGroups: { 'client-x': [DB_ADMINS] } });
  });

  it('registers no group gate when no client declares groups', () => {
    const capture = createCapturingLogger();
    const { identity } = inspecting({ active: true, memberOf: [] });
    const gates = buildAccountGates(configWith([FREE_CLIENT]), identity, capture.logger);
    expect(gates.map((gate) => gate.name)).toEqual(['account_active']);
    expect(capture.matching('per-client LDAP group restriction')).toHaveLength(0);
  });

  it('stops the build when groups are configured but the provider cannot read them', () => {
    const { identity } = livenessOnly(true);
    expect(() => buildAccountGates(configWith([RESTRICTED_CLIENT]), identity, createSilentLogger()))
      .toThrow('required_ldap_groups is set but the liveness-only identity provider cannot read AD groups');
  });

  it('keeps the SQL gate last, after the group gate', () => {
    const { identity } = inspecting({ active: true, memberOf: [DB_ADMINS] });
    const gates = buildAccountGates(
      configWith([RESTRICTED_CLIENT], {
        SQL_GROUP_CHECK_ENABLED: 'true',
        SQL_DRIVER: 'mysql',
        SQL_CONNECTION_STRING: 'mysql://user:pw@127.0.0.1:3306/backoffice',
        SQL_GROUP_QUERY: 'SELECT 1 FROM authorized_users WHERE username = ?',
      }),
      identity,
      createSilentLogger(),
      { sqlDriver: new FakeSqlDriver({ authorized: ['mario.rossi'] }) },
    );
    expect(gates.map((gate) => gate.name)).toEqual(['account_active', CLIENT_GROUP_GATE_NAME, SQL_GROUP_GATE_NAME]);
  });
});

describe('one directory read per gate run', () => {
  it('shares the read between account_active and client_ldap_group', async () => {
    const { identity, inspected } = inspecting({ active: true, memberOf: [DB_ADMINS] });
    const gates = buildAccountGates(configWith([RESTRICTED_CLIENT]), identity, createSilentLogger());

    await expect(runAccountGates(gates, context(), createSilentLogger())).resolves.toEqual({ ok: true });
    expect(inspected).toHaveLength(1);
  });

  it('reads afresh on the next run: a new context is a new run', async () => {
    const { identity, inspected } = inspecting({ active: true, memberOf: [DB_ADMINS] });
    const gates = buildAccountGates(configWith([RESTRICTED_CLIENT]), identity, createSilentLogger());

    await runAccountGates(gates, context('login'), createSilentLogger());
    await runAccountGates(gates, context('refresh'), createSilentLogger());
    expect(inspected).toHaveLength(2);
  });

  it('memoises a failed read too, so an outage is one round trip, not one per gate', async () => {
    const { identity, inspected } = inspecting(new Error('LDAP account search failed: ETIMEDOUT'));
    const gates = buildAccountGates(configWith([RESTRICTED_CLIENT]), identity, createSilentLogger());
    const ctx = context();

    await expect(gates[0]!.check(ctx)).rejects.toThrow(/ETIMEDOUT/);
    await expect(gates[1]!.check(ctx)).rejects.toThrow(/ETIMEDOUT/);
    expect(inspected).toHaveLength(1);
  });

  it('refuses a non-member through the group gate on the same single read', async () => {
    const { identity, inspected } = inspecting({ active: true, memberOf: [OPERATORS] });
    const gates = buildAccountGates(configWith([RESTRICTED_CLIENT]), identity, createSilentLogger());

    await expect(runAccountGates(gates, context(), createSilentLogger())).resolves.toEqual({
      ok: false,
      reason: CLIENT_GROUP_NOT_ALLOWED,
      gate: CLIENT_GROUP_GATE_NAME,
      unavailable: false,
    });
    expect(inspected).toHaveLength(1);
  });

  it('turns a directory outage into gate_unavailable on the first gate, never a pass', async () => {
    const { identity } = inspecting(new Error('LDAP account search failed: ETIMEDOUT'));
    const gates = buildAccountGates(configWith([RESTRICTED_CLIENT]), identity, createSilentLogger());
    await expect(runAccountGates(gates, context('token_exchange'), createSilentLogger())).resolves.toEqual({
      ok: false,
      reason: 'gate_unavailable',
      gate: 'account_active',
      unavailable: true,
    });
  });

  it('lets an unrestricted client through on the liveness read alone', async () => {
    const { identity, inspected } = inspecting({ active: true, memberOf: [] });
    const gates = buildAccountGates(configWith([RESTRICTED_CLIENT, FREE_CLIENT]), identity, createSilentLogger());
    await expect(runAccountGates(gates, context('authorization', 'client-y'), createSilentLogger()))
      .resolves.toEqual({ ok: true });
    expect(inspected).toHaveLength(1);
  });
});

describe('runAccountGates', () => {
  /** A gate that records being asked and answers as scripted. */
  function scripted(name: string, answer: 'allow' | 'deny' | Error | string, asked: string[]): AccountGate {
    return {
      name,
      async check() {
        asked.push(name);
        if (answer === 'allow') return { allowed: true };
        if (answer === 'deny') return { allowed: false, reason: `${name}_said_no` };
        throw answer;
      },
    };
  }

  it('passes an empty gate list', async () => {
    await expect(runAccountGates([], context(), createSilentLogger())).resolves.toEqual({ ok: true });
  });

  it('runs the gates in order and stops at the first refusal', async () => {
    const asked: string[] = [];
    const capture = createCapturingLogger();
    const verdict = await runAccountGates(
      [scripted('first', 'allow', asked), scripted('second', 'deny', asked), scripted('third', 'allow', asked)],
      context('refresh'),
      capture.logger,
    );
    expect(verdict).toEqual({ ok: false, reason: 'second_said_no', gate: 'second', unavailable: false });
    expect(asked).toEqual(['first', 'second']);

    const [line] = capture.matching('account gate rejected the request');
    expect(line).toMatchObject({
      level: 'warn',
      gate: 'second',
      stage: 'refresh',
      username: 'mario.rossi',
      clientId: 'client-x',
      reason: 'second_said_no',
    });
  });

  it('turns a throwing gate into gate_unavailable, logging the message and the stack', async () => {
    const asked: string[] = [];
    const capture = createCapturingLogger();
    const verdict = await runAccountGates(
      [scripted('remote', new Error('connect ECONNREFUSED'), asked), scripted('after', 'allow', asked)],
      context('token_exchange'),
      capture.logger,
    );
    expect(verdict).toEqual({ ok: false, reason: 'gate_unavailable', gate: 'remote', unavailable: true });
    expect(asked).toEqual(['remote']);

    const [line] = capture.withReason('gate_unavailable');
    expect(line).toMatchObject({ level: 'error', gate: 'remote', stage: 'token_exchange' });
    const err = line!.err as { message: string; stack: string };
    expect(err.message).toBe('connect ECONNREFUSED');
    expect(err.stack).toContain('connect ECONNREFUSED');
    expect(String(line!.msg)).toContain('fail closed');
  });

  it('logs a thrown non-Error as it was thrown', async () => {
    const capture = createCapturingLogger();
    const verdict = await runAccountGates([scripted('odd', 'a bare string', [])], context(), capture.logger);
    expect(verdict).toMatchObject({ ok: false, reason: 'gate_unavailable', unavailable: true });
    expect(capture.withReason('gate_unavailable')[0]!.err).toBe('a bare string');
  });

  it('says at debug that every gate passed', async () => {
    const capture = createCapturingLogger();
    await runAccountGates([scripted('only', 'allow', [])], context('authorization'), capture.logger);
    const [line] = capture.matching('all account gates passed');
    expect(line).toMatchObject({ level: 'debug', stage: 'authorization', clientId: 'client-x' });
  });

  it('hands the same context object to every gate of one run', async () => {
    const seen: AccountGateContext[] = [];
    const recorder = (name: string): AccountGate => ({
      name,
      async check(ctx) {
        seen.push(ctx);
        return { allowed: true };
      },
    });
    const ctx = context();
    await runAccountGates([recorder('a'), recorder('b')], ctx, createSilentLogger());
    expect(seen).toHaveLength(2);
    expect(seen[0]).toBe(ctx);
    expect(seen[1]).toBe(ctx);
  });
});
