/**
 * RFC 8693 token exchange through the token endpoint: the refusals that
 * test/tokenExchange.test.ts does not reach, on a real auth-server.
 *
 *   - `issued_by_grants` read word by word: a rule that accepts only the code
 *     grant takes the first A′ and refuses the renewed one;
 *   - a registry record that disagrees with the token, or that is malformed;
 *   - a Grant store that cannot answer: fail closed, nothing issued.
 *
 * The registry records are altered on the way out of the inspectable store
 * (test/helpers/memoryAdapter.ts), which is the only way to make the stored
 * state disagree with a token the server itself signed.
 *
 * Follows the token-exchange design notes (RFC 8693).
 */
import * as client from 'openid-client';
import type { Adapter, AdapterFactory, AdapterPayload } from 'oidc-provider';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import { SUBJECT_TOKEN_RECORD_MODEL } from '../../src/provider/subjectTokens.js';
import { createCapturingLogger, type CapturingLogger } from '../helpers/captureLogger.js';
import { decodeJwtPayload, discover, exchange, login } from '../helpers/flow.js';
import { createInspectableStore, type InspectableStore } from '../helpers/memoryAdapter.js';
import { CLIENT_ID, REGISTERED_REDIRECT, startTestServer, type TestServer } from '../helpers/server.js';
import {
  AGENT_CLIENT_ID,
  agentClient,
  agentKeys,
  assertion,
  contractRule,
  exchangeFields,
  exchangeRequest,
  type AgentKeys,
} from '../helpers/tokenExchange.js';

const AUDIENCE = 'https://easyoidc.test/api';
const DEFAULT_RESOURCE = { scope: 'api', grants: ['client_credentials'] };
const CRM = {
  scope: 'crm',
  audience: 'crm',
  grants: ['authorization_code', 'token-exchange'],
  exchange_scopes: ['llm'],
};
const AGENT = { scope: 'agent', audience: 'agent-service', grants: ['authorization_code'] };
const MARIO = { username: 'mario.rossi', password: 'Password1!' };
const USER_CLIENT = { client_id: CLIENT_ID, redirect_uris: [REGISTERED_REDIRECT], scope: 'openid crm agent' };

let keys: AgentKeys;
beforeAll(async () => {
  keys = await agentKeys('agent-provider-e2e');
});

const running: TestServer[] = [];
afterEach(async () => {
  while (running.length > 0) await running.pop()!.close();
});

interface Started {
  s: TestServer;
  capture: CapturingLogger;
  store: InspectableStore;
  /** Set to rewrite every SubjectTokenRecord the server reads. */
  tamper: { record?: (payload: AdapterPayload) => AdapterPayload };
}

/** The inspectable store, with the registry reads passing through `tamper.record`. */
function tamperingFactory(store: InspectableStore, tamper: Started['tamper']): AdapterFactory {
  return (model: string): Adapter => {
    const inner = store.adapterFactory(model) as Adapter;
    if (model !== SUBJECT_TOKEN_RECORD_MODEL) return inner;
    return {
      ...inner,
      async find(id) {
        const found = await inner.find(id);
        return found && tamper.record ? tamper.record(found) : found;
      },
    };
  };
}

async function server(rule: Record<string, unknown> = contractRule([CLIENT_ID])): Promise<Started> {
  const capture = createCapturingLogger();
  const store = createInspectableStore();
  const tamper: Started['tamper'] = {};
  const s = await startTestServer({
    users: [MARIO],
    logger: capture.logger,
    adapterFactory: tamperingFactory(store, tamper),
    env: {
      API_AUDIENCE: AUDIENCE,
      DEFAULT_RESOURCE_JSON: JSON.stringify(DEFAULT_RESOURCE),
      RESOURCE_SERVERS_JSON: JSON.stringify([CRM, AGENT]),
      CLIENTS_JSON: JSON.stringify([USER_CLIENT, agentClient([keys.publicJwk], [rule])]),
    },
  });
  running.push(s);
  return { s, capture, store, tamper };
}

/** A′: the person's login with scope `openid agent`, aud agent-service. */
async function aPrime(s: TestServer) {
  const config = await discover(s);
  const tokens = await exchange(config, await login(s, config, { ...MARIO, scope: 'openid agent' }));
  return { tokens, config };
}

async function exchangeAs(s: TestServer, subjectToken: string) {
  return exchangeRequest(s, exchangeFields(subjectToken), { assertion: await assertion(s, keys) });
}

function expectRefused(
  result: { status: number; body: Record<string, unknown> },
  error: string,
  capture: CapturingLogger,
  reason: string,
): void {
  expect(result.status).toBe(400);
  expect(result.body.error).toBe(error);
  expect(result.body.access_token).toBeUndefined();
  expect(capture.matching('token exchange refused').at(-1)).toMatchObject({ reason, clientId: AGENT_CLIENT_ID });
  expect(capture.matching('delegated access token issued')).toHaveLength(0);
}

describe('token exchange: issued_by_grants, word by word', () => {
  it('a rule that accepts only the code grant takes the first A′ and refuses the renewed one', async () => {
    const codeOnly = contractRule([CLIENT_ID]) as { subject: Record<string, unknown> };
    codeOnly.subject.issued_by_grants = ['authorization_code'];
    const { s, capture } = await server(codeOnly);
    const { tokens, config } = await aPrime(s);

    expect((await exchangeAs(s, tokens.access_token)).status).toBe(200);

    const renewed = await client.refreshTokenGrant(config, tokens.refresh_token!);
    expect(decodeJwtPayload(renewed.access_token).aud).toBe('agent-service');
    const refused = await exchangeAs(s, renewed.access_token);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('invalid_grant');
    expect(refused.body.error_description).toBe('subject_token was issued by a grant this rule does not accept');
    expect(capture.matching('token exchange refused').at(-1)).toMatchObject({
      reason: 'subject_grant_not_allowed',
      subjectJti: decodeJwtPayload(renewed.access_token).jti,
    });
  });
});

describe('token exchange: the registry record has to agree with the token', () => {
  it.each([
    ['accountId', 'luigi.verdi'],
    ['clientId', 'other-ui'],
    ['aud', 'crm'],
  ])('refuses a record whose %s differs from the token', async (field, value) => {
    const { s, capture, tamper } = await server();
    const { tokens } = await aPrime(s);
    tamper.record = (payload) => ({ ...payload, [field]: value });

    const refused = await exchangeAs(s, tokens.access_token);
    expectRefused(refused, 'invalid_grant', capture, 'subject_record_mismatch');
    expect(refused.body.error_description).toBe('subject_token is invalid');
  });

  it('fails closed on a malformed record, as on a registry that cannot answer', async () => {
    const { s, capture, tamper } = await server();
    const { tokens } = await aPrime(s);
    tamper.record = (payload) => {
      const { gty: _dropped, ...rest } = payload as Record<string, unknown>;
      return rest as AdapterPayload;
    };

    const refused = await exchangeAs(s, tokens.access_token);
    expectRefused(refused, 'temporarily_unavailable', capture, 'registry_unavailable');
    const logged = capture.matching('the subject token registry could not be read');
    expect(logged).toHaveLength(1);
    expect(String((logged[0]!.err as { message?: string }).message)).toContain('is malformed');
  });

  it('accepts the same token again once the record is back as it was', async () => {
    const { s, tamper } = await server();
    const { tokens } = await aPrime(s);
    tamper.record = (payload) => ({ ...payload, accountId: 'luigi.verdi' });
    expect((await exchangeAs(s, tokens.access_token)).status).toBe(400);
    tamper.record = undefined;
    expect((await exchangeAs(s, tokens.access_token)).status).toBe(200);
  });
});

describe('token exchange: the grant of the subject', () => {
  it('fails closed when the Grant store cannot answer, and the chain is left alone', async () => {
    const { s, capture, store } = await server();
    const { tokens } = await aPrime(s);
    const grantsBefore = store.entries('Grant').size;
    store.failFind('Grant');

    const refused = await exchangeAs(s, tokens.access_token);
    expectRefused(refused, 'temporarily_unavailable', capture, 'grant_unavailable');
    expect(capture.matching('the grant of the subject token could not be read')).toHaveLength(1);
    expect(store.entries('Grant').size).toBe(grantsBefore);
  });
});
