/**
 * The RFC 8693 grant handler (src/provider/tokenExchange.ts) on its own, with a
 * fake koa context: no HTTP, no oidc-provider instance, a subject token signed
 * by a key the test owns.
 *
 * The HTTP contract is proved in test/tokenExchange.test.ts; this file covers
 * what the token endpoint cannot reach or cannot see: the ORDER of the checks
 * (contract, LLM-IN-CRM.md «Fase 0», point 4 — a refusal at one step consults
 * nothing of the steps after it), every refusal reason the log keeps, the
 * second locks behind the startup validation (rule_ambiguous,
 * resource_not_exchangeable), the findAccount outcomes, the D5 scope of the
 * issued token, and the private members stripped from the verification keys.
 *
 * Follows the token-exchange design notes (RFC 8693).
 */
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from 'jose';
import { errors, type Account, type KoaContextWithOIDC } from 'oidc-provider';
import { beforeAll, describe, expect, it } from 'vitest';

import { ACCESS_TOKEN_TYPE, SUBJECT_GRANTS, type TokenExchangeRule } from '../../src/config.js';
import { TemporarilyUnavailable } from '../../src/provider/errors.js';
import type { SubjectTokenRecord } from '../../src/provider/subjectTokens.js';
import {
  createTokenExchangeHandler,
  publicJwksOf,
  TOKEN_EXCHANGE_GTY,
  TOKEN_EXCHANGE_PARAMETERS,
  type ExchangeResource,
  type ExchangedSubject,
} from '../../src/provider/tokenExchange.js';
import { createCapturingLogger, type CapturingLogger } from '../helpers/captureLogger.js';
import { AGENT_CLIENT_ID } from '../helpers/tokenExchange.js';

const ISSUER = 'http://127.0.0.1:4444';
const KID = 'issuer-key-1';
const SUBJECT_CLIENT = 'desktop-app';
const USER = 'mario.rossi';
const JTI = 'jti-a-prime';
const GRANT_ID = 'grant-1';
const RULE_WHERE = 'CLIENTS_JSON[1].token_exchange[0]';

const RULE: TokenExchangeRule = {
  subject: {
    token_type: ACCESS_TOKEN_TYPE,
    audience: 'agent-service',
    client_ids: [SUBJECT_CLIENT],
    issued_by_grants: ['authorization_code', 'refresh_token'],
  },
  issue: {
    token_type: ACCESS_TOKEN_TYPE,
    audience: 'crm',
    scope: 'crm llm',
    ttl_seconds: 900,
    refresh_token: false,
  },
  where: RULE_WHERE,
};

const CRM: ExchangeResource = {
  indicator: 'urn:easyoidc:crm',
  audience: 'crm',
  scope: 'crm',
  grants: ['authorization_code', 'token-exchange'],
  exchangeScopes: ['llm'],
};

let issuerKey: CryptoKey;
let issuerPrivateJwk: JWK;
let strangerKey: CryptoKey;
beforeAll(async () => {
  const issuer = await generateKeyPair('RS256', { extractable: true });
  issuerKey = issuer.privateKey;
  issuerPrivateJwk = { ...(await exportJWK(issuer.privateKey)), kid: KID, alg: 'RS256', use: 'sig' };
  strangerKey = (await generateKeyPair('RS256')).privateKey;
});

const now = (): number => Math.floor(Date.now() / 1000);

/** A′ as the issuer signs it; `claims` overrides (undefined = left out), `header`/`key` to forge. */
async function subjectToken(
  options: { claims?: Record<string, unknown>; typ?: string; key?: CryptoKey } = {},
): Promise<string> {
  const payload: Record<string, unknown> = {
    iss: ISSUER,
    sub: USER,
    aud: 'agent-service',
    client_id: SUBJECT_CLIENT,
    jti: JTI,
    scope: 'agent',
    iat: now(),
    exp: now() + 300,
    ...options.claims,
  };
  for (const [name, value] of Object.entries(payload)) {
    if (value === undefined) delete payload[name];
  }
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', typ: options.typ ?? 'at+jwt', kid: KID })
    .sign(options.key ?? issuerKey);
}

interface FakeGrant {
  accountId: string;
  clientId: string;
  isExpired: boolean;
}

interface World {
  rules?: Map<string, readonly TokenExchangeRule[]>;
  resources?: ExchangeResource[];
  /** The registry content; `registryFails` makes find throw. */
  records?: Map<string, SubjectTokenRecord>;
  registryFails?: boolean;
  grants?: Map<string, FakeGrant>;
  grantFindFails?: boolean;
  findAccount?: (sub: string, subjectClientId: string) => Promise<Account | undefined>;
}

class FakeResourceServer {
  constructor(
    readonly identifier: string,
    readonly info: Record<string, unknown>,
  ) {}
}

interface Outcome {
  error: unknown;
  body: unknown;
  entities: Record<string, unknown>;
  /** Every AccessToken constructed: its constructor argument and final scope. */
  issued: Array<{ init: Record<string, unknown>; scope?: string }>;
  registryLookups: string[];
  grantLookups: string[];
  accountLookups: Array<{ sub: string; subjectClientId: string }>;
  capture: CapturingLogger;
  ctx: KoaContextWithOIDC;
}

function defaultRecord(): SubjectTokenRecord {
  return {
    accountId: USER,
    clientId: SUBJECT_CLIENT,
    grantId: GRANT_ID,
    gty: 'authorization_code',
    aud: 'agent-service',
    exp: now() + 300,
  };
}

function defaultGrant(): FakeGrant {
  return { accountId: USER, clientId: SUBJECT_CLIENT, isExpired: false };
}

/** The well-formed request for B; a field set to undefined is left out. */
function fields(subject: string, overrides: Record<string, string | undefined> = {}): Record<string, string> {
  const all: Record<string, string | undefined> = {
    subject_token: subject,
    subject_token_type: ACCESS_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TYPE,
    audience: 'crm',
    scope: 'llm',
    ...overrides,
  };
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(all)) if (value !== undefined) out[name] = value;
  return out;
}

async function run(params: Record<string, string>, world: World = {}): Promise<Outcome> {
  const capture = createCapturingLogger();
  const records = world.records ?? new Map([[JTI, defaultRecord()]]);
  const grants = world.grants ?? new Map([[GRANT_ID, defaultGrant()]]);
  const resources = world.resources ?? [CRM];
  const outcome: Omit<Outcome, 'ctx' | 'error' | 'body'> = {
    entities: {},
    issued: [],
    registryLookups: [],
    grantLookups: [],
    accountLookups: [],
    capture,
  };

  class FakeAccessToken {
    scope?: string;
    readonly entry: { init: Record<string, unknown>; scope?: string };
    constructor(init: Record<string, unknown>) {
      this.entry = { init };
      outcome.issued.push(this.entry);
    }
    async save(): Promise<string> {
      this.entry.scope = this.scope;
      return 'issued-token-value';
    }
  }

  const ctx = {
    oidc: {
      client: { clientId: AGENT_CLIENT_ID },
      params,
      provider: {
        Grant: {
          async find(id: string) {
            outcome.grantLookups.push(id);
            if (world.grantFindFails) throw new Error('grant store is unreachable (test)');
            return grants.get(id);
          },
        },
        AccessToken: FakeAccessToken,
        ResourceServer: FakeResourceServer,
      },
      entity(name: string, value: unknown) {
        outcome.entities[name] = value;
      },
    },
    body: undefined as unknown,
  } as unknown as KoaContextWithOIDC;

  const handler = createTokenExchangeHandler({
    issuerUrl: ISSUER,
    rules: world.rules ?? new Map([[AGENT_CLIENT_ID, [RULE]]]),
    resourceByAudience: (audience) => resources.find((resource) => resource.audience === audience),
    signingJwks: { keys: [issuerPrivateJwk] },
    registry: {
      async record() {
        throw new Error('the handler never records');
      },
      async find(jti) {
        outcome.registryLookups.push(jti);
        if (world.registryFails) throw new Error('registry is unreachable (test)');
        return records.get(jti);
      },
    },
    async findAccount(_ctx, sub, subjectClientId) {
      outcome.accountLookups.push({ sub, subjectClientId });
      if (world.findAccount) return world.findAccount(sub, subjectClientId);
      return { accountId: sub, async claims() { return { sub }; } } as Account;
    },
    logger: capture.logger,
  });

  let error: unknown;
  try {
    await handler(ctx);
  } catch (caught) {
    error = caught;
  }
  return { ...outcome, error, body: (ctx as unknown as { body: unknown }).body, ctx };
}

/** The OAuth error, nothing issued, and the last `token exchange refused` line carrying `reason`. */
function expectRefused(
  outcome: Outcome,
  code: string,
  reason: string,
  description?: string,
): Record<string, unknown> {
  const error = outcome.error as { error?: string; error_description?: string };
  expect(error, `expected a refusal with ${reason}`).toBeDefined();
  expect(error.error).toBe(code);
  if (description !== undefined) expect(error.error_description).toBe(description);
  expect(outcome.body).toBeUndefined();
  expect(outcome.issued).toEqual([]);
  expect(outcome.entities).toEqual({});
  const refused = outcome.capture.matching('token exchange refused');
  expect(refused).toHaveLength(1);
  expect(refused[0]).toMatchObject({ level: 'warn', component: 'token-exchange', clientId: AGENT_CLIENT_ID, reason });
  return refused[0]!;
}

describe('token exchange handler: exports', () => {
  it('declares every parameter of the grant, so none is silently dropped', () => {
    expect([...TOKEN_EXCHANGE_PARAMETERS].sort()).toEqual([
      'actor_token',
      'actor_token_type',
      'audience',
      'requested_token_type',
      'resource',
      'scope',
      'subject_token',
      'subject_token_type',
    ]);
  });

  it('gives a delegated token a grant type no rule can accept as a subject', () => {
    expect(TOKEN_EXCHANGE_GTY).toBe('token-exchange');
    expect(SUBJECT_GRANTS as readonly string[]).not.toContain(TOKEN_EXCHANGE_GTY);
  });
});

describe('token exchange handler: publicJwksOf', () => {
  it('drops every RSA, EC, OKP and symmetric private member and keeps the public ones', () => {
    const privateKey: JWK = {
      kty: 'RSA', kid: 'k1', alg: 'RS256', use: 'sig', n: 'n-value', e: 'AQAB',
      d: 'd', p: 'p', q: 'q', dp: 'dp', dq: 'dq', qi: 'qi',
      oth: [{ r: 'r', d: 'd', t: 't' }],
    };
    const octKey: JWK = { kty: 'oct', kid: 'k2', k: 'secret' };
    const okpKey: JWK = { kty: 'OKP', kid: 'k3', crv: 'Ed25519', x: 'x-value', d: 'd' };

    const { keys } = publicJwksOf({ keys: [privateKey, octKey, okpKey] });
    expect(keys).toEqual([
      { kty: 'RSA', kid: 'k1', alg: 'RS256', use: 'sig', n: 'n-value', e: 'AQAB' },
      { kty: 'oct', kid: 'k2' },
      { kty: 'OKP', kid: 'k3', crv: 'Ed25519', x: 'x-value' },
    ]);
  });

  it('leaves the signing keys it was given untouched', () => {
    const privateKey: JWK = { kty: 'RSA', kid: 'k1', n: 'n', e: 'AQAB', d: 'd' };
    publicJwksOf({ keys: [privateKey] });
    expect(privateKey.d).toBe('d');
  });

  it('keeps a key that has no private member as it is', () => {
    const publicKey: JWK = { kty: 'EC', kid: 'k4', crv: 'P-256', x: 'x', y: 'y' };
    expect(publicJwksOf({ keys: [publicKey] }).keys).toEqual([publicKey]);
  });
});

describe('token exchange handler: issuing B', () => {
  it('issues an access token for the rule audience, with the RFC 8693 §2.2.1 response', async () => {
    const outcome = await run(fields(await subjectToken()));
    expect(outcome.error).toBeUndefined();
    expect(outcome.body).toEqual({
      access_token: 'issued-token-value',
      issued_token_type: ACCESS_TOKEN_TYPE,
      token_type: 'Bearer',
      expires_in: 900,
      scope: 'crm llm',
    });
    expect(outcome.capture.matching('token exchange refused')).toHaveLength(0);
  });

  it('builds B for the account, without a grant, with the exchange gty and the rule ttl', async () => {
    const outcome = await run(fields(await subjectToken()));
    expect(outcome.issued).toHaveLength(1);
    const { init, scope } = outcome.issued[0]!;
    expect(init).toMatchObject({
      accountId: USER,
      client: { clientId: AGENT_CLIENT_ID },
      gty: TOKEN_EXCHANGE_GTY,
      expiresIn: 900,
    });
    expect(init).not.toHaveProperty('grantId');
    expect(scope).toBe('crm llm');
    const resourceServer = init.resourceServer as FakeResourceServer;
    expect(resourceServer).toBeInstanceOf(FakeResourceServer);
    expect(resourceServer.identifier).toBe(CRM.indicator);
    expect(resourceServer.info).toEqual({
      audience: 'crm',
      scope: 'crm llm',
      accessTokenFormat: 'jwt',
      accessTokenTTL: 900,
      jwt: { sign: { alg: 'RS256' } },
    });
  });

  it('hands the rule, the subject and B to grant.success through the entities', async () => {
    const outcome = await run(fields(await subjectToken()));
    expect(outcome.entities.TokenExchangeRule).toBe(RULE);
    const subject: ExchangedSubject = { jti: JTI, sub: USER, clientId: SUBJECT_CLIENT };
    expect(outcome.entities.SubjectToken).toEqual(subject);
    expect(outcome.entities.AccessToken).toBeDefined();
  });

  it('asks for the account with the subject client, so its required_ldap_groups apply (1.3.0)', async () => {
    const outcome = await run(fields(await subjectToken()));
    expect(outcome.accountLookups).toEqual([{ sub: USER, subjectClientId: SUBJECT_CLIENT }]);
    expect(outcome.registryLookups).toEqual([JTI]);
    expect(outcome.grantLookups).toEqual([GRANT_ID]);
  });

  it('D5: the requested scopes plus the selector, in the order of issue.scope', async () => {
    const token = await subjectToken();
    // Only the selector asked: only the selector issued.
    expect((await run(fields(token, { scope: 'crm' }))).body).toMatchObject({ scope: 'crm' });
    // Repeats and extra blanks are ignored.
    expect((await run(fields(token, { scope: ' llm  llm crm ' }))).body).toMatchObject({ scope: 'crm llm' });

    // The order is the rule's, not the request's.
    const reversed: TokenExchangeRule = { ...RULE, issue: { ...RULE.issue, scope: 'llm crm' } };
    const outcome = await run(fields(token, { scope: 'crm llm' }), {
      rules: new Map([[AGENT_CLIENT_ID, [reversed]]]),
    });
    expect(outcome.body).toMatchObject({ scope: 'llm crm' });
  });

  it('uses the ttl of the rule for the response, the token and the resource server', async () => {
    const short: TokenExchangeRule = { ...RULE, issue: { ...RULE.issue, ttl_seconds: 120 } };
    const outcome = await run(fields(await subjectToken()), { rules: new Map([[AGENT_CLIENT_ID, [short]]]) });
    expect(outcome.body).toMatchObject({ expires_in: 120 });
    expect(outcome.issued[0]!.init.expiresIn).toBe(120);
    expect((outcome.issued[0]!.init.resourceServer as FakeResourceServer).info.accessTokenTTL).toBe(120);
  });

  it('picks, among the rules for the audience, the one whose subject audience the token carries', async () => {
    const other: TokenExchangeRule = {
      ...RULE,
      subject: { ...RULE.subject, audience: 'other-service' },
      where: 'CLIENTS_JSON[1].token_exchange[1]',
    };
    const outcome = await run(fields(await subjectToken({ claims: { aud: 'other-service' } })), {
      rules: new Map([[AGENT_CLIENT_ID, [RULE, other]]]),
      records: new Map([[JTI, { ...defaultRecord(), aud: 'other-service' }]]),
    });
    expect(outcome.error).toBeUndefined();
    expect(outcome.entities.TokenExchangeRule).toBe(other);
  });

  it('accepts a renewed subject whose gty lists both subject grants, blanks tolerated', async () => {
    const outcome = await run(fields(await subjectToken()), {
      records: new Map([[JTI, { ...defaultRecord(), gty: 'authorization_code  refresh_token' }]]),
    });
    expect(outcome.error).toBeUndefined();
  });
});

describe('token exchange handler: 1. parameters', () => {
  it.each([
    ['subject_token', 'subject_token is required'],
    ['subject_token_type', 'subject_token_type is required'],
    ['requested_token_type', 'requested_token_type is required'],
  ])('refuses a request without %s, or with it empty', async (name, description) => {
    const token = await subjectToken();
    for (const value of [undefined, '']) {
      const outcome = await run(fields(token, { [name]: value }));
      const line = expectRefused(outcome, 'invalid_request', 'parameter_missing', description);
      // Refused before any rule is chosen and before the subject is read.
      expect(line).not.toHaveProperty('rule');
      expect(line).not.toHaveProperty('subjectJti');
      expect(outcome.registryLookups).toEqual([]);
    }
  });

  it('refuses a token type other than the access token, on either side', async () => {
    const token = await subjectToken();
    const idToken = 'urn:ietf:params:oauth:token-type:id_token';
    expectRefused(
      await run(fields(token, { subject_token_type: idToken })),
      'invalid_request', 'token_type', `subject_token_type must be ${ACCESS_TOKEN_TYPE}`,
    );
    expectRefused(
      await run(fields(token, { requested_token_type: idToken })),
      'invalid_request', 'token_type', `requested_token_type must be ${ACCESS_TOKEN_TYPE}`,
    );
  });

  it('refuses actor_token or actor_token_type, even alone and even empty', async () => {
    const token = await subjectToken();
    for (const extra of [{ actor_token: token }, { actor_token_type: ACCESS_TOKEN_TYPE }, { actor_token: '' }]) {
      expectRefused(
        await run({ ...fields(token), ...extra }),
        'invalid_request', 'actor_token', 'actor tokens are not supported',
      );
    }
  });
});

describe('token exchange handler: 2. the rule', () => {
  it('refuses resource, even empty: audience is the only way to name the target', async () => {
    const token = await subjectToken();
    for (const resource of ['urn:easyoidc:crm', '']) {
      expectRefused(
        await run({ ...fields(token), resource }),
        'invalid_target', 'resource_parameter', 'resource is not supported by this grant: use audience',
      );
    }
  });

  it('refuses a request without audience', async () => {
    expectRefused(
      await run(fields(await subjectToken(), { audience: undefined })),
      'invalid_target', 'no_rule_audience', 'audience is required',
    );
  });

  it('refuses an audience no rule of this client issues for, and a client with no rules at all', async () => {
    const token = await subjectToken();
    expectRefused(
      await run(fields(token, { audience: 'agent-service' })),
      'invalid_target', 'no_rule_audience', 'audience agent-service is not allowed for this client',
    );
    expectRefused(
      await run(fields(token), { rules: new Map([['someone-else', [RULE]]]) }),
      'invalid_target', 'no_rule_audience', 'audience crm is not allowed for this client',
    );
  });

  it('refuses a request without scope', async () => {
    expectRefused(
      await run(fields(await subjectToken(), { scope: undefined })),
      'invalid_target', 'scope_missing', 'scope is required',
    );
  });

  it('names only the scopes beyond every rule', async () => {
    expectRefused(
      await run(fields(await subjectToken(), { scope: 'llm admin' })),
      'invalid_target', 'no_rule_scope', 'scope admin exceeds the token exchange rule',
    );
  });

  it('refuses scopes that no SINGLE rule allows together, naming all of them', async () => {
    const reports: TokenExchangeRule = {
      ...RULE,
      subject: { ...RULE.subject, audience: 'other-service' },
      issue: { ...RULE.issue, scope: 'crm report' },
      where: 'CLIENTS_JSON[1].token_exchange[1]',
    };
    const outcome = await run(fields(await subjectToken(), { scope: 'llm report' }), {
      rules: new Map([[AGENT_CLIENT_ID, [RULE, reports]]]),
    });
    expectRefused(outcome, 'invalid_target', 'no_rule_scope', 'scope llm report exceeds the token exchange rule');
    expect(outcome.registryLookups).toEqual([]);
  });

  it('second lock: two rules matching the same subject audience are ambiguous, never a guess', async () => {
    const twin: TokenExchangeRule = { ...RULE, where: 'CLIENTS_JSON[1].token_exchange[1]' };
    const outcome = await run(fields(await subjectToken()), { rules: new Map([[AGENT_CLIENT_ID, [RULE, twin]]]) });
    const line = expectRefused(
      outcome, 'invalid_target', 'rule_ambiguous', 'the request does not match exactly one token exchange rule',
    );
    expect(line.subjectJti).toBe(JTI);
    expect(line).not.toHaveProperty('rule');
    expect(outcome.registryLookups).toEqual([]);
  });
});

describe('token exchange handler: 3. the subject token', () => {
  it('refuses an expired subject', async () => {
    const outcome = await run(fields(await subjectToken({ claims: { exp: now() - 5, iat: now() - 60 } })));
    expectRefused(outcome, 'invalid_grant', 'subject_expired', 'subject_token is expired');
    expect((outcome.error as { error_detail?: string }).error_detail).toBe('subject_expired');
  });

  it('refuses a subject whose audience is not the subject audience of the rule', async () => {
    expectRefused(
      await run(fields(await subjectToken({ claims: { aud: 'crm' } }))),
      'invalid_grant', 'subject_audience', 'subject_token audience is not accepted by this rule',
    );
  });

  it.each([
    ['another issuer', { claims: { iss: 'https://evil.test' } }],
    ['a stranger signature', { key: 'stranger' as const }],
    ['typ JWT instead of at+jwt', { typ: 'JWT' }],
    ['no client_id', { claims: { client_id: undefined } }],
    ['no jti', { claims: { jti: undefined } }],
    ['no exp', { claims: { exp: undefined } }],
    ['a numeric client_id', { claims: { client_id: 42 } }],
    ['an array audience', { claims: { aud: ['agent-service', 'crm'] } }],
  ])('refuses a subject with %s as invalid', async (_label, options) => {
    const token = await subjectToken({
      ...('claims' in options ? { claims: options.claims } : {}),
      ...('typ' in options ? { typ: options.typ } : {}),
      ...('key' in options ? { key: strangerKey } : {}),
    });
    const outcome = await run(fields(token));
    const line = expectRefused(outcome, 'invalid_grant', 'subject_invalid', 'subject_token is invalid');
    expect(line).not.toHaveProperty('subjectJti');
    expect(outcome.registryLookups).toEqual([]);
  });

  it('refuses something that is not a JWT at all', async () => {
    expectRefused(await run(fields('not-a-jwt')), 'invalid_grant', 'subject_invalid', 'subject_token is invalid');
  });

  it('refuses a delegated token (it carries act), and logs the rule and the jti', async () => {
    const outcome = await run(fields(await subjectToken({ claims: { act: { sub: AGENT_CLIENT_ID } } })));
    const line = expectRefused(
      outcome, 'invalid_grant', 'subject_delegated', 'a delegated token cannot be exchanged again',
    );
    expect(line).toMatchObject({ rule: RULE_WHERE, subjectJti: JTI });
    expect(outcome.registryLookups).toEqual([]);
  });

  it('fails closed when the registry cannot answer: temporarily_unavailable, and an error line', async () => {
    const outcome = await run(fields(await subjectToken()), { registryFails: true });
    expectRefused(
      outcome, 'temporarily_unavailable', 'registry_unavailable',
      'the subject token could not be verified; try again later',
    );
    expect(outcome.error).toBeInstanceOf(TemporarilyUnavailable);
    const logged = outcome.capture.matching('the subject token registry could not be read');
    expect(logged).toHaveLength(1);
    expect(logged[0]).toMatchObject({
      level: 'error',
      rule: RULE_WHERE,
      subjectJti: JTI,
      err: { name: 'Error', message: 'registry is unreachable (test)' },
    });
    expect(outcome.grantLookups).toEqual([]);
  });

  it('refuses a subject the registry never recorded (not a person token)', async () => {
    const outcome = await run(fields(await subjectToken()), { records: new Map() });
    expectRefused(outcome, 'invalid_grant', 'subject_not_person', 'subject_token was not issued to a person');
    expect(outcome.grantLookups).toEqual([]);
  });

  it.each([
    ['accountId', { accountId: 'luigi.verdi' }],
    ['clientId', { clientId: 'other-ui' }],
    ['aud', { aud: 'other-service' }],
  ])('refuses a record whose %s does not match the token', async (_field, change) => {
    const outcome = await run(fields(await subjectToken()), {
      records: new Map([[JTI, { ...defaultRecord(), ...change }]]),
    });
    expectRefused(outcome, 'invalid_grant', 'subject_record_mismatch', 'subject_token is invalid');
    expect(outcome.grantLookups).toEqual([]);
  });

  it('refuses a subject obtained by a client outside subject.client_ids', async () => {
    const outcome = await run(fields(await subjectToken({ claims: { client_id: 'other-ui' } })), {
      records: new Map([[JTI, { ...defaultRecord(), clientId: 'other-ui' }]]),
      grants: new Map([[GRANT_ID, { ...defaultGrant(), clientId: 'other-ui' }]]),
    });
    expectRefused(
      outcome, 'invalid_grant', 'subject_client', 'subject_token was obtained by a client this rule does not accept',
    );
  });

  it.each([
    ['an empty gty', '', ['authorization_code', 'refresh_token']],
    ['a blank gty', '   ', ['authorization_code', 'refresh_token']],
    ['a refresh when the rule accepts only the code', 'authorization_code refresh_token', ['authorization_code']],
    ['a machine grant', 'client_credentials', ['authorization_code', 'refresh_token']],
    ['a delegated token gty', TOKEN_EXCHANGE_GTY, ['authorization_code', 'refresh_token']],
  ] as const)('refuses %s: every word of gty must be in issued_by_grants', async (_label, gty, issuedBy) => {
    const rule: TokenExchangeRule = { ...RULE, subject: { ...RULE.subject, issued_by_grants: [...issuedBy] } };
    const outcome = await run(fields(await subjectToken()), {
      rules: new Map([[AGENT_CLIENT_ID, [rule]]]),
      records: new Map([[JTI, { ...defaultRecord(), gty }]]),
    });
    expectRefused(
      outcome, 'invalid_grant', 'subject_grant_not_allowed',
      'subject_token was issued by a grant this rule does not accept',
    );
    expect(outcome.grantLookups).toEqual([]);
  });

  it('fails closed when the grant cannot be read', async () => {
    const outcome = await run(fields(await subjectToken()), { grantFindFails: true });
    expectRefused(outcome, 'temporarily_unavailable', 'grant_unavailable');
    expect(outcome.capture.matching('the grant of the subject token could not be read')).toHaveLength(1);
    expect(outcome.accountLookups).toEqual([]);
  });

  it.each([
    ['gone', undefined],
    ['expired', { ...defaultGrant(), isExpired: true }],
    ['of another account', { ...defaultGrant(), accountId: 'luigi.verdi' }],
    ['of another client', { ...defaultGrant(), clientId: 'other-ui' }],
  ])('refuses a subject whose grant is %s as revoked', async (_label, grant) => {
    const outcome = await run(fields(await subjectToken()), {
      grants: grant === undefined ? new Map() : new Map([[GRANT_ID, grant]]),
    });
    expectRefused(outcome, 'invalid_grant', 'subject_revoked', 'subject_token has been revoked');
    expect(outcome.accountLookups).toEqual([]);
  });
});

describe('token exchange handler: 4. the account', () => {
  it('passes a gate refusal through with the gate reason', async () => {
    const refusal = new errors.InvalidGrant('account_disabled');
    const outcome = await run(fields(await subjectToken()), {
      async findAccount() {
        throw refusal;
      },
    });
    expectRefused(outcome, 'invalid_grant', 'account_disabled');
    expect(outcome.error).toBe(refusal);
  });

  it('names an invalid_grant without detail account_refused', async () => {
    const outcome = await run(fields(await subjectToken()), {
      async findAccount() {
        throw new errors.InvalidGrant();
      },
    });
    expectRefused(outcome, 'invalid_grant', 'account_refused');
  });

  it('passes an account that cannot be verified through as account_unavailable', async () => {
    const unavailable = new TemporarilyUnavailable('the account could not be verified; try again later');
    const outcome = await run(fields(await subjectToken()), {
      async findAccount() {
        throw unavailable;
      },
    });
    expectRefused(outcome, 'temporarily_unavailable', 'account_unavailable');
    expect(outcome.error).toBe(unavailable);
  });

  it('lets any other failure through untouched, as a server error and not as a refusal', async () => {
    const bug = new Error('unexpected (test)');
    const outcome = await run(fields(await subjectToken()), {
      async findAccount() {
        throw bug;
      },
    });
    expect(outcome.error).toBe(bug);
    expect(outcome.capture.matching('token exchange refused')).toHaveLength(0);
    expect(outcome.issued).toEqual([]);
  });

  it('refuses when there is no account', async () => {
    const outcome = await run(fields(await subjectToken()), { findAccount: async () => undefined });
    expectRefused(outcome, 'invalid_grant', 'account_not_found', 'the account of the subject_token is not available');
  });
});

describe('token exchange handler: 5. issuance, second locks', () => {
  it('refuses when the rule audience is not a known resource', async () => {
    expectRefused(
      await run(fields(await subjectToken()), { resources: [] }),
      'invalid_target', 'resource_not_exchangeable', 'audience crm does not accept exchanged tokens',
    );
  });

  it('refuses when the resource does not list token-exchange among its grants', async () => {
    expectRefused(
      await run(fields(await subjectToken()), { resources: [{ ...CRM, grants: ['authorization_code'] }] }),
      'invalid_target', 'resource_not_exchangeable', 'audience crm does not accept exchanged tokens',
    );
  });

  it('refuses when the rule scope goes beyond the exchange_scopes of the resource', async () => {
    expectRefused(
      await run(fields(await subjectToken()), { resources: [{ ...CRM, exchangeScopes: [] }] }),
      'invalid_target', 'resource_not_exchangeable', 'audience crm does not accept the scope of this rule',
    );
  });
});
