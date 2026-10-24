/**
 * RFC 8693 token exchange: the startup checks of CLIENTS_JSON[i].token_exchange
 * and of the resources that accept exchanged tokens.
 *
 * Every refusal is a startup error with its exact message: there is no
 * default exchange, no default scope, no default lifetime.
 */
import { describe, expect, it } from 'vitest';

import {
  ACCESS_TOKEN_TYPE,
  ConfigError,
  loadConfig,
  MAX_EXCHANGE_TTL_SECONDS,
  RESOURCE_GRANTS,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from '../src/config.js';

const AUDIENCE = 'https://easyoidc.test/api';
const TE = TOKEN_EXCHANGE_GRANT_TYPE;
const AT = ACCESS_TOKEN_TYPE;

// The two resources of the contract (plan section 10).
const CRM = {
  scope: 'crm',
  audience: 'crm',
  grants: ['authorization_code', 'token-exchange'],
  exchange_scopes: ['llm'],
};
const AGENT = { scope: 'agent', audience: 'agent-service', grants: ['authorization_code'] };

const CRM_WEB = { client_id: 'crm-web', redirect_uris: ['http://localhost:6307/'], scope: 'openid crm agent' };

// The agent-service entry of the contract, verbatim (plan sections 4 and 10).
// The modulus is the documentation placeholder: the validator checks the
// shape of the key set, never the key material.
const AGENT_SERVICE_JSON = '{"client_id":"agent-service","token_endpoint_auth_method":"private_key_jwt",'
  + '"jwks":{"keys":[{"kty":"RSA","kid":"agent-2026-10","n":"<modulus>","e":"AQAB"}]},'
  + '"grant_types":["urn:ietf:params:oauth:grant-type:token-exchange"],"response_types":[],'
  + '"token_exchange":[{"subject":{"token_type":"urn:ietf:params:oauth:token-type:access_token",'
  + '"audience":"agent-service","client_ids":["crm-web"],"issued_by_grants":["authorization_code","refresh_token"]},'
  + '"issue":{"token_type":"urn:ietf:params:oauth:token-type:access_token","audience":"crm",'
  + '"scope":"crm llm","ttl_seconds":900,"refresh_token":false}}]}';

const AGENT_SERVICE = JSON.parse(AGENT_SERVICE_JSON) as Record<string, unknown>;
const CONTRACT_RULE = (AGENT_SERVICE.token_exchange as Record<string, unknown>[])[0]!;

const C = 'CLIENTS_JSON[1]';
const R = `${C}.token_exchange[0]`;

const BASE_ENV = {
  ISSUER_URL: 'http://127.0.0.1:3000',
  DEV_STUB_USERS: '[{"username":"mario.rossi","password":"x","active":true}]',
  DATA_DIR: '',
  API_AUDIENCE: AUDIENCE,
  DEFAULT_RESOURCE_JSON: '{"scope":"api","grants":["client_credentials"]}',
  RESOURCE_SERVERS_JSON: JSON.stringify([CRM, AGENT]),
};

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** The contract entry with some fields replaced (undefined = removed). */
function agentService(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const client = { ...clone(AGENT_SERVICE), ...overrides };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete client[key];
  }
  return client;
}

/** The contract rule with fields of `subject` and `issue` replaced (undefined = removed). */
function rule(
  subject: Record<string, unknown> = {},
  issue: Record<string, unknown> = {},
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  const base = clone(CONTRACT_RULE) as { subject: Record<string, unknown>; issue: Record<string, unknown> };
  const merged = { subject: { ...base.subject, ...subject }, issue: { ...base.issue, ...issue }, ...extra };
  for (const half of [merged.subject, merged.issue]) {
    for (const [key, value] of Object.entries(half)) {
      if (value === undefined) delete half[key];
    }
  }
  return merged;
}

const withRules = (...rules: unknown[]) => agentService({ token_exchange: rules });

function problemsFor(clients: unknown[], env: Record<string, string> = {}): string[] {
  try {
    loadConfig({ ...BASE_ENV, CLIENTS_JSON: JSON.stringify(clients), ...env });
    return [];
  } catch (error) {
    expect(error).toBeInstanceOf(ConfigError);
    return (error as ConfigError).problems;
  }
}

const exchange = (client: Record<string, unknown>, env: Record<string, string> = {}) =>
  problemsFor([CRM_WEB, client], env);

describe('token exchange: the contract configuration', () => {
  it('accepts the contract configuration', () => {
    expect(problemsFor([CRM_WEB, AGENT_SERVICE])).toEqual([]);
  });

  it('keeps the parsed rule in Config.tokenExchange and strips it from the client metadata', () => {
    const config = loadConfig({ ...BASE_ENV, CLIENTS_JSON: JSON.stringify([CRM_WEB, AGENT_SERVICE]) });
    expect([...config.tokenExchange.keys()]).toEqual(['agent-service']);
    expect(config.tokenExchange.get('agent-service')).toEqual([{
      subject: {
        token_type: AT,
        audience: 'agent-service',
        client_ids: ['crm-web'],
        issued_by_grants: ['authorization_code', 'refresh_token'],
      },
      issue: { token_type: AT, audience: 'crm', scope: 'crm llm', ttl_seconds: 900, refresh_token: false },
      where: 'CLIENTS_JSON[1].token_exchange[0]',
    }]);
    const client = config.clients.find((c) => c.client_id === 'agent-service')!;
    expect(client).not.toHaveProperty('token_exchange');
    expect(client.grant_types).toEqual([TE]);
    expect(client.token_endpoint_auth_method).toBe('private_key_jwt');
    expect(config.resourceServers).toEqual([CRM, AGENT]);
  });

  it('has no rules at all without an exchange client', () => {
    expect(loadConfig({ ...BASE_ENV, CLIENTS_JSON: JSON.stringify([CRM_WEB]) }).tokenExchange.size).toBe(0);
  });

  it('accepts the API_AUDIENCE resource as the issued audience when it lists token-exchange', () => {
    expect(exchange(withRules(rule({}, { audience: AUDIENCE, scope: 'api llm' })), {
      DEFAULT_RESOURCE_JSON: '{"scope":"api","grants":["client_credentials","token-exchange"],"exchange_scopes":["llm"]}',
    })).toEqual([]);
  });

  it('exports the three resource grants and the 900 s ceiling', () => {
    expect(RESOURCE_GRANTS).toEqual(['client_credentials', 'authorization_code', 'token-exchange']);
    expect(MAX_EXCHANGE_TTL_SECONDS).toBe(900);
  });
});

describe('token exchange: the client', () => {
  it('requires API_AUDIENCE', () => {
    const { scope: _scope, ...userClient } = CRM_WEB;
    expect(problemsFor([userClient, AGENT_SERVICE], {
      API_AUDIENCE: '', DEFAULT_RESOURCE_JSON: '', RESOURCE_SERVERS_JSON: '',
    })).toEqual([
      `${C} uses grant_types urn:ietf:params:oauth:grant-type:token-exchange, which requires API_AUDIENCE`,
      `${R}.subject.audience "agent-service" is not a declared resource audience (API_AUDIENCE or RESOURCE_SERVERS_JSON)`,
      `${R}.issue.audience "crm" is not a declared resource audience (API_AUDIENCE or RESOURCE_SERVERS_JSON)`,
    ]);
  });

  it('requires grant_types to be exactly the exchange grant', () => {
    expect(exchange(agentService({ grant_types: [TE, 'authorization_code'] }))).toEqual([
      `${C}.grant_types must be exactly ["urn:ietf:params:oauth:grant-type:token-exchange"] for a token exchange client`,
    ]);
  });

  it('refuses client_secret_basic: the method must be private_key_jwt', () => {
    expect(exchange(agentService({ token_endpoint_auth_method: 'client_secret_basic' }))).toEqual([
      `${C}.token_endpoint_auth_method must be private_key_jwt for a token exchange client, got "client_secret_basic"`,
    ]);
    expect(exchange(agentService({ token_endpoint_auth_method: undefined }))).toEqual([
      `${C}.token_endpoint_auth_method must be private_key_jwt for a token exchange client, got undefined`,
    ]);
  });

  it('requires a jwks of public RSA/EC/OKP keys', () => {
    const message = `${C}.jwks is required for a token exchange client: {"keys":[<public JWK>]}`;
    expect(exchange(agentService({ jwks: undefined }))).toEqual([message]);
    expect(exchange(agentService({ jwks: { keys: [] } }))).toEqual([message]);
    expect(exchange(agentService({ jwks: { keys: [{ kty: 'oct', kid: 'x' }] } }))).toEqual([message]);
    expect(exchange(agentService({ jwks: 'keys' }))).toEqual([message]);
  });

  it('refuses a jwks that holds a private key', () => {
    const message = `${C}.jwks must hold public keys only: the private key stays with the client`;
    for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
      expect(exchange(agentService({
        jwks: { keys: [{ kty: 'RSA', kid: 'agent-2026-10', n: '<modulus>', e: 'AQAB', [member]: 'secret' }] },
      }))).toEqual([message]);
    }
    expect(exchange(agentService({ jwks: { keys: [{ kty: 'oct', k: 'secret' }] } }))).toEqual([message]);
  });

  it('refuses a client_secret', () => {
    expect(exchange(agentService({ client_secret: 'a3f1c0de9b8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a392817060504' })))
      .toEqual([`${C}.client_secret is not allowed for a token exchange client`]);
  });

  it('requires response_types [] and redirect_uris absent or []', () => {
    expect(exchange(agentService({ response_types: ['code'] }))).toEqual([
      `${C}.response_types must be [] for a token exchange client`,
    ]);
    expect(exchange(agentService({ response_types: undefined }))).toEqual([
      `${C}.response_types must be [] for a token exchange client`,
    ]);
    expect(exchange(agentService({ redirect_uris: ['http://127.0.0.1/callback'] }))).toEqual([
      `${C}.redirect_uris must be absent or [] for a token exchange client`,
    ]);
    expect(exchange(agentService({ redirect_uris: [] }))).toEqual([]);
  });

  it('refuses the exchange grant without rules: there is no default exchange', () => {
    const message = `${C} has the token exchange grant but no token_exchange rules: there is no default exchange`;
    expect(exchange(agentService({ token_exchange: undefined }))).toEqual([message]);
    expect(exchange(agentService({ token_exchange: [] }))).toEqual([message]);
  });

  it('refuses token_exchange on a client without the exchange grant', () => {
    const message = `${C}.token_exchange requires grant_types ["urn:ietf:params:oauth:grant-type:token-exchange"]`;
    expect(problemsFor([CRM_WEB, { ...CRM_WEB, client_id: 'other', token_exchange: [CONTRACT_RULE] }]))
      .toEqual([message]);
    expect(problemsFor([CRM_WEB, {
      client_id: 'erp-sync',
      client_secret: 'a3f1c0de9b8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a392817060504',
      grant_types: ['client_credentials'],
      response_types: [],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: 'api',
      token_exchange: [CONTRACT_RULE],
    }])).toEqual([message]);
  });

  it('refuses two rules for the same pair of audiences', () => {
    expect(exchange(withRules(rule(), rule({}, { scope: 'crm' })))).toEqual([
      `${C}.token_exchange has two rules for subject.audience "agent-service" and issue.audience "crm": a request must match exactly one`,
    ]);
  });
});

describe('token exchange: the rule', () => {
  it('refuses unknown fields in the rule, its subject and its issue', () => {
    expect(exchange(withRules(rule({ actor: 'x' }, { act: { sub: 'x' } }, { comment: 'x' })))).toEqual([
      `${R} has unknown fields: comment (only subject and issue)`,
      `${R}.subject has unknown fields: actor (only token_type, audience, client_ids, issued_by_grants)`,
      `${R}.issue has unknown fields: act (only token_type, audience, scope, ttl_seconds, refresh_token)`,
    ]);
  });

  it('refuses a rule that is not an object, or without subject or issue', () => {
    expect(exchange(withRules('crm'))).toEqual([`${R} must be an object {"subject","issue"}`]);
    expect(exchange(withRules({ issue: clone(CONTRACT_RULE.issue) }))).toEqual([
      `${R}.subject is required: {"token_type","audience","client_ids","issued_by_grants"}`,
    ]);
    expect(exchange(withRules({ subject: clone(CONTRACT_RULE.subject) }))).toEqual([
      `${R}.issue is required: {"token_type","audience","scope","ttl_seconds","refresh_token"}`,
    ]);
  });

  it('accepts only the access token as subject token type', () => {
    const message = `${R}.subject.token_type must be "urn:ietf:params:oauth:token-type:access_token" (the only subject token type accepted)`;
    expect(exchange(withRules(rule({ token_type: 'urn:ietf:params:oauth:token-type:id_token' })))).toEqual([message]);
    expect(exchange(withRules(rule({ token_type: undefined })))).toEqual([message]);
  });

  it('issues only access tokens', () => {
    expect(exchange(withRules(rule({}, { token_type: 'urn:ietf:params:oauth:token-type:refresh_token' })))).toEqual([
      `${R}.issue.token_type must be "urn:ietf:params:oauth:token-type:access_token"`,
    ]);
  });

  it('refuses a subject audience that is not a declared resource', () => {
    expect(exchange(withRules(rule({ audience: 'billing' })))).toEqual([
      `${R}.subject.audience "billing" is not a declared resource audience (API_AUDIENCE or RESOURCE_SERVERS_JSON)`,
    ]);
  });

  it('refuses an issued audience that is not a declared resource', () => {
    expect(exchange(withRules(rule({}, { audience: 'billing' })))).toEqual([
      `${R}.issue.audience "billing" is not a declared resource audience (API_AUDIENCE or RESOURCE_SERVERS_JSON)`,
    ]);
  });

  it('refuses equal subject and issued audiences', () => {
    expect(exchange(withRules(rule({ audience: 'crm' }, { audience: 'crm' })))).toEqual([
      `${R}: subject.audience and issue.audience must differ`,
    ]);
  });

  it('refuses an issued resource that does not list token-exchange', () => {
    const closed = { scope: 'crm', audience: 'crm', grants: ['authorization_code'] };
    expect(exchange(AGENT_SERVICE, { RESOURCE_SERVERS_JSON: JSON.stringify([closed, AGENT]) })).toEqual([
      `${R}.issue.audience "crm": the resource does not list "token-exchange" in its grants`,
    ]);
  });

  it('requires subject.client_ids: a non-empty list of declared clients', () => {
    const required = `${R}.subject.client_ids is required: a non-empty list of client ids declared in CLIENTS_JSON`;
    expect(exchange(withRules(rule({ client_ids: undefined })))).toEqual([required]);
    expect(exchange(withRules(rule({ client_ids: [] })))).toEqual([required]);
    expect(exchange(withRules(rule({ client_ids: 'crm-web' })))).toEqual([required]);
    expect(exchange(withRules(rule({ client_ids: ['crm-web', 'desktop-app'] })))).toEqual([
      `${R}.subject.client_ids names an unknown client "desktop-app"`,
    ]);
  });

  it('accepts only authorization_code and refresh_token as the grants of the subject', () => {
    const message = `${R}.subject.issued_by_grants must be a non-empty list of "authorization_code", "refresh_token" without repeats (client_credentials and token-exchange tokens are never exchangeable)`;
    expect(exchange(withRules(rule({ issued_by_grants: ['authorization_code', 'client_credentials'] })))).toEqual([message]);
    expect(exchange(withRules(rule({ issued_by_grants: ['token-exchange'] })))).toEqual([message]);
    expect(exchange(withRules(rule({ issued_by_grants: [] })))).toEqual([message]);
    expect(exchange(withRules(rule({ issued_by_grants: undefined })))).toEqual([message]);
    expect(exchange(withRules(rule({ issued_by_grants: ['refresh_token', 'refresh_token'] })))).toEqual([message]);
    expect(exchange(withRules(rule({ issued_by_grants: ['authorization_code'] })))).toEqual([]);
  });

  it('requires issue.scope: space-separated tokens, no repeats', () => {
    const message = `${R}.issue.scope is required: space-separated scope tokens, no repeats`;
    for (const scope of [undefined, '', 'crm  llm', 'crm crm', ['crm']]) {
      expect(exchange(withRules(rule({}, { scope })))).toEqual([message]);
    }
  });

  it('requires issue.scope to contain the scope that selects the resource', () => {
    expect(exchange(withRules(rule({}, { scope: 'llm' })))).toEqual([
      `${R}.issue.scope must contain "crm", the scope that selects the resource`,
    ]);
  });

  it('requires every other scope of issue.scope in the exchange_scopes of the resource', () => {
    expect(exchange(withRules(rule({}, { scope: 'crm llm admin' })))).toEqual([
      `${R}.issue.scope lists "admin", which is not in the exchange_scopes of the resource "crm"`,
    ]);
    expect(exchange(withRules(rule({}, { scope: 'openid crm' })))).toEqual([
      `${R}.issue.scope lists "openid", which is not in the exchange_scopes of the resource "crm"`,
    ]);
    expect(exchange(withRules(rule({}, { scope: 'crm' })))).toEqual([]);
  });

  it('requires ttl_seconds: a positive integer not above 900', () => {
    const message = `${R}.issue.ttl_seconds must be a positive integer not above 900`;
    for (const ttl of [undefined, 0, -1, 1.5, '900', 901]) {
      expect(exchange(withRules(rule({}, { ttl_seconds: ttl })))).toEqual([message]);
    }
    expect(exchange(withRules(rule({}, { ttl_seconds: 1 })))).toEqual([]);
  });

  it('refuses refresh_token other than false', () => {
    const message = `${R}.issue.refresh_token must be false: exchanged tokens carry no refresh token`;
    expect(exchange(withRules(rule({}, { refresh_token: true })))).toEqual([message]);
    expect(exchange(withRules(rule({}, { refresh_token: undefined })))).toEqual([message]);
  });
});

describe('token exchange: the resource', () => {
  const userOnly = [{ client_id: 'crm-web', redirect_uris: ['http://localhost:6307/'] }];
  const resourcesProblems = (servers: unknown[], env: Record<string, string> = {}) =>
    problemsFor(userOnly, { RESOURCE_SERVERS_JSON: JSON.stringify(servers), ...env });

  it('requires exchange_scopes when grants lists token-exchange', () => {
    const message = 'RESOURCE_SERVERS_JSON[0].exchange_scopes is required when grants lists "token-exchange": the scopes an exchanged token may carry besides "crm"';
    const { exchange_scopes: _scopes, ...withoutScopes } = CRM;
    expect(resourcesProblems([withoutScopes, AGENT])).toEqual([message]);
    expect(resourcesProblems([{ ...CRM, exchange_scopes: [] }, AGENT])).toEqual([message]);
  });

  it('refuses exchange_scopes without token-exchange', () => {
    expect(resourcesProblems([CRM, { ...AGENT, exchange_scopes: ['llm'] }])).toEqual([
      'RESOURCE_SERVERS_JSON[1].exchange_scopes is only allowed when grants lists "token-exchange"',
    ]);
    expect(problemsFor(userOnly, {
      DEFAULT_RESOURCE_JSON: '{"scope":"api","grants":["client_credentials"],"exchange_scopes":["llm"]}',
    })).toEqual([
      'DEFAULT_RESOURCE_JSON.exchange_scopes is only allowed when grants lists "token-exchange"',
    ]);
  });

  it('refuses repeats and malformed scopes in exchange_scopes', () => {
    for (const scopes of [['llm', 'llm'], ['llm admin'], [7]]) {
      expect(resourcesProblems([{ ...CRM, exchange_scopes: scopes }, AGENT])).toEqual([
        'RESOURCE_SERVERS_JSON[0].exchange_scopes must be a list of scope tokens (letters, digits, "_", ".", "-") '
        + `without repeats, got ${JSON.stringify(scopes)}`,
      ]);
    }
    expect(resourcesProblems([{ ...CRM, exchange_scopes: 'llm' }, AGENT])).toEqual([
      'RESOURCE_SERVERS_JSON[0].exchange_scopes is required when grants lists "token-exchange": the scopes an exchanged token may carry besides "crm"',
    ]);
  });

  it('refuses the selecting scope and the OpenID Connect scopes in exchange_scopes', () => {
    expect(resourcesProblems([{ ...CRM, exchange_scopes: ['llm', 'crm'] }, AGENT])).toEqual([
      'RESOURCE_SERVERS_JSON[0].exchange_scopes must not list "crm": the scope that selects the resource is always carried',
    ]);
    expect(resourcesProblems([{ ...CRM, exchange_scopes: ['llm', 'openid'] }, AGENT])).toEqual([
      'RESOURCE_SERVERS_JSON[0].exchange_scopes must not list openid, offline_access, profile: they belong to OpenID Connect, not to an exchanged token',
    ]);
  });

  it('lists the three grants in the message of a wrong grants list', () => {
    expect(resourcesProblems([{ ...CRM, grants: ['token_exchange'] }, AGENT])).toEqual([
      'RESOURCE_SERVERS_JSON[0].grants is required: a non-empty list of "client_credentials", "authorization_code", "token-exchange" without repeats, got ["token_exchange"]',
    ]);
  });

  it('does not let a user client ask for a resource open only to token-exchange', () => {
    const exchangeOnly = { scope: 'crm', audience: 'crm', grants: ['token-exchange'], exchange_scopes: ['llm'] };
    expect(problemsFor([CRM_WEB], { RESOURCE_SERVERS_JSON: JSON.stringify([exchangeOnly, AGENT]) })).toEqual([
      'CLIENTS_JSON[0].scope lists "crm", not open to authorization_code: a user client can never obtain it',
    ]);
  });
});
