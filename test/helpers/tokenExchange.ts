/**
 * RFC 8693 helpers: the agent-service key pair, its CLIENTS_JSON entry, its
 * private_key_jwt client assertion, and the raw exchange request.
 */
import { randomUUID } from 'node:crypto';

import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from 'jose';

import { ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from '../../src/config.js';
import type { TestServer } from './server.js';

export const AGENT_CLIENT_ID = 'agent-service';
export const JWT_BEARER_ASSERTION = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export interface AgentKeys {
  privateKey: CryptoKey;
  /** The public half, with `kid`, `alg` and `use`: what goes into the client's `jwks`. */
  publicJwk: JWK;
  kid: string;
}

export async function agentKeys(kid = `agent-${randomUUID()}`): Promise<AgentKeys> {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  return { privateKey, publicJwk, kid };
}

/** The contract rule (plan section 10), with the subject clients of the test server. */
export function contractRule(clientIds: string[]): Record<string, unknown> {
  return {
    subject: {
      token_type: ACCESS_TOKEN_TYPE,
      audience: 'agent-service',
      client_ids: clientIds,
      issued_by_grants: ['authorization_code', 'refresh_token'],
    },
    issue: {
      token_type: ACCESS_TOKEN_TYPE,
      audience: 'crm',
      scope: 'crm llm',
      ttl_seconds: 900,
      refresh_token: false,
    },
  };
}

/** The agent-service entry of CLIENTS_JSON. */
export function agentClient(publicJwks: JWK[], rules: unknown[]): Record<string, unknown> {
  return {
    client_id: AGENT_CLIENT_ID,
    token_endpoint_auth_method: 'private_key_jwt',
    jwks: { keys: publicJwks },
    grant_types: [TOKEN_EXCHANGE_GRANT_TYPE],
    response_types: [],
    token_exchange: rules,
  };
}

/** A one-shot client assertion for the token endpoint (RFC 7523 §3). */
export async function assertion(server: TestServer, keys: AgentKeys): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', kid: keys.kid })
    .setIssuer(AGENT_CLIENT_ID)
    .setSubject(AGENT_CLIENT_ID)
    .setAudience(`${server.baseUrl}/token`)
    .setJti(randomUUID())
    .setIssuedAt()
    .setExpirationTime('60s')
    .sign(keys.privateKey);
}

/** The fields of a well-formed exchange of `subjectToken` for B (aud crm, scope llm). */
export function exchangeFields(subjectToken: string): Record<string, string> {
  return {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TYPE,
    audience: 'crm',
    scope: 'llm',
  };
}

/**
 * POST /token as the agent-service. `assertion` is the signed client
 * assertion; `fields` are sent as they are (undefined = left out), so a test
 * can drop or add any parameter. `headers` lets a test authenticate otherwise.
 */
export async function exchangeRequest(
  server: TestServer,
  fields: Record<string, string | undefined>,
  options: { assertion?: string; clientId?: string; headers?: Record<string, string> } = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  const form = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined) form.set(key, value);
  }
  if (options.assertion !== undefined) {
    form.set('client_assertion_type', JWT_BEARER_ASSERTION);
    form.set('client_assertion', options.assertion);
  }
  if (options.clientId !== undefined) form.set('client_id', options.clientId);
  const response = await fetch(`${server.baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...options.headers },
    body: form.toString(),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}
