/**
 * Drives a whole authorization-code + PKCE login: authorize, login form, the
 * silent consent hop, and back to the loopback callback with the code.
 */
import * as client from 'openid-client';

import { Browser } from './browser.js';
import { CLIENT_ID, type TestServer } from './server.js';

export interface LoginOptions {
  username: string;
  password: string;
  /** Phase 4-bis: the TOTP code, when TWO_FACTOR_ENABLED is on. */
  otp?: string;
  /** Defaults to a random loopback port, which is the point of RFC 8252. */
  redirectUri?: string;
  scope?: string;
  browser?: Browser;
}

export interface LoginResult {
  callbackUrl: string;
  codeVerifier: string;
  state: string;
  redirectUri: string;
  browser: Browser;
}

export async function discover(server: TestServer): Promise<client.Configuration> {
  return client.discovery(
    new URL(server.baseUrl),
    CLIENT_ID,
    { token_endpoint_auth_method: 'none' },
    client.None(),
    { execute: [client.allowInsecureRequests] },
  );
}

export function randomLoopbackRedirect(): string {
  const port = 20000 + Math.floor(Math.random() * 40000);
  return `http://127.0.0.1:${port}/callback`;
}

/**
 * Runs the browser half of the flow. Returns the callback URL carrying the
 * authorization code — the same string the desktop client's loopback listener sees.
 */
export async function login(
  server: TestServer,
  config: client.Configuration,
  options: LoginOptions,
): Promise<LoginResult> {
  const browser = options.browser ?? new Browser();
  const redirectUri = options.redirectUri ?? randomLoopbackRedirect();
  const codeVerifier = client.randomPKCECodeVerifier();
  const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
  const state = client.randomState();

  const authorizationUrl = client.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri,
    scope: options.scope ?? 'openid',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
  });

  const first = await browser.follow(authorizationUrl.toString(), server.baseUrl);
  if (first.callbackUrl) {
    // A session was already established: no form was needed.
    return { callbackUrl: first.callbackUrl, codeVerifier, state, redirectUri, browser };
  }

  const interactionUrl = first.visited.at(-1)!;
  const uid = interactionUrl.split('/').pop()!;

  const posted = await browser.postForm(`${server.baseUrl}/interaction/${uid}/login`, {
    username: options.username,
    password: options.password,
    ...(options.otp === undefined ? {} : { otp: options.otp }),
  });

  const location = posted.headers.get('location');
  if (!location) {
    throw new LoginRejected(posted.status, await posted.text());
  }

  const rest = await browser.follow(new URL(location, server.baseUrl).toString(), server.baseUrl);
  if (!rest.callbackUrl) {
    throw new Error(`login did not reach the callback: ${rest.visited.join(' -> ')}`);
  }

  return { callbackUrl: rest.callbackUrl, codeVerifier, state, redirectUri, browser };
}

export class LoginRejected extends Error {
  readonly status: number;
  readonly body: string;

  constructor(status: number, body: string) {
    super(`login rejected with HTTP ${status}`);
    this.name = 'LoginRejected';
    this.status = status;
    this.body = body;
  }
}

/** Exchanges the code for tokens with the correct verifier. */
export async function exchange(
  config: client.Configuration,
  result: LoginResult,
  overrides: { codeVerifier?: string | null } = {},
) {
  const checks: client.AuthorizationCodeGrantChecks = {
    expectedState: result.state,
    idTokenExpected: true,
  };
  const verifier = overrides.codeVerifier === undefined ? result.codeVerifier : overrides.codeVerifier;
  if (verifier !== null) checks.pkceCodeVerifier = verifier;

  return client.authorizationCodeGrant(config, new URL(result.callbackUrl), checks);
}

/** Decodes a JWT payload without verifying: the tests assert on claims, not on the signature. */
export function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const segment = jwt.split('.')[1]!;
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** Raw token-endpoint call, for the cases openid-client refuses to make. */
export async function tokenRequest(
  server: TestServer,
  fields: Record<string, string>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetch(`${server.baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: CLIENT_ID, ...fields }).toString(),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}
