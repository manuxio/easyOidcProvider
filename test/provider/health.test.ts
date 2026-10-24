/**
 * GET /health (src/routes/health.ts), the endpoint the Docker HEALTHCHECK
 * points at.
 *
 * The router alone, on a loopback port, with a fake Db: without Mongo the
 * answer is always healthy; with Mongo a failed ping turns it into 503
 * `degraded`, because a provider that cannot reach its store cannot issue or
 * verify anything. The full server's /health is in test/e2e.test.ts.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import express from 'express';
import type { Db } from 'mongodb';
import { afterEach, describe, expect, it } from 'vitest';

import { createHealthRouter, type HealthRouterOptions } from '../../src/routes/health.js';
import { createSilentLogger } from '../../src/logger.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';

const running: Server[] = [];
afterEach(async () => {
  while (running.length > 0) {
    const server = running.pop()!;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

async function serve(options: HealthRouterOptions): Promise<string> {
  const app = express();
  app.use(createHealthRouter(options));
  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  running.push(server);
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

/** A Db whose ping answers, or throws `failWith`. */
function fakeDb(failWith?: unknown): { db: Db; pings: unknown[] } {
  const pings: unknown[] = [];
  const db = {
    async command(command: unknown) {
      pings.push(command);
      if (failWith !== undefined) throw failWith;
      return { ok: 1 };
    },
  } as unknown as Db;
  return { db, pings };
}

async function health(baseUrl: string) {
  const response = await fetch(`${baseUrl}/health`);
  return { status: response.status, type: response.headers.get('content-type'), body: await response.json() as Record<string, unknown> };
}

describe('/health without Mongo', () => {
  it('answers 200 ok with the identity provider and the in-memory storage', async () => {
    const baseUrl = await serve({ identityProviderName: 'dev-stub', logger: createSilentLogger() });
    const { status, type, body } = await health(baseUrl);
    expect(status).toBe(200);
    expect(type).toMatch(/application\/json/);
    expect(body).toEqual({
      status: 'ok',
      uptimeSeconds: expect.any(Number),
      checks: { identityProvider: 'dev-stub', storage: 'memory' },
    });
    expect(body.uptimeSeconds).toBeGreaterThanOrEqual(0);
  });

  it('reports whichever identity provider it is given', async () => {
    const baseUrl = await serve({ identityProviderName: 'spnego', logger: createSilentLogger() });
    expect((await health(baseUrl)).body.checks).toMatchObject({ identityProvider: 'spnego' });
  });

  it('serves only GET /health', async () => {
    const baseUrl = await serve({ identityProviderName: 'dev-stub', logger: createSilentLogger() });
    expect((await fetch(`${baseUrl}/health`, { method: 'POST' })).status).toBe(404);
    expect((await fetch(`${baseUrl}/healthz`)).status).toBe(404);
  });
});

describe('/health with Mongo', () => {
  it('pings the database on every call and answers 200 when it replies', async () => {
    const { db, pings } = fakeDb();
    const baseUrl = await serve({ db, identityProviderName: 'dev-stub', logger: createSilentLogger() });

    const { status, body } = await health(baseUrl);
    expect(status).toBe(200);
    expect(body).toMatchObject({
      status: 'ok',
      checks: { identityProvider: 'dev-stub', storage: 'mongo', mongo: 'ok' },
    });
    await health(baseUrl);
    expect(pings).toEqual([{ ping: 1 }, { ping: 1 }]);
  });

  it('answers 503 degraded when the ping fails, and logs why', async () => {
    const { db } = fakeDb(new Error('connection refused (test)'));
    const capture = createCapturingLogger();
    const baseUrl = await serve({ db, identityProviderName: 'dev-stub', logger: capture.logger });

    const { status, body } = await health(baseUrl);
    expect(status).toBe(503);
    expect(body).toMatchObject({
      status: 'degraded',
      checks: { identityProvider: 'dev-stub', storage: 'mongo', mongo: 'unreachable' },
    });
    const logged = capture.matching('health check: mongo is unreachable');
    expect(logged).toHaveLength(1);
    expect(logged[0]).toMatchObject({ level: 'error', component: 'health', err: 'connection refused (test)' });
  });

  it('treats a non-Error rejection the same way', async () => {
    const { db } = fakeDb('socket hang up');
    const capture = createCapturingLogger();
    const baseUrl = await serve({ db, identityProviderName: 'dev-stub', logger: capture.logger });

    expect((await health(baseUrl)).status).toBe(503);
    expect(capture.matching('health check: mongo is unreachable')[0]).toMatchObject({ err: 'socket hang up' });
  });
});
