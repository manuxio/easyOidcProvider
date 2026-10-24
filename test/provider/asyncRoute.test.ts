/**
 * asyncRoute (src/routes/interaction.ts) on its own: which thrown errors count
 * as "the interaction session is gone" (400, Italian text) and which are a
 * fault (500). oidc-provider's SessionNotFound extends InvalidRequest, so its
 * `message` is 'invalid_request' and the "interaction session ..." text is in
 * `error_description` — the case the end-to-end answer in
 * test/provider/interaction.test.ts depends on.
 */
import type { Request, Response } from 'express';
import { errors } from 'oidc-provider';
import { describe, expect, it } from 'vitest';

import { asyncRoute } from '../../src/routes/interaction.js';
import { createCapturingLogger } from '../helpers/captureLogger.js';

const EXPIRED_TEXT = 'La sessione di accesso è scaduta';
const INTERNAL_TEXT = "Errore interno durante l'accesso.";

interface FakeResponse {
  res: Response;
  status?: number;
  type?: string;
  body?: string;
}

function fakeResponse(headersSent = false): FakeResponse {
  const out: FakeResponse = { res: undefined as unknown as Response };
  const res = {
    headersSent,
    status(code: number) {
      out.status = code;
      return res;
    },
    type(value: string) {
      out.type = value;
      return res;
    },
    send(body: string) {
      out.body = body;
      return res;
    },
  };
  out.res = res as unknown as Response;
  return out;
}

const req = { path: '/interaction/some-uid' } as unknown as Request;

async function run(thrown: unknown, headersSent = false) {
  const capture = createCapturingLogger();
  const out = fakeResponse(headersSent);
  const route = asyncRoute(async () => {
    throw thrown;
  }, capture.logger);
  await route(req, out.res);
  return { out, capture };
}

describe('asyncRoute', () => {
  it('a SessionNotFound-shaped error (message invalid_request, text in error_description) is 400', async () => {
    const thrown = Object.assign(new Error('invalid_request'), {
      name: 'SessionNotFound',
      error_description: 'interaction session not found',
    });
    const { out, capture } = await run(thrown);
    expect(out.status).toBe(400);
    expect(out.type).toBe('text');
    expect(out.body).toContain(EXPIRED_TEXT);
    expect(capture.matching('interaction session no longer valid')[0]).toMatchObject({
      level: 'warn',
      expired: true,
      path: '/interaction/some-uid',
      err: { name: 'SessionNotFound', message: 'invalid_request' },
    });
  });

  it("oidc-provider's own SessionNotFound is 400", async () => {
    const { out } = await run(new errors.SessionNotFound('interaction session not found'));
    expect(out.status).toBe(400);
    expect(out.body).toContain(EXPIRED_TEXT);
  });

  it('the text in error_description alone is enough, whatever the name', async () => {
    const thrown = Object.assign(new Error('invalid_request'), {
      error_description: 'interaction session id cookie not found',
    });
    const { out } = await run(thrown);
    expect(out.status).toBe(400);
  });

  it('the text in message alone is still enough', async () => {
    const { out } = await run(new Error('interaction session expired'));
    expect(out.status).toBe(400);
  });

  it('any other failure is 500 with the generic text and no stack trace', async () => {
    const { out, capture } = await run(new TypeError('boom'));
    expect(out.status).toBe(500);
    expect(out.body).toBe(INTERNAL_TEXT);
    expect(capture.matching('interaction failed')[0]).toMatchObject({
      level: 'warn',
      expired: false,
      err: { name: 'TypeError', message: 'boom' },
    });
  });

  it('a thrown non-object is a 500, not a crash', async () => {
    const { out } = await run('plain string');
    expect(out.status).toBe(500);
  });

  it('writes nothing once the headers are sent', async () => {
    const { out } = await run(new errors.SessionNotFound('interaction session not found'), true);
    expect(out.status).toBeUndefined();
    expect(out.body).toBeUndefined();
  });
});
