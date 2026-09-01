/**
 * Liveness/readiness endpoint. The Docker HEALTHCHECK points here (phase 5).
 * When Mongo is configured it is pinged, because a provider that cannot reach
 * its store cannot issue or verify anything.
 */
import { Router } from 'express';
import type { Db } from 'mongodb';

import type { Logger } from '../logger.js';

export interface HealthRouterOptions {
  db?: Db;
  identityProviderName: string;
  logger: Logger;
}

export function createHealthRouter(options: HealthRouterOptions): Router {
  const router = Router();
  const log = options.logger.child({ component: 'health' });
  const startedAt = Date.now();

  router.get('/health', (_req, res) => {
    void (async () => {
      const checks: Record<string, string> = {
        identityProvider: options.identityProviderName,
        storage: options.db ? 'mongo' : 'memory',
      };
      let healthy = true;

      if (options.db) {
        try {
          await options.db.command({ ping: 1 });
          checks.mongo = 'ok';
        } catch (error) {
          healthy = false;
          checks.mongo = 'unreachable';
          log.error(
            { err: error instanceof Error ? error.message : error },
            'health check: mongo is unreachable',
          );
        }
      }

      res.status(healthy ? 200 : 503).json({
        status: healthy ? 'ok' : 'degraded',
        uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
        checks,
      });
    })();
  });

  return router;
}
