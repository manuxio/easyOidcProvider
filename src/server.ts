/**
 * Process entry point. The only place that reads process.env, exits, or binds a
 * socket — everything testable lives in app.ts.
 */
import { createServer } from 'node:http';
import { config as loadDotenv } from 'dotenv';

import { createAuthServer } from './app.js';
import { ConfigError, loadConfig } from './config.js';
import { createLogger } from './logger.js';

loadDotenv({ quiet: true });

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig(process.env);
  } catch (error) {
    if (error instanceof ConfigError) {
      // Before the config is known there is no log level to honour, so this goes
      // straight to stderr, one offending parameter per line.
      process.stderr.write('auth-server cannot start: invalid configuration\n');
      for (const problem of error.problems) {
        process.stderr.write(`  - ${problem}\n`);
      }
      process.stderr.write('see .env.example for the full parameter list\n');
      process.exit(1);
    }
    throw error;
  }

  const logger = createLogger(config.logLevel);
  const server = await createAuthServer({ config, logger });
  const http = createServer(server.app);

  const shutdown = (signal: string): void => {
    logger.info({ signal }, 'shutting down');
    http.close(() => {
      void server.close().then(
        () => process.exit(0),
        (error: unknown) => {
          logger.error({ err: error }, 'error while closing');
          process.exit(1);
        },
      );
    });
    // Never hang a container on a lingering keep-alive connection.
    setTimeout(() => process.exit(0), 10_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  http.listen(config.port, config.host, () => {
    logger.info(
      {
        issuer: config.issuerUrl,
        port: config.port,
        host: config.host,
        identityProvider: config.identityProvider,
        clients: config.clients.map((client) => client.client_id),
        accessTokenTtl: config.accessTokenTtl,
        refreshTokenTtl: config.refreshTokenTtl,
      },
      'auth-server listening',
    );
  });
}

main().catch((error: unknown) => {
  process.stderr.write(`auth-server failed to start: ${String(error)}\n`);
  if (error instanceof Error && error.stack) process.stderr.write(`${error.stack}\n`);
  process.exit(1);
});
