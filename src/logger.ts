/**
 * Structured logger. Deliberately free of @predictive/* dependencies so the
 * Docker build context stays limited to this folder, but the shape of a record
 * (level, time, msg, plus flat fields) matches what the other applications emit.
 */
import { pino, type Logger } from 'pino';

export type { Logger };

export function createLogger(level: string): Logger {
  return pino({
    level,
    base: { app: 'auth-server' },
    formatters: {
      level: (label) => ({ level: label }),
    },
    timestamp: pino.stdTimeFunctions.isoTime,
  });
}

/** A logger that swallows everything; used by tests that assert on behaviour, not noise. */
export function createSilentLogger(): Logger {
  return pino({ level: 'silent' });
}
