/**
 * A pino logger writing into an array, so a test can assert on what the server
 * actually logged. Used for the claim that carries no other evidence: with the
 * SQL check disabled, nothing about SQL is ever logged and no query is ever run.
 */
import { pino } from 'pino';

import type { Logger } from '../../src/logger.js';

export interface CapturedLog {
  level: string;
  msg: string;
  [field: string]: unknown;
}

export interface CapturingLogger {
  logger: Logger;
  records: CapturedLog[];
  /** Records whose message contains the fragment, case-insensitively. */
  matching(fragment: string): CapturedLog[];
  /** Records carrying this `reason` field. */
  withReason(reason: string): CapturedLog[];
  text(): string;
}

export function createCapturingLogger(level = 'trace'): CapturingLogger {
  const records: CapturedLog[] = [];
  const logger = pino(
    {
      level,
      base: { app: 'auth-server' },
      formatters: { level: (label) => ({ level: label }) },
      timestamp: pino.stdTimeFunctions.isoTime,
    },
    {
      write(line: string) {
        records.push(JSON.parse(line) as CapturedLog);
      },
    },
  );

  return {
    logger,
    records,
    matching(fragment) {
      const needle = fragment.toLowerCase();
      return records.filter((record) => String(record.msg ?? '').toLowerCase().includes(needle));
    },
    withReason(reason) {
      return records.filter((record) => record.reason === reason);
    },
    text() {
      return records.map((record) => JSON.stringify(record)).join('\n');
    },
  };
}
