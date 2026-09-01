/**
 * The only place in the codebase that touches the native GSSAPI binding.
 *
 * It is a single function behind an interface so that (a) everything else stays
 * unit testable without a Kerberos runtime, and (b) the native module is
 * imported lazily: a server running with IDENTITY_PROVIDER=dev-stub never loads
 * it, and a machine without libkrb5 can still run the test suite.
 */
import type { Logger } from '../../logger.js';
import { toHostBasedServiceName } from './negotiate.js';

export type GssAcceptResult =
  /** The handshake finished: `principal` is the client's `user@REALM`. */
  | { status: 'complete'; principal: string; responseToken: string }
  /**
   * GSSAPI wants another leg. We do not keep a security context across HTTP
   * requests, so this is reported and refused rather than half-answered — see
   * the note in spnego.ts.
   */
  | { status: 'continue'; responseToken: string }
  /** The client's token was refused (bad ticket, wrong SPN, clock skew, replay). */
  | { status: 'rejected'; detail: string }
  /** We could not even present ourselves: keytab unreadable, SPN not in it. */
  | { status: 'unavailable'; detail: string };

export interface GssAcceptor {
  /** `token` is the base64 blob from the `Negotiate` header. */
  accept(token: string): Promise<GssAcceptResult>;
}

/** Shape of the pieces of `kerberos` we use, so the lazy import stays typed. */
interface KerberosServerContext {
  readonly username: string | null;
  readonly response: string | null;
  readonly contextComplete: boolean;
  step(challenge: string): Promise<string | null>;
}

interface KerberosModule {
  initializeServer(service: string): Promise<KerberosServerContext>;
}

let cachedModule: Promise<KerberosModule> | undefined;

/**
 * Loads the native binding once.
 *
 * `kerberos` is CommonJS, so from an ES module its exports arrive under
 * `default` and the named re-exports Node synthesises are not always there —
 * reaching for `default` first is what keeps this from being
 * "initializeServer is not a function" at the first handshake.
 */
async function loadKerberos(): Promise<KerberosModule> {
  cachedModule ??= import('kerberos').then((namespace) => {
    const candidate = namespace as unknown as { default?: KerberosModule };
    const api = candidate.default ?? (namespace as unknown as KerberosModule);
    if (typeof api.initializeServer !== 'function') {
      throw new Error('the kerberos module does not expose initializeServer');
    }
    return api;
  });
  return cachedModule;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export class NativeGssAcceptor implements GssAcceptor {
  /** Host-based form (`HTTP@host`), which is what gss_import_name expects. */
  readonly #serviceName: string;
  readonly #logger: Logger;

  constructor(serviceName: string, logger: Logger) {
    this.#serviceName = toHostBasedServiceName(serviceName);
    this.#logger = logger;
  }

  /** Exposed for the startup log line: the name GSSAPI will actually accept as. */
  get serviceName(): string {
    return this.#serviceName;
  }

  async accept(token: string): Promise<GssAcceptResult> {
    let kerberos: KerberosModule;
    try {
      kerberos = await loadKerberos();
    } catch (error) {
      return {
        status: 'unavailable',
        detail: `the native kerberos binding could not be loaded: ${messageOf(error)}`,
      };
    }

    let context: KerberosServerContext;
    try {
      context = await kerberos.initializeServer(this.#serviceName);
    } catch (error) {
      // Wrong or unreadable keytab, SPN absent from it, no KRB5_KTNAME: all of
      // these are our fault, not the caller's.
      return {
        status: 'unavailable',
        detail: `could not acquire the acceptor credential for ${this.#serviceName}: ${messageOf(error)}`,
      };
    }

    try {
      await context.step(token);
    } catch (error) {
      return { status: 'rejected', detail: messageOf(error) };
    }

    const responseToken = context.response ?? '';

    if (!context.contextComplete) {
      return { status: 'continue', responseToken };
    }

    const principal = context.username ?? '';
    if (principal === '') {
      this.#logger.error(
        { serviceName: this.#serviceName },
        'GSSAPI reported a complete context with no client name: refusing',
      );
      return { status: 'rejected', detail: 'the completed context carried no client name' };
    }

    return { status: 'complete', principal, responseToken };
  }
}
