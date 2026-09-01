/**
 * Ambient declaration for the `kerberos` native module, which ships no types.
 *
 * Only the server-side acceptor surface is declared, because that is all this
 * application uses (`src/identity/spnego/gss.ts`); the module also exposes a
 * client side, wrap/unwrap and a MongoDB auth process, none of which we touch.
 *
 * Signatures follow the JSDoc in `node_modules/kerberos/lib/kerberos.js`.
 */
declare module 'kerberos' {
  /** Server-side GSSAPI security context. */
  export interface KerberosServer {
    /** The authenticated client principal, `user@REALM`, once complete. */
    readonly username: string | null;
    /** Base64 output token of the last step, to send back in WWW-Authenticate. */
    readonly response: string | null;
    /** The acceptor name the context was initialised with. */
    readonly targetName: string | null;
    /** False while GSSAPI still wants another leg. */
    readonly contextComplete: boolean;
    /** Feeds one base64 client token into the context. */
    step(challenge: string): Promise<string | null>;
  }

  /**
   * Acquires the acceptor credential for `service`, given as the GSSAPI
   * host-based form `service@host` (e.g. `HTTP@auth.example.com`). The key comes
   * from the keytab named by the KRB5_KTNAME environment variable. An empty
   * string means "accept with the default credential".
   */
  export function initializeServer(service: string): Promise<KerberosServer>;

  export const version: string;
}
