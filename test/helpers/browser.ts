/**
 * The smallest thing that can drive an HTML login form: fetch plus a cookie jar.
 *
 * openid-client speaks the protocol but not the interaction pages, so the tests
 * use this to walk the redirect chain and post the form, then hand the resulting
 * callback URL back to openid-client for the token exchange.
 */

export class Browser {
  #cookies = new Map<string, string>();

  #storeCookies(response: Response): void {
    const raw = response.headers.getSetCookie?.() ?? [];
    for (const cookie of raw) {
      const [pair] = cookie.split(';');
      const separator = pair!.indexOf('=');
      if (separator === -1) continue;
      const name = pair!.slice(0, separator).trim();
      const value = pair!.slice(separator + 1).trim();
      if (value === '' || /expires=Thu, 01 Jan 1970/i.test(cookie)) {
        this.#cookies.delete(name);
      } else {
        this.#cookies.set(name, value);
      }
    }
  }

  #cookieHeader(): string {
    return [...this.#cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  }

  /** One request, redirects NOT followed. */
  async fetch(url: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    const cookies = this.#cookieHeader();
    if (cookies !== '') headers.set('cookie', cookies);

    const response = await fetch(url, { ...init, headers, redirect: 'manual' });
    this.#storeCookies(response);
    return response;
  }

  /**
   * Follows redirects until the location leaves `baseUrl` (i.e. the client's
   * loopback callback) or the response stops redirecting. Returns the last
   * response plus the final location, whichever came first.
   */
  async follow(
    startUrl: string,
    baseUrl: string,
    init: RequestInit = {},
  ): Promise<{ response: Response; callbackUrl?: string; visited: string[] }> {
    const visited: string[] = [];
    let url = startUrl;
    let options = init;

    for (let hop = 0; hop < 10; hop += 1) {
      visited.push(url);
      const response = await this.fetch(url, options);
      // Only the first hop may be a POST; a 303 turns everything after into GET.
      options = {};

      const location = response.headers.get('location');
      if (!location) return { response, visited };

      const next = new URL(location, baseUrl).toString();
      if (!next.startsWith(baseUrl)) {
        return { response, callbackUrl: next, visited };
      }
      url = next;
    }
    throw new Error(`redirect loop: ${visited.join(' -> ')}`);
  }

  async postForm(
    url: string,
    fields: Record<string, string>,
  ): Promise<Response> {
    return this.fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(fields).toString(),
    });
  }
}
