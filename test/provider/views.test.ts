/**
 * The server-rendered pages (src/views/): the HTML skeleton, the error page
 * oidc-provider's renderError shows, and the login form whose field names are
 * a contract with the desktop client (FORM CONTRACT in src/views/login.ts).
 *
 * Pure functions, no server: what is checked is the contract (field names,
 * the two-factor marker), the escaping of everything that comes from a request,
 * and the rule that a wrong user name reads exactly like a wrong password.
 */
import { describe, expect, it } from 'vitest';

import { CHALLENGE_REASONS } from '../../src/identity/types.js';
import { renderErrorPage } from '../../src/views/error.js';
import { escapeHtml, page } from '../../src/views/layout.js';
import {
  FORM_FIELD_OTP,
  FORM_FIELD_PASSWORD,
  FORM_FIELD_USERNAME,
  FORM_TWO_FACTOR_MARKER,
  renderFormDisabledPage,
  renderLoginPage,
  renderSsoOnlyPage,
} from '../../src/views/login.js';

const HOSTILE = `<script>alert("x")</script>&'`;
const HOSTILE_ESCAPED = '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;&#39;';

/** The text of the error banner, or undefined when there is none. */
function alertText(html: string): string | undefined {
  return /<p class="alert" role="alert">([^<]*)<\/p>/.exec(html)?.[1];
}

function titleOf(html: string): string | undefined {
  return /<title>([^<]*)<\/title>/.exec(html)?.[1];
}

describe('layout: escapeHtml', () => {
  it('escapes the five HTML-significant characters', () => {
    expect(escapeHtml(`&<>"'`)).toBe('&amp;&lt;&gt;&quot;&#39;');
  });

  it('escapes every occurrence, and & first so nothing is double-escaped', () => {
    expect(escapeHtml('a&b&c')).toBe('a&amp;b&amp;c');
    expect(escapeHtml('&lt;')).toBe('&amp;lt;');
    expect(escapeHtml(HOSTILE)).toBe(HOSTILE_ESCAPED);
  });

  it('leaves plain text, accents included, untouched', () => {
    expect(escapeHtml('')).toBe('');
    expect(escapeHtml('Già verificato: àèéìòù')).toBe('Già verificato: àèéìòù');
  });
});

describe('layout: page', () => {
  it('is a complete Italian HTML5 document with no external asset', () => {
    const html = page('Titolo', '<p>corpo</p>');
    expect(html.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(html).toContain('<html lang="it">');
    expect(html).toContain('<meta charset="utf-8">');
    expect(html).toContain('<meta name="viewport"');
    // Locked-down desktops and a hidden Electron window: nothing fetched from outside.
    expect(html).not.toMatch(/<link\b/);
    expect(html).not.toMatch(/<script\b/);
    expect(html).not.toMatch(/https?:\/\//);
  });

  it('escapes the title but inserts the body as markup', () => {
    const html = page(HOSTILE, '<p class="x">corpo</p>');
    expect(titleOf(html)).toBe(HOSTILE_ESCAPED);
    expect(html).toContain('<main>\n<p class="x">corpo</p>\n</main>');
  });

  it('follows the colour scheme of the system', () => {
    const html = page('t', '');
    expect(html).toContain('color-scheme: light dark');
    expect(html).toContain('@media (prefers-color-scheme: dark)');
  });
});

describe('error page', () => {
  it('lists the error code and its description', () => {
    const html = renderErrorPage({ error: 'invalid_request', error_description: 'missing required parameter' });
    expect(html).toContain('<h1>Accesso non riuscito</h1>');
    expect(html).toContain('<dt>error</dt><dd>invalid_request</dd>');
    expect(html).toContain('<dt>error_description</dt><dd>missing required parameter</dd>');
    expect(titleOf(html)).toContain('Errore di accesso');
  });

  it('leaves out an absent or empty description', () => {
    for (const fields of [{ error: 'server_error' }, { error: 'server_error', error_description: '' }]) {
      const html = renderErrorPage(fields);
      expect(html).toContain('<dt>error</dt><dd>server_error</dd>');
      expect(html).not.toContain('<dt>error_description</dt>');
    }
  });

  it('escapes what comes from the request', () => {
    const html = renderErrorPage({ error: HOSTILE, error_description: HOSTILE });
    expect(html).not.toContain('<script>');
    expect(html).toContain(`<dd>${HOSTILE_ESCAPED}</dd>`);
  });

  it('carries no stack trace and no exception text', () => {
    const html = renderErrorPage({ error: 'server_error', error_description: 'oops' });
    expect(html).not.toMatch(/\bat \S+ \(/);
    expect(html).not.toContain('Error:');
  });
});

describe('login page: the form contract', () => {
  it('posts username and password to the action, with no second factor by default', () => {
    const html = renderLoginPage({ action: '/interaction/abc/login' });
    expect(html).toContain('<form method="post" action="/interaction/abc/login"');
    expect(html).toContain(`name="${FORM_FIELD_USERNAME}"`);
    expect(html).toContain(`name="${FORM_FIELD_PASSWORD}"`);
    expect(html).toContain('type="password"');
    expect(html).not.toContain(`name="${FORM_FIELD_OTP}"`);
    expect(html).not.toContain(FORM_TWO_FACTOR_MARKER);
    expect(alertText(html)).toBeUndefined();
  });

  it('keeps the field names the desktop client posts', () => {
    expect([FORM_FIELD_USERNAME, FORM_FIELD_PASSWORD, FORM_FIELD_OTP]).toEqual(['username', 'password', 'otp']);
    expect(FORM_TWO_FACTOR_MARKER).toBe('data-two-factor="required"');
  });

  it('adds the six-digit code field and the machine-readable marker when the second factor is on', () => {
    const html = renderLoginPage({ action: '/interaction/abc/login', twoFactor: true });
    expect(html).toMatch(new RegExp(`<form [^>]*${FORM_TWO_FACTOR_MARKER}>`));
    const otp = new RegExp(`<input type="text" name="${FORM_FIELD_OTP}"[^>]*>`).exec(html)?.[0];
    expect(otp).toBeDefined();
    expect(otp).toContain('maxlength="6"');
    expect(otp).toContain('inputmode="numeric"');
    expect(otp).toContain('autocomplete="one-time-code"');
    expect(otp).toContain('required');
  });

  it('echoes the user name back, escaped, so the user does not retype it', () => {
    const html = renderLoginPage({ action: '/a', username: HOSTILE });
    expect(html).toContain(`value="${HOSTILE_ESCAPED}"`);
    expect(html).not.toContain('<script>');
    expect(renderLoginPage({ action: '/a' })).toContain(`name="${FORM_FIELD_USERNAME}" value=""`);
  });

  it('escapes the action and the client name', () => {
    const html = renderLoginPage({ action: `/interaction/"><x/login`, clientName: HOSTILE });
    expect(html).toContain('action="/interaction/&quot;&gt;&lt;x/login"');
    expect(html).toContain(`Accesso richiesto da <strong>${HOSTILE_ESCAPED}</strong>`);
  });

  it('names the asking application only when it is known', () => {
    expect(renderLoginPage({ action: '/a', clientName: 'desktop client' })).toContain('<strong>desktop client</strong>');
    expect(renderLoginPage({ action: '/a' })).toContain('Inserire le credenziali di dominio per continuare.');
  });
});

describe('login page: the reasons', () => {
  it('has a non-empty Italian message for every challenge reason', () => {
    for (const reason of CHALLENGE_REASONS) {
      const text = alertText(renderLoginPage({ action: '/a', reason }));
      expect(text, reason).toBeDefined();
      expect(text!.trim().length, reason).toBeGreaterThan(10);
    }
  });

  it('says the same thing for an unknown user name and a wrong password (no account enumeration)', () => {
    const wrongPassword = alertText(renderLoginPage({ action: '/a', reason: 'invalid_credentials' }));
    const unknownUser = alertText(renderLoginPage({ action: '/a', reason: 'account_not_found' }));
    expect(unknownUser).toBe(wrongPassword);
  });

  it('tells apart the reasons that are shown only after the password was accepted', () => {
    const wrongPassword = alertText(renderLoginPage({ action: '/a', reason: 'invalid_credentials' }));
    for (const reason of ['two_factor_not_enrolled', 'claims_user_not_found', 'client_group_not_allowed'] as const) {
      expect(alertText(renderLoginPage({ action: '/a', reason })), reason).not.toBe(wrongPassword);
    }
  });

  it('gives every reason its own wording except the deliberate pair above', () => {
    const texts = CHALLENGE_REASONS
      .filter((reason) => reason !== 'account_not_found')
      .map((reason) => alertText(renderLoginPage({ action: '/a', reason })));
    expect(new Set(texts).size).toBe(texts.length);
  });
});

describe('SSO-only pages (FALLBACK_FORM_ENABLED=false)', () => {
  it('the challenge page carries no form and no credential field', () => {
    const html = renderSsoOnlyPage();
    expect(html).toContain('Accesso automatico richiesto');
    expect(html).not.toContain('<form');
    expect(html).not.toContain(`name="${FORM_FIELD_PASSWORD}"`);
    expect(alertText(html)).toBeUndefined();
  });

  it('the challenge page shows the reason when there is one', () => {
    const html = renderSsoOnlyPage({ reason: 'sso_failed' });
    expect(alertText(html)).toBe(alertText(renderLoginPage({ action: '/a', reason: 'sso_failed' })));
    expect(html).not.toContain('<form');
  });

  it('the answer to a posted form says the password door is closed, with no form', () => {
    const html = renderFormDisabledPage();
    expect(html).toContain('Accesso con password disattivato');
    expect(html).not.toContain('<form');
    expect(html).not.toContain('<input');
  });
});
