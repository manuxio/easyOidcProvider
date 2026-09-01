/** Login form. User-facing text is Italian; identifiers and comments stay English. */
import type { ChallengeReason } from '../identity/types.js';
import { escapeHtml, page } from './layout.js';

/**
 * FORM CONTRACT — the desktop client (phase 6) posts these field names back to
 * `/interaction/:uid/login`, so they are part of the interface, not a detail:
 *
 *   username   the domain account name (with or without @realm)
 *   password   the domain password
 *   otp        the 6-digit TOTP code — present ONLY when TWO_FACTOR_ENABLED=true
 *
 * A page rendered with `twoFactor: true` also carries the marker below, so a
 * client can tell whether the code is expected without parsing the label.
 */
export const FORM_FIELD_USERNAME = 'username';
export const FORM_FIELD_PASSWORD = 'password';
export const FORM_FIELD_OTP = 'otp';
/** Machine-readable marker on the form element when the second factor is on. */
export const FORM_TWO_FACTOR_MARKER = 'data-two-factor="required"';

const REASON_TEXT: Record<ChallengeReason, string> = {
  invalid_credentials: 'Nome utente o password non corretti. Riprovare.',
  // Same wording as a wrong password on purpose: il modulo non deve rivelare
  // quali nomi utente esistono sul dominio.
  account_not_found: 'Nome utente o password non corretti. Riprovare.',
  account_disabled:
    "L'account non è più attivo sul dominio. Rivolgersi all'amministratore di sistema.",
  account_expired:
    "L'account di dominio è scaduto. Rivolgersi all'amministratore di sistema per rinnovarlo.",
  account_locked:
    "L'account è bloccato dopo troppi tentativi errati. Attendere qualche minuto oppure rivolgersi all'amministratore di sistema.",
  password_expired:
    'La password di dominio è scaduta e va cambiata prima di accedere. Cambiarla dal computer aziendale, poi riprovare.',
  group_not_allowed:
    "L'account esiste sul dominio ma non è abilitato a questa applicazione. Rivolgersi all'amministratore di sistema.",
  temporarily_unavailable:
    "Non è stato possibile verificare l'account: il servizio di dominio non risponde. Riprovare tra qualche minuto.",
  ntlm_not_supported:
    'Il computer ha proposto un accesso NTLM, che non è supportato. Usare il modulo qui sotto con le credenziali di dominio.',
  sso_failed:
    "L'accesso automatico al dominio non è riuscito. Inserire le credenziali di dominio nel modulo qui sotto.",
  sql_group_check_failed:
    "Le credenziali sono corrette, ma l'utenza non risulta abilitata all'uso di questa applicazione. Rivolgersi all'amministratore di sistema.",
  // --- phase 4-bis ---------------------------------------------------------
  // Deliberately explicit: this message is only ever shown AFTER the password
  // was accepted, so it reveals nothing to somebody guessing user names, and it
  // is the only way the user learns that the missing piece is their enrolment.
  two_factor_not_enrolled:
    "Le credenziali sono corrette, ma per questa utenza non è configurato il codice di verifica a due fattori. Rivolgersi all'amministratore di sistema.",
  too_many_attempts:
    'Troppi tentativi non riusciti per questo nome utente. Attendere qualche minuto prima di riprovare.',
  // --- end phase 4-bis -----------------------------------------------------
  // --- phase 4-ter ---------------------------------------------------------
  // Shown only after the password has already been accepted, like the message
  // above it: it names an administrative state, not a credential.
  claims_user_not_found:
    "Le credenziali di dominio sono corrette, ma questa utenza non risulta agganciata a nessun utente del gestionale. Senza quel collegamento il sistema non sa a chi attribuire il lavoro. Rivolgersi all'amministratore di sistema.",
  // --- end phase 4-ter -----------------------------------------------------
};

export interface LoginPageOptions {
  /** Where the form posts: the interaction endpoint of this login attempt. */
  action: string;
  reason?: ChallengeReason;
  username?: string;
  /** Shown under the title, so the user knows which application is asking. */
  clientName?: string;
  /** Phase 4-bis: adds the "Codice di verifica" field (TWO_FACTOR_ENABLED). */
  twoFactor?: boolean;
}

export function renderLoginPage(options: LoginPageOptions): string {
  const alert = options.reason
    ? `<p class="alert" role="alert">${escapeHtml(REASON_TEXT[options.reason])}</p>`
    : '';
  const subtitle = options.clientName
    ? `<p class="subtitle">Accesso richiesto da <strong>${escapeHtml(options.clientName)}</strong>.</p>`
    : '<p class="subtitle">Inserire le credenziali di dominio per continuare.</p>';

  // Six digits, numeric keypad on a touch device, and the autocomplete hint that
  // lets a phone offer the code straight from the SMS/authenticator sheet.
  const otpField = options.twoFactor
    ? `
  <label>Codice di verifica
    <input type="text" name="${FORM_FIELD_OTP}" inputmode="numeric" pattern="[0-9]*"
           maxlength="6" autocomplete="one-time-code"
           autocapitalize="off" autocorrect="off" spellcheck="false" required>
    <span class="hint">Le sei cifre mostrate in questo momento dall'applicazione di autenticazione.</span>
  </label>`
    : '';

  return page(
    'Accesso',
    `<h1>Accesso</h1>
${subtitle}
${alert}
<form method="post" action="${escapeHtml(options.action)}" autocomplete="off"${
      options.twoFactor ? ` ${FORM_TWO_FACTOR_MARKER}` : ''
    }>
  <label>Nome utente
    <input type="text" name="${FORM_FIELD_USERNAME}" value="${escapeHtml(options.username ?? '')}"
           autocapitalize="off" autocorrect="off" spellcheck="false" autofocus required>
  </label>
  <label>Password
    <input type="password" name="${FORM_FIELD_PASSWORD}" required>
  </label>${otpField}
  <button type="submit">Accedi</button>
</form>`,
  );
}

/**
 * Phase 4-bis: the challenge body when FALLBACK_FORM_ENABLED=false.
 *
 * There is no form here, by design — that is the whole point of the switch. The
 * 401 still carries `WWW-Authenticate: Negotiate`, so a domain-joined browser
 * never sees this page: it answers the header and signs in silently. Whoever
 * reads it is on a machine that cannot do Kerberos, and needs to be told why
 * there is nothing to type.
 */
export function renderSsoOnlyPage(options: { reason?: ChallengeReason } = {}): string {
  const alert = options.reason
    ? `<p class="alert" role="alert">${escapeHtml(REASON_TEXT[options.reason])}</p>`
    : '';

  return page(
    'Accesso',
    `<h1>Accesso automatico richiesto</h1>
<p class="subtitle">Questo servizio accetta solo l'accesso automatico con le credenziali di dominio.</p>
${alert}
<p>Il computer non ha presentato credenziali di dominio valide e l'accesso con nome utente e
password è disattivato su questo server.</p>
<p>Usare un computer collegato al dominio aziendale, oppure rivolgersi all'amministratore di
sistema.</p>`,
  );
}

/**
 * Phase 4-bis: the answer to a form POST while FALLBACK_FORM_ENABLED=false.
 * Separate from the page above because this one answers somebody who did type
 * credentials — into a form this server did not serve.
 */
export function renderFormDisabledPage(): string {
  return page(
    'Accesso',
    `<h1>Accesso con password disattivato</h1>
<p class="subtitle">Su questo server è attivo solo l'accesso automatico di dominio.</p>
<p>L'accesso con nome utente e password non è disponibile. Usare un computer collegato al
dominio aziendale, oppure rivolgersi all'amministratore di sistema.</p>`,
  );
}
