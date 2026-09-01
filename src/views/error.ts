/** Error page shown by oidc-provider's renderError. Italian text, no stack traces. */
import { escapeHtml, page } from './layout.js';

export interface ErrorPageFields {
  error: string;
  error_description?: string;
}

export function renderErrorPage(fields: ErrorPageFields): string {
  const rows = Object.entries(fields)
    .filter(([, value]) => value !== undefined && value !== '')
    .map(
      ([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(String(value))}</dd>`,
    )
    .join('\n');

  return page(
    'Errore di accesso',
    `<h1>Accesso non riuscito</h1>
<p class="subtitle">La richiesta di autorizzazione è stata rifiutata. Chiudere questa finestra e ripetere l'accesso dall'applicazione; se l'errore si ripete, segnalare all'assistenza il codice qui sotto.</p>
<dl>
${rows}
</dl>`,
  );
}
