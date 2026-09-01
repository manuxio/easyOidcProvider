/**
 * Minimal server-rendered pages. No client-side framework, no external assets:
 * the login page must work on a locked-down desktop and inside a hidden Electron
 * BrowserWindow. User-facing text is Italian, by project convention.
 */

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ESCAPES[char]!);
}

export function page(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #f4f5f7; color: #1c2024;
  }
  main {
    width: 100%; max-width: 26rem; margin: 1.5rem; padding: 2rem;
    background: #fff; border: 1px solid #dcdfe3; border-radius: 10px;
    box-shadow: 0 1px 3px rgba(0,0,0,.06);
  }
  h1 { margin: 0 0 .25rem; font-size: 1.25rem; }
  p.subtitle { margin: 0 0 1.5rem; color: #5b6470; font-size: .9rem; }
  label { display: block; margin-bottom: 1rem; font-weight: 600; font-size: .85rem; }
  input[type=text], input[type=password] {
    display: block; width: 100%; margin-top: .35rem; padding: .6rem .7rem;
    font: inherit; border: 1px solid #c3c8ce; border-radius: 6px; background: #fff; color: inherit;
  }
  input:focus { outline: 2px solid #2b6cb0; outline-offset: 1px; border-color: #2b6cb0; }
  button {
    width: 100%; padding: .65rem; font: inherit; font-weight: 600; cursor: pointer;
    color: #fff; background: #2b6cb0; border: 0; border-radius: 6px;
  }
  button:hover { background: #245a94; }
  .alert {
    margin: 0 0 1.25rem; padding: .7rem .8rem; border-radius: 6px; font-size: .875rem;
    background: #fdecec; border: 1px solid #f3b9b9; color: #8a1f1f;
  }
  .hint { display: block; margin-top: .3rem; font-weight: 400; font-size: .8rem; color: #5b6470; }
  dl { margin: 0; font-size: .85rem; color: #5b6470; }
  dt { font-weight: 600; margin-top: .75rem; }
  dd { margin: .1rem 0 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  @media (prefers-color-scheme: dark) {
    body { background: #16181c; color: #e6e8eb; }
    main { background: #1e2126; border-color: #333940; box-shadow: none; }
    p.subtitle, dl, .hint { color: #9aa3ad; }
    input[type=text], input[type=password] { background: #16181c; border-color: #3c434b; color: inherit; }
    .alert { background: #3a1c1c; border-color: #6b2b2b; color: #f5b5b5; }
  }
</style>
</head>
<body>
<main>
${body}
</main>
</body>
</html>
`;
}
