/**
 * Static analysis of CLAIMS_SQL_QUERY: which claim names will this query
 * produce?
 *
 * WHY THIS EXISTS AT ALL. The contract says the result columns become the
 * claims, and result columns are only known when the query runs. But the names
 * have to be known BEFORE that, twice over:
 *
 *  1. the reserved-name blacklist must stop the server at startup, not at
 *     somebody's first login;
 *  2. oidc-provider v9 only lets a claim into an id_token if its name was
 *     declared in the `claims` configuration when the Provider was built
 *     (`lib/helpers/claims.js` filters the account claims through
 *     `claimsSupported`, which `lib/helpers/configuration.js` freezes at
 *     construction). A name discovered at query time would be read, logged —
 *     and then silently dropped from the token.
 *
 * So the SELECT list is parsed at startup and its aliases ARE the declaration.
 * A query whose output names cannot be determined STOPS THE SERVER, by
 * parameter name, instead of starting a server that would quietly emit nothing.
 * The price is one rule for the customer — alias every computed column — which
 * is exactly what their reference query already does.
 *
 * The parser is deliberately narrow. It splits the SELECT list on top-level
 * commas and, for each item, takes either an explicit `AS <alias>` or a bare
 * (possibly qualified) column reference. It understands quoting and comments
 * well enough not to be fooled by a comma inside a string, and it refuses
 * everything else. It is NOT a SQL parser and must never grow into one: when it
 * cannot tell, the answer is "say so and stop", never "guess".
 *
 * The first execution then adds the other half of the enforcement — the real
 * column names are compared against this declaration, and any difference is a
 * hard, loud failure. See `sqlClaimsSource.ts`.
 */
import { assertClaimNameAllowed } from './reserved.js';
import { ExtraClaimsConfigError } from './types.js';

/**
 * The claim names CLAIMS_SQL_QUERY will produce, in SELECT-list order.
 * Throws ExtraClaimsConfigError — at startup — for anything it cannot pin down.
 */
export function parseClaimNames(query: string): string[] {
  const sql = stripTrailingSemicolon(query.trim());
  if (sql === '') {
    throw new ExtraClaimsConfigError('CLAIMS_SQL_QUERY is empty');
  }

  const map = scan(sql);
  const afterSelect = keywordEndAt(sql, 0, 'select');
  if (afterSelect === -1) {
    throw new ExtraClaimsConfigError(
      'CLAIMS_SQL_QUERY must be a single SELECT statement: its result columns are the claims',
    );
  }

  const list = sql.slice(afterSelect, endOfSelectList(sql, map, afterSelect));
  const items = splitTopLevel(list);

  const names: string[] = [];
  const seen = new Map<string, number>();

  items.forEach((item, index) => {
    const name = outputNameOf(item, index);
    assertClaimNameAllowed(name, 'startup analysis of CLAIMS_SQL_QUERY');

    const key = name.toLowerCase();
    const first = seen.get(key);
    if (first !== undefined) {
      throw new ExtraClaimsConfigError(
        `CLAIMS_SQL_QUERY produces the claim ${JSON.stringify(name)} twice `
        + `(select items ${first + 1} and ${index + 1}): a claim can only have one value`,
      );
    }
    seen.set(key, index);
    names.push(name);
  });

  return names;
}

// --------------------------------------------------------------- one item ---

/** The claim name one select item produces, or an explanation of why not. */
function outputNameOf(rawItem: string, index: number): string {
  const item = stripComments(rawItem).trim();
  const where = `select item ${index + 1} (${JSON.stringify(truncate(rawItem.trim()))})`;

  if (item === '') {
    throw new ExtraClaimsConfigError(`CLAIMS_SQL_QUERY has an empty ${where}`);
  }

  if (item === '*' || /(^|\.)\*$/.test(item)) {
    throw new ExtraClaimsConfigError(
      `CLAIMS_SQL_QUERY uses ${JSON.stringify(item)}: the claim names cannot be known before the `
      + 'query runs, so every column must be selected explicitly and given an alias',
    );
  }

  const aliased = trailingAlias(item);
  if (aliased !== undefined) return aliased;

  const bare = bareColumnName(item);
  if (bare !== undefined) return bare;

  throw new ExtraClaimsConfigError(
    `CLAIMS_SQL_QUERY: cannot tell which claim ${where} produces. `
    + 'Give it an explicit alias, as in "CONCAT(a, b) AS name" — the alias IS the claim name',
  );
}

/** `<expression> AS <alias>`, the alias being everything after the last top-level AS. */
function trailingAlias(item: string): string | undefined {
  const map = scan(item);
  let aliasAt = -1;
  for (let index = 0; index < item.length; index += 1) {
    if (map.kind[index] !== CODE || map.depth[index] !== 0) continue;
    if (isKeywordAt(item, index, 'as')) aliasAt = index + 2;
  }
  if (aliasAt === -1) return undefined;

  const alias = item.slice(aliasAt).trim();
  if (alias === '') {
    throw new ExtraClaimsConfigError('CLAIMS_SQL_QUERY has an "AS" with no alias after it');
  }
  return unquoteIdentifier(alias, 'alias');
}

/** A bare `column`, `table.column` or `` `t`.`column` `` — the last part wins. */
function bareColumnName(item: string): string | undefined {
  const parts = splitQualified(item);
  if (parts === undefined) return undefined;
  return unquoteIdentifier(parts[parts.length - 1]!, 'column');
}

/**
 * Splits a dotted identifier chain, or undefined when the text is anything else
 * (a function call, an arithmetic expression, a literal).
 */
function splitQualified(item: string): string[] | undefined {
  const map = scan(item);
  const parts: string[] = [];
  let current = '';

  for (let index = 0; index < item.length; index += 1) {
    const char = item[index]!;
    if (map.depth[index] !== 0) return undefined;

    if (map.kind[index] === CODE) {
      if (char === '.') {
        parts.push(current);
        current = '';
        continue;
      }
      // Whitespace inside a bare reference means it is not one. MySQL's
      // alias-without-AS form (`SELECT id remoteId`) is deliberately NOT
      // accepted here, because `SELECT a + b` would then silently become `b`.
      if (!/[A-Za-z0-9_$]/.test(char)) return undefined;
    }
    current += char;
  }

  parts.push(current);
  if (parts.some((part) => part.trim() === '')) return undefined;
  return parts;
}

/** Strips `` ` ``, `"`, `'` or `[` `]` quoting from an identifier. */
function unquoteIdentifier(raw: string, what: string): string {
  const text = raw.trim();
  const pairs: Array<[string, string, string]> = [
    ['`', '`', '``'],
    ['"', '"', '""'],
    ["'", "'", "''"],
    ['[', ']', ']]'],
  ];

  for (const [open, close, escaped] of pairs) {
    if (text.length >= 2 && text.startsWith(open) && text.endsWith(close)) {
      const unescaped = text.slice(1, -1).split(escaped).join(close);
      if (unescaped.includes(close) || unescaped.trim() === '') {
        throw new ExtraClaimsConfigError(
          `CLAIMS_SQL_QUERY: cannot read the ${what} ${JSON.stringify(text)}`,
        );
      }
      return unescaped;
    }
  }

  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(text)) {
    throw new ExtraClaimsConfigError(
      `CLAIMS_SQL_QUERY: ${JSON.stringify(text)} is not a usable ${what}; `
      + 'quote it or use a plain name',
    );
  }
  return text;
}

// ------------------------------------------------------------- the lexer ---

const CODE = 0;
const QUOTED = 1;
const COMMENT = 2;

interface SqlMap {
  /** CODE / QUOTED / COMMENT, one entry per character. */
  kind: Int8Array;
  /** Parenthesis nesting at that character; 0 is the top level. */
  depth: Int32Array;
}

/**
 * Classifies every character of a SQL fragment as code, quoted run or comment,
 * and records the parenthesis depth. Everything else in this file is an index
 * lookup on top of this one pass — which is why there is no second, disagreeing
 * notion of "is this inside a string".
 */
function scan(text: string): SqlMap {
  const kind = new Int8Array(text.length);
  const depth = new Int32Array(text.length);
  let index = 0;
  let level = 0;

  const fill = (from: number, to: number, value: number): void => {
    for (let at = from; at < to; at += 1) {
      kind[at] = value;
      depth[at] = level;
    }
  };

  while (index < text.length) {
    const char = text[index]!;
    const next = text[index + 1];

    if ((char === '-' && next === '-') || char === '#' || (char === '/' && next === '*')) {
      const block = char === '/';
      let end: number;
      if (block) {
        const close = text.indexOf('*/', index + 2);
        end = close === -1 ? text.length : close + 2;
      } else {
        const newline = text.indexOf('\n', index);
        end = newline === -1 ? text.length : newline + 1;
      }
      fill(index, end, COMMENT);
      index = end;
      continue;
    }

    if (char === "'" || char === '"' || char === '`' || char === '[') {
      const close = char === '[' ? ']' : char;
      const backslashEscapes = char === "'" || char === '"';
      let at = index + 1;
      let end = text.length;
      while (at < text.length) {
        const inner = text[at]!;
        if (backslashEscapes && inner === '\\') {
          at += 2;
          continue;
        }
        if (inner === close) {
          if (text[at + 1] === close) {
            at += 2;
            continue;
          }
          end = at + 1;
          break;
        }
        at += 1;
      }
      fill(index, end, QUOTED);
      index = end;
      continue;
    }

    if (char === '(') {
      depth[index] = level;
      kind[index] = CODE;
      level += 1;
    } else if (char === ')') {
      level -= 1;
      depth[index] = level;
      kind[index] = CODE;
    } else {
      depth[index] = level;
      kind[index] = CODE;
    }
    index += 1;
  }

  return { kind, depth };
}

/** True when `keyword` sits at exactly `at`, as a whole word. */
function isKeywordAt(text: string, at: number, keyword: string): boolean {
  if (text.slice(at, at + keyword.length).toLowerCase() !== keyword) return false;
  const before = at > 0 ? text[at - 1] : undefined;
  const after = text[at + keyword.length];
  if (before !== undefined && /[A-Za-z0-9_$]/.test(before)) return false;
  if (after !== undefined && /[A-Za-z0-9_$]/.test(after)) return false;
  return true;
}

/** Index just past `keyword` when it opens the text (blanks skipped); -1 otherwise. */
function keywordEndAt(text: string, from: number, keyword: string): number {
  let index = from;
  while (index < text.length && /\s/.test(text[index]!)) index += 1;
  return isKeywordAt(text, index, keyword) ? index + keyword.length : -1;
}

/** Where the SELECT list ends: the first top-level FROM, or the end of the text. */
function endOfSelectList(sql: string, map: SqlMap, from: number): number {
  for (let index = from; index < sql.length; index += 1) {
    if (map.kind[index] !== CODE || map.depth[index] !== 0) continue;
    if (isKeywordAt(sql, index, 'from')) return index;
  }
  return sql.length;
}

/** Splits on commas that are not inside parentheses, a quoted run or a comment. */
function splitTopLevel(list: string): string[] {
  const map = scan(list);
  const items: string[] = [];
  let start = 0;

  for (let index = 0; index < list.length; index += 1) {
    if (map.kind[index] === CODE && map.depth[index] === 0 && list[index] === ',') {
      items.push(list.slice(start, index));
      start = index + 1;
    }
  }
  items.push(list.slice(start));
  return items;
}

/**
 * The same text with every comment blanked out. Blanked, not deleted: deleting
 * the characters would glue an expression onto its own `AS` when a comment sits
 * between the two, leaving an item with no alias at all.
 */
function stripComments(text: string): string {
  const map = scan(text);
  let out = '';
  for (let index = 0; index < text.length; index += 1) {
    out += map.kind[index] === COMMENT ? ' ' : text[index];
  }
  return out;
}

function stripTrailingSemicolon(sql: string): string {
  return sql.endsWith(';') ? sql.slice(0, -1).trim() : sql;
}

function truncate(text: string, max = 60): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}
