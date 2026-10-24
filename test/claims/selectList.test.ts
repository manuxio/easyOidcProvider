/**
 * Phase 4-ter: the static analysis of CLAIMS_SQL_QUERY (src/claims/selectList.ts),
 * beyond the reference shapes already pinned in query.test.ts.
 *
 * The parser's own contract, from its header: split the SELECT list on
 * TOP-LEVEL commas, take an explicit `AS <alias>` or a bare (possibly
 * qualified) column reference, understand quoting and comments well enough not
 * to be fooled by them, and refuse everything else — "say so and stop, never
 * guess". Every case below is either something it must read correctly or
 * something it must refuse by name.
 */
import { describe, expect, it } from 'vitest';

import { ExtraClaimsConfigError, parseClaimNames } from '../../src/claims/index.js';

/** The parse failure, so a test can assert on its class and its message together. */
function failureOf(query: string): ExtraClaimsConfigError {
  try {
    parseClaimNames(query);
  } catch (error) {
    if (error instanceof ExtraClaimsConfigError) return error;
    throw error;
  }
  throw new Error(`the query was accepted: ${query}`);
}

describe('the statement around the SELECT list', () => {
  it('refuses an empty query, a blank one and a lone semicolon', () => {
    for (const query of ['', '   \n\t', ';', '  ;  ']) {
      expect(failureOf(query).message).toBe('CLAIMS_SQL_QUERY is empty');
    }
  });

  it('accepts one trailing semicolon and surrounding blanks', () => {
    expect(parseClaimNames('\n  SELECT a AS x FROM t WHERE u = ?;  \n')).toEqual(['x']);
  });

  it('reads the SELECT keyword whatever its case', () => {
    expect(parseClaimNames('select a as x from t where u = ?')).toEqual(['x']);
    expect(parseClaimNames('SeLeCt a As x FrOm t WhErE u = ?')).toEqual(['x']);
  });

  it('refuses a word that only starts like SELECT', () => {
    expect(failureOf('SELECTED a AS x FROM t WHERE u = ?').message)
      .toMatch(/must be a single SELECT statement/);
  });

  it('refuses a statement that is not a SELECT at all', () => {
    for (const query of [
      'UPDATE t SET a = 1 WHERE u = ?',
      'DELETE FROM t WHERE u = ?',
      'CALL claims_for(?)',
    ]) {
      expect(failureOf(query).message, query).toMatch(/must be a single SELECT statement/);
    }
  });

  it('refuses a comment before the SELECT keyword rather than reading past it', () => {
    // keywordEndAt skips blanks only: the statement must OPEN with SELECT.
    expect(failureOf('/* claims */ SELECT a AS x FROM t WHERE u = ?').message)
      .toMatch(/single SELECT statement/);
  });

  it('takes the whole text as the SELECT list when there is no FROM', () => {
    expect(parseClaimNames('SELECT ? AS login, 1 AS one')).toEqual(['login', 'one']);
  });
});

describe('where the SELECT list ends', () => {
  it('ignores a FROM inside a parenthesised subquery', () => {
    expect(parseClaimNames(
      'SELECT (SELECT MAX(id) FROM t2 WHERE t2.u = t.u) AS top, t.code FROM t WHERE t.u = ?',
    )).toEqual(['top', 'code']);
  });

  it('ignores a FROM inside a string literal', () => {
    expect(parseClaimNames("SELECT 'from here, and there' AS label FROM t WHERE u = ?"))
      .toEqual(['label']);
  });

  it('ignores a FROM inside a comment', () => {
    expect(parseClaimNames('SELECT a AS x /* taken from b */, c AS y FROM t WHERE u = ?'))
      .toEqual(['x', 'y']);
  });

  it('does not mistake a column that starts with "from" for the keyword', () => {
    expect(parseClaimNames('SELECT fromage, from_date AS since FROM t WHERE u = ?'))
      .toEqual(['fromage', 'since']);
  });
});

describe('splitting on top-level commas', () => {
  it('keeps the commas of a function call inside its item', () => {
    expect(parseClaimNames("SELECT CONCAT_WS(' ', a, b) AS full, IFNULL(c, 0) AS c FROM t WHERE u = ?"))
      .toEqual(['full', 'c']);
  });

  it('keeps a comma inside a double-quoted or backslash-escaped string', () => {
    expect(parseClaimNames(String.raw`SELECT "a,b" AS one, 'it\'s, ok' AS two FROM t WHERE u = ?`))
      .toEqual(['one', 'two']);
  });

  it('keeps a comma inside a doubled-quote string', () => {
    expect(parseClaimNames("SELECT 'it''s, fine' AS label, x FROM t WHERE u = ?"))
      .toEqual(['label', 'x']);
  });

  it('keeps the commas of a -- comment and of a # comment', () => {
    expect(parseClaimNames('SELECT a AS x, -- first, second\n b AS y # third, fourth\n FROM t WHERE u = ?'))
      .toEqual(['x', 'y']);
  });

  it('refuses an empty item between two commas, and a trailing comma', () => {
    expect(failureOf('SELECT a AS x, , b AS y FROM t WHERE u = ?').message)
      .toMatch(/has an empty select item 2/);
    expect(failureOf('SELECT a AS x, FROM t WHERE u = ?').message)
      .toMatch(/has an empty select item 2/);
  });

  it('refuses an item that is nothing but a comment', () => {
    expect(failureOf('SELECT a AS x, /* nothing */ FROM t WHERE u = ?').message)
      .toMatch(/empty select item 2/);
  });
});

describe('the alias', () => {
  it('takes the last top-level AS, ignoring an AS inside parentheses', () => {
    expect(parseClaimNames('SELECT CAST(a AS CHAR(10)) AS code FROM t WHERE u = ?')).toEqual(['code']);
  });

  it('ignores an AS inside a string', () => {
    expect(parseClaimNames("SELECT CONCAT('known as ', nick) AS nickname FROM t WHERE u = ?"))
      .toEqual(['nickname']);
  });

  it('reads an AS glued to its expression by a comment', () => {
    // Comments are blanked, not deleted: deleting would make `xAS`.
    expect(parseClaimNames('SELECT x/**/AS y FROM t WHERE u = ?')).toEqual(['y']);
  });

  it('does not see an AS inside a word', () => {
    expect(parseClaimNames('SELECT basket, alias_id FROM t WHERE u = ?')).toEqual(['basket', 'alias_id']);
  });

  it('unquotes a single-quoted alias and a bracketed one with a space', () => {
    expect(parseClaimNames("SELECT a AS 'label', b AS [full name] FROM t WHERE u = ?"))
      .toEqual(['label', 'full name']);
  });

  it('accepts $ and _ in a plain alias', () => {
    expect(parseClaimNames('SELECT a AS _private$1 FROM t WHERE u = ?')).toEqual(['_private$1']);
  });

  it('refuses an AS with nothing after it', () => {
    expect(failureOf('SELECT a AS FROM t WHERE u = ?').message)
      .toBe('CLAIMS_SQL_QUERY has an "AS" with no alias after it');
  });

  it('refuses an empty quoted alias', () => {
    expect(failureOf('SELECT a AS `` FROM t WHERE u = ?').message)
      .toMatch(/cannot read the alias "``"/);
    expect(failureOf('SELECT a AS "  " FROM t WHERE u = ?').message)
      .toMatch(/cannot read the alias/);
  });

  it('refuses an alias carrying an escaped quote character', () => {
    // NOTE: unquoteIdentifier undoubles `` → ` and then refuses any result that
    // still contains the closing quote, so a correctly escaped quote is refused
    // too and the undoubling never yields a usable name. Refusing is the safe
    // side (such a claim name is unusable anyway); recorded here as current
    // behaviour.
    expect(failureOf('SELECT a AS `we``ird` FROM t WHERE u = ?').message)
      .toMatch(/cannot read the alias/);
  });

  it('refuses an unquoted alias that is not a plain name', () => {
    expect(failureOf('SELECT a AS 1st FROM t WHERE u = ?').message)
      .toMatch(/"1st" is not a usable alias; quote it or use a plain name/);
    expect(failureOf('SELECT a AS my-claim FROM t WHERE u = ?').message)
      .toMatch(/"my-claim" is not a usable alias/);
  });
});

describe('a bare column reference', () => {
  it('takes the last part of a qualified or quoted reference', () => {
    expect(parseClaimNames('SELECT `u`.`nome`, db.t.code, [t].[x] FROM t WHERE u = ?'))
      .toEqual(['nome', 'code', 'x']);
  });

  it('refuses a dangling dot instead of naming an empty claim', () => {
    expect(failureOf('SELECT u. FROM t WHERE u = ?').message).toMatch(/Give it an explicit alias/);
  });

  it('refuses arithmetic, with or without spaces', () => {
    expect(failureOf('SELECT a + b FROM t WHERE u = ?').message).toMatch(/Give it an explicit alias/);
    expect(failureOf('SELECT a+b FROM t WHERE u = ?').message).toMatch(/Give it an explicit alias/);
  });

  it('refuses a numeric literal, which can never be a claim name', () => {
    expect(failureOf('SELECT 1 FROM t WHERE u = ?').message).toMatch(/"1" is not a usable column/);
  });

  it('refuses t.* exactly like *', () => {
    expect(failureOf('SELECT a AS x, t.* FROM t WHERE u = ?').message)
      .toMatch(/uses "t\.\*": the claim names cannot be known before the query runs/);
  });
});

describe('the declaration as a whole', () => {
  it('keeps the SELECT-list order and the case of each name', () => {
    expect(parseClaimNames('SELECT z AS Zeta, a AS alpha, m FROM t WHERE u = ?'))
      .toEqual(['Zeta', 'alpha', 'm']);
  });

  it('spots a duplicate between a bare column and an alias, case-insensitively, naming both items', () => {
    expect(failureOf('SELECT u.name, x AS NAME FROM t WHERE u = ?').message)
      .toBe('CLAIMS_SQL_QUERY produces the claim "NAME" twice (select items 1 and 2): a claim can only have one value');
  });

  it('refuses a reserved name reached through a bare column, naming the startup analysis', () => {
    expect(failureOf('SELECT u.sub FROM t WHERE u = ?').message)
      .toMatch(/"sub", which is reserved .*\[startup analysis of CLAIMS_SQL_QUERY\]/);
  });

  it('quotes a long unaliased item truncated in the message', () => {
    const long = `CONCAT(${'abcdefghij, '.repeat(8)}z)`;
    const message = failureOf(`SELECT ${long} FROM t WHERE u = ?`).message;
    expect(message).toContain('select item 1 (');
    expect(message).toContain('…');
    expect(message).not.toContain(long);
  });
});
