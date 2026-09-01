/**
 * Phase 4-ter, first half of the enforcement: everything that must be settled
 * at STARTUP, before a single token is ever minted.
 *
 * Two independent jobs are done here by the same parse of CLAIMS_SQL_QUERY:
 *
 *  - the reserved-name blacklist, which stops the server naming the claim;
 *  - the DECLARATION of the claim names, without which oidc-provider would drop
 *    them from the id token — see the comment at the top of selectList.ts.
 *
 * The customer's reference query is the fixture, verbatim, because it is the
 * one shape that has to keep working.
 */
import { describe, expect, it } from 'vitest';

import {
  buildExtraClaims,
  ExtraClaimsConfigError,
  parseClaimNames,
  RESERVED_CLAIM_NAMES,
} from '../../src/claims/index.js';
import { ConfigError, loadConfig, type Config } from '../../src/config.js';
import { createSilentLogger } from '../../src/logger.js';
import { CUSTOMER_CLAIMS_QUERY } from '../helpers/claimsQuery.js';
import { FakeSqlDriver } from '../helpers/fakeSqlDriver.js';

const BASE_ENV = {
  ISSUER_URL: 'http://127.0.0.1:3000',
  CLIENTS_JSON: '[{"client_id":"desktop-app","redirect_uris":["http://127.0.0.1/callback"]}]',
  DEV_STUB_USERS: '[{"username":"mario.rossi","password":"x","active":true}]',
  DATA_DIR: '',
};

function configWith(env: Record<string, string>): Config {
  return loadConfig({ ...BASE_ENV, ...env });
}

const ON = {
  CLAIMS_SQL_ENABLED: 'true',
  SQL_DRIVER: 'mysql',
  SQL_CONNECTION_STRING: 'mysql://user:pw@127.0.0.1:3306/backoffice',
  CLAIMS_SQL_QUERY: CUSTOMER_CLAIMS_QUERY,
};

const build = (query: string) =>
  buildExtraClaims(
    configWith({ ...ON, CLAIMS_SQL_QUERY: query }),
    createSilentLogger(),
    { sqlDriver: new FakeSqlDriver() },
  );

describe('the claim names are read out of the SELECT list', () => {
  it("reads the customer's own query", () => {
    expect(parseClaimNames(CUSTOMER_CLAIMS_QUERY)).toEqual(['remoteId', 'name']);
  });

  it('takes a bare column as its own claim, qualified or not', () => {
    expect(parseClaimNames('select u.id as remoteId, u.nome from users u where u.userid = ?'))
      .toEqual(['remoteId', 'nome']);
  });

  it('unquotes backticked, bracketed and double-quoted aliases', () => {
    expect(parseClaimNames('SELECT `ID` AS `remoteId`, b AS [name], c AS "surname" FROM t WHERE u = ?'))
      .toEqual(['remoteId', 'name', 'surname']);
  });

  it('is not fooled by a comma inside a string or a comment', () => {
    expect(parseClaimNames(
      "SELECT ID AS remoteId, 'x,y' AS label /* nota, con virgola */ FROM t WHERE u = ?",
    )).toEqual(['remoteId', 'label']);
  });

  it('refuses a * it could never name', () => {
    expect(() => parseClaimNames('SELECT * FROM users WHERE userid = ?'))
      .toThrow(/every column must be selected explicitly/);
  });

  it('refuses an unaliased expression instead of guessing a name for it', () => {
    expect(() => parseClaimNames('SELECT CONCAT(nome, cognome) FROM t WHERE userid = ?'))
      .toThrow(/Give it an explicit alias/);
  });

  it('refuses the alias-without-AS form, because "a + b" would become "b"', () => {
    expect(() => parseClaimNames('SELECT ID remoteId FROM t WHERE userid = ?'))
      .toThrow(ExtraClaimsConfigError);
  });

  it('refuses two select items that produce the same claim', () => {
    expect(() => parseClaimNames('SELECT a AS x, b AS X FROM t WHERE u = ?'))
      .toThrow(/twice/);
  });

  it('refuses anything that is not a plain SELECT', () => {
    expect(() => parseClaimNames('WITH c AS (SELECT 1) SELECT x FROM c WHERE u = ?'))
      .toThrow(/single SELECT statement/);
  });
});

describe('the reserved-name blacklist stops the server at startup', () => {
  for (const reserved of RESERVED_CLAIM_NAMES) {
    it(`refuses a column aliased ${reserved}, naming the claim`, () => {
      expect(() => build(`SELECT ID AS ${reserved} FROM users WHERE userid = ?`))
        .toThrow(new RegExp(`produces the claim "${reserved}", which is reserved`));
    });
  }

  it('refuses it whatever the case, so the catalogue stays readable', () => {
    expect(() => build('SELECT ID AS SUB FROM users WHERE userid = ?'))
      .toThrow(/reserved/);
  });

  it('allows `name`: it is a registered OIDC claim used in its own meaning', () => {
    const source = build("SELECT CONCAT_WS(' ', nome, cognome) AS name FROM t WHERE userid = ?");
    expect(source?.claimNames).toEqual(['name']);
  });
});

describe('the placeholder contract is the same as the other two queries', () => {
  it('accepts exactly one', () => {
    expect(build(CUSTOMER_CLAIMS_QUERY)?.claimNames).toEqual(['remoteId', 'name']);
  });

  it('refuses a query that does not bind the username, by parameter name', () => {
    expect(() => build('SELECT ID AS remoteId FROM users'))
      .toThrow(/CLAIMS_SQL_QUERY must contain exactly one/);
  });

  it('refuses two placeholders', () => {
    expect(() => build('SELECT ID AS remoteId FROM t WHERE a = ? OR b = ?'))
      .toThrow(/exactly one/);
  });
});

describe('the switch and the shared connection', () => {
  it('builds nothing at all when CLAIMS_SQL_ENABLED is absent', () => {
    const source = buildExtraClaims(configWith({}), createSilentLogger(), {});
    expect(source).toBeUndefined();
  });

  it('builds nothing when the switch is explicitly false, even with a query set', () => {
    const source = buildExtraClaims(
      configWith({ ...ON, CLAIMS_SQL_ENABLED: 'false' }),
      createSilentLogger(),
      { sqlDriver: new FakeSqlDriver() },
    );
    expect(source).toBeUndefined();
  });

  it('refuses to start without the query', () => {
    expect(() => configWith({ CLAIMS_SQL_ENABLED: 'true', SQL_CONNECTION_STRING: 'mysql://x/y' }))
      .toThrow(/CLAIMS_SQL_QUERY is required when CLAIMS_SQL_ENABLED=true/);
  });

  it('refuses to start without the shared connection string, naming it', () => {
    expect(() => configWith({ CLAIMS_SQL_ENABLED: 'true', CLAIMS_SQL_QUERY: CUSTOMER_CLAIMS_QUERY }))
      .toThrow(/SQL_CONNECTION_STRING is required when CLAIMS_SQL_ENABLED=true/);
  });

  it('needs the connection even with the group check and the second factor off', () => {
    const failure = (() => {
      try {
        configWith({ CLAIMS_SQL_ENABLED: 'true', CLAIMS_SQL_QUERY: CUSTOMER_CLAIMS_QUERY });
        return undefined;
      } catch (error) {
        return error as ConfigError;
      }
    })();
    expect(failure).toBeInstanceOf(ConfigError);
    expect(failure!.problems).toContain(
      'SQL_CONNECTION_STRING is required when CLAIMS_SQL_ENABLED=true',
    );
  });
});
