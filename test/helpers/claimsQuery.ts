/**
 * The customer's reference claims query, flattened to the single line it will
 * occupy in the env file.
 *
 * It lives in the tests (and in the docs) and NOWHERE in src/: the whole point
 * of phase 4-ter is that the code knows nothing about `users`, `ID`,
 * `nome` or `cognome` — only that whatever the SELECT list is called becomes a
 * claim.
 */
export const CUSTOMER_CLAIMS_QUERY =
  "SELECT ID AS remoteId, CONCAT_WS(' ', CONCAT(UPPER(LEFT(nome,1)),LOWER(SUBSTRING(nome,2))), "
  + "CONCAT(UPPER(LEFT(cognome,1)),LOWER(SUBSTRING(cognome,2)))) AS name FROM users WHERE userid = ?";

/** The claim names that query declares, in SELECT-list order. */
export const CUSTOMER_CLAIM_NAMES = ['remoteId', 'name'] as const;
