/**
 * Microsoft SQL Server driver, on `mssql` (tedious under it).
 *
 * The current customer runs MySQL; this driver exists because SQL Server is the
 * common case in the enterprise installations that come next, and writing it
 * now is what proves the driver seam is real rather than a MySQL wrapper with an
 * interface bolted on.
 *
 * Same discipline as the mysql driver: the library is imported lazily on the
 * first query, and the username is a named bind parameter (`@username`), never
 * part of the SQL text.
 */
import type { SqlDriver, SqlDriverOptions, SqlQueryParams, SqlRow } from './types.js';
import { SqlGroupCheckUnavailable } from './types.js';

/** mssql binds by name. The name is fixed: the query has one parameter. */
export const MSSQL_PLACEHOLDER = '@username';

/** The parameter name without the sigil, as `request.input()` wants it. */
const MSSQL_PARAM_NAME = 'username';

interface MssqlRequest {
  input(name: string, value: unknown): MssqlRequest;
  query(sql: string): Promise<{ recordset?: unknown }>;
}

interface MssqlPool {
  connect(): Promise<unknown>;
  request(): MssqlRequest;
  close(): Promise<unknown>;
}

export function createMssqlDriver(options: SqlDriverOptions): SqlDriver {
  let pool: Promise<MssqlPool> | undefined;

  async function getPool(): Promise<MssqlPool> {
    if (!pool) {
      pool = (async () => {
        const mssql = await import('mssql');
        // `mssql` accepts either a URL (mssql://user:pass@host/db) or the
        // classic ADO string (Server=…;Database=…;User Id=…;Password=…).
        const created = new mssql.ConnectionPool(
          options.connectionString,
        ) as unknown as MssqlPool;
        await created.connect();
        return created;
      })().catch((error: unknown) => {
        pool = undefined;
        throw new SqlGroupCheckUnavailable(
          'mssql',
          `mssql pool could not be created: ${errorMessage(error)}`,
          error,
        );
      });
    }
    return pool;
  }

  return {
    name: 'mssql',
    placeholder: MSSQL_PLACEHOLDER,

    async query(sql: string, params: SqlQueryParams): Promise<SqlRow[]> {
      const connectionPool = await getPool();
      try {
        const result = await connectionPool
          .request()
          .input(MSSQL_PARAM_NAME, params.username)
          .query(sql);
        return normalizeRows(result?.recordset);
      } catch (error) {
        throw new SqlGroupCheckUnavailable(
          'mssql',
          `mssql query failed: ${errorMessage(error)}`,
          error,
        );
      }
    },

    async close(): Promise<void> {
      const pending = pool;
      pool = undefined;
      if (!pending) return;
      await pending.then((p) => p.close()).catch(() => undefined);
    },
  };
}

/** No recordset means the query was not a SELECT: configuration, not an answer. */
function normalizeRows(recordset: unknown): SqlRow[] {
  if (Array.isArray(recordset)) return recordset as SqlRow[];
  throw new SqlGroupCheckUnavailable(
    'mssql',
    'SQL_GROUP_QUERY returned no recordset: it must be a SELECT',
  );
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    const code = (error as NodeJS.ErrnoException).code;
    return code ? `${code} ${error.message}` : error.message;
  }
  return String(error);
}
