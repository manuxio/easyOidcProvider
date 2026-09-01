# easyOidcProvider

[![CI](https://github.com/manuxio/easyOidcProvider/actions/workflows/ci.yml/badge.svg)](https://github.com/manuxio/easyOidcProvider/actions/workflows/ci.yml)
[![CodeQL](https://github.com/manuxio/easyOidcProvider/actions/workflows/codeql.yml/badge.svg)](https://github.com/manuxio/easyOidcProvider/actions/workflows/codeql.yml)
[![Docker image](https://github.com/manuxio/easyOidcProvider/actions/workflows/docker.yml/badge.svg)](https://github.com/manuxio/easyOidcProvider/actions/workflows/docker.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A batteries-included **OAuth2 / OpenID Connect authorization server** for
organizations that live on Active Directory, LDAP, or a plain user database —
built on the certified [`oidc-provider`](https://github.com/panva/node-oidc-provider)
core, with the enterprise plumbing already done:

- **Silent Kerberos SSO**: a domain-joined browser signs in with zero clicks
  (SPNEGO/Negotiate), with an LDAP password form as the out-of-domain fallback.
- **Database logins**: no AD? Verify credentials against your own SQL database
  (MySQL/MariaDB, SQL Server) or MongoDB — bcrypt, argon2id, scrypt, PBKDF2 and
  legacy digest hashes all understood.
- **Optional TOTP second factor** on the password form, seeds read from SQL,
  LDAP or Mongo. The Kerberos path is never asked for a code — a domain machine
  has already proven possession.
- **Tokens your API can trust offline**: RS256 JWT access tokens (one `aud` for
  your whole back end) verified via `/jwks`, or opaque tokens if you prefer.
- **Claims from your business database**: enrich every token with the user's
  identity in your back-office system, through one SQL query you control.
- **Fail closed, everywhere**: an unreachable directory or database is a
  rejection — at login *and at every refresh* — never a pass.

Everything is configured through environment variables, validated eagerly at
startup (a misconfigured server refuses to boot and names the offending
parameter), and shipped as a small multi-arch Docker image with **no secrets
baked in**.

---

## Quick start (5 minutes, no infrastructure)

```sh
docker run --rm -p 3000:3000 \
  -e ISSUER_URL=http://localhost:3000 \
  -e IDENTITY_PROVIDER=dev-stub \
  -e 'DEV_STUB_USERS=[{"username":"mario.rossi","password":"Password1!","active":true}]' \
  -e 'CLIENTS_JSON=[{"client_id":"my-app","redirect_uris":["http://127.0.0.1/callback"]}]' \
  ghcr.io/manuxio/easyoidcprovider:edge
```

Then check the discovery document:

```sh
curl -s http://localhost:3000/.well-known/openid-configuration | jq .issuer
```

Any standard OIDC client library can now run the full authorization-code +
PKCE flow against it. `docker-compose.prod-like.yml` shows a realistic
production-shaped deployment (MongoDB state, TLS proxy in front), and `lab/`
contains a **complete Kerberos laboratory** — a Samba Active Directory domain
controller, a domain-joined client and the server, all in containers — to try
real SPNEGO SSO on a laptop.

## Identity providers

Chosen with `IDENTITY_PROVIDER`. One server instance runs one provider.

| Provider | Who it is for | Doors |
| --- | --- | --- |
| `spnego` | Active Directory shops | Silent Kerberos SSO + LDAP password form fallback |
| `database` | No AD: users live in your own database | Password form only |
| `dev-stub` | Development and CI | Password form only, fixed users |

### `spnego` — Kerberos/Active Directory SSO

The browser on a domain-joined machine authenticates silently via
SPNEGO/Negotiate; everyone else gets a password form verified with an LDAP
simple bind. Account liveness (disabled flag, expiry) is re-checked against
the directory **at every token refresh**, so disabling a user in AD cuts their
access at the next refresh, not at the next login. Optional: restrict access
to one AD group (`LDAP_REQUIRED_GROUP`).

Needs: a service keytab (`KRB5_KTNAME`), the realm, and an LDAP service bind.
The `lab/` environment provisions all of it for local testing, and the
`.env.example` documents every parameter including the classic traps (SPN
naming, CNAME vs A records, clock skew).

### `database` — credentials in your own database

Username and password verified against a customer database, for deployments
with no Active Directory at all:

- **Sources**: SQL (`AUTH_DB_SOURCE=sql` — MySQL/MariaDB or SQL Server, one
  customer-written query that is also the activation policy) or MongoDB
  (`AUTH_DB_SOURCE=mongo` — your user collection, field names configurable).
- **Password schemes** (`AUTH_PASSWORD_SCHEME`): `bcrypt`, `argon2id`,
  `scrypt`, `pbkdf2` (Django style) are recognized automatically from the
  stored hash; legacy `sha256`/`sha1`/`md5` (optionally salted) and `plain`
  must be declared explicitly — and `plain` warns loudly at startup.
- **Anti-enumeration built in**: an unknown username burns the same
  verification work as a wrong password and gets the same answer.
- Account liveness is re-checked through the same store at every refresh.

### `dev-stub` — fixed users for development

Users and passwords from an environment variable, an `active` flag to
exercise refresh-time revocation in tests. Never for production.

## The token model

- **Authorization code + PKCE (S256), enforced.** Public clients cannot opt
  out. Loopback redirect URIs follow RFC 8252: register
  `http://127.0.0.1/callback` once, listen on any free port.
- **ID tokens** are RS256 JWTs carrying `sub` (the lowercased username),
  `preferred_username`, `realm`, `auth_time` — plus your custom claims.
- **Access tokens** are opaque by default. Set `API_AUDIENCE` and they become
  RS256 JWTs with that audience, verifiable **offline** by any resource server
  through `GET /jwks` — no introspection round-trip on every request.
- **Refresh tokens** with rotation, TTLs configurable; every refresh re-runs
  the account gates (directory liveness, group check, claims).

## Optional gates and claims

All independent switches; they share one database connection pool when more
than one is on.

- **SQL group check** (`SQL_GROUP_CHECK_ENABLED`): a second authorization gate
  against a non-AD database — one bound-parameter query; a row means
  authorized. Runs at login and refresh, fails closed.
- **Extra token claims** (`CLAIMS_SQL_ENABLED`): one SQL query returning
  exactly one row; its column aliases become claim names in every ID token
  (and JWT access token). NULL omits the claim; a reserved or undeclared
  column name is a loud refusal, never a silently dropped claim.
- **TOTP second factor** (`TWO_FACTOR_ENABLED`): RFC 6238, 6 digits, ±1 step,
  replay-protected. Seeds are only ever **read** — from SQL, an LDAP
  attribute, or the Mongo credential document; enrolment stays where your
  users already live. Form path only, by design.
- **Login rate limiting**: per-username cool-down on failed form attempts,
  on by default.

## Hardening that is already done for you

- Fail-closed discipline on every remote dependency, with distinct, stable
  log reasons (`temporarily_unavailable` is never confused with
  `invalid_credentials`).
- The SQL pool has **transport-level retry** (one retry on a fresh pool,
  within the login deadline) and an optional **keepalive probe** that logs
  path failures with timestamps instead of surfacing them as rejected logins
  — stateful firewalls that silently drop idle flows are a fact of life.
- Bound parameters everywhere: customer-written queries take exactly one
  placeholder and the username is always bound, never interpolated.
- The login page never reveals whether the username exists, which factor
  failed, or whether an account is disabled (that is only said *after* a
  correct password).
- No secrets in the image; startup validation refuses ambiguous configuration;
  security headers and strict body parsing on the interaction endpoints.

## Deploying

The published image is `ghcr.io/manuxio/easyoidcprovider` (multi-arch:
amd64/arm64). It runs as a non-root user, `node` is PID 1, and `/health`
reports readiness (including MongoDB reachability when configured).

- **State**: point `MONGO_URL` at a MongoDB and signing keys, sessions and
  grants survive restarts. Without it, state lives in `DATA_DIR`/memory —
  development only.
- **TLS**: terminate in front (nginx, an ingress). Set `TRUST_PROXY=true`.
  For Kerberos deployments, raise the request-header buffers on your proxy
  (`large_client_header_buffers 4 32k;` in nginx): a domain user with many
  groups carries an 8–16 KB ticket in one header, and the default answers
  that with a bare 400.
- **Single instance**: the TOTP replay table and the rate limiter are
  in-process. Run one replica (or shard by username at your proxy) until you
  externalize them.

The complete, commented configuration reference is
[`.env.example`](.env.example) — it is the single source of truth for every
parameter.

## Development

```sh
npm ci
npm run typecheck   # sources + tests
npm test            # unit + full OIDC e2e flows (250 tests)
npm run dev         # tsx watch mode
```

The e2e suites drive the real HTTP endpoints with a real OIDC client library
(`openid-client`), including the PKCE exchange, refresh rotation, 2FA and the
claims pipeline. Integration suites against real MySQL/SQL Server/AD are
gated behind env flags (`AUTH_SQL_IT=1`, …) so `npm test` stays green on any
machine; the `lab/` README explains how to bring the real thing up.

Heads-up: the login form currently ships in **Italian** (it was born in an
Italian deployment). The messages live in `src/views/login.ts` — translations
and an i18n pass are welcome PRs.

## License

[MIT](LICENSE)
