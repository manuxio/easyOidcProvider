# auth-server — Active Directory laboratory

A real Active Directory domain (KDC + LDAP + DNS) in Docker, so the auth-server's
Kerberos/SPNEGO work can be developed and tested without touching the customer's AD.

Built in two stages: first the domain,
then the auth-server container that runs inside it and the acceptance
script that drives the five SSO scenarios.

---

## What runs

| container | image | address | role |
|---|---|---|---|
| `auth-lab-dc` | `auth-lab/samba-dc` (built from `debian:stable-slim`, Samba 4.22) | `172.28.10.10` | domain controller: KDC `88`, LDAP `389`, LDAPS `636`, DNS `53`, SMB `445` |
| `auth-lab-client` | `auth-lab/krb-client` (built from `debian:stable-slim`) | `172.28.10.30` | test box: `kinit`, `kvno`, `klist`, `ldapsearch`, `curl`, `host`, `openssl` |
| `auth-lab-auth-server` | `auth-lab/auth-server-dev` (built from `node:22-bookworm-slim`) | `172.28.10.20` | the application under test, from `dev-server-compose.yml` — a separate compose project |

- Realm: **`LAB.EASYOIDC.LOCAL`** · NetBIOS domain: **`LAB`** · DNS zone: `lab.easyoidc.local`
- DC FQDN: `dc1.lab.easyoidc.local`
- Docker network `auth-lab`, subnet **`172.28.10.0/24`**, gateway `172.28.10.1`

The subnet is pinned on purpose. Docker's default address pool on this host
overlaps the production PBX network `172.19.132.0/24`; every compose network in
this project must declare a subnet inside `172.28.0.0/16`.

**Nothing is published to the host.** This machine is a production dialer with a
crowded port space, and rootless Docker cannot bind ports below 1024 on the host
anyway. Reach the lab from `auth-lab-client`, or attach your own container to the
`auth-lab` network.

### IP layout

| address | who |
|---|---|
| `172.28.10.1` | bridge gateway |
| `172.28.10.10` | `samba-dc` — also the DNS server of the lab network |
| `172.28.10.20` | the auth-server container (`dev-server-compose.yml`); published in DNS as `auth.lab.easyoidc.local`, which is the name inside the SPN |
| `172.28.10.30` | `krb-client` |
| `172.28.10.40` `.41` `.42` | the phase 5 production-like stack — nginx, the auth-server and its own test client (`../docker-compose.prod-like.yml`) |

---

## Accounts

Passwords are lab-only and deliberately in the clear. Domain policy is set to no
complexity requirement and no expiry, and every account is created `--noexpiry`.

| account | password | notes |
|---|---|---|
| `Administrator` | `Admin.Passw0rd!` | domain admin |
| `mario.rossi` | `Lab.Passw0rd!` | stays enabled; the happy-path user |
| `luigi.verdi` | `Lab.Passw0rd!` | the user phase 3 disables and re-enables (`samba-tool user disable/enable`) |
| `svc-auth` | `Svc.Passw0rd!` | auth-server service account, holds the SPN |

- SPN: `HTTP/auth.lab.easyoidc.local` on `svc-auth`
- Group: `easyoidc-users`, containing **only** `mario.rossi`
- Base DN: `DC=lab,DC=easyoidc,DC=local`
- Keytab: `secrets/auth.keytab` (gitignored), principal `HTTP/auth.lab.easyoidc.local@LAB.EASYOIDC.LOCAL`,
  with **AES256 and AES128 keys, no RC4**

The AES keys are not free: `samba-tool domain exportkeytab --principal=<SPN>`
only emits the enctypes `msDS-SupportedEncryptionTypes` allows, and that attribute
is unset on a freshly created account, which leaves RC4 (`arcfour-hmac`) as the
only exported key. `provision.sh` therefore sets it to `24`
(AES128-CTS-HMAC-SHA1-96 | AES256-CTS-HMAC-SHA1-96) on `svc-auth` before
exporting. Phase 8 of the plan asks the customer's AD administrator for exactly
the same thing on the real keytab.

Override any password before the first `provision.sh` by exporting
`LAB_ADMIN_PASSWORD`, `LAB_USER_PASSWORD`, `LAB_SVC_PASSWORD` (or putting them in
a local `lab/.env`, which is gitignored). Changing them after provisioning has no
effect: the domain database already exists.

---

## Use

```bash
cd applications/auth-server/lab

./provision.sh      # build + up + wait for health + create users/SPN/group/DNS/keytab (idempotent)
./verify.sh         # acceptance checks, all run from inside krb-client
docker compose down # stop; the domain survives in the named volumes
docker compose up -d
./reset.sh          # destroy the domain and the keytab, then rebuild from zero
```

`provision.sh` is safe to re-run: it reports `already present` for everything and
changes nothing.

### Hand checks

```bash
# Kerberos
docker compose exec krb-client bash -c \
  'printf "Lab.Passw0rd!\n" | kinit mario.rossi@LAB.EASYOIDC.LOCAL && klist'
docker compose exec krb-client kvno HTTP/auth.lab.easyoidc.local

# LDAPS (LDAPTLS_REQCERT=never is already in the container's environment:
# the DC serves the self-signed certificate Samba generated while provisioning)
docker compose exec krb-client ldapsearch -x -LLL \
  -H ldaps://dc1.lab.easyoidc.local \
  -D 'svc-auth@LAB.EASYOIDC.LOCAL' -w 'Svc.Passw0rd!' \
  -b 'DC=lab,DC=easyoidc,DC=local' \
  '(sAMAccountName=mario.rossi)' userAccountControl

# Keytab
docker compose exec krb-client klist -k /lab/secrets/auth.keytab

# Directory administration
docker compose exec samba-dc samba-tool user list
docker compose exec samba-dc samba-tool user disable luigi.verdi
docker compose exec samba-dc samba-tool user enable luigi.verdi
```

Plain `ldap://` **simple** binds are refused by the DC: Samba's
`ldap server require strong auth` defaults to `yes`. Use `ldaps://` (as
production will) or SASL/GSSAPI.

---

## The auth-server inside the lab (phase 3)

`dev-server-compose.yml` runs the application from the working tree, in a
container on the lab network, at `172.28.10.20` — the address the DNS record
`auth.lab.easyoidc.local` points at, which is the name inside the SPN.

**This is not a convenience, it is the only way.** Docker is rootless on this
host, so the host cannot route to `172.28.10.0/24`: a server started with
`npm run dev` on the host would be unreachable from `krb-client`, and would not
answer to the name in the SPN either.

```bash
cd applications/auth-server/lab

docker compose -f dev-server-compose.yml up -d --build   # start it
docker compose -f dev-server-compose.yml logs -f         # structured logs
docker compose -f dev-server-compose.yml restart         # after editing src/
docker compose -f dev-server-compose.yml down            # stop it (the domain stays up)
```

It is a **separate compose project** (`auth-lab-dev`) that joins `auth-lab` as an
external network, so bringing the server up and down never touches the DC.

| what | how |
|---|---|
| the code | `..` bind-mounted at `/app`, run with `tsx` — `node_modules` included, the host's prebuilt `kerberos` binary loads fine in this image |
| the keytab | `secrets/auth.keytab` mounted read-only at `/secrets/auth.keytab`, `KRB5_KTNAME` pointing at it |
| krb5 | `krb5.conf` mounted at `/etc/krb5.conf`; DNS is the DC, so the KDC is found through its SRV records |
| LDAP | `ldaps://dc1.lab.easyoidc.local`, service bind as `svc-auth@LAB.EASYOIDC.LOCAL` |
| TLS | `LDAP_TLS_INSECURE=true` — **lab only**, because Samba generated its own self-signed certificate. Production sets `LDAP_TLS_CA_FILE` instead, and the server logs a warning at every startup while the switch is on |
| storage | OIDC state in memory; the RS256 signing key persisted in the named volume `auth-lab-dev_auth-data`, so a restart does not invalidate live tokens |

The image (`dev-server/Dockerfile`) is `node:22-bookworm-slim` plus
`libgssapi-krb5-2`, `libkrb5-3` and `krb5-user`. No compiler and no krb5 headers:
the npm `kerberos` package ships a prebuilt binary, and only the runtime halves
of GSSAPI are missing from the base image. The production image is phase 5's job.

Clock skew matters: Kerberos rejects a difference above five minutes. Containers
inherit the host clock, so keep the host in NTP.

---

## The phase 3 acceptance run

```bash
./test-sso.sh
```

Six scenarios, all on the wire, all from inside the containers. The script
restores what it changes (`luigi.verdi` re-enabled, DC back up) even when a
check fails.

| # | scenario | what must happen |
|---|---|---|
| 1 | `kinit mario.rossi` + `curl --negotiate` through authorize → code → token | tokens, `sub=mario.rossi`, `realm=LAB.EASYOIDC.LOCAL` |
| 2 | `kdestroy` + the same request | `401` with `WWW-Authenticate: Negotiate` and the Italian form in the body |
| 2b | an NTLM type-1 message inside the `Negotiate` header | `401`, **no** `WWW-Authenticate` continuation, log `ntlm_not_supported` |
| 3 | the form with the right and the wrong domain password | tokens / Italian error and no tokens |
| 4 | `samba-tool user disable luigi.verdi` | login refused **and** an already-issued refresh token rejected with `invalid_grant`; log `account_disabled`, `revoked:true` |
| 5 | `samba-tool user enable luigi.verdi` | a fresh login works again, and the chain revoked in 4 stays dead |
| 6 | `docker stop auth-lab-dc` | refresh gets `temporarily_unavailable`, log says `fail closed`, `revoked:false`, and the same token works again once the DC is back |

`sso-flow.sh` is the piece that runs *inside* `krb-client`: one full OAuth2
exchange (PKCE included) driven by `curl`, printing a human transcript on stderr
and `KEY value` lines on stdout. It is fed to the container on stdin, so it needs
no mount:

```bash
docker exec -i -e MODE=sso auth-lab-client bash -s < sso-flow.sh
docker exec -i -e MODE=form -e FORM_USERNAME=mario.rossi -e FORM_PASSWORD='Lab.Passw0rd!' \
    auth-lab-client bash -s < sso-flow.sh
docker exec -i -e MODE=ntlm auth-lab-client bash -s < sso-flow.sh
docker exec -i -e MODE=refresh -e REFRESH_TOKEN=<token> auth-lab-client bash -s < sso-flow.sh
```

`AUTH_BASE` moves the whole exchange to another server and `CURL_OPTS` adds
arbitrary curl arguments to every request in it. That pair is how phase 5 runs
the same script through nginx over TLS, without touching the lab's DNS record:

```bash
docker exec -i -e MODE=sso \
    -e AUTH_BASE=https://auth.lab.easyoidc.local \
    -e CURL_OPTS='--resolve auth.lab.easyoidc.local:443:172.28.10.40 --cacert /lab/ca.crt' \
    auth-prod-like-client bash -s < sso-flow.sh
```

`MODE=sso` needs a ticket in the container first:

```bash
docker compose exec krb-client bash -c \
  'printf "Lab.Passw0rd!\n" | kinit mario.rossi@LAB.EASYOIDC.LOCAL'
```

### The group check, which is off by default

`LDAP_REQUIRED_GROUP` is implemented and disabled. To watch it work, start the
server with the lab group and try both users — `mario.rossi` is a member,
`luigi.verdi` is not:

```bash
LAB_REQUIRED_GROUP='CN=easyoidc-users,CN=Users,DC=lab,DC=easyoidc,DC=local' \
  docker compose -f dev-server-compose.yml up -d
# mario.rossi -> tokens; luigi.verdi -> 401, log reason "group_not_allowed"
docker compose -f dev-server-compose.yml up -d      # back to no group requirement
```

---

## The TOTP seed fixture (phase 4-bis)

`mario.rossi` carries a **TOTP seed in the `pager` attribute** of his directory
record:

```
pager: JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
```

It is a permanent lab fixture — leave it there. It exists so
`TWO_FACTOR_SOURCE=ldap` can be exercised against a real directory.

**Why `pager`:** it is a single-valued text attribute that already exists in the
Active Directory schema, that this lab uses for nothing, and that accepts base32
letters. Storing the seed there needs **no schema change**, which is the point —
a lab that redefines the schema stops resembling the customer's AD. In production
the administrator picks their own unused attribute and names it in
`TWO_FACTOR_LDAP_ATTRIBUTE`; nothing in the code knows about `pager`.

`luigi.verdi` deliberately has **no** seed: he is the "not enrolled" case, which
must be refused (log `two_factor_not_enrolled`) rather than let through.

To set or change it:

```bash
docker exec -i auth-lab-dc bash -c 'cat > /tmp/seed.ldif <<EOF
dn: CN=mario.rossi,CN=Users,DC=lab,DC=easyoidc,DC=local
changetype: modify
replace: pager
pager: JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
EOF
ldbmodify -H /var/lib/samba/private/sam.ldb /tmp/seed.ldif'

docker exec auth-lab-dc samba-tool user show mario.rossi | grep -i pager
```

The seed must be at least 128 bits of base32 (26 characters); the one above is
160 bits, the size RFC 4226 recommends.

To run the server with the second factor on, merge an override on top of
`dev-server-compose.yml` — do not edit that file:

```yaml
# /tmp/two-factor-override.yml
services:
  auth-server:
    environment:
      TWO_FACTOR_ENABLED: "true"
      TWO_FACTOR_SOURCE: ldap
      TWO_FACTOR_LDAP_ATTRIBUTE: pager
```

```bash
docker compose -f dev-server-compose.yml -f /tmp/two-factor-override.yml up -d
```

The form then carries a `otp` field; the Kerberos SSO path is unchanged and
never asks for a code.

## How it is built

No public samba-dc image is used. `dc/Dockerfile` installs Debian's `samba`
packages and `dc/entrypoint.sh` runs `samba-tool domain provision` itself on
first boot, so every provisioning decision is visible in this directory.

Three container-specific details worth knowing, all of them paid for the hard way:

- **`samba-tool-ntvfs`** (`dc/samba-tool-ntvfs`) is samba-tool with one kwarg
  forced. Stock `samba-tool domain provision` writes the sysvol NT ACLs through
  the in-process smbd bindings, which end in `chown_if_needed()` and panic under
  rootless Docker:

  ```
  INTERNAL ERROR: Security context active token stack underflow!
  ```

  Reproduced identically on Samba 4.19 (Alpine) and 4.22 (Debian), so it is the
  environment, not the version. The wrapper passes `use_ntvfs=True` and
  `useeadb=True`, which writes those ACLs into `private/eadb.tdb` instead of
  going through smbd — and avoids `security.*` filesystem xattrs, which a user
  namespace refuses anyway. The lab never serves sysvol or applies GPOs, so this
  costs nothing here; it would not be acceptable on a DC that serves files.

- **`server services` and `dcerpc endpoint servers` are deleted from `smb.conf`
  on every boot.** The side effect of provisioning with `use_ntvfs` is that
  provision writes the old NTVFS-era lists, and neither survives on Samba 4.22:
  the NTVFS file server is called `smb` where only `s3fs` now exists
  (`Failed to start service 'smb' - NT_STATUS_INVALID_SYSTEM_SERVICE`, samba
  exits), and the endpoint list names `winreg`/`srvsvc`, which are no longer s4
  endpoint servers, so the whole `rpc` service fails
  (`Failed to find endpoint server 'winreg'`) and takes epmapper/135 and
  `samba-tool dns` down with it. Removing both lines puts samba back on its own
  AD DC defaults, which are correct.

- **`dns forwarder = 127.0.0.11`** sends everything outside `lab.easyoidc.local`
  back to Docker's resolver, so the lab client can still resolve ordinary names.

Do **not** add `interfaces` / `bind interfaces only` to `smb.conf`: they break the
file server in the same way. Samba binds `0.0.0.0:53` happily next to Docker's
`127.0.0.11:53` — the more specific bind still wins for the container's own lookups.

`samba_dnsupdate` logs `Connecting to DNS RPC server … failed` every few minutes.
It is harmless noise: the DC's own records are written into the zone at provision
time, and the container's resolver is Docker's, not the DC's.

State lives in two named volumes, `auth-lab_samba-lib` (`/var/lib/samba`: the
domain database, the keytabs, sysvol) and `auth-lab_samba-etc` (`/etc/samba`).
`docker compose down` keeps them; only `docker compose down -v` — i.e. `reset.sh`
— throws the domain away.

## Files

```
lab/
  docker-compose.yml        phase 2: the two services, the pinned subnet, the fixed IPs
  provision.sh              host side: up + wait + run provision-objects.sh (idempotent)
  verify.sh                 phase 2 acceptance checks, run from krb-client
  reset.sh                  down -v + provision from scratch
  krb5.conf                 Kerberos configuration for the lab realm (client and server)
  dc/Dockerfile             Samba AD DC image
  dc/entrypoint.sh          first-boot domain provisioning + smb.conf fix-ups + samba
  dc/samba-tool-ntvfs       samba-tool without the smbd ACL backend (see below)
  dc/provision-objects.sh   users, SPN, group, DNS record, keytab export
  client/Dockerfile         krb5 + ldap-utils + curl test box

  dev-server-compose.yml    phase 3: the auth-server on the lab network at .20
  dev-server/Dockerfile     node:22 + the krb5 runtime libraries; no code baked in
  sso-flow.sh               one OAuth2 exchange, run inside krb-client via stdin
  test-sso.sh               phase 3 acceptance: the six SSO scenarios

  secrets/                  exported keytab — gitignored
```
