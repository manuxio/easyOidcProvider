# Production image for the authorization server.
# Multi-stage build: compile with the dev toolchain, run on a minimal image.
#
#   docker build -t easyoidc/auth-server:latest applications/auth-server
#
# The build context is this folder alone: the application is standalone, it has
# no `@predictive/*` dependency and its own package-lock.json lives here.
#
# NOTHING SECRET IS BAKED IN. The keytab, /etc/krb5.conf, the LDAP bind
# password and the whole environment are mounted or injected at run time; see
# docker-compose.prod-like.yml and the "Deploy" section of README.md.

##############################################################################
# Stage 1 — build
#
# The full dependency tree (devDependencies included, tsc lives there), the
# TypeScript compile, and then a prune back to production dependencies. Any
# compiler, header file or npm cache dies with this stage.
##############################################################################
FROM node:26-bookworm-slim AS build

WORKDIR /app

# The lockfile is the contract: `npm ci` installs exactly what it says or fails.
# Copied on its own so an edit to src/ does not re-run the install layer.
#
# The native `kerberos` module resolves here: its install script is
# `prebuild-install --runtime napi || node-gyp rebuild`. The prebuilt N-API
# binary is what normally lands, which is why no compiler and no krb5 headers
# are installed above. If a future version stops publishing prebuilds, this is
# the stage where `build-essential` + `libkrb5-dev` belong — and only here,
# because the final stage copies node_modules and nothing else.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Drop devDependencies from the tree the runtime stage is about to inherit,
# then strip what a running process never reads: the dependencies' own source
# maps and type declarations (~22 MB, most of it the Azure AD stack that the
# `mssql` driver pulls in). Our own dist/*.js.map is left alone — that one is
# what makes a production stack trace readable.
RUN npm prune --omit=dev \
 && find node_modules \( -name '*.js.map' -o -name '*.d.ts' -o -name '*.d.mts' \) -type f -delete

##############################################################################
# Stage 2 — runtime
#
# Debian slim plus the Node binary and the runtime halves of GSSAPI. Not
# `node:22-slim`, which would drag npm, npx, corepack and the C++ headers
# (~25 MB) into an image that only ever runs `node dist/server.js`.
##############################################################################
FROM debian:stable-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# libgssapi-krb5-2 / libkrb5-3: the shared libraries the prebuilt `kerberos`
# addon links against. Without them the module loads fine until the first
# SPNEGO handshake and then fails there, which is the worst possible place to
# find out. ca-certificates: LDAPS and any outbound TLS.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libgssapi-krb5-2 \
        libkrb5-3 \
        ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 10001 authsrv; \
    useradd --system --uid 10001 --gid authsrv \
        --home-dir /app --shell /usr/sbin/nologin authsrv

# The Node runtime, and only that.
COPY --from=build /usr/local/bin/node /usr/local/bin/node

WORKDIR /app

# Owned by root, readable by everyone: the process user must not be able to
# rewrite its own code.
COPY --from=build --chown=root:root /app/node_modules ./node_modules
COPY --from=build --chown=root:root /app/dist ./dist
COPY --from=build --chown=root:root /app/package.json ./package.json

# DATA_DIR is the only path the process writes: the RS256 signing key and the
# cookie keys, when MONGO_URL is not configured. Mount a volume here (or point
# MONGO_URL at a database) or a restart invalidates every token in circulation.
RUN install -d -o authsrv -g authsrv -m 0700 /var/lib/auth-server

ENV NODE_ENV=production \
    DATA_DIR=/var/lib/auth-server \
    HOST=0.0.0.0 \
    PORT=3000

USER authsrv
EXPOSE 3000

# `/health` also pings Mongo when Mongo is configured, so a database the server
# cannot reach turns the container unhealthy instead of quietly failing later.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

# No init system and no npm in between: node is PID 1 and receives SIGTERM
# directly, which src/server.ts handles (graceful close, 10 s hard stop).
CMD ["node", "dist/server.js"]
