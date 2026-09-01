# Development image for running the auth-server INSIDE the laboratory network.
#
# Why a container at all, when the app runs happily on the host: Docker is
# rootless on this machine, so the host cannot reach 172.28.10.0/24. The
# Kerberos SPN is HTTP/auth.lab.easyoidc.local and DNS points that name at
# 172.28.10.20, which only exists inside the lab network — so the server under
# test has to live there too.
#
# The image carries no application code. `src/` and `node_modules/` are
# bind-mounted from the repository and run with tsx, so an edit is one
# `docker compose restart` away. The production image is phase 5's job.
FROM node:22-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Runtime halves of the native `kerberos` module (GSSAPI/krb5). The npm package
# ships a prebuilt binary, so no compiler and no krb5 headers are needed here;
# phase 5's multi-stage build is where a from-source build would belong.
# krb5-user is only for klist/kvno while diagnosing inside this container.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libgssapi-krb5-2 \
        libkrb5-3 \
        krb5-user \
        ca-certificates; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# tsx from the bind-mounted node_modules; nothing is installed into the image.
CMD ["node", "node_modules/tsx/dist/cli.mjs", "src/server.ts"]
