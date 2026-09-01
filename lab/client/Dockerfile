# Kerberos/LDAP test client for the auth-server laboratory.
#
# Everything the acceptance checks need lives here, so the host machine stays
# untouched: no krb5-workstation, no ldap-utils, no keytab on the host PATH.
FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    echo "krb5-config krb5-config/default_realm string LAB.EASYOIDC.LOCAL" | debconf-set-selections; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        krb5-user \
        ldap-utils \
        curl \
        dnsutils \
        iputils-ping \
        ca-certificates; \
    rm -rf /var/lib/apt/lists/*

# krb5.conf is bind-mounted from ../krb5.conf by docker-compose.yml.
CMD ["sleep", "infinity"]
