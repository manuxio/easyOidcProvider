# Samba Active Directory Domain Controller for the auth-server laboratory.
#
# Built from a plain Debian base instead of a third-party samba-dc image so that
# the provisioning steps stay visible and reproducible: the entrypoint runs
# `samba-tool domain provision` itself on first boot.
#
# On Debian 13 the `samba` package alone is NOT enough for a domain controller:
# the `samba` daemon binary, `samba-tool` and the provisioning templates live in
# samba-ad-dc / python3-samba / samba-ad-provision.
FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive

# krb5-config would otherwise stop on a debconf question about the default realm.
RUN set -eux; \
    echo "krb5-config krb5-config/default_realm string LAB.EASYOIDC.LOCAL" | debconf-set-selections; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        samba \
        samba-ad-dc \
        samba-ad-provision \
        samba-dsdb-modules \
        samba-vfs-modules \
        python3-samba \
        python3-dnspython \
        smbclient \
        winbind \
        ldb-tools \
        ldap-utils \
        krb5-user \
        krb5-config \
        dnsutils \
        iproute2 \
        procps \
        ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    rm -f /etc/samba/smb.conf

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY samba-tool-ntvfs /usr/local/bin/samba-tool-ntvfs
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/samba-tool-ntvfs

# 53 DNS, 88 Kerberos, 135/139/445 SMB+RPC, 389 LDAP, 464 kpasswd, 636 LDAPS,
# 3268/3269 global catalog. Nothing is published to the host by the compose file.
EXPOSE 53/tcp 53/udp 88/tcp 88/udp 389/tcp 445/tcp 464/tcp 636/tcp 3268/tcp 3269/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
