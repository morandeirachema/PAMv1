#!/bin/sh
# PostgreSQL: configuration only.
#
# Deliberately NO cluster start, no psql and no role creation here. This runs
# inside debian-installer's chroot, where systemd is not running and Debian's
# policy-rc.d refuses service starts — so anything that needs a live cluster is
# fragile at best and silently skipped at worst. The role, the database and its
# password are created on FIRST BOOT (firstboot.sh), where systemd is real and
# where the password must be generated anyway so that no two appliances share one.
#
# Two deliberate choices, both least privilege:
#   - pamv1 connects as `pam`, which OWNS its database but is NOT a superuser.
#     The vault's KEK lives outside the database, so a database-only compromise
#     yields ciphertext — but since Phase 55 that same connection also carries the
#     cross-replica live-monitoring relay, so the role is worth more than it used
#     to be. Do not widen it.
#   - The listener stays on localhost. Nothing outside the VM speaks to Postgres.
set -eu

if [ ! -d /etc/postgresql ]; then
	echo "ERROR: /etc/postgresql is missing — the postgresql package did not install" >&2
	exit 1
fi
PGVER="$(ls /etc/postgresql | sort -V | tail -1)"
PGCONF="/etc/postgresql/${PGVER}/main"
[ -f "${PGCONF}/postgresql.conf" ] || { echo "ERROR: no cluster config at ${PGCONF}" >&2; exit 1; }

echo "postgresql ${PGVER}"

sed -i "s/^#\?listen_addresses.*/listen_addresses = 'localhost'/" "${PGCONF}/postgresql.conf"
sed -i "s/^#\?password_encryption.*/password_encryption = scram-sha-256/" "${PGCONF}/postgresql.conf"

# Replace the default host lines with an explicit localhost-only scram policy.
sed -i '/^host/d' "${PGCONF}/pg_hba.conf"
cat >> "${PGCONF}/pg_hba.conf" <<'EOF'
# pamv1 appliance: local TCP only, scram-sha-256. No remote access.
host    pam             pam             127.0.0.1/32            scram-sha-256
host    pam             pam             ::1/128                 scram-sha-256
EOF

systemctl enable postgresql
