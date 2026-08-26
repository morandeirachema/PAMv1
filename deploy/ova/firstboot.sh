#!/bin/sh
# pamv1 appliance — first boot.
#
# Runs once, before pamv1.service, as root. It creates everything that must be
# unique to THIS copy of the appliance:
#
#   1. the vault master key (KEK)      — one per appliance, or every clone shares a vault
#   2. the bootstrap admin API key     — also the SSH/DB proxy password
#   3. the PostgreSQL role password    — never leaves the box
#   4. SSH host keys                   — the build deletes them; clones must not share them
#   5. the machine id                  — cleared by the build so systemd regenerates it
#
# It is idempotent: if the env file already exists it does nothing, so a reboot
# never rotates a running appliance's keys out from under it.
set -eu

ENV_FILE=/etc/pamv1/pamv1.env
CRED_FILE=/root/pamv1-credentials.txt

if [ -s "$ENV_FILE" ]; then
	echo "pamv1: already initialised; nothing to do."
	exit 0
fi

echo "pamv1: first boot — generating this appliance's keys."

# --- 4. SSH host keys (the build removed them) -------------------------------
if [ -z "$(ls -A /etc/ssh/ssh_host_*_key 2>/dev/null || true)" ]; then
	ssh-keygen -A
	systemctl restart ssh || true
fi

# --- 1/2/3. pamv1 + database secrets ----------------------------------------
MASTER_KEY="$(/usr/local/bin/pam-server -genkey)"
# 32 urlsafe-base64 bytes: comfortably past the 16-character floor pamv1 enforces
# against a real database.
API_KEY="pamk_$(head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')"
DB_PASS="$(head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')"

systemctl start postgresql
# Wait for the cluster: on a cold clone this is the slowest thing on the box.
ready=0
for _ in $(seq 1 90); do
	if su - postgres -c "psql -tAc 'SELECT 1'" >/dev/null 2>&1; then ready=1; break; fi
	sleep 1
done
[ "$ready" = 1 ] || { echo "pamv1: PostgreSQL did not become ready; not writing a config that cannot work." >&2; exit 1; }

# The role and database are created HERE, not at build time: the installer chroot
# has no running systemd, and the password has to be generated per appliance
# anyway. Idempotent, so a re-run after a half-finished first boot is safe.
su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='pam'\"" | grep -q 1 || \
	su - postgres -c "psql -qc \"CREATE ROLE pam LOGIN\"" >/dev/null
su - postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='pam'\"" | grep -q 1 || \
	su - postgres -c "createdb -O pam pam"
su - postgres -c "psql -qc \"ALTER ROLE pam PASSWORD '${DB_PASS}'\"" >/dev/null

umask 027
cat > "$ENV_FILE" <<EOF
# Generated on first boot by pamv1-firstboot. Unique to this appliance.
#
# Every other knob pamv1 reads is documented in
#   /opt/pamv1/src/deploy/docker/.env.example
# and its Kubernetes twin under /opt/pamv1/src/deploy/k8s/. Add what you need
# below, then: systemctl restart pamv1
PAM_MASTER_KEY=${MASTER_KEY}
PAM_API_KEY=${API_KEY}
PAM_DATABASE_URL=postgres://pam:${DB_PASS}@127.0.0.1:5432/pam?sslmode=disable
PAM_LISTEN_ADDR=:8080
PAM_SSH_ADDR=:2222
PAM_RECORDING_DIR=/var/lib/pamv1/recordings
PAM_SSH_HOST_KEY=/var/lib/pamv1/ssh_host_key
PAM_LOG_FORMAT=json
PAM_LOG_LEVEL=info
EOF
chown root:pamv1 "$ENV_FILE"
chmod 0640 "$ENV_FILE"

cat > "$CRED_FILE" <<EOF
pamv1 appliance — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)

  Portal / REST API : http://<this-vm>:8080
  SSH session proxy : <this-vm>:2222
  Admin API key     : ${API_KEY}

Use the admin key as the "access token" on the portal Sign On screen (leave
Password blank), as the X-API-Key header on the REST API, and as the SSH password
when connecting through the proxy:

  ssh -p 2222 <credential-user>@<target-name>@<this-vm>

It is a root-equivalent credential for this appliance. Rotate it by editing
PAM_API_KEY in /etc/pamv1/pamv1.env and restarting pamv1, then DELETE this file:

  shred -u ${CRED_FILE}

The vault master key is in /etc/pamv1/pamv1.env. If you lose it, every vaulted
secret is unrecoverable — back it up somewhere other than this disk. In a real
deployment, point PAM_KEK_PROVIDER at a KMS or HSM instead so the wrapping key
never lives on the appliance at all.
EOF
chmod 0600 "$CRED_FILE"

# Also put it where a console operator will actually see it.
cat > /etc/motd <<EOF

  pamv1 appliance. Admin API key (also in ${CRED_FILE}):

      ${API_KEY}

  Portal: http://\$(hostname -I | awk '{print \$1}'):8080
  Docs and full source: /opt/pamv1/src   ·   Service: systemctl status pamv1

EOF

echo "pamv1: initialised. Admin API key: ${API_KEY}"
