#!/bin/sh
# Runs inside the target system during the installer's late_command, in order.
#
# Any failure aborts the build: a half-provisioned appliance that boots and looks
# fine is worse than one that never gets packaged.
#
# Everything that needs a shell — redirection, pipes, globbing — belongs HERE
# rather than in the preseed's late_command, where quoting failures are silent.
set -eu

cd "$(dirname "$0")"
LOG=/var/log/pamv1-provision.log

# Beacon: the build host serves the payload over HTTP, so a GET is a progress
# report that lands in ITS access log — the only channel out of the installer
# chroot that does not depend on the guest filesystem we cannot yet read. Purely
# diagnostic and always best-effort: outside a build there is nothing listening.
BEACON="${PAMV1_BEACON:-http://10.0.2.2:8099}"
beacon() { curl -fsS --max-time 3 -o /dev/null "${BEACON}/beacon/$1" 2>/dev/null || true; }
# Ship the log back to the build host. The installer chroot's filesystem cannot be
# read from outside without root, so this is the only way a failure is diagnosable.
uplink() { [ -f "$LOG" ] && curl -fsS --max-time 10 -o /dev/null \
	--data-binary "@${LOG}" "${BEACON}/upload/provision.log" 2>/dev/null || true; }

beacon start
{
	echo "=== pamv1 provisioning $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
	chmod +x ./*.sh

	for s in 10-base.sh 20-postgres.sh 30-pamv1.sh 40-firstboot.sh 50-harden.sh; do
		echo "=== provision: $s ==="
		beacon "$s"
		if ! sh -x "./$s"; then
			echo "=== provision: FAILED in $s ==="
			beacon "FAILED-$s"
			uplink
			exit 1
		fi
	done

	echo "=== provision: complete ==="
} >> "$LOG" 2>&1

uplink
beacon complete
# Also to the installer's own log, so a build without the beacon still shows it.
echo "pamv1 provisioning complete (see /var/log/pamv1-provision.log)"
