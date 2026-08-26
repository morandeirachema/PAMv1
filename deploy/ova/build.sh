#!/usr/bin/env bash
# Build the PAMv1 appliance OVA.
#
# Produces a VirtualBox/VMware-importable .ova containing Debian 13 (trixie),
# PostgreSQL, the pam-server binary and the full PAMv1 source tree.
#
# It needs NO root, NO VirtualBox and NO Packer — just QEMU, xorriso and the Go
# toolchain. The install is unattended (debian-installer preseed); provisioning
# runs inside the target from provision/, and the OVA is assembled by hand
# (an OVA is a tar of the OVF descriptor, a SHA-256 manifest and the disk).
#
#   ./build.sh                    # full build
#   OUT=/tmp/x.ova ./build.sh     # choose the output path
#   KEEP_WORK=1 ./build.sh        # keep the work dir for debugging
#
# Roughly 10–20 minutes with KVM, and a long time without it.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"

# --- Tunables ----------------------------------------------------------------
DEBIAN_VERSION="${DEBIAN_VERSION:-13.6.0}"
ISO_URL="${ISO_URL:-https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-${DEBIAN_VERSION}-amd64-netinst.iso}"
# Pinned: the build must fail rather than install an unverified base image.
ISO_SHA256="${ISO_SHA256:-65273beed27b2df543b68b65630ba525cfbad8df2b12035732b2dff87d6664e7}"
DISK_SIZE="${DISK_SIZE:-20G}"      # sparse; the OVA only carries written blocks
VM_MEM="${VM_MEM:-2048}"
VM_CPUS="${VM_CPUS:-2}"
HTTP_PORT="${HTTP_PORT:-8099}"     # host-side payload server, reached as 10.0.2.2
INSTALL_TIMEOUT="${INSTALL_TIMEOUT:-3600}"
CACHE="${CACHE:-${HOME}/.cache/pamv1-ova}"
OUT="${OUT:-${CACHE}/pamv1-appliance-${DEBIAN_VERSION}.ova}"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# --- 0. Preflight ------------------------------------------------------------
say "Preflight"
for t in qemu-system-x86_64 qemu-img xorriso curl sha256sum tar python3 go; do
	command -v "$t" >/dev/null || die "missing required tool: $t"
done
ACCEL=()
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
	ACCEL=(-enable-kvm -cpu host)
	echo "KVM: available"
else
	echo "KVM: NOT available — the install will be emulated and much slower."
fi
mkdir -p "$CACHE"
work="$(mktemp -d "${CACHE}/build.XXXXXX")"
cleanup() {
	[[ -n "${http_pid:-}" ]] && kill "$http_pid" 2>/dev/null || true
	if [[ "${KEEP_WORK:-0}" == "1" ]]; then
		echo "work dir kept: $work"
	else
		rm -rf "$work"
	fi
}
trap cleanup EXIT

# --- 1. Base image -----------------------------------------------------------
say "Debian ${DEBIAN_VERSION} netinst ISO"
iso="${CACHE}/debian-${DEBIAN_VERSION}-amd64-netinst.iso"
if [[ ! -f "$iso" ]]; then
	curl -fSL --progress-bar -o "$iso" "$ISO_URL"
fi
echo "${ISO_SHA256}  ${iso}" | sha256sum -c - || die "ISO checksum mismatch — refusing to build on an unverified base image"

# --- 2. Build pam-server (on the host, static) -------------------------------
# Built here rather than in the guest so the appliance carries no toolchain and
# the binary is bit-for-bit attributable to a commit.
say "Building pam-server (static, CGO_ENABLED=0)"
commit="$(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo unknown)"
version="$(git -C "$repo" describe --tags --always 2>/dev/null || echo dev)"
( cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	go build -trimpath -ldflags "-s -w -X main.version=${version} -X main.commit=${commit}" \
	-o "${work}/pam-server" ./cmd/pam-server )
file "${work}/pam-server" | grep -q "statically linked" || echo "note: binary may not be fully static"

# --- 3. Payload the installer will pull --------------------------------------
say "Assembling the payload"
payload="${work}/payload"
mkdir -p "$payload" "${work}/http"
cp "${work}/pam-server" "$payload/"
cp -r "${here}/provision" "${here}/systemd" "$payload/"
cp "${here}/firstboot.sh" "$payload/"
# The full source tree, so the appliance is readable and rebuildable. git archive
# keeps it to tracked files — no build junk, no .git, no local secrets.
mkdir -p "${payload}/src"
git -C "$repo" archive --format=tar HEAD | tar -x -C "${payload}/src"
cat > "${payload}/BUILD_INFO" <<EOF
PAMv1 appliance
  version        : ${version}
  commit         : ${commit}
  built          : $(date -u +%Y-%m-%dT%H:%M:%SZ)
  base image     : Debian ${DEBIAN_VERSION} amd64 (netinst, verified sha256)
  go             : $(go version | awk '{print $3}')
  pam-server     : sha256:$(sha256sum "${work}/pam-server" | cut -d' ' -f1)
EOF
chmod +x "${payload}"/provision/*.sh "${payload}/firstboot.sh"
tar -czf "${work}/http/payload.tar.gz" -C "$payload" .
cp "${here}/http/preseed.cfg" "${work}/http/"
du -h "${work}/http/payload.tar.gz" | awk '{print "payload: "$1}'

# --- 4. Installer kernel + initrd -------------------------------------------
# Booting the kernel directly is far more reliable to automate than driving the
# ISO's boot menu with simulated keystrokes.
say "Extracting the installer kernel"
xorriso -osirrox on -indev "$iso" \
	-extract /install.amd/vmlinuz "${work}/vmlinuz" \
	-extract /install.amd/initrd.gz "${work}/initrd.gz" >/dev/null 2>&1
[[ -s "${work}/vmlinuz" && -s "${work}/initrd.gz" ]] || die "could not extract vmlinuz/initrd from the ISO"

# --- 5. Serve the payload ----------------------------------------------------
say "Serving the payload on :${HTTP_PORT}"
( cd "${work}/http" && UPLOAD_DIR="${work}/uploads" exec python3 "${here}/serve.py" "$HTTP_PORT" ) \
	>"${work}/http.log" 2>&1 &
http_pid=$!
sleep 1
curl -fsS "http://127.0.0.1:${HTTP_PORT}/preseed.cfg" >/dev/null || die "payload server did not start"

# --- 6. Unattended install ---------------------------------------------------
say "Installing (headless; log: ${work}/install-serial.log)"
disk="${work}/disk.qcow2"
qemu-img create -f qcow2 "$disk" "$DISK_SIZE" >/dev/null

# `auto=true priority=critical` suppresses every question the preseed answers.
# The serial console is captured so a failed build is diagnosable.
append="auto=true priority=critical preseed/url=http://10.0.2.2:${HTTP_PORT}/preseed.cfg"
append+=" debian-installer/locale=en_US.UTF-8 keyboard-configuration/xkb-keymap=us"
append+=" netcfg/choose_interface=auto hostname=PAMv1 domain=local"
append+=" console=ttyS0,115200n8 --- console=ttyS0,115200n8"

set +e
timeout "$INSTALL_TIMEOUT" qemu-system-x86_64 \
	"${ACCEL[@]}" \
	-m "$VM_MEM" -smp "$VM_CPUS" \
	-drive "file=${disk},if=virtio,format=qcow2,cache=unsafe" \
	-cdrom "$iso" \
	-kernel "${work}/vmlinuz" -initrd "${work}/initrd.gz" -append "$append" \
	-netdev "user,id=n0" -device "virtio-net-pci,netdev=n0" \
	-display none -serial "file:${work}/install-serial.log" \
	-no-reboot
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
	tail -40 "${work}/install-serial.log" || true
	die "installer exited $rc (timeout is ${INSTALL_TIMEOUT}s) — see ${work}/install-serial.log"
fi
grep -qi "Power down\|poweroff" "${work}/install-serial.log" || {
	tail -40 "${work}/install-serial.log" || true
	die "the installer did not reach a clean power-off — see ${work}/install-serial.log"
}

# The provisioning ran inside the installer chroot, whose output never reaches the
# serial console. It reports progress by fetching beacon URLs from this very HTTP
# server, so the access log tells us exactly how far it got — and which script
# failed, instead of "the appliance is empty and we do not know why".
say "Provisioning report (from the payload server's access log)"
if grep -q "beacon/complete" "${work}/http.log"; then
	grep -o "beacon/[A-Za-z0-9._-]*" "${work}/http.log" | sed 's|beacon/|  ran: |'
else
	grep -o "beacon/[A-Za-z0-9._-]*" "${work}/http.log" | sed 's|beacon/|  ran: |' || true
	if grep -q "beacon/start" "${work}/http.log"; then
		# The guest uploads its provisioning log precisely so this is diagnosable.
		if [[ -s "${work}/uploads/provision.log" ]]; then
			echo; echo "--- last 40 lines of the guest's provisioning log ---"
			tail -40 "${work}/uploads/provision.log"
			echo "--- full log: ${work}/uploads/provision.log ---"
		fi
		die "provisioning started but did not complete — the last 'ran:' line above is where it stopped"
	fi
	die "provisioning never started: the installer's late_command did not reach this server. Check preseed quoting and that the guest can reach 10.0.2.2:${HTTP_PORT}"
fi
kill "$http_pid" 2>/dev/null || true; unset http_pid

# --- 6b. Boot the appliance and prove it works -------------------------------
# The installer's late_command writes its own log inside the guest, so grepping
# the install console for a success marker proves nothing. This does: boot the
# built image and ask the running PAMv1 for its health.
#
# It runs against a THROWAWAY COPY-ON-WRITE OVERLAY, never the image we ship —
# booting consumes first boot (keys get generated), and the OVA must leave that
# to whoever imports it.
say "Verifying the built appliance boots and serves"
overlay="${work}/verify-overlay.qcow2"
qemu-img create -f qcow2 -F qcow2 -b "$disk" "$overlay" >/dev/null
vport="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
qemu-system-x86_64 \
	"${ACCEL[@]}" \
	-m "$VM_MEM" -smp "$VM_CPUS" \
	-drive "file=${overlay},if=virtio,format=qcow2" \
	-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${vport}-:8080" \
	-device "virtio-net-pci,netdev=n0" \
	-display none -serial "file:${work}/firstboot-serial.log" &
vm_pid=$!
healthy=0
for _ in $(seq 1 180); do
	if curl -fsS -m 2 "http://127.0.0.1:${vport}/healthz" 2>/dev/null | grep -q '"ok"'; then
		healthy=1; break
	fi
	kill -0 "$vm_pid" 2>/dev/null || break
	sleep 1
done
if [[ $healthy -eq 1 ]]; then
	admin_key="$(grep -o 'Admin API key: pamk_[A-Za-z0-9_-]*' "${work}/firstboot-serial.log" | tail -1 || true)"
	echo "  /healthz answered ok"
	echo "  first boot generated its own credentials: ${admin_key:-<not echoed to serial>}"
fi
kill "$vm_pid" 2>/dev/null || true
wait "$vm_pid" 2>/dev/null || true
if [[ $healthy -ne 1 ]]; then
	tail -60 "${work}/firstboot-serial.log" 2>/dev/null | tr -d '\r' || true
	die "the appliance booted but PAMv1 never answered /healthz — see ${work}/firstboot-serial.log"
fi

# --- 7. Convert to a stream-optimized VMDK ----------------------------------
say "Converting to VMDK (streamOptimized)"
vmdk_name="pamv1-appliance-disk1.vmdk"
qemu-img convert -p -f qcow2 -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic \
	"$disk" "${work}/${vmdk_name}"

capacity="$(qemu-img info --output=json "$disk" | python3 -c 'import json,sys;print(json.load(sys.stdin)["virtual-size"])')"
file_size="$(stat -c%s "${work}/${vmdk_name}")"

# --- 8. OVF descriptor + manifest -------------------------------------------
say "Writing the OVF descriptor and manifest"
ovf_name="pamv1-appliance.ovf"
sed -e "s|@DISK_FILE@|${vmdk_name}|g" \
    -e "s|@DISK_FILE_SIZE@|${file_size}|g" \
    -e "s|@DISK_CAPACITY@|${capacity}|g" \
    -e "s|@DISK_POPULATED@|${file_size}|g" \
    -e "s|@BUILD_VERSION@|${version} (${commit})|g" \
    "${here}/pamv1.ovf.template" > "${work}/${ovf_name}"
python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parse(sys.argv[1])" "${work}/${ovf_name}" \
	|| die "generated OVF is not well-formed XML"

( cd "$work" && {
	printf 'SHA256(%s)= %s\n' "$ovf_name"   "$(sha256sum "$ovf_name"   | cut -d' ' -f1)"
	printf 'SHA256(%s)= %s\n' "$vmdk_name"  "$(sha256sum "$vmdk_name"  | cut -d' ' -f1)"
} > pamv1-appliance.mf )

# --- 9. Package --------------------------------------------------------------
# Order matters: importers stream the archive and expect the descriptor first,
# then the manifest, then the disk.
say "Packaging the OVA"
( cd "$work" && tar -cf "${OUT}.tmp" --format=ustar \
	"$ovf_name" "pamv1-appliance.mf" "$vmdk_name" )
mv "${OUT}.tmp" "$OUT"
sha256sum "$OUT" > "${OUT}.sha256"

say "Done"
printf '  %s\n  %s\n\n' "$OUT" "$(du -h "$OUT" | cut -f1)"
echo "Import:  VBoxManage import \"$OUT\"   (or File → Import Appliance)"
echo "Verify:  sha256sum -c \"${OUT}.sha256\""
