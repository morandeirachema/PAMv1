#!/bin/sh
# Base system: the service account pamv1 runs as, and its state directories.
set -eu

# A dedicated, non-login system user. pamv1 never needs root: its SSH proxy binds
# 2222 and its API 8080, both above 1024.
if ! id pamv1 >/dev/null 2>&1; then
	adduser --system --group --home /var/lib/pamv1 --shell /usr/sbin/nologin pamv1
fi

install -d -o pamv1 -g pamv1 -m 0750 /var/lib/pamv1
install -d -o pamv1 -g pamv1 -m 0750 /var/lib/pamv1/recordings
install -d -o root  -g pamv1 -m 0750 /etc/pamv1

# --- Interface-agnostic networking -------------------------------------------
# The build runs under QEMU (virtio-net → ens3); the OVA is imported into
# VirtualBox (E1000 → enp0s3) or VMware (vmxnet3 → ens33). ifupdown pins the
# interface NAME it saw at install time, so an appliance built one way and
# imported another comes up with no network — the single most common way a
# hand-rolled OVA arrives broken. systemd-networkd with a glob match does not
# care which NIC it gets.
systemctl disable networking 2>/dev/null || true
: > /etc/network/interfaces
cat > /etc/network/interfaces <<'EOF'
# Managed by systemd-networkd (see /etc/systemd/network/). Left empty on purpose:
# ifupdown would otherwise pin the install-time interface name.
source /etc/network/interfaces.d/*
EOF
cat > /etc/systemd/network/20-wired-dhcp.network <<'EOF'
[Match]
Name=en* eth*

[Network]
DHCP=yes
# An appliance that cannot resolve names cannot reach an IdP or a target.
LLMNR=no
MulticastDNS=no
EOF
systemctl enable systemd-networkd
# systemd-resolved is a separate package since Debian 12; the preseed installs it,
# but never let a missing optional unit abort provisioning — and only point
# resolv.conf at its stub if it is actually there, or the appliance boots with a
# dangling symlink and no DNS at all.
if systemctl enable systemd-resolved 2>/dev/null; then
	ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
else
	echo "note: systemd-resolved is absent; leaving /etc/resolv.conf as installed"
fi

# --- Console on both the display and the serial line -------------------------
# tty0 is what VirtualBox shows in its window; ttyS0 lets an operator (and this
# repo's build harness) drive the appliance headlessly over a serial port. The
# first-boot unit prints the generated admin key to the console, so which
# consoles exist decides whether that key is reachable at all.
sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet console=tty0 console=ttyS0,115200n8"/' /etc/default/grub
grep -q '^GRUB_TERMINAL' /etc/default/grub || echo 'GRUB_TERMINAL="console serial"' >> /etc/default/grub
grep -q '^GRUB_SERIAL_COMMAND' /etc/default/grub || echo 'GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200"' >> /etc/default/grub
update-grub
systemctl enable serial-getty@ttyS0.service

# Console banner. An appliance whose first screen does not say what it is, and
# what state it is in, gets misidentified in exactly the situation where that
# matters — an incident.
cat > /etc/issue <<'EOF'
      _____  _____ ___  ____   ______
     |  __ \|  _  |  \/  \ \ / /  _  |
     | |__) | |_| | .  . |\ V /| | | |   pamv1 appliance (Debian 13)
     |  ___/|  _  | |\/| | \ / | | | |   Privileged Access Management
     | |    | | | | |  | | | | | |_| |
     |_|    |_| |_|_|  |_| |_| |_____/   https://github.com/morandeirachema/pamv1

 Portal / API : http://\4:8080        SSH proxy : \4:2222
 Log in as    : pam   (you will be forced to set a new password on first login)
 Admin key    : printed on first boot; also in /root/pamv1-credentials.txt

 Educational build. Not production-hardened, not externally audited.

EOF
