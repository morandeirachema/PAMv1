#!/bin/sh
# pamv1 itself: the binary, the source tree, and the service unit.
#
# The binary is built on the BUILD HOST (CGO_ENABLED=0, static) and injected, so
# the appliance carries no Go toolchain and no build dependencies. The full source
# is shipped alongside it at /opt/pamv1/src — this is an educational project, and
# an appliance you cannot read the source of teaches nothing.
set -eu

install -o root -g root -m 0755 /opt/pamv1/pam-server /usr/local/bin/pam-server

# Version marker, so `pam-server -version`-style questions have an answer that
# survives into the running appliance.
if [ -f /opt/pamv1/BUILD_INFO ]; then
	install -o root -g root -m 0644 /opt/pamv1/BUILD_INFO /etc/pamv1/build-info
fi

install -o root -g root -m 0644 /opt/pamv1/systemd/pamv1.service /etc/systemd/system/pamv1.service
install -o root -g root -m 0644 /opt/pamv1/systemd/pamv1-firstboot.service /etc/systemd/system/pamv1-firstboot.service

# Enabled, but they do nothing useful until first boot has written the env file —
# pamv1.service requires it, so a failed first boot leaves the service down and
# visible rather than up and misconfigured.
systemctl enable pamv1-firstboot.service
systemctl enable pamv1.service

/usr/local/bin/pam-server -version 2>/dev/null || true
echo "pam-server installed: $(sha256sum /usr/local/bin/pam-server | cut -c1-16)…"
