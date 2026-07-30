#!/bin/sh
# Installs the first-boot script. Everything secret in this appliance is created
# THERE, not here, because an OVA is copied: a key baked at build time would be
# shared by every import of the image, which for a vault KEK means every appliance
# can decrypt every other appliance's secrets.
set -eu

install -o root -g root -m 0700 /opt/pamv1/firstboot.sh /usr/local/sbin/pamv1-firstboot
