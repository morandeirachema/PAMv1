#!/bin/sh
# Last provisioning step: strip everything that must not be shared between copies
# of this image, and shrink what is left.
set -eu

# --- Nothing unique may survive into the image -------------------------------
# SSH host keys: identical keys across clones mean every appliance is a valid
# man-in-the-middle for every other. First boot regenerates them.
rm -f /etc/ssh/ssh_host_*
# machine-id: emptied (not deleted) so systemd regenerates one per clone while
# /etc stays a valid filesystem for the initrd.
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -sf /etc/machine-id /var/lib/dbus/machine-id

# The build user's placeholder password must be changed at first login.
chage -d 0 pam

# --- SSH: keys over passwords, no root ---------------------------------------
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/10-PAMv1.conf <<'EOF'
# Administration of the appliance itself. This is NOT the PAMv1 session proxy,
# which is a separate listener on 2222 and is where privileged sessions go.
PermitRootLogin no
X11Forwarding no
AllowAgentForwarding no
# Password auth stays on so a freshly imported appliance is reachable at all
# (an OVA has nowhere to inject an authorized_keys from). Add your key and turn
# this off — it is the first thing to do after import.
PasswordAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
EOF

# --- Kernel/network hygiene ---------------------------------------------------
cat > /etc/sysctl.d/90-PAMv1.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
EOF

# --- Trim ---------------------------------------------------------------------
apt-get -y autoremove --purge
apt-get -y clean
rm -rf /var/lib/apt/lists/*
find /var/log -type f -exec truncate -s 0 {} \; 2>/dev/null || true
rm -f /root/.bash_history /home/pam/.bash_history

# Deliberately NOT zero-filling the free space. The usual `dd if=/dev/zero`
# trick helps a preallocated image, but this disk is a sparse qcow2: writing 17 GB
# of zeros would ALLOCATE every cluster, inflating the intermediate image and
# slowing the conversion, to help a converter that already skips unallocated
# clusters. fstrim achieves the same intent at no cost where the fs supports it.
fstrim -av 2>/dev/null || true
sync
