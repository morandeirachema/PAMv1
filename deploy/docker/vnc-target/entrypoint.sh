#!/bin/sh
# Start an Xvnc display serving XFCE on :5900. Kept simple and idempotent so
# `docker compose restart` works. Demo only — see the Dockerfile.
set -e

# Clear stale X lock/socket state from a previous run.
rm -f /tmp/.X0-lock /tmp/.X11-unix/X0 2>/dev/null || true
mkdir -p /var/run/dbus /tmp/.X11-unix

# XFCE needs a system D-Bus with a machine-id.
[ -s /var/lib/dbus/machine-id ] || dbus-uuidgen --ensure
rm -f /var/run/dbus/pid
dbus-daemon --system --fork

# Display :0 is VNC port 5900 (5900 + display number). VncAuth is the classic
# DES challenge-response — the whole reason this target is brokered rather than
# exposed: guacd holds the password, the operator never does.
Xvnc :0 -geometry 1280x800 -depth 24 -SecurityTypes VncAuth \
      -PasswordFile /root/.vnc/passwd -AlwaysShared -localhost=0 &

# Wait for the display, then launch the desktop inside it.
until [ -S /tmp/.X11-unix/X0 ]; do sleep 0.5; done
DISPLAY=:0 startxfce4 &

# Keep the container in the foreground on Xvnc.
wait -n
