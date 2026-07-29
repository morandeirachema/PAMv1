# VNC test target for the pamv1 in-portal VNC viewer demo: a throwaway Linux
# desktop (XFCE) served over TigerVNC, so the rendered-pixels path can be
# verified end to end without any proprietary server.
#
# NOT hardened — it serves an unencrypted VNC desktop with a well-known
# password. For local end-to-end testing only; never deploy it.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      tigervnc-standalone-server tigervnc-common \
      xfce4 xfce4-terminal dbus-x11 dbus iproute2 \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Demo password — MUST match the credential the compose file seeds into pamv1.
#
# Eight characters, and that is not a coincidence: classic VNC authentication
# (RFB security type 2) uses the password as a DES key, which is 56 bits, so
# every server truncates it to 8 characters. A longer password is not "more
# secure here" — its tail is silently discarded. See docs/PROTOCOLS-AND-CRYPTO.md.
ARG VNC_PASS=DemoVnc1
RUN mkdir -p /root/.vnc && printf '%s\n%s\n\n' "$VNC_PASS" "$VNC_PASS" | vncpasswd /root/.vnc/passwd

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 5900
HEALTHCHECK --interval=10s --timeout=3s --start-period=25s --retries=6 \
  CMD ss -lnt 2>/dev/null | grep -q ':5900' || exit 1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
