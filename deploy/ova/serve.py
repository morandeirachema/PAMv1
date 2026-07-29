#!/usr/bin/env python3
"""Build-time payload server for the pamv1 appliance build.

Three jobs, all on one port that only the guest can reach (10.0.2.2 under QEMU
user-mode networking):

  GET  /<file>            serve the payload and the preseed (like http.server)
  GET  /beacon/<name>     a progress report; recorded in the access log
  POST /upload/<name>     the guest uploads a file — this is the ONLY way to read
                          anything out of the installer chroot, whose filesystem
                          the build host cannot mount without root

The upload channel exists because provisioning runs inside d-i's /target chroot:
its output never reaches the serial console, and the disk image cannot be mounted
unprivileged. Without it, a failed provisioning step is invisible — which cost
this build two iterations before the channel existed.
"""
import http.server
import os
import pathlib
import re
import socketserver
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
UPLOAD_DIR = pathlib.Path(os.environ.get("UPLOAD_DIR", "uploads"))
SAFE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_UPLOAD = 8 * 1024 * 1024


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 (stdlib naming)
        if not self.path.startswith("/upload/"):
            self.send_error(404, "only /upload/<name> accepts POST")
            return
        name = self.path[len("/upload/"):]
        # The guest is not trusted to name a path: no traversal, no absolutes.
        if not SAFE.match(name):
            self.send_error(400, "bad upload name")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "bad Content-Length")
            return
        if length <= 0 or length > MAX_UPLOAD:
            self.send_error(413, "empty or oversized upload")
            return
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        (UPLOAD_DIR / name).write_bytes(self.rfile.read(length))
        self.send_response(204)
        self.end_headers()

    def do_GET(self):  # noqa: N802
        # Beacons carry no body; they exist purely to appear in the access log.
        if self.path.startswith("/beacon/"):
            self.send_response(204)
            self.end_headers()
            return
        super().do_GET()

    def log_message(self, fmt, *args):
        sys.stdout.write("%s - %s\n" % (self.address_string(), fmt % args))
        sys.stdout.flush()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("127.0.0.1", PORT), Handler) as httpd:
        print(f"payload server on 127.0.0.1:{PORT} (uploads -> {UPLOAD_DIR})", flush=True)
        httpd.serve_forever()
