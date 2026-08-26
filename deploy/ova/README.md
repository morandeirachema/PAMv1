# PAMv1 appliance (OVA)

A single-file virtual appliance: **Debian 13 (trixie)**, PostgreSQL, the
`pam-server` binary and the **full PAMv1 source tree**, packaged as an `.ova` you
can import into VirtualBox, VMware Workstation/Fusion or ESXi.

It is built by [`build.sh`](build.sh), which needs **no root, no VirtualBox and no
Packer** — just QEMU, `xorriso` and the Go toolchain. The install is a genuine
unattended `debian-installer` run driven by [`http/preseed.cfg`](http/preseed.cfg);
the OVA is assembled by hand, because an OVA is nothing more than a tar of an OVF
descriptor, a SHA-256 manifest and a disk image.

> ⚠️ **Educational build.** PAMv1 is not production-hardened and has never been
> externally audited. The appliance is a way to *run and read* it end to end in
> minutes — not somewhere to put real production credentials.

## Build it

```bash
cd deploy/ova
./build.sh
# → ~/.cache/pamv1-ova/pamv1-appliance-13.6.0.ova  (+ .sha256)
```

10–20 minutes with KVM; considerably longer without (the script says which one it
got). Useful knobs: `OUT=` output path, `DISK_SIZE=`, `VM_MEM=`, `KEEP_WORK=1` to
keep the work directory, `HTTP_PORT=` if 8099 is taken.

### What the build verifies, and what it does not

The build refuses to package an image it has not seen work. After the install it
boots the finished disk — on a **throwaway copy-on-write overlay**, never the image
you ship, because booting consumes first boot — and polls the guest's `/healthz`
through a forwarded port. Packaging only happens once PAMv1 answers, which
transitively proves the binary installed, PostgreSQL came up, the role and database
were created, first boot generated its keys and the systemd sandbox did not block
the service.

Provisioning runs inside `debian-installer`'s chroot, whose output reaches neither
the serial console nor any filesystem the build host can mount without root. So
[`serve.py`](serve.py) doubles as a log sink: the guest fetches `/beacon/<script>`
URLs as it goes (they land in the access log) and POSTs its provisioning log to
`/upload/`. A failed build therefore names the script that broke and prints the
guest's own log — this is what turned "the appliance is empty and I don't know why"
into a one-line diagnosis while this was being written.

**Not verified here:** the `VBoxManage import` itself. The build machine had QEMU
but no VirtualBox, so the OVF descriptor and the stream-optimized VMDK are
constructed to spec and validated as XML, and the disk is boot-tested under QEMU —
but the import path into VirtualBox, VMware or ESXi has not been exercised. Treat
that step as the one to try first.

The base image is pinned by SHA-256. If Debian moves `current/` on to a new point
release the checksum stops matching and the build **fails** rather than quietly
installing an unverified base — bump `DEBIAN_VERSION` and `ISO_SHA256` together.

## Import and first boot

```bash
VBoxManage import ~/.cache/pamv1-ova/pamv1-appliance-13.6.0.ova
# or: VirtualBox → File → Import Appliance
```

The appliance imports with 2 vCPU / 2048 MB and one NAT adapter. To reach the
portal, either forward the ports or attach a host-only adapter:

```bash
VBoxManage modifyvm pamv1-appliance --natpf1 "portal,tcp,127.0.0.1,8080,,8080"
VBoxManage modifyvm pamv1-appliance --natpf1 "sshproxy,tcp,127.0.0.1,2222,,2222"
VBoxManage modifyvm pamv1-appliance --natpf1 "admin,tcp,127.0.0.1,2200,,22"
VBoxManage startvm  pamv1-appliance --type headless
```

**First boot generates this appliance's own secrets** — vault master key, admin
API key, PostgreSQL password and SSH host keys — and prints the admin key to the
console. It is also in `/root/pamv1-credentials.txt`. Then:

- **Portal / REST API** — <http://127.0.0.1:8080>. Sign on with the admin key in
  the *access token* field, leaving *Password* blank.
- **SSH session proxy** — `ssh -p 2222 <credential-user>@<target>@127.0.0.1`,
  using the admin key as the SSH password.
- **Appliance shell** — user `pam` (`ssh -p 2200 pam@127.0.0.1`). The placeholder
  password is `PAMv1` and is **force-expired**: you must set a new one on first
  login. Add an SSH key and turn off `PasswordAuthentication` in
  `/etc/ssh/sshd_config.d/10-PAMv1.conf`.

## What is inside

| Path | What |
|---|---|
| `/usr/local/bin/pam-server` | The static binary (built from the commit named in `/etc/pamv1/build-info`) |
| `/etc/pamv1/pamv1.env` | This appliance's configuration and generated keys (`0640 root:pamv1`) |
| `/opt/pamv1/src` | **The full source tree** — read it, rebuild it, run the tests |
| `/var/lib/pamv1/recordings` | Session recordings |
| `/etc/systemd/system/pamv1.service` | The service: non-root, `ProtectSystem=strict`, no capabilities |
| `/var/log/pamv1-provision.log` | What the build did inside the guest |

```bash
systemctl status PAMv1          # the service
journalctl -u PAMv1 -f          # its logs
sudo -u PAMv1 pam-server -healthcheck   # what the readiness probe uses
cat /etc/pamv1/build-info       # version, commit, base image, binary digest
```

Every other `PAM_*` knob is documented in
[`../docker/.env.example`](../docker/.env.example) (shipped at
`/opt/pamv1/src/deploy/docker/.env.example`). Add lines to
`/etc/pamv1/pamv1.env`, then `systemctl restart PAMv1`.

## Design decisions worth knowing

**Debian 13, minimal.** No desktop, no printing stack, `--no-install-recommends`.
An appliance for a privileged-access system should be the least surprising thing
on the network: a stable base with a security team, systemd, PostgreSQL 17 in the
archive, and no snap layer.

**No secret is baked into the image.** An OVA gets copied, so anything created at
build time is shared by every import — for a vault KEK that would mean every
appliance can decrypt every other appliance's secrets. The master key, admin key,
database password, SSH host keys and machine-id are all generated on **first
boot** ([`firstboot.sh`](firstboot.sh)), which is idempotent, so a reboot never
rotates a running appliance's keys.

**PostgreSQL is localhost-only and PAMv1 is not a superuser.** The `pam` role owns
its database and nothing else, and `pg_hba.conf` allows only `127.0.0.1`. The
vault's KEK is outside the database, so a database-only compromise yields
ciphertext — but note that since Phase 55 the same connection also carries the
cross-replica live-monitoring relay, so the role is worth more than it once was.

**The network config is interface-agnostic.** The build runs under QEMU
(virtio-net → `ens3`) and the OVA is imported into VirtualBox (E1000 → `enp0s3`)
or VMware (vmxnet3 → `ens33`). `ifupdown` pins the interface *name* it saw at
install time, which is the single most common way a hand-rolled OVA arrives with
no network; systemd-networkd with `Name=en* eth*` does not care.

**Single disk, no LUKS.** Full-disk encryption inside an appliance needs a
passphrase at every boot, which an unattended appliance can only supply by storing
the key next to the data it protects. Encrypt the host volume or the datastore
instead.

## Not in the appliance

- **guacd**, so the in-portal RDP and VNC viewers are inactive. Install
  `guacd` and set `PAM_GUACD_ADDR=127.0.0.1:4822`, or use the
  [Docker demos](../docker/README.md) which wire it up for you.
- **A Go toolchain.** The source is present but rebuilding needs Go 1.26+, which
  Debian 13 does not carry — fetch it from <https://go.dev/dl/> if you want to
  rebuild in place.
- **TLS.** The portal serves plain HTTP on 8080. Set `PAM_TLS_CERT`/`PAM_TLS_KEY`
  (and `PAM_REQUIRE_HTTPS`) or front it with a reverse proxy before this is
  reachable by anyone but you.
- **Any target to connect to.** Add your own via the portal; the Docker demos
  include throwaway RDP and VNC targets if you want something to point at.
