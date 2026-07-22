# VAIEXIA Server — Operator Install Runbook

This document is a copy-pasteable installation and operation guide for
`vaiexia-server` and its privilege-separated helper `vaiexia-privd`.
Every command is real and runnable on a systemd-based Linux host.

---

## Table of Contents

1. [Build and install binaries + packaging artifacts](#1-build-and-install)
2. [privd uid drop-in](#2-privd-uid-drop-in)
3. [Package allowlist (optional, recommended for production)](#3-package-allowlist)
4. [Polkit allowlist mode (optional)](#4-polkit-allowlist-mode)
5. [Configure `/etc/vaiexia/server.toml`](#5-configure)
6. [Enable and start](#6-enable-and-start)
7. [First-run bootstrap](#7-first-run-bootstrap)
8. [Audit trail](#8-audit-trail)
9. [Security CI gates](#9-security-ci-gates)

---

## 1. Build and Install

### Build

```bash
cargo build --release
```

This produces `target/release/vaiexia-server` and
`target/release/vaiexia-privd`.  
The default `tls` feature is included in the workspace manifest; TLS listener
support (`kind = "https"` in the config) is therefore available in the
release binary with no extra flags.

### Copy binaries

```bash
install -o root -g root -m 0755 target/release/vaiexia-server /usr/bin/vaiexia-server
install -o root -g root -m 0755 target/release/vaiexia-privd   /usr/bin/vaiexia-privd
```

### Install packaging artifacts

```bash
# systemd units
install -o root -g root -m 0644 \
    packaging/systemd/vaiexia-server.service \
    packaging/systemd/vaiexia-privd.service  \
    packaging/systemd/vaiexia-privd.socket   \
    /etc/systemd/system/

# polkit rule
install -o root -g root -m 0644 \
    packaging/polkit/50-vaiexia-manage-units.rules \
    /etc/polkit-1/rules.d/

# sysusers (creates the vaiexia system user)
install -o root -g root -m 0644 \
    packaging/sysusers/vaiexia.conf \
    /usr/lib/sysusers.d/

# tmpfiles (creates /run/vaiexia and /var/lib/vaiexia)
install -o root -g root -m 0644 \
    packaging/tmpfiles/vaiexia.conf \
    /usr/lib/tmpfiles.d/
```

### Provision system user and directories

```bash
systemd-sysusers
systemd-tmpfiles --create
```

`systemd-sysusers` reads `/usr/lib/sysusers.d/vaiexia.conf` and creates:

```
u vaiexia - "VAIEXIA management daemon" /var/lib/vaiexia
```

`systemd-tmpfiles --create` reads `/usr/lib/tmpfiles.d/vaiexia.conf` and
creates:

```
d /run/vaiexia    0755 root    root    -
d /var/lib/vaiexia 0700 vaiexia vaiexia -
```

`/run/vaiexia` is **root-owned** by design — the socket file inside is
`0600 vaiexia:vaiexia` (set by the socket unit).  A compromised daemon cannot
replace the socket by writing to a directory it does not own.

---

## 2. privd uid drop-in

The `vaiexia-privd.service` unit ships with:

```ini
Environment=VAIEXIA_DAEMON_UID=%U
```

`%U` expands to the **service user** (root), not the `vaiexia` user uid.
privd uses this variable for its `SO_PEERCRED` uid gate — it refuses
connections from any process whose uid does not match.  Without a correct
value privd would reject the daemon's socket connections (fail-closed).

Fix this with a systemd drop-in **before starting the services**:

```bash
systemctl edit vaiexia-privd.service
```

In the editor that opens, paste:

```ini
[Service]
Environment=VAIEXIA_DAEMON_UID=UID_PLACEHOLDER
```

Replace `UID_PLACEHOLDER` with the actual numeric uid of the `vaiexia` user:

```bash
id -u vaiexia
```

Example (if `id -u vaiexia` prints `995`):

```ini
[Service]
Environment=VAIEXIA_DAEMON_UID=995
```

Save and close the editor.  The drop-in is written to
`/etc/systemd/system/vaiexia-privd.service.d/override.conf`.

---

## 3. Package Allowlist

### What it does

`/etc/vaiexia/pkg-allowlist` restricts which packages the daemon may ask
privd to install or remove.

- **Absent** (default): any valid package name is permitted — this is the
  pre-production default.
- **Present**: ONLY the packages listed in the file may be installed or
  removed, even if the daemon is fully compromised.  An attacker who gains
  control of the daemon cannot direct root-privd at an arbitrary malicious
  package.
- **Empty file** (or a file containing only comments): ALL package operations
  are refused.

This is a **fail-closed** control: invalid lines in the file are skipped with
a warning (narrowing the permitted set), and any I/O error other than
`ENOENT` causes privd to refuse to start.

### File format

```
# web stack
nginx
curl
vim
# WireGuard
wireguard-tools
```

- One package name per line.
- Lines starting with `#` and blank lines are ignored.
- Invalid package names (e.g. `-rf`) are logged and skipped (narrowing).
- The file is read once at privd startup; restart to apply changes:

```bash
systemctl restart vaiexia-privd.service
```

### Install

```bash
mkdir -p /etc/vaiexia
cat > /etc/vaiexia/pkg-allowlist <<'EOF'
# VAIEXIA package allowlist — edit to match your host
nginx
certbot
wireguard-tools
EOF
chmod 0600 /etc/vaiexia/pkg-allowlist
chown root:root /etc/vaiexia/pkg-allowlist
systemctl restart vaiexia-privd.service
```

The allowlist path can be overridden by setting `VAIEXIA_PKG_ALLOWLIST` in
the privd environment (same drop-in mechanism as above).

---

## 4. Polkit Allowlist Mode

### Default: denylist

The shipped rule (`/etc/polkit-1/rules.d/50-vaiexia-manage-units.rules`)
grants the `vaiexia` user the verbs `start`, `stop`, and `restart` on **any**
systemd unit **except** the following protected boundary units:

```
vaiexia-server.service
vaiexia-privd.service
vaiexia-privd.socket
dbus.service
dbus.socket
polkit.service
systemd-logind.service
systemd-journald.service
```

Everything else (enable/disable/mask/reload and any other verb) falls through
to the polkit default, which denies a non-admin system user.

### Optional: allowlist mode

For locked-down production deployments, switch to the allowlist variant
shipped at `packaging/polkit/50-vaiexia-manage-units.allowlist.rules.example`.

**Semantic difference:**
- Denylist mode: unlisted units/verbs fall through to the polkit default (may
  be permitted by other rules or the default policy).
- Allowlist mode: anything outside the list from the `vaiexia` user returns an
  explicit `polkit.Result.NO` — nothing outside the list, ever.

**Steps to switch:**

1. Edit the example file to list only the units this host should expose:

```bash
cp packaging/polkit/50-vaiexia-manage-units.allowlist.rules.example \
   /tmp/50-vaiexia-manage-units.rules
```

Open `/tmp/50-vaiexia-manage-units.rules` and replace the `allowed` array:

```javascript
var allowed = [
    "nginx.service",
    "wg-quick@wg0.service"
];
```

Do **not** list `vaiexia-server.service` or `vaiexia-privd.*` — the daemon
must not manage its own privilege boundary in either mode.

2. Replace the denylist rule:

```bash
rm /etc/polkit-1/rules.d/50-vaiexia-manage-units.rules
install -o root -g root -m 0644 \
    /tmp/50-vaiexia-manage-units.rules \
    /etc/polkit-1/rules.d/50-vaiexia-manage-units.rules
```

Polkit rescans rules automatically; no daemon restart needed.

---

## 5. Configure

Create the config directory and a `server.toml` before the first start:

```bash
mkdir -p /etc/vaiexia
```

### 5a. Default loopback + WireGuard posture (recommended)

Run the daemon on loopback and expose it through a WireGuard tunnel or a local
reverse proxy.  This is the safest default — TLS termination is handled by
the tunnel or proxy layer.

```toml
# /etc/vaiexia/server.toml

state_dir = "/var/lib/vaiexia"

[[listeners]]
kind = "http"
bind = "127.0.0.1:7443"

[backend]
mode = "auto"   # "auto" | "mock" | "real"

[audit]
enabled    = true
# dir defaults to <state_dir>/audit (/var/lib/vaiexia/audit)
max_bytes  = 8388608   # 8 MiB per rotation file
generations = 3        # keep audit.jsonl.1 … .3
queue      = 1024      # bounded queue between request tasks and the writer thread
```

### 5b. Direct TLS listener

Use this when the daemon is reachable directly from the network (no proxy).
The binary must be built with the default `tls` feature (it is, by default).

Obtain a certificate first — example with Let's Encrypt / certbot:

```bash
certbot certonly --standalone -d vpn.example.com
# Certificate: /etc/letsencrypt/live/vpn.example.com/fullchain.pem
# Key:         /etc/letsencrypt/live/vpn.example.com/privkey.pem
```

Or generate a self-signed cert for internal use (requires `openssl`):

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
    -keyout /etc/vaiexia/server.key \
    -out /etc/vaiexia/server.crt \
    -nodes -subj "/CN=vaiexia"
chmod 0600 /etc/vaiexia/server.key
```

Config with TLS:

```toml
# /etc/vaiexia/server.toml

state_dir = "/var/lib/vaiexia"

[[listeners]]
kind = "https"
bind = "0.0.0.0:7443"
cert = "/etc/letsencrypt/live/vpn.example.com/fullchain.pem"
key  = "/etc/letsencrypt/live/vpn.example.com/privkey.pem"

[backend]
mode = "auto"

[audit]
enabled     = true
max_bytes   = 8388608
generations = 3
queue       = 1024
```

The daemon reads the certificate and key at startup.  Certificate hot-reload
is not supported in v1 — restart the daemon to rotate certs:

```bash
systemctl restart vaiexia-server
```

### 5c. Validate the config

```bash
vaiexia-server --check-config --config /etc/vaiexia/server.toml
```

Exit code 0 = valid (warnings are printed but do not fail).  
Exit code 1 = invalid (error message on stderr).

This is also run automatically by the `ExecStartPre` line in
`vaiexia-server.service` before each start, so a broken config prevents the
daemon from starting and leaves a clear error in `journalctl`.

---

## 6. Enable and Start

```bash
systemctl daemon-reload
systemctl enable --now vaiexia-privd.socket vaiexia-server
```

`vaiexia-privd.socket` is socket-activated — systemd creates the socket at
`/run/vaiexia/privd.sock` and starts `vaiexia-privd.service` on the first
connection from the daemon.  There is no need to enable
`vaiexia-privd.service` directly.

Verify the units loaded cleanly:

```bash
systemd-analyze verify /etc/systemd/system/vaiexia-server.service
systemctl status vaiexia-privd.socket vaiexia-server
journalctl -u vaiexia-server -n 50
```

---

## 7. First-Run Bootstrap

On the very first start, if the identity store (`/var/lib/vaiexia/identity.json`)
is empty, the daemon generates a one-time bootstrap code and writes it to:

```
/var/lib/vaiexia/bootstrap.code
```

The file is created at mode `0600` owned by `vaiexia`.  The code is logged
as a **path** only — the secret itself never appears in the log or in
`journalctl`.  Read the code directly:

```bash
# As root or as the vaiexia user:
cat /var/lib/vaiexia/bootstrap.code
```

### Claim the bootstrap token via `auth.bootstrap.claim`

```bash
CODE=$(cat /var/lib/vaiexia/bootstrap.code)

curl -s -X POST http://127.0.0.1:7443/rpc \
    -H 'Content-Type: application/json' \
    -d "{
      \"jsonrpc\": \"2.0\",
      \"id\": 1,
      \"method\": \"auth.bootstrap.claim\",
      \"params\": {
        \"code\": \"${CODE}\",
        \"admin_name\": \"admin\",
        \"password\": \"your-strong-password-here\"
      }
    }"
```

On success the response contains a `vxs1.<key_id>.<secret>` capability token.
Store it securely — it grants full admin access (`auth.admin`,
`server.read`, `server.logs.read`, `server.services.write`,
`server.packages.write`).

### Bootstrap semantics

- **TTL**: 30 minutes from daemon start.  The code is regenerated automatically
  on expiry.
- **Attempt limit**: 5 failed attempts regenerate the code.  Check
  `/var/lib/vaiexia/bootstrap.code` for the new value.
- **Post-claim**: the code file is deleted and bootstrap is permanently disabled
  until the store is empty again.

### Recovery: reset admin

If admin access is lost, clear accounts and regenerate the bootstrap code:

```bash
vaiexia-server reset-admin --config /etc/vaiexia/server.toml
systemctl restart vaiexia-server
```

Then re-read `/var/lib/vaiexia/bootstrap.code` and claim again.

---

## 8. Audit Trail

### Location and rotation

The audit trail is written to:

```
/var/lib/vaiexia/audit/audit.jsonl
```

(Override with `[audit] dir = "/path/to/audit"` in the config.)

When `audit.jsonl` reaches `max_bytes` (default 8 MiB) it is rotated:

```
audit.jsonl        ← current (active)
audit.jsonl.1      ← previous
audit.jsonl.2      ← older
audit.jsonl.3      ← oldest kept
```

Older generations are deleted.  The chain links **across** files: the first
record of the new file has `prev` set to the last-line hash of the rotated
file, so each file verifies standalone and the cross-file link is also encoded
in the record.

### Schema v1 field reference

Each line is a JSON object.  Required fields are always present; optional
fields are omitted (not null) when not applicable.

| Field           | Type   | Required | Description |
|-----------------|--------|----------|-------------|
| `schema_version`| int    | yes      | Always `1` in v1 |
| `seq`           | uint64 | yes      | Monotonic sequence number (never resets across restarts) |
| `prev`          | string | yes      | First 16 hex chars of the BLAKE3 hash of the preceding line (genesis: `"0000000000000000"`) |
| `ts_wall`       | uint64 | yes      | Unix timestamp (seconds) |
| `kind`          | string | yes      | Event kind (see below) |
| `severity`      | string | yes      | `info` \| `notice` \| `warning` \| `security` |
| `decision`      | string | yes      | `allow` \| `deny` \| `ok` \| `err` |
| `subject`       | string | yes      | Account subject id (`user:admin`) or `anonymous` / `system` / `audit`.  Never the internal `cap:` handle. |
| `cap_key_id`    | string | no       | Loggable capability handle.  Never the secret. |
| `peer`          | string | no       | Remote address.  Reserved in v1 (empty — core does not expose peer to verifier/handlers; schema-stable for a future core additive). |
| `transport`     | string | no       | `http` \| `tls`.  Populated on `listener` events; empty per-request in v1. |
| `method`        | string | no       | RPC method name |
| `topic`         | string | no       | Subscription topic (for `topic_decision` events) |
| `request_id`    | string | no       | Correlation id.  Reserved in v1 (empty — core does not expose `Request.id` to handlers; schema-stable). |
| `reason_code`   | string | no       | Stable reason vocabulary (see below) |
| `detail`        | string | no       | Sanitized free-form detail (control chars stripped, max 1024 bytes) |
| `latency_us`    | uint64 | no       | Handler or privd round-trip latency in microseconds |

### Event kinds

| `kind`            | When emitted |
|-------------------|--------------|
| `auth_decision`   | Every `verify()` call: login, token verification |
| `topic_decision`  | Every `verify_topic()` call: log subscribe allow AND deny |
| `scope_decision`  | Scope check: always on deny; also on allow for `server.logs.query` (sensitive read) |
| `mutation`        | State-changing handler (services start/stop/restart, packages, token create/revoke) |
| `priv`            | Daemon-to-privd round trip (verb, outcome, latency) |
| `bootstrap`       | Bootstrap claim allow or deny |
| `lifecycle`       | Daemon start and shutdown |
| `config`          | Config loaded at startup |
| `listener`        | Listener bind/start/stop |
| `rate_limit`      | Rate-limit trip (login or bootstrap) |
| `degraded`        | Backend provider absent at startup |
| `job`             | Package install/remove job: start, succeed, fail, timeout |
| `audit_loss`      | Writer-emitted when events were dropped under queue overflow |

### Reason code vocabulary

`ok`, `bad_token`, `revoked`, `expired`, `missing_scope`, `unknown_topic`,
`rate_limited`, `bad_password`, `unknown_account`, `sensitive_read`,
`timeout`, `internal`.

Reason codes `bad_password` and `unknown_account` appear in the **audit log
only** — the wire response is uniform to prevent oracle attacks.

### Sensitive read auditing

`server.logs.query` and `server.logs` subscribe are audited even on **allow**
(`severity: notice`, `reason_code: sensitive_read`) because log content can
contain secrets.

### What `seq` and `prev` give you

- **`seq` gaps**: a missing or inserted record is immediately visible as a
  sequence number gap.
- **`prev` chain**: editing any line changes its hash, breaking all subsequent
  `prev` links.
- Together these give **tamper evidence**: edits, truncation, and loss are all
  detectable.

**Important:** the chain is tamper-*evident*, not tamper-*proof*.  An attacker
with write access to the file AND knowledge of the BLAKE3 scheme can re-chain
from the edit point forward.  True tamper-proofing requires shipping records
off-box before the attacker arrives.  See [THREAT-MODEL.md](THREAT-MODEL.md)
for the full discussion.

**Interim guidance:** ship `audit.jsonl*` off-box with your existing log
infrastructure (Filebeat, Fluentd, Vector, `journald` forwarding, etc.).  The
`AuditSink` trait is the designed seam for a future `ForwardingAuditSink`
(syslog/remote); it is not implemented in v1.

### Verify the chain

Chain verification is exposed as a library function
(`vaiexia_server::audit::verify_chain`).  An operator CLI wrapper is future
work.  To verify from a Rust test or custom tooling:

```rust
use vaiexia_server::audit::verify_chain;
let count = verify_chain(std::path::Path::new("/var/lib/vaiexia/audit/audit.jsonl"))?;
println!("verified {count} records");
```

---

## 9. Security CI Gates

The following gates must pass before any release.  Commands are shown as they
run on a nightly Linux CI host.

### Supply-chain check (`cargo deny`)

```bash
cargo deny check
```

Checks advisories (yanked crates), banned duplicate versions, wildcard
dependencies, license allowlist, and source registry policy against
`deny.toml` at the workspace root.  CI-gated — run `cargo install cargo-deny
--locked` to run it locally.

### Fuzz targets (nightly CI only)

Seven fuzz targets cover all attacker-facing parsers.  Each requires the
nightly toolchain and `cargo-fuzz`:

```bash
cargo +nightly fuzz run package_name -- -runs=200000
cargo +nightly fuzz run unit_name    -- -runs=200000
cargo +nightly fuzz run journal_line -- -runs=200000
cargo +nightly fuzz run priv_request -- -runs=200000
cargo +nightly fuzz run token_parse  -- -runs=200000
cargo +nightly fuzz run pkg_list     -- -runs=200000
cargo +nightly fuzz run audit_chain  -- -runs=200000
```

Fuzz targets live in `crates/vaiexia-server/fuzz/` (own workspace; not a
member of the main workspace).  Run them from that directory or pass `-p
vaiexia-server-fuzz` to cargo-fuzz.  These targets are **CI-gated** — a
stable toolchain cannot run them.  A portable adversarial corpus test
(`crates/vaiexia-server/tests/adversarial_corpus.rs`) covers the same parsers
on stable and runs on every `cargo test`.

### systemd unit verification (Linux CI only)

```bash
systemd-analyze verify /etc/systemd/system/vaiexia-server.service
```

This is a live systemd check and must run on a real systemd host.  It is
**CI-gated** — not runnable on the Windows dev host.

### Config validation (any host with the binary)

```bash
vaiexia-server --check-config --config /etc/vaiexia/server.toml
```

Exit 0 = valid.  This also runs as `ExecStartPre` in the systemd unit on
every daemon start.
