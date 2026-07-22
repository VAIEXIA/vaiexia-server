# VAIEXIA Server — Threat Model

This document describes the security design of the `vaiexia-server` daemon
and its privilege-separated helper `vaiexia-privd`, the attacker classes they
defend against, the mitigations in place, and the explicit residual risks that
remain unmitigated in v1.

---

## Attacker Classes and Mitigations

### 1. Unauthenticated network attacker

**Goal:** gain daemon access without credentials.

**Mitigations:**

- **Scoped `vxs1` tokens**: every request must carry a `vxs1.<key_id>.<secret>`
  capability token.  Tokens are verified with constant-time BLAKE3 comparison
  against the stored hash; no timing oracle is possible.
- **Bootstrap TTL and attempt limit**: first-run admin access requires reading a
  32-byte random code from `/var/lib/vaiexia/bootstrap.code` (mode 0600,
  `vaiexia` owned).  The window is 30 minutes; after 5 failed attempts the code
  is regenerated.  The path is logged, never the code.
- **Default loopback posture**: the shipped default config binds on
  `127.0.0.1:7443`, reachable only through a WireGuard tunnel or local reverse
  proxy.  Direct-network exposure requires opting into the `https` listener
  with an operator-supplied cert and key.

### 2. Authenticated but under-privileged attacker

**Goal:** escalate scope beyond the granted capability.

**Mitigations:**

- **Scoped capabilities**: each `vxs1` token carries an explicit scope list
  (`server.read`, `server.logs.read`, `server.services.write`,
  `server.packages.write`, `auth.admin`).  The scope check runs in
  `register_scoped` before any handler executes.
- **Scope denial always audited**: every scope miss is recorded as a
  `scope_decision` deny event (`reason_code: missing_scope`) in the audit log.
- **Sensitive read audited on allow**: `server.logs.query` and `server.logs`
  subscribe are also recorded on allow (`reason_code: sensitive_read`,
  `severity: notice`) because log content can leak secrets.

### 3. Credential-brute-force attacker (login / bootstrap)

**Goal:** guess a password or bootstrap code.

**Mitigations:**

- **Argon2id password hashing**: account passwords are stored as PHC-format
  argon2id hashes.
- **Login rate limiting**: repeated login failures trip the rate limiter; the
  trip is recorded as a `rate_limit` event (`severity: security`).  The wire
  response is uniform — the audit log may distinguish `bad_password` from
  `unknown_account`; the wire never does (no oracle).
- **Bootstrap attempt limit and code regeneration**: 5 failed attempts
  regenerate the code and emit a `rate_limit` event.

### 4. Input/injection attacker

**Goal:** corrupt the daemon state or escape validation through malformed input.

**Mitigations:**

- **Validated newtypes**: package names (`PackageName`) and unit names
  (`UnitName`) are validated newtypes.  Invalid values are rejected before
  reaching any handler or privd.
- **`--` guards on subprocess invocations**: shell-injection via package or unit
  names is structurally prevented by validated newtypes and typed dispatch.
- **Audit field sanitization**: all string fields in audit records have control
  characters replaced with spaces and are capped at 1024 bytes.  A hostile
  parameter cannot inject fake log lines or bloat the audit file.
- **Fuzz-tested parsers**: all attacker-facing parsers (package name, unit name,
  journal line, privd request frame, token parse, pkg-list, audit chain) are
  covered by seven cargo-fuzz targets that run 200,000 iterations each on
  nightly CI.  A portable adversarial corpus test runs on every `cargo test`.

### 5. Compromised daemon (post-exploit containment)

**Goal:** use the running daemon process to escalate to root or install attacker
packages.

**Mitigations:**

- **Non-root daemon**: the daemon runs as the `vaiexia` system user
  (`User=vaiexia` in the unit).
- **Empty `CapabilityBoundingSet`**: the daemon holds no Linux capabilities.
- **Full `SystemCallFilter=@system-service`**: the daemon is restricted to the
  systemd `@system-service` syscall group.
- **`privd` closed verb vocabulary**: the daemon communicates with privd over a
  typed `PrivRequest` struct.  There is no generic exec — privd can only run
  the verbs it was designed for.
- **`SO_PEERCRED` uid gate**: privd refuses connections from any process whose
  uid does not match `VAIEXIA_DAEMON_UID`.
- **In-privd `PackageName` re-validation**: package names are validated
  independently inside privd, independently of the daemon's validation.
- **Operator package allowlist** (`/etc/vaiexia/pkg-allowlist`): when present,
  only the listed packages may be installed or removed.  A compromised daemon
  cannot direct root-privd at an arbitrary attacker package.  Absent = any
  valid package name (default); present = only listed packages; empty file =
  deny all.  Invalid allowlist lines are skipped (fail-closed narrowing).
  See INSTALL.md §3.
- **Single job + hard timeout**: privd serializes all package operations and
  enforces a hard timeout per job.
- **Polkit scoped rule**: the daemon can only call `start`, `stop`, and
  `restart` on units outside the denylist of its own privilege-boundary units.
  The allowlist variant restricts this further to an enumerated set.

### 6. Supply-chain attacker

**Goal:** introduce a malicious dependency.

**Mitigations:**

- **`cargo deny`**: a `deny.toml` at the workspace root enforces the
  advisory database (yanked crates denied), a license allowlist (MIT, Apache-2.0,
  BSD-2-Clause, BSD-3-Clause, ISC, and a small set of named exceptions), ban on
  wildcard version requirements, and restriction to the crates.io registry.
  This check is a required CI gate before any release.
- **`rustls` for TLS**: no OpenSSL in the TLS stack.

### 7. Log tamper / forensic attacker

**Goal:** erase or alter audit evidence after a compromise.

**Mitigations:**

- **BLAKE3 hash chain**: every audit record carries `seq` (monotonic) and
  `prev` (first 16 hex chars of the BLAKE3 hash of the preceding line).
  Editing any line breaks all subsequent `prev` links; deleting a line creates
  a `seq` gap.  See the next section for the honest limits of this.

---

## Audit: Tamper-Evident vs Tamper-Proof

The BLAKE3 line chain makes the audit trail **tamper-evident**:

- Any edit to a record breaks the chain from that point forward.
- Any deleted record creates a visible `seq` gap.
- Any truncation ends the chain.
- Overflow (queue full) is recorded in the log itself as an `audit_loss` event
  with a `dropped=N` count.

**What the chain is NOT:** it is not tamper-proof.  An attacker who already
has write access to the audit file AND knows the hashing scheme can re-chain
from the edit point forward, producing a plausible-looking file.  64-bit
BLAKE3 truncation is ample for an append-only operator log but is not a
signature scheme and provides no asymmetric non-repudiation.

**True tamper-proofing = getting records off-box before the attacker arrives.**

The `AuditSink` trait (`emit` + `shutdown`) is the designed seam for this.
Every call site holds a `DynAuditSink = Arc<dyn AuditSink>`.  A future
`ForwardingAuditSink` that ships to syslog or a remote SIEM implements the
same trait and drops in without touching any call site or audit record format.
That forwarding sink is **not implemented in v1**.

**Interim operator guidance:** ship `audit.jsonl*` off-box with your existing
log infrastructure (Filebeat, Fluentd, Vector, journald forwarding, or any
syslog shipper).  The schema is stable JSONL (one record per line); no special
parser is needed to ingest it.

**Sensitive read auditing on ALLOW:** `server.logs.query` (query handler) and
`server.logs` subscribe are audited even when access is granted (`scope_decision`
allow, `reason_code: sensitive_read`, `severity: notice`).  Log content can
include error messages, stack traces, and other material that leaks internal
state; the spec (§4) requires recording who read it.

---

## Privilege Split: Why privd Has No seccomp

The system runs with an **asymmetric sandbox**:

| Component          | User  | Capabilities         | syscall filter                    |
|--------------------|-------|----------------------|-----------------------------------|
| `vaiexia-server`   | vaiexia (non-root) | `CapabilityBoundingSet=` (empty) | `SystemCallFilter=@system-service` |
| `vaiexia-privd`    | root  | (no drop)            | **none**                          |

**Why the daemon gets a tight sandbox:** it does not need root, does not need
any Linux capability, and the full `@system-service` filter covers everything
the Tokio async runtime requires.

**Why privd has NO `SystemCallFilter`:** package managers (`apt`, `dnf`,
`pacman`, and others) and the maintainer scripts they execute are not
controlled by VAIEXIA.  Those scripts invoke arbitrary syscalls — `ptrace`,
`personality`, `unshare`, and others that are outside `@system-service`.  A
seccomp filter on privd would cause silent install failures for legitimate
packages.  The filter is flagged as a potential future CI-tuned addition once
the syscall surface of the target distribution's package manager is known; it
is not shipped blind.

**privd's containment layers, in order:**

1. **Closed verb vocabulary** (`PrivRequest` typed enum): privd cannot execute
   an arbitrary command.  The only operations it can perform are those
   explicitly defined in the request schema.
2. **`SO_PEERCRED` uid gate**: privd reads the uid of the connecting process
   from the Unix socket credentials and refuses any uid that does not match
   `VAIEXIA_DAEMON_UID`.
3. **In-privd `PackageName` re-validation**: package names are re-parsed inside
   privd independently of the daemon — defense in depth.
4. **Operator package allowlist** (`/etc/vaiexia/pkg-allowlist`, fail-closed
   when present): bounds what a fully compromised daemon can make root install
   or remove.
5. **Single job + hard timeout**: privd serializes all jobs.  One job at a
   time; each has a hard timeout.
6. **Compatible systemd sandbox directives** (`NoNewPrivileges=true`,
   `ProtectHome=true`, `ProtectSystem=strict`, `PrivateTmp=true`,
   `RestrictRealtime=true`, `LockPersonality=true`,
   `SystemCallArchitectures=native`): defense in depth compatible with package
   manager execution.  `ReadWritePaths=/var /usr /etc /boot /opt` is wide by
   necessity — package managers write broadly.

**Scope set is spec-locked:** the five admin scopes granted on bootstrap
(`server.read`, `server.logs.read`, `server.services.write`,
`server.packages.write`, `auth.admin`) are defined in
`crates/vaiexia-server/src/auth/bootstrap.rs` and are stable.
The `server.logs.read` scope covers both query and subscribe;
the sensitive-read audit policy (`ScopeAudit::AuditAllow` on
`server.logs.query`, `TopicDecision`-allow on subscribe) stays coherent with
the scope set.

---

## Explicit Residual Risks (v1)

The following risks are known, documented, and explicitly deferred or
acknowledged.  They are NOT silently accepted.

| Risk | Status |
|------|--------|
| **obfs listeners** | Deferred.  The subscription-authz gap (§5.4) and lack of real-DPI validation mean obfs listeners are not included in v1. |
| **mTLS client auth** (`client_ca_pem`) | Reserved in core; not wired in v1.  The config key is accepted but has no effect. |
| **Certificate hot-reload** | Not supported.  Rotating a cert requires `systemctl restart vaiexia-server`.  A core additive is needed to watch the cert path. |
| **Live systemd / journald / privd / polkit behavior** | CI-gated.  The packaging artifacts are structurally tested on the dev host; runtime behavior (socket activation, polkit enforcement, privd dispatch, sd_notify readiness) is verified only on a real Linux/systemd CI host. |
| **Replay defense** | Encrypted transport only (TLS or WireGuard).  The `request_id` field in audit records is a correlation id, not a replay nonce.  Core does not expose `Request.id` to verifier/handlers in v1. |
| **privd `LISTEN_PID` check** | Not checked.  systemd sets `LISTEN_PID` and `LISTEN_FDS` correctly under socket activation; not checking it is benign in this deployment but is noted for completeness. |
| **`last_used` display lag** | The identity store debounces `last_used` touches by 60 seconds.  The displayed `last_used` timestamp may lag by up to 60 s.  This is a confirmed design decision (not a bug). |
| **`request_id` and `peer` empty in v1** | Core does not expose `Request.id` or the remote peer address to verifier/handler call sites.  The schema fields are reserved and will be populated when a core additive threads them through.  Until then, filtering audit records by `request_id` will return no results. |
| **Per-request `transport` field** | Populated only on `listener` events.  Per-request transport is empty in v1 for the same core-limitation reason. |
| **`ForwardingAuditSink`** | The `AuditSink` trait is the designed seam for off-box shipping (syslog/remote); the forwarding implementation is not in v1.  Operators must use external log shippers until it lands. |
| **privd package allowlist and polkit rules applied at start** | Both are read once at service startup.  Changes to `/etc/vaiexia/pkg-allowlist` or to the polkit rule require `systemctl restart vaiexia-privd.service` (allowlist) or a polkit rescan (rules, automatic). |
| **Audit queue overflow** | If the request rate exceeds the audit writer's throughput, events are dropped.  Each drop is counted atomically and recorded in the next `audit_loss` event.  The queue is bounded at `audit.queue` (default 1024 entries); `emit()` never blocks, never delays a request. |

---

## Default Posture and When to Use `serve_tls`

**Default (recommended):** bind on `127.0.0.1:7443` (HTTP) and expose the
daemon only through a WireGuard tunnel or a local reverse proxy that handles
TLS.  This is the correct posture for VPN gateway deployments where WireGuard
is already the transport-layer security boundary.

**When to use `serve_tls` (`kind = "https"`):** when the daemon must be
directly reachable from the network without a proxy (e.g. a standalone server
that is not the WireGuard gateway).  In this mode:

- The cert and key are read at startup (fail-closed: a missing or unreadable
  cert prevents the daemon from starting).
- rustls is used; OpenSSL is not in the TLS stack.
- Certificate rotation requires a restart.
- The daemon is now directly internet-facing; consider also enabling the
  polkit allowlist variant and the package allowlist.
