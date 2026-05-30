# ADR 0032 — guest-IP discovery from the libvirt lease for SSH tests

**Status:** Accepted (2026-05-30) · **Issue:** #103 · **Epic:** #100 · **Depends on:** #102 (ADR 0031) ·
**Affects:** `src/kdive/providers/libvirt_qemu.py` (`parse_domifaddr_ipv4`,
`BootPlan.domifaddr_argv`, `LibvirtQemuProvider.__init__` poll/sleep params, `execute_boot` success
branch), `src/kdive/server.py` (`target_run_tests_handler` override gate,
`_ssh_host_is_unset_or_loopback`).
Spec: [2026-05-30-guest-ip-lease-discovery.md](../specs/2026-05-30-guest-ip-lease-discovery.md).

## Context

#103 (child of first-run-readiness epic #100, following #102/ADR 0031 which made the default image
SSH-capable) removes the last manual step in the default boot→test path. A `qemu:///system` guest on the
default NAT network is reachable only at its `192.168.122.x` DHCP lease address, but `target.run_tests`
SSHes to the static `rootfs_profile.ssh_host` (`127.0.0.1` for `minimal`). The boot step is the only
component that knows the libvirt domain name and URI, so it is where the lease can be read. The decisions
below are the ones #103 leaves open and that have viable alternatives.

## Decision

### 1. The boot provider discovers the IP; run_tests owns host-selection policy

`LibvirtQemuProvider.execute_boot` discovers the guest IP on the success branch and surfaces it as a
boot-result **fact** (`details["guest_ip"]` + `details["guest_ip_discovery"]`). It does not know about
`ssh_host` override rules. `target_run_tests_handler` reads that fact from the persisted boot
`StepResult.details` and decides whether to substitute it for `ssh_host`. This keeps libvirt *mechanism*
(read the lease) separate from SSH-targeting *policy* (when does a discovered address win over a configured
one), mirrors the provider/handler split ADR 0031 established, and means a future non-libvirt boot provider
that surfaces `guest_ip` the same way reuses the run_tests gate unchanged.

### 2. Source the address from the lease, parsed host-side; first routable IPv4 wins

Discovery runs `virsh domifaddr <domain> --source lease` and parses the tabular output with a pure
`parse_domifaddr_ipv4` function that returns the first IPv4 address that is not loopback, link-local, or
unspecified. `--source lease` is the default-NAT mechanism named in the issue; it needs no guest agent.
The parser is total (skips malformed/short rows, never raises) and validates every candidate with
`ipaddress.IPv4Address`, so a stray `127.0.0.1`/`169.254.x` row or garbage never becomes an SSH target.

### 3. Discovery is best-effort; it never downgrades a successful boot

A boot that reached the readiness marker is a success. Discovery is wrapped (broad catch → log with
traceback → typed status), mirroring `_capture_kernel_provenance`, so no discovery defect or `virsh`
failure can turn a good boot `FAILED`. The outcome is reported as `guest_ip_discovery.status` ∈
`{found, no_lease, unavailable}`. `no_lease`/`unavailable` leave `guest_ip` null; `run_tests` against a
loopback host then fails to connect exactly as today (no regression) but with a machine-readable reason.

### 4. Bounded poll for lease registration, with an injectable clock and a bounded per-call timeout

The readiness marker can precede DHCP-lease registration, so discovery polls up to
`lease_discovery_attempts` times (default 8) with `lease_discovery_interval` seconds between (default 1.0),
stopping at the first routable IPv4. The attempt count, interval, and a `sleep` seam are
`LibvirtQemuProvider.__init__` parameters so unit tests exercise the poll with zero real delay. A
non-zero-exit `domifaddr` stops the poll immediately (the domain is gone — nothing to wait for) and reports
`unavailable`. Each `domifaddr` invocation uses its own short timeout (`lease_discovery_call_timeout`,
default 5 s), **not** the boot `plan.timeout_seconds` (up to 300 s) the define/start/console calls use, so a
hung `virsh` costs at most the per-call timeout per attempt and cannot stall the boot — which matters
because the poll runs while `boot_lock` + `target_lock` are held. Worst-case wall-clock is
`attempts × (interval + call_timeout)`.

### 4a. Discovery is gated on SSH relevance

`run_tests` is the only `guest_ip` consumer and rejects any non-SSH rootfs profile
(`plan_tests` requires `access_method in {"ssh", "ssh_and_serial"}`). So discovery runs only when the
boot's rootfs profile is SSH-relevant; for `serial`/`none` profiles it is skipped
(`guest_ip_discovery.status = "skipped"`, `guest_ip` null) rather than spending the poll budget on a value
nothing reads. The provider already holds `rootfs_profile` in `plan_boot`, so the gate is a plan-time
boolean (`BootPlan.discover_guest_ip`).

### 5. The override is in-memory only; the manifest stays immutable; staleness is tolerated

`run_tests` applies the discovered IP with `model_copy(update={"ssh_host": ...})` on a per-invocation
profile copy. It does not write the discovered address back into the manifest's frozen `RunRequest` or the
boot attempt's recorded `resolved_rootfs_profile`. The discovered runtime fact (boot `details["guest_ip"]`)
and the configured profile stay separate, and the manifest-immutability invariant is preserved.

Because `guest_ip` is a point-in-time lease fact and the boot short-circuit does not re-discover (it stays
cheap/side-effect-free), a persisted `guest_ip` can go stale across a restart or lease renewal. This is
tolerated by design: SSH key auth + per-run empty `known_hosts` + `StrictHostKeyChecking=accept-new` means
a stale address that now hosts a *different* VM fails to authenticate rather than running tests against the
wrong target, so the worst case degrades to "tests fail to connect" (the same observable as `no_lease`).
The recovery contract is `force_reboot` (re-boot re-discovers a fresh `guest_ip`). See the spec's
"Lease staleness" section.

### 6. "Unset or loopback" is the override trigger; everything else is an explicit override

`_ssh_host_is_unset_or_loopback(host)` returns `True` for `None`/empty, `"localhost"`, and any IP whose
`ipaddress.ip_address(...).is_loopback` holds (`127.0.0.0/8`, `::1`). Any other value — a routable IP or a
non-IP DNS name (`bastion.example`) — is treated as a deliberate operator override and preserved. This
honours the issue's "preserve an explicit `ssh_host` override for port-forwarded setups" while still
overriding the `minimal` default (`127.0.0.1`) and an unset host.

### 7. run_tests re-validates the persisted IP before trusting it as an SSH host

Even though the provider's parser validated the address at write time, `run_tests` re-validates
`guest_ip` with `ipaddress.ip_address(...)` (non-loopback/non-link-local) before substituting it into an
SSH argv, and ignores a value that fails (using the original `ssh_host` and logging a warning). The
persisted manifest is host-controlled state that could be corrupted or tampered with between boot and
test; re-validation at the point of use keeps the SSH argv injection-free regardless. Defense in depth, no
trust in persisted strings reaching a subprocess argv.

### 8. No wire-model change

`guest_ip`/`guest_ip_discovery` ride the existing free-form `StepResult.details` dict (already
provider-populated and redacted), and the override consumes an existing field (`RootfsProfile.ssh_host`).
No `domain.py` model gains a field, so there is no JSON-schema snapshot to regenerate and no frozen
manifest is affected.

## Consequences

- A clean machine runs `smoke-basic` against the default `minimal` rootfs on a default-NAT guest with no
  `ssh_host` override — the last manual step in epic #100's boot→test path is gone.
- `BootPlan` gains `domifaddr_argv`; `LibvirtQemuProvider.__init__` gains poll/sleep params; provider unit
  tests and the `FakeLibvirtRunner` adapt to answer `domifaddr`.
- A boot on a network with no lease (or `qemu:///session` SLIRP, which has no lease file) still SUCCEEDS;
  the agent sees `guest_ip_discovery.status` and either sets an explicit `ssh_host` (port-forward) or
  retries once the lease registers.
- Worst-case boot latency grows by up to `attempts × interval` (~7 s) only when the lease never appears;
  the common case returns on the first `found`.
- Persisted `guest_ip` is treated as untrusted at the run_tests boundary (decision 7), so a corrupted
  manifest degrades to today's behavior rather than injecting a bad SSH target.

## Considered & rejected

1. **Rewrite `ssh_host` inside the recorded `resolved_rootfs_profile` at boot time.** Rejected: it
   conflates the configured profile with a discovered runtime fact, mutates a record the manifest treats as
   the resolved-at-boot snapshot, and bakes host-selection policy into the boot provider. Surfacing the IP
   as a separate `details` fact and applying the override at consumption keeps mechanism and policy split
   and the manifest honest. (decisions 1, 5)
2. **Discover the IP inside `run_tests` instead of at boot.** Rejected: `run_tests` does not hold the
   libvirt URI/domain (it works off the rootfs/test profiles), discovery would re-run on every `run_tests`
   retry, and a second consumer (`debug.start_session`) would duplicate it. Boot is the single
   domain-aware producer; the IP is recorded once. (decision 1)
3. **Add a dedicated `guest_ip` field to a wire model (`BootResult`/`StepResult`).** Rejected as schema
   churn: `details` already carries provider-specific facts through the same redaction path, and a new
   typed field would force a JSON-schema snapshot bump and touch frozen-manifest compatibility for a value
   only two handlers read. (decision 8)
4. **Use `--source agent` (qemu-guest-agent) or `--source arp`.** Rejected: `agent` requires the guest
   agent installed and running (the `minimal` builder does not), and `arp` only sees addresses the host has
   already talked to (a chicken-and-egg before first contact). `lease` is the reliable default-NAT source
   and is what the issue specifies. (decision 2)
5. **Fail the boot (or emit a warning-status boot) when no lease is found.** Rejected: the boot demonstrably
   succeeded (the marker was reached); a missing lease is a networking/timing condition, not a boot failure,
   and conflating them would make `qemu:///session` and slow-DHCP guests spuriously fail. Best-effort with a
   typed status preserves the success signal and still tells the agent what happened. (decision 3)
6. **Single `domifaddr` call, no poll.** Rejected: the lease is frequently not yet registered at the instant
   the readiness marker fires, so a single call would usually return `no_lease` and defeat the feature. A
   short bounded poll with an injectable clock is robust without making tests slow. (decision 4)
7. **Treat any set `ssh_host` (including `127.0.0.1`) as an override and never substitute.** Rejected: the
   shipped default `minimal` profile sets `ssh_host="127.0.0.1"`, so "any set value wins" would never fire
   for the default and the feature would do nothing out of the box. Loopback/unset is the correct trigger;
   only a *routable* or DNS host signals a deliberate operator choice. (decision 6)
8. **Trust the persisted `guest_ip` and skip re-validation in run_tests.** Rejected: the value transits the
   on-disk manifest (host-controlled, potentially corrupted) before reaching a subprocess argv;
   re-validating at the point of use is cheap defense in depth and keeps the SSH argv injection-free without
   relying on the writer having been the only path. (decision 7)
