# Guest-IP discovery from the libvirt lease for SSH tests

**Status:** Accepted (2026-05-30) · **Issue:** #103 · **Epic:** #100 (first-run readiness) ·
**ADR:** [0032](../adr/0032-guest-ip-lease-discovery.md) ·
**Depends on:** #102 (SSH-capable default image, ADR 0031)

## Problem

`target.run_tests` SSHes to the static `rootfs_profile.ssh_host`
(`src/kdive/providers/local_ssh_tests.py:260`), which defaults to `127.0.0.1`
(`server.py:294`, the `minimal` profile). A `qemu:///system` guest on the default NAT network
(`virbr0` / `192.168.122.0/24`) receives its address by DHCP and is reachable only at that
`192.168.122.x` lease address — never at `127.0.0.1`, where nothing on the guest is listening from the
host's perspective. So the default end-to-end path (`#102` produces an SSH-capable image; the agent
boots it) still cannot run a single test: the agent must manually discover the guest's IP (e.g. by
running `virsh domifaddr` itself) and inject it via a `ssh_host` override before `target.run_tests`
connects. That manual step is exactly what epic #100 (first-run readiness) exists to remove.

## Goal

After a successful `target.boot` against a default-NAT guest, `target.run_tests` connects to the guest
**with no hand-set IP**: the boot step discovers the guest's IPv4 address from the libvirt lease, records
it on the boot result, and `run_tests` uses it as the SSH host whenever `ssh_host` is unset or loopback.
An operator who *has* set an explicit, non-loopback `ssh_host` (a port-forwarded `qemu:///session`
setup, or a bastion) keeps that value untouched. Concretely: `smoke-basic` passes against a default-NAT
guest booted with the `minimal` rootfs profile and no `ssh_host` override.

Non-goals: `qemu:///session` user-mode SLIRP networking (no lease file; that path is port-forward-only
and is served by the explicit-override branch), IPv6-only guests, multi-NIC address selection policy
beyond "first routable IPv4 lease", and the guest-agent (`--source agent`) / ARP (`--source arp`)
discovery sources. Those stay out of scope; the lease source is the documented default-NAT mechanism.

## Design

### 1. Discovery lives in the boot provider, surfaced as a boot-result fact

The `LibvirtQemuProvider`, on a **successful** boot (console reached the readiness marker) **whose rootfs
profile uses an SSH access method** (`access_method in {"ssh", "ssh_and_serial"}`), runs
`virsh -c <uri> domifaddr <domain> --source lease` and parses the first routable IPv4 address out of the
tabular output. The discovered address is surfaced on `BootExecutionResult.details["guest_ip"]` together
with `details["guest_ip_discovery"]` — a small status record (`{"status": "...", "source": "lease",
...}`) describing how discovery resolved. The provider does **not** know about `ssh_host` override policy;
it reports a domain fact. The host-selection policy lives one layer up, in `target_run_tests_handler`
(decision 3).

Discovery is **gated on SSH relevance** because `run_tests` is the only consumer and it rejects any
non-SSH rootfs profile (`plan_tests` requires `access_method in {"ssh", "ssh_and_serial"}`,
`local_ssh_tests.py:280-281`). A `serial`/`none` profile would never read `guest_ip`, so spending the
poll budget on it is pure waste; for those profiles discovery is skipped and `guest_ip_discovery.status`
is `skipped` (`guest_ip` null). This keeps the common SSH path's behavior unchanged while not stalling
serial-only boots up to the poll budget for a value nothing reads.

The `domifaddr` invocation uses a **short, bounded per-call timeout** (`lease_discovery_call_timeout`, a
`LibvirtQemuProvider.__init__` parameter, default 5 s) — **not** the boot `plan.timeout_seconds` (up to
300 s) that the define/start/console calls use. A hung `virsh domifaddr` therefore costs at most that
per-call timeout per attempt, not the full boot timeout, so the poll's worst-case wall-clock is
`attempts × (interval + call_timeout)` rather than unbounded. This matters because the poll runs inside
`boot_lock` + `target_lock`; bounding the per-call timeout keeps those locks from being held on a
misbehaving libvirtd.

`virsh domifaddr` tabular output looks like:

```
 Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
 vnet0      52:54:00:1a:2b:3c    ipv4         192.168.122.45/24
```

The parser (`parse_domifaddr_ipv4`, a pure module-level function) scans data rows, selects rows whose
protocol column is `ipv4`, strips the `/prefix`, validates each candidate with `ipaddress.IPv4Address`,
and returns the **first address that is not loopback, link-local, or unspecified** (so a stray
`127.0.0.1` or `169.254.x` never wins). It returns `None` when no such row exists (e.g. the lease has not
yet been registered). The parser is total: malformed/short rows are skipped, never raised.

### 2. Discovery is best-effort and never fails an otherwise-good boot

A boot that reached the readiness marker is a success regardless of IP discovery. Discovery is wrapped so
that **no** discovery outcome can downgrade that success, mirroring the existing
`_capture_kernel_provenance` pattern in `target_boot_handler` (broad catch → log with traceback → record
a typed status field). The `guest_ip_discovery` status is one of:

- `found` — a routable IPv4 lease was parsed; `guest_ip` is set.
- `no_lease` — `virsh domifaddr` ran (exit 0) but no routable IPv4 row was present after the bounded
  poll; `guest_ip` is `null`.
- `unavailable` — `virsh domifaddr` failed (non-zero exit / timed out) or `virsh` is missing;
  `guest_ip` is `null`. The (redacted) stderr snippet rides `guest_ip_discovery["detail"]`.
- `skipped` — the rootfs profile is not SSH-relevant (decision 1), so discovery did not run; `guest_ip`
  is `null`.

In the `no_lease` / `unavailable` cases the boot still returns `SUCCEEDED`; a later `run_tests` against a
loopback `ssh_host` will fail to connect exactly as it does today (no regression), but now the boot result
tells the agent *why* (`guest_ip_discovery.status`) and what to do (the failure path's
`suggested_next_actions` already points at `artifacts.get_manifest`, where the status is visible).

### 3. Bounded poll for lease registration

The readiness marker (`kdive-ready`) can fire a moment before the guest's DHCP lease is
registered in the dnsmasq lease file the provider reads. So discovery polls: up to
`lease_discovery_attempts` calls to `virsh domifaddr`, sleeping `lease_discovery_interval` seconds between
attempts, stopping at the first `found`. Both are `LibvirtQemuProvider.__init__` parameters with
production defaults (`attempts=8`, `interval=1.0` → ~7 s worst case) and an injectable `sleep` seam
(default `time.sleep`) so unit tests drive the poll deterministically with zero real delay. A
non-zero-exit `domifaddr` (domain vanished) stops the poll immediately and reports `unavailable` — there
is nothing to wait for.

### 4. Host selection is a run_tests override gate

`target_run_tests_handler` resolves `resolved_rootfs_profile` from the recorded boot attempt as today.
Before planning tests, it reads `guest_ip` from the persisted boot `StepResult.details`
(`manifest.step_results["boot"].details["guest_ip"]`, surviving a server restart because it is on disk).
If `guest_ip` is a non-empty string **and** the profile's `ssh_host` is unset or loopback, it applies
`resolved_rootfs_profile = resolved_rootfs_profile.model_copy(update={"ssh_host": guest_ip})`. Otherwise
the profile is used unchanged. "Unset or loopback" is decided by a pure helper
`_ssh_host_is_unset_or_loopback(host)`: `True` when `host` is `None`/empty, `"localhost"`, or an IP that
`ipaddress.ip_address(...).is_loopback` (covers `127.0.0.0/8` and `::1`); any other value — including a
non-IP DNS name like `bastion.example` — is treated as an explicit override and preserved.

The override is **in-memory only**: it copies the profile for this `run_tests` invocation and does not
write back to the manifest. The immutable `RunRequest` and the boot attempt's recorded
`resolved_rootfs_profile` are untouched, so the manifest invariant holds and the discovered runtime fact
stays separate from the configured profile.

### 4a. Discovered IP is validated before it is trusted as an SSH host

`guest_ip` originates from `virsh` output, so before `run_tests` substitutes it into an SSH argv it is
re-validated with `ipaddress.ip_address(...)` and required to be non-loopback/non-link-local. A value that
fails validation (corrupt persisted manifest, hostile lease file) is ignored — the profile's original
`ssh_host` is used unchanged and a warning is logged. This keeps the SSH argv free of injected tokens even
if the persisted detail is tampered with, independent of the provider-side parser already having validated
it at write time.

## Failure contract

| Situation | Boot status | `guest_ip` | `guest_ip_discovery.status` | `run_tests` behavior |
|---|---|---|---|---|
| Routable IPv4 lease found | `SUCCEEDED` | the IP | `found` | overrides loopback/unset `ssh_host` with the IP |
| Marker reached, no lease after poll | `SUCCEEDED` | `null` | `no_lease` | loopback `ssh_host` unchanged → connect fails as today |
| `domifaddr` non-zero / timed out / `virsh` absent | `SUCCEEDED` | `null` | `unavailable` | loopback `ssh_host` unchanged → connect fails as today |
| Lease found, explicit non-loopback `ssh_host` set | `SUCCEEDED` | the IP | `found` | explicit `ssh_host` **preserved** (override ignored) |
| Boot never reached marker | `FAILED` (timeout/readiness) | — (discovery skipped) | absent | n/a (run_tests requires a succeeded boot) |
| Marker reached, non-SSH rootfs profile | `SUCCEEDED` | `null` | `skipped` | n/a (run_tests rejects non-SSH profiles) |
| `guest_ip` present but fails re-validation in run_tests | n/a | (ignored) | n/a | original `ssh_host` used; warning logged |

Discovery only runs on the success branch (and only for SSH-relevant profiles), so a failed or
serial-only boot never spends the poll budget.

## Idempotency / short-circuit

`guest_ip` is recorded in the persisted boot `StepResult.details`, so:

- A `target.boot` short-circuit (recorded `SUCCEEDED`, e.g. after a server restart) returns the same
  details including `guest_ip`; `run_tests` still finds it. Re-boot (`force_reboot`) re-discovers and
  records a fresh `guest_ip` for the new attempt.
- `run_tests` reads `guest_ip` fresh from the manifest on every invocation, so a `force_rerun` after a
  re-boot picks up the latest discovered address.

### Lease staleness is intentional, and a connect failure is the recovery signal

`guest_ip` is a **point-in-time** lease fact, and the boot short-circuit deliberately does **not**
re-discover (a short-circuit must stay cheap and side-effect-free — it does not touch libvirt at all).
Across a long-lived run or a server restart the address can therefore go stale: the guest may have
renewed to a different lease, the lease may have expired, or — worst case — that `192.168.122.x` address
may now be held by a *different* guest. `run_tests` then SSHes to a stale/foreign address. The §4a
re-validation only checks the address *shape*, not its *freshness*; freshness is not knowable without
re-querying libvirt, which the short-circuit declines to do.

The recovery contract is therefore: **a connection/auth failure from `run_tests` against a discovered
`guest_ip` means "re-discover" — re-invoke `target.boot` with `force_reboot=True`**, which boots a fresh
attempt and records a current `guest_ip`. This is safe by construction: SSH uses key auth with a
per-run empty `known_hosts` and `StrictHostKeyChecking=accept-new`, so a stale address that now hosts a
*different* VM fails to authenticate rather than running tests against the wrong target. The stale-IP
failure mode degrades to "tests fail to connect" — the same observable as the `no_lease` case — never to
"tests run against a foreign guest". Re-discovering on the short-circuit was considered and rejected
(ADR 0032, rejected alternative 1's sibling reasoning): it would make every `run_tests` after a restart
pay a libvirt round-trip and re-introduce provider knowledge into the short-circuit path.

## Affected code

- `src/kdive/providers/libvirt_qemu.py`: `parse_domifaddr_ipv4` (new), `BootPlan.domifaddr_argv`
  (new field set in `plan_boot`) and `BootPlan.discover_guest_ip` (bool gate from the rootfs access
  method), `LibvirtQemuProvider.__init__` (`sleep`, `lease_discovery_attempts`,
  `lease_discovery_interval`, `lease_discovery_call_timeout` params), `execute_boot` success branch
  (gated poll + surface `guest_ip` / `guest_ip_discovery`).
- `src/kdive/server.py`: `target_run_tests_handler` (read `guest_ip` from boot details, apply
  override via `_ssh_host_is_unset_or_loopback` + re-validation).
- No `domain.py` wire-model change (the new fields ride the free-form `StepResult.details` dict that
  already carries provider details), so no JSON-schema snapshot regeneration.

## Verification

- Unit: `parse_domifaddr_ipv4` over real-shaped output (single/multi-NIC, ipv6 mixed in, headers-only,
  loopback-only, malformed rows, empty).
- Unit: `LibvirtQemuProvider.execute_boot` with a `FakeLibvirtRunner` extended to answer `domifaddr` —
  asserts `guest_ip`/`guest_ip_discovery` for found, no-lease (poll exhausts, sleep called N−1 times via
  the injected seam), `unavailable` (non-zero exit), and `skipped` (non-SSH rootfs profile, `domifaddr`
  never called) cases; asserts boot stays `SUCCEEDED` throughout and discovery is skipped on the
  timeout/readiness-failure branches; asserts the `domifaddr` call uses `lease_discovery_call_timeout`,
  not `plan.timeout_seconds`.
- Unit: `_ssh_host_is_unset_or_loopback` truth table (`None`, `""`, `127.0.0.1`, `127.0.0.2`, `::1`,
  `localhost`, `192.168.122.45`, `bastion.example`).
- Unit: `target_run_tests_handler` with injected boot manifest details — overrides loopback/unset
  `ssh_host`, preserves explicit non-loopback `ssh_host`, ignores a `guest_ip` that fails re-validation,
  and is a no-op when `guest_ip` is absent.
- The env-gated `test_libvirt_boot_integration.py` stays gated; no un-gating.
