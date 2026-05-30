# ADR 0035 — headless serial-console capture via a libvirt `<log>` file

**Status:** Accepted (2026-05-30) · **Epic:** #100 · **Affects:**
`src/kdive/providers/libvirt_qemu.py` (`render_domain_xml` adds a serial `<log>`;
`SubprocessLibvirtRunner.stream_console` tails the log file instead of running `virsh console`).

## Context

`SubprocessLibvirtRunner.stream_console` captured guest serial output by spawning
`virsh console --force <domain>` and reading its stdout. `virsh console` is an interactive
client: it requires a controlling TTY and aborts with `Cannot run interactive console without a
controlling TTY` when stdin is not a terminal. The MCP server runs headless (stdio, driven by an
agent; no TTY), so every `target.boot` failed console capture with `readiness_failure` even though
the domain defined, started, and ran correctly. This was found driving the epic-#100 dcache
acceptance run: the boot reached `running` but the readiness/crash output was never captured.

A second, latent defect in the old mechanism: `virsh console` attaches *after* the domain starts,
so early-boot output (including an early oops/panic) printed before attach is lost. The dcache
`dhash_entries=1` crash happens within the first second of boot — exactly the window `virsh console`
misses.

## Decision

### 1. libvirt writes the serial log to a file; the runner tails that file

`render_domain_xml` adds `<log file="<console_log_path>" append="off"/>` to the `<serial>` device.
libvirt (virtlogd) tees the serial chardev to that file from domain start, with no TTY involved and
no lost early output. `stream_console` no longer spawns `virsh console`; it tails the same file for
the readiness marker, returning the same `ConsoleResult` (`ready` / `timeout` / `exited`).

The `console_log_path` artifact is unchanged — libvirt now writes it instead of the runner, so the
`console-log` artifact contract and the redacted-snippet response field are preserved.

### 2. Domain liveness is polled via `virsh domstate`, replacing child-process `poll()`

The old code detected guest exit from the `virsh console` child exiting. With no child, the runner
polls `virsh domstate <domain>` (~once/second) and reports `exited` when the domain is no longer
`running`, after a final drain of the log file so output written just before shutdown is not lost.
Marker detection and the deadline/timeout path are otherwise unchanged.

### 3. The pty serial/console devices stay

`<serial type="pty">` and `<console type="pty">` remain so an operator can still `virsh console`
interactively for ad-hoc debugging. The `<log>` is additive: the automated path tails the file, the
human path still has a live pty.

## Consequences

- `target.boot` captures serial output headlessly; the dcache crash is recorded on the first attempt.
- Early-boot output is captured (the log is live from start), fixing the lost-early-oops gap.
- Under `qemu:///session` virtlogd runs as the invoking user and writes the log into the run dir
  without extra setup. Under `qemu:///system` the log is written by the root virtlogd; the separate
  qemu-process read-access constraint on the kernel/disk (already documented) is unaffected by this
  change.
- The interactive `virsh console` code path (Popen, selector, `_read_console_line`,
  `_terminate_process`) is deleted; its four unit tests are replaced by file-tailing tests.

## Considered & rejected

1. **Allocate a pty for `virsh console` (wrap in `script`/`openpty`).** Rejected: keeps the
   attach-after-start race that loses early output, adds a pty-management dependency, and is more
   fragile than letting libvirt write the file. It treats the symptom (no TTY), not the mechanism.
2. **`<serial type="file">` instead of `<serial type="pty"><log>`.** Rejected: a file-type chardev
   removes the live pty, so an operator can no longer attach `virsh console` for interactive
   debugging. The `<log>` subelement captures to a file *and* keeps the pty.
3. **Keep `virsh console` but feed it `/dev/null` stdin / `--safe`.** Rejected: `virsh console`
   still demands a real TTY for its terminal handling; redirecting stdin does not satisfy it, and it
   would still miss early output.
4. **A dedicated serial-log path separate from `console_log_path`.** Rejected: two files for one
   stream complicates the artifact contract for no benefit; pointing libvirt's `<log>` straight at
   `console_log_path` keeps a single source of truth.
