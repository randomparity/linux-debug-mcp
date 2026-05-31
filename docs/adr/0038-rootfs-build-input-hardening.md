# 0038 — `build-rootfs.sh` input hardening: username allowlist + output-path canonicalization

**Status:** Accepted

**Date:** 2026-05-30

## Context

The 2026-05-30 technical-debt audit (`docs/audits/2026-05-30-tech-debt-audit.md`,
issue #124) flagged five trust-boundary defects in `scripts/build-rootfs.sh`,
which interpolates untrusted environment variables into a guest shell and into
host filesystem operations:

- **TD-05 (High)** — `KDIVE_ROOTFS_SSH_USER` is interpolated unquoted into a
  `virt-builder --run-command "useradd … ${SSH_USER}"` guest shell → guest
  command injection.
- **TD-37 (Medium)** — the same value is embedded in the colon-delimited
  `--ssh-inject "${SSH_USER}:file:${key}"` selector; a `:` in the value
  misparses the format.
- **TD-06 (High)** — `KDIVE_ROOTFS` reaches `mkdir`, `virt-make-fs`, and
  `chmod` with no canonicalization or symlink check; a symlink or `..` could
  redirect the write/`chmod` onto an attacker-chosen file.
- **TD-38 (Medium)** — `mktemp` is called with the inherited umask, so the temp
  files (including a tar of the whole guest filesystem) are world-readable.
- **TD-94 (Low)** — the `guestfish` heredoc delimiter is unquoted.

## Decision

1. **Username allowlist (TD-05 + TD-37).** Validate `SSH_USER` once, before any
   tool runs, against `^[a-z_][a-z0-9_-]*$` with a 32-char cap (the `useradd`
   `NAME_REGEX` / `LOGIN_NAME_MAX` envelope). A conforming value cannot contain
   shell metacharacters or a `:`, so a single up-front check closes both the
   injection and the misparse. Reject with a clear message and exit 1.

2. **Output-path canonicalization + symlink refusal (TD-06).** Reject a
   pre-existing symlink at `ROOTFS_PATH`, then canonicalize its parent directory
   with `realpath -m` (collapsing `..` and resolving parent symlinks
   deterministically) while keeping the final component literal. Re-assert
   "regular file, not a symlink" immediately before the final `chmod`.

   We deliberately do **not** enforce containment under a fixed base directory
   (the audit's literal suggestion of `/var/lib/kdive/rootfs/`). The output path
   is legitimately operator-configurable — the integration test builds into a
   pytest `tmp_path`, and operators build into custom virt_image_t-labeled dirs
   (ADR 0037). A hardcoded base would break those flows. The genuine exploit the
   finding describes — redirection of the write/`chmod` via a symlink or `..` —
   is fully addressed by canonicalization + symlink refusal, which is
   independent of where the operator chooses to write.

3. **Deterministic `chmod 0600` on the tool-written temp files (TD-38).**
   `mktemp` already creates each file `0600` irrespective of umask, and the
   `>`-redirect config writes preserve that mode — so the config temps are never
   world-readable and need no umask. The two temp files written by *external*
   tools — `scratch` (`virt-builder --output`) and `rootfs_tar` (`virt-tar-out`,
   a tar of the whole guest filesystem) — may be unlinked and recreated at the
   inherited umask, so each is `chmod 0600`'d immediately after the tool writes
   it. This makes their mode deterministic regardless of tool behavior without
   touching the rootfs *parent* directory, which must stay traversable by the
   separate `qemu` user (ADR 0037 decision #6).

4. **Heredoc comment (TD-94).** The `guestfish` heredoc delimiter stays
   unquoted and gains a comment explaining why: `${fstab_file}`/`${selinux_file}`
   are host-side temp paths that must expand so `guestfish` receives real
   filenames; quoting the delimiter would pass them literally and break the
   upload. The audit's proposed remedy (quote the delimiter) is incorrect.

## Consequences

- A malformed `KDIVE_ROOTFS_SSH_USER` now fails fast with a clear error instead
  of injecting guest commands or corrupting the `--ssh-inject` selector.
- A symlinked or traversal `KDIVE_ROOTFS` fails fast instead of redirecting host
  writes/`chmod`.
- Temp files are `0600`, not world-readable, without affecting the
  qemu-traversable output directory.
- Validation runs before the `require <tool>` checks, so the guards are testable
  in CI without `libguestfs` installed (a unit test drives the script with bad
  inputs and asserts exit 1).

## Considered & rejected

- **Fixed-base containment for `ROOTFS_PATH`** (audit's literal suggestion).
  Rejected: breaks the `tmp_path` integration build and operator-custom output
  dirs; the symlink/traversal risk it targets is already covered by
  canonicalization + symlink refusal, which does not constrain location.
- **Quoting `${SSH_USER}` instead of validating.** Rejected: quoting the
  `--run-command` string protects the host shell but not the *guest* shell that
  `virt-builder` spawns, and does nothing for the `--ssh-inject` colon misparse.
  An allowlist closes both at once and fails fast.
- **Blanket `umask 0077` at the top of the script.** Rejected: it would also
  apply to the `mkdir -p` of the rootfs parent, making it `0700` and breaking
  qemu's traversal of a freshly created output directory.
- **A scoped `umask 0077` around the `mktemp` block.** Rejected: `mktemp`
  already yields `0600` regardless of umask (verified), so the umask changes
  nothing for those files, and it is restored before `virt-builder`/`virt-tar-out`
  write the actually-sensitive `scratch`/`rootfs_tar` — leaving the real exposure
  uncovered. An explicit `chmod 0600` after each tool write is both effective and
  honest about where the protection comes from.
- **Quoting the `guestfish` heredoc delimiter (TD-94's suggested fix).**
  Rejected: it would stop the intentional expansion of the host-side temp-file
  paths and break the upload.
