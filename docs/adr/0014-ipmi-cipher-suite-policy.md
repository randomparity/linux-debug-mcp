# ADR 0014 — IPMI cipher-suite policy: contract-layer enforcement + a single chokepoint + a CI tripwire, before the transport exists

**Status:** Accepted (2026-05-29) · **Issue:** #67 (epic #9, split from #17, depends on #15) · **Affects:** `safety/ipmi.py` (new policy chokepoint), `providers/contracts.py` (`ConsoleSessionRequest` gains `ipmi_cipher_suite` + a model validator), `justfile` + `.github/workflows/ci.yml` (new `check-ipmi` guard); plug-in point for #15 (the `ipmi-sol` provider, which must validate through `safety/ipmi.py`)

## Context

IPMI cipher suite 0 disables authentication entirely; the only acceptable posture is
the `lanplus` interface with an authenticated cipher suite (suite 3 baseline). Issue
#67 demands enforcement "in the IPMI transport path (code)" **and** a "CI guard that
fails if a cipher-0 / non-`lanplus` code path can be reached," with tests proving an
IPMI session refuses cipher 0 and requires `lanplus`.

The complication: the IPMI SOL transport (`ipmi-sol`, #15) is **not implemented**. It
is a stub-provider stub (`console-access-stub`) routed through `_stub_provider_handler`,
which validates the request contract and returns `NOT_IMPLEMENTED` without opening any
resource. So there is no live "transport path" to instrument yet — only the
`console.open_session` request contract, where `access_method` already accepts
`ipmi-sol`. #67 is a hardening issue deliberately landed *before* its transport so the
invariant exists the moment #15 does.

The open questions: **(1) where does the policy live and get enforced given the
provider is a stub; (2) how broad is the allowed cipher set; (3) how is the field typed
and what happens when it is supplied to a non-IPMI method; (4) what does the CI guard
actually assert when no `ipmitool` invocation exists yet?**

## Decision

1. **The policy lives in one new chokepoint, `safety/ipmi.py`** — constants
   (`IPMI_INTERFACE="lanplus"`, `IPMI_FORBIDDEN_CIPHER_SUITE=0`,
   `IPMI_DEFAULT_CIPHER_SUITE=3`, `IPMI_ALLOWED_CIPHER_SUITES=frozenset({3})`), a typed
   `IpmiPolicyError(ValueError)`, and `validate_ipmi_cipher_suite(value) -> int`
   (None→3, 0→raise, non-allowlisted→raise, else value). It opens no resources and
   depends on nothing in the provider/server layers, so both today's contract and the
   future `ipmi-sol` provider (#15) validate through the same code rather than
   re-deriving the rule.

2. **Enforcement is at the contract layer today** — `ConsoleSessionRequest` gains
   `ipmi_cipher_suite: int | None = None` and a `model_validator(mode="after")`: for
   `access_method=="ipmi-sol"` the field is normalized through
   `validate_ipmi_cipher_suite` (so a valid request carries the concrete approved suite,
   `3`); for any other method the field must be `None`. This is the only IPMI
   configuration surface that exists, and it is the live code path that "refuses cipher
   0." `IpmiPolicyError` being a `ValueError` makes it a normal Pydantic validation
   error, mapped to `CONFIGURATION_ERROR` by `_stub_provider_handler`.

3. **`lanplus` is enforced structurally, not by a flag** — `_CONSOLE_ACCESS_METHODS`
   offers `ipmi-sol` only (no bare `lan`/`ipmi`), so an IPMI console can never select a
   non-`lanplus` interface. A test pins that a legacy `"ipmi"` method is rejected by the
   allowlist.

4. **The allowed cipher set is exactly `{3}`**, expressed as a `frozenset` so widening
   to other authenticated suites later is a one-line, test-guarded change. #67 ships
   `{3}` per its acceptance criteria; anything else (including the no-auth suites 0/1/2)
   is rejected.

5. **The CI guard (`just check-ipmi`) is a textual tripwire**, mirroring `check-docs`:
   it greps `src/` for forbidden `ipmitool` invocation patterns (`-C 0` cipher-0
   selection; `-I lan` not followed by `plus`) and fails if any appear outside
   `safety/ipmi.py`. It is not a proof of runtime behavior — the contract test is that —
   but it guarantees that when #15 introduces real `ipmitool` calls, a cipher-0 /
   non-`lanplus` invocation fails the build.

## Consequences

- #67 is a small, low-risk change with no runtime transport: a ~30-line policy module,
  one new optional field + one validator on an existing contract, and a grep guard. No
  resource is opened; the stub still returns `NOT_IMPLEMENTED`.
- The invariant is enforced before the feature exists, so #15 inherits it: the provider
  reads a concrete approved suite from the validated request and must route any further
  cipher decision through `safety/ipmi.py`, and the CI guard catches a regression in the
  provider's command construction.
- A cipher suite supplied to a non-IPMI method is a hard error rather than silently
  ignored, so a mis-wired caller is told immediately.
- The guard's `safety/ipmi.py` exclusion is a known, scoped hole: the one file allowed
  to name cipher 0 is the one that defines it as forbidden. Any forbidden pattern
  elsewhere still fails.

## Considered & rejected

1. **Defer all enforcement to the `ipmi-sol` provider (#15) and ship nothing now.**
   Rejected: #67 exists precisely to land the invariant *before* the transport, so the
   policy cannot be skipped or mis-implemented when #15 is written under time pressure.
   The contract is a real, testable configuration surface today; leaving it unguarded
   would let a cipher-0 `ipmi-sol` request validate successfully.

2. **CI guard only, no contract enforcement.** Rejected: a grep tripwire cannot satisfy
   "IPMI sessions refuse cipher 0" — that is a runtime behavior the contract test must
   prove. The guard alone would pass on a tree whose contract happily accepts
   `ipmi_cipher_suite=0`.

3. **Contract enforcement only, no CI guard.** Rejected: issue #67 explicitly requires
   the guard, and the contract validator does not protect the *future* provider's
   command construction — a `subprocess` call assembling `ipmitool -C 0` in #15 would
   bypass the contract entirely. The guard is the backstop for that path.

4. **Build an `ipmitool` argv constructor now** (a `build_ipmitool_argv()` that hardcodes
   `-I lanplus -C 3`) as the chokepoint. Rejected as a phantom feature: no provider
   consumes it yet, so it would be untested-by-use speculative code (violates "no
   speculative features"). The constants + validator are the minimal chokepoint that has
   a real consumer today (the contract); #15 adds the argv constructor when it adds the
   `subprocess` call, and the CI guard already constrains that construction.

5. **Allow "any suite except 0" (reject only cipher 0).** Rejected: suites 1 and 2 are
   also weak (1 = no auth; 2 = HMAC-MD5 with no confidentiality). #67 mandates suite 3;
   an allowlist (`{3}`) is safer than a denylist (`{0}`) because new weak suites are
   rejected by default rather than admitted until denied.

6. **Pre-include suite 17 (AES-SHA256) in the allowlist** as a more modern option.
   Rejected for #67 scope: no consumer requests it, the issue names suite 3, and adding
   it now is speculative. The `frozenset` makes adding it later a trivial, test-guarded
   change when a real target needs it.

7. **Make `ipmi_cipher_suite` a string enum (`"3"`, `"lanplus-3"`) or a nested
   `IpmiConfig` object.** Rejected: cipher suites are small integers in IPMI/`ipmitool`
   (`-C <n>`); an `int | None` field maps directly to the wire form, and a nested object
   is premature structure for a single value. A free-form string would also reopen the
   safe-label/secret-marker validation surface for no gain.

8. **Silently ignore `ipmi_cipher_suite` when `access_method` is not `ipmi-sol`.**
   Rejected: silently dropping a security-relevant field hides caller error. Failing
   fast with `CONFIGURATION_ERROR` is consistent with the repo's fail-fast error
   handling and keeps the field's meaning unambiguous.

## References

Issue #67; spec
`docs/archive/superpowers/specs/2026-05-29-ipmi-cipher-policy-design.md`;
[ADR 0012](0012-secrets-store-backends-and-redaction.md) (credential redaction posture);
`docs/specs/interface-contracts.md` (`ipmi-sol` is `brokered_required`); IPMI v2.0 /
RMCP+ cipher suite definitions (suite 0 = no auth; suite 3 = RAKP-HMAC-SHA1 /
HMAC-SHA1-96 / AES-CBC-128).
