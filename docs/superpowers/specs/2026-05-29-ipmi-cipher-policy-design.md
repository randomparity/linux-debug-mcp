# IPMI cipher-suite policy: enforce lanplus/cipher-3, reject cipher 0

**Status:** Accepted (implemented) · **Issue:** #67 (epic #9, split from #17, depends on #15) ·
**Labels:** `security`, `bmc`, `x86_64`, `hardening` ·
**ADR:** [0014](../../adr/0014-ipmi-cipher-suite-policy.md)

## Problem

IPMI is historically insecure. IPMI cipher suite 0 disables authentication entirely:
a session negotiated with cipher 0 accepts an empty password and applies no integrity
or confidentiality, so anyone who can reach the BMC management port can drive the host's
out-of-band console and power. The only acceptable posture for this server is the
`lanplus` interface (IPMI v2.0 / RMCP+) with an authenticated cipher suite; cipher
suite 3 (RAKP-HMAC-SHA1 auth, HMAC-SHA1-96 integrity, AES-CBC-128 confidentiality) is
the baseline mandated by issue #67.

The IPMI Serial-over-LAN provider itself (`ipmi-sol`, issue #15) is **not yet
implemented** — it exists only as a future-provider stub (`console-access-stub`) that
returns `not_implemented` and opens no network/serial/power resources. #67 lands the
cipher policy *before* #15 ships the transport, so the invariant is enforced the moment
the real provider exists and a regression that reintroduces cipher 0 is caught in CI.

## Goals / non-goals

**Goals**

1. The only IPMI configuration surface that exists today — the `console.open_session`
   request contract for `access_method == "ipmi-sol"` — refuses cipher suite 0 and any
   non-`lanplus`/non-suite-3 configuration, returning `CONFIGURATION_ERROR`.
2. A single in-code chokepoint (`safety/ipmi.py`) owns the cipher allowlist and the
   `lanplus` interface constant, so the future `ipmi-sol` provider (#15) validates
   through the same policy rather than re-deriving it.
3. A CI guard fails the build if a cipher-0 / non-`lanplus` `ipmitool` invocation can
   appear anywhere in `src/`, independent of whether the contract is exercised at
   runtime. This is the regression tripwire for when #15 lands.

**Non-goals**

- Implementing the `ipmi-sol` transport, SOL byte-stream handling, or the agent-proxy
  RSP endpoint (issue #15).
- Credential storage / the `Secrets` interface and global redaction filter (#65,
  shipped separately) — this spec consumes the existing `credential_ref` reference
  field and adds no new secret-bearing field.
- Power control / boot-order (`hardware.*` stub).
- Widening the allowlist to other authenticated suites (e.g. suite 17, AES-SHA256). The
  allowlist is expressed as a set so widening is a one-line, test-guarded change, but
  #67 ships exactly `{3}` per its acceptance criteria.

## Design

### Policy chokepoint — `safety/ipmi.py`

A new module beside `safety/paths.py` and `safety/secrets.py`. It owns the policy as
data plus one validator; it opens no resources and imports nothing from the provider or
server layers.

```
IPMI_INTERFACE: str = "lanplus"                 # IPMI v2.0 / RMCP+; never bare "lan"
IPMI_FORBIDDEN_CIPHER_SUITE: int = 0            # cipher 0 = no auth; always rejected
IPMI_DEFAULT_CIPHER_SUITE: int = 3              # mandated baseline when caller omits it
IPMI_ALLOWED_CIPHER_SUITES: frozenset[int] = frozenset({3})

class IpmiPolicyError(ValueError): ...          # ValueError so pydantic surfaces it

def validate_ipmi_cipher_suite(value: int | None) -> int:
    # None -> IPMI_DEFAULT_CIPHER_SUITE (3)
    # 0    -> IpmiPolicyError("IPMI cipher suite 0 disables authentication ...")
    # not in IPMI_ALLOWED_CIPHER_SUITES -> IpmiPolicyError("... must be one of {3}")
    # else -> value
```

`IpmiPolicyError` subclasses `ValueError` so that when called from a Pydantic field
validator it is collected as a normal validation error and mapped to
`CONFIGURATION_ERROR` by the existing `_future_stub_handler` path. The message names
cipher 0 and the allowed set so the failure is actionable; it carries no
credential-bearing input.

The `0` and `3` constants live **only** in this module. The CI guard (below) treats the
literal cipher-0 / non-`lanplus` patterns as forbidden everywhere except this module
(which defines the forbidden constant) and the tests that assert the policy.

### Contract enforcement — `ConsoleSessionRequest`

`providers/contracts.py` adds one field to `ConsoleSessionRequest`:

```
ipmi_cipher_suite: int | None = None
```

and a `model_validator(mode="after")` with two rules:

1. **`access_method == "ipmi-sol"`** → `ipmi_cipher_suite` is normalized through
   `validate_ipmi_cipher_suite`. `None` becomes `3`; `0` and any non-allowlisted value
   raise (→ `CONFIGURATION_ERROR`). After validation the field is the effective suite
   (always `3` today), so a downstream provider reads a concrete, policy-approved value.
2. **`access_method != "ipmi-sol"`** (`serial`, `ssh`) → `ipmi_cipher_suite` **must be
   `None`**. A cipher suite is IPMI-specific; supplying it for a non-IPMI method is a
   `CONFIGURATION_ERROR`, not silently ignored (fail fast).

The `lanplus` requirement is satisfied structurally: `_CONSOLE_ACCESS_METHODS` offers
`ipmi-sol` only — there is no bare-`lan`/`ipmi` access method — so an IPMI session can
never select a non-`lanplus` interface. A test pins this by asserting a hypothetical
`"ipmi"` (legacy, non-lanplus) access method is rejected by the allowlist.

`ipmi_cipher_suite` is an integer, not a secret reference, so it does not interact with
the raw-secret-field guard or `_safe_label_fields`.

### CI guard — `just check-ipmi`

A `justfile` target mirroring `check-docs`, plus a CI job step that runs it. The guard
greps `src/` for forbidden IPMI invocation patterns and fails if any are present
outside `safety/ipmi.py`:

- `ipmitool` invocations selecting the bare-`lan` interface (`-I lan` not followed by
  `plus`).
- cipher-suite-0 selection on an `ipmitool` command line (`-C 0`, `-C0`,
  `-C  0`).

The guard is a textual tripwire, not a proof of runtime behavior; the contract test is
the runtime proof. Together they cover both layers issue #67 names ("enforce in the
IPMI transport path (code)" and "CI guard that fails if a cipher-0 / non-`lanplus` code
path can be reached"). The guard's exclusion of `safety/ipmi.py` is necessary because
that module legitimately names the forbidden constant; the exclusion is scoped to that
one file so a forbidden pattern anywhere else still fails.

## Failure contract

| Condition | `ErrorCategory` | `suggested_next_actions` |
|---|---|---|
| `ipmi-sol` + `ipmi_cipher_suite == 0` | `CONFIGURATION_ERROR` | `["providers.list"]` |
| `ipmi-sol` + cipher not in allowlist | `CONFIGURATION_ERROR` | `["providers.list"]` |
| non-`ipmi-sol` method + `ipmi_cipher_suite` set | `CONFIGURATION_ERROR` | `["providers.list"]` |
| `ipmi-sol` + cipher omitted/`3` (valid request) | `NOT_IMPLEMENTED` (stub) | `["providers.list"]` |

All four flow through the existing `_future_stub_handler`: invalid requests fail
contract validation (`CONFIGURATION_ERROR`); a valid `ipmi-sol` request reaches
`select_future_provider` and returns `NOT_IMPLEMENTED` because the provider is a stub.
The stub still opens no resources.

## Acceptance criteria (falsifiable)

- AC1: `console.open_session` with `access_method="ipmi-sol"`, `ipmi_cipher_suite=0`
  returns `CONFIGURATION_ERROR` and lists `ipmi_cipher_suite` in `validation_errors`.
- AC2: `console.open_session` with `access_method="ipmi-sol"` and `ipmi_cipher_suite`
  omitted is accepted by the contract (normalized to `3`) and returns
  `NOT_IMPLEMENTED` from the stub — never `CONFIGURATION_ERROR`.
- AC3: `console.open_session` with `access_method="ipmi-sol"`, `ipmi_cipher_suite=1`
  (a weak authenticated-claim suite outside the allowlist) returns
  `CONFIGURATION_ERROR`.
- AC4: `console.open_session` with `access_method="ssh"`, `ipmi_cipher_suite=3` returns
  `CONFIGURATION_ERROR` (cipher set on a non-IPMI method).
- AC5: `access_method="ipmi"` (non-lanplus) is rejected by `_CONSOLE_ACCESS_METHODS`
  with `CONFIGURATION_ERROR`.
- AC6: `validate_ipmi_cipher_suite(None) == 3`; `validate_ipmi_cipher_suite(0)` and
  `validate_ipmi_cipher_suite(17)` raise `IpmiPolicyError`; `validate_ipmi_cipher_suite(3) == 3`.
- AC7: `just check-ipmi` passes on the current tree and fails when a `-C 0` or `-I lan`
  (non-lanplus) `ipmitool` literal is introduced under `src/` outside
  `safety/ipmi.py`.

## References

- Issue #67 (this), #15 (`ipmi-sol` transport), #17 (cross-cutting hardening, closed).
- `docs/specs/interface-contracts.md` §transport (`ipmi-sol` is `brokered_required`).
- IPMI v2.0 / RMCP+ cipher suites: suite 0 = no auth/integrity/confidentiality;
  suite 3 = RAKP-HMAC-SHA1 / HMAC-SHA1-96 / AES-CBC-128.
