# ppc64le Provider Spike

Sprint 5 treats ppc64le as provider metadata and contract surface only. No
ppc64le build, provisioning, boot, console, hardware-control, or debug provider
is executable in this sprint. The implemented end-to-end workflow remains the
local x86_64 build, libvirt/QEMU boot, SSH smoke-test, artifact, and QEMU
gdbstub path.

The purpose of this spike is to record the ppc64le shape expected by future
provider work so agents can understand why ppc64le appears in stub metadata
without assuming it can run.

## Kernel Images And Build Artifacts

ppc64le kernel artifacts are not interchangeable with the local x86_64
`bzImage` artifacts used by the current pilot workflow. Future ppc64le build
providers need to identify the exact kernel image format and boot wrapper
expected by the target environment, such as a raw `vmlinux`, an architecture
specific boot image, or a distribution/vendor-specific packaged artifact.

The artifact contract must preserve at least:

- architecture, machine family, and endian assumption
- kernel image path and image format
- matching `vmlinux` or unstripped symbols for debug
- matching `.config`
- module tree or module package identity when modules are involved
- source revision and build profile labels
- firmware or boot-loader assumptions required to consume the image

Artifact identity matters more for ppc64le than for the local pilot because
build, provisioning, boot, and debug may happen on different systems. A future
provider must be able to prove that the kernel image, config, symbols, and any
modules came from the same build.

## Remote Build Needs

ppc64le support is expected to require remote or cross-build capacity. A future
remote build provider should model where the build runs, how source is supplied,
how artifacts are exported, and which trust boundary owns credentials.

Important unresolved design points:

- native ppc64le builders versus cross-compilers on another architecture
- build queue or reservation semantics for scarce builder capacity
- toolchain, distro, and kernel-package format selection
- artifact transfer, checksum, retention, and redaction rules
- isolation between concurrent agent-requested builds

Sprint 5 stubs may advertise `remote.build_kernel` and
`remote.sync_artifacts`, but they must not invoke build hosts, open network
connections, read credentials, or write external artifact stores.

## Boot Firmware And Kernel Arguments

The local x86_64 pilot uses direct kernel boot under libvirt/QEMU. Real ppc64le
targets may involve Open Firmware, petitboot, host firmware policy, bootloader
state, or platform-specific kernel command-line requirements. Future boot
contracts need explicit fields for the boot method and kernel argument source
instead of assuming the x86_64 direct-boot shape.

Kernel arguments may need to describe console devices, root device discovery,
network boot state, installer or rescue modes, crashkernel settings, and
platform-specific mitigations. Providers must record the final command line as
an artifact or result detail so failures are reproducible.

## PXE And NIM Provisioning Assumptions

Future ppc64le provisioning may use PXE-like network boot, NIM, vendor tooling,
or a lab-specific provisioning service. The MCP server should treat these as
external systems behind a provider contract, not as local side effects.

A real provisioning provider will need to state:

- target identity and reservation ownership
- provisioning profile or image label
- network boot method and boot server ownership
- timeout and rollback behavior
- whether disks, firmware settings, or boot order may be changed
- which destructive permissions are required

Sprint 5 `provision.prepare_target` metadata is only a stub declaration. It
does not prepare a target, alter boot services, or mutate external state.

## HMC, IPMI, And BMC Control

Power control for ppc64le hardware may flow through an HMC, IPMI, Redfish/BMC,
or site-local control service. These interfaces are operationally destructive
because they can power cycle shared or reserved hardware. Future providers must
make destructive permissions explicit for power and boot actions, even when the
requested action appears routine.

Provider contracts should separate:

- reservation and authorization
- power state changes
- one-shot boot or persistent boot-device changes
- firmware or management-console operations
- audit evidence for who changed target state and when

Sprint 5 `hardware.power_control` and `hardware.boot_kernel` stubs must fail
before any management interface is contacted.

## Serial Console Expectations

ppc64le console access may be exposed through HMC virtual terminal, BMC serial
over LAN, lab console servers, libvirt console devices, or another broker.
Future console providers should define whether sessions are exclusive, how
input is encoded, how reads are bounded, and how sensitive output is redacted.

Contracts should avoid assuming the current x86_64 `ttyS0` readiness marker.
The console device name, expected boot markers, login prompt behavior, and line
discipline may differ by platform and provisioning profile.

## Libvirt/QEMU Versus Real Hardware

ppc64le under libvirt/QEMU can be useful for contract tests and early provider
development, but it is not a substitute for real hardware support. Virtual
ppc64le providers and physical ppc64le providers should advertise distinct
target kinds, transports, limitations, and destructive permissions.

The existing local libvirt/QEMU provider remains x86_64-only. Future ppc64le
libvirt work should not be presented as proof that HMC, BMC, PXE, NIM, or
physical console workflows are implemented.

## Debug Limitations

The Sprint 4 debug path attaches local `gdb` to a localhost-only QEMU gdbstub
for an x86_64 libvirt/QEMU domain. ppc64le debug has different constraints:

- symbol architecture and ABI must match the running kernel
- remote targets may not expose a gdbstub
- hardware debug access may require a separate management path
- console, crash dump, and tracing workflows may be more realistic than live
  gdb for physical systems
- virtualization debug and physical hardware debug should be modeled as
  separate provider capabilities

Future debug providers must clearly identify which artifact supplies symbols
and how that artifact is matched to the booted kernel.

## Sprint 5 Boundary

For Sprint 5, ppc64le means:

- it may appear in stub provider `architectures`
- it may appear in typed future-provider request contracts
- valid future-facing requests should return stable `not_implemented`
- malformed requests should return stable `configuration_error`
- no ppc64le external systems are contacted
- no ppc64le run workspace is created by future stubs

Agents should use `providers.list` to discover implementation state and
documentation paths before attempting ppc64le operations.
