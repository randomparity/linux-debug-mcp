from __future__ import annotations

from types import MappingProxyType

from kdive.config import BuildProfile, DebugProfile, RootfsProfile, TargetProfile

DEFAULT_BUILD_PROFILES = MappingProxyType(
    {
        "x86_64-default": BuildProfile(name="x86_64-default", architecture="x86_64", base_config=["defconfig"]),
        "x86_64-debug": BuildProfile(
            name="x86_64-debug",
            architecture="x86_64",
            base_config=["defconfig"],
            config_lines=[
                "CONFIG_VIRTIO=y",
                "CONFIG_VIRTIO_PCI=y",
                "CONFIG_VIRTIO_BLK=y",
                "CONFIG_VIRTIO_NET=y",
                "CONFIG_VIRTIO_CONSOLE=y",
                "CONFIG_SERIAL_8250=y",
                "CONFIG_SERIAL_8250_CONSOLE=y",
                "CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y",
                "# CONFIG_RANDOMIZE_BASE is not set",
            ],
        ),
    }
)

DEFAULT_TARGET_PROFILES = MappingProxyType(
    {
        "local-qemu": TargetProfile(
            name="local-qemu",
            architecture="x86_64",
            target_ref="kdive-dev",
            managed_domain=True,
            managed_domain_prefix="kdive-",
            libvirt_uri="qemu:///system",
        ),
        "local-qemu-debug": TargetProfile(
            name="local-qemu-debug",
            architecture="x86_64",
            target_ref="kdive-dev-debug",
            managed_domain=True,
            managed_domain_prefix="kdive-",
            libvirt_uri="qemu:///system",
            debug_gdbstub=True,
            gdbstub_endpoint="127.0.0.1:1234",
        ),
    }
)

DEFAULT_ROOTFS_PROFILES = MappingProxyType(
    {
        "minimal": RootfsProfile(
            name="minimal",
            source="/var/lib/kdive/rootfs/minimal.qcow2",
            source_kind="builder",
            mutability="copy_on_write",
            readiness_marker="kdive-ready",
            ssh_host="127.0.0.1",
            ssh_port=22,
            ssh_user="root",
        ),
    }
)

DEFAULT_DEBUG_PROFILES = MappingProxyType(
    {
        "qemu-gdbstub-default": DebugProfile(name="qemu-gdbstub-default"),
    }
)
