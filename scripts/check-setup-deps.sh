#!/usr/bin/env bash
set -euo pipefail

readonly OS_RELEASE_FILE="${KDIVE_OS_RELEASE:-/etc/os-release}"

missing_commands=()
missing_packages=()

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

add_missing() {
    missing_commands+=("$1")
    add_package "$2"
}

add_package() {
    local package="$1"
    local existing

    for existing in "${missing_packages[@]}"; do
        if [[ "${existing}" == "${package}" ]]; then
            return
        fi
    done
    missing_packages+=("${package}")
}

load_distro_id() {
    local id=""
    local id_like=""

    if [[ -r "${OS_RELEASE_FILE}" ]]; then
        # shellcheck disable=SC1090
        source "${OS_RELEASE_FILE}"
        id="${ID:-}"
        id_like="${ID_LIKE:-}"
    fi

    case " ${id} ${id_like} " in
        *" fedora "*|*" rhel "*|*" centos "*) printf "fedora" ;;
        *" debian "*|*" ubuntu "*) printf "debian" ;;
        *" arch "*) printf "arch" ;;
        *" opensuse "*|*" suse "*) printf "opensuse" ;;
        *) printf "unknown" ;;
    esac
}

package_for() {
    local command_name="$1"
    local distro="$2"

    case "${command_name}:${distro}" in
        qemu-system-x86_64:fedora) printf "qemu-system-x86" ;;
        qemu-system-x86_64:debian) printf "qemu-system-x86" ;;
        qemu-system-x86_64:arch) printf "qemu-system-x86" ;;
        qemu-system-x86_64:opensuse) printf "qemu-x86" ;;
        virsh:fedora) printf "libvirt-client" ;;
        virsh:debian) printf "libvirt-clients" ;;
        virsh:arch) printf "libvirt" ;;
        virsh:opensuse) printf "libvirt-client" ;;
        virt-builder:*|virt-tar-out:*|virt-make-fs:*|guestfish:*|qemu-img:*) printf "libguestfs-tools" ;;
        *) printf "%s" "${command_name}" ;;
    esac
}

print_install_hint() {
    local distro="$1"
    shift
    local packages=("$@")

    case "${distro}" in
        fedora) printf "Install missing packages with: dnf install %s\n" "${packages[*]}" ;;
        debian) printf "Install missing packages with: apt install %s\n" "${packages[*]}" ;;
        arch) printf "Install missing packages with: pacman -S %s\n" "${packages[*]}" ;;
        opensuse) printf "Install missing packages with: zypper install %s\n" "${packages[*]}" ;;
        *)
            printf "Install the missing commands with your distribution package manager: %s\n" \
                "${missing_commands[*]}"
            ;;
    esac
}

join_by_comma() {
    local joined=""
    local item

    for item in "$@"; do
        if [[ -z "${joined}" ]]; then
            joined="${item}"
        else
            joined="${joined}, ${item}"
        fi
    done
    printf "%s" "${joined}"
}

distro="$(load_distro_id)"

for command_name in \
    uv \
    make \
    bash \
    git \
    qemu-system-x86_64 \
    virsh \
    gdb \
    crash \
    virt-builder \
    virt-tar-out \
    virt-make-fs \
    guestfish \
    qemu-img; do
    if ! command_exists "${command_name}"; then
        add_missing "${command_name}" "$(package_for "${command_name}" "${distro}")"
    fi
done

if ! command_exists gcc && ! command_exists clang; then
    add_missing "gcc or clang" "gcc"
fi

if ((${#missing_commands[@]} > 0)); then
    printf "Missing setup dependencies: %s\n" "$(join_by_comma "${missing_commands[@]}")" >&2
    print_install_hint "${distro}" "${missing_packages[@]}" >&2
    printf "Run the install command from a privileged shell, then rerun: just setup\n" >&2
    exit 1
fi

printf "Setup dependencies are present.\n"
