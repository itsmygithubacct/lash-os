"""Shared metadata and verified downloads for the portable VM builds."""
import hashlib
from pathlib import Path, PurePosixPath
import urllib.request

ARCHES = {
    "x86_64": {"debian": "amd64", "linux": "x86", "image": "arch/x86/boot/bzImage",
               "triplet": "x86_64-linux-gnu", "qemu": "qemu-system-x86_64", "package": "qemu-system-x86"},
    "aarch64": {"debian": "arm64", "linux": "arm64", "image": "arch/arm64/boot/Image",
                "triplet": "aarch64-linux-gnu", "qemu": "qemu-system-aarch64", "package": "qemu-system-arm"},
    "riscv64": {"debian": "riscv64", "linux": "riscv", "image": "arch/riscv/boot/Image",
                "triplet": "riscv64-linux-gnu", "qemu": "qemu-system-riscv64", "package": "qemu-system-riscv"},
}


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            result.update(block)
    return result.hexdigest()


def fetch(url, sha256, destination):
    destination = Path(destination)
    if destination.is_file() and digest(destination) == sha256:
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".partial")
    try:
        with urllib.request.urlopen(url, timeout=120) as source, temporary.open("wb") as output:
            while block := source.read(1024 * 1024):
                output.write(block)
        if digest(temporary) != sha256:
            raise ValueError(f"SHA256 mismatch for {url}")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def rooted(root, name):
    """Resolve symlinks inside a foreign sysroot, including absolute targets."""
    pending = list(PurePosixPath("/" + str(name).lstrip("/")).parts[1:])
    resolved, links = [], 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                raise ValueError(f"Path escapes sysroot: {name}")
            resolved.pop()
            continue
        candidate = root.joinpath(*resolved, part)
        if candidate.is_symlink():
            links += 1
            if links > 40:
                raise ValueError(f"Symlink loop in sysroot: {name}")
            target = candidate.readlink()
            if target.is_absolute():
                resolved = []
            pending = list(PurePosixPath(str(target).lstrip("/")).parts) + pending
        else:
            resolved.append(part)
    return root.joinpath(*resolved)
