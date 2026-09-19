#!/usr/bin/env python3
"""Build and publish the static musl loader around the existing full eBPF image."""
import sys
sys.dont_write_bytecode = True
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

from elf_dependencies import require_static, require_arch

from workspace import ROOT, BUILD, prepare_cmake, source_state


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def publish(source, destination):
    descriptor, temporary = tempfile.mkstemp(prefix="." + destination.name + "-",
                                            dir=destination.parent)
    os.close(descriptor)
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=["x86_64", "aarch64", "riscv64"],
                        default=os.environ.get("LASHOS_TARGET_ARCH", os.uname().machine))
    args = parser.parse_args()
    compiler = os.environ.get("PORTABLE_CC")
    sdk = os.environ.get("CAPSULE_SDK")
    if not compiler or not sdk:
        raise SystemExit("Use make portable, or scripts/dev.py --shell portable")
    target = subprocess.check_output([compiler, "-dumpmachine"], text=True).strip()
    if target != args.arch + "-unknown-linux-musl":
        raise SystemExit(f"Expected the pinned {args.arch} musl compiler; got {target}")
    profile = "portable" if args.arch == "x86_64" else "portable-" + args.arch
    build = BUILD / profile
    image = BUILD / 'kernel-full/bash.bpf.o'
    skeleton = BUILD / 'kernel-full/bash.skel.h'
    if not image.is_file() or not skeleton.is_file():
        raise SystemExit("Build the full image first with make build")
    prepare_cmake(build, ROOT / 'cmake/portable')
    cross = ["-DCMAKE_SYSTEM_NAME=Linux", "-DCMAKE_SYSTEM_PROCESSOR=" + args.arch]
    if args.arch != os.uname().machine:
        emulator = shutil.which("qemu-" + args.arch)
        if not emulator:
            raise SystemExit(f"Install qemu-user for {args.arch} cross-build tests")
        cross.append("-DCMAKE_CROSSCOMPILING_EMULATOR=" + emulator)
    subprocess.run(["cmake", "-S", str(ROOT / "cmake/portable"), "-B", str(build), *cross,
                    "-ULIBBPF_*", "-U__pkg_config_checked_LIBBPF",
                    "-DCMAKE_C_COMPILER=" + compiler,
                    "-DCAPSULE_INCLUDE_DIRECTORY=" + sdk + "/include/bpf-capsule",
                    "-DBASH_SKELETON_DIRECTORY=" + str(skeleton.parent)], check=True)
    subprocess.run(["cmake", "--build", str(build), "-j4"], check=True)
    subprocess.run(["ctest", "--test-dir", str(build), "--output-on-failure"], check=True)
    binary = build / "linux-bash-os"
    require_arch(binary, args.arch)
    dependencies = require_static(binary)
    require_static(build / "job-control-test")
    # Keep the exact embedded guest image for inspection and VM result hashes.
    publish(image, build / "bash.bpf.o")
    embedded = (build / "bash.bpf.o").read_bytes()
    if (len(embedded) < 64 or embedded[:6] != b"\x7fELF\x02\x01" or
            struct.unpack_from("<H", embedded, 18)[0] != 247 or
            struct.unpack_from("<Q", embedded, 40)[0] +
            struct.unpack_from("<H", embedded, 58)[0] * struct.unpack_from("<H", embedded, 60)[0] > len(embedded) or
            embedded not in binary.read_bytes()):
        raise SystemExit("The full BPF image and compiled skeleton differ; finish the full build before packaging")
    manifest = {
        "architecture": args.arch + "-linux", "libc": "musl", "compiler_target": target,
        "loader_sha256": digest(binary), "bpf_sha256": hashlib.sha256(embedded).hexdigest(),
        "bytes": binary.stat().st_size, "elf": dependencies,
        # Release packaging compares this with the published source revision.
        "build_source": source_state(),
    }
    (build / "portable.json").write_text(json.dumps(manifest, indent=2) + "\n")
    require_static(build / "sandbox-init")
    print(f"Static base executable: {binary} ({manifest['bytes']} bytes)")


if __name__ == "__main__":
    main()
