#!/usr/bin/env python3
"""Build and publish the static musl loader around the existing full eBPF image."""
import sys
sys.dont_write_bytecode = True
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from elf_dependencies import require_static

from workspace import ROOT, BUILD, prepare_cmake


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
    compiler = os.environ.get("PORTABLE_CC")
    sdk = os.environ.get("CAPSULE_SDK")
    if not compiler or not sdk:
        raise SystemExit("Use make portable, or scripts/dev.py --shell portable")
    target = subprocess.check_output([compiler, "-dumpmachine"], text=True).strip()
    if target != "x86_64-unknown-linux-musl":
        raise SystemExit(f"Expected the pinned x86_64 musl compiler; got {target}")
    build = BUILD / 'portable'
    image = BUILD / 'kernel-full/bash.bpf.o'
    skeleton = BUILD / 'kernel-full/bash.skel.h'
    if not image.is_file() or not skeleton.is_file():
        raise SystemExit("Build the full image first with make build")
    prepare_cmake(build, ROOT / 'cmake/portable')
    subprocess.run(["cmake", "-S", str(ROOT / "cmake/portable"), "-B", str(build),
                    "-ULIBBPF_*", "-U__pkg_config_checked_LIBBPF",
                    "-DCMAKE_C_COMPILER=" + compiler,
                    "-DCAPSULE_INCLUDE_DIRECTORY=" + sdk + "/include/bpf-capsule",
                    "-DBASH_SKELETON_DIRECTORY=" + str(skeleton.parent)], check=True)
    subprocess.run(["cmake", "--build", str(build), "-j4"], check=True)
    binary = build / "linux-bash-os"
    dependencies = require_static(binary)
    require_static(build / "job-control-test")
    # Keep the exact embedded guest image for inspection and VM result hashes.
    publish(image, build / "bash.bpf.o")
    manifest = {
        "architecture": "x86_64-linux", "libc": "musl", "compiler_target": target,
        "loader_sha256": digest(binary), "bpf_sha256": digest(image),
        "bytes": binary.stat().st_size, "elf": dependencies,
    }
    (build / "portable.json").write_text(json.dumps(manifest, indent=2) + "\n")
    require_static(build / "sandbox-init")
    print(f"Static base executable: {binary} ({manifest['bytes']} bytes)")


if __name__ == "__main__":
    main()
