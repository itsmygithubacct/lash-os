#!/usr/bin/env python3
"""Collect the three verified build outputs and checksums as local release candidates."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys
sys.dont_write_bytecode = True
from elf_dependencies import require_arch, require_static
from runtime import ARCHES, digest
from workspace import ROOT, OUT


def publish(source, destination):
    descriptor, name = tempfile.mkstemp(prefix="." + destination.name + "-", dir=destination.parent)
    os.close(descriptor)
    try:
        shutil.copy2(source, name)
        Path(name).replace(destination)
    finally:
        Path(name).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    version = (ROOT / "VERSION").read_text().strip()
    destination = OUT / "releases" / version
    destination.mkdir(parents=True, exist_ok=True)
    assets, sums = [], []
    for arch in ARCHES:
        profile = "portable" if arch == "x86_64" else "portable-" + arch
        binary = OUT / profile / "linux-bash-os"
        inventory = OUT / profile / "portable.json"
        manifest = json.loads(inventory.read_text())
        sha256 = digest(binary)
        require_arch(binary, arch)
        require_static(binary)
        if manifest["architecture"] != arch + "-linux" or manifest["loader_sha256"] != sha256:
            raise ValueError(f"Build inventory does not match the {arch} executable")
        command = [str(binary), "--version"]
        if arch != os.uname().machine:
            command.insert(0, "qemu-" + arch)
        reported = subprocess.check_output(command, text=True).strip()
        if reported != f"lashos {version} ({arch}-linux)":
            raise ValueError(f"Unexpected loader version: {reported}")
        name = f"lashos-{version}-linux-{arch}"
        publish(binary, destination / name)
        publish(inventory, destination / (name + ".json"))
        assets.append({"architecture": arch, "file": name, "bytes": binary.stat().st_size,
                       "sha256": sha256, "bpf_sha256": manifest["bpf_sha256"]})
        sums += [f"{sha256}  {name}", f"{digest(inventory)}  {name}.json"]
    if len({asset["bpf_sha256"] for asset in assets}) != 1:
        raise ValueError("The architecture builds do not contain the same BPF image")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
    release = {"version": version, "source_revision": revision, "source_dirty": dirty, "assets": assets}
    (destination / "release.json").write_text(json.dumps(release, indent=2) + "\n")
    sums.append(f"{digest(destination / 'release.json')}  release.json")
    (destination / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    print(f"Local release candidates: {destination}")
    for asset in assets:
        print(f"{asset['architecture']}: {asset['bytes']:,} bytes; SHA256 {asset['sha256']}")


if __name__ == "__main__":
    main()
