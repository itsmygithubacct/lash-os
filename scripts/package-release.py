#!/usr/bin/env python3
"""Collect the three verified build outputs and checksums as local release candidates."""
import argparse
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
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
    parser.add_argument("--with-sources", action="store_true",
                        help="Require and include both corresponding-source archives and release notes")
    args = parser.parse_args()
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
        assets.append({"architecture": arch, "status": "primary" if arch == "x86_64" else "experimental",
                       "file": name, "bytes": binary.stat().st_size,
                       "sha256": sha256, "bpf_sha256": manifest["bpf_sha256"]})
        sums += [f"{sha256}  {name}", f"{digest(inventory)}  {name}.json"]
    if len({asset["bpf_sha256"] for asset in assets}) != 1:
        raise ValueError("The architecture builds do not contain the same BPF image")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
    release = {"version": version, "source_revision": revision, "source_dirty": dirty, "assets": assets}
    if args.with_sources:
        if dirty:
            raise ValueError("Commit source changes before collecting the complete public release")
        project = destination / f"lashos-{version}-source.tar.zst"
        dependency = destination / f"lashos-{version}-dependency-sources.tar.zst"
        inventory = dependency.with_suffix(dependency.suffix + ".json")
        packed_project = subprocess.check_output(["zstd", "-q", "-dc", str(project)])
        with tarfile.open(fileobj=io.BytesIO(packed_project)) as archive:
            if archive.pax_headers.get("comment") != revision:
                raise ValueError("Project source archive does not match the release commit")
        source_inventory = json.loads(inventory.read_text())
        if source_inventory["sha256"] != digest(dependency):
            raise ValueError("Dependency source archive differs from its inventory")
        for arch in ARCHES:
            recorded = next(e for e in source_inventory["manifest"]["files"]
                            if e["archive_path"] == f"provenance/runtime/{arch}.json")
            if recorded["sha256"] != digest(ROOT / "config/runtime" / (arch + ".json")):
                raise ValueError(f"Dependency sources were collected for a different {arch} runtime")
        notes = destination / "RELEASE_NOTES.md"
        publish(ROOT / "docs/releases" / (version + ".md"), notes)
        release["source_assets"] = []
        for path in [project, dependency, inventory, notes]:
            if path.stat().st_size >= 2 * 1024 ** 3:
                raise ValueError(f"Asset exceeds GitHub's per-file limit: {path.name}")
            sha256 = digest(path)
            release["source_assets"].append({"file": path.name, "bytes": path.stat().st_size, "sha256": sha256})
            sums.append(f"{sha256}  {path.name}")
    (destination / "release.json").write_text(json.dumps(release, indent=2) + "\n")
    sums.append(f"{digest(destination / 'release.json')}  release.json")
    (destination / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    print(f"Local release candidates: {destination}")
    for asset in assets:
        print(f"{asset['architecture']}: {asset['bytes']:,} bytes; SHA256 {asset['sha256']}")


if __name__ == "__main__":
    main()
