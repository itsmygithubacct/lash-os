#!/usr/bin/env python3
"""Collect the three verified build outputs and checksums as local release candidates."""
import argparse
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import tarfile
import sys
sys.dont_write_bytecode = True
from elf_dependencies import require_arch, require_static
from runtime import ARCHES, KERNEL_PATCHES, digest
from workspace import ROOT, BUILD, OUT, source_differences


def publish(source, destination):
    descriptor, name = tempfile.mkstemp(prefix="." + destination.name + "-", dir=destination.parent)
    os.close(descriptor)
    try:
        shutil.copy2(source, name)
        Path(name).replace(destination)
    finally:
        Path(name).unlink(missing_ok=True)


def require_pinned_runtime(arch, manifest):
    """Refuse executables bundled with the build machine's kernel and QEMU."""
    lock = json.loads((ROOT / "config/runtime" / (arch + ".json")).read_text())
    linux = json.loads((ROOT / "config/runtime-sources.json").read_text())["linux"]
    # Architecture-named kernel patches change only that architecture's code. Kernels
    # built before patch tracking record no inventory and are valid when none apply.
    others = tuple(f"linux-{other}-" for other in ARCHES if other != arch)
    patches = {name: digest(ROOT / "patches" / name) for name in KERNEL_PATCHES if not name.startswith(others)}
    kernel = manifest.get("kernel")
    recorded = kernel.get("patches") if isinstance(kernel, dict) else None
    recorded = {name: value for name, value in (recorded or {}).items() if not name.startswith(others)}
    if (manifest.get("format") != "LASHOS-VM-v1" or manifest.get("runtime", "pinned") != "pinned" or
            manifest.get("package_sources") != lock or not isinstance(kernel, dict) or
            kernel.get("architecture") != arch or kernel.get("linux") != linux or recorded != patches):
        raise ValueError(f"The {arch} executable does not contain the pinned runtime; rebuild it with make portable-{arch}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-sources", action="store_true",
                        help="Require and include both corresponding-source archives and release notes")
    args = parser.parse_args()
    version = (ROOT / "VERSION").read_text().strip()
    destination = OUT / "releases" / version
    destination.mkdir(parents=True, exist_ok=True)
    assets, sums, manifests = [], [], {}
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
        require_pinned_runtime(arch, manifest)
        command = [str(binary), "--version"]
        if arch != os.uname().machine:
            command.insert(0, "qemu-" + arch)
        reported = subprocess.check_output(command, text=True).strip()
        if reported != f"lashos {version} ({arch}-linux)":
            raise ValueError(f"Unexpected loader version: {reported}")
        name = f"lashos-{version}-linux-{arch}"
        publish(binary, destination / name)
        publish(inventory, destination / (name + ".json"))
        manifests[arch] = manifest
        assets.append({"architecture": arch, "status": "primary" if arch == "x86_64" else "experimental",
                       "file": name, "bytes": binary.stat().st_size,
                       "sha256": sha256, "bpf_sha256": manifest["bpf_sha256"],
                       "build_source_revision": (manifest.get("build_source") or {}).get("revision")})
        sums += [f"{sha256}  {name}", f"{digest(inventory)}  {name}.json"]
    if len({asset["bpf_sha256"] for asset in assets}) != 1:
        raise ValueError("The architecture builds do not contain the same BPF image")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
    release = {"version": version, "source_revision": revision, "source_dirty": dirty, "assets": assets}
    if args.with_sources:
        if dirty:
            raise ValueError("Commit source changes before collecting the complete public release")
        for arch, manifest in manifests.items():
            for key in ["build_source", "loader_build_source"]:
                differences = source_differences(manifest.get(key), revision)
                if differences:
                    raise ValueError(f"The {arch} executable was not built from release commit {revision} "
                                     f"({', '.join(differences[:10])}); rebuild after committing")
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
        roots = runpy.run_path(str(ROOT / "scripts/collect-nix-sources.py"))["architecture_roots"]()
        if source_inventory["manifest"]["nix"].get("architecture_roots") != roots:
            raise ValueError("Dependency sources were collected from different portable builds; "
                             "rerun collect-nix-sources.py and package-sources.py")
        files = {entry["archive_path"]: entry for entry in source_inventory["manifest"]["files"]}
        for arch in ARCHES:
            recorded = files.get(f"provenance/runtime/{arch}.json")
            if not recorded or recorded["sha256"] != digest(ROOT / "config/runtime" / (arch + ".json")):
                raise ValueError(f"Dependency sources were collected for a different {arch} runtime")
            kernel = manifests[arch]["kernel"]
            kernel_file = BUILD / "runtime" / arch / "kernel.json"
            kernel_json = files.get(f"provenance/kernels/{arch}.json")
            kernel_config = files.get(f"provenance/kernels/{arch}.config")
            if (not kernel_json or not kernel_config or not kernel_file.is_file() or
                    kernel_json["sha256"] != digest(kernel_file) or
                    json.loads(kernel_file.read_text()) != kernel or
                    kernel_config["sha256"] != kernel.get("config_sha256")):
                raise ValueError(f"Dependency sources describe a different {arch} kernel than the executable")
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
