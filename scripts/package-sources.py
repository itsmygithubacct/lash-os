#!/usr/bin/env python3
"""Package project and corresponding dependency sources beside the release binaries."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
from runtime import ARCHES, digest, fetch
from workspace import ROOT, BUILD, DOWNLOADS, OUT


def json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def source_inputs():
    entries, paths = [], set()

    def add(path, name, sha256=None):
        path = Path(path)
        if name in paths:
            raise ValueError(f"Duplicate archive path: {name}")
        paths.add(name)
        actual = digest(path)
        if sha256 is not None and actual != sha256:
            raise ValueError(f"Source checksum mismatch: {path}")
        entries.append({"path": str(path), "archive_path": name,
                        "sha256": actual, "bytes": path.stat().st_size})

    versions = (ROOT / "vendor/bash-os/config/versions.sh").read_text()
    version = re.search(r"^BASH_SRC_VERSION=([\d.]+)$", versions, re.M)[1]
    sha256 = re.search(r"^BASH_SRC_SHA256=([a-f0-9]{64})$", versions, re.M)[1]
    name = "bash-" + version + ".tar.gz"
    add(fetch("https://ftp.gnu.org/gnu/bash/" + name, sha256, DOWNLOADS / name),
        "downloads/" + name, sha256)
    for name, sha256 in re.findall(r'"(bash\d+-\d{3}) ([a-f0-9]{64})"', versions):
        add(fetch(f"https://ftp.gnu.org/gnu/bash/bash-{version}-patches/{name}", sha256,
                  DOWNLOADS / "patches" / name), "downloads/patches/" + name, sha256)
    dependencies = json.loads((ROOT / "vendor/bash-os/config/dependencies.json").read_text())
    for package in dependencies.values():
        name = package["url"].rsplit("/", 1)[1]
        add(fetch(package["url"], package["sha256"], DOWNLOADS / "deps" / name),
            "downloads/deps/" + name, package["sha256"])
    kernel = json.loads((ROOT / "config/runtime-sources.json").read_text())["linux"]
    name = kernel["url"].rsplit("/", 1)[1]
    add(fetch(kernel["url"], kernel["sha256"], DOWNLOADS / "runtime" / name),
        "downloads/runtime/" + name, kernel["sha256"])
    sources = json.loads((ROOT / "config/runtime/sources.json").read_text())
    required = set()
    for arch in ARCHES:
        lock = ROOT / "config/runtime" / (arch + ".json")
        packages = json.loads(lock.read_text())["packages"]
        required.update((p["source"], p["source_version"]) for p in packages)
        add(lock, "provenance/runtime/" + arch + ".json")
        add(BUILD / "runtime" / arch / "kernel/.config", "provenance/kernels/" + arch + ".config")
        add(BUILD / "runtime" / arch / "kernel.json", "provenance/kernels/" + arch + ".json")
    if required != {(p["name"], p["version"]) for p in sources["packages"]}:
        raise ValueError("Runtime source lock does not cover the shipped package versions")
    for package in sources["packages"]:
        for item in package["files"]:
            relative = Path("runtime/sources") / package["name"] / item["file"]
            add(DOWNLOADS / relative, "downloads/" + str(relative), item["sha256"])
    add(ROOT / "config/runtime/sources.json", "provenance/runtime/sources.json")
    return entries


def normalized(info):
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    if info.isfile():
        info.mode = 0o755 if info.mode & 0o111 else 0o644
    elif info.isdir():
        info.mode = 0o755
    return info


def dependency_archive(destination, version):
    entries = source_inputs()
    nix_manifest = BUILD / "release-sources/nix-sources.json"
    if not nix_manifest.is_file():
        raise SystemExit("Run scripts/collect-nix-sources.py after building all three portable loaders")
    nix = json.loads(nix_manifest.read_text())
    nix_tools = runpy.run_path(str(ROOT / "scripts/collect-nix-sources.py"))
    # An inventory from an earlier toolchain would ship sources for different binaries.
    if nix.get("architecture_roots") != nix_tools["architecture_roots"]():
        raise SystemExit("The Nix source inventory does not match the current portable builds; "
                         "rerun scripts/collect-nix-sources.py")
    # The public manifest contains archive-relative names and immutable Nix
    # paths, never the maintainer's local download or build directories.
    manifest = {"version": version,
                "files": [{k: v for k, v in e.items() if k != "path"} for e in entries],
                "nix": nix}
    manifest_data = json_bytes(manifest)
    sidecar = destination.with_suffix(destination.suffix + ".json")
    if destination.is_file() and sidecar.is_file():
        previous = json.loads(sidecar.read_text())
        if previous["manifest"] == manifest and previous["sha256"] == digest(destination):
            print("Verified existing dependency source archive:", destination)
            return
    nix_tools["run"](["nix-store", "--verify-path", *[s["store_path"] for s in nix["sources"]]])
    descriptor, temporary = tempfile.mkstemp(prefix=".sources-", suffix=".tar.zst", dir=destination.parent)
    os.close(descriptor)
    compressor = subprocess.Popen(["zstd", "-q", "-f", "-T4", "-8", "--check", "-o", temporary],
                                  stdin=subprocess.PIPE)
    prefix = f"lashos-{version}-dependency-sources/"
    try:
        with tarfile.open(fileobj=compressor.stdin, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            info = normalized(tarfile.TarInfo(prefix + "manifest.json"))
            info.size = len(manifest_data)
            archive.addfile(info, io.BytesIO(manifest_data))
            for entry in entries:
                archive.add(entry["path"], arcname=prefix + entry["archive_path"], filter=normalized)
            for item in nix["sources"]:
                path = Path(item["store_path"])
                print("Archiving Nix source:", path.name, flush=True)
                archive.add(path, arcname=prefix + "nix/inputs/" + path.name, filter=normalized)
        compressor.stdin.close()
        if compressor.wait() != 0:
            raise RuntimeError("Source archive compression failed")
        if Path(temporary).stat().st_size >= 2 * 1024 ** 3:
            raise ValueError("The source archive exceeds GitHub's per-asset size limit")
        Path(temporary).replace(destination)
        sidecar.write_bytes(json_bytes({"sha256": digest(destination), "manifest": manifest}))
    finally:
        if compressor.poll() is None:
            compressor.kill()
            compressor.wait()
        Path(temporary).unlink(missing_ok=True)
    print("Dependency source archive:", destination, flush=True)


def project_archive(destination, version):
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT):
        raise ValueError("Commit source changes before packaging the project source")
    temporary = destination.with_suffix(destination.suffix + ".partial")
    producer = subprocess.Popen(["git", "archive", "--format=tar", f"--prefix=lashos-{version}/", "HEAD"],
                                cwd=ROOT, stdout=subprocess.PIPE)
    compressor = subprocess.Popen(["zstd", "-q", "-f", "-T4", "-8", "--check", "-o", str(temporary)],
                                  stdin=producer.stdout)
    producer.stdout.close()
    try:
        compressor_status = compressor.wait()
        producer_status = producer.wait()
        if producer_status or compressor_status:
            raise RuntimeError("Project source archive creation failed")
        temporary.replace(destination)
    finally:
        for process in [producer, compressor]:
            if process.poll() is None:
                process.kill()
                process.wait()
        temporary.unlink(missing_ok=True)
    print("Project source archive:", destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependencies-only", action="store_true",
                        help="Prepare the large source archive before committing final release documentation")
    args = parser.parse_args()
    version = (ROOT / "VERSION").read_text().strip()
    destination = OUT / "releases" / version
    destination.mkdir(parents=True, exist_ok=True)
    dependency_archive(destination / f"lashos-{version}-dependency-sources.tar.zst", version)
    if not args.dependencies_only:
        project_archive(destination / f"lashos-{version}-source.tar.zst", version)


if __name__ == "__main__":
    main()
