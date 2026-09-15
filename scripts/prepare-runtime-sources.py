#!/usr/bin/env python3
"""Fetch the exact Debian sources corresponding to all pinned runtime packages."""
import argparse
import concurrent.futures
import getpass
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from runtime import ARCHES, fetch
from workspace import ROOT, BUILD, DOWNLOADS

LOCK = ROOT / "config/runtime/sources.json"
MIRROR = "https://deb.debian.org/debian/"


def paragraphs(text):
    for paragraph in text.strip().split("\n\n"):
        fields, key = {}, None
        for line in paragraph.splitlines():
            if line[:1].isspace() and key:
                fields[key] += "\n" + line.strip()
            elif ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()
        if fields:
            yield fields


def required_sources():
    required = {}
    for arch in ARCHES:
        lock = json.loads((ROOT / "config/runtime" / (arch + ".json")).read_text())
        for package in lock["packages"]:
            key = package["source"], package["source_version"]
            required.setdefault(key, set()).add(arch)
    return required


def update_lock(required):
    apt = BUILD / "release-sources/apt"
    for name in ["state/lists/partial", "cache", "etc/empty", "log"]:
        (apt / name).mkdir(parents=True, exist_ok=True)
    (apt / "state/status").write_text("")
    keyring = Path("/usr/share/keyrings/debian-archive-keyring.gpg")
    if not keyring.is_file():
        raise SystemExit("Install debian-archive-keyring to authenticate source metadata")
    (apt / "etc/sources.list").write_text(
        f"deb-src [signed-by={keyring}] {MIRROR} trixie main\n")
    options = []
    for name, value in {
        "Dir": apt,
        "Dir::State": apt / "state",
        "Dir::Cache": apt / "cache",
        "Dir::Log": apt / "log",
        "Dir::Etc::sourcelist": apt / "etc/sources.list",
        "Dir::Etc::sourceparts": apt / "etc/empty",
        "Dir::Etc::preferencesparts": apt / "etc/empty",
        "Dir::State::status": apt / "state/status",
        "APT::Sandbox::User": getpass.getuser(),
        "Acquire::Languages": "none",
        "Debug::NoLocking": "true",
    }.items():
        options += ["-o", f"{name}={value}"]
    subprocess.run(["apt-get", *options, "update"], check=True)
    metadata = subprocess.check_output(
        ["apt-cache", *options, "showsrc", "--only-source",
         *sorted({name for name, _ in required})], text=True)
    available = {}
    for fields in paragraphs(metadata):
        key = fields.get("Package"), fields.get("Version")
        if key not in required:
            continue
        files = []
        for row in fields["Checksums-Sha256"].splitlines():
            if not row:
                continue
            sha256, size, filename = row.split()
            if Path(filename).name != filename:
                raise ValueError(f"Invalid source filename: {filename}")
            files.append({"file": filename, "sha256": sha256, "bytes": int(size),
                          "url": MIRROR + fields["Directory"] + "/" + filename})
        package = {"name": key[0], "version": key[1],
                   "architectures": sorted(required[key]), "files": sorted(files, key=lambda f: f["file"])}
        if key in available and available[key] != package:
            raise ValueError(f"Conflicting authenticated source metadata: {key}")
        available[key] = package
    missing = required.keys() - available.keys()
    if missing:
        raise ValueError(f"Exact source versions missing from authenticated metadata: {sorted(missing)}")
    LOCK.write_text(json.dumps({"distribution": "Debian 13 (trixie)",
                                "packages": [available[key] for key in sorted(available)]}, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-lock", action="store_true",
                        help="Resolve exact source versions using signed Debian APT metadata")
    args = parser.parse_args()
    required = required_sources()
    if args.update_lock:
        update_lock(required)
    if not LOCK.is_file():
        raise SystemExit("Missing source lock; maintainers must run --update-lock first")
    specification = json.loads(LOCK.read_text())
    packages = {(p["name"], p["version"]): p for p in specification["packages"]}
    if len(packages) != len(specification["packages"]) or packages.keys() != required.keys():
        raise ValueError("Source lock does not exactly cover the runtime package locks")
    downloads = []
    destinations = set()
    for key, package in packages.items():
        if sorted(required[key]) != package["architectures"]:
            raise ValueError(f"Source architecture coverage changed: {key}")
        if sum(f["file"].endswith(".dsc") for f in package["files"]) != 1:
            raise ValueError(f"Expected one Debian source descriptor: {key}")
        for item in package["files"]:
            if Path(item["file"]).name != item["file"] or Path(package["name"]).name != package["name"]:
                raise ValueError("Source lock contains an unsafe path")
            destination = DOWNLOADS / "runtime/sources" / package["name"] / item["file"]
            if destination in destinations:
                raise ValueError(f"Duplicate source destination: {destination}")
            destinations.add(destination)
            downloads.append((item, destination))

    def download(entry):
        item, destination = entry
        fetch(item["url"], item["sha256"], destination)
        if destination.stat().st_size != item["bytes"]:
            raise ValueError(f"Source size mismatch: {destination}")
        return destination

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for destination in pool.map(download, downloads):
            print("Verified", destination.name, flush=True)
    print(f"Complete runtime sources: {len(packages)} packages, {len(downloads)} files")


if __name__ == "__main__":
    main()
