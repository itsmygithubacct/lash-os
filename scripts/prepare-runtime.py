#!/usr/bin/env python3
"""Download verified distribution packages into an isolated, uninstalled sysroot."""
import argparse
import concurrent.futures
import getpass
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True
from runtime import ARCHES, digest, fetch
from workspace import ROOT, BUILD, DOWNLOADS


def control(text):
    return dict(line.split(": ", 1) for line in text.splitlines()
                if line and not line[0].isspace() and ": " in line)


def update_lock(arch, work, archives, lock):
    debian = ARCHES[arch]["debian"]
    apt = work / "apt"
    for name in ["state/lists/partial", "cache", "etc/empty", "log"]:
        (apt / name).mkdir(parents=True, exist_ok=True)
    apt_archives = apt / "archives"
    if apt_archives.exists():
        shutil.rmtree(apt_archives)
    (apt_archives / "partial").mkdir(parents=True)
    (apt / "state/status").write_text("")
    keyring = Path("/usr/share/keyrings/debian-archive-keyring.gpg")
    if not keyring.is_file():
        raise SystemExit("Install debian-archive-keyring to authenticate runtime packages")
    mirror = "https://deb.debian.org/debian/"
    (apt / "etc/sources.list").write_text(
        f"deb [arch={debian} signed-by={keyring}] {mirror} trixie main\n")
    options = []
    for name, value in {
        "Dir": apt, "Dir::State": apt / "state", "Dir::Cache": apt / "cache",
        "Dir::Log": apt / "log", "Dir::Etc::sourcelist": apt / "etc/sources.list",
        "Dir::Etc::sourceparts": apt / "etc/empty", "Dir::State::status": apt / "state/status",
        "Dir::Cache::archives": apt_archives, "APT::Architecture": debian,
        "Dir::Etc::preferencesparts": apt / "etc/empty",
        "APT::Sandbox::User": getpass.getuser(), "Acquire::Languages": "none",
        "APT::Install-Recommends": "false", "APT::Install-Suggests": "false",
        "Debug::NoLocking": "true",
    }.items():
        options += ["-o", f"{name}={value}"]
    subprocess.run(["apt-get", *options, "update"], check=True)
    requested = [ARCHES[arch]["package"], "busybox", "ca-certificates", "base-files"]
    if arch == "riscv64":
        requested.append("opensbi")
    subprocess.run(["apt-get", *options, "--download-only", "--no-install-recommends", "-y",
                    "install", *requested], check=True)
    packages = []
    for archive in sorted(apt_archives.glob("*.deb")):
        fields = control(subprocess.check_output(["dpkg-deb", "-f", str(archive)], text=True))
        name, version = fields["Package"], fields["Version"]
        metadata = control(subprocess.check_output(
            ["apt-cache", *options, "show", f"{name}={version}"], text=True).split("\n\n")[0])
        if digest(archive) != metadata["SHA256"]:
            raise ValueError(f"Package differs from authenticated APT metadata: {name}")
        shutil.copy2(archive, archives / Path(metadata["Filename"]).name)
        source = fields.get("Source", name)
        match = re.fullmatch(r"(\S+)(?: \(([^)]+)\))?", source)
        packages.append({"name": name, "version": version, "architecture": fields["Architecture"],
                         "source": match[1], "source_version": match[2] or version,
                         "url": mirror + metadata["Filename"], "sha256": metadata["SHA256"],
                         "bytes": archive.stat().st_size})
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(json.dumps({"distribution": "Debian 13 (trixie)", "architecture": arch,
                                "packages": packages}, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=ARCHES, required=True)
    parser.add_argument("--update-lock", action="store_true",
                        help="Maintainer operation: resolve versions from signed APT metadata")
    args = parser.parse_args()
    work = BUILD / "runtime" / args.arch
    archives = DOWNLOADS / "runtime" / args.arch / "packages"
    archives.mkdir(parents=True, exist_ok=True)
    (archives / "partial").mkdir(exist_ok=True)
    lock = ROOT / "config/runtime" / (args.arch + ".json")
    if args.update_lock:
        update_lock(args.arch, work, archives, lock)
    if not lock.is_file():
        raise SystemExit(f"Missing runtime lock: {lock}")
    specification = json.loads(lock.read_text())
    sysroot = work / "sysroot"
    marker = work / "sysroot.sha256"
    if sysroot.is_dir() and marker.is_file() and marker.read_text().strip() == digest(lock):
        print(f"Verified package sysroot already prepared: {sysroot}")
        return

    def download(package):
        return fetch(package["url"], package["sha256"], archives / Path(package["url"]).name)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        downloaded = list(executor.map(download, specification["packages"]))
    if sysroot.exists():
        shutil.rmtree(sysroot)
    sysroot.mkdir(parents=True)
    for name in ["bin", "sbin", "lib", "lib64"]:
        (sysroot / "usr" / name).mkdir(parents=True, exist_ok=True)
        (sysroot / name).symlink_to("usr/" + name)
    for archive in downloaded:
        subprocess.run(["dpkg-deb", "-x", str(archive), str(sysroot)], check=True)
    marker.write_text(digest(lock) + "\n")
    print(f"Prepared {args.arch} runtime: {len(downloaded)} packages in {sysroot}")


if __name__ == "__main__":
    main()
