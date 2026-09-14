#!/usr/bin/env python3
"""Bundle a Linux/KVM runtime into both loaders; no host tools are needed at launch."""
import sys
sys.dont_write_bytecode = True
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tempfile

from elf_dependencies import inspect, require_static

from workspace import ROOT, BUILD, OUT, PATHS
MAGIC = b"LASHOS-VM-v1".ljust(16, b"\0")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def publish(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + destination.name + "-", dir=destination.parent)
    os.close(fd)
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def newc(stage):
    archive = bytearray()
    inode = 0

    def entry(name, mode, data=b"", major=0, minor=0):
        nonlocal inode
        inode += 1
        encoded = name.encode() + b"\0"
        fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(encoded), 0]
        archive.extend(b"070701" + b"".join(f"{n:08x}".encode() for n in fields))
        archive.extend(encoded)
        archive.extend(b"\0" * (-len(archive) % 4))
        archive.extend(data)
        archive.extend(b"\0" * (-len(archive) % 4))

    for path in sorted(stage.rglob("*")):
        data = os.readlink(path).encode() if path.is_symlink() else path.read_bytes() if path.is_file() else b""
        entry(str(path.relative_to(stage)), path.lstat().st_mode, data)
    entry("dev/console", stat.S_IFCHR | 0o600, major=5, minor=1)
    entry("TRAILER!!!", 0)
    return archive


def dependencies(binary):
    # Build inputs are trusted distribution executables, never guest-supplied files.
    run = subprocess.run(["/usr/bin/ldd", str(binary)], text=True, capture_output=True,
                         env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    if "not found" in run.stdout:
        raise ValueError(f"Unresolved runtime dependencies for {binary}: {run.stdout}")
    return sorted({Path(p) for p in re.findall(r"(/[^\s()]+)", run.stdout) if Path(p).is_file()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, default=PATHS['kernel'])
    parser.add_argument("--modules", type=Path, default=PATHS['modules'])
    parser.add_argument("--qemu", type=Path, default=PATHS['qemu'])
    args = parser.parse_args()
    if os.uname().machine != "x86_64":
        parser.error("The bundled VM currently targets x86_64 Linux")
    raw = BUILD / 'portable/linux-bash-os'
    init = BUILD / 'portable/sandbox-init'
    require_static(raw)
    require_static(init)
    work = BUILD / 'sandbox'
    work.mkdir(parents=True, exist_ok=True)
    inventory = []
    packages = set()

    def record(source):
        source = Path(source)
        inventory.append({"source": str(source), "sha256": digest(source), "bytes": source.stat().st_size})
        if str(source).startswith(("/usr/", "/lib", "/boot/")):
            query = subprocess.run(["dpkg-query", "-S", str(source)], text=True, capture_output=True)
            if query.returncode:
                query = subprocess.run(["dpkg-query", "-S", str(source.resolve())], text=True, capture_output=True)
            for line in query.stdout.splitlines():
                if ": " in line:
                    packages.add(line.split(": ", 1)[0])

    with tempfile.TemporaryDirectory(prefix="stage-", dir=work) as temporary:
        stage = Path(temporary)
        guest, bundle = stage / "guest", stage / "bundle"
        guest.mkdir()
        bundle.mkdir()
        for directory in ["bin", "sbin", "usr/bin", "dev", "proc", "sys", "tmp", "etc", "root", "home", "run", "modules"]:
            (guest / directory).mkdir(parents=True, exist_ok=True)
        (guest / "tmp").chmod(0o1777)
        for source, name in [(raw, "bin/linux-bash-os"), (init, "init")]:
            shutil.copy2(source, guest / name)
            record(source)
        for name in ["sh", "bash"]:
            (guest / "bin" / name).symlink_to("linux-bash-os")
        # A small collection of external tools for scripts. Builtins still execute in BPF.
        busybox = Path("/usr/bin/busybox")
        shutil.copy2(busybox, guest / "bin/busybox")
        record(busybox)
        for library in dependencies(busybox):
            target = guest / str(library).lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(library, target)
            record(library)
        for name in subprocess.check_output([str(busybox), "--list"], text=True).splitlines():
            target = guest / "bin" / name
            if not target.exists():
                target.symlink_to("busybox")
        shutil.copyfile(ROOT / "config/os-release", guest / "etc/os-release")
        (guest / "etc/passwd").write_text("root:x:0:0:root:/home:/bin/bash\n")
        (guest / "etc/group").write_text("root:x:0:\n")
        (guest / "etc/hosts").write_text("127.0.0.1 localhost lash-os\n::1 localhost\n")
        (guest / "etc/resolv.conf").write_text("nameserver 10.0.2.3\n")
        certs = Path("/etc/ssl/certs/ca-certificates.crt")
        if certs.is_file():
            (guest / "etc/ssl/certs").mkdir(parents=True)
            shutil.copy2(certs, guest / "etc/ssl/certs/ca-certificates.crt")
            record(certs)
            packages.add("ca-certificates")

        dependency_map = {}
        for line in (args.modules / "modules.dep").read_text().splitlines():
            name, deps = line.split(":", 1)
            dependency_map[name] = deps.split()
        ordered = []

        def add_module(name):
            if name in ordered:
                return
            for dependency in dependency_map[name]:
                add_module(dependency)
            ordered.append(name)

        for module in ["9p", "9pnet_virtio", "virtio_net"]:
            matches = [p for p in dependency_map if Path(p).name.split(".")[0] == module]
            if len(matches) != 1:
                raise ValueError(f"Expected one {module} module in {args.modules}")
            add_module(matches[0])
        module_list = []
        for i, name in enumerate(ordered):
            source = args.modules / name
            data = source.read_bytes()
            if source.suffix == ".xz":
                data = lzma.decompress(data)
            elif source.suffix == ".zst":
                data = subprocess.check_output(["zstd", "-dc", str(source)])
            elif source.suffix != ".ko":
                raise ValueError(f"Unsupported module compression: {source}")
            destination = f"modules/{i:02d}.ko"
            (guest / destination).write_bytes(data)
            module_list.append("/" + destination)
            record(source)
        (guest / "modules/load").write_text("\n".join(module_list) + "\n")
        (bundle / "initramfs").write_bytes(newc(guest))
        shutil.copy2(args.kernel, bundle / "kernel")
        record(args.kernel)
        shutil.copy2(args.qemu, bundle / "qemu")
        record(args.qemu)
        elf = inspect(args.qemu)
        if not elf["interpreter"] or elf["runtime_search_paths"]:
            raise ValueError("Expected a distribution QEMU with a dynamic loader and no RPATH")
        interpreter = Path(elf["interpreter"])
        shutil.copy2(interpreter, bundle / "ld.so")
        record(interpreter)
        (bundle / "lib").mkdir()
        for library in dependencies(args.qemu):
            if library.resolve() == interpreter.resolve():
                continue
            if inspect(library)["runtime_search_paths"]:
                raise ValueError(f"Unexpected runtime library path in {library}")
            destination = bundle / "lib" / library.name
            if destination.exists() and digest(destination) != digest(library):
                raise ValueError(f"Library name collision: {library}")
            shutil.copy2(library, destination)
            record(library)
        (bundle / "firmware").mkdir()
        firmware = [Path("/usr/share/seabios/bios-256k.bin")]
        firmware += [Path("/usr/share/qemu") / n for n in ["linuxboot_dma.bin", "linuxboot.bin", "kvmvapic.bin", "pvh.bin"]]
        for source in firmware:
            shutil.copy2(source, bundle / "firmware" / source.name)
            record(source)

        versions = {}
        (bundle / "licenses").mkdir()
        for package in sorted(packages):
            name = package.split(":")[0]
            copyright_file = Path("/usr/share/doc") / name / "copyright"
            if copyright_file.is_file():
                shutil.copy2(copyright_file, bundle / "licenses" / (name + ".copyright"))
            query = subprocess.run(["dpkg-query", "-W", "-f=${Version}", package], text=True, capture_output=True)
            if not query.returncode:
                versions[package] = query.stdout
        for source in Path("/usr/share/common-licenses").iterdir():
            if source.is_file():
                shutil.copy2(source, bundle / "licenses" / source.name)
        manifest = {
            "format": "LASHOS-VM-v1", "architecture": "x86_64-linux",
            "kernel": str(args.kernel), "qemu_version": subprocess.check_output([str(args.qemu), "--version"], text=True).splitlines()[0],
            "bpf_sha256": digest(BUILD / 'kernel-full/bash.bpf.o'),
            "guest_loader_sha256": digest(raw), "guest_init_sha256": digest(init),
            "default_memory_mib": 4096, "default_cpus": 2, "default_network": "user",
            "packages": versions, "inputs": inventory,
            "source_locations": ["https://www.debian.org/distrib/packages", "https://snapshot.debian.org/", "https://www.qemu.org/download/", "https://kernel.org/"],
        }
        (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        archive = work / "bundle.archive"
        with archive.open("wb") as output:
            for source in sorted(bundle.rglob("*")):
                if not source.is_file():
                    continue
                name = str(source.relative_to(bundle)).encode()
                data = source.read_bytes()
                mode = 0o700 if source.name in ["qemu", "ld.so"] else 0o600
                output.write(struct.pack("<IIQ", len(name), mode, len(data)))
                output.write(name)
                output.write(data)
            output.write(bytes(16))
        compressed = work / "bundle.zst"
        subprocess.run(["zstd", "-q", "-f", "-6", "--check", str(archive), "-o", str(compressed)], check=True)
        for profile, base in [("full", BUILD / 'kernel-full/linux-bash-os'), ("portable", raw)]:
            destination = work / (profile + "-linux-bash-os")
            with destination.open("wb") as output, base.open("rb") as original, compressed.open("rb") as packed:
                shutil.copyfileobj(original, output)
                offset = output.tell()
                shutil.copyfileobj(packed, output)
                output.write(MAGIC + struct.pack("<QQQ", offset, compressed.stat().st_size, archive.stat().st_size))
            destination.chmod(0o755)
            profile_manifest = dict(manifest, loader_sha256=digest(destination), bytes=destination.stat().st_size,
                                    base_loader_sha256=digest(base), bundle_sha256=digest(compressed),
                                    elf=inspect(destination))
            if profile == "portable":
                require_static(destination)
            manifest_path = work / (profile + ".json")
            manifest_path.write_text(json.dumps(profile_manifest, indent=2) + "\n")
            publish(destination, OUT / profile / "linux-bash-os")
            publish(manifest_path, OUT / profile / ("portable.json" if profile == "portable" else "sandbox.json"))
            print(f"Bundled {profile} executable: {destination.stat().st_size:,} bytes", flush=True)
        publish(BUILD / 'kernel-full/bash.bpf.o', OUT / 'full/bash.bpf.o')


if __name__ == "__main__":
    main()
