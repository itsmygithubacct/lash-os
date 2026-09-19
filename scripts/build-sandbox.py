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

from elf_dependencies import inspect, require_static, require_arch
from runtime import ARCHES, rooted

from workspace import ROOT, BUILD, DOWNLOADS, OUT, PATHS, source_state
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
        # Normalize permissions so the archive does not depend on the builder's umask.
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            mode, data = stat.S_IFLNK | 0o777, os.readlink(path).encode()
        elif stat.S_ISDIR(info.st_mode):
            mode, data = stat.S_IFDIR | (0o1777 if info.st_mode & stat.S_ISVTX else 0o755), b""
        elif stat.S_ISREG(info.st_mode):
            mode, data = stat.S_IFREG | (0o755 if info.st_mode & 0o111 else 0o644), path.read_bytes()
        else:
            raise ValueError(f"Unsupported initramfs entry type: {path}")
        entry(str(path.relative_to(stage)), mode, data)
    entry("dev/console", stat.S_IFCHR | 0o600, major=5, minor=1)
    entry("TRAILER!!!", 0)
    return archive


def dependencies(binary, sysroot=None, triplet=None):
    if sysroot is not None:
        found = {}
        pending = [binary]
        directories = [f"usr/lib/{triplet}", f"lib/{triplet}", "usr/lib", "lib"]
        while pending:
            current = pending.pop()
            elf = inspect(current)
            if elf["runtime_search_paths"]:
                raise ValueError(f"Unexpected runtime search path: {current}")
            for name in elf["needed_libraries"]:
                if name in found:
                    continue
                matches = [rooted(sysroot, directory + "/" + name) for directory in directories]
                library = next((path for path in matches if path.is_file()), None)
                if library is None:
                    raise ValueError(f"Unresolved {name} required by {current}")
                found[name] = library
                pending.append(library)
        # Preserve DT_NEEDED names even when their files resolve to a versioned
        # symlink target with a different basename.
        return sorted(found.items())
    # Build inputs are trusted distribution executables, never guest-supplied files.
    run = subprocess.run(["/usr/bin/ldd", str(binary)], text=True, capture_output=True,
                         env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    if "not found" in run.stdout:
        raise ValueError(f"Unresolved runtime dependencies for {binary}: {run.stdout}")
    return sorted({Path(p) for p in re.findall(r"(/[^\s()]+)", run.stdout) if Path(p).is_file()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=ARCHES, help="Bundle the pinned cross-built runtime")
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--modules", type=Path)
    parser.add_argument("--qemu", type=Path)
    args = parser.parse_args()
    arch = args.arch or os.uname().machine
    if arch not in ARCHES:
        parser.error("Unsupported host architecture")
    profile = "portable" if arch == "x86_64" else "portable-" + arch
    sysroot, package_lock, kernel_manifest = None, None, None
    if args.arch:
        if args.kernel or args.modules or args.qemu:
            parser.error("--arch uses the pinned runtime; host runtime overrides cannot be combined with it")
        runtime = BUILD / "runtime" / arch
        sysroot = runtime / "sysroot"
        package_lock = json.loads((ROOT / "config/runtime" / (arch + ".json")).read_text())
        kernel_manifest = json.loads((runtime / "kernel.json").read_text())
        args.kernel = runtime / "kernel.bin"
        if digest(args.kernel) != kernel_manifest["sha256"]:
            raise ValueError("Runtime kernel differs from its build manifest")
        args.qemu = rooted(sysroot, "usr/bin/" + ARCHES[arch]["qemu"])
    else:
        if arch != "x86_64":
            parser.error("Use --arch for ARM64 and RISC-V64 runtimes")
        args.kernel = args.kernel or PATHS["kernel"]
        args.modules = args.modules or PATHS["modules"]
        args.qemu = args.qemu or PATHS["qemu"]
    raw = BUILD / profile / 'linux-bash-os'
    init = BUILD / profile / 'sandbox-init'
    base_manifest = json.loads((BUILD / profile / "portable.json").read_text())
    bpf_image = BUILD / profile / "bash.bpf.o"
    if (digest(raw) != base_manifest["loader_sha256"] or
            digest(bpf_image) != base_manifest["bpf_sha256"]):
        raise ValueError("Portable build inputs differ from their verified manifest; rebuild the static loader")
    require_static(raw)
    require_static(init)
    for executable in [raw, init, args.qemu]:
        require_arch(executable, arch)
    work = BUILD / ('sandbox-' + arch if args.arch else 'sandbox')
    work.mkdir(parents=True, exist_ok=True)
    inventory = []
    packages = set()

    def libraries(binary):
        found = dependencies(binary, sysroot, ARCHES[arch]["triplet"])
        return found if sysroot else [(path.name, path) for path in found]

    def run_target(binary, *arguments):
        command = [str(binary), *arguments]
        if sysroot:
            if arch != os.uname().machine:
                command = ["qemu-" + arch, "-L", str(sysroot), *command]
            else:
                interpreter = rooted(sysroot, inspect(binary)["interpreter"])
                command = [str(interpreter), "--library-path", str(sysroot / "usr/lib" / ARCHES[arch]["triplet"]), *command]
        return subprocess.check_output(command, text=True)

    def label(source):
        # Published inventories name inputs without the maintainer's local directories.
        source = Path(source)
        if sysroot and source.is_relative_to(sysroot):
            return str(source.relative_to(sysroot))
        for base, name in [(BUILD, "build"), (DOWNLOADS, "downloads"), (ROOT, "source")]:
            if source.is_relative_to(base):
                return name + "/" + str(source.relative_to(base))
        if str(source).startswith(("/usr/", "/lib", "/boot/", "/etc/", "/nix/store/")):
            return str(source)
        return "local/" + source.name

    def record(source):
        source = Path(source)
        inventory.append({"source": label(source), "sha256": digest(source), "bytes": source.stat().st_size})
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
        busybox = rooted(sysroot, "usr/bin/busybox") if sysroot else Path("/usr/bin/busybox")
        require_arch(busybox, arch)
        shutil.copy2(busybox, guest / "bin/busybox")
        record(busybox)
        for soname, library in libraries(busybox):
            name = library.relative_to(sysroot).with_name(soname) if sysroot else str(library).lstrip("/")
            target = guest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(library, target)
            record(library)
        if sysroot:
            interpreter = inspect(busybox)["interpreter"]
            target = guest / interpreter.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(rooted(sysroot, interpreter), target)
            record(rooted(sysroot, interpreter))
        for name in run_target(busybox, "--list").splitlines():
            target = guest / "bin" / name
            if not target.exists():
                target.symlink_to("busybox")
        shutil.copyfile(ROOT / "config/os-release", guest / "etc/os-release")
        (guest / "etc/passwd").write_text("root:x:0:0:root:/home:/bin/bash\n")
        (guest / "etc/group").write_text("root:x:0:\n")
        (guest / "etc/hosts").write_text("127.0.0.1 localhost lash-os\n::1 localhost\n")
        (guest / "etc/resolv.conf").write_text("nameserver 10.0.2.3\n")
        certs = Path("/etc/ssl/certs/ca-certificates.crt")
        if sysroot:
            (guest / "etc/ssl/certs").mkdir(parents=True)
            trusted = sorted((sysroot / "usr/share/ca-certificates/mozilla").glob("*.crt"))
            if not trusted:
                raise ValueError("Runtime has no Mozilla CA certificates")
            (guest / "etc/ssl/certs/ca-certificates.crt").write_bytes(b"\n".join(p.read_bytes() for p in trusted))
            for certificate in trusted:
                record(certificate)
        elif certs.is_file():
            (guest / "etc/ssl/certs").mkdir(parents=True)
            shutil.copy2(certs, guest / "etc/ssl/certs/ca-certificates.crt")
            record(certs)
            packages.add("ca-certificates")

        dependency_map = {}
        for line in (args.modules / "modules.dep").read_text().splitlines() if args.modules else []:
            name, deps = line.split(":", 1)
            dependency_map[name] = deps.split()
        ordered = []

        def add_module(name):
            if name in ordered:
                return
            for dependency in dependency_map[name]:
                add_module(dependency)
            ordered.append(name)

        for module in ["9p", "9pnet_virtio", "virtio_net"] if args.modules else []:
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
        (guest / "modules/load").write_text("".join(name + "\n" for name in module_list))
        (bundle / "initramfs").write_bytes(newc(guest))
        shutil.copy2(args.kernel, bundle / "kernel")
        record(args.kernel)
        shutil.copy2(args.qemu, bundle / "qemu")
        record(args.qemu)
        elf = inspect(args.qemu)
        if not elf["interpreter"] or elf["runtime_search_paths"]:
            raise ValueError("Expected a distribution QEMU with a dynamic loader and no RPATH")
        interpreter = rooted(sysroot, elf["interpreter"]) if sysroot else Path(elf["interpreter"])
        shutil.copy2(interpreter, bundle / "ld.so")
        record(interpreter)
        (bundle / "lib").mkdir()
        for soname, library in libraries(args.qemu):
            if library.resolve() == interpreter.resolve():
                continue
            if inspect(library)["runtime_search_paths"]:
                raise ValueError(f"Unexpected runtime library path in {library}")
            destination = bundle / "lib" / soname
            if destination.exists() and digest(destination) != digest(library):
                raise ValueError(f"Library name collision: {library}")
            shutil.copy2(library, destination)
            record(library)
        (bundle / "firmware").mkdir()
        firmware = []
        if arch == "x86_64":
            firmware = [Path("/usr/share/seabios/bios-256k.bin")]
            firmware += [Path("/usr/share/qemu") / n for n in ["linuxboot_dma.bin", "linuxboot.bin", "kvmvapic.bin", "pvh.bin"]]
        elif arch == "riscv64":
            firmware = [Path("/usr/lib/riscv64-linux-gnu/opensbi/generic/fw_dynamic.bin")]
        if sysroot:
            firmware = [rooted(sysroot, path) for path in firmware]
        for source in firmware:
            shutil.copy2(source, bundle / "firmware" / source.name)
            record(source)

        available = {path.name for path in (bundle / "lib").iterdir()} | {Path(elf["interpreter"]).name}
        for executable in [bundle / "qemu", bundle / "ld.so", *(bundle / "lib").iterdir()]:
            metadata = require_arch(executable, arch)
            missing = set(metadata["needed_libraries"]) - available
            if missing:
                raise ValueError(f"Incomplete bundled runtime for {executable.name}: {sorted(missing)}")
        check_runtime = [str(bundle / "ld.so"), "--inhibit-cache", "--library-path", str(bundle / "lib"),
                         str(bundle / "qemu"), "--version"]
        if arch != os.uname().machine:
            check_runtime.insert(0, "qemu-" + arch)
        qemu_version = subprocess.check_output(check_runtime, text=True).splitlines()[0]

        versions = {}
        (bundle / "licenses").mkdir()
        shutil.copyfile(ROOT / "LICENSE", bundle / "licenses/lashos.GPL-3.0")
        for source in sorted((ROOT / "vendor").rglob("*")):
            if source.is_file() and source.name.upper().startswith(("LICENSE", "COPYING", "COPYRIGHT")):
                name = "__".join(source.relative_to(ROOT).parts)
                shutil.copy2(source, bundle / "licenses" / name)
        if package_lock:
            packages = {package["name"] for package in package_lock["packages"]}
            versions = {package["name"]: package["version"] for package in package_lock["packages"]}
            shutil.copyfile(BUILD / "runtime/source" / ("linux-" + kernel_manifest["linux"]["version"]) / "COPYING",
                            bundle / "licenses/Linux.COPYING")
            shutil.copyfile(BUILD / "runtime" / arch / "kernel/.config", bundle / "kernel.config")
        for package in sorted(packages):
            name = package.split(":")[0]
            copyright_file = Path("/usr/share/doc") / name / "copyright"
            if sysroot:
                copyright_file = rooted(sysroot, copyright_file)
            if copyright_file.is_file():
                shutil.copy2(copyright_file, bundle / "licenses" / (name + ".copyright"))
            if not sysroot:
                query = subprocess.run(["dpkg-query", "-W", "-f=${Version}", package], text=True, capture_output=True)
                if not query.returncode:
                    versions[package] = query.stdout
        common_licenses = rooted(sysroot, "usr/share/common-licenses") if sysroot else Path("/usr/share/common-licenses")
        for source in common_licenses.iterdir() if common_licenses.exists() else []:
            if source.is_file():
                shutil.copy2(source, bundle / "licenses" / source.name)
        manifest = {
            "format": "LASHOS-VM-v1", "architecture": arch + "-linux",
            "runtime": "pinned" if args.arch else "build-host",
            "kernel": kernel_manifest or label(args.kernel), "qemu_version": qemu_version,
            "build_source": source_state(), "loader_build_source": base_manifest.get("build_source"),
            "bpf_sha256": digest(bpf_image),
            "guest_loader_sha256": digest(raw), "guest_init_sha256": digest(init),
            "default_memory_mib": 4096, "default_cpus": 2, "default_network": "user",
            "packages": versions, "inputs": inventory,
            "package_sources": package_lock,
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
        # Pinned bundles publish to portable*/; the build-host runtime has its own
        # output so it can never replace a pinned x86_64 release candidate.
        outputs = [(profile, raw)] if args.arch else [("full", BUILD / 'kernel-full/linux-bash-os'), ("portable-host", raw)]
        for name, base in outputs:
            if bpf_image.read_bytes() not in base.read_bytes():
                raise ValueError(f"The {name} loader embeds a different BPF image; rebuild before bundling")
            destination = work / (name + "-linux-bash-os")
            with destination.open("wb") as output, base.open("rb") as original, compressed.open("rb") as packed:
                shutil.copyfileobj(original, output)
                offset = output.tell()
                shutil.copyfileobj(packed, output)
                output.write(MAGIC + struct.pack("<QQQ", offset, compressed.stat().st_size, archive.stat().st_size))
            destination.chmod(0o755)
            profile_manifest = dict(manifest, loader_sha256=digest(destination), bytes=destination.stat().st_size,
                                    base_loader_sha256=digest(base), bundle_sha256=digest(compressed),
                                    elf=inspect(destination))
            if name.startswith("portable"):
                require_static(destination)
            manifest_path = work / (name + ".json")
            manifest_path.write_text(json.dumps(profile_manifest, indent=2) + "\n")
            publish(destination, OUT / name / "linux-bash-os")
            publish(manifest_path, OUT / name / ("portable.json" if name.startswith("portable") else "sandbox.json"))
            print(f"Bundled {name} executable: {destination.stat().st_size:,} bytes", flush=True)
        publish(bpf_image, OUT / (profile if args.arch else "full") / 'bash.bpf.o')


if __name__ == "__main__":
    main()
