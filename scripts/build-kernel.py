#!/usr/bin/env python3
"""Cross-build the pinned Linux runtime with built-in VM and BPF drivers."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import sys
sys.dont_write_bytecode = True
from runtime import ARCHES, digest, fetch
from workspace import ROOT, BUILD, DOWNLOADS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=ARCHES, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--configure-only", action="store_true")
    parser.add_argument("--jit-selftest", action="store_true", help="Also build the upstream BPF JIT test module")
    args = parser.parse_args()
    specification = json.loads((ROOT / "config/runtime-sources.json").read_text())["linux"]
    patches = [ROOT / "patches" / name for name in
               ["linux-riscv64-jit-zext.patch", "linux-riscv64-jit-region.patch"]]
    patch_inventory = {patch.name: digest(patch) for patch in patches}
    source = BUILD / "runtime/source" / ("linux-" + specification["version"])
    source.parent.mkdir(parents=True, exist_ok=True)
    marker = source.parent / (source.name + ".sha256")
    with (source.parent / ".prepare.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        archive = fetch(specification["url"], specification["sha256"],
                        DOWNLOADS / "runtime" / (source.name + ".tar.xz"))
        if not source.is_dir() or not marker.is_file() or marker.read_text().strip() != specification["sha256"]:
            if source.exists():
                raise SystemExit(f"Unverified kernel source directory exists: {source}; move it aside before rebuilding")
            with tempfile.TemporaryDirectory(prefix="extract-", dir=source.parent) as temporary:
                with tarfile.open(archive) as packed:
                    packed.extractall(temporary, filter="data")
                (Path(temporary) / source.name).rename(source)
            (source.parent / (source.name + ".patches.json")).unlink(missing_ok=True)
            marker.write_text(specification["sha256"] + "\n")
        patched = source.parent / (source.name + ".patches.json")
        applied = {}
        if patched.is_file():
            applied = json.loads(patched.read_text())
            if any(patch_inventory.get(name) != checksum for name, checksum in applied.items()):
                raise SystemExit(f"Kernel patch set changed; move {source} and {patched} aside before rebuilding")
        if applied != patch_inventory:
            for patch in patches:
                if patch.name in applied:
                    continue
                command = ["patch", "--batch", "--forward", "-p1", "-i", str(patch)]
                # A prior interrupted build may already have applied this patch.
                if subprocess.run([*command, "--dry-run"], cwd=source,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    subprocess.run(command, cwd=source, check=True)
                else:
                    subprocess.run(["patch", "--batch", "--reverse", "--dry-run", "-p1", "-i", str(patch)],
                                   cwd=source, check=True)
            patched.write_text(json.dumps(patch_inventory, indent=2) + "\n")
    build = BUILD / "runtime" / args.arch / "kernel"
    build.mkdir(parents=True, exist_ok=True)
    fragment = build / "requested.config"
    fragment.write_text("\n".join((ROOT / "config/kernel" / (name + ".config")).read_text()
                                   for name in ("common", args.arch)))
    environment = dict(os.environ, KCONFIG_ALLCONFIG=str(fragment),
                       KBUILD_BUILD_USER="builder", KBUILD_BUILD_HOST="lashos",
                       KBUILD_BUILD_TIMESTAMP="2026-09-14 00:00:00 +0000", KBUILD_BUILD_VERSION="1")
    command = ["make", "-C", str(source), "O=" + str(build), "ARCH=" + ARCHES[args.arch]["linux"],
               "LLVM=1", "HOSTCC=cc", "HOSTCXX=c++"]
    pahole_flags = ""
    if args.arch == "riscv64":
        # This pinned toolchain emits overlapping per-CPU variable offsets on
        # RISC-V. Keep BTF types, function prototypes and kfunc metadata, while
        # omitting the optional global-variable records (unused by this image).
        pahole_flags = ("--btf_features=encode_force,float,enum64,decl_tag,type_tag,"
                        "optimized_func,consistent_func,decl_tag_kfuncs,attributes "
                        "--skip_encoding_btf_vars")
        command.append("PAHOLE_FLAGS=" + pahole_flags)
    subprocess.run(command + ["alldefconfig"], env=environment, check=True)
    config = dict(line.split("=", 1) for line in (build / ".config").read_text().splitlines()
                  if line.startswith("CONFIG_") and "=" in line)
    required = ["64BIT", "BPF_SYSCALL", "BPF_JIT_ALWAYS_ON", "BPF_EVENTS", "DEBUG_INFO_BTF",
                "BINFMT_ELF", "BINFMT_SCRIPT", "BLK_DEV_INITRD", "VIRTIO_PCI", "VIRTIO_CONSOLE",
                "VIRTIO_NET", "9P_FS", "NET_9P_VIRTIO", "UNIX98_PTYS", "DEVTMPFS", "TMPFS"]
    if args.arch == "riscv64":
        required += ["RISCV_ISA_ZACAS"]
    missing = [name for name in required if config.get("CONFIG_" + name) != "y"]
    if missing:
        raise SystemExit("Required kernel features not enabled: " + ", ".join(missing))
    if args.configure_only:
        return
    previous_flags = build / "pahole-flags"
    if pahole_flags and (not previous_flags.exists() or previous_flags.read_text() != pahole_flags):
        # Kbuild does not track this exported environment setting in the final
        # link command. Force BTF regeneration when the encoding options change.
        (build / "vmlinux").unlink(missing_ok=True)
        (build / "vmlinux.unstripped").unlink(missing_ok=True)
    previous_flags.write_text(pahole_flags)
    image = ARCHES[args.arch]["image"]
    subprocess.run(command + [f"-j{args.jobs}", image.split("/")[-1]], env=environment, check=True)
    destination = build.parent / "kernel.bin"
    shutil.copy2(build / image, destination)
    manifest = {"architecture": args.arch, "linux": specification,
                "sha256": digest(destination), "config_sha256": digest(build / ".config"),
                "pahole_flags": pahole_flags, "patches": patch_inventory}
    (build.parent / "kernel.json").write_text(json.dumps(manifest, indent=2) + "\n")
    if args.jit_selftest:
        subprocess.run(command + [f"-j{args.jobs}", "CONFIG_TEST_BPF=m", "lib/test_bpf.ko"],
                       env=environment, check=True)
    print(f"Built {args.arch} Linux {specification['version']}: {destination}")


if __name__ == "__main__":
    main()
