#!/usr/bin/env python3
"""Boot an isolated local Linux kernel and test the actual BPF executable."""
import sys
sys.dont_write_bytecode = True
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import signal
import threading
import time
from elf_dependencies import require_static

from workspace import ROOT, BUILD, REPORTS, PATHS, prepare_work

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", default=str(PATHS['kernel']))
    parser.add_argument("--build", type=Path, default=BUILD / 'kernel-full')
    parser.add_argument("--reference", type=Path, default=BUILD / 'native-full/source/out/bash-kernel-reference')
    parser.add_argument("--cases", type=Path, default=ROOT / "tests/full-cases.sh")
    parser.add_argument("--init", type=Path, default=ROOT / "tests/full-init.sh")
    parser.add_argument("--work", type=Path, default=REPORTS / 'vm')
    parser.add_argument("--portable", action="store_true", help="Require static loading and remove /nix before kernel cases")
    parser.add_argument("--timeout", type=int, default=1500)
    parser.add_argument("--memory", type=int, default=8192, help="Guest memory in MiB")
    args = parser.parse_args()
    if args.memory < 256:
        parser.error("--memory must be at least 256 MiB")
    if args.portable:
        require_static(args.build / "linux-bash-os")
        require_static(args.build / "job-control-test")
    try:
        work = prepare_work(args.work)
    except ValueError as error:
        parser.error(str(error))
    stage = work / "root"
    # A reused staging tree could hide missing runtime dependencies.
    if stage.is_symlink():
        stage.unlink()
    elif stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True, exist_ok=True)

    def copy_binary(source, target, fixture=False):
        source = Path(source)
        destination = stage / target.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.unlink(missing_ok=True)
        shutil.copy2(source, destination)
        result = subprocess.run(["ldd", str(source)], capture_output=True, text=True)
        for name in set(re.findall(r"(/[^\s()]+)", result.stdout)):
            library = Path(name)
            if args.portable and fixture and library.is_relative_to("/nix"):
                raise SystemExit(f"Portable VM fixture {source} depends on {library}; run this test outside nix develop")
            if library.is_file():
                to = stage / name.lstrip("/")
                to.parent.mkdir(parents=True, exist_ok=True)
                to.unlink(missing_ok=True)
                shutil.copy2(library, to)

    copy_binary(shutil.which("busybox"), "/bin/busybox", fixture=True)
    copy_binary(shutil.which("script"), "/bin/script", fixture=True)
    if args.portable:
        copy_binary(args.build / "job-control-test", "/job-control-test", fixture=True)
        (stage / "portable-test").touch()
    else:
        subprocess.run(["cc", "-O2", "-Wall", "-Wextra", str(ROOT / "tests/job-control.c"),
                        "-o", str(work / 'job-control-test'), "-lutil"], check=True)
        copy_binary(work / 'job-control-test', "/job-control-test")
    copy_binary(args.build / "linux-bash-os", "/kernel-bash")
    copy_binary(args.reference, "/native-bash")
    for directory in ["dev", "proc", "sys", "tmp", "etc", "root"]:
        (stage / directory).mkdir(exist_ok=True)
    (stage / "bin/sh").unlink(missing_ok=True)
    (stage / "bin/sh").symlink_to("busybox")
    (stage / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    (stage / "etc/group").write_text("root:x:0:\n")
    # These tests exercise direct BPF loading inside their existing test VM.
    shutil.copyfile(ROOT / "config/os-release", stage / "etc/os-release")
    shutil.copyfile(ROOT/"config/builtin-names", stage/"builtin-names")
    shutil.copyfile(ROOT/"tests/cases.sh", stage/"core-cases.sh")
    shutil.copyfile(ROOT/"tests/network-cases.sh", stage/"network-cases.sh")
    (stage/"etc/hosts").write_text("127.0.0.1 localhost\n::1 localhost\n")
    test = args.init
    if test.exists():
        shutil.copyfile(test, stage / "init")
    else:
        (stage / "init").write_text('''#!/bin/sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/kernel-bash --stats -c 'printf "hello from %s %s\\n" "$BASH_VERSION" "$MACHTYPE"'
rc=$?
echo "KERNEL_BASH_TEST_EXIT=$rc"
/bin/busybox poweroff -f
''')
    (stage / "init").chmod(0o755)
    if args.cases.is_file():
        shutil.copyfile(args.cases, stage / "cases.sh")

    # Share the bundle's newc writer: it encodes the console node without host root
    # access and normalizes modes, so a group-writable umask cannot make the staged
    # /etc/os-release untrusted and silently select sandbox mode inside the VM.
    bundle_spec = importlib.util.spec_from_file_location("bundle", ROOT / "scripts/build-sandbox.py")
    bundle = importlib.util.module_from_spec(bundle_spec)
    bundle_spec.loader.exec_module(bundle)
    archive = bundle.newc(stage)
    initramfs = work / "initramfs.cpio.gz"
    with gzip.open(initramfs, "wb", compresslevel=1) as f:
        f.write(archive)
    command = [str(PATHS['qemu']), "-enable-kvm", "-cpu", "host", "-m", str(args.memory), "-smp", "2",
               "-nodefaults", "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot",
               "-kernel", args.kernel, "-initrd", str(initramfs),
               "-append", "console=ttyS0 rdinit=/init quiet panic=-1"]
    print("Booting kernel tests in an isolated KVM guest", flush=True)
    started = time.monotonic()
    with (work / "console.log").open("w") as log:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                   errors="replace", start_new_session=True)
        timeout = threading.Timer(args.timeout, lambda: os.killpg(process.pid, signal.SIGKILL))
        timeout.start()
        try:
            for line in process.stdout:
                log.write(line)
                log.flush()
                print(line, end="", flush=True)
            rc = process.wait()
        finally:
            timeout.cancel()
            # Interrupts and harness errors must not leave a large VM running unattended.
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                except ProcessLookupError:
                    process.wait()
    transcript = (work / "console.log").read_text()
    success = rc == 0 and "KERNEL_BASH_TEST_EXIT=0" in transcript
    if args.portable:
        success = success and "PASS: kernel cases run without /nix" in transcript
    def digest(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    (work / "result.json").write_text(json.dumps({
        "passed": success, "kernel": str(args.kernel), "qemu_exit": rc,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "memory_mib": args.memory,
        "portable_without_nix": args.portable,
        "bpf_sha256": digest(args.build / "bash.bpf.o"),
        "loader_sha256": digest(args.build / "linux-bash-os"),
        "native_sha256": digest(args.reference),
        "kernel_sha256": digest(args.kernel),
        "init_sha256": digest(stage / "init"),
        "cases_sha256": digest(stage / "cases.sh") if (stage / "cases.sh").is_file() else None,
        "core_cases_sha256": digest(stage / "core-cases.sh"),
        "builtin_names_sha256": digest(stage / "builtin-names"),
        "checks": [line for line in transcript.splitlines() if line.startswith(("PASS:", "FAIL:"))],
    }, indent=2) + "\n")
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
