#!/usr/bin/env python3
"""Boot an artifact's real guest kernel and loader on its target architecture.

Cross-architecture tests explicitly use TCG. The shipped launcher still requires
KVM; this harness does not certify native KVM or host confinement on other CPUs.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import struct
import subprocess
import time
import sys
sys.dont_write_bytecode = True
from elf_dependencies import require_arch, require_static
from runtime import ARCHES, digest
from workspace import ROOT, BUILD, OUT, REPORTS, prepare_work


def extract(binary, destination):
    with binary.open("rb") as stream:
        stream.seek(-40, os.SEEK_END)
        magic, offset, compressed, length = struct.unpack("<16sQQQ", stream.read(40))
        if (magic != b"LASHOS-VM-v1".ljust(16, b"\0") or length > 512 * 1024 * 1024 or
                offset + compressed + 40 != binary.stat().st_size):
            raise ValueError("Invalid VM bundle footer")
        stream.seek(offset)
        data = subprocess.check_output(["zstd", "-q", "-dc"], input=stream.read(compressed))
    if len(data) != length:
        raise ValueError("Invalid bundle length")
    cursor = 0
    while cursor + 16 <= len(data):
        namesize, mode, size = struct.unpack_from("<IIQ", data, cursor)
        cursor += 16
        if namesize == mode == size == 0:
            if cursor != len(data):
                raise ValueError("Trailing archive data")
            return
        name = data[cursor:cursor + namesize].decode()
        cursor += namesize
        if (Path(name).is_absolute() or ".." in Path(name).parts or not name or
                mode not in (0o600, 0o700) or cursor + size > len(data)):
            raise ValueError("Invalid bundle entry")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data[cursor:cursor + size])
        target.chmod(mode)
        cursor += size
    raise ValueError("Missing bundle terminator")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=ARCHES, required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--full", action="store_true", help="Run the full builtin and job-control suites")
    parser.add_argument("--jobs-only", action="store_true", help="Run only the PTY job-control suite")
    parser.add_argument("--network-only", action="store_true", help="Run only loopback HTTP and post-DNS fork checks")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--memory", type=int, default=6144, help="Guest RAM in MiB")
    parser.add_argument("--diagnostics", action="store_true", help="Log loader bridge calls and periodic guest task stacks")
    parser.add_argument("--jit-selftest", type=Path, help="Also load the matching upstream Linux lib/test_bpf.ko")
    parser.add_argument("--work", type=Path)
    args = parser.parse_args()
    if sum((args.full, args.jobs_only, args.network_only)) > 1:
        parser.error("--full, --jobs-only and --network-only are mutually exclusive")
    profile = "portable" if args.arch == "x86_64" else "portable-" + args.arch
    binary = (args.binary or OUT / profile / "linux-bash-os").resolve()
    require_arch(binary, args.arch)
    require_static(binary)
    group = "jobs" if args.jobs_only else "network" if args.network_only else "full" if args.full else "smoke"
    try:
        # Fixed-name subfolders below are replaced, so the directory must be dedicated to this harness.
        work = prepare_work(args.work or REPORTS / "architectures" / args.arch / group)
    except ValueError as error:
        parser.error(str(error))
    runtime = work / "runtime"
    if runtime.exists():
        shutil.rmtree(runtime)
    runtime.mkdir()
    extract(binary, runtime)
    extra = work / "extra"
    if extra.exists():
        shutil.rmtree(extra)
    extra.mkdir()
    for name in ["cases.sh", "full-cases.sh", "network-cases.sh"]:
        shutil.copyfile(ROOT / "tests" / name, extra / ("core-cases.sh" if name == "cases.sh" else name))
    shutil.copyfile(ROOT / "config/builtin-names", extra / "builtin-names")
    for name in ["syscall-abi-test", "job-control-test"]:
        shutil.copy2(BUILD / profile / name, extra / name)
    if args.jit_selftest:
        shutil.copyfile(args.jit_selftest, extra / "test_bpf.ko")
    command = "/bin/linux-bash-os --host --stats /full-cases.sh" if args.full else (
        "/bin/linux-bash-os --host --stats -c 'set -e; "
        "[[ $MACHTYPE == bpf-linux-capsule ]]; "
        "registered=0; while read -r name; do [[ ${ type -t \"$name\"; } == builtin ]]; "
        "((++registered)); done < /builtin-names; [[ $registered == 279 ]]; "
        "printf \"BPF_SMOKE_OK %s %s\\n\" \"$BASH_VERSION\" \"$registered\"'")
    if args.network_only:
        command = "/bin/linux-bash-os --host --stats /network-cases.sh"
    init = """#!/bin/busybox sh
export PATH=/bin HOME=/home LC_ALL=C
export LASHOS_TEST_STEP_TIMEOUT_MS=300000
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mkdir -p /dev/pts
/bin/busybox mount -t devpts devpts /dev/pts
/bin/busybox ln -s /proc/self/fd /dev/fd
/bin/busybox ln -s /proc/self/fd/0 /dev/stdin
/bin/busybox ln -s /proc/self/fd/1 /dev/stdout
/bin/busybox ln -s /proc/self/fd/2 /dev/stderr
/bin/busybox ip link set lo up
cd /home
/syscall-abi-test || { echo LASHOS_ARCH_EXIT=1; /bin/busybox poweroff -f; }
echo NATIVE_SYSCALL_ABI_OK
""" + ("/job-control-test /bin/linux-bash-os" if args.jobs_only else command) + "\nresult=$?\n"
    if args.jobs_only:
        init += "if [ $result = 0 ]; then echo JOB_CONTROL_OK; fi\n"
    if args.full:
        init += "if [ $result = 0 ]; then /job-control-test /bin/linux-bash-os; result=$?; fi\n"
    init += "echo LASHOS_ARCH_EXIT=$result\n/bin/busybox poweroff -f\n"
    if args.diagnostics:
        diagnostic = r'''
export LINUX_BASH_TRACE=1
(
    while /bin/busybox sleep 30; do
        for task in /proc/[0-9]*; do
            read -r name < "$task/comm" || continue
            [ "$name" = linux-bash-os ] || continue
            echo "LOAD_DIAGNOSTIC: $task"
            /bin/busybox cat "$task/syscall" "$task/wchan" "$task/stack"
        done
    done
) &
'''
        init = init.replace("cd /home\n", diagnostic + "cd /home\n")
    if args.jit_selftest:
        init = init.replace("cd /home\n", """/bin/busybox insmod /test_bpf.ko test_suite=test_bpf || {
    echo LASHOS_ARCH_EXIT=1; /bin/busybox poweroff -f;
}
echo KERNEL_JIT_SELFTEST_OK
/bin/busybox rmmod test_bpf
cd /home
""")
    (extra / "test-init").write_text(init)
    (extra / "test-init").chmod(0o755)
    spec = importlib.util.spec_from_file_location("bundle", ROOT / "scripts/build-sandbox.py")
    bundle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bundle)
    initramfs = work / "initramfs"
    initramfs.write_bytes((runtime / "initramfs").read_bytes() + bundle.newc(extra))
    native = args.arch == os.uname().machine
    accelerator = "kvm" if native and os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
    machine = ("pc" if args.arch == "x86_64" else "virt,gic-version=host"
               if args.arch == "aarch64" and accelerator == "kvm" else "virt")
    cpu = "host" if accelerator == "kvm" else "rv64,zacas=on" if args.arch == "riscv64" else "max"
    console = "ttyAMA0" if args.arch == "aarch64" else "ttyS0"
    qemu = ([str(runtime / "ld.so"), "--inhibit-cache", "--library-path", str(runtime / "lib"), str(runtime / "qemu")]
            if native else [ARCHES[args.arch]["qemu"]])
    command = [*qemu, "-accel", accelerator, "-machine", machine,
               "-cpu", cpu, "-m", str(args.memory), "-smp", "2", "-nodefaults", "-no-user-config",
               "-nographic", "-monitor", "none", "-serial", "stdio", "-no-reboot",
               "-kernel", str(runtime / "kernel"), "-initrd", str(initramfs),
               "-append", f"console={console} rdinit=/test-init panic=-1 net.ifnames=0",
               "-nic", "none"]
    if args.diagnostics:
        monitor = work / "monitor.sock"
        monitor.unlink(missing_ok=True)
        command += ["-qmp", f"unix:{monitor},server=on,wait=off"]
    if args.arch in ("x86_64", "riscv64"):
        bios = "bios-256k.bin" if args.arch == "x86_64" else "fw_dynamic.bin"
        command += ["-L", str(runtime / "firmware"), "-bios", str(runtime / "firmware" / bios)]
    start = time.monotonic()
    log = work / "console.log"
    result = {"architecture": args.arch, "accelerator": accelerator, "full": args.full, "group": group,
              "binary_sha256": digest(binary), "command": command, "passed": False}
    if args.jit_selftest:
        result["jit_selftest_sha256"] = digest(args.jit_selftest)
    try:
        with log.open("wb") as output:
            proc = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                result["qemu_exit"] = proc.wait(timeout=args.timeout)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
        transcript = log.read_text(errors="replace")
        marker = ("JOB_CONTROL_OK" if args.jobs_only else "NETWORK_CASES_PASSED" if args.network_only
                  else "FULL_CASES_PASSED" if args.full else "BPF_SMOKE_OK")
        result["passed"] = (result["qemu_exit"] == 0 and "LASHOS_ARCH_EXIT=0" in transcript and marker in transcript)
        if args.jit_selftest:
            result["passed"] = result["passed"] and "KERNEL_JIT_SELFTEST_OK" in transcript
    finally:
        result["seconds"] = round(time.monotonic() - start, 3)
        (work / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(f"Architecture test failed; see {log}")


if __name__ == "__main__":
    main()
