#!/usr/bin/env python3
"""Test a portable artifact's production init, console, shared home and network.

This is an explicit QEMU test harness, not a fallback in the portable launcher.
Cross-target TCG runs do not certify native host KVM or confinement.
"""
import argparse
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import threading
import time
import sys
sys.dont_write_bytecode = True
from elf_dependencies import require_arch, require_static
from runtime import ARCHES, digest
from workspace import ROOT, OUT, REPORTS, prepare_work


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=ARCHES, required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--smoke", action="store_true", help="Test startup, home, networking and random bytes without forks")
    parser.add_argument("--work", type=Path)
    args = parser.parse_args()
    profile = "portable" if args.arch == "x86_64" else "portable-" + args.arch
    binary = (args.binary or OUT / profile / "linux-bash-os").resolve()
    require_arch(binary, args.arch)
    require_static(binary)
    try:
        # Fixed-name subfolders below are replaced, so the directory must be dedicated to this harness.
        work = prepare_work(args.work or REPORTS / "architectures" / args.arch / "guest-runtime")
    except ValueError as error:
        parser.error(str(error))
    runtime, extra, home = (work / name for name in ("runtime", "extra", "home"))
    for directory in (runtime, extra, home):
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir()
    module("architecture", "test-architecture.py").extract(binary, runtime)
    (extra / "run").mkdir()
    (home / "host-marker").write_text("shared-home-fixture\n")

    class Fixture(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = b"outbound-fixture\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_):
            pass

    result = {"architecture": args.arch, "binary_sha256": digest(binary), "processes": not args.smoke, "passed": False}
    start = time.monotonic()
    output, errors = bytearray(), bytearray()
    with socketserver.TCPServer(("127.0.0.1", 0), Fixture) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        source = r'''set -e
[[ $HOME == /home && $PWD == /home && $MACHTYPE == bpf-linux-capsule ]]
read -r marker < host-marker
[[ $marker == shared-home-fixture ]]
read -r init < /proc/1/comm
[[ $init == init ]]
enable -a > registrations
printf 'persisted-from-guest\n' > persisted
curl -fsS --max-time 30 http://10.0.2.2:@PORT@/ > network-response
read -r response < network-response
[[ $response == outbound-fixture ]]
token=${ crypto random 8 -x; }
[[ ${#token} == 16 ]]
printf 'HOME_NETWORK_RANDOM_OK\n'
'''.replace("@PORT@", str(port))
        if not args.smoke:
            source += r'''
value=parent
( value=child; printf '%s\n' "$value" > child-value )
[[ $value == parent ]]
captured=$(printf child-result)
[[ $captured == child-result ]]
printf 'pear\napple\n' | sort > sorted
read -r first < sorted
[[ $first == apple ]]
sleep 0.01 &
wait "$!"
coproc producer { printf 'coprocess\n'; }
read -r -u "${producer[0]}" response
[[ $response == coprocess ]]
wait "$producer_PID" 2>/dev/null || :
read -r response < <(printf 'process-substitution\n')
[[ $response == process-substitution ]]
printf 'PROCESSES_OK\n'
'''
        source += r'''
printf 'stderr-marker\n' >&2
exit 37
'''
        arguments = ["linux-bash-os", "--host", "-c", source]
        config = struct.pack("<IIIIHH64s", 0x3148534c, len(arguments), 0, 1, 24, 80, b"xterm")
        (extra / "run/config").write_bytes(config + b"".join(a.encode() + b"\0" for a in arguments))
        initramfs = work / "initramfs"
        initramfs.write_bytes((runtime / "initramfs").read_bytes() + module("bundle", "build-sandbox.py").newc(extra))
        native = args.arch == os.uname().machine
        accelerator = "kvm" if native and os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
        machine = ("pc" if args.arch == "x86_64" else "virt,gic-version=host"
                   if args.arch == "aarch64" and accelerator == "kvm" else "virt")
        cpu = "host" if accelerator == "kvm" else "rv64,zacas=on" if args.arch == "riscv64" else "max"
        console = "ttyAMA0" if args.arch == "aarch64" else "ttyS0"
        parent, child = socket.socketpair()
        qemu = ([str(runtime / "ld.so"), "--inhibit-cache", "--library-path", str(runtime / "lib"), str(runtime / "qemu")]
                if native else [ARCHES[args.arch]["qemu"]])
        command = [*qemu, "-accel", accelerator, "-machine", machine, "-cpu", cpu,
                   "-m", "4096", "-smp", "2", "-nodefaults", "-no-user-config", "-nographic",
                   "-monitor", "none", "-serial", "stdio", "-no-reboot", "-kernel", str(runtime / "kernel"),
                   "-initrd", str(initramfs), "-append", f"console={console} rdinit=/init panic=-1 net.ifnames=0",
                   "-chardev", f"socket,id=io,fd={child.fileno()}", "-device", "virtio-serial-pci",
                   "-device", "virtserialport,chardev=io,name=lash.io", "-fsdev",
                   f"local,id=work,path={home},security_model=none,multidevs=remap",
                   "-device", "virtio-9p-pci,fsdev=work,mount_tag=work", "-netdev", "user,id=net,ipv6=off",
                   "-device", "virtio-net-pci,netdev=net,romfile="]
        if args.arch in ("x86_64", "riscv64"):
            bios = "bios-256k.bin" if args.arch == "x86_64" else "fw_dynamic.bin"
            command += ["-L", str(runtime / "firmware"), "-bios", str(runtime / "firmware" / bios)]
        result.update(accelerator=accelerator, command=command)
        try:
            with (work / "boot.log").open("wb") as log:
                proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                        pass_fds=(child.fileno(),), start_new_session=True)
                child.close()
                pending = bytearray()
                parent.settimeout(1)
                try:
                    while time.monotonic() - start < args.timeout and "guest_exit" not in result:
                        try:
                            data = parent.recv(65536)
                        except socket.timeout:
                            if proc.poll() is not None:
                                break
                            continue
                        if not data:
                            break
                        pending += data
                        while len(pending) >= 8:
                            kind, size = struct.unpack_from("<II", pending)
                            if size > 8192:
                                raise ValueError("Invalid console frame")
                            if len(pending) < 8 + size:
                                break
                            payload = pending[8:8 + size]
                            del pending[:8 + size]
                            if kind == 2:
                                output += payload
                            elif kind == 3:
                                errors += payload
                            elif kind == 5 and size == 4:
                                result["guest_exit"] = struct.unpack("<i", payload)[0]
                            elif kind == 7:
                                parent.sendall(struct.pack("<II", 4, 0))
                            else:
                                raise ValueError(f"Unexpected console frame: {kind}")
                finally:
                    parent.close()
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGTERM)
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()
            registrations = (home / "registrations").read_text() if (home / "registrations").exists() else ""
            registered = set(re.findall(r"^enable (?:-n )?(\S+)$", registrations, re.M))
            expected = set((ROOT / "config/builtin-names").read_text().splitlines())
            result["passed"] = (result.get("guest_exit") == 37 and expected <= registered and
                                b"HOME_NETWORK_RANDOM_OK" in output and (args.smoke or b"PROCESSES_OK" in output) and
                                errors == b"stderr-marker\n" and
                                (home / "persisted").read_text() == "persisted-from-guest\n")
        finally:
            child.close()
            parent.close()
            server.shutdown()
            thread.join()
            result["seconds"] = round(time.monotonic() - start, 3)
            (work / "stdout").write_bytes(output)
            (work / "stderr").write_bytes(errors)
            (work / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(f"Guest runtime test failed; see {work}")


if __name__ == "__main__":
    main()
