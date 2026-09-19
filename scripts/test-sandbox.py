#!/usr/bin/env python3
"""Exercise the shipped VM launcher as an unprivileged user, including its console."""
import sys
sys.dont_write_bytecode = True
import argparse
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import socketserver
import struct
import subprocess
import termios
import threading
import time

from elf_dependencies import require_static

from workspace import ROOT, BUILD, OUT, REPORTS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    # make portable publishes here; pass OUT/portable/linux-bash-os for the pinned release artifact.
    parser.add_argument("--binary", type=Path, default=OUT / 'portable-host/linux-bash-os')
    parser.add_argument("--work", type=Path, default=REPORTS / 'sandbox')
    parser.add_argument("--timeout", type=int, default=450,
                        help="Seconds per shell test; increase for slow full-image verification. "
                             "VM startup, detached-job and terminal waits use a fifth of this, "
                             "at least 90 seconds (default: 450)")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    wait_timeout = max(90, args.timeout // 5)
    if os.geteuid() == 0:
        parser.error("Run these tests as an ordinary KVM-enabled user")
    require_static(args.binary)
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    (work / "result.json").unlink(missing_ok=True)
    home = work / "folder with spaces, commas"
    home.mkdir(exist_ok=True)
    binary = home / "renamed lash-os, portable"
    shutil.copy2(args.binary, binary)
    shutil.copyfile(ROOT / "config/builtin-names", home / "builtin-names")
    outside = work / "host-only-marker"
    outside.write_text("outside the exported directory\n")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    environment = {"PATH": "/nonexistent", "HOME": "/nonexistent", "TERM": "xterm",
                   "LD_LIBRARY_PATH": "/nonexistent", "QEMU_MODULE_DIR": "/nonexistent"}
    results = []

    def stop(proc):
        """Terminate the launcher's whole process group, including QEMU, and reap it."""
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=5)
                return
            except subprocess.TimeoutExpired:
                pass
        proc.wait()

    def run(name, argv, data=b"", timeout=None, expected=0, program=None):
        started = time.monotonic()
        proc = subprocess.Popen([str(program or binary), *argv], cwd=home, env=environment,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        try:
            stdout, stderr = proc.communicate(data, timeout=args.timeout if timeout is None else timeout)
        except BaseException as error:
            # Stop the VM first; saving diagnostics must not be able to skip cleanup.
            stop(proc)
            if isinstance(error, subprocess.TimeoutExpired):
                partial = error.stdout, error.stderr
                try:
                    partial = proc.communicate(timeout=10)
                except (subprocess.TimeoutExpired, OSError, ValueError):
                    pass
                try:
                    (work / (name + ".stdout")).write_bytes(partial[0] or b"")
                    (work / (name + ".stderr")).write_bytes(partial[1] or b"")
                except OSError as write_error:
                    print(f"cannot save partial output for {name}: {write_error}", file=sys.stderr)
            raise
        (work / (name + ".stdout")).write_bytes(stdout)
        (work / (name + ".stderr")).write_bytes(stderr)
        result = {"name": name, "exit": proc.returncode, "seconds": round(time.monotonic() - started, 3)}
        results.append(result)
        assert proc.returncode == expected, (name, proc.returncode, stderr[-4000:], stdout[-4000:])
        print(f"PASS: {name} ({result['seconds']}s)", flush=True)
        return stdout, stderr

    stdout, stderr = run("bash-version", ["--sandbox-network=none", "--", "--version"])
    assert stdout.startswith(b"GNU bash, version ") and not stderr, (stdout, stderr)
    stdout, stderr = run("bash-invalid-option", ["--sandbox-network=none", "--",
                         "--lashos-invalid-bash-option"], expected=2)
    assert not stdout and b"--lashos-invalid-bash-option: invalid option" in stderr, (stdout, stderr)
    # A guest status of 125 is not a launcher failure, so no VM diagnostics are printed.
    stdout, stderr = run("guest-exit-125", ["--sandbox-network=none", "-c", "exit 125"], expected=125)
    assert not stdout and not stderr, (stdout, stderr)

    class Fixture(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = b"sandbox-outbound-fixture\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_):
            pass

    with socketserver.TCPServer(("127.0.0.1", 0), Fixture) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        source = r'''set -e
[[ $MACHTYPE == bpf-linux-capsule && $HOME == /home && $PWD == /home ]]
[[ ! -e @OUTSIDE@ && ! -e /nix ]]
read -r boot < /proc/sys/kernel/random/boot_id
[[ $boot != @BOOT@ ]]
read -r init < /proc/1/comm
[[ $init == init ]]
enable -a > registrations
printf 'persisted from the guest\n' > persisted
printf 'temporary root\n' > /root/ephemeral-marker
curl -fsS --max-time 15 http://10.0.2.2:@PORT@/ > network-response
read -r reply < network-response
[[ $reply == sandbox-outbound-fixture ]]
curl -fsS --max-time 30 http://example.com/ > internet-response
[[ -s internet-response ]]
printf 'PASS: guest kernel, home mapping, persistence, outbound HTTP and DNS\n'
value=parent
( value=child; printf '%s\n' "$value" > subshell )
[[ $value == parent ]]
captured=$(printf child-result)
[[ $captured == child-result ]]
printf 'pear\napple\n' | sort > sorted
read -r first < sorted
[[ $first == apple ]]
sleep 0.1 &
wait "$!"
coproc producer { printf 'coprocess\n'; }
read -r -u "${producer[0]}" reply
[[ $reply == coprocess ]]
wait "$producer_PID" 2>/dev/null || :
while read -r item; do [[ $item == substitution ]]; done < <(printf 'substitution\n')
printf 'PASS: subshell, command substitution, pipeline, job, coprocess and process substitution\n'
printf 'stderr-marker\n' >&2
exit 37
'''
        import shlex
        source = source.replace("@OUTSIDE@", shlex.quote(str(outside))).replace("@BOOT@", shlex.quote(boot_id)).replace("@PORT@", str(port))
        stdout, stderr = run("default-vm", ["-c", source], expected=37)
        assert b"PASS: guest kernel" in stdout and b"PASS: subshell" in stdout
        assert stderr == b"stderr-marker\n", stderr
        assert (home / "persisted").read_text() == "persisted from the guest\n"
        registered = set(re.findall(r"^enable (?:-n )?(\S+)$", (home / "registrations").read_text(), re.M))
        assert set((ROOT / "config/builtin-names").read_text().splitlines()) <= registered
        server.shutdown()
        thread.join()

    data = bytes(range(256)) * 2049
    stdout, stderr = run("binary-streams", ["--sandbox-cpus=1", "--sandbox-network=none", "-c", "exec /bin/busybox tee /dev/stderr"], data)
    assert stdout == data and stderr == data, (len(stdout), len(stderr))
    # The inner /bin/bash relies on trusted installed OS identity, without --host.
    stdout, stderr = run("offline-and-installed-auto", ["--sandbox", "--sandbox-network=none", "-c",
        "exec /bin/bash -c '[[ ! -e /sys/class/net/eth0 && ! -e /root/ephemeral-marker ]] || exit 19; read -r reply < persisted; [[ $reply == \"persisted from the guest\" ]] || exit 20; printf INSTALLED_AUTO_HOST'"])
    assert stdout == b"INSTALLED_AUTO_HOST" and not stderr
    run("detached-job-cleanup", ["-c", "exec /bin/busybox sh -c '/bin/busybox setsid /bin/busybox sleep 300 & exit 0'"], timeout=wait_timeout)
    for invalid in [["--host", "--sandbox"], ["--sandbox-memory=0"], ["--sandbox-cpus=-1"],
                    ["--sandbox-network=invalid"], ["--host", "--sandbox-network=none"]]:
        run("invalid-" + str(len(results)), invalid, expected=2, timeout=10)
    policy = BUILD / 'portable/sandbox-launch-policy'
    for name, message in [("deny-kvm", b"checking KVM access"), ("deny-landlock", b"checking Landlock")]:
        stdout, stderr = run(name, [name, str(binary), "-c", "printf unexpected"],
                             expected=125, timeout=10, program=policy)
        assert not stdout and message in stderr
    stdout, stderr = run("missing-bundle", ["-c", "printf unexpected"], expected=125, timeout=10,
                         program=BUILD / 'portable/linux-bash-os')
    assert not stdout and b"No valid bundled VM" in stderr
    truncated = home / "truncated-bundle"
    shutil.copy2(binary, truncated)
    with truncated.open("r+b") as f:
        f.truncate(truncated.stat().st_size - 1)
    try:
        stdout, stderr = run("truncated-bundle", ["-c", "printf unexpected"], expected=125,
                             timeout=10, program=truncated)
        assert not stdout and b"No valid bundled VM" in stderr
    finally:
        truncated.unlink()

    # The caller keeps the same stdin description; the launcher must not make it non-blocking.
    shared_input, shared_writer = os.pipe()
    shared_flags = fcntl.fcntl(shared_input, fcntl.F_GETFL)
    proc = subprocess.Popen([str(binary), "-c", "printf READY_TO_STOP; sleep 300"], cwd=home,
                            env=environment, stdin=shared_input, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)
    try:
        expected_ready = b"READY_TO_STOP"
        ready = bytearray()
        deadline = time.monotonic() + wait_timeout
        while len(ready) < len(expected_ready):
            remaining = deadline - time.monotonic()
            assert remaining > 0, ("VM startup timeout", bytes(ready))
            readable, _, _ = select.select([proc.stdout], [], [], remaining)
            if readable:
                chunk = os.read(proc.stdout.fileno(), len(expected_ready) - len(ready))
                assert chunk, ("launcher output closed", bytes(ready), proc.poll())
                ready.extend(chunk)
        assert ready == expected_ready, bytes(ready)
        assert fcntl.fcntl(shared_input, fcntl.F_GETFL) == shared_flags
        children = Path(f"/proc/{proc.pid}/task/{proc.pid}/children").read_text().split()
        assert len(children) == 1, children
        qemu_pid = int(children[0])
        runtime = Path(f"/proc/{qemu_pid}/cwd").resolve()
        status = dict(line.split(":", 1) for line in Path(f"/proc/{qemu_pid}/status").read_text().splitlines())
        assert set(map(int, status["Uid"].split())) == {os.getuid()}
        assert int(status["CapEff"].strip(), 16) == 0
        assert status["NoNewPrivs"].strip() == "1" and status["Seccomp"].strip() == "2"
        # The launcher's socket filter is stacked beneath QEMU's own -sandbox filter.
        if "Seccomp_filters" in status:
            assert int(status["Seccomp_filters"].strip()) >= 2, status["Seccomp_filters"]
        (work / "qemu-confinement.json").write_text(json.dumps({k: status[k].strip() for k in
            ["Uid", "Gid", "CapEff", "NoNewPrivs", "Seccomp", "Seccomp_filters"] if k in status},
            indent=2) + "\n")
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=10) == 143
        assert not runtime.exists() and not Path(f"/proc/{qemu_pid}").exists()
        assert fcntl.fcntl(shared_input, fcntl.F_GETFL) == shared_flags
        results.append({"name": "unprivileged-qemu-signal-cleanup", "exit": 143})
        print("PASS: unprivileged QEMU, no capabilities, seccomp, signal and runtime cleanup", flush=True)
    finally:
        stop(proc)
        os.close(shared_input)
        os.close(shared_writer)

    # Actual host PTY -> virtio console -> guest PTY. Check restoration as well.
    master, slave = pty.openpty()
    initial_termios = termios.tcgetattr(slave)
    initial_flags = fcntl.fcntl(slave, fcntl.F_GETFL)
    proc = subprocess.Popen([str(binary)], cwd=home, env=environment, stdin=slave,
                            stdout=slave, stderr=slave, start_new_session=True)
    pending = bytearray()
    transcript = bytearray()
    started = time.monotonic()

    def expect(needle, timeout=None):
        deadline = time.monotonic() + (wait_timeout if timeout is None else timeout)
        while needle not in pending:
            remaining = deadline - time.monotonic()
            assert remaining > 0, ("PTY timeout", needle, bytes(pending[-3000:]))
            readable, _, _ = select.select([master], [], [], min(remaining, 1))
            if readable:
                chunk = os.read(master, 65536)
                assert chunk, ("PTY disconnected", bytes(pending[-3000:]))
                pending.extend(chunk)
                transcript.extend(chunk)
            assert proc.poll() is None, ("PTY exited", proc.returncode, bytes(pending[-3000:]))
        end = pending.index(needle) + len(needle)
        del pending[:end]

    def send(data):
        os.write(master, data)

    def wait_until(predicate, what, timeout=10):
        deadline = time.monotonic() + timeout
        while not predicate():
            assert time.monotonic() < deadline, what
            time.sleep(0.05)

    def process_state(pid):
        # The state follows the parenthesized command name, which cannot contain ") ".
        return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]

    try:
        expect(b"kernel-bash# ")
        # The terminal's shared description stays blocking while the session runs.
        assert fcntl.fcntl(slave, fcntl.F_GETFL) == initial_flags
        # SIGTSTP returns the terminal while stopped; SIGCONT restores raw mode.
        os.kill(proc.pid, signal.SIGTSTP)
        wait_until(lambda: process_state(proc.pid) == "T", "launcher did not stop")
        assert termios.tcgetattr(slave) == initial_termios
        os.kill(proc.pid, signal.SIGCONT)
        wait_until(lambda: termios.tcgetattr(slave) != initial_termios, "raw mode was not restored")
        send(b"printf 'resumed\\n'\n")
        expect(b"\r\nresumed\r\n")
        expect(b"kernel-bash# ")
        send(b"( printf 'child-ready\\n'; sleep 300 )\n")
        expect(b"\r\nchild-ready\r\n")
        send(b"\x1a")
        expect(b"Stopped")
        expect(b"kernel-bash# ")
        send(b"jobs\n")
        expect(b"Stopped")
        expect(b"kernel-bash# ")
        send(b"bg\n")
        expect(b"kernel-bash# ")
        send(b"fg\n")
        expect(b"sleep 300 )\r\n")
        time.sleep(0.1)
        send(b"\x03")
        expect(b"kernel-bash# ")
        send(b"printf 'interrupt=%s\\n' \"$?\"\n")
        expect(b"\r\ninterrupt=130\r\n")
        expect(b"kernel-bash# ")
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 33, 101, 0, 0))
        os.kill(proc.pid, signal.SIGWINCH)
        send(b"/bin/busybox stty size\n")
        expect(b"\r\n33 101\r\n")
        expect(b"kernel-bash# ")
        send(b"exit\n")
        assert proc.wait(timeout=10) == 0
        assert termios.tcgetattr(slave) == initial_termios
        assert fcntl.fcntl(slave, fcntl.F_GETFL) == initial_flags
        results.append({"name": "terminal-jobs-resize-restore", "exit": 0,
                        "seconds": round(time.monotonic() - started, 3)})
        print("PASS: terminal jobs, Ctrl-Z/bg/fg/Ctrl-C, resize, terminal restoration", flush=True)
    finally:
        stop(proc)
        (work / "terminal.log").write_bytes(transcript)
        os.close(master)
        os.close(slave)
    report = {"passed": True, "loader_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "uid": os.getuid(), "tests": results, "builtin_registrations": len(registered)}
    (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
