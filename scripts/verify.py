#!/usr/bin/env python3
"""Compare the real kernel executable with its matching native Bash build."""
import sys
sys.dont_write_bytecode = True
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import time

from workspace import ROOT, BUILD, OUT, REPORTS
KERNEL = OUT / 'linux-bash-os'
NATIVE = BUILD / 'native-full/source/out/bash-kernel-reference'

def main():
    if os.geteuid() != 0:
        sys.exit("Direct-host verification requires root; use make verify for isolated VM tests")
    output = REPORTS / 'direct-host'
    output.mkdir(parents=True, exist_ok=True)
    checks = []

    def check(name, passed):
        checks.append({"name": name, "passed": bool(passed)})
        print(("PASS: " if passed else "FAIL: ") + name, flush=True)

    with tempfile.TemporaryDirectory(prefix="linux-bash-os-test-") as temporary:
        base = Path(temporary)
        results = {}
        for name, binary in [("native", NATIVE), ("kernel", KERNEL)]:
            work = base / name
            work.mkdir()
            arguments = [str(binary)]
            if name == "native":
                arguments += ["--noprofile", "--norc"]
            else:
                arguments += ["--host"]
            arguments.append(str(ROOT / "tests/cases.sh"))
            result = subprocess.run(arguments, cwd=work, capture_output=True, timeout=1200,
                                    env={**os.environ, "LC_ALL": "C", "PATH": ""})
            results[name] = result
            (output / f"{name}.stdout").write_bytes(result.stdout)
            (output / f"{name}.stderr").write_bytes(result.stderr)
        check("command suite exits successfully", all(x.returncode == 0 for x in results.values()))
        check("native and kernel stdout match byte for byte", results["native"].stdout == results["kernel"].stdout)
        check("kernel command suite has no diagnostics", results["kernel"].stderr == b"")

        for name, arguments, expected in [
            ("exit status", ["-c", "exit 37"], 37),
            ("syntax error", ["-c", "if then"], 2),
            ("missing command", ["-c", "linux_bash_missing_command"], 127),
        ]:
            result = subprocess.run([str(KERNEL), "--host", *arguments], cwd=base, capture_output=True, timeout=60)
            check(name, result.returncode == expected)
        result = subprocess.run([str(KERNEL), "--host"], input=b'printf "STDIN_SCRIPT_OK\\n"\n',
                                cwd=base, capture_output=True, timeout=60)
        check("stdin script", result.returncode == 0 and result.stdout == b"STDIN_SCRIPT_OK\n")

        master, slave = pty.openpty()
        try:
            process = subprocess.Popen([str(KERNEL), "--host", "-i"], stdin=slave, stdout=slave, stderr=slave, cwd=base)
            os.close(slave)
            slave = -1
            os.write(master, b'v=interactive; printf "PTY_%s_OK\\n" "$v"\nexit\n')
            transcript = bytearray()
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.2)[0]:
                    try:
                        transcript.extend(os.read(master, 65536))
                    except OSError:
                        break
                elif process.poll() is not None:
                    break
            try:
                rc = process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                rc = process.wait()
            check("interactive terminal", rc == 0 and b"PTY_interactive_OK" in transcript)
            (output / "terminal.log").write_bytes(transcript)
        finally:
            os.close(master)
            if slave >= 0:
                os.close(slave)
    report = {
        "passed": all(c["passed"] for c in checks), "kernel": os.uname().release,
        "bpf_sha256": hashlib.sha256((OUT / 'bash.bpf.o').read_bytes()).hexdigest(), "checks": checks,
    }
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Report: {output / 'result.json'}")
    sys.exit(0 if report["passed"] else 1)

if __name__ == "__main__":
    main()
