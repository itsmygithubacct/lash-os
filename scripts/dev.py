#!/usr/bin/env python3
"""Run a build command in the pinned toolchain, refreshing Nix group access."""
import grp
import os
import pwd
import shlex
import shutil
import sys

os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
command = sys.argv[1:]
profile = "default"
if command[:1] == ["--shell"]:
    if len(command) < 3 or command[1] not in ("default", "portable"):
        sys.exit("usage: scripts/dev.py [--shell default|portable] COMMAND [ARGUMENT ...]")
    profile, command = command[1], command[2:]
if not command:
    sys.exit("usage: scripts/dev.py [--shell default|portable] COMMAND [ARGUMENT ...]")
active = os.environ.get("LINUX_BASH_DEV_SHELL")
ready = active == profile or (not active and profile == "default" and shutil.which("bpf-capsule-cc"))
if not ready:
    if not shutil.which("nix"):
        sys.exit("Nix is required; install it, then run make again")
    command = ["nix", "--extra-experimental-features", "nix-command flakes", "develop", ".#" + profile, "--command", *command]
    try:
        group = grp.getgrnam("nix-users")
        if group.gr_gid not in os.getgroups() and pwd.getpwuid(os.getuid()).pw_name in group.gr_mem:
            command = ["sg", "nix-users", "-c", shlex.join(command)]
    except KeyError:
        pass
os.execvp(command[0], command)
