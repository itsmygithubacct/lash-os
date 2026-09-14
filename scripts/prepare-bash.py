#!/usr/bin/env python3
"""Build an isolated native reference from the pinned bash-os snapshot."""
import sys
sys.dont_write_bytecode = True
import os
import argparse
from pathlib import Path
import shutil
import subprocess
from source_tree import sync_tree

from workspace import ROOT, BUILD, DOWNLOADS, PATHS
SOURCE = BUILD / "native-pure/source"
# Native reference and guest use the same GNU shell features.
CONFIGURE = " ".join([
    "--disable-readline", "--disable-history", "--disable-bang-history",
    "--disable-progcomp", "--disable-process-substitution",
    "--disable-coprocesses", "--disable-net-redirections",
    "--disable-command-timing", "--disable-debugger", "--disable-nls",
])

def configure_guest():
    config = SOURCE / "build/bash-5.3/config.h"
    if '"linux_bash_config.h"' not in config.read_text():
        config.write_text(config.read_text() + '\n#ifdef __BPF__\n#include "linux_bash_config.h"\n#endif\n')
    quit_header = SOURCE / "build/bash-5.3/quit.h"
    text = quit_header.read_text()
    if 'linux_bash_poll_signals' not in text:
        text = '#ifdef __BPF__\nextern void linux_bash_poll_signals(void);\n#define KERNEL_SIGNAL_POLL() linux_bash_poll_signals()\n#else\n#define KERNEL_SIGNAL_POLL() ((void)0)\n#endif\n' + text
        text = text.replace('if (terminating_signal) termsig_handler', 'KERNEL_SIGNAL_POLL(); if (terminating_signal) termsig_handler')
        quit_header.write_text(text)
    names = SOURCE / "build/bash-5.3/signames.h"
    if '"linux_bash_signames.h"' not in names.read_text():
        names.write_text('#ifdef __BPF__\n#include "linux_bash_signames.h"\n#else\n' + names.read_text() + '\n#endif\n')

def main():
    global SOURCE
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['pure','full'], default='pure')
    args=parser.parse_args()
    configuration=CONFIGURE if args.profile=='pure' else '--disable-nls'
    SOURCE = BUILD / ("native-" + args.profile) / "source"
    sync_tree(ROOT / 'vendor/bash-os', SOURCE)
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    cache_link = SOURCE / 'dl'
    if cache_link.is_symlink() and cache_link.resolve() != DOWNLOADS:
        cache_link.unlink()
    if not cache_link.exists():
        cache_link.symlink_to(DOWNLOADS)
    # Cached downloads are rechecked against versions.sh by the upstream build.
    cache = PATHS['source_cache'] or DOWNLOADS
    for relative in [Path("bash-5.3.tar.gz"), *[Path("patches") / f"bash53-{n:03}" for n in range(1, 16)]]:
        src, dst = cache / relative, SOURCE / "dl" / relative
        if src.is_file() and not dst.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
    if args.profile=='full':
        subprocess.run(['python3',str(ROOT/'scripts/adapt-workspaces.py'),str(SOURCE/'loadables')],check=True)
    env = dict(os.environ, CONFIGURE_EXTRA=configuration, JOBS="4")
    subprocess.run(["bash", "build.sh", "--profile", args.profile, "--name", "kernel-reference", "--no-strip"],
                   cwd=SOURCE, env=env, check=True)
    configure_guest()

if __name__ == "__main__":
    main()
