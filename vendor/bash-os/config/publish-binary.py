#!/usr/bin/env python3
"""Publish a complete executable without overwriting a running inode."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

if len(sys.argv) not in (3, 4):
    sys.exit('usage: publish-binary.py SOURCE DESTINATION [STRIP_TOOL]')
source, destination = map(Path, sys.argv[1:3])
with tempfile.TemporaryDirectory(prefix='.publish-', dir=destination.parent) as scratch:
    staged = Path(scratch)/destination.name
    shutil.copy2(source, staged)
    if len(sys.argv) == 4:
        if strip_tool := shutil.which(sys.argv[3]):
            subprocess.run([strip_tool, str(staged)], check=True)
        else:
            sys.exit(f'build.sh: strip tool {sys.argv[3]} not found; use --no-strip to retain symbols')
    staged.replace(destination)
