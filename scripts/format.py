#!/usr/bin/env python3
"""Regenerate ABI adapters and format the port's C code."""
from pathlib import Path
import os,shutil,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
formatter=shutil.which('clang-format')
if not formatter:sys.exit('clang-format is required (available in the Nix shell)')
for script in ['generate-posix.py','generate-raw.py']:
    subprocess.run([sys.executable,str(ROOT/'scripts'/script)],check=True)
files=sorted((ROOT/'src').glob('*.c'))+sorted((ROOT/'src').glob('*.h'))
files += [ROOT/'include'/n for n in ['kernel_control.h','posix_extra.h','posix_generated.h','capsule_process.h']]
files += [ROOT/'tests/job-control.c']
subprocess.run([formatter,'-i',*map(str,files)],check=True)
