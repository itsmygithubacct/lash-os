#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build bashpython.so against an existing Bash build and static CPython prefix.

The module links libpython and its libraries into itself, and links against
glibc normally, so every reference to glibc carries its symbol version: the
dynamic linker binds an unversioned reference to a symbol's oldest version,
such as the GLIBC_2.2.5 condition variables Python cannot initialize. It may
need libc.so.6, libm.so.6 and the program interpreter, the dependencies pkg
accepts, and nothing else.

Before the module is written, it must pass:
- no DT_NEEDED except libc.so.6, libm.so.6 and the interpreter, and version
  requirements only on those;
- every strong undefined symbol defined by --bash, a library it needs, libm
  or its interpreter;
- --bash loading it with enable -f and running a threaded Python program with
  the prefix's standard library.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(command, **kwargs):
    return subprocess.run([str(c) for c in command], check=True, capture_output=True, text=True,
                          **kwargs).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--bash-build', type=Path, default=ROOT/'build/bash-5.3')
    parser.add_argument('--bash', type=Path, default=ROOT/'out/bash-shell')
    parser.add_argument('--python-prefix', type=Path)
    parser.add_argument('--output', type=Path, default=ROOT/'out/bashpython.so')
    parser.add_argument('--runner', default='', help='command that runs target executables')
    parser.add_argument('--no-strip', action='store_true')
    args = parser.parse_args()
    bt, output, bash = args.bash_build.resolve(), args.output.resolve(), args.bash.resolve()
    if not (bt/'config.h').is_file():
        parser.error('run build.sh first, or provide --bash-build')
    command = ['python3', str(ROOT/'config/build-python.py'), '--flags']
    if args.python_prefix:
        command += ['--prefix', str(args.python_prefix.resolve())]
    record = json.loads(subprocess.check_output(command, text=True))
    flags = record['flags']
    compiler = os.environ.get('CC', 'cc')
    readelf, nm = (compiler[:-3] + tool if compiler.endswith('-gcc') and shutil.which(compiler[:-3] + tool)
                   else tool for tool in ('readelf', 'nm'))
    interpreter = re.search(r'Requesting program interpreter: ([^\]]+)\]', run([readelf, '-l', bash]))
    if not interpreter:
        raise SystemExit(f'{bash} is not a dynamic executable')
    interpreter = Path(interpreter[1]).name
    libraries = re.findall(r'\(NEEDED\)\s+Shared library: \[([^\]]+)\]', run([readelf, '-d', bash]))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.bashpython-', dir=output.parent) as directory:
        scratch = Path(directory)
        shutil.copy2(ROOT/'loadables/_python/engine.h', scratch/'_python_engine.h')
        shared = scratch/'bashpython.so'
        subprocess.run([
            compiler, '-shared', '-fPIC', '-O2', '-static-libgcc',
            '-Wl,-Bsymbolic', '-Wl,--build-id=none', '-Wl,-z,relro', '-Wl,-z,now', '-Wl,-z,noexecstack',
            *([] if args.no_strip else ['-s']),
            '-DHAVE_CONFIG_H', '-DSHELL', '-DBASHOS_PYTHON_MODULE',
            '-I'+str(scratch), '-I'+str(bt), '-I'+str(bt/'include'), '-I'+str(bt/'lib'),
            '-I'+str(bt/'builtins'), '-I'+str(bt/'examples/loadables'), '-I'+str(ROOT/'loadables/common'),
            *shlex.split(flags['cppflags']),
            ROOT/'loadables/bashpython.c', ROOT/'loadables/_python/engine.c',
            ROOT/'loadables/_python/environment.c',
            '-o', shared, *shlex.split(flags['libraries']), '-lm'], check=True)
        needed = re.findall(r'\(NEEDED\)\s+Shared library: \[([^\]]+)\]', run([readelf, '-d', shared]))
        if set(needed) - {'libc.so.6', 'libm.so.6', interpreter}:
            raise SystemExit(f'bashpython.so needs shared libraries: {needed}')
        versions = set(re.findall(r'File: (\S+)', run([readelf, '-V', shared])))
        if versions - {'libc.so.6', 'libm.so.6', interpreter}:
            raise SystemExit(f'bashpython.so has version requirements on {sorted(versions)}')
        available = set()
        for path in [bash, *[run([compiler, f'-print-file-name={name}']).strip()
                             for name in dict.fromkeys([*libraries, 'libm.so.6', interpreter])]]:
            available |= {f[-1].split('@')[0] for f in map(str.split, run([nm, '-D', '--defined-only', path]).splitlines())
                          if len(f) >= 3}
        undefined = {f[1].split('@')[0] for f in map(str.split, run([nm, '-D', '--undefined-only', shared]).splitlines())
                     if len(f) == 2 and f[0] == 'U'}
        missing = sorted(undefined - available)
        if missing:
            raise SystemExit(f'bashpython.so needs {len(missing)} symbols no dynamic bash provides: {missing[:12]}')
        home = Path(record['data']['root'])/'share/bashpython'
        program = ('import sys, threading; out = []; t = threading.Thread(target=out.append, args=(sys.version,)); '
                   't.start(); t.join(); print(out[0].split()[0])')
        loaded = subprocess.run([*shlex.split(args.runner), bash, '--noprofile', '--norc', '-c',
                                 'PATH=; enable -f "$1" bashpython && [[ $(type -t bashpython) == builtin ]] && '
                                 'bashpython -c "$2"', '_', shared, program],
                                capture_output=True, text=True,
                                env={'LC_ALL': 'C', 'PYTHONHOME': str(home)}, timeout=120)
        expected = record['identity']['package']['version']
        if loaded.returncode or loaded.stdout.strip() != expected:
            raise SystemExit(f'bashpython.so did not run Python {expected}: '
                             f'status {loaded.returncode}, {loaded.stdout.strip()!r}, {loaded.stderr.strip()[-400:]!r}')
        shared.replace(output)
    print(f'bashpython loadable: {output} ({output.stat().st_size} bytes; '
          f'needs {needed or "no shared library"}; versions from {sorted(versions)})')


if __name__ == '__main__':
    main()
