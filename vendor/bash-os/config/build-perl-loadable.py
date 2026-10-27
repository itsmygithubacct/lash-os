#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build bashperl.so against an existing Bash build and static Perl prefix."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bash-build', type=Path, default=ROOT/'build/bash-5.3')
    parser.add_argument('--perl-prefix', type=Path)
    parser.add_argument('--output', type=Path, default=ROOT/'out/bashperl.so')
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--static-libcrypt', type=Path,
                        help='link this PIC libcrypt archive instead of -lcrypt')
    parser.add_argument('--static-libcrypt-sha256',
                        help='required SHA-256 pin for --static-libcrypt')
    args = parser.parse_args()
    bt, output = args.bash_build.resolve(), args.output.resolve()
    if not (bt/'config.h').is_file():
        parser.error('run build.sh first, or provide --bash-build')
    command = ['python3', str(ROOT/'config/build-perl.py'), '--flags']
    if args.perl_prefix:
        command += ['--prefix', str(args.perl_prefix.resolve())]
    record = json.loads(subprocess.check_output(command, text=True))
    flags = record['flags']
    libraries = shlex.split(flags['libraries'])
    if bool(args.static_libcrypt) != bool(args.static_libcrypt_sha256):
        parser.error('--static-libcrypt and --static-libcrypt-sha256 must be supplied together')
    if args.static_libcrypt:
        archive = args.static_libcrypt.resolve()
        if archive.suffix != '.a' or not archive.is_file():
            parser.error('--static-libcrypt must name a regular .a archive')
        with archive.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != args.static_libcrypt_sha256:
            parser.error('--static-libcrypt SHA-256 mismatch')
        if '-lcrypt' not in libraries:
            parser.error('the Perl link flags do not contain -lcrypt')
        libraries = [str(archive) if flag == '-lcrypt' else flag for flag in libraries]
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.bashperl-', dir=output.parent) as directory:
        scratch = Path(directory)
        shutil.copy2(ROOT/'loadables/_perl/engine.h', scratch/'_perl_engine.h')
        compiler = os.environ.get('CC', 'cc')
        command = [compiler, '-shared', '-fPIC', '-Wl,-Bsymbolic', '-Wl,-z,nodelete',
                   '-O1' if args.sanitize else '-O2', '-g', '-DHAVE_CONFIG_H',
                   '-DBASHOS_PERL_MODULE',
                   '-I'+str(scratch), '-I'+str(bt), '-I'+str(bt/'include'),
                   '-I'+str(bt/'builtins'), '-I'+str(bt/'examples/loadables'),
                   *shlex.split(flags['cppflags']),
                   str(ROOT/'loadables/bashperl.c'), str(ROOT/'loadables/_perl/engine.c'),
                   str(ROOT/'loadables/_perl/environment.c'),
                   '-o', str(scratch/'bashperl.so'), *libraries]
        if args.static_libcrypt:
            command += ['-Wl,-z,text', '-Wl,--exclude-libs,' + archive.name]
        if args.sanitize:
            command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run(command, check=True)
        (scratch/'bashperl.so').replace(output)
    print(f'bashperl loadable: {output}')


if __name__ == '__main__':
    main()
