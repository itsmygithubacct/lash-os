#!/usr/bin/env python3
"""Configure the kernel loader using the selected external build workspace."""
import argparse
import os
import subprocess
import sys
sys.dont_write_bytecode = True
from workspace import ROOT, BUILD, prepare_cmake


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['pure', 'full'], default='full')
    args = parser.parse_args()
    full = args.profile == 'full'
    build = BUILD / ('kernel-full' if full else 'kernel')
    libraries = []
    if full:
        libraries = [BUILD / 'full-bitcode-archives' / ('lib' + name + '.a')
                     for name in ['sh', 'glob', 'tilde', 'readline', 'termcap']]
        libraries += sorted((BUILD / 'deps/lib').glob('*.a'))
    prepare_cmake(build, ROOT)
    # The Capsule package compiles its platform and runtime sources with fixed
    # options, so remap build-machine paths through the compiler driver too.
    # Otherwise their names reach __FILE__ and debug records in the shipped image.
    environment = dict(os.environ,
                       CCC_OVERRIDE_OPTIONS=f'+-ffile-prefix-map={BUILD}=/lashos/build '
                                            f'+-ffile-prefix-map={ROOT}=/lashos/source')
    subprocess.run(['cmake', '-S', str(ROOT), '-B', str(build), '-UBpfCapsule_DIR',
                    '-DBASH_BITCODE_DIRECTORY=' + str(BUILD / ('full-bitcode' if full else 'bitcode')),
                    '-DBASH_USE_ARCHIVES=' + ('ON' if full else 'OFF'),
                    '-DLINUX_BASH_FIBER_STACK=2097152',
                    '-DBASH_EXTRA_LIBRARIES=' + ';'.join(map(str, libraries))],
                   check=True, env=environment)
    subprocess.run(['cmake', '--build', str(build), '-j4'], check=True, env=environment)


if __name__ == '__main__':
    main()
