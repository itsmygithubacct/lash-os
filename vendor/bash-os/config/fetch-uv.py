#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fetch the pinned upstream uv executable for one architecture.

Usage: python3 config/fetch-uv.py ARCH [--out DIR]
Downloads uv's static musl release for ARCH (x86_64, aarch64 or riscv64) into
dl/, checks it against the SHA-256 pinned in config/uv.json, and places the
executable at DIR/libexec/uv/uv (default out/uv/ARCH), ready for
build-packages.sh --data uv=DIR uv.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def publish(program, out):
    """Replace only a uv data tree, after its complete replacement is ready."""
    expected = {'libexec': 'directory', 'libexec/uv': 'directory', 'libexec/uv/uv': 'file'}
    if out.is_symlink() or (out.exists() and not out.is_dir()):
        raise SystemExit(f'fetch-uv: refusing to replace an unmanaged output: {out}')
    if out.exists():
        for path in out.rglob('*'):
            kind = expected.get(path.relative_to(out).as_posix())
            if (path.is_symlink() or kind is None
                    or not (path.is_dir() if kind == 'directory' else path.is_file())):
                raise SystemExit(f'fetch-uv: refusing to replace an unmanaged output: {path}')
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.uv-', dir=out.parent) as directory:
        scratch = Path(directory)
        staged = scratch/'data'
        target = staged/'libexec/uv/uv'
        target.parent.mkdir(parents=True)
        target.write_bytes(program)
        target.chmod(0o755)
        backup = scratch/'previous'
        if out.exists():
            out.rename(backup)
        try:
            staged.rename(out)
        except BaseException:
            if backup.exists():
                backup.rename(out)
            raise
    return out/'libexec/uv/uv'


def main():
    config = json.loads((ROOT/'config/uv.json').read_text())
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('arch', choices=sorted(config['targets']))
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    pin = config['targets'][args.arch]

    cache = ROOT/'dl'/f"uv-{config['version']}-{pin['target']}.tar.gz"
    if not cache.is_file() or hashlib.sha256(cache.read_bytes()).hexdigest() != pin['sha256']:
        url = config['url'].format(version=config['version'], target=pin['target'])
        with urllib.request.urlopen(url, timeout=300) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != pin['sha256']:
            raise SystemExit(f'fetch-uv: {url} does not match the SHA-256 in config/uv.json')
        cache.parent.mkdir(exist_ok=True)
        partial = cache.parent/(cache.name + '.part')
        partial.write_bytes(data)
        partial.replace(cache)

    with tarfile.open(cache) as archive:
        found = [m for m in archive.getmembers() if m.isfile() and Path(m.name).name == 'uv']
        if len(found) != 1:
            raise SystemExit(f'fetch-uv: {cache.name} does not hold exactly one uv executable')
        program = archive.extractfile(found[0]).read()

    out = args.out or ROOT/'out/uv'/args.arch
    target = publish(program, out)
    print(f"fetch-uv: uv {config['version']} for {args.arch}: {target} ({len(program)} bytes)")


if __name__ == '__main__':
    main()
