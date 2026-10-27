#!/usr/bin/env python3
"""Accept a build cache entry only while its published outputs and tree agree."""
import hashlib
import json
import os
from pathlib import Path
import sys


def valid(binary, tree, stamp, selection):
    def companion(suffix):
        return binary.with_name(binary.name + suffix)

    try:
        if companion('.stamp').read_text().strip() != stamp:
            return False
        if (tree / '.bash-os-stamp').read_text().strip() != stamp:
            return False
        if not all((tree / name).is_file() for name in
                   ('config.h', 'Makefile', 'builtins/Makefile', 'bash')):
            return False
        manifest = json.loads(companion('.manifest.json').read_text())
        if any(manifest.get(key) != value for key, value in selection.items()):
            return False
        if companion('.loadables.list').read_text() != selection['list']:
            return False
        if not companion('.manifest.txt').read_text().strip():
            return False
        if not os.access(binary, os.X_OK):
            return False
        data = binary.read_bytes()
        return (manifest.get('bytes') == len(data)
                and manifest.get('binary_sha256') == hashlib.sha256(data).hexdigest())
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return False


if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit('usage: build-cache.py BINARY TREE STAMP')
    sys.exit(0 if valid(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3],
                        json.loads(os.environ['SELECTION'])) else 1)
