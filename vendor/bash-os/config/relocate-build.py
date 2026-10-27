#!/usr/bin/env python3
"""Retarget configure's generated build paths before publishing its staged tree."""
from pathlib import Path
import os
import sys


def relocate(source, destination):
    old, new = str(source.resolve()), str(destination.resolve())
    # config.status must retain the new path too, otherwise the next Makefile
    # regeneration puts the removed staging directory back. po/Makefile.in and
    # examples/loadables/Makefile.inc are configure outputs despite their suffixes.
    paths = [source / 'config.status']
    paths += [path for path in source.rglob('Makefile*') if path.is_file()]
    for path in paths:
        content = path.read_text()
        if old in content:
            before = path.stat()
            path.write_text(content.replace(old, new))
            # Relocation does not change the build inputs. Retain timestamps so
            # Make does not regenerate otherwise unchanged headers in parallel.
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('usage: relocate-build.py SOURCE DESTINATION')
    relocate(Path(sys.argv[1]), Path(sys.argv[2]))
