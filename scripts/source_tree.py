#!/usr/bin/env python3
"""List and refresh vendored build inputs, retaining generated build caches."""
import argparse
import os
from pathlib import Path
import shutil
import stat

EXCLUDED = {".git", "build", "out", "dl", "__pycache__"}


def entries(root):
    root = Path(root)
    for directory, folders, files in os.walk(root, followlinks=False):
        folders[:] = sorted(name for name in folders if name not in EXCLUDED)
        for name in sorted([*folders, *files]):
            if name not in EXCLUDED:
                yield (Path(directory) / name).relative_to(root)


def remove(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def sync_tree(source, destination):
    source, destination = Path(source), Path(destination)
    if not source.is_dir():
        raise FileNotFoundError(source)
    if source.resolve() == destination.resolve():
        raise ValueError("source and destination must be different trees")
    wanted = set(entries(source))
    destination.mkdir(parents=True, exist_ok=True)
    # Remove obsolete source files, including deleted builtins and headers.
    # The generated build/, out/, and dl/ trees are excluded from both walks.
    obsolete = set(entries(destination)) - wanted
    for relative in sorted(obsolete, key=lambda p: len(p.parts), reverse=True):
        path = destination / relative
        if path.exists() or path.is_symlink():
            remove(path)
    for relative in sorted(wanted, key=lambda p: (len(p.parts), str(p))):
        original, target = source / relative, destination / relative
        if original.is_symlink():
            link = os.readlink(original)
            if target.is_symlink() and os.readlink(target) == link:
                continue
            if target.exists() or target.is_symlink():
                remove(target)
            target.symlink_to(link)
        elif original.is_dir():
            if target.is_symlink() or (target.exists() and not target.is_dir()):
                remove(target)
            target.mkdir(exist_ok=True)
        else:
            if target.is_symlink() or (target.exists() and not target.is_file()):
                remove(target)
            if (not target.exists() or original.read_bytes() != target.read_bytes()
                    or stat.S_IMODE(original.stat().st_mode) != stat.S_IMODE(target.stat().st_mode)):
                shutil.copy2(original, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["list", "sync"])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path, nargs="?")
    args = parser.parse_args()
    if args.operation == "sync":
        if args.destination is None:
            parser.error("sync requires a destination")
        sync_tree(args.source, args.destination)
    else:
        # Directory mtimes make additions and removals invalidate Make stamps.
        for path in [args.source, *(args.source / p for p in sorted(entries(args.source)))]:
            value = str(path).replace("$", "$$").replace("#", r"\#").replace(" ", r"\ ")
            print(value)


if __name__ == "__main__":
    main()
