#!/usr/bin/env python3
"""Resolve machine-local paths without creating files in the source checkout."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def settings(environment=None, home=None, source=ROOT):
    env = os.environ if environment is None else environment
    home = Path.home() if home is None else Path(home)
    config = Path(env.get("LASHOS_CONFIG", home / ".local/projects/lash-os/lashos/config.json")).expanduser().resolve()
    data = json.loads(config.read_text()) if config.exists() else {}
    keys = {"research", "build", "output", "downloads", "reports", "source_cache", "kernel", "modules", "qemu"}
    if not isinstance(data, dict) or set(data) - keys:
        raise ValueError(f"Invalid workspace settings in {config}; allowed keys: {', '.join(sorted(keys))}")

    def path(key, default):
        value = env.get("LASHOS_" + key.upper() + "_DIR", data.get(key, default)) if key in {"research", "build", "output", "downloads", "reports"} else env.get("LASHOS_" + key.upper(), data.get(key, default))
        if value is None and key == "source_cache":
            return None
        if not isinstance(value, (str, Path)) or not str(value):
            raise ValueError(f"{key} must be a nonempty path in {config}")
        result = Path(value).expanduser()
        if not result.is_absolute():
            result = config.parent / result
        return result.resolve()

    research = path("research", home / "research/projects/lash-os/lashos")
    result = {"config": config, "research": research}
    for key, directory in {"build": "build", "output": "out", "downloads": "downloads", "reports": "reports"}.items():
        result[key] = path(key, research / directory)
    result["source_cache"] = path("source_cache", None)
    result["kernel"] = path("kernel", Path("/boot") / ("vmlinuz-" + os.uname().release))
    result["modules"] = path("modules", Path("/lib/modules") / os.uname().release)
    result["qemu"] = path("qemu", "/usr/bin/qemu-system-x86_64")
    for key in ["research", "build", "output", "downloads", "reports"]:
        if result[key].is_relative_to(Path(source).resolve()):
            raise ValueError(f"{key} must be outside the source checkout: {result[key]}")
    return result


def prepare_cmake(directory, source):
    """Archive location-dependent CMake metadata when a checkout/cache moves."""
    directory, source = Path(directory).resolve(), Path(source).resolve()
    cache = directory / "CMakeCache.txt"
    if not cache.exists():
        directory.mkdir(parents=True, exist_ok=True)
        return
    entries = {}
    for line in cache.read_text().splitlines():
        if ":INTERNAL=" in line:
            key, value = line.split(":INTERNAL=", 1)
            entries[key] = value
    if (entries.get("CMAKE_HOME_DIRECTORY") == str(source) and
            entries.get("CMAKE_CACHEFILE_DIR") == str(directory)):
        return
    archive = RESEARCH / "relocated-cmake" / (directory.name + "-" + str(time.time_ns()))
    archive.mkdir(parents=True)
    for name in ["CMakeCache.txt", "CMakeFiles", "Makefile", "cmake_install.cmake", "CTestTestfile.cmake", "DartConfiguration.tcl", "build.ninja", "rules.ninja", ".ninja_deps", ".ninja_log"]:
        old = directory / name
        if old.exists() or old.is_symlink():
            old.rename(archive / name)
    print(f"Archived relocated CMake metadata in {archive}")


try:
    PATHS = settings()
except (OSError, ValueError) as error:
    raise SystemExit(str(error)) from None
RESEARCH = PATHS["research"]
BUILD = PATHS["build"]
OUT = PATHS["output"]
DOWNLOADS = PATHS["downloads"]
REPORTS = PATHS["reports"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--get", choices=sorted(PATHS))
    action.add_argument("--make-path", choices=["config", "build", "output", "downloads", "reports"])
    action.add_argument("--prepare-cmake", nargs=2, metavar=("BUILD", "SOURCE"), help="Archive stale CMake metadata after moving a checkout or build")
    action.add_argument("--clean", action="store_true", help="Remove the configured build directory, retaining output, downloads and reports")
    args = parser.parse_args()
    if args.clean:
        # Avoid broad deletion if a local setting points at a parent directory.
        forbidden = [Path.home(), ROOT, RESEARCH, OUT, DOWNLOADS, REPORTS, PATHS["config"].parent]
        if BUILD == Path("/") or any(p == BUILD or p.is_relative_to(BUILD) for p in forbidden):
            parser.error(f"Refusing to clean a directory containing source, configuration, or preserved data: {BUILD}")
        if BUILD.exists():
            shutil.rmtree(BUILD)
        print(f"Cleaned {BUILD}; output, downloads and reports retained")
    elif args.prepare_cmake:
        prepare_cmake(*args.prepare_cmake)
    elif args.make_path:
        value = str(PATHS[args.make_path])
        # Make's prerequisite syntax cannot safely represent arbitrary path text.
        if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-" for c in value):
            parser.error("Make output paths must contain only letters, digits, underscore, dash, dot and slash")
        print(value)
    elif args.get:
        if PATHS[args.get] is not None:
            print(PATHS[args.get])
    else:
        print(json.dumps({k: str(v) if v is not None else None for k, v in PATHS.items()}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(str(error))
