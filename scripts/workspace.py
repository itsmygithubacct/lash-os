#!/usr/bin/env python3
"""Resolve machine-local paths without creating files in the source checkout."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
BUILD_MARKER = ".lashos-build"
WORK_MARKER = ".lashos-test-work"
# Characters Make and the recipe shells handle without quoting or escaping.
MAKE_SAFE = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-+@")
# Entries only a lashos build creates, for trees made before the marker existed.
LEGACY_BUILD_ENTRIES = ["native-full.stamp", "native.stamp", "full-bitcode.stamp", "bitcode.stamp",
                        "deps.stamp", "kernel-full/CMakeCache.txt", "portable/portable.json"]


def make_safe(text):
    return all(c in MAKE_SAFE for c in str(text))


def git(root, *arguments, data=None):
    return subprocess.run(["git", *arguments], cwd=root, input=data, capture_output=True, check=True).stdout


def committed_blob(root, revision, path):
    try:
        return git(root, "rev-parse", "--verify", "--quiet", f"{revision}:{path}").decode().strip()
    except subprocess.CalledProcessError:
        return None


def source_state(root=ROOT):
    """Record the checkout revision and the content of every uncommitted path at build time."""
    try:
        revision = git(root, "rev-parse", "HEAD").decode().strip()
        fields = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all").split(b"\0")
        changed, index = {}, 0
        while index < len(fields) and fields[index]:
            record = os.fsdecode(fields[index])
            index += 1
            paths = [record[3:]]
            if record[0] in "RC" or record[1] in "RC":
                paths.append(os.fsdecode(fields[index]))
                index += 1
            for path in paths:
                file = Path(root) / path
                if file.is_symlink():
                    changed[path] = git(root, "hash-object", "--stdin", data=os.fsencode(os.readlink(file))).decode().strip()
                elif file.is_file():
                    changed[path] = git(root, "hash-object", "--", path).decode().strip()
                else:
                    changed[path] = None
    except (OSError, subprocess.CalledProcessError):
        return {"revision": None, "changed": None}
    return {"revision": revision, "changed": changed}


def documentation(path):
    return path.endswith(".md") or path.startswith("docs/")


def source_differences(state, revision, root=ROOT):
    """List non-documentation paths whose content at build time differs from a commit."""
    if not isinstance(state, dict) or not state.get("revision") or not isinstance(state.get("changed"), dict):
        return ["<build source was not recorded>"]
    changed = state["changed"]
    try:
        names = git(root, "diff", "--name-only", "-z", "--no-renames", state["revision"], revision).split(b"\0")
    except (OSError, subprocess.CalledProcessError):
        return [f"<unknown build revision {state['revision']}>"]
    differences = []
    for path in sorted(set(changed) | {os.fsdecode(name) for name in names if name}):
        expected = changed[path] if path in changed else committed_blob(root, state["revision"], path)
        if expected != committed_blob(root, revision, path) and not documentation(path):
            differences.append(path)
    return differences


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


def recognized_build(build):
    build = Path(build)
    return (build / BUILD_MARKER).is_file() or any((build / name).exists() for name in LEGACY_BUILD_ENTRIES)


def protected_paths(paths):
    return [p for p in [Path.home().resolve(), ROOT, paths["research"], paths["output"], paths["downloads"],
                        paths["reports"], paths["config"].parent, paths["source_cache"]] if p is not None]


def mark_build(paths):
    """Create or adopt the build directory, refusing unrelated existing data."""
    build = paths["build"]
    if build == Path("/") or any(p == build or p.is_relative_to(build) for p in protected_paths(paths)):
        raise ValueError(f"The build directory contains source, configuration, or preserved data: {build}")
    build.mkdir(parents=True, exist_ok=True)
    if not recognized_build(build) and any(build.iterdir()):
        raise ValueError(f"{build} is not empty and is not a lashos build tree; choose another build directory")
    (build / BUILD_MARKER).touch()


def clean_build(paths):
    build = paths["build"]
    # Avoid broad deletion if a local setting points at a parent directory.
    if build == Path("/") or any(p == build or p.is_relative_to(build) for p in protected_paths(paths)):
        raise ValueError(f"Refusing to clean a directory containing source, configuration, or preserved data: {build}")
    if build.is_dir() and any(build.iterdir()) and not recognized_build(build):
        raise ValueError(f"Refusing to clean {build}: it is not recognizably a lashos build tree")
    if build.exists():
        shutil.rmtree(build)


def prepare_work(path, paths=None):
    """Return a dedicated harness work directory whose fixed subfolders may be replaced."""
    paths = PATHS if paths is None else paths
    work = Path(path).expanduser().resolve()
    protected = protected_paths(paths) + [paths["build"]]
    if (work == Path("/") or work.is_relative_to(ROOT) or
            any(p == work or p.is_relative_to(work) for p in protected)):
        raise ValueError(f"Refusing to use {work} as a test work directory")
    work.mkdir(parents=True, exist_ok=True)
    previous = ["result.json", "console.log", "boot.log", "initramfs", "initramfs.cpio.gz"]
    if (not (work / WORK_MARKER).is_file() and any(work.iterdir()) and
            not any((work / name).exists() for name in previous)):
        raise ValueError(f"{work} is not empty and is not a lashos test work directory")
    (work / WORK_MARKER).touch()
    return work


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
    action.add_argument("--mark-build", action="store_true", help="Create or adopt the configured build directory")
    args = parser.parse_args()
    if args.clean:
        try:
            clean_build(PATHS)
        except ValueError as error:
            parser.error(str(error))
        print(f"Cleaned {BUILD}; output, downloads and reports retained")
    elif args.mark_build:
        try:
            mark_build(PATHS)
        except ValueError as error:
            parser.error(str(error))
    elif args.prepare_cmake:
        prepare_cmake(*args.prepare_cmake)
    elif args.make_path:
        value = str(PATHS[args.make_path])
        # Make's prerequisite syntax cannot safely represent arbitrary path text.
        if not make_safe(value):
            parser.error("Make output paths must contain only letters, digits, underscore, dash, dot, slash, plus and at signs")
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
