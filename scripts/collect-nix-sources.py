#!/usr/bin/env python3
"""Collect source inputs and recipes from the actual portable Nix builds."""
import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
from runtime import ARCHES
from workspace import ROOT, BUILD


def run(arguments):
    try:
        group = grp.getgrnam("nix-users")
        if group.gr_gid not in os.getgroups() and pwd.getpwuid(os.getuid()).pw_name in group.gr_mem:
            arguments = ["sg", "nix-users", "-c", shlex.join(arguments)]
    except KeyError:
        pass
    return subprocess.check_output(arguments, text=True)


def nix(*arguments):
    return run(["nix", "--extra-experimental-features", "nix-command flakes", *arguments])


def store_root(path):
    match = re.match(r"(/nix/store/[a-z0-9]{32}-[^/;\s]+)", str(path))
    if not match:
        raise ValueError(f"Expected a Nix store path: {path}")
    return match[1]


def words(value):
    return value if isinstance(value, list) else shlex.split(value or "")


def portable_profile(arch):
    return "portable" if arch == "x86_64" else "portable-" + arch


def cmake_roots(build):
    """Return the Nix roots linked into one portable loader build, and its SDK root."""
    cache = {}
    for line in (build / "CMakeCache.txt").read_text().splitlines():
        match = re.match(r"([^:#/][^:]*):[^=]+=(.*)", line)
        if match:
            cache[match[1]] = match[2]
    paths = {store_root(p) for p in cache["LIBBPF_STATIC_LIBRARY_DIRS"].split(";")}
    compiler = Path(store_root(cache["CMAKE_C_COMPILER"]))
    for name in ["orig-libc", "orig-cc"]:
        paths.add((compiler / "nix-support" / name).read_text().strip())
    sdk = store_root(cache["CAPSULE_INCLUDE_DIRECTORY"])
    paths.add(sdk)
    return sorted(paths), sdk


def architecture_roots():
    return {arch: cmake_roots(BUILD / portable_profile(arch))[0] for arch in ARCHES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    work = BUILD / "release-sources"
    work.mkdir(parents=True, exist_ok=True)
    inputs, roots, recipes = {}, {}, {}

    def source(path, reason):
        path = store_root(path)
        inputs.setdefault(path, set()).add(reason)

    def recipe(path, reason):
        path = store_root(path)
        if path in recipes:
            return recipes[path]
        derivation = run(["nix-store", "-q", "--deriver", path]).strip()
        if derivation == "unknown-deriver":
            raise ValueError(f"Build recipe is unavailable for {path}")
        data = json.loads(nix("derivation", "show", derivation))[derivation]
        env = dict(data["env"])
        env.update(json.loads(env.get("__json", "{}")))
        if "src" not in env:
            raise ValueError(f"Build recipe has no source: {derivation}")
        source(env["src"], reason)
        for patch in words(env.get("patches")):
            source(patch, reason + " patch")
        for flag in words(env.get("cmakeFlags")):
            if flag.startswith("-DFETCHCONTENT_SOURCE_DIR_"):
                key, value = flag.split("=", 1)
                source(value, key.removeprefix("-DFETCHCONTENT_SOURCE_DIR_"))
        # Retain the exact evaluated recipe, including configure flags and patch
        # phases. The locked Nixpkgs source supplies the original expressions.
        recipes[path] = {"derivation": derivation, "reason": reason, "recipe": data}
        return recipes[path]

    for arch in ARCHES:
        paths, sdk = cmake_roots(BUILD / portable_profile(arch))
        roots[arch] = paths
        for path in paths:
            entry = recipe(path, arch + " " + Path(path).name[33:])
            env = dict(entry["recipe"]["env"])
            env.update(json.loads(env.get("__json", "{}")))
            if "elfutils-" in path:
                # Include its auxiliary libraries as well as the linked closure.
                for dependency in words(env.get("buildInputs")):
                    recipe(dependency, arch + " elfutils dependency")
            if path == sdk:
                for dependency in words(env.get("buildInputs")):
                    if "linux-headers-" in dependency:
                        recipe(dependency, "Linux UAPI headers")

    archive = json.loads(nix("flake", "archive", "--json", "--no-write-lock-file", str(ROOT)))

    def flake_inputs(item):
        for name, child in item.get("inputs", {}).items():
            source(child["path"], "locked flake " + name)
            flake_inputs(child)

    flake_inputs(archive)
    files = []
    for path, reasons in sorted(inputs.items()):
        # Fetching a missing fixed input is allowed; the store authenticates it.
        if not Path(path).exists():
            run(["nix-store", "--realise", path])
        information = json.loads(nix("path-info", "--json", path))
        info = information[path] if isinstance(information, dict) else information[0]
        files.append({"store_path": path, "nar_hash": info["narHash"],
                      "nar_bytes": info["narSize"], "reasons": sorted(reasons)})
    manifest = {"architecture_roots": roots, "sources": files,
                "recipes": [recipes[p] for p in sorted(recipes)]}
    (work / "nix-sources.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Collected {len(files)} source inputs and {len(recipes)} evaluated recipes")
    print(f"Uncompressed Nix source size: {sum(f['nar_bytes'] for f in files):,} bytes")


if __name__ == "__main__":
    main()
