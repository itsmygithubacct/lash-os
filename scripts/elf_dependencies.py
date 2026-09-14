#!/usr/bin/env python3
"""Inspect ELF runtime dependencies without executing the inspected program."""
import argparse
import os
from pathlib import Path
import re
import subprocess


def inspect(path):
    environment = dict(os.environ, LC_ALL="C")
    def readelf(option):
        return subprocess.check_output(["readelf", option, "--wide", str(path)],
                                       text=True, env=environment)
    if not re.search(r"Type:\s+(EXEC|DYN)\b", readelf("--file-header")):
        raise ValueError(f"{path} is not an ELF executable")
    headers = readelf("--program-headers")
    dynamic = readelf("--dynamic")
    interpreter = re.search(r"Requesting program interpreter: (.*?)\]", headers)
    return {
        "interpreter": interpreter.group(1) if interpreter else None,
        "needed_libraries": re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic),
        "runtime_search_paths": re.findall(r"\((?:RPATH|RUNPATH)\).*?\[(.*?)\]", dynamic),
    }


def require_static(path):
    result = inspect(path)
    if result["interpreter"] or result["needed_libraries"] or result["runtime_search_paths"]:
        raise ValueError(f"{path} has external ELF runtime dependencies: {result}")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    try:
        require_static(args.binary)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + "\n")
    print(f"PASS: {args.binary} has no ELF interpreter, shared-library dependencies, or runtime search paths")
