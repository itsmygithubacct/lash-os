#!/usr/bin/env python3
"""Compile the native reference's exact object inventory into Capsule bitcode."""
import sys
sys.dont_write_bytecode = True
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import subprocess

from workspace import ROOT, BUILD
SOURCE = BUILD / "native-pure/source/build/bash-5.3"

def main():
    global SOURCE
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path)
    parser.add_argument('--profile', choices=['pure', 'full'], default='pure')
    parser.add_argument('--only', action='append')
    parser.add_argument('--retry-failed', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    full = args.profile == 'full'
    SOURCE = (args.source or BUILD / ('native-' + args.profile) / 'source/build/bash-5.3').resolve()
    compiler = shutil.which("bpf-capsule-cc")
    if not compiler:
        sys.exit("bpf-capsule-cc is missing; run this script inside nix develop")
    output = (args.output or BUILD / ('full-bitcode' if full else 'bitcode')).resolve()
    output.mkdir(parents=True, exist_ok=True)
    sources = []
    for obj in sorted((SOURCE / "builtins").glob("*.o")):
        definition = obj.with_suffix(".def")
        if definition.is_file() and not obj.with_suffix(".c").exists():
            subprocess.run(["./mkbuiltins", "-D", ".", definition.name], cwd=definition.parent, check=True)
    for directory in ["", "builtins", "lib/sh", "lib/glob", "lib/tilde", "lib/readline"]:
        for obj in sorted((SOURCE / directory).glob("*.o")):
            src = obj.with_suffix(".c")
            if src.is_file() and obj.stem not in ("mkbuiltins", "mksyntax", "mkversion", "signames"):
                sources.append(src)
    if full:
        sources += [SOURCE / "lib/termcap/termcap.c", SOURCE / "lib/termcap/tparam.c"]
    expected = {output / p.relative_to(SOURCE).with_suffix('.bc') for p in sources}
    for previous in output.rglob('*.bc'):
        if previous not in expected: previous.unlink()
    (output / "sources.json").write_text(json.dumps([str(p.relative_to(SOURCE)) for p in sources], indent=2)+"\n")
    flags = ["-c", "-g", "-std=gnu17", "-DHAVE_CONFIG_H", "-DSHELL", "-Dmain=bash_kernel_main",
             "-D_GNU_SOURCE", "-Wno-deprecated-non-prototype", "-Werror=incompatible-pointer-types",
             "-Wno-incompatible-pointer-types-discards-qualifiers",
             "-Werror=implicit-function-declaration", "-Werror=int-conversion", "-Wno-pointer-sign",
             "-Wno-discarded-qualifiers", "-Wno-unknown-warning-option",
             # Keep the build machine's directories out of __FILE__ and debug
             # records, which ship inside the image.
             f"-ffile-prefix-map={SOURCE}=/lashos/bash", f"-ffile-prefix-map={ROOT}=/lashos/source",
             "-fdebug-compilation-dir=/lashos"]
    for path in [ROOT / "include/guest", ROOT / "include", SOURCE, SOURCE / "include", SOURCE / "lib", SOURCE / "builtins"]:
        flags.append("-I"+str(path))
    flags += ["-idirafter", str(ROOT / "vendor/musl-headers")]
    if os.environ.get("LINUX_HEADERS"):
        flags += ["-idirafter", os.environ["LINUX_HEADERS"]]
    if full:
        flags += ["-D__linux__=1", "-D__unix__=1"]
        import shlex
        flags += shlex.split(subprocess.check_output(["pkg-config", "--cflags", "libpcre2-8", "libzstd", "zlib", "liblzma", "ncurses"], text=True))
        # bzip2 does not publish a pkg-config file.
        if os.environ.get('BZIP2_INCLUDE'):
            flags += ['-I'+os.environ['BZIP2_INCLUDE']]
        else:
            sys.exit('BZIP2_INCLUDE is missing; use the pinned Nix shell')
    def compile_one(src):
        dest = output / src.relative_to(SOURCE).with_suffix(".bc")
        dest.parent.mkdir(parents=True, exist_ok=True)
        command = [str(compiler), *flags, str(src), "-o", str(dest)]
        if src.name == "_libssh_misc.c":
            command += ["-include", str(ROOT / "include/guest/libssh_port.h")]
        if src.name == "bashline.c":
            command += ["-include", "netdb.h"]
        if src.name == "netopen.c":
            # GNU's no-network branch needs declarations outside its #if.
            command += ["-include", "locale.h"]
        result = subprocess.run(command, cwd=src.parent, capture_output=True, text=True)
        return src, result
    failures = []
    diagnostics = []
    work=sources
    if args.retry_failed:
        failed={e["source"] for e in json.loads((output/"errors.json").read_text())}
        work=[p for p in sources if str(p.relative_to(SOURCE)) in failed]
    if args.only: work=[p for p in sources if str(p.relative_to(SOURCE)) in args.only]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for src, result in pool.map(compile_one, work):
            if result.stderr:
                diagnostics.append({"source":str(src.relative_to(SOURCE)),"diagnostic":result.stderr})
            if result.returncode:
                failures.append({"source":str(src.relative_to(SOURCE)),"diagnostic":result.stderr})
    (output / "errors.json").write_text(json.dumps(failures, indent=2)+"\n")
    (output / "diagnostics.json").write_text(json.dumps(diagnostics, indent=2)+"\n")
    print(f"Compiled {len(work)-len(failures)}/{len(work)} requested Bash translation units ({len(sources)} in full inventory)")
    for error in failures[:8]:
        print(error['source']+':\n'+error['diagnostic'][-2500:])
    if failures:
        sys.exit(1)
    missing = sorted(str(p.relative_to(output)) for p in expected if not p.is_file())
    if missing:
        sys.exit("Missing bitcode; compile without --only to fill the inventory: " + ", ".join(missing))
    archive_dir = output.parent / (output.name + "-archives")
    archive_dir.mkdir(exist_ok=True)
    ar = shutil.which("llvm-ar")
    for directory in ["sh", "glob", "tilde", "readline", "termcap"]:
        files = sorted((output / "lib" / directory).glob("*.bc"))
        if not files: continue
        archive = archive_dir / ("lib" + directory + ".a")
        archive.unlink(missing_ok=True)
        subprocess.run([ar, "rcs", str(archive), *map(str, files)], check=True)

if __name__ == "__main__":
    main()
