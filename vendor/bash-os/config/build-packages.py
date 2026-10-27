#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build loadables as standalone shared objects and pack each one for pkg.

Usage: build-packages.sh [--bash BASH] [--tree DIR] [--deps-prefix DIR]
                         [--out DIR] [--version V] [--runner CMD] [NAME...]

With no NAME, every command in config/bash-loadables.list is built. Each
package holds a MANIFEST and one loadable/NAME.so. The object carries its own
copy of the helper sources, required commands and static libraries it uses,
needs no shared library but glibc's libc.so.6, libm.so.6 and dynamic loader
(the DT_NEEDED entries pkg accepts), with a symbol version on every reference
to them, and binds its own symbols locally, so it also loads into a shell
that already has a builtin of that name. A source without NAME_struct gets
the entry build.sh's builtin table gives it.

Sources are staged as build.sh stages them: this repository's loadables,
bash's own example loadables with build.sh's fixups, and flattened helpers.
They compile against the configured bash tree that ./build.sh leaves behind
(--tree); the tree of any dynamic build for the target will do.

An object is packed only after two gates:
- every strong undefined symbol is defined by BASH, a library BASH needs, or
  BASH's program interpreter;
- BASH loads it with enable -f (through --runner, such as qemu-user, for
  another architecture).
BASH should be the smallest dynamic build for the target (out/bash-shell by
default), so that a package loads into every dynamic profile. A static
executable cannot load packages at all.

--prebuilt NAME=SO packs an object built elsewhere, such as bashpython.so
with its static libpython, instead of compiling NAME; it passes the same gates.
--data NAME=DIR adds DIR/libexec/NAME/ and DIR/share/NAME/ to NAME's package,
which pkg installs under /usr/lib/bash-os. MANIFEST declares each of those
files with its mode and SHA-256, and such a package is xz-compressed. NAME
may also come from config/bash-loadables-optional.list.

The output directory receives the packages, an unsigned INDEX and
build-report.tsv. sign-packages.sh signs one or more of these directories
into a release.
"""
import argparse
import concurrent.futures
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from loadables import helpers_for, parse_list  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LOADABLES_DIR = '/usr/lib/bash-os/loadables'
# glibc 2.34 moved these into libc.so.6, which every bash already needs.
IN_LIBC = {'-lpthread', '-ldl', '-lrt', '-lutil'}
# glibc's libraries, which pkg accepts as dependencies along with the dynamic
# loader: linking against them records the symbol version of every reference
# (unversioned, glibc binds the oldest compatibility version), and glibc's
# libm.a cannot go into a shared object.
GLIBC = ('libc.so.6', 'libm.so.6')
LOAD_CHECK = ('PATH=; enable -f "$1" "$2" || exit 1; '
              '[[ $(type -t "$2") == builtin ]] || exit 1; help -s "$2" > /dev/null')
# build.sh's fixups for bash's own example loadables, applied only when this
# repository has no source of the same name.
PATCHES = json.loads((ROOT/'config/stock-patches.json').read_text())
REWRITES = {
    'fltexpr': [(r'^static sh_float_t nanval, infval;$',
                 'static sh_float_t nanval = NAN, infval = INFINITY;')],
    'mkdir': [(re.escape('  int tail;\n'), '  int tail, created;\n'),
              (re.escape('      if (mkdir (npath, 0) < 0)\n'),
               '      created = 0;\n      if (mkdir (npath, 0) == 0)\n\tcreated = 1;\n      else\n'),
              (re.escape('      if (chmod (npath, (tail == 0) ? parent_mode : nmode) != 0)\n'),
               '      if (created && chmod (npath, (tail == 0) ? parent_mode : nmode) != 0)\n')],
}


class Failure(Exception):
    pass


def die(message):
    raise SystemExit(f'build-packages: {message}')


def run(command, **kwargs):
    result = subprocess.run([str(word) for word in command], capture_output=True, text=True, **kwargs)
    if result.returncode:
        lines = [line for line in (result.stderr or result.stdout).strip().splitlines()
                 if not re.search(r'collect2|ld returned', line)]
        errors = [line for line in lines
                  if re.search(r'error|undefined reference|can not be used', line, re.I)] or lines[-3:]
        raise Failure(f'{Path(str(command[0])).name} exited {result.returncode}: '
                      + ' | '.join(errors[:3])[:400])
    return result.stdout


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def data_members(name, directory):
    """The files under DIRECTORY/libexec/NAME and DIRECTORY/share/NAME, as package members."""
    if directory.is_symlink() or not directory.is_dir():
        die(f'--data {directory}: not a regular directory')
    members = []
    for top in sorted(directory.iterdir()):
        if (top.is_symlink() or not top.is_dir() or top.name not in ('libexec', 'share')
                or [p.name for p in top.iterdir()] != [name]
                or (top/name).is_symlink() or not (top/name).is_dir()):
            die(f'--data {directory}: only libexec/{name}/ and share/{name}/ may be present')
        for path in sorted((top/name).rglob('*')):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                die(f'--data {path}: only regular files and directories can be packaged')
            if path.is_file():
                relative = path.relative_to(directory).as_posix()
                if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in relative):
                    die(f'--data {path}: whitespace and control characters cannot appear in MANIFEST paths')
                mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                members.append((relative, path.read_bytes(), mode))
    if not members:
        die(f'--data {directory}: no files')
    return members


def tar_bytes(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for path, data, mode in members:
            info = tarfile.TarInfo(path)
            info.size, info.mode, info.mtime = len(data), mode, 0
            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class Toolchain:
    def __init__(self, cc):
        self.cc = cc
        self.target = run([cc, '-dumpmachine']).strip()
        self.arch = self.target.split('-', 1)[0]
        self.ar, self.nm, self.readelf = (self.tool(name) for name in ('ar', 'nm', 'readelf'))

    def tool(self, name):
        if self.cc.endswith('-gcc') and shutil.which(self.cc[:-3] + name):
            return self.cc[:-3] + name
        return name

    def library(self, name):
        found = run([self.cc, f'-print-file-name={name}']).strip()
        return Path(found) if os.path.isabs(found) and os.path.isfile(found) else None

    def defined(self, path, dynamic=True):
        flags = ['-D'] if dynamic else []
        output = run([self.nm, *flags, '--defined-only', path])
        return {fields[-1].split('@')[0] for fields in map(str.split, output.splitlines())
                if len(fields) >= 3}

    def strong_undefined(self, path):
        output = run([self.nm, '-D', '--undefined-only', path])
        return {fields[1].split('@')[0] for fields in map(str.split, output.splitlines())
                if len(fields) == 2 and fields[0] == 'U'}

    def unversioned_undefined(self, path):
        output = run([self.nm, '-D', '--undefined-only', path])
        return {fields[1] for fields in map(str.split, output.splitlines())
                if len(fields) == 2 and fields[0] in ('U', 'w') and '@' not in fields[1]}

    def needed(self, path):
        return re.findall(r'\(NEEDED\)\s+Shared library: \[([^\]]+)\]', run([self.readelf, '-d', path]))

    def interpreter(self, path):
        found = re.search(r'Requesting program interpreter: ([^\]]+)\]', run([self.readelf, '-l', path]))
        return found and found[1]


def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__.split('\n')[0], formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Environment: CC, CFLAGS, CPPFLAGS, JOBS.')
    parser.add_argument('--bash', type=Path, help='dynamic bash-os used by both gates')
    parser.add_argument('--tree', type=Path, help='bash build tree configured for the target')
    parser.add_argument('--deps-prefix', type=Path, help='static PIC libraries from build-deps.sh')
    parser.add_argument('--out', type=Path, help='output directory (default out/packages/ARCH)')
    parser.add_argument('--version', help='package version (default: HEAD commit date)')
    parser.add_argument('--runner', default='', help='command that runs target executables')
    parser.add_argument('--prebuilt', action='append', default=[], metavar='NAME=SO',
                        help='pack SO as NAME instead of compiling it; the same gates apply')
    parser.add_argument('--data', action='append', default=[], metavar='NAME=DIR',
                        help="add DIR/libexec/NAME and DIR/share/NAME to NAME's package")
    parser.add_argument('--jobs', type=int, default=int(os.environ.get('JOBS') or os.cpu_count() or 2))
    parser.add_argument('names', nargs='*')
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    return args


def main():
    args = parse_args()
    tools = Toolchain(os.environ.get('CC', 'cc'))
    host = run(['cc', '-dumpmachine']).strip() if shutil.which('cc') else tools.target
    base = ROOT/'out' if tools.target == host else ROOT/'out'/tools.target
    bash_version = run(['bash', '-c', '. config/versions.sh; printf %s "$BASH_SRC_VERSION"'], cwd=ROOT)
    tree = (args.tree or ROOT/'build'/f'bash-{bash_version}').resolve()
    bash = (args.bash or base/'bash-shell').resolve()
    deps = args.deps_prefix or ROOT/'out/deps'/tools.target
    deps = deps.resolve() if (deps/'lib').is_dir() else None
    out = (args.out or ROOT/'out/packages'/tools.arch).resolve()
    runner = shlex.split(args.runner)

    if not (tree/'config.h').is_file():
        die(f'{tree} is not a configured bash tree; run ./build.sh --profile shell for this target')
    makefile = (tree/'Makefile').read_text()
    machine = re.search(r'^Machine = (\S+)', makefile, re.M)
    if not machine or machine[1] != tools.arch:
        die(f'{tree} was configured for {machine and machine[1]}, but CC targets {tools.arch}')
    if re.search(r'^LDFLAGS = .*-static\b', makefile, re.M):
        die(f'{tree} was configured for a static executable; run ./build.sh --profile shell '
            'to restore a dynamic build tree')
    if not bash.is_file():
        die(f'{bash} does not exist; build it with ./build.sh --profile shell')
    interpreter = tools.interpreter(bash)
    if not interpreter:
        die(f'{bash} is statically linked and cannot load packages')
    version = args.version or run(['git', 'log', '-1', '--format=%cd', '--date=format:%Y.%m.%d'], cwd=ROOT).strip()
    if not re.fullmatch(r'[0-9A-Za-z][0-9A-Za-z.+~-]*', version):
        die(f'invalid version {version!r}: use letters, digits and . + ~ -')
    if runner and not shutil.which(runner[0]):
        die(f'runner {runner[0]} not found')

    main_catalog = parse_list(ROOT/'config/bash-loadables.list')
    optional = ROOT/'config/bash-loadables-optional.list'
    catalog = {**main_catalog, **(parse_list(optional) if optional.is_file() else {})}
    names = args.names or list(main_catalog)
    unknown = [name for name in names if name not in catalog]
    if unknown:
        die('not in config/bash-loadables.list or its optional list: ' + ', '.join(unknown))
    data = {}
    for item in args.data:
        name, separator, directory = item.partition('=')
        if not separator or name not in names:
            die(f'--data {item!r}: expected NAME=DIR for a NAME being built')
        data[name] = data_members(name, Path(directory))
    prebuilt = {}
    for item in args.prebuilt:
        name, separator, shared = item.partition('=')
        if not separator or name not in names or not Path(shared).is_file():
            die(f'--prebuilt {item!r}: expected NAME=SO for a NAME being built and an existing SO')
        prebuilt[name] = Path(shared).resolve()

    # The symbols a loaded object may use, and those glibc itself defines.
    allowed_needed = {*GLIBC, Path(interpreter).name}
    available, glibc_symbols = tools.defined(bash), set()
    for library in dict.fromkeys([*tools.needed(bash), *allowed_needed]):
        path = tools.library(library)
        if not path:
            die(f'{Path(tools.cc).name} cannot find {library}, which {bash.name} needs')
        symbols = tools.defined(path)
        available |= symbols
        if library in allowed_needed:
            glibc_symbols |= symbols

    manifest = json.loads((ROOT/'config/helpers.json').read_text())
    sources = {}

    def origin(command):
        own = ROOT/'loadables'/f'{command}.c'
        return own if own.is_file() else tree/'examples/loadables'/f'{command}.c'

    def text(command):
        if command not in sources:
            path = origin(command)
            sources[command] = path.read_text(errors='replace') if path.is_file() else None
        return sources[command]

    def requires(command, found=None):
        found = [] if found is None else found
        if command not in found:
            found.append(command)
            for dependency in manifest['commands'].get(command, {}).get('requires', []):
                requires(dependency, found)
        return found

    # Some builtins are defined in a sibling's source (col in column.c), and
    # some through a macro in a shared header (reboot), which only nm confirms.
    definers, report = {}, {}
    for name in names:
        if name in prebuilt:
            continue
        definition = re.compile(rf'\bstruct\s+builtin\s+{name}_struct\b')
        if text(name) and definition.search(text(name)):
            definers[name] = name
            continue
        other = next((command for command in catalog
                      if command != name and text(command) and definition.search(text(command))), None)
        if other or text(name) is not None:
            definers[name] = other or name
        else:
            report[name] = ('failed', f'no source in loadables/ or {tree.name}/examples/loadables')
    closures = {name: list(dict.fromkeys(requires(name) + requires(definers[name])))
                for name in definers}
    commands = sorted({command for closure in closures.values() for command in closure})

    work = Path(tempfile.mkdtemp(prefix='.packages.', dir=ROOT/'build'))
    try:
        stage = work/'stage'
        for directory in (stage/'builtins', stage/'examples/loadables', work/'obj', work/'lib', work/'out'):
            directory.mkdir(parents=True)
        run([sys.executable, ROOT/'config/stage-helpers.py', '--stage', ROOT, stage, *commands])
        helper_names, _ = helpers_for(ROOT, commands)

        staged = {}
        for command in commands:
            if text(command) is None:
                staged[command] = f'no source for {command}'
                continue
            target = stage/'builtins'/f'{command}.c'
            # Match build.sh's include fixups before applying stock patches.
            content = text(command)
            for header in ('builtins.h', 'shell.h', 'bashansi.h', 'arrayfunc.h', 'array.h'):
                content = content.replace(f'#include "{header}"', f'#include "../{header}"')
            # As in build.sh, the builtin function and its documentation become global.
            target.write_text(re.sub(rf'^static (int {command}_builtin|char \*{command}_doc)', r'\1',
                                     content, flags=re.M))
            staged[command] = None
            if origin(command).parent == ROOT/'loadables':
                continue
            try:
                if command in PATCHES:
                    run(['patch', '--batch', '--fuzz=0', '-s', target, '-i', ROOT/'patches'/PATCHES[command]])
                content = target.read_text()
                for pattern, replacement in REWRITES.get(command, []):
                    content, count = re.subn(pattern, lambda _: replacement, content, flags=re.M)
                    if not count:
                        raise Failure(f"build.sh's {command} fixup no longer matches")
                target.write_text(content)
            except Failure as failure:
                staged[command] = str(failure)

        cflags = shlex.split(os.environ.get('CFLAGS', '-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2'))
        compile_flags = [
            '-c', '-fPIC', *cflags, f'-ffile-prefix-map={ROOT}=.', f'-ffile-prefix-map={work}=.',
            '-DHAVE_CONFIG_H', '-DSHELL', *shlex.split(os.environ.get('CPPFLAGS', '')),
            f'-I{stage}/builtins', f'-I{ROOT}/loadables/common', f'-I{tree}', f'-I{tree}/include',
            f'-I{tree}/lib', f'-I{tree}/builtins', f'-I{tree}/examples/loadables',
            *([f'-I{deps}/include'] if deps else [])]
        units = {command: (stage/'builtins'/f'{command}.c', work/'obj'/f'{command}.o')
                 for command in commands if not staged[command]}
        helper_units = {}
        for helper in helper_names:
            for source in sorted((ROOT/'loadables'/helper).glob('*.c')):
                flat = f'{helper}_{source.stem}'
                helper_units[flat] = (stage/'builtins'/f'{flat}.c', work/'obj'/f'{flat}.o', helper)

        def compile_unit(item):
            key, (source, target, *_) = item
            try:
                run([tools.cc, *compile_flags, source, '-o', target])
                return key, None
            except Failure as failure:
                return key, str(failure)

        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            compiled = dict(pool.map(compile_unit, [*units.items(), *helper_units.items()]))
        compiled.update({command: error for command, error in staged.items() if error})

        broken_helpers = {}
        for flat, (_, _, helper) in helper_units.items():
            if compiled[flat]:
                broken_helpers.setdefault(helper, f'{flat}.c: {compiled[flat]}')
        archives = {}
        for helper in helper_names:
            members = [target for flat, (_, target, owner) in helper_units.items() if owner == helper]
            if members and helper not in broken_helpers:
                archives[helper] = work/'lib'/f'lib{helper}.a'
                run([tools.ar, 'rcsD', archives[helper], *members])
        for command in units:
            if not compiled[command]:
                archives[command] = work/'lib'/f'cmd-{command}.a'
                run([tools.ar, 'rcsD', archives[command], units[command][1]])

        def static_libraries(flags):
            found = []
            for flag in flags:
                if flag in IN_LIBC or flag == '-lm':
                    continue
                name = f'lib{flag[2:]}.a'
                path = deps/'lib'/name if deps and (deps/'lib'/name).is_file() else tools.library(name)
                if not path:
                    raise Failure(f'no static {name} for {flag}; run ./build-deps.sh')
                found.append(path)
            return found

        def link(name, shared):
            definer, closure = definers[name], closures[name]
            if compiled.get(definer):
                raise Failure(f'{definer}.c: {compiled[definer]}')
            objects = [units[definer][1]]
            if f'{name}_struct' not in tools.defined(objects[0], dynamic=False):
                # enable -f looks up NAME_struct; give it build.sh's table entry.
                shim = work/'obj'/f'{name}-struct.c'
                shim.write_text(
                    '#include <config.h>\n#include "loadables.h"\n\n'
                    f'extern int {name}_builtin (WORD_LIST *);\n'
                    f'extern char * const {name}_doc[];\n\n'
                    f'struct builtin {name}_struct = {{ {json.dumps(name)}, {name}_builtin, '
                    f'BUILTIN_ENABLED, {name}_doc, {json.dumps(catalog[name], ensure_ascii=False)}, 0 }};\n')
                objects.append(shim.with_suffix('.o'))
                run([tools.cc, *compile_flags, shim, '-o', objects[-1]])
            helpers, flags = helpers_for(ROOT, closure)
            for helper in helpers:
                if helper in broken_helpers:
                    raise Failure(f'helper {broken_helpers[helper]}')
            run([tools.cc, '-shared', '-nodefaultlibs', '-fPIC', '-s',
                 '-Wl,-Bsymbolic', '-Wl,--exclude-libs,ALL', f'-Wl,-soname,{name}.so',
                 '-Wl,--build-id=none', '-Wl,-z,relro', '-Wl,-z,now', '-Wl,-z,noexecstack',
                 '-o', shared, *objects, '-Wl,--start-group',
                 *[archives[command] for command in closure if command != definer and command in archives],
                 *[archives[helper] for helper in helpers if helper in archives],
                 *static_libraries(flags), '-Wl,--end-group',
                 '-Wl,--as-needed', '-lm', '-Wl,--no-as-needed', '-lgcc', '-lc', '-lgcc'])

        def build(name):
            shared = work/'out'/f'{name}.so'
            if name in prebuilt:
                shutil.copyfile(prebuilt[name], shared)
            else:
                link(name, shared)
            needed = tools.needed(shared)
            if set(needed) - allowed_needed:
                raise Failure('links shared libraries: ' + ', '.join(needed))
            unversioned = sorted(tools.unversioned_undefined(shared) & glibc_symbols)
            if unversioned:
                raise Failure('unversioned glibc references: ' + ' '.join(unversioned[:6]))
            missing = sorted(tools.strong_undefined(shared) - available)
            if missing:
                raise Failure(f'{len(missing)} symbols no dynamic bash provides: ' + ' '.join(missing[:6]))
            loaded = subprocess.run([*runner, bash, '--noprofile', '--norc', '-c', LOAD_CHECK, '_', shared, name],
                                    capture_output=True, text=True, timeout=120,
                                    env={'LC_ALL': 'C', 'HOME': str(work), 'PATH': os.environ.get('PATH', '')})
            if loaded.returncode:
                detail = ' | '.join(loaded.stderr.strip().splitlines()[:2])[:300]
                raise Failure(f'enable -f failed (exit {loaded.returncode}): {detail}')
            body = shared.read_bytes()
            extra = data.get(name, [])
            manifest_text = (
                f'name: {name}\ntype: loadable\nversion: {version}\nbuiltin: {name}\n'
                f'abi: bash-{bash_version}\narch: {tools.arch}\nsha256: {sha256(body)}\n'
                f'description: {catalog[name]}\nmode: {LOADABLES_DIR}/{name}.so 0755\n'
                + ''.join(f'data: {path} {mode:04o} {sha256(content)}\n' for path, content, mode in extra))
            archive = tar_bytes([('MANIFEST', manifest_text.encode(), 0o644),
                                 (f'loadable/{name}.so', body, 0o755), *extra])
            if extra:
                archive = lzma.compress(archive, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=9)
            package = f'{name}_{version}_{tools.arch}.pkg'
            (work/'out'/package).write_bytes(archive)
            shared.unlink()
            record = (f'pkg-loadable-v1 name={name} version={version} builtin={name} '
                      f'abi=bash-{bash_version} arch={tools.arch} package={package} '
                      f'sha256={sha256(archive)} sig={package}.sig deps=-')
            return f'{len(body)} bytes', record

        def attempt(name):
            try:
                return name, build(name)
            except (Failure, subprocess.TimeoutExpired, ValueError) as failure:
                return name, failure

        records = []
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            for name, result in pool.map(attempt, sorted([*definers, *prebuilt])):
                if isinstance(result, Exception):
                    report[name] = ('failed', str(result))
                else:
                    report[name] = ('built', result[0])
                    records.append(result[1])

        (work/'out'/'INDEX').write_text(''.join(record + '\n' for record in sorted(records)))
        (work/'out'/'build-report.tsv').write_text(''.join(
            f'{name}\t{status}\t{detail}\n' for name, (status, detail) in sorted(report.items())))
        if out.exists():
            stray = [path.name for path in out.iterdir()
                     if not (path.suffix == '.pkg' or path.name in ('INDEX', 'build-report.tsv'))]
            if stray:
                die(f'{out} holds files this tool did not write: {", ".join(stray[:5])}')
            shutil.rmtree(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(work/'out', out)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    failed = sorted(name for name, (status, _) in report.items() if status == 'failed')
    for name in failed:
        print(f'build-packages: {name}: {report[name][1]}', file=sys.stderr)
    print(f'build-packages: {tools.arch} {version}: {len(records)} built, {len(failed)} failed; '
          f'report {out}/build-report.tsv')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
