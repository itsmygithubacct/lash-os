#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a private CPython installation with an embeddable static libpython.

The prefix (out/python/TARGET by default) receives:
- a CPython installation whose standard extension modules are compiled into
  a position-independent libpython, with bin/python3 as a reference build;
- lib/bashpython/*.a, the archives the embedding links, with Bash's exported
  getenv family redirected to the private copies in loadables/_python;
- data/share/bashpython/lib/python3.X, the trimmed standard library that pkg
  installs at /usr/lib/bash-os/share/bashpython;
- bash-os-python.json, recording the flags, modules and archive checksums;
- bash-os-installation.json, the complete installed-file inventory it verifies.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

import installation_cache

ROOT = Path(__file__).resolve().parent.parent
# Bash exports these, operating on shell variables instead of environ.
ENVIRONMENT = ('getenv', 'setenv', 'unsetenv', 'putenv', 'clearenv')
# Not built: readline and curses would duplicate the readline and terminfo code
# Bash already exports; tkinter and the dbm/gdbm bindings have no headers here;
# libuuid.a uses initial-exec TLS, which cannot go into a shared object, and
# uuid has a pure Python fallback.
DISABLED = ('readline', '_curses', '_curses_panel', '_tkinter', '_gdbm', '_dbm', '_uuid')
# Removed from the installed standard library: tools needing modules left out,
# and ensurepip, whose bundled wheels only serve virtual environments.
TRIMMED = ('idlelib', 'tkinter', 'turtledemo', 'turtle.py', 'ensurepip', 'site-packages')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def host_archive(cc, name):
    found = subprocess.check_output([cc, f'-print-file-name={name}'], text=True).strip()
    return Path(found) if os.path.isabs(found) and os.path.isfile(found) else None


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--prefix', type=Path)
    parser.add_argument('--deps-prefix', type=Path)
    parser.add_argument('--jobs', type=int, default=int(os.environ.get('JOBS', '4')))
    parser.add_argument('--flags', action='store_true', help='read an existing installation, as JSON')
    parser.add_argument('--build-python', type=Path,
                        help='for a cross build: the same CPython version, built natively')
    parser.add_argument('--runner', default='',
                        help='for a cross build: a command that runs target executables')
    args = parser.parse_args()
    cc = shutil.which(os.environ.get('CC', 'cc'))
    if not cc or args.jobs < 1:
        parser.error('an executable CC and a positive --jobs are required')
    target = subprocess.check_output([cc, '-dumpmachine'], text=True).strip()
    prefix = (args.prefix or ROOT/'out/python'/target).resolve()
    if any(c.isspace() for c in str(prefix)):
        parser.error('the Python prefix cannot contain whitespace')
    marker = prefix/'bash-os-python.json'

    def installed():
        return installation_cache.read_installation(prefix, marker.name)

    if args.flags:
        record = installed()
        if record is None or record['identity']['target'] != target:
            parser.error('missing, damaged, or wrong-target Python installation; run build-python.sh')
        print(json.dumps(record))
        return

    native = subprocess.check_output(['cc', '-dumpmachine'], text=True).strip()
    cross = target != native
    runner = shlex.split(args.runner)
    if cross and not (args.build_python and args.build_python.is_file() and runner):
        parser.error('a cross build needs --build-python, the same CPython built natively, '
                     'and --runner, a command that runs target executables')

    def tool(name):
        prefixed = cc[:-3] + name if cc.endswith('-gcc') else None
        return prefixed if prefixed and shutil.which(prefixed) else name

    deps = (args.deps_prefix or ROOT/'out/deps'/target).resolve()
    if not all((deps/'lib'/name).is_file() for name in ('libz.a', 'libbz2.a', 'liblzma.a', 'libzstd.a')):
        parser.error(f'{deps} lacks static zlib, bzip2, xz and zstd; run ./build-deps.sh')
    sqlite = ROOT/'loadables/_sqlite'
    spec = json.loads((ROOT/'config/python.json').read_text())
    # OpenSSL and libffi from build-deps.sh --python, or else the build host's own.
    optional = {name: deps/'lib'/name if (deps/'lib'/name).is_file()
                else None if cross else host_archive(cc, name)
                for name in ('libffi.a', 'libssl.a', 'libcrypto.a')}
    identity = dict(package=spec, target=target, cc=cc,
                    build_python=str(args.build_python) if cross else None,
                    compiler=subprocess.check_output([cc, '--version'], text=True),
                    recipe=digest(Path(__file__)), sqlite=digest(sqlite/'sqlite3.c'),
                    installation_recipe=digest(Path(installation_cache.__file__)),
                    deps={name: digest(deps/'lib'/name) for name in ('libz.a', 'libbz2.a', 'liblzma.a', 'libzstd.a')},
                    host={name: path and digest(path) for name, path in optional.items()})

    prefix.parent.mkdir(parents=True, exist_ok=True)
    with (prefix.parent/(prefix.name+'.lock')).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        record = installed()
        if record is not None and record['identity'] == identity:
            print(f'python: up to date: {prefix}', flush=True)
            return
        if prefix.exists() and any(prefix.iterdir()) and not marker.is_file():
            parser.error(f'refusing to replace an unmanaged prefix: {prefix}')
        download = ROOT/'dl/python'
        download.mkdir(parents=True, exist_ok=True)
        archive = download/spec['url'].rsplit('/', 1)[1]
        if not archive.exists():
            print(f'python: downloading {spec["version"]}', flush=True)
            # The far end is a public mirror that answers 504 under load, and
            # a download that arrives truncated fails the checksum; neither is
            # a bad pin, so ask again before giving up on it.
            data = None
            for attempt in (1, 2, 3):
                try:
                    with urllib.request.urlopen(spec['url'], timeout=300) as response:
                        data = response.read()
                except (urllib.error.URLError, TimeoutError) as failure:
                    if attempt == 3:
                        raise
                    print(f'python: {failure}, asking again', flush=True)
                    time.sleep(attempt * 5)
                    continue
                if hashlib.sha256(data).hexdigest() == spec['sha256']:
                    break
                if attempt == 3:
                    raise RuntimeError('CPython download checksum mismatch')
                print('python: the archive arrived damaged, asking again',
                      flush=True)
                time.sleep(attempt * 5)
            temporary = archive.with_suffix('.part')
            temporary.write_bytes(data)
            temporary.replace(archive)
        if digest(archive) != spec['sha256']:
            raise RuntimeError('CPython archive checksum mismatch')
        log = prefix.parent/(prefix.name+'.log')
        log.write_bytes(b'')
        with tempfile.TemporaryDirectory(prefix='.python-build-', dir=prefix.parent) as directory:
            work = Path(directory)
            with tarfile.open(archive) as bundle:
                bundle.extractall(work, filter='data')
            source = work/('Python-'+spec['version'])
            dest = work/'dest'
            install = dest/str(prefix).lstrip('/')
            env = {k: v for k, v in os.environ.items() if not k.startswith('PYTHON') and k != 'DESTDIR'}

            def run(command, cwd=source, environment=env):
                with log.open('ab') as output:
                    p = subprocess.run(command, cwd=cwd, env=environment,
                                       stdout=output, stderr=subprocess.STDOUT)
                if p.returncode:
                    print(log.read_text(errors='replace')[-8000:])
                    raise RuntimeError(f'Python build failed ({p.returncode}); see {log}')

            # SQLite from the vendored amalgamation, so no system library is needed.
            sqlite_lib = work/'sqlite'
            sqlite_lib.mkdir()
            run([cc, '-c', '-O2', '-fPIC', '-DSQLITE_THREADSAFE=1', '-DSQLITE_OMIT_LOAD_EXTENSION',
                 '-DSQLITE_ENABLE_FTS5', '-DSQLITE_ENABLE_RTREE', '-DSQLITE_ENABLE_MATH_FUNCTIONS',
                 str(sqlite/'sqlite3.c'), '-o', str(sqlite_lib/'sqlite3.o')])
            run([tool('ar'), 'rcsD', str(sqlite_lib/'libsqlite3.a'), str(sqlite_lib/'sqlite3.o')])

            variables = dict(
                MODULE_BUILDTYPE='static', CC=cc, CFLAGS='-O2 -fPIC',
                ZLIB_CFLAGS=f'-I{deps}/include', ZLIB_LIBS=str(deps/'lib/libz.a'),
                BZIP2_CFLAGS=f'-I{deps}/include', BZIP2_LIBS=str(deps/'lib/libbz2.a'),
                LIBLZMA_CFLAGS=f'-I{deps}/include', LIBLZMA_LIBS=str(deps/'lib/liblzma.a'),
                LIBSQLITE3_CFLAGS=f'-I{sqlite}',
                # configure's link checks add -lsqlite3 themselves; this directory holds
                # only the vendored archive, so it is what they find, native or cross.
                LIBSQLITE3_LIBS=f'-L{sqlite_lib} -lsqlite3 -lm')
            disabled = list(DISABLED)
            if optional['libffi.a']:
                variables.update(LIBFFI_CFLAGS=f'-I{deps}/include' if optional['libffi.a'].parent == deps/'lib'
                                 else '', LIBFFI_LIBS=str(optional['libffi.a']))
            else:
                disabled.append('_ctypes')
            if optional['libssl.a'] and optional['libcrypto.a']:
                # CPython's static OpenSSL link appends ZLIB_LIBS after libssl.a
                # and libcrypto.a; distribution builds of libcrypto also use zstd.
                variables['PY_UNSUPPORTED_OPENSSL_BUILD'] = 'static'
                variables['ZLIB_LIBS'] = f'{deps}/lib/libz.a {deps}/lib/libzstd.a'
            else:
                disabled += ['_ssl', '_hashlib']
            configure = ['./configure', '--prefix='+str(prefix), '--disable-shared',
                         '--disable-test-modules', '--without-ensurepip', '--with-lto=no',
                         *[f'py_cv_module_{name}=n/a' for name in disabled]]
            if 'PY_UNSUPPORTED_OPENSSL_BUILD' in variables and optional['libssl.a'].parent == deps/'lib':
                configure.append('--with-openssl='+str(deps))
            if cross:
                configure += ['--host='+target, '--build='+native, '--with-build-python='+str(args.build_python),
                              # Answers configure cannot find by running test programs.
                              'ac_cv_file__dev_ptmx=yes', 'ac_cv_file__dev_ptc=no',
                              'ac_cv_buggy_getaddrinfo=no']
            print(f'python: configuring {spec["version"]} for {target}; log: {log}', flush=True)
            run(configure, environment={**env, **variables})
            print('python: compiling interpreter and standard modules', flush=True)
            run(['make', '-j'+str(args.jobs)])
            # CPython otherwise uses compileall -j0 (all CPUs) during install,
            # independently of the limit used for the C build.
            run(['make', 'install', 'COMPILEALL_OPTS=-j'+str(args.jobs),
                 'DESTDIR='+str(dest)])

            built = source/'python'
            probe = ('import json, sys, sysconfig; '
                     'print(json.dumps(dict(version=sys.version, abi=sys.abiflags, '
                     'modules=sorted(sys.builtin_module_names), '
                     'ldversion=sysconfig.get_config_var("LDVERSION"), '
                     'libs=sysconfig.get_config_var("LIBS"), '
                     'modlibs=sysconfig.get_config_var("MODLIBS"), '
                     'syslibs=sysconfig.get_config_var("SYSLIBS"))))')
            config = json.loads(subprocess.check_output(
                [*runner, str(built), '-S', '-c', probe], cwd=source, text=True,
                env={**env, 'PYTHONHOME': str(install), 'PYTHONPATH': str(source/'Lib')}))
            version = '.'.join(spec['version'].split('.')[:2])
            required = ['_sqlite3', 'zlib', '_bz2', '_lzma', '_decimal', '_json', 'pyexpat']
            if optional['libffi.a']:
                required.append('_ctypes')
            if 'PY_UNSUPPORTED_OPENSSL_BUILD' in variables:
                required += ['_ssl', '_hashlib']
            missing = [name for name in required if name not in config['modules']]
            if missing:
                raise RuntimeError('modules were not compiled in: ' + ', '.join(missing))

            # Archives the embedding links: libpython and the static libraries its
            # modules use, rewritten to call the private environment functions.
            objcopy = shutil.which(os.environ.get('OBJCOPY', tool('objcopy')))
            if not objcopy:
                raise RuntimeError('objcopy is required for the embedding archives')
            remap = [f'--redefine-sym={name}=bos_python_env_{name}' for name in ENVIRONMENT]
            embedded = install/'lib/bashpython'
            embedded.mkdir(parents=True)
            libpython = source/f'libpython{config["ldversion"]}.a'
            inputs = [libpython]
            internal = [source/'Modules/_decimal/libmpdec/libmpdec.a', source/'Modules/expat/libexpat.a',
                        *sorted((source/'Modules/_hacl').glob('libHacl_*.a'))]
            inputs += [p for p in internal if p.is_file()]
            inputs += [sqlite_lib/'libsqlite3.a', deps/'lib/libz.a', deps/'lib/libbz2.a', deps/'lib/liblzma.a']
            if optional['libffi.a']:
                inputs.append(optional['libffi.a'])
            if 'PY_UNSUPPORTED_OPENSSL_BUILD' in variables:
                inputs += [optional['libssl.a'], optional['libcrypto.a'], deps/'lib/libzstd.a']
            readelf = shutil.which(os.environ.get('READELF', tool('readelf')))
            archives = []
            for index, original in enumerate(inputs):
                # Initial-exec and local-exec TLS cannot be linked into a shared object.
                relocations = subprocess.run([readelf, '-r', '--wide', str(original)], check=True,
                                             capture_output=True, text=True).stdout
                if any(kind in relocations for kind in ('_TPOFF32', '_TPOFF64 ', 'GOTTPOFF', 'TLS_IE', 'TLS_LE')):
                    raise RuntimeError(f'{original} uses initial-exec or local-exec TLS; build it with -fPIC')
                adapted = embedded/f'{index:02d}-{original.name}'
                subprocess.run([objcopy, *remap, str(original), str(adapted)], check=True)
                archives.append(adapted)

            # The standard library pkg installs: compiled once, trimmed of tests,
            # optimization-level variants and tools for modules left out.
            stdlib = install/'lib'/f'python{version}'
            data = install/'data/share/bashpython/lib'/f'python{version}'
            shutil.copytree(stdlib, data, symlinks=True,
                            ignore=shutil.ignore_patterns('*.opt-1.pyc', '*.opt-2.pyc', 'config-*'))
            for name in TRIMMED:
                target_path = data/name
                if target_path.is_dir():
                    shutil.rmtree(target_path)
                elif target_path.exists():
                    target_path.unlink()
            (data/'site-packages').mkdir()

            linked = [str(prefix/p.relative_to(install)) for p in archives]
            flags = dict(
                cppflags='-I'+str(prefix/'include'/f'python{config["ldversion"]}'),
                home=str(prefix),
                ldflags='-Wl,-E',
                # libpython whole, so separately built C extensions find the whole API.
                # libm last: with --as-needed, an earlier -lm is dropped before
                # the archives that use it are read.
                libraries=' '.join(['-Wl,--whole-archive', linked[0], '-Wl,--no-whole-archive',
                                    '-Wl,--start-group', *linked[1:], '-Wl,--end-group', '-lm']),
                archives=linked)
            files = [install/p.relative_to(install) for p in archives]
            files += [install/'include'/f'python{config["ldversion"]}'/'Python.h', install/'bin'/f'python{version}']
            checksums = {str(p.relative_to(install)): digest(p) for p in files}
            data_files = sorted(p for p in (install/'data').rglob('*') if p.is_file())
            record = dict(identity=identity, flags=flags, config=config, disabled=disabled,
                          checksums=checksums, data=dict(
                              root=str(prefix/'data'), files=len(data_files),
                              bytes=sum(p.stat().st_size for p in data_files)))
            notices = install/'share/licenses/python'
            notices.mkdir(parents=True)
            shutil.copy2(source/'LICENSE', notices/'LICENSE')
            record['installation'] = installation_cache.write_manifest(install, marker.name)
            (install/'bash-os-python.json').write_text(json.dumps(record, indent=2)+'\n')
            backup = work/'previous'
            if prefix.exists():
                prefix.rename(backup)
            try:
                install.rename(prefix)
            except BaseException:
                if backup.exists():
                    backup.rename(prefix)
                raise
        print(f'python: ready: {prefix}', flush=True)


if __name__ == '__main__':
    main()
