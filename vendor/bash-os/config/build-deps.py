#!/usr/bin/env python3
"""Build pinned static dependency libraries without modifying the compiler sysroot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path)
    parser.add_argument('--jobs', type=int, default=int(os.environ.get('JOBS', '4')))
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    cc = shutil.which(os.environ.get('CC', 'cc'))
    if not cc:
        parser.error('CC is not an executable compiler')
    target = subprocess.check_output([cc, '-dumpmachine'], text=True).strip()
    prefix = (args.prefix or ROOT/'out/deps'/target).resolve()
    config = ROOT/'config/dependencies.json'
    packages = json.loads(config.read_text())
    cflags = os.environ.get('CFLAGS', '-O2 -fPIC')
    identity = dict(packages=packages, target=target, cc=cc, cflags=cflags,
                    compiler=subprocess.check_output([cc, '--version'], text=True),
                    recipe=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    marker = prefix/'bash-os-dependencies.json'
    libraries = ['libpcre2-8.a', 'libz.a', 'liblzma.a', 'libzstd.a', 'libbz2.a']
    if marker.exists() and json.loads(marker.read_text()) == identity and all((prefix/'lib'/n).is_file() for n in libraries):
        print(f'dependencies: up to date: {prefix}')
        return
    if prefix.exists() and any(prefix.iterdir()) and not marker.is_file():
        parser.error(f'refusing to replace a nonempty unmanaged prefix: {prefix}')
    prefix.parent.mkdir(parents=True, exist_ok=True)
    download = ROOT/'dl/deps'; download.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env['CC'], env['CFLAGS'] = cc, cflags
    for var, suffix in [('AR','ar'), ('RANLIB','ranlib')]:
        candidate = cc[:-3]+suffix if cc.endswith('gcc') else suffix
        tool = shutil.which(os.environ.get(var, candidate))
        if not tool:
            parser.error(f'{var} is not an executable archive tool')
        env[var] = tool
    with tempfile.TemporaryDirectory(prefix='bash-os-deps-', dir=prefix.parent) as directory:
        work = Path(directory)
        dest = work/'dest'
        install = dest/str(prefix).lstrip('/')
        install.mkdir(parents=True)
        install_env = dict(env, DESTDIR=str(dest))
        for name in ['zlib', 'pcre2', 'xz', 'zstd', 'bzip2']:
            spec = packages[name]
            archive = download/spec['url'].rsplit('/', 1)[1]
            if not archive.exists():
                print(f'dependencies: downloading {name} {spec["version"]}', flush=True)
                with urllib.request.urlopen(spec['url'], timeout=120) as response:
                    data = response.read()
                if hashlib.sha256(data).hexdigest() != spec['sha256']:
                    raise RuntimeError(f'{name}: download checksum mismatch')
                temporary = archive.with_suffix(archive.suffix+'.part')
                temporary.write_bytes(data)
                temporary.replace(archive)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != spec['sha256']:
                raise RuntimeError(f'{archive}: checksum mismatch')
            source = work/name
            source.mkdir()
            with tarfile.open(archive) as bundle:
                bundle.extractall(source, filter='data')
            children = list(source.iterdir())
            if len(children) != 1 or not children[0].is_dir():
                raise RuntimeError(f'{archive}: unexpected archive layout')
            source = children[0]
            print(f'dependencies: building {name} {spec["version"]} for {target}', flush=True)
            log = work/(name+'.log')
            def run(command, cwd=source, environment=env):
                with log.open('ab') as output:
                    result = subprocess.run(command, cwd=cwd, env=environment, stdout=output, stderr=subprocess.STDOUT)
                if result.returncode:
                    print(log.read_text(errors='replace')[-12000:])
                    raise RuntimeError(f'{name}: build command failed with exit {result.returncode}: {command[0]}')
            if name == 'zlib':
                run(['./configure', '--static', '--prefix='+str(prefix)])
                run(['make', '-j'+str(args.jobs)])
                run(['make', 'install'], environment=install_env)
            elif name == 'bzip2':
                run(['make', '-j'+str(args.jobs), 'libbz2.a', 'CC='+cc, 'AR='+env['AR'], 'RANLIB='+env['RANLIB'], 'CFLAGS='+cflags])
                (install/'lib').mkdir(exist_ok=True)
                (install/'include').mkdir(exist_ok=True)
                shutil.copy2(source/'libbz2.a', install/'lib/libbz2.a')
                shutil.copy2(source/'bzlib.h', install/'include/bzlib.h')
            else:
                cmake_source = source/'build/cmake' if name == 'zstd' else source
                build = work/(name+'-build')
                options = {
                    'pcre2': ['-DPCRE2_BUILD_PCRE2GREP=OFF', '-DPCRE2_BUILD_TESTS=OFF', '-DPCRE2_SUPPORT_JIT=OFF', '-DPCRE2_BUILD_PCRE2_16=OFF', '-DPCRE2_BUILD_PCRE2_32=OFF'],
                    'xz': ['-DXZ_TOOL_XZ=OFF', '-DXZ_TOOL_XZDEC=OFF', '-DXZ_TOOL_LZMADEC=OFF', '-DXZ_TOOL_LZMAINFO=OFF', '-DXZ_TOOL_SCRIPTS=OFF', '-DXZ_DOC=OFF', '-DBUILD_TESTING=OFF'],
                    'zstd': ['-DZSTD_BUILD_PROGRAMS=OFF', '-DZSTD_BUILD_TESTS=OFF', '-DZSTD_BUILD_SHARED=OFF', '-DZSTD_BUILD_STATIC=ON'],
                }[name]
                run(['cmake', '-S', str(cmake_source), '-B', str(build), '-DCMAKE_SYSTEM_NAME=Linux',
                     '-DCMAKE_SYSTEM_PROCESSOR='+target.split('-')[0], '-DCMAKE_C_COMPILER='+cc,
                     '-DCMAKE_AR='+env['AR'], '-DCMAKE_RANLIB='+env['RANLIB'],
                     '-DCMAKE_C_FLAGS='+cflags, '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_SHARED_LIBS=OFF',
                     '-DCMAKE_INSTALL_LIBDIR=lib', '-DCMAKE_INSTALL_PREFIX='+str(prefix), *options])
                run(['cmake', '--build', str(build), '--parallel', str(args.jobs)])
                run(['cmake', '--install', str(build)], environment=install_env)
            notices = install/'share/licenses'/name
            notices.mkdir(parents=True)
            for path in source.iterdir():
                if path.is_file() and path.name.startswith(('LICENSE', 'LICENCE', 'COPYING')):
                    shutil.copy2(path, notices/path.name)
            if not any(notices.iterdir()):
                raise RuntimeError(f'{name}: no licence notice found')
        if not all((install/'lib'/n).is_file() for n in libraries):
            raise RuntimeError('dependency installation is incomplete')
        (install/'bash-os-dependencies.json').write_text(json.dumps(identity, indent=2)+'\n')
        backup = work/'previous'
        if prefix.exists():
            prefix.rename(backup)
        try:
            install.rename(prefix)
        except BaseException:
            if backup.exists(): backup.rename(prefix)
            raise
    print(f'dependencies: ready: {prefix}', flush=True)


if __name__ == '__main__':
    main()
