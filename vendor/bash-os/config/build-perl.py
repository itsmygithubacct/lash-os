#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a private Perl installation with an embeddable static libperl."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

import installation_cache

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path)
    parser.add_argument('--jobs', type=int, default=int(os.environ.get('JOBS', '4')))
    parser.add_argument('--flags', action='store_true', help='read an existing installation, as JSON')
    args = parser.parse_args()
    cc = shutil.which(os.environ.get('CC', 'cc'))
    if not cc or args.jobs < 1:
        parser.error('an executable CC and a positive --jobs are required')
    target = subprocess.check_output([cc, '-dumpmachine'], text=True).strip()
    prefix = (args.prefix or ROOT/'out/perl'/target).resolve()
    if any(c.isspace() for c in str(prefix)):
        parser.error('the Perl prefix cannot contain whitespace')
    marker = prefix/'bash-os-perl.json'
    spec = json.loads((ROOT/'config/perl.json').read_text())
    identity = dict(package=spec, target=target, cc=cc,
                    compiler=subprocess.check_output([cc, '--version'], text=True),
                    recipe=digest(Path(__file__)),
                    installation_recipe=digest(Path(installation_cache.__file__)))

    def installed():
        return installation_cache.read_installation(prefix, marker.name)

    if args.flags:
        record = installed()
        if record is None or record['identity']['target'] != target:
            parser.error('missing, damaged, or wrong-target Perl installation; run build-perl.sh')
        print(json.dumps(record))
        return
    native = subprocess.check_output(['cc', '-dumpmachine'], text=True).strip()
    if target != native:
        parser.error('automatic Perl builds require a native compiler; supply a prepared target --perl-prefix')
    prefix.parent.mkdir(parents=True, exist_ok=True)
    with (prefix.parent/(prefix.name+'.lock')).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        record = installed()
        if record is not None and record['identity'] == identity:
            print(f'perl: up to date: {prefix}', flush=True)
            return
        if prefix.exists() and any(prefix.iterdir()) and not marker.is_file():
            parser.error(f'refusing to replace an unmanaged prefix: {prefix}')
        download = ROOT/'dl/perl'
        download.mkdir(parents=True, exist_ok=True)
        archive = download/spec['url'].rsplit('/', 1)[1]
        if not archive.exists():
            print(f'perl: downloading {spec["version"]}', flush=True)
            with urllib.request.urlopen(spec['url'], timeout=120) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != spec['sha256']:
                raise RuntimeError('Perl download checksum mismatch')
            temporary = archive.with_suffix('.part')
            temporary.write_bytes(data)
            temporary.replace(archive)
        if digest(archive) != spec['sha256']:
            raise RuntimeError('Perl archive checksum mismatch')
        log = prefix.parent/(prefix.name+'.log')
        log.write_bytes(b'')
        with tempfile.TemporaryDirectory(prefix='.perl-build-', dir=prefix.parent) as directory:
            work = Path(directory)
            with tarfile.open(archive) as bundle:
                bundle.extractall(work, filter='data')
            source = work/('perl-'+spec['version'])
            dest = work/'dest'
            install = dest/str(prefix).lstrip('/')
            env = os.environ.copy()
            for key in ('PERL5OPT', 'PERL5LIB', 'PERLLIB', 'PERL_LOCAL_LIB_ROOT',
                        'PERL_MM_OPT', 'PERL_MB_OPT', 'DESTDIR'):
                env.pop(key, None)

            def run(command):
                with log.open('ab') as output:
                    p = subprocess.run(command, cwd=source, env=env,
                                       stdout=output, stderr=subprocess.STDOUT)
                if p.returncode:
                    print(log.read_text(errors='replace')[-8000:])
                    raise RuntimeError(f'Perl build failed ({p.returncode}); see {log}')

            print(f'perl: configuring {spec["version"]} for {target}; log: {log}', flush=True)
            run(['sh', 'Configure', '-des', '-Dprefix='+str(prefix), '-Dcc='+cc,
                 '-Dusemultiplicity', '-Uuseithreads', '-Uuseshrplib',
                 '-Ddynamic_ext=none',
                 '-Doptimize=-O2 -fPIC', '-Uinstallusrbinperl',
                 '-Dman1dir=none', '-Dman3dir=none'])
            print('perl: compiling interpreter and standard modules', flush=True)
            run(['make', '-j'+str(args.jobs)])
            run(['make', 'install', 'DESTDIR='+str(dest)])
            config_program = ('use Config; use JSON::PP; '
                              'print encode_json({map {$_ => $Config{$_}} '
                              'qw(archlib privlib ccflags ldflags libs libperl version static_ext)});')
            config = json.loads(subprocess.check_output(
                [str(source/'perl'), '-Ilib', '-e', config_program], cwd=source, env=env, text=True))
            core = Path(config['archlib'])/'CORE'
            relative_core = core.relative_to(prefix)
            library = install/relative_core/'libperl.a'
            if config['libperl'] != 'libperl.a' or not library.is_file():
                raise RuntimeError('Perl did not install a static libperl.a')
            # Bash exports replacements for the libc environment API that write
            # shell variables. Bind Perl's references to our private copy instead.
            embedded = install/relative_core/'bashperl-libperl.a'
            objcopy = shutil.which(os.environ.get('OBJCOPY', 'objcopy'))
            if not objcopy:
                raise RuntimeError('objcopy is required for the embedding archive')
            remap = [f'--redefine-sym={name}=bos_perl_env_{name}'
                     for name in ('getenv', 'setenv', 'unsetenv', 'putenv', 'clearenv')]
            subprocess.run([objcopy, *remap, str(library), str(embedded)], check=True)
            archives = [embedded]
            extra_libraries = []
            modules = ['DynaLoader', *config['static_ext'].split()]
            header = ['/* Generated from Perl Config by build-perl.py. */']
            body = []
            for module in modules:
                if not re.fullmatch(r'[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*', module):
                    raise RuntimeError(f'invalid static extension name: {module}')
                symbol = 'boot_'+module.replace('/', '__')
                method = module.replace('/', '::') + (
                    '::boot_DynaLoader' if module == 'DynaLoader' else '::bootstrap')
                header.append(f'EXTERN_C void {symbol}(pTHX_ CV *cv);')
                body.append(f'    newXS("{method}", {symbol}, __FILE__);')
                if module == 'DynaLoader':
                    continue
                auto = install/Path(config['archlib']).relative_to(prefix)/'auto'/module
                original = auto/(module.rsplit('/', 1)[-1]+'.a')
                if not original.is_file():
                    # Perl omits some developer/test extension archives from
                    # installation although they are in Config's static set.
                    auto = source/'lib/auto'/module
                    original = auto/(module.rsplit('/', 1)[-1]+'.a')
                    if not original.is_file():
                        raise RuntimeError(f'missing static extension: {original}')
                adapted = install/relative_core/(module.replace('/', '_')+'-bashperl.a')
                subprocess.run([objcopy, *remap, str(original), str(adapted)], check=True)
                archives.append(adapted)
                extra = auto/'extralibs.ld'
                if extra.exists():
                    extra_libraries.extend(extra.read_text().split())
            header += ['static void bos_perl_static_xs_init(pTHX)', '{', *body, '}']
            xs_header = install/relative_core/'bashperl-xs.h'
            xs_header.write_text('\n'.join(header)+'\n')
            linked = ' '.join(str(prefix/p.relative_to(install)) for p in archives)
            # Keep all public Perl entry points for XS modules loaded at runtime.
            flags = dict(cppflags=config['ccflags']+' -I'+str(core),
                         ldflags='-Wl,-E '+config['ldflags'],
                         libraries='-Wl,--whole-archive '+linked+
                                   ' -Wl,--no-whole-archive '+config['libs']+' '+
                                   ' '.join(dict.fromkeys(extra_libraries)))
            checksums = {str(p.relative_to(install)): digest(p)
                         for p in [library, *archives, xs_header, install/relative_core/'perl.h',
                                   install/relative_core/'config.h']}
            record = dict(identity=identity, flags=flags, config=config, checksums=checksums)
            notices = install/'share/licenses/perl'
            notices.mkdir(parents=True)
            for name in ('Copying', 'Artistic', 'README'):
                shutil.copy2(source/name, notices/name)
            record['installation'] = installation_cache.write_manifest(install, marker.name)
            (install/'bash-os-perl.json').write_text(json.dumps(record, indent=2)+'\n')
            backup = work/'previous'
            if prefix.exists():
                prefix.rename(backup)
            try:
                install.rename(prefix)
            except BaseException:
                if backup.exists():
                    backup.rename(prefix)
                raise
        print(f'perl: ready: {prefix}', flush=True)


if __name__ == '__main__':
    main()
