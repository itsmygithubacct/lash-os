#!/usr/bin/env python3
"""Compile the pinned compression and regex libraries as guest LLVM bitcode."""
import sys
sys.dont_write_bytecode = True
import concurrent.futures
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
from runtime import digest, fetch
from workspace import ROOT, BUILD, DOWNLOADS, PATHS, prepare_cmake
WORK = BUILD / 'deps'
PACKAGES = json.loads((ROOT / 'vendor/bash-os/config/dependencies.json').read_text())


def verified_archive(spec):
    """Return a checksum-verified archive; corrupt or partial files are replaced."""
    archive_name = spec['url'].rsplit('/', 1)[1]
    archive = DOWNLOADS / 'deps' / archive_name
    if archive.is_file() and digest(archive) == spec['sha256']:
        return archive
    archive.unlink(missing_ok=True)
    cache = PATHS['source_cache'] / 'deps' / archive_name if PATHS['source_cache'] else None
    if cache and cache.is_file():
        partial = archive.with_name(archive.name + '.partial')
        try:
            shutil.copyfile(cache, partial)
            if digest(partial) == spec['sha256']:
                partial.replace(archive)
                return archive
            print(f'Ignoring source cache with a different checksum: {cache}', flush=True)
        finally:
            partial.unlink(missing_ok=True)
    return fetch(spec['url'], spec['sha256'], archive)


def extracted_source(name, spec, archive):
    """Extract once per archive checksum, so version changes never reuse an old tree."""
    sources = WORK / 'source'
    source = sources / f"{name}-{spec['sha256'][:16]}"
    if not source.is_dir():
        (WORK / 'extract').mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=name + '-', dir=WORK / 'extract') as temporary:
            with tarfile.open(archive) as bundle:
                bundle.extractall(temporary, filter='data')
            children = list(Path(temporary).iterdir())
            if len(children) != 1 or not children[0].is_dir():
                raise SystemExit(f'{name}: unexpected archive layout')
            sources.mkdir(parents=True, exist_ok=True)
            children[0].rename(source)
    for stale in sources.iterdir():
        if stale != source and (stale.name == name or re.fullmatch(re.escape(name) + r'-[0-9a-f]{16}', stale.name)):
            shutil.rmtree(stale)
    return source


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    (DOWNLOADS / 'deps').mkdir(parents=True, exist_ok=True)
    compiler = shutil.which('bpf-capsule-cc')
    ar = shutil.which('llvm-ar')
    if not compiler or not ar: raise SystemExit('run inside scripts/dev.py')
    commands=[]
    for name, spec in PACKAGES.items():
        source = extracted_source(name, spec, verified_archive(spec))
        shutil.rmtree(WORK / 'bitcode' / name, ignore_errors=True)
        build=WORK/'native-config'/name
        build.mkdir(parents=True,exist_ok=True)
        if name=='bzip2':
            files=['blocksort.c','huffman.c','crctable.c','randtable.c','compress.c','decompress.c','bzlib.c']
            commands.extend((name,source/f,['-I'+str(source)]) for f in files)
            continue
        options={
            'pcre2':['-DPCRE2_BUILD_PCRE2GREP=OFF','-DPCRE2_BUILD_TESTS=OFF','-DPCRE2_SUPPORT_JIT=OFF','-DPCRE2_BUILD_PCRE2_16=OFF','-DPCRE2_BUILD_PCRE2_32=OFF'],
            'zlib':['-DZLIB_BUILD_TESTING=OFF','-DZLIB_BUILD_SHARED=OFF','-DZLIB_BUILD_STATIC=ON'],
            'xz':['-DXZ_TOOL_XZ=OFF','-DXZ_TOOL_XZDEC=OFF','-DXZ_TOOL_LZMADEC=OFF','-DXZ_TOOL_LZMAINFO=OFF','-DXZ_TOOL_SCRIPTS=OFF','-DXZ_DOC=OFF','-DBUILD_TESTING=OFF','-DXZ_THREADS=no','-DXZ_CLMUL_CRC=OFF','-DHAVE_IMMINTRIN_H=OFF','-DHAVE_CPUID_H=OFF','-DHAVE__MM_MOVEMASK_EPI8=OFF','-DHAVE_USABLE_CLMUL=OFF'],
            'zstd':['-DZSTD_BUILD_PROGRAMS=OFF','-DZSTD_BUILD_TESTS=OFF','-DZSTD_BUILD_SHARED=OFF','-DZSTD_BUILD_STATIC=ON','-DZSTD_DISABLE_ASM=ON','-DZSTD_MULTITHREAD_SUPPORT=OFF'],
        }[name]
        cmake_source=source/'build/cmake' if name=='zstd' else source
        prepare_cmake(build, cmake_source)
        command=['cmake','-S',str(cmake_source),'-B',str(build),'-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DBUILD_SHARED_LIBS=OFF',*options]
        with (build/'configure.log').open('w') as log:
            subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True)
        seen=set()
        for item in json.loads((build/'compile_commands.json').read_text()):
            src=Path(item['file'])
            if src.suffix!='.c' or src in seen:continue
            if any(part in src.parts for part in ('tests','test','contrib','examples')):continue
            if name=='pcre2' and not src.name.startswith('pcre2_'):continue
            seen.add(src)
            argv=shlex.split(item['command']); flags=[];i=1
            while i<len(argv):
                arg=argv[i]
                if arg in ('-I','-D','-U','-include','-isystem'):
                    flags.extend(argv[i:i+2]);i+=2;continue
                if arg.startswith(('-I','-D','-U','-std=')):flags.append(arg)
                i+=1
            commands.append((name,src,flags))
    failures=[]; objects={}
    def compile_one(item):
        name,src,flags=item
        obj=WORK/'bitcode'/name/(src.stem+'.bc');obj.parent.mkdir(parents=True,exist_ok=True)
        command=[compiler,'-c','-g','-D_GNU_SOURCE','-D__linux__=1','-D__unix__=1',
                 # The build machine's directories must not reach __FILE__ or debug records.
                 f'-ffile-prefix-map={WORK}=/lashos/deps', f'-ffile-prefix-map={ROOT}=/lashos/source',
                 '-fdebug-compilation-dir=/lashos',
                 '-I'+str(ROOT/'include/guest'),'-idirafter',str(ROOT/'vendor/musl-headers'),
                 '-idirafter',os.environ['LINUX_HEADERS'],*flags,str(src),'-o',str(obj)]
        result=subprocess.run(command,capture_output=True,text=True)
        return name,src,obj,result
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for name,src,obj,result in pool.map(compile_one,commands):
            if result.returncode:failures.append({'library':name,'source':str(src),'diagnostic':result.stderr})
            else:objects.setdefault(name,[]).append(obj)
    (WORK/'errors.json').write_text(json.dumps(failures,indent=2)+'\n')
    print(f'Compiled {len(commands)-len(failures)}/{len(commands)} dependency translation units')
    if failures:
        for error in failures[:8]:print(error['source']+'\n'+error['diagnostic'][-3000:])
        raise SystemExit(1)
    libs=WORK/'lib';libs.mkdir(exist_ok=True)
    for name,files in objects.items():
        archive=libs/('lib'+name+'.a');archive.unlink(missing_ok=True)
        subprocess.run([ar,'rcs',str(archive),*[str(p) for p in files]],check=True)
    (WORK/'manifest.json').write_text(json.dumps({'packages':PACKAGES,'objects':{n:len(v) for n,v in objects.items()}},indent=2)+'\n')
if __name__=='__main__':main()
