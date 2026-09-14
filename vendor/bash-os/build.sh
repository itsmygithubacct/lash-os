#!/usr/bin/env bash
# build.sh — build a standalone bash-os: GNU bash with the loadables in
# config/bash-loadables.list compiled in as static builtins, indistinguishable
# from bash's own (`type ls` says "ls is a shell builtin"). No busybox, no
# coreutils, no forks for the commands it covers.
#
# The technique (originally the upstream bash-os build tree's; see
# docs/PROVENANCE.md):
#   1. copy each listed loadable into bash's builtins/, rewriting its relative
#      includes and un-static-ing NAME_builtin / NAME_doc;
#   2. add NAME.o to OFILES in builtins/Makefile.in so it lands in libbuiltins.a;
#   3. after mkbuiltins generates builtins.c / builtext.h, append extern decls
#      and splice rows into shell_builtins[]. bash 5.3 computes num_shell_builtins
#      from sizeof(), so nothing else changes.
#
# Usage: ./build.sh [--profile NAME | --level N | --list FILE]
#                  [--include NAMES] [--include-list FILE] [--exclude NAMES]
#                  [--name TAG] [--static] [--deps-prefix DIR] [--no-strip] [--clean]
# Use --help for selection rules and --list-profiles for available profiles.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); cd "$HERE"
source config/versions.sh
source config/loadables.sh

die(){ echo "build.sh: $*" >&2; exit 1; }
say(){ echo "build.sh: $*"; }
usage(){
  cat <<'HELP'
Usage: ./build.sh [selection] [build options]

Selection (default: --profile full):
  --profile NAME       shell, pure, core, device, server, desktop, full
  --level N            0=shell, 1=pure, 2=core, 3=device, 4=server, 5=full
  --list FILE          exact NAME[|SHORT-DOC] inclusion list, instead of a profile
  --include NAMES      add comma/space-separated names; repeatable
  --include-list FILE  add entries from an inclusion list; repeatable
  --exclude NAMES      remove comma/space-separated names; repeatable
  --name TAG           output as out/bash-TAG (plus -static and target directory)
  --list-profiles      show levels, command counts and descriptions, then exit
  --list-loadables     show available commands and their short help, then exit
  --print-list         print the exact resolved inclusion list, then exit
  --show-config        print the selection, helper and library plan as JSON, then exit

With --include/--include-list alone the base is empty. With an explicit profile
or --list, they add to that base. Exclusions apply last. Required companion
builtins must be selected explicitly. GNU Bash's own builtins are always present.
Customized outputs receive a content-derived name unless --name is supplied.

Build options:
  --static             link a static executable
  --deps-prefix DIR    use target headers and libraries prepared by build-deps.sh
  --no-strip           retain symbols
  --clean              force rebuilding
  --help               show this help
Environment: CC, JOBS, CFLAGS, CPPFLAGS, LOCAL_LIBS, LDFLAGS_EXTRA,
CONFIGURE_EXTRA, BASH_TARBALL, EXTRA_LOADABLES (space-separated source directories).
HELP
}
STATIC=0; STRIP=1; CLEAN=0; DEPS_PREFIX=""; INFO=""; SELECT_ARGS=()
while [[ $# -gt 0 ]]; do case "$1" in
  --*=*) set -- "${1%%=*}" "${1#*=}" "${@:2}" ;;
  --profile|--level|--list|--include|--include-list|--exclude|--name)
    [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "$1 requires an argument"
    SELECT_ARGS+=("$1" "$2"); shift 2 ;;
  --deps-prefix)
    [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "$1 requires a directory"
    DEPS_PREFIX=$(cd "$2" && pwd); shift 2 ;;
  --list-profiles|--list-loadables)
    [[ -z $INFO ]] || die "choose one reporting option"
    SELECT_ARGS+=("$1"); INFO="$1"; shift ;;
  --print-list|--show-config)
    [[ -z $INFO ]] || die "choose one reporting option"
    INFO="$1"; shift ;;
  --static) STATIC=1; shift ;;
  --no-strip) STRIP=0; shift ;;
  --clean) CLEAN=1; shift ;;
  --help|-h) usage; exit 0 ;;
  *) die "unknown argument $1 (see --help)" ;;
esac; done
SELECTION=$(python3 config/loadables.py select --root "$HERE" "${SELECT_ARGS[@]}") || exit $?
export SELECTION
if [[ -n $INFO ]]; then
  python3 - "$INFO" <<'PYINFO'
import json, os, sys
s = json.loads(os.environ['SELECTION'])
if sys.argv[1] == '--list-profiles':
    print('PROFILE    LEVEL  BUILTINS  PURPOSE')
    for p in s: print(f"{p['name']:<10} {p['level']:<6} {p['count']:<9} {p['description']}")
elif sys.argv[1] == '--list-loadables':
    for name, doc in s.items(): print(name+'|'+doc)
elif sys.argv[1] == '--print-list': print(s['list'], end='')
else: print(json.dumps(s, indent=2))
PYINFO
  exit 0
fi
NAMES_TEXT=$(python3 -c 'import json,os; print("\n".join(json.loads(os.environ["SELECTION"])["names"]))')
NAMES=(); [[ -z $NAMES_TEXT ]] || mapfile -t NAMES <<< "$NAMES_TEXT"
LISTTAG=$(python3 -c 'import json,os; print(json.loads(os.environ["SELECTION"])["tag"])')
LIST_DESCRIPTION=$(python3 -c 'import json,os; print(json.loads(os.environ["SELECTION"])["base"])')
CC="${CC:-cc}"; JOBS="${JOBS:-$(nproc)}"
DL="$HERE/dl"; SRC="$HERE/build/bash-$BASH_SRC_VERSION"

# --- target and output naming ----------------------------------------------
TARGET=$("$CC" -dumpmachine 2>/dev/null) || die "cannot run CC=$CC"
HOSTM=$(cc -dumpmachine 2>/dev/null || echo "$TARGET")
CROSS=0; [[ "$TARGET" != "$HOSTM" || "${CONFIGURE_EXTRA:-}" == *--host=* ]] && CROSS=1
NAME="bash${LISTTAG:+-$LISTTAG}"; [[ $STATIC == 1 ]] && NAME="$NAME-static"
OUTDIR="$HERE/out"; [[ $CROSS == 1 ]] && OUTDIR="$HERE/out/$TARGET"
OUTBIN="$OUTDIR/$NAME"; LOG="$OUTBIN.log"; STAMPFILE="$OUTBIN.stamp"; MANIFEST="$OUTBIN.manifest.txt"
STRIPTOOL=strip; [[ "$CC" == *-gcc ]] && STRIPTOOL="${CC%-gcc}-strip"

# Hardened by default; a consumer overrides CFLAGS/LDFLAGS_EXTRA wholesale.
CFLAGS="${CFLAGS:--O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2}"
LDFLAGS="-Wl,--build-id=none -Wl,-z,relro -Wl,-z,now ${LDFLAGS_EXTRA:-}"; [[ $STATIC == 1 ]] && LDFLAGS="-static $LDFLAGS"
CPPFLAGS="${CPPFLAGS:-}"
if [[ -n $DEPS_PREFIX ]]; then
  [[ $DEPS_PREFIX != *[[:space:]]* ]] || die "--deps-prefix cannot contain whitespace"
  [[ -d $DEPS_PREFIX/include && -d $DEPS_PREFIX/lib ]] || die "dependency prefix needs include/ and lib/"
  CPPFLAGS="$CPPFLAGS -I$DEPS_PREFIX/include"
  LDFLAGS="$LDFLAGS -L$DEPS_PREFIX/lib"
fi
# LOCAL_LIBS is bash's own hook for libraries the injected builtins pull in:
# fltexpr needs libm, so -lm by default (a consumer adds e.g. -lz).
LOCAL_LIBS="${LOCAL_LIBS:--lm} $(python3 config/stage-helpers.py --libs "$HERE" - "${NAMES[@]}")"
# A cross configure cannot run test programs; these are the Linux answers.
CROSS_CACHE=(bash_cv_getcwd_malloc=yes bash_cv_job_control_missing=present
  bash_cv_sys_named_pipes=present bash_cv_func_sigsetjmp=present bash_cv_printf_a_format=yes
  bash_cv_ulimit_maxblocks=yes bash_cv_unusable_rtsigs=no bash_cv_wcwidth_broken=no
  bash_cv_dev_fd=standard bash_cv_dev_stdin=present)
CFGX=(); if [[ $CROSS == 1 ]]; then CFGX=("${CROSS_CACHE[@]}"); [[ "${CONFIGURE_EXTRA:-}" == *--host=* ]] || CFGX+=("--host=$TARGET"); fi

# Stamp: a hash of every input, so an unchanged rebuild is a no-op.
mkdir -p "$OUTDIR" "$DL" build
exec {BUILD_LOCK}> "$HERE/build/.lock"
flock "$BUILD_LOCK"
STAMP=$( { echo "$BASH_SRC_SHA256 ${BASH_PATCHES[*]} $BASH_PATCHLEVEL static=$STATIC strip=$STRIP cc=$CC target=$TARGET cflags=$CFLAGS cppflags=$CPPFLAGS ldflags=$LDFLAGS local_libs=$LOCAL_LIBS extra=${CONFIGURE_EXTRA:-}";
           printf '%s\n' "$SELECTION"; "$CC" --version;
           cat config/helpers.json config/profiles.json config/loadables.py config/stage-helpers.py config/publish-binary.py build.sh patches/head-stdin.patch patches/tee-io.patch;
           [[ -z $DEPS_PREFIX ]] || find "$DEPS_PREFIX/include" "$DEPS_PREFIX/lib" -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum;
           find loadables ${EXTRA_LOADABLES:-} -type f \( -name '*.c' -o -name '*.h' -o -name '*.data' \) -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum; } | sha256sum | cut -c1-64)
if [[ "$CLEAN" != 1 && -f "$OUTBIN" && -f "$STAMPFILE" && "$(cat "$STAMPFILE")" == "$STAMP" ]]; then
  say "up to date — $OUTBIN (pass --clean to force)"; exit 0
fi
: > "$LOG"

# --- 1. bash source and its patch set, pinned by sha256 --------------------
TARBALL="$DL/bash-$BASH_SRC_VERSION.tar.gz"
if [[ ! -f "$TARBALL" ]]; then
  if [[ -n "${BASH_TARBALL:-}" ]]; then cp "$BASH_TARBALL" "$TARBALL"
  else say "downloading $BASH_URL"; curl -fL -o "$TARBALL" "$BASH_URL"; fi
fi
echo "$BASH_SRC_SHA256  $TARBALL" | sha256sum -c - >/dev/null || die "bash tarball sha256 mismatch"
mkdir -p "$DL/patches"
for entry in "${BASH_PATCHES[@]}"; do
  pname=${entry%% *}; psha=${entry##* }; pfile="$DL/patches/$pname"
  [[ -f "$pfile" ]] || { say "downloading $pname"; curl -fL -o "$pfile" "$BASH_PATCH_URL/$pname"; }
  echo "$psha  $pfile" | sha256sum -c - >/dev/null || die "$pname sha256 mismatch"
done

# --- 2. fresh tree in a staging dir, swapped in at the end (atomic) --------
STAGE_PARENT=$(mktemp -d "$HERE/build/.stage.XXXXXX"); trap 'rm -rf "$STAGE_PARENT"' EXIT
tar xzf "$TARBALL" -C "$STAGE_PARENT"
STAGE="$STAGE_PARENT/bash-$BASH_SRC_VERSION"; [[ -d "$STAGE" ]] || die "tarball did not unpack as expected"
cd "$STAGE"
for entry in "${BASH_PATCHES[@]}"; do
  pname=${entry%% *}
  patch -p0 -s < "$DL/patches/$pname" >>"$LOG" 2>&1 || die "$pname did not apply (see $LOG)"
done
pl=$(awk '$1=="#define" && $2=="PATCHLEVEL" {print $3}' patchlevel.h)
[[ "$pl" == "$BASH_PATCHLEVEL" ]] || die "patchlevel $pl after patching, expected $BASH_PATCHLEVEL"

# --- 3. stage the loadable sources + helper headers ------------------------
say "staging loadables"
cp "$HERE/loadables"/*.c examples/loadables/
shopt -s nullglob
for h in "$HERE"/loadables/common/*.h; do cp "$h" builtins/; cp "$h" examples/loadables/; done
python3 "$HERE/config/stage-helpers.py" --stage "$HERE" "$STAGE" "${NAMES[@]}" >>"$LOG" 2>&1 || die "helper staging failed (see $LOG)"
for d in ${EXTRA_LOADABLES:-}; do
  d=$(cd "$OLDPWD" 2>/dev/null && cd "$HERE" && cd "$d" && pwd) || die "EXTRA_LOADABLES: no such directory: $d"
  for f in "$d"/*.c; do cp "$f" examples/loadables/; done
  for f in "$d"/*.h; do cp "$f" builtins/; cp "$f" examples/loadables/; done
done
shopt -u nullglob
cp examples/loadables/*.h builtins/ 2>/dev/null || true

# --- 4. the injected set: into builtins/ with include fixups + un-static ----
# The per-name fixups below patch bash's OWN example loadables (mkdir,
# fltexpr). A source this repo or EXTRA_LOADABLES supplies under the same
# name replaces the stock file whole and must not be patched.
is_stock() { [[ ! -f "$HERE/loadables/$1.c" ]] || return 1; local d; for d in ${EXTRA_LOADABLES:-}; do [[ -f "$d/$1.c" ]] && return 1; done; return 0; }
say "injecting ${#NAMES[@]} loadables ($NAME, $TARGET)"
for n in "${NAMES[@]}"; do
  src="examples/loadables/$n.c"; [[ -f "$src" ]] || die "no source for '$n' ($src) — neither loadables/$n.c nor a stock example"
  sed -e 's|#include "builtins.h"|#include "../builtins.h"|' \
      -e 's|#include "shell.h"|#include "../shell.h"|' \
      -e 's|#include "bashansi.h"|#include "../bashansi.h"|' \
      -e 's|#include "arrayfunc.h"|#include "../arrayfunc.h"|' \
      -e 's|#include "array.h"|#include "../array.h"|' \
      -e "s|^static \\(int ${n}_builtin\\)|\\1|" \
      -e "s|^static \\(char \\*${n}_doc\\)|\\1|" \
      "$src" > "builtins/$n.c"
  is_stock "$n" || continue
  case "$n" in
    head)
      patch --batch -s builtins/head.c < "$HERE/patches/head-stdin.patch" >>"$LOG" 2>&1 || die "head fixup did not apply (see $LOG)" ;;
    tee)
      patch --batch -s builtins/tee.c < "$HERE/patches/tee-io.patch" >>"$LOG" 2>&1 || die "tee fixup did not apply (see $LOG)" ;;
    fltexpr)
      sed -i 's|^static sh_float_t nanval, infval;$|static sh_float_t nanval = NAN, infval = INFINITY;|' builtins/fltexpr.c
      grep -q 'nanval = NAN' builtins/fltexpr.c || die "fltexpr fixup did not match" ;;
    mkdir)
      python3 - <<'PYMK'
from pathlib import Path
p = Path("builtins/mkdir.c"); t = p.read_text()
t = t.replace("  int tail;\n", "  int tail, created;\n")
t = t.replace("      if (mkdir (npath, 0) < 0)\n", "      created = 0;\n      if (mkdir (npath, 0) == 0)\n\tcreated = 1;\n      else\n")
t = t.replace("      if (chmod (npath, (tail == 0) ? parent_mode : nmode) != 0)\n", "      if (created && chmod (npath, (tail == 0) ? parent_mode : nmode) != 0)\n")
p.write_text(t)
PYMK
      grep -q 'created && chmod' builtins/mkdir.c || die "mkdir fixup did not match" ;;
  esac
done

# --- 5. OFILES in builtins/Makefile.in -------------------------------------
python3 - <<'PY'
import os, json
from pathlib import Path
p = Path("builtins/Makefile.in"); s = p.read_text()
old = "OFILES = builtins.o \\\n"
assert s.count(old) == 1, "OFILES anchor not found"
p.write_text(s.replace(old, "OFILES = builtins.o " + ''.join(n+'.o ' for n in json.loads(os.environ['SELECTION'])['names']) + Path("builtins/.helper-objs").read_text() + "\\\n", 1))
PY

# --- 6. configure ----------------------------------------------------------
say "configure"
./configure --disable-nls --without-bash-malloc ${CONFIGURE_EXTRA:-} "${CFGX[@]}" \
    CC="$CC" CFLAGS="$CFLAGS" CPPFLAGS="$CPPFLAGS" LDFLAGS="$LDFLAGS" LOCAL_LIBS="$LOCAL_LIBS" \
    >>"$LOG" 2>&1 || { tail -30 "$LOG"; die "configure failed (see $LOG)"; }
echo "$BASH_BUILD_NUMBER" > .build      # pin the build counter

# --- 7. mkbuiltins, then splice our builtins into the generated table ------
say "mkbuiltins"
make -C builtins builtins.c >>"$LOG" 2>&1 || { tail -30 "$LOG"; die "mkbuiltins failed"; }
{
  echo "/* bash-os loadables injected */"
  for n in "${NAMES[@]}"; do echo "extern int ${n}_builtin (WORD_LIST *);"; echo "extern char * const ${n}_doc[];"; done
} >> builtins/builtext.h
python3 - <<'PYTABLE'
import json, os
from pathlib import Path
entries = json.loads(os.environ['SELECTION'])['entries']
p = Path('builtins/builtins.c'); text = p.read_text()
anchor = '  { (char *)0x0,'
assert text.count(anchor) == 1, 'builtin table anchor not found'
rows = ''.join('  { '+json.dumps(n)+', '+n+'_builtin, BUILTIN_ENABLED, '+n+'_doc, '
               +json.dumps(doc, ensure_ascii=False)+', 0 },\n' for n, doc in entries.items())
p.write_text(text.replace(anchor, rows+anchor))
PYTABLE

# --- 8. build --------------------------------------------------------------
say "make -j$JOBS"
make -j"$JOBS" >>"$LOG" 2>&1 || { grep -nE 'error|Error' "$LOG" | tail -30; die "make failed (see $LOG)"; }
[[ -f bash ]] || die "no bash binary"

# --- 9. output + manifest --------------------------------------------------
STRIP_ARGS=(); [[ $STRIP != 1 ]] || STRIP_ARGS=("$STRIPTOOL")
python3 "$HERE/config/publish-binary.py" bash "$OUTBIN" "${STRIP_ARGS[@]}"
{
  echo "# bash-os manifest  $(date -u +%FT%TZ)"
  echo "bash $BASH_SRC_VERSION patchlevel $BASH_PATCHLEVEL  target=$TARGET static=$STATIC stripped=$STRIP"
  echo "cc=$($CC --version | head -1)"
  echo "cflags=$CFLAGS"
  echo "selection=$LIST_DESCRIPTION"
  echo "injected builtins (${#NAMES[@]}): ${NAMES[*]}"
  ( cd "$OUTDIR" && sha256sum "$NAME" && wc -c "$NAME" )
} | tee "$MANIFEST"
python3 - "$OUTBIN" "$TARGET" "$STATIC" "$STRIP" <<'PYMANIFEST'
import hashlib, json, os, sys
from pathlib import Path
p = Path(sys.argv[1]); selection = json.loads(os.environ['SELECTION'])
selection.update(target=sys.argv[2], static=sys.argv[3]=='1', stripped=sys.argv[4]=='1',
                 binary_sha256=hashlib.sha256(p.read_bytes()).hexdigest(), bytes=p.stat().st_size)
p.with_name(p.name+'.loadables.list').write_text(selection['list'])
p.with_name(p.name+'.manifest.json').write_text(json.dumps(selection, indent=2)+'\n')
PYMANIFEST
echo "$STAMP" > "$STAMPFILE"

# --- 10. swap the finished tree into place: two renames, no gap ------------
cd "$HERE"; rm -rf "$SRC.old"; [[ -d "$SRC" ]] && mv "$SRC" "$SRC.old"; mv "$STAGE" "$SRC"; rm -rf "$SRC.old"
say "done: ${OUTBIN#$HERE/}  ($(wc -c < "$OUTBIN") bytes, ${#NAMES[@]} injected builtins)"
