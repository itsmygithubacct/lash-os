# Provenance

## Sources

bash-os is assembled from these sources:

- **GNU bash 5.3** (GPL-3.0-or-later), pinned by sha256 in `config/versions.sh`
  and fetched at build time. Its own `examples/loadables/*.c` supply the stock
  builtins a list names but this repo does not carry (`cat`, `chmod`, `head`, …
  — the pure list except for the MIT replacements described below).
- **An upstream bash-os loadables collection** (MIT, "bash_linux contributors").
  The busybox-replacement loadables — `ls cp mv find sed sort grep ip ps pax`
  and the rest — and the injection technique originate there. This repo carries
  a curated subset, with the injector-visible symbols renamed from `bashNAME` to
  the real command name so an empty-`PATH` script resolves them.
- **Loadables written for the `lichee-nano-bashos` appliance** (MIT), generic
  enough to belong here: `httpd` (an HTTP server primitive), `rngseed` (credits
  a saved kernel random seed), `rtspcat` (an RTSP/RTP H.264 client),
  `reboot`/`halt`/`poweroff`/`chown`/`chgrp`.
- **Written for bash-os** (MIT): `stat`, a clean-room implementation of the
  GNU coreutils stat(1) surface (format directives, default and terse layouts,
  `--printf`, `-L`, birth time via statx) plus a small `-A NAME` array load.
  `tests/stat-parity.sh` holds it to byte-identical output with coreutils 9.7.
  It replaces bash's own GPL stat loadable in every variant, including the
  pure list.
- **Written for bash-os** (MIT): `cut`, the coreutils cut(1) surface — `-b`,
  `-c` (bytes, as GNU's), `-f`, `-d`, `-s`, `-z`, `--complement`,
  `--output-delimiter` (empty means NUL), the long options and their
  prefixes, options after the operands, the range-list grammar and every
  one of its errors, and the whole input as one record when the delimiter
  is the line delimiter (`cut -d $'\n' -f2`) — reading in 64 KB blocks with
  `memchr`, plus the `-a ARRAY` extension that bash's own loadable
  documents. `tests/cut-parity.sh` holds it to byte-identical output and
  status with coreutils 9.7, including unterminated `-z` records. It
  replaces bash's GPL cut loadable in every variant,
  including the pure list: on a 423 KB file the stock one took 8 ms per
  pass, GNU's 2.4 ms, this 1 ms.
- **Written for bash-os** (MIT): `seq`, a clean-room implementation of the GNU
  coreutils seq(1) surface — `[-w] [-s STRING] [-f FORMAT] [FIRST [INCREMENT]]
  LAST`, the precision and equal-width rules, the value one step past LAST
  that rounds to it, the same exit status on a bad number, a zero step or a
  bad format. Integers are counted on a decimal string and written a 64 KB
  block at a time, which is what makes `for i in $(seq N)` fast; floats go
  through the printf format coreutils would use. `tests/seq-parity.sh` holds
  it to byte-identical output and exit status with coreutils 9.7. It replaces
  bash's own GPL seq loadable in every variant, including the pure list.
- **Written for bash-os** (MIT): `zstd` and `zstdcat`, the subset of zstd(1) a
  script uses, using the linked libzstd so compression also works in static
  executables. `BASHOS_ZSTD_LIB` optionally loads a compatible shared library
  at first use; an unavailable override fails cleanly. The implementation
  uses zstd(1)'s file semantics:
  the source is kept unless `--rm`, no overwrite without `-f`, the target
  takes the source's mode and mtime. `tests/zstd-check.sh` checks it against
  the host's zstd both ways; `tests/zstd-host.c` runs the buffer paths under
  the sanitizers.

## Licences, file by file

| Files | Licence |
|---|---|
| command sources and `loadables/common/` | MIT (`LICENSE`) |
| `_ptybroker` native client and service | MIT, original project code |
| `_jsmn`, `_bl_key`, `_bl_screen`, `_bl_proc`, `_tomlc17` helpers | MIT, per-tree notices |
| `_libgrapheme` | ISC, per-tree notice |
| `_sqlite` | Public domain, upstream disclaimer retained |
| `_mbedtls` | Apache-2.0, selected from the upstream dual licence |
| `_libssh` | LGPL-2.1, source notices retained |
| `_monocypher` | BSD-2-Clause OR CC0-1.0 |
| `_sha1dc`, `_bashauth`, `_bashos_authcrypto`, `_stb` | MIT, per-tree notices |
| `_md4` | Public-domain dedication with BSD fallback notice |
| `_tree_sitter` | MIT with Unicode/ICU notices for bundled Unicode headers |
| `_ts_bash`, `_ts_json`, `_ts_toml`, `_ts_markdown`, `_ts_markdown_inline` | MIT, per-grammar notices |
| `tests/*.c`, `build.sh`, `config/` | MIT |
| `patches/head-stdin.patch` (adaptation of Bash's stock head) | GPL-3.0-or-later |

The project sources carry an MIT marker. Vendored helpers retain their original
notices and are registered in `config/helpers.json`; `tests/licence-check.sh`
checks all C/header/data files and rejects unregistered helper trees. The
combined executable remains governed by Bash's GPL-3.0-or-later licence.

## The util-linux family (imported 2026-09-06)

Twenty-five loadables taken from the upstream collection in one batch, renamed
`bashNAME` → `NAME` where prefixed (injector-visible symbols and the command
name in its own strings; internal helpers keep their names), each given an
SPDX line:

`flock setsid ionice blockdev ipcmk ipcctl chattr lsattr mkswap swapon swapoff
wipefs fincore fsfreeze losetup dmsetup getfacl setfacl fstrim prlimit hwclock
renice taskset chrt uclampset`

All plain libc plus Linux headers: no helper tree, no external library, no new
build dependency. `flock` is the one that most wants to be a builtin — `flock -x 9`
locks the descriptor the calling shell opened with `exec 9>lockfile`, which a
forked `flock` cannot do. Fixed on the way in, both found by checking against
the host's util-linux and by `gcc -fanalyzer`:

- `ionice`: a query printed the bare class name for `none` as well as `idle`;
  util-linux prints the priority for every class but `idle` (`none: prio 0`).
- `hwclock`: the adjtime writer skipped its `fclose` when the `fprintf` failed,
  leaking the stream on that path.

Known differences from util-linux, left as they are (these are subsets, not
reimplementations): `lsattr` shows fewer attribute flags, `fincore` and
`prlimit` lay their columns out differently, and `ipcctl` refuses removals by
default policy. `tests/util-linux-smoke.sh` covers what can be exercised
without privilege or destroying anything, and compares `ionice`, `taskset` and
`chrt` against the host's tools.

## The text and formatting tools (imported 2026-09-06)

Nineteen more from the same collection, in one batch, same rename and SPDX
treatment: `expand unexpand split csplit join pr tac column col colrm expr
hexdump tput tinfo strings ed ar uuencode uudecode`. `column.c` registers
three commands (`column`, `col`, `colrm`) and its two companion files exist
only so the build finds a source at each name. Five of them shipped an extra
alias struct for the unprefixed name, which the rename turned into a
duplicate definition; the redundant copy is dropped.

`tests/text-tools-parity.sh` byte-compares 22 invocations against the host's
coreutils and util-linux (all identical), round-trips `uuencode`/`uudecode`
both ways, and checks the host's `ar` can read an archive this `ar` wrote.
`tput` carries a curated capability table (`xterm`, `screen`, `tmux`,
`linux`, `vt100`, `dumb`) with a side-file path for anything else; an
unlisted `TERM` is a clean exit 3, which the test pins.

Fixed on the way in, all found by `gcc -fanalyzer` and all crash-on-
allocation-failure paths of the kind the earlier `diff` fix addressed:
`tac` grew three arrays with unchecked `realloc` and then indexed them,
`csplit` dereferenced an unchecked `calloc`/`malloc` and leaked its pattern
array on five error paths, and `expr` wrote into an unchecked `malloc` in
its substring operator. The remaining analyser reports in this batch are
false positives: a `FILE *` held past a `!= stdin` guard, and `memcpy` from
a buffer `fread` filled.

## The process and system tools (imported 2026-09-07)

Eighteen further MIT sources from the same collection: `who w uptime lsof
timeout signal hostid sysctl dmesg genl mlock utmp userdb keyctl caps cred ns
xattr`. The shared privilege-drop header is MIT and contains inline helpers.
The command names and references between imported loadables lose the upstream
`bash` prefix; persistent state and configuration variable names are retained.

`timeout` uses the existing child-dispatch helper so enabled builtins work
with an empty `PATH`, and restores the signal mask on a wait failure. The
batch test checks queries, child status and timeout handling, temporary utmp
records and extended attributes. Privileged host settings are not changed.
These remain the upstream subsets: `dmesg` reads `/dev/kmsg`, and `userdb
verify` needs the later password loadable. `hostid` prints `gethostid(3)`
like `hostid(1)`; `BASHHOSTID_MACHINE_ID_PATH` is a test override. Help and
registration are checked for every imported name.

## What deliberately stays out

The appliance's four board-coupled managers — `bashnpu`, `bashyolox`,
`bashrtsp`, `detectlog` — depend on NPU/video/detection ABIs and remain in that
project. bash-os is the board-agnostic layer it builds on.

## Local adaptations

Fixes to stock loadables, applied at build time in `build.sh` so the pinned
sources stay as taken:

- `head`: [a tracked patch](../patches/head-stdin.patch) gives redirected stdin
  a private stream, restores unread seekable input, avoids pipe read-ahead and
  propagates I/O errors. The upstream copyright and GPL header are preserved;
  [behavior and validation](https://github.com/itsmygithubacct/bash-os/blob/fa178afafddfce8ee870975a38a7f271b25140a9/docs/head-sed.md) document the remaining option limits.
- `mkdir -p`: only `chmod` the components it actually created, not existing
  parents.
- `fltexpr`: initialise NaN/Inf at compile time (its runtime `_builtin_load`
  hook never fires for a static builtin). Needs `libm`, linked via `LOCAL_LIBS`.

Changes carried in the sources, noted there:

- `ip`: `link set IFNAME address MAC` added (an `IFLA_ADDRESS` attribute on the
  existing `RTM_NEWLINK` request); the collection's version implements only
  `up|down|mtu`.
- `grep`: rewritten around a block reader. The input is read in 96 KB blocks
  and searched a block at a time: a pattern with no regex operator (or `-F`)
  by a memchr scan for its rarest byte and a compare, a regular expression
  by a literal every match must contain, found the same way, with `regexec`
  run only on the lines that carry it, or by one `regexec` over the block
  when no match can hold a newline; line numbers are counted only for `-n`,
  `-B` context is read back out of the block, and output is buffered (bash
  line-buffers stdout, a write per line). The default dialect is GNU's BRE
  compiled as BRE (`\| \+ \? \{ \}` are operators, `+ ? { } |` literal)
  and `-E` is ERE; the previous version compiled every pattern as ERE with
  a paren swap, so `foo\|bar` and `[0-9]\+` never matched and `a+` was a
  quantifier. Reproduced from grep 3.11: `-w` retrying a shorter match at
  the same place and then the next start, `-x`, `-m` with its trailing
  context, the empty-pattern cases, binary files (NULs then separate lines,
  output goes quiet, "binary file matches" on stderr), a printed line that
  is not valid in the locale's encoding, `-z`, `-f -`, patterns split at
  newlines, `-q`'s exit status, and stdin left just after the last match
  for `-m` or at its end when grep stopped early. PCRE2 (`-P`) stays behind
  `BASHGREP_PCRE2` (default 0) so no libpcre2 is needed. Not reproduced:
  `--color` (accepted, no color), and `.` matching a NUL byte under `-a`
  (glibc's `.` never matches NUL). Where the C library has no
  `REG_STARTEND` (musl, so every cross build), a part of a line is matched
  by terminating it in place, and a pattern that has to reach across an
  embedded NUL under `-a` does not match there; measured by forcing that
  path on the host, it is the only difference of the 574.
  `tests/grep-parity.sh` holds it to GNU grep on those 574 command lines in
  a UTF-8 and in the C locale, and `tests/grep-host.c` runs them again
  under ASan+UBSan.
- `pax`: the collection's `bashpax.c`, renamed; plain libc ustar list, create,
  extract and copy with PAX and GNU long-name headers read and `..` rejected.
  Fixed here: bodies were skipped with `fseek`, which fails on a pipe, so
  `cat x.tar | pax -r` lost every member after the first; a member is now
  written to a fresh file rather than through whatever sits at its name (a
  pre-existing symlink was followed); a PAX `size` beyond `long` no longer
  wraps into a backwards seek; and a full-length 257-byte ustar name is no
  longer truncated. Writing: a size above 8 GiB or a uid/gid above 2097151
  used to be silently truncated in the ustar field; it now goes into a PAX
  extended header (the reader already honoured them) and the field is
  clamped, never garbage.
- `cp`: a device, fifo or socket destination is written into, as coreutils
  does (`cp file /dev/null`); it used to be refused. Copying onto a symlink
  that points back at the source truncated the source before the same-file
  check: it now opens without truncating, compares the open descriptors'
  inodes, then truncates (contributed with `tests/regressions.py`).
- `diff`: the line-table growth is checked; out of memory is an error, not a
  crash.
- `wc`: a block-reading path for every call without `-m`/`-L` (lines by
  `memchr`, words by a byte state machine that knows the UTF-8 Unicode
  spaces), contributed from the appliance where the decoding loop took
  261 ms on a 423 KB file; now at the speed of the read. Adjusted here: a
  space sequence consumed past the block edge is not rescanned; the
  non-breaking set is U+00A0, U+2007, U+202F, U+2060 and is off under
  `POSIXLY_CORRECT`, as GNU's; in a unibyte locale only the byte 0xA0 joins
  the separators. The `-m`/`-L` path was rewritten to GNU's rules too: an
  invalid byte is a word character but not a character and has no width,
  decoding resumes at the next byte, an incomplete sequence at end of file
  is dropped, only printable characters have width, and CR and FF end a
  line's length. Output columns follow GNU's order (chars before bytes).
  `tests/wc-tail-parity.sh` holds it to byte-identical output with
  coreutils 9.7 in both the C and a UTF-8 locale.
- `tail`: `-n N` on a seekable file reads from the end in 8 KB blocks
  (contributed from the appliance: 3.2 ms to 0.63 ms for `tail -n 1` of an
  89 KB log); the ring buffer remains for pipes. Adjusted here: it never
  looks before the offset the stream was at when called, so a partial read
  followed by `tail` behaves as GNU's does.
- `sort`: the comparison keys are computed once per line, not on every
  comparison, and a numeric key is decomposed the way GNU `sort -n` reads
  it -- leading blanks, an optional `-`, digits and one decimal point,
  compared as digit strings of unbounded precision, anything else being
  zero -- where the collection's version ran `strtod` on both sides of every
  comparison (so `1e5`, `0x10`, `+5` and `inf` sorted as numbers, and two
  20-digit integers could tie). The sort permutes a 16-byte array of an
  order-preserving 64-bit prefix of the first key and a line pointer, the
  input is read whole and split in place, and output is written through one
  buffer. `-k`/`-t` keys follow GNU's `begfield`/`limfield`: a field's
  leading blanks belong to it, `-kN` alone runs to the end of the line, a
  `b` after the comma affects only the key's end, a key with letters of its
  own takes no global option (so `sort -r -k2n` is ascending), and `-u`
  keeps input order among equal keys instead of tie-breaking on the whole
  line. `-c` uses the whole order and treats equal keys as disorder under
  `-u`; `-m` picks by the whole order. `tests/sort-parity.sh` holds it to
  identical output and exit status with coreutils 9.7 in the C and a UTF-8
  locale.
- `bashjson`: a duplicate-key check freed its index array and then read the
  return value from it.
- `bashdhcp`: the lease-binding helper treated a null `bind_assoc_variable`
  result as success (the callers ignore the value, so no visible effect).

## Network and protocol helpers

The MIT upstream collection also supplies `nc`, `pkt`, `http`, `pcap`,
`dhcp6`, `dhcpd6`, `sftp`, `scp`, `audit`, and `fail2ban`. The shared DHCPv6
HMAC-MD5 header retains its public-domain origin notice. Public builtin names
use the same unprefixed convention as the other imports.

`tests/network-smoke.py` checks framing, malformed records, temporary lease
and ban databases, and transfers over loopback. The transfer clients speak
the collection's native command-stream protocol by default. `--openssh`
uses an installed OpenSSH client; the two transports have different wire
formats. The subprocess helper drains stdout and stderr while feeding stdin
and closes partially created pipes on errors. Tests cover a large diagnostic
before output and repeated failures under a low descriptor limit.

The import fixes HTTP response termination and output-close error handling.
The analyzer's remaining fail2ban null warnings require a positive row count
with a null allocation, which its bounded reader cannot return. Its remaining
sftp reports assume negative descriptors after successful pipe creation or a
successful allocation returning null; both paths were reviewed.

## Small utilities and file identification

A further 21 MIT collection sources supply `totp scrub bignum tz locale scm
notify cluster at batch crontab payload fsck mkfs lpr opt cal man apropos
whatis file`; `asort` comes from Bash's stock examples at build time.
`tests/misc-smoke.py` compares arbitrary-precision arithmetic with Python,
checks option quoting against getopt, exercises descriptor passing and Unix
notifications, and uses private temporary scheduling and filesystem fixtures.
The crontab importer now closes its output even when the input read fails.

The file identifier's private-key magic prefixes are adjacent C literals on
separate lines. Their compiled bytes are unchanged; marker-only fixtures test
all five signatures. No key material is included. The sources retain the
collection's scope: fsck checks the primary superblock, mkfs writes minimal
ext2, lpr simulates spool processing, and timezone support uses a curated
zone table. TOTP delegates HMAC to the crypto builtin. Payload installation
expects the appliance's installer, with explicit environment overrides.

## Terminal, input and editing primitives

Eighteen further MIT sources supply `pty expect termpixel termpixel_pong
escdelay fifo kgetch wgetch wget_wch mouse script buf undo clip nano2 watch
wall write`. The shared renderer header is `common/termpixel.h`; `write` is
a registration companion to `wall`. Buffer, undo and clipboard helpers are
linked together. The piece-table module `nano2` exposes its engine self-test;
it is separate from the interactive editor.

Pseudo-terminal spawning, recording and watch now run enabled builtins in
isolated children, so these paths work with an empty PATH. External commands
still use exec. The buffer/undo import bounds allocation growth and avoids
null pointers in zero-length copies when a grouped edit restores an empty
line. Normal and ASan/UBSan runs execute `tests/terminal-smoke.py`; the
sanitizer run instruments the loadables through shared objects. Leak checking
is disabled for the hosting shell's retained allocations. Analyzer reports
for retained undo stacks, bounded renderer buffers and child stdio descriptors
were reviewed; the latter descriptors deliberately survive until child exit.

## Larger standalone tools (imported 2026-09-07)

`awk jq bc vec sv cron curl fw dhcpd fdisk strace coreutils bsdgames` come
from the same MIT collection. Each has a separate case group in
`tests/large-smoke.py`; the complex parsers also run as ASan/UBSan runtime
loadables through `tests/large-sanitize.sh`. The checks compare supported
text/calculator operations with host tools, validate vector persistence and
GPT checksums independently, and exercise private services, loopback HTTP,
DHCP packets, child tracing, temporary installation/FIFO/shred operations,
and deterministic game checks.

Import fixes include checked allocation and input errors in awk, temporary
argument ownership in coreutils, compact JSON emission and whitespace around
scalar jq inputs, preserved decimal literal scale and fractional output in
bc, and empty command arguments in the trek game parser. GCC's analyzer
completed for twelve sources; its coreutils run crashed, so Clang's analyzer
was used for that file. Remaining reports concern a buffer filled by fread,
a stream protected by a `!= stdin` close guard, and unused assignments.

These are the upstream subsets. jq uses compact output and a bounded filter
language; bc has no user-defined functions or output-base conversion; fw's
pure backend stores rules without installing kernel filters. curl's TLS path
requires the crypto loadable. Tests exercise nft/iptables dry runs only.

## Helper libraries and their consumers (imported 2026-09-07)

The key, screen, and slab helpers are MIT components of the upstream collection.
The TOML parser is tomlc17 R260517 (commit cb9bba39f2e63a9e67fa61d6c7521a184eb5fc38),
SQLite is the public-domain 3.47.2 amalgamation (Fossil 2aabe05e2e8cae4847a802ee2daddc1d7413),
and libgrapheme carries its ISC notice and generated Unicode 17.0.0 tables.
Only build inputs and notices are included; the Unicode generation corpus is
not required to rebuild these already-generated tables.

`config/stage-helpers.py` selects helper dependencies for the requested list,
flattens their includes, and adds their objects to the builtin archive. The
same manifest selects external libraries. The full build now needs development
libraries for PCRE2, zlib, liblzma, libzstd, and bzip2; static builds also need
their static archives. The pure list still needs only its original libraries.
The builtin archive is revisited in a linker group for circular helper calls.

These imports expose upstream subsets. SQLite's handle API uses an unlocked
VFS for file databases: separate processes must not write one database
concurrently. Unicode collation is outside utf8's interface. The IDS supports
a documented rule subset, with offline packet fixtures used for verification.

The helper batch passes 71 fixture/interoperability checks under ASan/UBSan.
Bzip2 completion at an exact output-buffer boundary and truncated zstd/bzip2
streams are handled correctly; SQLite BLOB bindings reject non-hexadecimal
input and preserve an empty BLOB's type. All seventeen non-stub wrapper
analyzer runs completed. A VT clone report assumes a positive scrollback
capacity becomes zero while freeing the clone; the copied capacity and cleanup
loop were reviewed, and handle exhaustion is exercised by the sanitizer test.

SQLite documentation examples use the project’s standard sample home path.

## Process accounting rewrite (2026-09-07)

`procstat` is a new MIT implementation of the upstream command/help surface,
using the Linux kernel's documented proc and diskstats interfaces. The upstream
GPL implementation is not included. Tests construct CPU, disk, process-stat,
and mapping fixtures independently, including guest CPU accounting, command
names containing spaces and closing parentheses, repeated library mappings,
malformed records, invalid IDs, and absent processes. All 22 cases pass under
ASan/UBSan; GCC's analyzer completed without diagnostics.

It provides snapshots rather than interval/history collection. CPU and disk
rates are averages since boot, process CPU percentages are averages since the
process started, `pmap -x` adds file offsets, and `pldd` enumerates mapped shared
object paths rather than traversing the dynamic loader's private structures.

## Crypto, protocols, Git and rendering (imported 2026-09-07)

The final collection batch supplies `crypto claude ldap integrity dns login
passwd auth su doas cksum obj index pack ssh pkg ntp mail rsync wg acme uuidgen
screen sshd tiv kitty sixel nano ts hl sudo`, bringing the full list to 277.
The four board-specific managers remain in the appliance. Sources were taken
from the same 2026-09-06 snapshot and adapted to the public builtin names and
this repository's helper staging. The checked-in helper sources are the build
inputs; building does not fetch moving library branches.

The staged Mbed TLS headers identify 4.1.0, with TF-PSA-Crypto compatibility
headers and a selected configuration. This supersedes the collection's stale
3.6.x version label. The libssh headers identify 0.11.2. Tree-sitter supports
language ABIs 13 through 15 and includes generated Bash, JSON, TOML, Markdown,
and inline-Markdown parsers. Monocypher supplies Ed25519 and Argon2id; SHA1DC
supplies Git object/index checksums; stb_image supplies image decoding. Original
notices are retained, including the additional Unicode/ICU notice for the
Tree-sitter headers. The local stb_image adaptation accepts empty PNG IDAT
chunks without null-pointer arithmetic and rejects truncated in-memory IDAT
chunks before allocating their declared length. Regression fixtures cover both.
Cryptographic PEM recognizer/emitter strings use adjacent
C literals on separate lines, preserving their exact compiled bytes without
including private-key material.

The new `tests/final-smoke.py` compares hashes, MACs, key derivation, authenticated
encryption, public keys, and signatures with Python's independent cryptography
implementations. It checks ACME JWK/JWS encoding, RFC TOTP and UUID results, Git
loose objects/indexes/packfiles against Git itself, package deltas, rsync's local
shell transport, integrity manifests, and image protocol bytes. TLS verification
uses a temporary certificate and loopback server, including hostname rejection.
DNS and NTP use loopback packet fixtures; the API client uses offline HTTP/SSE
and request-assembly fixtures. Account updates use temporary passwd/shadow/group
files, and mail checks compile and expand private aliases. Editor and terminal
checks exercise engine self-tests, language parsing/highlighting, and private
multiplexer metadata. `tests/final-sanitize.sh` instruments both the wrappers
and all selected vendored C helpers. Sanitizer staging is private so a later
pure or tutorial build cannot remove its inputs.

Import corrections include empty-buffer handling, descriptor cleanup on failed
stream conversion, bounded vector/index growth, strict index path termination
and padding, and atomic-write error propagation. Image base64 decoding uses unsigned
accumulators so long input cannot cause signed-shift overflow. The account lookup helper
rejects invalid or overflowing numeric IDs before they can become UID/GID 0.
The DNS master-file parser uses leading whitespace to inherit owners, allowing
owners such as `ns`; wire parsing enforces ordinary DNS label limits. WireGuard
key generation emits the clamped scalar form used by the
[reference implementation](https://raw.githubusercontent.com/WireGuard/wireguard-tools/master/src/genkey.c).
The SSH known-hosts maintenance commands honor the same explicit file override
as encrypted connections.

These imports retain the collection's documented subsets and integration
requirements. Kernel authority tokens require `/dev/bashos-auth`; they do not
provide privilege elevation on a stock kernel. Appliance policy/UI scripts,
package repositories, service configuration, and CA deployment are separate
from these builtins. The API client defaults to the collection's configured
model and permits an environment override; live provider access is not part
of the tests. Mail delivery, system clock changes, privileged network setup,
and appliance kernel authorization are not exercised by the host suite.
SSH offers separate native command-stream and encrypted libssh transports.
Rsync's local shell transport uses an explicit `-e "$BASH -c"`; its documented
subset does not implement all stock rsync options. These requirements apply
even though every listed command is compiled into the full executable.

The selected libssh profile disables NIST ECDH and hybrid-MLKEM key exchange;
its fail-closed ECDH shim is built instead of the incomplete alternate ECDH
implementation. Curve25519 exchange and public-key authentication are checked
against the host OpenSSH client and between the two builtins. The sanitizer
loader is limited to the tested Bash executable, so an executed host shell
does not load modules built for another Bash ABI.

GCC's analyzer completed for the new wrappers except DNS, where it exceeded
the time limit; Clang completed that source. Its DNS findings led to guaranteed
stream closure after sync failures and validation of missing update/listener
arguments. The remaining DNS diagnostic is an unused timeout assignment.
Reviewed GCC reports assume that successful buffer growth leaves a null
allocation, that a returned file length differs from its allocation size, or
that a pointer becomes null between allocation and its check. Runtime boundary
fixtures also run with instrumented helper implementations.

## Persistent graphics builtin

`gpu.c` and `common/gpu-native.h` are MIT implementations of the Bash canvas,
Kitty presenter, input decoder, and optional GBM/EGL/GLES2 renderer. The GPU
backend uses public Linux library ABIs and loads drivers only when requested.
Its DMA-BUF v2 handoff and overlap-safe scroll composition target the Kilix
fork; ordinary frame transmission and updates use the Kitty graphics protocol.

`_soft_raster` vendors the source, headers, and MIT license from
`itsmygithubacct/soft-raster` at revision
`2c3a1008b82456a6d96c1c65557e4e396ffcb61c`, without source changes. Its embedded
bitmap fonts retain their upstream public-domain and permissive notices in the
font headers. The helper manifest selects this rasterizer only for `gpu`.
Canvas and presenter tests check independent pixel expectations, protocol replay,
resource cleanup, and optional real-driver rendering/export; the sanitizer
harness includes the rasterizer itself. See [the graphics API](https://github.com/itsmygithubacct/bash-os/blob/fa178afafddfce8ee870975a38a7f271b25140a9/docs/gpu.md).
