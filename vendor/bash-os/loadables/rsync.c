/* SPDX-License-Identifier: MIT */
/* rsync.c — minimal rsync subset (ML-T4-04 / missing-loadables T4).
 *
 * shell command per directory / file / symlink, and stream raw file contents
 * through the rsh subprocess's stdin pipe (so binary bytes survive shell
 * quoting). v2 adds rolling-checksum block-matching both on the
 * rsync↔rsync rsh shim (--delta) and on the genuine rsync proto-27
 * wire (--native / --rsync-protocol) when a destination basis exists.
 * See research/bash-os/BASHRSYNC_V2_DELTA.md for the original design.
 *
 * --- SCOPE / SUBSET ---
 *
 *   rsync [-a] [-v] [-n] [--delete [--delete-confirm]] [-e RSH] SRC [SRC...] DEST
 *
 *     -a        archive: preserve perms + mtime on transferred files.
 *               (v1 does NOT preserve owner/group — needs the loadable
 *               to run as root on the remote, which is not the common
 *               operator shape.)
 *     -v        verbose: print one "relpath\n" per file that is
 *               actually transferred. Files that match the remote's
 *               size+mtime are silently skipped.
 *     -n        dry-run: walk + probe + print verbose lines, but
 *               never run the writing remote command.
 *     -e RSH    rsh command string. Words are whitespace-split (no
 *               shell quoting). Default: `ssh`.
 *     --delete  after syncing a directory source, remove DEST entries
 *               absent from SRC. Refuses DEST=/ unless
 *               --delete-confirm is also present.
 *
 *   DEST shape:
 *     HOST:PATH   remote push via `RSH HOST CMD`
 *     :PATH       host omitted — invokes `RSH CMD` directly. Useful
 *                 with `-e 'sh -c'` so the "remote" command runs
 *                 locally (this is what the in-guest test uses).
 *
 *   Source trailing slash matches rsync's convention:
 *     SRC/        copy contents of SRC into DEST/.
 *     SRC         copy SRC itself into DEST/, creating DEST/basename(SRC).
 *
 *   rsync --version  Print the subset signature.
 *   rsync --help     One-line usage.
 *
 * --- LIMITS ---
 *
 *   - Bandwidth limit, --partial, --inplace.
 *   - Hard-link preservation (-H), extended attributes (-X), ACLs (-A).
 *
 * --- WIRE PROTOCOL ---
 *
 *   Every remote operation is one fork+execvp of:
 *
 *     argv = rsh_argv + [host?] + [cmd]
 *
 *   With `-e ssh` and `DEST=HOST:/path`, this becomes:
 *
 *     execvp("ssh", ["ssh", "HOST", cmd])
 *
 *   With `-e 'sh -c'` and `DEST=:/path` (empty host), this becomes:
 *
 *     execvp("sh", ["sh", "-c", cmd])
 *
 *   The host argument is dropped when empty. The remote command is
 *   built fresh each operation; we do NOT keep a persistent ssh
 *   session for v1. That keeps the code small (one helper) at the
 *   cost of one ssh connect per transferred file. v2 could batch
 *   via a single multiplexed channel.
 *
 *   Probing a remote file's size + mtime uses:
 *
 *     stat -c '%s %Y' '<path>'   (GNU coreutils form; bash-os ships
 *                                 a coreutils-compatible stat via the
 *                                 sbase-box dispatch)
 *
 *   Writing a remote file uses:
 *
 *     cat > '<path>'             (raw bytes piped through stdin)
 *
 *   Making a remote directory:
 *
 *     mkdir -p '<path>'
 *
 *   Replicating a remote symlink:
 *
 *     rm -f '<path>'; ln -s '<target>' '<path>'
 *
 *   After writing a regular file (and not in dry-run mode), the
 *   remote command is followed by `touch -d @<mtime> '<path>'` when
 *   `-a` is set, so a subsequent run can detect unchanged-ness
 *   without re-transferring.
 *
 *   Path single-quoting escapes embedded single quotes via the
 *   standard `'...'\\''...'` ladder so arbitrary filenames are safe.
 *
 * --- LICENSE ---
 * MIT — same boilerplate shape as other project-local loadables.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include <stdint.h>
#include <zlib.h>

#include "_md4_md4.h"     /* MD4 for rsync-protocol (--native) interop */
#include "loadables.h"

#define BR_VERSION_STR "rsync 2.0 (ssh+tar subset + delta + compression + push/pull + native rsync proto-27 delta + daemon)"

typedef struct {
    int aflag;
    int vflag;
    int nflag;
    int delete_flag;
    int delete_confirm;
    int delta_flag;        /* --delta: rolling-checksum delta transfer */
    int oflag;             /* -o: preserve owner (uid) */
    int gflag;             /* -g: preserve group (gid) */
    int zflag;             /* -z: compress payloads on the wire */
    int native;            /* --native: speak the real rsync wire protocol */
    int whole_file;        /* -W/--whole-file: force native all-literal sends */
    int lflag;             /* -l: preserve symlinks (native pull always sets) */
    char *rsync_path;      /* remote rsync binary for --native (default "rsync") */
    long block_size;       /* --block-size N override (0 = auto sqrt) */
    char **rsh_argv;
    int rsh_n;
    char *host;     /* may be empty string */
    char *rdir;     /* destination directory on remote, no trailing slash */
} br_ctx;

struct br_child_guard {
    struct sigaction old_chld;
    sigset_t oldmask;
};

static int
br_child_guard_begin (struct br_child_guard *g)
{
    struct sigaction dfl;
    sigset_t block;
    memset (&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    sigemptyset (&dfl.sa_mask);
    if (sigaction (SIGCHLD, &dfl, &g->old_chld) < 0)
        return -1;
    sigemptyset (&block);
    sigaddset (&block, SIGCHLD);
    if (sigprocmask (SIG_BLOCK, &block, &g->oldmask) < 0) {
        sigaction (SIGCHLD, &g->old_chld, NULL);
        return -1;
    }
    return 0;
}

static void
br_child_guard_parent_end (struct br_child_guard *g)
{
    sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
    sigaction (SIGCHLD, &g->old_chld, NULL);
}

static void
br_child_guard_child_end (struct br_child_guard *g)
{
    sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
}

/* ----- alloc helpers -------------------------------------------------- */

static void *
br_xmalloc (size_t n)
{
    void *p = malloc (n);
    if (!p) { builtin_error ("out of memory"); exit (2); }
    return p;
}

static void *
br_xrealloc (void *p, size_t n)
{
    void *q = realloc (p, n);
    if (!q) { builtin_error ("out of memory"); exit (2); }
    return q;
}

static char *
br_xstrdup (const char *s)
{
    char *p = strdup (s);
    if (!p) { builtin_error ("out of memory"); exit (2); }
    return p;
}

/* ====================================================================== */
/* v2 delta transfer — rolling-checksum block matching.                   */
/* See research/bash-os/BASHRSYNC_V2_DELTA.md for the full design.       */
/* ====================================================================== */

/* growable-buffer appends are defined further down (with the argv plumbing);
 * forward-declare them for the delta engine that precedes them. */
static void br_append (char **bufp, size_t *lenp, size_t *capp, const char *src, size_t n);
static void br_append_s (char **bufp, size_t *lenp, size_t *capp, const char *s);
static void br_preserve_meta (const br_ctx *c, const char *rpath, const struct stat *lst);
static char *br_sq (const char *in);
static char *br_join (const char *a, const char *b);
static int  br_run (const br_ctx *c, const char *cmd, const void *input, size_t input_len,
                    char **output, size_t *output_len);

/* ----- little-endian buffer helpers ---------------------------------- */
static void br_put_u32 (char **b, size_t *l, size_t *c, uint32_t v) {
    unsigned char t[4] = { (unsigned char) v, (unsigned char) (v >> 8),
                           (unsigned char) (v >> 16), (unsigned char) (v >> 24) };
    br_append (b, l, c, (const char *) t, 4);
}
static void br_put_u64 (char **b, size_t *l, size_t *c, uint64_t v) {
    unsigned char t[8];
    for (int i = 0; i < 8; i++) t[i] = (unsigned char) (v >> (8 * i));
    br_append (b, l, c, (const char *) t, 8);
}
static uint32_t br_get_u32 (const unsigned char *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}
static uint64_t br_get_u64 (const unsigned char *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t) p[i] << (8 * i);
    return v;
}

/* integer floor-sqrt (avoids linking libm) */
static long br_isqrt (uint64_t n) {
    if (n == 0) return 0;
    uint64_t x = n, y = (x + 1) / 2;
    while (y < x) { x = y; y = (x + n / x) / 2; }
    return (long) x;
}

/* ----- MD5 (public domain, compact) ---------------------------------- */
typedef struct { uint32_t a, b, c, d; uint64_t bits; unsigned char buf[64]; size_t n; } br_md5_ctx;

static void br_md5_block (br_md5_ctx *m, const unsigned char *p) {
    static const uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
    static const int S[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22, 5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23, 6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
    uint32_t M[16];
    for (int i = 0; i < 16; i++) M[i] = br_get_u32 (p + i * 4);
    uint32_t a = m->a, b = m->b, c = m->c, d = m->d;
    for (int i = 0; i < 64; i++) {
        uint32_t f; int g;
        if (i < 16)      { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;          g = (3 * i + 5) & 15; }
        else             { f = c ^ (b | ~d);       g = (7 * i) & 15; }
        f += a + K[i] + M[g];
        a = d; d = c; c = b;
        b += (f << S[i]) | (f >> (32 - S[i]));
    }
    m->a += a; m->b += b; m->c += c; m->d += d;
}
static void br_md5_init (br_md5_ctx *m) {
    m->a = 0x67452301; m->b = 0xefcdab89; m->c = 0x98badcfe; m->d = 0x10325476;
    m->bits = 0; m->n = 0;
}
static void br_md5_update (br_md5_ctx *m, const unsigned char *p, size_t len) {
    m->bits += (uint64_t) len * 8;
    while (len) {
        size_t take = 64 - m->n; if (take > len) take = len;
        memcpy (m->buf + m->n, p, take);
        m->n += take; p += take; len -= take;
        if (m->n == 64) { br_md5_block (m, m->buf); m->n = 0; }
    }
}
static void br_md5_final (br_md5_ctx *m, unsigned char out[16]) {
    unsigned char pad = 0x80;
    uint64_t bits = m->bits;
    br_md5_update (m, &pad, 1);
    unsigned char z = 0;
    while (m->n != 56) br_md5_update (m, &z, 1);
    unsigned char lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (unsigned char) (bits >> (8 * i));
    /* update bits would double-count; write length block directly */
    memcpy (m->buf + 56, lb, 8);
    br_md5_block (m, m->buf);
    uint32_t v[4] = { m->a, m->b, m->c, m->d };
    for (int i = 0; i < 4; i++) {
        out[i*4]   = (unsigned char) v[i];
        out[i*4+1] = (unsigned char) (v[i] >> 8);
        out[i*4+2] = (unsigned char) (v[i] >> 16);
        out[i*4+3] = (unsigned char) (v[i] >> 24);
    }
}
static void br_md5 (const unsigned char *p, size_t len, unsigned char out[16]) {
    br_md5_ctx m; br_md5_init (&m); br_md5_update (&m, p, len); br_md5_final (&m, out);
}

/* ----- weak rolling checksum (rsync's) ------------------------------- */
static uint32_t br_weak (const unsigned char *p, size_t len) {
    uint32_t a = 0, b = 0;
    for (size_t i = 0; i < len; i++) { a += p[i]; b += (uint32_t) (len - i) * p[i]; }
    return (a & 0xffff) | ((b & 0xffff) << 16);
}
static uint32_t br_roll (uint32_t s, unsigned char out, unsigned char in, uint32_t bs) {
    uint32_t a = s & 0xffff, b = (s >> 16) & 0xffff;
    a = (a - out + in) & 0xffff;
    b = (b - bs * out + a) & 0xffff;
    return a | (b << 16);
}

static long br_blocksize (uint64_t oldsize, long override) {
    if (override > 0) return override;
    long b = br_isqrt (oldsize);
    b = (b + 7) & ~7L;          /* round up to multiple of 8 */
    if (b < 512) b = 512;
    if (b > 65536) b = 65536;
    return b;
}

/* read an entire file into memory; returns 0/-1, sets *buf (malloc) + *len */
static int br_slurp (const char *path, unsigned char **buf, size_t *len) {
    int fd = open (path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat (fd, &st) < 0 || !S_ISREG (st.st_mode)) { close (fd); return -1; }
    size_t sz = (size_t) st.st_size, off = 0;
    unsigned char *b = (unsigned char *) br_xmalloc (sz ? sz : 1);
    while (off < sz) {
        ssize_t r = read (fd, b + off, sz - off);
        if (r < 0) { if (errno == EINTR) continue; close (fd); free (b); return -1; }
        if (r == 0) break;
        off += (size_t) r;
    }
    close (fd);
    *buf = b; *len = off;
    return 0;
}

static int br_write_all (int fd, const void *p, size_t n) {
    const char *q = (const char *) p;
    while (n) {
        ssize_t w = write (fd, q, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        q += w; n -= (size_t) w;
    }
    return 0;
}

/* ----- compression (zlib): frame = [u64 origlen LE][deflate stream] ----- */
static int br_deflate (const unsigned char *src, size_t slen,
                       unsigned char **out, size_t *olen) {
    uLong bound = compressBound ((uLong) slen);
    unsigned char *o = (unsigned char *) br_xmalloc (8 + bound);
    for (int i = 0; i < 8; i++) o[i] = (unsigned char) ((uint64_t) slen >> (8 * i));
    uLongf dl = bound;
    if (compress2 (o + 8, &dl, src, (uLong) slen, 6) != Z_OK) { free (o); return -1; }
    *out = o; *olen = 8 + (size_t) dl;
    return 0;
}
static int br_inflate (const unsigned char *src, size_t slen,
                       unsigned char **out, size_t *olen) {
    if (slen < 8) return -1;
    uint64_t orig = 0;
    for (int i = 0; i < 8; i++) orig |= (uint64_t) src[i] << (8 * i);
    unsigned char *o = (unsigned char *) br_xmalloc (orig ? orig : 1);
    uLongf dl = (uLongf) orig;
    if (uncompress (o, &dl, src + 8, (uLong) (slen - 8)) != Z_OK || dl != orig) {
        free (o); return -1;
    }
    *out = o; *olen = (size_t) dl;
    return 0;
}

/* read all of fd into a fresh buffer (caller frees). returns 0/-1. */
static int br_read_fd (int fd, unsigned char **out, size_t *olen) {
    size_t cap = 1 << 16, n = 0;
    unsigned char *b = (unsigned char *) br_xmalloc (cap);
    for (;;) {
        if (n + 4096 > cap) { cap *= 2; b = (unsigned char *) br_xrealloc (b, cap); }
        ssize_t r = read (fd, b + n, cap - n);
        if (r < 0) { if (errno == EINTR) continue; free (b); return -1; }
        if (r == 0) break;
        n += (size_t) r;
    }
    *out = b; *olen = n;
    return 0;
}

/* atomic write of (buf,len) to path via path.bRtmp → rename. 0/-1. */
static int br_atomic_write (const char *path, const unsigned char *buf, size_t len) {
    char tmp[4096];
    snprintf (tmp, sizeof tmp, "%s.bRtmp", path);
    int fd = open (tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    int rc = br_write_all (fd, buf, len);
    if (rc == 0) rc = (fsync (fd) == 0) ? 0 : -1;
    close (fd);
    if (rc != 0) { unlink (tmp); return -1; }
    if (rename (tmp, path) != 0) { unlink (tmp); return -1; }
    return 0;
}

/* SERVER side: read a compressed whole-file from stdin, inflate, write path. */
static int br_server_recvz (const char *path) {
    unsigned char *cz = NULL; size_t czlen = 0;
    if (br_read_fd (0, &cz, &czlen) != 0) return -1;
    unsigned char *raw = NULL; size_t rawlen = 0;
    int rc = br_inflate (cz, czlen, &raw, &rawlen);
    free (cz);
    if (rc != 0) return -1;
    rc = br_atomic_write (path, raw, rawlen);
    free (raw);
    return rc;
}

/* ====================================================================== */
/* Pull mode (HOST:SRC -> local DEST) — a self-describing tree stream.     */
/* The remote walks SRC and emits entries; the local side materializes     */
/* them. Stream (after an optional zlib frame): "bRT1" then entries        */
/* keyed by 'D'/'F'/'L', terminated by 'E'. Each carries relpath + mode +  */
/* mtime + uid + gid; F adds size+bytes, L adds the link target.           */
/* ====================================================================== */

static void br_put_u16 (char **b, size_t *l, size_t *c, uint16_t v) {
    unsigned char t[2] = { (unsigned char) v, (unsigned char) (v >> 8) };
    br_append (b, l, c, (const char *) t, 2);
}
static uint16_t br_get_u16 (const unsigned char *p) {
    return (uint16_t) (p[0] | (p[1] << 8));
}

/* common entry header: relpath + mode + mtime + uid + gid */
static void br_tree_hdr (char **b, size_t *l, size_t *c, char tag,
                         const char *rel, const struct stat *st) {
    char tg[1] = { tag };
    br_append (b, l, c, tg, 1);
    uint16_t pl = (uint16_t) strlen (rel);
    br_put_u16 (b, l, c, pl);
    br_append (b, l, c, rel, pl);
    br_put_u32 (b, l, c, (uint32_t) (st->st_mode & 07777));
    br_put_u64 (b, l, c, (uint64_t) st->st_mtime);
    br_put_u32 (b, l, c, (uint32_t) st->st_uid);
    br_put_u32 (b, l, c, (uint32_t) st->st_gid);
}

/* recursively append SRC subtree (abs path, rel path under DEST) to the buf. */
static void br_tree_emit (char **b, size_t *l, size_t *c,
                          const char *abs, const char *rel) {
    struct stat st;
    if (lstat (abs, &st) != 0) return;
    if (S_ISDIR (st.st_mode)) {
        br_tree_hdr (b, l, c, 'D', rel, &st);
        DIR *d = opendir (abs);
        if (d) {
            struct dirent *de;
            while ((de = readdir (d)) != NULL) {
                if (de->d_name[0] == '.' && (de->d_name[1] == 0
                    || (de->d_name[1] == '.' && de->d_name[2] == 0))) continue;
                char *ca = br_join (abs, de->d_name);
                char *cr = br_join (rel, de->d_name);
                br_tree_emit (b, l, c, ca, cr);
                free (ca); free (cr);
            }
            closedir (d);
        }
    } else if (S_ISLNK (st.st_mode)) {
        char tgt[4096];
        ssize_t n = readlink (abs, tgt, sizeof tgt - 1);
        if (n < 0) return;
        tgt[n] = 0;
        br_tree_hdr (b, l, c, 'L', rel, &st);
        br_put_u16 (b, l, c, (uint16_t) n);
        br_append (b, l, c, tgt, (size_t) n);
    } else if (S_ISREG (st.st_mode)) {
        unsigned char *data = NULL; size_t dl = 0;
        if (br_slurp (abs, &data, &dl) != 0) return;
        br_tree_hdr (b, l, c, 'F', rel, &st);
        br_put_u64 (b, l, c, (uint64_t) dl);
        br_append (b, l, c, (const char *) data, dl);
        free (data);
    }
    /* other file types are silently skipped */
}

/* SERVER side: emit the SRC tree to stdout. `contents`: SRC is a dir and we
 * emit its children at the top level (SRC/ trailing-slash semantics); else
 * emit SRC itself under its basename. `compress` → zlib-frame the stream. */
static int br_server_send (const char *src, int contents, int compress) {
    char *buf = NULL; size_t l = 0, cc = 0;
    br_append (&buf, &l, &cc, "bRT1", 4);
    struct stat st;
    if (lstat (src, &st) == 0) {
        if (contents && S_ISDIR (st.st_mode)) {
            DIR *d = opendir (src);
            if (d) {
                struct dirent *de;
                while ((de = readdir (d)) != NULL) {
                    if (de->d_name[0] == '.' && (de->d_name[1] == 0
                        || (de->d_name[1] == '.' && de->d_name[2] == 0))) continue;
                    char *ca = br_join (src, de->d_name);
                    br_tree_emit (&buf, &l, &cc, ca, de->d_name);
                    free (ca);
                }
                closedir (d);
            }
        } else {
            const char *bn = strrchr (src, '/');
            bn = bn ? bn + 1 : src;
            br_tree_emit (&buf, &l, &cc, src, bn);
        }
    }
    br_append (&buf, &l, &cc, "E", 1);
    int rc;
    if (compress) {
        unsigned char *cz = NULL; size_t czl = 0;
        if (br_deflate ((const unsigned char *) buf, l, &cz, &czl) != 0) { free (buf); return -1; }
        rc = br_write_all (1, cz, czl); free (cz);
    } else {
        rc = br_write_all (1, buf, l);
    }
    free (buf);
    return rc;
}

/* local: mkdir -p */
static void br_local_mkdirp (const char *path) {
    char tmp[4096];
    snprintf (tmp, sizeof tmp, "%s", path);
    for (char *q = tmp + 1; *q; q++) {
        if (*q == '/') { *q = 0; mkdir (tmp, 0755); *q = '/'; }
    }
    mkdir (tmp, 0755);
}
/* local: mkdir -p on the parent directory of `path` */
static void br_local_mkparent (const char *path) {
    char tmp[4096];
    snprintf (tmp, sizeof tmp, "%s", path);
    char *slash = strrchr (tmp, '/');
    if (slash && slash != tmp) { *slash = 0; br_local_mkdirp (tmp); }
}
/* local best-effort metadata application (pull side: direct syscalls) */
static void br_apply_meta_local (const br_ctx *c, const char *full,
                                 uint32_t mode, uint64_t mt,
                                 uint32_t uid, uint32_t gid, int is_link) {
    if (c->oflag || c->gflag) {
        uid_t u = c->oflag ? (uid_t) uid : (uid_t) -1;
        gid_t g = c->gflag ? (gid_t) gid : (gid_t) -1;
        if (is_link) { if (lchown (full, u, g) != 0 && c->vflag) {} }
        else         { if (chown  (full, u, g) != 0 && c->vflag) {} }
    }
    if (c->aflag && !is_link) {
        chmod (full, (mode_t) mode);
        struct timeval tv[2];
        tv[0].tv_sec = (time_t) mt; tv[0].tv_usec = 0; tv[1] = tv[0];
        utimes (full, tv);
    }
}

/* local: materialize a tree stream into DEST. Returns 0/-1. */
static int br_pull_recv (const br_ctx *c, const unsigned char *s, size_t len,
                         const char *dest) {
    if (len < 4 || memcmp (s, "bRT1", 4) != 0) return -1;
    const unsigned char *p = s + 4, *end = s + len;
    if (!c->nflag) br_local_mkdirp (dest);
    while (p < end) {
        unsigned char tag = *p++;
        if (tag == 'E') break;
        if (p + 2 > end) return -1;
        uint16_t pl = br_get_u16 (p); p += 2;
        if (p + pl > end || pl >= 4096) return -1;
        char rel[4096]; memcpy (rel, p, pl); rel[pl] = 0; p += pl;
        if (p + 4 + 8 + 4 + 4 > end) return -1;
        uint32_t mode = br_get_u32 (p); p += 4;
        uint64_t mt   = br_get_u64 (p); p += 8;
        uint32_t uid  = br_get_u32 (p); p += 4;
        uint32_t gid  = br_get_u32 (p); p += 4;
        char *full = br_join (dest, rel);
        if (c->vflag) fprintf (stderr, "%s\n", rel);
        if (tag == 'D') {
            if (!c->nflag) { br_local_mkdirp (full);
                br_apply_meta_local (c, full, mode, mt, uid, gid, 0); }
        } else if (tag == 'F') {
            if (p + 8 > end) { free (full); return -1; }
            uint64_t sz = br_get_u64 (p); p += 8;
            if ((uint64_t) (end - p) < sz) { free (full); return -1; }
            if (!c->nflag) {
                br_local_mkparent (full);
                if (br_atomic_write (full, p, (size_t) sz) == 0)
                    br_apply_meta_local (c, full, mode, mt, uid, gid, 0);
            }
            p += sz;
        } else if (tag == 'L') {
            if (p + 2 > end) { free (full); return -1; }
            uint16_t tl = br_get_u16 (p); p += 2;
            if (p + tl > end || tl >= 4096) { free (full); return -1; }
            char tgt[4096]; memcpy (tgt, p, tl); tgt[tl] = 0; p += tl;
            if (!c->nflag) {
                br_local_mkparent (full);
                unlink (full);
                if (symlink (tgt, full) == 0)
                    br_apply_meta_local (c, full, mode, mt, uid, gid, 1);
            }
        } else { free (full); return -1; }
        free (full);
    }
    return 0;
}

/* Pull one remote SRC (path on c->host) into local DEST. */
static int br_pull (const br_ctx *c, const char *rpath, const char *dest) {
    size_t rl = strlen (rpath);
    int contents = (rl > 0 && rpath[rl - 1] == '/');
    char *clean = br_xstrdup (rpath);
    while (rl > 1 && clean[rl - 1] == '/') clean[--rl] = 0;

    char *qrp = br_sq (clean);
    free (clean);
    char *cmd = NULL; size_t cl = 0, cc = 0;
    br_append_s (&cmd, &cl, &cc, "rsync --server-send ");
    br_append_s (&cmd, &cl, &cc, qrp);
    br_append_s (&cmd, &cl, &cc, contents ? " contents" : " tree");
    if (c->zflag) br_append_s (&cmd, &cl, &cc, " z");
    free (qrp);

    char *stream = NULL; size_t slen = 0;
    int rc = br_run (c, cmd, NULL, 0, &stream, &slen);
    free (cmd);
    if (rc != 0) { free (stream); builtin_error ("remote send failed (rc=%d): %s", rc, rpath); return -1; }

    const unsigned char *data = (const unsigned char *) stream; size_t dlen = slen;
    unsigned char *dec = NULL;
    if (c->zflag) {
        if (br_inflate ((const unsigned char *) stream, slen, &dec, &dlen) != 0) {
            free (stream); builtin_error ("inflate failed: %s", rpath); return -1;
        }
        data = dec;
    }
    rc = br_pull_recv (c, data, dlen, dest);
    free (dec); free (stream);
    if (rc != 0) builtin_error ("pull reconstruct failed: %s", rpath);
    return rc;
}

/* ----- signature: blocks of the basis file --------------------------- */
typedef struct {
    uint32_t blocksize;
    uint64_t oldsize;
    uint32_t nblocks;
    uint32_t *weak;          /* [nblocks] */
    unsigned char *strong;   /* [nblocks*16] */
} br_sig;

/* SERVER side: emit signature of `path` to fd 1. Missing/unreadable file →
 * emit an empty (nblocks=0) signature so the sender falls back to whole-file. */
static int br_server_sig (const char *path, long override) {
    unsigned char *data = NULL; size_t len = 0;
    int have = (br_slurp (path, &data, &len) == 0);
    uint32_t bs = (uint32_t) br_blocksize (have ? len : 0, override);
    uint32_t nb = have ? (uint32_t) (len / bs) : 0;   /* full blocks only */
    char *out = NULL; size_t ol = 0, oc = 0;
    br_append (&out, &ol, &oc, "bRS1", 4);
    br_put_u32 (&out, &ol, &oc, bs);
    br_put_u64 (&out, &ol, &oc, (uint64_t) (have ? len : 0));
    br_put_u32 (&out, &ol, &oc, nb);
    for (uint32_t i = 0; i < nb; i++) {
        const unsigned char *blk = data + (size_t) i * bs;
        br_put_u32 (&out, &ol, &oc, br_weak (blk, bs));
        unsigned char md[16];
        br_md5 (blk, bs, md);
        br_append (&out, &ol, &oc, (const char *) md, 16);
    }
    int rc = br_write_all (1, out, ol);
    free (out); free (data);
    return rc;
}

static int br_parse_sig (const unsigned char *buf, size_t len, br_sig *s) {
    memset (s, 0, sizeof *s);
    if (len < 4 + 4 + 8 + 4 || memcmp (buf, "bRS1", 4) != 0) return -1;
    const unsigned char *p = buf + 4;
    s->blocksize = br_get_u32 (p); p += 4;
    s->oldsize   = br_get_u64 (p); p += 8;
    s->nblocks   = br_get_u32 (p); p += 4;
    if (s->blocksize == 0) return -1;
    uint64_t need = (uint64_t) s->nblocks * (4 + 16);
    if ((uint64_t) (len - (size_t) (p - buf)) < need) return -1;
    if (s->nblocks) {
        s->weak = (uint32_t *) br_xmalloc (sizeof (uint32_t) * s->nblocks);
        s->strong = (unsigned char *) br_xmalloc ((size_t) s->nblocks * 16);
        for (uint32_t i = 0; i < s->nblocks; i++) {
            s->weak[i] = br_get_u32 (p); p += 4;
            memcpy (s->strong + (size_t) i * 16, p, 16); p += 16;
        }
    }
    return 0;
}
static void br_free_sig (br_sig *s) { free (s->weak); free (s->strong); memset (s, 0, sizeof *s); }

/* sorted (weak,index) table for O(log n) weak lookup */
typedef struct { uint32_t weak; uint32_t idx; } br_went;
static int br_wcmp (const void *a, const void *b) {
    uint32_t x = ((const br_went *) a)->weak, y = ((const br_went *) b)->weak;
    return x < y ? -1 : (x > y ? 1 : 0);
}

/* find a block index whose weak==w AND whose strong matches md5(window). -1 none. */
static long br_match (const br_sig *s, const br_went *tab, uint32_t w,
                      const unsigned char *win, uint32_t bs) {
    /* binary search for the first entry with weak >= w */
    uint32_t lo = 0, hi = s->nblocks;
    while (lo < hi) { uint32_t m = (lo + hi) / 2; if (tab[m].weak < w) lo = m + 1; else hi = m; }
    if (lo >= s->nblocks || tab[lo].weak != w) return -1;
    unsigned char md[16]; int have_md = 0;
    for (uint32_t i = lo; i < s->nblocks && tab[i].weak == w; i++) {
        if (!have_md) { br_md5 (win, bs, md); have_md = 1; }
        if (memcmp (md, s->strong + (size_t) tab[i].idx * 16, 16) == 0)
            return (long) tab[i].idx;
    }
    return -1;
}

/* SENDER side: compute delta of (newbuf,newlen) against signature s.
 * Output a delta blob (caller frees). */
static void br_compute_delta (const unsigned char *nb, size_t nl, const br_sig *s,
                              char **out, size_t *outlen) {
    char *d = NULL; size_t dl = 0, dc = 0;
    uint32_t bs = s->blocksize;
    br_append (&d, &dl, &dc, "bRD1", 4);
    br_put_u32 (&d, &dl, &dc, bs);
    br_put_u64 (&d, &dl, &dc, (uint64_t) nl);

    br_went *tab = NULL;
    if (s->nblocks) {
        tab = (br_went *) br_xmalloc (sizeof (br_went) * s->nblocks);
        for (uint32_t i = 0; i < s->nblocks; i++) { tab[i].weak = s->weak[i]; tab[i].idx = i; }
        qsort (tab, s->nblocks, sizeof *tab, br_wcmp);
    }

    size_t i = 0, lit = 0;
    if (s->nblocks && bs && nl >= bs) {
        uint32_t w = br_weak (nb, bs);
        for (;;) {
            long idx = br_match (s, tab, w, nb + i, bs);
            if (idx >= 0) {
                if (i > lit) {
                    br_append (&d, &dl, &dc, "L", 1);
                    br_put_u32 (&d, &dl, &dc, (uint32_t) (i - lit));
                    br_append (&d, &dl, &dc, (const char *) (nb + lit), i - lit);
                }
                br_append (&d, &dl, &dc, "C", 1);
                br_put_u32 (&d, &dl, &dc, (uint32_t) idx);
                i += bs; lit = i;
                if (i + bs <= nl) w = br_weak (nb + i, bs);
                else break;
            } else if (i + bs < nl) {
                w = br_roll (w, nb[i], nb[i + bs], bs);
                i++;
            } else {
                break;
            }
        }
    }
    if (nl > lit) {
        br_append (&d, &dl, &dc, "L", 1);
        br_put_u32 (&d, &dl, &dc, (uint32_t) (nl - lit));
        br_append (&d, &dl, &dc, (const char *) (nb + lit), nl - lit);
    }
    br_append (&d, &dl, &dc, "E", 1);
    unsigned char whole[16];
    br_md5 (nb, nl, whole);
    br_append (&d, &dl, &dc, (const char *) whole, 16);
    free (tab);
    *out = d; *outlen = dl;
}

/* SERVER side: apply a delta (read from fd 0) to `path` (the basis), writing
 * the reconstruction atomically. `compressed` → the delta is zlib-framed.
 * Returns 0/-1. */
static int br_server_patch (const char *path, int compressed) {
    unsigned char *delta = NULL; size_t dlen = 0;
    if (br_read_fd (0, &delta, &dlen) != 0) return -1;
    if (compressed) {
        unsigned char *raw = NULL; size_t rawlen = 0;
        if (br_inflate (delta, dlen, &raw, &rawlen) != 0) { free (delta); return -1; }
        free (delta); delta = raw; dlen = rawlen;
    }
    if (dlen < 4 + 4 + 8 + 1 + 16 || memcmp (delta, "bRD1", 4) != 0) { free (delta); return -1; }
    const unsigned char *p = delta + 4;
    uint32_t bs = br_get_u32 (p); p += 4;
    uint64_t newsize = br_get_u64 (p); p += 8;
    (void) bs;

    /* basis (may be absent: a pure-literal delta still reconstructs) */
    unsigned char *old = NULL; size_t oldlen = 0;
    br_slurp (path, &old, &oldlen);

    char *out = NULL; size_t ol = 0, oc = 0;
    const unsigned char *end = delta + dlen;
    int ok = 1;
    while (p < end) {
        unsigned char tag = *p++;
        if (tag == 'E') break;
        if (tag == 'C') {
            if (p + 4 > end) { ok = 0; break; }
            uint32_t idx = br_get_u32 (p); p += 4;
            uint64_t off = (uint64_t) idx * bs;
            if (!old || off >= oldlen) { ok = 0; break; }
            size_t n = bs; if (off + n > oldlen) n = oldlen - off;
            br_append (&out, &ol, &oc, (const char *) (old + off), n);
        } else if (tag == 'L') {
            if (p + 4 > end) { ok = 0; break; }
            uint32_t n = br_get_u32 (p); p += 4;
            if (p + n > end) { ok = 0; break; }
            br_append (&out, &ol, &oc, (const char *) p, n);
            p += n;
        } else { ok = 0; break; }
    }
    /* trailer: whole-file md5 */
    unsigned char want[16]; int have_want = 0;
    if (ok && p + 16 <= end) { memcpy (want, p, 16); have_want = 1; }

    if (ok && (uint64_t) ol == newsize && have_want) {
        unsigned char got[16];
        br_md5 ((const unsigned char *) out, ol, got);
        if (memcmp (got, want, 16) != 0) ok = 0;
    } else ok = 0;

    free (old); free (delta);
    if (!ok) { free (out); return -1; }

    int wrc = br_atomic_write (path, (const unsigned char *) out, ol);
    free (out);
    return wrc;
}

/* Whitespace-tokenize s into a freshly-allocated argv[]. No shell
 * quoting recognised — matches rsync(1)'s documented behavior for
 * `-e CMD` where the user is expected to keep their RSH command
 * argv-clean (no spaces in paths inside the rsh string). */
static int
br_split (const char *s, char ***out)
{
    char **argv = NULL;
    int n = 0, cap = 0;
    const char *p = s;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (n == cap) {
            cap = cap ? cap * 2 : 8;
            argv = (char **) br_xrealloc (argv, sizeof (char *) * (size_t) cap);
        }
        size_t len = (size_t) (p - start);
        char *w = (char *) br_xmalloc (len + 1);
        memcpy (w, start, len); w[len] = 0;
        argv[n++] = w;
    }
    *out = argv;
    return n;
}

/* ----- shell-quoting helpers ----------------------------------------- */

/* Append c to *bufp at *lenp, growing *capp if needed. */
static void
br_append (char **bufp, size_t *lenp, size_t *capp, const char *src, size_t n)
{
    if (*lenp == SIZE_MAX || n > SIZE_MAX - *lenp - 1) {
        builtin_error ("buffer too large"); exit (2);
    }
    if (*lenp + n + 1 > *capp) {
        size_t nc = *capp ? *capp : 256;
        while (nc < *lenp + n + 1) {
            if (nc > SIZE_MAX / 2) { nc = *lenp + n + 1; break; }
            nc *= 2;
        }
        *bufp = (char *) br_xrealloc (*bufp, nc);
        *capp = nc;
    }
    if (n) memcpy (*bufp + *lenp, src, n);
    *lenp += n;
    (*bufp)[*lenp] = 0;
}

static void
br_append_s (char **bufp, size_t *lenp, size_t *capp, const char *s)
{
    br_append (bufp, lenp, capp, s, strlen (s));
}

/* POSIX single-quote a single argument. Returns a freshly malloc'd
 * string. Single quotes inside the input are encoded as the standard
 * ladder: '...'\''...'. */
static char *
br_sq (const char *in)
{
    char *out = NULL;
    size_t len = 0, cap = 0;
    br_append_s (&out, &len, &cap, "'");
    for (const char *p = in; *p; p++) {
        if (*p == '\'') br_append_s (&out, &len, &cap, "'\\''");
        else br_append (&out, &len, &cap, p, 1);
    }
    br_append_s (&out, &len, &cap, "'");
    return out;
}

/* ----- joinpath helpers ---------------------------------------------- */

/* Returns malloc'd "a/b" — drops a trailing slash on `a` and a leading
 * slash on `b` so the result is canonical. */
static char *
br_join (const char *a, const char *b)
{
    size_t la = strlen (a);
    while (la > 1 && a[la - 1] == '/') la--;
    while (*b == '/') b++;
    size_t lb = strlen (b);
    char *out = (char *) br_xmalloc (la + 1 + lb + 1);
    memcpy (out, a, la);
    out[la] = '/';
    memcpy (out + la + 1, b, lb);
    out[la + 1 + lb] = 0;
    return out;
}

/* ----- rsh invocation ------------------------------------------------- */

/* Build a NULL-terminated argv: rsh_argv + [host?] + [cmd]. Caller
 * frees the returned pointer; entries are owned by the ctx and the
 * cmd string (do NOT free them individually). */
static char **
br_build_argv (const br_ctx *c, const char *cmd)
{
    int have_host = (c->host && c->host[0]) ? 1 : 0;
    int n = c->rsh_n + have_host + 1; /* +cmd */
    char **a = (char **) br_xmalloc (sizeof (char *) * (size_t) (n + 1));
    int i = 0;
    for (int k = 0; k < c->rsh_n; k++) a[i++] = c->rsh_argv[k];
    if (have_host) a[i++] = c->host;
    a[i++] = (char *) cmd;
    a[i] = NULL;
    return a;
}

/* Run `cmd` via rsh. If input != NULL, pipe (input, input_len) to
 * the child's stdin. If output != NULL, capture all child stdout
 * (NUL-terminated, *output_len set, malloc'd, caller frees). Returns
 * the child's exit status (0 success, -1 internal error). */
static int
br_run (const br_ctx *c, const char *cmd,
        const void *input, size_t input_len,
        char **output, size_t *output_len)
{
    int in_p[2] = { -1, -1 };
    int out_p[2] = { -1, -1 };
    if (input != NULL && pipe (in_p) < 0) {
        builtin_error ("pipe: %s", strerror (errno));
        return -1;
    }
    if (output != NULL && pipe (out_p) < 0) {
        if (in_p[0] >= 0) { close (in_p[0]); close (in_p[1]); }
        builtin_error ("pipe: %s", strerror (errno));
        return -1;
    }
    char **argv = br_build_argv (c, cmd);
    struct br_child_guard guard;
    if (br_child_guard_begin (&guard) < 0) {
        builtin_error ("SIGCHLD guard: %s", strerror (errno));
        free (argv);
        if (in_p[0] >= 0) { close (in_p[0]); close (in_p[1]); }
        if (out_p[0] >= 0) { close (out_p[0]); close (out_p[1]); }
        return -1;
    }
    pid_t pid = fork ();
    if (pid < 0) {
        br_child_guard_parent_end (&guard);
        builtin_error ("fork: %s", strerror (errno));
        free (argv);
        if (in_p[0] >= 0) { close (in_p[0]); close (in_p[1]); }
        if (out_p[0] >= 0) { close (out_p[0]); close (out_p[1]); }
        return -1;
    }
    if (pid == 0) {
        br_child_guard_child_end (&guard);
        /* SIGPIPE default — if the parent closes the input pipe early
         * we want a clean death. */
        signal (SIGPIPE, SIG_DFL);
        if (input != NULL) {
            dup2 (in_p[0], 0);
            close (in_p[0]); close (in_p[1]);
        } else {
            /* Detach stdin from the controlling tty so commands like
             * `stat` don't accidentally block on terminal input. */
            int dn = open ("/dev/null", O_RDONLY);
            if (dn >= 0) { dup2 (dn, 0); close (dn); }
        }
        if (output != NULL) {
            dup2 (out_p[1], 1);
            close (out_p[0]); close (out_p[1]);
        }
        execvp (argv[0], argv);
        fprintf (stderr, "rsync: execvp %s: %s\n", argv[0], strerror (errno));
        _exit (127);
    }
    /* parent */
    free (argv);
    if (input != NULL) {
        close (in_p[0]);
        const char *p = (const char *) input;
        size_t left = input_len;
        /* Ignore SIGPIPE so an early child exit comes back as EPIPE
         * we can detect via write() return rather than terminating
         * the bash shell. */
        struct sigaction old, ign;
        memset (&ign, 0, sizeof ign);
        ign.sa_handler = SIG_IGN;
        sigaction (SIGPIPE, &ign, &old);
        while (left > 0) {
            ssize_t w = write (in_p[1], p, left);
            if (w < 0) { if (errno == EINTR) continue; break; }
            p += w; left -= (size_t) w;
        }
        sigaction (SIGPIPE, &old, NULL);
        close (in_p[1]);
    }
    if (output != NULL) {
        close (out_p[1]);
        size_t cap = 4096, len = 0;
        char *buf = (char *) br_xmalloc (cap);
        while (1) {
            if (len + 1024 + 1 > cap) {
                cap *= 2;
                buf = (char *) br_xrealloc (buf, cap);
            }
            ssize_t r = read (out_p[0], buf + len, cap - len - 1);
            if (r < 0) { if (errno == EINTR) continue; break; }
            if (r == 0) break;
            len += (size_t) r;
        }
        close (out_p[0]);
        buf[len] = 0;
        *output = buf;
        if (output_len) *output_len = len;
    }
    int st = 0;
    while (waitpid (pid, &st, 0) < 0) {
        if (errno == EINTR) continue;
        br_child_guard_parent_end (&guard);
        return -1;
    }
    br_child_guard_parent_end (&guard);
    if (WIFEXITED (st)) return WEXITSTATUS (st);
    return -1;
}

/* ----- remote operations --------------------------------------------- */

/* Returns 0 on success, sets *size and *mtime. Returns 1 if remote
 * said "missing" (stat exit != 0 or empty output). Returns -1 on
 * pipeline error. */
static int
br_probe (const br_ctx *c, const char *rpath,
          long long *size, long long *mtime)
{
    char *qrp = br_sq (rpath);
    /* The redirect drops stat's stderr — "no such file" is expected. */
    char *cmd = NULL;
    size_t cl = 0, cc = 0;
    br_append_s (&cmd, &cl, &cc, "stat -c '%s %Y' ");
    br_append_s (&cmd, &cl, &cc, qrp);
    br_append_s (&cmd, &cl, &cc, " 2>/dev/null");
    free (qrp);

    char *out = NULL;
    size_t olen = 0;
    int rc = br_run (c, cmd, NULL, 0, &out, &olen);
    free (cmd);

    if (rc < 0) { free (out); return -1; }
    if (rc != 0 || olen == 0) { free (out); return 1; }

    long long s = -1, t = -1;
    if (sscanf (out, "%lld %lld", &s, &t) != 2) { free (out); return 1; }
    free (out);
    *size = s;
    *mtime = t;
    return 0;
}

static int
br_mkdir (const br_ctx *c, const char *rpath)
{
    if (c->nflag) return 0;
    char *qrp = br_sq (rpath);
    char *cmd = NULL;
    size_t cl = 0, cc = 0;
    br_append_s (&cmd, &cl, &cc, "mkdir -p ");
    br_append_s (&cmd, &cl, &cc, qrp);
    free (qrp);
    int rc = br_run (c, cmd, NULL, 0, NULL, NULL);
    free (cmd);
    if (rc != 0) {
        builtin_error ("remote mkdir failed (rc=%d): %s", rc, rpath);
        return -1;
    }
    return 0;
}

static int
br_send_file (const br_ctx *c, const char *lpath, const char *rpath,
              const struct stat *lst)
{
    if (c->nflag) return 0;
    int fd = open (lpath, O_RDONLY);
    if (fd < 0) {
        builtin_error ("open %s: %s", lpath, strerror (errno));
        return -1;
    }
    /* slurp file into memory — v1 doesn't stream, which keeps the
     * fork+pipe orchestration simple. Files larger than ~few MB
     * are not the typical v1 audience. */
    off_t sz = lst->st_size;
    char *buf = NULL;
    if (sz > 0) {
        buf = (char *) br_xmalloc ((size_t) sz);
        ssize_t left = sz, off = 0;
        while (left > 0) {
            ssize_t r = read (fd, buf + off, (size_t) left);
            if (r < 0) {
                if (errno == EINTR) continue;
                builtin_error ("read %s: %s", lpath, strerror (errno));
                close (fd); free (buf);
                return -1;
            }
            if (r == 0) break;
            off += r; left -= r;
        }
    }
    close (fd);

    char *qrp = br_sq (rpath);
    char *cmd = NULL;
    size_t cl = 0, cc = 0;
    int rc;
    if (c->zflag) {
        /* compress the payload; remote inflates via --server-recvz (needs
         * rsync on the remote). */
        unsigned char *cz = NULL; size_t czlen = 0;
        if (br_deflate ((const unsigned char *) (buf ? buf : (char *) ""),
                        (size_t) (sz > 0 ? sz : 0), &cz, &czlen) != 0) {
            free (buf); free (qrp);
            builtin_error ("compress failed: %s", lpath);
            return -1;
        }
        br_append_s (&cmd, &cl, &cc, "rsync --server-recvz ");
        br_append_s (&cmd, &cl, &cc, qrp);
        rc = br_run (c, cmd, cz, czlen, NULL, NULL);
        free (cz);
    } else {
        br_append_s (&cmd, &cl, &cc, "cat > ");
        br_append_s (&cmd, &cl, &cc, qrp);
        rc = br_run (c, cmd, buf, (size_t) (sz > 0 ? sz : 0), NULL, NULL);
    }
    free (cmd);
    free (buf);
    if (rc != 0) {
        free (qrp);
        builtin_error ("remote write failed (rc=%d): %s", rc, rpath);
        return -1;
    }

    free (qrp);
    br_preserve_meta (c, rpath, lst);
    return 0;
}

/* Best-effort metadata preservation: mode+mtime for -a (chmod/touch), and
 * owner/group for -o/-g (chown, numeric — needs root on the remote to take
 * effect, so failures are warned-not-fatal). Shared by all the send paths. */
static void
br_preserve_meta (const br_ctx *c, const char *rpath, const struct stat *lst)
{
    if (!c->aflag && !c->oflag && !c->gflag) return;
    char *qrp = br_sq (rpath);
    char *cmd = NULL; size_t cl = 0, cc = 0;
    int joined = 0;

    if (c->aflag) {
        char modebuf[32];
        snprintf (modebuf, sizeof modebuf, "%o", lst->st_mode & 07777);
        char mtbuf[32];
        struct tm mtm;
        if (gmtime_r (&lst->st_mtime, &mtm))
            strftime (mtbuf, sizeof mtbuf, "%Y-%m-%dT%H:%M:%SZ", &mtm);
        else
            snprintf (mtbuf, sizeof mtbuf, "1970-01-01T00:00:00Z");
        char *qmt = br_sq (mtbuf);
        br_append_s (&cmd, &cl, &cc, "chmod ");
        br_append_s (&cmd, &cl, &cc, modebuf);
        br_append_s (&cmd, &cl, &cc, " ");
        br_append_s (&cmd, &cl, &cc, qrp);
        br_append_s (&cmd, &cl, &cc, " && touch -d ");
        br_append_s (&cmd, &cl, &cc, qmt);
        br_append_s (&cmd, &cl, &cc, " ");
        br_append_s (&cmd, &cl, &cc, qrp);
        free (qmt);
        joined = 1;
    }
    if (c->oflag || c->gflag) {
        char own[48];
        if (c->oflag && c->gflag)
            snprintf (own, sizeof own, "%u:%u", (unsigned) lst->st_uid, (unsigned) lst->st_gid);
        else if (c->oflag)
            snprintf (own, sizeof own, "%u", (unsigned) lst->st_uid);
        else
            snprintf (own, sizeof own, ":%u", (unsigned) lst->st_gid);
        if (joined) br_append_s (&cmd, &cl, &cc, " && ");
        br_append_s (&cmd, &cl, &cc, "chown ");
        br_append_s (&cmd, &cl, &cc, own);
        br_append_s (&cmd, &cl, &cc, " ");
        br_append_s (&cmd, &cl, &cc, qrp);
    }
    int rc = br_run (c, cmd, NULL, 0, NULL, NULL);
    free (cmd); free (qrp);
    if (rc != 0 && c->vflag)
        fprintf (stderr, "rsync: warn: meta-preserve rc=%d: %s\n", rc, rpath);
}

/* Delta transfer of one regular file whose remote copy already exists.
 * Returns 0 if synced via delta; 1 to decline (caller should whole-file send);
 * never a hard error (delta is an optimization with a safe fallback). */
static int
br_send_file_delta (const br_ctx *c, const char *lpath, const char *rpath,
                    const struct stat *lst)
{
    if (c->nflag) return 0;
    char *qrp = br_sq (rpath);

    /* 1. fetch the remote signature. */
    char *scmd = NULL; size_t sl = 0, sc = 0;
    char bsbuf[32];
    snprintf (bsbuf, sizeof bsbuf, "%ld", c->block_size > 0 ? c->block_size : 0L);
    br_append_s (&scmd, &sl, &sc, "rsync --server-sig ");
    br_append_s (&scmd, &sl, &sc, qrp);
    br_append_s (&scmd, &sl, &sc, " ");
    br_append_s (&scmd, &sl, &sc, bsbuf);
    char *sigbuf = NULL; size_t siglen = 0;
    int rc = br_run (c, scmd, NULL, 0, &sigbuf, &siglen);
    free (scmd);
    if (rc != 0) { free (qrp); free (sigbuf); return 1; }   /* old/sh remote → fall back */
    br_sig sig;
    if (br_parse_sig ((unsigned char *) sigbuf, siglen, &sig) != 0) {
        free (qrp); free (sigbuf); return 1;
    }
    free (sigbuf);

    /* 2. read local new file + compute delta. */
    unsigned char *nb = NULL; size_t nl = 0;
    if (br_slurp (lpath, &nb, &nl) != 0) { br_free_sig (&sig); free (qrp); return 1; }
    char *delta = NULL; size_t dlen = 0;
    uint32_t dbg_nb = sig.nblocks, dbg_bs = sig.blocksize;
    br_compute_delta (nb, nl, &sig, &delta, &dlen);
    br_free_sig (&sig); free (nb);

    /* 3. only worth it if the delta is smaller than a whole-file send. */
    if (c->vflag > 2)
        fprintf (stderr, "rsync: dbg %s delta=%zu file=%zu nblocks=%u bs=%u\n",
                 rpath, dlen, nl, (unsigned) dbg_nb, (unsigned) dbg_bs);
    if (dlen >= nl) { free (delta); free (qrp); return 1; }

    /* 4. ship the delta; the remote reconstructs atomically. With -z the
     *    delta blob is zlib-framed and --server-patch inflates it ('z' arg). */
    char *pcmd = NULL; size_t pl = 0, pc = 0;
    br_append_s (&pcmd, &pl, &pc, "rsync --server-patch ");
    br_append_s (&pcmd, &pl, &pc, qrp);
    free (qrp);
    int prc;
    if (c->zflag) {
        unsigned char *cz = NULL; size_t czlen = 0;
        if (br_deflate ((const unsigned char *) delta, dlen, &cz, &czlen) != 0) {
            free (pcmd); free (delta); return 1;
        }
        br_append_s (&pcmd, &pl, &pc, " z");
        prc = br_run (c, pcmd, cz, czlen, NULL, NULL);
        free (cz);
    } else {
        prc = br_run (c, pcmd, delta, dlen, NULL, NULL);
    }
    free (pcmd); free (delta);
    if (prc != 0) return 1;        /* remote refused delta → fall back to whole-file */

    if (c->vflag > 1)
        fprintf (stderr, "rsync: delta %s (%zu delta / %zu file bytes)\n",
                 rpath, dlen, nl);
    br_preserve_meta (c, rpath, lst);
    return 0;
}

static int
br_send_symlink (const br_ctx *c, const char *lpath, const char *rpath)
{
    if (c->nflag) return 0;
    char tbuf[4096];
    ssize_t n = readlink (lpath, tbuf, sizeof tbuf - 1);
    if (n < 0) {
        builtin_error ("readlink %s: %s", lpath, strerror (errno));
        return -1;
    }
    tbuf[n] = 0;
    char *qtg = br_sq (tbuf);
    char *qrp = br_sq (rpath);
    char *cmd = NULL;
    size_t cl = 0, cc = 0;
    br_append_s (&cmd, &cl, &cc, "rm -f ");
    br_append_s (&cmd, &cl, &cc, qrp);
    br_append_s (&cmd, &cl, &cc, " && ln -s ");
    br_append_s (&cmd, &cl, &cc, qtg);
    br_append_s (&cmd, &cl, &cc, " ");
    br_append_s (&cmd, &cl, &cc, qrp);
    free (qtg); free (qrp);
    int rc = br_run (c, cmd, NULL, 0, NULL, NULL);
    free (cmd);
    if (rc != 0) {
        builtin_error ("remote ln -s failed (rc=%d): %s", rc, rpath);
        return -1;
    }
    return 0;
}

/* ----- recursive walk ------------------------------------------------- */

static int br_walk (br_ctx *c, const char *lpath, const char *rpath);
static int br_delete_extra (br_ctx *c, const char *lpath, const char *rpath);

/* lstat lpath, then dispatch. rpath is the corresponding remote path. */
static int
br_handle (br_ctx *c, const char *lpath, const char *rpath)
{
    struct stat lst;
    if (lstat (lpath, &lst) < 0) {
        builtin_error ("lstat %s: %s", lpath, strerror (errno));
        return -1;
    }

    if (S_ISDIR (lst.st_mode)) {
        if (br_mkdir (c, rpath) < 0) return -1;
        int rc = br_walk (c, lpath, rpath);
        if (rc == 0 && br_delete_extra (c, lpath, rpath) < 0) rc = -1;
        return rc;
    }

    if (S_ISLNK (lst.st_mode)) {
        if (c->vflag) fprintf (stderr, "%s (symlink)\n", rpath);
        return br_send_symlink (c, lpath, rpath);
    }

    if (S_ISREG (lst.st_mode)) {
        long long rsz = -1, rmt = -1;
        int prc = br_probe (c, rpath, &rsz, &rmt);
        if (prc == 0
            && rsz == (long long) lst.st_size
            && rmt == (long long) lst.st_mtime) {
            /* Match — skip. */
            return 0;
        }
        if (c->vflag) fprintf (stderr, "%s\n", rpath);
        /* Delta transfer when enabled and a remote basis exists; otherwise
         * (and on any delta decline) whole-file send. */
        if (c->delta_flag && prc == 0) {
            if (br_send_file_delta (c, lpath, rpath, &lst) == 0) return 0;
        }
        return br_send_file (c, lpath, rpath, &lst);
    }

    /* Other types (fifo, socket, block/char dev) — silently skip
     * with a verbose-only diagnostic so we don't crash the walk. */
    if (c->vflag) {
        fprintf (stderr, "rsync: skip non-regular: %s\n", lpath);
    }
    return 0;
}

/* Walk a local directory `lpath`, sending each entry to `rpath/entry`. */
static int
br_walk (br_ctx *c, const char *lpath, const char *rpath)
{
    DIR *d = opendir (lpath);
    if (!d) {
        builtin_error ("opendir %s: %s", lpath, strerror (errno));
        return -1;
    }
    int rc = 0;
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        if (de->d_name[0] == '.'
            && (de->d_name[1] == 0
                || (de->d_name[1] == '.' && de->d_name[2] == 0)))
            continue;
        char *lnext = br_join (lpath, de->d_name);
        char *rnext = br_join (rpath, de->d_name);
        if (br_handle (c, lnext, rnext) < 0) rc = -1;
        free (lnext); free (rnext);
    }
    closedir (d);
    return rc;
}

/* Remove remote entries directly under rpath that are absent from the
 * corresponding local directory lpath. Newline-bearing names are out of
 * scope for this v1 shell-command transport, matching the rest of the
 * line-oriented remote probing surface. */
static int
br_delete_extra (br_ctx *c, const char *lpath, const char *rpath)
{
    if (!c->delete_flag) return 0;
    if (c->nflag) return 0;

    char *qrp = br_sq (rpath);
    char *cmd = NULL;
    size_t cl = 0, cc = 0;
    br_append_s (&cmd, &cl, &cc, "for f in ");
    br_append_s (&cmd, &cl, &cc, qrp);
    br_append_s (&cmd, &cl, &cc, "/* ");
    br_append_s (&cmd, &cl, &cc, qrp);
    br_append_s (&cmd, &cl, &cc, "/.[!.]* ");
    br_append_s (&cmd, &cl, &cc, qrp);
    br_append_s (&cmd, &cl, &cc, "/..?*; do [ -e \"$f\" ] || [ -L \"$f\" ] || continue; printf '%s\\n' \"${f##*/}\"; done");
    free (qrp);

    char *out = NULL;
    size_t olen = 0;
    int rc = br_run (c, cmd, NULL, 0, &out, &olen);
    free (cmd);
    if (rc < 0) { free (out); return -1; }
    if (rc != 0) { free (out); return 0; }

    int ret = 0;
    char *save = NULL;
    for (char *name = strtok_r (out, "\n", &save);
         name;
         name = strtok_r (NULL, "\n", &save)) {
        if (!name[0] || !strcmp (name, ".") || !strcmp (name, ".."))
            continue;
        char *lnext = br_join (lpath, name);
        struct stat sb;
        int missing = (lstat (lnext, &sb) < 0 && errno == ENOENT);
        free (lnext);
        if (!missing) continue;

        char *rnext = br_join (rpath, name);
        if (c->vflag) fprintf (stderr, "%s (delete)\n", rnext);
        char *qrn = br_sq (rnext);
        char *dcmd = NULL;
        size_t dl = 0, dc = 0;
        br_append_s (&dcmd, &dl, &dc, "rm -rf -- ");
        br_append_s (&dcmd, &dl, &dc, qrn);
        free (qrn);
        int drc = br_run (c, dcmd, NULL, 0, NULL, NULL);
        free (dcmd);
        if (drc != 0) {
            builtin_error ("remote delete failed (rc=%d): %s", drc, rnext);
            ret = -1;
        }
        free (rnext);
    }
    free (out);
    return ret;
}

/* ----- argv plumbing ------------------------------------------------- */

/* A spec is "remote" (HOST:path or :path) when it has a ':' before any '/'. */
static int
br_is_remote (const char *s)
{
    const char *colon = strchr (s, ':');
    if (!colon) return 0;
    const char *slash = strchr (s, '/');
    return (!slash || colon < slash);
}

static int
br_parse_dest (br_ctx *c, const char *dest)
{
    /* Split on first ':'. If absent, treat as local-local copy with
     * empty host (caller decides whether that's an error). */
    const char *colon = strchr (dest, ':');
    if (!colon) {
        c->host = br_xstrdup ("");
        c->rdir = br_xstrdup (dest);
    } else {
        size_t hl = (size_t) (colon - dest);
        c->host = (char *) br_xmalloc (hl + 1);
        memcpy (c->host, dest, hl);
        c->host[hl] = 0;
        c->rdir = br_xstrdup (colon + 1);
    }
    /* Strip trailing slash from rdir (canonical). Leave "/" alone. */
    size_t rl = strlen (c->rdir);
    while (rl > 1 && c->rdir[rl - 1] == '/') {
        c->rdir[--rl] = 0;
    }
    if (rl == 0) {
        free (c->rdir);
        c->rdir = br_xstrdup (".");
    }
    return 0;
}

static int
br_one_src (br_ctx *c, const char *src)
{
    /* Trailing slash semantics: SRC/ → copy contents into DEST/;
     * SRC → copy SRC itself into DEST/. */
    size_t sl = strlen (src);
    int trailing = (sl > 0 && src[sl - 1] == '/') ? 1 : 0;
    char *lroot = br_xstrdup (src);
    /* Strip any number of trailing slashes for the lstat probe. */
    while (sl > 1 && lroot[sl - 1] == '/') lroot[--sl] = 0;

    struct stat lst;
    if (lstat (lroot, &lst) < 0) {
        builtin_error ("lstat %s: %s", src, strerror (errno));
        free (lroot);
        return -1;
    }

    int rc = 0;
    if (S_ISDIR (lst.st_mode) && trailing) {
        /* Pour SRC contents into c->rdir. */
        if (br_mkdir (c, c->rdir) < 0) { free (lroot); return -1; }
        rc = br_walk (c, lroot, c->rdir);
        if (rc == 0 && br_delete_extra (c, lroot, c->rdir) < 0) rc = -1;
    } else if (S_ISDIR (lst.st_mode)) {
        /* Create c->rdir/basename(src) then walk into it. */
        const char *bn = strrchr (lroot, '/');
        bn = bn ? bn + 1 : lroot;
        char *target = br_join (c->rdir, bn);
        if (br_mkdir (c, c->rdir) < 0) { free (lroot); free (target); return -1; }
        if (br_mkdir (c, target) < 0) { free (lroot); free (target); return -1; }
        rc = br_walk (c, lroot, target);
        if (rc == 0 && br_delete_extra (c, lroot, target) < 0) rc = -1;
        free (target);
    } else {
        /* Single file/symlink → DEST/basename(SRC). */
        const char *bn = strrchr (lroot, '/');
        bn = bn ? bn + 1 : lroot;
        char *target = br_join (c->rdir, bn);
        if (br_mkdir (c, c->rdir) < 0) { free (lroot); free (target); return -1; }
        rc = br_handle (c, lroot, target);
        free (target);
    }
    free (lroot);
    return rc;
}

static void
br_free_ctx (br_ctx *c)
{
    if (c->rsh_argv) {
        for (int i = 0; i < c->rsh_n; i++) free (c->rsh_argv[i]);
        free (c->rsh_argv);
    }
    free (c->host);
    free (c->rdir);
    free (c->rsync_path);
    memset (c, 0, sizeof *c);
}

/* ====================================================================== */
/* --native: speak the real rsync wire protocol (v27) to a stock          */
/* `rsync --server`. Reference: openrsync (research/refs/openrsync) and  */
/* its rsync.5. LE ints; client->server unmuxed, server->client muxed      */
/* (4-byte envelope, high byte 7 = data, else out-of-band/error).          */
/* ====================================================================== */

#define RS_PROTO 27
#define RS_S2LENGTH 2
#define RS_DELTA_MIN_BASIS 1
#define RS_CHAR_OFFSET 0
#define RS_MAX_CHUNK 32768

typedef struct {
    int      rfd, wfd;       /* read from server / write to server */
    pid_t    pid;
    int      mplex;          /* muxed reads active (after handshake) */
    uint32_t remain;         /* bytes left in the current data frame */
    int32_t  rver, seed;
} rs_sess;

/* blocking read of exactly n bytes; 0 ok / -1 eof|error */
static int rs_read_exact (int fd, void *buf, size_t n) {
    unsigned char *p = (unsigned char *) buf;
    while (n) {
        ssize_t r = read (fd, p, n);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        p += r; n -= (size_t) r;
    }
    return 0;
}

/* ensure remain>0 by reading mux frames; consumes/logs out-of-band msgs.
 * returns 0 ok, -1 io error, -2 remote error message (tag 1). */
static int rs_fill (rs_sess *s, int vflag) {
    while (s->remain == 0) {
        unsigned char h[4];
        if (rs_read_exact (s->rfd, h, 4) < 0) return -1;
        uint32_t tag = (uint32_t) h[0] | ((uint32_t) h[1] << 8)
                     | ((uint32_t) h[2] << 16) | ((uint32_t) h[3] << 24);
        uint32_t len = tag & 0xFFFFFF;
        int t = (int) (tag >> 24);
        if (t == 7) { s->remain = len; return 0; }
        /* out-of-band: a server log/error line */
        unsigned char mb[4096];
        uint32_t got = 0;
        while (got < len) {
            uint32_t k = len - got; if (k > sizeof mb) k = sizeof mb;
            if (rs_read_exact (s->rfd, mb, k) < 0) return -1;
            if (vflag) fprintf (stderr, "rsync: %.*s\n", (int) k, mb);
            got += k;
        }
        if (t - 7 == 1) return -2;     /* MSG_ERROR_XFER → remote error */
    }
    return 0;
}

static int rs_read_buf (rs_sess *s, void *buf, size_t n, int vflag) {
    unsigned char *p = (unsigned char *) buf;
    while (n > 0) {
        if (!s->mplex) { if (rs_read_exact (s->rfd, p, n) < 0) return -1; return 0; }
        if (s->remain == 0) { int r = rs_fill (s, vflag); if (r < 0) return r; }
        uint32_t k = (s->remain < n) ? s->remain : (uint32_t) n;
        if (rs_read_exact (s->rfd, p, k) < 0) return -1;
        s->remain -= k; p += k; n -= k;
    }
    return 0;
}

static int rs_read_int (rs_sess *s, int32_t *v, int vflag) {
    unsigned char b[4];
    int r = rs_read_buf (s, b, 4, vflag); if (r < 0) return r;
    *v = (int32_t) ((uint32_t) b[0] | ((uint32_t) b[1] << 8)
                  | ((uint32_t) b[2] << 16) | ((uint32_t) b[3] << 24));
    return 0;
}
static int rs_write_int (rs_sess *s, int32_t v) {
    unsigned char b[4] = { (unsigned char) v, (unsigned char) (v >> 8),
                           (unsigned char) (v >> 16), (unsigned char) (v >> 24) };
    return br_write_all (s->wfd, b, 4);
}
static int rs_write_byte (rs_sess *s, unsigned char v) { return br_write_all (s->wfd, &v, 1); }
static int rs_write_buf (rs_sess *s, const void *p, size_t n) { return br_write_all (s->wfd, p, n); }
/* rsync "long" (proto 27): int32 if 0..INT32_MAX else int32(-1)+int64 LE */
static int rs_write_long (rs_sess *s, int64_t v) {
    if (v >= 0 && v <= 0x7fffffff) return rs_write_int (s, (int32_t) v);
    if (rs_write_int (s, -1) < 0) return -1;
    unsigned char b[8];
    for (int i = 0; i < 8; i++) b[i] = (unsigned char) ((uint64_t) v >> (8 * i));
    return br_write_all (s->wfd, b, 8);
}
static int rs_read_long (rs_sess *s, int64_t *v, int vflag) {
    int32_t lo;
    if (rs_read_int (s, &lo, vflag) < 0) return -1;
    if (lo != -1) { *v = lo; return 0; }
    unsigned char b[8];
    if (rs_read_buf (s, b, 8, vflag) < 0) return -1;
    uint64_t u = 0; for (int i = 0; i < 8; i++) u |= (uint64_t) b[i] << (8 * i);
    *v = (int64_t) u; return 0;
}

/* rsync proto-27 block checksums. These are distinct from the bRD1 MD5
 * helpers above: checksum1 is rsync's adler-style rolling sum and checksum2
 * is seeded MD4, truncated on the wire to s2length bytes. */
static uint32_t rs_adler32 (const unsigned char *p, size_t len) {
    uint32_t s1 = 0, s2 = 0;
    for (size_t i = 0; i < len; i++) {
        uint32_t c = (uint32_t) p[i] + RS_CHAR_OFFSET;
        s1 += c;
        s2 += (uint32_t) (len - i) * c;
    }
    return (s1 & 0xffff) | ((s2 & 0xffff) << 16);
}

static uint32_t rs_adler_roll (uint32_t cs, unsigned char out,
                               unsigned char in, uint32_t blen) {
    uint32_t s1 = cs & 0xffff, s2 = (cs >> 16) & 0xffff;
    uint32_t outv = (uint32_t) out + RS_CHAR_OFFSET;
    uint32_t inv = (uint32_t) in + RS_CHAR_OFFSET;
    s1 = (s1 - outv + inv) & 0xffff;
    s2 = (s2 - blen * outv + s1) & 0xffff;
    return s1 | (s2 << 16);
}

static void rs_seed_bytes (int32_t seed, unsigned char sd[4]) {
    sd[0] = (unsigned char) seed;
    sd[1] = (unsigned char) (seed >> 8);
    sd[2] = (unsigned char) (seed >> 16);
    sd[3] = (unsigned char) (seed >> 24);
}

static void rs_md4_seed_init (MD4_CTX *md, int32_t seed) {
    unsigned char sd[4];
    rs_seed_bytes (seed, sd);
    MD4_Init (md);
    MD4_Update (md, sd, 4);
}

static void rs_block_sum2 (int32_t seed, const unsigned char *p,
                           size_t len, unsigned char out[16]) {
    MD4_CTX md;
    unsigned char sd[4];
    rs_seed_bytes (seed, sd);
    MD4_Init (&md);
    MD4_Update (&md, p, (unsigned long) len);
    MD4_Update (&md, sd, 4);
    MD4_Final (out, &md);
}

typedef struct {
    int32_t count, blength, s2length, remainder;
    uint32_t *weak;
    unsigned char *strong;
} rs_sig;

static void rs_free_sig (rs_sig *sig) {
    free (sig->weak);
    free (sig->strong);
    memset (sig, 0, sizeof *sig);
}

static long rs_sig_match (const rs_sig *sig, const br_went *tab, uint32_t w,
                          const unsigned char *win, uint32_t bs,
                          int32_t seed) {
    uint32_t lo = 0, hi = (uint32_t) sig->count;
    while (lo < hi) {
        uint32_t m = (lo + hi) / 2;
        if (tab[m].weak < w) lo = m + 1;
        else hi = m;
    }
    if (lo >= (uint32_t) sig->count || tab[lo].weak != w) return -1;
    unsigned char md[16];
    int have_md = 0;
    for (uint32_t i = lo; i < (uint32_t) sig->count && tab[i].weak == w; i++) {
        uint32_t idx = tab[i].idx;
        if (!have_md) {
            rs_block_sum2 (seed, win, bs, md);
            have_md = 1;
        }
        if (memcmp (md, sig->strong + (size_t) idx * (size_t) sig->s2length,
                    (size_t) sig->s2length) == 0)
            return (long) idx;
    }
    return -1;
}

static int rs_write_literal (rs_sess *s, MD4_CTX *md, const unsigned char *p,
                             size_t n) {
    while (n > 0) {
        size_t k = n > RS_MAX_CHUNK ? RS_MAX_CHUNK : n;
        if (rs_write_int (s, (int32_t) k) < 0) return -1;
        if (rs_write_buf (s, p, k) < 0) return -1;
        MD4_Update (md, p, (unsigned long) k);
        p += k; n -= k;
    }
    return 0;
}

static int rs_selftest_checksums (void) {
    const unsigned char a[] = "abcdef";
    const unsigned char b[] = "bcdefg";
    unsigned char md[16];
    static const unsigned char want_md[16] = {
        0xe1, 0xb5, 0xb6, 0xda, 0x71, 0x6b, 0x3f, 0x19,
        0x2b, 0x20, 0xad, 0x6f, 0xc7, 0x23, 0x61, 0xaf
    };
    uint32_t wa = rs_adler32 (a, 6);
    uint32_t wb = rs_adler32 (b, 6);
    uint32_t wr = rs_adler_roll (wa, 'a', 'g', 6);
    rs_block_sum2 (0x01020304, a, 6, md);
    if (wa != 0x08180255U || wb != 0x082d025bU || wr != wb
        || memcmp (md, want_md, sizeof want_md) != 0) {
        builtin_error ("rs checksum selftest failed weak=%08x shifted=%08x roll=%08x",
                       wa, wb, wr);
        return -1;
    }
    printf ("rs-checksums ok weak=%08x roll=%08x md4=e1b5b6da716b3f192b20ad6fc72361af\n",
            wa, wr);
    return 0;
}

/* spawn `RSH [host] servercmd` with bidirectional pipes. */
static int rs_spawn (const br_ctx *c, const char *servercmd, rs_sess *s) {
    int rp[2], wp[2];
    if (pipe (rp) < 0) return -1;
    if (pipe (wp) < 0) { close (rp[0]); close (rp[1]); return -1; }
    char **argv = br_build_argv (c, servercmd);
    pid_t pid = fork ();
    if (pid < 0) { free (argv); close (rp[0]); close (rp[1]); close (wp[0]); close (wp[1]); return -1; }
    if (pid == 0) {
        signal (SIGPIPE, SIG_DFL);
        dup2 (wp[0], 0); dup2 (rp[1], 1);
        close (rp[0]); close (rp[1]); close (wp[0]); close (wp[1]);
        execvp (argv[0], argv);
        fprintf (stderr, "rsync: execvp %s: %s\n", argv[0], strerror (errno));
        _exit (127);
    }
    free (argv);
    close (wp[0]); close (rp[1]);
    s->rfd = rp[0]; s->wfd = wp[1]; s->pid = pid;
    s->mplex = 0; s->remain = 0;
    return 0;
}

static int rs_handshake (rs_sess *s, int vflag) {
    if (rs_write_int (s, RS_PROTO) < 0) return -1;
    if (rs_read_int (s, &s->rver, vflag) < 0) return -1;
    if (rs_read_int (s, &s->seed, vflag) < 0) return -1;
    if (s->rver < RS_PROTO) { builtin_error ("remote rsync protocol %d < %d", s->rver, RS_PROTO); return -1; }
    s->mplex = 1;       /* server->client reads are muxed from here on */
    if (vflag) fprintf (stderr, "rsync: rsync handshake ok (proto %d, seed %d)\n", s->rver, s->seed);
    return 0;
}

/* Build the `rsync --server [--sender] <flags> . <path>` command string. */
static char *rs_server_cmd (const br_ctx *c, int sender_mode, const char *path,
                            int recursive, int links) {
    const char *rp = c->rsync_path ? c->rsync_path : "rsync";
    char *cmd = NULL; size_t l = 0, cc = 0;
    br_append_s (&cmd, &l, &cc, rp);
    br_append_s (&cmd, &l, &cc, " --server");
    if (sender_mode) br_append_s (&cmd, &l, &cc, " --sender");
    if (c->gflag) br_append_s (&cmd, &l, &cc, " -g");
    if (links) br_append_s (&cmd, &l, &cc, " -l");
    if (c->oflag) br_append_s (&cmd, &l, &cc, " -o");
    if (c->aflag) br_append_s (&cmd, &l, &cc, " -pt");   /* perms + times */
    if (recursive) br_append_s (&cmd, &l, &cc, " -r");
    if (c->nflag) br_append_s (&cmd, &l, &cc, " -n");
    br_append_s (&cmd, &l, &cc, " . ");
    char *qp = br_sq (path);
    br_append_s (&cmd, &l, &cc, qp);
    free (qp);
    return cmd;
}

/* ----- file list (sender) ----------------------------------------- */
typedef struct { char *rel; char *src; char *link; struct stat st; } rs_ent;

static int rs_ent_cmp (const void *a, const void *b) {
    return strcmp (((const rs_ent *) a)->rel, ((const rs_ent *) b)->rel);
}

typedef struct { rs_ent *v; int n, cap; int recursive, haslink; } rs_flist;

static void rs_flist_add (rs_flist *fl, const char *rel, const char *abs,
                          const struct stat *st, const char *link) {
    if (fl->n == fl->cap) {
        fl->cap = fl->cap ? fl->cap * 2 : 16;
        fl->v = (rs_ent *) br_xrealloc (fl->v, sizeof (rs_ent) * (size_t) fl->cap);
    }
    rs_ent *e = &fl->v[fl->n++];
    e->rel = br_xstrdup (rel);
    e->src = abs ? br_xstrdup (abs) : NULL;
    e->link = link ? br_xstrdup (link) : NULL;
    e->st = *st;
}

/* Recursively add `abs` (relative path `rel` under DEST) to the file list. */
static void rs_walk (rs_flist *fl, const char *abs, const char *rel) {
    struct stat st;
    if (lstat (abs, &st) != 0) return;
    if (S_ISDIR (st.st_mode)) {
        fl->recursive = 1;
        rs_flist_add (fl, rel, abs, &st, NULL);
        DIR *d = opendir (abs);
        if (d) {
            struct dirent *de;
            while ((de = readdir (d)) != NULL) {
                if (de->d_name[0] == '.' && (de->d_name[1] == 0
                    || (de->d_name[1] == '.' && de->d_name[2] == 0))) continue;
                char *ca = br_join (abs, de->d_name);
                char *cr = br_join (rel, de->d_name);
                rs_walk (fl, ca, cr);
                free (ca); free (cr);
            }
            closedir (d);
        }
    } else if (S_ISLNK (st.st_mode)) {
        char tgt[4096];
        ssize_t k = readlink (abs, tgt, sizeof tgt - 1);
        if (k < 0) return;
        tgt[k] = 0;
        fl->haslink = 1;
        rs_flist_add (fl, rel, NULL, &st, tgt);
    } else if (S_ISREG (st.st_mode)) {
        rs_flist_add (fl, rel, abs, &st, NULL);
    }
    /* other types skipped */
}

/* Build the sorted file list from the SOURCE operands (recursive for dirs). */
static int rs_build_flist (char **srcs, int nsrc, rs_flist *fl) {
    memset (fl, 0, sizeof *fl);
    for (int i = 0; i < nsrc; i++) {
        size_t sl = strlen (srcs[i]);
        int trailing = (sl > 0 && srcs[i][sl - 1] == '/');
        char *clean = br_xstrdup (srcs[i]);
        while (sl > 1 && clean[sl - 1] == '/') clean[--sl] = 0;
        struct stat st;
        if (lstat (clean, &st) != 0) {
            builtin_error ("%s: %s", srcs[i], strerror (errno));
            free (clean); return -1;
        }
        if (S_ISDIR (st.st_mode) && trailing) {
            DIR *d = opendir (clean);
            if (d) {
                struct dirent *de;
                while ((de = readdir (d)) != NULL) {
                    if (de->d_name[0] == '.' && (de->d_name[1] == 0
                        || (de->d_name[1] == '.' && de->d_name[2] == 0))) continue;
                    char *ca = br_join (clean, de->d_name);
                    rs_walk (fl, ca, de->d_name);
                    free (ca);
                }
                closedir (d);
            }
            fl->recursive = 1;
        } else {
            const char *bn = strrchr (clean, '/'); bn = bn ? bn + 1 : clean;
            rs_walk (fl, clean, bn);
        }
        free (clean);
    }
    qsort (fl->v, (size_t) fl->n, sizeof *fl->v, rs_ent_cmp);
    return 0;
}

static void rs_flist_free (rs_flist *fl) {
    for (int i = 0; i < fl->n; i++) { free (fl->v[i].rel); free (fl->v[i].src); free (fl->v[i].link); }
    free (fl->v);
    memset (fl, 0, sizeof *fl);
}

/* Send the file list (proto-27 encoding) + terminator. */
static int rs_flist_send (rs_sess *s, const br_ctx *c, const rs_flist *fl) {
    for (int i = 0; i < fl->n; i++) {
        const rs_ent *e = &fl->v[i];
        if (rs_write_byte (s, 0x40) < 0) return -1;                 /* FLIST_NAME_LONG */
        uint32_t nl = (uint32_t) strlen (e->rel);
        if (rs_write_int (s, (int32_t) nl) < 0) return -1;
        if (rs_write_buf (s, e->rel, nl) < 0) return -1;
        if (rs_write_long (s, (int64_t) e->st.st_size) < 0) return -1;
        if (rs_write_int (s, (int32_t) e->st.st_mtime) < 0) return -1;
        if (rs_write_int (s, (int32_t) e->st.st_mode) < 0) return -1;
        if (c->oflag && rs_write_int (s, (int32_t) e->st.st_uid) < 0) return -1;
        if (c->gflag && rs_write_int (s, (int32_t) e->st.st_gid) < 0) return -1;
        /* symlink target (only when we advertised -l, i.e. fl->haslink) */
        if (fl->haslink && S_ISLNK (e->st.st_mode) && e->link) {
            uint32_t tl = (uint32_t) strlen (e->link);
            if (rs_write_int (s, (int32_t) tl) < 0) return -1;
            if (rs_write_buf (s, e->link, tl) < 0) return -1;
        }
    }
    if (rs_write_byte (s, 0) < 0) return -1;     /* end of list */
    /* When we advertise -o/-g (and never --numeric-ids), the receiver expects
     * the uid→name and gid→name mapping lists immediately after the flist
     * terminator (before io_error).  We don't map names, so send EMPTY lists
     * (a lone zero-id terminator each) — the receiver then applies the numeric
     * uid/gid carried in the flist.  Omitting these desyncs the receiver. */
    if (c->oflag && rs_write_int (s, 0) < 0) return -1;
    if (c->gflag && rs_write_int (s, 0) < 0) return -1;
    return 0;
}

/* Send one regular file as a proto-27 token stream. When the receiver provides
 * a non-empty block set, emit negative COPY tokens for matching basis blocks
 * and literals for the changed runs; otherwise keep the all-literal path. */
static int rs_send_file_data (rs_sess *s, const br_ctx *c,
                              const rs_ent *e, int idx) {
    /* read the receiver's block request: blksz, len, csum, rem (16 bytes) */
    rs_sig sig;
    memset (&sig, 0, sizeof sig);
    if (rs_read_int (s, &sig.count, c->vflag) < 0
        || rs_read_int (s, &sig.blength, c->vflag) < 0
        || rs_read_int (s, &sig.s2length, c->vflag) < 0
        || rs_read_int (s, &sig.remainder, c->vflag) < 0) return -1;
    /* A fresh file's empty block set carries csum=0; only validate when blocks
       are actually present. */
    if (sig.count < 0) return -1;
    if (sig.count > 0) {
        if (sig.blength < 1 || sig.s2length != RS_S2LENGTH
            || sig.s2length > 16 || sig.remainder < 0)
            return -1;
        sig.weak = (uint32_t *) br_xmalloc (sizeof (uint32_t) * (size_t) sig.count);
        sig.strong = (unsigned char *) br_xmalloc ((size_t) sig.count * (size_t) sig.s2length);
        for (int32_t b = 0; b < sig.count; b++) {
            int32_t weak;
            if (rs_read_int (s, &weak, c->vflag) < 0
                || rs_read_buf (s, sig.strong + (size_t) b * (size_t) sig.s2length,
                                (size_t) sig.s2length, c->vflag) < 0) {
                rs_free_sig (&sig);
                return -1;
            }
            sig.weak[b] = (uint32_t) weak;
        }
    }
    /* echo the ack: idx, blksz, len, csum, rem (20 bytes) */
    if (rs_write_int (s, idx) < 0 || rs_write_int (s, sig.count) < 0
        || rs_write_int (s, sig.blength) < 0
        || rs_write_int (s, sig.s2length) < 0
        || rs_write_int (s, sig.remainder) < 0) {
        rs_free_sig (&sig);
        return -1;
    }

    /* whole-file MD4 over (seed_le || data); stream the data as literals. */
    MD4_CTX md;
    rs_md4_seed_init (&md, s->seed);

    if (sig.count > 0 && !c->whole_file) {
        unsigned char *nb = NULL;
        size_t nl = 0;
        if (br_slurp (e->src, &nb, &nl) != 0) { rs_free_sig (&sig); return -1; }

        br_went *tab = (br_went *) br_xmalloc (sizeof (br_went) * (size_t) sig.count);
        for (int32_t i = 0; i < sig.count; i++) {
            tab[i].weak = sig.weak[i];
            tab[i].idx = (uint32_t) i;
        }
        qsort (tab, (size_t) sig.count, sizeof *tab, br_wcmp);

        uint32_t bs = (uint32_t) sig.blength;
        size_t i = 0, lit = 0, literal_bytes = 0, copy_bytes = 0;
        if (bs > 0 && nl >= bs) {
            uint32_t w = rs_adler32 (nb, bs);
            for (;;) {
                long midx = rs_sig_match (&sig, tab, w, nb + i, bs, s->seed);
                if (midx >= 0) {
                    if (i > lit) {
                        size_t n = i - lit;
                        if (rs_write_literal (s, &md, nb + lit, n) < 0) {
                            free (tab); free (nb); rs_free_sig (&sig); return -1;
                        }
                        literal_bytes += n;
                    }
                    if (rs_write_int (s, (int32_t) (-(midx + 1))) < 0) {
                        free (tab); free (nb); rs_free_sig (&sig); return -1;
                    }
                    MD4_Update (&md, nb + i, bs);
                    copy_bytes += bs;
                    i += bs; lit = i;
                    if (i + bs <= nl) w = rs_adler32 (nb + i, bs);
                    else break;
                } else if (i + bs < nl) {
                    w = rs_adler_roll (w, nb[i], nb[i + bs], bs);
                    i++;
                } else {
                    break;
                }
            }
        }
        if (nl > lit) {
            if (rs_write_literal (s, &md, nb + lit, nl - lit) < 0) {
                free (tab); free (nb); rs_free_sig (&sig); return -1;
            }
            literal_bytes += nl - lit;
        }
        if (c->vflag >= 2)
            fprintf (stderr, "rsync: native delta send %s (%zu literal / %zu copy / %zu file bytes)\n",
                     e->rel, literal_bytes, copy_bytes, nl);
        free (tab);
        free (nb);
    } else {
        int fd = open (e->src, O_RDONLY);
        if (fd < 0) { rs_free_sig (&sig); return -1; }
        unsigned char *buf = (unsigned char *) br_xmalloc (RS_MAX_CHUNK);
        size_t literal_bytes = 0;
        for (;;) {
            ssize_t r = read (fd, buf, RS_MAX_CHUNK);
            if (r < 0) {
                if (errno == EINTR) continue;
                close (fd); free (buf); rs_free_sig (&sig); return -1;
            }
            if (r == 0) break;
            if (rs_write_int (s, (int32_t) r) < 0
                || rs_write_buf (s, buf, (size_t) r) < 0) {
                close (fd); free (buf); rs_free_sig (&sig); return -1;
            }
            MD4_Update (&md, buf, (unsigned long) r);
            literal_bytes += (size_t) r;
        }
        close (fd);
        free (buf);
        if (c->vflag >= 2)
            fprintf (stderr, "rsync: native whole send %s (%zu literal / 0 copy / %lld file bytes)\n",
                     e->rel, literal_bytes, (long long) e->st.st_size);
    }

    rs_free_sig (&sig);
    if (rs_write_int (s, 0) < 0) return -1;     /* end-of-tokens */
    unsigned char fmd[16];
    MD4_Final (fmd, &md);
    return rs_write_buf (s, fmd, 16);
}

/* The sender data phase + phase changes. Receiver only requests regular
   files (it materializes dirs/symlinks from the flist itself). */
static int rs_sender_phase (rs_sess *s, const br_ctx *c, const rs_flist *fl) {
    int phase = 0;
    while (phase < 2) {
        int32_t idx;
        if (rs_read_int (s, &idx, c->vflag) < 0) return -1;
        if (idx == -1) { if (rs_write_int (s, -1) < 0) return -1; phase++; continue; }
        if (idx < 0 || idx >= fl->n) { builtin_error ("rsync: bad file index %d", idx); return -1; }
        if (!S_ISREG (fl->v[idx].st.st_mode)) { builtin_error ("rsync: data requested for non-file idx %d", idx); return -1; }
        if (c->nflag) { if (rs_write_int (s, idx) < 0) return -1; continue; }  /* dry-run skip */
        if (rs_send_file_data (s, c, &fl->v[idx], idx) < 0) return -1;
    }
    /* Drain the receiver's end-of-sequence marker(s) until EOF so its final
       writes don't hit EPIPE on our close (clean session teardown). */
    { int32_t x; while (rs_read_int (s, &x, c->vflag) == 0) {} }
    return 0;
}

/* Full native push: spawn `rsync --server`, handshake, send flist, transfer. */
static int br_rsync_run (const br_ctx *c, int sender_mode, const char *path,
                         char **srcs, int nsrc) {
    rs_flist fl;
    if (rs_build_flist (srcs, nsrc, &fl) != 0) return -1;

    char *servercmd = rs_server_cmd (c, sender_mode, path, fl.recursive, fl.haslink);
    rs_sess s; memset (&s, 0, sizeof s);
    struct sigaction old, ign;
    memset (&ign, 0, sizeof ign); ign.sa_handler = SIG_IGN;
    sigaction (SIGPIPE, &ign, &old);
    int rc = -1;
    if (rs_spawn (c, servercmd, &s) == 0) {
        if (rs_handshake (&s, c->vflag) == 0
            && rs_flist_send (&s, c, &fl) == 0
            && rs_write_int (&s, 0) == 0          /* io_error = 0 */
            && rs_sender_phase (&s, c, &fl) == 0) {
            rc = 0;
        }
        close (s.wfd); close (s.rfd);
        int st; while (waitpid (s.pid, &st, 0) < 0 && errno == EINTR) {}
        if (rc == 0 && !(WIFEXITED (st) && WEXITSTATUS (st) == 0)) {
            if (c->vflag) fprintf (stderr, "rsync: remote rsync exited non-zero\n");
        }
    }
    sigaction (SIGPIPE, &old, NULL);
    free (servercmd);
    rs_flist_free (&fl);
    return rc;
}

/* ====================================================================== */
/* --native PULL: client-receiver from a stock `rsync --server --sender`. */
/* ====================================================================== */

typedef struct {
    char    *name;          /* relpath under DEST */
    char    *link;          /* symlink target or NULL */
    int64_t  size;
    int32_t  mtime, mode, uid, gid;
} rs_rent;

/* rsync sorts the file list by relative path (strcmp on the name) and the
 * per-file indices on the wire refer to that SORTED order — see openrsync
 * flist_cmp(). We receive entries in send order, so we must re-sort to the
 * same order or our index requests land on the wrong entry (e.g. a symlink
 * where we expect a regular file → "error in rsync protocol data stream"). */
static int rs_rent_cmp (const void *a, const void *b) {
    const rs_rent *x = (const rs_rent *) a, *y = (const rs_rent *) b;
    return strcmp (x->name, y->name);
}

static int rs_read_byte (rs_sess *s, unsigned char *b, int vflag) {
    return rs_read_buf (s, b, 1, vflag);
}

/* Consume one id→name mapping list: [int32 id][byte len][len name bytes]…
 * terminated by a zero id.  Returns 0/-1.  Names are discarded. */
static int rs_skip_idname_list (rs_sess *s, int vflag) {
    for (;;) {
        int32_t id;
        if (rs_read_int (s, &id, vflag) < 0) return -1;
        if (id == 0) return 0;
        unsigned char len;
        if (rs_read_byte (s, &len, vflag) < 0) return -1;
        if (len) {
            unsigned char nm[256];
            if (rs_read_buf (s, nm, (size_t) len, vflag) < 0) return -1;
        }
    }
}

/* Parse the server's file list (handles proto-27 dedup flags). 0/-1. */
static int rs_flist_recv (rs_sess *s, const br_ctx *c, rs_rent **out, int *nout) {
    rs_rent *v = NULL; int n = 0, cap = 0;
    char prev[4096] = "";
    int32_t pmtime = 0, pmode = 0, puid = 0, pgid = 0;
    int vflag = c->vflag;
    for (;;) {
        unsigned char flag;
        if (rs_read_byte (s, &flag, vflag) < 0) goto err;
        if (flag == 0) break;                       /* end of list */
        int inherit = 0;
        if (flag & 0x20) { unsigned char ib; if (rs_read_byte (s, &ib, vflag) < 0) goto err; inherit = ib; }
        int32_t namelen;
        if (flag & 0x40) { if (rs_read_int (s, &namelen, vflag) < 0) goto err; }
        else { unsigned char nb; if (rs_read_byte (s, &nb, vflag) < 0) goto err; namelen = nb; }
        if (namelen < 0 || inherit < 0 || (size_t) (inherit + namelen) >= sizeof prev) goto err;
        char name[4096];
        memcpy (name, prev, (size_t) inherit);
        if (namelen && rs_read_buf (s, name + inherit, (size_t) namelen, vflag) < 0) goto err;
        name[inherit + namelen] = 0;
        snprintf (prev, sizeof prev, "%s", name);
        int64_t size; if (rs_read_long (s, &size, vflag) < 0) goto err;
        int32_t mtime = pmtime;
        if (!(flag & 0x80)) { if (rs_read_int (s, &mtime, vflag) < 0) goto err; pmtime = mtime; }
        int32_t mode = pmode;
        if (!(flag & 0x02)) { if (rs_read_int (s, &mode, vflag) < 0) goto err; pmode = mode; }
        int32_t uid = puid, gid = pgid;
        if (c->oflag && !(flag & 0x08)) { if (rs_read_int (s, &uid, vflag) < 0) goto err; puid = uid; }
        if (c->gflag && !(flag & 0x10)) { if (rs_read_int (s, &gid, vflag) < 0) goto err; pgid = gid; }
        char *link = NULL;
        if (S_ISLNK ((mode_t) mode)) {           /* we always pass -l on pull */
            int32_t ll; if (rs_read_int (s, &ll, vflag) < 0) goto err;
            if (ll < 0 || ll >= 65536) goto err;
            link = (char *) br_xmalloc ((size_t) ll + 1);
            if (ll && rs_read_buf (s, link, (size_t) ll, vflag) < 0) { free (link); goto err; }
            link[ll] = 0;
        }
        if (n == cap) { cap = cap ? cap * 2 : 32; v = (rs_rent *) br_xrealloc (v, sizeof *v * (size_t) cap); }
        v[n].name = br_xstrdup (name); v[n].link = link;
        v[n].size = size; v[n].mtime = mtime; v[n].mode = mode; v[n].uid = uid; v[n].gid = gid;
        n++;
    }
    /* After the flist terminator, a sender invoked with -o/-g (and without
     * --numeric-ids, which we never pass) appends the uid→name and gid→name
     * mapping lists: repeated [int32 id != 0][byte namelen][name], ended by a
     * zero id.  We don't use the names, but we MUST consume the lists or the
     * caller's next read (io_error) lands mid-list and desyncs the stream. */
    if (c->oflag && rs_skip_idname_list (s, vflag) < 0) goto err;
    if (c->gflag && rs_skip_idname_list (s, vflag) < 0) goto err;
    *out = v; *nout = n;
    return 0;
err:
    for (int i = 0; i < n; i++) { free (v[i].name); free (v[i].link); }
    free (v);
    return -1;
}

/* Request + receive one regular file from the sender; write it under dest. */
static int rs_recv_one_file (rs_sess *s, const br_ctx *c, const rs_rent *f,
                             int idx, const char *dest) {
    char *full = br_join (dest, f->name);
    unsigned char *basis = NULL;
    size_t basis_len = 0;
    int32_t count = 0, blength = 0, remainder = 0;

    if (!c->whole_file) {
        struct stat st;
        if (stat (full, &st) == 0 && S_ISREG (st.st_mode)
            && st.st_size >= RS_DELTA_MIN_BASIS
            && br_slurp (full, &basis, &basis_len) == 0 && basis_len > 0) {
            uint64_t bs64 = (uint64_t) br_blocksize (basis_len, c->block_size);
            uint64_t cnt64 = ((uint64_t) basis_len + bs64 - 1) / bs64;
            if (cnt64 <= 0x7fffffffU && bs64 <= 0x7fffffffU) {
                count = (int32_t) cnt64;
                blength = (int32_t) bs64;
                remainder = (int32_t) (basis_len % (size_t) blength);
            } else {
                free (basis); basis = NULL; basis_len = 0;
            }
        }
    }

    /* request: idx + block checksum set, or an empty set for no basis. */
    if (rs_write_int (s, idx) < 0
        || rs_write_int (s, count) < 0
        || rs_write_int (s, blength) < 0
        || rs_write_int (s, count ? RS_S2LENGTH : 0) < 0
        || rs_write_int (s, remainder) < 0) {
        free (basis); free (full); return -1;
    }
    for (int32_t b = 0; b < count; b++) {
        size_t off = (size_t) b * (size_t) blength;
        size_t n = (size_t) blength;
        if (b == count - 1 && remainder > 0) n = (size_t) remainder;
        if (off + n > basis_len) n = basis_len - off;
        unsigned char md[16];
        uint32_t weak = rs_adler32 (basis + off, n);
        rs_block_sum2 (s->seed, basis + off, n, md);
        if (rs_write_int (s, (int32_t) weak) < 0
            || rs_write_buf (s, md, RS_S2LENGTH) < 0) {
            free (basis); free (full); return -1;
        }
    }
    if (c->vflag >= 3)
        fprintf (stderr, "rsync: native recv sum %s (%d blocks / %d blength / %d s2length)\n",
                 f->name, count, blength, count ? RS_S2LENGTH : 0);
    /* sender ack: idx, count, blength, s2length, remainder (20 bytes) */
    int32_t aidx, acnt, ablen, acsum, arem;
    if (rs_read_int (s, &aidx, c->vflag) < 0 || rs_read_int (s, &acnt, c->vflag) < 0
        || rs_read_int (s, &ablen, c->vflag) < 0 || rs_read_int (s, &acsum, c->vflag) < 0
        || rs_read_int (s, &arem, c->vflag) < 0) {
        free (basis); free (full); return -1;
    }
    if (aidx != idx || acnt != count || ablen != blength
        || acsum != (count ? RS_S2LENGTH : 0) || arem != remainder) {
        if (c->vflag)
            fprintf (stderr, "rsync: bad checksum ack on %s\n", f->name);
        free (basis); free (full); return -1;
    }
    /* token stream -> reconstruct literals plus negative COPY tokens. */
    char *buf = NULL; size_t bl = 0, bc = 0;
    size_t literal_bytes = 0, copy_bytes = 0;
    MD4_CTX md;
    rs_md4_seed_init (&md, s->seed);
    for (;;) {
        int32_t tok;
        if (rs_read_int (s, &tok, c->vflag) < 0) {
            free (buf); free (basis); free (full); return -1;
        }
        if (tok == 0) break;
        if (tok > 0) {
            unsigned char *chunk = (unsigned char *) br_xmalloc ((size_t) tok);
            if (rs_read_buf (s, chunk, (size_t) tok, c->vflag) < 0) {
                free (chunk); free (buf); free (basis); free (full); return -1;
            }
            br_append (&buf, &bl, &bc, (const char *) chunk, (size_t) tok);
            MD4_Update (&md, chunk, (unsigned long) tok);
            literal_bytes += (size_t) tok;
            free (chunk);
        } else {
            int64_t bidx = -(int64_t) tok - 1;
            if (!basis || bidx < 0 || bidx >= acnt || ablen <= 0) {
                free (buf); free (basis); free (full); return -1;
            }
            size_t off = (size_t) bidx * (size_t) ablen;
            if (off >= basis_len) {
                free (buf); free (basis); free (full); return -1;
            }
            size_t n = (size_t) ablen;
            if (bidx == acnt - 1 && arem > 0) n = (size_t) arem;
            if (off + n > basis_len) n = basis_len - off;
            br_append (&buf, &bl, &bc, (const char *) (basis + off), n);
            MD4_Update (&md, basis + off, (unsigned long) n);
            copy_bytes += n;
        }
    }
    unsigned char want[16], got[16];
    if (rs_read_buf (s, want, 16, c->vflag) < 0) {
        free (buf); free (basis); free (full); return -1;
    }
    MD4_Final (got, &md);
    if (memcmp (want, got, 16) != 0) {
        if (c->vflag) fprintf (stderr, "rsync: checksum mismatch on %s\n", f->name);
        free (buf); free (basis); free (full); return -1;
    }
    if (c->vflag >= 2)
        fprintf (stderr, "rsync: native delta recv %s (%zu literal / %zu copy / %zu file bytes)\n",
                 f->name, literal_bytes, copy_bytes, bl);
    if (!c->nflag) {
        br_local_mkparent (full);
        int rc = br_atomic_write (full, (const unsigned char *) (buf ? buf : (char *) ""), bl);
        if (rc == 0) br_apply_meta_local (c, full, (uint32_t) f->mode,
                                          (uint64_t) (uint32_t) f->mtime,
                                          (uint32_t) f->uid, (uint32_t) f->gid, 0);
        if (rc != 0) { free (buf); free (basis); free (full); return -1; }
    }
    if (c->vflag) fprintf (stderr, "%s\n", f->name);
    free (basis);
    free (full);
    free (buf);
    return 0;
}

/* Native pull: spawn `rsync --server --sender`, receive the tree into dest. */
static int br_rsync_pull (br_ctx *c, const char *rpath, const char *dest) {
    c->lflag = 1;
    char *servercmd = rs_server_cmd (c, 1 /* server is sender */, rpath, 1 /* -r */, 1 /* -l */);
    rs_sess s; memset (&s, 0, sizeof s);
    struct sigaction old, ign;
    memset (&ign, 0, sizeof ign); ign.sa_handler = SIG_IGN;
    sigaction (SIGPIPE, &ign, &old);
    int rc = -1;
    rs_rent *fl = NULL; int n = 0;
    if (rs_spawn (c, servercmd, &s) == 0) {
        int32_t ioerr;
        if (rs_handshake (&s, c->vflag) == 0
            && rs_write_int (&s, 0) == 0            /* receiver: exclusion count 0 */
            && rs_flist_recv (&s, c, &fl, &n) == 0
            && rs_read_int (&s, &ioerr, c->vflag) == 0) {
            rc = 0;
            /* match rsync's sorted index order before requesting by index */
            qsort (fl, (size_t) n, sizeof *fl, rs_rent_cmp);
            if (!c->nflag) br_local_mkdirp (dest);
            /* materialize dirs and symlinks directly from the flist */
            for (int i = 0; i < n && rc == 0; i++) {
                if (S_ISDIR ((mode_t) fl[i].mode)) {
                    if (!c->nflag) {
                        char *full = br_join (dest, fl[i].name);
                        br_local_mkdirp (full);
                        br_apply_meta_local (c, full, (uint32_t) fl[i].mode,
                            (uint64_t) (uint32_t) fl[i].mtime, (uint32_t) fl[i].uid, (uint32_t) fl[i].gid, 0);
                        free (full);
                    }
                    if (c->vflag) fprintf (stderr, "%s/\n", fl[i].name);
                } else if (S_ISLNK ((mode_t) fl[i].mode)) {
                    if (!c->nflag && fl[i].link) {
                        char *full = br_join (dest, fl[i].name);
                        br_local_mkparent (full); unlink (full);
                        if (symlink (fl[i].link, full) == 0)
                            br_apply_meta_local (c, full, (uint32_t) fl[i].mode,
                                (uint64_t) (uint32_t) fl[i].mtime, (uint32_t) fl[i].uid, (uint32_t) fl[i].gid, 1);
                        free (full);
                    }
                }
            }
            /* request + receive each regular file (phase 1).  Under -n the
             * server is also in dry-run and sends NO file data, so we must
             * not request any file (we'd block forever) — just list it. */
            for (int i = 0; i < n && rc == 0; i++)
                if (S_ISREG ((mode_t) fl[i].mode)) {
                    if (c->nflag) { if (c->vflag) fprintf (stderr, "%s\n", fl[i].name); }
                    else if (rs_recv_one_file (&s, c, &fl[i], i, dest) < 0) rc = -1;
                }
            /* end phase 1, no phase-2 redownloads, then drain.
             * After the phase-2 -1 we close the write side so the server's
             * trailing read() hits EOF and it exits — otherwise both ends
             * block reading (it waits for us to close, we wait for it to
             * send) and the session deadlocks at shutdown. */
            if (rc == 0) {
                if (rs_write_int (&s, -1) < 0) rc = -1;
                int32_t x;
                while (rc == 0 && rs_read_int (&s, &x, c->vflag) == 0) {
                    if (x == -1) { if (rs_write_int (&s, -1) < 0) rc = -1; break; }
                }
                close (s.wfd); s.wfd = -1;
                if (rc == 0) { int32_t y; while (rs_read_int (&s, &y, c->vflag) == 0) {} }
            }
        }
        if (s.wfd >= 0) close (s.wfd);
        close (s.rfd);
        int st; while (waitpid (s.pid, &st, 0) < 0 && errno == EINTR) {}
    }
    sigaction (SIGPIPE, &old, NULL);
    free (servercmd);
    for (int i = 0; i < n; i++) { free (fl[i].name); free (fl[i].link); }
    free (fl);
    return rc;
}

/* ====================================================================== */
/* --native DAEMON mode: connect to an rsync:// daemon (rsyncd, port 873). */
/* @RSYNCD greeting → module select → arg lines → seed → sender/receiver.  */
/* ====================================================================== */

/* A spec is an rsync daemon URL: rsync://host[:port]/module/path  or
 * host::module/path. */
static int rs_is_url (const char *s) {
    if (strncmp (s, "rsync://", 8) == 0) return 1;
    const char *c = strstr (s, "::");
    /* host::path — the "::" must come before any '/' to be a daemon spec */
    if (c) { const char *sl = strchr (s, '/'); return (!sl || c < sl); }
    return 0;
}

/* Parse a daemon URL into host, port, module, and "module/path" (modpath).
 * All out strings are malloc'd. Returns 0/-1. */
static int rs_parse_url (const char *s, char **host, int *port,
                         char **module, char **modpath) {
    *host = *module = *modpath = NULL; *port = 873;
    const char *rest;
    if (strncmp (s, "rsync://", 8) == 0) {
        const char *h = s + 8;
        const char *slash = strchr (h, '/');
        if (!slash) return -1;
        size_t hl = (size_t) (slash - h);
        char *hostport = br_xmalloc (hl + 1);
        memcpy (hostport, h, hl); hostport[hl] = 0;
        char *colon = strchr (hostport, ':');
        if (colon) { *colon = 0; *port = atoi (colon + 1); }
        *host = br_xstrdup (hostport);
        free (hostport);
        rest = slash + 1;                 /* "module/path" */
    } else {
        const char *cc = strstr (s, "::");
        size_t hl = (size_t) (cc - s);
        *host = br_xmalloc (hl + 1);
        memcpy (*host, s, hl); (*host)[hl] = 0;
        rest = cc + 2;                    /* "module/path" */
    }
    *modpath = br_xstrdup (rest);
    const char *slash = strchr (rest, '/');
    size_t ml = slash ? (size_t) (slash - rest) : strlen (rest);
    *module = br_xmalloc (ml + 1);
    memcpy (*module, rest, ml); (*module)[ml] = 0;
    if ((*module)[0] == 0) { free (*host); free (*module); free (*modpath); return -1; }
    return 0;
}

static int rs_connect_tcp (const char *host, int port) {
    char portbuf[16]; snprintf (portbuf, sizeof portbuf, "%d", port);
    struct addrinfo hints, *res = NULL, *ai;
    memset (&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo (host, portbuf, &hints, &res) != 0) return -1;
    int sd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        sd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sd < 0) continue;
        if (connect (sd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close (sd); sd = -1;
    }
    freeaddrinfo (res);
    return sd;
}

static int rs_write_line (rs_sess *s, const char *str) {
    if (br_write_all (s->wfd, str, strlen (str)) < 0) return -1;
    return br_write_all (s->wfd, "\n", 1);
}
/* read a line (up to cap-1) terminated by \n (stripped, with optional \r). */
static int rs_read_line (rs_sess *s, char *buf, size_t cap) {
    size_t i = 0;
    for (;;) {
        unsigned char b;
        if (rs_read_exact (s->rfd, &b, 1) < 0) return -1;
        if (b == '\n') break;
        if (i + 1 < cap) buf[i++] = (char) b;
    }
    if (i && buf[i - 1] == '\r') i--;
    buf[i] = 0;
    return (int) i;
}

/* @RSYNCD greeting + module select; reads lines until "@RSYNCD: OK".
 * Sets s->rver. Returns 0 ok, -1 error/auth-required. */
static int rs_daemon_greet (rs_sess *s, const char *module, int vflag) {
    char line[1024];
    snprintf (line, sizeof line, "@RSYNCD: %d", RS_PROTO);
    if (rs_write_line (s, line) < 0) return -1;
    if (rs_write_line (s, module) < 0) return -1;
    for (;;) {
        if (rs_read_line (s, line, sizeof line) < 0) return -1;
        if (strncmp (line, "@RSYNCD: ", 9) == 0) {
            const char *cp = line + 9;
            while (*cp == ' ' || *cp == '\t') cp++;
            if (strcmp (cp, "OK") == 0) return 0;
            if (strncmp (cp, "AUTHREQD", 8) == 0) {
                builtin_error ("rsync daemon requires authentication (unsupported)");
                return -1;
            }
            if (strncmp (cp, "EXIT", 4) == 0) return 0;
            int maj = 0;
            if (sscanf (cp, "%d", &maj) == 1) s->rver = maj;   /* version line */
            continue;
        }
        if (strncmp (line, "@ERROR", 6) == 0) {
            builtin_error ("rsync daemon: %s", line);
            return -1;
        }
        if (vflag && line[0]) fprintf (stderr, "%s\n", line);   /* MOTD */
    }
}

/* Send the server arg lines + blank-line terminator (daemon variant). */
static int rs_daemon_args (rs_sess *s, const br_ctx *c, int sender_mode,
                           int recursive, int links, const char *modpath) {
    if (rs_write_line (s, "--server") < 0) return -1;
    if (sender_mode && rs_write_line (s, "--sender") < 0) return -1;
    if (c->gflag && rs_write_line (s, "-g") < 0) return -1;
    if (links && rs_write_line (s, "-l") < 0) return -1;
    if (c->oflag && rs_write_line (s, "-o") < 0) return -1;
    if (c->aflag && rs_write_line (s, "-pt") < 0) return -1;
    if (recursive && rs_write_line (s, "-r") < 0) return -1;
    if (c->nflag && rs_write_line (s, "-n") < 0) return -1;
    if (rs_write_line (s, ".") < 0) return -1;
    if (rs_write_line (s, modpath) < 0) return -1;
    return br_write_all (s->wfd, "\n", 1);     /* empty line terminates args */
}

/* Daemon push: send local SRCs to rsync://…/module/path. */
static int br_rsync_daemon_push (br_ctx *c, const char *url, char **srcs, int nsrc) {
    char *host = NULL, *module = NULL, *modpath = NULL; int port;
    if (rs_parse_url (url, &host, &port, &module, &modpath) != 0) {
        builtin_error ("bad rsync URL: %s", url); return -1;
    }
    rs_flist fl;
    if (rs_build_flist (srcs, nsrc, &fl) != 0) { free (host); free (module); free (modpath); return -1; }

    struct sigaction old, ign;
    memset (&ign, 0, sizeof ign); ign.sa_handler = SIG_IGN;
    sigaction (SIGPIPE, &ign, &old);
    int rc = -1, sd = rs_connect_tcp (host, port);
    if (sd < 0) { builtin_error ("connect %s:%d: %s", host, port, strerror (errno)); }
    else {
        rs_sess s; memset (&s, 0, sizeof s); s.rfd = s.wfd = sd;
        if (rs_daemon_greet (&s, module, c->vflag) == 0
            && rs_daemon_args (&s, c, 0, fl.recursive, fl.haslink, modpath) == 0
            && rs_read_int (&s, &s.seed, c->vflag) == 0) {
            s.mplex = 1;
            if (rs_flist_send (&s, c, &fl) == 0
                && rs_write_int (&s, 0) == 0
                && rs_sender_phase (&s, c, &fl) == 0)
                rc = 0;
        }
        close (sd);
    }
    sigaction (SIGPIPE, &old, NULL);
    rs_flist_free (&fl);
    free (host); free (module); free (modpath);
    return rc;
}

/* Daemon pull: receive rsync://…/module/path into local dest. */
static int br_rsync_daemon_pull (br_ctx *c, const char *url, const char *dest) {
    char *host = NULL, *module = NULL, *modpath = NULL; int port;
    if (rs_parse_url (url, &host, &port, &module, &modpath) != 0) {
        builtin_error ("bad rsync URL: %s", url); return -1;
    }
    c->lflag = 1;
    struct sigaction old, ign;
    memset (&ign, 0, sizeof ign); ign.sa_handler = SIG_IGN;
    sigaction (SIGPIPE, &ign, &old);
    int rc = -1, sd = rs_connect_tcp (host, port);
    rs_rent *flv = NULL; int n = 0;
    if (sd < 0) { builtin_error ("connect %s:%d: %s", host, port, strerror (errno)); }
    else {
        rs_sess s; memset (&s, 0, sizeof s); s.rfd = s.wfd = sd;
        int32_t ioerr;
        if (rs_daemon_greet (&s, module, c->vflag) == 0
            && rs_daemon_args (&s, c, 1, 1, 1, modpath) == 0
            && rs_read_int (&s, &s.seed, c->vflag) == 0) {
            s.mplex = 1;
            if (rs_write_int (&s, 0) == 0           /* receiver exclusion 0 */
                && rs_flist_recv (&s, c, &flv, &n) == 0
                && rs_read_int (&s, &ioerr, c->vflag) == 0) {
                rc = 0;
                qsort (flv, (size_t) n, sizeof *flv, rs_rent_cmp);
                if (!c->nflag) br_local_mkdirp (dest);
                for (int i = 0; i < n && rc == 0; i++) {
                    if (S_ISDIR ((mode_t) flv[i].mode)) {
                        if (!c->nflag) { char *full = br_join (dest, flv[i].name);
                            br_local_mkdirp (full);
                            br_apply_meta_local (c, full, (uint32_t) flv[i].mode,
                                (uint64_t)(uint32_t) flv[i].mtime, (uint32_t) flv[i].uid, (uint32_t) flv[i].gid, 0);
                            free (full); }
                    } else if (S_ISLNK ((mode_t) flv[i].mode) && flv[i].link) {
                        if (!c->nflag) { char *full = br_join (dest, flv[i].name);
                            br_local_mkparent (full); unlink (full);
                            if (symlink (flv[i].link, full) == 0)
                                br_apply_meta_local (c, full, (uint32_t) flv[i].mode,
                                    (uint64_t)(uint32_t) flv[i].mtime, (uint32_t) flv[i].uid, (uint32_t) flv[i].gid, 1);
                            free (full); }
                    }
                }
                for (int i = 0; i < n && rc == 0; i++)
                    if (S_ISREG ((mode_t) flv[i].mode)) {
                        if (c->nflag) { if (c->vflag) fprintf (stderr, "%s\n", flv[i].name); }
                        else if (rs_recv_one_file (&s, c, &flv[i], i, dest) < 0) rc = -1;
                    }
                if (rc == 0) {
                    if (rs_write_int (&s, -1) < 0) rc = -1;
                    int32_t x;
                    while (rc == 0 && rs_read_int (&s, &x, c->vflag) == 0)
                        if (x == -1) { rs_write_int (&s, -1); break; }
                    /* half-close the socket so the daemon's trailing read hits
                     * EOF and exits, then drain its final stats to EOF. */
                    shutdown (sd, SHUT_WR);
                    if (rc == 0) { int32_t y; while (rs_read_int (&s, &y, c->vflag) == 0) {} }
                }
            }
        }
        close (sd);
    }
    sigaction (SIGPIPE, &old, NULL);
    for (int i = 0; i < n; i++) { free (flv[i].name); free (flv[i].link); }
    free (flv);
    free (host); free (module); free (modpath);
    return rc;
}

/* ----- bash entry point ---------------------------------------------- */

int
rsync_builtin (WORD_LIST *list)
{
    br_ctx c;
    memset (&c, 0, sizeof c);

    /* Server sub-modes (run on the remote via the RSH command) — handled
     * before normal arg parsing. These implement the v2 delta protocol's two
     * round trips. See BASHRSYNC_V2_DELTA.md. */
    if (list && list->word) {
        const char *w0 = list->word->word;
        if (!strcmp (w0, "--selftest-rs-checksums")) {
            return rs_selftest_checksums () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        }
        if (!strcmp (w0, "--server-sig")) {
            const char *path = list->next ? list->next->word->word : NULL;
            long ov = 0;
            if (list->next && list->next->next)
                ov = atol (list->next->next->word->word);
            if (!path) { builtin_error ("--server-sig PATH [BLOCKSIZE]"); return EX_USAGE; }
            return br_server_sig (path, ov) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        }
        if (!strcmp (w0, "--server-patch")) {
            const char *path = list->next ? list->next->word->word : NULL;
            int compressed = (list->next && list->next->next
                              && !strcmp (list->next->next->word->word, "z"));
            if (!path) { builtin_error ("--server-patch PATH [z]"); return EX_USAGE; }
            return br_server_patch (path, compressed) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        }
        if (!strcmp (w0, "--server-recvz")) {
            const char *path = list->next ? list->next->word->word : NULL;
            if (!path) { builtin_error ("--server-recvz PATH"); return EX_USAGE; }
            return br_server_recvz (path) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        }
        if (!strcmp (w0, "--server-send")) {
            const char *path = list->next ? list->next->word->word : NULL;
            const char *mode = (list->next && list->next->next) ? list->next->next->word->word : "tree";
            int contents = !strcmp (mode, "contents");
            int compress = (list->next && list->next->next && list->next->next->next
                            && !strcmp (list->next->next->next->word->word, "z"));
            if (!path) { builtin_error ("--server-send PATH [tree|contents] [z]"); return EX_USAGE; }
            return br_server_send (path, contents, compress) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        }
    }

    /* Default RSH command: ssh. */
    const char *rsh_str = "ssh";

    /* Collect positional args; flags are pre-positional. */
    char **pos = NULL;
    int posn = 0, poscap = 0;

    WORD_LIST *p = list;
    while (p) {
        const char *w = p->word->word;
        if (!strcmp (w, "--version")) {
            printf ("%s\n", BR_VERSION_STR);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--help") || !strcmp (w, "-h")) {
            printf ("rsync [-a] [-v] [-n] [-z] [-o] [-g] [-W] [--delta] [--block-size N]\n");
            printf ("          [--delete [--delete-confirm]] [-e RSH] SRC [SRC...] DEST\n");
            printf ("Push, pull and rsync-daemon transfers:\n");
            printf ("  push : SRC [SRC...] [HOST]:DEST          (ssh+tar subset; --delta for rolling-checksum delta)\n");
            printf ("  pull : [HOST]:SRC DEST                   (with --native, speaks stock rsync proto-27)\n");
            printf ("  daemon: rsync://HOST[:PORT]/MODULE/PATH  (or HOST::MODULE/PATH) as SRC or DEST\n");
            printf ("--native/--rsync-protocol interops with stock rsync (--server [--sender]);\n");
            printf ("native transfers use proto-27 delta when a basis exists unless -W/--whole-file is set.\n");
            printf ("Use -e 'sh -c' for v1 local tests, or -e \"$BASH -c\" for --delta local tests\n");
            printf ("(so the server sub-modes find the builtin).\n");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--delta")) { c.delta_flag = 1; p = p->next; continue; }
        if (!strcmp (w, "--whole-file") || !strcmp (w, "-W")) { c.whole_file = 1; p = p->next; continue; }
        if (!strcmp (w, "--no-delta")) { c.whole_file = 1; c.delta_flag = 0; p = p->next; continue; }
        if (!strcmp (w, "--native") || !strcmp (w, "--rsync-protocol")) { c.native = 1; p = p->next; continue; }
        if (!strcmp (w, "--rsync-path")) {
            p = p->next;
            if (!p) { builtin_error ("--rsync-path requires an argument"); br_free_ctx (&c); return EX_USAGE; }
            c.rsync_path = br_xstrdup (p->word->word);
            p = p->next; continue;
        }
        if (!strcmp (w, "--block-size") || !strcmp (w, "-B")) {
            p = p->next;
            if (!p) { builtin_error ("--block-size requires an argument"); br_free_ctx (&c); return EX_USAGE; }
            c.block_size = atol (p->word->word);
            if (c.block_size < 1) { builtin_error ("--block-size must be >= 1"); br_free_ctx (&c); return EX_USAGE; }
            p = p->next; continue;
        }
        if (!strcmp (w, "-a")) { c.aflag = 1; c.oflag = 1; c.gflag = 1; p = p->next; continue; }
        if (!strcmp (w, "-o") || !strcmp (w, "--owner")) { c.oflag = 1; p = p->next; continue; }
        if (!strcmp (w, "-g") || !strcmp (w, "--group")) { c.gflag = 1; p = p->next; continue; }
        if (!strcmp (w, "-z") || !strcmp (w, "--compress")) { c.zflag = 1; p = p->next; continue; }
        if (!strcmp (w, "-v")) { c.vflag++; p = p->next; continue; }
        if (!strcmp (w, "-vv")) { c.vflag += 2; p = p->next; continue; }
        if (!strcmp (w, "-vvv")) { c.vflag += 3; p = p->next; continue; }
        if (!strcmp (w, "--delete")) { c.delete_flag = 1; p = p->next; continue; }
        if (!strcmp (w, "--delete-confirm")) { c.delete_confirm = 1; p = p->next; continue; }
        if (!strcmp (w, "-n") || !strcmp (w, "--dry-run")) {
            c.nflag = 1; p = p->next; continue;
        }
        if (!strcmp (w, "-e")) {
            p = p->next;
            if (!p) { builtin_error ("-e requires an argument"); br_free_ctx (&c); return EX_USAGE; }
            rsh_str = p->word->word;
            p = p->next; continue;
        }
        if (!strcmp (w, "--")) { p = p->next; break; }
        /* clustered short boolean flags: -og, -avz, -vv, -an, ... */
        if (w[0] == '-' && w[1] && w[1] != '-') {
            int ok = 1;
            for (const char *cp = w + 1; *cp; cp++) {
                switch (*cp) {
                    case 'a': c.aflag = 1; c.oflag = 1; c.gflag = 1; break;
                    case 'v': c.vflag++; break;
                    case 'n': c.nflag = 1; break;
                    case 'o': c.oflag = 1; break;
                    case 'g': c.gflag = 1; break;
                    case 'z': c.zflag = 1; break;
                    case 'W': c.whole_file = 1; break;
                    default:  ok = 0; break;
                }
                if (!ok) break;
            }
            if (ok) { p = p->next; continue; }
        }
        if (w[0] == '-' && w[1]) {
            builtin_error ("unsupported flag in v1 subset: %s", w);
            br_free_ctx (&c);
            return EX_USAGE;
        }
        /* positional */
        if (posn == poscap) {
            poscap = poscap ? poscap * 2 : 8;
            pos = (char **) br_xrealloc (pos, sizeof (char *) * (size_t) poscap);
        }
        pos[posn++] = (char *) w;
        p = p->next;
    }
    /* Drain any remaining post-`--` positional args. */
    while (p) {
        if (posn == poscap) {
            poscap = poscap ? poscap * 2 : 8;
            pos = (char **) br_xrealloc (pos, sizeof (char *) * (size_t) poscap);
        }
        pos[posn++] = (char *) p->word->word;
        p = p->next;
    }

    if (posn < 2) {
        builtin_error ("usage: rsync [-a] [-v] [-n] [-e RSH] SRC [SRC...] DEST");
        free (pos);
        br_free_ctx (&c);
        return EX_USAGE;
    }

    c.rsh_n = br_split (rsh_str, &c.rsh_argv);
    if (c.rsh_n < 1) {
        builtin_error ("-e RSH must contain at least one word");
        free (pos);
        br_free_ctx (&c);
        return EX_USAGE;
    }

    const char *dest = pos[posn - 1];

    /* DAEMON mode (rsync://host/module/path or host::module/path) — always
     * speaks the real rsync protocol over a TCP socket; checked before the
     * rsh-shaped HOST:path detection (host::… also has a ':' before '/'). */
    if (rs_is_url (dest)) {
        int rc = br_rsync_daemon_push (&c, dest, pos, posn - 1);
        free (pos); br_free_ctx (&c);
        return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    {
        int any_url = 0;
        for (int i = 0; i < posn - 1; i++) if (rs_is_url (pos[i])) { any_url = 1; break; }
        if (any_url) {
            int rc = 0;
            for (int i = 0; i < posn - 1; i++) {
                if (!rs_is_url (pos[i])) { builtin_error ("cannot mix daemon and local sources: %s", pos[i]); rc = -1; continue; }
                if (br_rsync_daemon_pull (&c, pos[i], dest) < 0) rc = -1;
            }
            free (pos); br_free_ctx (&c);
            return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
        }
    }

    /* PULL mode: a remote source (HOST:path) with a local destination.
     * `host:p` / `:p` is remote (a ':' before the first '/'). */
    int dest_remote = br_is_remote (dest);
    int any_src_remote = 0;
    for (int i = 0; i < posn - 1; i++)
        if (br_is_remote (pos[i])) { any_src_remote = 1; break; }

    if (!dest_remote && any_src_remote) {
        int rc = 0;
        for (int i = 0; i < posn - 1; i++) {
            const char *src = pos[i];
            if (!br_is_remote (src)) {
                builtin_error ("cannot mix remote and local sources: %s", src);
                rc = -1; continue;
            }
            const char *colon = strchr (src, ':');
            size_t hl = (size_t) (colon - src);
            free (c.host);
            c.host = (char *) br_xmalloc (hl + 1);
            memcpy (c.host, src, hl); c.host[hl] = 0;
            int prc = c.native ? br_rsync_pull (&c, colon + 1, dest)
                               : br_pull (&c, colon + 1, dest);
            if (prc < 0) rc = -1;
        }
        free (pos);
        br_free_ctx (&c);
        return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }

    /* PUSH mode (remote dest, or all-local). */
    br_parse_dest (&c, dest);

    /* --native: speak the real rsync protocol to a stock `rsync --server`. */
    if (c.native) {
        int rc = br_rsync_run (&c, 0 /* client is sender */, c.rdir,
                               pos, posn - 1);
        free (pos);
        br_free_ctx (&c);
        return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }

    if (c.delete_flag && !c.delete_confirm && !strcmp (c.rdir, "/")) {
        builtin_error ("--delete refuses destination / without --delete-confirm");
        free (pos);
        br_free_ctx (&c);
        return EX_USAGE;
    }

    int rc = 0;
    for (int i = 0; i < posn - 1; i++) {
        if (br_one_src (&c, pos[i]) < 0) rc = -1;
    }
    free (pos);
    br_free_ctx (&c);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

char *rsync_doc[] = {
    "Minimal rsync subset: push, pull, native proto-27 and daemon transfers.",
    "The rsh shim supports optional rsync-to-rsync delta with --delta;",
    "native proto-27 mode uses rsync delta by default when a basis exists.",
    "",
    "    rsync [-a] [-v] [-n] [-z] [-o] [-g] [-W] \\",
    "             [--delta] [--block-size N] \\",
    "             [--delete [--delete-confirm]] [-e RSH] SRC [SRC...] DEST",
    "        DEST = [HOST]:PATH, or use [HOST]:SRC DEST for pull mode.",
    "        --native / --rsync-protocol interoperates with stock rsync --server;",
    "        rsync://HOST/MODULE/PATH and HOST::MODULE/PATH use daemon mode.",
    "    rsync --version    rsync --help",
    "",
    "Flags:",
    "    -a   archive: preserve mode + mtime on transferred files",
    "    -v   verbose: print one line per transferred entry (-vv: delta stats)",
    "    -n   dry-run: walk + probe, never write",
    "    -z   compress rsync-to-rsync payloads",
    "    -o/-g preserve owner/group where permitted",
    "    -e   override RSH command (default: ssh)",
    "    --delta            send only changed blocks for files that already exist",
    "                       on the remote rsync rsh shim.",
    "    --native           speak stock rsync proto-27; delta is automatic when",
    "                       a destination basis exists.",
    "    -W, --whole-file   force the native all-literal/whole-file path",
    "    --no-delta         alias for native whole-file behavior",
    "    --block-size N     delta block size in bytes (default: ~sqrt(filesize))",
    "    --delete           remove destination entries absent from source",
    "    --delete-confirm   required with --delete when DEST is /",
    "",
    "Still deferred: --partial/--inplace, bandwidth limit, -H, -A/-X.",
    "See BASHRSYNC_V2_DELTA.md.",
    (char *) NULL
};

struct builtin rsync_struct = {
    "rsync",
    rsync_builtin,
    BUILTIN_ENABLED,
    rsync_doc,
    "rsync [-a] [-v] [-n] [-e RSH] SRC [SRC...] [HOST]:DEST",
    0
};
