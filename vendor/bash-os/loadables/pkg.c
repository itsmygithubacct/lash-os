/* SPDX-License-Identifier: MIT */
/* pkg.c — Bash loadable module manager for bash-os.
 *
 * H05 direction: the accepted .pkg package is a signed POSIX ustar
 * envelope, optionally xz-compressed, containing a top-level MANIFEST and
 * exactly one loadable/<name>.so. The MANIFEST declares
 * name/version/builtin/abi/arch/sha256 and optional loadable deps. The v2
 * package installs only to the bash-os loadables directory plus pkg state.
 * The older files/ rootfs payload and hooks/ maintainer-script surface remains
 * legacy compatibility and requires an explicit --legacy-rootfs opt-in or
 * BASHPKG_ALLOW_LEGACY_ROOTFS=1.
 *
 * Verbs (see pkg_doc[]):
 *   pack DIR OUT.pkg            (engineering helper — bundle DIR/)
 *   install PKGFILE                 (install from a local .pkg)
 *   install PKGNAME                 (install from cache; resolve deps)
 *   remove PKGNAME                  (uninstall loadable/state; legacy rootfs
 *                                    removal requires explicit opt-in)
 *   list                            (list installed packages)
 *   info PKGNAME|PKGFILE           (print MANIFEST)
 *   search QUERY [--repo NAME] [--arch ARCH]
 *                                  (substring or glob search; --repo
 *                                   narrows to a single repo INDEX set)
 *   update [--arch ARCH]           (refresh repo INDEXes from sources)
 *   fetch [--arch ARCH]            (materialize http(s) sources locally)
 *   download PKGNAME [--arch ARCH] (copy repo package into cache)
 *   upgrade PACKAGE|PKGNAME        (replace from a package path or repo;
 *                                   named upgrades prefer a valid delta)
 *   verify PKGNAME|PKGFILE         (verify installed state or package file)
 *   load PKGNAME                    (verify + enable installed loadable)
 *   unload PKGNAME                  (unsupported: dlclose policy pending)
 *
 * v2 loadable state tree (per spec):
 *   /var/lib/pkg/installed/<name>/MANIFEST  — frozen at install
 *   /var/lib/pkg/installed/<name>/sha256    — v2 loadable digest
 *   /var/lib/pkg/cache/                     — downloaded .pkg
 *   /var/lib/pkg/repos/<repo>/INDEX         — legacy repo metadata mirror
 *   /var/lib/pkg/repos/<repo>/<arch>/INDEX  — arch-scoped metadata mirror
 *   /etc/pkg/sources.list                   — repo URL list (newline)
 * Legacy rootfs compatibility state additionally records:
 *   /var/lib/pkg/installed/<name>/files     — legacy newline path list
 *
 * Trust: install requires a sibling <PKGFILE>.sig by default and refuses
 * to proceed unless bashsignify verification succeeds. download verifies
 * indexed package SHA-256 and caches the indexed signature sidecar for the
 * install gate. Delta upgrade reconstructs a full candidate blob and feeds it
 * back through this same signed install path. Unsigned bootstrap/development
 * installs require the explicit -A override; legacy rootfs packages
 * additionally require the explicit compatibility opt-in.
 * For multi-arch repositories, each <repo>/<arch>/INDEX is independently
 * verified against its own sibling INDEX.sig by the same bashsignify path.
 * The operator-supplied bashsignify trust anchor authorizes those signatures:
 * publishers may use one key for all arch INDEXes or distinct per-arch keys,
 * but key trust is operator-managed, not embedded in INDEX records.
 *
 * --- LICENSE ---
 * MIT License
 *
 * Copyright (c) 2026 bash_linux contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED. See the full MIT text for the standard disclaimer.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <ctype.h>
#include <fnmatch.h>
#include <lzma.h>

#include "loadables.h"
#include "_mbedtls_sha256.h"

/* gcc's -Wformat-truncation flags every "%s/suffix" composition where
 * the source could theoretically fill BPKG_PATH_MAX, even though the
 * fixed BPKG_PATH_MAX bound at the input layer makes the chain safe in
 * practice. Silence rather than chase one false-positive at a time. */
#if defined(__GNUC__) && !defined(__clang__)
# pragma GCC diagnostic ignored "-Wformat-truncation"
#endif

/* ---- Tunable defaults ----------------------------------------------- */

#define BPKG_STATE_DIR     "/var/lib/pkg"
#define BPKG_INSTALLED_DIR BPKG_STATE_DIR "/installed"
#define BPKG_CACHE_DIR     BPKG_STATE_DIR "/cache"
#define BPKG_REPOS_DIR     BPKG_STATE_DIR "/repos"
#define BPKG_SOURCES_LIST  "/etc/pkg/sources.list"
#define BPKG_INSTALL_ROOT  "/"
#define BPKG_LOADABLES_DIR "/usr/lib/bash-os/loadables"

#define BPKG_TAR_BLOCK     512
#define BPKG_PATH_MAX      4096
#define BPKG_NAME_MAX      256
#define BPKG_MAX_DEPS      64
#define BPKG_MAX_FILES     65536

#define BPKG_DELTA_MAGIC   "BPKGDELTA1\n"

/* ---- Small dynamic byte buffer -------------------------------------- */

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} bp_buf;

struct bpkg_child_guard {
    struct sigaction old_chld;
    sigset_t oldmask;
};

static int
bpkg_child_guard_begin (struct bpkg_child_guard *g)
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
bpkg_child_guard_parent_end (struct bpkg_child_guard *g)
{
    sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
    sigaction (SIGCHLD, &g->old_chld, NULL);
}

static void
bpkg_child_guard_child_end (struct bpkg_child_guard *g)
{
    sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
}

static int
bp_buf_reserve (bp_buf *b, size_t need)
{
    if (b->cap - b->len >= need) return 0;
    size_t nc = b->cap ? b->cap : 4096;
    while (nc - b->len < need) {
        if (nc > (SIZE_MAX / 2)) return -1;
        nc *= 2;
    }
    unsigned char *p = realloc (b->data, nc);
    if (!p) return -1;
    b->data = p;
    b->cap = nc;
    return 0;
}

static int
bp_buf_append (bp_buf *b, const void *src, size_t n)
{
    if (!n) return 0;
    if (bp_buf_reserve (b, n) < 0) return -1;
    memcpy (b->data + b->len, src, n);
    b->len += n;
    return 0;
}

static void
bp_buf_free (bp_buf *b)
{
    free (b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

/* ---- Search-match helpers ------------------------------------------- */

/* A query carrying any shell-wildcard metacharacter is interpreted as a
 * glob (matched via fnmatch against the whole target); otherwise the
 * historical substring match via strstr is preserved so plain `search
 * foo` keeps the v1 behavior. */
static int
bp_query_is_glob (const char *q)
{
    for (const char *p = q; *p; p++) {
        if (*p == '*' || *p == '?' || *p == '[') return 1;
    }
    return 0;
}

static int
bp_match (const char *query, const char *target, int is_glob)
{
    if (is_glob) return fnmatch (query, target, 0) == 0;
    return strstr (target, query) != NULL;
}

/* ---- File I/O helpers ------------------------------------------------ */

static int
bp_read_all_fd (int fd, bp_buf *out)
{
    unsigned char tmp[8192];
    ssize_t n;
    while ((n = read (fd, tmp, sizeof tmp)) > 0) {
        if (bp_buf_append (out, tmp, (size_t) n) < 0) return -1;
    }
    return n < 0 ? -1 : 0;
}

static int
bp_read_file (const char *path, bp_buf *out)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int rc = bp_read_all_fd (fd, out);
    close (fd);
    return rc;
}

static int
bp_write_file_atomic (const char *path, const void *data, size_t n,
                      mode_t mode)
{
    char tmp[BPKG_PATH_MAX];
    if (snprintf (tmp, sizeof tmp, "%s.tmp.%d", path, (int) getpid ()) >=
        (int) sizeof tmp) return -1;
    int fd = open (tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return -1;
    const unsigned char *p = data;
    size_t left = n;
    while (left > 0) {
        ssize_t w = write (fd, p, left);
        if (w < 0) {
            if (errno == EINTR) continue;
            close (fd);
            unlink (tmp);
            return -1;
        }
        p += w; left -= (size_t) w;
    }
    if (close (fd) < 0) {
        unlink (tmp);
        return -1;
    }
    if (rename (tmp, path) < 0) {
        unlink (tmp);
        return -1;
    }
    return 0;
}

/* mkdir -p — accept an absolute or relative path, create every leading
 * directory with mode 0755. EEXIST treated as success. Trailing slash
 * tolerated. */
static int
bp_mkdir_p (const char *path)
{
    if (!path || !*path) return -1;
    char buf[BPKG_PATH_MAX];
    size_t n = strlen (path);
    if (n >= sizeof buf) return -1;
    memcpy (buf, path, n + 1);
    /* Trim trailing slashes (but keep leading "/"). */
    while (n > 1 && buf[n - 1] == '/') buf[--n] = 0;
    for (size_t i = 1; i <= n; i++) {
        if (buf[i] == '/' || buf[i] == 0) {
            int saved = buf[i];
            buf[i] = 0;
            if (mkdir (buf, 0755) < 0 && errno != EEXIST) return -1;
            buf[i] = saved;
        }
    }
    return 0;
}

/* ---- xz autodetect + decompression via liblzma --------------------- */

static int
bp_is_xz (const unsigned char *data, size_t n)
{
    static const unsigned char magic[6] = {
        0xFD, '7', 'z', 'X', 'Z', 0x00
    };
    return n >= 6 && memcmp (data, magic, 6) == 0;
}

static int
bp_xz_decompress (const unsigned char *in, size_t in_len, bp_buf *out)
{
    lzma_stream s = LZMA_STREAM_INIT;
    if (lzma_stream_decoder (&s, UINT64_MAX, LZMA_CONCATENATED) !=
        LZMA_OK) return -1;
    s.next_in = in;
    s.avail_in = in_len;
    unsigned char tmp[8192];
    for (;;) {
        s.next_out = tmp;
        s.avail_out = sizeof tmp;
        lzma_ret ret = lzma_code (&s,
            s.avail_in == 0 ? LZMA_FINISH : LZMA_RUN);
        size_t got = sizeof tmp - s.avail_out;
        if (got > 0 && bp_buf_append (out, tmp, got) < 0) {
            lzma_end (&s);
            return -1;
        }
        if (ret == LZMA_STREAM_END) break;
        if (ret != LZMA_OK) {
            lzma_end (&s);
            return -1;
        }
    }
    lzma_end (&s);
    return 0;
}

static int
bp_xz_compress (const unsigned char *in, size_t in_len, bp_buf *out)
{
    lzma_stream s = LZMA_STREAM_INIT;
    if (lzma_easy_encoder (&s, 6, LZMA_CHECK_CRC64) != LZMA_OK)
        return -1;
    s.next_in = in;
    s.avail_in = in_len;
    unsigned char tmp[8192];
    for (;;) {
        s.next_out = tmp;
        s.avail_out = sizeof tmp;
        lzma_ret ret = lzma_code (&s,
            s.avail_in == 0 ? LZMA_FINISH : LZMA_RUN);
        size_t got = sizeof tmp - s.avail_out;
        if (got > 0 && bp_buf_append (out, tmp, got) < 0) {
            lzma_end (&s);
            return -1;
        }
        if (ret == LZMA_STREAM_END) break;
        if (ret != LZMA_OK) {
            lzma_end (&s);
            return -1;
        }
    }
    lzma_end (&s);
    return 0;
}

/* ---- ustar tar reader/writer --------------------------------------- */

typedef struct {
    char  name[100];
    char  mode[8];
    char  uid[8];
    char  gid[8];
    char  size[12];
    char  mtime[12];
    char  chksum[8];
    char  typeflag;
    char  linkname[100];
    char  magic[6];
    char  version[2];
    char  uname[32];
    char  gname[32];
    char  devmajor[8];
    char  devminor[8];
    char  prefix[155];
    char  pad[12];
} bp_tar_hdr;

static long
bp_octal (const char *s, size_t n)
{
    long v = 0;
    size_t i = 0;
    while (i < n && (s[i] == ' ' || s[i] == '\t')) i++;
    while (i < n && s[i] >= '0' && s[i] <= '7') {
        v = (v << 3) | (s[i] - '0');
        i++;
    }
    return v;
}

static unsigned
bp_tar_chksum (const bp_tar_hdr *h)
{
    const unsigned char *p = (const unsigned char *) h;
    unsigned sum = 0;
    /* The chksum field is treated as 8 spaces during computation. */
    for (size_t i = 0; i < BPKG_TAR_BLOCK; i++) {
        if (i >= 148 && i < 156) sum += ' ';
        else sum += p[i];
    }
    return sum;
}

/* Iterate tar entries. cb returns 0 to continue, <0 on error, >0 to
 * stop iteration. opaque is forwarded to the callback. The callback
 * receives the header, the full pathname (prefix+name joined), the
 * raw byte stream pointer for the entry's content, and its byte count.
 */
typedef int (*bp_tar_cb) (const bp_tar_hdr *h, const char *path,
                          const unsigned char *body, size_t body_len,
                          void *opaque);

static int
bp_tar_iter (const unsigned char *data, size_t len, bp_tar_cb cb,
             void *opaque)
{
    size_t off = 0;
    int saw_eof = 0;
    while (off + BPKG_TAR_BLOCK <= len) {
        const bp_tar_hdr *h = (const bp_tar_hdr *) (data + off);
        /* Two consecutive zero blocks → end. */
        int all_zero = 1;
        for (size_t i = 0; i < BPKG_TAR_BLOCK; i++) {
            if (((const unsigned char *) h)[i] != 0) {
                all_zero = 0; break;
            }
        }
        if (all_zero) { saw_eof = 1; break; }

        /* Validate checksum. */
        long stored = bp_octal (h->chksum, sizeof h->chksum);
        unsigned actual = bp_tar_chksum (h);
        if (stored != (long) actual) return -1;

        long sz = bp_octal (h->size, sizeof h->size);
        if (sz < 0) return -1;
        size_t body_len = (size_t) sz;
        const unsigned char *body = data + off + BPKG_TAR_BLOCK;
        if (off + BPKG_TAR_BLOCK + body_len > len) return -1;

        char path[BPKG_PATH_MAX];
        size_t pl = 0;
        if (h->prefix[0]) {
            size_t pn = strnlen (h->prefix, sizeof h->prefix);
            if (pn >= sizeof path) return -1;
            memcpy (path, h->prefix, pn);
            pl = pn;
            if (pl < sizeof path - 1) path[pl++] = '/';
        }
        size_t nn = strnlen (h->name, sizeof h->name);
        if (pl + nn >= sizeof path) return -1;
        memcpy (path + pl, h->name, nn);
        path[pl + nn] = 0;

        int rc = cb (h, path, body, body_len, opaque);
        if (rc != 0) return rc;

        size_t pad = (BPKG_TAR_BLOCK - (body_len % BPKG_TAR_BLOCK))
                     % BPKG_TAR_BLOCK;
        off += BPKG_TAR_BLOCK + body_len + pad;
    }
    /* Refuse archives that ran out before the trailing zero-block marker
     * (truncated mid-stream). A legitimate archive ends with at least
     * one all-zero block before the buffer ends. Without this guard,
     * a kill-mid-extract truncation silently terminates the iter and
     * the caller records partial install state — breaking the rollback
     * contract pinned by 256-pkg-install-rollback.sh case 1. */
    if (!saw_eof) return -1;
    return 0;
}

/* Build a tar header for a regular file or directory. */
static void
bp_tar_emit_hdr (bp_tar_hdr *h, const char *name, size_t size,
                 mode_t mode, char typeflag, time_t mtime)
{
    memset (h, 0, sizeof *h);
    snprintf (h->name, sizeof h->name, "%s", name);
    snprintf (h->mode,  sizeof h->mode,  "%07o",  (unsigned) (mode & 07777));
    snprintf (h->uid,   sizeof h->uid,   "%07o",  0);
    snprintf (h->gid,   sizeof h->gid,   "%07o",  0);
    snprintf (h->size,  sizeof h->size,  "%011lo", (unsigned long) size);
    snprintf (h->mtime, sizeof h->mtime, "%011lo", (unsigned long) mtime);
    memset (h->chksum, ' ', sizeof h->chksum);
    h->typeflag = typeflag;
    memcpy (h->magic, "ustar", 5);
    h->magic[5] = 0;
    memcpy (h->version, "00", 2);
    snprintf (h->uname, sizeof h->uname, "%s", "root");
    snprintf (h->gname, sizeof h->gname, "%s", "root");

    unsigned sum = bp_tar_chksum (h);
    snprintf (h->chksum, sizeof h->chksum, "%06o", sum);
    h->chksum[6] = 0;
    h->chksum[7] = ' ';
}

/* ---- MANIFEST parser ------------------------------------------------ */

static int bp_hex64 (const char *s);

typedef struct {
    char name[BPKG_NAME_MAX];
    char version[BPKG_NAME_MAX];
    char builtin[BPKG_NAME_MAX];
    char abi[BPKG_NAME_MAX];
    char arch[BPKG_NAME_MAX];
    char type[BPKG_NAME_MAX];
    char sha256[65];
    char description[1024];
    char *deps[BPKG_MAX_DEPS];
    int  ndeps;
    int  type_declared;
} bp_manifest;

static int
bp_verify_installed_loadable (const char *root, const char *name,
                              const bp_manifest *mf,
                              char *so_path, size_t so_path_len);
static int
bp_read_installed_manifest (const char *root, const char *name,
                            bp_manifest *mf);

static void
bp_manifest_init (bp_manifest *m)
{
    memset (m, 0, sizeof *m);
    snprintf (m->type, sizeof m->type, "%s", "loadable");
}

static int bp_safe_name (const char *name);

static void
bp_manifest_free (bp_manifest *m)
{
    for (int i = 0; i < m->ndeps; i++) free (m->deps[i]);
    m->ndeps = 0;
}

static int
bp_manifest_is_loadable (const bp_manifest *m)
{
    return m && m->builtin[0] && m->abi[0] && m->sha256[0];
}

static const char *
bp_manifest_effective_type (const bp_manifest *m)
{
    if (m && m->type[0])
        return m->type;
    return "loadable";
}

static int
bp_manifest_type_is_declared (const bp_manifest *m)
{
    return m && m->type_declared;
}

static int
bp_manifest_effective_is_loadable (const bp_manifest *m)
{
    if (!m) return 0;
    if (bp_manifest_type_is_declared (m))
        return !strcmp (bp_manifest_effective_type (m), "loadable");
    return bp_manifest_is_loadable (m);
}

static int
bp_manifest_is_payload (const bp_manifest *m)
{
    return m && bp_manifest_type_is_declared (m) &&
           !strcmp (bp_manifest_effective_type (m), "payload");
}

static int
bp_manifest_is_v2_visible (const bp_manifest *m)
{
    return m && (bp_manifest_is_payload (m) ||
                 bp_manifest_effective_is_loadable (m));
}

static int
bp_manifest_type_is_known (const bp_manifest *m)
{
    const char *type = bp_manifest_effective_type (m);
    return !strcmp (type, "loadable") || !strcmp (type, "payload");
}

static void
bp_manifest_print (const bp_manifest *m)
{
    printf ("name: %s\n", m->name);
    printf ("type: %s\n", bp_manifest_effective_type (m));
    if (m->version[0]) printf ("version: %s\n", m->version);
    if (m->builtin[0]) printf ("builtin: %s\n", m->builtin);
    if (m->abi[0]) printf ("abi: %s\n", m->abi);
    if (m->arch[0]) printf ("arch: %s\n", m->arch);
    if (m->sha256[0]) printf ("sha256: %s\n", m->sha256);
    if (m->ndeps > 0) {
        printf ("deps: ");
        for (int i = 0; i < m->ndeps; i++)
            printf ("%s%s", i ? "," : "", m->deps[i]);
        putchar ('\n');
    }
    if (m->description[0])
        printf ("description: %s\n", m->description);
}

static char *
bp_strip (char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    size_t n = strlen (s);
    while (n > 0 &&
           (s[n - 1] == ' ' || s[n - 1] == '\t' ||
            s[n - 1] == '\r' || s[n - 1] == '\n'))
        s[--n] = 0;
    return s;
}

/* Parse "key: value" lines. Whitespace-trimmed. Lines beginning with
 * '#' or empty lines are ignored. deps is a comma-separated list. */
static int
bp_manifest_parse (bp_manifest *m, const unsigned char *data, size_t len)
{
    bp_manifest_init (m);
    size_t off = 0;
    while (off < len) {
        size_t end = off;
        while (end < len && data[end] != '\n') end++;
        size_t line_len = end - off;
        if (line_len > 0 && line_len < 4096) {
            char line[4096];
            memcpy (line, data + off, line_len);
            line[line_len] = 0;
            char *p = bp_strip (line);
            if (*p && *p != '#') {
                char *colon = strchr (p, ':');
                if (colon) {
                    *colon = 0;
                    char *key = bp_strip (p);
                    char *val = bp_strip (colon + 1);
                    if (!strcmp (key, "name")) {
                        snprintf (m->name, sizeof m->name, "%s", val);
                    } else if (!strcmp (key, "version")) {
                        snprintf (m->version, sizeof m->version, "%s",
                                  val);
                    } else if (!strcmp (key, "builtin")) {
                        snprintf (m->builtin, sizeof m->builtin, "%s",
                                  val);
                    } else if (!strcmp (key, "abi")) {
                        snprintf (m->abi, sizeof m->abi, "%s", val);
                    } else if (!strcmp (key, "arch")) {
                        snprintf (m->arch, sizeof m->arch, "%s", val);
                    } else if (!strcmp (key, "type")) {
                        snprintf (m->type, sizeof m->type, "%s", val);
                        m->type_declared = 1;
                    } else if (!strcmp (key, "sha256")) {
                        if (bp_hex64 (val))
                            snprintf (m->sha256, sizeof m->sha256, "%s",
                                      val);
                    } else if (!strcmp (key, "description")) {
                        snprintf (m->description,
                                  sizeof m->description, "%s", val);
	                    } else if (!strcmp (key, "deps")) {
	                        char *tok = strtok (val, ", \t");
	                        while (tok) {
	                            if (m->ndeps >= BPKG_MAX_DEPS) {
	                                bp_manifest_free (m);
	                                return -1;
	                            }
	                            m->deps[m->ndeps] = strdup (tok);
	                            if (!m->deps[m->ndeps]) {
	                                bp_manifest_free (m);
	                                return -1;
	                            }
	                            m->ndeps++;
	                            tok = strtok (NULL, ", \t");
	                        }
                    }
                }
            }
        }
        off = end + 1;
    }
    if (!bp_safe_name (m->name)) return -1;
    return 0;
}

static int
bp_hex64 (const char *s)
{
    if (!s || strlen (s) != 64) return 0;
    for (int i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

static int
bp_arch_matches (const char *arch)
{
    if (!arch[0] || !strcmp (arch, "any") || !strcmp (arch, "noarch"))
        return 1;
    struct utsname u;
    if (uname (&u) < 0) return 0;
    return !strcmp (arch, u.machine);
}

static int
bp_current_arch (char *out, size_t outsz)
{
    struct utsname u;
    if (uname (&u) < 0) return -1;
    if (snprintf (out, outsz, "%s", u.machine) >= (int) outsz)
        return -1;
    return 0;
}

static int
bp_select_arch (const char *override, char *out, size_t outsz)
{
    if (override && *override) {
        if (!bp_safe_name (override)) {
            builtin_error ("--arch: invalid architecture: %s", override);
            return -1;
        }
        if (snprintf (out, outsz, "%s", override) >= (int) outsz)
            return -1;
        return 0;
    }
    return bp_current_arch (out, outsz);
}

static int
bp_arch_matches_selected (const char *entry_arch, const char *selected_arch)
{
    if (!entry_arch || !*entry_arch || !strcmp (entry_arch, "any") ||
        !strcmp (entry_arch, "noarch"))
        return 1;
    return selected_arch && *selected_arch &&
           strcmp (entry_arch, selected_arch) == 0;
}

static int
bp_abi_matches (const char *abi)
{
    if (!abi[0] || !strcmp (abi, "any")) return 1;
    return !strcmp (abi, "bash-5.3");
}

/* ---- Path safety ---------------------------------------------------- */

static int
bp_safe_path (const char *p)
{
    if (!p || !*p) return 0;
    if (p[0] == '/') return 0;
    /* No "..", no embedded "/../", no NUL-traversal tricks. */
    if (!strcmp (p, "..")) return 0;
    if (strstr (p, "/../")) return 0;
    if (strncmp (p, "../", 3) == 0) return 0;
    size_t n = strlen (p);
    if (n >= 3 && !strcmp (p + n - 3, "/..")) return 0;
    return 1;
}

static int
bp_safe_name (const char *name)
{
    if (!name || !*name) return 0;
    if (!strcmp (name, ".") || !strcmp (name, "..")) return 0;
    if (strchr (name, '/')) return 0;
    if (strstr (name, "..")) return 0;
    return 1;
}

static int
bp_dep_stack_contains (char stack[][BPKG_NAME_MAX], int depth,
                       const char *name)
{
    for (int i = 0; i < depth; i++)
        if (strcmp (stack[i], name) == 0)
            return 1;
    return 0;
}

static int
bp_dep_stack_push (char stack[][BPKG_NAME_MAX], int *depth,
                   const char *name)
{
    if (*depth >= BPKG_MAX_DEPS)
        return -1;
    snprintf (stack[*depth], BPKG_NAME_MAX, "%s", name);
    (*depth)++;
    return 0;
}

static char bp_install_dep_stack[BPKG_MAX_DEPS][BPKG_NAME_MAX];
static int bp_install_dep_stack_depth;
static char bp_download_dep_stack[BPKG_MAX_DEPS][BPKG_NAME_MAX];
static int bp_download_dep_stack_depth;

static int
bp_download_name (const char *root, const char *sources,
                  const char *repo_filter, const char *arch_override,
                  const char *name, int depth);

static int
bp_reject_unsafe_name (const char *verb, const char *name)
{
    if (bp_safe_name (name))
        return 0;
    builtin_error ("%s: invalid package name: %s", verb, name ? name : "");
    return -1;
}

/* ---- Install state helpers ----------------------------------------- */

/* ---- Hook execution ------------------------------------------------- */

/* Bash maintains its own exported-variable cache (`export_env`) that is
 * NOT always synced to libc's `environ` array at the moment a loadable
 * runs (the sync happens lazily on real `execve`s issued by the shell).
 * For a loadable that forks and execs a child, this matters: relying
 * on setenv()+execl() in the child means BASHPKG_NAME et al. are
 * appended to libc-environ, but libc-environ may not contain the rest
 * of Bash's exports — and on some bash-os builds the child's environ
 * has been seen empty when no shell-level export was issued recently.
 *
 * Stage 28.A.C closed the matching gap for `ns spawn` by refreshing
 * `maybe_make_export_env()` and passing `export_env` to `execvpe()`
 * explicitly. We follow that pattern here: build an explicit envp by
 * copying bash's export_env (which already includes PATH, USER, HOME,
 * etc.), filter any pre-existing BASHPKG_* slots so we never emit
 * duplicate keys, then append the four BASHPKG_* slots required by
 * the documented hook contract. Use execve() with the curated env. */
extern char **export_env;
extern void maybe_make_export_env (void);
extern WORD_DESC *make_word (const char *);
extern WORD_LIST *make_word_list (WORD_DESC *, WORD_LIST *);
extern void dispose_words (WORD_LIST *);
extern int enable_builtin (WORD_LIST *);

/* Run a hook script via /bin/bash with the package context exported.
 *
 * Hook contract (must match the slots written by the test fixtures
 * under tests/bash-os/200-pkg.sh — cases 7 (post-install) and 16
 * (pre-remove) read these via $BASHPKG_NAME / $BASHPKG_ROOT):
 *   BASHPKG_NAME    — package name from MANIFEST
 *   BASHPKG_VERSION — package version (empty string if MANIFEST omits)
 *   BASHPKG_PREFIX  — the install root (`/` for system installs,
 *                     a sandbox dir under --root)
 *   BASHPKG_ROOT    — legacy alias for BASHPKG_PREFIX (kept so older
 *                     hook scripts continue to work)
 *
 * The hook runs as the same user as pkg (no setuid). Non-zero hook
 * exit propagates as -1 so the install/remove fails closed.
 *
 * Return: 0 on success / no-hook, -1 on dispatcher error or non-zero
 * hook exit.
 */
static int
bp_run_script (const char *path, const char *pkgname,
               const char *version, const char *prefix)
{
    struct stat st;
    if (stat (path, &st) < 0) return 0; /* no hook → success */
    /* Hooks run via `/bin/bash -- <path>`: bash reads the script directly,
       so the exec bit is unnecessary. Previously we chmod()'d the hook to
       0700 before execve()'ing it as a program, which mutated the operator's
       on-disk tree. Decision #3 (REVIEW-2026-05-26-DECISIONS) — drop the
       chmod, invoke bash with the script as an argument instead. The `--`
       sentinel keeps a hook path that happens to start with '-' from being
       interpreted as a flag. */

    /* Refresh Bash's exported-variable cache BEFORE fork so the child
       inherits a current snapshot. After fork the loadable can't call
       Bash internals safely, so do this on the parent side. */
    maybe_make_export_env ();

    struct bpkg_child_guard guard;
    if (bpkg_child_guard_begin (&guard) < 0) {
        builtin_error ("SIGCHLD guard: %s", strerror (errno));
        return -1;
    }
    pid_t pid = fork ();
    if (pid < 0) {
        bpkg_child_guard_parent_end (&guard);
        builtin_error ("fork: %s", strerror (errno));
        return -1;
    }
    if (pid == 0) {
        bpkg_child_guard_child_end (&guard);
        /* Build the envp the hook will see. Start from bash's
           export_env (the authoritative shell-level export set) and
           filter out any prior BASHPKG_* slots so we don't emit
           duplicate keys, then append the four contract slots. The
           BASHPKG_* assignments live on the child stack — they don't
           need to survive past execve. */
        char name_buf[BPKG_NAME_MAX + 32];
        char ver_buf [BPKG_NAME_MAX + 32];
        char pre_buf [BPKG_PATH_MAX + 32];
        char root_buf[BPKG_PATH_MAX + 32];
        snprintf (name_buf, sizeof name_buf, "BASHPKG_NAME=%s",
                  pkgname ? pkgname : "");
        snprintf (ver_buf,  sizeof ver_buf,  "BASHPKG_VERSION=%s",
                  version ? version : "");
        snprintf (pre_buf,  sizeof pre_buf,  "BASHPKG_PREFIX=%s",
                  prefix  ? prefix  : "/");
        snprintf (root_buf, sizeof root_buf, "BASHPKG_ROOT=%s",
                  prefix  ? prefix  : "/");

        /* Count incoming env slots (export_env first, then fall back
           to libc environ if bash never built one — defensive). */
        char **src = export_env;
        if (!src) {
            extern char **environ;
            src = environ;
        }
        size_t in_n = 0;
        if (src) while (src[in_n]) in_n++;

        /* Allocate envp: in_n existing + 4 BASHPKG_* + NULL. */
        char **envp = calloc (in_n + 5, sizeof (char *));
        if (!envp) {
            /* Fall back to a tiny env that AT LEAST carries the
               BASHPKG_* slots so the hook still observes the
               contract, even under OOM. */
            static char *small_envp[6];
            small_envp[0] = name_buf;
            small_envp[1] = ver_buf;
            small_envp[2] = pre_buf;
            small_envp[3] = root_buf;
            small_envp[4] = NULL;
            char *argv[] = { (char *) "bash", (char *) "--",
                             (char *) path, NULL };
            execve ("/bin/bash", argv, small_envp);
            _exit (126);
        }
        size_t out_n = 0;
        if (src) {
            for (size_t i = 0; i < in_n; i++) {
                const char *e = src[i];
                if (!strncmp (e, "BASHPKG_NAME=",    13)) continue;
                if (!strncmp (e, "BASHPKG_VERSION=", 16)) continue;
                if (!strncmp (e, "BASHPKG_PREFIX=",  15)) continue;
                if (!strncmp (e, "BASHPKG_ROOT=",    13)) continue;
                envp[out_n++] = (char *) e;
            }
        }
        envp[out_n++] = name_buf;
        envp[out_n++] = ver_buf;
        envp[out_n++] = pre_buf;
        envp[out_n++] = root_buf;
        envp[out_n]   = NULL;

        char *argv[] = { (char *) "bash", (char *) "--",
                         (char *) path, NULL };
        execve ("/bin/bash", argv, envp);
        /* execve only returns on failure. We can't easily distinguish
           ENOENT (no /bin/bash) from EACCES (permission) here — every
           bash-os variant ships /bin/bash by definition, so any failure
           is a real dispatcher error. */
        _exit (126);
    }
    int status = 0;
    while (waitpid (pid, &status, 0) < 0) {
        if (errno != EINTR) {
            bpkg_child_guard_parent_end (&guard);
            return -1;
        }
    }
    bpkg_child_guard_parent_end (&guard);
    if (WIFEXITED (status) && WEXITSTATUS (status) == 0) return 0;
    builtin_error ("hook %s exited non-zero (%d)", path,
                   WIFEXITED (status) ? WEXITSTATUS (status) : -1);
    return -1;
}

/* ---- Signature verification --------------------------------------- */

static int
bp_verify_signature_with_sig (const char *pkgfile, const char *sig)
{
    struct stat st;
    if (stat (sig, &st) < 0) {
        /* No sig — caller decides whether to allow. */
        return 1;
    }
    /* Use bashsignify if available on PATH. Sync Bash's exported-
     * variable cache to environ before fork so the child sees env
     * knobs the caller set via `VAR=val pkg install` (notably
     * BASHSIGNIFY_TRUSTED_KEYS_DIR and BASHSIGNIFY_REVOKED_KEYS).
     * Without this, those vars are in Bash's symbol table but not
     * in environ — the forked execlp child has the stale snapshot. */
    maybe_make_export_env ();
    struct bpkg_child_guard guard;
    if (bpkg_child_guard_begin (&guard) < 0)
        return -1;
    pid_t pid = fork ();
    if (pid < 0) {
        bpkg_child_guard_parent_end (&guard);
        return -1;
    }
    if (pid == 0) {
        bpkg_child_guard_child_end (&guard);
        /* Suppress bashsignify's success-path stdout ("Signature
         * Verified") so a quiet pkg install stays quiet, but let
         * stderr pass through so the operator sees revoked-key,
         * unknown-key, keynum-mismatch, malformed-sig, etc. diagnostics.
         * Without this, every install-time signature refusal looked
         * like a generic non-zero rc from pkg with no hint of why. */
        int devnull = open ("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2 (devnull, 1);
            close (devnull);
        }
        execlp ("bashsignify", "bashsignify", "verify",
                "-x", sig, "-m", pkgfile, (char *) NULL);
        _exit (127);
    }
    int status = 0;
    while (waitpid (pid, &status, 0) < 0) {
        if (errno != EINTR) {
            bpkg_child_guard_parent_end (&guard);
            return -1;
        }
    }
    bpkg_child_guard_parent_end (&guard);
    if (WIFEXITED (status) && WEXITSTATUS (status) == 0) return 0;
    return -1;
}

static int
bp_verify_signature (const char *pkgfile)
{
    char sig[BPKG_PATH_MAX];
    if (snprintf (sig, sizeof sig, "%s.sig", pkgfile) >= (int) sizeof sig)
        return -1;
    return bp_verify_signature_with_sig (pkgfile, sig);
}

/* ---- Per-file SHA-256 integrity ------------------------------------ */

/* Stage A.8 v2: signify guards the archive envelope, but a partial-trust
 * cache (mirror, proxy) can still feed a tampered .pkg whose payload
 * differs from the MANIFEST's intent. We refuse install if any extracted
 * file disagrees with its sha256 entry in MANIFEST.
 *
 * MANIFEST encoding (additive, backward-compatible with Round-8):
 *
 *   sha256: /usr/share/foo/a.txt 9f86d081884c7d659a2feaa0c55ad015...
 *   sha256: /usr/share/foo/b.txt 2c26b46b68ffc68ff99b453c1d304134...
 *
 * One entry per file under files/. PATH must be absolute (matching the
 * leading-slash form recorded in <installed>/files). HASH is exactly 64
 * lowercase or uppercase hex chars (case-folded on parse to lowercase).
 *
 * Policy (matching the Stage A.8 spec):
 *   - MANIFEST with zero sha256 lines → tolerant, allow install. This
 *     preserves the Round-8 package format so existing fixtures don't
 *     need re-packing.
 *   - MANIFEST with one or more sha256 lines → every extracted file
 *     under files/ must have a matching sha256 entry AND the on-disk
 *     content must hash to that entry. Any missing or mismatched
 *     entry refuses the install. Malformed sha256 lines (bad length,
 *     non-hex chars) also refuse the install.
 */

typedef struct {
    char *path;     /* malloc'd absolute path (leading slash). */
    char  hex[65];  /* lowercase hex SHA-256, NUL-terminated. */
} bp_hash_entry;

typedef struct {
    bp_hash_entry *items;
    size_t         n;
    size_t         cap;
} bp_hash_list;

static void
bp_hash_list_free (bp_hash_list *l)
{
    for (size_t i = 0; i < l->n; i++) free (l->items[i].path);
    free (l->items);
    l->items = NULL;
    l->n = l->cap = 0;
}

static int
bp_hash_list_add (bp_hash_list *l, const char *path, const char *hex)
{
    if (l->n >= l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 16;
        bp_hash_entry *p = realloc (l->items, nc * sizeof (*p));
        if (!p) return -1;
        l->items = p;
        l->cap = nc;
    }
    l->items[l->n].path = strdup (path);
    if (!l->items[l->n].path) return -1;
    memcpy (l->items[l->n].hex, hex, 65);
    l->n++;
    return 0;
}

static const bp_hash_entry *
bp_hash_list_find (const bp_hash_list *l, const char *path)
{
    for (size_t i = 0; i < l->n; i++)
        if (!strcmp (l->items[i].path, path)) return &l->items[i];
    return NULL;
}

/* Parse "sha256: PATH HEX64" lines out of MANIFEST text. Lines whose
 * first non-whitespace char is '#' are skipped. Returns 0 on success
 * (including the no-entries case) and -1 if any well-keyed line is
 * malformed — refuse-install is the right policy when MANIFEST is
 * structurally invalid. */
static int
bp_parse_sha256_lines (const unsigned char *data, size_t len,
                       bp_hash_list *out)
{
    size_t off = 0;
    while (off < len) {
        size_t end = off;
        while (end < len && data[end] != '\n') end++;
        size_t ll = end - off;
        if (ll == 0 || ll >= 4096) { off = end + 1; continue; }

        char line[4096];
        memcpy (line, data + off, ll);
        line[ll] = 0;

        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#') { off = end + 1; continue; }

        if (strncmp (p, "sha256", 6) != 0) { off = end + 1; continue; }
        char *q = p + 6;
        while (*q == ' ' || *q == '\t') q++;
        if (*q != ':') { off = end + 1; continue; }
        q++;
        while (*q == ' ' || *q == '\t') q++;
        if (!*q) {
            builtin_error ("sha256: empty value");
            return -1;
        }
        char *path_start = q;
        while (*q && *q != ' ' && *q != '\t') q++;
        if (!*q) {
            if (bp_hex64 (path_start)) { off = end + 1; continue; }
            builtin_error ("sha256: missing hash for %s", path_start);
            return -1;
        }
        *q++ = 0;
        while (*q == ' ' || *q == '\t') q++;
        char *hash_start = q;
        char *h = hash_start;
        while (*h && *h != ' ' && *h != '\t' && *h != '\r' && *h != '\n')
            h++;
        *h = 0;

        if (path_start[0] != '/') {
            builtin_error ("sha256: PATH must be absolute (got %s)",
                           path_start);
            return -1;
        }
        if (strlen (hash_start) != 64) {
            builtin_error ("sha256: hash for %s is not 64 hex chars",
                           path_start);
            return -1;
        }
        char hex[65];
        for (int i = 0; i < 64; i++) {
            char c = hash_start[i];
            if (c >= '0' && c <= '9')      hex[i] = c;
            else if (c >= 'a' && c <= 'f') hex[i] = c;
            else if (c >= 'A' && c <= 'F') hex[i] = (char)(c - 'A' + 'a');
            else {
                builtin_error ("sha256: non-hex char in hash for %s",
                               path_start);
                return -1;
            }
        }
        hex[64] = 0;

        if (bp_hash_list_add (out, path_start, hex) < 0) {
            builtin_error ("sha256: out of memory");
            return -1;
        }

        off = end + 1;
    }
    return 0;
}

static int
bp_sha256_bytes_hex (const unsigned char *data, size_t len, char hex_out[65])
{
    unsigned char digest[32];
    if (mbedtls_sha256 (data, len, digest, 0) != 0)
        return -1;
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex_out[2 * i]     = H[digest[i] >> 4];
        hex_out[2 * i + 1] = H[digest[i] & 0xf];
    }
    hex_out[64] = 0;
    return 0;
}

static int
bp_sha256_file_hex (const char *path, char hex_out[65])
{
    bp_buf body = {0};
    if (bp_read_file (path, &body) < 0) {
        bp_buf_free (&body);
        return -1;
    }
    int rc = bp_sha256_bytes_hex (body.data, body.len, hex_out);
    bp_buf_free (&body);
    return rc;
}

static int
bp_buf_append_line (bp_buf *b, const char *s)
{
    if (!s || !*s) return 0;
    if (bp_buf_append (b, (const unsigned char *) s, strlen (s)) < 0)
        return -1;
    return bp_buf_append (b, (const unsigned char *) "\n", 1);
}

/* On refused installs, walk the recorded files_list and unlink each extracted
 * file so a failed install doesn't strand payload on disk. ENOENT is expected
 * during partial-state cleanup (file never reached disk); any other unlink
 * failure is surfaced via builtin_warning so operators can diagnose the
 * stranded path. */
static void
bp_rollback_extracted (const char *root, const bp_buf *files_list)
{
    size_t off = 0;
    while (off < files_list->len) {
        size_t end = off;
        while (end < files_list->len && files_list->data[end] != '\n')
            end++;
        if (end > off) {
            char p[BPKG_PATH_MAX];
            size_t plen = end - off;
            if (plen < sizeof p) {
                if (root[0] && strcmp (root, "/") != 0 &&
                    files_list->data[off] == '/') {
                    snprintf (p, sizeof p, "%s%.*s", root,
                              (int) plen, files_list->data + off);
                } else {
                    memcpy (p, files_list->data + off, plen);
                    p[plen] = 0;
                }
                if (unlink (p) < 0 && errno != ENOENT)
                    builtin_warning ("rollback: unlink %s: %s",
                                     p, strerror (errno));
            }
        }
        off = end + 1;
    }
}

/* Best-effort directory cleanup for directories created during extraction.
 * Walk the newline-separated absolute path list in reverse so children are
 * removed before parents. ENOTEMPTY/EEXIST/ENOENT are the expected
 * "directory was pre-existing or still holds operator content" cases and
 * are silent; other failures surface via builtin_warning. */
static void
bp_rollback_dirs (const bp_buf *dirs_list)
{
    size_t end = dirs_list->len;
    while (end > 0) {
        while (end > 0 && dirs_list->data[end - 1] == '\n') end--;
        size_t start = end;
        while (start > 0 && dirs_list->data[start - 1] != '\n') start--;
        if (end > start) {
            char p[BPKG_PATH_MAX];
            size_t plen = end - start;
            if (plen < sizeof p) {
                memcpy (p, dirs_list->data + start, plen);
                p[plen] = 0;
                if (rmdir (p) < 0
                    && errno != ENOTEMPTY && errno != EEXIST
                    && errno != ENOENT)
                    builtin_warning ("rollback: rmdir %s: %s",
                                     p, strerror (errno));
            }
        }
        if (start == 0) break;
        end = start - 1;
    }
}

/* Walk files_list and verify each extracted file's SHA-256 against the
 * MANIFEST entries. See policy notes above. Returns 0 on success (or
 * tolerant skip), -1 on any failure. */
static int
bp_verify_files_sha256 (const char *root, const bp_buf *manifest,
                        const bp_buf *files_list)
{
    bp_hash_list hl = {0};
    if (bp_parse_sha256_lines (manifest->data, manifest->len, &hl) < 0) {
        bp_hash_list_free (&hl);
        return -1;
    }
    if (hl.n == 0) {
        /* Backward-compat: Round-8 MANIFESTs have no sha256 lines. */
        bp_hash_list_free (&hl);
        return 0;
    }

    size_t off = 0;
    while (off < files_list->len) {
        size_t end = off;
        while (end < files_list->len && files_list->data[end] != '\n')
            end++;
        if (end > off) {
            char rel[BPKG_PATH_MAX];
            size_t rl = end - off;
            if (rl >= sizeof rel) {
                builtin_error ("sha256: path too long in files_list");
                bp_hash_list_free (&hl);
                return -1;
            }
            memcpy (rel, files_list->data + off, rl);
            rel[rl] = 0;

            const bp_hash_entry *want = bp_hash_list_find (&hl, rel);
            if (!want) {
                builtin_error ("sha256: no MANIFEST hash for %s", rel);
                bp_hash_list_free (&hl);
                return -1;
            }

            char on_disk[BPKG_PATH_MAX];
            if (root[0] && strcmp (root, "/") != 0 && rel[0] == '/') {
                if (snprintf (on_disk, sizeof on_disk, "%s%s", root, rel)
                    >= (int) sizeof on_disk) {
                    builtin_error ("sha256: composed path too long");
                    bp_hash_list_free (&hl);
                    return -1;
                }
            } else {
                snprintf (on_disk, sizeof on_disk, "%s", rel);
            }
            char got[65];
            if (bp_sha256_file_hex (on_disk, got) < 0) {
                builtin_error ("sha256: cannot read %s", on_disk);
                bp_hash_list_free (&hl);
                return -1;
            }
            if (strcmp (got, want->hex) != 0) {
                builtin_error (
                    "sha256: mismatch for %s (got %s, want %s)",
                    rel, got, want->hex);
                bp_hash_list_free (&hl);
                return -1;
            }
        }
        off = end + 1;
    }

    bp_hash_list_free (&hl);
    return 0;
}

/* ---- Per-file mode-bit verification -------------------------------- */

/* Stage A.9 (Loadable hardening — pkg): even with the Stage A.8
 * SHA-256 gate, a tampered mirror can leave file content intact and
 * still flip the recorded tar header from 0755 to 04755, sneaking a
 * setuid bit onto a binary the MANIFEST never declared. We check each
 * extracted file's st_mode (low 12 bits) against a MANIFEST mode
 * column. Tampered mode bits no longer survive install.
 *
 * MANIFEST encoding (additive, backward-compatible with Stage A.8):
 *
 *   mode: /usr/bin/foo 0755
 *   mode: /etc/sudoers 0440
 *
 * One entry per file under files/. PATH must be absolute (matching the
 * leading-slash form recorded in <installed>/files). MODE is an octal
 * literal of up to 5 digits (covers setuid/setgid/sticky in the top
 * three bits plus the 9 rwx bits). Leading "0" is optional.
 *
 * Policy:
 *   - MANIFEST with zero mode lines → tolerant, no enforcement. Stage
 *     A.8 fixtures repacked without a mode column still install
 *     cleanly.
 *   - MANIFEST with one or more mode lines → for each file under
 *     files/:
 *       · MANIFEST has a mode entry → on-disk st_mode (low 12 bits)
 *         must equal it; mismatch refuses the install with
 *         "pkg: mode-bits mismatch: <path>".
 *       · MANIFEST has no entry for this path → warn on stderr and
 *         allow install (operators incrementally adding mode coverage
 *         to a large MANIFEST shouldn't be blocked).
 */

typedef struct {
    char  *path;    /* malloc'd absolute path (leading slash). */
    mode_t mode;    /* mask 07777 (setuid/setgid/sticky + rwxrwxrwx). */
} bp_mode_entry;

typedef struct {
    bp_mode_entry *items;
    size_t         n;
    size_t         cap;
} bp_mode_list;

static void
bp_mode_list_free (bp_mode_list *l)
{
    for (size_t i = 0; i < l->n; i++) free (l->items[i].path);
    free (l->items);
    l->items = NULL;
    l->n = l->cap = 0;
}

static int
bp_mode_list_add (bp_mode_list *l, const char *path, mode_t mode)
{
    if (l->n >= l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 16;
        bp_mode_entry *p = realloc (l->items, nc * sizeof (*p));
        if (!p) return -1;
        l->items = p;
        l->cap = nc;
    }
    l->items[l->n].path = strdup (path);
    if (!l->items[l->n].path) return -1;
    l->items[l->n].mode = mode;
    l->n++;
    return 0;
}

static const bp_mode_entry *
bp_mode_list_find (const bp_mode_list *l, const char *path)
{
    for (size_t i = 0; i < l->n; i++)
        if (!strcmp (l->items[i].path, path)) return &l->items[i];
    return NULL;
}

/* Parse "mode: PATH OCTAL" lines out of MANIFEST text. Lines whose
 * first non-whitespace char is '#' are skipped. Returns 0 on success
 * (including the no-entries case) and -1 if any well-keyed line is
 * malformed (refuse-install is the right policy when MANIFEST is
 * structurally invalid). */
static int
bp_parse_mode_lines (const unsigned char *data, size_t len,
                     bp_mode_list *out)
{
    size_t off = 0;
    while (off < len) {
        size_t end = off;
        while (end < len && data[end] != '\n') end++;
        size_t ll = end - off;
        if (ll == 0 || ll >= 4096) { off = end + 1; continue; }

        char line[4096];
        memcpy (line, data + off, ll);
        line[ll] = 0;

        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#') { off = end + 1; continue; }

        if (strncmp (p, "mode", 4) != 0) { off = end + 1; continue; }
        char *q = p + 4;
        /* Disambiguate against future "modeXYZ:" keys: the next char
         * after "mode" must be whitespace or ':'. */
        if (*q != ' ' && *q != '\t' && *q != ':') {
            off = end + 1; continue;
        }
        while (*q == ' ' || *q == '\t') q++;
        if (*q != ':') { off = end + 1; continue; }
        q++;
        while (*q == ' ' || *q == '\t') q++;
        if (!*q) {
            builtin_error ("mode: empty value");
            return -1;
        }
        char *path_start = q;
        while (*q && *q != ' ' && *q != '\t') q++;
        if (!*q) {
            builtin_error ("mode: missing octal for %s", path_start);
            return -1;
        }
        *q++ = 0;
        while (*q == ' ' || *q == '\t') q++;
        char *octal_start = q;
        char *h = octal_start;
        while (*h && *h != ' ' && *h != '\t' && *h != '\r' && *h != '\n')
            h++;
        *h = 0;

        if (path_start[0] != '/') {
            builtin_error ("mode: PATH must be absolute (got %s)",
                           path_start);
            return -1;
        }
        /* Optional leading "0" stripped; accept up to 5 octal digits. */
        const char *o = octal_start;
        if (*o == '0' && o[1] != 0) o++;
        size_t olen = strlen (o);
        if (olen == 0 || olen > 5) {
            builtin_error ("mode: octal for %s must be 1-5 digits "
                           "(got '%s')", path_start, octal_start);
            return -1;
        }
        mode_t mval = 0;
        for (size_t i = 0; i < olen; i++) {
            char c = o[i];
            if (c < '0' || c > '7') {
                builtin_error ("mode: non-octal char in mode for %s "
                               "(got '%s')", path_start, octal_start);
                return -1;
            }
            mval = (mode_t) ((mval << 3) | (mode_t) (c - '0'));
        }
        mval &= 07777;

        if (bp_mode_list_add (out, path_start, mval) < 0) {
            builtin_error ("mode: out of memory");
            return -1;
        }

        off = end + 1;
    }
    return 0;
}

/* Walk files_list and verify each extracted file's st_mode (low 12
 * bits) against the MANIFEST mode entries. See policy notes above.
 * Returns 0 on success (or tolerant skip), -1 on any failure. */
static int
bp_verify_files_modes (const char *root, const bp_buf *manifest,
                       const bp_buf *files_list)
{
    bp_mode_list ml = {0};
    if (bp_parse_mode_lines (manifest->data, manifest->len, &ml) < 0) {
        bp_mode_list_free (&ml);
        return -1;
    }
    if (ml.n == 0) {
        /* Tolerant: MANIFEST has no mode column at all. */
        bp_mode_list_free (&ml);
        return 0;
    }

    size_t off = 0;
    while (off < files_list->len) {
        size_t end = off;
        while (end < files_list->len && files_list->data[end] != '\n')
            end++;
        if (end > off) {
            char rel[BPKG_PATH_MAX];
            size_t rl = end - off;
            if (rl >= sizeof rel) {
                builtin_error ("mode: path too long in files_list");
                bp_mode_list_free (&ml);
                return -1;
            }
            memcpy (rel, files_list->data + off, rl);
            rel[rl] = 0;

            const bp_mode_entry *want = bp_mode_list_find (&ml, rel);
            if (!want) {
                /* missing-mode-column: warn-only, do not refuse. */
                fprintf (stderr,
                         "pkg: warning: no MANIFEST mode entry "
                         "for %s\n", rel);
                off = end + 1;
                continue;
            }

            char on_disk[BPKG_PATH_MAX];
            if (root[0] && strcmp (root, "/") != 0 && rel[0] == '/') {
                if (snprintf (on_disk, sizeof on_disk, "%s%s", root, rel)
                    >= (int) sizeof on_disk) {
                    builtin_error ("mode: composed path too long");
                    bp_mode_list_free (&ml);
                    return -1;
                }
            } else {
                snprintf (on_disk, sizeof on_disk, "%s", rel);
            }
            struct stat st;
            if (stat (on_disk, &st) < 0) {
                builtin_error ("mode-bits: cannot stat %s: %s",
                               on_disk, strerror (errno));
                bp_mode_list_free (&ml);
                return -1;
            }
            mode_t got = (mode_t) (st.st_mode & 07777);
            if (got != want->mode) {
                builtin_error (
                    "mode-bits mismatch: %s (got 0%o, want 0%o)",
                    rel, (unsigned) got, (unsigned) want->mode);
                bp_mode_list_free (&ml);
                return -1;
            }
        }
        off = end + 1;
    }

    bp_mode_list_free (&ml);
    return 0;
}

static int
bp_verify_loadable_mode (const char *root, const bp_buf *manifest,
                         const char *loadable_dest)
{
    bp_mode_list ml = {0};
    if (bp_parse_mode_lines (manifest->data, manifest->len, &ml) < 0) {
        bp_mode_list_free (&ml);
        return -1;
    }
    if (ml.n == 0) {
        bp_mode_list_free (&ml);
        return 0;
    }

    const char *rel = loadable_dest;
    if (root[0] && strcmp (root, "/") != 0) {
        size_t rlen = strlen (root);
        if (!strncmp (loadable_dest, root, rlen))
            rel = loadable_dest + rlen;
    }

    const bp_mode_entry *want = bp_mode_list_find (&ml, rel);
    if (!want) {
        fprintf (stderr,
                 "pkg: warning: no MANIFEST mode entry for %s\n", rel);
        bp_mode_list_free (&ml);
        return 0;
    }

    struct stat st;
    if (stat (loadable_dest, &st) < 0) {
        builtin_error ("mode-bits: cannot stat %s: %s",
                       loadable_dest, strerror (errno));
        bp_mode_list_free (&ml);
        return -1;
    }
    mode_t got = (mode_t) (st.st_mode & 07777);
    if (got != want->mode) {
        builtin_error ("mode-bits mismatch: %s (got 0%o, want 0%o)",
                       rel, (unsigned) got, (unsigned) want->mode);
        bp_mode_list_free (&ml);
        return -1;
    }
    bp_mode_list_free (&ml);
    return 0;
}

/* ---- Install: extract ---------------------------------------------- */

typedef struct {
    const char  *root;       /* / or test root */
    const char  *pkgname;    /* package name (for state recording) */
    bp_buf       files_list; /* newline-separated installed paths */
    bp_buf       dirs_list;  /* newline-separated dirs touched by extract */
    bp_buf       manifest;   /* MANIFEST content (binary copy) */
    bp_buf       hook_pre;   /* pre-install script, optional */
    bp_buf       hook_post;  /* post-install script, optional */
    bp_buf       hook_prerm; /* pre-remove script, optional */
    bp_buf       hook_postrm;/* post-remove script, optional */
    bp_buf       loadable_body; /* staged v2 loadable bytes */
    int          have_manifest;
    int          force;      /* --force: override file-owned conflicts */
    int          allow_legacy_rootfs;
    int          files_payload_count;
    int          loadable_count;
    int          other_payload_count;
    int          manifest_count;
    int          hook_count;
    int          loadable_bad_name;
    mode_t       loadable_mode;
    char         loadable_name[BPKG_NAME_MAX];
    char         loadable_dest[BPKG_PATH_MAX];
    char         loadable_backup[BPKG_PATH_MAX];
    int          loadable_backup_active;
    char         state_dir[BPKG_PATH_MAX];
    char         state_backup[BPKG_PATH_MAX];
    int          state_dir_active;
    int          state_backup_active;
} bp_install_ctx;

static void
bp_install_ctx_free (bp_install_ctx *ctx)
{
    bp_buf_free (&ctx->files_list);
    bp_buf_free (&ctx->dirs_list);
    bp_buf_free (&ctx->manifest);
    bp_buf_free (&ctx->hook_pre);
    bp_buf_free (&ctx->hook_post);
    bp_buf_free (&ctx->hook_prerm);
    bp_buf_free (&ctx->hook_postrm);
    bp_buf_free (&ctx->loadable_body);
}

static void
bp_remove_tree (const char *path)
{
    struct stat st;
    if (lstat (path, &st) < 0)
        return;
    if (!S_ISDIR (st.st_mode)) {
        unlink (path);
        return;
    }

    DIR *d = opendir (path);
    if (d) {
        struct dirent *de;
        while ((de = readdir (d)) != NULL) {
            if (!strcmp (de->d_name, ".") ||
                !strcmp (de->d_name, ".."))
                continue;
            char child[BPKG_PATH_MAX];
            if (snprintf (child, sizeof child, "%s/%s", path, de->d_name)
                < (int) sizeof child)
                bp_remove_tree (child);
        }
        closedir (d);
    }
    rmdir (path);
}

static int
bp_prepare_state_dir (bp_install_ctx *ctx, const char *dir)
{
    if (snprintf (ctx->state_dir, sizeof ctx->state_dir, "%s", dir) >=
        (int) sizeof ctx->state_dir) {
        builtin_error ("path too long: %s", dir);
        return -1;
    }

    struct stat st;
    if (lstat (dir, &st) == 0) {
        if (!S_ISDIR (st.st_mode)) {
            builtin_error ("state path is not a directory: %s", dir);
            return -1;
        }
        if (snprintf (ctx->state_backup, sizeof ctx->state_backup,
                      "%s.bak.%d", dir, (int) getpid ()) >=
            (int) sizeof ctx->state_backup) {
            builtin_error ("path too long: %s", dir);
            return -1;
        }
        if (rename (dir, ctx->state_backup) < 0) {
            builtin_error ("backup state dir %s: %s", dir, strerror (errno));
            return -1;
        }
        ctx->state_backup_active = 1;
    } else if (errno != ENOENT) {
        builtin_error ("stat state dir %s: %s", dir, strerror (errno));
        return -1;
    }

    ctx->state_dir_active = 1;
    return 0;
}

static void
bp_rollback_install (const char *root, bp_install_ctx *ctx)
{
    bp_rollback_extracted (root, &ctx->files_list);
    if (ctx->loadable_dest[0])
        unlink (ctx->loadable_dest);
    if (ctx->loadable_backup_active) {
        if (rename (ctx->loadable_backup, ctx->loadable_dest) == 0)
            ctx->loadable_backup_active = 0;
    }
    if (ctx->state_dir_active && ctx->state_dir[0]) {
        bp_remove_tree (ctx->state_dir);
        if (ctx->state_backup_active) {
            if (rename (ctx->state_backup, ctx->state_dir) == 0)
                ctx->state_backup_active = 0;
        }
        ctx->state_dir_active = 0;
    }
    bp_rollback_dirs (&ctx->dirs_list);
}

static void
bp_commit_install (bp_install_ctx *ctx)
{
    if (ctx->loadable_backup_active) {
        unlink (ctx->loadable_backup);
        ctx->loadable_backup_active = 0;
    }
    if (ctx->state_backup_active) {
        bp_remove_tree (ctx->state_backup);
        ctx->state_backup_active = 0;
    }
    ctx->state_dir_active = 0;
}

static int
bp_install_staged_loadable (bp_install_ctx *ctx, const char *root)
{
    char dest[BPKG_PATH_MAX];
    if (snprintf (dest, sizeof dest, "%s%s/%s",
                  root[0] && strcmp (root, "/") ? root : "",
                  BPKG_LOADABLES_DIR, ctx->loadable_name) >=
        (int) sizeof dest) {
        builtin_error ("path too long: %s", ctx->loadable_name);
        return -1;
    }

    char parent[BPKG_PATH_MAX];
    snprintf (parent, sizeof parent, "%s", dest);
    char *slash = strrchr (parent, '/');
    if (slash && slash != parent) {
        *slash = 0;
        if (bp_mkdir_p (parent) < 0) {
            builtin_error ("mkdir %s: %s", parent, strerror (errno));
            return -1;
        }
        if (bp_buf_append_line (&ctx->dirs_list, parent) < 0)
            return -1;
    }

    snprintf (ctx->loadable_dest, sizeof ctx->loadable_dest, "%s", dest);
    struct stat old_st;
    if (stat (dest, &old_st) == 0) {
        if (snprintf (ctx->loadable_backup, sizeof ctx->loadable_backup,
                      "%s.bak.%d", dest, (int) getpid ()) >=
            (int) sizeof ctx->loadable_backup) {
            builtin_error ("path too long: %s", dest);
            return -1;
        }
        if (rename (dest, ctx->loadable_backup) < 0) {
            builtin_error ("backup %s: %s", dest, strerror (errno));
            return -1;
        }
        ctx->loadable_backup_active = 1;
    }

    mode_t mode = ctx->loadable_mode ? ctx->loadable_mode : 0755;
    if (bp_write_file_atomic (dest, ctx->loadable_body.data,
                              ctx->loadable_body.len, mode) < 0) {
        builtin_error ("write %s: %s", dest, strerror (errno));
        return -1;
    }
    if (chmod (dest, mode) < 0) {
        builtin_error ("chmod %s: %s", dest, strerror (errno));
        return -1;
    }

    return 0;
}

static int
bp_range_fits (size_t off, size_t need, size_t len)
{
    return off <= len && need <= len - off;
}

static int
bp_elf64_vaddr_to_offset (const unsigned char *data, size_t len,
                          Elf64_Addr vaddr, size_t *out)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *) data;
    if (!bp_range_fits ((size_t) eh->e_phoff,
                        (size_t) eh->e_phnum * sizeof (Elf64_Phdr), len))
        return -1;

    const Elf64_Phdr *ph =
        (const Elf64_Phdr *) (const void *) (data + eh->e_phoff);
    for (Elf64_Half i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD)
            continue;
        if (vaddr < ph[i].p_vaddr)
            continue;
        Elf64_Addr delta = vaddr - ph[i].p_vaddr;
        if (delta >= ph[i].p_filesz)
            continue;
        Elf64_Off file_off = ph[i].p_offset + delta;
        if (file_off > SIZE_MAX || !bp_range_fits ((size_t) file_off, 1, len))
            return -1;
        *out = (size_t) file_off;
        return 0;
    }
    return -1;
}

static int
bp_loadable_reject_nonbundled_needed (const unsigned char *data, size_t len)
{
    if (len < SELFMAG || memcmp (data, ELFMAG, SELFMAG) != 0) {
        builtin_error ("loadable object is not ELF");
        return -1;
    }

    if (len < sizeof (Elf64_Ehdr)) {
        builtin_error ("truncated ELF loadable");
        return -1;
    }

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *) data;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_ident[EI_DATA] != ELFDATA2LSB ||
        eh->e_ident[EI_VERSION] != EV_CURRENT ||
        eh->e_phentsize != sizeof (Elf64_Phdr)) {
        builtin_error ("unsupported ELF loadable format");
        return -1;
    }
    if (!bp_range_fits ((size_t) eh->e_phoff,
                        (size_t) eh->e_phnum * sizeof (Elf64_Phdr), len)) {
        builtin_error ("truncated ELF program header table");
        return -1;
    }

    const Elf64_Phdr *ph =
        (const Elf64_Phdr *) (const void *) (data + eh->e_phoff);
    const Elf64_Phdr *dyn_ph = NULL;
    for (Elf64_Half i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn_ph = &ph[i];
            break;
        }
    }
    if (!dyn_ph)
        return 0;
    if (dyn_ph->p_offset > SIZE_MAX ||
        !bp_range_fits ((size_t) dyn_ph->p_offset,
                        (size_t) dyn_ph->p_filesz, len)) {
        builtin_error ("truncated ELF dynamic section");
        return -1;
    }

    const Elf64_Dyn *dyn =
        (const Elf64_Dyn *) (const void *) (data + dyn_ph->p_offset);
    size_t ndyn = (size_t) dyn_ph->p_filesz / sizeof (Elf64_Dyn);
    Elf64_Addr strtab_addr = 0;
    size_t strsz = 0;
    for (size_t i = 0; i < ndyn; i++) {
        if (dyn[i].d_tag == DT_STRTAB)
            strtab_addr = dyn[i].d_un.d_ptr;
        else if (dyn[i].d_tag == DT_STRSZ)
            strsz = (size_t) dyn[i].d_un.d_val;
        else if (dyn[i].d_tag == DT_NULL)
            break;
    }
    if (!strtab_addr)
        return 0;

    size_t strtab_off;
    if (bp_elf64_vaddr_to_offset (data, len, strtab_addr, &strtab_off) < 0) {
        builtin_error ("invalid ELF dynamic string table");
        return -1;
    }
    if (strsz == 0 || !bp_range_fits (strtab_off, strsz, len))
        strsz = len - strtab_off;

    for (size_t i = 0; i < ndyn; i++) {
        if (dyn[i].d_tag == DT_NULL)
            break;
        if (dyn[i].d_tag != DT_NEEDED)
            continue;
        size_t name_off = (size_t) dyn[i].d_un.d_val;
        if (name_off >= strsz) {
            builtin_error ("invalid ELF shared library dependency");
            return -1;
        }
        const char *needed = (const char *) data + strtab_off + name_off;
        size_t max = strsz - name_off;
        if (memchr (needed, '\0', max) == NULL) {
            builtin_error ("unterminated ELF shared library dependency");
            return -1;
        }
        builtin_error ("loadable has non-bundled shared library dependency: "
                       "%s", needed);
        return -1;
    }

    return 0;
}

/* Walk $root/var/lib/pkg/installed/<pkg>/files for every installed
 * package and return 1 if any of them lists `wanted_rel` (rel begins
 * with '/' and is the in-rootfs path, e.g. "/usr/share/foo/x.txt"). On
 * match, *owner_out (if non-NULL) is filled with the owning pkgname
 * (no trailing slash, fits within BPKG_PATH_MAX). Returns 0 if no other
 * package claims it, 1 on hit, <0 on error. */
static int
bp_path_already_owned (const char *root, const char *wanted_rel,
                       char *owner_out, size_t owner_out_len)
{
    /* Probe-mode contexts (verb_upgrade, verb_info, verb_verify)
     * iterate a cached tarball through bp_extract_cb with a zeroed
     * install ctx — ctx->root is NULL. Treat that as "no rootfs to
     * compare against → no conflicts possible". Without this guard,
     * the snprintf below would dereference NULL and crash the
     * upgrade probe path. */
    if (!root) return 0;
    char dir[BPKG_PATH_MAX];
    snprintf (dir, sizeof dir, "%s%s",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_INSTALLED_DIR);
    DIR *d = opendir (dir);
    if (!d) return 0;  /* no state dir yet -> no conflicts possible */
    struct dirent *de;
    int hit = 0;
    size_t want_len = strlen (wanted_rel);
    while ((de = readdir (d)) != NULL && !hit) {
        if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) continue;
        char fpath[BPKG_PATH_MAX];
        snprintf (fpath, sizeof fpath, "%s/%s/files", dir, de->d_name);
        bp_buf body = {0};
        if (bp_read_file (fpath, &body) != 0) { bp_buf_free (&body); continue; }
        /* Scan newline-separated path list. */
        size_t off = 0;
        while (off < body.len) {
            size_t end = off;
            while (end < body.len && body.data[end] != '\n') end++;
            size_t line_len = end - off;
            if (line_len == want_len &&
                memcmp (body.data + off, wanted_rel, want_len) == 0) {
                if (owner_out && owner_out_len > 0) {
                    snprintf (owner_out, owner_out_len, "%s", de->d_name);
                }
                hit = 1;
                break;
            }
            off = end + 1;
        }
        bp_buf_free (&body);
    }
    closedir (d);
    return hit;
}

static int
bp_extract_cb (const bp_tar_hdr *h, const char *path,
               const unsigned char *body, size_t body_len,
               void *opaque)
{
    bp_install_ctx *ctx = opaque;
    if (!bp_safe_path (path)) {
        builtin_error ("unsafe tar path: %s", path);
        return -1;
    }
    if (!strcmp (path, "MANIFEST")) {
        ctx->manifest_count++;
        bp_buf_free (&ctx->manifest);
        if (bp_buf_append (&ctx->manifest, body, body_len) < 0) return -1;
        ctx->have_manifest = 1;
        return 0;
    }
    if (!strcmp (path, "hooks/pre-install")) {
        ctx->hook_count++;
        return bp_buf_append (&ctx->hook_pre, body, body_len);
    }
    if (!strcmp (path, "hooks/post-install")) {
        ctx->hook_count++;
        return bp_buf_append (&ctx->hook_post, body, body_len);
    }
    if (!strcmp (path, "hooks/pre-remove")) {
        ctx->hook_count++;
        return bp_buf_append (&ctx->hook_prerm, body, body_len);
    }
    if (!strcmp (path, "hooks/post-remove")) {
        ctx->hook_count++;
        return bp_buf_append (&ctx->hook_postrm, body, body_len);
    }

    if (strncmp (path, "loadable/", 9) == 0) {
        const char *lname = path + 9;
        if (!*lname) return 0;
        if (h->typeflag == '5') {
            ctx->loadable_bad_name = 1;
            return 0;
        }
        if ((h->typeflag != '0' && h->typeflag != 0) ||
            strchr (lname, '/') != NULL ||
            strlen (lname) <= 3 ||
            strcmp (lname + strlen (lname) - 3, ".so") != 0) {
            ctx->loadable_bad_name = 1;
            return 0;
        }
        ctx->loadable_count++;
        snprintf (ctx->loadable_name, sizeof ctx->loadable_name, "%s",
                  lname);
        bp_buf_free (&ctx->loadable_body);
        if (bp_buf_append (&ctx->loadable_body, body, body_len) < 0)
            return -1;
        ctx->loadable_mode =
            (mode_t) (bp_octal (h->mode, sizeof h->mode) & 07777);
        if (ctx->loadable_mode == 0) ctx->loadable_mode = 0755;
        return 0;
    }

    /* Only files/ entries become rootfs paths for legacy packages. */
    if (strncmp (path, "files/", 6) != 0) {
        ctx->other_payload_count++;
        return 0;
    }
    const char *rel = path + 6;
    if (!*rel) {
        ctx->files_payload_count++;
        return 0;
    }
    ctx->files_payload_count++;
    if (!ctx->allow_legacy_rootfs) return 0;
    if (!ctx->root) return 0;

    char dest[BPKG_PATH_MAX];
    if (snprintf (dest, sizeof dest, "%s/%s", ctx->root, rel) >=
        (int) sizeof dest) {
        builtin_error ("path too long: %s", rel);
        return -1;
    }

    char typ = h->typeflag;
    if (typ == '5') {
        if (bp_mkdir_p (dest) < 0) {
            builtin_error ("mkdir %s: %s", dest, strerror (errno));
            return -1;
        }
        if (bp_buf_append_line (&ctx->dirs_list, dest) < 0)
            return -1;
        return 0;
    }
    if (typ != '0' && typ != 0) {
        /* Skip unknown types (links, devices). */
        return 0;
    }

    /* Ensure parent exists. */
    char parent[BPKG_PATH_MAX];
    snprintf (parent, sizeof parent, "%s", dest);
    char *slash = strrchr (parent, '/');
    if (slash && slash != parent) {
        *slash = 0;
        if (bp_mkdir_p (parent) < 0) {
            builtin_error ("mkdir %s: %s", parent, strerror (errno));
            return -1;
        }
        if (bp_buf_append_line (&ctx->dirs_list, parent) < 0)
            return -1;
    }

    mode_t mode = (mode_t) (bp_octal (h->mode, sizeof h->mode) & 07777);
    if (mode == 0) mode = 0644;

    /* File-owned conflict gate: refuse if another installed package
     * already claims this rootfs path, unless --force is set. We check
     * the relative path with a leading '/' to match what verb_remove
     * writes into the files-list. The conflict check sits BEFORE the
     * write so a refusing install leaves the existing owner's bytes
     * intact on disk; the outer bp_rollback_extracted unwinds anything
     * already extracted from earlier callbacks in this run. */
    char rel_with_slash[BPKG_PATH_MAX];
    snprintf (rel_with_slash, sizeof rel_with_slash, "/%s", rel);
    char owner[BPKG_PATH_MAX];
    owner[0] = 0;
    int owned = bp_path_already_owned (ctx->root, rel_with_slash,
                                       owner, sizeof owner);
    if (owned > 0 && !ctx->force) {
        builtin_error ("file conflict: %s already owned by package '%s' "
                       "(use --force to override)",
                       rel_with_slash, owner);
        return -1;
    }

    if (bp_write_file_atomic (dest, body, body_len, mode) < 0) {
        builtin_error ("write %s: %s", dest, strerror (errno));
        return -1;
    }
    /* The Linux kernel strips S_ISUID/S_ISGID from the `mode` arg of
     * open(O_CREAT) under many configurations (umask path / inode
     * setup), so the file landed via bp_write_file_atomic above may
     * carry only the low 9 bits even when the tar header asked for
     * setuid/setgid/sticky. An explicit chmod after the rename forces
     * the full 12-bit mode onto the on-disk inode so the Stage A.9
     * mode-bit verifier can catch a tampered header that lifts
     * 0755 → 04755 (the regression 630-pkg-mode-bits.sh pins). */
    if (chmod (dest, mode) < 0) {
        builtin_error ("chmod %s: %s", dest, strerror (errno));
        return -1;
    }

    /* Record the installed path. */
    if (bp_buf_append (&ctx->files_list,
                       (const unsigned char *) "/", 1) < 0) return -1;
    if (bp_buf_append (&ctx->files_list,
                       (const unsigned char *) rel, strlen (rel)) < 0)
        return -1;
    if (bp_buf_append (&ctx->files_list,
                       (const unsigned char *) "\n", 1) < 0) return -1;

    return 0;
}

static int
bp_validate_loadable_archive (const char *pkgfile, const char *expected_name,
                              int require_loadable,
                              bp_manifest *out_manifest)
{
    bp_buf raw = {0};
    if (bp_read_file (pkgfile, &raw) < 0) {
        builtin_error ("read %s: %s", pkgfile, strerror (errno));
        return -1;
    }

    bp_buf tar = {0};
    const unsigned char *tar_data;
    size_t tar_len;
    if (bp_is_xz (raw.data, raw.len)) {
        if (bp_xz_decompress (raw.data, raw.len, &tar) < 0) {
            builtin_error ("xz decode failed: %s", pkgfile);
            bp_buf_free (&raw);
            bp_buf_free (&tar);
            return -1;
        }
        tar_data = tar.data;
        tar_len = tar.len;
    } else {
        tar_data = raw.data;
        tar_len = raw.len;
    }

    bp_install_ctx ctx = {0};
    int rc = bp_tar_iter (tar_data, tar_len, bp_extract_cb, &ctx);
    bp_buf_free (&raw);
    bp_buf_free (&tar);
    if (rc < 0) {
        builtin_error ("tar parse failed: %s", pkgfile);
        bp_install_ctx_free (&ctx);
        return -1;
    }
    if (!ctx.have_manifest) {
        builtin_error ("missing MANIFEST in %s", pkgfile);
        bp_install_ctx_free (&ctx);
        return -1;
    }

    bp_manifest m;
    bp_manifest_init (&m);
    if (bp_manifest_parse (&m, ctx.manifest.data, ctx.manifest.len) < 0) {
        builtin_error ("invalid MANIFEST in %s", pkgfile);
        bp_install_ctx_free (&ctx);
        bp_manifest_free (&m);
        return -1;
    }
    int is_loadable_pkg = bp_manifest_effective_is_loadable (&m);
    if (!is_loadable_pkg) {
        if (ctx.loadable_count || ctx.loadable_bad_name) {
            builtin_error ("payload package may not contain loadable/ entries");
            bp_install_ctx_free (&ctx);
            bp_manifest_free (&m);
            return -1;
        }
        if (require_loadable) {
            builtin_error ("not a v2 loadable package: %s", pkgfile);
            bp_install_ctx_free (&ctx);
            bp_manifest_free (&m);
            return -1;
        }
        if (out_manifest) {
            *out_manifest = m;
        } else {
            bp_manifest_free (&m);
        }
        bp_install_ctx_free (&ctx);
        return 0;
    }

    int bad = 0;
    if (ctx.manifest_count != 1) {
        builtin_error ("loadable package must contain exactly one MANIFEST");
        bad = 1;
    }
    if (!m.version[0] || !m.builtin[0] || !m.abi[0] ||
        !m.arch[0] || !bp_hex64 (m.sha256)) {
        builtin_error ("loadable package requires name/version/builtin/"
                       "abi/arch/sha256");
        bad = 1;
    }
    if (expected_name && strcmp (m.name, expected_name) != 0) {
        builtin_error ("index package name mismatch: %s has MANIFEST name %s",
                       expected_name, m.name);
        bad = 1;
    }
    if (ctx.loadable_count != 1 || ctx.loadable_bad_name) {
        builtin_error ("loadable package must contain exactly one "
                       "loadable/<name>.so");
        bad = 1;
    }
    if (ctx.files_payload_count || ctx.other_payload_count || ctx.hook_count ||
        ctx.hook_pre.len || ctx.hook_post.len ||
        ctx.hook_prerm.len || ctx.hook_postrm.len) {
        builtin_error ("loadable package may contain only MANIFEST "
                       "and loadable/<name>.so");
        bad = 1;
    }
    if (ctx.loadable_name[0]) {
        char expected[BPKG_NAME_MAX];
        snprintf (expected, sizeof expected, "%s.so", m.name);
        if (strcmp (ctx.loadable_name, expected) != 0) {
            builtin_error ("loadable filename %s does not match "
                           "package name %s", ctx.loadable_name, m.name);
            bad = 1;
        }
    }
    if (!bp_abi_matches (m.abi)) {
        builtin_error ("loadable ABI mismatch: %s", m.abi);
        bad = 1;
    }
    if (!bp_arch_matches (m.arch)) {
        builtin_error ("loadable arch mismatch: %s", m.arch);
        bad = 1;
    }
    if (ctx.loadable_body.len == 0) {
        builtin_error ("loadable object is not ELF");
        bad = 1;
    } else {
        char got[65];
        if (bp_sha256_bytes_hex (ctx.loadable_body.data,
                                  ctx.loadable_body.len, got) < 0 ||
            strcasecmp (got, m.sha256) != 0) {
            builtin_error ("loadable sha256 mismatch for %s",
                           ctx.loadable_name);
            bad = 1;
        }
        if (bp_loadable_reject_nonbundled_needed (ctx.loadable_body.data,
                                                   ctx.loadable_body.len)
            < 0) {
            bad = 1;
        }
    }

    if (bad) {
        bp_install_ctx_free (&ctx);
        bp_manifest_free (&m);
        return -1;
    }

    if (out_manifest) {
        *out_manifest = m;
    } else {
        bp_manifest_free (&m);
    }
    bp_install_ctx_free (&ctx);
    return 1;
}

static int
bp_run_hook_buf (bp_buf *hook, const char *pkgname, const char *version,
                 const char *prefix, const char *tag)
{
    if (hook->len == 0) return 0;
    char tmp[BPKG_PATH_MAX];
    if (snprintf (tmp, sizeof tmp, "/tmp/pkg.%d.%s.sh",
                  (int) getpid (), tag) >= (int) sizeof tmp) return -1;
    if (bp_write_file_atomic (tmp, hook->data, hook->len, 0700) < 0) {
        builtin_error ("write hook %s: %s", tmp, strerror (errno));
        return -1;
    }
    int rc = bp_run_script (tmp, pkgname, version, prefix);
    unlink (tmp);
    return rc;
}

static int
bp_install_pkgfile (const char *pkgfile, const char *root,
                    int allow_unsigned, int force,
                    int allow_legacy_rootfs)
{
    /* Verify signature (if present + bashsignify on PATH). */
    int sigrc = bp_verify_signature (pkgfile);
    if (sigrc < 0) {
        builtin_error ("signature verification failed: %s", pkgfile);
        return EXECUTION_FAILURE;
    }
    if (sigrc == 1 && !allow_unsigned) {
        builtin_error ("no signature for %s (re-run with -A to allow)",
                       pkgfile);
        return EXECUTION_FAILURE;
    }

    /* Read archive. */
    bp_buf raw = {0};
    if (bp_read_file (pkgfile, &raw) < 0) {
        builtin_error ("read %s: %s", pkgfile, strerror (errno));
        bp_buf_free (&raw);
        return EXECUTION_FAILURE;
    }
    bp_buf tar = {0};
    const unsigned char *tar_data;
    size_t tar_len;
    if (bp_is_xz (raw.data, raw.len)) {
        if (bp_xz_decompress (raw.data, raw.len, &tar) < 0) {
            builtin_error ("xz decode failed: %s", pkgfile);
            bp_buf_free (&raw);
            bp_buf_free (&tar);
            return EXECUTION_FAILURE;
        }
        tar_data = tar.data;
        tar_len = tar.len;
    } else {
        tar_data = raw.data;
        tar_len = raw.len;
    }

    bp_install_ctx ctx = {0};
    ctx.root = root;
    ctx.pkgname = "";
    ctx.force = force;
    /* First pass is metadata-only even when legacy compatibility is enabled.
     * This prevents a malformed v2 loadable archive that also contains
     * files/ payloads from overwriting rootfs paths before the v2 envelope
     * gate rejects it. Legacy rootfs packages are extracted only after the
     * archive is classified as non-loadable below. */
    ctx.allow_legacy_rootfs = 0;
    int rc = bp_tar_iter (tar_data, tar_len, bp_extract_cb, &ctx);
    /* Rollback contract (H05): a refused install must NOT leave any
     * extracted payload under --root. The integrity-check branch
     * already rolls back via bp_rollback_extracted; the tar-iter /
     * missing-MANIFEST / invalid-MANIFEST early-exits previously
     * leaked any files/ entries that bp_extract_cb wrote before the
     * fault. A malicious archive with `entry-1: files/x` + `entry-2:
     * bad-checksum` would write x to disk and then bail without
     * unwinding it. Mirror the integrity-check unwinding here so all
     * pre-state-dir refusals satisfy the same atomicity contract that
     * 256-pkg-install-rollback.sh + 291-pkg-tar-safety.sh pin. */
    if (rc < 0) {
        builtin_error ("tar parse failed: %s", pkgfile);
        bp_rollback_install (root, &ctx);
        bp_install_ctx_free (&ctx);
        bp_buf_free (&raw);
        bp_buf_free (&tar);
        return EXECUTION_FAILURE;
    }
    if (!ctx.have_manifest) {
        builtin_error ("missing MANIFEST in %s", pkgfile);
        bp_rollback_install (root, &ctx);
        bp_install_ctx_free (&ctx);
        bp_buf_free (&raw);
        bp_buf_free (&tar);
        return EXECUTION_FAILURE;
    }

    /* Parse MANIFEST to learn the package name. */
    bp_manifest m;
    bp_manifest_init (&m);
    if (bp_manifest_parse (&m, ctx.manifest.data, ctx.manifest.len) < 0)
    {
        builtin_error ("invalid MANIFEST in %s", pkgfile);
        bp_rollback_install (root, &ctx);
        bp_install_ctx_free (&ctx);
        bp_manifest_free (&m);
        bp_buf_free (&raw);
        bp_buf_free (&tar);
        return EXECUTION_FAILURE;
    }

    int declared_type = bp_manifest_type_is_declared (&m);
    int is_loadable_pkg = bp_manifest_effective_is_loadable (&m);
    if (is_loadable_pkg) {
        if (bp_validate_loadable_archive (pkgfile, NULL, 1, NULL) < 0) {
            bp_rollback_install (root, &ctx);
            bp_install_ctx_free (&ctx);
            bp_manifest_free (&m);
            bp_buf_free (&raw);
            bp_buf_free (&tar);
            return EXECUTION_FAILURE;
        }
    } else if (ctx.loadable_count || ctx.loadable_bad_name) {
        builtin_error ("payload package may not contain loadable/ entries");
        bp_rollback_install (root, &ctx);
        bp_install_ctx_free (&ctx);
        bp_manifest_free (&m);
        bp_buf_free (&raw);
        bp_buf_free (&tar);
        return EXECUTION_FAILURE;
    } else if (!declared_type && !allow_legacy_rootfs) {
        builtin_error ("legacy rootfs package compatibility requires "
                       "--legacy-rootfs or BASHPKG_ALLOW_LEGACY_ROOTFS=1: %s",
                       pkgfile);
        bp_rollback_install (root, &ctx);
        bp_install_ctx_free (&ctx);
        bp_manifest_free (&m);
        bp_buf_free (&raw);
        bp_buf_free (&tar);
        return EXECUTION_FAILURE;
    } else {
        bp_install_ctx_free (&ctx);
        memset (&ctx, 0, sizeof ctx);
        ctx.root = root;
        ctx.pkgname = "";
        ctx.force = force;
        ctx.allow_legacy_rootfs = 1;
        rc = bp_tar_iter (tar_data, tar_len, bp_extract_cb, &ctx);
        if (rc < 0 || !ctx.have_manifest) {
            builtin_error (rc < 0 ? "tar parse failed: %s" :
                           "missing MANIFEST in %s", pkgfile);
            bp_rollback_install (root, &ctx);
            bp_install_ctx_free (&ctx);
            bp_manifest_free (&m);
            bp_buf_free (&raw);
            bp_buf_free (&tar);
            return EXECUTION_FAILURE;
        }
    }
    bp_buf_free (&raw);
    bp_buf_free (&tar);

    /* Dependency check: refuse install when any required package is not
     * installed. Each dep maps to /var/lib/pkg/installed/<name>/
     * MANIFEST. Report all missing deps at once so the caller sees the
     * full picture rather than a frustrating one-at-a-time loop. */
    {
        int missing_dep = 0;
        for (int i = 0; i < m.ndeps; i++) {
            if (!bp_safe_name (m.deps[i])) {
                builtin_error ("invalid dependency name: %s", m.deps[i]);
                missing_dep = 1;
                continue;
            }
            char dep_manifest[BPKG_PATH_MAX];
            snprintf (dep_manifest, sizeof dep_manifest,
                      "%s%s/%s/MANIFEST",
                      root[0] && strcmp (root, "/") ? root : "",
                      BPKG_INSTALLED_DIR, m.deps[i]);
            struct stat st;
            if (stat (dep_manifest, &st) < 0 || !S_ISREG (st.st_mode)) {
                builtin_error ("missing dependency: %s", m.deps[i]);
                missing_dep = 1;
            } else if (is_loadable_pkg) {
                bp_buf dep_body = {0};
                bp_manifest dep_mf;
                bp_manifest_init (&dep_mf);
                char dep_so[BPKG_PATH_MAX];
                if (bp_read_file (dep_manifest, &dep_body) < 0 ||
                    bp_manifest_parse (&dep_mf, dep_body.data,
                                       dep_body.len) < 0 ||
                    bp_verify_installed_loadable (root, m.deps[i],
                                                  &dep_mf, dep_so,
                                                  sizeof dep_so)
                    != EXECUTION_SUCCESS) {
                    builtin_error ("dependency is not a loadable package: %s",
                                   m.deps[i]);
                    missing_dep = 1;
                }
                bp_buf_free (&dep_body);
                bp_manifest_free (&dep_mf);
            }
        }
        if (missing_dep) {
            bp_rollback_install (root, &ctx);
            bp_install_ctx_free (&ctx);
            bp_manifest_free (&m);
            return EXECUTION_FAILURE;
        }
    }

    if (is_loadable_pkg && bp_install_staged_loadable (&ctx, root) < 0) {
        bp_rollback_install (root, &ctx);
        bp_install_ctx_free (&ctx);
        bp_manifest_free (&m);
        return EXECUTION_FAILURE;
    }
    if (is_loadable_pkg &&
        bp_verify_loadable_mode (root, &ctx.manifest, ctx.loadable_dest) < 0)
    {
        builtin_error ("mode-bit check failed: %s", pkgfile);
        bp_rollback_install (root, &ctx);
        bp_install_ctx_free (&ctx);
        bp_manifest_free (&m);
        return EXECUTION_FAILURE;
    }

    /* Per-file SHA-256 integrity gate (Stage A.8). Refuse install if
     * any extracted payload disagrees with its MANIFEST sha256 entry.
     * MANIFESTs with no sha256 entries are tolerated (Round-8 compat).
     * On failure we unlink the just-extracted files so the rootfs
     * doesn't carry tampered payload after the refused install. */
    if (bp_verify_files_sha256 (root, &ctx.manifest, &ctx.files_list) < 0)
    {
        builtin_error ("file integrity check failed: %s", pkgfile);
        bp_rollback_install (root, &ctx);
        bp_install_ctx_free (&ctx);
        bp_manifest_free (&m);
        return EXECUTION_FAILURE;
    }

    /* Per-file mode-bit verification (Stage A.9 hardening). Refuse
     * install if any extracted file's st_mode (low 12 bits) disagrees
     * with its MANIFEST mode entry. MANIFESTs with no mode entries are
     * tolerated (Stage A.8 compat); files with no entry in a
     * mode-populated MANIFEST emit a warn-only stderr line. Same
     * rollback shape as the sha256 gate so a refused install leaves no
     * extracted payload behind. */
    if (bp_verify_files_modes (root, &ctx.manifest, &ctx.files_list) < 0)
    {
        builtin_error ("mode-bit check failed: %s", pkgfile);
        bp_rollback_install (root, &ctx);
        bp_install_ctx_free (&ctx);
        bp_manifest_free (&m);
        return EXECUTION_FAILURE;
    }

    /* Run pre-install hook BEFORE writing any state. The extract loop
     * has already written files into the rootfs (idempotent overwrite),
     * so this hook gets a chance to abort propagation to state. */
    if (bp_run_hook_buf (&ctx.hook_pre, m.name, m.version, root,
                         "pre-install") < 0)
    {
        bp_rollback_install (root, &ctx);
        bp_install_ctx_free (&ctx);
        bp_manifest_free (&m);
        return EXECUTION_FAILURE;
    }

    /* Record install state. */
    char dir[BPKG_PATH_MAX];
    char manifest_path[BPKG_PATH_MAX];
    char files_path[BPKG_PATH_MAX];
    snprintf (dir, sizeof dir, "%s%s/%s",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_INSTALLED_DIR, m.name);
    if (bp_prepare_state_dir (&ctx, dir) < 0)
        goto fail_state;
    if (bp_mkdir_p (dir) < 0) {
        builtin_error ("mkdir state dir %s: %s", dir, strerror (errno));
        goto fail_state;
    }
    snprintf (manifest_path, sizeof manifest_path, "%s/MANIFEST", dir);
    snprintf (files_path,    sizeof files_path,    "%s/files",    dir);
    char sha256_path[BPKG_PATH_MAX];
    snprintf (sha256_path, sizeof sha256_path, "%s/sha256", dir);
    if (bp_write_file_atomic (manifest_path, ctx.manifest.data,
                              ctx.manifest.len, 0644) < 0) {
        builtin_error ("write %s: %s", manifest_path, strerror (errno));
        goto fail_state;
    }
    if (!is_loadable_pkg &&
        bp_write_file_atomic (files_path, ctx.files_list.data,
                              ctx.files_list.len, 0644) < 0) {
        builtin_error ("write %s: %s", files_path, strerror (errno));
        goto fail_state;
    }
    if (is_loadable_pkg &&
        bp_write_file_atomic (sha256_path,
                              (const unsigned char *) m.sha256,
                              strlen (m.sha256), 0644) < 0) {
        builtin_error ("write %s: %s", sha256_path, strerror (errno));
        goto fail_state;
    }
    /* Stash hook scripts for later removal. */
    if (ctx.hook_prerm.len > 0) {
        char hp[BPKG_PATH_MAX];
        snprintf (hp, sizeof hp, "%s/pre-remove", dir);
        if (bp_write_file_atomic (hp, ctx.hook_prerm.data,
                                  ctx.hook_prerm.len, 0700) < 0) {
            goto fail_state;
        }
    }
    if (ctx.hook_postrm.len > 0) {
        char hp[BPKG_PATH_MAX];
        snprintf (hp, sizeof hp, "%s/post-remove", dir);
        if (bp_write_file_atomic (hp, ctx.hook_postrm.data,
                                  ctx.hook_postrm.len, 0700) < 0) {
            goto fail_state;
        }
    }

    /* Run post-install. */
    if (bp_run_hook_buf (&ctx.hook_post, m.name, m.version, root,
                         "post-install") < 0)
    {
        goto fail_state;
    }

    printf ("installed %s %s\n", m.name,
            m.version[0] ? m.version : "(no version)");

    bp_commit_install (&ctx);
    bp_install_ctx_free (&ctx);
    bp_manifest_free (&m);
    return EXECUTION_SUCCESS;

fail_state:
    bp_rollback_install (root, &ctx);
    bp_install_ctx_free (&ctx);
    bp_manifest_free (&m);
    return EXECUTION_FAILURE;
}

/* ---- Cache lookup --------------------------------------------------- */

static int bp_manifest_from_pkgfile (const char *pkgfile, bp_manifest *m);

/* Find the lexically-largest filename-shaped cache candidate whose MANIFEST
 * name exactly matches the requested package. Prefix-shaped cache filenames
 * such as foo-bar-1.0.pkg must not mask a valid foo package. */
static int
bp_find_in_cache (const char *root, const char *name, char *out,
                  size_t outsz)
{
    char dir[BPKG_PATH_MAX];
    snprintf (dir, sizeof dir, "%s%s",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_CACHE_DIR);
    DIR *d = opendir (dir);
    if (!d) return -1;
    char best[BPKG_PATH_MAX] = {0};
    size_t nlen = strlen (name);
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        size_t dn = strlen (de->d_name);
        if (dn <= nlen + 1) continue;
        if (strncmp (de->d_name, name, nlen) != 0) continue;
        if (de->d_name[nlen] != '-' && de->d_name[nlen] != '.') continue;
        if (dn < 9 || strcmp (de->d_name + dn - 8, ".pkg") != 0)
            continue;
        char candidate[BPKG_PATH_MAX];
        if (snprintf (candidate, sizeof candidate, "%s/%s", dir,
                      de->d_name) >= (int) sizeof candidate)
            continue;
        bp_manifest mf;
        if (bp_manifest_from_pkgfile (candidate, &mf) < 0)
            continue;
        int name_matches = strcmp (mf.name, name) == 0;
        bp_manifest_free (&mf);
        if (!name_matches)
            continue;
        if (strcmp (de->d_name, best) > 0)
            snprintf (best, sizeof best, "%s", de->d_name);
    }
    closedir (d);
    if (!best[0]) return -1;
    if (snprintf (out, outsz, "%s/%s", dir, best) >= (int) outsz)
        return -1;
    return 0;
}

static int
bp_cache_candidate_name_matches (const char *pkgfile, const char *name,
                                 char *got, size_t got_len)
{
    bp_manifest mf;
    if (bp_manifest_from_pkgfile (pkgfile, &mf) < 0)
        return -1;
    if (got && got_len > 0)
        snprintf (got, got_len, "%s", mf.name);
    int match = strcmp (mf.name, name) == 0;
    bp_manifest_free (&mf);
    return match ? 1 : 0;
}

static int
bp_dep_installed (const char *root, const char *name)
{
    if (!bp_safe_name (name)) return 0;
    char dep_manifest[BPKG_PATH_MAX];
    snprintf (dep_manifest, sizeof dep_manifest, "%s%s/%s/MANIFEST",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_INSTALLED_DIR, name);
    struct stat st;
    return stat (dep_manifest, &st) == 0 && S_ISREG (st.st_mode);
}

static int
bp_loadable_dep_installed (const char *root, const char *name)
{
    if (!bp_safe_name (name)) return 0;
    char dep_manifest[BPKG_PATH_MAX];
    snprintf (dep_manifest, sizeof dep_manifest, "%s%s/%s/MANIFEST",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_INSTALLED_DIR, name);
    bp_buf body = {0};
    bp_manifest mf;
    if (bp_read_file (dep_manifest, &body) < 0)
        return 0;
    char so_path[BPKG_PATH_MAX];
    int ok = bp_manifest_parse (&mf, body.data, body.len) == 0 &&
             bp_verify_installed_loadable (root, name, &mf, so_path,
                                           sizeof so_path)
             == EXECUTION_SUCCESS;
    bp_manifest_free (&mf);
    bp_buf_free (&body);
    return ok;
}

typedef struct {
    bp_buf manifest;
    int have_manifest;
} bp_manifest_scan_ctx;

static int
bp_manifest_scan_cb (const bp_tar_hdr *h, const char *path,
                     const unsigned char *body, size_t body_len,
                     void *opaque)
{
    (void) h;
    bp_manifest_scan_ctx *ctx = (bp_manifest_scan_ctx *) opaque;
    if (!bp_safe_path (path))
        return -1;
    if (strcmp (path, "MANIFEST") != 0)
        return 0;
    bp_buf_free (&ctx->manifest);
    if (bp_buf_append (&ctx->manifest, body, body_len) < 0)
        return -1;
    ctx->have_manifest = 1;
    return 1;
}

static int
bp_manifest_from_pkgfile (const char *pkgfile, bp_manifest *m)
{
    bp_buf raw = {0};
    if (bp_read_file (pkgfile, &raw) < 0) {
        bp_buf_free (&raw);
        return -1;
    }

    bp_buf tar = {0};
    const unsigned char *tar_data;
    size_t tar_len;
    if (bp_is_xz (raw.data, raw.len)) {
        if (bp_xz_decompress (raw.data, raw.len, &tar) < 0) {
            bp_buf_free (&raw);
            bp_buf_free (&tar);
            return -1;
        }
        tar_data = tar.data;
        tar_len = tar.len;
    } else {
        tar_data = raw.data;
        tar_len = raw.len;
    }

    bp_manifest_scan_ctx ctx = {0};
    int rc = bp_tar_iter (tar_data, tar_len, bp_manifest_scan_cb, &ctx);
    bp_buf_free (&raw);
    bp_buf_free (&tar);
    if (rc < 0 || !ctx.have_manifest) {
        bp_buf_free (&ctx.manifest);
        return -1;
    }

    rc = bp_manifest_parse (m, ctx.manifest.data, ctx.manifest.len);
    bp_buf_free (&ctx.manifest);
    return rc;
}

static int
bp_install_pkgfile_resolving_deps (const char *pkgfile, const char *root,
                                   int allow_unsigned, int force,
                                   int allow_legacy_rootfs, int depth)
{
    if (depth == 0)
        bp_install_dep_stack_depth = 0;
    if (depth > BPKG_MAX_DEPS) {
        builtin_error ("dependency resolution depth exceeded: %s", pkgfile);
        return EXECUTION_FAILURE;
    }

    /* Do not let an archive whose envelope would be refused drive
     * recursive dependency selection via its MANIFEST. The lower install
     * path verifies again before extraction; this pre-check protects the
     * resolver's manifest-only scan. */
    int sigrc = bp_verify_signature (pkgfile);
    if (sigrc < 0) {
        builtin_error ("signature verification failed: %s", pkgfile);
        return EXECUTION_FAILURE;
    }
    if (sigrc == 1 && !allow_unsigned) {
        builtin_error ("no signature for %s (re-run with -A to allow)",
                       pkgfile);
        return EXECUTION_FAILURE;
    }

    bp_manifest m;
    if (bp_manifest_from_pkgfile (pkgfile, &m) < 0) {
        /* Keep malformed archive diagnostics centralized in the normal
         * install path, which already emits the precise failure reason. */
        return bp_install_pkgfile (pkgfile, root, allow_unsigned, force,
                                   allow_legacy_rootfs);
    }

    if (bp_manifest_type_is_declared (&m) &&
        !bp_manifest_type_is_known (&m)) {
        builtin_error ("install: unsupported package type: %s",
                       bp_manifest_effective_type (&m));
        bp_manifest_free (&m);
        return EXECUTION_FAILURE;
    }

    int is_loadable_pkg = bp_manifest_effective_is_loadable (&m);
    if (is_loadable_pkg &&
        bp_validate_loadable_archive (pkgfile, NULL, 0, NULL) < 0) {
        bp_manifest_free (&m);
        return EXECUTION_FAILURE;
    }
    for (int i = 0; i < m.ndeps; i++) {
        if (!bp_safe_name (m.deps[i])) {
            builtin_error ("invalid dependency name: %s", m.deps[i]);
            bp_manifest_free (&m);
            return EXECUTION_FAILURE;
        }
        if (!strcmp (m.deps[i], m.name)) {
            builtin_error ("package depends on itself: %s", m.name);
            bp_manifest_free (&m);
            return EXECUTION_FAILURE;
        }
        if (bp_dep_stack_contains (bp_install_dep_stack,
                                   bp_install_dep_stack_depth, m.deps[i])) {
            builtin_error ("dependency cycle: %s -> %s", m.name, m.deps[i]);
            bp_manifest_free (&m);
            return EXECUTION_FAILURE;
        }
        if (is_loadable_pkg
            ? bp_loadable_dep_installed (root, m.deps[i])
            : bp_dep_installed (root, m.deps[i]))
            continue;

        char dep_path[BPKG_PATH_MAX];
        if (bp_find_in_cache (root, m.deps[i], dep_path,
                              sizeof dep_path) < 0)
        {
            builtin_error ("missing dependency: %s", m.deps[i]);
            bp_manifest_free (&m);
            return EXECUTION_FAILURE;
        }
        char got_name[BPKG_NAME_MAX] = {0};
        if (bp_cache_candidate_name_matches (dep_path, m.deps[i], got_name,
                                             sizeof got_name) != 1) {
            builtin_error ("cache candidate name mismatch: %s has MANIFEST "
                           "name %s",
                           m.deps[i], got_name[0] ? got_name : "(unknown)");
            bp_manifest_free (&m);
            return EXECUTION_FAILURE;
        }
        if (is_loadable_pkg) {
            if (bp_validate_loadable_archive (dep_path, m.deps[i],
                                              1, NULL) < 0) {
                builtin_error ("dependency is not a loadable package: %s",
                               m.deps[i]);
                bp_manifest_free (&m);
                return EXECUTION_FAILURE;
            }
        }

        if (bp_dep_stack_push (bp_install_dep_stack,
                               &bp_install_dep_stack_depth, m.name) < 0) {
            builtin_error ("dependency resolution depth exceeded: %s",
                           m.name);
            bp_manifest_free (&m);
            return EXECUTION_FAILURE;
        }
        int rc = bp_install_pkgfile_resolving_deps (dep_path, root,
                                                    allow_unsigned, force,
                                                    is_loadable_pkg ? 0 :
                                                        allow_legacy_rootfs,
                                                    depth + 1);
        bp_install_dep_stack_depth--;
        if (rc != EXECUTION_SUCCESS) {
            bp_manifest_free (&m);
            return rc;
        }
    }

    bp_manifest_free (&m);
    return bp_install_pkgfile (pkgfile, root, allow_unsigned, force,
                               allow_legacy_rootfs);
}

static int
bp_index_line_is_loadable_record (const char *line)
{
    if (!line) return 0;
    while (*line && isspace ((unsigned char) *line)) line++;
    if (!*line || *line == '#') return 0;

    char copy[2048];
    size_t llen = strlen (line);
    if (llen >= sizeof copy) return 0;
    memcpy (copy, line, llen + 1);

    int first = 1;
    char *save = NULL;
    for (char *tok = strtok_r (copy, " \t\r\n", &save);
         tok;
         tok = strtok_r (NULL, " \t\r\n", &save)) {
        if (first && strcmp (tok, "pkg-loadable-v1") == 0)
            return 1;
        if (strcmp (tok, "type=loadable") == 0)
            return 1;
        first = 0;
    }
    return 0;
}

static int
bp_index_pkg_candidate (const char *line, const char *name,
                        char *out, size_t outsz,
                        char *sha_out, size_t sha_outsz,
                        char *sig_out, size_t sig_outsz,
                        char *deps_out, size_t deps_outsz,
                        char *version_out, size_t version_outsz,
                        char *builtin_out, size_t builtin_outsz,
                        char *abi_out, size_t abi_outsz,
                        char *arch_out, size_t arch_outsz,
                        char *delta_out, size_t delta_outsz,
                        char *delta_sig_out, size_t delta_sig_outsz,
                        char *delta_from_out, size_t delta_from_outsz,
                        char *delta_to_out, size_t delta_to_outsz,
                        int *is_url_out)
{
    if (!line || !name || !*name) return 0;
    while (*line && isspace ((unsigned char) *line)) line++;
    if (!*line || *line == '#') return 0;

    if (bp_index_line_is_loadable_record (line))
    {
        char copy[2048];
        char iname[BPKG_NAME_MAX] = {0};
        char version[BPKG_NAME_MAX] = {0};
        char builtin[BPKG_NAME_MAX] = {0};
        char abi[BPKG_NAME_MAX] = {0};
        char arch[BPKG_NAME_MAX] = {0};
        char pkg[BPKG_PATH_MAX] = {0};
        char sha[65] = {0};
        char sig[BPKG_PATH_MAX] = {0};
        char deps[1024] = {0};
        char delta[BPKG_PATH_MAX] = {0};
        char delta_sig[BPKG_PATH_MAX] = {0};
        char delta_from[65] = {0};
        char delta_to[65] = {0};
        int is_url = 0;
        size_t llen = strlen (line);
        if (llen >= sizeof copy) return 0;
        memcpy (copy, line, llen + 1);
        char *save = NULL;
        for (char *tok = strtok_r (copy, " \t\r\n", &save);
             tok;
             tok = strtok_r (NULL, " \t\r\n", &save))
        {
            if (!strncmp (tok, "name=", 5))
                snprintf (iname, sizeof iname, "%s", tok + 5);
            else if (!strncmp (tok, "version=", 8))
                snprintf (version, sizeof version, "%s", tok + 8);
            else if (!strncmp (tok, "builtin=", 8))
                snprintf (builtin, sizeof builtin, "%s", tok + 8);
            else if (!strncmp (tok, "abi=", 4))
                snprintf (abi, sizeof abi, "%s", tok + 4);
            else if (!strncmp (tok, "arch=", 5))
                snprintf (arch, sizeof arch, "%s", tok + 5);
            else if (!strncmp (tok, "package=", 8))
                snprintf (pkg, sizeof pkg, "%s", tok + 8);
            else if (!strncmp (tok, "path=", 5))
                snprintf (pkg, sizeof pkg, "%s", tok + 5);
            else if (!strncmp (tok, "url=", 4)) {
                snprintf (pkg, sizeof pkg, "%s", tok + 4);
                is_url = 1;
            }
            else if (!strncmp (tok, "sha256=", 7))
                snprintf (sha, sizeof sha, "%s", tok + 7);
            else if (!strncmp (tok, "sig=", 4))
                snprintf (sig, sizeof sig, "%s", tok + 4);
            else if (!strncmp (tok, "deps=", 5))
                snprintf (deps, sizeof deps, "%s", tok + 5);
            else if (!strncmp (tok, "delta=", 6))
                snprintf (delta, sizeof delta, "%s", tok + 6);
            else if (!strncmp (tok, "delta_sig=", 10))
                snprintf (delta_sig, sizeof delta_sig, "%s", tok + 10);
            else if (!strncmp (tok, "delta-from=", 11))
                snprintf (delta_from, sizeof delta_from, "%s", tok + 11);
            else if (!strncmp (tok, "delta_from=", 11))
                snprintf (delta_from, sizeof delta_from, "%s", tok + 11);
            else if (!strncmp (tok, "from-sha256=", 12))
                snprintf (delta_from, sizeof delta_from, "%s", tok + 12);
            else if (!strncmp (tok, "delta-to=", 9))
                snprintf (delta_to, sizeof delta_to, "%s", tok + 9);
            else if (!strncmp (tok, "delta_to=", 9))
                snprintf (delta_to, sizeof delta_to, "%s", tok + 9);
            else if (!strncmp (tok, "to-sha256=", 10))
                snprintf (delta_to, sizeof delta_to, "%s", tok + 10);
        }
        if (!iname[0] || strcmp (iname, name) != 0 || !pkg[0])
            return 0;
        if (!version[0]) {
            builtin_error ("loadable index entry for %s requires version=VER",
                           name);
            return -1;
        }
        if (!builtin[0]) {
            builtin_error ("loadable index entry for %s requires builtin=NAME",
                           name);
            return -1;
        }
        if (!abi[0]) {
            builtin_error ("loadable index entry for %s requires abi=ABI",
                           name);
            return -1;
        }
        if (!arch[0]) {
            builtin_error ("loadable index entry for %s requires arch=ARCH",
                           name);
            return -1;
        }
        if (!bp_hex64 (sha)) {
            builtin_error ("loadable index entry for %s requires sha256=HEX64",
                           name);
            return -1;
        }
        if (!sig[0]) {
            builtin_error ("loadable index entry for %s requires sig=REF",
                           name);
            return -1;
        }
        if (!deps[0]) {
            builtin_error ("loadable index entry for %s requires deps=LIST",
                           name);
            return -1;
        }
        if (delta[0] &&
            (strlen (delta) < 15 ||
             strcmp (delta + strlen (delta) - 14, ".pkg.delta") != 0)) {
            builtin_error ("loadable index entry for %s has bad delta=REF",
                           name);
            return -1;
        }
        if (delta[0] && (!bp_hex64 (delta_from) || !bp_hex64 (delta_to))) {
            builtin_error ("loadable index entry for %s delta requires "
                           "delta_from=HEX64 and delta_to=HEX64", name);
            return -1;
        }
        size_t plen = strlen (pkg);
        if (plen < 9 || strcmp (pkg + plen - 8, ".pkg") != 0)
            return 0;
        if (snprintf (out, outsz, "%s", pkg) >= (int) outsz)
            return -1;
        if (sha_out && sha_outsz > 0 &&
            snprintf (sha_out, sha_outsz, "%s", sha) >= (int) sha_outsz)
            return -1;
        if (sig_out && sig_outsz > 0 &&
            snprintf (sig_out, sig_outsz, "%s", sig) >= (int) sig_outsz)
            return -1;
        if (deps_out && deps_outsz > 0 &&
            snprintf (deps_out, deps_outsz, "%s", deps) >= (int) deps_outsz)
            return -1;
        if (version_out && version_outsz > 0 &&
            snprintf (version_out, version_outsz, "%s", version) >=
            (int) version_outsz)
            return -1;
        if (builtin_out && builtin_outsz > 0 &&
            snprintf (builtin_out, builtin_outsz, "%s", builtin) >=
            (int) builtin_outsz)
            return -1;
        if (abi_out && abi_outsz > 0 &&
            snprintf (abi_out, abi_outsz, "%s", abi) >= (int) abi_outsz)
            return -1;
        if (arch_out && arch_outsz > 0 &&
            snprintf (arch_out, arch_outsz, "%s", arch) >= (int) arch_outsz)
            return -1;
        if (delta_out && delta_outsz > 0 &&
            snprintf (delta_out, delta_outsz, "%s", delta) >=
            (int) delta_outsz)
            return -1;
        if (delta_sig_out && delta_sig_outsz > 0 &&
            snprintf (delta_sig_out, delta_sig_outsz, "%s", delta_sig) >=
            (int) delta_sig_outsz)
            return -1;
        if (delta_from_out && delta_from_outsz > 0 &&
            snprintf (delta_from_out, delta_from_outsz, "%s", delta_from) >=
            (int) delta_from_outsz)
            return -1;
        if (delta_to_out && delta_to_outsz > 0 &&
            snprintf (delta_to_out, delta_to_outsz, "%s", delta_to) >=
            (int) delta_to_outsz)
            return -1;
        if (is_url_out)
            *is_url_out = is_url;
        return 1;
    }

    return 0;
}

static int
bp_index_line_supported (const char *line)
{
    return bp_index_line_is_loadable_record (line);
}

static int
bp_source_local_path (const char *url, char *out, size_t outsz)
{
    const char *local = NULL;
    if (strncmp (url, "file://", 7) == 0) {
        local = url + 7;
        if (local[0] != '/')
            return -1;
    } else if (url[0] == '/') {
        local = url;
    } else {
        return 0;
    }
    if (!*local) return 0;
    if (snprintf (out, outsz, "%s", local) >= (int) outsz) return -1;
    return 1;
}

static int
bp_source_index_path (const char *local, char *idx, size_t idxsz,
                      char *pkgdir, size_t pkgdirsz)
{
    struct stat st;
    if (stat (local, &st) < 0) return -1;
    if (S_ISDIR (st.st_mode)) {
        if (snprintf (idx, idxsz, "%s/INDEX", local) >= (int) idxsz)
            return -1;
        if (snprintf (pkgdir, pkgdirsz, "%s", local) >= (int) pkgdirsz)
            return -1;
    } else {
        const char *slash = strrchr (local, '/');
        size_t dlen = slash ? (size_t) (slash - local) : 1;
        if (snprintf (idx, idxsz, "%s", local) >= (int) idxsz)
            return -1;
        if (dlen >= pkgdirsz) return -1;
        if (slash) {
            memcpy (pkgdir, local, dlen);
            pkgdir[dlen] = 0;
        } else {
            snprintf (pkgdir, pkgdirsz, ".");
        }
    }
    return 0;
}

static int
bp_source_arch_index_path (const char *local, const char *arch,
                           char *idx, size_t idxsz,
                           char *pkgdir, size_t pkgdirsz)
{
    struct stat st;
    if (!arch || !*arch || !bp_safe_name (arch)) return -1;
    if (stat (local, &st) < 0 || !S_ISDIR (st.st_mode)) return -1;
    if (snprintf (idx, idxsz, "%s/%s/INDEX", local, arch) >= (int) idxsz)
        return -1;
    if (snprintf (pkgdir, pkgdirsz, "%s/%s", local, arch) >=
        (int) pkgdirsz)
        return -1;
    if (stat (idx, &st) < 0 || !S_ISREG (st.st_mode)) return -1;
    return 0;
}

static int
bp_update_copy_index (const char *src_idx, const char *src_pkgdir,
                      const char *dest_dir)
{
    if (bp_mkdir_p (dest_dir) < 0)
        return -1;
    bp_buf idx_body = {0};
    if (bp_read_file (src_idx, &idx_body) < 0) {
        builtin_warning ("source %s: %s", src_idx, strerror (errno));
        bp_buf_free (&idx_body);
        return -1;
    }
    int sigrc = bp_verify_signature (src_idx);
    if (sigrc < 0) {
        builtin_error ("signature verification failed for %s", src_idx);
        bp_buf_free (&idx_body);
        return -1;
    }
    char idx[BPKG_PATH_MAX];
    if (snprintf (idx, sizeof idx, "%s/INDEX", dest_dir) >=
        (int) sizeof idx) {
        bp_buf_free (&idx_body);
        return -1;
    }
    if (bp_write_file_atomic (idx, idx_body.data, idx_body.len, 0644) < 0) {
        builtin_error ("write %s: %s", idx, strerror (errno));
        bp_buf_free (&idx_body);
        return -1;
    }
    bp_buf_free (&idx_body);

    char origin[BPKG_PATH_MAX];
    if (snprintf (origin, sizeof origin, "%s/ORIGIN", dest_dir) <
        (int) sizeof origin) {
        size_t olen = strlen (src_pkgdir);
        bp_write_file_atomic (origin, (const unsigned char *) src_pkgdir,
                              olen, 0644);
    }
    return 0;
}

static int
bp_remote_url (const char *url)
{
    return url && (!strncmp (url, "http://", 7) ||
                   !strncmp (url, "https://", 8));
}

static int
bp_source_remote (const char *url, int *is_https_out, int *is_http_out)
{
    const char *p = NULL;
    int is_https = 0;
    int is_http = 0;
    if (!url) return 0;
    if (!strncmp (url, "https://", 8)) {
        p = url + 8;
        is_https = 1;
    } else if (!strncmp (url, "http://", 7)) {
        p = url + 7;
        is_http = 1;
    } else {
        return 0;
    }

    const char *slash = strchr (p, '/');
    if (!slash || slash == p || slash[1] == 0)
        return -1;
    for (const char *q = p; q < slash; q++) {
        if (isspace ((unsigned char) *q) || *q == '/')
            return -1;
    }
    if (is_https_out) *is_https_out = is_https;
    if (is_http_out) *is_http_out = is_http;
    return 1;
}

static char *
bp_source_parse_marker (char *line, int *remote_out, int *insecure_out)
{
    char *p = bp_strip (line);
    int remote = 0;
    int insecure = 0;
    for (;;) {
        char *q = p;
        while (*q && !isspace ((unsigned char) *q))
            q++;
        size_t n = (size_t) (q - p);
        if (n == 6 && strncmp (p, "remote", 6) == 0) {
            remote = 1;
        } else if ((n == 15 && strncmp (p, "remote-insecure", 15) == 0) ||
                   (n == 8 && strncmp (p, "insecure", 8) == 0)) {
            remote = 1;
            insecure = 1;
        } else {
            break;
        }
        p = bp_strip (q);
    }
    if (remote_out) *remote_out = remote;
    if (insecure_out) *insecure_out = insecure;
    return p;
}

static int
bp_repo_name_from_source (const char *url, char *out, size_t outsz)
{
    char tmp[BPKG_PATH_MAX];
    if (!url || snprintf (tmp, sizeof tmp, "%s", url) >= (int) sizeof tmp)
        return -1;
    size_t n = strlen (tmp);
    while (n > 0 && tmp[n - 1] == '/')
        tmp[--n] = 0;
    const char *base = strrchr (tmp, '/');
    base = base ? base + 1 : tmp;
    if (!*base || !bp_safe_name (base))
        base = "default";
    return snprintf (out, outsz, "%s", base) < (int) outsz ? 0 : -1;
}

static int
bp_url_join (const char *base, const char *ref, char *out, size_t outsz)
{
    if (!base || !*base || !ref || !*ref) return -1;
    if (bp_remote_url (ref))
        return snprintf (out, outsz, "%s", ref) < (int) outsz ? 0 : -1;
    if (ref[0] == '/' || !bp_safe_path (ref))
        return -1;
    size_t bl = strlen (base);
    return snprintf (out, outsz, "%s%s%s", base,
                     (bl > 0 && base[bl - 1] == '/') ? "" : "/", ref)
           < (int) outsz ? 0 : -1;
}

static int
bp_parent_mkdir_p (const char *path)
{
    char parent[BPKG_PATH_MAX];
    if (!path || snprintf (parent, sizeof parent, "%s", path) >=
        (int) sizeof parent)
        return -1;
    char *slash = strrchr (parent, '/');
    if (!slash) return 0;
    if (slash == parent)
        slash[1] = 0;
    else
        *slash = 0;
    return bp_mkdir_p (parent);
}

static int
bp_ref_relative_path (const char *ref, int is_url, char *out, size_t outsz)
{
    const char *rel = ref;
    if (!ref || !*ref) return -1;
    if (is_url || bp_remote_url (ref)) {
        rel = strrchr (ref, '/');
        rel = rel ? rel + 1 : ref;
    }
    if (!*rel || rel[0] == '/' || !bp_safe_path (rel))
        return -1;
    return snprintf (out, outsz, "%s", rel) < (int) outsz ? 0 : -1;
}

static int
bp_copy_file_atomic_mode (const char *src, const char *dst, mode_t mode)
{
    bp_buf body = {0};
    if (bp_read_file (src, &body) < 0) {
        bp_buf_free (&body);
        return -1;
    }
    if (bp_parent_mkdir_p (dst) < 0) {
        bp_buf_free (&body);
        return -1;
    }
    int rc = bp_write_file_atomic (dst, body.data, body.len, mode);
    bp_buf_free (&body);
    return rc;
}

static int
bp_copy_tree_into (const char *src, const char *dst)
{
    struct stat st;
    if (lstat (src, &st) < 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }
    if (S_ISDIR (st.st_mode)) {
        if (bp_mkdir_p (dst) < 0)
            return -1;
        DIR *d = opendir (src);
        if (!d) return -1;
        struct dirent *de;
        while ((de = readdir (d)) != NULL) {
            if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, ".."))
                continue;
            char s[BPKG_PATH_MAX], t[BPKG_PATH_MAX];
            if (snprintf (s, sizeof s, "%s/%s", src, de->d_name) >=
                    (int) sizeof s ||
                snprintf (t, sizeof t, "%s/%s", dst, de->d_name) >=
                    (int) sizeof t) {
                closedir (d);
                return -1;
            }
            if (bp_copy_tree_into (s, t) < 0) {
                closedir (d);
                return -1;
            }
        }
        closedir (d);
        return 0;
    }
    if (!S_ISREG (st.st_mode))
        return -1;
    return bp_copy_file_atomic_mode (src, dst, (mode_t) (st.st_mode & 0777));
}

static int
bp_fetch_url (const char *url, const char *out_path, const char *cacert,
              int insecure, int timeout, long *http_code_out)
{
    if (!bp_remote_url (url) || !out_path || !*out_path)
        return -1;
    if (timeout <= 0)
        timeout = 30;
    if (bp_parent_mkdir_p (out_path) < 0)
        return -1;
    unlink (out_path);

    char timeout_buf[32];
    snprintf (timeout_buf, sizeof timeout_buf, "%d", timeout);
    maybe_make_export_env ();

    int pipefd[2];
    if (pipe (pipefd) < 0)
        return -1;
    struct bpkg_child_guard guard;
    if (bpkg_child_guard_begin (&guard) < 0) {
        close (pipefd[0]);
        close (pipefd[1]);
        return -1;
    }
    pid_t pid = fork ();
    if (pid < 0) {
        bpkg_child_guard_parent_end (&guard);
        close (pipefd[0]);
        close (pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        bpkg_child_guard_child_end (&guard);
        close (pipefd[0]);
        if (dup2 (pipefd[1], STDOUT_FILENO) < 0)
            _exit (126);
        close (pipefd[1]);
        if (cacert && *cacert && insecure)
            execlp ("curl", "curl", "-fsS", "-m", timeout_buf,
                    "--cacert", cacert, "-k", "-o", out_path,
                    "-w", "%{http_code}", url, (char *) NULL);
        else if (cacert && *cacert)
            execlp ("curl", "curl", "-fsS", "-m", timeout_buf,
                    "--cacert", cacert, "-o", out_path,
                    "-w", "%{http_code}", url, (char *) NULL);
        else if (insecure)
            execlp ("curl", "curl", "-fsS", "-m", timeout_buf,
                    "-k", "-o", out_path, "-w", "%{http_code}", url,
                    (char *) NULL);
        else
            execlp ("curl", "curl", "-fsS", "-m", timeout_buf,
                    "-o", out_path, "-w", "%{http_code}", url,
                    (char *) NULL);
        _exit (127);
    }
    close (pipefd[1]);
    bp_buf out = {0};
    int read_rc = bp_read_all_fd (pipefd[0], &out);
    close (pipefd[0]);

    int status = 0;
    while (waitpid (pid, &status, 0) < 0) {
        if (errno != EINTR) {
            bpkg_child_guard_parent_end (&guard);
            bp_buf_free (&out);
            unlink (out_path);
            return -1;
        }
    }
    bpkg_child_guard_parent_end (&guard);
    if (read_rc < 0) {
        bp_buf_free (&out);
        unlink (out_path);
        return -1;
    }
    long code = 0;
    if (out.len > 0) {
        char tmp[32];
        size_t n = out.len < sizeof tmp - 1 ? out.len : sizeof tmp - 1;
        memcpy (tmp, out.data, n);
        tmp[n] = 0;
        code = strtol (tmp, NULL, 10);
    }
    bp_buf_free (&out);
    if (http_code_out)
        *http_code_out = code;
    if (!WIFEXITED (status) || WEXITSTATUS (status) != 0 ||
        (code >= 400 && code <= 999)) {
        unlink (out_path);
        return -1;
    }
    struct stat st;
    if (stat (out_path, &st) < 0 || !S_ISREG (st.st_mode) ||
        st.st_size <= 0) {
        unlink (out_path);
        return -1;
    }
    return 0;
}

typedef struct {
    char name[BPKG_NAME_MAX];
    char pkg[BPKG_PATH_MAX];
    int pkg_is_url;
    char sig[BPKG_PATH_MAX];
    char sha[65];
    char arch[BPKG_NAME_MAX];
    char delta[BPKG_PATH_MAX];
    char delta_sig[BPKG_PATH_MAX];
    char delta_from[65];
    char delta_to[65];
} bp_fetch_entry;

static int
bp_fetch_line_name (const char *line, char *name, size_t namesz)
{
    char copy[2048];
    if (!line || strlen (line) >= sizeof copy) return -1;
    snprintf (copy, sizeof copy, "%s", line);
    char *save = NULL;
    for (char *tok = strtok_r (copy, " \t\r\n", &save);
         tok;
         tok = strtok_r (NULL, " \t\r\n", &save)) {
        if (!strncmp (tok, "name=", 5)) {
            if (!bp_safe_name (tok + 5) ||
                snprintf (name, namesz, "%s", tok + 5) >= (int) namesz)
                return -1;
            return 0;
        }
    }
    return -1;
}

static int
bp_fetch_entry_from_line (const char *line, const char *selected_arch,
                          bp_fetch_entry *e)
{
    memset (e, 0, sizeof *e);
    if (!bp_index_line_is_loadable_record (line))
        return 0;
    if (bp_fetch_line_name (line, e->name, sizeof e->name) < 0)
        return -1;
    char deps[1024], version[BPKG_NAME_MAX], builtin[BPKG_NAME_MAX];
    char abi[BPKG_NAME_MAX];
    int rc = bp_index_pkg_candidate (
        line, e->name, e->pkg, sizeof e->pkg,
        e->sha, sizeof e->sha, e->sig, sizeof e->sig,
        deps, sizeof deps, version, sizeof version,
        builtin, sizeof builtin, abi, sizeof abi,
        e->arch, sizeof e->arch, e->delta, sizeof e->delta,
        e->delta_sig, sizeof e->delta_sig,
        e->delta_from, sizeof e->delta_from,
        e->delta_to, sizeof e->delta_to, &e->pkg_is_url);
    if (rc <= 0)
        return rc;
    if (!bp_arch_matches_selected (e->arch, selected_arch))
        return 0;
    if (e->delta[0] && e->delta_to[0] && e->sha[0] &&
        strcasecmp (e->delta_to, e->sha) != 0) {
        builtin_error ("fetch: delta_to does not match sha256 for %s",
                       e->name);
        return -1;
    }
    return 1;
}

static int
bp_fetch_delta_line (const unsigned char *data, size_t len, size_t *off,
                     char *out, size_t outsz)
{
    if (*off >= len || outsz == 0) return -1;
    size_t start = *off;
    while (*off < len && data[*off] != '\n')
        (*off)++;
    if (*off >= len) return -1;
    size_t n = *off - start;
    if (n >= outsz) return -1;
    memcpy (out, data + start, n);
    out[n] = 0;
    (*off)++;
    return 0;
}

static int
bp_delta_header_matches (const char *path, const char *from, const char *to)
{
    bp_buf body = {0};
    if (bp_read_file (path, &body) < 0) {
        bp_buf_free (&body);
        return -1;
    }
    size_t off = strlen (BPKG_DELTA_MAGIC);
    char got_from[65], got_to[65];
    int rc = -1;
    if (body.len >= off &&
        memcmp (body.data, BPKG_DELTA_MAGIC, off) == 0 &&
        bp_fetch_delta_line (body.data, body.len, &off, got_from,
                             sizeof got_from) == 0 &&
        bp_fetch_delta_line (body.data, body.len, &off, got_to,
                             sizeof got_to) == 0 &&
        bp_hex64 (got_from) && bp_hex64 (got_to) &&
        (!from || !*from || strcasecmp (got_from, from) == 0) &&
        (!to || !*to || strcasecmp (got_to, to) == 0))
        rc = 0;
    bp_buf_free (&body);
    return rc;
}

static int
bp_fetch_ref_to_stage (const char *base_url, const char *ref, int is_url,
                       const char *stage_root, const char *cacert,
                       int insecure, int timeout, char *out_path,
                       size_t outsz)
{
    char url[BPKG_PATH_MAX];
    char rel[BPKG_PATH_MAX];
    if (bp_url_join (base_url, ref, url, sizeof url) < 0 ||
        bp_ref_relative_path (ref, is_url, rel, sizeof rel) < 0 ||
        snprintf (out_path, outsz, "%s/%s", stage_root, rel) >=
            (int) outsz)
        return -1;
    long code = 0;
    if (bp_fetch_url (url, out_path, cacert, insecure, timeout, &code) < 0) {
        builtin_error ("fetch: failed %s", url);
        return -1;
    }
    return 0;
}

static int
bp_fetch_index_artifacts (const char *idx, const char *root,
                          const char *base_url, const char *stage_root,
                          const char *selected_arch, const char *cacert,
                          int insecure, int timeout)
{
    bp_buf body = {0};
    if (bp_read_file (idx, &body) < 0) {
        bp_buf_free (&body);
        return -1;
    }
    if (bp_mkdir_p (stage_root) < 0) {
        bp_buf_free (&body);
        return -1;
    }
    size_t off = 0;
    while (off < body.len) {
        size_t end = off;
        while (end < body.len && body.data[end] != '\n') end++;
        if (end > off && end - off < 2048) {
            char line[2048];
            memcpy (line, body.data + off, end - off);
            line[end - off] = 0;
            bp_fetch_entry e;
            int erc = bp_fetch_entry_from_line (line, selected_arch, &e);
            if (erc < 0) {
                bp_buf_free (&body);
                return -1;
            }
            if (erc > 0) {
                int use_delta = 0;
                if (e.delta[0] && e.delta_from[0]) {
                    char old_pkg[BPKG_PATH_MAX], old_sha[65];
                    if (bp_find_in_cache (root, e.name, old_pkg,
                                          sizeof old_pkg) == 0 &&
                        bp_sha256_file_hex (old_pkg, old_sha) == 0 &&
                        strcasecmp (old_sha, e.delta_from) == 0)
                        use_delta = 1;
                }
                char stage_path[BPKG_PATH_MAX];
                if (use_delta) {
                    if (bp_fetch_ref_to_stage (base_url, e.delta, 0,
                                               stage_root, cacert,
                                               insecure, timeout,
                                               stage_path,
                                               sizeof stage_path) < 0 ||
                        bp_delta_header_matches (stage_path, e.delta_from,
                                                 e.delta_to) < 0) {
                        builtin_error ("fetch: delta header mismatch for %s",
                                       e.name);
                        bp_buf_free (&body);
                        return -1;
                    }
                    if (e.delta_sig[0] &&
                        bp_fetch_ref_to_stage (base_url, e.delta_sig, 0,
                                               stage_root, cacert,
                                               insecure, timeout,
                                               stage_path,
                                               sizeof stage_path) < 0) {
                        bp_buf_free (&body);
                        return -1;
                    }
                    if (bp_fetch_ref_to_stage (base_url, e.sig, 0,
                                               stage_root, cacert,
                                               insecure, timeout,
                                               stage_path,
                                               sizeof stage_path) < 0) {
                        bp_buf_free (&body);
                        return -1;
                    }
                } else {
                    if (bp_fetch_ref_to_stage (base_url, e.pkg, e.pkg_is_url,
                                               stage_root, cacert,
                                               insecure, timeout,
                                               stage_path,
                                               sizeof stage_path) < 0) {
                        bp_buf_free (&body);
                        return -1;
                    }
                    char got[65];
                    if (bp_sha256_file_hex (stage_path, got) < 0 ||
                        strcasecmp (got, e.sha) != 0) {
                        builtin_error ("fetch: package sha256 mismatch for %s",
                                       e.pkg);
                        bp_buf_free (&body);
                        return -1;
                    }
                    if (bp_fetch_ref_to_stage (base_url, e.sig, 0,
                                               stage_root, cacert,
                                               insecure, timeout,
                                               stage_path,
                                               sizeof stage_path) < 0) {
                        bp_buf_free (&body);
                        return -1;
                    }
                }
            }
        }
        off = end + 1;
    }
    bp_buf_free (&body);
    return 0;
}

static int
bp_fetch_remote_segment (const char *source_url, const char *segment,
                         const char *repo_dir, const char *root,
                         const char *selected_arch, const char *cacert,
                         int insecure, int timeout)
{
    char seg_url[BPKG_PATH_MAX];
    char dest_dir[BPKG_PATH_MAX];
    char stage_dir[BPKG_PATH_MAX];
    const char *segname = (segment && *segment) ? segment : "flat";
    if (segment && *segment) {
        if (bp_url_join (source_url, segment, seg_url, sizeof seg_url) < 0 ||
            snprintf (dest_dir, sizeof dest_dir, "%s/%s", repo_dir,
                      segment) >= (int) sizeof dest_dir)
            return -1;
    } else {
        if (snprintf (seg_url, sizeof seg_url, "%s", source_url) >=
                (int) sizeof seg_url ||
            snprintf (dest_dir, sizeof dest_dir, "%s", repo_dir) >=
                (int) sizeof dest_dir)
            return -1;
    }
    if (snprintf (stage_dir, sizeof stage_dir, "%s/.staging.%d/%s",
                  repo_dir, (int) getpid (), segname) >=
        (int) sizeof stage_dir)
        return -1;
    bp_remove_tree (stage_dir);
    if (bp_mkdir_p (stage_dir) < 0)
        return -1;

    char idx_url[BPKG_PATH_MAX], sig_url[BPKG_PATH_MAX];
    char stage_idx[BPKG_PATH_MAX], stage_sig[BPKG_PATH_MAX];
    if (bp_url_join (seg_url, "INDEX", idx_url, sizeof idx_url) < 0 ||
        bp_url_join (seg_url, "INDEX.sig", sig_url, sizeof sig_url) < 0 ||
        snprintf (stage_idx, sizeof stage_idx, "%s/INDEX", stage_dir) >=
            (int) sizeof stage_idx ||
        snprintf (stage_sig, sizeof stage_sig, "%s/INDEX.sig", stage_dir) >=
            (int) sizeof stage_sig) {
        bp_remove_tree (stage_dir);
        return -1;
    }
    long code = 0;
    if (bp_fetch_url (idx_url, stage_idx, cacert, insecure, timeout, &code) < 0) {
        bp_remove_tree (stage_dir);
        return 0;
    }
    if (bp_fetch_url (sig_url, stage_sig, cacert, insecure, timeout, &code) < 0) {
        builtin_error ("fetch: missing INDEX.sig for %s", idx_url);
        bp_remove_tree (stage_dir);
        return -1;
    }
    if (bp_verify_signature (stage_idx) < 0) {
        builtin_error ("signature verification failed for %s", stage_idx);
        bp_remove_tree (stage_dir);
        return -1;
    }

    char stage_artifacts[BPKG_PATH_MAX];
    if (snprintf (stage_artifacts, sizeof stage_artifacts, "%s/artifacts",
                  stage_dir) >= (int) sizeof stage_artifacts ||
        bp_fetch_index_artifacts (stage_idx, root, seg_url, stage_artifacts,
                                  selected_arch, cacert, insecure, timeout) < 0) {
        bp_remove_tree (stage_dir);
        return -1;
    }
    char dest_sig[BPKG_PATH_MAX];
    if (snprintf (dest_sig, sizeof dest_sig, "%s/INDEX.sig", dest_dir) >=
            (int) sizeof dest_sig ||
        bp_update_copy_index (stage_idx, seg_url, dest_dir) < 0 ||
        bp_copy_file_atomic_mode (stage_sig, dest_sig, 0644) < 0 ||
        bp_copy_tree_into (stage_artifacts, dest_dir) < 0) {
        bp_remove_tree (stage_dir);
        return -1;
    }
    bp_remove_tree (stage_dir);
    return 1;
}

static int
bp_fetch_remote_arches (const char *source_url, const char *repo_dir,
                        const char *cacert, int insecure, int timeout)
{
    char url[BPKG_PATH_MAX], tmp[BPKG_PATH_MAX], dest[BPKG_PATH_MAX];
    if (bp_url_join (source_url, "INDEX.arches", url, sizeof url) < 0 ||
        snprintf (tmp, sizeof tmp, "%s/.INDEX.arches.tmp.%d", repo_dir,
                  (int) getpid ()) >= (int) sizeof tmp ||
        snprintf (dest, sizeof dest, "%s/INDEX.arches", repo_dir) >=
            (int) sizeof dest)
        return -1;
    long code = 0;
    if (bp_fetch_url (url, tmp, cacert, insecure, timeout, &code) == 0) {
        if (bp_copy_file_atomic_mode (tmp, dest, 0644) < 0) {
            unlink (tmp);
            return -1;
        }
        unlink (tmp);
    }
    return 0;
}

static int
bp_fetch_remote_source (const char *url, const char *repo_dir,
                        const char *root, const char *selected_arch,
                        const char *cacert, int insecure, int timeout)
{
    if (bp_mkdir_p (repo_dir) < 0)
        return -1;
    (void) bp_fetch_remote_arches (url, repo_dir, cacert, insecure, timeout);
    const char *segments[4] = { selected_arch, "noarch", "any", "" };
    int fetched = 0;
    for (int i = 0; i < 4; i++) {
        if (!segments[i]) continue;
        if (i > 0 && segments[i][0] &&
            strcmp (segments[i], selected_arch) == 0)
            continue;
        int rc = bp_fetch_remote_segment (url, segments[i], repo_dir, root,
                                          selected_arch, cacert, insecure,
                                          timeout);
        if (rc < 0)
            return -1;
        if (rc > 0)
            fetched = 1;
    }
    if (!fetched) {
        builtin_error ("fetch: no signed INDEX found at %s", url);
        return -1;
    }
    return 0;
}

static int
bp_fetch_local_source (const char *url, const char *local,
                       const char *repo_dir, const char *selected_arch)
{
    int failed = 0;
    int fetched = 0;
    char src_idx[BPKG_PATH_MAX];
    char src_pkgdir[BPKG_PATH_MAX];
    src_idx[0] = 0;
    src_pkgdir[0] = 0;
    if (bp_source_index_path (local, src_idx, sizeof src_idx, src_pkgdir,
                              sizeof src_pkgdir) == 0) {
        struct stat idx_st;
        if (stat (src_idx, &idx_st) == 0 && S_ISREG (idx_st.st_mode)) {
            if (bp_update_copy_index (src_idx, src_pkgdir, repo_dir) < 0)
                failed = 1;
            else
                fetched = 1;
        }
    }
    const char *arch_segments[3] = { selected_arch, "noarch", "any" };
    for (int ai = 0; ai < 3; ai++) {
        if (!arch_segments[ai][0]) continue;
        if (ai > 0 && strcmp (arch_segments[ai], selected_arch) == 0)
            continue;
        char a_src_idx[BPKG_PATH_MAX];
        char a_src_pkgdir[BPKG_PATH_MAX];
        if (bp_source_arch_index_path (local, arch_segments[ai], a_src_idx,
                                       sizeof a_src_idx, a_src_pkgdir,
                                       sizeof a_src_pkgdir) == 0) {
            char a_dest[BPKG_PATH_MAX];
            snprintf (a_dest, sizeof a_dest, "%s/%s", repo_dir,
                      arch_segments[ai]);
            if (bp_update_copy_index (a_src_idx, a_src_pkgdir, a_dest) < 0)
                failed = 1;
            else
                fetched = 1;
        }
    }
    if (!fetched || failed) {
        builtin_error ("fetch: local source failed: %s", url);
        return -1;
    }
    return 0;
}

typedef struct {
    char pkg[BPKG_PATH_MAX];
    char url[BPKG_PATH_MAX];
    char repo[BPKG_NAME_MAX];
    char sig[BPKG_PATH_MAX];
    char sha[65];
    char deps[1024];
    char version[BPKG_NAME_MAX];
    char builtin[BPKG_NAME_MAX];
    char abi[BPKG_NAME_MAX];
    char arch[BPKG_NAME_MAX];
    char delta[BPKG_PATH_MAX];
    char delta_sig[BPKG_PATH_MAX];
    char delta_from[65];
    char delta_to[65];
} bp_index_hit;

static void
bp_index_hit_init (bp_index_hit *h)
{
    memset (h, 0, sizeof *h);
}

static int
bp_resolve_index_ref (const char *ref, int is_url, const char *pkgdir,
                      int origin_remote, const char *what, const char *name,
                      char *out, size_t outsz)
{
    if (!ref || !*ref) {
        if (out && outsz) out[0] = 0;
        return 0;
    }
    if (origin_remote && bp_remote_url (ref)) {
        char rel[BPKG_PATH_MAX];
        if (bp_ref_relative_path (ref, 1, rel, sizeof rel) < 0 ||
            snprintf (out, outsz, "%s/%s", pkgdir, rel) >= (int) outsz) {
            builtin_error ("bad remote %s url in loadable index entry "
                           "for %s: %s", what, name, ref);
            return -1;
        }
        return 0;
    }
    if (is_url) {
        int url_rc = bp_source_local_path (ref, out, outsz);
        if (url_rc < 0) {
            builtin_error ("local %s url too long in loadable index entry "
                           "for %s", what, name);
            return -1;
        }
        if (url_rc == 0) {
            builtin_error ("non-local %s url in loadable index entry for "
                           "%s: %s", what, name, ref);
            return -1;
        }
        return 0;
    }
    if (ref[0] == '/') {
        if (snprintf (out, outsz, "%s", ref) >= (int) outsz)
            return -1;
        return 0;
    }
    if (bp_safe_path (ref)) {
        if (snprintf (out, outsz, "%s/%s", pkgdir, ref) >= (int) outsz)
            return -1;
        return 0;
    }
    builtin_error ("unsafe %s path in loadable index entry for %s", what,
                   name);
    return -1;
}

static int
bp_repo_origin_dir (const char *repo_dir, char *pkgdir, size_t pkgdirsz)
{
    if (snprintf (pkgdir, pkgdirsz, "%s", repo_dir) >= (int) pkgdirsz)
        return -1;
    char origin[BPKG_PATH_MAX];
    if (snprintf (origin, sizeof origin, "%s/ORIGIN", repo_dir) >=
        (int) sizeof origin)
        return -1;
    bp_buf origin_body = {0};
    if (bp_read_file (origin, &origin_body) == 0) {
        char origin_line[BPKG_PATH_MAX];
        size_t olen = origin_body.len;
        if (olen >= sizeof origin_line)
            olen = sizeof origin_line - 1;
        memcpy (origin_line, origin_body.data, olen);
        origin_line[olen] = 0;
        char *nl = strchr (origin_line, '\n');
        if (nl) *nl = 0;
        char *ostrip = bp_strip (origin_line);
        if (*ostrip && !bp_remote_url (ostrip) &&
            snprintf (pkgdir, pkgdirsz, "%s", ostrip) >= (int) pkgdirsz) {
            bp_buf_free (&origin_body);
            return -1;
        }
    }
    bp_buf_free (&origin_body);
    return 0;
}

static int
bp_scan_index_for_hit (const char *idx, const char *pkgdir,
                       const char *repo, const char *repo_url,
                       const char *name, const char *selected_arch,
                       bp_index_hit *best)
{
    bp_buf idx_body = {0};
    if (bp_read_file (idx, &idx_body) < 0) {
        bp_buf_free (&idx_body);
        return 0;
    }
    size_t io = 0;
    while (io < idx_body.len) {
        size_t ie = io;
        while (ie < idx_body.len && idx_body.data[ie] != '\n') ie++;
        if (ie > io) {
            char iline[2048], cand[BPKG_PATH_MAX];
            char cand_sha[65] = {0};
            char cand_sig[BPKG_PATH_MAX] = {0};
            char cand_deps[1024] = {0};
            char cand_version[BPKG_NAME_MAX] = {0};
            char cand_builtin[BPKG_NAME_MAX] = {0};
            char cand_abi[BPKG_NAME_MAX] = {0};
            char cand_arch[BPKG_NAME_MAX] = {0};
            char cand_delta[BPKG_PATH_MAX] = {0};
            char cand_delta_sig[BPKG_PATH_MAX] = {0};
            char cand_delta_from[65] = {0};
            char cand_delta_to[65] = {0};
            int cand_is_url = 0;
            size_t il = ie - io;
            if (il < sizeof iline) {
                memcpy (iline, idx_body.data + io, il);
                iline[il] = 0;
                int crc = bp_index_pkg_candidate (
                    iline, name, cand, sizeof cand,
                    cand_sha, sizeof cand_sha,
                    cand_sig, sizeof cand_sig,
                    cand_deps, sizeof cand_deps,
                    cand_version, sizeof cand_version,
                    cand_builtin, sizeof cand_builtin,
                    cand_abi, sizeof cand_abi,
                    cand_arch, sizeof cand_arch,
                    cand_delta, sizeof cand_delta,
                    cand_delta_sig, sizeof cand_delta_sig,
                    cand_delta_from, sizeof cand_delta_from,
                    cand_delta_to, sizeof cand_delta_to,
                    &cand_is_url);
                if (crc < 0) {
                    bp_buf_free (&idx_body);
                    return -1;
                }
                if (crc > 0 &&
                    bp_arch_matches_selected (cand_arch, selected_arch)) {
                    char full[BPKG_PATH_MAX];
                    char full_sig[BPKG_PATH_MAX] = {0};
                    char full_delta[BPKG_PATH_MAX] = {0};
                    char full_delta_sig[BPKG_PATH_MAX] = {0};
                    int origin_remote = bp_remote_url (repo_url);
                    if (bp_resolve_index_ref (cand, cand_is_url, pkgdir,
                                              origin_remote,
                                              "package", name, full,
                                              sizeof full) < 0 ||
                        bp_resolve_index_ref (cand_sig, 0, pkgdir,
                                              origin_remote,
                                              "signature", name, full_sig,
                                              sizeof full_sig) < 0 ||
                        bp_resolve_index_ref (cand_delta, 0, pkgdir,
                                              origin_remote,
                                              "delta", name, full_delta,
                                              sizeof full_delta) < 0 ||
                        bp_resolve_index_ref (cand_delta_sig, 0, pkgdir,
                                              origin_remote,
                                              "delta signature", name,
                                              full_delta_sig,
                                              sizeof full_delta_sig) < 0) {
                        bp_buf_free (&idx_body);
                        return -1;
                    }
                    const char *fname = strrchr (full, '/');
                    fname = fname ? fname + 1 : full;
                    if (!best->pkg[0] ||
                        strcmp (fname, strrchr (best->pkg, '/') ?
                                strrchr (best->pkg, '/') + 1 :
                                best->pkg) > 0) {
                        snprintf (best->pkg, sizeof best->pkg, "%s", full);
                        snprintf (best->url, sizeof best->url, "%s",
                                  repo_url);
                        snprintf (best->repo, sizeof best->repo, "%s",
                                  repo);
                        snprintf (best->sig, sizeof best->sig, "%s",
                                  full_sig);
                        snprintf (best->sha, sizeof best->sha, "%s",
                                  cand_sha);
                        snprintf (best->deps, sizeof best->deps, "%s",
                                  cand_deps);
                        snprintf (best->version, sizeof best->version, "%s",
                                  cand_version);
                        snprintf (best->builtin, sizeof best->builtin, "%s",
                                  cand_builtin);
                        snprintf (best->abi, sizeof best->abi, "%s",
                                  cand_abi);
                        snprintf (best->arch, sizeof best->arch, "%s",
                                  cand_arch);
                        snprintf (best->delta, sizeof best->delta, "%s",
                                  full_delta);
                        snprintf (best->delta_sig, sizeof best->delta_sig,
                                  "%s", full_delta_sig);
                        snprintf (best->delta_from, sizeof best->delta_from,
                                  "%s", cand_delta_from);
                        snprintf (best->delta_to, sizeof best->delta_to,
                                  "%s", cand_delta_to);
                    }
                }
            }
        }
        io = ie + 1;
    }
    bp_buf_free (&idx_body);
    return best->pkg[0] ? 1 : 0;
}

static int
bp_find_repo_hit (const char *root, const char *sources,
                  const char *repo_filter, const char *name,
                  const char *arch_override, bp_index_hit *hit)
{
    bp_index_hit_init (hit);
    char selected_arch[BPKG_NAME_MAX];
    if (bp_select_arch (arch_override, selected_arch, sizeof selected_arch) < 0)
        return -1;

    char src_path[BPKG_PATH_MAX];
    if (sources) {
        snprintf (src_path, sizeof src_path, "%s", sources);
    } else {
        snprintf (src_path, sizeof src_path, "%s%s",
                  root[0] && strcmp (root, "/") ? root : "",
                  BPKG_SOURCES_LIST);
    }
    bp_buf sources_body = {0};
    if (bp_read_file (src_path, &sources_body) < 0) {
        builtin_error ("no sources configured at %s", src_path);
        bp_buf_free (&sources_body);
        return -1;
    }

    size_t off = 0;
    while (off < sources_body.len) {
        size_t end = off;
        while (end < sources_body.len && sources_body.data[end] != '\n') end++;
        size_t ll = end - off;
        if (ll > 0 && ll < 2048 && sources_body.data[off] != '#') {
            char line[2048];
            memcpy (line, sources_body.data + off, ll);
            line[ll] = 0;
            int line_remote = 0;
            int line_insecure = 0;
            char *url = bp_source_parse_marker (line, &line_remote,
                                                &line_insecure);
            (void) line_remote;
            (void) line_insecure;
            if (*url) {
                char base[BPKG_NAME_MAX];
                if (bp_repo_name_from_source (url, base, sizeof base) < 0)
                    snprintf (base, sizeof base, "default");
                if (repo_filter && strcmp (repo_filter, base) != 0)
                    goto next_source;

                char repo_dir[BPKG_PATH_MAX];
                snprintf (repo_dir, sizeof repo_dir, "%s%s/%s",
                          root[0] && strcmp (root, "/") ? root : "",
                          BPKG_REPOS_DIR, base);

                const char *segments[4] = {
                    selected_arch, "noarch", "any", ""
                };
                for (int si = 0; si < 4; si++) {
                    char idx[BPKG_PATH_MAX];
                    char idir[BPKG_PATH_MAX];
                    if (segments[si][0]) {
                        snprintf (idir, sizeof idir, "%s/%s", repo_dir,
                                  segments[si]);
                        snprintf (idx, sizeof idx, "%s/INDEX", idir);
                    } else {
                        snprintf (idir, sizeof idir, "%s", repo_dir);
                        snprintf (idx, sizeof idx, "%s/INDEX", repo_dir);
                    }
                    char pkgdir[BPKG_PATH_MAX];
                    if (bp_repo_origin_dir (idir, pkgdir, sizeof pkgdir) < 0)
                        continue;
                    int rc = bp_scan_index_for_hit (idx, pkgdir, base, url,
                                                    name, selected_arch, hit);
                    if (rc < 0) {
                        bp_buf_free (&sources_body);
                        return -1;
                    }
                    if (hit->pkg[0])
                        break;
                }
            }
        }
next_source:
        off = end + 1;
    }
    bp_buf_free (&sources_body);
    return hit->pkg[0] ? 1 : 0;
}

static void bp_remove_state_dir (const char *dir);

static int
bp_index_line_is_payload_record (const char *line, const char *name,
                                 const char *selected_arch)
{
    if (!line || !name || !*name) return 0;
    while (*line && isspace ((unsigned char) *line)) line++;
    if (!*line || *line == '#') return 0;

    char copy[2048];
    size_t llen = strlen (line);
    if (llen >= sizeof copy) return 0;
    memcpy (copy, line, llen + 1);

    char iname[BPKG_NAME_MAX] = {0};
    char arch[BPKG_NAME_MAX] = {0};
    char type[16] = "payload";
    int first = 1;
    char *save = NULL;
    for (char *tok = strtok_r (copy, " \t\r\n", &save);
         tok;
         tok = strtok_r (NULL, " \t\r\n", &save)) {
        if (first) {
            if (strcmp (tok, "blpkg-v1") != 0)
                return 0;
            first = 0;
            continue;
        }
        char *eq = strchr (tok, '=');
        if (!eq) continue;
        *eq = 0;
        const char *key = tok;
        const char *val = eq + 1;
        if (!strcmp (key, "name"))
            snprintf (iname, sizeof iname, "%s", val);
        else if (!strcmp (key, "arch"))
            snprintf (arch, sizeof arch, "%s", val);
        else if (!strcmp (key, "type")) {
            if (strcmp (val, "loadable") && strcmp (val, "payload")) {
                builtin_error ("payload index entry for %s has bad type=%s",
                               name, val);
                return -1;
            }
            snprintf (type, sizeof type, "%s", val);
        }
    }
    if (strcmp (type, "payload") != 0)
        return 0;
    if (!iname[0] || strcmp (iname, name) != 0)
        return 0;
    if (!arch[0]) {
        builtin_error ("payload index entry for %s requires arch=ARCH",
                       name);
        return -1;
    }
    return bp_arch_matches_selected (arch, selected_arch) ? 1 : 0;
}

static int
bp_scan_payload_index_for_repo (const char *idx, const char *name,
                                const char *selected_arch)
{
    bp_buf idx_body = {0};
    if (bp_read_file (idx, &idx_body) < 0) {
        bp_buf_free (&idx_body);
        return 0;
    }
    size_t off = 0;
    while (off < idx_body.len) {
        size_t end = off;
        while (end < idx_body.len && idx_body.data[end] != '\n') end++;
        if (end > off) {
            char line[2048];
            size_t ll = end - off;
            if (ll < sizeof line) {
                memcpy (line, idx_body.data + off, ll);
                line[ll] = 0;
                int rc = bp_index_line_is_payload_record (line, name,
                                                          selected_arch);
                if (rc != 0) {
                    bp_buf_free (&idx_body);
                    return rc;
                }
            }
        }
        off = end + 1;
    }
    bp_buf_free (&idx_body);
    return 0;
}

static int
bp_find_payload_repo_dir (const char *root, const char *sources,
                          const char *repo_filter, const char *name,
                          const char *arch_override,
                          char *repo_dir_out, size_t repo_dir_outsz)
{
    char selected_arch[BPKG_NAME_MAX];
    if (bp_select_arch (arch_override, selected_arch, sizeof selected_arch) < 0)
        return -1;

    char src_path[BPKG_PATH_MAX];
    if (sources) {
        snprintf (src_path, sizeof src_path, "%s", sources);
    } else {
        snprintf (src_path, sizeof src_path, "%s%s",
                  root[0] && strcmp (root, "/") ? root : "",
                  BPKG_SOURCES_LIST);
    }
    bp_buf sources_body = {0};
    if (bp_read_file (src_path, &sources_body) < 0) {
        bp_buf_free (&sources_body);
        return 0;
    }

    size_t off = 0;
    while (off < sources_body.len) {
        size_t end = off;
        while (end < sources_body.len && sources_body.data[end] != '\n') end++;
        size_t ll = end - off;
        if (ll > 0 && ll < 2048 && sources_body.data[off] != '#') {
            char line[2048];
            memcpy (line, sources_body.data + off, ll);
            line[ll] = 0;
            int line_remote = 0;
            int line_insecure = 0;
            char *url = bp_source_parse_marker (line, &line_remote,
                                                &line_insecure);
            (void) line_remote;
            (void) line_insecure;
            if (*url) {
                char base[BPKG_NAME_MAX];
                if (bp_repo_name_from_source (url, base, sizeof base) < 0)
                    snprintf (base, sizeof base, "default");
                if (repo_filter && strcmp (repo_filter, base) != 0)
                    goto next_source;

                char repo_dir[BPKG_PATH_MAX];
                snprintf (repo_dir, sizeof repo_dir, "%s%s/%s",
                          root[0] && strcmp (root, "/") ? root : "",
                          BPKG_REPOS_DIR, base);

                const char *segments[4] = {
                    selected_arch, "noarch", "any", ""
                };
                for (int si = 0; si < 4; si++) {
                    char idx[BPKG_PATH_MAX];
                    char idir[BPKG_PATH_MAX];
                    if (segments[si][0]) {
                        snprintf (idir, sizeof idir, "%s/%s", repo_dir,
                                  segments[si]);
                        snprintf (idx, sizeof idx, "%s/INDEX", idir);
                    } else {
                        snprintf (idir, sizeof idir, "%s", repo_dir);
                        snprintf (idx, sizeof idx, "%s/INDEX", repo_dir);
                    }
                    int rc = bp_scan_payload_index_for_repo (idx, name,
                                                            selected_arch);
                    if (rc < 0) {
                        bp_buf_free (&sources_body);
                        return -1;
                    }
                    if (rc > 0) {
                        if (snprintf (repo_dir_out, repo_dir_outsz, "%s",
                                      idir) >= (int) repo_dir_outsz) {
                            bp_buf_free (&sources_body);
                            return -1;
                        }
                        bp_buf_free (&sources_body);
                        return 1;
                    }
                }
            }
        }
next_source:
        off = end + 1;
    }
    bp_buf_free (&sources_body);
    return 0;
}

static int
bp_is_executable_file (const char *path)
{
    return path && *path && access (path, X_OK) == 0;
}

static const char *
bp_get_exported_env (const char *key)
{
    size_t klen = strlen (key);
    maybe_make_export_env ();
    if (export_env) {
        for (size_t i = 0; export_env[i]; i++) {
            if (!strncmp (export_env[i], key, klen) &&
                export_env[i][klen] == '=')
                return export_env[i] + klen + 1;
        }
    }
    return getenv (key);
}

static int
bp_find_executable_in_path (const char *name, char *out, size_t outsz)
{
    const char *path = bp_get_exported_env ("PATH");
    if (!path || !*path)
        path = "/bin:/usr/bin:/bash-os";
    char copy[BPKG_PATH_MAX * 2];
    if (strlen (path) >= sizeof copy)
        return 0;
    snprintf (copy, sizeof copy, "%s", path);
    char *save = NULL;
    for (char *dir = strtok_r (copy, ":", &save);
         dir;
         dir = strtok_r (NULL, ":", &save)) {
        if (!*dir) dir = ".";
        char cand[BPKG_PATH_MAX];
        if (snprintf (cand, sizeof cand, "%s/%s", dir, name) >=
            (int) sizeof cand)
            continue;
        if (bp_is_executable_file (cand)) {
            if (snprintf (out, outsz, "%s", cand) >= (int) outsz)
                return -1;
            return 1;
        }
    }
    return 0;
}

static int
bp_locate_blpkg (char *out, size_t outsz)
{
    if (bp_is_executable_file ("/bash-os/bl-pkg.sh")) {
        if (snprintf (out, outsz, "%s", "/bash-os/bl-pkg.sh") >=
            (int) outsz)
            return -1;
        return 0;
    }
    const char *env_path = bp_get_exported_env ("BASHPKG_BLPKG_PATH");
    if (env_path && *env_path) {
        if (!bp_is_executable_file (env_path)) {
            builtin_error ("BASHPKG_BLPKG_PATH is not executable: %s",
                           env_path);
            return -1;
        }
        if (snprintf (out, outsz, "%s", env_path) >= (int) outsz)
            return -1;
        return 0;
    }
    int prc = bp_find_executable_in_path ("bl-pkg.sh", out, outsz);
    if (prc < 0)
        return -1;
    if (prc > 0)
        return 0;
    prc = bp_find_executable_in_path ("bl-pkg", out, outsz);
    if (prc < 0)
        return -1;
    if (prc > 0)
        return 0;
    builtin_error ("bl-pkg.sh not found (expected /bash-os/bl-pkg.sh, "
                   "BASHPKG_BLPKG_PATH, or PATH)");
    return -1;
}

static char **
bp_blpkg_child_env (char *internal_buf)
{
    char **src = export_env;
    if (!src) {
        extern char **environ;
        src = environ;
    }
    size_t in_n = 0;
    if (src) while (src[in_n]) in_n++;

    char **envp = calloc (in_n + 2, sizeof (char *));
    if (!envp)
        return NULL;
    size_t out_n = 0;
    for (size_t i = 0; src && i < in_n; i++) {
        if (!strncmp (src[i], "BASHPKG_INTERNAL=", 17))
            continue;
        envp[out_n++] = src[i];
    }
    envp[out_n++] = internal_buf;
    envp[out_n] = NULL;
    return envp;
}

static int
bp_run_blpkg_capture (const char *blpkg, char *const argv[], bp_buf *out)
{
    maybe_make_export_env ();

    int pipefd[2];
    if (pipe (pipefd) < 0) {
        builtin_error ("pipe: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }

    struct bpkg_child_guard guard;
    if (bpkg_child_guard_begin (&guard) < 0) {
        close (pipefd[0]);
        close (pipefd[1]);
        builtin_error ("SIGCHLD guard: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    pid_t pid = fork ();
    if (pid < 0) {
        bpkg_child_guard_parent_end (&guard);
        close (pipefd[0]);
        close (pipefd[1]);
        builtin_error ("fork: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (pid == 0) {
        bpkg_child_guard_child_end (&guard);
        close (pipefd[0]);
        if (dup2 (pipefd[1], STDOUT_FILENO) < 0)
            _exit (126);
        close (pipefd[1]);
        char internal_buf[] = "BASHPKG_INTERNAL=1";
        char **envp = bp_blpkg_child_env (internal_buf);
        if (envp) {
            execve (blpkg, argv, envp);
        } else {
            char *small_envp[] = { internal_buf, NULL };
            execve (blpkg, argv, small_envp);
        }
        _exit (127);
    }
    close (pipefd[1]);
    int read_rc = bp_read_all_fd (pipefd[0], out);
    close (pipefd[0]);

    int status = 0;
    while (waitpid (pid, &status, 0) < 0) {
        if (errno != EINTR) {
            bpkg_child_guard_parent_end (&guard);
            return EXECUTION_FAILURE;
        }
    }
    bpkg_child_guard_parent_end (&guard);
    if (read_rc < 0) {
        builtin_error ("read bl-pkg output: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (WIFEXITED (status))
        return WEXITSTATUS (status) == 0 ? EXECUTION_SUCCESS :
               EXECUTION_FAILURE;
    builtin_error ("bl-pkg terminated by signal");
    return EXECUTION_FAILURE;
}

static int
bp_is_txn_id (const char *s)
{
    if (!s || strncmp (s, "txn-", 4) != 0)
        return 0;
    for (const char *p = s + 4; *p; p++) {
        if (!isalnum ((unsigned char) *p) &&
            *p != '.' && *p != '_' && *p != '+' && *p != '-')
            return 0;
    }
    return s[4] != 0;
}

static int
bp_extract_txn_line (const bp_buf *out, const char *prefix,
                     char *txn, size_t txnsz)
{
    size_t plen = strlen (prefix);
    size_t off = 0;
    while (off < out->len) {
        size_t end = off;
        while (end < out->len && out->data[end] != '\n') end++;
        size_t ll = end - off;
        if (ll >= plen && !memcmp (out->data + off, prefix, plen)) {
            size_t tlen = ll - plen;
            if (tlen >= txnsz)
                return -1;
            char tmp[BPKG_NAME_MAX];
            if (tlen >= sizeof tmp)
                return -1;
            memcpy (tmp, out->data + off + plen, tlen);
            tmp[tlen] = 0;
            char *stripped = bp_strip (tmp);
            if (!bp_is_txn_id (stripped))
                return -1;
            snprintf (txn, txnsz, "%s", stripped);
            return 0;
        }
        off = end + 1;
    }
    return -1;
}

static int
bp_write_payload_pointer (const char *root, const char *name,
                          const char *txn)
{
    if (!bp_safe_name (name) || !bp_is_txn_id (txn)) {
        builtin_error ("payload pointer: invalid name or transaction id");
        return -1;
    }
    char dir[BPKG_PATH_MAX];
    snprintf (dir, sizeof dir, "%s%s/%s",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_INSTALLED_DIR, name);
    bp_remove_state_dir (dir);
    if (bp_mkdir_p (dir) < 0) {
        builtin_error ("mkdir state dir %s: %s", dir, strerror (errno));
        return -1;
    }

    char manifest[1024];
    int mn = snprintf (manifest, sizeof manifest,
                       "name: %s\n"
                       "type: payload\n"
                       "backend: bl-pkg\n"
                       "txn: %s\n",
                       name, txn);
    if (mn < 0 || mn >= (int) sizeof manifest)
        return -1;
    char pointer[1024];
    int pn = snprintf (pointer, sizeof pointer,
                       "type=payload\n"
                       "backend=bl-pkg\n"
                       "txn=%s\n",
                       txn);
    if (pn < 0 || pn >= (int) sizeof pointer)
        return -1;

    char path[BPKG_PATH_MAX];
    snprintf (path, sizeof path, "%s/MANIFEST", dir);
    if (bp_write_file_atomic (path, manifest, (size_t) mn, 0644) < 0) {
        builtin_error ("write %s: %s", path, strerror (errno));
        return -1;
    }
    snprintf (path, sizeof path, "%s/pointer", dir);
    if (bp_write_file_atomic (path, pointer, (size_t) pn, 0644) < 0) {
        builtin_error ("write %s: %s", path, strerror (errno));
        return -1;
    }
    snprintf (path, sizeof path, "%s/txn", dir);
    if (bp_write_file_atomic (path, txn, strlen (txn), 0644) < 0) {
        builtin_error ("write %s: %s", path, strerror (errno));
        return -1;
    }
    snprintf (path, sizeof path, "%s/backend", dir);
    if (bp_write_file_atomic (path, "bl-pkg\n", 7, 0644) < 0) {
        builtin_error ("write %s: %s", path, strerror (errno));
        return -1;
    }
    return 0;
}

static int
bp_read_payload_pointer (const char *root, const char *name,
                         char *txn, size_t txnsz)
{
    char path[BPKG_PATH_MAX];
    snprintf (path, sizeof path, "%s%s/%s/pointer",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_INSTALLED_DIR, name);
    bp_buf body = {0};
    if (bp_read_file (path, &body) < 0) {
        bp_buf_free (&body);
        return 0;
    }
    int payload = 0;
    int backend = 0;
    int have_txn = 0;
    size_t off = 0;
    while (off < body.len) {
        size_t end = off;
        while (end < body.len && body.data[end] != '\n') end++;
        if (end > off && end - off < 512) {
            char line[512];
            memcpy (line, body.data + off, end - off);
            line[end - off] = 0;
            char *p = bp_strip (line);
            if (!strcmp (p, "type=payload"))
                payload = 1;
            else if (!strcmp (p, "backend=bl-pkg"))
                backend = 1;
            else if (!strncmp (p, "txn=", 4)) {
                if (!bp_is_txn_id (p + 4) ||
                    snprintf (txn, txnsz, "%s", p + 4) >= (int) txnsz) {
                    bp_buf_free (&body);
                    return -1;
                }
                have_txn = 1;
            }
        }
        off = end + 1;
    }
    bp_buf_free (&body);
    return payload && backend && have_txn ? 1 : -1;
}

static int
bp_payload_trust_dir (const char *root, char *out, size_t outsz)
{
    const char *env = bp_get_exported_env ("BASHPKG_BLPKG_TRUST_DIR");
    if (!env || !*env)
        env = bp_get_exported_env ("BASHPKG_TRUST_DIR");
    if (env && *env) {
        if (snprintf (out, outsz, "%s", env) >= (int) outsz)
            return -1;
        return 1;
    }
    char cand[BPKG_PATH_MAX];
    snprintf (cand, sizeof cand, "%s/etc/bash-os/trust",
              root[0] && strcmp (root, "/") ? root : "");
    struct stat st;
    if (stat (cand, &st) == 0 && S_ISDIR (st.st_mode)) {
        if (snprintf (out, outsz, "%s", cand) >= (int) outsz)
            return -1;
        return 1;
    }
    return 0;
}

static int
bp_install_payload_via_blpkg (const char *root, const char *sources,
                              const char *repo_filter,
                              const char *arch_override,
                              const char *target,
                              int allow_unsigned)
{
    char repo_dir[BPKG_PATH_MAX];
    int frc = bp_find_payload_repo_dir (root, sources, repo_filter, target,
                                        arch_override, repo_dir,
                                        sizeof repo_dir);
    if (frc < 0)
        return EXECUTION_FAILURE;
    if (frc == 0) {
        builtin_error ("%s: no payload package in configured sources",
                       target);
        return EXECUTION_FAILURE;
    }

    char blpkg[BPKG_PATH_MAX];
    if (bp_locate_blpkg (blpkg, sizeof blpkg) < 0)
        return EXECUTION_FAILURE;

    char trust_dir[BPKG_PATH_MAX];
    int trust_rc = bp_payload_trust_dir (root, trust_dir, sizeof trust_dir);
    if (trust_rc < 0)
        return EXECUTION_FAILURE;
    if (!allow_unsigned && trust_rc == 0) {
        builtin_error ("payload install requires -A or a configured "
                       "BASHPKG_BLPKG_TRUST_DIR/BASHPKG_TRUST_DIR");
        return EXECUTION_FAILURE;
    }

    char *argv[18];
    int ac = 0;
    argv[ac++] = blpkg;
    argv[ac++] = (char *) "--internal";
    argv[ac++] = (char *) "--root";
    argv[ac++] = (char *) root;
    argv[ac++] = (char *) "--repo";
    argv[ac++] = repo_dir;
    if (arch_override && *arch_override) {
        argv[ac++] = (char *) "--arch";
        argv[ac++] = (char *) arch_override;
    }
    if (allow_unsigned) {
        argv[ac++] = (char *) "--allow-unsigned";
    } else {
        argv[ac++] = (char *) "--trust";
        argv[ac++] = trust_dir;
    }
    argv[ac++] = (char *) "install";
    argv[ac++] = (char *) target;
    argv[ac] = NULL;

    bp_buf out = {0};
    int rc = bp_run_blpkg_capture (blpkg, argv, &out);
    if (rc != EXECUTION_SUCCESS) {
        bp_buf_free (&out);
        return rc;
    }
    char txn[BPKG_NAME_MAX];
    if (bp_extract_txn_line (&out, "installed txn=", txn, sizeof txn) < 0) {
        builtin_error ("bl-pkg install did not report installed txn=");
        bp_buf_free (&out);
        return EXECUTION_FAILURE;
    }
    if (bp_write_payload_pointer (root, target, txn) < 0) {
        bp_buf_free (&out);
        return EXECUTION_FAILURE;
    }
    if (out.len > 0)
        fwrite (out.data, 1, out.len, stdout);
    bp_buf_free (&out);
    return EXECUTION_SUCCESS;
}

static int
bp_blpkg_rollback_txn (const char *root, const char *txn)
{
    char blpkg[BPKG_PATH_MAX];
    if (bp_locate_blpkg (blpkg, sizeof blpkg) < 0)
        return EXECUTION_FAILURE;
    char *argv[8];
    int ac = 0;
    argv[ac++] = blpkg;
    argv[ac++] = (char *) "--internal";
    argv[ac++] = (char *) "--root";
    argv[ac++] = (char *) root;
    argv[ac++] = (char *) "rollback";
    argv[ac++] = (char *) txn;
    argv[ac] = NULL;

    bp_buf out = {0};
    int rc = bp_run_blpkg_capture (blpkg, argv, &out);
    if (rc != EXECUTION_SUCCESS) {
        bp_buf_free (&out);
        return rc;
    }
    char got[BPKG_NAME_MAX];
    if (bp_extract_txn_line (&out, "rolled-back txn=", got, sizeof got) < 0 ||
        strcmp (got, txn) != 0) {
        builtin_error ("bl-pkg rollback did not report rolled-back txn=%s",
                       txn);
        bp_buf_free (&out);
        return EXECUTION_FAILURE;
    }
    if (out.len > 0)
        fwrite (out.data, 1, out.len, stdout);
    bp_buf_free (&out);
    return EXECUTION_SUCCESS;
}

static int
bp_update_payload_pointer_from_blpkg (const char *root, const char *name)
{
    char state[BPKG_PATH_MAX];
    snprintf (state, sizeof state, "%s/var/lib/bl-pkg/installed/%s",
              root[0] && strcmp (root, "/") ? root : "", name);
    bp_buf body = {0};
    if (bp_read_file (state, &body) < 0) {
        char dir[BPKG_PATH_MAX];
        snprintf (dir, sizeof dir, "%s%s/%s",
                  root[0] && strcmp (root, "/") ? root : "",
                  BPKG_INSTALLED_DIR, name);
        bp_remove_state_dir (dir);
        bp_buf_free (&body);
        return 0;
    }
    char txn[BPKG_NAME_MAX] = {0};
    size_t off = 0;
    while (off < body.len) {
        size_t end = off;
        while (end < body.len && body.data[end] != '\n') end++;
        if (end > off && end - off < 512) {
            char line[512];
            memcpy (line, body.data + off, end - off);
            line[end - off] = 0;
            char *p = bp_strip (line);
            if (!strncmp (p, "txn=", 4) && bp_is_txn_id (p + 4)) {
                snprintf (txn, sizeof txn, "%s", p + 4);
                break;
            }
        }
        off = end + 1;
    }
    bp_buf_free (&body);
    if (!txn[0]) {
        builtin_error ("payload rollback: installed record lacks txn: %s",
                       name);
        return -1;
    }
    return bp_write_payload_pointer (root, name, txn);
}

static int
bp_copy_package_to_cache (const char *root, const char *pkgpath,
                          char *out, size_t outsz)
{
    bp_manifest mf;
    if (bp_manifest_from_pkgfile (pkgpath, &mf) < 0)
        return -1;
    if (!mf.version[0] || !bp_safe_name (mf.version)) {
        bp_manifest_free (&mf);
        return -1;
    }
    char cdir[BPKG_PATH_MAX];
    snprintf (cdir, sizeof cdir, "%s%s",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_CACHE_DIR);
    if (bp_mkdir_p (cdir) < 0) {
        bp_manifest_free (&mf);
        return -1;
    }
    char dest[BPKG_PATH_MAX];
    if (snprintf (dest, sizeof dest, "%s/%s-%s.pkg", cdir,
                  mf.name, mf.version) >= (int) sizeof dest) {
        bp_manifest_free (&mf);
        return -1;
    }
    bp_manifest_free (&mf);
    bp_buf body = {0};
    if (bp_read_file (pkgpath, &body) < 0) {
        bp_buf_free (&body);
        return -1;
    }
    int rc = bp_write_file_atomic (dest, body.data, body.len, 0644);
    bp_buf_free (&body);
    if (rc < 0) return -1;
    if (out && outsz > 0)
        snprintf (out, outsz, "%s", dest);
    return 0;
}

static int
bp_copy_signature_to_cache (const char *sigpath, const char *cached_pkg)
{
    if (!sigpath || !*sigpath || !cached_pkg || !*cached_pkg)
        return -1;
    char dest[BPKG_PATH_MAX];
    if (snprintf (dest, sizeof dest, "%s.sig", cached_pkg) >=
        (int) sizeof dest)
        return -1;
    bp_buf body = {0};
    if (bp_read_file (sigpath, &body) < 0) {
        bp_buf_free (&body);
        return -1;
    }
    int rc = bp_write_file_atomic (dest, body.data, body.len, 0644);
    bp_buf_free (&body);
    return rc;
}

static int
bp_buf_append_decimal_line (bp_buf *b, uint64_t v)
{
    char tmp[64];
    int n = snprintf (tmp, sizeof tmp, "%llu\n",
                      (unsigned long long) v);
    if (n < 0 || n >= (int) sizeof tmp) return -1;
    return bp_buf_append (b, tmp, (size_t) n);
}

static int
bp_delta_read_line (const unsigned char *data, size_t len, size_t *off,
                    char *out, size_t outsz)
{
    if (*off >= len || outsz == 0) return -1;
    size_t start = *off;
    while (*off < len && data[*off] != '\n') (*off)++;
    if (*off >= len) return -1;
    size_t n = *off - start;
    if (n >= outsz) return -1;
    memcpy (out, data + start, n);
    out[n] = 0;
    (*off)++;
    return 0;
}

static int
bp_delta_parse_u64 (const char *s, uint64_t *out)
{
    if (!s || !*s) return -1;
    uint64_t v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        uint64_t nv = v * 10 + (uint64_t) (*p - '0');
        if (nv < v) return -1;
        v = nv;
    }
    *out = v;
    return 0;
}

static int
bp_delta_make_file (const char *old_path, const char *new_path,
                    const char *patch_path)
{
    bp_buf oldb = {0}, newb = {0}, patch = {0};
    if (bp_read_file (old_path, &oldb) < 0 ||
        bp_read_file (new_path, &newb) < 0) {
        builtin_error ("delta-make: cannot read input");
        bp_buf_free (&oldb); bp_buf_free (&newb);
        return EXECUTION_FAILURE;
    }
    char from[65], to[65];
    if (bp_sha256_bytes_hex (oldb.data, oldb.len, from) < 0 ||
        bp_sha256_bytes_hex (newb.data, newb.len, to) < 0) {
        bp_buf_free (&oldb); bp_buf_free (&newb);
        return EXECUTION_FAILURE;
    }
    size_t prefix = 0;
    while (prefix < oldb.len && prefix < newb.len &&
           oldb.data[prefix] == newb.data[prefix])
        prefix++;
    size_t suffix = 0;
    while (suffix < oldb.len - prefix && suffix < newb.len - prefix &&
           oldb.data[oldb.len - 1 - suffix] ==
           newb.data[newb.len - 1 - suffix])
        suffix++;
    size_t insert_len = newb.len - prefix - suffix;
    if (bp_buf_append (&patch, BPKG_DELTA_MAGIC,
                       strlen (BPKG_DELTA_MAGIC)) < 0 ||
        bp_buf_append (&patch, from, 64) < 0 ||
        bp_buf_append (&patch, "\n", 1) < 0 ||
        bp_buf_append (&patch, to, 64) < 0 ||
        bp_buf_append (&patch, "\n", 1) < 0 ||
        bp_buf_append_decimal_line (&patch, (uint64_t) oldb.len) < 0 ||
        bp_buf_append_decimal_line (&patch, (uint64_t) newb.len) < 0 ||
        bp_buf_append_decimal_line (&patch, (uint64_t) prefix) < 0 ||
        bp_buf_append_decimal_line (&patch, (uint64_t) suffix) < 0 ||
        bp_buf_append_decimal_line (&patch, (uint64_t) insert_len) < 0 ||
        bp_buf_append (&patch, newb.data + prefix, insert_len) < 0) {
        bp_buf_free (&oldb); bp_buf_free (&newb); bp_buf_free (&patch);
        return EXECUTION_FAILURE;
    }
    int rc = bp_write_file_atomic (patch_path, patch.data, patch.len, 0644);
    bp_buf_free (&oldb); bp_buf_free (&newb); bp_buf_free (&patch);
    if (rc < 0) {
        builtin_error ("delta-make: write %s: %s", patch_path,
                       strerror (errno));
        return EXECUTION_FAILURE;
    }
    printf ("delta\t%s\t%s\n", from, to);
    return EXECUTION_SUCCESS;
}

static int
bp_delta_apply_file (const char *old_path, const char *patch_path,
                     const char *out_path)
{
    bp_buf oldb = {0}, patch = {0}, out = {0};
    if (bp_read_file (old_path, &oldb) < 0 ||
        bp_read_file (patch_path, &patch) < 0) {
        builtin_error ("delta-apply: cannot read input");
        bp_buf_free (&oldb); bp_buf_free (&patch);
        return EXECUTION_FAILURE;
    }
    size_t off = 0;
    if (patch.len < strlen (BPKG_DELTA_MAGIC) ||
        memcmp (patch.data, BPKG_DELTA_MAGIC,
                strlen (BPKG_DELTA_MAGIC)) != 0) {
        builtin_error ("delta-apply: bad delta magic");
        bp_buf_free (&oldb); bp_buf_free (&patch);
        return EXECUTION_FAILURE;
    }
    off = strlen (BPKG_DELTA_MAGIC);
    char from[65], to[65], num[64];
    uint64_t old_len, new_len, prefix, suffix, insert_len;
    if (bp_delta_read_line (patch.data, patch.len, &off, from,
                            sizeof from) < 0 ||
        bp_delta_read_line (patch.data, patch.len, &off, to,
                            sizeof to) < 0 ||
        bp_delta_read_line (patch.data, patch.len, &off, num,
                            sizeof num) < 0 ||
        bp_delta_parse_u64 (num, &old_len) < 0 ||
        bp_delta_read_line (patch.data, patch.len, &off, num,
                            sizeof num) < 0 ||
        bp_delta_parse_u64 (num, &new_len) < 0 ||
        bp_delta_read_line (patch.data, patch.len, &off, num,
                            sizeof num) < 0 ||
        bp_delta_parse_u64 (num, &prefix) < 0 ||
        bp_delta_read_line (patch.data, patch.len, &off, num,
                            sizeof num) < 0 ||
        bp_delta_parse_u64 (num, &suffix) < 0 ||
        bp_delta_read_line (patch.data, patch.len, &off, num,
                            sizeof num) < 0 ||
        bp_delta_parse_u64 (num, &insert_len) < 0 ||
        !bp_hex64 (from) || !bp_hex64 (to)) {
        builtin_error ("delta-apply: malformed delta");
        bp_buf_free (&oldb); bp_buf_free (&patch);
        return EXECUTION_FAILURE;
    }
    char got_from[65];
    if (bp_sha256_bytes_hex (oldb.data, oldb.len, got_from) < 0 ||
        strcasecmp (got_from, from) != 0) {
        builtin_error ("delta-apply: base sha256 mismatch");
        bp_buf_free (&oldb); bp_buf_free (&patch);
        return EXECUTION_FAILURE;
    }
    if (old_len != oldb.len || prefix > oldb.len ||
        suffix > oldb.len - prefix ||
        insert_len > patch.len - off ||
        new_len != prefix + insert_len + suffix) {
        builtin_error ("delta-apply: delta bounds mismatch");
        bp_buf_free (&oldb); bp_buf_free (&patch);
        return EXECUTION_FAILURE;
    }
    if (bp_buf_append (&out, oldb.data, (size_t) prefix) < 0 ||
        bp_buf_append (&out, patch.data + off, (size_t) insert_len) < 0 ||
        bp_buf_append (&out, oldb.data + oldb.len - suffix,
                       (size_t) suffix) < 0) {
        bp_buf_free (&oldb); bp_buf_free (&patch); bp_buf_free (&out);
        return EXECUTION_FAILURE;
    }
    char got_to[65];
    if (bp_sha256_bytes_hex (out.data, out.len, got_to) < 0 ||
        strcasecmp (got_to, to) != 0) {
        builtin_error ("delta-apply: output sha256 mismatch");
        bp_buf_free (&oldb); bp_buf_free (&patch); bp_buf_free (&out);
        return EXECUTION_FAILURE;
    }
    int rc = bp_write_file_atomic (out_path, out.data, out.len, 0644);
    bp_buf_free (&oldb); bp_buf_free (&patch); bp_buf_free (&out);
    if (rc < 0) {
        builtin_error ("delta-apply: write %s: %s", out_path,
                       strerror (errno));
        return EXECUTION_FAILURE;
    }
    printf ("delta-applied\t%s\n", got_to);
    return EXECUTION_SUCCESS;
}

/* ---- Verbs ---------------------------------------------------------- */

/* Reject NULL, empty, or the literal "(null)" string. The last form
   originates from callers that stringified a NULL pointer via printf %s
   on glibc and passed the result through to --root, which would
   otherwise create artifacts under ./(null)/. */
static int
bp_check_root (const char *root)
{
    if (!root || !*root || !strcmp (root, "(null)")) {
        builtin_error ("--root: empty or null value");
        return -1;
    }
    return 0;
}

static int
verb_pack (WORD_LIST *args)
{
    const char *src = NULL, *out = NULL;
    int do_xz = 0;
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "-z")) do_xz = 1;
        else if (!src) src = w;
        else if (!out) out = w;
        else {
            builtin_error ("pack DIR OUT.pkg [-z]");
            return EX_USAGE;
        }
        args = args->next;
    }
    if (!src || !out) {
        builtin_error ("pack DIR OUT.pkg [-z]");
        return EX_USAGE;
    }

    char manifest_path[BPKG_PATH_MAX];
    snprintf (manifest_path, sizeof manifest_path, "%s/MANIFEST", src);
    bp_buf manifest_body = {0};
    bp_manifest manifest;
    bp_manifest_init (&manifest);
    if (bp_read_file (manifest_path, &manifest_body) < 0) {
        builtin_error ("pack: %s/MANIFEST missing", src);
        bp_buf_free (&manifest_body);
        return EXECUTION_FAILURE;
    }
    if (bp_manifest_parse (&manifest, manifest_body.data,
                           manifest_body.len) < 0) {
        builtin_error ("pack: invalid MANIFEST in %s", src);
        bp_buf_free (&manifest_body);
        bp_manifest_free (&manifest);
        return EXECUTION_FAILURE;
    }
    if (bp_manifest_type_is_declared (&manifest) &&
        !bp_manifest_type_is_known (&manifest)) {
        builtin_error ("pack: unsupported package type: %s",
                       bp_manifest_effective_type (&manifest));
        bp_buf_free (&manifest_body);
        bp_manifest_free (&manifest);
        return EXECUTION_FAILURE;
    }
    if (bp_manifest_type_is_declared (&manifest)) {
        char loadable_path[BPKG_PATH_MAX];
        char files_path[BPKG_PATH_MAX];
        char hooks_path[BPKG_PATH_MAX];
        struct stat st_loadable, st_files, st_hooks;
        int has_loadable, has_files, has_hooks;
        snprintf (loadable_path, sizeof loadable_path, "%s/loadable", src);
        snprintf (files_path, sizeof files_path, "%s/files", src);
        snprintf (hooks_path, sizeof hooks_path, "%s/hooks", src);
        has_loadable = stat (loadable_path, &st_loadable) == 0;
        has_files = stat (files_path, &st_files) == 0;
        has_hooks = stat (hooks_path, &st_hooks) == 0;
        if (bp_manifest_effective_is_loadable (&manifest)) {
            if (!has_loadable) {
                builtin_error ("pack: type loadable requires loadable/");
                bp_buf_free (&manifest_body);
                bp_manifest_free (&manifest);
                return EXECUTION_FAILURE;
            }
            if (has_files || has_hooks) {
                builtin_error ("pack: type loadable may contain only "
                               "MANIFEST and loadable/");
                bp_buf_free (&manifest_body);
                bp_manifest_free (&manifest);
                return EXECUTION_FAILURE;
            }
        } else if (has_loadable) {
            builtin_error ("pack: type payload may not contain loadable/");
            bp_buf_free (&manifest_body);
            bp_manifest_free (&manifest);
            return EXECUTION_FAILURE;
        }
    }
    bp_buf_free (&manifest_body);
    bp_manifest_free (&manifest);

    /* Add MANIFEST first, then supported payload directories. */
    bp_buf tar = {0};
    const char *order[] = { "MANIFEST", "loadable", "files", "hooks", NULL };
    int found_manifest = 0;
    for (int oi = 0; order[oi]; oi++) {
        char path[BPKG_PATH_MAX];
        snprintf (path, sizeof path, "%s/%s", src, order[oi]);
        struct stat st;
        if (stat (path, &st) < 0) continue;
        if (S_ISREG (st.st_mode)) {
            if (!strcmp (order[oi], "MANIFEST")) found_manifest = 1;
            bp_buf body = {0};
            if (bp_read_file (path, &body) < 0) {
                bp_buf_free (&body);
                bp_buf_free (&tar);
                return EXECUTION_FAILURE;
            }
            bp_tar_hdr h;
            bp_tar_emit_hdr (&h, order[oi], body.len, st.st_mode & 07777,
                             '0', st.st_mtime);
            if (bp_buf_append (&tar, &h, sizeof h) < 0) {
                bp_buf_free (&body);
                bp_buf_free (&tar);
                return EXECUTION_FAILURE;
            }
            if (bp_buf_append (&tar, body.data, body.len) < 0) {
                bp_buf_free (&body);
                bp_buf_free (&tar);
                return EXECUTION_FAILURE;
            }
            size_t pad = (BPKG_TAR_BLOCK -
                          (body.len % BPKG_TAR_BLOCK)) % BPKG_TAR_BLOCK;
            if (pad) {
                unsigned char zeros[BPKG_TAR_BLOCK] = {0};
                if (bp_buf_append (&tar, zeros, pad) < 0) {
                    bp_buf_free (&body);
                    bp_buf_free (&tar);
                    return EXECUTION_FAILURE;
                }
            }
            bp_buf_free (&body);
        } else if (S_ISDIR (st.st_mode)) {
            /* Recursive walk. */
            char *queue[BPKG_MAX_FILES];
            int head = 0, tail = 0;
            queue[tail++] = strdup (path);
            if (!queue[0]) {
                bp_buf_free (&tar);
                return EXECUTION_FAILURE;
            }
            while (head < tail) {
                char *cur = queue[head++];
                DIR *d = opendir (cur);
                if (!d) {
                    free (cur);
                    continue;
                }
                struct dirent *de;
                while ((de = readdir (d)) != NULL) {
                    if (!strcmp (de->d_name, ".") ||
                        !strcmp (de->d_name, "..")) continue;
                    char child[BPKG_PATH_MAX];
                    snprintf (child, sizeof child, "%s/%s", cur,
                              de->d_name);
                    struct stat cst;
                    if (lstat (child, &cst) < 0) continue;
                    /* Build archive name relative to src. */
                    const char *rel = child + strlen (src) + 1;
                    if (S_ISDIR (cst.st_mode)) {
                        bp_tar_hdr h;
                        bp_tar_emit_hdr (&h, rel, 0,
                                         cst.st_mode & 07777, '5',
                                         cst.st_mtime);
                        if (bp_buf_append (&tar, &h, sizeof h) < 0)
                            goto pack_fail;
                        if (tail < BPKG_MAX_FILES) {
                            queue[tail] = strdup (child);
                            if (!queue[tail]) goto pack_fail;
                            tail++;
                        }
                    } else if (S_ISREG (cst.st_mode)) {
                        bp_buf body = {0};
                        if (bp_read_file (child, &body) < 0) {
                            bp_buf_free (&body);
                            goto pack_fail;
                        }
                        bp_tar_hdr h;
                        bp_tar_emit_hdr (&h, rel, body.len,
                                         cst.st_mode & 07777, '0',
                                         cst.st_mtime);
                        if (bp_buf_append (&tar, &h, sizeof h) < 0) {
                            bp_buf_free (&body);
                            goto pack_fail;
                        }
                        if (bp_buf_append (&tar, body.data, body.len)
                            < 0) {
                            bp_buf_free (&body);
                            goto pack_fail;
                        }
                        size_t pad = (BPKG_TAR_BLOCK -
                                      (body.len % BPKG_TAR_BLOCK)) %
                                     BPKG_TAR_BLOCK;
                        if (pad) {
                            unsigned char zeros[BPKG_TAR_BLOCK] = {0};
                            if (bp_buf_append (&tar, zeros, pad) < 0) {
                                bp_buf_free (&body);
                                goto pack_fail;
                            }
                        }
                        bp_buf_free (&body);
                    }
                }
                closedir (d);
                free (cur);
                continue;
pack_fail:
                closedir (d);
                free (cur);
                while (head < tail) free (queue[head++]);
                bp_buf_free (&tar);
                return EXECUTION_FAILURE;
            }
        }
    }
    if (!found_manifest) {
        builtin_error ("pack: %s/MANIFEST missing", src);
        bp_buf_free (&tar);
        return EXECUTION_FAILURE;
    }
    /* Two zero blocks terminate the archive. */
    unsigned char zeros[BPKG_TAR_BLOCK * 2] = {0};
    if (bp_buf_append (&tar, zeros, sizeof zeros) < 0) {
        bp_buf_free (&tar);
        return EXECUTION_FAILURE;
    }
    int rc;
    if (do_xz) {
        bp_buf xz = {0};
        if (bp_xz_compress (tar.data, tar.len, &xz) < 0) {
            bp_buf_free (&tar);
            bp_buf_free (&xz);
            builtin_error ("xz encode failed");
            return EXECUTION_FAILURE;
        }
        rc = bp_write_file_atomic (out, xz.data, xz.len, 0644);
        bp_buf_free (&xz);
    } else {
        rc = bp_write_file_atomic (out, tar.data, tar.len, 0644);
    }
    bp_buf_free (&tar);
    if (rc < 0) {
        builtin_error ("write %s: %s", out, strerror (errno));
        return EXECUTION_FAILURE;
    }
    printf ("packed %s\n", out);
    return EXECUTION_SUCCESS;
}

static int
verb_delta_make (WORD_LIST *args)
{
    const char *old_path = NULL, *new_path = NULL, *patch_path = NULL;
    while (args) {
        const char *w = args->word->word;
        if (!old_path) old_path = w;
        else if (!new_path) new_path = w;
        else if (!patch_path) patch_path = w;
        else {
            builtin_error ("delta-make OLD NEW PATCH");
            return EX_USAGE;
        }
        args = args->next;
    }
    if (!old_path || !new_path || !patch_path) {
        builtin_error ("delta-make OLD NEW PATCH");
        return EX_USAGE;
    }
    return bp_delta_make_file (old_path, new_path, patch_path);
}

static int
verb_delta_apply (WORD_LIST *args)
{
    const char *old_path = NULL, *patch_path = NULL, *out_path = NULL;
    while (args) {
        const char *w = args->word->word;
        if (!old_path) old_path = w;
        else if (!patch_path) patch_path = w;
        else if (!out_path) out_path = w;
        else {
            builtin_error ("delta-apply OLD PATCH OUT");
            return EX_USAGE;
        }
        args = args->next;
    }
    if (!old_path || !patch_path || !out_path) {
        builtin_error ("delta-apply OLD PATCH OUT");
        return EX_USAGE;
    }
    return bp_delta_apply_file (old_path, patch_path, out_path);
}

static int
bp_install_one (const char *root, const char *sources,
                const char *repo_filter, const char *arch_override,
                int allow_unsigned, int force, int allow_legacy_rootfs,
                const char *target)
{
    struct stat st;
    if (stat (target, &st) == 0 && S_ISREG (st.st_mode)) {
        bp_manifest mf;
        bp_manifest_init (&mf);
        int manifest_ok = bp_manifest_from_pkgfile (target, &mf) == 0;
        if (manifest_ok && bp_manifest_type_is_declared (&mf) &&
            !bp_manifest_type_is_known (&mf)) {
            builtin_error ("install: unsupported package type: %s",
                           bp_manifest_effective_type (&mf));
            bp_manifest_free (&mf);
            return EXECUTION_FAILURE;
        }
        int payload = manifest_ok && bp_manifest_is_payload (&mf);
        char pname[BPKG_NAME_MAX] = {0};
        if (payload)
            snprintf (pname, sizeof pname, "%s", mf.name);
        bp_manifest_free (&mf);
        if (payload && bp_reject_unsafe_name ("install", pname) < 0)
            return EXECUTION_FAILURE;
        /* A DIRECT type:payload FILE is a native pkg archive produced
         * by `pkg pack` (MANIFEST + files/ + hooks/), not a bl-pkg
         * repo transaction. Extract the GIVEN file via the same pkgfile
         * path the loadable FILE branch uses: bp_install_pkgfile already
         * extracts files/ into the rootfs, runs the declared hooks, records
         * install state, and rejects smuggled loadable/ entries in a
         * payload package. The bl-pkg repo backend is reserved for the
         * bare-PKGNAME / configured-sources resolution paths below, which
         * resolve a payload transaction rather than installing a file. The
         * signed-trust gate stays fail-closed: bp_install_pkgfile refuses an
         * unsigned archive unless -A is supplied, exactly as the loadable
         * file path does. */
        return bp_install_pkgfile_resolving_deps (target, root,
                                                 allow_unsigned, force,
                                                 allow_legacy_rootfs, 0);
    }

    /* Treat as PKGNAME. Payload INDEX records are handled by bl-pkg; if
     * no payload candidate is present, fall back to the existing loadable
     * cache/download resolver unchanged. */
    if (bp_reject_unsafe_name ("install", target) < 0)
        return EXECUTION_FAILURE;

    char payload_repo[BPKG_PATH_MAX];
    int prc = bp_find_payload_repo_dir (root, sources, repo_filter, target,
                                        arch_override, payload_repo,
                                        sizeof payload_repo);
    if (prc < 0)
        return EXECUTION_FAILURE;
    if (prc > 0)
        return bp_install_payload_via_blpkg (root, sources, repo_filter,
                                            arch_override, target,
                                            allow_unsigned);

    char path[BPKG_PATH_MAX];
    if (bp_find_in_cache (root, target, path, sizeof path) < 0) {
        if (bp_download_name (root, sources, repo_filter, arch_override,
                              target, 0) != EXECUTION_SUCCESS) {
            builtin_error ("%s: not in cache and not a file", target);
            return EXECUTION_FAILURE;
        }
        if (bp_find_in_cache (root, target, path, sizeof path) < 0) {
            builtin_error ("%s: downloaded package missing from cache",
                           target);
            return EXECUTION_FAILURE;
        }
    }
    char got_name[BPKG_NAME_MAX] = {0};
    if (bp_cache_candidate_name_matches (path, target, got_name,
                                         sizeof got_name) != 1) {
        builtin_error ("cache candidate name mismatch: %s has MANIFEST "
                       "name %s",
                       target, got_name[0] ? got_name : "(unknown)");
        return EXECUTION_FAILURE;
    }
    return bp_install_pkgfile_resolving_deps (path, root, allow_unsigned,
                                             force, allow_legacy_rootfs, 0);
}

static int
verb_install (WORD_LIST *args)
{
    const char *root = BPKG_INSTALL_ROOT;
    const char *sources = NULL;
    const char *repo_filter = NULL;
    const char *arch_override = NULL;
    int allow_unsigned = 0; /* H05 production posture: signatures are
                               required unless -A explicitly opts into
                               bootstrap/development unsigned installs. */
    int force = 0;
    int allow_legacy_rootfs = getenv ("BASHPKG_ALLOW_LEGACY_ROOTFS") &&
                              !strcmp (getenv ("BASHPKG_ALLOW_LEGACY_ROOTFS"),
                                       "1");
    const char *targets[BPKG_MAX_DEPS];
    int ntargets = 0;
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--root")) {
            if (!args->next) {
                builtin_error ("install PKGFILE | install PKGNAME "
                               "[--sources FILE] [--repo NAME] "
                               "[--arch ARCH]");
                return EX_USAGE;
            }
            args = args->next;
            root = args->word->word;
            if (bp_check_root (root) < 0) return EX_USAGE;
        } else if (!strcmp (w, "--sources")) {
            if (!args->next) {
                builtin_error ("install PKGFILE | install PKGNAME "
                               "[--sources FILE] [--repo NAME] "
                               "[--arch ARCH]");
                return EX_USAGE;
            }
            args = args->next;
            sources = args->word->word;
        } else if (!strcmp (w, "--repo")) {
            if (!args->next) {
                builtin_error ("install PKGFILE | install PKGNAME "
                               "[--sources FILE] [--repo NAME] "
                               "[--arch ARCH]");
                return EX_USAGE;
            }
            args = args->next;
            repo_filter = args->word->word;
        } else if (!strcmp (w, "--arch")) {
            if (!args->next) {
                builtin_error ("install PKGFILE | install PKGNAME "
                               "[--sources FILE] [--repo NAME] "
                               "[--arch ARCH]");
                return EX_USAGE;
            }
            args = args->next;
            arch_override = args->word->word;
        } else if (!strcmp (w, "-S")) {
            allow_unsigned = 0;
        } else if (!strcmp (w, "-A")) {
            allow_unsigned = 1;
        } else if (!strcmp (w, "--force") || !strcmp (w, "-f")) {
            force = 1;
        } else if (!strcmp (w, "--legacy-rootfs")) {
            allow_legacy_rootfs = 1;
        } else if (ntargets < BPKG_MAX_DEPS) {
            targets[ntargets++] = w;
        } else {
            builtin_error ("install PKGFILE | install PKGNAME "
                           "[--sources FILE] [--repo NAME] [--arch ARCH]");
            return EX_USAGE;
        }
        args = args->next;
    }
    if (ntargets == 0) {
        builtin_error ("install PKGFILE | install PKGNAME [--sources FILE] "
                       "[--repo NAME] [--arch ARCH]");
        return EX_USAGE;
    }
    for (int i = 0; i < ntargets; i++) {
        int rc = bp_install_one (root, sources, repo_filter, arch_override,
                                 allow_unsigned, force,
                                 allow_legacy_rootfs, targets[i]);
        if (rc != EXECUTION_SUCCESS)
            return rc;
    }
    return EXECUTION_SUCCESS;
}

static int
verb_rollback (WORD_LIST *args)
{
    const char *root = BPKG_INSTALL_ROOT;
    const char *target = NULL;
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--root")) {
            if (!args->next) {
                builtin_error ("rollback [--root R] PKGNAME|txn-ID");
                return EX_USAGE;
            }
            args = args->next;
            root = args->word->word;
            if (bp_check_root (root) < 0) return EX_USAGE;
        } else if (!target) {
            target = w;
        } else {
            builtin_error ("rollback [--root R] PKGNAME|txn-ID");
            return EX_USAGE;
        }
        args = args->next;
    }
    if (!target) {
        builtin_error ("rollback [--root R] PKGNAME|txn-ID");
        return EX_USAGE;
    }
    if (!strncmp (target, "txn-", 4)) {
        if (!bp_is_txn_id (target)) {
            builtin_error ("rollback: invalid transaction id: %s", target);
            return EXECUTION_FAILURE;
        }
        return bp_blpkg_rollback_txn (root, target);
    }

    if (bp_reject_unsafe_name ("rollback", target) < 0)
        return EXECUTION_FAILURE;

    char txn[BPKG_NAME_MAX];
    int prc = bp_read_payload_pointer (root, target, txn, sizeof txn);
    if (prc < 0) {
        builtin_error ("rollback: malformed payload pointer for %s", target);
        return EXECUTION_FAILURE;
    }
    if (prc == 0) {
        bp_manifest mf;
        bp_manifest_init (&mf);
        if (bp_read_installed_manifest (root, target, &mf) ==
            EXECUTION_SUCCESS) {
            if (bp_manifest_effective_is_loadable (&mf))
                builtin_error ("rollback: loadable rollback unsupported: %s",
                               target);
            else
                builtin_error ("rollback: no payload transaction pointer "
                               "for %s", target);
            bp_manifest_free (&mf);
        }
        return EXECUTION_FAILURE;
    }

    int rc = bp_blpkg_rollback_txn (root, txn);
    if (rc != EXECUTION_SUCCESS)
        return rc;
    if (bp_update_payload_pointer_from_blpkg (root, target) < 0)
        return EXECUTION_FAILURE;
    return EXECUTION_SUCCESS;
}

static void
bp_remove_state_dir (const char *dir)
{
    DIR *d = opendir (dir);
    if (d) {
        struct dirent *de;
        while ((de = readdir (d)) != NULL) {
            if (!strcmp (de->d_name, ".") ||
                !strcmp (de->d_name, "..")) continue;
            char p[BPKG_PATH_MAX];
            snprintf (p, sizeof p, "%s/%s", dir, de->d_name);
            unlink (p);
        }
        closedir (d);
    }
    rmdir (dir);
}

static int
verb_remove (WORD_LIST *args)
{
    const char *root = BPKG_INSTALL_ROOT;
    const char *name = NULL;
    int allow_legacy_rootfs = getenv ("BASHPKG_ALLOW_LEGACY_ROOTFS") &&
                              !strcmp (getenv ("BASHPKG_ALLOW_LEGACY_ROOTFS"),
                                       "1");
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--root")) {
            if (!args->next) {
                builtin_error ("remove PKGNAME");
                return EX_USAGE;
            }
            args = args->next;
            root = args->word->word;
            if (bp_check_root (root) < 0) return EX_USAGE;
        } else if (!strcmp (w, "--legacy-rootfs")) {
            allow_legacy_rootfs = 1;
        } else if (!name) {
            name = w;
        } else {
            builtin_error ("remove PKGNAME");
            return EX_USAGE;
        }
        args = args->next;
    }
    if (!name) {
        builtin_error ("remove PKGNAME");
        return EX_USAGE;
    }
    if (bp_reject_unsafe_name ("remove", name) < 0)
        return EXECUTION_FAILURE;
    char dir[BPKG_PATH_MAX];
    snprintf (dir, sizeof dir, "%s%s/%s",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_INSTALLED_DIR, name);

    /* Read the recorded MANIFEST so the remove hooks see BASHPKG_VERSION
     * matching what install set. Missing version is tolerated — older
     * installs predating this dispatcher contract may have an empty
     * version field, and the hook contract documents the empty-string
     * fallback. */
    char manifest_path[BPKG_PATH_MAX];
    snprintf (manifest_path, sizeof manifest_path, "%s/MANIFEST", dir);
    bp_manifest mf;
    bp_manifest_init (&mf);
    bp_buf manifest_body = {0};
    if (bp_read_file (manifest_path, &manifest_body) == 0) {
        bp_manifest_parse (&mf, manifest_body.data, manifest_body.len);
    }
    bp_buf_free (&manifest_body);
    const char *version = mf.version[0] ? mf.version : "";
    char so_path[BPKG_PATH_MAX];
    snprintf (so_path, sizeof so_path, "%s%s/%s.so",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_LOADABLES_DIR, name);
    char sha_path[BPKG_PATH_MAX];
    snprintf (sha_path, sizeof sha_path, "%s/sha256", dir);
    char files_path[BPKG_PATH_MAX];
    snprintf (files_path, sizeof files_path, "%s/files", dir);
    struct stat so_st, sha_st, files_st;
    int has_legacy_files_state = stat (files_path, &files_st) == 0;
    int has_loadable_state =
        bp_manifest_effective_is_loadable (&mf) ||
        stat (sha_path, &sha_st) == 0 ||
        (!has_legacy_files_state && stat (so_path, &so_st) == 0);

    if (has_loadable_state) {
        int errs = 0;

        if (unlink (so_path) < 0 && errno != ENOENT)
            errs++;

        bp_remove_state_dir (dir);
        bp_manifest_free (&mf);
        printf ("removed %s%s\n", name, errs ? " (with errors)" : "");
        return errs ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }

    if (!allow_legacy_rootfs && !bp_manifest_is_payload (&mf)) {
        builtin_error ("legacy rootfs package compatibility requires "
                       "--legacy-rootfs or BASHPKG_ALLOW_LEGACY_ROOTFS=1: %s",
                       name);
        bp_manifest_free (&mf);
        return EXECUTION_FAILURE;
    }

    bp_buf files = {0};
    if (bp_read_file (files_path, &files) < 0) {
        builtin_error ("%s not installed", name);
        bp_buf_free (&files);
        bp_manifest_free (&mf);
        return EXECUTION_FAILURE;
    }

    /* pre-remove. */
    char hpre[BPKG_PATH_MAX];
    snprintf (hpre, sizeof hpre, "%s/pre-remove", dir);
    if (bp_run_script (hpre, name, version, root) < 0) {
        bp_buf_free (&files);
        bp_manifest_free (&mf);
        return EXECUTION_FAILURE;
    }

    /* Unlink each recorded file. */
    size_t off = 0;
    int errs = 0;
    while (off < files.len) {
        size_t end = off;
        while (end < files.len && files.data[end] != '\n') end++;
        if (end > off) {
            char p[BPKG_PATH_MAX];
            size_t plen = end - off;
            if (plen >= sizeof p) {
                errs++;
            } else {
                /* Prefix with root if not "/". */
                if (root[0] && strcmp (root, "/") != 0 &&
                    files.data[off] == '/') {
                    snprintf (p, sizeof p, "%s%.*s", root, (int) plen,
                              files.data + off);
                } else {
                    memcpy (p, files.data + off, plen);
                    p[plen] = 0;
                }
                if (unlink (p) < 0 && errno != ENOENT) errs++;
            }
        }
        off = end + 1;
    }
    bp_buf_free (&files);

    /* post-remove. */
    char hpost[BPKG_PATH_MAX];
    snprintf (hpost, sizeof hpost, "%s/post-remove", dir);
    if (bp_run_script (hpost, name, version, root) < 0) errs++;

    /* Remove state dir contents and the dir itself. */
    bp_remove_state_dir (dir);

    bp_manifest_free (&mf);
    printf ("removed %s%s\n", name, errs ? " (with errors)" : "");
    return errs ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
verb_list (WORD_LIST *args)
{
    const char *root = BPKG_INSTALL_ROOT;
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--root")) {
            if (!args->next) {
                builtin_error ("list [--root R]");
                return EX_USAGE;
            }
            args = args->next;
            root = args->word->word;
            if (bp_check_root (root) < 0) return EX_USAGE;
        } else {
            builtin_error ("list [--root R]");
            return EX_USAGE;
        }
        args = args->next;
    }
    char dir[BPKG_PATH_MAX];
    snprintf (dir, sizeof dir, "%s%s",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_INSTALLED_DIR);
    DIR *d = opendir (dir);
    if (!d) return EXECUTION_SUCCESS; /* nothing installed */
    struct dirent *de;
    int count = 0;
    while ((de = readdir (d)) != NULL) {
        if (!strcmp (de->d_name, ".") ||
            !strcmp (de->d_name, "..")) continue;
        char m[BPKG_PATH_MAX];
        snprintf (m, sizeof m, "%s/%s/MANIFEST", dir, de->d_name);
        bp_buf body = {0};
        if (bp_read_file (m, &body) == 0) {
            bp_manifest mf;
            bp_manifest_init (&mf);
            if (bp_manifest_parse (&mf, body.data, body.len) == 0) {
                if (bp_manifest_is_v2_visible (&mf)) {
                    printf ("%s\t%s\t%s\t%s\t%s\n", mf.name,
                            mf.version[0] ? mf.version : "-",
                            mf.builtin[0] ? mf.builtin : "-",
                            mf.abi[0] ? mf.abi : "-",
                            mf.arch[0] ? mf.arch : "-");
                    count++;
                }
                bp_manifest_free (&mf);
            }
        }
        bp_buf_free (&body);
    }
    closedir (d);
    if (count == 0) printf ("no packages installed\n");
    return EXECUTION_SUCCESS;
}

static int
verb_info (WORD_LIST *args)
{
    const char *root = BPKG_INSTALL_ROOT;
    const char *name = NULL;
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--root")) {
            if (!args->next) {
                builtin_error ("info PKGNAME|PKGFILE");
                return EX_USAGE;
            }
            args = args->next;
            root = args->word->word;
            if (bp_check_root (root) < 0) return EX_USAGE;
        } else if (!name) {
            name = w;
        } else {
            builtin_error ("info PKGNAME|PKGFILE");
            return EX_USAGE;
        }
        args = args->next;
    }
    if (!name) {
        builtin_error ("info PKGNAME|PKGFILE");
        return EX_USAGE;
    }
    struct stat name_st;
    if (stat (name, &name_st) == 0 && S_ISREG (name_st.st_mode)) {
        bp_manifest mf;
        bp_manifest_init (&mf);
        if (bp_validate_loadable_archive (name, NULL, 0, &mf) < 0) {
            bp_manifest_free (&mf);
            return EXECUTION_FAILURE;
        }
        bp_manifest_print (&mf);
        bp_manifest_free (&mf);
        return EXECUTION_SUCCESS;
    }
    if (bp_reject_unsafe_name ("info", name) < 0)
        return EXECUTION_FAILURE;
    char m[BPKG_PATH_MAX];
    snprintf (m, sizeof m, "%s%s/%s/MANIFEST",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_INSTALLED_DIR, name);
    bp_buf body = {0};
    if (bp_read_file (m, &body) < 0) {
        /* Try cache. */
        char path[BPKG_PATH_MAX];
        if (bp_find_in_cache (root, name, path, sizeof path) < 0) {
            builtin_error ("%s: no installed or cached package", name);
            bp_buf_free (&body);
            return EXECUTION_FAILURE;
        }
        char got_name[BPKG_NAME_MAX] = {0};
        if (bp_cache_candidate_name_matches (path, name, got_name,
                                             sizeof got_name) != 1) {
            builtin_error ("cache candidate name mismatch: %s has MANIFEST "
                           "name %s",
                           name, got_name[0] ? got_name : "(unknown)");
            bp_buf_free (&body);
            return EXECUTION_FAILURE;
        }
        bp_manifest mf;
        bp_manifest_init (&mf);
        if (bp_validate_loadable_archive (path, name, 1, &mf) < 0) {
            bp_manifest_free (&mf);
            builtin_error ("%s: cached package is not a v2 loadable package",
                           name);
            return EXECUTION_FAILURE;
        }
        bp_manifest_print (&mf);
        bp_manifest_free (&mf);
        return EXECUTION_SUCCESS;
    }
    bp_manifest mf;
    bp_manifest_init (&mf);
    if (bp_manifest_parse (&mf, body.data, body.len) < 0 ||
        strcmp (mf.name, name) != 0) {
        bp_manifest_free (&mf);
        bp_buf_free (&body);
        builtin_error ("%s is not an installed pkg package", name);
        return EXECUTION_FAILURE;
    }
    if (!bp_manifest_is_payload (&mf) &&
        (!bp_manifest_effective_is_loadable (&mf) ||
         !mf.version[0] || !mf.builtin[0] || !mf.abi[0] ||
         !mf.arch[0] || !bp_hex64 (mf.sha256))) {
        bp_manifest_free (&mf);
        bp_buf_free (&body);
        builtin_error ("%s is not an installed v2 loadable package", name);
        return EXECUTION_FAILURE;
    }
    bp_manifest_free (&mf);
    fwrite (body.data, 1, body.len, stdout);
    if (body.len == 0 || body.data[body.len - 1] != '\n') putchar ('\n');
    bp_buf_free (&body);
    return EXECUTION_SUCCESS;
}

static int
verb_search (WORD_LIST *args)
{
    const char *root = BPKG_INSTALL_ROOT;
    const char *q = NULL;
    const char *repo_filter = NULL;
    const char *arch_override = NULL;
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--root")) {
            if (!args->next) {
                builtin_error ("search QUERY [--repo NAME] [--arch ARCH]");
                return EX_USAGE;
            }
            args = args->next;
            root = args->word->word;
            if (bp_check_root (root) < 0) return EX_USAGE;
        } else if (!strcmp (w, "--repo")) {
            if (!args->next) {
                builtin_error ("search QUERY [--repo NAME] [--arch ARCH]");
                return EX_USAGE;
            }
            args = args->next;
            repo_filter = args->word->word;
        } else if (!strcmp (w, "--arch")) {
            if (!args->next) {
                builtin_error ("search QUERY [--repo NAME] [--arch ARCH]");
                return EX_USAGE;
            }
            args = args->next;
            arch_override = args->word->word;
        } else if (!q) {
            q = w;
        } else {
            builtin_error ("search QUERY [--repo NAME] [--arch ARCH]");
            return EX_USAGE;
        }
        args = args->next;
    }
    if (!q) {
        builtin_error ("search QUERY [--repo NAME] [--arch ARCH]");
        return EX_USAGE;
    }
    char selected_arch[BPKG_NAME_MAX];
    if (bp_select_arch (arch_override, selected_arch, sizeof selected_arch) < 0)
        return EX_USAGE;
    int is_glob = bp_query_is_glob (q);
    int hits = 0;

    /* --repo NAME narrows scope to that repo's INDEX only; installed +
     * cache are scoped to the local node, not a remote repo, so they
     * are skipped when the caller asked specifically for a repo view. */
    if (!repo_filter) {
        /* Installed. */
        char dir[BPKG_PATH_MAX];
        snprintf (dir, sizeof dir, "%s%s",
                  root[0] && strcmp (root, "/") ? root : "",
                  BPKG_INSTALLED_DIR);
        DIR *d = opendir (dir);
        if (d) {
            struct dirent *de;
            while ((de = readdir (d)) != NULL) {
                if (!strcmp (de->d_name, ".") ||
                    !strcmp (de->d_name, "..")) continue;
	                char mpath[BPKG_PATH_MAX];
	                snprintf (mpath, sizeof mpath, "%s/%s/MANIFEST",
	                          dir, de->d_name);
	                bp_buf ibody = {0};
	                bp_manifest imf;
	                bp_manifest_init (&imf);
	                int visible =
	                    bp_read_file (mpath, &ibody) == 0 &&
	                    bp_manifest_parse (&imf, ibody.data, ibody.len) == 0 &&
	                    bp_manifest_is_v2_visible (&imf);
	                bp_buf_free (&ibody);
	                bp_manifest_free (&imf);
	                if (visible && bp_match (q, de->d_name, is_glob)) {
	                    printf ("installed\t%s\n", de->d_name);
	                    hits++;
	                }
            }
            closedir (d);
        }

        /* Cache. */
        char cdir[BPKG_PATH_MAX];
        snprintf (cdir, sizeof cdir, "%s%s",
                  root[0] && strcmp (root, "/") ? root : "",
                  BPKG_CACHE_DIR);
        d = opendir (cdir);
        if (d) {
            struct dirent *de;
            while ((de = readdir (d)) != NULL) {
                if (!strcmp (de->d_name, ".") ||
                    !strcmp (de->d_name, "..")) continue;
	                char cpath[BPKG_PATH_MAX];
	                snprintf (cpath, sizeof cpath, "%s/%s", cdir,
	                          de->d_name);
	                bp_manifest cmf;
	                bp_manifest_init (&cmf);
	                int visible =
	                    bp_manifest_from_pkgfile (cpath, &cmf) == 0 &&
	                    bp_manifest_is_v2_visible (&cmf);
	                bp_manifest_free (&cmf);
	                if (visible && bp_match (q, de->d_name, is_glob)) {
	                    printf ("cache\t%s\n", de->d_name);
	                    hits++;
	                }
            }
            closedir (d);
        }
    }

    /* Repo INDEXes — filtered by --repo NAME when set. */
    char rdir[BPKG_PATH_MAX];
    snprintf (rdir, sizeof rdir, "%s%s",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_REPOS_DIR);
    DIR *d = opendir (rdir);
    if (d) {
        struct dirent *de;
        while ((de = readdir (d)) != NULL) {
            if (!strcmp (de->d_name, ".") ||
                !strcmp (de->d_name, "..")) continue;
            if (repo_filter && strcmp (de->d_name, repo_filter) != 0)
                continue;
            const char *segments[4] = { selected_arch, "noarch", "any", "" };
            for (int si = 0; si < 4; si++) {
                char idx[BPKG_PATH_MAX];
                if (segments[si][0])
                    snprintf (idx, sizeof idx, "%s/%s/%s/INDEX", rdir,
                              de->d_name, segments[si]);
                else
                    snprintf (idx, sizeof idx, "%s/%s/INDEX", rdir,
                              de->d_name);
                bp_buf body = {0};
                if (bp_read_file (idx, &body) == 0) {
                    size_t off = 0;
                    while (off < body.len) {
                        size_t end = off;
                        while (end < body.len && body.data[end] != '\n')
                            end++;
                        if (end > off) {
                            char line[2048];
                            size_t ll = end - off;
                            if (ll < sizeof line) {
                                memcpy (line, body.data + off, ll);
                                line[ll] = 0;
                                if (bp_index_line_supported (line) &&
                                    bp_match (q, line, is_glob)) {
                                    printf ("repo:%s%s%s\t%s\n", de->d_name,
                                            segments[si][0] ? "/" : "",
                                            segments[si], line);
                                    hits++;
                                }
                            }
                        }
                        off = end + 1;
                    }
                }
                bp_buf_free (&body);
            }
        }
        closedir (d);
    }

    if (hits == 0) printf ("no matches for %s\n", q);
    return EXECUTION_SUCCESS;
}

static int
verb_update (WORD_LIST *args)
{
    const char *root = BPKG_INSTALL_ROOT;
    const char *sources = NULL;
    const char *arch_override = NULL;
    const char *cacert = NULL;
    int allow_remote = 0;
    int remote_insecure = 0;
    int timeout = 30;
    const char *usage = "update [--root R] [--sources FILE] [--arch ARCH] "
                        "[--remote] [--remote-insecure|-k] "
                        "[--cacert PEM] [--timeout SEC]";
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--root")) {
            if (!args->next) {
                builtin_error ("%s", usage);
                return EX_USAGE;
            }
            args = args->next;
            root = args->word->word;
            if (bp_check_root (root) < 0) return EX_USAGE;
        } else if (!strcmp (w, "--sources")) {
            if (!args->next) {
                builtin_error ("%s", usage);
                return EX_USAGE;
            }
            args = args->next;
            sources = args->word->word;
        } else if (!strcmp (w, "--arch")) {
            if (!args->next) {
                builtin_error ("%s", usage);
                return EX_USAGE;
            }
            args = args->next;
            arch_override = args->word->word;
        } else if (!strcmp (w, "--remote")) {
            allow_remote = 1;
        } else if (!strcmp (w, "--remote-insecure") ||
                   !strcmp (w, "--insecure") || !strcmp (w, "-k")) {
            allow_remote = 1;
            remote_insecure = 1;
        } else if (!strcmp (w, "--cacert") || !strcmp (w, "--pin")) {
            if (!args->next) {
                builtin_error ("%s", usage);
                return EX_USAGE;
            }
            args = args->next;
            cacert = args->word->word;
        } else if (!strcmp (w, "--timeout")) {
            if (!args->next) {
                builtin_error ("%s", usage);
                return EX_USAGE;
            }
            args = args->next;
            timeout = atoi (args->word->word);
            if (timeout <= 0 || timeout > 86400) {
                builtin_error ("update: --timeout needs 1..86400 seconds");
                return EX_USAGE;
            }
        } else {
            builtin_error ("%s", usage);
            return EX_USAGE;
        }
        args = args->next;
    }
    char selected_arch[BPKG_NAME_MAX];
    if (bp_select_arch (arch_override, selected_arch, sizeof selected_arch) < 0)
        return EX_USAGE;
    char src_path[BPKG_PATH_MAX];
    if (sources) {
        snprintf (src_path, sizeof src_path, "%s", sources);
    } else {
        snprintf (src_path, sizeof src_path, "%s%s",
                  root[0] && strcmp (root, "/") ? root : "",
                  BPKG_SOURCES_LIST);
    }
    bp_buf body = {0};
    if (bp_read_file (src_path, &body) < 0) {
        printf ("no sources configured at %s\n", src_path);
        bp_buf_free (&body);
        return EXECUTION_SUCCESS;
    }
	    /* Parse one URL per line; for each, ensure the per-repo dir
	     * exists. H05 local sources (file:// and bare absolute paths) are
	     * fetched in-process by copying their INDEX into
	     * BPKG_REPOS_DIR/<repo>/INDEX. Remote sources remain rejected by
	     * update; pkg fetch materializes them into this local mirror.
	     * Trust mirrors install: a sibling <INDEX>.sig is verified via
     * bashsignify when present; verification failure refuses
     * to write that source's INDEX. */
    char rdir[BPKG_PATH_MAX];
    snprintf (rdir, sizeof rdir, "%s%s",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_REPOS_DIR);
    if (bp_mkdir_p (rdir) < 0) {
        builtin_error ("mkdir %s: %s", rdir, strerror (errno));
        bp_buf_free (&body);
        return EXECUTION_FAILURE;
    }
    int n = 0;
    int failed = 0;
    size_t off = 0;
    while (off < body.len) {
        size_t end = off;
        while (end < body.len && body.data[end] != '\n') end++;
        size_t ll = end - off;
        if (ll > 0 && ll < 2048 && body.data[off] != '#') {
            char line[2048];
            memcpy (line, body.data + off, ll);
            line[ll] = 0;
            int line_remote = 0;
            int line_insecure = 0;
            char *url = bp_source_parse_marker (line, &line_remote,
                                                &line_insecure);
            if (*url) {
                char local_buf[BPKG_PATH_MAX];
                const char *local = NULL;
                int lrc = bp_source_local_path (url, local_buf,
                                                sizeof local_buf);
                if (lrc < 0) {
                    builtin_error ("invalid local source: %s", url);
                    failed++;
                    n++;
                    off = end + 1;
                    continue;
                }
                if (lrc == 0) {
                    int is_https = 0;
                    int is_http = 0;
                    int rrc = bp_source_remote (url, &is_https, &is_http);
                    (void) is_https;
                    if (rrc < 0) {
                        builtin_error ("invalid remote source: %s", url);
                        failed++;
                        n++;
                        off = end + 1;
                        continue;
                    }
                    if (rrc == 0 || !(allow_remote || line_remote)) {
                        builtin_error ("non-local source unsupported: %s", url);
                        failed++;
                        n++;
                        off = end + 1;
                        continue;
                    }
                    int use_insecure = remote_insecure || line_insecure;
                    if (is_http && !use_insecure) {
                        builtin_error ("remote http source requires "
                                       "--remote-insecure: %s", url);
                        failed++;
                        n++;
                        off = end + 1;
                        continue;
                    }

                    char repo[BPKG_NAME_MAX];
                    if (bp_repo_name_from_source (url, repo, sizeof repo) < 0)
                        snprintf (repo, sizeof repo, "default");
                    char repo_dir[BPKG_PATH_MAX];
                    snprintf (repo_dir, sizeof repo_dir, "%s/%s", rdir, repo);

                    int rc = bp_fetch_remote_source (url, repo_dir, root,
                                                     selected_arch, cacert,
                                                     use_insecure, timeout);
                    if (rc < 0) {
                        failed++;
                        printf ("source\t%s\n", url);
                    } else {
                        printf ("source\t%s\tfetched\n", url);
                    }
                    n++;
                    off = end + 1;
                    continue;
                }
                if (lrc > 0)
                    local = local_buf;

                char repo[BPKG_NAME_MAX];
                if (bp_repo_name_from_source (url, repo, sizeof repo) < 0)
                    snprintf (repo, sizeof repo, "default");
                char repo_dir[BPKG_PATH_MAX];
                snprintf (repo_dir, sizeof repo_dir, "%s/%s", rdir, repo);
                bp_mkdir_p (repo_dir);

		                /* Local-fetcher slice: accept file:// scheme or
		                 * a bare absolute path. The source may point at
	                 * an INDEX file directly, or at a directory that
	                 * contains an INDEX. Directory sources may also
	                 * expose <arch>/INDEX and noarch/INDEX. */
                int fetched = 0;
                if (local && *local) {
                    char src_idx[BPKG_PATH_MAX];
                    char src_pkgdir[BPKG_PATH_MAX];
                    src_idx[0] = 0;
                    src_pkgdir[0] = 0;
                    if (bp_source_index_path (local, src_idx,
                                              sizeof src_idx, src_pkgdir,
                                              sizeof src_pkgdir) < 0) {
                        builtin_error ("source path unavailable: %s", local);
                        failed++;
                        src_idx[0] = 0;
                    }
                    if (src_idx[0]) {
                        struct stat idx_st;
                        if (stat (src_idx, &idx_st) == 0 &&
                            S_ISREG (idx_st.st_mode)) {
                            if (bp_update_copy_index (src_idx, src_pkgdir,
                                                      repo_dir) < 0)
                                failed++;
                            else
                                fetched = 1;
                        }
                    }

                    /* Per-arch trust boundary: each arch-scoped INDEX copy
                     * below enters bp_update_copy_index(), which verifies
                     * that <arch>/INDEX against its own sibling INDEX.sig.
                     * The operator's bashsignify wrapper chooses the trusted
                     * pubkey(s); INDEX does not carry per-arch key binding. */
                    const char *arch_segments[3] = {
                        selected_arch, "noarch", "any"
                    };
                    for (int ai = 0; ai < 3; ai++) {
                        if (!arch_segments[ai][0]) continue;
                        if (ai > 0 &&
                            strcmp (arch_segments[ai], selected_arch) == 0)
                            continue;
                        char a_src_idx[BPKG_PATH_MAX];
                        char a_src_pkgdir[BPKG_PATH_MAX];
                        if (bp_source_arch_index_path (
                                local, arch_segments[ai], a_src_idx,
                                sizeof a_src_idx, a_src_pkgdir,
                                sizeof a_src_pkgdir) == 0) {
                            char a_dest[BPKG_PATH_MAX];
                            snprintf (a_dest, sizeof a_dest, "%s/%s",
                                      repo_dir, arch_segments[ai]);
                            if (bp_update_copy_index (a_src_idx,
                                                      a_src_pkgdir,
                                                      a_dest) < 0)
                                failed++;
                            else
                                fetched = 1;
                        }
                    }
                }

	                if (!fetched)
	                    failed++;
                if (fetched)
                    printf ("source\t%s\tfetched\n", url);
                else
                    printf ("source\t%s\n", url);
                n++;
            }
        }
        off = end + 1;
    }
    bp_buf_free (&body);
    printf ("updated %d source(s)\n", n);
    return failed ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
verb_fetch (WORD_LIST *args)
{
    const char *root = BPKG_INSTALL_ROOT;
    const char *sources = NULL;
    const char *arch_override = NULL;
    int insecure = 0;
    int timeout = 30;
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--root")) {
            if (!args->next) {
                builtin_error ("fetch [--root R] [--sources FILE] [--arch ARCH] [--insecure] [--timeout SEC]");
                return EX_USAGE;
            }
            args = args->next;
            root = args->word->word;
            if (bp_check_root (root) < 0) return EX_USAGE;
        } else if (!strcmp (w, "--sources")) {
            if (!args->next) {
                builtin_error ("fetch [--root R] [--sources FILE] [--arch ARCH] [--insecure] [--timeout SEC]");
                return EX_USAGE;
            }
            args = args->next;
            sources = args->word->word;
        } else if (!strcmp (w, "--arch")) {
            if (!args->next) {
                builtin_error ("fetch [--root R] [--sources FILE] [--arch ARCH] [--insecure] [--timeout SEC]");
                return EX_USAGE;
            }
            args = args->next;
            arch_override = args->word->word;
        } else if (!strcmp (w, "--insecure") || !strcmp (w, "-k")) {
            insecure = 1;
        } else if (!strcmp (w, "--timeout")) {
            if (!args->next) {
                builtin_error ("fetch [--root R] [--sources FILE] [--arch ARCH] [--insecure] [--timeout SEC]");
                return EX_USAGE;
            }
            args = args->next;
            timeout = atoi (args->word->word);
            if (timeout <= 0 || timeout > 86400) {
                builtin_error ("fetch: --timeout needs 1..86400 seconds");
                return EX_USAGE;
            }
        } else {
            builtin_error ("fetch [--root R] [--sources FILE] [--arch ARCH] [--insecure] [--timeout SEC]");
            return EX_USAGE;
        }
        args = args->next;
    }

    char selected_arch[BPKG_NAME_MAX];
    if (bp_select_arch (arch_override, selected_arch, sizeof selected_arch) < 0)
        return EX_USAGE;
    char src_path[BPKG_PATH_MAX];
    if (sources) {
        snprintf (src_path, sizeof src_path, "%s", sources);
    } else {
        snprintf (src_path, sizeof src_path, "%s%s",
                  root[0] && strcmp (root, "/") ? root : "",
                  BPKG_SOURCES_LIST);
    }
    bp_buf body = {0};
    if (bp_read_file (src_path, &body) < 0) {
        printf ("no sources configured at %s\n", src_path);
        bp_buf_free (&body);
        return EXECUTION_SUCCESS;
    }
    char rdir[BPKG_PATH_MAX];
    snprintf (rdir, sizeof rdir, "%s%s",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_REPOS_DIR);
    if (bp_mkdir_p (rdir) < 0) {
        builtin_error ("mkdir %s: %s", rdir, strerror (errno));
        bp_buf_free (&body);
        return EXECUTION_FAILURE;
    }

    int n = 0;
    int failed = 0;
    size_t off = 0;
    while (off < body.len) {
        size_t end = off;
        while (end < body.len && body.data[end] != '\n') end++;
        size_t ll = end - off;
        if (ll > 0 && ll < 2048 && body.data[off] != '#') {
            char line[2048];
            memcpy (line, body.data + off, ll);
            line[ll] = 0;
            int line_remote = 0;
            int line_insecure = 0;
            char *url = bp_source_parse_marker (line, &line_remote,
                                                &line_insecure);
            (void) line_remote;
            if (*url) {
                char repo[BPKG_NAME_MAX];
                if (bp_repo_name_from_source (url, repo, sizeof repo) < 0) {
                    builtin_error ("fetch: bad source name: %s", url);
                    failed++;
                    n++;
                    off = end + 1;
                    continue;
                }
                char repo_dir[BPKG_PATH_MAX];
                snprintf (repo_dir, sizeof repo_dir, "%s/%s", rdir, repo);

	                int rc = 0;
	                if (bp_remote_url (url)) {
	                    rc = bp_fetch_remote_source (url, repo_dir, root,
	                                                 selected_arch, NULL,
	                                                 insecure || line_insecure,
	                                                 timeout);
                } else {
                    char local_buf[BPKG_PATH_MAX];
                    int lrc = bp_source_local_path (url, local_buf,
                                                    sizeof local_buf);
                    if (lrc <= 0) {
                        builtin_error ("fetch: unsupported source: %s", url);
                        rc = -1;
                    } else {
                        rc = bp_fetch_local_source (url, local_buf, repo_dir,
                                                    selected_arch);
                    }
                }
                if (rc < 0) {
                    failed++;
                    printf ("source\t%s\n", url);
                } else {
                    printf ("source\t%s\tfetched\n", url);
                }
                n++;
            }
        }
        off = end + 1;
    }
    bp_buf_free (&body);
    printf ("fetched %d source(s)\n", n);
    return failed ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bp_download_name (const char *root, const char *sources,
                  const char *repo_filter, const char *arch_override,
                  const char *name, int depth)
{
    if (depth == 0)
        bp_download_dep_stack_depth = 0;
    if (depth > BPKG_MAX_DEPS) {
        builtin_error ("dependency download depth exceeded: %s", name);
        return EXECUTION_FAILURE;
    }

    bp_index_hit best;
    int hrc = bp_find_repo_hit (root, sources, repo_filter, name,
                                arch_override, &best);
    if (hrc < 0)
        return EXECUTION_FAILURE;
    if (!best.pkg[0]) {
        if (repo_filter)
            builtin_error ("%s: no downloadable package in repo %s "
                           "(run pkg update)", name, repo_filter);
        else
            builtin_error ("%s: no downloadable package in configured "
                           "local sources (run pkg update)", name);
        return EXECUTION_FAILURE;
    }
    if (best.sha[0]) {
        char got[65];
        if (bp_sha256_file_hex (best.pkg, got) < 0 ||
            strcasecmp (got, best.sha) != 0) {
            builtin_error ("package sha256 mismatch for %s", best.pkg);
            return EXECUTION_FAILURE;
        }
    }
    int sigrc = best.sig[0]
        ? bp_verify_signature_with_sig (best.pkg, best.sig)
        : bp_verify_signature (best.pkg);
    if (sigrc < 0) {
        builtin_error ("signature verification failed for %s", best.pkg);
        return EXECUTION_FAILURE;
    }
    if (sigrc == 1 && best.sig[0]) {
        builtin_error ("no signature for %s", best.pkg);
        return EXECUTION_FAILURE;
    }
    if (bp_arch_matches (best.arch)) {
        bp_manifest best_manifest;
        bp_manifest_init (&best_manifest);
        if (bp_validate_loadable_archive (best.pkg, name, 1,
                                          &best_manifest) < 0) {
            builtin_error ("invalid loadable package in index for %s: %s",
                           name, best.pkg);
            return EXECUTION_FAILURE;
        }
        if (strcmp (best_manifest.version, best.version) != 0 ||
            strcmp (best_manifest.builtin, best.builtin) != 0 ||
            strcmp (best_manifest.abi, best.abi) != 0 ||
            strcmp (best_manifest.arch, best.arch) != 0) {
            builtin_error ("index metadata mismatch for %s", name);
            bp_manifest_free (&best_manifest);
            return EXECUTION_FAILURE;
        }
        bp_manifest_free (&best_manifest);
    }
    if (best.deps[0] && strcmp (best.deps, "-") != 0) {
        char deps_copy[sizeof best.deps];
        snprintf (deps_copy, sizeof deps_copy, "%s", best.deps);
        char *save = NULL;
        for (char *dep = strtok_r (deps_copy, ",", &save); dep;
             dep = strtok_r (NULL, ",", &save)) {
            dep = bp_strip (dep);
            if (!*dep || !strcmp (dep, "-"))
                continue;
            if (!strcmp (dep, name)) {
                builtin_error ("package depends on itself: %s", name);
                return EXECUTION_FAILURE;
            }
            if (!bp_safe_name (dep)) {
                builtin_error ("invalid dependency name: %s", dep);
                return EXECUTION_FAILURE;
            }
            if (bp_dep_stack_contains (bp_download_dep_stack,
                                       bp_download_dep_stack_depth, dep)) {
                builtin_error ("dependency cycle: %s -> %s", name, dep);
                return EXECUTION_FAILURE;
            }
            if (bp_dep_stack_push (bp_download_dep_stack,
                                   &bp_download_dep_stack_depth, name) < 0) {
                builtin_error ("dependency download depth exceeded: %s",
                               name);
                return EXECUTION_FAILURE;
            }
            const char *dep_repo = repo_filter ? repo_filter :
                (best.repo[0] ? best.repo : NULL);
            if (bp_download_name (root, sources, dep_repo, arch_override, dep,
                                  depth + 1) != EXECUTION_SUCCESS) {
                bp_download_dep_stack_depth--;
                return EXECUTION_FAILURE;
            }
            bp_download_dep_stack_depth--;
        }
    }
    char dest[BPKG_PATH_MAX];
    if (bp_copy_package_to_cache (root, best.pkg, dest, sizeof dest) < 0) {
        builtin_error ("download %s: %s", best.pkg, strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (best.sig[0] && bp_copy_signature_to_cache (best.sig, dest) < 0) {
        builtin_error ("download signature %s: %s", best.sig,
                       strerror (errno));
        unlink (dest);
        return EXECUTION_FAILURE;
    }
    printf ("downloaded\t%s\t%s\t%s\n", name, best.url, dest);
    return EXECUTION_SUCCESS;
}

static int
verb_download (WORD_LIST *args)
{
    const char *root = BPKG_INSTALL_ROOT;
    const char *sources = NULL;
    const char *repo_filter = NULL;
    const char *arch_override = NULL;
    const char *name = NULL;
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--root")) {
            if (!args->next) {
                builtin_error ("download PKGNAME [--root R] [--sources FILE] [--repo NAME] [--arch ARCH]");
                return EX_USAGE;
            }
            args = args->next;
            root = args->word->word;
            if (bp_check_root (root) < 0) return EX_USAGE;
        } else if (!strcmp (w, "--sources")) {
            if (!args->next) {
                builtin_error ("download PKGNAME [--root R] [--sources FILE] [--repo NAME] [--arch ARCH]");
                return EX_USAGE;
            }
            args = args->next;
            sources = args->word->word;
        } else if (!strcmp (w, "--repo")) {
            if (!args->next) {
                builtin_error ("download PKGNAME [--root R] [--sources FILE] [--repo NAME] [--arch ARCH]");
                return EX_USAGE;
            }
            args = args->next;
            repo_filter = args->word->word;
        } else if (!strcmp (w, "--arch")) {
            if (!args->next) {
                builtin_error ("download PKGNAME [--root R] [--sources FILE] [--repo NAME] [--arch ARCH]");
                return EX_USAGE;
            }
            args = args->next;
            arch_override = args->word->word;
        } else if (!name) {
            name = w;
        } else {
            builtin_error ("download PKGNAME [--root R] [--sources FILE] [--repo NAME] [--arch ARCH]");
            return EX_USAGE;
        }
        args = args->next;
    }
    if (!name) {
        builtin_error ("download PKGNAME [--root R] [--sources FILE] [--repo NAME] [--arch ARCH]");
        return EX_USAGE;
    }
    if (bp_reject_unsafe_name ("download", name) < 0)
        return EXECUTION_FAILURE;
    return bp_download_name (root, sources, repo_filter, arch_override, name,
                             0);
}

static int
verb_upgrade (WORD_LIST *args)
{
    const char *root = BPKG_INSTALL_ROOT;
    const char *sources = NULL;
    const char *repo_filter = NULL;
    const char *arch_override = NULL;
    int allow_unsigned = 0;
    int no_delta = 0;
    const char *only = NULL;
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--root")) {
            if (!args->next) {
                builtin_error ("upgrade PACKAGE|PKGNAME [--root R] "
                               "[--sources FILE] [--repo NAME] "
                               "[--arch ARCH] [--no-delta] [-S|-A]");
                return EX_USAGE;
            }
            args = args->next;
            root = args->word->word;
            if (bp_check_root (root) < 0) return EX_USAGE;
        } else if (!strcmp (w, "--sources")) {
            if (!args->next) {
                builtin_error ("upgrade PACKAGE|PKGNAME [--root R] "
                               "[--sources FILE] [--repo NAME] "
                               "[--arch ARCH] [--no-delta] [-S|-A]");
                return EX_USAGE;
            }
            args = args->next;
            sources = args->word->word;
        } else if (!strcmp (w, "--repo")) {
            if (!args->next) {
                builtin_error ("upgrade PACKAGE|PKGNAME [--root R] "
                               "[--sources FILE] [--repo NAME] "
                               "[--arch ARCH] [--no-delta] [-S|-A]");
                return EX_USAGE;
            }
            args = args->next;
            repo_filter = args->word->word;
        } else if (!strcmp (w, "--arch")) {
            if (!args->next) {
                builtin_error ("upgrade PACKAGE|PKGNAME [--root R] "
                               "[--sources FILE] [--repo NAME] "
                               "[--arch ARCH] [--no-delta] [-S|-A]");
                return EX_USAGE;
            }
            args = args->next;
            arch_override = args->word->word;
        } else if (!strcmp (w, "-S")) {
            allow_unsigned = 0;
        } else if (!strcmp (w, "-A")) {
            allow_unsigned = 1;
        } else if (!strcmp (w, "--no-delta")) {
            no_delta = 1;
        } else if (!strcmp (w, "--legacy-rootfs")) {
            builtin_error ("upgrade does not support legacy rootfs packages");
            return EXECUTION_FAILURE;
        } else if (!only) {
            only = w;
        } else {
            builtin_error ("upgrade PACKAGE|PKGNAME [--root R] "
                           "[--sources FILE] [--repo NAME] "
                           "[--arch ARCH] [--no-delta] [-S|-A]");
            return EX_USAGE;
        }
        args = args->next;
    }
    if (!only) {
        builtin_error ("upgrade PACKAGE|PKGNAME [--root R] [--sources FILE] "
                       "[--repo NAME] [--arch ARCH] [--no-delta] [-S|-A]");
        return EX_USAGE;
    }
    struct stat only_st;
    if (!(stat (only, &only_st) == 0 && S_ISREG (only_st.st_mode))) {
        if (bp_reject_unsafe_name ("upgrade", only) < 0)
            return EXECUTION_FAILURE;
        bp_manifest installed;
        if (bp_read_installed_manifest (root, only, &installed) !=
            EXECUTION_SUCCESS)
            return EXECUTION_FAILURE;
        if (!bp_manifest_effective_is_loadable (&installed)) {
            bp_manifest_free (&installed);
            builtin_error ("%s is not an installed v2 loadable package",
                           only);
            return EXECUTION_FAILURE;
        }
        char installed_so[BPKG_PATH_MAX];
        if (bp_verify_installed_loadable (root, only, &installed,
                                          installed_so,
                                          sizeof installed_so) !=
            EXECUTION_SUCCESS) {
            bp_manifest_free (&installed);
            return EXECUTION_FAILURE;
        }
        bp_index_hit hit;
        int hrc = bp_find_repo_hit (root, sources, repo_filter, only,
                                    arch_override, &hit);
        if (hrc < 0) {
            bp_manifest_free (&installed);
            return EXECUTION_FAILURE;
        }
        if (!hit.pkg[0]) {
            bp_manifest_free (&installed);
            builtin_error ("%s: no upgrade candidate in configured local "
                           "sources", only);
            return EXECUTION_FAILURE;
        }

        char candidate_path[BPKG_PATH_MAX] = {0};
        int used_delta = 0;
        if (!no_delta && hit.delta[0] && hit.delta_from[0] &&
            hit.delta_to[0]) {
            char old_pkg[BPKG_PATH_MAX];
            char old_sha[65];
            if (bp_find_in_cache (root, only, old_pkg, sizeof old_pkg) == 0 &&
                bp_sha256_file_hex (old_pkg, old_sha) == 0 &&
                strcasecmp (old_sha, hit.delta_from) == 0) {
                if (hit.delta_sig[0]) {
                    int dsig = bp_verify_signature_with_sig (hit.delta,
                                                             hit.delta_sig);
                    if (dsig < 0) {
                        bp_manifest_free (&installed);
                        builtin_error ("signature verification failed for %s",
                                       hit.delta);
                        return EXECUTION_FAILURE;
                    }
                }
                char cdir[BPKG_PATH_MAX];
                snprintf (cdir, sizeof cdir, "%s%s",
                          root[0] && strcmp (root, "/") ? root : "",
                          BPKG_CACHE_DIR);
                if (bp_mkdir_p (cdir) < 0) {
                    bp_manifest_free (&installed);
                    return EXECUTION_FAILURE;
                }
                snprintf (candidate_path, sizeof candidate_path,
                          "%s/%s-%s.pkg", cdir, only,
                          hit.version[0] ? hit.version : "upgrade");
                if (bp_delta_apply_file (old_pkg, hit.delta,
                                         candidate_path) == EXECUTION_SUCCESS) {
                    char got[65];
                    if (bp_sha256_file_hex (candidate_path, got) == 0 &&
                        strcasecmp (got, hit.sha) == 0) {
                        if (hit.sig[0] &&
                            bp_copy_signature_to_cache (hit.sig,
                                                        candidate_path) < 0) {
                            unlink (candidate_path);
                            bp_manifest_free (&installed);
                            builtin_error ("download signature %s: %s",
                                           hit.sig, strerror (errno));
                            return EXECUTION_FAILURE;
                        }
                        used_delta = 1;
                    } else {
                        unlink (candidate_path);
                        candidate_path[0] = 0;
                    }
                }
            }
        }
        if (!used_delta) {
            if (bp_download_name (root, sources, repo_filter, arch_override,
                                  only, 0) != EXECUTION_SUCCESS) {
                bp_manifest_free (&installed);
                return EXECUTION_FAILURE;
            }
            if (bp_find_in_cache (root, only, candidate_path,
                                  sizeof candidate_path) < 0) {
                bp_manifest_free (&installed);
                builtin_error ("%s: cached upgrade candidate missing", only);
                return EXECUTION_FAILURE;
            }
        }
        bp_manifest candidate;
        if (bp_manifest_from_pkgfile (candidate_path, &candidate) < 0) {
            bp_manifest_free (&installed);
            builtin_error ("invalid upgrade package: %s", candidate_path);
            return EXECUTION_FAILURE;
        }
        printf ("upgrade\t%s\t%s -> %s%s\n", candidate.name,
                installed.version[0] ? installed.version : "-",
                candidate.version[0] ? candidate.version : "-",
                used_delta ? "\t(delta)" : "");
        bp_manifest_free (&installed);
        bp_manifest_free (&candidate);
        return bp_install_pkgfile_resolving_deps (candidate_path, root,
                                                  allow_unsigned, 1, 0, 0);
    }
    char dir[BPKG_PATH_MAX];
    snprintf (dir, sizeof dir, "%s%s",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_INSTALLED_DIR);
    DIR *d = opendir (dir);
    if (!d) {
        builtin_error ("no packages installed");
        return EXECUTION_FAILURE;
    }

            int sigrc = bp_verify_signature (only);
            if (sigrc < 0) {
                closedir (d);
                builtin_error ("signature verification failed: %s", only);
                return EXECUTION_FAILURE;
            }
            if (sigrc == 1 && !allow_unsigned) {
                closedir (d);
                builtin_error ("no signature for %s (re-run with -A to allow)",
                               only);
                return EXECUTION_FAILURE;
            }
            bp_manifest candidate;
            if (bp_manifest_from_pkgfile (only, &candidate) < 0) {
                closedir (d);
                builtin_error ("invalid upgrade package: %s", only);
                return EXECUTION_FAILURE;
            }
            if (!bp_manifest_effective_is_loadable (&candidate)) {
                bp_manifest_free (&candidate);
                closedir (d);
                builtin_error ("upgrade package is not a v2 loadable: %s",
                               only);
                return EXECUTION_FAILURE;
            }
            if (bp_validate_loadable_archive (only, NULL, 1, NULL) < 0) {
                bp_manifest_free (&candidate);
                closedir (d);
                return EXECUTION_FAILURE;
            }

            char installed_manifest[BPKG_PATH_MAX];
            snprintf (installed_manifest, sizeof installed_manifest,
                      "%s/%s/MANIFEST", dir, candidate.name);
            bp_buf body = {0};
            bp_manifest installed;
            bp_manifest_init (&installed);
            if (bp_read_file (installed_manifest, &body) < 0 ||
                bp_manifest_parse (&installed, body.data, body.len) < 0) {
                bp_buf_free (&body);
                bp_manifest_free (&installed);
                bp_manifest_free (&candidate);
                closedir (d);
                builtin_error ("%s not installed", candidate.name);
                return EXECUTION_FAILURE;
            }
            bp_buf_free (&body);
            if (!bp_manifest_effective_is_loadable (&installed)) {
                bp_manifest_free (&installed);
                bp_manifest_free (&candidate);
                closedir (d);
                builtin_error ("%s is not an installed v2 loadable package",
                               candidate.name);
                return EXECUTION_FAILURE;
            }
            char installed_so[BPKG_PATH_MAX];
            if (bp_verify_installed_loadable (root, candidate.name,
                                              &installed, installed_so,
                                              sizeof installed_so)
                != EXECUTION_SUCCESS) {
                bp_manifest_free (&installed);
                bp_manifest_free (&candidate);
                closedir (d);
                return EXECUTION_FAILURE;
            }

            printf ("upgrade\t%s\t%s -> %s\n", candidate.name,
                    installed.version[0] ? installed.version : "-",
                    candidate.version[0] ? candidate.version : "-");
            bp_manifest_free (&installed);
            bp_manifest_free (&candidate);
            closedir (d);
            return bp_install_pkgfile_resolving_deps (only, root,
                                                      allow_unsigned, 1,
                                                      0,
                                                      0);
}

static int
bp_verify_pkgfile (const char *pkgfile)
{
    int sigrc = bp_verify_signature (pkgfile);
    if (sigrc < 0) {
        builtin_error ("signature verification failed: %s", pkgfile);
        return EXECUTION_FAILURE;
    }
    if (sigrc == 1) {
        builtin_error ("no signature for %s", pkgfile);
        return EXECUTION_FAILURE;
    }

    bp_manifest mf;
    bp_manifest_init (&mf);
    if (bp_validate_loadable_archive (pkgfile, NULL, 1, &mf) < 0) {
        bp_manifest_free (&mf);
        return EXECUTION_FAILURE;
    }
    printf ("verify %s\tpackage=ok\n", mf.name);
    bp_manifest_free (&mf);
    return EXECUTION_SUCCESS;
}

static int
verb_verify (WORD_LIST *args)
{
    const char *root = BPKG_INSTALL_ROOT;
    const char *name = NULL;
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--root")) {
            if (!args->next) {
                builtin_error ("verify PKGNAME|PKGFILE");
                return EX_USAGE;
            }
            args = args->next;
            root = args->word->word;
            if (bp_check_root (root) < 0) return EX_USAGE;
        } else if (!name) {
            name = w;
        } else {
            builtin_error ("verify PKGNAME|PKGFILE");
            return EX_USAGE;
        }
        args = args->next;
    }
    if (!name) {
        builtin_error ("verify PKGNAME|PKGFILE");
        return EX_USAGE;
    }
    struct stat name_st;
    if (stat (name, &name_st) == 0 && S_ISREG (name_st.st_mode))
        return bp_verify_pkgfile (name);
    if (bp_reject_unsafe_name ("verify", name) < 0)
        return EXECUTION_FAILURE;

    char manifest_path[BPKG_PATH_MAX];
    snprintf (manifest_path, sizeof manifest_path, "%s%s/%s/MANIFEST",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_INSTALLED_DIR, name);
    bp_buf manifest = {0};
    bp_manifest mf;
    bp_manifest_init (&mf);
    int manifest_ok = 0;
    if (bp_read_file (manifest_path, &manifest) == 0 &&
        bp_manifest_parse (&mf, manifest.data, manifest.len) == 0) {
        manifest_ok = 1;
    }
    if (manifest_ok && bp_manifest_effective_is_loadable (&mf))
    {
        int bad = 0;
        if (strcmp (mf.name, name) != 0) {
            printf ("BAD-LOADABLE-METADATA\t%s\n", name);
            bad = 1;
        }
        if (!mf.version[0] || !mf.builtin[0] || !mf.abi[0] ||
            !mf.arch[0] || !mf.sha256[0]) {
            printf ("BAD-LOADABLE-METADATA\t%s\n", name);
            bad = 1;
        }
        if (mf.abi[0] && !bp_abi_matches (mf.abi)) {
            printf ("ABI-MISMATCH\t%s\t%s\n", name, mf.abi);
            bad = 1;
        }
        if (mf.arch[0] && !bp_arch_matches (mf.arch)) {
            printf ("ARCH-MISMATCH\t%s\t%s\n", name, mf.arch);
            bad = 1;
        }
        char state_sha_path[BPKG_PATH_MAX];
        snprintf (state_sha_path, sizeof state_sha_path, "%s%s/%s/sha256",
                  root[0] && strcmp (root, "/") ? root : "",
                  BPKG_INSTALLED_DIR, name);
        bp_buf state_sha = {0};
        if (bp_read_file (state_sha_path, &state_sha) < 0) {
            printf ("MISSING\t%s\n", state_sha_path);
            bad = 1;
        } else {
            char want[65];
            size_t len = state_sha.len;
            while (len > 0 &&
                   (state_sha.data[len - 1] == '\n' ||
                    state_sha.data[len - 1] == '\r' ||
                    state_sha.data[len - 1] == ' ' ||
                    state_sha.data[len - 1] == '\t'))
                len--;
            if (len != 64) {
                printf ("BAD-SHA256-STATE\t%s\n", state_sha_path);
                bad = 1;
            } else {
                memcpy (want, state_sha.data, 64);
                want[64] = 0;
                if (!bp_hex64 (want) ||
                    (mf.sha256[0] && strcasecmp (want, mf.sha256) != 0)) {
                    printf ("BAD-SHA256-STATE\t%s\n", state_sha_path);
                    bad = 1;
                } else {
                    char so_path[BPKG_PATH_MAX];
                    snprintf (so_path, sizeof so_path, "%s%s/%s.so",
                              root[0] && strcmp (root, "/") ? root : "",
                              BPKG_LOADABLES_DIR, name);
                    char got[65];
                    if (bp_sha256_file_hex (so_path, got) < 0) {
                        printf ("MISSING\t%s\n", so_path);
                        bad = 1;
                    } else if (strcasecmp (got, want) != 0) {
                        printf ("SHA256-MISMATCH\t%s\n", so_path);
                        bad = 1;
                    } else {
                        printf ("verify %s\tloadable=ok\n", name);
                    }
                }
            }
        }
        bp_buf_free (&state_sha);
        bp_buf_free (&manifest);
        bp_manifest_free (&mf);
        return bad ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }
    if (manifest_ok && bp_manifest_is_payload (&mf))
    {
        int bad = 0;
        if (strcmp (mf.name, name) != 0) {
            printf ("BAD-PAYLOAD-METADATA\t%s\n", name);
            bad = 1;
        }
        char files_path[BPKG_PATH_MAX];
        snprintf (files_path, sizeof files_path, "%s%s/%s/files",
                  root[0] && strcmp (root, "/") ? root : "",
                  BPKG_INSTALLED_DIR, name);
        bp_buf files = {0};
        if (bp_read_file (files_path, &files) < 0) {
            printf ("MISSING\t%s\n", files_path);
            bad = 1;
        } else {
            size_t off = 0;
            while (off < files.len) {
                size_t end = off;
                while (end < files.len && files.data[end] != '\n') end++;
                if (end > off) {
                    char path[BPKG_PATH_MAX];
                    size_t plen = end - off;
                    if (plen >= sizeof path) {
                        printf ("BAD-PAYLOAD-PATH\t%s\n", name);
                        bad = 1;
                    } else {
                        if (root[0] && strcmp (root, "/") != 0 &&
                            files.data[off] == '/') {
                            snprintf (path, sizeof path, "%s%.*s", root,
                                      (int) plen, files.data + off);
                        } else {
                            memcpy (path, files.data + off, plen);
                            path[plen] = 0;
                        }
                        struct stat st;
                        if (stat (path, &st) < 0) {
                            printf ("MISSING\t%s\n", path);
                            bad = 1;
                        }
                    }
                }
                off = end + 1;
            }
        }
        bp_buf_free (&files);
        if (!bad)
            printf ("verify %s\tpayload=ok\n", name);
        bp_buf_free (&manifest);
        bp_manifest_free (&mf);
        return bad ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }
    bp_buf_free (&manifest);
    bp_manifest_free (&mf);

    if (manifest_ok)
        builtin_error ("%s is not an installed v2 loadable package", name);
    else
        builtin_error ("%s not installed", name);
    return EXECUTION_FAILURE;
}

static int
bp_read_installed_manifest (const char *root, const char *name,
                            bp_manifest *mf)
{
    if (bp_reject_unsafe_name ("installed manifest", name) < 0)
        return EXECUTION_FAILURE;
    char manifest_path[BPKG_PATH_MAX];
    snprintf (manifest_path, sizeof manifest_path, "%s%s/%s/MANIFEST",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_INSTALLED_DIR, name);
    bp_buf manifest = {0};
    bp_manifest_init (mf);
    if (bp_read_file (manifest_path, &manifest) < 0) {
        builtin_error ("%s not installed", name);
        bp_buf_free (&manifest);
        return EXECUTION_FAILURE;
    }
    if (bp_manifest_parse (mf, manifest.data, manifest.len) < 0) {
        builtin_error ("%s: invalid installed MANIFEST", name);
        bp_buf_free (&manifest);
        return EXECUTION_FAILURE;
    }
    bp_buf_free (&manifest);
    return EXECUTION_SUCCESS;
}

static int
bp_verify_installed_loadable (const char *root, const char *name,
                              const bp_manifest *mf,
                              char *so_path, size_t so_path_len)
{
    if (bp_reject_unsafe_name ("loadable verify", name) < 0)
        return EXECUTION_FAILURE;
    if (strcmp (mf->name, name) != 0 ||
        !mf->version[0] || !mf->builtin[0] || !mf->abi[0] ||
        !mf->arch[0] || !mf->sha256[0] ||
        !bp_manifest_effective_is_loadable (mf)) {
        builtin_error ("%s is not an installed v2 loadable package", name);
        return EXECUTION_FAILURE;
    }
    if (!bp_abi_matches (mf->abi)) {
        builtin_error ("loadable ABI mismatch: %s", mf->abi);
        return EXECUTION_FAILURE;
    }
    if (!bp_arch_matches (mf->arch)) {
        builtin_error ("loadable arch mismatch: %s", mf->arch);
        return EXECUTION_FAILURE;
    }

    char state_sha_path[BPKG_PATH_MAX];
    snprintf (state_sha_path, sizeof state_sha_path, "%s%s/%s/sha256",
              root[0] && strcmp (root, "/") ? root : "",
              BPKG_INSTALLED_DIR, name);
    bp_buf state_sha = {0};
    if (bp_read_file (state_sha_path, &state_sha) < 0) {
        builtin_error ("missing loadable sha256 state: %s", state_sha_path);
        bp_buf_free (&state_sha);
        return EXECUTION_FAILURE;
    }
    char want[65];
    size_t len = state_sha.len;
    while (len > 0 &&
           (state_sha.data[len - 1] == '\n' ||
            state_sha.data[len - 1] == '\r' ||
            state_sha.data[len - 1] == ' ' ||
            state_sha.data[len - 1] == '\t'))
        len--;
    if (len != 64) {
        builtin_error ("bad loadable sha256 state: %s", state_sha_path);
        bp_buf_free (&state_sha);
        return EXECUTION_FAILURE;
    }
    memcpy (want, state_sha.data, 64);
    want[64] = 0;
    bp_buf_free (&state_sha);
    if (!bp_hex64 (want) ||
        (mf->sha256[0] && strcasecmp (want, mf->sha256) != 0)) {
        builtin_error ("bad loadable sha256 state: %s", state_sha_path);
        return EXECUTION_FAILURE;
    }

    if (snprintf (so_path, so_path_len, "%s%s/%s.so",
                  root[0] && strcmp (root, "/") ? root : "",
                  BPKG_LOADABLES_DIR, name) >= (int) so_path_len) {
        builtin_error ("loadable path too long: %s", name);
        return EXECUTION_FAILURE;
    }
    char got[65];
    if (bp_sha256_file_hex (so_path, got) < 0) {
        builtin_error ("missing installed loadable: %s", so_path);
        return EXECUTION_FAILURE;
    }
    if (strcasecmp (got, want) != 0) {
        builtin_error ("installed loadable sha256 mismatch: %s", so_path);
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static WORD_LIST *
bp_word_list2 (const char *a, const char *b)
{
    WORD_LIST *wa = make_word_list (make_word (a), NULL);
    WORD_LIST *wb = make_word_list (make_word (b), NULL);
    if (!wa || !wb) {
        if (wa) dispose_words (wa);
        if (wb) dispose_words (wb);
        return NULL;
    }
    wa->next = wb;
    return wa;
}

static WORD_LIST *
bp_word_list3 (const char *a, const char *b, const char *c)
{
    WORD_LIST *wa = make_word_list (make_word (a), NULL);
    WORD_LIST *wb = make_word_list (make_word (b), NULL);
    WORD_LIST *wc = make_word_list (make_word (c), NULL);
    if (!wa || !wb || !wc) {
        if (wa) dispose_words (wa);
        if (wb) dispose_words (wb);
        if (wc) dispose_words (wc);
        return NULL;
    }
    wa->next = wb;
    wb->next = wc;
    return wa;
}

static int
verb_load (WORD_LIST *args)
{
    const char *root = BPKG_INSTALL_ROOT;
    const char *name = NULL;
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--root")) {
            if (!args->next) {
                builtin_error ("load PKGNAME");
                return EX_USAGE;
            }
            args = args->next;
            root = args->word->word;
            if (bp_check_root (root) < 0) return EX_USAGE;
        } else if (!name) {
            name = w;
        } else {
            builtin_error ("load PKGNAME");
            return EX_USAGE;
        }
        args = args->next;
    }
    if (!name) {
        builtin_error ("load PKGNAME");
        return EX_USAGE;
    }

    bp_manifest mf;
    if (bp_read_installed_manifest (root, name, &mf) != EXECUTION_SUCCESS)
        return EXECUTION_FAILURE;

    char so_path[BPKG_PATH_MAX];
    if (bp_verify_installed_loadable (root, name, &mf, so_path,
                                      sizeof so_path) != EXECUTION_SUCCESS) {
        bp_manifest_free (&mf);
        return EXECUTION_FAILURE;
    }

    struct builtin *existing = builtin_address_internal (mf.builtin, 1);
    if (existing && (existing->flags & STATIC_BUILTIN)) {
        builtin_error ("%s: builtin already exists and is static",
                       mf.builtin);
        bp_manifest_free (&mf);
        return EXECUTION_FAILURE;
    }

    WORD_LIST *elist = bp_word_list3 ("-f", so_path, mf.builtin);
    if (!elist) {
        builtin_error ("out of memory");
        bp_manifest_free (&mf);
        return EXECUTION_FAILURE;
    }
    int rc = enable_builtin (elist);
    dispose_words (elist);
    if (rc == EXECUTION_SUCCESS)
        printf ("loaded %s\t%s\t%s\n", name, mf.builtin, so_path);
    bp_manifest_free (&mf);
    return rc == EXECUTION_SUCCESS ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
verb_unload (WORD_LIST *args)
{
    const char *root = BPKG_INSTALL_ROOT;
    const char *name = NULL;
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--root")) {
            if (!args->next) {
                builtin_error ("unload PKGNAME");
                return EX_USAGE;
            }
            args = args->next;
            root = args->word->word;
            if (bp_check_root (root) < 0) return EX_USAGE;
        } else if (!name) {
            name = w;
        } else {
            builtin_error ("unload PKGNAME");
            return EX_USAGE;
        }
        args = args->next;
    }
    if (!name) {
        builtin_error ("unload PKGNAME");
        return EX_USAGE;
    }

    bp_manifest mf;
    if (bp_read_installed_manifest (root, name, &mf) != EXECUTION_SUCCESS)
        return EXECUTION_FAILURE;
    if (!bp_manifest_effective_is_loadable (&mf) || !mf.builtin[0]) {
        builtin_error ("%s is not an installed v2 loadable package", name);
        bp_manifest_free (&mf);
        return EXECUTION_FAILURE;
    }

    struct builtin *existing = builtin_address_internal (mf.builtin, 1);
    if (!existing) {
        builtin_error ("%s: builtin is not currently loaded", mf.builtin);
        bp_manifest_free (&mf);
        return EXECUTION_FAILURE;
    }
    if (existing->flags & STATIC_BUILTIN) {
        builtin_error ("%s: builtin is static, not load-managed",
                       mf.builtin);
        bp_manifest_free (&mf);
        return EXECUTION_FAILURE;
    }

    WORD_LIST *elist = bp_word_list2 ("-d", mf.builtin);
    if (!elist) {
        builtin_error ("out of memory");
        bp_manifest_free (&mf);
        return EXECUTION_FAILURE;
    }
    int rc = enable_builtin (elist);
    dispose_words (elist);
    if (rc == EXECUTION_SUCCESS)
        printf ("unloaded %s\t%s\n", name, mf.builtin);
    bp_manifest_free (&mf);
    return rc == EXECUTION_SUCCESS ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ---- Dispatch ------------------------------------------------------- */

int
pkg_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "pack"))    return verb_pack (args);
    if (!strcmp (cmd, "install")) return verb_install (args);
    if (!strcmp (cmd, "rollback")) return verb_rollback (args);
    if (!strcmp (cmd, "remove"))  return verb_remove (args);
    if (!strcmp (cmd, "list"))    return verb_list (args);
    if (!strcmp (cmd, "info"))    return verb_info (args);
    if (!strcmp (cmd, "search"))  return verb_search (args);
    if (!strcmp (cmd, "update"))  return verb_update (args);
    if (!strcmp (cmd, "fetch"))   return verb_fetch (args);
    if (!strcmp (cmd, "download")) return verb_download (args);
    if (!strcmp (cmd, "upgrade")) return verb_upgrade (args);
    if (!strcmp (cmd, "verify"))  return verb_verify (args);
    if (!strcmp (cmd, "load"))    return verb_load (args);
    if (!strcmp (cmd, "unload"))  return verb_unload (args);
    if (!strcmp (cmd, "delta-make")) return verb_delta_make (args);
    if (!strcmp (cmd, "delta-apply")) return verb_delta_apply (args);
    builtin_error ("unknown verb: %s", cmd);
    return EX_USAGE;
}

char *pkg_doc[] = {
    "Bash loadable module manager for bash-os.",
    "",
    "    pkg pack DIR OUT.pkg [-z]",
    "    pkg delta-make OLD NEW PATCH",
    "    pkg delta-apply OLD PATCH OUT",
    "    pkg install PKGFILE | PKGNAME [--root R] [--sources FILE]",
    "                    [--repo NAME] [--arch ARCH] [-S|-A] [--force]",
    "                    [--legacy-rootfs]",
    "    pkg rollback PKGNAME|txn-ID [--root R]",
    "    pkg remove  PKGNAME [--root R] [--legacy-rootfs]",
    "    pkg list    [--root R]",
    "    pkg info    PKGNAME|PKGFILE [--root R]",
    "    pkg search  QUERY   [--root R] [--repo NAME] [--arch ARCH]",
    "    pkg update  [--root R] [--sources FILE] [--arch ARCH]",
    "                     [--remote] [--remote-insecure|-k] [--cacert PEM]",
    "    pkg fetch   [--root R] [--sources FILE] [--arch ARCH]",
    "                     [--insecure] [--timeout SEC]",
    "    pkg download PKGNAME [--root R] [--sources FILE] [--repo NAME]",
    "                     [--arch ARCH]",
    "    pkg upgrade PACKAGE|PKGNAME [--root R] [--sources FILE]",
    "                     [--repo NAME] [--arch ARCH] [--no-delta] [-S|-A]",
    "    pkg verify  PKGNAME|PKGFILE [--root R]",
    "    pkg load    PKGNAME [--root R]",
    "    pkg unload  PKGNAME",
    "",
    "Package format: ustar tar archive (optionally xz-compressed).",
    "  v2 loadable package:",
    "    MANIFEST       — type: loadable plus name/version/builtin/abi/arch/sha256",
    "                     optional deps list for loadable packages",
    "    loadable/N.so  — exactly one ELF Bash loadable object; installed",
    "                     under /usr/lib/bash-os/loadables/ beneath",
    "                     the selected --root prefix.",
    "    Multiple .so files, non-loadable payload entries, digest",
    "    mismatches, and ABI/arch mismatches are refused.",
    "",
    "  payload package:",
    "  MANIFEST       — type: payload plus name/version/deps/arch/description",
    "                   optional `sha256: /abs/path HEX64` lines (one",
    "                   per file under files/); when present, install",
    "                   refuses any payload that does not match.",
    "  files/         — payload mirroring rootfs layout",
    "  hooks/         — optional pre/post-install + pre/post-remove",
    "  Declared type: payload packages use the payload backend directly;",
    "  undeclared legacy payloads still require --legacy-rootfs or",
    "  BASHPKG_ALLOW_LEGACY_ROOTFS=1.",
    "",
    "v2 loadable state tree (per --root prefix):",
    "  /var/lib/pkg/installed/<name>/MANIFEST",
    "  /var/lib/pkg/installed/<name>/sha256",
    "  /var/lib/pkg/cache/<name>-<ver>.pkg",
    "  /var/lib/pkg/repos/<repo>/INDEX",
    "  /var/lib/pkg/repos/<repo>/<arch>/INDEX",
    "  /etc/pkg/sources.list",
    "Legacy rootfs compatibility state additionally records:",
    "  /var/lib/pkg/installed/<name>/files",
    "",
    "Trust: installs require a sibling <PKGFILE>.sig verified by",
    "bashsignify by default; -S spells that production policy explicitly,",
    "and -A allows unsigned bootstrap/development installs.",
    "Legacy rootfs packages are additionally disabled by default and",
    "require --legacy-rootfs or BASHPKG_ALLOW_LEGACY_ROOTFS=1.",
    "load verifies installed v2 loadable state and SHA-256 before",
    "delegating to Bash's native `enable -f PATH BUILTIN`.",
    "unload verifies installed v2 loadable state and delegates to",
    "Bash's native `enable -d BUILTIN` dlclose path.",
    "",
    "update local-fetch: sources.list entries of the form",
    "  file:///abs/path/to/INDEX     copy INDEX in place",
    "  file:///abs/path/to/REPO_DIR  copy REPO_DIR/INDEX",
    "  /abs/path/to/...              same lookup, no scheme",
    "are fetched in-process. Directory repos may also expose",
    "<arch>/INDEX plus noarch/INDEX or any/INDEX; update mirrors the",
    "selected arch (default: uname -m) plus universal dirs. Other schemes",
    "are rejected by default. With --remote, https:// sources (and http://",
    "only under --remote-insecure) are materialized through curl before",
    "the same INDEX.sig gate; sources.list may prefix a line with `remote`",
    "or `remote-insecure` for persistent opt-in. A sibling <INDEX>.sig is verified via bashsignify when",
    "present; verification failure refuses to copy the source INDEX",
    "content; the destination remains absent or keeps its previous snapshot.",
    "",
    "fetch also remote-materializes http:// and https:// sources into the same",
    "local mirror tree consumed by update/download/upgrade. It delegates",
    "network I/O to curl, fetches signed per-arch INDEX files, promotes",
    "them through the same INDEX.sig bashsignify gate as update, and stages",
    "referenced artifacts only after SHA-256 package checks or delta",
    "from/to header checks. With a cached package whose hash matches",
    "delta_from, fetch requests the delta sidecar and signatures; otherwise",
    "it requests the full .pkg blob. --insecure forwards curl -k",
    "and is for test or explicitly degraded TLS policy only.",
    "",
    "download local-fetch reads configured local repo INDEX files,",
    "checks indexed package SHA-256, copies the best matching package",
    "into cache, and copies the indexed sig= sidecar to the cached",
    "package .sig for the install-time signature gate. New H05 lines",
    "use: pkg-loadable-v1 name=N version=V builtin=B abi=A",
    "arch=ARCH sha256=HEX package=N-V.pkg sig=N-V.pkg.sig",
    "deps=-. Bare .pkg INDEX lines are ignored by H05 download/search.",
    "Optional delta fields: delta=N-old-to-new.pkg.delta",
    "delta_from=HEX64 delta_to=HEX64 [delta_sig=REF]. upgrade PKGNAME",
    "uses a delta only when the cached previous .pkg hash matches",
    "delta_from; the reconstructed blob must match sha256= and then",
    "passes through the normal signed install path.",
    "",
    "Search: QUERY defaults to a substring match across installed +",
    "cache + every repo INDEX. If QUERY contains a shell wildcard",
    "(* ? [), it is treated as a glob (fnmatch) against the whole",
    "name/line. --repo NAME narrows scope to a single repo's INDEX",
    "(skips the local installed + cache views). --arch selects the repo",
    "arch directory for search/download/update/upgrade; install still",
    "enforces the package MANIFEST arch against the running machine.",
    "",
    "Legacy rootfs hook env (only with --legacy-rootfs packages):",
    "  BASHPKG_NAME    — package name from MANIFEST",
    "  BASHPKG_VERSION — package version (empty if MANIFEST omits)",
    "  BASHPKG_PREFIX  — install root (`/` for system installs;",
    "                    --root DIR sandboxes hooks into DIR)",
    "  BASHPKG_ROOT    — legacy alias for BASHPKG_PREFIX",
    "Hooks run as the calling user (no setuid). A non-zero hook exit",
    "aborts install or remove (post-remove records the error but lets",
    "state cleanup proceed so a partial removal doesn't strand state).",
    (char *) NULL
};

struct builtin pkg_struct = {
    "pkg",
    pkg_builtin,
    BUILTIN_ENABLED,
    pkg_doc,
    "pkg pack|delta-make|delta-apply|install|remove|list|info|search|update|fetch|download|upgrade|verify|load|unload ...",
    0
};
