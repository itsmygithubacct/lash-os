/* SPDX-License-Identifier: MIT */
/* cksum.c — POSIX cksum(1) as a bash builtin.
 *
 * Phase S of bash-os POSIX gap-fillers.
 *
 *   cksum [FILE...]
 *       Print "<crc> <bytes> <name>" lines, one per FILE. With no
 *       FILE or "-", reads stdin (and prints "<crc> <bytes>" with no
 *       name).
 *   cksum -a md5|sha1|sha224|sha256|sha384|sha512 [FILE...]
 *       Match GNU cksum digest modes for common algorithms, defaulting
 *       to tagged output: "SHA256 (FILE) = HEX". --untagged emits
 *       "HEX  FILE". With stdin, FILE is "-".
 *
 * Algorithm: POSIX-defined CRC-32 (the "Ethernet" polynomial 0x04C11DB7
 * as a non-reflected CRC, with the file length appended as input bytes
 * before the final XOR-with-zero, per POSIX.1-2024 cksum spec). NOT
 * the same as gzip's CRC-32 (which is reflected). Digest modes use the
 * same vendored mbedTLS primitives as crypto.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "_mbedtls_md5.h"
#include "_mbedtls_sha1.h"
#include "_mbedtls_sha256.h"
#include "_mbedtls_sha512.h"
#include "loadables.h"

/* POSIX cksum CRC-32 table (non-reflected, polynomial 0x04C11DB7). */
static uint32_t bck_table[256];
static int bck_table_init = 0;

static void
bck_init_table (void)
{
    if (bck_table_init) return;
    for (int i = 0; i < 256; i++) {
        uint32_t c = (uint32_t) i << 24;
        for (int j = 0; j < 8; j++) {
            c = (c & 0x80000000U) ? (c << 1) ^ 0x04C11DB7U : (c << 1);
        }
        bck_table[i] = c;
    }
    bck_table_init = 1;
}

/* Stream FD into the running CRC + byte count. POSIX algorithm. */
static int
bck_compute_fd (int fd, uint32_t *crc_out, uint64_t *bytes_out)
{
    bck_init_table ();
    uint32_t crc = 0;
    uint64_t bytes = 0;
    unsigned char buf[8192];
    ssize_t n = 0;
    while ((n = read (fd, buf, sizeof buf)) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            crc = (crc << 8) ^ bck_table[((crc >> 24) ^ buf[i]) & 0xFF];
        }
        bytes += (uint64_t) n;
    }
    if (n < 0) return -1;
    /* POSIX: append length octets in MSB-first order, dropping leading
       zero bytes, then final XOR with 0xFFFFFFFF. */
    uint64_t len = bytes;
    while (len > 0) {
        crc = (crc << 8) ^ bck_table[((crc >> 24) ^ (len & 0xFF)) & 0xFF];
        len >>= 8;
    }
    crc = ~crc;
    *crc_out = crc;
    *bytes_out = bytes;
    return 0;
}

enum bck_alg {
    BCK_ALG_CRC = 0,
    BCK_ALG_MD5,
    BCK_ALG_SHA1,
    BCK_ALG_SHA224,
    BCK_ALG_SHA256,
    BCK_ALG_SHA384,
    BCK_ALG_SHA512
};

static enum bck_alg
bck_parse_alg (const char *alg)
{
    if (!strcmp (alg, "crc")) return BCK_ALG_CRC;
    if (!strcmp (alg, "md5")) return BCK_ALG_MD5;
    if (!strcmp (alg, "sha1")) return BCK_ALG_SHA1;
    if (!strcmp (alg, "sha224")) return BCK_ALG_SHA224;
    if (!strcmp (alg, "sha256")) return BCK_ALG_SHA256;
    if (!strcmp (alg, "sha384")) return BCK_ALG_SHA384;
    if (!strcmp (alg, "sha512")) return BCK_ALG_SHA512;
    return (enum bck_alg) -1;
}

static const char *
bck_alg_tag (enum bck_alg alg)
{
    switch (alg) {
    case BCK_ALG_MD5: return "MD5";
    case BCK_ALG_SHA1: return "SHA1";
    case BCK_ALG_SHA224: return "SHA224";
    case BCK_ALG_SHA256: return "SHA256";
    case BCK_ALG_SHA384: return "SHA384";
    case BCK_ALG_SHA512: return "SHA512";
    case BCK_ALG_CRC:
    default: return "CRC";
    }
}

static size_t
bck_alg_digest_len (enum bck_alg alg)
{
    switch (alg) {
    case BCK_ALG_MD5: return 16;
    case BCK_ALG_SHA1: return 20;
    case BCK_ALG_SHA224: return 28;
    case BCK_ALG_SHA256: return 32;
    case BCK_ALG_SHA384: return 48;
    case BCK_ALG_SHA512: return 64;
    case BCK_ALG_CRC:
    default: return 0;
    }
}

static void
bck_hex (const unsigned char *digest, size_t len, char *out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hx[(digest[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hx[digest[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int
bck_compute_digest_fd (int fd, enum bck_alg alg, unsigned char digest[64])
{
    unsigned char buf[8192];
    ssize_t n = 0;
    int rc = 0;

    switch (alg) {
    case BCK_ALG_MD5: {
        mbedtls_md5_context ctx;
        mbedtls_md5_init (&ctx);
        rc = mbedtls_md5_starts (&ctx);
        while (rc == 0 && (n = read (fd, buf, sizeof buf)) > 0)
            rc = mbedtls_md5_update (&ctx, buf, (size_t) n);
        if (rc == 0 && n < 0) rc = -1;
        if (rc == 0) rc = mbedtls_md5_finish (&ctx, digest);
        mbedtls_md5_free (&ctx);
        return rc;
    }
    case BCK_ALG_SHA1: {
        mbedtls_sha1_context ctx;
        mbedtls_sha1_init (&ctx);
        rc = mbedtls_sha1_starts (&ctx);
        while (rc == 0 && (n = read (fd, buf, sizeof buf)) > 0)
            rc = mbedtls_sha1_update (&ctx, buf, (size_t) n);
        if (rc == 0 && n < 0) rc = -1;
        if (rc == 0) rc = mbedtls_sha1_finish (&ctx, digest);
        mbedtls_sha1_free (&ctx);
        return rc;
    }
    case BCK_ALG_SHA224:
    case BCK_ALG_SHA256: {
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init (&ctx);
        rc = mbedtls_sha256_starts (&ctx, alg == BCK_ALG_SHA224);
        while (rc == 0 && (n = read (fd, buf, sizeof buf)) > 0)
            rc = mbedtls_sha256_update (&ctx, buf, (size_t) n);
        if (rc == 0 && n < 0) rc = -1;
        if (rc == 0) rc = mbedtls_sha256_finish (&ctx, digest);
        mbedtls_sha256_free (&ctx);
        return rc;
    }
    case BCK_ALG_SHA384:
    case BCK_ALG_SHA512: {
        mbedtls_sha512_context ctx;
        mbedtls_sha512_init (&ctx);
        rc = mbedtls_sha512_starts (&ctx, alg == BCK_ALG_SHA384);
        while (rc == 0 && (n = read (fd, buf, sizeof buf)) > 0)
            rc = mbedtls_sha512_update (&ctx, buf, (size_t) n);
        if (rc == 0 && n < 0) rc = -1;
        if (rc == 0) rc = mbedtls_sha512_finish (&ctx, digest);
        mbedtls_sha512_free (&ctx);
        return rc;
    }
    case BCK_ALG_CRC:
    default:
        return -1;
    }
}

static void
bck_print_digest (enum bck_alg alg, const char *name,
                  const unsigned char digest[64], int untagged, int delim)
{
    char hex[129];
    size_t dlen = bck_alg_digest_len (alg);
    bck_hex (digest, dlen, hex);
    if (untagged)
        printf ("%s  %s%c", hex, name, delim);
    else
        printf ("%s (%s) = %s%c", bck_alg_tag (alg), name, hex, delim);
}

int
cksum_builtin (WORD_LIST *list)
{
    int rc = EXECUTION_SUCCESS;
    int delim = '\n';   /* '\0' under -z/--zero */
    enum bck_alg selected_alg = BCK_ALG_CRC;
    int untagged = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { builtin_usage (); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "--version")) {
            puts ("cksum 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-z") || !strcmp (w, "--zero")) {
            delim = '\0';
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--tag")) {
            untagged = 0;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--untagged")) {
            untagged = 1;
            list = list->next;
            continue;
        }
        /* -a ALG / -aALG / --algorithm ALG / --algorithm=ALG. */
        const char *alg_name = NULL;
        if (!strcmp (w, "-a") || !strcmp (w, "--algorithm")) {
            if (!list->next) {
                builtin_error ("%s needs an algorithm", w);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            alg_name = list->word->word;
        } else if (!strncmp (w, "-a", 2) && w[2]) {
            alg_name = w + 2;
        } else if (!strncmp (w, "--algorithm=", 12)) {
            alg_name = w + 12;
        }
        if (alg_name) {
            enum bck_alg parsed = bck_parse_alg (alg_name);
            if ((int) parsed < 0) {
                builtin_error ("unsupported algorithm: %s "
                               "(supported: crc, md5, sha1, sha224, sha256, sha384, sha512)", alg_name);
                builtin_usage ();
                return EX_USAGE;
            }
            selected_alg = parsed;
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }
    if (!list) {
        if (selected_alg != BCK_ALG_CRC) {
            unsigned char digest[64];
            if (bck_compute_digest_fd (STDIN_FILENO, selected_alg, digest) < 0) {
                builtin_error ("read stdin: %s", strerror (errno));
                return EXECUTION_FAILURE;
            }
            bck_print_digest (selected_alg, "-", digest, untagged, delim);
            return EXECUTION_SUCCESS;
        }
        uint32_t crc;
        uint64_t bytes;
        if (bck_compute_fd (STDIN_FILENO, &crc, &bytes) < 0) {
            builtin_error ("read stdin: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        printf ("%" PRIu32 " %" PRIu64 "%c", crc, bytes, delim);
        return EXECUTION_SUCCESS;
    }
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *path = p->word->word;
        int fd;
        /* Options were consumed above; a leading '-' here only reaches us
           after '--', so treat it as a (dash-leading) filename. */
        int from_stdin = (strcmp (path, "-") == 0);
        if (from_stdin) {
            fd = STDIN_FILENO;
        } else {
            fd = open (path, O_RDONLY);
            if (fd < 0) {
                builtin_error ("%s: %s", path, strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
        }
        if (selected_alg != BCK_ALG_CRC) {
            unsigned char digest[64];
            if (bck_compute_digest_fd (fd, selected_alg, digest) < 0) {
                builtin_error ("read %s: %s", path, strerror (errno));
                if (!from_stdin) close (fd);
                rc = EXECUTION_FAILURE;
                continue;
            }
            bck_print_digest (selected_alg, from_stdin ? "-" : path, digest, untagged, delim);
            if (!from_stdin) close (fd);
            continue;
        }
        uint32_t crc;
        uint64_t bytes;
        if (bck_compute_fd (fd, &crc, &bytes) < 0) {
            builtin_error ("read %s: %s", path, strerror (errno));
            if (!from_stdin) close (fd);
            rc = EXECUTION_FAILURE;
            continue;
        }
        if (from_stdin)
            printf ("%" PRIu32 " %" PRIu64 "%c", crc, bytes, delim);
        else
            printf ("%" PRIu32 " %" PRIu64 " %s%c", crc, bytes, path, delim);
        if (!from_stdin) close (fd);
    }
    return rc;
}

char *cksum_doc[] = {
    "POSIX CRC-32 + byte-count, plus common GNU cksum digest modes.",
    "",
    "    cksum [-a crc|md5|sha1|sha224|sha256|sha384|sha512] [-z] [--tag|--untagged] [FILE...]",
    "    cksum --help | --version",
    "        CRC mode prints '<crc> <bytes> <FILE>'. Digest modes",
    "        default to tagged output, e.g. 'SHA256 (FILE) = HEX'.",
    "        With no FILE or '-', read stdin. Digest stdin is named '-'.",
    "        Use -- before dash-leading filenames.",
    "",
    "    -a, --algorithm=ALG   crc, md5, sha1, sha224, sha256, sha384, or sha512",
    "    -z, --zero            end each output line with NUL, not newline",
    "    --tag / --untagged    tagged or reversed digest output",
    "",
    "Algorithm is POSIX-mandated CRC-32 (polynomial 0x04C11DB7,",
    "non-reflected, with length-byte injection + final XOR).",
    "Unsupported: --check, --raw, --base64, --length, sysv, bsd, crc32b, blake2b, sm3.",
    (char *)NULL
};

struct builtin cksum_struct = {
    "cksum",
    cksum_builtin,
    BUILTIN_ENABLED,
    cksum_doc,
    "cksum [FILE...]",
    0
};
