/* SPDX-License-Identifier: MIT */
/* pack.c — git packfile commands.
 *
 * The packfile format lives in _git/pack.c, shared with the other git
 * builtins; this file is the command surface over it. Loose objects are in
 * _git/odb.c, which obj exposes.
 *
 * Verbs:
 *   pack list-objects IDX
 *       Enumerate every SHA in the .idx file (one per line).
 *   pack cat PACK IDX SHA
 *       Decompress + delta-resolve the object at SHA in PACK,
 *       emit raw content (no header) on stdout.
 *   pack list-packs REPO
 *       List every <repo>/.git/objects/pack/pack-*.idx file.
 *   pack unpack PACK REPO
 *       Unpack a fetched .pack into loose objects under REPO/.git/objects/.
 *   pack create OUTFILE [--idx IDXFILE] [-r REPO] SHA [SHA...]
 *       Inverse of unpack: build a pack v2 file from a list of
 *       loose-object SHAs. With --idx, also writes the paired v2 .idx.
 *       Always emits full bases (no delta encoding); the receive-pack
 *       server can still apply pack-deltas on its end.
 *   pack verify-idx IDX [PACK]
 *       Validate a v2 .idx, and with PACK its CRC-32 table.
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
#include <strings.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>
#include <dirent.h>

#include "loadables.h"

#include "_git_pack.h"
#include "_git_odb.h"

/* Static builds retain the verified-pack snapshot until replacement or
   process exit. */
void
pack_builtin_unload (char *name)
{
    (void) name;
    bgit_pack_cache_release ();
}

/* --- list-objects: walk every SHA in idx ------------------------------- */
static int
bp_list_objects_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("list-objects: IDX path required"); return EX_USAGE; }
    const char *idx_path = args->word->word;
    size_t ilen;
    unsigned char *idx = bgit_pack_slurp (idx_path, &ilen);
    if (!idx) { builtin_error ("read %s: %s", idx_path, strerror (errno)); return EXECUTION_FAILURE; }
    /* v2 magic */
    if (ilen < 8 || memcmp (idx, "\377tOc", 4) != 0) {
        free (idx);
        builtin_error ("not a v2 idx (or unsupported v1)");
        return EXECUTION_FAILURE;
    }
    uint32_t ver = bgit_pack_be32 (idx + 4);
    if (ver != 2) {
        free (idx);
        builtin_error ("unsupported idx version %u", ver);
        return EXECUTION_FAILURE;
    }
    /* Fanout (256×4 = 1024 bytes at offset 8) must fit. Without this
     * gate, the be32 at `idx + 1028` below reads OOB on any idx
     * with 8 ≤ ilen < 1032. */
    if (ilen < 1032) {
        free (idx);
        builtin_error ("idx truncated (fanout)");
        return EXECUTION_FAILURE;
    }
    /* fanout @ +8, 256×4 = 1024 bytes; total objects = fanout[255] */
    uint32_t n = bgit_pack_be32 (idx + 8 + 255 * 4);
    /* SHAs start at offset 8 + 1024 = 1032. Promote the multiplication to
     * size_t with an overflow guard: in uint32_t arithmetic, n above
     * ~2.1e8 (4 GiB / 20) wraps and the truncation check would pass
     * incorrectly, so the indexed read at `idx + 1032 + i*20` would walk
     * past the buffer. */
    size_t sha_bytes = (size_t) n * 20;
    if (n != 0 && sha_bytes / 20 != (size_t) n) {
        free (idx);
        builtin_error ("idx object count %u overflows size", n);
        return EXECUTION_FAILURE;
    }
    if (sha_bytes > SIZE_MAX - 1032) {
        free (idx);
        builtin_error ("idx object count %u overflows size", n);
        return EXECUTION_FAILURE;
    }
    if (ilen < 1032 + sha_bytes) {
        free (idx);
        builtin_error ("idx truncated");
        return EXECUTION_FAILURE;
    }
    char hex[41];
    for (uint32_t i = 0; i < n; i++) {
        bgit_sha_to_hex (idx + 1032 + (size_t) i * 20, hex);
        puts (hex);
    }
    free (idx);
    return EXECUTION_SUCCESS;
}

/* --- cat verb ---------------------------------------------------------- */
static int
bp_cat_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next) {
        builtin_error ("cat: PACK IDX SHA [-r REPO]"); return EX_USAGE;
    }
    const char *pack_path = args->word->word;
    const char *idx_path  = args->next->word->word;
    const char *sha_hex   = args->next->next->word->word;
    const char *repo = NULL;
    for (WORD_LIST *p = args->next->next->next; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-r") == 0 && p->next) { repo = p->next->word->word; p = p->next; }
        else { builtin_error ("cat: unexpected '%s'", w); return EX_USAGE; }
    }

    unsigned char sha[20];
    if (bgit_hex_to_sha (sha_hex, sha) < 0) { builtin_error ("bad sha"); return EX_USAGE; }
    size_t ilen, plen;
    unsigned char *idx = bgit_pack_slurp (idx_path, &ilen);
    if (!idx) { builtin_error ("read %s: %s", idx_path, strerror (errno)); return EXECUTION_FAILURE; }
    unsigned char *pack = bgit_pack_slurp (pack_path, &plen);
    if (!pack) { free (idx); builtin_error ("read %s: %s", pack_path, strerror (errno)); return EXECUTION_FAILURE; }
    if (plen < 32 || memcmp (pack, "PACK", 4) != 0) {
        free (idx); free (pack);
        builtin_error ("cat: not a packfile");
        return EXECUTION_FAILURE;
    }
    uint32_t pack_ver = bgit_pack_be32 (pack + 4);
    if (pack_ver != 2 && pack_ver != 3) {
        free (idx); free (pack);
        builtin_error ("cat: unsupported pack version %u", pack_ver);
        return EXECUTION_FAILURE;
    }
    if (plen < 40) {
        free (idx); free (pack);
        builtin_error ("cat: too short (no trailer)");
        return EXECUTION_FAILURE;
    }
    int checksum_cached = bgit_pack_checksum_cached (pack, plen);
    if (!checksum_cached) {
        unsigned char pack_sha[20];
        if (bgit_sha1 (pack, plen - 20, pack_sha) < 0) {
            free (idx); free (pack);
            builtin_error ("cat: SHA-1 init failed");
            return EXECUTION_FAILURE;
        }
        if (memcmp (pack_sha, pack + plen - 20, 20) != 0) {
            free (idx); free (pack);
            builtin_error ("cat: packfile SHA-1 mismatch (corrupt)");
            return EXECUTION_FAILURE;
        }
    }
    if (bgit_pack_verify_idx (idx, ilen, pack + plen - 20) < 0) {
        free (idx); free (pack);
        return EXECUTION_FAILURE;
    }

    uint64_t off = bgit_pack_lookup_offset (idx, ilen, sha);
    if (off == (uint64_t) -1) {
        free (idx); free (pack);
        builtin_error ("cat: %s not in idx", sha_hex);
        return EXECUTION_FAILURE;
    }
    int type;
    unsigned char *content;
    size_t clen;
    if (bgit_pack_read_object_at (pack, plen, idx, ilen, repo, off, &type,
                                  &content, &clen, 0) < 0) {
        free (idx); free (pack);
        builtin_error ("cat: read failed for %s", sha_hex);
        return EXECUTION_FAILURE;
    }
    if (!checksum_cached) bgit_pack_remember_verified (pack, plen);
    fwrite (content, 1, clen, stdout);
    free (content); free (idx); free (pack);
    (void) type;
    return EXECUTION_SUCCESS;
}

/* --- list-packs verb --------------------------------------------------- */
static int
bp_list_packs_cmd (WORD_LIST *args)
{
    const char *repo = args ? args->word->word : ".";
    char dir[4096];
    snprintf (dir, sizeof dir, "%s/.git/objects/pack", repo);
    DIR *d = opendir (dir);
    if (!d) { builtin_error ("opendir %s: %s", dir, strerror (errno)); return EXECUTION_FAILURE; }
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        const char *n = de->d_name;
        size_t l = strlen (n);
        if (l > 4 && memcmp (n + l - 4, ".idx", 4) == 0) {
            printf ("%s/%s\n", dir, n);
        }
    }
    closedir (d);
    return EXECUTION_SUCCESS;
}

static int
bp_unpack_cmd (WORD_LIST *args)
{
    if (!args || !args->next) {
        builtin_error ("unpack: PACK REPO");
        return EX_USAGE;
    }
    const char *pack_path = args->word->word;
    const char *repo = args->next->word->word;
    size_t plen;
    unsigned char *pack = bgit_pack_slurp (pack_path, &plen);
    if (!pack) { builtin_error ("read %s: %s", pack_path, strerror (errno)); return EXECUTION_FAILURE; }
    if (plen < 32 || memcmp (pack, "PACK", 4) != 0) {
        free (pack);
        builtin_error ("unpack: not a packfile");
        return EXECUTION_FAILURE;
    }
    uint32_t ver = bgit_pack_be32 (pack + 4);
    uint32_t count = bgit_pack_be32 (pack + 8);
    if (ver != 2 && ver != 3) {
        free (pack);
        builtin_error ("unpack: unsupported pack version %u", ver);
        return EXECUTION_FAILURE;
    }

    /* Validate pack SHA-1 trailer: last 20 bytes = sha1 of all preceding
       bytes. A collision report does not change the comparison. */
    if (plen < 40) {
        free (pack);
        builtin_error ("unpack: too short (no trailer)");
        return EXECUTION_FAILURE;
    }
    {
        unsigned char computed[20];
        (void) bgit_sha1 (pack, plen - 20, computed);
        if (memcmp (computed, pack + plen - 20, 20) != 0) {
            free (pack);
            builtin_error ("unpack: packfile SHA-1 mismatch (corrupt)");
            return EXECUTION_FAILURE;
        }
    }

    size_t off = 12;
    uint32_t written = 0;
    for (uint32_t i = 0; i < count; i++) {
        size_t obj_off = off;
        int wire_type;
        uint64_t expected, data_off;
        if (bgit_pack_read_obj_header (pack, plen, obj_off, &wire_type,
                                       &expected, &data_off) < 0) {
            free (pack);
            builtin_error ("unpack: bad object header");
            return EXECUTION_FAILURE;
        }
        size_t zoff = (size_t) data_off;
        if (wire_type == BGIT_PACK_OFS_DELTA) {
            if (zoff >= plen) { free (pack); return EXECUTION_FAILURE; }
            unsigned char b = pack[zoff++];
            int iters = 0;
            while (b & 0x80) {
                if (zoff >= plen) { free (pack); return EXECUTION_FAILURE; }
                if (iters >= 9) { free (pack); return EXECUTION_FAILURE; }
                b = pack[zoff++];
                iters++;
            }
        } else if (wire_type == BGIT_PACK_REF_DELTA) {
            /* `zoff + 20 > plen` is overflow-unsafe if zoff is close
             * to SIZE_MAX (a malformed object header could push it
             * there). Rewrite as `20 > plen - zoff` after the
             * `zoff <= plen` invariant from the OFS arm just above. */
            if (zoff > plen || 20 > plen - zoff) { free (pack); return EXECUTION_FAILURE; }
            zoff += 20;
        }

        unsigned char *infl = NULL;
        size_t infl_len = 0, used = 0;
        if (bgit_pack_inflate (pack + zoff, plen - zoff, (size_t) expected,
                               &infl, &infl_len, &used) < 0) {
            free (pack);
            builtin_error ("unpack: inflate failed");
            return EXECUTION_FAILURE;
        }
        free (infl);
        off = zoff + used;

        int type;
        unsigned char *content = NULL;
        size_t clen = 0;
        if (bgit_pack_read_object_at (pack, plen, NULL, 0, repo, obj_off, &type,
                                      &content, &clen, 0) < 0) {
            free (pack);
            builtin_error ("unpack: delta resolution failed at object %u", i + 1);
            return EXECUTION_FAILURE;
        }
        const char *tn = bgit_pack_type_name (type);
        char hdr[64];
        int hn = snprintf (hdr, sizeof hdr, "%s %zu", tn, clen);
        if (hn <= 0 || (size_t) hn + 1 >= sizeof hdr) {
            free (content); free (pack); return EXECUTION_FAILURE;
        }
        size_t prelen = (size_t) hn + 1 + clen;
        unsigned char *pre = malloc (prelen);
        if (!pre) { free (content); free (pack); return EXECUTION_FAILURE; }
        memcpy (pre, hdr, (size_t) hn);
        pre[hn] = '\0';
        memcpy (pre + hn + 1, content, clen);
        free (content);

        unsigned char digest[20];
        if (bgit_sha1 (pre, prelen, digest) < 0) {
            free (pre); free (pack);
            builtin_error ("unpack: SHA-1 collision detected");
            return EXECUTION_FAILURE;
        }
        char hex[41];
        bgit_sha_to_hex (digest, hex);
        unsigned char *deflated = NULL;
        size_t dlen = 0;
        if (bgit_deflate (pre, prelen, &deflated, &dlen) < 0) {
            free (pre); free (pack); return EXECUTION_FAILURE;
        }
        free (pre);
        if (bgit_pack_write_loose (repo, hex, deflated, dlen) < 0) {
            free (deflated); free (pack); return EXECUTION_FAILURE;
        }
        free (deflated);
        written++;
    }
    free (pack);
    printf ("%u\n", written);
    return EXECUTION_SUCCESS;
}

/* --- create: build a pack v2 from a list of loose-object SHAs ---------- */
static int
bp_create_cmd (WORD_LIST *args)
{
    if (!args) {
        builtin_error ("create: OUTFILE [--idx IDXFILE] [-r REPO] SHA [SHA...]");
        return EX_USAGE;
    }
    const char *outfile = args->word->word;
    const char *idx_path = NULL;
    const char *repo = ".";
    const char **shas = NULL;
    size_t n_shas = 0, sha_cap = 0;

    for (WORD_LIST *p = args->next; p; p = p->next) {
        if (!strcmp (p->word->word, "--idx")) {
            if (!p->next) {
                builtin_error ("create: --idx requires IDXFILE");
                free (shas);
                return EX_USAGE;
            }
            p = p->next; idx_path = p->word->word; continue;
        }
        if (!strcmp (p->word->word, "-r") && p->next) {
            p = p->next; repo = p->word->word; continue;
        }
        if (strlen (p->word->word) != 40) {
            builtin_error ("create: invalid SHA '%s' (expected 40 hex chars)", p->word->word);
            free (shas);
            return EX_USAGE;
        }
        if (n_shas == sha_cap) {
            sha_cap = sha_cap ? sha_cap * 2 : 8;
            const char **ns = realloc (shas, sha_cap * sizeof *shas);
            if (!ns) { free (shas); return EXECUTION_FAILURE; }
            shas = ns;
        }
        shas[n_shas++] = p->word->word;
    }
    if (n_shas == 0) {
        builtin_error ("create: no SHAs given");
        free (shas);
        return EX_USAGE;
    }
    if (n_shas > UINT32_MAX) {
        builtin_error ("create: too many objects for pack v2");
        free (shas);
        return EXECUTION_FAILURE;
    }

    struct bgit_pack_idx_entry *ents = NULL;
    if (idx_path) {
        ents = calloc (n_shas, sizeof *ents);
        if (!ents) { free (shas); return EXECUTION_FAILURE; }
    }

    /* Build pack image in memory: header + objects. SHA-1 over the whole
     * thing goes at the end, then write the file atomically via a tmp+rename. */
    unsigned char *body = NULL;
    size_t body_len = 0, body_cap = 0;

    /* Header: "PACK" + be32(version=2) + be32(count). */
    if (bgit_pack_buf_append (&body, &body_len, &body_cap, "PACK", 4) < 0) goto oom;
    unsigned char be4[4] = { 0, 0, 0, 2 };
    if (bgit_pack_buf_append (&body, &body_len, &body_cap, be4, 4) < 0) goto oom;
    be4[0] = (unsigned char) ((n_shas >> 24) & 0xff);
    be4[1] = (unsigned char) ((n_shas >> 16) & 0xff);
    be4[2] = (unsigned char) ((n_shas >>  8) & 0xff);
    be4[3] = (unsigned char) ( n_shas        & 0xff);
    if (bgit_pack_buf_append (&body, &body_len, &body_cap, be4, 4) < 0) goto oom;

    for (size_t i = 0; i < n_shas; i++) {
        int type;
        unsigned char *content = NULL;
        size_t clen = 0;
        if (ents && bgit_hex_to_sha (shas[i], ents[i].sha) < 0) {
            builtin_error ("create: invalid SHA '%s' (expected 40 hex chars)", shas[i]);
            free (body); free (shas); free (ents);
            return EX_USAGE;
        }
        if (bgit_pack_read_loose (repo, shas[i], &type, &content, &clen) < 0) {
            builtin_error ("create: cannot read loose object %s in %s", shas[i], repo);
            free (body); free (shas); free (ents);
            return EXECUTION_FAILURE;
        }
        uint64_t obj_off = (uint64_t) body_len;
        unsigned char ohdr[16];
        size_t ohdr_len = 0;
        bgit_pack_encode_obj_header (type, clen, ohdr, &ohdr_len);
        if (bgit_pack_buf_append (&body, &body_len, &body_cap, ohdr, ohdr_len) < 0) {
            free (content); goto oom;
        }
        unsigned char *zbuf = NULL;
        size_t zlen = 0;
        if (bgit_deflate (content, clen, &zbuf, &zlen) < 0) {
            free (content);
            builtin_error ("create: deflate failed for %s", shas[i]);
            free (body); free (shas); free (ents);
            return EXECUTION_FAILURE;
        }
        free (content);
        if (bgit_pack_buf_append (&body, &body_len, &body_cap, zbuf, zlen) < 0) {
            free (zbuf); goto oom;
        }
        free (zbuf);
        if (ents) {
            ents[i].off = obj_off;
            ents[i].crc = bgit_pack_crc32 (body + obj_off,
                                           body_len - (size_t) obj_off);
        }
    }

    /* Trailer: SHA-1 of everything written so far. */
    unsigned char digest[20];
    if (bgit_sha1 (body, body_len, digest) < 0) {
        builtin_error ("create: SHA-1 collision attack detected");
        free (body); free (shas); free (ents);
        return EXECUTION_FAILURE;
    }
    if (bgit_pack_buf_append (&body, &body_len, &body_cap, digest, 20) < 0) goto oom;

    /* Atomic write via tmp + rename. */
    char tmp[4096];
    snprintf (tmp, sizeof tmp, "%s.tmpXXXXXX", outfile);
    int fd = mkstemp (tmp);
    if (fd < 0) {
        builtin_error ("create: mkstemp %s: %s", tmp, strerror (errno));
        free (body); free (shas); free (ents);
        return EXECUTION_FAILURE;
    }
    fchmod (fd, 0444);
    size_t off = 0;
    while (off < body_len) {
        ssize_t w = write (fd, body + off, body_len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            builtin_error ("create: write %s: %s", tmp, strerror (errno));
            close (fd); unlink (tmp);
            free (body); free (shas); free (ents);
            return EXECUTION_FAILURE;
        }
        off += (size_t) w;
    }
    fdatasync (fd);
    close (fd);
    if (rename (tmp, outfile) < 0) {
        builtin_error ("create: rename %s -> %s: %s", tmp, outfile, strerror (errno));
        unlink (tmp);
        free (body); free (shas); free (ents);
        return EXECUTION_FAILURE;
    }
    if (idx_path && bgit_pack_write_idx_v2 (idx_path, ents, n_shas, digest) < 0) {
        free (body); free (shas); free (ents);
        return EXECUTION_FAILURE;
    }
    free (body); free (shas); free (ents);
    printf ("%zu\n", n_shas);
    return EXECUTION_SUCCESS;

oom:
    builtin_error ("create: out of memory");
    free (body); free (shas); free (ents);
    return EXECUTION_FAILURE;
}

static int
bp_verify_idx_cmd (WORD_LIST *args)
{
    if (!args) {
        builtin_error ("verify-idx: IDX [PACK]");
        return EX_USAGE;
    }
    const char *idx_path = args->word->word;
    const char *pack_path = (args->next ? args->next->word->word : NULL);
    if (args->next && args->next->next) {
        builtin_error ("verify-idx: extra arg %s", args->next->next->word->word);
        return EX_USAGE;
    }
    size_t ilen;
    unsigned char *idx = bgit_pack_slurp (idx_path, &ilen);
    if (!idx) {
        builtin_error ("verify-idx: read %s: %s", idx_path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    unsigned char pack_sha[20];
    const unsigned char *expected = NULL;
    unsigned char *pack = NULL;
    size_t plen = 0;
    if (pack_path) {
        pack = bgit_pack_slurp (pack_path, &plen);
        if (!pack) {
            free (idx);
            builtin_error ("verify-idx: read %s: %s", pack_path, strerror (errno));
            return EXECUTION_FAILURE;
        }
        if (plen < 20) {
            free (idx); free (pack);
            builtin_error ("verify-idx: pack too short (no trailer)");
            return EXECUTION_FAILURE;
        }
        memcpy (pack_sha, pack + plen - 20, 20);
        expected = pack_sha;
    }
    int rc = bgit_pack_verify_idx (idx, ilen, expected);
    if (rc == 0 && pack)
        rc = bgit_pack_verify_idx_crc32 (idx, ilen, pack, plen);
    free (idx);
    free (pack);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

int
pack_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "list-objects")) return bp_list_objects_cmd (args);
    if (!strcmp (cmd, "cat"))          return bp_cat_cmd (args);
    if (!strcmp (cmd, "list-packs"))   return bp_list_packs_cmd (args);
    if (!strcmp (cmd, "unpack"))       return bp_unpack_cmd (args);
    if (!strcmp (cmd, "create"))       return bp_create_cmd (args);
    if (!strcmp (cmd, "verify-idx"))   return bp_verify_idx_cmd (args);
    builtin_error ("unknown verb: %s", cmd);
    return EX_USAGE;
}

char *pack_doc[] = {
    "Read + write git packfiles (resolves OFS_DELTA + REF_DELTA chains).",
    "",
    "    pack list-objects IDX",
    "        Enumerate every SHA in the .idx file.",
    "    pack cat PACK IDX SHA [-r REPO]",
    "        Decompress + delta-resolve; emit raw object content.",
    "    pack list-packs [REPO]",
    "        List <repo>/.git/objects/pack/pack-*.idx files.",
    "    pack unpack PACK REPO",
    "        Unpack a fetched packfile into loose objects.",
    "    pack create OUTFILE [--idx IDXFILE] [-r REPO] SHA [SHA...]",
    "        Build a pack v2 from local loose objects (full bases, no",
    "        deltas). Used by 'git push' to assemble the receive-pack",
    "        request body. Output is atomic via tmp+rename. With --idx,",
    "        also write the paired v2 .idx: SHA-sorted fanout, CRC,",
    "        offset tables, and pack-SHA + idx-SHA trailer.",
    "    pack verify-idx IDX [PACK]",
    "        Validate a v2 .idx file: header + magic + version, fanout",
    "        monotonicity, exact-size match against fanout count plus",
    "        the 64-bit overflow table (verifies the CRC32 table's",
    "        presence + bounds implicitly), and SHA-1 trailer over",
    "        idx[0..ilen-20]. When PACK is given, also cross-checks",
    "        the idx trailer's embedded pack SHA-1 against the pack's",
    "        own trailer SHA-1 and validates per-object CRC32 table",
    "        entries against the corresponding packed object bytes.",
    (char *)NULL
};

struct builtin pack_struct = {
    "pack",
    pack_builtin,
    BUILTIN_ENABLED,
    pack_doc,
    "pack list-objects|cat|list-packs|unpack|create|verify-idx ARGS",
    0
};
