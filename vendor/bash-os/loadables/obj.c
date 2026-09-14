/* SPDX-License-Identifier: MIT */
/* obj.c — git object access (loose, read-only at v1).
 *
 * Phase W W-1a of bash-os git primitives. Reads loose objects from
 * <repo>/.git/objects/<aa>/<bbbb...> (zlib-compressed; header
 * "<type> <size>\0" + payload). Pack access is handled by pack.
 *
 * Verbs:
 *   obj cat SHA [-r REPO] [-V VAR]
 *       Inflate object, strip header, emit content. -V binds to a
 *       bash variable (truncates at NUL — use -X for binary content).
 *
 *   obj --batch|--batch-check [-r REPO]
 *       Read object names from stdin and emit git cat-file compatible
 *       batch records.
 *
 *   obj type SHA [-r REPO]
 *       Print the type token (blob/tree/commit/tag).
 *
 *   obj size SHA [-r REPO]
 *       Print the content size in bytes.
 *
 *   obj parse-tree SHA [-r REPO] [-V VAR]
 *       Emit each tree entry as "<mode> <name> <sha>" line. With -V,
 *       binds a bash array (one element per entry).
 *
 *   obj parse-commit SHA [-r REPO] [-V VAR]
 *       Emit commit fields one per line: "tree <sha>", "parent <sha>"
 *       (zero or more), "author <line>", "committer <line>", then a
 *       blank line and the message body. With -V, binds <PFX>_tree,
 *       <PFX>_parents (space-joined), <PFX>_author, <PFX>_committer,
 *       <PFX>_message.
 *
 *   -r REPO   repo root (containing .git/). Defaults to cwd; if cwd
 *             has no .git/, walks parents like real git.
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
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <zlib.h>

/* sha1dc — collision-detecting SHA-1. Vendored under _sha1dc/, flattened
   to builtins/_sha1dc_*.{c,h} by patch-bash-loadables.sh at build time. */
#include "_sha1dc_sha1.h"

#include "loadables.h"
#include "arrayfunc.h"

/* git cat-file exits 128 ("fatal") on a missing/unresolvable/malformed
   object. We match that for object-read failures so scripts that branch on
   `$?` behave identically against git and obj. Usage errors keep
   EX_USAGE; this is only for the object-read/resolve paths. */
#define BO_EX_FATAL 128

/* Object types. */
enum bo_type { BO_BLOB, BO_TREE, BO_COMMIT, BO_TAG, BO_UNKNOWN };

static const char *
bo_type_name (enum bo_type t)
{
    switch (t) {
    case BO_BLOB:   return "blob";
    case BO_TREE:   return "tree";
    case BO_COMMIT: return "commit";
    case BO_TAG:    return "tag";
    default:        return "unknown";
    }
}

static int
bo_type_valid_name (const char *name)
{
    return (strcmp (name, "blob") == 0
            || strcmp (name, "tree") == 0
            || strcmp (name, "commit") == 0
            || strcmp (name, "tag") == 0);
}

static int
bo_type_literally_acceptable (const char *name)
{
    if (!name || !*name)
        return 0;
    for (const unsigned char *p = (const unsigned char *) name; *p; p++)
        if (*p <= ' ' || *p == 0x7f)
            return 0;
    return 1;
}

/* Walk parent dirs from `start` looking for a .git/. Returns malloc'd
   path to the repo root (parent of .git/), or NULL. */
static char *
bor_find_repo (const char *start)
{
    char *cur = realpath (start, NULL);
    if (!cur) return NULL;
    while (1) {
        char probe[4096];
        snprintf (probe, sizeof probe, "%s/.git", cur);
        struct stat st;
        if (stat (probe, &st) == 0 && S_ISDIR (st.st_mode)) return cur;
        /* Walk up. */
        char *slash = strrchr (cur, '/');
        if (!slash || slash == cur) { free (cur); return NULL; }
        *slash = '\0';
    }
}

/* Return 1 if `s` is non-empty and entirely lowercase/uppercase hex. */
static int
bor_all_hex (const char *s)
{
    if (!s || !*s)
        return 0;
    for (const char *p = s; *p; p++)
        if (!isxdigit ((unsigned char) *p))
            return 0;
    return 1;
}

/* Resolve a possibly-abbreviated hex object name to its full 40-char SHA by
   scanning the loose-object store (<repo>/.git/objects/<aa>/<rest...>),
   mirroring `git cat-file`'s unique-prefix rule. `sha` is full hex (length
   4..40). On success writes 40 hex chars + NUL into full[41] and returns 0.
   On ambiguous/none/error emits a git-style message and returns -1. */
static int
bor_resolve_prefix (const char *repo, const char *sha, char full[41])
{
    size_t slen = strlen (sha);
    if (slen == 40) {
        memcpy (full, sha, 40);
        full[40] = '\0';
        return 0;
    }
    /* git's minimum abbreviation is 4 hex; shorter is rejected. */
    if (slen < 4) {
        builtin_error ("Not a valid object name %s", sha);
        return -1;
    }
    char dir[4096];
    snprintf (dir, sizeof dir, "%s/.git/objects/%c%c", repo, sha[0], sha[1]);
    DIR *d = opendir (dir);
    if (!d) {
        builtin_error ("Not a valid object name %s", sha);
        return -1;
    }
    const char *rest = sha + 2;          /* prefix to match against filenames */
    size_t restlen = slen - 2;
    int matches = 0;
    char hit[39] = "";                   /* the matched filename (38 hex + NUL) */
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        if (strlen (de->d_name) != 38)   /* loose-object basename length */
            continue;
        if (strncmp (de->d_name, rest, restlen) == 0) {
            if (matches == 0) {
                memcpy (hit, de->d_name, 38);
                hit[38] = '\0';
            }
            matches++;
            if (matches > 1)
                break;
        }
    }
    closedir (d);
    if (matches == 0) {
        builtin_error ("Not a valid object name %s", sha);
        return -1;
    }
    if (matches > 1) {
        builtin_error ("ambiguous argument '%s': unknown revision or object name", sha);
        return -1;
    }
    full[0] = sha[0];
    full[1] = sha[1];
    memcpy (full + 2, hit, 38);
    full[40] = '\0';
    return 0;
}

/* Read a loose object file at <repo>/.git/objects/<aa>/<bbbb...> and
   return inflated bytes. Caller frees out. Accepts a full 40-char SHA or a
   unique hex prefix (>= 4 chars), resolving the latter against the store. */
static int
bor_read_loose (const char *repo, const char *sha_in,
                unsigned char **out, size_t *out_len)
{
    if (!bor_all_hex (sha_in) || strlen (sha_in) > 40) {
        builtin_error ("invalid sha: %s", sha_in);
        return -1;
    }
    char sha[41];
    if (bor_resolve_prefix (repo, sha_in, sha) < 0)
        return -1;
    char path[4096];
    snprintf (path, sizeof path, "%s/.git/objects/%c%c/%s",
              repo, sha[0], sha[1], sha + 2);
    int fd = open (path, O_RDONLY);
    if (fd < 0) {
        builtin_error ("loose object %s: %s", sha, strerror (errno));
        return -1;
    }
    /* Stat for size; mmap would be nice but read+inflate is simpler. */
    struct stat st;
    if (fstat (fd, &st) < 0) { close (fd); return -1; }
    unsigned char *raw = malloc ((size_t) st.st_size);
    if (!raw) { close (fd); return -1; }
    ssize_t got = 0;
    while (got < st.st_size) {
        ssize_t r = read (fd, raw + got, (size_t) (st.st_size - got));
        if (r < 0) {
            if (errno == EINTR) continue;
            builtin_error ("read loose: %s", strerror (errno));
            free (raw); close (fd); return -1;
        }
        if (r == 0) break;
        got += r;
    }
    close (fd);

    /* Inflate. Loose objects use zlib format (window bits 15). */
    z_stream s = {0};
    if (inflateInit (&s) != Z_OK) {
        builtin_error ("zlib init failed");
        free (raw);
        return -1;
    }
    s.next_in = raw;
    s.avail_in = (uInt) got;
    size_t cap = (size_t) got * 4 + 256;
    unsigned char *buf = malloc (cap);
    size_t total = 0;
    int z_rc;
    do {
        if (total + 4096 > cap) {
            cap = cap * 2 + 4096;
            unsigned char *nb = realloc (buf, cap);
            if (!nb) { free (buf); free (raw); inflateEnd (&s); return -1; }
            buf = nb;
        }
        s.next_out = buf + total;
        s.avail_out = (uInt) (cap - total);
        z_rc = inflate (&s, Z_NO_FLUSH);
        if (z_rc != Z_OK && z_rc != Z_STREAM_END) {
            builtin_error ("zlib inflate failed: %s", s.msg ? s.msg : "?");
            free (buf); free (raw); inflateEnd (&s); return -1;
        }
        total = cap - s.avail_out;
    } while (z_rc != Z_STREAM_END);
    inflateEnd (&s);
    free (raw);
    *out = buf;
    *out_len = total;
    return 0;
}

static int
bor_loose_path_exists (const char *repo, const char sha[41])
{
    char path[4096];
    snprintf (path, sizeof path, "%s/.git/objects/%c%c/%s",
              repo, sha[0], sha[1], sha + 2);
    return access (path, R_OK) == 0;
}

/* Parse "<type> <size>\0" header. Returns offset of NUL+1 (start of
   payload), or -1 on parse error. */
static long
bor_parse_header (const unsigned char *data, size_t len,
                  enum bo_type *type, size_t *payload_size)
{
    /* Find space. */
    size_t i = 0;
    while (i < len && data[i] != ' ') i++;
    if (i >= len) return -1;
    if (i == 4 && memcmp (data, "blob", 4) == 0)        *type = BO_BLOB;
    else if (i == 4 && memcmp (data, "tree", 4) == 0)   *type = BO_TREE;
    else if (i == 6 && memcmp (data, "commit", 6) == 0) *type = BO_COMMIT;
    else if (i == 3 && memcmp (data, "tag", 3) == 0)    *type = BO_TAG;
    else                                                return -1;
    /* Parse size up to NUL. */
    size_t j = i + 1;
    size_t sz = 0;
    while (j < len && data[j] != '\0') {
        if (data[j] < '0' || data[j] > '9') return -1;
        sz = sz * 10 + (size_t) (data[j] - '0');
        j++;
    }
    if (j >= len) return -1;
    *payload_size = sz;
    return (long) (j + 1);
}

/* ---- arg parsing helpers ---- */

typedef struct {
    const char *sha;
    const char *repo_arg;       /* NULL = autodetect */
    const char *var;            /* NULL = stdout */
    int zmode;                  /* parse-tree: NUL-record/TAB-field output */
} bor_args;

static int
bor_parse_args (WORD_LIST *args, bor_args *out)
{
    memset (out, 0, sizeof *out);
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-r") == 0 && p->next) { out->repo_arg = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-V") == 0 && p->next) { out->var = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-z") == 0) { out->zmode = 1; }
        else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("unknown flag: %s", w);
            builtin_usage ();
            return -1;
        } else {
            if (out->sha) {
                builtin_error ("too many positionals");
                builtin_usage ();
                return -1;
            }
            out->sha = w;
        }
    }
    if (!out->sha) {
        builtin_error ("missing SHA");
        builtin_usage ();
        return -1;
    }
    return 0;
}

/* Resolve repo: -r REPO if given, else find from cwd. Returns malloc'd
   path; caller frees. */
static char *
bor_resolve_repo (const bor_args *a)
{
    if (a->repo_arg) {
        /* Verify .git/ exists. */
        char probe[4096];
        snprintf (probe, sizeof probe, "%s/.git", a->repo_arg);
        struct stat st;
        if (stat (probe, &st) != 0 || !S_ISDIR (st.st_mode)) {
            builtin_error ("not a git repo: %s", a->repo_arg);
            return NULL;
        }
        return strdup (a->repo_arg);
    }
    char *r = bor_find_repo (".");
    if (!r) builtin_error ("not in a git repo");
    return r;
}

/* ---- verb implementations ---- */

static int
bor_cat_cmd (WORD_LIST *args)
{
    bor_args a;
    if (bor_parse_args (args, &a) < 0) return EX_USAGE;
    char *repo = bor_resolve_repo (&a);
    if (!repo) return BO_EX_FATAL;

    unsigned char *obj; size_t olen;
    if (bor_read_loose (repo, a.sha, &obj, &olen) < 0) {
        free (repo); return BO_EX_FATAL;
    }
    free (repo);
    enum bo_type type; size_t psize;
    long off = bor_parse_header (obj, olen, &type, &psize);
    if (off < 0) {
        builtin_error ("malformed object header");
        free (obj); return BO_EX_FATAL;
    }
    if (a.var) {
        /* NUL-truncated, but useful for blobs / commit messages. */
        char *s = malloc (psize + 1);
        memcpy (s, obj + off, psize);
        s[psize] = '\0';
        builtin_bind_variable ((char *) a.var, s, 0);
        free (s);
    } else {
        fwrite (obj + off, 1, psize, stdout);
    }
    free (obj);
    return EXECUTION_SUCCESS;
}

static int
bor_type_cmd (WORD_LIST *args)
{
    bor_args a;
    if (bor_parse_args (args, &a) < 0) return EX_USAGE;
    char *repo = bor_resolve_repo (&a);
    if (!repo) return BO_EX_FATAL;

    unsigned char *obj; size_t olen;
    if (bor_read_loose (repo, a.sha, &obj, &olen) < 0) {
        free (repo); return BO_EX_FATAL;
    }
    free (repo);
    enum bo_type type; size_t psize;
    if (bor_parse_header (obj, olen, &type, &psize) < 0) {
        builtin_error ("malformed object header");
        free (obj); return BO_EX_FATAL;
    }
    printf ("%s\n", bo_type_name (type));
    free (obj);
    return EXECUTION_SUCCESS;
}

static int
bor_size_cmd (WORD_LIST *args)
{
    bor_args a;
    if (bor_parse_args (args, &a) < 0) return EX_USAGE;
    char *repo = bor_resolve_repo (&a);
    if (!repo) return BO_EX_FATAL;

    unsigned char *obj; size_t olen;
    if (bor_read_loose (repo, a.sha, &obj, &olen) < 0) {
        free (repo); return BO_EX_FATAL;
    }
    free (repo);
    enum bo_type type; size_t psize;
    if (bor_parse_header (obj, olen, &type, &psize) < 0) {
        builtin_error ("malformed object header");
        free (obj); return BO_EX_FATAL;
    }
    printf ("%zu\n", psize);
    free (obj);
    return EXECUTION_SUCCESS;
}

static int
bor_batch_cmd (WORD_LIST *args, int emit_content)
{
    const char *repo_arg = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-r") == 0 && p->next) {
            repo_arg = p->next->word->word;
            p = p->next;
        } else {
            builtin_error ("%s: unexpected arg '%s'",
                           emit_content ? "--batch" : "--batch-check", w);
            builtin_usage ();
            return EX_USAGE;
        }
    }

    bor_args a;
    memset (&a, 0, sizeof a);
    a.repo_arg = repo_arg;
    char *repo = bor_resolve_repo (&a);
    if (!repo)
        return BO_EX_FATAL;

    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    while ((nread = getline (&line, &cap, stdin)) >= 0) {
        while (nread > 0 && (line[nread - 1] == '\n' || line[nread - 1] == '\r'))
            line[--nread] = '\0';

        char full[41];
        unsigned char *obj = NULL;
        size_t olen = 0;
        if (nread <= 0 || !bor_all_hex (line) || strlen (line) > 40
            || bor_resolve_prefix (repo, line, full) < 0
            || !bor_loose_path_exists (repo, full)
            || bor_read_loose (repo, full, &obj, &olen) < 0) {
            printf ("%s missing\n", line);
            continue;
        }

        enum bo_type type;
        size_t psize;
        long off = bor_parse_header (obj, olen, &type, &psize);
        if (off < 0 || (size_t) off > olen || psize > olen - (size_t) off) {
            printf ("%s missing\n", line);
            free (obj);
            continue;
        }

        printf ("%s %s %zu\n", full, bo_type_name (type), psize);
        if (emit_content) {
            fwrite (obj + off, 1, psize, stdout);
            putchar ('\n');
        }
        free (obj);
    }

    free (line);
    free (repo);
    return EXECUTION_SUCCESS;
}

/* Format a 20-byte SHA as 40 hex chars. */
static void
bor_sha_to_hex (const unsigned char *sha, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < 20; i++) {
        out[2*i]   = d[sha[i] >> 4];
        out[2*i+1] = d[sha[i] & 0xF];
    }
    out[40] = '\0';
}

static int
bor_parse_tree_cmd (WORD_LIST *args)
{
    bor_args a;
    if (bor_parse_args (args, &a) < 0) return EX_USAGE;
    char *repo = bor_resolve_repo (&a);
    if (!repo) return BO_EX_FATAL;

    unsigned char *obj; size_t olen;
    if (bor_read_loose (repo, a.sha, &obj, &olen) < 0) {
        free (repo); return BO_EX_FATAL;
    }
    free (repo);
    enum bo_type type; size_t psize;
    long off = bor_parse_header (obj, olen, &type, &psize);
    if (off < 0 || type != BO_TREE) {
        builtin_error ("not a tree object");
        free (obj); return BO_EX_FATAL;
    }

    /* Tree body: repeated "<mode> <name>\0<20-byte-sha>". */
    SHELL_VAR *arr = NULL;
    int idx = 0;
    if (a.var) {
        unbind_variable ((char *) a.var);
        arr = find_or_make_array_variable ((char *) a.var, 1);
    }

    size_t pos = (size_t) off;
    size_t end = (size_t) off + psize;
    while (pos < end) {
        /* mode: ASCII digits up to space. */
        size_t ms = pos;
        while (pos < end && obj[pos] != ' ') pos++;
        if (pos >= end) { builtin_error ("malformed tree (mode)"); free (obj); return EXECUTION_FAILURE; }
        size_t ml = pos - ms;
        pos++;  /* skip space */
        size_t ns = pos;
        while (pos < end && obj[pos] != '\0') pos++;
        if (pos >= end) { builtin_error ("malformed tree (name)"); free (obj); return EXECUTION_FAILURE; }
        size_t nl = pos - ns;
        pos++;  /* skip NUL */
        if (pos + 20 > end) { builtin_error ("malformed tree (sha)"); free (obj); return EXECUTION_FAILURE; }

        char hex[41];
        bor_sha_to_hex (obj + pos, hex);
        pos += 20;

        char line[4096];
        int emit_z = a.zmode && !(a.var && arr);
        int wrote;
        if (emit_z) {
            /* NUL-terminated record; TAB precedes the arbitrary path field.
               Mode is digits-only and hex is [0-9a-f], so neither can
               contain TAB and the name is everything after the first TAB. */
            wrote = snprintf (line, sizeof line, "%.*s %s\t%.*s",
                              (int) ml, (char *) (obj + ms),
                              hex,
                              (int) nl, (char *) (obj + ns));
        } else {
            wrote = snprintf (line, sizeof line, "%.*s %.*s %s",
                              (int) ml, (char *) (obj + ms),
                              (int) nl, (char *) (obj + ns),
                              hex);
        }
        if (wrote < 0) wrote = 0;
        if ((size_t) wrote >= sizeof line) wrote = sizeof line - 1;
        if (a.var && arr) {
            ARRAY *aa = array_cell (arr);
            array_insert (aa, idx++, line);
        } else if (emit_z) {
            fwrite (line, 1, (size_t) wrote, stdout);
            putchar ('\0');
        } else {
            puts (line);
        }
    }
    free (obj);
    return EXECUTION_SUCCESS;
}

/* Parse a commit object. Walk header lines until blank line; then body. */
static int
bor_parse_commit_cmd (WORD_LIST *args)
{
    bor_args a;
    if (bor_parse_args (args, &a) < 0) return EX_USAGE;
    char *repo = bor_resolve_repo (&a);
    if (!repo) return BO_EX_FATAL;

    unsigned char *obj; size_t olen;
    if (bor_read_loose (repo, a.sha, &obj, &olen) < 0) {
        free (repo); return BO_EX_FATAL;
    }
    free (repo);
    enum bo_type type; size_t psize;
    long off = bor_parse_header (obj, olen, &type, &psize);
    if (off < 0 || type != BO_COMMIT) {
        builtin_error ("not a commit object");
        free (obj); return BO_EX_FATAL;
    }
    /* Walk lines. */
    char tree[64] = "";
    char author[1024] = "", committer[1024] = "";
    char parents[8192] = "";
    char *p = (char *) obj + off;
    char *end = (char *) obj + off + psize;
    char *body = NULL;
    while (p < end) {
        char *nl = memchr (p, '\n', (size_t) (end - p));
        size_t llen = nl ? (size_t) (nl - p) : (size_t) (end - p);
        if (llen == 0) {
            /* blank line — body follows */
            body = nl ? nl + 1 : NULL;
            break;
        }
        if (llen > 5 && memcmp (p, "tree ", 5) == 0) {
            size_t cp = llen - 5; if (cp >= sizeof tree) cp = sizeof tree - 1;
            memcpy (tree, p + 5, cp); tree[cp] = '\0';
        } else if (llen > 7 && memcmp (p, "parent ", 7) == 0) {
            size_t need = strlen (parents) + (llen - 7) + 2;
            if (need < sizeof parents) {
                if (parents[0]) strcat (parents, " ");
                strncat (parents, p + 7, llen - 7);
            }
        } else if (llen > 7 && memcmp (p, "author ", 7) == 0) {
            size_t cp = llen - 7; if (cp >= sizeof author) cp = sizeof author - 1;
            memcpy (author, p + 7, cp); author[cp] = '\0';
        } else if (llen > 10 && memcmp (p, "committer ", 10) == 0) {
            size_t cp = llen - 10; if (cp >= sizeof committer) cp = sizeof committer - 1;
            memcpy (committer, p + 10, cp); committer[cp] = '\0';
        }
        p = nl ? nl + 1 : end;
    }
    size_t body_len = body ? (size_t) (end - body) : 0;

    if (a.var) {
        char vbuf[5][1100];
        snprintf (vbuf[0], sizeof vbuf[0], "%s_tree", a.var);
        snprintf (vbuf[1], sizeof vbuf[1], "%s_parents", a.var);
        snprintf (vbuf[2], sizeof vbuf[2], "%s_author", a.var);
        snprintf (vbuf[3], sizeof vbuf[3], "%s_committer", a.var);
        snprintf (vbuf[4], sizeof vbuf[4], "%s_message", a.var);
        builtin_bind_variable (vbuf[0], tree, 0);
        builtin_bind_variable (vbuf[1], parents, 0);
        builtin_bind_variable (vbuf[2], author, 0);
        builtin_bind_variable (vbuf[3], committer, 0);
        char *msg = malloc (body_len + 1);
        if (msg) {
            memcpy (msg, body ? body : "", body_len);
            msg[body_len] = '\0';
            /* Trim trailing newline. */
            if (body_len > 0 && msg[body_len - 1] == '\n') msg[body_len - 1] = '\0';
            builtin_bind_variable (vbuf[4], msg, 0);
            free (msg);
        }
    } else {
        printf ("tree %s\n", tree);
        if (parents[0]) {
            char *q = parents;
            while (*q) {
                char *sp = strchr (q, ' ');
                size_t pl = sp ? (size_t) (sp - q) : strlen (q);
                printf ("parent %.*s\n", (int) pl, q);
                if (!sp) break;
                q = sp + 1;
            }
        }
        printf ("author %s\n", author);
        printf ("committer %s\n", committer);
        putchar ('\n');
        fwrite (body ? body : "", 1, body_len, stdout);
    }
    free (obj);
    return EXECUTION_SUCCESS;
}

/* ===== W-1b: write path ===================================================
 * Verbs: hash, blob, tree, commit. All hash via sha1dc and (with -w / by
 * default for blob/tree/commit) write zlib-compressed loose objects to
 * <repo>/.git/objects/<aa>/<bbbb...>. Atomic via mkstemp + rename. */

/* Hash bytes through sha1dc. Returns 0 on success; -1 if a SHAttered-style
   collision was detected (caller should refuse to write). digest[20] gets
   the canonical SHA-1 either way (SafeHash=0). */
static int
bow_sha1 (const unsigned char *data, size_t n, unsigned char digest[20])
{
    SHA1_CTX ctx;
    SHA1DCInit (&ctx);
    SHA1DCSetSafeHash (&ctx, 0);   /* always emit canonical SHA-1 */
    SHA1DCUpdate (&ctx, (const char *) data, n);
    return SHA1DCFinal (digest, &ctx) == 0 ? 0 : -1;
}

/* zlib-deflate `data[0..n)` into a malloc'd output buffer; caller frees. */
static int
bow_deflate (const unsigned char *data, size_t n,
             unsigned char **out, size_t *out_len)
{
    z_stream s = {0};
    if (deflateInit (&s, Z_DEFAULT_COMPRESSION) != Z_OK) return -1;
    size_t cap = deflateBound (&s, n);
    unsigned char *buf = malloc (cap);
    if (!buf) { deflateEnd (&s); return -1; }
    s.next_in = (unsigned char *) data;
    s.avail_in = (uInt) n;
    s.next_out = buf;
    s.avail_out = (uInt) cap;
    int rc = deflate (&s, Z_FINISH);
    if (rc != Z_STREAM_END) {
        free (buf);
        deflateEnd (&s);
        return -1;
    }
    *out = buf;
    *out_len = cap - s.avail_out;
    deflateEnd (&s);
    return 0;
}

/* Atomically write deflated bytes to <repo>/.git/objects/<aa>/<bbbb...>.
   No-op if the object already exists (git's standard behavior). */
static int
bow_write_loose (const char *repo, const char *sha,
                 const unsigned char *deflated, size_t dlen)
{
    char dir[4096], path[4096], tmp[4096];
    snprintf (dir, sizeof dir, "%s/.git/objects/%c%c", repo, sha[0], sha[1]);
    snprintf (path, sizeof path, "%s/%s", dir, sha + 2);
    /* If already present, success. */
    struct stat st;
    if (stat (path, &st) == 0) return 0;
    if (mkdir (dir, 0755) < 0 && errno != EEXIST) {
        builtin_error ("mkdir %s: %s", dir, strerror (errno));
        return -1;
    }
    snprintf (tmp, sizeof tmp, "%s.tmpXXXXXX", path);
    int fd = mkstemp (tmp);
    if (fd < 0) {
        builtin_error ("mkstemp %s: %s", tmp, strerror (errno));
        return -1;
    }
    fchmod (fd, 0444);  /* git uses 0444 for loose objects */
    size_t off = 0;
    while (off < dlen) {
        ssize_t w = write (fd, deflated + off, dlen - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            builtin_error ("write %s: %s", tmp, strerror (errno));
            close (fd); unlink (tmp);
            return -1;
        }
        off += w;
    }
    fdatasync (fd);
    close (fd);
    if (rename (tmp, path) < 0) {
        builtin_error ("rename %s -> %s: %s", tmp, path, strerror (errno));
        unlink (tmp);
        return -1;
    }
    return 0;
}

/* Build the in-memory pre-image (header + content), hash it, optionally
   write it. Returns 0 + sets sha_hex (40 chars + NUL) on success. */
static int
bow_hash_and_write (const char *type, const unsigned char *content, size_t clen,
                    int do_write, const char *repo, char sha_hex[41])
{
    /* Header: "TYPE LEN\0" */
    char hdr[64];
    int hl = snprintf (hdr, sizeof hdr, "%s %zu", type, clen);
    if (hl <= 0 || hl >= (int) sizeof hdr) return -1;
    size_t pre_len = (size_t) hl + 1 + clen;  /* +1 for NUL */
    unsigned char *pre = malloc (pre_len);
    if (!pre) { builtin_error ("malloc"); return -1; }
    memcpy (pre, hdr, (size_t) hl);
    pre[hl] = '\0';
    memcpy (pre + hl + 1, content, clen);

    unsigned char digest[20];
    int collision = bow_sha1 (pre, pre_len, digest);
    bor_sha_to_hex (digest, sha_hex);
    if (collision < 0) {
        free (pre);
        builtin_error ("sha1dc: collision attempt detected for %s — refusing to write", sha_hex);
        return -1;
    }

    if (do_write) {
        unsigned char *deflated;
        size_t dlen;
        if (bow_deflate (pre, pre_len, &deflated, &dlen) < 0) {
            free (pre);
            builtin_error ("deflate failed");
            return -1;
        }
        free (pre);
        int rc = bow_write_loose (repo, sha_hex, deflated, dlen);
        free (deflated);
        return rc;
    }
    free (pre);
    return 0;
}

/* Read entire stdin into malloc'd buffer. Caller frees. */
static int
bow_slurp_stdin (unsigned char **out, size_t *out_len)
{
    size_t cap = 8192, n = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) return -1;
    ssize_t r;
    while ((r = read (STDIN_FILENO, buf + n, cap - n)) > 0) {
        n += r;
        if (n == cap) {
            cap *= 2;
            unsigned char *nb = realloc (buf, cap);
            if (!nb) { free (buf); return -1; }
            buf = nb;
        }
    }
    if (r < 0) { free (buf); return -1; }
    *out = buf;
    *out_len = n;
    return 0;
}

/* Read the named file into a malloc'd buffer. Caller frees. */
static int
bow_slurp_file (const char *path, unsigned char **out, size_t *out_len)
{
    int fd = open (path, O_RDONLY);
    if (fd < 0) {
        builtin_error ("hash: %s: %s", path, strerror (errno));
        return -1;
    }

    size_t cap = 8192, n = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) { close (fd); return -1; }

    ssize_t r;
    while ((r = read (fd, buf + n, cap - n)) > 0) {
        n += r;
        if (n == cap) {
            cap *= 2;
            unsigned char *nb = realloc (buf, cap);
            if (!nb) { free (buf); close (fd); return -1; }
            buf = nb;
        }
    }
    close (fd);
    if (r < 0) {
        builtin_error ("hash: %s: %s", path, strerror (errno));
        free (buf);
        return -1;
    }

    *out = buf;
    *out_len = n;
    return 0;
}

/* hash [--stdin|--stdin-paths] [--no-filters] [--filters] [--path FILE]
   [--literally] [-t TYPE] [-w] [-r REPO] [-V VAR] — read stdin, hash,
   optionally write.
   Default type=blob. */
static int
bow_hash_cmd (WORD_LIST *args)
{
    const char *type = "blob";
    int do_write = 0;
    int literally = 0;
    int stdin_mode = 0;
    int stdin_paths = 0;
    int no_filters = 0;
    const char *path_spec = NULL;
    const char *repo_arg = NULL;
    const char *var = NULL;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--stdin") == 0) { stdin_mode = 1; }
        else if (strcmp (w, "--no-stdin") == 0) { stdin_mode = 0; }
        else if (strcmp (w, "--no-filters") == 0) { no_filters = 1; }
        else if (strcmp (w, "--filters") == 0) { no_filters = 0; }
        else if (strcmp (w, "--stdin-paths") == 0) { stdin_paths = 1; }
        else if (strcmp (w, "--no-stdin-paths") == 0) { stdin_paths = 0; }
        else if (strcmp (w, "--no-path") == 0) { path_spec = NULL; }
        else if (strcmp (w, "--path") == 0 && p->next) { path_spec = p->next->word->word; p = p->next; }
        else if (strncmp (w, "--path=", 7) == 0) { path_spec = w + 7; }
        else if (strcmp (w, "--literally") == 0) { literally = 1; }
        else if (strcmp (w, "--no-literally") == 0) { literally = 0; }
        else if (strcmp (w, "-t") == 0 && p->next) { type = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-w") == 0) { do_write = 1; }
        else if (strcmp (w, "-r") == 0 && p->next) { repo_arg = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-V") == 0 && p->next) { var = p->next->word->word; p = p->next; }
        else { builtin_error ("hash: unexpected arg '%s'", w); builtin_usage (); return EX_USAGE; }
    }

    if (!bo_type_valid_name (type) && !literally) {
        builtin_error ("hash: invalid object type '%s'", type);
        builtin_usage ();
        return EX_USAGE;
    }
    if (literally && !bo_type_literally_acceptable (type)) {
        builtin_error ("hash: invalid object type '%s'", type);
        builtin_usage ();
        return EX_USAGE;
    }

    if (stdin_paths && var) {
        builtin_error ("hash: --stdin-paths cannot be combined with -V");
        builtin_usage ();
        return EX_USAGE;
    }
    if (stdin_paths && stdin_mode) {
        builtin_error ("hash: Can't use --stdin-paths with --stdin");
        builtin_usage ();
        return EX_USAGE;
    }
    if (path_spec && no_filters) {
        builtin_error ("hash: can't use --path with --no-filters");
        builtin_usage ();
        return EX_USAGE;
    }
    if (path_spec && stdin_paths) {
        builtin_error ("hash: can't use --stdin-paths with --path");
        builtin_usage ();
        return EX_USAGE;
    }

    char *repo = NULL;
    if (do_write) {
        bor_args ra = { .repo_arg = repo_arg };
        repo = bor_resolve_repo (&ra);
        if (!repo) return EXECUTION_FAILURE;
    }

    if (stdin_paths) {
        char *line = NULL;
        size_t llen = 0;
        ssize_t got;
        while ((got = getline (&line, &llen, stdin)) > 0) {
            if (got > 0 && line[got - 1] == '\n') {
                line[got - 1] = '\0';
                got--;
            }
            if (got > 0 && line[got - 1] == '\r')
                line[got - 1] = '\0';

            unsigned char *content;
            size_t clen;
            if (bow_slurp_file (line, &content, &clen) < 0) {
                free (line); free (repo);
                return EXECUTION_FAILURE;
            }
            char sha_hex[41];
            int rc = bow_hash_and_write (type, content, clen, do_write, repo, sha_hex);
            free (content);
            if (rc < 0) {
                free (line); free (repo);
                return EXECUTION_FAILURE;
            }
            printf ("%s\n", sha_hex);
        }
        free (line); free (repo);
        return ferror (stdin) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }

    unsigned char *content;
    size_t clen;
    if (bow_slurp_stdin (&content, &clen) < 0) {
        free (repo);
        builtin_error ("hash: read stdin: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    char sha_hex[41];
    int rc = bow_hash_and_write (type, content, clen, do_write, repo, sha_hex);
    free (content); free (repo);
    if (rc < 0) return EXECUTION_FAILURE;

    if (var) builtin_bind_variable ((char *) var, sha_hex, 0);
    else     printf ("%s\n", sha_hex);
    return EXECUTION_SUCCESS;
}

/* blob FILE [-r REPO] [-V VAR] — sugar for hash -t blob -w with file input. */
static int
bow_blob_cmd (WORD_LIST *args)
{
    const char *file = NULL;
    const char *repo_arg = NULL;
    const char *var = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-r") == 0 && p->next) { repo_arg = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-V") == 0 && p->next) { var = p->next->word->word; p = p->next; }
        else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("blob: unknown flag %s", w); builtin_usage (); return EX_USAGE;
        } else {
            if (file) { builtin_error ("blob: too many args"); builtin_usage (); return EX_USAGE; }
            file = w;
        }
    }
    if (!file) { builtin_error ("blob: missing FILE"); builtin_usage (); return EX_USAGE; }

    bor_args ra = { .repo_arg = repo_arg };
    char *repo = bor_resolve_repo (&ra);
    if (!repo) return EXECUTION_FAILURE;

    int fd = open (file, O_RDONLY);
    if (fd < 0) {
        free (repo);
        builtin_error ("blob open %s: %s", file, strerror (errno));
        return EXECUTION_FAILURE;
    }
    struct stat st;
    if (fstat (fd, &st) < 0) {
        close (fd); free (repo); return EXECUTION_FAILURE;
    }
    unsigned char *content = malloc ((size_t) st.st_size);
    if (!content) { close (fd); free (repo); return EXECUTION_FAILURE; }
    ssize_t got = 0;
    while (got < st.st_size) {
        ssize_t r = read (fd, content + got, (size_t) (st.st_size - got));
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            free (content); close (fd); free (repo);
            return EXECUTION_FAILURE;
        }
        got += r;
    }
    close (fd);

    char sha_hex[41];
    int rc = bow_hash_and_write ("blob", content, (size_t) got, 1, repo, sha_hex);
    free (content); free (repo);
    if (rc < 0) return EXECUTION_FAILURE;

    if (var) builtin_bind_variable ((char *) var, sha_hex, 0);
    else     printf ("%s\n", sha_hex);
    return EXECUTION_SUCCESS;
}

/* tree [-r REPO] [-V VAR] — read "<mode> <name> <sha40>" lines from stdin,
   build tree object, hash, write. */
static int
bow_tree_cmd (WORD_LIST *args)
{
    const char *repo_arg = NULL;
    const char *var = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-r") == 0 && p->next) { repo_arg = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-V") == 0 && p->next) { var = p->next->word->word; p = p->next; }
        else { builtin_error ("tree: unexpected arg '%s'", w); builtin_usage (); return EX_USAGE; }
    }
    bor_args ra = { .repo_arg = repo_arg };
    char *repo = bor_resolve_repo (&ra);
    if (!repo) return EXECUTION_FAILURE;

    /* Build payload by reading lines from stdin. */
    size_t cap = 4096, n = 0;
    unsigned char *body = malloc (cap);
    if (!body) { free (repo); return EXECUTION_FAILURE; }

    char *line = NULL;
    size_t llen = 0;
    ssize_t got;
    FILE *in = stdin;
    while ((got = getline (&line, &llen, in)) > 0) {
        if (got > 0 && line[got - 1] == '\n') { line[got - 1] = '\0'; got--; }
        if (got == 0) continue;
        /* parse: MODE SP NAME SP SHA40 */
        char *sp1 = strchr (line, ' ');
        if (!sp1) continue;
        *sp1 = '\0';
        char *name = sp1 + 1;
        char *sp2 = strrchr (name, ' ');
        if (!sp2) continue;
        *sp2 = '\0';
        char *sha = sp2 + 1;
        if (strlen (sha) != 40) {
            free (line); free (body); free (repo);
            builtin_error ("tree: bad sha (must be 40 hex)");
            return EXECUTION_FAILURE;
        }
        /* Append "MODE SP NAME NUL <20-byte-sha>". */
        size_t need = strlen (line) + 1 + strlen (name) + 1 + 20;
        if (n + need > cap) {
            while (n + need > cap) cap *= 2;
            unsigned char *nb = realloc (body, cap);
            if (!nb) { free (line); free (body); free (repo); return EXECUTION_FAILURE; }
            body = nb;
        }
        memcpy (body + n, line, strlen (line));     n += strlen (line);
        body[n++] = ' ';
        memcpy (body + n, name, strlen (name));     n += strlen (name);
        body[n++] = '\0';
        for (int i = 0; i < 20; i++) {
            int hi = sha[2*i],   lo = sha[2*i+1];
            hi = (hi >= '0' && hi <= '9') ? hi - '0'
                 : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10
                 : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : 0;
            lo = (lo >= '0' && lo <= '9') ? lo - '0'
                 : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10
                 : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : 0;
            body[n++] = (unsigned char) ((hi << 4) | lo);
        }
    }
    free (line);

    char sha_hex[41];
    int rc = bow_hash_and_write ("tree", body, n, 1, repo, sha_hex);
    free (body); free (repo);
    if (rc < 0) return EXECUTION_FAILURE;
    if (var) builtin_bind_variable ((char *) var, sha_hex, 0);
    else     printf ("%s\n", sha_hex);
    return EXECUTION_SUCCESS;
}

/* commit -t TREE [-p PARENT...] -m MSG [-a "NAME <email>"] [-c "..."]
            [-d UNIXSEC] [-G GPGSIG_FILE] [-r REPO] [-V VAR]
   Builds a commit object. Timestamps default to now (UTC); -d pins them and
   -G injects a folded gpgsig header for signed commits. */
static int
bow_commit_cmd (WORD_LIST *args)
{
    const char *tree = NULL;
    const char *msg = NULL;
    const char *author = NULL;
    const char *committer = NULL;
    const char *repo_arg = NULL;
    const char *var = NULL;
    const char *gpgsig_file = NULL;
    long long fixed_ts = -1;
    /* Up to 16 parents — plenty. */
    const char *parents[16];
    int n_parents = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-t") == 0 && p->next) { tree = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-p") == 0 && p->next) {
            if (n_parents < 16) parents[n_parents++] = p->next->word->word;
            p = p->next;
        }
        else if (strcmp (w, "-m") == 0 && p->next) { msg = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-a") == 0 && p->next) { author = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-c") == 0 && p->next) { committer = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-d") == 0 && p->next) { fixed_ts = strtoll (p->next->word->word, NULL, 10); p = p->next; }
        else if (strcmp (w, "-G") == 0 && p->next) { gpgsig_file = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-r") == 0 && p->next) { repo_arg = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-V") == 0 && p->next) { var = p->next->word->word; p = p->next; }
        else { builtin_error ("commit: unexpected arg '%s'", w); builtin_usage (); return EX_USAGE; }
    }
    if (!tree) { builtin_error ("commit: -t TREE required"); builtin_usage (); return EX_USAGE; }
    if (!msg)  { builtin_error ("commit: -m MSG required"); builtin_usage (); return EX_USAGE; }
    if (strlen (tree) != 40) { builtin_error ("commit: bad tree sha"); builtin_usage (); return EX_USAGE; }

    bor_args ra = { .repo_arg = repo_arg };
    char *repo = bor_resolve_repo (&ra);
    if (!repo) return EXECUTION_FAILURE;

    /* Default identity = "obj <obj@bash-os>" */
    if (!author)    author    = "obj <obj@bash-os>";
    if (!committer) committer = author;
    /* Timestamp: now UTC. Format: "<unixsec> +0000". */
    char ts[64];
    snprintf (ts, sizeof ts, "%lld +0000", fixed_ts >= 0 ? fixed_ts : (long long) time (NULL));

    /* Build commit body. */
    size_t cap = 4096, n = 0;
    char *body = malloc (cap);
    if (!body) { free (repo); return EXECUTION_FAILURE; }
    int wrote;
#define BO_APPEND(...) do { \
    while (1) { \
        size_t left = cap - n; \
        wrote = snprintf (body + n, left, __VA_ARGS__); \
        if (wrote < 0) { free (body); free (repo); return EXECUTION_FAILURE; } \
        if ((size_t) wrote < left) { n += (size_t) wrote; break; } \
        cap *= 2; \
        char *nb = realloc (body, cap); \
        if (!nb) { free (body); free (repo); return EXECUTION_FAILURE; } \
        body = nb; \
    } \
} while (0)
    BO_APPEND ("tree %s\n", tree);
    for (int i = 0; i < n_parents; i++) BO_APPEND ("parent %s\n", parents[i]);
    BO_APPEND ("author %s %s\n", author, ts);
    BO_APPEND ("committer %s %s\n", committer, ts);
    if (gpgsig_file) {
        unsigned char *sig = NULL;
        size_t sig_len = 0;
        if (bow_slurp_file (gpgsig_file, &sig, &sig_len) < 0) {
            free (body); free (repo);
            return EXECUTION_FAILURE;
        }
        while (sig_len > 0 && (sig[sig_len - 1] == '\n' || sig[sig_len - 1] == '\r'))
            sig_len--;
        if (sig_len == 0) {
            builtin_error ("commit: empty gpgsig file");
            free (sig); free (body); free (repo);
            return EXECUTION_FAILURE;
        }
        BO_APPEND ("gpgsig ");
        for (size_t i = 0; i < sig_len; i++) {
            if (sig[i] == '\r') continue;
            if (sig[i] == '\n') BO_APPEND ("\n ");
            else BO_APPEND ("%c", sig[i]);
        }
        BO_APPEND ("\n");
        free (sig);
    }
    BO_APPEND ("\n%s", msg);
    /* Trailing newline if missing. */
    if (n == 0 || body[n - 1] != '\n') BO_APPEND ("\n");
#undef BO_APPEND

    char sha_hex[41];
    int rc = bow_hash_and_write ("commit", (unsigned char *) body, n, 1, repo, sha_hex);
    free (body); free (repo);
    if (rc < 0) return EXECUTION_FAILURE;
    if (var) builtin_bind_variable ((char *) var, sha_hex, 0);
    else     printf ("%s\n", sha_hex);
    return EXECUTION_SUCCESS;
}

/* tag -o OBJECT -n NAME [-T TYPE] [-m MSG] [-a "NAME <email>"]
        [-r REPO] [-V VAR]
   Builds an annotated tag object (object/type/tag/tagger\n\nmsg), hashes it
   with sha1dc and writes the loose object. Completes the blob/tree/commit/tag
   write quartet (read side already exists via cat/type/parse-*). TYPE defaults
   to commit; the tagger timestamp defaults to now (UTC), mirroring `commit`. */
static int
bow_tag_cmd (WORD_LIST *args)
{
    const char *object = NULL;
    const char *name = NULL;
    const char *type = "commit";
    const char *msg = NULL;
    const char *tagger = NULL;
    const char *repo_arg = NULL;
    const char *var = NULL;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-o") == 0 && p->next) { object = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-n") == 0 && p->next) { name = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-T") == 0 && p->next) { type = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-m") == 0 && p->next) { msg = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-a") == 0 && p->next) { tagger = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-r") == 0 && p->next) { repo_arg = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-V") == 0 && p->next) { var = p->next->word->word; p = p->next; }
        else { builtin_error ("tag: unexpected arg '%s'", w); builtin_usage (); return EX_USAGE; }
    }
    if (!object) { builtin_error ("tag: -o OBJECT required"); builtin_usage (); return EX_USAGE; }
    if (!name)   { builtin_error ("tag: -n NAME required"); builtin_usage (); return EX_USAGE; }
    if (strlen (object) != 40) { builtin_error ("tag: bad object sha"); builtin_usage (); return EX_USAGE; }
    if (strcmp (type, "blob") && strcmp (type, "tree")
        && strcmp (type, "commit") && strcmp (type, "tag")) {
        builtin_error ("tag: bad object type '%s'", type); builtin_usage (); return EX_USAGE;
    }

    bor_args ra = { .repo_arg = repo_arg };
    char *repo = bor_resolve_repo (&ra);
    if (!repo) return EXECUTION_FAILURE;

    /* Default identity = "obj <obj@bash-os>", message = empty. */
    if (!tagger) tagger = "obj <obj@bash-os>";
    if (!msg)    msg = "";
    char ts[64];
    snprintf (ts, sizeof ts, "%lld +0000", (long long) time (NULL));

    size_t cap = 4096, n = 0;
    char *body = malloc (cap);
    if (!body) { free (repo); return EXECUTION_FAILURE; }
    int wrote;
#define BO_APPEND(...) do { \
    while (1) { \
        size_t left = cap - n; \
        wrote = snprintf (body + n, left, __VA_ARGS__); \
        if (wrote < 0) { free (body); free (repo); return EXECUTION_FAILURE; } \
        if ((size_t) wrote < left) { n += (size_t) wrote; break; } \
        cap *= 2; \
        char *nb = realloc (body, cap); \
        if (!nb) { free (body); free (repo); return EXECUTION_FAILURE; } \
        body = nb; \
    } \
} while (0)
    BO_APPEND ("object %s\n", object);
    BO_APPEND ("type %s\n", type);
    BO_APPEND ("tag %s\n", name);
    BO_APPEND ("tagger %s %s\n", tagger, ts);
    BO_APPEND ("\n%s", msg);
    /* Trailing newline if missing (git tag objects end with one). */
    if (n == 0 || body[n - 1] != '\n') BO_APPEND ("\n");
#undef BO_APPEND

    char sha_hex[41];
    int rc = bow_hash_and_write ("tag", (unsigned char *) body, n, 1, repo, sha_hex);
    free (body); free (repo);
    if (rc < 0) return EXECUTION_FAILURE;
    if (var) builtin_bind_variable ((char *) var, sha_hex, 0);
    else     printf ("%s\n", sha_hex);
    return EXECUTION_SUCCESS;
}

int
obj_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    /* --batch, --batch-check and hash --stdin-paths read stdin with getline.
       A builtin does not fork, so the stream outlives the call: without this,
       the EOF flag from a previous invocation makes the next one read no
       objects at all and still exit 0. */
    clearerr (stdin);
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    /* read */
    if (!strcmp (cmd, "--batch"))      return bor_batch_cmd (args, 1);
    if (!strcmp (cmd, "--batch-check")) return bor_batch_cmd (args, 0);
    if (!strcmp (cmd, "cat"))          return bor_cat_cmd (args);
    if (!strcmp (cmd, "type"))         return bor_type_cmd (args);
    if (!strcmp (cmd, "size"))         return bor_size_cmd (args);
    if (!strcmp (cmd, "parse-tree"))   return bor_parse_tree_cmd (args);
    if (!strcmp (cmd, "parse-commit")) return bor_parse_commit_cmd (args);
    /* write (W-1b) */
    if (!strcmp (cmd, "hash"))         return bow_hash_cmd (args);
    if (!strcmp (cmd, "blob"))         return bow_blob_cmd (args);
    if (!strcmp (cmd, "tree"))         return bow_tree_cmd (args);
    if (!strcmp (cmd, "commit"))       return bow_commit_cmd (args);
    if (!strcmp (cmd, "tag"))          return bow_tag_cmd (args);
    builtin_error ("unknown verb: %s", cmd);
    builtin_usage ();
    return EX_USAGE;
}

char *obj_doc[] = {
    "Read + write loose git objects (zlib + sha1dc).",
    "",
    "  Read:",
    "    obj cat SHA [-r REPO] [-V VAR]      → object content",
    "    obj type SHA [-r REPO]              → blob/tree/commit/tag",
    "    obj size SHA [-r REPO]              → content size",
    "    obj --batch [-r REPO]               → '<sha> <type> <size>' + content",
    "    obj --batch-check [-r REPO]         → '<sha> <type> <size>'",
    "    obj parse-tree SHA [-r REPO] [-V VAR] [-z]",
    "        → '<mode> <name> <sha>' lines (or array entries)",
    "          -z: NUL-terminated '<mode> <sha>\\t<name>' records (ws-safe)",
    "    obj parse-commit SHA [-r REPO] [-V VAR]",
    "        → tree / parents / author / committer + body",
    "          With -V: binds <VAR>_tree, <VAR>_parents, _author,",
    "          _committer, _message",
    "",
    "  Write (W-1b — uses sha1dc collision-detecting SHA-1):",
    "    obj hash [--stdin|--stdin-paths] [--no-filters] [--literally]",
    "                 [-t TYPE] [-w] [-r REPO] [-V VAR]",
    "        Read stdin, hash, optionally -w write loose object.",
    "    obj blob FILE [-r REPO] [-V VAR]",
    "        Hash + write FILE as a blob.",
    "    obj tree [-r REPO] [-V VAR]",
    "        Read '<mode> <name> <sha40>' lines, build tree, write.",
    "    obj commit -t TREE [-p PARENT]... -m MSG",
    "                   [-a 'NAME <email>'] [-c 'NAME <email>']",
    "                   [-r REPO] [-V VAR]",
    "    obj tag -o OBJECT -n NAME [-T TYPE] [-m MSG]",
    "                [-a 'NAME <email>'] [-r REPO] [-V VAR]",
    "        Build + write an annotated tag object (TYPE default commit).",
    "",
    "Default repo = walk up from cwd looking for .git/.",
    "Pack access is handled by pack when available.",
    (char *)NULL
};

struct builtin obj_struct = {
    "obj",
    obj_builtin,
    BUILTIN_ENABLED,
    obj_doc,
    "obj cat|type|size|parse-tree|parse-commit|--batch|--batch-check|hash|blob|tree|commit|tag ARGS...",
    0
};
