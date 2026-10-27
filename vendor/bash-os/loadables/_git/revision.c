/* SPDX-License-Identifier: MIT */
/* _git/revision.c — revision syntax. See revision.h.
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
#include <ctype.h>

#include "loadables.h"

#include "odb.h"
#include "refs.h"
#include "repo.h"
#include "revision.h"
#include "tree.h"

/* One step of `<rev>:<path>`: the entry in a tree with exactly that path. */
struct bgit_rev_path_ctx {
    const char *want;
    char *out;
    int found;
};

static int
bgit_rev_path_visit (void *context, const char *mode, const char *type,
                     const char *sha, const char *path)
{
    (void) mode;
    (void) type;
    struct bgit_rev_path_ctx *ctx = context;
    if (strcmp (path, ctx->want)) return 0;
    memcpy (ctx->out, sha, 41);
    ctx->found = 1;
    return 1;
}

int
bgit_commit_parents (bgit_odb *odb, const char *sha, char parents[][41], int max)
{
    enum bgit_type type;
    unsigned char *data = NULL;
    size_t len = 0;
    if (bgit_odb_read (odb, sha, &type, &data, &len) < 0) return -1;
    if (type != BGIT_COMMIT) { free (data); return -1; }
    int n = 0;
    const char *p = (const char *) data;
    const char *end = p + len;
    while (p < end) {
        const char *nl = memchr (p, '\n', (size_t) (end - p));
        size_t line = nl ? (size_t) (nl - p) : (size_t) (end - p);
        if (!line) break;                       /* header ends */
        if (line > 7 && !memcmp (p, "parent ", 7) && n < max) {
            size_t take = line - 7 < 40 ? line - 7 : 40;
            memcpy (parents[n], p + 7, take);
            parents[n][take] = '\0';
            n++;
        }
        if (!nl) break;
        p = nl + 1;
    }
    free (data);
    return n;
}

int
bgit_commit_tree (bgit_odb *odb, const char *sha, char out[41])
{
    enum bgit_type type;
    unsigned char *data = NULL;
    size_t len = 0;
    if (bgit_odb_read (odb, sha, &type, &data, &len) < 0) return -1;
    if (type != BGIT_COMMIT) { free (data); return -1; }
    int rc = -1;
    if (len > 5 && !memcmp (data, "tree ", 5)) {
        memcpy (out, data + 5, 40);
        out[40] = '\0';
        rc = 0;
    }
    free (data);
    return rc;
}

/* The object a tag points at. */
static int
bgit_tag_target (bgit_odb *odb, const char *sha, char out[41],
                 enum bgit_type *target_type)
{
    enum bgit_type type;
    unsigned char *data = NULL;
    size_t len = 0;
    if (bgit_odb_read (odb, sha, &type, &data, &len) < 0) return -1;
    if (type != BGIT_TAG) { free (data); return -1; }
    int rc = -1;
    const char *p = (const char *) data;
    const char *end = p + len;
    char object[41] = "";
    char kind[32] = "";
    while (p < end) {
        const char *nl = memchr (p, '\n', (size_t) (end - p));
        size_t line = nl ? (size_t) (nl - p) : (size_t) (end - p);
        if (!line) break;
        if (line > 7 && !memcmp (p, "object ", 7) && line - 7 >= 40) {
            memcpy (object, p + 7, 40);
            object[40] = '\0';
        } else if (line > 5 && !memcmp (p, "type ", 5)) {
            size_t take = line - 5 < sizeof kind - 1 ? line - 5 : sizeof kind - 1;
            memcpy (kind, p + 5, take);
            kind[take] = '\0';
        }
        if (!nl) break;
        p = nl + 1;
    }
    free (data);
    if (object[0]) {
        memcpy (out, object, 41);
        if (target_type) {
            *target_type = !strcmp (kind, "commit") ? BGIT_COMMIT
                         : !strcmp (kind, "tree") ? BGIT_TREE
                         : !strcmp (kind, "blob") ? BGIT_BLOB
                         : !strcmp (kind, "tag") ? BGIT_TAG : BGIT_UNKNOWN;
        }
        rc = 0;
    }
    return rc;
}

static int
bgit_object_type (bgit_odb *odb, const char *sha, enum bgit_type *type)
{
    unsigned char *data = NULL;
    size_t len = 0;
    if (bgit_odb_read (odb, sha, type, &data, &len) < 0) return -1;
    free (data);
    return 0;
}

int
bgit_peel_to_type (bgit_odb *odb, const char *sha, enum bgit_type want,
                   char out[41])
{
    char current[41];
    memcpy (current, sha, 41);
    for (int step = 0; step < 16; step++) {
        enum bgit_type type;
        if (bgit_object_type (odb, current, &type) < 0) return -1;
        if (want == BGIT_UNKNOWN) {
            /* ^{} peels a tag once, and leaves anything else alone. */
            if (type != BGIT_TAG) { memcpy (out, current, 41); return 0; }
            char target[41];
            if (bgit_tag_target (odb, current, target, NULL) < 0) return -1;
            memcpy (out, target, 41);
            return 0;
        }
        if (type == want) { memcpy (out, current, 41); return 0; }
        if (type == BGIT_TAG) {
            char target[41];
            if (bgit_tag_target (odb, current, target, NULL) < 0) return -1;
            memcpy (current, target, 41);
            continue;
        }
        if (type == BGIT_COMMIT && want == BGIT_TREE) {
            char tree[41];
            if (bgit_commit_tree (odb, current, tree) < 0) return -1;
            memcpy (out, tree, 41);
            return 0;
        }
        return -1;
    }
    return -1;
}

/* The base of an expression: an id, an abbreviation, or a ref, looked for
   under the prefixes git searches. */
static int
bgit_rev_base (const bgit_repo *repo, bgit_odb *odb, const char *name,
               char out[41], char **symref)
{
    if (!*name) return -1;
    if (symref) { free (*symref); *symref = NULL; }
    char full[41];
    if (bgit_ref_resolve (repo, name, full, symref) == 0) {
        memcpy (out, full, 41);
        if (symref && !*symref && strchr (name, '/')) *symref = strdup (name);
        return 0;
    }
    if (symref && *symref) { free (*symref); *symref = NULL; }
    /* FETCH_HEAD is a list rather than a ref — an id, what a merge should
       make of it, and where it came from, a line for each — and naming it
       means the first of them, which is what git reads too. */
    if (!strchr (name, '/') && repo->git_dir) {
        char path[4096];
        if (snprintf (path, sizeof path, "%s/%s", repo->git_dir, name) <
            (int) sizeof path) {
            FILE *file = fopen (path, "r");
            char line[4096];
            if (file) {
                int got = fgets (line, sizeof line, file) != NULL &&
                          strlen (line) > 40 &&
                          (line[40] == ' ' || line[40] == '\t');
                for (int i = 0; got && i < 40; i++)
                    if (!isxdigit ((unsigned char) line[i])) got = 0;
                fclose (file);
                if (got) {
                    memcpy (out, line, 40);
                    out[40] = '\0';
                    if (symref) *symref = strdup (name);
                    return 0;
                }
            }
        }
    }
    static const char *const prefixes[] = {
        "refs/", "refs/tags/", "refs/heads/", "refs/remotes/", NULL
    };
    for (int i = 0; prefixes[i]; i++) {
        char candidate[4096];
        if (snprintf (candidate, sizeof candidate, "%s%s", prefixes[i], name) >=
            (int) sizeof candidate)
            continue;
        if (bgit_ref_read (repo, candidate, out) == 0) {
            if (symref) *symref = strdup (candidate);
            return 0;
        }
    }
    if (bgit_all_hex (name) && strlen (name) >= 4 && strlen (name) <= 40) {
        int was_quiet = odb->quiet;
        odb->quiet = 1;
        int rc = bgit_odb_resolve (odb, name, out);
        odb->quiet = was_quiet;
        if (rc == 0) return 0;
    }
    return -1;
}

/* The value a ref had N changes ago, from its reflog. */
static int
bgit_rev_reflog (const bgit_repo *repo, const char *refname, long n,
                 char out[41])
{
    char **lines = NULL;
    size_t count = 0;
    if (bgit_reflog_lines (repo, refname, &lines, &count) != 0 || !count)
        return -1;
    int rc = -1;
    /* Entries are oldest first: "<old> <new> <ident>\t<message>". @{0} is
       what the ref holds now, @{n} what it held n changes ago. */
    if (n == 0) {
        if (strlen (lines[count - 1]) >= 81) {
            memcpy (out, lines[count - 1] + 41, 40);
            out[40] = '\0';
            rc = 0;
        }
    } else if ((size_t) n <= count) {
        const char *line = lines[count - (size_t) n];
        if (strlen (line) >= 40) {
            memcpy (out, line, 40);
            out[40] = '\0';
            rc = 0;
        }
    }
    for (size_t i = 0; i < count; i++) free (lines[i]);
    free (lines);
    return rc;
}

int
bgit_rev_parse (const bgit_repo *repo, bgit_odb *odb, const char *spec,
                char out[41], char **symref)
{
    if (symref) *symref = NULL;
    if (!spec || !*spec) return -1;

    /* `<rev>:<path>` names what a path held in that revision. A leading
       colon would name the index instead, which is not read here. */
    const char *colon = strchr (spec, ':');
    if (colon == spec) return -1;
    if (colon) {
        char rev[4096];
        size_t len = (size_t) (colon - spec);
        if (len >= sizeof rev) return -1;
        memcpy (rev, spec, len);
        rev[len] = '\0';
        char id[41], tree[41];
        if (bgit_rev_parse (repo, odb, rev, id, NULL) < 0 ||
            bgit_peel_to_type (odb, id, BGIT_TREE, tree) < 0)
            return -1;
        if (!colon[1]) { memcpy (out, tree, 41); return 0; }
        struct bgit_rev_path_ctx ctx = { colon + 1, out, 0 };
        bgit_tree_walk (odb, tree, "", 1, 1, bgit_rev_path_visit, &ctx);
        return ctx.found ? 0 : -1;
    }

    /* Split the base from its suffixes. Ref names cannot hold ^ or ~, and a
       @{ only starts a suffix, so the first of those ends the base. */
    size_t base_len = strlen (spec);
    for (size_t i = 0; spec[i]; i++) {
        if (spec[i] == '^' || spec[i] == '~' ||
            (spec[i] == '@' && spec[i + 1] == '{')) {
            base_len = i;
            break;
        }
    }
    if (!base_len) return -1;
    char base[4096];
    if (base_len >= sizeof base) return -1;
    memcpy (base, spec, base_len);
    base[base_len] = '\0';

    char current[41];
    char *base_ref = NULL;
    if (bgit_rev_base (repo, odb, base, current, &base_ref) < 0) {
        free (base_ref);
        return -1;
    }

    const char *p = spec + base_len;
    while (*p) {
        if (*p == '@' && p[1] == '{') {
            const char *close = strchr (p, '}');
            if (!close || !base_ref) { free (base_ref); return -1; }
            char inside[64];
            size_t len = (size_t) (close - p - 2);
            if (len >= sizeof inside) { free (base_ref); return -1; }
            memcpy (inside, p + 2, len);
            inside[len] = '\0';
            char *end = NULL;
            long n = strtol (inside, &end, 10);
            if (!end || *end || n < 0) { free (base_ref); return -1; }
            if (bgit_rev_reflog (repo, base_ref, n, current) < 0) {
                free (base_ref);
                return -1;
            }
            p = close + 1;
            continue;
        }
        if (*p == '~') {
            p++;
            long n = 1;
            if (isdigit ((unsigned char) *p)) {
                char *end = NULL;
                n = strtol (p, &end, 10);
                p = end;
            }
            for (long step = 0; step < n; step++) {
                char peeled[41];
                if (bgit_peel_to_type (odb, current, BGIT_COMMIT, peeled) < 0) {
                    free (base_ref); return -1;
                }
                char parents[BGIT_MAX_PARENTS][41];
                int count = bgit_commit_parents (odb, peeled, parents,
                                                 BGIT_MAX_PARENTS);
                if (count < 1) { free (base_ref); return -1; }
                memcpy (current, parents[0], 41);
            }
            continue;
        }
        if (*p == '^') {
            p++;
            if (*p == '{') {
                const char *close = strchr (p, '}');
                if (!close) { free (base_ref); return -1; }
                char inside[32];
                size_t len = (size_t) (close - p - 1);
                if (len >= sizeof inside) { free (base_ref); return -1; }
                memcpy (inside, p + 1, len);
                inside[len] = '\0';
                enum bgit_type want = BGIT_UNKNOWN;
                if (!*inside) want = BGIT_UNKNOWN;                 /* ^{} */
                else if (!strcmp (inside, "commit")) want = BGIT_COMMIT;
                else if (!strcmp (inside, "tree")) want = BGIT_TREE;
                else if (!strcmp (inside, "blob")) want = BGIT_BLOB;
                else if (!strcmp (inside, "tag")) want = BGIT_TAG;
                else { free (base_ref); return -1; }
                char peeled[41];
                if (bgit_peel_to_type (odb, current, want, peeled) < 0) {
                    free (base_ref); return -1;
                }
                memcpy (current, peeled, 41);
                p = close + 1;
                continue;
            }
            long n = 1;
            if (isdigit ((unsigned char) *p)) {
                char *end = NULL;
                n = strtol (p, &end, 10);
                p = end;
            }
            char peeled[41];
            if (bgit_peel_to_type (odb, current, BGIT_COMMIT, peeled) < 0) {
                free (base_ref); return -1;
            }
            if (n == 0) {   /* ^0 is the commit itself */
                memcpy (current, peeled, 41);
                continue;
            }
            char parents[BGIT_MAX_PARENTS][41];
            int count = bgit_commit_parents (odb, peeled, parents,
                                             BGIT_MAX_PARENTS);
            if (count < n) { free (base_ref); return -1; }
            memcpy (current, parents[n - 1], 41);
            continue;
        }
        free (base_ref);
        return -1;
    }
    memcpy (out, current, 41);
    if (symref) *symref = base_ref;
    else free (base_ref);
    return 0;
}
