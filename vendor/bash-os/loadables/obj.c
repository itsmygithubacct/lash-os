/* SPDX-License-Identifier: MIT */
/* obj.c — git object access.
 *
 * The object store lives in _git/: odb.c holds the loose format and hashing,
 * store.c looks an object up across loose objects, every pack and the
 * alternates, and repo.c finds the repository. This file is the command
 * surface over them, so `obj cat` reads an object whether it is loose or in a
 * pack, in a worktree, a linked worktree or a bare repository.
 *
 * Verbs:
 *   obj cat SHA [-r REPO] [-V VAR]
 *       Emit object content. -V binds to a bash variable (truncates at NUL
 *       — use the stdout form for binary content).
 *
 *   obj --batch|--batch-check [-r REPO]
 *       Read object names from stdin and emit git cat-file compatible
 *       batch records.
 *
 *   obj type|size SHA [-r REPO]
 *       Print the type token (blob/tree/commit/tag), or the content size.
 *
 *   obj parse-tree SHA [-r REPO] [-V VAR] [-z]
 *       Emit each tree entry as "<mode> <name> <sha>". With -V, binds a bash
 *       array (one element per entry).
 *
 *   obj parse-commit SHA [-r REPO] [-V VAR]
 *       Emit commit fields one per line: "tree <sha>", "parent <sha>"
 *       (zero or more), "author <line>", "committer <line>", then a
 *       blank line and the message body. With -V, binds <PFX>_tree,
 *       <PFX>_parents (space-joined), <PFX>_author, <PFX>_committer,
 *       <PFX>_message.
 *
 *   obj hash|blob|tree|commit|tag
 *       Hash and write objects; see obj_doc below.
 *
 *   -r REPO   a worktree, a bare repository, or a git directory. Defaults to
 *             the repository containing the current directory, found as git
 *             does, following a .git file to its target.
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
#include <time.h>

#include "loadables.h"
#include "arrayfunc.h"

#include "_git_odb.h"
#include "_git_repo.h"

/* git cat-file exits 128 ("fatal") on a missing/unresolvable/malformed
   object. We match that for object-read failures so scripts that branch on
   `$?` behave identically against git and obj. Usage errors keep
   EX_USAGE; this is only for the object-read/resolve paths. */
#define BO_EX_FATAL 128

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

/* Open the repository REPO_ARG names, or the one containing the current
   directory, together with its object store. */
static int
bor_open (const char *repo_arg, bgit_repo *repo, bgit_odb *odb)
{
    int rc = repo_arg ? bgit_repo_open (repo_arg, repo)
                      : bgit_repo_discover (".", repo);
    if (rc < 0) {
        if (repo_arg) builtin_error ("not a git repo: %s", repo_arg);
        else          builtin_error ("not in a git repo");
        return -1;
    }
    if (bgit_odb_open (repo, odb) < 0) {
        builtin_error ("cannot read the object store of %s", repo->git_dir);
        bgit_repo_release (repo);
        return -1;
    }
    return 0;
}

static void
bor_close (bgit_repo *repo, bgit_odb *odb)
{
    bgit_odb_release (odb);
    bgit_repo_release (repo);
}

/* ---- verb implementations ---- */

static int
bor_cat_cmd (WORD_LIST *args)
{
    bor_args a;
    if (bor_parse_args (args, &a) < 0) return EX_USAGE;
    bgit_repo repo; bgit_odb odb;
    if (bor_open (a.repo_arg, &repo, &odb) < 0) return BO_EX_FATAL;

    enum bgit_type type;
    unsigned char *data;
    size_t len;
    if (bgit_odb_read (&odb, a.sha, &type, &data, &len) < 0) {
        bor_close (&repo, &odb);
        return BO_EX_FATAL;
    }
    if (a.var) {
        /* NUL-truncated, but useful for blobs / commit messages. */
        char *s = malloc (len + 1);
        if (s) {
            memcpy (s, data, len);
            s[len] = '\0';
            builtin_bind_variable ((char *) a.var, s, 0);
            free (s);
        }
    } else {
        fwrite (data, 1, len, stdout);
    }
    free (data);
    bor_close (&repo, &odb);
    return EXECUTION_SUCCESS;
}

static int
bor_type_cmd (WORD_LIST *args)
{
    bor_args a;
    if (bor_parse_args (args, &a) < 0) return EX_USAGE;
    bgit_repo repo; bgit_odb odb;
    if (bor_open (a.repo_arg, &repo, &odb) < 0) return BO_EX_FATAL;

    enum bgit_type type;
    unsigned char *data;
    size_t len;
    if (bgit_odb_read (&odb, a.sha, &type, &data, &len) < 0) {
        bor_close (&repo, &odb);
        return BO_EX_FATAL;
    }
    printf ("%s\n", bgit_type_name (type));
    free (data);
    bor_close (&repo, &odb);
    return EXECUTION_SUCCESS;
}

static int
bor_size_cmd (WORD_LIST *args)
{
    bor_args a;
    if (bor_parse_args (args, &a) < 0) return EX_USAGE;
    bgit_repo repo; bgit_odb odb;
    if (bor_open (a.repo_arg, &repo, &odb) < 0) return BO_EX_FATAL;

    enum bgit_type type;
    unsigned char *data;
    size_t len;
    if (bgit_odb_read (&odb, a.sha, &type, &data, &len) < 0) {
        bor_close (&repo, &odb);
        return BO_EX_FATAL;
    }
    printf ("%zu\n", len);
    free (data);
    bor_close (&repo, &odb);
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

    bgit_repo repo; bgit_odb odb;
    if (bor_open (repo_arg, &repo, &odb) < 0)
        return BO_EX_FATAL;

    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    while ((nread = getline (&line, &cap, stdin)) >= 0) {
        while (nread > 0 && (line[nread - 1] == '\n' || line[nread - 1] == '\r'))
            line[--nread] = '\0';

        /* A name git cannot resolve is reported as missing, not as an error. */
        char full[41];
        if (nread <= 0 || !bgit_all_hex (line) || strlen (line) > 40) {
            printf ("%s missing\n", line);
            continue;
        }
        if (strlen (line) == 40) {
            memcpy (full, line, 41);
            if (!bgit_odb_has (&odb, full)) {
                printf ("%s missing\n", line);
                continue;
            }
        } else if (bgit_odb_resolve (&odb, line, full) < 0) {
            printf ("%s missing\n", line);
            continue;
        }

        enum bgit_type type;
        unsigned char *data;
        size_t len;
        if (bgit_odb_read (&odb, full, &type, &data, &len) < 0) {
            printf ("%s missing\n", line);
            continue;
        }
        printf ("%s %s %zu\n", full, bgit_type_name (type), len);
        if (emit_content) {
            fwrite (data, 1, len, stdout);
            putchar ('\n');
        }
        free (data);
    }

    free (line);
    bor_close (&repo, &odb);
    return EXECUTION_SUCCESS;
}

static int
bor_parse_tree_cmd (WORD_LIST *args)
{
    bor_args a;
    if (bor_parse_args (args, &a) < 0) return EX_USAGE;
    bgit_repo repo; bgit_odb odb;
    if (bor_open (a.repo_arg, &repo, &odb) < 0) return BO_EX_FATAL;

    enum bgit_type type;
    unsigned char *obj;
    size_t len;
    if (bgit_odb_read (&odb, a.sha, &type, &obj, &len) < 0) {
        bor_close (&repo, &odb);
        return BO_EX_FATAL;
    }
    bor_close (&repo, &odb);
    if (type != BGIT_TREE) {
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

    size_t pos = 0;
    while (pos < len) {
        /* mode: ASCII digits up to space. */
        size_t ms = pos;
        while (pos < len && obj[pos] != ' ') pos++;
        if (pos >= len) { builtin_error ("malformed tree (mode)"); free (obj); return EXECUTION_FAILURE; }
        size_t ml = pos - ms;
        pos++;  /* skip space */
        size_t ns = pos;
        while (pos < len && obj[pos] != '\0') pos++;
        if (pos >= len) { builtin_error ("malformed tree (name)"); free (obj); return EXECUTION_FAILURE; }
        size_t nl = pos - ns;
        pos++;  /* skip NUL */
        if (pos + 20 > len) { builtin_error ("malformed tree (sha)"); free (obj); return EXECUTION_FAILURE; }

        char hex[41];
        bgit_sha_to_hex (obj + pos, hex);
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
    bgit_repo repo; bgit_odb odb;
    if (bor_open (a.repo_arg, &repo, &odb) < 0) return BO_EX_FATAL;

    enum bgit_type type;
    unsigned char *obj;
    size_t len;
    if (bgit_odb_read (&odb, a.sha, &type, &obj, &len) < 0) {
        bor_close (&repo, &odb);
        return BO_EX_FATAL;
    }
    bor_close (&repo, &odb);
    if (type != BGIT_COMMIT) {
        builtin_error ("not a commit object");
        free (obj); return BO_EX_FATAL;
    }
    /* Walk lines. */
    char tree[64] = "";
    char author[1024] = "", committer[1024] = "";
    char parents[8192] = "";
    char *p = (char *) obj;
    char *end = (char *) obj + len;
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

/* ===== write path =========================================================
 * Verbs: hash, blob, tree, commit, tag. All hash via sha1dc and (with -w /
 * by default for blob/tree/commit/tag) write a loose object into the
 * repository's own objects directory. */

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

    if (!bgit_type_valid_name (type) && !literally) {
        builtin_error ("hash: invalid object type '%s'", type);
        builtin_usage ();
        return EX_USAGE;
    }
    if (literally && !bgit_type_printable (type)) {
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

    bgit_repo repo; bgit_odb odb;
    char *objects = NULL;
    if (do_write) {
        if (bor_open (repo_arg, &repo, &odb) < 0) return EXECUTION_FAILURE;
        objects = odb.object_dirs[0];
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
            if (bgit_slurp_file (line, &content, &clen) < 0) {
                free (line);
                if (do_write) bor_close (&repo, &odb);
                return EXECUTION_FAILURE;
            }
            char sha_hex[41];
            int rc = bgit_write_object (objects, type, content, clen, do_write, sha_hex);
            free (content);
            if (rc < 0) {
                free (line);
                if (do_write) bor_close (&repo, &odb);
                return EXECUTION_FAILURE;
            }
            printf ("%s\n", sha_hex);
        }
        free (line);
        if (do_write) bor_close (&repo, &odb);
        return ferror (stdin) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }

    unsigned char *content;
    size_t clen;
    if (bgit_slurp_fd (STDIN_FILENO, &content, &clen) < 0) {
        if (do_write) bor_close (&repo, &odb);
        builtin_error ("hash: read stdin: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    char sha_hex[41];
    int rc = bgit_write_object (objects, type, content, clen, do_write, sha_hex);
    free (content);
    if (do_write) bor_close (&repo, &odb);
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

    bgit_repo repo; bgit_odb odb;
    if (bor_open (repo_arg, &repo, &odb) < 0) return EXECUTION_FAILURE;

    int fd = open (file, O_RDONLY);
    if (fd < 0) {
        bor_close (&repo, &odb);
        builtin_error ("blob open %s: %s", file, strerror (errno));
        return EXECUTION_FAILURE;
    }
    unsigned char *content = NULL;
    size_t clen = 0;
    if (bgit_slurp_fd (fd, &content, &clen) < 0) {
        close (fd); bor_close (&repo, &odb);
        builtin_error ("blob read %s: %s", file, strerror (errno));
        return EXECUTION_FAILURE;
    }
    close (fd);

    char sha_hex[41];
    int rc = bgit_write_object (odb.object_dirs[0], "blob", content, clen, 1, sha_hex);
    free (content);
    bor_close (&repo, &odb);
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
    bgit_repo repo; bgit_odb odb;
    if (bor_open (repo_arg, &repo, &odb) < 0) return EXECUTION_FAILURE;

    /* Build payload by reading lines from stdin. */
    size_t cap = 4096, n = 0;
    unsigned char *body = malloc (cap);
    if (!body) { bor_close (&repo, &odb); return EXECUTION_FAILURE; }

    char *line = NULL;
    size_t llen = 0;
    ssize_t got;
    while ((got = getline (&line, &llen, stdin)) > 0) {
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
            free (line); free (body); bor_close (&repo, &odb);
            builtin_error ("tree: bad sha (must be 40 hex)");
            return EXECUTION_FAILURE;
        }
        /* Append "MODE SP NAME NUL <20-byte-sha>". */
        size_t need = strlen (line) + 1 + strlen (name) + 1 + 20;
        if (n + need > cap) {
            while (n + need > cap) cap *= 2;
            unsigned char *nb = realloc (body, cap);
            if (!nb) { free (line); free (body); bor_close (&repo, &odb); return EXECUTION_FAILURE; }
            body = nb;
        }
        memcpy (body + n, line, strlen (line));     n += strlen (line);
        body[n++] = ' ';
        memcpy (body + n, name, strlen (name));     n += strlen (name);
        body[n++] = '\0';
        unsigned char binary[20];
        if (bgit_hex_to_sha (sha, binary) < 0) {
            free (line); free (body); bor_close (&repo, &odb);
            builtin_error ("tree: bad sha (must be 40 hex)");
            return EXECUTION_FAILURE;
        }
        memcpy (body + n, binary, 20);
        n += 20;
    }
    free (line);

    char sha_hex[41];
    int rc = bgit_write_object (odb.object_dirs[0], "tree", body, n, 1, sha_hex);
    free (body);
    bor_close (&repo, &odb);
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

    bgit_repo repo; bgit_odb odb;
    if (bor_open (repo_arg, &repo, &odb) < 0) return EXECUTION_FAILURE;

    /* Default identity = "obj <obj@bash-os>" */
    if (!author)    author    = "obj <obj@bash-os>";
    if (!committer) committer = author;
    /* Timestamp: now UTC. Format: "<unixsec> +0000". */
    char ts[64];
    snprintf (ts, sizeof ts, "%lld +0000", fixed_ts >= 0 ? fixed_ts : (long long) time (NULL));

    /* Build commit body. */
    size_t cap = 4096, n = 0;
    char *body = malloc (cap);
    if (!body) { bor_close (&repo, &odb); return EXECUTION_FAILURE; }
    int wrote;
#define BO_APPEND(...) do { \
    while (1) { \
        size_t left = cap - n; \
        wrote = snprintf (body + n, left, __VA_ARGS__); \
        if (wrote < 0) { free (body); bor_close (&repo, &odb); return EXECUTION_FAILURE; } \
        if ((size_t) wrote < left) { n += (size_t) wrote; break; } \
        cap *= 2; \
        char *nb = realloc (body, cap); \
        if (!nb) { free (body); bor_close (&repo, &odb); return EXECUTION_FAILURE; } \
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
        if (bgit_slurp_file (gpgsig_file, &sig, &sig_len) < 0) {
            free (body); bor_close (&repo, &odb);
            return EXECUTION_FAILURE;
        }
        while (sig_len > 0 && (sig[sig_len - 1] == '\n' || sig[sig_len - 1] == '\r'))
            sig_len--;
        if (sig_len == 0) {
            builtin_error ("commit: empty gpgsig file");
            free (sig); free (body); bor_close (&repo, &odb);
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
    int rc = bgit_write_object (odb.object_dirs[0], "commit",
                               (unsigned char *) body, n, 1, sha_hex);
    free (body);
    bor_close (&repo, &odb);
    if (rc < 0) return EXECUTION_FAILURE;
    if (var) builtin_bind_variable ((char *) var, sha_hex, 0);
    else     printf ("%s\n", sha_hex);
    return EXECUTION_SUCCESS;
}

/* tag -o OBJECT -n NAME [-T TYPE] [-m MSG] [-a "NAME <email>"]
        [-r REPO] [-V VAR]
   Builds an annotated tag object (object/type/tag/tagger\n\nmsg), hashes it
   with sha1dc and writes the loose object. TYPE defaults to commit; the
   tagger timestamp defaults to now (UTC), mirroring `commit`. */
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
    if (!bgit_type_valid_name (type)) {
        builtin_error ("tag: bad object type '%s'", type); builtin_usage (); return EX_USAGE;
    }

    bgit_repo repo; bgit_odb odb;
    if (bor_open (repo_arg, &repo, &odb) < 0) return EXECUTION_FAILURE;

    /* Default identity = "obj <obj@bash-os>", message = empty. */
    if (!tagger) tagger = "obj <obj@bash-os>";
    if (!msg)    msg = "";
    char ts[64];
    snprintf (ts, sizeof ts, "%lld +0000", (long long) time (NULL));

    size_t cap = 4096, n = 0;
    char *body = malloc (cap);
    if (!body) { bor_close (&repo, &odb); return EXECUTION_FAILURE; }
    int wrote;
#define BO_APPEND(...) do { \
    while (1) { \
        size_t left = cap - n; \
        wrote = snprintf (body + n, left, __VA_ARGS__); \
        if (wrote < 0) { free (body); bor_close (&repo, &odb); return EXECUTION_FAILURE; } \
        if ((size_t) wrote < left) { n += (size_t) wrote; break; } \
        cap *= 2; \
        char *nb = realloc (body, cap); \
        if (!nb) { free (body); bor_close (&repo, &odb); return EXECUTION_FAILURE; } \
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
    int rc = bgit_write_object (odb.object_dirs[0], "tag",
                               (unsigned char *) body, n, 1, sha_hex);
    free (body);
    bor_close (&repo, &odb);
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
    /* write */
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
    "Read + write git objects (loose or packed; zlib + sha1dc).",
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
    "  Write (uses sha1dc collision-detecting SHA-1):",
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
    "Reads search loose objects, every pack, and the alternates named by",
    "objects/info/alternates or GIT_ALTERNATE_OBJECT_DIRECTORIES. The repo",
    "is -r REPO, GIT_DIR, or the one containing the current directory; a",
    "linked worktree's .git file and a bare repository both work.",
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
