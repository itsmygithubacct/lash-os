/* bashfind.c — POSIX-shape find(1) as a bash builtin.
 *
 * Phase A of bash-os shell-ergonomics. Recursive walker + predicate
 * expression tree + cycle detection (via dev/inode tuple set).
 *
 * Supported predicates: -name, -iname, -path, -type, -size, -mtime,
 * -mmin, -amin, -cmin, -atime, -ctime, -perm, -user, -group,
 * -uid, -gid, -nouser, -nogroup, -regex, -iregex, -maxdepth,
 * -mindepth, -xdev/-mount, -prune, -empty, -newer.
 * Operators: `-a` (implicit AND between predicates), `-o`, `!`,
 *           `(` `)`.
 * Actions: -print (default), -print0, -printf FORMAT, -delete,
 *          -exec ... \;, -exec ... {} +, -execdir.
 *
 * Out of scope: -links, -inum, -anewer.
 *
 * No static globals — per-call options live on the stack. Walker uses
 * a small (dev,ino) set to avoid symlink-loop infinite recursion.
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
#include <dirent.h>
#include <fnmatch.h>
#include <regex.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>

#include "loadables.h"
#include "command-run.h"

/* Predicate kinds. */
typedef enum {
    BF_AND, BF_OR, BF_NOT,
    BF_NAME, BF_INAME, BF_PATH,
    BF_TYPE, BF_SIZE, BF_MTIME, BF_MAXDEPTH, BF_MINDEPTH, BF_XDEV,
    BF_PRUNE, BF_EMPTY, BF_NEWER,
    BF_PRINT, BF_PRINT0, BF_PRINTF, BF_EXEC, BF_EXECDIR, BF_DELETE,
    BF_MMIN, BF_AMIN, BF_CMIN, BF_ATIME, BF_CTIME,
    BF_REGEX, BF_IREGEX,
    BF_PERM, BF_USER, BF_GROUP, BF_UID, BF_GID, BF_NOUSER, BF_NOGROUP,
    BF_TRUE, BF_FALSE
} bf_kind;

typedef struct bf_expr {
    bf_kind        kind;
    struct bf_expr *a, *b;     /* AND/OR/NOT operands */
    char          *sval;       /* glob pattern, type char, etc. */
    long long      nval;       /* size/mtime/depth */
    int            ncmp;       /* -1: <N, 0: =N, +1: >N (for size/mtime) */
    time_t         tval;       /* -newer reference mtime (seconds) */
    long           tnsec;      /* -newer reference mtime (nanoseconds) */
    /* For BF_EXEC / BF_EXECDIR: argv template terminated by NULL.
       exec_batch: 0 = `\;` (per-file), 1 = `+` (batched until ARG_MAX). */
    char         **exec_argv;
    int            exec_argc;
    int            exec_batch;
    /* For BF_EXEC `+` form: per-node pending batch. */
    char         **pending_paths;
    size_t         pending_count;
    size_t         pending_cap;
    size_t         pending_bytes;
    /* For BF_REGEX / BF_IREGEX: compiled regex. */
    regex_t        re;
    int            re_ok;
} bf_expr;

/* Symlink-traversal mode. POSIX find takes the first non-option arg as
   one of -H, -L, -P:
     BF_FOLLOW_NONE (-P, default): never follow symlinks (lstat throughout).
     BF_FOLLOW_ARGS (-H): follow symlinks named on the command line, but
                         lstat() everything found via recursion.
     BF_FOLLOW_ALL  (-L): always follow symlinks (stat() throughout). When
                         a symlink would create a directory loop, the
                         existing (dev,ino) seen-set breaks it. */
typedef enum {
    BF_FOLLOW_NONE = 0,
    BF_FOLLOW_ARGS = 1,
    BF_FOLLOW_ALL  = 2
} bf_follow;

typedef struct {
    bf_expr *root;
    int      maxdepth;         /* -1 = unbounded */
    int      mindepth;         /* 0 = no min */
    int      pruned;           /* set by -prune for current dir */
    int      had_action;       /* if no -print/-print0 specified, default to -print */
    int      print0;           /* default action: 0 = newline, 1 = NUL */
    bf_follow follow;          /* -H/-L/-P semantics */
    int      xdev;             /* -xdev/-mount: do not descend across devices */
    int      root_dev_valid;   /* root_dev is set once per starting path */
    dev_t    root_dev;
    int      postorder;        /* set by -delete: evaluate after children */
    int      exit_status;      /* 1 if any non-ENOENT stat/opendir/etc. failed */
    const char *start_path;    /* current command-line starting point (depth 0); for -printf %P */
} bf_ctx;

typedef struct {
    const char    *path;
    const char    *base;        /* basename within path */
    const char    *root;        /* command-line starting point (for -printf %P) */
    int            depth;
    struct stat    st;
} bf_pinfo;

/* ---- expression parser ---- */

typedef struct {
    int          argc;
    char       **argv;
    int          pos;
} bf_parse;

static const char *bf_peek (bf_parse *p) { return (p->pos < p->argc) ? p->argv[p->pos] : NULL; }
static void        bf_advance (bf_parse *p) { p->pos++; }

static bf_expr *
bf_alloc (bf_kind k)
{
    bf_expr *e = calloc (1, sizeof *e);
    if (e) e->kind = k;
    return e;
}

static void
bf_free (bf_expr *e)
{
    if (!e) return;
    bf_free (e->a);
    bf_free (e->b);
    free (e->sval);
    if (e->exec_argv) {
        for (int i = 0; i < e->exec_argc; i++) free (e->exec_argv[i]);
        free (e->exec_argv);
    }
    if (e->pending_paths) {
        for (size_t i = 0; i < e->pending_count; i++) free (e->pending_paths[i]);
        free (e->pending_paths);
    }
    if (e->re_ok) regfree (&e->re);
    free (e);
}

/* Parse N / +N / -N for size and mtime style predicates.
   Returns the absolute number; sets *cmp_out to -1/0/+1. */
static long long
bf_parse_signed (const char *s, int *cmp_out)
{
    if (s[0] == '+') { *cmp_out =  1; s++; }
    else if (s[0] == '-') { *cmp_out = -1; s++; }
    else                  { *cmp_out = 0; }
    return atoll (s);
}

/* Parse the MODE operand for -perm. Octal modes are accepted directly.
   Symbolic modes intentionally implement the mask subset find needs:
   [ugoa]*[+-=][rwxst]+ clauses, comma-separated. The operator does not
   matter for find's mask comparison; it only separates "who" from bits. */
static int
bf_parse_perm_mode (const char *s, mode_t *out)
{
    if (!s || !*s) return -1;
    int all_octal = 1;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '7') { all_octal = 0; break; }
    }
    if (all_octal) {
        char *end;
        long mode = strtol (s, &end, 8);
        if (*end || mode < 0) return -1;
        *out = (mode_t) mode;
        return 0;
    }

    mode_t mode = 0;
    const char *p = s;
    while (*p) {
        int who = 0;
        while (*p == 'u' || *p == 'g' || *p == 'o' || *p == 'a') {
            if (*p == 'u') who |= 1;
            else if (*p == 'g') who |= 2;
            else if (*p == 'o') who |= 4;
            else who |= 7;
            p++;
        }
        if (who == 0) who = 7;
        if (*p != '+' && *p != '-' && *p != '=') return -1;
        p++;
        if (!*p || *p == ',') return -1;
        while (*p && *p != ',') {
            switch (*p) {
                case 'r':
                    if (who & 1) mode |= S_IRUSR;
                    if (who & 2) mode |= S_IRGRP;
                    if (who & 4) mode |= S_IROTH;
                    break;
                case 'w':
                    if (who & 1) mode |= S_IWUSR;
                    if (who & 2) mode |= S_IWGRP;
                    if (who & 4) mode |= S_IWOTH;
                    break;
                case 'x':
                    if (who & 1) mode |= S_IXUSR;
                    if (who & 2) mode |= S_IXGRP;
                    if (who & 4) mode |= S_IXOTH;
                    break;
                case 's':
                    if (who & 1) mode |= S_ISUID;
                    if (who & 2) mode |= S_ISGID;
                    break;
                case 't':
                    mode |= S_ISVTX;
                    break;
                default:
                    return -1;
            }
            p++;
        }
        if (*p == ',') {
            p++;
            if (!*p) return -1;
        }
    }
    *out = mode;
    return 0;
}

static bf_expr *bf_parse_or (bf_parse *p, bf_ctx *ctx);

static int
bf_printf_validate (const char *fmt, const char **bad)
{
    for (const char *s = fmt; *s; s++)
    {
        if (*s == '%')
        {
            s++;
            if (!*s || !strchr ("%pPfhys", *s))
            {
                if (bad) *bad = s;
                return -1;
            }
        }
    }
    return 0;
}

static bf_expr *
bf_parse_primary (bf_parse *p, bf_ctx *ctx)
{
    const char *t = bf_peek (p);
    if (!t) return NULL;

    if (!strcmp (t, "(")) {
        bf_advance (p);
        bf_expr *inner = bf_parse_or (p, ctx);
        if (!inner || !bf_peek (p) || strcmp (bf_peek (p), ")") != 0)
            { bf_free (inner); builtin_error ("expected )"); return NULL; }
        bf_advance (p);
        return inner;
    }
    if (!strcmp (t, "!") || !strcmp (t, "-not")) {
        bf_advance (p);
        bf_expr *inner = bf_parse_primary (p, ctx);
        if (!inner) return NULL;
        bf_expr *e = bf_alloc (BF_NOT);
        if (!e) { bf_free (inner); return NULL; }
        e->a = inner;
        return e;
    }

    bf_kind k = BF_TRUE;
    int needs_arg = 0;
    int is_action = 0;

    if      (!strcmp (t, "-name"))     { k = BF_NAME;     needs_arg = 1; }
    else if (!strcmp (t, "-iname"))    { k = BF_INAME;    needs_arg = 1; }
    else if (!strcmp (t, "-path"))     { k = BF_PATH;     needs_arg = 1; }
    else if (!strcmp (t, "-type"))     { k = BF_TYPE;     needs_arg = 1; }
    else if (!strcmp (t, "-size"))     { k = BF_SIZE;     needs_arg = 1; }
    else if (!strcmp (t, "-mtime"))    { k = BF_MTIME;    needs_arg = 1; }
    else if (!strcmp (t, "-maxdepth")) { k = BF_MAXDEPTH; needs_arg = 1; is_action = 1; }
    else if (!strcmp (t, "-mindepth")) { k = BF_MINDEPTH; needs_arg = 1; is_action = 1; }
    else if (!strcmp (t, "-xdev") || !strcmp (t, "-mount")) { k = BF_XDEV; ctx->xdev = 1; }
    else if (!strcmp (t, "-prune"))    { k = BF_PRUNE; }
    else if (!strcmp (t, "-empty"))    { k = BF_EMPTY; }
    else if (!strcmp (t, "-newer"))    { k = BF_NEWER;    needs_arg = 1; }
    else if (!strcmp (t, "-mmin"))     { k = BF_MMIN;     needs_arg = 1; }
    else if (!strcmp (t, "-amin"))     { k = BF_AMIN;     needs_arg = 1; }
    else if (!strcmp (t, "-cmin"))     { k = BF_CMIN;     needs_arg = 1; }
    else if (!strcmp (t, "-atime"))    { k = BF_ATIME;    needs_arg = 1; }
    else if (!strcmp (t, "-ctime"))    { k = BF_CTIME;    needs_arg = 1; }
    else if (!strcmp (t, "-regex"))    { k = BF_REGEX;    needs_arg = 1; }
    else if (!strcmp (t, "-iregex"))   { k = BF_IREGEX;   needs_arg = 1; }
    else if (!strcmp (t, "-perm"))     { k = BF_PERM;     needs_arg = 1; }
    else if (!strcmp (t, "-user"))     { k = BF_USER;     needs_arg = 1; }
    else if (!strcmp (t, "-group"))    { k = BF_GROUP;    needs_arg = 1; }
    else if (!strcmp (t, "-uid"))      { k = BF_UID;      needs_arg = 1; }
    else if (!strcmp (t, "-gid"))      { k = BF_GID;      needs_arg = 1; }
    else if (!strcmp (t, "-nouser"))   { k = BF_NOUSER; }
    else if (!strcmp (t, "-nogroup"))  { k = BF_NOGROUP; }
    else if (!strcmp (t, "-delete"))   { k = BF_DELETE;   is_action = 1; ctx->had_action = 1; ctx->postorder = 1; }
    else if (!strcmp (t, "-print"))    { k = BF_PRINT;    is_action = 1; ctx->had_action = 1; }
    else if (!strcmp (t, "-print0"))   { k = BF_PRINT0;   is_action = 1; ctx->had_action = 1; ctx->print0 = 1; }
    else if (!strcmp (t, "-printf"))   { k = BF_PRINTF;   needs_arg = 1; is_action = 1; ctx->had_action = 1; }
    else if (!strcmp (t, "-exec") || !strcmp (t, "-execdir"))
    {
        /* Consume tokens until `\;` (per-file) or `+` (batched). */
        int is_execdir = !strcmp (t, "-execdir");
        bf_advance (p);
        bf_expr *e = bf_alloc (is_execdir ? BF_EXECDIR : BF_EXEC);
        if (!e) return NULL;
        e->exec_argv = NULL;
        e->exec_argc = 0;
        int cap = 0;
        const char *tok;
        while ((tok = bf_peek (p)) != NULL) {
            if (!strcmp (tok, ";")) { e->exec_batch = 0; bf_advance (p); break; }
            if (!strcmp (tok, "+"))  { e->exec_batch = 1; bf_advance (p); break; }
            if (e->exec_argc >= cap) {
                cap = cap ? cap * 2 : 8;
                char **n = realloc (e->exec_argv, (size_t) cap * sizeof *n);
                if (!n) { bf_free (e); builtin_error ("oom"); return NULL; }
                e->exec_argv = n;
            }
            e->exec_argv[e->exec_argc] = strdup (tok);
            if (!e->exec_argv[e->exec_argc]) { bf_free (e); return NULL; }
            e->exec_argc++;
            bf_advance (p);
        }
        if (e->exec_argc == 0 || (tok == NULL)) {
            bf_free (e);
            builtin_error ("-exec: missing terminator (`;` or `+`)");
            return NULL;
        }
        /* For `+` form, POSIX requires `{}` immediately before `+`. */
        if (e->exec_batch && (e->exec_argc == 0 ||
            strcmp (e->exec_argv[e->exec_argc - 1], "{}") != 0)) {
            bf_free (e);
            builtin_error ("-exec ... +: `{}` must be the last argument before `+`");
            return NULL;
        }
        is_action = 1;
        ctx->had_action = 1;
        return e;
    }
    else
    {
        builtin_error ("unknown predicate: %s", t);
        return NULL;
    }
    bf_advance (p);

    bf_expr *e = bf_alloc (k);
    if (!e) return NULL;

    if (needs_arg)
    {
        const char *arg = bf_peek (p);
        if (!arg) { bf_free (e); builtin_error ("predicate %s needs an argument", t); return NULL; }
        bf_advance (p);
        if (k == BF_SIZE || k == BF_MTIME ||
            k == BF_MMIN || k == BF_AMIN || k == BF_CMIN ||
            k == BF_ATIME || k == BF_CTIME)
        {
            e->nval = bf_parse_signed (arg, &e->ncmp);
            /* For -size, suffix 'k', 'M', 'c': default is 512-byte blocks
               (POSIX), but we'll accept just bytes (cN), KiB (kN), MiB (MN).
               Time predicates keep nval in user units here; evaluation
               applies the minute/day bucket once so +N/-N match find-style
               truncated age semantics. */
            if (k == BF_SIZE)
            {
                size_t l = strlen (arg);
                char suf = (l > 0) ? arg[l - 1] : 'b';
                if (suf == 'c' || suf == 'k' || suf == 'M')
                {
                    long long mult = (suf == 'c') ? 1 : (suf == 'k') ? 1024 : 1024 * 1024;
                    e->nval *= mult;
                }
                else
                {
                    /* default: 512-byte blocks */
                    e->nval *= 512;
                }
            }
        }
        else if (k == BF_REGEX || k == BF_IREGEX)
        {
            int flags = REG_EXTENDED | REG_NOSUB;
            if (k == BF_IREGEX) flags |= REG_ICASE;
            if (regcomp (&e->re, arg, flags) != 0)
                { bf_free (e); builtin_error ("bad regex: %s", arg); return NULL; }
            e->re_ok = 1;
        }
        else if (k == BF_PERM)
        {
            /* MODE = exact; -MODE = all-bits-set; /MODE = any-bit-set. */
            const char *m = arg;
            char op = 'e';   /* exact */
            if (*m == '-') { op = 'a'; m++; }
            else if (*m == '/') { op = 'n'; m++; }
            mode_t mode = 0;
            if (bf_parse_perm_mode (m, &mode) != 0)
                { bf_free (e); builtin_error ("-perm: bad mode: %s", arg); return NULL; }
            e->nval = mode;
            e->ncmp = (op == 'a') ? -1 : (op == 'n') ? 1 : 0;
        }
        else if (k == BF_USER)
        {
            struct passwd *pw = getpwnam (arg);
            if (!pw) { bf_free (e); builtin_error ("-user: unknown user: %s", arg); return NULL; }
            e->nval = pw->pw_uid;
        }
        else if (k == BF_GROUP)
        {
            struct group *gr = getgrnam (arg);
            if (!gr) { bf_free (e); builtin_error ("-group: unknown group: %s", arg); return NULL; }
            e->nval = gr->gr_gid;
        }
        else if (k == BF_UID || k == BF_GID)
        {
            e->nval = atoll (arg);
        }
        else if (k == BF_MAXDEPTH || k == BF_MINDEPTH)
        {
            int d = atoi (arg);
            if (k == BF_MAXDEPTH) ctx->maxdepth = d;
            else                  ctx->mindepth = d;
        }
        else if (k == BF_NEWER)
        {
            struct stat st;
            if (stat (arg, &st) != 0)
                { bf_free (e); builtin_error ("-newer %s: %s", arg, strerror (errno)); return NULL; }
            e->tval = st.st_mtim.tv_sec;
            e->tnsec = st.st_mtim.tv_nsec;
        }
        else if (k == BF_PRINTF)
        {
            const char *bad = NULL;
            if (bf_printf_validate (arg, &bad) != 0)
                { bf_free (e); builtin_error ("-printf: unsupported format escape near: %s", bad ? bad : arg); return NULL; }
            e->sval = strdup (arg);
        }
        else
        {
            e->sval = strdup (arg);
        }
    }
    (void) is_action;
    return e;
}

static bf_expr *
bf_parse_and (bf_parse *p, bf_ctx *ctx)
{
    bf_expr *lhs = bf_parse_primary (p, ctx);
    if (!lhs) return NULL;
    while (bf_peek (p) && strcmp (bf_peek (p), ")") != 0
                       && strcmp (bf_peek (p), "-o") != 0)
    {
        if (!strcmp (bf_peek (p), "-a")) bf_advance (p);
        bf_expr *rhs = bf_parse_primary (p, ctx);
        if (!rhs) { bf_free (lhs); return NULL; }
        bf_expr *and_node = bf_alloc (BF_AND);
        if (!and_node) { bf_free (lhs); bf_free (rhs); return NULL; }
        and_node->a = lhs; and_node->b = rhs;
        lhs = and_node;
    }
    return lhs;
}

static bf_expr *
bf_parse_or (bf_parse *p, bf_ctx *ctx)
{
    bf_expr *lhs = bf_parse_and (p, ctx);
    if (!lhs) return NULL;
    while (bf_peek (p) && !strcmp (bf_peek (p), "-o"))
    {
        bf_advance (p);
        bf_expr *rhs = bf_parse_and (p, ctx);
        if (!rhs) { bf_free (lhs); return NULL; }
        bf_expr *or_node = bf_alloc (BF_OR);
        if (!or_node) { bf_free (lhs); bf_free (rhs); return NULL; }
        or_node->a = lhs; or_node->b = rhs;
        lhs = or_node;
    }
    return lhs;
}

/* ---- evaluator ---- */

/* lowercase a string into a buf (for -iname). */
static void
bf_strlower (const char *src, char *dst, size_t dstsz)
{
    size_t i;
    for (i = 0; i < dstsz - 1 && src[i]; i++)
        dst[i] = (char) tolower ((unsigned char) src[i]);
    dst[i] = '\0';
}

static int
bf_match_glob (const char *pat, const char *s, int icase)
{
    if (!icase) return fnmatch (pat, s, 0) == 0;
    /* Heap-alloc sized to inputs so paths >4095 bytes don't truncate. */
    size_t dlen = strlen (s) + 1, plen = strlen (pat) + 1;
    char *dst = malloc (dlen);
    char *dpat = malloc (plen);
    int rc = 0;
    if (dst && dpat)
    {
        bf_strlower (s, dst, dlen);
        bf_strlower (pat, dpat, plen);
        rc = fnmatch (dpat, dst, 0) == 0;
    }
    free (dst); free (dpat);
    return rc;
}

static int bf_eval (bf_expr *e, bf_pinfo *p, bf_ctx *ctx);

/* Run a single-shot exec for the `\;` form: substitute every `{}` in the
   template with `path`, fork+execvp+waitpid. Return WEXITSTATUS == 0. */
static int
bf_exec_once (bf_expr *e, const char *path)
{
    /* Build argv with substitutions. */
    char **argv = malloc ((size_t) (e->exec_argc + 1) * sizeof *argv);
    if (!argv) { builtin_error ("oom"); return 0; }
    for (int i = 0; i < e->exec_argc; i++) {
        const char *t = e->exec_argv[i];
        if (strstr (t, "{}")) {
            /* Replace ALL `{}` occurrences with path. */
            size_t plen = strlen (path), tlen = strlen (t);
            size_t out_cap = tlen + plen + 1;
            char *out = malloc (out_cap);
            if (!out) { for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
            size_t op = 0;
            for (size_t s = 0; s < tlen;) {
                if (t[s] == '{' && t[s+1] == '}') {
                    if (op + plen + 1 > out_cap) {
                        out_cap = (op + plen + 1) * 2;
                        char *no = realloc (out, out_cap);
                        if (!no) { free (out); for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
                        out = no;
                    }
                    memcpy (out + op, path, plen); op += plen; s += 2;
                } else {
                    if (op + 2 > out_cap) {
                        out_cap *= 2;
                        char *no = realloc (out, out_cap);
                        if (!no) { free (out); for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
                        out = no;
                    }
                    out[op++] = t[s++];
                }
            }
            out[op] = '\0';
            argv[i] = out;
        } else {
            argv[i] = strdup (t);
            if (!argv[i]) { for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
        }
    }
    argv[e->exec_argc] = NULL;
    struct sigaction chld_dfl, chld_save;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &chld_save);

    sigset_t chld_set, prev_mask;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld_set, &prev_mask);

    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    int rc = 0;
    if (pid == 0) {
        bos_prepare_child ();
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
        _exit (127);
    } else if (pid > 0) {
        int status = 0;
        pid_t w;
        while ((w = waitpid (pid, &status, 0)) < 0 && errno == EINTR) { /* retry */ }
        rc = (w == pid && WIFEXITED (status) && WEXITSTATUS (status) == 0) ? 1 : 0;
    } else {
        builtin_error ("fork: %s", strerror (errno));
    }
    sigprocmask (SIG_SETMASK, &prev_mask, NULL);
    sigaction (SIGCHLD, &chld_save, NULL);
    for (int i = 0; i <= e->exec_argc; i++) free (argv[i]);
    free (argv);
    return rc;
}

/* Run a single-shot exec after chdir(dir), used by -execdir. `{}` is
   substituted with `arg_path`, normally the matched entry basename. */
static int
bf_exec_once_in_dir (bf_expr *e, const char *dir, const char *arg_path)
{
    char **argv = malloc ((size_t) (e->exec_argc + 1) * sizeof *argv);
    if (!argv) { builtin_error ("oom"); return 0; }
    for (int i = 0; i < e->exec_argc; i++) {
        const char *t = e->exec_argv[i];
        if (strstr (t, "{}")) {
            size_t plen = strlen (arg_path), tlen = strlen (t);
            size_t out_cap = tlen + plen + 1;
            char *out = malloc (out_cap);
            if (!out) { for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
            size_t op = 0;
            for (size_t s = 0; s < tlen;) {
                if (t[s] == '{' && t[s+1] == '}') {
                    if (op + plen + 1 > out_cap) {
                        out_cap = (op + plen + 1) * 2;
                        char *no = realloc (out, out_cap);
                        if (!no) { free (out); for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
                        out = no;
                    }
                    memcpy (out + op, arg_path, plen); op += plen; s += 2;
                } else {
                    if (op + 2 > out_cap) {
                        out_cap *= 2;
                        char *no = realloc (out, out_cap);
                        if (!no) { free (out); for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
                        out = no;
                    }
                    out[op++] = t[s++];
                }
            }
            out[op] = '\0';
            argv[i] = out;
        } else {
            argv[i] = strdup (t);
            if (!argv[i]) { for (int j = 0; j < i; j++) free (argv[j]); free (argv); return 0; }
        }
    }
    argv[e->exec_argc] = NULL;

    struct sigaction chld_dfl, chld_save;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &chld_save);

    sigset_t chld_set, prev_mask;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld_set, &prev_mask);

    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    int rc = 0;
    if (pid == 0) {
        bos_prepare_child ();
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        if (chdir (dir) < 0)
            _exit (126);
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
        _exit (127);
    } else if (pid > 0) {
        int status = 0;
        pid_t w;
        while ((w = waitpid (pid, &status, 0)) < 0 && errno == EINTR) { /* retry */ }
        rc = (w == pid && WIFEXITED (status) && WEXITSTATUS (status) == 0) ? 1 : 0;
    } else {
        builtin_error ("fork: %s", strerror (errno));
    }
    sigprocmask (SIG_SETMASK, &prev_mask, NULL);
    sigaction (SIGCHLD, &chld_save, NULL);
    for (int i = 0; i <= e->exec_argc; i++) free (argv[i]);
    free (argv);
    return rc;
}

/* Flush a `+`-form pending batch: build argv from template (with `{}`
   replaced by ALL pending paths), fork+execvp+waitpid. */
static int
bf_exec_flush (bf_expr *e)
{
    if (e->pending_count == 0) return 1;
    /* argv = template[0..argc-2]   (everything except the trailing `{}`)
              + pending_paths[0..count-1]
              + NULL */
    int prefix_n = e->exec_argc - 1;   /* drop the `{}` placeholder */
    size_t total = (size_t) prefix_n + e->pending_count + 1;
    char **argv = malloc (total * sizeof *argv);
    if (!argv) { builtin_error ("oom"); return 0; }
    int n = 0;
    for (int i = 0; i < prefix_n; i++) argv[n++] = e->exec_argv[i];
    for (size_t i = 0; i < e->pending_count; i++) argv[n++] = e->pending_paths[i];
    argv[n] = NULL;
    struct sigaction chld_dfl, chld_save;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &chld_save);

    sigset_t chld_set, prev_mask;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld_set, &prev_mask);

    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    int rc = 1;
    if (pid == 0) {
        bos_prepare_child ();
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
        _exit (127);
    } else if (pid > 0) {
        int status = 0;
        pid_t w;
        while ((w = waitpid (pid, &status, 0)) < 0 && errno == EINTR) { /* retry */ }
        rc = (w == pid && WIFEXITED (status) && WEXITSTATUS (status) == 0) ? 1 : 0;
    } else {
        builtin_error ("fork: %s", strerror (errno));
        rc = 0;
    }
    sigprocmask (SIG_SETMASK, &prev_mask, NULL);
    sigaction (SIGCHLD, &chld_save, NULL);
    free (argv);
    /* Reset batch. */
    for (size_t i = 0; i < e->pending_count; i++) free (e->pending_paths[i]);
    e->pending_count = 0;
    e->pending_bytes = 0;
    return rc;
}

/* Recursively flush all BF_EXEC `+` batches in the AST. */
static void
bf_flush_all (bf_expr *e)
{
    if (!e) return;
    bf_flush_all (e->a);
    bf_flush_all (e->b);
    if (e->kind == BF_EXEC && e->exec_batch) bf_exec_flush (e);
}

/* Append a path to a `+`-form node's pending batch. Flush if batch is
   getting large (env limit minus reserved slack). */
static int
bf_exec_batch_append (bf_expr *e, const char *path)
{
    /* Use a conservative cap — half ARG_MAX or 64 KiB, whichever smaller. */
    long arg_max = sysconf (_SC_ARG_MAX);
    if (arg_max <= 0) arg_max = 131072;
    size_t cap_bytes = (size_t) arg_max / 2;
    if (cap_bytes > 65536) cap_bytes = 65536;
    size_t plen = strlen (path) + 1;
    if (e->pending_count > 0 && e->pending_bytes + plen > cap_bytes)
        bf_exec_flush (e);
    if (e->pending_count >= e->pending_cap) {
        size_t nc = e->pending_cap ? e->pending_cap * 2 : 16;
        char **n = realloc (e->pending_paths, nc * sizeof *n);
        if (!n) { builtin_error ("oom in -exec batch"); return 0; }
        e->pending_paths = n;
        e->pending_cap = nc;
    }
    e->pending_paths[e->pending_count] = strdup (path);
    if (!e->pending_paths[e->pending_count]) return 0;
    e->pending_count++;
    e->pending_bytes += plen;
    return 1;   /* `+` form is always-true predicate */
}

static char
bf_type_char (mode_t m)
{
    if (S_ISREG (m))  return 'f';
    if (S_ISDIR (m))  return 'd';
    if (S_ISLNK (m))  return 'l';
    if (S_ISFIFO (m)) return 'p';
    if (S_ISSOCK (m)) return 's';
    if (S_ISBLK (m))  return 'b';
    if (S_ISCHR (m))  return 'c';
    return '?';
}

static void
bf_put_dirname (const char *path)
{
    const char *slash = strrchr (path, '/');
    if (!slash)
    {
        fputs (".", stdout);
        return;
    }
    if (slash == path)
    {
        fputs ("/", stdout);
        return;
    }
    fwrite (path, 1, (size_t) (slash - path), stdout);
}

static int
bf_printf_emit (bf_pinfo *p, const char *fmt)
{
    for (const char *s = fmt; *s; s++)
    {
        if (*s == '\\')
        {
            s++;
            switch (*s)
            {
                case '\0':
                    putchar ('\\');
                    return 1;
                case 'n':
                    putchar ('\n');
                    break;
                case '0':
                    putchar ('\0');
                    break;
                case '\\':
                    putchar ('\\');
                    break;
                default:
                    putchar ('\\');
                    putchar (*s);
                    break;
            }
            continue;
        }
        if (*s == '%')
        {
            s++;
            switch (*s)
            {
                case '%':
                    putchar ('%');
                    break;
                case 'p':
                    fputs (p->path, stdout);
                    break;
                case 'P':
                    /* Path with the command-line starting point removed
                       (GNU find %P). For root ".", "./a/b" -> "a/b"; the
                       start itself -> "". */
                    {
                        const char *pp = p->path;
                        const char *rt = p->root;
                        if (rt && *rt)
                        {
                            size_t rl = strlen (rt);
                            if (strncmp (pp, rt, rl) == 0)
                            {
                                pp += rl;
                                if (*pp == '/') pp++;
                            }
                        }
                        fputs (pp, stdout);
                    }
                    break;
                case 'f':
                    fputs (p->base, stdout);
                    break;
                case 'h':
                    bf_put_dirname (p->path);
                    break;
                case 'y':
                    putchar (bf_type_char (p->st.st_mode));
                    break;
                case 's':
                    printf ("%lld", (long long) p->st.st_size);
                    break;
                default:
                    builtin_error ("-printf: unsupported format escape near: %c", *s ? *s : '%');
                    return 0;
            }
            continue;
        }
        putchar (*s);
    }
    return 1;
}

static int
bf_eval (bf_expr *e, bf_pinfo *p, bf_ctx *ctx)
{
    if (!e) return 1;
    switch (e->kind)
    {
        case BF_AND:
            return bf_eval (e->a, p, ctx) && bf_eval (e->b, p, ctx);
        case BF_OR:
            return bf_eval (e->a, p, ctx) || bf_eval (e->b, p, ctx);
        case BF_NOT:
            return !bf_eval (e->a, p, ctx);
        case BF_NAME:
            return bf_match_glob (e->sval, p->base, 0);
        case BF_INAME:
            return bf_match_glob (e->sval, p->base, 1);
        case BF_PATH:
            return fnmatch (e->sval, p->path, 0) == 0;
        case BF_TYPE:
        {
            char want = e->sval[0];
            mode_t m = p->st.st_mode;
            switch (want)
            {
                case 'f': return S_ISREG (m);
                case 'd': return S_ISDIR (m);
                case 'l': return S_ISLNK (m);
                case 'c': return S_ISCHR (m);
                case 'b': return S_ISBLK (m);
                case 'p': return S_ISFIFO (m);
                case 's': return S_ISSOCK (m);
            }
            return 0;
        }
        case BF_SIZE:
            switch (e->ncmp)
            {
                case  0: return (long long) p->st.st_size == e->nval;
                case  1: return (long long) p->st.st_size >  e->nval;
                case -1: return (long long) p->st.st_size <  e->nval;
            }
            return 0;
        case BF_MTIME:
        {
            /* GNU find: `-mtime N` divides age by 86400 and compares
               the truncated count, so the operand is in DAYS, not
               seconds. Multiply nval by the bucket size before the
               comparison; case 1 (+N "older than N days") uses
               age >= (N+1)*bucket because truncation makes
               int(age/bucket) > N equivalent to age >= (N+1)*bucket. */
            time_t age = time (NULL) - p->st.st_mtime;
            long long threshold = (long long) e->nval * 86400;
            switch (e->ncmp)
            {
                case  0: return (long long) age >= threshold &&
                                (long long) age <  threshold + 86400;
                case  1: return (long long) age >= threshold + 86400;
                case -1: return (long long) age <  threshold;
            }
            return 0;
        }
        case BF_NEWER:
            /* GNU find compares full-precision mtimes: a file is newer iff
               its mtime is strictly greater than the reference's, tie-broken
               by nanoseconds. Second-granularity (st_mtime) wrongly treats
               sub-second-newer files as not newer. */
            return p->st.st_mtim.tv_sec > e->tval
                   || (p->st.st_mtim.tv_sec == e->tval
                       && p->st.st_mtim.tv_nsec > e->tnsec);
        case BF_MMIN:
        case BF_AMIN:
        case BF_CMIN:
        case BF_ATIME:
        case BF_CTIME:
        {
            /* GNU find: operand is in MINUTES for -*min and DAYS for
               -*time. Same truncation rule as BF_MTIME above. */
            time_t now = time (NULL);
            time_t when = (e->kind == BF_AMIN || e->kind == BF_ATIME)
                              ? p->st.st_atime
                          : (e->kind == BF_CMIN || e->kind == BF_CTIME)
                              ? p->st.st_ctime
                              : p->st.st_mtime;
            time_t age = now - when;
            int bucket = (e->kind == BF_MMIN || e->kind == BF_AMIN || e->kind == BF_CMIN)
                              ? 60 : 86400;
            long long threshold = (long long) e->nval * bucket;
            switch (e->ncmp)
            {
                case  0: return (long long) age >= threshold &&
                                (long long) age <  threshold + bucket;
                case  1: return (long long) age >= threshold + bucket;
                case -1: return (long long) age <  threshold;
            }
            return 0;
        }
        case BF_REGEX:
        case BF_IREGEX:
            if (!e->re_ok) return 0;
            return regexec (&e->re, p->path, 0, NULL, 0) == 0;
        case BF_PERM:
        {
            mode_t m = p->st.st_mode & 07777;
            mode_t want = (mode_t) e->nval;
            switch (e->ncmp)
            {
                case  0: return m == want;
                case -1: return (m & want) == want;     /* all bits set */
                case  1: return (m & want) != 0;        /* any bit set */
            }
            return 0;
        }
        case BF_USER:
        case BF_UID:
            return p->st.st_uid == (uid_t) e->nval;
        case BF_GROUP:
        case BF_GID:
            return p->st.st_gid == (gid_t) e->nval;
        case BF_NOUSER:
            return getpwuid (p->st.st_uid) == NULL;
        case BF_NOGROUP:
            return getgrgid (p->st.st_gid) == NULL;
        case BF_DELETE:
        {
            int rc;
            if (!strcmp (p->base, ".") || !strcmp (p->base, "..")) {
                builtin_warning ("refusing to delete %s", p->path);
                ctx->exit_status = 1;
                return 0;
            }
            rc = S_ISDIR (p->st.st_mode) ? rmdir (p->path) : unlink (p->path);
            if (rc < 0) {
                builtin_warning ("%s %s: %s",
                                 S_ISDIR (p->st.st_mode) ? "rmdir" : "unlink",
                                 p->path, strerror (errno));
                ctx->exit_status = 1;
            }
            return rc == 0;
        }
        case BF_EXECDIR:
        {
            /* Like -exec but run from the matched file's parent directory;
               {} is replaced with ./basename. */
            const char *base = strrchr (p->path, '/');
            base = base ? base + 1 : p->path;
            char relbuf[PATH_MAX];
            char dirbuf[PATH_MAX];
            const char *slash = strrchr (p->path, '/');
            if (slash) {
                size_t n = (size_t) (slash - p->path);
                if (n == 0) n = 1;
                if (n >= sizeof dirbuf) return 0;
                memcpy (dirbuf, p->path, n);
                dirbuf[n] = '\0';
            } else {
                snprintf (dirbuf, sizeof dirbuf, ".");
            }
            if (snprintf (relbuf, sizeof relbuf, "./%s", base) >= (int) sizeof relbuf)
                return 0;
            return bf_exec_once_in_dir (e, dirbuf, relbuf);
        }
        case BF_EMPTY:
            if (S_ISREG (p->st.st_mode)) return p->st.st_size == 0;
            if (S_ISDIR (p->st.st_mode)) {
                DIR *d = opendir (p->path);
                if (!d) return 0;
                int empty = 1;
                struct dirent *de;
                while ((de = readdir (d)) != NULL) {
                    if (strcmp (de->d_name, ".") && strcmp (de->d_name, "..")) {
                        empty = 0; break;
                    }
                }
                closedir (d);
                return empty;
            }
            return 0;
        case BF_PRUNE:
            ctx->pruned = 1;
            return 1;       /* always true */
        case BF_PRINT:
            fputs (p->path, stdout); putchar ('\n');
            return 1;
        case BF_PRINT0:
            fputs (p->path, stdout); putchar ('\0');
            return 1;
        case BF_PRINTF:
            return bf_printf_emit (p, e->sval);
        case BF_EXEC:
            if (e->exec_batch)
                return bf_exec_batch_append (e, p->path);
            return bf_exec_once (e, p->path);
        case BF_MAXDEPTH:
        case BF_MINDEPTH:
        case BF_XDEV:
        case BF_TRUE:
            return 1;
        case BF_FALSE:
            return 0;
    }
    return 0;
}

/* Per-descent-chain (dev,ino) stack for symlink-loop detection under -L.
   GNU find only detects *cyclic* re-entry: a directory that is an
   ancestor of itself in the current descent chain. Two distinct path
   spellings of the same inode (e.g. `tree/d1/x` and `tree/link-to-d1/x`)
   are NOT a loop — both are walked. The earlier implementation used a
   monotonic seen-set which collapsed those spellings and dropped one of
   the walks; that doesn't match GNU and silently lost output. The
   stack is pushed on directory entry and popped on exit so siblings
   don't pollute each other's history. */
typedef struct {
    int     used, cap;
    dev_t  *dev;
    ino_t  *ino;
} bf_seen;

static int
bf_chain_contains (const bf_seen *s, const struct stat *st)
{
    for (int i = 0; i < s->used; i++)
        if (s->dev[i] == st->st_dev && s->ino[i] == st->st_ino) return 1;
    return 0;
}

static int
bf_chain_push (bf_seen *s, const struct stat *st)
{
    if (s->used == s->cap)
    {
        int nc = s->cap ? s->cap * 2 : 16;
        dev_t *nd = realloc (s->dev, nc * sizeof *nd);
        if (!nd) return 0;
        s->dev = nd;  /* commit first realloc before attempting second */
        ino_t *ni = realloc (s->ino, nc * sizeof *ni);
        if (!ni) return 0;  /* dev grew but ino didn't; cap unchanged so used<cap remains false */
        s->ino = ni; s->cap = nc;
    }
    s->dev[s->used] = st->st_dev;
    s->ino[s->used] = st->st_ino;
    s->used++;
    return 1;
}

static void
bf_chain_pop (bf_seen *s)
{
    if (s->used > 0) s->used--;
}

/* Recursive walker. */
static void
bf_walk (const char *path, int depth, bf_ctx *ctx, bf_seen *seen)
{
    struct stat st;
    /* Remember the command-line starting point so -printf %P can strip it. */
    if (depth == 0)
        ctx->start_path = path;
    /* -L: follow symlinks at every depth.
       -H: follow symlinks only when the path was named on the command
            line (depth == 0).
       -P (default): never follow. */
    int do_stat = (ctx->follow == BF_FOLLOW_ALL)
                || (ctx->follow == BF_FOLLOW_ARGS && depth == 0);
    int sr = do_stat ? stat (path, &st) : lstat (path, &st);
    if (sr != 0)
    {
        /* Symlink-follow miss (-L on a dangling link) falls back to lstat
           so the symlink itself is still reported, mirroring GNU find. */
        if (do_stat && (errno == ENOENT || errno == ELOOP) &&
            lstat (path, &st) == 0)
        {
            /* keep going with the symlink-itself stat */
        }
        else
        {
            /* Surface real errors (permission denied, broken symlink target).
               ENOENT is silenced because find is regularly run on transient
               paths and `find /tmp` complaining about every gone-by-now file
               is noise. Anything else flips the find-level exit status to 1
               so callers can distinguish a partial walk from a clean walk,
               matching GNU/BSD find. */
            if (errno != ENOENT) {
                builtin_warning ("%s: %s", path, strerror (errno));
                ctx->exit_status = 1;
            }
            return;
        }
    }

    if (ctx->maxdepth >= 0 && depth > ctx->maxdepth) return;
    if (depth == 0) {
        ctx->root_dev = st.st_dev;
        ctx->root_dev_valid = 1;
    }

    /* Cycle detection only for directories — files can't loop. Only
       meaningful under -L: with -P/-H we lstat() at depth>0 so a
       symlinked-back-to-ancestor entry is reported as a symlink and
       never descended into. Under -L we follow at every depth, so a
       directory that's already on the current descent chain (an
       ancestor of itself via symlink) would otherwise recurse
       forever. We do NOT dedup against sibling/cousin chains —
       two distinct path-spellings of the same inode are both walked
       (matching GNU find -L). */
    int is_dir = S_ISDIR (st.st_mode);
    int pushed = 0;
    if (is_dir && ctx->follow == BF_FOLLOW_ALL)
    {
        if (bf_chain_contains (seen, &st)) return;
        pushed = bf_chain_push (seen, &st);
        /* On push-fail (OOM) we fall through; the worst case is the
           caller sees infinite recursion on a truly cyclic tree, which
           is no worse than skipping the check entirely. */
    }

    /* Find the basename. */
    const char *base = strrchr (path, '/');
    base = base ? base + 1 : path;

    bf_pinfo info = { .path = path, .base = base, .root = ctx->start_path, .depth = depth, .st = st };
    int saved_pruned = ctx->pruned;
    ctx->pruned = 0;

    if (!ctx->postorder && depth >= ctx->mindepth)
    {
        int matched = bf_eval (ctx->root, &info, ctx);
        if (matched && !ctx->had_action)
        {
            /* default action: -print */
            fputs (path, stdout);
            putchar (ctx->print0 ? '\0' : '\n');
        }
    }

    if (is_dir && !ctx->pruned
        && (!ctx->xdev || depth == 0 || !ctx->root_dev_valid
            || st.st_dev == ctx->root_dev))
    {
        DIR *d = opendir (path);
        if (d)
        {
            struct dirent *de;
            while ((de = readdir (d)) != NULL)
            {
                const char *n = de->d_name;
                if (!strcmp (n, ".") || !strcmp (n, "..")) continue;
                size_t pl = strlen (path), nl = strlen (n);
                int slash = (pl == 0 || path[pl - 1] != '/') ? 1 : 0;
                char *child = malloc (pl + slash + nl + 1);
                if (!child) continue;
                memcpy (child, path, pl);
                if (slash) child[pl] = '/';
                memcpy (child + pl + slash, n, nl + 1);
                bf_walk (child, depth + 1, ctx, seen);
                free (child);
            }
            closedir (d);
        }
        else
        {
            /* Permission-denied / I/O errors on a directory we already
               reported: warn-and-continue, and flag the run as partial
               (exit 1). ENOENT means the directory vanished between
               stat() and opendir() — silence, mirroring GNU find. */
            if (errno != ENOENT) {
                builtin_warning ("%s: %s", path, strerror (errno));
                ctx->exit_status = 1;
            }
        }
    }

    if (ctx->postorder && depth >= ctx->mindepth)
    {
        int matched = bf_eval (ctx->root, &info, ctx);
        if (matched && !ctx->had_action)
        {
            /* default action: -print */
            fputs (path, stdout);
            putchar (ctx->print0 ? '\0' : '\n');
        }
    }

    /* Pop the ancestor-chain entry so a sibling subtree reachable via a
       different path-spelling isn't blocked from descending into the
       same inode. */
    if (pushed) bf_chain_pop (seen);
    ctx->pruned = saved_pruned;
}

int
find_builtin (WORD_LIST *list)
{
    /* Convert WORD_LIST → argv. */
    int argc = 0;
    for (WORD_LIST *p = list; p; p = p->next) argc++;
	if (argc < 1)
	{
	    builtin_usage ();
	    return EX_USAGE;
	}
    char **argv = malloc ((argc + 1) * sizeof *argv);
    if (!argv) { builtin_error ("malloc: %s", strerror (errno)); return EXECUTION_FAILURE; }
    int i = 0;
    for (WORD_LIST *p = list; p; p = p->next) argv[i++] = p->word->word;
    argv[argc] = NULL;

    /* POSIX: -H/-L/-P appear before the path list. Last one wins so a
       caller can layer flags. Anything else falls through to path/expr
       handling below. */
    bf_follow follow = BF_FOLLOW_NONE;
    int opt_start = 0;
    while (opt_start < argc) {
        const char *a = argv[opt_start];
        if      (!strcmp (a, "-H")) follow = BF_FOLLOW_ARGS;
        else if (!strcmp (a, "-L")) follow = BF_FOLLOW_ALL;
        else if (!strcmp (a, "-P")) follow = BF_FOLLOW_NONE;
        else break;
        opt_start++;
    }
    int eff_argc   = argc - opt_start;
    char **eff_argv = argv + opt_start;

    /* Split argv into PATHs (until first arg starting with - or ! or () and EXPR. */
    int n_paths = 0;
    for (int j = 0; j < eff_argc; j++)
    {
        const char *a = eff_argv[j];
        if (a[0] == '-' || !strcmp (a, "(") || !strcmp (a, "!")) break;
        n_paths++;
    }
    /* When no path is given, default to ".". Don't mutate eff_argv[0] —
       it's the first expression token and clobbering it loses the
       predicate. */
    const char *default_path = ".";
    char **paths;
    int paths_count;
    if (n_paths == 0) { paths = (char **) &default_path; paths_count = 1; }
    else               { paths = eff_argv; paths_count = n_paths; }

    bf_ctx ctx = {0};
    ctx.maxdepth = -1;
    ctx.mindepth = 0;
    ctx.follow   = follow;

    bf_parse pp = { .argc = eff_argc - n_paths, .argv = eff_argv + n_paths, .pos = 0 };
    if (pp.argc > 0)
    {
        ctx.root = bf_parse_or (&pp, &ctx);
        if (!ctx.root || pp.pos != pp.argc)
	        {
	            bf_free (ctx.root);
	            const char *unparsed = (pp.pos < pp.argc) ? pp.argv[pp.pos] : "(end of args)";
	            builtin_error ("parse error in find expression at: %s", unparsed);
	            builtin_usage ();
	            free (argv);
	            return EX_USAGE;
	        }
    }

    bf_seen seen = {0};
    for (int j = 0; j < paths_count; j++) {
        ctx.root_dev_valid = 0;
        bf_walk (paths[j], 0, &ctx, &seen);
    }

    /* Flush any pending `-exec ... +` batches. */
    bf_flush_all (ctx.root);

    bf_free (ctx.root);
    free (seen.dev);
    free (seen.ino);
    free (argv);
    /* Match GNU/BSD find: 0 on full success, 1 if any path could not be
       descended (permission denied, broken non-ENOENT lstat). */
    return ctx.exit_status ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

char *find_doc[] = {
    "POSIX-shape find(1) — recursive directory search.",
    "",
    "    bashfind [-H|-L|-P] PATH... [EXPR]",
    "",
    "    -H  follow symlinks only when named on the command line",
    "    -L  follow symlinks at every depth (cycles broken by dev/ino)",
    "    -P  never follow symlinks (default)",
    "",
    "Predicates:",
    "    -name PAT        glob match against basename",
    "    -iname PAT       case-insensitive -name",
    "    -path PAT        glob match against full path",
    "    -type X          X is one of f d l c b p s",
    "    -size N[ckM]     size compare; +N larger / -N smaller",
    "    -mtime N         modified N days ago; +N older / -N newer",
    "    -mmin N          modified N minutes ago; +N older / -N newer",
    "    -amin/-cmin N    access/change time in minutes",
    "    -atime/-ctime N  access/change time in days",
    "    -perm MODE       exact mode; -MODE all bits; /MODE any bit",
    "                     MODE may be octal or symbolic (u+x,g-w,a=r)",
    "    -user/-group N   owner/group name",
    "    -uid/-gid N      numeric owner/group id",
    "    -nouser/-nogroup owner/group id has no passwd/group entry",
    "    -regex PAT       POSIX ERE match against full path",
    "    -iregex PAT      case-insensitive -regex",
    "    -maxdepth N      limit recursion",
    "    -mindepth N      skip output until depth >= N",
    "    -xdev, -mount    do not descend into directories on other filesystems",
    "    -prune           skip subtree below this point",
    "    -empty           zero-size files / empty directories",
    "    -newer FILE      modified after FILE's mtime",
    "Operators: -a (implicit), -o, ! / -not, ( )",
    "Actions:",
    "    -print           one path per line (default)",
    "    -print0          NUL-separated paths (pipe to xargs -0)",
    "    -printf FORMAT   bounded GNU formatter: %% \\n \\0 \\\\ %p %f %h %y %s",
    "    -delete          depth-first unlink/rmdir matched paths",
    "    -exec CMD {} \\;  per-file fork+exec (`{}` substituted)",
    "    -exec CMD {} +   batched: queue paths up to ARG_MAX, then exec",
    "    -execdir CMD ... like -exec but cwd is the file's parent dir",
    "",
    "Out of scope: -links, -inum, -anewer, full GNU -printf formatting.",
    (char *)NULL
};

struct builtin bashfind_struct = {
    "bashfind",
    find_builtin,
    BUILTIN_ENABLED,
    find_doc,
    "bashfind [-H|-L|-P] PATH... [EXPR]",
    0
};
