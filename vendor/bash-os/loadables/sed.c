/* bashsed.c — POSIX-shape sed(1) as a bash builtin.
 *
 * Phase A of bash-os shell-ergonomics. v1 covers the patterns that
 * 95% of one-liner sed usage needs: substitution (with capture
 * groups), delete/print/quit/=, address ranges, hold buffer,
 * labels/branches, blocks, in-place editing.
 *
 * Commands supported:
 *   [ADDR1[,ADDR2]] s/REGEX/REPLACE/[gipnN]
 *   [ADDR] d                 delete current line
 *   [ADDR] p                 print current line
 *   [ADDR] q                 quit immediately
 *   [ADDR] !COMMAND          apply COMMAND to lines NOT in addr
 *   [ADDR] =                 print line number
 *   [ADDR] h / H             copy/append pattern to hold buffer
 *   [ADDR] g / G             copy/append hold to pattern
 *   [ADDR] x                 swap pattern and hold
 *   [ADDR] a TEXT            append TEXT after current line
 *   [ADDR] i TEXT            insert TEXT before current line
 *   [ADDR] c TEXT            replace addressed range with TEXT
 *   [ADDR] y/SET1/SET2/      transliterate (1:1 byte map; sets same length)
 *   [ADDR] n                 next: print pattern, replace with next line
 *   [ADDR] N                 append next input line to pattern space
 *   [ADDR] D                 delete to first \n in pattern, restart cycle
 *   [ADDR] P                 print to first \n in pattern
 *   [ADDR] l                 print pattern space with escapes
 *   [ADDR] :LABEL            label
 *   [ADDR] b LABEL           unconditional branch
 *   [ADDR] t LABEL           branch if last s/// matched
 *   [ADDR] {COMMANDS}        block grouping
 *
 * Addresses:
 *   $          last line
 *   N          line number
 *   /REGEX/    regex match
 *   ADDR1,ADDR2  range
 *
 * Replace string supports & (whole match) and \1..\9 (capture groups).
 *
 * Flags:
 *   -i [SUFFIX]   in-place edit; SUFFIX (if non-empty) saves backup
 *   -e SCRIPT     append SCRIPT (multiple allowed; semicolon-joined)
 *   -f FILE       read commands from FILE
 *   -E            extended regex (always on; -E accepted no-op)
 *   -n            suppress default print
 *
 * Security: e / s///e shell execution is disabled unless
 * BASHSED_ALLOW_EXEC=1 is set.
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
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <regex.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "loadables.h"

/* Address kinds. */
typedef enum { BS_ADDR_NONE, BS_ADDR_LINE, BS_ADDR_LAST, BS_ADDR_REGEX,
               BS_ADDR_STEP,
               BS_ADDR_PLUS,   /* addr2 only: ,+N  -> end = start + N */
               BS_ADDR_MULT    /* addr2 only: ,~N  -> end = next multiple of N after start */
             } bs_addrkind;

typedef struct {
    bs_addrkind kind;
    long        line;        /* for ADDR_LINE; "first" for ADDR_STEP */
    long        step;        /* for ADDR_STEP (GNU first~step) */
    regex_t     re;          /* for ADDR_REGEX */
    int         re_ok;
} bs_addr;

/* Command kinds. */
typedef enum {
    BS_S, BS_D, BS_P, BS_Q, BS_BIGQ, BS_EQ,
    BS_H, BS_HUP, BS_G, BS_GUP, BS_X,
    BS_LABEL, BS_B, BS_T, BS_BIGT,   /* BS_BIGT = T: branch if NO s/// matched */
    BS_BLOCK_OPEN, BS_BLOCK_CLOSE,
    BS_A, BS_I, BS_C,    /* append / insert / change text */
    BS_R,                /* r FILE: append the file's contents after the line */
    BS_W,                /* w FILE: write the pattern space to a file */
    BS_BIGW,             /* W FILE: write only the first line of pattern space */
    BS_BIGR,             /* R FILE: read one line per cycle from a file */
    BS_F,                /* F: print the current input filename */
    BS_E,                /* e: execute pattern space via /bin/sh -c */
    BS_Y,                 /* y/SET1/SET2/ transliterate */
    BS_N_CMD, BS_NUP_CMD, /* n / N: refill or append next input line */
    BS_D_LO, BS_P_LO,     /* D / P: head-line delete / print (multi-line ops) */
    BS_L_CMD              /* l: print pattern with escapes */
} bs_cmdkind;

typedef struct {
    bs_cmdkind kind;
    bs_addr    addr1;        /* optional */
    bs_addr    addr2;        /* optional (range) */
    int        has_a1, has_a2;
    int        negate;       /* ! prefix */
    /* s/// */
    regex_t    s_re;
    int        s_re_ok;
    int        s_empty_re;   /* s//repl/ : reuse the last regex at runtime */
    char      *s_repl;       /* replacement, may contain & and \1..\9 */
    int        s_global;     /* g flag */
    int        s_print;      /* p flag */
    int        s_n;          /* N flag (substitute Nth match — simplified) */
    int        s_icase;      /* i flag */
    int        s_multiline;  /* m/M flag: ^/$ match at embedded newlines */
    int        s_exec;       /* e flag: execute resulting pattern space */
    int        q_code;       /* q/Q exit code (default 0) */
    char      *s_wfile;      /* s///w FILE : write substituted line to FILE */
    /* labels / branches */
    char      *label;
    int        target_idx;   /* resolved during second pass; -1 if unresolved */
    /* block grouping */
    int        block_close_idx;
    /* a/i/c text */
    char      *text;
    /* y/SET1/SET2/ — 256-byte translation table; y_active=1 if populated. */
    unsigned char y_table[256];
    int        y_active;
} bs_cmd;

typedef struct {
    char  *str;
    size_t len;
    size_t cap;
    int    failed;   /* once set, all further ops become no-ops */
} bs_string;

/* BRE→ERE compat: when we compile with REG_EXTENDED but the caller wrote
 * BRE-style escaped metacharacters (`\(`, `\)`, `\+`, `\?`, `\{`, `\}`,
 * `\|`), translate the escape away so the same metachar is recognized
 * by ERE. POSIX sed defaults to BRE; users will write `s/\(.\)\(.\)/\2\1/`
 * and expect capture groups. Returns a malloc'd buffer the caller frees;
 * NULL on OOM. Pattern is unchanged when it has no BRE escapes — `(`, `+`,
 * etc. without a leading `\` stay ERE-meta as before. Pre-escaped digits
 * (`\1`..`\9`) used by s/// in the REPLACEMENT half are NOT touched
 * here; this function only processes regex SOURCE patterns. */
static char *
bs_bre_to_ere_compat (const char *pat)
{
    if (!pat) return NULL;
    size_t n = strlen (pat);
    char *out = malloc (n + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        char c = pat[i];
        if (c == '\\' && i + 1 < n) {
            char nx = pat[i + 1];
            /* These BRE escapes are ERE meta when un-escaped. */
            if (nx == '(' || nx == ')' || nx == '+' || nx == '?'
                || nx == '{' || nx == '}' || nx == '|') {
                out[j++] = nx;
                i++;
                continue;
            }
        }
        out[j++] = c;
    }
    out[j] = '\0';
    return out;
}

static void
bs_str_init (bs_string *s) { s->str = NULL; s->len = 0; s->cap = 0; s->failed = 0; }
static void
bs_str_free (bs_string *s) { free (s->str); s->str = NULL; s->len = s->cap = 0; s->failed = 0; }
static int
bs_str_reserve (bs_string *s, size_t n)
{
    if (s->failed) return -1;
    if (n + 1 < n) { s->failed = 1; return -1; }   /* SIZE_MAX overflow */
    if (s->cap >= n + 1) return 0;
    size_t nc = s->cap ? s->cap * 2 : 64;
    while (nc < n + 1) {
        if (nc > SIZE_MAX / 2) { s->failed = 1; return -1; }
        nc *= 2;
    }
    char *p = realloc (s->str, nc);
    if (!p) { s->failed = 1; return -1; }
    s->str = p; s->cap = nc;
    return 0;
}
static int
bs_str_set (bs_string *s, const char *src, size_t srclen)
{
    if (s->failed) return -1;
    if (bs_str_reserve (s, srclen) < 0) return -1;
    memcpy (s->str, src, srclen);
    s->str[srclen] = '\0';
    s->len = srclen;
    return 0;
}
static int
bs_str_append (bs_string *s, const char *src, size_t srclen)
{
    if (s->failed) return -1;
    if (bs_str_reserve (s, s->len + srclen) < 0) return -1;
    memcpy (s->str + s->len, src, srclen);
    s->len += srclen;
    s->str[s->len] = '\0';
    return 0;
}

typedef struct {
    FILE *fp;
    int missing_newline;
} bs_output;

static bs_output bs_stdout, bs_stderr;

/* An unterminated pattern stays unterminated until another record is printed
   to the same output during this invocation (for example, p plus auto-print). */
static void
bs_emit (bs_output *out, const char *data, size_t len, int newline)
{
    if (out->missing_newline) fputc ('\n', out->fp);
    if (len) fwrite (data, 1, len, out->fp);
    if (newline) fputc ('\n', out->fp);
    out->missing_newline = !newline;
}

static void
bs_l_emit_token (FILE *out, const char *tok, size_t len, int *col)
{
    if (*col > 0 && *col + (int) len > 70)
    {
        fputs ("\\\n", out);
        *col = 0;
    }
    fwrite (tok, 1, len, out);
    *col += (int) len;
}

static void
bs_l_emit (FILE *out, const char *s, size_t len)
{
    int col = 0;
    for (size_t i = 0; i < len; i++)
    {
        unsigned char ch = (unsigned char) s[i];
        char oct[5];
        const char *tok = NULL;
        switch (ch)
        {
            case '\\': tok = "\\\\"; break;
            case '\a': tok = "\\a"; break;
            case '\b': tok = "\\b"; break;
            case '\f': tok = "\\f"; break;
            case '\n': tok = "\\n"; break;
            case '\r': tok = "\\r"; break;
            case '\t': tok = "\\t"; break;
            case '\v': tok = "\\v"; break;
            default:
                if (ch >= 0x20 && ch < 0x7f)
                {
                    char c = (char) ch;
                    bs_l_emit_token (out, &c, 1, &col);
                    continue;
                }
                snprintf (oct, sizeof oct, "\\%03o", ch);
                tok = oct;
                break;
        }
        bs_l_emit_token (out, tok, strlen (tok), &col);
    }
    fputs ("$\n", out);
}

/* Parse a single address from *psp. Advances *psp past the address.
   Returns 1 if an address was parsed, 0 if none, -1 on error. */
/* Decode one y/// set up to (but not consuming) the unescaped delimiter,
   resolving POSIX escapes (\n \t \r \a \f \v \\ and \<delim>). Leaves *pp at
   the delimiter. Returns 0 on success, -1 on overflow. */
static int
bs_y_decode (const char **pp, char delim, unsigned char *out, size_t cap, size_t *outlen)
{
    const char *p = *pp;
    size_t n = 0;
    while (*p && *p != delim) {
        unsigned char ch;
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
                case 'n': ch = '\n'; break;
                case 't': ch = '\t'; break;
                case 'r': ch = '\r'; break;
                case 'a': ch = '\a'; break;
                case 'f': ch = '\f'; break;
                case 'v': ch = '\v'; break;
                case '\\': ch = '\\'; break;
                /* \<delim> or any other escaped char: take it literally. */
                default:  ch = (unsigned char) *p; break;
            }
            p++;
        } else {
            ch = (unsigned char) *p; p++;
        }
        if (n >= cap) return -1;
        out[n++] = ch;
    }
    *pp = p; *outlen = n;
    return 0;
}

static int
bs_parse_addr (const char **psp, bs_addr *a, int icase)
{
    const char *p = *psp;
    while (*p == ' ' || *p == '\t') p++;
    a->kind = BS_ADDR_NONE; a->re_ok = 0;
    if (*p == '$') { a->kind = BS_ADDR_LAST; *psp = p + 1; return 1; }
    /* GNU relative end-addresses (valid only as addr2): ,+N and ,~N. */
    if (*p == '+' || *p == '~') {
        int mult = (*p == '~');
        p++;
        long n = 0;
        while (*p >= '0' && *p <= '9') { n = n * 10 + (*p - '0'); p++; }
        a->kind = mult ? BS_ADDR_MULT : BS_ADDR_PLUS;
        a->step = n;
        *psp = p;
        return 1;
    }
    if (*p >= '0' && *p <= '9')
    {
        a->kind = BS_ADDR_LINE;
        long n = 0;
        while (*p >= '0' && *p <= '9') { n = n * 10 + (*p - '0'); p++; }
        a->line = n;
        /* GNU step address: first~step (e.g. 1~2 = every other line). */
        if (*p == '~') {
            p++;
            long st = 0;
            while (*p >= '0' && *p <= '9') { st = st * 10 + (*p - '0'); p++; }
            a->kind = BS_ADDR_STEP;
            a->step = st;
        }
        *psp = p;
        return 1;
    }
    if (*p == '/')
    {
        const char *start = ++p;
        while (*p && *p != '/') {
            if (*p == '\\' && p[1]) p++;     /* skip escaped char */
            p++;
        }
        if (*p != '/') { builtin_error ("unterminated regex address"); return -1; }
        size_t rlen = (size_t) (p - start);
        char *pat_raw = strndup (start, rlen);
        if (!pat_raw) return -1;
        char *pat = bs_bre_to_ere_compat (pat_raw);
        free (pat_raw);
        if (!pat) return -1;
        int flags = REG_EXTENDED | REG_NEWLINE;
        if (icase) flags |= REG_ICASE;
        if (regcomp (&a->re, pat, flags) != 0) {
            builtin_error ("bad regex in address: %s", pat);
            free (pat); return -1;
        }
        free (pat);
        a->kind = BS_ADDR_REGEX;
        a->re_ok = 1;
        *psp = p + 1;
        return 1;
    }
    return 0;
}

/* Most recently used regex (address or s///), for POSIX empty-regex reuse
   (`s//repl/`, `//addr`). Reset at the start of each bs_run. */
static regex_t *bs_last_re = NULL;

/* q/Q quit signalling: when a q/Q command runs, the whole stream editor stops
   (across all input files) and exits with bs_quit_code. Reset by the builtin
   before processing. */
static int bs_quit_signaled = 0;
static int bs_quit_code = 0;
static int bs_runtime_error = 0;

static int
bs_exec_allowed (void)
{
    const char *v = getenv ("BASHSED_ALLOW_EXEC");
    return v && strcmp (v, "1") == 0;
}

static int
bs_exec_capture (const char *cmd, bs_string *out)
{
    FILE *fp;
    char buf[4096];
    size_t got;

    bs_str_set (out, "", 0);
    if (!bs_exec_allowed ()) {
        builtin_error ("e command requires BASHSED_ALLOW_EXEC=1");
        bs_runtime_error = 1;
        return -1;
    }

    fp = popen (cmd ? cmd : "", "r");
    if (!fp) {
        builtin_error ("e command failed: %s", strerror (errno));
        bs_runtime_error = 1;
        return -1;
    }

    while ((got = fread (buf, 1, sizeof buf, fp)) > 0)
        bs_str_append (out, buf, got);
    pclose (fp);

    if (out->len > 0 && out->str[out->len - 1] == '\n')
        out->str[--out->len] = '\0';
    if (out->failed) {
        bs_runtime_error = 1;
        return -1;
    }
    return 0;
}

/* Write-stream table for `w FILE` / `s///w FILE`. Each distinct path is opened
   once (truncating) and shared across commands and input files (GNU semantics);
   closed by the builtin at the end. */
#define BS_MAX_WSTREAMS 64
static struct { char *path; bs_output out; } bs_wstreams[BS_MAX_WSTREAMS];
static int bs_n_wstreams = 0;

static bs_output *
bs_get_wstream (const char *path)
{
    if (!path || !*path) return NULL;
    if (!strcmp (path, "/dev/stdout")) return &bs_stdout;
    if (!strcmp (path, "/dev/stderr")) return &bs_stderr;
    for (int i = 0; i < bs_n_wstreams; i++)
        if (!strcmp (bs_wstreams[i].path, path)) return &bs_wstreams[i].out;
    if (bs_n_wstreams >= BS_MAX_WSTREAMS) { bs_runtime_error = 1; return NULL; }
    FILE *fp = fopen (path, "w");   /* truncate on first use */
    if (!fp) {
        builtin_error ("%s: %s", path, strerror (errno));
        bs_runtime_error = 1;
        return NULL;
    }
    char *copy = strdup (path);
    if (!copy) { fclose (fp); bs_runtime_error = 1; return NULL; }
    bs_wstreams[bs_n_wstreams].path = copy;
    bs_wstreams[bs_n_wstreams].out = (bs_output) { fp, 0 };
    return &bs_wstreams[bs_n_wstreams++].out;
}

static int
bs_close_wstreams (void)
{
    int failed = 0;
    for (int i = 0; i < bs_n_wstreams; i++) {
        FILE *fp = bs_wstreams[i].out.fp;
        int error = ferror (fp);
        if (fclose (fp) != 0 || error) {
            builtin_error ("%s: write error", bs_wstreams[i].path);
            failed = 1;
        }
        free (bs_wstreams[i].path);
        bs_wstreams[i].path = NULL; bs_wstreams[i].out.fp = NULL;
    }
    bs_n_wstreams = 0;
    return failed ? -1 : 0;
}

/* Read-stream table for `R FILE`: each path keeps a persistent handle so
   successive R commands consume successive lines. */
#define BS_MAX_RSTREAMS 64
static struct { char *path; FILE *fp; } bs_rstreams[BS_MAX_RSTREAMS];
static int bs_n_rstreams = 0;

static FILE *
bs_get_rstream (const char *path)
{
    if (!path || !*path) return NULL;
    for (int i = 0; i < bs_n_rstreams; i++)
        if (!strcmp (bs_rstreams[i].path, path)) return bs_rstreams[i].fp;
    if (bs_n_rstreams >= BS_MAX_RSTREAMS) return NULL;
    FILE *fp = fopen (path, "r");   /* NULL handle is cached so we don't retry */
    bs_rstreams[bs_n_rstreams].path = strdup (path);
    bs_rstreams[bs_n_rstreams].fp = fp;
    bs_n_rstreams++;
    return fp;
}

static void
bs_close_rstreams (void)
{
    for (int i = 0; i < bs_n_rstreams; i++) {
        if (bs_rstreams[i].fp) fclose (bs_rstreams[i].fp);
        free (bs_rstreams[i].path);
        bs_rstreams[i].path = NULL; bs_rstreams[i].fp = NULL;
    }
    bs_n_rstreams = 0;
}

static int
bs_addr_match (bs_addr *a, long lineno, int is_last, const char *line)
{
    if (a->kind == BS_ADDR_REGEX && a->re_ok)
        bs_last_re = &a->re;   /* track for empty-regex reuse */
    switch (a->kind)
    {
        case BS_ADDR_NONE: return 0;
        case BS_ADDR_LINE: return lineno == a->line;
        case BS_ADDR_STEP:
            /* first~step: match lines first, first+step, first+2*step, …
               step<=0 degenerates to just the single line `first` (GNU). */
            if (a->step <= 0) return lineno == a->line;
            return lineno >= a->line && (lineno - a->line) % a->step == 0;
        case BS_ADDR_LAST: return is_last;
        case BS_ADDR_REGEX:
            if (!a->re_ok) return 0;
            return regexec (&a->re, line, 0, NULL, 0) == 0;
    }
    return 0;
}

/* Free per-command resources. */
static void
bs_cmd_free (bs_cmd *c)
{
    if (c->addr1.re_ok) regfree (&c->addr1.re);
    if (c->addr2.re_ok) regfree (&c->addr2.re);
    if (c->s_re_ok)     regfree (&c->s_re);
    free (c->s_repl);
    free (c->label);
    free (c->text);
    free (c->s_wfile);
    memset (c, 0, sizeof *c);
}

/* Parse the entire script into a flat command list. Returns malloc'd
   array; *out_n is the count. Returns -1 on parse error. */
static int
bs_parse_script (const char *script, bs_cmd **out_cmds, int *out_n)
{
    int cap = 16, n = 0;
    bs_cmd *cmds = calloc ((size_t) cap, sizeof *cmds);
    if (!cmds) return -1;
    const char *p = script;
    int seen_regex = 0;   /* any regex (address or s///) seen so far, for s// reuse */
    while (*p)
    {
        if (n == cap)
        {
            if (cap > INT_MAX / 2 || (size_t) cap > SIZE_MAX / sizeof *cmds / 2) goto err;
            int new_cap = cap * 2;
            bs_cmd *bigger = realloc (cmds, (size_t) new_cap * sizeof *cmds);
            if (!bigger) goto err;
            cmds = bigger;
            memset (cmds + n, 0, (size_t) (new_cap - n) * sizeof *cmds);
            cap = new_cap;
        }
        bs_cmd *c = &cmds[n];

        /* skip whitespace + separators */
        while (*p == ' ' || *p == '\t' || *p == ';' || *p == '\n') p++;
        if (!*p) break;

        /* Comment? */
        if (*p == '#') { while (*p && *p != '\n') p++; continue; }

        /* Parse address(es). */
        int got_a = bs_parse_addr (&p, &c->addr1, 0);
        if (got_a < 0) goto err;
        c->has_a1 = got_a;
        if (c->addr1.kind == BS_ADDR_REGEX) seen_regex = 1;
        if (c->has_a1 && *p == ',')
        {
            p++;
            int got2 = bs_parse_addr (&p, &c->addr2, 0);
            if (got2 < 0) goto err;
            c->has_a2 = got2;
            if (c->addr2.kind == BS_ADDR_REGEX) seen_regex = 1;
        }
        while (*p == ' ' || *p == '\t') p++;

        /* ! ? */
        if (*p == '!') { c->negate = 1; p++; while (*p == ' ' || *p == '\t') p++; }

        /* Command character. */
        char op = *p++;
        switch (op)
        {
            case 's':
            {
                c->kind = BS_S;
                if (!*p) { builtin_error ("s/// missing delimiter"); goto err; }
                char delim = *p++;
                /* regex */
                const char *re_start = p;
                while (*p && *p != delim) {
                    if (*p == '\\' && p[1]) p++;
                    p++;
                }
                if (*p != delim) { builtin_error ("s/// unterminated regex"); goto err; }
                size_t rlen = (size_t) (p - re_start);
                char *pat = strndup (re_start, rlen);
                if (!pat) goto err;
                p++;   /* skip delim */
                /* replacement */
                const char *rep_start = p;
                while (*p && *p != delim) {
                    if (*p == '\\' && p[1]) p++;
                    p++;
                }
                if (*p != delim) { free (pat); builtin_error ("s/// unterminated replace"); goto err; }
                size_t replen = (size_t) (p - rep_start);
                c->s_repl = strndup (rep_start, replen);
                if (!c->s_repl) { free (pat); goto err; }
                p++;   /* skip closing delim */
                /* flags */
                while (*p && *p != ';' && *p != '\n')
                {
                    if      (*p == 'g') c->s_global = 1;
                    else if (*p == 'p') c->s_print = 1;
                    else if (*p == 'i' || *p == 'I') c->s_icase = 1;
                    else if (*p == 'm' || *p == 'M') c->s_multiline = 1;
                    else if (*p == 'e') c->s_exec = 1;
                    else if (*p == 'w') {
                        /* w FILE must be the LAST flag: rest of line = filename. */
                        p++;
                        while (*p == ' ' || *p == '\t') p++;
                        const char *wf = p;
                        while (*p && *p != '\n') p++;
                        c->s_wfile = strndup (wf, (size_t) (p - wf));
                        break;
                    }
                    else if (*p >= '0' && *p <= '9') {
                        int occurrence = 0;
                        while (*p >= '0' && *p <= '9') { occurrence = occurrence * 10 + (*p - '0'); p++; }
                        c->s_n = occurrence;
                        continue;
                    }
                    else if (*p == ' ' || *p == '\t') { /* skip — fall through to p++ */ }
                    else break;
                    p++;
                }
                int rflags = REG_EXTENDED;
                if (c->s_icase) rflags |= REG_ICASE;
                /* m/M: ^ and $ match at embedded newlines in the pattern
                   space (REG_NEWLINE), like GNU sed's multiline flag. */
                if (c->s_multiline) rflags |= REG_NEWLINE;
                if (rlen == 0) {
                    /* Empty regex: POSIX reuses the last regex used (address
                       or s///) at runtime. Like GNU, error at parse time if no
                       regex has appeared lexically before this point. */
                    free (pat);
                    if (!seen_regex) {
                        builtin_error ("no previous regular expression");
                        goto err;
                    }
                    c->s_empty_re = 1;
                    break;
                }
                seen_regex = 1;
                char *pat_compat = bs_bre_to_ere_compat (pat);
                free (pat);
                if (!pat_compat) goto err;
                if (regcomp (&c->s_re, pat_compat, rflags) != 0) {
                    builtin_error ("s/// bad regex: %s", pat_compat);
                    free (pat_compat); goto err;
                }
                free (pat_compat);
                c->s_re_ok = 1;
                break;
            }
            case 'd': c->kind = BS_D; break;
            case 'p': c->kind = BS_P; break;
            case 'q': case 'Q':
                c->kind = (op == 'q') ? BS_Q : BS_BIGQ;  /* Q quits without auto-print */
                /* optional exit code: q N / Q N (POSIX). Default 0. */
                while (*p == ' ' || *p == '\t') p++;
                if (*p >= '0' && *p <= '9') {
                    int code = 0;
                    while (*p >= '0' && *p <= '9') { code = code * 10 + (*p - '0'); p++; }
                    c->q_code = code & 0xff;
                }
                break;
            case '=': c->kind = BS_EQ; break;
            case 'F': c->kind = BS_F; break;   /* print current input filename */
            case 'e': c->kind = BS_E; break;   /* execute pattern space */
            case 'h': c->kind = BS_H; break;
            case 'H': c->kind = BS_HUP; break;
            case 'g': c->kind = BS_G; break;
            case 'G': c->kind = BS_GUP; break;
            case 'x': c->kind = BS_X; break;
            case 'n': c->kind = BS_N_CMD; break;
            case 'N': c->kind = BS_NUP_CMD; break;
            case 'D': c->kind = BS_D_LO; break;
            case 'P': c->kind = BS_P_LO; break;
            case 'l': c->kind = BS_L_CMD; break;
            case ':':
                c->kind = BS_LABEL;
                while (*p == ' ' || *p == '\t') p++;
                {
                    const char *s = p;
                    while (*p && *p != ' ' && *p != '\t' && *p != ';' && *p != '\n') p++;
                    c->label = strndup (s, (size_t) (p - s));
                }
                break;
            case 'r': case 'R': {
                /* r FILE: append the whole file after the line. R FILE: append
                   ONE line per cycle (sequential). Filename = rest of line. */
                c->kind = (op == 'r') ? BS_R : BS_BIGR;
                while (*p == ' ' || *p == '\t') p++;
                const char *s = p;
                while (*p && *p != '\n') p++;
                c->text = strndup (s, (size_t) (p - s));
                break;
            }
            case 'w': case 'W': {
                /* w FILE: write the pattern space to FILE; W: only its first
                   line (up to the first embedded newline). Rest of line=FILE. */
                c->kind = (op == 'w') ? BS_W : BS_BIGW;
                while (*p == ' ' || *p == '\t') p++;
                const char *s = p;
                while (*p && *p != '\n') p++;
                c->text = strndup (s, (size_t) (p - s));
                break;
            }
            case 'b': case 't': case 'T':
                c->kind = (op == 'b') ? BS_B : (op == 't') ? BS_T : BS_BIGT;
                while (*p == ' ' || *p == '\t') p++;
                {
                    const char *s = p;
                    while (*p && *p != ';' && *p != '\n') p++;
                    /* trim trailing space */
                    const char *e = p;
                    while (e > s && (e[-1] == ' ' || e[-1] == '\t')) e--;
                    c->label = strndup (s, (size_t) (e - s));
                    c->target_idx = -1;
                }
                break;
            case '{': c->kind = BS_BLOCK_OPEN;  break;
            case '}': c->kind = BS_BLOCK_CLOSE; break;
            case 'y':
                c->kind = BS_Y;
                {
                    /* y/SET1/SET2/ — sets (with POSIX escapes decoded) must be
                       the same length. */
                    char delim = *p;
                    if (!delim) { builtin_error ("y: missing delimiter"); goto err; }
                    p++;
                    unsigned char set1[256], set2[256];
                    size_t l1 = 0, l2 = 0;
                    if (bs_y_decode (&p, delim, set1, sizeof set1, &l1) < 0)
                        { builtin_error ("y: SET1 too long"); goto err; }
                    if (*p != delim) { builtin_error ("y: missing 2nd delim"); goto err; }
                    p++;
                    if (bs_y_decode (&p, delim, set2, sizeof set2, &l2) < 0)
                        { builtin_error ("y: SET2 too long"); goto err; }
                    if (*p != delim) { builtin_error ("y: missing 3rd delim"); goto err; }
                    p++;
                    if (l1 != l2) { builtin_error ("y: SET1 and SET2 must be same length"); goto err; }
                    /* identity table, then map SET1[i] -> SET2[i]. */
                    for (int i = 0; i < 256; i++) c->y_table[i] = (unsigned char) i;
                    for (size_t i = 0; i < l1; i++)
                        c->y_table[set1[i]] = set2[i];
                    c->y_active = 1;
                }
                break;
            case 'a': case 'i': case 'c':
                /* a/i/c TEXT: text starts after optional `\` continuation
                   or whitespace.  bash-os accepts the single-line form
                   `aTEXT` and `a TEXT`.  Per spec §1.19 edit 3 in
                   `COREUTILS-IMPLEMENTATION-STEPS.md:886-913`, the
                   parser honors backslash-newline continuation: a
                   trailing `\` immediately before a literal `\n` in the
                   script folds into a literal newline in the output
                   text, and scanning continues on the next line.
                   Un-continued `\n` or `;` terminates the TEXT. */
                c->kind = (op == 'a') ? BS_A : (op == 'i') ? BS_I : BS_C;
                {
                    /* Skip optional leading whitespace and `\` continuation. */
                    if (*p == '\\') {
                        p++;
                        /* POSIX/GNU `a\<newline>text` form: a backslash
                           immediately followed by a newline means the text
                           begins on the next line — consume that newline. */
                        if (*p == '\n') p++;
                    }
                    while (*p == ' ' || *p == '\t') p++;
                    /* First pass: scan to the end of the (possibly
                       continued) TEXT.  A `\n` is the terminator unless
                       the immediately-preceding source byte is `\\`,
                       in which case the pair `\\\n` is a continuation
                       and we keep scanning. */
                    const char *s = p;
                    while (*p) {
                        if (*p == ';') break;
                        if (*p == '\n') {
                            if (p > s && p[-1] == '\\') {
                                p++;          /* swallow the LF; keep scanning */
                                continue;
                            }
                            break;
                        }
                        p++;
                    }
                    /* Second pass: copy [s..p), replacing every two-
                       byte sequence `\\\n` with a single `\n`.  Output
                       length is bounded above by the input length so
                       one malloc is enough. */
                    size_t total = (size_t) (p - s);
                    c->text = malloc (total + 1);
                    if (!c->text) goto err;
                    size_t out_i = 0;
                    for (size_t i = 0; i < total; i++) {
                        if (i + 1 < total && s[i] == '\\' && s[i + 1] == '\n') {
                            c->text[out_i++] = '\n';
                            i++;              /* skip the consumed LF */
                        } else {
                            c->text[out_i++] = s[i];
                        }
                    }
                    c->text[out_i] = '\0';
                }
                break;
            default:
                if (op >= 0x20 && op < 0x7f)
                    builtin_error ("unknown command: %c", op);
                else
                    builtin_error ("unknown command: 0x%02x", (unsigned) op);
                goto err;
        }
        n++;
    }

    /* Resolve labels. */
    for (int i = 0; i < n; i++)
    {
        if (cmds[i].kind == BS_B || cmds[i].kind == BS_T || cmds[i].kind == BS_BIGT)
        {
            if (!cmds[i].label || !*cmds[i].label) continue;  /* branch to end */
            int found = -1;
            for (int j = 0; j < n; j++)
            {
                if (cmds[j].kind == BS_LABEL &&
                    cmds[j].label && !strcmp (cmds[j].label, cmds[i].label))
                {
                    found = j; break;
                }
            }
            if (found < 0) {
                builtin_error ("undefined label: %s", cmds[i].label);
                goto err;
            }
            cmds[i].target_idx = found;
        }
    }
    /* Resolve {...} matching close indexes. */
    for (int i = 0; i < n; i++)
    {
        if (cmds[i].kind == BS_BLOCK_OPEN)
        {
            int depth = 1, j;
            for (j = i + 1; j < n && depth > 0; j++)
            {
                if (cmds[j].kind == BS_BLOCK_OPEN) depth++;
                else if (cmds[j].kind == BS_BLOCK_CLOSE) depth--;
            }
            if (depth != 0) {
                builtin_error ("unbalanced { ... }");
                goto err;
            }
            cmds[i].block_close_idx = j - 1;
        }
    }

    *out_cmds = cmds; *out_n = n;
    return 0;
err:
    for (int i = 0; i <= n; i++) bs_cmd_free (&cmds[i]);
    free (cmds);
    return -1;
}

/* Append a buffer to `out` applying GNU sed replacement case conversion.
   *mode is the active span ('U'/'L'/0 from \U \L \E); *one is a one-shot
   ('u'/'l'/0 from \u \l) consumed on the first emitted character. The
   one-shot takes precedence over the span for that one character. A chunk
   of length 0 leaves *one pending for the next chunk (matches GNU). */
static void
bs_case_append (bs_string *out, const char *s, size_t n, int *mode, int *one)
{
    for (size_t i = 0; i < n; i++) {
        char ch = s[i];
        if (*one == 'u')      { ch = (char) toupper ((unsigned char) ch); *one = 0; }
        else if (*one == 'l') { ch = (char) tolower ((unsigned char) ch); *one = 0; }
        else if (*mode == 'U') ch = (char) toupper ((unsigned char) ch);
        else if (*mode == 'L') ch = (char) tolower ((unsigned char) ch);
        bs_str_append (out, &ch, 1);
    }
}

/* Emit the replacement string for one match (expanding & and \1..\9).
   `off` is the absolute offset within pat->str that m[*] are relative to.
   Honors GNU sed case-conversion directives \U \L \u \l \E. */
static void
bs_emit_replace (bs_cmd *c, bs_string *pat, regmatch_t *m, size_t off, bs_string *out)
{
    int mode = 0;   /* 0 / 'U' / 'L' : \U \L span, ended by \E */
    int one  = 0;   /* 0 / 'u' / 'l' : \u \l one-shot */
    for (const char *r = c->s_repl; *r; r++)
    {
        if (*r == '\\' && r[1] >= '1' && r[1] <= '9') {
            int idx = r[1] - '0';
            r++;
            if (m[idx].rm_so >= 0) {
                size_t s = (size_t) m[idx].rm_so + off;
                size_t e = (size_t) m[idx].rm_eo + off;
                bs_case_append (out, pat->str + s, e - s, &mode, &one);
            }
        }
        else if (*r == '\\' && r[1]) {
            r++;
            /* Case-conversion directives (GNU sed). */
            switch (*r) {
                case 'U': mode = 'U'; continue;
                case 'L': mode = 'L'; continue;
                case 'E': mode = 0;   continue;
                case 'u': one  = 'u'; continue;
                case 'l': one  = 'l'; continue;
            }
            /* Recognized escape sequences: \n \t \\ ; everything else
               passes through as the literal character (matches GNU sed). */
            char e_ch;
            switch (*r) {
                case 'n': e_ch = '\n'; break;
                case 't': e_ch = '\t'; break;
                case '\\': e_ch = '\\'; break;
                default:  e_ch = *r;   break;
            }
            bs_case_append (out, &e_ch, 1, &mode, &one);
        }
        else if (*r == '&') {
            size_t s = (size_t) m[0].rm_so + off;
            size_t e = (size_t) m[0].rm_eo + off;
            bs_case_append (out, pat->str + s, e - s, &mode, &one);
        }
        else {
            bs_case_append (out, r, 1, &mode, &one);
        }
    }
}

/* Apply s/// to pattern space. Returns 1 if matched (and substituted). */
static int
bs_apply_s (bs_cmd *c, bs_string *pat)
{
    regmatch_t m[10];
    int matched_any = 0;
    size_t off = 0;
    bs_string out;
    /* Effective regex: an empty s// reuses the last regex used at runtime. */
    regex_t *re = c->s_empty_re ? bs_last_re : &c->s_re;
    if (!re) { builtin_error ("no previous regular expression"); return 0; }
    bs_last_re = re;
    bs_str_init (&out);

    /* POSIX/GNU occurrence semantics. `s_n` is the numeric flag (0 if absent):
         s///        -> replace occurrence 1 only      (start=1, !global)
         s///g       -> replace all from occurrence 1  (start=1, global)
         s///N       -> replace occurrence N only      (start=N, !global)
         s///Ng      -> replace occurrence N and after (start=N, global)
       Occurrences before `start` are copied through unchanged. */
    int start = c->s_n > 0 ? c->s_n : 1;
    int idx = 0;                       /* 1-based occurrence counter */
    size_t last_end = (size_t) -1;     /* abs end of previous match (none yet) */

    while (off <= pat->len)
    {
        if (regexec (re, pat->str + off, 10, m, off > 0 ? REG_NOTBOL : 0) != 0)
            break;
        /* GNU/POSIX: an empty match is suppressed when it sits exactly at the
           end of the previous match (prevents a spurious extra replacement
           when a star-quantified pattern matches non-empty then empty at the
           same spot). Copy the lead-up + one char and skip. */
        if (m[0].rm_so == m[0].rm_eo
            && (size_t) (off + m[0].rm_so) == last_end)
        {
            if (m[0].rm_so > 0)
                bs_str_append (&out, pat->str + off, (size_t) m[0].rm_so);
            off += (size_t) m[0].rm_so;
            if (off < pat->len) { bs_str_append (&out, pat->str + off, 1); off++; }
            else off = pat->len + 1;
            continue;
        }
        idx++;
        int do_sub = (idx >= start) && (c->s_global || idx == start);
        int last_for_nonglobal = (do_sub && !c->s_global);  /* stop after this one */

        if (m[0].rm_so == m[0].rm_eo)
        {
            /* zero-width match: first copy any text BEFORE the match position
               (e.g. `$` matches empty at end-of-string, rm_so > 0), then
               (optionally) emit the replacement, then advance one char to
               avoid an infinite loop. POSIX/GNU: 's/X<star>/Y/g' on "ab"
               produces "YaYbY"; 's/$/!/' on "abc" produces "abc!". */
            if (m[0].rm_so > 0)
                bs_str_append (&out, pat->str + off, (size_t) m[0].rm_so);
            if (do_sub) { bs_emit_replace (c, pat, m, off, &out); matched_any = 1; }
            off += (size_t) m[0].rm_so;   /* advance to the match position */
            last_end = off;               /* this empty match ends here */
            if (last_for_nonglobal)
            {
                if (off < pat->len) bs_str_append (&out, pat->str + off, pat->len - off);
                off = pat->len + 1;
                break;
            }
            if (off < pat->len) bs_str_append (&out, pat->str + off, 1);
            off++;
            continue;
        }
        /* Append the lead-up. */
        bs_str_append (&out, pat->str + off, (size_t) m[0].rm_so);
        if (do_sub) { bs_emit_replace (c, pat, m, off, &out); matched_any = 1; }
        else        /* occurrence skipped (< Nth): copy it through verbatim */
            bs_str_append (&out, pat->str + off + (size_t) m[0].rm_so,
                           (size_t) (m[0].rm_eo - m[0].rm_so));
        off += (size_t) m[0].rm_eo;
        last_end = off;                   /* non-empty match ends here */
        if (last_for_nonglobal)
        {
            /* Append rest of pattern. */
            if (off < pat->len) bs_str_append (&out, pat->str + off, pat->len - off);
            off = pat->len + 1;
            break;
        }
    }
    if (matched_any && !out.failed)
    {
        if (off <= pat->len)
            bs_str_append (&out, pat->str + off, pat->len - off);
        if (!out.failed) {
            if (c->s_exec) {
                bs_string exec_out;
                bs_str_init (&exec_out);
                if (bs_exec_capture (out.str ? out.str : "", &exec_out) < 0) {
                    bs_str_free (&exec_out);
                    bs_str_free (&out);
                    return -1;
                }
                bs_str_set (pat, exec_out.str ? exec_out.str : "", exec_out.len);
                bs_str_free (&exec_out);
            } else {
                bs_str_set (pat, out.str ? out.str : "", out.len);
            }
        }
    }
    bs_str_free (&out);
    return matched_any;
}

/* Only an evaluated $ address needs lookahead. Ordinary cycles, including
   q before a later $ command, must not consume the next byte from a pipe. */
static int
bs_input_addr_match (bs_addr *addr, long lineno, int *is_last, const char *pat, FILE *in)
{
    if (addr->kind == BS_ADDR_LAST && *is_last < 0) {
        int ch = getc (in);
        *is_last = ch == EOF;
        if (ch != EOF) ungetc (ch, in);
    }
    return bs_addr_match (addr, lineno, *is_last > 0, pat);
}

/* Run the script over an input stream. Returns 0 on success. */
static int
bs_run (bs_cmd *cmds, int n_cmds, FILE *in, bs_output *out, int suppress_default, const char *filename)
{
    char *cur = NULL;
    size_t cur_cap = 0;
    ssize_t rd;
    int pat_nl = 1, hold_nl = 1;

    bs_string pat, hold, a_queue;
    bs_str_init (&pat); bs_str_init (&hold); bs_str_init (&a_queue);

    bs_last_re = NULL;   /* reset empty-regex-reuse tracking for this run */
    bs_runtime_error = 0;

    /* range_active[i]: 1 if a 2-address range is currently open for cmd i.
       range_end[i]: computed end line for ,+N / ,~N relative end-addresses. */
    int *range_active = calloc ((size_t) n_cmds, sizeof *range_active);
    long *range_end = calloc ((size_t) n_cmds, sizeof *range_end);

    /* GNU `0,/re/`: a range whose start address is line 0 is active from the
       very first line, so addr2 (a regex) can close it on line 1 — unlike
       `1,/re/`, where addr2 is not tested until line 2. Pre-open these. */
    if (range_active)
        for (int i = 0; i < n_cmds; i++)
            if (cmds[i].has_a1 && cmds[i].has_a2
                && cmds[i].addr1.kind == BS_ADDR_LINE && cmds[i].addr1.line == 0
                && cmds[i].addr2.kind == BS_ADDR_REGEX)
                range_active[i] = 1;

    if (n_cmds && (!range_active || !range_end)) {
        bs_runtime_error = 1;
        goto done;
    }
    long lineno = 0;
    while ((rd = getline (&cur, &cur_cap, in)) >= 0)
    {
        lineno++;
        pat_nl = rd > 0 && cur[rd - 1] == '\n';
        int is_last = -1;
        bs_str_set (&pat, cur, (size_t) rd - pat_nl);

        int last_subst = 0;
        int suppress_this_line = 0;   /* set by BS_C */
    restart_script:
        for (int ci = 0; ci < n_cmds; ci++)
        {
            bs_cmd *c = &cmds[ci];

            /* Address matching. */
            int addr_match = 1;
            if (c->has_a1 && !c->has_a2)
            {
                addr_match = bs_input_addr_match (&c->addr1, lineno, &is_last, pat.str, in);
            }
            else if (c->has_a1 && c->has_a2)
            {
                if (range_active[ci])
                {
                    addr_match = 1;
                    int close;
                    if (c->addr2.kind == BS_ADDR_PLUS || c->addr2.kind == BS_ADDR_MULT)
                        close = (lineno >= range_end[ci]);
                    else
                        close = bs_input_addr_match (&c->addr2, lineno, &is_last, pat.str, in);
                    if (close) range_active[ci] = 0;
                }
                else if (bs_input_addr_match (&c->addr1, lineno, &is_last, pat.str, in))
                {
                    addr_match = 1;
                    range_active[ci] = 1;
                    if (c->addr2.kind == BS_ADDR_PLUS) {
                        /* ,+N : end N lines after addr1; +0 = single line. */
                        range_end[ci] = lineno + c->addr2.step;
                        if (lineno >= range_end[ci]) range_active[ci] = 0;
                    }
                    else if (c->addr2.kind == BS_ADDR_MULT) {
                        /* ,~N : next multiple of N strictly after addr1. */
                        long N = c->addr2.step;
                        if (N <= 0) range_active[ci] = 0;
                        else range_end[ci] = (lineno / N + 1) * N;
                    }
                    /* A regexp end-address is only tested from the line AFTER
                       addr1 (POSIX/GNU), so it can never close the range on the
                       opening line. A line-number/$ end-address may yield a
                       single-line range when it already holds here. */
                    else if (c->addr2.kind != BS_ADDR_REGEX
                        && bs_input_addr_match (&c->addr2, lineno, &is_last, pat.str, in))
                        range_active[ci] = 0;
                }
                else addr_match = 0;
            }
            if (c->negate) addr_match = !addr_match;
            if (!addr_match) {
                /* For BLOCK_OPEN with no match, skip to matching close. */
                if (c->kind == BS_BLOCK_OPEN) ci = c->block_close_idx;
                continue;
            }

            switch (c->kind)
            {
                case BS_S:
                    last_subst = bs_apply_s (c, &pat);
                    if (last_subst < 0)
                        goto done;
                    if (last_subst && c->s_print) {
                        bs_emit (out, pat.str, pat.len, pat_nl);
                    }
                    /* s///w FILE: on a successful substitution, write the
                       resulting pattern space to FILE. */
                    if (last_subst && c->s_wfile) {
                        bs_output *wf = bs_get_wstream (c->s_wfile);
                        if (wf) bs_emit (wf, pat.str, pat.len, pat_nl);
                    }
                    break;
                case BS_D:
                    /* Skip to next input line. */
                    pat.len = 0;
                    if (pat.str) pat.str[0] = '\0';
                    goto next_line;
                case BS_P:
                    bs_emit (out, pat.str, pat.len, pat_nl);
                    break;
                case BS_Q:
                    if (!suppress_default) {
                        bs_emit (out, pat.str, pat.len, pat_nl);
                    }
                    bs_quit_signaled = 1; bs_quit_code = c->q_code;
                    goto done;
                case BS_BIGQ:
                    /* Q: quit immediately WITHOUT auto-printing the line. */
                    bs_quit_signaled = 1; bs_quit_code = c->q_code;
                    goto done;
                case BS_EQ:
                    if (out->missing_newline) fputc ('\n', out->fp);
                    fprintf (out->fp, "%ld\n", lineno);
                    out->missing_newline = 0;
                    break;
                case BS_F:
                    /* Print the current input filename ("-" for stdin). */
                    bs_emit (out, filename ? filename : "-",
                             strlen (filename ? filename : "-"), 1);
                    break;
                case BS_E: {
                    bs_string exec_out;
                    bs_str_init (&exec_out);
                    if (bs_exec_capture (pat.str ? pat.str : "", &exec_out) < 0) {
                        bs_str_free (&exec_out);
                        goto done;
                    }
                    bs_str_set (&pat, exec_out.str ? exec_out.str : "", exec_out.len);
                    bs_str_free (&exec_out);
                    break;
                }
                case BS_H:
                    bs_str_set (&hold, pat.str, pat.len);
                    hold_nl = pat_nl;
                    break;
                case BS_HUP:
                    bs_str_append (&hold, "\n", 1);
                    bs_str_append (&hold, pat.str, pat.len);
                    hold_nl = pat_nl;
                    break;
                case BS_G:
                    bs_str_set (&pat, hold.str ? hold.str : "", hold.len);
                    pat_nl = hold_nl;
                    break;
                case BS_GUP:
                    bs_str_append (&pat, "\n", 1);
                    bs_str_append (&pat, hold.str ? hold.str : "", hold.len);
                    pat_nl = hold_nl;
                    break;
                case BS_X:
                {
                    bs_string tmp = pat; pat = hold; hold = tmp;
                    int tmp_nl = pat_nl; pat_nl = hold_nl; hold_nl = tmp_nl;
                    break;
                }
                case BS_LABEL:
                case BS_BLOCK_OPEN:
                case BS_BLOCK_CLOSE:
                    break;
                case BS_B:
                    if (c->target_idx >= 0) ci = c->target_idx;
                    else ci = n_cmds;       /* branch to end */
                    break;
                case BS_T:
                    if (last_subst) {
                        last_subst = 0;
                        if (c->target_idx >= 0) ci = c->target_idx;
                        else ci = n_cmds;
                    }
                    break;
                case BS_BIGT:
                    /* Branch if NO s/// has succeeded since the last input line
                       or branch taken. The flag is reset when the branch is
                       taken (it is already 0 here) — mirror of BS_T. */
                    if (!last_subst) {
                        if (c->target_idx >= 0) ci = c->target_idx;
                        else ci = n_cmds;
                    } else {
                        last_subst = 0;
                    }
                    break;
                case BS_I:
                    /* Insert: emit text immediately (before pat prints). */
                    if (c->text) bs_emit (out, c->text, strlen (c->text), 1);
                    break;
                case BS_Y:
                    /* Transliterate per the y_table. */
                    if (c->y_active && pat.str) {
                        for (size_t i = 0; i < pat.len; i++)
                            pat.str[i] = (char) c->y_table[(unsigned char) pat.str[i]];
                    }
                    break;
                case BS_P_LO:
                    /* Print pattern up to first \n (or whole pattern if none). */
                    if (pat.str) {
                        size_t i = 0;
                        while (i < pat.len && pat.str[i] != '\n') i++;
                        bs_emit (out, pat.str, i, i < pat.len || pat_nl);
                    }
                    break;
                case BS_L_CMD:
                    /* Print pattern with sed l-command escapes. */
                    if (pat.str) {
                        if (out->missing_newline) fputc ('\n', out->fp);
                        bs_l_emit (out->fp, pat.str, pat.len);
                        out->missing_newline = 0;
                    }
                    break;
                case BS_N_CMD:
                    if (!suppress_default) {
                        bs_emit (out, pat.str, pat.len, pat_nl);
                    }
                    if (a_queue.len > 0) {
                        bs_emit (out, a_queue.str, a_queue.len, 0);
                        out->missing_newline = a_queue.str[a_queue.len - 1] != '\n';
                        a_queue.len = 0;
                        if (a_queue.str) a_queue.str[0] = '\0';
                    }
                    rd = getline (&cur, &cur_cap, in);
                    if (rd < 0) goto done;
                    lineno++;
                    pat_nl = rd > 0 && cur[rd - 1] == '\n';
                    is_last = -1;
                    bs_str_set (&pat, cur, (size_t) rd - pat_nl);
                    suppress_this_line = 0;
                    break;
                case BS_NUP_CMD:
                    rd = getline (&cur, &cur_cap, in);
                    if (rd < 0) {
                        if (!suppress_default) bs_emit (out, pat.str, pat.len, pat_nl);
                        goto done;
                    }
                    bs_str_append (&pat, "\n", 1);
                    pat_nl = rd > 0 && cur[rd - 1] == '\n';
                    bs_str_append (&pat, cur, (size_t) rd - pat_nl);
                    lineno++;
                    is_last = -1;
                    break;
                case BS_D_LO:
                    if (pat.str) {
                        char *nl = memchr (pat.str, '\n', pat.len);
                        if (nl) {
                            size_t drop = (size_t) (nl - pat.str) + 1;
                            size_t rest = pat.len - drop;
                            memmove (pat.str, pat.str + drop, rest);
                            pat.str[rest] = '\0';
                            pat.len = rest;
                            suppress_this_line = 0;
                            goto restart_script;
                        }
                    }
                    pat.len = 0;
                    if (pat.str) pat.str[0] = '\0';
                    goto next_line;
                    break;
                case BS_A:
                    /* Append: queue text for emission after pat default-print. */
                    if (c->text) {
                        bs_str_append (&a_queue, c->text, strlen (c->text));
                        bs_str_append (&a_queue, "\n", 1);
                    }
                    break;
                case BS_R:
                    /* r FILE: queue the file's contents (verbatim) after the
                       line. A missing/unreadable file is silently ignored
                       (matches GNU sed). */
                    if (c->text && *c->text) {
                        FILE *rf = fopen (c->text, "r");
                        if (rf) {
                            char rbuf[4096]; size_t got;
                            while ((got = fread (rbuf, 1, sizeof rbuf, rf)) > 0)
                                bs_str_append (&a_queue, rbuf, got);
                            fclose (rf);
                        }
                    }
                    break;
                case BS_W: {
                    /* w FILE: preserve the pattern space line ending. */
                    bs_output *wf = bs_get_wstream (c->text);
                    if (wf) bs_emit (wf, pat.str, pat.len, pat_nl);
                    break;
                }
                case BS_BIGW: {
                    /* W FILE: write only the first line of the pattern space
                       (up to the first embedded newline). */
                    bs_output *wf = bs_get_wstream (c->text);
                    if (wf) {
                        const char *nl = memchr (pat.str, '\n', pat.len);
                        size_t flen = nl ? (size_t) (nl - pat.str) : pat.len;
                        bs_emit (wf, pat.str, flen, nl != NULL || pat_nl);
                    }
                    break;
                }
                case BS_BIGR: {
                    /* R FILE: queue the NEXT line from FILE after this cycle.
                       Successive R calls consume successive lines; EOF / a
                       missing file is silently ignored (matches GNU). */
                    FILE *rf = bs_get_rstream (c->text);
                    if (rf) {
                        char *rl = NULL; size_t rcap = 0;
                        ssize_t rn = getline (&rl, &rcap, rf);
                        if (rn > 0) {
                            bs_str_append (&a_queue, rl, (size_t) rn);
                            if (rl[rn - 1] != '\n') bs_str_append (&a_queue, "\n", 1);
                        }
                        free (rl);
                    }
                    break;
                }
                case BS_C:
                    /* Change: replace pat with text. For single-address,
                       always; for range, emit only when range closes
                       (i.e. addr_match was true and range_active is now 0). */
                    if (c->has_a2 && range_active[ci]) {
                        /* Mid-range: suppress pat-print but don't emit text yet. */
                        suppress_this_line = 1;
                    } else {
                        /* End of range OR single-address: emit text, suppress pat. */
                        if (c->text) bs_emit (out, c->text, strlen (c->text), 1);
                        suppress_this_line = 1;
                    }
                    break;
            }
        }
        if (!suppress_default && !suppress_this_line) {
            bs_emit (out, pat.str, pat.len, pat_nl);
        }
        if (a_queue.len > 0) {
            bs_emit (out, a_queue.str, a_queue.len, 0);
            out->missing_newline = a_queue.str[a_queue.len - 1] != '\n';
            a_queue.len = 0;
            if (a_queue.str) a_queue.str[0] = '\0';
        }
    next_line:;
    }
done:
    if (ferror (in)) {
        builtin_error ("%s: read error: %s", filename, strerror (errno));
        bs_runtime_error = 1;
    }
    if (fflush (out->fp) == EOF || ferror (out->fp)) {
        builtin_error ("write error: %s", strerror (errno));
        bs_runtime_error = 1;
    }
    if (pat.failed || hold.failed || a_queue.failed) bs_runtime_error = 1;
    bs_str_free (&pat); bs_str_free (&hold); bs_str_free (&a_queue);
    free (range_active);
    free (range_end);
    free (cur);
    return bs_runtime_error ? -1 : 0;
}

/* In-place edit of a single FILE: write result to a tempfile, then
   atomic-rename. If suffix given, save backup. */
static int
bs_inplace (bs_cmd *cmds, int n_cmds, const char *path, const char *suffix, int suppress_default)
{
    /* Refuse to edit non-regular files (symlinks, fifos, devices). */
    struct stat src_st;
    if (lstat (path, &src_st) != 0)
        { builtin_error ("%s: %s", path, strerror (errno)); return -1; }
    if (!S_ISREG (src_st.st_mode))
        { builtin_error ("-i: not a regular file: %s", path); return -1; }

    FILE *in = fopen (path, "r");
    if (!in) { builtin_error ("%s: %s", path, strerror (errno)); return -1; }

    char tmp[4096];
    int written = snprintf (tmp, sizeof tmp, "%s.bsedXXXXXX", path);
    if (written < 0 || (size_t) written >= sizeof tmp)
        { fclose (in); builtin_error ("path too long: %s", path); return -1; }
    int fd = mkstemp (tmp);
    if (fd < 0) { fclose (in); builtin_error ("mkstemp: %s", strerror (errno)); return -1; }
    FILE *out = fdopen (fd, "w");
    if (!out) { close (fd); fclose (in); unlink (tmp); return -1; }

    bs_output output = { out, 0 };
    int rc = bs_run (cmds, n_cmds, in, &output, suppress_default, path);
    if (fclose (in) != 0) rc = -1;
    /* Preserve owner+mode via the open fd before closing. fchown/fchmod are
       symlink-safe and avoid TOCTOU on the path. */
    if (fchmod (fd, src_st.st_mode & 07777) < 0)
        builtin_warning ("fchmod %s: %s", tmp, strerror (errno));
    if (fchown (fd, src_st.st_uid, src_st.st_gid) < 0 && errno != EPERM)
        builtin_warning ("fchown %s: %s", tmp, strerror (errno));
    if (fclose (out) != 0) rc = -1;
    if (rc < 0) { unlink (tmp); return -1; }

    if (suffix && *suffix)
    {
        char bak[4096];
        int bw = snprintf (bak, sizeof bak, "%s%s", path, suffix);
        if (bw < 0 || (size_t) bw >= sizeof bak)
            { unlink (tmp); builtin_error ("backup path too long"); return -1; }
        if (rename (path, bak) != 0)
            builtin_warning ("rename %s -> %s: %s", path, bak, strerror (errno));
    }
    if (rename (tmp, path) != 0) {
        builtin_error ("rename %s: %s", path, strerror (errno));
        unlink (tmp);
        return -1;
    }
    return 0;
}

int
sed_builtin (WORD_LIST *list)
{
    int suppress_default = 0;
    int inplace = 0;
    char inplace_suffix[64] = {0};
    char *script = NULL;
    size_t script_cap = 0, script_len = 0;
    int n_files = 0, files_cap = 8;
    const char **files = malloc ((size_t) files_cap * sizeof *files);
    if (!files) return EXECUTION_FAILURE;

    /* Append text to the script buffer. */
    #define APP_SCRIPT(text, tlen) do { \
        size_t need = script_len + (tlen) + 2; \
        if (script_cap < need) { \
            size_t nc = script_cap ? script_cap * 2 : 256; \
            while (nc < need) nc *= 2; \
            char *ns = realloc (script, nc); \
            if (!ns) { free (files); free (script); return EXECUTION_FAILURE; } \
            script = ns; script_cap = nc; \
        } \
        if (script_len > 0) { script[script_len++] = '\n'; } \
        memcpy (script + script_len, (text), (tlen)); \
        script_len += (tlen); \
        script[script_len] = '\0'; \
    } while (0)

    int script_seen = 0;
    WORD_LIST *p = list;
    while (p)
    {
        const char *w = p->word->word;
        if (w[0] == '-' && w[1] != '\0' && strcmp (w, "--") != 0)
        {
            if (!strcmp (w, "--help")) {
                puts ("bashsed: stream editor");
                puts ("Usage: bashsed [-niE] [-e SCRIPT] [-f FILE] [SCRIPT] [INPUT ...]");
                free (files); free (script);
                return EXECUTION_SUCCESS;
            }
            for (const char *c = w + 1; *c; c++)
            {
                switch (*c)
                {
                    case 'n': suppress_default = 1; break;
                    case 'E': /* default extended — no-op */ break;
                    case 'i':
                        inplace = 1;
                        /* If next char is non-flag/non-end, take as suffix on this token. */
                        if (c[1] && c[1] != ' ') {
                            size_t slen = strlen (c + 1);
                            if (slen >= sizeof inplace_suffix) {
                                builtin_error ("-i suffix too long (max %zu bytes)",
                                               sizeof inplace_suffix - 1);
                                free (files); free (script); return EX_USAGE;
                            }
                            memcpy (inplace_suffix, c + 1, slen);
                            inplace_suffix[slen] = '\0';
                            c += slen;
                        }
                        break;
                    case 'e':
                        if (!p->next) { builtin_error ("-e needs SCRIPT"); free (files); free (script); return EX_USAGE; }
                        p = p->next;
                        APP_SCRIPT (p->word->word, strlen (p->word->word));
                        script_seen = 1;
                        goto next_word;
                    case 'f':
                    {
                        if (!p->next) { builtin_error ("-f needs FILE"); free (files); free (script); return EX_USAGE; }
                        p = p->next;
                        FILE *sf = fopen (p->word->word, "r");
                        if (!sf) { builtin_error ("-f %s: %s", p->word->word, strerror (errno)); free (files); free (script); return EXECUTION_FAILURE; }
                        char buf[4096];
                        size_t rd;
                        while ((rd = fread (buf, 1, sizeof buf, sf)) > 0)
                            APP_SCRIPT (buf, rd);
                        fclose (sf);
                        script_seen = 1;
                        goto next_word;
                    }
                    default:
                        builtin_error ("unknown flag: -%c", *c);
                        builtin_usage ();
                        free (files); free (script);
                        return EX_USAGE;
                }
            }
        }
        else
        {
            if (!script_seen)
            {
                APP_SCRIPT (w, strlen (w));
                script_seen = 1;
            }
            else
            {
                if (n_files == files_cap) {
                    if (files_cap > INT_MAX / 2 || (size_t) files_cap > SIZE_MAX / sizeof *files / 2)
                        { free (files); free (script); return EXECUTION_FAILURE; }
                    int new_cap = files_cap * 2;
                    const char **bigger = realloc (files, (size_t) new_cap * sizeof *files);
                    if (!bigger) { free (files); free (script); return EXECUTION_FAILURE; }
                    files = bigger;
                    files_cap = new_cap;
                }
                files[n_files++] = w;
            }
        }
    next_word:
        p = p->next;
    }

    if (!script_seen) { free (files); free (script); builtin_error ("no script"); return EX_USAGE; }

    bs_cmd *cmds = NULL; int n_cmds = 0;
    if (bs_parse_script (script, &cmds, &n_cmds) < 0) {
        free (files); free (script);
        return EXECUTION_FAILURE;
    }

    int rc = EXECUTION_SUCCESS;
    bs_stdout = (bs_output) { stdout, 0 };
    bs_stderr = (bs_output) { stderr, 0 };
    bs_quit_signaled = 0; bs_quit_code = 0;
    if (inplace)
    {
        for (int i = 0; i < n_files; i++)
            if (bs_inplace (cmds, n_cmds, files[i], inplace_suffix, suppress_default) < 0)
                rc = EXECUTION_FAILURE;
    }
    else
    {
        for (int i = 0; i < (n_files ? n_files : 1); i++)
        {
            const char *name = n_files ? files[i] : "-";
            int use_stdin = !strcmp (name, "-");
            int fd = use_stdin ? dup (STDIN_FILENO) : open (name, O_RDONLY);
            FILE *f = fd < 0 ? NULL : fdopen (fd, "r");
            if (!f) {
                builtin_error ("%s: %s", name, strerror (errno));
                if (fd >= 0) close (fd);
                rc = EXECUTION_FAILURE;
                continue;
            }
            int seekable = lseek (fd, 0, SEEK_CUR) != (off_t) -1;
            if (!seekable) setvbuf (f, NULL, _IONBF, 0);
            if (bs_run (cmds, n_cmds, f, &bs_stdout, suppress_default, name) < 0)
                rc = EXECUTION_FAILURE;
            /* Reconcile stdio read-ahead with the shared descriptor offset.
               fclose alone would discard bytes that shell read still needs. */
            if (use_stdin && seekable && fseeko (f, 0, SEEK_CUR) != 0) {
                builtin_error ("stdin: %s", strerror (errno));
                rc = EXECUTION_FAILURE;
            }
            if (fclose (f) != 0) rc = EXECUTION_FAILURE;
            if (bs_quit_signaled) {
                if (rc == EXECUTION_SUCCESS) rc = bs_quit_code;
                break;
            }
        }
    }

    if (bs_close_wstreams () < 0) rc = EXECUTION_FAILURE;
    if (fflush (stdout) == EOF || ferror (stdout)) rc = EXECUTION_FAILURE;
    if (fflush (stderr) == EOF || ferror (stderr)) rc = EXECUTION_FAILURE;
    clearerr (stdout);
    clearerr (stderr);
    bs_close_rstreams ();   /* close any `R` input files */
    for (int i = 0; i < n_cmds; i++) bs_cmd_free (&cmds[i]);
    free (cmds);
    free (files);
    free (script);
    return rc;
}

char *sed_doc[] = {
    "POSIX-shape sed(1) — stream editor.",
    "",
    "    bashsed [-iE] [-e SCRIPT] [-f FILE] [SCRIPT] [INPUT ...]",
    "",
    "Commands: s/// (capture groups), d p q =, h H g G x,",
    "          a/i/c TEXT, y/SET1/SET2/, n D P,",
    "          r/R FILE, w/W FILE, F, e (gated),",
    "          :LABEL, b LABEL, t LABEL, { ... }, ! prefix.",
    "Addresses: $, N, /REGEX/, ADDR1,ADDR2.",
    "Replace: & = whole match; \\1..\\9 = capture groups.",
    "",
    "Flags:",
    "    -n            suppress default print",
    "    -i [SUFFIX]   in-place edit; SUFFIX saves backup",
    "    -e SCRIPT     append SCRIPT (multiple OK)",
    "    -f FILE       read commands from FILE",
    "    -E            extended regex (always on)",
    "",
    "Security: e and s///e shell execution require BASHSED_ALLOW_EXEC=1.",
    (char *)NULL
};

struct builtin bashsed_struct = {
    "bashsed",
    sed_builtin,
    BUILTIN_ENABLED,
    sed_doc,
    "bashsed [-iE] [-e SCRIPT] [-f FILE] [SCRIPT] [INPUT ...]",
    0
};
