/* SPDX-License-Identifier: MIT */
/* man.c — minimal man(1) as a bash builtin.
 *
 * Locates a manpage under $MANPATH (default
 * /usr/share/man:/usr/local/share/man), decodes a small subset of
 * roff/mdoc, and writes the rendered text to stdout. The /bash-os/
 * man.sh wrapper pages the output via the less builtin.
 *
 * This is not a wholesale mandoc port — mandoc-portable is kept as
 * a reference under research/refs/mandoc/ (~45 KLoC, BSD-licensed)
 * for future fidelity work. What lives here is the 80%-case render
 * loop a typical reader needs: titled sections (.SH/.SS), paragraphs
 * (.PP/.LP), tagged paragraphs (.TP/.IP), font escapes (\fB \fI \fR
 * and their .B/.I/.BR siblings), the common groff special chars, and
 * comment stripping. Tables (.TS), pic(1), and eqn(1) are passed
 * through verbatim.
 *
 * Surface:
 *   man NAME                  — locate + render + print
 *   man SECTION NAME          — restrict to section (e.g. 1, 3p)
 *   man -s SECTION NAME       — same, explicit
 *   man -f PATH               — render a specific file
 *   man -                     — render stdin (roff in, text out)
 *   man -w NAME               — print resolved path, do not render
 *
 * Sibling builtins (apropos.c, whatis.c) reuse the whatis
 * helpers exported from this translation unit.
 *
 * --- LICENSE --- MIT, same boilerplate as less.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "loadables.h"

#define BM_DEFAULT_MANPATH "/usr/share/man:/usr/local/share/man"
#define BM_MAX_SECTIONS    9

/* ---- Path search ----------------------------------------------------- */

/* Look in $base/man$sect/ for $name, $name.$sect, $name.$sect.gz,
   $name.gz. Returns 0 + writes resolved path to out on success. */
static int
bm_try_section (const char *base, const char *sect, const char *name,
                char *out, size_t outsz)
{
    static const char *exts[] = { "", ".gz", NULL };
    char cand[1024];
    for (int e = 0; exts[e]; e++)
    {
        snprintf (cand, sizeof cand, "%s/man%s/%s.%s%s",
                  base, sect, name, sect, exts[e]);
        if (access (cand, R_OK) == 0)
        {
            strncpy (out, cand, outsz - 1); out[outsz - 1] = '\0';
            return 0;
        }
        snprintf (cand, sizeof cand, "%s/man%s/%s%s",
                  base, sect, name, exts[e]);
        if (access (cand, R_OK) == 0)
        {
            strncpy (out, cand, outsz - 1); out[outsz - 1] = '\0';
            return 0;
        }
    }
    return -1;
}

/* Walk $MANPATH (colon-separated) trying each section. If sect_only is
   non-NULL, only that section is consulted. */
int
bm_locate (const char *name, const char *sect_only,
           char *out, size_t outsz)
{
    const char *mp = getenv ("MANPATH");
    if (!mp || !*mp) mp = BM_DEFAULT_MANPATH;

    char buf[4096];
    strncpy (buf, mp, sizeof buf - 1); buf[sizeof buf - 1] = '\0';

    char *save = NULL;
    for (char *p = strtok_r (buf, ":", &save); p; p = strtok_r (NULL, ":", &save))
    {
        if (sect_only)
        {
            if (bm_try_section (p, sect_only, name, out, outsz) == 0)
                return 0;
            continue;
        }
        /* Conventional ordering: 1, 8, 6, 5, 4, 3, 2, 7, 9. */
        static const char *order[] = {
            "1", "8", "6", "5", "4", "3", "2", "7", "9", NULL
        };
        for (int i = 0; order[i]; i++)
            if (bm_try_section (p, order[i], name, out, outsz) == 0)
                return 0;
    }
    return -1;
}

/* ---- Roff decoder ---------------------------------------------------- */

/* Replace common groff escapes/specials in-place. Length never grows
   (every replacement is <= the escape it replaces), so an in-place
   pass is safe. */
static void
bm_unescape (char *s)
{
    char *d = s;
    while (*s)
    {
        if (s[0] == '\\' && s[1])
        {
            if (s[1] == 'f' && s[2])
            {
                /* Font escapes \fB \fI \fR \fP \f1 \f2 ... — drop. */
                s += 3; continue;
            }
            if (s[1] == '-') { *d++ = '-'; s += 2; continue; }
            if (s[1] == '&') { s += 2; continue; }
            if (s[1] == '.') { *d++ = '.'; s += 2; continue; }
            if (s[1] == '\\') { *d++ = '\\'; s += 2; continue; }
            if (s[1] == 'e') { *d++ = '\\'; s += 2; continue; }
            if (s[1] == ' ') { *d++ = ' '; s += 2; continue; }
            if (s[1] == '0' || s[1] == '~') { *d++ = ' '; s += 2; continue; }
            if (s[1] == '(' && s[2] && s[3])
            {
                /* Two-letter specials. Cover the ones manpages actually use. */
                const char *map[][2] = {
                    {"co", "(c)"}, {"rg", "(R)"}, {"tm", "(tm)"},
                    {"em", "--"},  {"en", "-"},   {"hy", "-"},
                    {"bu", "*"},   {"ba", "|"},   {"ti", "~"},
                    {"sh", "#"},   {"aq", "'"},   {"dq", "\""},
                    {"lq", "\""},  {"rq", "\""},  {"oq", "`"},
                    {"cq", "'"},   {"de", " deg"}, {"mu", "x"},
                    {"di", "/"},   {"+-", "+/-"}, {"<=", "<="},
                    {">=", ">="},  {"!=", "!="},  {NULL, NULL}
                };
                int handled = 0;
                for (int i = 0; map[i][0]; i++)
                    if (s[2] == map[i][0][0] && s[3] == map[i][0][1])
                    {
                        size_t n = strlen (map[i][1]);
                        memcpy (d, map[i][1], n); d += n;
                        s += 4; handled = 1; break;
                    }
                if (handled) continue;
                s += 4; continue;
            }
            /* Unknown \X — drop the backslash, keep X. */
            s += 1; continue;
        }
        *d++ = *s++;
    }
    *d = '\0';
}

/* Decode a single .B/.I/.BR/.RB/.IR/.RI style request. Strips the
   request word and concatenates the alternating arguments into a
   plain string. Caller frees nothing — buf is written back. */
static void
bm_flatten_args (char *buf)
{
    /* Skip leading dot-request word, then collapse remaining quoted /
       whitespace-separated tokens into single-space-joined text. */
    char *p = buf;
    while (*p && !isspace ((unsigned char) *p)) p++;
    while (*p && isspace ((unsigned char) *p)) p++;
    char *d = buf;
    int first = 1;
    while (*p)
    {
        if (!first) *d++ = ' ';
        first = 0;
        if (*p == '"')
        {
            p++;
            while (*p && *p != '"') *d++ = *p++;
            if (*p == '"') p++;
        }
        else
        {
            while (*p && !isspace ((unsigned char) *p)) *d++ = *p++;
        }
        while (*p && isspace ((unsigned char) *p)) p++;
    }
    *d = '\0';
}

int
bm_render_stream (FILE *in, FILE *out)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int in_nf = 0;          /* .nf (no-fill) mode */
    int blanked = 1;        /* coalesce leading blank lines */
    int saw_th = 0;

    while ((n = getline (&line, &cap, in)) != -1)
    {
        if (n > 0 && line[n - 1] == '\n') { line[--n] = '\0'; }
        if (n > 0 && line[n - 1] == '\r') { line[--n] = '\0'; }

        /* Comment requests: .\" and '\" */
        if ((line[0] == '.' || line[0] == '\'') && line[1] == '\\' && line[2] == '"')
            continue;

        if (line[0] == '.')
        {
            /* Identify request word (up to 4 chars, ASCII). */
            char req[8] = { 0 };
            int ri = 0;
            int i;
            for (i = 1; line[i] && !isspace ((unsigned char) line[i])
                        && ri < (int)(sizeof req - 1); i++)
                req[ri++] = line[i];

            if (!strcmp (req, "TH")) { saw_th = 1; blanked = 1; continue; }
            if (!strcmp (req, "Dd") || !strcmp (req, "Dt")
                || !strcmp (req, "Os")) { saw_th = 1; blanked = 1; continue; }
            if (!strcmp (req, "SH") || !strcmp (req, "Sh"))
            {
                bm_flatten_args (line);
                bm_unescape (line);
                if (!blanked) fputc ('\n', out);
                fprintf (out, "%s\n", line);
                blanked = 0; in_nf = 0; continue;
            }
            if (!strcmp (req, "SS") || !strcmp (req, "Ss"))
            {
                bm_flatten_args (line);
                bm_unescape (line);
                if (!blanked) fputc ('\n', out);
                fprintf (out, "  %s\n", line);
                blanked = 0; in_nf = 0; continue;
            }
            if (!strcmp (req, "PP") || !strcmp (req, "LP")
                || !strcmp (req, "P")  || !strcmp (req, "Pp"))
            {
                if (!blanked) { fputc ('\n', out); blanked = 1; }
                in_nf = 0; continue;
            }
            if (!strcmp (req, "br")) { fputc ('\n', out); continue; }
            if (!strcmp (req, "sp"))
            {
                if (!blanked) { fputc ('\n', out); blanked = 1; }
                continue;
            }
            if (!strcmp (req, "nf")) { in_nf = 1; continue; }
            if (!strcmp (req, "fi")) { in_nf = 0; continue; }
            if (!strcmp (req, "RS") || !strcmp (req, "RE")
                || !strcmp (req, "HP") || !strcmp (req, "ad")
                || !strcmp (req, "na") || !strcmp (req, "hy")
                || !strcmp (req, "nh") || !strcmp (req, "ne")
                || !strcmp (req, "ll") || !strcmp (req, "in")
                || !strcmp (req, "ti") || !strcmp (req, "ft")
                || !strcmp (req, "ps") || !strcmp (req, "vs")
                || !strcmp (req, "de") || !strcmp (req, "ds")
                || !strcmp (req, "if") || !strcmp (req, "ie")
                || !strcmp (req, "el") || !strcmp (req, "so"))
                continue;
            if (!strcmp (req, "TP") || !strcmp (req, "IP"))
            {
                /* Next non-empty line is the tag; the one after that
                   is the body. Approximation: indent the next line
                   normally and prefix two spaces. We just leave a
                   blank line marker. */
                if (!blanked) { fputc ('\n', out); blanked = 1; }
                continue;
            }
            if (!strcmp (req, "B") || !strcmp (req, "I")
                || !strcmp (req, "BR") || !strcmp (req, "RB")
                || !strcmp (req, "BI") || !strcmp (req, "IB")
                || !strcmp (req, "IR") || !strcmp (req, "RI"))
            {
                bm_flatten_args (line);
                bm_unescape (line);
                fprintf (out, "%s\n", line);
                blanked = (line[0] == '\0'); continue;
            }
            /* Unknown .request — drop the line silently. Matches the
               minimal-renderer contract. */
            continue;
        }

        /* Body line. In .nf mode preserve verbatim; otherwise unescape. */
        bm_unescape (line);
        if (in_nf)
            fprintf (out, "%s\n", line);
        else
        {
            if (line[0] == '\0')
            {
                if (!blanked) { fputc ('\n', out); blanked = 1; }
            }
            else
            {
                fprintf (out, "%s\n", line);
                blanked = 0;
            }
        }
    }
    free (line);
    (void) saw_th;
    return 0;
}

/* ---- whatis cache helpers (exported to apropos / whatis) ----- */

/* Check whether any file under <root>/man<N>/ has an mtime newer than
   whatis_mtime. Returns 1 if at least one source file is newer than
   the cache (stale), 0 otherwise. Best-effort: if a directory can't be
   read, it's skipped silently. */
#include <dirent.h>
static int
bm_whatis_source_newer (const char *root, time_t whatis_mtime)
{
    for (int section = 1; section <= 9; section++)
    {
        char dirpath[1024];
        if (snprintf (dirpath, sizeof dirpath, "%s/man%d", root, section)
                >= (int) sizeof dirpath)
            continue;
        DIR *d = opendir (dirpath);
        if (!d) continue;
        struct dirent *de;
        while ((de = readdir (d))) {
            if (de->d_name[0] == '.') continue;
            char fp[1280];
            if (snprintf (fp, sizeof fp, "%s/%s", dirpath, de->d_name)
                    >= (int) sizeof fp)
                continue;
            struct stat sb;
            if (stat (fp, &sb) == 0 && sb.st_mtime > whatis_mtime) {
                closedir (d);
                return 1;
            }
        }
        closedir (d);
    }
    return 0;
}

/* Open the first $MANPATH/whatis file we find. Returns NULL if the
   corpus's whatis index is not present — callers should SKIP cleanly.
   Side effect: if any source page in $MANPATH/man[1-9]/ has an mtime
   newer than the whatis cache, emit a one-shot stderr warning
   ("man: whatis cache stale: <X> newer than <whatis_path>"). The
   warning is suppressed by setting BASHMAN_STALE_QUIET=1 in the
   environment so internal callers (tools, pipelines, scripted tests)
   can stay silent. */
FILE *
bm_open_whatis (void)
{
    const char *mp = getenv ("MANPATH");
    if (!mp || !*mp) mp = BM_DEFAULT_MANPATH;
    const char *quiet = getenv ("BASHMAN_STALE_QUIET");
    int do_check = !(quiet && *quiet && quiet[0] != '0');
    char buf[4096];
    strncpy (buf, mp, sizeof buf - 1); buf[sizeof buf - 1] = '\0';
    char *save = NULL;
    for (char *p = strtok_r (buf, ":", &save); p; p = strtok_r (NULL, ":", &save))
    {
        char cand[1024];
        snprintf (cand, sizeof cand, "%s/whatis", p);
        FILE *f = fopen (cand, "r");
        if (f) {
            if (do_check) {
                struct stat sb;
                if (stat (cand, &sb) == 0
                    && bm_whatis_source_newer (p, sb.st_mtime)) {
                    fprintf (stderr,
                             "man: whatis cache stale: source page "
                             "newer than %s (run mandb to refresh)\n",
                             cand);
                }
            }
            return f;
        }
    }
    return NULL;
}

/* whatis line format (mandoc / man-db convention):
     name(section) - one-line description
   Some indices use whitespace separators instead of "(section)". We
   accept both. Returns 1 if line matches mode/needle, 0 otherwise.
   mode: 0 = substring match anywhere; 1 = exact name match (head). */
int
bm_whatis_match (const char *line, const char *needle, int exact)
{
    if (!line || !needle || !*needle) return 0;
    if (exact)
    {
        /* Match each comma-separated name token at the head. */
        const char *p = line;
        size_t nlen = strlen (needle);
        while (*p && *p != '-')
        {
            while (*p == ' ' || *p == '\t' || *p == ',') p++;
            if (!strncmp (p, needle, nlen)
                && (p[nlen] == ' ' || p[nlen] == '\t'
                    || p[nlen] == '(' || p[nlen] == ','))
                return 1;
            while (*p && *p != ' ' && *p != '\t' && *p != ',' && *p != '-') p++;
        }
        return 0;
    }
    return strstr (line, needle) != NULL;
}

/* ---- man builtin -------------------------------------------------- */

int
man_builtin (WORD_LIST *list)
{
    const char *section = NULL;
    const char *file = NULL;
    int from_stdin = 0;
    int print_path_only = 0;

    while (list && list->word && list->word->word[0] == '-')
    {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "-")) { from_stdin = 1; list = list->next; break; }
        if (!strcmp (w, "-s") || !strcmp (w, "--section"))
        {
            if (!list->next) { builtin_error ("-s needs SECTION"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            section = list->word->word;
            list = list->next; continue;
        }
        if (!strcmp (w, "-f") || !strcmp (w, "--file"))
        {
            if (!list->next) { builtin_error ("-f needs PATH"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            file = list->word->word;
            list = list->next; continue;
        }
        if (!strcmp (w, "-w") || !strcmp (w, "--where"))
        {
            print_path_only = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-h") || !strcmp (w, "--help"))
        {
            puts ("man [-s SECTION] NAME | man -f PATH | man -");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-V") || !strcmp (w, "--version"))
        {
            puts ("man 0.1 (bash-os minimal man)");
            return EXECUTION_SUCCESS;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    if (from_stdin) { return bm_render_stream (stdin, stdout) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE; }

    if (!file)
    {
        if (!list || !list->word) { builtin_usage (); return EX_USAGE; }
        /* Two-positional shorthand: man SECTION NAME */
        if (!section && list->next && list->next->word)
        {
            const char *first = list->word->word;
            /* Only treat as section if it's all digit/letter-suffix. */
            int looks_like_section = first[0] && first[0] >= '0' && first[0] <= '9';
            if (looks_like_section)
            {
                section = first;
                list = list->next;
            }
        }
        const char *name = list->word->word;
        char path[1024];
        if (bm_locate (name, section, path, sizeof path) != 0)
        {
            builtin_error ("no manual entry for %s", name);
            return EXECUTION_FAILURE;
        }
        if (print_path_only) { puts (path); return EXECUTION_SUCCESS; }
        file = path;
        FILE *in = fopen (file, "r");
        if (!in) { builtin_error ("%s: %s", file, strerror (errno)); return EXECUTION_FAILURE; }
        /* Refuse gzipped manpages — wrapper handles decompression
           via zlib. Magic bytes 1F 8B. */
        unsigned char magic[2] = { 0, 0 };
        if (fread (magic, 1, 2, in) == 2 && magic[0] == 0x1f && magic[1] == 0x8b)
        {
            fclose (in);
            builtin_error ("%s: gzipped; pipe through `zlib -d -F gzip` first", file);
            return EXECUTION_FAILURE;
        }
        rewind (in);
        int rc = bm_render_stream (in, stdout);
        fclose (in);
        return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }

    /* -f PATH branch */
    if (print_path_only) { puts (file); return EXECUTION_SUCCESS; }
    FILE *in = fopen (file, "r");
    if (!in) { builtin_error ("%s: %s", file, strerror (errno)); return EXECUTION_FAILURE; }
    int rc = bm_render_stream (in, stdout);
    fclose (in);
    return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

char *man_doc[] = {
    "Render a manpage to stdout via minimal roff decoding.",
    "",
    "    man [-s SECTION] NAME",
    "    man SECTION NAME",
    "    man -f PATH",
    "    man -                read roff source from stdin",
    "    man -w NAME          print the resolved path only",
    "",
    "Searches $MANPATH (default /usr/share/man:/usr/local/share/man).",
    "Plain manpages only — pipe gzipped pages through `zlib -d -F gzip`.",
    "Pair with /bash-os/man.sh to page output via less.",
    (char *)NULL
};

struct builtin man_struct = {
    "man",
    man_builtin,
    BUILTIN_ENABLED,
    man_doc,
    "man [-s SECTION] NAME | -f PATH | -",
    0
};
