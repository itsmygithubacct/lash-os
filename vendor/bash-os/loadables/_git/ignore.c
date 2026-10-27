/* SPDX-License-Identifier: MIT */
/* _git/ignore.c — .gitignore matching. See ignore.h.
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

#include "config.h"
#include "ignore.h"
#include "repo.h"

/* gitignore's globbing: '*' and '?' stop at '/', '**' does not, and a
   bracket expression works as in a shell. */
int
bgit_wild (const char *p, const char *s)
{
    while (*p) {
        if (*p == '*') {
            if (p[1] == '*') {
                const char *rest = p + 2;
                if (*rest == '/') rest++;
                if (!*rest) return 1;          /* "a/**" takes everything */
                /* Any number of whole directories may come first. */
                for (const char *t = s;; ) {
                    if (bgit_wild (rest, t)) return 1;
                    const char *slash = strchr (t, '/');
                    if (!slash) return 0;
                    t = slash + 1;
                }
            }
            p++;
            for (const char *t = s;; t++) {
                if (bgit_wild (p, t)) return 1;
                if (!*t || *t == '/') return 0;
            }
        }
        if (*p == '?') {
            if (!*s || *s == '/') return 0;
            p++; s++;
            continue;
        }
        if (*p == '[') {
            if (!*s || *s == '/') return 0;
            const char *class = p + 1;
            int negate = 0;
            if (*class == '!' || *class == '^') { negate = 1; class++; }
            int matched = 0, first = 1;
            while (*class && (*class != ']' || first)) {
                first = 0;
                if (class[1] == '-' && class[2] && class[2] != ']') {
                    if ((unsigned char) *s >= (unsigned char) class[0] &&
                        (unsigned char) *s <= (unsigned char) class[2])
                        matched = 1;
                    class += 3;
                    continue;
                }
                if (*class == *s) matched = 1;
                class++;
            }
            if (*class != ']') return 0;        /* unterminated: no match */
            if (matched == negate) return 0;
            p = class + 1;
            s++;
            continue;
        }
        if (*p == '\\' && p[1]) p++;
        if (*p != *s) return 0;
        p++; s++;
    }
    return *s == '\0';
}

static int
bgit_ignore_push (bgit_ignore *ignore, const char *line, const char *source,
                  long number, const char *base)
{
    char pattern[4096];
    snprintf (pattern, sizeof pattern, "%s", line);
    /* Trailing whitespace is ignored unless it was escaped. */
    size_t full = strlen (pattern);
    while (full > 1 && (pattern[full - 1] == ' ' || pattern[full - 1] == '\t') &&
           pattern[full - 2] != '\\')
        pattern[--full] = '\0';
    /* Keep the line as written: check-ignore -v reports it, slash and all. */
    char raw[4096];
    snprintf (raw, sizeof raw, "%s", pattern);
    int negated = 0, directory_only = 0, anchored = 0;
    char *p = pattern;
    if (*p == '!') { negated = 1; p++; }
    size_t len = strlen (p);
    if (len && p[len - 1] == '/') { directory_only = 1; p[--len] = '\0'; }
    if (!len) return 0;
    if (*p == '/') { anchored = 1; p++; len--; }
    else if (strchr (p, '/')) anchored = 1;
    if (!len) return 0;

    if (ignore->n == ignore->cap) {
        size_t next = ignore->cap ? ignore->cap * 2 : 32;
        bgit_ignore_rule *grown = realloc (ignore->rules, next * sizeof *grown);
        if (!grown) return -1;
        ignore->rules = grown;
        ignore->cap = next;
    }
    bgit_ignore_rule *rule = &ignore->rules[ignore->n];
    memset (rule, 0, sizeof *rule);
    rule->pattern = strdup (p);
    rule->text = strdup (raw);
    rule->source = strdup (source);
    rule->base = strdup (base);
    rule->line = number;
    rule->negated = negated;
    rule->directory_only = directory_only;
    rule->anchored = anchored;
    if (!rule->pattern || !rule->text || !rule->source || !rule->base) {
        free (rule->pattern); free (rule->text);
        free (rule->source); free (rule->base);
        return -1;
    }
    ignore->n++;
    return 0;
}

/* Read one exclude file. SOURCE is the name to report, BASE the directory
   its patterns are relative to. */
static int
bgit_ignore_read (bgit_ignore *ignore, const char *path, const char *source,
                  const char *base)
{
    FILE *f = fopen (path, "r");
    if (!f) return 1;
    char line[4096];
    long number = 0;
    while (fgets (line, sizeof line, f)) {
        number++;
        size_t len = strlen (line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (!len || line[0] == '#') continue;
        if (bgit_ignore_push (ignore, line, source, number, base) < 0) {
            fclose (f);
            return -1;
        }
    }
    fclose (f);
    return 0;
}

int
bgit_ignore_load (bgit_ignore *ignore, const bgit_repo *repo,
                  const bgit_config *cfg)
{
    memset (ignore, 0, sizeof *ignore);
    /* Weakest first: core.excludesFile, then info/exclude, then the
       worktree's own files, deeper directories last. */
    const char *excludes = cfg ? bgit_config_get (cfg, "core.excludesfile") : NULL;
    if (excludes && *excludes) {
        char path[4096];
        if (excludes[0] == '~' && excludes[1] == '/' && getenv ("HOME"))
            snprintf (path, sizeof path, "%s/%s", getenv ("HOME"), excludes + 2);
        else
            snprintf (path, sizeof path, "%s", excludes);
        bgit_ignore_read (ignore, path, path, "");
    }
    char path[4096];
    snprintf (path, sizeof path, "%s/info/exclude", repo->common_dir);
    bgit_ignore_read (ignore, path, ".git/info/exclude", "");
    return bgit_ignore_add_dir (ignore, repo, "");
}

int
bgit_ignore_add_dir (bgit_ignore *ignore, const bgit_repo *repo,
                     const char *relative)
{
    if (!repo->work_tree) return 0;
    char path[4096], source[4096];
    if (relative && *relative) {
        snprintf (path, sizeof path, "%s/%s/.gitignore", repo->work_tree, relative);
        snprintf (source, sizeof source, "%s/.gitignore", relative);
    } else {
        snprintf (path, sizeof path, "%s/.gitignore", repo->work_tree);
        snprintf (source, sizeof source, ".gitignore");
    }
    int rc = bgit_ignore_read (ignore, path, source,
                              relative && *relative ? relative : "");
    return rc < 0 ? -1 : 0;
}

void
bgit_ignore_release (bgit_ignore *ignore)
{
    if (!ignore) return;
    for (size_t i = 0; i < ignore->n; i++) {
        free (ignore->rules[i].pattern);
        free (ignore->rules[i].text);
        free (ignore->rules[i].source);
        free (ignore->rules[i].base);
    }
    free (ignore->rules);
    memset (ignore, 0, sizeof *ignore);
}

static int
bgit_ignore_rule_matches (const bgit_ignore_rule *rule, const char *path,
                          int is_dir)
{
    if (rule->directory_only && !is_dir) return 0;
    const char *relative = path;
    if (*rule->base) {
        size_t len = strlen (rule->base);
        if (strncmp (path, rule->base, len) != 0 || path[len] != '/') return 0;
        relative = path + len + 1;
    }
    if (rule->anchored)
        return bgit_wild (rule->pattern, relative);
    /* Without a slash, a pattern matches a name at any depth. */
    for (const char *at = relative;;) {
        if (bgit_wild (rule->pattern, at)) return 1;
        const char *slash = strchr (at, '/');
        if (!slash) return 0;
        at = slash + 1;
    }
}

/* The last rule that has anything to say about this path, which is the one
   that decides. */
static const bgit_ignore_rule *
bgit_ignore_last (const bgit_ignore *ignore, const char *path, int is_dir)
{
    const bgit_ignore_rule *last = NULL;
    for (size_t i = 0; i < ignore->n; i++)
        if (bgit_ignore_rule_matches (&ignore->rules[i], path, is_dir))
            last = &ignore->rules[i];
    return last;
}

int
bgit_ignore_match (const bgit_ignore *ignore, const char *path, int is_dir,
                   const bgit_ignore_rule **matched)
{
    /* Each directory on the way down first: once one is excluded, nothing
       under it can be brought back, and git names that rule as the one
       that covers the path. */
    char held[4096];
    size_t len = strlen (path);
    if (len < sizeof held) {
        memcpy (held, path, len + 1);
        for (char *slash = strchr (held, '/'); slash;
             slash = strchr (slash + 1, '/')) {
            *slash = '\0';
            const bgit_ignore_rule *above = bgit_ignore_last (ignore, held, 1);
            *slash = '/';
            if (above && !above->negated) {
                if (matched) *matched = above;
                return 1;
            }
        }
    }
    const bgit_ignore_rule *last = bgit_ignore_last (ignore, path, is_dir);
    if (matched) *matched = last;
    return last && !last->negated;
}
