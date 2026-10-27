/* SPDX-License-Identifier: MIT */
/* _git/config.c — git's configuration files. See config.h.
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
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>

#include "loadables.h"

#include "config.h"
#include "lock.h"
#include "repo.h"

#define BGIT_CONFIG_INCLUDE_DEPTH 10

static char *
bgit_config_join (const char *a, const char *b)
{
    size_t n = strlen (a) + 1 + strlen (b) + 1;
    char *out = malloc (n);
    if (out) snprintf (out, n, "%s/%s", a, b);
    return out;
}

static int
bgit_config_add (bgit_config *cfg, const char *key, const char *value, int level)
{
    if (cfg->n == cfg->cap) {
        size_t next = cfg->cap ? cfg->cap * 2 : 32;
        bgit_config_entry *grown = realloc (cfg->entries, next * sizeof *grown);
        if (!grown) return -1;
        cfg->entries = grown;
        cfg->cap = next;
    }
    bgit_config_entry *e = &cfg->entries[cfg->n];
    e->key = strdup (key);
    e->value = value ? strdup (value) : NULL;
    e->level = level;
    if (!e->key || (value && !e->value)) {
        free (e->key); free (e->value);
        return -1;
    }
    cfg->n++;
    return 0;
}

/* A growing string, for values assembled from escapes and continuations. */
typedef struct { char *data; size_t len, cap; } bgit_buf;

static int
bgit_buf_putc (bgit_buf *b, char c)
{
    if (b->len + 2 > b->cap) {
        size_t next = b->cap ? b->cap * 2 : 64;
        char *grown = realloc (b->data, next);
        if (!grown) return -1;
        b->data = grown;
        b->cap = next;
    }
    b->data[b->len++] = c;
    b->data[b->len] = '\0';
    return 0;
}

/* Parse one file's text. Sections, subsections, values with quotes,
   escapes, comments and continuations, and include.path. */
static int
bgit_config_parse (bgit_config *cfg, const char *path, const char *text,
                   int level, int depth)
{
    char section[512] = "";
    const char *p = text;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        if (*p == '#' || *p == ';') {
            while (*p && *p != '\n') p++;
            continue;
        }
        if (*p == '[') {
            p++;
            char name[512];
            size_t n = 0;
            while (*p && *p != ']' && *p != '"' && !isspace ((unsigned char) *p)) {
                if (n + 1 < sizeof name)
                    name[n++] = (char) tolower ((unsigned char) *p);
                p++;
            }
            name[n] = '\0';
            while (*p == ' ' || *p == '\t') p++;
            char subsection[512] = "";
            size_t sn = 0;
            if (*p == '"') {
                p++;
                while (*p && *p != '"') {
                    if (*p == '\\' && p[1]) p++;
                    if (sn + 1 < sizeof subsection) subsection[sn++] = *p;
                    p++;
                }
                subsection[sn] = '\0';
                if (*p == '"') p++;
                while (*p == ' ' || *p == '\t') p++;
            }
            if (*p != ']') {
                builtin_error ("bad config line in %s", path);
                return -1;
            }
            p++;
            if (sn)
                snprintf (section, sizeof section, "%s.%s.", name, subsection);
            else
                snprintf (section, sizeof section, "%s.", name);
            continue;
        }
        /* A key, and the value that may follow it. */
        char key[512];
        size_t kn = 0;
        while (*p && (isalnum ((unsigned char) *p) || *p == '-')) {
            if (kn + 1 < sizeof key)
                key[kn++] = (char) tolower ((unsigned char) *p);
            p++;
        }
        key[kn] = '\0';
        if (!kn) {
            builtin_error ("bad config line in %s", path);
            return -1;
        }
        while (*p == ' ' || *p == '\t') p++;
        bgit_buf value = {0};
        int has_value = 0;
        if (*p == '=') {
            has_value = 1;
            p++;
            while (*p == ' ' || *p == '\t') p++;
            int quoted = 0;
            size_t trailing = 0;   /* unquoted whitespace, dropped if the value ends */
            while (*p) {
                if (*p == '\n') { p++; break; }
                if (*p == '\\') {
                    p++;
                    if (*p == '\n') { p++; continue; }   /* continuation */
                    char c = *p;
                    char decoded = c == 'n' ? '\n' : c == 't' ? '\t'
                                 : c == 'b' ? '\b' : c;
                    if (!c) break;
                    for (size_t i = 0; i < trailing; i++) bgit_buf_putc (&value, ' ');
                    trailing = 0;
                    if (bgit_buf_putc (&value, decoded) < 0) { free (value.data); return -1; }
                    p++;
                    continue;
                }
                if (*p == '"') { quoted = !quoted; p++; continue; }
                if (!quoted && (*p == '#' || *p == ';')) {
                    while (*p && *p != '\n') p++;
                    break;
                }
                if (!quoted && (*p == ' ' || *p == '\t')) { trailing++; p++; continue; }
                for (size_t i = 0; i < trailing; i++) bgit_buf_putc (&value, ' ');
                trailing = 0;
                if (bgit_buf_putc (&value, *p) < 0) { free (value.data); return -1; }
                p++;
            }
        } else {
            while (*p && *p != '\n') {
                if (*p == '#' || *p == ';') break;
                if (!isspace ((unsigned char) *p)) {
                    builtin_error ("bad config line in %s", path);
                    free (value.data);
                    return -1;
                }
                p++;
            }
            while (*p && *p != '\n') p++;
        }
        char full[1100];
        snprintf (full, sizeof full, "%s%s", section, key);
        if (bgit_config_add (cfg, full, has_value ? (value.data ? value.data : "") : NULL,
                             level) < 0) {
            free (value.data);
            return -1;
        }
        /* include.path pulls in another file at this point. */
        if (strcmp (full, "include.path") == 0 && value.data && depth < BGIT_CONFIG_INCLUDE_DEPTH) {
            char *included;
            if (value.data[0] == '/') {
                included = strdup (value.data);
            } else if (value.data[0] == '~' && value.data[1] == '/' && getenv ("HOME")) {
                included = bgit_config_join (getenv ("HOME"), value.data + 2);
            } else {
                char dir[4096];
                snprintf (dir, sizeof dir, "%s", path);
                char *slash = strrchr (dir, '/');
                if (slash) *slash = '\0'; else snprintf (dir, sizeof dir, ".");
                included = bgit_config_join (dir, value.data);
            }
            if (included) {
                char *text2 = NULL;
                FILE *f = fopen (included, "r");
                if (f) {
                    size_t cap = 4096, len = 0;
                    text2 = malloc (cap);
                    if (text2) {
                        size_t got;
                        while ((got = fread (text2 + len, 1, cap - len - 1, f)) > 0) {
                            len += got;
                            if (len + 1 >= cap) {
                                cap *= 2;
                                char *grown = realloc (text2, cap);
                                if (!grown) break;
                                text2 = grown;
                            }
                        }
                        text2[len] = '\0';
                    }
                    fclose (f);
                }
                if (text2) bgit_config_parse (cfg, included, text2, level, depth + 1);
                free (text2);
                free (included);
            }
        }
        free (value.data);
    }
    return 0;
}

int
bgit_config_read_file (bgit_config *cfg, const char *path, int level)
{
    FILE *f = fopen (path, "r");
    if (!f) return 1;
    size_t cap = 4096, len = 0;
    char *text = malloc (cap);
    if (!text) { fclose (f); return -1; }
    size_t got;
    while ((got = fread (text + len, 1, cap - len - 1, f)) > 0) {
        len += got;
        if (len + 1 >= cap) {
            cap *= 2;
            char *grown = realloc (text, cap);
            if (!grown) { free (text); fclose (f); return -1; }
            text = grown;
        }
    }
    text[len] = '\0';
    fclose (f);
    int rc = bgit_config_parse (cfg, path, text, level, 0);
    free (text);
    return rc;
}

int
bgit_config_global_file (char *out, size_t outsz)
{
    const char *env = getenv ("GIT_CONFIG_GLOBAL");
    if (env && *env)
        return snprintf (out, outsz, "%s", env) < (int) outsz ? 0 : -1;
    const char *home = getenv ("HOME");
    if (!home || !*home) return -1;
    return snprintf (out, outsz, "%s/.gitconfig", home) < (int) outsz ? 0 : -1;
}

int
bgit_config_repo_file (const bgit_repo *repo, char *out, size_t outsz)
{
    if (!repo) return -1;
    return snprintf (out, outsz, "%s/config", repo->common_dir) < (int) outsz
           ? 0 : -1;
}

int
bgit_config_load (bgit_config *cfg, const bgit_repo *repo,
                  const char *const *overrides, size_t n_overrides)
{
    memset (cfg, 0, sizeof *cfg);
    if (!getenv ("GIT_CONFIG_NOSYSTEM"))
        bgit_config_read_file (cfg, "/etc/gitconfig", 0);
    char path[4096];
    if (bgit_config_global_file (path, sizeof path) == 0)
        bgit_config_read_file (cfg, path, 1);
    char held_xdg[4096], held_home[4096], held_global[4096];
    const char *xdg = bgit_env ("XDG_CONFIG_HOME", held_xdg, sizeof held_xdg);
    const char *home = bgit_env ("HOME", held_home, sizeof held_home);
    if (!bgit_env ("GIT_CONFIG_GLOBAL", held_global, sizeof held_global)) {
        if (xdg && *xdg) {
            snprintf (path, sizeof path, "%s/git/config", xdg);
            bgit_config_read_file (cfg, path, 1);
        } else if (home && *home) {
            snprintf (path, sizeof path, "%s/.config/git/config", home);
            bgit_config_read_file (cfg, path, 1);
        }
    }
    if (repo && bgit_config_repo_file (repo, path, sizeof path) == 0)
        bgit_config_read_file (cfg, path, 2);
    for (size_t i = 0; i < n_overrides; i++) {
        const char *eq = strchr (overrides[i], '=');
        char key[1100];
        if (eq) {
            size_t n = (size_t) (eq - overrides[i]);
            if (n >= sizeof key) n = sizeof key - 1;
            memcpy (key, overrides[i], n);
            key[n] = '\0';
        } else {
            snprintf (key, sizeof key, "%s", overrides[i]);
        }
        for (char *p = key; *p; p++) {
            /* A subsection keeps its case; the rest is folded. */
            if (*p == '"') break;
            *p = (char) tolower ((unsigned char) *p);
        }
        if (bgit_config_add (cfg, key, eq ? eq + 1 : NULL, 3) < 0) return -1;
    }
    return 0;
}

void
bgit_config_release (bgit_config *cfg)
{
    if (!cfg) return;
    for (size_t i = 0; i < cfg->n; i++) {
        free (cfg->entries[i].key);
        free (cfg->entries[i].value);
    }
    free (cfg->entries);
    memset (cfg, 0, sizeof *cfg);
}

/* git matches a section and a variable without regard to case, and a
   subsection — whatever stands between the first dot and the last —
   exactly. Keys are stored that way, so a key being looked for is folded
   the same way before it is compared. */
static void
bgit_config_fold (const char *key, char *out, size_t outsz)
{
    snprintf (out, outsz, "%s", key);
    char *first = strchr (out, '.');
    char *last = strrchr (out, '.');
    for (char *p = out; *p; p++) {
        if (first && p >= first && p < last) continue;   /* the subsection */
        *p = (char) tolower ((unsigned char) *p);
    }
}

/* The last entry set for KEY, or NULL. */
static const bgit_config_entry *
bgit_config_find (const bgit_config *cfg, const char *key)
{
    char wanted[4096];
    bgit_config_fold (key, wanted, sizeof wanted);
    const bgit_config_entry *found = NULL;
    for (size_t i = 0; i < cfg->n; i++)
        if (strcmp (cfg->entries[i].key, wanted) == 0)
            found = &cfg->entries[i];
    return found;
}

const char *
bgit_config_get (const bgit_config *cfg, const char *key)
{
    /* A key with no value reads as empty, as `git config --get` prints it;
       only the boolean reading calls it true. */
    const bgit_config_entry *found = bgit_config_find (cfg, key);
    return found ? (found->value ? found->value : "") : NULL;
}

size_t
bgit_config_get_all (const bgit_config *cfg, const char *key,
                     const char ***values)
{
    char wanted[4096];
    bgit_config_fold (key, wanted, sizeof wanted);
    size_t n = 0;
    for (size_t i = 0; i < cfg->n; i++)
        if (strcmp (cfg->entries[i].key, wanted) == 0) n++;
    if (!n) { *values = NULL; return 0; }
    const char **out = calloc (n, sizeof *out);
    if (!out) { *values = NULL; return 0; }
    size_t w = 0;
    for (size_t i = 0; i < cfg->n; i++)
        if (strcmp (cfg->entries[i].key, wanted) == 0)
            out[w++] = cfg->entries[i].value ? cfg->entries[i].value : "";
    *values = out;
    return n;
}

int
bgit_config_bool (const bgit_config *cfg, const char *key, int fallback)
{
    const bgit_config_entry *entry = bgit_config_find (cfg, key);
    if (!entry) return fallback;
    if (!entry->value) return 1;          /* a key alone means true */
    const char *value = entry->value;
    if (!*value) return 0;
    if (!strcasecmp (value, "true") || !strcasecmp (value, "yes") ||
        !strcasecmp (value, "on") || !strcmp (value, "1"))
        return 1;
    if (!strcasecmp (value, "false") || !strcasecmp (value, "no") ||
        !strcasecmp (value, "off") || !strcmp (value, "0"))
        return 0;
    return fallback;
}

/* ---- writing ----------------------------------------------------------- */

/* Split "section.subsection.key" into its parts. The subsection, if any, is
   everything between the first and last dot. */
static int
bgit_config_split (const char *key, char *section, size_t section_sz,
                   char *subsection, size_t subsection_sz,
                   char *name, size_t name_sz)
{
    const char *first = strchr (key, '.');
    const char *last = strrchr (key, '.');
    if (!first || first == key || !last[1]) return -1;
    size_t sn = (size_t) (first - key);
    if (sn >= section_sz) return -1;
    memcpy (section, key, sn);
    section[sn] = '\0';
    for (char *p = section; *p; p++) *p = (char) tolower ((unsigned char) *p);
    /* The variable's name keeps the case it was typed in, as git writes it;
       matching is case-insensitive either way. */
    snprintf (name, name_sz, "%s", last + 1);
    if (first == last) {
        subsection[0] = '\0';
    } else {
        size_t len = (size_t) (last - first - 1);
        if (len >= subsection_sz) return -1;
        memcpy (subsection, first + 1, len);
        subsection[len] = '\0';
    }
    return 0;
}

/* A value needs quoting when it has edge whitespace or a comment character. */
static void
bgit_config_quote (const char *value, char *out, size_t outsz)
{
    int needs = !*value || isspace ((unsigned char) value[0]) ||
                isspace ((unsigned char) value[strlen (value) - 1]) ||
                strpbrk (value, "#;\"\\\n\t") != NULL;
    size_t w = 0;
    if (!needs) { snprintf (out, outsz, "%s", value); return; }
    if (w + 1 < outsz) out[w++] = '"';
    for (const char *p = value; *p && w + 3 < outsz; p++) {
        if (*p == '"' || *p == '\\') { out[w++] = '\\'; out[w++] = *p; }
        else if (*p == '\n') { out[w++] = '\\'; out[w++] = 'n'; }
        else if (*p == '\t') { out[w++] = '\\'; out[w++] = 't'; }
        else out[w++] = *p;
    }
    if (w + 1 < outsz) out[w++] = '"';
    out[w] = '\0';
}

/* Is LINE the header of the section we want? */
static int
bgit_config_is_section (const char *line, const char *section,
                        const char *subsection)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '[') return 0;
    p++;
    size_t n = strlen (section);
    if (strncasecmp (p, section, n) != 0) return 0;
    p += n;
    while (*p == ' ' || *p == '\t') p++;
    if (*subsection) {
        if (*p != '"') return 0;
        p++;
        size_t sn = strlen (subsection);
        if (strncmp (p, subsection, sn) != 0) return 0;
        p += sn;
        if (*p != '"') return 0;
        p++;
        while (*p == ' ' || *p == '\t') p++;
    }
    return *p == ']';
}

/* Is LINE "name = ..." for the key we want? */
static int
bgit_config_is_key (const char *line, const char *name)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    size_t n = strlen (name);
    if (strncasecmp (p, name, n) != 0) return 0;
    p += n;
    while (*p == ' ' || *p == '\t') p++;
    return *p == '=' || *p == '\n' || *p == '\0';
}

/* Rewrite PATH with the key set, added or removed. */
static int
bgit_config_edit (const char *path, const char *key, const char *value,
                  int multiple, int remove)
{
    char section[256], subsection[512], name[256];
    if (bgit_config_split (key, section, sizeof section, subsection,
                           sizeof subsection, name, sizeof name) < 0) {
        builtin_error ("invalid key: %s", key);
        return -1;
    }
    char **lines = NULL;
    size_t n = 0, cap = 0;
    FILE *f = fopen (path, "r");
    if (f) {
        char buf[8192];
        while (fgets (buf, sizeof buf, f)) {
            if (n == cap) {
                size_t next = cap ? cap * 2 : 64;
                char **grown = realloc (lines, next * sizeof *grown);
                if (!grown) { fclose (f); goto oom; }
                lines = grown;
                cap = next;
            }
            lines[n] = strdup (buf);
            if (!lines[n]) { fclose (f); goto oom; }
            n++;
        }
        fclose (f);
    }

    char quoted[8192];
    if (value) bgit_config_quote (value, quoted, sizeof quoted);

    int in_section = 0, done = 0;
    size_t section_end = 0;
    int section_seen = 0;
    for (size_t i = 0; i < n; i++) {
        const char *line = lines[i];
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '[') {
            in_section = bgit_config_is_section (line, section, subsection);
            if (in_section) { section_seen = 1; section_end = i + 1; }
            continue;
        }
        if (!in_section) continue;
        section_end = i + 1;
        if (!bgit_config_is_key (line, name)) continue;
        if (remove) {
            free (lines[i]);
            memmove (lines + i, lines + i + 1, (n - i - 1) * sizeof *lines);
            n--; i--;
            done = 1;
            continue;
        }
        if (multiple) continue;   /* --add leaves existing values alone */
        char replacement[8192];
        snprintf (replacement, sizeof replacement, "\t%s = %s\n", name, quoted);
        free (lines[i]);
        lines[i] = strdup (replacement);
        if (!lines[i]) goto oom;
        done = 1;
    }

    if (!remove && (!done || multiple)) {
        char addition[8192];
        snprintf (addition, sizeof addition, "\t%s = %s\n", name, quoted);
        size_t at;
        if (section_seen) {
            at = section_end;
        } else {
            char header[1024];
            if (*subsection)
                snprintf (header, sizeof header, "[%s \"%s\"]\n", section, subsection);
            else
                snprintf (header, sizeof header, "[%s]\n", section);
            if (n == cap) {
                size_t next = cap ? cap * 2 : 8;
                char **grown = realloc (lines, next * sizeof *grown);
                if (!grown) goto oom;
                lines = grown;
                cap = next;
            }
            lines[n] = strdup (header);
            if (!lines[n]) goto oom;
            n++;
            at = n;
        }
        if (n == cap) {
            size_t next = cap ? cap * 2 : 8;
            char **grown = realloc (lines, next * sizeof *grown);
            if (!grown) goto oom;
            lines = grown;
            cap = next;
        }
        memmove (lines + at + 1, lines + at, (n - at) * sizeof *lines);
        lines[at] = strdup (addition);
        if (!lines[at]) goto oom;
        n++;
    }

    bgit_lock lock;
    if (bgit_lock_acquire (&lock, path) < 0) goto oom;
    for (size_t i = 0; i < n; i++) {
        if (bgit_lock_write (&lock, lines[i], strlen (lines[i])) < 0) {
            bgit_lock_rollback (&lock);
            goto oom;
        }
    }
    int rc = bgit_lock_commit (&lock);
    for (size_t i = 0; i < n; i++) free (lines[i]);
    free (lines);
    return rc;
oom:
    for (size_t i = 0; i < n; i++) free (lines[i]);
    free (lines);
    return -1;
}

int
bgit_config_set_file (const char *path, const char *key, const char *value,
                      int multiple)
{
    return bgit_config_edit (path, key, value, multiple, 0);
}

int
bgit_config_unset_file (const char *path, const char *key)
{
    return bgit_config_edit (path, key, NULL, 0, 1);
}

int
bgit_config_remove_section_file (const char *path, const char *name)
{
    /* The section's name may carry a subsection: "remote.origin" is
       [remote "origin"], as git reads it here. */
    char section[256], subsection[512];
    snprintf (section, sizeof section, "%s", name);
    *subsection = '\0';
    char *dot = strchr (section, '.');
    if (dot) {
        *dot = '\0';
        snprintf (subsection, sizeof subsection, "%s", dot + 1);
    }
    for (char *at = section; *at; at++) *at = (char) tolower ((unsigned char) *at);

    FILE *f = fopen (path, "r");
    if (!f) return 1;
    char **lines = NULL;
    size_t n = 0, cap = 0;
    char buf[8192];
    while (fgets (buf, sizeof buf, f)) {
        if (n == cap) {
            size_t next = cap ? cap * 2 : 64;
            char **grown = realloc (lines, next * sizeof *grown);
            if (!grown) { fclose (f); goto oom; }
            lines = grown;
            cap = next;
        }
        lines[n] = strdup (buf);
        if (!lines[n]) { fclose (f); goto oom; }
        n++;
    }
    fclose (f);

    int inside = 0, found = 0;
    size_t kept = 0;
    for (size_t i = 0; i < n; i++) {
        const char *at = lines[i];
        while (*at == ' ' || *at == '\t') at++;
        if (*at == '[') {
            inside = bgit_config_is_section (lines[i], section, subsection);
            if (inside) found = 1;
        }
        if (inside) { free (lines[i]); continue; }
        lines[kept++] = lines[i];
    }
    n = kept;
    int rc = 0;
    if (found) {
        FILE *out = fopen (path, "w");
        if (!out) rc = -1;
        else {
            for (size_t i = 0; i < n; i++) fputs (lines[i], out);
            if (fclose (out) != 0) rc = -1;
        }
    }
    for (size_t i = 0; i < n; i++) free (lines[i]);
    free (lines);
    return rc < 0 ? -1 : (found ? 0 : 1);
oom:
    for (size_t i = 0; i < n; i++) free (lines[i]);
    free (lines);
    return -1;
}

/* One of the zones git writes: "Z", "+hh", "+hhmm" or "+hh:mm". Returns the
   offset in seconds and how many characters it read, or -1. */
static int
bgit_date_zone (const char *text, long *offset, size_t *read)
{
    if (*text == 'Z' || *text == 'z') {
        *offset = 0;
        *read = 1;
        return 0;
    }
    if (*text != '+' && *text != '-') return -1;
    int sign = *text == '-' ? -1 : 1;
    const char *at = text + 1;
    if (!isdigit ((unsigned char) at[0]) || !isdigit ((unsigned char) at[1]))
        return -1;
    long hours = (at[0] - '0') * 10 + (at[1] - '0');
    at += 2;
    long minutes = 0;
    if (*at == ':') at++;
    if (isdigit ((unsigned char) at[0]) && isdigit ((unsigned char) at[1])) {
        minutes = (at[0] - '0') * 10 + (at[1] - '0');
        at += 2;
    }
    *offset = sign * (hours * 3600 + minutes * 60);
    *read = (size_t) (at - text);
    return 0;
}

/* The month a name stands for, 1 to 12, or 0. */
static int
bgit_date_month (const char *text)
{
    static const char *const names[] = { "jan", "feb", "mar", "apr", "may",
                                         "jun", "jul", "aug", "sep", "oct",
                                         "nov", "dec" };
    for (int i = 0; i < 12; i++)
        if (tolower ((unsigned char) text[0]) == names[i][0] &&
            tolower ((unsigned char) text[1]) == names[i][1] &&
            tolower ((unsigned char) text[2]) == names[i][2])
            return i + 1;
    return 0;
}

/* Write a moment the way git writes one in an object: the seconds since the
   epoch, then the zone it was named in. */
static void
bgit_date_written (long long seconds, long offset, char *out, size_t outsz)
{
    long away = offset < 0 ? -offset : offset;
    snprintf (out, outsz, "%lld %c%02ld%02ld", seconds,
              offset < 0 ? '-' : '+', away / 3600, (away % 3600) / 60);
}

/* A date and time named exactly, which is all git accepts for an author or
   committer line: the raw form it writes itself, "@<seconds>", a date and
   time with -, . or / between the parts of the day and an optional zone, or
   the RFC 2822 form with the month by name. A day with no time of it, and
   anything relative, is not a date git takes here. Returns 0 and fills OUT
   with "<seconds> <+hhmm>", or -1. */
static int
bgit_date_raw (const char *text, char *out, size_t outsz)
{
    while (*text == ' ' || *text == '\t') text++;
    if (!*text) return -1;

    /* The raw form, and the one with an @ in front of the seconds. */
    {
        const char *at = text;
        if (*at == '@') at++;
        if (isdigit ((unsigned char) *at)) {
            char *end = NULL;
            long long seconds = strtoll (at, &end, 10);
            const char *rest = end;
            while (*rest == ' ') rest++;
            long offset = 0;
            size_t read = 0;
            int has_zone = *rest && bgit_date_zone (rest, &offset, &read) == 0;
            if (has_zone) rest += read;
            while (*rest == ' ' || *rest == '\t') rest++;
            /* A run of digits on its own is only a moment when it could not
               be a year: "2025-06-15" has to go the other way. */
            if (!*rest && (at != text || has_zone || end - at > 4)) {
                bgit_date_written (seconds, offset, out, outsz);
                return 0;
            }
        }
    }

    int year = 0, month = 0, day = 0, hour = -1, minute = 0, second = 0;
    const char *at = text;
    /* RFC 2822 starts with the day of the week, which says nothing. */
    if (isalpha ((unsigned char) at[0]) && isalpha ((unsigned char) at[1]) &&
        isalpha ((unsigned char) at[2]) && !bgit_date_month (at)) {
        while (*at && *at != ' ') at++;
        while (*at == ' ') at++;
    }
    if (isdigit ((unsigned char) at[0]) && isdigit ((unsigned char) at[1]) &&
        isdigit ((unsigned char) at[2]) && isdigit ((unsigned char) at[3])) {
        /* A year first: YYYY-MM-DD, with any of -, . or / between. */
        year = atoi (at);
        at += 4;
        if (*at != '-' && *at != '.' && *at != '/') return -1;
        at++;
        if (!isdigit ((unsigned char) *at)) return -1;
        month = atoi (at);
        while (isdigit ((unsigned char) *at)) at++;
        if (*at != '-' && *at != '.' && *at != '/') return -1;
        at++;
        if (!isdigit ((unsigned char) *at)) return -1;
        day = atoi (at);
        while (isdigit ((unsigned char) *at)) at++;
        /* Where the first of the two cannot be a month, it is the day: git
           reads the numbers for what they can be. */
        if (month > 12 && day <= 12) {
            int held = month;
            month = day;
            day = held;
        }
    } else if (isdigit ((unsigned char) at[0])) {
        /* A day first, with the month by name: DD Mon YYYY. */
        day = atoi (at);
        while (isdigit ((unsigned char) *at)) at++;
        while (*at == ' ' || *at == '-') at++;
        month = bgit_date_month (at);
        if (!month) return -1;
        while (isalpha ((unsigned char) *at)) at++;
        while (*at == ' ' || *at == '-') at++;
        if (!isdigit ((unsigned char) *at)) return -1;
        year = atoi (at);
        while (isdigit ((unsigned char) *at)) at++;
    } else return -1;

    while (*at == ' ' || *at == 'T' || *at == 't') at++;
    if (!isdigit ((unsigned char) *at)) return -1;   /* a day is not a date */
    hour = atoi (at);
    while (isdigit ((unsigned char) *at)) at++;
    if (*at != ':') return -1;
    at++;
    if (!isdigit ((unsigned char) *at)) return -1;
    minute = atoi (at);
    while (isdigit ((unsigned char) *at)) at++;
    if (*at == ':') {
        at++;
        if (!isdigit ((unsigned char) *at)) return -1;
        second = atoi (at);
        while (isdigit ((unsigned char) *at)) at++;
    }
    while (*at == ' ') at++;

    long offset = 0;
    int named_zone = 0;
    if (*at) {
        size_t read = 0;
        if (bgit_date_zone (at, &offset, &read) < 0) return -1;
        named_zone = 1;
        at += read;
        while (*at == ' ' || *at == '\t') at++;
        if (*at) return -1;
    }
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 24 ||
        minute > 59 || second > 61)
        return -1;

    struct tm when;
    memset (&when, 0, sizeof when);
    when.tm_year = year - 1900;
    when.tm_mon = month - 1;
    when.tm_mday = day;
    when.tm_hour = hour;
    when.tm_min = minute;
    when.tm_sec = second;
    when.tm_isdst = -1;
    long long seconds;
    if (named_zone) {
        /* The wall clock was that zone's, so the moment is that many
           seconds the other way. */
        seconds = (long long) timegm (&when) - offset;
    } else {
        time_t local = mktime (&when);
        if (local == (time_t) -1) return -1;
        seconds = (long long) local;
        struct tm here;
        if (localtime_r (&local, &here)) offset = here.tm_gmtoff;
    }
    bgit_date_written (seconds, offset, out, outsz);
    return 0;
}

int
bgit_ident (const bgit_config *cfg, int committer, char *out, size_t outsz)
{
    char held_name[512], held_email[512], held_date[64];
    const char *name = bgit_env (committer ? "GIT_COMMITTER_NAME"
                                           : "GIT_AUTHOR_NAME",
                                 held_name, sizeof held_name);
    const char *email = bgit_env (committer ? "GIT_COMMITTER_EMAIL"
                                            : "GIT_AUTHOR_EMAIL",
                                  held_email, sizeof held_email);
    const char *date = bgit_env (committer ? "GIT_COMMITTER_DATE"
                                           : "GIT_AUTHOR_DATE",
                                 held_date, sizeof held_date);
    if (!name && cfg) name = bgit_config_get (cfg, "user.name");
    if (!email && cfg) email = bgit_config_get (cfg, "user.email");
    if (!name || !*name) name = "bash-os";
    if (!email || !*email) email = "bash-os@localhost";

    char when[64];
    if (date && *date) {
        /* git takes a moment named exactly and nothing else, and says so
           rather than going on with the wrong one. */
        if (bgit_date_raw (date, when, sizeof when) < 0) return -2;
        return snprintf (out, outsz, "%s <%s> %s", name, email, when) <
               (int) outsz ? 0 : -1;
    }
    time_t now = time (NULL);
    struct tm local;
    long offset = 0;
    if (localtime_r (&now, &local)) offset = local.tm_gmtoff;
    long absolute = offset < 0 ? -offset : offset;
    snprintf (when, sizeof when, "%lld %c%02ld%02ld", (long long) now,
              offset < 0 ? '-' : '+', absolute / 3600, (absolute % 3600) / 60);
    return snprintf (out, outsz, "%s <%s> %s", name, email, when) <
           (int) outsz ? 0 : -1;
}
