/* SPDX-License-Identifier: MIT */
/* _git/refs.c — refs, packed-refs, symbolic refs and the reflog. See refs.h.
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
#include <dirent.h>

#include "loadables.h"

#include "lock.h"
#include "odb.h"
#include "refs.h"
#include "repo.h"

#define BGIT_SYMREF_DEPTH 8

int
bgit_ref_name_ok (const char *name)
{
    if (!name || !*name) return 0;
    size_t n = strlen (name);
    if (name[0] == '/' || name[n - 1] == '/' || name[n - 1] == '.') return 0;
    if (strstr (name, "..") || strstr (name, "@{") || strstr (name, "//"))
        return 0;
    if (n >= 5 && strcmp (name + n - 5, ".lock") == 0) return 0;
    int component_start = 1;
    for (const unsigned char *p = (const unsigned char *) name; *p; p++) {
        if (*p < 0x20 || *p == 0x7f) return 0;
        if (strchr (" ~^:?*[\\", *p)) return 0;
        if (component_start && *p == '.') return 0;
        component_start = (*p == '/');
    }
    return 1;
}

/* HEAD and the in-progress state belong to one worktree; everything else is
   shared through commondir. */
static int
bgit_ref_per_worktree (const char *refname)
{
    static const char *const names[] = {
        "HEAD", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD",
        "REVERT_HEAD", "REBASE_HEAD", "BISECT_HEAD", "AUTO_MERGE", NULL
    };
    for (int i = 0; names[i]; i++)
        if (strcmp (refname, names[i]) == 0) return 1;
    return strncmp (refname, "refs/bisect/", 12) == 0 ||
           strncmp (refname, "refs/worktree/", 14) == 0 ||
           strncmp (refname, "refs/rewritten/", 15) == 0;
}

int
bgit_ref_path (const bgit_repo *repo, const char *refname, char *out, size_t outsz)
{
    const char *base = bgit_ref_per_worktree (refname) ? repo->git_dir
                                                       : repo->common_dir;
    return snprintf (out, outsz, "%s/%s", base, refname) < (int) outsz ? 0 : -1;
}

/* The first line of a file, without its newline. NULL if unreadable. */
static char *
bgit_first_line (const char *path)
{
    FILE *f = fopen (path, "r");
    if (!f) return NULL;
    char buf[4096];
    if (!fgets (buf, sizeof buf, f)) { fclose (f); return NULL; }
    fclose (f);
    size_t n = strlen (buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
    return strdup (buf);
}

static int
bgit_packed_refs_read (const bgit_repo *repo, const char *refname, char full[41])
{
    char path[4096];
    if (snprintf (path, sizeof path, "%s/packed-refs", repo->common_dir) >=
        (int) sizeof path)
        return -1;
    FILE *f = fopen (path, "r");
    if (!f) return 1;
    char line[8192];
    int found = 1;
    while (fgets (line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '^') continue;
        size_t n = strlen (line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (n < 42 || line[40] != ' ') continue;
        if (strcmp (line + 41, refname) != 0) continue;
        memcpy (full, line, 40);
        full[40] = '\0';
        found = 0;
        break;
    }
    fclose (f);
    return found;
}

int
bgit_ref_read (const bgit_repo *repo, const char *refname, char full[41])
{
    char path[4096];
    if (bgit_ref_path (repo, refname, path, sizeof path) < 0) return -1;
    char *line = bgit_first_line (path);
    if (!line)
        return bgit_packed_refs_read (repo, refname, full);
    if (strncmp (line, "ref:", 4) == 0) { free (line); return -1; }
    if (strlen (line) < 40 || !bgit_all_hex (line)) {
        /* Not an object id: a malformed ref, which git also refuses. */
        free (line);
        return -1;
    }
    memcpy (full, line, 40);
    full[40] = '\0';
    free (line);
    return 0;
}

int
bgit_symref_read (const bgit_repo *repo, const char *name, char **target)
{
    char path[4096];
    if (bgit_ref_path (repo, name, path, sizeof path) < 0) return -1;
    char *line = bgit_first_line (path);
    if (!line) return 1;
    if (strncmp (line, "ref:", 4) != 0) { free (line); return 1; }
    char *value = line + 4;
    while (*value && isspace ((unsigned char) *value)) value++;
    if (!*value) { free (line); return -1; }
    *target = strdup (value);
    free (line);
    return *target ? 0 : -1;
}

int
bgit_ref_resolve (const bgit_repo *repo, const char *name, char full[41],
                  char **symref)
{
    if (symref) *symref = NULL;
    if (bgit_all_hex (name) && strlen (name) == 40) {
        memcpy (full, name, 41);
        return 0;
    }
    char current[4096];
    if (snprintf (current, sizeof current, "%s", name) >= (int) sizeof current)
        return -1;
    for (int depth = 0; depth < BGIT_SYMREF_DEPTH; depth++) {
        char *target = NULL;
        int rc = bgit_symref_read (repo, current, &target);
        if (rc < 0) return -1;
        if (rc == 0) {
            if (symref) { free (*symref); *symref = strdup (target); }
            if (snprintf (current, sizeof current, "%s", target) >=
                (int) sizeof current) { free (target); return -1; }
            free (target);
            continue;
        }
        return bgit_ref_read (repo, current, full);
    }
    return -1;
}

/* Set by the git builtin from the configuration, for this command only. */
static char *bgit_ident_override;

void
bgit_refs_set_ident (const char *ident)
{
    free (bgit_ident_override);
    bgit_ident_override = ident ? strdup (ident) : NULL;
}

int
bgit_committer_ident (char *out, size_t outsz)
{
    if (bgit_ident_override)
        return snprintf (out, outsz, "%s", bgit_ident_override) < (int) outsz
               ? 0 : -1;
    char held_name[512], held_email[512], held_date[64];
    const char *name = bgit_env ("GIT_COMMITTER_NAME", held_name,
                                 sizeof held_name);
    const char *email = bgit_env ("GIT_COMMITTER_EMAIL", held_email,
                                  sizeof held_email);
    const char *date = bgit_env ("GIT_COMMITTER_DATE", held_date,
                                 sizeof held_date);
    if (!name || !*name) name = "bash-os";
    if (!email || !*email) email = "bash-os@localhost";

    char when[64];
    /* git's raw date form is "<seconds> <+hhmm>", which is what a reflog
       entry stores; anything else falls back to now. */
    if (date && *date) {
        long long seconds;
        char zone[8];
        if (sscanf (date, "%lld %5s", &seconds, zone) == 2 &&
            (zone[0] == '+' || zone[0] == '-')) {
            snprintf (when, sizeof when, "%lld %s", seconds, zone);
            return snprintf (out, outsz, "%s <%s> %s", name, email, when) <
                   (int) outsz ? 0 : -1;
        }
    }
    time_t now = time (NULL);
    struct tm local;
    long offset = 0;
    if (localtime_r (&now, &local))
        offset = local.tm_gmtoff;
    int sign = offset < 0 ? -1 : 1;
    long absolute = offset < 0 ? -offset : offset;
    snprintf (when, sizeof when, "%lld %c%02ld%02ld", (long long) now,
              sign < 0 ? '-' : '+', absolute / 3600, (absolute % 3600) / 60);
    return snprintf (out, outsz, "%s <%s> %s", name, email, when) <
           (int) outsz ? 0 : -1;
}

/* A reflog lives beside the ref, under logs/. */
static int
bgit_reflog_path (const bgit_repo *repo, const char *refname, char *out,
                  size_t outsz)
{
    const char *base = bgit_ref_per_worktree (refname) ? repo->git_dir
                                                       : repo->common_dir;
    return snprintf (out, outsz, "%s/logs/%s", base, refname) < (int) outsz
           ? 0 : -1;
}

static int
bgit_mkdir_parents (const char *path)
{
    char buf[4096];
    if (snprintf (buf, sizeof buf, "%s", path) >= (int) sizeof buf) return -1;
    char *slash = strrchr (buf, '/');
    if (!slash || slash == buf) return 0;
    *slash = '\0';
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir (buf, 0777) < 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    return mkdir (buf, 0777) == 0 || errno == EEXIST ? 0 : -1;
}

int
bgit_reflog_append (const bgit_repo *repo, const char *refname,
                    const char *old_sha, const char *new_sha,
                    const char *message)
{
    /* git keeps logs for HEAD, for refs under refs/heads, refs/remotes and
       refs/notes, and for refs/stash — whose log is the stash stack —
       without being asked; other refs only if a log exists already. */
    char path[4096];
    if (bgit_reflog_path (repo, refname, path, sizeof path) < 0) return -1;
    int always = strcmp (refname, "HEAD") == 0 ||
                 strcmp (refname, "refs/stash") == 0 ||
                 strncmp (refname, "refs/heads/", 11) == 0 ||
                 strncmp (refname, "refs/remotes/", 13) == 0 ||
                 strncmp (refname, "refs/notes/", 11) == 0;
    if (!always && access (path, F_OK) != 0) return 0;
    if (bgit_mkdir_parents (path) < 0) {
        builtin_error ("cannot create reflog directory for %s: %s", refname,
                       strerror (errno));
        return -1;
    }
    char ident[512];
    if (bgit_committer_ident (ident, sizeof ident) < 0) return -1;
    FILE *f = fopen (path, "a");
    if (!f) {
        builtin_error ("cannot append to %s: %s", path, strerror (errno));
        return -1;
    }
    const char zeroes[41] = "0000000000000000000000000000000000000000";
    fprintf (f, "%s %s %s\t%s\n", old_sha && *old_sha ? old_sha : zeroes,
             new_sha && *new_sha ? new_sha : zeroes, ident,
             message ? message : "");
    int rc = ferror (f) ? -1 : 0;
    if (fclose (f) != 0) rc = -1;
    if (rc < 0) builtin_error ("cannot write %s: %s", path, strerror (errno));
    return rc;
}

/* The id an entry ends at, which the next entry starts from. */
static void
bgit_reflog_ids (const char *line, char old_id[41], char new_id[41])
{
    old_id[0] = new_id[0] = '\0';
    if (strlen (line) < 81) return;
    memcpy (old_id, line, 40);
    old_id[40] = '\0';
    memcpy (new_id, line + 41, 40);
    new_id[40] = '\0';
}

int
bgit_reflog_drop (const bgit_repo *repo, const char *refname, size_t index)
{
    char **lines = NULL;
    size_t n = 0;
    if (bgit_reflog_lines (repo, refname, &lines, &n) != 0 || !n) {
        free (lines);
        return -1;
    }
    if (index >= n) {
        for (size_t i = 0; i < n; i++) free (lines[i]);
        free (lines);
        return -1;
    }
    size_t at = n - 1 - index;      /* the reflog is oldest first */

    /* The entry after the one leaving now starts where it started. */
    if (at + 1 < n) {
        char gone_old[41], gone_new[41], next_old[41], next_new[41];
        bgit_reflog_ids (lines[at], gone_old, gone_new);
        bgit_reflog_ids (lines[at + 1], next_old, next_new);
        if (*gone_old && *next_old && strlen (lines[at + 1]) >= 81)
            memcpy (lines[at + 1], gone_old, 40);
    }

    char path[4096];
    int rc = -1;
    if (bgit_reflog_path (repo, refname, path, sizeof path) == 0) {
        if (at + 1 == n && n == 1) {
            /* The last entry: the ref goes with it. */
            unlink (path);
            bgit_ref_delete (repo, refname, NULL, NULL);
            rc = 0;
        } else {
            FILE *f = fopen (path, "w");
            if (f) {
                for (size_t i = 0; i < n; i++)
                    if (i != at) fprintf (f, "%s\n", lines[i]);
                rc = fclose (f) == 0 ? 0 : -1;
            }
            /* The ref follows the newest entry left. */
            if (rc == 0) {
                size_t newest = n - 1 == at ? n - 2 : n - 1;
                char old_id[41], new_id[41];
                bgit_reflog_ids (lines[newest], old_id, new_id);
                if (*new_id) {
                    char ref_path[4096];
                    if (bgit_ref_path (repo, refname, ref_path,
                                       sizeof ref_path) == 0) {
                        FILE *out = fopen (ref_path, "w");
                        if (out) {
                            fprintf (out, "%s\n", new_id);
                            if (fclose (out) != 0) rc = -1;
                        } else rc = -1;
                    }
                }
            }
        }
    }
    for (size_t i = 0; i < n; i++) free (lines[i]);
    free (lines);
    return rc;
}

int
bgit_reflog_lines (const bgit_repo *repo, const char *refname, char ***lines,
                   size_t *n)
{
    char path[4096];
    if (bgit_reflog_path (repo, refname, path, sizeof path) < 0) return -1;
    FILE *f = fopen (path, "r");
    if (!f) return 1;
    char **out = NULL;
    size_t count = 0, cap = 0;
    char buf[8192];
    while (fgets (buf, sizeof buf, f)) {
        size_t len = strlen (buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
            buf[--len] = '\0';
        if (count == cap) {
            size_t next = cap ? cap * 2 : 16;
            char **grown = realloc (out, next * sizeof *grown);
            if (!grown) { fclose (f); goto oom; }
            out = grown;
            cap = next;
        }
        out[count] = strdup (buf);
        if (!out[count]) { fclose (f); goto oom; }
        count++;
    }
    fclose (f);
    *lines = out;
    *n = count;
    return 0;
oom:
    for (size_t i = 0; i < count; i++) free (out[i]);
    free (out);
    return -1;
}

/* Check the caller's expectation of what the ref holds. */
static int
bgit_ref_check_old (const bgit_repo *repo, const char *refname,
                    const char *old_sha, char current[41], int *exists)
{
    int rc = bgit_ref_read (repo, refname, current);
    if (rc < 0) {
        builtin_error ("cannot read ref %s", refname);
        return -1;
    }
    *exists = (rc == 0);
    if (!old_sha) return 0;
    if (!*old_sha) {
        if (*exists) {
            builtin_error ("cannot lock ref '%s': reference already exists",
                           refname);
            return -1;
        }
        return 0;
    }
    if (!*exists) {
        builtin_error ("cannot lock ref '%s': unable to resolve reference '%s'",
                       refname, refname);
        return -1;
    }
    if (strcasecmp (current, old_sha) != 0) {
        builtin_error ("cannot lock ref '%s': is at %s but expected %s",
                       refname, current, old_sha);
        return -1;
    }
    return 0;
}

int
bgit_ref_update (const bgit_repo *repo, const char *refname,
                 const char *new_sha, const char *old_sha, const char *message)
{
    if (!bgit_ref_name_ok (refname)) {
        builtin_error ("invalid ref format: %s", refname);
        return -1;
    }
    if (!new_sha || strlen (new_sha) != 40 || !bgit_all_hex (new_sha)) {
        builtin_error ("invalid object name: %s", new_sha ? new_sha : "");
        return -1;
    }
    char current[41] = "";
    int exists = 0;
    if (bgit_ref_check_old (repo, refname, old_sha, current, &exists) < 0)
        return -1;

    char path[4096];
    if (bgit_ref_path (repo, refname, path, sizeof path) < 0) return -1;
    bgit_lock lock;
    if (bgit_lock_acquire (&lock, path) < 0) return -1;
    char line[42];
    int len = snprintf (line, sizeof line, "%s\n", new_sha);
    if (bgit_lock_write (&lock, line, (size_t) len) < 0 ||
        bgit_lock_commit (&lock) < 0) {
        bgit_lock_rollback (&lock);
        return -1;
    }
    /* A ref set to what it already held has not moved, and git's log of it
       records moves. HEAD is written elsewhere, where a checkout logs the
       move whether the id changed or not. */
    if (exists && !strcmp (current, new_sha)) return 0;
    return bgit_reflog_append (repo, refname, exists ? current : NULL, new_sha,
                               message);
}

int
bgit_ref_set (const bgit_repo *repo, const char *refname, const char *new_sha,
              const char *old_sha)
{
    char current[41] = "";
    int exists = 0;
    if (!bgit_ref_name_ok (refname)) {
        builtin_error ("invalid ref name: %s", refname);
        return -1;
    }
    if (!new_sha || strlen (new_sha) != 40 || !bgit_all_hex (new_sha)) {
        builtin_error ("invalid object name: %s", new_sha ? new_sha : "");
        return -1;
    }
    if (bgit_ref_check_old (repo, refname, old_sha, current, &exists) < 0)
        return -1;
    char path[4096];
    if (bgit_ref_path (repo, refname, path, sizeof path) < 0) return -1;
    bgit_lock lock;
    if (bgit_lock_acquire (&lock, path) < 0) return -1;
    char line[42];
    int len = snprintf (line, sizeof line, "%s\n", new_sha);
    if (bgit_lock_write (&lock, line, (size_t) len) < 0 ||
        bgit_lock_commit (&lock) < 0) {
        bgit_lock_rollback (&lock);
        return -1;
    }
    return 0;
}

int
bgit_symref_write (const bgit_repo *repo, const char *name, const char *target,
                   const char *message)
{
    if (!bgit_ref_name_ok (target)) {
        builtin_error ("invalid ref format: %s", target);
        return -1;
    }
    char path[4096];
    if (bgit_ref_path (repo, name, path, sizeof path) < 0) return -1;
    char before[41] = "";
    int had = bgit_ref_resolve (repo, name, before, NULL) == 0;
    bgit_lock lock;
    if (bgit_lock_acquire (&lock, path) < 0) return -1;
    char line[4200];
    int len = snprintf (line, sizeof line, "ref: %s\n", target);
    if (len < 0 || len >= (int) sizeof line ||
        bgit_lock_write (&lock, line, (size_t) len) < 0 ||
        bgit_lock_commit (&lock) < 0) {
        bgit_lock_rollback (&lock);
        return -1;
    }
    if (!message) return 0;
    char after[41] = "";
    int now_has = bgit_ref_resolve (repo, name, after, NULL) == 0;
    return bgit_reflog_append (repo, name, had ? before : NULL,
                               now_has ? after : NULL, message);
}

/* Rewrite packed-refs without REFNAME, under its own lock. */
static int
bgit_packed_refs_remove (const bgit_repo *repo, const char *refname)
{
    char path[4096];
    if (snprintf (path, sizeof path, "%s/packed-refs", repo->common_dir) >=
        (int) sizeof path)
        return -1;
    FILE *f = fopen (path, "r");
    if (!f) return 0;
    char **keep = NULL;
    size_t n = 0, cap = 0;
    char line[8192];
    int dropped = 0, drop_peel = 0;
    while (fgets (line, sizeof line, f)) {
        int is_peel = line[0] == '^';
        if (is_peel && drop_peel) { drop_peel = 0; continue; }
        drop_peel = 0;
        if (!is_peel && line[0] != '#') {
            size_t len = strlen (line);
            char trimmed[8192];
            memcpy (trimmed, line, len + 1);
            while (len > 0 && (trimmed[len - 1] == '\n' || trimmed[len - 1] == '\r'))
                trimmed[--len] = '\0';
            if (len > 41 && trimmed[40] == ' ' &&
                strcmp (trimmed + 41, refname) == 0) {
                dropped = 1;
                drop_peel = 1;
                continue;
            }
        }
        if (n == cap) {
            size_t next = cap ? cap * 2 : 64;
            char **grown = realloc (keep, next * sizeof *grown);
            if (!grown) { fclose (f); goto oom; }
            keep = grown;
            cap = next;
        }
        keep[n] = strdup (line);
        if (!keep[n]) { fclose (f); goto oom; }
        n++;
    }
    fclose (f);
    if (!dropped) {
        for (size_t i = 0; i < n; i++) free (keep[i]);
        free (keep);
        return 0;
    }
    bgit_lock lock;
    if (bgit_lock_acquire (&lock, path) < 0) goto oom;
    for (size_t i = 0; i < n; i++) {
        if (bgit_lock_write (&lock, keep[i], strlen (keep[i])) < 0) {
            bgit_lock_rollback (&lock);
            goto oom;
        }
    }
    int rc = bgit_lock_commit (&lock);
    for (size_t i = 0; i < n; i++) free (keep[i]);
    free (keep);
    return rc;
oom:
    for (size_t i = 0; i < n; i++) free (keep[i]);
    free (keep);
    return -1;
}

int
bgit_ref_delete (const bgit_repo *repo, const char *refname,
                 const char *old_sha, const char *message)
{
    char current[41] = "";
    int exists = 0;
    if (bgit_ref_check_old (repo, refname, old_sha, current, &exists) < 0)
        return -1;
    if (!exists) {
        builtin_error ("unable to delete '%s': reference does not exist",
                       refname);
        return -1;
    }
    char path[4096];
    if (bgit_ref_path (repo, refname, path, sizeof path) < 0) return -1;
    if (unlink (path) < 0 && errno != ENOENT) {
        builtin_error ("cannot remove %s: %s", path, strerror (errno));
        return -1;
    }
    if (bgit_packed_refs_remove (repo, refname) < 0) return -1;
    (void) message;   /* a deleted ref's log goes with it */
    char log[4096];
    if (bgit_reflog_path (repo, refname, log, sizeof log) == 0)
        unlink (log);
    return 0;
}

struct bgit_ref_collect {
    bgit_ref *refs;
    size_t n, cap;
    const bgit_repo *repo;     /* to follow a symbolic ref while listing */
};

static int
bgit_ref_collect_add (struct bgit_ref_collect *c, const char *name,
                      const char *sha)
{
    for (size_t i = 0; i < c->n; i++)
        if (strcmp (c->refs[i].name, name) == 0) return 0;   /* loose wins */
    if (c->n == c->cap) {
        size_t next = c->cap ? c->cap * 2 : 32;
        bgit_ref *grown = realloc (c->refs, next * sizeof *grown);
        if (!grown) return -1;
        c->refs = grown;
        c->cap = next;
    }
    c->refs[c->n].name = strdup (name);
    if (!c->refs[c->n].name) return -1;
    memcpy (c->refs[c->n].sha, sha, 41);
    c->n++;
    return 0;
}

/* Walk refs/ under one git directory. */
static int
bgit_refs_walk (struct bgit_ref_collect *c, const char *base,
                const char *relative, const char *prefix)
{
    char dir[4096];
    if (snprintf (dir, sizeof dir, "%s/%s", base, relative) >= (int) sizeof dir)
        return -1;
    DIR *handle = opendir (dir);
    if (!handle) return 0;
    struct dirent *entry;
    int rc = 0;
    while ((entry = readdir (handle)) != NULL) {
        if (!strcmp (entry->d_name, ".") || !strcmp (entry->d_name, ".."))
            continue;
        char name[4096];
        if (snprintf (name, sizeof name, "%s/%s", relative, entry->d_name) >=
            (int) sizeof name)
            continue;
        char path[4096];
        if (snprintf (path, sizeof path, "%s/%s", base, name) >= (int) sizeof path)
            continue;
        struct stat st;
        if (stat (path, &st) < 0) continue;
        if (S_ISDIR (st.st_mode)) {
            rc = bgit_refs_walk (c, base, name, prefix);
            if (rc < 0) break;
            continue;
        }
        size_t plen = strlen (prefix);
        if (plen && strncmp (name, prefix, plen) != 0) continue;
        char *line = bgit_first_line (path);
        if (!line) continue;
        if (strlen (line) >= 40 && bgit_all_hex (line)) {
            char sha[41];
            memcpy (sha, line, 40);
            sha[40] = '\0';
            if (bgit_ref_collect_add (c, name, sha) < 0) rc = -1;
        } else if (!strncmp (line, "ref: ", 5)) {
            /* A symbolic ref is listed too, standing for what it points
               at — refs/remotes/origin/HEAD is one, and git lists it. */
            char sha[41];
            if (bgit_ref_read (c->repo, line + 5, sha) == 0 &&
                bgit_ref_collect_add (c, name, sha) < 0)
                rc = -1;
        }
        free (line);
        if (rc < 0) break;
    }
    closedir (handle);
    return rc;
}

static int
bgit_ref_compare (const void *a, const void *b)
{
    return strcmp (((const bgit_ref *) a)->name, ((const bgit_ref *) b)->name);
}

int
bgit_refs_list (const bgit_repo *repo, const char *prefix, bgit_ref **out,
                size_t *n)
{
    struct bgit_ref_collect c = {0};
    c.repo = repo;
    const char *want = prefix ? prefix : "";
    if (bgit_refs_walk (&c, repo->common_dir, "refs", want) < 0) goto fail;
    if (strcmp (repo->git_dir, repo->common_dir) != 0 &&
        bgit_refs_walk (&c, repo->git_dir, "refs", want) < 0)
        goto fail;

    char packed[4096];
    if (snprintf (packed, sizeof packed, "%s/packed-refs", repo->common_dir) <
        (int) sizeof packed) {
        FILE *f = fopen (packed, "r");
        if (f) {
            char line[8192];
            while (fgets (line, sizeof line, f)) {
                if (line[0] == '#' || line[0] == '^') continue;
                size_t len = strlen (line);
                while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                    line[--len] = '\0';
                if (len < 42 || line[40] != ' ') continue;
                const char *name = line + 41;
                if (*want && strncmp (name, want, strlen (want)) != 0) continue;
                char sha[41];
                memcpy (sha, line, 40);
                sha[40] = '\0';
                if (bgit_ref_collect_add (&c, name, sha) < 0) {
                    fclose (f);
                    goto fail;
                }
            }
            fclose (f);
        }
    }
    if (c.n > 1) qsort (c.refs, c.n, sizeof *c.refs, bgit_ref_compare);
    *out = c.refs;
    *n = c.n;
    return 0;
fail:
    bgit_refs_free (c.refs, c.n);
    return -1;
}

void
bgit_refs_free (bgit_ref *refs, size_t n)
{
    for (size_t i = 0; i < n; i++) free (refs[i].name);
    free (refs);
}
