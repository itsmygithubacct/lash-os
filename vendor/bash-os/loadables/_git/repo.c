/* SPDX-License-Identifier: MIT */
/* _git/repo.c — finding a repository and its object directories.
 *
 * See repo.h. Nothing here prints: callers report "not a git repository"
 * themselves, because each command words it differently.
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
#include <sys/stat.h>

#include "repo.h"

static char *
bgit_join (const char *a, const char *b)
{
    size_t la = strlen (a);
    int slash = la > 0 && a[la - 1] == '/';
    size_t n = la + (slash ? 0 : 1) + strlen (b) + 1;
    char *out = malloc (n);
    if (!out) return NULL;
    snprintf (out, n, "%s%s%s", a, slash ? "" : "/", b);
    return out;
}

static int
bgit_is_dir (const char *path)
{
    struct stat st;
    return path && stat (path, &st) == 0 && S_ISDIR (st.st_mode);
}

static int
bgit_is_file (const char *path)
{
    struct stat st;
    return path && stat (path, &st) == 0 && S_ISREG (st.st_mode);
}

/* Read a small file, trimming trailing newlines. NULL if unreadable. */
static char *
bgit_read_line_file (const char *path)
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

/* A .git *file* says "gitdir: PATH". Relative paths are relative to the
   directory holding the file, as git resolves them. */
static char *
bgit_gitfile_target (const char *gitfile)
{
    char *line = bgit_read_line_file (gitfile);
    if (!line) return NULL;
    const char *prefix = "gitdir:";
    if (strncmp (line, prefix, strlen (prefix)) != 0) { free (line); return NULL; }
    char *value = line + strlen (prefix);
    while (*value && isspace ((unsigned char) *value)) value++;
    if (!*value) { free (line); return NULL; }
    char *target;
    if (value[0] == '/') {
        target = strdup (value);
    } else {
        char *copy = strdup (gitfile);
        if (!copy) { free (line); return NULL; }
        char *slash = strrchr (copy, '/');
        if (slash) *slash = '\0';
        else { free (copy); copy = strdup ("."); }
        target = copy ? bgit_join (copy, value) : NULL;
        free (copy);
    }
    free (line);
    if (!target) return NULL;
    char *resolved = realpath (target, NULL);
    if (resolved) { free (target); return resolved; }
    return target;
}

/* A linked worktree's git directory holds "commondir", pointing at the main
   repository's git directory, which owns refs and objects. */
static char *
bgit_common_dir (const char *git_dir)
{
    char *path = bgit_join (git_dir, "commondir");
    if (!path) return NULL;
    char *line = bgit_read_line_file (path);
    free (path);
    if (!line) return strdup (git_dir);
    char *common;
    if (line[0] == '/') {
        common = strdup (line);
    } else {
        common = bgit_join (git_dir, line);
    }
    free (line);
    if (!common) return NULL;
    char *resolved = realpath (common, NULL);
    if (resolved) { free (common); return resolved; }
    return common;
}

static int
bgit_repo_fill (const char *git_dir, const char *work_tree, bgit_repo *out)
{
    memset (out, 0, sizeof *out);
    char *resolved = realpath (git_dir, NULL);
    out->git_dir = resolved ? resolved : strdup (git_dir);
    if (!out->git_dir) return -1;
    out->common_dir = bgit_common_dir (out->git_dir);
    if (!out->common_dir) { bgit_repo_release (out); return -1; }
    /* A directory named .git is not enough. Linked worktrees keep HEAD
       locally and the object/ref directories under commondir. */
    char *head = bgit_join (out->git_dir, "HEAD");
    char *refs = bgit_join (out->common_dir, "refs");
    char *objects = bgit_join (out->common_dir, "objects");
    const char *object_override = getenv ("GIT_OBJECT_DIRECTORY");
    int valid = bgit_is_file (head) && bgit_is_dir (refs) &&
                bgit_is_dir (object_override && *object_override ?
                             object_override : objects);
    free (head); free (refs); free (objects);
    if (!valid) { bgit_repo_release (out); return -1; }
    const char *env_work = getenv ("GIT_WORK_TREE");
    if (env_work && *env_work) work_tree = env_work;
    if (work_tree && *work_tree) {
        char *w = realpath (work_tree, NULL);
        out->work_tree = w ? w : strdup (work_tree);
        if (!out->work_tree) { bgit_repo_release (out); return -1; }
    } else {
        out->bare = 1;
    }
    return 0;
}

int
bgit_repo_open (const char *git_dir, bgit_repo *out)
{
    if (!git_dir || !*git_dir) return -1;
    /* A directory holding .git is a worktree; .git itself is the git dir. */
    char *inner = bgit_join (git_dir, ".git");
    if (!inner) return -1;
    if (bgit_is_dir (inner)) {
        int rc = bgit_repo_fill (inner, git_dir, out);
        free (inner);
        return rc;
    }
    if (bgit_is_file (inner)) {
        char *target = bgit_gitfile_target (inner);
        free (inner);
        if (!target) return -1;
        int rc = bgit_repo_fill (target, git_dir, out);
        free (target);
        return rc;
    }
    free (inner);
    if (!bgit_is_dir (git_dir)) return -1;
    /* A bare repository, or a git directory named directly. */
    char *head = bgit_join (git_dir, "HEAD");
    int looks_like_repo = bgit_is_file (head);
    free (head);
    if (!looks_like_repo) return -1;
    return bgit_repo_fill (git_dir, NULL, out);
}

const char *
bgit_env (const char *name, char *out, size_t outsz)
{
    const char *value = getenv (name);
    if (!value || !*value) return NULL;
    snprintf (out, outsz, "%s", value);
    return out;
}

int
bgit_repo_discover (const char *start, bgit_repo *out)
{
    char held_dir[4096], held_work[4096];
    const char *env_dir = bgit_env ("GIT_DIR", held_dir, sizeof held_dir);
    if (env_dir) {
        const char *work = bgit_env ("GIT_WORK_TREE", held_work,
                                     sizeof held_work);
        if (bgit_is_dir (env_dir))
            return bgit_repo_fill (env_dir, work ? work : ".", out);
        return -1;
    }
    char *cur = realpath (start && *start ? start : ".", NULL);
    if (!cur) return -1;
    for (;;) {
        char *candidate = bgit_join (cur, ".git");
        if (!candidate) { free (cur); return -1; }
        if (bgit_is_dir (candidate)) {
            int rc = bgit_repo_fill (candidate, cur, out);
            free (candidate); free (cur);
            return rc;
        }
        if (bgit_is_file (candidate)) {
            char *target = bgit_gitfile_target (candidate);
            free (candidate);
            if (!target) { free (cur); return -1; }
            int rc = bgit_repo_fill (target, cur, out);
            free (target); free (cur);
            return rc;
        }
        free (candidate);
        /* A bare repository given as the starting directory. */
        char *head = bgit_join (cur, "HEAD");
        char *objects = bgit_join (cur, "objects");
        int bare = bgit_is_file (head) && bgit_is_dir (objects);
        free (head); free (objects);
        if (bare) {
            int rc = bgit_repo_fill (cur, NULL, out);
            free (cur);
            return rc;
        }
        char *slash = strrchr (cur, '/');
        if (!slash || slash == cur) { free (cur); return -1; }
        *slash = '\0';
    }
}

void
bgit_repo_release (bgit_repo *repo)
{
    if (!repo) return;
    free (repo->git_dir);
    free (repo->common_dir);
    free (repo->work_tree);
    memset (repo, 0, sizeof *repo);
}

static int
bgit_dirs_push (char ***dirs, size_t *n, size_t *cap, char *path)
{
    if (!path) return -1;
    for (size_t i = 0; i < *n; i++)
        if (strcmp ((*dirs)[i], path) == 0) { free (path); return 0; }
    if (*n == *cap) {
        size_t next = *cap ? *cap * 2 : 4;
        char **grown = realloc (*dirs, next * sizeof **dirs);
        if (!grown) { free (path); return -1; }
        *dirs = grown;
        *cap = next;
    }
    (*dirs)[(*n)++] = path;
    return 0;
}

/* GIT_ALTERNATE_OBJECT_DIRECTORIES is a colon-separated list; an
   objects/info/alternates file holds one path per line, '#' comments
   skipped, relative paths resolved against the objects directory. */
static int
bgit_add_alternates (const char *objects, char ***dirs, size_t *n, size_t *cap)
{
    const char *env = getenv ("GIT_ALTERNATE_OBJECT_DIRECTORIES");
    if (env && *env) {
        const char *p = env;
        while (*p) {
            const char *colon = strchr (p, ':');
            size_t len = colon ? (size_t) (colon - p) : strlen (p);
            if (len) {
                char *path = strndup (p, len);
                if (bgit_dirs_push (dirs, n, cap, path) < 0) return -1;
            }
            if (!colon) break;
            p = colon + 1;
        }
    }
    char *list = bgit_join (objects, "info/alternates");
    if (!list) return -1;
    FILE *f = fopen (list, "r");
    free (list);
    if (!f) return 0;
    char line[4096];
    while (fgets (line, sizeof line, f)) {
        size_t len = strlen (line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (!len || line[0] == '#') continue;
        char *path = line[0] == '/' ? strdup (line) : bgit_join (objects, line);
        if (bgit_dirs_push (dirs, n, cap, path) < 0) { fclose (f); return -1; }
    }
    fclose (f);
    return 0;
}

int
bgit_repo_object_dirs (const bgit_repo *repo, char ***dirs_out, size_t *n_out)
{
    char **dirs = NULL;
    size_t n = 0, cap = 0;
    const char *env = getenv ("GIT_OBJECT_DIRECTORY");
    char *objects = (env && *env) ? strdup (env)
                                  : bgit_join (repo->common_dir, "objects");
    if (!objects) return -1;
    if (bgit_dirs_push (&dirs, &n, &cap, objects) < 0) {
        bgit_repo_free_object_dirs (dirs, n);
        return -1;
    }
    if (bgit_add_alternates (dirs[0], &dirs, &n, &cap) < 0) {
        bgit_repo_free_object_dirs (dirs, n);
        return -1;
    }
    *dirs_out = dirs;
    *n_out = n;
    return 0;
}

void
bgit_repo_free_object_dirs (char **dirs, size_t n)
{
    for (size_t i = 0; i < n; i++) free (dirs[i]);
    free (dirs);
}
