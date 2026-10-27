/* SPDX-License-Identifier: MIT */
/* _git/config.h — git's configuration files.
 *
 * The syntax git-config(1) describes: sections in brackets, subsections in
 * quotes, "key = value" pairs, a key alone meaning true, comments after #
 * or ;, values continued with a trailing backslash, quoted values with the
 * \n \t \b \" \\ escapes, and include.path pulling in another file.
 *
 * Files are read in git's order, each overriding the last: the system file
 * (unless GIT_CONFIG_NOSYSTEM), the user's (GIT_CONFIG_GLOBAL, or
 * ~/.gitconfig and ~/.config/git/config), the repository's, and finally
 * anything given with `git -c`.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_CONFIG_H
#define BASH_OS_GIT_CONFIG_H

#include <stddef.h>

#include "repo.h"

typedef struct {
    char *key;     /* lowercase section, subsection as written, lowercase key */
    char *value;   /* NULL for a key with no value, which means true */
    int level;     /* 0 system, 1 global, 2 repository, 3 command line */
} bgit_config_entry;

typedef struct {
    bgit_config_entry *entries;
    size_t n;
    size_t cap;
} bgit_config;

/* Read one file into CFG at LEVEL. Returns 0, 1 when there is no such file,
   or -1 with a message for a malformed one. */
int bgit_config_read_file (bgit_config *cfg, const char *path, int level);

/* Read every file that applies to REPO (which may be NULL, for outside a
   repository), then apply OVERRIDES, the "key=value" strings from `git -c`. */
int bgit_config_load (bgit_config *cfg, const bgit_repo *repo,
                      const char *const *overrides, size_t n_overrides);

void bgit_config_release (bgit_config *cfg);

/* The last value set for KEY ("user.name"), or NULL. */
const char *bgit_config_get (const bgit_config *cfg, const char *key);

/* Every value for KEY, oldest first; the count is returned. */
size_t bgit_config_get_all (const bgit_config *cfg, const char *key,
                            const char ***values);

/* git's truth values: true/yes/on/1 and a valueless key are true;
   false/no/off/0 and an empty value are false. Anything else is DEFAULT. */
int bgit_config_bool (const bgit_config *cfg, const char *key, int fallback);

/* Set, add to or remove KEY in one file, keeping the rest of the file as it
   is. With MULTIPLE, an add leaves existing values alone. */
int bgit_config_set_file (const char *path, const char *key, const char *value,
                          int multiple);
int bgit_config_unset_file (const char *path, const char *key);

/* Take a whole section out of one file, header and all. Returns 0, or 1
   when the file has no such section. */
int bgit_config_remove_section_file (const char *path, const char *section);

/* Where `git config` writes without --file: the repository's config. */
int bgit_config_repo_file (const bgit_repo *repo, char *out, size_t outsz);
/* And with --global: GIT_CONFIG_GLOBAL, or ~/.gitconfig. */
int bgit_config_global_file (char *out, size_t outsz);

/* The identity for an author or committer line: the GIT_* variables, then
   user.name and user.email, then a plain fallback. The date comes from
   GIT_AUTHOR_DATE / GIT_COMMITTER_DATE where one is set and otherwise from
   the clock, and is written in git's raw form, "<seconds> <+hhmm>". Returns
   0, -1 when the line will not fit, or -2 when the date in the environment
   is not one git would take — the caller says so in git's words. */
int bgit_ident (const bgit_config *cfg, int committer, char *out, size_t outsz);

#endif /* BASH_OS_GIT_CONFIG_H */
