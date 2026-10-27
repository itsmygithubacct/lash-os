/* SPDX-License-Identifier: MIT */
/* _git/lock.h — git's lock files.
 *
 * git writes a file by creating "<path>.lock" exclusively, writing the new
 * content there, and renaming it over the old one. A second writer fails to
 * create the lock and says so instead of corrupting the file.
 *
 * Every held lock is registered, so a fatal error or a signal can remove
 * them all rather than leaving a repository that looks locked.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_LOCK_H
#define BASH_OS_GIT_LOCK_H

#include <stddef.h>

typedef struct bgit_lock bgit_lock;

struct bgit_lock {
    char *path;        /* the file being replaced */
    char *lock_path;   /* path + ".lock" */
    int fd;            /* -1 once committed or rolled back */
    bgit_lock *next;   /* registry of held locks */
};

/* Take the lock for PATH. Returns 0, or -1 with git's message, including
   "Unable to create '<path>.lock': File exists." when another writer holds
   it. */
int bgit_lock_acquire (bgit_lock *lock, const char *path);

/* Write into the held lock. */
int bgit_lock_write (bgit_lock *lock, const void *data, size_t n);

/* Flush, close and rename the lock over its file. */
int bgit_lock_commit (bgit_lock *lock);

/* Drop the lock without touching the file. Safe on a committed lock. */
void bgit_lock_rollback (bgit_lock *lock);

/* Remove every lock this process holds: for a fatal path or a signal. */
void bgit_lock_release_all (void);

#endif /* BASH_OS_GIT_LOCK_H */
