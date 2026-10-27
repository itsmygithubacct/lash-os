/* SPDX-License-Identifier: MIT */
/* _git/lock.c — git's lock files. See lock.h.
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

#include "loadables.h"

#include "lock.h"

/* Locks this process holds, newest first. */
static bgit_lock *bgit_locks_held;

/* Create every directory above PATH, as git does for a new ref. */
static int
bgit_lock_mkdir_parents (const char *path)
{
    char buf[4096];
    if (snprintf (buf, sizeof buf, "%s", path) >= (int) sizeof buf)
        return -1;
    char *slash = strrchr (buf, '/');
    if (!slash || slash == buf) return 0;
    *slash = '\0';
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir (buf, 0777) < 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir (buf, 0777) < 0 && errno != EEXIST) return -1;
    return 0;
}

/* Give up a lock we never took: free the fields, and leave whatever is on
   disk alone. Rolling back here would delete the lock another writer holds. */
static void
bgit_lock_abandon (bgit_lock *lock)
{
    free (lock->path);
    free (lock->lock_path);
    memset (lock, 0, sizeof *lock);
    lock->fd = -1;
}

int
bgit_lock_acquire (bgit_lock *lock, const char *path)
{
    memset (lock, 0, sizeof *lock);
    lock->fd = -1;
    size_t need = strlen (path) + sizeof ".lock";
    lock->path = strdup (path);
    lock->lock_path = malloc (need);
    if (!lock->path || !lock->lock_path) {
        free (lock->path); free (lock->lock_path);
        memset (lock, 0, sizeof *lock);
        lock->fd = -1;
        return -1;
    }
    snprintf (lock->lock_path, need, "%s.lock", path);
    if (bgit_lock_mkdir_parents (lock->lock_path) < 0) {
        builtin_error ("cannot create directory for '%s': %s",
                       lock->lock_path, strerror (errno));
        bgit_lock_abandon (lock);
        return -1;
    }
    lock->fd = open (lock->lock_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
    if (lock->fd < 0) {
        if (errno == EEXIST)
            builtin_error ("Unable to create '%s': File exists.", lock->lock_path);
        else
            builtin_error ("cannot create '%s': %s", lock->lock_path, strerror (errno));
        bgit_lock_abandon (lock);
        return -1;
    }
    lock->next = bgit_locks_held;
    bgit_locks_held = lock;
    return 0;
}

int
bgit_lock_write (bgit_lock *lock, const void *data, size_t n)
{
    if (!lock || lock->fd < 0) return -1;
    const unsigned char *p = data;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write (lock->fd, p + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            builtin_error ("write '%s': %s", lock->lock_path, strerror (errno));
            return -1;
        }
        off += (size_t) w;
    }
    return 0;
}

static void
bgit_lock_forget (bgit_lock *lock)
{
    bgit_lock **link = &bgit_locks_held;
    while (*link) {
        if (*link == lock) { *link = lock->next; break; }
        link = &(*link)->next;
    }
    lock->next = NULL;
}

int
bgit_lock_commit (bgit_lock *lock)
{
    if (!lock || lock->fd < 0) return -1;
    if (fsync (lock->fd) < 0 && errno != EINVAL) {
        builtin_error ("fsync '%s': %s", lock->lock_path, strerror (errno));
        bgit_lock_rollback (lock);
        return -1;
    }
    if (close (lock->fd) < 0) {
        lock->fd = -1;
        builtin_error ("close '%s': %s", lock->lock_path, strerror (errno));
        bgit_lock_rollback (lock);
        return -1;
    }
    lock->fd = -1;
    if (rename (lock->lock_path, lock->path) < 0) {
        builtin_error ("rename '%s' to '%s': %s", lock->lock_path, lock->path,
                       strerror (errno));
        bgit_lock_rollback (lock);
        return -1;
    }
    bgit_lock_forget (lock);
    free (lock->path); free (lock->lock_path);
    memset (lock, 0, sizeof *lock);
    lock->fd = -1;
    return 0;
}

void
bgit_lock_rollback (bgit_lock *lock)
{
    if (!lock) return;
    if (lock->fd >= 0) { close (lock->fd); lock->fd = -1; }
    if (lock->lock_path) unlink (lock->lock_path);
    bgit_lock_forget (lock);
    free (lock->path); free (lock->lock_path);
    memset (lock, 0, sizeof *lock);
    lock->fd = -1;
}

void
bgit_lock_release_all (void)
{
    while (bgit_locks_held)
        bgit_lock_rollback (bgit_locks_held);
}
