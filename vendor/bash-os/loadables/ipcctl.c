/* SPDX-License-Identifier: MIT */
/* ipcctl.c -- gated System V IPC control syscalls for bash-os.
 *
 * Narrow internal surface for rootfs/bash-os/ipcrm.sh:
 *   ipcctl --rm shm ID
 *   ipcctl --rm msg ID
 *   ipcctl --rm sem ID
 *
 * Removal is policy-off by default. The caller must set
 * BASHOS_IPCRM_ALLOW_RMID=1; the kernel still enforces normal IPC
 * ownership/CAP_IPC_OWNER rules.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

#include "loadables.h"

static int
ipcctl_parse_id (const char *s, int *id_out)
{
    char *end = NULL;
    long v;

    if (s == NULL || *s == '\0')
        return -1;
    errno = 0;
    v = strtol (s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 0 || v > INT_MAX)
        return -1;
    *id_out = (int) v;
    return 0;
}

static int
ipcctl_policy_allows_rmid (void)
{
    const char *v = getenv ("BASHOS_IPCRM_ALLOW_RMID");
    return v != NULL && strcmp (v, "1") == 0;
}

static int
ipcctl_usage (void)
{
    fprintf (stderr, "Usage: ipcctl --rm shm|msg|sem <id>\n");
    return EXECUTION_FAILURE;
}

static int
ipcctl_policy_denied (void)
{
    fprintf (stderr, "ipcctl: removal not permitted by policy (read-only mode)\n");
    return EXECUTION_FAILURE;
}

int
ipcctl_builtin (WORD_LIST *list)
{
    const char *op, *kind, *id_s;
    int id;

    if (list == NULL)
        return ipcctl_usage ();

    op = list->word->word;
    if (!strcmp (op, "--help") || !strcmp (op, "-h")) {
        puts ("Usage: ipcctl --rm shm|msg|sem <id>");
        puts ("Remove one System V IPC object when BASHOS_IPCRM_ALLOW_RMID=1.");
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (op, "--version") || !strcmp (op, "-V")) {
        puts ("ipcctl 1.0 (bash-os)");
        return EXECUTION_SUCCESS;
    }
    if (strcmp (op, "--rm") != 0)
        return ipcctl_usage ();

    list = list->next;
    if (list == NULL)
        return ipcctl_usage ();
    kind = list->word->word;

    list = list->next;
    if (list == NULL)
        return ipcctl_usage ();
    id_s = list->word->word;

    if (list->next != NULL)
        return ipcctl_usage ();

    if (ipcctl_parse_id (id_s, &id) < 0) {
        fprintf (stderr, "ipcctl: invalid id '%s'\n", id_s);
        return EXECUTION_FAILURE;
    }

    if (!ipcctl_policy_allows_rmid ())
        return ipcctl_policy_denied ();

    if (!strcmp (kind, "shm")) {
        if (shmctl (id, IPC_RMID, NULL) == 0)
            return EXECUTION_SUCCESS;
        fprintf (stderr, "ipcctl: shm IPC_RMID failed for id %d: %s\n", id, strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (!strcmp (kind, "msg")) {
        if (msgctl (id, IPC_RMID, NULL) == 0)
            return EXECUTION_SUCCESS;
        fprintf (stderr, "ipcctl: msg IPC_RMID failed for id %d: %s\n", id, strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (!strcmp (kind, "sem")) {
        if (semctl (id, 0, IPC_RMID) == 0)
            return EXECUTION_SUCCESS;
        fprintf (stderr, "ipcctl: sem IPC_RMID failed for id %d: %s\n", id, strerror (errno));
        return EXECUTION_FAILURE;
    }

    return ipcctl_usage ();
}

char *ipcctl_doc[] = {
    "Run gated System V IPC control operations.",
    "",
    "    ipcctl --rm shm|msg|sem <id>",
    "",
    "Mutating removal requires BASHOS_IPCRM_ALLOW_RMID=1.",
    (char *) NULL
};

struct builtin ipcctl_struct = {
    "ipcctl",
    ipcctl_builtin,
    BUILTIN_ENABLED,
    ipcctl_doc,
    "ipcctl --rm shm|msg|sem <id>",
    0
};
