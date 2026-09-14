/* SPDX-License-Identifier: MIT */
/* ipcmk.c -- create Linux System V IPC resources, as a bash builtin.
 *
 * Narrow util-linux-compatible surface:
 *   ipcmk -M SIZE [-p MODE]     shmget(IPC_PRIVATE, SIZE, ...)
 *   ipcmk -S NSEMS [-p MODE]    semget(IPC_PRIVATE, NSEMS, ...)
 *   ipcmk -Q [-p MODE]          msgget(IPC_PRIVATE, ...)
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/types.h>

#include "loadables.h"

enum ipcmk_kind {
    IPCMK_NONE = 0,
    IPCMK_SHM,
    IPCMK_SEM,
    IPCMK_MSG
};

static void
ipcmk_try_help (void)
{
    fprintf (stderr, "Try 'ipcmk --help' for more information.\n");
}

static int
ipcmk_bad_usage (void)
{
    fprintf (stderr, "ipcmk: bad usage\n");
    ipcmk_try_help ();
    return EXECUTION_FAILURE;
}

static int
ipcmk_missing_argument (const char *opt)
{
    fprintf (stderr, "ipcmk: option '%s' requires an argument\n", opt);
    ipcmk_try_help ();
    return EXECUTION_FAILURE;
}

static int
ipcmk_unrecognized (const char *opt)
{
    fprintf (stderr, "ipcmk: unrecognized option '%s'\n", opt);
    ipcmk_try_help ();
    return EXECUTION_FAILURE;
}

static int
ipcmk_posix_unsupported (void)
{
    fprintf (stderr,
             "ipcmk: POSIX IPC unsupported on bash-os (kernel built without CONFIG_POSIX_MQUEUE / no /dev/shm)\n");
    return EXECUTION_FAILURE;
}

static int
ipcmk_parse_mode (const char *s, unsigned int *mode_out)
{
    char *end = NULL;
    unsigned long mode;

    if (s == NULL || *s == '\0')
        return -1;
    errno = 0;
    mode = strtoul (s, &end, 8);
    if (errno != 0 || end == s || *end != '\0' || mode > 0777)
        return -1;
    *mode_out = (unsigned int) mode;
    return 0;
}

static int
ipcmk_parse_count (const char *s, int *count_out)
{
    char *end = NULL;
    unsigned long count;

    if (s == NULL || *s == '\0')
        return -1;
    errno = 0;
    count = strtoul (s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || count == 0 || count > INT_MAX)
        return -1;
    *count_out = (int) count;
    return 0;
}

static int
ipcmk_suffix_multiplier (const char *suffix, unsigned long long *mult_out)
{
    if (suffix == NULL || *suffix == '\0') {
        *mult_out = 1ULL;
        return 0;
    }
    if (!strcasecmp (suffix, "K") || !strcasecmp (suffix, "KiB")) {
        *mult_out = 1024ULL;
        return 0;
    }
    if (!strcasecmp (suffix, "M") || !strcasecmp (suffix, "MiB")) {
        *mult_out = 1024ULL * 1024ULL;
        return 0;
    }
    if (!strcasecmp (suffix, "G") || !strcasecmp (suffix, "GiB")) {
        *mult_out = 1024ULL * 1024ULL * 1024ULL;
        return 0;
    }
    if (!strcasecmp (suffix, "T") || !strcasecmp (suffix, "TiB")) {
        *mult_out = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
        return 0;
    }
    return -1;
}

static int
ipcmk_parse_size (const char *s, size_t *size_out)
{
    char *end = NULL;
    unsigned long long base, mult;

    if (s == NULL || *s == '\0')
        return -1;
    errno = 0;
    base = strtoull (s, &end, 10);
    if (errno != 0 || end == s || base == 0)
        return -1;
    if (ipcmk_suffix_multiplier (end, &mult) < 0)
        return -1;
    if (base > ULLONG_MAX / mult)
        return -1;
    base *= mult;
    if (base > (unsigned long long) SIZE_MAX)
        return -1;
    *size_out = (size_t) base;
    return 0;
}

static void
ipcmk_print_help (void)
{
    puts ("");
    puts ("Usage:");
    puts (" ipcmk [options]");
    puts ("");
    puts ("Create various IPC resources.");
    puts ("");
    puts ("Options:");
    puts (" -M, --shmem <size>       create shared memory segment of size <size>");
    puts (" -m, --posix-shmem <size> create POSIX shared memory segment of size <size>");
    puts (" -S, --semaphore <number> create semaphore array with <number> elements");
    puts (" -s, --posix-semaphore    create POSIX semaphore");
    puts (" -Q, --queue              create message queue");
    puts (" -q, --posix-mqueue       create POSIX message queue");
    puts (" -p, --mode <mode>        permission for the resource (default is 0644)");
    puts (" -n, --name <name>        name of the POSIX resource");
    puts ("");
    puts (" -h, --help               display this help");
    puts (" -V, --version            display version");
}

static int
ipcmk_set_kind (enum ipcmk_kind *kind, enum ipcmk_kind next)
{
    if (*kind != IPCMK_NONE && *kind != next)
        return -1;
    *kind = next;
    return 0;
}

int
ipcmk_builtin (WORD_LIST *list)
{
    enum ipcmk_kind kind = IPCMK_NONE;
    unsigned int mode = 0644;
    size_t shm_size = 0;
    int sem_count = 0;

    while (list) {
        const char *w = list->word->word;
        const char *arg = NULL;

        if (!strcmp (w, "--help") || !strcmp (w, "-h")) {
            ipcmk_print_help ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version") || !strcmp (w, "-V")) {
            puts ("ipcmk from util-linux 2.41");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--")) {
            list = list->next;
            break;
        }

        if (!strcmp (w, "--queue") || !strcmp (w, "-Q")) {
            if (ipcmk_set_kind (&kind, IPCMK_MSG) < 0)
                return ipcmk_bad_usage ();
            list = list->next;
            continue;
        }

        if (!strcmp (w, "--posix-semaphore") || !strcmp (w, "--posix-mqueue")
            || !strcmp (w, "-s") || !strcmp (w, "-q"))
            return ipcmk_posix_unsupported ();

        if (!strcmp (w, "--posix-shmem") || !strncmp (w, "--posix-shmem=", 14)
            || !strcmp (w, "-m") || !strncmp (w, "-m", 2))
            return ipcmk_posix_unsupported ();

        if (!strcmp (w, "--name") || !strncmp (w, "--name=", 7)
            || !strcmp (w, "-n") || !strncmp (w, "-n", 2))
            return ipcmk_posix_unsupported ();

        if (!strcmp (w, "--shmem") || !strncmp (w, "--shmem=", 8)
            || !strcmp (w, "-M") || !strncmp (w, "-M", 2)) {
            if (!strncmp (w, "--shmem=", 8))
                arg = w + 8;
            else if (!strncmp (w, "-M", 2) && w[2] != '\0')
                arg = w + 2;
            else {
                if (!list->next)
                    return ipcmk_missing_argument (w);
                list = list->next;
                arg = list->word->word;
            }
            if (ipcmk_parse_size (arg, &shm_size) < 0) {
                fprintf (stderr, "ipcmk: invalid shared memory size '%s'\n", arg);
                return EXECUTION_FAILURE;
            }
            if (ipcmk_set_kind (&kind, IPCMK_SHM) < 0)
                return ipcmk_bad_usage ();
            list = list->next;
            continue;
        }

        if (!strcmp (w, "--semaphore") || !strncmp (w, "--semaphore=", 12)
            || !strcmp (w, "-S") || !strncmp (w, "-S", 2)) {
            if (!strncmp (w, "--semaphore=", 12))
                arg = w + 12;
            else if (!strncmp (w, "-S", 2) && w[2] != '\0')
                arg = w + 2;
            else {
                if (!list->next)
                    return ipcmk_missing_argument (w);
                list = list->next;
                arg = list->word->word;
            }
            if (ipcmk_parse_count (arg, &sem_count) < 0) {
                fprintf (stderr, "ipcmk: invalid semaphore count '%s'\n", arg);
                return EXECUTION_FAILURE;
            }
            if (ipcmk_set_kind (&kind, IPCMK_SEM) < 0)
                return ipcmk_bad_usage ();
            list = list->next;
            continue;
        }

        if (!strcmp (w, "--mode") || !strncmp (w, "--mode=", 7)
            || !strcmp (w, "-p") || !strncmp (w, "-p", 2)) {
            if (!strncmp (w, "--mode=", 7))
                arg = w + 7;
            else if (!strncmp (w, "-p", 2) && w[2] != '\0')
                arg = w + 2;
            else {
                if (!list->next)
                    return ipcmk_missing_argument (w);
                list = list->next;
                arg = list->word->word;
            }
            if (ipcmk_parse_mode (arg, &mode) < 0) {
                fprintf (stderr, "ipcmk: invalid mode '%s'\n", arg);
                return EXECUTION_FAILURE;
            }
            list = list->next;
            continue;
        }

        if (w[0] == '-')
            return ipcmk_unrecognized (w);
        return ipcmk_bad_usage ();
    }

    if (list)
        return ipcmk_bad_usage ();

    if (kind == IPCMK_NONE)
        return ipcmk_bad_usage ();

    switch (kind) {
    case IPCMK_SHM: {
        int id = shmget (IPC_PRIVATE, shm_size, IPC_CREAT | IPC_EXCL | (int) mode);
        if (id < 0) {
            fprintf (stderr, "ipcmk: shared memory get failed: %s\n", strerror (errno));
            return EXECUTION_FAILURE;
        }
        printf ("Shared memory id: %d\n", id);
        return EXECUTION_SUCCESS;
    }
    case IPCMK_SEM: {
        int id = semget (IPC_PRIVATE, sem_count, IPC_CREAT | IPC_EXCL | (int) mode);
        if (id < 0) {
            fprintf (stderr, "ipcmk: semaphore get failed: %s\n", strerror (errno));
            return EXECUTION_FAILURE;
        }
        printf ("Semaphore id: %d\n", id);
        return EXECUTION_SUCCESS;
    }
    case IPCMK_MSG: {
        int id = msgget (IPC_PRIVATE, IPC_CREAT | IPC_EXCL | (int) mode);
        if (id < 0) {
            fprintf (stderr, "ipcmk: message queue get failed: %s\n", strerror (errno));
            return EXECUTION_FAILURE;
        }
        printf ("Message queue id: %d\n", id);
        return EXECUTION_SUCCESS;
    }
    default:
        return ipcmk_bad_usage ();
    }
}

char *ipcmk_doc[] = {
    "Create System V IPC resources.",
    "",
    "    ipcmk [-p mode] -M size",
    "    ipcmk [-p mode] -S number",
    "    ipcmk [-p mode] -Q",
    "",
    "POSIX IPC modes are intentionally unsupported in bash-os.",
    (char *) NULL
};

struct builtin ipcmk_struct = {
    "ipcmk",
    ipcmk_builtin,
    BUILTIN_ENABLED,
    ipcmk_doc,
    "ipcmk [-p mode] (-M size|-S number|-Q)",
    0
};
