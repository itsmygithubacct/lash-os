/* SPDX-License-Identifier: MIT */
/* ipcmk.c -- create System V and named POSIX IPC resources as a bash builtin.
 *
 * Narrow util-linux-compatible surface:
 *   ipcmk -M SIZE [-p MODE]     shmget(IPC_PRIVATE, SIZE, ...)
 *   ipcmk -S NSEMS [-p MODE]    semget(IPC_PRIVATE, NSEMS, ...)
 *   ipcmk -Q [-p MODE]          msgget(IPC_PRIVATE, ...)
 *   ipcmk -n /NAME (-m SIZE|-s|-q) [-p MODE]  named POSIX IPC
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <semaphore.h>
#include <sys/mman.h>
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
    IPCMK_MSG,
    IPCMK_POSIX_SHM,
    IPCMK_POSIX_SEM,
    IPCMK_POSIX_MSG
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

/* Flush before reporting success: a lost identifier would orphan the object. */
static int
ipcmk_output_ok (void)
{
    return fflush (stdout) == 0 && !ferror (stdout);
}

static int
ipcmk_parse_mode (const char *s, unsigned int *mode_out)
{
    char *end = NULL;
    unsigned long mode;

    if (s == NULL || *s < '0' || *s > '9')
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

    if (s == NULL || *s < '0' || *s > '9')
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

    if (s == NULL || *s < '0' || *s > '9')
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
    puts ("");
    puts ("POSIX modes require -n /name; permissions are filtered by umask.");
    puts ("Sizes accept K/KiB, M/MiB, G/GiB and T/TiB suffixes.");
    puts ("Create one resource per call; successful resources persist until removed.");
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
    const char *name = NULL;

    clearerr (stdout);

    while (list) {
        const char *w = list->word->word;
        const char *arg = NULL;

        if (!strcmp (w, "--help") || !strcmp (w, "-h")) {
            ipcmk_print_help ();
            return ipcmk_output_ok () ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        }
        if (!strcmp (w, "--version") || !strcmp (w, "-V")) {
            puts ("ipcmk from util-linux 2.41");
            return ipcmk_output_ok () ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
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

        if (!strcmp (w, "--posix-semaphore") || !strcmp (w, "-s")
            || !strcmp (w, "--posix-mqueue") || !strcmp (w, "-q")) {
            enum ipcmk_kind next = (!strcmp (w, "-s") || !strcmp (w, "--posix-semaphore"))
                                  ? IPCMK_POSIX_SEM : IPCMK_POSIX_MSG;
            if (ipcmk_set_kind (&kind, next) < 0)
                return ipcmk_bad_usage ();
            list = list->next;
            continue;
        }

        if (!strcmp (w, "--name") || !strncmp (w, "--name=", 7)
            || !strncmp (w, "-n", 2)) {
            if (!strncmp (w, "--name=", 7))
                name = w + 7;
            else if (w[1] == 'n' && w[2] != '\0')
                name = w + 2;
            else {
                if (!list->next)
                    return ipcmk_missing_argument (w);
                list = list->next;
                name = list->word->word;
            }
            list = list->next;
            continue;
        }

        if (!strcmp (w, "--shmem") || !strncmp (w, "--shmem=", 8)
            || !strncmp (w, "-M", 2) || !strcmp (w, "--posix-shmem")
            || !strncmp (w, "--posix-shmem=", 14) || !strncmp (w, "-m", 2)) {
            int posix = w[1] == 'm' || !strncmp (w, "--posix-shmem", 13);
            if (!strncmp (w, "--shmem=", 8))
                arg = w + 8;
            else if (!strncmp (w, "--posix-shmem=", 14))
                arg = w + 14;
            else if ((w[1] == 'M' || w[1] == 'm') && w[2] != '\0')
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
            if (ipcmk_set_kind (&kind, posix ? IPCMK_POSIX_SHM : IPCMK_SHM) < 0)
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

    if (kind >= IPCMK_POSIX_SHM) {
        /* One leading slash, no other slash; never open an existing object. */
        if (!name || name[0] != '/' || !name[1] || strchr (name + 1, '/')) {
            fprintf (stderr, "ipcmk: POSIX resources require --name /name (no further slashes)\n");
            return EXECUTION_FAILURE;
        }
        if (kind == IPCMK_POSIX_SHM) {
            off_t length = (off_t) shm_size;
            int fd, saved;
            if (length <= 0 || (uintmax_t) length != (uintmax_t) shm_size) {
                fprintf (stderr, "ipcmk: shared memory size exceeds off_t range\n");
                return EXECUTION_FAILURE;
            }
            fd = shm_open (name, O_RDWR | O_CREAT | O_EXCL, mode);
            if (fd < 0)
                goto posix_error;
            if (ftruncate (fd, length) < 0) {
                saved = errno;
                close (fd);
                shm_unlink (name);
                errno = saved;
                goto posix_error;
            }
            if (close (fd) < 0) {
                saved = errno;
                shm_unlink (name);
                errno = saved;
                goto posix_error;
            }
        } else if (kind == IPCMK_POSIX_SEM) {
            sem_t *sem = sem_open (name, O_CREAT | O_EXCL, mode, 0U);
            if (sem == SEM_FAILED)
                goto posix_error;
            if (sem_close (sem) < 0) {
                int saved = errno;
                sem_unlink (name);
                errno = saved;
                goto posix_error;
            }
        } else {
            mqd_t mq = mq_open (name, O_RDWR | O_CREAT | O_EXCL, mode, (struct mq_attr *) NULL);
            if (mq == (mqd_t) -1)
                goto posix_error;
            if (mq_close (mq) < 0) {
                int saved = errno;
                mq_unlink (name);
                errno = saved;
                goto posix_error;
            }
        }
        printf ("%s name: %s\n", kind == IPCMK_POSIX_SHM ? "Shared memory" :
                kind == IPCMK_POSIX_SEM ? "Semaphore" : "Message queue", name);
        if (ipcmk_output_ok ())
            return EXECUTION_SUCCESS;
        if (kind == IPCMK_POSIX_SHM)
            shm_unlink (name);
        else if (kind == IPCMK_POSIX_SEM)
            sem_unlink (name);
        else
            mq_unlink (name);
        fprintf (stderr, "ipcmk: write error\n");
        return EXECUTION_FAILURE;
    }
    if (name)
        return ipcmk_bad_usage ();

    switch (kind) {
    case IPCMK_SHM: {
        int id = shmget (IPC_PRIVATE, shm_size, IPC_CREAT | IPC_EXCL | (int) mode);
        if (id < 0) {
            fprintf (stderr, "ipcmk: shared memory get failed: %s\n", strerror (errno));
            return EXECUTION_FAILURE;
        }
        printf ("Shared memory id: %d\n", id);
        if (ipcmk_output_ok ())
            return EXECUTION_SUCCESS;
        shmctl (id, IPC_RMID, NULL);
        fprintf (stderr, "ipcmk: write error\n");
        return EXECUTION_FAILURE;
    }
    case IPCMK_SEM: {
        int id = semget (IPC_PRIVATE, sem_count, IPC_CREAT | IPC_EXCL | (int) mode);
        if (id < 0) {
            fprintf (stderr, "ipcmk: semaphore get failed: %s\n", strerror (errno));
            return EXECUTION_FAILURE;
        }
        printf ("Semaphore id: %d\n", id);
        if (ipcmk_output_ok ())
            return EXECUTION_SUCCESS;
        semctl (id, 0, IPC_RMID);
        fprintf (stderr, "ipcmk: write error\n");
        return EXECUTION_FAILURE;
    }
    case IPCMK_MSG: {
        int id = msgget (IPC_PRIVATE, IPC_CREAT | IPC_EXCL | (int) mode);
        if (id < 0) {
            fprintf (stderr, "ipcmk: message queue get failed: %s\n", strerror (errno));
            return EXECUTION_FAILURE;
        }
        printf ("Message queue id: %d\n", id);
        if (ipcmk_output_ok ())
            return EXECUTION_SUCCESS;
        msgctl (id, IPC_RMID, NULL);
        fprintf (stderr, "ipcmk: write error\n");
        return EXECUTION_FAILURE;
    }
    default:
        return ipcmk_bad_usage ();
    }

posix_error:
    fprintf (stderr, "ipcmk: POSIX IPC creation failed for %s: %s\n", name, strerror (errno));
    return EXECUTION_FAILURE;
}

char *ipcmk_doc[] = {
    "Create System V or named POSIX IPC resources.",
    "",
    "    ipcmk [-p mode] -M size",
    "    ipcmk [-p mode] -S number",
    "    ipcmk [-p mode] -Q",
    "",
    "    ipcmk [-p mode] -n /name (-m size|-s|-q)",
    "POSIX permissions are filtered by umask; semaphore initial value is zero.",
    "Successful resources persist until explicitly removed or unlinked.",
    (char *) NULL
};

struct builtin ipcmk_struct = {
    "ipcmk",
    ipcmk_builtin,
    BUILTIN_ENABLED,
    ipcmk_doc,
    "ipcmk [-p mode] (-M size|-S number|-Q|-n /name (-m size|-s|-q))",
    0
};
