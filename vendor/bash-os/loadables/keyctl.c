/* SPDX-License-Identifier: MIT */
/* keyctl.c — small Linux keyring syscall wrapper for bash-os.
 *
 * Verbs:
 *   keyctl session [NAME]              join/create a session keyring
 *   keyctl add TYPE DESC [KEYRING]     read payload from stdin, add_key
 *   keyctl search [KEYRING] TYPE DESC  print key serial
 *   keyctl print SERIAL                print key payload bytes
 *   keyctl revoke SERIAL               revoke key
 *   keyctl clear [KEYRING]             clear keyring
 *
 * This is intentionally much smaller than keyutils keyctl(1). It exists so
 * dnssec-keywrap can keep a KEK in the kernel keyring instead of on disk.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/syscall.h>
#include <linux/keyctl.h>

#include "loadables.h"

#ifndef SYS_add_key
# if defined (__NR_add_key)
#  define SYS_add_key __NR_add_key
# endif
#endif

#ifndef SYS_keyctl
# if defined (__NR_keyctl)
#  define SYS_keyctl __NR_keyctl
# endif
#endif

static long
bk_add_key (const char *type, const char *desc, const void *payload,
            size_t plen, long ring)
{
#if defined (SYS_add_key)
    return syscall (SYS_add_key, type, desc, payload, plen, ring);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static long
bk_keyctl (int cmd, unsigned long a1, unsigned long a2,
           unsigned long a3, unsigned long a4)
{
#if defined (SYS_keyctl)
    return syscall (SYS_keyctl, cmd, a1, a2, a3, a4);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
parse_long (const char *s, long *out)
{
    char *end = NULL;
    long v;
    if (!s || !*s) return -1;
    errno = 0;
    v = strtol (s, &end, 10);
    if (*end || errno == ERANGE)
        return -1;
    *out = v;
    return 0;
}

static int
parse_keyring (const char *s, long *out)
{
    if (!s || !*s || !strcmp (s, "@s")) {
        *out = KEY_SPEC_SESSION_KEYRING;
        return 0;
    }
    if (!strcmp (s, "@t")) { *out = KEY_SPEC_THREAD_KEYRING; return 0; }
    if (!strcmp (s, "@p")) { *out = KEY_SPEC_PROCESS_KEYRING; return 0; }
    if (!strcmp (s, "@u")) { *out = KEY_SPEC_USER_KEYRING; return 0; }
    if (!strcmp (s, "@us")) { *out = KEY_SPEC_USER_SESSION_KEYRING; return 0; }
    if (!strcmp (s, "@g")) { *out = KEY_SPEC_GROUP_KEYRING; return 0; }
    return parse_long (s, out);
}

static char *
read_stdin_all (size_t *lenp)
{
    size_t cap = 256, len = 0;
    char *buf = malloc (cap);
    if (!buf)
        return NULL;

    for (;;) {
        if (len == cap) {
            size_t ncap = cap * 2;
            char *nbuf = realloc (buf, ncap);
            if (!nbuf) {
                free (buf);
                return NULL;
            }
            buf = nbuf;
            cap = ncap;
        }
        ssize_t n = read (STDIN_FILENO, buf + len, cap - len);
        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            free (buf);
            return NULL;
        }
        len += (size_t)n;
    }
    *lenp = len;
    return buf;
}

static int
cmd_session (WORD_LIST *args)
{
    const char *name = args ? args->word->word : NULL;
    long serial = bk_keyctl (KEYCTL_JOIN_SESSION_KEYRING,
                             (unsigned long) name, 0, 0, 0);
    if (serial < 0) {
        builtin_error ("session: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    printf ("%ld\n", serial);
    return EXECUTION_SUCCESS;
}

static int
cmd_add (WORD_LIST *args)
{
    const char *type, *desc, *ring_s = "@s";
    long ring, serial;
    char *payload;
    size_t plen = 0;

    if (!args || !args->next) {
        builtin_error ("add: TYPE DESC [KEYRING]");
        return EX_USAGE;
    }
    type = args->word->word;
    desc = args->next->word->word;
    if (args->next->next)
        ring_s = args->next->next->word->word;
    if (parse_keyring (ring_s, &ring) < 0) {
        builtin_error ("add: invalid keyring: %s", ring_s);
        return EX_USAGE;
    }

    payload = read_stdin_all (&plen);
    if (!payload) {
        builtin_error ("add: read stdin: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }

    serial = bk_add_key (type, desc, payload, plen, ring);
    free (payload);
    if (serial < 0) {
        builtin_error ("add_key: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    printf ("%ld\n", serial);
    return EXECUTION_SUCCESS;
}

static int
cmd_search (WORD_LIST *args)
{
    const char *ring_s = "@s", *type, *desc;
    long ring, serial;

    if (!args || !args->next) {
        builtin_error ("search: [KEYRING] TYPE DESC");
        return EX_USAGE;
    }
    if (args->next->next) {
        ring_s = args->word->word;
        type = args->next->word->word;
        desc = args->next->next->word->word;
    } else {
        type = args->word->word;
        desc = args->next->word->word;
    }

    if (parse_keyring (ring_s, &ring) < 0) {
        builtin_error ("search: invalid keyring: %s", ring_s);
        return EX_USAGE;
    }

    serial = bk_keyctl (KEYCTL_SEARCH, (unsigned long) ring,
                        (unsigned long) type, (unsigned long) desc, 0);
    if (serial < 0) {
        builtin_error ("search: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    printf ("%ld\n", serial);
    return EXECUTION_SUCCESS;
}

static int
cmd_print (WORD_LIST *args)
{
    long serial, n;
    char *buf;

    if (!args || args->next) {
        builtin_error ("print: SERIAL");
        return EX_USAGE;
    }
    if (parse_long (args->word->word, &serial) < 0) {
        builtin_error ("print: invalid serial: %s", args->word->word);
        return EX_USAGE;
    }

    n = bk_keyctl (KEYCTL_READ, (unsigned long) serial, 0, 0, 0);
    if (n < 0) {
        builtin_error ("read: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    buf = malloc ((size_t)n ? (size_t)n : 1);
    if (!buf)
        return EXECUTION_FAILURE;
    n = bk_keyctl (KEYCTL_READ, (unsigned long) serial,
                   (unsigned long) buf, (unsigned long)n, 0);
    if (n < 0) {
        free (buf);
        builtin_error ("read: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (n > 0 && fwrite (buf, 1, (size_t)n, stdout) != (size_t)n) {
        free (buf);
        builtin_error ("write stdout: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    free (buf);
    return EXECUTION_SUCCESS;
}

static int
cmd_revoke (WORD_LIST *args)
{
    long serial;
    if (!args || args->next) {
        builtin_error ("revoke: SERIAL");
        return EX_USAGE;
    }
    if (parse_long (args->word->word, &serial) < 0) {
        builtin_error ("revoke: invalid serial: %s", args->word->word);
        return EX_USAGE;
    }
    if (bk_keyctl (KEYCTL_REVOKE, (unsigned long) serial, 0, 0, 0) < 0) {
        builtin_error ("revoke: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
cmd_clear (WORD_LIST *args)
{
    const char *ring_s = args ? args->word->word : "@s";
    long ring;
    if (args && args->next) {
        builtin_error ("clear: [KEYRING]");
        return EX_USAGE;
    }
    if (parse_keyring (ring_s, &ring) < 0) {
        builtin_error ("clear: invalid keyring: %s", ring_s);
        return EX_USAGE;
    }
    if (bk_keyctl (KEYCTL_CLEAR, (unsigned long) ring, 0, 0, 0) < 0) {
        builtin_error ("clear: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

int
keyctl_builtin (WORD_LIST *list)
{
    const char *verb;
    if (!list) {
        builtin_error ("usage: keyctl {session|add|search|print|revoke|clear} ...");
        return EX_USAGE;
    }
    verb = list->word->word;
    list = list->next;
    if (!strcmp (verb, "session")) return cmd_session (list);
    if (!strcmp (verb, "add")) return cmd_add (list);
    if (!strcmp (verb, "search")) return cmd_search (list);
    if (!strcmp (verb, "print")) return cmd_print (list);
    if (!strcmp (verb, "revoke")) return cmd_revoke (list);
    if (!strcmp (verb, "clear")) return cmd_clear (list);
    builtin_error ("unknown verb: %s", verb);
    return EX_USAGE;
}

char *keyctl_doc[] = {
    "Small Linux keyring syscall wrapper.",
    "Verbs: session, add, search, print, revoke, clear.",
    (char *) NULL
};

struct builtin keyctl_struct = {
    "keyctl",
    keyctl_builtin,
    BUILTIN_ENABLED,
    keyctl_doc,
    "keyctl {session|add|search|print|revoke|clear} ...",
    0
};
