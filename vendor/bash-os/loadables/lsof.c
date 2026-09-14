/* SPDX-License-Identifier: MIT */
/* lsof.c — list open file descriptors via /proc/PID/fd.
 *
 *   lsof [-p PID] [-u USER] [PID...]
 *
 *   -p PID    restrict to one PID (repeatable)
 *   -u USER   restrict to processes owned by USER (name or uid)
 *   PID...    bare PIDs are equivalent to -p PID PID...
 *
 * Output (POSIX-ish columns):
 *   COMMAND   PID    USER  FD  TYPE  PATH
 *
 * TYPE column heuristics:
 *   REG       regular file
 *   DIR       directory
 *   CHR/BLK   char / block device
 *   FIFO      named pipe
 *   SOCK      socket (stat shows sockfs)
 *   sock      anonymous (`socket:[N]`)
 *   pipe      anonymous pipe
 *   IPv4/IPv6 inferred from `socket:[N]` + /proc/net/{tcp,udp} match (skipped at v1)
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
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
#include <dirent.h>
#include <pwd.h>
#include <sys/stat.h>

#include "loadables.h"

static const char *
bl_user_for_pid (int pid)
{
    static char buf[64];
    char path[64];
    snprintf (path, sizeof path, "/proc/%d/status", pid);
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "?";
    char raw[1024];
    ssize_t n = read (fd, raw, sizeof raw - 1);
    close (fd);
    if (n <= 0) return "?";
    raw[n] = '\0';
    char *u = strstr (raw, "\nUid:");
    if (!u) return "?";
    long uid_val = -1;
    sscanf (u, "\nUid:\t%ld", &uid_val);
    if (uid_val < 0) return "?";
    struct passwd *pw = getpwuid ((uid_t) uid_val);
    if (pw) {
        snprintf (buf, sizeof buf, "%s", pw->pw_name);
    } else {
        snprintf (buf, sizeof buf, "%ld", uid_val);
    }
    return buf;
}

static const char *
bl_comm_for_pid (int pid)
{
    static char comm[64];
    char path[64];
    snprintf (path, sizeof path, "/proc/%d/comm", pid);
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "?";
    ssize_t n = read (fd, comm, sizeof comm - 1);
    close (fd);
    if (n <= 0) return "?";
    comm[n] = '\0';
    if (n > 0 && comm[n - 1] == '\n') comm[n - 1] = '\0';
    return comm;
}

static const char *
bl_classify (const char *target, const struct stat *st)
{
    if (target[0] != '/') {
        /* Anonymous: socket:[N], pipe:[N], anon_inode:[N], ... */
        if (!strncmp (target, "socket:", 7)) return "sock";
        if (!strncmp (target, "pipe:",   5)) return "pipe";
        if (!strncmp (target, "anon_inode:", 11)) return "anon";
        return "OTHER";
    }
    if (S_ISREG (st->st_mode))  return "REG";
    if (S_ISDIR (st->st_mode))  return "DIR";
    if (S_ISCHR (st->st_mode))  return "CHR";
    if (S_ISBLK (st->st_mode))  return "BLK";
    if (S_ISFIFO (st->st_mode)) return "FIFO";
    if (S_ISSOCK (st->st_mode)) return "SOCK";
    if (S_ISLNK (st->st_mode))  return "LNK";
    return "OTHER";
}

static int
bl_dump_pid (int pid, const char *want_user)
{
    const char *user = bl_user_for_pid (pid);
    if (want_user && strcmp (want_user, user) != 0) return 0;
    const char *comm = bl_comm_for_pid (pid);

    char fdpath[64];
    snprintf (fdpath, sizeof fdpath, "/proc/%d/fd", pid);
    DIR *d = opendir (fdpath);
    if (!d) return 0;   /* Permission denied is normal for other-user PIDs. */
    struct dirent *de;
    while ((de = readdir (d))) {
        if (de->d_name[0] == '.') continue;
        char linkbuf[1024];
        char fullpath[128];
        snprintf (fullpath, sizeof fullpath, "/proc/%d/fd/%s", pid, de->d_name);
        ssize_t n = readlink (fullpath, linkbuf, sizeof linkbuf - 1);
        if (n < 0) continue;
        linkbuf[n] = '\0';
        struct stat st;
        if (stat (fullpath, &st) < 0) memset (&st, 0, sizeof st);
        const char *type = bl_classify (linkbuf, &st);
        printf ("%-12s %5d %-8s %3s %-5s %s\n",
                comm, pid, user, de->d_name, type, linkbuf);
    }
    closedir (d);
    return 0;
}

static int
bl_resolve_user (const char *s, char *out, size_t cap)
{
    char *end;
    long n = strtol (s, &end, 10);
    if (*end == '\0') {
        struct passwd *pw = getpwuid ((uid_t) n);
        if (pw) snprintf (out, cap, "%s", pw->pw_name);
        else    snprintf (out, cap, "%ld", n);
    } else {
        snprintf (out, cap, "%s", s);
    }
    return 0;
}

int
lsof_builtin (WORD_LIST *list)
{
    int explicit_pids[256];
    int n_pids = 0;
    char want_user[64] = "";

    while (list) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version") || !strcmp (w, "-v")) {
            puts ("lsof 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-p")) {
            if (!list->next) {
                builtin_error ("-p needs PID");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            if (n_pids >= (int) (sizeof explicit_pids / sizeof explicit_pids[0])) {
                builtin_error ("too many -p PIDs");
                builtin_usage ();
                return EX_USAGE;
            }
            explicit_pids[n_pids++] = atoi (list->word->word);
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-u")) {
            if (!list->next) {
                builtin_error ("-u needs USER");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            bl_resolve_user (list->word->word, want_user, sizeof want_user);
            list = list->next;
            continue;
        }
        if (w[0] >= '0' && w[0] <= '9') {
            if (n_pids >= (int) (sizeof explicit_pids / sizeof explicit_pids[0])) {
                builtin_error ("too many PIDs");
                builtin_usage ();
                return EX_USAGE;
            }
            explicit_pids[n_pids++] = atoi (w);
            list = list->next;
            continue;
        }
        builtin_error ("unknown arg: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    printf ("%-12s %5s %-8s %3s %-5s %s\n",
            "COMMAND", "PID", "USER", "FD", "TYPE", "PATH");

    if (n_pids > 0) {
        for (int i = 0; i < n_pids; i++) {
            bl_dump_pid (explicit_pids[i], want_user[0] ? want_user : NULL);
        }
        return EXECUTION_SUCCESS;
    }
    DIR *d = opendir ("/proc");
    if (!d) { builtin_error ("opendir /proc: %s", strerror (errno)); return EXECUTION_FAILURE; }
    struct dirent *de;
    while ((de = readdir (d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        int pid = atoi (de->d_name);
        if (pid <= 0) continue;
        bl_dump_pid (pid, want_user[0] ? want_user : NULL);
    }
    closedir (d);
    return EXECUTION_SUCCESS;
}

char *lsof_doc[] = {
    "List open file descriptors via /proc/PID/fd.",
    "",
    "    lsof [-p PID]... [-u USER] [PID...]",
    "",
    "    -p PID    restrict to one PID (repeatable)",
    "    -u USER   restrict to one user (name or uid)",
    "    PID...    bare numeric PIDs equivalent to -p PID PID...",
    "    --help    print usage information and exit",
    "    -v, --version",
    "              print version information and exit",
    "",
    "Output columns: COMMAND PID USER FD TYPE PATH.",
    "TYPE: REG / DIR / CHR / BLK / FIFO / SOCK / LNK for fs entries;",
    "sock / pipe / anon for kernel anonymous fds.",
    (char *)NULL
};

struct builtin lsof_struct = {
    "lsof",
    lsof_builtin,
    BUILTIN_ENABLED,
    lsof_doc,
    "lsof [-p PID]... [-u USER] [PID...]",
    0
};
