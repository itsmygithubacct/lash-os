/* SPDX-License-Identifier: MIT */
/* crontab.c - crontab(1)-shaped user crontab manager for bash-os. */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "loadables.h"

static const char *
bct_spool_root (void)
{
    const char *s = getenv ("BASHCRON_SPOOL_DIR");
    return (s && *s) ? s : "/var/spool/cron";
}

static const char *
bct_user (void)
{
    const char *u = getenv ("USER");
    if (u && *u)
        return u;
    struct passwd *pw = getpwuid (getuid ());
    return (pw && pw->pw_name) ? pw->pw_name : "root";
}

static char *
bct_policy_trim (char *s)
{
    while (isspace ((unsigned char)*s))
        s++;
    char *e = s + strlen (s);
    while (e > s && isspace ((unsigned char)e[-1]))
        *--e = '\0';
    return s;
}

static int
bct_user_list_contains (const char *path, const char *user)
{
    FILE *f = fopen (path, "r");
    if (!f)
        return 0;
    char line[256];
    int found = 0;
    while (fgets (line, sizeof line, f)) {
        char *s = bct_policy_trim (line);
        if (*s == '\0' || *s == '#')
            continue;
        if (!strcmp (s, user)) {
            found = 1;
            break;
        }
    }
    fclose (f);
    return found;
}

static int
bct_user_allowed (const char *user)
{
    char path[PATH_MAX];
    if (!user || !*user || strchr (user, '/') || strstr (user, ".."))
        return 0;

    if (snprintf (path, sizeof path, "%s/cron.allow", bct_spool_root ()) >= (int) sizeof path)
        return 0;
    if (access (path, F_OK) == 0)
        return bct_user_list_contains (path, user);

    if (snprintf (path, sizeof path, "%s/cron.deny", bct_spool_root ()) >= (int) sizeof path)
        return 0;
    if (access (path, F_OK) == 0)
        return !bct_user_list_contains (path, user);

    return 1;
}

static int
bct_mkdir_p (const char *path)
{
    char tmp[PATH_MAX];
    size_t len = strlen (path);
    if (len == 0 || len >= sizeof tmp)
        return -1;
    memcpy (tmp, path, len + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir (tmp, 0700) < 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir (tmp, 0700) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int
bct_tabs_dir (char *buf, size_t buflen)
{
    if (snprintf (buf, buflen, "%s/tabs", bct_spool_root ()) >= (int) buflen)
        return -1;
    return bct_mkdir_p (buf);
}

static int
bct_user_path (char *buf, size_t buflen)
{
    const char *u = bct_user ();
    if (strchr (u, '/') || strstr (u, ".."))
        return -1;
    char dir[PATH_MAX];
    if (bct_tabs_dir (dir, sizeof dir) < 0)
        return -1;
    return snprintf (buf, buflen, "%s/%s", dir, u) < (int) buflen ? 0 : -1;
}

static int
bct_copy_file (const char *src, const char *dst)
{
    FILE *in = fopen (src, "r");
    if (!in) {
        builtin_error ("open %s: %s", src, strerror (errno));
        return EXECUTION_FAILURE;
    }
    char tmp[PATH_MAX];
    if (snprintf (tmp, sizeof tmp, "%s.tmp.%ld", dst, (long) getpid ()) >= (int) sizeof tmp) {
        fclose (in);
        return EXECUTION_FAILURE;
    }
    FILE *out = fopen (tmp, "w");
    if (!out) {
        fclose (in);
        builtin_error ("create crontab: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    chmod (tmp, 0600);
    char buf[4096];
    size_t n;
    while ((n = fread (buf, 1, sizeof buf, in)) > 0) {
        if (fwrite (buf, 1, n, out) != n) {
            fclose (in);
            fclose (out);
            unlink (tmp);
            return EXECUTION_FAILURE;
        }
    }
    int input_error = ferror (in);
    int output_error = fclose (out) != 0;
    if (input_error || output_error) {
        fclose (in);
        unlink (tmp);
        return EXECUTION_FAILURE;
    }
    fclose (in);
    if (rename (tmp, dst) < 0) {
        unlink (tmp);
        builtin_error ("install crontab: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bct_cat (const char *path)
{
    FILE *f = fopen (path, "r");
    if (!f) {
        builtin_error ("no crontab for %s", bct_user ());
        return EXECUTION_FAILURE;
    }
    char buf[4096];
    size_t n;
    while ((n = fread (buf, 1, sizeof buf, f)) > 0)
        fwrite (buf, 1, n, stdout);
    int bad = ferror (f);
    fclose (f);
    return bad ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bct_edit (const char *path)
{
    const char *ed = getenv ("VISUAL");
    if (!ed || !*ed)
        ed = getenv ("EDITOR");
    if (!ed || !*ed)
        ed = "vi";

    char tmp[PATH_MAX];
    if (snprintf (tmp, sizeof tmp, "%s.edit.%ld", path, (long) getpid ()) >= (int) sizeof tmp)
        return EXECUTION_FAILURE;
    FILE *out = fopen (tmp, "w");
    if (!out) {
        builtin_error ("create temp crontab: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    chmod (tmp, 0600);
    FILE *in = fopen (path, "r");
    if (in) {
        char buf[4096];
        size_t n;
        while ((n = fread (buf, 1, sizeof buf, in)) > 0)
            fwrite (buf, 1, n, out);
        fclose (in);
    }
    fclose (out);

    struct sigaction chld_dfl, chld_save;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &chld_save);

    sigset_t chld_set, prev_mask;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld_set, &prev_mask);

    pid_t pid = fork ();
    if (pid < 0) {
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        sigaction (SIGCHLD, &chld_save, NULL);
        unlink (tmp);
        return EXECUTION_FAILURE;
    }
    if (pid == 0) {
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        execlp (ed, ed, tmp, (char *) NULL);
        _exit (127);
    }
    int st;
    pid_t w;
    while ((w = waitpid (pid, &st, 0)) < 0 && errno == EINTR) ;
    if (w < 0 || !WIFEXITED (st) || WEXITSTATUS (st) != 0) {
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        sigaction (SIGCHLD, &chld_save, NULL);
        unlink (tmp);
        builtin_error ("editor failed");
        return EXECUTION_FAILURE;
    }
    sigprocmask (SIG_SETMASK, &prev_mask, NULL);
    sigaction (SIGCHLD, &chld_save, NULL);
    if (rename (tmp, path) < 0) {
        unlink (tmp);
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

int
crontab_builtin (WORD_LIST *list)
{
    char path[PATH_MAX];
    const char *user = bct_user ();
    if (bct_user_path (path, sizeof path) < 0) {
        builtin_error ("invalid crontab path");
        return EXECUTION_FAILURE;
    }
    if (!list) {
        builtin_error ("usage: crontab FILE | -l | -e | -r");
        return EX_USAGE;
    }
    const char *arg = list->word->word;
    if (!strcmp (arg, "--help") || !strcmp (arg, "-h")) {
        extern char *crontab_doc[];
        char *const *dp;
        for (dp = crontab_doc; *dp; dp++)
            puts (*dp);
        return EX_USAGE;
    }
    if (list->next) {
        builtin_error ("unexpected extra argument");
        return EX_USAGE;
    }
    if (!bct_user_allowed (user)) {
        builtin_error ("user %s is not allowed to use crontab", user);
        return EXECUTION_FAILURE;
    }
    if (!strcmp (arg, "-l"))
        return bct_cat (path);
    if (!strcmp (arg, "-r")) {
        if (unlink (path) < 0 && errno != ENOENT) {
            builtin_error ("remove crontab: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (arg, "-e"))
        return bct_edit (path);
    if (arg[0] == '-') {
        builtin_error ("unknown option: %s", arg);
        return EX_USAGE;
    }
    return bct_copy_file (arg, path);
}

char *crontab_doc[] = {
    "Install, list, edit, or remove a user crontab.",
    "",
    "    crontab FILE",
    "    crontab -l",
    "    crontab -e",
    "    crontab -r",
    "",
    "Crontabs live under ${BASHCRON_SPOOL_DIR:-/var/spool/cron}/tabs.",
    (char *)NULL
};

struct builtin crontab_struct = {
    "crontab",
    crontab_builtin,
    BUILTIN_ENABLED,
    crontab_doc,
    "crontab FILE | -l | -e | -r",
    0
};
