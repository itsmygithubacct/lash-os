/* SPDX-License-Identifier: MIT */
/* cron.c - minimal cron/at daemon loop for bash-os.
 *
 *   cron run [--once] [--interval SEC]
 *   cron next [--from EPOCH] MIN HOUR DOM MONTH DOW
 *
 * Polls ${BASHCRON_SPOOL_DIR:-/var/spool/cron}/atjobs and /tabs plus
 * ${BASHCRON_ETC_DIR:-/etc}/crontab and
 * ${BASHCRON_CROND_DIR:-/etc/cron.d}.
 * Per-user crontabs are "min hour dom mon dow command"; system crontabs are
 * "min hour dom mon dow user command".
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

#include "loadables.h"

static volatile sig_atomic_t bc_stop;
static volatile sig_atomic_t bc_reload;

#define BC_SMALL_MISSED_MINUTES 5

static void
bc_on_signal (int sig)
{
    (void) sig;
    bc_stop = 1;
}

static void
bc_on_reload (int sig)
{
    (void) sig;
    bc_reload = 1;
}

static const char *
bc_spool_root (void)
{
    const char *s = getenv ("BASHCRON_SPOOL_DIR");
    return (s && *s) ? s : "/var/spool/cron";
}

static const char *
bc_etc_crontab_path (void)
{
    static char path[PATH_MAX];
    const char *s = getenv ("BASHCRON_ETC_DIR");
    const char *dir = (s && *s) ? s : "/etc";
    if (snprintf (path, sizeof path, "%s/crontab", dir) >= (int) sizeof path)
        return "";
    return path;
}

static const char *
bc_crond_dir (void)
{
    const char *s = getenv ("BASHCRON_CROND_DIR");
    return (s && *s) ? s : "/etc/cron.d";
}

static const char *
bc_output_dir (void)
{
    const char *s = getenv ("BASHCRON_OUTPUT_DIR");
    return (s && *s) ? s : "/var/spool/cron/out";
}

static const char *
bc_mail_dir (void)
{
    const char *s = getenv ("BASHCRON_MAIL_DIR");
    return (s && *s) ? s : "/var/spool/mail";
}

/* Operator-tunable replay/catch-up window. Default preserves the prior
   hard-coded 5-minute policy; values outside (0, 1440] fall back to the
   default. The 1440-minute (24h) ceiling is a deliberate sanity cap. */
static int
bc_catchup_max_minutes (void)
{
    const char *s = getenv ("BASHCRON_CATCHUP_MAX_MIN");
    if (s && *s) {
        char *end;
        long v = strtol (s, &end, 10);
        if (end != s && *end == '\0' && v > 0 && v <= 1440)
            return (int) v;
    }
    return BC_SMALL_MISSED_MINUTES;
}

static time_t
bc_parse_epoch_value (const char *s, int *ok)
{
    char *end;
    long long v;

    if (ok)
        *ok = 0;
    if (!s || !*s)
        return (time_t) 0;
    errno = 0;
    v = strtoll (s, &end, 10);
    while (end && isspace ((unsigned char)*end))
        end++;
    if (end == s || (end && *end != '\0') || errno == ERANGE || v < 0)
        return (time_t) 0;
    if (ok)
        *ok = 1;
    return (time_t) v;
}

static time_t
bc_now (void)
{
    const char *epoch = getenv ("BASHCRON_NOW_EPOCH");
    const char *path = getenv ("BASHCRON_NOW_FILE");
    static FILE *test_now;
    static char opened[PATH_MAX];
    static time_t last_test_now;
    int ok;

    if (epoch && *epoch) {
        time_t injected = bc_parse_epoch_value (epoch, &ok);
        if (ok)
            return injected;
    }

    if (!path || !*path)
        path = getenv ("BASHCRON_TEST_NOW_FILE");

    if (path && *path) {
        if (!test_now || strcmp (opened, path) != 0) {
            if (test_now)
                fclose (test_now);
            test_now = fopen (path, "r");
            if (test_now)
                (void) snprintf (opened, sizeof opened, "%s", path);
            else
                opened[0] = '\0';
            last_test_now = 0;
        }
        if (test_now) {
            char line[64];
            if (fgets (line, sizeof line, test_now)) {
                time_t injected = bc_parse_epoch_value (line, &ok);
                if (ok) {
                    last_test_now = injected;
                    return last_test_now;
                }
            }
            if (last_test_now != 0)
                return last_test_now;
        }
    }

    return time (NULL);
}

/* Operator-supplied state file for last_cron_minute persistence across
   daemon restarts. No default: when unset, bc_state_load / bc_state_save
   are no-ops and behavior is byte-identical to the pre-2026-05-19 daemon.
   When set, the daemon writes the most recently evaluated cron-minute on
   every poll and reads it on startup so a restart that lands within
   bc_catchup_max_minutes() of the prior minute replays the gap. */
static const char *
bc_state_file_path (void)
{
    const char *s = getenv ("BASHCRON_STATE_FILE");
    return (s && *s) ? s : NULL;
}

/* Returns 0 + writes *out on success, -1 if state file absent/unparseable. */
static int
bc_state_load (time_t *out)
{
    const char *path = bc_state_file_path ();
    if (!path || !out)
        return -1;
    FILE *fp = fopen (path, "r");
    if (!fp)
        return -1;
    char line[64];
    int ok = 0;
    if (fgets (line, sizeof line, fp)) {
        char *end;
        long long v = strtoll (line, &end, 10);
        if (end != line && v >= 0) {
            *out = (time_t) v;
            ok = 1;
        }
    }
    fclose (fp);
    return ok ? 0 : -1;
}

/* Atomic write: <path>.tmp -> rename(). 0600 perms match the crontab
   safety contract. Silent best-effort; bc_state_save never aborts the
   poll loop on persistence failure. */
static void
bc_state_save (time_t v)
{
    const char *path = bc_state_file_path ();
    if (!path)
        return;
    char tmp[PATH_MAX];
    if (snprintf (tmp, sizeof tmp, "%s.tmp", path) >= (int) sizeof tmp)
        return;
    int fd = open (tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return;
    char buf[64];
    int n = snprintf (buf, sizeof buf, "%lld\n", (long long) v);
    if (n > 0 && (int) write (fd, buf, (size_t) n) == n) {
        close (fd);
        if (rename (tmp, path) != 0)
            unlink (tmp);
    } else {
        close (fd);
        unlink (tmp);
    }
}

static char *
bc_policy_trim (char *s)
{
    while (isspace ((unsigned char)*s))
        s++;
    char *e = s + strlen (s);
    while (e > s && isspace ((unsigned char)e[-1]))
        *--e = '\0';
    return s;
}

static int
bc_user_list_contains (const char *path, const char *user)
{
    FILE *f = fopen (path, "r");
    if (!f)
        return 0;
    char line[256];
    int found = 0;
    while (fgets (line, sizeof line, f)) {
        char *s = bc_policy_trim (line);
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
bc_user_allowed (const char *user)
{
    char path[PATH_MAX];
    if (!user || !*user || strchr (user, '/') || strstr (user, ".."))
        return 0;

    if (snprintf (path, sizeof path, "%s/cron.allow", bc_spool_root ()) >= (int) sizeof path)
        return 0;
    if (access (path, F_OK) == 0)
        return bc_user_list_contains (path, user);

    if (snprintf (path, sizeof path, "%s/cron.deny", bc_spool_root ()) >= (int) sizeof path)
        return 0;
    if (access (path, F_OK) == 0)
        return !bc_user_list_contains (path, user);

    return 1;
}

static int
bc_crontab_secure (const char *path)
{
    struct stat st;
    if (stat (path, &st) < 0)
        return 0;
    if (!S_ISREG (st.st_mode))
        return 0;
    if ((st.st_mode & S_IRUSR) == 0)
        return 0;
    if ((st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH | S_IWGRP | S_IWOTH)) != 0)
        return 0;
    return 1;
}

static int
bc_mkdir_p (const char *path)
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
bc_child_status (int st)
{
    if (WIFEXITED (st))
        return WEXITSTATUS (st);
    if (WIFSIGNALED (st))
        return 128 + WTERMSIG (st);
    return 1;
}

static int
bc_wait_child (pid_t pid)
{
    int st;
    while (waitpid (pid, &st, 0) < 0) {
        if (errno == EINTR)
            continue;
        return 1;
    }
    return bc_child_status (st);
}

struct bc_child_guard {
    struct sigaction old_action;
    sigset_t old_mask;
};

static void
bc_child_guard_begin (struct bc_child_guard *g)
{
    struct sigaction chld_dfl;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &g->old_action);

    sigset_t chld_set;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld_set, &g->old_mask);
}

static void
bc_child_guard_parent_end (struct bc_child_guard *g)
{
    sigprocmask (SIG_SETMASK, &g->old_mask, NULL);
    sigaction (SIGCHLD, &g->old_action, NULL);
}

static void
bc_child_guard_child_end (struct bc_child_guard *g)
{
    sigprocmask (SIG_SETMASK, &g->old_mask, NULL);
}

static void
bc_run_script_file (const char *path)
{
    struct bc_child_guard guard;
    bc_child_guard_begin (&guard);
    pid_t pid = fork ();
    if (pid < 0) {
        bc_child_guard_parent_end (&guard);
        return;
    }
    if (pid == 0) {
        bc_child_guard_child_end (&guard);
        signal (SIGHUP, SIG_DFL);
        signal (SIGTERM, SIG_DFL);
        signal (SIGINT, SIG_DFL);
        execl ("/bin/bash", "bash", path, (char *) NULL);
        execlp ("bash", "bash", path, (char *) NULL);
        _exit (127);
    }
    (void) bc_wait_child (pid);
    bc_child_guard_parent_end (&guard);
}

struct bc_file_env {
    char path[1024];
    char shell[128];
    char mailto[128];
    int mailto_set;
};

static int
bc_write_all_fd (int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write (fd, buf, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        buf += n;
        len -= (size_t) n;
    }
    return 0;
}

static int
bc_recipient_safe (const char *s)
{
    if (!s || !*s || strchr (s, '/') || strstr (s, ".."))
        return 0;
    for (const unsigned char *p = (const unsigned char *) s; *p; p++) {
        if (!(isalnum (*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    }
    return 1;
}

static int
bc_open_job_tmpfile (char *path, size_t pathsz)
{
    const char *dir = bc_output_dir ();
    if (bc_mkdir_p (dir) < 0)
        return -1;
    if (snprintf (path, pathsz, "%s/job.XXXXXX", dir) >= (int) pathsz)
        return -1;
    int fd = mkstemp (path);
    if (fd < 0)
        return -1;
    (void) fchmod (fd, 0600);
    int flags = fcntl (fd, F_GETFD);
    if (flags >= 0)
        (void) fcntl (fd, F_SETFD, flags | FD_CLOEXEC);
    return fd;
}

static void
bc_sweep_output_dir (void)
{
    const char *dir = bc_output_dir ();
    DIR *d = opendir (dir);
    if (!d)
        return;
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        if (strncmp (de->d_name, "job.", 4) != 0)
            continue;
        if (strchr (de->d_name, '/'))
            continue;
        char path[PATH_MAX];
        if (snprintf (path, sizeof path, "%s/%s", dir, de->d_name) >= (int) sizeof path)
            continue;
        struct stat st;
        if (lstat (path, &st) == 0 && S_ISREG (st.st_mode))
            unlink (path);
    }
    closedir (d);
}

static void
bc_prepare_output_dir (void)
{
    if (bc_mkdir_p (bc_output_dir ()) == 0)
        bc_sweep_output_dir ();
}

static void
bc_subject_command (const char *cmd, char *out, size_t outsz)
{
    size_t i = 0;
    if (outsz == 0)
        return;
    for (; cmd && *cmd && i + 1 < outsz && i < 80; cmd++) {
        unsigned char c = (unsigned char) *cmd;
        out[i++] = (c == '\n' || c == '\r') ? ' ' : (char) c;
    }
    out[i] = '\0';
}

static void
bc_deliver_job_output (const char *user, const char *cmd,
                       const struct bc_file_env *env,
                       int tmpfd, const char *tmppath)
{
    struct stat st;
    if (tmpfd < 0 || fstat (tmpfd, &st) < 0 || st.st_size <= 0)
        goto out;

    const char *recipient = user;
    if (env && env->mailto_set) {
        if (env->mailto[0] == '\0')
            goto out;               /* MAILTO="" suppresses delivery. */
        recipient = env->mailto;
    }
    if (!bc_recipient_safe (recipient))
        goto out;

    struct passwd *pw = getpwnam (recipient);
    if (!pw)
        goto out;

    const char *maildir = bc_mail_dir ();
    if (bc_mkdir_p (maildir) < 0)
        goto out;
    char inbox[PATH_MAX];
    if (snprintf (inbox, sizeof inbox, "%s/%s", maildir, recipient) >= (int) sizeof inbox)
        goto out;

    int mfd = open (inbox, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0600);
    if (mfd < 0)
        goto out;
    (void) fchmod (mfd, 0600);
    (void) fchown (mfd, pw->pw_uid, pw->pw_gid);
    (void) flock (mfd, LOCK_EX);

    char host[128];
    if (gethostname (host, sizeof host) != 0 || host[0] == '\0')
        snprintf (host, sizeof host, "localhost");
    host[sizeof host - 1] = '\0';

    time_t now = time (NULL);
    char datebuf[64];
    struct tm tm;
    localtime_r (&now, &tm);
    if (strftime (datebuf, sizeof datebuf, "%a %b %e %H:%M:%S %Y", &tm) == 0)
        snprintf (datebuf, sizeof datebuf, "%lld", (long long) now);

    char subj_cmd[96];
    bc_subject_command (cmd, subj_cmd, sizeof subj_cmd);

    char hdr[512];
    int hn = snprintf (hdr, sizeof hdr,
                       "From cron@%s %s\n"
                       "From: cron@%s\n"
                       "To: %s\n"
                       "Subject: Cron <%s@%s> %s\n"
                       "\n",
                       host, datebuf, host, recipient,
                       (user && *user) ? user : "unknown", host, subj_cmd);
    if (hn > 0 && hn < (int) sizeof hdr)
        (void) bc_write_all_fd (mfd, hdr, (size_t) hn);

    if (lseek (tmpfd, 0, SEEK_SET) == 0) {
        char buf[4096];
        ssize_t n;
        while ((n = read (tmpfd, buf, sizeof buf)) > 0)
            if (bc_write_all_fd (mfd, buf, (size_t) n) < 0)
                break;
    }
    (void) bc_write_all_fd (mfd, "\n\n", 2);
    (void) flock (mfd, LOCK_UN);
    close (mfd);

out:
    if (tmpfd >= 0)
        close (tmpfd);
    if (tmppath && *tmppath)
        unlink (tmppath);
}

static size_t
bc_shell_quote_append (char *dst, size_t cap, size_t pos, const char *s)
{
    if (pos + 1 >= cap)
        return cap;
    dst[pos++] = '\'';
    for (; *s && pos + 4 < cap; s++) {
        if (*s == '\'') {
            dst[pos++] = '\'';
            dst[pos++] = '\\';
            dst[pos++] = '\'';
            dst[pos++] = '\'';
        } else {
            dst[pos++] = *s;
        }
    }
    if (pos + 1 >= cap)
        return cap;
    dst[pos++] = '\'';
    dst[pos] = '\0';
    return pos;
}

static size_t
bc_env_assignment_append (char *dst, size_t cap, size_t pos,
                          const char *name, const char *value)
{
    if (!name || !*name || !value || !*value)
        return pos;
    if (pos >= cap)
        return cap;
    int n = snprintf (dst + pos, cap - pos, "%s=", name);
    if (n < 0 || n >= (int)(cap - pos))
        return cap;
    pos += (size_t) n;
    pos = bc_shell_quote_append (dst, cap, pos, value);
    if (pos >= cap)
        return cap;
    n = snprintf (dst + pos, cap - pos, "; export %s; ", name);
    if (n < 0 || n >= (int)(cap - pos))
        return cap;
    return pos + (size_t) n;
}

static const char *
bc_wrap_command_env (const char *cmd, const char *user, const char *home,
                     const char *shell, const char *path,
                     char *buf, size_t buflen)
{
    size_t pos = 0;

    buf[0] = '\0';
    pos = bc_env_assignment_append (buf, buflen, pos, "USER", user);
    pos = bc_env_assignment_append (buf, buflen, pos, "LOGNAME", user);
    pos = bc_env_assignment_append (buf, buflen, pos, "HOME", home);
    pos = bc_env_assignment_append (buf, buflen, pos, "PATH", path);
    pos = bc_env_assignment_append (buf, buflen, pos, "SHELL", shell);
    if (pos >= buflen)
        return cmd;
    if (snprintf (buf + pos, buflen - pos, "%s", cmd) >= (int)(buflen - pos))
        return cmd;
    return buf;
}

static int
bc_drop_to_user (const char *user, struct passwd **out_pw)
{
    struct passwd *pw = NULL;
    if (out_pw)
        *out_pw = NULL;

    if (user && *user)
        pw = getpwnam (user);
    if (out_pw)
        *out_pw = pw;

    if (geteuid () != 0)
        return 0;

    if (!pw)
        return -1;
    if (pw->pw_uid == 0)
        return 0;

    if (setgid (pw->pw_gid) != 0)
        return -1;
    if (initgroups (pw->pw_name, pw->pw_gid) != 0)
        return -1;
    if (setuid (pw->pw_uid) != 0)
        return -1;
    return 0;
}

static void
bc_run_command (const char *user, const char *cmd, const struct bc_file_env *env)
{
    char tmppath[PATH_MAX] = "";
    int tmpfd = bc_open_job_tmpfile (tmppath, sizeof tmppath);
    struct bc_child_guard guard;
    bc_child_guard_begin (&guard);
    pid_t pid = fork ();
    if (pid < 0) {
        bc_child_guard_parent_end (&guard);
        if (tmpfd >= 0) {
            close (tmpfd);
            unlink (tmppath);
        }
        return;
    }
    if (pid == 0) {
        bc_child_guard_child_end (&guard);
        if (tmpfd >= 0) {
            (void) dup2 (tmpfd, STDOUT_FILENO);
            (void) dup2 (tmpfd, STDERR_FILENO);
            if (tmpfd > STDERR_FILENO)
                close (tmpfd);
        }
        signal (SIGHUP, SIG_DFL);
        signal (SIGTERM, SIG_DFL);
        signal (SIGINT, SIG_DFL);

        struct passwd *pw = NULL;
        if (bc_drop_to_user (user, &pw) != 0)
            _exit (127);

        if (user && *user) {
            setenv ("USER", user, 1);
            setenv ("LOGNAME", user, 1);
        }
        if (pw && pw->pw_dir && *pw->pw_dir)
            setenv ("HOME", pw->pw_dir, 1);

        const char *shell = (env && env->shell[0]) ? env->shell :
                            (pw && pw->pw_shell && *pw->pw_shell) ? pw->pw_shell :
                            "/bin/bash";
        const char *path = (env && env->path[0]) ? env->path : "/usr/bin:/bin";
        const char *home = (pw && pw->pw_dir && *pw->pw_dir) ? pw->pw_dir :
                           getenv ("HOME");
        setenv ("PATH", path, 1);
        setenv ("SHELL", shell, 1);
        const char *shell_name = strrchr (shell, '/');
        shell_name = shell_name ? shell_name + 1 : shell;
        char wrapped[8192];
        const char *run_cmd = bc_wrap_command_env (cmd, user, home, shell, path,
                                                   wrapped, sizeof wrapped);
        execl (shell, shell_name, "-c", run_cmd, (char *) NULL);
        execlp (shell_name, shell_name, "-c", run_cmd, (char *) NULL);
        execl ("/bin/bash", "bash", "-c", run_cmd, (char *) NULL);
        execlp ("bash", "bash", "-c", run_cmd, (char *) NULL);
        _exit (127);
    }
    (void) bc_wait_child (pid);
    bc_child_guard_parent_end (&guard);
    bc_deliver_job_output (user, cmd, env, tmpfd, tmppath);
}

static void
bc_env_init (struct bc_file_env *e)
{
    e->path[0] = e->shell[0] = e->mailto[0] = '\0';
    e->mailto_set = 0;
}

static void
bc_env_copy_value (char *dst, size_t dstsz, const char *src)
{
    if (!src) {
        if (dstsz)
            dst[0] = '\0';
        return;
    }
    size_t len = strlen (src);
    if (len >= 2 && ((src[0] == '"' && src[len - 1] == '"') ||
                     (src[0] == '\'' && src[len - 1] == '\''))) {
        len -= 2;
        if (len >= dstsz)
            len = dstsz ? dstsz - 1 : 0;
        if (dstsz) {
            memcpy (dst, src + 1, len);
            dst[len] = '\0';
        }
    } else {
        (void) snprintf (dst, dstsz, "%s", src);
    }
}

/* Parse a KEY=VALUE crontab environment line.  Returns 1 if consumed. */
static int
bc_parse_env_line (char *s, struct bc_file_env *e)
{
    if (strncmp (s, "PATH=", 5) == 0) {
        bc_env_copy_value (e->path, sizeof e->path, s + 5);
        return 1;
    }
    if (strncmp (s, "SHELL=", 6) == 0) {
        bc_env_copy_value (e->shell, sizeof e->shell, s + 6);
        return 1;
    }
    if (strncmp (s, "MAILTO=", 7) == 0) {
        bc_env_copy_value (e->mailto, sizeof e->mailto, s + 7);
        e->mailto_set = 1;
        return 1;
    }
    return 0;
}

static int
bc_strcmp_cb (const void *a, const void *b)
{
    return strcmp (*(const char *const *) a, *(const char *const *) b);
}

static void
bc_poll_atjobs (time_t now)
{
    char dir[PATH_MAX];
    if (snprintf (dir, sizeof dir, "%s/atjobs", bc_spool_root ()) >= (int) sizeof dir ||
        bc_mkdir_p (dir) < 0)
        return;
    DIR *d = opendir (dir);
    if (!d)
        return;
    /* Collect job filenames first, then sort lexicographically so the
       processing order matches submission order. batch uses jobids
       of the shape <sec>.<pid>.<seq>; lexicographic sort = submission
       order, satisfying the FIFO guarantee documented in batch's
       help text. Pre-2026-05-18 implementation walked readdir() order
       and was filesystem-dependent. */
    char **names = NULL;
    size_t n_names = 0, cap_names = 0;
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        size_t nlen = strlen (de->d_name);
        if (de->d_name[0] == '.' || nlen < 5 ||
            strcmp (de->d_name + nlen - 4, ".job") != 0)
            continue;
        if (n_names == cap_names) {
            size_t new_cap = cap_names ? cap_names * 2 : 16;
            char **grown = realloc (names, new_cap * sizeof *names);
            if (!grown) break;
            names = grown;
            cap_names = new_cap;
        }
        names[n_names] = strdup (de->d_name);
        if (!names[n_names]) break;
        n_names++;
    }
    closedir (d);
    if (n_names > 1)
        qsort (names, n_names, sizeof *names, bc_strcmp_cb);
    for (size_t i = 0; i < n_names; i++) {
        char path[PATH_MAX], runpath[PATH_MAX];
        if (snprintf (path, sizeof path, "%s/%s", dir, names[i]) >= (int) sizeof path) {
            free (names[i]);
            continue;
        }
        FILE *f = fopen (path, "r");
        if (!f) { free (names[i]); continue; }
        long long run_at = 0;
        char line[256];
        if (fgets (line, sizeof line, f) &&
            sscanf (line, "# run_at=%lld", &run_at) == 1 &&
            (time_t) run_at <= now) {
            fclose (f);
            if (snprintf (runpath, sizeof runpath, "%s.running.%ld", path, (long) getpid ()) >= (int) sizeof runpath) {
                free (names[i]);
                continue;
            }
            if (rename (path, runpath) == 0) {
                bc_run_script_file (runpath);
                unlink (runpath);
            }
        } else {
            fclose (f);
        }
        free (names[i]);
    }
    free (names);
}

/* Compare first 3 chars case-insensitively (for month/DOW names). */
static int
bc_namematch (const char *s, const char *name)
{
    if (!s || !name) return 0;
    for (int i = 0; i < 3; i++) {
        if (tolower ((unsigned char)s[i]) != tolower ((unsigned char)name[i]))
            return 0;
        if (s[i] == '\0') return 0;
    }
    return 1;
}

/* Convert 3-letter month abbreviation to 1-12, or -1. */
static int
bc_month_val (const char *s)
{
    static const char *months[] =
        {"jan","feb","mar","apr","may","jun",
         "jul","aug","sep","oct","nov","dec"};
    for (int i = 0; i < 12; i++)
        if (bc_namematch (s, months[i]))
            return i + 1;
    return -1;
}

/* Convert 3-letter weekday abbreviation to 0-6, or -1. */
static int
bc_dow_val (const char *s)
{
    static const char *days[] =
        {"sun","mon","tue","wed","thu","fri","sat"};
    for (int i = 0; i < 7; i++)
        if (bc_namematch (s, days[i]))
            return i;
    return -1;
}

/* Match a crontab field against a single value.
 *
 * idx identifies the field (0=minute, 1=hour, 2=dom, 3=month, 4=dow)
 * and controls month/DOW name resolution and the implicit star/S base.
 *
 * Supports: *, N, N,M,O, N-M, N-M/S, star/S.  Month and DOW names
 * are recognized in fields 3 and 4 (JAN-DEC, SUN-SAT).
 */
static int
bc_field_match (const char *field, int value, int idx, int mday)
{
    if (!strcmp (field, "*"))
        return 1;

    /* lo_min is the implicit start for star/S (0-based vs 1-based fields). */
    int lo_min = (idx == 2 || idx == 3) ? 1 : 0;

    const char *p = field;
    while (*p) {
        int lo, hi, step = 1, nth = -1;

        while (isspace ((unsigned char)*p)) p++;
        if (!*p) break;

        /* Handle * at segment level: bare * matches everything; star/N is a step. */
        if (*p == '*') {
            p++;
            if (*p == '/') {
                p++;
                char *end;
                long s = strtol (p, &end, 10);
                if (end == p || s <= 0) { p = end; goto next; }
                step = (int)s;
                p = end;
                lo = lo_min;
                hi = INT_MAX;
            } else {
                return 1;           /* bare * in a list = matches all */
            }
        } else if (isdigit ((unsigned char)*p)) {
            char *end;
            lo = (int)strtol (p, &end, 10);
            if (end == p) goto next;
            p = end;
            hi = lo;
        } else if (idx == 3) {      /* month name */
            lo = bc_month_val (p);
            if (lo < 0) goto next;
            p += 3;
            hi = lo;
        } else if (idx == 4) {      /* DOW name */
            lo = bc_dow_val (p);
            if (lo < 0) goto next;
            p += 3;
            hi = lo;
        } else {
            goto next;
        }

        /* Range? */
        if (*p == '-') {
            p++;
            if (isdigit ((unsigned char)*p)) {
                char *end;
                hi = (int)strtol (p, &end, 10);
                if (end == p) goto next;
                p = end;
            } else if (idx == 3) {
                hi = bc_month_val (p);
                if (hi < 0) goto next;
                p += 3;
            } else if (idx == 4) {
                hi = bc_dow_val (p);
                if (hi < 0) goto next;
                p += 3;
            } else {
                goto next;
            }
        }

        /* Step? */
        if (*p == '/') {
            p++;
            char *end;
            long s = strtol (p, &end, 10);
            if (end == p || s <= 0) goto next;
            step = (int)s;
            p = end;
        }

        /* Vixie `dow#n`: the nth occurrence of a weekday in the month. Only
           valid in the DOW field, on a single value, with n in 1..5. */
        if (idx == 4 && *p == '#') {
            char *end;
            p++;
            long nn = strtol (p, &end, 10);
            if (end == p || nn < 1 || nn > 5 || lo != hi) goto next;
            nth = (int) nn;
            p = end;
        }

        /* A well-formed segment ends at ',' or end-of-string. Reject any other
           trailing syntax (e.g. the unsupported 'L'/'W' DOM modifiers) rather
           than silently matching just the leading number. */
        while (isspace ((unsigned char)*p)) p++;
        if (*p != '\0' && *p != ',')
            goto next;

        if (value >= lo && value <= hi && ((value - lo) % step == 0)) {
            if (nth < 0)
                return 1;
            /* nth occurrence: days 1-7 -> 1st, 8-14 -> 2nd, ... */
            if (mday >= 1 && (mday - 1) / 7 + 1 == nth)
                return 1;
        }

    next:
        while (*p && *p != ',') p++;
        if (*p == ',') { p++; continue; }
        break;
    }
    return 0;
}

static int
bc_tm_same_civil_minute (const struct tm *a, const struct tm *b)
{
    return a && b &&
           a->tm_year == b->tm_year &&
           a->tm_yday == b->tm_yday &&
           a->tm_hour == b->tm_hour &&
           a->tm_min == b->tm_min;
}

static int
bc_is_repeated_civil_minute (time_t now)
{
    struct tm cur;
    if (localtime_r (&now, &cur) == NULL)
        return 0;

    for (int mins = 1; mins <= 180; mins++) {
        time_t prev_epoch = now - (time_t) mins * 60;
        struct tm prev;
        if (localtime_r (&prev_epoch, &prev) == NULL)
            continue;
        if (bc_tm_same_civil_minute (&cur, &prev) &&
            cur.tm_isdst != prev.tm_isdst)
            return 1;
    }
    return 0;
}

static int
bc_field_has_wildcard (const char *field)
{
    return field && strchr (field, '*') != NULL;
}

/* True only for a literal bare "*" field (after surrounding whitespace).
   Unlike bc_field_has_wildcard(), a step field such as "*\/10" is NOT a
   bare star — it is a restricted set. This matches the Vixie/cronie
   DOM_STAR/DOW_STAR flag used for the day-field union rule, confirmed
   against cronie cronnext (e.g. "0 0 *\/10 5 5" unions like a restricted
   DOM, not a wildcard). */
static int
bc_field_is_bare_star (const char *field)
{
    if (!field)
        return 0;
    while (*field == ' ' || *field == '\t')
        field++;
    if (*field != '*')
        return 0;
    field++;
    while (*field == ' ' || *field == '\t')
        field++;
    return *field == '\0';
}

static int
bc_schedule_is_wildcard (char *fields[6])
{
    return fields &&
           (bc_field_has_wildcard (fields[0]) ||
            bc_field_has_wildcard (fields[1]));
}

static int
bc_suppress_fixed_time_duplicate (char *fields[6], int repeated_civil_minute)
{
    return repeated_civil_minute && !bc_schedule_is_wildcard (fields);
}

static int
bc_schedule_matches_tm (char *fields[5], const struct tm *tm)
{
    if (!fields || !tm)
        return 0;
    if (!bc_field_match (fields[0], tm->tm_min, 0, -1) ||
        !bc_field_match (fields[1], tm->tm_hour, 1, -1) ||
        !bc_field_match (fields[3], tm->tm_mon + 1, 3, -1))
        return 0;
    /* Vixie crontab(5) day rule: when BOTH day-of-month (field 2) and
       day-of-week (field 4) are restricted (neither is a bare "*"), the
       entry fires when EITHER matches; otherwise both must match. A bare
       "*" always matches, so the plain AND form is only wrong in the
       both-restricted case. "Restricted" keys on a literal bare star, not
       on the mere presence of a "*", so step fields like "*\/10" count as
       restricted — matching cronie/Vixie (the cronnext oracle the
       `cron next` counterpart compares against). */
    int dom_ok = bc_field_match (fields[2], tm->tm_mday, 2, -1);
    int dow_ok = bc_field_match (fields[4], tm->tm_wday, 4, tm->tm_mday);
    int dom_restricted = !bc_field_is_bare_star (fields[2]);
    int dow_restricted = !bc_field_is_bare_star (fields[4]);
    if (dom_restricted && dow_restricted)
        return dom_ok || dow_ok;
    return dom_ok && dow_ok;
}

static int
bc_macro_fields (const char *macro, char *fields[5])
{
    if (!macro || !fields || macro[0] != '@')
        return 0;
    if (!strcmp (macro, "@hourly")) {
        fields[0] = "0"; fields[1] = "*"; fields[2] = "*"; fields[3] = "*"; fields[4] = "*";
        return 1;
    }
    if (!strcmp (macro, "@daily") || !strcmp (macro, "@midnight")) {
        fields[0] = "0"; fields[1] = "0"; fields[2] = "*"; fields[3] = "*"; fields[4] = "*";
        return 1;
    }
    if (!strcmp (macro, "@weekly")) {
        fields[0] = "0"; fields[1] = "0"; fields[2] = "*"; fields[3] = "*"; fields[4] = "0";
        return 1;
    }
    if (!strcmp (macro, "@monthly")) {
        fields[0] = "0"; fields[1] = "0"; fields[2] = "1"; fields[3] = "*"; fields[4] = "*";
        return 1;
    }
    if (!strcmp (macro, "@yearly") || !strcmp (macro, "@annually")) {
        fields[0] = "0"; fields[1] = "0"; fields[2] = "1"; fields[3] = "1"; fields[4] = "*";
        return 1;
    }
    return 0;
}

static int
bc_next_schedule_time (char *fields[5], time_t from, time_t *out)
{
    time_t start = from - (from % 60);
    if (from % 60)
        start += 60;

    /* Ten years is a bounded guardrail, not a semantic limit. It covers
       leap-year and sparse annual schedules while preventing accidental
       infinite scans for impossible expressions. */
    const time_t max_minutes = (time_t) 10 * 366 * 24 * 60;
    for (time_t i = 0; i <= max_minutes; i++) {
        time_t candidate = start + i * 60;
        struct tm tm;
        if (localtime_r (&candidate, &tm) == NULL)
            continue;
        if (bc_schedule_matches_tm (fields, &tm)) {
            if (out)
                *out = candidate;
            return 0;
        }
    }
    return -1;
}

static char *
bc_trim (char *s)
{
    while (isspace ((unsigned char)*s))
        s++;
    char *e = s + strlen (s);
    while (e > s && isspace ((unsigned char)e[-1]))
        *--e = '\0';
    return s;
}

static int
bc_next_token (char **cursor, char **word)
{
    char *p = cursor ? *cursor : NULL;
    if (!p || !word)
        return 0;
    while (isspace ((unsigned char)*p))
        p++;
    if (!*p)
        return 0;
    *word = p;
    while (*p && !isspace ((unsigned char)*p))
        p++;
    if (*p)
        *p++ = '\0';
    while (isspace ((unsigned char)*p))
        p++;
    *cursor = p;
    return 1;
}

static int
bc_system_user_ok (const char *user)
{
    if (!bc_user_allowed (user))
        return 0;
    return getpwnam (user) != NULL;
}

static int
bc_crond_name_ok (const char *name)
{
    if (!name || !*name || name[0] == '.')
        return 0;
    for (const unsigned char *p = (const unsigned char *) name; *p; p++) {
        if (!(isalnum (*p) || *p == '_' || *p == '-'))
            return 0;
    }
    return 1;
}

static int
bc_row_user (char **cursor, const char *fixed_user, int system_crontab,
             char **out_user)
{
    if (!out_user)
        return 0;
    if (!system_crontab) {
        if (!fixed_user || !*fixed_user || !bc_user_allowed (fixed_user))
            return 0;
        *out_user = (char *) fixed_user;
        return 1;
    }

    char *user = NULL;
    if (!bc_next_token (cursor, &user))
        return 0;
    if (!bc_system_user_ok (user))
        return 0;
    *out_user = user;
    return 1;
}

static void
bc_poll_crontab_file_shape (const char *fixed_user, const char *path,
                            const struct tm *tm, int repeated_civil_minute,
                            int system_crontab, int reboot_pass)
{
    FILE *f = fopen (path, "r");
    if (!f)
        return;
    struct bc_file_env env;
    bc_env_init (&env);
    char line[4096];
    while (fgets (line, sizeof line, f)) {
        char *s = bc_trim (line);
        if (*s == '\0' || *s == '#')
            continue;
        /* Environment assignment lines (MAILTO=, PATH=, SHELL=). */
        if (bc_parse_env_line (s, &env))
            continue;

        if (*s == '@') {
            char *macro = s;
            if (!bc_next_token (&s, &macro))
                continue;

            char *row_user = NULL;
            if (!bc_row_user (&s, fixed_user, system_crontab, &row_user))
                continue;
            if (!*s)
                continue;

            if (reboot_pass) {
                if (strcmp (macro, "@reboot") == 0)
                    bc_run_command (row_user, s, &env);
                continue;
            }

            char *macro_fields[6];
            if (!bc_macro_fields (macro, macro_fields))
                continue;           /* @reboot is handled only at daemon startup. */
            macro_fields[5] = s;
            if (bc_schedule_matches_tm (macro_fields, tm) &&
                !bc_suppress_fixed_time_duplicate (macro_fields, repeated_civil_minute))
                bc_run_command (row_user, macro_fields[5], &env);
            continue;
        }

        if (reboot_pass)
            continue;

        char *fields[6];
        char *p = s;
        int ok = 1;
        for (int i = 0; i < 5; i++) {
            if (!bc_next_token (&p, &fields[i])) {
                ok = 0;
                break;
            }
        }
        if (!ok)
            continue;

        char *row_user = NULL;
        if (!bc_row_user (&p, fixed_user, system_crontab, &row_user) || !*p)
            continue;
        fields[5] = p;
        if (bc_schedule_matches_tm ((char **) fields, tm) &&
            !bc_suppress_fixed_time_duplicate (fields, repeated_civil_minute))
            bc_run_command (row_user, fields[5], &env);
    }
    fclose (f);
}

static void
bc_poll_crontab_file (const char *user, const char *path, const struct tm *tm,
                      int repeated_civil_minute)
{
    bc_poll_crontab_file_shape (user, path, tm, repeated_civil_minute, 0, 0);
}

static void
bc_poll_system_crontab_file (const char *path, const struct tm *tm,
                             int repeated_civil_minute, int reboot_pass)
{
    bc_poll_crontab_file_shape (NULL, path, tm, repeated_civil_minute, 1,
                                reboot_pass);
}

static void
bc_poll_reboot_file (const char *user, const char *path)
{
    bc_poll_crontab_file_shape (user, path, NULL, 0, 0, 1);
}

static void
bc_poll_system_crontab_path (const struct tm *tm, int repeated_civil_minute,
                             int reboot_pass)
{
    const char *path = bc_etc_crontab_path ();
    if (!path || !*path || !bc_crontab_secure (path))
        return;
    bc_poll_system_crontab_file (path, tm, repeated_civil_minute, reboot_pass);
}

static void
bc_poll_crond_dir_path (const struct tm *tm, int repeated_civil_minute,
                        int reboot_pass)
{
    const char *dir = bc_crond_dir ();
    DIR *d = opendir (dir);
    if (!d)
        return;
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        if (!bc_crond_name_ok (de->d_name))
            continue;
        char path[PATH_MAX];
        if (snprintf (path, sizeof path, "%s/%s", dir, de->d_name) >= (int) sizeof path)
            continue;
        if (!bc_crontab_secure (path))
            continue;
        bc_poll_system_crontab_file (path, tm, repeated_civil_minute, reboot_pass);
    }
    closedir (d);
}

static void
bc_poll_reboot_crontabs (void)
{
    bc_poll_system_crontab_path (NULL, 0, 1);
    bc_poll_crond_dir_path (NULL, 0, 1);

    char dir[PATH_MAX];
    if (snprintf (dir, sizeof dir, "%s/tabs", bc_spool_root ()) >= (int) sizeof dir ||
        bc_mkdir_p (dir) < 0)
        return;
    DIR *d = opendir (dir);
    if (!d)
        return;
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        if (de->d_name[0] == '.' || strchr (de->d_name, '/'))
            continue;
        if (!bc_user_allowed (de->d_name))
            continue;
        char path[PATH_MAX];
        if (snprintf (path, sizeof path, "%s/%s", dir, de->d_name) >= (int) sizeof path)
            continue;
        if (!bc_crontab_secure (path))
            continue;
        bc_poll_reboot_file (de->d_name, path);
    }
    closedir (d);
}

static void
bc_poll_crontabs (time_t now)
{
    struct tm tm;
    localtime_r (&now, &tm);
    int repeated_civil_minute = bc_is_repeated_civil_minute (now);

    bc_poll_system_crontab_path (&tm, repeated_civil_minute, 0);
    bc_poll_crond_dir_path (&tm, repeated_civil_minute, 0);

    char dir[PATH_MAX];
    if (snprintf (dir, sizeof dir, "%s/tabs", bc_spool_root ()) >= (int) sizeof dir ||
        bc_mkdir_p (dir) < 0)
        return;
    DIR *d = opendir (dir);
    if (!d)
        return;
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        if (de->d_name[0] == '.' || strchr (de->d_name, '/'))
            continue;
        if (!bc_user_allowed (de->d_name))
            continue;
        char path[PATH_MAX];
        if (snprintf (path, sizeof path, "%s/%s", dir, de->d_name) >= (int) sizeof path)
            continue;
        if (!bc_crontab_secure (path))
            continue;
        bc_poll_crontab_file (de->d_name, path, &tm, repeated_civil_minute);
    }
    closedir (d);
}

static void
bc_poll_once (int force_crontabs, time_t *last_cron_minute)
{
    time_t now = bc_now ();
    bc_poll_atjobs (now);
    time_t cron_minute = now / 60;
    if (force_crontabs || !last_cron_minute || *last_cron_minute < 0) {
        if (last_cron_minute)
            *last_cron_minute = cron_minute;
        bc_poll_crontabs (cron_minute * 60);
        if (last_cron_minute)
            bc_state_save (*last_cron_minute);
        return;
    }
    if (*last_cron_minute == cron_minute)
        return;
    if (cron_minute > *last_cron_minute) {
        time_t missed = cron_minute - *last_cron_minute;
        if (missed <= bc_catchup_max_minutes ()) {
            for (time_t m = *last_cron_minute + 1; m <= cron_minute; m++)
                bc_poll_crontabs (m * 60);
        } else {
            bc_poll_crontabs (cron_minute * 60);
        }
    } else {
        bc_poll_crontabs (cron_minute * 60);
    }
    *last_cron_minute = cron_minute;
    bc_state_save (*last_cron_minute);
}

extern char *cron_doc[];

int
cron_builtin (WORD_LIST *list)
{
    if (list && list->word && list->word->word &&
        (!strcmp (list->word->word, "-h") ||
         !strcmp (list->word->word, "--help"))) {
        for (char **lp = cron_doc; *lp; lp++)
            puts (*lp);
        return EXECUTION_SUCCESS;
    }
    if (!list || !list->word || !list->word->word) {
        builtin_error ("usage: cron run [--once] [--interval SEC]");
        return EX_USAGE;
    }

    if (!strcmp (list->word->word, "next")) {
        time_t from = bc_now ();
        char *fields[5];
        int n_fields = 0;
        for (list = list->next; list; list = list->next) {
            const char *w = list->word->word;
            if (!strcmp (w, "--from")) {
                int ok = 0;
                if (!list->next)
                    return EX_USAGE;
                list = list->next;
                from = bc_parse_epoch_value (list->word->word, &ok);
                if (!ok)
                    return EX_USAGE;
            } else {
                if (n_fields >= 5)
                    return EX_USAGE;
                fields[n_fields++] = list->word->word;
            }
        }
        if (n_fields == 1 && fields[0][0] == '@') {
            if (!bc_macro_fields (fields[0], fields)) {
                builtin_error ("unsupported schedule nickname: %s", fields[0]);
                return EX_USAGE;
            }
        } else if (n_fields != 5) {
            builtin_error ("usage: cron next [--from EPOCH] {MIN HOUR DOM MONTH DOW|@daily}");
            return EX_USAGE;
        }
        time_t next;
        if (bc_next_schedule_time (fields, from, &next) != 0) {
            builtin_error ("no matching schedule within search horizon");
            return EXECUTION_FAILURE;
        }
        printf ("%lld\n", (long long) next);
        return EXECUTION_SUCCESS;
    }

    if (strcmp (list->word->word, "run")) {
        builtin_error ("usage: cron run [--once] [--interval SEC]");
        return EX_USAGE;
    }
    int once = 0;
    int interval = 60;
    for (list = list->next; list; list = list->next) {
        const char *w = list->word->word;
        if (!strcmp (w, "--once")) {
            once = 1;
        } else if (!strcmp (w, "--interval")) {
            if (!list->next)
                return EX_USAGE;
            list = list->next;
            interval = atoi (list->word->word);
            if (interval <= 0)
                return EX_USAGE;
        } else {
            builtin_error ("unknown arg: %s", w);
            return EX_USAGE;
        }
    }

    char root[PATH_MAX];
    if (snprintf (root, sizeof root, "%s", bc_spool_root ()) >= (int) sizeof root ||
        bc_mkdir_p (root) < 0) {
        builtin_error ("mkdir spool: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    bc_prepare_output_dir ();

    if (once) {
        /* When BASHCRON_STATE_FILE is set, --once participates in the
           same persistence + catch-up flow as the daemon loop: if a
           previous minute was persisted and lies within
           bc_catchup_max_minutes() of now, the gap is replayed. When
           unset, --once is byte-identical to the pre-2026-05-19
           force-evaluate-current-minute behavior. */
        if (bc_state_file_path ()) {
            time_t once_last = (time_t) -1;
            (void) bc_state_load (&once_last);
            bc_poll_once (0, &once_last);
        } else {
            bc_poll_once (1, NULL);
        }
        return EXECUTION_SUCCESS;
    }

    signal (SIGTERM, bc_on_signal);
    signal (SIGINT, bc_on_signal);
    signal (SIGHUP, bc_on_reload);
    time_t last_cron_minute = (time_t) -1;
    /* Best-effort: if BASHCRON_STATE_FILE is set and parseable, seed
       last_cron_minute from it so a restart catches up the elapsed
       window via the same bc_poll_once logic as a normal forward gap. */
    (void) bc_state_load (&last_cron_minute);
    bc_poll_reboot_crontabs ();
    while (!bc_stop) {
        int force_crontabs = 0;
        if (bc_reload) {
            bc_reload = 0;
            force_crontabs = 1;
        }
        bc_poll_once (force_crontabs, &last_cron_minute);
        for (int i = 0; i < interval && !bc_stop && !bc_reload; i++)
            sleep (1);
    }
    return EXECUTION_SUCCESS;
}

char *cron_doc[] = {
    "Run the bash-os cron/at polling daemon.",
    "",
    "    cron run [--once] [--interval SEC]",
    "    cron next [--from EPOCH] {MIN HOUR DOM MONTH DOW|@daily}",
    "",
    "Polls ${BASHCRON_SPOOL_DIR:-/var/spool/cron}/atjobs and /tabs,",
    "  ${BASHCRON_ETC_DIR:-/etc}/crontab, and",
    "  ${BASHCRON_CROND_DIR:-/etc/cron.d} drop-ins.",
    "",
    "Per-user crontab fields: MIN HOUR DOM MONTH DOW COMMAND.",
    "System crontab fields: MIN HOUR DOM MONTH DOW USER COMMAND.",
    "Each field accepts *, comma-separated values, ranges (N-M),",
    "steps (*/N, N-M/S), and month/DOW abbreviations (JAN-DEC, SUN-SAT).",
    "Nicknames: @hourly, @daily/@midnight, @weekly, @monthly,",
    "  @yearly/@annually. @reboot runs once when daemon mode starts;",
    "  it is not a cron next schedule and is not run by --once.",
    "",
    "BASHCRON_CATCHUP_MAX_MIN: minutes (1..1440) the daemon will replay",
    "  minute-by-minute after a forward poll gap; larger gaps collapse to",
    "  the current minute. Default: 5.",
    "BASHCRON_STATE_FILE: persist last-evaluated cron-minute across",
    "  daemon restarts. When set, the daemon reads it on startup and",
    "  writes it after every poll (atomic rename, mode 0600); restart",
    "  catch-up reuses the same window as forward-gap catch-up. Unset",
    "  by default: no state file is created or consulted.",
    "BASHCRON_NOW_EPOCH: fixed Unix epoch-second clock source for",
    "  deterministic scheduler operation. Invalid values are ignored.",
    "BASHCRON_NOW_FILE: newline-delimited Unix epoch-second clock source;",
    "  each poll consumes one line and EOF reuses the last valid value.",
    "  BASHCRON_TEST_NOW_FILE remains accepted as a compatibility alias.",
    "BASHCRON_ETC_DIR: directory containing system crontab. Default: /etc.",
    "BASHCRON_CROND_DIR: directory containing cron.d drop-ins. Default:",
    "  /etc/cron.d.",
    "",
    "System crontab rows run as their USER column. When cron is root,",
    "  it drops privileges with setgid, initgroups, then setuid before exec;",
    "  failures exit 127 without executing the command. Non-root daemon runs",
    "  keep the daemon uid but still set USER, LOGNAME, HOME, SHELL, and PATH.",
    "",
    "cron next prints the next matching Unix epoch-second for a",
    "  five-field or supported nickname schedule using the same matcher as",
    "  the daemon.",
    "",
    "Crontab command output: stdout and stderr from matching crontab",
    "  entries are captured together. If any output is produced, cron",
    "  appends an mbox-shaped local notification to the crontab owner's",
    "  inbox under ${BASHCRON_MAIL_DIR:-/var/spool/mail}. MAILTO=user",
    "  redirects delivery to that local user; MAILTO=\"\" suppresses it.",
    "BASHCRON_OUTPUT_DIR: private temporary capture directory. Default:",
    "  /var/spool/cron/out. Stale job.* files are swept on startup.",
    (char *)NULL
};

struct builtin cron_struct = {
    "cron",
    cron_builtin,
    BUILTIN_ENABLED,
    cron_doc,
    "cron run [--once] [--interval SEC] | cron next [--from EPOCH] {MIN HOUR DOM MONTH DOW|@daily}",
    0
};
