/* SPDX-License-Identifier: MIT */
/* expect.c - expect-style pty automation for bash-os.
 *
 * This folds the old /bash-os/expect.sh read/match/send loop into C so
 * prompt bytes and secret sends avoid bash string variables where possible.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>

#include "loadables.h"
#include "command-run.h"

#define BE_BUF_MAX 65536
#define BE_STATE_MAX 16
#define BE_LOG_FD_MAX 4

extern int bashcrypto_secret_write_fd (const char *handle, int fd) __attribute__ ((weak));

typedef struct {
  int in_use;
  int fd;
  pid_t pid;
  int status_fd;
  int log_fds[BE_LOG_FD_MAX];
  int log_fd_count;
  int log_markers;
  int log_last_dir;
  char *buf;
  size_t len;
  size_t cap;
} be_state;

static be_state be_states[BE_STATE_MAX];
static volatile sig_atomic_t be_sigalrm_seen = 0;
static int be_log_user = 1;

struct be_child_guard {
  struct sigaction old_chld;
  sigset_t oldmask;
};

struct be_sigalrm_guard {
  struct sigaction old_alrm;
  int active;
};

static void
be_sigalrm_handler (int sig)
{
  (void) sig;
  be_sigalrm_seen = 1;
}

static int
be_sigalrm_guard_begin (struct be_sigalrm_guard *g)
{
  struct sigaction sa;
  memset (g, 0, sizeof *g);
  memset (&sa, 0, sizeof sa);
  sa.sa_handler = be_sigalrm_handler;
  sigemptyset (&sa.sa_mask);
  if (sigaction (SIGALRM, &sa, &g->old_alrm) < 0)
    return -1;
  be_sigalrm_seen = 0;
  g->active = 1;
  return 0;
}

static void
be_sigalrm_guard_end (struct be_sigalrm_guard *g)
{
  int seen = be_sigalrm_seen;
  if (!g->active)
    return;
  sigaction (SIGALRM, &g->old_alrm, NULL);
  g->active = 0;
  if (seen && g->old_alrm.sa_handler != SIG_IGN)
    raise (SIGALRM);
}

static int
be_child_guard_begin (struct be_child_guard *g)
{
  struct sigaction dfl;
  sigset_t block;
  memset (&dfl, 0, sizeof dfl);
  dfl.sa_handler = SIG_DFL;
  sigemptyset (&dfl.sa_mask);
  if (sigaction (SIGCHLD, &dfl, &g->old_chld) < 0)
    return -1;
  sigemptyset (&block);
  sigaddset (&block, SIGCHLD);
  if (sigprocmask (SIG_BLOCK, &block, &g->oldmask) < 0)
    {
      sigaction (SIGCHLD, &g->old_chld, NULL);
      return -1;
    }
  return 0;
}

static void
be_child_guard_parent_end (struct be_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
  sigaction (SIGCHLD, &g->old_chld, NULL);
}

static void
be_child_guard_child_end (struct be_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
}

static long
be_now_ms (void)
{
  struct timespec ts;
  if (clock_gettime (CLOCK_MONOTONIC, &ts) < 0)
    return 0;
  return (long) ts.tv_sec * 1000L + (long) ts.tv_nsec / 1000000L;
}

static int be_write_all (int fd, const char *data, size_t n);

static int
be_parse_fd (const char *s, int *out)
{
  char *end = NULL;
  long v = strtol (s, &end, 10);
  if (end == s || *end != '\0' || v < 0 || v > 1024 * 1024)
    return -1;
  *out = (int) v;
  return 0;
}

static be_state *
be_get_state (int fd, int create)
{
  be_state *free_slot = NULL;
  for (int i = 0; i < BE_STATE_MAX; i++)
    {
      if (be_states[i].in_use && be_states[i].fd == fd)
        return &be_states[i];
      if (!be_states[i].in_use && !free_slot)
        free_slot = &be_states[i];
    }
  if (!create || !free_slot)
    return NULL;
  memset (free_slot, 0, sizeof *free_slot);
  free_slot->in_use = 1;
  free_slot->fd = fd;
  free_slot->pid = 0;
  free_slot->status_fd = -1;
  for (int j = 0; j < BE_LOG_FD_MAX; j++)
    free_slot->log_fds[j] = -1;
  free_slot->log_fd_count = 0;
  free_slot->log_markers = 0;
  free_slot->log_last_dir = 0;
  return free_slot;
}

static void
be_free_state (int fd)
{
  for (int i = 0; i < BE_STATE_MAX; i++)
    if (be_states[i].in_use && be_states[i].fd == fd)
      {
        free (be_states[i].buf);
        if (be_states[i].status_fd >= 0)
          close (be_states[i].status_fd);
        memset (&be_states[i], 0, sizeof be_states[i]);
        be_states[i].status_fd = -1;
        for (int j = 0; j < BE_LOG_FD_MAX; j++)
          be_states[i].log_fds[j] = -1;
        be_states[i].log_fd_count = 0;
        be_states[i].log_markers = 0;
        be_states[i].log_last_dir = 0;
        return;
      }
}

static void
be_log_bytes (be_state *st, int dir, const char *data, size_t n)
{
  if (!st || st->log_fd_count <= 0 || n == 0)
    return;
  if (st->log_markers && st->log_last_dir != dir)
    {
      const char *marker = dir == '<' ? "<<<\n" : ">>>\n";
      for (int i = 0; i < st->log_fd_count; i++)
        {
          size_t left = 4;
          const char *p = marker;
          while (left > 0)
            {
              ssize_t w = write (st->log_fds[i], p, left);
              if (w < 0 && errno == EINTR) continue;
              if (w <= 0) break;
              p += w;
              left -= (size_t) w;
            }
        }
      st->log_last_dir = dir;
    }
  for (int i = 0; i < st->log_fd_count; i++)
    {
      const char *p = data;
      size_t left = n;
      while (left > 0)
        {
          ssize_t w = write (st->log_fds[i], p, left);
          if (w < 0 && errno == EINTR) continue;
          if (w <= 0) break;
          p += w;
          left -= (size_t) w;
        }
    }
}

static void
be_signal_pty_child (pid_t pid, int sig)
{
  if (pid <= 0)
    return;
  if (kill (-pid, sig) < 0)
    (void) kill (pid, sig);
}

static ssize_t
be_read_full_status (int fd, void *buf, size_t n, pid_t pid)
{
  char *p = (char *) buf;
  size_t got = 0;
  int signaled = 0;
  while (got < n)
    {
      ssize_t r = read (fd, p + got, n - got);
      if (r < 0 && errno == EINTR)
        {
          if (be_sigalrm_seen && !signaled)
            {
              be_signal_pty_child (pid, SIGTERM);
              signaled = 1;
            }
          continue;
        }
      if (r < 0)
        return r;
      if (r == 0)
        break;
      got += (size_t) r;
    }
  return (ssize_t) got;
}

static int
be_append (be_state *st, const char *data, size_t n)
{
  if (n == 0)
    return 0;
  be_log_bytes (st, '<', data, n);
  if (be_log_user && be_write_all (STDOUT_FILENO, data, n) != EXECUTION_SUCCESS)
    return -1;

  if (!st->buf)
    {
      st->cap = BE_BUF_MAX + 1;
      st->buf = (char *) malloc (st->cap);
      if (!st->buf)
        { builtin_error ("buffer malloc: %s", strerror (errno)); return -1; }
      st->len = 0;
      st->buf[0] = '\0';
    }

  if (n >= BE_BUF_MAX)
    {
      memcpy (st->buf, data + (n - BE_BUF_MAX), BE_BUF_MAX);
      st->len = BE_BUF_MAX;
      st->buf[st->len] = '\0';
      return 0;
    }
  if (st->len + n > BE_BUF_MAX)
    {
      size_t drop = st->len + n - BE_BUF_MAX;
      memmove (st->buf, st->buf + drop, st->len - drop);
      st->len -= drop;
    }
  memcpy (st->buf + st->len, data, n);
  st->len += n;
  st->buf[st->len] = '\0';
  return 0;
}

static int
be_write_all (int fd, const char *data, size_t n)
{
  while (n > 0)
    {
      ssize_t w = write (fd, data, n);
      if (w < 0 && errno == EINTR) continue;
      if (w < 0)
        { builtin_error ("write: %s", strerror (errno)); return EXECUTION_FAILURE; }
      if (w == 0)
        { builtin_error ("write: short write"); return EXECUTION_FAILURE; }
      data += w;
      n -= (size_t) w;
    }
  return EXECUTION_SUCCESS;
}

static int
be_poll_read (be_state *st, int timeout_sec, int eof_rc, int timeout_rc)
{
  long deadline = be_now_ms () + (long) timeout_sec * 1000L;
  for (;;)
    {
      long rem = deadline - be_now_ms ();
      if (rem < 0) rem = 0;
      struct pollfd pfd = { .fd = st->fd, .events = POLLIN | POLLHUP | POLLERR, .revents = 0 };
      int pr = poll (&pfd, 1, (int) rem);
      if (pr < 0 && errno == EINTR) continue;
      if (pr < 0)
        { builtin_error ("poll: %s", strerror (errno)); return EXECUTION_FAILURE; }
      if (pr == 0)
        return timeout_rc;
      char tmp[256];
      ssize_t r = read (st->fd, tmp, sizeof tmp);
      if (r < 0 && errno == EINTR) continue;
      if (r < 0 && errno == EIO)
        return eof_rc;
      if (r < 0)
        { builtin_error ("read: %s", strerror (errno)); return EXECUTION_FAILURE; }
      if (r == 0)
        return eof_rc;
      if (be_append (st, tmp, (size_t) r) < 0)
        return EXECUTION_FAILURE;
      return EXECUTION_SUCCESS;
    }
}

static int
be_regex_match (const char *buf, const char *pat, char **match_out)
{
  regex_t re;
  int rc = regcomp (&re, pat, REG_EXTENDED | REG_NEWLINE);
  if (rc != 0)
    {
      char msg[160];
      regerror (rc, &re, msg, sizeof msg);
      builtin_error ("regex compile: %s", msg);
      return -1;
    }
  regmatch_t pm[1];
  rc = regexec (&re, buf ? buf : "", 1, pm, 0);
  if (rc == 0)
    {
      if (match_out)
        {
          size_t n = (size_t) (pm[0].rm_eo - pm[0].rm_so);
          char *m = (char *) malloc (n + 1);
          if (!m)
            { regfree (&re); builtin_error ("match malloc: %s", strerror (errno)); return -1; }
          memcpy (m, (buf ? buf : "") + pm[0].rm_so, n);
          m[n] = '\0';
          *match_out = m;
        }
      regfree (&re);
      return 1;
    }
  regfree (&re);
  return 0;
}

static int
be_bind (const char *var, const char *val)
{
  if (var)
    builtin_bind_variable ((char *) var, (char *) val, 0);
  return 0;
}

static int
be_spawn_cmd (WORD_LIST *args)
{
  WORD_LIST *cmd_start = args;
  WORD_LIST *p = args;
  const char *fdvar = NULL;
  const char *pidvar = NULL;
  int argc = 0;

  for (; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-h") == 0)
        break;
      argc++;
    }
  if (!cmd_start || argc == 0)
    { builtin_error ("spawn needs CMD [ARGS...] -h FD_VAR -h PID_VAR"); return EX_USAGE; }
  for (; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-h") != 0 || !p->next)
        { builtin_error ("spawn handles must be -h FD_VAR -h PID_VAR"); return EX_USAGE; }
      p = p->next;
      if (!fdvar) fdvar = p->word->word;
      else if (!pidvar) pidvar = p->word->word;
      else { builtin_error ("spawn got too many handles"); return EX_USAGE; }
    }
  if (!fdvar || !pidvar)
    { builtin_error ("spawn needs two -h handles"); return EX_USAGE; }

  char **argv = (char **) malloc ((argc + 1) * sizeof (char *));
  if (!argv)
    { builtin_error ("argv malloc: %s", strerror (errno)); return EXECUTION_FAILURE; }
  int i = 0;
  for (p = cmd_start; p && i < argc; p = p->next)
    argv[i++] = p->word->word;
  argv[argc] = NULL;

  int master = posix_openpt (O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0)
    { free (argv); builtin_error ("posix_openpt: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (grantpt (master) < 0 || unlockpt (master) < 0)
    { close (master); free (argv); builtin_error ("grantpt/unlockpt: %s", strerror (errno)); return EXECUTION_FAILURE; }

  char slave_path[256];
  if (ptsname_r (master, slave_path, sizeof slave_path) != 0)
    { close (master); free (argv); builtin_error ("ptsname: %s", strerror (errno)); return EXECUTION_FAILURE; }

  int statpipe[2];
  if (pipe (statpipe) < 0)
    { close (master); free (argv); builtin_error ("pipe: %s", strerror (errno)); return EXECUTION_FAILURE; }
  fcntl (statpipe[0], F_SETFD, FD_CLOEXEC);

  struct be_child_guard guard;
  if (be_child_guard_begin (&guard) < 0)
    { close (master); close (statpipe[0]); close (statpipe[1]); free (argv); builtin_error ("SIGCHLD guard: %s", strerror (errno)); return EXECUTION_FAILURE; }

  pid_t intermediate = fork ();
  if (intermediate < 0)
    { be_child_guard_parent_end (&guard); close (master); close (statpipe[0]); close (statpipe[1]); free (argv); builtin_error ("fork: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (intermediate == 0)
    {
      be_child_guard_child_end (&guard);
      close (master);
      close (statpipe[0]);
      struct be_child_guard target_guard;
      if (be_child_guard_begin (&target_guard) < 0)
        { dprintf (2, "expect spawn: SIGCHLD guard: %s\n", strerror (errno)); _exit (126); }
      pid_t target = fork ();
      if (target < 0)
        { be_child_guard_parent_end (&target_guard); dprintf (2, "expect spawn: fork: %s\n", strerror (errno)); _exit (126); }
      if (target == 0)
        {
          be_child_guard_child_end (&target_guard);
          close (statpipe[1]);
          if (setsid () < 0)
            { dprintf (2, "expect child: setsid: %s\n", strerror (errno)); _exit (126); }
          int slave = open (slave_path, O_RDWR);
          if (slave < 0)
            { dprintf (2, "expect child: open(%s): %s\n", slave_path, strerror (errno)); _exit (126); }
          if (ioctl (slave, TIOCSCTTY, 0) < 0)
            { dprintf (2, "expect child: TIOCSCTTY: %s\n", strerror (errno)); _exit (126); }
          if (dup2 (slave, 0) < 0 || dup2 (slave, 1) < 0 || dup2 (slave, 2) < 0)
            { dprintf (2, "expect child: dup2: %s\n", strerror (errno)); _exit (126); }
          if (slave > 2) close (slave);
          bos_prepare_child ();
          bos_run_builtin (argv[0], argv, NULL);
          execvp (argv[0], argv);
          dprintf (2, "expect child: execvp(%s): %s\n", argv[0], strerror (errno));
          _exit (127);
        }
      ssize_t w = write (statpipe[1], &target, sizeof target);
      (void) w;
      int status = 0;
      pid_t waited;
      while ((waited = waitpid (target, &status, 0)) < 0)
        {
          if (errno == EINTR) continue;
          break;
        }
      be_child_guard_parent_end (&target_guard);
      int exit_code = waited == target && WIFEXITED (status) ? WEXITSTATUS (status)
                    : WIFSIGNALED (status) ? 128 + WTERMSIG (status)
                    : 1;
      w = write (statpipe[1], &exit_code, sizeof exit_code);
      (void) w;
      close (statpipe[1]);
      _exit (0);
  }

  free (argv);
  close (statpipe[1]);
  pid_t target_pid;
  if (be_read_full_status (statpipe[0], &target_pid, sizeof target_pid, 0)
      != (ssize_t) sizeof target_pid)
    {
      be_child_guard_parent_end (&guard);
      close (master);
      close (statpipe[0]);
      builtin_error ("spawn: short read from intermediate");
      return EXECUTION_FAILURE;
    }
  be_child_guard_parent_end (&guard);

  be_state *st = be_get_state (master, 1);
  if (!st)
    {
      close (master);
      close (statpipe[0]);
      builtin_error ("spawn: state table full");
      return EXECUTION_FAILURE;
    }
  st->pid = target_pid;
  st->status_fd = statpipe[0];

  char nb[32];
  snprintf (nb, sizeof nb, "%d", master);
  be_bind (fdvar, nb);
  snprintf (nb, sizeof nb, "%d", (int) target_pid);
  be_bind (pidvar, nb);
  return EXECUTION_SUCCESS;
}

static int
be_send_cmd (WORD_LIST *args, int newline)
{
  if (!args || !args->next)
    { builtin_error (newline ? "sendline needs FD STRING" : "send needs FD STRING"); return EX_USAGE; }
  int fd;
  if (be_parse_fd (args->word->word, &fd) < 0)
    { builtin_error ("bad fd: %s", args->word->word); return EX_USAGE; }
  const char *s = args->next->word->word;
  be_state *st = be_get_state (fd, 0);
  int rc = be_write_all (fd, s, strlen (s));
  if (rc != EXECUTION_SUCCESS || !newline)
    {
      if (rc == EXECUTION_SUCCESS && st)
        be_log_bytes (st, '>', s, strlen (s));
      return rc;
    }
  if (st)
    {
      be_log_bytes (st, '>', s, strlen (s));
      be_log_bytes (st, '>', "\n", 1);
    }
  return be_write_all (fd, "\n", 1);
}

static int
be_send_secret_cmd (WORD_LIST *args)
{
  if (!args || !args->next)
    { builtin_error ("send-secret needs FD HANDLE"); return EX_USAGE; }
  int fd;
  if (be_parse_fd (args->word->word, &fd) < 0)
    { builtin_error ("bad fd: %s", args->word->word); return EX_USAGE; }
  if (!bashcrypto_secret_write_fd)
    { builtin_error ("send-secret requires crypto secret handle support"); return EXECUTION_FAILURE; }
  return bashcrypto_secret_write_fd (args->next->word->word, fd) == 0
       ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
be_expect_cmd (WORD_LIST *args)
{
  if (!args || !args->next)
    { builtin_error ("expect needs FD PATTERN [-t SEC] [-V MATCH_VAR]"); return EX_USAGE; }
  int fd;
  if (be_parse_fd (args->word->word, &fd) < 0)
    { builtin_error ("bad fd: %s", args->word->word); return EX_USAGE; }
  const char *pat = args->next->word->word;
  int timeout = 10;
  const char *match_var = NULL;
  for (WORD_LIST *p = args->next->next; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-t") == 0 && p->next)
        { p = p->next; timeout = atoi (p->word->word); }
      else if (strcmp (w, "-V") == 0 && p->next)
        { p = p->next; match_var = p->word->word; }
      else { builtin_error ("expect: unexpected arg: %s", w); return EX_USAGE; }
    }
  be_state *st = be_get_state (fd, 1);
  if (!st)
    { builtin_error ("expect: state table full"); return EXECUTION_FAILURE; }

  for (;;)
    {
      char *m = NULL;
      int mr = be_regex_match (st->buf, pat, &m);
      if (mr < 0) return EX_USAGE;
      if (mr > 0)
        {
          if (match_var) be_bind (match_var, m);
          free (m);
          return EXECUTION_SUCCESS;
        }
      int rr = be_poll_read (st, timeout, 2, 1);
      if (rr != EXECUTION_SUCCESS)
        return rr;
    }
}

static int
be_expect_alt_cmd (WORD_LIST *args)
{
  if (!args || !args->next)
    { builtin_error ("expect-alt needs FD PAT... [-t SEC] -V WHICH_VAR -V MATCH_VAR"); return EX_USAGE; }
  int fd;
  if (be_parse_fd (args->word->word, &fd) < 0)
    { builtin_error ("bad fd: %s", args->word->word); return EX_USAGE; }
  const char *patterns[64];
  int npat = 0;
  int timeout = 10;
  const char *which_var = NULL;
  const char *match_var = NULL;
  for (WORD_LIST *p = args->next; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-t") == 0 && p->next)
        { p = p->next; timeout = atoi (p->word->word); }
      else if (strcmp (w, "-V") == 0 && p->next)
        {
          p = p->next;
          if (!which_var) which_var = p->word->word;
          else if (!match_var) match_var = p->word->word;
          else { builtin_error ("expect-alt: too many -V vars"); return EX_USAGE; }
        }
      else
        {
          if (npat >= 64)
            { builtin_error ("expect-alt: too many patterns"); return EX_USAGE; }
          patterns[npat++] = w;
        }
    }
  if (npat == 0)
    { builtin_error ("expect-alt needs at least one pattern"); return EX_USAGE; }
  be_state *st = be_get_state (fd, 1);
  if (!st)
    { builtin_error ("expect-alt: state table full"); return EXECUTION_FAILURE; }

  for (;;)
    {
      for (int i = 0; i < npat; i++)
        {
          char *m = NULL;
          int mr = be_regex_match (st->buf, patterns[i], &m);
          if (mr < 0) return EX_USAGE;
          if (mr > 0)
            {
              char nb[32];
              snprintf (nb, sizeof nb, "%d", i);
              if (which_var) be_bind (which_var, nb);
              if (match_var) be_bind (match_var, m);
              free (m);
              return EXECUTION_SUCCESS;
            }
        }
      int rr = be_poll_read (st, timeout, 2, 1);
      if (rr != EXECUTION_SUCCESS)
        return rr;
    }
}

static int
be_eof_cmd (WORD_LIST *args)
{
  if (!args)
    { builtin_error ("eof needs FD [-t SEC]"); return EX_USAGE; }
  int fd;
  if (be_parse_fd (args->word->word, &fd) < 0)
    { builtin_error ("bad fd: %s", args->word->word); return EX_USAGE; }
  int timeout = 10;
  for (WORD_LIST *p = args->next; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-t") == 0 && p->next)
        { p = p->next; timeout = atoi (p->word->word); }
      else { builtin_error ("eof: unexpected arg: %s", w); return EX_USAGE; }
    }
  be_state *st = be_get_state (fd, 1);
  if (!st)
    { builtin_error ("eof: state table full"); return EXECUTION_FAILURE; }
  for (;;)
    {
      int rr = be_poll_read (st, timeout, 3, EXECUTION_FAILURE);
      if (rr == 3)
        return EXECUTION_SUCCESS;
      if (rr != EXECUTION_SUCCESS)
        return rr;
    }
}

static int
be_close_cmd (WORD_LIST *args)
{
  if (!args || !args->next)
    { builtin_error ("close needs FD PID"); return EX_USAGE; }
  int fd;
  if (be_parse_fd (args->word->word, &fd) < 0)
    { builtin_error ("bad fd: %s", args->word->word); return EX_USAGE; }
  pid_t pid = (pid_t) atoi (args->next->word->word);
  be_state *st = be_get_state (fd, 0);
  int status_fd = st ? st->status_fd : -1;
  struct be_sigalrm_guard alrm_guard;
  int guard_active = be_sigalrm_guard_begin (&alrm_guard) == 0;
  if (fd >= 0)
    close (fd);
  int exit_code = 0;
  if (status_fd >= 0)
    {
      ssize_t r = be_read_full_status (status_fd, &exit_code, sizeof exit_code, pid);
      if (r != (ssize_t) sizeof exit_code)
        exit_code = EXECUTION_FAILURE;
    }
  else
    {
      int status;
      if (waitpid (pid, &status, 0) == pid)
        exit_code = WIFEXITED (status) ? WEXITSTATUS (status)
                  : WIFSIGNALED (status) ? 128 + WTERMSIG (status)
                  : 1;
      else
        exit_code = EXECUTION_FAILURE;
    }
  /* Reap any zombie intermediates left behind by spawn (be_state's
     intermediate forks _exit(0) once the target is reaped, leaving a
     <defunct> until somebody waits). Non-blocking sweep — best-effort. */
  while (waitpid (-1, NULL, WNOHANG) > 0) { }
  be_free_state (fd);
  if (guard_active)
    be_sigalrm_guard_end (&alrm_guard);
  return exit_code;
}

static int
be_log_cmd (WORD_LIST *args)
{
  if (!args)
    { builtin_error ("log needs FD -F LOGFD"); return EX_USAGE; }
  int fd;
  if (be_parse_fd (args->word->word, &fd) < 0)
    { builtin_error ("bad fd: %s", args->word->word); return EX_USAGE; }
  int log_fd = -1;
  int log_markers = 0;
  int disable = 0;
  for (WORD_LIST *p = args->next; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-F") == 0 && p->next)
        { p = p->next; if (be_parse_fd (p->word->word, &log_fd) < 0) return EX_USAGE; }
      else if (strcmp (w, "-m") == 0 || strcmp (w, "--markers") == 0)
        log_markers = 1;
      else if (strcmp (w, "off") == 0 || strcmp (w, "-off") == 0 || strcmp (w, "--off") == 0)
        { disable = 1; log_fd = -1; log_markers = 0; }
      else { builtin_error ("log: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (log_fd < 0 && !disable)
    { builtin_error ("log needs -F LOGFD"); return EX_USAGE; }
  if (!disable && fcntl (log_fd, F_GETFD) < 0)
    { builtin_error ("log: bad LOGFD %d: %s", log_fd, strerror (errno)); return EX_USAGE; }
  be_state *st = be_get_state (fd, 1);
  if (!st)
    { builtin_error ("log: state table full"); return EXECUTION_FAILURE; }
  if (disable)
    {
      for (int i = 0; i < BE_LOG_FD_MAX; i++)
        st->log_fds[i] = -1;
      st->log_fd_count = 0;
      st->log_markers = 0;
      st->log_last_dir = 0;
      return EXECUTION_SUCCESS;
    }
  for (int i = 0; i < st->log_fd_count; i++)
    if (st->log_fds[i] == log_fd)
      {
        st->log_markers = st->log_markers || log_markers;
        st->log_last_dir = 0;
        return EXECUTION_SUCCESS;
      }
  if (st->log_fd_count >= BE_LOG_FD_MAX)
    { builtin_error ("log: too many log fds (max %d)", BE_LOG_FD_MAX); return EXECUTION_FAILURE; }
  st->log_fds[st->log_fd_count++] = log_fd;
  st->log_markers = st->log_markers || log_markers;
  st->log_last_dir = 0;
  return EXECUTION_SUCCESS;
}

static int
be_debug_cmd (WORD_LIST *args)
{
  (void) args;
  puts ("expect: spawn available");
  puts ("expect: expect available");
  puts ("expect: send available");
  puts ("expect: log available");
  return EXECUTION_SUCCESS;
}

static int
be_log_user_cmd (WORD_LIST *args)
{
  if (!args)
    {
      printf ("log_user %s\n", be_log_user ? "on" : "off");
      return EXECUTION_SUCCESS;
    }
  const char *w = args->word->word;
  if (strcmp (w, "on") == 0 || strcmp (w, "1") == 0)
    { be_log_user = 1; return EXECUTION_SUCCESS; }
  if (strcmp (w, "off") == 0 || strcmp (w, "0") == 0)
    { be_log_user = 0; return EXECUTION_SUCCESS; }
  builtin_error ("log_user expects on|off");
  return EX_USAGE;
}

static int
be_interact_cmd (WORD_LIST *args)
{
  (void) args;
  char buf[256];
  while (read (STDIN_FILENO, buf, sizeof buf) > 0)
    { }
  return EXECUTION_SUCCESS;
}

int
expect_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "--version") == 0 || strcmp (cmd, "version") == 0)
    { puts ("expect 1.0"); return EXECUTION_SUCCESS; }
  if (strcmp (cmd, "-d") == 0 || strcmp (cmd, "--debug") == 0)
    return be_debug_cmd (args);
  if (strcmp (cmd, "spawn") == 0) return be_spawn_cmd (args);
  if (strcmp (cmd, "expect") == 0) return be_expect_cmd (args);
  if (strcmp (cmd, "expect-alt") == 0) return be_expect_alt_cmd (args);
  if (strcmp (cmd, "send") == 0) return be_send_cmd (args, 0);
  if (strcmp (cmd, "sendline") == 0) return be_send_cmd (args, 1);
  if (strcmp (cmd, "send-secret") == 0) return be_send_secret_cmd (args);
  if (strcmp (cmd, "eof") == 0) return be_eof_cmd (args);
  if (strcmp (cmd, "close") == 0) return be_close_cmd (args);
  if (strcmp (cmd, "log") == 0) return be_log_cmd (args);
  if (strcmp (cmd, "log_user") == 0) return be_log_user_cmd (args);
  if (strcmp (cmd, "interact") == 0) return be_interact_cmd (args);
  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *expect_doc[] = {
  "Expect-style pty automation for bash-os.",
  "",
  "    expect spawn CMD [ARGS...] -h FD_VAR -h PID_VAR",
  "    expect expect FD PATTERN [-t SEC] [-V MATCH_VAR]",
  "    expect expect-alt FD PAT1 [PAT2 ...] [-t SEC] -V WHICH_VAR -V MATCH_VAR",
  "    expect send FD STRING",
  "    expect sendline FD STRING",
  "    expect send-secret FD HANDLE",
  "    expect eof FD [-t SEC]",
  "    expect close FD PID",
  "    expect log FD -F LOGFD [-m|--markers]",
  "    expect log FD off",
  "    expect log_user on|off",
  "    expect interact",
  "    expect -d|--debug",
  "    expect --version",
  (char *)NULL
};

struct builtin expect_struct = {
  "expect",
  expect_builtin,
  BUILTIN_ENABLED,
  expect_doc,
  "expect spawn|expect|expect-alt|send|sendline|send-secret|eof|close|log|log_user|interact ...",
  0
};
