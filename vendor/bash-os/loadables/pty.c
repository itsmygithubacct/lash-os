/* SPDX-License-Identifier: MIT */
/* pty.c — TTY / session management for bash-os getty + login.
 *
 * Bash can drive a terminal via /dev/ttyXXX redirection but can't
 * issue setsid / TIOCSCTTY / tcsetpgrp — those are syscalls that
 * make a TTY into a controlling terminal for a session. pty
 * exposes the minimum surface needed for getty.sh / login login
 * to run real login sessions on a console without forking to /sbin/
 * agetty or /bin/login.
 *
 * Subcommands:
 *
 *   pty setsid
 *       setsid(2). The calling process becomes a new session
 *       leader with no controlling terminal. Required before
 *       open-tty (TIOCSCTTY only works on a session leader with
 *       no current ctty).
 *
 *   pty open-tty PATH [FDVAR]
 *       open(PATH, O_RDWR|O_NOCTTY), then ioctl(fd, TIOCSCTTY)
 *       to install it as the session's controlling terminal.
 *       By default also dup2's the new fd into stdin/stdout/stderr
 *       so subsequent reads/writes go to the tty without further
 *       redirection. With FDVAR, just bind $FDVAR to the fd and
 *       leave 0/1/2 alone.
 *
 *   pty isatty FD
 *       Exit 0 if FD is a terminal.
 *
 *   pty tty-name FD
 *       Print the filesystem path of the TTY backing FD (e.g.,
 *       /dev/pts/3 or /dev/ttyS0).
 *
 *   pty foreground PGRP [FD]
 *       tcsetpgrp(FD, PGRP). FD defaults to stdin (0). Used after
 *       fork+exec to give a child shell the foreground process
 *       group on the controlling tty.
 *
 *   pty close FD
 *       close(FD). Convenience.
 *
 *   pty spawn FDVAR PIDVAR CMD [ARG ...]
 *       Allocate a pty, fork a child, and exec CMD with the slave
 *       end as its controlling tty (stdin/stdout/stderr all wired
 *       to slave). Parent retains the master fd; reading the master
 *       gives the child's output, writing the master sends to its
 *       stdin. The master fd is bound to $FDVAR, the child pid to
 *       $PIDVAR. Use bash redirection to read/write — e.g.
 *           read -u "$FDVAR" -N 1 -t 5 ch     # read with timeout
 *           printf '%s\n' "$pw" >&"$FDVAR"    # send a line
 *       After EOF, `pty close "$FDVAR"; pty waitpid "$PIDVAR"` cleans up.
 *       This is the spawn primitive for /bash-os/expect.sh.
 *
 * Refuses TIOCSCTTY if not the session leader — the calling script
 * is responsible for setsid before open-tty.
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
#include <limits.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "loadables.h"
#include "command-run.h"

struct bp_child_guard {
  struct sigaction old_chld;
  sigset_t oldmask;
};

static int
bp_child_guard_begin (struct bp_child_guard *g)
{
  struct sigaction dfl;
  sigset_t block;
  memset (&dfl, 0, sizeof dfl);
  dfl.sa_handler = SIG_DFL;
  sigemptyset (&dfl.sa_mask);
  sigemptyset (&block);
  sigaddset (&block, SIGCHLD);
  if (sigprocmask (SIG_BLOCK, &block, &g->oldmask) < 0)
    return -1;
  if (sigaction (SIGCHLD, &dfl, &g->old_chld) < 0)
    {
      sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
      return -1;
    }
  return 0;
}

static void
bp_child_guard_parent_end (struct bp_child_guard *g)
{
  sigaction (SIGCHLD, &g->old_chld, NULL);
  sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
}

static void
bp_child_guard_child_end (struct bp_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
}

static int
bp_setsid_cmd (WORD_LIST *args)
{
  (void) args;
  pid_t s = setsid ();
  if (s < 0)
    {
      builtin_error ("setsid: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
bp_open_tty_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("open-tty needs PATH [FDVAR]"); return EX_USAGE; }
  const char *path = args->word->word;
  const char *fdvar = (args->next) ? args->next->word->word : NULL;

  /* O_NOCTTY: don't let open() implicitly grab the tty. We do that
     explicitly with TIOCSCTTY below, after verifying we're a session
     leader. O_RDWR for bidirectional. */
  int fd = open (path, O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (fd < 0)
    {
      builtin_error ("open %s: %s", path, strerror (errno));
      return EXECUTION_FAILURE;
    }

  /* Acquire the controlling terminal. Fails if we already have one
     (caller should setsid first to start with no ctty) or if we're
     not a session leader. Pass 0 to TIOCSCTTY (don't force-steal). */
  if (ioctl (fd, TIOCSCTTY, 0) < 0)
    {
      /* Note: this can fail with EPERM if we already have a ctty —
         common in interactive / dev sessions. Don't fail hard; the
         tty is still usable for reads/writes, just not "controlling". */
      builtin_error ("TIOCSCTTY %s: %s (continuing without controlling)",
                     path, strerror (errno));
      /* Fall through — keep the fd; warn was enough. */
    }

  if (fdvar)
    {
      /* Caller wants the fd via variable; don't touch 0/1/2. */
      char buf[32];
      snprintf (buf, sizeof buf, "%d", fd);
      builtin_bind_variable ((char *) fdvar, buf, 0);
      return EXECUTION_SUCCESS;
    }

  /* Default: dup2 over stdin/stdout/stderr so the calling shell now
     reads/writes the tty. This is what getty wants. */
  if (dup2 (fd, 0) < 0 || dup2 (fd, 1) < 0 || dup2 (fd, 2) < 0)
    {
      builtin_error ("dup2: %s", strerror (errno));
      close (fd);
      return EXECUTION_FAILURE;
    }
  /* Close the original (CLOEXEC isn't enough — the dup2'd copies
     don't carry it). */
  if (fd > 2) close (fd);
  return EXECUTION_SUCCESS;
}

static int
bp_isatty_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("isatty needs FD"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  return isatty (fd) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bp_ttyname_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("tty-name needs FD"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  char buf[256];
  if (ttyname_r (fd, buf, sizeof buf) != 0)
    {
      builtin_error ("ttyname: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  printf ("%s\n", buf);
  return EXECUTION_SUCCESS;
}

static int
bp_foreground_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("foreground needs PGRP [FD]"); return EX_USAGE; }
  pid_t pgrp = (pid_t) atoi (args->word->word);
  int fd = (args->next) ? atoi (args->next->word->word) : 0;
  if (tcsetpgrp (fd, pgrp) < 0)
    {
      int saved = errno;
      if (saved == ENOTTY)
        {
          pid_t current = -1;
          if (ioctl (fd, TIOCGPGRP, &current) == 0 && current == pgrp)
            return EXECUTION_SUCCESS;
          char slave_path[256];
          if (ptsname_r (fd, slave_path, sizeof slave_path) == 0)
            {
              int slave = open (slave_path, O_RDWR | O_NOCTTY);
              if (slave >= 0)
                {
                  int rc = tcsetpgrp (slave, pgrp);
                  saved = errno;
                  close (slave);
                  if (rc == 0)
                    return EXECUTION_SUCCESS;
                }
            }
        }
      errno = saved;
      builtin_error ("tcsetpgrp: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
bp_close_cmd (WORD_LIST *args)
{
  if (!args || args->next) { builtin_error ("close needs FD"); return EX_USAGE; }
  char *end;
  errno = 0;
  long number = strtol (args->word->word, &end, 10);
  if (errno || !*args->word->word || *end || number < 0 || number > INT_MAX)
    { builtin_error ("close: invalid FD: %s", args->word->word); return EX_USAGE; }
  int fd = (int) number;
  if (close (fd) < 0)
    {
      builtin_error ("close: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

/* Each intermediate owns one target and writes its result to a private
   pipe. Bash may reap the intermediates without losing these results. */
struct bp_status {
  pid_t target_pid;
  int pipe_fd, exit_code;
  size_t received;
  struct bp_status *next;
};
static struct bp_status *bp_statuses;
static pid_t bp_status_owner;

static void
bp_clear_statuses (void)
{
  while (bp_statuses)
    {
      struct bp_status *entry = bp_statuses;
      bp_statuses = entry->next;
      close (entry->pipe_fd);
      free (entry);
    }
}

/* A subshell must never consume its parent's status pipe. Closing its
   inherited copies leaves the owning shell's descriptors untouched. */
static void
bp_check_owner (void)
{
  if (bp_status_owner != getpid ())
    {
      bp_clear_statuses ();
      bp_status_owner = getpid ();
    }
}

void
pty_builtin_unload (char *name)
{
  (void) name;
  bp_clear_statuses ();
}

/* Resolve only scalar names; array subscripts can evaluate shell code.
   Validate both spawn outputs before allocating resources or starting CMD. */
static char *
bp_output_name (const char *name)
{
  const char *target = name;
  for (int depth = 0; depth < 64; depth++)
    {
      if (!target || !legal_identifier (target)) break;
      SHELL_VAR *v = find_variable_noref (target);
      if (v && (readonly_p (v) || noassign_p (v) || array_p (v) ||
                assoc_p (v) || v->dynamic_value || v->assign_func)) break;
      if (v && nameref_p (v))
        { target = nameref_cell (v); continue; }
      char *copy = strdup (target);
      if (!copy) builtin_error ("output variable: %s", strerror (errno));
      return copy;
    }
  builtin_error ("output variable must be a writable scalar: %s", name);
  return NULL;
}

static int
bp_bind_number (char *name, int value)
{
  char text[32];
  snprintf (text, sizeof text, "%d", value);
  SHELL_VAR *v = builtin_bind_variable (name, text, 0);
  return v && !readonly_p (v) && !noassign_p (v) ? 0 : -1;
}

static int
bp_read_exact (int fd, void *buffer, size_t length)
{
  size_t used = 0;
  while (used < length)
    {
      ssize_t n = read (fd, (char *) buffer + used, length - used);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) return -1;
      used += n;
    }
  return 0;
}

/* The intermediate never execs, and the target can dispatch a builtin.
   Apply close-on-exec here so other PTYs and native handles do not stay
   alive solely because another pty spawn inherited them. */
static void
bp_close_cloexec (int keep_a, int keep_b)
{
  DIR *dir = opendir ("/proc/self/fd");
  if (dir)
    {
      struct dirent *entry;
      while ((entry = readdir (dir)))
        {
          if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
          int fd = atoi (entry->d_name);
          if (fd <= 2 || fd == dirfd (dir) || fd == keep_a || fd == keep_b) continue;
          int flags = fcntl (fd, F_GETFD);
          if (flags >= 0 && (flags & FD_CLOEXEC)) close (fd);
        }
      closedir (dir);
    }
  else
    {
      long limit = sysconf (_SC_OPEN_MAX);
      if (limit < 0 || limit > INT_MAX) limit = 65536;
      for (int fd = 3; fd < limit; fd++)
        {
          if (fd == keep_a || fd == keep_b) continue;
          int flags = fcntl (fd, F_GETFD);
          if (flags >= 0 && (flags & FD_CLOEXEC)) close (fd);
        }
    }
}

/* spawn: allocate pty, fork, exec child with slave as ctty.
 *
 * The pattern (POSIX): posix_openpt → grantpt → unlockpt → ptsname →
 * fork → child opens slave by path, makes it ctty, dup2 to 0/1/2,
 * exec; parent keeps master.
 *
 * We pre-grant in the parent so the child doesn't need root for
 * grantpt (which can chown the slave). Slave is opened by path AFTER
 * setsid in the child — Linux uses "first tty opened by a session
 * leader without O_NOCTTY becomes the ctty" which the open() does
 * implicitly, but we also issue an explicit TIOCSCTTY for portability.
 *
 * Errors before fork: cleaned up; errors after fork in child:
 * _exit(126) for setup, _exit(127) for exec — same convention as
 * shells use for "command not found" and "command not executable",
 * so the parent's wait status is informative.
 */
static int
bp_spawn_cmd (WORD_LIST *args)
{
  if (!args || !args->next || !args->next->next)
    {
      builtin_error ("spawn needs FDVAR PIDVAR CMD [ARG ...]");
      return EX_USAGE;
    }
  char *fdvar = bp_output_name (args->word->word);
  char *pidvar = bp_output_name (args->next->word->word);
  if (!fdvar || !pidvar)
    { free (fdvar); free (pidvar); return EXECUTION_FAILURE; }
  if (strcmp (fdvar, pidvar) == 0)
    {
      builtin_error ("spawn needs distinct FDVAR and PIDVAR variables");
      free (fdvar); free (pidvar); return EX_USAGE;
    }

  WORD_LIST *cmd_list = args->next->next;
  int argc = 0;
  for (WORD_LIST *p = cmd_list; p; p = p->next) argc++;
  char **argv = malloc (((size_t) argc + 1) * sizeof *argv);
  struct bp_status *entry = calloc (1, sizeof *entry);
  int master = -1, statpipe[2] = { -1, -1 }, gate[2] = { -1, -1 };
  const char *error = "allocation";
  if (!argv || !entry) goto fail;
  int i = 0;
  for (WORD_LIST *p = cmd_list; p; p = p->next) argv[i++] = p->word->word;
  argv[argc] = NULL;

  error = "posix_openpt";
  master = posix_openpt (O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0) goto fail;
  error = "grantpt";
  if (grantpt (master) < 0) goto fail;
  error = "unlockpt";
  if (unlockpt (master) < 0) goto fail;
  char slave_path[256];
  error = "ptsname";
  int pts_error = ptsname_r (master, slave_path, sizeof slave_path);
  if (pts_error) { errno = pts_error; goto fail; }
  error = "pipe";
  if (pipe2 (statpipe, O_CLOEXEC) < 0 ||
      socketpair (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, gate) < 0) goto fail;

  struct bp_child_guard guard;
  error = "SIGCHLD guard";
  if (bp_child_guard_begin (&guard) < 0) goto fail;
  pid_t intermediate = fork ();
  if (intermediate < 0)
    { bp_child_guard_parent_end (&guard); error = "fork"; goto fail; }
  if (intermediate == 0)
    {
      bp_child_guard_child_end (&guard);
      close (master);
      close (statpipe[0]);
      close (gate[1]);
      bp_clear_statuses ();
      bp_close_cloexec (statpipe[1], gate[0]);
      /* A closed status reader must not kill the target's reaper. */
      struct sigaction ignore;
      memset (&ignore, 0, sizeof ignore);
      ignore.sa_handler = SIG_IGN;
      sigemptyset (&ignore.sa_mask);
      sigaction (SIGPIPE, &ignore, NULL);
      struct bp_child_guard target_guard;
      if (bp_child_guard_begin (&target_guard) < 0) _exit (126);
      pid_t target = fork ();
      if (target < 0) _exit (126);
      if (target == 0)
        {
          bp_child_guard_child_end (&target_guard);
          close (statpipe[1]);
          /* Do not start an unreturnable child if output binding fails. */
          char ready;
          if (bp_read_exact (gate[0], &ready, 1) < 0 || ready != 'G') _exit (126);
          close (gate[0]);
          if (setsid () < 0)
            { dprintf (2, "pty spawn child: setsid: %s\n", strerror (errno)); _exit (126); }
          int slave = open (slave_path, O_RDWR);
          if (slave < 0)
            { dprintf (2, "pty spawn child: open(%s): %s\n", slave_path, strerror (errno)); _exit (126); }
          if (ioctl (slave, TIOCSCTTY, 0) < 0)
            { dprintf (2, "pty spawn child: TIOCSCTTY: %s\n", strerror (errno)); _exit (126); }
          if (dup2 (slave, 0) < 0 || dup2 (slave, 1) < 0 || dup2 (slave, 2) < 0)
            { dprintf (2, "pty spawn child: dup2: %s\n", strerror (errno)); _exit (126); }
          if (slave > 2) close (slave);
          bos_prepare_child ();
          bos_run_builtin (argv[0], argv, NULL);
          execvp (argv[0], argv);
          dprintf (2, "pty spawn child: execvp(%s): %s\n", argv[0], strerror (errno));
          _exit (127);
        }
      close (gate[0]);
      ssize_t n;
      do { n = write (statpipe[1], &target, sizeof target); }
      while (n < 0 && errno == EINTR);
      /* Even if the caller vanished, reap the target after gate EOF. */
      int status = 0;
      pid_t waited;
      do { waited = waitpid (target, &status, 0); }
      while (waited < 0 && errno == EINTR);
      int exit_code = waited == target && WIFEXITED (status) ? WEXITSTATUS (status)
                    : waited == target && WIFSIGNALED (status) ? 128 + WTERMSIG (status)
                    : 1;
      do { n = write (statpipe[1], &exit_code, sizeof exit_code); }
      while (n < 0 && errno == EINTR);
      close (statpipe[1]);
      _exit (0);
    }

  close (statpipe[1]); statpipe[1] = -1;
  close (gate[0]); gate[0] = -1;
  error = "target PID handoff";
  int handoff = bp_read_exact (statpipe[0], &entry->target_pid, sizeof entry->target_pid);
  bp_child_guard_parent_end (&guard);
  if (handoff < 0) { errno = EIO; goto fail; }
  /* The public API uses PIDs. Refuse reuse while an older result with the
     same PID is still retained, before either output variable is changed. */
  for (struct bp_status *old = bp_statuses; old; old = old->next)
    if (old->target_pid == entry->target_pid)
      { error = "target PID still has an unconsumed status"; errno = EEXIST; goto fail; }
  error = "output variable binding";
  if (bp_bind_number (fdvar, master) < 0 || bp_bind_number (pidvar, entry->target_pid) < 0)
    { errno = EINVAL; goto fail; }
  error = "child start handoff";
  ssize_t n;
  do { n = send (gate[1], "G", 1, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
  if (n != 1) goto fail;
  close (gate[1]);
  entry->pipe_fd = statpipe[0];
  entry->next = bp_statuses;
  bp_statuses = entry;
  free (argv); free (fdvar); free (pidvar);
  return EXECUTION_SUCCESS;

fail:
  {
    int saved = errno;
    if (master >= 0) close (master);
    for (int i = 0; i < 2; i++)
      { if (statpipe[i] >= 0) close (statpipe[i]); if (gate[i] >= 0) close (gate[i]); }
    free (entry); free (argv); free (fdvar); free (pidvar);
    builtin_error ("spawn: %s: %s", error, strerror (saved));
    return EXECUTION_FAILURE;
  }
}

/* waitpid: read the target's exit status from the pipe stashed by
 * the matching `pty spawn`. Direct waitpid(2) doesn't work
 * because bash's interactive SIGCHLD handler reaps spawn'd children
 * eagerly — by the time userspace gets a chance to call waitpid,
 * ECHILD. The double-fork in spawn moves the actual target one level
 * down (parented by an intermediate that bash CAN reap), and pipes
 * the status back here.
 *
 * Exit status convention matches the shell: 0..255 for clean exit,
 * 128 + signum for signal death.
 */
static int
bp_waitpid_cmd (WORD_LIST *args)
{
  if (!args || (args->next && args->next->next))
    { builtin_error ("waitpid needs PID [STATUSVAR]"); return EX_USAGE; }
  char *end;
  errno = 0;
  long number = strtol (args->word->word, &end, 10);
  if (errno || !*args->word->word || *end || number <= 0 || number > INT_MAX)
    { builtin_error ("waitpid: invalid PID: %s", args->word->word); return EX_USAGE; }
  pid_t pid = (pid_t) number;
  struct bp_status **slot = &bp_statuses;
  while (*slot && (*slot)->target_pid != pid) slot = &(*slot)->next;
  if (!*slot)
    {
      builtin_error ("waitpid %d: no owned status (was this PID spawned in this shell?)", (int) pid);
      return EXECUTION_FAILURE;
    }
  char *statusvar = args->next ? bp_output_name (args->next->word->word) : NULL;
  if (args->next && !statusvar) return EXECUTION_FAILURE;
  struct bp_status *entry = *slot;
  while (entry->received < sizeof entry->exit_code)
    {
      /* Leave the status available for a later call when a trap interrupts
         the wait. A bounded poll also handles SA_RESTART signal handlers. */
      int sig = terminating_signal ? terminating_signal
              : interrupt_state ? SIGINT : first_pending_trap ();
      if (sig > 0)
        { free (statusvar); return 128 + sig; }
      struct pollfd pfd = { .fd = entry->pipe_fd, .events = POLLIN };
      int ready = poll (&pfd, 1, 100);
      if (ready < 0 && errno == EINTR) continue;
      if (!ready) continue;
      ssize_t n = ready < 0 ? -1 : read (entry->pipe_fd,
                  (char *) &entry->exit_code + entry->received,
                  sizeof entry->exit_code - entry->received);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0)
        {
          builtin_error ("waitpid %d: incomplete status from intermediate", (int) pid);
          *slot = entry->next;
          close (entry->pipe_fd); free (entry); free (statusvar);
          return EXECUTION_FAILURE;
        }
      entry->received += n;
    }
  if (statusvar && bp_bind_number (statusvar, entry->exit_code) < 0)
    { free (statusvar); return EXECUTION_FAILURE; }
  int exit_code = entry->exit_code;
  *slot = entry->next;
  close (entry->pipe_fd); free (entry); free (statusvar);
  return exit_code;
}

/* echo FD on|off — toggle ECHO/ECHOE/ECHOK/ECHONL on the line
   discipline backing FD (master pty fd works on Linux because both
   ends share line-discipline state). Used by expect.sh for password
   prompts. */
static int
bp_echo_cmd (WORD_LIST *args)
{
  if (!args || !args->next)
    { builtin_error ("echo needs FD on|off"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  const char *mode = args->next->word->word;
  int on;
  if      (strcmp (mode, "on")  == 0 || strcmp (mode, "1") == 0) on = 1;
  else if (strcmp (mode, "off") == 0 || strcmp (mode, "0") == 0) on = 0;
  else { builtin_error ("echo: mode must be on|off (got '%s')", mode); return EX_USAGE; }

  struct termios tio;
  if (tcgetattr (fd, &tio) < 0)
    { builtin_error ("tcgetattr: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (on)
    tio.c_lflag |=  (ECHO | ECHOE | ECHOK | ECHONL);
  else
    tio.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
  if (tcsetattr (fd, TCSANOW, &tio) < 0)
    { builtin_error ("tcsetattr: %s", strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

/* resize FD -W cols -H rows — set winsize on master fd; kernel
   delivers SIGWINCH to the foreground process group on the slave.
   Also accepts positional FD COLS ROWS form for terseness. */
static int
bp_resize_cmd (WORD_LIST *args)
{
  if (!args)
    { builtin_error ("resize needs FD -W COLS -H ROWS (or FD COLS ROWS)"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  int cols = -1, rows = -1;
  WORD_LIST *p = args->next;

  /* Try positional first: FD COLS ROWS */
  if (p && p->next && p->word->word[0] != '-')
    {
      cols = atoi (p->word->word);
      rows = atoi (p->next->word->word);
    }
  else
    {
      for (; p; p = p->next)
        {
          const char *w = p->word->word;
          if      ((!strcmp (w, "-W") || !strcmp (w, "--cols")) && p->next)
            { cols = atoi (p->next->word->word); p = p->next; }
          else if ((!strcmp (w, "-H") || !strcmp (w, "--rows")) && p->next)
            { rows = atoi (p->next->word->word); p = p->next; }
          else
            { builtin_error ("resize: unknown arg '%s'", w); return EX_USAGE; }
        }
    }
  if (cols <= 0 || rows <= 0)
    { builtin_error ("resize: cols and rows must be > 0 (got %d %d)", cols, rows); return EX_USAGE; }

  struct winsize ws = { .ws_row = (unsigned short) rows,
                        .ws_col = (unsigned short) cols,
                        .ws_xpixel = 0, .ws_ypixel = 0 };
  if (ioctl (fd, TIOCSWINSZ, &ws) < 0)
    { builtin_error ("TIOCSWINSZ: %s", strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

static WORD_LIST *
bp_arg_at (WORD_LIST *args, int index)
{
  WORD_LIST *p = args;
  for (int i = 0; p && i < index; i++)
    p = p->next;
  return p;
}

static int
bp_parse_int_arg (const char *s, const char *what, int *out)
{
  char *end = NULL;
  long v;
  errno = 0;
  v = strtol (s, &end, 0);
  if (errno || end == s || *end != '\0')
    {
      builtin_error ("set-ldisc: invalid %s: %s", what, s);
      return -1;
    }
  *out = (int) v;
  return 0;
}

static int
bp_parse_ulong_arg (const char *s, const char *what, unsigned long *out)
{
  char *end = NULL;
  unsigned long v;
  errno = 0;
  v = strtoul (s, &end, 0);
  if (errno || end == s || *end != '\0')
    {
      builtin_error ("set-ldisc: invalid %s: %s", what, s);
      return -1;
    }
  *out = v;
  return 0;
}

static int
bp_speed_constant (int speed, speed_t *out)
{
  switch (speed)
    {
    case 0: *out = B0; return 0;
#ifdef B50
    case 50: *out = B50; return 0;
#endif
#ifdef B75
    case 75: *out = B75; return 0;
#endif
#ifdef B110
    case 110: *out = B110; return 0;
#endif
#ifdef B134
    case 134: *out = B134; return 0;
#endif
#ifdef B150
    case 150: *out = B150; return 0;
#endif
#ifdef B200
    case 200: *out = B200; return 0;
#endif
#ifdef B300
    case 300: *out = B300; return 0;
#endif
#ifdef B600
    case 600: *out = B600; return 0;
#endif
#ifdef B1200
    case 1200: *out = B1200; return 0;
#endif
#ifdef B1800
    case 1800: *out = B1800; return 0;
#endif
#ifdef B2400
    case 2400: *out = B2400; return 0;
#endif
#ifdef B4800
    case 4800: *out = B4800; return 0;
#endif
#ifdef B9600
    case 9600: *out = B9600; return 0;
#endif
#ifdef B19200
    case 19200: *out = B19200; return 0;
#endif
#ifdef B38400
    case 38400: *out = B38400; return 0;
#endif
#ifdef B57600
    case 57600: *out = B57600; return 0;
#endif
#ifdef B115200
    case 115200: *out = B115200; return 0;
#endif
#ifdef B230400
    case 230400: *out = B230400; return 0;
#endif
#ifdef B460800
    case 460800: *out = B460800; return 0;
#endif
#ifdef B500000
    case 500000: *out = B500000; return 0;
#endif
#ifdef B576000
    case 576000: *out = B576000; return 0;
#endif
#ifdef B921600
    case 921600: *out = B921600; return 0;
#endif
#ifdef B1000000
    case 1000000: *out = B1000000; return 0;
#endif
#ifdef B1152000
    case 1152000: *out = B1152000; return 0;
#endif
#ifdef B1500000
    case 1500000: *out = B1500000; return 0;
#endif
#ifdef B2000000
    case 2000000: *out = B2000000; return 0;
#endif
#ifdef B2500000
    case 2500000: *out = B2500000; return 0;
#endif
#ifdef B3000000
    case 3000000: *out = B3000000; return 0;
#endif
#ifdef B3500000
    case 3500000: *out = B3500000; return 0;
#endif
#ifdef B4000000
    case 4000000: *out = B4000000; return 0;
#endif
    default:
      return -1;
    }
}

static int
bp_have_cap_sys_admin (void)
{
  FILE *fp = fopen ("/proc/self/status", "r");
  if (!fp)
    return 0;

  char line[256];
  int have = 0;
  while (fgets (line, sizeof line, fp))
    {
      if (strncmp (line, "CapEff:", 7) == 0)
        {
          char *p = line + 7;
          while (*p == ' ' || *p == '\t') p++;
          errno = 0;
          unsigned long long caps = strtoull (p, NULL, 16);
          if (!errno && (caps & (1ULL << 21)) != 0)
            have = 1;
          break;
        }
    }
  fclose (fp);
  return have;
}

static int
bp_set_ldisc_cmd (WORD_LIST *args)
{
  if (!args || !args->next)
    {
      builtin_error ("set-ldisc needs LDISC DEVICE [SPEED|-] [CSIZE|-] [PARITY|-] [STOPBITS|-] [IFLAG_SET|-] [IFLAG_CLEAR|-]");
      return EX_USAGE;
    }

  int ldisc = 0;
  if (bp_parse_int_arg (args->word->word, "line discipline", &ldisc) < 0)
    return EX_USAGE;
  const char *device = args->next->word->word;

  const char *speed_s = bp_arg_at (args, 2) ? bp_arg_at (args, 2)->word->word : "-";
  const char *csize_s = bp_arg_at (args, 3) ? bp_arg_at (args, 3)->word->word : "-";
  const char *parity_s = bp_arg_at (args, 4) ? bp_arg_at (args, 4)->word->word : "-";
  const char *stop_s = bp_arg_at (args, 5) ? bp_arg_at (args, 5)->word->word : "-";
  const char *iflag_set_s = bp_arg_at (args, 6) ? bp_arg_at (args, 6)->word->word : "-";
  const char *iflag_clear_s = bp_arg_at (args, 7) ? bp_arg_at (args, 7)->word->word : "-";

  int fd = open (device, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0)
    {
      builtin_error ("set-ldisc: open %s: %s", device, strerror (errno));
      return EXECUTION_FAILURE;
    }

  struct stat st;
  if (fstat (fd, &st) < 0)
    {
      builtin_error ("set-ldisc: fstat %s: %s", device, strerror (errno));
      close (fd);
      return EXECUTION_FAILURE;
    }
  if (!S_ISCHR (st.st_mode) || !isatty (fd))
    {
      builtin_error ("set-ldisc: %s is not a serial line", device);
      close (fd);
      return EXECUTION_FAILURE;
    }

  if (!bp_have_cap_sys_admin ())
    {
      builtin_error ("set-ldisc: cannot set line discipline: Operation not permitted");
      close (fd);
      return EXECUTION_FAILURE;
    }

  int need_termios = 0;
  int speed = -1, csize = 0, stopbits = 0;
  unsigned long iflag_set = 0, iflag_clear = 0;
  speed_t speed_const = 0;

  if (speed_s && strcmp (speed_s, "-") != 0)
    {
      if (bp_parse_int_arg (speed_s, "speed", &speed) < 0)
        { close (fd); return EX_USAGE; }
      if (bp_speed_constant (speed, &speed_const) < 0)
        {
          builtin_error ("set-ldisc: unsupported speed: %d", speed);
          close (fd);
          return EX_USAGE;
        }
      need_termios = 1;
    }
  if (csize_s && strcmp (csize_s, "-") != 0)
    {
      if (bp_parse_int_arg (csize_s, "character size", &csize) < 0)
        { close (fd); return EX_USAGE; }
      if (csize != 7 && csize != 8)
        {
          builtin_error ("set-ldisc: character size must be 7 or 8");
          close (fd);
          return EX_USAGE;
        }
      need_termios = 1;
    }
  if (parity_s && strcmp (parity_s, "-") != 0)
    {
      if (strcmp (parity_s, "none") != 0 && strcmp (parity_s, "even") != 0
          && strcmp (parity_s, "odd") != 0)
        {
          builtin_error ("set-ldisc: parity must be none|even|odd");
          close (fd);
          return EX_USAGE;
        }
      need_termios = 1;
    }
  if (stop_s && strcmp (stop_s, "-") != 0)
    {
      if (bp_parse_int_arg (stop_s, "stop bits", &stopbits) < 0)
        { close (fd); return EX_USAGE; }
      if (stopbits != 1 && stopbits != 2)
        {
          builtin_error ("set-ldisc: stop bits must be 1 or 2");
          close (fd);
          return EX_USAGE;
        }
      need_termios = 1;
    }
  if (iflag_set_s && strcmp (iflag_set_s, "-") != 0)
    {
      if (bp_parse_ulong_arg (iflag_set_s, "iflag set mask", &iflag_set) < 0)
        { close (fd); return EX_USAGE; }
      need_termios = 1;
    }
  if (iflag_clear_s && strcmp (iflag_clear_s, "-") != 0)
    {
      if (bp_parse_ulong_arg (iflag_clear_s, "iflag clear mask", &iflag_clear) < 0)
        { close (fd); return EX_USAGE; }
      need_termios = 1;
    }

  if (need_termios)
    {
      struct termios tio;
      if (tcgetattr (fd, &tio) < 0)
        {
          builtin_error ("set-ldisc: tcgetattr %s: %s", device, strerror (errno));
          close (fd);
          return EXECUTION_FAILURE;
        }
      if (speed >= 0)
        {
          if (cfsetispeed (&tio, speed_const) < 0 || cfsetospeed (&tio, speed_const) < 0)
            {
              builtin_error ("set-ldisc: cfsetspeed %d: %s", speed, strerror (errno));
              close (fd);
              return EXECUTION_FAILURE;
            }
        }
      if (csize)
        {
          tio.c_cflag &= ~CSIZE;
          tio.c_cflag |= (csize == 7) ? CS7 : CS8;
        }
      if (parity_s && strcmp (parity_s, "-") != 0)
        {
          if (strcmp (parity_s, "none") == 0)
            tio.c_cflag &= ~(PARENB | PARODD);
          else if (strcmp (parity_s, "even") == 0)
            {
              tio.c_cflag |= PARENB;
              tio.c_cflag &= ~PARODD;
            }
          else
            tio.c_cflag |= (PARENB | PARODD);
        }
      if (stopbits)
        {
          if (stopbits == 2)
            tio.c_cflag |= CSTOPB;
          else
            tio.c_cflag &= ~CSTOPB;
        }
      tio.c_iflag |= (tcflag_t) iflag_set;
      tio.c_iflag &= ~((tcflag_t) iflag_clear);
      if (tcsetattr (fd, TCSANOW, &tio) < 0)
        {
          builtin_error ("set-ldisc: tcsetattr %s: %s", device, strerror (errno));
          close (fd);
          return EXECUTION_FAILURE;
        }
    }

  if (ioctl (fd, TIOCSETD, &ldisc) < 0)
    {
      builtin_error ("set-ldisc: TIOCSETD %s: %s", device, strerror (errno));
      close (fd);
      return EXECUTION_FAILURE;
    }

  close (fd);
  return EXECUTION_SUCCESS;
}

int
pty_builtin (WORD_LIST *list)
{
  bp_check_owner ();
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "setsid")     == 0) return bp_setsid_cmd (args);
  if (strcmp (cmd, "open-tty")   == 0) return bp_open_tty_cmd (args);
  if (strcmp (cmd, "isatty")     == 0) return bp_isatty_cmd (args);
  if (strcmp (cmd, "tty-name")   == 0) return bp_ttyname_cmd (args);
  if (strcmp (cmd, "foreground") == 0) return bp_foreground_cmd (args);
  if (strcmp (cmd, "close")      == 0) return bp_close_cmd (args);
  if (strcmp (cmd, "spawn")      == 0) return bp_spawn_cmd (args);
  if (strcmp (cmd, "waitpid")    == 0) return bp_waitpid_cmd (args);
  if (strcmp (cmd, "echo")       == 0) return bp_echo_cmd (args);
  if (strcmp (cmd, "resize")     == 0) return bp_resize_cmd (args);
  if (strcmp (cmd, "set-ldisc")  == 0) return bp_set_ldisc_cmd (args);
  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *pty_doc[] = {
  "TTY + session management primitives for bash-os getty / login.",
  "",
  "    pty setsid",
  "        Become a new session leader (no controlling tty).",
  "    pty open-tty PATH [FDVAR]",
  "        Open PATH (a /dev/tty*) and install as controlling tty.",
  "        Default: dup2 to 0/1/2. With FDVAR: bind $FDVAR, leave",
  "        stdio alone.",
  "    pty isatty FD",
  "        Exit 0 if FD is a terminal.",
  "    pty tty-name FD",
  "        Print the device path of the tty backing FD.",
  "    pty foreground PGRP [FD]",
  "        tcsetpgrp — give PGRP the foreground (FD defaults to 0).",
  "    pty close FD",
  "        close(2) wrapper.",
  "    pty spawn FDVAR PIDVAR CMD [ARG ...]",
  "        Fork+exec CMD on a fresh pty. Master fd → $FDVAR,",
  "        child pid → $PIDVAR. Used by /bash-os/expect.sh.",
  "    pty waitpid PID [STATUSVAR]",
  "        Blocking waitpid(2) on PID; sets $? (and $STATUSVAR) to",
  "        the child's exit status. Use this for spawn'd children —",
  "        bash's `wait` builtin doesn't see them. Concurrent spawns retain",
  "        independent statuses; waitpid is restricted to the spawning shell.",
  "        A trapped signal returns 128+signal without consuming the status.",
  "        Output variables must be writable scalars (simple namerefs work).",
  "    pty echo FD on|off",
  "        Toggle ECHO/ECHOE/ECHOK/ECHONL on FD's line discipline.",
  "        On a spawn'd master fd, this affects what the child sees",
  "        (echo on / off for password prompts).",
  "    pty resize FD -W COLS -H ROWS",
  "        TIOCSWINSZ on FD. Kernel sends SIGWINCH to the slave's",
  "        foreground process group. Also accepts FD COLS ROWS positional.",
  "    pty set-ldisc LDISC DEVICE [SPEED|-] [CSIZE|-] [PARITY|-]",
  "        [STOPBITS|-] [IFLAG_SET|-] [IFLAG_CLEAR|-]",
  "        Gated TIOCSETD + optional termios setup for ldattach.",
  "",
  "Typical getty flow:",
  "    ( pty setsid; pty open-tty /dev/ttyS0; exec login ) &",
  (char *)NULL
};

struct builtin pty_struct = {
  "pty",
  pty_builtin,
  BUILTIN_ENABLED,
  pty_doc,
  "pty setsid|open-tty|isatty|tty-name|foreground|close|spawn|waitpid|echo|resize|set-ldisc ARGS...",
  0
};
