/* SPDX-License-Identifier: MIT */
/* watch.c — periodic command repeat (watch(1) subset). Loadable for bash.
 *
 * Procps-ng's watch(1) and BusyBox's watch.c implement the "rerun this
 * command every N seconds and clear the screen between runs" pattern
 * that is central to ops debugging. watch ships the same minimal
 * surface as a bash builtin so bash-os doesn't need a separate watch
 * binary on PATH.
 *
 * Verbs:
 *     watch CMD [ARGS...]              run every 2 seconds (default)
 *     watch -n SEC CMD [ARGS...]       run every SEC seconds
 *     watch -x CMD [ARGS...]           execvp CMD directly (no sh -c)
 *     watch -b CMD [ARGS...]           write BEL when CMD exits non-zero
 *     watch -e CMD [ARGS...]           exit when CMD exits non-zero
 *     watch -g CMD [ARGS...]           exit when CMD output changes
 *     watch -d CMD [ARGS...]           highlight cells that differ
 *                                          from the previous iteration
 *                                          (procps watch -d / --differences)
 *     watch -t|--no-title CMD [...]    accept procps no-title flag
 *                                          (no-op: watch never emits a
 *                                          title row)
 *     watch -p|--precise CMD [...]     accept procps precise flag
 *                                          (no-op: cadence is already
 *                                          absolute-deadline based)
 *     watch -C FILE CMD [ARGS...]      tee each iteration's rendered
 *                                          output (with SGR diff escapes
 *                                          when -d is also set) to FILE
 *                                          for test capture; the file is
 *                                          truncated on start, each
 *                                          iteration appended with a
 *                                          `--- iteration N ---\n` marker
 *
 * Without -x, the remaining words are joined with single spaces and fed
 * to `sh -c "<joined>"`, matching procps watch behavior so that shell
 * metacharacters in the CMD string work. With -x, the words are passed
 * to execvp(CMD, [CMD, ARGS...]) verbatim, bypassing the shell — same
 * semantic as `watch -x`.
 *
 * SEC accepts a fractional value (e.g. 0.5). The inter-iteration delay
 * is computed from CLOCK_MONOTONIC absolute deadlines via
 * clock_nanosleep(TIMER_ABSTIME), so cadence does not drift when a
 * command takes variable time.
 *
 * SIGINT (Ctrl-C) terminates the watch loop cleanly: the parent
 * catches SIGINT, marks a stop flag, kills the in-flight child if any
 * (so we don't block in waitpid), and exits with EXECUTION_SUCCESS.
 * SIGCHLD is reset to SIG_DFL across the fork (same workaround
 * pattern as nohup) so bash's async SIGCHLD handler can't reap the
 * child before our waitpid sees it.
 *
 * Diff-highlight (-d): each iteration's stdout is captured, compared
 * byte-for-byte against the previous iteration's buffer (positionally,
 * starting at offset 0), and bytes that differ get wrapped in SGR
 * reverse-video escapes (CSI 7m / CSI 27m) — the same standout
 * sequence procps watch emits via terminfo `smso`. Bytes past the
 * shorter of the two buffers are also flagged as changed. The
 * comparison is cell-equivalent for ASCII; multi-byte sequences are
 * still byte-aligned (good enough for "did the value change" pinning;
 * for full grapheme-cluster awareness see procps watch.c).
 *
 * Capture (-C FILE): writes each iteration's rendered output (with
 * SGR escapes when -d is on) into FILE after a `--- iteration N ---\n`
 * separator. The file is truncated on start so test consumers see only
 * this run's frames. Capture is independent of stdout; the live tty
 * still gets cleared+rewritten as usual.
 *
 * Procps compatibility no-ops:
 *     -t / --no-title    accepted; watch never emits a title row
 *     -p / --precise     accepted; watch already uses TIMER_ABSTIME
 *                         absolute-deadline scheduling
 *
 * Source counterparts:
 *     research/refs/procps-ng/watch.c        (canonical)
 *     research/refs/busybox/util-linux/watch.c
 *
 * Companion wrapper:
 *     /bash-os/watch.sh                        (POSIX command-name shim)
 *
 * --- LICENSE ---
 * MIT License
 *
 * Copyright (c) 2026 bash_linux contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "loadables.h"
#include "command-run.h"

static volatile sig_atomic_t bw_stop = 0;
static volatile sig_atomic_t bw_child_pid = 0;

/* -d / -C state. bw_prev_buf holds the previous iteration's raw
   captured stdout for byte-positional comparison; bw_cap_fd is the
   append-mode descriptor to the capture file (or -1 when unset). */
static int bw_diff_mode = 0;
static int bw_beep_mode = 0;
static int bw_errexit_mode = 0;
static int bw_chgexit_mode = 0;
static int bw_cap_fd = -1;
static char *bw_prev_buf = NULL;
static size_t bw_prev_len = 0;
static unsigned long bw_iter = 0;

static void
bw_normalize_long_options (WORD_LIST *list)
{
  for (WORD_LIST *p = list; p && p->word && p->word->word; p = p->next)
    {
      char *w = p->word->word;
      if (w[0] != '-' || w[1] == '\0')
        break;
      if (strcmp (w, "--") == 0)
        break;
      if (strcmp (w, "--no-title") == 0)
        {
          w[1] = 't';
          w[2] = '\0';
        }
      else if (strcmp (w, "--precise") == 0)
        {
          w[1] = 'p';
          w[2] = '\0';
        }
      if ((strcmp (w, "-n") == 0 || strcmp (w, "-C") == 0) && p->next)
        p = p->next;
    }
}

static void
bw_sigint_handler (int signo)
{
  (void) signo;
  bw_stop = 1;
  pid_t cp = bw_child_pid;
  if (cp > 0)
    (void) kill (cp, SIGTERM);
}

/* Parse "<secs>[.<nanos>]" with locale-independent '.' separator into
   a struct timespec. Returns 0 on success, -1 on failure (caller has
   already prefixed flag context to its error message). */
static int
bw_parse_interval (const char *s, struct timespec *out, const char *flag)
{
  if (s == 0 || *s == '\0')
    { builtin_error ("%s: empty interval", flag); return -1; }

  long long secs = 0;
  long nanos = 0;
  const char *p = s;
  int seen_digit = 0;

  while (*p >= '0' && *p <= '9')
    { secs = secs * 10 + (*p - '0'); p++; seen_digit = 1; }

  if (*p == '.')
    {
      p++;
      int digits = 0;
      while (*p >= '0' && *p <= '9' && digits < 9)
        { nanos = nanos * 10 + (*p - '0'); p++; digits++; seen_digit = 1; }
      while (digits < 9) { nanos *= 10; digits++; }
      /* Sub-ns precision is silently truncated. */
      while (*p >= '0' && *p <= '9') p++;
    }

  if (!seen_digit || (*p != '\0' && *p != '\n'))
    { builtin_error ("%s: bad seconds: %s", flag, s); return -1; }
  if (secs == 0 && nanos == 0)
    { builtin_error ("%s: interval must be > 0", flag); return -1; }
  if (secs > 86400)
    { builtin_error ("%s: interval too large (>1d): %s", flag, s); return -1; }

  out->tv_sec = (time_t) secs;
  out->tv_nsec = nanos;
  return 0;
}

/* Emit CSI 2J (erase screen) + CSI H (cursor home) when stdout is a
   tty. Non-tty stdout (test capture, piped consumer) gets no clear
   sequence — same procps watch behavior, keeps captured output clean
   for downstream parsers. */
static void
bw_clear_screen (void)
{
  if (isatty (STDOUT_FILENO))
    {
      static const char seq[] = "\033[H\033[2J";
      ssize_t w = write (STDOUT_FILENO, seq, sizeof seq - 1);
      (void) w;
    }
}

/* Slurp the parent end of a pipe into a heap buffer until EOF (writer
   side closed). Returns 0 on success and writes the buffer/length back
   through out_buf / out_len; the buffer is malloc'd and must be freed
   by the caller. On allocation failure returns -1 and leaves *out_buf
   = NULL. */
static int
bw_slurp_pipe (int fd, char **out_buf, size_t *out_len)
{
  size_t cap = 4096, len = 0;
  char *buf = malloc (cap);
  if (!buf) { *out_buf = NULL; *out_len = 0; return -1; }
  for (;;)
    {
      if (len + 1024 > cap)
        {
          size_t ncap = cap * 2;
          char *nb = realloc (buf, ncap);
          if (!nb) { free (buf); *out_buf = NULL; *out_len = 0; return -1; }
          buf = nb;
          cap = ncap;
        }
      ssize_t r = read (fd, buf + len, cap - len);
      if (r < 0)
        {
          if (errno == EINTR) continue;
          break;
        }
      if (r == 0) break;
      len += (size_t) r;
    }
  *out_buf = buf;
  *out_len = len;
  return 0;
}

/* Render src/srclen with SGR diff highlighting against bw_prev_buf.
   On first iteration (bw_prev_buf == NULL) emits src verbatim. Bytes
   past the shorter buffer (either truncation or growth) are flagged
   as changed. Writes the rendered bytes to fd. Returns 0 on success
   or -1 on a fatal write failure. */
static int
bw_write_diff (int fd, const char *src, size_t srclen)
{
  static const char on[]  = "\033[7m";
  static const char off[] = "\033[27m";
  int in_run = 0;
  size_t i = 0;
  while (i < srclen)
    {
      int differ;
      if (bw_prev_buf == NULL)
        differ = 0;
      else if (i >= bw_prev_len)
        differ = 1;
      else
        differ = (src[i] != bw_prev_buf[i]);
      if (differ && !in_run)
        {
          if (write (fd, on, sizeof on - 1) < 0) return -1;
          in_run = 1;
        }
      else if (!differ && in_run)
        {
          if (write (fd, off, sizeof off - 1) < 0) return -1;
          in_run = 0;
        }
      if (write (fd, src + i, 1) < 0) return -1;
      i++;
    }
  if (in_run)
    {
      if (write (fd, off, sizeof off - 1) < 0) return -1;
    }
  return 0;
}

/* Append `--- iteration N ---\n` + the iteration's rendered output to
   the capture file. Errors are non-fatal (warning only); we don't
   abort the watch loop because of a transient capture-file IO problem.
   Render uses diff escapes when bw_diff_mode is set, even if the
   capture file isn't a tty — the test harness wants the escapes
   visible. */
static void
bw_capture_iteration (const char *buf, size_t len)
{
  if (bw_cap_fd < 0) return;
  char hdr[64];
  int hlen = snprintf (hdr, sizeof hdr, "--- iteration %lu ---\n", bw_iter);
  if (hlen < 0 || hlen >= (int) sizeof hdr) return;
  if (write (bw_cap_fd, hdr, (size_t) hlen) < 0)
    return;
  if (bw_diff_mode)
    (void) bw_write_diff (bw_cap_fd, buf, len);
  else
    {
      size_t off = 0;
      while (off < len)
        {
          ssize_t w = write (bw_cap_fd, buf + off, len - off);
          if (w < 0)
            {
              if (errno == EINTR) continue;
              return;
            }
          off += (size_t) w;
        }
    }
}

static int
bw_output_changed (const char *buf, size_t len)
{
  if (bw_prev_buf == NULL)
    return 0;
  if (len != bw_prev_len)
    return 1;
  if (len == 0)
    return 0;
  return memcmp (buf, bw_prev_buf, len) != 0;
}

/* Fork+exec one iteration of the watched command. Returns 0 when the
   watch loop should continue, 1 when -e requested exit after a child
   failure, 2 when -g requested successful exit after an output change,
   and -1 on a hard error (fork failed) that should abort the watch loop.
   Without -e, non-zero child exit status does NOT abort the loop —
   watch(1) intentionally keeps running.

   When -d (diff highlight), -g (chgexit), or -C (capture-file) is in effect,
   the child's stdout is piped through the parent so we can render diff
   escapes / tee to the capture file. The cheap path (no -d, no -g, no -C)
   leaves the child's stdout inherited untouched. */
static int
bw_run_iteration (char **argv, int exec_form)
{
  struct sigaction chld_dfl, chld_save;
  memset (&chld_dfl, 0, sizeof chld_dfl);
  chld_dfl.sa_handler = SIG_DFL;
  sigemptyset (&chld_dfl.sa_mask);
  sigaction (SIGCHLD, &chld_dfl, &chld_save);
  sigset_t chld_set, old_set;
  sigemptyset (&chld_set);
  sigaddset (&chld_set, SIGCHLD);
  if (sigprocmask (SIG_BLOCK, &chld_set, &old_set) < 0)
    {
      sigaction (SIGCHLD, &chld_save, NULL);
      return -1;
    }

  int capture_pipe = (bw_diff_mode || bw_chgexit_mode || bw_cap_fd >= 0);
  int pfd[2] = { -1, -1 };
  if (capture_pipe && pipe (pfd) < 0)
    {
      builtin_error ("pipe: %s", strerror (errno));
      sigprocmask (SIG_SETMASK, &old_set, NULL);
      sigaction (SIGCHLD, &chld_save, NULL);
      return -1;
    }

  pid_t pid = fork ();
  if (pid < 0)
    {
      builtin_error ("fork: %s", strerror (errno));
      if (capture_pipe) { close (pfd[0]); close (pfd[1]); }
      sigprocmask (SIG_SETMASK, &old_set, NULL);
      sigaction (SIGCHLD, &chld_save, NULL);
      return -1;
    }
  if (pid == 0)
    {
      sigprocmask (SIG_SETMASK, &old_set, NULL);
      /* Child: restore SIGINT to default disposition so Ctrl-C can
         terminate the running command. Parent still has its own SIGINT
         handler installed and will break out of the loop on the next
         iteration check. */
      signal (SIGINT, SIG_DFL);

      if (capture_pipe)
        {
          close (pfd[0]);
          dup2 (pfd[1], STDOUT_FILENO);
          if (pfd[1] != STDOUT_FILENO) close (pfd[1]);
        }

      bos_prepare_child ();
      if (exec_form) {
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
      }
      else
        {
          char *sh_argv[] = { (char *) "sh", (char *) "-c", argv[0], NULL };
          char *eval_argv[] = {"eval", argv[0], NULL};
          bos_run_builtin ("eval", eval_argv, NULL);
          execvp (sh_argv[0], sh_argv);
        }
      int err = errno;
      fprintf (stderr, "watch: %s: %s\n", argv[0], strerror (err));
      _exit (err == ENOENT ? 127 : 126);
    }

  bw_child_pid = pid;

  char *cur_buf = NULL;
  size_t cur_len = 0;
  int changed = 0;
  if (capture_pipe)
    {
      close (pfd[1]);
      (void) bw_slurp_pipe (pfd[0], &cur_buf, &cur_len);
      close (pfd[0]);
      bw_iter++;
      changed = bw_output_changed (cur_buf, cur_len);
      bw_capture_iteration (cur_buf, cur_len);
      /* Mirror to real stdout so the live tty still sees the frame.
         Diff escapes only emitted when -d is on. */
      if (bw_diff_mode)
        (void) bw_write_diff (STDOUT_FILENO, cur_buf, cur_len);
      else if (cur_len)
        {
          size_t off = 0;
          while (off < cur_len)
            {
              ssize_t w = write (STDOUT_FILENO, cur_buf + off, cur_len - off);
              if (w < 0) { if (errno == EINTR) continue; break; }
              off += (size_t) w;
            }
        }
      free (bw_prev_buf);
      bw_prev_buf = cur_buf;
      bw_prev_len = cur_len;
    }

  int status = 0;
  for (;;)
    {
      pid_t wrc = waitpid (pid, &status, 0);
      if (wrc < 0)
        {
          if (errno == EINTR)
            {
              /* SIGINT during waitpid: handler already sent SIGTERM to
                 the child. Loop until we collect the exit. */
              continue;
            }
          builtin_error ("waitpid: %s", strerror (errno));
          bw_child_pid = 0;
          sigprocmask (SIG_SETMASK, &old_set, NULL);
          sigaction (SIGCHLD, &chld_save, NULL);
          return -1;
        }
      break;
    }
  bw_child_pid = 0;
  sigprocmask (SIG_SETMASK, &old_set, NULL);
  sigaction (SIGCHLD, &chld_save, NULL);

  int child_failed = ((WIFEXITED (status) && WEXITSTATUS (status) != 0)
                      || WIFSIGNALED (status));

  if (bw_beep_mode && child_failed)
    {
      static const char bel[] = "\a";
      (void) write (STDOUT_FILENO, bel, sizeof bel - 1);
    }

  if (bw_errexit_mode && child_failed)
    return 1;

  if (bw_chgexit_mode && changed)
    return 2;

  /* Don't propagate the child's rc by default — watch loops regardless
     of exit status unless -e/--errexit is selected. */
  return 0;
}

/* clock_nanosleep CLOCK_MONOTONIC TIMER_ABSTIME with EINTR handling.
   Returns 0 on full sleep, 1 if SIGINT broke the sleep (caller should
   stop), -1 on an unrecoverable clock_nanosleep error. */
static int
bw_sleep_until (struct timespec *target)
{
  for (;;)
    {
      int rc = clock_nanosleep (CLOCK_MONOTONIC, TIMER_ABSTIME, target, NULL);
      if (rc == 0) return 0;
      if (rc == EINTR)
        {
          if (bw_stop) return 1;
          /* Spurious wake (e.g. SIGCHLD reaped by default handler):
             clock_nanosleep with TIMER_ABSTIME is idempotent — retry
             against the same absolute target. */
          continue;
        }
      builtin_error ("clock_nanosleep: %s", strerror (rc));
      return -1;
    }
}

int
watch_builtin (WORD_LIST *list)
{
  struct timespec interval = { 2, 0 };  /* procps watch default: 2.0s */
  int exec_form = 0;
  int opt;

  bw_diff_mode = 0;
  bw_beep_mode = 0;
  bw_errexit_mode = 0;
  bw_chgexit_mode = 0;
  if (bw_cap_fd >= 0) { close (bw_cap_fd); bw_cap_fd = -1; }
  free (bw_prev_buf);
  bw_prev_buf = NULL;
  bw_prev_len = 0;
  bw_iter = 0;

#define BW_CLEANUP_AND_RETURN(_rc) do {                                       \
    if (bw_cap_fd >= 0) { close (bw_cap_fd); bw_cap_fd = -1; }                \
    free (bw_prev_buf); bw_prev_buf = NULL; bw_prev_len = 0;                  \
    return (_rc);                                                             \
  } while (0)

  bw_normalize_long_options (list);
  reset_internal_getopt ();
  while ((opt = internal_getopt (list, "n:xbegdtpC:")) != -1)
    {
      switch (opt)
        {
        case 'n':
          if (bw_parse_interval (list_optarg, &interval, "-n") < 0)
            BW_CLEANUP_AND_RETURN (EX_USAGE);
          break;
        case 'x':
          exec_form = 1;
          break;
        case 'b':
          bw_beep_mode = 1;
          break;
        case 'e':
          bw_errexit_mode = 1;
          break;
        case 'g':
          bw_chgexit_mode = 1;
          break;
        case 'd':
          bw_diff_mode = 1;
          break;
        case 't':
          /* procps watch -t / --no-title suppresses its header. watch
             never prints a header, so the short flag is accepted as a
             compatibility no-op. */
          break;
        case 'p':
          /* procps watch -p / --precise anchors cadence to the original
             start time. watch already schedules with TIMER_ABSTIME, so
             the short flag is accepted as a compatibility no-op. */
          break;
        case 'C':
          if (!list_optarg || !*list_optarg)
            { builtin_error ("-C: empty FILE"); BW_CLEANUP_AND_RETURN (EX_USAGE); }
          if (bw_cap_fd >= 0) close (bw_cap_fd);
          bw_cap_fd = open (list_optarg,
                            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
          if (bw_cap_fd < 0)
            {
              builtin_error ("-C %s: %s", list_optarg, strerror (errno));
              BW_CLEANUP_AND_RETURN (EXECUTION_FAILURE);
            }
          break;
        CASE_HELPOPT;
        default:
          builtin_usage ();
          BW_CLEANUP_AND_RETURN (EX_USAGE);
        }
    }
  list = loptend;

  if (!list)
    {
      builtin_error ("usage: watch [-n SEC] [-x] [-b] [-e] [-g] [-d] [-t|--no-title] [-p|--precise] [-C FILE] CMD [ARGS...]");
      BW_CLEANUP_AND_RETURN (EX_USAGE);
    }

  int argc = 0;
  for (WORD_LIST *p = list; p; p = p->next) argc++;
  char **argv = calloc ((size_t) argc + 1, sizeof *argv);
  if (!argv)
    {
      builtin_error ("calloc: %s", strerror (errno));
      BW_CLEANUP_AND_RETURN (EXECUTION_FAILURE);
    }
  int i = 0;
  for (WORD_LIST *p = list; p; p = p->next) argv[i++] = p->word->word;
  argv[argc] = NULL;

  /* Default (non-exec) form: join remaining words with single spaces
     into one CMD string and run via `sh -c`. Quoting at the bash call
     site is preserved by bash's tokenization — `watch 'ls -la /tmp'`
     comes through as argc=1, argv[0]="ls -la /tmp". */
  char *joined = NULL;
  if (!exec_form && argc > 1)
    {
      size_t total = 0;
      for (int j = 0; j < argc; j++) total += strlen (argv[j]) + 1;
      joined = malloc (total + 1);
      if (!joined)
        {
          builtin_error ("malloc: %s", strerror (errno));
          free (argv);
          BW_CLEANUP_AND_RETURN (EXECUTION_FAILURE);
        }
      joined[0] = '\0';
      for (int j = 0; j < argc; j++)
        {
          if (j > 0) strcat (joined, " ");
          strcat (joined, argv[j]);
        }
      argv[0] = joined;
      argv[1] = NULL;
    }

  struct sigaction sa, sa_save;
  memset (&sa, 0, sizeof sa);
  sa.sa_handler = bw_sigint_handler;
  sigemptyset (&sa.sa_mask);
  /* No SA_RESTART so waitpid/clock_nanosleep return EINTR on SIGINT. */
  sigaction (SIGINT, &sa, &sa_save);

  bw_stop = 0;
  bw_child_pid = 0;

  struct timespec next;
  if (clock_gettime (CLOCK_MONOTONIC, &next) < 0)
    {
      builtin_error ("clock_gettime: %s", strerror (errno));
      sigaction (SIGINT, &sa_save, NULL);
      free (joined);
      free (argv);
      BW_CLEANUP_AND_RETURN (EXECUTION_FAILURE);
    }

  int rc = EXECUTION_SUCCESS;
  while (!bw_stop)
    {
      bw_clear_screen ();
      int ir = bw_run_iteration (argv, exec_form);
      if (ir < 0) { rc = EXECUTION_FAILURE; break; }
      if (ir == 1) { rc = EXECUTION_FAILURE; break; }
      if (ir == 2) break;
      if (bw_stop) break;

      next.tv_sec += interval.tv_sec;
      next.tv_nsec += interval.tv_nsec;
      if (next.tv_nsec >= 1000000000L)
        { next.tv_sec += 1; next.tv_nsec -= 1000000000L; }

      int sr = bw_sleep_until (&next);
      if (sr == 1) break;            /* SIGINT during sleep */
      if (sr < 0) { rc = EXECUTION_FAILURE; break; }
    }

  sigaction (SIGINT, &sa_save, NULL);
  free (joined);
  free (argv);
  BW_CLEANUP_AND_RETURN (rc);
}
#undef BW_CLEANUP_AND_RETURN

char *watch_doc[] = {
  "Run CMD periodically, clearing the screen between runs.",
  "",
  "    watch CMD [ARGS...]              run every 2 seconds (default)",
  "    watch -n SEC CMD [ARGS...]       run every SEC seconds",
  "    watch -x CMD [ARGS...]           execvp CMD directly (no sh -c)",
  "    watch -b CMD [ARGS...]           beep when CMD exits non-zero",
  "    watch -e CMD [ARGS...]           exit when CMD exits non-zero",
  "    watch -g CMD [ARGS...]           exit when output changes",
  "    watch -d CMD [ARGS...]           highlight differences from the",
  "                                         previous iteration (SGR reverse",
  "                                         video on changed bytes; same",
  "                                         spirit as procps watch -d /",
  "                                         --differences)",
  "    watch -t|--no-title CMD [...]    no-title compatibility flag",
  "                                         (no-op; watch emits no title)",
  "    watch -p|--precise CMD [...]     precise compatibility flag",
  "                                         (no-op; cadence is already",
  "                                         absolute-deadline based)",
  "    watch -C FILE CMD [ARGS...]      tee each iteration's rendered",
  "                                         output to FILE for test capture",
  "                                         (file truncated on start,",
  "                                         iterations separated by",
  "                                         `--- iteration N ---` markers)",
  "",
  "Without -x, the remaining words are joined with single spaces and",
  "fed to `sh -c \"<joined>\"`, matching watch(1) behavior so shell",
  "metacharacters work. With -x, the words are execvp'd verbatim",
  "(argv[0]=CMD, argv[1..]=ARGS), bypassing the shell.",
  "",
  "SEC accepts a fractional value (e.g. 0.5). Cadence is anchored to",
  "CLOCK_MONOTONIC absolute deadlines via clock_nanosleep(TIMER_ABSTIME)",
  "so it does not drift when a command takes variable time.",
  "",
  "-d highlights bytes that differ from the previous iteration with the",
  "CSI 7m / CSI 27m reverse-video escapes. Comparison is byte-positional",
  "starting at offset 0; bytes past the shorter buffer are flagged as",
  "changed. Multi-byte sequences are byte-aligned (good for value-",
  "change pinning; for full grapheme-cluster awareness see procps).",
  "",
  "SIGINT (Ctrl-C) terminates the loop cleanly. Procps -t/--no-title",
  "and -p/--precise are accepted as compatibility no-ops.",
  (char *) NULL
};

struct builtin watch_struct = {
  "watch",
  watch_builtin,
  BUILTIN_ENABLED,
  watch_doc,
  "watch [-n SEC] [-x] [-b] [-e] [-g] [-d] [-t|--no-title] [-p|--precise] [-C FILE] CMD [ARGS...]",
  0
};
