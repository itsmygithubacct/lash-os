/* SPDX-License-Identifier: MIT */
/* userdb.c - Stage 35.B pluggable user database lookup.
 *
 * Provides a small NSS-like provider chain for bash-os. The built-in
 * passwd provider is always first and reads PHCLIB_PASSWD/PASSWD_FILE
 * or /etc/passwd. Password verification delegates to passwd
 * verify-fd so PHCLIB_SHADOW/SHADOW_FILE and passwd's C-owned
 * password buffers remain the source of truth.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

#include "loadables.h"

#define BUD_TIMEOUT_SEC 5
#define BUD_MAX_LINE 4096
#define BUD_MAX_ARGS 32

typedef struct bud_provider {
  char *name;
  char *path;
  char **args;
  int argc;
  struct bud_provider *next;
} bud_provider;

typedef struct {
  int rc;
  int timed_out;
  int output_invalid;
  char out[BUD_MAX_LINE];
  char err[BUD_MAX_LINE];
} bud_run;

static bud_provider *bud_providers;
static int bud_config_loaded;

static void
bud_free_provider (bud_provider *p)
{
  if (!p) return;
  free (p->name);
  free (p->path);
  if (p->args)
    {
      for (int i = 0; i < p->argc; i++) free (p->args[i]);
      free (p->args);
    }
  free (p);
}

static int
bud_valid_name (const char *s)
{
  if (!s || !*s || strlen (s) > 64) return 0;
  for (const unsigned char *p = (const unsigned char *) s; *p; p++)
    if (!(isalnum (*p) || *p == '_' || *p == '-' || *p == '.'))
      return 0;
  return 1;
}

static int
bud_valid_user (const char *s)
{
  if (!s || !*s || strlen (s) > 255) return 0;
  for (const unsigned char *p = (const unsigned char *) s; *p; p++)
    if (*p == ':' || *p == '\n' || *p == '\r' || *p == '\0')
      return 0;
  return 1;
}

static const char *
bud_passwd_path (void)
{
  const char *p = getenv ("BASHUSERDB_PASSWD");
  if (!p || !*p) p = getenv ("PHCLIB_PASSWD");
  if (!p || !*p) p = getenv ("PASSWD_FILE");
  if (!p || !*p) p = "/etc/passwd";
  return p;
}

static const char *
bud_config_path (void)
{
  const char *p = getenv ("BASHUSERDB_CONF");
  return (p && *p) ? p : "/etc/userdb.conf";
}

static int
bud_valid_id (const char *s, const char *end, uintmax_t limit)
{
  uintmax_t value = 0;
  if (s == end) return 0;
  for (; s < end; s++)
    {
      if (*s < '0' || *s > '9') return 0;
      unsigned digit = (unsigned) (*s - '0');
      if (value > (limit - digit) / 10) return 0;
      value = value * 10 + digit;
    }
  return 1;
}

static int
bud_valid_record (const char *s)
{
  int colons = 0;
  if (!s || !*s || strlen (s) >= BUD_MAX_LINE) return 0;
  for (const unsigned char *p = (const unsigned char *) s; *p; p++)
    {
      if (*p == '\n' || *p == '\r') return 0;
      if (*p == ':') colons++;
    }
  if (colons != 4) return 0;
  const char *uid_end = strchr (s, ':'), *gid_end = strchr (uid_end + 1, ':');
  return bud_valid_id (s, uid_end, (uintmax_t) (uid_t) -1 - 1) &&
         bud_valid_id (uid_end + 1, gid_end, (uintmax_t) (gid_t) -1 - 1);
}

static int
bud_passwd_lookup (const char *user, char *out, size_t outsz)
{
  FILE *f = fopen (bud_passwd_path (), "r");
  if (!f) return 1;

  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  int rc = 1;
  while ((n = getline (&line, &cap, f)) > 0)
    {
      if (memchr (line, '\0', (size_t) n)) continue;
      if (n && line[n - 1] == '\n') line[--n] = '\0';
      /* Keep the five record fields intact: empty GECOS, home, shell and
         password fields must not shift the later fields as strtok does. */
      char *name_end = strchr (line, ':');
      if (!name_end) continue;
      *name_end = '\0';
      if (strcmp (line, user) != 0) continue;
      char *record = strchr (name_end + 1, ':');
      if (!record || !bud_valid_record (++record)) continue;
      size_t length = strlen (record);
      if (length >= outsz) continue;
      memcpy (out, record, length + 1);
      rc = 0;
      break;
    }
  free (line);
  fclose (f);
  return rc;
}

static int
bud_bind_record (const char *name, const char *record)
{
  SHELL_VAR *v = builtin_bind_variable ((char *) name, (char *) record, 0);
  return v && !readonly_p (v) && !noassign_p (v) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bud_set_nonblock (int fd)
{
  int fl = fcntl (fd, F_GETFL, 0);
  return fl < 0 ? -1 : fcntl (fd, F_SETFL, fl | O_NONBLOCK);
}

static void
bud_close (int *fd)
{
  if (*fd >= 0) close (*fd);
  *fd = -1;
}

/* Retain only the first line, but drain both streams. Limit each pass so a
   provider continuously writing output cannot starve its own deadline. */
static void
bud_append_read (int *fd, char *buf, size_t *len, int *line_done, int *invalid)
{
  char tmp[512];
  for (int chunk = 0; *fd >= 0 && chunk < 32; chunk++)
    {
      ssize_t n = read (*fd, tmp, sizeof tmp);
      if (n > 0)
        {
          for (ssize_t i = 0; i < n && !*line_done; i++)
            {
              if (tmp[i] == '\r' || tmp[i] == '\n') *line_done = 1;
              else if (tmp[i] == '\0' || *len == BUD_MAX_LINE - 1) *invalid = 1;
              else buf[(*len)++] = tmp[i];
            }
          buf[*len] = '\0';
          continue;
        }
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return;
      if (n < 0) *invalid = 1;
      bud_close (fd);
      return;
    }
}

static long long
bud_mono_ms (void)
{
  struct timespec now;
  if (clock_gettime (CLOCK_MONOTONIC, &now) < 0) return -1;
  return (long long) now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int
bud_run_provider (bud_provider *p, const char *op, const char *user,
                  const char *password, bud_run *r)
{
  int outp[2] = { -1, -1 }, errp[2] = { -1, -1 }, pwp[2] = { -1, -1 };
  int builtin_passwd = strcmp (p->name, "passwd") == 0;
  int fd_verify = password && strcmp (op, "verify") == 0 &&
                  (builtin_passwd || strcmp (p->name, "ldap") == 0);
  int password_fd = builtin_passwd ? STDIN_FILENO : 3;
  int guarded = 0, failed = 0, reaped = 0, status = 0, channel_error = 0;
  size_t olen = 0, elen = 0, sent = 0, password_len = password ? strlen (password) : 0;
  size_t password_bytes = password_len + (fd_verify && !builtin_passwd ? 1 : 0);
  int out_done = 0, err_done = 0, err_invalid = 0;
  pid_t pid = -1;
  sigset_t chld_set, prev_mask;
  struct sigaction chld_dfl, chld_save;
  memset (r, 0, sizeof *r);
  r->rc = 127;
  if (pipe2 (outp, O_CLOEXEC) < 0 || pipe2 (errp, O_CLOEXEC) < 0 ||
      (fd_verify && socketpair (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pwp) < 0))
    { failed = 1; goto cleanup; }

  memset (&chld_dfl, 0, sizeof chld_dfl);
  chld_dfl.sa_handler = SIG_DFL;
  sigemptyset (&chld_dfl.sa_mask);
  sigemptyset (&chld_set);
  sigaddset (&chld_set, SIGCHLD);
  if (sigprocmask (SIG_BLOCK, &chld_set, &prev_mask) < 0)
    { failed = 1; goto cleanup; }
  if (sigaction (SIGCHLD, &chld_dfl, &chld_save) < 0)
    { sigprocmask (SIG_SETMASK, &prev_mask, NULL); failed = 1; goto cleanup; }
  guarded = 1;

  pid = fork ();
  if (pid < 0)
    { failed = 1; goto cleanup; }
  if (pid == 0)
    {
      if (setpgid (0, 0) < 0) _exit (127);
      /* Move sources above all destinations before closing any pipe ends.
         This also works when the caller entered with fd 0, 1 or 2 closed. */
      int output = fcntl (outp[1], F_DUPFD_CLOEXEC, 4);
      int error = fcntl (errp[1], F_DUPFD_CLOEXEC, 4);
      int input = fd_verify ? fcntl (pwp[0], F_DUPFD_CLOEXEC, 4) : -1;
      if (output < 0 || error < 0 || (fd_verify && input < 0)) _exit (127);
      bud_close (&outp[0]); bud_close (&outp[1]); bud_close (&errp[0]); bud_close (&errp[1]);
      bud_close (&pwp[0]); bud_close (&pwp[1]);
      if (dup2 (output, STDOUT_FILENO) < 0 || dup2 (error, STDERR_FILENO) < 0 ||
          (fd_verify && dup2 (input, password_fd) < 0)) _exit (127);
      close (output); close (error); if (input >= 0) close (input);
      if (fd_verify)
        {
          if (setenv ("BASHUSERDB_VERIFY_FD", builtin_passwd ? "0" : "3", 1) < 0) _exit (127);
          /* Bash's setenv updates its variable table, not libc's environ. */
          array_needs_making = 1;
        }
      maybe_make_export_env ();
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      int extra = password && !fd_verify ? 3 : 2;
      int ac = 1 + p->argc + extra;
      char **argv = calloc ((size_t) ac + 1, sizeof *argv);
      if (!argv) _exit (127);
      int i = 0;
      argv[i++] = p->path;
      for (int j = 0; j < p->argc; j++) argv[i++] = p->args[j];
      argv[i++] = (char *) op;
      argv[i++] = (char *) user;
      if (password && !fd_verify) argv[i++] = (char *) password;
      argv[i] = NULL;
      execv (p->path, argv);
      if (builtin_passwd) execv ("/bin/bash", argv);
      _exit (127);
    }

  (void) setpgid (pid, pid);
  bud_close (&outp[1]); bud_close (&errp[1]); bud_close (&pwp[0]);
  if (bud_set_nonblock (outp[0]) < 0 || bud_set_nonblock (errp[0]) < 0 ||
      (fd_verify && bud_set_nonblock (pwp[1]) < 0))
    { failed = 1; goto cleanup; }

  long long now = bud_mono_ms (), deadline = now + BUD_TIMEOUT_SEC * 1000;
  if (now < 0) { failed = 1; goto cleanup; }
  while (!reaped)
    {
      bud_append_read (&outp[0], r->out, &olen, &out_done, &r->output_invalid);
      bud_append_read (&errp[0], r->err, &elen, &err_done, &err_invalid);
      if (pwp[1] >= 0 && sent == password_bytes) bud_close (&pwp[1]);
      if (pwp[1] >= 0)
        {
          const char *bytes = sent < password_len ? password + sent : "\n";
          size_t remaining = sent < password_len ? password_len - sent : 1;
          ssize_t n = send (pwp[1], bytes, remaining, MSG_NOSIGNAL);
          if (n > 0)
            {
              sent += (size_t) n;
              if (sent == password_bytes) bud_close (&pwp[1]);
            }
          else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
            { channel_error = 1; bud_close (&pwp[1]); }
        }
      pid_t w = waitpid (pid, &status, WNOHANG);
      if (w == pid) { reaped = 1; break; }
      if (w < 0 && errno != EINTR) { failed = 1; break; }
      now = bud_mono_ms ();
      if (now < 0) { failed = 1; break; }
      if (now >= deadline) { r->timed_out = 1; break; }
      struct pollfd fds[] = {
        { .fd = outp[0], .events = POLLIN }, { .fd = errp[0], .events = POLLIN },
        { .fd = pwp[1], .events = POLLOUT }
      };
      int delay = deadline - now > 100 ? 100 : (int) (deadline - now);
      if (poll (fds, 3, delay) < 0 && errno != EINTR) { failed = 1; break; }
    }

cleanup:
  if (pid > 0 && !reaped)
    {
      /* The provider owns this process group; a timeout also ends helpers
         that could otherwise keep our pipes open after the provider dies. */
      (void) kill (-pid, SIGKILL);
      (void) kill (pid, SIGKILL);
      pid_t w;
      do w = waitpid (pid, &status, 0); while (w < 0 && errno == EINTR);
      reaped = w == pid;
    }
  if (pid > 0 && !failed)
    {
      bud_append_read (&outp[0], r->out, &olen, &out_done, &r->output_invalid);
      bud_append_read (&errp[0], r->err, &elen, &err_done, &err_invalid);
    }
  bud_close (&outp[0]); bud_close (&outp[1]); bud_close (&errp[0]); bud_close (&errp[1]);
  bud_close (&pwp[0]); bud_close (&pwp[1]);
  if (guarded)
    {
      sigaction (SIGCHLD, &chld_save, NULL);
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
    }
  if (failed) return -1;

  if (r->timed_out) r->rc = 124;
  else if (!reaped || channel_error || (fd_verify && sent != password_bytes)) r->rc = 1;
  else if (WIFEXITED (status)) r->rc = WEXITSTATUS (status);
  else r->rc = 128;
  return 0;
}

static bud_provider *
bud_find_provider (const char *name)
{
  for (bud_provider *p = bud_providers; p; p = p->next)
    if (strcmp (p->name, name) == 0) return p;
  return NULL;
}

static int
bud_add_provider_internal (const char *name, const char *path, int argc,
                           char **argv, int quiet)
{
  if (!bud_valid_name (name) || strcmp (name, "passwd") == 0)
    { if (!quiet) builtin_error ("bad provider name: %s", name ? name : ""); return EX_USAGE; }
  if (!path || !*path || path[0] != '/')
    { if (!quiet) builtin_error ("provider path must be absolute"); return EX_USAGE; }
  if (argc > BUD_MAX_ARGS)
    { if (!quiet) builtin_error ("too many provider args"); return EX_USAGE; }
  if (bud_find_provider (name))
    { if (!quiet) builtin_error ("provider already exists: %s", name); return EXECUTION_FAILURE; }

  bud_provider *p = calloc (1, sizeof *p);
  if (!p) return EXECUTION_FAILURE;
  p->name = strdup (name);
  p->path = strdup (path);
  p->argc = argc;
  p->args = calloc ((size_t) argc, sizeof *p->args);
  if (!p->name || !p->path || (argc && !p->args))
    { bud_free_provider (p); return EXECUTION_FAILURE; }
  for (int i = 0; i < argc; i++)
    {
      p->args[i] = strdup (argv[i]);
      if (!p->args[i]) { bud_free_provider (p); return EXECUTION_FAILURE; }
    }
  if (!bud_providers) bud_providers = p;
  else
    {
      bud_provider *tail = bud_providers;
      while (tail->next) tail = tail->next;
      tail->next = p;
    }
  return EXECUTION_SUCCESS;
}

static void
bud_load_config (void)
{
  if (bud_config_loaded) return;
  bud_config_loaded = 1;
  FILE *f = fopen (bud_config_path (), "r");
  if (!f) return;
  char *line = NULL;
  size_t cap = 0;
  while (getline (&line, &cap, f) > 0)
    {
      char *p = line;
      while (isspace ((unsigned char) *p)) p++;
      if (*p == '#' || *p == '\0') continue;
      char *save = NULL;
      char *tok[BUD_MAX_ARGS + 3];
      int n = 0;
      for (char *t = strtok_r (p, " \t\r\n", &save);
           t && n < (int) (sizeof tok / sizeof tok[0]);
           t = strtok_r (NULL, " \t\r\n", &save))
        tok[n++] = t;
      if (n >= 3 && strcmp (tok[0], "provider") == 0)
        bud_add_provider_internal (tok[1], tok[2], n - 3, tok + 3, 1);
    }
  free (line);
  fclose (f);
}

static int
bud_passwd_verify (const char *user, const char *password)
{
  char *args[] = { "-c", "builtin passwd verify-fd \"$2\" 0", "userdb-passwd" };
  bud_provider provider = { .name = "passwd", .path = "/proc/self/exe", .args = args, .argc = 3 };
  bud_run result;
  if (bud_run_provider (&provider, "verify", user, password ? password : "", &result) < 0)
    return EXECUTION_FAILURE;
  if (result.timed_out) builtin_error ("passwd provider timed out");
  return result.rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bud_lookup_cmd (WORD_LIST *args)
{
  bud_load_config ();
  const char *user = NULL, *var = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-V") == 0 && p->next)
        { p = p->next; var = p->word->word; continue; }
      if (w[0] == '-' && w[1])
        { builtin_error ("lookup: unknown option %s", w); return EX_USAGE; }
      if (user)
        { builtin_error ("lookup: extra arg %s", w); return EX_USAGE; }
      user = w;
    }
  if (!user || !var) { builtin_error ("lookup needs USER -V VAR"); return EX_USAGE; }
  if (!bud_valid_user (user)) { builtin_error ("lookup: invalid user"); return EX_USAGE; }
  if (valid_identifier ((char *) var) == 0) { sh_invalidid ((char *) var); return EXECUTION_FAILURE; }

  char rec[BUD_MAX_LINE];
  if (bud_passwd_lookup (user, rec, sizeof rec) == 0)
    {
      return bud_bind_record (var, rec);
    }

  int tried = 0;
  for (bud_provider *p = bud_providers; p; p = p->next)
    {
      bud_run r;
      tried++;
      if (bud_run_provider (p, "lookup", user, NULL, &r) < 0) continue;
      if (r.timed_out)
        { builtin_error ("provider %s lookup timed out", p->name); continue; }
      if (r.rc == 0 && !r.output_invalid && bud_valid_record (r.out))
        {
          return bud_bind_record (var, r.out);
        }
      if (r.rc == 1)
        continue;             /* expected user-not-found, stay silent */
      /* All other rcs: emit a diagnostic so operators can see WHY a
       * provider failed. rc=127 means execv() failed in the child
       * (provider binary missing / not executable / shebang broken);
       * the child died before producing stderr so r.err is typically
       * empty — distinguishing this from a normal rc=2/3/... failure
       * is what lets operators triage misconfigured provider paths
       * from genuine provider-side errors. */
      if (r.rc == 127)
        {
          if (r.err[0])
            builtin_error ("provider %s lookup: exec failed (rc=127): %s",
                           p->name, r.err);
          else
            builtin_error ("provider %s lookup: exec failed (rc=127)",
                           p->name);
        }
      else if (r.err[0])
        builtin_error ("provider %s lookup: rc=%d: %s",
                       p->name, r.rc, r.err);
      else
        builtin_error ("provider %s lookup: rc=%d", p->name, r.rc);
    }
  if (tried == 0)
    builtin_error ("lookup: '%s' not in built-in passwd and no providers configured",
                   user);
  return EXECUTION_FAILURE;
}

static int
bud_verify_cmd (WORD_LIST *args)
{
  bud_load_config ();
  if (!args || !args->next || args->next->next)
    { builtin_error ("verify needs USER PASSWORD"); return EX_USAGE; }
  const char *user = args->word->word;
  const char *password = args->next->word->word;
  if (!bud_valid_user (user)) { builtin_error ("verify: invalid user"); return EX_USAGE; }

  char rec[BUD_MAX_LINE];
  if (bud_passwd_lookup (user, rec, sizeof rec) == 0)
    return bud_passwd_verify (user, password);

  int tried = 0;
  for (bud_provider *p = bud_providers; p; p = p->next)
    {
      bud_run r;
      tried++;
      if (bud_run_provider (p, "verify", user, password, &r) < 0) continue;
      if (r.timed_out)
        { builtin_error ("provider %s verify timed out", p->name); continue; }
      if (r.rc == 0) return EXECUTION_SUCCESS;
      if (r.rc == 1)
        continue;             /* wrong password / user-not-found, silent */
      /* See bud_lookup_cmd for the diagnostic policy rationale. */
      if (r.rc == 127)
        {
          if (r.err[0])
            builtin_error ("provider %s verify: exec failed (rc=127): %s",
                           p->name, r.err);
          else
            builtin_error ("provider %s verify: exec failed (rc=127)",
                           p->name);
        }
      else if (r.err[0])
        builtin_error ("provider %s verify: rc=%d: %s",
                       p->name, r.rc, r.err);
      else
        builtin_error ("provider %s verify: rc=%d", p->name, r.rc);
    }
  if (tried == 0)
    builtin_error ("verify: '%s' not in built-in passwd and no providers configured",
                   user);
  return EXECUTION_FAILURE;
}

static int
bud_list_cmd (WORD_LIST *args)
{
  if (args) { builtin_error ("list-providers takes no args"); return EX_USAGE; }
  bud_load_config ();
  printf ("passwd builtin\n");
  for (bud_provider *p = bud_providers; p; p = p->next)
    {
      printf ("%s %s", p->name, p->path);
      for (int i = 0; i < p->argc; i++) printf (" %s", p->args[i]);
      putchar ('\n');
    }
  return EXECUTION_SUCCESS;
}

static int
bud_add_cmd (WORD_LIST *args)
{
  bud_load_config ();
  if (!args || !args->next) { builtin_error ("add-provider needs NAME PATH [ARGS...]"); return EX_USAGE; }
  const char *name = args->word->word;
  const char *path = args->next->word->word;
  char *av[BUD_MAX_ARGS];
  int ac = 0;
  for (WORD_LIST *p = args->next->next; p; p = p->next)
    {
      if (ac >= BUD_MAX_ARGS) { builtin_error ("too many provider args"); return EX_USAGE; }
      av[ac++] = p->word->word;
    }
  return bud_add_provider_internal (name, path, ac, av, 0);
}

static int
bud_remove_cmd (WORD_LIST *args)
{
  bud_load_config ();
  if (!args || args->next) { builtin_error ("remove-provider needs NAME"); return EX_USAGE; }
  const char *name = args->word->word;
  if (strcmp (name, "passwd") == 0)
    { builtin_error ("cannot remove built-in passwd provider"); return EXECUTION_FAILURE; }
  bud_provider **pp = &bud_providers;
  while (*pp)
    {
      bud_provider *cur = *pp;
      if (strcmp (cur->name, name) == 0)
        {
          *pp = cur->next;
          bud_free_provider (cur);
          return EXECUTION_SUCCESS;
        }
      pp = &cur->next;
    }
  return EXECUTION_FAILURE;
}

int
userdb_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "lookup") == 0) return bud_lookup_cmd (args);
  if (strcmp (cmd, "verify") == 0) return bud_verify_cmd (args);
  if (strcmp (cmd, "list-providers") == 0) return bud_list_cmd (args);
  if (strcmp (cmd, "add-provider") == 0) return bud_add_cmd (args);
  if (strcmp (cmd, "remove-provider") == 0) return bud_remove_cmd (args);
  builtin_error ("unknown verb: %s", cmd);
  return EX_USAGE;
}

char *userdb_doc[] = {
  "Pluggable user database provider chain (Stage 35.B).",
  "",
  "    userdb lookup USER -V VAR",
  "        Bind VAR to uid:gid:gecos:home:shell. rc 0 found, rc 1 not found.",
  "    userdb verify USER PASSWORD",
  "        Verify USER's password through the provider chain. The built-in",
  "        passwd provider delegates to passwd verify-fd.",
  "    userdb list-providers",
  "        Print passwd builtin first, then configured external providers.",
  "    userdb add-provider NAME PATH [ARGS...]",
  "        Add an external provider. Providers are invoked as",
  "        PATH [ARGS...] lookup USER or PATH [ARGS...] verify USER PASSWORD.",
  "        The ldap provider receives the password on fd 3 instead of argv;",
  "        BASHUSERDB_VERIFY_FD identifies that descriptor.",
  "    userdb remove-provider NAME",
  "",
  "Config: /etc/userdb.conf lines of: provider NAME PATH [ARGS...]",
  "Provider exchange (including password input) has a five-second deadline.",
  "Lookup accepts one complete first-line record of at most 4095 bytes.",
  "",
  "Provider error diagnostics: rc=0 success, rc=1 silent (user not",
  "found / wrong password). rc=127 reports 'exec failed (rc=127)'",
  "(provider binary missing or not executable). All other non-zero",
  "rcs report 'rc=N' plus the provider's stderr when non-empty.",
  "If the built-in passwd lookup fails AND no external providers are",
  "configured, a 'no providers configured' diagnostic fires so the",
  "operator can distinguish 'user not found' from 'nothing tried'.",
  (char *) NULL
};

struct builtin userdb_struct = {
  "userdb",
  userdb_builtin,
  BUILTIN_ENABLED,
  userdb_doc,
  "userdb lookup|verify|list-providers|add-provider|remove-provider ...",
  0
};
