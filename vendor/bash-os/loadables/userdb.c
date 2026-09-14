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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
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
bud_valid_record (const char *s)
{
  int colons = 0;
  if (!s || !*s || strlen (s) >= BUD_MAX_LINE) return 0;
  for (const unsigned char *p = (const unsigned char *) s; *p; p++)
    {
      if (*p == '\n' || *p == '\r') return 0;
      if (*p == ':') colons++;
    }
  return colons == 4;
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
      if (n && line[n - 1] == '\n') line[n - 1] = '\0';
      char *save = NULL;
      char *name = strtok_r (line, ":", &save);
      char *pw = strtok_r (NULL, ":", &save);
      char *uid = strtok_r (NULL, ":", &save);
      char *gid = strtok_r (NULL, ":", &save);
      char *gecos = strtok_r (NULL, ":", &save);
      char *home = strtok_r (NULL, ":", &save);
      char *shell = strtok_r (NULL, ":", &save);
      (void) pw;
      if (!name || !uid || !gid || !gecos || !home || !shell) continue;
      if (strcmp (name, user) != 0) continue;
      snprintf (out, outsz, "%s:%s:%s:%s:%s", uid, gid, gecos, home, shell);
      rc = 0;
      break;
    }
  free (line);
  fclose (f);
  return rc;
}

static int
bud_set_nonblock (int fd)
{
  int fl = fcntl (fd, F_GETFL, 0);
  return fl < 0 ? -1 : fcntl (fd, F_SETFL, fl | O_NONBLOCK);
}

static void
bud_append_read (int fd, char *buf, size_t *len)
{
  char tmp[512];
  for (;;)
    {
      ssize_t n = read (fd, tmp, sizeof tmp);
      if (n > 0)
        {
          size_t room = BUD_MAX_LINE - 1 - *len;
          size_t take = (size_t) n < room ? (size_t) n : room;
          if (take)
            {
              memcpy (buf + *len, tmp, take);
              *len += take;
              buf[*len] = '\0';
            }
          continue;
        }
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return;
      return;
    }
}

static void
bud_first_line (char *s)
{
  char *p = strpbrk (s, "\r\n");
  if (p) *p = '\0';
}

static int
bud_run_provider (bud_provider *p, const char *op, const char *user,
                  const char *password, bud_run *r)
{
  int outp[2] = { -1, -1 }, errp[2] = { -1, -1 }, pwp[2] = { -1, -1 };
  int fd_verify = password && strcmp (op, "verify") == 0 && strcmp (p->name, "ldap") == 0;
  memset (r, 0, sizeof *r);
  r->rc = 127;
  if (pipe (outp) < 0 || pipe (errp) < 0 || (fd_verify && pipe (pwp) < 0))
    {
      if (outp[0] >= 0) close (outp[0]);
      if (outp[1] >= 0) close (outp[1]);
      if (errp[0] >= 0) close (errp[0]);
      if (errp[1] >= 0) close (errp[1]);
      if (pwp[0] >= 0) close (pwp[0]);
      if (pwp[1] >= 0) close (pwp[1]);
      return -1;
    }

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
  if (pid < 0)
    {
      close (outp[0]); close (outp[1]); close (errp[0]); close (errp[1]);
      if (pwp[0] >= 0) close (pwp[0]);
      if (pwp[1] >= 0) close (pwp[1]);
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      sigaction (SIGCHLD, &chld_save, NULL);
      return -1;
    }
  if (pid == 0)
    {
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      dup2 (outp[1], STDOUT_FILENO);
      dup2 (errp[1], STDERR_FILENO);
      if (fd_verify)
        {
          if (pwp[0] != 3 && dup2 (pwp[0], 3) < 0)
            _exit (127);
          setenv ("BASHUSERDB_VERIFY_FD", "3", 1);
        }
      close (outp[0]); close (outp[1]); close (errp[0]); close (errp[1]);
      if (pwp[0] >= 0 && pwp[0] != 3) close (pwp[0]);
      if (pwp[1] >= 0 && pwp[1] != 3) close (pwp[1]);
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
      _exit (127);
    }

  close (outp[1]);
  close (errp[1]);
  if (fd_verify)
    {
      const char *pcur = password;
      size_t left = strlen (password);
      close (pwp[0]);
      while (left > 0)
        {
          ssize_t n = write (pwp[1], pcur, left);
          if (n < 0 && errno == EINTR) continue;
          if (n <= 0) break;
          pcur += n;
          left -= (size_t) n;
        }
      (void) write (pwp[1], "\n", 1);
      close (pwp[1]);
    }
  bud_set_nonblock (outp[0]);
  bud_set_nonblock (errp[0]);

  size_t olen = 0, elen = 0;
  time_t deadline = time (NULL) + BUD_TIMEOUT_SEC;
  int status = 0, done = 0;
  while (!done)
    {
      bud_append_read (outp[0], r->out, &olen);
      bud_append_read (errp[0], r->err, &elen);
      pid_t w = waitpid (pid, &status, WNOHANG);
      if (w == pid) { done = 1; break; }
      if (w < 0 && errno != EINTR) { done = 1; break; }
      if (time (NULL) >= deadline)
        {
          r->timed_out = 1;
          kill (pid, SIGKILL);
          while (waitpid (pid, &status, 0) < 0 && errno == EINTR) ;
          done = 1;
          break;
        }
      fd_set rfds;
      FD_ZERO (&rfds);
      FD_SET (outp[0], &rfds);
      FD_SET (errp[0], &rfds);
      int maxfd = outp[0] > errp[0] ? outp[0] : errp[0];
      struct timeval tv;
      tv.tv_sec = 0;
      tv.tv_usec = 100000;
      select (maxfd + 1, &rfds, NULL, NULL, &tv);
    }
  bud_append_read (outp[0], r->out, &olen);
  bud_append_read (errp[0], r->err, &elen);
  sigprocmask (SIG_SETMASK, &prev_mask, NULL);
  sigaction (SIGCHLD, &chld_save, NULL);
  close (outp[0]);
  close (errp[0]);

  if (r->timed_out) r->rc = 124;
  else if (WIFEXITED (status)) r->rc = WEXITSTATUS (status);
  else r->rc = 128;
  bud_first_line (r->out);
  bud_first_line (r->err);
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
  int p[2];
  if (pipe (p) < 0) return EXECUTION_FAILURE;

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
  if (pid < 0)
    {
      close (p[0]); close (p[1]);
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      sigaction (SIGCHLD, &chld_save, NULL);
      return EXECUTION_FAILURE;
    }
  if (pid == 0)
    {
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      dup2 (p[0], STDIN_FILENO);
      close (p[0]);
      close (p[1]);
      execl ("/proc/self/exe", "bash", "-c",
             "builtin passwd verify-fd \"$1\" 0",
             "userdb-passwd", user, (char *) NULL);
      execl ("/bin/bash", "bash", "-c",
             "builtin passwd verify-fd \"$1\" 0",
             "userdb-passwd", user, (char *) NULL);
      _exit (127);
    }
  close (p[0]);
  size_t len = strlen (password ? password : "");
  const char *q = password ? password : "";
  while (len)
    {
      ssize_t n = write (p[1], q, len);
      if (n < 0)
        {
          if (errno == EINTR) continue;
          break;
        }
      q += n;
      len -= (size_t) n;
    }
  close (p[1]);

  int status = 0;
  time_t deadline = time (NULL) + BUD_TIMEOUT_SEC;
  for (;;)
    {
      pid_t w = waitpid (pid, &status, WNOHANG);
      if (w == pid) break;
      if (w < 0 && errno != EINTR)
        {
          sigprocmask (SIG_SETMASK, &prev_mask, NULL);
          sigaction (SIGCHLD, &chld_save, NULL);
          return EXECUTION_FAILURE;
        }
      if (time (NULL) >= deadline)
        {
          kill (pid, SIGKILL);
          while (waitpid (pid, &status, 0) < 0 && errno == EINTR) ;
          sigprocmask (SIG_SETMASK, &prev_mask, NULL);
          sigaction (SIGCHLD, &chld_save, NULL);
          builtin_error ("passwd provider timed out");
          return EXECUTION_FAILURE;
        }
      usleep (100000);
    }
  sigprocmask (SIG_SETMASK, &prev_mask, NULL);
  sigaction (SIGCHLD, &chld_save, NULL);
  return (WIFEXITED (status) && WEXITSTATUS (status) == 0)
         ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
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
      builtin_bind_variable ((char *) var, rec, 0);
      return EXECUTION_SUCCESS;
    }

  int tried = 0;
  for (bud_provider *p = bud_providers; p; p = p->next)
    {
      bud_run r;
      tried++;
      if (bud_run_provider (p, "lookup", user, NULL, &r) < 0) continue;
      if (r.timed_out)
        { builtin_error ("provider %s lookup timed out", p->name); continue; }
      if (r.rc == 0 && bud_valid_record (r.out))
        {
          builtin_bind_variable ((char *) var, r.out, 0);
          return EXECUTION_SUCCESS;
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
  "    userdb remove-provider NAME",
  "",
  "Config: /etc/userdb.conf lines of: provider NAME PATH [ARGS...]",
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
