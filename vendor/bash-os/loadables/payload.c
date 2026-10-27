/* SPDX-License-Identifier: MIT */
/* payload.c — bash-os loadable builtin: a friendly, pre-wired front-end for the
 * bashy.box native-payload set (bun, python3, rust, npm, gcc, ...).
 *
 * bashy.box stages its payloads as a drop-in bl-pkg repo on the per-instance 9P
 * share (default /root/loadables: an INDEX + pool/<name>_<ver>_<arch>.blpkg),
 * and the low-level installer (/bash-os/bl-pkg.sh) installs/rolls them back,
 * recording state under /var/lib/bl-pkg/installed/<name>. `pkg` is the
 * general package builtin; `payload` is the easy button scoped to that share:
 *
 *     payload [list]            list available payloads + install status
 *     payload installed         list only the installed payloads
 *     payload info NAME         show one payload's INDEX record + state
 *     payload install NAME...   install from the share (via bl-pkg)
 *     payload remove  NAME...   remove (rolls back the recorded install txn)
 *     payload help
 *
 * list/info/installed are read natively here (no subprocess); install/remove
 * reuse /bash-os/bl-pkg.sh verbatim so there is exactly one install code path.
 * That helper belongs to the bashy.box image, not to this repository; the argv
 * it receives is the contract (docs/opus-payload.md):
 *
 *     $BASH INSTALLER --internal --root ROOT --repo REPO --allow-unsigned
 *           install NAME...
 *     $BASH INSTALLER --internal --root ROOT rollback TXN
 *
 * Every NAME is checked against [A-Za-z0-9][A-Za-z0-9._+-]* and must have an
 * INDEX record before the helper runs; TXN must be printable, space-free and
 * must not begin with '-'. Names cannot be paths; TXNs are opaque helper IDs.
 * The helper's exit status is the builtin's (128+N if signal N killed it).
 *
 * Env overrides (all optional):
 *   BASHPKG_LOADABLES_DATADIR / PAYLOAD_REPO   repo dir   (default /root/loadables)
 *   PAYLOAD_ROOT                               install root (default /)
 *   PAYLOAD_INSTALLER                          installer  (default /bash-os/bl-pkg.sh)
 *
 * Static-musl notes: allocated paths (no PATH_MAX reliance), bounded line
 * input (no getline feature-macro dance), pure POSIX fork/exec.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "loadables.h"
#include "child-wait.h"
#include "command-run.h"
#include "bl-output.h"

#define PL_DEFAULT_REPO      "/root/loadables"
#define PL_DEFAULT_ROOT      "/"
#define PL_DEFAULT_INSTALLER "/bash-os/bl-pkg.sh"

#define PL_LINESZ 8192
#define PL_FLDSZ  256

extern char *payload_doc[];
extern struct builtin payload_struct;

/* --- configuration (resolved once per call into owned copies) -------------- */

/* Bash's getenv() hands back one shared buffer for a variable assigned for a
 * single command and frees it on the next lookup, so
 * `PAYLOAD_ROOT=/r PAYLOAD_REPO=/p payload install x` used to pass the repo
 * where the root belonged. Every value is copied before the next is read. */
typedef struct
{
  char *repo;
  char *root;
  char *installer;
  char *bash;
  int statefd;          /* <root>/var/lib/bl-pkg/installed, or -1 */
} pl_cfg;

static char *
pl_getvar (const char *env_name, const char *bash_name, const char *dflt)
{
  const char *v = env_name ? getenv (env_name) : NULL;
  if (v && *v)
    return savestring (v);
  if (bash_name)
    {
      char *b = get_string_value (bash_name);
      if (b && *b)
        return savestring (b);
    }
  return savestring (dflt);
}

static void
pl_cfg_init (pl_cfg *c)
{
  char *state;
  size_t len;
  const char *v;

  /* PAYLOAD_REPO overrides; else BASHPKG_LOADABLES_DATADIR (set by /init), as
   * the payload-autoinstall service and download_codex use; else the default. */
  v = getenv ("PAYLOAD_REPO");
  c->repo = (v && *v) ? savestring (v)
            : pl_getvar ("BASHPKG_LOADABLES_DATADIR", "BASHPKG_LOADABLES_DATADIR",
                         PL_DEFAULT_REPO);
  c->root = pl_getvar ("PAYLOAD_ROOT", NULL, PL_DEFAULT_ROOT);
  c->installer = pl_getvar ("PAYLOAD_INSTALLER", NULL, PL_DEFAULT_INSTALLER);
  /* The bl-pkg.sh script ships non-executable, so run it with bash. Prefer the
   * running shell's $BASH; fall back to a PATH lookup of `bash`. */
  c->bash = pl_getvar ("BASH", "BASH", "bash");

  /* One directory descriptor serves every state probe, so a 20000-record
   * listing does not resolve the root prefix 20000 times. Double slash when
   * root ends in '/' is harmless on Linux. */
  len = strlen (c->root);
  state = xmalloc (len + sizeof "/var/lib/bl-pkg/installed");
  memcpy (state, c->root, len);
  memcpy (state + len, "/var/lib/bl-pkg/installed", sizeof "/var/lib/bl-pkg/installed");
  c->statefd = open (state, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  free (state);
}

static void
pl_cfg_free (pl_cfg *c)
{
  if (c->statefd >= 0)
    close (c->statefd);
  free (c->repo);
  free (c->root);
  free (c->installer);
  free (c->bash);
}

/* --- names and line input -------------------------------------------------- */

/* A payload name is used as a state file name and as helper argv, so it may
 * not contain '/', start with '.' or '-', or carry spaces or controls. */
static int
pl_valid_name (const char *s)
{
  size_t i, n = strlen (s);
  if (n == 0 || n >= PL_FLDSZ)
    return 0;
  for (i = 0; i < n; i++)
    {
      unsigned char ch = s[i];
      int alnum = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
                  || (ch >= '0' && ch <= '9');
      if (!alnum && (i == 0 || !strchr ("._+-", ch)))
        return 0;
    }
  return 1;
}

/* Read one bounded line, consuming it completely even when it is malformed.
 * fgets + strlen cannot distinguish an embedded NUL from the terminator and
 * could silently accept a truncated record or transaction id. */
static int
pl_getline (FILE *f, char *buf, size_t sz)
{
  size_t n = 0;
  int ch, bad = 0, any = 0;
  flockfile (f);
  while ((ch = getc_unlocked (f)) != EOF)
    {
      any = 1;
      if (ch == 0) bad = 1;
      if (n + 1 < sz) buf[n++] = (char) ch;
      else bad = 1;
      if (ch == '\n') break;
    }
  funlockfile (f);
  buf[n] = '\0';
  if (!any) return 0;
  if (n + 1 == sz && (n == 0 || buf[n - 1] != '\n')) bad = 1;
  return bad ? -1 : 1;
}

/* --- install-state probes (bl-pkg records under <root>/var/lib/bl-pkg) ------ */

static int
pl_is_installed (const pl_cfg *c, const char *name)
{
  struct stat st;
  return c->statefd >= 0 && fstatat (c->statefd, name, &st, 0) == 0
         && S_ISREG (st.st_mode);
}

#define PL_TXN_OK        0
#define PL_TXN_ABSENT    1
#define PL_TXN_MALFORMED 2

/* Read the install transaction id recorded for NAME (txn=... in the state
 * file) into a malloc'd *OUT. Only the first txn= line counts. */
static int
pl_read_txn (const pl_cfg *c, const char *name, char **out)
{
  char line[PL_LINESZ];
  int fd, r, rc = PL_TXN_ABSENT;
  FILE *f;
  struct stat st;

  *out = NULL;
  if (c->statefd < 0
      || (fd = openat (c->statefd, name, O_RDONLY | O_CLOEXEC | O_NONBLOCK)) < 0)
    return PL_TXN_ABSENT;
  /* Check the opened object too: a FIFO must not block even if the state
   * changes between the installed probe and this open. */
  if (fstat (fd, &st) < 0 || !S_ISREG (st.st_mode))
    {
      close (fd);
      return PL_TXN_MALFORMED;
    }
  if (!(f = fdopen (fd, "r")))
    {
      close (fd);
      return PL_TXN_ABSENT;
    }
  while ((r = pl_getline (f, line, sizeof line)) != 0)
    {
      char *v;
      size_t i;
      if (r < 0)
        {
          if (strncmp (line, "txn=", 4) == 0)
            {
              rc = PL_TXN_MALFORMED;
              break;
            }
          continue;
        }
      if (strncmp (line, "txn=", 4) != 0)
        continue;
      v = line + 4;
      size_t len = strlen (v);
      if (len && v[len - 1] == '\n') v[--len] = '\0';
      if (len && v[len - 1] == '\r') v[--len] = '\0';
      rc = PL_TXN_MALFORMED;
      if (!*v || *v == '-' || strlen (v) >= PL_FLDSZ)
        break;
      for (i = 0; v[i]; i++)
        if ((unsigned char) v[i] <= ' ' || (unsigned char) v[i] >= 0x7f)
          break;
      if (v[i])
        break;
      *out = savestring (v);
      rc = PL_TXN_OK;
      break;
    }
  if (ferror (f) && rc == PL_TXN_ABSENT)
    rc = PL_TXN_MALFORMED;
  fclose (f);
  return rc;
}

/* --- INDEX parsing --------------------------------------------------------- */

typedef struct
{
  char name[PL_FLDSZ];
  char ver[PL_FLDSZ];
  char arch[PL_FLDSZ];
  char type[PL_FLDSZ];
  char prov[PL_FLDSZ];
} pl_rec;

/* Copy TOK's value when it carries KEY. Returns -1 if the value is too long. */
static int
pl_field (const char *tok, const char *key, char *out, size_t sz)
{
  size_t klen = strlen (key), vlen;
  if (strncmp (tok, key, klen) != 0)
    return 0;
  vlen = strlen (tok + klen);
  if (vlen >= sz)
    return -1;
  memcpy (out, tok + klen, vlen + 1);
  return 1;
}

#define PL_REC_NONE      0     /* not a blpkg-v1 line: comment, blank, other */
#define PL_REC_OK        1
#define PL_REC_MALFORMED 2     /* blpkg-v1 line we refuse to act on */

/* Parse one `blpkg-v1 ...` record line (mutated by strtok). */
static int
pl_parse_record (char *line, pl_rec *r)
{
  char *save = NULL, *tok;
  unsigned char *p;
  int bad = 0;
  if (strncmp (line, "blpkg-v1 ", 9) != 0 && strncmp (line, "blpkg-v1\t", 9) != 0)
    return PL_REC_NONE;
  for (p = (unsigned char *) line; *p; p++)
    if ((*p < ' ' && *p != '\t' && *p != '\r' && *p != '\n') || *p == 0x7f)
      return PL_REC_MALFORMED;
  r->name[0] = r->ver[0] = r->arch[0] = r->prov[0] = '\0';
  memcpy (r->type, "payload", sizeof "payload");
  tok = strtok_r (line, " \t", &save);          /* the blpkg-v1 magic */
  while ((tok = strtok_r (NULL, " \t\r\n", &save)) != NULL)
    {
      bad |= pl_field (tok, "name=",     r->name, sizeof r->name) < 0;
      bad |= pl_field (tok, "version=",  r->ver,  sizeof r->ver) < 0;
      bad |= pl_field (tok, "arch=",     r->arch, sizeof r->arch) < 0;
      bad |= pl_field (tok, "type=",     r->type, sizeof r->type) < 0;
      bad |= pl_field (tok, "provides=", r->prov, sizeof r->prov) < 0;
    }
  if (bad || !pl_valid_name (r->name))
    return PL_REC_MALFORMED;
  return PL_REC_OK;
}

/* Fetch the next usable record. Returns 1 with *R filled, 0 at EOF; malformed
 * and overlong blpkg-v1 lines are counted in *BAD and skipped. */
static int
pl_next_record (FILE *f, pl_rec *r, int *bad)
{
  char line[PL_LINESZ];
  int got;
  while ((got = pl_getline (f, line, sizeof line)) != 0)
    {
      int k;
      if (got < 0)
        {
          if (strncmp (line, "blpkg-v1", 8) == 0)
            (*bad)++;
          continue;
        }
      k = pl_parse_record (line, r);
      if (k == PL_REC_OK)
        return 1;
      if (k == PL_REC_MALFORMED)
        (*bad)++;
    }
  return 0;
}

/* Open the repo INDEX. On failure QUIET callers report it themselves; the
 * listing verbs keep their friendly stdout hint. */
static FILE *
pl_open_index (const pl_cfg *c, int quiet)
{
  char *idx;
  FILE *f = NULL;
  struct stat st;
  int fd, err;
  size_t len = strlen (c->repo);
  idx = xmalloc (len + sizeof "/INDEX");
  memcpy (idx, c->repo, len);
  memcpy (idx + len, "/INDEX", sizeof "/INDEX");
  fd = open (idx, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  free (idx);
  if (fd >= 0)
    {
      if (fstat (fd, &st) == 0)
        {
          if (S_ISREG (st.st_mode))
            f = fdopen (fd, "r");
          else
            errno = S_ISDIR (st.st_mode) ? EISDIR : EINVAL;
        }
      if (!f)
        {
          err = errno;
          close (fd);
          errno = err;
        }
    }
  err = errno;
  if (!f && !quiet)
    {
      builtin_error ("%s/INDEX: read error: %s", c->repo, strerror (err));
      printf ("payload: no payload repo staged at %s\n", c->repo);
      printf ("payload: (this image has no staged payloads; nothing to list)\n");
    }
  errno = err;
  return f;
}

/* Close the INDEX, reporting read errors and skipped records. Returns 0 if
 * the INDEX was read completely. */
static int
pl_close_index (const pl_cfg *c, FILE *f, int bad)
{
  int err = ferror (f) ? errno : 0;
  fclose (f);
  if (err)
    {
      builtin_error ("%s/INDEX: read error: %s", c->repo, strerror (err));
      return -1;
    }
  if (bad)
    builtin_warning ("%s/INDEX: skipped %d malformed record%s", c->repo, bad,
                     bad == 1 ? "" : "s");
  return 0;
}

static int
pl_finish_output (int status)
{
  if (fflush (stdout) == EOF || ferror (stdout))
    {
      builtin_error ("write error: %s", strerror (errno));
      clearerr (stdout);
      return EXECUTION_FAILURE;
    }
  return status;
}

/* --- verbs ----------------------------------------------------------------- */

/* filter: 0 = all, 1 = installed only, 2 = available only.
 * porcelain: machine-readable `status\tname\tversion\tprovides` per line, no
 *            header/summary (consumed by payload-menu.sh). */
static int
pl_verb_list (const pl_cfg *c, int filter, int porcelain)
{
  FILE *f;
  pl_rec r;
  bl_output output;
  int total = 0, installed = 0, shown = 0, bad = 0, read_rc;

  f = pl_open_index (c, 0);
  if (!f)
    return pl_finish_output (EXECUTION_FAILURE);

  /* Single streaming pass: total/installed are tallied as we go (the summary is
   * printed after the loop), so the INDEX is never buffered whole. */
  if (!porcelain)
    {
      printf ("payload: repo %s\n\n", c->repo);
      printf ("  %-10s  %-18s  %-12s  %s\n", "STATUS", "NAME", "VERSION", "PROVIDES");
    }
  /* Keep Bash's stdio settings intact. Pipe/file output is batched, while
   * terminal rows are still flushed at each newline. */
  bl_output_init (&output, stdout);
  while (pl_next_record (f, &r, &bad))
    {
      char row[4 * PL_FLDSZ + 64];
      int is_i, length;
      total++;
      is_i = pl_is_installed (c, r.name);
      if (is_i)
        installed++;
      if ((filter == 1 && !is_i) || (filter == 2 && is_i))
        continue;
      if (porcelain)
        length = snprintf (row, sizeof row, "%s\t%s\t%s\t%s\n",
                           is_i ? "installed" : "available",
                           r.name, r.ver[0] ? r.ver : "-", r.prov);
      else
        length = snprintf (row, sizeof row, "  %-10s  %-18s  %-12s  %s\n",
                           is_i ? "installed" : "available",
                           r.name, r.ver[0] ? r.ver : "-", r.prov);
      if (length < 0 || (size_t) length >= sizeof row)
        output.error = EOVERFLOW;
      else
        bl_output_write (&output, row, length);
      if (output.error)
        break;
      shown++;
    }
  read_rc = pl_close_index (c, f, bad);
  bl_output_flush (&output);
  if (output.error)
    {
      builtin_error ("write error: %s", strerror (output.error));
      clearerr (stdout);
      return EXECUTION_FAILURE;
    }
  if (read_rc < 0)
    return pl_finish_output (EXECUTION_FAILURE);
  if (porcelain)
    return pl_finish_output (EXECUTION_SUCCESS);
  printf ("\npayload: %d available, %d installed", total, installed);
  if (filter == 1)
    printf (" (showing installed)");
  else if (filter == 2)
    printf (" (showing not-installed)");
  printf ("\n");
  if (filter != 0 && shown == 0)
    printf ("payload: (none)\n");
  return pl_finish_output (EXECUTION_SUCCESS);
}

static int
pl_verb_info (const pl_cfg *c, const char *name)
{
  FILE *f;
  pl_rec r;
  int found = 0, bad = 0;
  char *txn;

  if (!pl_valid_name (name))
    {
      builtin_error ("info: invalid payload name '%s'", name);
      return EX_USAGE;
    }
  f = pl_open_index (c, 0);
  if (!f)
    return pl_finish_output (EXECUTION_FAILURE);
  while (pl_next_record (f, &r, &bad))
    if (strcmp (r.name, name) == 0)
      {
        found = 1;
        break;
      }
  if (pl_close_index (c, f, found ? 0 : bad) < 0)
    return pl_finish_output (EXECUTION_FAILURE);
  if (!found)
    {
      builtin_error ("info: no payload named '%s' in %s", name, c->repo);
      return pl_finish_output (EXECUTION_FAILURE);
    }
  printf ("name:      %s\n", r.name);
  printf ("version:   %s\n", r.ver[0] ? r.ver : "-");
  printf ("arch:      %s\n", r.arch[0] ? r.arch : "-");
  printf ("type:      %s\n", r.type);
  if (r.prov[0])
    printf ("provides:  %s\n", r.prov);
  if (!pl_is_installed (c, name))
    printf ("status:    available (not installed)\n");
  else if (pl_read_txn (c, name, &txn) == PL_TXN_OK)
    {
      printf ("status:    installed (txn %s)\n", txn);
      free (txn);
    }
  else
    printf ("status:    installed\n");
  return pl_finish_output (EXECUTION_SUCCESS);
}

/* The helper is a script run by $BASH, so it needs to be a readable regular
 * file, not an executable one. Returns 0, or the 127/126 status to report. */
static int
pl_check_helper (const pl_cfg *c, const char *verb)
{
  struct stat st;
  if (stat (c->installer, &st) < 0)
    {
      int err = errno;
      builtin_error ("%s: installer %s: %s", verb, c->installer, strerror (err));
      return err == ENOENT || err == ENOTDIR ? 127 : 126;
    }
  if (!S_ISREG (st.st_mode))
    {
      builtin_error ("%s: installer %s: not a regular file", verb, c->installer);
      return 126;
    }
  if (access (c->installer, R_OK) < 0)
    {
      builtin_error ("%s: installer %s: %s", verb, c->installer, strerror (errno));
      return 126;
    }
  return 0;
}

/* Run argv synchronously. Returns the child's exit status, 128+N if signal N
 * killed it, or 126/127 if it could not be started (-1 if fork failed). */
static int
pl_run (char **argv)
{
  bos_child_wait child_wait;
  pid_t pid, w;
  int st = 0;

  if (bos_child_wait_begin (&child_wait) < 0)
    {
      builtin_error ("SIGCHLD setup: %s", strerror (errno));
      return -1;
    }
  /* Exported variables and `VAR=x payload ...` assignments reach the helper. */
  maybe_make_export_env ();
  fflush (stdout);
  fflush (stderr);
  pid = fork ();
  if (pid < 0)
    {
      int e = errno;
      bos_child_wait_end (&child_wait);
      builtin_error ("fork: %s", strerror (e));
      return -1;
    }
  if (pid == 0)
    {
      int e;
      bos_prepare_child ();
      bos_child_wait_child (&child_wait);
      environ = export_env;
      execvp (argv[0], argv);
      e = errno;
      fprintf (stderr, "payload: %s: %s\n", argv[0], strerror (e));
      _exit (e == ENOENT ? 127 : 126);
    }
  while ((w = waitpid (pid, &st, 0)) < 0 && errno == EINTR)
    ;
  if (w < 0)
    {
      int e = errno;
      bos_child_wait_end (&child_wait);
      builtin_error ("waitpid: %s", strerror (e));
      return -1;
    }
  bos_child_wait_end (&child_wait);
  if (WIFEXITED (st))
    return WEXITSTATUS (st);
  if (WIFSIGNALED (st))
    return 128 + WTERMSIG (st);
  return -1;
}

/* payload install NAME...  ->  bash bl-pkg.sh --internal --root R --repo REPO
 *                               --allow-unsigned install NAME...
 * Every NAME must be valid and listed in the INDEX before the helper runs. */
static int
pl_verb_install (const pl_cfg *c, WORD_LIST *names)
{
  WORD_LIST *l;
  int count = 0, n = 0, i, rc, bad = 0, missing = 0;
  char **argv, *found;
  FILE *f;
  pl_rec r;

  for (l = names; l; l = l->next)
    {
      if (!pl_valid_name (l->word->word))
        {
          builtin_error ("install: invalid payload name '%s'", l->word->word);
          return EX_USAGE;
        }
      count++;
    }
  if (count == 0)
    {
      builtin_error ("install: at least one NAME required");
      return EX_USAGE;
    }

  if (!(f = pl_open_index (c, 1)))
    {
      builtin_error ("install: no payload repo staged at %s (INDEX read error): %s", c->repo,
                     strerror (errno));
      return EXECUTION_FAILURE;
    }
  found = xmalloc (count);
  memset (found, 0, count);
  while (pl_next_record (f, &r, &bad))
    for (i = 0, l = names; l; l = l->next, i++)
      if (strcmp (r.name, l->word->word) == 0)
        found[i] = 1;
  if (pl_close_index (c, f, bad) < 0)
    {
      free (found);
      return EXECUTION_FAILURE;
    }
  for (i = 0, l = names; l; l = l->next, i++)
    if (!found[i])
      {
        builtin_error ("install: no payload named '%s' in %s", l->word->word,
                       c->repo);
        missing++;
      }
  free (found);
  if (missing)
    return EXECUTION_FAILURE;
  if ((rc = pl_check_helper (c, "install")) != 0)
    return rc;

  argv = (char **) xmalloc ((10 + count) * sizeof (char *));
  argv[n++] = c->bash;
  argv[n++] = c->installer;
  argv[n++] = (char *) "--internal";
  argv[n++] = (char *) "--root";
  argv[n++] = c->root;
  argv[n++] = (char *) "--repo";
  argv[n++] = c->repo;
  argv[n++] = (char *) "--allow-unsigned";
  argv[n++] = (char *) "install";
  for (l = names; l; l = l->next)
    argv[n++] = l->word->word;
  argv[n] = NULL;

  rc = pl_run (argv);
  free (argv);
  if (rc != 0)
    {
      builtin_error ("install failed (bl-pkg exit %d)", rc);
      return rc > 0 ? rc : EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

/* payload remove NAME...  ->  snapshot the requested install txn IDs, then
 *                     bash bl-pkg.sh --internal --root R rollback TXN
 * A rollback may remove several state files. Resolve names before any helper
 * runs and attempt each distinct transaction just once, including failures.
 * Returns the first failing helper status, else 1 if any NAME was refused. */
static int
pl_verb_remove (const pl_cfg *c, WORD_LIST *names)
{
  WORD_LIST *l;
  int refused = 0, helper_rc = 0, checked = 0, count = 0, i, j;
  struct request { const char *name; char *txn; int rc; } *requests;

  if (names == NULL)
    {
      builtin_error ("remove: at least one NAME required");
      return EX_USAGE;
    }
  for (l = names; l; l = l->next)
    count++;
  requests = xmalloc (count * sizeof *requests);
  memset (requests, 0, count * sizeof *requests);
  /* Keep valid references even when an earlier rollback removes their files. */
  for (l = names, i = 0; l; l = l->next, i++)
    {
      const char *name = requests[i].name = l->word->word;
      int rc;
      if (!pl_valid_name (name))
        {
          builtin_error ("remove: invalid payload name '%s'", name);
          refused++;
        }
      else if (!pl_is_installed (c, name))
        {
          builtin_error ("remove: '%s' is not installed", name);
          refused++;
        }
      else if ((rc = pl_read_txn (c, name, &requests[i].txn)) != PL_TXN_OK)
        {
          builtin_error ("remove: cannot determine install transaction for '%s' "
                         "(%s txn= in its bl-pkg state); use 'pkg remove %s' "
                         "or roll back manually",
                         name, rc == PL_TXN_ABSENT ? "no" : "malformed", name);
          refused++;
        }
    }
  for (i = 0; i < count; i++)
    {
      const char *name = requests[i].name;
      char *txn = requests[i].txn;
      char *argv[8];
      int n = 0, rc;

      if (!txn)
        continue;
      if (!checked)
        {
          if ((rc = pl_check_helper (c, "remove")) != 0)
            {
              helper_rc = rc;
              break;
            }
          checked = 1;
        }
      argv[n++] = c->bash;
      argv[n++] = c->installer;
      argv[n++] = (char *) "--internal";
      argv[n++] = (char *) "--root";
      argv[n++] = c->root;
      argv[n++] = (char *) "rollback";
      argv[n++] = txn;
      argv[n] = NULL;

      for (j = 0; j < i; j++)
        if (requests[j].txn && strcmp (requests[j].txn, txn) == 0)
          break;
      rc = requests[i].rc = j < i ? requests[j].rc : pl_run (argv);
      if (rc != 0)
        {
          builtin_error ("remove: rollback failed for '%s' (bl-pkg exit %d)",
                         name, rc);
          if (!helper_rc)
            helper_rc = rc > 0 ? rc : EXECUTION_FAILURE;
        }
      else
        printf ("payload: removed %s\n", name);
    }
  for (i = 0; i < count; i++)
    free (requests[i].txn);
  free (requests);
  if (helper_rc)
    return pl_finish_output (helper_rc);
  return pl_finish_output (refused ? EXECUTION_FAILURE : EXECUTION_SUCCESS);
}

/* --- entry point ----------------------------------------------------------- */

static int
pl_dispatch (const pl_cfg *c, WORD_LIST *list)
{
  const char *verb;
  WORD_LIST *rest;

  if (list == NULL)
    return pl_verb_list (c, 0, 0);      /* bare `payload` == `payload list`  */

  verb = list->word->word;
  rest = list->next;

  if (strcmp (verb, "list") == 0)
    {
      int filter = 0, porcelain = 0;
      WORD_LIST *o;
      for (o = rest; o; o = o->next)
        {
          const char *opt = o->word->word;
          if (strcmp (opt, "--installed") == 0)
            filter = 1;
          else if (strcmp (opt, "--available") == 0)
            filter = 2;
          else if (strcmp (opt, "--porcelain") == 0 || strcmp (opt, "-p") == 0)
            porcelain = 1;
          else
            {
              builtin_error ("list: unknown option '%s' "
                             "(use --installed, --available, or --porcelain)", opt);
              return EX_USAGE;
            }
        }
      return pl_verb_list (c, filter, porcelain);
    }
  if (strcmp (verb, "installed") == 0)
    {
      if (rest)
        {
          builtin_error ("installed: unexpected argument '%s'", rest->word->word);
          return EX_USAGE;
        }
      return pl_verb_list (c, 1, 0);
    }
  if (strcmp (verb, "info") == 0)
    {
      if (!rest || !rest->word || !rest->word->word)
        {
          builtin_error ("info: a payload NAME is required");
          return EX_USAGE;
        }
      if (rest->next)
        {
          builtin_error ("info: unexpected argument '%s'", rest->next->word->word);
          return EX_USAGE;
        }
      return pl_verb_info (c, rest->word->word);
    }
  if (strcmp (verb, "install") == 0)
    return pl_verb_install (c, rest);
  if (strcmp (verb, "remove") == 0)
    return pl_verb_remove (c, rest);
  if (strcmp (verb, "help") == 0 || strcmp (verb, "--help") == 0
      || strcmp (verb, "-h") == 0)
    {
      char **d;
      printf ("usage: %s\n\n", payload_struct.short_doc);
      for (d = payload_doc; *d; d++)
        printf ("%s\n", *d);
      return pl_finish_output (EXECUTION_SUCCESS);
    }

  builtin_error ("unknown verb: %s (try `payload help`)", verb);
  return EX_USAGE;
}

int
payload_builtin (WORD_LIST *list)
{
  pl_cfg c;
  int rc;

  clearerr (stdout);
  pl_cfg_init (&c);
  rc = pl_dispatch (&c, list);
  pl_cfg_free (&c);
  return rc;
}

char *payload_doc[] = {
  "Manage bashy.box native payloads (bun, python3, rust, npm, gcc, ...).",
  "",
  "A friendly, pre-wired front-end over the per-instance bl-pkg payload share",
  "(default /root/loadables). list/info read the share INDEX and install state",
  "natively; install/remove reuse /bash-os/bl-pkg.sh (remove rolls back the",
  "transaction that installed the payload).",
  "",
  "Verbs:",
  "    payload [list [--installed|--available] [--porcelain]]",
  "                                               list payloads + status",
  "    payload installed                          list installed payloads only",
  "    payload info NAME                          show one payload's record/state",
  "    payload install NAME...                    install from the share",
  "    payload remove  NAME...                    remove (rollback the install)",
  "    payload help",
  "",
  "Env overrides: PAYLOAD_REPO (or BASHPKG_LOADABLES_DATADIR), PAYLOAD_ROOT,",
  "PAYLOAD_INSTALLER. Installs are unsigned local-repo installs (the share is a",
  "trusted host-staged repo); use `pkg` for the signed mirror workflow.",
  "",
  "Exit status: 0 on success, 2 for usage errors or invalid names, 127/126 if",
  "the installer is missing or unreadable, otherwise the installer's own status",
  "(128+N if signal N killed it); 1 for other failures.",
  (char *) NULL
};

struct builtin payload_struct = {
  "payload",
  payload_builtin,
  BUILTIN_ENABLED,
  payload_doc,
  "payload [list|installed|info|install|remove|help] [ARG...]",
  0
};
