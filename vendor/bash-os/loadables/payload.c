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
 *
 * Env overrides (all optional):
 *   BASHPKG_LOADABLES_DATADIR / PAYLOAD_REPO   repo dir   (default /root/loadables)
 *   PAYLOAD_ROOT                               install root (default /)
 *   PAYLOAD_INSTALLER                          installer  (default /bash-os/bl-pkg.sh)
 *
 * Static-musl notes: fixed 4 KiB path buffers (no PATH_MAX reliance), fgets (no
 * getline feature-macro dance), pure POSIX fork/exec.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "loadables.h"

#define PL_DEFAULT_REPO      "/root/loadables"
#define PL_DEFAULT_ROOT      "/"
#define PL_DEFAULT_INSTALLER "/bash-os/bl-pkg.sh"

#define PL_PATHSZ 4096
#define PL_LINESZ 8192
#define PL_FLDSZ  256

/* --- configuration sources (env first, then bash variable, then default) --- */

static const char *
pl_getvar (const char *env_name, const char *bash_name, const char *dflt)
{
  const char *v = env_name ? getenv (env_name) : NULL;
  if (v && *v)
    return v;
  if (bash_name)
    {
      char *b = get_string_value (bash_name);
      if (b && *b)
        return b;
    }
  return dflt;
}

static const char *
pl_repo (void)
{
  /* PAYLOAD_REPO overrides; else BASHPKG_LOADABLES_DATADIR (set by /init), as
   * the payload-autoinstall service and download_codex use; else the default. */
  const char *v = getenv ("PAYLOAD_REPO");
  if (v && *v)
    return v;
  return pl_getvar ("BASHPKG_LOADABLES_DATADIR", "BASHPKG_LOADABLES_DATADIR",
                    PL_DEFAULT_REPO);
}

static const char *
pl_root (void)
{
  return pl_getvar ("PAYLOAD_ROOT", NULL, PL_DEFAULT_ROOT);
}

static const char *
pl_installer (void)
{
  return pl_getvar ("PAYLOAD_INSTALLER", NULL, PL_DEFAULT_INSTALLER);
}

static const char *
pl_bash (void)
{
  /* The bl-pkg.sh script ships non-executable, so run it with bash. Prefer the
   * running shell's $BASH; fall back to a PATH lookup of `bash`. */
  char *b = get_string_value ("BASH");
  if (b && *b)
    return b;
  const char *e = getenv ("BASH");
  return (e && *e) ? e : "bash";
}

/* --- install-state probes (bl-pkg records under <root>/var/lib/bl-pkg) ------ */

static void
pl_state_path (char *out, size_t sz, const char *name)
{
  /* Double slash when root ends in '/' is harmless on Linux. */
  snprintf (out, sz, "%s/var/lib/bl-pkg/installed/%s", pl_root (), name);
}

static int
pl_is_installed (const char *name)
{
  char p[PL_PATHSZ];
  struct stat st;
  pl_state_path (p, sizeof p, name);
  return stat (p, &st) == 0;
}

/* Read the install transaction id recorded for NAME (txn=... in the state
 * file). Returns a malloc'd string (caller frees) or NULL if absent. */
static char *
pl_read_txn (const char *name)
{
  char p[PL_PATHSZ], line[PL_LINESZ], *txn = NULL;
  FILE *f;
  pl_state_path (p, sizeof p, name);
  f = fopen (p, "r");
  if (!f)
    return NULL;
  while (fgets (line, sizeof line, f))
    {
      if (strncmp (line, "txn=", 4) == 0)
        {
          char *v = line + 4;
          v[strcspn (v, "\r\n")] = '\0';
          if (*v)
            txn = savestring (v);
          break;
        }
    }
  fclose (f);
  return txn;
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

static void
pl_field (const char *tok, const char *key, char *out, size_t sz)
{
  size_t klen = strlen (key);
  if (strncmp (tok, key, klen) == 0)
    snprintf (out, sz, "%s", tok + klen);
}

/* Parse one `blpkg-v1 ...` record line (mutated by strtok). Returns 1 if it is
 * a record with a name=, else 0. */
static int
pl_parse_record (char *line, pl_rec *r)
{
  char *save = NULL, *tok;
  if (strncmp (line, "blpkg-v1 ", 9) != 0 && strncmp (line, "blpkg-v1\t", 9) != 0)
    return 0;
  r->name[0] = r->ver[0] = r->arch[0] = r->prov[0] = '\0';
  snprintf (r->type, sizeof r->type, "%s", "payload");
  tok = strtok_r (line, " \t", &save);          /* the blpkg-v1 magic */
  while ((tok = strtok_r (NULL, " \t\r\n", &save)) != NULL)
    {
      pl_field (tok, "name=",     r->name, sizeof r->name);
      pl_field (tok, "version=",  r->ver,  sizeof r->ver);
      pl_field (tok, "arch=",     r->arch, sizeof r->arch);
      pl_field (tok, "type=",     r->type, sizeof r->type);
      pl_field (tok, "provides=", r->prov, sizeof r->prov);
    }
  return r->name[0] != '\0';
}

static void
pl_index_path (char *out, size_t sz)
{
  snprintf (out, sz, "%s/INDEX", pl_repo ());
}

/* Open the repo INDEX, or print a friendly hint and return NULL. */
static FILE *
pl_open_index (void)
{
  char idx[PL_PATHSZ];
  FILE *f;
  pl_index_path (idx, sizeof idx);
  f = fopen (idx, "r");
  if (!f)
    {
      printf ("payload: no payload repo staged at %s\n", pl_repo ());
      printf ("payload: (this image has no staged payloads; nothing to list)\n");
    }
  return f;
}

/* --- verbs ----------------------------------------------------------------- */

/* filter: 0 = all, 1 = installed only, 2 = available only.
 * porcelain: machine-readable `status\tname\tversion\tprovides` per line, no
 *            header/summary (consumed by payload-menu.sh). */
static int
pl_verb_list (int filter, int porcelain)
{
  char line[PL_LINESZ];
  FILE *f;
  int total = 0, installed = 0, shown = 0;

  f = pl_open_index ();
  if (!f)
    return EXECUTION_FAILURE;

  /* Single streaming pass: total/installed are tallied as we go (the summary is
   * printed after the loop), so the INDEX is never buffered whole. */
  if (!porcelain)
    {
      printf ("payload: repo %s\n\n", pl_repo ());
      printf ("  %-10s  %-18s  %-12s  %s\n", "STATUS", "NAME", "VERSION", "PROVIDES");
    }
  while (fgets (line, sizeof line, f))
    {
      pl_rec r;
      char tmp[PL_LINESZ];
      int is_i;
      snprintf (tmp, sizeof tmp, "%s", line);
      if (!pl_parse_record (tmp, &r))
        continue;
      total++;
      is_i = pl_is_installed (r.name);
      if (is_i)
        installed++;
      if ((filter == 1 && !is_i) || (filter == 2 && is_i))
        continue;
      if (porcelain)
        printf ("%s\t%s\t%s\t%s\n", is_i ? "installed" : "available",
                r.name, r.ver[0] ? r.ver : "-", r.prov);
      else
        printf ("  %-10s  %-18s  %-12s  %s\n",
                is_i ? "installed" : "available",
                r.name, r.ver[0] ? r.ver : "-", r.prov);
      shown++;
    }
  fclose (f);
  if (porcelain)
    return EXECUTION_SUCCESS;
  printf ("\npayload: %d available, %d installed", total, installed);
  if (filter == 1)
    printf (" (showing installed)");
  else if (filter == 2)
    printf (" (showing not-installed)");
  printf ("\n");
  if (filter != 0 && shown == 0)
    printf ("payload: (none)\n");
  return EXECUTION_SUCCESS;
}

static int
pl_verb_info (const char *name)
{
  char line[PL_LINESZ];
  FILE *f;
  int found = 0;

  f = pl_open_index ();
  if (!f)
    return EXECUTION_FAILURE;
  while (fgets (line, sizeof line, f))
    {
      pl_rec r;
      char tmp[PL_LINESZ];
      snprintf (tmp, sizeof tmp, "%s", line);
      if (!pl_parse_record (tmp, &r))
        continue;
      if (strcmp (r.name, name) != 0)
        continue;
      found = 1;
      printf ("name:      %s\n", r.name);
      printf ("version:   %s\n", r.ver[0] ? r.ver : "-");
      printf ("arch:      %s\n", r.arch[0] ? r.arch : "-");
      printf ("type:      %s\n", r.type);
      if (r.prov[0])
        printf ("provides:  %s\n", r.prov);
      break;
    }
  fclose (f);
  if (!found)
    {
      builtin_error ("info: no payload named '%s' in %s", name, pl_repo ());
      return EXECUTION_FAILURE;
    }
  if (pl_is_installed (name))
    {
      char *txn = pl_read_txn (name);
      if (txn)
        {
          printf ("status:    installed (txn %s)\n", txn);
          free (txn);
        }
      else
        printf ("status:    installed\n");
    }
  else
    printf ("status:    available (not installed)\n");
  return EXECUTION_SUCCESS;
}

/* Run argv synchronously; return its exit status, or -1 on spawn failure. */
static int
pl_run (char **argv)
{
  pid_t pid = fork ();
  int st;
  if (pid < 0)
    {
      builtin_error ("fork: %s", strerror (errno));
      return -1;
    }
  if (pid == 0)
    {
      execvp (argv[0], argv);
      _exit (127);
    }
  while (waitpid (pid, &st, 0) < 0 && errno == EINTR)
    ;
  if (WIFEXITED (st))
    return WEXITSTATUS (st);
  return -1;
}

/* payload install NAME...  ->  bash bl-pkg.sh --internal --root R --repo REPO
 *                               --allow-unsigned install NAME...               */
static int
pl_verb_install (WORD_LIST *names)
{
  WORD_LIST *l;
  int count = 0, n = 0, rc;
  char **argv;

  for (l = names; l; l = l->next)
    count++;
  if (count == 0)
    {
      builtin_error ("install: at least one NAME required");
      return EX_USAGE;
    }
  argv = (char **) xmalloc ((10 + count) * sizeof (char *));
  argv[n++] = (char *) pl_bash ();
  argv[n++] = (char *) pl_installer ();
  argv[n++] = (char *) "--internal";
  argv[n++] = (char *) "--root";
  argv[n++] = (char *) pl_root ();
  argv[n++] = (char *) "--repo";
  argv[n++] = (char *) pl_repo ();
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
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

/* payload remove NAME...  ->  for each: look up its install txn, then
 *                             bash bl-pkg.sh --internal --root R rollback TXN   */
static int
pl_verb_remove (WORD_LIST *names)
{
  WORD_LIST *l;
  int failures = 0, any = 0;

  if (names == NULL)
    {
      builtin_error ("remove: at least one NAME required");
      return EX_USAGE;
    }
  for (l = names; l; l = l->next)
    {
      const char *name = l->word->word;
      char *txn;
      char *argv[8];
      int n = 0, rc;

      any = 1;
      if (!pl_is_installed (name))
        {
          builtin_error ("remove: '%s' is not installed", name);
          failures++;
          continue;
        }
      txn = pl_read_txn (name);
      if (!txn)
        {
          builtin_error ("remove: cannot determine install transaction for '%s' "
                         "(no txn= in its bl-pkg state); use 'pkg remove %s' "
                         "or roll back manually",
                         name, name);
          failures++;
          continue;
        }
      argv[n++] = (char *) pl_bash ();
      argv[n++] = (char *) pl_installer ();
      argv[n++] = (char *) "--internal";
      argv[n++] = (char *) "--root";
      argv[n++] = (char *) pl_root ();
      argv[n++] = (char *) "rollback";
      argv[n++] = txn;
      argv[n] = NULL;

      rc = pl_run (argv);
      free (txn);
      if (rc != 0)
        {
          builtin_error ("remove: rollback failed for '%s' (bl-pkg exit %d)",
                         name, rc);
          failures++;
        }
      else
        printf ("payload: removed %s\n", name);
    }
  if (!any)
    return EX_USAGE;
  return failures ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

/* --- entry point ----------------------------------------------------------- */

int
payload_builtin (WORD_LIST *list)
{
  const char *verb;
  WORD_LIST *rest;

  if (list == NULL)
    return pl_verb_list (0, 0);         /* bare `payload` == `payload list`  */

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
      return pl_verb_list (filter, porcelain);
    }
  if (strcmp (verb, "installed") == 0)
    return pl_verb_list (1, 0);
  if (strcmp (verb, "info") == 0)
    {
      if (!rest || !rest->word || !rest->word->word)
        {
          builtin_error ("info: a payload NAME is required");
          return EX_USAGE;
        }
      return pl_verb_info (rest->word->word);
    }
  if (strcmp (verb, "install") == 0)
    return pl_verb_install (rest);
  if (strcmp (verb, "remove") == 0)
    return pl_verb_remove (rest);
  if (strcmp (verb, "help") == 0 || strcmp (verb, "--help") == 0
      || strcmp (verb, "-h") == 0)
    {
      builtin_usage ();
      return EXECUTION_SUCCESS;
    }

  builtin_error ("unknown verb: %s (try `payload help`)", verb);
  return EX_USAGE;
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
  "    payload [list [--installed|--available]]   list payloads + status",
  "    payload installed                          list installed payloads only",
  "    payload info NAME                          show one payload's record/state",
  "    payload install NAME...                    install from the share",
  "    payload remove  NAME...                    remove (rollback the install)",
  "    payload help",
  "",
  "Env overrides: PAYLOAD_REPO (or BASHPKG_LOADABLES_DATADIR), PAYLOAD_ROOT,",
  "PAYLOAD_INSTALLER. Installs are unsigned local-repo installs (the share is a",
  "trusted host-staged repo); use `pkg` for the signed mirror workflow.",
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
