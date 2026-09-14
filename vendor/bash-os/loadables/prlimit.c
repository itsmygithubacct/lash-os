/* SPDX-License-Identifier: MIT */
/* prlimit.c — prlimit(8) subset over prlimit(2).
 *
 *   prlimit [-r RES]                 (no --pid: the calling process)
 *   prlimit --pid PID
 *   prlimit --pid PID -r RES
 *   prlimit --pid PID -r RES SOFT[:HARD]
 *   prlimit --pid PID --nofile[=SOFT[:HARD]]
 *   prlimit --json --pid PID [-r RES]
 *   prlimit --raw --noheadings --pid PID [-r RES]
 *   prlimit --nofile=SOFT[:HARD] COMMAND [ARG...]
 *   prlimit --help | --version
 *
 * v1 covers arbitrary-PID query/set and spawn-and-exec mode.
 *
 * Source counterpart:
 *   research/refs/util-linux/sys-utils/prlimit.c
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
#include <ctype.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "loadables.h"

typedef struct bpl_res {
  const char *name;
  int resource;
} bpl_res;

typedef struct bpl_alias {
  const char *longopt;
  char shortopt;
  const char *resource_name;
} bpl_alias;

static const bpl_res bpl_resources[] = {
#ifdef RLIMIT_AS
  { "AS", RLIMIT_AS },
#endif
#ifdef RLIMIT_CORE
  { "CORE", RLIMIT_CORE },
#endif
#ifdef RLIMIT_CPU
  { "CPU", RLIMIT_CPU },
#endif
#ifdef RLIMIT_DATA
  { "DATA", RLIMIT_DATA },
#endif
#ifdef RLIMIT_FSIZE
  { "FSIZE", RLIMIT_FSIZE },
#endif
#ifdef RLIMIT_LOCKS
  { "LOCKS", RLIMIT_LOCKS },
#endif
#ifdef RLIMIT_MEMLOCK
  { "MEMLOCK", RLIMIT_MEMLOCK },
#endif
#ifdef RLIMIT_MSGQUEUE
  { "MSGQUEUE", RLIMIT_MSGQUEUE },
#endif
#ifdef RLIMIT_NICE
  { "NICE", RLIMIT_NICE },
#endif
#ifdef RLIMIT_NOFILE
  { "NOFILE", RLIMIT_NOFILE },
#endif
#ifdef RLIMIT_NPROC
  { "NPROC", RLIMIT_NPROC },
#endif
#ifdef RLIMIT_RSS
  { "RSS", RLIMIT_RSS },
#endif
#ifdef RLIMIT_RTPRIO
  { "RTPRIO", RLIMIT_RTPRIO },
#endif
#ifdef RLIMIT_RTTIME
  { "RTTIME", RLIMIT_RTTIME },
#endif
#ifdef RLIMIT_SIGPENDING
  { "SIGPENDING", RLIMIT_SIGPENDING },
#endif
#ifdef RLIMIT_STACK
  { "STACK", RLIMIT_STACK },
#endif
  { NULL, 0 }
};

static const bpl_alias bpl_aliases[] = {
  { "as",         'v', "AS" },
  { "core",       'c', "CORE" },
  { "cpu",        't', "CPU" },
  { "data",       'd', "DATA" },
  { "fsize",      'f', "FSIZE" },
  { "locks",      'x', "LOCKS" },
  { "memlock",    'l', "MEMLOCK" },
  { "msgqueue",   'q', "MSGQUEUE" },
  { "nice",       'e', "NICE" },
  { "nofile",     'n', "NOFILE" },
  { "nproc",      'u', "NPROC" },
  { "rss",        'm', "RSS" },
  { "rtprio",      0, "RTPRIO" }, /* -r is the historic -r RES selector. */
  { "rttime",     'y', "RTTIME" },
  { "sigpending", 'i', "SIGPENDING" },
  { "stack",      's', "STACK" },
  { NULL,          0, NULL }
};

static int
bpl_prlimit (pid_t pid, int resource, const struct rlimit *newlim,
             struct rlimit *oldlim)
{
#if defined (SYS_prlimit64)
  return (int) syscall (SYS_prlimit64, pid, resource, newlim, oldlim);
#else
  return prlimit (pid, resource, newlim, oldlim);
#endif
}

static const bpl_res *
bpl_find_res (const char *name)
{
  for (const bpl_res *r = bpl_resources; r->name; r++)
    if (strcasecmp (r->name, name) == 0)
      return r;
  return NULL;
}

static const bpl_alias *
bpl_find_long_alias (const char *name, size_t len)
{
  for (const bpl_alias *a = bpl_aliases; a->longopt; a++)
    if (strlen (a->longopt) == len && strncmp (a->longopt, name, len) == 0)
      return a;
  return NULL;
}

static const bpl_alias *
bpl_find_short_alias (char opt)
{
  for (const bpl_alias *a = bpl_aliases; a->longopt; a++)
    if (a->shortopt == opt)
      return a;
  return NULL;
}

static int
bpl_select_resource (const char **res_name, const char **set_spec,
                     const char *new_res, const char *new_spec)
{
  if (*res_name && strcasecmp (*res_name, new_res) != 0)
    {
      builtin_error ("only one resource may be selected");
      return EX_USAGE;
    }
  *res_name = new_res;
  if (new_spec)
    {
      if (*set_spec)
        {
          builtin_error ("only one limit value may be specified");
          return EX_USAGE;
        }
      *set_spec = new_spec;
    }
  return EXECUTION_SUCCESS;
}

static void
bpl_format_limit (char *buf, size_t bufsz, rlim_t v)
{
  if (v == RLIM_INFINITY)
    snprintf (buf, bufsz, "unlimited");
  else
    snprintf (buf, bufsz, "%llu", (unsigned long long) v);
}

/* Bits recording which side(s) of a SOFT:HARD spec were given explicitly;
 * an omitted side is later filled from the resource's current limit, to
 * match prlimit(1)'s `:hard` / `soft:` partial-range forms. */
#define BPL_SOFT (1 << 0)
#define BPL_HARD (1 << 1)

static int
bpl_parse_limit_value (const char *s, rlim_t *out)
{
  char *end = NULL;
  unsigned long long v;
  if (strcasecmp (s, "unlimited") == 0 || strcmp (s, "inf") == 0)
    { *out = RLIM_INFINITY; return 0; }
  if (*s == '\0' || *s == '-')
    return -1;
  errno = 0;
  v = strtoull (s, &end, 10);
  if (errno || !end || *end != '\0')
    return -1;
  *out = (rlim_t) v;
  return 0;
}

/* Parse a SOFT[:HARD] spec. *found records which sides were explicit
 * (BPL_SOFT/BPL_HARD); an empty side ("soft:" or ":hard") leaves the
 * corresponding rlimit field untouched for the caller to fill from the
 * current limit. Mirrors prlimit(1)'s get_range(). */
static int
bpl_parse_limit_pair (const char *s, struct rlimit *lim, int *found)
{
  char *copy = strdup (s);
  char *colon;
  int rc = -1;
  if (!copy)
    return -1;
  *found = 0;
  lim->rlim_cur = lim->rlim_max = 0;
  colon = strchr (copy, ':');
  if (colon)
    *colon++ = '\0';
  if (!colon)
    {
      /* bare value or "unlimited" → both soft and hard */
      if (bpl_parse_limit_value (copy, &lim->rlim_cur) == 0)
        {
          lim->rlim_max = lim->rlim_cur;
          *found = BPL_SOFT | BPL_HARD;
          rc = 0;
        }
    }
  else
    {
      int ok = 1;
      if (*copy != '\0')          /* left of colon: soft */
        {
          if (bpl_parse_limit_value (copy, &lim->rlim_cur) == 0)
            *found |= BPL_SOFT;
          else
            ok = 0;
        }
      if (ok && *colon != '\0')   /* right of colon: hard */
        {
          if (bpl_parse_limit_value (colon, &lim->rlim_max) == 0)
            *found |= BPL_HARD;
          else
            ok = 0;
        }
      /* a bare ":" (neither side given) is not a valid spec */
      if (ok && *found != 0)
        rc = 0;
    }
  free (copy);
  return rc;
}

/* Fill any side not explicitly given from the resource's current limit on
 * PID, matching prlimit(1)'s get_unknown_hardsoft(). */
static int
bpl_fill_unspecified (pid_t pid, const bpl_res *res, struct rlimit *lim,
                      int found)
{
  struct rlimit cur;
  if (found == (BPL_SOFT | BPL_HARD))
    return 0;
  if (bpl_prlimit (pid, res->resource, NULL, &cur) < 0)
    {
      builtin_error ("pid %ld %s: %s", (long) pid, res->name, strerror (errno));
      return -1;
    }
  if (!(found & BPL_SOFT))
    lim->rlim_cur = cur.rlim_cur;
  if (!(found & BPL_HARD))
    lim->rlim_max = cur.rlim_max;
  return 0;
}

/* Reject soft > hard, matching prlimit(1)'s explicit check (the kernel
 * would otherwise return EINVAL with a less specific message). */
static int
bpl_check_soft_le_hard (const bpl_res *res, const struct rlimit *lim)
{
  if (lim->rlim_cur > lim->rlim_max
      && (lim->rlim_cur != RLIM_INFINITY || lim->rlim_max != RLIM_INFINITY))
    {
      builtin_error ("the soft limit %s cannot exceed the hard limit",
                     res->name);
      return -1;
    }
  return 0;
}

static int
bpl_parse_pid (const char *s, pid_t *out)
{
  char *end = NULL;
  long v;
  errno = 0;
  v = strtol (s, &end, 10);
  if (errno || !end || *end != '\0' || v <= 0 || v > INT_MAX)
    return -1;
  *out = (pid_t) v;
  return 0;
}

static void
bpl_print_one (const bpl_res *res, const struct rlimit *lim)
{
  char soft[64], hard[64];
  bpl_format_limit (soft, sizeof soft, lim->rlim_cur);
  bpl_format_limit (hard, sizeof hard, lim->rlim_max);
  printf ("%s %s %s\n", res->name, soft, hard);
}

static void
bpl_print_raw_one (const bpl_res *res, const struct rlimit *lim)
{
  char soft[64], hard[64];
  bpl_format_limit (soft, sizeof soft, lim->rlim_cur);
  bpl_format_limit (hard, sizeof hard, lim->rlim_max);
  printf ("%s\t%s\t%s\n", res->name, soft, hard);
}

static void
bpl_print_json_one (pid_t pid, const bpl_res *res, const struct rlimit *lim)
{
  char soft[64], hard[64];
  bpl_format_limit (soft, sizeof soft, lim->rlim_cur);
  bpl_format_limit (hard, sizeof hard, lim->rlim_max);
  printf ("{\"pid\":%ld,\"resource\":\"%s\",\"soft\":\"%s\",\"hard\":\"%s\"}",
          (long) pid, res->name, soft, hard);
}

static int
bpl_show_one (pid_t pid, const bpl_res *res, int json, int raw)
{
  struct rlimit oldlim;
  if (bpl_prlimit (pid, res->resource, NULL, &oldlim) < 0)
    {
      builtin_error ("pid %ld %s: %s", (long) pid, res->name, strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (json)
    {
      bpl_print_json_one (pid, res, &oldlim);
      putchar ('\n');
    }
  else
    {
      if (raw)
        bpl_print_raw_one (res, &oldlim);
      else
        bpl_print_one (res, &oldlim);
    }
  return EXECUTION_SUCCESS;
}

static int
bpl_show_all (pid_t pid, int json, int raw)
{
  int rc = EXECUTION_SUCCESS;
  int first = 1;
  if (json)
    printf ("{\"pid\":%ld,\"limits\":[", (long) pid);
  for (const bpl_res *r = bpl_resources; r->name; r++)
    {
      struct rlimit oldlim;
      if (bpl_prlimit (pid, r->resource, NULL, &oldlim) < 0)
        {
          builtin_error ("pid %ld %s: %s", (long) pid, r->name, strerror (errno));
          rc = EXECUTION_FAILURE;
          continue;
        }
      if (json)
        {
          if (!first)
            putchar (',');
          first = 0;
          bpl_print_json_one (pid, r, &oldlim);
        }
      else
        {
          if (raw)
            bpl_print_raw_one (r, &oldlim);
          else
            bpl_print_one (r, &oldlim);
        }
    }
  if (json)
    puts ("]}");
  return rc;
}

static int
bpl_set_one (pid_t pid, const bpl_res *res, const char *spec, int json,
             int raw)
{
  struct rlimit newlim, oldlim;
  int found;
  if (bpl_parse_limit_pair (spec, &newlim, &found) < 0)
    {
      builtin_error ("invalid limit: %s", spec);
      return EX_USAGE;
    }
  if (bpl_fill_unspecified (pid, res, &newlim, found) < 0)
    return EXECUTION_FAILURE;
  if (bpl_check_soft_le_hard (res, &newlim) < 0)
    return EXECUTION_FAILURE;
  if (bpl_prlimit (pid, res->resource, &newlim, &oldlim) < 0)
    {
      builtin_error ("set pid %ld %s: %s", (long) pid, res->name,
                     strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (json)
    {
      bpl_print_json_one (pid, res, &newlim);
      putchar ('\n');
    }
  else
    {
      if (raw)
        bpl_print_raw_one (res, &newlim);
      else
        bpl_print_one (res, &newlim);
    }
  return EXECUTION_SUCCESS;
}

static char **
bpl_words_to_argv (WORD_LIST *cmd)
{
  WORD_LIST *p;
  char **argv;
  int argc = 0;
  int i = 0;

  for (p = cmd; p; p = p->next)
    argc++;
  if (argc == 0)
    return NULL;
  argv = (char **) malloc ((argc + 1) * sizeof *argv);
  if (argv == NULL)
    return NULL;
  for (p = cmd; p; p = p->next)
    argv[i++] = p->word->word;
  argv[i] = NULL;
  return argv;
}

static int
bpl_spawn (const bpl_res *res, const char *spec, WORD_LIST *cmd)
{
  struct rlimit newlim;
  char **argv;
  pid_t child;
  int status;
  int found;

  if (bpl_parse_limit_pair (spec, &newlim, &found) < 0)
    {
      builtin_error ("invalid limit: %s", spec);
      return EX_USAGE;
    }
  /* An omitted side is taken from the calling process's current limit,
   * which the child inherits — matching prlimit(1) COMMAND mode. */
  if (bpl_fill_unspecified (0, res, &newlim, found) < 0)
    return EXECUTION_FAILURE;
  if (bpl_check_soft_le_hard (res, &newlim) < 0)
    return EXECUTION_FAILURE;
  argv = bpl_words_to_argv (cmd);
  if (argv == NULL)
    {
      builtin_error ("missing command");
      return EX_USAGE;
    }

  child = fork ();
  if (child < 0)
    {
      builtin_error ("fork: %s", strerror (errno));
      free (argv);
      return EXECUTION_FAILURE;
    }
  if (child == 0)
    {
      if (bpl_prlimit (0, res->resource, &newlim, NULL) < 0)
        {
          builtin_error ("set %s: %s", res->name, strerror (errno));
          _exit (126);
        }
      execvp (argv[0], argv);
      builtin_error ("%s: %s", argv[0], strerror (errno));
      _exit (errno == ENOENT ? 127 : 126);
    }

  free (argv);
  while (waitpid (child, &status, 0) < 0)
    {
      if (errno == EINTR)
        continue;
      builtin_error ("waitpid: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (WIFEXITED (status))
    return WEXITSTATUS (status);
  if (WIFSIGNALED (status))
    return 128 + WTERMSIG (status);
  return EXECUTION_FAILURE;
}

static int
bpl_help (void)
{
  puts ("prlimit — prlimit(8) subset over prlimit(2)");
  puts ("usage: prlimit [-r RES]            (no --pid: the calling process)");
  puts ("       prlimit --pid PID");
  puts ("       prlimit --pid PID -r RES");
  puts ("       prlimit --pid PID -r RES SOFT[:HARD]");
  puts ("       prlimit --pid PID --nofile[=SOFT[:HARD]]");
  puts ("       prlimit --json --pid PID [-r RES]");
  puts ("       prlimit --raw --noheadings --pid PID [-r RES]");
  puts ("       prlimit --nofile=SOFT[:HARD] COMMAND [ARG...]");
  puts ("       prlimit --help | --version");
  puts ("RES names: AS CORE CPU DATA FSIZE LOCKS MEMLOCK MSGQUEUE NICE");
  puts ("           NOFILE NPROC RSS RTPRIO RTTIME SIGPENDING STACK");
  puts ("Aliases: --as --core --cpu --data --fsize --locks --memlock");
  puts ("         --msgqueue --nice --nofile --nproc --rss --rtprio");
  puts ("         --rttime --sigpending --stack; short aliases except -r");
  puts ("Ranges: SOFT, SOFT:HARD, SOFT: (keep hard), :HARD (keep soft), unlimited.");
  puts ("Output: default text lines, --raw tab-delimited lines, or --json objects.");
  return EXECUTION_SUCCESS;
}

int
prlimit_builtin (WORD_LIST *list)
{
  pid_t pid = -1;
  const char *res_name = NULL;
  const char *set_spec = NULL;
  WORD_LIST *command = NULL;
  int json = 0;
  int raw = 0;
  const bpl_res *res;

  /* No args is not an error: prlimit(1) prints every limit of the
   * calling process. The pid<0 default below routes there. */

  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "--help") == 0 || strcmp (w, "-h") == 0)
        return bpl_help ();
      if (strcmp (w, "--version") == 0)
        { puts ("prlimit 0.5"); return EXECUTION_SUCCESS; }
      if (strcmp (w, "--json") == 0)
        { json = 1; continue; }
      if (strcmp (w, "--raw") == 0)
        { raw = 1; continue; }
      if (strcmp (w, "--noheadings") == 0)
        continue;
      if (strcmp (w, "--") == 0)
        {
          command = p->next;
          break;
        }
      if ((strcmp (w, "--pid") == 0 || strcmp (w, "-p") == 0) && p->next)
        {
          p = p->next;
          if (bpl_parse_pid (p->word->word, &pid) < 0)
            { builtin_error ("invalid pid: %s", p->word->word); return EX_USAGE; }
        }
      else if (strncmp (w, "--pid=", 6) == 0)
        {
          if (bpl_parse_pid (w + 6, &pid) < 0)
            { builtin_error ("invalid pid: %s", w + 6); return EX_USAGE; }
        }
      else if ((strcmp (w, "-r") == 0 || strcmp (w, "--resource") == 0) && p->next)
        {
          p = p->next;
          res_name = p->word->word;
        }
      else if (strncmp (w, "--resource=", 11) == 0)
        res_name = w + 11;
      else if (strncmp (w, "--", 2) == 0)
        {
          const char *name = w + 2;
          const char *eq = strchr (name, '=');
          const bpl_alias *a = bpl_find_long_alias (name, eq ? (size_t)(eq - name) : strlen (name));
          if (!a)
            { builtin_error ("unknown option: %s", w); return EX_USAGE; }
          if (bpl_select_resource (&res_name, &set_spec, a->resource_name,
                                   eq ? eq + 1 : NULL) != EXECUTION_SUCCESS)
            return EX_USAGE;
        }
      else if (w[0] == '-' && w[1] != '\0' && w[2] == '\0')
        {
          const bpl_alias *a = bpl_find_short_alias (w[1]);
          if (!a)
            { builtin_error ("unknown option: %s", w); return EX_USAGE; }
          if (bpl_select_resource (&res_name, &set_spec, a->resource_name,
                                   NULL) != EXECUTION_SUCCESS)
            return EX_USAGE;
        }
      else if (!set_spec)
        set_spec = w;
      else if (!command)
        {
          command = p;
          break;
        }
      else
        { builtin_error ("unexpected argument: %s", w); return EX_USAGE; }
    }

  if (command && pid > 0)
    { builtin_error ("--pid cannot be combined with command mode"); return EX_USAGE; }
  if (json && raw)
    { builtin_error ("choose only one output mode"); return EX_USAGE; }
  if (command && (json || raw))
    { builtin_error ("output modes require a target pid"); return EX_USAGE; }
  /* Without --pid (and without a command) operate on the calling
   * process, matching prlimit(1). Using getpid() rather than 0 keeps
   * --json's pid field meaningful; prlimit(2) treats them alike. */
  if (!command && pid < 0)
    pid = getpid ();
  if (!res_name)
    {
      if (set_spec)
        { builtin_error ("limit value requires -r RES"); return EX_USAGE; }
      return bpl_show_all (pid, json, raw);
    }
  res = bpl_find_res (res_name);
  if (!res)
    { builtin_error ("unknown resource: %s", res_name); return EX_USAGE; }
  if (command)
    {
      if (!set_spec)
        { builtin_error ("command mode requires a limit value"); return EX_USAGE; }
      return bpl_spawn (res, set_spec, command);
    }
  if (set_spec)
    return bpl_set_one (pid, res, set_spec, json, raw);
  return bpl_show_one (pid, res, json, raw);
}

char *prlimit_doc[] = {
  "prlimit(8) subset over prlimit(2).",
  "",
  "    prlimit [-r RES]            (no --pid: the calling process)",
  "    prlimit --pid PID",
  "    prlimit --pid PID -r RES",
  "    prlimit --pid PID -r RES SOFT[:HARD]",
  "    prlimit --pid PID --nofile[=SOFT[:HARD]]",
  "    prlimit --json --pid PID [-r RES]",
  "    prlimit --raw --noheadings --pid PID [-r RES]",
  "    prlimit --nofile=SOFT[:HARD] COMMAND [ARG...]",
  "    prlimit --help | --version",
  "",
  "RES names: AS CORE CPU DATA FSIZE LOCKS MEMLOCK MSGQUEUE NICE",
  "           NOFILE NPROC RSS RTPRIO RTTIME SIGPENDING STACK",
  "Aliases: --as --core --cpu --data --fsize --locks --memlock",
  "         --msgqueue --nice --nofile --nproc --rss --rtprio",
  "         --rttime --sigpending --stack; short aliases except -r",
  "Ranges: SOFT, SOFT:HARD, SOFT: (keep hard), :HARD (keep soft), unlimited.",
  "Output: default text lines, --raw tab-delimited lines, or --json objects.",
  (char *)0
};

struct builtin prlimit_struct = {
  "prlimit",
  prlimit_builtin,
  BUILTIN_ENABLED,
  prlimit_doc,
  "prlimit --pid PID [-r RES [SOFT[:HARD]]] | --nofile=LIMIT COMMAND",
  0
};
