/* SPDX-License-Identifier: MIT */
/* opt.c — POSIX / GNU-enhanced getopt(1) parser as a bash loadable.
 *
 * Doc 82 / Round 1778961001 / ML-T2-08 spec calls this loadable
 * "bashgetopt"; the source-tree name collides with bash's own internal
 * builtins/bashgetopt.c (which defines internal_getopt() and is
 * referenced by every other builtin). patch-bash-loadables.sh stages
 * scripts/loadables/${name}.c into builtins/${name}.c, so a name of
 * "bashgetopt" would clobber bash's source tree and break the build.
 * Renamed to `opt` and documented here + in the loadables list +
 * in the tracker entry. The user-visible PATH command stays `getopt`
 * via /bash-os/getopt.sh.
 *
 * Surface (subset of util-linux getopt(1)):
 *
 *     opt OPTSTRING ARG...                          compat mode
 *     opt [OPTIONS] [--] OPTSTRING ARG...           enhanced mode
 *     opt [OPTIONS] -o|--options OPTSTRING [OPTIONS] [--] ARG...
 *
 * Self options:
 *     -a, --alternative           getopt_long_only (long options with single -)
 *     -l, --longoptions LONGS     comma-separated long-option spec
 *     -n, --name NAME             progname used by getopt(3) error diagnostics
 *     -o, --options OPTSTRING     short-option string
 *     -q, --quiet                 suppress getopt(3) error reporting
 *     -Q, --quiet-output          suppress normal output
 *     -s, --shell SHELL           output quoting style: bash|sh|tcsh|csh
 *     -T, --test                  exit 4 (enhanced-getopt sentinel)
 *     -u, --unquoted              do not quote output
 *     -U, --unknown               leave unknown options as-is (implies -q)
 *     -h, --help                  show usage
 *     -V, --version               show version
 *
 * LONGS: comma-separated, each optionally followed by ':' (required
 * argument) or '::' (optional argument).
 *
 * Output: each parsed option is emitted preceded by a single space.
 * The token stream is terminated by ' --' and the non-option arguments,
 * then a newline. Default quoting is bash single-quote form (each ' is
 * replaced with '\''); tcsh form additionally escapes \, !, and
 * whitespace.
 *
 * Exit codes (match util-linux getopt(1)):
 *     0   parse OK
 *     1   getopt(3) returned an error (unknown / missing-arg)
 *     2   parameter parsing error
 *     4   -T / --test sentinel
 *
 * Source counterpart: research/refs/util-linux/misc-utils/getopt.c.
 *
 * Companion wrapper: /bash-os/getopt.sh.
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
#include <ctype.h>

#include "loadables.h"

/* Bash's builtins/ ships a stripped getopt.h (declares sh_optarg /
   sh_optind for bash core) that the -I order in the patched build
   shadows the system <getopt.h> with. We need libc's getopt_long
   surface here; declare the minimum subset directly. ABI is stable on
   both glibc and musl (POSIX-derived struct option layout). */
struct option {
  const char *name;
  int         has_arg;
  int        *flag;
  int         val;
};
#ifndef no_argument
#  define no_argument        0
#  define required_argument  1
#  define optional_argument  2
#endif
extern char *optarg;
extern int   optind;
extern int   opterr;
extern int   optopt;
extern int   getopt_long      (int, char *const *, const char *,
                               const struct option *, int *);
extern int   getopt_long_only (int, char *const *, const char *,
                               const struct option *, int *);

#define BG_PARAM_ERR    2   /* parameter parse error */
#define BG_GETOPT_ERR   1   /* getopt(3) signalled an error */
#define BG_TEST_RC      4   /* -T enhanced-getopt sentinel */
#define BG_LONGCAP      256 /* max long options we will register */

extern char *opt_doc[];

struct bg_ctl {
  const char *progname;
  char         *optstr;
  struct option longopts[BG_LONGCAP];
  int           nlong;
  int           alternative;
  int           quote;
  int           quiet_errors;
  int           quiet_output;
  int           ignore_unknown;
  int           shell_tcsh;
};

static void
bg_init (struct bg_ctl *c)
{
  memset (c, 0, sizeof *c);
  c->progname = "getopt";
  c->quote = 1;
}

static void
bg_free (struct bg_ctl *c)
{
  free (c->optstr);
  c->optstr = NULL;
  for (int i = 0; i < c->nlong; i++)
    free ((char *) c->longopts[i].name);
  c->nlong = 0;
}

/* Emit ARG to stdout in the configured quoting style, preceded by a
   single space (matches util-linux getopt). */
static void
bg_emit_normalized (const struct bg_ctl *c, const char *arg)
{
  if (!c->quote)
    {
      putchar (' ');
      fputs (arg, stdout);
      return;
    }
  putchar (' ');
  putchar ('\'');
  for (const char *p = arg; *p; p++)
    {
      unsigned char ch = (unsigned char) *p;
      if (ch == '\'')
        {
          fputs ("'\\''", stdout);
          continue;
        }
      if (c->shell_tcsh)
        {
          if (ch == '\\')        { fputs ("\\\\", stdout); continue; }
          if (ch == '!')         { fputs ("'\\!'", stdout); continue; }
          if (ch == '\n')        { fputs ("\\n", stdout); continue; }
          if (isspace (ch))      { fputs ("'\\", stdout); putchar (ch); putchar ('\''); continue; }
        }
      putchar (ch);
    }
  putchar ('\'');
}

static int
bg_add_longopt (struct bg_ctl *c, const char *name, int has_arg)
{
  if (c->nlong >= BG_LONGCAP - 1)
    {
      builtin_error ("%s: too many long options (>%d)", c->progname, BG_LONGCAP - 1);
      return -1;
    }
  c->longopts[c->nlong].name    = strdup (name);
  if (!c->longopts[c->nlong].name)
    {
      builtin_error ("%s: out of memory", c->progname);
      return -1;
    }
  c->longopts[c->nlong].has_arg = has_arg;
  c->longopts[c->nlong].flag    = NULL;
  c->longopts[c->nlong].val     = 0;
  c->nlong++;
  return 0;
}

/* Parse a comma/whitespace-separated longopts SPEC. SPEC is mutated by
   strtok_r; caller passes a heap-owned dup. */
static int
bg_parse_longspec (struct bg_ctl *c, char *spec)
{
  char *save = NULL;
  for (char *tok = strtok_r (spec, ", \t\n", &save);
       tok != NULL;
       tok = strtok_r (NULL, ", \t\n", &save))
    {
      size_t L = strlen (tok);
      int has = no_argument;
      if (L >= 2 && tok[L - 1] == ':' && tok[L - 2] == ':')
        { has = optional_argument; tok[L - 2] = '\0'; }
      else if (L >= 1 && tok[L - 1] == ':')
        { has = required_argument; tok[L - 1] = '\0'; }
      if (*tok == '\0')
        {
          builtin_error ("%s: empty long option after -l", c->progname);
          return -1;
        }
      if (bg_add_longopt (c, tok, has) < 0)
        return -1;
    }
  return 0;
}

static int
bg_install_optstr (struct bg_ctl *c, const char *s)
{
  free (c->optstr);
  size_t L = strlen (s);
  int posixly = (getenv ("POSIXLY_CORRECT") != NULL);
  int prepend = posixly && *s != '+' && *s != '-';
  c->optstr = malloc (L + (prepend ? 2 : 1));
  if (!c->optstr)
    {
      builtin_error ("%s: out of memory", c->progname);
      return -1;
    }
  if (prepend)
    {
      c->optstr[0] = '+';
      memcpy (c->optstr + 1, s, L + 1);
    }
  else
    memcpy (c->optstr, s, L + 1);
  return 0;
}

static int
bg_set_shell (struct bg_ctl *c, const char *s)
{
  if (!strcmp (s, "bash") || !strcmp (s, "sh"))   { c->shell_tcsh = 0; return 0; }
  if (!strcmp (s, "tcsh") || !strcmp (s, "csh"))  { c->shell_tcsh = 1; return 0; }
  builtin_error ("%s: unknown shell after -s argument: %s", c->progname, s);
  return -1;
}

static int
bg_find_long_prefix (const struct bg_ctl *c, const char *name, size_t len)
{
  int found = -1;

  for (int i = 0; i < c->nlong; i++)
    {
      if (strncmp (c->longopts[i].name, name, len) != 0)
        continue;
      if (c->longopts[i].name[len] == '\0')
        return i;
      if (found >= 0)
        return -2;
      found = i;
    }

  return found;
}

static int
bg_emit_w_long (struct bg_ctl *c, int argc, char **argv)
{
  char *eq;
  const char *arg;
  const char *value = NULL;
  size_t name_len;
  int idx;

  if (!optarg || *optarg == '\0')
    return BG_GETOPT_ERR;

  arg = optarg;
  eq = strchr (optarg, '=');
  name_len = eq ? (size_t) (eq - optarg) : strlen (optarg);
  idx = bg_find_long_prefix (c, arg, name_len);
  if (idx < 0)
    return BG_GETOPT_ERR;

  if (eq)
    value = eq + 1;
  else if (c->longopts[idx].has_arg == required_argument)
    {
      if (optind >= argc)
        return BG_GETOPT_ERR;
      value = argv[optind++];
    }

  if (!c->quiet_output)
    {
      printf (" --%s", c->longopts[idx].name);
      if (c->longopts[idx].has_arg)
        bg_emit_normalized (c, value ? value : "");
    }
  return EXECUTION_SUCCESS;
}

/* Run getopt_long over the user's argv and emit the normalized token
   stream to stdout. Returns the loadable's exit code. */
static int
bg_generate (struct bg_ctl *c, int argc, char **argv)
{
  int exit_code = EXECUTION_SUCCESS;
  int longidx   = -1;
  int opt;
  int parse_argc = argc;
  char **parse_argv = argv;
  char **owned = NULL;
  int (*go_fn) (int, char *const *, const char *,
                const struct option *, int *) =
      c->alternative ? getopt_long_only : getopt_long;

  if (strstr (c->optstr, "W;") != NULL)
    {
      int j = 0;
      owned = calloc ((size_t) argc + 1, sizeof *owned);
      parse_argv = calloc ((size_t) argc + 1, sizeof *parse_argv);
      if (!owned || !parse_argv)
        {
          free (owned);
          free (parse_argv);
          builtin_error ("%s: out of memory", c->progname);
          return EXECUTION_FAILURE;
        }

      for (int i = 0; i < argc; i++)
        {
          if (i > 0 && !strcmp (argv[i], "-W") && i + 1 < argc)
            {
              size_t L = strlen (argv[i + 1]);
              owned[j] = malloc (L + 3);
              if (!owned[j])
                {
                  builtin_error ("%s: out of memory", c->progname);
                  for (int k = 0; k < j; k++) free (owned[k]);
                  free (owned);
                  free (parse_argv);
                  return EXECUTION_FAILURE;
                }
              owned[j][0] = '-';
              owned[j][1] = '-';
              memcpy (owned[j] + 2, argv[i + 1], L + 1);
              parse_argv[j] = owned[j];
              j++;
              i++;
              continue;
            }
          if (i > 0 && argv[i][0] == '-' && argv[i][1] == 'W' && argv[i][2] != '\0')
            {
              size_t L = strlen (argv[i] + 2);
              owned[j] = malloc (L + 3);
              if (!owned[j])
                {
                  builtin_error ("%s: out of memory", c->progname);
                  for (int k = 0; k < j; k++) free (owned[k]);
                  free (owned);
                  free (parse_argv);
                  return EXECUTION_FAILURE;
                }
              owned[j][0] = '-';
              owned[j][1] = '-';
              memcpy (owned[j] + 2, argv[i] + 2, L + 1);
              parse_argv[j] = owned[j];
              j++;
              continue;
            }
          parse_argv[j++] = argv[i];
        }
      parse_argv[j] = NULL;
      parse_argc = j;
    }

  /* Reset libc getopt state. optind=0 triggers the GNU/musl re-init
     path so any state left over by an earlier call (e.g. our own
     self-parse) is dropped. */
  optind = 0;
  opterr = (c->quiet_errors || c->ignore_unknown) ? 0 : 1;

  while ((opt = go_fn (parse_argc, parse_argv, c->optstr, c->longopts, &longidx)) != -1)
    {
      if (c->ignore_unknown && opt == '?')
        {
          if (optind > 0 && optind <= parse_argc)
            bg_emit_normalized (c, parse_argv[optind - 1]);
          continue;
        }
      if (opt == '?' || opt == ':')
        {
          exit_code = BG_GETOPT_ERR;
          continue;
        }
      if (c->quiet_output)
        continue;
      if (opt == 1)
        {
          /* GNU getopt returns 1 for a non-option operand when the
             optstring starts with '-'. util-linux getopt emits those
             operands inline instead of moving them behind the final --. */
          bg_emit_normalized (c, optarg ? optarg : parse_argv[optind - 1]);
          continue;
        }
      if (opt == 0)
        {
          /* Long option matched (flag=NULL, val=0). */
          printf (" --%s", c->longopts[longidx].name);
          if (c->longopts[longidx].has_arg)
            bg_emit_normalized (c, optarg ? optarg : "");
        }
      else
        {
          const char *p = strchr (c->optstr, opt);
          if (opt == 'W' && p && p[1] == ';')
            {
              if (bg_emit_w_long (c, parse_argc, parse_argv) != EXECUTION_SUCCESS)
                exit_code = BG_GETOPT_ERR;
              continue;
            }
          int has = (p && p[1] == ':');
          printf (" -%c", opt);
          if (has)
            bg_emit_normalized (c, optarg ? optarg : "");
        }
    }

  if (!c->quiet_output)
    {
      fputs (" --", stdout);
      for (int i = optind; i < parse_argc; i++)
        bg_emit_normalized (c, parse_argv[i]);
      putchar ('\n');
    }
  fflush (stdout);
  if (owned)
    {
      for (int i = 0; i < parse_argc; i++)
        free (owned[i]);
      free (owned);
      free (parse_argv);
    }
  return exit_code;
}

int
opt_builtin (WORD_LIST *list)
{
  struct bg_ctl c;
  bg_init (&c);

  if (!list)
    {
      builtin_error ("%s: missing optstring argument", c.progname);
      return BG_PARAM_ERR;
    }

  /* Build a synthetic argv from the WORD_LIST so we can hand it to
     libc getopt_long. argv[0] is the progname slot — used by getopt
     for its own error prefixes; we overwrite it again below once -n
     has been seen. */
  int n = 0;
  for (WORD_LIST *p = list; p; p = p->next) n++;
  char **argv = calloc ((size_t) n + 2, sizeof *argv);
  if (!argv)
    {
      builtin_error ("%s: out of memory", c.progname);
      return EXECUTION_FAILURE;
    }
  argv[0] = (char *) c.progname;
  int idx = 1;
  for (WORD_LIST *p = list; p; p = p->next)
    argv[idx++] = p->word->word;
  int argc = idx;
  argv[argc] = NULL;

  /* Compat mode: GETOPT_COMPATIBLE or first arg doesn't start with -. */
  int compat = (getenv ("GETOPT_COMPATIBLE") != NULL) || (argv[1][0] != '-');
  if (compat)
    {
      c.quote = 0;
      const char *src = argv[1];
      src += strspn (src, "-+");
      if (bg_install_optstr (&c, src) < 0) goto err;
      /* The remaining args are argv[2..argc-1]; libc getopt_long needs
         an argv whose [0] is the progname. Re-use slot 1 by overwriting
         it with the progname. */
      argv[1] = (char *) c.progname;
      int rc = bg_generate (&c, argc - 1, argv + 1);
      free (argv);
      bg_free (&c);
      return rc;
    }

  /* Self-parse using libc getopt_long. Leading '+' in the optstring
     means "stop at first non-option", so the input args are left in
     argv[optind..]. */
  static const char self_short[] = "+o:l:n:s:qQuUaThV";
  static const struct option self_long[] = {
    {"options",       required_argument, NULL, 'o'},
    {"longoptions",   required_argument, NULL, 'l'},
    {"long",          required_argument, NULL, 'l'},
    {"name",          required_argument, NULL, 'n'},
    {"shell",         required_argument, NULL, 's'},
    {"quiet",         no_argument,       NULL, 'q'},
    {"quiet-output",  no_argument,       NULL, 'Q'},
    {"unquoted",      no_argument,       NULL, 'u'},
    {"unknown",       no_argument,       NULL, 'U'},
    {"alternative",   no_argument,       NULL, 'a'},
    {"test",          no_argument,       NULL, 'T'},
    {"help",          no_argument,       NULL, 'h'},
    {"version",       no_argument,       NULL, 'V'},
    {NULL,            0,                 NULL, 0  }
  };

  optind = 0;
  opterr = 1;
  int opt;
  while ((opt = getopt_long (argc, argv, self_short, self_long, NULL)) != -1)
    {
      switch (opt)
        {
        case 'o':
          if (bg_install_optstr (&c, optarg) < 0) goto err;
          break;
        case 'l':
          {
            char *dup = strdup (optarg);
            if (!dup) { builtin_error ("%s: out of memory", c.progname); goto err; }
            int r = bg_parse_longspec (&c, dup);
            free (dup);
            if (r < 0) goto err;
            break;
          }
        case 'n':
          c.progname = optarg;
          break;
        case 's':
          if (bg_set_shell (&c, optarg) < 0) goto err;
          break;
        case 'q':
          c.quiet_errors = 1;
          break;
        case 'Q':
          c.quiet_output = 1;
          break;
        case 'u':
          c.quote = 0;
          break;
        case 'U':
          c.ignore_unknown = 1;
          c.quiet_errors   = 1;
          break;
        case 'a':
          c.alternative = 1;
          break;
        case 'T':
          free (argv);
          bg_free (&c);
          return BG_TEST_RC;
        case 'h':
          for (int i = 0; opt_doc[i]; i++)
            printf ("%s\n", opt_doc[i]);
          free (argv);
          bg_free (&c);
          return EXECUTION_SUCCESS;
        case 'V':
          printf ("opt from bash-os 1.0\n");
          free (argv);
          bg_free (&c);
          return EXECUTION_SUCCESS;
        case '?':
        case ':':
        default:
          /* libc has already emitted its own diagnostic when opterr=1. */
          goto err;
        }
    }

  /* If -o was not provided, the next positional word is the optstring. */
  if (!c.optstr)
    {
      if (optind >= argc)
        {
          builtin_error ("%s: missing optstring argument", c.progname);
          goto err;
        }
      if (bg_install_optstr (&c, argv[optind]) < 0) goto err;
      optind++;
    }

  /* The input args are argv[optind..argc-1]. getopt(3) wants argv[0] to
     be the progname. Re-use the slot at optind-1 (which we know exists:
     it held either '--' or the optstring we just consumed). */
  argv[optind - 1] = (char *) c.progname;
  int rc = bg_generate (&c, argc - optind + 1, argv + optind - 1);

  free (argv);
  bg_free (&c);
  return rc;

err:
  free (argv);
  bg_free (&c);
  return BG_PARAM_ERR;
}

char *opt_doc[] = {
  "Parse command options (POSIX/GNU-enhanced getopt(1) subset).",
  "",
  "    opt OPTSTRING ARG...",
  "    opt [OPTIONS] [--] OPTSTRING ARG...",
  "    opt [OPTIONS] -o|--options OPTSTRING [OPTIONS] [--] ARG...",
  "",
  "Options:",
  "    -a, --alternative           accept long opts starting with single -",
  "    -l, --longoptions LONGS     comma-separated long-option list",
  "    -n, --name NAME             use NAME in error diagnostics",
  "    -o, --options OPTSTRING     short-option string",
  "    -q, --quiet                 suppress getopt(3) errors",
  "    -Q, --quiet-output          suppress normal output",
  "    -s, --shell SHELL           bash|sh|tcsh|csh (output quoting)",
  "    -T, --test                  exit 4 (enhanced-getopt sentinel)",
  "    -u, --unquoted              do not quote output",
  "    -U, --unknown               leave unknown options as-is (implies -q)",
  "    -h, --help                  show this help",
  "    -V, --version               show version",
  "",
  "LONGS format: comma-separated; each name may be followed by ':' for a",
  "required argument or '::' for an optional argument.",
  "",
  "Output: each parsed token is emitted preceded by a single space; the",
  "stream is terminated by ' --' and the non-option arguments, then a",
  "newline. Quoting defaults to bash single-quote form (every ' replaced",
  "by '\\''). Exit codes: 0 OK, 1 getopt(3) error, 2 param parse error,",
  "4 -T sentinel.",
  (char *) NULL
};

struct builtin opt_struct = {
  "opt",
  opt_builtin,
  BUILTIN_ENABLED,
  opt_doc,
  "opt [-a] [-l LONGS] [-n NAME] [-o OPTSTRING] [-qQ] [-s SHELL] [-T] [-u] [-U] [-hV] [--] [OPTSTRING] [ARG ...]",
  0
};
