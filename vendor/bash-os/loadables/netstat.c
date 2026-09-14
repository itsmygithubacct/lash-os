/* SPDX-License-Identifier: MIT */
/* bashnetstat.c — netstat(8) surface (legacy column headers) on top of
 *                  bashss's sock_diag + /proc/net machinery.
 *
 * Sibling of bashss.c.  Provides the legacy netstat column layout
 * (Proto / Recv-Q / Send-Q / Local / Foreign / State / PID-Program).
 * Reuses the bss_opts + bss_run helpers exported from bashss.c so
 * the transport and pid-map logic stay in one place.
 *
 *   bashnetstat [-t] [-u] [-x] [-l] [-a] [-n] [-p] [-h | --help] [--version]
 *
 * Verb semantics match bashss with one delta: legacy_columns=1, so the
 * header line uses "Proto / Recv-Q / Send-Q / Local Address / Foreign
 * Address / State" rather than the ss-style "Netid / State / Recv-Q ..."
 * ordering.
 *
 * Source counterpart: research/refs/busybox/networking/netstat.c.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loadables.h"

struct bss_opts
{
  int show_tcp;
  int show_udp;
  int show_unix;
  int listen_only;
  int all_states;
  int show_pid;
  int numeric;
  int legacy_columns;
};

extern int bss_run (struct bss_opts *o);

int
netstat_builtin (WORD_LIST *list)
{
  struct bss_opts o;
  memset (&o, 0, sizeof o);
  o.numeric = 1;
  o.legacy_columns = 1;

  int explicit_family = 0;
  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-h") == 0 || strcmp (w, "--help") == 0)
        { builtin_usage (); return EXECUTION_SUCCESS; }
      if (strcmp (w, "--version") == 0)
        {
          printf ("bashnetstat — netstat(8) surface "
                  "(legacy headers over bashss)\n");
          return EXECUTION_SUCCESS;
        }
      /* net-tools long-option aliases, so `bashnetstat --tcp --listening`
       * works like the real netstat(8) instead of being mis-parsed as a
       * cluster of short flags. Spellings match net-tools exactly. */
      if (strcmp (w, "--tcp") == 0)       { o.show_tcp = 1;  explicit_family = 1; continue; }
      if (strcmp (w, "--udp") == 0)       { o.show_udp = 1;  explicit_family = 1; continue; }
      if (strcmp (w, "--unix") == 0)      { o.show_unix = 1; explicit_family = 1; continue; }
      if (strcmp (w, "--listening") == 0) { o.listen_only = 1; continue; }
      if (strcmp (w, "--all") == 0)       { o.all_states = 1;  continue; }
      if (strcmp (w, "--numeric") == 0)   { o.numeric = 1;     continue; }
      if (strcmp (w, "--programs") == 0)  { o.show_pid = 1;    continue; }
      if (w[0] != '-' || w[1] == 0)
        {
          builtin_error ("unknown argument: %s", w);
          builtin_usage ();
          return EX_USAGE;
        }
      /* Any unmatched long option ('--foo') would otherwise fall into the
         short-flag cluster loop below, where the leading '-' of the '--'
         hits the default case and prints a useless 'unknown flag: --' that
         drops the actual token. Route long-option misses to a real error
         that names what the user typed. */
      if (w[1] == '-')
        {
          builtin_error ("unknown option: %s", w);
          builtin_usage ();
          return EX_USAGE;
        }
      for (const char *c = w + 1; *c; c++)
        {
          switch (*c)
            {
            case 't': o.show_tcp = 1; explicit_family = 1; break;
            case 'u': o.show_udp = 1; explicit_family = 1; break;
            case 'x': o.show_unix = 1; explicit_family = 1; break;
            case 'l': o.listen_only = 1; break;
            case 'a': o.all_states = 1; break;
            case 'n': o.numeric = 1; break;
            case 'p': o.show_pid = 1; break;
            default:
              builtin_error ("unknown flag: -%c", *c);
              builtin_usage ();
              return EX_USAGE;
            }
        }
    }

  /* netstat with no -t/-u/-x defaults to showing TCP + UDP + unix,
   * matching the GNU netstat behaviour the busybox port mimics. */
  if (!explicit_family)
    {
      o.show_tcp = 1;
      o.show_udp = 1;
      o.show_unix = 1;
    }
  if (!o.listen_only && !o.all_states)
    o.all_states = 1;

  return bss_run (&o) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

char *netstat_doc[] = {
  "netstat(8) surface (legacy column headers) over bashss.",
  "",
  "    bashnetstat [-t] [-u] [-x] [-l] [-a] [-n] [-p]",
  "    bashnetstat -h | --help",
  "    bashnetstat --version",
  "",
  "net-tools long aliases are also accepted: --tcp, --udp, --unix,",
  "--listening, --all, --numeric, --programs.",
  "",
  "Identical flag set to bashss; output uses Proto/Recv-Q/Send-Q/Local/",
  "Foreign/State columns. With no family flag, shows TCP + UDP + unix.",
  (char *) NULL
};

struct builtin bashnetstat_struct = {
  "bashnetstat",
  netstat_builtin,
  BUILTIN_ENABLED,
  netstat_doc,
  "bashnetstat [-t|-u|-x] [-l|-a] [-n] [-p]",
  0
};
