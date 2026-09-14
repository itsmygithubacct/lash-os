/* SPDX-License-Identifier: MIT */
/* reboot-impl.h — the shared body of the reboot/halt/poweroff builtins.
 *
 * All three are the same reboot(2) wrapper differing only in the RB_* command
 * and their strings, so the logic lives here once and each NAME.c is three
 * lines. Kept as separate .c because the hybrid bash injects one builtin per
 * source file (build/build-bash.sh); the DUPLICATION the injector would
 * otherwise force is removed here instead.
 *
 * MIT-licensed.
 */
#ifndef REBOOT_IMPL_H
#define REBOOT_IMPL_H

#include <config.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/reboot.h>
#include "loadables.h"
#include "bashgetopt.h"

/* One reboot(2) call. `-f` skips the sync, `-n` is a dry run (report only). */
static int
reboot_impl (WORD_LIST *list, int cmd, const char *name)
{
  int opt, force = 0, dry = 0;
  reset_internal_getopt ();
  while ((opt = internal_getopt (list, "fn")) != -1)
    {
      switch (opt)
	{
	case 'f': force = 1; break;	/* skip the sync */
	case 'n': dry = 1; break;	/* dry run: report, do not act */
	default: builtin_usage (); return (EX_USAGE);
	}
    }
  if (dry)
    { printf ("%s: would %s (dry run)\n", name, name); return (EXECUTION_SUCCESS); }
  if (force == 0)
    sync ();
  reboot (cmd);
  builtin_error ("%s: %s", name, strerror (errno));	/* only reached on failure */
  return (EXECUTION_FAILURE);
}

/* Emit NAME_builtin / NAME_doc / NAME_struct for one command. */
#define REBOOT_BUILTIN(fn, cmd, verb)					\
  int fn##_builtin (WORD_LIST *list) { return reboot_impl (list, cmd, #fn); } \
  char *fn##_doc[] = {							\
    verb " the system.", "",						\
    #fn " [-f] [-n]   -f: skip sync;  -n: dry run (report, do not act).",\
    (char *) NULL };							\
  struct builtin fn##_struct = {					\
    #fn, fn##_builtin, BUILTIN_ENABLED, fn##_doc, #fn " [-f] [-n]", 0 };

#endif /* REBOOT_IMPL_H */
