/* SPDX-License-Identifier: MIT */
/* scp.c — scp(1) cmd-shape wrapper around sftp's dispatch.
 *
 * Companion to sftp.c (Round 1778961001 / Doc 17, ML-T4-05). The
 * actual argv parsing + sftp ops live in sftp.c so this file is a
 * thin registration stub: bash's loadables harness expects one .c per
 * builtin name (the patch-bash-loadables.sh loop copies
 * `examples/loadables/<name>.c` into `builtins/`), so registering
 * `scp` in config/bash-loadables-bash-os.list mandates a source
 * file named scp.c. All real work is `extern` from sftp.c.
 *
 * License: MIT — same boilerplate as the rest of scripts/loadables/.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
# include <unistd.h>
#endif

#include "loadables.h"

extern int bashsftp_scp_dispatch (WORD_LIST *list);

int
scp_builtin (WORD_LIST *list)
{
  return bashsftp_scp_dispatch (list);
}

char *scp_doc[] = {
  "scp(1)-shape file copy over the sshd command-stream transport.",
  "",
  "    scp [-r] [-P PORT] [-i KEY] [-l USER] [--openssh] SRC DST",
  "",
  "SRC or DST may be a remote spec of the form [user@]host:/path or",
  "a local filesystem path. Exactly one side must be remote; remote-",
  "to-remote copy is not supported in v1. With -r, recursive copies",
  "are tunnelled as a tar pipe over the channel.",
  (char *) NULL
};

struct builtin scp_struct = {
  "scp",
  scp_builtin,
  BUILTIN_ENABLED,
  scp_doc,
  "scp [-r] [-P PORT] [-i KEY] [-l USER] [--openssh] SRC DST",
  0
};
