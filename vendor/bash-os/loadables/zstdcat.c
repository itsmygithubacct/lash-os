/* SPDX-License-Identifier: MIT */
/* zstdcat.c — zstdcat(1): decompress zstd files to standard output. The
 * alias of `zstd -dc`; the work is in zstd.c, so this builtin exists only
 * where zstd is compiled in alongside it (as in every bash-os list). */
#include <config.h>
#include "loadables.h"

extern int bashos_zstd_run (WORD_LIST *list, int cat_mode);

int
zstdcat_builtin (WORD_LIST *list)
{
  return bashos_zstd_run (list, 1);
}

char *zstdcat_doc[] = {
  "Decompress zstd files to standard output.",
  "",
  "The same as `zstd -dc FILE...`: each FILE.zst is decompressed to",
  "standard output and left in place. \"-\" reads standard input.",
  "",
  "Exit status: 0, or 1 if any file failed.",
  (char *)NULL
};

struct builtin zstdcat_struct = {
  "zstdcat", zstdcat_builtin, BUILTIN_ENABLED, zstdcat_doc, "zstdcat FILE...", 0
};
