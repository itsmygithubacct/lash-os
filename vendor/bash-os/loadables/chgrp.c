/* SPDX-License-Identifier: MIT */
/* chgrp.c — change file group via chown(2)/lchown(2). bash-os loadable (MIT).
 * Replaces busybox chgrp (plan D22).  chgrp [-h] GROUP FILE... */
#include <config.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <grp.h>
#include "loadables.h"
#include "bashgetopt.h"

int
chgrp_builtin (WORD_LIST *list)
{
  int opt, deref = 1, rc = EXECUTION_SUCCESS;
  gid_t gid; char *end; struct group *gr;
  WORD_LIST *l;

  reset_internal_getopt ();
  while ((opt = internal_getopt (list, "h")) != -1)
    {
      if (opt == 'h') deref = 0;
      else { builtin_usage (); return (EX_USAGE); }
    }
  list = loptend;
  if (list == 0 || list->next == 0)
    { builtin_usage (); return (EX_USAGE); }

  gr = getgrnam (list->word->word);
  if (gr)
    gid = gr->gr_gid;
  else
    {
      long v = strtol (list->word->word, &end, 10);
      if (*end) { builtin_error ("invalid group: %s", list->word->word); return (EXECUTION_FAILURE); }
      gid = (gid_t) v;
    }

  for (l = list->next; l; l = l->next)
    {
      int r = deref ? chown (l->word->word, (uid_t) -1, gid)
		    : lchown (l->word->word, (uid_t) -1, gid);
      if (r < 0)
	{ builtin_error ("%s: %s", l->word->word, strerror (errno)); rc = EXECUTION_FAILURE; }
    }
  return (rc);
}

char *chgrp_doc[] = {
  "Change file group.",
  "",
  "chgrp [-h] GROUP FILE...   GROUP is a name or numeric id.",
  (char *) NULL
};

struct builtin chgrp_struct = {
  "chgrp", chgrp_builtin, BUILTIN_ENABLED, chgrp_doc, "chgrp [-h] GROUP FILE...", 0
};
