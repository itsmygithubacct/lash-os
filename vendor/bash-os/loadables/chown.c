/* SPDX-License-Identifier: MIT */
/* chown.c — change file owner/group via chown(2)/lchown(2). bash-os loadable
 * (MIT). Replaces busybox chown; mirrors the stock chmod loadable (plan D22).
 *
 *   chown [-h] OWNER[:GROUP] FILE...     chown [-h] :GROUP FILE...
 * OWNER/GROUP may be names or numeric ids. -h acts on symlinks (lchown).
 */
#include <config.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "loadables.h"
#include "bashgetopt.h"

/* Resolve a "owner[:group]" or ":group" spec to uid/gid; -1 means "unchanged". */
static int
parse_owner (char *spec, uid_t *uid, gid_t *gid)
{
  char *colon, *o, *g;
  struct passwd *pw;
  struct group *gr;
  char *end;

  *uid = (uid_t) -1;
  *gid = (gid_t) -1;
  colon = strchr (spec, ':');
  if (colon == 0)
    colon = strchr (spec, '.');		/* legacy owner.group */
  if (colon)
    { *colon = '\0'; o = spec; g = colon + 1; }
  else
    { o = spec; g = 0; }

  if (o && *o)
    {
      pw = getpwnam (o);
      if (pw)
	*uid = pw->pw_uid;
      else
	{
	  long v = strtol (o, &end, 10);
	  if (*end) { builtin_error ("invalid user: %s", o); return -1; }
	  *uid = (uid_t) v;
	}
    }
  if (g && *g)
    {
      gr = getgrnam (g);
      if (gr)
	*gid = gr->gr_gid;
      else
	{
	  long v = strtol (g, &end, 10);
	  if (*end) { builtin_error ("invalid group: %s", g); return -1; }
	  *gid = (gid_t) v;
	}
    }
  return 0;
}

int
chown_builtin (WORD_LIST *list)
{
  int opt, deref = 1, rc = EXECUTION_SUCCESS;
  uid_t uid; gid_t gid;
  WORD_LIST *l;

  reset_internal_getopt ();
  while ((opt = internal_getopt (list, "h")) != -1)
    {
      if (opt == 'h') deref = 0;	/* operate on the link itself */
      else { builtin_usage (); return (EX_USAGE); }
    }
  list = loptend;
  if (list == 0 || list->next == 0)
    { builtin_usage (); return (EX_USAGE); }

  if (parse_owner (list->word->word, &uid, &gid) < 0)
    return (EXECUTION_FAILURE);

  for (l = list->next; l; l = l->next)
    {
      int r = deref ? chown (l->word->word, uid, gid)
		    : lchown (l->word->word, uid, gid);
      if (r < 0)
	{ builtin_error ("%s: %s", l->word->word, strerror (errno)); rc = EXECUTION_FAILURE; }
    }
  return (rc);
}

char *chown_doc[] = {
  "Change file owner and group.",
  "",
  "chown [-h] OWNER[:GROUP] FILE...   OWNER/GROUP are names or numeric ids;",
  "-h changes a symlink itself rather than its target.",
  (char *) NULL
};

struct builtin chown_struct = {
  "chown", chown_builtin, BUILTIN_ENABLED, chown_doc, "chown [-h] OWNER[:GROUP] FILE...", 0
};
