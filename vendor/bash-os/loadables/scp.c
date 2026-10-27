/* SPDX-License-Identifier: MIT */
/* scp.c - bounded local regular-file copies and the existing remote dispatch.
 * License: MIT, as with the other bash-os loadables. */

#include <config.h>
#if defined (HAVE_UNISTD_H)
# include <unistd.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "loadables.h"

extern int bashsftp_scp_dispatch (WORD_LIST *list);

/* A colon before any slash denotes the existing remote CLI. A leading
   colon is a local filename; ./ also makes names containing colons local. */
static int
bscp_remote (const char *s)
{
  for (const char *p = s; *p && *p != '/'; p++)
    if (*p == ':')
      return p != s;
  return 0;
}

static int
bscp_copy (const char *src, const char *dst)
{
  struct stat from, to;
  int in = -1, out = -1, rc = EXECUTION_FAILURE;
  char *joined = NULL;
  char buf[16384];
  ssize_t n;

  /* Nonblocking opens let us reject nonregular files before reading/writing. */
  in = open (src, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (in < 0 || fstat (in, &from) < 0)
    { builtin_error ("%s: %s", src, strerror (errno)); goto done; }
  if (!S_ISREG (from.st_mode))
    { builtin_error ("%s: local mode requires a regular file", src); goto done; }

  if (stat (dst, &to) == 0 && S_ISDIR (to.st_mode))
    {
      const char *base = strrchr (src, '/');
      size_t len;
      base = base ? base + 1 : src;
      len = strlen (dst) + strlen (base) + 2;
      joined = malloc (len);
      if (!joined)
        { builtin_error ("out of memory"); goto done; }
      snprintf (joined, len, "%s/%s", dst, base);
      dst = joined;
    }
  if (stat (dst, &to) == 0)
    {
      if (from.st_dev == to.st_dev && from.st_ino == to.st_ino)
        { builtin_error ("%s and %s are the same file", src, dst); goto done; }
      if (!S_ISREG (to.st_mode))
        { builtin_error ("%s: local destination must be a regular file", dst); goto done; }
    }
  else if (errno != ENOENT)
    { builtin_error ("%s: %s", dst, strerror (errno)); goto done; }

  /* Do not truncate until fstat verifies the opened destination as well. */
  out = open (dst, O_WRONLY | O_CREAT | O_NONBLOCK | O_CLOEXEC,
              from.st_mode & 0777);
  if (out < 0 || fstat (out, &to) < 0)
    { builtin_error ("%s: %s", dst, strerror (errno)); goto done; }
  if (from.st_dev == to.st_dev && from.st_ino == to.st_ino)
    { builtin_error ("%s and %s are the same file", src, dst); goto done; }
  if (!S_ISREG (to.st_mode))
    { builtin_error ("%s: local destination must be a regular file", dst); goto done; }
  if (ftruncate (out, 0) < 0)
    { builtin_error ("%s: %s", dst, strerror (errno)); goto done; }

  for (;;)
    {
      n = read (in, buf, sizeof buf);
      if (n < 0 && errno == EINTR)
        continue;
      if (n < 0)
        { builtin_error ("%s: %s", src, strerror (errno)); goto done; }
      if (n == 0)
        break;
      for (ssize_t pos = 0; pos < n;)
        {
          ssize_t written = write (out, buf + pos, (size_t) (n - pos));
          if (written < 0 && errno == EINTR)
            continue;
          if (written <= 0)
            { builtin_error ("%s: %s", dst, strerror (written ? errno : EIO)); goto done; }
          pos += written;
        }
    }
  rc = EXECUTION_SUCCESS;
 done:
  if (out >= 0 && close (out) < 0)
    { builtin_error ("%s: %s", dst, strerror (errno)); rc = EXECUTION_FAILURE; }
  if (in >= 0)
    close (in);
  free (joined);
  return rc;
}

int
scp_builtin (WORD_LIST *list)
{
  WORD_LIST *original = list;
  const char *src = NULL, *dst = NULL;
  int options = 1, recursive = 0, transport_options = 0;

  /* Keep the remote dispatch's private options; local mode has a deliberately
     smaller contract. In particular, remote -p/-l retain their legacy meanings. */
  for (; list; list = list->next)
    {
      const char *arg = list->word->word;
      if (options && !strcmp (arg, "--"))
        { options = 0; continue; }
      if (options && !strcmp (arg, "-r"))
        { recursive = 1; continue; }
      if (options && (!strcmp (arg, "-P") || !strcmp (arg, "-p")
                      || !strcmp (arg, "-i") || !strcmp (arg, "-l")))
        {
          if (!list->next)
            { builtin_error ("%s requires an argument", arg); return EXECUTION_FAILURE; }
          list = list->next;
          transport_options = 1;
          continue;
        }
      if (options && (!strcmp (arg, "--openssh") || !strcmp (arg, "--ssh")
                      || !strcmp (arg, "--native")))
        { transport_options = 1; continue; }
      if (options && arg[0] == '-' && arg[1])
        { builtin_error ("unknown option: %s", arg); return EXECUTION_FAILURE; }
      if (!src)
        src = arg;
      else if (!dst)
        dst = arg;
      else
        { builtin_error ("local/remote mode requires exactly SRC DST"); return EXECUTION_FAILURE; }
    }
  if (!src || !dst)
    { builtin_usage (); return EXECUTION_FAILURE; }
  if (bscp_remote (src) || bscp_remote (dst))
    {
      int rc = bashsftp_scp_dispatch (original);
      return rc == EX_USAGE ? EXECUTION_FAILURE : rc;
    }
  if (recursive || transport_options)
    {
      builtin_error ("local mode supports only [--] SRC DST regular-file copies");
      return EXECUTION_FAILURE;
    }
  return bscp_copy (src, dst);
}

char *scp_doc[] = {
  "Copy a local regular file or use the sshd command-stream transport.",
  "",
  "    scp [--] SRC DST",
  "    scp [-r] [-P PORT] [-i KEY] [-l USER] [--openssh] SRC DST",
  "",
  "Local mode copies exactly one regular file, following file symlinks.",
  "DST may be a regular file or directory. Same-file copies fail without",
  "truncation. New files use source permissions filtered by umask; existing",
  "files keep their permissions. No recursive local copy or -p preservation.",
  "Exit status: 0 on success; 1 for usage or copy errors.",
  "",
  "Remote SRC or DST uses [user@]host:/path and the existing transport.",
  "Remote-to-remote copy is unsupported. Remote -l USER and -p PORT are",
  "legacy private options, not OpenSSH bandwidth/preservation options.",
  (char *) NULL
};

struct builtin scp_struct = {
  "scp",
  scp_builtin,
  BUILTIN_ENABLED,
  scp_doc,
  "scp [--] SRC DST | scp [-r] [-P PORT] [-i KEY] [-l USER] [--openssh] SRC DST",
  0
};
