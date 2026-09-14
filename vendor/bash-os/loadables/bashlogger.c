/* SPDX-License-Identifier: MIT */
/* bashlogger.c - minimal logger(1)-style syslog sender for bash-os.
 *
 * v1 focuses on the socket-safety surface: every /dev/log socket is
 * created with SOCK_CLOEXEC so a later exec from the same shell cannot
 * inherit the syslog fd.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include "loadables.h"

#ifndef SOCK_CLOEXEC
#  define SOCK_CLOEXEC 02000000
#endif

static int
blog_set_cloexec (int fd)
{
  int flags = fcntl (fd, F_GETFD);
  if (flags < 0)
    return -1;
  return fcntl (fd, F_SETFD, flags | FD_CLOEXEC);
}

static int
blog_open_syslog_socket (void)
{
  int fd = socket (AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0 && errno == EINVAL)
    fd = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (fd < 0)
    return -1;
  if (blog_set_cloexec (fd) < 0)
    {
      int saved = errno;
      close (fd);
      errno = saved;
      return -1;
    }
  return fd;
}

static int
blog_send_line (const char *line)
{
  struct sockaddr_un sun;
  const char *sock_path = getenv ("BASHLOGGER_SOCKET");
  int fd = blog_open_syslog_socket ();
  if (fd < 0)
    {
      builtin_error ("socket %s: %s", sock_path ? sock_path : "/dev/log",
                     strerror (errno));
      return EXECUTION_FAILURE;
    }

  if (!sock_path || !*sock_path)
    sock_path = "/dev/log";
  memset (&sun, 0, sizeof sun);
  sun.sun_family = AF_UNIX;
  snprintf (sun.sun_path, sizeof sun.sun_path, "%s", sock_path);

  size_t len = strlen (line);
  ssize_t n = sendto (fd, line, len, 0, (struct sockaddr *) &sun,
                      (socklen_t) sizeof sun);
  int saved = errno;
  close (fd);
  if (n < 0)
    {
      errno = saved;
      builtin_error ("sendto %s: %s", sock_path, strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static void
blog_append (char *dst, size_t cap, const char *fmt, ...)
{
  size_t used = strlen (dst);
  if (used >= cap)
    return;
  va_list ap;
  va_start (ap, fmt);
  vsnprintf (dst + used, cap - used, fmt, ap);
  va_end (ap);
}

static int
blog_cmd (WORD_LIST *args)
{
  const char *tag = "user";
  const char *priority = "user.notice";
  int include_pid = 0;
  char msg[2048] = "";

  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-i") == 0 || strcmp (w, "--id") == 0)
        include_pid = 1;
      else if (strcmp (w, "-t") == 0 || strcmp (w, "--tag") == 0)
        {
          if (!p->next) { builtin_error ("%s needs TAG", w); return EX_USAGE; }
          p = p->next;
          tag = p->word->word;
        }
      else if (strncmp (w, "--tag=", 6) == 0)
        tag = w + 6;
      else if (strcmp (w, "-p") == 0 || strcmp (w, "--priority") == 0)
        {
          if (!p->next) { builtin_error ("%s needs PRI", w); return EX_USAGE; }
          p = p->next;
          priority = p->word->word;
        }
      else if (strncmp (w, "--priority=", 11) == 0)
        priority = w + 11;
      else if (strcmp (w, "--") == 0)
        {
          for (p = p->next; p; p = p->next)
            blog_append (msg, sizeof msg, "%s%s", msg[0] ? " " : "",
                         p->word->word);
          break;
        }
      else if (w[0] == '-')
        {
          builtin_error ("unknown flag: %s", w);
          builtin_usage ();
          return EX_USAGE;
        }
      else
        blog_append (msg, sizeof msg, "%s%s", msg[0] ? " " : "", w);
    }

  if (!msg[0])
    {
      char buf[512];
      while (fgets (buf, sizeof buf, stdin))
        {
          buf[strcspn (buf, "\r\n")] = '\0';
          blog_append (msg, sizeof msg, "%s%s", msg[0] ? "\n" : "", buf);
        }
    }
  if (!msg[0])
    { builtin_error ("no message"); return EX_USAGE; }

  char line[3072] = "";
  if (include_pid)
    snprintf (line, sizeof line, "<%s> %s[%ld]: %s", priority, tag,
              (long) getpid (), msg);
  else
    snprintf (line, sizeof line, "<%s> %s: %s", priority, tag, msg);
  return blog_send_line (line);
}

int
bashlogger_builtin (WORD_LIST *list)
{
  return blog_cmd (list);
}

char *bashlogger_doc[] = {
  "Send one logger(1)-style message to /dev/log.",
  "",
  "    bashlogger [-i] [-t TAG] [-p PRI] [MESSAGE...]",
  "    bashlogger [--id] [--tag=TAG] [--priority=PRI] [MESSAGE...]",
  "",
  "The syslog socket is opened with SOCK_CLOEXEC/FD_CLOEXEC.",
  "BASHLOGGER_SOCKET overrides /dev/log for focused tests.",
  (char *) NULL
};

struct builtin bashlogger_struct = {
  "bashlogger",
  bashlogger_builtin,
  BUILTIN_ENABLED,
  bashlogger_doc,
  "bashlogger [-i] [-t TAG] [-p PRI] [MESSAGE...]",
  0
};
