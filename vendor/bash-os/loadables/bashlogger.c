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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <strings.h>

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
  int fd;
  if (!sock_path || !*sock_path)
    sock_path = "/dev/log";
  if (strlen (sock_path) >= sizeof sun.sun_path)
    {
      builtin_error ("socket path too long: %s", sock_path);
      return EXECUTION_FAILURE;
    }
  fd = blog_open_syslog_socket ();
  if (fd < 0)
    {
      builtin_error ("socket %s: %s", sock_path ? sock_path : "/dev/log",
                     strerror (errno));
      return EXECUTION_FAILURE;
    }

  memset (&sun, 0, sizeof sun);
  sun.sun_family = AF_UNIX;
  snprintf (sun.sun_path, sizeof sun.sun_path, "%s", sock_path);

  size_t len = strlen (line);
  ssize_t n;
  do
    n = sendto (fd, line, len, 0, (struct sockaddr *) &sun,
                (socklen_t) sizeof sun);
  while (n < 0 && errno == EINTR);
  int saved = errno;
  close (fd);
  if (n < 0 || (size_t) n != len)
    {
      errno = n < 0 ? saved : EIO;
      builtin_error ("sendto %s: %s", sock_path, strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

struct blog_name {
  const char *name;
  int value;
};

static const struct blog_name blog_facilities[] = {
  {"kern", 0}, {"user", 1}, {"mail", 2}, {"daemon", 3},
  {"auth", 4}, {"security", 4}, {"syslog", 5}, {"lpr", 6},
  {"news", 7}, {"uucp", 8}, {"cron", 9}, {"authpriv", 10}, {"ftp", 11},
  {"local0", 16}, {"local1", 17}, {"local2", 18}, {"local3", 19},
  {"local4", 20}, {"local5", 21}, {"local6", 22}, {"local7", 23},
  {0, 0}
};

static const struct blog_name blog_severities[] = {
  {"emerg", 0}, {"panic", 0}, {"alert", 1}, {"crit", 2},
  {"err", 3}, {"error", 3}, {"warning", 4}, {"warn", 4},
  {"notice", 5}, {"info", 6}, {"debug", 7}, {0, 0}
};

/* Decimal only, with a range check before multiplication (also bounds overflow). */
static int
blog_number (const char *text, size_t len, int max)
{
  int value = 0;
  if (len == 0)
    return -1;
  for (size_t i = 0; i < len; i++)
    {
      int digit = text[i] - '0';
      if (digit < 0 || digit > 9 || value > (max - digit) / 10)
        return -1;
      value = value * 10 + digit;
      if (value > max)
        return -1;
    }
  return value;
}

static int
blog_lookup (const char *text, size_t len, const struct blog_name *names, int max)
{
  int number = blog_number (text, len, max);
  if (number >= 0)
    return number;
  for (; names->name; names++)
    if (strlen (names->name) == len && strncasecmp (text, names->name, len) == 0)
      return names->value;
  return -1;
}

static int
blog_priority (const char *text)
{
  const char *dot = strchr (text, '.');
  if (dot)
    {
      int facility = blog_lookup (text, dot - text, blog_facilities, 23);
      int severity = blog_lookup (dot + 1, strlen (dot + 1), blog_severities, 7);
      return facility < 0 || severity < 0 ? -1 : facility * 8 + severity;
    }
  int number = blog_number (text, strlen (text), 191);
  if (number >= 0)
    return number;
  int severity = blog_lookup (text, strlen (text), blog_severities, 7);
  return severity < 0 ? -1 : 8 + severity;
}

static int
blog_append (char *dst, size_t cap, size_t *used, const char *word, int separator)
{
  size_t len = strlen (word);
  if (len >= cap - *used || (separator && len + 1 >= cap - *used))
    {
      builtin_error ("message too long (maximum 2047 bytes)");
      return -1;
    }
  if (separator)
    dst[(*used)++] = ' ';
  memcpy (dst + *used, word, len + 1);
  *used += len;
  return 0;
}

static int
blog_cmd (WORD_LIST *args)
{
  const char *tag = "user";
  const char *priority = "user.notice";
  int include_pid = 0;
  char msg[2048] = "";
  size_t used = 0;
  int operands = 0;

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
            if (blog_append (msg, sizeof msg, &used, p->word->word, operands++) < 0)
              return EX_USAGE;
          break;
        }
      else if (w[0] == '-')
        {
          builtin_error ("unknown flag: %s", w);
          builtin_usage ();
          return EX_USAGE;
        }
      else if (blog_append (msg, sizeof msg, &used, w, operands++) < 0)
        return EX_USAGE;
    }

  int pri = blog_priority (priority);
  if (pri < 0)
    {
      builtin_error ("invalid priority: %s", priority);
      return EX_USAGE;
    }

  if (!operands)
    {
      int c;
      clearerr (stdin);
      while ((c = fgetc (stdin)) != EOF)
        {
          if (c == 0)
            { builtin_error ("NUL in message"); return EX_USAGE; }
          if (used == sizeof msg - 1)
            { builtin_error ("message too long (maximum 2047 bytes)"); return EX_USAGE; }
          msg[used++] = c;
        }
      if (ferror (stdin))
        { builtin_error ("read: %s", strerror (errno)); return EXECUTION_FAILURE; }
      if (!used)
        { builtin_error ("no message"); return EX_USAGE; }
      if (msg[used - 1] == '\n')
        {
          used--;
          if (used && msg[used - 1] == '\r')
            used--;
        }
      msg[used] = '\0';
    }

  char line[3072];
  int len;
  if (include_pid)
    len = snprintf (line, sizeof line, "<%d> %s[%ld]: %s", pri, tag,
                    (long) getpid (), msg);
  else
    len = snprintf (line, sizeof line, "<%d> %s: %s", pri, tag, msg);
  if (len < 0 || (size_t) len >= sizeof line)
    { builtin_error ("formatted message too long (maximum 3071 bytes)"); return EX_USAGE; }
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
  "PRI is decimal 0..191, facility.severity, or a named severity (user facility).",
  "Facilities 0..23 and severities 0..7 also work within facility.severity.",
  "Default: user.notice (13), tag user. Arguments join with one space.",
  "Without MESSAGE, read one message from stdin, removing one final LF/CRLF.",
  "Messages over 2047 bytes or formatted datagrams over 3071 bytes fail.",
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
