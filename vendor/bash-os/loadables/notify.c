/* SPDX-License-Identifier: MIT */
/* notify.c - sd_notify(3)-style AF_UNIX datagram sender for bash-os.
 *
 * This is intentionally small: systemd-notify.sh remains the compatibility
 * parser and lifecycle wrapper. The builtin owns only socket address encoding
 * and sendto(2), including systemd's '@name' abstract namespace spelling.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "loadables.h"

#ifndef SOCK_CLOEXEC
#  define SOCK_CLOEXEC 02000000
#endif

static int
bnfy_set_cloexec (int fd)
{
  int flags = fcntl (fd, F_GETFD);
  if (flags < 0)
    return -1;
  return fcntl (fd, F_SETFD, flags | FD_CLOEXEC);
}

static int
bnfy_open_socket (void)
{
  int fd = socket (AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0 && errno == EINVAL)
    fd = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (fd < 0)
    return -1;
  if (bnfy_set_cloexec (fd) < 0)
    {
      int saved = errno;
      close (fd);
      errno = saved;
      return -1;
    }
  return fd;
}

static int
bnfy_make_addr (const char *socket_name, struct sockaddr_un *sun,
                socklen_t *sunlen)
{
  size_t n;

  if (!socket_name || !*socket_name)
    {
      errno = EINVAL;
      return -1;
    }

  memset (sun, 0, sizeof *sun);
  sun->sun_family = AF_UNIX;

  if (socket_name[0] == '@')
    {
      n = strlen (socket_name + 1);
      if (n == 0 || n + 1 > sizeof sun->sun_path)
        {
          errno = ENAMETOOLONG;
          return -1;
        }
      sun->sun_path[0] = '\0';
      memcpy (sun->sun_path + 1, socket_name + 1, n);
      *sunlen = (socklen_t) (offsetof (struct sockaddr_un, sun_path) + 1 + n);
      return 0;
    }

  n = strlen (socket_name);
  if (n >= sizeof sun->sun_path)
    {
      errno = ENAMETOOLONG;
      return -1;
    }
  memcpy (sun->sun_path, socket_name, n + 1);
  *sunlen = (socklen_t) (offsetof (struct sockaddr_un, sun_path) + n + 1);
  return 0;
}

static int
bnfy_send (const char *socket_name, const char *payload)
{
  struct sockaddr_un sun;
  socklen_t sunlen;
  int fd;
  ssize_t n;
  size_t payload_len;

  if (bnfy_make_addr (socket_name, &sun, &sunlen) < 0)
    {
      builtin_error ("bad NOTIFY_SOCKET %s: %s", socket_name ? socket_name : "",
                     strerror (errno));
      return EXECUTION_FAILURE;
    }

  fd = bnfy_open_socket ();
  if (fd < 0)
    {
      builtin_error ("socket: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }

  payload_len = payload ? strlen (payload) : 0;
  n = sendto (fd, payload ? payload : "", payload_len, 0,
              (struct sockaddr *) &sun, sunlen);
  int saved = errno;
  close (fd);
  if (n < 0)
    {
      errno = saved;
      builtin_error ("sendto %s: %s", socket_name, strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

int
notify_builtin (WORD_LIST *list)
{
  const char *cmd;

  if (!list || !list->word || !list->word->word)
    {
      builtin_usage ();
      return EX_USAGE;
    }

  cmd = list->word->word;
  if (strcmp (cmd, "--help") == 0 || strcmp (cmd, "-h") == 0)
    {
      puts ("notify send SOCKET PAYLOAD");
      puts ("notify --help | --version");
      return EXECUTION_SUCCESS;
    }
  if (strcmp (cmd, "--version") == 0)
    {
      puts ("notify 1.0 (bash-loadable)");
      return EXECUTION_SUCCESS;
    }
  if (strcmp (cmd, "send") == 0)
    {
      WORD_LIST *args = list->next;
      if (!args || !args->next || !args->word || !args->next->word)
        {
          builtin_error ("send needs SOCKET PAYLOAD");
          return EX_USAGE;
        }
      return bnfy_send (args->word->word, args->next->word->word);
    }

  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *notify_doc[] = {
  "Send sd_notify-style AF_UNIX datagrams.",
  "",
  "    notify send SOCKET PAYLOAD",
  "",
  "SOCKET may be a filesystem AF_UNIX datagram socket path or systemd's",
  "'@name' abstract-namespace spelling. systemd-notify.sh owns CLI parsing;",
  "this builtin owns only datagram delivery.",
  (char *) NULL
};

struct builtin notify_struct = {
  "notify",
  notify_builtin,
  BUILTIN_ENABLED,
  notify_doc,
  "notify send SOCKET PAYLOAD",
  0
};
