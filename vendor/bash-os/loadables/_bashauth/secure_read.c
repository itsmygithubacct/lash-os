/* SPDX-License-Identifier: MIT */
#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <termios.h>
#include <unistd.h>

#include "_bashauth_secure_read.h"

static void
bashos_secure_wipe (void *p, size_t n)
{
  volatile unsigned char *q = (volatile unsigned char *) p;
  while (q && n--)
    *q++ = 0;
}

void
bashos_secure_free_password (unsigned char *buf)
{
  if (!buf)
    return;
  bashos_secure_wipe (buf, BASHOS_AUTH_PASSWORD_MAX);
  munlock (buf, BASHOS_AUTH_PASSWORD_MAX);
  munmap (buf, BASHOS_AUTH_PASSWORD_MAX);
}

int
bashos_secure_read_password (const char *prompt, unsigned char **out,
                             size_t *out_len)
{
  if (!out || !out_len)
    {
      errno = EINVAL;
      return -1;
    }
  *out = NULL;
  *out_len = 0;

  int fd = open ("/dev/tty", O_RDWR | O_CLOEXEC);
  if (fd < 0)
    {
      if (!isatty (STDIN_FILENO))
        {
          errno = ENOTTY;
          return -1;
        }
      fd = STDIN_FILENO;
    }

  struct termios oldt, newt;
  int have_termios = (tcgetattr (fd, &oldt) == 0);
  if (have_termios)
    {
      newt = oldt;
      newt.c_lflag &= ~(ECHO | ICANON);
      newt.c_cc[VMIN] = 1;
      newt.c_cc[VTIME] = 0;
      if (tcsetattr (fd, TCSAFLUSH, &newt) < 0)
        have_termios = 0;
    }

  int prompted = 0;
  if (prompt && *prompt)
    {
      ssize_t ignored = write (fd == STDIN_FILENO ? STDERR_FILENO : fd,
                               prompt, strlen (prompt));
      (void) ignored;
      prompted = 1;
    }

  unsigned char *buf = mmap (NULL, BASHOS_AUTH_PASSWORD_MAX,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buf == MAP_FAILED)
    {
      int saved = errno;
      if (have_termios)
        tcsetattr (fd, TCSANOW, &oldt);
      if (prompted)
        write (fd == STDIN_FILENO ? STDERR_FILENO : fd, "\n", 1);
      if (fd != STDIN_FILENO)
        close (fd);
      errno = saved;
      return -1;
    }
  (void) mlock (buf, BASHOS_AUTH_PASSWORD_MAX);

  size_t len = 0;
  int saved = 0;
  for (;;)
    {
      unsigned char c;
      ssize_t r = read (fd, &c, 1);
      if (r < 0)
        {
          if (errno == EINTR)
            continue;
          saved = errno;
          break;
        }
      if (r == 0 || c == '\n' || c == '\r')
        break;
      if (len >= BASHOS_AUTH_PASSWORD_MAX)
        {
          saved = E2BIG;
          break;
        }
      buf[len++] = c;
    }

  if (have_termios)
    tcsetattr (fd, TCSANOW, &oldt);
  if (prompted)
    write (fd == STDIN_FILENO ? STDERR_FILENO : fd, "\n", 1);
  if (fd != STDIN_FILENO)
    close (fd);

  if (saved)
    {
      bashos_secure_free_password (buf);
      errno = saved;
      return -1;
    }

  *out = buf;
  *out_len = len;
  return 0;
}
