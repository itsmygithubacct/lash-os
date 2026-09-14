/* SPDX-License-Identifier: MIT */
/* wget_wch.c - UTF-8 / wide-character input helper for bash-os.
 *
 * Phase 3 slice from PROPOSAL_NCURSES_INPUT.md. It exposes a compact
 * wget_wch-shaped primitive that decodes one UTF-8 scalar plus following
 * combining marks / variation selectors / ZWJ-linked scalars as a single
 * grapheme-ish cluster. It intentionally keeps the interface byte-oriented
 * so callers do not store raw input in Bash variables unless they choose to.
 *
 * Surface:
 *   wget_wch decode HEX...   -> wch U+XXXX[,U+YYYY...] bytes=N
 *   wget_wch read [FD]       -> same, reading one cluster
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loadables.h"

#define BWW_MAX_BYTES 64
#define BWW_MAX_CPS 16

static int
bww_hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
bww_parse_hex (WORD_LIST *list, unsigned char *buf, size_t *out_len)
{
  size_t n = 0;
  for (; list; list = list->next)
    {
      const char *w = list->word->word;
      size_t len = strlen (w);
      if (len >= 2 && w[0] == '0' && (w[1] == 'x' || w[1] == 'X'))
        { w += 2; len -= 2; }
      if (len == 0 || len % 2 != 0)
        return -1;
      for (size_t i = 0; i < len; i += 2)
        {
          int hi = bww_hexval ((unsigned char) w[i]);
          int lo = bww_hexval ((unsigned char) w[i + 1]);
          if (hi < 0 || lo < 0 || n >= BWW_MAX_BYTES)
            return -1;
          buf[n++] = (unsigned char) ((hi << 4) | lo);
        }
    }
  *out_len = n;
  return n ? 0 : -1;
}

static int
bww_utf8_one (const unsigned char *buf, size_t len, unsigned *cp, size_t *used)
{
  unsigned char b0;
  if (len == 0) return -1;
  b0 = buf[0];
  if (b0 < 0x80)
    { *cp = b0; *used = 1; return 0; }
  if (b0 >= 0xc2 && b0 <= 0xdf)
    {
      if (len < 2 || (buf[1] & 0xc0) != 0x80) return -1;
      *cp = ((unsigned) (b0 & 0x1f) << 6) | (unsigned) (buf[1] & 0x3f);
      *used = 2; return 0;
    }
  if (b0 >= 0xe0 && b0 <= 0xef)
    {
      if (len < 3 || (buf[1] & 0xc0) != 0x80 || (buf[2] & 0xc0) != 0x80)
        return -1;
      if ((b0 == 0xe0 && buf[1] < 0xa0) || (b0 == 0xed && buf[1] >= 0xa0))
        return -1;
      *cp = ((unsigned) (b0 & 0x0f) << 12)
          | ((unsigned) (buf[1] & 0x3f) << 6)
          | (unsigned) (buf[2] & 0x3f);
      *used = 3; return 0;
    }
  if (b0 >= 0xf0 && b0 <= 0xf4)
    {
      if (len < 4 || (buf[1] & 0xc0) != 0x80 || (buf[2] & 0xc0) != 0x80
          || (buf[3] & 0xc0) != 0x80)
        return -1;
      if ((b0 == 0xf0 && buf[1] < 0x90) || (b0 == 0xf4 && buf[1] >= 0x90))
        return -1;
      *cp = ((unsigned) (b0 & 0x07) << 18)
          | ((unsigned) (buf[1] & 0x3f) << 12)
          | ((unsigned) (buf[2] & 0x3f) << 6)
          | (unsigned) (buf[3] & 0x3f);
      *used = 4; return 0;
    }
  return -1;
}

static int
bww_is_extend (unsigned cp)
{
  return (cp >= 0x0300 && cp <= 0x036f)
      || (cp >= 0x1ab0 && cp <= 0x1aff)
      || (cp >= 0x1dc0 && cp <= 0x1dff)
      || (cp >= 0x20d0 && cp <= 0x20ff)
      || (cp >= 0xfe00 && cp <= 0xfe0f)
      || (cp >= 0xe0100 && cp <= 0xe01ef)
      || (cp >= 0x1f3fb && cp <= 0x1f3ff)
      || cp == 0x200d;
}

static int
bww_decode_cluster (const unsigned char *buf, size_t len,
                    unsigned *cps, size_t *ncp, size_t *nbytes)
{
  size_t off = 0, used = 0, count = 0;
  unsigned cp;
  int join_next = 0;
  if (bww_utf8_one (buf, len, &cp, &used) < 0)
    return -1;
  cps[count++] = cp;
  off += used;
  join_next = (cp == 0x200d);

  while (off < len && count < BWW_MAX_CPS)
    {
      if (bww_utf8_one (buf + off, len - off, &cp, &used) < 0)
        break;
      if (!bww_is_extend (cp) && !join_next)
        break;
      cps[count++] = cp;
      off += used;
      join_next = (cp == 0x200d);
    }
  *ncp = count;
  *nbytes = off;
  return 0;
}

static int
bww_read_byte (int fd, unsigned char *out)
{
  ssize_t n;
  do
    n = read (fd, out, 1);
  while (n < 0 && errno == EINTR);
  return n == 1 ? 0 : -1;
}

static int
bww_read_more_ready (int fd)
{
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  return poll (&pfd, 1, 0) > 0;
}

static int
bww_read_cluster (int fd, unsigned char *buf, size_t *len)
{
  size_t n = 0;
  if (bww_read_byte (fd, &buf[n++]) < 0)
    return -1;
  while (n < BWW_MAX_BYTES && bww_read_more_ready (fd))
    {
      unsigned tmp[BWW_MAX_CPS];
      size_t ncp = 0, nbytes = 0, used = 0;
      if (bww_utf8_one (buf, n, &tmp[0], &used) == 0
          && bww_decode_cluster (buf, n, tmp, &ncp, &nbytes) == 0
          && nbytes < n)
        break;
      if (bww_read_byte (fd, &buf[n++]) < 0)
        break;
    }
  *len = n;
  return 0;
}

static void
bww_print (const unsigned *cps, size_t ncp, size_t nbytes)
{
  printf ("wch ");
  for (size_t i = 0; i < ncp; i++)
    printf ("%sU+%04X", i ? "," : "", cps[i]);
  printf (" bytes=%zu\n", nbytes);
}

static const char *
bww_next (WORD_LIST **p)
{
  if (!p || !*p) return NULL;
  const char *w = (*p)->word->word;
  *p = (*p)->next;
  return w;
}

int
wget_wch_builtin (WORD_LIST *list)
{
  const char *cmd = bww_next (&list);
  unsigned char buf[BWW_MAX_BYTES];
  unsigned cps[BWW_MAX_CPS];
  size_t len = 0, ncp = 0, nbytes = 0;

  if (!cmd || !strcmp (cmd, "--help") || !strcmp (cmd, "-h"))
    {
      builtin_usage ();
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "decode"))
    {
      if (bww_parse_hex (list, buf, &len) < 0
          || bww_decode_cluster (buf, len, cps, &ncp, &nbytes) < 0)
        { builtin_error ("usage: wget_wch decode HEX..."); return EX_USAGE; }
      bww_print (cps, ncp, nbytes);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "read"))
    {
      int fd = STDIN_FILENO;
      const char *fd_s = bww_next (&list);
      if (fd_s)
        {
          char *end = NULL;
          long v = strtol (fd_s, &end, 10);
          if (!end || *end || v < 0 || v > 1024 || list)
            { builtin_error ("usage: wget_wch read [FD]"); return EX_USAGE; }
          fd = (int) v;
        }
      if (bww_read_cluster (fd, buf, &len) < 0
          || bww_decode_cluster (buf, len, cps, &ncp, &nbytes) < 0)
        return EXECUTION_FAILURE;
      bww_print (cps, ncp, nbytes);
      return EXECUTION_SUCCESS;
    }

  builtin_error ("unknown command: %s", cmd);
  builtin_usage ();
  return EX_USAGE;
}

char *wget_wch_doc[] = {
  "Decode one UTF-8 wide-character / grapheme-style cluster.",
  "",
  "    wget_wch decode HEX...",
  "    wget_wch read [FD]",
  "",
  "Output is: wch U+XXXX[,U+YYYY...] bytes=N.",
  (char *)NULL
};

struct builtin wget_wch_struct = {
  "wget_wch",
  wget_wch_builtin,
  BUILTIN_ENABLED,
  wget_wch_doc,
  "wget_wch decode HEX... | read [FD]",
  0
};
