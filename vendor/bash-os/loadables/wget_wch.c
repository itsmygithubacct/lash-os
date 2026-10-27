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
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
  return n == 1 ? 1 : n == 0 ? 0 : -1;
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

/* Nonseekable input needs one scalar of lookahead. Key this by stream
   identity, rather than the descriptor number, so switches and dup aliases
   do not mix distinct pipes. Seekable input is rewound instead. This private
   cache belongs to wget_wch: mixing other readers, or reopening a FIFO/TTY
   with the same identity, needs an explicit reader lifecycle API. */
#define BWW_PENDING_STREAMS 1025
static struct {
  int valid;
  dev_t device;
  ino_t inode;
  mode_t type;
  dev_t rdevice;
  unsigned char bytes[4];
  size_t len;
} bww_pending[BWW_PENDING_STREAMS];

static int
bww_pending_matches (size_t i, const struct stat *st)
{
  return bww_pending[i].valid
      && bww_pending[i].device == st->st_dev
      && bww_pending[i].inode == st->st_ino
      && bww_pending[i].type == (st->st_mode & S_IFMT)
      && bww_pending[i].rdevice == st->st_rdev;
}

static int
bww_take_pending (int fd, unsigned char *buf, size_t *len)
{
  struct stat st;
  int flags = fcntl (fd, F_GETFL);
  if (flags < 0) return -1;
  if ((flags & O_ACCMODE) == O_WRONLY) { errno = EBADF; return -1; }
  if (fstat (fd, &st) < 0) return -1;
  for (size_t i = 0; i < BWW_PENDING_STREAMS; i++)
    if (bww_pending_matches (i, &st))
      {
        *len = bww_pending[i].len;
        memcpy (buf, bww_pending[i].bytes, *len);
        bww_pending[i].valid = 0;
        return 1;
      }
  return 0;
}

static int
bww_save_pending (int fd, const unsigned char *buf, size_t len)
{
  if (lseek (fd, -(off_t) len, SEEK_CUR) != (off_t) -1) return 0;
  if (errno != ESPIPE) return -1;
  struct stat st;
  if (fstat (fd, &st) < 0) return -1;
  for (size_t i = 0; i < BWW_PENDING_STREAMS; i++)
    if (!bww_pending[i].valid)
      {
        bww_pending[i].device = st.st_dev;
        bww_pending[i].inode = st.st_ino;
        bww_pending[i].type = st.st_mode & S_IFMT;
        bww_pending[i].rdevice = st.st_rdev;
        bww_pending[i].len = len;
        memcpy (bww_pending[i].bytes, buf, len);
        bww_pending[i].valid = 1;
        return 0;
      }
  errno = ENOBUFS;
  return -1;
}

/* Read a complete scalar before making a cluster-boundary decision.
   1 = scalar, 0 = EOF, -1 = invalid/incomplete scalar or input error. */
static int
bww_read_scalar (int fd, unsigned char *buf, size_t *len, unsigned *cp)
{
  size_t used;
  int pending = bww_take_pending (fd, buf, len);
  if (pending < 0) return -1;
  if (!pending)
    {
      *len = 0;
      int r = bww_read_byte (fd, buf);
      if (r <= 0) return r;
      *len = 1;
      size_t need = buf[0] < 0x80 ? 1
                  : buf[0] >= 0xc2 && buf[0] <= 0xdf ? 2
                  : buf[0] >= 0xe0 && buf[0] <= 0xef ? 3
                  : buf[0] >= 0xf0 && buf[0] <= 0xf4 ? 4 : 1;
      while (*len < need)
        {
          if (bww_read_byte (fd, buf + *len) != 1) return -1;
          (*len)++;
        }
    }
  return bww_utf8_one (buf, *len, cp, &used) == 0 ? 1 : -1;
}

static int
bww_read_cluster (int fd, unsigned char *buf, size_t *len)
{
  unsigned char scalar[4];
  size_t used = 0, n = 0, count = 1;
  unsigned cp;
  if (bww_read_scalar (fd, scalar, &used, &cp) != 1) return -1;
  memcpy (buf, scalar, used);
  n = used;
  int join_next = cp == 0x200d;
  while (count < BWW_MAX_CPS && bww_read_more_ready (fd))
    {
      int r = bww_read_scalar (fd, scalar, &used, &cp);
      if (r == 0) break;
      if (r < 0) return -1;
      if (!bww_is_extend (cp) && !join_next)
        {
          if (bww_save_pending (fd, scalar, used) < 0) return -1;
          break;
        }
      memcpy (buf + n, scalar, used);
      n += used;
      count++;
      join_next = cp == 0x200d;
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
  "Nonseekable read owns process-local lookahead: drain an input using",
  "wget_wch in one shell process. Do not mix other readers, fork between",
  "reads, or reopen the same FIFO/TTY while lookahead remains pending.",
  "Seekable file lookahead is rewound; ordinary FD switches are supported.",
  "Closing an undrained input retains its pending slot until shell exit.",
  "Read failures, including exhausted pending slots, can consume input.",
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
