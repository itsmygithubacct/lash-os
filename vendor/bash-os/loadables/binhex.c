/* binhex.c — hex-encode/decode a byte stream. Loadable for bash.
 *
 * Bash variables are C strings; storing a NUL byte truncates the
 * value. That cuts off whole classes of binary processing in pure
 * bash. binhex sidesteps the limit by operating on FILE DESCRIPTORS
 * (read(2)/write(2), no variable in the byte path) and producing
 * NUL-free ASCII (lowercase hex) output that IS storable.
 *
 * Encode (default):
 *     binhex < bin > hex
 *     hexvar=$(binhex bin)
 *
 * Decode (-d):
 *     binhex -d < hex > bin
 *     printf '%s' "$hexvar" | binhex -d > bin
 *
 * Format: lowercase hex, 2 chars per byte, no separators, no
 * line wrapping. ASCII whitespace + leading "0x"/"0X" tolerated
 * on decode (so xxd-style output with embedded spaces / output
 * captured into a bash here-string survives).
 *
 * Companion docs:
 *     /docs/bash/NUL-LIMIT.txt — why this exists
 *
 * --- LICENSE ---
 * MIT License
 *
 * Copyright (c) 2026 bash_linux contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Note: when compiled and statically linked into GNU Bash, the resulting
 * combined binary is a derivative work of bash and is governed by GPL-3+
 * (bash's license). MIT for this source file is GPL-3+-compatible, so
 * the binary's GPL-3+ status is unchanged. The MIT grant lets anyone
 * lift this file into a non-GPL project independently of our build.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include "loadables.h"

#define BUFSZ 4096
static const char hexdigits[16] = "0123456789abcdef";

/* Encode bytes from `in_fd` to `out_fd` as 2-char-per-byte lowercase hex.
   Returns 0 on success, 1 on read/write error. */
static int
binhex_encode (int in_fd, int out_fd)
{
  unsigned char inbuf[BUFSZ];
  char outbuf[2 * BUFSZ];
  ssize_t n;
  size_t i, o;

  for (;;)
    {
      n = read (in_fd, inbuf, BUFSZ);
      if (n < 0)
        {
          if (errno == EINTR) continue;
          builtin_error ("read: %s", strerror (errno));
          return 1;
        }
      if (n == 0)
        return 0;
      for (i = 0, o = 0; i < (size_t)n; i++)
        {
          outbuf[o++] = hexdigits[(inbuf[i] >> 4) & 0xf];
          outbuf[o++] = hexdigits[inbuf[i] & 0xf];
        }
      /* Loop write to handle short writes / EINTR. */
      char *p = outbuf;
      size_t left = o;
      while (left > 0)
        {
          ssize_t w = write (out_fd, p, left);
          if (w < 0)
            {
              if (errno == EINTR) continue;
              builtin_error ("write: %s", strerror (errno));
              return 1;
            }
          p += w;
          left -= (size_t)w;
        }
    }
}

/* Map a hex digit to its 0..15 value. Returns -1 on invalid char.
   ASCII-locale only (we don't deal with EBCDIC). */
static int
hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Decode hex from `in_fd` to bytes on `out_fd`. Tolerates ASCII
   whitespace + leading 0x/0X prefix. Returns 0 on success, 1 on
   read/write/format error. */
static int
binhex_decode (int in_fd, int out_fd)
{
  char inbuf[BUFSZ];
  unsigned char outbuf[BUFSZ / 2 + 1];
  ssize_t n;
  size_t i, o;
  int hi = -1;          /* held high nibble; -1 = none */
  int saw_nonws = 0;    /* for 0x prefix detection — only at the start */
  int prev_zero = 0;    /* saw a leading '0' that might begin "0x" */

  for (;;)
    {
      n = read (in_fd, inbuf, BUFSZ);
      if (n < 0)
        {
          if (errno == EINTR) continue;
          builtin_error ("read: %s", strerror (errno));
          return 1;
        }
      if (n == 0)
        break;
      for (i = 0, o = 0; i < (size_t)n; i++)
        {
          int c = (unsigned char)inbuf[i];
          if (isspace (c))
            continue;
          /* Strip a single leading 0x/0X if we haven't started decoding. */
          if (!saw_nonws && c == '0')
            {
              prev_zero = 1;
              saw_nonws = 1;
              continue;
            }
          if (prev_zero && (c == 'x' || c == 'X'))
            {
              prev_zero = 0;
              hi = -1;
              continue;
            }
          if (prev_zero)
            {
              /* That '0' was a real digit, not a prefix. */
              hi = 0;
              prev_zero = 0;
            }
          saw_nonws = 1;
          int v = hexval (c);
          if (v < 0)
            {
              builtin_error ("invalid hex character: 0x%02x", c);
              return 1;
            }
          if (hi < 0)
            hi = v;
          else
            {
              outbuf[o++] = (unsigned char)((hi << 4) | v);
              hi = -1;
            }
        }
      if (o > 0)
        {
          unsigned char *p = outbuf;
          size_t left = o;
          while (left > 0)
            {
              ssize_t w = write (out_fd, p, left);
              if (w < 0)
                {
                  if (errno == EINTR) continue;
                  builtin_error ("write: %s", strerror (errno));
                  return 1;
                }
              p += w;
              left -= (size_t)w;
            }
        }
    }
  if (hi >= 0)
    {
      builtin_error ("odd number of hex digits in input");
      return 1;
    }
  return 0;
}

int
binhex_builtin (WORD_LIST *list)
{
  int opt;
  int decode = 0;
  int in_fd = -1;
  int close_in = 0;
  const char *path = NULL;

  reset_internal_getopt ();
  while ((opt = internal_getopt (list, "d")) != -1)
    {
      switch (opt)
        {
        case 'd':
          decode = 1;
          break;
        CASE_HELPOPT;
        default:
          builtin_usage ();
          return (EX_USAGE);
        }
    }
  list = loptend;

  if (list != 0)
    {
      path = list->word->word;
      if (list->next != 0)
        {
          builtin_error ("at most one FILE argument is accepted");
          builtin_usage ();
          return (EX_USAGE);
        }
    }

  if (path == NULL || (path[0] == '-' && path[1] == '\0'))
    in_fd = STDIN_FILENO;
  else
    {
      in_fd = open (path, O_RDONLY);
      if (in_fd < 0)
        {
          builtin_error ("%s: %s", path, strerror (errno));
          return (EXECUTION_FAILURE);
        }
      close_in = 1;
    }

  int rc = decode
    ? binhex_decode (in_fd, STDOUT_FILENO)
    : binhex_encode (in_fd, STDOUT_FILENO);

  if (close_in)
    close (in_fd);
  fflush (stdout);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

char *binhex_doc[] = {
  "Hex-encode or decode a byte stream — bypasses bash's NUL-byte",
  "variable-storage limit by reading/writing via file descriptors",
  "(read(2)/write(2)) and producing NUL-free ASCII hex output.",
  "",
  "Without -d:  read raw bytes, emit lowercase 2-char-per-byte hex.",
  "With    -d:  read hex (whitespace + leading 0x/0X tolerated),",
  "             emit raw bytes (NULs preserved at the FD layer).",
  "",
  "Examples:",
  "    h=$(binhex /etc/hostname)        # capture binary as hex var",
  "    printf %s \"$h\" | binhex -d > /tmp/copy",
  "    binhex < bin.dat | sha256sum     # hash arbitrary binary",
  "",
  "See /docs/bash/NUL-LIMIT.txt for the full picture.",
  (char *)NULL
};

struct builtin binhex_struct = {
  "binhex",
  binhex_builtin,
  BUILTIN_ENABLED,
  binhex_doc,
  "binhex [-d] [FILE]",
  0
};
