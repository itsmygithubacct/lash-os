/* SPDX-License-Identifier: MIT */
/* zlib.c — multi-format compression/decompression loadable for bash.
 *
 * Wraps libz / liblzma / libzstd as a single bash builtin. Operates on
 * file descriptors (read(2)/write(2)) for NUL safety — same model as
 * binhex. Supports gzip (RFC 1952), zlib (RFC 1950), raw deflate
 * (RFC 1951), xz/lzma, and zstd in both directions.
 *
 * Why this exists:
 *   /docs/bash/COMPRESSION-LIMIT.txt explains why pure bash can't do
 *   gzip/xz/zstd at usable speed. This loadable is the bash-os answer:
 *   a static C wrapper around mature audited libraries (libz, liblzma,
 *   libzstd), exposed as a bash builtin so callers don't fork.
 *
 * Usage:
 *     zlib < foo.gz > foo                 # decode (default)
 *     zlib -e < foo > foo.gz              # encode (gzip default)
 *     zlib -e -1 < foo > foo.gz           # fastest level
 *     zlib -e -9 < foo > foo.gz           # max level
 *     zlib -f xz < foo.xz > foo
 *     zlib -f zstd < foo.zst > foo
 *     zlib -e -f zstd -3 < foo > foo.zst  # zstd level 3
 *     zlib -z < foo.zlib > foo            # raw RFC 1950 zlib
 *     zlib -R < foo.deflate > foo         # raw RFC 1951 deflate
 *
 * NUL safety: input/output flow through file descriptors (no bash
 * variable in the byte path). Output is binary; pipe to `binhex` if
 * you need to round-trip through a bash variable.
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
 * OR IMPLIED. See the full MIT text for the standard disclaimer.
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
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <zlib.h>
#include <lzma.h>
#include <zstd.h>
#include <bzlib.h>

#include "loadables.h"

#define BZ_BUFSZ 65536

enum bz_format { BZ_GZIP = 0, BZ_XZ, BZ_LZMA, BZ_ZSTD, BZ_ZLIB, BZ_DEFLATE, BZ_BZIP2 };

/* ---- gzip / zlib / deflate (libz) ----------------------------------- */
static int
bz_codec_zlib (int in_fd, int out_fd, int encode, int level, enum bz_format fmt)
{
  z_stream s;
  unsigned char inbuf[BZ_BUFSZ], outbuf[BZ_BUFSZ];
  int ret, wbits;
  ssize_t n = 0;

  memset (&s, 0, sizeof s);

  /* wbits convention (zlib.h):
   *    8..15      → zlib wrap
   *    -8..-15    → raw deflate (no header/trailer)
   *    16+(8..15) → gzip wrap (encode side)
   *    32+(8..15) → autodetect (inflate side; gzip OR zlib)
   */
  switch (fmt)
    {
    case BZ_GZIP:    wbits = encode ? (15 + 16) : (15 + 32); break;
    case BZ_ZLIB:    wbits = 15;                              break;
    case BZ_DEFLATE: wbits = -15;                             break;
    default:         builtin_error ("bz_codec_zlib: bad format");  return 1;
    }

  if (encode)
    {
      if (level < 0) level = Z_DEFAULT_COMPRESSION;
      ret = deflateInit2 (&s, level, Z_DEFLATED, wbits, 8, Z_DEFAULT_STRATEGY);
    }
  else
    {
      ret = inflateInit2 (&s, wbits);
    }
  if (ret != Z_OK)
    {
      /* On init failure, s.msg may be NULL (stream wasn't fully set up).
         zError(ret) is a static lookup that always returns a string. */
      builtin_error ("zlib init: %s", zError (ret));
      return 1;
    }

  for (;;)
    {
      /* Read input unless leftover data from a concatenated gzip member
       * boundary is already buffered (inflateReset preserves avail_in). */
      if (s.avail_in == 0)
        {
          n = read (in_fd, inbuf, sizeof inbuf);
          if (n < 0)
            {
              if (errno == EINTR) continue;
              builtin_error ("read: %s", strerror (errno));
              (encode ? deflateEnd : inflateEnd) (&s);
              return 1;
            }
          s.next_in = inbuf;
          s.avail_in = (uInt) n;
        }
      int flush = (n == 0) ? Z_FINISH : Z_NO_FLUSH;

      do
        {
          s.next_out = outbuf;
          s.avail_out = sizeof outbuf;
          ret = encode ? deflate (&s, flush) : inflate (&s, flush);
          if (ret == Z_STREAM_ERROR ||
              ret == Z_NEED_DICT    ||
              ret == Z_DATA_ERROR   ||
              ret == Z_MEM_ERROR    ||
              ret == Z_BUF_ERROR)
            {
              builtin_error ("zlib: %s",
                             s.msg ? s.msg : zError (ret));
              (encode ? deflateEnd : inflateEnd) (&s);
              return 1;
            }
          size_t produced = sizeof outbuf - s.avail_out;
          if (produced > 0)
            {
              unsigned char *p = outbuf;
              size_t left = produced;
              while (left > 0)
                {
                  ssize_t w = write (out_fd, p, left);
                  if (w < 0)
                    {
                      if (errno == EINTR) continue;
                      builtin_error ("write: %s", strerror (errno));
                      (encode ? deflateEnd : inflateEnd) (&s);
                      return 1;
                    }
                  p += w;
                  left -= (size_t) w;
                }
            }
        }
      while (s.avail_out == 0 && ret != Z_STREAM_END);

      if (ret == Z_STREAM_END)
        {
          /* Concatenated gzip: inflate does not auto-skip to the next
           * member, so we inflateReset and continue when more input is
           * available (buffered or from the fd).  For encode or non-gzip
           * formats a single Z_STREAM_END is terminal. */
          if (!encode && fmt == BZ_GZIP)
            {
              inflateReset (&s);
              if (s.avail_in > 0)
                continue;             /* next member already buffered */
              /* Exact buffer boundary — try to read the next member. */
              n = read (in_fd, inbuf, sizeof inbuf);
              if (n < 0)
                {
                  if (errno == EINTR) continue;
                  builtin_error ("read: %s", strerror (errno));
                  inflateEnd (&s);
                  return 1;
                }
              if (n == 0)
                break;                /* EOF — all members processed */
              s.next_in = inbuf;
              s.avail_in = (uInt) n;
              continue;
            }
          /* Non-gzip or encode: single member is terminal. */
          break;
        }
      if (n == 0)
        break;
    }

  (encode ? deflateEnd : inflateEnd) (&s);
  return 0;
}

/* ---- xz / lzma (liblzma) -------------------------------------------- */
static int
bz_codec_xz (int in_fd, int out_fd, int encode, int level, enum bz_format fmt)
{
  lzma_stream s = LZMA_STREAM_INIT;
  unsigned char inbuf[BZ_BUFSZ], outbuf[BZ_BUFSZ];
  lzma_ret ret;
  ssize_t n = 0;

  if (level < 0) level = LZMA_PRESET_DEFAULT;
  if (level > 9) level = 9;

  if (fmt == BZ_LZMA)
    {
      if (encode)
        {
          lzma_options_lzma opt_lzma;
          if (lzma_lzma_preset (&opt_lzma, (uint32_t) level))
            {
              builtin_error ("lzma preset: %d", level);
              return 1;
            }
          ret = lzma_alone_encoder (&s, &opt_lzma);
        }
      else
        ret = lzma_alone_decoder (&s, UINT64_MAX);
    }
  else
    ret = encode
          ? lzma_easy_encoder (&s, (uint32_t) level, LZMA_CHECK_CRC64)
          : lzma_auto_decoder (&s, UINT64_MAX, LZMA_CONCATENATED);
  if (ret != LZMA_OK)
    {
      builtin_error ("lzma init: code=%d", (int) ret);
      return 1;
    }

  lzma_action action = LZMA_RUN;
  s.next_in = NULL; s.avail_in = 0;
  s.next_out = outbuf; s.avail_out = sizeof outbuf;

  for (;;)
    {
      if (s.avail_in == 0 && action != LZMA_FINISH)
        {
          n = read (in_fd, inbuf, sizeof inbuf);
          if (n < 0)
            {
              if (errno == EINTR) continue;
              builtin_error ("read: %s", strerror (errno));
              lzma_end (&s);
              return 1;
            }
          s.next_in = inbuf;
          s.avail_in = (size_t) n;
          if (n == 0) action = LZMA_FINISH;
        }

      ret = lzma_code (&s, action);

      if (s.avail_out == 0 || ret == LZMA_STREAM_END)
        {
          size_t produced = sizeof outbuf - s.avail_out;
          unsigned char *p = outbuf;
          size_t left = produced;
          while (left > 0)
            {
              ssize_t w = write (out_fd, p, left);
              if (w < 0)
                {
                  if (errno == EINTR) continue;
                  builtin_error ("write: %s", strerror (errno));
                  lzma_end (&s);
                  return 1;
                }
              p += w;
              left -= (size_t) w;
            }
          s.next_out = outbuf;
          s.avail_out = sizeof outbuf;
        }

      if (ret == LZMA_STREAM_END) break;
      if (ret != LZMA_OK)
        {
          builtin_error ("lzma: code=%d", (int) ret);
          lzma_end (&s);
          return 1;
        }
    }

  lzma_end (&s);
  return 0;
}

/* ---- zstd (libzstd) ------------------------------------------------- */
static int
bz_codec_zstd (int in_fd, int out_fd, int encode, int level)
{
  unsigned char inbuf[BZ_BUFSZ], outbuf[BZ_BUFSZ];
  ssize_t n = 0;

  if (encode)
    {
      ZSTD_CStream *cctx = ZSTD_createCStream ();
      if (!cctx) { builtin_error ("zstd: createCStream"); return 1; }
      if (level < 0) level = ZSTD_CLEVEL_DEFAULT;
      ZSTD_CCtx_setParameter (cctx, ZSTD_c_compressionLevel, level);

      for (;;)
        {
          n = read (in_fd, inbuf, sizeof inbuf);
          if (n < 0)
            {
              if (errno == EINTR) continue;
              builtin_error ("read: %s", strerror (errno));
              ZSTD_freeCStream (cctx); return 1;
            }
          ZSTD_inBuffer in = { inbuf, (size_t) n, 0 };
          ZSTD_EndDirective mode = (n == 0) ? ZSTD_e_end : ZSTD_e_continue;

          int finished;
          do
            {
              ZSTD_outBuffer out = { outbuf, sizeof outbuf, 0 };
              size_t rem = ZSTD_compressStream2 (cctx, &out, &in, mode);
              if (ZSTD_isError (rem))
                {
                  builtin_error ("zstd compress: %s", ZSTD_getErrorName (rem));
                  ZSTD_freeCStream (cctx); return 1;
                }
              unsigned char *p = outbuf;
              size_t left = out.pos;
              while (left > 0)
                {
                  ssize_t w = write (out_fd, p, left);
                  if (w < 0)
                    {
                      if (errno == EINTR) continue;
                      builtin_error ("write: %s", strerror (errno));
                      ZSTD_freeCStream (cctx); return 1;
                    }
                  p += w; left -= (size_t) w;
                }
              finished = (mode == ZSTD_e_end) ? (rem == 0) : (in.pos == in.size);
            }
          while (!finished);

          if (n == 0) break;
        }
      ZSTD_freeCStream (cctx);
      return 0;
    }
  else
    {
      ZSTD_DStream *dctx = ZSTD_createDStream ();
      if (!dctx) { builtin_error ("zstd: createDStream"); return 1; }
      size_t remaining = 1;

      for (;;)
        {
          n = read (in_fd, inbuf, sizeof inbuf);
          if (n < 0)
            {
              if (errno == EINTR) continue;
              builtin_error ("read: %s", strerror (errno));
              ZSTD_freeDStream (dctx); return 1;
            }
          if (n == 0) break;
          ZSTD_inBuffer in = { inbuf, (size_t) n, 0 };
          ZSTD_outBuffer out;
          do
            {
              out = (ZSTD_outBuffer) { outbuf, sizeof outbuf, 0 };
              size_t rc = ZSTD_decompressStream (dctx, &out, &in);
              remaining = rc;
              if (ZSTD_isError (rc))
                {
                  builtin_error ("zstd decompress: %s", ZSTD_getErrorName (rc));
                  ZSTD_freeDStream (dctx); return 1;
                }
              unsigned char *p = outbuf;
              size_t left = out.pos;
              while (left > 0)
                {
                  ssize_t w = write (out_fd, p, left);
                  if (w < 0)
                    {
                      if (errno == EINTR) continue;
                      builtin_error ("write: %s", strerror (errno));
                      ZSTD_freeDStream (dctx); return 1;
                    }
                  p += w; left -= (size_t) w;
                }
            }
          while (in.pos < in.size || (out.pos == out.size && remaining != 0));
        }
      ZSTD_freeDStream (dctx);
      if (remaining) { builtin_error ("zstd: truncated stream"); return 1; }
      return 0;
    }
}

/* ---- bzip2 (libbz2) ------------------------------------------------- */
static int
bz_codec_bzip2 (int in_fd, int out_fd, int encode, int level)
{
  bz_stream s;
  unsigned char inbuf[BZ_BUFSZ], outbuf[BZ_BUFSZ];
  int ret;
  ssize_t n = 0;

  memset (&s, 0, sizeof s);   /* bzalloc/bzfree/opaque NULL → libc malloc */

  if (encode)
    {
      if (level < 1) level = 9;      /* blockSize100k must be 1..9 */
      if (level > 9) level = 9;
      ret = BZ2_bzCompressInit (&s, level, 0, 0);
      if (ret != BZ_OK)
        { builtin_error ("bzip2 compressInit: error %d", ret); return 1; }
    }
  else
    {
      ret = BZ2_bzDecompressInit (&s, 0, 0);
      if (ret != BZ_OK)
        { builtin_error ("bzip2 decompressInit: error %d", ret); return 1; }
    }

  for (;;)
    {
      if (s.avail_in == 0)
        {
          n = read (in_fd, inbuf, sizeof inbuf);
          if (n < 0)
            {
              if (errno == EINTR) continue;
              builtin_error ("read: %s", strerror (errno));
              (encode ? BZ2_bzCompressEnd : BZ2_bzDecompressEnd) (&s);
              return 1;
            }
          s.next_in = (char *) inbuf;
          s.avail_in = (unsigned int) n;
        }
      int action = (n == 0) ? BZ_FINISH : BZ_RUN;   /* encode side only */

      do
        {
          s.next_out = (char *) outbuf;
          s.avail_out = sizeof outbuf;
          ret = encode ? BZ2_bzCompress (&s, action) : BZ2_bzDecompress (&s);

          if (encode)
            {
              if (ret != BZ_RUN_OK && ret != BZ_FINISH_OK && ret != BZ_STREAM_END)
                {
                  builtin_error ("bzip2 compress: error %d", ret);
                  BZ2_bzCompressEnd (&s);
                  return 1;
                }
            }
          else
            {
              if (ret != BZ_OK && ret != BZ_STREAM_END)
                {
                  builtin_error ("bzip2 decompress: error %d", ret);
                  BZ2_bzDecompressEnd (&s);
                  return 1;
                }
            }

          size_t produced = sizeof outbuf - s.avail_out;
          if (produced > 0)
            {
              unsigned char *p = outbuf;
              size_t left = produced;
              while (left > 0)
                {
                  ssize_t w = write (out_fd, p, left);
                  if (w < 0)
                    {
                      if (errno == EINTR) continue;
                      builtin_error ("write: %s", strerror (errno));
                      (encode ? BZ2_bzCompressEnd : BZ2_bzDecompressEnd) (&s);
                      return 1;
                    }
                  p += w;
                  left -= (size_t) w;
                }
            }
        }
      while (s.avail_out == 0 && ret != BZ_STREAM_END);

      if (ret == BZ_STREAM_END)
        break;             /* single bzip2 stream is terminal */
      if (n == 0)
        break;
    }

  (encode ? BZ2_bzCompressEnd : BZ2_bzDecompressEnd) (&s);
  if (ret != BZ_STREAM_END) { builtin_error ("bzip2: truncated stream"); return 1; }
  return 0;
}

/* ---- bash builtin entry --------------------------------------------- */
int
zlib_builtin (WORD_LIST *list)
{
  int opt;
  int encode = 0;          /* default: decode */
  int level = -1;          /* default per format */
  enum bz_format fmt = BZ_GZIP;
  int explicit_format = 0;
  const char *path = NULL;
  int in_fd = -1;
  int close_in = 0;

  reset_internal_getopt ();
  /* Single-char flags. -1..-9 also valid (level shortcuts). */
  while ((opt = internal_getopt (list, "edzRf:0123456789")) != -1)
    {
      switch (opt)
        {
        case 'e': encode = 1; break;
        case 'd': encode = 0; break;
        case 'z': fmt = BZ_ZLIB;    explicit_format = 1; break;
        case 'R': fmt = BZ_DEFLATE; explicit_format = 1; break;
        case 'f':
          {
            const char *fname = list_optarg;
            if      (strcmp (fname, "gzip")    == 0) fmt = BZ_GZIP;
            else if (strcmp (fname, "xz")      == 0) fmt = BZ_XZ;
            else if (strcmp (fname, "lzma")    == 0) fmt = BZ_LZMA;
            else if (strcmp (fname, "zstd")    == 0) fmt = BZ_ZSTD;
            else if (strcmp (fname, "zlib")    == 0) fmt = BZ_ZLIB;
            else if (strcmp (fname, "deflate") == 0) fmt = BZ_DEFLATE;
            else if (strcmp (fname, "bzip2")   == 0) fmt = BZ_BZIP2;
            else if (strcmp (fname, "bz2")     == 0) fmt = BZ_BZIP2;
            else
              {
                builtin_error ("unknown format: %s (use gzip/xz/zstd/bzip2/zlib/deflate)", fname);
                return (EX_USAGE);
              }
            explicit_format = 1;
            break;
          }
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
          level = opt - '0';
          break;
        CASE_HELPOPT;
        default:
          builtin_usage ();
          return (EX_USAGE);
        }
    }
  list = loptend;

  /* Optional FILE arg. "-" or absent → stdin. */
  if (list != 0)
    {
      path = list->word->word;
      if (list->next != 0)
        {
          builtin_error ("at most one FILE argument is accepted");
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

  (void) explicit_format;  /* reserved for future "auto-detect from
                              filename" mode; keeps -Wunused quiet. */

  int rc;
  switch (fmt)
    {
    case BZ_GZIP:
    case BZ_ZLIB:
    case BZ_DEFLATE:
      rc = bz_codec_zlib (in_fd, STDOUT_FILENO, encode, level, fmt);
      break;
    case BZ_XZ:
    case BZ_LZMA:
      rc = bz_codec_xz   (in_fd, STDOUT_FILENO, encode, level, fmt);
      break;
    case BZ_ZSTD:
      rc = bz_codec_zstd (in_fd, STDOUT_FILENO, encode, level);
      break;
    case BZ_BZIP2:
      rc = bz_codec_bzip2 (in_fd, STDOUT_FILENO, encode, level);
      break;
    default:
      rc = 1;
    }

  if (close_in) close (in_fd);
  fflush (stdout);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

char *zlib_doc[] = {
  "Multi-format compression / decompression — wraps libz / liblzma /",
  "libzstd via FD-level read(2)/write(2). Output bytes flow through",
  "stdout (NUL-safe at the FD layer); pipe to binhex if you need to",
  "round-trip through a bash variable.",
  "",
  "Without -e: decode (default).",
  "With    -e: encode.",
  "",
  "Formats (-f NAME, default gzip):",
  "    gzip      RFC 1952 (the universal default)",
  "    xz        .xz container; auto-decodes .xz and legacy .lzma",
  "    lzma      legacy .lzma-alone stream",
  "    zstd      RFC 8478",
  "    bzip2     .bz2 (alias bz2); single-stream",
  "    zlib      RFC 1950 (raw zlib wrap, NOT gzip)",
  "    deflate   RFC 1951 (raw bit stream, no wrap)",
  "  Shortcuts: -z = -f zlib, -R = -f deflate.",
  "  Gzip decode handles concatenated (multi-member) .gz files.",
  "",
  "Compression levels: -1 (fastest) to -9 (max) for gzip/zlib/xz.",
  "  zstd accepts -1..-22 (use -f zstd -N).",
  "",
  "Examples:",
  "    zlib < foo.gz > foo                 # gunzip-equivalent",
  "    zlib -e -1 < foo > foo.gz           # fastest gzip",
  "    zlib -f xz < foo.xz > foo",
  "    zlib -f lzma < foo.lzma > foo",
  "    zlib -e -f zstd -3 < foo > foo.zst",
  "",
  "See /docs/bash/COMPRESSION-LIMIT.txt for the ceiling this breaks.",
  (char *) NULL
};

struct builtin zlib_struct = {
  "zlib",
  zlib_builtin,
  BUILTIN_ENABLED,
  zlib_doc,
  "zlib [-e|-d] [-f FORMAT|-z|-R] [-N] [FILE]",
  0
};
