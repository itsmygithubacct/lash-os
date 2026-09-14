/* SPDX-License-Identifier: MIT */
/* zstd.c — zstd(1) as a bash builtin, using the linked libzstd.
 *
 * The linked library also works in a fully static executable. An explicit
 * BASHOS_ZSTD_LIB override loads a compatible library with dlopen/dlsym;
 * an unavailable override fails without affecting the shell. Files
 * are read whole (256 MiB cap); decompression is streamed into a growing
 * buffer (1 GiB cap), so a frame's declared size is never trusted for an
 * allocation.
 *
 *   zstd [-1..-19] [-d] [-c] [-f] [-k] [--rm] [-q] [-o OUT] FILE...
 *   zstdcat FILE...                     = zstd -dc   (loadables/zstdcat.c)
 *
 * The subset of zstd(1) a script uses, with zstd(1)'s semantics: the source
 * is kept unless --rm; an existing target is not overwritten without -f;
 * FILE.zst is the target of FILE and FILE that of FILE.zst; "-" is stdin to
 * stdout; -c writes to stdout; -o names the target of a single input; the
 * target gets the source's mode and mtime. Exit 0, or 1 if any file failed.
 *
 * Copyright (c) 2026 bash_linux contributors
 * MIT License — full text in the repository's LICENSE file.
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <zstd.h>
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>
#include "loadables.h"

#define ZS_MAX_INPUT   (256UL * 1024 * 1024)
#define ZS_MAX_OUTPUT  (1024UL * 1024 * 1024)
#define ZS_DEFAULT_LEVEL 3

/* Use the linked library by default, including in static executables. */
typedef ZSTD_inBuffer zs_inbuf;
typedef ZSTD_outBuffer zs_outbuf;
typedef ZSTD_DStream zs_dstream;
static struct {
  void *handle;
  int loaded;
  size_t (*compress) (void *, size_t, const void *, size_t, int);
  size_t (*compressBound) (size_t);
  unsigned (*isError) (size_t);
  const char *(*getErrorName) (size_t);
  zs_dstream *(*createDStream) (void);
  size_t (*initDStream) (zs_dstream *);
  size_t (*decompressStream) (zs_dstream *, zs_outbuf *, zs_inbuf *);
  size_t (*freeDStream) (zs_dstream *);
  size_t (*DStreamOutSize) (void);
} zs;

static int
zs_load (void)
{
  const char *lib, *err; void *h;
  if (zs.loaded) return 0;
  lib = getenv ("BASHOS_ZSTD_LIB");             /* an override, and how the tests simulate absence */
  if (lib == NULL || *lib == 0)
    {
      zs.compress = ZSTD_compress;
      zs.compressBound = ZSTD_compressBound;
      zs.isError = ZSTD_isError;
      zs.getErrorName = ZSTD_getErrorName;
      zs.createDStream = ZSTD_createDStream;
      zs.initDStream = ZSTD_initDStream;
      zs.decompressStream = ZSTD_decompressStream;
      zs.freeDStream = ZSTD_freeDStream;
      zs.DStreamOutSize = ZSTD_DStreamOutSize;
      zs.loaded = 1;
      return 0;
    }
  h = dlopen (lib, RTLD_NOW | RTLD_LOCAL);
  if (h == NULL)
    {
      err = dlerror ();
      builtin_error ("%s: not available (%s); zstd needs libzstd at run time", lib, err ? err : "dlopen failed");
      return -1;
    }
#define ZS_SYM(field, name) do { *(void **) &zs.field = dlsym (h, name); \
    if (zs.field == NULL) { builtin_error ("%s: %s missing from the library", lib, name); dlclose (h); return -1; } } while (0)
  ZS_SYM (compress, "ZSTD_compress");
  ZS_SYM (compressBound, "ZSTD_compressBound");
  ZS_SYM (isError, "ZSTD_isError");
  ZS_SYM (getErrorName, "ZSTD_getErrorName");
  ZS_SYM (createDStream, "ZSTD_createDStream");
  ZS_SYM (initDStream, "ZSTD_initDStream");
  ZS_SYM (decompressStream, "ZSTD_decompressStream");
  ZS_SYM (freeDStream, "ZSTD_freeDStream");
  ZS_SYM (DStreamOutSize, "ZSTD_DStreamOutSize");
#undef ZS_SYM
  zs.handle = h;
  zs.loaded = 1;
  return 0;
}

/* Read everything from FD into a malloc'd buffer, capped. */
static int
zs_read_all (int fd, const char *name, unsigned char **out, size_t *outlen)
{
  struct stat st; size_t cap = 65536, n = 0; unsigned char *b, *nb; ssize_t r;
  if (fstat (fd, &st) == 0 && S_ISREG (st.st_mode) && st.st_size > 0)
    {
      if ((unsigned long long) st.st_size > ZS_MAX_INPUT)
        { builtin_error ("%s: larger than the %lu MiB this builtin reads whole", name, ZS_MAX_INPUT >> 20); return -1; }
      cap = (size_t) st.st_size + 1;
    }
  b = malloc (cap);
  if (b == NULL) { builtin_error ("%s: out of memory", name); return -1; }
  for (;;)
    {
      if (n == cap)
        {
          if (cap >= ZS_MAX_INPUT) { builtin_error ("%s: larger than the %lu MiB this builtin reads whole", name, ZS_MAX_INPUT >> 20); free (b); return -1; }
          cap = cap * 2 > ZS_MAX_INPUT ? ZS_MAX_INPUT : cap * 2;
          nb = realloc (b, cap);
          if (nb == NULL) { builtin_error ("%s: out of memory", name); free (b); return -1; }
          b = nb;
        }
      r = read (fd, b + n, cap - n);
      if (r < 0) { if (errno == EINTR) continue; builtin_error ("%s: read: %s", name, strerror (errno)); free (b); return -1; }
      if (r == 0) break;
      n += (size_t) r;
    }
  *out = b; *outlen = n;
  return 0;
}

static int
zs_write_all (int fd, const unsigned char *b, size_t n, const char *name)
{
  while (n)
    {
      ssize_t w = write (fd, b, n);
      if (w < 0) { if (errno == EINTR) continue; builtin_error ("%s: write: %s", name, strerror (errno)); return -1; }
      b += w; n -= (size_t) w;
    }
  return 0;
}

static int
zs_compress_buf (const unsigned char *in, size_t len, int level, unsigned char **out, size_t *outlen, const char *name)
{
  size_t bound = zs.compressBound (len), r; unsigned char *b;
  if (zs.isError (bound)) { builtin_error ("%s: %s", name, zs.getErrorName (bound)); return -1; }
  b = malloc (bound ? bound : 1);
  if (b == NULL) { builtin_error ("%s: out of memory", name); return -1; }
  r = zs.compress (b, bound, in, len, level);
  if (zs.isError (r)) { builtin_error ("%s: %s", name, zs.getErrorName (r)); free (b); return -1; }
  *out = b; *outlen = r;
  return 0;
}

/* Stream every frame of IN into a growing buffer. The frame header's content
   size is not consulted for the allocation; the cap bounds it. */
static int
zs_decompress_buf (const unsigned char *in, size_t len, unsigned char **out, size_t *outlen, const char *name)
{
  zs_dstream *ds; size_t cap, n = 0, r = 1, chunk; unsigned char *b, *nb; zs_inbuf ib;
  ds = zs.createDStream ();
  if (ds == NULL) { builtin_error ("%s: out of memory", name); return -1; }
  r = zs.initDStream (ds);
  if (zs.isError (r)) { builtin_error ("%s: %s", name, zs.getErrorName (r)); zs.freeDStream (ds); return -1; }
  chunk = zs.DStreamOutSize (); if (chunk < 65536) chunk = 65536;
  cap = chunk;
  b = malloc (cap);
  if (b == NULL) { builtin_error ("%s: out of memory", name); zs.freeDStream (ds); return -1; }
  ib.src = in; ib.size = len; ib.pos = 0;
  while (ib.pos < len)
    {
      zs_outbuf ob; size_t before = ib.pos;
      if (n == cap)
        {
          if (cap >= ZS_MAX_OUTPUT) { builtin_error ("%s: decompressed data exceeds the %lu MiB cap", name, ZS_MAX_OUTPUT >> 20); goto fail; }
          cap = cap * 2 > ZS_MAX_OUTPUT ? ZS_MAX_OUTPUT : cap * 2;
          nb = realloc (b, cap);
          if (nb == NULL) { builtin_error ("%s: out of memory", name); goto fail; }
          b = nb;
        }
      ob.dst = b + n; ob.size = cap - n; ob.pos = 0;
      r = zs.decompressStream (ds, &ob, &ib);
      if (zs.isError (r)) { builtin_error ("%s: %s", name, zs.getErrorName (r)); goto fail; }
      n += ob.pos;
      if (ob.pos == 0 && ib.pos == before && n < cap)
        { builtin_error ("%s: decoder made no progress", name); goto fail; }
    }
  if (r != 0) { builtin_error ("%s: truncated input, the last frame is incomplete", name); goto fail; }
  zs.freeDStream (ds);
  *out = b; *outlen = n;
  return 0;
fail:
  zs.freeDStream (ds); free (b);
  return -1;
}

struct zs_opts { int level, decompress, to_stdout, force, remove, quiet; const char *outname; };

/* Compress or decompress one input to its target. Returns 0 or -1. */
static int
zs_one (const char *src, const struct zs_opts *o)
{
  int in_fd = -1, out_fd = -1, from_stdin = strcmp (src, "-") == 0, to_stdout = o->to_stdout || from_stdin;
  unsigned char *in = NULL, *out = NULL; size_t inlen = 0, outlen = 0;
  char target[PATH_MAX + 8]; struct stat st; int rc = -1;

  if (!to_stdout)
    {
      if (o->outname) snprintf (target, sizeof target, "%s", o->outname);
      else if (o->decompress)
        {
          size_t l = strlen (src);
          if (l <= 4 || strcmp (src + l - 4, ".zst") != 0)
            { builtin_error ("%s: unknown suffix, cannot name the target (use -o or -c)", src); return -1; }
          snprintf (target, sizeof target, "%.*s", (int) (l - 4), src);
        }
      else snprintf (target, sizeof target, "%s.zst", src);
      if (strcmp (target, src) == 0) { builtin_error ("%s: target is the source", src); return -1; }
    }

  in_fd = from_stdin ? 0 : open (src, O_RDONLY);
  if (in_fd < 0) { builtin_error ("%s: %s", src, strerror (errno)); return -1; }
  if (fstat (in_fd, &st) < 0) { builtin_error ("%s: %s", src, strerror (errno)); goto out; }
  if (!from_stdin && S_ISDIR (st.st_mode)) { builtin_error ("%s: is a directory", src); goto out; }
  if (zs_read_all (in_fd, src, &in, &inlen) < 0) goto out;

  if (o->decompress ? zs_decompress_buf (in, inlen, &out, &outlen, src) : zs_compress_buf (in, inlen, o->level, &out, &outlen, src))
    goto out;

  if (to_stdout)
    {
      if (zs_write_all (1, out, outlen, "stdout") < 0) goto out;
    }
  else
    {
      out_fd = open (target, O_WRONLY | O_CREAT | (o->force ? O_TRUNC : O_EXCL), 0600);
      if (out_fd < 0)
        {
          if (errno == EEXIST) builtin_error ("%s: already exists; use -f to overwrite", target);
          else builtin_error ("%s: %s", target, strerror (errno));
          goto out;
        }
      if (zs_write_all (out_fd, out, outlen, target) < 0) { unlink (target); goto out; }
      /* the target takes the source's mode and times, as zstd(1) does */
      fchmod (out_fd, st.st_mode & 07777);
      {
        struct timespec ts[2]; ts[0] = st.st_atim; ts[1] = st.st_mtim;
        futimens (out_fd, ts);
      }
      if (close (out_fd) < 0) { builtin_error ("%s: close: %s", target, strerror (errno)); out_fd = -1; unlink (target); goto out; }
      out_fd = -1;
      if (o->remove && unlink (src) < 0)
        builtin_error ("%s: not removed: %s", src, strerror (errno));
    }
  rc = 0;
out:
  if (in_fd > 0) close (in_fd);
  if (out_fd >= 0) close (out_fd);
  free (in); free (out);
  return rc;
}

/* The work, shared with zstdcat. */
int
bashos_zstd_run (WORD_LIST *list, int cat_mode)
{
  struct zs_opts o = { ZS_DEFAULT_LEVEL, cat_mode, cat_mode, 0, 0, 0, NULL };
  WORD_LIST *l; int status = EXECUTION_SUCCESS, nfiles = 0;

  for (l = list; l; l = l->next)
    {
      char *w = l->word->word, *p; int done = 0;
      if (w[0] != '-' || w[1] == 0) break;
      if (strcmp (w, "--") == 0) { l = l->next; break; }
      if (strcmp (w, "--rm") == 0) { o.remove = 1; continue; }
      if (strcmp (w, "--keep") == 0) { o.remove = 0; continue; }
      if (strcmp (w, "--force") == 0) { o.force = 1; continue; }
      if (strcmp (w, "--stdout") == 0) { o.to_stdout = 1; continue; }
      if (strcmp (w, "--decompress") == 0 || strcmp (w, "--uncompress") == 0) { o.decompress = 1; continue; }
      if (strcmp (w, "--compress") == 0) { o.decompress = 0; continue; }
      if (strcmp (w, "--quiet") == 0) { o.quiet = 1; continue; }
      if (w[1] == '-') { builtin_error ("%s: invalid option", w); builtin_usage (); return EX_USAGE; }
      if (w[1] >= '0' && w[1] <= '9')
        {
          char *end; long lv = strtol (w + 1, &end, 10);
          if (*end || lv < 1 || lv > 19) { builtin_error ("%s: compression level must be 1..19", w); return EX_USAGE; }
          o.level = (int) lv; continue;
        }
      for (p = w + 1; *p && !done; p++)
        switch (*p)
          {
          case 'd': o.decompress = 1; break;
          case 'z': o.decompress = 0; break;
          case 'c': o.to_stdout = 1; break;
          case 'f': o.force = 1; break;
          case 'k': o.remove = 0; break;
          case 'q': o.quiet = 1; break;
          case 'v': break;
          case 'o':
            if (p[1]) o.outname = p + 1;
            else if (l->next) { l = l->next; o.outname = l->word->word; }
            else { builtin_error ("-o: option requires an argument"); builtin_usage (); return EX_USAGE; }
            done = 1; break;
          default: builtin_error ("-%c: invalid option", *p); builtin_usage (); return EX_USAGE;
          }
    }
  for (WORD_LIST *m = l; m; m = m->next) nfiles++;
  if (nfiles == 0) { builtin_error ("no input file (use - for stdin)"); builtin_usage (); return EX_USAGE; }
  if (o.outname && nfiles > 1) { builtin_error ("-o names one target; there are %d inputs", nfiles); return EX_USAGE; }
  if (zs_load () < 0) return EXECUTION_FAILURE;

  for (; l; l = l->next)
    if (zs_one (l->word->word, &o) < 0) status = EXECUTION_FAILURE;
  if (fflush (stdout) == EOF) status = EXECUTION_FAILURE;
  return status;
}

int
zstd_builtin (WORD_LIST *list)
{
  return bashos_zstd_run (list, 0);
}

char *zstd_doc[] = {
  "Compress or decompress files with zstd.",
  "",
  "Compresses each FILE to FILE.zst, or with -d decompresses FILE.zst to",
  "FILE. libzstd is loaded at run time (libzstd.so.1); without it, zstd",
  "reports that and fails. The source is kept unless --rm, an existing",
  "target is not overwritten without -f, and the target takes the source's",
  "mode and modification time. \"-\" reads stdin and writes stdout.",
  "",
  "  -1 .. -19    compression level (default 3)",
  "  -d           decompress",
  "  -c           write to standard output, keep the source",
  "  -o OUT       name the target (one input)",
  "  -f           overwrite an existing target",
  "  -k, --rm     keep (the default) or remove the source after success",
  "  -q, -v       accepted; nothing is printed but errors",
  "",
  "Files are read whole, up to 256 MiB; decompressed data up to 1 GiB.",
  "Exit status: 0, or 1 if any file failed.",
  (char *)NULL
};

struct builtin zstd_struct = {
  "zstd", zstd_builtin, BUILTIN_ENABLED, zstd_doc, "zstd [-1..-19] [-d] [-c] [-f] [-k|--rm] [-o OUT] FILE...", 0
};
