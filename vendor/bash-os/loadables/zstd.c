/* SPDX-License-Identifier: MIT */
/* zstd.c — zstd(1) as a bash builtin, using the linked libzstd.
 *
 * The linked library also works in a fully static executable. An explicit
 * BASHOS_ZSTD_LIB override loads a compatible library with dlopen/dlsym;
 * an unavailable override fails without affecting the shell. Files
 * stream through fixed-size buffers. Decoder windows are limited to 128 MiB;
 * named output is published atomically only after the entire stream succeeds.
 *
 *   zstd [-1..-19] [-d] [-c] [-f] [-k] [--rm] [-q] [-o OUT] FILE...
 *   zstdcat [FILE...]                   = zstd -dcf  (loadables/zstdcat.c)
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

#define ZS_CHUNK (128 * 1024)
#define ZS_WINDOW_LOG_MAX 27
#define ZS_DEFAULT_LEVEL 3

/* Use the linked library by default, including in static executables. */
typedef ZSTD_inBuffer zs_inbuf;
typedef ZSTD_outBuffer zs_outbuf;
typedef ZSTD_DStream zs_dstream;
static struct {
  void *handle;
  int loaded;
  ZSTD_CStream *(*createCStream) (void);
  size_t (*initCStream) (ZSTD_CStream *, int);
  size_t (*compressStream) (ZSTD_CStream *, zs_outbuf *, zs_inbuf *);
  size_t (*endStream) (ZSTD_CStream *, zs_outbuf *);
  size_t (*freeCStream) (ZSTD_CStream *);
  unsigned (*isError) (size_t);
  const char *(*getErrorName) (size_t);
  zs_dstream *(*createDStream) (void);
  size_t (*initDStream) (zs_dstream *);
  size_t (*decompressStream) (zs_dstream *, zs_outbuf *, zs_inbuf *);
  size_t (*freeDStream) (zs_dstream *);
  size_t (*DCtx_setParameter) (ZSTD_DCtx *, ZSTD_dParameter, int);
  size_t (*CCtx_setParameter) (ZSTD_CCtx *, ZSTD_cParameter, int);
} zs;

static int
zs_load (void)
{
  const char *lib, *err; void *h;
  if (zs.loaded) return 0;
  lib = getenv ("BASHOS_ZSTD_LIB");             /* an override, and how the tests simulate absence */
  if (lib == NULL || *lib == 0)
    {
      zs.createCStream = ZSTD_createCStream;
      zs.initCStream = ZSTD_initCStream;
      zs.compressStream = ZSTD_compressStream;
      zs.endStream = ZSTD_endStream;
      zs.freeCStream = ZSTD_freeCStream;
      zs.isError = ZSTD_isError;
      zs.getErrorName = ZSTD_getErrorName;
      zs.createDStream = ZSTD_createDStream;
      zs.initDStream = ZSTD_initDStream;
      zs.decompressStream = ZSTD_decompressStream;
      zs.freeDStream = ZSTD_freeDStream;
      zs.DCtx_setParameter = ZSTD_DCtx_setParameter;
      zs.CCtx_setParameter = ZSTD_CCtx_setParameter;
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
  ZS_SYM (createCStream, "ZSTD_createCStream");
  ZS_SYM (initCStream, "ZSTD_initCStream");
  ZS_SYM (compressStream, "ZSTD_compressStream");
  ZS_SYM (endStream, "ZSTD_endStream");
  ZS_SYM (freeCStream, "ZSTD_freeCStream");
  ZS_SYM (isError, "ZSTD_isError");
  ZS_SYM (getErrorName, "ZSTD_getErrorName");
  ZS_SYM (createDStream, "ZSTD_createDStream");
  ZS_SYM (initDStream, "ZSTD_initDStream");
  ZS_SYM (decompressStream, "ZSTD_decompressStream");
  ZS_SYM (freeDStream, "ZSTD_freeDStream");
  ZS_SYM (DCtx_setParameter, "ZSTD_DCtx_setParameter");
  ZS_SYM (CCtx_setParameter, "ZSTD_CCtx_setParameter");
#undef ZS_SYM
  zs.handle = h;
  zs.loaded = 1;
  return 0;
}

static int
zs_write_all (int fd, const unsigned char *b, size_t n, const char *name)
{
  while (n)
    {
      ssize_t w = write (fd, b, n);
      if (w < 0 && errno == EINTR) continue;
      if (w <= 0)
        { builtin_error ("%s: write: %s", name, strerror (w == 0 ? EIO : errno)); return -1; }
      b += w; n -= (size_t) w;
    }
  return 0;
}

/* Fixed input/output buffers plus libzstd's level-dependent context/window.
   Never allocate from a file size or a frame's declared content size. */
static int
zs_frame_magic (const unsigned char *p)
{
  return (p[0] == 0x28 && p[1] == 0xb5 && p[2] == 0x2f && p[3] == 0xfd)
         || ((p[0] & 0xf0) == 0x50 && p[1] == 0x2a && p[2] == 0x4d && p[3] == 0x18);
}

static int
zs_stream (int input, int output, int decompress, int level, int pass_through, int no_content_size,
           const char *src, const char *target)
{
  unsigned char *in = NULL, *out = NULL;
  ZSTD_CStream *cs = NULL; zs_dstream *ds = NULL;
  size_t r = 1, pending = 0;
  int rc = -1, eof = 0, frame_start = 1, raw = 0;
  in = malloc (ZS_CHUNK); out = malloc (ZS_CHUNK);
  if (!in || !out) goto nomem;
  if (decompress)
    {
      ds = zs.createDStream ();
      if (!ds) goto nomem;
      r = zs.initDStream (ds);
      if (zs.isError (r)) goto liberr;
      r = zs.DCtx_setParameter (ds, ZSTD_d_windowLogMax, ZS_WINDOW_LOG_MAX);
    }
  else
    {
      cs = zs.createCStream ();
      if (!cs) goto nomem;
      r = zs.initCStream (cs, level);
      if (!zs.isError (r) && no_content_size)
        r = zs.CCtx_setParameter (cs, ZSTD_c_contentSizeFlag, 0);
    }
  if (zs.isError (r)) goto liberr;
  r = 1;                              /* Empty compressed input is incomplete. */
  for (;;)
    {
      ssize_t n;
      zs_inbuf ib;
      do n = read (input, in + pending, ZS_CHUNK - pending); while (n < 0 && errno == EINTR);
      if (n < 0) { builtin_error ("%s: read: %s", src, strerror (errno)); goto done; }
      eof = n == 0;
      if (eof && pending == 0) break;
      ib.src = in; ib.size = pending + (size_t) n; ib.pos = 0;
      pending = 0;
      for (;;)
        {
          zs_outbuf ob = { out, ZS_CHUNK, 0 };
          size_t before = ib.pos;
          if (decompress && pass_through && frame_start && !raw)
            {
              size_t left = ib.size - ib.pos;
              /* A pipe may split the magic anywhere. Retain the undecided
                 prefix; never fall back after a recognized frame has begun. */
              if (left < 4 && !eof)
                {
                  memmove (in, in + ib.pos, left);
                  pending = left;
                  break;
                }
              if (left < 4 || !zs_frame_magic (in + ib.pos)) raw = 1;
              frame_start = 0;
            }
          if (raw)
            {
              if (zs_write_all (output, in + ib.pos, ib.size - ib.pos, target) < 0) goto done;
              break;
            }
          r = decompress ? zs.decompressStream (ds, &ob, &ib) : zs.compressStream (cs, &ob, &ib);
          if (zs.isError (r)) goto liberr;
          if (zs_write_all (output, out, ob.pos, target) < 0) goto done;
          if (decompress && r == 0) frame_start = 1;
          if (ib.pos == ib.size && (!decompress || ob.pos < ob.size || r == 0)) break;
          if (ib.pos == before && ob.pos == 0)
            {
              if (ib.pos == ib.size) break; /* Decoder needs more input. */
              builtin_error ("%s: codec made no progress", src); goto done;
            }
        }
    }
  if (decompress)
    {
      if (!raw && r != 0) { builtin_error ("%s: truncated input, the last frame is incomplete", src); goto done; }
    }
  else
    do
      {
        zs_outbuf ob = { out, ZS_CHUNK, 0 };
        r = zs.endStream (cs, &ob);
        if (zs.isError (r)) goto liberr;
        if (zs_write_all (output, out, ob.pos, target) < 0) goto done;
        if (r && ob.pos == 0) { builtin_error ("%s: encoder made no progress", src); goto done; }
      }
    while (r);
  rc = 0;
  goto done;
nomem:
  builtin_error ("%s: out of memory", src);
  goto done;
liberr:
  builtin_error ("%s: %s", src, zs.getErrorName (r));
done:
  if (ds) zs.freeDStream (ds);
  if (cs) zs.freeCStream (cs);
  free (in); free (out);
  return rc;
}

struct zs_opts { int level, decompress, to_stdout, force, remove, quiet, no_content_size; const char *outname; };

/* Compress or decompress one input to its target. Returns 0 or -1. */
static int
zs_one (const char *src, const struct zs_opts *o)
{
  int in_fd = -1, out_fd = -1, from_stdin = strcmp (src, "-") == 0;
  int to_stdout = o->to_stdout || (from_stdin && !o->outname)
                  || (o->outname && strcmp (o->outname, "-") == 0);
  char target[PATH_MAX + 8], temp[PATH_MAX + 32] = "";
  struct stat st, dst, source_path; int rc = -1, n;

  if (!to_stdout)
    {
      if (o->outname) n = snprintf (target, sizeof target, "%s", o->outname);
      else if (o->decompress)
        {
          size_t l = strlen (src);
          if (l <= 4 || strcmp (src + l - 4, ".zst") != 0)
            { builtin_error ("%s: unknown suffix, cannot name the target (use -o or -c)", src); return -1; }
          if (l - 4 >= sizeof target) { builtin_error ("%s: target name too long", src); return -1; }
          n = snprintf (target, sizeof target, "%.*s", (int) (l - 4), src);
        }
      else n = snprintf (target, sizeof target, "%s.zst", src);
      if (n < 0 || (size_t) n >= sizeof target)
        { builtin_error ("%s: target name too long", src); return -1; }
      if (strcmp (target, src) == 0) { builtin_error ("%s: target is the source", src); return -1; }
    }

  in_fd = from_stdin ? 0 : open (src, O_RDONLY);
  if (in_fd < 0) { builtin_error ("%s: %s", src, strerror (errno)); return -1; }
  if (fstat (in_fd, &st) < 0) { builtin_error ("%s: %s", src, strerror (errno)); goto out; }
  if (!from_stdin && lstat (src, &source_path) < 0)
    { builtin_error ("%s: %s", src, strerror (errno)); goto out; }
  if (!from_stdin && S_ISDIR (st.st_mode)) { builtin_error ("%s: is a directory", src); goto out; }
  if (!to_stdout)
    {
      if (stat (target, &dst) == 0 && dst.st_dev == st.st_dev && dst.st_ino == st.st_ino)
        { builtin_error ("%s: target is the source", target); goto out; }
      if (lstat (target, &dst) == 0)
        {
          if (!o->force) { builtin_error ("%s: already exists; use -f to overwrite", target); goto out; }
          if (!S_ISREG (dst.st_mode)) { builtin_error ("%s: target is not a regular file", target); goto out; }
        }
      else if (errno != ENOENT) { builtin_error ("%s: %s", target, strerror (errno)); goto out; }
      snprintf (temp, sizeof temp, "%s.tmp.XXXXXX", target);
      out_fd = mkstemp (temp);
      if (out_fd < 0) { builtin_error ("%s: %s", target, strerror (errno)); temp[0] = 0; goto out; }
    }
  if (zs_stream (in_fd, to_stdout ? 1 : out_fd, o->decompress, o->level,
                 o->force && (o->to_stdout || (from_stdin && !o->outname)),
                 o->no_content_size,
                 src, to_stdout ? "stdout" : target) < 0) goto out;
  /* Close input before publication/removal so delayed input errors also keep
     the old destination and source. Never close the shell's stdin. */
  if (!from_stdin)
    {
      int fd = in_fd; in_fd = -1;
      if (close (fd) < 0) { builtin_error ("%s: close: %s", src, strerror (errno)); goto out; }
    }
  if (!to_stdout)
    {
      struct timespec ts[2];
      mode_t mode;
      if (from_stdin)
        { mode_t mask = umask (0); umask (mask); mode = 0666 & ~mask; }
      else mode = st.st_mode & 07777;
      if (fchmod (out_fd, mode) < 0) { builtin_error ("%s: mode: %s", target, strerror (errno)); goto out; }
      ts[0] = st.st_atim; ts[1] = st.st_mtim;
      if (!from_stdin && futimens (out_fd, ts) < 0) { builtin_error ("%s: times: %s", target, strerror (errno)); goto out; }
      {
        int fd = out_fd; out_fd = -1;
        if (close (fd) < 0) { builtin_error ("%s: close: %s", target, strerror (errno)); goto out; }
      }
      /* link provides an atomic no-clobber commit even if a target appeared
         during the stream. rename replaces an old target only with -f. */
      if ((o->force ? rename (temp, target) : link (temp, target)) < 0)
        {
          if (errno == EEXIST) builtin_error ("%s: already exists; use -f to overwrite", target);
          else builtin_error ("%s: publish: %s", target, strerror (errno));
          goto out;
        }
      if (!o->force && unlink (temp) < 0)
        { builtin_error ("%s: temporary file cleanup: %s", target, strerror (errno)); goto out; }
      temp[0] = 0;
      if (o->remove && !from_stdin)
        {
          if (lstat (src, &dst) < 0 || dst.st_dev != source_path.st_dev || dst.st_ino != source_path.st_ino)
            { builtin_error ("%s: source changed; not removed", src); goto out; }
          if (unlink (src) < 0) { builtin_error ("%s: not removed: %s", src, strerror (errno)); goto out; }
        }
    }
  rc = 0;
out:
  if (!from_stdin && in_fd >= 0) close (in_fd);
  if (out_fd >= 0) close (out_fd);
  if (temp[0]) unlink (temp);
  return rc;
}

/* The work, shared with zstdcat. */
int
bashos_zstd_run (WORD_LIST *list, int cat_mode)
{
  struct zs_opts o = { ZS_DEFAULT_LEVEL, cat_mode, cat_mode, cat_mode, 0, 0, 0, NULL };
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
      if (strcmp (w, "--no-content-size") == 0) { o.no_content_size = 1; continue; }
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
            o.to_stdout = 0;
            done = 1; break;
          default: builtin_error ("-%c: invalid option", *p); builtin_usage (); return EX_USAGE;
          }
    }
  for (WORD_LIST *m = l; m; m = m->next) nfiles++;
  if (o.outname && nfiles > 1) { builtin_error ("-o names one target; there are %d inputs", nfiles); return EX_USAGE; }
  if (zs_load () < 0) return EXECUTION_FAILURE;

  if (nfiles == 0 && zs_one ("-", &o) < 0) status = EXECUTION_FAILURE;
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
  "FILE. Uses linked libzstd (BASHOS_ZSTD_LIB overrides it at run time).",
  "The source is kept unless --rm, an existing",
  "target is not overwritten without -f, and the target takes the source's",
  "mode and modification time. \"-\" reads stdin and writes stdout.",
  "With no FILE, read standard input. -dcf passes unrecognized input through.",
  "",
  "  -1 .. -19    compression level (default 3)",
  "  -d           decompress",
  "  -c           write to standard output, keep the source",
  "  -o OUT       name the target (one input)",
  "  -f           overwrite an existing target",
  "  -k, --rm     keep (the default) or remove the source after success",
  "  -q, -v       accepted; nothing is printed but errors",
  "  --no-content-size  omit the original size from compressed frame headers",
  "",
  "Streams use bounded memory; decoder windows are limited to 128 MiB.",
  "Named output is published atomically after successful completion.",
  "Exit status: 0, or 1 if any file failed.",
  (char *)NULL
};

struct builtin zstd_struct = {
  "zstd", zstd_builtin, BUILTIN_ENABLED, zstd_doc, "zstd [-1..-19] [-d] [-c] [-f] [-k|--rm] [-o OUT] [FILE...]", 0
};
