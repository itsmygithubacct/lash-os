/* SPDX-License-Identifier: MIT */
/* rngseed.c — credit and refresh the kernel random seed. bash-os loadable (MIT).
 *
 * Why: this SoC has no hardware RNG, so the kernel CRNG initialises only from
 * interrupt timing — 3 to 13 s on a quiet boot — and anything that needs real
 * randomness before then blocks (dropbear's ed25519 host key, on first boot).
 * A seed saved from an INITIALISED pool and credited back on the next boot
 * lets the CRNG initialise at once, so the wait is paid on the first boot only.
 *
 * The seedrng convention this follows, and why each verb satisfies it:
 *   - a seed may be CREDITED only if it was written by a process whose pool
 *     was initialised. `save` uses a BLOCKING getrandom(2), so it waits for
 *     exactly that before writing.
 *   - a seed is never used twice. `load` replaces the file the moment it is
 *     credited. The credit itself initialises the pool, so the replacement is
 *     drawn from an initialised pool and is creditable next boot. If the pool
 *     is somehow still not ready, the spent seed is REMOVED rather than
 *     rewritten with weak bytes; `save` writes a fresh one later.
 *
 *   rngseed load FILE    credit FILE (32..4096 bytes; 512 expected), refresh it.
 *                        A missing FILE is the first boot: one line to stderr,
 *                        exit 0. Never blocks — safe from PID 1's boot path.
 *   rngseed save FILE    512 bytes from a BLOCKING getrandom(2) -> FILE.
 *
 * FILE is written 0600 to a temp name in the same directory, fsynced, renamed
 * over, and the directory fsynced, so a power cut leaves the old seed or the
 * new one — never a torn file.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <config.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <linux/random.h>
#include "loadables.h"
#include "bashgetopt.h"

#define SEED_LEN 512		/* what save writes, what load expects */
#define SEED_MIN 32
#define SEED_MAX 4096

/* Kernel pool size in bits: a credit must not exceed it. If the sysctl is
   unreadable the kernel clamps the credit itself, so ask for the full amount. */
static int
pool_bits (int want)
{
  FILE *f = fopen ("/proc/sys/kernel/random/poolsize", "r");
  int bits = 0;
  if (f)
    {
      if (fscanf (f, "%d", &bits) != 1) bits = 0;
      fclose (f);
    }
  return (bits > 0 && bits < want) ? bits : want;
}

/* Read up to SEED_MAX bytes. Returns the count; -1 on error with *missing set
   when the file simply does not exist (the first boot, not a failure). */
static int
read_seed (const char *path, unsigned char *buf, int *missing)
{
  *missing = 0;
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) { if (errno == ENOENT) *missing = 1; return -1; }
  int n = 0;
  while (n < SEED_MAX)
    {
      ssize_t r = read (fd, buf + n, SEED_MAX - n);
      if (r < 0) { if (errno == EINTR) continue; close (fd); return -1; }
      if (r == 0) break;
      n += (int) r;
    }
  close (fd);
  return n;
}

/* Atomic write: temp in the same dir, 0600 regardless of umask, fsync, rename,
   then fsync the directory so the rename survives a power cut too. */
static int
write_seed (const char *path, const unsigned char *buf, int n)
{
  char tmp[PATH_MAX], dir[PATH_MAX];
  if (snprintf (tmp, sizeof tmp, "%s.tmp", path) >= (int) sizeof tmp)
    { errno = ENAMETOOLONG; return -1; }
  int fd = open (tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) return -1;
  if (fchmod (fd, 0600) != 0) { close (fd); unlink (tmp); return -1; }
  for (int off = 0; off < n; )
    {
      ssize_t w = write (fd, buf + off, n - off);
      if (w < 0) { if (errno == EINTR) continue; close (fd); unlink (tmp); return -1; }
      off += (int) w;
    }
  if (fsync (fd) != 0 || close (fd) != 0) { unlink (tmp); return -1; }
  if (rename (tmp, path) != 0) { unlink (tmp); return -1; }

  strncpy (dir, path, sizeof dir - 1); dir[sizeof dir - 1] = '\0';
  char *slash = strrchr (dir, '/');
  if (slash == 0) strcpy (dir, ".");
  else if (slash == dir) slash[1] = '\0';
  else *slash = '\0';
  int dfd = open (dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd >= 0) { fsync (dfd); close (dfd); }
  return 0;
}

/* Exactly n bytes from getrandom(2); `flags` decides blocking. -1 on failure,
   errno EAGAIN when GRND_NONBLOCK and the pool is not yet initialised. */
static int
get_random (unsigned char *buf, int n, unsigned flags)
{
  for (int off = 0; off < n; )
    {
      ssize_t r = getrandom (buf + off, n - off, flags);
      if (r < 0) { if (errno == EINTR) continue; return -1; }
      off += (int) r;
    }
  return 0;
}

static int
do_load (const char *path)
{
  unsigned char seed[SEED_MAX], fresh[SEED_MAX];
  int missing, rc, err;
  int n = read_seed (path, seed, &missing);
  if (n < 0 && missing)
    { fprintf (stderr, "rngseed: no seed at %s (first boot)\n", path); return EXECUTION_SUCCESS; }
  if (n < 0)
    { builtin_error ("load %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
  if (n < SEED_MIN)
    { builtin_error ("load %s: seed too short (%d bytes; need %d..%d)", path, n, SEED_MIN, SEED_MAX);
      return EXECUTION_FAILURE; }

  /* Credit it. RNDADDENTROPY needs CAP_SYS_ADMIN, which PID 1 has. */
  struct rand_pool_info *rpi = malloc (sizeof *rpi + n);
  if (rpi == 0) { builtin_error ("load: out of memory"); return EXECUTION_FAILURE; }
  rpi->entropy_count = pool_bits (8 * n);
  rpi->buf_size = n;
  memcpy (rpi->buf, seed, n);
  memset (seed, 0, sizeof seed);
  int fd = open ("/dev/urandom", O_WRONLY | O_CLOEXEC);
  rc = fd < 0 ? -1 : ioctl (fd, RNDADDENTROPY, rpi);
  err = errno;
  if (fd >= 0) close (fd);
  memset (rpi, 0, sizeof *rpi + n);
  free (rpi);
  if (rc != 0)
    { builtin_error ("load: RNDADDENTROPY: %s", strerror (err)); return EXECUTION_FAILURE; }

  /* The seed is spent: replace it at once, from the pool the credit just
     initialised. NON-blocking, so PID 1 can never stall here. */
  if (get_random (fresh, n, GRND_NONBLOCK) == 0)
    {
      rc = write_seed (path, fresh, n);
      err = errno;
      memset (fresh, 0, sizeof fresh);
      if (rc != 0) { builtin_error ("load: refresh %s: %s", path, strerror (err)); return EXECUTION_FAILURE; }
      return EXECUTION_SUCCESS;
    }
  if (errno == EAGAIN)
    {
      /* Pool still uninitialised after the credit. Never leave a spent seed
         where it could be credited again; save will write a fresh one. */
      unlink (path);
      fprintf (stderr, "rngseed: pool not initialised after credit; %s consumed, not refreshed\n", path);
      return EXECUTION_SUCCESS;
    }
  builtin_error ("load: getrandom: %s", strerror (errno));
  return EXECUTION_FAILURE;
}

static int
do_save (const char *path)
{
  unsigned char fresh[SEED_LEN];
  int rc, err;
  /* BLOCKING: returns only once the CRNG is initialised, which is exactly what
     makes the result creditable next boot. Callers run this in the background. */
  if (get_random (fresh, SEED_LEN, 0) != 0)
    { builtin_error ("save: getrandom: %s", strerror (errno)); return EXECUTION_FAILURE; }
  rc = write_seed (path, fresh, SEED_LEN);
  err = errno;
  memset (fresh, 0, sizeof fresh);
  if (rc != 0) { builtin_error ("save %s: %s", path, strerror (err)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

int
rngseed_builtin (WORD_LIST *list)
{
  reset_internal_getopt ();
  if (internal_getopt (list, "") != -1)		/* no options; `--` is accepted */
    { builtin_usage (); return (EX_USAGE); }
  list = loptend;
  if (list == 0 || list->next == 0 || list->next->next != 0)
    { builtin_usage (); return (EX_USAGE); }
  const char *verb = list->word->word, *path = list->next->word->word;
  if (strcmp (verb, "load") == 0) return do_load (path);
  if (strcmp (verb, "save") == 0) return do_save (path);
  builtin_error ("unknown verb '%s' (load|save)", verb);
  return (EX_USAGE);
}

char *rngseed_doc[] = {
  "Credit and refresh the kernel random seed.",
  "",
  "rngseed load FILE   credit FILE into the kernel pool (RNDADDENTROPY), then",
  "                    replace it with fresh bytes so it is never used twice.",
  "                    A missing FILE is the first boot: reported, exit 0.",
  "rngseed save FILE   write 512 bytes from a BLOCKING getrandom(2) to FILE;",
  "                    waits for the pool to initialise (run in background).",
  "Written 0600, temp + fsync + rename. Pays the CRNG wait on the first boot only.",
  (char *) NULL
};

struct builtin rngseed_struct = {
  "rngseed", rngseed_builtin, BUILTIN_ENABLED, rngseed_doc, "rngseed load|save FILE", 0
};
