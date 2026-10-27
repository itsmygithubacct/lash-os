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
 *   - load unlinks and directory-fsyncs a seed BEFORE crediting it. A crash or
 *     failed refresh therefore cannot leave a spent seed at FILE. Failed
 *     credit restores the original through the same durable write protocol.
 *     Operations lock the parent directory, so cooperating calls serialize.
 *
 *   rngseed load FILE    credit FILE (32..4096 bytes; 512 expected), refresh it.
 *                        A missing FILE is the first boot: one line to stderr,
 *                        exit 0. Never waits for entropy on PID 1's boot path.
 *   rngseed save FILE    512 bytes from a BLOCKING getrandom(2) -> FILE.
 *
 * FILE is written 0600 to a temp name in the same directory, fsynced, renamed
 * over, and the directory fsynced, so a power cut leaves the old seed or the
 * new one — never a torn file. Load may leave no seed after consumption.
 * Seeds must be regular, single-link, caller-owned 0600 files in a trusted
 * directory. Raw seeds have no checksum: size-valid corruption is undetectable.
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
#include <sys/file.h>
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

/* All pathname operations are relative to one opened, locked directory.
   The parent must be private/trusted; flock coordinates rngseed callers, not
   arbitrary writers or snapshots of the backing filesystem. */
struct seed_path { int dir; char *storage, *name; };

static void
wipe (void *p, size_t n)
{
  volatile unsigned char *v = p;
  while (n--) *v++ = 0;
}

static int
open_path (const char *path, struct seed_path *p)
{
  p->dir = -1;
  p->storage = strdup (path);
  if (!p->storage) return -1;
  char *slash = strrchr (p->storage, '/');
  const char *dir = ".";
  p->name = p->storage;
  if (slash)
    {
      *slash = 0;
      dir = slash == p->storage ? "/" : p->storage;
      p->name = slash + 1;
    }
  if (!*p->name) { errno = EINVAL; goto fail; }
  p->dir = open (dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (p->dir < 0 || flock (p->dir, LOCK_EX | LOCK_NB) != 0) goto fail;
  return 0;
fail:
  {
    int err = errno;
    if (p->dir >= 0) close (p->dir);
    free (p->storage);
    errno = err;
    return -1;
  }
}

static void
close_path (struct seed_path *p)
{
  int err = errno;
  close (p->dir);
  free (p->storage);
  errno = err;
}

/* One extra byte distinguishes an oversized seed from an exact SEED_MAX seed.
   Refuse links, non-regular files, other owners and non-private permissions. */
static int
read_seed (struct seed_path *p, unsigned char *buf, int *missing)
{
  *missing = 0;
  int fd = openat (p->dir, p->name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) { if (errno == ENOENT) *missing = 1; return -1; }
  struct stat st;
  int n = -1, err;
  if (fstat (fd, &st) != 0) goto out;
  if (!S_ISREG (st.st_mode) || (st.st_mode & 07777) != 0600 ||
      st.st_uid != geteuid () || st.st_nlink != 1)
    { errno = EPERM; goto out; }
  n = 0;
  while (n <= SEED_MAX)
    {
      ssize_t r = read (fd, buf + n, SEED_MAX + 1 - n);
      if (r < 0) { if (errno == EINTR) continue; n = -1; break; }
      if (r == 0) break;
      n += (int) r;
    }
out:
  err = errno;
  if (close (fd) != 0 && n >= 0) return -1;
  errno = err;
  return n;
}

/* Exclusive temp creation never follows an attacker-supplied .tmp symlink.
   Success means write -> fsync(file) -> close -> rename -> fsync(directory).
   Every failure closes descriptors, removes the temp, and preserves errno. */
static int
write_seed (struct seed_path *p, const unsigned char *buf, int n)
{
  static unsigned long serial;
  char tmp[80];
  int fd = -1, err;
  for (int i = 0; i < 128; i++)
    {
      snprintf (tmp, sizeof tmp, ".rngseed-%ld-%lu", (long) getpid (), ++serial);
      fd = openat (p->dir, tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
      if (fd >= 0 || errno != EEXIST) break;
    }
  if (fd < 0) return -1;
  if (fchmod (fd, 0600) != 0) goto fail;
  for (int off = 0; off < n; )
    {
      ssize_t w = write (fd, buf + off, n - off);
      if (w < 0) { if (errno == EINTR) continue; goto fail; }
      if (w == 0) { errno = EIO; goto fail; }
      off += (int) w;
    }
  if (fsync (fd) != 0) goto fail;
  if (close (fd) != 0) { fd = -1; goto fail; }
  fd = -1;
  if (renameat (p->dir, tmp, p->dir, p->name) != 0) goto fail;
  return fsync (p->dir);
fail:
  err = errno;
  if (fd >= 0) close (fd);
  unlinkat (p->dir, tmp, 0);
  errno = err;
  return -1;
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
      if (r == 0) { errno = EIO; return -1; }
      off += (int) r;
    }
  return 0;
}

static int
do_load (const char *path)
{
  unsigned char seed[SEED_MAX + 1], fresh[SEED_MAX];
  struct seed_path p;
  struct rand_pool_info *rpi = 0;
  int missing, n, fd, rc = EXECUTION_FAILURE, err;
  if (open_path (path, &p) != 0)
    { builtin_error ("load %s: %s", path, strerror (errno)); return rc; }
  n = read_seed (&p, seed, &missing);
  if (n < 0 && missing)
    {
      rc = fprintf (stderr, "rngseed: no seed at %s (first boot)\n", path) < 0 ||
           fflush (stderr) != 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
      goto out;
    }
  if (n < 0)
    { builtin_error ("load %s: %s", path, strerror (errno)); goto out; }
  if (n < SEED_MIN || n > SEED_MAX)
    { builtin_error ("load %s: invalid seed size (%d; need %d..%d)", path, n, SEED_MIN, SEED_MAX); goto out; }

  rpi = malloc (sizeof *rpi + n);
  if (!rpi) { builtin_error ("load: out of memory"); goto out; }
  rpi->entropy_count = pool_bits (8 * n);
  rpi->buf_size = n;
  memcpy (rpi->buf, seed, n);
  /* Persist consumption before the irreversible credit. A failed sync means
     no credit; losing an uncredited seed is preferable to crediting it twice. */
  if (unlinkat (p.dir, p.name, 0) != 0 || fsync (p.dir) != 0)
    { builtin_error ("load: consume %s: %s", path, strerror (errno)); goto out; }
  fd = open ("/dev/urandom", O_WRONLY | O_CLOEXEC);
  int credit = fd < 0 ? -1 : ioctl (fd, RNDADDENTROPY, rpi);
  err = errno;
  if (fd >= 0) close (fd);
  if (credit != 0)
    {
      builtin_error ("load: RNDADDENTROPY: %s", strerror (err));
      if (write_seed (&p, seed, n) != 0)
        builtin_error ("load: restore %s: %s", path, strerror (errno));
      goto out;
    }
  if (get_random (fresh, n, GRND_NONBLOCK) == 0)
    {
      if (write_seed (&p, fresh, n) != 0)
        { builtin_error ("load: refresh %s: %s", path, strerror (errno)); goto out; }
      rc = EXECUTION_SUCCESS;
    }
  else if (errno == EAGAIN)
    rc = fprintf (stderr, "rngseed: pool not initialised after credit; %s consumed, not refreshed\n", path) < 0 ||
         fflush (stderr) != 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
  else builtin_error ("load: getrandom: %s", strerror (errno));
out:
  wipe (seed, sizeof seed);
  wipe (fresh, sizeof fresh);
  if (rpi) { wipe (rpi, sizeof *rpi + n); free (rpi); }
  close_path (&p);
  return rc;
}

static int
do_save (const char *path)
{
  unsigned char fresh[SEED_LEN];
  struct seed_path p;
  int rc = EXECUTION_FAILURE;
  if (open_path (path, &p) != 0)
    { builtin_error ("save %s: %s", path, strerror (errno)); return rc; }
  /* Blocking getrandom is the qualification for creditable saved bytes. */
  if (get_random (fresh, SEED_LEN, 0) != 0)
    builtin_error ("save: getrandom: %s", strerror (errno));
  else if (write_seed (&p, fresh, SEED_LEN) != 0)
    builtin_error ("save %s: %s", path, strerror (errno));
  else rc = EXECUTION_SUCCESS;
  wipe (fresh, sizeof fresh);
  close_path (&p);
  return rc;
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
  "rngseed load FILE   durably consume FILE, credit it (RNDADDENTROPY),",
  "                    then refresh it with nonblocking getrandom.",
  "                    A missing FILE is the first boot: reported, exit 0.",
  "rngseed save FILE   write 512 bytes from a BLOCKING getrandom(2) to FILE;",
  "                    waits for the pool to initialise (run in background).",
  "Written 0600, temp + fsync + rename. Pays the CRNG wait on the first boot only.",
  (char *) NULL
};

struct builtin rngseed_struct = {
  "rngseed", rngseed_builtin, BUILTIN_ENABLED, rngseed_doc, "rngseed load|save FILE", 0
};
