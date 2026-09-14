/* SPDX-License-Identifier: MIT */
/* passwd.c — password verification for bash-os.
 *
 * Stage 35 first slice: move password verification out of shell scripts.
 * This loadable reads password bytes into C-owned memory, verifies the
 * existing Argon2id PHC strings from /etc/shadow, wipes the password buffer,
 * and returns only an exit status to Bash.
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
#include <stdint.h>
#include <termios.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "_monocypher_monocypher-ed25519.h"
#include "_bashauth_pwverify.h"
#include "loadables.h"

#define BPW_MAX_PASSWORD 4096
#define BPW_LOCK_FAIL_MAX 5
#define BPW_LOCK_WINDOW 600
#define BPW_LOCK_DURATION 900
#define BPW_AUTH_IOC_MAGIC 0xBA
#define BPW_AUTH_DEV "/dev/bashos-auth"
#define BPW_AUTH_FEAT_SECRETS (1ull << 0)
/* RFC 9106 §4 lists two recommended argon2id parameter sets:
 *   - m=2^16 KiB (64 MiB), t=3, p=1  — recommended for high-security
 *     contexts. Was the bash-os default through v3.4.
 *   - m=2^14.246 KiB (~19 MiB), t=2, p=1 — minimum recommended for
 *     resource-constrained contexts.
 * bash-os historically shipped with a 128 MiB QEMU default, where a
 * 64 MiB mlock'd argon2 working set could run the guest into OOM-kill
 * on the first `passwd add`. The launcher now defaults to 512 MiB
 * to keep the initramfs-backed writable root above 128 MiB, but this
 * 19 MiB / t=2 / p=1 floor remains the conservative default for small
 * or overridden boots. Operators can override via PHCLIB_M / PHCLIB_T /
 * PHCLIB_P env vars (clamped to [1024,262144] / [1,10] / [1,8] at use
 * time). Re-tuned 2026-05-13; launcher default raised 2026-06-04. */
#define BPW_ARGON_M 19456
#define BPW_ARGON_T 2
#define BPW_ARGON_P 1
#define BPW_HASH_LEN 32

struct bpw_auth_version {
  unsigned int abi_major;
  unsigned int abi_minor;
  unsigned long long features;
  unsigned char reserved[16];
};

struct bpw_auth_handle {
  unsigned int id;
  unsigned int flags;
};

struct bpw_auth_secret_write {
  unsigned int id;
  unsigned int len;
  unsigned long long user_ptr;
};

struct bpw_auth_secret_export {
  unsigned int id;
  unsigned int len;
  unsigned long long user_ptr;
};

struct bpw_auth_secret_compare {
  unsigned int id_a;
  unsigned int id_b;
  unsigned int result;
  unsigned int flags;
};

#define BPW_AUTH_IOC_VERSION \
  _IOR(BPW_AUTH_IOC_MAGIC, 0x01, struct bpw_auth_version)
#define BPW_AUTH_IOC_NEW_SECRET \
  _IOWR(BPW_AUTH_IOC_MAGIC, 0x02, struct bpw_auth_handle)
#define BPW_AUTH_IOC_WRITE_SECRET \
  _IOW(BPW_AUTH_IOC_MAGIC, 0x03, struct bpw_auth_secret_write)
#define BPW_AUTH_IOC_SEAL_SECRET \
  _IOW(BPW_AUTH_IOC_MAGIC, 0x04, struct bpw_auth_handle)
#define BPW_AUTH_IOC_CLEAR_SECRET \
  _IOW(BPW_AUTH_IOC_MAGIC, 0x05, struct bpw_auth_handle)
#define BPW_AUTH_IOC_EXPORT_ONCE \
  _IOWR(BPW_AUTH_IOC_MAGIC, 0x06, struct bpw_auth_secret_export)
#define BPW_AUTH_IOC_SAME_SECRET \
  _IOWR(BPW_AUTH_IOC_MAGIC, 0x07, struct bpw_auth_secret_compare)

static unsigned int
bpw_env_uint (const char *name, unsigned int def, unsigned int min, unsigned int max)
{
  const char *s = getenv (name);
  if (!s || !*s) return def;
  char *end = NULL;
  unsigned long v = strtoul (s, &end, 10);
  if (end == s || *end != '\0' || v < min || v > max) return def;
  return (unsigned int) v;
}

typedef struct {
  unsigned int m, t, p;
  char salt_hex[129];
  char hash_hex[257];
} bpw_phc;

typedef struct {
  char name[64];
  unsigned int uid;
  unsigned int gid;
  char gecos[128];
  char home[256];
  char shell[256];
} bpw_user;

typedef struct {
  int fd;
  unsigned int id;
  int owns_fd;
} bpw_secret_ref;

static int bpw_read_tty_password (const char *prompt, unsigned char **out, size_t *out_len);
static int bpw_verify_user_buf (const char *user, const unsigned char *pw, size_t pw_len);
static int bpw_temp_open (const char *path, char *tmp, size_t tmpsz, mode_t mode);
static int bpw_fsync_parent (const char *path);

static void
bpw_wipe (void *p, size_t n)
{
  if (!p || n == 0) return;
  crypto_wipe (p, n);
}

static void
bpw_release_tty_password (unsigned char *p)
{
  if (!p) return;
  bpw_wipe (p, BPW_MAX_PASSWORD);
  munlock (p, BPW_MAX_PASSWORD);
  munmap (p, BPW_MAX_PASSWORD);
}

static int
bpw_kernel_secrets_disabled (void)
{
  const char *v = getenv ("BASHPASSWD_KERNEL_SECRETS");
  return v && strcmp (v, "0") == 0;
}

static int
bpw_kernel_secrets_required (void)
{
  const char *v = getenv ("BASHPASSWD_REQUIRE_KERNEL_SECRETS");
  return v && strcmp (v, "0") != 0;
}

static int
bpw_auth_open_optional (void)
{
  if (bpw_kernel_secrets_disabled ())
    return -1;

  int fd = open (BPW_AUTH_DEV, O_RDWR | O_CLOEXEC);
  if (fd < 0)
    {
      if (bpw_kernel_secrets_required ())
        builtin_error ("%s: %s", BPW_AUTH_DEV, strerror (errno));
      return -1;
    }
  int fl = fcntl (fd, F_GETFD, 0);
  if (fl >= 0)
    (void) fcntl (fd, F_SETFD, fl | FD_CLOEXEC);

  struct bpw_auth_version v;
  memset (&v, 0, sizeof v);
  if (ioctl (fd, BPW_AUTH_IOC_VERSION, &v) < 0 ||
      v.abi_major != 1 ||
      (v.features & BPW_AUTH_FEAT_SECRETS) == 0)
    {
      if (bpw_kernel_secrets_required ())
        builtin_error ("%s: missing secret-slot support", BPW_AUTH_DEV);
      close (fd);
      return -1;
    }
  return fd;
}

static int
bpw_secret_new (bpw_secret_ref *s)
{
  int fd = bpw_auth_open_optional ();
  if (fd < 0)
    return bpw_kernel_secrets_required () ? -1 : -2;

  struct bpw_auth_handle h;
  memset (&h, 0, sizeof h);
  if (ioctl (fd, BPW_AUTH_IOC_NEW_SECRET, &h) < 0)
    {
      builtin_error ("kernel secret create: %s", strerror (errno));
      close (fd);
      return -1;
    }
  s->fd = fd;
  s->id = h.id;
  s->owns_fd = 1;
  return 0;
}

static int
bpw_secret_new_on_fd (int fd, bpw_secret_ref *s)
{
  struct bpw_auth_handle h;
  memset (&h, 0, sizeof h);
  if (ioctl (fd, BPW_AUTH_IOC_NEW_SECRET, &h) < 0)
    {
      builtin_error ("kernel secret create: %s", strerror (errno));
      return -1;
    }
  s->fd = fd;
  s->id = h.id;
  s->owns_fd = 0;
  return 0;
}

static void
bpw_secret_clear (bpw_secret_ref *s)
{
  if (!s || s->fd < 0)
    return;
  struct bpw_auth_handle h;
  memset (&h, 0, sizeof h);
  h.id = s->id;
  (void) ioctl (s->fd, BPW_AUTH_IOC_CLEAR_SECRET, &h);
  if (s->owns_fd)
    close (s->fd);
  s->fd = -1;
  s->id = 0;
  s->owns_fd = 0;
}

static int
bpw_secret_write (const bpw_secret_ref *s, const void *buf, size_t len)
{
  if (len == 0)
    return 0;
  if (len > BPW_MAX_PASSWORD)
    {
      errno = E2BIG;
      return -1;
    }
  struct bpw_auth_secret_write w;
  memset (&w, 0, sizeof w);
  w.id = s->id;
  w.len = (unsigned int) len;
  w.user_ptr = (unsigned long long) (uintptr_t) buf;
  return ioctl (s->fd, BPW_AUTH_IOC_WRITE_SECRET, &w);
}

static int
bpw_secret_seal (const bpw_secret_ref *s)
{
  struct bpw_auth_handle h;
  memset (&h, 0, sizeof h);
  h.id = s->id;
  return ioctl (s->fd, BPW_AUTH_IOC_SEAL_SECRET, &h);
}

static int
bpw_secret_same (const bpw_secret_ref *a, const bpw_secret_ref *b)
{
  struct bpw_auth_secret_compare c;
  memset (&c, 0, sizeof c);
  c.id_a = a->id;
  c.id_b = b->id;
  if (ioctl (a->fd, BPW_AUTH_IOC_SAME_SECRET, &c) < 0)
    return -1;
  return c.result ? 1 : 0;
}

static int
bpw_secret_export_once (const bpw_secret_ref *s, unsigned char **out, size_t *out_len)
{
  unsigned char *buf = mmap (NULL, BPW_MAX_PASSWORD, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buf == MAP_FAILED)
    return -1;
  if (mlock (buf, BPW_MAX_PASSWORD) < 0)
    ; /* best effort; exported bytes are wiped before munmap */

  struct bpw_auth_secret_export e;
  memset (&e, 0, sizeof e);
  e.id = s->id;
  e.len = BPW_MAX_PASSWORD;
  e.user_ptr = (unsigned long long) (uintptr_t) buf;
  if (ioctl (s->fd, BPW_AUTH_IOC_EXPORT_ONCE, &e) < 0)
    {
      int err = errno;
      bpw_release_tty_password (buf);
      errno = err;
      return -1;
    }
  *out = buf;
  *out_len = e.len;
  return 0;
}

static int
bpw_hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
bpw_unhex (const char *hex, unsigned char *out, size_t outsz)
{
  size_t o = 0;
  int hi = -1;
  for (const char *p = hex; *p; p++)
    {
      int v = bpw_hexval ((unsigned char) *p);
      if (v < 0) return -1;
      if (hi < 0) { hi = v; continue; }
      if (o >= outsz) return -1;
      out[o++] = (unsigned char) ((hi << 4) | v);
      hi = -1;
    }
  return hi < 0 ? (int) o : -1;
}

static int
bpw_valid_user (const char *u)
{
  if (!u || !*u) return 0;
  unsigned char c0 = (unsigned char) u[0];
  if (!((c0 >= 'a' && c0 <= 'z') || c0 == '_')) return 0;
  size_t n = strlen (u);
  if (n > 32) return 0;
  for (size_t i = 1; i < n; i++)
    {
      unsigned char c = (unsigned char) u[i];
      if (!((c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-'))
        return 0;
    }
  return 1;
}

static const char *
bpw_shadow_path (void)
{
  const char *path = getenv ("PHCLIB_SHADOW");
  if (!path || !*path) path = getenv ("SHADOW_FILE");
  if (!path || !*path) path = "/etc/shadow";
  return path;
}

static const char *
bpw_passwd_path (void)
{
  const char *path = getenv ("PHCLIB_PASSWD");
  if (!path || !*path) path = getenv ("PASSWD_FILE");
  if (!path || !*path) path = "/etc/passwd";
  return path;
}

static const char *
bpw_group_path (void)
{
  const char *path = getenv ("PHCLIB_GROUP");
  if (!path || !*path) path = getenv ("GROUP_FILE");
  if (!path || !*path) path = "/etc/group";
  return path;
}

static void
bpw_print_hex (const unsigned char *buf, size_t n, char *out)
{
  static const char d[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++)
    {
      out[i * 2] = d[(buf[i] >> 4) & 0xf];
      out[i * 2 + 1] = d[buf[i] & 0xf];
    }
  out[n * 2] = '\0';
}

static int
bpw_random_bytes (unsigned char *buf, size_t n)
{
  int fd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd < 0) { builtin_error ("/dev/urandom: %s", strerror (errno)); return -1; }
  size_t off = 0;
  while (off < n)
    {
      ssize_t r = read (fd, buf + off, n - off);
      if (r < 0) { if (errno == EINTR) continue; close (fd); return -1; }
      if (r == 0) { close (fd); errno = EIO; return -1; }
      off += (size_t) r;
    }
  close (fd);
  return 0;
}

static int
bpw_parse_phc (const char *phc, bpw_phc *out)
{
  if (!phc || strncmp (phc, "$argon2id$", 10) != 0) return -1;

  char *copy = strdup (phc);
  if (!copy) return -1;
  char *save = NULL;
  char *parts[6] = { 0 };
  int n = 0;
  for (char *tok = strtok_r (copy, "$", &save); tok && n < 6;
       tok = strtok_r (NULL, "$", &save))
    parts[n++] = tok;

  if (n != 5 || strcmp (parts[0], "argon2id") != 0 ||
      strcmp (parts[1], "v=19") != 0)
    { free (copy); return -1; }

  memset (out, 0, sizeof *out);
  char *psave = NULL;
  for (char *kv = strtok_r (parts[2], ",", &psave); kv;
       kv = strtok_r (NULL, ",", &psave))
    {
      if (strncmp (kv, "m=", 2) == 0) out->m = (unsigned int) strtoul (kv + 2, NULL, 10);
      else if (strncmp (kv, "t=", 2) == 0) out->t = (unsigned int) strtoul (kv + 2, NULL, 10);
      else if (strncmp (kv, "p=", 2) == 0) out->p = (unsigned int) strtoul (kv + 2, NULL, 10);
    }

  size_t sl = strlen (parts[3]), hl = strlen (parts[4]);
  if (out->m < 1024 || out->m > 262144 ||
      out->t < 1 || out->t > 10 ||
      out->p < 1 || out->p > 8 ||
      sl < 16 || sl > 128 || (sl & 1) ||
      hl < 32 || hl > 256 || (hl & 1))
    { free (copy); return -1; }

  strncpy (out->salt_hex, parts[3], sizeof out->salt_hex - 1);
  strncpy (out->hash_hex, parts[4], sizeof out->hash_hex - 1);
  free (copy);
  return 0;
}

static int
bpw_shadow_phc (const char *user, char *out, size_t outsz)
{
  const char *path = bpw_shadow_path ();

  FILE *f = fopen (path, "r");
  if (!f) { builtin_error ("cannot read %s: %s", path, strerror (errno)); return -1; }

  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  int rc = -1;
  while ((n = getline (&line, &cap, f)) > 0)
    {
      if (n && line[n - 1] == '\n') line[n - 1] = '\0';
      char *first_colon = strchr (line, ':');
      if (!first_colon) continue;
      *first_colon = '\0';
      if (strcmp (line, user) != 0) continue;
      char *phc = first_colon + 1;
      char *next = strchr (phc, ':');
      if (next) *next = '\0';
      if (phc[0] == '\0' || phc[0] == '!' || phc[0] == '*')
        { builtin_error ("%s is locked or has no password", user); rc = -2; break; }
      if (strlen (phc) >= outsz) { builtin_error ("shadow PHC too long"); rc = -1; break; }
      strcpy (out, phc);
      rc = 0;
      break;
    }
  free (line);
  fclose (f);
  if (rc == -1) builtin_error ("no shadow entry for %s", user);
  return rc;
}

static int
bpw_lookup_user (const char *user, bpw_user *out)
{
  FILE *f = fopen (bpw_passwd_path (), "r");
  if (!f) return -1;
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  int rc = -1;
  while ((n = getline (&line, &cap, f)) > 0)
    {
      if (n && line[n - 1] == '\n') line[n - 1] = '\0';
      char *save = NULL;
      char *name = strtok_r (line, ":", &save);
      strtok_r (NULL, ":", &save);
      char *uid = strtok_r (NULL, ":", &save);
      char *gid = strtok_r (NULL, ":", &save);
      char *gecos = strtok_r (NULL, ":", &save);
      char *home = strtok_r (NULL, ":", &save);
      char *shell = strtok_r (NULL, ":", &save);
      if (!name || strcmp (name, user) != 0) continue;
      memset (out, 0, sizeof *out);
      snprintf (out->name, sizeof out->name, "%s", name);
      out->uid = uid ? (unsigned int) strtoul (uid, NULL, 10) : 0;
      out->gid = gid ? (unsigned int) strtoul (gid, NULL, 10) : 0;
      snprintf (out->gecos, sizeof out->gecos, "%s", gecos ? gecos : "");
      snprintf (out->home, sizeof out->home, "%s", home ? home : "/");
      snprintf (out->shell, sizeof out->shell, "%s", shell ? shell : "/bin/bash");
      rc = 0;
      break;
    }
  free (line);
  fclose (f);
  return rc;
}

static int
bpw_user_uid_token (const char *user, char *out, size_t outsz)
{
  const char *path = bpw_passwd_path ();

  FILE *f = fopen (path, "r");
  if (f)
    {
      char *line = NULL;
      size_t cap = 0;
      ssize_t n;
      while ((n = getline (&line, &cap, f)) > 0)
        {
          if (n && line[n - 1] == '\n') line[n - 1] = '\0';
          char *save = NULL;
          char *name = strtok_r (line, ":", &save);
          strtok_r (NULL, ":", &save);
          char *uid = strtok_r (NULL, ":", &save);
          if (name && uid && strcmp (name, user) == 0)
            {
              snprintf (out, outsz, "%s", uid);
              free (line);
              fclose (f);
              return 0;
            }
        }
      free (line);
      fclose (f);
    }

  /* Tests may provide a shadow-only fixture. Fall back to a username
     token so lockout still works there; real systems use uid scope. */
  size_t j = 0;
  for (const char *p = user; *p && j + 1 < outsz; p++)
    {
      unsigned char c = (unsigned char) *p;
      out[j++] = ((c >= 'A' && c <= 'Z') ||
                  (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') ||
                  c == '_' || c == '-') ? (char) c : '_';
    }
  out[j] = '\0';
  return out[0] ? 0 : -1;
}

static const char *
bpw_lock_dir (void)
{
  const char *d = getenv ("BPW_LOCK_DIR");
  if (!d || !*d) d = "/run/login";
  return d;
}

static int
bpw_lock_path (const char *user, char *out, size_t outsz)
{
  char tok[64];
  if (bpw_user_uid_token (user, tok, sizeof tok) < 0)
    return -1;
  snprintf (out, outsz, "%s/fail.%s", bpw_lock_dir (), tok);
  return 0;
}

static int
bpw_read_lock_state (const char *path, int *count, long *last, long *locked_until)
{
  *count = 0;
  *last = 0;
  *locked_until = 0;

  FILE *f = fopen (path, "r");
  if (!f) return 0;
  char line[128];
  while (fgets (line, sizeof line, f))
    {
      if (strncmp (line, "COUNT=", 6) == 0) *count = atoi (line + 6);
      else if (strncmp (line, "LAST=", 5) == 0) *last = strtol (line + 5, NULL, 10);
      else if (strncmp (line, "LOCKED_UNTIL=", 13) == 0) *locked_until = strtol (line + 13, NULL, 10);
    }
  fclose (f);
  return 0;
}

static int
bpw_check_lockout (const char *user)
{
  char path[256];
  if (bpw_lock_path (user, path, sizeof path) < 0)
    return 0;
  int count;
  long last, locked_until;
  bpw_read_lock_state (path, &count, &last, &locked_until);
  long now = (long) time (NULL);
  if (locked_until > now)
    {
      builtin_error ("account locked; try again in %ld seconds", locked_until - now);
      return -1;
    }
  return 0;
}

static void
bpw_record_failure (const char *user)
{
  const char *dir = bpw_lock_dir ();
  if (mkdir (dir, 0700) < 0 && errno != EEXIST)
    return;

  char path[256], tmp[512];
  if (bpw_lock_path (user, path, sizeof path) < 0)
    return;
  int count;
  long last, locked_until;
  bpw_read_lock_state (path, &count, &last, &locked_until);

  long now = (long) time (NULL);
  if (now - last > BPW_LOCK_WINDOW)
    count = 0;
  count++;
  last = now;
  if (count >= BPW_LOCK_FAIL_MAX)
    locked_until = now + BPW_LOCK_DURATION;
  else
    locked_until = 0;

  int fd = bpw_temp_open (path, tmp, sizeof tmp, 0600);
  if (fd < 0) return;
  FILE *f = fdopen (fd, "w");
  if (!f) { close (fd); unlink (tmp); return; }
  fprintf (f, "COUNT=%d\nLAST=%ld\nLOCKED_UNTIL=%ld\n", count, last, locked_until);
  fflush (f);
  fd = fileno (f);
  if (fd >= 0) fsync (fd);
  fclose (f);
  chmod (tmp, 0600);
  rename (tmp, path);
}

static void
bpw_record_success (const char *user)
{
  char path[256];
  if (bpw_lock_path (user, path, sizeof path) == 0)
    unlink (path);
}

static int
bpw_verify_secret (const unsigned char *pw, size_t pw_len, const char *phc)
{
  int rc = bashos_verify_phc_secret (pw, pw_len, phc);
  if (rc < 0)
    builtin_error ("unsupported or malformed PHC string");
  return rc;
}

static int
bpw_hash_secret (const unsigned char *pw, size_t pw_len, char *out, size_t outsz)
{
  unsigned char salt[16];
  unsigned char hash[BPW_HASH_LEN];
  if (bpw_random_bytes (salt, sizeof salt) < 0)
    return -1;

  unsigned int argon_m = bpw_env_uint ("PHCLIB_M", BPW_ARGON_M, 1024, 262144);
  unsigned int argon_t = bpw_env_uint ("PHCLIB_T", BPW_ARGON_T, 1, 10);
  unsigned int argon_p = bpw_env_uint ("PHCLIB_P", BPW_ARGON_P, 1, 8);
  size_t work_bytes = (size_t) argon_m * 1024;
  void *work = malloc (work_bytes);
  if (!work) { builtin_error ("argon2id: out of memory"); return -1; }
  int locked = (mlock (work, work_bytes) == 0);

  crypto_argon2_config cfg = {
    .algorithm = CRYPTO_ARGON2_ID,
    .nb_blocks = argon_m,
    .nb_passes = argon_t,
    .nb_lanes = argon_p,
  };
  crypto_argon2_inputs in = {
    .pass = pw,
    .salt = salt,
    .pass_size = (uint32_t) pw_len,
    .salt_size = (uint32_t) sizeof salt,
  };
  crypto_argon2 (hash, sizeof hash, work, cfg, in, crypto_argon2_no_extras);
  bpw_wipe (work, work_bytes);
  if (locked) munlock (work, work_bytes);
  free (work);

  char salt_hex[sizeof salt * 2 + 1], hash_hex[sizeof hash * 2 + 1];
  bpw_print_hex (salt, sizeof salt, salt_hex);
  bpw_print_hex (hash, sizeof hash, hash_hex);
  int n = snprintf (out, outsz, "$argon2id$v=19$m=%u,t=%u,p=%u$%s$%s",
                    argon_m, argon_t, argon_p, salt_hex, hash_hex);
  bpw_wipe (salt, sizeof salt);
  bpw_wipe (hash, sizeof hash);
  bpw_wipe (salt_hex, sizeof salt_hex);
  bpw_wipe (hash_hex, sizeof hash_hex);
  return (n > 0 && (size_t) n < outsz) ? 0 : -1;
}

static int
bpw_read_new_password (unsigned char **out, size_t *out_len)
{
  unsigned char *a = NULL, *b = NULL;
  size_t al = 0, bl = 0;
  if (bpw_read_tty_password ("New password: ", &a, &al) < 0) return -1;
  if (bpw_read_tty_password ("Retype new password: ", &b, &bl) < 0)
    {
      bpw_release_tty_password (a);
      return -1;
    }
  if (al == 0)
    {
      builtin_error ("empty password rejected");
      bpw_release_tty_password (a);
      bpw_release_tty_password (b);
      return -1;
    }
  if (al != bl || memcmp (a, b, al) != 0)
    {
      builtin_error ("passwords did not match");
      bpw_release_tty_password (a);
      bpw_release_tty_password (b);
      return -1;
    }
  bpw_release_tty_password (b);
  *out = a;
  *out_len = al;
  return 0;
}

static int
bpw_parent_dir (const char *path, char *dir, size_t dirsz)
{
  const char *slash = strrchr (path, '/');
  if (!slash)
    return snprintf (dir, dirsz, ".") < (int) dirsz ? 0 : -1;
  if (slash == path)
    return snprintf (dir, dirsz, "/") < (int) dirsz ? 0 : -1;
  size_t n = (size_t) (slash - path);
  if (n == 0 || n >= dirsz) return -1;
  memcpy (dir, path, n);
  dir[n] = '\0';
  return 0;
}

static int
bpw_temp_open (const char *path, char *tmp, size_t tmpsz, mode_t mode)
{
  char dir[512];
  struct stat st;
  if (bpw_parent_dir (path, dir, sizeof dir) < 0 ||
      lstat (dir, &st) < 0 ||
      !S_ISDIR (st.st_mode))
    {
      builtin_error ("unsafe temp parent for %s", path);
      return -1;
    }
  if (st.st_uid != geteuid ())
    {
      builtin_error ("refusing temp file in directory not owned by caller: %s", dir);
      return -1;
    }
  if (st.st_mode & (S_IWGRP | S_IWOTH))
    {
      builtin_error ("refusing temp file in group/world-writable dir: %s", dir);
      return -1;
    }

  int n = snprintf (tmp, tmpsz, "%s/.%s.XXXXXX", dir, strrchr (path, '/') ? strrchr (path, '/') + 1 : path);
  if (n <= 0 || (size_t) n >= tmpsz)
    { errno = ENAMETOOLONG; return -1; }

  int fd = mkstemp (tmp);
  if (fd < 0)
    return -1;
  if (fcntl (fd, F_SETFD, FD_CLOEXEC) < 0 ||
      fchmod (fd, mode) < 0)
    {
      int saved = errno;
      close (fd);
      unlink (tmp);
      errno = saved;
      return -1;
    }
  return fd;
}

static int
bpw_fsync_parent (const char *path)
{
  char dir[512];
  if (bpw_parent_dir (path, dir, sizeof dir) < 0)
    return -1;
  int dfd = open (dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd < 0)
    return -1;
  int rc = fsync (dfd);
  close (dfd);
  return rc;
}

static int
bpw_shadow_set (const char *user, const char *phc, int add_missing)
{
  if (!bpw_valid_user (user)) { builtin_error ("invalid user name"); return -1; }
  const char *path = bpw_shadow_path ();
  FILE *in = fopen (path, "r");
  if (!in && errno != ENOENT)
    { builtin_error ("open %s: %s", path, strerror (errno)); return -1; }

  char tmp[512];
  int fd = bpw_temp_open (path, tmp, sizeof tmp, 0600);
  if (fd < 0) { if (in) fclose (in); builtin_error ("open %s: %s", tmp, strerror (errno)); return -1; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); if (in) fclose (in); return -1; }

  long today = (long) (time (NULL) / 86400);
  int found = 0;
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  if (in)
    {
      while ((n = getline (&line, &cap, in)) > 0)
        {
          if (n && line[n - 1] == '\n') line[n - 1] = '\0';
          char *colon = strchr (line, ':');
          if (!colon) { fprintf (out, "%s\n", line); continue; }
          *colon = '\0';
          char *rest = colon + 1;
          char *next = strchr (rest, ':');
          if (strcmp (line, user) == 0)
            {
              found = 1;
              fprintf (out, "%s:%s:%ld:0:99999:7:::\n", user, phc, today);
            }
          else
            {
              *colon = ':';
              fprintf (out, "%s\n", line);
            }
          (void) next;
        }
      fclose (in);
    }
  free (line);
  if (!found)
    {
      if (!add_missing)
        {
          fclose (out); unlink (tmp);
          builtin_error ("no shadow entry for %s", user);
          return -1;
        }
      fprintf (out, "%s:%s:%ld:0:99999:7:::\n", user, phc, today);
    }
  fflush (out);
  fsync (fd);
  if (fclose (out) != 0 || rename (tmp, path) != 0)
    { unlink (tmp); builtin_error ("rewrite %s: %s", path, strerror (errno)); return -1; }
  chmod (path, 0600);
  (void) bpw_fsync_parent (path);
  return 0;
}

static int
bpw_shadow_delete (const char *user)
{
  const char *path = bpw_shadow_path ();
  FILE *in = fopen (path, "r");
  if (!in) return errno == ENOENT ? 0 : -1;
  char tmp[512];
  int fd = bpw_temp_open (path, tmp, sizeof tmp, 0600);
  if (fd < 0) { fclose (in); return -1; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); fclose (in); return -1; }
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  while ((n = getline (&line, &cap, in)) > 0)
    {
      if (n && line[n - 1] == '\n') line[n - 1] = '\0';
      char *colon = strchr (line, ':');
      if (colon) *colon = '\0';
      int match = (strcmp (line, user) == 0);
      if (colon) *colon = ':';
      if (!match) fprintf (out, "%s\n", line);
    }
  free (line);
  fclose (in);
  fflush (out); fsync (fd);
  if (fclose (out) != 0 || rename (tmp, path) != 0)
    { unlink (tmp); return -1; }
  chmod (path, 0600);
  (void) bpw_fsync_parent (path);
  return 0;
}

static int
bpw_passwd_add (const bpw_user *u)
{
  if (!bpw_valid_user (u->name)) { builtin_error ("invalid user name"); return -1; }
  bpw_user existing;
  if (bpw_lookup_user (u->name, &existing) == 0)
    { builtin_error ("%s already exists", u->name); return -1; }
  const char *path = bpw_passwd_path ();
  FILE *in = fopen (path, "r");
  if (!in && errno != ENOENT)
    { builtin_error ("open %s: %s", path, strerror (errno)); return -1; }
  char tmp[512];
  int fd = bpw_temp_open (path, tmp, sizeof tmp, 0644);
  if (fd < 0) { if (in) fclose (in); return -1; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); if (in) fclose (in); return -1; }
  if (in)
    {
      char buf[4096];
      while (fgets (buf, sizeof buf, in))
        fputs (buf, out);
      fclose (in);
    }
  fprintf (out, "%s:x:%u:%u:%s:%s:%s\n", u->name, u->uid, u->gid,
           u->gecos, u->home, u->shell);
  fflush (out); fsync (fd);
  if (fclose (out) != 0 || rename (tmp, path) != 0)
    { unlink (tmp); return -1; }
  chmod (path, 0644);
  (void) bpw_fsync_parent (path);
  return 0;
}

static int
bpw_file_delete_user (const char *path, const char *user)
{
  FILE *in = fopen (path, "r");
  if (!in) return errno == ENOENT ? 0 : -1;
  char tmp[512];
  int fd = bpw_temp_open (path, tmp, sizeof tmp, 0644);
  if (fd < 0) { fclose (in); return -1; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); fclose (in); return -1; }
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  while ((n = getline (&line, &cap, in)) > 0)
    {
      if (n && line[n - 1] == '\n') line[n - 1] = '\0';
      char *colon = strchr (line, ':');
      if (colon) *colon = '\0';
      int match = (strcmp (line, user) == 0);
      if (colon) *colon = ':';
      if (!match) fprintf (out, "%s\n", line);
    }
  free (line);
  fclose (in);
  fflush (out); fsync (fd);
  if (fclose (out) != 0 || rename (tmp, path) != 0)
    { unlink (tmp); return -1; }
  chmod (path, 0644);
  (void) bpw_fsync_parent (path);
  return 0;
}

static int
bpw_group_add_primary (const char *user, unsigned int gid)
{
  const char *path = bpw_group_path ();
  FILE *in = fopen (path, "r");
  if (!in && errno != ENOENT) return -1;
  char tmp[512];
  int fd = bpw_temp_open (path, tmp, sizeof tmp, 0644);
  if (fd < 0) { if (in) fclose (in); return -1; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); if (in) fclose (in); return -1; }
  if (in)
    {
      char buf[4096];
      while (fgets (buf, sizeof buf, in))
        fputs (buf, out);
      fclose (in);
    }
  fprintf (out, "%s:x:%u:\n", user, gid);
  fflush (out); fsync (fd);
  if (fclose (out) != 0 || rename (tmp, path) != 0)
    { unlink (tmp); return -1; }
  chmod (path, 0644);
  (void) bpw_fsync_parent (path);
  return 0;
}

static void
bpw_rollback_account (const char *user)
{
  (void) bpw_file_delete_user (bpw_passwd_path (), user);
  (void) bpw_shadow_delete (user);
  (void) bpw_file_delete_user (bpw_group_path (), user);
}

static int
bpw_read_fd_all (int fd, unsigned char **out, size_t *out_len)
{
  size_t cap = 128, len = 0;
  unsigned char *buf = malloc (cap);
  if (!buf) return -1;
  for (;;)
    {
      if (len == cap)
        {
          if (cap >= BPW_MAX_PASSWORD) { free (buf); errno = E2BIG; return -1; }
          cap *= 2;
          if (cap > BPW_MAX_PASSWORD) cap = BPW_MAX_PASSWORD;
          unsigned char *n = realloc (buf, cap);
          if (!n) { free (buf); return -1; }
          buf = n;
        }
      ssize_t r = read (fd, buf + len, cap - len);
      if (r < 0) { if (errno == EINTR) continue; free (buf); return -1; }
      if (r == 0) break;
      len += (size_t) r;
    }
  while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) len--;
  *out = buf;
  *out_len = len;
  return 0;
}

static int
bpw_read_tty_password (const char *prompt, unsigned char **out, size_t *out_len)
{
  int fd = open ("/dev/tty", O_RDWR | O_CLOEXEC);
  if (fd < 0)
    {
      if (!isatty (STDIN_FILENO))
        { builtin_error ("stdin is not a tty"); return -1; }
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
      tcsetattr (fd, TCSAFLUSH, &newt);
    }

  if (prompt && *prompt) write (fd == STDIN_FILENO ? STDERR_FILENO : fd, prompt, strlen (prompt));

  unsigned char *buf = mmap (NULL, BPW_MAX_PASSWORD, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buf == MAP_FAILED)
    {
      int err = errno;
      if (have_termios) tcsetattr (fd, TCSANOW, &oldt);
      write (fd == STDIN_FILENO ? STDERR_FILENO : fd, "\n", 1);
      if (fd != STDIN_FILENO) close (fd);
      errno = err;
      return -1;
    }
  if (mlock (buf, BPW_MAX_PASSWORD) < 0)
    ; /* best effort; Argon2 work area is still separately mlocked */

  size_t len = 0;
  int err = 0;
  for (;;)
    {
      unsigned char c;
      ssize_t r = read (fd, &c, 1);
      if (r < 0) { if (errno == EINTR) continue; err = errno; break; }
      if (r == 0 || c == '\n' || c == '\r') break;
      if (len >= BPW_MAX_PASSWORD) { err = E2BIG; break; }
      buf[len++] = c;
    }

  if (have_termios) tcsetattr (fd, TCSANOW, &oldt);
  write (fd == STDIN_FILENO ? STDERR_FILENO : fd, "\n", 1);
  if (fd != STDIN_FILENO) close (fd);

  if (err)
    {
      bpw_release_tty_password (buf);
      errno = err;
      return -1;
    }

  *out = buf;
  *out_len = len;
  return 0;
}

static int
bpw_read_tty_secret (const char *prompt, bpw_secret_ref *secret, size_t *out_len)
{
  int nr = bpw_secret_new (secret);
  if (nr)
    return nr;

  int fd = open ("/dev/tty", O_RDWR | O_CLOEXEC);
  if (fd < 0)
    {
      if (!isatty (STDIN_FILENO))
        {
          if (bpw_kernel_secrets_required ())
            builtin_error ("stdin is not a tty");
          bpw_secret_clear (secret);
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
      tcsetattr (fd, TCSAFLUSH, &newt);
    }

  if (prompt && *prompt)
    write (fd == STDIN_FILENO ? STDERR_FILENO : fd, prompt, strlen (prompt));

  size_t len = 0;
  int err = 0;
  for (;;)
    {
      unsigned char c = 0;
      ssize_t r = read (fd, &c, 1);
      if (r < 0) { if (errno == EINTR) continue; err = errno; break; }
      if (r == 0 || c == '\n' || c == '\r')
        {
          bpw_wipe (&c, sizeof c);
          break;
        }
      if (len >= BPW_MAX_PASSWORD) { err = E2BIG; bpw_wipe (&c, sizeof c); break; }
      if (bpw_secret_write (secret, &c, 1) < 0)
        { err = errno; bpw_wipe (&c, sizeof c); break; }
      bpw_wipe (&c, sizeof c);
      len++;
    }

  if (have_termios) tcsetattr (fd, TCSANOW, &oldt);
  write (fd == STDIN_FILENO ? STDERR_FILENO : fd, "\n", 1);
  if (fd != STDIN_FILENO) close (fd);

  if (err)
    {
      bpw_secret_clear (secret);
      errno = err;
      return -1;
    }
  if (bpw_secret_seal (secret) < 0)
    {
      int saved = errno;
      bpw_secret_clear (secret);
      errno = saved;
      return -1;
    }
  *out_len = len;
  return 0;
}

static int
bpw_read_tty_secret_on_auth_fd (int auth_fd, const char *prompt,
                                bpw_secret_ref *secret, size_t *out_len)
{
  int nr = bpw_secret_new_on_fd (auth_fd, secret);
  if (nr)
    return nr;

  int fd = open ("/dev/tty", O_RDWR | O_CLOEXEC);
  if (fd < 0)
    {
      if (!isatty (STDIN_FILENO))
        {
          builtin_error ("stdin is not a tty");
          bpw_secret_clear (secret);
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
      tcsetattr (fd, TCSAFLUSH, &newt);
    }

  if (prompt && *prompt)
    write (fd == STDIN_FILENO ? STDERR_FILENO : fd, prompt, strlen (prompt));

  size_t len = 0;
  int err = 0;
  for (;;)
    {
      unsigned char c = 0;
      ssize_t r = read (fd, &c, 1);
      if (r < 0) { if (errno == EINTR) continue; err = errno; break; }
      if (r == 0 || c == '\n' || c == '\r')
        {
          bpw_wipe (&c, sizeof c);
          break;
        }
      if (len >= BPW_MAX_PASSWORD) { err = E2BIG; bpw_wipe (&c, sizeof c); break; }
      if (bpw_secret_write (secret, &c, 1) < 0)
        { err = errno; bpw_wipe (&c, sizeof c); break; }
      bpw_wipe (&c, sizeof c);
      len++;
    }

  if (have_termios) tcsetattr (fd, TCSANOW, &oldt);
  write (fd == STDIN_FILENO ? STDERR_FILENO : fd, "\n", 1);
  if (fd != STDIN_FILENO) close (fd);

  if (err)
    {
      bpw_secret_clear (secret);
      errno = err;
      return -1;
    }
  if (bpw_secret_seal (secret) < 0)
    {
      int saved = errno;
      bpw_secret_clear (secret);
      errno = saved;
      return -1;
    }
  *out_len = len;
  return 0;
}

static int
bpw_read_fd_secret (int input_fd, bpw_secret_ref *secret, size_t *out_len)
{
  int nr = bpw_secret_new (secret);
  if (nr)
    return nr;

  size_t len = 0, pending_eol = 0;
  int err = 0;
  for (;;)
    {
      unsigned char c = 0;
      ssize_t r = read (input_fd, &c, 1);
      if (r < 0) { if (errno == EINTR) continue; err = errno; break; }
      if (r == 0)
        {
          bpw_wipe (&c, sizeof c);
          break;
        }
      if (c == '\n' || c == '\r')
        {
          if (len + pending_eol >= BPW_MAX_PASSWORD)
            { err = E2BIG; bpw_wipe (&c, sizeof c); break; }
          pending_eol++;
          bpw_wipe (&c, sizeof c);
          continue;
        }
      while (pending_eol)
        {
          unsigned char nl = '\n';
          if (bpw_secret_write (secret, &nl, 1) < 0)
            { err = errno; bpw_wipe (&nl, sizeof nl); break; }
          bpw_wipe (&nl, sizeof nl);
          len++;
          pending_eol--;
        }
      if (err) { bpw_wipe (&c, sizeof c); break; }
      if (len >= BPW_MAX_PASSWORD) { err = E2BIG; bpw_wipe (&c, sizeof c); break; }
      if (bpw_secret_write (secret, &c, 1) < 0)
        { err = errno; bpw_wipe (&c, sizeof c); break; }
      bpw_wipe (&c, sizeof c);
      len++;
    }

  if (err)
    {
      bpw_secret_clear (secret);
      errno = err;
      return -1;
    }
  if (bpw_secret_seal (secret) < 0)
    {
      int saved = errno;
      bpw_secret_clear (secret);
      errno = saved;
      return -1;
    }
  *out_len = len;
  return 0;
}

static int
bpw_read_new_password_secret (bpw_secret_ref *secret, size_t *out_len)
{
  int auth_fd = bpw_auth_open_optional ();
  if (auth_fd < 0)
    return bpw_kernel_secrets_required () ? -1 : -2;

  bpw_secret_ref a = { -1, 0, 0 }, b = { -1, 0, 0 };
  size_t al = 0, bl = 0;
  int ar = bpw_read_tty_secret_on_auth_fd (auth_fd, "New password: ", &a, &al);
  if (ar)
    {
      close (auth_fd);
      return ar;
    }
  int br = bpw_read_tty_secret_on_auth_fd (auth_fd, "Retype new password: ", &b, &bl);
  if (br)
    {
      bpw_secret_clear (&a);
      close (auth_fd);
      return br;
    }
  int same = (al == bl) ? bpw_secret_same (&a, &b) : 0;
  bpw_secret_clear (&b);
  if (same != 1)
    {
      bpw_secret_clear (&a);
      close (auth_fd);
      if (same < 0)
        builtin_error ("kernel secret compare: %s", strerror (errno));
      else
        builtin_error ("passwords do not match");
      return -1;
    }
  if (al == 0)
    {
      bpw_secret_clear (&a);
      close (auth_fd);
      builtin_error ("empty password rejected");
      return -1;
    }
  a.owns_fd = 1;
  *secret = a;
  *out_len = al;
  return 0;
}

static int
bpw_hash_secret_ref (bpw_secret_ref *secret, char *out, size_t outsz)
{
  unsigned char *pw = NULL;
  size_t pw_len = 0;
  if (bpw_secret_export_once (secret, &pw, &pw_len) < 0)
    return -1;
  int rc = bpw_hash_secret (pw, pw_len, out, outsz);
  bpw_release_tty_password (pw);
  return rc;
}

static int
bpw_verify_user_secret_ref (const char *user, bpw_secret_ref *secret)
{
  unsigned char *pw = NULL;
  size_t pw_len = 0;
  if (bpw_secret_export_once (secret, &pw, &pw_len) < 0)
    return 2;
  int rc = bpw_verify_user_buf (user, pw, pw_len);
  bpw_release_tty_password (pw);
  return rc;
}

static int
bpw_verify_user_buf (const char *user, const unsigned char *pw, size_t pw_len)
{
  if (bpw_check_lockout (user) < 0) return 1;
  char phc[512];
  if (bpw_shadow_phc (user, phc, sizeof phc) != 0) return 2;
  int r = bpw_verify_secret (pw, pw_len, phc);
  if (r == 0) bpw_record_success (user);
  else if (r == 1) bpw_record_failure (user);
  return r == 0 ? 0 : (r == 1 ? 1 : 2);
}

static int
bpw_verify_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("verify needs USER"); return EX_USAGE; }
  const char *user = args->word->word;
  bpw_secret_ref secret = { -1, 0, 0 };
  size_t secret_len = 0;
  int sr = bpw_read_tty_secret ("Password: ", &secret, &secret_len);
  if (sr == 0)
    {
      int rc = bpw_verify_user_secret_ref (user, &secret);
      bpw_secret_clear (&secret);
      return rc == 0 ? EXECUTION_SUCCESS : (rc == 1 ? EXECUTION_FAILURE : EX_USAGE);
    }
  if (sr != -2)
    {
      builtin_error ("password read: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  unsigned char *pw = NULL;
  size_t pw_len = 0;
  if (bpw_read_tty_password ("Password: ", &pw, &pw_len) < 0)
    { builtin_error ("password read: %s", strerror (errno)); return EXECUTION_FAILURE; }
  int rc = bpw_verify_user_buf (user, pw, pw_len);
  bpw_release_tty_password (pw);
  return rc == 0 ? EXECUTION_SUCCESS : (rc == 1 ? EXECUTION_FAILURE : EX_USAGE);
}

static int
bpw_verify_fd_cmd (WORD_LIST *args)
{
  if (!args || !args->next) { builtin_error ("verify-fd needs USER FD"); return EX_USAGE; }
  const char *user = args->word->word;
  int fd = atoi (args->next->word->word);
  if (fd < 0) { builtin_error ("bad fd"); return EX_USAGE; }
  bpw_secret_ref secret = { -1, 0, 0 };
  size_t secret_len = 0;
  int sr = bpw_read_fd_secret (fd, &secret, &secret_len);
  if (sr == 0)
    {
      int rc = bpw_verify_user_secret_ref (user, &secret);
      bpw_secret_clear (&secret);
      return rc == 0 ? EXECUTION_SUCCESS : (rc == 1 ? EXECUTION_FAILURE : EX_USAGE);
    }
  if (sr != -2)
    { builtin_error ("fd read: %s", strerror (errno)); return EXECUTION_FAILURE; }
  unsigned char *pw = NULL;
  size_t pw_len = 0;
  if (bpw_read_fd_all (fd, &pw, &pw_len) < 0)
    { builtin_error ("fd read: %s", strerror (errno)); return EXECUTION_FAILURE; }
  int rc = bpw_verify_user_buf (user, pw, pw_len);
  bpw_wipe (pw, pw_len);
  free (pw);
  return rc == 0 ? EXECUTION_SUCCESS : (rc == 1 ? EXECUTION_FAILURE : EX_USAGE);
}

static int
bpw_lock_cmd (WORD_LIST *args)
{
  if (!args || args->next) { builtin_error ("lock needs USER"); return EX_USAGE; }
  char phc[512];
  int r = bpw_shadow_phc (args->word->word, phc, sizeof phc);
  if (r == 0)
    {
      char locked[560];
      snprintf (locked, sizeof locked, "!%s", phc);
      return bpw_shadow_set (args->word->word, locked, 0) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  return bpw_shadow_set (args->word->word, "!", 1) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bpw_unlock_cmd (WORD_LIST *args)
{
  if (!args || args->next) { builtin_error ("unlock needs USER"); return EX_USAGE; }
  const char *path = bpw_shadow_path ();
  FILE *f = fopen (path, "r");
  if (!f) { builtin_error ("open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  char hash[512] = {0};
  while ((n = getline (&line, &cap, f)) > 0)
    {
      if (n && line[n - 1] == '\n') line[n - 1] = '\0';
      char *colon = strchr (line, ':');
      if (!colon) continue;
      *colon = '\0';
      if (strcmp (line, args->word->word) != 0) continue;
      char *h = colon + 1;
      char *next = strchr (h, ':');
      if (next) *next = '\0';
      while (*h == '!') h++;
      snprintf (hash, sizeof hash, "%s", h);
      break;
    }
  free (line);
  fclose (f);
  if (!hash[0] || hash[0] == '*')
    { builtin_error ("cannot unlock without a stored hash"); return EXECUTION_FAILURE; }
  return bpw_shadow_set (args->word->word, hash, 0) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bpw_delete_cmd (WORD_LIST *args)
{
  if (!args || args->next) { builtin_error ("delete needs USER"); return EX_USAGE; }
  const char *user = args->word->word;
  int rc = 0;
  if (bpw_file_delete_user (bpw_passwd_path (), user) < 0) rc = -1;
  if (bpw_shadow_delete (user) < 0) rc = -1;
  if (bpw_file_delete_user (bpw_group_path (), user) < 0) rc = -1;
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bpw_info_cmd (WORD_LIST *args)
{
  if (!args || args->next) { builtin_error ("info needs USER"); return EX_USAGE; }
  bpw_user u;
  if (bpw_lookup_user (args->word->word, &u) < 0)
    { builtin_error ("no passwd entry for %s", args->word->word); return EXECUTION_FAILURE; }
  char phc[512];
  const char *state = "NP";
  if (bpw_shadow_phc (u.name, phc, sizeof phc) == 0) state = "P";
  else
    {
      FILE *f = fopen (bpw_shadow_path (), "r");
      if (f)
        {
          char *line = NULL; size_t cap = 0; ssize_t n;
          while ((n = getline (&line, &cap, f)) > 0)
            {
              if (n && line[n - 1] == '\n') line[n - 1] = '\0';
              char *colon = strchr (line, ':');
              if (!colon) continue;
              *colon = '\0';
              if (strcmp (line, u.name) == 0)
                {
                  char *h = colon + 1;
                  if (*h == '!' || *h == '*') state = "L";
                  break;
                }
            }
          free (line); fclose (f);
        }
    }
  printf ("%s uid=%u gid=%u home=%s shell=%s password=%s\n",
          u.name, u.uid, u.gid, u.home, u.shell, state);
  return EXECUTION_SUCCESS;
}

static int
bpw_list_cmd (WORD_LIST *args)
{
  int long_out = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      if (strcmp (p->word->word, "-l") == 0) long_out = 1;
      else { builtin_error ("list: unexpected arg %s", p->word->word); return EX_USAGE; }
    }
  FILE *f = fopen (bpw_passwd_path (), "r");
  if (!f) { builtin_error ("open passwd: %s", strerror (errno)); return EXECUTION_FAILURE; }
  char *line = NULL; size_t cap = 0; ssize_t n;
  while ((n = getline (&line, &cap, f)) > 0)
    {
      if (n && line[n - 1] == '\n') line[n - 1] = '\0';
      char *copy = strdup (line);
      if (!copy) continue;
      char *save = NULL;
      char *name = strtok_r (copy, ":", &save);
      strtok_r (NULL, ":", &save);
      char *uid = strtok_r (NULL, ":", &save);
      char *gid = strtok_r (NULL, ":", &save);
      strtok_r (NULL, ":", &save);
      char *home = strtok_r (NULL, ":", &save);
      char *shell = strtok_r (NULL, ":", &save);
      if (name)
        {
          if (long_out)
            printf ("%s:%s:%s:%s:%s\n", name, uid ? uid : "", gid ? gid : "",
                    home ? home : "", shell ? shell : "");
          else
            printf ("%s\n", name);
        }
      free (copy);
    }
  free (line);
  fclose (f);
  return EXECUTION_SUCCESS;
}

static int
bpw_expire_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("expire needs USER [DAYS]"); return EX_USAGE; }
  const char *user = args->word->word;
  const char *days = args->next ? args->next->word->word : "0";
  if (args->next && args->next->next) { builtin_error ("expire: too many args"); return EX_USAGE; }

  const char *path = bpw_shadow_path ();
  FILE *in = fopen (path, "r");
  if (!in) { builtin_error ("open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
  char tmp[512];
  int fd = bpw_temp_open (path, tmp, sizeof tmp, 0600);
  if (fd < 0) { fclose (in); return EXECUTION_FAILURE; }
  FILE *out = fdopen (fd, "w");
  if (!out) { close (fd); unlink (tmp); fclose (in); return EXECUTION_FAILURE; }
  char *line = NULL; size_t cap = 0; ssize_t n; int found = 0;
  while ((n = getline (&line, &cap, in)) > 0)
    {
      if (n && line[n - 1] == '\n') line[n - 1] = '\0';
      char *copy = strdup (line);
      char *name = copy;
      char *c1 = copy ? strchr (copy, ':') : NULL;
      char *hash = c1 ? c1 + 1 : NULL;
      char *c2 = hash ? strchr (hash, ':') : NULL;
      if (c1)
        *c1 = '\0';
      if (name && strcmp (name, user) == 0)
        {
          found = 1;
          if (c2)
            {
              *c2 = '\0';
              char *aging = c2 + 1;
              char *after_lastchg = strchr (aging, ':');
              if (after_lastchg)
                fprintf (out, "%s:%s:%s:%s\n", name, hash ? hash : "", days,
                         after_lastchg + 1);
              else
                fprintf (out, "%s:%s:%s:0:99999:7:::\n", name,
                         hash ? hash : "", days);
            }
          else
            fprintf (out, "%s:%s:%s:0:99999:7:::\n", name, hash ? hash : "", days);
        }
      else
        fprintf (out, "%s\n", line);
      free (copy);
    }
  free (line); fclose (in);
  fflush (out); fsync (fd);
  if (fclose (out) != 0 || rename (tmp, path) != 0)
    { unlink (tmp); return EXECUTION_FAILURE; }
  chmod (path, 0600);
  (void) bpw_fsync_parent (path);
  return found ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bpw_set_cmd (WORD_LIST *args)
{
  if (!args || args->next) { builtin_error ("set needs USER"); return EX_USAGE; }
  bpw_secret_ref secret = { -1, 0, 0 };
  size_t secret_len = 0;
  int sr = bpw_read_new_password_secret (&secret, &secret_len);
  if (sr == 0)
    {
      char phc[512];
      int rc = bpw_hash_secret_ref (&secret, phc, sizeof phc);
      bpw_secret_clear (&secret);
      if (rc < 0) return EXECUTION_FAILURE;
      return bpw_shadow_set (args->word->word, phc, 1) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (sr != -2)
    return EXECUTION_FAILURE;
  unsigned char *pw = NULL; size_t pw_len = 0;
  if (bpw_read_new_password (&pw, &pw_len) < 0) return EXECUTION_FAILURE;
  char phc[512];
  int rc = bpw_hash_secret (pw, pw_len, phc, sizeof phc);
  bpw_release_tty_password (pw);
  if (rc < 0) return EXECUTION_FAILURE;
  return bpw_shadow_set (args->word->word, phc, 1) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bpw_set_fd_cmd (WORD_LIST *args)
{
  if (!args || !args->next) { builtin_error ("set-fd needs USER FD"); return EX_USAGE; }
  int fd = atoi (args->next->word->word);
  bpw_secret_ref secret = { -1, 0, 0 };
  size_t secret_len = 0;
  int sr = bpw_read_fd_secret (fd, &secret, &secret_len);
  if (sr == 0)
    {
      if (secret_len == 0)
        { bpw_secret_clear (&secret); builtin_error ("empty password rejected"); return EXECUTION_FAILURE; }
      char phc[512];
      int rc = bpw_hash_secret_ref (&secret, phc, sizeof phc);
      bpw_secret_clear (&secret);
      if (rc < 0) return EXECUTION_FAILURE;
      return bpw_shadow_set (args->word->word, phc, 1) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (sr != -2)
    return EXECUTION_FAILURE;
  unsigned char *pw = NULL; size_t pw_len = 0;
  if (bpw_read_fd_all (fd, &pw, &pw_len) < 0) return EXECUTION_FAILURE;
  if (pw_len == 0) { free (pw); builtin_error ("empty password rejected"); return EXECUTION_FAILURE; }
  char phc[512];
  int rc = bpw_hash_secret (pw, pw_len, phc, sizeof phc);
  bpw_wipe (pw, pw_len); free (pw);
  if (rc < 0) return EXECUTION_FAILURE;
  return bpw_shadow_set (args->word->word, phc, 1) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bpw_change_cmd (WORD_LIST *args)
{
  const char *user = args ? args->word->word : getenv ("USER");
  if (!user || !*user) user = "root";
  if (args && args->next) { builtin_error ("change takes at most USER"); return EX_USAGE; }
  bpw_secret_ref secret = { -1, 0, 0 };
  size_t secret_len = 0;
  int sr = bpw_read_tty_secret ("Current password: ", &secret, &secret_len);
  if (sr == 0)
    {
      int v = bpw_verify_user_secret_ref (user, &secret);
      bpw_secret_clear (&secret);
      if (v != 0) { builtin_error ("authentication failure"); return EXECUTION_FAILURE; }
      return bpw_set_cmd (args);
    }
  if (sr != -2)
    return EXECUTION_FAILURE;
  unsigned char *old = NULL; size_t old_len = 0;
  if (bpw_read_tty_password ("Current password: ", &old, &old_len) < 0)
    return EXECUTION_FAILURE;
  int v = bpw_verify_user_buf (user, old, old_len);
  bpw_release_tty_password (old);
  if (v != 0) { builtin_error ("authentication failure"); return EXECUTION_FAILURE; }
  return bpw_set_cmd (args);
}

static int
bpw_add_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("add needs USER"); return EX_USAGE; }
  bpw_user u;
  memset (&u, 0, sizeof u);
  snprintf (u.name, sizeof u.name, "%s", args->word->word);
  u.uid = 1000; u.gid = 1000;
  snprintf (u.gecos, sizeof u.gecos, "%s", u.name);
  snprintf (u.home, sizeof u.home, "/home/%s", u.name);
  snprintf (u.shell, sizeof u.shell, "/bin/bash");

  for (WORD_LIST *p = args->next; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-u") == 0 && p->next) { p = p->next; u.uid = (unsigned int) strtoul (p->word->word, NULL, 10); }
      else if (strcmp (w, "-g") == 0 && p->next) { p = p->next; u.gid = (unsigned int) strtoul (p->word->word, NULL, 10); }
      else if (strcmp (w, "-d") == 0 && p->next) { p = p->next; snprintf (u.home, sizeof u.home, "%s", p->word->word); }
      else if (strcmp (w, "-s") == 0 && p->next) { p = p->next; snprintf (u.shell, sizeof u.shell, "%s", p->word->word); }
      else { builtin_error ("add: unexpected arg %s", w); return EX_USAGE; }
    }

  bpw_secret_ref secret = { -1, 0, 0 };
  size_t secret_len = 0;
  int sr = bpw_read_new_password_secret (&secret, &secret_len);
  if (sr == 0)
    {
      char phc[512];
      int rc = bpw_hash_secret_ref (&secret, phc, sizeof phc);
      bpw_secret_clear (&secret);
      if (rc < 0) return EXECUTION_FAILURE;
      if (bpw_passwd_add (&u) < 0) return EXECUTION_FAILURE;
      if (bpw_group_add_primary (u.name, u.gid) < 0 ||
          bpw_shadow_set (u.name, phc, 1) < 0)
        {
          bpw_rollback_account (u.name);
          return EXECUTION_FAILURE;
        }
      return EXECUTION_SUCCESS;
    }
  if (sr != -2)
    return EXECUTION_FAILURE;
  unsigned char *pw = NULL; size_t pw_len = 0;
  if (bpw_read_new_password (&pw, &pw_len) < 0) return EXECUTION_FAILURE;
  char phc[512];
  int rc = bpw_hash_secret (pw, pw_len, phc, sizeof phc);
  bpw_release_tty_password (pw);
  if (rc < 0) return EXECUTION_FAILURE;
  if (bpw_passwd_add (&u) < 0) return EXECUTION_FAILURE;
  if (bpw_group_add_primary (u.name, u.gid) < 0 ||
      bpw_shadow_set (u.name, phc, 1) < 0)
    {
      bpw_rollback_account (u.name);
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
bpw_add_fd_cmd (WORD_LIST *args)
{
  if (!args || !args->next) { builtin_error ("add-fd needs USER FD"); return EX_USAGE; }
  char fdword[32];
  snprintf (fdword, sizeof fdword, "%s", args->next->word->word);

  bpw_user u;
  memset (&u, 0, sizeof u);
  snprintf (u.name, sizeof u.name, "%s", args->word->word);
  u.uid = 1000; u.gid = 1000;
  snprintf (u.gecos, sizeof u.gecos, "%s", u.name);
  snprintf (u.home, sizeof u.home, "/home/%s", u.name);
  snprintf (u.shell, sizeof u.shell, "/bin/bash");
  for (WORD_LIST *p = args->next->next; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-u") == 0 && p->next) { p = p->next; u.uid = (unsigned int) strtoul (p->word->word, NULL, 10); }
      else if (strcmp (w, "-g") == 0 && p->next) { p = p->next; u.gid = (unsigned int) strtoul (p->word->word, NULL, 10); }
      else if (strcmp (w, "-d") == 0 && p->next) { p = p->next; snprintf (u.home, sizeof u.home, "%s", p->word->word); }
      else if (strcmp (w, "-s") == 0 && p->next) { p = p->next; snprintf (u.shell, sizeof u.shell, "%s", p->word->word); }
      else { builtin_error ("add-fd: unexpected arg %s", w); return EX_USAGE; }
    }
  int fd = atoi (fdword);
  bpw_secret_ref secret = { -1, 0, 0 };
  size_t secret_len = 0;
  int sr = bpw_read_fd_secret (fd, &secret, &secret_len);
  if (sr == 0)
    {
      if (secret_len == 0) { bpw_secret_clear (&secret); builtin_error ("empty password rejected"); return EXECUTION_FAILURE; }
      char phc[512];
      int rc = bpw_hash_secret_ref (&secret, phc, sizeof phc);
      bpw_secret_clear (&secret);
      if (rc < 0) return EXECUTION_FAILURE;
      if (bpw_passwd_add (&u) < 0) return EXECUTION_FAILURE;
      if (bpw_group_add_primary (u.name, u.gid) < 0 ||
          bpw_shadow_set (u.name, phc, 1) < 0)
        {
          bpw_rollback_account (u.name);
          return EXECUTION_FAILURE;
        }
      return EXECUTION_SUCCESS;
    }
  if (sr != -2)
    return EXECUTION_FAILURE;
  unsigned char *pw = NULL; size_t pw_len = 0;
  if (bpw_read_fd_all (fd, &pw, &pw_len) < 0) return EXECUTION_FAILURE;
  if (pw_len == 0) { free (pw); builtin_error ("empty password rejected"); return EXECUTION_FAILURE; }
  char phc[512];
  int rc = bpw_hash_secret (pw, pw_len, phc, sizeof phc);
  bpw_wipe (pw, pw_len); free (pw);
  if (rc < 0) return EXECUTION_FAILURE;
  if (bpw_passwd_add (&u) < 0) return EXECUTION_FAILURE;
  if (bpw_group_add_primary (u.name, u.gid) < 0 ||
      bpw_shadow_set (u.name, phc, 1) < 0)
    {
      bpw_rollback_account (u.name);
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

extern char *passwd_doc[];

int
passwd_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  if (strcmp (cmd, "--help") == 0 || strcmp (cmd, "-h") == 0) {
      char **d;
      for (d = passwd_doc; *d; d++) puts (*d);
      return EXECUTION_SUCCESS;
  }
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "add") == 0) return bpw_add_cmd (args);
  if (strcmp (cmd, "add-fd") == 0) return bpw_add_fd_cmd (args);
  if (strcmp (cmd, "change") == 0) return bpw_change_cmd (args);
  if (strcmp (cmd, "set") == 0) return bpw_set_cmd (args);
  if (strcmp (cmd, "set-fd") == 0) return bpw_set_fd_cmd (args);
  if (strcmp (cmd, "delete") == 0) return bpw_delete_cmd (args);
  if (strcmp (cmd, "lock") == 0) return bpw_lock_cmd (args);
  if (strcmp (cmd, "unlock") == 0) return bpw_unlock_cmd (args);
  if (strcmp (cmd, "list") == 0) return bpw_list_cmd (args);
  if (strcmp (cmd, "expire") == 0) return bpw_expire_cmd (args);
  if (strcmp (cmd, "info") == 0) return bpw_info_cmd (args);
  if (strcmp (cmd, "verify") == 0) return bpw_verify_cmd (args);
  if (strcmp (cmd, "verify-fd") == 0) return bpw_verify_fd_cmd (args);
  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *passwd_doc[] = {
  "Password and account management for bash-os.",
  "",
  "    passwd add USER [-u UID] [-g GID] [-d HOME] [-s SHELL]",
  "    passwd add-fd USER FD [-u UID] [-g GID] [-d HOME] [-s SHELL]",
  "    passwd change [USER]",
  "    passwd set USER",
  "    passwd set-fd USER FD",
  "    passwd delete USER",
  "    passwd lock USER",
  "    passwd unlock USER",
  "    passwd list [-l]",
  "    passwd expire USER [DAYS]",
  "    passwd info USER",
  "    passwd verify USER",
  "        Prompt on /dev/tty and verify USER's password.",
  "",
  "    passwd verify-fd USER FD",
  "        Read password bytes from FD and verify USER.",
  "",
  "Password bytes are handled in C-owned buffers and wiped after use.",
  (char *)NULL
};

struct builtin passwd_struct = {
  "passwd",
  passwd_builtin,
  BUILTIN_ENABLED,
  passwd_doc,
  "passwd add|change|set|delete|lock|unlock|list|expire|info|verify|verify-fd ...",
  0
};
