/* SPDX-License-Identifier: MIT */
/* su.c - C-owned password prompt, PHC verify, and switch-user exec.
 *
 * This is the narrow bash-os su slice from the kernel-mediated secrets
 * authority plan: password bytes live in C-owned memory only, verification
 * reuses the local Argon2id PHC format, and the privilege transition is kept
 * inside the builtin instead of shell control flow.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>

#include "_monocypher_monocypher-ed25519.h"
#include "_bashauth_pwverify.h"
#include "_bashauth_cred_exec.h"
#include "_bashauth_passwd_lookup.h"
#include "_bashauth_secure_read.h"
#include "bashcred_privdrop.h"
#include "loadables.h"

#define BSU_MAX_PASSWORD 4096
#define BSU_LOCK_FAIL_MAX 5
#define BSU_LOCK_WINDOW 600
#define BSU_LOCK_DURATION 900
#define BSU_AUTH_IOC_MAGIC 0xBA
#define BSU_AUTH_DEV "/dev/bashos-auth"
#define BSU_AUTH_TOKEN_BYTES 32
#define BSU_AUTH_USER_BYTES 64
#define BSU_AUTH_TOKEN_SU 2

struct bsu_auth_token_req {
  unsigned int uid;
  unsigned int gid;
  unsigned int purpose;
  unsigned int expires_sec;
  unsigned char token[BSU_AUTH_TOKEN_BYTES];
  char user[BSU_AUTH_USER_BYTES];
  unsigned int flags;
  unsigned int reserved;
};

#define BSU_AUTH_IOC_MINT_TOKEN \
  _IOWR(BSU_AUTH_IOC_MAGIC, 0x08, struct bsu_auth_token_req)
#define BSU_AUTH_IOC_CONSUME_TOKEN \
  _IOW(BSU_AUTH_IOC_MAGIC, 0x09, struct bsu_auth_token_req)

typedef struct {
  unsigned int m, t, p;
  char salt_hex[129];
  char hash_hex[257];
} bsu_phc;

static void
bsu_wipe (void *p, size_t n)
{
  if (p && n) crypto_wipe (p, n);
}

static int
bsu_auth_fill_token_req (struct bsu_auth_token_req *req,
                         const bc_user_info *u)
{
  memset (req, 0, sizeof *req);
  req->uid = (unsigned int) u->uid;
  req->gid = (unsigned int) u->gid;
  req->purpose = BSU_AUTH_TOKEN_SU;
  strncpy (req->user, u->name, sizeof req->user - 1);
  return 0;
}

static int
bsu_consume_auth_token_fd (int fd, const bc_user_info *u,
                           const unsigned char token[BSU_AUTH_TOKEN_BYTES])
{
  struct bsu_auth_token_req req;
  bsu_auth_fill_token_req (&req, u);
  memcpy (req.token, token, BSU_AUTH_TOKEN_BYTES);
  int rc = ioctl (fd, BSU_AUTH_IOC_CONSUME_TOKEN, &req);
  bsu_wipe (&req, sizeof req);
  return rc;
}

static int
bsu_kernel_proof (const bc_user_info *u)
{
  int fd = open (BSU_AUTH_DEV, O_RDWR | O_CLOEXEC);
  if (fd < 0)
    {
      builtin_error ("kernel auth: %s: %s", BSU_AUTH_DEV, strerror (errno));
      return -1;
    }
  int fl = fcntl (fd, F_GETFD, 0);
  if (fl >= 0)
    (void) fcntl (fd, F_SETFD, fl | FD_CLOEXEC);

  struct bsu_auth_token_req req;
  bsu_auth_fill_token_req (&req, u);
  req.expires_sec = 5;
  if (ioctl (fd, BSU_AUTH_IOC_MINT_TOKEN, &req) < 0)
    {
      builtin_error ("kernel auth token mint failed: %s", strerror (errno));
      bsu_wipe (&req, sizeof req);
      close (fd);
      return -1;
    }

  if (bsu_consume_auth_token_fd (fd, u, req.token) < 0)
    {
      builtin_error ("kernel auth token rejected: %s", strerror (errno));
      bsu_wipe (&req, sizeof req);
      close (fd);
      return -1;
    }

  bsu_wipe (&req, sizeof req);
  close (fd);
  return 0;
}

static const char *
bsu_shadow_path (void)
{
  const char *path = getenv ("PHCLIB_SHADOW");
  if (!path || !*path) path = getenv ("SHADOW_FILE");
  if (!path || !*path) path = "/etc/shadow";
  return path;
}

static const char *
bsu_passwd_path (void)
{
  const char *path = getenv ("PHCLIB_PASSWD");
  if (!path || !*path) path = getenv ("PASSWD_FILE");
  if (!path || !*path) path = "/etc/passwd";
  return path;
}

static int
bsu_hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
bsu_valid_user_name (const char *user)
{
  return bashos_valid_user_name (user);
}

static int
bsu_unhex (const char *hex, unsigned char *out, size_t outsz)
{
  size_t o = 0;
  int hi = -1;
  for (const char *p = hex; *p; p++)
    {
      int v = bsu_hexval ((unsigned char) *p);
      if (v < 0) return -1;
      if (hi < 0) { hi = v; continue; }
      if (o >= outsz) return -1;
      out[o++] = (unsigned char) ((hi << 4) | v);
      hi = -1;
    }
  return hi < 0 ? (int) o : -1;
}

static void
bsu_print_hex (const unsigned char *buf, size_t n, char *out)
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
bsu_parse_phc (const char *phc, bsu_phc *out)
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
bsu_shadow_phc (const char *user, char *out, size_t outsz)
{
  int rc = bashos_read_shadow_phc (user, out, outsz);
  if (rc == -2)
    builtin_error ("%s is locked or has no password", user);
  else if (rc == -1)
    builtin_error ("no shadow entry for %s", user);
  return rc;
}

static int
bsu_user_uid_token (const char *user, char *out, size_t outsz)
{
  FILE *f = fopen (bsu_passwd_path (), "r");
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
bsu_lock_dir (void)
{
  const char *d = getenv ("BPW_LOCK_DIR");
  if (!d || !*d) d = "/run/login";
  return d;
}

static int
bsu_lock_path (const char *user, char *out, size_t outsz)
{
  char tok[64];
  if (bsu_user_uid_token (user, tok, sizeof tok) < 0) return -1;
  snprintf (out, outsz, "%s/fail.%s", bsu_lock_dir (), tok);
  return 0;
}

static void
bsu_read_lock_state (const char *path, int *count, long *last, long *locked_until)
{
  *count = 0;
  *last = 0;
  *locked_until = 0;
  FILE *f = fopen (path, "r");
  if (!f) return;
  char line[128];
  while (fgets (line, sizeof line, f))
    {
      if (strncmp (line, "COUNT=", 6) == 0) *count = atoi (line + 6);
      else if (strncmp (line, "LAST=", 5) == 0) *last = strtol (line + 5, NULL, 10);
      else if (strncmp (line, "LOCKED_UNTIL=", 13) == 0) *locked_until = strtol (line + 13, NULL, 10);
    }
  fclose (f);
}

static int
bsu_check_lockout (const char *user)
{
  char path[256];
  if (bsu_lock_path (user, path, sizeof path) < 0) return 0;
  int count;
  long last, locked_until;
  bsu_read_lock_state (path, &count, &last, &locked_until);
  (void) count;
  (void) last;
  long now = (long) time (NULL);
  if (locked_until > now)
    {
      builtin_error ("account locked; try again in %ld seconds", locked_until - now);
      return -1;
    }
  return 0;
}

static void
bsu_record_failure (const char *user)
{
  const char *dir = bsu_lock_dir ();
  if (mkdir (dir, 0700) < 0 && errno != EEXIST) return;
  char path[256], tmp[512];
  if (bsu_lock_path (user, path, sizeof path) < 0) return;
  int count;
  long last, locked_until;
  bsu_read_lock_state (path, &count, &last, &locked_until);
  long now = (long) time (NULL);
  if (now - last > BSU_LOCK_WINDOW) count = 0;
  count++;
  last = now;
  locked_until = (count >= BSU_LOCK_FAIL_MAX) ? now + BSU_LOCK_DURATION : 0;
  snprintf (tmp, sizeof tmp, "%s.tmp.%ld", path, (long) getpid ());
  int fd = open (tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) return;
  FILE *f = fdopen (fd, "w");
  if (!f) { close (fd); unlink (tmp); return; }
  fprintf (f, "COUNT=%d\nLAST=%ld\nLOCKED_UNTIL=%ld\n", count, last, locked_until);
  fflush (f);
  fsync (fd);
  fclose (f);
  rename (tmp, path);
}

static void
bsu_record_success (const char *user)
{
  char path[256];
  if (bsu_lock_path (user, path, sizeof path) == 0) unlink (path);
}

static int
bsu_verify_secret (const unsigned char *pw, size_t pw_len, const char *phc)
{
  int rc = bashos_verify_phc_secret (pw, pw_len, phc);
  if (rc < 0)
    builtin_error ("unsupported or malformed PHC string");
  return rc;
}

static void
bsu_free_password (unsigned char *buf)
{
  bashos_secure_free_password (buf);
}

static int
bsu_secure_read_password (const char *prompt, unsigned char **out, size_t *out_len)
{
  return bashos_secure_read_password (prompt, out, out_len);
}

static int
bsu_verify_user_interactive (const char *user)
{
  if (bsu_check_lockout (user) < 0) return 1;
  char phc[512];
  if (bsu_shadow_phc (user, phc, sizeof phc) != 0) return 2;
  unsigned char *pw = NULL;
  size_t pw_len = 0;
  if (bsu_secure_read_password ("Password: ", &pw, &pw_len) < 0)
    { builtin_error ("password read: %s", strerror (errno)); return 2; }
  int r = bsu_verify_secret (pw, pw_len, phc);
  bsu_free_password (pw);
  if (r == 0) bsu_record_success (user);
  else if (r == 1) bsu_record_failure (user);
  return r == 0 ? 0 : (r == 1 ? 1 : 2);
}

static int
bsu_exec_user (const bc_user_info *u, int keep_env, int login_shell, const char *cmd)
{
  char err[BC_PD_ERR_MAX];
  if (bsu_kernel_proof (u) < 0)
    return EXECUTION_FAILURE;

  /* Load the TARGET user's full group membership (initgroups(3) semantics, as
     su(1)/login(1) and doas already do) so the dropped process carries
     supplementary groups such as `wheel`. The kernel PRIVCMD %group matcher reads
     the LIVE process credential, NOT /etc/group — so without this a wheel member
     silently fails a `%wheel NOPASSWD` sudo rule. Only this setgroups (run while
     still root, inside bc_privdrop_to_user) sticks; the later cred_exec setgroups
     runs post-drop as the target and is tolerated. n_groups<=0 would otherwise
     collapse the drop to {primary gid} only (the historical su behavior). */
  gid_t groups[BC_PD_GROUPS_MAX];
  int n_groups = 0;
  (void) bc_load_supplementary_groups (u->name, groups, &n_groups, BC_PD_GROUPS_MAX);
  {
    int already = 0;
    for (int i = 0; i < n_groups; i++)
      if (groups[i] == u->gid) { already = 1; break; }
    if (!already && n_groups < BC_PD_GROUPS_MAX)
      groups[n_groups++] = u->gid;
  }

  if (bc_privdrop_to_user (u->uid, u->gid, groups, n_groups, err, sizeof err) < 0)
    {
      builtin_error ("privdrop: %s", err[0] ? err : strerror (errno));
      return EXECUTION_FAILURE;
    }

  bashos_cred_exec_user ceu = {
    u->name, u->uid, u->gid, u->home, u->shell
  };
  if (bashos_cred_exec_user_shell (&ceu, "su", keep_env, login_shell,
                                   cmd, 0, NULL) < 0)
    fprintf (stderr, "su: exec setup: %s\n", strerror (errno));
  _exit (126);
}

extern char *su_doc[];

int
su_builtin (WORD_LIST *list)
{
  const char *target = "root";
  const char *cmd = NULL;
  int login_shell = 1;
  int keep_env = 0;

  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-h") == 0 || strcmp (w, "--help") == 0)
        {
          for (char **d = su_doc; *d; d++) puts (*d);
          return EXECUTION_SUCCESS;
        }
      if (strcmp (w, "-") == 0 || strcmp (w, "-l") == 0 || strcmp (w, "--login") == 0)
        login_shell = 1;
      else if (strcmp (w, "--no-login") == 0)
        login_shell = 0;
      else if (strcmp (w, "--keep-env") == 0 || strcmp (w, "--unsafe-keep-env") == 0)
        keep_env = 1;
      else if (strcmp (w, "-c") == 0)
        {
          if (!p->next) { builtin_error ("-c needs CMD"); return EX_USAGE; }
          p = p->next;
          cmd = p->word->word;
        }
      else if (strncmp (w, "-c", 2) == 0 && w[2] != '\0')
        cmd = w + 2;
      else if (strcmp (w, "--") == 0)
        {
          if (p->next) { p = p->next; target = p->word->word; }
          if (p->next) { builtin_error ("extra arg %s", p->next->word->word); return EX_USAGE; }
        }
      else if (w[0] == '-')
        { builtin_error ("unknown flag: %s", w); return EX_USAGE; }
      else
        {
          target = w;
          if (p->next) { builtin_error ("extra arg %s", p->next->word->word); return EX_USAGE; }
        }
    }

  bashos_auth_user au;
  if (!bsu_valid_user_name (target))
    { builtin_error ("invalid user: %s", target); return EX_USAGE; }
  int lr = bashos_lookup_user (target, &au);
  if (lr == -2) { builtin_error ("cannot read passwd database: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (lr == -1) { builtin_error ("no such user: %s", target); return EXECUTION_FAILURE; }
  bc_user_info u;
  memset (&u, 0, sizeof u);
  strncpy (u.name, au.name, sizeof u.name - 1);
  u.uid = au.uid;
  u.gid = au.gid;
  strncpy (u.gecos, au.gecos, sizeof u.gecos - 1);
  strncpy (u.home, au.home, sizeof u.home - 1);
  strncpy (u.shell, au.shell, sizeof u.shell - 1);

  if (getuid () != 0)
    {
      /* Non-root su owns target-password bytes and PHC verification in this
         process, so make the process non-dumpable before prompting. */
      if (prctl (PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
        builtin_warning ("prctl(PR_SET_DUMPABLE,0): %s", strerror (errno));
      int vr = bsu_verify_user_interactive (target);
      if (vr != 0) return vr == 1 ? EXECUTION_FAILURE : EX_USAGE;
    }

  return bsu_exec_user (&u, keep_env, login_shell, cmd);
}

char *su_doc[] = {
  "Switch user with C-owned password verification.",
  "",
  "    su [--login|--no-login] [--keep-env] [-c CMD] [USER]",
  "",
  "Non-root callers authenticate as the target user through the same",
  "Argon2id PHC shadow format used by passwd. Password bytes are",
  "read from a tty into an mlock'd C buffer and wiped before return.",
  "A short-lived kernel auth token is minted and consumed internally",
  "immediately before the credential transition.",
  (char *) NULL
};

struct builtin su_struct = {
  "su",
  su_builtin,
  BUILTIN_ENABLED,
  su_doc,
  "su [--login|--no-login] [--keep-env] [-c CMD] [USER]",
  0
};
