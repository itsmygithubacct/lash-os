/* SPDX-License-Identifier: MIT */
/* login.c — privilege drop + exec for bash-os multi-user auth.
 *
 * bash can't issue setresuid/setresgid/setgroups/clearenv from script
 * level — those are syscalls that need C. login closes the loop:
 * after a caller verifies a password, login atomically drops
 * privileges and exec's the user's shell or a specified command.
 *
 * The `login` verb owns interactive password verification and
 * persistent lockout state. The `become` verb remains a privilege-drop
 * primitive for callers that already authenticated through passwd.
 *
 * Subcommands:
 *
 *   login lookup USER
 *       Look USER up in the passwd database. On success, print:
 *           uid:gid:home:shell:gecos
 *       Exit 1 if not found.
 *
 *   login become USER [--auth-fd N | --auth-token HEX]
 *                    [--unsafe-keep-env] [-c CMD] [-- ARGS...]
 *       Drop to USER's identity and exec their shell (or CMD with -c).
 *       Steps, in order (any failure is fatal — never partial drop):
 *         1. Reject if real uid != 0.
 *         2. Look up USER in the passwd database.
 *         3. Consume the kernel auth proof unless the legacy migration
 *            env disables it. Two forms are accepted:
 *              --auth-fd N    (preferred) — read 32 binary token bytes
 *                              from inherited fd N, then ioctl(fd, CONSUME)
 *                              on the same fd. Token never lands in argv
 *                              or /proc/<pid>/cmdline.
 *              --auth-token HEX (deprecated; removed in v4.4) — token
 *                              passed as hex on the command line. Visible
 *                              in /proc/<pid>/cmdline and shell history.
 *                              Emits a stderr warning when used.
 *            If both are given, --auth-fd wins and --auth-token is
 *            still warned about.
 *         4. setgroups({GID}) — primary group only at v1.
 *         5. setresgid(GID, GID, GID).
 *         6. setresuid(UID, UID, UID).
 *         7. clearenv() unless --unsafe-keep-env. Whitelist below.
 *         8. chdir(HOME).
 *         9. execve(SHELL, [shell, ...args], envp).
 *
 *       Default exec is `SHELL --login` (interactive login shell).
 *       With `-c CMD`, exec is `SHELL -c CMD`.
 *
 *       Whitelisted env (always set; current values from caller env
 *       are preserved unless --unsafe-keep-env is also set):
 *           USER, LOGNAME, HOME, SHELL  ← from passwd entry
 *           PATH = /bin:/bash-os:/usr/bin   ← bash-os' default PATH
 *           TERM, LANG, LC_ALL              ← preserved if set
 *
 * Refuses to run if the calling uid is non-root. By default, callers
 * must pass a kernel token minted after C-side password verification.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <limits.h>
#include <termios.h>
#include <time.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <pwd.h>
#include <grp.h>
#include <utmp.h>
#include <lastlog.h>

#include "_monocypher_monocypher-ed25519.h"
#include "_bashauth_pwverify.h"
#include "_bashauth_cred_exec.h"
#include "_bashauth_passwd_lookup.h"
#include "_bashauth_secure_read.h"
#include "loadables.h"
/* Stage 23 v1: shared priv-drop primitives. The setgroups/setresgid/
   setresuid sequence + getresuid verify lives in bc_privdrop_to_user
   so login and ns and cred all run the same body. */
#include "bashcred_privdrop.h"

#define BL_MAX_PASSWORD 4096
#define BL_LOCK_FAIL_MAX 5
#define BL_LOCK_WINDOW 600
#define BL_LOCK_DURATION 900
#define BL_AUTH_IOC_MAGIC 0xBA
#define BL_AUTH_DEV "/dev/bashos-auth"
#define BL_AUTH_TOKEN_BYTES 32
#define BL_AUTH_USER_BYTES 64
#define BL_AUTH_TOKEN_LOGIN 1
#define BL_LOGIN_POLICY_PATH "/etc/auth.d/login"
#define BL_POLICY_MAX_TTYS 32
#define BL_POLICY_MAX_ENV 32
#define BL_POLICY_NAME_MAX 64
#define BL_POLICY_MAX_CHAIN 64
#define BL_POLICY_ARGS_MAX 256

/* Module-chain enums for the (opt-in) PAM-style ordered evaluator. The
   default login path still uses the flat knobs in bl_login_policy; the chain
   is an additive, ordered record of the parsed directives so the control-flow
   semantics (required/requisite/sufficient/optional) can be evaluated. */
enum { BL_PH_AUTH, BL_PH_ACCOUNT, BL_PH_SESSION, BL_PH_PASSWORD };
enum { BL_CTL_REQUIRED, BL_CTL_REQUISITE, BL_CTL_OPTIONAL, BL_CTL_SUFFICIENT };
enum { BL_MOD_SECURETTY, BL_MOD_TIME, BL_MOD_LOCKOUT, BL_MOD_LIMITS, BL_MOD_ENV,
       BL_MOD_MOTD, BL_MOD_LASTLOG, BL_MOD_DENY, BL_MOD_USERDB,
       BL_MOD_CONDITION, BL_MOD_WARN, BL_MOD_EXPIRY };

struct bl_auth_token_req {
  unsigned int uid;
  unsigned int gid;
  unsigned int purpose;
  unsigned int expires_sec;
  unsigned char token[BL_AUTH_TOKEN_BYTES];
  char user[BL_AUTH_USER_BYTES];
  unsigned int flags;
  unsigned int reserved;
};

#define BL_AUTH_IOC_CONSUME_TOKEN \
  _IOW(BL_AUTH_IOC_MAGIC, 0x09, struct bl_auth_token_req)
#define BL_AUTH_IOC_MINT_TOKEN \
  _IOWR(BL_AUTH_IOC_MAGIC, 0x08, struct bl_auth_token_req)

/* passwd entry — populated by bl_lookup_user. */
typedef struct {
  char name[64];
  uid_t uid;
  gid_t gid;
  char gecos[256];
  char home[256];
  char shell[256];
} bl_user;

typedef struct {
  unsigned int m, t, p;
  char salt_hex[129];
  char hash_hex[257];
} bl_phc;

typedef struct {
  int present;
  int securetty;
  char securetty_file[256];
  char securetty_ttys[BL_POLICY_MAX_TTYS][BL_POLICY_NAME_MAX];
  size_t n_securetty_ttys;
  int time_deny_always;
  int lock_fail_max;
  long lock_window;
  long lock_duration;
  rlim_t limit_nofile;
  rlim_t limit_nproc;
  rlim_t limit_fsize;
  rlim_t limit_as;
  rlim_t limit_core;
  char env_keep[BL_POLICY_MAX_ENV][BL_POLICY_NAME_MAX];
  size_t n_env_keep;
  char env_delete[BL_POLICY_MAX_ENV][BL_POLICY_NAME_MAX];
  size_t n_env_delete;
  int chain_policy;
  int policy_version;
  /* Ordered module chain (phase/control/module per directive, in file order),
     captured at parse time. Backs the opt-in chain evaluator; the flat knobs
     above remain the default-path source of truth. */
  struct {
    int phase, control, module;
    char args[BL_POLICY_ARGS_MAX];
  } chain[BL_POLICY_MAX_CHAIN];
  int n_chain;
} bl_login_policy;

static volatile sig_atomic_t bl_login_hup_seen = 0;

static void
bl_login_signal (int sig)
{
  (void) sig;
  bl_login_hup_seen = 1;
}

static void
bl_wipe (void *p, size_t n)
{
  if (p && n) crypto_wipe (p, n);
}

static int
bl_hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
bl_unhex (const char *hex, unsigned char *out, size_t outsz)
{
  size_t o = 0;
  int hi = -1;
  for (const char *p = hex; *p; p++)
    {
      int v = bl_hexval ((unsigned char) *p);
      if (v < 0) return -1;
      if (hi < 0) { hi = v; continue; }
      if (o >= outsz) return -1;
      out[o++] = (unsigned char) ((hi << 4) | v);
      hi = -1;
    }
  return hi < 0 ? (int) o : -1;
}

static void
bl_print_hex (const unsigned char *buf, size_t n, char *out)
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
bl_auth_fill_token_req (struct bl_auth_token_req *req, const bl_user *u)
{
  memset (req, 0, sizeof *req);
  req->uid = (unsigned int) u->uid;
  req->gid = (unsigned int) u->gid;
  req->purpose = BL_AUTH_TOKEN_LOGIN;
  strncpy (req->user, u->name, sizeof req->user - 1);
  return 0;
}

static int
bl_consume_auth_token_fd (int fd, const bl_user *u,
                          const unsigned char token[BL_AUTH_TOKEN_BYTES])
{
  struct bl_auth_token_req req;
  bl_auth_fill_token_req (&req, u);
  memcpy (req.token, token, BL_AUTH_TOKEN_BYTES);
  int rc = ioctl (fd, BL_AUTH_IOC_CONSUME_TOKEN, &req);
  bl_wipe (&req, sizeof req);
  return rc;
}

/* Read exactly BL_AUTH_TOKEN_BYTES from fd into out. Handles short reads
   and EINTR. Returns 0 on success, -1 on any error (errno preserved). */
static int
bl_read_token_from_fd (int fd, unsigned char out[BL_AUTH_TOKEN_BYTES])
{
  size_t have = 0;
  while (have < BL_AUTH_TOKEN_BYTES)
    {
      ssize_t n = read (fd, out + have, BL_AUTH_TOKEN_BYTES - have);
      if (n < 0)
        {
          if (errno == EINTR) continue;
          return -1;
        }
      if (n == 0) { errno = EIO; return -1; }   /* EOF before full token */
      have += (size_t) n;
    }
  return 0;
}

static int
bl_consume_auth_token_via_fd (const bl_user *u, int fd)
{
  unsigned char tok[BL_AUTH_TOKEN_BYTES];
  if (bl_read_token_from_fd (fd, tok) < 0)
    {
      builtin_error ("become: --auth-fd %d: read token: %s",
                     fd, strerror (errno));
      bl_wipe (tok, sizeof tok);
      return -1;
    }
  int rc = bl_consume_auth_token_fd (fd, u, tok);
  bl_wipe (tok, sizeof tok);
  if (rc < 0)
    {
      builtin_error ("become: --auth-fd %d: kernel auth token rejected: %s",
                     fd, strerror (errno));
      return -1;
    }
  return 0;
}

static int
bl_consume_auth_token (const bl_user *u, const char *token_hex)
{
  unsigned char tok[BL_AUTH_TOKEN_BYTES];
  if (!token_hex || strlen (token_hex) != BL_AUTH_TOKEN_BYTES * 2 ||
      bl_unhex (token_hex, tok, sizeof tok) != BL_AUTH_TOKEN_BYTES)
    {
      builtin_error ("become: invalid --auth-token");
      return -1;
    }

  struct rlimit rl;
  long maxfd = 1024;
  if (getrlimit (RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
    maxfd = (long) rl.rlim_cur;
  if (maxfd > 4096)
    maxfd = 4096;

  int saw_auth_device = 0;
  for (int fd = 0; fd < maxfd; fd++)
    {
      if (bl_consume_auth_token_fd (fd, u, tok) == 0)
        {
          bl_wipe (tok, sizeof tok);
          return 0;
        }
      if (errno != EBADF && errno != ENOTTY && errno != EINVAL)
        saw_auth_device = 1;
    }

  bl_wipe (tok, sizeof tok);
  builtin_error ("become: kernel auth token rejected%s",
                 saw_auth_device ? "" : " (no open /dev/bashos-auth fd)");
  return -1;
}

static int
bl_kernel_token_required (void)
{
  const char *v = getenv ("BASHLOGIN_REQUIRE_KERNEL_TOKEN");
  return !(v && strcmp (v, "0") == 0);
}

static int
bl_login_kernel_proof (const bl_user *u)
{
  if (!bl_kernel_token_required ())
    return 0;

  int fd = open (BL_AUTH_DEV, O_RDWR | O_CLOEXEC);
  if (fd < 0)
    {
      builtin_error ("login: %s: %s", BL_AUTH_DEV, strerror (errno));
      return -1;
    }
  int fl = fcntl (fd, F_GETFD, 0);
  if (fl >= 0)
    (void) fcntl (fd, F_SETFD, fl | FD_CLOEXEC);

  struct bl_auth_token_req req;
  bl_auth_fill_token_req (&req, u);
  req.expires_sec = 5;
  if (ioctl (fd, BL_AUTH_IOC_MINT_TOKEN, &req) < 0)
    {
      builtin_error ("login: kernel auth token mint failed: %s", strerror (errno));
      bl_wipe (&req, sizeof req);
      close (fd);
      return -1;
    }

  if (bl_consume_auth_token_fd (fd, u, req.token) < 0)
    {
      builtin_error ("login: kernel auth token rejected: %s", strerror (errno));
      bl_wipe (&req, sizeof req);
      close (fd);
      return -1;
    }

  bl_wipe (&req, sizeof req);
  close (fd);
  return 0;
}

static int
bl_valid_user_name (const char *s)
{
  return bashos_valid_user_name (s);
}

static int
bl_parse_phc (const char *phc, bl_phc *out)
{
  if (!phc || strncmp (phc, "$argon2id$", 10) != 0) return -1;
  char *copy = strdup (phc);
  if (!copy) return -1;
  char *save = NULL, *parts[6] = { 0 };
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
  if (out->m < 1024 || out->m > 262144 || out->t < 1 || out->t > 10 ||
      out->p < 1 || out->p > 8 || sl < 16 || sl > 128 || (sl & 1) ||
      hl < 32 || hl > 256 || (hl & 1))
    { free (copy); return -1; }
  strncpy (out->salt_hex, parts[3], sizeof out->salt_hex - 1);
  strncpy (out->hash_hex, parts[4], sizeof out->hash_hex - 1);
  free (copy);
  return 0;
}

static int
bl_read_shadow_entry (const char *user, bashos_shadow_entry *out)
{
  return bashos_read_shadow_entry (user, out);
}

static long
bl_today_days (void)
{
  return (long) (time (NULL) / 86400);
}

static int
bl_shadow_aging_status (const bashos_shadow_entry *ent, long today,
                        long *warn_remaining)
{
  if (warn_remaining)
    *warn_remaining = -1;
  if (!ent)
    return 0;

  if (ent->expire_days >= 0 && today >= ent->expire_days)
    return -3;

  if (ent->last_change < 0 || ent->max_days < 0)
    return 0;

  long expires = ent->last_change + ent->max_days;
  if (today >= expires)
    {
      if (ent->inactive_days >= 0 && today >= expires + ent->inactive_days)
        return -2;
      return -1;
    }

  if (ent->warn_days >= 0 && today >= expires - ent->warn_days)
    {
      if (warn_remaining)
        *warn_remaining = expires - today;
      return 1;
    }

  return 0;
}

static void
bl_shadow_aging_report (const char *user, int status, long warn_remaining)
{
  switch (status)
    {
    case 1:
      if (warn_remaining == 1)
        fprintf (stderr, "Warning: password for %s expires in 1 day.\n", user);
      else if (warn_remaining >= 0)
        fprintf (stderr, "Warning: password for %s expires in %ld days.\n",
                 user, warn_remaining);
      else
        fprintf (stderr, "Warning: password for %s will expire soon.\n", user);
      break;
    case -1:
      fprintf (stderr, "Password expired for %s.\n", user);
      break;
    case -2:
      fprintf (stderr, "Account inactive for %s due to expired password.\n", user);
      break;
    case -3:
      fprintf (stderr, "Account expired for %s.\n", user);
      break;
    default:
      break;
    }
}

static const char *
bl_policy_path (void)
{
  const char *p = getenv ("BASHAUTH_LOGIN_POLICY");
  return (p && *p) ? p : BL_LOGIN_POLICY_PATH;
}

static void
bl_policy_init (bl_login_policy *p)
{
  memset (p, 0, sizeof *p);
  snprintf (p->securetty_file, sizeof p->securetty_file, "/etc/securetty");
  p->lock_fail_max = BL_LOCK_FAIL_MAX;
  p->lock_window = BL_LOCK_WINDOW;
  p->lock_duration = BL_LOCK_DURATION;
  p->limit_nofile = RLIM_INFINITY;
  p->limit_nproc = RLIM_INFINITY;
  p->limit_fsize = RLIM_INFINITY;
  p->limit_as = RLIM_INFINITY;
  p->limit_core = RLIM_INFINITY;
  p->policy_version = 2;
}

static char *
bl_trim (char *s)
{
  while (*s && isspace ((unsigned char) *s)) s++;
  char *e = s + strlen (s);
  while (e > s && isspace ((unsigned char) e[-1])) *--e = '\0';
  return s;
}

static int
bl_streq (const char *a, const char *b)
{
  return a && b && strcmp (a, b) == 0;
}

static int
bl_parse_long_arg (const char *s, long *out)
{
  char *end = NULL;
  long v;
  if (!s || !*s) return -1;
  errno = 0;
  v = strtol (s, &end, 10);
  if (errno || !end || *end || v < 0) return -1;
  *out = v;
  return 0;
}

static int
bl_parse_rlim_arg (const char *s, rlim_t *out)
{
  long v;
  if (bl_streq (s, "infinity") || bl_streq (s, "unlimited"))
    { *out = RLIM_INFINITY; return 0; }
  if (bl_parse_long_arg (s, &v) < 0) return -1;
  *out = (rlim_t) v;
  return 0;
}

static int
bl_policy_name_pattern_ok (const char *name)
{
  if (!name || !*name)
    return 0;
  size_t n = strlen (name);
  if (n == 0 || n >= BL_POLICY_NAME_MAX)
    return 0;
  for (const char *p = name; *p; p++)
    {
      unsigned char c = (unsigned char) *p;
      if (!(isalnum (c) || c == '_' || c == '-' || c == '*' || c == '.'))
        return 0;
    }
  return 1;
}

static int
bl_policy_tty_pattern_ok (const char *name)
{
  if (!name || !*name || *name == '/' || strlen (name) >= 128 ||
      strstr (name, ".."))
    return 0;
  for (const char *p = name; *p; p++)
    {
      unsigned char c = (unsigned char) *p;
      if (!(isalnum (c) || c == '_' || c == '-' || c == '*' ||
            c == '.' || c == '/'))
        return 0;
    }
  return 1;
}

static int
bl_policy_parse_csv_with (const char *csv, int (*okfn) (const char *))
{
  if (!csv || !*csv)
    return -1;
  char *copy = strdup (csv);
  if (!copy)
    return -1;
  int ok = 0;
  char *save = NULL;
  for (char *tok = strtok_r (copy, ",", &save); tok;
       tok = strtok_r (NULL, ",", &save))
    {
      tok = bl_trim (tok);
      if (!*tok || !okfn (tok))
        { free (copy); return -1; }
      ok = 1;
    }
  free (copy);
  return ok ? 0 : -1;
}

static int
bl_policy_uid_token_ok (const char *s)
{
  long n;
  return bl_parse_long_arg (s, &n) == 0 &&
         (uid_t) n == (unsigned long) n;
}

static int
bl_policy_parse_condition (char **argv, int argc)
{
  if (argc != 3)
    return -1;
  const char *key = argv[0], *op = argv[1], *operand = argv[2];
  if (bl_streq (key, "uid"))
    {
      if (bl_streq (op, "in"))
        return bl_policy_parse_csv_with (operand, bl_policy_uid_token_ok);
      if (bl_streq (op, "eq") || bl_streq (op, "ne") ||
          bl_streq (op, "lt") || bl_streq (op, "le") ||
          bl_streq (op, "gt") || bl_streq (op, "ge"))
        {
          long n;
          return bl_parse_long_arg (operand, &n) == 0 &&
                 (uid_t) n == (unsigned long) n ? 0 : -1;
        }
      return -1;
    }
  if ((bl_streq (key, "user") || bl_streq (key, "group")) &&
      bl_streq (op, "in"))
    return bl_policy_parse_csv_with (operand, bl_policy_name_pattern_ok);
  if (bl_streq (key, "tty") && bl_streq (op, "in"))
    return bl_policy_parse_csv_with (operand, bl_policy_tty_pattern_ok);
  return -1;
}

static void
bl_policy_add_name (char names[][BL_POLICY_NAME_MAX], size_t *used,
                    size_t cap, const char *name)
{
  if (!name || !*name || *used >= cap) return;
  if (!bl_policy_name_pattern_ok (name)) return;
  for (size_t i = 0; i < *used; i++)
    if (strcmp (names[i], name) == 0) return;
  strncpy (names[*used], name, BL_POLICY_NAME_MAX - 1);
  (*used)++;
}

static void
bl_policy_add_csv (char names[][BL_POLICY_NAME_MAX], size_t *used,
                   size_t cap, const char *csv)
{
  if (!csv) return;
  char *copy = strdup (csv);
  if (!copy) return;
  char *save = NULL;
  for (char *tok = strtok_r (copy, ",", &save); tok;
       tok = strtok_r (NULL, ",", &save))
    bl_policy_add_name (names, used, cap, bl_trim (tok));
  free (copy);
}

static int
bl_policy_name_matches (const char *pat, const char *name, size_t namelen)
{
  size_t plen = strlen (pat);
  if (plen > 0 && pat[plen - 1] == '*')
    return namelen >= plen - 1 && strncmp (name, pat, plen - 1) == 0;
  return namelen == plen && strncmp (name, pat, plen) == 0;
}

static int
bl_policy_parse_securetty (bl_login_policy *p, char **argv, int argc)
{
  p->securetty = 1;
  for (int i = 0; i < argc; i++)
    {
      char *a = argv[i];
      if (bl_streq (a, "off") || bl_streq (a, "disabled"))
        p->securetty = 0;
      else if (bl_streq (a, "on") || bl_streq (a, "required"))
        p->securetty = 1;
      else if (strncmp (a, "file=", 5) == 0 && a[5] == '/')
        snprintf (p->securetty_file, sizeof p->securetty_file, "%s", a + 5);
      else if (strncmp (a, "tty=", 4) == 0)
        bl_policy_add_csv (p->securetty_ttys, &p->n_securetty_ttys,
                           BL_POLICY_MAX_TTYS, a + 4);
      else
        return -1;
    }
  return 0;
}

static int
bl_policy_parse_time (bl_login_policy *p, char **argv, int argc)
{
  for (int i = 0; i < argc; i++)
    {
      char *a = argv[i];
      if (bl_streq (a, "deny") || bl_streq (a, "deny=always") ||
          bl_streq (a, "allow=never"))
        p->time_deny_always = 1;
      else if (bl_streq (a, "allow") || bl_streq (a, "allow=always") ||
               bl_streq (a, "deny=never"))
        p->time_deny_always = 0;
      else
        return -1;
    }
  return 0;
}

static int
bl_policy_parse_lockout (bl_login_policy *p, char **argv, int argc)
{
  for (int i = 0; i < argc; i++)
    {
      char *a = argv[i], *v = strchr (a, '=');
      long n;
      if (!v) return -1;
      *v++ = '\0';
      if (bl_parse_long_arg (v, &n) < 0) return -1;
      if (bl_streq (a, "max") || bl_streq (a, "fail_max") ||
          bl_streq (a, "deny"))
        p->lock_fail_max = (int) n;
      else if (bl_streq (a, "window") || bl_streq (a, "fail_interval"))
        p->lock_window = n;
      else if (bl_streq (a, "duration") || bl_streq (a, "lock_time") ||
               bl_streq (a, "unlock_time"))
        p->lock_duration = n;
      else
        return -1;
    }
  return 0;
}

static int
bl_policy_parse_limits (bl_login_policy *p, char **argv, int argc)
{
  for (int i = 0; i < argc; i++)
    {
      char *a = argv[i], *v = strchr (a, '=');
      rlim_t n;
      if (!v) return -1;
      *v++ = '\0';
      if (bl_parse_rlim_arg (v, &n) < 0) return -1;
      if (bl_streq (a, "nofile")) p->limit_nofile = n;
      else if (bl_streq (a, "nproc")) p->limit_nproc = n;
      else if (bl_streq (a, "fsize")) p->limit_fsize = n;
      else if (bl_streq (a, "as")) p->limit_as = n;
      else if (bl_streq (a, "core")) p->limit_core = n;
      else return -1;
    }
  return 0;
}

static int
bl_policy_parse_env (bl_login_policy *p, char **argv, int argc)
{
  for (int i = 0; i < argc; i++)
    {
      char *a = argv[i];
      if (strncmp (a, "keep=", 5) == 0)
        bl_policy_add_csv (p->env_keep, &p->n_env_keep, BL_POLICY_MAX_ENV, a + 5);
      else if (strncmp (a, "delete=", 7) == 0)
        bl_policy_add_csv (p->env_delete, &p->n_env_delete, BL_POLICY_MAX_ENV, a + 7);
      else
        return -1;
    }
  return 0;
}

static int
bl_policy_parse_deny (char **argv, int argc)
{
  for (int i = 0; i < argc; i++)
    {
      char *a = argv[i];
      if (bl_streq (a, "all") || bl_streq (a, "always") ||
          bl_streq (a, "nologin"))
        continue;
      if (strncmp (a, "file=", 5) == 0 && a[5] == '/')
        continue;
      if (strncmp (a, "user=", 5) == 0 && a[5])
        continue;
      if (strncmp (a, "group=", 6) == 0 && a[6])
        continue;
      if (strncmp (a, "uid=", 4) == 0 && a[4])
        {
          long n;
          if (bl_parse_long_arg (a + 4, &n) == 0)
            continue;
        }
      return -1;
    }
  return 0;
}

static int
bl_policy_parse_userdb (char **argv, int argc)
{
  if (argc != 1)
    return -1;
  return bl_streq (argv[0], "source=nss") ? 0 : -1;
}

static int
bl_policy_parse_directive (bl_login_policy *p, char **argv, int argc)
{
  if (argc < 3) return -1;
  int ph, ctl, mod, r = 0;
  char raw_args[BL_POLICY_ARGS_MAX];
  raw_args[0] = '\0';
  for (int i = 3; i < argc; i++)
    {
      size_t used = strlen (raw_args);
      size_t need = strlen (argv[i]) + (used ? 1 : 0);
      if (used + need >= sizeof raw_args)
        return -1;
      if (used)
        strcat (raw_args, " ");
      strcat (raw_args, argv[i]);
    }
  if      (bl_streq (argv[0], "auth"))     ph = BL_PH_AUTH;
  else if (bl_streq (argv[0], "account"))  ph = BL_PH_ACCOUNT;
  else if (bl_streq (argv[0], "session"))  ph = BL_PH_SESSION;
  else if (bl_streq (argv[0], "password")) ph = BL_PH_PASSWORD;
  else return -1;
  if      (bl_streq (argv[1], "required"))   ctl = BL_CTL_REQUIRED;
  else if (bl_streq (argv[1], "requisite"))  ctl = BL_CTL_REQUISITE;
  else if (bl_streq (argv[1], "optional"))   ctl = BL_CTL_OPTIONAL;
  else if (bl_streq (argv[1], "sufficient")) ctl = BL_CTL_SUFFICIENT;
  else return -1;
  if      (bl_streq (argv[2], "securetty")) { mod = BL_MOD_SECURETTY; r = bl_policy_parse_securetty (p, argv + 3, argc - 3); }
  else if (bl_streq (argv[2], "time"))      { mod = BL_MOD_TIME;      r = bl_policy_parse_time (p, argv + 3, argc - 3); }
  else if (bl_streq (argv[2], "lockout"))   { mod = BL_MOD_LOCKOUT;   r = bl_policy_parse_lockout (p, argv + 3, argc - 3); }
  else if (bl_streq (argv[2], "limits"))    { mod = BL_MOD_LIMITS;    r = bl_policy_parse_limits (p, argv + 3, argc - 3); }
  else if (bl_streq (argv[2], "env"))       { mod = BL_MOD_ENV;       r = bl_policy_parse_env (p, argv + 3, argc - 3); }
  /* Chain-only modules (no flat-struct knob yet; their runtime result is
     supplied to the evaluator). Recognized so policies can order them. */
  else if (bl_streq (argv[2], "motd"))
    { mod = BL_MOD_MOTD; if (argc > 3) r = -1; }
  else if (bl_streq (argv[2], "lastlog"))
    { mod = BL_MOD_LASTLOG; if (argc > 3) r = -1; }
  else if (bl_streq (argv[2], "deny"))
    { mod = BL_MOD_DENY; r = bl_policy_parse_deny (argv + 3, argc - 3); }
  else if (bl_streq (argv[2], "userdb"))
    {
      if (ph != BL_PH_ACCOUNT) return -1;
      mod = BL_MOD_USERDB;
      r = bl_policy_parse_userdb (argv + 3, argc - 3);
    }
  else if (bl_streq (argv[2], "condition"))
    {
      if (ph != BL_PH_AUTH && ph != BL_PH_ACCOUNT) return -1;
      mod = BL_MOD_CONDITION;
      r = bl_policy_parse_condition (argv + 3, argc - 3);
    }
  else if (bl_streq (argv[2], "warn"))
    {
      if (ph == BL_PH_PASSWORD || ctl != BL_CTL_OPTIONAL || argc < 4)
        return -1;
      mod = BL_MOD_WARN;
    }
  else if (bl_streq (argv[2], "expiry"))
    {
      if (ph != BL_PH_PASSWORD || ctl != BL_CTL_REQUIRED || argc > 3)
        return -1;
      for (int i = 0; i < p->n_chain; i++)
        if (p->chain[i].phase == BL_PH_PASSWORD)
          return -1;
      mod = BL_MOD_EXPIRY;
    }
  else return -1;
  if (ph == BL_PH_PASSWORD && mod != BL_MOD_EXPIRY)
    return -1;
  if (r < 0) return -1;
  if (p->n_chain < BL_POLICY_MAX_CHAIN)
    {
      p->chain[p->n_chain].phase   = ph;
      p->chain[p->n_chain].control = ctl;
      p->chain[p->n_chain].module  = mod;
      snprintf (p->chain[p->n_chain].args,
                sizeof p->chain[p->n_chain].args, "%s", raw_args);
      p->n_chain++;
    }
  return 0;
}

static int
bl_policy_load (bl_login_policy *p)
{
  bl_policy_init (p);
  const char *path = bl_policy_path ();
  FILE *f = fopen (path, "r");
  if (!f)
    return errno == ENOENT ? 0 : -1;

  p->present = 1;
  char line[1024];
  unsigned int lno = 0;
  while (fgets (line, sizeof line, f))
    {
      lno++;
      char *hash = strchr (line, '#');
      if (hash) *hash = '\0';
      char *s = bl_trim (line);
      if (!*s) continue;

      char *argv[32];
      int argc = 0;
      char *save = NULL;
      for (char *tok = strtok_r (s, " \t\r\n", &save);
           tok && argc < (int) (sizeof argv / sizeof argv[0]);
           tok = strtok_r (NULL, " \t\r\n", &save))
        argv[argc++] = tok;
      if (argc == 0) continue;
      if (argc == 1 && bl_streq (argv[0], "chain"))
        {
          p->chain_policy = 1;
          continue;
        }
      if (argc == 2 && bl_streq (argv[0], "chain") &&
          bl_streq (argv[1], "strict-optional"))
        {
          p->chain_policy = 1;
          p->policy_version = 3;
          continue;
        }
      if (argc == 2 && bl_streq (argv[0], "version") &&
          (bl_streq (argv[1], "2") || bl_streq (argv[1], "3")))
        {
          p->chain_policy = 1;
          p->policy_version = bl_streq (argv[1], "3") ? 3 : 2;
          continue;
        }
      if (argc >= (int) (sizeof argv / sizeof argv[0]) ||
          bl_policy_parse_directive (p, argv, argc) < 0)
        {
          fclose (f);
          builtin_error ("login: policy %s:%u: invalid directive", path, lno);
          return -1;
        }
    }
  fclose (f);
  if (p->lock_fail_max < 0 || p->lock_window < 0 || p->lock_duration < 0)
    {
      builtin_error ("login: policy %s: invalid lockout values", path);
      return -1;
    }
  return 0;
}

static const char *
bl_lock_dir (void)
{
  const char *d = getenv ("BPW_LOCK_DIR");
  if (!d || !*d) d = "/run/login";
  return d;
}

static void
bl_lock_token (const char *user, const bl_user *u, char *out, size_t outsz)
{
  if (u)
    {
      snprintf (out, outsz, "%lu", (unsigned long) u->uid);
      return;
    }

  size_t j = 0;
  for (const char *p = user ? user : ""; *p && j + 1 < outsz; p++)
    {
      unsigned char c = (unsigned char) *p;
      out[j++] = ((c >= 'A' && c <= 'Z') ||
                  (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') ||
                  c == '_' || c == '-') ? (char) c : '_';
    }
  if (j == 0 && outsz > 1) out[j++] = '_';
  out[j] = '\0';
}

static void
bl_lock_path (const char *user, const bl_user *u, char *out, size_t outsz)
{
  char tok[64];
  bl_lock_token (user, u, tok, sizeof tok);
  snprintf (out, outsz, "%s/fail.%s", bl_lock_dir (), tok);
}

static int
bl_parent_dir (const char *path, char *dir, size_t dirsz)
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
bl_temp_open (const char *path, char *tmp, size_t tmpsz, mode_t mode)
{
  char dir[512];
  struct stat st;
  if (bl_parent_dir (path, dir, sizeof dir) < 0 ||
      lstat (dir, &st) < 0 ||
      !S_ISDIR (st.st_mode))
    return -1;
  if (st.st_uid != geteuid ())
    return -1;
  if (st.st_mode & (S_IWGRP | S_IWOTH))
    return -1;

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
bl_fsync_parent (const char *path)
{
  char dir[512];
  if (bl_parent_dir (path, dir, sizeof dir) < 0)
    return -1;
  int dfd = open (dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd < 0)
    return -1;
  int rc = fsync (dfd);
  close (dfd);
  return rc;
}

static void
bl_read_lock_state (const char *path, int *count, long *last, long *locked_until)
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
bl_check_lockout (const char *user, const bl_user *u,
                  const bl_login_policy *policy)
{
  int max = policy ? policy->lock_fail_max : BL_LOCK_FAIL_MAX;
  if (max <= 0) return 0;
  char path[256];
  bl_lock_path (user, u, path, sizeof path);
  int count;
  long last, locked_until;
  bl_read_lock_state (path, &count, &last, &locked_until);
  long now = (long) time (NULL);
  if (locked_until > now)
    {
      fprintf (stderr, "Account locked. Try again in %ld seconds.\n", locked_until - now);
      return -1;
    }
  return 0;
}

static void
bl_record_failure (const char *user, const bl_user *u,
                   const bl_login_policy *policy)
{
  int max = policy ? policy->lock_fail_max : BL_LOCK_FAIL_MAX;
  long window = policy ? policy->lock_window : BL_LOCK_WINDOW;
  long duration = policy ? policy->lock_duration : BL_LOCK_DURATION;
  if (max <= 0) return;

  const char *dir = bl_lock_dir ();
  if (mkdir (dir, 0700) < 0 && errno != EEXIST)
    return;

  char path[256], tmp[512];
  bl_lock_path (user, u, path, sizeof path);
  int count;
  long last, locked_until;
  bl_read_lock_state (path, &count, &last, &locked_until);

  long now = (long) time (NULL);
  if (now - last > window)
    count = 0;
  count++;
  last = now;
  locked_until = (count >= max) ? now + duration : 0;

  int fd = bl_temp_open (path, tmp, sizeof tmp, 0600);
  if (fd < 0) return;
  FILE *f = fdopen (fd, "w");
  if (!f) { close (fd); unlink (tmp); return; }
  fprintf (f, "COUNT=%d\nLAST=%ld\nLOCKED_UNTIL=%ld\n", count, last, locked_until);
  fflush (f);
  fd = fileno (f);
  if (fd >= 0) fsync (fd);
  fclose (f);
  chmod (tmp, 0600);
  if (rename (tmp, path) == 0)
    (void) bl_fsync_parent (path);
  else
    unlink (tmp);
}

static void
bl_record_success (const char *user, const bl_user *u)
{
  char path[256];
  bl_lock_path (user, u, path, sizeof path);
  unlink (path);
}

static void
bl_record_audit (const char *event, const char *user, const bl_user *u,
                 const char *tty_name, const char *phase, const char *msg)
{
  const char *dir = bl_lock_dir ();
  if (mkdir (dir, 0700) < 0 && errno != EEXIST)
    return;

  char tok[64], path[256];
  bl_lock_token (user, u, tok, sizeof tok);
  snprintf (path, sizeof path, "%s/audit.%s", dir, tok);
  int fd = open (path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0)
    return;
  dprintf (fd, "event=%s user=%s tty=%s phase=%s msg=%s\n",
           event ? event : "-",
           user && *user ? user : "-",
           tty_name && *tty_name ? tty_name : "-",
           phase && *phase ? phase : "-",
           msg && *msg ? msg : "-");
  close (fd);
}

static int
bl_verify_secret (const unsigned char *pw, size_t pw_len, const char *phc)
{
  return bashos_verify_phc_secret (pw, pw_len, phc);
}

static int
bl_read_password (const char *prompt, unsigned char **out, size_t *out_len)
{
  return bashos_secure_read_password (prompt, out, out_len);
}

static const char *
bl_passwd_path (void)
{
  const char *path = getenv ("PHCLIB_PASSWD");
  if (!path || !*path) path = getenv ("PASSWD_FILE");
  if (!path || !*path) path = "/etc/passwd";
  return path;
}

/* Manually parse the passwd database. We don't link nsswitch / NSS
 * modules (musl static link) so getpwnam_r would only consult
 * /etc/passwd anyway — but parsing here keeps the dependency surface
 * tiny and makes the lookup auditable. Test and recovery flows can
 * point PHCLIB_PASSWD/PASSWD_FILE at a fixture database, matching
 * passwd's account-file convention. Returns 0 on success, -1 on
 * not-found, -2 on file-read error. */
static int
bl_lookup_user (const char *user, bl_user *out)
{
  bashos_auth_user u;
  int rc = bashos_lookup_user (user, &u);
  if (rc == 0)
    {
      memset (out, 0, sizeof *out);
      strncpy (out->name, u.name, sizeof out->name - 1);
      out->uid = u.uid;
      out->gid = u.gid;
      strncpy (out->gecos, u.gecos, sizeof out->gecos - 1);
      strncpy (out->home, u.home, sizeof out->home - 1);
      strncpy (out->shell, u.shell, sizeof out->shell - 1);
    }
  return rc;
}

static int
bl_safe_text_field (const char *s, int allow_empty)
{
  if (!s || (!allow_empty && !*s)) return 0;
  for (const unsigned char *p = (const unsigned char *) s; *p; p++)
    if (*p == ':' || *p == '\n' || *p == '\r' || *p == '\t' || *p < 0x20)
      return 0;
  return 1;
}

static int
bl_parse_nss_passwd_line (const char *want, const char *line, bl_user *out)
{
  if (!want || !line || !out || strlen (line) >= 1024)
    return -1;
  char buf[1024];
  snprintf (buf, sizeof buf, "%s", line);
  buf[strcspn (buf, "\r\n")] = '\0';

  char *save = NULL;
  char *name = strtok_r (buf, ":", &save);
  char *pw = strtok_r (NULL, ":", &save);
  char *uid_s = strtok_r (NULL, ":", &save);
  char *gid_s = strtok_r (NULL, ":", &save);
  char *gecos = strtok_r (NULL, ":", &save);
  char *home = strtok_r (NULL, ":", &save);
  char *shell = strtok_r (NULL, ":", &save);
  char *extra = strtok_r (NULL, ":", &save);
  (void) pw;
  if (!name || !uid_s || !gid_s || !gecos || !home || !shell || extra)
    return -1;
  if (!bl_valid_user_name (name) || strcmp (name, want) != 0)
    return -1;
  if (!bl_safe_text_field (gecos, 1) ||
      !bl_safe_text_field (home, 0) ||
      !bl_safe_text_field (shell, 0) ||
      home[0] != '/' || shell[0] != '/')
    return -1;

  char *end = NULL;
  errno = 0;
  unsigned long uid = strtoul (uid_s, &end, 10);
  if (errno || !end || *end || (unsigned long) (uid_t) uid != uid)
    return -1;
  errno = 0;
  unsigned long gid = strtoul (gid_s, &end, 10);
  if (errno || !end || *end || (unsigned long) (gid_t) gid != gid)
    return -1;

  memset (out, 0, sizeof *out);
  snprintf (out->name, sizeof out->name, "%s", name);
  out->uid = (uid_t) uid;
  out->gid = (gid_t) gid;
  snprintf (out->gecos, sizeof out->gecos, "%s", gecos);
  snprintf (out->home, sizeof out->home, "%s", home);
  snprintf (out->shell, sizeof out->shell, "%s", shell);
  return 0;
}

static int
bl_getent_path_ok (const char *path)
{
  if (!path || path[0] != '/')
    return 0;
  for (const unsigned char *p = (const unsigned char *) path; *p; p++)
    if (*p == '\n' || *p == '\r' || *p == '\t' || *p < 0x20)
      return 0;
  return 1;
}

static const char *
bl_nss_getent_path (void)
{
  const char *p = getenv ("BASHLOGIN_NSS_GETENT");
  return (p && *p) ? p : "/bash-os/getent.sh";
}

static int
bl_lookup_user_nss (const char *user, bl_user *out)
{
  const char *getent = bl_nss_getent_path ();
  if (!bl_getent_path_ok (getent) || !bl_valid_user_name (user))
    return -1;

  int pipefd[2];
  if (pipe (pipefd) < 0)
    return -1;
  pid_t pid = fork ();
  if (pid < 0)
    {
      close (pipefd[0]);
      close (pipefd[1]);
      return -1;
    }
  if (pid == 0)
    {
      int devnull = open ("/dev/null", O_WRONLY);
      close (pipefd[0]);
      if (dup2 (pipefd[1], STDOUT_FILENO) < 0)
        _exit (127);
      if (devnull >= 0)
        {
          (void) dup2 (devnull, STDERR_FILENO);
          close (devnull);
        }
      close (pipefd[1]);
      execl (getent, getent, "passwd", user, (char *) NULL);
      _exit (127);
    }

  close (pipefd[1]);
  char buf[1024];
  size_t used = 0;
  ssize_t n;
  while ((n = read (pipefd[0], buf + used, sizeof buf - 1 - used)) > 0)
    {
      used += (size_t) n;
      if (used >= sizeof buf - 1)
        break;
    }
  close (pipefd[0]);
  int status = 0;
  while (waitpid (pid, &status, 0) < 0)
    if (errno != EINTR)
      return -1;
  if (!WIFEXITED (status) || WEXITSTATUS (status) != 0 || used == 0 ||
      used >= sizeof buf - 1)
    return -1;
  buf[used] = '\0';
  if (strchr (buf, '\n') && strchr (strchr (buf, '\n') + 1, '\n'))
    return -1;
  return bl_parse_nss_passwd_line (user, buf, out);
}

static int
bl_policy_wants_nss_userdb (const bl_login_policy *policy)
{
  if (!policy)
    return 0;
  for (int i = 0; i < policy->n_chain; i++)
    if (policy->chain[i].phase == BL_PH_ACCOUNT &&
        policy->chain[i].module == BL_MOD_USERDB &&
        bl_streq (policy->chain[i].args, "source=nss"))
      return 1;
  return 0;
}

static int
bl_lookup_cmd (WORD_LIST *args)
{
  if (!args)
    { builtin_error ("lookup needs USER"); return EX_USAGE; }
  bl_user u;
  int r = bl_lookup_user (args->word->word, &u);
  if (r == -2) { builtin_error ("cannot read passwd database: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (r == -1) return EXECUTION_FAILURE;
  printf ("%u:%u:%s:%s:%s\n", u.uid, u.gid, u.home, u.shell, u.gecos);
  return EXECUTION_SUCCESS;
}

static void bl_cat_file (const char *path);
static void bl_cat_file_fd (const char *path, FILE *out);

static int
bl_policy_set_limit (int resource, rlim_t value, const char *name)
{
  if (value == RLIM_INFINITY)
    return 0;
  struct rlimit rl;
  rl.rlim_cur = value;
  rl.rlim_max = value;
  if (setrlimit (resource, &rl) < 0)
    {
      builtin_error ("login: limits %s=%llu: %s", name,
                     (unsigned long long) value, strerror (errno));
      return -1;
    }
  return 0;
}

static int
bl_policy_apply_limits (const bl_login_policy *policy)
{
  if (!policy) return 0;
  if (bl_policy_set_limit (RLIMIT_NOFILE, policy->limit_nofile, "nofile") < 0)
    return -1;
  if (bl_policy_set_limit (RLIMIT_NPROC, policy->limit_nproc, "nproc") < 0)
    return -1;
  if (bl_policy_set_limit (RLIMIT_FSIZE, policy->limit_fsize, "fsize") < 0)
    return -1;
  if (bl_policy_set_limit (RLIMIT_AS, policy->limit_as, "as") < 0)
    return -1;
  if (bl_policy_set_limit (RLIMIT_CORE, policy->limit_core, "core") < 0)
    return -1;
  return 0;
}

static int
bl_rebind_tty_stdio (const char *tty_name)
{
  if (!tty_name || !*tty_name)
    return 0;

  char path[256];
  if (strncmp (tty_name, "/dev/", 5) == 0)
    snprintf (path, sizeof path, "%s", tty_name);
  else
    snprintf (path, sizeof path, "/dev/%s", tty_name);

  int fd = open (path, O_RDWR | O_NOCTTY);
  if (fd < 0)
    {
      builtin_warning ("login: open tty %s: %s", path, strerror (errno));
      return -1;
    }

  if (dup2 (fd, STDIN_FILENO) < 0 ||
      dup2 (fd, STDOUT_FILENO) < 0 ||
      dup2 (fd, STDERR_FILENO) < 0)
    {
      int saved = errno;
      if (fd > STDERR_FILENO) close (fd);
      errno = saved;
      builtin_warning ("login: dup2 tty %s: %s", path, strerror (errno));
      return -1;
    }

  if (fd > STDERR_FILENO)
    close (fd);
  return 0;
}

static int
bl_exec_user (const bl_user *u, int keep_env, int login_shell,
              int show_motd,
              const char *cmd, int extra_argc, const char **extra_argv,
              const char *tty_name,
              int with_supplementary, int no_new_privs,
              const char *caps_keep,
              const bl_login_policy *policy)
{
  if (extra_argc < 0 || extra_argc > 64)
    {
      builtin_error ("become: too many exec arguments");
      return EX_USAGE;
    }

  /* Stage 37.I: login shells must inherit a live pty on 0/1/2.  The
     direct expect harness and getty both know the slave path; rebind
     before the uid/gid drop so non-root logins do not need permission to
     reopen the pty after authentication. */
  if (bl_rebind_tty_stdio (tty_name) < 0)
    return EXECUTION_FAILURE;

  if (bl_policy_apply_limits (policy) < 0)
    return EXECUTION_FAILURE;

  /* J01 v1: optional PR_SET_NO_NEW_PRIVS BEFORE the drop, matching the
     docs/SECURITY-PRIV-DROP.md canonical ordering
     (namespace setup → no-new-privs → caps-clear → drop). The bit
     survives execve(2) and defangs any setuid/file-capability binary
     the dropped shell might reach (shadow-utils login(1) gained the
     equivalent via util-linux-2.39 setpriv --no-new-privs wiring). */
  if (no_new_privs)
    {
      char err[BC_PD_ERR_MAX];
      if (bc_no_new_privs (err, sizeof err) < 0)
        {
          builtin_error ("become: %s", err[0] ? err : strerror (errno));
          return EXECUTION_FAILURE;
        }
    }

  /* J01 v2: --caps-clear[=KEEP] plumbing. bc_caps_clear drops every
     capability not in the keep-CSV before the uid/gid drop, so the
     child process starts with zero or minimal caps regardless of what
     the calling root process held. Requires CAP_SETPCAP in the caller's
     bounding set (true for root on a standard bash-os kernel).
     NULL means no caps clearing requested; empty string clears all. */
  if (caps_keep != NULL)
    {
      char err[BC_PD_ERR_MAX];
      if (bc_caps_clear (caps_keep, err, sizeof err) < 0)
        {
          builtin_error ("become: %s", err[0] ? err : strerror (errno));
          return EXECUTION_FAILURE;
        }
    }

  /* J01 v1: with --with-supplementary, walk /etc/group via
     bc_load_supplementary_groups (already used by cred drop) and
     append the primary gid so the drop preserves the entire group
     membership shadow-utils' su(1)/login(1) install via initgroups(3).
     Without the flag the drop collapses to {primary gid} only —
     historical Stage 23 v1 behavior — so existing call sites keep the
     conservative footprint. */
  gid_t groups[BC_PD_GROUPS_MAX];
  int n_groups = 0;
  const gid_t *groups_ptr = NULL;
  if (with_supplementary)
    {
      bc_load_supplementary_groups (u->name, groups, &n_groups,
                                    BC_PD_GROUPS_MAX);
      int already = 0;
      for (int i = 0; i < n_groups; i++)
        if (groups[i] == u->gid) { already = 1; break; }
      if (!already && n_groups < BC_PD_GROUPS_MAX)
        groups[n_groups++] = u->gid;
      groups_ptr = groups;
    }

  /* Stage 23 v1: route the drop body through bc_privdrop_to_user so
     login / ns / cred share one canonical sequence
     (setgroups → setresgid → setresuid → getresuid+getresgid verify).
     Passing n_groups=0 collapses to a single-element {primary gid}
     setgroups call inside the helper, matching prior behavior.
     If the helper returns -1 the identity is *not yet* transformed
     (every step short-circuits on first failure), so EXECUTION_FAILURE
     is still safe — the _exit(126) rule below kicks in only AFTER the
     drop has succeeded but the post-drop exec or env-build fails. */
  {
    char err[BC_PD_ERR_MAX];
    if (bc_privdrop_to_user (u->uid, u->gid, groups_ptr, n_groups,
                             err, sizeof err) < 0)
      {
        builtin_error ("become: %s", err[0] ? err : strerror (errno));
        return EXECUTION_FAILURE;
      }
  }

  if (show_motd)
    {
      char hush[512];
      snprintf (hush, sizeof hush, "%s/.hushlogin", u->home);
      if (access (hush, F_OK) != 0)
        {
          bl_cat_file ("/etc/motd");
          if (tty_name && *tty_name)
            {
              const char *base = strrchr (tty_name, '/');
              base = base ? base + 1 : tty_name;
              if (*base && !strchr (base, '/') && !strstr (base, ".."))
                {
                  char tty_motd[256];
                  snprintf (tty_motd, sizeof tty_motd, "/etc/motd.%s", base);
                  bl_cat_file (tty_motd);
                }
            }
        }
      fflush (stdout);
    }

  bashos_cred_exec_user ceu = {
    u->name, u->uid, u->gid, u->home, u->shell
  };
  const char *env_keep[BL_POLICY_MAX_ENV];
  const char *env_delete[BL_POLICY_MAX_ENV];
  bashos_cred_exec_env_policy env_policy = {0};
  bashos_cred_exec_env_policy *env_policyp = NULL;
  if (policy && policy->present)
    {
      for (size_t i = 0; i < policy->n_env_keep; i++)
        env_keep[i] = policy->env_keep[i];
      for (size_t i = 0; i < policy->n_env_delete; i++)
        env_delete[i] = policy->env_delete[i];
      env_policy.keep = env_keep;
      env_policy.nkeep = policy->n_env_keep;
      env_policy.delete = env_delete;
      env_policy.ndelete = policy->n_env_delete;
      env_policyp = &env_policy;
    }
  /* Only returns on pre-exec argument validation failure. After the drop,
     returning to script code is unsafe, so fail closed with su-like 126. */
  if (bashos_cred_exec_user_shell_policy (&ceu, "login", keep_env,
                                          login_shell, cmd, extra_argc,
                                          extra_argv, env_policyp) < 0)
    fprintf (stderr, "login: exec setup: %s\n", strerror (errno));
  _exit (126);
}

static int
bl_become_cmd (WORD_LIST *args)
{
  /* Defensive: only root can drop. */
  if (getuid () != 0)
    {
      builtin_error ("become: only root may drop privileges (uid=%u)", getuid ());
      return EXECUTION_FAILURE;
    }

  const char *user = NULL;
  const char *cmd = NULL;
  const char *auth_token = NULL;
  int auth_fd = -1;   /* --auth-fd N: -1 means "not set" */
  int keep_env = 0;
  int login_shell = 1;   /* default: interactive login shell */
  int with_supplementary = 0;
  int no_new_privs = 0;
  const char *caps_keep = NULL;   /* NULL = no caps clearing requested */
  int saw_dashdash = 0;

  int extra_argc = 0;
  const char *extra_argv[64] = { 0 };

  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (saw_dashdash)
        {
          if (extra_argc < 63) extra_argv[extra_argc++] = w;
        }
      else if (strcmp (w, "--unsafe-keep-env") == 0) keep_env = 1;
      else if (strcmp (w, "--keep-env") == 0) {
        /* Deprecated alias. Renamed in the 2026-05-07 security review
           sweep — the original name reads as "safe to use", which it
           is decidedly not (a uid boundary is exactly where env-var
           preservation is dangerous: TZ, PERL5OPT, LD_PRELOAD via
           caller-controlled paths, etc.). Keep the old name working
           with a stderr warning so existing scripts don't break in
           one push. Drop the alias after one release. */
        builtin_warning ("--keep-env is deprecated; use --unsafe-keep-env");
        keep_env = 1;
      }
      else if (strcmp (w, "--no-login")  == 0) login_shell = 0;
      else if (strcmp (w, "--with-supplementary") == 0) with_supplementary = 1;
      else if (strcmp (w, "--no-new-privs")       == 0) no_new_privs       = 1;
      else if (strcmp (w, "--auth-token") == 0)
        { if (!p->next) { builtin_error ("--auth-token needs HEX"); return EX_USAGE; }
          p = p->next; auth_token = p->word->word;
          /* Deprecated 2026-05-26 (REVIEW-2026-05-26 decision #5): token
             value lands in argv → /proc/<pid>/cmdline and shell history.
             Accepted through v4.4; users should migrate to --auth-fd N. */
          builtin_warning ("--auth-token HEX: token will be visible in /proc/<pid>/cmdline; prefer --auth-fd N (deprecated, will be removed in v4.4)");
        }
      else if (strcmp (w, "--auth-fd") == 0)
        { if (!p->next) { builtin_error ("--auth-fd needs N"); return EX_USAGE; }
          p = p->next;
          errno = 0;
          char *end = NULL;
          long n = strtol (p->word->word, &end, 10);
          if (errno != 0 || !end || *end != '\0' || n < 0 || n > INT_MAX) {
            builtin_error ("--auth-fd: invalid fd %s", p->word->word);
            return EX_USAGE;
          }
          auth_fd = (int) n; }
      else if (strcmp (w, "--caps-clear") == 0)
        caps_keep = "";   /* clear all */
      else if (strncmp (w, "--caps-clear=", 13) == 0)
        caps_keep = w + 13;  /* keep only listed caps */
      else if (strcmp (w, "-c") == 0)
        { if (!p->next) { builtin_error ("-c needs CMD"); return EX_USAGE; }
          p = p->next; cmd = p->word->word; }
      else if (strcmp (w, "--") == 0) saw_dashdash = 1;
      else if (!user)                  user = w;
      else { builtin_error ("become: extra arg %s", w); return EX_USAGE; }
    }
  if (!user) { builtin_error ("become needs USER"); return EX_USAGE; }

  bl_user u;
  int r = bl_lookup_user (user, &u);
  if (r == -2) { builtin_error ("cannot read passwd database: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (r == -1) { builtin_error ("become: no such user: %s", user); return EXECUTION_FAILURE; }
  if (auth_fd < 0 && (!auth_token || !*auth_token) && bl_kernel_token_required ())
    {
      /* Message keeps the historical "--auth-token required" phrasing
         for backward compatibility with tests/operators that grep for
         it; tests 133/136 pin this string. The newer --auth-fd form is
         mentioned for forward guidance. */
      builtin_error ("become: --auth-token required (or --auth-fd N)");
      return EXECUTION_FAILURE;
    }
  /* Prefer --auth-fd over --auth-token when both are present: the fd path
     keeps the token bytes off of /proc/<pid>/cmdline. */
  if (auth_fd >= 0)
    {
      if (bl_consume_auth_token_via_fd (&u, auth_fd) < 0)
        return EXECUTION_FAILURE;
    }
  else if (auth_token && bl_consume_auth_token (&u, auth_token) < 0)
    return EXECUTION_FAILURE;
  return bl_exec_user (&u, keep_env, login_shell, 0, cmd, extra_argc, extra_argv, NULL,
                       with_supplementary, no_new_privs, caps_keep, NULL);
}

static void
bl_cat_file (const char *path)
{
  bl_cat_file_fd (path, stdout);
}

static void
bl_cat_file_fd (const char *path, FILE *out)
{
  FILE *f = fopen (path, "r");
  if (!f) return;
  char buf[512];
  size_t n;
  while ((n = fread (buf, 1, sizeof buf, f)) > 0)
    fwrite (buf, 1, n, out);
  fclose (f);
}

static void
bl_sleep_after_failure (int attempt, int max_tries)
{
  if (max_tries <= 1) return;
  sleep (attempt == 0 ? 1 : (attempt == 1 ? 5 : 30));
}

static int
bl_nologin_blocks (const bl_user *u)
{
  if (u->uid == 0) return 0;
  if (access ("/etc/nologin", F_OK) != 0) return 0;
  bl_cat_file_fd ("/etc/nologin", stderr);
  return 1;
}

static int
bl_tty_line (const char *tty_name, char *out, size_t out_sz)
{
  if (!tty_name || !*tty_name) return -1;
  const char *p = tty_name;
  if (strncmp (p, "/dev/", 5) == 0) p += 5;
  if (!*p || *p == '/' || strstr (p, "..") || strlen (p) >= out_sz) return -1;
  strcpy (out, p);
  return 0;
}

static int
bl_policy_tty_list_contains (const char names[][BL_POLICY_NAME_MAX], size_t used,
                             const char *line)
{
  for (size_t i = 0; i < used; i++)
    if (strcmp (names[i], line) == 0)
      return 1;
  return 0;
}

static int
bl_policy_file_contains_tty (const char *path, const char *line)
{
  FILE *f = fopen (path, "r");
  if (!f) return 0;
  char buf[256];
  int ok = 0;
  while (fgets (buf, sizeof buf, f))
    {
      char *hash = strchr (buf, '#');
      if (hash) *hash = '\0';
      char *s = bl_trim (buf);
      if (strcmp (s, line) == 0)
        { ok = 1; break; }
    }
  fclose (f);
  return ok;
}

static int
bl_policy_check_access (const bl_login_policy *policy, const bl_user *u,
                        const char *tty_name)
{
  if (!policy || !policy->present) return 0;
  if (policy->time_deny_always)
    {
      fprintf (stderr, "Login not permitted at this time.\n");
      return -1;
    }
  if (policy->securetty && u->uid == 0)
    {
      char line[128];
      if (bl_tty_line (tty_name, line, sizeof line) < 0)
        {
          fprintf (stderr, "Root login refused on unknown tty.\n");
          return -1;
        }
      if (!bl_policy_tty_list_contains (policy->securetty_ttys,
                                        policy->n_securetty_ttys, line) &&
          !bl_policy_file_contains_tty (policy->securetty_file, line))
        {
          fprintf (stderr, "Root login refused on this tty.\n");
          return -1;
        }
    }
  return 0;
}

#define BL_UTMP    "/var/run/utmp"
#define BL_WTMP    "/var/log/wtmp"
#define BL_LASTLOG "/var/log/lastlog"

static void
bl_fill_utmp (struct utmp *rec, const bl_user *u, const char *line)
{
  memset (rec, 0, sizeof *rec);
  strncpy (rec->ut_user, u->name, UT_NAMESIZE - 1);
  strncpy (rec->ut_line, line, UT_LINESIZE - 1);
  rec->ut_pid = getpid ();
  rec->ut_type = USER_PROCESS;

  size_t llen = strlen (line);
  size_t take = llen > 4 ? 4 : llen;
  if (take > 0)
    memcpy (rec->ut_id, line + (llen - take), take);

  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  rec->ut_tv.tv_sec = (int32_t) ts.tv_sec;
  rec->ut_tv.tv_usec = (int32_t) (ts.tv_nsec / 1000);
}

static int
bl_utmp_write (const struct utmp *rec)
{
  int fd = open (BL_UTMP, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
  if (fd < 0)
    { builtin_warning ("login: open %s: %s", BL_UTMP, strerror (errno)); return -1; }
  if (flock (fd, LOCK_EX) < 0 && errno != ENOSYS)
    { builtin_warning ("login: flock %s: %s", BL_UTMP, strerror (errno)); close (fd); return -1; }

  struct utmp tmp;
  off_t pos = 0;
  ssize_t n;
  while ((n = read (fd, &tmp, sizeof tmp)) == sizeof tmp)
    {
      if (memcmp (tmp.ut_line, rec->ut_line, UT_LINESIZE) == 0)
        {
          if (lseek (fd, pos, SEEK_SET) < 0 ||
              write (fd, rec, sizeof *rec) != (ssize_t) sizeof *rec)
            { close (fd); return -1; }
          close (fd);
          return 0;
        }
      pos += sizeof tmp;
    }
  if (n < 0)
    { close (fd); return -1; }
  if (lseek (fd, 0, SEEK_END) < 0 ||
      write (fd, rec, sizeof *rec) != (ssize_t) sizeof *rec)
    { close (fd); return -1; }
  close (fd);
  return 0;
}

static int
bl_wtmp_append (const struct utmp *rec)
{
  int fd = open (BL_WTMP, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0664);
  if (fd < 0)
    { builtin_warning ("login: open %s: %s", BL_WTMP, strerror (errno)); return -1; }
  if (write (fd, rec, sizeof *rec) != (ssize_t) sizeof *rec)
    { close (fd); return -1; }
  close (fd);
  return 0;
}

static int
bl_record_utmp_login (const bl_user *u, const char *tty_name)
{
  char line[128];
  if (bl_tty_line (tty_name, line, sizeof line) < 0)
    return 0;

  struct utmp rec;
  bl_fill_utmp (&rec, u, line);
  if (bl_utmp_write (&rec) < 0 || bl_wtmp_append (&rec) < 0)
    { builtin_warning ("login: utmp/wtmp record failed for %s on %s", u->name, line); return -1; }
  return 0;
}

static int
bl_lastlog_write (const bl_user *u, const char *tty_name)
{
  char line[128];
  if (bl_tty_line (tty_name, line, sizeof line) < 0)
    return 0;

  int fd = open (BL_LASTLOG, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
  if (fd < 0)
    { builtin_warning ("login: open %s: %s", BL_LASTLOG, strerror (errno)); return -1; }
  if (flock (fd, LOCK_EX) < 0 && errno != ENOSYS)
    { builtin_warning ("login: flock %s: %s", BL_LASTLOG, strerror (errno)); close (fd); return -1; }

  struct lastlog ll;
  memset (&ll, 0, sizeof ll);
  ll.ll_time = time (NULL);
  strncpy (ll.ll_line, line, sizeof ll.ll_line - 1);

  off_t off = (off_t) u->uid * (off_t) sizeof ll;
  if (lseek (fd, off, SEEK_SET) < 0 ||
      write (fd, &ll, sizeof ll) != (ssize_t) sizeof ll)
    {
      builtin_warning ("login: write %s: %s", BL_LASTLOG, strerror (errno));
      close (fd);
      return -1;
    }
  close (fd);
  return 0;
}

static int
bl_policy_chain_requested (const bl_login_policy *policy, int flag)
{
  if (flag || (policy && policy->chain_policy))
    return 1;
  const char *v = getenv ("BASHLOGIN_POLICY_CHAIN");
  if (!v || !*v)
    return 0;
  return bl_streq (v, "1") || bl_streq (v, "yes") ||
         bl_streq (v, "true") || bl_streq (v, "on");
}

static int
bl_csv_name_matches (const char *csv, const char *name, size_t namelen)
{
  if (!csv || !*csv) return 0;
  char *copy = strdup (csv);
  if (!copy) return 0;
  int matched = 0;
  char *save = NULL;
  for (char *tok = strtok_r (copy, ",", &save); tok;
       tok = strtok_r (NULL, ",", &save))
    {
      tok = bl_trim (tok);
      if (*tok && bl_policy_name_matches (tok, name, namelen))
        { matched = 1; break; }
    }
  free (copy);
  return matched;
}

static int
bl_user_group_matches (const bl_user *u, const char *pat)
{
  if (!u || !pat || !*pat) return 0;

  char *end = NULL;
  errno = 0;
  long gid = strtol (pat, &end, 10);
  if (end && *end == '\0' && errno == 0 && gid >= 0 && (gid_t) gid == u->gid)
    return 1;

  struct group *gr = getgrgid (u->gid);
  if (gr && bl_policy_name_matches (pat, gr->gr_name, strlen (gr->gr_name)))
    return 1;

  setgrent ();
  int matched = 0;
  while ((gr = getgrent ()) != NULL)
    {
      if (!bl_policy_name_matches (pat, gr->gr_name, strlen (gr->gr_name)))
        continue;
      for (char **m = gr->gr_mem; m && *m; m++)
        if (strcmp (*m, u->name) == 0)
          { matched = 1; break; }
      if (matched)
        break;
    }
  endgrent ();
  return matched;
}

static int
bl_csv_group_matches (const bl_user *u, const char *csv)
{
  if (!csv || !*csv) return 0;
  char *copy = strdup (csv);
  if (!copy) return 0;
  int matched = 0;
  char *save = NULL;
  for (char *tok = strtok_r (copy, ",", &save); tok;
       tok = strtok_r (NULL, ",", &save))
    {
      tok = bl_trim (tok);
      if (*tok && bl_user_group_matches (u, tok))
        { matched = 1; break; }
    }
  free (copy);
  return matched;
}

static const char *
bl_phase_name (int phase)
{
  switch (phase)
    {
    case BL_PH_AUTH:     return "auth";
    case BL_PH_ACCOUNT:  return "account";
    case BL_PH_SESSION:  return "session";
    case BL_PH_PASSWORD: return "password";
    default:             return "unknown";
    }
}

static int
bl_condition_uid_in (uid_t uid, const char *csv)
{
  if (!csv || !*csv) return 0;
  char *copy = strdup (csv);
  if (!copy) return 0;
  int matched = 0;
  char *save = NULL;
  for (char *tok = strtok_r (copy, ",", &save); tok;
       tok = strtok_r (NULL, ",", &save))
    {
      long n;
      tok = bl_trim (tok);
      if (bl_parse_long_arg (tok, &n) == 0 &&
          (uid_t) n == uid)
        { matched = 1; break; }
    }
  free (copy);
  return matched;
}

static int
bl_chain_condition_matches (const bl_user *u, const char *tty_name,
                            const char *args)
{
  if (!u || !args || !*args)
    return 0;
  char copy[BL_POLICY_ARGS_MAX];
  snprintf (copy, sizeof copy, "%s", args);
  char *save = NULL;
  char *key = strtok_r (copy, " \t\r\n", &save);
  char *op = strtok_r (NULL, " \t\r\n", &save);
  char *operand = strtok_r (NULL, " \t\r\n", &save);
  char *extra = strtok_r (NULL, " \t\r\n", &save);
  if (!key || !op || !operand || extra)
    return 0;

  if (bl_streq (key, "uid"))
    {
      if (bl_streq (op, "in"))
        return bl_condition_uid_in (u->uid, operand);
      long rhs;
      if (bl_parse_long_arg (operand, &rhs) < 0)
        return 0;
      long lhs = (long) u->uid;
      if (bl_streq (op, "eq")) return lhs == rhs;
      if (bl_streq (op, "ne")) return lhs != rhs;
      if (bl_streq (op, "lt")) return lhs < rhs;
      if (bl_streq (op, "le")) return lhs <= rhs;
      if (bl_streq (op, "gt")) return lhs > rhs;
      if (bl_streq (op, "ge")) return lhs >= rhs;
      return 0;
    }
  if (bl_streq (key, "user") && bl_streq (op, "in"))
    return bl_csv_name_matches (operand, u->name, strlen (u->name));
  if (bl_streq (key, "group") && bl_streq (op, "in"))
    return bl_csv_group_matches (u, operand);
  if (bl_streq (key, "tty") && bl_streq (op, "in"))
    {
      char line[128];
      if (bl_tty_line (tty_name, line, sizeof line) < 0)
        return 0;
      return bl_csv_name_matches (operand, line, strlen (line));
    }
  return 0;
}

static void
bl_chain_warn (const bl_user *u, const char *tty_name, int phase,
               const char *msg)
{
  const char *user = u ? u->name : "-";
  const char *phase_name = bl_phase_name (phase);
  fprintf (stderr, "login: warn user=%s tty=%s phase=%s: %s\n",
           user, tty_name && *tty_name ? tty_name : "-",
           phase_name, msg && *msg ? msg : "-");
  bl_record_audit ("warn", user, u, tty_name, phase_name, msg);
}

static int
bl_chain_deny_matches (const bl_user *u, const char *args)
{
  if (!args || !*args)
    return 1;
  char *copy = strdup (args);
  if (!copy)
    return 0;
  int deny = 0;
  char *save = NULL;
  for (char *tok = strtok_r (copy, " \t\r\n", &save); tok;
       tok = strtok_r (NULL, " \t\r\n", &save))
    {
      if (bl_streq (tok, "all") || bl_streq (tok, "always"))
        { deny = 1; break; }
      if (bl_streq (tok, "nologin"))
        {
          if (u->uid != 0 && access ("/etc/nologin", F_OK) == 0)
            { bl_cat_file_fd ("/etc/nologin", stderr); deny = 1; break; }
          continue;
        }
      if (strncmp (tok, "file=", 5) == 0)
        {
          if (u->uid != 0 && access (tok + 5, F_OK) == 0)
            { bl_cat_file_fd (tok + 5, stderr); deny = 1; break; }
          continue;
        }
      if (strncmp (tok, "user=", 5) == 0 &&
          bl_csv_name_matches (tok + 5, u->name, strlen (u->name)))
        { deny = 1; break; }
      if (strncmp (tok, "group=", 6) == 0 &&
          bl_csv_group_matches (u, tok + 6))
        { deny = 1; break; }
      if (strncmp (tok, "uid=", 4) == 0)
        {
          char *end = NULL;
          errno = 0;
          long uid = strtol (tok + 4, &end, 10);
          if (end && *end == '\0' && errno == 0 && uid >= 0 &&
              (uid_t) uid == u->uid)
            { deny = 1; break; }
        }
    }
  free (copy);
  return deny;
}

static void
bl_policy_show_motd (const bl_user *u, const char *tty_name)
{
  char hush[512];
  snprintf (hush, sizeof hush, "%s/.hushlogin", u->home);
  if (access (hush, F_OK) == 0)
    return;
  bl_cat_file ("/etc/motd");
  if (tty_name && *tty_name)
    {
      const char *base = strrchr (tty_name, '/');
      base = base ? base + 1 : tty_name;
      if (*base && !strchr (base, '/') && !strstr (base, ".."))
        {
          char tty_motd[256];
          snprintf (tty_motd, sizeof tty_motd, "/etc/motd.%s", base);
          bl_cat_file (tty_motd);
        }
    }
  fflush (stdout);
}

typedef struct {
  const bl_user *u;
  const char *tty_name;
  int show_motd;
  int motd_done;
  int lastlog_done;
  const bashos_shadow_entry *shadow;
  const char *login_name;
  long today_days;
  long warn_remaining;
  int aging_status;
  int aging_checked;
} bl_chain_ctx;

static int
bl_policy_phase_has (const bl_login_policy *policy, int phase)
{
  if (!policy)
    return 0;
  for (int i = 0; i < policy->n_chain; i++)
    if (policy->chain[i].phase == phase)
      return 1;
  return 0;
}

static int
bl_policy_decide_phase (const bl_login_policy *policy, int phase,
                        const int failed[BL_POLICY_MAX_CHAIN],
                        int upto_chain, int final,
                        int *decided, int *deciding)
{
  int phase_entries = 0, optional_entries = 0;
  for (int i = 0; i < policy->n_chain; i++)
    if (policy->chain[i].phase == phase)
      {
        phase_entries++;
        if (policy->chain[i].control == BL_CTL_OPTIONAL)
          optional_entries++;
      }

  if (decided) *decided = 0;
  if (deciding) *deciding = -1;
  if (phase_entries == 0)
    {
      if (decided) *decided = 1;
      return 0;
    }

  int strict_optional = policy->policy_version >= 3;
  int required_failed = 0, required_failer = -1;
  int sole_optional = -1;
  int optional_failed = 0, first_optional_failed = -1;

  for (int i = 0; i < policy->n_chain; i++)
    {
      if (policy->chain[i].phase != phase)
        continue;
      if (!final && i > upto_chain)
        break;

      int ctl = policy->chain[i].control, mod = policy->chain[i].module;
      int mod_failed = failed[i] != 0;
      switch (ctl)
        {
        case BL_CTL_REQUISITE:
          if (mod_failed)
            {
              if (decided) *decided = 1;
              if (deciding) *deciding = mod;
              return 1;
            }
          break;
        case BL_CTL_REQUIRED:
          if (mod_failed && !required_failed)
            { required_failed = 1; required_failer = mod; }
          break;
        case BL_CTL_SUFFICIENT:
          if (!mod_failed && !required_failed)
            {
              if (decided) *decided = 1;
              if (deciding) *deciding = mod;
              return 0;
            }
          break;
        case BL_CTL_OPTIONAL:
          if (strict_optional)
            {
              if (mod_failed)
                {
                  optional_failed++;
                  if (first_optional_failed < 0)
                    first_optional_failed = mod;
                }
            }
          else if (phase_entries == 1)
            sole_optional = mod_failed ? mod : -1;
          break;
        }
    }

  if (!final)
    return 0;

  if (required_failed)
    {
      if (decided) *decided = 1;
      if (deciding) *deciding = required_failer;
      return 1;
    }
  if (strict_optional && optional_entries == phase_entries &&
      optional_failed == phase_entries && first_optional_failed >= 0)
    {
      if (decided) *decided = 1;
      if (deciding) *deciding = first_optional_failed;
      return 1;
    }
  if (!strict_optional && sole_optional >= 0)
    {
      if (decided) *decided = 1;
      if (deciding) *deciding = sole_optional;
      return 1;
    }

  if (decided) *decided = 1;
  return 0;
}

static int
bl_policy_run_chain (const bl_login_policy *policy, int phase, bl_chain_ctx *ctx)
{
  if (!policy || policy->n_chain == 0)
    return 0;

  int phase_entries = 0;
  for (int i = 0; i < policy->n_chain; i++)
    if (policy->chain[i].phase == phase)
      phase_entries++;
  if (phase_entries == 0)
    return 0;

  int failed_by_chain[BL_POLICY_MAX_CHAIN];
  memset (failed_by_chain, 0, sizeof failed_by_chain);
  for (int i = 0; i < policy->n_chain; i++)
    {
      if (policy->chain[i].phase != phase) continue;
      int mod = policy->chain[i].module;
      int failed = 0;

      switch (mod)
        {
        case BL_MOD_SECURETTY:
          if (ctx->u && policy->securetty && ctx->u->uid == 0)
            {
              char line[128];
              if (bl_tty_line (ctx->tty_name, line, sizeof line) < 0)
                {
                  fprintf (stderr, "Root login refused on unknown tty.\n");
                  failed = 1;
                }
              else if (!bl_policy_tty_list_contains (policy->securetty_ttys,
                                                     policy->n_securetty_ttys, line) &&
                       !bl_policy_file_contains_tty (policy->securetty_file, line))
                {
                  fprintf (stderr, "Root login refused on this tty.\n");
                  failed = 1;
                }
            }
          break;
        case BL_MOD_TIME:
          if (policy->time_deny_always)
            {
              fprintf (stderr, "Login not permitted at this time.\n");
              failed = 1;
            }
          break;
        case BL_MOD_LOCKOUT:
          if (ctx->u && bl_check_lockout (ctx->u->name, ctx->u, policy) < 0)
            failed = 1;
          break;
        case BL_MOD_LIMITS:
          failed = bl_policy_apply_limits (policy) < 0;
          break;
        case BL_MOD_ENV:
          failed = 0;
          break;
        case BL_MOD_MOTD:
          if (ctx->show_motd && !ctx->motd_done)
            {
              bl_policy_show_motd (ctx->u, ctx->tty_name);
              ctx->motd_done = 1;
            }
          break;
        case BL_MOD_LASTLOG:
          if (!ctx->lastlog_done)
            {
              failed = bl_lastlog_write (ctx->u, ctx->tty_name) < 0;
              if (!failed)
                ctx->lastlog_done = 1;
            }
          break;
        case BL_MOD_DENY:
          if (ctx->u && bl_chain_deny_matches (ctx->u, policy->chain[i].args))
            {
              if (policy->chain[i].args[0])
                fprintf (stderr, "Login denied by policy.\n");
              failed = 1;
            }
          break;
        case BL_MOD_USERDB:
          failed = ctx->u == NULL;
          break;
        case BL_MOD_CONDITION:
          failed = !bl_chain_condition_matches (ctx->u, ctx->tty_name,
                                                policy->chain[i].args);
          break;
        case BL_MOD_WARN:
          bl_chain_warn (ctx->u, ctx->tty_name, phase, policy->chain[i].args);
          failed = 0;
          break;
        case BL_MOD_EXPIRY:
          ctx->warn_remaining = -1;
          ctx->aging_status = bl_shadow_aging_status (ctx->shadow,
                                                      ctx->today_days,
                                                      &ctx->warn_remaining);
          ctx->aging_checked = 1;
          if (ctx->aging_status != 0)
            bl_shadow_aging_report (ctx->login_name ? ctx->login_name :
                                    (ctx->u ? ctx->u->name : "-"),
                                    ctx->aging_status,
                                    ctx->warn_remaining);
          failed = ctx->aging_status < 0;
          break;
        default:
          break;
        }

      failed_by_chain[i] = failed;
      int decided = 0, deciding = -1;
      int verdict = bl_policy_decide_phase (policy, phase, failed_by_chain,
                                            i, 0, &decided, &deciding);
      (void) deciding;
      if (decided)
        return verdict == 0 ? 0 : -1;
    }

  int decided = 0, deciding = -1;
  int verdict = bl_policy_decide_phase (policy, phase, failed_by_chain,
                                        policy->n_chain - 1, 1,
                                        &decided, &deciding);
  (void) decided;
  (void) deciding;
  return verdict == 0 ? 0 : -1;
}

static int
bl_login_cmd (WORD_LIST *args)
{
  const char *tty_name = NULL;
  int max_tries = 3;
  int no_motd = 0;
  int policy_chain_flag = 0;
  int keep_env = 0;
  int with_supplementary = 0;
  int no_new_privs = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-t") == 0)
        { if (!p->next) { builtin_error ("login: -t needs TTY"); return EX_USAGE; }
          p = p->next; tty_name = p->word->word; }
      else if (strcmp (w, "--no-motd") == 0) no_motd = 1;
      else if (strcmp (w, "--policy-chain") == 0) policy_chain_flag = 1;
      else if (strcmp (w, "--unsafe-keep-env") == 0) keep_env = 1;
      else if (strcmp (w, "--keep-env") == 0) {
        builtin_warning ("--keep-env is deprecated; use --unsafe-keep-env");
        keep_env = 1;
      }
      else if (strcmp (w, "--with-supplementary") == 0) with_supplementary = 1;
      else if (strcmp (w, "--no-new-privs")       == 0) no_new_privs       = 1;
      else if (strcmp (w, "--max-tries") == 0)
        { if (!p->next) { builtin_error ("login: --max-tries needs N"); return EX_USAGE; }
          p = p->next; max_tries = atoi (p->word->word); }
      else { builtin_error ("login: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (max_tries < 1 || max_tries > 10) max_tries = 3;

  bl_login_policy policy;
  if (bl_policy_load (&policy) < 0)
    return EXECUTION_FAILURE;
  int policy_chain = bl_policy_chain_requested (&policy, policy_chain_flag);
  int policy_password_phase = policy_chain &&
                              bl_policy_phase_has (&policy, BL_PH_PASSWORD);

  /* The login verb reads and verifies password bytes in-process. Avoid
     writing that address space to a core dump while authentication runs. */
  if (prctl (PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
    builtin_warning ("login: prctl(PR_SET_DUMPABLE,0): %s", strerror (errno));

  bl_login_hup_seen = 0;
  struct sigaction old_hup, old_term, old_int, sa;
  memset (&sa, 0, sizeof sa);
  sa.sa_handler = bl_login_signal;
  sigemptyset (&sa.sa_mask);
  sigaction (SIGHUP, &sa, &old_hup);
  sigaction (SIGTERM, &sa, &old_term);
  sigaction (SIGINT, &sa, &old_int);

  bl_cat_file ("/etc/issue");
  char hn[128] = "bash-os";
  FILE *hf = fopen ("/etc/hostname", "r");
  if (hf)
    {
      if (fgets (hn, sizeof hn, hf))
        hn[strcspn (hn, "\r\n")] = '\0';
      fclose (hf);
    }

  for (int attempt = 0; attempt < max_tries; attempt++)
    {
      if (bl_login_hup_seen)
        return EXECUTION_FAILURE;
      char user[64];
      printf ("%s login: ", hn);
      fflush (stdout);
      if (!fgets (user, sizeof user, stdin)) return EXECUTION_FAILURE;
      if (bl_login_hup_seen)
        return EXECUTION_FAILURE;
      user[strcspn (user, "\r\n")] = '\0';
      if (!bl_valid_user_name (user))
        {
          bl_sleep_after_failure (attempt, max_tries);
          printf ("Login incorrect\n");
          continue;
        }

	      bl_user u;
	      int lr = bl_lookup_user (user, &u);
	      if (lr != 0 && policy_chain && bl_policy_wants_nss_userdb (&policy))
	        lr = bl_lookup_user_nss (user, &u);
	      bashos_shadow_entry shadow;
	      int sr = bl_read_shadow_entry (user, &shadow);
	      if (lr == 0 && policy_chain)
	        {
	          bl_chain_ctx ctx = {
	            .u = &u, .tty_name = tty_name, .show_motd = !no_motd
	          };
	          if (bl_policy_run_chain (&policy, BL_PH_AUTH, &ctx) < 0)
	            {
	              bl_sleep_after_failure (attempt, max_tries);
	              continue;
	            }
	        }
	      else if (lr == 0 && bl_check_lockout (user, &u, &policy) < 0)
	        {
	          bl_sleep_after_failure (attempt, max_tries);
	          continue;
	        }
	      unsigned char *pw = NULL;
	      size_t pw_len = 0;
	      if (bl_read_password ("Password: ", &pw, &pw_len) < 0)
	        return EXECUTION_FAILURE;
	      if (bl_login_hup_seen)
	        {
	          if (pw)
	            {
		      bashos_secure_free_password (pw);
	            }
	          return EXECUTION_FAILURE;
	        }

      int ok = 0;
      if (lr == 0 && sr == 0 && bl_verify_secret (pw, pw_len, shadow.phc) == 0)
        ok = 1;
      bashos_secure_free_password (pw);

	      if (!ok)
	        {
	          bl_record_failure (user, lr == 0 ? &u : NULL, &policy);
	          bl_sleep_after_failure (attempt, max_tries);
	          printf ("Login incorrect\n");
	          continue;
	        }

	      long warn_remaining = -1;
	      int aging_status = 0;
	      if (policy_password_phase)
	        {
	          bl_chain_ctx ctx = {
	            .u = &u, .tty_name = tty_name, .show_motd = !no_motd,
	            .shadow = &shadow, .login_name = user,
	            .today_days = bl_today_days (), .warn_remaining = -1
	          };
	          if (bl_policy_run_chain (&policy, BL_PH_PASSWORD, &ctx) < 0)
	            return EXECUTION_FAILURE;
	          if (ctx.aging_checked)
	            {
	              aging_status = ctx.aging_status;
	              warn_remaining = ctx.warn_remaining;
	            }
	        }
	      else
	        {
	          aging_status = bl_shadow_aging_status (&shadow, bl_today_days (),
	                                                 &warn_remaining);
	          if (aging_status < 0)
	            {
	              bl_shadow_aging_report (user, aging_status, warn_remaining);
	              return EXECUTION_FAILURE;
	            }
	        }

	      if (policy_chain)
	        {
	          bl_chain_ctx ctx = {
	            .u = &u, .tty_name = tty_name, .show_motd = !no_motd
	          };
	          if (bl_policy_run_chain (&policy, BL_PH_ACCOUNT, &ctx) < 0)
	            return EXECUTION_FAILURE;
	        }
	      else
	        {
	          if (bl_policy_check_access (&policy, &u, tty_name) < 0)
	            return EXECUTION_FAILURE;

	          if (bl_nologin_blocks (&u))
	            return EXECUTION_FAILURE;
	        }

	      if (bl_login_kernel_proof (&u) < 0)
	        return EXECUTION_FAILURE;

	      bl_record_success (user, &u);
	      if (!policy_password_phase && aging_status > 0)
	        bl_shadow_aging_report (user, aging_status, warn_remaining);

	      if (tty_name && bl_record_utmp_login (&u, tty_name) < 0)
	        return EXECUTION_FAILURE;

	      if (policy_chain)
	        {
	          bl_chain_ctx ctx = {
	            .u = &u, .tty_name = tty_name, .show_motd = !no_motd
	          };
	          if (bl_policy_run_chain (&policy, BL_PH_SESSION, &ctx) < 0)
	            return EXECUTION_FAILURE;
	        }

      return bl_exec_user (&u, keep_env, 1, !no_motd && !policy_chain,
                           NULL, 0, NULL, tty_name,
                           with_supplementary, no_new_privs, NULL, &policy);
    }
  fprintf (stderr, "Maximum number of tries exceeded.\n");
  return EXECUTION_FAILURE;
}

static int
bl_aging_check_cmd (WORD_LIST *args)
{
  if (!args || !args->next || args->next->next)
    {
      builtin_error ("aging-check needs USER TODAY_DAYS");
      return EX_USAGE;
    }

  const char *user = args->word->word;
  char *end = NULL;
  errno = 0;
  long today = strtol (args->next->word->word, &end, 10);
  if (errno || !end || *end)
    {
      builtin_error ("aging-check: invalid TODAY_DAYS");
      return EX_USAGE;
    }

  bashos_shadow_entry shadow;
  int sr = bl_read_shadow_entry (user, &shadow);
  if (sr != 0)
    {
      builtin_error ("aging-check: no usable shadow entry for %s", user);
      return EXECUTION_FAILURE;
    }

  long warn_remaining = -1;
  int status = bl_shadow_aging_status (&shadow, today, &warn_remaining);
  if (status == 1)
    {
      printf ("warn %ld\n", warn_remaining);
      return EXECUTION_SUCCESS;
    }
  if (status == -1)
    {
      puts ("password-expired");
      return EXECUTION_FAILURE;
    }
  if (status == -2)
    {
      puts ("inactive");
      return EXECUTION_FAILURE;
    }
  if (status == -3)
    {
      puts ("account-expired");
      return EXECUTION_FAILURE;
    }
  puts ("ok");
  return EXECUTION_SUCCESS;
}

/* ---- Opt-in PAM-style ordered chain evaluator -------------------------- */

static const char *
bl_mod_name (int m)
{
  switch (m)
    {
    case BL_MOD_SECURETTY: return "securetty";
    case BL_MOD_TIME:      return "time";
    case BL_MOD_LOCKOUT:   return "lockout";
    case BL_MOD_LIMITS:    return "limits";
    case BL_MOD_ENV:       return "env";
    case BL_MOD_MOTD:      return "motd";
    case BL_MOD_LASTLOG:   return "lastlog";
    case BL_MOD_DENY:      return "deny";
    case BL_MOD_USERDB:    return "userdb";
    case BL_MOD_CONDITION: return "condition";
    case BL_MOD_WARN:      return "warn";
    case BL_MOD_EXPIRY:    return "expiry";
    default:               return "default";
    }
}

/* Evaluate one phase of the parsed chain with PAM control-flow semantics.
   results[] gives one outcome per chain entry OF THIS PHASE in file order
   (0 = module succeeded, non-0 = failed; missing entries default to success).
   Returns 0 (allow) / 1 (deny). *deciding (if non-NULL) gets the module enum
   that determined the verdict, or -1 for the default (empty / all-passed).
   - requisite fail  -> immediate deny
   - required  fail  -> deny at the end (keeps evaluating)
   - sufficient pass (no prior required fail) -> immediate allow
   - optional        -> v2 ignores unless it is the sole entry; v3 ignores
                        when non-optional modules exist, and all-optional
                        phases deny only when every optional module failed */
static int
bl_eval_phase (const bl_login_policy *p, int phase,
               const int *results, int nresults, int *deciding)
{
  int idx = 0;
  int failed_by_chain[BL_POLICY_MAX_CHAIN];
  memset (failed_by_chain, 0, sizeof failed_by_chain);
  for (int i = 0; i < p->n_chain; i++)
    {
      if (p->chain[i].phase != phase) continue;
      failed_by_chain[i] = (idx < nresults) ? (results[idx] != 0) : 0;
      idx++;
    }
  int decided = 0;
  return bl_policy_decide_phase (p, phase, failed_by_chain, p->n_chain - 1,
                                 1, &decided, deciding);
}

/* policy-eval PHASE [ok|fail ...] — dry-run the chain evaluator for PHASE with
   synthetic per-module results (in file order). Prints `allow module=X` or
   `deny module=X` and exits 0/1. Pure decision logic — does not touch the real
   login path (which still uses the flat-knob default until the chain is wired
   in behind BASHLOGIN_POLICY_CHAIN). */
static int
bl_policy_eval_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("policy-eval: PHASE [ok|fail ...]"); return EX_USAGE; }
  const char *phs = args->word->word;
  int phase;
  if      (bl_streq (phs, "auth"))     phase = BL_PH_AUTH;
  else if (bl_streq (phs, "account"))  phase = BL_PH_ACCOUNT;
  else if (bl_streq (phs, "session"))  phase = BL_PH_SESSION;
  else if (bl_streq (phs, "password")) phase = BL_PH_PASSWORD;
  else { builtin_error ("policy-eval: bad phase %s", phs); return EX_USAGE; }
  bl_login_policy p;
  if (bl_policy_load (&p) < 0) return EXECUTION_FAILURE;
  int results[BL_POLICY_MAX_CHAIN], nresults = 0;
  for (WORD_LIST *w = args->next; w && nresults < BL_POLICY_MAX_CHAIN; w = w->next)
    {
      const char *r = w->word->word;
      if (bl_streq (r, "ok") || bl_streq (r, "pass") || bl_streq (r, "0"))
        results[nresults++] = 0;
      else if (bl_streq (r, "fail") || bl_streq (r, "1"))
        results[nresults++] = 1;
      else { builtin_error ("policy-eval: result must be ok|fail, got %s", r); return EX_USAGE; }
    }
  int deciding = -1;
  int verdict = bl_eval_phase (&p, phase, results, nresults, &deciding);
  printf ("%s module=%s\n", verdict == 0 ? "allow" : "deny", bl_mod_name (deciding));
  return verdict == 0 ? EXECUTION_SUCCESS : 1;
}

int
login_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "lookup") == 0) return bl_lookup_cmd (args);
  if (strcmp (cmd, "policy-eval") == 0) return bl_policy_eval_cmd (args);
  if (strcmp (cmd, "become") == 0) return bl_become_cmd (args);
  if (strcmp (cmd, "login")  == 0) return bl_login_cmd (args);
  if (strcmp (cmd, "aging-check") == 0) return bl_aging_check_cmd (args);
  builtin_error ("unknown subcommand: %s (try lookup, become, login, aging-check, or policy-eval)", cmd);
  return EX_USAGE;
}

char *login_doc[] = {
  "Privilege drop + exec for bash-os multi-user auth.",
  "",
  "    login lookup USER",
  "        Print uid:gid:home:shell:gecos for USER, or exit 1.",
  "",
  "    login become USER [--auth-fd N | --auth-token HEX]",
  "                     [--unsafe-keep-env] [--no-login]",
  "                     [--with-supplementary] [--no-new-privs]",
  "                     [--caps-clear[=KEEP]]",
  "                     [-c CMD] [-- ARGS...]",
  "        Drop privileges to USER and exec their shell.",
  "        Refuses if calling uid != 0.",
  "        --auth-fd N: (preferred) read a 32-byte one-use /dev/bashos-auth",
  "          login token for USER from inherited fd N, then consume it via",
  "          ioctl(N) before any uid/gid change. Keeps the token off of",
  "          /proc/<pid>/cmdline and shell history. Required by default;",
  "          set BASHLOGIN_REQUIRE_KERNEL_TOKEN=0 only for audited legacy",
  "          root-only migration call sites.",
  "        --auth-token HEX: deprecated; same effect as --auth-fd but",
  "          passes the token in argv where it is visible to anyone who",
  "          can read /proc/<pid>/cmdline. Emits a warning and will be",
  "          removed in v4.4. Migrate to --auth-fd N.",
  "        --unsafe-keep-env: append caller env after the safe allowlist.",
  "          Crossing a uid boundary while preserving env is a known",
  "          escalation source (TZ, PERL5OPT, LD_PRELOAD via caller paths,",
  "          ...). Use only for development. The deprecated --keep-env",
  "          alias still works but prints a warning. Defense-in-depth:",
  "          even with --unsafe-keep-env, known-dangerous prefixes (LD_*,",
  "          DYLD_*, BASH_FUNC_*) and names (BASH_ENV, ENV, IFS, CDPATH,",
  "          GLOBIGNORE, PROMPT_COMMAND, PERL5*, PYTHON*, RUBY*, NODE_*,",
  "          HOSTALIASES, NLSPATH, LOCPATH, GCONV_PATH, GETCONF_DIR,",
  "          RES_OPTIONS, TERMCAP, TZDIR, SHELLOPTS, BASHOPTS, PS4,",
  "          BASH_XTRACEFD) are stripped from the child env; a single",
  "          warning prints to stderr when any were dropped.",
  "        --no-login: don't mark the shell as a login shell.",
  "        --with-supplementary: load /etc/group supplementary groups",
  "          via bc_load_supplementary_groups before the setgroups call,",
  "          matching shadow-utils su(1)/login(1)'s initgroups(3)",
  "          install. Without the flag the drop sets only the primary",
  "          gid (current Stage 23 v1 default).",
  "        --no-new-privs: set PR_SET_NO_NEW_PRIVS before the drop so",
  "          the bit survives execve(2) and defangs setuid/file-cap",
  "          binaries the dropped shell might reach.",
  "        --caps-clear[=KEEP]: clear capability sets before the drop.",
  "          Without KEEP, every capability is dropped (the child process",
  "          has zero caps). With KEEP as a comma-separated list of CAP_*",
  "          names, only the listed caps are preserved.",
  "          Requires CAP_SETPCAP in the caller's bounding set.",
  "          Example: --caps-clear=CAP_NET_RAW,CAP_NET_BIND_SERVICE",
  "        -c CMD:     exec SHELL -c CMD instead of interactive shell.",
  "        --          end of login args; rest is argv for the shell.",
  "",
  "    login login [-t TTY] [--unsafe-keep-env] [--no-motd]",
  "                    [--with-supplementary] [--no-new-privs]",
  "                    [--policy-chain] [--max-tries N]",
  "        Prompt for username/password, verify /etc/shadow, and exec shell.",
  "        -t TTY records the session through utmp before exec.",
  "        /etc/nologin blocks non-root users after successful auth",
  "          unless the opt-in policy chain owns account denial.",
  "        Successful auth mints and consumes an internal /dev/bashos-auth",
  "          token before the credential transition; set",
  "          BASHLOGIN_REQUIRE_KERNEL_TOKEN=0 only for audited migration.",
  "        --unsafe-keep-env has the same warning-level risk as become.",
  "        --with-supplementary / --no-new-privs forward through to the",
  "          drop sequence identically to become.",
  "        Stored /etc/shadow aging fields are enforced at login time:",
  "          account expiration, password max-days, warn-days, and inactive.",
  "          Minimum-days is recorded for passwd/chage compatibility; it",
  "          does not restrict login.",
  "        Optional /etc/auth.d/login policy lines use:",
  "          TYPE CONTROL DIRECTIVE [key=value ...]",
  "          Built-ins: securetty, time, lockout, limits, env,",
  "          motd, lastlog, deny, userdb.",
  "          account ... userdb source=nss can resolve identities",
  "          through bash-os NSS; password verification remains shadow.",
  "          --policy-chain, BASHLOGIN_POLICY_CHAIN=1, or policy",
  "          `version 2`/`chain` enables ordered PAM-style phase",
  "          evaluation. Default keeps the historical flat policy.",
  "          Example: auth required lockout max=5 window=600 duration=900",
  "          Missing policy keeps the historical direct-login behavior;",
  "          parse errors fail closed before password prompting.",
  "",
  "    login aging-check USER TODAY_DAYS",
  "        Offline helper: evaluate stored shadow aging fields for tests.",
  "",
  "Verification is the caller's responsibility for become; login verifies",
  "the password itself and shares passwd's persistent lockout state.",
  (char *)NULL
};

struct builtin login_struct = {
  "login",
  login_builtin,
  BUILTIN_ENABLED,
  login_doc,
  "login lookup|become|login USER [--auth-fd N | --auth-token HEX] [--with-supplementary] [--no-new-privs] [--caps-clear[=KEEP]] [...]",
  0
};
