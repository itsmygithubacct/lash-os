/* SPDX-License-Identifier: MIT */
/* doas.c - conservative doas/sudo front-end for bash-os.
 *
 * Security boundary:
 *   - This loadable is not setuid and does not implement doas.conf or
 *     sudoers policy.
 *   - Non-root callers use /dev/bashos-auth when the v2 authority is
 *     advertised, otherwise they delegate to an external setuid doas binary.
 *   - Root callers may use the loadable to drop to a target user and exec a
 *     command with a small, scrubbed environment.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>		/* isatty / fork / _exit — v2 interactive vs UMH routing */

#include "_mbedtls_sha256.h"
#include "_bashos_auth_uapi.h"
#include "bashcred_privdrop.h"
#include "loadables.h"
#include "child-wait.h"

extern char **export_env;
extern void maybe_make_export_env (void);
extern char *doas_doc[];
extern char *sudo_doc[];
/* auth is a required companion of sudo. The renderer owns its input stream. */
extern int bashos_auth_policy_list (FILE *, const char *, int, FILE *, unsigned int *);

#ifndef BDA_FD_CLOSE_MAX
#  define BDA_FD_CLOSE_MAX 1048576
#endif

/* Multi-target sudoedit cap. MUST match the kernel's
 * BASHOS_AUTH_SUDOEDIT_MAX_TARGETS (bashos_auth.c) — it is NOT exported via the
 * UAPI header, so we mirror it here. The kernel is authoritative: a request over
 * the cap is rejected (-EOPNOTSUPP) at OPEN/COPYBACK redeem; this front-end cap
 * just pre-validates + sizes the fixed per-target arrays so we never mint a
 * handle that will fail at redeem. */
#ifndef BDA_SUDOEDIT_MAX_TARGETS
#  define BDA_SUDOEDIT_MAX_TARGETS 16
#endif

#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif

typedef struct {
  int is_sudo;
  int non_interactive;
  int shell_mode;
  int login_mode;
  int edit_mode;		/* sudo -e / sudoedit: edit a file via the SUDOEDIT flow */
  int list_mode;		/* sudo -l/-ll: authority-bound, read-only policy projection */
  int validate;
  int reset;
  int reset_all;
  int reset_first;		/* sudo -k with an action: reset, then perform it */
  int target_set;		/* -u/--user given explicitly */
  const char *target;
  const char *target_group;	/* sudo -g/--group: explicit runas group (name or #gid) */
  char **env_assign;
  int envc;
  char **cmd;
  int cmdc;
  char self_target[24];		/* sudo -g without -u runs as the caller */
} bda_opts;

/* Userspace-only constant (not part of the kernel UAPI). All struct,
 * ioctl, and constant definitions for /dev/bashos-auth live in
 * _bashos_auth_uapi.h, the flattened userspace mirror of
 * kernel/bashos-auth/uapi/linux/bashos_auth.h. */
#define BASHOS_AUTH_DEV          "/dev/bashos-auth"

/* Internal routing sentinel: never collide with a child exit status. */
#define BDA_AUTH_UNAVAILABLE (-2)
#define BDA_PRIVCMD_MAX_ENVS 256
#define BDA_ENV_CALLER_PREFIX "BASHOS_CALLER_"
#define BDA_ENV_INLINE_PREFIX "BASHOS_INLINE_"
#define BDA_SECURE_PATH "/bin:/bash-os:/usr/bin"
/* sudo(8) truncates the argument text of SUDO_COMMAND at 4096 bytes so the
   diagnostic value cannot by itself make execve fail with E2BIG. */
#define BDA_SUDO_COMMAND_ARGS_MAX 4096

static int bda_wait_status (pid_t pid);
static void bda_child_reset_signals (void);
static void bda_child_close_fds (void);
static char *bda_quote_join_cmd (char **cmd, int cmdc);
static char *bda_sudo_shell_join (char **cmd, int cmdc);

/* Bash refreshes the C environ (its export_env) only when it next runs an
   external command, so after `export PATH=...` a raw execvp would search the
   old PATH and pass the old environment. Refresh it in the child first. */
static void
bda_sync_environ (void)
{
  maybe_make_export_env ();
}

/* Bash must not reap a raw child before this command collects its status.
   Keep unrelated SIGCHLD notifications pending until our wait is complete. */
static pid_t
bda_fork_owned (bos_child_wait *waiting)
{
  if (bos_child_wait_begin (waiting) < 0) return -1;
  pid_t pid = fork ();
  if (pid == 0) bos_child_wait_child (waiting);
  else if (pid < 0) bos_child_wait_end (waiting);
  return pid;
}

static int
bda_wait_owned (pid_t pid, const bos_child_wait *waiting)
{
  int rc = bda_wait_status (pid);
  bos_child_wait_end (waiting);
  return rc;
}


/* Reject numeric target overflow before the shared resolver casts to uid_t. */
static int
bda_lookup_user (const char *target, bc_user_info *u)
{
  if (bc_pd_all_digits (target))
    {
      unsigned long id;
      if (bc_pd_id (target, &id) < 0 || (unsigned long) (uid_t) id != id ||
          (uid_t) id == (uid_t) -1)
        {
          errno = EINVAL;
          return -1;
        }
    }
  return bc_lookup_user (target, u);
}

static int
bda_word_count (WORD_LIST *list)
{
  int n = 0;
  for (; list; list = list->next) n++;
  return n;
}

static char **
bda_words_to_argv (WORD_LIST *list, int *argcp)
{
  int n = bda_word_count (list);
  char **argv = calloc ((size_t) n + 1, sizeof *argv);
  if (!argv) return NULL;
  int i = 0;
  for (; list; list = list->next)
    argv[i++] = list->word->word;
  argv[i] = NULL;
  *argcp = n;
  return argv;
}

static unsigned int
bda_privcmd_mode (const bda_opts *o)
{
  if (o->validate) return BASHOS_AUTH_PRIVCMD_MODE_VALIDATE;
  if (o->reset) return BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP;
  if (o->edit_mode) return BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT;
  if (o->login_mode) return BASHOS_AUTH_PRIVCMD_MODE_LOGIN;
  if (o->shell_mode) return BASHOS_AUTH_PRIVCMD_MODE_SHELL;
  return BASHOS_AUTH_PRIVCMD_MODE_EXEC;
}

static int
bda_resolve_command (const char *word, char *out, size_t cap)
{
  const char *path, *start;
  size_t word_len;
  int too_long = 0;

  if (!word || !*word || !out || cap == 0)
    {
      errno = EINVAL;
      return -1;
    }
  word_len = strlen (word);
  if (word[0] == '/')
    {
      if (word_len >= cap)
        {
          errno = ENAMETOOLONG;
          return -1;
        }
      memcpy (out, word, word_len + 1);
      return 0;
    }

  path = BDA_SECURE_PATH;
  start = path;
  for (;;)
    {
      const char *end = strchr (start, ':');
      size_t dir_len = end ? (size_t) (end - start) : strlen (start);

      if (dir_len > 0)
        {
          if (dir_len + 1 + word_len >= cap)
            {
              too_long = 1;
            }
          else
            {
              memcpy (out, start, dir_len);
              out[dir_len] = '/';
              memcpy (out + dir_len + 1, word, word_len + 1);
              if (access (out, X_OK) == 0)
                return 0;
            }
        }
      if (!end)
        break;
      start = end + 1;
    }
  errno = too_long ? ENAMETOOLONG : ENOENT;
  return -1;
}

static char *
bda_argv_blob (char **argv, int argc, unsigned int *bytesp)
{
  size_t bytes = 0;
  for (int i = 0; i < argc; i++)
    bytes += strlen (argv[i]) + 1;
  if (bytes > 1024 * 1024)
    {
      errno = E2BIG;
      return NULL;
    }
  char *blob = calloc (bytes ? bytes : 1, 1);
  if (!blob) return NULL;
  size_t off = 0;
  for (int i = 0; i < argc; i++)
    {
      size_t n = strlen (argv[i]) + 1;
      memcpy (blob + off, argv[i], n);
      off += n;
    }
  *bytesp = (unsigned int) bytes;
  return blob;
}

static int
bda_env_name_len (const char *kv, size_t *name_lenp)
{
  const char *eq;

  if (!kv || !((*kv >= 'A' && *kv <= 'Z') || (*kv >= 'a' && *kv <= 'z') || *kv == '_'))
    return 0;
  eq = strchr (kv, '=');
  if (!eq || eq == kv)
    return 0;
  for (const char *p = kv + 1; p < eq; p++)
    if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
          (*p >= '0' && *p <= '9') || *p == '_'))
      return 0;
  *name_lenp = (size_t) (eq - kv);
  return 1;
}

static int
bda_env_vec_append_encoded (char ***vecp, int *countp, int *capp,
                            const char *prefix, const char *kv)
{
  size_t name_len;
  char *entry = NULL;
  int n;

  if (!bda_env_name_len (kv, &name_len))
    return 0;
  if (*countp >= BDA_PRIVCMD_MAX_ENVS)
    {
      errno = E2BIG;
      return -1;
    }
  if (*countp + 1 >= *capp)
    {
      int nc = *capp ? *capp * 2 : 16;
      char **nv = realloc (*vecp, (size_t) nc * sizeof **vecp);
      if (!nv)
        return -1;
      for (int i = *capp; i < nc; i++)
        nv[i] = NULL;
      *vecp = nv;
      *capp = nc;
    }
  n = asprintf (&entry, "%s%.*s%s", prefix, (int) name_len, kv, kv + name_len);
  if (n < 0)
    return -1;
  (*vecp)[(*countp)++] = entry;
  (*vecp)[*countp] = NULL;
  return 0;
}

static void
bda_env_vec_free (char **vec, int count)
{
  if (!vec) return;
  for (int i = 0; i < count; i++)
    free (vec[i]);
  free (vec);
}

static char *
bda_authority_env_blob (const bda_opts *o, unsigned int mode,
                        unsigned int *bytesp, unsigned int *countp)
{
  char **vec = NULL;
  int count = 0, cap = 0;
  char *blob;

  *bytesp = 0;
  *countp = 0;
  if (mode == BASHOS_AUTH_PRIVCMD_MODE_VALIDATE ||
      mode == BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP)
    return bda_argv_blob (NULL, 0, bytesp);

  maybe_make_export_env ();
  for (char **ep = export_env; ep && *ep; ep++)
    if (bda_env_vec_append_encoded (&vec, &count, &cap,
                                    BDA_ENV_CALLER_PREFIX, *ep) < 0)
      goto fail;
  for (int i = 0; i < o->envc; i++)
    if (bda_env_vec_append_encoded (&vec, &count, &cap,
                                    BDA_ENV_INLINE_PREFIX, o->env_assign[i]) < 0)
      goto fail;

  blob = bda_argv_blob (vec, count, bytesp);
  if (!blob && count)
    goto fail;
  *countp = (unsigned int) count;
  bda_env_vec_free (vec, count);
  return blob;

fail:
  bda_env_vec_free (vec, count);
  return NULL;
}

static int
bda_digest_update_u32 (mbedtls_sha256_context *sha, unsigned int v)
{
  unsigned char b[4];
  b[0] = (unsigned char) (v & 0xff);
  b[1] = (unsigned char) ((v >> 8) & 0xff);
  b[2] = (unsigned char) ((v >> 16) & 0xff);
  b[3] = (unsigned char) ((v >> 24) & 0xff);
  return mbedtls_sha256_update (sha, b, sizeof b);
}

static int
bda_digest_update_str (mbedtls_sha256_context *sha, const char *s)
{
  size_t n = s ? strlen (s) : 0;
  if (bda_digest_update_u32 (sha, (unsigned int) n) != 0)
    return -1;
  return n ? mbedtls_sha256_update (sha, (const unsigned char *) s, n) : 0;
}

static int
bda_fill_request_digest (struct bashos_auth_privcmd *r,
                         const char *argv_blob, const char *env_blob)
{
  mbedtls_sha256_context sha;
  mbedtls_sha256_init (&sha);
  int rc = mbedtls_sha256_starts (&sha, 0);
  if (rc == 0)
    rc = mbedtls_sha256_update (&sha,
                                (const unsigned char *) "bashos-privcmd-v1",
                                16);
  if (rc == 0) rc = bda_digest_update_u32 (&sha, r->mode);
  if (rc == 0) rc = bda_digest_update_u32 (&sha, r->flags);
  if (rc == 0) rc = bda_digest_update_u32 (&sha, r->non_interactive);
  if (rc == 0) rc = bda_digest_update_u32 (&sha, r->caller_uid);
  if (rc == 0) rc = bda_digest_update_u32 (&sha, r->caller_gid);
  if (rc == 0) rc = bda_digest_update_u32 (&sha, r->target_uid);
  if (rc == 0) rc = bda_digest_update_u32 (&sha, r->target_gid);
  if (rc == 0) rc = bda_digest_update_u32 (&sha, r->argc);
  if (rc == 0) rc = bda_digest_update_u32 (&sha, r->envc);
  if (rc == 0) rc = bda_digest_update_u32 (&sha, r->argv_bytes);
  if (rc == 0) rc = bda_digest_update_u32 (&sha, r->env_bytes);
  if (rc == 0) rc = bda_digest_update_str (&sha, r->caller_user);
  if (rc == 0) rc = bda_digest_update_str (&sha, r->target_user);
  if (rc == 0) rc = bda_digest_update_str (&sha, r->cwd);
  if (rc == 0 && r->argv_bytes)
    rc = mbedtls_sha256_update (&sha, (const unsigned char *) argv_blob,
                                r->argv_bytes);
  if (rc == 0 && r->env_bytes)
    rc = mbedtls_sha256_update (&sha, (const unsigned char *) env_blob,
                                r->env_bytes);
  if (rc == 0)
    rc = mbedtls_sha256_finish (&sha, r->request_digest);
  mbedtls_sha256_free (&sha);
  return rc == 0 ? 0 : -1;
}

static void
bda_hex_encode (const unsigned char *buf, size_t n, char *out)
{
  static const char h[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++)
    {
      out[i * 2] = h[buf[i] >> 4];
      out[i * 2 + 1] = h[buf[i] & 15];
    }
  out[n * 2] = '\0';
}

static const char *
bda_policy_status_name (unsigned int status)
{
  switch (status)
    {
    case 0: return "ok";
    case 1: return "missing";
    case 2: return "unsafe";
    case 3: return "error";
    default: return "unknown";
    }
}

static int
bda_version_reserved_zero (const struct bashos_auth_version *v)
{
  for (size_t i = 0; i < sizeof v->reserved; i++)
    if (v->reserved[i] != 0)
      return 0;
  return 1;
}

static int
bda_open_authority_if_available (void)
{
  int fd = open (BASHOS_AUTH_DEV, O_RDWR | O_CLOEXEC);
  if (fd < 0) return -1;
  int fl = fcntl (fd, F_GETFD, 0);
  if (fl >= 0)
    (void) fcntl (fd, F_SETFD, fl | FD_CLOEXEC);

  struct bashos_auth_version v;
  memset (&v, 0, sizeof v);
  if (ioctl (fd, BASHOS_AUTH_IOC_VERSION, &v) < 0)
    {
      close (fd);
      errno = ENODEV;
      return -1;
    }
  if (v.abi_major != BASHOS_AUTH_ABI_MAJOR ||
      v.abi_minor < BASHOS_AUTH_ABI_MINOR ||
      !bda_version_reserved_zero (&v))
    {
      close (fd);
      errno = EPROTO;
      return -1;
    }
  if ((v.features & BASHOS_AUTH_FEAT_PRIVCMD) == 0)
    {
      close (fd);
      errno = ENODEV;
      return -1;
    }
  return fd;
}

static void
bda_exec_verify_child (int fd, const bda_opts *o,
                       const struct bashos_auth_privcmd *r)
{
  struct bashos_auth_exec_verify_req vr;
  memset (&vr, 0, sizeof vr);
  vr.size = sizeof vr;
  vr.mode = r->mode;
  vr.caller_uid = r->caller_uid;
  vr.caller_gid = r->caller_gid;
  vr.target_uid = r->target_uid;
  vr.target_gid = r->target_gid;
  vr.policy_generation = r->policy_generation;
  vr.timeout_sec = r->timestamp_timeout;
  vr.policy_status = r->policy_status;
  memcpy (vr.request_digest, r->request_digest, sizeof vr.request_digest);
  memcpy (vr.normalized_policy_digest, r->normalized_policy_digest,
          sizeof vr.normalized_policy_digest);
  if (ioctl (fd, BASHOS_AUTH_IOC_EXEC_VERIFY, &vr) < 0)
    {
      fprintf (stderr, "%s: v2 verifier launch failed: %s\n",
               o->is_sudo ? "sudo" : "doas", strerror (errno));
      _exit (126);
    }
  _exit (0); /* success replaces this process with /bash-os/auth-verify */
}

static int
bda_run_verify_once (int fd, const bda_opts *o,
                     const struct bashos_auth_privcmd *r)
{
  bos_child_wait waiting;
  pid_t pid = bda_fork_owned (&waiting);
  if (pid < 0)
    {
      builtin_error ("v2 verifier fork: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (pid == 0)
    bda_exec_verify_child (fd, o, r);
  return bda_wait_owned (pid, &waiting);
}

static void
bda_reset_authz_response (struct bashos_auth_privcmd *r)
{
  r->decision = 0;
  r->env_policy = 0;
  r->timestamp_timeout = 0;
  r->policy_generation = 0;
  r->policy_status = 0;
  r->reserved0 = 0;
  r->audit_id = 0;
  memset (r->exec_token, 0, sizeof r->exec_token);
  memset (r->policy_digest, 0, sizeof r->policy_digest);
  memset (r->normalized_policy_digest, 0, sizeof r->normalized_policy_digest);
  memset (r->reason, 0, sizeof r->reason);
  r->handle_id = 0;
  r->handle_expires_sec = 0;
  memset (r->reserved, 0, sizeof r->reserved);
}

/* Resolve a sudo -g/--group GROUP spec to a numeric gid. "#NNN" is a literal
 * gid; otherwise the NAME is looked up in /etc/group (field 2). Returns 0 on
 * success, -1 on unknown/malformed. (Evaluates the gid field while it is still
 * NUL-terminated, BEFORE restoring the ':' separator — the verifier passwd-parse
 * bug lesson.) */
static int
bda_group_to_gid (const char *spec, gid_t *out)
{
  if (!spec || !*spec)
    return -1;
  if (spec[0] == '#')
    {
      unsigned long v;
      if (bc_pd_id (spec + 1, &v) < 0 ||
          (unsigned long) (gid_t) v != v || (gid_t) v == (gid_t) -1)
        return -1;
      *out = (gid_t) v;
      return 0;
    }

  FILE *f = fopen ("/etc/group", "r");
  char *line = NULL;
  size_t cap = 0;
  int found = -1;
  if (!f)
    return -1;
  while (getline (&line, &cap, f) >= 0)
    {
      char *p1 = strchr (line, ':');	/* after group name */
      char *p2, *p3;
      unsigned long g;
      if (!p1 || (size_t) (p1 - line) != strlen (spec) ||
          memcmp (line, spec, (size_t) (p1 - line)) != 0)
        continue;
      p2 = strchr (p1 + 1, ':');	/* after passwd field */
      if (!p2)
        continue;
      p3 = strchr (p2 + 1, ':');	/* after gid field */
      if (!p3)
        continue;
      *p3 = '\0';
      if (bc_pd_id (p2 + 1, &g) == 0 &&
          (unsigned long) (gid_t) g == g && (gid_t) g != (gid_t) -1)
        {
          *out = (gid_t) g;
          found = 0;
        }
      *p3 = ':';
      break;
    }
  free (line);
  fclose (f);
  return found;
}

/* Resolve the editor to run, AS THE CALLER, on a sudoedit temp copy. Mirrors
 * sudo's SUDO_EDITOR/VISUAL/EDITOR precedence with a conservative /bin/vi
 * fallback. Like sudo, the variable is split into words at blanks without
 * shell parsing, so SUDO_EDITOR="vi -n" passes an option; a blank variable is
 * skipped. The editor NEVER runs as root: this front-end is already executing
 * as the unprivileged caller on the SUDOEDIT path. Returns a malloc'd argv of
 * the editor words followed by the N temp paths; *wordsp owns the strings. */
static char **
bda_sudoedit_editor_argv (char **temps, int n, char **wordsp)
{
  static const char *vars[] = { "SUDO_EDITOR", "VISUAL", "EDITOR", NULL };
  const char *e = NULL;
  char *words, *p;
  char **argv;
  int count = 0, i;

  *wordsp = NULL;
  for (i = 0; vars[i] && !e; i++)
    {
      const char *v = getenv (vars[i]);
      if (v && v[strspn (v, " \t\n")])
        e = v;
    }
  if (!e)
    e = "/bin/vi";
  words = strdup (e);
  if (!words)
    return NULL;
  for (p = words; *p; )
    {
      p += strspn (p, " \t\n");
      if (!*p)
        break;
      count++;
      p += strcspn (p, " \t\n");
    }
  /* [word0 .. word{count-1}, temp0 .. temp{n-1}, NULL] */
  argv = (char **) malloc ((size_t) (count + n + 1) * sizeof (char *));
  if (!argv)
    {
      free (words);
      return NULL;
    }
  count = 0;
  for (p = words; *p; )
    {
      p += strspn (p, " \t\n");
      if (!*p)
        break;
      argv[count++] = p;
      p += strcspn (p, " \t\n");
      if (*p)
        *p++ = '\0';
    }
  for (i = 0; i < n; i++)
    argv[count + i] = temps[i];
  argv[count + n] = NULL;
  *wordsp = words;
  return argv;
}

/* Fork+exec the editor ONCE on all N temp copies as the caller (no privilege
 * transition) and wait — this mirrors real sudoedit, which invokes
 * `$EDITOR temp1 temp2 ...` in a single editor session. The environment is the
 * caller's own (the editor runs with caller authority). Returns the editor exit
 * status, or -1 on spawn failure. n must be >= 1. */
static int
bda_spawn_editor (char **temps, int n)
{
  pid_t pid;
  char **argv, *words;

  if (n < 1)
    return -1;
  argv = bda_sudoedit_editor_argv (temps, n, &words);
  if (!argv)
    return -1;

  fflush (NULL);
  bos_child_wait waiting;
  pid = bda_fork_owned (&waiting);
  if (pid < 0)
    {
      free (argv);
      free (words);
      return -1;
    }
  if (pid == 0)
    {
      /* Caller creds are already in effect (non-root SUDOEDIT path). */
      bda_child_reset_signals ();
      bda_child_close_fds ();
      bda_sync_environ ();
      execvp (argv[0], argv);
      _exit (127);
    }
  free (argv);			/* child has its own (COW) copy; parent's is done */
  free (words);
  return bda_wait_owned (pid, &waiting);
}

/*
 * SUDOEDIT two-call orchestration (front-end half), N targets (1..MAX). On entry
 * *r has been AUTHZ'd to DECISION_ALLOW_EDIT (handle minted in r->handle_id) and
 * argv_blob carries the N absolute target paths (argc==eff_cmdc). Steps:
 *
 *   Phase 1 (OPEN): EXEC_HANDOFF + SUDOEDIT_OPEN re-presents the digest-bound
 *     argv; the kernel safe-opens EVERY target as root and returns N caller-owned
 *     temp-copy paths (NUL-separated). (The OPEN handle is single-use consumed.)
 *   Phase 2 (edit-as-caller): run $EDITOR ONCE on all N temps AS THE CALLER.
 *   Phase 3 (COPYBACK): re-run AUTHZ to MINT A FRESH EDIT HANDLE (the
 *     between-phases policy revalidation — if policy drifted, AUTHZ now denies
 *     and copyback never happens; argv is byte-identical so the OPEN session,
 *     keyed by argv_digest, is the one the kernel consumes), then EXEC_HANDOFF +
 *     SUDOEDIT_COPYBACK with the fd VECTOR (one open fd per edited temp); the
 *     kernel revalidates each inode identity + atomically renames each temp over
 *     ONLY its originally-authorized target. The cross-target rename is NOT
 *     atomic (documented irreducible residual) — a Pass-2 failure can leave a
 *     prefix committed; we surface the kernel reject_stage verbatim.
 *
 * The single-use token is consumed per phase (OPEN consumes handle #1, COPYBACK
 * consumes handle #2 from the re-AUTHZ), so no token is reused across phases.
 * We always use the fd VECTOR (sudoedit_temp_fds_*), even for N==1, rather than
 * the legacy scalar sudoedit_temp_fd — one code path, and it exercises the
 * vector uniformly. On the shipped image the kernel copyback gate is OFF:
 * EXEC_HANDOFF -ENOSYS's the EDIT redeem and we report a clean "not enabled"
 * error (no file touched).
 */
static int
bda_run_sudoedit (int fd, const bda_opts *o, struct bashos_auth_privcmd *r,
                  char *argv_blob, unsigned int argv_bytes, int eff_cmdc)
{
  int n = eff_cmdc;
  struct bashos_auth_exec_handoff_req hr;
  char *paths_buf = NULL;
  size_t cap;
  char *temps[BDA_SUDOEDIT_MAX_TARGETS];	/* point into paths_buf */
  unsigned int tfds[BDA_SUDOEDIT_MAX_TARGETS];	/* __u32 fd vector for COPYBACK */
  int opened[BDA_SUDOEDIT_MAX_TARGETS];		/* fds to close on exit (-1 = none) */
  int i, edrc, rc = EXECUTION_FAILURE;
  unsigned int bytes;
  size_t off;

  if (n < 1 || n > BDA_SUDOEDIT_MAX_TARGETS)
    {
      builtin_error ("sudoedit: target count %d out of range (1..%d)",
                     n, BDA_SUDOEDIT_MAX_TARGETS);
      return EXECUTION_FAILURE;
    }
  for (i = 0; i < n; i++)
    {
      temps[i] = NULL;
      tfds[i] = 0;
      opened[i] = -1;
    }
  if (r->handle_id == 0)
    {
      builtin_error ("v2 authority: sudoedit allow without a handle");
      return EXECUTION_FAILURE;
    }

  cap = (size_t) n * BASHOS_AUTH_PATH_BYTES;
  paths_buf = (char *) malloc (cap);
  if (!paths_buf)
    {
      builtin_error ("sudoedit: out of memory");
      return EXECUTION_FAILURE;
    }

  /* Phase 1: OPEN — kernel safe-opens every target and returns N temp paths. */
  memset (&hr, 0, sizeof hr);
  hr.size = sizeof hr;
  hr.mode = BASHOS_AUTH_EXEC_HANDOFF_MODE_NONINTERACTIVE;
  hr.flags = BASHOS_AUTH_EXEC_HANDOFF_FLAG_SUDOEDIT_OPEN;
  hr.argc = (unsigned int) n;
  hr.argv_bytes = argv_bytes;
  hr.argv_user_ptr = (unsigned long long) (uintptr_t) argv_blob;
  hr.handle.handle_id = r->handle_id;
  hr.sudoedit_temp_paths_user_ptr = (unsigned long long) (uintptr_t) paths_buf;
  hr.sudoedit_temp_paths_cap = (unsigned int) cap;
  if (ioctl (fd, BASHOS_AUTH_IOC_EXEC_HANDOFF, &hr) < 0)
    {
      if (errno == ENOSYS)
        builtin_error ("sudoedit is not enabled on this system "
                       "(kernel sudoedit_live gate is off)");
      else
        builtin_error ("v2 authority sudoedit open: %s (reject_stage=%u)",
                       strerror (errno), hr.reject_stage);
      goto cleanup;
    }
  if (hr.approval_status != BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_ALLOWED ||
      hr.sudoedit_temp_count != (unsigned int) n)
    {
      builtin_error ("v2 authority sudoedit open denied: reject_stage=%u "
                     "(temp_count=%u, expected %d)",
                     hr.reject_stage, hr.sudoedit_temp_count, n);
      goto cleanup;
    }

  /* Parse N NUL-terminated temp paths packed back-to-back in paths_buf, bounded
   * by sudoedit_temp_paths_bytes. Each must be non-empty + NUL-terminated within
   * the reported byte span; anything else is a malformed kernel reply -> abort. */
  bytes = hr.sudoedit_temp_paths_bytes;
  if (bytes == 0 || bytes > cap)
    {
      builtin_error ("sudoedit: malformed temp-path buffer (%u bytes)", bytes);
      goto cleanup;
    }
  off = 0;
  for (i = 0; i < n; i++)
    {
      size_t len;
      if (off >= bytes)
        {
          builtin_error ("sudoedit: temp-path buffer underran at target %d", i);
          goto cleanup;
        }
      len = strnlen (paths_buf + off, (size_t) bytes - off);
      if (len == 0 || off + len >= bytes)	/* empty or unterminated */
        {
          builtin_error ("sudoedit: malformed temp path at target %d", i);
          goto cleanup;
        }
      temps[i] = paths_buf + off;
      off += len + 1;
    }

  /* Phase 2: run the editor ONCE on all N temps AS THE CALLER. */
  edrc = bda_spawn_editor (temps, n);
  if (edrc != 0)
    {
      builtin_error ("sudoedit: editor exited %d; not copying back", edrc);
      goto cleanup;
    }

  /* Phase 3a: RE-AUTHZ to mint a fresh handle (revalidates policy between the
   * open and the copyback — a policy reload denies here and aborts copyback).
   * argv is unchanged, so the digest (and the kernel OPEN session keyed by it)
   * is identical to Phase 1. */
  bda_reset_authz_response (r);
  if (ioctl (fd, BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, r) < 0)
    {
      builtin_error ("v2 authority sudoedit re-authz: %s", strerror (errno));
      goto cleanup;
    }
  /* The password timestamp can expire while the editor is open — and a
   * multi-file edit keeps it open longer — so a non-NOPASSWD rule's re-AUTHZ
   * may now come back AUTH_REQUIRED rather than ALLOW_EDIT. That is NOT a policy
   * denial: re-verify ONCE (interactive only) and re-AUTHZ, mirroring the
   * entry-AUTHZ path, so a still-permitted edit is not silently thrown away. A
   * scripted/non-tty caller cannot re-prompt and falls through to the clear
   * "authentication required" diagnostic below (edit discarded, fail-closed). */
  if (r->decision == BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED &&
      o && !o->non_interactive && isatty (STDIN_FILENO))
    {
      if (bda_run_verify_once (fd, o, r) == 0)
        {
          bda_reset_authz_response (r);
          if (ioctl (fd, BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, r) < 0)
            {
              builtin_error ("v2 authority sudoedit re-authz after verify: %s",
                             strerror (errno));
              goto cleanup;
            }
        }
    }
  if (r->decision != BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT || r->handle_id == 0)
    {
      const char *why =
          (r->decision == BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED)
              ? "authentication required (timestamp expired during edit); "
                "re-run sudoedit"
              : (r->reason[0] ? r->reason : "policy drift");
      builtin_error ("v2 authority sudoedit revalidation denied (%s); "
                     "edits discarded, original(s) untouched", why);
      goto cleanup;
    }

  /* Phase 3b: open each edited temp read-only + build the __u32 fd vector. */
  for (i = 0; i < n; i++)
    {
      int t = open (temps[i], O_RDONLY | O_NOFOLLOW);
      if (t < 0)
        {
          builtin_error ("sudoedit: cannot reopen edited temp %s: %s",
                         temps[i], strerror (errno));
          goto cleanup;
        }
      opened[i] = t;
      tfds[i] = (unsigned int) t;
    }
  memset (&hr, 0, sizeof hr);
  hr.size = sizeof hr;
  hr.mode = BASHOS_AUTH_EXEC_HANDOFF_MODE_NONINTERACTIVE;
  hr.flags = BASHOS_AUTH_EXEC_HANDOFF_FLAG_SUDOEDIT_COPYBACK;
  hr.argc = (unsigned int) n;
  hr.argv_bytes = argv_bytes;
  hr.argv_user_ptr = (unsigned long long) (uintptr_t) argv_blob;
  hr.handle.handle_id = r->handle_id;
  hr.sudoedit_temp_fds_user_ptr = (unsigned long long) (uintptr_t) tfds;
  hr.sudoedit_temp_fds_count = (unsigned int) n;
  hr.sudoedit_temp_fds_reserved = 0;
  if (ioctl (fd, BASHOS_AUTH_IOC_EXEC_HANDOFF, &hr) < 0)
    {
      if (errno == ENOSYS)
        builtin_error ("sudoedit copyback not enabled (kernel sudoedit_live gate off)");
      else
        builtin_error ("v2 authority sudoedit copyback: %s (reject_stage=%u)",
                       strerror (errno), hr.reject_stage);
      goto cleanup;
    }
  if (hr.approval_status != BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_ALLOWED)
    {
      builtin_error ("v2 authority sudoedit copyback denied: reject_stage=%u "
                     "(original(s) untouched unless a partial multi-target "
                     "commit is reported)", hr.reject_stage);
      goto cleanup;
    }
  rc = EXECUTION_SUCCESS;

cleanup:
  for (i = 0; i < n; i++)
    if (opened[i] >= 0)
      close (opened[i]);
  /* caller-owned temps; remove after copyback (or on any abort). */
  for (i = 0; i < n; i++)
    if (temps[i])
      (void) unlink (temps[i]);
  free (paths_buf);
  return rc;
}

/* Absolute $SHELL, otherwise the invoking account's shell. -1 leaves the
   caller free to keep the target account's shell. */
static int
bda_sudo_invoke_shell (char *out, size_t cap)
{
  const char *env = getenv ("SHELL");
  const char *chosen = NULL;
  bc_user_info me;
  char id[32];

  if (env && env[0] == '/')
    chosen = env;
  else
    {
      snprintf (id, sizeof id, "%lu", (unsigned long) getuid ());
      if (bda_lookup_user (id, &me) == 0 && me.shell[0] == '/')
        chosen = me.shell;
    }
  if (!chosen)
    return -1;
  if (strlen (chosen) >= cap)
    {
      errno = ENAMETOOLONG;
      return -1;
    }
  memcpy (out, chosen, strlen (chosen) + 1);
  return 0;
}

/* Read or write the one-byte interactive verification marker. EINTR is
   retried. Any other error means the parent cannot tell a verify-only child
   from one that executed, so the caller fails closed. */
static int
bda_status_write (int fd, const void *buf, size_t n)
{
  const char *p = buf;
  size_t off = 0;

  while (off < n)
    {
      ssize_t w = write (fd, p + off, n - off);
      if (w < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }
      if (w == 0)
        return -1;
      off += (size_t) w;
    }
  return 0;
}

/* 1 = one byte read, 0 = EOF (no marker), -1 = error with errno set. */
static int
bda_status_read (int fd, char *marker)
{
  for (;;)
    {
      ssize_t n = read (fd, marker, 1);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }
      if (n == 0)
        {
          *marker = 0;
          return 0;
        }
      return 1;
    }
}

/* Required gids stay in the vector. Supplementary groups fill the remaining
   slots. A full list loses a non-required membership before a required gid.
   Returns -1 only when the required gids themselves do not fit. */
static int
bda_ensure_groups (gid_t *groups, int *ngroups, gid_t passwd_gid, gid_t primary)
{
  gid_t required[2];
  int nreq = 0;

  required[nreq++] = passwd_gid;
  if (primary != passwd_gid)
    required[nreq++] = primary;
  for (int r = 0; r < nreq; r++)
    {
      int have = 0;
      for (int i = 0; i < *ngroups; i++)
        if (groups[i] == required[r])
          have = 1;
      if (have)
        continue;
      if (*ngroups >= BC_PD_GROUPS_MAX)
        {
          int drop = -1;
          for (int i = *ngroups - 1; i >= 0; i--)
            {
              int keep = 0;
              for (int k = 0; k < nreq; k++)
                if (groups[i] == required[k])
                  keep = 1;
              if (!keep)
                {
                  drop = i;
                  break;
                }
            }
          if (drop < 0)
            return -1;
          for (int i = drop; i < *ngroups - 1; i++)
            groups[i] = groups[i + 1];
          (*ngroups)--;
        }
      groups[(*ngroups)++] = required[r];
    }
  return 0;
}

static int
bda_run_authority (const bda_opts *o)
{
  /* sudo -k with an action first discards the cached credential, so the
     action is authorized afresh. A failed reset performs nothing. */
  if (o->reset_first)
    {
      bda_opts ro = *o;
      ro.reset_first = 0;
      ro.reset = 1;
      ro.validate = ro.edit_mode = ro.shell_mode = ro.login_mode = 0;
      ro.cmdc = ro.envc = 0;
      int rrc = bda_run_authority (&ro);
      if (rrc != EXECUTION_SUCCESS)
        return rrc;
    }

  int fd = bda_open_authority_if_available ();
  if (fd < 0)
    return BDA_AUTH_UNAVAILABLE;
  char *shell_quote = NULL;

  const char *target = o->target ? o->target : "root";
  bc_user_info u;
  if (bda_lookup_user (target, &u) != 0)
    {
      close (fd);
      builtin_error ("unknown user: %s", target);
      return EXECUTION_FAILURE;
    }

  /* sudo -g/--group: resolve the explicit runas group to a numeric gid up front
   * (a bad group fails before any authority call). The kernel matches this
   * target_gid against the matched rule's runas ':group' half ONLY when the
   * EXPLICIT_GROUP flag is set; without -g the target user's default gid is used
   * and the runas group half is not consulted. */
  gid_t bda_explicit_gid = 0;
  int bda_have_group = 0;
  if (o->target_group)
    {
      if (bda_group_to_gid (o->target_group, &bda_explicit_gid) != 0)
        {
          close (fd);
          builtin_error ("unknown group: %s", o->target_group);
          return EXECUTION_FAILURE;
        }
      bda_have_group = 1;
    }

  if (o->cmdc == 0 && !o->shell_mode && !o->login_mode &&
      !o->validate && !o->reset)
    {
      close (fd);
      builtin_error ("command required");
      return EX_USAGE;
    }

  /* SUDOEDIT: 1..MAX absolute target files. The kernel safe-opens each
   * digest-bound target no-follow; a relative path can't be made safe across the
   * open/copyback re-resolution, so every target must be absolute. The kernel is
   * authoritative on the cap (rejects >MAX at redeem); we pre-validate here so a
   * bad request fails before minting a handle. */
  if (o->edit_mode)
    {
      int ei;
      if (o->cmdc < 1 || o->cmdc > BDA_SUDOEDIT_MAX_TARGETS)
        {
          close (fd);
          builtin_error ("sudoedit: 1..%d file arguments required (got %d)",
                         BDA_SUDOEDIT_MAX_TARGETS, o->cmdc);
          return EX_USAGE;
        }
      for (ei = 0; ei < o->cmdc; ei++)
        if (o->cmd[ei][0] != '/')
          {
            close (fd);
            builtin_error ("sudoedit: file must be an absolute path: %s",
                           o->cmd[ei]);
            return EX_USAGE;
          }
    }

  /* SHELL (-s) / LOGIN (-i). The kernel executes argv[0], so the front-end
     supplies the absolute shell. With no command, argv is that shell, and -i
     appends "-l". sudo with a command runs `shell [-l] -c` on one string:
     each byte except ASCII alphanumerics, '_', '-' and '$' is backslash-escaped
     and the words are joined with spaces. doas keeps an explicit command
     unwrapped. sudo -s uses $SHELL or the invoking account's shell; -i and
     doas use the target account's shell. */
  char *synth_cmd[5];
  char invoke_shell[PATH_MAX];
  char **eff_cmd = o->cmd;
  int eff_cmdc = o->cmdc;
  const char *mode_shell = u.shell;
  if (o->is_sudo && o->shell_mode && !o->login_mode &&
      bda_sudo_invoke_shell (invoke_shell, sizeof invoke_shell) == 0)
    mode_shell = invoke_shell;
  if (o->shell_mode || o->login_mode)
    {
      if (mode_shell[0] != '/')
        {
          close (fd);
          builtin_error ("no valid login shell for %s", u.name);
          return EXECUTION_FAILURE;
        }
      if (o->cmdc == 0)
        {
          synth_cmd[0] = (char *) mode_shell;
          eff_cmdc = 1;
          if (o->login_mode)
            {
              synth_cmd[1] = (char *) "-l";
              eff_cmdc = 2;
            }
          synth_cmd[eff_cmdc] = NULL;
          eff_cmd = synth_cmd;
        }
      else if (o->is_sudo)
        {
          int ai = 0;
          shell_quote = bda_sudo_shell_join (o->cmd, o->cmdc);
          if (!shell_quote)
            {
              close (fd);
              builtin_error ("shell command build: out of memory");
              return EXECUTION_FAILURE;
            }
          synth_cmd[ai++] = (char *) mode_shell;
          if (o->login_mode)
            synth_cmd[ai++] = (char *) "-l";
          synth_cmd[ai++] = (char *) "-c";
          synth_cmd[ai++] = shell_quote;
          synth_cmd[ai] = NULL;
          eff_cmd = synth_cmd;
          eff_cmdc = ai;
        }
    }

  unsigned int argv_bytes = 0, env_bytes = 0, env_count = 0;
  unsigned int req_mode = bda_privcmd_mode (o);
  char resolved_cmd[PATH_MAX];
  if (req_mode == BASHOS_AUTH_PRIVCMD_MODE_EXEC && eff_cmdc > 0 && eff_cmd[0][0] != '/')
    {
      if (bda_resolve_command (eff_cmd[0], resolved_cmd, sizeof resolved_cmd) < 0)
        {
          close (fd);
          builtin_error ("command not found in secure path: %s", eff_cmd[0]);
          return 127;
        }
      eff_cmd[0] = resolved_cmd;
    }
  char *argv_blob = bda_argv_blob (eff_cmd, eff_cmdc, &argv_bytes);
  if (!argv_blob && eff_cmdc)
    {
      free (shell_quote);
      close (fd);
      builtin_error ("v2 authority argv build: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  char *env_blob = bda_authority_env_blob (o, req_mode, &env_bytes, &env_count);
  if (!env_blob && errno)
    {
      free (shell_quote);
      free (argv_blob);
      close (fd);
      builtin_error ("v2 authority env build: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }

  struct bashos_auth_privcmd r;
  memset (&r, 0, sizeof r);
  r.size = sizeof r;
  r.mode = req_mode;
  if (o->reset_all)
    r.flags |= BASHOS_AUTH_PRIVCMD_FLAG_RESET_ALL;
  if (bda_have_group)
    r.flags |= BASHOS_AUTH_PRIVCMD_FLAG_EXPLICIT_GROUP;
  r.non_interactive = (unsigned int) o->non_interactive;
  r.caller_uid = (unsigned int) getuid ();
  r.caller_gid = (unsigned int) getgid ();
  r.target_uid = (unsigned int) u.uid;
  r.target_gid = bda_have_group ? (unsigned int) bda_explicit_gid
                                : (unsigned int) u.gid;
  r.argc = (unsigned int) eff_cmdc;
  r.envc = env_count;
  r.argv_bytes = argv_bytes;
  r.env_bytes = env_bytes;
  /* The kernel's validate_blob requires a NULL user_ptr when the count is 0
   * (rejects "unexpected privcmd {argv,env} blob" otherwise). bda_argv_blob
   * returns a 1-byte allocation even for count 0, so only publish the pointer
   * when there is actually content. */
  r.argv_user_ptr = (eff_cmdc && argv_blob) ? (unsigned long long) (uintptr_t) argv_blob : 0;
  r.env_user_ptr  = (env_count && env_blob)  ? (unsigned long long) (uintptr_t) env_blob  : 0;
  snprintf (r.caller_user, sizeof r.caller_user, "%u", r.caller_uid);
  snprintf (r.target_user, sizeof r.target_user, "%s", u.name);
  if (!getcwd (r.cwd, sizeof r.cwd))
    strncpy (r.cwd, "/", sizeof r.cwd - 1);

  int rc = EXECUTION_FAILURE;
  if (bda_fill_request_digest (&r, argv_blob, env_blob) < 0)
    {
      builtin_error ("v2 authority request digest failed");
      goto out;
    }

  /*
   * ROUTING: an EXEC command, or a SHELL (-s) / LOGIN (-i) request, with a
   * controlling tty (and no -n) runs via the INTERACTIVE in-context-execve path
   * so it keeps the tty (editors, interactive root shells, etc.). The front-end
   * supplies the argv for every mode, including a sudo shell command wrapped as
   * `shell [-l] -c`. Everything else
   * (piped/scripted, -n, SUDOEDIT) runs via the non-interactive UMH handoff. The
   * interactive path requires mint+redeem in the SAME task (kernel lineage
   * check) and replaces the task on success, so it FORKS and does AUTHZ +
   * EXEC_INTERACTIVE in the child; the parent (this shell) survives + reports.
   */
  int bda_wants_interactive =
      (r.mode == BASHOS_AUTH_PRIVCMD_MODE_EXEC ||
       r.mode == BASHOS_AUTH_PRIVCMD_MODE_SHELL ||
       r.mode == BASHOS_AUTH_PRIVCMD_MODE_LOGIN);
  if (bda_wants_interactive && !o->non_interactive && isatty (STDIN_FILENO))
    {
      int verified_once = 0;
      for (;;)
        {
          int pfd[2];
          char marker = 0;
          if (pipe (pfd) < 0)
            {
              builtin_error ("v2 authority pipe: %s", strerror (errno));
              goto out;
            }
          fflush (NULL);
          bos_child_wait waiting;
          pid_t pid = bda_fork_owned (&waiting);
          if (pid < 0)
            {
              close (pfd[0]);
              close (pfd[1]);
              builtin_error ("v2 authority fork: %s", strerror (errno));
              goto out;
            }
          if (pid == 0)
            {
              close (pfd[0]);
              bda_reset_authz_response (&r);
              if (ioctl (fd, BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, &r) < 0)
                { fprintf (stderr, "%s: v2 AUTHZ: %s\n", o->is_sudo ? "sudo" : "doas", strerror (errno)); _exit (125); }
              if (r.decision == BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED)
                {
                  /* A verify-only child must deliver the marker before it
                     can exit 0. A failed write is not verification. */
                  if (bda_status_write (pfd[1], "V", 1) < 0)
                    {
                      close (pfd[1]);
                      _exit (125);
                    }
                  close (pfd[1]);
                  bda_exec_verify_child (fd, o, &r);
                }
              close (pfd[1]);
              if (r.decision != BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC || r.handle_id == 0)
                { fprintf (stderr, "%s: v2 authority denied (%s)\n", o->is_sudo ? "sudo" : "doas", r.reason[0] ? r.reason : "denied"); _exit (125); }
              struct bashos_auth_exec_handoff_req hr;
              memset (&hr, 0, sizeof hr);
              hr.size = sizeof hr;
              hr.mode = BASHOS_AUTH_EXEC_HANDOFF_MODE_INTERACTIVE;
              /* EXEC/SHELL/LOGIN all carry a command argv: EXEC the caller's command,
               * SHELL/LOGIN the synthesized login shell (eff_cmd). argc>=1 always. */
              hr.argc = (unsigned int) eff_cmdc;
              hr.argv_bytes = argv_bytes;
              hr.argv_user_ptr = (unsigned long long) (uintptr_t) argv_blob;
              hr.handle.handle_id = r.handle_id;
              /* On success the kernel replaces this child with the target on the tty
               * (never returns); on ANY return it failed (and was force-killed if
               * already elevated) — report + die without running as the target. */
              ioctl (fd, BASHOS_AUTH_IOC_EXEC_INTERACTIVE, &hr);
              fprintf (stderr, "%s: v2 interactive elevation failed: reject_stage=%u\n",
                       o->is_sudo ? "sudo" : "doas", hr.reject_stage);
              _exit (126);
            }
          close (pfd[1]);
          marker = 0;
          int status_rc = bda_status_read (pfd[0], &marker);
          int status_errno = errno;
          close (pfd[0]);
          /* Reap the child and restore the parent's signals even when the
             marker itself cannot be read. */
          rc = bda_wait_owned (pid, &waiting);
          if (status_rc < 0)
            {
              builtin_error ("v2 authority status: %s", strerror (status_errno));
              rc = EXECUTION_FAILURE;
              break;
            }
          /* A byte other than V is not a verify-only child and not a
             finished command. EOF (status_rc 0) still returns the wait
             status. The writer only emits V; anything else fails closed. */
          if (status_rc == 1 && marker != 'V')
            {
              builtin_error ("v2 authority status: unexpected marker");
              rc = EXECUTION_FAILURE;
              break;
            }
          if (marker == 'V' && rc == 0 && !verified_once)
            {
              verified_once = 1;
              continue;
            }
          /* A child that only verified never ran the command: success of a
             second verification is not authorization. */
          if (marker == 'V' && rc == 0)
            {
              builtin_error ("v2 authority still requires authentication after verification");
              rc = EXECUTION_FAILURE;
            }
          break;
        }
      goto out;
    }

  /* NON-INTERACTIVE: AUTHZ + UMH handoff in this process (no tty needed). */
  bda_reset_authz_response (&r);
  if (ioctl (fd, BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, &r) < 0)
    {
      builtin_error ("v2 authority ioctl: %s", strerror (errno));
      goto out;
    }
  if (r.decision == BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED)
    {
      if (o->non_interactive || !isatty (STDIN_FILENO))
        {
          builtin_error ("v2 authority requires authentication");
          goto out;
        }
      rc = bda_run_verify_once (fd, o, &r);
      if (rc != 0)
        goto out;
      /* Successful verification is not authorization. Any retry failure or
         denial must retain failure until an explicit successful response. */
      rc = EXECUTION_FAILURE;
      bda_reset_authz_response (&r);
      if (ioctl (fd, BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, &r) < 0)
        {
          builtin_error ("v2 authority ioctl after verification: %s", strerror (errno));
          goto out;
        }
    }
  if (r.decision == BASHOS_AUTH_PRIVCMD_DECISION_DENY)
    {
      char digest_hex[65];
      char normalized_digest_hex[65];
      bda_hex_encode (r.policy_digest, sizeof r.policy_digest, digest_hex);
      bda_hex_encode (r.normalized_policy_digest,
                      sizeof r.normalized_policy_digest, normalized_digest_hex);
      builtin_error ("v2 authority denied: audit_id=%llu policy_generation=%u policy_status=%s policy_sha256=%s normalized_policy_sha256=%s reason=%s",
                     r.audit_id, r.policy_generation,
                     bda_policy_status_name (r.policy_status), digest_hex,
                     normalized_digest_hex,
                     r.reason[0] ? r.reason : "denied");
      goto out;
    }
  if ((r.decision == BASHOS_AUTH_PRIVCMD_DECISION_VALIDATE_OK &&
       req_mode == BASHOS_AUTH_PRIVCMD_MODE_VALIDATE) ||
      (r.decision == BASHOS_AUTH_PRIVCMD_DECISION_RESET_OK &&
       req_mode == BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP))
    {
      rc = EXECUTION_SUCCESS;
      goto out;
    }
  if (r.decision == BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT && o->edit_mode)
    {
      /* SUDOEDIT: two-call open/edit-as-caller/copyback orchestration. */
      rc = bda_run_sudoedit (fd, o, &r, argv_blob, argv_bytes, eff_cmdc);
      goto out;
    }
  if (r.decision != BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC || r.handle_id == 0 ||
      (req_mode != BASHOS_AUTH_PRIVCMD_MODE_EXEC &&
       req_mode != BASHOS_AUTH_PRIVCMD_MODE_SHELL &&
       req_mode != BASHOS_AUTH_PRIVCMD_MODE_LOGIN))
    {
      builtin_error ("v2 authority: invalid exec decision or missing handle");
      goto out;
    }
  {
    struct bashos_auth_exec_handoff_req hr;
    memset (&hr, 0, sizeof hr);
    hr.size = sizeof hr;
    hr.mode = BASHOS_AUTH_EXEC_HANDOFF_MODE_NONINTERACTIVE;
    hr.argc = (unsigned int) eff_cmdc;
    hr.argv_bytes = argv_bytes;
    hr.argv_user_ptr = (unsigned long long) (uintptr_t) argv_blob;
    hr.handle.handle_id = r.handle_id;
    if (ioctl (fd, BASHOS_AUTH_IOC_EXEC_HANDOFF, &hr) < 0)
      {
        builtin_error ("v2 authority EXEC_HANDOFF: %s", strerror (errno));
        goto out;
      }
    if (hr.approval_status != BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_ALLOWED &&
        hr.approval_status != BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_FORCED_UMH)
      {
        builtin_error ("v2 authority handoff denied: reject_stage=%u", hr.reject_stage);
        goto out;
      }
    rc = (int) hr.exit_code;	/* the UMH-run command's exit status */
  }

out:
  free (shell_quote);
  free (argv_blob);
  free (env_blob);
  close (fd);
  return rc;
}

static int
bda_is_env_assign (const char *s)
{
  if (!s || !((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') || *s == '_'))
    return 0;
  for (const char *p = s + 1; *p; p++)
    {
      if (*p == '=') return 1;
      if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
            (*p >= '0' && *p <= '9') || *p == '_'))
        return 0;
    }
  return 0;
}

static int
bda_env_name_dangerous (const char *kv)
{
  const char *eq = strchr (kv, '=');
  size_t n = eq ? (size_t) (eq - kv) : strlen (kv);
  static const char *prefixes[] = { "LD_", "DYLD_", "BASH_FUNC_", NULL };
  for (int i = 0; prefixes[i]; i++)
    {
      size_t p = strlen (prefixes[i]);
      if (n >= p && strncmp (kv, prefixes[i], p) == 0) return 1;
    }
  static const char *exact[] = {
    "PERL5OPT", "PERL5LIB", "PERLLIB", "PERL5DB",
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT",
    "PYTHONUSERBASE", "PYTHONNOUSERSITE", "PYTHONOPTIMIZE",
    "RUBYOPT", "RUBYLIB", "RUBYPATH",
    "BASH_ENV", "ENV", "CDPATH", "IFS", "GLOBIGNORE", "PROMPT_COMMAND",
    "NODE_OPTIONS", "NODE_PATH",
    "HOSTALIASES", "NLSPATH", "LOCPATH", "GCONV_PATH", "GETCONF_DIR",
    "RES_OPTIONS", "TERMCAP", "TZDIR",
    /* Bash startup-influencing vars: bash imports SHELLOPTS/BASHOPTS at
       startup and applies the encoded set -o / shopt options; PS4 is
       command-substituted under xtrace (SHELLOPTS=xtrace + PS4='$(cmd)' runs
       cmd as the target user at shell start); BASH_XTRACEFD redirects trace
       output to an inherited fd. bash-os's login shell is bash. Keep this
       list in sync with bashos_ce_env_name_is_dangerous (_bashauth/cred_exec.c),
       the shared scrub used by login/su. */
    "SHELLOPTS", "BASHOPTS", "PS4", "BASH_XTRACEFD",
    NULL
  };
  for (int i = 0; exact[i]; i++)
    if (n == strlen (exact[i]) && strncmp (kv, exact[i], n) == 0) return 1;
  return 0;
}

static int
bda_append_env (char ***envp, size_t *usedp, size_t *capp, char *entry)
{
  if (!entry) return -1;
  if (*usedp + 1 >= *capp)
    {
      size_t nc = *capp ? *capp * 2 : 16;
      char **ne = realloc (*envp, nc * sizeof **envp);
      if (!ne) { free (entry); return -1; }
      for (size_t k = *capp; k < nc; k++) ne[k] = NULL;
      *envp = ne;
      *capp = nc;
    }
  (*envp)[(*usedp)++] = entry;
  (*envp)[*usedp] = NULL;
  return 0;
}

static int
bda_append_envf (char ***envp, size_t *usedp, size_t *capp,
                 const char *name, const char *value)
{
  char *entry = NULL;
  if (asprintf (&entry, "%s=%s", name, value ? value : "") < 0) return -1;
  return bda_append_env (envp, usedp, capp, entry);
}

static void
bda_free_env (char **env)
{
  if (!env) return;
  for (char **e = env; *e; e++) free (*e);
  free (env);
}

static char **
bda_build_env (const bc_user_info *u, const bda_opts *o)
{
  size_t cap = 16, used = 0;
  char **env = calloc (cap, sizeof *env);
  if (!env) return NULL;

  if (bda_append_envf (&env, &used, &cap, "USER", u->name) < 0 ||
      bda_append_envf (&env, &used, &cap, "LOGNAME", u->name) < 0 ||
      bda_append_envf (&env, &used, &cap, "HOME", u->home) < 0 ||
      bda_append_envf (&env, &used, &cap, "SHELL", u->shell) < 0 ||
      bda_append_envf (&env, &used, &cap, "PATH", BDA_SECURE_PATH) < 0)
    goto fail;

  const char *keep[] = { "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ", NULL };
  for (int i = 0; keep[i]; i++)
    {
      const char *v = getenv (keep[i]);
      if (v && bda_append_envf (&env, &used, &cap, keep[i], v) < 0)
        goto fail;
    }

  /* SUDO_USER names the invoking account, not a caller-set $USER. */
  bc_user_info caller;
  const char *su = NULL;
  if (bc_lookup_user_by_uid (getuid (), &caller) == 0)
    su = caller.name;
  if (!su || !*su) su = getenv ("USER");
  if (!su || !*su) su = getenv ("LOGNAME");
  if (!su || !*su) su = "root";
  char uidbuf[32], gidbuf[32];
  snprintf (uidbuf, sizeof uidbuf, "%ld", (long) getuid ());
  snprintf (gidbuf, sizeof gidbuf, "%ld", (long) getgid ());
  if (bda_append_envf (&env, &used, &cap, "SUDO_USER", su) < 0 ||
      bda_append_envf (&env, &used, &cap, "SUDO_UID", uidbuf) < 0 ||
      bda_append_envf (&env, &used, &cap, "SUDO_GID", gidbuf) < 0)
    goto fail;

  /* A command-line assignment replaces any entry of the same name, so the
     child sees one value: the last one given. */
  for (int i = 0; i < o->envc; i++)
    {
      const char *kv = o->env_assign[i];
      size_t n = strcspn (kv, "=");
      size_t k;
      if (bda_env_name_dangerous (kv))
        continue;
      for (k = 0; k < used; k++)
        if (strncmp (env[k], kv, n) == 0 && env[k][n] == '=')
          break;
      if (k < used)
        {
          char *entry = strdup (kv);
          if (!entry) goto fail;
          free (env[k]);
          env[k] = entry;
        }
      else if (bda_append_env (&env, &used, &cap, strdup (kv)) < 0)
        goto fail;
    }
  return env;

fail:
  bda_free_env (env);
  return NULL;
}

/* Append SUDO_COMMAND=PREFIX[ WORD...] to a built environment. The words are
   joined by single spaces, unquoted, and the argument text is truncated at
   4096 bytes (sudo(8)) so a long argv cannot make this one string exceed the
   kernel's exec limit. The argv passed to execve is unchanged. A command-line
   assignment of the same name is already present and wins. */
static int
bda_env_add_command (char ***envp, const char *prefix, char **words, int n)
{
  size_t used = 0, cap, prefix_len, args_used = 0, value_len;
  char *value;
  int rc, any = 0;

  if (!prefix)
    return -1;
  for (char **e = *envp; *e; e++)
    if (strncmp (*e, "SUDO_COMMAND=", 13) == 0)
      return 0;
  prefix_len = strlen (prefix);
  if (prefix_len > SIZE_MAX - (BDA_SUDO_COMMAND_ARGS_MAX + 2))
    return -1;
  value = malloc (prefix_len + BDA_SUDO_COMMAND_ARGS_MAX + 2);
  if (!value)
    return -1;
  memcpy (value, prefix, prefix_len);
  value_len = prefix_len;
  for (int i = 0; i < n && args_used < BDA_SUDO_COMMAND_ARGS_MAX; i++)
    {
      const char *word = words[i] ? words[i] : "";
      size_t wlen = strlen (word);
      size_t room, copy;

      if (!any)
        {
          value[value_len++] = ' ';
          any = 1;
        }
      else
        {
          value[value_len++] = ' ';
          args_used++;
          if (args_used >= BDA_SUDO_COMMAND_ARGS_MAX)
            break;
        }
      room = BDA_SUDO_COMMAND_ARGS_MAX - args_used;
      copy = wlen < room ? wlen : room;
      memcpy (value + value_len, word, copy);
      value_len += copy;
      args_used += copy;
      if (copy < wlen)
        break;
    }
  value[value_len] = '\0';
  while ((*envp)[used])
    used++;
  cap = used + 1;
  rc = bda_append_envf (envp, &used, &cap, "SUDO_COMMAND", value);
  free (value);
  return rc;
}

static int
bda_quote_append (char *out, size_t cap, size_t *pos, const char *s)
{
  if (*pos + 2 >= cap) return -1;
  out[(*pos)++] = '\'';
  for (const char *p = s; *p; p++)
    {
      if (*p == '\'')
        {
          if (*pos + 4 >= cap) return -1;
          out[(*pos)++] = '\'';
          out[(*pos)++] = '\\';
          out[(*pos)++] = '\'';
          out[(*pos)++] = '\'';
        }
      else
        {
          if (*pos + 1 >= cap) return -1;
          out[(*pos)++] = *p;
        }
    }
  if (*pos + 1 >= cap) return -1;
  out[(*pos)++] = '\'';
  out[*pos] = '\0';
  return 0;
}

static char *
bda_quote_join_cmd (char **cmd, int cmdc)
{
  size_t n = 1;
  for (int i = 0; i < cmdc; i++) n += (strlen (cmd[i]) * 4) + 4;
  char *out = malloc (n);
  if (!out) return NULL;
  out[0] = '\0';
  size_t pos = 0;
  for (int i = 0; i < cmdc; i++)
    {
      if (i)
        {
          if (pos + 1 >= n) { free (out); return NULL; }
          out[pos++] = ' ';
          out[pos] = '\0';
        }
      if (bda_quote_append (out, n, &pos, cmd[i]) < 0)
        { free (out); return NULL; }
    }
  return out;
}

/* sudo 1.9.16p2 -i/-s: escape every byte except ASCII letters, digits,
   underscore, hyphen and dollar, then join the words with single spaces.
   Dollar is left for the target shell. Two cases that rule cannot express
   stay words. An empty argument is two single quotes, because a raw empty
   field disappears between spaces. An argument that contains a newline is
   single-quoted, with an embedded quote closed and reopened, because a
   backslash before a raw newline is a shell line continuation and deletes
   the newline. A dollar in a newline word is therefore literal. doas does
   not use this function. */
static int
bda_sudo_escape_append (char *out, size_t cap, size_t *pos, const char *s)
{
  for (const unsigned char *p = (const unsigned char *) s; *p; p++)
    {
      int plain = (*p >= '0' && *p <= '9')
        || (*p >= 'A' && *p <= 'Z')
        || (*p >= 'a' && *p <= 'z')
        || *p == '_' || *p == '-' || *p == '$';
      if (!plain)
        {
          if (*pos + 1 >= cap)
            return -1;
          out[(*pos)++] = '\\';
        }
      if (*pos + 1 >= cap)
        return -1;
      out[(*pos)++] = (char) *p;
    }
  out[*pos] = '\0';
  return 0;
}

static char *
bda_sudo_shell_join (char **cmd, int cmdc)
{
  size_t n = 1;

  for (int i = 0; i < cmdc; i++)
    {
      const char *s = cmd[i] ? cmd[i] : "";
      size_t len = strlen (s);
      if (i)
        n += 1;
      if (!*s || strchr (s, '\n'))
        n += len * 4 + 2;
      else
        n += len * 2;
    }
  char *out = malloc (n);
  if (!out)
    return NULL;
  out[0] = '\0';
  size_t pos = 0;
  for (int i = 0; i < cmdc; i++)
    {
      const char *s = cmd[i] ? cmd[i] : "";
      if (i)
        {
          if (pos + 1 >= n)
            {
              free (out);
              return NULL;
            }
          out[pos++] = ' ';
          out[pos] = '\0';
        }
      int quoted = !*s || strchr (s, '\n');
      if ((quoted ? bda_quote_append (out, n, &pos, s)
                  : bda_sudo_escape_append (out, n, &pos, s)) < 0)
        {
          free (out);
          return NULL;
        }
    }
  return out;
}

static int
bda_wait_status (pid_t pid)
{
  int st;
  pid_t w;
  while ((w = waitpid (pid, &st, 0)) < 0 && errno == EINTR) { }
  if (w < 0)
    {
      builtin_error ("waitpid: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (WIFEXITED (st)) return WEXITSTATUS (st);
  if (WIFSIGNALED (st)) return 128 + WTERMSIG (st);
  return EXECUTION_FAILURE;
}

static void
bda_child_reset_signals (void)
{
  sigset_t empty;
  if (sigemptyset (&empty) == 0)
    (void) sigprocmask (SIG_SETMASK, &empty, NULL);

  int sigs[] = {
    SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE,
    SIGPIPE, SIGALRM, SIGTERM, SIGUSR1, SIGUSR2, SIGCHLD, SIGCONT,
    SIGTSTP, SIGTTIN, SIGTTOU
  };
  for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++)
    (void) signal (sigs[i], SIG_DFL);
}

static void
bda_child_close_fds (void)
{
#ifdef SYS_close_range
  /* One kernel operation avoids a million failed close calls on shells with a
     large RLIMIT_NOFILE. Older kernels and syscall filters use the loop. */
  if (syscall (SYS_close_range, 3U, ~0U, 0U) == 0)
    return;
#endif
  long maxfd = sysconf (_SC_OPEN_MAX);
  if (maxfd < 0 || maxfd > BDA_FD_CLOSE_MAX)
    maxfd = BDA_FD_CLOSE_MAX;
  for (int fd = 3; fd < maxfd; fd++)
    (void) close (fd);
}

/* Without the authority, sudo's default delegate is an external doas, which
   understands only part of sudo's syntax. Translate what doas expresses and
   refuse the rest, rather than handing doas sudo-only words to misread. */
static char **
bda_sudo_doas_argv (const bda_opts *o, const char *path)
{
  const char *why = NULL;
  if (o->login_mode) why = "-i";
  else if (o->edit_mode) why = "-e";
  else if (o->validate) why = "-v";
  else if (o->target_group) why = "-g";
  else if (o->reset_first) why = "-k with a command";
  else if (o->envc) why = "VAR=value";
  else if (o->shell_mode && o->cmdc) why = "-s with a command";
  if (why)
    {
      builtin_error ("%s requires the bash-os authority; external doas cannot express it", why);
      return NULL;
    }

  char **argv = calloc ((size_t) o->cmdc + 8, sizeof *argv);
  int n = 0;
  if (!argv)
    {
      builtin_error ("out of memory");
      return NULL;
    }
  argv[n++] = (char *) path;
  if (o->reset)
    argv[n++] = (char *) "-L";
  else
    {
      if (o->non_interactive) argv[n++] = (char *) "-n";
      argv[n++] = (char *) "-u";
      argv[n++] = (char *) o->target;
      if (o->shell_mode) argv[n++] = (char *) "-s";
      else
        {
          argv[n++] = (char *) "--";
          for (int i = 0; i < o->cmdc; i++)
            argv[n++] = o->cmd[i];
        }
    }
  argv[n] = NULL;
  return argv;
}

static char **
bda_verbatim_argv (const char *path, char **orig, int origc)
{
  char **argv = calloc ((size_t) origc + 2, sizeof *argv);
  if (!argv)
    {
      builtin_error ("out of memory");
      return NULL;
    }
  argv[0] = (char *) path;
  for (int i = 0; i < origc; i++) argv[i + 1] = orig[i];
  argv[origc + 1] = NULL;
  return argv;
}

static int
bda_run_external (const bda_opts *o, char **orig, int origc)
{
  /* An explicitly named delegate receives the original words unchanged. */
  const char *path = getenv (o->is_sudo ? "BASHSUDO_EXTERNAL" : "BASHDOAS_EXTERNAL");
  if (!path || !*path) path = getenv (o->is_sudo ? "BASHDOAS_EXTERNAL" : "BASHSUDO_EXTERNAL");
  char **argv;
  if (path && *path)
    argv = bda_verbatim_argv (path, orig, origc);
  else
    {
      path = "doas";
      argv = o->is_sudo ? bda_sudo_doas_argv (o, path)
                        : bda_verbatim_argv (path, orig, origc);
    }
  if (!argv)
    return EXECUTION_FAILURE;

  bos_child_wait waiting;
  pid_t pid = bda_fork_owned (&waiting);
  if (pid < 0)
    {
      builtin_error ("fork: %s", strerror (errno));
      free (argv);
      return EXECUTION_FAILURE;
    }
  if (pid == 0)
    {
      bda_child_reset_signals ();
      bda_child_close_fds ();
      bda_sync_environ ();
      execvp (path, argv);
      int exec_errno = errno;
      fprintf (stderr, "%s: external doas: %s: %s\n",
               o->is_sudo ? "sudo" : "doas", path, strerror (errno));
      _exit (exec_errno == ENOENT ? 127 : 126);
    }
  free (argv);
  return bda_wait_owned (pid, &waiting);
}

/* A list is a caller-filtered policy projection, never an authorization.
   Read only the path advertised by the authority, bind the exact bytes to its
   digest, and render a private snapshot. No host sudoers convention, untrusted
   override path, authentication, token, or command execution is involved. */
static int
bda_run_list (const bda_opts *o, char **orig, int origc)
{
  int authority = bda_open_authority_if_available ();
  if (authority < 0)
    {
      /* Only an explicitly selected sudo-compatible delegate can list.
         The default external doas cannot express this operation. */
      const char *delegate = getenv ("BASHSUDO_EXTERNAL");
      if (delegate && *delegate)
        return bda_run_external (o, orig, origc);
      builtin_error ("listing requires the bash-os authority or BASHSUDO_EXTERNAL");
      return EXECUTION_FAILURE;
    }

  int rc = EXECUTION_FAILURE, fd = -1;
  FILE *input = NULL, *output = NULL;
  char *bytes = NULL, *rendered = NULL;
  size_t rendered_len = 0;
  struct bashos_auth_policy_info p, after;
  struct stat st;
  bc_user_info caller;
  unsigned char digest[32];
  unsigned int entries = 0;

  /* Native listing is a read-only projection for the caller. Do not silently
     discard command, runas, assignment or timestamp modifiers. */
  if (o->cmdc || o->envc || o->target_set || o->target_group ||
      o->reset || o->reset_first)
    {
      builtin_error ("native listing accepts only -l/-ll/--list and -n");
      rc = EX_USAGE;
      goto out;
    }
  if (bc_lookup_user_by_uid (getuid (), &caller) < 0)
    {
      builtin_error ("listing: cannot resolve caller");
      goto out;
    }
  memset (&p, 0, sizeof p);
  p.size = sizeof p;
  if (ioctl (authority, BASHOS_AUTH_IOC_POLICY_INFO, &p) < 0)
    {
      builtin_error ("listing: policy info: %s", strerror (errno));
      goto out;
    }
  if (p.status != BASHOS_AUTH_POLICY_STATUS_OK || p.path[0] != '/' ||
      !memchr (p.path, 0, sizeof p.path) || p.size_bytes > 1024 * 1024 ||
      p.uid != 0 || (p.mode & 022))
    {
      builtin_error ("listing: unavailable or unsafe policy metadata");
      goto out;
    }
  fd = open (p.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0)
    {
      builtin_error ("listing: open policy: %s", strerror (errno));
      goto out;
    }
  if (fstat (fd, &st) < 0 || !S_ISREG (st.st_mode) || st.st_uid != p.uid ||
      st.st_gid != p.gid || (st.st_mode & 07777) != (p.mode & 07777) ||
      st.st_ino != p.ino || st.st_size < 0 ||
      (unsigned long long) st.st_size != p.size_bytes ||
      st.st_mtime != p.mtime_sec || st.st_ctime != p.ctime_sec)
    {
      builtin_error ("listing: policy metadata changed or not a regular file");
      goto out;
    }
  size_t size = (size_t) p.size_bytes, used = 0;
  bytes = malloc (size + 1);
  if (!bytes) goto out;
  /* Include one extra byte in the read to reject a growing file. */
  while (used < size + 1)
    {
      ssize_t n = read (fd, bytes + used, size + 1 - used);
      if (n < 0 && errno == EINTR) continue;
      if (n < 0)
        {
          builtin_error ("listing: read policy: %s", strerror (errno));
          goto out;
        }
      if (n == 0) break;
      used += (size_t) n;
    }
  close (fd);
  fd = -1;
  if (used != size || memchr (bytes, 0, size) ||
      mbedtls_sha256 ((const unsigned char *) bytes, size, digest, 0) != 0 ||
      memcmp (digest, p.policy_digest, sizeof digest))
    {
      builtin_error ("listing: policy content does not match authority digest");
      goto out;
    }
  bytes[size] = 0;
  /* fmemopen rejects an empty buffer on some libcs; the NUL terminator gives
     an empty policy a portable readable stream. Nonempty input uses its size. */
  input = fmemopen (bytes, size ? size : 1, "r");
  output = open_memstream (&rendered, &rendered_len);
  if (!input || !output) goto out;
  rc = bashos_auth_policy_list (input, caller.name, o->list_mode > 1,
                               output, &entries);
  input = NULL;                 /* renderer closed it */
  if (fclose (output) != 0) rc = EXECUTION_FAILURE;
  output = NULL;
  if (rc != EXECUTION_SUCCESS) goto out;
  rc = EXECUTION_FAILURE;
  memset (&after, 0, sizeof after);
  after.size = sizeof after;
  if (ioctl (authority, BASHOS_AUTH_IOC_POLICY_INFO, &after) < 0 ||
      after.status != BASHOS_AUTH_POLICY_STATUS_OK ||
      after.generation != p.generation ||
      memcmp (after.policy_digest, p.policy_digest, sizeof p.policy_digest) ||
      memcmp (after.normalized_policy_digest, p.normalized_policy_digest,
              sizeof p.normalized_policy_digest) ||
      memcmp (after.path, p.path, sizeof p.path))
    {
      builtin_error ("listing: authority policy changed while listing");
      goto out;
    }
  printf ("Policy projection for %s (generation %u; not an execution approval):\n",
          caller.name, p.generation);
  if (fwrite (rendered, 1, rendered_len, stdout) != rendered_len ||
      fflush (stdout) != 0 || ferror (stdout))
    goto out;
  rc = entries ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
out:
  if (input) fclose (input);
  if (output) fclose (output);
  if (fd >= 0) close (fd);
  close (authority);
  free (bytes);
  free (rendered);
  return rc;
}

static int
bda_run_root (const bda_opts *o)
{
  const char *target = o->target ? o->target : "root";
  bc_user_info u;
  char err[BC_PD_ERR_MAX];
  if (bda_lookup_user (target, &u) != 0)
    {
      builtin_error ("unknown user: %s", target);
      return EXECUTION_FAILURE;
    }

  /* The target keeps its account's primary group as a supplementary group
     when -g selects another primary group, as sudo's runas group vector does.
     That gid is required: a full membership list must not drop it. */
  gid_t passwd_gid = u.gid;
  if (o->target_group && bda_group_to_gid (o->target_group, &u.gid) != 0)
    {
      builtin_error ("unknown group: %s", o->target_group);
      return EXECUTION_FAILURE;
    }

  if (o->reset) return EXECUTION_SUCCESS;
  if (o->validate) return EXECUTION_SUCCESS;
  if (o->edit_mode)
    {
      /* Root caller editing file(s): no privilege transition is needed (root is
       * already privileged), so just run the editor on the targets directly.
       * The kernel SUDOEDIT copyback flow exists for the UNPRIVILEGED caller. */
      if (o->cmdc < 1 || o->cmdc > BDA_SUDOEDIT_MAX_TARGETS)
        {
          builtin_error ("sudoedit: 1..%d file arguments required (got %d)",
                         BDA_SUDOEDIT_MAX_TARGETS, o->cmdc);
          return EX_USAGE;
        }
      return bda_spawn_editor (o->cmd, o->cmdc) == 0 ? EXECUTION_SUCCESS
                                                     : EXECUTION_FAILURE;
    }
  if (o->cmdc == 0 && !o->shell_mode && !o->login_mode)
    {
      builtin_error ("command required");
      return EX_USAGE;
    }

  char invoke_shell[PATH_MAX];
  const char *sudo_s_shell = NULL;
  if (o->is_sudo && o->shell_mode && !o->login_mode &&
      bda_sudo_invoke_shell (invoke_shell, sizeof invoke_shell) == 0)
    sudo_s_shell = invoke_shell;

  bos_child_wait waiting;
  pid_t pid = bda_fork_owned (&waiting);
  if (pid < 0)
    {
      builtin_error ("fork: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (pid == 0)
    {
      gid_t groups[BC_PD_GROUPS_MAX];
      int ngroups = 0;
      (void) bc_load_supplementary_groups (u.name, groups, &ngroups, BC_PD_GROUPS_MAX);
      if (bda_ensure_groups (groups, &ngroups, passwd_gid, u.gid) < 0)
        {
          fprintf (stderr, "%s: group vector cannot hold the required groups\n",
                   o->is_sudo ? "sudo" : "doas");
          _exit (126);
        }
      /* Capture caller IDs in SUDO_UID/GID before changing credentials. */
      char **env = bda_build_env (&u, o);
      if (!env)
        {
          fprintf (stderr, "%s: env build: out of memory\n",
                   o->is_sudo ? "sudo" : "doas");
          _exit (126);
        }
      if (u.uid != 0 && bc_no_new_privs (err, sizeof err) < 0)
        {
          fprintf (stderr, "%s: no_new_privs: %s\n",
                   o->is_sudo ? "sudo" : "doas", err);
          _exit (126);
        }
      if (bc_privdrop_to_user (u.uid, u.gid, groups, ngroups, err, sizeof err) < 0)
        {
          fprintf (stderr, "%s: privdrop: %s\n",
                   o->is_sudo ? "sudo" : "doas", err);
          _exit (126);
        }

      bda_child_reset_signals ();
      bda_child_close_fds ();
      /* sudo -i starts in the target's home; like sudo, a missing home is
         reported and the shell starts where it is. */
      if (o->login_mode && chdir (u.home) < 0)
        fprintf (stderr, "%s: unable to change directory to %s: %s\n",
                 o->is_sudo ? "sudo" : "doas", u.home, strerror (errno));
      if (o->shell_mode || o->login_mode || o->cmdc == 0)
        {
          /* sudo -s runs the invoking shell. -i and doas keep the target shell. */
          const char *shell_path = sudo_s_shell ? sudo_s_shell : u.shell;
          /* doas keeps the single-quoted command string. sudo uses the
             sudo(8) -i/-s escape class. */
          char *cmdstr = NULL;
          if (o->cmdc)
            cmdstr = o->is_sudo ? bda_sudo_shell_join (o->cmd, o->cmdc)
                                : bda_quote_join_cmd (o->cmd, o->cmdc);
          if (o->cmdc && !cmdstr)
            {
              fprintf (stderr, "%s: shell command build: out of memory\n",
                       o->is_sudo ? "sudo" : "doas");
              _exit (126);
            }
          char *shell_words[] = { (char *) "-c", cmdstr };
          if (o->is_sudo &&
              bda_env_add_command (&env, shell_path, shell_words, cmdstr ? 2 : 0) < 0)
            {
              fprintf (stderr, "sudo: env build: out of memory\n");
              _exit (126);
            }
          /* A login shell is named "-" plus the target shell's basename. */
          char login_name[sizeof u.shell + 1];
          const char *base = strrchr (u.shell, '/');
          snprintf (login_name, sizeof login_name, "-%s", base ? base + 1 : u.shell);
          char *argv[5];
          int ai = 0;
          argv[ai++] = o->login_mode ? login_name : (char *) shell_path;
          if (cmdstr)
            {
              if (o->login_mode) argv[ai++] = "-l";
              argv[ai++] = "-c";
              argv[ai++] = cmdstr;
            }
          else if (o->login_mode)
            {
              argv[ai++] = "-l";
            }
          argv[ai] = NULL;
          execve (shell_path, argv, env);
          int exec_errno = errno;
          fprintf (stderr, "%s: exec %s: %s\n",
                   o->is_sudo ? "sudo" : "doas", shell_path, strerror (errno));
          _exit (exec_errno == ENOENT ? 127 : 126);
        }

      char resolved_cmd[PATH_MAX];
      char **exec_cmd = o->cmd;
      if (bda_resolve_command (o->cmd[0], resolved_cmd, sizeof resolved_cmd) < 0)
        {
          fprintf (stderr, "%s: command not found in secure path: %s\n",
                   o->is_sudo ? "sudo" : "doas", o->cmd[0]);
          _exit (127);
        }
      exec_cmd[0] = resolved_cmd;
      if (o->is_sudo &&
          bda_env_add_command (&env, exec_cmd[0], exec_cmd + 1, o->cmdc - 1) < 0)
        {
          fprintf (stderr, "sudo: env build: out of memory\n");
          _exit (126);
        }
      execve (exec_cmd[0], exec_cmd, env);
      int exec_errno = errno;
      fprintf (stderr, "%s: exec %s: %s\n",
               o->is_sudo ? "sudo" : "doas", exec_cmd[0], strerror (errno));
      _exit (exec_errno == ENOENT ? 127 : 126);
    }
  return bda_wait_owned (pid, &waiting);
}

static void
bda_init_opts (bda_opts *o, int is_sudo)
{
  memset (o, 0, sizeof *o);
  o->is_sudo = is_sudo;
  o->target = "root";
}

static int
bda_refuse (const char *prog, const char *flag)
{
  builtin_error ("%s is not supported by %s v1", flag, prog);
  return EX_USAGE;
}

static int
bda_parse_doas (bda_opts *o, char **argv, int argc)
{
  int i = 0;
  for (; i < argc; i++)
    {
      char *a = argv[i];
      if (strcmp (a, "--") == 0) { i++; break; }
      if (strcmp (a, "-n") == 0) o->non_interactive = 1;
      else if (strcmp (a, "-s") == 0) o->shell_mode = 1;
      else if (strcmp (a, "-L") == 0) o->reset = 1;
      else if (strcmp (a, "-u") == 0)
        {
          if (++i >= argc) { builtin_error ("-u needs USER"); return EX_USAGE; }
          o->target = argv[i];
        }
      else if (strncmp (a, "-u", 2) == 0 && a[2])
        o->target = a + 2;
      else if (strcmp (a, "-g") == 0 || strcmp (a, "--group") == 0)
        {
          if (++i >= argc) { builtin_error ("%s needs GROUP", a); return EX_USAGE; }
          o->target_group = argv[i];
        }
      else if (strncmp (a, "--group=", 8) == 0)
        o->target_group = a + 8;
      else if (strncmp (a, "-g", 2) == 0 && a[2])
        o->target_group = a + 2;
      else if (a[0] == '-')
        return bda_refuse ("doas", a);
      else break;
    }
  o->cmd = argv + i;
  o->cmdc = argc - i;
  return EXECUTION_SUCCESS;
}

/* Only one of -e, -i, -K, -l, -s and -v may be given; repeating one is fine. */
static int
bda_sudo_mode (bda_opts *o, char *excl, char opt)
{
  if (*excl && *excl != opt)
    {
      builtin_error ("only one of the -e, -i, -K, -l, -s or -v options may be specified");
      return EX_USAGE;
    }
  *excl = opt;
  switch (opt)
    {
    case 'e': o->edit_mode = 1; break;
    case 'i': o->login_mode = 1; break;
    case 'K': o->reset = o->reset_all = 1; break;
    case 'l': o->list_mode = o->list_mode ? 2 : 1; break;
    case 's': o->shell_mode = 1; break;
    case 'v': o->validate = 1; break;
    }
  return EXECUTION_SUCCESS;
}

static int
bda_sudo_flag (bda_opts *o, char *excl, char opt)
{
  char flag[3] = { '-', opt, '\0' };
  switch (opt)
    {
    case 'n': o->non_interactive = 1; return EXECUTION_SUCCESS;
    case 'k': o->reset = 1; return EXECUTION_SUCCESS;
    case 'H': case 'B': return EXECUTION_SUCCESS;
    case 'e': case 'i': case 'K': case 'l': case 's': case 'v':
      return bda_sudo_mode (o, excl, opt);
    default: return bda_refuse ("sudo", flag);
    }
}

static void
bda_sudo_value (bda_opts *o, char opt, const char *value)
{
  if (opt == 'u')
    {
      o->target = value[0] == '#' ? value + 1 : value;
      o->target_set = 1;
    }
  else
    o->target_group = value;
}

static const struct { const char *name; char opt; int arg; } bda_sudo_long[] = {
  { "non-interactive", 'n', 0 }, { "shell", 's', 0 }, { "login", 'i', 0 },
  { "reset-timestamp", 'k', 0 }, { "remove-timestamp", 'K', 0 },
  { "validate", 'v', 0 }, { "list", 'l', 0 }, { "edit", 'e', 0 },
  { "set-home", 'H', 0 }, { "bell", 'B', 0 },
  { "user", 'u', 1 }, { "group", 'g', 1 },
  { NULL, 0, 0 }
};

/* sudo(8) parses with getopt_long and a leading '+': short options bundle
   (-iu bob), an option argument is attached (-ubob) or the next word, parsing
   stops at the first operand, and VAR=value operands that precede the command
   become its environment. Unlisted options are refused, never ignored. */
static int
bda_parse_sudo (bda_opts *o, char **argv, int argc)
{
  char excl = 0;
  int i = 0, rc;
  for (; i < argc; i++)
    {
      char *a = argv[i];
      const char *value;
      char opt;
      if (a[0] != '-' || a[1] == '\0') break;
      if (strcmp (a, "--") == 0) { i++; break; }
      if (a[1] == '-')
        {
          const char *eq = strchr (a + 2, '=');
          size_t len = eq ? (size_t) (eq - (a + 2)) : strlen (a + 2);
          int k;
          for (k = 0; bda_sudo_long[k].name; k++)
            if (strlen (bda_sudo_long[k].name) == len &&
                strncmp (a + 2, bda_sudo_long[k].name, len) == 0)
              break;
          if (!bda_sudo_long[k].name || (eq && !bda_sudo_long[k].arg))
            return bda_refuse ("sudo", a);
          opt = bda_sudo_long[k].opt;
          if (!bda_sudo_long[k].arg)
            {
              if ((rc = bda_sudo_flag (o, &excl, opt)) != EXECUTION_SUCCESS)
                return rc;
              continue;
            }
          value = eq ? eq + 1 : (i + 1 < argc ? argv[++i] : NULL);
        }
      else
        {
          char *p = a + 1;
          for (; *p && *p != 'u' && *p != 'g'; p++)
            if ((rc = bda_sudo_flag (o, &excl, *p)) != EXECUTION_SUCCESS)
              return rc;
          if (!*p)
            continue;
          opt = *p;
          value = p[1] ? p + 1 : (i + 1 < argc ? argv[++i] : NULL);
        }
      if (!value)
        {
          builtin_error ("%s needs %s", a, opt == 'u' ? "USER" : "GROUP");
          return EX_USAGE;
        }
      bda_sudo_value (o, opt, value);
    }
  /* sudoedit operands are files, never environment. */
  for (; !o->edit_mode && i < argc && bda_is_env_assign (argv[i]); i++)
    {
      char **nv = realloc (o->env_assign, (size_t) (o->envc + 1) * sizeof *nv);
      if (!nv) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
      o->env_assign = nv;
      o->env_assign[o->envc++] = argv[i];
    }
  o->cmd = argv + i;
  o->cmdc = argc - i;
  if ((o->reset_all || o->validate) && (o->cmdc || o->envc))
    {
      builtin_error ("%s cannot be used with a command", o->reset_all ? "-K" : "-v");
      return EX_USAGE;
    }
  if (o->envc && !o->cmdc && !o->shell_mode && !o->login_mode)
    {
      builtin_error ("environment assignments require a command");
      return EX_USAGE;
    }
  /* -k with something to do resets the cached credential and then does it. */
  if (o->reset && !o->reset_all &&
      (o->cmdc || o->shell_mode || o->login_mode || o->edit_mode || o->validate))
    {
      o->reset = 0;
      o->reset_first = 1;
    }
  /* -g without -u runs the command as the invoking user. */
  if (o->target_group && !o->target_set)
    {
      snprintf (o->self_target, sizeof o->self_target, "%lu",
                (unsigned long) getuid ());
      o->target = o->self_target;
    }
  return EXECUTION_SUCCESS;
}

int
bashdoas_dispatch (int is_sudo, WORD_LIST *list)
{
  clearerr (stdout);
  int argc = 0;
  char **argv = bda_words_to_argv (list, &argc);
  if (!argv && argc) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }

  if (argc == 0)
    {
      char **doc = is_sudo ? sudo_doc : doas_doc;
      for (char **d = doc; *d; d++) puts (*d);
      free (argv);
      return EX_USAGE;
    }
  if (strcmp (argv[0], "-h") == 0 || strcmp (argv[0], "--help") == 0)
    {
      char **doc = is_sudo ? sudo_doc : doas_doc;
      for (char **d = doc; *d; d++) puts (*d);
      free (argv);
      return fflush (stdout) == 0 && !ferror (stdout) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (strcmp (argv[0], "--version") == 0 || strcmp (argv[0], "-V") == 0)
    {
      puts (is_sudo ? "sudo 0.1" : "doas 0.1");
      free (argv);
      return fflush (stdout) == 0 && !ferror (stdout) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }

  bda_opts o;
  bda_init_opts (&o, is_sudo);
  int rc = is_sudo ? bda_parse_sudo (&o, argv, argc) : bda_parse_doas (&o, argv, argc);
  if (rc == EXECUTION_SUCCESS)
    {
      if (is_sudo && o.list_mode)
        rc = bda_run_list (&o, argv, argc);
      else if (geteuid () == 0)
        rc = bda_run_root (&o);
      else
        {
          rc = bda_run_authority (&o);
          if (rc == BDA_AUTH_UNAVAILABLE)
            rc = bda_run_external (&o, argv, argc);
        }
    }
  free (o.env_assign);
  free (argv);
  return rc;
}

int
doas_builtin (WORD_LIST *list)
{
  return bashdoas_dispatch (0, list);
}

char *doas_doc[] = {
  "doas - conservative doas front-end",
  "usage: doas [-n] [-u USER] [-g GROUP] [-s] [--] command [args...]",
  "       doas -L",
  "Supports -g/--group as an explicit runas group when policy permits it.",
  "Non-root callers use v2 authority when available, otherwise external doas.",
  "Root callers drop and exec with scrubbed environment and child hygiene.",
  (char *) 0
};

struct builtin doas_struct = {
  "doas",
  doas_builtin,
  BUILTIN_ENABLED,
  doas_doc,
  "doas [-n] [-u USER] [-g GROUP] command [args...]",
  0
};
