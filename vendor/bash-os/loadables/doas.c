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
#include <sys/wait.h>
#include <unistd.h>		/* isatty / fork / _exit — v2 interactive vs UMH routing */

#include "_mbedtls_sha256.h"
#include "_bashos_auth_uapi.h"
#include "bashcred_privdrop.h"
#include "loadables.h"

extern char **export_env;
extern void maybe_make_export_env (void);
extern char *doas_doc[];
extern char *sudo_doc[];

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
  int list_mode;		/* sudo -l/-ll: wrapper-rendered, read-only policy projection */
  int validate;
  int reset;
  int reset_all;
  const char *target;
  const char *target_group;	/* sudo -g/--group: explicit runas group (name or #gid) */
  char **env_assign;
  int envc;
  char **cmd;
  int cmdc;
} bda_opts;

/* Userspace-only constant (not part of the kernel UAPI). All struct,
 * ioctl, and constant definitions for /dev/bashos-auth live in
 * _bashos_auth_uapi.h, the flattened userspace mirror of
 * kernel/bashos-auth/uapi/linux/bashos_auth.h. */
#define BASHOS_AUTH_DEV          "/dev/bashos-auth"

#define BDA_AUTH_UNAVAILABLE 125
#define BDA_PRIVCMD_MAX_ENVS 256
#define BDA_ENV_CALLER_PREFIX "BASHOS_CALLER_"
#define BDA_ENV_INLINE_PREFIX "BASHOS_INLINE_"
#define BDA_SECURE_PATH "/bin:/bash-os:/usr/bin"

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
  pid_t pid = fork ();
  if (pid < 0)
    {
      builtin_error ("v2 verifier fork: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (pid == 0)
    bda_exec_verify_child (fd, o, r);
  int status = 0;
  while (waitpid (pid, &status, 0) < 0 && errno == EINTR)
    ;
  return WIFEXITED (status) ? WEXITSTATUS (status)
       : WIFSIGNALED (status) ? 128 + WTERMSIG (status) : EXECUTION_FAILURE;
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
      char *end = NULL;
      unsigned long v = strtoul (spec + 1, &end, 10);
      if (end == spec + 1 || !end || *end)
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
      char *p2, *p3, *end = NULL;
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
      g = strtoul (p2 + 1, &end, 10);
      if (end && end != p2 + 1 && *end == '\0' && g <= 0xffffffffUL)
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
 * fallback. The editor NEVER runs as root: this front-end is already executing
 * as the unprivileged caller on the SUDOEDIT path. */
static const char *
bda_sudoedit_editor (void)
{
  const char *e = getenv ("SUDO_EDITOR");
  if (!e || !*e) e = getenv ("VISUAL");
  if (!e || !*e) e = getenv ("EDITOR");
  if (!e || !*e) e = "/bin/vi";
  return e;
}

/* Fork+exec the editor ONCE on all N temp copies as the caller (no privilege
 * transition) and wait — this mirrors real sudoedit, which invokes
 * `$EDITOR temp1 temp2 ...` in a single editor session. The environment is the
 * caller's own (the editor runs with caller authority). Returns the editor exit
 * status, or -1 on spawn failure. n must be >= 1. */
static int
bda_spawn_editor (char **temps, int n)
{
  const char *editor = bda_sudoedit_editor ();
  pid_t pid;
  int status = 0, i;
  char **argv;

  if (n < 1)
    return -1;
  /* [editor, temp0 .. temp{n-1}, NULL] */
  argv = (char **) malloc ((size_t) (n + 2) * sizeof (char *));
  if (!argv)
    return -1;
  argv[0] = (char *) editor;
  for (i = 0; i < n; i++)
    argv[i + 1] = temps[i];
  argv[n + 1] = NULL;

  fflush (NULL);
  pid = fork ();
  if (pid < 0)
    {
      free (argv);
      return -1;
    }
  if (pid == 0)
    {
      /* Caller creds are already in effect (non-root SUDOEDIT path). */
      execvp (editor, argv);
      _exit (127);
    }
  free (argv);			/* child has its own (COW) copy; parent's is done */
  while (waitpid (pid, &status, 0) < 0 && errno == EINTR)
    ;
  if (WIFEXITED (status))
    return WEXITSTATUS (status);
  if (WIFSIGNALED (status))
    return 128 + WTERMSIG (status);
  return -1;
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

static int
bda_run_authority (const bda_opts *o)
{
  int fd = bda_open_authority_if_available ();
  if (fd < 0)
    return BDA_AUTH_UNAVAILABLE;

  const char *target = o->target ? o->target : "root";
  bc_user_info u;
  if (bc_lookup_user (target, &u) != 0)
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

  /* SHELL (-s) / LOGIN (-i) with no explicit command: run the TARGET's login
   * shell AS the command. The kernel executes argv[0] for SHELL/LOGIN exactly
   * like EXEC (the mode only labels env/audit) — so the front-end owns this UX
   * translation and the kernel never resolves a shell of its own. The policy
   * authorizes the shell's absolute path (e.g. a sudoers `... /bin/bash` rule), and LOGIN
   * appends "-l" so bash sources the login profile. An explicit command with
   * -s/-i is run as-is in v1 (not wrapped in `$SHELL -c`). */
  char *synth_cmd[3];
  char **eff_cmd = o->cmd;
  int eff_cmdc = o->cmdc;
  if ((o->shell_mode || o->login_mode) && o->cmdc == 0)
    {
      if (u.shell[0] != '/')
        {
          close (fd);
          builtin_error ("no valid login shell for %s", u.name);
          return EXECUTION_FAILURE;
        }
      synth_cmd[0] = u.shell;
      eff_cmdc = 1;
      if (o->login_mode)
        {
          synth_cmd[1] = (char *) "-l";
          eff_cmdc = 2;
        }
      synth_cmd[eff_cmdc] = NULL;
      eff_cmd = synth_cmd;
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
      close (fd);
      builtin_error ("v2 authority argv build: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  char *env_blob = bda_authority_env_blob (o, req_mode, &env_bytes, &env_count);
  if (!env_blob && errno)
    {
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
   * so it keeps the tty (editors, interactive root shells, etc.). EXEC carries a
   * caller command; SHELL/LOGIN carry none — the kernel builds [shell] /
   * [shell,"-l"] from the target's pinned login shell. Everything else
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
          pid_t pid = fork ();
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
                  (void) write (pfd[1], "V", 1);
                  close (pfd[1]);
                  bda_exec_verify_child (fd, o, &r);
                }
              close (pfd[1]);
              if (r.decision == BASHOS_AUTH_PRIVCMD_DECISION_DENY || r.handle_id == 0)
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
          (void) read (pfd[0], &marker, 1);
          close (pfd[0]);
          int status = 0;
          while (waitpid (pid, &status, 0) < 0 && errno == EINTR)
            ;
          rc = WIFEXITED (status) ? WEXITSTATUS (status)
             : WIFSIGNALED (status) ? 128 + WTERMSIG (status) : EXECUTION_FAILURE;
          if (marker == 'V' && rc == 0 && !verified_once)
            {
              verified_once = 1;
              continue;
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
  if (r.decision == BASHOS_AUTH_PRIVCMD_DECISION_VALIDATE_OK ||
      r.decision == BASHOS_AUTH_PRIVCMD_DECISION_RESET_OK)
    {
      rc = EXECUTION_SUCCESS;
      goto out;
    }
  if (r.decision == BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT)
    {
      /* SUDOEDIT: two-call open/edit-as-caller/copyback orchestration. */
      rc = bda_run_sudoedit (fd, o, &r, argv_blob, argv_bytes, eff_cmdc);
      goto out;
    }
  if (r.handle_id == 0)
    {
      builtin_error ("v2 authority: allow without a handle");
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
    if (hr.approval_status == BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED)
      {
        builtin_error ("v2 authority handoff denied: reject_stage=%u", hr.reject_stage);
        goto out;
      }
    rc = (int) hr.exit_code;	/* the UMH-run command's exit status */
  }

out:
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
      if (*p == '=') return p > s + 1;
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

  const char *su = getenv ("USER");
  if (!su || !*su) su = getenv ("LOGNAME");
  if (!su || !*su) su = "root";
  char uidbuf[32], gidbuf[32];
  snprintf (uidbuf, sizeof uidbuf, "%ld", (long) getuid ());
  snprintf (gidbuf, sizeof gidbuf, "%ld", (long) getgid ());
  if (bda_append_envf (&env, &used, &cap, "SUDO_USER", su) < 0 ||
      bda_append_envf (&env, &used, &cap, "SUDO_UID", uidbuf) < 0 ||
      bda_append_envf (&env, &used, &cap, "SUDO_GID", gidbuf) < 0)
    goto fail;

  for (int i = 0; i < o->envc; i++)
    {
      if (bda_env_name_dangerous (o->env_assign[i]))
        continue;
      if (bda_append_env (&env, &used, &cap, strdup (o->env_assign[i])) < 0)
        goto fail;
    }
  return env;

fail:
  bda_free_env (env);
  return NULL;
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
  long maxfd = sysconf (_SC_OPEN_MAX);
  if (maxfd < 0 || maxfd > BDA_FD_CLOSE_MAX)
    maxfd = BDA_FD_CLOSE_MAX;
  for (int fd = 3; fd < maxfd; fd++)
    (void) close (fd);
}

static int
bda_run_external (const bda_opts *o, char **orig, int origc)
{
  const char *path = getenv ("BASHDOAS_EXTERNAL");
  if (!path || !*path) path = getenv ("BASHSUDO_EXTERNAL");
  if (!path || !*path) path = "doas";

  char **argv = calloc ((size_t) origc + 2, sizeof *argv);
  if (!argv) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
  argv[0] = (char *) path;
  for (int i = 0; i < origc; i++) argv[i + 1] = orig[i];
  argv[origc + 1] = NULL;

  pid_t pid = fork ();
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
      execvp (path, argv);
      fprintf (stderr, "%s: external doas: %s: %s\n",
               o->is_sudo ? "sudo" : "doas", path, strerror (errno));
      _exit (errno == ENOENT ? 127 : 126);
    }
  free (argv);
  return bda_wait_status (pid);
}

static int
bda_run_root (const bda_opts *o)
{
  const char *target = o->target ? o->target : "root";
  bc_user_info u;
  char err[BC_PD_ERR_MAX];
  if (bc_lookup_user (target, &u) != 0)
    {
      builtin_error ("unknown user: %s", target);
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

  pid_t pid = fork ();
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

      char **env = bda_build_env (&u, o);
      if (!env)
        {
          fprintf (stderr, "%s: env build: out of memory\n",
                   o->is_sudo ? "sudo" : "doas");
          _exit (126);
        }

      bda_child_reset_signals ();
      bda_child_close_fds ();
      if (o->shell_mode || o->login_mode || o->cmdc == 0)
        {
          char *cmdstr = o->cmdc ? bda_quote_join_cmd (o->cmd, o->cmdc) : NULL;
          if (o->cmdc && !cmdstr)
            {
              fprintf (stderr, "%s: shell command build: out of memory\n",
                       o->is_sudo ? "sudo" : "doas");
              _exit (126);
            }
          char *argv[5];
          int ai = 0;
          argv[ai++] = o->login_mode ? "-bash" : u.shell;
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
          execve (u.shell, argv, env);
          fprintf (stderr, "%s: exec %s: %s\n",
                   o->is_sudo ? "sudo" : "doas", u.shell, strerror (errno));
          _exit (errno == ENOENT ? 127 : 126);
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
      execve (exec_cmd[0], exec_cmd, env);
      fprintf (stderr, "%s: exec %s: %s\n",
               o->is_sudo ? "sudo" : "doas", exec_cmd[0], strerror (errno));
      _exit (errno == ENOENT ? 127 : 126);
    }
  return bda_wait_status (pid);
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

static int
bda_parse_sudo (bda_opts *o, char **argv, int argc)
{
  int i = 0;
  for (; i < argc; i++)
    {
      char *a = argv[i];
      if (strcmp (a, "--") == 0) { i++; break; }
      if (strcmp (a, "-n") == 0 || strcmp (a, "--non-interactive") == 0)
        o->non_interactive = 1;
      else if (strcmp (a, "-s") == 0 || strcmp (a, "--shell") == 0)
        o->shell_mode = 1;
      else if (strcmp (a, "-i") == 0 || strcmp (a, "--login") == 0)
        o->login_mode = 1;
      else if (strcmp (a, "-k") == 0 ||
               strcmp (a, "--reset-timestamp") == 0)
        o->reset = 1;
      else if (strcmp (a, "-K") == 0 ||
               strcmp (a, "--remove-timestamp") == 0)
        {
          o->reset = 1;
          o->reset_all = 1;
        }
      else if (strcmp (a, "-v") == 0 || strcmp (a, "--validate") == 0)
        o->validate = 1;
      else if (strcmp (a, "-l") == 0 || strcmp (a, "--list") == 0)
        o->list_mode = o->list_mode ? 2 : 1;
      else if (strcmp (a, "-ll") == 0)
        o->list_mode = 2;
      else if (strcmp (a, "-u") == 0 || strcmp (a, "--user") == 0)
        {
          if (++i >= argc) { builtin_error ("%s needs USER", a); return EX_USAGE; }
          o->target = argv[i][0] == '#' ? argv[i] + 1 : argv[i];
        }
      else if (strncmp (a, "--user=", 7) == 0)
        o->target = a[7] == '#' ? a + 8 : a + 7;
      else if (strcmp (a, "-g") == 0 || strcmp (a, "--group") == 0)
        {
          if (++i >= argc) { builtin_error ("%s needs GROUP", a); return EX_USAGE; }
          o->target_group = argv[i];
        }
      else if (strncmp (a, "--group=", 8) == 0)
        o->target_group = a + 8;
      else if (strcmp (a, "-H") == 0 || strcmp (a, "--set-home") == 0 ||
               strcmp (a, "-B") == 0 || strcmp (a, "--bell") == 0)
        { }
      else if (strcmp (a, "-E") == 0 || strncmp (a, "--preserve-env", 14) == 0 ||
               strcmp (a, "-S") == 0 || strcmp (a, "-A") == 0 ||
               strcmp (a, "-p") == 0 || strncmp (a, "--prompt", 8) == 0)
        return bda_refuse ("sudo", a);
      else if (strcmp (a, "-e") == 0 || strcmp (a, "--edit") == 0)
        o->edit_mode = 1;
      else if (a[0] == '-')
        return bda_refuse ("sudo", a);
      else if (bda_is_env_assign (a))
        {
          o->env_assign = realloc (o->env_assign, (size_t) (o->envc + 1) * sizeof *o->env_assign);
          if (!o->env_assign) return EXECUTION_FAILURE;
          o->env_assign[o->envc++] = a;
        }
      else break;
    }
  o->cmd = argv + i;
  o->cmdc = argc - i;
  if (o->shell_mode && o->login_mode)
    { builtin_error ("-s and -i are mutually exclusive"); return EX_USAGE; }
  return EXECUTION_SUCCESS;
}

int
bashdoas_dispatch (int is_sudo, WORD_LIST *list)
{
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
      return EXECUTION_SUCCESS;
    }
  if (strcmp (argv[0], "--version") == 0 || strcmp (argv[0], "-V") == 0)
    {
      puts (is_sudo ? "sudo 0.1" : "doas 0.1");
      free (argv);
      return EXECUTION_SUCCESS;
    }

  bda_opts o;
  bda_init_opts (&o, is_sudo);
  int rc = is_sudo ? bda_parse_sudo (&o, argv, argc) : bda_parse_doas (&o, argv, argc);
  if (rc == EXECUTION_SUCCESS)
    {
      if (is_sudo && o.list_mode)
        {
          builtin_error ("sudo -l is rendered by the /bash-os/sudo.sh wrapper");
          rc = EX_USAGE;
        }
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
