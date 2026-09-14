/* SPDX-License-Identifier: MIT */
#ifndef BASHAUTH_CRED_EXEC_H
#define BASHAUTH_CRED_EXEC_H

#include <stddef.h>
#include <sys/types.h>

typedef struct bashos_cred_exec_user {
  const char *name;
  uid_t uid;
  gid_t gid;
  const char *home;
  const char *shell;
} bashos_cred_exec_user;

typedef struct bashos_cred_exec_env_policy {
  const char *const *keep;
  size_t nkeep;
  const char *const *delete;
  size_t ndelete;
  /* Inline VAR=value assignments (sudo-style) requested by the caller. These
     are applied only when allow_setenv is nonzero (i.e. matched policy granted
     SETENV/keepenv); each is still filtered through the same authority
     dangerous-name path as the keep_env preserve set, and never overrides a
     synthesized safe default (USER/LOGNAME/HOME/SHELL/PATH/...). Trailing
     fields: callers that do not set them must zero-initialize the struct. */
  const char *const *setenv;
  size_t nsetenv;
  int allow_setenv;
} bashos_cred_exec_env_policy;

int bashos_cred_exec_user_shell (const bashos_cred_exec_user *u,
                                 const char *progname,
                                 int keep_env,
                                 int login_shell,
                                 const char *cmd,
                                 int extra_argc,
                                 const char **extra_argv);

int bashos_cred_exec_user_shell_policy (const bashos_cred_exec_user *u,
                                        const char *progname,
                                        int keep_env,
                                        int login_shell,
                                        const char *cmd,
                                        int extra_argc,
                                        const char **extra_argv,
                                        const bashos_cred_exec_env_policy *env_policy);

/* Synthesize the authority-owned environment without performing any exec.
   Returns a malloc'd NULL-terminated envp (free with
   bashos_cred_exec_free_env), or NULL on allocation failure. Exposed so the
   env policy can be exercised by host-static tests; the trusted-handoff exec
   path uses the same builder internally. */
char **bashos_cred_exec_build_env (const bashos_cred_exec_user *u,
                                   int keep_env,
                                   const bashos_cred_exec_env_policy *env_policy);

void bashos_cred_exec_free_env (char **env);

/* ---- Trusted-handoff setup-order executor (Track 3) -----------------------
 *
 * The root-owned executor applies an exact ordered sequence of credential /
 * environment setup steps and then execs. The order mirrors the kernel's
 * bashos_auth_child_setup_step (drivers/bashos/bashos_auth.c) so the plan named
 * authority-side and the sequence applied executor-side stay in lockstep. The
 * binding contract is fail-closed: if ANY step fails the executor must abort
 * BEFORE exec — a half-applied credential transition must never reach execve.
 *
 * Steps are invoked through an injectable ops table so the sequencing /
 * abort-before-exec contract can be exercised on the host without performing a
 * real privilege transition (tests supply mock step handlers; production wires
 * the real syscalls). */
typedef enum {
  BASHOS_CE_STEP_RESOLVE_TARGET = 0,
  BASHOS_CE_STEP_SUPPLEMENTARY_GROUPS,
  BASHOS_CE_STEP_SET_GID,
  BASHOS_CE_STEP_SET_UID,
  BASHOS_CE_STEP_CAPABILITY_LOCKDOWN,
  BASHOS_CE_STEP_NO_NEW_PRIVS,
  BASHOS_CE_STEP_SECUREBITS,
  BASHOS_CE_STEP_DUMPABILITY,
  BASHOS_CE_STEP_RLIMITS,
  BASHOS_CE_STEP_UMASK,
  BASHOS_CE_STEP_TTY_SESSION,
  BASHOS_CE_STEP_RESET_SIGNALS,
  BASHOS_CE_STEP_DESCRIPTOR_POLICY,
  BASHOS_CE_STEP_ENVIRONMENT,
  BASHOS_CE_STEP_EXEC,
  BASHOS_CE_STEP__COUNT
} bashos_cred_exec_step;

/* A step handler returns 0 on success, <0 on failure (abort before exec).
   The EXEC handler does not return on success (it execve's); a return means
   the exec itself failed. A NULL handler is treated as a no-op success, so a
   partial ops table can exercise a subset. */
typedef int (*bashos_cred_exec_step_fn) (void *ctx);

typedef struct bashos_cred_exec_ops {
  bashos_cred_exec_step_fn step[BASHOS_CE_STEP__COUNT];
  void *ctx;
} bashos_cred_exec_ops;

typedef struct bashos_cred_exec_plan {
  int failed_step;             /* bashos_cred_exec_step that failed, or -1 */
  int reached_exec;            /* nonzero once the EXEC step was reached */
  unsigned long ran_step_mask; /* bit i set when step i's handler ran */
  int step_count;              /* == BASHOS_CE_STEP__COUNT */
} bashos_cred_exec_plan;

/* Stable name for a step, matching the kernel setup-order matrix strings. */
const char *bashos_cred_exec_step_name (bashos_cred_exec_step step);

/* Apply the ordered setup steps in ops, aborting before exec on the first
   failure. Returns 0 only if the EXEC handler returned 0 (production execve
   never returns on success); returns -1 on any step failure with
   plan->failed_step set. plan may be NULL. */
int bashos_cred_exec_run_setup (const bashos_cred_exec_ops *ops,
                                bashos_cred_exec_plan *plan);

/* Context consumed by the production default step handlers. */
typedef struct bashos_cred_exec_ctx {
  const bashos_cred_exec_user *user;
  const gid_t *groups;      /* supplementary groups to install */
  int ngroups;              /* 0 + NULL groups => CLEAR supplementary groups */
  int keep_env;
  int login_shell;
  const char *cmd;          /* -c CMD, or NULL */
  int extra_argc;
  const char **extra_argv;  /* explicit argv tail (direct command), or NULL */
  int require_absolute_cmd; /* direct command argv[0] must be an absolute path */
  const bashos_cred_exec_env_policy *env_policy;
  /* Command-digest pin: when expect_cmd_digest is non-NULL the program about to
     be exec'd is hashed (via cmd_digest_fn) and must match, else the executor
     aborts before exec. cmd_digest_fn is injected so the digest algorithm (real
     SHA-256 in the full build, a mock in host tests) is not hard-wired here; a
     pin with no hook fails closed. */
  const unsigned char *expect_cmd_digest;
  unsigned int expect_cmd_digest_len;
  int (*cmd_digest_fn) (const char *path, unsigned char *out, unsigned int outlen);
  char **envp;              /* internal: synthesized env (set during run) */
} bashos_cred_exec_ctx;

/* Verify the command-digest pin (if any) against PROG. Returns 0 when no pin is
   configured or the digest matches; -1 on mismatch, missing hook, or hash
   failure (fail-closed). */
int bashos_cred_exec_verify_cmd_digest (const bashos_cred_exec_ctx *ctx,
                                        const char *prog);

/* Resolve the program to execve and its argv for ctx, applying the command
   policy WITHOUT execing:
   - shell -c CMD       => prog = shell, argv = { shell, "-c", CMD }
   - direct command     => prog = extra_argv[0], argv = extra_argv (the command
                           runs directly, not under the shell); when
                           require_absolute_cmd is set, argv[0] must be absolute
   - login shell        => prog = shell, argv = { "-bash", "-i" }
   - plain shell        => prog = shell, argv = { shell }
   Fills argv[] (NULL-terminated, capacity argv_max) and *prog. Returns the
   argc on success, -1 on error (capacity, bad extra_argc, or a non-absolute
   direct command when required). */
int bashos_cred_exec_resolve_exec (const bashos_cred_exec_ctx *ctx,
                                   const char **prog,
                                   const char **argv, int argv_max);

/* Fill ops with the production default step handlers operating on ctx. The
   load-bearing credential steps (supplementary groups, set-gid, set-uid,
   capability lockdown) hard-fail (return <0) so the executor aborts before
   exec; hardening steps (securebits, dumpability, rlimits, tty/session,
   descriptor policy) are best-effort. */
void bashos_cred_exec_default_ops (bashos_cred_exec_ops *ops,
                                   bashos_cred_exec_ctx *ctx);

/* Convenience: build the default ops over ctx and run the ordered setup. On
   the success path the EXEC step execve's and does not return; otherwise
   returns -1 with plan->failed_step set (no credential change reaches exec). */
int bashos_cred_exec_run (bashos_cred_exec_ctx *ctx,
                          bashos_cred_exec_plan *plan);

#endif /* BASHAUTH_CRED_EXEC_H */
