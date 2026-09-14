/* SPDX-License-Identifier: MIT */
#include <config.h>

#include <errno.h>
#include <grp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/capability.h>

#include "_bashauth_cred_exec.h"

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_SET_SECUREBITS
#define PR_SET_SECUREBITS 28
#endif
/* securebits: no-root + locks (from <linux/securebits.h>, inlined to avoid a
   musl/uapi header dependency). Defense-in-depth; applied best-effort. */
#ifndef SECBIT_NOROOT
#define SECBIT_NOROOT            (1 << 0)
#define SECBIT_NOROOT_LOCKED     (1 << 1)
#define SECBIT_NO_SETUID_FIXUP        (1 << 2)
#define SECBIT_NO_SETUID_FIXUP_LOCKED (1 << 3)
#endif

static int
bashos_ce_env_append (char ***envp, size_t *usedp, size_t *capp, char *entry)
{
  if (!entry)
    return -1;
  if (*usedp + 1 >= *capp)
    {
      size_t ncap = *capp ? *capp * 2 : 16;
      char **nenv = realloc (*envp, ncap * sizeof **envp);
      if (!nenv)
        {
          free (entry);
          return -1;
        }
      for (size_t k = *capp; k < ncap; k++)
        nenv[k] = NULL;
      *envp = nenv;
      *capp = ncap;
    }
  (*envp)[(*usedp)++] = entry;
  (*envp)[*usedp] = NULL;
  return 0;
}

static int
bashos_ce_env_appendf (char ***envp, size_t *usedp, size_t *capp,
                       const char *name, const char *value)
{
  char *entry = NULL;
  if (asprintf (&entry, "%s=%s", name, value ? value : "") < 0)
    return -1;
  return bashos_ce_env_append (envp, usedp, capp, entry);
}

static int
bashos_ce_env_name_matches (const char *pat, const char *name, size_t namelen)
{
  size_t plen = strlen (pat);
  if (plen > 0 && pat[plen - 1] == '*')
    return namelen >= plen - 1 && strncmp (name, pat, plen - 1) == 0;
  return namelen == plen && strncmp (name, pat, plen) == 0;
}

static int
bashos_ce_env_name_is_dangerous (const char *kv, size_t namelen,
                                 const bashos_cred_exec_env_policy *policy)
{
  if (policy)
    for (size_t i = 0; i < policy->ndelete; i++)
      if (policy->delete[i] &&
          bashos_ce_env_name_matches (policy->delete[i], kv, namelen))
        return 1;

  static const char *prefixes[] = {
    "LD_", "DYLD_", "BASH_FUNC_", NULL
  };
  for (int i = 0; prefixes[i]; i++)
    {
      size_t plen = strlen (prefixes[i]);
      if (namelen >= plen && strncmp (kv, prefixes[i], plen) == 0)
        return 1;
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
    /* Bash startup-influencing vars. bash imports SHELLOPTS/BASHOPTS at
       startup; PS4 is command-substituted under xtrace; BASH_XTRACEFD
       redirects trace output to an inherited fd. bash-os's login shell is
       bash, so keep-env must not carry this family across a uid boundary. */
    "SHELLOPTS", "BASHOPTS", "PS4", "BASH_XTRACEFD",
    NULL
  };
  for (int i = 0; exact[i]; i++)
    {
      size_t el = strlen (exact[i]);
      if (namelen == el && strncmp (kv, exact[i], el) == 0)
        return 1;
    }
  return 0;
}

static int
bashos_ce_env_name_already_set (char **env, size_t used, const char *entry)
{
  for (size_t k = 0; k < used; k++)
    {
      char *eq = strchr (env[k], '=');
      if (!eq)
        continue;
      size_t namelen = (size_t) (eq - env[k]);
      if (strncmp (entry, env[k], namelen) == 0 && entry[namelen] == '=')
        return 1;
    }
  return 0;
}

static char **
bashos_ce_build_env (const bashos_cred_exec_user *u, int keep_env,
                     const bashos_cred_exec_env_policy *policy)
{
  size_t cap = 16;
  size_t used = 0;
  char **env = calloc (cap, sizeof *env);
  if (!env)
    return NULL;

  if (bashos_ce_env_appendf (&env, &used, &cap, "USER", u->name) < 0 ||
      bashos_ce_env_appendf (&env, &used, &cap, "LOGNAME", u->name) < 0 ||
      bashos_ce_env_appendf (&env, &used, &cap, "HOME", u->home) < 0 ||
      bashos_ce_env_appendf (&env, &used, &cap, "SHELL", u->shell) < 0 ||
      bashos_ce_env_appendf (&env, &used, &cap, "PATH",
                             "/bin:/bash-os:/usr/bin") < 0)
    goto fail;

  const char *pt[] = { "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ", NULL };
  for (int k = 0; pt[k]; k++)
    {
      const char *v = getenv (pt[k]);
      if (v && bashos_ce_env_appendf (&env, &used, &cap, pt[k], v) < 0)
        goto fail;
    }
  if (policy)
    for (size_t k = 0; k < policy->nkeep; k++)
      {
        const char *name = policy->keep[k];
        if (!name || !*name)
          continue;
        size_t namelen = strlen (name);
        if (bashos_ce_env_name_is_dangerous (name, namelen, policy))
          continue;
        int already = 0;
        for (size_t j = 0; j < used; j++)
          {
            char *eq = strchr (env[j], '=');
            size_t existing_len = eq ? (size_t) (eq - env[j]) : strlen (env[j]);
            if (namelen == existing_len && strncmp (env[j], name, existing_len) == 0)
              { already = 1; break; }
          }
        if (already)
          continue;
        const char *v = getenv (name);
        if (v && bashos_ce_env_appendf (&env, &used, &cap, name, v) < 0)
          goto fail;
      }

  if (keep_env)
    {
      extern char **environ;
      size_t stripped = 0;
      for (char **e = environ; *e; e++)
        {
          char *eq = strchr (*e, '=');
          size_t namelen = eq ? (size_t) (eq - *e) : strlen (*e);
          if (bashos_ce_env_name_is_dangerous (*e, namelen, policy))
            { stripped++; continue; }
          if (namelen >= 7 && strncmp (*e, "BASHSU_", 7) == 0)
            continue;
          if (bashos_ce_env_name_already_set (env, used, *e))
            continue;
          if (bashos_ce_env_append (&env, &used, &cap, strdup (*e)) < 0)
            goto fail;
        }
      if (stripped > 0)
        fprintf (stderr, "--unsafe-keep-env: stripped %zu dangerous env var%s "
                 "(LD_*, BASH_ENV, PERL5OPT, PYTHONPATH, etc.)\n",
                 stripped, stripped == 1 ? "" : "s");
    }

  /* Inline VAR=value assignments (sudo-style). Authority-gated: applied only
     when policy granted SETENV/keepenv (allow_setenv). Each is filtered
     through the same dangerous-name path as the keep set, and an assignment
     never overrides a synthesized safe default or an already-present name. */
  if (policy && policy->allow_setenv)
    for (size_t k = 0; k < policy->nsetenv; k++)
      {
        const char *kv = policy->setenv[k];
        if (!kv)
          continue;
        const char *eq = strchr (kv, '=');
        if (!eq || eq == kv)
          continue;                       /* no name, or empty name: reject */
        size_t namelen = (size_t) (eq - kv);
        if (bashos_ce_env_name_is_dangerous (kv, namelen, policy))
          continue;                       /* dangerous name: refuse silently */
        if (bashos_ce_env_name_already_set (env, used, kv))
          continue;                       /* don't override safe defaults */
        if (bashos_ce_env_append (&env, &used, &cap, strdup (kv)) < 0)
          goto fail;
      }

  return env;

fail:
  for (size_t k = 0; k < used; k++)
    free (env[k]);
  free (env);
  return NULL;
}

static void
bashos_ce_free_env (char **env)
{
  if (!env)
    return;
  for (char **e = env; *e; e++)
    free (*e);
  free (env);
}

char **
bashos_cred_exec_build_env (const bashos_cred_exec_user *u, int keep_env,
                            const bashos_cred_exec_env_policy *env_policy)
{
  if (!u || !u->name || !u->home || !u->shell)
    return NULL;
  return bashos_ce_build_env (u, keep_env, env_policy);
}

void
bashos_cred_exec_free_env (char **env)
{
  bashos_ce_free_env (env);
}

/* ---- Trusted-handoff setup-order executor (Track 3) --------------------- */

const char *
bashos_cred_exec_step_name (bashos_cred_exec_step step)
{
  /* Strings match the kernel bashos_auth_child_setup_order[] names so the
     authority-side plan and the executor-side sequence stay in lockstep. */
  static const char *const names[BASHOS_CE_STEP__COUNT] = {
    [BASHOS_CE_STEP_RESOLVE_TARGET]       = "resolve-policy-target",
    [BASHOS_CE_STEP_SUPPLEMENTARY_GROUPS] = "supplementary-groups",
    [BASHOS_CE_STEP_SET_GID]              = "set-gid",
    [BASHOS_CE_STEP_SET_UID]              = "set-uid",
    [BASHOS_CE_STEP_CAPABILITY_LOCKDOWN]  = "capability-lockdown",
    [BASHOS_CE_STEP_NO_NEW_PRIVS]         = "no-new-privs",
    [BASHOS_CE_STEP_SECUREBITS]           = "securebits",
    [BASHOS_CE_STEP_DUMPABILITY]          = "dumpability",
    [BASHOS_CE_STEP_RLIMITS]              = "rlimits",
    [BASHOS_CE_STEP_UMASK]                = "umask",
    [BASHOS_CE_STEP_TTY_SESSION]          = "tty-session-policy",
    [BASHOS_CE_STEP_RESET_SIGNALS]        = "reset-signals",
    [BASHOS_CE_STEP_DESCRIPTOR_POLICY]    = "descriptor-policy",
    [BASHOS_CE_STEP_ENVIRONMENT]          = "environment",
    [BASHOS_CE_STEP_EXEC]                 = "exec",
  };
  if ((unsigned) step >= BASHOS_CE_STEP__COUNT)
    return "?";
  return names[step] ? names[step] : "?";
}

int
bashos_cred_exec_run_setup (const bashos_cred_exec_ops *ops,
                            bashos_cred_exec_plan *plan)
{
  bashos_cred_exec_plan local;
  if (!plan)
    plan = &local;
  plan->failed_step = -1;
  plan->reached_exec = 0;
  plan->ran_step_mask = 0;
  plan->step_count = BASHOS_CE_STEP__COUNT;

  if (!ops)
    {
      plan->failed_step = BASHOS_CE_STEP_RESOLVE_TARGET;
      return -1;
    }

  for (int i = 0; i < BASHOS_CE_STEP__COUNT; i++)
    {
      /*
       * Reaching the EXEC step means every prior credential/environment step
       * succeeded. Mark it before invoking the handler so a failed exec is
       * still recorded as "reached", while a failure at any earlier step
       * returns below with reached_exec == 0 — the abort-before-exec contract.
       */
      if (i == BASHOS_CE_STEP_EXEC)
        plan->reached_exec = 1;

      bashos_cred_exec_step_fn fn = ops->step[i];
      if (!fn)
        continue;                       /* NULL handler == no-op success */

      plan->ran_step_mask |= (1UL << (unsigned) i);
      if (fn (ops->ctx) < 0)
        {
          plan->failed_step = i;
          if (i != BASHOS_CE_STEP_EXEC)
            plan->reached_exec = 0;     /* never crossed into exec */
          return -1;
        }
    }

  /* Production execve replaces the image, so a real EXEC handler does not
     return; reaching here means a (test) handler returned success. */
  return 0;
}

/* ---- Production default step handlers ---------------------------------- *
 *
 * These perform the REAL credential transition. Load-bearing steps (groups,
 * gid, uid, capability lockdown) hard-fail (return <0) so the executor aborts
 * before exec — a half-applied transition never reaches execve. Hardening
 * steps (securebits, dumpability, rlimits, tty/session, descriptor policy) are
 * best-effort. Invoked only via the gated handoff path. */

static int
bashos_ce_caps_lockdown (void)
{
  struct __user_cap_header_struct hdr = {
    .version = _LINUX_CAPABILITY_VERSION_3,
    .pid = 0,
  };
  struct __user_cap_data_struct data[2];
  memset (data, 0, sizeof data);

  /* Ambient + bounding-set are best-effort (bounding drop needs CAP_SETPCAP;
     a process holding no caps has nothing to drop). */
  (void) prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

  /* Zeroing our own effective/permitted/inheritable caps is always permitted
     and MUST succeed — this is the load-bearing part. */
  if (syscall (SYS_capset, &hdr, data) != 0)
    return -1;

  for (int cap = 0; cap <= 63; cap++)
    (void) prctl (PR_CAPBSET_DROP, (unsigned long) cap, 0, 0, 0);

  return 0;
}

static int
ce_step_resolve_target (void *vctx)
{
  bashos_cred_exec_ctx *c = vctx;
  if (!c || !c->user || !c->user->name || !c->user->home || !c->user->shell)
    return -1;
  return 0;
}

static int
ce_step_supplementary_groups (void *vctx)
{
  bashos_cred_exec_ctx *c = vctx;
  /* ngroups 0 + NULL clears the inherited (root) supplementary group set. */
  return setgroups ((size_t) c->ngroups, c->groups) == 0 ? 0 : -1;
}

static int
ce_step_set_gid (void *vctx)
{
  bashos_cred_exec_ctx *c = vctx;
  if (setresgid (c->user->gid, c->user->gid, c->user->gid) != 0)
    return -1;
  return getgid () == c->user->gid && getegid () == c->user->gid ? 0 : -1;
}

static int
ce_step_set_uid (void *vctx)
{
  bashos_cred_exec_ctx *c = vctx;
  if (setresuid (c->user->uid, c->user->uid, c->user->uid) != 0)
    return -1;
  /* Verify the transition stuck (no lingering saved-set privilege). */
  return getuid () == c->user->uid && geteuid () == c->user->uid ? 0 : -1;
}

static int
ce_step_capability_lockdown (void *vctx)
{
  (void) vctx;
  return bashos_ce_caps_lockdown ();
}

static int
ce_step_no_new_privs (void *vctx)
{
  (void) vctx;
  return prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 ? 0 : -1;
}

static int
ce_step_securebits (void *vctx)        /* best-effort hardening */
{
  (void) vctx;
  (void) prctl (PR_SET_SECUREBITS,
                SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
                SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED,
                0, 0, 0);
  return 0;
}

static int
ce_step_dumpability (void *vctx)       /* best-effort hardening */
{
  (void) vctx;
  (void) prctl (PR_SET_DUMPABLE, 0, 0, 0, 0);
  return 0;
}

static int
ce_step_rlimits (void *vctx)           /* best-effort hardening */
{
  struct rlimit rl = { 0, 0 };
  (void) vctx;
  (void) setrlimit (RLIMIT_CORE, &rl);
  return 0;
}

static int
ce_step_umask (void *vctx)
{
  (void) vctx;
  umask (022);
  return 0;
}

static int
ce_step_tty_session (void *vctx)       /* best-effort */
{
  (void) vctx;
  (void) setsid ();          /* fails if already a session leader: tolerate */
  return 0;
}

static int
ce_step_reset_signals (void *vctx)
{
  static const int sigs[] = {
    SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGPIPE, SIGTSTP
  };
  (void) vctx;
  for (size_t i = 0; i < sizeof sigs / sizeof *sigs; i++)
    signal (sigs[i], SIG_DFL);
  return 0;
}

static int
ce_step_descriptor_policy (void *vctx) /* best-effort placeholder */
{
  (void) vctx;
  /* Full fd-policy (close-from / CLOEXEC sweep) is deferred to the gated
     backend; stdio is left intact for the exec. */
  return 0;
}

static int
ce_step_environment (void *vctx)
{
  bashos_cred_exec_ctx *c = vctx;
  if (chdir (c->user->home) < 0)
    (void) chdir ("/");
  c->envp = bashos_cred_exec_build_env (c->user, c->keep_env, c->env_policy);
  return c->envp ? 0 : -1;
}

int
bashos_cred_exec_resolve_exec (const bashos_cred_exec_ctx *c,
                               const char **prog,
                               const char **argv, int argv_max)
{
  int ai = 0;

  if (!c || !c->user || !c->user->shell || !prog || !argv || argv_max < 2)
    return -1;
  if (c->extra_argc < 0 || c->extra_argc > 64)
    return -1;

  if (c->cmd)
    {
      /* shell -c CMD: the command string runs under the target shell, which
         owns word-splitting/quoting. */
      if (argv_max < 4)
        return -1;
      *prog = c->user->shell;
      argv[ai++] = c->user->shell;
      argv[ai++] = "-c";
      argv[ai++] = c->cmd;
    }
  else if (c->extra_argc > 0)
    {
      /* Direct command: exec the command itself, not the shell. sudo-style
         absolute-path policy is enforced here when requested. */
      if (!c->extra_argv || !c->extra_argv[0])
        return -1;
      if (c->require_absolute_cmd && c->extra_argv[0][0] != '/')
        return -1;
      if (argv_max < c->extra_argc + 1)
        return -1;
      *prog = c->extra_argv[0];
      for (int k = 0; k < c->extra_argc; k++)
        argv[ai++] = c->extra_argv[k];
    }
  else if (c->login_shell)
    {
      /* Login shell: argv[0] = "-bash" so the shell runs its login profile. */
      if (argv_max < 3)
        return -1;
      *prog = c->user->shell;
      argv[ai++] = "-bash";
      argv[ai++] = "-i";
    }
  else
    {
      *prog = c->user->shell;
      argv[ai++] = c->user->shell;
    }

  argv[ai] = NULL;
  return ai;
}

int
bashos_cred_exec_verify_cmd_digest (const bashos_cred_exec_ctx *c,
                                    const char *prog)
{
  unsigned char actual[64];

  if (!c || !c->expect_cmd_digest || c->expect_cmd_digest_len == 0)
    return 0;                  /* no pin configured */
  /* A pin was requested: fail closed unless a hash hook can satisfy it. */
  if (!c->cmd_digest_fn || !prog ||
      c->expect_cmd_digest_len > sizeof actual)
    return -1;
  if (c->cmd_digest_fn (prog, actual, c->expect_cmd_digest_len) != 0)
    return -1;
  return memcmp (actual, c->expect_cmd_digest,
                 c->expect_cmd_digest_len) == 0 ? 0 : -1;
}

static int
ce_step_exec (void *vctx)
{
  bashos_cred_exec_ctx *c = vctx;
  const char *argv[68];
  const char *prog = NULL;

  if (bashos_cred_exec_resolve_exec (c, &prog, argv,
                                     (int) (sizeof argv / sizeof *argv)) < 0)
    return -1;

  /* Last gate before the point of no return: a pinned command must match. */
  if (bashos_cred_exec_verify_cmd_digest (c, prog) != 0)
    return -1;

  execve (prog, (char *const *) argv, c->envp);
  return -1;                   /* only reached if execve failed */
}

void
bashos_cred_exec_default_ops (bashos_cred_exec_ops *ops,
                              bashos_cred_exec_ctx *ctx)
{
  if (!ops)
    return;
  memset (ops, 0, sizeof *ops);
  ops->ctx = ctx;
  ops->step[BASHOS_CE_STEP_RESOLVE_TARGET]       = ce_step_resolve_target;
  ops->step[BASHOS_CE_STEP_SUPPLEMENTARY_GROUPS] = ce_step_supplementary_groups;
  ops->step[BASHOS_CE_STEP_SET_GID]              = ce_step_set_gid;
  ops->step[BASHOS_CE_STEP_SET_UID]              = ce_step_set_uid;
  ops->step[BASHOS_CE_STEP_CAPABILITY_LOCKDOWN]  = ce_step_capability_lockdown;
  ops->step[BASHOS_CE_STEP_NO_NEW_PRIVS]         = ce_step_no_new_privs;
  ops->step[BASHOS_CE_STEP_SECUREBITS]           = ce_step_securebits;
  ops->step[BASHOS_CE_STEP_DUMPABILITY]          = ce_step_dumpability;
  ops->step[BASHOS_CE_STEP_RLIMITS]              = ce_step_rlimits;
  ops->step[BASHOS_CE_STEP_UMASK]                = ce_step_umask;
  ops->step[BASHOS_CE_STEP_TTY_SESSION]          = ce_step_tty_session;
  ops->step[BASHOS_CE_STEP_RESET_SIGNALS]        = ce_step_reset_signals;
  ops->step[BASHOS_CE_STEP_DESCRIPTOR_POLICY]    = ce_step_descriptor_policy;
  ops->step[BASHOS_CE_STEP_ENVIRONMENT]          = ce_step_environment;
  ops->step[BASHOS_CE_STEP_EXEC]                 = ce_step_exec;
}

int
bashos_cred_exec_run (bashos_cred_exec_ctx *ctx, bashos_cred_exec_plan *plan)
{
  bashos_cred_exec_ops ops;
  if (!ctx)
    return -1;
  bashos_cred_exec_default_ops (&ops, ctx);
  return bashos_cred_exec_run_setup (&ops, plan);
}

int
bashos_cred_exec_user_shell_policy (const bashos_cred_exec_user *u,
                                    const char *progname,
                                    int keep_env,
                                    int login_shell,
                                    const char *cmd,
                                    int extra_argc,
                                    const char **extra_argv,
                                    const bashos_cred_exec_env_policy *env_policy)
{
  if (!u || !u->name || !u->home || !u->shell || !progname)
    {
      errno = EINVAL;
      return -1;
    }
  if (extra_argc < 0 || extra_argc > 64)
    {
      errno = E2BIG;
      return -1;
    }

  if (chdir (u->home) < 0)
    chdir ("/");

  char **envp = bashos_ce_build_env (u, keep_env, env_policy);
  if (!envp)
    {
      fprintf (stderr, "%s: env build: out of memory after drop\n", progname);
      _exit (126);
    }

  const char *argv[68];
  int ai = 0;
  argv[ai++] = u->shell;
  if (cmd)
    {
      argv[ai++] = "-c";
      argv[ai++] = cmd;
    }
  else if (extra_argc > 0)
    {
      for (int k = 0; k < extra_argc; k++)
        argv[ai++] = extra_argv[k];
    }
  else if (login_shell)
    {
      argv[0] = "-bash";
      argv[ai++] = "-i";
    }
  argv[ai] = NULL;

  signal (SIGHUP, SIG_DFL);
  signal (SIGINT, SIG_DFL);
  signal (SIGTERM, SIG_DFL);

  execve (u->shell, (char *const *) argv, envp);
  fprintf (stderr, "%s: execve %s: %s\n", progname, u->shell,
           strerror (errno));
  bashos_ce_free_env (envp);
  _exit (126);
}

int
bashos_cred_exec_user_shell (const bashos_cred_exec_user *u,
                             const char *progname,
                             int keep_env,
                             int login_shell,
                             const char *cmd,
                             int extra_argc,
                             const char **extra_argv)
{
  return bashos_cred_exec_user_shell_policy (u, progname, keep_env,
                                             login_shell, cmd, extra_argc,
                                             extra_argv, NULL);
}
