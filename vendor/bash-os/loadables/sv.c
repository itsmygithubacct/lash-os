/* SPDX-License-Identifier: MIT */
/* sv.c — small service supervisor loadable for bash-os.
 *
 * Stage 40 v1: C supervisor surface compatible with /bash-os/sv.sh.
 * It keeps the runit-shaped service directory contract:
 *   /etc/bash-os/sv/<name>/run
 *   /etc/bash-os/sv/<name>/finish
 *   /etc/bash-os/sv/<name>/disabled
 *
 * State is written under /run/sv by default:
 *   <svc>/pid, <svc>/super-pid, <svc>/status, <svc>/down
 *
 * Verbs:
 *   sv up NAME
 *   sv down NAME
 *   sv restart NAME
 *   sv status [NAME]
 *   sv boot
 *   sv shutdown
 *   sv run [-d DIR]
 *   sv log NAME [-n N]
 *
 * This v1 intentionally keeps control direct through state files rather
 * than a persistent control socket. The blocking `run` verb is for PID 1:
 * /init can restart it if the supervisor process crashes.
 *
 * Service run scripts may start with comment directives:
 *   # namespace: pid,net,mount
 *   # user: daemon
 *   # capabilities-drop: CAP_NET_RAW,CAP_NET_ADMIN
 *   # restart: always        (default longrun behavior)
 *   # restart: on-failure    (only non-zero exit or signal)
 *   # restart: never
 *   # restart-max: 3         (restarts allowed per window)
 *   # restart-window: 60     (seconds; default 60 when max is set)
 *   # restart-delay: 1       (seconds; default is exponential backoff)
 *   # requires: network logger
 *   # after: entropy
 *   # before: webapp        (this service starts before webapp; i.e. webapp
 *                            gains an implicit `after: this`)
 *   # readiness: ./check    (or an explicit shell health command)
 *   # readiness: notify     (sd_notify-style push: the service signals its
 *                            own state over a per-service abstract AF_UNIX
 *                            SOCK_DGRAM socket; the supervisor exports
 *                            NOTIFY_SOCKET=@sv/<name> and recognizes the
 *                            READY=1 / RELOADING=1 / STOPPING=1 / STATUS= /
 *                            MAINPID= subset; `sv notify KEY=VALUE ...`
 *                            is the client. The shell fallback mirrors the
 *                            grammar over a FIFO at $BASHSV_RUNDIR/<name>/notify
 *                            because bash cannot bind AF_UNIX datagram sockets.)
 *   # readiness-timeout: 30
 * `boot` starts services in dependency order; `shutdown` stops them in the
 * reverse of that order (dependents before their dependencies).
 * matching the bash fallback wrapper. `# user:` now resolves and drops
 * privileges in-process through the Stage 23 cred helper; namespace
 * directives keep the ns fallback when no user drop is requested.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <netdb.h>
#include <pwd.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "loadables.h"
#include "variables.h"
#include "bashcred_privdrop.h"

extern void maybe_make_export_env (void);

static const char *bsv_sv_dir = "/etc/bash-os/sv";
static const char *bsv_run_dir = "/run/sv";
static const char *bsv_log_dir = "/var/log/sv";
static off_t bsv_log_max_bytes = 1048576;
static int bsv_log_generations = 1;
#define BSV_LOG_GEN_MAX 16
static volatile sig_atomic_t bsv_stop = 0;
static int bsv_listen_activation = 0;

struct bsv_log_policy {
  off_t max_bytes;
  int generations;
  int timestamp;
};

static int
bsv_clamp_log_generations (long n)
{
  if (n < 1)
    return 1;
  if (n > BSV_LOG_GEN_MAX)
    return BSV_LOG_GEN_MAX;
  return (int) n;
}

#ifndef CLONE_NEWNS
#  define CLONE_NEWNS     0x00020000
#endif
#ifndef CLONE_NEWUTS
#  define CLONE_NEWUTS    0x04000000
#endif
#ifndef CLONE_NEWIPC
#  define CLONE_NEWIPC    0x08000000
#endif
#ifndef CLONE_NEWUSER
#  define CLONE_NEWUSER   0x10000000
#endif
#ifndef CLONE_NEWPID
#  define CLONE_NEWPID    0x20000000
#endif
#ifndef CLONE_NEWNET
#  define CLONE_NEWNET    0x40000000
#endif
#ifndef CLONE_NEWCGROUP
#  define CLONE_NEWCGROUP 0x02000000
#endif

static const struct { const char *name; int flag; } bsv_ns_flags[] = {
  { "mount",  CLONE_NEWNS     },
  { "uts",    CLONE_NEWUTS    },
  { "ipc",    CLONE_NEWIPC    },
  { "user",   CLONE_NEWUSER   },
  { "pid",    CLONE_NEWPID    },
  { "net",    CLONE_NEWNET    },
  { "cgroup", CLONE_NEWCGROUP },
};

#define BSV_SERVICE_MAX 256
#define BSV_DEPS_MAX 32
#define BSV_TYPE_LONGRUN 0
#define BSV_TYPE_ONESHOT 1
#define BSV_TYPE_BUNDLE 2
#define BSV_READY_TIMEOUT_DEFAULT 30
#define BSV_READY_TIMEOUT_MAX 300
/* readiness modes: how a service's `ready` state is determined. */
#define BSV_READY_NONE 0      /* no readiness gate */
#define BSV_READY_PROBE 1     /* supervisor runs ./check (pull) */
#define BSV_READY_COMMAND 2   /* supervisor runs a shell command (pull) */
#define BSV_READY_NOTIFY 3    /* service pushes READY=1 over NOTIFY_SOCKET */
#define BSV_RESTART_ALWAYS 0
#define BSV_RESTART_ON_FAILURE 1
#define BSV_RESTART_NEVER 2
#define BSV_RESTART_MAX_LIMIT 1000
#define BSV_RESTART_WINDOW_MAX 86400
#define BSV_RESTART_DELAY_MAX 3600

struct bsv_service_meta {
  char name[97];
  char requires[BSV_DEPS_MAX][97];
  int nrequires;
  char after[BSV_DEPS_MAX][97];
  int nafter;
  /* `# before: X` means this service must start before X — i.e. X gains an
     implicit `after: this`. Stored here at parse time, then resolved into the
     target's `after` list once every service meta is known (bsv_collect_services
     post-pass), so the existing topological sort handles it with no extra
     traversal logic. Mirrors runit/s6 reverse-ordering ergonomics. */
  char before[BSV_DEPS_MAX][97];
  int nbefore;
  int disabled;
  int type;
};

struct bsv_readiness_policy {
  int enabled;
  int use_shell;
  int mode;                     /* BSV_READY_* */
  int timeout;
  char command[256];
  char check_path[512];
};

struct bsv_restart_policy {
  int mode;
  int max;
  int window;
  int delay;
};

static int bsv_open_log (const char *logfile,
                         const struct bsv_log_policy *policy);

static void
bsv_on_term (int sig)
{
  (void) sig;
  bsv_stop = 1;
}

static int
bsv_mkdir_p (const char *path, mode_t mode)
{
  char tmp[512];
  size_t n = strlen (path);
  if (n == 0 || n >= sizeof tmp) return -1;
  memcpy (tmp, path, n + 1);
  for (char *p = tmp + 1; *p; p++)
    if (*p == '/')
      {
        *p = '\0';
        if (mkdir (tmp, mode) < 0 && errno != EEXIST) return -1;
        *p = '/';
      }
  if (mkdir (tmp, mode) < 0 && errno != EEXIST) return -1;
  return 0;
}

static int
bsv_valid_name (const char *s)
{
  if (!s || !*s || strlen (s) > 96) return 0;
  for (; *s; s++)
    if (!(('A' <= *s && *s <= 'Z') || ('a' <= *s && *s <= 'z') ||
          ('0' <= *s && *s <= '9') || *s == '_' || *s == '-' || *s == '.'))
      return 0;
  return 1;
}

static int
bsv_path (char *out, size_t out_sz, const char *base, const char *name,
          const char *leaf)
{
  int n = snprintf (out, out_sz, "%s/%s%s%s", base, name ? name : "",
                    leaf ? "/" : "", leaf ? leaf : "");
  return n > 0 && (size_t) n < out_sz ? 0 : -1;
}

static int
bsv_writef (const char *path, const char *fmt, ...)
{
  FILE *f = fopen (path, "w");
  if (!f) return -1;
  va_list ap;
  va_start (ap, fmt);
  int rc = vfprintf (f, fmt, ap);
  va_end (ap);
  fclose (f);
  return rc < 0 ? -1 : 0;
}

static int
bsv_read_pid (const char *path, pid_t *pid)
{
  FILE *f = fopen (path, "r");
  long v;
  if (!f) return -1;
  if (fscanf (f, "%ld", &v) != 1) { fclose (f); return -1; }
  fclose (f);
  if (v <= 0) return -1;
  *pid = (pid_t) v;
  return 0;
}

static int
bsv_super_running (const char *name)
{
  char p[512];
  pid_t pid;
  if (bsv_path (p, sizeof p, bsv_run_dir, name, "super-pid") < 0) return 0;
  if (bsv_read_pid (p, &pid) < 0) return 0;
  return kill (pid, 0) == 0;
}

static int
bsv_service_exists (const char *name, char *run_script, size_t run_sz)
{
  char svc[512];
  if (!bsv_valid_name (name)) return 0;
  if (bsv_path (svc, sizeof svc, bsv_sv_dir, name, "run") < 0) return 0;
  if (access (svc, X_OK) != 0) return 0;
  if (run_script && run_sz)
    snprintf (run_script, run_sz, "%s", svc);
  return 1;
}

static int
bsv_service_is_bundle_name (const char *name)
{
  char p[512];
  FILE *f;
  char line[64];
  if (!bsv_valid_name (name)) return 0;
  if (bsv_path (p, sizeof p, bsv_sv_dir, name, "type=bundle") == 0 &&
      access (p, F_OK) == 0)
    return 1;
  if (bsv_path (p, sizeof p, bsv_sv_dir, name, "type") < 0)
    return 0;
  f = fopen (p, "r");
  if (!f) return 0;
  if (!fgets (line, sizeof line, f))
    line[0] = '\0';
  fclose (f);
  line[strcspn (line, " \t\r\n")] = '\0';
  return strcmp (line, "bundle") == 0;
}

static int
bsv_copy_name (char *dst, size_t dst_sz, const char *src, size_t n)
{
  if (n == 0 || n >= dst_sz)
    return -1;
  char buf[97];
  if (n >= sizeof buf)
    return -1;
  memcpy (buf, src, n);
  buf[n] = '\0';
  if (!bsv_valid_name (buf))
    return -1;
  memcpy (dst, buf, n + 1);
  return 0;
}

static int
bsv_add_dep (char deps[BSV_DEPS_MAX][97], int *ndeps, const char *s, size_t n,
             const char *kind, const char *run_script)
{
  char name[97];
  if (bsv_copy_name (name, sizeof name, s, n) < 0)
    {
      fprintf (stderr, "sv: invalid %s dependency in %s\n",
               kind, run_script);
      return -1;
    }
  for (int i = 0; i < *ndeps; i++)
    if (strcmp (deps[i], name) == 0)
      return 0;
  if (*ndeps >= BSV_DEPS_MAX)
    {
      fprintf (stderr, "sv: too many %s dependencies in %s\n",
               kind, run_script);
      return -1;
    }
  strcpy (deps[*ndeps], name);
  (*ndeps)++;
  return 0;
}

static int
bsv_parse_dep_list (const char *p, char deps[BSV_DEPS_MAX][97], int *ndeps,
                    const char *kind, const char *run_script)
{
  while (*p)
    {
      while (*p == ' ' || *p == '\t' || *p == ',') p++;
      if (*p == '\0' || *p == '\r' || *p == '\n')
        break;
      const char *start = p;
      while (*p && *p != ' ' && *p != '\t' && *p != ',' &&
             *p != '\r' && *p != '\n')
        p++;
      if (bsv_add_dep (deps, ndeps, start, (size_t) (p - start),
                       kind, run_script) < 0)
        return -1;
    }
  return 0;
}

static int
bsv_parse_service_deps (const char *run_script, struct bsv_service_meta *meta)
{
  FILE *f = fopen (run_script, "r");
  char line[256];
  if (!f)
    return -1;
  meta->nrequires = 0;
  meta->nafter = 0;
  meta->nbefore = 0;
  while (fgets (line, sizeof line, f))
    {
      char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      if (*p != '#') break;
      p++;
      while (*p == ' ' || *p == '\t') p++;
      if (strncmp (p, "requires:", 9) == 0)
        {
          p += 9;
          if (bsv_parse_dep_list (p, meta->requires, &meta->nrequires,
                                  "requires", run_script) < 0)
            { fclose (f); return -1; }
        }
      else if (strncmp (p, "after:", 6) == 0)
        {
          p += 6;
          if (bsv_parse_dep_list (p, meta->after, &meta->nafter,
                                  "after", run_script) < 0)
            { fclose (f); return -1; }
        }
      else if (strncmp (p, "before:", 7) == 0)
        {
          p += 7;
          if (bsv_parse_dep_list (p, meta->before, &meta->nbefore,
                                  "before", run_script) < 0)
            { fclose (f); return -1; }
        }
    }
  fclose (f);
  return 0;
}

static int
bsv_parse_capability_list (const char *p, size_t n, char *out, size_t out_sz,
                           const char *run_script)
{
  if (n == 0 || n >= out_sz)
    {
      if (n > 0)
        fprintf (stderr, "sv: capabilities-drop directive too long in %s\n",
                 run_script);
      return n == 0 ? 0 : -1;
    }
  for (size_t i = 0; i < n; i++)
    if (!(('A' <= p[i] && p[i] <= 'Z') ||
          ('a' <= p[i] && p[i] <= 'z') ||
          ('0' <= p[i] && p[i] <= '9') ||
          p[i] == '_' || p[i] == ','))
      {
        fprintf (stderr, "sv: invalid capabilities-drop directive in %s\n",
                 run_script);
        return -1;
      }
  memcpy (out, p, n);
  out[n] = '\0';
  return 0;
}

static void
bsv_restart_policy_init (struct bsv_restart_policy *rp)
{
  rp->mode = BSV_RESTART_ALWAYS;
  rp->max = -1;
  rp->window = 60;
  rp->delay = -1;
}

static int
bsv_parse_restart_number (const char *p, const char *field, long min,
                          long max, int *out, const char *run_script)
{
  char *endp = NULL;
  long v;
  while (*p == ' ' || *p == '\t') p++;
  errno = 0;
  v = strtol (p, &endp, 10);
  if (errno != 0 || endp == p)
    {
      fprintf (stderr, "sv: invalid %s directive in %s\n",
               field, run_script);
      return -1;
    }
  while (*endp == ' ' || *endp == '\t' || *endp == '\r' || *endp == '\n')
    endp++;
  if (*endp != '\0')
    {
      fprintf (stderr, "sv: invalid %s directive in %s\n",
               field, run_script);
      return -1;
    }
  if (v < min || v > max)
    {
      fprintf (stderr, "sv: out-of-range %s directive in %s\n",
               field, run_script);
      return -1;
    }
  *out = (int) v;
  return 0;
}

static int
bsv_parse_restart_mode (const char *p, struct bsv_restart_policy *rp,
                        const char *run_script)
{
  size_t n;
  while (*p == ' ' || *p == '\t') p++;
  n = strcspn (p, " \t\r\n");
  if (n == 6 && strncmp (p, "always", 6) == 0)
    rp->mode = BSV_RESTART_ALWAYS;
  else if (n == 10 && strncmp (p, "on-failure", 10) == 0)
    rp->mode = BSV_RESTART_ON_FAILURE;
  else if (n == 5 && strncmp (p, "never", 5) == 0)
    rp->mode = BSV_RESTART_NEVER;
  else
    {
      fprintf (stderr, "sv: invalid restart directive in %s\n",
               run_script);
      return -1;
    }
  p += n;
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
  if (*p != '\0')
    {
      fprintf (stderr, "sv: invalid restart directive in %s\n",
               run_script);
      return -1;
    }
  return 0;
}

static int
bsv_exit_was_success (int st)
{
  return WIFEXITED (st) && WEXITSTATUS (st) == 0;
}

static int
bsv_finish_status_arg (int st)
{
  if (WIFEXITED (st))
    return WEXITSTATUS (st);
  if (WIFSIGNALED (st))
    return 128 + WTERMSIG (st);
  return 111;
}

static int
bsv_restart_prepare (const struct bsv_restart_policy *rp, int st,
                     const char *status, const char *transition,
                     time_t *window_start, int *window_count)
{
  time_t now;
  int should_restart = 0;

  if (rp->mode == BSV_RESTART_ALWAYS)
    should_restart = 1;
  else if (rp->mode == BSV_RESTART_ON_FAILURE)
    should_restart = !bsv_exit_was_success (st);

  if (!should_restart)
    return 0;

  if (rp->max >= 0)
    {
      now = time (NULL);
      if (*window_start == 0 || now - *window_start > rp->window)
        {
          *window_start = now;
          *window_count = 0;
        }
      if (*window_count >= rp->max)
        {
          bsv_writef (transition, "restart-limit rc=%d\n",
                      bsv_finish_status_arg (st));
          bsv_writef (status, "restart-limit rc=%d\n",
                      bsv_finish_status_arg (st));
          return -1;
        }
      (*window_count)++;
    }
  return 1;
}

static void
bsv_restart_sleep (const struct bsv_restart_policy *rp, int *backoff,
                   time_t started)
{
  if (time (NULL) - started >= 60)
    *backoff = 1;
  if (rp->delay >= 0)
    {
      sleep ((unsigned int) rp->delay);
      return;
    }
  sleep ((unsigned int) *backoff);
  if (*backoff < 60)
    *backoff *= 2;
}

static int
bsv_parse_run_directives (const char *run_script, char *ns, size_t ns_sz,
                          char *user, size_t user_sz,
                          char *caps_drop, size_t caps_drop_sz,
                          struct bsv_restart_policy *restart_policy)
{
  FILE *f = fopen (run_script, "r");
  char line[256];
  int rc = 0;
  ns[0] = '\0';
  user[0] = '\0';
  caps_drop[0] = '\0';
  if (restart_policy)
    bsv_restart_policy_init (restart_policy);
  if (!f) return -1;
  while (fgets (line, sizeof line, f))
    {
      char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      if (*p != '#') break;
      p++;
      while (*p == ' ' || *p == '\t') p++;
      if (strncmp (p, "namespace:", 10) == 0)
        {
          p += 10;
          while (*p == ' ' || *p == '\t') p++;
          size_t n = strcspn (p, " \t\r\n");
          if (n > 0 && n < ns_sz)
            {
              int ok = 1;
              for (size_t i = 0; i < n; i++)
                if (!(('a' <= p[i] && p[i] <= 'z') || p[i] == ','))
                  { ok = 0; break; }
              if (ok) { memcpy (ns, p, n); ns[n] = '\0'; }
              else
                {
                  fprintf (stderr, "sv: invalid namespace directive in %s\n",
                           run_script);
                  rc = -1;
                  break;
                }
            }
          else if (n > 0)
            {
              fprintf (stderr, "sv: namespace directive too long in %s\n",
                       run_script);
              rc = -1;
              break;
            }
        }
      else if (strncmp (p, "user:", 5) == 0)
        {
          p += 5;
          while (*p == ' ' || *p == '\t') p++;
          size_t n = strcspn (p, " \t\r\n");
          if (n > 0 && n < user_sz)
            {
              int ok = 1;
              for (size_t i = 0; i < n; i++)
                if (!(('A' <= p[i] && p[i] <= 'Z') ||
                      ('a' <= p[i] && p[i] <= 'z') ||
                      ('0' <= p[i] && p[i] <= '9') ||
                      p[i] == '_' || p[i] == '-' || p[i] == '.'))
                  { ok = 0; break; }
              if (ok) { memcpy (user, p, n); user[n] = '\0'; }
              else
                {
                  fprintf (stderr, "sv: invalid user directive in %s\n",
                           run_script);
                  rc = -1;
                  break;
                }
            }
          else if (n > 0)
            {
              fprintf (stderr, "sv: user directive too long in %s\n",
                       run_script);
              rc = -1;
              break;
            }
        }
      else if (strncmp (p, "capabilities-drop:", 18) == 0)
        {
          p += 18;
          while (*p == ' ' || *p == '\t') p++;
          size_t n = strcspn (p, " \t\r\n");
          if (bsv_parse_capability_list (p, n, caps_drop, caps_drop_sz,
                                         run_script) < 0)
            {
              rc = -1;
              break;
            }
        }
      else if (restart_policy && strncmp (p, "restart:", 8) == 0)
        {
          p += 8;
          if (bsv_parse_restart_mode (p, restart_policy, run_script) < 0)
            {
              rc = -1;
              break;
            }
        }
      else if (restart_policy && strncmp (p, "restart-max:", 12) == 0)
        {
          p += 12;
          if (bsv_parse_restart_number (p, "restart-max", 1,
                                        BSV_RESTART_MAX_LIMIT,
                                        &restart_policy->max,
                                        run_script) < 0)
            {
              rc = -1;
              break;
            }
        }
      else if (restart_policy && strncmp (p, "restart-window:", 15) == 0)
        {
          p += 15;
          if (bsv_parse_restart_number (p, "restart-window", 1,
                                        BSV_RESTART_WINDOW_MAX,
                                        &restart_policy->window,
                                        run_script) < 0)
            {
              rc = -1;
              break;
            }
        }
      else if (restart_policy && strncmp (p, "restart-delay:", 14) == 0)
        {
          p += 14;
          if (bsv_parse_restart_number (p, "restart-delay", 0,
                                        BSV_RESTART_DELAY_MAX,
                                        &restart_policy->delay,
                                        run_script) < 0)
            {
              rc = -1;
              break;
            }
        }
    }
  fclose (f);
  return rc;
}

static void
bsv_trim_span (char **start, char **end)
{
  while (*start < *end && (**start == ' ' || **start == '\t')) (*start)++;
  while (*end > *start &&
         ((*end)[-1] == ' ' || (*end)[-1] == '\t' ||
          (*end)[-1] == '\r' || (*end)[-1] == '\n'))
    (*end)--;
  **end = '\0';
}

static int
bsv_parse_ready_timeout (const char *p, int *timeout, const char *run_script)
{
  char *endp = NULL;
  long v;
  while (*p == ' ' || *p == '\t') p++;
  errno = 0;
  v = strtol (p, &endp, 10);
  if (errno != 0 || endp == p)
    {
      fprintf (stderr, "sv: invalid readiness-timeout in %s\n",
               run_script);
      return -1;
    }
  while (*endp == ' ' || *endp == '\t' || *endp == '\r' || *endp == '\n')
    endp++;
  if (*endp != '\0' && *endp != '#')
    {
      fprintf (stderr, "sv: invalid readiness-timeout in %s\n",
               run_script);
      return -1;
    }
  if (v < 1)
    v = 1;
  if (v > BSV_READY_TIMEOUT_MAX)
    v = BSV_READY_TIMEOUT_MAX;
  *timeout = (int) v;
  return 0;
}

static int
bsv_readiness_policy_for (const char *name, const char *run_script,
                          struct bsv_readiness_policy *pol)
{
  FILE *f;
  char line[512];
  int explicit_disable = 0;

  memset (pol, 0, sizeof *pol);
  pol->timeout = BSV_READY_TIMEOUT_DEFAULT;
  if (bsv_path (pol->check_path, sizeof pol->check_path, bsv_sv_dir, name,
                "check") < 0)
    return -1;
  if (access (pol->check_path, X_OK) == 0)
    {
      pol->enabled = 1;
      pol->use_shell = 0;
      pol->mode = BSV_READY_PROBE;
    }

  f = fopen (run_script, "r");
  if (!f)
    return -1;
  while (fgets (line, sizeof line, f))
    {
      char *p = line;
      char *e;
      while (*p == ' ' || *p == '\t') p++;
      if (*p != '#') break;
      p++;
      while (*p == ' ' || *p == '\t') p++;
      if (strncmp (p, "readiness-timeout:", 18) == 0)
        {
          p += 18;
          if (bsv_parse_ready_timeout (p, &pol->timeout, run_script) < 0)
            { fclose (f); return -1; }
        }
      else if (strncmp (p, "readiness:", 10) == 0)
        {
          p += 10;
          e = p + strcspn (p, "\r\n");
          bsv_trim_span (&p, &e);
          if (*p == '\0' ||
              strcmp (p, "none") == 0 ||
              strcmp (p, "off") == 0 ||
              strcmp (p, "disabled") == 0)
            {
              pol->enabled = 0;
              pol->use_shell = 0;
              pol->mode = BSV_READY_NONE;
              explicit_disable = 1;
              pol->command[0] = '\0';
            }
          else if (strcmp (p, "check") == 0 || strcmp (p, "./check") == 0)
            {
              pol->enabled = 1;
              pol->use_shell = 0;
              pol->mode = BSV_READY_PROBE;
              pol->command[0] = '\0';
              explicit_disable = 0;
            }
          else if (strcmp (p, "notify") == 0)
            {
              /* sd_notify-style push protocol: mutually exclusive with the
                 pull probes; an explicit directive wins over an executable
                 ./check (same precedence as the explicit-disable arm). */
              pol->enabled = 1;
              pol->use_shell = 0;
              pol->mode = BSV_READY_NOTIFY;
              pol->command[0] = '\0';
              explicit_disable = 0;
            }
          else
            {
              size_t n = strlen (p);
              if (n >= sizeof pol->command)
                {
                  fprintf (stderr, "sv: readiness command too long in %s\n",
                           run_script);
                  fclose (f);
                  return -1;
                }
              pol->enabled = 1;
              pol->use_shell = 1;
              pol->mode = BSV_READY_COMMAND;
              memcpy (pol->command, p, n + 1);
              explicit_disable = 0;
            }
        }
    }
  fclose (f);

  if (pol->mode == BSV_READY_PROBE && access (pol->check_path, X_OK) != 0)
    {
      if (explicit_disable)
        return 0;
      fprintf (stderr, "sv: readiness check not executable: %s\n",
               pol->check_path);
      return -1;
    }
  return 0;
}

static void
bsv_log_notice (const char *name, const struct bsv_log_policy *policy,
                const char *fmt, ...)
{
  char logfile[512];
  int fd;
  va_list ap;
  if (bsv_path (logfile, sizeof logfile, bsv_log_dir, name, NULL) < 0)
    return;
  fd = bsv_open_log (logfile, policy);
  if (fd < 0)
    return;
  va_start (ap, fmt);
  vdprintf (fd, fmt, ap);
  va_end (ap);
  close (fd);
}

static int
bsv_parse_namespace_flags (const char *flags, int *out)
{
  char buf[256];
  *out = 0;
  if (!flags || !*flags) return 0;
  if (strlen (flags) >= sizeof buf) return -1;
  strcpy (buf, flags);
  for (char *p = buf, *tok; (tok = strtok (p, ",")); p = NULL)
    {
      int hit = 0;
      for (size_t i = 0; i < sizeof bsv_ns_flags / sizeof bsv_ns_flags[0]; i++)
        if (strcmp (tok, bsv_ns_flags[i].name) == 0)
          {
            *out |= bsv_ns_flags[i].flag;
            hit = 1;
            break;
          }
      if (!hit) return -1;
    }
  return 0;
}

static int
bsv_clone_namespace (const char *ns)
{
  int flags = 0;
  if (bsv_parse_namespace_flags (ns, &flags) < 0)
    {
      fprintf (stderr, "sv: unknown namespace directive: %s\n", ns);
      return -1;
    }
  if (flags == 0) return 0;

  struct sigaction chld_dfl, chld_save;
  sigset_t chld_set, old_set;
  memset (&chld_dfl, 0, sizeof chld_dfl);
  chld_dfl.sa_handler = SIG_DFL;
  sigemptyset (&chld_dfl.sa_mask);
  sigaction (SIGCHLD, &chld_dfl, &chld_save);
  sigemptyset (&chld_set);
  sigaddset (&chld_set, SIGCHLD);
  if (sigprocmask (SIG_BLOCK, &chld_set, &old_set) < 0)
    {
      sigaction (SIGCHLD, &chld_save, NULL);
      return -1;
    }

  pid_t pid = (pid_t) syscall (SYS_clone, (long) (flags | SIGCHLD),
                               (void *) NULL, (void *) NULL,
                               (void *) NULL, 0L);
  if (pid < 0)
    {
      sigprocmask (SIG_SETMASK, &old_set, NULL);
      sigaction (SIGCHLD, &chld_save, NULL);
      fprintf (stderr, "sv: clone namespace %s: %s\n",
               ns, strerror (errno));
      return -1;
    }
  if (pid == 0)
    {
      sigprocmask (SIG_SETMASK, &old_set, NULL);
      return 0;
    }

  int st = 0;
  while (waitpid (pid, &st, 0) < 0)
    {
      if (errno == EINTR) continue;
      sigprocmask (SIG_SETMASK, &old_set, NULL);
      sigaction (SIGCHLD, &chld_save, NULL);
      fprintf (stderr, "sv: wait namespace child: %s\n", strerror (errno));
      _exit (127);
    }
  sigprocmask (SIG_SETMASK, &old_set, NULL);
  sigaction (SIGCHLD, &chld_save, NULL);
  if (WIFEXITED (st)) _exit (WEXITSTATUS (st));
  if (WIFSIGNALED (st)) _exit (128 + WTERMSIG (st));
  _exit (127);
}

static int
bsv_resolve_user (const char *name, uid_t *uid, gid_t *gid,
                  gid_t *groups, int *ngroups, size_t max_groups)
{
  bc_user_info info;
  int sup = 0;
  if (!name || !*name || !uid || !gid || !groups || !ngroups || max_groups == 0)
    { errno = EINVAL; return -1; }
  if (bc_lookup_user (name, &info) != 0)
    return -1;

  *uid = info.uid;
  *gid = info.gid;
  groups[0] = info.gid;
  *ngroups = 1;
  bc_load_supplementary_groups (info.name, groups + 1, &sup,
                                (int) max_groups - 1);
  for (int i = 0; i < sup && *ngroups < (int) max_groups; i++)
    {
      int dup = 0;
      for (int j = 0; j < *ngroups; j++)
        if (groups[j] == groups[1 + i]) { dup = 1; break; }
      if (!dup) groups[(*ngroups)++] = groups[1 + i];
    }
  return 0;
}

extern char **environ;

/* execve the run script with an explicitly assembled envp: bash's exported
   environment minus any stale SV_NAME/NOTIFY_SOCKET, plus the supervisor's
   per-service values.  setenv() in a forked loadable child does NOT survive
   exec* under the static-musl build (bash re-points environ at its own
   export_env), so the env must be built by hand — the same trap
   bsv_execve_with_listen_env already works around for LISTEN_*. */
static void
bsv_execve_service (const char *run_script, const char *name,
                    const char *notify_socket)
{
  size_t nenv = 0, out = 0;
  char svbuf[160], nfbuf[192];
  char *argv[2];
  char **envp;

  while (environ && environ[nenv])
    nenv++;
  envp = calloc (nenv + 3, sizeof *envp);
  if (!envp)
    _exit (127);

  for (size_t i = 0; i < nenv; i++)
    {
      if (strncmp (environ[i], "SV_NAME=", 8) == 0 ||
          strncmp (environ[i], "NOTIFY_SOCKET=", 14) == 0)
        continue;
      envp[out++] = environ[i];
    }

  snprintf (svbuf, sizeof svbuf, "SV_NAME=%s", name);
  envp[out++] = svbuf;
  if (notify_socket && *notify_socket)
    {
      snprintf (nfbuf, sizeof nfbuf, "NOTIFY_SOCKET=%s", notify_socket);
      envp[out++] = nfbuf;
    }
  envp[out] = NULL;

  argv[0] = (char *) run_script;
  argv[1] = NULL;
  execve (run_script, argv, envp);
  fprintf (stderr, "sv: exec %s: %s\n", run_script, strerror (errno));
  _exit (127);
}

static void
bsv_exec_service (const char *name, const char *run_script, const char *ns,
                  const char *user, const char *caps_drop,
                  const char *notify_socket)
{
  setenv ("SV_NAME", name, 1);
  if (notify_socket && *notify_socket)
    setenv ("NOTIFY_SOCKET", notify_socket, 1);
  if (bsv_listen_activation)
    {
      char pidbuf[32];
      snprintf (pidbuf, sizeof pidbuf, "%ld", (long) getpid ());
      SHELL_VAR *v;
      v = builtin_bind_variable ("LISTEN_FDS", "1", 0);
      if (v) SETVARATTR (v, att_exported, 0);
      v = builtin_bind_variable ("LISTEN_PID", pidbuf, 0);
      if (v) SETVARATTR (v, att_exported, 0);
      v = builtin_bind_variable ("LISTEN_FDNAMES", (char *) name, 0);
      if (v) SETVARATTR (v, att_exported, 0);
    }
  maybe_make_export_env ();
  char err[BC_PD_ERR_MAX];

  if (user && *user)
    {
      uid_t uid;
      gid_t gid;
      gid_t groups[BC_PD_GROUPS_MAX];
      int ngroups = 0;
      if (geteuid () != 0)
        {
          fprintf (stderr,
                   "sv: # user requires cred builtin (Stage 23+) and root\n");
          _exit (69);
        }
      if (bsv_resolve_user (user, &uid, &gid, groups, &ngroups,
                            sizeof groups / sizeof groups[0]) < 0)
        {
          fprintf (stderr, "sv: user not found: %s\n", user);
          _exit (1);
        }
      if (ns && *ns && bsv_clone_namespace (ns) < 0)
        _exit (1);
      setenv ("SV_NAME", name, 1);
      if (notify_socket && *notify_socket)
        setenv ("NOTIFY_SOCKET", notify_socket, 1);
      if (bc_no_new_privs (err, sizeof err) < 0)
        {
          fprintf (stderr, "sv: %s\n", err[0] ? err : strerror (errno));
          _exit (1);
        }
      /* Keep just enough privilege to perform the actual uid/gid switch.
         A full caps-clear before bc_privdrop_to_user() makes setgroups(2)
         fail with EPERM; after setresuid() Linux drops the remaining
         effective/permitted capabilities for us. */
      if (bc_caps_clear ("CAP_SETGID,CAP_SETUID", err, sizeof err) < 0)
        {
          fprintf (stderr, "sv: %s\n", err[0] ? err : strerror (errno));
          _exit (1);
        }
      if (bc_privdrop_to_user (uid, gid, groups, ngroups, err, sizeof err) < 0)
        {
          fprintf (stderr, "sv: %s\n", err[0] ? err : strerror (errno));
          _exit (1);
        }
      if (ns && *ns)
        execl ("/bin/bash", "bash", "-c",
               "export SV_NAME=\"$1\"; "
               "[ -n \"$3\" ] && export NOTIFY_SOCKET=\"$3\"; exec \"$2\"",
               "sv-service", name, run_script,
               notify_socket ? notify_socket : "", (char *) NULL);
      else
        bsv_execve_service (run_script, name, notify_socket);
      fprintf (stderr, "sv: exec %s: %s\n", run_script, strerror (errno));
      _exit (127);
    }

  if (caps_drop && *caps_drop)
    {
      if (bc_caps_drop (caps_drop, err, sizeof err) < 0)
        {
          fprintf (stderr, "sv: %s\n", err[0] ? err : strerror (errno));
          _exit (1);
        }
    }

  if (ns && *ns)
    execl ("/bin/bash", "bash", "-c",
           "export SV_NAME=\"$3\"; "
           "[ -n \"$4\" ] && export NOTIFY_SOCKET=\"$4\"; "
           "if [[ $(type -t ns 2>/dev/null) == builtin ]]; then "
           "ns spawn --no-new-privs \"$1\" \"$2\"; exit $?; fi; exec \"$2\"",
           "sv-service", ns, run_script, name,
           notify_socket ? notify_socket : "", (char *) NULL);
  else
    bsv_execve_service (run_script, name, notify_socket);
  _exit (127);
}

static void
bsv_write_exit_status (const char *status, int st)
{
  if (WIFEXITED (st))
    bsv_writef (status, "exited rc=%d\n", WEXITSTATUS (st));
  else if (WIFSIGNALED (st))
    bsv_writef (status, "exited signal=%d\n", WTERMSIG (st));
  else
    bsv_writef (status, "exited\n");
}

static void
bsv_write_exit_status_pair (const char *status, const char *transition, int st)
{
  bsv_write_exit_status (status, st);
  if (transition)
    bsv_write_exit_status (transition, st);
}

static int
bsv_finish_arg (int st)
{
  if (WIFEXITED (st))
    return WEXITSTATUS (st);
  if (WIFSIGNALED (st))
    return 128 + WTERMSIG (st);
  return 0;
}

static void
bsv_log_policy_for (const char *name, struct bsv_log_policy *pol)
{
  char cfg[512], line[256];
  FILE *f;
  pol->max_bytes = bsv_log_max_bytes;
  pol->generations = bsv_clamp_log_generations (bsv_log_generations);
  pol->timestamp = 0;
  if (!name || bsv_path (cfg, sizeof cfg, bsv_sv_dir, name, "log/config") < 0)
    return;
  f = fopen (cfg, "r");
  if (!f)
    return;
  while (fgets (line, sizeof line, f))
    {
      char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      if (*p == '#' || *p == '\0' || *p == '\r' || *p == '\n') continue;
      char *e = p + strcspn (p, "#\r\n");
      while (e > p && (e[-1] == ' ' || e[-1] == '\t')) e--;
      *e = '\0';
      if (*p == 's' && isdigit ((unsigned char) p[1]))
        pol->max_bytes = (off_t) strtoll (p + 1, NULL, 10);
      else if (*p == 'n' && isdigit ((unsigned char) p[1]))
        pol->generations = bsv_clamp_log_generations (strtol (p + 1, NULL, 10));
      else if (strcmp (p, "t") == 0 || strcmp (p, "T") == 0 ||
               strcmp (p, "timestamp") == 0 ||
               strcmp (p, "timestamp=1") == 0 ||
               strcmp (p, "timestamp=true") == 0)
        pol->timestamp = 1;
      else if (strncmp (p, "max-bytes=", 10) == 0)
        pol->max_bytes = (off_t) strtoll (p + 10, NULL, 10);
      else if (strncmp (p, "generations=", 12) == 0)
        pol->generations = bsv_clamp_log_generations (strtol (p + 12, NULL, 10));
    }
  fclose (f);
  if (pol->max_bytes < 0) pol->max_bytes = bsv_log_max_bytes;
  pol->generations = bsv_clamp_log_generations (pol->generations);
}

static void
bsv_write_timestamp_prefix (int fd)
{
  char ts[64];
  struct timespec tv;
  struct tm tm;
  clock_gettime (CLOCK_REALTIME, &tv);
  gmtime_r (&tv.tv_sec, &tm);
  int n = snprintf (ts, sizeof ts, "%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ ",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_nsec);
  if (n > 0)
    write (fd, ts, (size_t) n);
}

static void
bsv_write_timestamped_chunk (int fd, const char *buf, ssize_t n, int *line_start)
{
  ssize_t i = 0;
  while (i < n)
    {
      if (*line_start)
        {
          bsv_write_timestamp_prefix (fd);
          *line_start = 0;
        }
      ssize_t j = i;
      while (j < n && buf[j] != '\n') j++;
      if (j > i)
        write (fd, buf + i, (size_t) (j - i));
      if (j < n && buf[j] == '\n')
        {
          write (fd, "\n", 1);
          *line_start = 1;
          j++;
        }
      i = j;
    }
}

static int
bsv_open_log (const char *logfile, const struct bsv_log_policy *policy)
{
  struct stat st;
  char rotated[640], next[640];
  int gens = policy ? bsv_clamp_log_generations (policy->generations)
                    : bsv_clamp_log_generations (bsv_log_generations);
  off_t max_bytes = policy ? policy->max_bytes : bsv_log_max_bytes;

  if (max_bytes > 0 &&
      stat (logfile, &st) == 0 &&
      S_ISREG (st.st_mode) &&
      st.st_size >= max_bytes)
    {
      /* Drop the oldest, then shift .N-1 → .N, .N-2 → .N-1, ..., .1 → .2.
         rename(2) is a no-op on missing source under POSIX (errno ENOENT),
         which is fine here — we just skip empty slots on the shift up.  */
      if (snprintf (rotated, sizeof rotated, "%s.%d", logfile, gens)
          < (int) sizeof rotated)
        unlink (rotated);
      for (int i = gens - 1; i >= 1; i--)
        {
          if (snprintf (rotated, sizeof rotated, "%s.%d", logfile, i)
              >= (int) sizeof rotated)
            continue;
          if (snprintf (next, sizeof next, "%s.%d", logfile, i + 1)
              >= (int) sizeof next)
            continue;
          rename (rotated, next);
        }
      if (snprintf (rotated, sizeof rotated, "%s.1", logfile)
          < (int) sizeof rotated)
        rename (logfile, rotated);
    }

  return open (logfile, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
}

static void
bsv_run_finish (const char *name, int st, const char *logfile)
{
  char finish[512], arg[32];
  pid_t pid;
  int fd;
  struct bsv_log_policy policy;

  if (bsv_path (finish, sizeof finish, bsv_sv_dir, name, "finish") < 0)
    return;
  if (access (finish, X_OK) != 0)
    return;

  snprintf (arg, sizeof arg, "%d", bsv_finish_arg (st));
  pid = fork ();
  if (pid < 0)
    return;
  if (pid == 0)
    {
      setenv ("SV_NAME", name, 1);
      bsv_log_policy_for (name, &policy);
      fd = bsv_open_log (logfile, &policy);
      if (fd >= 0)
        {
          dup2 (fd, STDOUT_FILENO);
          dup2 (fd, STDERR_FILENO);
          if (fd > STDERR_FILENO) close (fd);
        }
      execl (finish, finish, arg, (char *) NULL);
      fprintf (stderr, "sv: exec %s: %s\n", finish, strerror (errno));
      _exit (127);
    }
  while (waitpid (pid, NULL, 0) < 0 && errno == EINTR)
    ;
}

static pid_t
bsv_fork_service_logged (const char *name, const char *run_script,
                         const char *ns_flags, const char *run_user,
                         const char *caps_drop, const char *logfile,
                         const struct bsv_log_policy *policy,
                         const char *notify_socket,
                         int *pipe_read, int *log_fd)
{
  int pfd[2] = { -1, -1 };
  *pipe_read = -1;
  *log_fd = -1;
  if (policy && policy->timestamp)
    {
      if (pipe (pfd) < 0)
        return -1;
      *log_fd = bsv_open_log (logfile, policy);
      if (*log_fd < 0)
        {
          close (pfd[0]); close (pfd[1]);
          return -1;
        }
    }
  pid_t pid = fork ();
  if (pid < 0)
    {
      if (pfd[0] >= 0) close (pfd[0]);
      if (pfd[1] >= 0) close (pfd[1]);
      if (*log_fd >= 0) close (*log_fd);
      return -1;
    }
  if (pid == 0)
    {
      sigset_t empty_mask;
      sigemptyset (&empty_mask);
      sigprocmask (SIG_SETMASK, &empty_mask, NULL);
      if (policy && policy->timestamp)
        {
          close (pfd[0]);
          dup2 (pfd[1], STDOUT_FILENO);
          dup2 (pfd[1], STDERR_FILENO);
          if (pfd[1] > STDERR_FILENO) close (pfd[1]);
          if (*log_fd > STDERR_FILENO) close (*log_fd);
        }
      else
        {
          int fd = bsv_open_log (logfile, policy);
          if (fd >= 0)
            {
              dup2 (fd, STDOUT_FILENO);
              dup2 (fd, STDERR_FILENO);
              if (fd > STDERR_FILENO) close (fd);
            }
        }
      setpgid (0, 0);
      bsv_exec_service (name, run_script, ns_flags, run_user, caps_drop,
                        notify_socket);
    }
  if (policy && policy->timestamp)
    {
      close (pfd[1]);
      fcntl (pfd[0], F_SETFL, fcntl (pfd[0], F_GETFL, 0) | O_NONBLOCK);
      *pipe_read = pfd[0];
    }
  return pid;
}

static void
bsv_drain_log_pipe_once (int rfd, int lfd, int *line_start)
{
  char buf[512];
  while (1)
    {
      ssize_t n = read (rfd, buf, sizeof buf);
      if (n > 0)
        bsv_write_timestamped_chunk (lfd, buf, n, line_start);
      else
        break;
    }
}

static pid_t
bsv_fork_readiness_logged (const char *name,
                           const struct bsv_readiness_policy *ready,
                           const char *logfile,
                           const struct bsv_log_policy *policy,
                           int *pipe_read, int *log_fd)
{
  int pfd[2] = { -1, -1 };
  *pipe_read = -1;
  *log_fd = -1;
  if (policy && policy->timestamp)
    {
      if (pipe (pfd) < 0)
        return -1;
      *log_fd = bsv_open_log (logfile, policy);
      if (*log_fd < 0)
        {
          close (pfd[0]); close (pfd[1]);
          return -1;
        }
    }

  pid_t pid = fork ();
  if (pid < 0)
    {
      if (pfd[0] >= 0) close (pfd[0]);
      if (pfd[1] >= 0) close (pfd[1]);
      if (*log_fd >= 0) close (*log_fd);
      return -1;
    }
  if (pid == 0)
    {
      sigset_t empty_mask;
      sigemptyset (&empty_mask);
      sigprocmask (SIG_SETMASK, &empty_mask, NULL);
      setenv ("SV_NAME", name, 1);
      maybe_make_export_env ();
      if (policy && policy->timestamp)
        {
          close (pfd[0]);
          dup2 (pfd[1], STDOUT_FILENO);
          dup2 (pfd[1], STDERR_FILENO);
          if (pfd[1] > STDERR_FILENO) close (pfd[1]);
          if (*log_fd > STDERR_FILENO) close (*log_fd);
        }
      else
        {
          int fd = bsv_open_log (logfile, policy);
          if (fd >= 0)
            {
              dup2 (fd, STDOUT_FILENO);
              dup2 (fd, STDERR_FILENO);
              if (fd > STDERR_FILENO) close (fd);
            }
        }
      if (ready->use_shell)
        execl ("/bin/bash", "bash", "-c", ready->command, (char *) NULL);
      else
        execl (ready->check_path, ready->check_path, (char *) NULL);
      fprintf (stderr, "sv: exec readiness probe: %s\n", strerror (errno));
      _exit (127);
    }

  if (policy && policy->timestamp)
    {
      close (pfd[1]);
      fcntl (pfd[0], F_SETFL, fcntl (pfd[0], F_GETFL, 0) | O_NONBLOCK);
      *pipe_read = pfd[0];
    }
  return pid;
}

static int
bsv_run_readiness_probe (const char *name,
                         const struct bsv_readiness_policy *ready,
                         pid_t svc_pid,
                         const char *status,
                         const char *transition,
                         const char *logfile,
                         const struct bsv_log_policy *policy)
{
  int pipe_read = -1, log_fd = -1, line_start = 1;
  int st = 0;
  time_t deadline;
  pid_t w;

  if (!ready || !ready->enabled)
    return EXECUTION_SUCCESS;

  bsv_writef (transition, "readiness-checking\n");
  w = bsv_fork_readiness_logged (name, ready, logfile, policy, &pipe_read,
                                 &log_fd);
  if (w < 0)
    {
      bsv_writef (transition, "readiness-failed fork errno=%d\n", errno);
      bsv_writef (status, "readiness-failed fork errno=%d pid=%ld\n", errno,
                  (long) svc_pid);
      bsv_log_notice (name, policy,
                      "sv: readiness failed: fork: %s\n",
                      strerror (errno));
      return EXECUTION_FAILURE;
    }

  deadline = time (NULL) + ready->timeout;
  while (1)
    {
      if (pipe_read >= 0)
        bsv_drain_log_pipe_once (pipe_read, log_fd, &line_start);
      pid_t got = waitpid (w, &st, WNOHANG);
      if (got == w)
        break;
      if (got < 0 && errno != EINTR)
        {
          bsv_writef (transition, "readiness-failed wait errno=%d\n", errno);
          bsv_writef (status, "readiness-failed wait errno=%d pid=%ld\n",
                      errno, (long) svc_pid);
          bsv_log_notice (name, policy,
                          "sv: readiness failed: wait: %s\n",
                          strerror (errno));
          if (pipe_read >= 0)
            {
              close (pipe_read);
              close (log_fd);
            }
          return EXECUTION_FAILURE;
        }
      if (time (NULL) >= deadline)
        {
          kill (w, SIGTERM);
          usleep (100000);
          if (waitpid (w, &st, WNOHANG) == 0)
            {
              kill (w, SIGKILL);
              waitpid (w, &st, 0);
            }
          if (pipe_read >= 0)
            bsv_drain_log_pipe_once (pipe_read, log_fd, &line_start);
          bsv_writef (transition, "readiness-failed timeout\n");
          bsv_writef (status, "readiness-failed timeout pid=%ld\n",
                      (long) svc_pid);
          bsv_log_notice (name, policy,
                          "sv: readiness failed: timeout after %d seconds\n",
                          ready->timeout);
          if (pipe_read >= 0)
            {
              close (pipe_read);
              close (log_fd);
            }
          return EXECUTION_FAILURE;
        }
      usleep (100000);
    }

  if (pipe_read >= 0)
    {
      bsv_drain_log_pipe_once (pipe_read, log_fd, &line_start);
      close (pipe_read);
      close (log_fd);
    }

  if (WIFEXITED (st) && WEXITSTATUS (st) == 0)
    {
      bsv_writef (transition, "ready\n");
      bsv_writef (status, "ready pid=%ld\n", (long) svc_pid);
      return EXECUTION_SUCCESS;
    }
  if (WIFEXITED (st))
    {
      bsv_writef (transition, "readiness-failed rc=%d\n", WEXITSTATUS (st));
      bsv_writef (status, "readiness-failed rc=%d pid=%ld\n",
                  WEXITSTATUS (st), (long) svc_pid);
      bsv_log_notice (name, policy,
                      "sv: readiness failed: rc=%d\n", WEXITSTATUS (st));
    }
  else if (WIFSIGNALED (st))
    {
      bsv_writef (transition, "readiness-failed signal=%d\n", WTERMSIG (st));
      bsv_writef (status, "readiness-failed signal=%d pid=%ld\n",
                  WTERMSIG (st), (long) svc_pid);
      bsv_log_notice (name, policy,
                      "sv: readiness failed: signal=%d\n",
                      WTERMSIG (st));
    }
  else
    {
      bsv_writef (transition, "readiness-failed\n");
      bsv_writef (status, "readiness-failed pid=%ld\n", (long) svc_pid);
      bsv_log_notice (name, policy, "sv: readiness failed\n");
    }
  return EXECUTION_FAILURE;
}

/* --- J04 sd_notify-style readiness push protocol (opt-in) ----------------
   `# readiness: notify` services signal their own state to the supervisor
   over a per-service abstract AF_UNIX SOCK_DGRAM socket (no filesystem
   path, auto-cleaned when the supervisor closes the fd).  The supervisor
   exports NOTIFY_SOCKET=@sv/<name> next to SV_NAME and recognizes the
   sd_notify-compatible subset READY=1 / RELOADING=1 / STOPPING=1 /
   STATUS=<text> / MAINPID=<pid>; unknown keys are ignored
   (forward-compatible).  Intentionally OUT of scope (see
   docs/SECURITY-J04-SERVICES.md): WATCHDOG=1/WATCHDOG_USEC liveness,
   FDSTORE=1 fd passing, BARRIER=1, EXTEND_TIMEOUT_USEC, Type=notify-reload,
   and full SCM_CREDENTIALS per-message peer authentication (SO_PASSCRED is
   set best-effort only; MAINPID is sanity-checked against the supervised
   process tree instead).  The shell fallback (rootfs/bash-os/sv.sh)
   mirrors the same line grammar and status vocabulary over a named FIFO at
   $BASHSV_RUNDIR/<name>/notify because bash cannot bind AF_UNIX datagram
   sockets; that divergence is the documented dual-contract exception. */

struct bsv_notify_state {
  int fd;                       /* bound dgram socket, -1 when inactive */
  int got_ready;                /* READY=1 seen at least once */
  int failed;                   /* readiness timeout already published */
  int state;                    /* 0 running, 1 ready, 2 reloading, 3 stopping */
  pid_t main_pid;               /* supervised pid, or validated MAINPID= */
  char text[128];               /* sanitized STATUS= free text */
};

static int
bsv_notify_addr (const char *name, struct sockaddr_un *addr, socklen_t *alen)
{
  int n;
  if (!bsv_valid_name (name))
    return -1;
  memset (addr, 0, sizeof *addr);
  addr->sun_family = AF_UNIX;
  /* abstract namespace: leading NUL byte, then "sv/<name>" */
  n = snprintf (addr->sun_path + 1, sizeof addr->sun_path - 1, "sv/%s",
                name);
  if (n < 0 || (size_t) n >= sizeof addr->sun_path - 1)
    return -1;
  *alen = (socklen_t) (offsetof (struct sockaddr_un, sun_path) + 1 + n);
  return 0;
}

static int
bsv_notify_bind (const char *name, int *out_fd)
{
  struct sockaddr_un addr;
  socklen_t alen;
  int fd, one = 1;
  *out_fd = -1;
  if (bsv_notify_addr (name, &addr, &alen) < 0)
    return -1;
  fd = socket (AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0)
    return -1;
  if (bind (fd, (struct sockaddr *) &addr, alen) < 0)
    {
      close (fd);
      return -1;
    }
  setsockopt (fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof one); /* best effort */
  *out_fd = fd;
  return 0;
}

/* Return 1 when pid is the supervised process or a descendant of it
   (bounded /proc ppid walk), so a forking service can hand off its real
   worker pid via MAINPID= while a foreign pid is ignored. */
static int
bsv_notify_pid_ok (pid_t pid, pid_t svc_pid)
{
  int hops;
  if (pid <= 0 || svc_pid <= 0)
    return 0;
  if (pid == svc_pid)
    return 1;
  if (kill (pid, 0) < 0 && errno != EPERM)
    return 0;
  for (hops = 0; hops < 16 && pid > 1; hops++)
    {
      char path[64], buf[512], *rp;
      int sfd;
      ssize_t n;
      long ppid = 0;
      snprintf (path, sizeof path, "/proc/%ld/stat", (long) pid);
      sfd = open (path, O_RDONLY);
      if (sfd < 0)
        return 0;
      n = read (sfd, buf, sizeof buf - 1);
      close (sfd);
      if (n <= 0)
        return 0;
      buf[n] = '\0';
      rp = strrchr (buf, ')');  /* comm may contain spaces/parens */
      if (!rp || sscanf (rp + 1, " %*c %ld", &ppid) != 1)
        return 0;
      if ((pid_t) ppid == svc_pid)
        return 1;
      pid = (pid_t) ppid;
    }
  return 0;
}

static void
bsv_notify_publish (const struct bsv_notify_state *ns, const char *status,
                    const char *transition)
{
  const char *tok = ns->state == 1 ? "ready"
                  : ns->state == 2 ? "reloading"
                  : "stopping";
  /* transition gets the bare token, status the token + pid — the exact
     vocabulary bsv_run_readiness_probe publishes on probe success, so
     bsv_wait_start_barrier gates dependents with zero changes. */
  bsv_writef (transition, "%s\n", tok);
  if (ns->text[0])
    bsv_writef (status, "%s pid=%ld status=%s\n", tok, (long) ns->main_pid,
                ns->text);
  else
    bsv_writef (status, "%s pid=%ld\n", tok, (long) ns->main_pid);
}

static void
bsv_notify_drain (struct bsv_notify_state *ns, pid_t svc_pid,
                  const char *status, const char *transition,
                  const char *pidfile)
{
  char buf[1024];
  if (ns->fd < 0)
    return;
  for (;;)
    {
      ssize_t n = recv (ns->fd, buf, sizeof buf - 1, 0);
      int changed = 0;
      char *line, *next;
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          break;                /* EAGAIN/EWOULDBLOCK: drained */
        }
      buf[n] = '\0';
      for (line = buf; line && *line; line = next)
        {
          next = strchr (line, '\n');
          if (next)
            *next++ = '\0';
          if (strcmp (line, "READY=1") == 0)
            {
              ns->state = 1;
              ns->got_ready = 1;
              changed = 1;
            }
          else if (strcmp (line, "RELOADING=1") == 0)
            {
              ns->state = 2;
              changed = 1;
            }
          else if (strcmp (line, "STOPPING=1") == 0)
            {
              /* advisory only: records intent; teardown stays driven by
                 `down`/SIGTERM exactly as today. */
              ns->state = 3;
              changed = 1;
            }
          else if (strncmp (line, "STATUS=", 7) == 0)
            {
              size_t tn = strcspn (line + 7, "\r\n");
              size_t i;
              if (tn >= sizeof ns->text)
                tn = sizeof ns->text - 1;
              memcpy (ns->text, line + 7, tn);
              ns->text[tn] = '\0';
              for (i = 0; i < tn; i++)   /* keep the status file one-line */
                if ((unsigned char) ns->text[i] < 0x20)
                  ns->text[i] = ' ';
              changed = 1;
            }
          else if (strncmp (line, "MAINPID=", 8) == 0)
            {
              char *endp = NULL;
              long v = strtol (line + 8, &endp, 10);
              if (endp && *endp == '\0' && v > 0 &&
                  bsv_notify_pid_ok ((pid_t) v, svc_pid))
                {
                  ns->main_pid = (pid_t) v;
                  bsv_writef (pidfile, "%ld\n", (long) v);
                  changed = 1;
                }
            }
          /* unknown keys ignored (sd_notify forward compatibility) */
        }
      if (changed && ns->state > 0)
        bsv_notify_publish (ns, status, transition);
    }
}

/* `sv notify KEY=VALUE ...` — sd_notify client half.  Sends one
   newline-joined datagram to $NOTIFY_SOCKET.  Supports the supervisor's
   abstract address (@...), a pathname AF_UNIX socket, and the shell
   fallback's FIFO (plain write). */
static int
bsv_notify_send (WORD_LIST *args)
{
  const char *sock = getenv ("NOTIFY_SOCKET");
  char msg[1024];
  size_t off = 0;
  WORD_LIST *p;
  struct stat sb;

  if (!sock || !*sock)
    {
      builtin_error ("notify: NOTIFY_SOCKET not set");
      return EXECUTION_FAILURE;
    }
  if (!args)
    {
      builtin_error ("notify needs KEY=VALUE ...");
      return EX_USAGE;
    }
  for (p = args; p; p = p->next)
    {
      size_t n = strlen (p->word->word);
      if (off + n + 1 >= sizeof msg)
        {
          builtin_error ("notify: message too long");
          return EXECUTION_FAILURE;
        }
      memcpy (msg + off, p->word->word, n);
      off += n;
      msg[off++] = '\n';
    }

  if (sock[0] == '@' ||
      (stat (sock, &sb) == 0 && S_ISSOCK (sb.st_mode)))
    {
      struct sockaddr_un addr;
      socklen_t alen;
      int fd;
      ssize_t rc;
      size_t pn = strlen (sock[0] == '@' ? sock + 1 : sock);
      memset (&addr, 0, sizeof addr);
      addr.sun_family = AF_UNIX;
      if (sock[0] == '@')
        {
          if (pn == 0 || pn >= sizeof addr.sun_path - 1)
            {
              builtin_error ("notify: bad NOTIFY_SOCKET");
              return EXECUTION_FAILURE;
            }
          memcpy (addr.sun_path + 1, sock + 1, pn);
          alen = (socklen_t) (offsetof (struct sockaddr_un, sun_path) + 1 + pn);
        }
      else
        {
          if (pn == 0 || pn >= sizeof addr.sun_path)
            {
              builtin_error ("notify: bad NOTIFY_SOCKET");
              return EXECUTION_FAILURE;
            }
          memcpy (addr.sun_path, sock, pn + 1);
          alen = (socklen_t) (offsetof (struct sockaddr_un, sun_path) + pn);
        }
      fd = socket (AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
      if (fd < 0)
        {
          builtin_error ("notify: socket: %s", strerror (errno));
          return EXECUTION_FAILURE;
        }
      rc = sendto (fd, msg, off, 0, (struct sockaddr *) &addr, alen);
      close (fd);
      if (rc < 0)
        {
          builtin_error ("notify: send: %s", strerror (errno));
          return EXECUTION_FAILURE;
        }
      return EXECUTION_SUCCESS;
    }

  /* shell-fallback FIFO (or plain file): O_NONBLOCK so a missing reader
     fails fast instead of blocking the service. */
  {
    int fd = open (sock, O_WRONLY | O_NONBLOCK);
    ssize_t rc;
    if (fd < 0)
      {
        builtin_error ("notify: open %s: %s", sock, strerror (errno));
        return EXECUTION_FAILURE;
      }
    rc = write (fd, msg, off);
    close (fd);
    if (rc < 0)
      {
        builtin_error ("notify: write: %s", strerror (errno));
        return EXECUTION_FAILURE;
      }
  }
  return EXECUTION_SUCCESS;
}

/* Returns 1 if the run script declares `# type: oneshot` in its leading
   comment block. s6-rc oneshot semantics: run the service to completion
   exactly once and never respawn, recording a terminal status. The default
   (`# type: longrun` or no directive) is the existing always-respawn behavior. */
static int
bsv_service_is_oneshot (const char *run_script)
{
  FILE *f = fopen (run_script, "r");
  if (!f) return 0;
  char line[256];
  int oneshot = 0;
  while (fgets (line, sizeof line, f))
    {
      char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      if (*p != '#') break;            /* end of the leading comment block */
      p++;
      while (*p == ' ' || *p == '\t') p++;
      if (strncmp (p, "type:", 5) == 0)
        {
          p += 5;
          while (*p == ' ' || *p == '\t') p++;
          if (strncmp (p, "oneshot", 7) == 0) oneshot = 1;
          break;
        }
    }
  fclose (f);
  return oneshot;
}

static int
bsv_service_name_is_oneshot (const char *name)
{
  char run_script[512];
  if (!bsv_service_exists (name, run_script, sizeof run_script))
    return 0;
  return bsv_service_is_oneshot (run_script);
}

static int
bsv_wait_oneshot_ok (const char *name)
{
  char p[512], buf[256];

  if (!bsv_service_name_is_oneshot (name))
    return EXECUTION_SUCCESS;
  if (bsv_path (p, sizeof p, bsv_run_dir, name, "status") < 0)
    return EXECUTION_FAILURE;

  /* 12000 * 0.1s = 1200s oneshot budget (raised 30 -> 60 -> 180 -> 300 -> 600 ->
     1200). The payload-autoinstall set installs in PARALLEL (run script), but a big
     set with python3 + perl (thousands of small files each) takes minutes; 1200s is
     generous margin. NOTE: a BAKED image (build_bashy_box.py --bake-payloads) has
     the set pre-installed in the initramfs, so payload-autoinstall is a no-op and
     this budget never applies — that is the way to avoid the per-boot install. */
  for (int i = 0; i < 12000; i++)
    {
      FILE *f = fopen (p, "r");
      buf[0] = '\0';
      if (f)
        {
          if (fgets (buf, sizeof buf, f))
            buf[strcspn (buf, "\r\n")] = '\0';
          fclose (f);
        }
      if (strcmp (buf, "oneshot-ok") == 0)
        return EXECUTION_SUCCESS;
      if (strncmp (buf, "oneshot-failed", 14) == 0)
        {
          builtin_error ("oneshot failed: %s", name);
          return EXECUTION_FAILURE;
        }
      usleep (100000);
    }

  builtin_error ("oneshot timed out: %s", name);
  return EXECUTION_FAILURE;
}

static int
bsv_wait_start_barrier (const char *name)
{
  char run_script[512], p[512], buf[256];
  struct bsv_readiness_policy ready;
  int wait_ticks;

  if (bsv_wait_oneshot_ok (name) != EXECUTION_SUCCESS)
    return EXECUTION_FAILURE;
  if (bsv_service_name_is_oneshot (name))
    return EXECUTION_SUCCESS;

  if (!bsv_service_exists (name, run_script, sizeof run_script))
    return EXECUTION_FAILURE;
  if (bsv_readiness_policy_for (name, run_script, &ready) < 0)
    return EXECUTION_FAILURE;
  if (!ready.enabled)
    return EXECUTION_SUCCESS;
  if (bsv_path (p, sizeof p, bsv_run_dir, name, "status") < 0)
    return EXECUTION_FAILURE;

  wait_ticks = (ready.timeout + 5) * 10;
  for (int i = 0; i < wait_ticks; i++)
    {
      FILE *f = fopen (p, "r");
      buf[0] = '\0';
      if (f)
        {
          if (fgets (buf, sizeof buf, f))
            buf[strcspn (buf, "\r\n")] = '\0';
          fclose (f);
        }
      if (strncmp (buf, "ready", 5) == 0)
        return EXECUTION_SUCCESS;
      if (strncmp (buf, "readiness-failed", 16) == 0)
        {
          builtin_error ("readiness failed: %s: %s", name, buf);
          return EXECUTION_FAILURE;
        }
      if (strncmp (buf, "exited", 6) == 0 ||
          strncmp (buf, "down", 4) == 0)
        {
          builtin_error ("readiness unavailable: %s: %s", name, buf);
          return EXECUTION_FAILURE;
        }
      usleep (100000);
    }

  builtin_error ("readiness timed out: %s", name);
  return EXECUTION_FAILURE;
}

static void
bsv_supervise (const char *name)
{
  char svdir[512], run_script[512], status[512], transition[512], pidfile[512], spidfile[512], down[512], logfile[512];
  char ns_flags[128], run_user[128], caps_drop[256];
  int backoff = 1;
  struct bsv_log_policy log_policy;
  struct bsv_restart_policy restart_policy;
  time_t restart_window_start = 0;
  int restart_window_count = 0;
  struct bsv_readiness_policy ready_policy;

  signal (SIGTERM, bsv_on_term);
  signal (SIGINT, bsv_on_term);
  signal (SIGHUP, SIG_IGN);
  /* The supervisor was forked from bash, which installs a SIGCHLD
     handler that opportunistically reaps children for job control.
     Inheriting that handler here breaks our waitpid(WNOHANG) loop:
     the service exit gets reaped by bash's handler running inside
     us, then waitpid returns -1/ECHILD and the inner loop never
     observes the exit. Reset to the kernel default so we own the
     reap path. */
  signal (SIGCHLD, SIG_DFL);

  if (!bsv_service_exists (name, run_script, sizeof run_script))
    _exit (111);
  bsv_path (svdir, sizeof svdir, bsv_run_dir, name, NULL);
  bsv_mkdir_p (svdir, 0755);
  bsv_path (status, sizeof status, bsv_run_dir, name, "status");
  bsv_path (transition, sizeof transition, bsv_run_dir, name, "transition");
  bsv_path (pidfile, sizeof pidfile, bsv_run_dir, name, "pid");
  bsv_path (spidfile, sizeof spidfile, bsv_run_dir, name, "super-pid");
  bsv_path (down, sizeof down, bsv_run_dir, name, "down");
  bsv_path (logfile, sizeof logfile, bsv_log_dir, name, NULL);
  unlink (down);
  bsv_writef (spidfile, "%ld\n", (long) getpid ());

  int oneshot = bsv_service_is_oneshot (run_script);

  while (!bsv_stop)
    {
      time_t started = time (NULL);
      if (bsv_parse_run_directives (run_script, ns_flags, sizeof ns_flags,
                                    run_user, sizeof run_user,
                                    caps_drop, sizeof caps_drop,
                                    &restart_policy) < 0)
        {
          bsv_writef (transition, "policy-error rc=2\n");
          bsv_writef (status, "policy-error rc=2\n");
          break;
        }
      if (bsv_readiness_policy_for (name, run_script, &ready_policy) < 0)
        {
          bsv_writef (transition, "exited rc=2\n");
          bsv_writef (status, "exited rc=2\n");
          sleep (backoff);
          if (backoff < 60) backoff *= 2;
          continue;
        }
      bsv_log_policy_for (name, &log_policy);

      /* notify mode: bind the per-service abstract dgram socket BEFORE the
         fork so the address exists when the child execs, and export its
         name through NOTIFY_SOCKET (SOCK_CLOEXEC keeps the fd ours). */
      int notify_mode = (!oneshot && ready_policy.mode == BSV_READY_NOTIFY);
      struct bsv_notify_state nstate;
      char notify_env[128];
      memset (&nstate, 0, sizeof nstate);
      nstate.fd = -1;
      notify_env[0] = '\0';
      if (notify_mode)
        {
          if (bsv_notify_bind (name, &nstate.fd) < 0)
            {
              bsv_writef (transition, "readiness-failed bind errno=%d\n",
                          errno);
              bsv_writef (status, "readiness-failed bind errno=%d\n", errno);
              bsv_log_notice (name, &log_policy,
                              "sv: readiness failed: notify bind: %s\n",
                              strerror (errno));
              sleep (backoff);
              if (backoff < 60) backoff *= 2;
              continue;
            }
          snprintf (notify_env, sizeof notify_env, "@sv/%s", name);
        }

      bsv_writef (transition, "starting\n");
      bsv_writef (status, "starting\n");
      int pipe_read = -1, log_fd = -1, line_start = 1;
      pid_t pid = bsv_fork_service_logged (name, run_script, ns_flags, run_user,
                                           caps_drop, logfile, &log_policy,
                                           notify_mode ? notify_env : NULL,
                                           &pipe_read, &log_fd);
      if (pid < 0)
        {
          bsv_writef (status, "failed fork errno=%d\n", errno);
          if (nstate.fd >= 0) { close (nstate.fd); nstate.fd = -1; }
          sleep (backoff);
          if (backoff < 60) backoff *= 2;
          continue;
        }
      bsv_writef (pidfile, "%ld\n", (long) pid);
      int st = 0;
      pid_t first = waitpid (pid, &st, WNOHANG);
      if (first == pid)
        {
          if (nstate.fd >= 0) { close (nstate.fd); nstate.fd = -1; }
          if (pipe_read >= 0)
            {
              bsv_drain_log_pipe_once (pipe_read, log_fd, &line_start);
              close (pipe_read);
              close (log_fd);
            }
          bsv_write_exit_status_pair (status, transition, st);
          bsv_run_finish (name, st, logfile);
          if (oneshot)
            {
              bsv_writef (transition, (WIFEXITED (st) && WEXITSTATUS (st) == 0)
                                      ? "oneshot-ok\n" : "oneshot-failed\n");
              bsv_writef (status, (WIFEXITED (st) && WEXITSTATUS (st) == 0)
                                    ? "oneshot-ok\n" : "oneshot-failed\n");
              break;
            }
          if (access (down, F_OK) == 0 || bsv_stop)
            {
              bsv_writef (transition, "down\n");
              bsv_writef (status, "down\n");
              break;
            }
          int restart_rc = bsv_restart_prepare (&restart_policy, st, status,
                                                transition,
                                                &restart_window_start,
                                                &restart_window_count);
          if (restart_rc <= 0)
            break;
          bsv_restart_sleep (&restart_policy, &backoff, started);
          continue;
        }
      if (first < 0 && errno == ECHILD)
        {
          if (nstate.fd >= 0) { close (nstate.fd); nstate.fd = -1; }
          if (pipe_read >= 0)
            {
              close (pipe_read);
              close (log_fd);
            }
          bsv_writef (transition, "exited wait-lost\n");
          bsv_writef (status, "exited wait-lost\n");
          bsv_restart_sleep (&restart_policy, &backoff, started);
          continue;
        }
      bsv_writef (transition, "running pid=%ld\n", (long) pid);
      bsv_writef (status, "running pid=%ld\n", (long) pid);
      if (!oneshot && (ready_policy.mode == BSV_READY_PROBE ||
                       ready_policy.mode == BSV_READY_COMMAND))
        bsv_run_readiness_probe (name, &ready_policy, pid, status, transition,
                                 logfile, &log_policy);
      time_t notify_deadline = 0;
      if (notify_mode)
        {
          nstate.main_pid = pid;
          bsv_writef (transition, "readiness-checking\n");
          notify_deadline = time (NULL) + ready_policy.timeout;
        }
      while (!bsv_stop)
        {
          if (pipe_read >= 0)
            bsv_drain_log_pipe_once (pipe_read, log_fd, &line_start);
          if (notify_mode && nstate.fd >= 0)
            {
              bsv_notify_drain (&nstate, pid, status, transition, pidfile);
              if (!nstate.got_ready && !nstate.failed &&
                  time (NULL) >= notify_deadline)
                {
                  /* fail closed for dependents, exactly like the probe
                     timeout; the service itself keeps running and the
                     watch ends (a late READY does not flip the verdict). */
                  nstate.failed = 1;
                  close (nstate.fd);
                  nstate.fd = -1;
                  bsv_writef (transition, "readiness-failed timeout\n");
                  bsv_writef (status, "readiness-failed timeout pid=%ld\n",
                              (long) pid);
                  bsv_log_notice (name, &log_policy,
                                  "sv: readiness failed: timeout after %d seconds\n",
                                  ready_policy.timeout);
                }
            }
          pid_t w = waitpid (pid, &st, WNOHANG);
          if (w == pid) break;
          if (access (down, F_OK) == 0) { kill (-pid, SIGTERM); kill (pid, SIGTERM); }
          usleep (100000);
        }
      if (bsv_stop) { kill (-pid, SIGTERM); kill (pid, SIGTERM); waitpid (pid, &st, 0); }
      if (nstate.fd >= 0) { close (nstate.fd); nstate.fd = -1; }
      if (pipe_read >= 0)
        {
          bsv_drain_log_pipe_once (pipe_read, log_fd, &line_start);
          close (pipe_read);
          close (log_fd);
        }

      bsv_write_exit_status_pair (status, transition, st);
      bsv_run_finish (name, st, logfile);

      if (oneshot)
        {
          bsv_writef (transition, (WIFEXITED (st) && WEXITSTATUS (st) == 0)
                                  ? "oneshot-ok\n" : "oneshot-failed\n");
          bsv_writef (status, (WIFEXITED (st) && WEXITSTATUS (st) == 0)
                                ? "oneshot-ok\n" : "oneshot-failed\n");
          break;
        }
      if (access (down, F_OK) == 0 || bsv_stop)
        {
          bsv_writef (transition, "down\n");
          bsv_writef (status, "down\n");
          break;
        }
      int restart_rc = bsv_restart_prepare (&restart_policy, st, status,
                                            transition, &restart_window_start,
                                            &restart_window_count);
      if (restart_rc <= 0)
        break;
      bsv_restart_sleep (&restart_policy, &backoff, started);
    }
  _exit (0);
}

static int
bsv_stale_pid_cleanup (const char *name)
{
  char p[512];
  pid_t pid;
  if (bsv_path (p, sizeof p, bsv_run_dir, name, "pid") < 0) return 0;
  if (bsv_read_pid (p, &pid) < 0) return 0;
  if (kill (pid, 0) == 0) return 0;
  if (errno == EPERM) return 0;       /* process exists but can't signal */
  printf ("sv: %s: cleaning stale pid %ld\n", name, (long) pid);
  unlink (p);                          /* remove stale pid file */
  bsv_path (p, sizeof p, bsv_run_dir, name, "super-pid");
  unlink (p);                          /* remove stale super-pid file */
  bsv_path (p, sizeof p, bsv_run_dir, name, "status");
  unlink (p);                          /* remove stale status file */
  return 1;
}

static int
bsv_signal_from_name (const char *name, int *sig)
{
  struct sigmap { const char *name; int sig; };
  static const struct sigmap signals[] = {
    { "TERM", SIGTERM }, { "KILL", SIGKILL }, { "HUP", SIGHUP },
    { "INT", SIGINT }, { "QUIT", SIGQUIT }, { "USR1", SIGUSR1 },
    { "USR2", SIGUSR2 }, { "ALRM", SIGALRM }, { "STOP", SIGSTOP },
    { "CONT", SIGCONT }
  };
  const char *p = name;
  if (!name || !*name)
    return -1;
  if (strncmp (p, "SIG", 3) == 0)
    p += 3;
  for (size_t i = 0; i < sizeof signals / sizeof signals[0]; i++)
    if (strcmp (p, signals[i].name) == 0)
      {
        *sig = signals[i].sig;
        return 0;
      }
  return -1;
}

static int
bsv_signal_service (const char *name, const char *sig_name)
{
  char p[512];
  pid_t pid;
  int sig;

  if (!bsv_valid_name (name)) { builtin_error ("bad service name"); return EX_USAGE; }
  if (bsv_signal_from_name (sig_name, &sig) < 0)
    { builtin_error ("bad signal: %s", sig_name ? sig_name : ""); return EX_USAGE; }
  if (bsv_path (p, sizeof p, bsv_run_dir, name, "pid") < 0 ||
      bsv_read_pid (p, &pid) < 0)
    { builtin_error ("%s: not running", name); return EXECUTION_FAILURE; }
  if (kill (pid, 0) < 0 && errno == ESRCH)
    { builtin_error ("%s: stale pid %ld", name, (long) pid); return EXECUTION_FAILURE; }
  if (kill (-pid, sig) < 0)
    {
      if (errno != ESRCH || kill (pid, sig) < 0)
        { builtin_error ("signal %s: %s", name, strerror (errno)); return EXECUTION_FAILURE; }
    }
  printf ("%s: signal %s\n", name, sig_name);
  return EXECUTION_SUCCESS;
}

static int
bsv_up (const char *name)
{
  char svdir[512], down[512];
  if (!bsv_service_exists (name, NULL, 0))
    { builtin_error ("no service: %s", name); return EXECUTION_FAILURE; }
  bsv_path (svdir, sizeof svdir, bsv_run_dir, name, NULL);
  bsv_mkdir_p (svdir, 0755);
  bsv_mkdir_p (bsv_log_dir, 0755);
  if (bsv_super_running (name))
    { printf ("%s: already up\n", name); return EXECUTION_SUCCESS; }
  /* s6-rc oneshot semantics: a oneshot that completed successfully is
     already up; a repeated `up` must stay terminal, not re-run it. An
     explicit `down` writes want=down, so down -> up (and `restart`)
     still re-executes the oneshot. */
  if (bsv_service_name_is_oneshot (name))
    {
      char sp[512], sbuf[64] = "", wbuf[64] = "";
      FILE *sf;
      if (bsv_path (sp, sizeof sp, bsv_run_dir, name, "status") == 0 &&
          (sf = fopen (sp, "r")) != NULL)
        {
          if (fgets (sbuf, sizeof sbuf, sf))
            sbuf[strcspn (sbuf, "\r\n")] = '\0';
          fclose (sf);
        }
      if (bsv_path (sp, sizeof sp, bsv_run_dir, name, "want") == 0 &&
          (sf = fopen (sp, "r")) != NULL)
        {
          if (fgets (wbuf, sizeof wbuf, sf))
            wbuf[strcspn (wbuf, "\r\n")] = '\0';
          fclose (sf);
        }
      if (strcmp (sbuf, "oneshot-ok") == 0 && strcmp (wbuf, "down") != 0)
        { printf ("%s: already up (oneshot-ok)\n", name); return EXECUTION_SUCCESS; }
    }
  bsv_path (down, sizeof down, bsv_run_dir, name, "down");
  unlink (down);
  if (bsv_path (down, sizeof down, bsv_run_dir, name, "want") == 0)
    bsv_writef (down, "up\n");

  bsv_stale_pid_cleanup (name);

  pid_t pid = fork ();
  if (pid < 0) { builtin_error ("fork: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (pid == 0)
    {
      int fd = open ("/dev/null", O_RDWR);
      if (fd >= 0)
        {
          dup2 (fd, STDIN_FILENO);
          dup2 (fd, STDOUT_FILENO);
          dup2 (fd, STDERR_FILENO);
          if (fd > STDERR_FILENO) close (fd);
        }
      bsv_supervise (name);
    }
  printf ("%s: up\n", name);
  return EXECUTION_SUCCESS;
}

static int
bsv_once (const char *name)
{
  char run_script[512], ns_flags[128], run_user[128], caps_drop[256];
  char svdir[512], logfile[512];
  struct bsv_log_policy log_policy;
  struct bsv_restart_policy restart_policy;

  if (!bsv_service_exists (name, run_script, sizeof run_script))
    {
      builtin_error ("no service: %s", name);
      return EXECUTION_FAILURE;
    }

  if (bsv_parse_run_directives (run_script, ns_flags, sizeof ns_flags,
                                run_user, sizeof run_user,
                                caps_drop, sizeof caps_drop,
                                &restart_policy) < 0)
    return EXECUTION_FAILURE;

  bsv_mkdir_p (bsv_log_dir, 0755);
  if (bsv_path (svdir, sizeof svdir, bsv_run_dir, name, NULL) == 0)
    bsv_mkdir_p (svdir, 0755);
  bsv_path (logfile, sizeof logfile, bsv_log_dir, name, NULL);
  bsv_log_policy_for (name, &log_policy);

  /* Reset and block SIGCHLD so bash's reaper doesn't race our waitpid. */
  {
    struct sigaction chld_dfl, chld_save;
    sigset_t chld_set, old_set;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &chld_save);
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    if (sigprocmask (SIG_BLOCK, &chld_set, &old_set) < 0)
      {
        sigaction (SIGCHLD, &chld_save, NULL);
        builtin_error ("sigprocmask: %s", strerror (errno));
        return EXECUTION_FAILURE;
      }

    int pipe_read = -1, log_fd = -1, line_start = 1;
    pid_t pid = bsv_fork_service_logged (name, run_script, ns_flags, run_user,
                                         caps_drop, logfile, &log_policy,
                                         NULL, &pipe_read, &log_fd);
    if (pid < 0)
      {
        sigprocmask (SIG_SETMASK, &old_set, NULL);
        sigaction (SIGCHLD, &chld_save, NULL);
        builtin_error ("fork: %s", strerror (errno));
        return EXECUTION_FAILURE;
      }

    int st = 0;
    pid_t w;
    while (1)
      {
        if (pipe_read >= 0)
          bsv_drain_log_pipe_once (pipe_read, log_fd, &line_start);
        w = waitpid (pid, &st, WNOHANG);
        if (w == pid || (w < 0 && errno != EINTR))
          break;
        usleep (100000);
      }
    if (pipe_read >= 0)
      {
        bsv_drain_log_pipe_once (pipe_read, log_fd, &line_start);
        close (pipe_read);
        close (log_fd);
      }

    if (w < 0)
      {
        sigprocmask (SIG_SETMASK, &old_set, NULL);
        sigaction (SIGCHLD, &chld_save, NULL);
        builtin_error ("waitpid: %s", strerror (errno));
        return EXECUTION_FAILURE;
      }

    if (WIFEXITED (st))
      {
        int rc = WEXITSTATUS (st);
        bsv_run_finish (name, st, logfile);
        sigprocmask (SIG_SETMASK, &old_set, NULL);
        sigaction (SIGCHLD, &chld_save, NULL);
        printf ("%s: exited rc=%d\n", name, rc);
        return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
      }
    else if (WIFSIGNALED (st))
      {
        bsv_run_finish (name, st, logfile);
        sigprocmask (SIG_SETMASK, &old_set, NULL);
        sigaction (SIGCHLD, &chld_save, NULL);
        printf ("%s: signal %d\n", name, WTERMSIG (st));
        return EXECUTION_FAILURE;
      }
    bsv_run_finish (name, st, logfile);
    sigprocmask (SIG_SETMASK, &old_set, NULL);
    sigaction (SIGCHLD, &chld_save, NULL);
    printf ("%s: exited\n", name);
    return EXECUTION_SUCCESS;
  }
}

static int
bsv_down (const char *name)
{
  char p[512];
  pid_t pid;
  if (!bsv_valid_name (name)) { builtin_error ("bad service name"); return EX_USAGE; }
  bsv_path (p, sizeof p, bsv_run_dir, name, NULL);
  bsv_mkdir_p (p, 0755);
  bsv_path (p, sizeof p, bsv_run_dir, name, "down");
  bsv_writef (p, "1\n");
  bsv_path (p, sizeof p, bsv_run_dir, name, "want");
  bsv_writef (p, "down\n");
  bsv_path (p, sizeof p, bsv_run_dir, name, "pid");
  if (bsv_read_pid (p, &pid) == 0) { kill (-pid, SIGTERM); kill (pid, SIGTERM); }
  printf ("%s: down\n", name);
  return EXECUTION_SUCCESS;
}

static int
bsv_status_one (const char *name)
{
  char p[512], buf[256] = "stopped", want[64] = "", transition[256] = "";
  FILE *f;
  bsv_path (p, sizeof p, bsv_run_dir, name, "status");
  f = fopen (p, "r");
  if (f)
    {
      if (!fgets (buf, sizeof buf, f)) strcpy (buf, "unknown");
      fclose (f);
      buf[strcspn (buf, "\r\n")] = '\0';
    }
  bsv_path (p, sizeof p, bsv_run_dir, name, "want");
  f = fopen (p, "r");
  if (f)
    {
      if (fgets (want, sizeof want, f))
        want[strcspn (want, "\r\n")] = '\0';
      fclose (f);
    }
  bsv_path (p, sizeof p, bsv_run_dir, name, "transition");
  f = fopen (p, "r");
  if (f)
    {
      if (fgets (transition, sizeof transition, f))
        transition[strcspn (transition, "\r\n")] = '\0';
      fclose (f);
    }
  printf ("%-20s %s", name, buf);
  if (want[0]) printf (" want=%s", want);
  if (transition[0]) printf (" transition=%s", transition);
  printf ("\n");
  return EXECUTION_SUCCESS;
}

static int
bsv_cmp_service_meta (const void *a, const void *b)
{
  const struct bsv_service_meta *sa = a;
  const struct bsv_service_meta *sb = b;
  return strcmp (sa->name, sb->name);
}

static int
bsv_find_service_meta (struct bsv_service_meta *svcs, int nsvcs,
                       const char *name)
{
  for (int i = 0; i < nsvcs; i++)
    if (strcmp (svcs[i].name, name) == 0)
      return i;
  return -1;
}

/* Fold each service's `before: X` directives into X's `after` list, so the
   topological sort treats "S before X" identically to "X after S". Best-effort:
   a before-target that is absent or whose `after` list is already full is
   skipped silently (matching the soft semantics of `after`). */
static void
bsv_resolve_before_edges (struct bsv_service_meta *svcs, int nsvcs)
{
  for (int i = 0; i < nsvcs; i++)
    for (int j = 0; j < svcs[i].nbefore; j++)
      {
        int t = bsv_find_service_meta (svcs, nsvcs, svcs[i].before[j]);
        if (t < 0)
          continue;
        /* add svcs[i].name to svcs[t].after (dedup + bounds inside) */
        for (int k = 0; k < svcs[t].nafter; k++)
          if (strcmp (svcs[t].after[k], svcs[i].name) == 0)
            goto next;
        if (svcs[t].nafter < BSV_DEPS_MAX)
          {
            strcpy (svcs[t].after[svcs[t].nafter], svcs[i].name);
            svcs[t].nafter++;
          }
      next: ;
      }
}

static int
bsv_collect_services (struct bsv_service_meta *svcs, int *nsvcs, int parse_deps)
{
  DIR *d = opendir (bsv_sv_dir);
  if (!d)
    return EXECUTION_SUCCESS;
  struct dirent *de;
  int rc = EXECUTION_SUCCESS;
  *nsvcs = 0;
  while ((de = readdir (d)) != NULL)
    {
      char run[512], disabled[512];
      if (de->d_name[0] == '.') continue;
      if (!bsv_valid_name (de->d_name)) continue;
      if (bsv_path (run, sizeof run, bsv_sv_dir, de->d_name, "run") < 0)
        continue;
      if (access (run, X_OK) != 0)
        continue;
      if (*nsvcs >= BSV_SERVICE_MAX)
        {
          builtin_error ("too many services in %s", bsv_sv_dir);
          rc = EXECUTION_FAILURE;
          break;
        }
      struct bsv_service_meta *m = &svcs[*nsvcs];
      memset (m, 0, sizeof *m);
      strcpy (m->name, de->d_name);
      m->type = BSV_TYPE_LONGRUN;
      bsv_path (disabled, sizeof disabled, bsv_sv_dir, de->d_name, "disabled");
      m->disabled = access (disabled, F_OK) == 0;
      if (parse_deps && bsv_parse_service_deps (run, m) < 0)
        {
          rc = EXECUTION_FAILURE;
          break;
        }
      (*nsvcs)++;
    }
  closedir (d);
  if (rc == EXECUTION_SUCCESS)
    {
      qsort (svcs, (size_t) *nsvcs, sizeof svcs[0], bsv_cmp_service_meta);
      if (parse_deps)
        bsv_resolve_before_edges (svcs, *nsvcs);
    }
  return rc;
}

static int
bsv_visit_ordered_service (struct bsv_service_meta *svcs, int nsvcs, int idx,
                           unsigned char *state, const char **stack,
                           int depth, const char **ordered, int *nordered);

static int
bsv_mark_target_rec (const char *name, struct bsv_service_meta *svcs, int nsvcs,
                     unsigned char *selected, const char **stack, int depth)
{
  char contents[512], member[128];
  if (!bsv_valid_name (name))
    {
      builtin_error ("bad service name: %s", name ? name : "");
      return EXECUTION_FAILURE;
    }
  for (int i = 0; i < depth; i++)
    if (strcmp (stack[i], name) == 0)
      {
        builtin_error ("bundle cycle at %s", name);
        return EXECUTION_FAILURE;
      }
  if (!bsv_service_is_bundle_name (name))
    {
      int idx = bsv_find_service_meta (svcs, nsvcs, name);
      if (idx < 0)
        {
          builtin_error ("no service: %s", name);
          return EXECUTION_FAILURE;
        }
      if (!svcs[idx].disabled)
        selected[idx] = 1;
      return EXECUTION_SUCCESS;
    }

  if (bsv_path (contents, sizeof contents, bsv_sv_dir, name, "contents") < 0)
    {
      builtin_error ("bundle path too long: %s", name);
      return EXECUTION_FAILURE;
    }
  FILE *f = fopen (contents, "r");
  if (!f)
    {
      builtin_error ("bundle has no contents: %s", name);
      return EXECUTION_FAILURE;
    }
  stack[depth++] = name;
  int rc = EXECUTION_SUCCESS;
  while (fscanf (f, "%127s", member) == 1)
    {
      if (member[0] == '#')
        {
          int ch;
          while ((ch = fgetc (f)) != EOF && ch != '\n')
            ;
          continue;
        }
      if (!bsv_valid_name (member))
        {
          builtin_error ("invalid bundle member in %s", name);
          rc = EXECUTION_FAILURE;
          break;
        }
      if (bsv_mark_target_rec (member, svcs, nsvcs, selected, stack, depth)
          != EXECUTION_SUCCESS)
        {
          rc = EXECUTION_FAILURE;
          break;
        }
    }
  fclose (f);
  return rc;
}

static int
bsv_order_selected_target (const char *name, struct bsv_service_meta *svcs,
                           int *nsvcs, const char **ordered, int *nordered,
                           unsigned char *selected)
{
  const char *stack[BSV_SERVICE_MAX];
  unsigned char state[BSV_SERVICE_MAX];
  if (bsv_collect_services (svcs, nsvcs, 1) != EXECUTION_SUCCESS)
    return EXECUTION_FAILURE;
  memset (selected, 0, BSV_SERVICE_MAX);
  memset (state, 0, BSV_SERVICE_MAX);
  *nordered = 0;
  if (bsv_mark_target_rec (name, svcs, *nsvcs, selected, stack, 0)
      != EXECUTION_SUCCESS)
    return EXECUTION_FAILURE;
  for (int i = 0; i < *nsvcs; i++)
    if (selected[i] &&
        bsv_visit_ordered_service (svcs, *nsvcs, i, state, stack, 0,
                                   ordered, nordered) != EXECUTION_SUCCESS)
      return EXECUTION_FAILURE;
  return EXECUTION_SUCCESS;
}

static int
bsv_up_target (const char *name)
{
  if (!bsv_service_is_bundle_name (name))
    return bsv_up (name);
  struct bsv_service_meta svcs[BSV_SERVICE_MAX];
  const char *ordered[BSV_SERVICE_MAX];
  unsigned char selected[BSV_SERVICE_MAX];
  int nsvcs = 0, nordered = 0;
  if (bsv_order_selected_target (name, svcs, &nsvcs, ordered, &nordered,
                                 selected) != EXECUTION_SUCCESS)
    return EXECUTION_FAILURE;
  for (int i = 0; i < nordered; i++)
    {
      if (bsv_up (ordered[i]) != EXECUTION_SUCCESS ||
          bsv_wait_start_barrier (ordered[i]) != EXECUTION_SUCCESS)
        return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
bsv_down_target (const char *name)
{
  if (!bsv_service_is_bundle_name (name))
    return bsv_down (name);
  struct bsv_service_meta svcs[BSV_SERVICE_MAX];
  const char *ordered[BSV_SERVICE_MAX];
  unsigned char selected[BSV_SERVICE_MAX];
  int nsvcs = 0, nordered = 0;
  if (bsv_order_selected_target (name, svcs, &nsvcs, ordered, &nordered,
                                 selected) != EXECUTION_SUCCESS)
    return EXECUTION_FAILURE;
  for (int i = nordered - 1; i >= 0; i--)
    bsv_down (ordered[i]);
  return EXECUTION_SUCCESS;
}

static int
bsv_status_target (const char *name)
{
  if (!bsv_service_is_bundle_name (name))
    return bsv_status_one (name);
  struct bsv_service_meta svcs[BSV_SERVICE_MAX];
  const char *ordered[BSV_SERVICE_MAX];
  unsigned char selected[BSV_SERVICE_MAX];
  int nsvcs = 0, nordered = 0;
  if (bsv_order_selected_target (name, svcs, &nsvcs, ordered, &nordered,
                                 selected) != EXECUTION_SUCCESS)
    return EXECUTION_FAILURE;
  for (int i = 0; i < nordered; i++)
    bsv_status_one (ordered[i]);
  return EXECUTION_SUCCESS;
}

static int
bsv_visit_ordered_service (struct bsv_service_meta *svcs, int nsvcs, int idx,
                           unsigned char *state, const char **stack,
                           int depth, const char **ordered, int *nordered)
{
  if (state[idx] == 2)
    return EXECUTION_SUCCESS;
  if (state[idx] == 1)
    {
      fprintf (stderr, "sv: dependency cycle:");
      int start = 0;
      for (int i = depth - 1; i >= 0; i--)
        if (strcmp (stack[i], svcs[idx].name) == 0)
          { start = i; break; }
      for (int i = start; i < depth; i++)
        fprintf (stderr, " %s ->", stack[i]);
      fprintf (stderr, " %s\n", svcs[idx].name);
      return EXECUTION_FAILURE;
    }
  state[idx] = 1;
  stack[depth++] = svcs[idx].name;

  for (int pass = 0; pass < 2; pass++)
    {
      int ndeps = pass == 0 ? svcs[idx].nrequires : svcs[idx].nafter;
      for (int i = 0; i < ndeps; i++)
        {
          const char *dep = pass == 0 ? svcs[idx].requires[i] : svcs[idx].after[i];
          int dep_idx = bsv_find_service_meta (svcs, nsvcs, dep);
          if (dep_idx < 0 || svcs[dep_idx].disabled)
            {
              if (pass == 0)
                {
                  fprintf (stderr, "sv: %s requires missing service: %s\n",
                           svcs[idx].name, dep);
                  return EXECUTION_FAILURE;
                }
              continue;
            }
          if (bsv_visit_ordered_service (svcs, nsvcs, dep_idx, state, stack,
                                         depth, ordered, nordered) != EXECUTION_SUCCESS)
            return EXECUTION_FAILURE;
        }
    }

  state[idx] = 2;
  ordered[(*nordered)++] = svcs[idx].name;
  return EXECUTION_SUCCESS;
}

static int
bsv_start_enabled_ordered (void)
{
  struct bsv_service_meta svcs[BSV_SERVICE_MAX];
  unsigned char state[BSV_SERVICE_MAX];
  const char *stack[BSV_SERVICE_MAX];
  const char *ordered[BSV_SERVICE_MAX];
  int nsvcs = 0, nordered = 0;

  if (bsv_collect_services (svcs, &nsvcs, 1) != EXECUTION_SUCCESS)
    return EXECUTION_FAILURE;
  memset (state, 0, sizeof state);

  for (int i = 0; i < nsvcs; i++)
    {
      if (svcs[i].disabled)
        {
          printf ("%s: disabled (skipped)\n", svcs[i].name);
          state[i] = 2;
          continue;
        }
      if (bsv_visit_ordered_service (svcs, nsvcs, i, state, stack, 0,
                                     ordered, &nordered) != EXECUTION_SUCCESS)
        return EXECUTION_FAILURE;
    }

  for (int i = 0; i < nordered; i++)
    {
      if (bsv_up (ordered[i]) != EXECUTION_SUCCESS ||
          bsv_wait_start_barrier (ordered[i]) != EXECUTION_SUCCESS)
        return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

/* Shutdown counterpart of bsv_start_enabled_ordered: stop services in REVERSE
   dependency order so a dependent is always torn down before the service it
   depends on. Best-effort — if the dependency graph cannot be ordered (cycle
   or a missing hard `requires`), fall back to downing every service unordered
   so shutdown never wedges. Disabled services are downed last (order among
   them is irrelevant; they carry no graph edges that were honored at boot). */
/* Bounded wait for a service's supervisor to actually exit. During an ordered
   shutdown this keeps a dependency alive until its dependent is fully down,
   so the reverse-order guarantee is real (and observable by finish hooks),
   not just the order in which SIGTERM was delivered. ~5s ceiling. */
static void
bsv_wait_stopped (const char *name)
{
  for (int i = 0; i < 100; i++)
    {
      if (!bsv_super_running (name))
        return;
      usleep (50000);
    }
}

static int
bsv_stop_enabled_ordered (void)
{
  struct bsv_service_meta svcs[BSV_SERVICE_MAX];
  unsigned char state[BSV_SERVICE_MAX];
  const char *stack[BSV_SERVICE_MAX];
  const char *ordered[BSV_SERVICE_MAX];
  int nsvcs = 0, nordered = 0;

  if (bsv_collect_services (svcs, &nsvcs, 1) != EXECUTION_SUCCESS)
    return EXECUTION_FAILURE;
  memset (state, 0, sizeof state);

  for (int i = 0; i < nsvcs; i++)
    {
      if (svcs[i].disabled)
        {
          state[i] = 2;
          continue;
        }
      if (bsv_visit_ordered_service (svcs, nsvcs, i, state, stack, 0,
                                     ordered, &nordered) != EXECUTION_SUCCESS)
        {
          /* Graph is unorderable — fall back to downing everything. */
          fprintf (stderr, "sv: shutdown ordering unavailable; "
                   "stopping all services unordered\n");
          for (int k = 0; k < nsvcs; k++)
            bsv_down (svcs[k].name);
          return EXECUTION_SUCCESS;
        }
    }

  /* Enabled services in reverse dependency order: dependents first, waiting
     for each to fully stop before tearing down the service it depends on. */
  for (int i = nordered - 1; i >= 0; i--)
    {
      bsv_down (ordered[i]);
      bsv_wait_stopped (ordered[i]);
    }
  /* Then any disabled services (excluded from the ordered set above). */
  for (int i = 0; i < nsvcs; i++)
    if (svcs[i].disabled)
      bsv_down (svcs[i].name);
  return EXECUTION_SUCCESS;
}

static int
bsv_each_service (int (*fn)(const char *), int skip_disabled)
{
  struct bsv_service_meta svcs[BSV_SERVICE_MAX];
  int nsvcs = 0;

  if (bsv_collect_services (svcs, &nsvcs, 0) != EXECUTION_SUCCESS)
    return EXECUTION_FAILURE;
  for (int i = 0; i < nsvcs; i++)
    {
      if (skip_disabled)
        {
          if (svcs[i].disabled)
            { printf ("%s: disabled (skipped)\n", svcs[i].name); continue; }
        }
      fn (svcs[i].name);
    }
  return EXECUTION_SUCCESS;
}

static int
bsv_run_foreground (void)
{
  signal (SIGTERM, bsv_on_term);
  signal (SIGINT, bsv_on_term);
  if (bsv_start_enabled_ordered () != EXECUTION_SUCCESS)
    return EXECUTION_FAILURE;
  while (!bsv_stop)
    {
      char p[512];
      snprintf (p, sizeof p, "%s/shutdown", bsv_run_dir);
      if (access (p, F_OK) == 0) break;
      sleep (1);
    }
  bsv_stop_enabled_ordered ();
  return EXECUTION_SUCCESS;
}

static int
bsv_log (const char *name, int nlines)
{
  char p[512];
  FILE *f;
  char **ring = NULL;
  int idx = 0, count = 0;
  if (!bsv_valid_name (name)) { builtin_error ("bad service name"); return EX_USAGE; }
  if (nlines < 1) nlines = 20;
  ring = calloc ((size_t) nlines, sizeof *ring);
  if (!ring) return EXECUTION_FAILURE;
  bsv_path (p, sizeof p, bsv_log_dir, name, NULL);
  f = fopen (p, "r");
  if (!f) { free (ring); return EXECUTION_FAILURE; }
  char line[512];
  while (fgets (line, sizeof line, f))
    {
      free (ring[idx]);
      ring[idx] = strdup (line);
      idx = (idx + 1) % nlines;
      if (count < nlines) count++;
    }
  fclose (f);
  /* Earliest entry is at idx - count (mod nlines): when the buffer
     hasn't wrapped (count < nlines) that's plain 0; once it wraps
     it's idx (the next-write slot, which holds the oldest entry).
     The naive `(idx + i) % nlines` is only correct when count ==
     nlines and emits zero output for short logs. */
  int start = (idx - count + nlines) % nlines;
  for (int i = 0; i < count; i++)
    {
      int j = (start + i) % nlines;
      if (ring[j]) fputs (ring[j], stdout);
      free (ring[j]);
    }
  free (ring);
  return EXECUTION_SUCCESS;
}

static const char *
bsv_cron_root (void)
{
  const char *s = getenv ("BASHCRON_SPOOL_DIR");
  return (s && *s) ? s : "/var/spool/cron";
}

static int
bsv_safe_tab_user (const char *s)
{
  if (!s || !*s || strlen (s) > 96)
    return 0;
  for (; *s; s++)
    if (!(('A' <= *s && *s <= 'Z') || ('a' <= *s && *s <= 'z') ||
          ('0' <= *s && *s <= '9') || *s == '_' || *s == '-' || *s == '.'))
      return 0;
  return 1;
}

static const char *
bsv_timer_user (char *buf, size_t bufsz)
{
  const char *u = getenv ("USER");
  if (bsv_safe_tab_user (u))
    return u;
  struct passwd *pw = getpwuid (getuid ());
  if (pw && bsv_safe_tab_user (pw->pw_name))
    return pw->pw_name;
  snprintf (buf, bufsz, "uid%ld", (long) getuid ());
  return buf;
}

static size_t
bsv_shell_quote_append (char *dst, size_t cap, size_t pos, const char *s)
{
  if (pos + 1 >= cap)
    return cap;
  dst[pos++] = '\'';
  for (; s && *s && pos + 4 < cap; s++)
    {
      if (*s == '\'')
        {
          dst[pos++] = '\'';
          dst[pos++] = '\\';
          dst[pos++] = '\'';
          dst[pos++] = '\'';
        }
      else
        dst[pos++] = *s;
    }
  if (pos + 1 >= cap)
    return cap;
  dst[pos++] = '\'';
  dst[pos] = '\0';
  return pos;
}

static int
bsv_timer_field_count (const char *s)
{
  int fields = 0;
  while (s && *s)
    {
      while (isspace ((unsigned char) *s))
        s++;
      if (!*s)
        break;
      fields++;
      while (*s && !isspace ((unsigned char) *s))
        s++;
    }
  return fields;
}

static int
bsv_timer_collect_schedule (WORD_LIST *list, char *out, size_t out_sz)
{
  size_t pos = 0;
  out[0] = '\0';
  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      size_t n = strlen (w);
      if (pos && pos + 1 < out_sz)
        out[pos++] = ' ';
      if (pos + n >= out_sz)
        return -1;
      memcpy (out + pos, w, n);
      pos += n;
      out[pos] = '\0';
    }
  return bsv_timer_field_count (out) == 5 ? 0 : -1;
}

static int
bsv_timer_build_command (char *out, size_t out_sz, const char *name)
{
  const char *envs[][2] = {
    { "BASHSV_DIR", bsv_sv_dir },
    { "BASHSV_RUNDIR", bsv_run_dir },
    { "BASHSV_LOGDIR", bsv_log_dir },
    { "BASHSV_LOG_MAX_BYTES", getenv ("BASHSV_LOG_MAX_BYTES") },
    { "BASHSV_LOG_GENERATIONS", getenv ("BASHSV_LOG_GENERATIONS") },
  };
  size_t pos = 0;
  out[0] = '\0';

  for (size_t i = 0; i < sizeof envs / sizeof envs[0]; i++)
    {
      if (!envs[i][1] || !*envs[i][1])
        continue;
      int n = snprintf (out + pos, pos < out_sz ? out_sz - pos : 0,
                        "%s=", envs[i][0]);
      if (n < 0 || pos + (size_t) n >= out_sz)
        return -1;
      pos += (size_t) n;
      pos = bsv_shell_quote_append (out, out_sz, pos, envs[i][1]);
      if (pos + 1 >= out_sz)
        return -1;
      out[pos++] = ' ';
      out[pos] = '\0';
    }

  int n = snprintf (out + pos, pos < out_sz ? out_sz - pos : 0,
                    "sv once ");
  if (n < 0 || pos + (size_t) n >= out_sz)
    return -1;
  pos += (size_t) n;
  pos = bsv_shell_quote_append (out, out_sz, pos, name);
  return pos < out_sz ? 0 : -1;
}

static int
bsv_timer_write_tab (const char *name, const char *schedule, int cancel)
{
  char tabs[512], tab[640], tmp[704], userbuf[64], begin[160], end[160], cmd[1024];
  const char *user = bsv_timer_user (userbuf, sizeof userbuf);
  const char *root = bsv_cron_root ();
  FILE *in = NULL, *out = NULL;
  char line[4096];
  int skipping = 0;
  int rc = EXECUTION_FAILURE;

  if (snprintf (tabs, sizeof tabs, "%s/tabs", root) >= (int) sizeof tabs ||
      snprintf (tab, sizeof tab, "%s/%s", tabs, user) >= (int) sizeof tab ||
      snprintf (tmp, sizeof tmp, "%s.tmp.%ld", tab, (long) getpid ()) >= (int) sizeof tmp ||
      snprintf (begin, sizeof begin, "# sv-timer %s begin\n", name) >= (int) sizeof begin ||
      snprintf (end, sizeof end, "# sv-timer %s end\n", name) >= (int) sizeof end)
    {
      builtin_error ("timer path too long");
      return EXECUTION_FAILURE;
    }
  if (!cancel && bsv_timer_build_command (cmd, sizeof cmd, name) < 0)
    {
      builtin_error ("timer command too long");
      return EXECUTION_FAILURE;
    }
  if (bsv_mkdir_p (tabs, 0700) < 0)
    {
      builtin_error ("timer mkdir: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }

  in = fopen (tab, "r");
  out = fopen (tmp, "w");
  if (!out)
    {
      builtin_error ("timer create: %s", strerror (errno));
      if (in)
        fclose (in);
      return EXECUTION_FAILURE;
    }

  if (in)
    {
      while (fgets (line, sizeof line, in))
        {
          if (strcmp (line, begin) == 0)
            {
              skipping = 1;
              continue;
            }
          if (skipping)
            {
              if (strcmp (line, end) == 0)
                skipping = 0;
              continue;
            }
          fputs (line, out);
        }
      fclose (in);
    }

  if (!cancel)
    {
      fprintf (out, "%s", begin);
      fprintf (out, "%s %s\n", schedule, cmd);
      fprintf (out, "%s", end);
    }

  if (fclose (out) != 0)
    {
      builtin_error ("timer write: %s", strerror (errno));
      unlink (tmp);
      return EXECUTION_FAILURE;
    }
  chmod (tmp, 0600);
  if (rename (tmp, tab) < 0)
    {
      builtin_error ("timer install: %s", strerror (errno));
      unlink (tmp);
      return EXECUTION_FAILURE;
    }

  printf ("%s %s\n", cancel ? "cancelled" : "installed", name);
  rc = EXECUTION_SUCCESS;
  return rc;
}

static int
bsv_timer (const char *name, WORD_LIST *args)
{
  if (!bsv_valid_name (name))
    {
      builtin_error ("bad service name");
      return EX_USAGE;
    }
  if (!args)
    {
      builtin_error ("timer needs NAME -- SCHEDULE or NAME --cancel");
      return EX_USAGE;
    }
  if (strcmp (args->word->word, "--cancel") == 0)
    {
      if (args->next)
        {
          builtin_error ("timer --cancel takes no schedule");
          return EX_USAGE;
        }
      return bsv_timer_write_tab (name, NULL, 1);
    }
  if (strcmp (args->word->word, "--") != 0)
    {
      builtin_error ("timer needs -- before SCHEDULE");
      return EX_USAGE;
    }
  char schedule[256];
  if (!args->next ||
      bsv_timer_collect_schedule (args->next, schedule, sizeof schedule) < 0)
    {
      builtin_error ("timer schedule must be five cron fields");
      return EX_USAGE;
    }
  return bsv_timer_write_tab (name, schedule, 0);
}

static int
bsv_clear_cloexec (int fd)
{
  int flags = fcntl (fd, F_GETFD, 0);
  if (flags < 0)
    return -1;
  return fcntl (fd, F_SETFD, flags & ~FD_CLOEXEC);
}

static void bsv_execve_with_listen_env (const char *run_script, const char *name);

static int
bsv_once_with_listen_fd (const char *name, int listen_fd)
{
  char run_script[512], ns_flags[128], run_user[128], caps_drop[256];
  char svdir[512], logfile[512];
  struct bsv_log_policy log_policy;
  struct bsv_restart_policy restart_policy;

  if (!bsv_service_exists (name, run_script, sizeof run_script))
    {
      builtin_error ("no service: %s", name);
      return EXECUTION_FAILURE;
    }

  if (bsv_parse_run_directives (run_script, ns_flags, sizeof ns_flags,
                                run_user, sizeof run_user,
                                caps_drop, sizeof caps_drop,
                                &restart_policy) < 0)
    return EXECUTION_FAILURE;

  bsv_mkdir_p (bsv_log_dir, 0755);
  if (bsv_path (svdir, sizeof svdir, bsv_run_dir, name, NULL) == 0)
    bsv_mkdir_p (svdir, 0755);
  bsv_path (logfile, sizeof logfile, bsv_log_dir, name, NULL);
  bsv_log_policy_for (name, &log_policy);

  struct sigaction chld_dfl, chld_save;
  sigset_t chld_set, old_set;
  memset (&chld_dfl, 0, sizeof chld_dfl);
  chld_dfl.sa_handler = SIG_DFL;
  sigemptyset (&chld_dfl.sa_mask);
  sigaction (SIGCHLD, &chld_dfl, &chld_save);
  sigemptyset (&chld_set);
  sigaddset (&chld_set, SIGCHLD);
  if (sigprocmask (SIG_BLOCK, &chld_set, &old_set) < 0)
    {
      sigaction (SIGCHLD, &chld_save, NULL);
      builtin_error ("sigprocmask: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }

  pid_t pid = fork ();
  if (pid < 0)
    {
      sigprocmask (SIG_SETMASK, &old_set, NULL);
      sigaction (SIGCHLD, &chld_save, NULL);
      builtin_error ("fork: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }

  if (pid == 0)
    {
      sigprocmask (SIG_SETMASK, &old_set, NULL);
      int fd = bsv_open_log (logfile, &log_policy);
      if (fd >= 0)
        {
          dup2 (fd, STDOUT_FILENO);
          dup2 (fd, STDERR_FILENO);
          if (fd > STDERR_FILENO && fd != listen_fd) close (fd);
        }
      if (listen_fd != 3)
        {
          dup2 (listen_fd, 3);
          close (listen_fd);
        }
      bsv_clear_cloexec (3);
      {
        char pidbuf[32];
        snprintf (pidbuf, sizeof pidbuf, "%ld", (long) getpid ());
        setenv ("SV_NAME", name, 1);
        setenv ("LISTEN_FDS", "1", 1);
        setenv ("LISTEN_PID", pidbuf, 1);
        setenv ("LISTEN_FDNAMES", name, 1);
      }
      bsv_listen_activation = 1;
      setpgid (0, 0);
      if (!ns_flags[0] && !run_user[0] && !caps_drop[0])
        bsv_execve_with_listen_env (run_script, name);
      bsv_exec_service (name, run_script, ns_flags, run_user, caps_drop, NULL);
    }

  int st = 0;
  pid_t w;
  while ((w = waitpid (pid, &st, 0)) < 0 && errno == EINTR)
    ;
  sigprocmask (SIG_SETMASK, &old_set, NULL);
  sigaction (SIGCHLD, &chld_save, NULL);
  if (w < 0)
    {
      builtin_error ("waitpid: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  bsv_run_finish (name, st, logfile);
  if (WIFEXITED (st))
    return WEXITSTATUS (st) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  return EXECUTION_FAILURE;
}

extern char **environ;

static void
bsv_execve_with_listen_env (const char *run_script, const char *name)
{
  size_t nenv = 0, out = 0;
  char pidbuf[32], svbuf[160], pidenv[64], nameenv[160];
  char *argv[2];
  char **envp;

  while (environ && environ[nenv])
    nenv++;
  envp = calloc (nenv + 5, sizeof *envp);
  if (!envp)
    _exit (127);

  for (size_t i = 0; i < nenv; i++)
    {
      if (strncmp (environ[i], "SV_NAME=", 8) == 0 ||
          strncmp (environ[i], "LISTEN_FDS=", 11) == 0 ||
          strncmp (environ[i], "LISTEN_PID=", 11) == 0 ||
          strncmp (environ[i], "LISTEN_FDNAMES=", 15) == 0)
        continue;
      envp[out++] = environ[i];
    }

  snprintf (pidbuf, sizeof pidbuf, "%ld", (long) getpid ());
  snprintf (svbuf, sizeof svbuf, "SV_NAME=%s", name);
  snprintf (pidenv, sizeof pidenv, "LISTEN_PID=%s", pidbuf);
  snprintf (nameenv, sizeof nameenv, "LISTEN_FDNAMES=%s", name);
  envp[out++] = svbuf;
  envp[out++] = "LISTEN_FDS=1";
  envp[out++] = pidenv;
  envp[out++] = nameenv;
  envp[out] = NULL;

  argv[0] = (char *) run_script;
  argv[1] = NULL;
  execve (run_script, argv, envp);
  fprintf (stderr, "sv: exec %s: %s\n", run_script, strerror (errno));
  _exit (127);
}

static int
bsv_open_listener (const char *spec, char *bound, size_t bound_sz)
{
  char host[256], port[32];
  const char *colon = strrchr (spec ? spec : "", ':');
  if (!colon || colon == spec || !colon[1] ||
      (size_t) (colon - spec) >= sizeof host || strlen (colon + 1) >= sizeof port)
    {
      builtin_error ("socket address must be ADDR:PORT");
      return -1;
    }
  memcpy (host, spec, (size_t) (colon - spec));
  host[colon - spec] = '\0';
  strcpy (port, colon + 1);

  struct addrinfo hints, *res = NULL, *rp;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICSERV;
  int gai = getaddrinfo (host, port, &hints, &res);
  if (gai != 0)
    {
      builtin_error ("getaddrinfo %s: %s", spec, gai_strerror (gai));
      return -1;
    }

  int fd = -1;
  for (rp = res; rp; rp = rp->ai_next)
    {
      fd = socket (rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
      if (fd < 0)
        continue;
      int one = 1;
      setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
      if (bind (fd, rp->ai_addr, rp->ai_addrlen) == 0 && listen (fd, 16) == 0)
        break;
      close (fd);
      fd = -1;
    }
  freeaddrinfo (res);
  if (fd < 0)
    {
      builtin_error ("socket listen %s: %s", spec, strerror (errno));
      return -1;
    }

  struct sockaddr_storage ss;
  socklen_t sl = sizeof ss;
  if (getsockname (fd, (struct sockaddr *) &ss, &sl) == 0)
    {
      char h[NI_MAXHOST], p[NI_MAXSERV];
      if (getnameinfo ((struct sockaddr *) &ss, sl, h, sizeof h, p, sizeof p,
                       NI_NUMERICHOST | NI_NUMERICSERV) == 0)
        snprintf (bound, bound_sz, "%s:%s", h, p);
      else
        snprintf (bound, bound_sz, "%s", spec);
    }
  else
    snprintf (bound, bound_sz, "%s", spec);
  return fd;
}

static int
bsv_socket_activate (const char *name, WORD_LIST *args)
{
  int once = 0;
  if (!bsv_valid_name (name))
    {
      builtin_error ("bad service name");
      return EX_USAGE;
    }
  if (!args || strcmp (args->word->word, "--") != 0 || !args->next)
    {
      builtin_error ("socket needs NAME -- ADDR:PORT [--once]");
      return EX_USAGE;
    }
  const char *spec = args->next->word->word;
  for (WORD_LIST *p = args->next->next; p; p = p->next)
    {
      if (strcmp (p->word->word, "--once") == 0)
        once = 1;
      else
        {
          builtin_error ("socket: unknown arg %s", p->word->word);
          return EX_USAGE;
        }
    }
  if (!bsv_service_exists (name, NULL, 0))
    {
      builtin_error ("no service: %s", name);
      return EXECUTION_FAILURE;
    }

  char bound[320];
  int fd = bsv_open_listener (spec, bound, sizeof bound);
  if (fd < 0)
    return EXECUTION_FAILURE;
  signal (SIGTERM, bsv_on_term);
  signal (SIGINT, bsv_on_term);
  printf ("listening %s %s\n", name, bound);
  fflush (stdout);

  int rc = EXECUTION_SUCCESS;
  while (!bsv_stop)
    {
      struct pollfd pfd = { .fd = fd, .events = POLLIN };
      int pr = poll (&pfd, 1, 1000);
      if (pr < 0)
        {
          if (errno == EINTR)
            continue;
          builtin_error ("socket poll: %s", strerror (errno));
          rc = EXECUTION_FAILURE;
          break;
        }
      if (pr == 0 || !(pfd.revents & POLLIN))
        continue;
      rc = bsv_once_with_listen_fd (name, fd);
      if (once)
        break;
    }
  close (fd);
  return rc;
}

static int
bsv_path_activate (const char *name, WORD_LIST *args)
{
  int once = 0;
  if (!bsv_valid_name (name))
    {
      builtin_error ("bad service name");
      return EX_USAGE;
    }
  if (!args || strcmp (args->word->word, "--") != 0 || !args->next ||
      !args->next->next)
    {
      builtin_error ("path needs NAME -- PATH MASK [--once]");
      return EX_USAGE;
    }
  const char *watch_path = args->next->word->word;
  const char *mask_s = args->next->next->word->word;
  for (WORD_LIST *p = args->next->next->next; p; p = p->next)
    {
      if (strcmp (p->word->word, "--once") == 0)
        once = 1;
      else
        {
          builtin_error ("path: unknown arg %s", p->word->word);
          return EX_USAGE;
        }
    }
  if (!bsv_service_exists (name, NULL, 0))
    {
      builtin_error ("no service: %s", name);
      return EXECUTION_FAILURE;
    }

  char *end = NULL;
  unsigned long mask = strtoul (mask_s, &end, 0);
  if (!end || *end != '\0' || mask == 0)
    {
      if (strcmp (mask_s, "create") == 0) mask = IN_CREATE;
      else if (strcmp (mask_s, "modify") == 0) mask = IN_MODIFY;
      else if (strcmp (mask_s, "delete") == 0) mask = IN_DELETE;
      else if (strcmp (mask_s, "move") == 0) mask = IN_MOVE;
      else if (strcmp (mask_s, "close-write") == 0) mask = IN_CLOSE_WRITE;
      else
        {
          builtin_error ("path mask must be numeric or create|modify|delete|move|close-write");
          return EX_USAGE;
        }
    }

  int fd = inotify_init1 (IN_CLOEXEC | IN_NONBLOCK);
  if (fd < 0)
    {
      builtin_error ("inotify_init1: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  int wd = inotify_add_watch (fd, watch_path, (uint32_t) mask);
  if (wd < 0)
    {
      builtin_error ("inotify_add_watch %s: %s", watch_path, strerror (errno));
      close (fd);
      return EXECUTION_FAILURE;
    }

  signal (SIGTERM, bsv_on_term);
  signal (SIGINT, bsv_on_term);
  printf ("watching %s %s %s\n", name, watch_path, mask_s);
  fflush (stdout);

  int rc = EXECUTION_SUCCESS;
  while (!bsv_stop)
    {
      struct pollfd pfd = { .fd = fd, .events = POLLIN };
      int pr = poll (&pfd, 1, 1000);
      if (pr < 0)
        {
          if (errno == EINTR)
            continue;
          builtin_error ("path poll: %s", strerror (errno));
          rc = EXECUTION_FAILURE;
          break;
        }
      if (pr == 0 || !(pfd.revents & POLLIN))
        continue;
      char buf[4096];
      while (read (fd, buf, sizeof buf) > 0)
        ;
      rc = bsv_once (name);
      if (once)
        break;
    }
  close (fd);
  return rc;
}

static const char *
word (WORD_LIST *l)
{
  return l ? l->word->word : NULL;
}

int
sv_builtin (WORD_LIST *list)
{
  const char *cmd = word (list);
  if (!cmd) { builtin_usage (); return EX_USAGE; }

  /* Sync bash's exported-variable table to environ. Without this, env
     vars set via `export X=val` in the calling shell may not appear in
     environ at getenv() time, because bash lazily reconciles the two
     tables (it normally only does so on the way to fork+exec from the
     command-execution path — builtins that fork directly miss the
     sync). Also resets sv-state defaults so a previous invocation's
     env values don't leak through when the same bash process re-calls
     sv with the env now unset. */
  maybe_make_export_env ();
  bsv_sv_dir = "/etc/bash-os/sv";
  bsv_run_dir = "/run/sv";
  bsv_log_dir = "/var/log/sv";
  bsv_log_max_bytes = 1048576;
  bsv_log_generations = 1;

  bsv_sv_dir = getenv ("BASHSV_DIR") && *getenv ("BASHSV_DIR") ? getenv ("BASHSV_DIR") : bsv_sv_dir;
  bsv_run_dir = getenv ("BASHSV_RUNDIR") && *getenv ("BASHSV_RUNDIR") ? getenv ("BASHSV_RUNDIR") : bsv_run_dir;
  bsv_log_dir = getenv ("BASHSV_LOGDIR") && *getenv ("BASHSV_LOGDIR") ? getenv ("BASHSV_LOGDIR") : bsv_log_dir;
  if (getenv ("BASHSV_LOG_MAX_BYTES") && *getenv ("BASHSV_LOG_MAX_BYTES"))
    {
      char *end = NULL;
      long long n = strtoll (getenv ("BASHSV_LOG_MAX_BYTES"), &end, 10);
      if (end && *end == '\0' && n >= 0)
        bsv_log_max_bytes = (off_t) n;
    }
  if (getenv ("BASHSV_LOG_GENERATIONS") && *getenv ("BASHSV_LOG_GENERATIONS"))
    {
      char *end = NULL;
      long n = strtol (getenv ("BASHSV_LOG_GENERATIONS"), &end, 10);
      if (end && *end == '\0')
        bsv_log_generations = bsv_clamp_log_generations (n);
    }
  bsv_mkdir_p (bsv_run_dir, 0755);
  bsv_mkdir_p (bsv_log_dir, 0755);

  if (strcmp (cmd, "up") == 0)
    { const char *n = word (list->next); if (!n) { builtin_error ("up needs NAME"); return EX_USAGE; } return bsv_up_target (n); }
  if (strcmp (cmd, "down") == 0)
    { const char *n = word (list->next); if (!n) { builtin_error ("down needs NAME"); return EX_USAGE; } return bsv_down_target (n); }
  if (strcmp (cmd, "restart") == 0)
    { const char *n = word (list->next); if (!n) { builtin_error ("restart needs NAME"); return EX_USAGE; } bsv_down_target (n); sleep (1); return bsv_up_target (n); }
  if (strcmp (cmd, "once") == 0)
    { const char *n = word (list->next); if (!n) { builtin_error ("once needs NAME"); return EX_USAGE; } return bsv_once (n); }
  if (strcmp (cmd, "timer") == 0)
    {
      const char *n = word (list->next);
      if (!n) { builtin_error ("timer needs NAME"); return EX_USAGE; }
      return bsv_timer (n, list->next->next);
    }
  if (strcmp (cmd, "socket") == 0)
    {
      const char *n = word (list->next);
      if (!n) { builtin_error ("socket needs NAME"); return EX_USAGE; }
      return bsv_socket_activate (n, list->next->next);
    }
  if (strcmp (cmd, "path") == 0)
    {
      const char *n = word (list->next);
      if (!n) { builtin_error ("path needs NAME"); return EX_USAGE; }
      return bsv_path_activate (n, list->next->next);
    }
  if (strcmp (cmd, "signal") == 0)
    {
      const char *n = word (list->next);
      const char *s = list->next ? word (list->next->next) : NULL;
      if (!n || !s) { builtin_error ("signal needs NAME SIGNAL"); return EX_USAGE; }
      return bsv_signal_service (n, s);
    }
  if (strcmp (cmd, "notify") == 0)
    return bsv_notify_send (list->next);
  if (strcmp (cmd, "status") == 0)
    { const char *n = word (list->next); return n ? bsv_status_target (n) : bsv_each_service (bsv_status_one, 0); }
  if (strcmp (cmd, "boot") == 0)
    return bsv_start_enabled_ordered ();
  if (strcmp (cmd, "shutdown") == 0)
    { char p[512]; snprintf (p, sizeof p, "%s/shutdown", bsv_run_dir); bsv_writef (p, "1\n"); return bsv_stop_enabled_ordered (); }
  if (strcmp (cmd, "run") == 0)
    {
      for (WORD_LIST *p = list->next; p; p = p->next)
        if (strcmp (p->word->word, "-d") == 0 && p->next)
          { p = p->next; bsv_sv_dir = p->word->word; }
        else { builtin_error ("run: unknown arg %s", p->word->word); return EX_USAGE; }
      return bsv_run_foreground ();
    }
  if (strcmp (cmd, "log") == 0)
    {
      const char *n = word (list->next);
      int lines = 20;
      if (!n) { builtin_error ("log needs NAME"); return EX_USAGE; }
      for (WORD_LIST *p = list->next->next; p; p = p->next)
        if (strcmp (p->word->word, "-n") == 0 && p->next)
          { p = p->next; lines = atoi (p->word->word); }
      return bsv_log (n, lines);
    }
  builtin_error ("unknown command: %s", cmd);
  return EX_USAGE;
}

char *sv_doc[] = {
  "Service supervisor for bash-os.",
  "",
  "    sv up NAME",
  "    sv down NAME",
  "    sv restart NAME",
  "    sv once NAME",
  "    sv timer NAME -- 'MIN HOUR DOM MON DOW'",
  "    sv timer NAME --cancel",
  "    sv socket NAME -- ADDR:PORT [--once]",
  "    sv path NAME -- PATH MASK [--once]",
  "    sv signal NAME SIGNAL",
  "    sv notify KEY=VALUE ...",
  "    sv status [NAME]",
  "    sv boot",
  "    sv shutdown",
  "    sv run [-d DIR]",
  "    sv log NAME [-n N]",
  "",
  "Run-script directives: # restart: always|on-failure|never,",
  "  # restart-max: N, # restart-window: SECONDS, # restart-delay: SECONDS,",
  "  # readiness: ./check|COMMAND|notify, # readiness-timeout: SECONDS.",
  "",
  "Readiness `notify` (sd_notify subset): the supervisor binds an abstract",
  "AF_UNIX datagram socket, exports NOTIFY_SOCKET=@sv/<NAME>, and the",
  "service pushes READY=1, RELOADING=1, STOPPING=1, STATUS=text, MAINPID=pid",
  "(`sv notify KEY=VALUE ...` sends; unknown keys are ignored). READY",
  "publishes the same `ready pid=N` status the ./check probe writes, so",
  "dependents gate identically. No READY within readiness-timeout writes",
  "`readiness-failed timeout`. Watchdog/FDSTORE/BARRIER are out of scope.",
  "",
  "Environment: BASHSV_DIR, BASHSV_RUNDIR, BASHSV_LOGDIR, BASHSV_LOG_MAX_BYTES,",
  "  BASHSV_LOG_GENERATIONS (1..16, default 1 — newest is NAME.1).",
  "  sv timer writes ${BASHCRON_SPOOL_DIR:-/var/spool/cron}/tabs/$USER.",
  "  sv socket passes a listening fd as fd 3 with LISTEN_FDS metadata.",
  "  sv path accepts numeric inotify masks or create/modify/delete/move/close-write.",
  (char *)NULL
};

struct builtin sv_struct = {
  "sv",
  sv_builtin,
  BUILTIN_ENABLED,
  sv_doc,
  "sv up|down|restart|once|timer|socket|path|signal|notify|status|boot|shutdown|run|log ...",
  0
};
