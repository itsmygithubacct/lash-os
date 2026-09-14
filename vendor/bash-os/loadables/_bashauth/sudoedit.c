/* SPDX-License-Identifier: MIT */
#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "_bashauth/sudoedit.h"

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* ---- identity capture / comparison ------------------------------------- */

int
bashos_sudoedit_capture_identity (int fd, bashos_sudoedit_identity *id)
{
  struct stat st;
  if (!id || fd < 0)
    return -1;
  memset (id, 0, sizeof *id);
  if (fstat (fd, &st) != 0)
    return -1;
  id->dev   = st.st_dev;
  id->ino   = st.st_ino;
  id->uid   = st.st_uid;
  id->gid   = st.st_gid;
  id->mode  = st.st_mode;
  id->nlink = st.st_nlink;
  id->size  = st.st_size;
#if defined(st_mtime)
  id->mtime = st.st_mtim;
#else
  id->mtime.tv_sec  = st.st_mtime;
  id->mtime.tv_nsec = 0;
#endif
  id->valid = 1;
  return 0;
}

int
bashos_sudoedit_identity_equal (const bashos_sudoedit_identity *a,
                                const bashos_sudoedit_identity *b)
{
  if (!a || !b || !a->valid || !b->valid)
    return 0;
  /* Same file, same owner/mode, no new hardlink: the content (size/mtime) is
     expected to change across an edit, so those are deliberately not compared.
     dev+ino pin the inode; uid/gid/mode/nlink catch a swap-and-chmod race. */
  return a->dev == b->dev && a->ino == b->ino &&
         a->uid == b->uid && a->gid == b->gid &&
         a->mode == b->mode && a->nlink == b->nlink;
}

/* ---- safe open --------------------------------------------------------- */

bashos_sudoedit_reject
bashos_sudoedit_safe_open (const char *path, int *fd,
                           bashos_sudoedit_identity *id)
{
  int f;

  if (fd)
    *fd = -1;
  if (!path || !*path || !fd || !id)
    return BASHOS_SE_REJECT_PARAM;

  /* O_NOFOLLOW rejects a symlink as the FINAL path component (ELOOP). Unsafe
     symlinks earlier in the path are the gated handoff's openat2/RESOLVE_*
     concern; this host-side helper pins the final component + identity. */
  f = open (path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (f < 0)
    {
      if (errno == ELOOP)
        return BASHOS_SE_REJECT_SYMLINK;
      return BASHOS_SE_REJECT_OPEN;
    }

  if (bashos_sudoedit_capture_identity (f, id) != 0)
    {
      close (f);
      return BASHOS_SE_REJECT_OPEN;
    }

  if (!S_ISREG (id->mode))
    {
      close (f);
      return BASHOS_SE_REJECT_NOT_REGULAR;
    }
  if (id->nlink > 1)
    {
      close (f);
      return BASHOS_SE_REJECT_HARDLINK;
    }
  if (id->mode & (S_ISUID | S_ISGID))
    {
      close (f);
      return BASHOS_SE_REJECT_UNSAFE_MODE;
    }

  *fd = f;
  return BASHOS_SE_OK;
}

/* ---- byte copy --------------------------------------------------------- */

static int
bashos_se_copy_fd (int src_fd, int dst_fd)
{
  char buf[65536];
  ssize_t n;

  if (lseek (src_fd, 0, SEEK_SET) == (off_t) -1 && errno != ESPIPE)
    return -1;
  for (;;)
    {
      n = read (src_fd, buf, sizeof buf);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }
      if (n == 0)
        break;
      {
        char *p = buf;
        ssize_t left = n;
        while (left > 0)
          {
            ssize_t w = write (dst_fd, p, (size_t) left);
            if (w < 0)
              {
                if (errno == EINTR)
                  continue;
                return -1;
              }
            p += w;
            left -= w;
          }
      }
    }
  return 0;
}

/* Derive the directory of PATH into a malloc'd string ("." when no slash). */
static char *
bashos_se_dirname_dup (const char *path)
{
  const char *slash = strrchr (path, '/');
  char *d;
  size_t len;
  if (!slash)
    return strdup (".");
  if (slash == path)              /* "/file" -> "/" */
    return strdup ("/");
  len = (size_t) (slash - path);
  d = malloc (len + 1);
  if (!d)
    return NULL;
  memcpy (d, path, len);
  d[len] = '\0';
  return d;
}

/* ---- atomic copyback --------------------------------------------------- */

bashos_sudoedit_reject
bashos_sudoedit_atomic_copyback (const char *target, int src_fd,
                                 const bashos_sudoedit_identity *orig)
{
  char *dir = NULL, *tmpl = NULL;
  int tfd = -1, vfd = -1;
  bashos_sudoedit_identity now;
  bashos_sudoedit_reject rej = BASHOS_SE_REJECT_COPYBACK;

  if (!target || src_fd < 0 || !orig || !orig->valid)
    return BASHOS_SE_REJECT_PARAM;

  dir = bashos_se_dirname_dup (target);
  if (!dir)
    return BASHOS_SE_REJECT_COPYBACK;
  if (asprintf (&tmpl, "%s/.sudoedit.XXXXXX", dir) < 0)
    {
      tmpl = NULL;
      goto out;
    }

  /* Same-directory temp so the final rename(2) is atomic on one filesystem. */
  tfd = mkstemp (tmpl);
  if (tfd < 0)
    goto out;

  if (bashos_se_copy_fd (src_fd, tfd) != 0)
    { rej = BASHOS_SE_REJECT_COPY; goto out; }
  if (fsync (tfd) != 0)
    goto out;

  /* Preserve documented mode/ownership. fchown is best-effort (needs privilege
     when the caller is unprivileged); mode is load-bearing. */
  if (fchmod (tfd, orig->mode & 07777) != 0)
    goto out;
  (void) fchown (tfd, orig->uid, orig->gid);

  /* FINAL race check: the live target must still be the inode we opened, with
     unchanged owner/mode/linkcount, right before we replace it. */
  vfd = open (target, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (vfd < 0)
    { rej = (errno == ELOOP) ? BASHOS_SE_REJECT_SYMLINK : BASHOS_SE_REJECT_RACE; goto out; }
  if (bashos_sudoedit_capture_identity (vfd, &now) != 0 ||
      !bashos_sudoedit_identity_equal (orig, &now))
    { rej = BASHOS_SE_REJECT_RACE; goto out; }
  close (vfd);
  vfd = -1;

  if (rename (tmpl, target) != 0)
    goto out;

  tfd = -1;                       /* renamed away; do not unlink below */
  free (tmpl);
  tmpl = NULL;
  rej = BASHOS_SE_OK;

out:
  if (vfd >= 0)
    close (vfd);
  if (tfd >= 0)
    close (tfd);
  if (tmpl)
    {
      (void) unlink (tmpl);       /* never leave a partial copy behind */
      free (tmpl);
    }
  free (dir);
  return rej;
}

/* ---- ordered substep orchestrator -------------------------------------- */

const char *
bashos_sudoedit_step_name (bashos_sudoedit_step step)
{
  static const char *const names[BASHOS_SE_STEP__COUNT] = {
    [BASHOS_SE_STEP_POLICY_CHECK]     = "policy-check",
    [BASHOS_SE_STEP_SAFE_OPEN]        = "safe-open",
    [BASHOS_SE_STEP_TEMP_COPY]        = "temp-copy",
    [BASHOS_SE_STEP_EDIT_AS_CALLER]   = "editor-as-caller",
    [BASHOS_SE_STEP_REVALIDATE]       = "revalidate",
    [BASHOS_SE_STEP_ATOMIC_COPYBACK]  = "atomic-copyback",
  };
  if ((unsigned) step >= BASHOS_SE_STEP__COUNT)
    return "?";
  return names[step] ? names[step] : "?";
}

int
bashos_sudoedit_run_setup (const bashos_sudoedit_ops *ops,
                           bashos_sudoedit_plan *plan)
{
  bashos_sudoedit_plan local;
  if (!plan)
    plan = &local;
  plan->failed_step = -1;
  plan->reached_copyback = 0;
  plan->ran_step_mask = 0;
  plan->step_count = BASHOS_SE_STEP__COUNT;

  if (!ops)
    {
      plan->failed_step = BASHOS_SE_STEP_POLICY_CHECK;
      return -1;
    }

  for (int i = 0; i < BASHOS_SE_STEP__COUNT; i++)
    {
      /* Reaching COPYBACK means every prior substep (policy, open, copy, edit,
         revalidate) succeeded. Mark it before invoking the handler so a failed
         copyback is still recorded as "reached", while a failure at any earlier
         substep returns with reached_copyback == 0 — the abort-before-copyback
         contract that keeps the original target untouched on a rejected edit. */
      if (i == BASHOS_SE_STEP_ATOMIC_COPYBACK)
        plan->reached_copyback = 1;

      bashos_sudoedit_step_fn fn = ops->step[i];
      if (!fn)
        continue;                 /* NULL handler == no-op success */

      plan->ran_step_mask |= (1UL << (unsigned) i);
      if (fn (ops->ctx) < 0)
        {
          plan->failed_step = i;
          if (i != BASHOS_SE_STEP_ATOMIC_COPYBACK)
            plan->reached_copyback = 0;
          return -1;
        }
    }
  return 0;
}

/* ---- production default substep handlers ------------------------------- */

static int
se_step_policy_check (void *vctx)
{
  bashos_sudoedit_ctx *c = vctx;
  if (!c || !c->target || !c->target->path)
    return -1;
  c->target->orig_fd = -1;
  c->target->temp_fd = -1;
  c->target->temp_path = NULL;
  c->target->reject = BASHOS_SE_OK;

  if (c->require_edit_token && !c->edit_token_valid)
    { c->target->reject = BASHOS_SE_REJECT_TOKEN; return -1; }

  if (c->policy_fn)
    {
      if (c->policy_fn (c->target, c->policy_ud) != 0)
        { c->target->reject = BASHOS_SE_REJECT_POLICY_DRIFT; return -1; }
    }
  else if (c->require_policy_fn)
    { c->target->reject = BASHOS_SE_REJECT_POLICY_DRIFT; return -1; }

  return 0;
}

static int
se_step_safe_open (void *vctx)
{
  bashos_sudoedit_ctx *c = vctx;
  bashos_sudoedit_reject r =
    bashos_sudoedit_safe_open (c->target->path, &c->target->orig_fd,
                               &c->target->orig);
  if (r != BASHOS_SE_OK)
    { c->target->reject = r; return -1; }
  return 0;
}

static int
se_step_temp_copy (void *vctx)
{
  bashos_sudoedit_ctx *c = vctx;
  const char *dir = c->tmpdir && *c->tmpdir ? c->tmpdir : "/tmp";
  char *tmpl = NULL;
  int fd;

  if (asprintf (&tmpl, "%s/sudoedit-XXXXXX", dir) < 0)
    { c->target->reject = BASHOS_SE_REJECT_TEMP; return -1; }
  fd = mkstemp (tmpl);
  if (fd < 0)
    { free (tmpl); c->target->reject = BASHOS_SE_REJECT_TEMP; return -1; }

  /* Caller-owned, private mode. fchown is best-effort (the live path runs this
     after privilege is available; host tests are already the caller). */
  (void) fchmod (fd, 0600);
  (void) fchown (fd, c->caller_uid, c->caller_gid);

  if (bashos_se_copy_fd (c->target->orig_fd, fd) != 0)
    {
      close (fd);
      (void) unlink (tmpl);
      free (tmpl);
      c->target->reject = BASHOS_SE_REJECT_COPY;
      return -1;
    }

  c->target->temp_fd = fd;
  c->target->temp_path = tmpl;    /* ownership transfers to the target */
  return 0;
}

static int
se_step_edit_as_caller (void *vctx)
{
  bashos_sudoedit_ctx *c = vctx;
  /* The editor ALWAYS runs as the caller (never root). A missing hook fails
     closed — the library never silently skips the edit. */
  if (!c->editor_fn)
    { c->target->reject = BASHOS_SE_REJECT_EDITOR; return -1; }
  if (c->editor_fn (c->target->temp_path, c->editor_ud) != 0)
    { c->target->reject = BASHOS_SE_REJECT_EDITOR; return -1; }
  return 0;
}

static int
se_step_revalidate (void *vctx)
{
  bashos_sudoedit_ctx *c = vctx;
  bashos_sudoedit_identity now;
  int vfd;

  /* Edit token + policy must STILL hold after the (untrusted-duration) edit. */
  if (c->require_edit_token && !c->edit_token_valid)
    { c->target->reject = BASHOS_SE_REJECT_TOKEN; return -1; }
  if (c->policy_fn && c->policy_fn (c->target, c->policy_ud) != 0)
    { c->target->reject = BASHOS_SE_REJECT_POLICY_DRIFT; return -1; }

  /* The original path must still resolve (no-follow) to the same inode with
     unchanged owner/mode/linkcount. */
  vfd = open (c->target->path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
  if (vfd < 0)
    {
      c->target->reject = (errno == ELOOP) ? BASHOS_SE_REJECT_SYMLINK
                                           : BASHOS_SE_REJECT_RACE;
      return -1;
    }
  if (bashos_sudoedit_capture_identity (vfd, &now) != 0 ||
      !bashos_sudoedit_identity_equal (&c->target->orig, &now))
    { close (vfd); c->target->reject = BASHOS_SE_REJECT_RACE; return -1; }
  close (vfd);
  return 0;
}

static int
se_step_atomic_copyback (void *vctx)
{
  bashos_sudoedit_ctx *c = vctx;
  bashos_sudoedit_reject r =
    bashos_sudoedit_atomic_copyback (c->target->path, c->target->temp_fd,
                                     &c->target->orig);
  if (r != BASHOS_SE_OK)
    { c->target->reject = r; return -1; }
  return 0;
}

void
bashos_sudoedit_default_ops (bashos_sudoedit_ops *ops, bashos_sudoedit_ctx *ctx)
{
  if (!ops)
    return;
  memset (ops, 0, sizeof *ops);
  ops->ctx = ctx;
  ops->step[BASHOS_SE_STEP_POLICY_CHECK]    = se_step_policy_check;
  ops->step[BASHOS_SE_STEP_SAFE_OPEN]       = se_step_safe_open;
  ops->step[BASHOS_SE_STEP_TEMP_COPY]       = se_step_temp_copy;
  ops->step[BASHOS_SE_STEP_EDIT_AS_CALLER]  = se_step_edit_as_caller;
  ops->step[BASHOS_SE_STEP_REVALIDATE]      = se_step_revalidate;
  ops->step[BASHOS_SE_STEP_ATOMIC_COPYBACK] = se_step_atomic_copyback;
}

void
bashos_sudoedit_target_cleanup (bashos_sudoedit_target *t)
{
  if (!t)
    return;
  if (t->orig_fd >= 0)
    { close (t->orig_fd); t->orig_fd = -1; }
  if (t->temp_fd >= 0)
    { close (t->temp_fd); t->temp_fd = -1; }
  if (t->temp_path)
    {
      (void) unlink (t->temp_path);
      free (t->temp_path);
      t->temp_path = NULL;
    }
}

int
bashos_sudoedit_run (bashos_sudoedit_ctx *ctx, bashos_sudoedit_plan *plan)
{
  bashos_sudoedit_ops ops;
  int rc;
  if (!ctx || !ctx->target)
    return -1;
  bashos_sudoedit_default_ops (&ops, ctx);
  rc = bashos_sudoedit_run_setup (&ops, plan);
  bashos_sudoedit_target_cleanup (ctx->target);
  return rc;
}
