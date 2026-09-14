/* SPDX-License-Identifier: MIT */
#ifndef BASHAUTH_SUDOEDIT_H
#define BASHAUTH_SUDOEDIT_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

/* ---- sudoedit safe edit-flow helper (Track 4) -----------------------------
 *
 * The future edit path is a SEPARATE edit-token flow (never an editor-as-root).
 * This library realizes the userspace half of the selected sudoedit copyback
 * model from BASHSUDO-POLICY-AUTHORITY-DESIGN.md (§sudoedit) and the suppressed
 * deny-only plan substeps named kernel-side (bashos_auth.c
 * edit_authorization_candidate_{safe_open,temp_copy,editor_as_caller,
 * revalidate,atomic_copyback}_*):
 *
 *   policy-check -> safe (no-follow, race-checked) open -> caller-owned temp
 *   copy -> run-editor-AS-CALLER -> pre-copyback revalidation (path, inode,
 *   owner, mode, symlink state, policy digest, edit token) -> atomic copyback.
 *
 * The flow is FAIL-CLOSED: if ANY substep fails the helper aborts BEFORE the
 * atomic copyback, so the original target is never touched on a rejected edit.
 * Substeps are invoked through an injectable ops table (mirroring cred_exec.c)
 * so the sequencing / abort-before-copyback contract is exercisable on the host
 * with real temporary files and a mock editor hook, without ever running an
 * editor as root or flipping BASHOS_AUTH_FEAT_PRIVCMD. The live invocation is
 * the gated handoff backend; this library performs no privilege transition. */

typedef enum {
  BASHOS_SE_OK = 0,
  BASHOS_SE_REJECT_PARAM,         /* bad/missing arguments */
  BASHOS_SE_REJECT_SYMLINK,       /* a path component / target is a symlink */
  BASHOS_SE_REJECT_NOT_REGULAR,   /* dir, device, fifo, socket — not a file */
  BASHOS_SE_REJECT_HARDLINK,      /* st_nlink > 1 (hardlink race surface) */
  BASHOS_SE_REJECT_UNSAFE_MODE,   /* setuid/setgid bit set on the target */
  BASHOS_SE_REJECT_OPEN,          /* open/stat of the target failed */
  BASHOS_SE_REJECT_TEMP,          /* could not create the caller temp copy */
  BASHOS_SE_REJECT_COPY,          /* read/write while copying failed */
  BASHOS_SE_REJECT_EDITOR,        /* editor hook missing or returned failure */
  BASHOS_SE_REJECT_TOKEN,         /* edit token required but not valid */
  BASHOS_SE_REJECT_POLICY_DRIFT,  /* policy revalidation hook rejected */
  BASHOS_SE_REJECT_RACE,          /* identity drift between open and copyback */
  BASHOS_SE_REJECT_COPYBACK       /* atomic copyback (temp/rename) failed */
} bashos_sudoedit_reject;

/* Captured target identity used for TOCTOU revalidation. */
typedef struct bashos_sudoedit_identity {
  dev_t  dev;
  ino_t  ino;
  uid_t  uid;
  gid_t  gid;
  mode_t mode;
  nlink_t nlink;
  off_t  size;
  struct timespec mtime;
  int    valid;
} bashos_sudoedit_identity;

typedef enum {
  BASHOS_SE_STEP_POLICY_CHECK = 0,   /* policy + edit-token gate, per target */
  BASHOS_SE_STEP_SAFE_OPEN,          /* no-follow open + identity capture */
  BASHOS_SE_STEP_TEMP_COPY,          /* caller-owned temp copy of the target */
  BASHOS_SE_STEP_EDIT_AS_CALLER,     /* run editor as caller (injected hook) */
  BASHOS_SE_STEP_REVALIDATE,         /* re-check identity + policy + token */
  BASHOS_SE_STEP_ATOMIC_COPYBACK,    /* same-dir temp + rename over target */
  BASHOS_SE_STEP__COUNT
} bashos_sudoedit_step;

/* A step handler returns 0 on success, <0 on failure (abort before copyback).
   A NULL handler is a no-op success so a partial ops table can exercise a
   subset. */
typedef int (*bashos_sudoedit_step_fn) (void *ctx);

typedef struct bashos_sudoedit_ops {
  bashos_sudoedit_step_fn step[BASHOS_SE_STEP__COUNT];
  void *ctx;
} bashos_sudoedit_ops;

typedef struct bashos_sudoedit_plan {
  int failed_step;             /* bashos_sudoedit_step that failed, or -1 */
  int reached_copyback;        /* nonzero once the COPYBACK step was reached */
  unsigned long ran_step_mask; /* bit i set when step i's handler ran */
  int step_count;              /* == BASHOS_SE_STEP__COUNT */
} bashos_sudoedit_plan;

/* Per-target working state. The orchestrator edits ONE target; callers loop
   over multiple targets, each with its own ctx/target (every target is
   policy-checked before any copy is made, per the design). */
typedef struct bashos_sudoedit_target {
  const char *path;                  /* original target path (caller-owned) */
  bashos_sudoedit_identity orig;     /* identity captured at safe_open */
  int orig_fd;                       /* no-follow fd to the original, or -1 */
  char *temp_path;                   /* caller-owned temp copy (malloc'd) */
  int temp_fd;                       /* fd to the temp copy, or -1 */
  bashos_sudoedit_reject reject;     /* why this target was rejected, if any */
} bashos_sudoedit_target;

/* Run the accepted editor on TEMP_PATH as the CALLER (never root). Returns 0 on
   success. Production forks, drops to the caller, filters the environment, and
   execs the editor; host tests inject a mock that mutates the temp file. */
typedef int (*bashos_sudoedit_editor_fn) (const char *temp_path, void *ud);

/* Optional policy revalidation hook (the gated authority supplies the real
   one: it re-checks the matched edit rule + normalized policy digest against
   the live target). Returns 0 when the edit is still authorized. */
typedef int (*bashos_sudoedit_policy_fn) (const bashos_sudoedit_target *t,
                                          void *ud);

typedef struct bashos_sudoedit_ctx {
  bashos_sudoedit_target *target;    /* the single target being edited */
  uid_t caller_uid;                  /* temp copy is owned by the caller */
  gid_t caller_gid;
  const char *tmpdir;                /* caller-writable dir for the temp copy */

  /* Edit-token gate: the gated authority sets edit_token_valid once a valid
     fd-bound edit token has been consumed. When require_edit_token is set and
     the token is not valid the flow fails closed at POLICY_CHECK. The token
     bytes are NEVER visible here — only the validated boolean. */
  int require_edit_token;
  int edit_token_valid;

  /* Policy revalidation hook (NULL => skipped unless required). */
  bashos_sudoedit_policy_fn policy_fn;
  void *policy_ud;
  int   require_policy_fn;           /* fail closed if the hook is missing */

  /* Editor hook (must be set; a NULL hook fails closed at EDIT_AS_CALLER). */
  bashos_sudoedit_editor_fn editor_fn;
  void *editor_ud;
} bashos_sudoedit_ctx;

/* Stable name for a step. */
const char *bashos_sudoedit_step_name (bashos_sudoedit_step step);

/* Capture FD's identity into ID (fstat). Returns 0 on success. */
int bashos_sudoedit_capture_identity (int fd, bashos_sudoedit_identity *id);

/* True when two captured identities describe the same file unchanged
   (dev, ino, uid, gid, mode, nlink). Size/mtime are allowed to differ (the
   copyback writes new content). Both must be valid. */
int bashos_sudoedit_identity_equal (const bashos_sudoedit_identity *a,
                                    const bashos_sudoedit_identity *b);

/* Safely open PATH for edit: O_NOFOLLOW|O_RDONLY (no symlink final component),
   reject non-regular / hardlinked / setuid-setgid targets, and capture the
   identity. On success *fd is an open fd and *id is filled; on failure returns
   a bashos_sudoedit_reject code (< 0 mapping: see the enum) and *fd == -1. */
bashos_sudoedit_reject bashos_sudoedit_safe_open (const char *path, int *fd,
                                                  bashos_sudoedit_identity *id);

/* Atomically copy the edited contents in SRC_FD back over TARGET path: write a
   temp file in the SAME directory as TARGET, copy SRC_FD into it, fsync, set
   mode/owner to match ORIG, do a FINAL no-follow identity re-check of TARGET
   against ORIG, then rename(2) over TARGET. The original is left untouched on
   any failure (the same-dir temp is removed). Returns BASHOS_SE_OK or a reject
   code. */
bashos_sudoedit_reject bashos_sudoedit_atomic_copyback (const char *target,
                                                        int src_fd,
                                                        const bashos_sudoedit_identity *orig);

/* Apply the ordered substeps in OPS, aborting BEFORE copyback on the first
   failure. Returns 0 only if every step (including copyback) succeeded; -1 on
   any failure with plan->failed_step set. plan may be NULL. */
int bashos_sudoedit_run_setup (const bashos_sudoedit_ops *ops,
                               bashos_sudoedit_plan *plan);

/* Fill OPS with the production default substep handlers operating on CTX. */
void bashos_sudoedit_default_ops (bashos_sudoedit_ops *ops,
                                  bashos_sudoedit_ctx *ctx);

/* Convenience: build the default ops over CTX and run the ordered flow. On
   success the target has been edited and copied back; on failure returns -1
   with plan->failed_step set and ctx->target->reject describing the cause (the
   original target is untouched). Releases the target's temp file + fds. */
int bashos_sudoedit_run (bashos_sudoedit_ctx *ctx, bashos_sudoedit_plan *plan);

/* Release any open fds + remove/free the temp copy held in T. */
void bashos_sudoedit_target_cleanup (bashos_sudoedit_target *t);

#endif /* BASHAUTH_SUDOEDIT_H */
