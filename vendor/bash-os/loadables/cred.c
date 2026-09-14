/* SPDX-License-Identifier: MIT */
/* cred.c - Stage 23 v1: consolidated priv-drop primitive.
 *
 * Owns the canonical setresuid/setresgid/setgroups + PR_SET_NO_NEW_PRIVS
 * + capability-clear sequences that used to be re-implemented in
 * login (`become`), ns (`spawn --no-new-privs`), and ad-hoc
 * setpriv-style call sites. Implementation lives in
 * `bashcred_privdrop.h` (static inline) so cred / login /
 * ns each get their own copy without changing the build infra.
 *
 * Verbs:
 *
 *   cred drop USER [--keep-supplementary]
 *       Resolve USER (numeric uid OR /etc/passwd name), optionally
 *       load /etc/group supplementary groups, then drop in this
 *       order:
 *           1. setgroups
 *           2. setresgid(gid, gid, gid)
 *           3. setresuid(uid, uid, uid)
 *           4. getresuid + getresgid verify
 *       Without --keep-supplementary the supplementary set collapses
 *       to the primary gid only. On any failure rc=64 with a clear
 *       diagnostic; the caller MUST NOT continue with rc=64 because
 *       the caller's identity may be partially transformed. This
 *       loadable does not exec; the caller is expected to follow up
 *       with `exec ...` (or `_exit`) themselves.
 *
 *   cred no-new-privs
 *       prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0). rc 0 on success,
 *       rc 1 on EPERM/ENOSYS with a stderr diagnostic.
 *
 *   cred caps-clear [--keep CAP[,CAP...]]
 *       Drop bounding + ambient + permitted/effective/inheritable
 *       capability sets except those listed. CAP names match
 *       Linux's CAP_* set with or without the prefix
 *       (case-insensitive). NULL keep-list drops every cap. Calls
 *       prctl(PR_CAPBSET_DROP) per-cap, capset() with the keep
 *       mask, prctl(PR_CAP_AMBIENT_CLEAR_ALL), then
 *       PR_CAP_AMBIENT_RAISE for each kept cap.
 *
 *   cred lookup USER -h UID_VAR -h GID_VAR [-h GROUPS_VAR]
 *       Pure-resolver verb: writes uid/gid/groups (comma-separated)
 *       to bash variables without dropping. Lets shell scripts
 *       inspect a user before invoking drop. Three -h flags total
 *       are allowed; the first binds uid, the second binds gid, and
 *       the optional third binds the supplementary-group list as
 *       comma-separated decimals. rc 0 on hit, rc 1 on not-found.
 *
 *   cred status
 *       Prints current uid/gid/euid/egid/groups in a parseable
 *       single line:
 *           uid=N gid=N euid=N egid=N groups=N,N,N
 *       rc 0 always; trivial introspection helper.
 *
 * Ordering contract (see loadables/common/bashcred_privdrop.h): for a fully
 * hardened transition, callers should compose
 *     namespace setup -> no-new-privs -> caps-clear -> drop
 * Reordering can defeat the drop on partial-failure paths.
 *
 * --- LICENSE ---
 * MIT License - same boilerplate as binhex.c.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "loadables.h"
#include "bashcred_privdrop.h"

#define BC_DROP_FAIL_RC 64

static int
bc_drop_cmd (WORD_LIST *args)
{
    const char *user = NULL;
    int keep_sup = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--keep-supplementary") == 0) {
            keep_sup = 1;
            continue;
        }
        if (w[0] == '-' && w[1]) {
            builtin_error ("drop: unknown option %s", w);
            return EX_USAGE;
        }
        if (user) {
            builtin_error ("drop: extra arg %s", w);
            return EX_USAGE;
        }
        user = w;
    }
    if (!user) {
        builtin_error ("drop: USER required");
        return EX_USAGE;
    }

    bc_user_info info;
    int r = bc_lookup_user (user, &info);
    if (r == -2) {
        builtin_error ("drop: cannot read /etc/passwd: %s", strerror (errno));
        return BC_DROP_FAIL_RC;
    }
    if (r == -1) {
        builtin_error ("drop: no such user: %s", user);
        return BC_DROP_FAIL_RC;
    }

    /* Build the supplementary group set. With --keep-supplementary
       we walk /etc/group; otherwise we pass an empty list which
       bc_privdrop_to_user collapses to a single-element {primary
       gid} setgroups call. */
    gid_t groups[BC_PD_GROUPS_MAX];
    int n_groups = 0;
    if (keep_sup) {
        bc_load_supplementary_groups (info.name, groups, &n_groups,
                                      BC_PD_GROUPS_MAX);
        /* Always include the primary gid so it survives the
           setgroups call. Skip if already present from the group
           file (rare but harmless to dedupe). */
        int already = 0;
        for (int i = 0; i < n_groups; i++)
            if (groups[i] == info.gid) { already = 1; break; }
        if (!already && n_groups < BC_PD_GROUPS_MAX)
            groups[n_groups++] = info.gid;
    }

    char err[BC_PD_ERR_MAX];
    if (bc_privdrop_to_user (info.uid, info.gid,
                             keep_sup ? groups : NULL,
                             keep_sup ? n_groups : 0,
                             err, sizeof err) < 0) {
        builtin_error ("drop %s: %s", user, err[0] ? err : "failed");
        return BC_DROP_FAIL_RC;
    }
    return EXECUTION_SUCCESS;
}

static int
bc_no_new_privs_cmd (WORD_LIST *args)
{
    if (args) {
        builtin_error ("no-new-privs: takes no arguments");
        return EX_USAGE;
    }
    char err[BC_PD_ERR_MAX];
    if (bc_no_new_privs (err, sizeof err) < 0) {
        builtin_error ("%s", err[0] ? err : "no-new-privs failed");
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bc_caps_clear_cmd (WORD_LIST *args)
{
    const char *keep = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--keep") == 0) {
            if (!p->next) {
                builtin_error ("caps-clear: --keep needs CAP[,CAP...]");
                return EX_USAGE;
            }
            p = p->next;
            keep = p->word->word;
            continue;
        }
        builtin_error ("caps-clear: unknown option %s", w);
        return EX_USAGE;
    }
    char err[BC_PD_ERR_MAX];
    if (bc_caps_clear (keep, err, sizeof err) < 0) {
        builtin_error ("caps-clear: %s", err[0] ? err : "failed");
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

/* Three sequential -h FLAG slots: uid, gid, supplementary groups
 * (last is optional). Returns the bound names by output param. */
static int
bc_lookup_cmd (WORD_LIST *args)
{
    const char *user = NULL;
    const char *vars[3] = { NULL, NULL, NULL };
    int nvars = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-h") == 0) {
            if (!p->next) {
                builtin_error ("lookup: -h needs VAR");
                return EX_USAGE;
            }
            p = p->next;
            if (nvars >= 3) {
                builtin_error ("lookup: too many -h slots (max 3: uid, gid, groups)");
                return EX_USAGE;
            }
            vars[nvars++] = p->word->word;
            continue;
        }
        if (user) {
            builtin_error ("lookup: extra arg %s", w);
            return EX_USAGE;
        }
        user = w;
    }
    if (!user) {
        builtin_error ("lookup: USER required");
        return EX_USAGE;
    }
    if (nvars < 2) {
        builtin_error ("lookup: needs at least -h UID_VAR -h GID_VAR");
        return EX_USAGE;
    }

    bc_user_info info;
    int r = bc_lookup_user (user, &info);
    if (r == -2) {
        builtin_error ("lookup: cannot read /etc/passwd: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (r == -1) {
        builtin_error ("lookup: no such user: %s", user);
        return EXECUTION_FAILURE;
    }

    char buf[64];
    snprintf (buf, sizeof buf, "%lu", (unsigned long) info.uid);
    builtin_bind_variable ((char *) vars[0], buf, 0);
    snprintf (buf, sizeof buf, "%lu", (unsigned long) info.gid);
    builtin_bind_variable ((char *) vars[1], buf, 0);

    if (nvars == 3) {
        gid_t groups[BC_PD_GROUPS_MAX];
        int n_groups = 0;
        bc_load_supplementary_groups (info.name, groups, &n_groups,
                                      BC_PD_GROUPS_MAX);
        char gbuf[1024];
        size_t off = 0;
        gbuf[0] = '\0';
        for (int i = 0; i < n_groups; i++) {
            int written = snprintf (gbuf + off, sizeof gbuf - off,
                                    "%s%lu", off ? "," : "",
                                    (unsigned long) groups[i]);
            if (written < 0 || (size_t) written >= sizeof gbuf - off) break;
            off += (size_t) written;
        }
        builtin_bind_variable ((char *) vars[2], gbuf, 0);
    }
    return EXECUTION_SUCCESS;
}

static int
bc_status_cmd (WORD_LIST *args)
{
    if (args) {
        builtin_error ("status: takes no arguments");
        return EX_USAGE;
    }

    /* Snapshot identity. Use getresuid/getresgid where supported so
       the saved-set value is visible too — but we only emit the real
       and effective ids in the canonical line so the parseable
       format stays compact. */
    uid_t ru = getuid ();
    gid_t rg = getgid ();
    uid_t eu = geteuid ();
    gid_t eg = getegid ();

    /* getgroups: query length first, then materialize. NGROUPS_MAX
       is OS-dependent; cap to BC_PD_GROUPS_MAX which is the same
       limit our other helpers honor. */
    gid_t groups[BC_PD_GROUPS_MAX];
    int n = getgroups (BC_PD_GROUPS_MAX, groups);
    if (n < 0) n = 0;

    /* Print uid/gid/euid/egid/groups in one pass to stdout. */
    printf ("uid=%lu gid=%lu euid=%lu egid=%lu groups=",
            (unsigned long) ru, (unsigned long) rg,
            (unsigned long) eu, (unsigned long) eg);
    for (int i = 0; i < n; i++) {
        printf ("%s%lu", i ? "," : "", (unsigned long) groups[i]);
    }
    printf ("\n");
    return EXECUTION_SUCCESS;
}

int
cred_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;

    if (strcmp (cmd, "drop")          == 0) return bc_drop_cmd          (args);
    if (strcmp (cmd, "no-new-privs")  == 0) return bc_no_new_privs_cmd  (args);
    if (strcmp (cmd, "caps-clear")    == 0) return bc_caps_clear_cmd    (args);
    if (strcmp (cmd, "lookup")        == 0) return bc_lookup_cmd        (args);
    if (strcmp (cmd, "status")        == 0) return bc_status_cmd        (args);
    builtin_error ("unknown verb: %s "
                   "(try drop, no-new-privs, caps-clear, lookup, or status)",
                   cmd);
    return EX_USAGE;
}

char *cred_doc[] = {
    "Consolidated priv-drop primitive (Stage 23).",
    "",
    "    cred drop USER [--keep-supplementary]",
    "        Drop privileges to USER. setgroups + setresgid + setresuid",
    "        + verify. rc 64 on any failure (caller must not continue).",
    "    cred no-new-privs",
    "        prctl(PR_SET_NO_NEW_PRIVS, 1) — defangs setuid binaries +",
    "        file capabilities for this process and its descendants.",
    "    cred caps-clear [--keep CAP[,CAP...]]",
    "        Drop bounding + ambient + permitted/effective/inheritable",
    "        capabilities except those listed. CAP names match Linux's",
    "        CAP_* set, with or without the prefix.",
    "    cred lookup USER -h UID_VAR -h GID_VAR [-h GROUPS_VAR]",
    "        Resolve USER (uid or name) without dropping. Binds bash",
    "        variables; rc 1 on not-found.",
    "    cred status",
    "        Prints uid=N gid=N euid=N egid=N groups=N,N,N for the",
    "        current process.",
    "",
    "Ordering contract for full hardening:",
    "    namespace setup -> no-new-privs -> caps-clear -> drop",
    "Reordering can defeat the drop on partial-failure paths. See",
    "loadables/common/bashcred_privdrop.h.",
    (char *) NULL
};

struct builtin cred_struct = {
    "cred",
    cred_builtin,
    BUILTIN_ENABLED,
    cred_doc,
    "cred drop|no-new-privs|caps-clear|lookup|status [args...]",
    0
};
