/* bashcred_privdrop.h — shared priv-drop primitives for bash-os.
 *
 * Stage 23 v1: consolidates the canonical setresuid/setresgid/
 * setgroups + PR_SET_NO_NEW_PRIVS + capability-clear sequences that
 * used to be re-implemented in bashlogin (`become`), bashns (`spawn
 * --no-new-privs`), and ad-hoc setpriv-style call sites. Three
 * loadables include this header (bashcred, bashlogin, bashns); each
 * gets its own copy of the implementations because the helpers live
 * here as `static inline` rather than as a separate compiled
 * translation unit. Operator-side bloat is in the kilobyte range and
 * keeps the build infra unchanged.
 *
 * Public surface (every helper is fail-loud and writes a one-line
 * diagnostic into a caller-provided err buffer when it returns -1):
 *
 *   bc_user_info — pwent-shaped record populated by the lookup
 *                  helpers below.
 *   bc_lookup_user_by_name(name, &info)
 *                — parse /etc/passwd by user name. Returns 0 on
 *                  hit, -1 on not-found, -2 on /etc/passwd open
 *                  failure (errno preserved).
 *   bc_lookup_user_by_uid(uid, &info)
 *                — same shape, looks up by numeric uid.
 *   bc_lookup_user(spec, &info)
 *                — caller-friendly resolver: if `spec` is all
 *                  digits we treat it as a uid, otherwise a name.
 *   bc_load_supplementary_groups(name, gid_t *gids, int *count, int max)
 *                — parse /etc/group, capture every gid whose member
 *                  list contains `name`. *count is set to the number
 *                  written; truncates silently if there are more
 *                  than `max` matches. Best-effort: a missing
 *                  /etc/group is treated as zero supplementary
 *                  groups, not an error.
 *   bc_privdrop_to_user(uid, gid, gids, n_gids, err, errsz)
 *                — atomic identity change.
 *                  Order:
 *                      1. setgroups(n_gids, gids)
 *                      2. setresgid(gid, gid, gid)
 *                      3. setresuid(uid, uid, uid)
 *                      4. getresuid + getresgid verify
 *                  Returns 0 on success, -1 on partial drop (err
 *                  populated with the failing step + errno). Caller
 *                  MUST NOT continue with a -1 — re-exec, _exit, or
 *                  abort. This helper does not exec.
 *   bc_no_new_privs(err, errsz)
 *                — prctl(PR_SET_NO_NEW_PRIVS, 1). 0 on success,
 *                  -1 on EPERM/ENOSYS.
 *   bc_caps_clear(keep_csv, err, errsz)
 *                — drop bounding + ambient + inheritable + permitted
 *                  + effective capability sets except for the names
 *                  in `keep_csv` (comma-separated CAP_* names with or
 *                  without the prefix; case-insensitive). NULL or ""
 *                  keep_csv drops every cap.
 *
 * Error-buffer convention: `err` is a caller-owned buffer of `errsz`
 * bytes; helpers always NUL-terminate (snprintf semantics). `errsz`
 * of 128 is generous for every diagnostic this header produces.
 *
 * Ordering contract (see loadables/common/bashcred_privdrop.h): callers compose
 * these helpers in this order for a fully hardened transition:
 *     namespace setup → bc_no_new_privs → bc_caps_clear → bc_privdrop_to_user
 * Reordering can defeat the drop on partial-failure paths.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASHCRED_PRIVDROP_H
#define BASHCRED_PRIVDROP_H

/* unistd.h must come first so _GNU_SOURCE-gated declarations
 * (setresuid/setresgid/getresuid/getresgid, geteuid, syscall) are
 * exposed to consumers. Bash's loadable build always passes
 * -D_GNU_SOURCE; the standalone bashcred_privdrop.c audit defines it
 * before including this header. */
#include <unistd.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define BC_PD_NAME_MAX  64
#define BC_PD_PATH_MAX  256
#define BC_PD_GECOS_MAX 256
#define BC_PD_GROUPS_MAX 64
#define BC_PD_ERR_MAX   128

typedef struct {
    char  name[BC_PD_NAME_MAX];
    uid_t uid;
    gid_t gid;
    char  home[BC_PD_PATH_MAX];
    char  shell[BC_PD_PATH_MAX];
    char  gecos[BC_PD_GECOS_MAX];
} bc_user_info;

/* Cap-name table — Linux 6.12 set, mirrors bashcaps.c indexing.
 * Defined here as well so callers that don't link bashcaps still
 * get the keep-list resolver. */
static const char *bc_pd_cap_names[] = {
    "CAP_CHOWN",            "CAP_DAC_OVERRIDE",     "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",           "CAP_FSETID",           "CAP_KILL",
    "CAP_SETGID",           "CAP_SETUID",           "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",  "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",        "CAP_NET_RAW",          "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",        "CAP_SYS_MODULE",       "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",       "CAP_SYS_PTRACE",       "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",        "CAP_SYS_BOOT",         "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",     "CAP_SYS_TIME",         "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",            "CAP_LEASE",            "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",    "CAP_SETFCAP",          "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",        "CAP_SYSLOG",           "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",    "CAP_AUDIT_READ",       "CAP_PERFMON",
    "CAP_BPF",              "CAP_CHECKPOINT_RESTORE",
};
#define BC_PD_CAP_LAST  40
#define BC_PD_CAP_COUNT (BC_PD_CAP_LAST + 1)

/* PR_CAP_AMBIENT_CLEAR_ALL is from Linux 4.3+; define if missing. */
#ifndef PR_CAP_AMBIENT
#  define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_RAISE
#  define PR_CAP_AMBIENT_RAISE 2
#endif
#ifndef PR_CAP_AMBIENT_LOWER
#  define PR_CAP_AMBIENT_LOWER 3
#endif
#ifndef PR_CAP_AMBIENT_IS_SET
#  define PR_CAP_AMBIENT_IS_SET 1
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#  define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

static inline int
bc_pd_cap_lookup (const char *name)
{
    if (!name) return -1;
    const char *base = name;
    if (strncasecmp (base, "CAP_", 4) == 0) base += 4;
    for (int i = 0; i < BC_PD_CAP_COUNT; i++) {
        const char *n = bc_pd_cap_names[i] + 4;
        if (strcasecmp (n, base) == 0) return i;
    }
    return -1;
}

static inline int
bc_pd_all_digits (const char *s)
{
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++)
        if (!isdigit ((unsigned char) *p)) return 0;
    return 1;
}

/* Split an account database row only when it has exactly the expected fields. */
static inline int
bc_pd_fields (char *line, char **fields, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        fields[i] = line;
        char *colon = strchr (line, ':');
        if (i + 1 == count) return colon ? -1 : 0;
        if (!colon) return -1;
        *colon = '\0';
        line = colon + 1;
    }
    return -1;
}

static inline int
bc_pd_id (const char *s, unsigned long *out)
{
    if (!bc_pd_all_digits (s)) return -1;
    errno = 0;
    *out = strtoul (s, NULL, 10);
    return errno == ERANGE ? -1 : 0;
}

/* Parse one /etc/passwd row. Returns 0 if the row matches, -1 if not.
 * `match_name` is the user name to match (NULL = ignore name); `match_uid`
 * is matched only if `use_uid` is non-zero. */
static inline int
bc_pd_match_row (char *line, ssize_t n,
                 const char *match_name, int use_uid, uid_t match_uid,
                 bc_user_info *out)
{
    if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
    if (line[0] == '#' || line[0] == '\0') return -1;

    char *fields[7] = { 0 };
    if (bc_pd_fields (line, fields, 7) < 0) return -1;
    unsigned long uid_value, gid_value;
    if (bc_pd_id (fields[2], &uid_value) < 0 ||
        bc_pd_id (fields[3], &gid_value) < 0 ||
        (uid_t) uid_value != uid_value || (gid_t) gid_value != gid_value)
        return -1;
    uid_t uid = (uid_t) uid_value;
    if (match_name) {
        if (strcmp (fields[0], match_name) != 0) return -1;
    } else if (use_uid) {
        if (uid != match_uid) return -1;
    } else {
        return -1;
    }

    memset (out, 0, sizeof *out);
    strncpy (out->name,  fields[0], sizeof out->name  - 1);
    out->uid = uid;
    out->gid = (gid_t) gid_value;
    strncpy (out->gecos, fields[4], sizeof out->gecos - 1);
    strncpy (out->home,  fields[5], sizeof out->home  - 1);
    strncpy (out->shell, fields[6], sizeof out->shell - 1);
    if (out->shell[0] == '\0')
        strncpy (out->shell, "/bin/bash", sizeof out->shell - 1);
    return 0;
}

static inline int
bc_pd_lookup_common (const char *match_name, int use_uid, uid_t match_uid,
                     bc_user_info *out)
{
    FILE *f = fopen ("/etc/passwd", "r");
    if (!f) return -2;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int found = 0;
    while ((n = getline (&line, &cap, f)) > 0) {
        if (bc_pd_match_row (line, n, match_name, use_uid, match_uid, out) == 0) {
            found = 1;
            break;
        }
    }
    free (line);
    fclose (f);
    return found ? 0 : -1;
}

static inline int
bc_lookup_user_by_name (const char *name, bc_user_info *out)
{
    if (!name || !*name || !out) { errno = EINVAL; return -1; }
    return bc_pd_lookup_common (name, 0, 0, out);
}

static inline int
bc_lookup_user_by_uid (uid_t uid, bc_user_info *out)
{
    if (!out) { errno = EINVAL; return -1; }
    return bc_pd_lookup_common (NULL, 1, uid, out);
}

static inline int
bc_lookup_user (const char *spec, bc_user_info *out)
{
    if (!spec || !*spec || !out) { errno = EINVAL; return -1; }
    if (bc_pd_all_digits (spec)) {
        uid_t uid = (uid_t) strtoul (spec, NULL, 10);
        return bc_lookup_user_by_uid (uid, out);
    }
    return bc_lookup_user_by_name (spec, out);
}

/* Parse /etc/group; collect every gid whose member list contains
 * `name` (member-list is the 4th colon field, comma-separated). The
 * primary gid is NOT included here — callers normally call this and
 * then add the primary gid separately if needed. */
static inline int
bc_pd_groups_from_stream (FILE *f, const char *name, gid_t *out, int *count, int max)
{
    if (count) *count = 0;
    if (!f || !name || !*name || !out || max <= 0) return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int written = 0;
    while ((n = getline (&line, &cap, f)) > 0 && written < max) {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;
        char *fields[4] = { 0 };
        if (bc_pd_fields (line, fields, 4) < 0) continue;
        unsigned long gid_value;
        if (bc_pd_id (fields[2], &gid_value) < 0 ||
            (gid_t) gid_value != gid_value) continue;
        gid_t gid = (gid_t) gid_value;
        char *members = fields[3];
        char *psave = NULL;
        for (char *tok = strtok_r (members, ",", &psave); tok && written < max;
             tok = strtok_r (NULL, ",", &psave)) {
            if (strcmp (tok, name) == 0) {
                out[written++] = gid;
                break;
            }
        }
    }
    free (line);
    if (count) *count = written;
    return 0;
}

static inline int
bc_load_supplementary_groups (const char *name, gid_t *out, int *count, int max)
{
    FILE *f = fopen ("/etc/group", "r");
    int rc = bc_pd_groups_from_stream (f, name, out, count, max);
    if (f) fclose (f);
    return rc;
}

static inline int
bc_privdrop_to_user (uid_t uid, gid_t gid,
                     const gid_t *groups, int n_groups,
                     char *err, size_t errsz)
{
    if (err && errsz) err[0] = '\0';
    if (geteuid () != 0) {
        if (err) snprintf (err, errsz,
                           "privdrop: not root (euid=%lu)",
                           (unsigned long) geteuid ());
        errno = EPERM;
        return -1;
    }
    /* setgroups: use the caller-provided list, falling back to the
       single primary gid when the caller passed n_groups==0. */
    int rc;
    if (n_groups <= 0) {
        const gid_t one = gid;
        rc = setgroups (1, &one);
    } else {
        rc = setgroups ((size_t) n_groups, groups);
    }
    if (rc < 0) {
        if (err) snprintf (err, errsz,
                           "setgroups(%d): %s",
                           n_groups <= 0 ? 1 : n_groups, strerror (errno));
        return -1;
    }
    if (setresgid (gid, gid, gid) < 0) {
        if (err) snprintf (err, errsz,
                           "setresgid(%lu): %s",
                           (unsigned long) gid, strerror (errno));
        return -1;
    }
    if (setresuid (uid, uid, uid) < 0) {
        if (err) snprintf (err, errsz,
                           "setresuid(%lu): %s",
                           (unsigned long) uid, strerror (errno));
        return -1;
    }
    /* Verify the drop took. setresuid/gid can succeed without
       actually changing the IDs in some sandbox configs. */
    uid_t ru, eu, su;
    gid_t rg, eg, sg;
    if (getresuid (&ru, &eu, &su) < 0 ||
        getresgid (&rg, &eg, &sg) < 0) {
        if (err) snprintf (err, errsz,
                           "getresuid/gid verify: %s",
                           strerror (errno));
        return -1;
    }
    if (ru != uid || eu != uid || su != uid ||
        rg != gid || eg != gid || sg != gid) {
        if (err) snprintf (err, errsz,
                           "verify: ids did not stick (uid r=%lu e=%lu s=%lu, gid r=%lu e=%lu s=%lu)",
                           (unsigned long) ru, (unsigned long) eu, (unsigned long) su,
                           (unsigned long) rg, (unsigned long) eg, (unsigned long) sg);
        errno = EPERM;
        return -1;
    }
    return 0;
}

static inline int
bc_no_new_privs (char *err, size_t errsz)
{
    if (err && errsz) err[0] = '\0';
    if (prctl (PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) < 0) {
        if (err) snprintf (err, errsz,
                           "prctl(PR_SET_NO_NEW_PRIVS): %s",
                           strerror (errno));
        return -1;
    }
    return 0;
}

/* 64-bit cap mask helpers — used internally by bc_caps_clear. */
static inline int
bc_pd_capset (uint64_t eff, uint64_t prm, uint64_t inh)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    data[0].effective   = (uint32_t) (eff & 0xFFFFFFFFu);
    data[1].effective   = (uint32_t) (eff >> 32);
    data[0].permitted   = (uint32_t) (prm & 0xFFFFFFFFu);
    data[1].permitted   = (uint32_t) (prm >> 32);
    data[0].inheritable = (uint32_t) (inh & 0xFFFFFFFFu);
    data[1].inheritable = (uint32_t) (inh >> 32);
    return (int) syscall (SYS_capset, &hdr, data);
}

static inline int
bc_pd_capget (uint64_t *eff, uint64_t *prm, uint64_t *inh)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (syscall (SYS_capget, &hdr, data) != 0) return -1;
    if (eff) *eff = ((uint64_t) data[1].effective << 32) | data[0].effective;
    if (prm) *prm = ((uint64_t) data[1].permitted << 32) | data[0].permitted;
    if (inh) *inh = ((uint64_t) data[1].inheritable << 32) | data[0].inheritable;
    return 0;
}

static inline int
bc_pd_caps_parse (const char *csv, uint64_t *out, const char *what,
                  char *err, size_t errsz)
{
    uint64_t mask = 0;
    if (csv && *csv) {
        char buf[512];
        if (strlen (csv) >= sizeof buf) {
            if (err) snprintf (err, errsz, "%s: list too long", what);
            errno = E2BIG;
            return -1;
        }
        strcpy (buf, csv);
        char *psave = NULL;
        for (char *tok = strtok_r (buf, ",", &psave); tok;
             tok = strtok_r (NULL, ",", &psave)) {
            while (*tok == ' ' || *tok == '\t') tok++;
            if (!*tok) continue;
            int idx = bc_pd_cap_lookup (tok);
            if (idx < 0) {
                if (err) snprintf (err, errsz, "%s: unknown cap '%s'", what, tok);
                errno = EINVAL;
                return -1;
            }
            mask |= ((uint64_t) 1 << idx);
        }
    }
    if (out) *out = mask;
    return 0;
}

static inline int
bc_caps_drop (const char *drop_csv, char *err, size_t errsz)
{
    if (err && errsz) err[0] = '\0';
    uint64_t drop = 0;
    if (bc_pd_caps_parse (drop_csv, &drop, "caps-drop", err, errsz) < 0)
        return -1;
    if (drop == 0) return 0;

    uint64_t eff = 0, prm = 0, inh = 0;
    if (bc_pd_capget (&eff, &prm, &inh) < 0) {
        if (err) snprintf (err, errsz, "capget: %s", strerror (errno));
        return -1;
    }

    for (int i = 0; i < BC_PD_CAP_COUNT; i++) {
        if (!(drop & ((uint64_t) 1 << i))) continue;
        int r = prctl (PR_CAPBSET_DROP, (unsigned long) i, 0, 0, 0);
        if (r < 0 && errno != EINVAL) {
            if (err) snprintf (err, errsz, "PR_CAPBSET_DROP %s: %s",
                               bc_pd_cap_names[i], strerror (errno));
            return -1;
        }
        r = prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER,
                   (unsigned long) i, 0, 0);
        if (r < 0 && errno != EINVAL && errno != EPERM) {
            if (err) snprintf (err, errsz, "PR_CAP_AMBIENT_LOWER %s: %s",
                               bc_pd_cap_names[i], strerror (errno));
            return -1;
        }
    }

    eff &= ~drop;
    prm &= ~drop;
    inh &= ~drop;
    if (bc_pd_capset (eff, prm, inh) < 0 && errno != EINVAL) {
        if (err) snprintf (err, errsz, "capset: %s", strerror (errno));
        return -1;
    }
    return 0;
}

static inline int
bc_caps_clear (const char *keep_csv, char *err, size_t errsz)
{
    if (err && errsz) err[0] = '\0';

    /* Build the keep mask from comma-separated names. NULL/"" → 0. */
    uint64_t keep = 0;
    if (bc_pd_caps_parse (keep_csv, &keep, "caps-clear", err, errsz) < 0)
        return -1;

    /* 1. Drop bounding-set caps not in the keep mask.
       PR_CAPBSET_DROP requires CAP_SETPCAP — caller must hold it. */
    for (int i = 0; i < BC_PD_CAP_COUNT; i++) {
        if (keep & ((uint64_t) 1 << i)) continue;
        int r = prctl (PR_CAPBSET_DROP, (unsigned long) i, 0, 0, 0);
        if (r < 0 && errno != EINVAL) {
            if (err) snprintf (err, errsz,
                               "PR_CAPBSET_DROP %s: %s",
                               bc_pd_cap_names[i], strerror (errno));
            return -1;
        }
    }

    /* 2. capset() inheritable+permitted+effective to the keep mask
       only. EFFECTIVE bits raise to keep so any subsequent code path
       in this process can still use them; PERMITTED is the upper
       bound so we set them equal. INHERITABLE matches so children
       can inherit. */
    if (bc_pd_capset (keep, keep, keep) < 0 && errno != EINVAL) {
        if (err) snprintf (err, errsz, "capset: %s", strerror (errno));
        return -1;
    }

    /* 3. Wipe ambient set, then raise only the kept bits. */
    if (prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0L, 0L, 0L) < 0
        && errno != EINVAL) {
        if (err) snprintf (err, errsz,
                           "PR_CAP_AMBIENT_CLEAR_ALL: %s", strerror (errno));
        return -1;
    }
    for (int i = 0; i < BC_PD_CAP_COUNT; i++) {
        if (!(keep & ((uint64_t) 1 << i))) continue;
        int r = prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE,
                       (unsigned long) i, 0, 0);
        if (r < 0 && errno != EINVAL && errno != EPERM) {
            if (err) snprintf (err, errsz,
                               "PR_CAP_AMBIENT_RAISE %s: %s",
                               bc_pd_cap_names[i], strerror (errno));
            return -1;
        }
    }
    return 0;
}

#endif /* BASHCRED_PRIVDROP_H */
