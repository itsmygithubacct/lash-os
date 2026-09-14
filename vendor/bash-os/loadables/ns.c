/* SPDX-License-Identifier: MIT */
/* ns.c — Linux namespace primitives as bash builtins (Stage 28 v1).
 *
 * Wraps unshare(2), setns(2), and the /proc/<pid>/{uid_map,gid_map,
 * setgroups} interfaces so bash can move itself (or about-to-be-fork'd
 * children) into new or existing namespaces.
 *
 * Verbs:
 *   ns unshare FLAGS
 *       FLAGS = comma-separated subset of {pid,mount,net,user,ipc,uts,
 *       cgroup,time}. PID-namespace caveat: this process stays in the
 *       caller's PID-ns; only future children land in the new one.
 *       Same kernel semantics as unshare(1).
 *
 *   ns enter FD
 *       setns(FD, 0). FD must be open against /proc/PID/ns/<name>.
 *
 *   ns list-ns [-V VAR]
 *       Enumerate /proc/self/ns/* — for each namespace type, prints
 *       'TYPE: <inode-id>' (or binds NEWLINE-joined string to VAR).
 *       Lets callers detect whether they're already in a private
 *       namespace before re-unsharing.
 *
 *   ns mount-private
 *       mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL). Cleans up
 *       mount-propagation surprises after `unshare mount` — the
 *       canonical idiom for sandbox setup.
 *
 *   ns remount-readonly PATH
 *       mount(NULL, PATH, NULL, MS_REMOUNT|MS_RDONLY, NULL). Intended
 *       for use after entering a private mount namespace.
 *
 *   ns map-uid INSIDE OUTSIDE LEN
 *       Write 'INSIDE OUTSIDE LEN\n' to /proc/self/uid_map. For
 *       unprivileged user-ns, 'deny-setgroups' must be called first
 *       (kernel safety check enforced at gid_map write time but the
 *       same constraint applies; document for callers).
 *
 *   ns map-gid INSIDE OUTSIDE LEN
 *       Same shape, /proc/self/gid_map.
 *
 *   ns deny-setgroups
 *       Write 'deny' to /proc/self/setgroups. Required before gid_map
 *       in an unprivileged user-ns.
 *
 *   ns bind SRC DST [ro|rw]
 *       Bind-mount SRC at DST inside the current mount namespace.
 *       With "ro", follow up with MS_BIND|MS_REMOUNT|MS_RDONLY (the
 *       kernel silently ignores MS_RDONLY on the initial bind). Used
 *       by sandbox.sh --rw / --ro after `mount-private`.
 *
 *   ns seccomp PROFILE
 *       Read PROFILE as a binary array of struct sock_filter, then
 *       call seccomp(SECCOMP_SET_MODE_FILTER). Caller must have
 *       PR_SET_NO_NEW_PRIVS set or hold CAP_SYS_ADMIN.
 *
 *   ns lsm-detect [-V VAR]
 *       Detect whether AppArmor is available under securityfs. Honors
 *       BASHNS_SECURITYFS_ROOT for host-safe fixture tests.
 *
 *   ns lsm-onexec PROFILE
 *       Arrange an AppArmor transition on the next exec by writing
 *       "exec PROFILE" to /proc/self/attr/apparmor/exec. Honors
 *       BASHNS_PROC_ROOT for host-safe fixture tests.
 *
 *   ns cgroup-create NAME
 *   ns cgroup-set NAME FILE VALUE
 *   ns cgroup-add NAME [PID]
 *   ns cgroup-remove NAME
 *   ns cgroup-enable CONTROLLERS [NAME]
 *       Tiny cgroup v2 helpers for sandbox resource limits. NAME is a
 *       relative cgroup path under /sys/fs/cgroup; FILE is a single
 *       controller file such as memory.max, cpu.max, or pids.max.
 *
 * Security notes:
 *   - unshare USER namespace gives the caller CAP_SYS_ADMIN inside
 *     the new ns. Document the CVE-class escape vectors (run the
 *     subsequent process with --no-new-privs to defang setuid bins).
 *   - All verbs return EPERM cleanly when the kernel forbids the op
 *     for the current credential set; we don't hide errno.
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
#include <fcntl.h>
#include <dirent.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "loadables.h"

/* Bash keeps exported shell variables in its own export_env cache.
   Loadables that exec directly must refresh and pass it explicitly; libc
   environ can lag behind `export NAME=value` performed in the shell. */
extern char **export_env;
extern void maybe_make_export_env (void);
extern int execvpe (const char *, char *const [], char *const []);

/* Stage 23 v1: ns shares the PR_SET_NO_NEW_PRIVS primitive with
   cred + login via the shared header. Internal — ns'
   external `--no-new-privs` flag still works the same way. */
#include "bashcred_privdrop.h"

/* CLONE_NEW* are in <sched.h> on glibc; musl too with _GNU_SOURCE. */
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
#ifndef CLONE_NEWTIME
#  define CLONE_NEWTIME   0x00000080
#endif

static const struct { const char *name; int flag; } bn_ns_flags[] = {
    { "mount",  CLONE_NEWNS     },
    { "uts",    CLONE_NEWUTS    },
    { "ipc",    CLONE_NEWIPC    },
    { "user",   CLONE_NEWUSER   },
    { "pid",    CLONE_NEWPID    },
    { "net",    CLONE_NEWNET    },
    { "cgroup", CLONE_NEWCGROUP },
    /* time namespace (CLONE_NEWTIME, Linux >= 5.6 / util-linux `unshare
       --time`). Like pid, it is a "for_children" namespace: unshare(2)
       sets up time_for_children and the caller stays put. Where the guest
       kernel lacks CONFIG_TIME_NS, unshare(2) returns EINVAL, matching
       unshare(1)'s behavior on the same kernel. */
    { "time",   CLONE_NEWTIME   },
};
#define BN_NS_COUNT (sizeof (bn_ns_flags) / sizeof (bn_ns_flags[0]))

/* Comma-separated list → CLONE_NEW* OR-mask. -1 on unknown name. */
static int
bn_parse_flags (const char *flags, int *out)
{
    *out = 0;
    if (!flags || !strcmp (flags, "NONE") || !strcmp (flags, "none"))
        return 0;
    char buf[256];
    if (strlen (flags) >= sizeof (buf)) return -1;
    strcpy (buf, flags);
    for (char *p = buf, *tok; (tok = strtok (p, ",")); p = NULL) {
        int hit = 0;
        for (size_t i = 0; i < BN_NS_COUNT; i++) {
            if (strcmp (tok, bn_ns_flags[i].name) == 0) {
                *out |= bn_ns_flags[i].flag;
                hit = 1;
                break;
            }
        }
        if (!hit) {
            builtin_error ("unknown namespace: %s "
                           "(try mount/uts/ipc/user/pid/net/cgroup/time)", tok);
            return -1;
        }
    }
    return 0;
}

static int
bn_ns_stat_path (const char *prefix, const char *name, struct stat *st)
{
    char path[80];
    int n = snprintf (path, sizeof path, "%s/%s", prefix, name);
    if (n < 0 || (size_t) n >= sizeof path)
        return -1;
    return stat (path, st);
}

static int
bn_same_ns (const char *left_prefix, const char *left_name,
            const char *right_prefix, const char *right_name,
            int *same)
{
    struct stat left, right;
    if (bn_ns_stat_path (left_prefix, left_name, &left) != 0 ||
        bn_ns_stat_path (right_prefix, right_name, &right) != 0)
        return -1;
    *same = (left.st_dev == right.st_dev && left.st_ino == right.st_ino);
    return 0;
}

static int
bn_filter_idempotent_unshare_flags (int flags)
{
    int filtered = flags;
    int same;

    /* PID namespaces are unusual: unshare(CLONE_NEWPID) only affects
       future children, so a second request in the same shell can be
       detected by pid_for_children already pointing at the pending ns.
       For mount/net/user/etc., comparing against /proc/1 is not a safe
       idempotency baseline inside containers, so preserve normal
       unshare(2) semantics for those flags. */
    if ((flags & CLONE_NEWPID) &&
        bn_same_ns ("/proc/self/ns", "pid",
                    "/proc/self/ns", "pid_for_children", &same) == 0 &&
        !same)
        filtered &= ~CLONE_NEWPID;
    return filtered;
}

static int
bn_unshare_cmd (WORD_LIST *args)
{
    if (!args) {
        builtin_error ("unshare: FLAGS (comma-separated)");
        return EX_USAGE;
    }
    int flags = 0;
    if (bn_parse_flags (args->word->word, &flags) != 0) return EXECUTION_FAILURE;
    flags = bn_filter_idempotent_unshare_flags (flags);
    if (flags == 0)
        return EXECUTION_SUCCESS;
    if (unshare (flags) != 0) {
        builtin_error ("unshare: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bn_enter_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("enter: FD"); return EX_USAGE; }
    int fd = atoi (args->word->word);
    if (setns (fd, 0) != 0) {
        builtin_error ("setns: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

/* Read a /proc/self/ns/X symlink and return the inode-id portion of the
   target (e.g., "mnt:[4026531840]" → "4026531840"). Buffer must be sized
   for the readlink result; out_cap=64 is plenty. */
static int
bn_read_ns_id (const char *name, char *out, size_t out_cap)
{
    char path[64];
    snprintf (path, sizeof (path), "/proc/self/ns/%s", name);
    char target[128];
    ssize_t r = readlink (path, target, sizeof (target) - 1);
    if (r < 0) return -1;
    target[r] = '\0';
    /* Format is "<type>:[<id>]". Extract the id. */
    char *open_b = strchr (target, '[');
    char *close_b = strrchr (target, ']');
    if (!open_b || !close_b || close_b <= open_b + 1) {
        snprintf (out, out_cap, "%s", target);
        return 0;
    }
    size_t l = (size_t) (close_b - (open_b + 1));
    if (l >= out_cap) l = out_cap - 1;
    memcpy (out, open_b + 1, l);
    out[l] = '\0';
    return 0;
}

static int
bn_list_ns_cmd (WORD_LIST *args)
{
    const char *var = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        if (!strcmp (p->word->word, "-V") && p->next) {
            var = p->next->word->word; p = p->next;
        }
    }
    /* Some kernels expose mnt as "mnt" not "mount" in /proc/self/ns/.
       Walk the actual entries instead of a fixed list. */
    DIR *d = opendir ("/proc/self/ns");
    if (!d) {
        builtin_error ("opendir /proc/self/ns: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    char buf[1024]; size_t off = 0;
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char id[64];
        if (bn_read_ns_id (de->d_name, id, sizeof (id)) != 0) continue;
        size_t need = strlen (de->d_name) + 2 + strlen (id) + (off ? 1 : 0);
        if (off + need + 1 > sizeof (buf)) break;
        if (off) buf[off++] = '\n';
        off += (size_t) snprintf (buf + off, sizeof (buf) - off,
                                  "%s: %s", de->d_name, id);
    }
    closedir (d);
    buf[off] = '\0';
    if (var) builtin_bind_variable ((char *) var, buf, 0);
    else printf ("%s\n", buf);
    return EXECUTION_SUCCESS;
}

static const char *
bn_env_or (const char *name, const char *fallback)
{
    const char *v = getenv (name);
    return (v && *v) ? v : fallback;
}

static int
bn_join_path3 (char *out, size_t out_cap, const char *a, const char *b,
               const char *c)
{
    int n = snprintf (out, out_cap, "%s/%s/%s", a, b, c);
    return (n >= 0 && (size_t) n < out_cap) ? 0 : -1;
}

enum bn_lsm_kind {
    BN_LSM_NONE = 0,
    BN_LSM_APPARMOR,
    BN_LSM_SELINUX
};

static const char *
bn_lsm_kind_name (enum bn_lsm_kind kind)
{
    switch (kind) {
    case BN_LSM_APPARMOR: return "apparmor";
    case BN_LSM_SELINUX:  return "selinux";
    case BN_LSM_NONE:
    default:              return "absent";
    }
}

static enum bn_lsm_kind
bn_lsm_detect_kind (void)
{
    char path[512];
    struct stat st;
    const char *aa_root = bn_env_or ("BASHNS_SECURITYFS_ROOT", "/sys/kernel/security");
    if (strlen (aa_root) + strlen ("/apparmor") < sizeof path) {
        snprintf (path, sizeof path, "%s/apparmor", aa_root);
        if (stat (path, &st) == 0 && S_ISDIR (st.st_mode))
            return BN_LSM_APPARMOR;
    }

    const char *se_root = bn_env_or ("BASHNS_SELINUXFS_ROOT", "/sys/fs/selinux");
    if (strlen (se_root) + strlen ("/enforce") < sizeof path) {
        snprintf (path, sizeof path, "%s/enforce", se_root);
        if (stat (path, &st) == 0)
            return BN_LSM_SELINUX;
    }

    return BN_LSM_NONE;
}

static int
bn_apparmor_available (void)
{
    return bn_lsm_detect_kind () == BN_LSM_APPARMOR;
}

static int
bn_lsm_detect_cmd (WORD_LIST *args)
{
    const char *var = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        if (!strcmp (p->word->word, "-V") && p->next) {
            var = p->next->word->word;
            p = p->next;
        } else {
            builtin_error ("lsm-detect: [-V VAR]");
            return EX_USAGE;
        }
    }
    enum bn_lsm_kind kind = bn_lsm_detect_kind ();
    const char *kind_name = bn_lsm_kind_name (kind);
    if (var)
        builtin_bind_variable ((char *) var, (char *) kind_name, 0);
    else
        printf ("%s: %s\n", kind == BN_LSM_NONE ? "none" : kind_name,
                kind == BN_LSM_NONE ? "absent" : "available");
    return EXECUTION_SUCCESS;
}

static int
bn_lsm_attr_path (enum bn_lsm_kind kind, char *out, size_t out_cap)
{
    const char *proc = bn_env_or ("BASHNS_PROC_ROOT", "/proc");
    char aa[512];
    if (kind == BN_LSM_APPARMOR &&
        bn_join_path3 (aa, sizeof aa, proc, "self/attr/apparmor", "exec") == 0) {
        struct stat st;
        if (stat (aa, &st) == 0) {
            snprintf (out, out_cap, "%s", aa);
            return strlen (aa) < out_cap ? 0 : -1;
        }
    }
    return bn_join_path3 (out, out_cap, proc, "self/attr", "exec");
}

static int
bn_lsm_onexec_apply (const char *profile, char *err, size_t err_cap)
{
    if (!profile || !*profile || strchr (profile, '\n')) {
        snprintf (err, err_cap, "lsm-onexec: PROFILE must be non-empty and newline-free");
        return -1;
    }
    enum bn_lsm_kind kind = bn_lsm_detect_kind ();
    if (kind == BN_LSM_NONE) {
        snprintf (err, err_cap,
                  "lsm-onexec: no supported LSM available under %s or %s",
                  bn_env_or ("BASHNS_SECURITYFS_ROOT", "/sys/kernel/security"),
                  bn_env_or ("BASHNS_SELINUXFS_ROOT", "/sys/fs/selinux"));
        return -1;
    }

    char path[512];
    if (bn_lsm_attr_path (kind, path, sizeof path) != 0) {
        snprintf (err, err_cap, "lsm-onexec: proc attr path too long");
        return -1;
    }

    int fd = open (path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf (err, err_cap, "lsm-onexec: open %s: %s", path, strerror (errno));
        return -1;
    }
    struct stat st;
    if (fstat (fd, &st) == 0 && S_ISREG (st.st_mode))
        ftruncate (fd, 0);

    char line[512];
    int n;
    if (kind == BN_LSM_APPARMOR)
        n = snprintf (line, sizeof line, "exec %s", profile);
    else
        n = snprintf (line, sizeof line, "%s", profile);
    if (n < 0 || (size_t) n >= sizeof line) {
        close (fd);
        snprintf (err, err_cap, "lsm-onexec: PROFILE too long");
        return -1;
    }
    size_t off = 0, len = (size_t) n;
    while (off < len) {
        ssize_t w = write (fd, line + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            snprintf (err, err_cap, "lsm-onexec: write %s: %s", path, strerror (errno));
            close (fd);
            return -1;
        }
        off += (size_t) w;
    }
    close (fd);
    return 0;
}

static int
bn_lsm_onexec_cmd (WORD_LIST *args)
{
    if (!args) {
        builtin_error ("lsm-onexec: PROFILE");
        return EX_USAGE;
    }
    char err[512];
    if (bn_lsm_onexec_apply (args->word->word, err, sizeof err) != 0) {
        builtin_error ("%s", err);
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bn_mount_private_cmd (WORD_LIST *args)
{
    (void) args;
    if (mount (NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        builtin_error ("mount(/, MS_REC|MS_PRIVATE): %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bn_remount_readonly_cmd (WORD_LIST *args)
{
    if (!args) {
        builtin_error ("remount-readonly: PATH");
        return EX_USAGE;
    }
    const char *path = args->word->word;
    if (mount (NULL, path, NULL, MS_REMOUNT | MS_RDONLY, NULL) == 0)
        return EXECUTION_SUCCESS;

    int saved_errno = errno;
    if (saved_errno == EBUSY || saved_errno == EINVAL) {
        if (mount (path, path, NULL, MS_BIND | MS_REC, NULL) == 0 &&
            mount (NULL, path, NULL,
                   MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL) == 0)
            return EXECUTION_SUCCESS;
        saved_errno = errno;
    }
    builtin_error ("remount-readonly(%s): %s", path, strerror (saved_errno));
    return EXECUTION_FAILURE;
}

#define BN_CGROUP_ROOT "/sys/fs/cgroup"

static int
bn_valid_relpath (const char *s)
{
    if (!s || !*s || s[0] == '/')
        return 0;
    if (!strcmp (s, "."))
        return 1;
    char buf[256];
    if (strlen (s) >= sizeof buf)
        return 0;
    strcpy (buf, s);
    for (char *p = buf, *tok; (tok = strtok (p, "/")); p = NULL) {
        if (!strcmp (tok, ".") || !strcmp (tok, "..") || !*tok)
            return 0;
    }
    return 1;
}

static int
bn_valid_cgroup_file (const char *s)
{
    return s && *s && !strchr (s, '/') && strcmp (s, ".") && strcmp (s, "..");
}

static int
bn_cgroup_path (const char *name, const char *file, char *out, size_t out_cap)
{
    if (!bn_valid_relpath (name))
        return -1;
    if (file && !bn_valid_cgroup_file (file))
        return -1;
    int n;
    if (!strcmp (name, "."))
        n = file ? snprintf (out, out_cap, "%s/%s", BN_CGROUP_ROOT, file)
                 : snprintf (out, out_cap, "%s", BN_CGROUP_ROOT);
    else
        n = file ? snprintf (out, out_cap, "%s/%s/%s", BN_CGROUP_ROOT, name, file)
                 : snprintf (out, out_cap, "%s/%s", BN_CGROUP_ROOT, name);
    return (n >= 0 && (size_t) n < out_cap) ? 0 : -1;
}

static int
bn_mkdir_p (const char *path)
{
    char tmp[512];
    if (strlen (path) >= sizeof tmp)
        return -1;
    strcpy (tmp, path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir (tmp, 0755) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    if (mkdir (tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int
bn_write_text_file (const char *path, const char *value)
{
    int fd = open (path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        builtin_error ("open %s: %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    char line[512];
    int n = snprintf (line, sizeof line, "%s\n", value);
    if (n < 0 || (size_t) n >= sizeof line) {
        close (fd);
        builtin_error ("write %s: value too long", path);
        return EX_USAGE;
    }
    size_t off = 0, len = (size_t) n;
    while (off < len) {
        ssize_t w = write (fd, line + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            builtin_error ("write %s: %s", path, strerror (errno));
            close (fd);
            return EXECUTION_FAILURE;
        }
        off += (size_t) w;
    }
    close (fd);
    return EXECUTION_SUCCESS;
}

static int
bn_cgroup_create_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("cgroup-create: NAME"); return EX_USAGE; }
    char path[512];
    if (bn_cgroup_path (args->word->word, NULL, path, sizeof path) != 0) {
        builtin_error ("cgroup-create: NAME must be relative under %s", BN_CGROUP_ROOT);
        return EX_USAGE;
    }
    if (bn_mkdir_p (path) != 0) {
        builtin_error ("mkdir %s: %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bn_cgroup_set_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next) {
        builtin_error ("cgroup-set: NAME FILE VALUE");
        return EX_USAGE;
    }
    char path[512];
    if (bn_cgroup_path (args->word->word, args->next->word->word,
                        path, sizeof path) != 0) {
        builtin_error ("cgroup-set: invalid NAME or FILE");
        return EX_USAGE;
    }
    return bn_write_text_file (path, args->next->next->word->word);
}

static int
bn_cgroup_add_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("cgroup-add: NAME [PID]"); return EX_USAGE; }
    char path[512], pidbuf[32];
    const char *pid = args->next ? args->next->word->word : pidbuf;
    if (!args->next)
        snprintf (pidbuf, sizeof pidbuf, "%ld", (long) getpid ());
    if (bn_cgroup_path (args->word->word, "cgroup.procs", path, sizeof path) != 0) {
        builtin_error ("cgroup-add: invalid NAME");
        return EX_USAGE;
    }
    return bn_write_text_file (path, pid);
}

static int
bn_cgroup_remove_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("cgroup-remove: NAME"); return EX_USAGE; }
    char path[512];
    if (bn_cgroup_path (args->word->word, NULL, path, sizeof path) != 0) {
        builtin_error ("cgroup-remove: NAME must be relative under %s", BN_CGROUP_ROOT);
        return EX_USAGE;
    }
    if (rmdir (path) != 0) {
        builtin_error ("rmdir %s: %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bn_cgroup_enable_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("cgroup-enable: CONTROLLERS [NAME]"); return EX_USAGE; }
    const char *name = args->next ? args->next->word->word : ".";
    char path[512], value[256];
    if (bn_cgroup_path (name, "cgroup.subtree_control", path, sizeof path) != 0) {
        builtin_error ("cgroup-enable: invalid NAME");
        return EX_USAGE;
    }
    value[0] = '\0';
    char spec[128];
    if (strlen (args->word->word) >= sizeof spec) {
        builtin_error ("cgroup-enable: controller list too long");
        return EX_USAGE;
    }
    strcpy (spec, args->word->word);
    for (char *p = spec, *tok; (tok = strtok (p, ",")); p = NULL) {
        if (!*tok || strchr (tok, '/') || strchr (tok, ' ') || strchr (tok, '\t')) {
            builtin_error ("cgroup-enable: invalid controller '%s'", tok);
            return EX_USAGE;
        }
        if (strlen (value) + strlen (tok) + 3 >= sizeof value) {
            builtin_error ("cgroup-enable: controller list too long");
            return EX_USAGE;
        }
        if (value[0]) strcat (value, " ");
        strcat (value, "+");
        strcat (value, tok);
    }
    return bn_write_text_file (path, value);
}

/* Write 'INSIDE OUTSIDE LEN\n' to the named map file. */
static int
bn_write_map (const char *path, const char *inside, const char *outside,
              const char *len)
{
    int fd = open (path, O_WRONLY);
    if (fd < 0) {
        builtin_error ("open %s: %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    char line[64];
    int n = snprintf (line, sizeof (line), "%s %s %s\n", inside, outside, len);
    if (n < 0 || n >= (int) sizeof (line)) {
        close (fd);
        builtin_error ("map line too long");
        return EXECUTION_FAILURE;
    }
    ssize_t w = write (fd, line, (size_t) n);
    close (fd);
    if (w != n) {
        builtin_error ("write %s: %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bn_map_uid_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next) {
        builtin_error ("map-uid: INSIDE OUTSIDE LEN"); return EX_USAGE;
    }
    return bn_write_map ("/proc/self/uid_map",
                         args->word->word,
                         args->next->word->word,
                         args->next->next->word->word);
}

static int
bn_map_gid_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next) {
        builtin_error ("map-gid: INSIDE OUTSIDE LEN"); return EX_USAGE;
    }
    return bn_write_map ("/proc/self/gid_map",
                         args->word->word,
                         args->next->word->word,
                         args->next->next->word->word);
}

/* Stage 28: ns spawn FLAGS CMD [ARGS...] — clone(2) into a new
 * namespace and exec CMD. Unlike unshare(), the child IS in the new
 * namespaces from the start, so CLONE_NEWPID makes the child PID 1
 * of the new pidns (the way real container runtimes do it).
 *
 * Implementation uses raw SYS_clone with `flags | SIGCHLD` so the
 * caller still gets a normal SIGCHLD on child exit. CLONE_VM is
 * NOT set — the child has its own memory, like fork(). The child
 * refreshes Bash's export_env, runs execvpe() with that env, and exits
 * 127 on exec failure; the parent waits and propagates the child's exit
 * code.
 *
 * Caveat: cloning with CLONE_NEWUSER from an unprivileged caller
 * grants CAP_SYS_ADMIN inside the new ns. Pair with caps to
 * drop bounding-set caps before exec for defense in depth.
 */
static int
bn_spawn_cmd (WORD_LIST *args)
{
    /* Optional leading flags:
       --no-new-privs calls prctl(PR_SET_NO_NEW_PRIVS,1)
       in the child before exec, defanging setuid binaries inside the new
       namespaces. Recommended whenever CLONE_NEWUSER is in FLAGS (the user-ns
       grants CAP_SYS_ADMIN, which combined with a setuid binary in the
       inherited mount tree is a classic escape vector). Fixes 2026-05-07
       security review Medium ("ns spawn does not apply no_new_privs").

       --apparmor/--lsm-onexec, or the leading positional alias
       lsm PROFILE, writes the LSM onexec transition in the child after
       no-new-privs and before execvpe(). */
    int nnp = 0;
    int prop = 0;               /* mount-propagation flag (MS_PRIVATE/SLAVE/SHARED), 0 = unchanged */
    const char *apparmor_profile = NULL;
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "lsm")) {
            if (!args->next) {
                builtin_error ("spawn: lsm needs PROFILE");
                return EX_USAGE;
            }
            apparmor_profile = args->next->word->word;
            args = args->next->next;
            continue;
        }
        if (!(w[0] == '-' && w[1] == '-'))
            break;
        if (!strcmp (w, "--no-new-privs")) {
            nnp = 1;
            args = args->next;
            continue;
        }
        if (!strcmp (w, "--propagation")) {
            if (!args->next) {
                builtin_error ("spawn: --propagation needs MODE");
                return EX_USAGE;
            }
            const char *m = args->next->word->word;
            if (!strcmp (m, "private"))        prop = MS_PRIVATE;
            else if (!strcmp (m, "slave"))     prop = MS_SLAVE;
            else if (!strcmp (m, "shared"))    prop = MS_SHARED;
            else if (!strcmp (m, "unchanged")) prop = 0;
            else {
                builtin_error ("spawn: unsupported --propagation mode %s", m);
                return EX_USAGE;
            }
            args = args->next->next;
            continue;
        }
        if (!strcmp (w, "--apparmor") || !strcmp (w, "--lsm-onexec")) {
            if (!args->next) {
                builtin_error ("spawn: %s needs PROFILE", w);
                return EX_USAGE;
            }
            apparmor_profile = args->next->word->word;
            args = args->next->next;
            continue;
        }
        if (!strcmp (w, "--")) { args = args->next; break; }
        builtin_error ("spawn: unknown option %s", w);
        return EX_USAGE;
    }

    if (!args || !args->next) {
        builtin_error ("spawn: [lsm PROFILE] [--no-new-privs] [--apparmor PROFILE] FLAGS CMD [ARGS...]");
        return EX_USAGE;
    }
    int flags = 0;
    if (bn_parse_flags (args->word->word, &flags) != 0) return EXECUTION_FAILURE;
    args = args->next;

    /* Build argv for execvpe. WORD_LIST is a singly-linked list; count
       first, then allocate. */
    int argc = 0;
    for (WORD_LIST *p = args; p; p = p->next) argc++;
    char **argv = calloc ((size_t) argc + 1, sizeof (char *));
    if (!argv) {
        builtin_error ("calloc: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    int i = 0;
    for (WORD_LIST *p = args; p; p = p->next) argv[i++] = p->word->word;
    argv[argc] = NULL;

    /* Bash installs an async SIGCHLD handler for job control. If that
       handler reaps this child before our waitpid(), spawn reports
       ECHILD instead of the service exit status. Temporarily reset it
       around clone+wait; the child inherits the default disposition
       too, which is the normal exec behavior for SIGCHLD. */
    struct sigaction chld_dfl, chld_save;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &chld_save);
    sigset_t chld_set, old_set;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    if (sigprocmask (SIG_BLOCK, &chld_set, &old_set) < 0) {
        sigaction (SIGCHLD, &chld_save, NULL);
        free (argv);
        return EXECUTION_FAILURE;
    }

    /* Raw clone() syscall: flags | SIGCHLD gives fork-like semantics
       (parent receives SIGCHLD on child exit). The child returns 0;
       parent gets the child PID. */
    pid_t pid = (pid_t) syscall (SYS_clone, (long) (flags | SIGCHLD),
                                 (void *) NULL, (void *) NULL,
                                 (void *) NULL, 0L);
    if (pid < 0) {
        builtin_error ("clone: %s", strerror (errno));
        sigprocmask (SIG_SETMASK, &old_set, NULL);
        sigaction (SIGCHLD, &chld_save, NULL);
        free (argv);
        return EXECUTION_FAILURE;
    }
    if (pid == 0) {
        sigprocmask (SIG_SETMASK, &old_set, NULL);
        /* Child: optionally set mount propagation on the new mount
           namespace root (util-linux `unshare --propagation MODE`
           semantics), before no-new-privs / exec. Only meaningful when
           CLONE_NEWNS is in FLAGS; harmless otherwise. */
        if (prop != 0) {
            if (mount (NULL, "/", NULL, (unsigned long) (MS_REC | prop),
                       NULL) != 0) {
                fprintf (stderr, "ns spawn: propagation mount(/): %s\n",
                         strerror (errno));
                _exit (127);
            }
        }
        /* Child: optionally raise PR_SET_NO_NEW_PRIVS, then exec. The
           prctl is irrevocable and inherited across exec, neutralizing
           setuid bits + file caps in any descendant. Stage 23 v1: route
           through bc_no_new_privs so cred / ns / future
           callers all run the same body. */
        if (nnp) {
            char err[BC_PD_ERR_MAX];
            if (bc_no_new_privs (err, sizeof err) < 0) {
                fprintf (stderr, "ns spawn: %s\n",
                         err[0] ? err : strerror (errno));
                _exit (127);
            }
        }
        if (apparmor_profile) {
            char err[512];
            if (bn_lsm_onexec_apply (apparmor_profile, err, sizeof err) != 0) {
                fprintf (stderr, "ns spawn: %s\n",
                         err[0] ? err : "lsm-onexec failed");
                _exit (127);
            }
        }
        maybe_make_export_env ();
        execvpe (argv[0], argv, export_env);
        /* execvpe only returns on failure. */
        fprintf (stderr, "ns spawn: execvpe %s: %s\n",
                 argv[0], strerror (errno));
        _exit (127);
    }
    /* Parent: wait for child to finish, propagate exit code. */
    free (argv);
    int status = 0;
    while (waitpid (pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        builtin_error ("waitpid: %s", strerror (errno));
        sigprocmask (SIG_SETMASK, &old_set, NULL);
        sigaction (SIGCHLD, &chld_save, NULL);
        return EXECUTION_FAILURE;
    }
    sigprocmask (SIG_SETMASK, &old_set, NULL);
    sigaction (SIGCHLD, &chld_save, NULL);
    if (WIFEXITED (status)) return WEXITSTATUS (status);
    if (WIFSIGNALED (status)) return 128 + WTERMSIG (status);
    return EXECUTION_FAILURE;
}

/* Stage 28: ns pivot-root NEW OLD — wraps pivot_root(2). Only
 * valid AFTER unshare(CLONE_NEWNS) when standing on a mount that
 * contains both NEW and OLD. The kernel enforces several
 * prerequisites (NEW + OLD must be on different mounts, not bind
 * mounts of /, etc.); we surface kernel errno verbatim instead of
 * mapping to a curated set since the spec is the authority. Used
 * by container-init scripts to swap into a fresh root after
 * mounting an image. */
static int
bn_pivot_root_cmd (WORD_LIST *args)
{
    if (!args || !args->next) {
        builtin_error ("pivot-root: NEW OLD");
        return EX_USAGE;
    }
    const char *new_root = args->word->word;
    const char *put_old  = args->next->word->word;
    if (syscall (SYS_pivot_root, new_root, put_old) != 0) {
        builtin_error ("pivot_root(%s, %s): %s",
                       new_root, put_old, strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

/* Stage 28.E: ns bind SRC DST [ro|rw]
 *
 * Bind-mounts SRC at DST. The third arg, when "ro", does a follow-up
 * remount with MS_BIND|MS_REMOUNT|MS_RDONLY (the kernel requires the
 * two-step dance for a read-only bind — MS_RDONLY on the initial bind
 * is silently ignored). Default is read-write.
 *
 * Both paths must exist before the call. For files SRC must be a
 * regular file and DST must be a regular file (typically created with
 * `touch` beforehand). For directories both must be directories.
 *
 * Used by sandbox.sh's --rw / --ro flags; runs inside the sandbox's
 * mount namespace AFTER `ns mount-private` so the bind cannot
 * leak back to the host's mount propagation graph.
 */
static int
bn_bind_cmd (WORD_LIST *args)
{
    int read_only = 0;
    if (!args || !args->next) {
        builtin_error ("bind: SRC DST [ro|rw]");
        return EX_USAGE;
    }
    const char *src = args->word->word;
    const char *dst = args->next->word->word;
    WORD_LIST *mode = args->next->next;
    if (mode) {
        if (!strcmp (mode->word->word, "ro"))      read_only = 1;
        else if (!strcmp (mode->word->word, "rw")) read_only = 0;
        else {
            builtin_error ("bind: mode must be ro or rw, got '%s'",
                           mode->word->word);
            return EX_USAGE;
        }
    }
    if (mount (src, dst, NULL, MS_BIND | MS_REC, NULL) != 0) {
        builtin_error ("bind(%s -> %s): %s", src, dst, strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (read_only) {
        if (mount (NULL, dst, NULL,
                   MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL) != 0) {
            int saved = errno;
            /* Best-effort teardown of the bind we just laid down so we
               don't leave a writable surface that the caller thinks is
               read-only. umount2(MNT_DETACH) so we don't block on
               EBUSY from any process that may have raced into the
               mount point. */
            umount2 (dst, MNT_DETACH);
            builtin_error ("bind remount-ro(%s): %s", dst, strerror (saved));
            return EXECUTION_FAILURE;
        }
    }
    return EXECUTION_SUCCESS;
}

/* Stage 28.E: ns seccomp PROFILE
 *
 * Loads a raw BPF filter program from PROFILE and applies it via
 * seccomp(SECCOMP_SET_MODE_FILTER). PROFILE is a binary file whose
 * contents are an array of `struct sock_filter` (8 bytes per
 * instruction on Linux). The kernel cap is 4096 instructions
 * (BPF_MAXINSNS); we enforce the same and emit a clear error
 * instead of letting the kernel return EINVAL.
 *
 * Why raw bytes and not a high-level DSL: keeps the loadable tiny,
 * matches the kernel-facing format exactly, and lets profile
 * authoring be its own tool (a separate compiler script can emit
 * the binary). The simplest useful profile — "allow everything" —
 * is 8 bytes:
 *
 *     struct sock_filter prog[] = {
 *         BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
 *     };
 *
 * which encodes as the byte sequence  06 00 00 00  00 00 ff 7f.
 *
 * The caller must have PR_SET_NO_NEW_PRIVS set OR CAP_SYS_ADMIN.
 * sandbox.sh defaults --no-new-privs ON, so unprivileged seccomp
 * Just Works under the wrapper.
 */
static int
bn_seccomp_cmd (WORD_LIST *args)
{
    if (!args) {
        builtin_error ("seccomp: PROFILE");
        return EX_USAGE;
    }
    const char *path = args->word->word;
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        builtin_error ("seccomp: open %s: %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    struct stat st;
    if (fstat (fd, &st) != 0) {
        builtin_error ("seccomp: stat %s: %s", path, strerror (errno));
        close (fd);
        return EXECUTION_FAILURE;
    }
    if (st.st_size <= 0 || (st.st_size % (off_t) sizeof (struct sock_filter)) != 0) {
        builtin_error ("seccomp: profile %s has bad size %lld "
                       "(must be a non-empty multiple of %zu)",
                       path, (long long) st.st_size,
                       sizeof (struct sock_filter));
        close (fd);
        return EXECUTION_FAILURE;
    }
    size_t insn_count = (size_t) st.st_size / sizeof (struct sock_filter);
    if (insn_count > BPF_MAXINSNS) {
        builtin_error ("seccomp: profile %s has %zu insns, kernel cap is %u",
                       path, insn_count, (unsigned) BPF_MAXINSNS);
        close (fd);
        return EXECUTION_FAILURE;
    }
    struct sock_filter *insns = calloc (insn_count, sizeof (struct sock_filter));
    if (!insns) {
        builtin_error ("seccomp: calloc: %s", strerror (errno));
        close (fd);
        return EXECUTION_FAILURE;
    }
    size_t want = insn_count * sizeof (struct sock_filter);
    char *p = (char *) insns;
    while (want) {
        ssize_t r = read (fd, p, want);
        if (r < 0) {
            if (errno == EINTR) continue;
            builtin_error ("seccomp: read %s: %s", path, strerror (errno));
            free (insns); close (fd);
            return EXECUTION_FAILURE;
        }
        if (r == 0) {
            builtin_error ("seccomp: short read on %s", path);
            free (insns); close (fd);
            return EXECUTION_FAILURE;
        }
        p += r; want -= (size_t) r;
    }
    close (fd);

    struct sock_fprog prog = {
        .len    = (unsigned short) insn_count,
        .filter = insns,
    };

    /* Prefer the seccomp(2) syscall over prctl(PR_SET_SECCOMP, ...).
       The syscall lets the kernel synchronize the filter across all
       threads in TSYNC mode (we don't use TSYNC here — sandbox.sh
       applies the filter pre-exec in a single-threaded child) and is
       the documented interface for new code. Glibc may not wrap it
       on musl-cross-make builds, so we go through syscall(2). */
    long rc = syscall (SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
    if (rc != 0) {
        int saved = errno;
        free (insns);
        /* EINVAL with mode-filter usually means "kernel built without
           CONFIG_SECCOMP_FILTER" or "caller is missing both
           NO_NEW_PRIVS and CAP_SYS_ADMIN". Surface errno so the
           caller can disambiguate. */
        builtin_error ("seccomp(SET_MODE_FILTER): %s", strerror (saved));
        return EXECUTION_FAILURE;
    }
    /* Filter is now installed in the kernel; the userspace copy is
       no longer needed. */
    free (insns);
    return EXECUTION_SUCCESS;
}

static int
bn_deny_setgroups_cmd (WORD_LIST *args)
{
    (void) args;
    int fd = open ("/proc/self/setgroups", O_WRONLY);
    if (fd < 0) {
        builtin_error ("open /proc/self/setgroups: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    ssize_t w = write (fd, "deny", 4);
    close (fd);
    if (w != 4) {
        builtin_error ("write setgroups: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

int
ns_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "unshare"))         return bn_unshare_cmd       (args);
    if (!strcmp (cmd, "enter"))           return bn_enter_cmd         (args);
    if (!strcmp (cmd, "list-ns"))         return bn_list_ns_cmd       (args);
    if (!strcmp (cmd, "mount-private"))   return bn_mount_private_cmd (args);
    if (!strcmp (cmd, "remount-readonly")) return bn_remount_readonly_cmd (args);
    if (!strcmp (cmd, "map-uid"))         return bn_map_uid_cmd       (args);
    if (!strcmp (cmd, "map-gid"))         return bn_map_gid_cmd       (args);
    if (!strcmp (cmd, "deny-setgroups"))  return bn_deny_setgroups_cmd (args);
    if (!strcmp (cmd, "spawn"))           return bn_spawn_cmd          (args);
    if (!strcmp (cmd, "pivot-root"))      return bn_pivot_root_cmd     (args);
    if (!strcmp (cmd, "bind"))            return bn_bind_cmd           (args);
    if (!strcmp (cmd, "seccomp"))         return bn_seccomp_cmd        (args);
    if (!strcmp (cmd, "lsm-detect"))      return bn_lsm_detect_cmd     (args);
    if (!strcmp (cmd, "lsm-onexec"))      return bn_lsm_onexec_cmd     (args);
    if (!strcmp (cmd, "cgroup-create"))   return bn_cgroup_create_cmd  (args);
    if (!strcmp (cmd, "cgroup-set"))      return bn_cgroup_set_cmd     (args);
    if (!strcmp (cmd, "cgroup-add"))      return bn_cgroup_add_cmd     (args);
    if (!strcmp (cmd, "cgroup-remove"))   return bn_cgroup_remove_cmd  (args);
    if (!strcmp (cmd, "cgroup-enable"))   return bn_cgroup_enable_cmd  (args);
    builtin_error ("unknown verb: %s "
                   "(try unshare/enter/list-ns/mount-private/"
                   "remount-readonly/map-uid/map-gid/deny-setgroups/"
                   "spawn [lsm PROFILE]/pivot-root/bind/seccomp/lsm-detect/lsm-onexec/cgroup-create/"
                   "cgroup-set/cgroup-add/cgroup-remove/cgroup-enable)", cmd);
    return EX_USAGE;
}

char *ns_doc[] = {
    "Linux namespace primitives — unshare, setns, ns enumeration.",
    "",
    "    ns unshare FLAGS         FLAGS ∈ comma-list of",
    "        {mount,uts,ipc,user,pid,net,cgroup,time}. pid/time are",
    "        for-children: only future children land in the new ns.",
    "    ns enter FD              setns(FD, 0). FD must be opened",
    "        on /proc/PID/ns/<name>.",
    "    ns list-ns [-V VAR]      Lines of 'TYPE: inode-id'",
    "        from /proc/self/ns/*.",
    "    ns mount-private         mount(/, MS_REC|MS_PRIVATE, ...).",
    "        Use after `unshare mount` to defang propagation.",
    "    ns remount-readonly PATH",
    "        Remount PATH read-only inside the current mount namespace.",
    "    ns map-uid INSIDE OUTSIDE LEN",
    "    ns map-gid INSIDE OUTSIDE LEN",
    "    ns deny-setgroups        Required before gid_map in an",
    "        unprivileged user-ns.",
    "    ns spawn [lsm PROFILE] [--no-new-privs] [--apparmor PROFILE] FLAGS CMD [ARGS...]",
    "        clone(2) into a new namespace and exec CMD. With",
    "        --no-new-privs the child sets PR_SET_NO_NEW_PRIVS",
    "        before exec, neutralizing setuid + file caps for the",
    "        whole subtree (recommended whenever FLAGS includes user).",
    "        lsm PROFILE (or --apparmor/--lsm-onexec PROFILE) arranges",
    "        an LSM onexec transition immediately before the child execs CMD.",
    "    ns bind SRC DST [ro|rw]",
    "        mount --bind SRC at DST. ro applies a second remount",
    "        with MS_BIND|MS_REMOUNT|MS_RDONLY (the kernel ignores",
    "        MS_RDONLY on the initial bind).",
    "    ns seccomp PROFILE",
    "        Load PROFILE (a binary file of struct sock_filter",
    "        instructions, 8 bytes each) and apply via",
    "        seccomp(SECCOMP_SET_MODE_FILTER). Caller must have",
    "        PR_SET_NO_NEW_PRIVS or CAP_SYS_ADMIN.",
    "    ns lsm-detect [-V VAR]",
    "        Report LSM support as 'apparmor: available',",
    "        'selinux: available', or 'none: absent'. -V binds the kind",
    "        word. BASHNS_SECURITYFS_ROOT and BASHNS_SELINUXFS_ROOT can",
    "        point tests at fixture trees.",
    "    ns lsm-onexec PROFILE",
    "        AppArmor writes 'exec PROFILE'; SELinux writes bare PROFILE",
    "        to /proc/self/attr/exec for the next exec. BASHNS_PROC_ROOT",
    "        can point tests at a fixture tree.",
    "    ns cgroup-create NAME",
    "    ns cgroup-set NAME FILE VALUE",
    "    ns cgroup-add NAME [PID]",
    "    ns cgroup-remove NAME",
    "    ns cgroup-enable CONTROLLERS [NAME]",
    "        Manage cgroup v2 paths under /sys/fs/cgroup.",
    "",
    "Pairs with caps (Stage 27) and cred (Stage 23) for",
    "container-style sandbox setup.",
    (char *)NULL
};

struct builtin ns_struct = {
    "ns",
    ns_builtin,
    BUILTIN_ENABLED,
    ns_doc,
    "ns unshare|enter|list-ns|mount-private|remount-readonly|map-uid|map-gid|deny-setgroups|spawn [lsm PROFILE]|pivot-root|bind|seccomp|lsm-detect|lsm-onexec|cgroup-create|cgroup-set|cgroup-add|cgroup-remove|cgroup-enable ARGS",
    0
};
