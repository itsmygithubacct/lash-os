/* SPDX-License-Identifier: MIT */
/* caps.c — fine-grained Linux capabilities as bash builtins (Stage 27).
 *
 * Wraps capget(2) / capset(2) (via the legacy header-define ABI) plus
 * prctl(PR_CAPBSET_*) and prctl(PR_CAP_AMBIENT_*) for runtime cap
 * inspection / manipulation. Pairs with cred (Stage 23) which
 * drops the entire bounding set; caps gives per-cap control.
 *
 * Verbs:
 *   caps probe [-V VAR]
 *       Bind a 5-element array: permitted, effective, inheritable,
 *       ambient, bounding. Each element is a comma-separated list of
 *       cap names that are currently set. Without -V, prints one
 *       'set: name1,name2,...' line per set.
 *
 *   caps drop SET CAP1,CAP2,...
 *       Remove named caps from named SET. SET ∈
 *       {permitted,effective,inheritable,ambient,bounding}. Kernel
 *       forbids dropping from {permitted,effective} of root via this
 *       path on most kernels — surface that as an error.
 *
 *   caps add SET CAP1,CAP2,...
 *       Add caps to SET. Only valid for {inheritable,ambient}. Other
 *       sets reject with 'kernel forbids raising'.
 *
 *   caps clear SET
 *       Drop all caps from SET (equivalent to `drop SET <full-list>`).
 *
 *   caps file PATH [-V VAR]
 *       Read /usr/include/linux/capability.h-shaped vfs_cap data via
 *       the security.capability xattr. Print or bind decoded form
 *       'permitted=...,inheritable=...,effective=N'.
 *
 *   caps has CAP
 *       Exit rc 0 iff CAP is in current process's effective set.
 *
 * Implementation notes:
 *   - No libcap dependency. Uses syscall(SYS_capset) + the legacy
 *     header struct (data version _LINUX_CAPABILITY_VERSION_3).
 *   - Bounding set is per-thread; PR_CAPBSET_DROP is one-way.
 *   - Ambient set is per-thread; require permitted+inheritable to
 *     have the cap before raising it ambient.
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
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/xattr.h>
#include <linux/capability.h>

#include "loadables.h"

/* Cap name table — Linux 6.12 set. CAP_LAST_CAP = 41 = CAP_CHECKPOINT_RESTORE.
   Indexing matches the kernel's bit numbers exactly: caps[N] is CAP N. */
static const char *bc_cap_names[] = {
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
#define BC_CAP_LAST 40                  /* index of last entry above */
#define BC_CAP_COUNT (BC_CAP_LAST + 1)

/* Map a name (with or without CAP_ prefix, case-insensitive) → index, or -1. */
static int
bc_cap_lookup (const char *name)
{
    /* Skip leading "CAP_" if present. */
    const char *base = name;
    if (strncasecmp (base, "CAP_", 4) == 0) base += 4;
    for (int i = 0; i < BC_CAP_COUNT; i++) {
        const char *n = bc_cap_names[i] + 4;     /* skip "CAP_" */
        if (strcasecmp (n, base) == 0) return i;
    }
    return -1;
}

/* Use 64-bit cap masks throughout — _LINUX_CAPABILITY_VERSION_3 has
   two 32-bit u32 entries which we coalesce to one uint64_t. */

static int
bc_capget (uint64_t *eff, uint64_t *prm, uint64_t *inh)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (syscall (SYS_capget, &hdr, data) != 0) return -1;
    *eff = ((uint64_t) data[1].effective   << 32) | data[0].effective;
    *prm = ((uint64_t) data[1].permitted   << 32) | data[0].permitted;
    *inh = ((uint64_t) data[1].inheritable << 32) | data[0].inheritable;
    return 0;
}

static int
bc_capset (uint64_t eff, uint64_t prm, uint64_t inh)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    data[0].effective   = (uint32_t) (eff & 0xFFFFFFFF);
    data[1].effective   = (uint32_t) (eff >> 32);
    data[0].permitted   = (uint32_t) (prm & 0xFFFFFFFF);
    data[1].permitted   = (uint32_t) (prm >> 32);
    data[0].inheritable = (uint32_t) (inh & 0xFFFFFFFF);
    data[1].inheritable = (uint32_t) (inh >> 32);
    return syscall (SYS_capset, &hdr, data);
}

/* PR_CAPBSET_READ for bounding: query cap-by-cap. Returns 0/1/-1. */
static int
bc_bounding_has (int cap)
{
    int r = prctl (PR_CAPBSET_READ, (unsigned long) cap, 0, 0, 0);
    return r;
}

static int
bc_ambient_has (int cap)
{
    int r = prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET,
                   (unsigned long) cap, 0, 0);
    return r;
}

/* Build the bounding set bitmask by querying every cap. */
static uint64_t
bc_bounding_mask (void)
{
    uint64_t m = 0;
    for (int i = 0; i < BC_CAP_COUNT; i++) {
        if (bc_bounding_has (i) == 1) m |= ((uint64_t) 1 << i);
    }
    return m;
}

static uint64_t
bc_ambient_mask (void)
{
    uint64_t m = 0;
    for (int i = 0; i < BC_CAP_COUNT; i++) {
        if (bc_ambient_has (i) == 1) m |= ((uint64_t) 1 << i);
    }
    return m;
}

/* Format a 64-bit mask as comma-separated cap names, into out (size cap). */
static void
bc_mask_to_names (uint64_t mask, char *out, size_t cap)
{
    out[0] = '\0';
    size_t off = 0;
    for (int i = 0; i < BC_CAP_COUNT; i++) {
        if (!(mask & ((uint64_t) 1 << i))) continue;
        const char *name = bc_cap_names[i];
        size_t need = strlen (name) + (off ? 1 : 0);
        if (off + need + 1 > cap) break;       /* truncate quietly */
        if (off) out[off++] = ',';
        memcpy (out + off, name, strlen (name));
        off += strlen (name);
        out[off] = '\0';
    }
}

/* Comma-separated list of names → bitmask. Returns -1 on unknown name. */
static int
bc_names_to_mask (const char *names, uint64_t *out)
{
    *out = 0;
    char buf[1024];
    if (strlen (names) >= sizeof (buf)) return -1;
    strcpy (buf, names);
    for (char *p = buf, *tok; (tok = strtok (p, ",")); p = NULL) {
        int idx = bc_cap_lookup (tok);
        if (idx < 0) {
            builtin_error ("unknown capability: %s", tok);
            return -1;
        }
        *out |= ((uint64_t) 1 << idx);
    }
    return 0;
}

static int
bc_probe_cmd (WORD_LIST *args)
{
    const char *var = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        if (!strcmp (p->word->word, "-V") && p->next) {
            var = p->next->word->word; p = p->next;
        }
    }
    uint64_t eff = 0, prm = 0, inh = 0;
    if (bc_capget (&eff, &prm, &inh) != 0) {
        builtin_error ("capget: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    uint64_t amb = bc_ambient_mask ();
    uint64_t bnd = bc_bounding_mask ();
    char p_names[1024], e_names[1024], i_names[1024];
    char a_names[1024], b_names[1024];
    bc_mask_to_names (prm, p_names, sizeof (p_names));
    bc_mask_to_names (eff, e_names, sizeof (e_names));
    bc_mask_to_names (inh, i_names, sizeof (i_names));
    bc_mask_to_names (amb, a_names, sizeof (a_names));
    bc_mask_to_names (bnd, b_names, sizeof (b_names));
    if (var) {
        /* Bind a 5-element associative array via SHELL_VAR. Simpler:
           bind 5 separate variables VAR_permitted etc. */
        char vname[64];
        snprintf (vname, sizeof (vname), "%s_permitted",   var); builtin_bind_variable (vname, p_names, 0);
        snprintf (vname, sizeof (vname), "%s_effective",   var); builtin_bind_variable (vname, e_names, 0);
        snprintf (vname, sizeof (vname), "%s_inheritable", var); builtin_bind_variable (vname, i_names, 0);
        snprintf (vname, sizeof (vname), "%s_ambient",     var); builtin_bind_variable (vname, a_names, 0);
        snprintf (vname, sizeof (vname), "%s_bounding",    var); builtin_bind_variable (vname, b_names, 0);
    } else {
        printf ("permitted: %s\n",   p_names);
        printf ("effective: %s\n",   e_names);
        printf ("inheritable: %s\n", i_names);
        printf ("ambient: %s\n",     a_names);
        printf ("bounding: %s\n",    b_names);
    }
    return EXECUTION_SUCCESS;
}

/* drop / add: SET CAP1,CAP2,... */
static int
bc_modify_cmd (int adding, WORD_LIST *args)
{
    if (!args || !args->next) {
        builtin_error ("%s: SET CAP1,CAP2,...", adding ? "add" : "drop");
        return EX_USAGE;
    }
    const char *set = args->word->word;
    const char *list = args->next->word->word;
    uint64_t mask = 0;
    if (bc_names_to_mask (list, &mask) != 0) return EXECUTION_FAILURE;

    if (!strcmp (set, "bounding")) {
        if (adding) {
            builtin_error ("kernel forbids raising bounding set"); return EX_USAGE;
        }
        for (int i = 0; i < BC_CAP_COUNT; i++) {
            if (!(mask & ((uint64_t) 1 << i))) continue;
            if (prctl (PR_CAPBSET_DROP, (unsigned long) i, 0, 0, 0) != 0) {
                builtin_error ("PR_CAPBSET_DROP %s: %s",
                               bc_cap_names[i], strerror (errno));
                return EXECUTION_FAILURE;
            }
        }
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (set, "ambient")) {
        for (int i = 0; i < BC_CAP_COUNT; i++) {
            if (!(mask & ((uint64_t) 1 << i))) continue;
            int op = adding ? PR_CAP_AMBIENT_RAISE : PR_CAP_AMBIENT_LOWER;
            if (prctl (PR_CAP_AMBIENT, op, (unsigned long) i, 0, 0) != 0) {
                builtin_error ("PR_CAP_AMBIENT %s %s: %s",
                               adding ? "RAISE" : "LOWER",
                               bc_cap_names[i], strerror (errno));
                return EXECUTION_FAILURE;
            }
        }
        return EXECUTION_SUCCESS;
    }
    /* permitted / effective / inheritable: capset path. */
    uint64_t eff = 0, prm = 0, inh = 0;
    if (bc_capget (&eff, &prm, &inh) != 0) {
        builtin_error ("capget: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (!strcmp (set, "permitted")) {
        if (adding) { builtin_error ("kernel forbids raising permitted"); return EX_USAGE; }
        prm &= ~mask; eff &= ~mask; inh &= ~mask;     /* dropping permitted clears the others too */
    } else if (!strcmp (set, "effective")) {
        if (adding) { builtin_error ("kernel forbids raising effective"); return EX_USAGE; }
        eff &= ~mask;
    } else if (!strcmp (set, "inheritable")) {
        if (adding) inh |= mask; else inh &= ~mask;
    } else {
        builtin_error ("%s: unknown set (try permitted/effective/inheritable/ambient/bounding)", set);
        return EX_USAGE;
    }
    if (bc_capset (eff, prm, inh) != 0) {
        builtin_error ("capset: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bc_clear_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("clear: SET"); return EX_USAGE; }
    const char *set = args->word->word;
    /* "clear all" — drop bounding first (needs CAP_SETPCAP in effective),
       then ambient, then permitted/effective/inheritable. Doing this in
       any other order silently no-ops the bounding-drop because clearing
       permitted also wipes effective. */
    if (!strcmp (set, "all")) {
        for (int i = 0; i < BC_CAP_COUNT; i++) {
            if (prctl (PR_CAPBSET_DROP, (unsigned long) i, 0, 0, 0) != 0) {
                builtin_error ("clear all: drop bounding %s: %s",
                               bc_cap_names[i], strerror (errno));
                return EXECUTION_FAILURE;
            }
        }
        for (int i = 0; i < BC_CAP_COUNT; i++)
            (void) prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER,
                          (unsigned long) i, 0, 0);
        if (bc_capset (0, 0, 0) != 0) {
            builtin_error ("capset: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (set, "bounding")) {
        for (int i = 0; i < BC_CAP_COUNT; i++) {
            if (prctl (PR_CAPBSET_DROP, (unsigned long) i, 0, 0, 0) != 0) {
                builtin_error ("clear bounding: drop %s: %s",
                               bc_cap_names[i], strerror (errno));
                return EXECUTION_FAILURE;
            }
        }
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (set, "ambient")) {
        for (int i = 0; i < BC_CAP_COUNT; i++)
            (void) prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER,
                          (unsigned long) i, 0, 0);
        return EXECUTION_SUCCESS;
    }
    uint64_t eff = 0, prm = 0, inh = 0;
    if (bc_capget (&eff, &prm, &inh) != 0) {
        builtin_error ("capget: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (!strcmp (set, "permitted"))   { prm = 0; eff = 0; inh = 0; }
    else if (!strcmp (set, "effective"))   eff = 0;
    else if (!strcmp (set, "inheritable")) inh = 0;
    else {
        builtin_error ("clear: unknown set: %s", set); return EX_USAGE;
    }
    if (bc_capset (eff, prm, inh) != 0) {
        builtin_error ("capset: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

/* file: read security.capability xattr. The struct vfs_cap_data layout
   is documented in <linux/capability.h>: u32 magic_etc + 2× (u32 permitted, u32 inheritable). */
static int
bc_file_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("file: PATH [-V VAR]"); return EX_USAGE; }
    const char *path = args->word->word;
    const char *var = NULL;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        if (!strcmp (p->word->word, "-V") && p->next) {
            var = p->next->word->word; p = p->next;
        }
    }
    /* vfs_cap_data v3 is 24 bytes: magic_etc + 2× cap_data[2] + rootid. */
    char buf[64];
    ssize_t n = getxattr (path, "security.capability", buf, sizeof (buf));
    if (n < 0) {
        /* ENODATA = no security.capability xattr set on this file.
           ENOTSUP = filesystem doesn't support xattrs (ramfs, vfat).
           Both translate to 'no file caps' from a caller's perspective —
           the binary won't gain caps via fs-cap exec. Surface as success
           with empty payload. */
        if (errno == ENODATA || errno == ENOTSUP) {
            char out[8] = "";
            if (var) builtin_bind_variable ((char *) var, out, 0);
            else printf ("(no file caps)\n");
            return EXECUTION_SUCCESS;
        }
        builtin_error ("getxattr security.capability: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (n < 12) {
        builtin_error ("malformed vfs_cap_data: %zd bytes", n);
        return EXECUTION_FAILURE;
    }
    uint32_t magic;
    memcpy (&magic, buf, 4);
    /* VFS_CAP_REVISION_2 = 0x02000000; v3 = 0x03000000. Effective bit = 0x01. */
    int effective = (magic & 0x01) ? 1 : 0;
    uint32_t perm0 = 0, perm1 = 0, inh0 = 0, inh1 = 0;
    memcpy (&perm0, buf + 4,  4);
    memcpy (&inh0,  buf + 8,  4);
    if (n >= 20) {
        memcpy (&perm1, buf + 12, 4);
        memcpy (&inh1,  buf + 16, 4);
    }
    uint64_t prm = ((uint64_t) perm1 << 32) | perm0;
    uint64_t inh = ((uint64_t) inh1  << 32) | inh0;
    char p_names[1024], i_names[1024];
    bc_mask_to_names (prm, p_names, sizeof (p_names));
    bc_mask_to_names (inh, i_names, sizeof (i_names));
    char out[3072];
    snprintf (out, sizeof (out), "permitted=%s,inheritable=%s,effective=%d",
              p_names, i_names, effective);
    if (var) builtin_bind_variable ((char *) var, out, 0);
    else printf ("%s\n", out);
    return EXECUTION_SUCCESS;
}

static int
bc_has_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("has: CAP"); return EX_USAGE; }
    int idx = bc_cap_lookup (args->word->word);
    if (idx < 0) {
        builtin_error ("unknown capability: %s", args->word->word);
        return EX_USAGE;
    }
    uint64_t eff = 0, prm = 0, inh = 0;
    if (bc_capget (&eff, &prm, &inh) != 0) {
        builtin_error ("capget: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return (eff & ((uint64_t) 1 << idx)) ? EXECUTION_SUCCESS : 1;
}

int
caps_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "probe")) return bc_probe_cmd (args);
    if (!strcmp (cmd, "drop"))  return bc_modify_cmd (0, args);
    if (!strcmp (cmd, "add"))   return bc_modify_cmd (1, args);
    if (!strcmp (cmd, "clear")) return bc_clear_cmd (args);
    if (!strcmp (cmd, "file"))  return bc_file_cmd (args);
    if (!strcmp (cmd, "has"))   return bc_has_cmd (args);
    builtin_error ("unknown verb: %s (try probe/drop/add/clear/file/has)", cmd);
    return EX_USAGE;
}

char *caps_doc[] = {
    "Linux per-process capabilities — read, drop, add, clear sets.",
    "",
    "    caps probe [-V VAR]",
    "        Bind <VAR>_{permitted,effective,inheritable,ambient,bounding}",
    "        to comma-separated cap names; print 5-line table without -V.",
    "    caps drop SET CAP1,CAP2,...   SET ∈ {permitted,effective,",
    "        inheritable,ambient,bounding}. Kernel forbids dropping",
    "        permitted/effective on most kernels — surfaces error.",
    "    caps add SET CAP1,CAP2,...    Only inheritable+ambient",
    "        accept add; raising permitted/effective is impossible.",
    "    caps clear SET                Drop every cap from SET.",
    "    caps clear all                Drop every cap from every set",
    "        (bounding → ambient → permitted/effective/inheritable, in the",
    "        only order that survives the loss of CAP_SETPCAP).",
    "    caps file PATH [-V VAR]       Decode security.capability",
    "        xattr → 'permitted=...,inheritable=...,effective=N'.",
    "    caps has CAP                  rc 0 if CAP in effective set.",
    "",
    "Pairs with cred (Stage 23) for whole-bounding-set drop and",
    "with xattr (Stage 29) for raw xattr access.",
    (char *)NULL
};

struct builtin caps_struct = {
    "caps",
    caps_builtin,
    BUILTIN_ENABLED,
    caps_doc,
    "caps probe|drop|add|clear|file|has ARGS",
    0
};
