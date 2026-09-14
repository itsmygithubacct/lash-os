/* SPDX-License-Identifier: MIT */
/* setfacl.c — set POSIX.1e file access control lists, as a bash builtin.
 *
 *   setfacl -m ACL  file...     modify/add entries
 *   setfacl -x ACL  file...     remove entries
 *   setfacl -b      file...     remove all extended ACL entries
 *   setfacl --set ACL file...   replace the ACL entirely
 *
 * ACL spec is a comma list of:  u:user:perms  g:group:perms  u::perms
 * g::perms  o::perms  m::perms  (perms = rwx letters or an octal digit).
 *
 * Reads/writes the system.posix_acl_access xattr; the kernel keeps the file
 * mode in sync. Requires write access (usually ownership) to the file.
 *
 * --- LICENSE --- MIT, same boilerplate as the other bash-os loadables.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <stdint.h>

#include "loadables.h"

#define ACL_USER_OBJ  0x01
#define ACL_USER      0x02
#define ACL_GROUP_OBJ 0x04
#define ACL_GROUP     0x08
#define ACL_MASK      0x10
#define ACL_OTHER     0x20
#define ACL_UNDEFINED_ID  ((uint32_t) -1)
#define XACCESS "system.posix_acl_access"

typedef struct { uint16_t tag; uint16_t perm; uint32_t id; } aclent;

#define MAXENT 256
static aclent ents[MAXENT];
static int nent;

static void wr16 (unsigned char *p, uint16_t v) { p[0]=v&0xff; p[1]=(v>>8)&0xff; }
static void wr32 (unsigned char *p, uint32_t v) { p[0]=v&0xff; p[1]=(v>>8)&0xff; p[2]=(v>>16)&0xff; p[3]=(v>>24)&0xff; }
static uint16_t rd16 (const unsigned char *p) { return (uint16_t)(p[0]|(p[1]<<8)); }
static uint32_t rd32 (const unsigned char *p) { return (uint32_t)(p[0]|(p[1]<<8)|(p[2]<<16)|((uint32_t)p[3]<<24)); }

static void add_or_replace (uint16_t tag, uint32_t id, uint16_t perm) {
    for (int i = 0; i < nent; i++)
        if (ents[i].tag == tag && (tag != ACL_USER && tag != ACL_GROUP ? 1 : ents[i].id == id)) {
            ents[i].perm = perm; return;
        }
    if (nent < MAXENT) { ents[nent].tag = tag; ents[nent].id = id; ents[nent].perm = perm; nent++; }
}
static void remove_ent (uint16_t tag, uint32_t id, int has_id) {
    int w = 0;
    for (int i = 0; i < nent; i++) {
        int match = (ents[i].tag == tag) && (!has_id || ents[i].id == id);
        if (!match) ents[w++] = ents[i];
    }
    nent = w;
}

/* Load the current ACL into ents[]: from the xattr if present, else the three
   base entries from the mode. */
static int load_current (const char *path) {
    nent = 0;
    unsigned char buf[8192];
    ssize_t n = getxattr (path, XACCESS, buf, sizeof buf);
    if (n >= 8 && rd32 (buf) == 2) {
        for (ssize_t off = 4; off + 8 <= n && nent < MAXENT; off += 8) {
            ents[nent].tag = rd16 (buf+off); ents[nent].perm = rd16 (buf+off+2); ents[nent].id = rd32 (buf+off+4); nent++;
        }
        return 0;
    }
    struct stat st;
    if (lstat (path, &st) < 0) return -1;
    add_or_replace (ACL_USER_OBJ,  ACL_UNDEFINED_ID, (st.st_mode>>6)&7);
    add_or_replace (ACL_GROUP_OBJ, ACL_UNDEFINED_ID, (st.st_mode>>3)&7);
    add_or_replace (ACL_OTHER,     ACL_UNDEFINED_ID,  st.st_mode    &7);
    return 0;
}

/* Parse a perm string ("rwx", "r-x", or an octal digit) → bits, or -1. */
static int parse_perm (const char *s) {
    if (s[0] >= '0' && s[0] <= '7' && s[1] == '\0') return s[0]-'0';
    int p = 0;
    for (const char *c = s; *c; c++) {
        switch (*c) {
            case 'r': p |= 4; break; case 'w': p |= 2; break;
            case 'x': p |= 1; break; case '-': break;
            default: return -1;
        }
    }
    return p;
}

/* Parse one ACL entry token. removing=1 means perms may be omitted. */
static int parse_one (char *tok, int removing) {
    /* split on ':' into up to 3 fields */
    char *f[3] = {0,0,0}; int nf = 0;
    char *p = tok;
    f[nf++] = p;
    while (*p && nf < 3) { if (*p == ':') { *p = '\0'; f[nf++] = p+1; } p++; }
    /* also handle the case of trailing ':' giving empty perms */
    const char *type = f[0];
    const char *name = (nf >= 2) ? f[1] : "";
    const char *perms = (nf >= 3) ? f[2] : "";

    uint16_t tag; uint32_t id = ACL_UNDEFINED_ID;
    int named = (name && *name);

    if (!strcmp (type, "u") || !strcmp (type, "user"))       tag = named ? ACL_USER : ACL_USER_OBJ;
    else if (!strcmp (type, "g") || !strcmp (type, "group")) tag = named ? ACL_GROUP : ACL_GROUP_OBJ;
    else if (!strcmp (type, "o") || !strcmp (type, "other")) tag = ACL_OTHER;
    else if (!strcmp (type, "m") || !strcmp (type, "mask"))  tag = ACL_MASK;
    else { builtin_error ("invalid ACL type: %s", type); return -1; }

    if (named) {
        if (tag == ACL_USER) {
            if (name[0] >= '0' && name[0] <= '9') id = (uint32_t) strtoul (name, NULL, 10);
            else { struct passwd *pw = getpwnam (name); if (!pw) { builtin_error ("unknown user: %s", name); return -1; } id = pw->pw_uid; }
        } else if (tag == ACL_GROUP) {
            if (name[0] >= '0' && name[0] <= '9') id = (uint32_t) strtoul (name, NULL, 10);
            else { struct group *gr = getgrnam (name); if (!gr) { builtin_error ("unknown group: %s", name); return -1; } id = gr->gr_gid; }
        }
    }

    if (removing) { remove_ent (tag, id, named); return 0; }

    int perm = parse_perm (perms);
    if (perm < 0) { builtin_error ("invalid permissions: %s", perms); return -1; }
    add_or_replace (tag, id, (uint16_t) perm);
    return 0;
}

static int parse_spec (const char *spec, int removing) {
    char *dup = strdup (spec); if (!dup) return -1;
    int rc = 0;
    char *save = NULL, *tok = strtok_r (dup, ",", &save);
    while (tok) { if (parse_one (tok, removing) < 0) { rc = -1; break; } tok = strtok_r (NULL, ",", &save); }
    free (dup);
    return rc;
}

/* Recompute ACL_MASK as the union of perms over USER/GROUP/GROUP_OBJ when
   named entries exist and no explicit mask is present. */
static void fix_mask (void) {
    int has_named = 0, has_mask = 0; unsigned u = 0;
    for (int i = 0; i < nent; i++) {
        if (ents[i].tag == ACL_USER || ents[i].tag == ACL_GROUP) has_named = 1;
        if (ents[i].tag == ACL_USER || ents[i].tag == ACL_GROUP || ents[i].tag == ACL_GROUP_OBJ) u |= ents[i].perm;
        if (ents[i].tag == ACL_MASK) has_mask = 1;
    }
    if (has_named && !has_mask) add_or_replace (ACL_MASK, ACL_UNDEFINED_ID, (uint16_t) u);
}

static int tag_order (uint16_t t) {
    switch (t) { case ACL_USER_OBJ: return 0; case ACL_USER: return 1; case ACL_GROUP_OBJ: return 2;
                 case ACL_GROUP: return 3; case ACL_MASK: return 4; case ACL_OTHER: return 5; } return 6;
}

static int encode_and_set (const char *path) {
    /* canonical order: USER_OBJ, USER(by id), GROUP_OBJ, GROUP(by id), MASK, OTHER */
    for (int i = 0; i < nent; i++)
        for (int j = i+1; j < nent; j++) {
            int oi = tag_order (ents[i].tag), oj = tag_order (ents[j].tag);
            if (oj < oi || (oj == oi && ents[j].id < ents[i].id)) { aclent t = ents[i]; ents[i] = ents[j]; ents[j] = t; }
        }
    unsigned char buf[4 + MAXENT*8];
    wr32 (buf, 2);
    int off = 4;
    for (int i = 0; i < nent; i++) {
        wr16 (buf+off, ents[i].tag); wr16 (buf+off+2, ents[i].perm); wr32 (buf+off+4, ents[i].id); off += 8;
    }
    if (setxattr (path, XACCESS, buf, off, 0) < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    return 0;
}

int
setfacl_builtin (WORD_LIST *list)
{
    const char *mod = NULL, *del = NULL, *setspec = NULL;
    int do_b = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *setfacl_doc[]; for (char **lp = setfacl_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-m") || !strcmp (w, "--modify")) { if (!list->next){builtin_error("-m requires an argument");return EX_USAGE;} list=list->next; mod=list->word->word; list=list->next; continue; }
        if (!strcmp (w, "-x") || !strcmp (w, "--remove")) { if (!list->next){builtin_error("-x requires an argument");return EX_USAGE;} list=list->next; del=list->word->word; list=list->next; continue; }
        if (!strcmp (w, "--set")) { if (!list->next){builtin_error("--set requires an argument");return EX_USAGE;} list=list->next; setspec=list->word->word; list=list->next; continue; }
        if (!strcmp (w, "-b") || !strcmp (w, "--remove-all")) { do_b = 1; list = list->next; continue; }
        builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE;
    }

    if (!mod && !del && !setspec && !do_b) { builtin_error ("need one of -m, -x, -b, --set"); builtin_usage (); return EX_USAGE; }
    if (!list) { builtin_error ("no files specified"); builtin_usage (); return EX_USAGE; }

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *path = p->word->word;

        if (do_b && !mod && !setspec && !del) {
            /* drop the extended ACL entirely → reverts to the mode bits */
            if (removexattr (path, XACCESS) < 0 && errno != ENODATA) {
                builtin_error ("%s: %s", path, strerror (errno)); rc = EXECUTION_FAILURE;
            }
            continue;
        }

        if (setspec) { nent = 0; if (parse_spec (setspec, 0) < 0) return EXECUTION_FAILURE; }
        else {
            if (load_current (path) < 0) { builtin_error ("%s: %s", path, strerror (errno)); rc = EXECUTION_FAILURE; continue; }
            if (do_b) { /* keep only base entries, then apply -m below */
                int w = 0;
                for (int i = 0; i < nent; i++)
                    if (ents[i].tag == ACL_USER_OBJ || ents[i].tag == ACL_GROUP_OBJ || ents[i].tag == ACL_OTHER) ents[w++] = ents[i];
                nent = w;
            }
            if (del && parse_spec (del, 1) < 0) return EXECUTION_FAILURE;
            if (mod && parse_spec (mod, 0) < 0) return EXECUTION_FAILURE;
        }

        fix_mask ();
        if (encode_and_set (path) < 0) rc = EXECUTION_FAILURE;
    }
    return rc;
}

char *setfacl_doc[] = {
    "Set POSIX.1e file access control lists.",
    "",
    "    setfacl -m ACL file...     add/modify entries",
    "    setfacl -x ACL file...     remove entries",
    "    setfacl -b file...         remove all extended entries",
    "    setfacl --set ACL file...  replace the ACL",
    "",
    "ACL: comma list of u:user:perms g:group:perms u::perms g::perms",
    "     o::perms m::perms  (perms = rwx letters or an octal digit).",
    (char *) NULL
};

struct builtin setfacl_struct = {
    "setfacl",
    setfacl_builtin,
    BUILTIN_ENABLED,
    setfacl_doc,
    "setfacl [-m ACL] [-x ACL] [-b] [--set ACL] file...",
    0
};
