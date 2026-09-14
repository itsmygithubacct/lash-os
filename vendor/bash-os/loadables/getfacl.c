/* SPDX-License-Identifier: MIT */
/* getfacl.c — display POSIX.1e file access control lists, as a bash builtin.
 *
 *   getfacl [-a] [-d] [--omit-header] [-p] file...
 *
 *   -a            access ACL only (default shows access ACL)
 *   -d            show the default ACL (directories)
 *   --omit-header suppress the "# file/owner/group" comment header
 *
 * Reads the system.posix_acl_access xattr; if the file has no extended ACL
 * the three base entries are synthesised from the mode bits, exactly like
 * getfacl(1).
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

static uint16_t rd16 (const unsigned char *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32 (const unsigned char *p) { return (uint32_t)(p[0] | (p[1]<<8) | (p[2]<<16) | ((uint32_t)p[3]<<24)); }

static void
perm_str (unsigned p, char out[4])
{
    out[0] = (p & 4) ? 'r' : '-';
    out[1] = (p & 2) ? 'w' : '-';
    out[2] = (p & 1) ? 'x' : '-';
    out[3] = '\0';
}

static void
print_entry (uint16_t tag, uint16_t perm, uint32_t id)
{
    char ps[4]; perm_str (perm, ps);
    switch (tag) {
        case ACL_USER_OBJ:  printf ("user::%s\n", ps); break;
        case ACL_GROUP_OBJ: printf ("group::%s\n", ps); break;
        case ACL_MASK:      printf ("mask::%s\n", ps); break;
        case ACL_OTHER:     printf ("other::%s\n", ps); break;
        case ACL_USER: {
            struct passwd *pw = getpwuid ((uid_t) id);
            if (pw) printf ("user:%s:%s\n", pw->pw_name, ps);
            else    printf ("user:%u:%s\n", id, ps);
            break;
        }
        case ACL_GROUP: {
            struct group *gr = getgrgid ((gid_t) id);
            if (gr) printf ("group:%s:%s\n", gr->gr_name, ps);
            else    printf ("group:%u:%s\n", id, ps);
            break;
        }
    }
}

static int
show_file (const char *path, int omit_header, int want_default)
{
    struct stat st;
    if (lstat (path, &st) < 0) { builtin_error ("%s: %s", path, strerror (errno)); return -1; }

    if (!omit_header) {
        struct passwd *pw = getpwuid (st.st_uid);
        struct group  *gr = getgrgid (st.st_gid);
        printf ("# file: %s\n", path);
        if (pw) printf ("# owner: %s\n", pw->pw_name); else printf ("# owner: %u\n", st.st_uid);
        if (gr) printf ("# group: %s\n", gr->gr_name); else printf ("# group: %u\n", st.st_gid);
    }

    const char *xname = want_default ? "system.posix_acl_default" : "system.posix_acl_access";
    unsigned char buf[8192];
    ssize_t n = getxattr (path, xname, buf, sizeof buf);

    if (n >= 8 && rd32 (buf) == 2) {
        /* decode binary entries (8 bytes each after the 4-byte version) */
        for (ssize_t off = 4; off + 8 <= n; off += 8)
            print_entry (rd16 (buf + off), rd16 (buf + off + 2), rd32 (buf + off + 4));
    } else if (!want_default) {
        /* no extended ACL → synthesise the three base entries from the mode */
        char ps[4];
        perm_str ((st.st_mode >> 6) & 7, ps); printf ("user::%s\n", ps);
        perm_str ((st.st_mode >> 3) & 7, ps); printf ("group::%s\n", ps);
        perm_str ( st.st_mode       & 7, ps); printf ("other::%s\n", ps);
    }
    printf ("\n");
    return 0;
}

int
getfacl_builtin (WORD_LIST *list)
{
    int omit_header = 0, want_default = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *getfacl_doc[]; for (char **lp = getfacl_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-a") || !strcmp (w, "--access")) { want_default = 0; list = list->next; continue; }
        if (!strcmp (w, "-d") || !strcmp (w, "--default")) { want_default = 1; list = list->next; continue; }
        if (!strcmp (w, "-c") || !strcmp (w, "--omit-header")) { omit_header = 1; list = list->next; continue; }
        /* -p/--absolute-names controls leading-'/' stripping in the "# file:"
           name, NOT the header — it must NOT suppress the header (GNU getfacl). */
        if (!strcmp (w, "-p") || !strcmp (w, "--absolute-names")) { list = list->next; continue; }
        builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE;
    }

    if (!list) { builtin_error ("no files specified"); builtin_usage (); return EX_USAGE; }
    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next)
        if (show_file (p->word->word, omit_header, want_default) < 0) rc = EXECUTION_FAILURE;
    return rc;
}

char *getfacl_doc[] = {
    "Display POSIX.1e file access control lists.",
    "",
    "    getfacl [-a] [-d] [--omit-header] file...",
    "",
    "    -a  access ACL (default)   -d  default ACL (directories)",
    "    --omit-header  suppress the # file/owner/group header",
    "",
    "Files with no extended ACL show base entries derived from the mode.",
    (char *) NULL
};

struct builtin getfacl_struct = {
    "getfacl",
    getfacl_builtin,
    BUILTIN_ENABLED,
    getfacl_doc,
    "getfacl [-a] [-d] [--omit-header] file...",
    0
};
