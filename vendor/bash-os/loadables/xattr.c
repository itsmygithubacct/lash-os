/* SPDX-License-Identifier: MIT */
/* xattr.c — extended-attribute syscall wrappers as bash builtins
 * (Stage 29). Wraps {get,set,list,remove}xattr(2) plus the symlink
 * (l*) and fd (f*) variants.
 *
 * Verbs:
 *   xattr read   PATH NAME [-V VAR]    getxattr; print or bind
 *   xattr write  PATH NAME VALUE [-f create|replace]
 *   xattr list   PATH [-V ARR]         listxattr; print one name/line
 *   xattr remove PATH NAME             removexattr
 *
 * Modifiers (place before the verb):
 *   -L     operate on the symlink itself (l*xattr family)
 *   -F FD  operate on a file descriptor (f*xattr family); takes
 *          precedence over PATH (which is then ignored)
 *
 * Notes:
 *   - Values are arbitrary byte sequences. Read returns the raw
 *     bytes; binhex enc/dec handles NUL-containing payloads.
 *   - ENOTSUP (fs lacks xattr support) is distinguished from
 *     ENODATA (named xattr not set on this file).
 *   - `read` retries on ERANGE with a growing buffer (up to 8 rounds),
 *     so a writer racing the size-probe doesn't surface as a user
 *     error. Other errno values bail immediately.
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
#include <limits.h>
#include <sys/xattr.h>

#include "loadables.h"

typedef struct { int symlink_only; int fd_mode; int fd; } bx_opts;

static int
bx_parse_opts (WORD_LIST **plist, bx_opts *o)
{
    o->symlink_only = 0;
    o->fd_mode = 0;
    o->fd = -1;
    WORD_LIST *p = *plist;
    while (p) {
        const char *w = p->word->word;
        if (!strcmp (w, "-L")) { o->symlink_only = 1; p = p->next; }
        else if (!strcmp (w, "-F")) {
            if (!p->next) {
                builtin_error ("-F requires a file descriptor");
                return -1;
            }
            const char *fd_s = p->next->word->word;
            char *end = NULL;
            errno = 0;
            long fd = strtol (fd_s, &end, 10);
            if (fd_s[0] == '\0' || *end != '\0' || errno == ERANGE
                || fd < 0 || fd > INT_MAX) {
                builtin_error ("-F: invalid file descriptor: %s", fd_s);
                return -1;
            }
            o->fd_mode = 1; o->fd = (int) fd;
            p = p->next->next;
        }
        else break;
    }
    *plist = p;
    return 0;
}

static int
bx_read_cmd (bx_opts *o, WORD_LIST *args)
{
    if (!args || (!o->fd_mode && !args->next)) {
        builtin_error ("read: PATH NAME [-V VAR]"); return EX_USAGE;
    }
    const char *path = o->fd_mode ? NULL : args->word->word;
    const char *name = o->fd_mode ? args->word->word : args->next->word->word;
    const char *var = NULL;
    WORD_LIST *p = o->fd_mode ? args->next : args->next->next;
    for (; p; p = p->next) {
        if (!strcmp (p->word->word, "-V") && p->next) {
            var = p->next->word->word; p = p->next;
        }
    }
    /* Size first, then read with ERANGE growth retry. The xattr value
       can grow between the probe and the read (another writer replaces
       it with a longer payload), in which case the read returns
       -1/ERANGE. Old code surfaced that as a hard error; loop instead. */
    ssize_t n;
    if (o->fd_mode)            n = fgetxattr (o->fd, name, NULL, 0);
    else if (o->symlink_only)  n = lgetxattr (path, name, NULL, 0);
    else                       n = getxattr  (path, name, NULL, 0);
    if (n < 0) {
        builtin_error ("getxattr: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    size_t cap = (size_t) n;
    char *buf = NULL;
    int got = 0;
    for (int tries = 0; tries < 8; tries++) {
        char *nb = realloc (buf, cap + 1);
        if (!nb) { free (buf); return EXECUTION_FAILURE; }
        buf = nb;
        if (o->fd_mode)            n = fgetxattr (o->fd, name, buf, cap);
        else if (o->symlink_only)  n = lgetxattr (path, name, buf, cap);
        else                       n = getxattr  (path, name, buf, cap);
        if (n >= 0) { got = 1; break; }
        if (errno != ERANGE) {
            free (buf);
            builtin_error ("getxattr: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        /* ERANGE: value grew under us. Re-probe new size, then grow
           the buffer to at least 2x to avoid livelock under a writer
           that keeps incrementing the value length. */
        ssize_t ns;
        if (o->fd_mode)            ns = fgetxattr (o->fd, name, NULL, 0);
        else if (o->symlink_only)  ns = lgetxattr (path, name, NULL, 0);
        else                       ns = getxattr  (path, name, NULL, 0);
        if (ns < 0) {
            free (buf);
            builtin_error ("getxattr: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        size_t want = ((size_t) ns > cap * 2) ? (size_t) ns : cap * 2;
        cap = want ? want : 1;
    }
    if (!got) {
        free (buf);
        builtin_error ("getxattr: ERANGE retry limit exceeded");
        return EXECUTION_FAILURE;
    }
    buf[n] = '\0';
    if (var) builtin_bind_variable ((char *) var, buf, 0);
    else     fwrite (buf, 1, (size_t) n, stdout);
    free (buf);
    return EXECUTION_SUCCESS;
}

static int
bx_write_cmd (bx_opts *o, WORD_LIST *args)
{
    if (!args || !args->next || (!o->fd_mode && !args->next->next)) {
        builtin_error ("write: PATH NAME VALUE [-f create|replace]"); return EX_USAGE;
    }
    const char *path  = o->fd_mode ? NULL : args->word->word;
    const char *name  = o->fd_mode ? args->word->word : args->next->word->word;
    const char *value = o->fd_mode ? args->next->word->word : args->next->next->word->word;
    int flags = 0;
    WORD_LIST *p = o->fd_mode ? args->next->next : args->next->next->next;
    for (; p; p = p->next) {
        if (!strcmp (p->word->word, "-f") && p->next) {
            const char *f = p->next->word->word;
            if      (!strcmp (f, "create"))  flags = XATTR_CREATE;
            else if (!strcmp (f, "replace")) flags = XATTR_REPLACE;
            p = p->next;
        }
    }
    size_t vlen = strlen (value);
    int rc;
    if (o->fd_mode)            rc = fsetxattr (o->fd, name, value, vlen, flags);
    else if (o->symlink_only)  rc = lsetxattr (path, name, value, vlen, flags);
    else                       rc = setxattr  (path, name, value, vlen, flags);
    if (rc != 0) {
        builtin_error ("setxattr: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bx_list_cmd (bx_opts *o, WORD_LIST *args)
{
    if (!args && !o->fd_mode) {
        builtin_error ("list: PATH [-V ARR]"); return EX_USAGE;
    }
    const char *path = o->fd_mode ? NULL : args->word->word;
    const char *var = NULL;
    for (WORD_LIST *p = o->fd_mode ? args : args->next; p; p = p->next) {
        if (!strcmp (p->word->word, "-V") && p->next) {
            var = p->next->word->word; p = p->next;
        }
    }
    /* Two-call sizing. */
    ssize_t n;
    if (o->fd_mode)            n = flistxattr (o->fd, NULL, 0);
    else if (o->symlink_only)  n = llistxattr (path, NULL, 0);
    else                       n = listxattr  (path, NULL, 0);
    if (n < 0) {
        builtin_error ("listxattr: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (n == 0) {
        if (var) builtin_bind_variable ((char *) var, "", 0);
        return EXECUTION_SUCCESS;
    }
    char *buf = malloc ((size_t) n);
    if (!buf) return EXECUTION_FAILURE;
    if (o->fd_mode)            n = flistxattr (o->fd, buf, (size_t) n);
    else if (o->symlink_only)  n = llistxattr (path, buf, (size_t) n);
    else                       n = listxattr  (path, buf, (size_t) n);
    if (n < 0) {
        free (buf);
        builtin_error ("listxattr: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    /* listxattr returns a NUL-separated list of names. */
    if (var) {
        /* Bind newline-separated names to the variable. */
        char *v = malloc ((size_t) n + 1);
        if (!v) { free (buf); return EXECUTION_FAILURE; }
        size_t v_off = 0;
        for (ssize_t i = 0; i < n; ) {
            size_t l = strlen (buf + i);
            if (v_off) v[v_off++] = '\n';
            memcpy (v + v_off, buf + i, l);
            v_off += l;
            i += (ssize_t) l + 1;
        }
        v[v_off] = '\0';
        builtin_bind_variable ((char *) var, v, 0);
        free (v);
    } else {
        for (ssize_t i = 0; i < n; ) {
            size_t l = strlen (buf + i);
            printf ("%s\n", buf + i);
            i += (ssize_t) l + 1;
        }
    }
    free (buf);
    return EXECUTION_SUCCESS;
}

static int
bx_remove_cmd (bx_opts *o, WORD_LIST *args)
{
    if (!args || (!o->fd_mode && !args->next)) {
        builtin_error ("remove: PATH NAME"); return EX_USAGE;
    }
    const char *path = o->fd_mode ? NULL : args->word->word;
    const char *name = o->fd_mode ? args->word->word : args->next->word->word;
    int rc;
    if (o->fd_mode)            rc = fremovexattr (o->fd, name);
    else if (o->symlink_only)  rc = lremovexattr (path, name);
    else                       rc = removexattr  (path, name);
    if (rc != 0) {
        builtin_error ("removexattr: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

int
xattr_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    bx_opts o;
    if (bx_parse_opts (&list, &o) != 0)
        return EX_USAGE;
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "read"))   return bx_read_cmd   (&o, args);
    if (!strcmp (cmd, "write"))  return bx_write_cmd  (&o, args);
    if (!strcmp (cmd, "list"))   return bx_list_cmd   (&o, args);
    if (!strcmp (cmd, "remove")) return bx_remove_cmd (&o, args);
    builtin_error ("unknown verb: %s (try read/write/list/remove)", cmd);
    return EX_USAGE;
}

char *xattr_doc[] = {
    "Extended attributes via {get,set,list,remove}xattr(2).",
    "",
    "    xattr [-L|-F FD] read   PATH NAME [-V VAR]",
    "    xattr [-L|-F FD] write  PATH NAME VALUE [-f create|replace]",
    "    xattr [-L|-F FD] list   PATH [-V ARR]",
    "    xattr [-L|-F FD] remove PATH NAME",
    "",
    "Modifiers: -L = symlink-no-follow, -F FD = operate on fd",
    "(supersedes PATH).",
    "",
    "ENOTSUP (filesystem unsupported) and ENODATA (xattr unset) are",
    "distinguishable from each other in the surfaced errno. `read`",
    "retries on ERANGE with a growing buffer for racing-writer safety.",
    (char *)NULL
};

struct builtin xattr_struct = {
    "xattr",
    xattr_builtin,
    BUILTIN_ENABLED,
    xattr_doc,
    "xattr [-L|-F FD] read|write|list|remove ARGS",
    0
};
