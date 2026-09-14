/* SPDX-License-Identifier: MIT */
/* scm.c — Unix-domain socket FD passing via SCM_RIGHTS.
 *
 * Phase C-1 (multiplexer prereq). poll already gives socket /
 * accept / connect / wait / signalfd, but does NOT support
 * sendmsg/recvmsg with SCM_RIGHTS ancillary data. scm fills the gap:
 * the bash-screen multiplexer engine uses it to hand a pty master fd
 * from the server process to a client process across the daemon socket.
 *
 * Verbs:
 *   scm pair [-h FDVAR1] [-h FDVAR2]
 *       socketpair(AF_UNIX, SOCK_DGRAM); two endpoints. Bind to FDVARs
 *       (or print "<fd1> <fd2>").
 *
 *   scm listen PATH [-h FDVAR]
 *       AF_UNIX SOCK_DGRAM bound to PATH. Returns listening FD.
 *       (DGRAM not STREAM — ancillary data + datagrams pair naturally;
 *       no listen()/accept() needed.)
 *
 *   scm connect PATH [-h FDVAR]
 *       AF_UNIX SOCK_DGRAM connected to PATH.
 *
 *   scm send-fd SOCK_FD MSG_FD [DATA]
 *       Send MSG_FD over SOCK_FD via SCM_RIGHTS. Optional DATA bytes
 *       go in the message body (often a 1-byte sentinel — needed
 *       because some kernels reject ancillary-only sends).
 *
 *   scm recv-fd SOCK_FD [-h FDVAR] [-V DATAVAR]
 *       Receive one fd from SOCK_FD, bind to FDVAR. Body bytes (if
 *       any) bind to DATAVAR.
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
#include <limits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "loadables.h"

/* Safe stale-socket helper (security review 2026-05-07 #1).
 * The previous unconditional `unlink(path)` could destroy any
 * filesystem entry the caller had write access to. Now: lstat first,
 * accept missing path, accept S_IFSOCK (stale Unix socket), refuse
 * everything else. Caller passes `verb` for the error message.
 * Returns 0 on success (path now ready for bind), -1 on refusal. */
static int
bs_safe_unlink_socket (const char *path, const char *verb)
{
    struct stat st;
    if (lstat (path, &st) < 0) {
        if (errno == ENOENT) return 0;            /* nothing to remove */
        builtin_error ("%s: lstat %s: %s", verb, path, strerror (errno));
        return -1;
    }
    if (!S_ISSOCK (st.st_mode)) {
        builtin_error ("%s: refusing to unlink non-socket %s "
                       "(mode=0%o); pick a different path or remove it manually",
                       verb, path, (unsigned) (st.st_mode & 07777));
        return -1;
    }
    if (unlink (path) < 0 && errno != ENOENT) {
        builtin_error ("%s: unlink %s: %s", verb, path, strerror (errno));
        return -1;
    }
    return 0;
}

static int
bs_emit_fd (int fd, const char *fdvar)
{
    char buf[32];
    snprintf (buf, sizeof buf, "%d", fd);
    if (fdvar) {
        if (!builtin_bind_variable ((char *) fdvar, buf, 0)) {
            builtin_error ("could not bind: %s", fdvar);
            close (fd);
            return -1;
        }
    } else {
        printf ("%d\n", fd);
    }
    return 0;
}

static int
bs_parse_id (const char *s, unsigned long long max, unsigned long long *out)
{
    char *end = NULL;
    unsigned long long v;
    if (!s || !*s) return -1;
    errno = 0;
    v = strtoull (s, &end, 10);
    if (errno || !end || end == s || *end || v > max)
        return -1;
    *out = v;
    return 0;
}

static int
bs_check_peer_cred (int sock_fd, int want_uid, uid_t uid,
                    int want_gid, gid_t gid, int want_pid, pid_t pid)
{
#ifdef SO_PEERCRED
    struct ucred cred;
    socklen_t len = sizeof cred;

    if (!want_uid && !want_gid && !want_pid)
        return 0;
    if (getsockopt (sock_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0) {
        builtin_error ("recv-fd: SO_PEERCRED: %s", strerror (errno));
        return -1;
    }
    if (len < sizeof cred) {
        builtin_error ("recv-fd: SO_PEERCRED returned short credentials");
        return -1;
    }
    if (want_uid && cred.uid != uid) {
        builtin_error ("recv-fd: peer uid mismatch (got %lu, want %lu)",
                       (unsigned long) cred.uid, (unsigned long) uid);
        return -1;
    }
    if (want_gid && cred.gid != gid) {
        builtin_error ("recv-fd: peer gid mismatch (got %lu, want %lu)",
                       (unsigned long) cred.gid, (unsigned long) gid);
        return -1;
    }
    if (want_pid && cred.pid != pid) {
        builtin_error ("recv-fd: peer pid mismatch (got %ld, want %ld)",
                       (long) cred.pid, (long) pid);
        return -1;
    }
    return 0;
#else
    (void) sock_fd; (void) uid; (void) gid; (void) pid;
    if (want_uid || want_gid || want_pid) {
        builtin_error ("recv-fd: peer credential checks unavailable on this platform");
        return -1;
    }
    return 0;
#endif
}

static int
bs_check_fd_type (int fd, int want_tty, int want_regular, int want_socket)
{
    struct stat st;
    if (!want_tty && !want_regular && !want_socket)
        return 0;
    if (fstat (fd, &st) < 0) {
        builtin_error ("recv-fd: fstat received fd: %s", strerror (errno));
        return -1;
    }
    if (want_tty && !isatty (fd)) {
        builtin_error ("recv-fd: received fd is not a tty");
        return -1;
    }
    if (want_regular && !S_ISREG (st.st_mode)) {
        builtin_error ("recv-fd: received fd is not a regular file");
        return -1;
    }
    if (want_socket && !S_ISSOCK (st.st_mode)) {
        builtin_error ("recv-fd: received fd is not a socket");
        return -1;
    }
    return 0;
}

static int
bs_pair_cmd (WORD_LIST *args)
{
    const char *v1 = NULL, *v2 = NULL;
    int seen = 0;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-h") == 0 && p->next) {
            if (seen == 0) v1 = p->next->word->word;
            else if (seen == 1) v2 = p->next->word->word;
            else { builtin_error ("pair: max 2 -h vars"); builtin_usage (); return EX_USAGE; }
            seen++;
            p = p->next;
        } else {
            builtin_error ("pair: unexpected '%s'", w);
            builtin_usage ();
            return EX_USAGE;
        }
    }
    int sv[2];
    if (socketpair (AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv) < 0) {
        builtin_error ("socketpair: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (v1 && v2) {
        if (bs_emit_fd (sv[0], v1) < 0) { close (sv[1]); return EXECUTION_FAILURE; }
        if (bs_emit_fd (sv[1], v2) < 0) return EXECUTION_FAILURE;
    } else {
        printf ("%d %d\n", sv[0], sv[1]);
    }
    return EXECUTION_SUCCESS;
}

static int
bs_listen_cmd (WORD_LIST *args)
{
    const char *path = NULL, *fdvar = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-h") == 0 && p->next) { fdvar = p->next->word->word; p = p->next; }
        else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("listen: unknown flag %s", w); builtin_usage (); return EX_USAGE;
        } else {
            if (path) { builtin_error ("listen: too many args"); builtin_usage (); return EX_USAGE; }
            path = w;
        }
    }
    if (!path) { builtin_error ("listen: PATH required"); builtin_usage (); return EX_USAGE; }
    if (strlen (path) >= sizeof ((struct sockaddr_un *)0)->sun_path) {
        builtin_error ("listen: PATH too long"); builtin_usage (); return EX_USAGE;
    }
    int fd = socket (AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf (addr.sun_path, sizeof addr.sun_path, "%s", path);
    if (bs_safe_unlink_socket (path, "listen") < 0) {
        close (fd);
        return EXECUTION_FAILURE;
    }
    if (bind (fd, (struct sockaddr *) &addr, sizeof addr) < 0) {
        builtin_error ("bind %s: %s", path, strerror (errno));
        close (fd); return EXECUTION_FAILURE;
    }
    return bs_emit_fd (fd, fdvar) < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bs_connect_cmd (WORD_LIST *args)
{
    const char *path = NULL, *fdvar = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-h") == 0 && p->next) { fdvar = p->next->word->word; p = p->next; }
        else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("connect: unknown flag %s", w); builtin_usage (); return EX_USAGE;
        } else {
            if (path) { builtin_error ("connect: too many args"); builtin_usage (); return EX_USAGE; }
            path = w;
        }
    }
    if (!path) { builtin_error ("connect: PATH required"); builtin_usage (); return EX_USAGE; }
    int fd = socket (AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf (addr.sun_path, sizeof addr.sun_path, "%s", path);
    if (connect (fd, (struct sockaddr *) &addr, sizeof addr) < 0) {
        builtin_error ("connect %s: %s", path, strerror (errno));
        close (fd); return EXECUTION_FAILURE;
    }
    return bs_emit_fd (fd, fdvar) < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bs_send_fd_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("send-fd: SOCK_FD MSG_FD [DATA]"); builtin_usage (); return EX_USAGE; }
    int sock_fd = atoi (args->word->word);
    int msg_fd  = atoi (args->next->word->word);
    const char *data = args->next->next ? args->next->next->word->word : "F";
    size_t dlen = strlen (data);
    if (dlen == 0) { data = "F"; dlen = 1; }  /* must send some payload */

    struct iovec iov = { .iov_base = (void *) data, .iov_len = dlen };
    char cbuf[CMSG_SPACE (sizeof (int))];
    memset (cbuf, 0, sizeof cbuf);

    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof cbuf;

    struct cmsghdr *cm = CMSG_FIRSTHDR (&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN (sizeof (int));
    memcpy (CMSG_DATA (cm), &msg_fd, sizeof (int));

    ssize_t n = sendmsg (sock_fd, &msg, 0);
    if (n < 0) {
        builtin_error ("sendmsg: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bs_recv_fd_cmd (WORD_LIST *args)
{
    if (!args) {
        builtin_error ("recv-fd: SOCK_FD [-h FDVAR] [-V DATAVAR] [--peer-uid UID] [--peer-gid GID] [--peer-pid PID] [--token DATA] [--fd-tty|--fd-regular|--fd-socket]");
        builtin_usage ();
        return EX_USAGE;
    }
    int sock_fd = atoi (args->word->word);
    const char *fdvar = NULL, *datavar = NULL;
    const char *token = NULL;
    int want_uid = 0, want_gid = 0, want_pid = 0;
    int want_tty = 0, want_regular = 0, want_socket = 0;
    uid_t peer_uid = 0;
    gid_t peer_gid = 0;
    pid_t peer_pid = 0;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-h") == 0 && p->next) { fdvar = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-V") == 0 && p->next) { datavar = p->next->word->word; p = p->next; }
        else if (strcmp (w, "--token") == 0 && p->next) { token = p->next->word->word; p = p->next; }
        else if (strcmp (w, "--peer-uid") == 0 && p->next) {
            unsigned long long v;
            if (bs_parse_id (p->next->word->word, (unsigned long long) UINT_MAX, &v) < 0)
                { builtin_error ("recv-fd: bad --peer-uid"); builtin_usage (); return EX_USAGE; }
            want_uid = 1; peer_uid = (uid_t) v; p = p->next;
        }
        else if (strcmp (w, "--peer-gid") == 0 && p->next) {
            unsigned long long v;
            if (bs_parse_id (p->next->word->word, (unsigned long long) UINT_MAX, &v) < 0)
                { builtin_error ("recv-fd: bad --peer-gid"); builtin_usage (); return EX_USAGE; }
            want_gid = 1; peer_gid = (gid_t) v; p = p->next;
        }
        else if (strcmp (w, "--peer-pid") == 0 && p->next) {
            unsigned long long v;
            if (bs_parse_id (p->next->word->word, (unsigned long long) INT_MAX, &v) < 0)
                { builtin_error ("recv-fd: bad --peer-pid"); builtin_usage (); return EX_USAGE; }
            want_pid = 1; peer_pid = (pid_t) v; p = p->next;
        }
        else if (strcmp (w, "--fd-tty") == 0) { want_tty = 1; }
        else if (strcmp (w, "--fd-regular") == 0) { want_regular = 1; }
        else if (strcmp (w, "--fd-socket") == 0) { want_socket = 1; }
        else { builtin_error ("recv-fd: unexpected '%s'", w); builtin_usage (); return EX_USAGE; }
    }
    if (bs_check_peer_cred (sock_fd, want_uid, peer_uid,
                            want_gid, peer_gid, want_pid, peer_pid) < 0)
        return EXECUTION_FAILURE;

    char dbuf[8192];
    struct iovec iov = { .iov_base = dbuf, .iov_len = sizeof dbuf - 1 };
    char cbuf[CMSG_SPACE (sizeof (int))];
    memset (cbuf, 0, sizeof cbuf);

    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof cbuf;

    /* MSG_CMSG_CLOEXEC: kernel atomically sets FD_CLOEXEC on the
     * received descriptor before recvmsg returns. Without it, an
     * intervening fork+exec between recvmsg and a later
     * fcntl(F_SETFD, FD_CLOEXEC) would leak the descriptor to a
     * child process. Addresses scm fd-passing review item from
     * BASH-OS-LOADABLES-SECURITY-REVIEW-2026-05-07.md (#2 high:
     * "set FD_CLOEXEC on received fds with fcntl"). Linux-only flag
     * (available since 2.6.23) — bash-os targets Linux only. */
    ssize_t n = recvmsg (sock_fd, &msg, MSG_CMSG_CLOEXEC);
    if (n < 0) {
        builtin_error ("recvmsg: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    int recvd_fd = -1;
    for (struct cmsghdr *cm = CMSG_FIRSTHDR (&msg); cm; cm = CMSG_NXTHDR (&msg, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
            memcpy (&recvd_fd, CMSG_DATA (cm), sizeof recvd_fd);
            break;
        }
    }
    if (recvd_fd < 0) {
        builtin_error ("recv-fd: no SCM_RIGHTS ancillary data");
        return EXECUTION_FAILURE;
    }
    if (token) {
        size_t tlen = strlen (token);
        if ((size_t) n != tlen || memcmp (dbuf, token, tlen) != 0) {
            close (recvd_fd);
            builtin_error ("recv-fd: token mismatch");
            return EXECUTION_FAILURE;
        }
    }
    if (bs_check_fd_type (recvd_fd, want_tty, want_regular, want_socket) < 0) {
        close (recvd_fd);
        return EXECUTION_FAILURE;
    }
    if (datavar) {
        dbuf[n] = '\0';
        builtin_bind_variable ((char *) datavar, dbuf, 0);
    }
    return bs_emit_fd (recvd_fd, fdvar) < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

int
scm_builtin (WORD_LIST *list)
{
    if (list && list->word && list->word->word) {
        const char *w = list->word->word;
        if (strcmp (w, "--help") == 0) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0) {
            puts ("scm 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
    }
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "pair"))    return bs_pair_cmd (args);
    if (!strcmp (cmd, "listen"))  return bs_listen_cmd (args);
    if (!strcmp (cmd, "connect")) return bs_connect_cmd (args);
    if (!strcmp (cmd, "send-fd")) return bs_send_fd_cmd (args);
    if (!strcmp (cmd, "recv-fd")) return bs_recv_fd_cmd (args);
    builtin_error ("unknown verb: %s", cmd);
    builtin_error ("usage: scm {pair|listen|connect|send-fd|recv-fd} ARGS");
    builtin_usage ();
    return EX_USAGE;
}

char *scm_doc[] = {
    "Unix-domain socket FD passing via SCM_RIGHTS.",
    "",
    "    scm pair [-h FDVAR1] [-h FDVAR2]",
    "        socketpair(AF_UNIX, SOCK_DGRAM); emit two FDs.",
    "    scm listen PATH [-h FDVAR]",
    "        AF_UNIX SOCK_DGRAM bound to PATH.",
    "    scm connect PATH [-h FDVAR]",
    "        AF_UNIX SOCK_DGRAM connected to PATH.",
    "    scm send-fd SOCK_FD MSG_FD [DATA]",
    "        Pass MSG_FD as ancillary data; DATA in body (default 'F').",
    "    scm recv-fd SOCK_FD [-h FDVAR] [-V DATAVAR]",
    "        Receive one fd; body bytes -> DATAVAR.",
    "        Optional checks: --peer-uid UID --peer-gid GID",
    "        --peer-pid PID --token DATA --fd-tty|--fd-regular|--fd-socket.",
    "    scm --help | --version",
    "",
    "Used by bash-screen multi-attach (server hands pty master to clients).",
    (char *)NULL
};

struct builtin scm_struct = {
    "scm",
    scm_builtin,
    BUILTIN_ENABLED,
    scm_doc,
    "scm pair|listen|connect|send-fd|recv-fd ARGS [--help|--version]",
    0
};
