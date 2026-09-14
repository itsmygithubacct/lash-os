/* SPDX-License-Identifier: MIT */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE 1
#endif

/* screen.c - Bash window/pane policy backed by the native PTY broker.
 *
 * Every live pane owns an independent service. Shell invocations keep only
 * layout and focus metadata; input, geometry, process lifetime and bounded
 * raw output history belong to the broker. Live attach never replays raw
 * history: a raw transcript is not a terminal checkpoint, and replaying it
 * can repeat terminal queries. --metadata retains offline layout fixtures.
 *
 * State directory: /tmp/.screen/<NAME>/
 *     pid            ← zero sentinel for the logical session
 *     backend        ← ptybroker or explicit metadata mode
 *     brokers/<id>/control.sock ← one private service socket per pane
 *     active         ← active <window>:<pane> focus pointer
 *     info           ← human-readable metadata
 *     windows/<idx>/ ← per-window state (Stage 9)
 *         pid
 *         name
 *         vt-handle      ← Stage 50.C metadata placeholder, not a live pty
 *         vt-generation  ← last observed vt generation (metadata-only)
 *         vt-dirty       ← relay dirtiness bit (metadata-only)
 *         panes/<pidx>/  (Stage 18)
 *             pid
 *             geom        — "row col rows cols"
 *             broker-id   — stable native session ID
 *             scrollback  — offline fixture history only
 *             pty.fd      — live pty socket path or metadata placeholder
 *     attachers/<pid>    ← per-client last-seen metadata
 *     relay-status       ← live relay status / diagnostics
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
#include <dirent.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <poll.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>
#include <zlib.h>

#if __has_include ("_libssh_libssh.h")
#  include "_libssh_libssh.h"
#  define BSCREEN_HAVE_LIBSSH 1
#elif __has_include ("_libssh/libssh.h")
#  include "_libssh/libssh.h"
#  define BSCREEN_HAVE_LIBSSH 1
#else
#  define BSCREEN_HAVE_LIBSSH 0
#endif

#include "loadables.h"
#if __has_include ("_ptybroker_transport.h")
#  include "_ptybroker_transport.h"
#else
#  include "_ptybroker/transport.h"
#endif

/* Default state directory. Override via BASHSCREEN_STATE_DIR env.
 *
 * Security review 2026-05-07 #3: define the private-dir contract NOW
 * before Stages 50.B/5/9/12/17/18 land socket / pid / scrollback files
 * here. The contract is: when the state dir already exists, it MUST
 * be owned by the calling uid and have mode 0700. A world-writable
 * /tmp/.screen is rejected so an attacker can't create the
 * directory first and then exploit symlink/race conditions on the
 * future per-session subdirs.
 */
#define BSCREEN_DEFAULT_STATE_DIR "/tmp/.screen"
#define BSCREEN_WINDOW_NAME_MAX 64
#define BSCREEN_CLUSTER_DEFAULT_DIR "/var/lib/cluster"
#define BSCREEN_REMOTE_MAGIC "BSCR"
#define BSCREEN_REMOTE_VERSION 1
#define BSCREEN_REMOTE_FRAME_PTY 1
#define BSCREEN_REMOTE_FRAME_QUERY 2
#define BSCREEN_REMOTE_FRAME_CONTROL 3
#define BSCREEN_DEFAULT_DETACH_KEY '\001'
#define BSCREEN_DEFAULT_ROAM_KEY 'r'

typedef enum {
    BSCREEN_RELAY_ERROR = -1,
    BSCREEN_RELAY_EOF = 0,
    BSCREEN_RELAY_DETACH = 1,
    BSCREEN_RELAY_ROAM = 2
} bscreen_relay_result;

struct bs_remote_frame_header {
    char magic[4];
    unsigned char version;
    unsigned char type;
    unsigned char len_be[4];
};

static void
bs_remote_u32_pack (unsigned char out[4], uint32_t v)
{
    out[0] = (unsigned char) ((v >> 24) & 0xff);
    out[1] = (unsigned char) ((v >> 16) & 0xff);
    out[2] = (unsigned char) ((v >> 8) & 0xff);
    out[3] = (unsigned char) (v & 0xff);
}

static uint32_t
bs_remote_u32_unpack (const unsigned char in[4])
{
    return ((uint32_t) in[0] << 24) |
           ((uint32_t) in[1] << 16) |
           ((uint32_t) in[2] << 8) |
           (uint32_t) in[3];
}

static void
bs_remote_frame_init (struct bs_remote_frame_header *h,
                      unsigned char type, uint32_t len)
{
    memcpy (h->magic, BSCREEN_REMOTE_MAGIC, sizeof h->magic);
    h->version = BSCREEN_REMOTE_VERSION;
    h->type = type;
    bs_remote_u32_pack (h->len_be, len);
}

static int
bs_remote_frame_valid (const struct bs_remote_frame_header *h,
                       uint32_t *len_out)
{
    if (memcmp (h->magic, BSCREEN_REMOTE_MAGIC, sizeof h->magic) != 0)
        return 0;
    if (h->version != BSCREEN_REMOTE_VERSION)
        return 0;
    if (h->type != BSCREEN_REMOTE_FRAME_PTY &&
        h->type != BSCREEN_REMOTE_FRAME_QUERY &&
        h->type != BSCREEN_REMOTE_FRAME_CONTROL)
        return 0;
    if (len_out)
        *len_out = bs_remote_u32_unpack (h->len_be);
    return 1;
}

static const char *
bscreen_state_dir (void)
{
    const char *override = getenv ("BASHSCREEN_STATE_DIR");
    return override && *override ? override : BSCREEN_DEFAULT_STATE_DIR;
}

static const char *
bscreen_cluster_state_dir (void)
{
    const char *override = getenv ("BASHCLUSTER_STATE_DIR");
    if (override && *override) return override;
    override = getenv ("BASHCLUSTER_DIR");
    return override && *override ? override : BSCREEN_CLUSTER_DEFAULT_DIR;
}

static int bs_attach_live_relay (const char *sdir);
static int bs_relay_write_all (int fd, const char *buf, ssize_t n);
static int bs_session_path (char *out, size_t n, const char *root, const char *name);
static int bs_remote_ssh_attach (const char *hostport, const char *key,
                                 const char *session);
static unsigned char bs_detach_key (void);
static unsigned char bs_roam_key (void);
static int bs_key_match (unsigned char ch, unsigned char key);
static long bs_roam_reconnect_count (void);

/* Validate a private state directory. All screen state directories
 * are owned by the caller, mode 0700, and are checked with lstat so a
 * symlink is never accepted as a directory. */
static int
bs_validate_private_dir (const char *path, mode_t mode, const char *what)
{
    struct stat st;
    if (lstat (path, &st) < 0)
      {
        builtin_error ("screen: lstat %s: %s", path, strerror (errno));
        return -1;
      }
    if (!S_ISDIR (st.st_mode)) {
        builtin_error ("screen: %s %s is not a directory "
                       "(mode=0%o)",
                       what, path, (unsigned) (st.st_mode & 07777));
        return -1;
    }
    if (st.st_uid != geteuid ()) {
        builtin_error ("screen: %s %s is owned by uid %u, "
                       "not the caller (uid %u) — refusing to use it",
                       what, path, (unsigned) st.st_uid,
                       (unsigned) geteuid ());
        return -1;
    }
    if ((st.st_mode & 07777) != mode) {
        builtin_error ("screen: %s %s has mode 0%o, "
                       "expected 0%o — refuse to expose session state "
                       "to other users",
                       what, path, (unsigned) (st.st_mode & 07777),
                       (unsigned) mode);
        return -1;
    }
    return 0;
}

/* Validate (or create) the state-dir parent. Returns 0 if it's safe
 * to use, -1 if a security check failed (with builtin_error already
 * called). If mkdir races with another process, the path is rechecked
 * with lstat before use.
 */
static int
bscreen_validate_state_dir (const char *path)
{
    struct stat st;
    if (lstat (path, &st) < 0) {
        if (errno != ENOENT) {
            builtin_error ("screen: lstat %s: %s",
                           path, strerror (errno));
            return -1;
        }
        if (mkdir (path, 0700) < 0 && errno != EEXIST) {
            builtin_error ("screen: mkdir %s: %s",
                           path, strerror (errno));
            return -1;
        }
    }
    return bs_validate_private_dir (path, 0700, "state dir");
}

static const char *
bs_word (WORD_LIST **args)
{
    if (!args || !*args) return NULL;
    const char *w = (*args)->word->word;
    *args = (*args)->next;
    return w;
}

static int
bs_name_ok (const char *name)
{
    if (!name || !*name || strlen (name) > 96) return 0;
    if (!strcmp (name, ".") || !strcmp (name, "..")) return 0;
    for (const unsigned char *p = (const unsigned char *) name; *p; p++)
        if (!( (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
               (*p >= '0' && *p <= '9') || *p == '_' || *p == '.' || *p == '-' ))
            return 0;
    return 1;
}

static const char *
bs_window_name_capped (const char *name, char out[BSCREEN_WINDOW_NAME_MAX + 1])
{
    const char *src = name && *name ? name : "bash";
    size_t len = strlen (src);
    if (len <= BSCREEN_WINDOW_NAME_MAX)
        return src;
    memcpy (out, src, BSCREEN_WINDOW_NAME_MAX);
    out[BSCREEN_WINDOW_NAME_MAX] = '\0';
    return out;
}

static int
bs_mkdir_if_needed (const char *path, mode_t mode)
{
    if (mkdir (path, mode) < 0 && errno != EEXIST) {
        builtin_error ("screen: mkdir %s: %s", path, strerror (errno));
        return -1;
    }
    return bs_validate_private_dir (path, mode, "state subdir");
}

static int
bs_write_file (const char *path, const char *value)
{
    char tmp[1024];
    int n = snprintf (tmp, sizeof tmp, "%s.tmp.%ld", path, (long) getpid ());
    if (n < 0 || (size_t) n >= sizeof tmp) {
        builtin_error ("screen: temp path too long for %s", path);
        return -1;
    }

    FILE *f = fopen (tmp, "w");
    if (!f) {
        builtin_error ("screen: write %s: %s", tmp, strerror (errno));
        return -1;
    }
    if (fputs (value ? value : "", f) < 0 || fflush (f) == EOF ||
        fsync (fileno (f)) < 0) {
        int saved = errno;
        fclose (f);
        unlink (tmp);
        errno = saved;
        builtin_error ("screen: write %s: %s", tmp, strerror (errno));
        return -1;
    }
    if (fclose (f) == EOF) {
        int saved = errno;
        unlink (tmp);
        errno = saved;
        builtin_error ("screen: close %s: %s", tmp, strerror (errno));
        return -1;
    }
    if (rename (tmp, path) < 0) {
        int saved = errno;
        unlink (tmp);
        errno = saved;
        builtin_error ("screen: rename %s -> %s: %s", tmp, path, strerror (errno));
        return -1;
    }
    return 0;
}

static int
bs_session_exists (const char *sdir)
{
    char file[512];
    struct stat st;
    if (bs_validate_private_dir (sdir, 0700, "session dir") < 0)
        return 0;
    snprintf (file, sizeof file, "%s/pid", sdir);
    return lstat (file, &st) == 0 && S_ISREG (st.st_mode) &&
           st.st_uid == geteuid ();
}

static int
bs_read_file (const char *path, char *buf, size_t n)
{
    FILE *f = fopen (path, "r");
    if (!f) return -1;
    if (!fgets (buf, (int)n, f)) { fclose (f); return -1; }
    fclose (f);
    buf[strcspn (buf, "\r\n")] = '\0';
    return 0;
}

static int
bs_cluster_members_path (char *out, size_t n)
{
    int rc = snprintf (out, n, "%s/members", bscreen_cluster_state_dir ());
    if (rc < 0 || (size_t) rc >= n) {
        builtin_error ("screen: cluster members path too long");
        return -1;
    }
    return 0;
}

static int
bs_cluster_node_id (char *out, size_t n)
{
    char path[1024];
    int rc = snprintf (path, sizeof path, "%s/node_id", bscreen_cluster_state_dir ());
    if (rc < 0 || (size_t) rc >= sizeof path)
        return -1;
    return bs_read_file (path, out, n);
}

static int
bs_valid_cluster_token (const char *s)
{
    if (!s || !*s || strlen (s) > 128) return 0;
    for (const unsigned char *p = (const unsigned char *) s; *p; p++)
        if (!( (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
               (*p >= '0' && *p <= '9') || *p == '_' || *p == '.' ||
               *p == '-' || *p == ':' || *p == '/' || *p == '@' ))
            return 0;
    return 1;
}

static int
bs_cluster_lookup_member (const char *node, char *hostport, size_t hostport_sz,
                          char *key, size_t key_sz)
{
    char path[1024], line[1024];
    FILE *f;

    if (!node || !*node) {
        builtin_error ("screen: remote target needs NODE/SESSION");
        return -1;
    }
    if (bs_cluster_members_path (path, sizeof path) < 0)
        return -1;
    f = fopen (path, "r");
    if (!f) {
        builtin_error ("screen: cluster members unavailable at %s", path);
        return -1;
    }
    while (fgets (line, sizeof line, f)) {
        char mnode[129], mhost[129], mkey[256];
        char *p = line;
        mnode[0] = mhost[0] = '\0';
        mkey[0] = '-'; mkey[1] = '\0';
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '#') continue;
        if (sscanf (p, "%128s %128s %255s", mnode, mhost, mkey) < 2)
            continue;
        if (!strcmp (mnode, node)) {
            fclose (f);
            if (!bs_valid_cluster_token (mnode) || !bs_valid_cluster_token (mhost)) {
                builtin_error ("screen: unsafe cluster member line for %s", node);
                return -1;
            }
            snprintf (hostport, hostport_sz, "%s", mhost);
            snprintf (key, key_sz, "%s", mkey[0] ? mkey : "-");
            return 0;
        }
    }
    fclose (f);
    builtin_error ("screen: no such cluster member: %s", node);
    return -1;
}

static int
bs_cluster_print_node_sessions (const char *node, const char *hostport,
                                const char *key)
{
    const char *root = bscreen_state_dir ();
    DIR *d;
    char local_node[129] = "";

    if (!bs_valid_cluster_token (node) || !bs_valid_cluster_token (hostport)) {
        builtin_error ("screen: unsafe cluster member: %s %s",
                       node ? node : "(null)", hostport ? hostport : "(null)");
        return -1;
    }

    /* Host-safe first slice: the fixture can advertise sessions in
     * $BASHCLUSTER_STATE_DIR/sessions/<node>. When that file is absent
     * for the local node, fall back to the local screen state dir.
     * This keeps discovery deterministic without requiring a second host
     * or SSH daemon. */
    {
        char sessions_path[1024], line[256];
        FILE *sf;
        int rc = snprintf (sessions_path, sizeof sessions_path, "%s/sessions/%s",
                           bscreen_cluster_state_dir (), node);
        if (rc >= 0 && (size_t) rc < sizeof sessions_path &&
            (sf = fopen (sessions_path, "r")) != NULL) {
            while (fgets (line, sizeof line, sf)) {
                line[strcspn (line, "\r\n")] = '\0';
                if (!line[0] || line[0] == '#') continue;
                if (!bs_name_ok (line)) continue;
                printf ("%s/%s\t%s\tkey=%s\n", node, line, hostport,
                        (key && *key) ? key : "-");
            }
            fclose (sf);
            return 0;
        }
    }

    if (bs_cluster_node_id (local_node, sizeof local_node) < 0 ||
        strcmp (local_node, node) != 0)
        return 0;

    if (bscreen_validate_state_dir (root) < 0)
        return -1;
    d = opendir (root);
    if (!d)
        return 0;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        char pidpath[512];
        struct stat st;
        if (ent->d_name[0] == '.') continue;
        if (!bs_name_ok (ent->d_name)) continue;
        snprintf (pidpath, sizeof pidpath, "%s/%s/pid", root, ent->d_name);
        if (stat (pidpath, &st) == 0 && S_ISREG (st.st_mode))
            printf ("%s/%s\t%s\tkey=%s\n", node, ent->d_name, hostport,
                    (key && *key) ? key : "-");
    }
    closedir (d);
    return 0;
}

static int
bscreen_cluster_list_cmd (void)
{
    char path[1024], line[1024];
    FILE *f;

    if (bs_cluster_members_path (path, sizeof path) < 0)
        return EXECUTION_FAILURE;
    f = fopen (path, "r");
    if (!f)
        return EXECUTION_SUCCESS;

    while (fgets (line, sizeof line, f)) {
        char node[129], hostport[129], key[256];
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '#') continue;
        key[0] = '-'; key[1] = '\0';
        if (sscanf (p, "%128s %128s %255s", node, hostport, key) < 2)
            continue;
        if (bs_cluster_print_node_sessions (node, hostport, key) < 0) {
            fclose (f);
            return EXECUTION_FAILURE;
        }
    }
    fclose (f);
    return EXECUTION_SUCCESS;
}

static int
bs_resolve_remote_target (const char *verb, const char *target,
                          const char *key_override,
                          char *node, size_t node_sz,
                          char *session, size_t session_sz,
                          char *hostport, size_t hostport_sz,
                          char *key, size_t key_sz)
{
    const char *slash;
    size_t node_len, session_len;

    if (!target || !(slash = strchr (target, '/')) || slash == target || !slash[1]) {
        builtin_error ("%s: target must be NODE/SESSION", verb);
        return EX_USAGE;
    }
    node_len = (size_t) (slash - target);
    session_len = strlen (slash + 1);
    if (node_len >= node_sz || session_len >= session_sz) {
        builtin_error ("%s: target too long", verb);
        return EX_USAGE;
    }
    memcpy (node, target, node_len);
    node[node_len] = '\0';
    snprintf (session, session_sz, "%s", slash + 1);
    if (!bs_valid_cluster_token (node) || !bs_name_ok (session)) {
        builtin_error ("%s: unsafe target: %s", verb, target);
        return EX_USAGE;
    }
    if (bs_cluster_lookup_member (node, hostport, hostport_sz, key, key_sz) < 0)
        return EXECUTION_FAILURE;
    if (key_override && *key_override)
        snprintf (key, key_sz, "%s", key_override);
    return EXECUTION_SUCCESS;
}

static int
bscreen_attach_remote_cmd (const char *target, const char *key_override, int dry_run)
{
    char node[129], session[129], hostport[129], key[256];
    int resolved = bs_resolve_remote_target ("attach --remote", target, key_override,
                                             node, sizeof node, session, sizeof session,
                                             hostport, sizeof hostport, key, sizeof key);
    if (resolved != EXECUTION_SUCCESS)
        return resolved;

    if (dry_run) {
        printf ("node=%s\nsession=%s\nhostport=%s\nkey=%s\ncommand=screen attach %s -r\n",
                node, session, hostport, key, session);
        return EXECUTION_SUCCESS;
    }

    if ((getenv ("BASHSCREEN_REMOTE_LOOPBACK") &&
         strcmp (getenv ("BASHSCREEN_REMOTE_LOOPBACK"), "0") != 0) ||
        !strcmp (hostport, "local") || !strcmp (hostport, "localhost:0")) {
        char sdir[512];
        const char *root = bscreen_state_dir ();
        if (bscreen_validate_state_dir (root) < 0)
            return EXECUTION_FAILURE;
        if (bs_session_path (sdir, sizeof sdir, root, session) < 0)
            return EX_USAGE;
        if (bs_attach_live_relay (sdir) >= 0)
            return EXECUTION_SUCCESS;
        builtin_error ("attach --remote: loopback relay unavailable for %s/%s",
                       node, session);
        return EXECUTION_FAILURE;
    }

    return bs_remote_ssh_attach (hostport, key, session);
}

static int
bs_parse_remote_hostport (const char *hostport, char *host, size_t host_sz,
                          char *port, size_t port_sz, char *user,
                          size_t user_sz)
{
    char tmp[256];
    const char *hp;
    const char *at, *colon;

    if (!hostport || !*hostport || !bs_valid_cluster_token (hostport))
        return -1;
    snprintf (tmp, sizeof tmp, "%s", hostport);
    hp = tmp;
    user[0] = '\0';

    at = strchr (hp, '@');
    if (at) {
        size_t ul = (size_t) (at - hp);
        if (ul == 0 || ul >= user_sz)
            return -1;
        memcpy (user, hp, ul);
        user[ul] = '\0';
        hp = at + 1;
    }

    colon = strrchr (hp, ':');
    if (colon && strchr (hp, ':') == colon) {
        size_t hl = (size_t) (colon - hp);
        if (hl == 0 || hl >= host_sz || strlen (colon + 1) >= port_sz)
            return -1;
        memcpy (host, hp, hl);
        host[hl] = '\0';
        snprintf (port, port_sz, "%s", colon + 1);
    } else {
        if (strlen (hp) >= host_sz)
            return -1;
        snprintf (host, host_sz, "%s", hp);
        snprintf (port, port_sz, "22");
    }

    if (!host[0] || !port[0])
        return -1;
    for (const char *p = port; *p; p++)
        if (*p < '0' || *p > '9')
            return -1;
    return 0;
}

#if BSCREEN_HAVE_LIBSSH
static int bs_remote_libssh_initialized;

static int
bs_remote_libssh_init (void)
{
    if (bs_remote_libssh_initialized)
        return 0;
    if (ssh_init () != SSH_OK) {
        builtin_error ("attach --remote: libssh init failed");
        return -1;
    }
    bs_remote_libssh_initialized = 1;
    return 0;
}

static int
bs_remote_set_crypto_env (ssh_session ssh)
{
    const char *c = getenv ("BASHSSH_CIPHERS");
    const char *m = getenv ("BASHSSH_MACS");
    const char *k = getenv ("BASHSSH_KEX");
    const char *rk = getenv ("BASHSSH_REKEY");

    if ((c && *c && (ssh_options_set (ssh, SSH_OPTIONS_CIPHERS_C_S, c) != SSH_OK
                 || ssh_options_set (ssh, SSH_OPTIONS_CIPHERS_S_C, c) != SSH_OK))
        || (m && *m && (ssh_options_set (ssh, SSH_OPTIONS_HMAC_C_S, m) != SSH_OK
                    || ssh_options_set (ssh, SSH_OPTIONS_HMAC_S_C, m) != SSH_OK))
        || (k && *k && ssh_options_set (ssh, SSH_OPTIONS_KEY_EXCHANGE, k) != SSH_OK)) {
        builtin_error ("attach --remote: rejected SSH crypto allow-list: %s",
                       ssh_get_error (ssh));
        return -1;
    }
    if (rk && *rk) {
        uint64_t rd = (uint64_t) strtoull (rk, NULL, 10);
        if (rd > 0)
            ssh_options_set (ssh, SSH_OPTIONS_REKEY_DATA, &rd);
    }
    return 0;
}

static int
bs_remote_known_host_check (ssh_session ssh, const char *host)
{
    int mode = 0; /* 0=accept-new, 1=yes, 2=no */
    const char *m = getenv ("BASHSSH_STRICT_HOST_KEY_CHECKING");
    if (m && (!strcmp (m, "yes") || !strcmp (m, "strict")))
        mode = 1;
    else if (m && (!strcmp (m, "no") || !strcmp (m, "off")))
        mode = 2;

    enum ssh_known_hosts_e kh = ssh_session_is_known_server (ssh);
    if (kh == SSH_KNOWN_HOSTS_OK)
        return 0;
    if (kh == SSH_KNOWN_HOSTS_CHANGED) {
        if (mode == 2) {
            fprintf (stderr, "screen: WARNING: host key changed for %s; accepting (StrictHostKeyChecking=no)\n",
                     host);
            return ssh_session_update_known_hosts (ssh) == SSH_OK ? 0 : -1;
        }
        builtin_error ("attach --remote: host key CHANGED for %s", host);
        return -1;
    }
    if (kh == SSH_KNOWN_HOSTS_UNKNOWN || kh == SSH_KNOWN_HOSTS_NOT_FOUND) {
        if (mode == 1) {
            builtin_error ("attach --remote: unknown host key for %s", host);
            return -1;
        }
        if (ssh_session_update_known_hosts (ssh) == SSH_OK)
            return 0;
        builtin_error ("attach --remote: could not update known_hosts for %s: %s",
                       host, ssh_get_error (ssh));
        return -1;
    }
    builtin_error ("attach --remote: host key error for %s: %s",
                   host, ssh_get_error (ssh));
    return -1;
}

static int
bs_remote_channel_write_all (ssh_channel ch, const char *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        int wr = ssh_channel_write (ch, buf + off, (uint32_t) (n - off));
        if (wr == SSH_ERROR)
            return -1;
        if (wr == SSH_AGAIN || wr == 0)
            continue;
        off += (size_t) wr;
    }
    return 0;
}

static int
bs_remote_channel_send_control_roam (ssh_channel ch)
{
    /* Remote attach consumes the same prefix as local attach. Protocol
     * metadata must never be injected into the pane's application input. */
    char keys[2] = { (char) bs_detach_key (), (char) bs_roam_key () };
    return bs_remote_channel_write_all (ch, keys, sizeof keys);
}

static int
bs_remote_channel_relay (ssh_session ssh, ssh_channel ch)
{
    bscreen_relay_result result = BSCREEN_RELAY_EOF;
    int sfd = ssh_get_fd (ssh);
    int stdin_open = 1;
    int is_tty = isatty (STDIN_FILENO);
    int raw_set = 0;
    int escape_pending = 0;
    unsigned char detach_key = bs_detach_key ();
    unsigned char roam_key = bs_roam_key ();
    struct termios orig;
    char buf[8192];

    if (is_tty && tcgetattr (STDIN_FILENO, &orig) == 0) {
        struct termios raw = orig;
        cfmakeraw (&raw);
        if (tcsetattr (STDIN_FILENO, TCSANOW, &raw) == 0)
            raw_set = 1;
    }

    for (;;) {
        fd_set rfds;
        int maxfd = sfd;
        struct timeval tv;
        FD_ZERO (&rfds);
        if (stdin_open) {
            FD_SET (STDIN_FILENO, &rfds);
            if (STDIN_FILENO > maxfd) maxfd = STDIN_FILENO;
        }
        if (sfd >= 0)
            FD_SET (sfd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        int sel = select (maxfd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR)
                continue;
            result = BSCREEN_RELAY_ERROR;
            break;
        }

        if (stdin_open && FD_ISSET (STDIN_FILENO, &rfds)) {
            ssize_t nr = read (STDIN_FILENO, buf, sizeof buf);
            if (nr > 0) {
                ssize_t start = 0;
                int stop_stdin = 0;
                for (ssize_t i = 0; i < nr; i++) {
                    unsigned char uch = (unsigned char) buf[i];
                    if (escape_pending) {
                        if (i > start &&
                            bs_remote_channel_write_all (ch, buf + start, (size_t) (i - start)) < 0) {
                            result = BSCREEN_RELAY_ERROR;
                            goto out;
                        }
                        escape_pending = 0;
                        start = i + 1;
                        if (bs_key_match (uch, 'd')) {
                            ssh_channel_send_eof (ch);
                            stdin_open = 0;
                            result = BSCREEN_RELAY_DETACH;
                            stop_stdin = 1;
                            break;
                        }
                        if (bs_key_match (uch, roam_key)) {
                            if (bs_remote_channel_send_control_roam (ch) < 0)
                                result = BSCREEN_RELAY_ERROR;
                            else {
                                ssh_channel_send_eof (ch);
                                stdin_open = 0;
                                result = BSCREEN_RELAY_ROAM;
                            }
                            stop_stdin = 1;
                            break;
                        }
                        {
                            char literal[2] = { (char) detach_key, (char) uch };
                            if (bs_remote_channel_write_all (ch, literal, sizeof literal) < 0) {
                                result = BSCREEN_RELAY_ERROR;
                                goto out;
                            }
                        }
                    } else if (uch == detach_key) {
                        if (i > start &&
                            bs_remote_channel_write_all (ch, buf + start, (size_t) (i - start)) < 0) {
                            result = BSCREEN_RELAY_ERROR;
                            goto out;
                        }
                        escape_pending = 1;
                        start = i + 1;
                    }
                }
                if (stop_stdin && result == BSCREEN_RELAY_ERROR)
                    goto out;
                if (!stop_stdin && nr > start &&
                    bs_remote_channel_write_all (ch, buf + start, (size_t) (nr - start)) < 0) {
                    result = BSCREEN_RELAY_ERROR;
                    break;
                }
            } else {
                if (escape_pending) {
                    char lit = (char) detach_key;
                    (void) bs_remote_channel_write_all (ch, &lit, 1);
                    escape_pending = 0;
                }
                ssh_channel_send_eof (ch);
                stdin_open = 0;
            }
        }

        int avail = ssh_channel_poll_timeout (ch, 0, 0);
        if (avail == SSH_ERROR) {
            result = BSCREEN_RELAY_ERROR;
            break;
        }
        while (avail > 0) {
            uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
            int rr = ssh_channel_read (ch, buf, chunk, 0);
            if (rr <= 0)
                break;
            if (bs_relay_write_all (STDOUT_FILENO, buf, rr) < 0)
                break;
            avail -= rr;
        }

        avail = ssh_channel_poll_timeout (ch, 0, 1);
        if (avail == SSH_ERROR) {
            result = BSCREEN_RELAY_ERROR;
            break;
        }
        while (avail > 0) {
            uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
            int rr = ssh_channel_read (ch, buf, chunk, 1);
            if (rr <= 0)
                break;
            if (bs_relay_write_all (STDERR_FILENO, buf, rr) < 0)
                break;
            avail -= rr;
        }

        if (ssh_channel_is_eof (ch) || !ssh_channel_is_open (ch))
            break;
    }

out:
    if (raw_set)
        tcsetattr (STDIN_FILENO, TCSANOW, &orig);
    return result;
}

static int
bs_remote_ssh_attach (const char *hostport, const char *key, const char *session)
{
    char host[129], port[16], user[129], cmd[256], start_line[512];
    int port_i, batch = 1, no = 0, strict_yes = SSH_STRICT_HOSTKEY_YES;
    int pubkey = SSH_PUBKEY_AUTH_ALL;
    bool identities_only = true;
    ssh_session ssh = NULL;
    ssh_channel ch = NULL;
    int rc = EXECUTION_FAILURE;
    long reconnects;
    int attempt = 0;
    bscreen_relay_result relay_rc = BSCREEN_RELAY_ERROR;

    if (bs_parse_remote_hostport (hostport, host, sizeof host, port, sizeof port,
                                  user, sizeof user) < 0) {
        builtin_error ("attach --remote: bad hostport: %s", hostport ? hostport : "(null)");
        return EX_USAGE;
    }
    port_i = atoi (port);
    if (port_i <= 0 || port_i > 65535) {
        builtin_error ("attach --remote: bad port in %s", hostport);
        return EX_USAGE;
    }
    if (bs_remote_libssh_init () < 0)
        return EXECUTION_FAILURE;
    reconnects = bs_roam_reconnect_count ();

retry:
    ssh = ssh_new ();
    if (!ssh) {
        builtin_error ("attach --remote: ssh_new failed");
        return EXECUTION_FAILURE;
    }
    const char *no_agent = "/nonexistent/screen-agent.sock";
    if (ssh_options_set (ssh, SSH_OPTIONS_HOST, host) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_PORT, &port_i) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_BATCH_MODE, &batch) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict_yes) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_IDENTITIES_ONLY, &identities_only) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_IDENTITY_AGENT, no_agent) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_PASSWORD_AUTH, &no) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_KBDINT_AUTH, &no) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_GSSAPI_AUTH, &no) != SSH_OK ||
        ssh_options_set (ssh, SSH_OPTIONS_PUBKEY_AUTH, &pubkey) != SSH_OK ||
        (user[0] && ssh_options_set (ssh, SSH_OPTIONS_USER, user) != SSH_OK) ||
        bs_remote_set_crypto_env (ssh) < 0) {
        builtin_error ("attach --remote: SSH options failed: %s", ssh_get_error (ssh));
        goto out;
    }
    {
        const char *khf = getenv ("BASHSSH_KNOWN_HOSTS");
        if (khf && *khf &&
            (ssh_options_set (ssh, SSH_OPTIONS_KNOWNHOSTS, khf) != SSH_OK ||
             ssh_options_set (ssh, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, "/dev/null") != SSH_OK)) {
            builtin_error ("attach --remote: known_hosts option failed: %s",
                           ssh_get_error (ssh));
            goto out;
        }
    }
    if (ssh_connect (ssh) != SSH_OK) {
        builtin_error ("attach --remote: connect %s:%s: %s", host, port,
                       ssh_get_error (ssh));
        relay_rc = BSCREEN_RELAY_EOF;
        goto maybe_retry;
    }
    if (bs_remote_known_host_check (ssh, host) < 0)
        goto out;

    if (key && key[0] && strcmp (key, "-")) {
        ssh_key auth_key = NULL;
        if (ssh_pki_import_privkey_file (key, NULL, NULL, NULL, &auth_key) != SSH_OK) {
            builtin_error ("attach --remote: identity %s: %s", key,
                           ssh_get_error (ssh));
            goto out;
        }
        int auth_rc = ssh_userauth_publickey (ssh, NULL, auth_key);
        ssh_key_free (auth_key);
        if (auth_rc != SSH_AUTH_SUCCESS) {
            builtin_error ("attach --remote: public-key auth failed for %s: %s",
                           host, ssh_get_error (ssh));
            goto out;
        }
    } else if (ssh_userauth_publickey_auto (ssh, NULL, NULL) != SSH_AUTH_SUCCESS) {
        builtin_error ("attach --remote: public-key auth failed for %s: %s",
                       host, ssh_get_error (ssh));
        goto out;
    }

    ch = ssh_channel_new (ssh);
    if (!ch || ssh_channel_open_session (ch) != SSH_OK) {
        builtin_error ("attach --remote: channel open failed: %s",
                       ssh_get_error (ssh));
        goto out;
    }
    {
        int cols = 80, rows = 24;
        struct winsize ws;
        const char *term = getenv ("TERM");
        if (isatty (STDIN_FILENO) && ioctl (STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
            cols = ws.ws_col;
            rows = ws.ws_row;
        }
        if (ssh_channel_request_pty_size (ch, term && *term ? term : "xterm",
                                          cols, rows) != SSH_OK) {
            builtin_error ("attach --remote: pty request failed: %s",
                           ssh_get_error (ssh));
            goto out;
        }
        if (ssh_channel_request_shell (ch) != SSH_OK) {
            builtin_error ("attach --remote: shell request failed: %s",
                           ssh_get_error (ssh));
            goto out;
        }
    }
    {
        const char *remote_bash = getenv ("BASHSCREEN_REMOTE_BASH");
        const char *remote_state = getenv ("BASHSCREEN_REMOTE_STATE_DIR");
        if (!remote_state || !*remote_state)
            remote_state = getenv ("BASHSCREEN_STATE_DIR");
        if (remote_state && *remote_state && !bs_valid_cluster_token (remote_state)) {
            builtin_error ("attach --remote: unsafe remote state dir");
            goto out;
        }
        if (remote_bash && *remote_bash) {
            if (!bs_valid_cluster_token (remote_bash)) {
                builtin_error ("attach --remote: unsafe BASHSCREEN_REMOTE_BASH");
                goto out;
            }
            snprintf (cmd, sizeof cmd, "%s -c 'screen attach %s -r'",
                      remote_bash, session);
        } else {
            snprintf (cmd, sizeof cmd, "screen attach %s -r", session);
        }
        if (remote_state && *remote_state)
            snprintf (start_line, sizeof start_line,
                      "BASHSCREEN_STATE_DIR=%s exec %s\n", remote_state, cmd);
        else
            snprintf (start_line, sizeof start_line, "exec %s\n", cmd);
    }
    if (bs_remote_channel_write_all (ch, start_line, strlen (start_line)) < 0) {
        builtin_error ("attach --remote: failed to start remote command");
        goto out;
    }
    relay_rc = bs_remote_channel_relay (ssh, ch);
    if (relay_rc == BSCREEN_RELAY_ERROR)
        goto out;
    if (relay_rc == BSCREEN_RELAY_EOF && attempt < reconnects)
        goto maybe_retry;
    rc = ssh_channel_get_exit_status (ch);
    for (int i = 0; i < 100 && rc < 0; i++) {
        ssh_channel_poll_timeout (ch, 10, 0);
        rc = ssh_channel_get_exit_status (ch);
    }
    if (rc < 0) rc = 0;

out:
    if (ch) {
        ssh_channel_close (ch);
        ssh_channel_free (ch);
    }
    if (ssh) {
        ssh_disconnect (ssh);
        ssh_free (ssh);
    }
    return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;

maybe_retry:
    if (ch) {
        ssh_channel_close (ch);
        ssh_channel_free (ch);
        ch = NULL;
    }
    if (ssh) {
        ssh_disconnect (ssh);
        ssh_free (ssh);
        ssh = NULL;
    }
    if (relay_rc == BSCREEN_RELAY_EOF && attempt++ < reconnects) {
        usleep (250000);
        goto retry;
    }
    goto out;
}
#else
static int
bs_remote_ssh_attach (const char *hostport, const char *key, const char *session)
{
    (void) hostport; (void) key; (void) session;
    builtin_error ("attach --remote: libssh transport is not compiled in");
    return EXECUTION_FAILURE;
}
#endif

/* Stage 50.F scrollback compression + GC (2026-05-11).
 *
 * Long-running screen sessions can grow per-pane scrollback
 * without bound. To cap memory, the loadable folds aging history
 * into gzip blobs and drops the oldest blob when total bytes
 * exceed a configurable cap.
 *
 * Layout (per-pane):
 *     <pane_dir>/scrollback           live append-only tail
 *     <pane_dir>/blobs/000000.gz      oldest compressed slab
 *     <pane_dir>/blobs/000001.gz      ...
 *     <pane_dir>/blobs/.last-gc       mtime gates GC rate-limit
 *
 * Compression triggers when the live scrollback reaches
 * BASHSCREEN_COMPRESS_AFTER_LINES newlines. The entire live file
 * is gzipped into the next blob and then truncated; the next
 * appends start a fresh tail. GC drops the oldest blob whenever
 * total bytes (live + blobs) exceed BASHSCREEN_MAX_BYTES, and is
 * rate-limited by BASHSCREEN_GC_INTERVAL_SEC (mtime of
 * blobs/.last-gc). Set the interval to 0 to run GC every time.
 *
 * The session-level scrollback (<sdir>/scrollback) is treated as
 * just another pane scrollback for this purpose — its blobs live
 * at <sdir>/blobs/.
 */
#define BSCREEN_DEFAULT_COMPRESS_LINES 1024L
#define BSCREEN_DEFAULT_MAX_BYTES      (4L * 1024L * 1024L)
#define BSCREEN_DEFAULT_GC_INTERVAL    60L
#define BSCREEN_GC_INTERVAL_MAX        86400L

static long
bs_env_long (const char *name, long defv)
{
    const char *v = getenv (name);
    if (!v || !*v) return defv;
    char *end = NULL;
    long n = strtol (v, &end, 10);
    if (end == v || (*end != '\0' && *end != '\n') || n < 0) return defv;
    return n;
}

static long bs_compress_threshold (void) { return bs_env_long ("BASHSCREEN_COMPRESS_AFTER_LINES", BSCREEN_DEFAULT_COMPRESS_LINES); }
static long bs_max_bytes          (void) { return bs_env_long ("BASHSCREEN_MAX_BYTES",            BSCREEN_DEFAULT_MAX_BYTES); }

static unsigned char
bs_env_key (const char *name, unsigned char defv)
{
    const char *v = getenv (name);
    if (!v || !*v)
        return defv;
    if (v[0] == '^' && v[1] && !v[2]) {
        unsigned char c = (unsigned char) v[1];
        if (c >= 'a' && c <= 'z')
            c = (unsigned char) (c - 'a' + 'A');
        return (unsigned char) (c & 0x1f);
    }
    return (unsigned char) v[0];
}

static unsigned char bs_detach_key (void) { return bs_env_key ("BASHSCREEN_DETACH_KEY", BSCREEN_DEFAULT_DETACH_KEY); }
static unsigned char bs_roam_key   (void) { return bs_env_key ("BASHSCREEN_ROAM_KEY",   BSCREEN_DEFAULT_ROAM_KEY); }

static int
bs_key_match (unsigned char ch, unsigned char key)
{
    if (ch == key)
        return 1;
    if (key >= 'a' && key <= 'z' && ch == (unsigned char) (key - 'a' + 'A'))
        return 1;
    return 0;
}

static long
bs_roam_reconnect_count (void)
{
    long n = bs_env_long ("BASHSCREEN_ROAM_RECONNECT", 0);
    if (n > 16)
        return 16;
    return n;
}

/* Round 1778631147 Doc 5: BASHSCREEN_GC_INTERVAL_SEC accepts integers
 * but a negative or absurdly large value previously slid through as
 * either "use the default" (negative — bs_env_long rejected) or "wait
 * forever" (huge). Clamp to [0, BSCREEN_GC_INTERVAL_MAX] and emit a
 * single warning per process when the raw env value lands out of
 * range. Garbage / unset env keeps the original default-fallthrough. */
static long
bs_gc_interval_sec (void)
{
    static int warned = 0;
    const char *v = getenv ("BASHSCREEN_GC_INTERVAL_SEC");
    if (!v || !*v) return BSCREEN_DEFAULT_GC_INTERVAL;
    char *end = NULL;
    long n = strtol (v, &end, 10);
    if (end == v || (*end != '\0' && *end != '\n')) return BSCREEN_DEFAULT_GC_INTERVAL;
    if (n < 0) {
        if (!warned) {
            warned = 1;
            builtin_warning ("BASHSCREEN_GC_INTERVAL_SEC=%ld out of range [0,%ld]; clamped to 0",
                             n, BSCREEN_GC_INTERVAL_MAX);
        }
        return 0;
    }
    if (n > BSCREEN_GC_INTERVAL_MAX) {
        if (!warned) {
            warned = 1;
            builtin_warning ("BASHSCREEN_GC_INTERVAL_SEC=%ld out of range [0,%ld]; clamped to %ld",
                             n, BSCREEN_GC_INTERVAL_MAX, BSCREEN_GC_INTERVAL_MAX);
        }
        return BSCREEN_GC_INTERVAL_MAX;
    }
    return n;
}

/* Derive blobs dir from a scrollback file path. sb_path MUST end in
 * "/scrollback"; on success, out is "<parent-dir>/blobs". */
static int
bs_scrollback_blobs_dir (const char *sb_path, char *out, size_t n)
{
    static const char suffix[] = "/scrollback";
    size_t slen = sizeof suffix - 1;
    size_t len = strlen (sb_path);
    if (len < slen || strcmp (sb_path + len - slen, suffix) != 0) {
        errno = EINVAL;
        return -1;
    }
    size_t prefix_len = len - slen;
    int rc = snprintf (out, n, "%.*s/blobs", (int) prefix_len, sb_path);
    if (rc < 0 || (size_t) rc >= n) return -1;
    return 0;
}

static long
bs_count_newlines (const char *path)
{
    FILE *f = fopen (path, "r");
    if (!f) return -1;
    long n = 0;
    int ch;
    while ((ch = fgetc (f)) != EOF) if (ch == '\n') n++;
    fclose (f);
    return n;
}

/* Largest valid 6+ digit "NNN.gz" blob index in dir, or -1 if none. */
static int
bs_max_blob_idx (const char *blobs_dir)
{
    DIR *d = opendir (blobs_dir);
    if (!d) return -1;
    int max = -1;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end == ent->d_name) continue;
        if (strcmp (end, ".gz") != 0) continue;
        if (v > max) max = (int) v;
    }
    closedir (d);
    return max;
}

/* Sum of byte sizes across live scrollback + all blobs. */
static long
bs_total_scrollback_bytes (const char *sb_path, const char *blobs_dir)
{
    long total = 0;
    struct stat st;
    if (stat (sb_path, &st) == 0) total += (long) st.st_size;
    DIR *d = opendir (blobs_dir);
    if (!d) return total;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        if (strtol (ent->d_name, &end, 10) == 0 && end == ent->d_name) continue;
        if (strcmp (end, ".gz") != 0) continue;
        char p[1024];
        int rc = snprintf (p, sizeof p, "%s/%s", blobs_dir, ent->d_name);
        if (rc < 0 || (size_t) rc >= sizeof p) continue;
        if (stat (p, &st) == 0) total += (long) st.st_size;
    }
    closedir (d);
    return total;
}

/* Find the oldest blob (smallest numeric index) in blobs_dir. Returns
 * 0 on success with name copied into out (sized >= 64), -1 if no blob. */
static int
bs_find_oldest_blob (const char *blobs_dir, char *out, size_t outsz)
{
    DIR *d = opendir (blobs_dir);
    if (!d) return -1;
    long min = -1;
    char picked[64] = "";
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end == ent->d_name) continue;
        if (strcmp (end, ".gz") != 0) continue;
        if (min < 0 || v < min) {
            min = v;
            snprintf (picked, sizeof picked, "%s", ent->d_name);
        }
    }
    closedir (d);
    if (min < 0) return -1;
    snprintf (out, outsz, "%s", picked);
    return 0;
}

/* Sorted ascending blob name list. Caller frees the returned array
 * (and each entry). Returns count, or 0 with *out_names NULL on empty
 * or alloc failure. */
static int
bs_list_blobs_sorted (const char *blobs_dir, char ***out_names)
{
    *out_names = NULL;
    DIR *d = opendir (blobs_dir);
    if (!d) return 0;
    int cap = 32, n = 0;
    long *idxs = malloc ((size_t) cap * sizeof *idxs);
    char **names = malloc ((size_t) cap * sizeof *names);
    if (!idxs || !names) { free (idxs); free (names); closedir (d); return 0; }
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end == ent->d_name) continue;
        if (strcmp (end, ".gz") != 0) continue;
        if (n >= cap) {
            int nc = cap * 2;
            long *ni = realloc (idxs, (size_t) nc * sizeof *ni);
            char **nn = realloc (names, (size_t) nc * sizeof *nn);
            if (!ni || !nn) {
                if (ni) idxs = ni;
                if (nn) names = nn;
                for (int i = 0; i < n; i++) free (names[i]);
                free (idxs); free (names); closedir (d); return 0;
            }
            idxs = ni; names = nn; cap = nc;
        }
        idxs[n] = v;
        names[n] = strdup (ent->d_name);
        if (!names[n]) {
            for (int i = 0; i < n; i++) free (names[i]);
            free (idxs); free (names); closedir (d); return 0;
        }
        n++;
    }
    closedir (d);
    for (int i = 1; i < n; i++) {
        long iv = idxs[i]; char *in = names[i];
        int j = i;
        while (j > 0 && idxs[j-1] > iv) {
            idxs[j] = idxs[j-1]; names[j] = names[j-1];
            j--;
        }
        idxs[j] = iv; names[j] = in;
    }
    free (idxs);
    *out_names = names;
    return n;
}

/* Compress the entire live scrollback into the next blob and
 * truncate the live file. Caller must have already verified that
 * compression is warranted.
 *
 * Round 1778567182 / Stage 50.F robustness pass: the prior version
 * left several silent-failure traps that produced size-32, wrong-
 * magic blobs on the guest while passing host-side syntax gates.
 * Each step below is now explicitly checked, AND the finished tmp
 * file is sniffed for the gzip magic (1f 8b) BEFORE the atomic
 * rename — so a half-written stream can never end up at the final
 * path under any failure mode (short write, zlib internal error,
 * fclose-without-fsync followed by power loss / OOM at flush, or
 * a concurrent writer racing to the same tmp name).
 *
 * Round 1778567182 / Doc 1 follow-up (2026-05-11): the magic-byte
 * sniff catches half-written headers, but a blob whose header is
 * correct yet whose deflate body lost the payload (zlib internal
 * Z_BUF_ERROR swallowed by gzclose's flush ladder under static-musl
 * link) would still pass and surface as count=0 at the reader. We
 * now ALSO run a roundtrip gzread immediately after gzclose: open
 * the tmp blob with gzopen("rb") and read the first chunk back. If
 * the writer ingested any uncompressed bytes (`uncompressed_total
 * > 0`) but the roundtrip reads zero, that's a header-only blob —
 * exactly the failure shape Round 1778567182 / Doc 1 traced and
 * the case-9 diagnostic in 199-screen-scrollback-gc.sh asserts
 * against. Reject and unlink the tmp before publishing.
 *
 * Cost: one extra gzopen + gzread + gzclose on a file that's
 * almost always <8 KiB after compression. Negligible vs the
 * deflate work that already ran.
 *
 * The fopen(in,"rb") -> gzopen(out,"wb") -> fread/gzwrite loop is
 * stdio-buffered on both sides. We explicitly fflush() the bash
 * stdio path used for appends earlier in the call chain
 * (bs_append_file's fclose() is the flush), but the writer here
 * MUST NOT rely on any I/O ordering between this process and a
 * concurrent relay-loop writer in the bash-os daemon. The tmp
 * name carries getpid() to keep parallel compresses from clobber-
 * ing each other's tmp; the rename is the single atomic publish. */
static int
bs_compress_scrollback_now (const char *sb_path)
{
    char blobs_dir[1024], blob_path[1024], blob_tmp[1100];
    if (bs_scrollback_blobs_dir (sb_path, blobs_dir, sizeof blobs_dir) < 0) return -1;
    if (bs_mkdir_if_needed (blobs_dir, 0700) < 0) return -1;
    int idx = bs_max_blob_idx (blobs_dir) + 1;
    int rc = snprintf (blob_path, sizeof blob_path, "%s/%06d.gz", blobs_dir, idx);
    if (rc < 0 || (size_t) rc >= sizeof blob_path) return -1;
    rc = snprintf (blob_tmp, sizeof blob_tmp, "%s.tmp.%ld", blob_path, (long) getpid ());
    if (rc < 0 || (size_t) rc >= sizeof blob_tmp) return -1;

    /* Pre-clear any stale tmp from a previous interrupted compress
     * with the same pid (recycled after a fork-exec ladder). */
    unlink (blob_tmp);

    FILE *in = fopen (sb_path, "rb");
    if (!in) return -1;

    /* gzopen("wb") opens the file with mode "wb" (truncating) and
     * sets compression level 6 / gzip wrapper format by default —
     * the resulting stream MUST start with the two-byte gzip magic
     * 1f 8b. If a non-gzip blob ever appears at the final path,
     * the post-write magic check below catches it and aborts the
     * publish rather than serving corrupted data to capture-pane. */
    gzFile gz = gzopen (blob_tmp, "wb");
    if (!gz) { fclose (in); return -1; }
    char buf[8192];
    size_t r;
    int err = 0;
    long uncompressed_total = 0;
    while ((r = fread (buf, 1, sizeof buf, in)) > 0) {
        int w = gzwrite (gz, buf, (unsigned int) r);
        /* gzwrite returns the input bytes written or 0 on error.
         * Anything other than `r` means a short / failed write. */
        if (w <= 0 || (size_t) w != r) { err = 1; break; }
        uncompressed_total += (long) r;
    }
    /* If fread terminated on a stream error (not EOF), flag it. */
    if (!err && ferror (in)) err = 1;
    fclose (in);

    /* gzclose flushes any pending deflate output, writes the
     * gzip trailer (CRC32 + ISIZE), and fclose()s the underlying
     * FILE*. Z_OK means the trailer reached the kernel; anything
     * else (Z_ERRNO, Z_BUF_ERROR, Z_STREAM_ERROR, Z_MEM_ERROR)
     * means the file on disk may be truncated, header-only, or
     * otherwise unreadable as a gzip member. */
    int gzc = gzclose (gz);
    if (gzc != Z_OK || err) {
        unlink (blob_tmp);
        return -1;
    }

    /* TRAP: prior versions trusted gzclose==Z_OK as proof of a
     * well-formed file. In practice — under guest-side I/O
     * pressure, an interrupted syscall during gzclose's internal
     * fflush(), or a static-libz build link that silently lost
     * the gzip wrapper — the tmp file could end up size>0 but
     * NOT starting with 1f 8b. capture-pane then served bytes
     * that never decompressed to anything, manifesting as
     * count=0 results in the -N seam-bridge test cases. Verify
     * the magic explicitly before publishing. */
    {
        int vfd = open (blob_tmp, O_RDONLY);
        if (vfd < 0) {
            unlink (blob_tmp);
            return -1;
        }
        unsigned char magic[2] = { 0, 0 };
        ssize_t mr = read (vfd, magic, sizeof magic);
        close (vfd);
        if (mr != 2 || magic[0] != 0x1f || magic[1] != 0x8b) {
            unlink (blob_tmp);
            return -1;
        }
    }

    /* Round 1778567182 / Doc 1: roundtrip gzread verification.
     * If the writer ingested any uncompressed bytes but the blob
     * decompresses to zero, the deflate body is empty — exactly
     * the failure mode `199-screen-scrollback-gc.sh` case 9
     * (the Round-11 diagnostic) asserts against. We reject those
     * blobs before publishing so capture-pane never has to walk
     * a header-only entry. Reading only the first chunk is enough
     * for the assertion: if any uncompressed payload exists, the
     * first gzread MUST return > 0. */
    if (uncompressed_total > 0) {
        gzFile rgz = gzopen (blob_tmp, "rb");
        if (!rgz) {
            unlink (blob_tmp);
            return -1;
        }
        char rb[64];
        int rback = gzread (rgz, rb, sizeof rb);
        gzclose (rgz);
        if (rback <= 0) {
            unlink (blob_tmp);
            return -1;
        }
    }

    if (rename (blob_tmp, blob_path) < 0) {
        unlink (blob_tmp);
        return -1;
    }
    int fd = open (sb_path, O_WRONLY | O_TRUNC);
    if (fd >= 0) close (fd);
    (void) uncompressed_total;  /* kept for debug breakpoints; not used */
    return 0;
}

static int
bs_maybe_compress_scrollback (const char *sb_path)
{
    long threshold = bs_compress_threshold ();
    if (threshold <= 0) return 0;
    struct stat st;
    if (stat (sb_path, &st) < 0) return 0;
    if ((long) st.st_size < threshold) return 0;
    long nlines = bs_count_newlines (sb_path);
    if (nlines < threshold) return 0;
    return bs_compress_scrollback_now (sb_path);
}

static int
bs_maybe_gc_scrollback (const char *sb_path)
{
    char blobs_dir[1024];
    if (bs_scrollback_blobs_dir (sb_path, blobs_dir, sizeof blobs_dir) < 0) return 0;
    struct stat dst;
    if (stat (blobs_dir, &dst) < 0) return 0;

    long interval = bs_gc_interval_sec ();
    char tspath[1100];
    int rc = snprintf (tspath, sizeof tspath, "%s/.last-gc", blobs_dir);
    if (rc < 0 || (size_t) rc >= sizeof tspath) return 0;
    if (interval > 0) {
        struct stat ts;
        if (stat (tspath, &ts) == 0) {
            time_t now = time (NULL);
            if (now - ts.st_mtime < interval) return 0;
        }
    }

    long cap_bytes = bs_max_bytes ();
    if (cap_bytes > 0) {
        for (;;) {
            long total = bs_total_scrollback_bytes (sb_path, blobs_dir);
            if (total <= cap_bytes) break;
            char victim[64];
            if (bs_find_oldest_blob (blobs_dir, victim, sizeof victim) < 0) break;
            char vpath[1100];
            rc = snprintf (vpath, sizeof vpath, "%s/%s", blobs_dir, victim);
            if (rc < 0 || (size_t) rc >= sizeof vpath) break;
            if (unlink (vpath) < 0) break;
        }
    }
    int fd = open (tspath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) close (fd);
    return 0;
}

/* Maintain a scrollback file: compress if it has grown past the
 * threshold, then GC oldest blobs back under the byte cap. Safe to
 * call after every append; rate-limited internally. */
static void
bs_pane_scrollback_maintain (const char *sb_path)
{
    bs_maybe_compress_scrollback (sb_path);
    bs_maybe_gc_scrollback (sb_path);
}

/* Stream a single gzipped blob to stdout. */
static int
bs_stream_blob (const char *blob_path)
{
    gzFile gz = gzopen (blob_path, "rb");
    if (!gz) return -1;
    char buf[8192];
    int n;
    while ((n = gzread (gz, buf, sizeof buf)) > 0) {
        char *p = buf;
        size_t left = (size_t) n;
        while (left > 0) {
            ssize_t w = write (STDOUT_FILENO, p, left);
            if (w < 0) {
                if (errno == EINTR) continue;
                gzclose (gz);
                return -1;
            }
            p += w; left -= (size_t) w;
        }
    }
    gzclose (gz);
    return 0;
}

static int
bs_session_path (char *out, size_t n, const char *root, const char *name)
{
    if (bscreen_validate_state_dir (root) < 0)
        return -1;
    if (!bs_name_ok (name)) {
        builtin_error ("screen: unsafe or empty session name: %s", name ? name : "(null)");
        return -1;
    }
    int len = snprintf (out, n, "%s/%s", root, name);
    if (len < 0 || (size_t) len >= n) {
        errno = ENAMETOOLONG;
        builtin_error ("screen: session path is too long");
        return -1;
    }
    return 0;
}

static int
bs_next_numeric_dir (const char *parent)
{
    DIR *d = opendir (parent);
    int max = -1;
    if (!d) return errno == ENOENT ? 0 : -1;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        char *end;
        errno = 0;
        long v = strtol (ent->d_name, &end, 10);
        if (*end || v < 0) continue;
        if (errno || v >= INT_MAX) { closedir (d); errno = EOVERFLOW; return -1; }
        if (v > max) max = (int) v;
    }
    closedir (d);
    return max + 1;
}

/* Recursive rm -rf of PATH. Refuses empty, "/", or paths containing
 * "..". Doesn't descend through symlinks (lstat-based; symlinks are
 * unlinked, not followed). Used by win-kill to drop a window dir tree.
 * Returns 0 on success, -1 on error. Stage 9 (2026-05-07). */
static int
bs_rm_rf (const char *path)
{
    if (!path || !*path || !strcmp (path, "/")) return -1;
    if (strstr (path, "/../") || strstr (path, "/..")) return -1;

    struct stat st;
    if (lstat (path, &st) < 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }
    if (S_ISDIR (st.st_mode)) {
        DIR *d = opendir (path);
        if (!d) return -1;
        struct dirent *ent;
        char child[1024];
        int rc = 0;
        while ((ent = readdir (d)) != NULL) {
            if (!strcmp (ent->d_name, ".") || !strcmp (ent->d_name, "..")) continue;
            int n = snprintf (child, sizeof child, "%s/%s", path, ent->d_name);
            if (n < 0 || (size_t) n >= sizeof child) { rc = -1; break; }
            if (bs_rm_rf (child) < 0) { rc = -1; break; }
        }
        closedir (d);
        if (rc < 0) return -1;
        if (rmdir (path) < 0) return -1;
        return 0;
    }
    return unlink (path);
}

/* Does the window directory <sdir>/windows/<idx>/ exist?
 * Used by win-switch / win-rename / win-kill to validate the index. */
static int
bs_window_exists (const char *sdir, const char *idx)
{
    if (!idx || !*idx) return 0;
    for (const char *p = idx; *p; p++)
        if (*p < '0' || *p > '9') return 0;
    char path[1024];
    snprintf (path, sizeof path, "%s/windows/%s", sdir, idx);
    struct stat st;
    return (stat (path, &st) == 0 && S_ISDIR (st.st_mode));
}

/* Does <sdir>/windows/<win>/panes/<pane>/ exist?
 * Stage 18 v1 (2026-05-07). */
static int
bs_pane_exists (const char *sdir, const char *win, const char *pane)
{
    if (!bs_window_exists (sdir, win)) return 0;
    if (!pane || !*pane) return 0;
    for (const char *p = pane; *p; p++)
        if (*p < '0' || *p > '9') return 0;
    char path[1024];
    snprintf (path, sizeof path, "%s/windows/%s/panes/%s", sdir, win, pane);
    struct stat st;
    return (stat (path, &st) == 0 && S_ISDIR (st.st_mode));
}

static void
bs_read_active_pair (const char *sdir, char *win, size_t wsz, char *pane, size_t psz)
{
    char file[512], active[128] = "0:0";
    snprintf (file, sizeof file, "%s/active", sdir);
    if (bs_read_file (file, active, sizeof active) == 0) {
        char *colon = strchr (active, ':');
        if (colon) {
            *colon = '\0';
            snprintf (win, wsz, "%s", active);
            snprintf (pane, psz, "%s", colon + 1);
            return;
        }
    }
    snprintf (file, sizeof file, "%s/active-window", sdir);
    strcpy (win, "0");
    bs_read_file (file, win, wsz);
    snprintf (file, sizeof file, "%s/active-pane", sdir);
    strcpy (pane, "0");
    bs_read_file (file, pane, psz);
}

static int
bs_write_active_pair (const char *sdir, const char *win, const char *pane)
{
    char file[512], val[128];
    if (bs_window_exists (sdir, win)) {
        snprintf (file, sizeof file, "%s/windows/%s/active-pane", sdir, win);
        if (bs_write_file (file, pane) < 0) return -1;
    }
    snprintf (file, sizeof file, "%s/active-window", sdir);
    if (bs_write_file (file, win) < 0) return -1;
    snprintf (file, sizeof file, "%s/active-pane", sdir);
    if (bs_write_file (file, pane) < 0) return -1;
    snprintf (file, sizeof file, "%s/active", sdir);
    snprintf (val, sizeof val, "%s:%s\n", win, pane);
    return bs_write_file (file, val);
}

static int
bs_focus_window (const char *sdir, const char *win)
{
    char path[640], pane[64] = "0";
    snprintf (path, sizeof path, "%s/windows/%s/active-pane", sdir, win);
    (void) bs_read_file (path, pane, sizeof pane);
    if (!bs_pane_exists (sdir, win, pane)) {
        snprintf (path, sizeof path, "%s/windows/%s/panes", sdir, win);
        DIR *d = opendir (path);
        if (!d) return -1;
        struct dirent *ent;
        unsigned long best = ULONG_MAX;
        while ((ent = readdir (d)) != NULL) {
            if (!bs_pane_exists (sdir, win, ent->d_name)) continue;
            char *end;
            errno = 0;
            unsigned long n = strtoul (ent->d_name, &end, 10);
            if (!errno && !*end && n < best) best = n;
        }
        closedir (d);
        if (best == ULONG_MAX) { errno = ENOENT; return -1; }
        snprintf (pane, sizeof pane, "%lu", best);
    }
    return bs_write_active_pair (sdir, win, pane);
}

static int
bs_parse_target (const char *target, char *win, size_t wsz, char *pane, size_t psz)
{
    if (!target || !*target) return -1;
    const char *colon = strchr (target, ':');
    if (!colon) {
        snprintf (pane, psz, "%s", target);
        return 0;
    }
    size_t wl = (size_t)(colon - target);
    if (wl == 0 || wl >= wsz) return -1;
    memcpy (win, target, wl);
    win[wl] = '\0';
    snprintf (pane, psz, "%s", colon + 1);
    return *pane ? 0 : -1;
}

static int
bs_init_window_vt_metadata (const char *wdir)
{
    char file[512];
    snprintf (file, sizeof file, "%s/vt-handle", wdir);
    if (bs_write_file (file, "pending\n") < 0) return -1;
    snprintf (file, sizeof file, "%s/vt-generation", wdir);
    if (bs_write_file (file, "0\n") < 0) return -1;
    snprintf (file, sizeof file, "%s/vt-dirty", wdir);
    if (bs_write_file (file, "0\n") < 0) return -1;
    return 0;
}

static int
bs_parse_geom (const char *geom, long *r, long *c, long *rr, long *cc)
{
    const char *p = geom;
    long *values[] = { r, c, rr, cc };
    for (int i = 0; i < 4; i++) {
        char *end;
        errno = 0;
        *values[i] = strtol (p, &end, 10);
        if (errno || end == p || *values[i] < 0 || *values[i] > INT_MAX ||
            (i < 3 ? *end != ' ' : *end != '\0' && *end != '\n')) return -1;
        p = end + (i < 3);
    }
    return *rr > 65535 || *cc > 65535 ? -1 : 0;
}

static int
bs_create_window (const char *sdir, const char *wname)
{
    char parent[512], path[512], file[512], val[64];
    snprintf (parent, sizeof parent, "%s/windows", sdir);
    if (bs_mkdir_if_needed (parent, 0700) < 0) return -1;
    int idx = bs_next_numeric_dir (parent);
    if (idx < 0) return -1;
    snprintf (path, sizeof path, "%s/%d", parent, idx);
    if (mkdir (path, 0700) < 0) return -1;
    snprintf (file, sizeof file, "%s/name", path);
    /* Cap window name bytes to bound state-dir metadata size. */
    char wname_buf[BSCREEN_WINDOW_NAME_MAX + 1];
    const char *wname_eff = bs_window_name_capped (wname, wname_buf);
    if (bs_write_file (file, wname_eff) < 0) goto fail;
    snprintf (file, sizeof file, "%s/pid", path);
    snprintf (val, sizeof val, "0\n");
    if (bs_write_file (file, val) < 0) goto fail;
    if (bs_init_window_vt_metadata (path) < 0) goto fail;
    snprintf (file, sizeof file, "%s/panes", path);
    if (bs_mkdir_if_needed (file, 0700) < 0) goto fail;
    snprintf (path, sizeof path, "%s/windows/%d/panes/0", sdir, idx);
    if (bs_mkdir_if_needed (path, 0700) < 0) goto fail;
    snprintf (file, sizeof file, "%s/name", path);
    if (bs_write_file (file, "0") < 0) goto fail;
    snprintf (file, sizeof file, "%s/geom", path);
    if (bs_write_file (file, "0 0 24 80") < 0) goto fail;
    snprintf (file, sizeof file, "%s/scrollback", path);
    if (bs_write_file (file, "") < 0) goto fail;
    snprintf (file, sizeof file, "%s/pty.fd", path);
    if (bs_write_file (file, "metadata\n") < 0) goto fail;
    return idx;
fail:
    {
        int saved = errno;
        snprintf (path, sizeof path, "%s/windows/%d", sdir, idx);
        (void) bs_rm_rf (path);
        errno = saved;
        return -1;
    }
}

/* The backend marker distinguishes live services from explicit offline
 * fixtures. Numeric PIDs are diagnostic data, never authority to signal. */
static int
bs_broker_mode (const char *sdir)
{
    char file[640], value[32];
    snprintf (file, sizeof file, "%s/backend", sdir);
    return bs_read_file (file, value, sizeof value) == 0 &&
           !strcmp (value, "ptybroker");
}

static int
bs_broker_path (const char *sdir, const char *win, const char *pane,
                char root[640], char id[PB_ID_MAX + 1])
{
    char file[768];
    int n = snprintf (root, 640, "%s/brokers", sdir);
    if (n < 0 || n >= 640 || sdir[0] != '/') {
        errno = sdir[0] == '/' ? ENAMETOOLONG : EINVAL;
        return -1;
    }
    if (!bs_pane_exists (sdir, win, pane)) { errno = ENOENT; return -1; }
    snprintf (file, sizeof file, "%s/windows/%s/panes/%s/broker-id", sdir, win, pane);
    if (bs_read_file (file, id, PB_ID_MAX + 1) < 0) return -1;
    if (!pb_valid_id (id)) { errno = EINVAL; return -1; }
    return 0;
}

static int
bs_current_shell (char *path, size_t size)
{
    ssize_t n = readlink ("/proc/self/exe", path, size - 1);
    if (n < 0 || (size_t) n >= size - 1) return -1;
    path[n] = '\0';
    return 0;
}

static int
bs_broker_new_pane (const char *sdir, const char *win, const char *pane,
                    char *const *argv, const char *geom)
{
    char root[640], id[PB_ID_MAX + 1], file[768], value[768];
    char shell[4096], cwd[4096];
    char *default_argv[] = { shell, "--noprofile", "--norc", "-i", NULL };
    struct pb_status status;
    long r, c, rows, cols;
    if (!bs_broker_mode (sdir)) return 0;
    if (bs_parse_geom (geom, &r, &c, &rows, &cols) < 0 ||
        rows < 1 || cols < 1 || rows > 65535 || cols > 65535) {
        errno = EINVAL;
        return -1;
    }
    int n = snprintf (root, sizeof root, "%s/brokers", sdir);
    if (n < 0 || (size_t) n >= sizeof root || sdir[0] != '/') {
        errno = sdir[0] == '/' ? ENAMETOOLONG : EINVAL;
        return -1;
    }
    n = snprintf (id, sizeof id, "w%s-p%s", win, pane);
    if (n < 0 || (size_t) n >= sizeof id || !pb_valid_id (id)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (!argv || !argv[0]) {
        if (bs_current_shell (shell, sizeof shell) < 0) return -1;
        argv = default_argv;
    }
    if (!getcwd (cwd, sizeof cwd)) return -1;
    if (bos_ptybroker_create (root, id, argv, cwd, (unsigned) rows,
                              (unsigned) cols, &status) < 0) return -1;
    snprintf (file, sizeof file, "%s/windows/%s/panes/%s/broker-id", sdir, win, pane);
    if (bs_write_file (file, id) < 0) goto fail;
    snprintf (file, sizeof file, "%s/windows/%s/panes/%s/pid", sdir, win, pane);
    snprintf (value, sizeof value, "%d\n", status.child_pid);
    if (bs_write_file (file, value) < 0) goto fail;
    snprintf (file, sizeof file, "%s/windows/%s/panes/%s/pty.fd", sdir, win, pane);
    snprintf (value, sizeof value, "%s/%s/control.sock\n", root, id);
    if (bs_write_file (file, value) < 0) goto fail;
    snprintf (file, sizeof file, "%s/windows/%s/vt-handle", sdir, win);
    if (bs_write_file (file, "none: raw PTY service\n") < 0) goto fail;
    return 0;
fail:
    {
        int saved = errno;
        (void) pb_terminate (root, id);
        errno = saved;
        return -1;
    }
}

static int
bs_broker_stop_pane (const char *sdir, const char *win, const char *pane)
{
    char root[640], id[PB_ID_MAX + 1];
    if (!bs_broker_mode (sdir)) return 0;
    if (bs_broker_path (sdir, win, pane, root, id) < 0) return -1;
    if (pb_terminate (root, id) < 0 && errno != ENOENT) {
        builtin_error ("screen: terminate pane %s:%s: %s", win, pane, strerror (errno));
        return -1;
    }
    return 0;
}

static int
bs_broker_stop_window (const char *sdir, const char *win)
{
    char parent[640];
    if (!bs_broker_mode (sdir)) return 0;
    snprintf (parent, sizeof parent, "%s/windows/%s/panes", sdir, win);
    DIR *d = opendir (parent);
    if (!d) return -1;
    struct dirent *ent;
    int result = 0;
    while ((ent = readdir (d)) != NULL) {
        if (!bs_pane_exists (sdir, win, ent->d_name)) continue;
        if (bs_broker_stop_pane (sdir, win, ent->d_name) < 0) result = -1;
    }
    closedir (d);
    return result;
}

static int
bs_broker_stop_all (const char *sdir)
{
    char root[640];
    snprintf (root, sizeof root, "%s/brokers", sdir);
    DIR *d = opendir (root);
    if (!d) return errno == ENOENT ? 0 : -1;
    struct dirent *ent;
    int result = 0;
    while ((ent = readdir (d)) != NULL) {
        if (!pb_valid_id (ent->d_name)) continue;
        if (pb_terminate (root, ent->d_name) < 0 && errno != ENOENT) result = -1;
    }
    closedir (d);
    return result;
}

static int
bs_set_geometry (const char *sdir, const char *win, const char *pane,
                  const char *geom)
{
    char file[768], old[128], root[640], id[PB_ID_MAX + 1];
    long r, c, rows, cols;
    if (bs_parse_geom (geom, &r, &c, &rows, &cols) < 0 ||
        rows < 1 || cols < 1 || rows > 65535 || cols > 65535) {
        errno = EINVAL;
        builtin_error ("screen: pane size must be between 1 and 65535");
        return -1;
    }
    snprintf (file, sizeof file, "%s/windows/%s/panes/%s/geom", sdir, win, pane);
    if (bs_read_file (file, old, sizeof old) < 0) return -1;
    if (bs_broker_mode (sdir)) {
        if (bs_broker_path (sdir, win, pane, root, id) < 0 ||
            pb_resize (root, id, (unsigned) rows, (unsigned) cols) < 0) {
            builtin_error ("screen: resize pane %s:%s: %s", win, pane, strerror (errno));
            return -1;
        }
    }
    if (bs_write_file (file, geom) == 0) return 0;
    if (bs_broker_mode (sdir) && bs_parse_geom (old, &r, &c, &rows, &cols) == 0)
        (void) pb_resize (root, id, (unsigned) rows, (unsigned) cols);
    return -1;
}

static FILE *
bs_broker_history (const char *sdir, const char *win, const char *pane)
{
    char root[640], id[PB_ID_MAX + 1];
    if (bs_broker_path (sdir, win, pane, root, id) < 0) return NULL;
    FILE *f = tmpfile ();
    if (!f) return NULL;
    (void) fcntl (fileno (f), F_SETFD, FD_CLOEXEC);
    if (pb_capture (root, id, fileno (f)) < 0 || fseek (f, 0, SEEK_SET) < 0) {
        int saved = errno;
        fclose (f);
        errno = saved;
        return NULL;
    }
    return f;
}

static int
bs_broker_capture (const char *sdir, const char *win, const char *pane, int lines)
{
    FILE *f = bs_broker_history (sdir, win, pane);
    if (!f) {
        builtin_error ("capture-pane: %s:%s: %s", win, pane, strerror (errno));
        return EXECUTION_FAILURE;
    }
    unsigned char *data = malloc (PB_HISTORY + 1);
    if (!data) { fclose (f); return EXECUTION_FAILURE; }
    size_t size = fread (data, 1, PB_HISTORY + 1, f), start = 0;
    int error = ferror (f) ? EIO : size > PB_HISTORY ? EOVERFLOW : 0;
    fclose (f);
    if (lines > 0 && size) {
        size_t i = size;
        if (data[i - 1] == '\n') i--;
        while (i > 0) {
            if (data[--i] == '\n' && --lines == 0) { start = i + 1; break; }
        }
    }
    if (!error && bs_relay_write_all (STDOUT_FILENO, (char *) data + start,
                                     (ssize_t) (size - start)) < 0) error = errno;
    free (data);
    if (error) {
        builtin_error ("capture-pane: output: %s", strerror (error));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

/* Attach presents only new output from the focused pane. Switching focus
 * closes the old subscription before claiming the next pane's controller. */
static int
bs_attach_broker (const char *sdir, int observer)
{
    char root[640], id[PB_ID_MAX + 1], win[64], pane[64];
    char active_win[64] = "", active_pane[64] = "";
    char detach_file[640], detach_before[128] = "", detach_now[128];
    struct termios saved, raw;
    struct pb_status status;
    int fd = -1, raw_enabled = 0, pending = 0, result = BSCREEN_RELAY_EOF, stdin_open = 1;
    unsigned char prefix = bs_detach_key ();
    snprintf (detach_file, sizeof detach_file, "%s/detach", sdir);
    (void) bs_read_file (detach_file, detach_before, sizeof detach_before);
    if (isatty (STDIN_FILENO) && tcgetattr (STDIN_FILENO, &saved) == 0) {
        raw = saved;
        cfmakeraw (&raw);
        if (tcsetattr (STDIN_FILENO, TCSANOW, &raw) < 0) return BSCREEN_RELAY_ERROR;
        raw_enabled = 1;
    }
    for (;;) {
        bs_read_active_pair (sdir, win, sizeof win, pane, sizeof pane);
        if (strcmp (win, active_win) || strcmp (pane, active_pane)) {
            if (fd >= 0) close (fd);
            fd = -1;
            if (bs_broker_path (sdir, win, pane, root, id) < 0 ||
                pb_attach (root, id, observer ? PB_OBSERVE : PB_CONTROL, &fd, &status) < 0) {
                result = BSCREEN_RELAY_ERROR;
                break;
            }
            snprintf (active_win, sizeof active_win, "%s", win);
            snprintf (active_pane, sizeof active_pane, "%s", pane);
            pending = 0;
        }
        if (bs_read_file (detach_file, detach_now, sizeof detach_now) == 0 &&
            strcmp (detach_before, detach_now)) {
            result = BSCREEN_RELAY_DETACH;
            break;
        }
        struct pollfd fds[2] = { { fd, POLLIN, 0 }, { stdin_open ? STDIN_FILENO : -1, POLLIN, 0 } };
        if (poll (fds, 2, 100) < 0) { result = BSCREEN_RELAY_ERROR; break; }
        if (fds[0].revents & POLLIN) {
            struct pb_event event;
            if (pb_receive (fd, &event, 0) < 0) {
                if (errno != EAGAIN && errno != ETIMEDOUT) {
                    result = BSCREEN_RELAY_ERROR;
                    break;
                }
            } else if (event.type == PB_OUTPUT) {
                if (bs_relay_write_all (STDOUT_FILENO, (char *) event.data,
                                        (ssize_t) event.size) < 0) {
                    result = BSCREEN_RELAY_ERROR;
                    break;
                }
            } else if (event.type == PB_EXIT) break;
        } else if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (fds[1].revents & POLLIN) {
            unsigned char input[1024], output[1025];
            ssize_t n = read (STDIN_FILENO, input, sizeof input);
            size_t out = 0;
            if (n <= 0) {
                if (observer) { stdin_open = 0; continue; }
                if (pending && pb_send (root, id, &prefix, 1) < 0) result = BSCREEN_RELAY_ERROR;
                break;
            }
            for (ssize_t i = 0; i < n; i++) {
                if (pending) {
                    pending = 0;
                    if (input[i] == 'd' || input[i] == 'D') {
                        result = BSCREEN_RELAY_DETACH;
                        if (!observer && out && pb_send (root, id, output, out) < 0)
                            result = BSCREEN_RELAY_ERROR;
                        goto done;
                    }
                    if (bs_key_match (input[i], bs_roam_key ())) {
                        result = BSCREEN_RELAY_ROAM;
                        if (!observer && out && pb_send (root, id, output, out) < 0)
                            result = BSCREEN_RELAY_ERROR;
                        goto done;
                    }
                    output[out++] = prefix;
                    if (input[i] != prefix) output[out++] = input[i];
                } else if (input[i] == prefix) pending = 1;
                else output[out++] = input[i];
            }
            if (!observer && out && pb_send (root, id, output, out) < 0) {
                result = BSCREEN_RELAY_ERROR;
                break;
            }
        } else if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            if (observer) stdin_open = 0;
            else break;
        }
    }
done:
    {
        int saved_errno = errno;
        if (fd >= 0) close (fd);
        if (raw_enabled) (void) tcsetattr (STDIN_FILENO, TCSANOW, &saved);
        errno = saved_errno;
    }
    return result;
}

static int
bs_relay_write_all (int fd, const char *buf, ssize_t n)
{
    if (n < 0) { errno = EINVAL; return -1; }
    return pb_fd_write (fd, buf, (size_t) n, pb_now () + PB_TIMEOUT);
}

static int
bs_attach_live_relay (const char *sdir)
{
    if (bs_broker_mode (sdir)) return bs_attach_broker (sdir, 0);
    errno = ENOTSUP;
    return BSCREEN_RELAY_ERROR;
}

/* Consume an argv vector literally. Only an explicit -c asks the current
 * bash-os executable to interpret shell code. */
static int
bs_launch_argv (WORD_LIST *args, const char *code, char shell[4096],
                char *argv[128])
{
    int n = 0;
    if (code) {
        if (bs_current_shell (shell, 4096) < 0) return -1;
        argv[n++] = shell;
        argv[n++] = "--noprofile";
        argv[n++] = "--norc";
        argv[n++] = "-c";
        argv[n++] = (char *) code;
    }
    const char *w;
    while ((w = bs_word (&args)) != NULL) {
        if (n >= 127) { errno = E2BIG; return -1; }
        argv[n++] = (char *) w;
    }
    argv[n] = NULL;
    return 0;
}

static int
bscreen_run_cmd (WORD_LIST *args)
{
    const char *name = NULL, *code = NULL, *w;
    int metadata = 0;
    while (args) {
        w = args->word->word;
        if (!strcmp (w, "--")) { args = args->next; break; }
        if (!strcmp (w, "-n") || !strcmp (w, "-S")) {
            args = args->next;
            name = bs_word (&args);
            if (!name) { builtin_error ("run: -n requires NAME"); return EX_USAGE; }
        } else if (!strcmp (w, "-d") || !strcmp (w, "--detached")) args = args->next;
        else if (!strcmp (w, "--metadata")) { metadata = 1; args = args->next; }
        else if (!strcmp (w, "-c")) {
            args = args->next;
            code = bs_word (&args);
            if (!code) { builtin_error ("run: -c requires CODE"); return EX_USAGE; }
            break;
        } else if (!name) { name = w; args = args->next; }
        else break;
    }
    if (!name) name = "default";
    if (metadata && (code || args)) {
        builtin_error ("run: --metadata does not execute commands");
        return EX_USAGE;
    }
    char shell[4096], *argv[128];
    if (bs_launch_argv (args, code, shell, argv) < 0) {
        builtin_error ("run: command: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    char sdir[512], file[640];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0)
        return EXECUTION_FAILURE;
    if (!metadata && sdir[0] != '/') {
        builtin_error ("run: live sessions require an absolute BASHSCREEN_STATE_DIR");
        return EXECUTION_FAILURE;
    }
    if (mkdir (sdir, 0700) < 0) {
        builtin_error ("run: create %s: %s", name, strerror (errno));
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/backend", sdir);
    if (bs_write_file (file, metadata ? "metadata\n" : "ptybroker\n") < 0) goto fail;
    snprintf (file, sizeof file, "%s/pid", sdir);
    if (bs_write_file (file, "0\n") < 0) goto fail;
    snprintf (file, sizeof file, "%s/info", sdir);
    if (bs_write_file (file, metadata ? "screen offline layout\n" : "screen raw PTY panes\n") < 0)
        goto fail;
    if (bs_write_active_pair (sdir, "0", "0") < 0) goto fail;
    snprintf (file, sizeof file, "%s/scrollback", sdir);
    if (bs_write_file (file, "") < 0 || bs_create_window (sdir, "bash") < 0) goto fail;
    if (!metadata && bs_broker_new_pane (sdir, "0", "0", argv, "0 0 24 80") < 0) goto fail;
    snprintf (file, sizeof file, "%s/relay-status", sdir);
    if (bs_write_file (file, metadata ? "metadata-only; no PTY\n" :
                       "ptybroker raw-output; independent panes; no terminal checkpoint\n") < 0)
        goto fail;
    printf ("%s\n", name);
    return EXECUTION_SUCCESS;
fail:
    {
        int saved = errno;
        if (metadata || bs_broker_stop_all (sdir) == 0) (void) bs_rm_rf (sdir);
        builtin_error ("run: %s: %s", name, strerror (saved));
        return EXECUTION_FAILURE;
    }
}

static int
bscreen_kill_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("kill: NAME"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char sdir[512], file[512];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    snprintf (file, sizeof file, "%s/pid", sdir);
    if (access (file, F_OK) < 0) {
        builtin_error ("kill: no such session: %s", name);
        return EXECUTION_FAILURE;
    }
    if (bs_broker_mode (sdir)) {
        if (bs_broker_stop_all (sdir) < 0) {
            builtin_error ("kill: broker shutdown incomplete: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
    } else {
        char pidbuf[64];
        if (bs_read_file (file, pidbuf, sizeof pidbuf) == 0 && strcmp (pidbuf, "0")) {
            builtin_error ("kill: legacy relay identity is unverified; refusing a PID-file signal");
            return EXECUTION_FAILURE;
        }
    }
    if (bs_rm_rf (sdir) < 0) {
        builtin_error ("kill: failed to remove %s: %s", sdir, strerror (errno));
        return EXECUTION_FAILURE;
    }
    printf ("killed %s\n", name);
    return EXECUTION_SUCCESS;
}

static int
bscreen_attach_cmd (WORD_LIST *args)
{
    int force_detach = 0, detach_only = 0, multi = 0, live_request = 0, remote = 0, dry_run = 0;
    const char *name = NULL, *w, *key_override = NULL;
    while ((w = bs_word (&args)) != NULL) {
        if (!strcmp (w, "-d")) detach_only = 1;
        else if (!strcmp (w, "-x")) multi = 1;
        else if (!strcmp (w, "-r")) live_request = 1;
        else if (!strcmp (w, "-rd") || !strcmp (w, "-dr")) force_detach = 1;
        else if (!strcmp (w, "--remote")) remote = 1;
        else if (!strcmp (w, "--dry-run")) dry_run = 1;
        else if (!strcmp (w, "--key")) {
            key_override = bs_word (&args);
            if (!key_override) { builtin_error ("attach --key needs FILE"); return EX_USAGE; }
        }
        else if (!name) name = w;
        else { builtin_error ("attach: unexpected '%s'", w); return EX_USAGE; }
    }
    if (!name) { builtin_error ("attach: NAME [-r|-rd|-x|-d] [--remote --key FILE] [--dry-run]"); return EX_USAGE; }
    if (remote)
        return bscreen_attach_remote_cmd (name, key_override, dry_run);
    if (dry_run) { builtin_error ("attach: --dry-run requires --remote"); return EX_USAGE; }

    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], adir[512], val[256], active_win[64] = "0", active_pane[64] = "0";
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    snprintf (file, sizeof file, "%s/pid", sdir);
    if (access (file, R_OK) < 0) {
        builtin_error ("attach: no such session: %s", name);
        return EXECUTION_FAILURE;
    }

    if (bs_broker_mode (sdir)) {
        if (force_detach || detach_only) {
            struct timespec now;
            if (clock_gettime (CLOCK_MONOTONIC, &now) < 0) return EXECUTION_FAILURE;
            snprintf (file, sizeof file, "%s/detach", sdir);
            snprintf (val, sizeof val, "%ld %ld %ld\n", (long) getpid (),
                      (long) now.tv_sec, now.tv_nsec);
            if (bs_write_file (file, val) < 0) return EXECUTION_FAILURE;
            if (detach_only) { printf ("detached %s\n", name); return EXECUTION_SUCCESS; }
            /* Existing clients inspect the token at each 100ms poll. */
            for (int i = 0; i < 20; i++) {
                char broker_root[640], broker_id[PB_ID_MAX + 1];
                struct pb_status status;
                bs_read_active_pair (sdir, active_win, sizeof active_win,
                                     active_pane, sizeof active_pane);
                if (bs_broker_path (sdir, active_win, active_pane, broker_root, broker_id) < 0 ||
                    pb_status (broker_root, broker_id, &status) < 0 || !status.controller) break;
                if (poll (NULL, 0, 50) < 0) return EXECUTION_FAILURE;
            }
        }
        snprintf (adir, sizeof adir, "%s/attachers", sdir);
        if (bs_mkdir_if_needed (adir, 0700) < 0) return EXECUTION_FAILURE;
        snprintf (file, sizeof file, "%s/%ld", adir, (long) getpid ());
        snprintf (val, sizeof val, "pid %ld\nmode %s\nrelay ptybroker\nreplay none\n",
                  (long) getpid (), multi ? "observer" : "controller");
        if (bs_write_file (file, val) < 0) return EXECUTION_FAILURE;
        int result = bs_attach_broker (sdir, multi);
        int saved = errno;
        (void) unlink (file);
        if (result < 0) {
            builtin_error ("attach: %s: %s", name, strerror (saved));
            return EXECUTION_FAILURE;
        }
        return EXECUTION_SUCCESS;
    }

    if (live_request) {
        builtin_error ("attach: metadata session has no live PTY");
        return EXECUTION_FAILURE;
    }
    snprintf (adir, sizeof adir, "%s/attachers", sdir);
    if (bs_mkdir_if_needed (adir, 0700) < 0) return EXECUTION_FAILURE;

    if (force_detach || detach_only) {
        snprintf (file, sizeof file, "%s/detach", sdir);
        snprintf (val, sizeof val, "%ld\n", (long)getpid ());
        if (bs_write_file (file, val) < 0) return EXECUTION_FAILURE;
        if (!multi) bs_rm_rf (adir);
        if (detach_only) { printf ("detached %s\n", name); return EXECUTION_SUCCESS; }
        if (bs_mkdir_if_needed (adir, 0700) < 0) return EXECUTION_FAILURE;
    } else if (!multi && !live_request) {
        DIR *d = opendir (adir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir (d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                closedir (d);
                builtin_error ("attach: session already attached: %s", name);
                return EXECUTION_FAILURE;
            }
            closedir (d);
        }
    }

    snprintf (file, sizeof file, "%s/active-window", sdir);
    bs_read_file (file, active_win, sizeof active_win);
    snprintf (file, sizeof file, "%s/active-pane", sdir);
    bs_read_file (file, active_pane, sizeof active_pane);
    snprintf (file, sizeof file, "%s/%ld", adir, (long)getpid ());
    snprintf (val, sizeof val,
              "pid %ld\nmode %s\nwindow %s\npane %s\n"
              "last-seen-vt pending\nlast-seen-generation 0\n"
              "relay %s\n",
              (long)getpid (), multi ? "multi" : "single", active_win, active_pane,
              live_request ? "live" : "metadata");
    if (bs_write_file (file, val) < 0) return EXECUTION_FAILURE;
    if (live_request) {
        if (bs_attach_live_relay (sdir) >= 0) return EXECUTION_SUCCESS;
        builtin_error ("attach: live relay unavailable for %s", name);
        return EXECUTION_FAILURE;
    }
    printf ("metadata-attached %s %s\n", name, multi ? "multi" : "single");
    return EXECUTION_SUCCESS;
}

static int
bscreen_roam_cmd (WORD_LIST *args)
{
    int dry_run = 0;
    const char *target = NULL, *key_override = NULL, *w;
    while ((w = bs_word (&args)) != NULL) {
        if (!strcmp (w, "--dry-run")) dry_run = 1;
        else if (!strcmp (w, "--key")) {
            key_override = bs_word (&args);
            if (!key_override) { builtin_error ("roam --key needs FILE"); return EX_USAGE; }
        }
        else if (!target) target = w;
        else { builtin_error ("roam: unexpected '%s'", w); return EX_USAGE; }
    }
    if (!target) { builtin_error ("roam: NODE/SESSION [--key FILE] [--dry-run]"); return EX_USAGE; }

    if (dry_run) {
        char node[129], session[129], hostport[129], key[256], from[129] = "local";
        int resolved = bs_resolve_remote_target ("roam", target, key_override,
                                                 node, sizeof node, session, sizeof session,
                                                 hostport, sizeof hostport, key, sizeof key);
        if (resolved != EXECUTION_SUCCESS)
            return resolved;
        (void) bs_cluster_node_id (from, sizeof from);
        printf ("from=%s\nto=%s/%s\nhostport=%s\nkey=%s\ncommand=screen attach %s -r\n",
                from, node, session, hostport, key, session);
        return EXECUTION_SUCCESS;
    }

    return bscreen_attach_remote_cmd (target, key_override, 0);
}

static int
bscreen_state_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("state: NAME"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], active[64] = "0";
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    snprintf (file, sizeof file, "%s/pid", sdir);
    if (!bs_session_exists (sdir)) { builtin_error ("state: no such session: %s", name); return EXECUTION_FAILURE; }
    snprintf (file, sizeof file, "%s/active-window", sdir); bs_read_file (file, active, sizeof active);
    if (bs_broker_mode (sdir)) {
        char win[64], pane[64], info[512];
        bs_read_active_pair (sdir, win, sizeof win, pane, sizeof pane);
        int n = snprintf (info, sizeof info, "session %s\nactive-window %s\n"
                          "backend ptybroker\noutput raw-history\nactive-pane %s:%s\n",
                          name, active, win, pane);
        if (n < 0 || (size_t) n >= sizeof info ||
            bs_relay_write_all (STDOUT_FILENO, info, n) < 0) return EXECUTION_FAILURE;
        return bs_broker_capture (sdir, win, pane, 0);
    }
    printf ("session %s\nactive-window %s\n", name, active);
    snprintf (file, sizeof file, "%s/scrollback", sdir);
    FILE *f = fopen (file, "r");
    if (f) { int ch; while ((ch = fgetc (f)) != EOF) putchar (ch); fclose (f); }
    return EXECUTION_SUCCESS;
}

static int
bscreen_find_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *pat = bs_word (&args);
    if (!name || !pat) { builtin_error ("find: NAME PATTERN"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], line[1024];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) { builtin_error ("find: no such session: %s", name); return EXECUTION_FAILURE; }
    snprintf (file, sizeof file, "%s/scrollback", sdir);
    FILE *f;
    if (bs_broker_mode (sdir)) {
        char win[64], pane[64];
        bs_read_active_pair (sdir, win, sizeof win, pane, sizeof pane);
        f = bs_broker_history (sdir, win, pane);
        if (!f) return EXECUTION_FAILURE;
    } else f = fopen (file, "r");
    int row = 0;
    if (f) {
        while (fgets (line, sizeof line, f)) {
            row++;
            char *m = strstr (line, pat);
            if (m) printf ("%d %ld\n", row, (long)(m - line + 1));
        }
        fclose (f);
    }
    return EXECUTION_SUCCESS;
}

/* Stage 9 v1 (2026-05-07): win-list now marks the active window with a
 * trailing "*" and emits rows in numeric order, not directory order. */
static int
bscreen_win_list_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("win-list: NAME"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char path[512], parent[512], afile[512], active[64] = "0";
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (path, sizeof path, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (path)) { builtin_error ("win-list: no such session: %s", name); return EXECUTION_FAILURE; }
    snprintf (parent, sizeof parent, "%s/windows", path);
    snprintf (afile,  sizeof afile,  "%s/active-window", path);
    bs_read_file (afile, active, sizeof active);

    DIR *d = opendir (parent);
    if (!d) return EXECUTION_SUCCESS;
    /* Collect numeric children, sort ascending. */
    int idxs[256], n = 0;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL && n < (int)(sizeof idxs / sizeof idxs[0])) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end && *end == '\0' && v >= 0) idxs[n++] = (int) v;
    }
    closedir (d);
    /* Insertion sort — n is small (<=256). */
    for (int i = 1; i < n; i++) {
        int x = idxs[i], j = i;
        while (j > 0 && idxs[j-1] > x) { idxs[j] = idxs[j-1]; j--; }
        idxs[j] = x;
    }
    char nfile[512], wname[128];
    int active_idx = (int) strtol (active, NULL, 10);
    for (int i = 0; i < n; i++) {
        snprintf (nfile, sizeof nfile, "%s/%d/name", parent, idxs[i]);
        strcpy (wname, "bash"); bs_read_file (nfile, wname, sizeof wname);
        printf ("%d %s%s\n", idxs[i], wname, idxs[i] == active_idx ? " *" : "");
    }
    return EXECUTION_SUCCESS;
}

static int
bscreen_win_create_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *wname = NULL, *code = NULL;
    if (!name) { builtin_error ("win-create: NAME [WIN] [-c CODE | -- CMD...]"); return EX_USAGE; }
    while (args) {
        const char *w = args->word->word;
        if (!strcmp (w, "--")) { args = args->next; break; }
        if (!strcmp (w, "-c")) {
            args = args->next;
            code = bs_word (&args);
            if (!code) { builtin_error ("win-create: -c requires CODE"); return EX_USAGE; }
            break;
        }
        if (wname) { builtin_error ("win-create: use -- before CMD"); return EX_USAGE; }
        wname = w;
        args = args->next;
    }
    char sdir[512], path[640], win[64], shell[4096], *argv[128];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) { builtin_error ("win-create: no such session: %s", name); return EXECUTION_FAILURE; }
    if (!bs_broker_mode (sdir) && (code || args)) {
        builtin_error ("win-create: metadata sessions do not execute commands");
        return EXECUTION_FAILURE;
    }
    if (bs_launch_argv (args, code, shell, argv) < 0) return EXECUTION_FAILURE;
    int idx = bs_create_window (sdir, wname ? wname : "bash");
    if (idx < 0) return EXECUTION_FAILURE;
    snprintf (win, sizeof win, "%d", idx);
    if (bs_broker_new_pane (sdir, win, "0", argv, "0 0 24 80") < 0) {
        int saved = errno;
        snprintf (path, sizeof path, "%s/windows/%s", sdir, win);
        (void) bs_rm_rf (path);
        builtin_error ("win-create: %s", strerror (saved));
        return EXECUTION_FAILURE;
    }
    printf ("%d\n", idx);
    return EXECUTION_SUCCESS;
}

/* Stage 9 v1: validates that the requested window index exists before
 * writing active-window. Previously accepted any string. */
static int
bscreen_win_switch_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *idx = bs_word (&args);
    if (!name || !idx) { builtin_error ("win-switch: NAME INDEX"); return EX_USAGE; }
    char sdir[512];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_window_exists (sdir, idx)) {
        builtin_error ("win-switch: no such window %s in session %s", idx, name);
        return EXECUTION_FAILURE;
    }
    return bs_focus_window (sdir, idx) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* Stage 9 v1: win-rename NAME IDX NEWNAME — overwrite the window's
 * `name` metadata file. NEWNAME is constrained to the same charset as
 * session names (alphanumeric + . _ -) for path-safety even though it's
 * a content field, not a path component. */
static int
bscreen_win_rename_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *idx = bs_word (&args), *new_name = bs_word (&args);
    if (!name || !idx || !new_name) {
        builtin_error ("win-rename: NAME INDEX NEWNAME");
        return EX_USAGE;
    }
    if (!bs_name_ok (new_name)) {
        builtin_error ("win-rename: unsafe NEWNAME (alphanumeric + . _ - only)");
        return EX_USAGE;
    }
    char sdir[512], file[512];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_window_exists (sdir, idx)) {
        builtin_error ("win-rename: no such window %s in session %s", idx, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/windows/%s/name", sdir, idx);
    /* Cap window name bytes to bound state-dir metadata size. */
    char new_name_buf[BSCREEN_WINDOW_NAME_MAX + 1];
    const char *new_name_eff = bs_window_name_capped (new_name, new_name_buf);
    return bs_write_file (file, new_name_eff) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* Stage 9 v1: win-kill NAME IDX — drop the window dir tree. If the
 * killed window was the active one, advances to the lowest remaining
 * index (or leaves active-window pointing at "0" if no windows are
 * left, mirroring GNU screen's "session ends if last window closes"
 * — but the *session* lifetime is the run-loop's job, not ours). */
static int
bscreen_win_kill_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *idx = bs_word (&args);
    if (!name || !idx) { builtin_error ("win-kill: NAME INDEX"); return EX_USAGE; }
    char sdir[512], wpath[512], afile[512], active[64] = "0";
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_window_exists (sdir, idx)) {
        builtin_error ("win-kill: no such window %s in session %s", idx, name);
        return EXECUTION_FAILURE;
    }
    if (bs_broker_stop_window (sdir, idx) < 0) return EXECUTION_FAILURE;
    snprintf (wpath, sizeof wpath, "%s/windows/%s", sdir, idx);
    if (bs_rm_rf (wpath) < 0) {
        builtin_error ("win-kill: failed to remove %s: %s", wpath, strerror (errno));
        return EXECUTION_FAILURE;
    }
    /* If we just removed the active window, point active at the lowest
     * surviving index. */
    snprintf (afile, sizeof afile, "%s/active-window", sdir);
    bs_read_file (afile, active, sizeof active);
    if (!strcmp (active, idx)) {
        char parent[512]; snprintf (parent, sizeof parent, "%s/windows", sdir);
        DIR *d = opendir (parent);
        int next = -1;
        if (d) {
            struct dirent *ent;
            while ((ent = readdir (d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                char *end = NULL;
                long v = strtol (ent->d_name, &end, 10);
                if (end && *end == '\0' && (next < 0 || v < next)) next = (int) v;
            }
            closedir (d);
        }
        char val[64];
        snprintf (val, sizeof val, "%d\n", next < 0 ? 0 : next);
        if (bs_write_file (afile, val) < 0) return EXECUTION_FAILURE;
        snprintf (val, sizeof val, "%d", next < 0 ? 0 : next);
        if (next >= 0 && bs_focus_window (sdir, val) < 0) return EXECUTION_FAILURE;
        if (next < 0 && bs_write_active_pair (sdir, "0", "0") < 0) return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bscreen_win_cycle_cmd (WORD_LIST *args, int dir)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error (dir > 0 ? "win-next: NAME" : "win-prev: NAME"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char sdir[512], parent[512], afile[512], active[64] = "0";
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) { builtin_error (dir > 0 ? "win-next: no such session: %s" : "win-prev: no such session: %s", name); return EXECUTION_FAILURE; }
    snprintf (parent, sizeof parent, "%s/windows", sdir);
    snprintf (afile, sizeof afile, "%s/active-window", sdir);
    bs_read_file (afile, active, sizeof active);
    int active_idx = (int) strtol (active, NULL, 10);

    DIR *d = opendir (parent);
    if (!d) return EXECUTION_FAILURE;
    int idxs[256], n = 0;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL && n < (int)(sizeof idxs / sizeof idxs[0])) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end && *end == '\0' && v >= 0) idxs[n++] = (int) v;
    }
    closedir (d);
    if (n == 0) return EXECUTION_SUCCESS;
    for (int i = 1; i < n; i++) {
        int x = idxs[i], j = i;
        while (j > 0 && idxs[j-1] > x) { idxs[j] = idxs[j-1]; j--; }
        idxs[j] = x;
    }
    int pos = -1;
    for (int i = 0; i < n; i++)
        if (idxs[i] == active_idx) { pos = i; break; }
    if (pos < 0) pos = 0;
    int next_pos = dir > 0 ? (pos + 1) % n : (pos + n - 1) % n;
    char val[64];
    snprintf (val, sizeof val, "%d\n", idxs[next_pos]);
    snprintf (val, sizeof val, "%d", idxs[next_pos]);
    if (bs_focus_window (sdir, val) < 0) return EXECUTION_FAILURE;
    printf ("%d\n", idxs[next_pos]);
    return EXECUTION_SUCCESS;
}

/* Stage 18 v1 (2026-05-07): pane-list now sorts numerically and marks
 * the active pane with a trailing " *". Defaults WIN to active-window
 * when omitted (rather than the constant "0") so it matches operator
 * intent on multi-window sessions. */
static int
bscreen_pane_list_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = bs_word (&args);
    if (!name) { builtin_error ("pane-list: NAME [WIN]"); return EX_USAGE; }
    char sdir[512], parent[512], afile[512], abuf[64], pbuf[64];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!win) {
        snprintf (afile, sizeof afile, "%s/active-window", sdir);
        strcpy (abuf, "0"); bs_read_file (afile, abuf, sizeof abuf);
        win = abuf;
    }
    if (!bs_window_exists (sdir, win)) {
        builtin_error ("pane-list: no such window %s in session %s", win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (parent, sizeof parent, "%s/windows/%s/panes", sdir, win);
    snprintf (afile, sizeof afile, "%s/active-pane", sdir);
    strcpy (pbuf, "0"); bs_read_file (afile, pbuf, sizeof pbuf);
    int active_pane = (int) strtol (pbuf, NULL, 10);

    DIR *d = opendir (parent);
    if (!d) return EXECUTION_SUCCESS;
    int idxs[256], n = 0;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL && n < (int)(sizeof idxs / sizeof idxs[0])) {
        if (ent->d_name[0] == '.') continue;
        char *end = NULL;
        long v = strtol (ent->d_name, &end, 10);
        if (end && *end == '\0' && v >= 0) idxs[n++] = (int) v;
    }
    closedir (d);
    for (int i = 1; i < n; i++) {
        int x = idxs[i], j = i;
        while (j > 0 && idxs[j-1] > x) { idxs[j] = idxs[j-1]; j--; }
        idxs[j] = x;
    }
    char nfile[512], geom[128];
    for (int i = 0; i < n; i++) {
        snprintf (nfile, sizeof nfile, "%s/%d/geom", parent, idxs[i]);
        strcpy (geom, "0 0 24 80"); bs_read_file (nfile, geom, sizeof geom);
        printf ("%d %s%s\n", idxs[i], geom, idxs[i] == active_pane ? " *" : "");
    }
    return EXECUTION_SUCCESS;
}

/* Stage 18 v4: validates the requested WIN exists, then splits the
 * currently active pane's geometry instead of assigning a fixed
 * placeholder rectangle. `h` creates left/right panes; `v` creates
 * top/bottom panes. A one-cell gap is left for the eventual border. */
static int
bscreen_pane_split_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = NULL, *direction = "h", *code = NULL;
    if (!name) { builtin_error ("pane-split: NAME [WIN] [h|v] [-c CODE | -- CMD...]"); return EX_USAGE; }
    if (args && args->word->word[0] >= '0' && args->word->word[0] <= '9') win = bs_word (&args);
    if (args && (!strcasecmp (args->word->word, "h") || !strcasecmp (args->word->word, "v")))
        direction = bs_word (&args);
    if (args) {
        const char *w = bs_word (&args);
        if (!strcmp (w, "-c")) {
            code = bs_word (&args);
            if (!code) { builtin_error ("pane-split: -c requires CODE"); return EX_USAGE; }
        } else if (strcmp (w, "--")) {
            builtin_error ("pane-split: expected h, v, -c or --");
            return EX_USAGE;
        }
    }
    char sdir[512], parent[640], path[640], file[768], active[64], active_win[64];
    char geom[128], oldgeom[128], newgeom[128], pane[64], shell[4096], *argv[128];
    long r, c, rows, cols;
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    bs_read_active_pair (sdir, active_win, sizeof active_win, active, sizeof active);
    if (!win) win = active_win;
    if (!bs_window_exists (sdir, win)) {
        builtin_error ("pane-split: no such window %s in session %s", win, name);
        return EXECUTION_FAILURE;
    }
    if (strcmp (win, active_win)) {
        snprintf (file, sizeof file, "%s/windows/%s/active-pane", sdir, win);
        strcpy (active, "0");
        (void) bs_read_file (file, active, sizeof active);
    }
    if (!bs_pane_exists (sdir, win, active)) strcpy (active, "0");
    if (!bs_pane_exists (sdir, win, active)) {
        builtin_error ("pane-split: no active pane in window %s", win);
        return EXECUTION_FAILURE;
    }
    if (!bs_broker_mode (sdir) && (code || args)) {
        builtin_error ("pane-split: metadata sessions do not execute commands");
        return EXECUTION_FAILURE;
    }
    if (bs_launch_argv (args, code, shell, argv) < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/windows/%s/panes/%s/geom", sdir, win, active);
    if (bs_read_file (file, geom, sizeof geom) < 0 ||
        bs_parse_geom (geom, &r, &c, &rows, &cols) < 0) return EXECUTION_FAILURE;
    if (direction[0] == 'v' || direction[0] == 'V') {
        if (rows < 3) { builtin_error ("pane-split: pane too short"); return EXECUTION_FAILURE; }
        snprintf (oldgeom, sizeof oldgeom, "%ld %ld %ld %ld", r, c, rows / 2, cols);
        snprintf (newgeom, sizeof newgeom, "%ld %ld %ld %ld", r + rows / 2 + 1, c, rows - rows / 2 - 1, cols);
    } else {
        if (cols < 3) { builtin_error ("pane-split: pane too narrow"); return EXECUTION_FAILURE; }
        snprintf (oldgeom, sizeof oldgeom, "%ld %ld %ld %ld", r, c, rows, cols / 2);
        snprintf (newgeom, sizeof newgeom, "%ld %ld %ld %ld", r, c + cols / 2 + 1, rows, cols - cols / 2 - 1);
    }
    snprintf (parent, sizeof parent, "%s/windows/%s/panes", sdir, win);
    int idx = bs_next_numeric_dir (parent);
    if (idx < 0) return EXECUTION_FAILURE;
    snprintf (pane, sizeof pane, "%d", idx);
    snprintf (path, sizeof path, "%s/%s", parent, pane);
    if (mkdir (path, 0700) < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/name", path);
    if (bs_write_file (file, direction) < 0) goto fail;
    snprintf (file, sizeof file, "%s/geom", path);
    if (bs_write_file (file, newgeom) < 0) goto fail;
    snprintf (file, sizeof file, "%s/scrollback", path);
    if (bs_write_file (file, "") < 0) goto fail;
    snprintf (file, sizeof file, "%s/pty.fd", path);
    if (bs_write_file (file, "metadata\n") < 0) goto fail;
    if (bs_broker_new_pane (sdir, win, pane, argv, newgeom) < 0) goto fail;
    if (bs_set_geometry (sdir, win, active, oldgeom) < 0) goto stop;
    if (bs_write_active_pair (sdir, win, pane) < 0) {
        (void) bs_set_geometry (sdir, win, active, geom);
        goto stop;
    }
    printf ("%d\n", idx);
    return EXECUTION_SUCCESS;
stop:
    if (bs_broker_stop_pane (sdir, win, pane) < 0) return EXECUTION_FAILURE;
fail:
    {
        int saved = errno;
        (void) bs_rm_rf (path);
        builtin_error ("pane-split: %s", strerror (saved));
        return EXECUTION_FAILURE;
    }
}

/* Stage 18 v1: pane-select NAME PANE [WIN]. Validates that PANE exists
 * in WIN (default = active-window). Previously wrote any string to
 * active-pane regardless. */
static int
bscreen_pane_select_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *pane = bs_word (&args), *win = bs_word (&args);
    if (!name || !pane) { builtin_error ("pane-select: NAME PANE [WIN]"); return EX_USAGE; }
    char sdir[512], file[512], val[64], abuf[64];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!win) {
        snprintf (file, sizeof file, "%s/active-window", sdir);
        strcpy (abuf, "0"); bs_read_file (file, abuf, sizeof abuf);
        win = abuf;
    }
    if (!bs_pane_exists (sdir, win, pane)) {
        builtin_error ("pane-select: no such pane %s in window %s of session %s",
                       pane, win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/active-pane", sdir);
    snprintf (val, sizeof val, "%s\n", pane);
    if (bs_write_file (file, val) < 0) return EXECUTION_FAILURE;
    return bs_write_active_pair (sdir, win, pane) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bscreen_pane_select_dir_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = bs_word (&args);
    const char *pane = bs_word (&args), *dir = bs_word (&args);
    if (!name || !win || !pane || !dir) {
        builtin_error ("pane-select-dir: NAME WIN PANE U|D|L|R");
        return EX_USAGE;
    }
    char sdir[512], file[512], geom[128];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_pane_exists (sdir, win, pane)) {
        builtin_error ("pane-select-dir: no such pane %s in window %s of session %s", pane, win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/windows/%s/panes/%s/geom", sdir, win, pane);
    strcpy (geom, "0 0 24 80"); bs_read_file (file, geom, sizeof geom);
    long r, c, rr, cc;
    if (bs_parse_geom (geom, &r, &c, &rr, &cc) < 0) {
        builtin_error ("pane-select-dir: active pane GEOM must be four non-negative ints");
        return EXECUTION_FAILURE;
    }
    char parent[512]; snprintf (parent, sizeof parent, "%s/windows/%s/panes", sdir, win);
    DIR *d = opendir (parent);
    if (!d) return EXECUTION_FAILURE;
    int best = -1;
    long best_dist = 999999;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.' || !strcmp (ent->d_name, pane)) continue;
        char *end = NULL;
        long idx = strtol (ent->d_name, &end, 10);
        if (!end || *end != '\0') continue;
        snprintf (file, sizeof file, "%s/%s/geom", parent, ent->d_name);
        strcpy (geom, "");
        if (bs_read_file (file, geom, sizeof geom) < 0) continue;
        long pr, pc, prr, pcc, dist = 0;
        if (bs_parse_geom (geom, &pr, &pc, &prr, &pcc) < 0) continue;
        switch (dir[0]) {
        case 'U': case 'u':
            if (pr + prr > r || !(pc < c + cc && pc + pcc > c)) continue;
            dist = r - (pr + prr); break;
        case 'D': case 'd':
            if (pr < r + rr || !(pc < c + cc && pc + pcc > c)) continue;
            dist = pr - (r + rr); break;
        case 'L': case 'l':
            if (pc + pcc > c || !(pr < r + rr && pr + prr > r)) continue;
            dist = c - (pc + pcc); break;
        case 'R': case 'r':
            if (pc < c + cc || !(pr < r + rr && pr + prr > r)) continue;
            dist = pc - (c + cc); break;
        default:
            closedir (d);
            builtin_error ("pane-select-dir: direction must be U, D, L, or R");
            return EX_USAGE;
        }
        if (dist < best_dist) { best_dist = dist; best = (int) idx; }
    }
    closedir (d);
    if (best < 0) return EXECUTION_FAILURE;
    snprintf (file, sizeof file, "%s/active-pane", sdir);
    snprintf (geom, sizeof geom, "%d\n", best);
    if (bs_write_file (file, geom) < 0) return EXECUTION_FAILURE;
    snprintf (geom, sizeof geom, "%d", best);
    if (bs_write_active_pair (sdir, win, geom) < 0) return EXECUTION_FAILURE;
    printf ("%d\n", best);
    return EXECUTION_SUCCESS;
}

/* Stage 18 v1: pane-resize NAME WIN PANE GEOM. GEOM is "R C RR CC"
 * (row, col, rows, cols) — same shape pane-split writes initially. */
static int
bscreen_pane_resize_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = bs_word (&args), *pane = bs_word (&args);
    if (!name || !win || !pane) {
        builtin_error ("pane-resize: NAME WIN PANE GEOM");
        return EX_USAGE;
    }
    /* GEOM is the rest of the argv joined with spaces — accept either
     * a single quoted string or four positional ints. */
    char geom[128]; geom[0] = '\0';
    size_t off = 0;
    const char *w;
    while ((w = bs_word (&args)) != NULL) {
        size_t wn = strlen (w);
        if (off + wn + 2 > sizeof geom) {
            builtin_error ("pane-resize: GEOM too long");
            return EX_USAGE;
        }
        if (off) geom[off++] = ' ';
        memcpy (geom + off, w, wn);
        off += wn;
        geom[off] = '\0';
    }
    if (!*geom) {
        builtin_error ("pane-resize: GEOM required (e.g. \"0 0 12 40\")");
        return EX_USAGE;
    }
    /* Validate GEOM = four space-separated non-negative ints. */
    {
        const char *p = geom;
        for (int i = 0; i < 4; i++) {
            char *end = NULL;
            long v = strtol (p, &end, 10);
            if (end == p || v < 0 || (i < 3 ? *end != ' ' : (*end != '\0' && *end != '\n'))) {
                builtin_error ("pane-resize: GEOM must be four non-negative ints \"R C RR CC\"");
                return EX_USAGE;
            }
            p = end + (i < 3 ? 1 : 0);
        }
    }
    char sdir[512], file[512];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_pane_exists (sdir, win, pane)) {
        builtin_error ("pane-resize: no such pane %s in window %s of session %s",
                       pane, win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/windows/%s/panes/%s/geom", sdir, win, pane);
    return bs_set_geometry (sdir, win, pane, geom) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* Resize one pane and its real PTY. Neighbor redistribution remains a
 * layout policy operation for the caller. */
static int
bscreen_pane_resize_dir_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = bs_word (&args);
    const char *pane = bs_word (&args), *dir = bs_word (&args);
    const char *amount_s = bs_word (&args);
    if (!name || !win || !pane || !dir) {
        builtin_error ("pane-resize-dir: NAME WIN PANE U|D|L|R [N]");
        return EX_USAGE;
    }
    char *end = NULL;
    long amount = amount_s ? strtol (amount_s, &end, 10) : 1;
    if (amount <= 0 || amount > 65535 || (amount_s && (!end || *end != '\0'))) {
        builtin_error ("pane-resize-dir: N must be a positive integer");
        return EX_USAGE;
    }
    char sdir[512], file[512], geom[128];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_pane_exists (sdir, win, pane)) {
        builtin_error ("pane-resize-dir: no such pane %s in window %s of session %s",
                       pane, win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file, sizeof file, "%s/windows/%s/panes/%s/geom", sdir, win, pane);
    strcpy (geom, "0 0 24 80");
    bs_read_file (file, geom, sizeof geom);
    long r, c, rr, cc;
    if (bs_parse_geom (geom, &r, &c, &rr, &cc) < 0) goto bad_geom;
    if (strlen (dir) != 1) {
        builtin_error ("pane-resize-dir: direction must be U, D, L, or R");
        return EX_USAGE;
    }
    switch (dir[0]) {
    case 'U': case 'u': rr = rr > amount ? rr - amount : 1; break;
    case 'D': case 'd': rr += amount; break;
    case 'L': case 'l': cc = cc > amount ? cc - amount : 1; break;
    case 'R': case 'r': cc += amount; break;
    default:
        builtin_error ("pane-resize-dir: direction must be U, D, L, or R");
        return EX_USAGE;
    }
    snprintf (geom, sizeof geom, "%ld %ld %ld %ld", r, c, rr, cc);
    return bs_set_geometry (sdir, win, pane, geom) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;

bad_geom:
    builtin_error ("pane-resize-dir: stored GEOM must be four non-negative ints \"R C RR CC\"");
    return EXECUTION_FAILURE;
}

/* Exchange pane rectangles without changing process identities. */
static int
bscreen_pane_swap_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = bs_word (&args);
    const char *pane_a = bs_word (&args), *pane_b = bs_word (&args);
    if (!name || !win || !pane_a || !pane_b) {
        builtin_error ("pane-swap: NAME WIN PANE_A PANE_B");
        return EX_USAGE;
    }
    char sdir[512], file_a[512], file_b[512], geom_a[128], geom_b[128];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_pane_exists (sdir, win, pane_a)) {
        builtin_error ("pane-swap: no such pane %s in window %s of session %s",
                       pane_a, win, name);
        return EXECUTION_FAILURE;
    }
    if (!bs_pane_exists (sdir, win, pane_b)) {
        builtin_error ("pane-swap: no such pane %s in window %s of session %s",
                       pane_b, win, name);
        return EXECUTION_FAILURE;
    }
    snprintf (file_a, sizeof file_a, "%s/windows/%s/panes/%s/geom", sdir, win, pane_a);
    snprintf (file_b, sizeof file_b, "%s/windows/%s/panes/%s/geom", sdir, win, pane_b);
    strcpy (geom_a, "0 0 24 80"); bs_read_file (file_a, geom_a, sizeof geom_a);
    strcpy (geom_b, "0 0 24 80"); bs_read_file (file_b, geom_b, sizeof geom_b);
    if (bs_set_geometry (sdir, win, pane_a, geom_b) < 0) return EXECUTION_FAILURE;
    if (bs_set_geometry (sdir, win, pane_b, geom_a) < 0) {
        (void) bs_set_geometry (sdir, win, pane_a, geom_a);
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

/* Stage 18 v1: pane-kill NAME WIN PANE. Drops the pane dir tree; if it
 * was the active pane (and active-window matches WIN), advances
 * active-pane to the lowest surviving pane in that window (or 0 if no
 * panes left — the operator's run-loop owns kill-window-when-empty). */
static int
bscreen_pane_kill_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args), *win = bs_word (&args), *pane = bs_word (&args);
    if (!name || !win || !pane) { builtin_error ("pane-kill: NAME WIN PANE"); return EX_USAGE; }
    char sdir[512], ppath[512], afile[512], abuf[64], wbuf[64];
    if (bs_session_path (sdir, sizeof sdir, bscreen_state_dir (), name) < 0) return EX_USAGE;
    if (!bs_pane_exists (sdir, win, pane)) {
        builtin_error ("pane-kill: no such pane %s in window %s of session %s",
                       pane, win, name);
        return EXECUTION_FAILURE;
    }
    if (bs_broker_stop_pane (sdir, win, pane) < 0) return EXECUTION_FAILURE;
    snprintf (ppath, sizeof ppath, "%s/windows/%s/panes/%s", sdir, win, pane);
    if (bs_rm_rf (ppath) < 0) {
        builtin_error ("pane-kill: failed to remove %s: %s", ppath, strerror (errno));
        return EXECUTION_FAILURE;
    }
    /* If the killed pane was the active one (and we're killing in the
     * active window), advance to the lowest surviving sibling. */
    snprintf (afile, sizeof afile, "%s/active-pane", sdir);
    strcpy (abuf, ""); bs_read_file (afile, abuf, sizeof abuf);
    char wfile[512]; snprintf (wfile, sizeof wfile, "%s/active-window", sdir);
    strcpy (wbuf, ""); bs_read_file (wfile, wbuf, sizeof wbuf);
    if (!strcmp (abuf, pane) && !strcmp (wbuf, win)) {
        char parent[512]; snprintf (parent, sizeof parent, "%s/windows/%s/panes", sdir, win);
        DIR *d = opendir (parent);
        int next = -1;
        if (d) {
            struct dirent *ent;
            while ((ent = readdir (d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                char *end = NULL;
                long v = strtol (ent->d_name, &end, 10);
                if (end && *end == '\0' && (next < 0 || v < next)) next = (int) v;
            }
            closedir (d);
        }
        char val[64];
        snprintf (val, sizeof val, "%d\n", next < 0 ? 0 : next);
        if (bs_write_file (afile, val) < 0) return EXECUTION_FAILURE;
        snprintf (val, sizeof val, "%d", next < 0 ? 0 : next);
        if (bs_write_active_pair (sdir, win, val) < 0) return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bscreen_send_keys_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("send-keys: NAME KEYS..."); return EX_USAGE; }
    const char *target = NULL;
    if (args && args->word && args->word->word &&
        (!strcmp (args->word->word, "-p") || !strcmp (args->word->word, "-t"))) {
        args = args->next;
        if (!args || !args->word || !args->word->word) {
            builtin_error ("send-keys: -p requires WIN:PANE or PANE");
            return EX_USAGE;
        }
        target = args->word->word;
        args = args->next;
    }
    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], win[64], pane[64];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    snprintf (file, sizeof file, "%s/pid", sdir);
    if (access (file, R_OK) < 0) { builtin_error ("send-keys: no such session: %s", name); return EXECUTION_FAILURE; }
    bs_read_active_pair (sdir, win, sizeof win, pane, sizeof pane);
    if (target && bs_parse_target (target, win, sizeof win, pane, sizeof pane) < 0) {
        builtin_error ("send-keys: invalid target: %s", target);
        return EX_USAGE;
    }
    if (!bs_pane_exists (sdir, win, pane)) {
        builtin_error ("send-keys: no such pane %s in window %s of session %s", pane, win, name);
        return EXECUTION_FAILURE;
    }
    if (!bs_broker_mode (sdir)) {
        builtin_error ("send-keys: metadata session has no live PTY");
        return EXECUTION_FAILURE;
    }
    char broker_root[640], broker_id[PB_ID_MAX + 1];
    unsigned char data[PB_CHUNK];
    size_t size = 0;
    int first = 1;
    const char *w;
    while ((w = bs_word (&args)) != NULL) {
        size_t n = strlen (w);
        size_t separator = first ? 0 : 1;
        if (size > sizeof data - separator - 1 ||
            n > sizeof data - size - separator - 1) {
            builtin_error ("send-keys: input exceeds %u bytes", PB_CHUNK);
            return EXECUTION_FAILURE;
        }
        if (separator) data[size++] = ' ';
        memcpy (data + size, w, n);
        size += n;
        first = 0;
    }
    data[size++] = '\n';
    if (bs_broker_path (sdir, win, pane, broker_root, broker_id) < 0 ||
        pb_send (broker_root, broker_id, data, size) < 0) {
        builtin_error ("send-keys: %s:%s: %s", win, pane, strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bscreen_send_mouse_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("send-mouse: NAME [WIN PANE] BUTTON ROW COL [ACTION]"); return EX_USAGE; }
    const char *words[6];
    int n = 0;
    const char *w;
    while ((w = bs_word (&args)) != NULL && n < 6) words[n++] = w;
    if (bs_word (&args) != NULL) { builtin_error ("send-mouse: too many arguments"); return EX_USAGE; }
    if (n != 3 && n != 4 && n != 5 && n != 6) {
        builtin_error ("send-mouse: NAME [WIN PANE] BUTTON ROW COL [ACTION]");
        return EX_USAGE;
    }

    const char *win = NULL, *pane = NULL, *button, *row, *col, *action = "press";
    if (n >= 5) {
        win = words[0]; pane = words[1]; button = words[2]; row = words[3]; col = words[4];
        if (n == 6) action = words[5];
    } else {
        button = words[0]; row = words[1]; col = words[2];
        if (n == 4) action = words[3];
    }

    char *end = NULL;
    long r = strtol (row, &end, 10);
    if (!end || *end || r < 0) { builtin_error ("send-mouse: invalid row: %s", row); return EX_USAGE; }
    long c = strtol (col, &end, 10);
    if (!end || *end || c < 0) { builtin_error ("send-mouse: invalid col: %s", col); return EX_USAGE; }

    const char *root = bscreen_state_dir ();
    char sdir[512], file[512];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    snprintf (file, sizeof file, "%s/pid", sdir);
    if (access (file, R_OK) < 0) { builtin_error ("send-mouse: no such session: %s", name); return EXECUTION_FAILURE; }
    if (win && pane && !bs_pane_exists (sdir, win, pane)) {
        builtin_error ("send-mouse: no such pane %s in window %s of session %s", pane, win, name);
        return EXECUTION_FAILURE;
    }

    if (bs_broker_mode (sdir)) {
        builtin_error ("send-mouse: raw PTY sessions require frontend mouse-mode encoding");
        return EXECUTION_FAILURE;
    }

    snprintf (file, sizeof file, "%s/mouse", sdir);
    FILE *mf = fopen (file, "a");
    if (!mf) return EXECUTION_FAILURE;
    if (win && pane) fprintf (mf, "%s %s %s %ld %ld %s\n", win, pane, button, r, c, action);
    else fprintf (mf, "%s %ld %ld %s\n", button, r, c, action);
    fclose (mf);

    snprintf (file, sizeof file, "%s/scrollback", sdir);
    FILE *sf = fopen (file, "a");
    if (!sf) return EXECUTION_FAILURE;
    if (win && pane) fprintf (sf, "mouse %s %s %s %ld %ld %s\n", win, pane, button, r, c, action);
    else fprintf (sf, "mouse %s %ld %ld %s\n", button, r, c, action);
    fclose (sf);
    bs_pane_scrollback_maintain (file);
    return EXECUTION_SUCCESS;
}

static int
bscreen_capture_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("capture-pane: NAME"); return EX_USAGE; }
    int limit = 0;
    const char *target = NULL;
    const char *w;
    while ((w = bs_word (&args)) != NULL) {
        if ((!strcmp (w, "-N") || !strcmp (w, "-n")) && args) {
            const char *value = bs_word (&args);
            char *end;
            errno = 0;
            long parsed = strtol (value, &end, 10);
            if (errno || end == value || *end || parsed < 0 || parsed > INT_MAX) {
                builtin_error ("capture-pane: -N requires a non-negative line count");
                return EX_USAGE;
            }
            limit = (int) parsed;
        } else if ((!strcmp (w, "-t") || !strcmp (w, "-p")) && args) {
            target = bs_word (&args);
        } else {
            builtin_error ("capture-pane: unexpected '%s'", w);
            return EX_USAGE;
        }
    }
    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], win[64], pane[64];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) { builtin_error ("capture-pane: no such session: %s", name); return EXECUTION_FAILURE; }
    if (bs_broker_mode (sdir)) {
        bs_read_active_pair (sdir, win, sizeof win, pane, sizeof pane);
        if ((target && bs_parse_target (target, win, sizeof win, pane, sizeof pane) < 0) ||
            !bs_pane_exists (sdir, win, pane)) {
            builtin_error ("capture-pane: no such target");
            return EXECUTION_FAILURE;
        }
        return bs_broker_capture (sdir, win, pane, limit);
    }
    if (target) {
        bs_read_active_pair (sdir, win, sizeof win, pane, sizeof pane);
        if (bs_parse_target (target, win, sizeof win, pane, sizeof pane) < 0) {
            builtin_error ("capture-pane: invalid target: %s", target);
            return EX_USAGE;
        }
    }
    if (target && bs_pane_exists (sdir, win, pane))
        snprintf (file, sizeof file, "%s/windows/%s/panes/%s/scrollback", sdir, win, pane);
    else
        snprintf (file, sizeof file, "%s/scrollback", sdir);

    /* Stage 50.F: read compressed blobs (oldest first) before the
     * live scrollback so callers see the full history transparently. */
    char blobs_dir[1024];
    int has_blobs = 0;
    char **blob_names = NULL;
    int n_blobs = 0;
    if (bs_scrollback_blobs_dir (file, blobs_dir, sizeof blobs_dir) == 0) {
        struct stat bd;
        if (stat (blobs_dir, &bd) == 0 && S_ISDIR (bd.st_mode)) {
            has_blobs = 1;
            n_blobs = bs_list_blobs_sorted (blobs_dir, &blob_names);
        }
    }

    if (limit <= 0) {
        for (int i = 0; i < n_blobs; i++) {
            char bp[1100];
            snprintf (bp, sizeof bp, "%s/%s", blobs_dir, blob_names[i]);
            bs_stream_blob (bp);
        }
        FILE *f = fopen (file, "r");
        if (f) {
            int ch; while ((ch = fgetc (f)) != EOF) putchar (ch);
            fclose (f);
        }
    } else {
        /* Stage 50.F -N path (v3.5 -- Round 1778564979 Doc 2,
         * screen-capture-N-cross-blob, 2026-05-12).
         *
         * v3.3 produced empty guest output: mixed FILE-star vs fd I/O
         * and shared realloc ownership between getline and the
         * bs_ring_feed helper. v3.4 collapsed to one I/O shape
         * (single buffer then write to fd 1) which was algorithmically
         * correct on paper but still produced count=0 in the v3.3
         * sweep for cases 4, 9, and 10. The doc explicitly fences
         * this round to "decompress and concat from oldest needed
         * blob forward" rather than decompressing every blob
         * unconditionally.
         *
         * v3.5 algorithm:
         *   1. Read live tail into buf first.
         *   2. Count newlines in buf. If already at-or-above limit,
         *      jump straight to the suffix walk.
         *   3. Otherwise, walk blobs newest-to-oldest, decompressing
         *      each in front of buf until cumulative newline count
         *      reaches limit. Older blobs are NEVER touched.
         *   4. Walk back from end-of-buf to find the start of the
         *      last limit lines; write that suffix to fd 1.
         *
         * The oldest-needed-blob-first concat shape matches the
         * doc's instruction and bounds the buffer size to whatever
         * fits the requested suffix -- important for very long
         * scrollback histories where the v3.4 decompress-all could
         * allocate hundreds of MB on the guest.
         *
         * BASHSCREEN_DEBUG_CAPTURE=1 (env var) emits a single
         * diagnostic line to stderr so operator sweeps can see at
         * a glance whether the blob walk fired and what byte counts
         * resulted. Stays silent otherwise.
         */
        const char *dbg_env = getenv ("BASHSCREEN_DEBUG_CAPTURE");
        int dbg = (dbg_env && *dbg_env && *dbg_env != '0');

        size_t bcap = 0, blen = 0;
        char *buf = NULL;
        size_t live_bytes = 0;

        /* Step 1 -- live tail first. */
        FILE *f = fopen (file, "r");
        if (f) {
            char rdbuf[8192];
            size_t nr;
            while ((nr = fread (rdbuf, 1, sizeof rdbuf, f)) > 0) {
                if (blen + nr + 1 > bcap) {
                    size_t nc = bcap ? bcap * 2 : 8192;
                    while (nc < blen + nr + 1) nc *= 2;
                    char *p = realloc (buf, nc);
                    if (!p) { break; }
                    buf = p; bcap = nc;
                }
                memcpy (buf + blen, rdbuf, nr);
                blen += nr;
            }
            fclose (f);
            live_bytes = blen;
        }

        /* Newline count for current `buf`. A trailing '\n' counts as
         * the end of the final line, not as an extra empty line. */
        int nl_count = 0;
        for (size_t k = 0; k < blen; k++)
            if (buf[k] == '\n') nl_count++;
        if (blen > 0 && buf && buf[blen - 1] != '\n') nl_count++;

        /* Step 2/3 — walk blobs newest→oldest if needed. We
         * decompress each blob into a temporary slab, then PREPEND
         * it to `buf` (memmove existing content right, copy slab
         * into the new head). Stops as soon as nl_count >= limit. */
        int blobs_used = 0;
        for (int i = n_blobs - 1; i >= 0 && nl_count < limit; i--) {
            char bp[1100];
            snprintf (bp, sizeof bp, "%s/%s", blobs_dir, blob_names[i]);
            gzFile gz = gzopen (bp, "rb");
            if (!gz) {
                builtin_warning ("capture-pane: failed to open %s",
                                 blob_names[i]);
                continue;
            }
            /* Decompress this blob into a fresh slab so we can
             * PREPEND atomically. Two-pass realloc would have to
             * memmove the entire current buf on every chunk; one
             * full-slab + one memmove is the cheaper shape. */
            size_t scap = 8192, slen = 0;
            char *slab = malloc (scap);
            int gerr = 0;
            if (!slab) {
                gerr = 1;
            } else {
                char rdbuf[8192];
                int nr;
                while ((nr = gzread (gz, rdbuf, sizeof rdbuf)) > 0) {
                    if (slen + (size_t) nr > scap) {
                        size_t nc = scap * 2;
                        while (nc < slen + (size_t) nr) nc *= 2;
                        char *p = realloc (slab, nc);
                        if (!p) { gerr = 1; break; }
                        slab = p; scap = nc;
                    }
                    memcpy (slab + slen, rdbuf, (size_t) nr);
                    slen += (size_t) nr;
                }
            }
            gzclose (gz);
            if (gerr) {
                builtin_warning ("capture-pane: oom decompressing %s",
                                 blob_names[i]);
                free (slab);
                continue;
            }
            /* Prepend slab to buf: grow buf, memmove existing right,
             * copy slab into the head. */
            if (slen > 0) {
                if (blen + slen + 1 > bcap) {
                    size_t nc = bcap ? bcap : 8192;
                    while (nc < blen + slen + 1) nc *= 2;
                    char *p = realloc (buf, nc);
                    if (!p) { free (slab); continue; }
                    buf = p; bcap = nc;
                }
                if (blen > 0) memmove (buf + slen, buf, blen);
                memcpy (buf, slab, slen);
                blen += slen;
                for (size_t k = 0; k < slen; k++)
                    if (slab[k] == '\n') nl_count++;
            }
            free (slab);
            blobs_used++;
        }

        if (dbg) {
            fprintf (stderr,
                "screen capture-N: limit=%d blobs_seen=%d "
                "live_bytes=%zu total=%zu nl=%d\n",
                limit, blobs_used, live_bytes, blen, nl_count);
        }

        /* Step 4 — walk backwards from end of `buf` to locate the
         * start of the last `limit` lines, then write that suffix
         * directly to fd 1. Identical shape to v3.4's tail walk so
         * regression risk is bounded to the prepend logic above.
         *
         * Round 1778571667 / Doc 1 (2026-05-12, v3.6): defensively
         * fflush(stdout) before the raw write() ladder. Static-musl
         * bash buffers stdout fully when fd 1 is a pipe (the shape
         * used by `out=$(...)` capture); any stdio output from the
         * surrounding bash invocation that landed in the FILE*'s
         * buffer would otherwise be flushed AFTER our raw write()
         * bytes when the builtin returns — interleaving the output
         * across the seam between bash's stdout buffer and the kernel
         * pipe, and producing exactly the count=0 shape seen in cases
         * 4/7/8 across five prior fix rounds. The fflush() is cheap
         * (typical bash stdout buffer is empty at builtin entry) and
         * makes the -N branch's output order deterministic regardless
         * of caller-side stdio activity. */
        fflush (stdout);
        if (blen > 0 && buf) {
            ssize_t cursor = (ssize_t) blen - 1;
            int seen = 0;
            ssize_t start_off = 0;
            if (buf[cursor] == '\n') cursor--;
            while (cursor >= 0) {
                if (buf[cursor] == '\n') {
                    seen++;
                    if (seen >= limit) {
                        start_off = cursor + 1;
                        break;
                    }
                }
                cursor--;
            }
            if (seen < limit) start_off = 0;
            size_t out_len = blen - (size_t) start_off;
            const char *p = buf + start_off;
            size_t left = out_len;
            while (left > 0) {
                ssize_t w = write (STDOUT_FILENO, p, left);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                p += w; left -= (size_t) w;
            }
        }
        free (buf);
    }
    for (int i = 0; i < n_blobs; i++) free (blob_names[i]);
    free (blob_names);
    (void) has_blobs;
    return EXECUTION_SUCCESS;
}

/* `screen list` — enumerate active sessions. Skeleton just scans
   the state directory and prints names of subdirs that contain a
   readable `pid` file. Empty output when no sessions. Refuses to
   touch a state dir that fails the private-dir contract. */
static int
bscreen_list_cmd (WORD_LIST *args)
{
    const char *w;
    while ((w = bs_word (&args)) != NULL) {
        if (!strcmp (w, "--cluster"))
            return bscreen_cluster_list_cmd ();
        builtin_error ("list: unexpected '%s'", w);
        return EX_USAGE;
    }
    const char *root = bscreen_state_dir ();
    /* Walk the contract first; if the dir doesn't exist yet we
       create it (0700) to lock in the contract for any subsequent
       writes by the multiplexer server. */
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    DIR *d = opendir (root);
    if (!d) {
        if (errno == ENOENT) return EXECUTION_SUCCESS;  /* no sessions yet */
        builtin_error ("opendir %s: %s", root, strerror (errno));
        return EXECUTION_FAILURE;
    }
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char pidpath[512];
        snprintf (pidpath, sizeof pidpath, "%s/%s/pid", root, ent->d_name);
        struct stat st;
        if (stat (pidpath, &st) == 0 && S_ISREG (st.st_mode))
            printf ("%s\n", ent->d_name);
    }
    closedir (d);
    return EXECUTION_SUCCESS;
}

static int
bscreen_relay_status_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("relay-status: NAME"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], line[256];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) {
        builtin_error ("relay-status: no such session: %s", name);
        return EXECUTION_FAILURE;
    }
    if (bs_broker_mode (sdir)) {
        char win[64], pane[64], broker_root[640], id[PB_ID_MAX + 1];
        struct pb_status status;
        bs_read_active_pair (sdir, win, sizeof win, pane, sizeof pane);
        if (bs_broker_path (sdir, win, pane, broker_root, id) < 0 ||
            pb_status (broker_root, id, &status) < 0) {
            builtin_error ("relay-status: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        printf ("backend ptybroker\npane %s:%s\nbroker %d\nchild %d\n"
                "running %d\nsize %u %u\ncontroller %u\nobservers %u\n"
                "history raw-bounded\nterminal-checkpoint none\nattach-replay none\n",
                win, pane, status.broker_pid, status.child_pid, status.running,
                status.rows, status.cols, status.controller, status.observers);
        return EXECUTION_SUCCESS;
    }
    snprintf (file, sizeof file, "%s/relay-status", sdir);
    if (bs_read_file (file, line, sizeof line) < 0)
        strcpy (line, "live-relay unavailable");
    printf ("%s\n", line);
    return EXECUTION_SUCCESS;
}

static int
bscreen_vt_info_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    const char *win = bs_word (&args);
    if (!name) { builtin_error ("vt-info: NAME [WIN]"); return EX_USAGE; }

    const char *root = bscreen_state_dir ();
    char sdir[512], file[512], active[64] = "0";
    char handle[128] = "pending", gen[64] = "0", dirty[64] = "0";
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) {
        builtin_error ("vt-info: no such session: %s", name);
        return EXECUTION_FAILURE;
    }
    if (!win) {
        snprintf (file, sizeof file, "%s/active-window", sdir);
        bs_read_file (file, active, sizeof active);
        win = active;
    }
    if (!bs_window_exists (sdir, win)) {
        builtin_error ("vt-info: no such window %s in session %s", win, name);
        return EXECUTION_FAILURE;
    }
    if (bs_broker_mode (sdir)) {
        printf ("window %s\nbackend ptybroker\nterminal-state none\n"
                "output raw-bytes\nhistory bounded\nattach-replay none\n"
                "graphics-state frontend-owned\n", win);
        return EXECUTION_SUCCESS;
    }
    snprintf (file, sizeof file, "%s/windows/%s/vt-handle", sdir, win);
    bs_read_file (file, handle, sizeof handle);
    snprintf (file, sizeof file, "%s/windows/%s/vt-generation", sdir, win);
    bs_read_file (file, gen, sizeof gen);
    snprintf (file, sizeof file, "%s/windows/%s/vt-dirty", sdir, win);
    bs_read_file (file, dirty, sizeof dirty);

    printf ("window %s\nvt-handle %s\nvt-generation %s\nvt-dirty %s\nrelay none: offline metadata\n",
            win, handle, gen, dirty);
    return EXECUTION_SUCCESS;
}

static int
bscreen_client_list_cmd (WORD_LIST *args)
{
    const char *name = bs_word (&args);
    if (!name) { builtin_error ("client-list: NAME"); return EX_USAGE; }
    const char *root = bscreen_state_dir ();
    char sdir[512], adir[512], file[512], line[256];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    if (bs_session_path (sdir, sizeof sdir, root, name) < 0) return EX_USAGE;
    if (!bs_session_exists (sdir)) {
        builtin_error ("client-list: no such session: %s", name);
        return EXECUTION_FAILURE;
    }
    snprintf (adir, sizeof adir, "%s/attachers", sdir);
    DIR *d = opendir (adir);
    if (!d) return EXECUTION_SUCCESS;
    struct dirent *ent;
    while ((ent = readdir (d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        snprintf (file, sizeof file, "%s/%s", adir, ent->d_name);
        FILE *f = fopen (file, "r");
        if (!f) continue;
        printf ("client %s\n", ent->d_name);
        while (fgets (line, sizeof line, f)) fputs (line, stdout);
        fclose (f);
    }
    closedir (d);
    return EXECUTION_SUCCESS;
}

/* `screen state-dir` — print the current state directory path
   (handy for shell scripts wiring up against screen). Bonus
   skeleton verb not in the original surface table. */
static int
bscreen_state_dir_cmd (WORD_LIST *args)
{
    (void) args;
    printf ("%s\n", bscreen_state_dir ());
    return EXECUTION_SUCCESS;
}

static int
bs_remote_frame_type_id (const char *s)
{
    if (!s) return -1;
    if (!strcmp (s, "pty")) return BSCREEN_REMOTE_FRAME_PTY;
    if (!strcmp (s, "query")) return BSCREEN_REMOTE_FRAME_QUERY;
    if (!strcmp (s, "control")) return BSCREEN_REMOTE_FRAME_CONTROL;
    return -1;
}

static const char *
bs_remote_frame_type_name (int type)
{
    switch (type) {
    case BSCREEN_REMOTE_FRAME_PTY: return "pty";
    case BSCREEN_REMOTE_FRAME_QUERY: return "query";
    case BSCREEN_REMOTE_FRAME_CONTROL: return "control";
    default: return "unknown";
    }
}

static int
bs_read_exact_fd (int fd, void *buf, size_t n)
{
    char *p = (char *) buf;
    size_t off = 0;
    while (off < n) {
        ssize_t r = read (fd, p + off, n - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        off += (size_t) r;
    }
    return 0;
}

static int
bscreen_remote_frame_cmd (WORD_LIST *args)
{
    const char *sub = bs_word (&args);
    if (!sub) { builtin_error ("remote-frame: encode TYPE PAYLOAD | decode"); return EX_USAGE; }
    if (!strcmp (sub, "encode")) {
        const char *type_s = bs_word (&args);
        const char *payload = bs_word (&args);
        int type = bs_remote_frame_type_id (type_s);
        struct bs_remote_frame_header h;
        if (type < 0 || !payload || bs_word (&args) != NULL) {
            builtin_error ("remote-frame encode: TYPE PAYLOAD");
            return EX_USAGE;
        }
        size_t len = strlen (payload);
        if (len > UINT32_MAX) {
            builtin_error ("remote-frame encode: payload too large");
            return EXECUTION_FAILURE;
        }
        bs_remote_frame_init (&h, (unsigned char) type, (uint32_t) len);
        fflush (stdout);
        if (bs_relay_write_all (STDOUT_FILENO, (const char *) &h, sizeof h) < 0 ||
            bs_relay_write_all (STDOUT_FILENO, payload, (ssize_t) len) < 0)
            return EXECUTION_FAILURE;
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (sub, "decode")) {
        struct bs_remote_frame_header h;
        uint32_t len = 0;
        char *payload;
        if (bs_word (&args) != NULL) {
            builtin_error ("remote-frame decode: no arguments");
            return EX_USAGE;
        }
        if (bs_read_exact_fd (STDIN_FILENO, &h, sizeof h) < 0 ||
            !bs_remote_frame_valid (&h, &len) ||
            len > (1024u * 1024u)) {
            builtin_error ("remote-frame decode: invalid frame");
            return EXECUTION_FAILURE;
        }
        payload = malloc ((size_t) len + 1);
        if (!payload) return EXECUTION_FAILURE;
        if (bs_read_exact_fd (STDIN_FILENO, payload, len) < 0) {
            free (payload);
            builtin_error ("remote-frame decode: short payload");
            return EXECUTION_FAILURE;
        }
        payload[len] = '\0';
        printf ("type=%s\nlen=%u\npayload=%s\n",
                bs_remote_frame_type_name (h.type), (unsigned) len, payload);
        free (payload);
        return EXECUTION_SUCCESS;
    }
    builtin_error ("remote-frame: unknown subcommand: %s", sub);
    return EX_USAGE;
}

static int
bs_dispatch (WORD_LIST *list)
{
    if (list && list->word && list->word->word) {
        const char *w = list->word->word;
        if (strcmp (w, "--help") == 0) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0) {
            puts ("screen 2.0 (bash-loadable, ptybroker)");
            return EXECUTION_SUCCESS;
        }
    }
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;

    if (!strcmp (cmd, "list") || !strcmp (cmd, "ls"))
                                    return bscreen_list_cmd      (args);
    if (!strcmp (cmd, "state-dir")) return bscreen_state_dir_cmd (args);
    if (!strcmp (cmd, "run"))       return bscreen_run_cmd       (args);
    if (!strcmp (cmd, "kill"))      return bscreen_kill_cmd      (args);
    if (!strcmp (cmd, "attach"))    return bscreen_attach_cmd    (args);
    if (!strcmp (cmd, "roam"))      return bscreen_roam_cmd      (args);
    if (!strcmp (cmd, "state"))     return bscreen_state_cmd     (args);
    if (!strcmp (cmd, "find"))      return bscreen_find_cmd      (args);
    if (!strcmp (cmd, "win-create")) return bscreen_win_create_cmd (args);
    if (!strcmp (cmd, "win-switch")) return bscreen_win_switch_cmd (args);
    if (!strcmp (cmd, "win-list"))   return bscreen_win_list_cmd   (args);
    if (!strcmp (cmd, "win-rename")) return bscreen_win_rename_cmd (args);
    if (!strcmp (cmd, "win-kill"))   return bscreen_win_kill_cmd   (args);
    if (!strcmp (cmd, "win-next"))   return bscreen_win_cycle_cmd  (args, 1);
    if (!strcmp (cmd, "win-prev"))   return bscreen_win_cycle_cmd  (args, -1);
    if (!strcmp (cmd, "pane-split")) return bscreen_pane_split_cmd (args);
    if (!strcmp (cmd, "pane-select")) return bscreen_pane_select_cmd (args);
    if (!strcmp (cmd, "pane-select-dir")) return bscreen_pane_select_dir_cmd (args);
    if (!strcmp (cmd, "pane-list"))  return bscreen_pane_list_cmd  (args);
    if (!strcmp (cmd, "pane-resize")) return bscreen_pane_resize_cmd (args);
    if (!strcmp (cmd, "pane-resize-dir")) return bscreen_pane_resize_dir_cmd (args);
    if (!strcmp (cmd, "pane-swap"))  return bscreen_pane_swap_cmd   (args);
    if (!strcmp (cmd, "pane-display")) return bscreen_pane_list_cmd (args);
    if (!strcmp (cmd, "pane-kill"))  return bscreen_pane_kill_cmd  (args);
    if (!strcmp (cmd, "send-keys"))  return bscreen_send_keys_cmd  (args);
    if (!strcmp (cmd, "capture-pane")) return bscreen_capture_cmd  (args);
    if (!strcmp (cmd, "scrollback")) return bscreen_capture_cmd    (args);
    if (!strcmp (cmd, "send-mouse")) return bscreen_send_mouse_cmd (args);
    if (!strcmp (cmd, "vt-info"))    return bscreen_vt_info_cmd    (args);
    if (!strcmp (cmd, "client-list")) return bscreen_client_list_cmd (args);
    if (!strcmp (cmd, "relay-status")) return bscreen_relay_status_cmd (args);
    if (!strcmp (cmd, "remote-frame")) return bscreen_remote_frame_cmd (args);
    builtin_error ("unknown verb: %s "
                   "(try list/state-dir; reserved: run/kill/attach/state/find/"
                   "win-*/pane-*/send-keys/capture-pane/scrollback/send-mouse/"
                   "vt-info/client-list/relay-status/roam)",
                   cmd);
    return EX_USAGE;
}

int
screen_builtin (WORD_LIST *list)
{
    static const char *const mutations[] = {
        "run", "kill", "win-create", "win-switch", "win-rename", "win-kill",
        "win-next", "win-prev", "pane-split", "pane-select", "pane-select-dir",
        "pane-resize", "pane-resize-dir", "pane-swap", "pane-kill", NULL
    };
    int mutate = 0;
    if (list && list->word && list->word->word)
        for (int i = 0; mutations[i]; i++)
            if (!strcmp (list->word->word, mutations[i])) { mutate = 1; break; }
    if (!mutate) return bs_dispatch (list);
    const char *root = bscreen_state_dir ();
    char path[640];
    if (bscreen_validate_state_dir (root) < 0) return EXECUTION_FAILURE;
    int n = snprintf (path, sizeof path, "%s/.layout.lock", root);
    if (n < 0 || (size_t) n >= sizeof path) return EXECUTION_FAILURE;
    int fd = open (path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return EXECUTION_FAILURE;
    struct stat st;
    if (fstat (fd, &st) < 0 || !S_ISREG (st.st_mode) || st.st_uid != geteuid () ||
        (st.st_mode & 07777) != 0600 || st.st_nlink != 1) {
        close (fd);
        builtin_error ("screen: invalid layout lock file");
        return EXECUTION_FAILURE;
    }
    int locked = 0;
    for (int i = 0; i < 150; i++) {
        if (flock (fd, LOCK_EX | LOCK_NB) == 0) { locked = 1; break; }
        if ((errno != EAGAIN && errno != EWOULDBLOCK) || poll (NULL, 0, 20) < 0) break;
    }
    if (!locked) {
        close (fd);
        builtin_error ("screen: another layout operation is in progress");
        return EXECUTION_FAILURE;
    }
    int result = bs_dispatch (list);
    (void) flock (fd, LOCK_UN);
    close (fd);
    return result;
}

char *screen_doc[] = {
    "Bash window/pane policy with independent native PTY services.",
    "",
    "    list|ls [--cluster]                  enumerate sessions",
    "    state-dir                           print the private state directory",
    "    run -n NAME [-d] [-c CODE | -- CMD...]",
    "                                        start a persistent pane; default current bash-os",
    "    run -n NAME --metadata              create an offline layout fixture",
    "    kill NAME                           stop all pane services and descendants",
    "    attach NAME [-r|-rd|-x|-d]          live focused pane; -x observes, -d detaches",
    "    attach NODE/SESSION --remote [--key FILE] [--dry-run]",
    "    roam NODE/SESSION [--key FILE] [--dry-run]",
    "    win-create NAME [TITLE] [-c CODE | -- CMD...]",
    "    win-switch NAME INDEX | win-list NAME",
    "    win-rename NAME INDEX TITLE | win-kill NAME INDEX",
    "    win-next NAME | win-prev NAME",
    "    pane-split NAME [WIN] [h|v] [-c CODE | -- CMD...]",
    "    pane-select NAME PANE [WIN] | pane-list NAME [WIN]",
    "    pane-select-dir NAME WIN PANE U|D|L|R",
    "    pane-resize NAME WIN PANE 'ROW COL ROWS COLS'",
    "    pane-resize-dir NAME WIN PANE U|D|L|R [N]",
    "    pane-swap NAME WIN PANE_A PANE_B      exchange geometry and resize both PTYs",
    "    pane-kill NAME WIN PANE | pane-display NAME [WIN]",
    "    send-keys NAME [-p WIN:PANE] WORD...  join words and send a newline",
    "    capture-pane|scrollback NAME [-p WIN:PANE] [-N LINES]",
    "    state NAME | find NAME PATTERN       selected pane's raw output history",
    "    vt-info NAME [WIN] | relay-status NAME | client-list NAME",
    "    send-mouse NAME ...                  offline fixture recording only",
    "    remote-frame encode TYPE PAYLOAD | remote-frame decode",
    "",
    "Live services require an absolute BASHSCREEN_STATE_DIR (default /tmp/.screen).",
    "run always returns after service readiness. Use attach for foreground I/O.",
    "Attach follows focus changes and accepts the detach prefix (default ^A) + d.",
    "Attach supplies new raw bytes only; it never replays terminal queries.",
    "Capture is bounded raw history, not a terminal grid or graphics checkpoint.",
    "A frontend owns VT parsing, mouse encoding, layout rendering and redraw.",
    "-c explicitly interprets CODE using this bash-os executable; -- keeps argv literal.",
    "Cluster discovery uses BASHCLUSTER_STATE_DIR (or BASHCLUSTER_DIR).",
    (char *) NULL
};

struct builtin screen_struct = {
    "screen",
    screen_builtin,
    BUILTIN_ENABLED,
    screen_doc,
    "screen <verb> [args...] [--help|--version]",
    0
};
