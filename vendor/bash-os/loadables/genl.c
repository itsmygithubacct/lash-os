/* SPDX-License-Identifier: MIT */
/* genl.c - generic-netlink controller reader for bash-os `genl`.
 *
 * Scope mirrors the Debian iproute2 genl(8) read-only controller path:
 *   genl ctrl list
 *   genl ctrl get name NAME
 *   genl ctrl get id ID
 *
 * This is intentionally a controller reader only.  It sends
 * CTRL_CMD_GETFAMILY over NETLINK_GENERIC and formats the family dump
 * into the same broad shape as `/usr/sbin/genl ctrl list|get`.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#include "loadables.h"

#ifndef SOCK_CLOEXEC
#  define SOCK_CLOEXEC 02000000
#endif

#ifndef NLA_ALIGNTO
#  define NLA_ALIGNTO 4
#endif
#ifndef NLA_F_NESTED
#  define NLA_F_NESTED (1 << 15)
#endif
#ifndef NLA_F_NET_BYTEORDER
#  define NLA_F_NET_BYTEORDER (1 << 14)
#endif
#ifndef NLA_TYPE_MASK
#  define NLA_TYPE_MASK (~(NLA_F_NESTED | NLA_F_NET_BYTEORDER))
#endif

#ifndef GENL_ADMIN_PERM
#  define GENL_ADMIN_PERM 0x01
#endif
#ifndef GENL_CMD_CAP_DO
#  define GENL_CMD_CAP_DO 0x02
#endif
#ifndef GENL_CMD_CAP_DUMP
#  define GENL_CMD_CAP_DUMP 0x04
#endif
#ifndef GENL_CMD_CAP_HASPOL
#  define GENL_CMD_CAP_HASPOL 0x08
#endif

#define BGENL_BUFSZ 65536
#define BGENL_SEQ_BASE 0xb9e60000U
#define BGENL_RECV_TIMEOUT_SEC 2
#define BGENL_NLA_ALIGN(x) (((x) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define BGENL_NLA_HDRLEN BGENL_NLA_ALIGN (sizeof (struct nlattr))

typedef int (*bgenl_cb_t) (struct nlmsghdr *, void *);

struct bgenl_print_ctx {
    unsigned families;
};

static int
bgenl_open (void)
{
    int fd = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) {
        builtin_error ("netlink socket: %s", strerror (errno));
        return -1;
    }

    struct sockaddr_nl sa;
    memset (&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    if (bind (fd, (struct sockaddr *) &sa, sizeof sa) < 0) {
        builtin_error ("netlink bind: %s", strerror (errno));
        close (fd);
        return -1;
    }

    return fd;
}

static unsigned
bgenl_seq (void)
{
    static unsigned s = 0;
    if (s == 0)
        s = BGENL_SEQ_BASE ^ (unsigned) time (NULL) ^ ((unsigned) getpid () << 8);
    return ++s;
}

static size_t
bgenl_attr_payload_len (const struct nlattr *a)
{
    if (a->nla_len < BGENL_NLA_HDRLEN)
        return 0;
    return (size_t) a->nla_len - BGENL_NLA_HDRLEN;
}

static void *
bgenl_attr_data (const struct nlattr *a)
{
    return (void *) ((const unsigned char *) a + BGENL_NLA_HDRLEN);
}

static int
bgenl_attr_type (const struct nlattr *a)
{
    return a->nla_type & NLA_TYPE_MASK;
}

static int
bgenl_parse_attrs (struct nlattr **tb, int max, struct nlattr *attrs, size_t len)
{
    memset (tb, 0, (size_t) (max + 1) * sizeof (*tb));

    while (len >= BGENL_NLA_HDRLEN) {
        if (attrs->nla_len < BGENL_NLA_HDRLEN || attrs->nla_len > len)
            return -1;

        int type = bgenl_attr_type (attrs);
        if (type >= 0 && type <= max)
            tb[type] = attrs;

        size_t step = BGENL_NLA_ALIGN ((size_t) attrs->nla_len);
        if (step == 0 || step > len)
            return -1;
        len -= step;
        attrs = (struct nlattr *) ((unsigned char *) attrs + step);
    }

    return 0;
}

static uint32_t
bgenl_attr_u32 (const struct nlattr *a)
{
    uint32_t v = 0;
    size_t n = bgenl_attr_payload_len (a);
    if (n > sizeof v)
        n = sizeof v;
    if (n > 0)
        memcpy (&v, bgenl_attr_data (a), n);
    return v;
}

static uint16_t
bgenl_attr_u16 (const struct nlattr *a)
{
    uint16_t v = 0;
    size_t n = bgenl_attr_payload_len (a);
    if (n > sizeof v)
        n = sizeof v;
    if (n > 0)
        memcpy (&v, bgenl_attr_data (a), n);
    return v;
}

static const char *
bgenl_attr_str (const struct nlattr *a)
{
    if (bgenl_attr_payload_len (a) == 0)
        return "";
    return (const char *) bgenl_attr_data (a);
}

static int
bgenl_nla_put (unsigned char *buf, size_t *off, size_t max, uint16_t type,
               const void *data, size_t len)
{
    size_t need = BGENL_NLA_HDRLEN + len;
    size_t aligned = BGENL_NLA_ALIGN (need);
    if (*off + aligned > max)
        return -1;

    struct nlattr *a = (struct nlattr *) (buf + *off);
    a->nla_type = type;
    a->nla_len = (uint16_t) need;
    if (len > 0 && data != NULL)
        memcpy (buf + *off + BGENL_NLA_HDRLEN, data, len);
    if (aligned > need)
        memset (buf + *off + need, 0, aligned - need);
    *off += aligned;
    return 0;
}

static int
bgenl_nla_put_u16 (unsigned char *buf, size_t *off, size_t max,
                   uint16_t type, uint16_t v)
{
    return bgenl_nla_put (buf, off, max, type, &v, sizeof v);
}

static int
bgenl_nla_put_str (unsigned char *buf, size_t *off, size_t max,
                   uint16_t type, const char *s)
{
    return bgenl_nla_put (buf, off, max, type, s, strlen (s) + 1);
}

static int
bgenl_talk (int fd, unsigned char *buf, size_t buf_len,
            bgenl_cb_t cb, void *ctx)
{
    struct sockaddr_nl kaddr;
    memset (&kaddr, 0, sizeof kaddr);
    kaddr.nl_family = AF_NETLINK;

    struct iovec iov = { buf, buf_len };
    struct msghdr msg;
    memset (&msg, 0, sizeof msg);
    msg.msg_name = &kaddr;
    msg.msg_namelen = sizeof kaddr;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg (fd, &msg, 0) < 0) {
        builtin_error ("netlink send: %s", strerror (errno));
        return -1;
    }

    unsigned wanted_seq = ((struct nlmsghdr *) buf)->nlmsg_seq;
    unsigned char *rbuf = malloc (BGENL_BUFSZ);
    if (rbuf == NULL) {
        builtin_error ("malloc");
        return -1;
    }

    int rc = 0;
    int done = 0;
    while (!done) {
        fd_set rfds;
        FD_ZERO (&rfds);
        FD_SET (fd, &rfds);

        struct timeval tv;
        tv.tv_sec = BGENL_RECV_TIMEOUT_SEC;
        tv.tv_usec = 0;
        int ready = select (fd + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            builtin_error ("netlink recv wait: %s", strerror (errno));
            rc = -1;
            break;
        }
        if (ready == 0) {
            builtin_error ("netlink recv timeout waiting for generic netlink controller");
            rc = -1;
            break;
        }

        iov.iov_base = rbuf;
        iov.iov_len = BGENL_BUFSZ;
        msg.msg_namelen = sizeof kaddr;

        ssize_t got = recvmsg (fd, &msg, 0);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            builtin_error ("netlink recv: %s", strerror (errno));
            rc = -1;
            break;
        }
        if (got == 0) {
            builtin_error ("netlink: EOF on socket");
            rc = -1;
            break;
        }

        int rem = (int) got;
        struct nlmsghdr *h = (struct nlmsghdr *) rbuf;
        while (NLMSG_OK (h, rem)) {
            if (h->nlmsg_seq != wanted_seq) {
                h = NLMSG_NEXT (h, rem);
                continue;
            }

            if (h->nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            }

            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h);
                if (err->error == 0) {
                    done = 1;
                    break;
                }
                errno = -err->error;
                fprintf (stderr, "RTNETLINK answers: %s\n", strerror (errno));
                fprintf (stderr, "Error talking to the kernel\n");
                rc = -1;
                done = 1;
                break;
            }

            if (cb != NULL && cb (h, ctx) != 0) {
                done = 1;
                break;
            }
            if ((h->nlmsg_flags & NLM_F_MULTI) == 0)
                done = 1;

            h = NLMSG_NEXT (h, rem);
        }
    }

    free (rbuf);
    return rc;
}

static void
bgenl_print_caps (uint32_t flags)
{
    int any = 0;

    printf ("\t\tCapabilities (0x%x):\n", flags);
    printf (" \t\t  ");
    if (flags & GENL_ADMIN_PERM) {
        printf ("requires admin permission; ");
        any = 1;
    }
    if (flags & GENL_CMD_CAP_DO) {
        printf ("can doit; ");
        any = 1;
    }
    if (flags & GENL_CMD_CAP_DUMP) {
        printf ("can dumpit; ");
        any = 1;
    }
    if (flags & GENL_CMD_CAP_HASPOL) {
        printf ("has policy");
        any = 1;
    }
    if (!any)
        printf ("none");
    printf ("\n");
}

static void
bgenl_print_ops (struct nlattr *ops)
{
    struct nlattr *entry = (struct nlattr *) bgenl_attr_data (ops);
    size_t rem = bgenl_attr_payload_len (ops);
    unsigned idx = 1;

    if (rem == 0)
        return;

    printf ("\tcommands supported: \n");
    while (rem >= BGENL_NLA_HDRLEN) {
        if (entry->nla_len < BGENL_NLA_HDRLEN || entry->nla_len > rem)
            break;

        struct nlattr *tb[CTRL_ATTR_OP_MAX + 1];
        struct nlattr *nested = (struct nlattr *) bgenl_attr_data (entry);
        size_t nested_len = bgenl_attr_payload_len (entry);
        if (bgenl_parse_attrs (tb, CTRL_ATTR_OP_MAX, nested, nested_len) == 0
            && tb[CTRL_ATTR_OP_ID] != NULL) {
            uint32_t id = bgenl_attr_u32 (tb[CTRL_ATTR_OP_ID]);
            uint32_t flags = tb[CTRL_ATTR_OP_FLAGS] != NULL
                ? bgenl_attr_u32 (tb[CTRL_ATTR_OP_FLAGS]) : 0;

            printf ("\t\t#%u:  ID-0x%x \n", idx, id);
            bgenl_print_caps (flags);
            printf ("\n");
            idx++;
        }

        size_t step = BGENL_NLA_ALIGN ((size_t) entry->nla_len);
        if (step == 0 || step > rem)
            break;
        rem -= step;
        entry = (struct nlattr *) ((unsigned char *) entry + step);
    }

    printf ("\n");
}

static void
bgenl_print_groups (struct nlattr *groups)
{
    struct nlattr *entry = (struct nlattr *) bgenl_attr_data (groups);
    size_t rem = bgenl_attr_payload_len (groups);
    unsigned idx = 1;

    if (rem == 0)
        return;

    printf ("\tmulticast groups:\n");
    while (rem >= BGENL_NLA_HDRLEN) {
        if (entry->nla_len < BGENL_NLA_HDRLEN || entry->nla_len > rem)
            break;

        struct nlattr *tb[CTRL_ATTR_MCAST_GRP_MAX + 1];
        struct nlattr *nested = (struct nlattr *) bgenl_attr_data (entry);
        size_t nested_len = bgenl_attr_payload_len (entry);
        if (bgenl_parse_attrs (tb, CTRL_ATTR_MCAST_GRP_MAX, nested, nested_len) == 0
            && tb[CTRL_ATTR_MCAST_GRP_ID] != NULL
            && tb[CTRL_ATTR_MCAST_GRP_NAME] != NULL) {
            uint32_t id = bgenl_attr_u32 (tb[CTRL_ATTR_MCAST_GRP_ID]);
            const char *name = bgenl_attr_str (tb[CTRL_ATTR_MCAST_GRP_NAME]);
            printf ("\t\t#%u:  ID-0x%x  name: %s \n", idx, id, name);
            idx++;
        }

        size_t step = BGENL_NLA_ALIGN ((size_t) entry->nla_len);
        if (step == 0 || step > rem)
            break;
        rem -= step;
        entry = (struct nlattr *) ((unsigned char *) entry + step);
    }

    printf ("\n");
}

static int
bgenl_print_family_cb (struct nlmsghdr *h, void *vctx)
{
    struct bgenl_print_ctx *ctx = (struct bgenl_print_ctx *) vctx;

    if (h->nlmsg_len < NLMSG_LENGTH (sizeof (struct genlmsghdr)))
        return 0;

    struct genlmsghdr *gh = (struct genlmsghdr *) NLMSG_DATA (h);
    size_t rem = h->nlmsg_len - NLMSG_LENGTH (sizeof *gh);
    struct nlattr *attrs = (struct nlattr *) ((unsigned char *) gh + sizeof *gh);
    struct nlattr *tb[CTRL_ATTR_MAX + 1];

    if (bgenl_parse_attrs (tb, CTRL_ATTR_MAX, attrs, rem) < 0)
        return 0;

    if (tb[CTRL_ATTR_FAMILY_NAME] == NULL || tb[CTRL_ATTR_FAMILY_ID] == NULL)
        return 0;

    const char *name = bgenl_attr_str (tb[CTRL_ATTR_FAMILY_NAME]);
    uint32_t id = bgenl_attr_u16 (tb[CTRL_ATTR_FAMILY_ID]);
    uint32_t version = tb[CTRL_ATTR_VERSION] != NULL
        ? bgenl_attr_u32 (tb[CTRL_ATTR_VERSION]) : 0;
    uint32_t hdrsize = tb[CTRL_ATTR_HDRSIZE] != NULL
        ? bgenl_attr_u32 (tb[CTRL_ATTR_HDRSIZE]) : 0;
    uint32_t maxattr = tb[CTRL_ATTR_MAXATTR] != NULL
        ? bgenl_attr_u32 (tb[CTRL_ATTR_MAXATTR]) : 0;

    printf ("\n");
    printf ("Name: %s\n", name);
    printf ("\tID: 0x%x  Version: 0x%x  header size: %u  max attribs: %u \n",
            id, version, hdrsize, maxattr);

    if (tb[CTRL_ATTR_OPS] != NULL)
        bgenl_print_ops (tb[CTRL_ATTR_OPS]);
    if (tb[CTRL_ATTR_MCAST_GROUPS] != NULL)
        bgenl_print_groups (tb[CTRL_ATTR_MCAST_GROUPS]);

    ctx->families++;
    return 0;
}

static int
bgenl_ctrl_query (int dump, const char *name, int by_id, uint16_t id)
{
    unsigned char buf[1024];
    memset (buf, 0, sizeof buf);

    struct nlmsghdr *nh = (struct nlmsghdr *) buf;
    nh->nlmsg_type = GENL_ID_CTRL;
    nh->nlmsg_flags = NLM_F_REQUEST | (dump ? NLM_F_DUMP : 0);
    nh->nlmsg_seq = bgenl_seq ();
    nh->nlmsg_pid = 0;

    struct genlmsghdr *gh = (struct genlmsghdr *) NLMSG_DATA (nh);
    gh->cmd = CTRL_CMD_GETFAMILY;
    gh->version = 1;

    size_t off = NLMSG_LENGTH (sizeof *gh);
    if (name != NULL) {
        if (bgenl_nla_put_str (buf, &off, sizeof buf,
                               CTRL_ATTR_FAMILY_NAME, name) < 0) {
            builtin_error ("genetlink: family-name request too large");
            return EXECUTION_FAILURE;
        }
    } else if (by_id) {
        if (bgenl_nla_put_u16 (buf, &off, sizeof buf,
                               CTRL_ATTR_FAMILY_ID, id) < 0) {
            builtin_error ("genetlink: family-id request too large");
            return EXECUTION_FAILURE;
        }
    }
    nh->nlmsg_len = off;

    int fd = bgenl_open ();
    if (fd < 0)
        return EXECUTION_FAILURE;

    struct bgenl_print_ctx ctx;
    memset (&ctx, 0, sizeof ctx);

    int rc = bgenl_talk (fd, buf, off, bgenl_print_family_cb, &ctx);
    close (fd);

    if (rc < 0)
        return EXECUTION_FAILURE;
    if (ctx.families == 0) {
        fprintf (stderr, "RTNETLINK answers: No such file or directory\n");
        fprintf (stderr, "Error talking to the kernel\n");
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bgenl_parse_family_id (const char *s, uint16_t *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul (s, &end, 0);
    if (errno != 0 || end == s || *end != '\0' || v > 0xffffUL)
        return -1;
    *out = (uint16_t) v;
    return 0;
}

int
genl_builtin (WORD_LIST *list)
{
    if (list == 0) {
        builtin_usage ();
        return EX_USAGE;
    }

    const char *object = list->word->word;
    WORD_LIST *args = list->next;

    if (strcmp (object, "ctrl") != 0) {
        builtin_error ("unsupported genl object: %s", object);
        return EX_USAGE;
    }

    if (args == 0) {
        builtin_error ("wrong controller params");
        return EX_USAGE;
    }

    const char *cmd = args->word->word;
    args = args->next;

    if (strcmp (cmd, "list") == 0) {
        if (args != 0) {
            builtin_error ("wrong controller params");
            return EX_USAGE;
        }
        return bgenl_ctrl_query (1, NULL, 0, 0);
    }

    if (strcmp (cmd, "get") == 0) {
        if (args == 0 || args->next == 0 || args->next->next != 0) {
            builtin_error ("wrong controller params");
            return EX_USAGE;
        }

        const char *kind = args->word->word;
        const char *value = args->next->word->word;
        if (strcmp (kind, "name") == 0)
            return bgenl_ctrl_query (0, value, 0, 0);
        if (strcmp (kind, "id") == 0) {
            uint16_t id;
            if (bgenl_parse_family_id (value, &id) < 0) {
                builtin_error ("invalid family id: %s", value);
                return EX_USAGE;
            }
            return bgenl_ctrl_query (0, NULL, 1, id);
        }
    }

    builtin_error ("unsupported ctrl command: %s", cmd);
    return EX_USAGE;
}

char *genl_doc[] = {
    "Generic-netlink controller reader.",
    "",
    "    genl ctrl list",
    "    genl ctrl get name NAME",
    "    genl ctrl get id ID",
    "",
    "Read-only CTRL_CMD_GETFAMILY frontend used by /bash-os/genl.sh.",
    (char *) NULL
};

struct builtin genl_struct = {
    "genl",
    genl_builtin,
    BUILTIN_ENABLED,
    genl_doc,
    "genl ctrl list|get name NAME|get id ID",
    0
};
