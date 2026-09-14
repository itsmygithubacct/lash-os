/* bashhostname.c — hostname(1) get/set wrapper.
 *
 *   bashhostname               # print current hostname (default = -f form)
 *   bashhostname -s            # short form: strip at first dot
 *   bashhostname -d            # domain form: strip up to and including first dot
 *   bashhostname -f            # fqdn form: print full hostname (explicit alias of default)
 *   bashhostname -i            # print resolved IP address(es) for this host
 *   bashhostname -I            # print configured non-loopback IP addresses
 *   bashhostname -A            # print all discoverable FQDNs for this host
 *   bashhostname -F FILE       # read hostname from file (requires privilege)
 *   bashhostname NEWNAME       # set hostname (requires privilege)
 *
 * -s/-d/-f/-i/-I/-A are mutually exclusive (coreutils/busybox parity).
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
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
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "loadables.h"

static const char *
hostname_fixture_root (void)
{
    const char *root = getenv ("BASHOS_HOSTNAME_FIXTURE_ROOT");
    return (root && *root) ? root : NULL;
}

static int
hostname_fixture_path (char *buf, size_t bufsz, const char *name)
{
    const char *root = hostname_fixture_root ();
    int n;

    if (!root)
        return 0;

    n = snprintf (buf, bufsz, "%s/%s", root, name);
    if (n < 0 || (size_t)n >= bufsz)
        return -1;
    return 1;
}

static int
read_fixture_line (const char *name, char *buf, size_t bufsz)
{
    char path[PATH_MAX];
    FILE *fp;
    size_t nlen;
    int prc = hostname_fixture_path (path, sizeof path, name);

    if (prc <= 0)
        return prc;

    fp = fopen (path, "r");
    if (!fp) {
        builtin_error ("BASHOS_HOSTNAME_FIXTURE_ROOT/%s: %s",
                       name, strerror (errno));
        return -1;
    }

    if (!fgets (buf, bufsz, fp)) {
        if (ferror (fp))
            builtin_error ("BASHOS_HOSTNAME_FIXTURE_ROOT/%s: %s",
                           name, strerror (errno));
        else
            builtin_error ("BASHOS_HOSTNAME_FIXTURE_ROOT/%s: empty file", name);
        fclose (fp);
        return -1;
    }
    fclose (fp);

    nlen = strlen (buf);
    while (nlen > 0 && (buf[nlen - 1] == '\n' || buf[nlen - 1] == '\r'))
        buf[--nlen] = '\0';
    return 1;
}

static int
print_fixture_tokens (const char *name)
{
    char path[PATH_MAX];
    FILE *fp;
    char token[NI_MAXHOST];
    int printed = 0;
    int prc = hostname_fixture_path (path, sizeof path, name);

    if (prc <= 0)
        return prc;

    fp = fopen (path, "r");
    if (!fp) {
        builtin_error ("BASHOS_HOSTNAME_FIXTURE_ROOT/%s: %s",
                       name, strerror (errno));
        return -1;
    }

    while (fscanf (fp, "%1024s", token) == 1) {
        printf ("%s%s", printed ? " " : "", token);
        printed = 1;
    }
    if (ferror (fp)) {
        builtin_error ("BASHOS_HOSTNAME_FIXTURE_ROOT/%s: %s",
                       name, strerror (errno));
        fclose (fp);
        return -1;
    }

    fclose (fp);
    putchar ('\n');
    return 1;
}

int
hostname_builtin (WORD_LIST *list)
{
    int short_form = 0;
    int domain_form = 0;
    int fqdn_form = 0;
    int all_ips = 0;
    int ip_form = 0;
    int all_fqdns = 0;
    int file_set = 0;
    int dry_run = 0;
    const char *file_arg = NULL;
    char filebuf[256];

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "-s")) { short_form = 1; list = list->next; continue; }
        if (!strcmp (w, "-d")) { domain_form = 1; list = list->next; continue; }
        if (!strcmp (w, "-f")) { fqdn_form = 1; list = list->next; continue; }
        if (!strcmp (w, "-I")) { all_ips = 1; list = list->next; continue; }
        if (!strcmp (w, "-i") || !strcmp (w, "--ip-address")) { ip_form = 1; list = list->next; continue; }
        if (!strcmp (w, "-A")) { all_fqdns = 1; list = list->next; continue; }
        if (!strcmp (w, "-n") || !strcmp (w, "--dry-run")) {
            dry_run = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-F")) {
            file_set = 1;
            list = list->next;
            if (!list) {
                builtin_error ("-F: missing file argument");
                builtin_usage ();
                return EX_USAGE;
            }
            file_arg = list->word->word;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--help")) {
            puts ("bashhostname: get or set the system hostname");
            printf ("Usage: %s [-s | -d | -f | -i | -I | -A | -F FILE | [-n|--dry-run] NAME]\n",
                    "bashhostname");
            puts ("  -n, --dry-run  print 'would set' audit line, skip sethostname(2)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version") || !strcmp (w, "-V")) {
            puts ("bashhostname 1.0 (bash-loadable, hostname-compatible)");
            return EXECUTION_SUCCESS;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    /* Print-mode selectors are mutually exclusive (coreutils/busybox parity). */
    if (short_form + domain_form + fqdn_form + ip_form + all_ips + all_fqdns > 1) {
        builtin_error ("-s, -d, -f, -i, -I, -A are mutually exclusive");
        builtin_usage ();
        return EX_USAGE;
    }

    /* Determine name source for set mode (file or positional). */
    const char *name = NULL;

    if (file_set) {
        if (list) {
            builtin_error ("cannot combine -F with a NAME argument");
            builtin_usage ();
            return EX_USAGE;
        }
        FILE *fp = fopen (file_arg, "r");
        if (!fp) {
            builtin_error ("-F: cannot read '%s': %s",
                           file_arg, strerror (errno));
            return EXECUTION_FAILURE;
        }
        if (!fgets (filebuf, sizeof filebuf, fp)) {
            if (ferror (fp))
                builtin_error ("-F: '%s': %s", file_arg, strerror (errno));
            else
                builtin_error ("-F: '%s': empty file", file_arg);
            fclose (fp);
            return EXECUTION_FAILURE;
        }
        fclose (fp);
        /* Strip trailing newline / carriage return. */
        {
            size_t nlen = strlen (filebuf);
            while (nlen > 0 && (filebuf[nlen - 1] == '\n'
                                || filebuf[nlen - 1] == '\r'))
                filebuf[--nlen] = '\0';
        }
        if (filebuf[0] == '\0') {
            builtin_error ("-F: '%s': empty hostname", file_arg);
            return EXECUTION_FAILURE;
        }
        name = filebuf;
    } else if (list) {
        name = list->word->word;
        if (list->next) {
            builtin_error ("too many NAME operands");
            builtin_usage ();
            return EX_USAGE;
        }
    }

    if (name) {
        /* Set form. */
        if (short_form || domain_form || fqdn_form || ip_form || all_ips || all_fqdns) {
            builtin_error ("-s/-d/-f/-i/-I/-A cannot be combined with a set operation");
            builtin_usage ();
            return EX_USAGE;
        }
        size_t nlen = strlen (name);
        if (nlen >= (size_t)HOST_NAME_MAX) {
            builtin_error ("hostname too long (max %d characters)",
                           HOST_NAME_MAX - 1);
            return EXECUTION_FAILURE;
        }
        if (strchr (name, '/')) {
            builtin_error ("invalid hostname: '%s'", name);
            return EXECUTION_FAILURE;
        }
        if (dry_run) {
            fprintf (stderr, "bashhostname: dry-run: would set hostname to '%s'\n",
                     name);
            return EXECUTION_SUCCESS;
        }
        if (sethostname (name, nlen) < 0) {
            builtin_error ("sethostname: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        return EXECUTION_SUCCESS;
    }

    if (all_ips) {
        int frc = print_fixture_tokens ("ifaddrs");
        if (frc > 0)
            return EXECUTION_SUCCESS;
        if (frc < 0)
            return EXECUTION_FAILURE;

        struct ifaddrs *ifaddr = NULL;
        int printed = 0;
        if (getifaddrs (&ifaddr) < 0) {
            builtin_error ("getifaddrs: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }

        for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr)
                continue;
            if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK))
                continue;

            int family = ifa->ifa_addr->sa_family;
            char addrbuf[INET6_ADDRSTRLEN];
            const void *src = NULL;

            if (family == AF_INET) {
                src = &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
            } else if (family == AF_INET6) {
                const struct in6_addr *a6 =
                    &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;
                if (IN6_IS_ADDR_LINKLOCAL (a6))
                    continue;
                src = a6;
            } else {
                continue;
            }

            if (inet_ntop (family, src, addrbuf, sizeof addrbuf)) {
                /* GNU `hostname -I` prints each address followed by a
                   space (so the line ends with a trailing space). */
                printf ("%s ", addrbuf);
                printed = 1;
            }
        }
        freeifaddrs (ifaddr);
        (void) printed;
        putchar ('\n');
        return EXECUTION_SUCCESS;
    }

    if (ip_form) {
        int frc = print_fixture_tokens ("ipaddrs");
        if (frc > 0)
            return EXECUTION_SUCCESS;
        if (frc < 0)
            return EXECUTION_FAILURE;

        /* GNU `hostname -i`: resolve the hostname and print its network
           address(es), space-separated, with NO trailing space (unlike
           -I). Resolution via getaddrinfo (matches /etc/hosts + DNS). */
        char hostbuf[256];
        if (gethostname (hostbuf, sizeof hostbuf) < 0) {
            builtin_error ("gethostname: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        hostbuf[sizeof hostbuf - 1] = '\0';

        struct addrinfo hints, *res = NULL;
        memset (&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        int printed = 0;
        char seen[32][INET6_ADDRSTRLEN];
        int seen_n = 0;
        if (getaddrinfo (hostbuf, NULL, &hints, &res) == 0) {
            for (struct addrinfo *ai = res; ai && seen_n < 32; ai = ai->ai_next) {
                char addrbuf[INET6_ADDRSTRLEN];
                const void *src = NULL;
                if (ai->ai_family == AF_INET)
                    src = &((struct sockaddr_in *) ai->ai_addr)->sin_addr;
                else if (ai->ai_family == AF_INET6)
                    src = &((struct sockaddr_in6 *) ai->ai_addr)->sin6_addr;
                else
                    continue;
                if (!inet_ntop (ai->ai_family, src, addrbuf, sizeof addrbuf))
                    continue;
                int dup = 0;
                for (int i = 0; i < seen_n; i++)
                    if (strcmp (seen[i], addrbuf) == 0) { dup = 1; break; }
                if (dup)
                    continue;
                snprintf (seen[seen_n], sizeof seen[seen_n], "%s", addrbuf);
                printf ("%s%s", printed ? " " : "", seen[seen_n]);
                printed = 1;
                seen_n++;
            }
            freeaddrinfo (res);
        }
        putchar ('\n');
        return EXECUTION_SUCCESS;
    }

    if (all_fqdns) {
        int frc = print_fixture_tokens ("fqdns");
        if (frc > 0)
            return EXECUTION_SUCCESS;
        if (frc < 0)
            return EXECUTION_FAILURE;

        char hostbuf[256];
        int printed = 0;
        char seen[16][NI_MAXHOST];
        int seen_n = 0;

        if (gethostname (hostbuf, sizeof hostbuf) < 0) {
            builtin_error ("gethostname: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        hostbuf[sizeof hostbuf - 1] = '\0';

        struct addrinfo hints;
        struct addrinfo *res = NULL;
        memset (&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_CANONNAME;

        if (getaddrinfo (hostbuf, NULL, &hints, &res) == 0) {
            for (struct addrinfo *ai = res; ai && seen_n < 16; ai = ai->ai_next) {
                char namebuf[NI_MAXHOST];
                const char *name = NULL;

                if (ai->ai_canonname && strchr (ai->ai_canonname, '.'))
                    name = ai->ai_canonname;
                else if (getnameinfo (ai->ai_addr, ai->ai_addrlen,
                                      namebuf, sizeof namebuf, NULL, 0,
                                      NI_NAMEREQD) == 0 && strchr (namebuf, '.'))
                    name = namebuf;

                if (!name || !*name)
                    continue;

                int dup = 0;
                for (int i = 0; i < seen_n; i++)
                    if (strcmp (seen[i], name) == 0)
                        { dup = 1; break; }
                if (dup)
                    continue;

                snprintf (seen[seen_n], sizeof seen[seen_n], "%s", name);
                printf ("%s%s", printed ? " " : "", seen[seen_n]);
                printed = 1;
                seen_n++;
            }
            freeaddrinfo (res);
        }

        if (!printed && strchr (hostbuf, '.'))
            printf ("%s", hostbuf);
        putchar ('\n');
        return EXECUTION_SUCCESS;
    }

    /* Print form. */
    char buf[256];
    {
        int frc = read_fixture_line ("hostname", buf, sizeof buf);
        if (frc < 0)
            return EXECUTION_FAILURE;
        if (frc == 0) {
            if (gethostname (buf, sizeof buf) < 0) {
                builtin_error ("gethostname: %s", strerror (errno));
                return EXECUTION_FAILURE;
            }
            buf[sizeof buf - 1] = '\0';
        }
    }
    if (short_form) {
        char *dot = strchr (buf, '.');
        if (dot) *dot = '\0';
        puts (buf);
    } else if (domain_form) {
        char *dot = strchr (buf, '.');
        puts (dot ? dot + 1 : "");
    } else {
        /* Default and -f both print the full gethostname() result. */
        (void) fqdn_form;
        puts (buf);
    }
    return EXECUTION_SUCCESS;
}

char *hostname_doc[] = {
    "Get or set the system hostname.",
    "",
    "    bashhostname            # print current hostname",
    "    bashhostname -s         # short form (strip at first dot)",
    "    bashhostname -d         # domain form (strip up to and including first dot)",
    "    bashhostname -f         # fqdn form (full gethostname() result; default)",
    "    bashhostname -i         # resolved IP address(es) for this host",
    "    bashhostname -I         # configured non-loopback IP addresses",
    "    bashhostname -A         # all discoverable FQDNs for this host",
    "    bashhostname -F FILE    # read hostname from FILE (requires privilege)",
    "    bashhostname NAME       # sethostname(NAME) -- requires privilege",
    "    bashhostname -n NAME    # dry-run: print 'would set' audit, no sethostname(2)",
    "    bashhostname -V, --version",
    "",
    "Default form prints the kernel hostname via gethostname(2).",
    "-s, -d, -f, -i, -I, -A are mutually exclusive.",
    "-i resolves the current hostname and prints unique IP addresses with no",
    "  trailing space; resolver absence yields an empty successful line.",
    "-I enumerates UP non-loopback AF_INET/AF_INET6 addresses via getifaddrs(3),",
    "  omitting IPv6 link-local addresses, matching hostname(1)'s all-IP shape.",
    "-A resolves the current hostname and prints unique canonical/reverse names",
    "  containing a dot; resolver absence yields an empty successful line.",
    "-n/--dry-run combined with NAME or -F FILE emits a stderr audit line",
    "  ('bashhostname: dry-run: would set hostname to '<NAME>'') and returns",
    "  EXECUTION_SUCCESS without calling sethostname(2). Lets tests assert the",
    "  set path is wired up correctly without mutating the live hostname.",
    "Tests may set BASHOS_HOSTNAME_FIXTURE_ROOT to a directory containing",
    "  hostname, ipaddrs, ifaddrs, and/or fqdns text fixtures for read-only print modes.",
    (char *)NULL
};

struct builtin bashhostname_struct = {
    "bashhostname",
    hostname_builtin,
    BUILTIN_ENABLED,
    hostname_doc,
    "bashhostname [-s | -d | -f | -i | -I | -A | -F FILE | NAME | -V | --version]",
    0
};
