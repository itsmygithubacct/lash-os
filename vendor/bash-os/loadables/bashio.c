/* bashio.c — random-access file I/O. Loadable for bash.
 *
 * Bash's redirection model is sequential: `exec 3<foo` opens fd 3
 * and `read -u 3` consumes the position. There's no way to read
 * offset N without losing the file position, no pread(2)/pwrite(2)
 * exposure, and no efficient byte-level edits to a block device.
 *
 * bashio wraps the POSIX random-access primitives. Hex in/out for
 * binary safety (matches binhex's NUL-bypass pattern); raw bytes
 * available on stdout for streaming.
 *
 * Subcommands:
 *     bashio open PATH MODE [-c] [-x]    open file, print fd
 *                                          MODE: r r+ w w+ a a+
 *                                          -c: O_CREAT | mode 0644
 *                                          -x: O_EXCL (with -c)
 *     bashio pread FD LEN OFF [-x]       read LEN bytes at OFF;
 *                                          stdout raw, -x for hex
 *     bashio pwrite FD HEX OFF           write hex-decoded bytes at OFF
 *     bashio lseek FD OFF WHENCE         WHENCE: set / cur / end
 *                                          prints new position
 *     bashio fstat FD                    "size mtime mode" one line
 *     bashio truncate FD LEN             set file size to LEN
 *     bashio sync FD                     fdatasync
 *     bashio close FD
 *
 * Examples:
 *     fd=$(bashio open /var/log/foo.bin r+)
 *     hex=$(bashio pread "$fd" 16 1024 -x)
 *     bashio pwrite "$fd" "deadbeef" 0
 *     bashio close "$fd"
 *
 * Companion docs:
 *     /docs/bash/bashio.txt
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c. See that file's header
 * for the full grant.
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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>

#include "loadables.h"

static int
bio_hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Decode hex string to bytes. Returns # bytes decoded, or -1 on error.
   Caller-provided buffer; caller ensures size >= strlen(hex)/2. */
static ssize_t
bio_unhex (const char *hex, unsigned char *out)
{
  size_t n = 0;
  while (*hex)
    {
      while (*hex == ' ' || *hex == '\t' || *hex == '\n' || *hex == '\r') hex++;
      if (*hex == '\0') break;
      int hi = bio_hexval (*hex++);
      if (hi < 0) return -1;
      if (*hex == '\0') return -1;  /* odd-length hex */
      int lo = bio_hexval (*hex++);
      if (lo < 0) return -1;
      out[n++] = (unsigned char) ((hi << 4) | lo);
    }
  return (ssize_t) n;
}

static void
bio_print_hex (const unsigned char *buf, size_t n)
{
  static const char digits[16] = "0123456789abcdef";
  /* Build into a 4KB chunk (= 2KB input bytes) and fwrite — keeps stdio
     locking out of the per-byte path on multi-MB pread -x calls. */
  char chunk[4096];
  size_t cp = 0;
  for (size_t i = 0; i < n; i++)
    {
      if (cp + 2 > sizeof chunk) { fwrite (chunk, 1, cp, stdout); cp = 0; }
      chunk[cp++] = digits[buf[i] >> 4];
      chunk[cp++] = digits[buf[i] & 0xf];
    }
  if (cp + 1 <= sizeof chunk) chunk[cp++] = '\n';
  else { fwrite (chunk, 1, cp, stdout); cp = 0; chunk[cp++] = '\n'; }
  fwrite (chunk, 1, cp, stdout);
}

static int
bio_parse_mode (const char *mode)
{
  if (!strcmp (mode, "r"))  return O_RDONLY;
  if (!strcmp (mode, "r+")) return O_RDWR;
  if (!strcmp (mode, "w"))  return O_WRONLY | O_TRUNC;
  if (!strcmp (mode, "w+")) return O_RDWR   | O_TRUNC;
  if (!strcmp (mode, "a"))  return O_WRONLY | O_APPEND;
  if (!strcmp (mode, "a+")) return O_RDWR   | O_APPEND;
  return -1;
}

static int
bio_open (WORD_LIST *args)
{
  const char *path = NULL, *mode = NULL, *fdvar = NULL;
  int creat = 0, excl = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-c") == 0)      creat = 1;
      else if (strcmp (w, "-x") == 0) excl  = 1;
      else if (!path)                 path = w;
      else if (!mode)                 mode = w;
      else if (!fdvar)                fdvar = w;
      else { builtin_error ("open: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!path || !mode) { builtin_error ("open needs PATH MODE [FDVAR]"); return EX_USAGE; }
  int flags = bio_parse_mode (mode);
  if (flags < 0) { builtin_error ("open: bad mode %s (want r r+ w w+ a a+)", mode); return EX_USAGE; }
  if (creat) flags |= O_CREAT;
  if (excl)  flags |= O_EXCL;
  flags |= O_CLOEXEC;
  int fd = open (path, flags, 0644);
  if (fd < 0) { builtin_error ("open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }

  /* Two output modes:
     - FDVAR present: bind $FDVAR to the fd in the caller's shell.
       Required when the caller is a non-subshell context (the
       common case). The fd survives because we're a builtin, not
       a fork.
     - FDVAR absent: print to stdout. Only useful from a subshell
       where the fd will die anyway (rare; mostly for testing). */
  if (fdvar)
    {
      char buf[32];
      snprintf (buf, sizeof buf, "%d", fd);
      builtin_bind_variable ((char *) fdvar, buf, 0);
    }
  else
    printf ("%d\n", fd);
  return EXECUTION_SUCCESS;
}

static int
bio_close (WORD_LIST *args)
{
  if (!args) { builtin_error ("close: needs FD"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  if (close (fd) < 0) { builtin_error ("close: %s", strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

static int
bio_pread (WORD_LIST *args)
{
  int fd = -1;
  long long len = -1, off = -1;
  int hex_out = 0;
  int pos = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-x") == 0) { hex_out = 1; continue; }
      switch (pos++)
        {
        case 0: fd  = atoi (w); break;
        case 1: len = strtoll (w, NULL, 0); break;
        case 2: off = strtoll (w, NULL, 0); break;
        default: builtin_error ("pread: extra arg %s", w); return EX_USAGE;
        }
    }
  if (fd < 0 || len < 0 || off < 0)
    { builtin_error ("pread needs FD LEN OFF"); return EX_USAGE; }
  if (len > (1LL << 30))
    { builtin_error ("pread: LEN too big (max 1 GiB per call)"); return EX_USAGE; }
  if (len == 0) return EXECUTION_SUCCESS;  /* nothing to read */

  unsigned char *buf = malloc ((size_t) len);
  if (!buf) { builtin_error ("pread: out of memory"); return EXECUTION_FAILURE; }
  /* Retry on EINTR — bash trap handlers don't install SA_RESTART, so a
     trap firing mid-pread would otherwise surface as a spurious error. */
  ssize_t n;
  do { n = pread (fd, buf, (size_t) len, (off_t) off); }
  while (n < 0 && errno == EINTR);
  if (n < 0) { builtin_error ("pread: %s", strerror (errno)); free (buf); return EXECUTION_FAILURE; }
  if (hex_out)
    bio_print_hex (buf, (size_t) n);
  else
    {
      ssize_t w = 0;
      while (w < n)
        {
          ssize_t k = write (STDOUT_FILENO, buf + w, (size_t) (n - w));
          if (k < 0)
            {
              if (errno == EINTR) continue;
              builtin_error ("write: %s", strerror (errno));
              free (buf);
              return EXECUTION_FAILURE;
            }
          w += k;
        }
    }
  free (buf);
  fflush (stdout);
  return EXECUTION_SUCCESS;
}

static int
bio_pwrite (WORD_LIST *args)
{
  int fd = -1;
  const char *hex = NULL;
  long long off = -1;
  int pos = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      switch (pos++)
        {
        case 0: fd = atoi (w); break;
        case 1: hex = w; break;
        case 2: off = strtoll (w, NULL, 0); break;
        default: builtin_error ("pwrite: extra arg %s", w); return EX_USAGE;
        }
    }
  if (fd < 0 || !hex || off < 0)
    { builtin_error ("pwrite needs FD HEX OFF"); return EX_USAGE; }
  size_t hexlen = strlen (hex);
  unsigned char *buf = malloc (hexlen / 2 + 1);
  if (!buf) { builtin_error ("pwrite: out of memory"); return EXECUTION_FAILURE; }
  ssize_t n = bio_unhex (hex, buf);
  if (n < 0) { builtin_error ("pwrite: bad hex"); free (buf); return EX_USAGE; }
  ssize_t total = 0;
  while (total < n)
    {
      ssize_t k = pwrite (fd, buf + total, (size_t) (n - total),
                          (off_t) (off + total));
      if (k < 0)
        {
          if (errno == EINTR) continue;
          builtin_error ("pwrite: %s", strerror (errno));
          free (buf);
          return EXECUTION_FAILURE;
        }
      total += k;
    }
  printf ("%lld\n", (long long) total);
  free (buf);
  return EXECUTION_SUCCESS;
}

static int
bio_lseek (WORD_LIST *args)
{
  int fd = -1;
  long long off = 0;
  int whence = -1;
  int pos = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      switch (pos++)
        {
        case 0: fd = atoi (w); break;
        case 1: off = strtoll (w, NULL, 0); break;
        case 2:
          if      (strcmp (w, "set") == 0) whence = SEEK_SET;
          else if (strcmp (w, "cur") == 0) whence = SEEK_CUR;
          else if (strcmp (w, "end") == 0) whence = SEEK_END;
          else { builtin_error ("lseek: bad WHENCE %s", w); return EX_USAGE; }
          break;
        default: builtin_error ("lseek: extra arg %s", w); return EX_USAGE;
        }
    }
  if (fd < 0 || whence < 0)
    { builtin_error ("lseek needs FD OFF WHENCE"); return EX_USAGE; }
  off_t r = lseek (fd, (off_t) off, whence);
  if (r < 0) { builtin_error ("lseek: %s", strerror (errno)); return EXECUTION_FAILURE; }
  printf ("%lld\n", (long long) r);
  return EXECUTION_SUCCESS;
}

static int
bio_fstat (WORD_LIST *args)
{
  if (!args) { builtin_error ("fstat: needs FD"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  struct stat st;
  if (fstat (fd, &st) < 0)
    { builtin_error ("fstat: %s", strerror (errno)); return EXECUTION_FAILURE; }
  /* size mtime mode_octal */
  printf ("%lld %lld %o\n",
          (long long) st.st_size,
          (long long) st.st_mtime,
          (unsigned int) (st.st_mode & 07777));
  return EXECUTION_SUCCESS;
}

static int
bio_truncate (WORD_LIST *args)
{
  if (!args || !args->next) { builtin_error ("truncate: needs FD LEN"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  long long len = strtoll (args->next->word->word, NULL, 0);
  if (len < 0)
    { builtin_error ("truncate: negative length: %lld", len); return EX_USAGE; }
  if (ftruncate (fd, (off_t) len) < 0)
    { builtin_error ("ftruncate: %s", strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

/* `bashio touch PATH...` — bump atime+mtime on PATH(s) to NOW. Creates
   PATH as an empty regular file if missing (matches POSIX touch(1) semantics).
   Filling a gap: bash's pure-bash touch.sh can't do utimensat on existing
   files, leaving mtime unchanged — breaks every "is X newer than Y" caller. */
static int
bio_touch (WORD_LIST *args)
{
  if (!args) { builtin_error ("touch: needs PATH"); return EX_USAGE; }
  int rc = EXECUTION_SUCCESS;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *path = p->word->word;
      if (utimensat (AT_FDCWD, path, NULL, 0) < 0)
        {
          if (errno == ENOENT)
            {
              int fd = open (path, O_WRONLY | O_CREAT | O_NOCTTY, 0644);
              if (fd < 0)
                {
                  builtin_error ("touch %s: %s", path, strerror (errno));
                  rc = EXECUTION_FAILURE;
                  continue;
                }
              close (fd);
            }
          else
            {
              builtin_error ("touch %s: %s", path, strerror (errno));
              rc = EXECUTION_FAILURE;
            }
        }
    }
  return rc;
}

static int
bio_sync (WORD_LIST *args)
{
  if (!args) { builtin_error ("sync: needs FD"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  if (fdatasync (fd) < 0)
    { builtin_error ("fdatasync: %s", strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

/* chown UID[:GID] PATH...
 * Filling a gap: bash ships chmod as a loadable but not chown, and
 * bash-os' /bin has no chown binary. Without this, useradd's chown
 * call against a fresh home directory silently fails (`2>/dev/null`)
 * and the new user can't enter their own home (mode 0700 owned by
 * root). Accepts UID by number or name, optional :GID by number or
 * name. Resolves names via /etc/passwd / /etc/group.
 */
static int
bio_resolve_uid (const char *s)
{
  /* Numeric? */
  char *end;
  long v = strtol (s, &end, 10);
  if (*end == '\0') return (int) v;
  /* Name lookup. */
  /* "re" = read + O_CLOEXEC. Defense-in-depth: if a bash trap forks
     between fopen and fclose, the FD won't leak into the child. */
  FILE *f = fopen ("/etc/passwd", "re");
  if (!f) return -1;
  char *line = NULL; size_t cap = 0; int found = -1;
  while (getline (&line, &cap, f) > 0)
    {
      char *p = strchr (line, ':');
      if (!p || (size_t) (p - line) != strlen (s)
          || strncmp (line, s, strlen (s)) != 0) continue;
      /* Skip x: */
      char *q = strchr (p + 1, ':');
      if (!q) continue;
      found = atoi (q + 1);
      break;
    }
  free (line); fclose (f);
  return found;
}

static int
bio_resolve_gid (const char *s)
{
  char *end;
  long v = strtol (s, &end, 10);
  if (*end == '\0') return (int) v;
  FILE *f = fopen ("/etc/group", "re");  /* "re" = read + O_CLOEXEC */
  if (!f) return -1;
  char *line = NULL; size_t cap = 0; int found = -1;
  while (getline (&line, &cap, f) > 0)
    {
      char *p = strchr (line, ':');
      if (!p || (size_t) (p - line) != strlen (s)
          || strncmp (line, s, strlen (s)) != 0) continue;
      char *q = strchr (p + 1, ':');
      if (!q) continue;
      found = atoi (q + 1);
      break;
    }
  free (line); fclose (f);
  return found;
}

static int
bio_chown (WORD_LIST *args)
{
  if (!args || !args->next)
    { builtin_error ("chown needs UID[:GID] PATH..."); return EX_USAGE; }
  const char *spec = args->word->word;
  /* Parse UID[:GID]. UID may be empty (just :GID — chgrp shape). */
  char user[64] = "", group[64] = "";
  const char *colon = strchr (spec, ':');
  if (colon)
    {
      size_t ul = colon - spec;
      if (ul >= sizeof user) { builtin_error ("chown: name too long"); return EX_USAGE; }
      memcpy (user, spec, ul); user[ul] = '\0';
      strncpy (group, colon + 1, sizeof group - 1);
    }
  else
    strncpy (user, spec, sizeof user - 1);

  uid_t uid = (uid_t) -1;
  gid_t gid = (gid_t) -1;
  if (user[0])
    {
      int u = bio_resolve_uid (user);
      if (u < 0) { builtin_error ("chown: unknown user: %s", user); return EXECUTION_FAILURE; }
      uid = (uid_t) u;
    }
  if (group[0])
    {
      int g = bio_resolve_gid (group);
      if (g < 0) { builtin_error ("chown: unknown group: %s", group); return EXECUTION_FAILURE; }
      gid = (gid_t) g;
    }

  /* Apply to each PATH (skip the first arg which was the spec). lchown is
     used so symlinks themselves are chowned (not their targets) — defends
     against symlink-replacement TOCTOU on attacker-controllable paths. */
  int rc = EXECUTION_SUCCESS;
  for (WORD_LIST *p = args->next; p; p = p->next)
    {
      if (lchown (p->word->word, uid, gid) < 0)
        {
          builtin_error ("chown %s: %s", p->word->word, strerror (errno));
          rc = EXECUTION_FAILURE;
        }
    }
  return rc;
}

/* set-addr IFACE IP MASK — configure interface address + netmask via
 * ioctl SIOCSIFADDR + SIOCSIFNETMASK + SIOCSIFFLAGS. Equivalent to
 * `ip addr add IP/MASK dev IFACE && ip link set IFACE up`.
 *
 * IFACE: interface name (e.g. eth0)
 * IP:    dotted-quad IPv4 address
 * MASK:  dotted-quad netmask (e.g. 255.255.255.0)
 *
 * Requires CAP_NET_ADMIN. bash-os runs everything as root → fine.
 * For an unprivileged caller, the ioctl returns EPERM; we surface it.
 *
 * Reference: research/refs/sdhcp/sdhcp.c:164-190 — same ioctl pattern.
 */
static int
bio_set_addr (WORD_LIST *args)
{
  if (!args || !args->next || !args->next->next)
    { builtin_error ("set-addr needs IFACE IP MASK"); return EX_USAGE; }
  const char *iface = args->word->word;
  const char *ip    = args->next->word->word;
  const char *mask  = args->next->next->word->word;

  int sfd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sfd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }

  struct ifreq ifr;
  memset (&ifr, 0, sizeof ifr);
  strncpy (ifr.ifr_name, iface, IFNAMSIZ - 1);

  /* Set address. */
  struct sockaddr_in *sin = (struct sockaddr_in *) &ifr.ifr_addr;
  sin->sin_family = AF_INET;
  if (inet_pton (AF_INET, ip, &sin->sin_addr) != 1)
    { builtin_error ("bad IP: %s", ip); close (sfd); return EX_USAGE; }
  if (ioctl (sfd, SIOCSIFADDR, &ifr) < 0)
    { builtin_error ("SIOCSIFADDR %s %s: %s", iface, ip, strerror (errno));
      close (sfd); return EXECUTION_FAILURE; }

  /* Set netmask. */
  sin = (struct sockaddr_in *) &ifr.ifr_netmask;
  sin->sin_family = AF_INET;
  if (inet_pton (AF_INET, mask, &sin->sin_addr) != 1)
    { builtin_error ("bad MASK: %s", mask); close (sfd); return EX_USAGE; }
  if (ioctl (sfd, SIOCSIFNETMASK, &ifr) < 0)
    { builtin_error ("SIOCSIFNETMASK %s %s: %s", iface, mask, strerror (errno));
      close (sfd); return EXECUTION_FAILURE; }

  /* Set IFF_UP|IFF_RUNNING on the iface we just addressed. /init brings up
     `lo` at boot, but other interfaces (e.g. eth0 during DHCP) still need
     this transition. Re-asserting after addr config is harmless and
     matches sdhcp. */
  if (ioctl (sfd, SIOCGIFFLAGS, &ifr) < 0)
    { builtin_error ("SIOCGIFFLAGS: %s", strerror (errno));
      close (sfd); return EXECUTION_FAILURE; }
  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  if (ioctl (sfd, SIOCSIFFLAGS, &ifr) < 0)
    { builtin_error ("SIOCSIFFLAGS: %s", strerror (errno));
      close (sfd); return EXECUTION_FAILURE; }

  close (sfd);
  return EXECUTION_SUCCESS;
}

/* set-route GATEWAY [-i IFACE] — install a default route via GATEWAY.
 * Equivalent to `ip route add default via GATEWAY [dev IFACE]`.
 *
 * Mechanically: ioctl SIOCADDRT with rtentry { rt_dst=0.0.0.0,
 * rt_genmask=0.0.0.0, rt_gateway=GATEWAY, rt_flags=RTF_UP|RTF_GATEWAY }.
 * If -i IFACE is given, rt_dev is set; otherwise the kernel picks
 * based on the gateway's reachability.
 *
 * Reference: research/refs/sdhcp/sdhcp.c:206-221 — same pattern.
 */
static int
bio_set_route (WORD_LIST *args)
{
  if (!args) { builtin_error ("set-route needs GATEWAY [-i IFACE]"); return EX_USAGE; }
  const char *gw = NULL;
  const char *iface = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-i") == 0)
        { if (!p->next) { builtin_error ("-i needs IFACE"); return EX_USAGE; }
          p = p->next; iface = p->word->word; }
      else if (!gw) gw = w;
      else { builtin_error ("set-route: extra arg %s", w); return EX_USAGE; }
    }
  if (!gw) { builtin_error ("set-route needs GATEWAY [-i IFACE]"); return EX_USAGE; }

  int sfd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sfd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }

  struct rtentry rt;
  memset (&rt, 0, sizeof rt);

  struct sockaddr_in *dst = (struct sockaddr_in *) &rt.rt_dst;
  struct sockaddr_in *msk = (struct sockaddr_in *) &rt.rt_genmask;
  struct sockaddr_in *gwa = (struct sockaddr_in *) &rt.rt_gateway;
  dst->sin_family = msk->sin_family = gwa->sin_family = AF_INET;
  /* dst + mask remain 0.0.0.0 (= default route). */
  if (inet_pton (AF_INET, gw, &gwa->sin_addr) != 1)
    { builtin_error ("bad GATEWAY: %s", gw); close (sfd); return EX_USAGE; }

  rt.rt_flags = RTF_UP | RTF_GATEWAY;
  /* rt_dev is `char *`. Use a writable stack copy rather than casting
     away const on a possibly-string-literal `iface`. */
  char ifname[IFNAMSIZ];
  if (iface)
    {
      if (strlen (iface) >= sizeof ifname)
        { builtin_error ("interface name too long: %s", iface); close (sfd); return EX_USAGE; }
      strcpy (ifname, iface);
      rt.rt_dev = ifname;
    }

  if (ioctl (sfd, SIOCADDRT, &rt) < 0)
    {
      /* EEXIST is non-fatal: the route is already there. */
      if (errno != EEXIST)
        { builtin_error ("SIOCADDRT via %s: %s", gw, strerror (errno));
          close (sfd); return EXECUTION_FAILURE; }
    }
  close (sfd);
  return EXECUTION_SUCCESS;
}

int
bashio_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;

  if (strcmp (cmd, "open")     == 0) return bio_open (args);
  if (strcmp (cmd, "close")    == 0) return bio_close (args);
  if (strcmp (cmd, "pread")    == 0) return bio_pread (args);
  if (strcmp (cmd, "pwrite")   == 0) return bio_pwrite (args);
  if (strcmp (cmd, "lseek")    == 0) return bio_lseek (args);
  if (strcmp (cmd, "fstat")    == 0) return bio_fstat (args);
  if (strcmp (cmd, "truncate") == 0) return bio_truncate (args);
  if (strcmp (cmd, "touch")    == 0) return bio_touch (args);
  if (strcmp (cmd, "sync")     == 0) return bio_sync (args);
  if (strcmp (cmd, "chown")    == 0) return bio_chown (args);
  if (strcmp (cmd, "set-addr") == 0) return bio_set_addr (args);
  if (strcmp (cmd, "set-route")== 0) return bio_set_route (args);

  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *bashio_doc[] = {
  "Random-access file I/O via pread/pwrite/lseek/fstat/truncate.",
  "",
  "    bashio open PATH MODE [-c] [-x]    open, print fd",
  "    bashio pread FD LEN OFF [-x]       read LEN bytes at OFF",
  "    bashio pwrite FD HEX OFF           write hex bytes at OFF",
  "    bashio lseek FD OFF WHENCE         WHENCE: set/cur/end",
  "    bashio fstat FD                    print: size mtime mode",
  "    bashio truncate FD LEN",
  "    bashio sync FD",
  "    bashio close FD",
  "    bashio touch PATH                  utimensat(2) — update atime+mtime",
  "    bashio chown OWNER[:GROUP] PATH... by name or uid:gid",
  "    bashio set-addr IFACE IP MASK         configure interface IPv4 addr",
  "    bashio set-route GATEWAY [-i IFACE]   install default IPv4 route",
  "",
  "Hex output (-x on pread) is binhex-style: NUL-safe variable storage.",
  "Raw output goes through stdout (binary-safe at the FD layer).",
  (char *)NULL
};

struct builtin bashio_struct = {
  "bashio",
  bashio_builtin,
  BUILTIN_ENABLED,
  bashio_doc,
  "bashio open|close|pread|pwrite|lseek|fstat|truncate|sync|chown|set-addr|set-route ARGS...",
  0
};
