/* SPDX-License-Identifier: MIT */
/* audit.c — NETLINK_AUDIT consumer for the bash-os audit engine.
 *
 * Debian-server-parity AUDIT-6.2 Pass 2 (design
 * research/bash-os/DEBIAN-SERVER-PARITY-IMPL-AUDIT-IDS.md §6.2). Pass 1
 * (auditctl/ausearch/aureport shell CLIs + lib/auditctl-rules.sh +
 * lib/audit-records.sh) already landed; this loadable is the kernel-facing
 * half they call into.
 *
 * Per design §12.1 review: audit polls its OWN netlink fd internally
 * (like pcap), NOT via poll — so there is no poll dependency.
 *
 * Verbs:
 *   audit status [-V VAR]
 *       AUDIT_GET → print (or bind <VAR>_{enabled,pid,lost,backlog,
 *       rate_limit,backlog_limit,failure}) the kernel audit status.
 *   audit set-enabled 0|1|2
 *       AUDIT_SET STATUS_ENABLED. Needs CAP_AUDIT_WRITE.
 *   audit add-rule PRIO ACTION FILTER SYSCALLS FIELDS KEY
 *   audit del-rule PRIO ACTION FILTER SYSCALLS FIELDS KEY
 *       Program/unprogram one rule in the kernel. The six args are exactly
 *       the canonical TSV columns produced by lib/auditctl-rules.sh
 *       (arule_parse): prio∈{a,A}, action∈{always,never}, filter∈{task,
 *       exit,user,exclude}, SYSCALLS=comma list or 'all', FIELDS=';'-joined
 *       'F OP V' triples or ';', KEY or ''. Needs CAP_AUDIT_WRITE.
 *   audit list-rules
 *       AUDIT_LIST_RULES → render each kernel rule in canonical "-a ..." form.
 *   audit run [-c COUNT] [-t SECONDS] [-o FILE]
 *       Register as the audit daemon (AUDIT_SET pid=self,enabled=1), then
 *       self-poll the netlink fd and append decoded records to FILE
 *       (default lib/audit-records.sh path). Stops after COUNT records,
 *       SECONDS elapsed, or SIGINT/SIGTERM. Needs CAP_AUDIT_READ (+WRITE to
 *       set the daemon pid).
 *   audit decode-text TYPE PAYLOAD [-o FILE]
 *       HOST-TESTABLE deserializer seam: feed a numeric AUDIT_* message TYPE
 *       and the raw text PAYLOAD (the kernel's "audit(SEC.MSEC:SERIAL): ..."
 *       string) and emit one bash-os-native TSV record. The internal run
 *       loop funnels every received message through the SAME emitter.
 *   audit typename NUM | typenum NAME
 *       Pinned AUDIT_* map lookups (must match lib/audit-records.sh).
 *
 * Record format is the 9-field TSV defined in lib/audit-records.sh:
 *   type<TAB>epoch_ms<TAB>serial<TAB>auid<TAB>uid<TAB>pid<TAB>exe<TAB>key<TAB>kv
 * Deliberately NOT byte-identical to upstream /var/log/audit/audit.log
 * (design §6.2; Q13: no symlink alias). Out-of-pinned-set message types are
 * recorded under type=UNKNOWN with the numeric AUDIT_* in the kv tail — no
 * silent drop (lib/audit-records.sh contract).
 *
 * Host vs in-guest: decode-text / typename / typenum / rule ENCODING are
 * pure and host-testable (stub-ABI harness or the live static bash binary).
 * status / set-enabled / add-rule / del-rule / list-rules / run touch the
 * kernel and need CAP_AUDIT_READ/WRITE — exercised by the QEMU netlink
 * fixture (design §7).
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
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/audit.h>

#include "loadables.h"

#ifndef NETLINK_AUDIT
#  define NETLINK_AUDIT 9
#endif
/* x86_64 / i386 audit arch words (avoid pulling <linux/elf-em.h>). */
#ifndef BA_ARCH_X86_64
#  define BA_ARCH_X86_64 0xC000003EU
#endif
#ifndef BA_ARCH_I386
#  define BA_ARCH_I386   0x40000003U
#endif

#define BA_BUFSZ 8192

/* ----------------------------------------------------------------- */
/* Pinned AUDIT_* type map — MUST match lib/audit-records.sh (Q2 v1). */
/* ----------------------------------------------------------------- */

struct ba_type { const char *name; int num; };
static const struct ba_type ba_types[] = {
  { "SYSCALL", 1300 }, { "PATH", 1302 }, { "CWD", 1307 },
  { "EXECVE", 1309 }, { "CONFIG_CHANGE", 1305 },
  { "USER_AUTH", 1100 }, { "USER_ACCT", 1101 }, { "CRED_ACQ", 1103 },
  { "USER_END", 1106 }, { "CRED_DISP", 1108 }, { "USER_LOGIN", 1112 },
  { "USER_LOGOUT", 1113 },
  { "ANOM_LOGIN_FAILURES", 2100 }, { "ANOM_LOGIN_TIME", 2101 },
  { NULL, 0 }
};

static const char *
ba_type_name (int num)
{
  for (const struct ba_type *t = ba_types; t->name; t++)
    if (t->num == num)
      return t->name;
  return NULL;                  /* out of pinned set */
}

static int
ba_type_num (const char *name)
{
  for (const struct ba_type *t = ba_types; t->name; t++)
    if (strcmp (t->name, name) == 0)
      return t->num;
  return -1;
}

/* ----------------------------------------------------------------- */
/* Record deserializer (pure / host-testable)                        */
/* ----------------------------------------------------------------- */

/* Pull the value of "key=" or 'key="..."' out of a kernel audit payload.
 * Returns a malloc'd string (caller frees) or NULL if absent. */
static char *
ba_field (const char *payload, const char *key)
{
  size_t klen = strlen (key);
  const char *p = payload;
  while ((p = strstr (p, key)) != NULL)
    {
      /* Must be at start or preceded by whitespace, and followed by '='. */
      if ((p == payload || isspace ((unsigned char) p[-1])) && p[klen] == '=')
        {
          const char *v = p + klen + 1;
          const char *end;
          char *out;
          if (*v == '"')
            {
              v++;
              end = strchr (v, '"');
              if (!end)
                end = v + strlen (v);
            }
          else
            {
              end = v;
              while (*end && !isspace ((unsigned char) *end))
                end++;
            }
          out = malloc ((size_t) (end - v) + 1);
          if (!out)
            return NULL;
          memcpy (out, v, (size_t) (end - v));
          out[end - v] = '\0';
          return out;
        }
      p += klen;
    }
  return NULL;
}

/* Whitespace-escape into the lib/audit-records.sh kv convention
 * (tab → %09, newline → %0a) so the record stays one logical line. */
static void
ba_emit_escaped (FILE *out, const char *s)
{
  for (; *s; s++)
    {
      if (*s == '\t')      fputs ("%09", out);
      else if (*s == '\n') fputs ("%0a", out);
      else                 fputc (*s, out);
    }
}

/* Build the space-separated kv tail: every "k=v" / 'k="v"' token from the
 * payload EXCEPT the columns we lifted (auid/uid/pid/exe/key) and the
 * leading audit(...) stamp. Writes directly to `out`, escaped. */
static void
ba_emit_kv_tail (FILE *out, const char *payload)
{
  static const char *lifted[] = { "auid", "uid", "pid", "exe", "key", NULL };
  const char *p = payload;
  int first = 1;
  while (*p)
    {
      while (*p && isspace ((unsigned char) *p))
        p++;
      if (!*p)
        break;
      /* token runs to next unquoted whitespace */
      const char *start = p;
      int inq = 0;
      while (*p && (inq || !isspace ((unsigned char) *p)))
        {
          if (*p == '"')
            inq = !inq;
          p++;
        }
      size_t len = (size_t) (p - start);
      /* skip the "audit(...)" / "audit(...):" stamp token */
      if (len >= 6 && strncmp (start, "audit(", 6) == 0)
        continue;
      /* skip a bare ":" left over from the stamp */
      if (len == 1 && start[0] == ':')
        continue;
      /* skip lifted columns (match "name=") */
      int skip = 0;
      for (const char **k = lifted; *k; k++)
        {
          size_t kl = strlen (*k);
          if (len > kl && strncmp (start, *k, kl) == 0 && start[kl] == '=')
            { skip = 1; break; }
        }
      if (skip)
        continue;
      if (!first)
        fputc (' ', out);
      first = 0;
      for (size_t i = 0; i < len; i++)
        {
          char c = start[i];
          if (c == '\t')      fputs ("%09", out);
          else if (c == '\n') fputs ("%0a", out);
          else                fputc (c, out);
        }
    }
}

/* Emit ONE record (9-field TSV) for a received/decoded message.
 * type_num is the netlink nlmsg_type; payload is the kernel text body. */
static void
ba_emit_record (FILE *out, int type_num, const char *payload)
{
  const char *tname = ba_type_name (type_num);
  long long epoch_ms = 0;
  long long serial = 0;
  char *auid = NULL, *uid = NULL, *pid = NULL, *exe = NULL, *key = NULL;

  /* Parse the "audit(SEC.MSEC:SERIAL)" stamp if present. */
  const char *a = strstr (payload, "audit(");
  if (a)
    {
      long sec = 0, msec = 0, ser = 0;
      a += 6;
      sec = strtol (a, (char **) &a, 10);
      if (*a == '.')
        msec = strtol (a + 1, (char **) &a, 10);
      if (*a == ':')
        ser = strtol (a + 1, (char **) &a, 10);
      epoch_ms = (long long) sec * 1000 + msec;
      serial = ser;
    }

  auid = ba_field (payload, "auid");
  uid  = ba_field (payload, "uid");
  pid  = ba_field (payload, "pid");
  exe  = ba_field (payload, "exe");
  key  = ba_field (payload, "key");

  /* type column: pinned name, else UNKNOWN (numeric goes in kv tail). */
  fputs (tname ? tname : "UNKNOWN", out);
  fprintf (out, "\t%lld\t%lld\t", epoch_ms, serial);
  fputs (auid ? auid : "-", out); fputc ('\t', out);
  fputs (uid  ? uid  : "-", out); fputc ('\t', out);
  fputs (pid  ? pid  : "-", out); fputc ('\t', out);
  if (exe) { ba_emit_escaped (out, exe); } else fputc ('-', out);
  fputc ('\t', out);
  if (key) { ba_emit_escaped (out, key); } else fputc ('-', out);
  fputc ('\t', out);
  /* kv tail: for UNKNOWN types, lead with the numeric audit type. */
  if (!tname)
    fprintf (out, "audit_type=%d ", type_num);
  ba_emit_kv_tail (out, payload);
  fputc ('\n', out);

  free (auid); free (uid); free (pid); free (exe); free (key);
}

/* Resolve the operator output stream for -o FILE (NULL → default path). */
static FILE *
ba_open_out (const char *path)
{
  const char *p = path;
  if (!p)
    {
      p = getenv ("AUDIT_RECORDS_FILE");
      if (!p) p = getenv ("BASH_OS_AUDIT_LOG");
      if (!p) p = "/var/log/bash-os/audit/records.tsv";
    }
  if (strcmp (p, "-") == 0)
    return stdout;
  return fopen (p, "a");
}

/* ----------------------------------------------------------------- */
/* Rule encoder (pure / host-testable)                               */
/* ----------------------------------------------------------------- */

/* x86_64 syscall name → number for the audited-call subset. bash-os targets
 * x86_64; an unknown name rejects (honest, bounded — design §2 anti-drift). */
struct ba_sc { const char *name; int nr; };
static const struct ba_sc ba_syscalls[] = {
  { "read", 0 }, { "write", 1 }, { "open", 2 }, { "close", 3 },
  { "stat", 4 }, { "fstat", 5 }, { "lstat", 6 }, { "lseek", 8 },
  { "mmap", 9 }, { "mprotect", 10 }, { "ioctl", 16 },
  { "pread64", 17 }, { "pwrite64", 18 }, { "access", 21 },
  { "pipe", 22 }, { "dup", 32 }, { "dup2", 33 }, { "socket", 41 },
  { "connect", 42 }, { "accept", 43 }, { "sendto", 44 },
  { "bind", 49 }, { "listen", 50 },
  { "setsockopt", 54 }, { "clone", 56 }, { "fork", 57 }, { "vfork", 58 },
  { "execve", 59 }, { "exit", 60 }, { "kill", 62 }, { "fcntl", 72 },
  { "truncate", 76 }, { "ftruncate", 77 }, { "getdents", 78 },
  { "rename", 82 }, { "mkdir", 83 }, { "rmdir", 84 }, { "creat", 85 },
  { "link", 86 }, { "unlink", 87 }, { "symlink", 88 }, { "readlink", 89 },
  { "chmod", 90 }, { "fchmod", 91 }, { "chown", 92 }, { "fchown", 93 },
  { "lchown", 94 }, { "umask", 95 }, { "ptrace", 101 }, { "setuid", 105 },
  { "setgid", 106 }, { "setreuid", 113 }, { "setregid", 114 },
  { "setresuid", 117 }, { "setresgid", 119 }, { "setfsuid", 122 },
  { "setfsgid", 123 }, { "mount", 165 }, { "umount2", 166 },
  { "swapon", 167 }, { "swapoff", 168 }, { "reboot", 169 },
  { "sethostname", 170 }, { "setdomainname", 171 }, { "init_module", 175 },
  { "delete_module", 176 }, { "settimeofday", 164 }, { "adjtimex", 159 },
  { "clock_settime", 227 }, { "openat", 257 }, { "mkdirat", 258 },
  { "mknodat", 259 }, { "fchownat", 260 }, { "unlinkat", 263 },
  { "renameat", 264 }, { "linkat", 265 }, { "symlinkat", 266 },
  { "readlinkat", 267 }, { "fchmodat", 268 }, { "faccessat", 269 },
  { "finit_module", 313 }, { "renameat2", 316 }, { "execveat", 322 },
  { NULL, 0 }
};

static int
ba_syscall_nr (const char *name)
{
  if (isdigit ((unsigned char) name[0]))
    return atoi (name);
  for (const struct ba_sc *s = ba_syscalls; s->name; s++)
    if (strcmp (s->name, name) == 0)
      return s->nr;
  return -1;
}

/* Map a canonical filter name → AUDIT_FILTER_* flag. */
static int
ba_filter_flag (const char *f)
{
  if (strcmp (f, "task") == 0)    return AUDIT_FILTER_TASK;
  if (strcmp (f, "exit") == 0)    return AUDIT_FILTER_EXIT;
  if (strcmp (f, "user") == 0)    return AUDIT_FILTER_USER;
  if (strcmp (f, "exclude") == 0) return AUDIT_FILTER_EXCLUDE;
  return -1;
}

/* Map a canonical -F field name → kernel field type. -1 = unknown,
 * -2 = recognised but watch-style (path/dir/name): not programmable via -F
 * in this engine (needs the AUDIT_WATCH/-w ABI). */
static int
ba_field_type (const char *f)
{
  if (!strcmp (f, "arch"))    return AUDIT_ARCH;
  if (!strcmp (f, "auid"))    return AUDIT_LOGINUID;
  if (!strcmp (f, "uid"))     return AUDIT_UID;
  if (!strcmp (f, "gid"))     return AUDIT_GID;
  if (!strcmp (f, "euid"))    return AUDIT_EUID;
  if (!strcmp (f, "egid"))    return AUDIT_EGID;
  if (!strcmp (f, "suid"))    return AUDIT_SUID;
  if (!strcmp (f, "sgid"))    return AUDIT_SGID;
  if (!strcmp (f, "fsuid"))   return AUDIT_FSUID;
  if (!strcmp (f, "fsgid"))   return AUDIT_FSGID;
  if (!strcmp (f, "pid"))     return AUDIT_PID;
  if (!strcmp (f, "ppid"))    return AUDIT_PPID;
  if (!strcmp (f, "exit"))    return AUDIT_EXIT;
  if (!strcmp (f, "success")) return AUDIT_SUCCESS;
  if (!strcmp (f, "perm"))    return AUDIT_PERM;
  if (!strcmp (f, "msgtype")) return AUDIT_MSGTYPE;
  if (!strcmp (f, "key"))     return AUDIT_FILTERKEY;
  if (!strcmp (f, "path") || !strcmp (f, "dir") || !strcmp (f, "name"))
    return -2;
  return -1;
}

/* Map a canonical operator → AUDIT_* comparator flag. */
static unsigned
ba_op_flag (const char *op)
{
  if (!strcmp (op, "="))  return AUDIT_EQUAL;
  if (!strcmp (op, "!=")) return AUDIT_NOT_EQUAL;
  if (!strcmp (op, "<"))  return AUDIT_LESS_THAN;
  if (!strcmp (op, ">"))  return AUDIT_GREATER_THAN;
  if (!strcmp (op, "<=")) return AUDIT_LESS_THAN | AUDIT_EQUAL;
  if (!strcmp (op, ">=")) return AUDIT_GREATER_THAN | AUDIT_EQUAL;
  if (!strcmp (op, "&"))  return AUDIT_BIT_MASK;
  return 0;
}

/* Decode a -F value for a given field type into the numeric kernel value.
 * Returns 0 on success, -1 on a value we refuse to guess at. */
static int
ba_field_value (int ftype, const char *v, __u32 *out)
{
  if (ftype == AUDIT_ARCH)
    {
      if (!strcmp (v, "b64")) { *out = BA_ARCH_X86_64; return 0; }
      if (!strcmp (v, "b32")) { *out = BA_ARCH_I386;   return 0; }
      *out = (__u32) strtoul (v, NULL, 0);   /* hex/dec literal */
      return 0;
    }
  if (ftype == AUDIT_SUCCESS)
    {
      if (!strcmp (v, "yes") || !strcmp (v, "1")) { *out = 1; return 0; }
      if (!strcmp (v, "no")  || !strcmp (v, "0")) { *out = 0; return 0; }
      *out = (__u32) strtoul (v, NULL, 0); return 0;
    }
  if (ftype == AUDIT_PERM)
    {
      __u32 m = 0;
      if (isdigit ((unsigned char) v[0]))
        { *out = (__u32) strtoul (v, NULL, 0); return 0; }
      for (const char *c = v; *c; c++)
        switch (*c)
          {
          case 'r': m |= AUDIT_PERM_READ;  break;
          case 'w': m |= AUDIT_PERM_WRITE; break;
          case 'x': m |= AUDIT_PERM_EXEC;  break;
          case 'a': m |= AUDIT_PERM_ATTR;  break;
          default: return -1;
          }
      *out = m;
      return 0;
    }
  /* numeric uid/gid/pid/exit/msgtype/etc. Require a number — name→id
   * resolution is out of this engine's scope (no NSS in bash-os). */
  if (!isdigit ((unsigned char) v[0]) && v[0] != '-')
    return -1;
  *out = (__u32) strtoul (v, NULL, 0);
  return 0;
}

/* Build a kernel audit_rule_data from canonical TSV columns. On success
 * returns a malloc'd buffer (caller frees) and sets *plen to its total
 * length; on parse failure returns NULL and writes a builtin_error. */
static struct audit_rule_data *
ba_build_rule (const char *prio, const char *action, const char *filter,
               const char *syscalls, const char *fields, const char *key,
               size_t *plen)
{
  int ffl = ba_filter_flag (filter);
  if (ffl < 0)
    { builtin_error ("add-rule: bad filter: %s", filter); return NULL; }
  int act;
  if (!strcmp (action, "always")) act = AUDIT_ALWAYS;
  else if (!strcmp (action, "never")) act = AUDIT_NEVER;
  else { builtin_error ("add-rule: bad action: %s", action); return NULL; }

  /* String fields live in a trailing buf[]; size it generously. */
  size_t bufcap = (key ? strlen (key) : 0) + 256;
  struct audit_rule_data *r = calloc (1, sizeof (*r) + bufcap);
  if (!r)
    { builtin_error ("add-rule: out of memory"); return NULL; }
  r->flags = (unsigned) ffl;
  if (prio && prio[0] == 'A')
    r->flags |= AUDIT_FILTER_PREPEND;
  r->action = (unsigned) act;

  /* Syscall mask. 'all' → every bit; else set each named/numbered call. */
  if (!strcmp (syscalls, "all"))
    {
      for (int i = 0; i < AUDIT_BITMASK_SIZE; i++)
        r->mask[i] = ~0U;
    }
  else
    {
      char *tmp = strdup (syscalls), *save = NULL, *tok;
      if (!tmp) { free (r); builtin_error ("add-rule: oom"); return NULL; }
      for (tok = strtok_r (tmp, ",", &save); tok;
           tok = strtok_r (NULL, ",", &save))
        {
          int nr = ba_syscall_nr (tok);
          if (nr < 0 || nr >= AUDIT_BITMASK_SIZE * 32)
            {
              builtin_error ("add-rule: unknown/out-of-range syscall: %s", tok);
              free (tmp); free (r); return NULL;
            }
          r->mask[nr / 32] |= (1U << (nr % 32));
        }
      free (tmp);
    }

  /* -F field clauses. `fields` is ';'-joined "F OP V" or a bare ';'. */
  __u32 buflen = 0;
  if (fields && strcmp (fields, ";") != 0 && fields[0])
    {
      char *tmp = strdup (fields), *save = NULL, *clause;
      if (!tmp) { free (r); builtin_error ("add-rule: oom"); return NULL; }
      for (clause = strtok_r (tmp, ";", &save); clause;
           clause = strtok_r (NULL, ";", &save))
        {
          char f[32] = {0}, op[4] = {0}, v[192] = {0};
          if (sscanf (clause, "%31s %3s %191s", f, op, v) != 3)
            {
              builtin_error ("add-rule: malformed -F clause: %s", clause);
              free (tmp); free (r); return NULL;
            }
          if (r->field_count >= AUDIT_MAX_FIELDS)
            {
              builtin_error ("add-rule: too many -F fields (max %d)",
                             AUDIT_MAX_FIELDS);
              free (tmp); free (r); return NULL;
            }
          int ft = ba_field_type (f);
          if (ft == -2)
            {
              builtin_error ("add-rule: -F %s is watch-style; not "
                             "programmable via -F (use a path watch)", f);
              free (tmp); free (r); return NULL;
            }
          if (ft < 0)
            {
              builtin_error ("add-rule: unknown -F field: %s", f);
              free (tmp); free (r); return NULL;
            }
          unsigned opf = ba_op_flag (op);
          if (!opf)
            {
              builtin_error ("add-rule: bad -F operator: %s", op);
              free (tmp); free (r); return NULL;
            }
          unsigned idx = r->field_count;
          r->fields[idx] = (unsigned) ft;
          r->fieldflags[idx] = opf;
          if (ft == AUDIT_FILTERKEY)
            {
              size_t vl = strlen (v);
              if (buflen + vl > bufcap)
                { builtin_error ("add-rule: field buffer overflow");
                  free (tmp); free (r); return NULL; }
              memcpy (r->buf + buflen, v, vl);
              r->values[idx] = (unsigned) vl;
              buflen += (unsigned) vl;
            }
          else
            {
              __u32 nv = 0;
              if (ba_field_value (ft, v, &nv) < 0)
                {
                  builtin_error ("add-rule: -F %s: non-numeric value: %s", f, v);
                  free (tmp); free (r); return NULL;
                }
              r->values[idx] = nv;
            }
          r->field_count++;
        }
      free (tmp);
    }

  /* A -k KEY (separate from -F key) appends a FILTERKEY field. */
  if (key && key[0])
    {
      if (r->field_count >= AUDIT_MAX_FIELDS)
        { builtin_error ("add-rule: no room for -k key"); free (r); return NULL; }
      size_t kl = strlen (key);
      if (buflen + kl > bufcap)
        { builtin_error ("add-rule: key buffer overflow"); free (r); return NULL; }
      unsigned idx = r->field_count;
      r->fields[idx] = AUDIT_FILTERKEY;
      r->fieldflags[idx] = AUDIT_EQUAL;
      memcpy (r->buf + buflen, key, kl);
      r->values[idx] = (unsigned) kl;
      buflen += (unsigned) kl;
      r->field_count++;
    }

  r->buflen = buflen;
  *plen = sizeof (*r) + buflen;
  return r;
}

/* ----------------------------------------------------------------- */
/* Netlink transport (privileged / in-guest)                         */
/* ----------------------------------------------------------------- */

static int
ba_open (void)
{
  int fd = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_AUDIT);
  if (fd < 0)
    return -1;
  struct sockaddr_nl sa;
  memset (&sa, 0, sizeof sa);
  sa.nl_family = AF_NETLINK;
  if (bind (fd, (struct sockaddr *) &sa, sizeof sa) < 0)
    { close (fd); return -1; }
  return fd;
}

static unsigned
ba_seq (void)
{
  static unsigned s = 0;
  if (s == 0)
    s = 0xada00000U ^ (unsigned) time (NULL) ^ ((unsigned) getpid () << 8);
  return ++s;
}

/* Send one netlink message (type/flags/payload) to the kernel. */
static int
ba_send (int fd, int type, int flags, const void *data, size_t len, unsigned seq)
{
  char *buf = calloc (1, NLMSG_SPACE (len));
  if (!buf)
    return -1;
  struct nlmsghdr *nlh = (struct nlmsghdr *) buf;
  nlh->nlmsg_len = NLMSG_LENGTH (len);
  nlh->nlmsg_type = (unsigned short) type;
  nlh->nlmsg_flags = (unsigned short) (NLM_F_REQUEST | flags);
  nlh->nlmsg_seq = seq;
  nlh->nlmsg_pid = 0;
  if (len && data)
    memcpy (NLMSG_DATA (nlh), data, len);
  struct sockaddr_nl kaddr;
  memset (&kaddr, 0, sizeof kaddr);
  kaddr.nl_family = AF_NETLINK;
  ssize_t n = sendto (fd, buf, nlh->nlmsg_len, 0,
                      (struct sockaddr *) &kaddr, sizeof kaddr);
  free (buf);
  return n < 0 ? -1 : 0;
}

/* Wait for the ACK (NLMSG_ERROR with error==0) for `seq`. Returns 0 on
 * success, -1 with errno set on a kernel error. */
static int
ba_wait_ack (int fd, unsigned seq)
{
  char buf[BA_BUFSZ];
  for (;;)
    {
      ssize_t s = recv (fd, buf, sizeof buf, 0);
      if (s < 0)
        { if (errno == EINTR) continue; return -1; }
      for (struct nlmsghdr *h = (struct nlmsghdr *) buf;
           NLMSG_OK (h, (size_t) s); h = NLMSG_NEXT (h, s))
        {
          if (h->nlmsg_seq != seq)
            continue;
          if (h->nlmsg_type == NLMSG_ERROR)
            {
              struct nlmsgerr *e = (struct nlmsgerr *) NLMSG_DATA (h);
              if (e->error == 0)
                return 0;
              errno = -e->error;
              return -1;
            }
        }
    }
}

/* --- status -------------------------------------------------------- */

static int
ba_cmd_status (const char *var)
{
  int fd = ba_open ();
  if (fd < 0)
    { builtin_error ("status: NETLINK_AUDIT socket: %s", strerror (errno));
      return EXECUTION_FAILURE; }
  unsigned seq = ba_seq ();
  if (ba_send (fd, AUDIT_GET, 0, NULL, 0, seq) < 0)
    { builtin_error ("status: send: %s", strerror (errno));
      close (fd); return EXECUTION_FAILURE; }

  char buf[BA_BUFSZ];
  struct audit_status st;
  int got = 0;
  for (; !got; )
    {
      ssize_t s = recv (fd, buf, sizeof buf, 0);
      if (s < 0)
        { if (errno == EINTR) continue;
          builtin_error ("status: recv: %s", strerror (errno));
          close (fd); return EXECUTION_FAILURE; }
      for (struct nlmsghdr *h = (struct nlmsghdr *) buf;
           NLMSG_OK (h, (size_t) s); h = NLMSG_NEXT (h, s))
        {
          if (h->nlmsg_type == NLMSG_ERROR)
            { struct nlmsgerr *e = (struct nlmsgerr *) NLMSG_DATA (h);
              if (e->error)
                { errno = -e->error;
                  builtin_error ("status: kernel: %s", strerror (errno));
                  close (fd); return EXECUTION_FAILURE; } }
          if (h->nlmsg_type == AUDIT_GET)
            { memset (&st, 0, sizeof st);
              size_t pl = NLMSG_PAYLOAD (h, 0);
              if (pl > sizeof st) pl = sizeof st;
              memcpy (&st, NLMSG_DATA (h), pl);
              got = 1; break; }
        }
    }
  close (fd);

  if (var)
    {
      char nm[128], val[32];
#define BIND(field, member) \
      snprintf (nm, sizeof nm, "%s_%s", var, field); \
      snprintf (val, sizeof val, "%u", (unsigned) st.member); \
      builtin_bind_variable (nm, val, 0)
      BIND ("enabled", enabled);
      BIND ("pid", pid);
      BIND ("rate_limit", rate_limit);
      BIND ("backlog_limit", backlog_limit);
      BIND ("lost", lost);
      BIND ("backlog", backlog);
      BIND ("failure", failure);
#undef BIND
    }
  else
    {
      printf ("enabled=%u\n",       (unsigned) st.enabled);
      printf ("pid=%u\n",           (unsigned) st.pid);
      printf ("rate_limit=%u\n",    (unsigned) st.rate_limit);
      printf ("backlog_limit=%u\n", (unsigned) st.backlog_limit);
      printf ("lost=%u\n",          (unsigned) st.lost);
      printf ("backlog=%u\n",       (unsigned) st.backlog);
      printf ("failure=%u\n",       (unsigned) st.failure);
    }
  return EXECUTION_SUCCESS;
}

/* --- set-enabled --------------------------------------------------- */

static int
ba_cmd_set_enabled (const char *arg)
{
  char *end;
  unsigned long v = strtoul (arg, &end, 10);
  if (*end || v > 2)
    { builtin_error ("set-enabled: expected 0, 1 or 2"); return EX_USAGE; }
  int fd = ba_open ();
  if (fd < 0)
    { builtin_error ("set-enabled: socket: %s", strerror (errno));
      return EXECUTION_FAILURE; }
  struct audit_status st;
  memset (&st, 0, sizeof st);
  st.mask = AUDIT_STATUS_ENABLED;
  st.enabled = (unsigned) v;
  unsigned seq = ba_seq ();
  int rc = EXECUTION_SUCCESS;
  if (ba_send (fd, AUDIT_SET, NLM_F_ACK, &st, sizeof st, seq) < 0
      || ba_wait_ack (fd, seq) < 0)
    { builtin_error ("set-enabled: %s", strerror (errno));
      rc = EXECUTION_FAILURE; }
  close (fd);
  return rc;
}

/* --- add/del rule -------------------------------------------------- */

static int
ba_cmd_rule (int add, char **a, int n)
{
  if (n != 6)
    { builtin_error ("%s: need PRIO ACTION FILTER SYSCALLS FIELDS KEY",
                     add ? "add-rule" : "del-rule");
      return EX_USAGE; }
  size_t len = 0;
  struct audit_rule_data *r =
    ba_build_rule (a[0], a[1], a[2], a[3], a[4], a[5], &len);
  if (!r)
    return EXECUTION_FAILURE;     /* ba_build_rule already reported why */
  int fd = ba_open ();
  if (fd < 0)
    { builtin_error ("%s: socket: %s", add ? "add-rule" : "del-rule",
                     strerror (errno));
      free (r); return EXECUTION_FAILURE; }
  unsigned seq = ba_seq ();
  int rc = EXECUTION_SUCCESS;
  if (ba_send (fd, add ? AUDIT_ADD_RULE : AUDIT_DEL_RULE,
               NLM_F_ACK, r, len, seq) < 0
      || ba_wait_ack (fd, seq) < 0)
    { builtin_error ("%s: %s", add ? "add-rule" : "del-rule",
                     strerror (errno));
      rc = EXECUTION_FAILURE; }
  close (fd);
  free (r);
  return rc;
}

/* --- list-rules ---------------------------------------------------- */

/* Render one received audit_rule_data in canonical "-a action,filter ..." */
static void
ba_render_rule (const struct audit_rule_data *r)
{
  const char *act = (r->action == AUDIT_ALWAYS) ? "always"
                  : (r->action == AUDIT_NEVER)  ? "never" : "?";
  unsigned filt = r->flags & 0x7;
  const char *fname = filt == AUDIT_FILTER_TASK ? "task"
                    : filt == AUDIT_FILTER_EXIT ? "exit"
                    : filt == AUDIT_FILTER_USER ? "user"
                    : filt == AUDIT_FILTER_EXCLUDE ? "exclude" : "?";
  const char *flag = (r->flags & AUDIT_FILTER_PREPEND) ? "-A" : "-a";
  printf ("%s %s,%s", flag, act, fname);

  /* syscalls: list set bits unless every bit is set ('all'). */
  int all = 1;
  for (int i = 0; i < AUDIT_BITMASK_SIZE; i++)
    if (r->mask[i] != ~0U) { all = 0; break; }
  if (all)
    printf (" -S all");
  else
    {
      for (int nr = 0; nr < AUDIT_BITMASK_SIZE * 32; nr++)
        if (r->mask[nr / 32] & (1U << (nr % 32)))
          {
            const char *nm = NULL;
            for (const struct ba_sc *s = ba_syscalls; s->name; s++)
              if (s->nr == nr) { nm = s->name; break; }
            if (nm) printf (" -S %s", nm);
            else    printf (" -S %d", nr);
          }
    }

  /* fields */
  __u32 boff = 0;
  for (unsigned i = 0; i < r->field_count && i < AUDIT_MAX_FIELDS; i++)
    {
      unsigned ft = r->fields[i];
      if (ft == AUDIT_FILTERKEY)
        {
          unsigned l = r->values[i];
          printf (" -k %.*s", (int) l, r->buf + boff);
          boff += l;
          continue;
        }
      const char *fn = ft == AUDIT_LOGINUID ? "auid"
                     : ft == AUDIT_UID ? "uid" : ft == AUDIT_GID ? "gid"
                     : ft == AUDIT_EUID ? "euid" : ft == AUDIT_EGID ? "egid"
                     : ft == AUDIT_SUID ? "suid" : ft == AUDIT_SGID ? "sgid"
                     : ft == AUDIT_FSUID ? "fsuid" : ft == AUDIT_FSGID ? "fsgid"
                     : ft == AUDIT_PID ? "pid" : ft == AUDIT_PPID ? "ppid"
                     : ft == AUDIT_EXIT ? "exit" : ft == AUDIT_SUCCESS ? "success"
                     : ft == AUDIT_PERM ? "perm" : ft == AUDIT_ARCH ? "arch"
                     : ft == AUDIT_MSGTYPE ? "msgtype" : NULL;
      unsigned op = r->fieldflags[i] & AUDIT_OPERATORS;
      const char *ops = op == AUDIT_EQUAL ? "="
                      : op == AUDIT_NOT_EQUAL ? "!="
                      : op == AUDIT_LESS_THAN ? "<"
                      : op == AUDIT_GREATER_THAN ? ">"
                      : op == (AUDIT_LESS_THAN|AUDIT_EQUAL) ? "<="
                      : op == (AUDIT_GREATER_THAN|AUDIT_EQUAL) ? ">="
                      : op == AUDIT_BIT_MASK ? "&" : "=";
      if (fn) printf (" -F %s%s%u", fn, ops, r->values[i]);
      else    printf (" -F field%u%s%u", ft, ops, r->values[i]);
    }
  printf ("\n");
}

static int
ba_cmd_list_rules (void)
{
  int fd = ba_open ();
  if (fd < 0)
    { builtin_error ("list-rules: socket: %s", strerror (errno));
      return EXECUTION_FAILURE; }
  unsigned seq = ba_seq ();
  if (ba_send (fd, AUDIT_LIST_RULES, NLM_F_DUMP, NULL, 0, seq) < 0)
    { builtin_error ("list-rules: send: %s", strerror (errno));
      close (fd); return EXECUTION_FAILURE; }

  char buf[BA_BUFSZ];
  int n = 0, done = 0;
  while (!done)
    {
      ssize_t s = recv (fd, buf, sizeof buf, 0);
      if (s < 0)
        { if (errno == EINTR) continue;
          builtin_error ("list-rules: recv: %s", strerror (errno));
          close (fd); return EXECUTION_FAILURE; }
      for (struct nlmsghdr *h = (struct nlmsghdr *) buf;
           NLMSG_OK (h, (size_t) s); h = NLMSG_NEXT (h, s))
        {
          if (h->nlmsg_type == NLMSG_DONE) { done = 1; break; }
          if (h->nlmsg_type == NLMSG_ERROR)
            { struct nlmsgerr *e = (struct nlmsgerr *) NLMSG_DATA (h);
              if (e->error)
                { errno = -e->error;
                  builtin_error ("list-rules: kernel: %s", strerror (errno));
                  close (fd); return EXECUTION_FAILURE; }
              done = 1; break; }
          if (h->nlmsg_type == AUDIT_LIST_RULES)
            { ba_render_rule ((struct audit_rule_data *) NLMSG_DATA (h));
              n++; }
        }
    }
  close (fd);
  if (n == 0)
    printf ("No rules\n");
  return EXECUTION_SUCCESS;
}

/* --- run (self-polling consumer) ----------------------------------- */

static volatile sig_atomic_t ba_stop = 0;
static void ba_on_signal (int sig) { (void) sig; ba_stop = 1; }

static int
ba_cmd_run (long count, long seconds, const char *outpath)
{
  FILE *out = ba_open_out (outpath);
  if (!out)
    { builtin_error ("run: cannot open record file: %s", strerror (errno));
      return EXECUTION_FAILURE; }

  int fd = ba_open ();
  if (fd < 0)
    { builtin_error ("run: NETLINK_AUDIT socket: %s", strerror (errno));
      if (out != stdout) fclose (out);
      return EXECUTION_FAILURE; }

  /* Register as the audit daemon: pid=self, enabled=1. */
  struct audit_status st;
  memset (&st, 0, sizeof st);
  st.mask = AUDIT_STATUS_PID | AUDIT_STATUS_ENABLED;
  st.pid = (unsigned) getpid ();
  st.enabled = 1;
  unsigned seq = ba_seq ();
  if (ba_send (fd, AUDIT_SET, NLM_F_ACK, &st, sizeof st, seq) < 0
      || ba_wait_ack (fd, seq) < 0)
    { builtin_error ("run: register audit daemon: %s", strerror (errno));
      close (fd); if (out != stdout) fclose (out); return EXECUTION_FAILURE; }

  struct sigaction sa;
  memset (&sa, 0, sizeof sa);
  sa.sa_handler = ba_on_signal;
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);
  sigaction (SIGALRM, &sa, NULL);
  ba_stop = 0;

  time_t deadline = (seconds > 0) ? time (NULL) + seconds : 0;
  long emitted = 0;
  char buf[BA_BUFSZ];

  while (!ba_stop)
    {
      int tmo = 500;            /* ms; re-check deadline/stop periodically */
      if (deadline)
        {
          long rem = (long) (deadline - time (NULL));
          if (rem <= 0) break;
          if (rem * 1000 < tmo) tmo = (int) (rem * 1000);
        }
      struct pollfd pfd = { .fd = fd, .events = POLLIN };
      int pr = poll (&pfd, 1, tmo);
      if (pr < 0)
        { if (errno == EINTR) continue; break; }
      if (pr == 0)
        continue;
      ssize_t s = recv (fd, buf, sizeof buf, MSG_DONTWAIT);
      if (s < 0)
        { if (errno == EINTR || errno == EAGAIN) continue; break; }
      for (struct nlmsghdr *h = (struct nlmsghdr *) buf;
           NLMSG_OK (h, (size_t) s); h = NLMSG_NEXT (h, s))
        {
          int t = h->nlmsg_type;
          if (t == NLMSG_DONE || t == NLMSG_ERROR || t == NLMSG_NOOP)
            continue;
          /* Audit event messages carry a text payload. */
          char *payload = (char *) NLMSG_DATA (h);
          size_t plen = NLMSG_PAYLOAD (h, 0);
          /* NUL-terminate within our buffer copy region (safe: payload
           * sits inside `buf`, and there is slack after NLMSG_OK ran). */
          char tmpc[BA_BUFSZ];
          if (plen >= sizeof tmpc) plen = sizeof tmpc - 1;
          memcpy (tmpc, payload, plen);
          tmpc[plen] = '\0';
          ba_emit_record (out, t, tmpc);
          emitted++;
          if (count > 0 && emitted >= count) { ba_stop = 1; break; }
        }
      fflush (out);
    }

  /* Best-effort: deregister as the audit daemon on the way out. */
  memset (&st, 0, sizeof st);
  st.mask = AUDIT_STATUS_PID;
  st.pid = 0;
  seq = ba_seq ();
  ba_send (fd, AUDIT_SET, NLM_F_ACK, &st, sizeof st, seq);
  ba_wait_ack (fd, seq);

  close (fd);
  if (out != stdout) fclose (out);
  printf ("%ld\n", emitted);     /* records emitted */
  return EXECUTION_SUCCESS;
}

/* ----------------------------------------------------------------- */
/* Builtin entry                                                     */
/* ----------------------------------------------------------------- */

static void
ba_collect (WORD_LIST *list, char **argv, int *argc, int max)
{
  int n = 0;
  for (WORD_LIST *p = list; p && n < max; p = p->next)
    argv[n++] = p->word->word;
  *argc = n;
}

int
audit_builtin (WORD_LIST *list)
{
  if (!list)
    { builtin_usage (); return EX_USAGE; }

  char *argv[64];
  int argc = 0;
  ba_collect (list, argv, &argc, 64);
  const char *cmd = argv[0];

  if (!strcmp (cmd, "--version"))
    { printf ("audit (bash-os AUDIT-6.2) netlink-audit consumer; "
              "pinned AUDIT_* v1\n"); return EXECUTION_SUCCESS; }
  if (!strcmp (cmd, "-h") || !strcmp (cmd, "--help"))
    { builtin_usage (); return EXECUTION_SUCCESS; }

  if (!strcmp (cmd, "typename"))
    {
      if (argc != 2) { builtin_error ("typename NUM"); return EX_USAGE; }
      const char *nm = ba_type_name (atoi (argv[1]));
      printf ("%s\n", nm ? nm : "UNKNOWN");
      return nm ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (!strcmp (cmd, "typenum"))
    {
      if (argc != 2) { builtin_error ("typenum NAME"); return EX_USAGE; }
      int num = ba_type_num (argv[1]);
      if (num < 0) { builtin_error ("typenum: not in pinned set: %s", argv[1]);
        return EXECUTION_FAILURE; }
      printf ("%d\n", num);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "decode-text"))
    {
      /* decode-text TYPE PAYLOAD [-o FILE] */
      if (argc < 3) { builtin_error ("decode-text TYPE PAYLOAD [-o FILE]");
        return EX_USAGE; }
      const char *outpath = NULL;
      if (argc >= 5 && !strcmp (argv[3], "-o"))
        outpath = argv[4];
      FILE *out = ba_open_out (outpath);
      if (!out) { builtin_error ("decode-text: open out: %s", strerror (errno));
        return EXECUTION_FAILURE; }
      ba_emit_record (out, atoi (argv[1]), argv[2]);
      if (out != stdout) fclose (out);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "status"))
    {
      const char *var = NULL;
      if (argc >= 3 && !strcmp (argv[1], "-V")) var = argv[2];
      else if (argc != 1) { builtin_error ("status [-V VAR]"); return EX_USAGE; }
      return ba_cmd_status (var);
    }
  if (!strcmp (cmd, "set-enabled"))
    {
      if (argc != 2) { builtin_error ("set-enabled 0|1|2"); return EX_USAGE; }
      return ba_cmd_set_enabled (argv[1]);
    }
  if (!strcmp (cmd, "add-rule"))
    return ba_cmd_rule (1, argv + 1, argc - 1);
  if (!strcmp (cmd, "del-rule"))
    return ba_cmd_rule (0, argv + 1, argc - 1);
  if (!strcmp (cmd, "list-rules"))
    return ba_cmd_list_rules ();

  if (!strcmp (cmd, "run"))
    {
      long count = 0, seconds = 0;
      const char *outpath = NULL;
      for (int i = 1; i < argc; i++)
        {
          if (!strcmp (argv[i], "-c") && i + 1 < argc) count = atol (argv[++i]);
          else if (!strcmp (argv[i], "-t") && i + 1 < argc) seconds = atol (argv[++i]);
          else if (!strcmp (argv[i], "-o") && i + 1 < argc) outpath = argv[++i];
          else { builtin_error ("run: bad arg: %s", argv[i]); return EX_USAGE; }
        }
      return ba_cmd_run (count, seconds, outpath);
    }

  builtin_error ("unknown verb: %s (try status/set-enabled/add-rule/"
                 "del-rule/list-rules/run/decode-text/typename/typenum)", cmd);
  return EX_USAGE;
}

char *audit_doc[] = {
  "NETLINK_AUDIT consumer for the bash-os audit engine (AUDIT-6.2).",
  "",
  "    audit status [-V VAR]         AUDIT_GET; print or bind",
  "        <VAR>_{enabled,pid,rate_limit,backlog_limit,lost,backlog,failure}.",
  "    audit set-enabled 0|1|2       AUDIT_SET enabled (CAP_AUDIT_WRITE).",
  "    audit add-rule PRIO ACTION FILTER SYSCALLS FIELDS KEY",
  "    audit del-rule PRIO ACTION FILTER SYSCALLS FIELDS KEY",
  "        Program/unprogram one rule. Args are the canonical TSV columns",
  "        from lib/auditctl-rules.sh (CAP_AUDIT_WRITE). Watch-style -F",
  "        path/dir/name reject (use a path watch).",
  "    audit list-rules              AUDIT_LIST_RULES; render canonical.",
  "    audit run [-c N] [-t SECS] [-o FILE]",
  "        Self-poll the netlink fd as the audit daemon; append decoded",
  "        records (lib/audit-records.sh TSV) to FILE. Stop on N records,",
  "        SECS elapsed, or SIGINT/SIGTERM. Prints the emitted count.",
  "    audit decode-text TYPE PAYLOAD [-o FILE]",
  "        Deserialize one raw kernel audit message (text) → TSV record.",
  "    audit typename NUM | typenum NAME   pinned AUDIT_* map.",
  "",
  "Record format and the pinned AUDIT_* set are defined in",
  "lib/audit-records.sh; out-of-set types record as UNKNOWN (no drop).",
  (char *) NULL
};

struct builtin audit_struct = {
  "audit",
  audit_builtin,
  BUILTIN_ENABLED,
  audit_doc,
  "audit status|set-enabled|add-rule|del-rule|list-rules|run|decode-text|typename|typenum ARGS",
  0
};
