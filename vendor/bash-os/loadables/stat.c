/* SPDX-License-Identifier: MIT */
/* stat.c — stat(1) as a bash builtin, with the GNU coreutils surface.
 *
 * Written for bash-os from the documented interface of coreutils stat(1):
 * its format directives, the default and terse layouts, -L and --printf.
 * Scripts written for coreutils — `stat -c%s FILE` above all — work unchanged
 * with an empty PATH. It is not derived from GNU bash's own stat loadable
 * (which loads an array and is GPL); the -A NAME array load here is a small
 * convenience that uses the same key names, so a script written for that
 * interface keeps working.
 *
 *   stat [-L] [-t] [-c FORMAT | --format=FORMAT | --printf=FORMAT]
 *        [-A NAME] FILE...
 *
 * Copyright (c) 2026 bash_linux contributors
 * MIT License — full text in the repository's LICENSE file. The combined
 * binary is a derivative work of bash and is governed by GPL-3+ (bash's
 * licence); MIT for this source file is GPL-3+-compatible.
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include "loadables.h"
#include "bashgetopt.h"

/* coreutils 9.x layouts */
#define STAT_FMT_DEFAULT \
  "  File: %N\n" \
  "  Size: %-10s\tBlocks: %-10b IO Block: %-6o %F\n" \
  "Device: %Hd,%Ld\tInode: %-10i  Links: %h\n" \
  "Access: (%04a/%10.10A)  Uid: (%5u/%8U)   Gid: (%5g/%8G)\n" \
  "Access: %x\nModify: %y\nChange: %z\n Birth: %w\n"
#define STAT_FMT_DEVICE \
  "  File: %N\n" \
  "  Size: %-10s\tBlocks: %-10b IO Block: %-6o %F\n" \
  "Device: %Hd,%Ld\tInode: %-10i  Links: %-5h Device type: %Hr,%Lr\n" \
  "Access: (%04a/%10.10A)  Uid: (%5u/%8U)   Gid: (%5g/%8G)\n" \
  "Access: %x\nModify: %y\nChange: %z\n Birth: %w\n"
#define STAT_FMT_TERSE "%n %s %b %f %u %g %D %i %h %t %T %X %Y %Z %W %o\n"

struct stat_file {
  const char *name;
  struct stat st;
  char link[PATH_MAX + 1];      /* target if NAME is a symlink we did not follow */
  int is_link;
  int quote_always;             /* %N: coreutils always quotes in a user format */
  int has_btime;                /* birth time, when the kernel and filesystem report one */
  int64_t bsec; long bnsec;
};

/* Birth time comes from statx(2). Declared privately, with the kernel's
   layout, so the same code builds against glibc and musl of any age. */
#ifdef SYS_statx
struct stat_x_ts { int64_t sec; uint32_t nsec; int32_t pad; };
struct stat_x {
  uint32_t mask, blksize; uint64_t attributes; uint32_t nlink, uid, gid; uint16_t mode, spare0;
  uint64_t ino, size, blocks, attributes_mask;
  struct stat_x_ts atime, btime, ctime, mtime;
  uint64_t rest[16];
};
#define STAT_X_BTIME 0x800U
#define STAT_X_NOFOLLOW 0x100
#endif

static void
stat_birth_time (struct stat_file *f, int follow)
{
#ifdef SYS_statx
  struct stat_x x;
  memset (&x, 0, sizeof x);
  if (syscall (SYS_statx, AT_FDCWD, f->name, follow ? 0 : STAT_X_NOFOLLOW, STAT_X_BTIME, &x) == 0
      && (x.mask & STAT_X_BTIME))
    { f->has_btime = 1; f->bsec = x.btime.sec; f->bnsec = x.btime.nsec; }
#endif
}

static const char *
stat_type_name (const struct stat *st)
{
  if (S_ISREG (st->st_mode))  return st->st_size ? "regular file" : "regular empty file";
  if (S_ISDIR (st->st_mode))  return "directory";
  if (S_ISLNK (st->st_mode))  return "symbolic link";
  if (S_ISCHR (st->st_mode))  return "character special file";
  if (S_ISBLK (st->st_mode))  return "block special file";
  if (S_ISFIFO (st->st_mode)) return "fifo";
  if (S_ISSOCK (st->st_mode)) return "socket";
  return "weird file";
}

static void
stat_mode_string (mode_t m, char out[11])
{
  out[0] = S_ISDIR (m) ? 'd' : S_ISLNK (m) ? 'l' : S_ISCHR (m) ? 'c' : S_ISBLK (m) ? 'b'
         : S_ISFIFO (m) ? 'p' : S_ISSOCK (m) ? 's' : '-';
  out[1] = (m & S_IRUSR) ? 'r' : '-';
  out[2] = (m & S_IWUSR) ? 'w' : '-';
  out[3] = (m & S_ISUID) ? ((m & S_IXUSR) ? 's' : 'S') : ((m & S_IXUSR) ? 'x' : '-');
  out[4] = (m & S_IRGRP) ? 'r' : '-';
  out[5] = (m & S_IWGRP) ? 'w' : '-';
  out[6] = (m & S_ISGID) ? ((m & S_IXGRP) ? 's' : 'S') : ((m & S_IXGRP) ? 'x' : '-');
  out[7] = (m & S_IROTH) ? 'r' : '-';
  out[8] = (m & S_IWOTH) ? 'w' : '-';
  out[9] = (m & S_ISVTX) ? ((m & S_IXOTH) ? 't' : 'T') : ((m & S_IXOTH) ? 'x' : '-');
  out[10] = 0;
}

static void
stat_time_string (char *out, size_t n, time_t sec, long nsec)
{
  struct tm tm; char date[40], zone[8];
  localtime_r (&sec, &tm);
  strftime (date, sizeof date, "%Y-%m-%d %H:%M:%S", &tm);
  strftime (zone, sizeof zone, "%z", &tm);
  snprintf (out, n, "%s.%09ld %s", date, nsec, zone);
}

/* %N: coreutils single-quotes the name in a user-supplied format, and prints
   it bare in its own default layout. */
static void
stat_quote_name (char *out, size_t n, const char *name, int quote)
{
  const char *p; size_t o = 0;
  if (quote == 0)
    { snprintf (out, n, "%s", name); return; }
  if (o < n - 1) out[o++] = '\'';
  for (p = name; *p && o < n - 6; p++)
    {
      if (*p == '\'') { memcpy (out + o, "'\\''", 4); o += 4; }
      else out[o++] = *p;
    }
  if (o < n - 1) out[o++] = '\'';
  out[o] = 0;
}

/* The mount point of PATH: walk up until the parent is on another device. */
static int
stat_mount_point (const char *path, char *out, size_t n)
{
  char cur[PATH_MAX], parent[PATH_MAX]; struct stat a, b; char *sl;
  if (realpath (path, cur) == 0) return -1;
  for (;;)
    {
      if (stat (cur, &a) < 0) return -1;
      if (strcmp (cur, "/") == 0) break;
      strcpy (parent, cur);
      sl = strrchr (parent, '/');
      if (sl == parent) strcpy (parent, "/"); else *sl = 0;
      if (stat (parent, &b) < 0) return -1;
      if (a.st_dev != b.st_dev || a.st_ino == b.st_ino) break;
      strcpy (cur, parent);
    }
  snprintf (out, n, "%s", cur);
  return 0;
}

/* Expand one directive character (plus the H/L device prefix) into VAL. */
static int
stat_directive (const struct stat_file *f, int prefix, int c, char *val, size_t n)
{
  const struct stat *st = &f->st; char mode[11];
  struct passwd *pw; struct group *gr;
  switch (c)
    {
    case 'a': snprintf (val, n, "%lo", (unsigned long)(st->st_mode & 07777)); break;
    case 'A': stat_mode_string (st->st_mode, mode); snprintf (val, n, "%s", mode); break;
    case 'b': snprintf (val, n, "%" PRIuMAX, (uintmax_t) st->st_blocks); break;
    case 'B': snprintf (val, n, "512"); break;
    case 'd':
      if (prefix == 'H')      snprintf (val, n, "%u", major (st->st_dev));
      else if (prefix == 'L') snprintf (val, n, "%u", minor (st->st_dev));
      else                    snprintf (val, n, "%" PRIuMAX, (uintmax_t) st->st_dev);
      break;
    case 'D': snprintf (val, n, "%" PRIxMAX, (uintmax_t) st->st_dev); break;
    case 'f': snprintf (val, n, "%lx", (unsigned long) st->st_mode); break;
    case 'F': snprintf (val, n, "%s", stat_type_name (st)); break;
    case 'g': snprintf (val, n, "%lu", (unsigned long) st->st_gid); break;
    case 'G': gr = getgrgid (st->st_gid);
      if (gr) snprintf (val, n, "%s", gr->gr_name); else snprintf (val, n, "%lu", (unsigned long) st->st_gid);
      break;
    case 'h': snprintf (val, n, "%" PRIuMAX, (uintmax_t) st->st_nlink); break;
    case 'i': snprintf (val, n, "%" PRIuMAX, (uintmax_t) st->st_ino); break;
    case 'm': if (stat_mount_point (f->name, val, n) < 0) snprintf (val, n, "?"); break;
    case 'n': snprintf (val, n, "%s", f->name); break;
    case 'N':
      {
        char q[PATH_MAX + 8], t[PATH_MAX + 8];
        stat_quote_name (q, sizeof q, f->name, f->quote_always);
        if (f->is_link) { stat_quote_name (t, sizeof t, f->link, f->quote_always); snprintf (val, n, "%s -> %s", q, t); }
        else snprintf (val, n, "%s", q);
      }
      break;
    case 'o': snprintf (val, n, "%" PRIuMAX, (uintmax_t) st->st_blksize); break;
    case 'r':
      if (prefix == 'H')      snprintf (val, n, "%u", major (st->st_rdev));
      else if (prefix == 'L') snprintf (val, n, "%u", minor (st->st_rdev));
      else                    snprintf (val, n, "%" PRIuMAX, (uintmax_t) st->st_rdev);
      break;
    case 's': snprintf (val, n, "%" PRIdMAX, (intmax_t) st->st_size); break;
    case 't': snprintf (val, n, "%x", major (st->st_rdev)); break;
    case 'T': snprintf (val, n, "%x", minor (st->st_rdev)); break;
    case 'u': snprintf (val, n, "%lu", (unsigned long) st->st_uid); break;
    case 'U': pw = getpwuid (st->st_uid);
      if (pw) snprintf (val, n, "%s", pw->pw_name); else snprintf (val, n, "%lu", (unsigned long) st->st_uid);
      break;
    case 'w': if (f->has_btime) stat_time_string (val, n, (time_t) f->bsec, f->bnsec); else snprintf (val, n, "-"); break;
    case 'W': snprintf (val, n, "%" PRIdMAX, f->has_btime ? (intmax_t) f->bsec : (intmax_t) 0); break;
    case 'x': stat_time_string (val, n, st->st_atim.tv_sec, st->st_atim.tv_nsec); break;
    case 'X': snprintf (val, n, "%" PRIdMAX, (intmax_t) st->st_atim.tv_sec); break;
    case 'y': stat_time_string (val, n, st->st_mtim.tv_sec, st->st_mtim.tv_nsec); break;
    case 'Y': snprintf (val, n, "%" PRIdMAX, (intmax_t) st->st_mtim.tv_sec); break;
    case 'z': stat_time_string (val, n, st->st_ctim.tv_sec, st->st_ctim.tv_nsec); break;
    case 'Z': snprintf (val, n, "%" PRIdMAX, (intmax_t) st->st_ctim.tv_sec); break;
    case 'C': snprintf (val, n, "?"); break;          /* security context: none */
    case '%': snprintf (val, n, "%%"); break;
    default: return -1;
    }
  return 0;
}

static void
stat_put_padded (const char *val, int left, int zero, int width)
{
  int len = (int) strlen (val), pad = width > len ? width - len : 0, i;
  if (!left)
    for (i = 0; i < pad; i++)
      putchar (zero && ISDIGIT ((unsigned char) val[0]) ? '0' : ' ');
  fputs (val, stdout);
  if (left)
    for (i = 0; i < pad; i++) putchar (' ');
}

/* Print FMT for F. ESCAPES: interpret backslash sequences (--printf).
   Returns -1 on an invalid directive. */
static int
stat_print (const struct stat_file *f, const char *fmt, int escapes)
{
  const char *p = fmt; char val[PATH_MAX * 2 + 32];
  while (*p)
    {
      if (*p == '%')
        {
          int left = 0, zero = 0, width = 0, prefix = 0;
          const char *start = p++;
          while (*p && strchr ("-#0+ '", *p)) { if (*p == '-') left = 1; if (*p == '0') zero = 1; p++; }
          while (ISDIGIT ((unsigned char) *p)) width = width * 10 + (*p++ - '0');
          if (*p == '.') { p++; while (ISDIGIT ((unsigned char) *p)) p++; }   /* precision: accepted, ignored */
          if (*p == 'H' || *p == 'L') prefix = *p++;
          if (*p == 0) { fputs (start, stdout); break; }
          if (stat_directive (f, prefix, *p, val, sizeof val) < 0)
            {
              builtin_error ("%.*s: invalid directive", (int)(p - start + 1), start);
              return -1;
            }
          stat_put_padded (val, left, zero, width);
          p++;
        }
      else if (*p == '\\' && escapes)
        {
          p++;
          switch (*p)
            {
            case 'n': putchar ('\n'); p++; break;
            case 't': putchar ('\t'); p++; break;
            case 'r': putchar ('\r'); p++; break;
            case 'a': putchar ('\a'); p++; break;
            case 'b': putchar ('\b'); p++; break;
            case 'f': putchar ('\f'); p++; break;
            case 'v': putchar ('\v'); p++; break;
            case '\\': putchar ('\\'); p++; break;
            case '"': putchar ('"'); p++; break;
            case 'x':
              {
                int v = 0, k = 0;
                p++;
                while (k < 2 && ISXDIGIT ((unsigned char) *p)) { v = v * 16 + (ISDIGIT ((unsigned char)*p) ? *p - '0' : (*p | 32) - 'a' + 10); p++; k++; }
                if (k) putchar (v); else fputs ("\\x", stdout);
              }
              break;
            case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7':
              {
                int v = 0, k = 0;
                while (k < 3 && *p >= '0' && *p <= '7') { v = v * 8 + (*p - '0'); p++; k++; }
                putchar (v & 0xff);
              }
              break;
            case 0: putchar ('\\'); break;
            default: putchar ('\\'); putchar (*p); p++; break;
            }
        }
      else
        putchar (*p++);
    }
  return 0;
}

static int
stat_load_array (const char *aname, const struct stat_file *f)
{
  SHELL_VAR *v; char b[PATH_MAX + 32]; char mode[11];
  const struct stat *st = &f->st;
  v = find_variable (aname);
  if (v == 0)
    v = make_new_assoc_variable ((char *) aname);
  else if (assoc_p (v) == 0)
    { builtin_error ("%s: not an associative array", aname); return -1; }
  if (v == 0) return -1;
  assoc_flush (assoc_cell (v));
#define STAT_SET(key, ...) do { snprintf (b, sizeof b, __VA_ARGS__); \
    if (bind_assoc_variable (v, (char *) aname, savestring (key), b, ASS_FORCE) == 0) return -1; } while (0)
  STAT_SET ("name", "%s", f->name);
  STAT_SET ("device", "%" PRIuMAX, (uintmax_t) st->st_dev);
  STAT_SET ("inode", "%" PRIuMAX, (uintmax_t) st->st_ino);
  STAT_SET ("type", "%s", stat_type_name (st));
  STAT_SET ("mode", "%lo", (unsigned long) st->st_mode);
  stat_mode_string (st->st_mode, mode);
  STAT_SET ("perms", "%s", mode);
  STAT_SET ("nlink", "%" PRIuMAX, (uintmax_t) st->st_nlink);
  STAT_SET ("uid", "%lu", (unsigned long) st->st_uid);
  STAT_SET ("gid", "%lu", (unsigned long) st->st_gid);
  STAT_SET ("rdev", "%" PRIuMAX, (uintmax_t) st->st_rdev);
  STAT_SET ("size", "%" PRIdMAX, (intmax_t) st->st_size);
  STAT_SET ("blksize", "%" PRIuMAX, (uintmax_t) st->st_blksize);
  STAT_SET ("blocks", "%" PRIuMAX, (uintmax_t) st->st_blocks);
  STAT_SET ("atime", "%" PRIdMAX, (intmax_t) st->st_atim.tv_sec);
  STAT_SET ("mtime", "%" PRIdMAX, (intmax_t) st->st_mtim.tv_sec);
  STAT_SET ("ctime", "%" PRIdMAX, (intmax_t) st->st_ctim.tv_sec);
  STAT_SET ("link", "%s", f->is_link ? f->link : "");
#undef STAT_SET
  return 0;
}

int
stat_builtin (WORD_LIST *list)
{
  WORD_LIST *l; const char *fmt = 0, *aname = 0; int escapes = 0, follow = 0, terse = 0;
  int status = EXECUTION_SUCCESS;

  for (l = list; l; l = l->next)
    {
      char *w = l->word->word, *p; int consumed_next = 0;
      if (w[0] != '-' || w[1] == 0) break;
      if (strcmp (w, "--") == 0) { l = l->next; break; }
      if (strncmp (w, "--format=", 9) == 0) { fmt = w + 9; escapes = 0; continue; }
      if (strncmp (w, "--printf=", 9) == 0) { fmt = w + 9; escapes = 1; continue; }
      if (strcmp (w, "--dereference") == 0) { follow = 1; continue; }
      if (strcmp (w, "--terse") == 0) { terse = 1; continue; }
      if (w[1] == '-') { builtin_error ("%s: invalid option", w); builtin_usage (); return EX_USAGE; }
      for (p = w + 1; *p && consumed_next == 0; p++)
        switch (*p)
          {
          case 'L': follow = 1; break;
          case 't': terse = 1; break;
          case 'c': case 'A':
            {
              char *arg;
              if (p[1]) arg = p + 1;
              else if (l->next) { l = l->next; arg = l->word->word; }
              else { builtin_error ("-%c: option requires an argument", *p); builtin_usage (); return EX_USAGE; }
              if (*p == 'c') { fmt = arg; escapes = 0; } else aname = arg;
              consumed_next = 1;
            }
            break;
          default:
            builtin_error ("-%c: invalid option", *p); builtin_usage (); return EX_USAGE;
          }
    }
  if (l == 0) { builtin_error ("missing operand"); builtin_usage (); return EX_USAGE; }
  if (aname && legal_identifier ((char *) aname) == 0)
    { sh_invalidid ((char *) aname); return EX_USAGE; }

  for (; l; l = l->next)
    {
      struct stat_file f; int r; const char *use;
      memset (&f, 0, sizeof f);
      f.name = l->word->word;
      r = follow ? stat (f.name, &f.st) : lstat (f.name, &f.st);
      if (r < 0)
        {
          builtin_error ("cannot stat '%s': %s", f.name, strerror (errno));
          status = EXECUTION_FAILURE;
          continue;
        }
      if (S_ISLNK (f.st.st_mode))
        {
          ssize_t k = readlink (f.name, f.link, sizeof f.link - 1);
          if (k >= 0) { f.link[k] = 0; f.is_link = 1; }
        }
      stat_birth_time (&f, follow);
      f.quote_always = fmt != 0;
      if (aname)
        {
          if (stat_load_array (aname, &f) < 0) { status = EXECUTION_FAILURE; }
          continue;
        }
      use = fmt ? fmt : terse ? STAT_FMT_TERSE
          : (S_ISCHR (f.st.st_mode) || S_ISBLK (f.st.st_mode)) ? STAT_FMT_DEVICE : STAT_FMT_DEFAULT;
      if (stat_print (&f, use, escapes) < 0) return EXECUTION_FAILURE;
      if (fmt && escapes == 0) putchar ('\n');     /* -c/--format: newline after each use */
    }
  fflush (stdout);
  return sh_chkwrite (status);
}

char *stat_doc[] = {
  "Display file status, GNU coreutils style.",
  "",
  "Print the status of each FILE, from lstat(2) — or stat(2) with -L, so a",
  "symbolic link is followed. With no format the coreutils layout is used;",
  "-t prints the terse one-line form.",
  "",
  "  -c FORMAT, --format=FORMAT  print FORMAT, then a newline, for each FILE",
  "  --printf=FORMAT             like -c, but interpret \\n \\t \\\\ \\NNN \\xHH",
  "                              escapes and print no trailing newline",
  "  -L, --dereference           follow symbolic links",
  "  -t, --terse                 terse form: %n %s %b %f %u %g %D %i %h %t %T %X %Y %Z %W %o",
  "  -A NAME                     load the status into associative array NAME",
  "                              (keys: name device inode type mode perms nlink",
  "                              uid gid rdev size blksize blocks atime mtime",
  "                              ctime link) instead of printing",
  "",
  "Directives take an optional - (left-align), 0 (zero-pad) and width:",
  "  %a octal perms   %A symbolic perms   %b blocks       %B block size (512)",
  "  %d device        %D device (hex)     %Hd/%Ld major/minor of device",
  "  %f raw mode hex  %F file type        %g gid          %G group name",
  "  %h hard links    %i inode            %m mount point  %n name",
  "  %N quoted name, with -> target for a link            %o I/O block size",
  "  %s size          %t/%T major/minor of rdev (hex)     %Hr/%Lr (decimal)",
  "  %u uid           %U user name        %w/%W birth time (- / 0 if unknown)",
  "  %x/%X atime      %y/%Y mtime         %z/%Z ctime (human / epoch)   %% literal",
  "",
  "Exit status: 0, or 1 if any FILE could not be stat'ed.",
  (char *)NULL
};

struct builtin stat_struct = {
  "stat", stat_builtin, BUILTIN_ENABLED, stat_doc,
  "stat [-L] [-t] [-c FORMAT | --printf=FORMAT] [-A NAME] FILE...", 0
};
