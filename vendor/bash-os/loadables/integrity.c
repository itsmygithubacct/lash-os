/* SPDX-License-Identifier: MIT */
/* integrity.c - fd-pinned manifest emitter for bl-integrity.
 *
 * The shell wrapper owns config, signing, and UX. This builtin owns the
 * security-sensitive inner loop: walk selected paths under a root fd, keep
 * file descriptors pinned while collecting metadata and hashes, and emit the
 * existing bl-integrity manifest-v2 rows.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "_mbedtls_sha256.h"
#include "_monocypher_monocypher.h"
#include "loadables.h"

#ifndef O_CLOEXEC
#  define O_CLOEXEC 02000000
#endif
#ifndef O_NOFOLLOW
#  define O_NOFOLLOW 00400000
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW 0x100
#endif

typedef struct {
  char **v;
  size_t n;
  size_t cap;
} bi_vec;

static void
bi_vec_free (bi_vec *xs)
{
  if (!xs)
    return;
  for (size_t i = 0; i < xs->n; i++)
    free (xs->v[i]);
  free (xs->v);
  xs->v = NULL;
  xs->n = xs->cap = 0;
}

static char *
bi_xstrdup (const char *s)
{
  size_t n = strlen (s);
  char *p = malloc (n + 1);
  if (!p)
    return NULL;
  memcpy (p, s, n + 1);
  return p;
}

static int
bi_vec_push (bi_vec *xs, char *s)
{
  if (xs->n == xs->cap)
    {
      if (xs->cap > SIZE_MAX / 2 / sizeof *xs->v) return -1;
      size_t nc = xs->cap ? xs->cap * 2 : 64;
      char **nv = realloc (xs->v, nc * sizeof *nv);
      if (!nv)
        return -1;
      xs->v = nv;
      xs->cap = nc;
    }
  xs->v[xs->n++] = s;
  return 0;
}

static int
bi_vec_push_dup (bi_vec *xs, const char *s)
{
  char *p = bi_xstrdup (s);
  if (!p)
    return -1;
  if (bi_vec_push (xs, p) < 0)
    {
      free (p);
      return -1;
    }
  return 0;
}

static int
bi_strcmp_qsort (const void *a, const void *b)
{
  const char *const *sa = a;
  const char *const *sb = b;
  return strcmp (*sa, *sb);
}

static void
bi_vec_sort (bi_vec *xs)
{
  if (xs->n > 1)
    qsort (xs->v, xs->n, sizeof xs->v[0], bi_strcmp_qsort);
}

static int
bi_has_bad_field_byte (const char *s)
{
  for (const unsigned char *p = (const unsigned char *) s; *p; p++)
    if (*p == '\n' || *p == '\t')
      return 1;
  return 0;
}

static int
bi_rel_from_abs (const char *path, char **out)
{
  const char *p;

  if (!path || path[0] != '/')
    {
      builtin_error ("path must be absolute: %s", path ? path : "");
      return -1;
    }
  if (bi_has_bad_field_byte (path))
    {
      builtin_error ("path cannot contain tab/newline: %s", path);
      return -1;
    }
  if (strstr (path, "/../") || strcmp (path, "/..") == 0
      || strncmp (path, "/../", 4) == 0)
    {
      builtin_error ("path cannot contain traversal: %s", path);
      return -1;
    }

  p = path;
  while (*p == '/')
    p++;
  *out = bi_xstrdup (p);
  return *out ? 0 : -1;
}

static char *
bi_join_rel (const char *a, const char *b)
{
  size_t na = strlen (a);
  size_t nb = strlen (b);
  size_t need = na + (na ? 1 : 0) + nb + 1;
  char *out = malloc (need);
  if (!out)
    return NULL;
  if (na)
    snprintf (out, need, "%s/%s", a, b);
  else
    snprintf (out, need, "%s", b);
  return out;
}

static int
bi_excluded (const bi_vec *excludes, const char *rel)
{
  for (size_t i = 0; i < excludes->n; i++)
    {
      const char *pat = excludes->v[i];
      while (*pat == '/')
        pat++;
      if (fnmatch (pat, rel, 0) == 0)
        return 1;
    }
  return 0;
}

static int
bi_open_root (const char *root)
{
  int fd = open (root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0 && errno == EINVAL)
    fd = open (root, O_RDONLY | O_DIRECTORY);
  if (fd >= 0)
    {
      int flags = fcntl (fd, F_GETFD);
      if (flags >= 0)
        (void) fcntl (fd, F_SETFD, flags | FD_CLOEXEC);
    }
  return fd;
}

static int
bi_open_parent (int rootfd, const char *rel, int *parent_out, char **base_out)
{
  char *tmp, *save = NULL, *tok, *next;
  int fd;

  tmp = bi_xstrdup (rel);
  if (!tmp)
    return -1;
  fd = dup (rootfd);
  if (fd < 0)
    {
      free (tmp);
      return -1;
    }

  tok = strtok_r (tmp, "/", &save);
  if (!tok)
    {
      *parent_out = fd;
      *base_out = bi_xstrdup ("");
      free (tmp);
      if (*base_out)
        return 0;
      close (fd);
      return -1;
    }

  for (;;)
    {
      next = strtok_r (NULL, "/", &save);
      if (!next)
        break;
      int nfd = openat (fd, tok, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
      if (nfd < 0)
        {
          int saved = errno;
          close (fd);
          free (tmp);
          errno = saved;
          return -1;
        }
      close (fd);
      fd = nfd;
      tok = next;
    }

  *parent_out = fd;
  *base_out = bi_xstrdup (tok);
  free (tmp);
  if (!*base_out)
    {
      close (fd);
      return -1;
    }
  return 0;
}

static int bi_collect_rel (int rootfd, const char *rel, const bi_vec *excludes,
                           bi_vec *paths);

static int
bi_collect_dir_fd (int rootfd, int dirfd, const char *rel, const bi_vec *excludes,
                   bi_vec *paths)
{
  int dupfd = dup (dirfd);
  DIR *dir;
  struct dirent *de;

  if (dupfd < 0)
    return -1;
  dir = fdopendir (dupfd);
  if (!dir)
    {
      int saved = errno;
      close (dupfd);
      errno = saved;
      return -1;
    }

  while ((de = readdir (dir)) != NULL)
    {
      char *child;
      if (strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0)
        continue;
      if (bi_has_bad_field_byte (de->d_name))
        continue;
      child = bi_join_rel (rel, de->d_name);
      if (!child)
        {
          closedir (dir);
          return -1;
        }
      if (bi_collect_rel (rootfd, child, excludes, paths) < 0)
        {
          free (child);
          closedir (dir);
          return -1;
        }
      free (child);
    }
  closedir (dir);
  return 0;
}

static int
bi_collect_rel (int rootfd, const char *rel, const bi_vec *excludes,
                bi_vec *paths)
{
  int parent = -1;
  char *base = NULL;
  struct stat st;
  int rc = 0;

  if (rel[0] == '\0')
    {
      int dfd = dup (rootfd);
      if (dfd < 0)
        return -1;
      rc = bi_collect_dir_fd (rootfd, dfd, "", excludes, paths);
      close (dfd);
      return rc;
    }

  if (bi_open_parent (rootfd, rel, &parent, &base) < 0)
    return -1;
  if (fstatat (parent, base, &st, AT_SYMLINK_NOFOLLOW) < 0)
    {
      close (parent);
      free (base);
      return 0;                   /* Missing paths are ignored like the shell wrapper. */
    }

  if (S_ISREG (st.st_mode) || S_ISLNK (st.st_mode))
    {
      if (!bi_excluded (excludes, rel))
        rc = bi_vec_push_dup (paths, rel);
    }
  else if (S_ISDIR (st.st_mode))
    {
      int dfd = openat (parent, base, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
      if (dfd >= 0)
        {
      rc = bi_collect_dir_fd (rootfd, dfd, rel, excludes, paths);
          close (dfd);
        }
    }

  close (parent);
  free (base);
  return rc;
}

static void
bi_hex (const unsigned char *in, size_t n, char *out)
{
  static const char h[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++)
    {
      out[i * 2] = h[in[i] >> 4];
      out[i * 2 + 1] = h[in[i] & 15];
    }
  out[n * 2] = '\0';
}

static int
bi_hash_fd (int fd, char sha_hex[65], char blake_hex[129])
{
  mbedtls_sha256_context sha;
  crypto_blake2b_ctx blake;
  unsigned char buf[8192];
  unsigned char sha_out[32];
  unsigned char blake_out[64];
  ssize_t n;

  if (lseek (fd, 0, SEEK_SET) < 0)
    return -1;

  mbedtls_sha256_init (&sha);
  if (mbedtls_sha256_starts (&sha, 0) != 0)
    {
      mbedtls_sha256_free (&sha);
      return -1;
    }
  crypto_blake2b_init (&blake, 64);

  while ((n = read (fd, buf, sizeof buf)) > 0)
    {
      if (mbedtls_sha256_update (&sha, buf, (size_t) n) != 0)
        {
          mbedtls_sha256_free (&sha);
          return -1;
        }
      crypto_blake2b_update (&blake, buf, (size_t) n);
    }
  if (n < 0)
    {
      mbedtls_sha256_free (&sha);
      return -1;
    }
  if (mbedtls_sha256_finish (&sha, sha_out) != 0)
    {
      mbedtls_sha256_free (&sha);
      return -1;
    }
  mbedtls_sha256_free (&sha);
  crypto_blake2b_final (&blake, blake_out);
  bi_hex (sha_out, sizeof sha_out, sha_hex);
  bi_hex (blake_out, sizeof blake_out, blake_hex);
  return 0;
}

static char *
bi_readlink_parent (int parent, const char *base)
{
  size_t cap = 256;
  char *buf = NULL;

  for (;;)
    {
      ssize_t n;
      char *nb = realloc (buf, cap);
      if (!nb)
        {
          free (buf);
          return NULL;
        }
      buf = nb;
      n = readlinkat (parent, base, buf, cap - 1);
      if (n < 0)
        {
          free (buf);
          return NULL;
        }
      if ((size_t) n < cap - 1)
        {
          buf[n] = '\0';
          return buf;
        }
      cap *= 2;
    }
}

static char *
bi_make_file_row (const char *rel, const struct stat *st, int fd)
{
  char sha[65], blake[129];
  char *row;
  int n;

  if (bi_hash_fd (fd, sha, blake) < 0)
    return NULL;
  n = snprintf (NULL, 0, "file\t%o\t%llu\t%s\t%s\t%llu\t%llu\t%llu\t%llu\t-\t/%s",
                (unsigned) (st->st_mode & 07777),
                (unsigned long long) st->st_size,
                sha, blake,
                (unsigned long long) st->st_uid,
                (unsigned long long) st->st_gid,
                (unsigned long long) st->st_mtime,
                (unsigned long long) st->st_ctime,
                rel);
  if (n < 0)
    return NULL;
  row = malloc ((size_t) n + 1);
  if (!row)
    return NULL;
  snprintf (row, (size_t) n + 1, "file\t%o\t%llu\t%s\t%s\t%llu\t%llu\t%llu\t%llu\t-\t/%s",
            (unsigned) (st->st_mode & 07777),
            (unsigned long long) st->st_size,
            sha, blake,
            (unsigned long long) st->st_uid,
            (unsigned long long) st->st_gid,
            (unsigned long long) st->st_mtime,
            (unsigned long long) st->st_ctime,
            rel);
  return row;
}

static char *
bi_make_symlink_row (const char *rel, const struct stat *st, const char *target)
{
  char *row;
  int n = snprintf (NULL, 0, "symlink\t%o\t-\t-\t-\t-\t-\t-\t-\t%s\t/%s",
                    (unsigned) (st->st_mode & 07777), target, rel);
  if (n < 0)
    return NULL;
  row = malloc ((size_t) n + 1);
  if (!row)
    return NULL;
  snprintf (row, (size_t) n + 1, "symlink\t%o\t-\t-\t-\t-\t-\t-\t-\t%s\t/%s",
            (unsigned) (st->st_mode & 07777), target, rel);
  return row;
}

static char *
bi_row_for_rel (int rootfd, const char *rel)
{
  int parent = -1, fd = -1;
  char *base = NULL, *target = NULL, *row = NULL;
  struct stat st;

  if (bi_open_parent (rootfd, rel, &parent, &base) < 0)
    return NULL;
  if (fstatat (parent, base, &st, AT_SYMLINK_NOFOLLOW) < 0)
    goto out;

  if (S_ISREG (st.st_mode))
    {
      fd = openat (parent, base, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
      if (fd < 0)
        goto out;
      if (fstat (fd, &st) < 0)
        goto out;
      row = bi_make_file_row (rel, &st, fd);
    }
  else if (S_ISLNK (st.st_mode))
    {
      target = bi_readlink_parent (parent, base);
      if (!target || bi_has_bad_field_byte (target))
        goto out;
      row = bi_make_symlink_row (rel, &st, target);
    }

out:
  if (fd >= 0)
    close (fd);
  if (parent >= 0)
    close (parent);
  free (base);
  free (target);
  return row;
}

static int
bi_generate_rows (const char *root, const bi_vec *roots, const bi_vec *excludes,
                  bi_vec *rows)
{
  int rootfd = bi_open_root (root);
  bi_vec paths = {0};
  int rc = 0;

  if (rootfd < 0)
    {
      builtin_error ("open root %s: %s", root, strerror (errno));
      return -1;
    }

  for (size_t i = 0; i < roots->n; i++)
    {
      char *rel = NULL;
      if (bi_rel_from_abs (roots->v[i], &rel) < 0)
        {
          rc = -1;
          break;
        }
      if (bi_collect_rel (rootfd, rel, excludes, &paths) < 0)
        {
          builtin_error ("walk /%s: %s", rel, strerror (errno));
          free (rel);
          rc = -1;
          break;
        }
      free (rel);
    }

  if (rc == 0)
    {
      bi_vec_sort (&paths);
      for (size_t i = 0; i < paths.n; i++)
        {
          char *row = bi_row_for_rel (rootfd, paths.v[i]);
          if (!row)
            {
              builtin_error ("emit /%s: %s", paths.v[i], strerror (errno));
              rc = -1;
              break;
            }
          if (bi_vec_push (rows, row) < 0)
            {
              free (row);
              rc = -1;
              break;
            }
        }
    }

  bi_vec_free (&paths);
  close (rootfd);
  return rc;
}

static int
bi_default_roots (bi_vec *roots)
{
  return bi_vec_push_dup (roots, "/bin") == 0
    && bi_vec_push_dup (roots, "/bash-os") == 0
    && bi_vec_push_dup (roots, "/etc/bash-os") == 0 ? 0 : -1;
}

static int
bi_emit_manifest_cmd (WORD_LIST *args, int header)
{
  const char *root = "/";
  bi_vec roots = {0}, excludes = {0}, rows = {0};
  int rc = EXECUTION_FAILURE;

  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "--root") == 0)
        {
          if (!p->next)
            { builtin_error ("--root needs DIR"); rc = EX_USAGE; goto out; }
          p = p->next;
          root = p->word->word;
        }
      else if (strcmp (w, "--exclude") == 0)
        {
          if (!p->next)
            { builtin_error ("--exclude needs PATTERN"); rc = EX_USAGE; goto out; }
          p = p->next;
          if (bi_vec_push_dup (&excludes, p->word->word) < 0)
            goto out;
        }
      else if (strcmp (w, "--no-header") == 0)
        header = 0;
      else if (strcmp (w, "--") == 0)
        {
          for (p = p->next; p; p = p->next)
            if (bi_vec_push_dup (&roots, p->word->word) < 0)
              goto out;
          break;
        }
      else if (w[0] == '-')
        {
          builtin_error ("unknown option: %s", w);
          rc = EX_USAGE;
          goto out;
        }
      else if (bi_vec_push_dup (&roots, w) < 0)
        goto out;
    }

  if (roots.n == 0 && bi_default_roots (&roots) < 0)
    goto out;
  if (bi_generate_rows (root, &roots, &excludes, &rows) < 0)
    goto out;

  if (header)
    {
      printf ("# bl-integrity manifest v2\n");
      printf ("# columns: type mode size sha256 blake2b uid gid mtime ctime target rel\n");
      printf ("# root=%s\n", root);
    }
  for (size_t i = 0; i < rows.n; i++)
    printf ("%s\n", rows.v[i]);
  rc = EXECUTION_SUCCESS;

out:
  bi_vec_free (&roots);
  bi_vec_free (&excludes);
  bi_vec_free (&rows);
  return rc;
}

static const char *
bi_row_path (const char *row)
{
  const char *p = row;
  int tabs = 0;
  while (*p)
    {
      if (*p == '\t' && ++tabs == 10)
        return p + 1;
      p++;
    }
  return NULL;
}

static int
bi_load_manifest_rows (const char *path, bi_vec *rows)
{
  FILE *fp = fopen (path, "r");
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;

  if (!fp)
    {
      builtin_error ("open manifest %s: %s", path, strerror (errno));
      return -1;
    }

  while ((n = getline (&line, &cap, fp)) >= 0)
    {
      while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
        line[--n] = '\0';
      if (n == 0 || line[0] == '#')
        continue;
      if (bi_vec_push_dup (rows, line) < 0)
        {
          free (line);
          fclose (fp);
          return -1;
        }
    }
  free (line);
  fclose (fp);
  return 0;
}

static const char *
bi_find_by_path (const bi_vec *rows, const char *path)
{
  for (size_t i = 0; i < rows->n; i++)
    {
      const char *rp = bi_row_path (rows->v[i]);
      if (rp && strcmp (rp, path) == 0)
        return rows->v[i];
    }
  return NULL;
}

static int
bi_verify_cmd (WORD_LIST *args)
{
  const char *manifest = NULL;
  const char *root = "/";
  bi_vec roots = {0}, excludes = {0}, want = {0}, got = {0};
  int diffs = 0;
  int rc = EXECUTION_FAILURE;

  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "--root") == 0)
        {
          if (!p->next)
            { builtin_error ("--root needs DIR"); rc = EX_USAGE; goto out; }
          p = p->next;
          root = p->word->word;
        }
      else if (strcmp (w, "--exclude") == 0)
        {
          if (!p->next)
            { builtin_error ("--exclude needs PATTERN"); rc = EX_USAGE; goto out; }
          p = p->next;
          if (bi_vec_push_dup (&excludes, p->word->word) < 0)
            goto out;
        }
      else if (w[0] == '-' && strcmp (w, "--") != 0)
        {
          builtin_error ("unknown option: %s", w);
          rc = EX_USAGE;
          goto out;
        }
      else if (!manifest)
        manifest = w;
      else if (bi_vec_push_dup (&roots, w) < 0)
        goto out;
    }

  if (!manifest)
    {
      builtin_error ("verify needs MANIFEST");
      rc = EX_USAGE;
      goto out;
    }
  if (roots.n == 0 && bi_default_roots (&roots) < 0)
    goto out;
  if (bi_load_manifest_rows (manifest, &want) < 0)
    goto out;
  if (bi_generate_rows (root, &roots, &excludes, &got) < 0)
    goto out;

  for (size_t i = 0; i < want.n; i++)
    {
      const char *path = bi_row_path (want.v[i]);
      const char *cur = path ? bi_find_by_path (&got, path) : NULL;
      if (!path)
        {
          printf ("malformed\t%s\n", want.v[i]);
          diffs = 1;
        }
      else if (!cur)
        {
          printf ("missing\t%s\n", path);
          diffs = 1;
        }
      else if (strcmp (want.v[i], cur) != 0)
        {
          printf ("changed\t%s\n", path);
          diffs = 1;
        }
    }
  for (size_t i = 0; i < got.n; i++)
    {
      const char *path = bi_row_path (got.v[i]);
      if (path && !bi_find_by_path (&want, path))
        {
          printf ("added\t%s\n", path);
          diffs = 1;
        }
    }
  rc = diffs ? EXECUTION_FAILURE : EXECUTION_SUCCESS;

out:
  bi_vec_free (&roots);
  bi_vec_free (&excludes);
  bi_vec_free (&want);
  bi_vec_free (&got);
  return rc;
}

int
integrity_builtin (WORD_LIST *list)
{
  const char *cmd;

  if (!list || !list->word || !list->word->word)
    {
      builtin_usage ();
      return EX_USAGE;
    }

  cmd = list->word->word;
  if (strcmp (cmd, "--help") == 0 || strcmp (cmd, "-h") == 0)
    {
      puts ("integrity emit-manifest [--root DIR] [--exclude PAT] [PATH...]");
      puts ("integrity snapshot [--root DIR] [--exclude PAT] [PATH...]");
      puts ("integrity verify MANIFEST [--root DIR] [--exclude PAT] [PATH...]");
      return EXECUTION_SUCCESS;
    }
  if (strcmp (cmd, "--version") == 0)
    {
      puts ("integrity 1.0 (bash-loadable)");
      return EXECUTION_SUCCESS;
    }
  if (strcmp (cmd, "emit-manifest") == 0 || strcmp (cmd, "snapshot") == 0)
    return bi_emit_manifest_cmd (list->next, 1);
  if (strcmp (cmd, "verify") == 0)
    return bi_verify_cmd (list->next);

  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *integrity_doc[] = {
  "Emit and verify bl-integrity manifest rows.",
  "",
  "    integrity emit-manifest [--root DIR] [--exclude PAT] [PATH...]",
  "    integrity snapshot [--root DIR] [--exclude PAT] [PATH...]",
  "    integrity verify MANIFEST [--root DIR] [--exclude PAT] [PATH...]",
  "",
  "The shell bl-integrity wrapper owns config loading, signatures, and UX.",
  "This builtin owns the fd-pinned tree walk, metadata capture, SHA-256,",
  "and BLAKE2b hashing inner loop.",
  (char *) NULL
};

struct builtin integrity_struct = {
  "integrity",
  integrity_builtin,
  BUILTIN_ENABLED,
  integrity_doc,
  "integrity emit-manifest|snapshot|verify [ARGS...]",
  0
};
