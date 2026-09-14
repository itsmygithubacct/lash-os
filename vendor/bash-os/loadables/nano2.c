/* SPDX-License-Identifier: MIT */
/* nano2.c - Stage 16 piece-table buffer engine for nano.
 *
 * This is the Stage 16 fork point: keep the existing interactive nano
 * stable while landing a testable piece-table core with load/save/edit/undo.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef BASHNANO2_STANDALONE
#  include "loadables.h"
#else
#  define EXECUTION_SUCCESS 0
#  define EXECUTION_FAILURE 1
#  define EX_USAGE 2
typedef struct word_desc { char *word; } WORD_DESC;
typedef struct word_list { struct word_list *next; WORD_DESC *word; } WORD_LIST;
#  define builtin_error(...) fprintf (stderr, __VA_ARGS__)
#endif

typedef enum { PT_ORIG = 0, PT_ADD = 1 } pt_source;

typedef struct {
  pt_source source;
  size_t offset;
  size_t length;
  size_t line_count;
} pt_piece;

typedef struct {
  char *original;
  size_t original_len;
  char *add;
  size_t add_len;
  size_t add_cap;
  pt_piece *pieces;
  size_t n_pieces;
  size_t pieces_cap;
  size_t total_len;
  size_t total_lines;
  char *path;
  int dirty;
} pt_buffer;

typedef struct {
  size_t pos;
} pt_cursor;

typedef struct {
  pt_piece *pieces;
  size_t n_pieces;
  size_t total_len;
  size_t total_lines;
  int dirty;
} pt_snapshot;

typedef struct {
  pt_snapshot *v;
  size_t n;
  size_t cap;
} pt_undo;

typedef struct {
  pt_undo undo;
  pt_undo redo;
} pt_history;

static size_t
pt_count_nl (const char *s, size_t n)
{
  size_t c = 0;
  for (size_t i = 0; i < n; i++)
    if (s[i] == '\n') c++;
  return c;
}

static const char *
pt_piece_data (const pt_buffer *b, const pt_piece *p)
{
  return p->source == PT_ORIG ? b->original + p->offset : b->add + p->offset;
}

static void
pt_free (pt_buffer *b)
{
  if (!b) return;
  free (b->original);
  free (b->add);
  free (b->pieces);
  free (b->path);
  memset (b, 0, sizeof *b);
}

static int
pt_reserve_pieces (pt_buffer *b, size_t need)
{
  if (b->pieces_cap >= need) return 0;
  size_t nc = b->pieces_cap ? b->pieces_cap * 2 : 8;
  while (nc < need) nc *= 2;
  pt_piece *np = realloc (b->pieces, nc * sizeof *np);
  if (!np) return -1;
  b->pieces = np;
  b->pieces_cap = nc;
  return 0;
}

static int
pt_reserve_add (pt_buffer *b, size_t need)
{
  if (b->add_cap >= need) return 0;
  size_t nc = b->add_cap ? b->add_cap * 2 : 1024;
  while (nc < need) nc *= 2;
  char *na = realloc (b->add, nc);
  if (!na) return -1;
  b->add = na;
  b->add_cap = nc;
  return 0;
}

static void
pt_recount (pt_buffer *b)
{
  b->total_len = 0;
  b->total_lines = 0;
  for (size_t i = 0; i < b->n_pieces; i++)
    {
      b->total_len += b->pieces[i].length;
      b->total_lines += b->pieces[i].line_count;
    }
}

static int
pt_init_text (pt_buffer *b, const char *path, const char *data, size_t len)
{
  memset (b, 0, sizeof *b);
  b->path = path ? strdup (path) : NULL;
  if (path && !b->path) return -1;
  if (len)
    {
      b->original = malloc (len);
      if (!b->original) { pt_free (b); return -1; }
      memcpy (b->original, data, len);
      b->original_len = len;
      if (pt_reserve_pieces (b, 1) < 0) { pt_free (b); return -1; }
      b->pieces[0].source = PT_ORIG;
      b->pieces[0].offset = 0;
      b->pieces[0].length = len;
      b->pieces[0].line_count = pt_count_nl (data, len);
      b->n_pieces = 1;
    }
  b->total_len = len;
  b->total_lines = pt_count_nl (data, len);
  return 0;
}

static int
pt_load (pt_buffer *b, const char *path)
{
  int fd = open (path, O_RDONLY);
  if (fd < 0)
    return pt_init_text (b, path, "", 0);

  struct stat st;
  if (fstat (fd, &st) < 0) { close (fd); return -1; }
  if (st.st_size < 0) { close (fd); errno = EINVAL; return -1; }
  size_t len = (size_t) st.st_size;
  char *buf = len ? malloc (len) : NULL;
  if (len && !buf) { close (fd); return -1; }
  size_t off = 0;
  while (off < len)
    {
      ssize_t r = read (fd, buf + off, len - off);
      if (r < 0) { if (errno == EINTR) continue; free (buf); close (fd); return -1; }
      if (r == 0) break;
      off += (size_t) r;
    }
  close (fd);
  int rc = pt_init_text (b, path, buf ? buf : "", off);
  free (buf);
  return rc;
}

static int
pt_find_piece (const pt_buffer *b, size_t pos, size_t *idx, size_t *inner)
{
  size_t cur = 0;
  for (size_t i = 0; i < b->n_pieces; i++)
    {
      size_t next = cur + b->pieces[i].length;
      if (pos < next)
	{
	  *idx = i;
	  *inner = pos - cur;
	  return 0;
	}
      cur = next;
    }
  *idx = b->n_pieces;
  *inner = 0;
  return pos == b->total_len ? 0 : -1;
}

static int
pt_replace_span (pt_buffer *b, size_t start, size_t end,
		 const char *ins, size_t ins_len)
{
  if (start > end || end > b->total_len) return -1;

  size_t si, so, ei, eo;
  pt_find_piece (b, start, &si, &so);
  pt_find_piece (b, end, &ei, &eo);

  pt_piece newp[3];
  size_t nn = 0;
  if (si < b->n_pieces && so > 0)
    {
      newp[nn] = b->pieces[si];
      newp[nn].length = so;
      newp[nn].line_count = pt_count_nl (pt_piece_data (b, &newp[nn]), newp[nn].length);
      nn++;
    }
  if (ins_len)
    {
      if (pt_reserve_add (b, b->add_len + ins_len) < 0) return -1;
      size_t off = b->add_len;
      memcpy (b->add + off, ins, ins_len);
      b->add_len += ins_len;
      newp[nn].source = PT_ADD;
      newp[nn].offset = off;
      newp[nn].length = ins_len;
      newp[nn].line_count = pt_count_nl (ins, ins_len);
      nn++;
    }
  if (ei < b->n_pieces && eo < b->pieces[ei].length)
    {
      newp[nn] = b->pieces[ei];
      newp[nn].offset += eo;
      newp[nn].length -= eo;
      newp[nn].line_count = pt_count_nl (pt_piece_data (b, &newp[nn]), newp[nn].length);
      nn++;
    }

  size_t remove_start = si;
  size_t remove_end = (end == b->total_len) ? b->n_pieces : ei + 1;
  if (start == b->total_len)
    remove_start = remove_end = b->n_pieces;
  size_t remove_n = remove_end - remove_start;
  size_t new_count = b->n_pieces - remove_n + nn;
  if (pt_reserve_pieces (b, new_count) < 0) return -1;
  if (remove_end < b->n_pieces && remove_start + nn != remove_end)
    memmove (b->pieces + remove_start + nn, b->pieces + remove_end,
	     (b->n_pieces - remove_end) * sizeof *b->pieces);
  if (nn)
    memcpy (b->pieces + remove_start, newp, nn * sizeof *newp);
  b->n_pieces = new_count;
  pt_recount (b);
  b->dirty = 1;
  return 0;
}

static int
pt_insert (pt_buffer *b, pt_cursor *c, const char *s, size_t n)
{
  if (pt_replace_span (b, c->pos, c->pos, s, n) < 0) return -1;
  c->pos += n;
  return 0;
}

static int
pt_delete (pt_buffer *b, pt_cursor *c, size_t n)
{
  if (c->pos + n > b->total_len) return -1;
  return pt_replace_span (b, c->pos, c->pos + n, NULL, 0);
}

static int
pt_snapshot_push (pt_undo *u, const pt_buffer *b)
{
  if (u->n == u->cap)
    {
      size_t nc = u->cap ? u->cap * 2 : 16;
      pt_snapshot *nv = realloc (u->v, nc * sizeof *nv);
      if (!nv) return -1;
      u->v = nv;
      u->cap = nc;
    }
  pt_snapshot *s = &u->v[u->n++];
  memset (s, 0, sizeof *s);
  if (b->n_pieces)
    {
      s->pieces = malloc (b->n_pieces * sizeof *s->pieces);
      if (!s->pieces) { u->n--; return -1; }
      memcpy (s->pieces, b->pieces, b->n_pieces * sizeof *s->pieces);
    }
  s->n_pieces = b->n_pieces;
  s->total_len = b->total_len;
  s->total_lines = b->total_lines;
  s->dirty = b->dirty;
  return 0;
}

static int
pt_snapshot_restore (pt_buffer *b, pt_snapshot *s)
{
  if (pt_reserve_pieces (b, s->n_pieces) < 0) return -1;
  if (s->n_pieces) memcpy (b->pieces, s->pieces, s->n_pieces * sizeof *b->pieces);
  b->n_pieces = s->n_pieces;
  b->total_len = s->total_len;
  b->total_lines = s->total_lines;
  b->dirty = s->dirty;
  return 0;
}

static int
pt_snapshot_pop_restore (pt_undo *u, pt_buffer *b)
{
  if (u->n == 0) return -1;
  pt_snapshot s = u->v[--u->n];
  int rc = pt_snapshot_restore (b, &s);
  free (s.pieces);
  return rc;
}

static int
pt_undo_pop (pt_undo *u, pt_buffer *b)
{
  return pt_snapshot_pop_restore (u, b);
}

static void
pt_undo_free (pt_undo *u)
{
  for (size_t i = 0; i < u->n; i++) free (u->v[i].pieces);
  free (u->v);
  memset (u, 0, sizeof *u);
}

static int
pt_history_mark (pt_history *h, const pt_buffer *b)
{
  pt_undo_free (&h->redo);
  return pt_snapshot_push (&h->undo, b);
}

static int
pt_history_undo (pt_history *h, pt_buffer *b)
{
  if (h->undo.n == 0) return -1;
  if (pt_snapshot_push (&h->redo, b) < 0) return -1;
  return pt_snapshot_pop_restore (&h->undo, b);
}

static int
pt_history_redo (pt_history *h, pt_buffer *b)
{
  if (h->redo.n == 0) return -1;
  if (pt_snapshot_push (&h->undo, b) < 0) return -1;
  return pt_snapshot_pop_restore (&h->redo, b);
}

static void
pt_history_free (pt_history *h)
{
  pt_undo_free (&h->undo);
  pt_undo_free (&h->redo);
}

static char
pt_byte_at (const pt_buffer *b, size_t pos)
{
  size_t idx, off;
  if (pt_find_piece (b, pos, &idx, &off) < 0 || idx >= b->n_pieces) return '\0';
  return pt_piece_data (b, &b->pieces[idx])[off];
}

static char *
pt_flatten (const pt_buffer *b, size_t *out_len)
{
  char *s = malloc (b->total_len + 1);
  if (!s) return NULL;
  size_t off = 0;
  for (size_t i = 0; i < b->n_pieces; i++)
    {
      memcpy (s + off, pt_piece_data (b, &b->pieces[i]), b->pieces[i].length);
      off += b->pieces[i].length;
    }
  s[off] = '\0';
  if (out_len) *out_len = off;
  return s;
}

static char *
pt_flatten_range (const pt_buffer *b, size_t start, size_t end, size_t *out_len)
{
  if (start > end || end > b->total_len) return NULL;
  size_t len = end - start;
  char *s = malloc (len + 1);
  if (!s) return NULL;
  size_t copied = 0, cur = 0;
  for (size_t i = 0; i < b->n_pieces && copied < len; i++)
    {
      size_t p_start = cur;
      size_t p_end = cur + b->pieces[i].length;
      if (p_end > start && p_start < end)
	{
	  size_t lo = start > p_start ? start - p_start : 0;
	  size_t hi = end < p_end ? end - p_start : b->pieces[i].length;
	  size_t n = hi - lo;
	  memcpy (s + copied, pt_piece_data (b, &b->pieces[i]) + lo, n);
	  copied += n;
	}
      cur = p_end;
    }
  s[copied] = '\0';
  if (out_len) *out_len = copied;
  return s;
}

static int
pt_lc_to_pos (const pt_buffer *b, size_t line, size_t col, size_t *pos)
{
  size_t cur_line = 0, cur_col = 0;
  for (size_t i = 0; i < b->total_len; i++)
    {
      if (cur_line == line && cur_col == col) { *pos = i; return 0; }
      char ch = pt_byte_at (b, i);
      if (ch == '\n') { cur_line++; cur_col = 0; }
      else cur_col++;
    }
  if (cur_line == line && cur_col == col) { *pos = b->total_len; return 0; }
  return -1;
}

static int
pt_pos_to_lc (const pt_buffer *b, size_t pos, size_t *line, size_t *col)
{
  if (pos > b->total_len) return -1;
  size_t l = 0, c = 0;
  for (size_t i = 0; i < pos; i++)
    {
      char ch = pt_byte_at (b, i);
      if (ch == '\n') { l++; c = 0; }
      else c++;
    }
  *line = l;
  *col = c;
  return 0;
}

static int
pt_save (const pt_buffer *b, const char *path)
{
  char tmp[512];
  snprintf (tmp, sizeof tmp, "%s.tmp.%ld", path, (long)getpid ());
  int fd = open (tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) return -1;
  for (size_t i = 0; i < b->n_pieces; i++)
    {
      const char *p = pt_piece_data (b, &b->pieces[i]);
      size_t off = 0;
      while (off < b->pieces[i].length)
	{
	  ssize_t w = write (fd, p + off, b->pieces[i].length - off);
	  if (w < 0) { if (errno == EINTR) continue; close (fd); unlink (tmp); return -1; }
	  off += (size_t)w;
	}
    }
  if (fsync (fd) < 0) { close (fd); unlink (tmp); return -1; }
  if (close (fd) < 0) { unlink (tmp); return -1; }
  if (rename (tmp, path) < 0) { unlink (tmp); return -1; }
  /* G03 atomic-save — fsync the parent directory so the rename itself
     is durable across power loss. Without this, POSIX permits a successful
     rename() return to roll back across a crash because the directory
     entry pointing at the freshly-renamed inode has not been flushed yet
     (the file data is already durable via fsync(fd) above). Best-effort:
     dirfd-open failures stay non-fatal because the data is already on disk. */
  {
    const char *slash = strrchr (path, '/');
    const char *dirpath = ".";
    char dirbuf[4096];
    if (slash)
      {
	size_t dlen = (slash == path) ? 1 : (size_t) (slash - path);
	if (dlen < sizeof dirbuf)
	  {
	    memcpy (dirbuf, path, dlen);
	    dirbuf[dlen] = '\0';
	    dirpath = dirbuf;
	  }
      }
    int dfd = open (dirpath, O_RDONLY | O_DIRECTORY);
    if (dfd >= 0)
      {
	(void) fsync (dfd);
	close (dfd);
      }
  }
  return 0;
}

static int
tap_check (int *n, int cond, const char *desc)
{
  printf ("%s %d - %s\n", cond ? "ok" : "not ok", ++*n, desc);
  return cond ? 0 : 1;
}

static int
bn2_selftest (void)
{
  int n = 0, fails = 0;
  pt_buffer b;
  pt_cursor c = { 0 };
  pt_undo u = { 0 };
  pt_history hist = { 0 };

  if (pt_init_text (&b, "mem", "alpha\nbeta\n", 11) < 0) return 1;
  fails += tap_check (&n, b.n_pieces == 1 && b.total_len == 11 && b.total_lines == 2,
		      "load creates one original piece with newline count");
  size_t pos = 999;
  fails += tap_check (&n, pt_lc_to_pos (&b, 1, 2, &pos) == 0 && pos == 8,
		      "line/column maps to byte position");
  size_t line = 0, col = 0;
  fails += tap_check (&n, pt_pos_to_lc (&b, 8, &line, &col) == 0 && line == 1 && col == 2,
		      "byte position maps to line/column");

  c.pos = 0;
  pt_snapshot_push (&u, &b);
  pt_insert (&b, &c, "START\n", 6);
  size_t flat_len = 0;
  char *flat = pt_flatten (&b, &flat_len);
  fails += tap_check (&n, flat && flat_len == 17 && memcmp (flat, "START\nalpha\nbeta\n", 17) == 0,
		      "insert at start splits original without copying it");
  free (flat);

  c.pos = 11;
  pt_snapshot_push (&u, &b);
  pt_delete (&b, &c, 1);
  flat = pt_flatten (&b, &flat_len);
  fails += tap_check (&n, flat && memcmp (flat, "START\nalphabeta\n", 16) == 0,
		      "delete across newline joins text");
  free (flat);

  fails += tap_check (&n, pt_undo_pop (&u, &b) == 0, "undo restores previous piece list");
  flat = pt_flatten (&b, &flat_len);
  fails += tap_check (&n, flat && memcmp (flat, "START\nalpha\nbeta\n", 17) == 0,
		      "undo restores bytes");
  free (flat);

  flat = pt_flatten_range (&b, 6, 11, &flat_len);
  fails += tap_check (&n, flat && flat_len == 5 && memcmp (flat, "alpha", 5) == 0,
		      "render_range extracts visible byte span");
  free (flat);

  c.pos = b.total_len;
  for (int i = 0; i < 1000; i++)
    {
      if (pt_insert (&b, &c, "x", 1) < 0) { fails++; break; }
    }
  fails += tap_check (&n, b.total_len == 1017 && b.add_len == 1006,
		      "1000 cursor inserts append to add buffer");

  char *big = malloc (65536);
  if (big)
    {
      memset (big, 'L', 65536);
      c.pos = 6;
      fails += tap_check (&n, pt_insert (&b, &c, big, 65536) == 0
			  && b.total_len == 66553,
			  "large-line insert grows add buffer without flattening");
      size_t check_len = 0;
      char *check = pt_flatten_range (&b, 6, 6 + 65536, &check_len);
      fails += tap_check (&n, check && check_len == 65536
			  && check[0] == 'L' && check[65535] == 'L',
			  "large-line insert round-trips as one byte span");
      free (check);
      free (big);
    }
  else
    {
      fails += tap_check (&n, 0, "large-line insert grows add buffer without flattening");
      fails += tap_check (&n, 0, "large-line insert round-trips as one byte span");
    }

  pt_free (&b);
  if (pt_init_text (&b, "hist", "", 0) < 0) return 1;
  c.pos = 0;
  int hist_ok = 1;
  for (int i = 0; i < 100; i++)
    {
      char ch = (char) ('a' + (i % 26));
      if (pt_history_mark (&hist, &b) < 0 || pt_insert (&b, &c, &ch, 1) < 0)
	{ hist_ok = 0; break; }
    }
  fails += tap_check (&n, hist_ok && b.total_len == 100,
		      "100-step edit history records inserts");
  for (int i = 0; i < 100 && hist_ok; i++)
    if (pt_history_undo (&hist, &b) < 0) hist_ok = 0;
  fails += tap_check (&n, hist_ok && b.total_len == 0,
		      "100-step undo returns to empty buffer");
  for (int i = 0; i < 100 && hist_ok; i++)
    if (pt_history_redo (&hist, &b) < 0) hist_ok = 0;
  fails += tap_check (&n, hist_ok && b.total_len == 100,
		      "100-step redo reapplies edits");
  pt_history_free (&hist);

  const char bin_src[] = { 'A', '\0', 'B', '\n', '\xff', 'Z' };
  pt_free (&b);
  if (pt_init_text (&b, "bin", bin_src, sizeof bin_src) < 0) return 1;
  c.pos = 2;
  const char bin_ins[] = { '\0', 'X', '\0' };
  fails += tap_check (&n, pt_insert (&b, &c, bin_ins, sizeof bin_ins) == 0,
		      "binary-clean insert accepts NUL bytes");
  char *bin_flat = pt_flatten (&b, &flat_len);
  const char bin_expect[] = { 'A', '\0', '\0', 'X', '\0', 'B', '\n', '\xff', 'Z' };
  fails += tap_check (&n, bin_flat && flat_len == sizeof bin_expect
		      && memcmp (bin_flat, bin_expect, sizeof bin_expect) == 0,
		      "binary-clean flatten preserves embedded NUL bytes");
  free (bin_flat);

  char templ[] = "/tmp/nano2.XXXXXX";
  int fd = mkstemp (templ);
  if (fd >= 0)
    {
      close (fd);
      fails += tap_check (&n, pt_save (&b, templ) == 0, "save streams piece list to temp file");
      pt_buffer r;
      if (pt_load (&r, templ) == 0)
	{
	  char *rf = pt_flatten (&r, &flat_len);
	  size_t saved_len = 0;
	  char *saved = pt_flatten (&b, &saved_len);
	  fails += tap_check (&n, rf && saved && flat_len == saved_len
			      && memcmp (rf, saved, saved_len) == 0,
			      "saved file reloads byte-identical");
	  free (rf);
	  free (saved);
	  pt_free (&r);
	}
      else
	fails += tap_check (&n, 0, "saved file reloads byte-identical");
      unlink (templ);
    }
  else
    {
      fails += tap_check (&n, 0, "save streams piece list to temp file");
      fails += tap_check (&n, 0, "saved file reloads byte-identical");
    }

  /* G03 atomic-save — pt_save chain is open/write/fsync(fd)/rename +
     fsync(parent-dir). Pin no-residue + relative-path fallback. */
  char saveroot[] = "/tmp/nano2-as.XXXXXX";
  char *sdir = mkdtemp (saveroot);
  if (sdir)
    {
      char target[256];
      snprintf (target, sizeof target, "%s/saved.txt", sdir);
      pt_buffer ab;
      if (pt_init_text (&ab, "atomic", "hello\n", 6) == 0)
	{
	  int rc = pt_save (&ab, target);
	  fails += tap_check (&n, rc == 0, "pt_save returns 0 into fresh dir");

	  int residue = 0, have_target = 0;
	  DIR *d = opendir (sdir);
	  if (d)
	    {
	      struct dirent *de;
	      while ((de = readdir (d)) != NULL)
		{
		  if (strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0)
		    continue;
		  if (strstr (de->d_name, ".tmp.") != NULL) residue++;
		  if (strcmp (de->d_name, "saved.txt") == 0) have_target = 1;
		}
	      closedir (d);
	    }
	  fails += tap_check (&n, residue == 0, "pt_save leaves no .tmp.PID residue");
	  fails += tap_check (&n, have_target == 1, "pt_save creates target file");

	  /* Two consecutive saves to same path. */
	  int rc2 = pt_save (&ab, target);
	  fails += tap_check (&n, rc2 == 0, "second consecutive pt_save returns 0");

	  unlink (target);
	  pt_free (&ab);
	}
      else
	{
	  fails += tap_check (&n, 0, "pt_save returns 0 into fresh dir");
	  fails += tap_check (&n, 0, "pt_save leaves no .tmp.PID residue");
	  fails += tap_check (&n, 0, "pt_save creates target file");
	  fails += tap_check (&n, 0, "second consecutive pt_save returns 0");
	}
      rmdir (sdir);
    }
  else
    {
      fails += tap_check (&n, 0, "pt_save returns 0 into fresh dir");
      fails += tap_check (&n, 0, "pt_save leaves no .tmp.PID residue");
      fails += tap_check (&n, 0, "pt_save creates target file");
      fails += tap_check (&n, 0, "second consecutive pt_save returns 0");
    }

  /* Relative-path save exercises the dirpath="." fallback. */
  char relroot[] = "/tmp/nano2-asrel.XXXXXX";
  char *rdir = mkdtemp (relroot);
  if (rdir)
    {
      char saved_cwd[4096];
      if (getcwd (saved_cwd, sizeof saved_cwd) != NULL)
	{
	  if (chdir (rdir) == 0)
	    {
	      pt_buffer rb;
	      if (pt_init_text (&rb, "rel", "relpath\n", 8) == 0)
		{
		  int rc = pt_save (&rb, "rel-out.txt");
		  fails += tap_check (&n, rc == 0,
				      "pt_save relative path (dirpath=. fallback) returns 0");
		  unlink ("rel-out.txt");
		  pt_free (&rb);
		}
	      else
		fails += tap_check (&n, 0,
				    "pt_save relative path (dirpath=. fallback) returns 0");
	      (void) chdir (saved_cwd);
	    }
	  else
	    fails += tap_check (&n, 0,
				"pt_save relative path (dirpath=. fallback) returns 0");
	}
      else
	fails += tap_check (&n, 0,
			    "pt_save relative path (dirpath=. fallback) returns 0");
      rmdir (rdir);
    }
  else
    fails += tap_check (&n, 0,
			"pt_save relative path (dirpath=. fallback) returns 0");

  printf ("1..%d\n", n);
  pt_undo_free (&u);
  pt_history_free (&hist);
  pt_free (&b);
  return fails ? 1 : 0;
}

int
nano2_builtin (WORD_LIST *list)
{
  if (!list || !list->word || strcmp (list->word->word, "selftest") != 0)
    {
      builtin_error ("usage: nano2 selftest");
      return EX_USAGE;
    }
  return bn2_selftest () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

char *nano2_doc[] = {
  "Stage 16 piece-table buffer engine for nano.",
  "",
  "Usage: nano2 selftest",
  "",
  "nano2 is a forked, non-interactive Stage 16 engine while the",
  "existing nano editor remains the registered interactive editor.",
  "The selftest covers byte-preserving save, large inserts, binary",
  "NUL handling, and 100-step undo/redo history.",
  (char *)NULL
};

#ifndef BASHNANO2_STANDALONE
struct builtin nano2_struct = {
  "nano2",
  nano2_builtin,
  BUILTIN_ENABLED,
  nano2_doc,
  "nano2 selftest",
  0
};
#endif
#ifdef BASHNANO2_STANDALONE
int
main (void)
{
  return bn2_selftest ();
}
#endif
