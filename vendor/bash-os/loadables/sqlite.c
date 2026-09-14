/* SPDX-License-Identifier: MIT */
/* sqlite.c - small SQLite handle API for bash-os.
 *
 * Stage 24 v1 deliberately exposes a streaming prepared-statement surface:
 * open/exec/prepare/bind/step/reset/finalize/close. Result rows are returned
 * as tab-separated text in a scalar variable so callers never need to buffer
 * a whole result set in Bash memory.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#include "loadables.h"
#include "_sqlite_sqlite3.h"

#define BSQL_MAX_DB 32
#define BSQL_MAX_STMT 256

typedef struct {
  sqlite3 *db;
  unsigned int gen;
} bsql_db_slot;

typedef struct {
  sqlite3_stmt *stmt;
  int db_idx;
  unsigned int gen;
} bsql_stmt_slot;

static bsql_db_slot bsql_dbs[BSQL_MAX_DB];
static bsql_stmt_slot bsql_stmts[BSQL_MAX_STMT];
static unsigned int bsql_next_gen = 1;

static const char *
next_word (WORD_LIST **p)
{
  if (!p || !*p) return NULL;
  const char *w = (*p)->word->word;
  *p = (*p)->next;
  return w;
}

static int
bind_scalar (const char *var, const char *val)
{
  if (var)
    {
      builtin_bind_variable ((char *) var, (char *) (val ? val : ""), 0);
      return EXECUTION_SUCCESS;
    }
  if (val) printf ("%s\n", val);
  return EXECUTION_SUCCESS;
}

static int
parse_db (const char *h)
{
  int idx = -1;
  unsigned int gen = 0;
  if (!h || sscanf (h, "Q%dg%u", &idx, &gen) != 2 ||
      idx < 0 || idx >= BSQL_MAX_DB ||
      !bsql_dbs[idx].db || bsql_dbs[idx].gen != gen)
    return -1;
  return idx;
}

static int
parse_stmt (const char *h)
{
  int idx = -1;
  unsigned int gen = 0;
  if (!h || sscanf (h, "T%dg%u", &idx, &gen) != 2 ||
      idx < 0 || idx >= BSQL_MAX_STMT ||
      !bsql_stmts[idx].stmt || bsql_stmts[idx].gen != gen)
    return -1;
  return idx;
}

static int
alloc_db (sqlite3 *db, char *out, size_t outsz)
{
  for (int i = 0; i < BSQL_MAX_DB; i++)
    if (!bsql_dbs[i].db)
      {
        bsql_dbs[i].db = db;
        bsql_dbs[i].gen = bsql_next_gen++;
        if (bsql_next_gen == 0) bsql_next_gen = 1;
        snprintf (out, outsz, "Q%dg%u", i, bsql_dbs[i].gen);
        return 0;
      }
  return -1;
}

static int
alloc_stmt (sqlite3_stmt *stmt, int db_idx, char *out, size_t outsz)
{
  for (int i = 0; i < BSQL_MAX_STMT; i++)
    if (!bsql_stmts[i].stmt)
      {
        bsql_stmts[i].stmt = stmt;
        bsql_stmts[i].db_idx = db_idx;
        bsql_stmts[i].gen = bsql_next_gen++;
        if (bsql_next_gen == 0) bsql_next_gen = 1;
        snprintf (out, outsz, "T%dg%u", i, bsql_stmts[i].gen);
        return 0;
      }
  return -1;
}

static int
open_cmd (WORD_LIST *args)
{
  const char *path = next_word (&args);
  const char *var = NULL, *w;
  while ((w = next_word (&args)))
    {
      if (!strcmp (w, "-h") && args) var = next_word (&args);
      else { builtin_error ("open: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!path || !var) { builtin_error ("open PATH -h HANDLE_VAR"); return EX_USAGE; }

  sqlite3 *db = NULL;
  int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX;
  const char *vfs = strcmp (path, ":memory:") ? "unix-none" : NULL;
  int rc = sqlite3_open_v2 (path, &db, flags, vfs);
  if (rc != SQLITE_OK)
    {
      builtin_error ("open: %s", db ? sqlite3_errmsg (db) : "out of memory");
      if (db) sqlite3_close (db);
      return EXECUTION_FAILURE;
    }
  sqlite3_exec (db, "PRAGMA journal_mode=MEMORY; PRAGMA synchronous=OFF; PRAGMA foreign_keys=ON", NULL, NULL, NULL);

  char h[32];
  if (alloc_db (db, h, sizeof h) < 0)
    {
      sqlite3_close (db);
      builtin_error ("open: db handle table full");
      return EXECUTION_FAILURE;
    }
  return bind_scalar (var, h);
}

static int
exec_cmd (WORD_LIST *args)
{
  const char *h = next_word (&args);
  const char *sql = next_word (&args);
  int idx = parse_db (h);
  if (idx < 0 || !sql) { builtin_error ("exec DB SQL"); return EX_USAGE; }
  char *err = NULL;
  int rc = sqlite3_exec (bsql_dbs[idx].db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK)
    {
      builtin_error ("exec: %s", err ? err : sqlite3_errmsg (bsql_dbs[idx].db));
      sqlite3_free (err);
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
prepare_cmd (WORD_LIST *args)
{
  const char *h = next_word (&args);
  const char *sql = next_word (&args);
  const char *var = NULL, *w;
  while ((w = next_word (&args)))
    {
      if (!strcmp (w, "-h") && args) var = next_word (&args);
      else { builtin_error ("prepare: unexpected arg: %s", w); return EX_USAGE; }
    }
  int db_idx = parse_db (h);
  if (db_idx < 0 || !sql || !var) { builtin_error ("prepare DB SQL -h STMT_VAR"); return EX_USAGE; }
  sqlite3_stmt *stmt = NULL;
  int rc = sqlite3_prepare_v2 (bsql_dbs[db_idx].db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK)
    {
      builtin_error ("prepare: %s", sqlite3_errmsg (bsql_dbs[db_idx].db));
      return EXECUTION_FAILURE;
    }
  char sh[32];
  if (alloc_stmt (stmt, db_idx, sh, sizeof sh) < 0)
    {
      sqlite3_finalize (stmt);
      builtin_error ("prepare: statement handle table full");
      return EXECUTION_FAILURE;
    }
  return bind_scalar (var, sh);
}

static int
bind_cmd (WORD_LIST *args)
{
  const char *h = next_word (&args);
  const char *n_s = next_word (&args);
  const char *val = next_word (&args);
  const char *type = "TEXT", *w;
  while ((w = next_word (&args)))
    {
      if (!strcmp (w, "-t") && args) type = next_word (&args);
      else { builtin_error ("bind: unexpected arg: %s", w); return EX_USAGE; }
    }
  int si = parse_stmt (h);
  if (si < 0 || !n_s) { builtin_error ("bind STMT N VALUE [-t TYPE]"); return EX_USAGE; }
  int n = atoi (n_s);
  int rc;
  if (!strcmp (type, "NULL"))
    rc = sqlite3_bind_null (bsql_stmts[si].stmt, n);
  else if (!strcmp (type, "INTEGER"))
    rc = sqlite3_bind_int64 (bsql_stmts[si].stmt, n, val ? strtoll (val, NULL, 10) : 0);
  else if (!strcmp (type, "REAL"))
    rc = sqlite3_bind_double (bsql_stmts[si].stmt, n, val ? strtod (val, NULL) : 0.0);
  else if (!strcmp (type, "BLOB"))
    {
      const char *hex = val ? val : "";
      size_t hexlen = strlen (hex);
      int valid = hexlen <= INT_MAX && hexlen % 2 == 0;
      for (size_t i = 0; valid && i < hexlen; i++)
        if (!isxdigit ((unsigned char) hex[i])) valid = 0;
      if (!valid)
        {
          builtin_error ("bind: BLOB value must be hex-encoded (even length)");
          /* Auto-finalize on bind failure (same contract as the
           * rc != SQLITE_OK path below): the stmt slot can't be
           * reused after a bind error. Reclaiming here keeps the
           * documented "bind failure auto-finalizes the prepared
           * statement (slot reclaimed)" invariant true for ALL
           * bind-failure paths, including pre-bind validation
           * errors like odd-length hex. */
          sqlite3_finalize (bsql_stmts[si].stmt);
          bsql_stmts[si].stmt = NULL;
          bsql_stmts[si].db_idx = -1;
          return EX_USAGE;
        }
      int blen = (int) (hexlen / 2);
      unsigned char *blob = blen > 0 ? malloc (blen) : NULL;
      if (blen > 0 && !blob)
        {
          /* Same auto-finalize discipline on the malloc-fail path. */
          sqlite3_finalize (bsql_stmts[si].stmt);
          bsql_stmts[si].stmt = NULL;
          bsql_stmts[si].db_idx = -1;
          return EXECUTION_FAILURE;
        }
      for (int i = 0; i < blen; i++)
        {
          unsigned int byte = 0;
          sscanf (hex + 2 * i, "%2x", &byte);
          blob[i] = (unsigned char) byte;
        }
      rc = blen ? sqlite3_bind_blob (bsql_stmts[si].stmt, n, blob, blen, free)
                : sqlite3_bind_zeroblob (bsql_stmts[si].stmt, n, 0);
    }
  else
    rc = sqlite3_bind_text (bsql_stmts[si].stmt, n, val ? val : "", -1, SQLITE_TRANSIENT);
  if (rc != SQLITE_OK)
    {
      int dbi = bsql_stmts[si].db_idx;
      builtin_error ("bind: %s", sqlite3_errmsg (bsql_dbs[dbi].db));
      /* Auto-finalize on bind failure: the stmt slot can't be reused
         after a bind error (caller would have to reset+re-bind every
         param), and abandoning the handle without finalize leaks the
         slot. Reclaiming here matches the documented contract that
         bind failures clean up the prepared statement. */
      sqlite3_finalize (bsql_stmts[si].stmt);
      bsql_stmts[si].stmt = NULL;
      bsql_stmts[si].db_idx = -1;
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
step_cmd (WORD_LIST *args)
{
  const char *h = next_word (&args);
  const char *var = NULL, *w;
  while ((w = next_word (&args)))
    {
      if (!strcmp (w, "-V") && args) var = next_word (&args);
      else { builtin_error ("step: unexpected arg: %s", w); return EX_USAGE; }
    }
  int si = parse_stmt (h);
  if (si < 0) { builtin_error ("step STMT [-V ROW_VAR]"); return EX_USAGE; }
  sqlite3_stmt *stmt = bsql_stmts[si].stmt;
  int rc = sqlite3_step (stmt);
  if (rc == SQLITE_DONE) return EXECUTION_FAILURE;
  if (rc != SQLITE_ROW)
    {
      int dbi = bsql_stmts[si].db_idx;
      builtin_error ("step: %s", sqlite3_errmsg (bsql_dbs[dbi].db));
      return EXECUTION_FAILURE;
    }
  int cols = sqlite3_column_count (stmt);
  size_t cap = 128, len = 0;
  char *row = malloc (cap);
  if (!row) return EXECUTION_FAILURE;
  row[0] = '\0';
  for (int i = 0; i < cols; i++)
    {
      const unsigned char *txt = sqlite3_column_text (stmt, i);
      const char *s = txt ? (const char *) txt : "";
      size_t sl = strlen (s);
      while (len + sl + 2 > cap)
        {
          cap *= 2;
          char *nr = realloc (row, cap);
          if (!nr) { free (row); return EXECUTION_FAILURE; }
          row = nr;
        }
      if (i) row[len++] = '\t';
      memcpy (row + len, s, sl);
      len += sl;
      row[len] = '\0';
    }
  int brc = bind_scalar (var, row);
  free (row);
  return brc;
}

static int
reset_cmd (WORD_LIST *args)
{
  int si = parse_stmt (next_word (&args));
  if (si < 0) { builtin_error ("reset STMT"); return EX_USAGE; }
  sqlite3_reset (bsql_stmts[si].stmt);
  sqlite3_clear_bindings (bsql_stmts[si].stmt);
  return EXECUTION_SUCCESS;
}

static int
finalize_cmd (WORD_LIST *args)
{
  int si = parse_stmt (next_word (&args));
  if (si < 0) { builtin_error ("finalize STMT"); return EX_USAGE; }
  sqlite3_finalize (bsql_stmts[si].stmt);
  memset (&bsql_stmts[si], 0, sizeof bsql_stmts[si]);
  return EXECUTION_SUCCESS;
}

static int
close_cmd (WORD_LIST *args)
{
  int di = parse_db (next_word (&args));
  if (di < 0) { builtin_error ("close DB"); return EX_USAGE; }
  for (int i = 0; i < BSQL_MAX_STMT; i++)
    if (bsql_stmts[i].stmt && bsql_stmts[i].db_idx == di)
      {
        builtin_error ("close: unfinalized statements remain");
        return EXECUTION_FAILURE;
      }
  int rc = sqlite3_close (bsql_dbs[di].db);
  if (rc != SQLITE_OK)
    {
      builtin_error ("close: %s", sqlite3_errmsg (bsql_dbs[di].db));
      return EXECUTION_FAILURE;
    }
  memset (&bsql_dbs[di], 0, sizeof bsql_dbs[di]);
  return EXECUTION_SUCCESS;
}

static int
simple_int_cmd (WORD_LIST *args, int which)
{
  int di = parse_db (next_word (&args));
  if (di < 0) return EX_USAGE;
  if (which == 0) printf ("%d\n", sqlite3_changes (bsql_dbs[di].db));
  else printf ("%lld\n", (long long) sqlite3_last_insert_rowid (bsql_dbs[di].db));
  return EXECUTION_SUCCESS;
}

static int
stats_cmd (void)
{
  int stmt_active = 0;
  for (int i = 0; i < BSQL_MAX_STMT; i++)
    if (bsql_stmts[i].stmt)
      stmt_active++;
  printf ("active_stmts %d\n", stmt_active);
  printf ("max_stmts %d\n", BSQL_MAX_STMT);
  return EXECUTION_SUCCESS;
}

extern char *sqlite_doc[];

int
sqlite_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  /* Top-level --help/-h/help: print sqlite_doc (same arm as
     `help sqlite' uses); the verb dispatcher otherwise treated
     --help as an unknown subcommand, confusing for a verb-grammar tool. */
  if (!strcmp (cmd, "--help") || !strcmp (cmd, "-h") || !strcmp (cmd, "help")) {
    for (char **lp = sqlite_doc; *lp; lp++)
      puts (*lp);
    return EXECUTION_SUCCESS;
  }
  if (!strcmp (cmd, "--stats") || !strcmp (cmd, "stats"))
    return stats_cmd ();
  if (!strcmp (cmd, "open")) return open_cmd (args);
  if (!strcmp (cmd, "exec")) return exec_cmd (args);
  if (!strcmp (cmd, "prepare")) return prepare_cmd (args);
  if (!strcmp (cmd, "bind")) return bind_cmd (args);
  if (!strcmp (cmd, "step")) return step_cmd (args);
  if (!strcmp (cmd, "reset")) return reset_cmd (args);
  if (!strcmp (cmd, "finalize")) return finalize_cmd (args);
  if (!strcmp (cmd, "close")) return close_cmd (args);
  if (!strcmp (cmd, "changes")) return simple_int_cmd (args, 0);
  if (!strcmp (cmd, "last-insert-rowid")) return simple_int_cmd (args, 1);
  if (!strcmp (cmd, "transaction"))
    {
      const char *h = next_word (&args);
      const char *op = next_word (&args);
      int di = parse_db (h);
      if (di < 0 || !op) { builtin_error ("transaction DB BEGIN|COMMIT|ROLLBACK"); return EX_USAGE; }
      if (strcmp (op, "BEGIN") && strcmp (op, "COMMIT") && strcmp (op, "ROLLBACK"))
        { builtin_error ("transaction: expected BEGIN|COMMIT|ROLLBACK"); return EX_USAGE; }
      char *err = NULL;
      int rc = sqlite3_exec (bsql_dbs[di].db, op, NULL, NULL, &err);
      if (rc != SQLITE_OK)
        {
          builtin_error ("transaction: %s", err ? err : sqlite3_errmsg (bsql_dbs[di].db));
          sqlite3_free (err);
          return EXECUTION_FAILURE;
        }
      return EXECUTION_SUCCESS;
    }
  builtin_error ("unknown verb: %s", cmd);
  return EX_USAGE;
}

char *sqlite_doc[] = {
  "SQLite handle API for bash-os.",
  "  sqlite open PATH -h DB_VAR",
  "  sqlite exec DB SQL",
  "  sqlite prepare DB SQL -h STMT_VAR",
  "  sqlite bind STMT N VALUE [-t TEXT|INTEGER|REAL|NULL|BLOB]",
  "  sqlite step STMT [-V ROW_VAR]",
  "  sqlite reset|finalize STMT",
  "  sqlite close DB",
  "  sqlite transaction DB BEGIN|COMMIT|ROLLBACK",
  "  sqlite changes DB",
  "  sqlite last-insert-rowid DB",
  "  sqlite --stats             # print active_stmts and max_stmts",
  "",
  "  (file databases use unix-none VFS, memory SQLITE_OPEN_NOMUTEX; no locking)",
  "  bind failure auto-finalizes the prepared statement (slot reclaimed).",
  (char *) NULL
};

struct builtin sqlite_struct = {
  "sqlite",
  sqlite_builtin,
  BUILTIN_ENABLED,
  sqlite_doc,
  "sqlite open|exec|prepare|bind|step|reset|finalize|close ...",
  0
};
