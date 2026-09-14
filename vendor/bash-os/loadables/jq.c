/* SPDX-License-Identifier: MIT */
/* jq.c — jq-subset filter loadable for bash-os (Stage 48 v1).
 *
 * This ports the documented /bash-os/jq.sh functional subset into C:
 * paths, pipes, iteration, length/keys/type, select/map, comparisons,
 * boolean ops, arithmetic, default //, if/elif/else, literals, and -r/-e.
 * Deliberately unsupported jq features return EX_USAGE with a direct
 * "use system+ jq" diagnostic rather than silently drifting.
 *
 * ──── Identifier-dispatch surface (parser table at line ~624) ────
 * Identifiers recognized by the parser:
 *   Core (7):    length, keys, type, not, has, select, map
 *   Wave 3 (20): first, last, reverse, add, min, max, sort, unique,
 *                to_entries, from_entries, tostring, tonumber,
 *                tojson, fromjson, ascii_downcase, ascii_upcase,
 *                floor, ceil, fabs, sqrt
 *   Wave 4 (10): exp, log (0-arg math),
 *                ltrimstr, rtrimstr, startswith, endswith, contains,
 *                split, join, splits (1-arg string/value form,
 *                parsed like has/select/map).
 *   Wave 5 (7):  range (1/2/3-arg via the new `;` call-arg form),
 *                nth (2-arg N;F filter), getpath (1-arg path array),
 *                setpath (2-arg P;V), delpaths (1-arg paths array),
 *                pow (2-arg X;Y math).
 *   Wave 6 (4):  recurse, recurse_down (jq-1.5 spelling, kept as a
 *                no-arg alias), paths, leaf_paths. Plus a top-level
 *                `..` operator (FT_RECURSE token / N_RECURSE node) that
 *                lex-produces a recurse call.
 *   Wave 7 (1):  path(F) for the supported exact path-expression subset.
 * Everything else falls through to "unknown identifier: %s".
 * Pinned counterparts live at
 * tests/bash-os/h01-jq-path-recurse-counterpart.sh.
 *
 * ──── Wave 5 parser changes (2026-05-26) ────
 *
 * `,` (comma operator): jq's value-stream concat. `E1,E2` evaluates
 *     E1 and E2 against the SAME input, concatenating the value
 *     streams. Binds TIGHTER than `|` (pipe) so `.a | .b, .c` is
 *     `.a | (.b, .c)`. Inserted between parse_pipe and parse_default
 *     in the precedence ladder. AST node: N_COMMA.
 *
 * `;` (call-arg separator): jq's multi-arg call form, distinct from
 *     `,`. Used in range(F;U;S), nth(N;F), setpath(P;V), pow(X;Y),
 *     etc. Filter dispatch entries that accept >1 arg consume
 *     `EXPR ; EXPR [; EXPR]` between `(` and `)`. The existing
 *     a/b/c slots on node_t carry args 0/1/2 without restructuring.
 *
 * ──── Wave 6 parser changes (2026-05-26) ────
 *
 * `..` (recursive descent): WAS lex-rejected with "use system+ jq",
 *     NOW tokenized as FT_RECURSE and parses to N_RECURSE — a top-
 *     level primary that emits the input value followed by every
 *     reachable sub-value (depth-first, source order). Treated as a
 *     no-arg primary, not a postfix; `.a..` is a parse error (matching
 *     jq, which also rejects that form).
 *
 * `recurse` / `recurse_down`: 0-arg identifier aliases for `..`. Note
 *     that jq-1.7 removed `recurse_down` (errors on it), so the
 *     counterpart sweep grep-asserts dispatch for `recurse_down` but
 *     does not try a parity comparison.
 *
 * `paths`: 0-arg filter that emits every path to a non-root sub-value
 *     of the input, each path as a JSON array of components. Scalars
 *     and empty containers emit nothing. Depth-first, source order;
 *     includes intermediate container paths.
 *
 * `leaf_paths`: like `paths` but only emits paths whose value is a
 *     scalar (non-container). Also dropped by jq-1.7 in favor of
 *     `paths(scalars)`; we keep it for source compat with older jq
 *     scripts that the operator may carry.
 *
 * ──── Wave 7 path(F) subset (2026-06-02) ───────────────────────────
 *
 * `path(F)` returns the path expression(s) matched by filter F (e.g.
 * `path(.a.b[0])` → `["a","b",0]`). The first supported slice covers
 * exact root / field / index expressions, comma streams, simple pipes
 * that extend one path context (`path(.a | .b)`), and postfix `?`.
 * Value-producing filters, iterators, recursive descent, calls such as
 * `length`/`paths`, arithmetic, and conditionals fail closed with
 * `path: unsupported path expression`.
 *
 * ──── Deliberate divergences from jq (DO NOT "fix" without operator
 *      sign-off — see HOST-SAFE-RESIDUALS.parts/03-...) ────
 *
 * (a) Postfix `?` on type errors: jq emits `null`; jq emits
 *     nothing (suppresses the value). This is a consequence of
 *     jq's broader "no errors, just null" philosophy — eval_node
 *     paths return null on type mismatch rather than raising an
 *     error that `?` could swallow. Aligning would require an
 *     error-tracking refactor of every node-eval path. Pending if
 *     operator demand surfaces.
 *
 * (b) `+` between mismatched scalars: jq's N_ADD coerces both
 *     sides via strtod and emits a numeric result (typically `0`).
 *     jq errors. The current behavior is silently wrong for
 *     unintentional type mismatches; fixing it changes every
 *     existing `+` invocation in operator scripts. PENDING DECISION —
 *     resolution requires explicit operator sign-off because the
 *     change has wider blast radius than (a) or above.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JSMN_STATIC
#define JSMN_PARENT_LINKS
#include "_jsmn_jsmn.h"

#include "loadables.h"

typedef struct { char *p; size_t n, cap; } sbuf_t;
typedef struct { char **v; int n, cap; } vals_t;

static int
slurp_fd (int fd, char **out, size_t *out_len)
{
  size_t cap = 8192, n = 0;
  char *buf = malloc (cap + 1);
  if (!buf) return -1;
  for (;;)
    {
      if (n + 4096 + 1 > cap)
        {
          cap *= 2;
          char *nb = realloc (buf, cap + 1);
          if (!nb) { free (buf); return -1; }
          buf = nb;
        }
      ssize_t k = read (fd, buf + n, cap - n);
      if (k < 0)
        {
          if (errno == EINTR) continue;
          free (buf); return -1;
        }
      if (k == 0) break;
      n += (size_t) k;
    }
  buf[n] = '\0';
  *out = buf; *out_len = n;
  return 0;
}

static int
slurp_file (const char *path, char **out, size_t *out_len)
{
  FILE *f = fopen (path, "rb");
  if (!f) return -1;
  size_t cap = 8192, n = 0;
  char *buf = malloc (cap + 1);
  if (!buf) { fclose (f); return -1; }
  for (;;)
    {
      if (n + 4096 + 1 > cap)
        {
          cap *= 2;
          char *nb = realloc (buf, cap + 1);
          if (!nb) { free (buf); fclose (f); return -1; }
          buf = nb;
        }
      size_t k = fread (buf + n, 1, cap - n, f);
      n += k;
      if (k == 0)
        {
          if (ferror (f)) { free (buf); fclose (f); return -1; }
          break;
        }
    }
  fclose (f);
  buf[n] = '\0';
  *out = buf; *out_len = n;
  return 0;
}

static int
sb_putn (sbuf_t *b, const char *s, size_t n)
{
  if (b->n + n + 1 > b->cap)
    {
      size_t nc = b->cap ? b->cap * 2 : 128;
      while (b->n + n + 1 > nc) nc *= 2;
      char *np = realloc (b->p, nc);
      if (!np) return -1;
      b->p = np; b->cap = nc;
    }
  memcpy (b->p + b->n, s, n);
  b->n += n; b->p[b->n] = '\0';
  return 0;
}

static int sb_puts (sbuf_t *b, const char *s) { return sb_putn (b, s, strlen (s)); }
static char *xstrndup (const char *s, size_t n) { char *p = malloc (n + 1); if (!p) return NULL; memcpy (p, s, n); p[n] = 0; return p; }
static char *xstrdup (const char *s) { return xstrndup (s, strlen (s)); }

static int
vals_add_take (vals_t *vs, char *s)
{
  if (!s) return -1;
  if (vs->n == vs->cap)
    {
      int nc = vs->cap ? vs->cap * 2 : 8;
      char **nv = realloc (vs->v, sizeof *nv * (size_t) nc);
      if (!nv) { free (s); return -1; }
      vs->v = nv; vs->cap = nc;
    }
  vs->v[vs->n++] = s;
  return 0;
}

static int vals_add (vals_t *vs, const char *s) { return vals_add_take (vs, xstrdup (s)); }
static void vals_free (vals_t *vs) { for (int i = 0; i < vs->n; i++) free (vs->v[i]); free (vs->v); vs->v = NULL; vs->n = vs->cap = 0; }

static int jq_validate_primitives (const char *src, jsmntok_t *toks, int ntoks);

static jsmntok_t *
jq_tokenize_json (const char *src, size_t len, int *out_ntoks)
{
  jsmn_parser p;
  int cap = 256;
  jsmntok_t *toks = malloc (sizeof *toks * (size_t) cap);
  if (!toks) return NULL;
  for (;;)
    {
      jsmn_init (&p);
      int r = jsmn_parse (&p, src, len, toks, (unsigned int) cap);
      if (r >= 0)
        {
          if (jq_validate_primitives (src, toks, r) < 0)
            {
              free (toks);
              return NULL;
            }
          *out_ntoks = r;
          return toks;
        }
      if (r == JSMN_ERROR_NOMEM)
        {
          cap *= 2;
          jsmntok_t *nt = realloc (toks, sizeof *toks * (size_t) cap);
          if (!nt) { free (toks); return NULL; }
          toks = nt; continue;
        }
      free (toks); return NULL;
    }
}

static int
jq_skip (jsmntok_t *toks, int idx)
{
  jsmntok_t *t = &toks[idx];
  if (t->type == JSMN_OBJECT)
    {
      int ni = idx + 1;
      for (int i = 0; i < t->size; i++) { ni = jq_skip (toks, ni); ni = jq_skip (toks, ni); }
      return ni;
    }
  if (t->type == JSMN_ARRAY)
    {
      int ni = idx + 1;
      for (int i = 0; i < t->size; i++) ni = jq_skip (toks, ni);
      return ni;
    }
  return idx + 1;
}

static int tok_eq (const char *src, jsmntok_t *t, const char *s)
{
  size_t n = (size_t)(t->end - t->start);
  return strlen (s) == n && strncmp (src + t->start, s, n) == 0;
}

static int
jq_valid_json_number (const char *s, size_t n)
{
  size_t i = 0;

  if (i < n && s[i] == '-') i++;
  if (i >= n) return 0;

  if (s[i] == '0')
    {
      i++;
      if (i < n && isdigit ((unsigned char) s[i])) return 0;
    }
  else if (s[i] >= '1' && s[i] <= '9')
    {
      while (i < n && isdigit ((unsigned char) s[i])) i++;
    }
  else
    return 0;

  if (i < n && s[i] == '.')
    {
      i++;
      if (i >= n || !isdigit ((unsigned char) s[i])) return 0;
      while (i < n && isdigit ((unsigned char) s[i])) i++;
    }

  if (i < n && (s[i] == 'e' || s[i] == 'E'))
    {
      i++;
      if (i < n && (s[i] == '+' || s[i] == '-')) i++;
      if (i >= n || !isdigit ((unsigned char) s[i])) return 0;
      while (i < n && isdigit ((unsigned char) s[i])) i++;
    }

  return i == n;
}

static int
jq_validate_primitives (const char *src, jsmntok_t *toks, int ntoks)
{
  for (int i = 0; i < ntoks; i++)
    {
      jsmntok_t *t = &toks[i];
      size_t n;
      const char *s;

      if (t->type != JSMN_PRIMITIVE)
        continue;

      n = (size_t)(t->end - t->start);
      s = src + t->start;

      if ((n == 4 && strncmp (s, "true", 4) == 0)
          || (n == 4 && strncmp (s, "null", 4) == 0)
          || (n == 5 && strncmp (s, "false", 5) == 0))
        continue;

      if (!jq_valid_json_number (s, n))
        return -1;
    }

  return 0;
}

static int
jq_validate_json_document (const char *doc)
{
  int nt = 0;
  jsmntok_t *toks = jq_tokenize_json (doc, strlen (doc), &nt);
  if (!toks || nt <= 0)
    {
      free (toks);
      return -1;
    }

  size_t end = (size_t) toks[0].end;
  /* jsmn string tokens span the CONTENT only (between the quotes), so a
     top-level JSON string like "x" leaves toks[0].end on the closing quote.
     Advance past it; otherwise the closing quote reads as trailing garbage
     and a valid bare-string document is wrongly rejected (jq accepts it). */
  if (toks[0].type == JSMN_STRING)
    end++;
  while (doc[end] && isspace ((unsigned char) doc[end]))
    end++;
  if (doc[end])
    {
      free (toks);
      return -1;
    }

  free (toks);
  return 0;
}

static int
emit_tok_to (sbuf_t *b, const char *src, jsmntok_t *t)
{
  if (t->type == JSMN_STRING && sb_puts (b, "\"") < 0) return -1;
  if (sb_putn (b, src + t->start, (size_t)(t->end - t->start)) < 0) return -1;
  if (t->type == JSMN_STRING && sb_puts (b, "\"") < 0) return -1;
  return 0;
}

static char *
tok_json (const char *src, jsmntok_t *t)
{
  sbuf_t b = {0};
  if (emit_tok_to (&b, src, t) < 0) { free (b.p); return NULL; }
  return b.p ? b.p : xstrdup ("");
}

static const char *
json_type (const char *v)
{
  if (!v) return "unknown";
  if (!strcmp (v, "null")) return "null";
  if (!strcmp (v, "true") || !strcmp (v, "false")) return "boolean";
  if (v[0] == '"') return "string";
  if (v[0] == '[') return "array";
  if (v[0] == '{') return "object";
  char *end = NULL; strtod (v, &end);
  return end && *end == 0 && end != v ? "number" : "unknown";
}

static int
jq_key_string_cmp (const void *a, const void *b)
{
  const char *ka = *(const char * const *)a;
  const char *kb = *(const char * const *)b;
  return strcmp (ka ? ka : "", kb ? kb : "");
}

static int truthy (const char *v) { return v && strcmp (v, "false") && strcmp (v, "null"); }

static char *
json_string (const char *s)
{
  sbuf_t b = {0};
  if (sb_puts (&b, "\"") < 0) goto oom;
  for (const unsigned char *p = (const unsigned char *)s; *p; p++)
    {
      char tmp[8];
      switch (*p)
        {
        case '\\': if (sb_puts (&b, "\\\\") < 0) goto oom; break;
        case '"':  if (sb_puts (&b, "\\\"") < 0) goto oom; break;
        case '\n': if (sb_puts (&b, "\\n") < 0) goto oom; break;
        case '\t': if (sb_puts (&b, "\\t") < 0) goto oom; break;
        case '\r': if (sb_puts (&b, "\\r") < 0) goto oom; break;
        default:
          if (*p < 0x20) { snprintf (tmp, sizeof tmp, "\\u%04x", *p); if (sb_puts (&b, tmp) < 0) goto oom; }
          else if (sb_putn (&b, (const char *)p, 1) < 0) goto oom;
        }
    }
  if (sb_puts (&b, "\"") < 0) goto oom;
  return b.p;
oom:
  free (b.p); return NULL;
}

static char *
json_unstring (const char *v)
{
  size_t n = strlen (v);
  if (n < 2 || v[0] != '"' || v[n-1] != '"') return NULL;
  sbuf_t b = {0};
  for (size_t i = 1; i + 1 < n; i++)
    {
      char c = v[i];
      if (c == '\\' && i + 1 < n - 1)
        {
          c = v[++i];
          switch (c)
            {
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'r': c = '\r'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            default: break;
            }
        }
      if (sb_putn (&b, &c, 1) < 0) { free (b.p); return NULL; }
    }
  return b.p ? b.p : xstrdup ("");
}

typedef enum {
  FT_EOF, FT_DOT, FT_PIPE, FT_LP, FT_RP, FT_LB, FT_RB, FT_Q, FT_PLUS, FT_MINUS, FT_MUL, FT_DIV, FT_MOD,
  FT_DEFAULT, FT_EQ, FT_NE, FT_LT, FT_LE, FT_GT, FT_GE, FT_IDENT, FT_NUMBER, FT_STRING,
  FT_IF, FT_THEN, FT_ELIF, FT_ELSE, FT_END, FT_AND, FT_OR, FT_TRUE, FT_FALSE, FT_NULL,
  /* Wave 5 (2026-05-26): comma value-stream operator + semicolon
     multi-arg call separator. Previously both were lex-rejected. */
  FT_COMMA, FT_SEMI,
  /* Wave 6 (2026-05-26): recursive descent token `..`. Previously
     lex-rejected with a "use system+ jq" diagnostic. */
  FT_RECURSE
} ftok_t;

typedef struct { ftok_t t; char *v; } token_t;
typedef struct { token_t *v; int n, cap, pos; char err[256]; } lexer_t;

static int
lex_add (lexer_t *lx, ftok_t t, const char *s, size_t n)
{
  if (lx->n == lx->cap)
    {
      int nc = lx->cap ? lx->cap * 2 : 32;
      token_t *nv = realloc (lx->v, sizeof *nv * (size_t) nc);
      if (!nv) return -1;
      lx->v = nv; lx->cap = nc;
    }
  lx->v[lx->n].t = t;
  lx->v[lx->n].v = s ? xstrndup (s, n) : NULL;
  if (s && !lx->v[lx->n].v) return -1;
  lx->n++;
  return 0;
}

static int
lex_err (lexer_t *lx, const char *msg)
{
  snprintf (lx->err, sizeof lx->err, "%s", msg);
  return -1;
}

static int
lex_filter (lexer_t *lx, const char *s)
{
  for (size_t i = 0; s[i]; )
    {
      unsigned char c = (unsigned char)s[i];
      if (isspace (c)) { i++; continue; }
      /* Wave 6 (2026-05-26): `..` recursive descent — was lex-rejected.
         Now emits FT_RECURSE, which parse_primary lifts into N_RECURSE.
         Must be checked BEFORE the single-dot case so `.` doesn't win. */
      if (c == '.' && s[i+1] == '.') { if (lex_add (lx, FT_RECURSE, NULL, 0) < 0) return -1; i += 2; continue; }
      if (c == '{' || c == '}') return lex_err (lx, "object construction not supported; use system+ jq.");
      switch (c)
        {
        case '.': if (lex_add (lx, FT_DOT, NULL, 0) < 0) return -1; i++; continue;
        case '|': if (lex_add (lx, FT_PIPE, NULL, 0) < 0) return -1; i++; continue;
        /* Wave 5 (2026-05-26): comma operator + semicolon call-arg
           separator — were lex-rejected by pre-Wave-5 jq with a
           "use system+ jq" diagnostic. */
        case ',': if (lex_add (lx, FT_COMMA, NULL, 0) < 0) return -1; i++; continue;
        case ';': if (lex_add (lx, FT_SEMI, NULL, 0) < 0) return -1; i++; continue;
        case '(': if (lex_add (lx, FT_LP, NULL, 0) < 0) return -1; i++; continue;
        case ')': if (lex_add (lx, FT_RP, NULL, 0) < 0) return -1; i++; continue;
        case '[': if (lex_add (lx, FT_LB, NULL, 0) < 0) return -1; i++; continue;
        case ']': if (lex_add (lx, FT_RB, NULL, 0) < 0) return -1; i++; continue;
        case '?': if (lex_add (lx, FT_Q, NULL, 0) < 0) return -1; i++; continue;
        case '+': if (lex_add (lx, FT_PLUS, NULL, 0) < 0) return -1; i++; continue;
        case '-': if (lex_add (lx, FT_MINUS, NULL, 0) < 0) return -1; i++; continue;
        case '*': if (lex_add (lx, FT_MUL, NULL, 0) < 0) return -1; i++; continue;
        case '%': if (lex_add (lx, FT_MOD, NULL, 0) < 0) return -1; i++; continue;
        case '/':
          if (s[i+1] == '/') { if (lex_add (lx, FT_DEFAULT, NULL, 0) < 0) return -1; i += 2; }
          else { if (lex_add (lx, FT_DIV, NULL, 0) < 0) return -1; i++; }
          continue;
        case '=':
          if (s[i+1] != '=') return lex_err (lx, "expected ==");
          if (lex_add (lx, FT_EQ, NULL, 0) < 0) return -1;
          i += 2;
          continue;
        case '!':
          if (s[i+1] != '=') return lex_err (lx, "expected !=");
          if (lex_add (lx, FT_NE, NULL, 0) < 0) return -1;
          i += 2;
          continue;
        case '<':
          if (s[i+1] == '=') { if (lex_add (lx, FT_LE, NULL, 0) < 0) return -1; i += 2; }
          else { if (lex_add (lx, FT_LT, NULL, 0) < 0) return -1; i++; }
          continue;
        case '>':
          if (s[i+1] == '=') { if (lex_add (lx, FT_GE, NULL, 0) < 0) return -1; i += 2; }
          else { if (lex_add (lx, FT_GT, NULL, 0) < 0) return -1; i++; }
          continue;
        case '"':
          {
            size_t st = i++;
            while (s[i])
              {
                if (s[i] == '\\' && s[i+1]) { i += 2; continue; }
                if (s[i] == '"') { i++; break; }
                i++;
              }
            if (s[i-1] != '"') return lex_err (lx, "unterminated string");
            if (lex_add (lx, FT_STRING, s + st, i - st) < 0) return -1;
            continue;
          }
        default: break;
        }
      if (isdigit (c))
        {
          size_t st = i++;
          while (isdigit ((unsigned char)s[i])) i++;
          if (s[i] == '.' && isdigit ((unsigned char)s[i+1])) { i++; while (isdigit ((unsigned char)s[i])) i++; }
          if (s[i] == 'e' || s[i] == 'E') { i++; if (s[i] == '+' || s[i] == '-') i++; while (isdigit ((unsigned char)s[i])) i++; }
          if (lex_add (lx, FT_NUMBER, s + st, i - st) < 0) return -1;
          continue;
        }
      if (isalpha (c) || c == '_')
        {
          size_t st = i++;
          while (isalnum ((unsigned char)s[i]) || s[i] == '_') i++;
          size_t n = i - st;
          ftok_t t = FT_IDENT;
          if (n == 2 && !strncmp (s + st, "if", n)) t = FT_IF;
          else if (n == 4 && !strncmp (s + st, "then", n)) t = FT_THEN;
          else if (n == 4 && !strncmp (s + st, "elif", n)) t = FT_ELIF;
          else if (n == 4 && !strncmp (s + st, "else", n)) t = FT_ELSE;
          else if (n == 3 && !strncmp (s + st, "end", n)) t = FT_END;
          else if (n == 3 && !strncmp (s + st, "and", n)) t = FT_AND;
          else if (n == 2 && !strncmp (s + st, "or", n)) t = FT_OR;
          else if (n == 4 && !strncmp (s + st, "true", n)) t = FT_TRUE;
          else if (n == 5 && !strncmp (s + st, "false", n)) t = FT_FALSE;
          else if (n == 4 && !strncmp (s + st, "null", n)) t = FT_NULL;
          if (lex_add (lx, t, t == FT_IDENT ? s + st : NULL, t == FT_IDENT ? n : 0) < 0) return -1;
          continue;
        }
      snprintf (lx->err, sizeof lx->err, "unexpected character '%c'", c);
      return -1;
    }
  return lex_add (lx, FT_EOF, NULL, 0);
}

typedef enum {
  N_ROOT, N_LITERAL, N_FIELD, N_INDEX, N_ITER, N_PIPE, N_DEFAULT, N_CALL_LENGTH, N_CALL_KEYS, N_CALL_TYPE,
  N_CALL_HAS, N_CALL_SELECT, N_CALL_MAP, N_CALL_NOT, N_CMP_EQ, N_CMP_NE, N_CMP_LT, N_CMP_LE, N_CMP_GT, N_CMP_GE,
  N_AND, N_OR, N_ADD, N_SUB, N_MUL, N_DIV, N_MOD, N_NEG, N_IF, N_TRY,
  /* HOST-SAFE-RESIDUALS Wave 3 (2026-05-26): 0-arg filter dispatchers.
     Each value below is a single identifier with no parsed args. */
  N_CALL_FIRST, N_CALL_LAST, N_CALL_REVERSE, N_CALL_ADD,
  N_CALL_MIN, N_CALL_MAX, N_CALL_SORT, N_CALL_UNIQUE,
  N_CALL_TO_ENTRIES, N_CALL_FROM_ENTRIES,
  N_CALL_TOSTRING, N_CALL_TONUMBER, N_CALL_TOJSON, N_CALL_FROMJSON,
  N_CALL_ASCII_DOWNCASE, N_CALL_ASCII_UPCASE,
  N_CALL_FLOOR, N_CALL_CEIL, N_CALL_FABS, N_CALL_SQRT,
  /* HOST-SAFE-RESIDUALS Wave 4 (2026-05-26): 2 zero-arg math + 8 single-
     arg string/value filters parsed with the has(EXPR) call form. */
  N_CALL_EXP, N_CALL_LOG,
  N_CALL_LTRIMSTR, N_CALL_RTRIMSTR, N_CALL_STARTSWITH, N_CALL_ENDSWITH,
  N_CALL_CONTAINS, N_CALL_SPLIT, N_CALL_JOIN, N_CALL_SPLITS,
  /* HOST-SAFE-RESIDUALS Wave 5 (2026-05-26): comma-stream + multi-arg
     filter dispatchers. N_COMMA is the value-stream concat operator.
     N_CALL_RANGE accepts 1/2/3 args (a/b/c slots — NULL = absent).
     The others have fixed arities encoded by the slots they use.
     N_ARRAY collects the value stream of its child filter into an
     array literal (`[E]` syntax; empty `[]` ⇒ N_ARRAY with a NULL
     child). Required to make path-array arguments to getpath/
     setpath/delpaths usable. N_CALL_PATH is jq's path(F) for the
     supported exact path-expression subset. */
  N_COMMA, N_ARRAY,
  N_CALL_RANGE, N_CALL_NTH, N_CALL_GETPATH, N_CALL_SETPATH,
  N_CALL_DELPATHS, N_CALL_POW, N_CALL_PATH,
  /* HOST-SAFE-RESIDUALS Wave 6 (2026-05-26): recursive descent +
     path enumerators. N_RECURSE walks the input and yields every
     reachable value; N_CALL_PATHS / N_CALL_LEAF_PATHS yield every
     path-to-sub-value as a JSON array of components. recurse and
     recurse_down map to N_RECURSE (no separate node — identical
     semantics). */
  N_RECURSE, N_CALL_PATHS, N_CALL_LEAF_PATHS
} nkind_t;

typedef struct node { nkind_t k; struct node *a, *b, *c; char *s; } node_t;

static node_t *node_new (nkind_t k, node_t *a, node_t *b, node_t *c, const char *s)
{
  node_t *n = calloc (1, sizeof *n);
  if (!n) return NULL;
  n->k = k; n->a = a; n->b = b; n->c = c; n->s = s ? xstrdup (s) : NULL;
  return n;
}
static void node_free (node_t *n) { if (!n) return; node_free (n->a); node_free (n->b); node_free (n->c); free (n->s); free (n); }

typedef struct { lexer_t *lx; char err[256]; } parser_t;
static token_t *peek (parser_t *p) { return &p->lx->v[p->lx->pos]; }
static int accept (parser_t *p, ftok_t t) { if (peek (p)->t == t) { p->lx->pos++; return 1; } return 0; }
static int expect (parser_t *p, ftok_t t) { if (accept (p, t)) return 1; snprintf (p->err, sizeof p->err, "unexpected token"); return 0; }

static node_t *parse_expr (parser_t *p);

/* Wave 5 (2026-05-26): parse a `;`-separated argument list at a call
   site. Reads `( EXPR [; EXPR [; EXPR]] )` and stuffs args into
   out[0..*nout]. min/max enforce the filter's documented arity. On
   error returns -1 and frees any args already parsed. */
static int
parse_call_args (parser_t *p, int min_args, int max_args,
                 node_t **out, int *nout)
{
  *nout = 0;
  if (!expect (p, FT_LP)) return -1;
  for (;;)
    {
      if (*nout >= max_args)
        { snprintf (p->err, sizeof p->err, "too many args (max %d)", max_args);
          for (int i = 0; i < *nout; i++) node_free (out[i]);
          return -1; }
      node_t *a = parse_expr (p);
      if (!a)
        { for (int i = 0; i < *nout; i++) node_free (out[i]); return -1; }
      out[(*nout)++] = a;
      if (accept (p, FT_SEMI)) continue;
      break;
    }
  if (!expect (p, FT_RP) || *nout < min_args)
    { if (*nout < min_args) snprintf (p->err, sizeof p->err, "too few args (min %d)", min_args);
      for (int i = 0; i < *nout; i++) node_free (out[i]);
      return -1; }
  return 0;
}

/* PATH-KEY (2026-06-15): jq string-form field access (."k" and
   .["k"]).  The FT_STRING token value is the RAW bytes between the
   quotes INCLUDING the surrounding quote chars and WITHOUT escape
   decoding (lexer line ~562).  N_FIELD's eval calls
   json_resolve_field()->tok_eq(), which byte-compares against the
   literal JSON key bytes, so the key we hand to node_new must be the
   bare (unquoted) content.  Strip only the two outer quote chars;
   the returned buffer is freshly malloc'd and owned by the caller
   (node_new xstrdup's its `s` arg, exactly like the FT_IDENT path,
   so the caller frees this temporary). */
static char *
jq_strkey (const char *tokval)
{
  size_t n = strlen (tokval);
  if (n >= 2 && tokval[0] == '"' && tokval[n-1] == '"')
    return xstrndup (tokval + 1, n - 2);
  return xstrdup (tokval);
}

static node_t *
parse_path_tail (parser_t *p, node_t *base)
{
  for (;;)
    {
      if (accept (p, FT_DOT))
        {
          if (peek (p)->t == FT_IDENT)
            { char *f = peek (p)->v; p->lx->pos++; base = node_new (N_FIELD, base, NULL, NULL, f); }
          else if (peek (p)->t == FT_STRING)
            { char *f = jq_strkey (peek (p)->v); p->lx->pos++; base = node_new (N_FIELD, base, NULL, NULL, f); free (f); }
          else if (accept (p, FT_LB))
            {
              if (accept (p, FT_RB)) base = node_new (N_ITER, base, NULL, NULL, NULL);
              else if (peek (p)->t == FT_STRING) { char *f = jq_strkey (peek (p)->v); p->lx->pos++; if (!expect (p, FT_RB)) { free (f); goto bad; } base = node_new (N_FIELD, base, NULL, NULL, f); free (f); }
              else { if (peek (p)->t != FT_NUMBER) goto bad; char *idx = peek (p)->v; p->lx->pos++; if (!expect (p, FT_RB)) goto bad; base = node_new (N_INDEX, base, NULL, NULL, idx); }
            }
          else goto bad;
        }
      else if (accept (p, FT_LB))
        {
          if (accept (p, FT_RB)) base = node_new (N_ITER, base, NULL, NULL, NULL);
          else if (peek (p)->t == FT_STRING) { char *f = jq_strkey (peek (p)->v); p->lx->pos++; if (!expect (p, FT_RB)) { free (f); goto bad; } base = node_new (N_FIELD, base, NULL, NULL, f); free (f); }
          else { if (peek (p)->t != FT_NUMBER) goto bad; char *idx = peek (p)->v; p->lx->pos++; if (!expect (p, FT_RB)) goto bad; base = node_new (N_INDEX, base, NULL, NULL, idx); }
        }
      else break;
      if (!base) return NULL;
    }
  return base;
bad:
  snprintf (p->err, sizeof p->err, "bad path expression");
  node_free (base); return NULL;
}

static node_t *
parse_if_tail (parser_t *p)
{
  node_t *cond = parse_expr (p);
  if (!cond || !expect (p, FT_THEN)) { node_free (cond); return NULL; }
  node_t *tb = parse_expr (p), *eb = NULL;
  if (!tb) { node_free (cond); return NULL; }
  if (accept (p, FT_ELIF)) eb = parse_if_tail (p);
  else if (accept (p, FT_ELSE)) { eb = parse_expr (p); if (!expect (p, FT_END)) { node_free (cond); node_free (tb); node_free (eb); return NULL; } }
  else { snprintf (p->err, sizeof p->err, "expected else or elif"); node_free (cond); node_free (tb); return NULL; }
  if (!eb) { node_free (cond); node_free (tb); return NULL; }
  return node_new (N_IF, cond, tb, eb, NULL);
}

static node_t *
parse_primary (parser_t *p)
{
  token_t *t = peek (p);
  if (accept (p, FT_DOT))
    {
      node_t *base = node_new (N_ROOT, NULL, NULL, NULL, NULL);
      if (peek (p)->t == FT_IDENT) { char *f = peek (p)->v; p->lx->pos++; base = node_new (N_FIELD, base, NULL, NULL, f); }
      else if (peek (p)->t == FT_STRING) { char *f = jq_strkey (peek (p)->v); p->lx->pos++; base = node_new (N_FIELD, base, NULL, NULL, f); free (f); }
      else if (accept (p, FT_LB))
        {
          if (accept (p, FT_RB)) base = node_new (N_ITER, base, NULL, NULL, NULL);
          else if (peek (p)->t == FT_STRING) { char *f = jq_strkey (peek (p)->v); p->lx->pos++; if (!expect (p, FT_RB)) { free (f); goto bad; } base = node_new (N_FIELD, base, NULL, NULL, f); free (f); }
          else { if (peek (p)->t != FT_NUMBER) goto bad; char *idx = peek (p)->v; p->lx->pos++; if (!expect (p, FT_RB)) goto bad; base = node_new (N_INDEX, base, NULL, NULL, idx); }
        }
      return parse_path_tail (p, base);
    }
  /* Wave 6 (2026-05-26): top-level `..` recursive descent. Standalone
     primary — does NOT chain into parse_path_tail (jq rejects `.a..`
     too). Equivalent to the `recurse` / `recurse_down` identifiers. */
  if (accept (p, FT_RECURSE)) return node_new (N_RECURSE, NULL, NULL, NULL, NULL);
  if (accept (p, FT_LP)) { node_t *n = parse_expr (p); if (!expect (p, FT_RP)) { node_free (n); return NULL; } return parse_path_tail (p, n); }
  /* Wave 5 (2026-05-26): array construction `[E]` collects the value
     stream of E into an array. Empty `[]` is the empty-array literal.
     Required for path-array arguments to getpath/setpath/delpaths. */
  if (accept (p, FT_LB))
    {
      if (accept (p, FT_RB))
        return node_new (N_ARRAY, NULL, NULL, NULL, NULL);
      node_t *inner = parse_expr (p);
      if (!inner || !expect (p, FT_RB)) { node_free (inner); return NULL; }
      return node_new (N_ARRAY, inner, NULL, NULL, NULL);
    }
  if (t->t == FT_NUMBER || t->t == FT_STRING) { p->lx->pos++; return node_new (N_LITERAL, NULL, NULL, NULL, t->v); }
  if (accept (p, FT_TRUE)) return node_new (N_LITERAL, NULL, NULL, NULL, "true");
  if (accept (p, FT_FALSE)) return node_new (N_LITERAL, NULL, NULL, NULL, "false");
  if (accept (p, FT_NULL)) return node_new (N_LITERAL, NULL, NULL, NULL, "null");
  if (accept (p, FT_IF)) return parse_if_tail (p);
  if (t->t == FT_IDENT)
    {
      char *name = t->v; p->lx->pos++;
      if (!strcmp (name, "length")) return node_new (N_CALL_LENGTH, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "keys")) return node_new (N_CALL_KEYS, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "type")) return node_new (N_CALL_TYPE, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "not")) return node_new (N_CALL_NOT, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "has")) { if (!expect (p, FT_LP)) return NULL; node_t *a = parse_expr (p); if (!expect (p, FT_RP)) { node_free (a); return NULL; } return node_new (N_CALL_HAS, a, NULL, NULL, NULL); }
      if (!strcmp (name, "select")) { if (!expect (p, FT_LP)) return NULL; node_t *a = parse_expr (p); if (!expect (p, FT_RP)) { node_free (a); return NULL; } return node_new (N_CALL_SELECT, a, NULL, NULL, NULL); }
      if (!strcmp (name, "map")) { if (!expect (p, FT_LP)) return NULL; node_t *a = parse_expr (p); if (!expect (p, FT_RP)) { node_free (a); return NULL; } return node_new (N_CALL_MAP, a, NULL, NULL, NULL); }
      /* HOST-SAFE-RESIDUALS Wave 3 (2026-05-26): 0-arg jq filter dispatch. */
      if (!strcmp (name, "first")) return node_new (N_CALL_FIRST, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "last")) return node_new (N_CALL_LAST, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "reverse")) return node_new (N_CALL_REVERSE, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "add")) return node_new (N_CALL_ADD, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "min")) return node_new (N_CALL_MIN, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "max")) return node_new (N_CALL_MAX, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "sort")) return node_new (N_CALL_SORT, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "unique")) return node_new (N_CALL_UNIQUE, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "to_entries")) return node_new (N_CALL_TO_ENTRIES, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "from_entries")) return node_new (N_CALL_FROM_ENTRIES, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "tostring")) return node_new (N_CALL_TOSTRING, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "tonumber")) return node_new (N_CALL_TONUMBER, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "tojson")) return node_new (N_CALL_TOJSON, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "fromjson")) return node_new (N_CALL_FROMJSON, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "ascii_downcase")) return node_new (N_CALL_ASCII_DOWNCASE, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "ascii_upcase")) return node_new (N_CALL_ASCII_UPCASE, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "floor")) return node_new (N_CALL_FLOOR, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "ceil")) return node_new (N_CALL_CEIL, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "fabs")) return node_new (N_CALL_FABS, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "sqrt")) return node_new (N_CALL_SQRT, NULL, NULL, NULL, NULL);
      /* HOST-SAFE-RESIDUALS Wave 4 (2026-05-26): 0-arg math + 1-arg string filters. */
      if (!strcmp (name, "exp")) return node_new (N_CALL_EXP, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "log")) return node_new (N_CALL_LOG, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "ltrimstr")) { if (!expect (p, FT_LP)) return NULL; node_t *a = parse_expr (p); if (!expect (p, FT_RP)) { node_free (a); return NULL; } return node_new (N_CALL_LTRIMSTR, a, NULL, NULL, NULL); }
      if (!strcmp (name, "rtrimstr")) { if (!expect (p, FT_LP)) return NULL; node_t *a = parse_expr (p); if (!expect (p, FT_RP)) { node_free (a); return NULL; } return node_new (N_CALL_RTRIMSTR, a, NULL, NULL, NULL); }
      if (!strcmp (name, "startswith")) { if (!expect (p, FT_LP)) return NULL; node_t *a = parse_expr (p); if (!expect (p, FT_RP)) { node_free (a); return NULL; } return node_new (N_CALL_STARTSWITH, a, NULL, NULL, NULL); }
      if (!strcmp (name, "endswith")) { if (!expect (p, FT_LP)) return NULL; node_t *a = parse_expr (p); if (!expect (p, FT_RP)) { node_free (a); return NULL; } return node_new (N_CALL_ENDSWITH, a, NULL, NULL, NULL); }
      if (!strcmp (name, "contains")) { if (!expect (p, FT_LP)) return NULL; node_t *a = parse_expr (p); if (!expect (p, FT_RP)) { node_free (a); return NULL; } return node_new (N_CALL_CONTAINS, a, NULL, NULL, NULL); }
      if (!strcmp (name, "split")) { if (!expect (p, FT_LP)) return NULL; node_t *a = parse_expr (p); if (!expect (p, FT_RP)) { node_free (a); return NULL; } return node_new (N_CALL_SPLIT, a, NULL, NULL, NULL); }
      if (!strcmp (name, "join")) { if (!expect (p, FT_LP)) return NULL; node_t *a = parse_expr (p); if (!expect (p, FT_RP)) { node_free (a); return NULL; } return node_new (N_CALL_JOIN, a, NULL, NULL, NULL); }
      if (!strcmp (name, "splits")) { if (!expect (p, FT_LP)) return NULL; node_t *a = parse_expr (p); if (!expect (p, FT_RP)) { node_free (a); return NULL; } return node_new (N_CALL_SPLITS, a, NULL, NULL, NULL); }
      /* HOST-SAFE-RESIDUALS Wave 5 (2026-05-26): multi-arg call form
         using the new `;` separator. Each filter declares its arity
         range; parse_call_args enforces. */
      if (!strcmp (name, "range"))
        {
          node_t *args[3]; int na = 0;
          if (parse_call_args (p, 1, 3, args, &na) < 0) return NULL;
          return node_new (N_CALL_RANGE, args[0],
                           na >= 2 ? args[1] : NULL,
                           na >= 3 ? args[2] : NULL, NULL);
        }
      if (!strcmp (name, "nth"))
        {
          node_t *args[2]; int na = 0;
          if (parse_call_args (p, 2, 2, args, &na) < 0) return NULL;
          return node_new (N_CALL_NTH, args[0], args[1], NULL, NULL);
        }
      if (!strcmp (name, "getpath"))
        {
          node_t *args[1]; int na = 0;
          if (parse_call_args (p, 1, 1, args, &na) < 0) return NULL;
          return node_new (N_CALL_GETPATH, args[0], NULL, NULL, NULL);
        }
      if (!strcmp (name, "setpath"))
        {
          node_t *args[2]; int na = 0;
          if (parse_call_args (p, 2, 2, args, &na) < 0) return NULL;
          return node_new (N_CALL_SETPATH, args[0], args[1], NULL, NULL);
        }
      if (!strcmp (name, "delpaths"))
        {
          node_t *args[1]; int na = 0;
          if (parse_call_args (p, 1, 1, args, &na) < 0) return NULL;
          return node_new (N_CALL_DELPATHS, args[0], NULL, NULL, NULL);
        }
      if (!strcmp (name, "pow"))
        {
          node_t *args[2]; int na = 0;
          if (parse_call_args (p, 2, 2, args, &na) < 0) return NULL;
          return node_new (N_CALL_POW, args[0], args[1], NULL, NULL);
        }
      if (!strcmp (name, "path"))
        {
          node_t *args[1]; int na = 0;
          if (parse_call_args (p, 1, 1, args, &na) < 0) return NULL;
          return node_new (N_CALL_PATH, args[0], NULL, NULL, NULL);
        }
      /* HOST-SAFE-RESIDUALS Wave 6 (2026-05-26): recurse / recurse_down
         are 0-arg aliases for `..`. paths / leaf_paths are 0-arg path
         enumerators. None take a call-arg list. */
      if (!strcmp (name, "recurse")) return node_new (N_RECURSE, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "recurse_down")) return node_new (N_RECURSE, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "paths")) return node_new (N_CALL_PATHS, NULL, NULL, NULL, NULL);
      if (!strcmp (name, "leaf_paths")) return node_new (N_CALL_LEAF_PATHS, NULL, NULL, NULL, NULL);
      snprintf (p->err, sizeof p->err, "unknown identifier: %s (use system+ jq for full builtins)", name);
      return NULL;
    }
bad:
  snprintf (p->err, sizeof p->err, "unexpected token");
  return NULL;
}

static node_t *parse_postfix (parser_t *p) { node_t *n = parse_primary (p); while (n && accept (p, FT_Q)) n = node_new (N_TRY, n, NULL, NULL, NULL); return n; }
static node_t *parse_unary (parser_t *p) { if (accept (p, FT_MINUS)) return node_new (N_NEG, parse_unary (p), NULL, NULL, NULL); return parse_postfix (p); }

static node_t *
parse_mul (parser_t *p)
{
  node_t *n = parse_unary (p);
  while (n)
    {
      nkind_t k; if (accept (p, FT_MUL)) k = N_MUL; else if (accept (p, FT_DIV)) k = N_DIV; else if (accept (p, FT_MOD)) k = N_MOD; else break;
      n = node_new (k, n, parse_unary (p), NULL, NULL);
    }
  return n;
}
static node_t *
parse_add (parser_t *p)
{
  node_t *n = parse_mul (p);
  while (n)
    {
      nkind_t k; if (accept (p, FT_PLUS)) k = N_ADD; else if (accept (p, FT_MINUS)) k = N_SUB; else break;
      n = node_new (k, n, parse_mul (p), NULL, NULL);
    }
  return n;
}
static node_t *
parse_cmp (parser_t *p)
{
  node_t *n = parse_add (p); if (!n) return NULL;
  nkind_t k;
  if (accept (p, FT_EQ)) k = N_CMP_EQ; else if (accept (p, FT_NE)) k = N_CMP_NE; else if (accept (p, FT_LT)) k = N_CMP_LT;
  else if (accept (p, FT_LE)) k = N_CMP_LE; else if (accept (p, FT_GT)) k = N_CMP_GT; else if (accept (p, FT_GE)) k = N_CMP_GE; else return n;
  return node_new (k, n, parse_add (p), NULL, NULL);
}
static node_t *parse_and (parser_t *p) { node_t *n = parse_cmp (p); while (n && accept (p, FT_AND)) n = node_new (N_AND, n, parse_cmp (p), NULL, NULL); return n; }
static node_t *parse_or (parser_t *p) { node_t *n = parse_and (p); while (n && accept (p, FT_OR)) n = node_new (N_OR, n, parse_and (p), NULL, NULL); return n; }
static node_t *parse_default (parser_t *p) { node_t *n = parse_or (p); if (n && accept (p, FT_DEFAULT)) n = node_new (N_DEFAULT, n, parse_default (p), NULL, NULL); return n; }
/* Wave 5 (2026-05-26): comma value-stream operator. Left-associative,
   tighter than pipe (so `.a | .b, .c` is `.a | (.b, .c)`), looser than
   the default `//` and below it. Right-recursion would also work but a
   while-loop keeps the AST balanced. */
static node_t *parse_comma (parser_t *p) { node_t *n = parse_default (p); while (n && accept (p, FT_COMMA)) n = node_new (N_COMMA, n, parse_default (p), NULL, NULL); return n; }
static node_t *parse_pipe (parser_t *p) { node_t *n = parse_comma (p); while (n && accept (p, FT_PIPE)) n = node_new (N_PIPE, n, parse_comma (p), NULL, NULL); return n; }
static node_t *parse_expr (parser_t *p) { return parse_pipe (p); }

static int eval_node (node_t *n, const char *in, vals_t *out);

static int
json_resolve_field (const char *json, const char *field, char **out)
{
  int nt = 0; jsmntok_t *toks = jq_tokenize_json (json, strlen (json), &nt);
  if (!toks || nt <= 0 || toks[0].type != JSMN_OBJECT) { free (toks); return -1; }
  int ci = 1, found = -1;
  for (int i = 0; i < toks[0].size; i++)
    {
      int vi = ci + 1;
      if (toks[ci].type == JSMN_STRING && tok_eq (json, &toks[ci], field)) { found = vi; break; }
      ci = jq_skip (toks, vi);
    }
  if (found >= 0) *out = tok_json (json, &toks[found]);
  free (toks);
  return found >= 0 && *out ? 0 : -1;
}

static int
json_resolve_index (const char *json, int want, char **out)
{
  int nt = 0; jsmntok_t *toks = jq_tokenize_json (json, strlen (json), &nt);
  if (!toks || nt <= 0 || toks[0].type != JSMN_ARRAY || want < 0 || want >= toks[0].size) { free (toks); return -1; }
  int ci = 1; for (int i = 0; i < want; i++) ci = jq_skip (toks, ci);
  *out = tok_json (json, &toks[ci]);
  free (toks);
  return *out ? 0 : -1;
}

static int
json_array_each (const char *json, vals_t *out)
{
  int nt = 0; jsmntok_t *toks = jq_tokenize_json (json, strlen (json), &nt);
  if (!toks || nt <= 0 || toks[0].type != JSMN_ARRAY) { free (toks); return 0; }
  int ci = 1;
  for (int i = 0; i < toks[0].size; i++) { if (vals_add_take (out, tok_json (json, &toks[ci])) < 0) { free (toks); return -1; } ci = jq_skip (toks, ci); }
  free (toks); return 0;
}

static int
/* HOST-SAFE-RESIDUALS pass 4 fix (2026-05-26): jq parity for `length`.
 *   - numbers: return fabs(value) (jq: "5 | length" → 5; "-7 | length" → 7;
 *              "3.14 | length" → 3.14). Was: byte span of the literal.
 *   - booleans: ERROR (jq: "true | length" → "boolean has no length", rc=5).
 *              Was: byte span (4 or 5).
 *   - everything else: unchanged.
 * *out is now double so float values like 3.14 round-trip through
 * the caller's printf at N_CALL_LENGTH.
 */
json_length (const char *json, double *out)
{
  int nt = 0; jsmntok_t *toks = jq_tokenize_json (json, strlen (json), &nt);
  if (!toks || nt <= 0) { free (toks); return -1; }
  if (toks[0].type == JSMN_ARRAY || toks[0].type == JSMN_OBJECT) *out = (double) toks[0].size;
  else if (toks[0].type == JSMN_STRING) *out = (double) (toks[0].end - toks[0].start);
  else if (toks[0].type == JSMN_PRIMITIVE)
    {
      char first = json[toks[0].start];
      if (first == 'n') { *out = 0; }                  /* null → 0 */
      else if (first == 't' || first == 'f')           /* true/false → error */
        { builtin_error ("length: boolean has no length"); free (toks); return -1; }
      else                                             /* number → abs(value) */
        {
          char *end;
          double v = strtod (json + toks[0].start, &end);
          *out = v < 0 ? -v : v;
        }
    }
  else *out = (double) (toks[0].end - toks[0].start);
  free (toks); return 0;
}

static char *
json_keys_array (const char *json)
{
  int nt = 0; jsmntok_t *toks = jq_tokenize_json (json, strlen (json), &nt);
  if (!toks || nt <= 0 || toks[0].type != JSMN_OBJECT) { free (toks); return NULL; }
  char **keys = (char **)xmalloc ((size_t)toks[0].size * sizeof (char *));
  int nkeys = 0;
  int ci = 1;
  for (int i = 0; i < toks[0].size; i++)
    {
      keys[nkeys++] = tok_json (json, &toks[ci]);
      ci = jq_skip (toks, ci + 1);
    }
  qsort (keys, (size_t)nkeys, sizeof (keys[0]), jq_key_string_cmp);
  sbuf_t b = {0}; sb_puts (&b, "[");
  for (int i = 0; i < nkeys; i++)
    {
      if (i) sb_puts (&b, ",");
      sb_puts (&b, keys[i] ? keys[i] : "\"\"");
      free (keys[i]);
    }
  free (keys);
  sb_puts (&b, "]");
  free (toks); return b.p;
}

static int
json_has (const char *json, const char *key, int *out)
{
  int nt = 0;
  jsmntok_t *toks = jq_tokenize_json (json, strlen (json), &nt);
  if (!toks || nt <= 0)
    { free (toks); return -1; }

  *out = 0;
  if (toks[0].type == JSMN_OBJECT)
    {
      char *field = json_unstring (key);
      if (!field)
        { free (toks); return -1; }
      int ci = 1;
      for (int i = 0; i < toks[0].size; i++)
        {
          int vi = ci + 1;
          char *key_json = toks[ci].type == JSMN_STRING ? tok_json (json, &toks[ci]) : NULL;
          char *object_key = key_json ? json_unstring (key_json) : NULL;
          int match = object_key && !strcmp (object_key, field);
          free (object_key);
          free (key_json);
          if (match)
            {
              *out = 1;
              break;
            }
          ci = jq_skip (toks, vi);
        }
      free (field);
      free (toks);
      return 0;
    }

  if (toks[0].type == JSMN_ARRAY)
    {
      char *end = NULL;
      double d = strtod (key, &end);
      long idx;
      if (!end || *end != '\0')
        { free (toks); return -1; }
      idx = (long)d;
      if (!isfinite (d))
        { free (toks); return -1; }
      *out = idx >= 0 && idx < toks[0].size;
      free (toks);
      return 0;
    }

  free (toks);
  return -1;
}

static char *
json_array_concat (const char *lhs, const char *rhs)
{
  int lnt = 0, rnt = 0;
  jsmntok_t *lt = jq_tokenize_json (lhs, strlen (lhs), &lnt);
  jsmntok_t *rt = jq_tokenize_json (rhs, strlen (rhs), &rnt);
  if (!lt || !rt || lnt <= 0 || rnt <= 0 ||
      lt[0].type != JSMN_ARRAY || rt[0].type != JSMN_ARRAY)
    { free (lt); free (rt); return NULL; }
  sbuf_t b = {0};
  if (sb_puts (&b, "[") < 0) goto oom;
  int first = 1;
  int ci = 1;
  for (int i = 0; i < lt[0].size; i++)
    {
      if (!first && sb_puts (&b, ",") < 0) goto oom;
      if (emit_tok_to (&b, lhs, &lt[ci]) < 0) goto oom;
      first = 0;
      ci = jq_skip (lt, ci);
    }
  ci = 1;
  for (int i = 0; i < rt[0].size; i++)
    {
      if (!first && sb_puts (&b, ",") < 0) goto oom;
      if (emit_tok_to (&b, rhs, &rt[ci]) < 0) goto oom;
      first = 0;
      ci = jq_skip (rt, ci);
    }
  if (sb_puts (&b, "]") < 0) goto oom;
  free (lt); free (rt);
  return b.p;
oom:
  free (b.p); free (lt); free (rt);
  return NULL;
}

static char *
json_slurp_array (const char *src)
{
  size_t len = strlen (src), off = 0;
  sbuf_t b = {0};
  int first = 1;

  if (sb_puts (&b, "[") < 0)
    goto oom;

  while (off < len)
    {
      while (off < len && isspace ((unsigned char)src[off]))
        off++;
      if (off >= len)
        break;

      int nt = 0;
      jsmntok_t *toks = jq_tokenize_json (src + off, len - off, &nt);
      if (!toks || nt <= 0 || toks[0].end < 0)
        {
          free (toks);
          free (b.p);
          return NULL;
        }

      if (!first && sb_puts (&b, ",") < 0)
        {
          free (toks);
          goto oom;
        }
      if (sb_putn (&b, src + off, (size_t)toks[0].end) < 0)
        {
          free (toks);
          goto oom;
        }
      first = 0;
      off += (size_t)toks[0].end;
      free (toks);
    }

  if (sb_puts (&b, "]") < 0)
    goto oom;
  return b.p;

oom:
  free (b.p);
  return NULL;
}

static char *
json_path_append (const char *path, const char *seg)
{
  size_t n = strlen (path);
  sbuf_t b = {0};
  if (n == 0 || path[n - 1] != ']')
    return NULL;
  if (sb_putn (&b, path, n - 1) < 0) goto oom;
  if (n > 2 && sb_puts (&b, ",") < 0) goto oom;
  if (sb_puts (&b, seg) < 0) goto oom;
  if (sb_puts (&b, "]") < 0) goto oom;
  return b.p;
oom:
  free (b.p);
  return NULL;
}

static char *
json_path_concat (const char *left, const char *right)
{
  size_t ln = strlen (left), rn = strlen (right);
  int left_empty = (ln == 2 && left[0] == '[' && left[1] == ']');
  int right_empty = (rn == 2 && right[0] == '[' && right[1] == ']');
  sbuf_t b = {0};

  if (ln < 2 || rn < 2 || left[0] != '[' || left[ln - 1] != ']'
      || right[0] != '[' || right[rn - 1] != ']')
    return NULL;
  if (left_empty)
    return xstrdup (right);
  if (right_empty)
    return xstrdup (left);

  if (sb_putn (&b, left, ln - 1) < 0) goto oom;
  if (sb_puts (&b, ",") < 0) goto oom;
  if (sb_putn (&b, right + 1, rn - 1) < 0) goto oom;
  return b.p;
oom:
  free (b.p);
  return NULL;
}

static int
json_stream_add_tuple (vals_t *out, const char *path, const char *value)
{
  sbuf_t b = {0};
  if (sb_puts (&b, "[") < 0) goto oom;
  if (sb_puts (&b, path) < 0) goto oom;
  if (sb_puts (&b, ",") < 0) goto oom;
  if (sb_puts (&b, value) < 0) goto oom;
  if (sb_puts (&b, "]") < 0) goto oom;
  return vals_add_take (out, b.p);
oom:
  free (b.p);
  return -1;
}

static int
json_stream_walk (const char *src, jsmntok_t *toks, int idx,
                  const char *path, vals_t *out)
{
  jsmntok_t *t = &toks[idx];
  if (t->type == JSMN_OBJECT)
    {
      if (t->size == 0)
        return json_stream_add_tuple (out, path, "{}");
      int ci = idx + 1;
      for (int i = 0; i < t->size; i++)
        {
          int key = ci;
          int val = key + 1;
          char *seg = tok_json (src, &toks[key]);
          char *next_path = seg ? json_path_append (path, seg) : NULL;
          free (seg);
          if (!next_path)
            return -1;
          if (json_stream_walk (src, toks, val, next_path, out) < 0)
            { free (next_path); return -1; }
          free (next_path);
          ci = jq_skip (toks, val);
        }
      return 0;
    }
  if (t->type == JSMN_ARRAY)
    {
      if (t->size == 0)
        return json_stream_add_tuple (out, path, "[]");
      int ci = idx + 1;
      for (int i = 0; i < t->size; i++)
        {
          char seg[64];
          snprintf (seg, sizeof seg, "%d", i);
          char *next_path = json_path_append (path, seg);
          if (!next_path)
            return -1;
          if (json_stream_walk (src, toks, ci, next_path, out) < 0)
            { free (next_path); return -1; }
          free (next_path);
          ci = jq_skip (toks, ci);
        }
      return 0;
    }
  char *value = tok_json (src, t);
  if (!value)
    return -1;
  int rc = json_stream_add_tuple (out, path, value);
  free (value);
  return rc;
}

static int
json_stream_values (const char *doc, vals_t *out)
{
  int nt = 0;
  jsmntok_t *toks = jq_tokenize_json (doc, strlen (doc), &nt);
  if (!toks || nt <= 0)
    { free (toks); return -1; }
  int rc = json_stream_walk (doc, toks, 0, "[]", out);
  free (toks);
  return rc;
}

static int
eval_one (node_t *n, const char *in, char **out)
{
  vals_t vs = {0};
  if (eval_node (n, in, &vs) < 0 || vs.n == 0) { vals_free (&vs); return -1; }
  *out = xstrdup (vs.v[0]);
  vals_free (&vs);
  return *out ? 0 : -1;
}

/* HOST-SAFE-RESIDUALS Wave 3 helpers (2026-05-26) — jq value ordering,
   array fold/sort/dedupe, object<->entries conversion. */

/* jq's total order on JSON values:
   null < false < true < numbers < strings < arrays < objects.
   Returns <0, 0, >0 like strcmp. */
static int json_value_cmp (const char *a, const char *b);

static int
json_type_rank (const char *v)
{
  const char *t = json_type (v);
  if (!strcmp (t, "null"))    return 0;
  if (!strcmp (t, "boolean")) return v[0] == 'f' ? 1 : 2;
  if (!strcmp (t, "number"))  return 3;
  if (!strcmp (t, "string"))  return 4;
  if (!strcmp (t, "array"))   return 5;
  if (!strcmp (t, "object"))  return 6;
  return 7;
}

static int
json_array_cmp (const char *a, const char *b)
{
  vals_t ea = {0}, eb = {0};
  json_array_each (a, &ea);
  json_array_each (b, &eb);
  int n = ea.n < eb.n ? ea.n : eb.n;
  int rc = 0;
  for (int i = 0; i < n && rc == 0; i++)
    rc = json_value_cmp (ea.v[i], eb.v[i]);
  if (rc == 0) rc = ea.n - eb.n;
  vals_free (&ea); vals_free (&eb);
  return rc;
}

static int
json_object_cmp (const char *a, const char *b)
{
  /* jq compares objects by sorted keys, then by values at those keys.
     We approximate by sorting both keys arrays and walking. */
  char *ka = json_keys_array (a), *kb = json_keys_array (b);
  if (!ka || !kb) { free (ka); free (kb); return 0; }
  vals_t kva = {0}, kvb = {0};
  json_array_each (ka, &kva);
  json_array_each (kb, &kvb);
  int n = kva.n < kvb.n ? kva.n : kvb.n;
  int rc = 0;
  for (int i = 0; i < n && rc == 0; i++)
    rc = strcmp (kva.v[i], kvb.v[i]);
  if (rc == 0)
    for (int i = 0; i < n && rc == 0; i++)
      {
        char *uk = json_unstring (kva.v[i]);
        if (!uk) continue;
        char *va = NULL, *vb = NULL;
        json_resolve_field (a, uk, &va);
        json_resolve_field (b, uk, &vb);
        if (va && vb) rc = json_value_cmp (va, vb);
        free (va); free (vb); free (uk);
      }
  if (rc == 0) rc = kva.n - kvb.n;
  vals_free (&kva); vals_free (&kvb);
  free (ka); free (kb);
  return rc;
}

static int
json_value_cmp (const char *a, const char *b)
{
  int ra = json_type_rank (a), rb = json_type_rank (b);
  if (ra != rb) return ra - rb;
  const char *t = json_type (a);
  if (!strcmp (t, "number"))
    {
      double da = strtod (a, NULL), db = strtod (b, NULL);
      if (da < db) return -1;
      if (da > db) return 1;
      return 0;
    }
  if (!strcmp (t, "string"))
    {
      char *sa = json_unstring (a), *sb = json_unstring (b);
      int rc = strcmp (sa ? sa : "", sb ? sb : "");
      free (sa); free (sb);
      return rc;
    }
  if (!strcmp (t, "array"))   return json_array_cmp (a, b);
  if (!strcmp (t, "object"))  return json_object_cmp (a, b);
  /* null/booleans are fully ordered by rank — equal within rank. */
  return 0;
}

static int
json_value_cmp_qsort (const void *a, const void *b)
{
  return json_value_cmp (*(const char * const *)a, *(const char * const *)b);
}

/* Build a JSON array literal from a vals_t of element JSON-text. */
static char *
vals_to_json_array (vals_t *vs)
{
  sbuf_t b = {0};
  if (sb_puts (&b, "[") < 0) goto oom;
  for (int i = 0; i < vs->n; i++)
    {
      if (i && sb_puts (&b, ",") < 0) goto oom;
      if (sb_puts (&b, vs->v[i]) < 0) goto oom;
    }
  if (sb_puts (&b, "]") < 0) goto oom;
  return b.p ? b.p : xstrdup ("[]");
oom:
  free (b.p);
  return NULL;
}

/* Object → [{"key":K,"value":V},...] in source order (jq matches input
   order for to_entries — verified against jq-1.7). */
static char *
json_to_entries (const char *json)
{
  int nt = 0;
  jsmntok_t *toks = jq_tokenize_json (json, strlen (json), &nt);
  if (!toks || nt <= 0 || toks[0].type != JSMN_OBJECT)
    { free (toks); return NULL; }
  sbuf_t b = {0};
  if (sb_puts (&b, "[") < 0) { free (toks); free (b.p); return NULL; }
  int ci = 1;
  for (int i = 0; i < toks[0].size; i++)
    {
      int ki = ci, vi = ci + 1;
      char *key = tok_json (json, &toks[ki]);
      char *val = tok_json (json, &toks[vi]);
      if (!key || !val) { free (key); free (val); free (toks); free (b.p); return NULL; }
      if (i && sb_puts (&b, ",") < 0) goto oom;
      if (sb_puts (&b, "{\"key\":") < 0) goto oom;
      if (sb_puts (&b, key) < 0) goto oom;
      if (sb_puts (&b, ",\"value\":") < 0) goto oom;
      if (sb_puts (&b, val) < 0) goto oom;
      if (sb_puts (&b, "}") < 0) goto oom;
      free (key); free (val);
      ci = jq_skip (toks, vi);
    }
  if (sb_puts (&b, "]") < 0) { free (toks); free (b.p); return NULL; }
  free (toks);
  return b.p;
oom:
  free (toks); free (b.p);
  return NULL;
}

/* [{"key":K,"value":V},...] → {K:V,...}. Accepts "k"/"key"/"name" for
   the key field and "v"/"value" for the value field, matching jq. */
static char *
json_from_entries (const char *json)
{
  int nt = 0;
  jsmntok_t *toks = jq_tokenize_json (json, strlen (json), &nt);
  if (!toks || nt <= 0 || toks[0].type != JSMN_ARRAY)
    { free (toks); return NULL; }
  sbuf_t b = {0};
  if (sb_puts (&b, "{") < 0) { free (toks); free (b.p); return NULL; }
  int ci = 1;
  for (int i = 0; i < toks[0].size; i++)
    {
      char *elem = tok_json (json, &toks[ci]);
      if (!elem) { free (toks); free (b.p); return NULL; }
      char *key = NULL, *val = NULL;
      json_resolve_field (elem, "key", &key);
      if (!key) json_resolve_field (elem, "k", &key);
      if (!key) json_resolve_field (elem, "name", &key);
      json_resolve_field (elem, "value", &val);
      if (!val) json_resolve_field (elem, "v", &val);
      free (elem);
      /* Missing fields default to null per jq. */
      if (!key) key = xstrdup ("null");
      if (!val) val = xstrdup ("null");
      /* Key must be a string to be a valid object key — quote it if
         it's already JSON-string form; otherwise emit the JSON-string
         of its raw text (jq is forgiving on string-coercible keys). */
      char *key_str = NULL;
      if (key[0] == '"') key_str = xstrdup (key);
      else
        {
          char *unstr = json_unstring (key);
          key_str = json_string (unstr ? unstr : key);
          free (unstr);
        }
      if (i && sb_puts (&b, ",") < 0) goto oom;
      if (sb_puts (&b, key_str ? key_str : "\"\"") < 0) goto oom;
      if (sb_puts (&b, ":") < 0) goto oom;
      if (sb_puts (&b, val) < 0) goto oom;
      free (key); free (val); free (key_str);
      ci = jq_skip (toks, ci);
    }
  if (sb_puts (&b, "}") < 0) { free (toks); free (b.p); return NULL; }
  free (toks);
  return b.p;
oom:
  free (toks); free (b.p);
  return NULL;
}

/* For tostring/tojson on non-string scalars/composites: produce a
   JSON-string whose contents are the JSON text of the input. */
static char *
json_to_json_string (const char *v)
{
  /* json_string handles escaping including backslashes and quotes. */
  return json_string (v);
}

/* Re-emit a JSON value as its textual form. For our representation
   (everything's already a JSON-text string), this is identity except
   for strings, which return their unquoted content as a raw string —
   that's the "tostring" semantics for non-strings. */
static char *
json_tostring_value (const char *v)
{
  if (v[0] == '"')
    return xstrdup (v);  /* strings unchanged */
  /* Everything else: wrap raw JSON text in JSON-string quotes. */
  return json_to_json_string (v);
}

/* ──── HOST-SAFE-RESIDUALS Wave 4 (2026-05-26) helpers ─────────────
   contains(V) recursive containment + split/splits/join string helpers.
   The contains() spec (matches jq-1.7 behavior — verified spot-check):
     - mismatched types → false (booleans/numbers/null: byte-equal,
       strings: substring, arrays: every elem of V is contained-by
       SOME elem of input, objects: every key/value of V exists in
       input AND value is recursively contained).
     - non-comparable type pair (e.g. string vs array) → jq errors;
       we return false for permissiveness, matching jq's broader
       "no errors, just null/false" philosophy.
   ───────────────────────────────────────────────────────────────── */
static int json_contains (const char *in, const char *v);

static int
json_contains_string (const char *in, const char *v)
{
  /* Both args are JSON-string text (with quotes). Unquote and strstr. */
  char *a = json_unstring (in), *b = json_unstring (v);
  int rc = 0;
  if (a && b) rc = strstr (a, b) != NULL;
  free (a); free (b);
  return rc;
}

static int
json_contains_array (const char *in, const char *v)
{
  vals_t ea = {0}, eb = {0};
  json_array_each (in, &ea);
  json_array_each (v, &eb);
  int rc = 1;
  for (int i = 0; i < eb.n && rc; i++)
    {
      int found = 0;
      for (int j = 0; j < ea.n && !found; j++)
        if (json_contains (ea.v[j], eb.v[i])) found = 1;
      if (!found) rc = 0;
    }
  vals_free (&ea); vals_free (&eb);
  return rc;
}

static int
json_contains_object (const char *in, const char *v)
{
  /* For each key of V, input must have the same key AND input's value
     at that key must contain V's value at that key (recursive). */
  int nt = 0;
  jsmntok_t *toks = jq_tokenize_json (v, strlen (v), &nt);
  if (!toks || nt <= 0 || toks[0].type != JSMN_OBJECT) { free (toks); return 0; }
  int rc = 1, ci = 1;
  for (int i = 0; i < toks[0].size && rc; i++)
    {
      char *key_json = tok_json (v, &toks[ci]);
      char *vval = tok_json (v, &toks[ci + 1]);
      char *uk = key_json ? json_unstring (key_json) : NULL;
      char *ival = NULL;
      if (uk) json_resolve_field (in, uk, &ival);
      if (!ival || !vval || !json_contains (ival, vval)) rc = 0;
      free (key_json); free (vval); free (uk); free (ival);
      ci = jq_skip (toks, ci + 1);
    }
  free (toks);
  return rc;
}

static int
json_contains (const char *in, const char *v)
{
  const char *ti = json_type (in), *tv = json_type (v);
  if (strcmp (ti, tv) != 0) return 0;
  if (!strcmp (ti, "string"))  return json_contains_string (in, v);
  if (!strcmp (ti, "array"))   return json_contains_array (in, v);
  if (!strcmp (ti, "object"))  return json_contains_object (in, v);
  /* numbers / booleans / null: byte-equality (jq parity for these). */
  return !strcmp (in, v);
}

/* Split a raw (already-unquoted) string by separator. Empty separator
   → array of single chars (jq parity). Returns an allocated JSON array
   literal of JSON-string elements. */
static char *
json_split_to_array (const char *raw, const char *sep)
{
  sbuf_t b = {0};
  if (sb_puts (&b, "[") < 0) goto oom;
  size_t slen = strlen (sep);
  int first = 1;
  if (slen == 0)
    {
      /* Per-char split. Match jq: "" → [], "a" → ["a"], "abc" → ["a","b","c"]. */
      for (const char *p = raw; *p; p++)
        {
          char ch[2] = { *p, 0 };
          char *js = json_string (ch);
          if (!js) goto oom;
          if (!first && sb_puts (&b, ",") < 0) { free (js); goto oom; }
          if (sb_puts (&b, js) < 0) { free (js); goto oom; }
          free (js); first = 0;
        }
    }
  else
    {
      const char *p = raw;
      for (;;)
        {
          const char *q = strstr (p, sep);
          size_t n = q ? (size_t) (q - p) : strlen (p);
          char *piece = xstrndup (p, n);
          char *js = piece ? json_string (piece) : NULL;
          free (piece);
          if (!js) goto oom;
          if (!first && sb_puts (&b, ",") < 0) { free (js); goto oom; }
          if (sb_puts (&b, js) < 0) { free (js); goto oom; }
          free (js); first = 0;
          if (!q) break;
          p = q + slen;
        }
    }
  if (sb_puts (&b, "]") < 0) goto oom;
  return b.p ? b.p : xstrdup ("[]");
oom:
  free (b.p); return NULL;
}

/* Coerce a single JSON value to a raw string for join(). Numbers use
   tostring-style format; null → ""; strings unquoted; arrays/objects
   /booleans → tojson-style raw text (matches jq for booleans only —
   jq errors on array/object elements, but jq's lenient posture
   round-trips the JSON text instead of erroring). */
static char *
json_coerce_for_join (const char *v)
{
  if (!strcmp (v, "null")) return xstrdup ("");
  if (v[0] == '"')
    {
      char *u = json_unstring (v);
      return u ? u : xstrdup ("");
    }
  return xstrdup (v);
}

/* Parse a JSON-text string back into a JSON value. Input is the
   JSON-string form (with quotes); output is the parsed JSON text. */
static char *
json_fromjson_value (const char *v)
{
  if (v[0] != '"') return NULL;
  char *unstr = json_unstring (v);
  if (!unstr) return NULL;
  if (jq_validate_json_document (unstr) < 0) { free (unstr); return NULL; }
  /* Re-tokenize to canonicalize whitespace away. */
  int nt = 0;
  jsmntok_t *toks = jq_tokenize_json (unstr, strlen (unstr), &nt);
  if (!toks || nt <= 0) { free (toks); free (unstr); return NULL; }
  char *out = tok_json (unstr, &toks[0]);
  free (toks); free (unstr);
  return out;
}

static char *
fmt_num (double d)
{
  char buf[128];
  if (isfinite (d) && fabs (d - (long long)d) < 1e-9) snprintf (buf, sizeof buf, "%lld", (long long)d);
  else snprintf (buf, sizeof buf, "%.15g", d);
  return xstrdup (buf);
}

/* ──── HOST-SAFE-RESIDUALS Wave 5 (2026-05-26) setpath/delpaths helpers ──
   Recursive container rebuild for setpath; iterative delete-by-path for
   delpaths. Both are O(depth × size-per-level) — fine for typical jq
   workloads but not optimized for deep documents. ──────────────────── */

/* Build a JSON array literal from a vals_t. Caller frees. */
static char *vals_to_array (vals_t *vs) { return vals_to_json_array (vs); }

/* Build a JSON object literal from parallel key/value vals_t arrays.
   Keys are raw (unquoted) strings; values are JSON text. */
static char *
kv_to_object (char **keys, char **vals, int n)
{
  sbuf_t b = {0};
  if (sb_puts (&b, "{") < 0) goto oom;
  for (int i = 0; i < n; i++)
    {
      if (i && sb_puts (&b, ",") < 0) goto oom;
      char *ks = json_string (keys[i] ? keys[i] : "");
      if (!ks || sb_puts (&b, ks) < 0) { free (ks); goto oom; }
      free (ks);
      if (sb_puts (&b, ":") < 0) goto oom;
      if (sb_puts (&b, vals[i] ? vals[i] : "null") < 0) goto oom;
    }
  if (sb_puts (&b, "}") < 0) goto oom;
  return b.p ? b.p : xstrdup ("{}");
oom:
  free (b.p); return NULL;
}

/* Decompose a JSON object into parallel keys[] (raw) + values[] (JSON
   text). Returns count, or -1 on error. Caller frees each entry and
   the arrays. */
static int
object_decompose (const char *json, char ***okeys, char ***ovals)
{
  int nt = 0; jsmntok_t *toks = jq_tokenize_json (json, strlen (json), &nt);
  if (!toks || nt <= 0 || toks[0].type != JSMN_OBJECT) { free (toks); return -1; }
  int n = toks[0].size;
  char **keys = calloc ((size_t) (n > 0 ? n : 1), sizeof *keys);
  char **vals = calloc ((size_t) (n > 0 ? n : 1), sizeof *vals);
  if (!keys || !vals) { free (keys); free (vals); free (toks); return -1; }
  int ci = 1;
  for (int i = 0; i < n; i++)
    {
      char *kjson = tok_json (json, &toks[ci]);
      keys[i] = kjson ? json_unstring (kjson) : NULL;
      free (kjson);
      vals[i] = tok_json (json, &toks[ci + 1]);
      ci = jq_skip (toks, ci + 1);
    }
  free (toks);
  *okeys = keys; *ovals = vals;
  return n;
}

/* Recursive setpath: walk comps[idx..] into cur, returning a new JSON
   text with vstr installed at the path tip. Auto-vivifies objects for
   string components and arrays for numeric components. */
static char *
json_setpath_helper (const char *cur, vals_t *comps, int idx, const char *vstr)
{
  if (idx >= comps->n) return xstrdup (vstr);
  const char *comp = comps->v[idx];
  const char *ct = json_type (comp);
  if (!strcmp (ct, "string"))
    {
      char *key = json_unstring (comp);
      if (!key) return NULL;
      const char *ctype = json_type (cur);
      /* If cur is null or non-object, replace it with {}. */
      char **keys = NULL, **vals = NULL;
      int nk = 0;
      if (!strcmp (ctype, "object"))
        nk = object_decompose (cur, &keys, &vals);
      if (nk < 0) nk = 0;
      /* Locate existing key. */
      int found = -1;
      for (int i = 0; i < nk; i++)
        if (keys[i] && !strcmp (keys[i], key)) { found = i; break; }
      char *sub_in;
      if (found >= 0) sub_in = xstrdup (vals[found]);
      else            sub_in = xstrdup ("null");
      char *new_sub = json_setpath_helper (sub_in, comps, idx + 1, vstr);
      free (sub_in);
      if (!new_sub) { for (int i = 0; i < nk; i++) { free (keys[i]); free (vals[i]); } free (keys); free (vals); free (key); return NULL; }
      if (found >= 0) { free (vals[found]); vals[found] = new_sub; free (key); }
      else
        {
          /* Append new key/value. */
          char **nk_arr = realloc (keys, sizeof (char *) * (size_t) (nk + 1));
          char **nv_arr = realloc (vals, sizeof (char *) * (size_t) (nk + 1));
          if (!nk_arr || !nv_arr) { free (key); free (new_sub); return NULL; }
          keys = nk_arr; vals = nv_arr;
          keys[nk] = key; vals[nk] = new_sub; nk++;
        }
      char *res = kv_to_object (keys, vals, nk);
      for (int i = 0; i < nk; i++) { free (keys[i]); free (vals[i]); }
      free (keys); free (vals);
      return res;
    }
  else if (!strcmp (ct, "number"))
    {
      long want = (long) strtod (comp, NULL);
      const char *ctype = json_type (cur);
      vals_t elems = {0};
      if (!strcmp (ctype, "array"))
        json_array_each (cur, &elems);
      /* Extend with nulls if needed. */
      while (elems.n <= want)
        if (vals_add (&elems, "null") < 0) { vals_free (&elems); return NULL; }
      char *new_sub = json_setpath_helper (elems.v[want], comps, idx + 1, vstr);
      if (!new_sub) { vals_free (&elems); return NULL; }
      free (elems.v[want]);
      elems.v[want] = new_sub;
      char *res = vals_to_array (&elems);
      vals_free (&elems);
      return res;
    }
  return NULL;
}

/* Compare two path arrays for sort (descending by length, then
   lexicographic on raw JSON). Used to delete deeper/later paths first
   so earlier indices don't shift. */
static int
path_cmp_desc (const void *pa, const void *pb)
{
  const char *a = *(const char * const *) pa;
  const char *b = *(const char * const *) pb;
  /* Decompose lengths via array_each — cheap for typical depth. */
  vals_t ea = {0}, eb = {0};
  json_array_each (a, &ea); json_array_each (b, &eb);
  int na = ea.n, nb = eb.n;
  vals_free (&ea); vals_free (&eb);
  if (na != nb) return nb - na;     /* longer first */
  return strcmp (b, a);             /* lex desc — later array indices first */
}

/* Delete a single path (array of components) from cur; returns new
   JSON text. Missing intermediate paths are no-ops (jq parity). */
static char *
json_del_one_path (const char *cur, vals_t *comps, int idx)
{
  if (idx >= comps->n) { (void) cur; return NULL; /* whole-doc delete; caller-handled */ }
  const char *comp = comps->v[idx];
  const char *ct = json_type (comp);
  const char *ctype = json_type (cur);
  if (!strcmp (ct, "string") && !strcmp (ctype, "object"))
    {
      char *key = json_unstring (comp);
      char **keys = NULL, **vals = NULL;
      int nk = object_decompose (cur, &keys, &vals);
      if (nk < 0) { free (key); return xstrdup (cur); }
      int found = -1;
      for (int i = 0; i < nk; i++)
        if (keys[i] && !strcmp (keys[i], key)) { found = i; break; }
      if (found < 0)
        {
          for (int i = 0; i < nk; i++) { free (keys[i]); free (vals[i]); } free (keys); free (vals); free (key);
          return xstrdup (cur);
        }
      if (idx + 1 == comps->n)
        {
          /* Delete this key. */
          char **nkeys = malloc (sizeof (char *) * (size_t) (nk - 1 > 0 ? nk - 1 : 1));
          char **nvals = malloc (sizeof (char *) * (size_t) (nk - 1 > 0 ? nk - 1 : 1));
          int nn = 0;
          for (int i = 0; i < nk; i++)
            if (i != found) { nkeys[nn] = keys[i]; nvals[nn] = vals[i]; nn++; }
            else            { free (keys[i]); free (vals[i]); }
          free (keys); free (vals); free (key);
          char *res = kv_to_object (nkeys, nvals, nn);
          for (int i = 0; i < nn; i++) { free (nkeys[i]); free (nvals[i]); }
          free (nkeys); free (nvals);
          return res;
        }
      char *new_sub = json_del_one_path (vals[found], comps, idx + 1);
      if (new_sub) { free (vals[found]); vals[found] = new_sub; }
      char *res = kv_to_object (keys, vals, nk);
      for (int i = 0; i < nk; i++) { free (keys[i]); free (vals[i]); }
      free (keys); free (vals); free (key);
      return res;
    }
  if (!strcmp (ct, "number") && !strcmp (ctype, "array"))
    {
      long want = (long) strtod (comp, NULL);
      vals_t elems = {0};
      json_array_each (cur, &elems);
      if (want < 0 || want >= elems.n) { vals_free (&elems); return xstrdup (cur); }
      if (idx + 1 == comps->n)
        {
          /* Delete this index. */
          vals_t kept = {0};
          for (int i = 0; i < elems.n; i++)
            if (i != want) vals_add (&kept, elems.v[i]);
          char *res = vals_to_array (&kept);
          vals_free (&elems); vals_free (&kept);
          return res;
        }
      char *new_sub = json_del_one_path (elems.v[want], comps, idx + 1);
      if (new_sub) { free (elems.v[want]); elems.v[want] = new_sub; }
      char *res = vals_to_array (&elems);
      vals_free (&elems);
      return res;
    }
  /* Path type doesn't match container type → no-op. */
  return xstrdup (cur);
}

static char *
json_delpaths_helper (const char *in, const char *paths)
{
  /* paths is an array of path-arrays. Sort descending so deletes in
     the same parent array don't shift earlier indices. */
  vals_t plist = {0};
  if (json_array_each (paths, &plist) < 0) return NULL;
  if (plist.n > 1)
    qsort (plist.v, (size_t) plist.n, sizeof plist.v[0], path_cmp_desc);
  char *cur = xstrdup (in);
  for (int i = 0; i < plist.n && cur; i++)
    {
      if (json_type (plist.v[i])[0] != 'a') continue;
      vals_t comps = {0};
      if (json_array_each (plist.v[i], &comps) < 0) { vals_free (&plist); free (cur); return NULL; }
      if (comps.n == 0) { vals_free (&comps); continue; }
      char *next = json_del_one_path (cur, &comps, 0);
      vals_free (&comps);
      if (next) { free (cur); cur = next; }
    }
  vals_free (&plist);
  return cur;
}

/* ──── HOST-SAFE-RESIDUALS Wave 6 (2026-05-26) ──────────────────────
   Recursive-descent + path-enumerator helpers backing N_RECURSE,
   N_CALL_PATHS, N_CALL_LEAF_PATHS. The walk uses jsmn token offsets
   directly so each sub-value is emitted as the canonical JSON text
   (no re-tokenize per level — keeps cost O(n) for plain recurse).
   ─────────────────────────────────────────────────────────────────── */

/* Recursive descent at token idx, depth-first, source order. Emits the
   value at idx, then if container, recurses into each child. */
static int
json_recurse_walk (const char *src, jsmntok_t *toks, int idx, vals_t *out)
{
  jsmntok_t *t = &toks[idx];
  char *self = tok_json (src, t);
  if (!self) return -1;
  if (vals_add_take (out, self) < 0) return -1;
  if (t->type == JSMN_OBJECT)
    {
      int ci = idx + 1;
      for (int i = 0; i < t->size; i++)
        {
          int vi = ci + 1;
          if (json_recurse_walk (src, toks, vi, out) < 0) return -1;
          ci = jq_skip (toks, vi);
        }
    }
  else if (t->type == JSMN_ARRAY)
    {
      int ci = idx + 1;
      for (int i = 0; i < t->size; i++)
        {
          if (json_recurse_walk (src, toks, ci, out) < 0) return -1;
          ci = jq_skip (toks, ci);
        }
    }
  return 0;
}

/* Build a JSON array literal from a comps vals_t of components
   (each comp is already JSON text: strings as "key", numbers as N). */
static char *
comps_to_json_array (vals_t *comps)
{
  sbuf_t b = {0};
  if (sb_puts (&b, "[") < 0) goto oom;
  for (int i = 0; i < comps->n; i++)
    {
      if (i && sb_puts (&b, ",") < 0) goto oom;
      if (sb_puts (&b, comps->v[i]) < 0) goto oom;
    }
  if (sb_puts (&b, "]") < 0) goto oom;
  return b.p ? b.p : xstrdup ("[]");
oom:
  free (b.p); return NULL;
}

/* Walk at token idx, emitting one path per non-root sub-value reached
   from there. comps tracks the path-from-original-input. leaf_only=1
   filters out container paths (matches jq leaf_paths). The root call
   should pass comps with .n == 0 and the root token idx — the root
   itself is never emitted (jq parity: `paths` on a bare scalar emits
   nothing). */
static int
json_paths_walk (const char *src, jsmntok_t *toks, int idx,
                 vals_t *comps, int leaf_only, vals_t *out)
{
  jsmntok_t *t = &toks[idx];
  /* Emit path for THIS node — unless we're at the root (comps empty).
     leaf_only suppresses container-typed sub-values. */
  if (comps->n > 0)
    {
      int is_container = (t->type == JSMN_OBJECT || t->type == JSMN_ARRAY);
      if (!leaf_only || !is_container)
        {
          char *path_json = comps_to_json_array (comps);
          if (!path_json) return -1;
          if (vals_add_take (out, path_json) < 0) return -1;
        }
    }
  if (t->type == JSMN_OBJECT)
    {
      int ci = idx + 1;
      for (int i = 0; i < t->size; i++)
        {
          int ki = ci, vi = ci + 1;
          char *key_seg = tok_json (src, &toks[ki]);   /* keeps quotes */
          if (!key_seg || vals_add_take (comps, key_seg) < 0) return -1;
          int rc = json_paths_walk (src, toks, vi, comps, leaf_only, out);
          /* Pop last component (matches push above). */
          free (comps->v[--comps->n]);
          if (rc < 0) return -1;
          ci = jq_skip (toks, vi);
        }
    }
  else if (t->type == JSMN_ARRAY)
    {
      int ci = idx + 1;
      for (int i = 0; i < t->size; i++)
        {
          char buf[32];
          snprintf (buf, sizeof buf, "%d", i);
          char *seg = xstrdup (buf);
          if (!seg || vals_add_take (comps, seg) < 0) return -1;
          int rc = json_paths_walk (src, toks, ci, comps, leaf_only, out);
          free (comps->v[--comps->n]);
          if (rc < 0) return -1;
          ci = jq_skip (toks, ci);
        }
    }
  return 0;
}

static int
eval_paths (node_t *n, const char *in, vals_t *paths)
{
  (void) in;
  if (!n) return -1;
  switch (n->k)
    {
    case N_ROOT:
      return vals_add (paths, "[]");
    case N_FIELD:
      {
        vals_t base = {0};
        char *seg = json_string (n->s ? n->s : "");
        int rc = 0;
        if (!seg || eval_paths (n->a, in, &base) < 0)
          { free (seg); vals_free (&base); return -1; }
        for (int i = 0; i < base.n && rc == 0; i++)
          {
            char *p = json_path_append (base.v[i], seg);
            rc = vals_add_take (paths, p);
          }
        free (seg);
        vals_free (&base);
        return rc;
      }
    case N_INDEX:
      {
        vals_t base = {0};
        int rc = 0;
        if (eval_paths (n->a, in, &base) < 0)
          { vals_free (&base); return -1; }
        for (int i = 0; i < base.n && rc == 0; i++)
          {
            char *p = json_path_append (base.v[i], n->s ? n->s : "0");
            rc = vals_add_take (paths, p);
          }
        vals_free (&base);
        return rc;
      }
    case N_COMMA:
      if (eval_paths (n->a, in, paths) < 0) return -1;
      return eval_paths (n->b, in, paths);
    case N_PIPE:
      {
        vals_t left = {0}, right = {0};
        int rc = 0;
        if (eval_paths (n->a, in, &left) < 0)
          { vals_free (&left); return -1; }
        if (eval_paths (n->b, in, &right) < 0)
          { vals_free (&left); vals_free (&right); return -1; }
        for (int i = 0; i < left.n && rc == 0; i++)
          for (int j = 0; j < right.n && rc == 0; j++)
            {
              char *p = json_path_concat (left.v[i], right.v[j]);
              rc = vals_add_take (paths, p);
            }
        vals_free (&left);
        vals_free (&right);
        return rc;
      }
    case N_TRY:
      return eval_paths (n->a, in, paths);
    default:
      builtin_error ("path: unsupported path expression");
      return -1;
    }
}

static int
eval_node (node_t *n, const char *in, vals_t *out)
{
  if (!n) return -1;
  switch (n->k)
    {
    case N_ROOT: return vals_add (out, in);
    case N_LITERAL: return vals_add (out, n->s);
    case N_FIELD:
      {
        vals_t sub = {0}; if (eval_node (n->a, in, &sub) < 0) return -1;
        for (int i = 0; i < sub.n; i++) { char *v = NULL; if (json_resolve_field (sub.v[i], n->s, &v) < 0) v = xstrdup ("null"); vals_add_take (out, v); }
        vals_free (&sub); return 0;
      }
    case N_INDEX:
      {
        vals_t sub = {0}; int idx = atoi (n->s); if (eval_node (n->a, in, &sub) < 0) return -1;
        for (int i = 0; i < sub.n; i++) { char *v = NULL; if (json_resolve_index (sub.v[i], idx, &v) < 0) v = xstrdup ("null"); vals_add_take (out, v); }
        vals_free (&sub); return 0;
      }
    case N_ITER:
      {
        vals_t sub = {0}; if (eval_node (n->a, in, &sub) < 0) return -1;
        for (int i = 0; i < sub.n; i++) if (json_array_each (sub.v[i], out) < 0) { vals_free (&sub); return -1; }
        vals_free (&sub); return 0;
      }
    case N_PIPE:
      {
        vals_t lhs = {0}; if (eval_node (n->a, in, &lhs) < 0) return -1;
        for (int i = 0; i < lhs.n; i++) if (eval_node (n->b, lhs.v[i], out) < 0) { vals_free (&lhs); return -1; }
        vals_free (&lhs); return 0;
      }
    case N_DEFAULT:
      {
        vals_t lhs = {0}; int saw = 0; eval_node (n->a, in, &lhs);
        for (int i = 0; i < lhs.n; i++) if (strcmp (lhs.v[i], "null") && strcmp (lhs.v[i], "false")) { vals_add (out, lhs.v[i]); saw = 1; }
        vals_free (&lhs); if (!saw) return eval_node (n->b, in, out); return 0;
      }
    case N_CALL_LENGTH: { double l = 0; if (json_length (in, &l) < 0) return -1; char buf[64];
      /* Match jq: integer-valued result prints with no decimal point;
         otherwise %g (jq uses g-style formatting too). */
      if (l == (double) (long long) l) snprintf (buf, sizeof buf, "%lld", (long long) l);
      else snprintf (buf, sizeof buf, "%.15g", l);
      return vals_add (out, buf); }
    case N_CALL_KEYS: return vals_add_take (out, json_keys_array (in));
    case N_CALL_TYPE:
      {
        const char *t = json_type (in);
        char *quoted = xmalloc (strlen (t) + 3);
        sprintf (quoted, "\"%s\"", t);
        return vals_add_take (out, quoted);
      }
    case N_CALL_NOT: return vals_add (out, truthy (in) ? "false" : "true");
    case N_CALL_HAS:
      {
        char *key = NULL;
        int has = 0;
        if (eval_one (n->a, in, &key) < 0 || json_has (in, key, &has) < 0)
          { free (key); return -1; }
        free (key);
        return vals_add (out, has ? "true" : "false");
      }
    case N_CALL_SELECT:
      {
        char *cond = NULL; int ok = eval_one (n->a, in, &cond) == 0 && truthy (cond);
        free (cond); return ok ? vals_add (out, in) : 0;
      }
    case N_CALL_MAP:
      {
        vals_t elems = {0}; if (json_array_each (in, &elems) < 0) return -1;
        sbuf_t b = {0}; sb_puts (&b, "["); int first = 1;
        for (int i = 0; i < elems.n; i++)
          {
            vals_t r = {0}; eval_node (n->a, elems.v[i], &r);
            for (int j = 0; j < r.n; j++) { if (!first) sb_puts (&b, ","); sb_puts (&b, r.v[j]); first = 0; }
            vals_free (&r);
          }
        vals_free (&elems); sb_puts (&b, "]"); return vals_add_take (out, b.p);
      }
    /* ──── HOST-SAFE-RESIDUALS Wave 3 (2026-05-26) ──── */
    case N_CALL_FIRST:
      {
        /* jq: array → element 0 or null when empty; error on non-array. */
        if (json_type (in)[0] != 'a') { builtin_error ("first: input is not an array"); return -1; }
        vals_t elems = {0}; if (json_array_each (in, &elems) < 0) return -1;
        int rc = vals_add (out, elems.n > 0 ? elems.v[0] : "null");
        vals_free (&elems); return rc;
      }
    case N_CALL_LAST:
      {
        if (json_type (in)[0] != 'a') { builtin_error ("last: input is not an array"); return -1; }
        vals_t elems = {0}; if (json_array_each (in, &elems) < 0) return -1;
        int rc = vals_add (out, elems.n > 0 ? elems.v[elems.n - 1] : "null");
        vals_free (&elems); return rc;
      }
    case N_CALL_REVERSE:
      {
        if (json_type (in)[0] != 'a') { builtin_error ("reverse: input is not an array"); return -1; }
        vals_t elems = {0}; if (json_array_each (in, &elems) < 0) return -1;
        sbuf_t b = {0}; sb_puts (&b, "[");
        for (int i = elems.n - 1; i >= 0; i--)
          { if (i != elems.n - 1) sb_puts (&b, ","); sb_puts (&b, elems.v[i]); }
        sb_puts (&b, "]");
        vals_free (&elems);
        return vals_add_take (out, b.p ? b.p : xstrdup ("[]"));
      }
    case N_CALL_ADD:
      {
        /* jq: fold + over the array; empty/null-input → null. */
        if (!strcmp (in, "null")) return vals_add (out, "null");
        if (json_type (in)[0] != 'a') { builtin_error ("add: input is not an array"); return -1; }
        vals_t elems = {0}; if (json_array_each (in, &elems) < 0) return -1;
        if (elems.n == 0) { vals_free (&elems); return vals_add (out, "null"); }
        char *acc = xstrdup (elems.v[0]);
        for (int i = 1; i < elems.n && acc; i++)
          {
            const char *cur = elems.v[i];
            const char *ta = json_type (acc), *tb = json_type (cur);
            char *next = NULL;
            if (!strcmp (acc, "null")) next = xstrdup (cur);
            else if (!strcmp (cur, "null")) next = xstrdup (acc);
            else if (!strcmp (ta, "number") && !strcmp (tb, "number"))
              next = fmt_num (strtod (acc, NULL) + strtod (cur, NULL));
            else if (!strcmp (ta, "string") && !strcmp (tb, "string"))
              { char *sa = json_unstring (acc), *sb = json_unstring (cur);
                sbuf_t tmp = {0}; sb_puts (&tmp, sa ? sa : ""); sb_puts (&tmp, sb ? sb : "");
                next = json_string (tmp.p ? tmp.p : ""); free (tmp.p); free (sa); free (sb); }
            else if (!strcmp (ta, "array") && !strcmp (tb, "array"))
              next = json_array_concat (acc, cur);
            else
              { builtin_error ("add: incompatible element types"); free (acc); vals_free (&elems); return -1; }
            free (acc); acc = next;
          }
        vals_free (&elems);
        return vals_add_take (out, acc);
      }
    case N_CALL_MIN: case N_CALL_MAX:
      {
        if (!strcmp (in, "null")) return vals_add (out, "null");
        if (json_type (in)[0] != 'a') { builtin_error ("min/max: input is not an array"); return -1; }
        vals_t elems = {0}; if (json_array_each (in, &elems) < 0) return -1;
        if (elems.n == 0) { vals_free (&elems); return vals_add (out, "null"); }
        int best = 0;
        for (int i = 1; i < elems.n; i++)
          {
            int c = json_value_cmp (elems.v[i], elems.v[best]);
            if ((n->k == N_CALL_MIN && c < 0) || (n->k == N_CALL_MAX && c > 0))
              best = i;
          }
        int rc = vals_add (out, elems.v[best]);
        vals_free (&elems); return rc;
      }
    case N_CALL_SORT:
      {
        if (json_type (in)[0] != 'a') { builtin_error ("sort: input is not an array"); return -1; }
        vals_t elems = {0}; if (json_array_each (in, &elems) < 0) return -1;
        if (elems.n > 1)
          qsort (elems.v, (size_t) elems.n, sizeof elems.v[0], json_value_cmp_qsort);
        char *res = vals_to_json_array (&elems);
        vals_free (&elems);
        return vals_add_take (out, res);
      }
    case N_CALL_UNIQUE:
      {
        if (json_type (in)[0] != 'a') { builtin_error ("unique: input is not an array"); return -1; }
        vals_t elems = {0}; if (json_array_each (in, &elems) < 0) return -1;
        if (elems.n > 1)
          qsort (elems.v, (size_t) elems.n, sizeof elems.v[0], json_value_cmp_qsort);
        vals_t dedup = {0};
        for (int i = 0; i < elems.n; i++)
          {
            if (dedup.n > 0 && json_value_cmp (dedup.v[dedup.n - 1], elems.v[i]) == 0) continue;
            vals_add (&dedup, elems.v[i]);
          }
        char *res = vals_to_json_array (&dedup);
        vals_free (&elems); vals_free (&dedup);
        return vals_add_take (out, res);
      }
    case N_CALL_TO_ENTRIES:
      {
        if (json_type (in)[0] != 'o') { builtin_error ("to_entries: input is not an object"); return -1; }
        char *res = json_to_entries (in);
        if (!res) return -1;
        return vals_add_take (out, res);
      }
    case N_CALL_FROM_ENTRIES:
      {
        if (json_type (in)[0] != 'a') { builtin_error ("from_entries: input is not an array"); return -1; }
        char *res = json_from_entries (in);
        if (!res) return -1;
        return vals_add_take (out, res);
      }
    case N_CALL_TOSTRING:
      {
        char *res = json_tostring_value (in);
        if (!res) return -1;
        return vals_add_take (out, res);
      }
    case N_CALL_TONUMBER:
      {
        const char *t = json_type (in);
        if (!strcmp (t, "number")) return vals_add (out, in);
        if (!strcmp (t, "string"))
          {
            char *raw = json_unstring (in);
            if (!raw) return -1;
            char *end = NULL;
            double d = strtod (raw, &end);
            /* jq accepts leading whitespace; reject if no digits parsed. */
            if (end == raw) { free (raw); builtin_error ("tonumber: not a number"); return -1; }
            free (raw);
            return vals_add_take (out, fmt_num (d));
          }
        builtin_error ("tonumber: input is not a number or string");
        return -1;
      }
    case N_CALL_TOJSON:
      {
        /* jq: any value → its JSON-text wrapped in a JSON string. */
        char *res = json_to_json_string (in);
        if (!res) return -1;
        return vals_add_take (out, res);
      }
    case N_CALL_FROMJSON:
      {
        if (json_type (in)[0] != 's') { builtin_error ("fromjson: input is not a string"); return -1; }
        char *res = json_fromjson_value (in);
        if (!res) { builtin_error ("fromjson: invalid JSON in string"); return -1; }
        return vals_add_take (out, res);
      }
    case N_CALL_ASCII_DOWNCASE: case N_CALL_ASCII_UPCASE:
      {
        if (json_type (in)[0] != 's') { builtin_error ("ascii_{down,up}case: input is not a string"); return -1; }
        char *raw = json_unstring (in);
        if (!raw) return -1;
        for (char *p = raw; *p; p++)
          {
            if (n->k == N_CALL_ASCII_DOWNCASE && *p >= 'A' && *p <= 'Z') *p = (char) (*p + 32);
            else if (n->k == N_CALL_ASCII_UPCASE && *p >= 'a' && *p <= 'z') *p = (char) (*p - 32);
          }
        char *res = json_string (raw);
        free (raw);
        if (!res) return -1;
        return vals_add_take (out, res);
      }
    case N_CALL_FLOOR: case N_CALL_CEIL: case N_CALL_FABS: case N_CALL_SQRT:
      {
        if (json_type (in)[0] != 'n')
          { builtin_error ("math: input is not a number"); return -1; }
        double d = strtod (in, NULL), r = 0;
        if (n->k == N_CALL_FLOOR) r = floor (d);
        else if (n->k == N_CALL_CEIL) r = ceil (d);
        else if (n->k == N_CALL_FABS) r = fabs (d);
        else /* SQRT */
          { if (d < 0) return vals_add (out, "null"); r = sqrt (d); }
        return vals_add_take (out, fmt_num (r));
      }
    /* ──── HOST-SAFE-RESIDUALS Wave 4 (2026-05-26) ──── */
    case N_CALL_EXP: case N_CALL_LOG:
      {
        if (json_type (in)[0] != 'n')
          { builtin_error ("exp/log: input is not a number"); return -1; }
        double d = strtod (in, NULL), r = 0;
        if (n->k == N_CALL_EXP) r = exp (d);
        else /* LOG */
          {
            if (d < 0) return vals_add (out, "null");
            /* log(0) = -inf; jq clamps inf to ±DBL_MAX per its JSON-double
               printer. Match that so parity tests against jq pass. */
            if (d == 0) { return vals_add (out, "-1.7976931348623157e+308"); }
            r = log (d);
          }
        if (!isfinite (r))
          {
            /* Match jq: NaN → null. */
            if (isnan (r)) return vals_add (out, "null");
            /* ±inf → clamped ±DBL_MAX (jq parity). */
            return vals_add (out, r < 0
                                  ? "-1.7976931348623157e+308"
                                  :  "1.7976931348623157e+308");
          }
        return vals_add_take (out, fmt_num (r));
      }
    case N_CALL_LTRIMSTR: case N_CALL_RTRIMSTR:
      {
        /* jq: input must be string for stripping; numbers/null/bool
           pass through unchanged. Argument must be a string; non-string
           arg with string input → return input unchanged (jq parity). */
        if (json_type (in)[0] != 's') return vals_add (out, in);
        char *arg = NULL;
        if (eval_one (n->a, in, &arg) < 0) return -1;
        if (json_type (arg)[0] != 's') { free (arg); return vals_add (out, in); }
        char *raw = json_unstring (in), *sub = json_unstring (arg);
        free (arg);
        if (!raw || !sub) { free (raw); free (sub); return -1; }
        size_t rlen = strlen (raw), slen = strlen (sub);
        char *res = NULL;
        if (n->k == N_CALL_LTRIMSTR)
          {
            if (slen && rlen >= slen && memcmp (raw, sub, slen) == 0)
              res = json_string (raw + slen);
            else res = json_string (raw);
          }
        else /* RTRIMSTR */
          {
            if (slen && rlen >= slen && memcmp (raw + rlen - slen, sub, slen) == 0)
              {
                char *trimmed = xstrndup (raw, rlen - slen);
                res = trimmed ? json_string (trimmed) : NULL;
                free (trimmed);
              }
            else res = json_string (raw);
          }
        free (raw); free (sub);
        if (!res) return -1;
        return vals_add_take (out, res);
      }
    case N_CALL_STARTSWITH: case N_CALL_ENDSWITH:
      {
        if (json_type (in)[0] != 's')
          { builtin_error ("startswith/endswith: input is not a string"); return -1; }
        char *arg = NULL;
        if (eval_one (n->a, in, &arg) < 0) return -1;
        if (json_type (arg)[0] != 's')
          { free (arg); builtin_error ("startswith/endswith: argument is not a string"); return -1; }
        char *raw = json_unstring (in), *sub = json_unstring (arg);
        free (arg);
        if (!raw || !sub) { free (raw); free (sub); return -1; }
        size_t rlen = strlen (raw), slen = strlen (sub);
        int r = 0;
        if (slen > rlen) r = 0;
        else if (n->k == N_CALL_STARTSWITH) r = memcmp (raw, sub, slen) == 0;
        else /* ENDSWITH */                 r = memcmp (raw + rlen - slen, sub, slen) == 0;
        free (raw); free (sub);
        return vals_add (out, r ? "true" : "false");
      }
    case N_CALL_CONTAINS:
      {
        char *arg = NULL;
        if (eval_one (n->a, in, &arg) < 0) return -1;
        int r = json_contains (in, arg);
        free (arg);
        return vals_add (out, r ? "true" : "false");
      }
    case N_CALL_SPLIT:
      {
        if (json_type (in)[0] != 's')
          { builtin_error ("split: input is not a string"); return -1; }
        char *arg = NULL;
        if (eval_one (n->a, in, &arg) < 0) return -1;
        if (json_type (arg)[0] != 's')
          { free (arg); builtin_error ("split: separator is not a string"); return -1; }
        char *raw = json_unstring (in), *sep = json_unstring (arg);
        free (arg);
        if (!raw || !sep) { free (raw); free (sep); return -1; }
        char *res = json_split_to_array (raw, sep);
        free (raw); free (sep);
        if (!res) return -1;
        return vals_add_take (out, res);
      }
    case N_CALL_SPLITS:
      {
        /* splits emits one value per part (a stream, not an array). */
        if (json_type (in)[0] != 's')
          { builtin_error ("splits: input is not a string"); return -1; }
        char *arg = NULL;
        if (eval_one (n->a, in, &arg) < 0) return -1;
        if (json_type (arg)[0] != 's')
          { free (arg); builtin_error ("splits: separator is not a string"); return -1; }
        char *raw = json_unstring (in), *sep = json_unstring (arg);
        free (arg);
        if (!raw || !sep) { free (raw); free (sep); return -1; }
        char *arr = json_split_to_array (raw, sep);
        free (raw); free (sep);
        if (!arr) return -1;
        vals_t parts = {0};
        int rc = json_array_each (arr, &parts);
        free (arr);
        if (rc < 0) { vals_free (&parts); return -1; }
        for (int i = 0; i < parts.n; i++)
          if (vals_add (out, parts.v[i]) < 0) { vals_free (&parts); return -1; }
        vals_free (&parts);
        return 0;
      }
    case N_CALL_JOIN:
      {
        if (json_type (in)[0] != 'a')
          { builtin_error ("join: input is not an array"); return -1; }
        char *arg = NULL;
        if (eval_one (n->a, in, &arg) < 0) return -1;
        if (json_type (arg)[0] != 's')
          { free (arg); builtin_error ("join: separator is not a string"); return -1; }
        char *sep = json_unstring (arg);
        free (arg);
        if (!sep) return -1;
        vals_t elems = {0};
        if (json_array_each (in, &elems) < 0) { free (sep); return -1; }
        sbuf_t b = {0};
        for (int i = 0; i < elems.n; i++)
          {
            if (i && sb_puts (&b, sep) < 0) { free (b.p); free (sep); vals_free (&elems); return -1; }
            char *piece = json_coerce_for_join (elems.v[i]);
            if (!piece || sb_puts (&b, piece) < 0) { free (piece); free (b.p); free (sep); vals_free (&elems); return -1; }
            free (piece);
          }
        free (sep); vals_free (&elems);
        char *res = json_string (b.p ? b.p : "");
        free (b.p);
        if (!res) return -1;
        return vals_add_take (out, res);
      }
    case N_CMP_EQ: case N_CMP_NE: case N_CMP_LT: case N_CMP_LE: case N_CMP_GT: case N_CMP_GE:
      {
        char *a = NULL, *b = NULL; if (eval_one (n->a, in, &a) < 0 || eval_one (n->b, in, &b) < 0) { free (a); free (b); return -1; }
        int r = 0; const char *ta = json_type (a), *tb = json_type (b);
        if (n->k == N_CMP_EQ) r = !strcmp (a, b);
        else if (n->k == N_CMP_NE) r = strcmp (a, b) != 0;
        else if (!strcmp (ta, "number") && !strcmp (tb, "number"))
          { double da = strtod (a, NULL), db = strtod (b, NULL); if (n->k == N_CMP_LT) r = da < db; else if (n->k == N_CMP_LE) r = da <= db; else if (n->k == N_CMP_GT) r = da > db; else r = da >= db; }
        else if (!strcmp (ta, "string") && !strcmp (tb, "string"))
          { char *sa = json_unstring (a), *sb = json_unstring (b); int c = strcmp (sa ? sa : "", sb ? sb : ""); if (n->k == N_CMP_LT) r = c < 0; else if (n->k == N_CMP_LE) r = c <= 0; else if (n->k == N_CMP_GT) r = c > 0; else r = c >= 0; free (sa); free (sb); }
        free (a); free (b); return vals_add (out, r ? "true" : "false");
      }
    case N_AND: case N_OR:
      {
        char *a = NULL, *b = NULL; eval_one (n->a, in, &a);
        if (n->k == N_AND && !truthy (a)) { free (a); return vals_add (out, "false"); }
        if (n->k == N_OR && truthy (a)) { free (a); return vals_add (out, "true"); }
        free (a); eval_one (n->b, in, &b); int r = truthy (b); free (b); return vals_add (out, r ? "true" : "false");
      }
    case N_ADD: case N_SUB: case N_MUL: case N_DIV: case N_MOD:
      {
        char *a = NULL, *b = NULL; if (eval_one (n->a, in, &a) < 0 || eval_one (n->b, in, &b) < 0) { free (a); free (b); return -1; }
        char *res = NULL;
        if (n->k == N_ADD && !strcmp (a, "null"))
          res = xstrdup (b);
        else if (n->k == N_ADD && !strcmp (b, "null"))
          res = xstrdup (a);
        else if (n->k == N_ADD && !strcmp (json_type (a), "string") && !strcmp (json_type (b), "string"))
          { char *sa = json_unstring (a), *sb = json_unstring (b); sbuf_t tmp = {0}; sb_puts (&tmp, sa ? sa : ""); sb_puts (&tmp, sb ? sb : ""); res = json_string (tmp.p ? tmp.p : ""); free (tmp.p); free (sa); free (sb); }
        else if (n->k == N_ADD && !strcmp (json_type (a), "array") && !strcmp (json_type (b), "array"))
          res = json_array_concat (a, b);
        else
          { double da = strtod (a, NULL), db = strtod (b, NULL), d = 0; if (n->k == N_ADD) d = da + db; else if (n->k == N_SUB) d = da - db; else if (n->k == N_MUL) d = da * db; else if (n->k == N_DIV) d = da / db; else d = (double)((long long)da % (long long)db); res = fmt_num (d); }
        free (a); free (b); return vals_add_take (out, res);
      }
    case N_NEG:
      { char *a = NULL; if (eval_one (n->a, in, &a) < 0) return -1; char *r = fmt_num (-strtod (a, NULL)); free (a); return vals_add_take (out, r); }
    case N_IF:
      { char *c = NULL; eval_one (n->a, in, &c); int tr = truthy (c); free (c); return eval_node (tr ? n->b : n->c, in, out); }
    case N_TRY: return eval_node (n->a, in, out) < 0 ? 0 : 0;
    /* ──── HOST-SAFE-RESIDUALS Wave 5 (2026-05-26) ──── */
    case N_COMMA:
      {
        /* jq: E1, E2 evaluates BOTH against the same input, emits the
           combined value stream. Errors on either side bubble. */
        if (eval_node (n->a, in, out) < 0) return -1;
        if (eval_node (n->b, in, out) < 0) return -1;
        return 0;
      }
    case N_ARRAY:
      {
        /* jq: [E] collects the value stream of E (against input `in`)
           into a JSON array. Empty `[]` (n->a == NULL) is an empty
           array literal — does NOT depend on input. */
        vals_t elems = {0};
        if (n->a && eval_node (n->a, in, &elems) < 0)
          { vals_free (&elems); return -1; }
        char *res = vals_to_json_array (&elems);
        vals_free (&elems);
        if (!res) return -1;
        return vals_add_take (out, res);
      }
    case N_CALL_RANGE:
      {
        /* range(N)        → 0,1,…,N-1
           range(F;U)      → F,F+1,…,<U
           range(F;U;S)    → F,F+S,…  (S>0: while <U; S<0: while >U)
           Args are filters; each evaluates against `in` to a stream.
           For range(N), iterate N's stream and emit a sub-range per. */
        vals_t va = {0}, vb = {0}, vc = {0};
        if (eval_node (n->a, in, &va) < 0) { vals_free (&va); return -1; }
        if (n->b && eval_node (n->b, in, &vb) < 0) { vals_free (&va); vals_free (&vb); return -1; }
        if (n->c && eval_node (n->c, in, &vc) < 0) { vals_free (&va); vals_free (&vb); vals_free (&vc); return -1; }
        int rc = 0;
        for (int i = 0; i < va.n && rc == 0; i++)
          {
            int jmax = n->b ? vb.n : 1;
            for (int j = 0; j < jmax && rc == 0; j++)
              {
                int kmax = n->c ? vc.n : 1;
                for (int k = 0; k < kmax && rc == 0; k++)
                  {
                    double from, upto, step;
                    if (n->b)
                      { from = strtod (va.v[i], NULL); upto = strtod (vb.v[j], NULL); }
                    else
                      { from = 0; upto = strtod (va.v[i], NULL); }
                    step = n->c ? strtod (vc.v[k], NULL) : 1.0;
                    if (step == 0) { builtin_error ("range: step cannot be 0"); rc = -1; break; }
                    /* Safety cap to avoid runaway streams. jq itself has no
                       cap, but 1e7 elements is way past any reasonable
                       loadable invocation; surfaces faster than OOM. */
                    long maxn = 10000000;
                    for (double x = from;
                         (step > 0 ? x < upto : x > upto) && maxn > 0;
                         x += step, maxn--)
                      {
                        char *s = fmt_num (x);
                        if (vals_add_take (out, s) < 0) { rc = -1; break; }
                      }
                  }
              }
          }
        vals_free (&va); vals_free (&vb); vals_free (&vc);
        return rc;
      }
    case N_CALL_NTH:
      {
        /* nth(N; F): evaluate F to a stream, return N-th value (0-indexed).
           null if F yields fewer than N+1 values. N evaluates first; if it
           yields multiple values, emit one nth result per N. */
        vals_t va = {0};
        if (eval_node (n->a, in, &va) < 0) { vals_free (&va); return -1; }
        int rc = 0;
        for (int i = 0; i < va.n && rc == 0; i++)
          {
            long idx = (long) strtod (va.v[i], NULL);
            vals_t vb = {0};
            if (eval_node (n->b, in, &vb) < 0) { vals_free (&va); vals_free (&vb); return -1; }
            if (idx < 0 || idx >= vb.n) rc = vals_add (out, "null");
            else                         rc = vals_add (out, vb.v[idx]);
            vals_free (&vb);
          }
        vals_free (&va);
        return rc;
      }
    case N_CALL_GETPATH:
      {
        /* getpath(P): P is an array of path components (strings for
           object keys, numbers for array indices). Walks input and
           returns the value at the path, or null on miss. */
        char *parr = NULL;
        if (eval_one (n->a, in, &parr) < 0) return -1;
        if (json_type (parr)[0] != 'a')
          { free (parr); builtin_error ("getpath: path must be an array"); return -1; }
        vals_t comps = {0};
        if (json_array_each (parr, &comps) < 0) { free (parr); return -1; }
        free (parr);
        char *cur = xstrdup (in);
        for (int i = 0; i < comps.n && cur; i++)
          {
            char *next = NULL;
            const char *t = json_type (comps.v[i]);
            if (!strcmp (t, "string"))
              {
                char *key = json_unstring (comps.v[i]);
                if (key) { json_resolve_field (cur, key, &next); free (key); }
              }
            else if (!strcmp (t, "number"))
              {
                long idx = (long) strtod (comps.v[i], NULL);
                json_resolve_index (cur, (int) idx, &next);
              }
            free (cur);
            cur = next ? next : xstrdup ("null");
            /* If we hit null mid-walk, keep walking → keeps yielding null. */
            if (!strcmp (cur, "null") && i + 1 < comps.n)
              { /* allow null short-circuit */ }
          }
        vals_free (&comps);
        return vals_add_take (out, cur);
      }
    case N_CALL_SETPATH:
      {
        /* setpath(P; V): return input with V set at path P. Implemented
           via a recursive helper that rebuilds the containers along
           the path. Auto-vivifies missing intermediate objects/arrays
           (jq: missing object key → {}; missing array index → fills
           with nulls then sets). */
        char *parr = NULL;
        if (eval_one (n->a, in, &parr) < 0) return -1;
        if (json_type (parr)[0] != 'a')
          { free (parr); builtin_error ("setpath: path must be an array"); return -1; }
        char *vstr = NULL;
        if (eval_one (n->b, in, &vstr) < 0) { free (parr); return -1; }
        vals_t comps = {0};
        if (json_array_each (parr, &comps) < 0) { free (parr); free (vstr); return -1; }
        free (parr);
        char *res = json_setpath_helper (in, &comps, 0, vstr);
        vals_free (&comps); free (vstr);
        if (!res) return -1;
        return vals_add_take (out, res);
      }
    case N_CALL_DELPATHS:
      {
        /* delpaths(PS): PS is an array of path arrays. Delete each
           path from the input. Per jq spec, process longest-path-first
           (actually jq sorts paths and processes in reverse) to avoid
           index drift in arrays. */
        char *parr = NULL;
        if (eval_one (n->a, in, &parr) < 0) return -1;
        if (json_type (parr)[0] != 'a')
          { free (parr); builtin_error ("delpaths: paths must be an array"); return -1; }
        char *res = json_delpaths_helper (in, parr);
        free (parr);
        if (!res) return -1;
        return vals_add_take (out, res);
      }
    case N_CALL_POW:
      {
        /* pow(X; Y) → X**Y, math.h pow. */
        char *xs = NULL, *ys = NULL;
        if (eval_one (n->a, in, &xs) < 0) return -1;
        if (eval_one (n->b, in, &ys) < 0) { free (xs); return -1; }
        double x = strtod (xs, NULL), y = strtod (ys, NULL);
        free (xs); free (ys);
        double r = pow (x, y);
        if (!isfinite (r))
          {
            if (isnan (r)) return vals_add (out, "null");
            return vals_add (out, r < 0
                                  ? "-1.7976931348623157e+308"
                                  :  "1.7976931348623157e+308");
          }
        return vals_add_take (out, fmt_num (r));
      }
    case N_CALL_PATH:
      return eval_paths (n->a, in, out);
    /* ──── HOST-SAFE-RESIDUALS Wave 6 (2026-05-26) ──── */
    case N_RECURSE:
      {
        /* Recursive descent: emit input, then depth-first every reachable
           sub-value. Scalars degenerate to "just the input". */
        int nt = 0;
        jsmntok_t *toks = jq_tokenize_json (in, strlen (in), &nt);
        if (!toks || nt <= 0)
          { free (toks); return vals_add (out, in); }
        int rc = json_recurse_walk (in, toks, 0, out);
        free (toks);
        return rc;
      }
    case N_CALL_PATHS: case N_CALL_LEAF_PATHS:
      {
        /* Emit every path-to-sub-value as a JSON array of components.
           leaf_paths suppresses container-typed paths. Scalars / empty
           containers at the root produce no output (jq parity). */
        int nt = 0;
        jsmntok_t *toks = jq_tokenize_json (in, strlen (in), &nt);
        if (!toks || nt <= 0) { free (toks); return 0; }
        vals_t comps = {0};
        int rc = json_paths_walk (in, toks, 0, &comps,
                                  n->k == N_CALL_LEAF_PATHS ? 1 : 0, out);
        vals_free (&comps);
        free (toks);
        return rc;
      }
    }
  return -1;
}

/* JSON values are retained as source slices. Compact them at emission without
   altering whitespace or escaped quotation marks inside strings. */
static void
json_compact (char *text)
{
  char *out = text;
  int quoted = 0, escaped = 0;
  for (char *p = text; *p; p++)
    {
      unsigned char c = (unsigned char) *p;
      if (quoted)
        {
          *out++ = *p;
          if (escaped) escaped = 0;
          else if (c == '\\') escaped = 1;
          else if (c == '"') quoted = 0;
        }
      else if (!isspace (c))
        { *out++ = *p; if (c == '"') quoted = 1; }
    }
  *out = 0;
}

static int
run_filter (const char *filter, char *doc, int raw, int exit_status, const char *out_var)
{
  lexer_t lx = {0};
  if (jq_validate_json_document (doc) < 0)
    {
      builtin_error ("invalid JSON input");
      return EXECUTION_FAILURE;
    }
  json_compact (doc);
  if (lex_filter (&lx, filter) < 0) { builtin_error ("%s", lx.err[0] ? lx.err : "lex failed"); return EX_USAGE; }
  parser_t p = { .lx = &lx };
  node_t *root = parse_expr (&p);
  if (!root || peek (&p)->t != FT_EOF) { builtin_error ("%s", p.err[0] ? p.err : "parse failed"); node_free (root); return EX_USAGE; }
  vals_t out = {0};
  int rc = eval_node (root, doc, &out) < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
  sbuf_t bound = {0};
  for (int i = 0; i < out.n; i++)
    {
      json_compact (out.v[i]);
      char *raw_s = NULL;
      const char *emit = out.v[i];
      if (raw && json_type (out.v[i]) && !strcmp (json_type (out.v[i]), "string"))
        { raw_s = json_unstring (out.v[i]); emit = raw_s ? raw_s : ""; }
      if (out_var)
        {
          if (i && sb_puts (&bound, "\n") < 0) rc = EXECUTION_FAILURE;
          if (sb_puts (&bound, emit) < 0) rc = EXECUTION_FAILURE;
        }
      else
        printf ("%s\n", emit);
      free (raw_s);
    }
  if (out_var && rc == EXECUTION_SUCCESS)
    builtin_bind_variable ((char *) out_var, bound.p ? bound.p : "", 0);
  if (exit_status)
    {
      if (out.n == 0 || !strcmp (out.v[out.n-1], "null") || !strcmp (out.v[out.n-1], "false")) rc = EXECUTION_FAILURE;
    }
  free (bound.p);
  vals_free (&out); node_free (root);
  for (int i = 0; i < lx.n; i++) free (lx.v[i].v);
  free (lx.v);
  return rc;
}

static int
run_stream_filter (const char *filter, const char *doc, int raw,
                   int exit_status, const char *out_var)
{
  vals_t stream = {0};
  if (json_stream_values (doc, &stream) < 0)
    { vals_free (&stream); builtin_error ("cannot stream JSON input"); return EXECUTION_FAILURE; }

  lexer_t lx = {0};
  if (lex_filter (&lx, filter) < 0)
    { vals_free (&stream); builtin_error ("%s", lx.err[0] ? lx.err : "lex failed"); return EX_USAGE; }
  parser_t p = { .lx = &lx };
  node_t *root = parse_expr (&p);
  if (!root || peek (&p)->t != FT_EOF)
    {
      builtin_error ("%s", p.err[0] ? p.err : "parse failed");
      node_free (root); vals_free (&stream);
      for (int i = 0; i < lx.n; i++) free (lx.v[i].v);
      free (lx.v);
      return EX_USAGE;
    }

  vals_t out = {0};
  int rc = EXECUTION_SUCCESS;
  for (int i = 0; i < stream.n; i++)
    if (eval_node (root, stream.v[i], &out) < 0)
      { rc = EXECUTION_FAILURE; break; }

  sbuf_t bound = {0};
  for (int i = 0; i < out.n; i++)
    {
      json_compact (out.v[i]);
      char *raw_s = NULL;
      const char *emit = out.v[i];
      if (raw && json_type (out.v[i]) && !strcmp (json_type (out.v[i]), "string"))
        { raw_s = json_unstring (out.v[i]); emit = raw_s ? raw_s : ""; }
      if (out_var)
        {
          if (i && sb_puts (&bound, "\n") < 0) rc = EXECUTION_FAILURE;
          if (sb_puts (&bound, emit) < 0) rc = EXECUTION_FAILURE;
        }
      else
        printf ("%s\n", emit);
      free (raw_s);
    }
  if (out_var && rc == EXECUTION_SUCCESS)
    builtin_bind_variable ((char *) out_var, bound.p ? bound.p : "", 0);
  if (exit_status)
    {
      if (out.n == 0 || !strcmp (out.v[out.n-1], "null") || !strcmp (out.v[out.n-1], "false")) rc = EXECUTION_FAILURE;
    }

  free (bound.p);
  vals_free (&out);
  vals_free (&stream);
  node_free (root);
  for (int i = 0; i < lx.n; i++) free (lx.v[i].v);
  free (lx.v);
  return rc;
}

int
jq_builtin (WORD_LIST *list)
{
  int raw = 0, exit_status = 0, slurp = 0, stream = 0, null_input = 0;
  const char *filter = NULL, *file = NULL, *filter_file = NULL;
  const char *input_var = NULL, *out_var = NULL;
  for (WORD_LIST *a = list; a; a = a->next)
    {
      const char *w = a->word->word;
      if (!strcmp (w, "-r") || !strcmp (w, "--raw-output")) raw = 1;
      else if (!strcmp (w, "-e") || !strcmp (w, "--exit-status")) exit_status = 1;
      else if (!strcmp (w, "-c") || !strcmp (w, "--compact-output")) ;
      else if (!strcmp (w, "-n") || !strcmp (w, "--null-input")) null_input = 1;
      else if (!strcmp (w, "-f")) { if (!a->next) { builtin_error ("-f needs file"); return EX_USAGE; } a = a->next; filter_file = a->word->word; }
      else if (!strcmp (w, "-i")) { if (!a->next) { builtin_error ("-i needs INPUT_VAR"); return EX_USAGE; } a = a->next; input_var = a->word->word; }
      else if (!strcmp (w, "-V")) { if (!a->next) { builtin_error ("-V needs OUT_VAR"); return EX_USAGE; } a = a->next; out_var = a->word->word; }
      else if (!strcmp (w, "-s") || !strcmp (w, "--slurp")) slurp = 1;
      else if (!strcmp (w, "--stream")) stream = 1;
      /* A leading '-' followed by a non-alphabetic char is a FILTER beginning
         with unary minus (jq's `-.`, `-5`, `-(...)`), not a flag. Only treat
         `-<alpha>...` and `--<long>` as flags, so typo'd alpha flags still
         error while a unary-minus filter is accepted (jq parity). */
      else if (w[0] == '-' && (isalpha ((unsigned char) w[1]) || w[1] == '-'))
        { builtin_error ("unknown flag: %s", w); builtin_usage (); return EX_USAGE; }
      else if (!filter) filter = w;
      else if (!file) file = w;
      else { builtin_error ("extra arg: %s", w); return EX_USAGE; }
    }
  char *filter_buf = NULL, *doc = NULL; size_t len = 0;
  if (filter_file)
    {
      if (slurp_file (filter_file, &filter_buf, &len) < 0) { builtin_error ("cannot read %s", filter_file); return EXECUTION_FAILURE; }
      filter = filter_buf;
    }
  if (!filter) { builtin_error ("usage: jq [-r] [-e] FILTER [FILE]"); free (filter_buf); return EX_USAGE; }
  if (input_var)
    {
      char *v = get_string_value (input_var);
      if (!v) { builtin_error ("input variable not set: %s", input_var); free (filter_buf); return EXECUTION_FAILURE; }
      doc = xstrdup (v);
      if (!doc) { free (filter_buf); return EXECUTION_FAILURE; }
    }
  else if (null_input)
    {
      doc = xstrdup ("null");
      if (!doc) { free (filter_buf); return EXECUTION_FAILURE; }
    }
  else
    {
      int sr = file ? slurp_file (file, &doc, &len) : slurp_fd (STDIN_FILENO, &doc, &len);
      if (sr < 0) { builtin_error ("cannot read input"); free (filter_buf); return EXECUTION_FAILURE; }
    }
  if (slurp)
    {
      char *slurped = json_slurp_array (doc);
      if (!slurped) { builtin_error ("cannot slurp JSON input"); free (filter_buf); free (doc); return EXECUTION_FAILURE; }
      free (doc);
      doc = slurped;
    }
  int rc = stream ? run_stream_filter (filter, doc, raw, exit_status, out_var)
                  : run_filter (filter, doc, raw, exit_status, out_var);
  free (filter_buf); free (doc);
  return rc;
}

char *jq_doc[] = {
  "jq-subset filter evaluator for bash-os (Stage 48).",
  "    jq [-r] [-e] FILTER [FILE]",
  "    jq -n FILTER",
  "    jq FILTER -i INPUT_VAR -V OUT_VAR",
  "    jq -f FILTER_FILE [FILE]",
  "    jq --slurp FILTER [FILE]",
  "    jq --stream FILTER [FILE]",
  "Supports paths, pipes, [], length/keys/type/has, select/map, comparisons,",
  "boolean ops, arithmetic, //, if/elif/else, literals, postfix ?, and",
  "streaming leaf tuples.",
  (char *)NULL
};

struct builtin jq_struct = {
  "jq",
  jq_builtin,
  BUILTIN_ENABLED,
  jq_doc,
  "jq [-r] [-e] [-n] FILTER [FILE]",
  0
};
