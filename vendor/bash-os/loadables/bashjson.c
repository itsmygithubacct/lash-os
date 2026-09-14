/* bashjson.c — JSON parser/serializer. Loadable for bash.
 *
 * Bash has no native structured-data parser. Hand-rolled grep/sed
 * solutions break on real-world JSON (escape sequences, unicode,
 * nested arrays/objects). bashjson uses the vendored jsmn tokenizer
 * (zserge/jsmn, MIT) plus a small path resolver.
 *
 * ──── Deliberate divergences from Python json (DO NOT "loosen"
 *      without operator sign-off — see HOST-SAFE-RESIDUALS.parts/
 *      03-structured-data-and-time.md) ────
 *
 * (1) Duplicate object keys → REJECTED by default.
 *     Python json.loads accepts duplicates with last-wins semantics.
 *     RFC 8259 §4 says implementations SHOULD reject duplicates;
 *     bashjson does. This is the standards-compliant posture. Operators
 *     can opt out only for validation compatibility with
 *     `--no-strict-json` / `--python-json-lenient`.
 *
 * (2) Negative array index `[-N]` → REJECTED.
 *     jq supports `.arr[-1]` for the last element; Python json's
 *     standard subset doesn't have a path syntax to compare against.
 *     bashjson's STEP_INDEX parser at bj_parse_step (line ~346) is
 *     digit-only by design. Additive feature; add
 *     `if (idx < 0) idx += t->size;` if operator demand surfaces.
 *
 * (3) JSON `NaN` / `Infinity` / `-Infinity` literals → REJECTED by default.
 *     Python json.loads accepts these by default (allow_nan=True).
 *     RFC 8259 §6 explicitly disallows them. bashjson rejects via
 *     bj_syntax_literal's strict memcmp. bashjson is the
 *     RFC-compliant side; Python is the lenient outlier. The explicit
 *     validation opt-out accepts these three constants only.
 *
 * (4) Path-component buffer cap (`name[256]`) → REJECTED.
 *     Inherent to bashjson's path verbs. Python json doesn't have
 *     this notion (uses dict access). Documented hard limit.
 *
 * Subcommands:
 *   bashjson parse   < doc           emit "TYPE PATH VALUE" per leaf
 *   bashjson get   PATH < doc        print value at PATH (one line, JSON-quoted)
 *   bashjson set   PATH VALUE < doc  rewrite, print new doc
 *   bashjson type  PATH < doc        prints: string|number|bool|null|array|object|none
 *   bashjson has   PATH < doc        exit 0 if exists, 1 otherwise
 *   bashjson length PATH < doc       array len, object key count,
 *                                      or string length (UTF-8 bytes)
 *   bashjson keys  PATH < doc        object keys, one per line
 *
 * Path syntax (subset of jq):
 *   .                    root
 *   .foo                 object field
 *   .foo.bar             nested
 *   .arr[3]              array index
 *   .arr[3].field        chained
 *
 * All input via stdin or with the doc piped through. Output is
 * JSON-encoded by default (so strings keep their quotes); jq.sh
 * implements the -r raw output option on top.
 *
 * Companion docs:
 *     /docs/bash/bashjson.txt
 *     /bash-os/jq.sh — jq-subset wrapper using these subcommands
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
#include <ctype.h>

#define JSMN_STATIC
#define JSMN_PARENT_LINKS
#include "_jsmn_jsmn.h"

/* Max nesting depth for validate. 64 is deep enough for ordinary JSON;
   the env override is bounded to keep pathological inputs constrained. */
#define BJ_DEFAULT_MAX_NESTING 64
#define BJ_HARD_MAX_NESTING 4096

#include "loadables.h"

typedef struct {
  int strict_json;
  int python_lenient;
} bj_opts;

/* ---- Slurp stdin into a malloc'd buffer ----------------------------- */
static int
bj_slurp_stdin (char **out_buf, size_t *out_len)
{
  size_t cap = 8192, n = 0;
  char *buf = malloc (cap);
  if (!buf) return -1;
  for (;;)
    {
      if (n + 4096 > cap)
        {
          cap *= 2;
          char *nb = realloc (buf, cap);
          if (!nb) { free (buf); return -1; }
          buf = nb;
        }
      ssize_t k = read (STDIN_FILENO, buf + n, cap - n);
      if (k < 0)
        {
          if (errno == EINTR) continue;
          free (buf);
          return -1;
        }
      if (k == 0) break;
      n += (size_t) k;
    }
  buf[n] = '\0';
  *out_buf = buf;
  *out_len = n;
  return 0;
}

/* ---- Token utilities ------------------------------------------------ */
/* Compare two tokens' source slices for byte-equality. */
static int
bj_tok_eq_tok (const char *src, const jsmntok_t *a, const jsmntok_t *b)
{
  size_t na = (size_t) (a->end - a->start);
  size_t nb = (size_t) (b->end - b->start);
  if (na != nb) return 0;
  return memcmp (src + a->start, src + b->start, na) == 0;
}

/* Print a token's raw JSON slice (no decoding). */
static void
bj_print_tok (const char *src, const jsmntok_t *t)
{
  fwrite (src + t->start, 1, (size_t) (t->end - t->start), stdout);
}

/* Print a token as a JSON-encoded value. For strings, wrap in quotes
   and re-escape via the source bytes (the source already has them
   escaped, but jsmn returns the inside of the quotes — re-add them). */
static void
bj_emit_value (const char *src, const jsmntok_t *t)
{
  switch (t->type)
    {
    case JSMN_STRING:
      putchar ('"');
      bj_print_tok (src, t);
      putchar ('"');
      break;
    case JSMN_PRIMITIVE:
    case JSMN_OBJECT:
    case JSMN_ARRAY:
    default:
      bj_print_tok (src, t);
      break;
    }
}

static int
bj_hex4 (const char *s, unsigned int *out)
{
  unsigned int code = 0;

  for (size_t h = 0; h < 4; h++)
    {
      unsigned char c = (unsigned char) s[h];
      unsigned int hv;

      if      (c >= '0' && c <= '9') hv = (unsigned) (c - '0');
      else if (c >= 'a' && c <= 'f') hv = (unsigned) (c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') hv = (unsigned) (c - 'A' + 10);
      else return -1;

      code = (code << 4) | hv;
    }

  *out = code;
  return 0;
}

static int
bj_append_utf8_codepoint (unsigned int code, char *out, size_t *pos)
{
  if (code <= 0x7F)
    {
      out[(*pos)++] = (char) code;
      return 0;
    }
  if (code <= 0x7FF)
    {
      out[(*pos)++] = (char) (0xC0 | (code >> 6));
      out[(*pos)++] = (char) (0x80 | (code & 0x3F));
      return 0;
    }
  if (code <= 0xFFFF)
    {
      if (code >= 0xD800 && code <= 0xDFFF)
        return -1;
      out[(*pos)++] = (char) (0xE0 | (code >> 12));
      out[(*pos)++] = (char) (0x80 | ((code >> 6) & 0x3F));
      out[(*pos)++] = (char) (0x80 | (code & 0x3F));
      return 0;
    }
  if (code <= 0x10FFFF)
    {
      out[(*pos)++] = (char) (0xF0 | (code >> 18));
      out[(*pos)++] = (char) (0x80 | ((code >> 12) & 0x3F));
      out[(*pos)++] = (char) (0x80 | ((code >> 6) & 0x3F));
      out[(*pos)++] = (char) (0x80 | (code & 0x3F));
      return 0;
    }

  return -1;
}

/* Decode the JSON escape spelling from a JSMN string token into bytes.
   Unicode escapes are expanded to UTF-8 so escaped object keys resolve the
   same way as raw UTF-8 keys. */
static char *
bj_decode_string_token (const char *src, const jsmntok_t *t, size_t *out_len)
{
  size_t n = (size_t) (t->end - t->start);
  char *out = malloc (n + 1);
  size_t pos = 0;

  if (!out)
    return NULL;

  for (size_t i = 0; i < n; i++)
    {
      unsigned char ch = (unsigned char) src[t->start + (int) i];
      if (ch == '\\' && i + 1 < n)
        {
          unsigned char esc = (unsigned char) src[t->start + (int) ++i];
          switch (esc)
            {
            case '"': case '\\': case '/':
              out[pos++] = (char) esc;
              break;
            case 'b':
              out[pos++] = '\b';
              break;
            case 'f':
              out[pos++] = '\f';
              break;
            case 'n':
              out[pos++] = '\n';
              break;
            case 'r':
              out[pos++] = '\r';
              break;
            case 't':
              out[pos++] = '\t';
              break;
            case 'u':
              if (i + 4 < n)
                {
                  unsigned int code;
                  if (bj_hex4 (src + t->start + (int) i + 1, &code) == 0)
                    {
                      if (code >= 0xD800 && code <= 0xDBFF
                          && i + 10 < n
                          && src[t->start + (int) i + 5] == '\\'
                          && src[t->start + (int) i + 6] == 'u')
                        {
                          unsigned int low;
                          if (bj_hex4 (src + t->start + (int) i + 7, &low) == 0
                              && low >= 0xDC00 && low <= 0xDFFF)
                            {
                              code = 0x10000 + (((code - 0xD800) << 10)
                                                | (low - 0xDC00));
                              if (bj_append_utf8_codepoint (code, out, &pos) < 0)
                                out[pos++] = '?';
                              i += 10;
                              break;
                            }
                        }
                      if (bj_append_utf8_codepoint (code, out, &pos) < 0)
                        out[pos++] = '?';
                    }
                  else
                    out[pos++] = '?';
                  i += 4;
                }
              else
                out[pos++] = (char) esc;
              break;
            default:
              out[pos++] = (char) esc;
              break;
            }
        }
      else
        out[pos++] = (char) ch;
    }

  out[pos] = '\0';
  if (out_len)
    *out_len = pos;
  return out;
}

static int
bj_tok_decoded_eq (const char *src, const jsmntok_t *t, const char *s, size_t n)
{
  size_t keyn;
  char *key = bj_decode_string_token (src, t, &keyn);
  int match;

  if (!key)
    return 0;

  match = (keyn == n && memcmp (key, s, n) == 0);
  free (key);
  return match;
}

/* Walk past a token and all its descendants, returning the index of
   the next sibling (or end of array). With JSMN_PARENT_LINKS we could
   binary-search; the simple recursive walk is fine for shell-pace use. */
static int
bj_skip (jsmntok_t *toks, int idx)
{
  jsmntok_t *t = &toks[idx];
  switch (t->type)
    {
    case JSMN_OBJECT:
      {
        int ni = idx + 1;
        for (int i = 0; i < t->size; i++)
          {
            ni = bj_skip (toks, ni);  /* key (always primitive/string) */
            ni = bj_skip (toks, ni);  /* value */
          }
        return ni;
      }
    case JSMN_ARRAY:
      {
        int ni = idx + 1;
        for (int i = 0; i < t->size; i++)
          ni = bj_skip (toks, ni);
        return ni;
      }
    default:
      return idx + 1;
    }
}

/* Parse a single path step: ".name" or "[N]". Returns the length of
   the consumed prefix, writes the step kind + value to *out_kind /
   *out_buf. Returns 0 on parse error or end-of-path. */
typedef enum { STEP_FIELD, STEP_INDEX, STEP_END } bj_step_kind;
static int
bj_parse_step (const char *path, bj_step_kind *out_kind, char *out_buf, size_t out_sz, int *out_idx)
{
  if (*path == '\0') { *out_kind = STEP_END; return 0; }
  if (path[0] == '.')
    {
      const char *p = path + 1;
      char *q = out_buf;
      char *qend = out_buf + out_sz - 1;  /* leave room for NUL */
      while (*p && *p != '.' && *p != '[')
        {
          if (q >= qend) return -1;        /* path component too long */
          if (*p == '\\' && p[1])
            {
              p++;
              switch (*p)
                {
                case 'n': *q++ = '\n'; p++; continue;
                case 'r': *q++ = '\r'; p++; continue;
                case 't': *q++ = '\t'; p++; continue;
                case 'b': *q++ = '\b'; p++; continue;
                case 'f': *q++ = '\f'; p++; continue;
                default: *q++ = *p++; continue;
                }
            }
          *q++ = *p++;
        }
      *q = '\0';
      *out_kind = STEP_FIELD;
      return (int) (p - path);
    }
  if (path[0] == '[')
    {
      const char *p = path + 1;
      int idx = 0;
      int ndigits = 0;
      while (*p >= '0' && *p <= '9') { idx = idx * 10 + (*p - '0'); p++; ndigits++; }
      if (ndigits == 0) return -1;
      if (*p != ']') return -1;
      *out_idx = idx;
      *out_kind = STEP_INDEX;
      return (int) (p + 1 - path);
    }
  return -1;
}

/* Resolve a path through a tokenized JSON document. Returns the
   matching token index, or -1 if not found. The path "." (or empty
   after the leading dot is consumed) returns the root. */
static int
bj_resolve (const char *src, jsmntok_t *toks, int ntoks, const char *path)
{
  int cur = 0;
  if (cur >= ntoks) return -1;

  /* Path "." or "" → root. The most common single-step cases. */
  if (path[0] == '\0' || (path[0] == '.' && path[1] == '\0'))
    return 0;

  while (*path)
    {
      char name[256];
      int idx = -1;
      bj_step_kind kind;
      int consumed = bj_parse_step (path, &kind, name, sizeof name, &idx);
      if (consumed < 0) return -1;        /* path component too long */
      if (consumed == 0 && kind != STEP_END) return -1;
      path += consumed;
      if (kind == STEP_END) break;

      jsmntok_t *t = &toks[cur];
      if (kind == STEP_FIELD)
        {
          if (t->type != JSMN_OBJECT) return -1;
          /* Walk children: pairs of (key, value). */
          int ci = cur + 1;
          int found = -1;
          for (int i = 0; i < t->size; i++)
            {
              jsmntok_t *kt = &toks[ci];
              int vi = ci + 1;
              if (kt->type == JSMN_STRING
                  && bj_tok_decoded_eq (src, kt, name, strlen (name)))
                { found = vi; break; }
              ci = bj_skip (toks, vi);  /* skip value */
            }
          if (found < 0) return -1;
          cur = found;
        }
      else if (kind == STEP_INDEX)
        {
          if (t->type != JSMN_ARRAY) return -1;
          if (idx >= t->size) return -1;
          int ci = cur + 1;
          for (int i = 0; i < idx; i++)
            ci = bj_skip (toks, ci);
          cur = ci;
        }
    }
  return cur;
}

/* ---- jsmn wrapper: parse with growth ------------------------------- */
static jsmntok_t *
bj_tokenize (const char *src, size_t len, int *out_ntoks)
{
  jsmn_parser p;
  int cap = 256;
  jsmntok_t *toks = malloc (sizeof *toks * cap);
  if (!toks) return NULL;
  for (;;)
    {
      jsmn_init (&p);
      int r = jsmn_parse (&p, src, len, toks, cap);
      if (r >= 0) { *out_ntoks = r; return toks; }
      if (r == JSMN_ERROR_NOMEM)
        {
          cap *= 2;
          jsmntok_t *nt = realloc (toks, sizeof *toks * cap);
          if (!nt) { free (toks); return NULL; }
          toks = nt;
          continue;
        }
      free (toks);
      return NULL;
    }
}

/* ---- Subcommands ---------------------------------------------------- */

static const char *
bj_typename (jsmntype_t t, const char *src, jsmntok_t *tok)
{
  switch (t)
    {
    case JSMN_STRING:    return "string";
    case JSMN_OBJECT:    return "object";
    case JSMN_ARRAY:     return "array";
    case JSMN_PRIMITIVE:
      {
        char c = src[tok->start];
        if (c == 't' || c == 'f') return "boolean";
        if (c == 'n')              return "null";
        return "number";
      }
    default: return "unknown";
    }
}

static int
bj_get_cmd (WORD_LIST *args)
{
  const char *path = (args && args->word) ? args->word->word : ".";
  /* Strip leading '.' for our resolver: ".foo" → ".foo" (we expect
     the dot). But ".foo.bar" works as-is. Empty/"." == root. */
  char *src; size_t len;
  if (bj_slurp_stdin (&src, &len) < 0) { builtin_error ("slurp stdin"); return EXECUTION_FAILURE; }
  int ntoks;
  jsmntok_t *toks = bj_tokenize (src, len, &ntoks);
  if (!toks || ntoks <= 0)
    { builtin_error ("invalid JSON"); free (src); free (toks); return EXECUTION_FAILURE; }
  int idx = bj_resolve (src, toks, ntoks, path);
  if (idx < 0)
    { free (src); free (toks); return EXECUTION_FAILURE; }
  bj_emit_value (src, &toks[idx]);
  putchar ('\n');
  free (src); free (toks);
  return EXECUTION_SUCCESS;
}

static int
bj_type_cmd (WORD_LIST *args)
{
  const char *path = (args && args->word) ? args->word->word : ".";
  char *src; size_t len;
  if (bj_slurp_stdin (&src, &len) < 0) return EXECUTION_FAILURE;
  int ntoks;
  jsmntok_t *toks = bj_tokenize (src, len, &ntoks);
  if (!toks || ntoks <= 0)
    { fputs ("none\n", stdout); free (src); free (toks); return EXECUTION_SUCCESS; }
  int idx = bj_resolve (src, toks, ntoks, path);
  if (idx < 0) { fputs ("none\n", stdout); free (src); free (toks); return EXECUTION_SUCCESS; }
  printf ("%s\n", bj_typename (toks[idx].type, src, &toks[idx]));
  free (src); free (toks);
  return EXECUTION_SUCCESS;
}

static int
bj_has_cmd (WORD_LIST *args)
{
  const char *path = (args && args->word) ? args->word->word : ".";
  char *src; size_t len;
  if (bj_slurp_stdin (&src, &len) < 0) return EXECUTION_FAILURE;
  int ntoks;
  jsmntok_t *toks = bj_tokenize (src, len, &ntoks);
  int idx = (toks && ntoks > 0) ? bj_resolve (src, toks, ntoks, path) : -1;
  free (src); free (toks);
  return idx >= 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bj_append_path_key_bytes (char *path, size_t pathmax, size_t pathlen,
                          const char *key, size_t keyn)
{
  size_t pos = pathlen;

  if (pos + 2 > pathmax)
    return -1;

  path[pos++] = '.';
  for (size_t i = 0; i < keyn; i++)
    {
      unsigned char ch = (unsigned char) key[i];
      int short_escape = (ch == '\n' || ch == '\r' || ch == '\t' ||
                          ch == '\b' || ch == '\f');
      int needs_escape = short_escape || ch == '.' || ch == '[' || ch == ']' ||
                          ch == '\\' || ch == '"';
      size_t need = needs_escape ? 2 : 1;

      if (pos + need + 1 > pathmax)
        return -1;

      if (needs_escape)
        {
          path[pos++] = '\\';
          switch (ch)
            {
            case '\n': path[pos++] = 'n'; continue;
            case '\r': path[pos++] = 'r'; continue;
            case '\t': path[pos++] = 't'; continue;
            case '\b': path[pos++] = 'b'; continue;
            case '\f': path[pos++] = 'f'; continue;
            default: break;
            }
        }
      path[pos++] = (char) ch;
    }
  path[pos] = '\0';
  return (int) pos;
}

static int
bj_append_path_key (char *path, size_t pathmax, size_t pathlen,
                    const char *src, const jsmntok_t *kt)
{
  size_t keyn;
  char *key = bj_decode_string_token (src, kt, &keyn);
  int newlen;

  if (!key)
    return -1;

  newlen = bj_append_path_key_bytes (path, pathmax, pathlen, key, keyn);
  free (key);
  return newlen;
}

static int
bj_length_cmd (WORD_LIST *args)
{
  const char *path = (args && args->word) ? args->word->word : ".";
  char *src; size_t len;
  if (bj_slurp_stdin (&src, &len) < 0) return EXECUTION_FAILURE;
  int ntoks;
  jsmntok_t *toks = bj_tokenize (src, len, &ntoks);
  if (!toks || ntoks <= 0)
    { builtin_error ("invalid JSON"); free (src); free (toks); return EXECUTION_FAILURE; }
  int idx = bj_resolve (src, toks, ntoks, path);
  if (idx < 0)
    { builtin_error ("path not found: %s", path); free (src); free (toks); return EXECUTION_FAILURE; }
  jsmntok_t *t = &toks[idx];
  long long n;
  switch (t->type)
    {
    case JSMN_ARRAY:
    case JSMN_OBJECT:
      n = t->size;
      break;
    case JSMN_STRING:
      /* Length in UTF-8 bytes of the string (raw, not decoded). */
      n = (long long) (t->end - t->start);
      break;
    case JSMN_PRIMITIVE:
      /* For null we return 0 (jq convention); for numbers we return
         the digit count which is meaningless — but this matches
         neither bash users' expectation; raise an error. Actually:
         jq says length of a number is its absolute value. We don't
         have a float parser here; emit the digit-byte length and
         document. */
      if (src[t->start] == 'n') n = 0;
      else                       n = (long long) (t->end - t->start);
      break;
    default: n = 0;
    }
  printf ("%lld\n", n);
  free (src); free (toks);
  return EXECUTION_SUCCESS;
}

static int
bj_keys_cmd (WORD_LIST *args)
{
  const char *path = (args && args->word) ? args->word->word : ".";
  char *src; size_t len;
  if (bj_slurp_stdin (&src, &len) < 0) return EXECUTION_FAILURE;
  int ntoks;
  jsmntok_t *toks = bj_tokenize (src, len, &ntoks);
  if (!toks || ntoks <= 0)
    { builtin_error ("invalid JSON"); free (src); free (toks); return EXECUTION_FAILURE; }
  int idx = bj_resolve (src, toks, ntoks, path);
  if (idx < 0)
    { builtin_error ("path not found: %s", path); free (src); free (toks); return EXECUTION_FAILURE; }
  if (toks[idx].type != JSMN_OBJECT)
    { builtin_error ("not an object: %s", path); free (src); free (toks); return EXECUTION_FAILURE; }
  int ci = idx + 1;
  for (int i = 0; i < toks[idx].size; i++)
    {
      jsmntok_t *kt = &toks[ci];
      bj_print_tok (src, kt);
      putchar ('\n');
      ci = bj_skip (toks, ci + 1);  /* skip value */
    }
  free (src); free (toks);
  return EXECUTION_SUCCESS;
}

typedef struct {
  int key;
  int value;
} bj_obj_ent;

static int
bj_tok_slice_cmp (const char *src, const jsmntok_t *a, const jsmntok_t *b)
{
  size_t na = (size_t) (a->end - a->start);
  size_t nb = (size_t) (b->end - b->start);
  size_t n = na < nb ? na : nb;
  int r = memcmp (src + a->start, src + b->start, n);

  if (r != 0)
    return r;
  if (na < nb)
    return -1;
  if (na > nb)
    return 1;
  return 0;
}

static void
bj_sort_obj_entries (const char *src, jsmntok_t *toks, bj_obj_ent *ents, int n)
{
  for (int i = 1; i < n; i++)
    {
      bj_obj_ent cur = ents[i];
      int j = i - 1;
      while (j >= 0
             && bj_tok_slice_cmp (src, &toks[ents[j].key], &toks[cur.key]) > 0)
        {
          ents[j + 1] = ents[j];
          j--;
        }
      ents[j + 1] = cur;
    }
}

static void bj_emit_json_sorted (const char *src, jsmntok_t *toks, int idx,
                                 int pretty, int level);
static int bj_validate_syntax (const char *src, size_t len, const char **err,
                               const bj_opts *opts);
static int bj_max_depth (jsmntok_t *toks, int ntoks);
static int bj_max_nesting_limit (void);
static int bj_dupkey_idx (const char *src, jsmntok_t *toks, int ntoks);

static void
bj_emit_indent (int level)
{
  for (int i = 0; i < level * 3; i++)
    putchar (' ');
}

static void
bj_emit_object_sorted (const char *src, jsmntok_t *toks, int idx,
                       int pretty, int level)
{
  int n = toks[idx].size;
  bj_obj_ent *ents = NULL;
  int ci = idx + 1;

  if (n > 0)
    {
      ents = malloc ((size_t) n * sizeof *ents);
      if (!ents)
        {
          /* Best-effort fallback: preserve source order if allocation fails. */
          putchar ('{');
          for (int i = 0; i < n; i++)
            {
              int key = ci;
              int val = ci + 1;
              if (i > 0) putchar (',');
              bj_emit_value (src, &toks[key]);
              putchar (':');
              bj_emit_json_sorted (src, toks, val, 0, level);
              ci = bj_skip (toks, val);
            }
          putchar ('}');
          return;
        }

      for (int i = 0; i < n; i++)
        {
          ents[i].key = ci;
          ents[i].value = ci + 1;
          ci = bj_skip (toks, ci + 1);
        }
      bj_sort_obj_entries (src, toks, ents, n);
    }

  if (!pretty)
    {
      putchar ('{');
      for (int i = 0; i < n; i++)
        {
          if (i > 0) putchar (',');
          bj_emit_value (src, &toks[ents[i].key]);
          putchar (':');
          bj_emit_json_sorted (src, toks, ents[i].value, pretty, level);
        }
      putchar ('}');
      free (ents);
      return;
    }

  printf ("{\n");
  for (int i = 0; i < n; i++)
    {
      if (i > 0)
        printf (",\n");
      bj_emit_indent (level + 1);
      bj_emit_value (src, &toks[ents[i].key]);
      printf (" : ");
      bj_emit_json_sorted (src, toks, ents[i].value, pretty, level + 1);
    }
  printf ("\n");
  bj_emit_indent (level);
  putchar ('}');
  free (ents);
}

static void
bj_emit_array_sorted (const char *src, jsmntok_t *toks, int idx,
                      int pretty, int level)
{
  int n = toks[idx].size;
  int ci = idx + 1;

  if (!pretty)
    {
      putchar ('[');
      for (int i = 0; i < n; i++)
        {
          if (i > 0) putchar (',');
          bj_emit_json_sorted (src, toks, ci, pretty, level);
          ci = bj_skip (toks, ci);
        }
      putchar (']');
      return;
    }

  printf ("[\n");
  for (int i = 0; i < n; i++)
    {
      if (i > 0)
        printf (",\n");
      bj_emit_indent (level + 1);
      bj_emit_json_sorted (src, toks, ci, pretty, level + 1);
      ci = bj_skip (toks, ci);
    }
  printf ("\n");
  bj_emit_indent (level);
  putchar (']');
}

static void
bj_emit_json_sorted (const char *src, jsmntok_t *toks, int idx,
                     int pretty, int level)
{
  switch (toks[idx].type)
    {
    case JSMN_OBJECT:
      bj_emit_object_sorted (src, toks, idx, pretty, level);
      break;
    case JSMN_ARRAY:
      bj_emit_array_sorted (src, toks, idx, pretty, level);
      break;
    default:
      bj_emit_value (src, &toks[idx]);
      break;
    }
}

static int
bj_emit_cmd (WORD_LIST *args, const bj_opts *opts, int default_pretty)
{
  int pretty = default_pretty;

  while (args && args->word && args->word->word)
    {
      const char *a = args->word->word;
      if (strcmp (a, "--pretty") == 0)
        pretty = 1;
      else if (strcmp (a, "--compact") == 0 || strcmp (a, "--canonical") == 0)
        pretty = 0;
      else
        {
          builtin_error ("unknown emit option: %s", a);
          return EX_USAGE;
        }
      args = args->next;
    }

  char *src; size_t len;
  if (bj_slurp_stdin (&src, &len) < 0)
    { builtin_error ("slurp stdin"); return EXECUTION_FAILURE; }

  int ntoks;
  jsmntok_t *toks = bj_tokenize (src, len, &ntoks);
  if (!toks || ntoks <= 0)
    { builtin_error ("invalid JSON"); free (src); free (toks); return EXECUTION_FAILURE; }

  const char *syntax_err = NULL;
  if (bj_validate_syntax (src, len, &syntax_err, opts) < 0)
    {
      builtin_error ("%s", syntax_err ? syntax_err : "invalid JSON");
      free (src); free (toks); return EXECUTION_FAILURE;
    }

  if (bj_max_depth (toks, ntoks) > bj_max_nesting_limit ())
    {
      builtin_error ("nesting too deep");
      free (src); free (toks); return EXECUTION_FAILURE;
    }

  if (!opts || opts->strict_json)
    {
      int dk = bj_dupkey_idx (src, toks, ntoks);
      if (dk >= 0)
        {
          builtin_error ("duplicate key");
          free (src); free (toks); return EXECUTION_FAILURE;
        }
    }

  bj_emit_json_sorted (src, toks, 0, pretty, 0);
  if (pretty)
    putchar ('\n');
  free (src); free (toks);
  return EXECUTION_SUCCESS;
}

/* parse: emit "TYPE PATH VALUE" per leaf (or container). Walks the
   token tree producing a stream the caller can read into associative
   arrays. Path uses the same dot/bracket notation as get/set. */
static void
bj_walk (const char *src, jsmntok_t *toks, int idx, char *path, size_t pathmax, size_t pathlen)
{
  jsmntok_t *t = &toks[idx];
  const char *typ = bj_typename (t->type, src, t);
  /* Print: "TYPE PATH VALUE\n". For containers, emit raw JSON (which
     can be huge but is correct); the caller will likely recurse. */
  printf ("%s %s ", typ, pathlen ? path : ".");
  bj_emit_value (src, t);
  putchar ('\n');
  if (t->type == JSMN_OBJECT)
    {
      int ci = idx + 1;
      for (int i = 0; i < t->size; i++)
        {
          jsmntok_t *kt = &toks[ci];
          int vi = ci + 1;
          /* Append .KEY to path */
          int newlen = bj_append_path_key (path, pathmax, pathlen, src, kt);
          if (newlen < 0) { ci = bj_skip (toks, vi); continue; }
          bj_walk (src, toks, vi, path, pathmax, newlen);
          path[pathlen] = '\0';
          ci = bj_skip (toks, vi);
        }
    }
  else if (t->type == JSMN_ARRAY)
    {
      int ci = idx + 1;
      for (int i = 0; i < t->size; i++)
        {
          char buf[32];
          int n = snprintf (buf, sizeof buf, "[%d]", i);
          if (pathlen + (size_t) n + 1 > pathmax) { ci = bj_skip (toks, ci); continue; }
          memcpy (path + pathlen, buf, (size_t) n);
          size_t newlen = pathlen + (size_t) n;
          path[newlen] = '\0';
          bj_walk (src, toks, ci, path, pathmax, newlen);
          path[pathlen] = '\0';
          ci = bj_skip (toks, ci);
        }
    }
}

static int
bj_parse_cmd (WORD_LIST *args)
{
  (void) args;
  char *src; size_t len;
  if (bj_slurp_stdin (&src, &len) < 0) return EXECUTION_FAILURE;
  int ntoks;
  jsmntok_t *toks = bj_tokenize (src, len, &ntoks);
  if (!toks || ntoks <= 0)
    { builtin_error ("invalid JSON"); free (src); free (toks); return EXECUTION_FAILURE; }
  char path[1024] = "";
  bj_walk (src, toks, 0, path, sizeof path, 0);
  free (src); free (toks);
  return EXECUTION_SUCCESS;
}

/* set: rewrite JSON with a value at PATH. Approach: tokenize, find the
   target token's byte range, splice [src..start] + new value +
   [end..end_of_doc] to stdout. Doesn't reformat surrounding whitespace
   (passes through verbatim). New value must be a valid JSON literal
   (caller's responsibility — bashjson set ".foo" '"hello"' for a
   string, '42' for a number, etc.). */
static int
bj_set_cmd (WORD_LIST *args)
{
  if (!args || !args->next)
    { builtin_error ("set needs PATH VALUE"); return EX_USAGE; }
  const char *path = args->word->word;
  const char *value = args->next->word->word;
  char *src; size_t len;
  if (bj_slurp_stdin (&src, &len) < 0) return EXECUTION_FAILURE;
  int ntoks;
  jsmntok_t *toks = bj_tokenize (src, len, &ntoks);
  if (!toks || ntoks <= 0)
    { builtin_error ("invalid JSON"); free (src); free (toks); return EXECUTION_FAILURE; }
  int idx = bj_resolve (src, toks, ntoks, path);
  if (idx < 0)
    { builtin_error ("path not found: %s", path); free (src); free (toks); return EXECUTION_FAILURE; }
  jsmntok_t *t = &toks[idx];
  /* For strings, jsmn's start/end exclude the surrounding quotes.
     For other types, they cover the whole literal. We need the
     full slice including quotes for replacement. Adjust if
     string. */
  int s = t->start, e = t->end;
  if (t->type == JSMN_STRING) { s -= 1; e += 1; }
  fwrite (src, 1, (size_t) s, stdout);
  fputs (value, stdout);
  fwrite (src + e, 1, len - (size_t) e, stdout);
  free (src); free (toks);
  return EXECUTION_SUCCESS;
}

/* Compute the maximum container nesting depth of the token tree.
   Returns 0 for a single value, 1 for [1], 2 for [[1]], etc. */
static int
bj_max_depth (jsmntok_t *toks, int ntoks)
{
  int maxd = 0;
  for (int i = 0; i < ntoks; i++)
    {
      if (toks[i].type == JSMN_OBJECT || toks[i].type == JSMN_ARRAY)
        {
          int depth = 1;
          int p = toks[i].parent;
          while (p >= 0) { depth++; p = toks[p].parent; }
          if (depth > maxd) maxd = depth;
        }
    }
  return maxd;
}

static int
bj_max_nesting_limit (void)
{
  const char *s = getenv ("BASHJSON_MAX_NESTING");
  long n;

  if (!s || !*s)
    return BJ_DEFAULT_MAX_NESTING;

  n = 0;
  for (const unsigned char *p = (const unsigned char *) s; *p; p++)
    {
      if (!isdigit (*p))
        return BJ_DEFAULT_MAX_NESTING;
      n = n * 10 + (*p - '0');
      if (n > BJ_HARD_MAX_NESTING)
        return BJ_DEFAULT_MAX_NESTING;
    }
  if (n < 1)
    return BJ_DEFAULT_MAX_NESTING;

  return (int) n;
}

/* ---- bj_validate_cmd : validate JSON strictly ---------------------- */

/* Validate the content of a UTF-8 string token (unescaped control chars,
   invalid escape sequences past what jsmn already catches, invalid UTF-8
   continuation bytes).  Returns 0 on success, -1 on error. */
static int
bj_validate_string (const char *src, const jsmntok_t *t)
{
  const unsigned char *s = (const unsigned char *) src + t->start;
  size_t n = (size_t) (t->end - t->start);
  size_t i;
  for (i = 0; i < n; i++)
    {
      if (s[i] == '\\')
        {
          i++;
          if (i >= n) return -1;
          switch (s[i])
            {
            case '"': case '\\': case '/': case 'b':
            case 'f': case 'n': case 'r': case 't':
              break;
            case 'u':
              {
                /* RFC 8259 §7 strict surrogate-pair validation.
                   jsmn's parse_string (_jsmn/jsmn.h:239-251) already
                   enforces \u<4 hex digits> at parse time, so by the
                   time bj_validate_string runs the 4 bytes after \u
                   are guaranteed hex.  What jsmn does NOT enforce is
                   surrogate pairing: a high surrogate (U+D800..U+DBFF)
                   MUST be followed by `\u` plus a low surrogate
                   (U+DC00..U+DFFF), and a lone low surrogate is
                   invalid.  Pre-2026-05-19 this branch did a bare
                   `i += 4` skip and silently accepted lone or
                   mismatched surrogates.  This loop decodes the 4
                   hex digits, ranges-checks the codepoint, and for
                   high surrogates absorbs the trailing \uHHHH after
                   ranges-checking it as a low surrogate.  Hex-digit
                   defense-in-depth retained in case a future jsmn
                   upgrade relaxes its own \u check. */
                if (i + 4 >= n) return -1;
                unsigned int code = 0;
                for (size_t h = 1; h <= 4; h++)
                  {
                    unsigned char c = s[i + h];
                    unsigned int hv;
                    if      (c >= '0' && c <= '9') hv = (unsigned) (c - '0');
                    else if (c >= 'a' && c <= 'f') hv = (unsigned) (c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') hv = (unsigned) (c - 'A' + 10);
                    else return -1;
                    code = (code << 4) | hv;
                  }
                if (code >= 0xDC00 && code <= 0xDFFF)
                  return -1;            /* lone low surrogate */
                if (code >= 0xD800 && code <= 0xDBFF)
                  {
                    /* High surrogate — require `\uHHHH` low surrogate.
                       After the first \uHHHH consumes positions
                       [i..i+4], the trailing pair lives at
                       s[i+5]=='\\', s[i+6]=='u', s[i+7..i+10] hex. */
                    if (i + 10 >= n) return -1;
                    if (s[i + 5] != '\\' || s[i + 6] != 'u') return -1;
                    unsigned int low = 0;
                    for (size_t h = 0; h < 4; h++)
                      {
                        unsigned char c = s[i + 7 + h];
                        unsigned int hv;
                        if      (c >= '0' && c <= '9') hv = (unsigned) (c - '0');
                        else if (c >= 'a' && c <= 'f') hv = (unsigned) (c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') hv = (unsigned) (c - 'A' + 10);
                        else return -1;
                        low = (low << 4) | hv;
                      }
                    if (low < 0xDC00 || low > 0xDFFF) return -1;
                    i += 10;  /* absorb both \uHHHH; outer i++ moves past last hex */
                  }
                else
                  {
                    i += 4;
                  }
              }
              break;
            default:
              return -1;
            }
        }
      else if (s[i] < 0x20)
        return -1;               /* unescaped control character */
      else if (s[i] >= 0x80)
        {
          /* multi-byte UTF-8 — validate continuation bytes */
          size_t cont;
          if      (s[i] >= 0xF5) return -1;  /* > U+10FFFF */
          else if (s[i] >= 0xF0) cont = 3;
          else if (s[i] >= 0xE0) cont = 2;
          else if (s[i] >= 0xC2) cont = 1;
          else                   return -1;  /* stray continuation byte */
          size_t j;
          for (j = 1; j <= cont; j++)
            if (i + j >= n || (s[i + j] & 0xC0) != 0x80)
              return -1;
          /* reject overlong sequences */
          if (cont == 1 && s[i] == 0xC0 && (s[i+1] & 0xFE) == 0x80) return -1;
          if (cont == 2 && s[i] == 0xE0 && (s[i+1] & 0xE0) == 0x80) return -1;
          if (cont == 3 && s[i] == 0xF0 && (s[i+1] & 0xF0) == 0x80) return -1;
          i += cont;
        }
    }
  return 0;
}

/* Validate that a primitive token is a valid JSON literal (true/false/null)
   or a valid JSON number per RFC 8259 §6.  Returns 0 on success, -1 on
   error with *err set to a short diagnostic string. */
static int
bj_validate_primitive (const char *src, const jsmntok_t *t, const char **err)
{
  const unsigned char *s = (const unsigned char *) src + t->start;
  size_t n = (size_t) (t->end - t->start);
  /* check fixed literals first */
  if ((n == 4 && memcmp (s, "true",  4) == 0) ||
      (n == 5 && memcmp (s, "false", 5) == 0) ||
      (n == 4 && memcmp (s, "null",  4) == 0))
    return 0;
  /* must be a JSON number — RFC 8259 §6:  minus? int frac? exp? */
  size_t i = 0;
  if (s[i] == '-') i++;
  if (i >= n || !isdigit (s[i])) { *err = "invalid number"; return -1; }
  if (s[i] == '0' && i + 1 < n && isdigit (s[i + 1]))
    { *err = "leading zero"; return -1; }
  while (i < n && isdigit (s[i])) i++;
  if (i < n && s[i] == '.')
    {
      i++;
      if (i >= n || !isdigit (s[i])) { *err = "invalid number"; return -1; }
      while (i < n && isdigit (s[i])) i++;
    }
  if (i < n && (s[i] == 'e' || s[i] == 'E'))
    {
      i++;
      if (i < n && (s[i] == '+' || s[i] == '-')) i++;
      if (i >= n || !isdigit (s[i])) { *err = "invalid number"; return -1; }
      while (i < n && isdigit (s[i])) i++;
    }
  if (i != n) { *err = "invalid number"; return -1; }
  return 0;
}

static int
bj_python_nonfinite_literal (const char *s, size_t n)
{
  return ((n == 3 && memcmp (s, "NaN", 3) == 0) ||
          (n == 8 && memcmp (s, "Infinity", 8) == 0) ||
          (n == 9 && memcmp (s, "-Infinity", 9) == 0));
}

static int
bj_validate_primitive_with_opts (const char *src, const jsmntok_t *t,
                                 const bj_opts *opts, const char **err)
{
  const char *s = src + t->start;
  size_t n = (size_t) (t->end - t->start);

  if (opts && opts->python_lenient && bj_python_nonfinite_literal (s, n))
    return 0;

  return bj_validate_primitive (src, t, err);
}

static void
bj_syntax_skip_ws (const char *src, size_t len, size_t *pos)
{
  while (*pos < len)
    {
      unsigned char c = (unsigned char) src[*pos];
      if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
        break;
      (*pos)++;
    }
}

static int
bj_syntax_string (const char *src, size_t len, size_t *pos, const char **err)
{
  size_t p = *pos + 1;

  while (p < len)
    {
      unsigned char c = (unsigned char) src[p++];
      if (c == '"')
        {
          *pos = p;
          return 0;
        }
      if (c < 0x20)
        {
          *err = "invalid string";
          return -1;
        }
      if (c == '\\')
        {
          if (p >= len)
            return -1;
          c = (unsigned char) src[p++];
          switch (c)
            {
            case '"': case '\\': case '/': case 'b':
            case 'f': case 'n': case 'r': case 't':
              break;
            case 'u':
              for (int i = 0; i < 4; i++)
                {
                  if (p >= len || !isxdigit ((unsigned char) src[p]))
                    return -1;
                  p++;
                }
              break;
            default:
              return -1;
            }
        }
    }
  return -1;
}

static int bj_syntax_value (const char *src, size_t len, size_t *pos,
                            const char **err, const bj_opts *opts);

static int
bj_syntax_number (const char *src, size_t len, size_t *pos, const char **err)
{
  size_t start = *pos;
  size_t p = start;
  jsmntok_t tok;

  if (src[p] == '-')
    p++;
  if (p >= len || !isdigit ((unsigned char) src[p]))
    {
      *err = "invalid number";
      return -1;
    }
  if (src[p] == '0' && p + 1 < len && isdigit ((unsigned char) src[p + 1]))
    {
      *err = "leading zero";
      return -1;
    }
  while (p < len && isdigit ((unsigned char) src[p]))
    p++;
  if (p < len && src[p] == '.')
    {
      p++;
      if (p >= len || !isdigit ((unsigned char) src[p]))
        {
          *err = "invalid number";
          return -1;
        }
      while (p < len && isdigit ((unsigned char) src[p]))
        p++;
    }
  if (p < len && (src[p] == 'e' || src[p] == 'E'))
    {
      p++;
      if (p < len && (src[p] == '+' || src[p] == '-'))
        p++;
      if (p >= len || !isdigit ((unsigned char) src[p]))
        {
          *err = "invalid number";
          return -1;
        }
      while (p < len && isdigit ((unsigned char) src[p]))
        p++;
    }

  tok.type = JSMN_PRIMITIVE;
  tok.start = (int) start;
  tok.end = (int) p;
  tok.size = 0;
#ifdef JSMN_PARENT_LINKS
  tok.parent = -1;
#endif
  if (bj_validate_primitive (src, &tok, err) < 0)
    return -1;

  *pos = p;
  return 0;
}

static int
bj_syntax_literal (const char *src, size_t len, size_t *pos, const char *lit)
{
  size_t n = strlen (lit);
  if (*pos + n > len || memcmp (src + *pos, lit, n) != 0)
    return -1;
  *pos += n;
  return 0;
}

static int
bj_syntax_python_nonfinite (const char *src, size_t len, size_t *pos)
{
  size_t p = *pos;

  if (p + 3 <= len && memcmp (src + p, "NaN", 3) == 0)
    {
      *pos = p + 3;
      return 0;
    }
  if (p + 8 <= len && memcmp (src + p, "Infinity", 8) == 0)
    {
      *pos = p + 8;
      return 0;
    }
  if (p + 9 <= len && memcmp (src + p, "-Infinity", 9) == 0)
    {
      *pos = p + 9;
      return 0;
    }

  return -1;
}

static int
bj_syntax_array (const char *src, size_t len, size_t *pos, const char **err,
                 const bj_opts *opts)
{
  (*pos)++;
  bj_syntax_skip_ws (src, len, pos);
  if (*pos < len && src[*pos] == ']')
    {
      (*pos)++;
      return 0;
    }

  for (;;)
    {
      if (bj_syntax_value (src, len, pos, err, opts) < 0)
        return -1;
      bj_syntax_skip_ws (src, len, pos);
      if (*pos >= len)
        return -1;
      if (src[*pos] == ']')
        {
          (*pos)++;
          return 0;
        }
      if (src[*pos] != ',')
        return -1;
      (*pos)++;
      bj_syntax_skip_ws (src, len, pos);
      if (*pos >= len || src[*pos] == ']')
        return -1;
    }
}

static int
bj_syntax_object (const char *src, size_t len, size_t *pos, const char **err,
                  const bj_opts *opts)
{
  (*pos)++;
  bj_syntax_skip_ws (src, len, pos);
  if (*pos < len && src[*pos] == '}')
    {
      (*pos)++;
      return 0;
    }

  for (;;)
    {
      if (*pos >= len || src[*pos] != '"')
        return -1;
      if (bj_syntax_string (src, len, pos, err) < 0)
        return -1;
      bj_syntax_skip_ws (src, len, pos);
      if (*pos >= len || src[*pos] != ':')
        return -1;
      (*pos)++;
      if (bj_syntax_value (src, len, pos, err, opts) < 0)
        return -1;
      bj_syntax_skip_ws (src, len, pos);
      if (*pos >= len)
        return -1;
      if (src[*pos] == '}')
        {
          (*pos)++;
          return 0;
        }
      if (src[*pos] != ',')
        return -1;
      (*pos)++;
      bj_syntax_skip_ws (src, len, pos);
      if (*pos >= len || src[*pos] == '}')
        return -1;
    }
}

static int
bj_syntax_value (const char *src, size_t len, size_t *pos, const char **err,
                 const bj_opts *opts)
{
  bj_syntax_skip_ws (src, len, pos);
  if (*pos >= len)
    return -1;

  if (opts && opts->python_lenient
      && bj_syntax_python_nonfinite (src, len, pos) == 0)
    return 0;

  switch (src[*pos])
    {
    case '{':
      return bj_syntax_object (src, len, pos, err, opts);
    case '[':
      return bj_syntax_array (src, len, pos, err, opts);
    case '"':
      return bj_syntax_string (src, len, pos, err);
    case 't':
      return bj_syntax_literal (src, len, pos, "true");
    case 'f':
      return bj_syntax_literal (src, len, pos, "false");
    case 'n':
      return bj_syntax_literal (src, len, pos, "null");
    case '-':
      return bj_syntax_number (src, len, pos, err);
    default:
      if (isdigit ((unsigned char) src[*pos]))
        return bj_syntax_number (src, len, pos, err);
      if (src[*pos] == '.')
        *err = "invalid number";
      return -1;
    }
}

static int
bj_validate_syntax (const char *src, size_t len, const char **err,
                    const bj_opts *opts)
{
  size_t pos = 0;

  *err = NULL;
  if (bj_syntax_value (src, len, &pos, err, opts) < 0)
    return -1;
  bj_syntax_skip_ws (src, len, &pos);
  if (pos != len)
    return -1;
  return 0;
}

/* Check all keys in an object for duplicates.  Returns the first
   duplicate-key token index, or -1 if no duplicates found.
   Walks every object token (root + children) by linear scan since
   bj_skip skips entire sub-trees. */
static int
bj_dupkey_idx (const char *src, jsmntok_t *toks, int ntoks)
{
  for (int i = 0; i < ntoks; i++)
    {
      if (toks[i].type == JSMN_OBJECT)
        {
          int nk = toks[i].size;
          if (nk > 1)
            {
              int *ki = malloc ((size_t) nk * sizeof (int));
              if (!ki) return -1;
              int ci = i + 1;
              int j;
              for (j = 0; j < nk; j++)
                {
                  ki[j] = ci;
                  ci = bj_skip (toks, ci + 1);
                }
              for (j = 0; j < nk; j++)
                {
                  int k;
                  for (k = j + 1; k < nk; k++)
                    {
                      if (bj_tok_eq_tok (src, &toks[ki[j]], &toks[ki[k]]))
                        {
                          int dup = ki[k];
                          free (ki);
                          return dup;
                        }
                    }
                }
              free (ki);
            }
        }
    }
  return -1;
}

static int
bj_validate_cmd (WORD_LIST *args, const bj_opts *opts)
{
  (void) args;
  char *src; size_t len;
  if (bj_slurp_stdin (&src, &len) < 0)
    { builtin_error ("slurp stdin"); return EXECUTION_FAILURE; }
  int ntoks;
  jsmntok_t *toks = bj_tokenize (src, len, &ntoks);
  if (!toks || ntoks <= 0)
    { builtin_error ("invalid JSON"); free (src); free (toks); return EXECUTION_FAILURE; }

  const char *syntax_err = NULL;
  if (bj_validate_syntax (src, len, &syntax_err, opts) < 0)
    {
      builtin_error ("%s", syntax_err ? syntax_err : "invalid JSON");
      free (src); free (toks); return EXECUTION_FAILURE;
    }

  /* 1) Nesting-depth check — catch pathological input early */
  if (bj_max_depth (toks, ntoks) > bj_max_nesting_limit ())
    {
      builtin_error ("nesting too deep");
      free (src); free (toks); return EXECUTION_FAILURE;
    }

  /* 2) Duplicate-key check */
  if (!opts || opts->strict_json)
    {
      int dk = bj_dupkey_idx (src, toks, ntoks);
      if (dk >= 0)
        {
          builtin_error ("duplicate key");
          free (src); free (toks); return EXECUTION_FAILURE;
        }
    }

  /* 3) Validate every token's content */
  int i;
  for (i = 0; i < ntoks; i++)
    {
      if (toks[i].type == JSMN_PRIMITIVE)
        {
          const char *err = NULL;
          if (bj_validate_primitive_with_opts (src, &toks[i], opts, &err) < 0)
            {
              builtin_error ("%s", err);
              free (src); free (toks); return EXECUTION_FAILURE;
            }
        }
      else if (toks[i].type == JSMN_STRING)
        {
          if (bj_validate_string (src, &toks[i]) < 0)
            {
              builtin_error ("invalid string");
              free (src); free (toks); return EXECUTION_FAILURE;
            }
        }
    }

  free (src); free (toks);
  return EXECUTION_SUCCESS;
}

/* ---- Bash entry ---------------------------------------------------- */

int
bashjson_builtin (WORD_LIST *list)
{
  bj_opts opts;
  int saw_strict = 0;
  int saw_lenient = 0;

  if (!list) { builtin_usage (); return EX_USAGE; }
  opts.strict_json = 1;
  opts.python_lenient = 0;

  while (list && list->word && list->word->word
         && strncmp (list->word->word, "--", 2) == 0)
    {
      const char *opt = list->word->word;
      if (strcmp (opt, "--strict-json") == 0)
        {
          saw_strict = 1;
          opts.strict_json = 1;
          opts.python_lenient = 0;
          list = list->next;
          continue;
        }
      if (strcmp (opt, "--no-strict-json") == 0
          || strcmp (opt, "--python-json-lenient") == 0)
        {
          saw_lenient = 1;
          opts.strict_json = 0;
          opts.python_lenient = 1;
          list = list->next;
          continue;
        }
      break;
    }

  if (saw_strict && saw_lenient)
    {
      builtin_error ("conflicting --strict-json and --no-strict-json options");
      return EX_USAGE;
    }

  if (!list) { builtin_usage (); return EX_USAGE; }

  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "parse")  == 0) return bj_parse_cmd (args);
  if (strcmp (cmd, "get")    == 0) return bj_get_cmd (args);
  if (strcmp (cmd, "set")    == 0) return bj_set_cmd (args);
  if (strcmp (cmd, "type")   == 0) return bj_type_cmd (args);
  if (strcmp (cmd, "has")    == 0) return bj_has_cmd (args);
  if (strcmp (cmd, "length") == 0) return bj_length_cmd (args);
  if (strcmp (cmd, "keys")     == 0) return bj_keys_cmd (args);
  if (strcmp (cmd, "validate") == 0) return bj_validate_cmd (args, &opts);
  if (strcmp (cmd, "pretty")   == 0) return bj_emit_cmd (args, &opts, 1);
  if (strcmp (cmd, "canonical") == 0) return bj_emit_cmd (args, &opts, 0);
  if (strcmp (cmd, "emit")     == 0) return bj_emit_cmd (args, &opts, 1);
  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *bashjson_doc[] = {
  "JSON parser/serializer via the vendored jsmn tokenizer.",
  "",
  "    bashjson parse   < doc          \"TYPE PATH VALUE\" per leaf",
  "    bashjson get   PATH < doc       value at PATH (JSON-encoded)",
  "    bashjson set   PATH VAL < doc   rewrite at PATH; emit new doc",
  "    bashjson type  PATH < doc       string|number|...|null|none",
  "    bashjson has   PATH < doc       exit 0/1",
  "    bashjson length PATH < doc      array len / obj key count / str bytes",
  "    bashjson keys  PATH < doc       object keys, one per line",
  "    bashjson validate < doc         strict validation (exit 0/1)",
  "    bashjson pretty < doc           JSON::PP-style sorted pretty output",
  "    bashjson canonical < doc        sorted compact JSON output",
  "    bashjson emit [--pretty|--compact] < doc",
  "    bashjson --no-strict-json validate < doc",
  "    bashjson --python-json-lenient validate < doc",
  "",
  "Validation defaults to strict RFC 8259 mode: duplicate object keys and",
  "NaN/Infinity/-Infinity are rejected. --no-strict-json (alias:",
  "--python-json-lenient) accepts only Python json's duplicate-key and",
  "non-finite-number lenience for validate; it is not JSON5.",
  "",
  "Path syntax: dot/bracket subset of jq.",
  "    .foo  .a.b.c  .arr[3]  .arr[3].field",
  "    .                           root identity",
  "    \\.                          escape literal dot in a key",
  "",
  "Use /bash-os/jq.sh for a richer jq-style filter surface.",
  (char *)NULL
};

struct builtin bashjson_struct = {
  "bashjson",
  bashjson_builtin,
  BUILTIN_ENABLED,
  bashjson_doc,
  "bashjson [--strict-json|--no-strict-json|--python-json-lenient] parse|get|set|type|has|length|keys|validate|pretty|canonical|emit [ARGS...] < DOC",
  0
};
