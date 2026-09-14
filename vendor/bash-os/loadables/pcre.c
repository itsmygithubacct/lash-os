/* SPDX-License-Identifier: MIT */
/* pcre.c — Perl-compatible regex via libpcre2-8. Loadable for bash.
 *
 * bash's `[[ STR =~ REGEX ]]` is POSIX ERE only — no lookahead, no
 * backrefs in search, no Unicode property classes, no non-greedy
 * quantifiers. PCRE2 is the de-facto standard outside bash; pcre
 * exposes match / substitute / find-all / grep / sed against PCRE2
 * 10.43 (statically linked, no JIT).
 *
 * Subcommands:
 *   pcre match PATTERN STRING [-i] [-m] [-s] [-x] [-U]
 *                    Returns 0/1 by exit code. Populates
 *                    BPCRE_MATCH array: [0]=full match, [1..]=captures.
 *
 *   pcre subst PATTERN REPLACEMENT STRING [-g] [flags]
 *                    Substitute first match (or all with -g). Print
 *                    result to stdout. Replacement uses $1..$N for
 *                    captures (PCRE2 default syntax). With -X all
 *                    three positional args are hex-decoded and the
 *                    result is hex-encoded on stdout (NUL-safe).
 *
 *   pcre find-all PATTERN STRING [flags]
 *                    Print every match, one per line.
 *
 *   pcre grep PATTERN [FILE...] [flags]
 *                    grep -P equivalent. Reads stdin if no files.
 *
 *   pcre sed PATTERN REPLACEMENT [FILE...] [flags]
 *                    sed-like global substitution per line. With -X,
 *                    PATTERN/REPLACEMENT and each input line are hex-
 *                    decoded, and each output line is hex-encoded.
 *
 * Common flags:
 *   -i   case-insensitive (PCRE2_CASELESS)
 *   -m   multiline; ^ and $ match per-line (PCRE2_MULTILINE)
 *   -s   dotall; . matches newline (PCRE2_DOTALL)
 *   -x   extended; whitespace + comments in pattern (PCRE2_EXTENDED)
 *   -U   ungreedy by default (PCRE2_UNGREEDY)
 *   -b   bytes mode (disable PCRE2_UTF; for non-UTF-8 binary data)
 *
 * Default mode is UTF-8 (PCRE2_UTF | PCRE2_UCP). Use -b to disable
 * if you're matching against bytes that aren't valid UTF-8.
 *
 * Pattern cache: 16-entry LRU keyed on (pattern, flags) so back-to-back
 * uses of the same regex don't recompile.
 *
 * Companion docs:
 *     /docs/bash/pcre.txt
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

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "loadables.h"
#include "arrayfunc.h"

/* ---- Pattern cache (LRU) ------------------------------------------- */
#define BP_CACHE_SIZE 16

typedef struct {
  char       *pattern;
  uint32_t    flags;
  pcre2_code *code;
  unsigned    last_used;
} bp_cache_entry;

static bp_cache_entry g_cache[BP_CACHE_SIZE];
static unsigned       g_cache_clock = 0;

/* ---- Match limits (catastrophic-backtracking guard) -----------------
 * PCRE2's default match limit (~10M) lets a pathological pattern/subject
 * (e.g. nested quantifiers on a long non-match) spin for seconds before
 * failing. Bound it so an evil input returns PCRE2_ERROR_MATCHLIMIT /
 * _DEPTHLIMIT deterministically instead of hanging the shell. Override via
 * BASHPCRE_MATCH_LIMIT / BASHPCRE_DEPTH_LIMIT for the rare legitimately-heavy
 * match. One process-lifetime context is shared across every pcre2_match()
 * caller (match contexts are reusable and read-only during a match). */
#define BP_DEFAULT_MATCH_LIMIT 1000000u   /* backtracking steps */
#define BP_DEFAULT_DEPTH_LIMIT 10000u     /* backtracking/recursion depth */

static pcre2_match_context *
bp_match_ctx (void)
{
  /* Cache only the context allocation; re-apply the limits from the
   * environment on every call so BASHPCRE_MATCH_LIMIT / _DEPTH_LIMIT are
   * honored dynamically (the env getenv + two O(1) setters are negligible
   * next to a match). */
  static pcre2_match_context *ctx = NULL;
  if (!ctx)
    {
      ctx = pcre2_match_context_create (NULL);
      if (!ctx)
        return NULL;   /* OOM: callers fall back to NULL (PCRE2 defaults) */
    }
  uint32_t mlim = BP_DEFAULT_MATCH_LIMIT, dlim = BP_DEFAULT_DEPTH_LIMIT;
  const char *e;
  if ((e = getenv ("BASHPCRE_MATCH_LIMIT")) && *e)
    { unsigned long v = strtoul (e, NULL, 10); if (v) mlim = (uint32_t) v; }
  if ((e = getenv ("BASHPCRE_DEPTH_LIMIT")) && *e)
    { unsigned long v = strtoul (e, NULL, 10); if (v) dlim = (uint32_t) v; }
  pcre2_set_match_limit (ctx, mlim);
  pcre2_set_depth_limit (ctx, dlim);
  return ctx;
}

static pcre2_code *
bp_compile (const char *pattern, uint32_t flags)
{
  /* Cache lookup. */
  for (int i = 0; i < BP_CACHE_SIZE; i++)
    if (g_cache[i].pattern && g_cache[i].flags == flags
        && strcmp (g_cache[i].pattern, pattern) == 0)
      {
        g_cache[i].last_used = ++g_cache_clock;
        return g_cache[i].code;
      }

  /* Compile fresh. */
  int errcode;
  PCRE2_SIZE erroffset;
  pcre2_code *code = pcre2_compile (
      (PCRE2_SPTR) pattern, PCRE2_ZERO_TERMINATED, flags,
      &errcode, &erroffset, NULL);
  if (!code)
    {
      char buf[256];
      pcre2_get_error_message (errcode, (PCRE2_UCHAR *) buf, sizeof buf);
      builtin_error ("pcre2 compile at offset %zu: %s", (size_t) erroffset, buf);
      return NULL;
    }

  /* Find LRU slot. */
  int victim = 0;
  unsigned oldest = g_cache_clock + 1;
  for (int i = 0; i < BP_CACHE_SIZE; i++)
    if (g_cache[i].pattern == NULL)
      { victim = i; oldest = 0; break; }
    else if (g_cache[i].last_used < oldest)
      { victim = i; oldest = g_cache[i].last_used; }
  if (g_cache[victim].pattern)
    {
      free (g_cache[victim].pattern);
      pcre2_code_free (g_cache[victim].code);
    }
  g_cache[victim].pattern = strdup (pattern);
  g_cache[victim].flags = flags;
  g_cache[victim].code = code;
  g_cache[victim].last_used = ++g_cache_clock;
  return code;
}

/* ---- Flag parser ---------------------------------------------------- */
/* Returns 0 + sets *out_flags on success; -1 on unknown flag. */
static int
bp_parse_flags (WORD_LIST *p, uint32_t *out_flags)
{
  uint32_t f = PCRE2_UTF | PCRE2_UCP;
  for (; p; p = p->next)
    {
      const char *w = p->word->word;
      if (w[0] != '-' || !w[1] || w[2]) continue;  /* not a flag — caller strips */
      switch (w[1])
        {
        case 'i': f |= PCRE2_CASELESS; break;
        case 'm': f |= PCRE2_MULTILINE; break;
        case 's': f |= PCRE2_DOTALL; break;
        case 'x': f |= PCRE2_EXTENDED; break;
        case 'U': f |= PCRE2_UNGREEDY; break;
        case 'b': f &= ~(PCRE2_UTF | PCRE2_UCP); break;
        case 'g': /* not a compile flag; consumed by callers that care */ break;
        case 'X': /* hex-input mode (pcre-side, not PCRE2); see bp_*_cmd */ break;
        default: return -1;
        }
    }
  *out_flags = f;
  return 0;
}

/* Helper: collect non-flag positional args into argv-like array. */
static int
bp_positional (WORD_LIST *args, const char **out, int max)
{
  int n = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (w[0] == '-' && w[1] && !w[2]) continue;  /* short flag */
      if (n >= max) return -1;
      out[n++] = w;
    }
  return n;
}

static int
bp_has_flag (WORD_LIST *args, char flag)
{
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (w[0] == '-' && w[1] == flag && !w[2]) return 1;
    }
  return 0;
}

/* ---- Hex codec for -X mode (bytes <-> ASCII hex pairs) -------------- */
/* On error: returns NULL, sets *out_err to short message. Caller must
   free the returned buffer. *out_len holds raw byte length. */
static unsigned char *
bp_hex_decode (const char *hex, size_t *out_len, const char **out_err)
{
  size_t hl = strlen (hex);
  if (hl % 2 != 0)
    { *out_err = "hex input must have even length"; return NULL; }
  size_t bl = hl / 2;
  unsigned char *out = malloc (bl + 1);
  if (!out) { *out_err = "malloc"; return NULL; }
  for (size_t i = 0; i < bl; i++)
    {
      int hi = hex[2*i], lo = hex[2*i+1];
      hi = (hi >= '0' && hi <= '9') ? hi - '0'
           : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10
           : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
      lo = (lo >= '0' && lo <= '9') ? lo - '0'
           : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10
           : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
      if (hi < 0 || lo < 0)
        { free (out); *out_err = "hex input has non-hex byte"; return NULL; }
      out[i] = (unsigned char) ((hi << 4) | lo);
    }
  out[bl] = '\0';
  *out_len = bl;
  return out;
}

/* Encode `n` bytes as 2*n lowercase ASCII hex, NUL-terminated. */
static char *
bp_hex_encode (const unsigned char *data, size_t n)
{
  static const char digits[] = "0123456789abcdef";
  char *out = malloc (2 * n + 1);
  if (!out) return NULL;
  for (size_t i = 0; i < n; i++) {
    out[2*i]   = digits[data[i] >> 4];
    out[2*i+1] = digits[data[i] & 0xF];
  }
  out[2*n] = '\0';
  return out;
}

static PCRE2_SIZE
bp_advance_subject_offset (const unsigned char *subject, PCRE2_SIZE len,
                           PCRE2_SIZE off, uint32_t flags)
{
  if (off >= len)
    return off + 1;
  if ((flags & PCRE2_UTF) == 0)
    return off + 1;

  unsigned char c = subject[off];
  PCRE2_SIZE step = 1;
  if (c < 0x80)
    step = 1;
  else if ((c & 0xE0) == 0xC0)
    step = 2;
  else if ((c & 0xF0) == 0xE0)
    step = 3;
  else if ((c & 0xF8) == 0xF0)
    step = 4;

  return off + step <= len ? off + step : off + 1;
}

/* ---- match: populate BPCRE_MATCH array, return 0/1 by exit code --- */
static int
bp_match_cmd (WORD_LIST *args)
{
  uint32_t flags;
  if (bp_parse_flags (args, &flags) < 0)
    { builtin_error ("unknown flag"); builtin_usage (); return EX_USAGE; }
  int hex_mode = bp_has_flag (args, 'X');
  const char *pos[4];
  int n = bp_positional (args, pos, 4);
  if (n != 2) { builtin_error ("match needs PATTERN STRING"); builtin_usage (); return EX_USAGE; }
  unbind_variable ("BPCRE_MATCH");

  /* Resolve subject + pattern into raw bytes. In -X mode both args are
     hex-encoded; decode to support NUL-containing patterns/strings
     (which bash itself can't carry through ARGV otherwise). */
  const unsigned char *pat_bytes = (const unsigned char *) pos[0];
  size_t pat_len = strlen (pos[0]);
  const unsigned char *sub_bytes = (const unsigned char *) pos[1];
  PCRE2_SIZE slen = strlen (pos[1]);
  unsigned char *pat_decoded = NULL, *sub_decoded = NULL;
  if (hex_mode)
    {
      const char *err;
      size_t pl, sl;
      pat_decoded = bp_hex_decode (pos[0], &pl, &err);
      if (!pat_decoded) { builtin_error ("PATTERN: %s", err); builtin_usage (); return EX_USAGE; }
      sub_decoded = bp_hex_decode (pos[1], &sl, &err);
      if (!sub_decoded) { free (pat_decoded); builtin_error ("STRING: %s", err); builtin_usage (); return EX_USAGE; }
      pat_bytes = pat_decoded; pat_len = pl;
      sub_bytes = sub_decoded; slen = (PCRE2_SIZE) sl;
      /* Hex mode requires byte-mode regex: NUL bytes aren't valid UTF-8.
         OR in PCRE2_NEVER_UTF and clear UTF/UCP. */
      flags &= ~(PCRE2_UTF | PCRE2_UCP);
    }

  /* In non-hex mode, use the LRU cache (bp_compile). In hex mode, the
     decoded pattern may contain NUL — bp_compile's strdup-keyed cache
     would truncate it, so do a direct one-off compile instead. */
  pcre2_code *code;
  int hex_owned_code = 0;
  if (hex_mode)
    {
      int errcode;
      PCRE2_SIZE erroffset;
      code = pcre2_compile (pat_bytes, pat_len, flags,
                            &errcode, &erroffset, NULL);
      if (!code)
        {
          char buf[256];
          pcre2_get_error_message (errcode, (PCRE2_UCHAR *) buf, sizeof buf);
          builtin_error ("pcre2 compile at offset %zu: %s", (size_t) erroffset, buf);
          free (pat_decoded); free (sub_decoded);
          return EXECUTION_FAILURE;
        }
      hex_owned_code = 1;
    }
  else
    {
      code = bp_compile (pos[0], flags);
      if (!code) return EXECUTION_FAILURE;
    }
  pcre2_match_data *md = pcre2_match_data_create_from_pattern (code, NULL);
  int rc = pcre2_match (code, sub_bytes, slen, 0, 0, md, bp_match_ctx ());

  if (rc < 0)
    {
      pcre2_match_data_free (md);
      if (hex_owned_code) pcre2_code_free (code);
      free (pat_decoded); free (sub_decoded);
      return EXECUTION_FAILURE;
    }

  PCRE2_SIZE *ovec = pcre2_get_ovector_pointer (md);
  SHELL_VAR *arr = find_or_make_array_variable ("BPCRE_MATCH", 1);
  if (!arr) {
    pcre2_match_data_free (md);
    if (hex_owned_code) pcre2_code_free (code);
    free (pat_decoded); free (sub_decoded);
    return EXECUTION_FAILURE;
  }
  ARRAY *a = array_cell (arr);
  for (int i = 0; i < rc; i++)
    {
      PCRE2_SIZE s = ovec[2 * i];
      PCRE2_SIZE e = ovec[2 * i + 1];
      if (s == PCRE2_UNSET) continue;
      char *piece;
      if (hex_mode) {
        /* Encode the byte slice as hex so callers receive NUL-safe data. */
        piece = bp_hex_encode (sub_bytes + s, (size_t) (e - s));
      } else {
        piece = malloc (e - s + 1);
        memcpy (piece, sub_bytes + s, e - s);
        piece[e - s] = '\0';
      }
      array_insert (a, i, piece);
      free (piece);
    }
  pcre2_match_data_free (md);
  if (hex_owned_code) pcre2_code_free (code);
  free (pat_decoded); free (sub_decoded);
  return EXECUTION_SUCCESS;
}

/* Rewrite sed-style backref syntax into PCRE2's native ${N}/${name}
 * form. PCRE2's replacement parser already understands ${N} (numeric)
 * and ${name} (named) — but not `\N` or `\g<name>`. Pre-rewriting
 * those before pcre2_substitute lets users use the more familiar
 * sed/Perl `\1` and Python/PCRE `\g<name>` forms in the replacement.
 *
 * Transformations (single forward pass, no backtracking):
 *   `\\`           → `\\`            (keep — PCRE2 handles literal '\')
 *   `\g<NAME>`     → `${NAME}`       (Python/PCRE named-ref alias)
 *   `\N` (N=0..9)  → `${N}`          (sed/Perl numeric backref)
 *   anything else  → emitted as-is
 *
 * The expansion is bounded: `\1` (2 chars) → `${1}` (4 chars); a name
 * of K chars becomes K+3. Worst case is 2x growth (for `\\`) + 4 char
 * tail growth per backref, so a 4*input_len buffer is comfortable.
 *
 * Returns a malloc'd buffer that the caller must free; sets *out_len
 * to the byte count (NUL-terminated for convenience but the count
 * doesn't include the NUL). On allocation failure returns NULL. */
static unsigned char *
bp_rewrite_subst_replacement (const unsigned char *in, size_t in_len,
                              size_t *out_len)
{
  size_t cap = in_len * 4 + 16;
  unsigned char *out = malloc (cap);
  if (!out) return NULL;
  size_t o = 0;
  for (size_t i = 0; i < in_len; )
    {
      unsigned char c = in[i];
      if (c != '\\') { out[o++] = c; i++; continue; }
      /* Saw backslash; lookahead. */
      if (i + 1 >= in_len) { out[o++] = c; i++; continue; }
      unsigned char nxt = in[i + 1];
      if (nxt == '\\')
        {
          out[o++] = '\\'; out[o++] = '\\'; i += 2; continue;
        }
      if (nxt >= '0' && nxt <= '9')
        {
          /* `\N` → `${N}` */
          out[o++] = '$'; out[o++] = '{'; out[o++] = nxt; out[o++] = '}';
          i += 2; continue;
        }
      if (nxt == 'g' && i + 2 < in_len && in[i + 2] == '<')
        {
          /* `\g<NAME>` → `${NAME}` */
          size_t j = i + 3;
          while (j < in_len && in[j] != '>') j++;
          if (j < in_len)
            {
              out[o++] = '$'; out[o++] = '{';
              for (size_t k = i + 3; k < j; k++) out[o++] = in[k];
              out[o++] = '}';
              i = j + 1; continue;
            }
        }
      /* Unknown escape: pass through literally. */
      out[o++] = c; i++;
    }
  out[o] = '\0';
  *out_len = o;
  return out;
}

/* ---- subst: PCRE2_SUBSTITUTE_GLOBAL when -g -------------------- */
static int
bp_subst_cmd (WORD_LIST *args)
{
  uint32_t flags;
  if (bp_parse_flags (args, &flags) < 0)
    { builtin_error ("unknown flag"); builtin_usage (); return EX_USAGE; }
  const char *pos[4];
  int n = bp_positional (args, pos, 4);
  if (n != 3) { builtin_error ("subst needs PATTERN REPLACEMENT STRING"); builtin_usage (); return EX_USAGE; }
  int global = bp_has_flag (args, 'g');
  int hex_mode = bp_has_flag (args, 'X');

  /* Resolve PATTERN / REPLACEMENT / STRING into explicit (bytes,len)
     pairs. Non-X path: pos[i] + strlen(pos[i]). -X path: hex-decode
     all three (which lets the operator carry NUL bytes through bash
     ARGV, same way bp_match_cmd does for match -X). */
  const unsigned char *pat_bytes = (const unsigned char *) pos[0];
  size_t pat_len = strlen (pos[0]);
  const unsigned char *rep_bytes = (const unsigned char *) pos[1];
  size_t rep_len = strlen (pos[1]);
  const unsigned char *sub_bytes = (const unsigned char *) pos[2];
  PCRE2_SIZE slen = strlen (pos[2]);
  unsigned char *pat_decoded = NULL, *rep_decoded = NULL, *sub_decoded = NULL;
  if (hex_mode)
    {
      const char *err;
      size_t pl, rl, sl;
      pat_decoded = bp_hex_decode (pos[0], &pl, &err);
      if (!pat_decoded) { builtin_error ("PATTERN: %s", err); builtin_usage (); return EX_USAGE; }
      rep_decoded = bp_hex_decode (pos[1], &rl, &err);
      if (!rep_decoded) { free (pat_decoded); builtin_error ("REPLACEMENT: %s", err); builtin_usage (); return EX_USAGE; }
      sub_decoded = bp_hex_decode (pos[2], &sl, &err);
      if (!sub_decoded) { free (pat_decoded); free (rep_decoded); builtin_error ("STRING: %s", err); builtin_usage (); return EX_USAGE; }
      pat_bytes = pat_decoded; pat_len = pl;
      rep_bytes = rep_decoded; rep_len = rl;
      sub_bytes = sub_decoded; slen = (PCRE2_SIZE) sl;
      /* Hex mode requires byte-mode regex: NUL bytes aren't valid UTF-8. */
      flags &= ~(PCRE2_UTF | PCRE2_UCP);
    }

  /* Non-X: cached compile via bp_compile. -X: direct compile with
     explicit length (cache key is strdup'd pattern, would truncate
     a NUL-bearing pattern). */
  pcre2_code *code;
  int hex_owned_code = 0;
  if (hex_mode)
    {
      int errcode;
      PCRE2_SIZE erroffset;
      code = pcre2_compile (pat_bytes, pat_len, flags,
                            &errcode, &erroffset, NULL);
      if (!code)
        {
          char buf[256];
          pcre2_get_error_message (errcode, (PCRE2_UCHAR *) buf, sizeof buf);
          builtin_error ("pcre2 compile at offset %zu: %s", (size_t) erroffset, buf);
          free (pat_decoded); free (rep_decoded); free (sub_decoded);
          return EXECUTION_FAILURE;
        }
      hex_owned_code = 1;
    }
  else
    {
      code = bp_compile (pos[0], flags);
      if (!code) return EXECUTION_FAILURE;
    }

  PCRE2_SIZE outlen = slen * 2 + 256;
  PCRE2_UCHAR *outbuf = malloc (outlen);
  uint32_t opts = global ? PCRE2_SUBSTITUTE_GLOBAL : 0;
  /* Pre-rewrite `\N` and `\g<name>` into PCRE2's native `${N}` /
     `${name}` form. PCRE2's substitute parser handles `${...}` even
     without PCRE2_SUBSTITUTE_EXTENDED, so the rewrite gives users the
     more familiar sed/Perl/Python backref syntax for free. */
  size_t rep_rewritten_len = 0;
  unsigned char *rep_rewritten =
      bp_rewrite_subst_replacement (rep_bytes, rep_len, &rep_rewritten_len);
  if (!rep_rewritten)
    {
      free (outbuf);
      if (hex_owned_code) pcre2_code_free (code);
      free (pat_decoded); free (rep_decoded); free (sub_decoded);
      builtin_error ("subst: out of memory rewriting replacement");
      return EXECUTION_FAILURE;
    }
  /* pcre2_substitute runs the matcher internally; pass the same bounded
     match context used by match/find-all so catastrophic patterns fail closed. */
  pcre2_match_context *mctx = bp_match_ctx ();
  int rc = pcre2_substitute (code, sub_bytes, slen,
                             0, opts, NULL, mctx,
                             rep_rewritten, rep_rewritten_len,
                             outbuf, &outlen);
  if (rc == PCRE2_ERROR_NOMEMORY)
    {
      outlen *= 2;
      outbuf = realloc (outbuf, outlen);
      rc = pcre2_substitute (code, sub_bytes, slen,
                             0, opts, NULL, mctx,
                             rep_rewritten, rep_rewritten_len,
                             outbuf, &outlen);
    }
  free (rep_rewritten);
  if (rc < 0)
    {
      char buf[256];
      pcre2_get_error_message (rc, (PCRE2_UCHAR *) buf, sizeof buf);
      builtin_error ("subst: %s", buf);
      free (outbuf);
      if (hex_owned_code) pcre2_code_free (code);
      free (pat_decoded); free (rep_decoded); free (sub_decoded);
      return EXECUTION_FAILURE;
    }
  if (hex_mode)
    {
      char *hex = bp_hex_encode (outbuf, (size_t) outlen);
      if (hex) { fputs (hex, stdout); free (hex); }
    }
  else
    {
      fwrite (outbuf, 1, outlen, stdout);
    }
  putchar ('\n');
  free (outbuf);
  if (hex_owned_code) pcre2_code_free (code);
  free (pat_decoded); free (rep_decoded); free (sub_decoded);
  return EXECUTION_SUCCESS;
}

/* ---- find-all: print every match ----------------------------------- */
static int
bp_find_all_cmd (WORD_LIST *args)
{
  uint32_t flags;
  if (bp_parse_flags (args, &flags) < 0)
    { builtin_error ("unknown flag"); builtin_usage (); return EX_USAGE; }
  const char *pos[4];
  int n = bp_positional (args, pos, 4);
  if (n != 2) { builtin_error ("find-all needs PATTERN STRING"); builtin_usage (); return EX_USAGE; }

  pcre2_code *code = bp_compile (pos[0], flags);
  if (!code) return EXECUTION_FAILURE;
  pcre2_match_data *md = pcre2_match_data_create_from_pattern (code, NULL);

  const char *s = pos[1];
  PCRE2_SIZE slen = strlen (s);
  PCRE2_SIZE off = 0;
  uint32_t match_opts = 0;
  int hits = 0;
  while (off <= slen)
    {
      int rc = pcre2_match (code, (PCRE2_SPTR) s, slen, off, match_opts, md, bp_match_ctx ());
      if (rc == PCRE2_ERROR_NOMATCH)
        {
          /* Canonical PCRE2 empty-match idiom (pcre2demo.c): a plain
             NOMATCH ends iteration, but a NOMATCH while we were asking
             for a non-empty/anchored retry just means there's no
             *non-empty* match at this offset — step forward one char and
             keep scanning. Without this two-stage handling, patterns whose
             match is empty yet still consume input via \K (e.g. ".\K",
             "\w\K") are under-counted: the old loop advanced straight past
             ovec[1], skipping the next position. */
          if (match_opts == 0) break;
          off = bp_advance_subject_offset ((const unsigned char *) s, slen,
                                           off, flags);
          match_opts = 0;
          continue;
        }
      if (rc < 0) break;
      PCRE2_SIZE *ovec = pcre2_get_ovector_pointer (md);
      fwrite (s + ovec[0], 1, ovec[1] - ovec[0], stdout);
      putchar ('\n');
      hits++;
      if (ovec[1] == ovec[0])
        {
          /* Empty match: first retry at the same end offset, anchored and
             forbidding another empty match there, so a "consumed input but
             reset to empty" match (\K) is still discovered. Only if that
             retry yields NOMATCH do we advance by one character (handled
             in the NOMATCH arm above). */
          if (ovec[1] >= slen) break;
          off = ovec[1];
          match_opts = PCRE2_NOTEMPTY_ATSTART | PCRE2_ANCHORED;
        }
      else
        {
          off = ovec[1];
          match_opts = 0;
        }
    }
  pcre2_match_data_free (md);
  return hits > 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ---- grep: stream lines, print matching ---------------------------- */
static int
bp_grep_cmd (WORD_LIST *args)
{
  uint32_t flags;
  if (bp_parse_flags (args, &flags) < 0)
    { builtin_error ("unknown flag"); builtin_usage (); return EX_USAGE; }
  /* Positional: PATTERN [FILE...]. Files default to stdin. */
  const char *pat = NULL;
  int nfiles = 0;
  const char *files[16];
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (w[0] == '-' && w[1] && !w[2]) continue;
      if (!pat) pat = w;
      else if (nfiles < 16) files[nfiles++] = w;
    }
  if (!pat) { builtin_error ("grep needs PATTERN"); builtin_usage (); return EX_USAGE; }

  pcre2_code *code = bp_compile (pat, flags);
  if (!code) return EXECUTION_FAILURE;
  pcre2_match_data *md = pcre2_match_data_create_from_pattern (code, NULL);

  int hits_total = 0;
  int show_filename = nfiles > 1;

  for (int fi = 0; fi == 0 || fi < nfiles; fi++)
    {
      FILE *f;
      const char *fname;
      if (nfiles == 0) { f = stdin; fname = "-"; }
      else { fname = files[fi]; f = fopen (fname, "r"); }
      if (!f) { builtin_error ("%s: %s", fname, strerror (errno)); continue; }

      char *line = NULL;
      size_t linecap = 0;
      ssize_t n;
      while ((n = getline (&line, &linecap, f)) > 0)
        {
          /* Strip trailing newline for match (re-add on print). */
          size_t mlen = (size_t) n;
          if (mlen > 0 && line[mlen - 1] == '\n') mlen--;
          int rc = pcre2_match (code, (PCRE2_SPTR) line, mlen, 0, 0, md, bp_match_ctx ());
          if (rc >= 0)
            {
              if (show_filename) printf ("%s:", fname);
              fwrite (line, 1, (size_t) n, stdout);
              if (n > 0 && line[n - 1] != '\n') putchar ('\n');
              hits_total++;
            }
        }
      free (line);
      if (f != stdin) fclose (f);
      if (nfiles == 0) break;
    }
  pcre2_match_data_free (md);
  return hits_total > 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ---- sed: per-line global substitution ----------------------------- */
static int
bp_sed_cmd (WORD_LIST *args)
{
  uint32_t flags;
  if (bp_parse_flags (args, &flags) < 0)
    { builtin_error ("unknown flag"); builtin_usage (); return EX_USAGE; }
  int hex_mode = bp_has_flag (args, 'X');
  const char *pat = NULL, *repl = NULL;
  int nfiles = 0;
  const char *files[16];
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (w[0] == '-' && w[1] && !w[2]) continue;
      if      (!pat)  pat = w;
      else if (!repl) repl = w;
      else if (nfiles < 16) files[nfiles++] = w;
    }
  if (!pat || !repl) { builtin_error ("sed needs PATTERN REPLACEMENT [FILE...]"); builtin_usage (); return EX_USAGE; }

  const unsigned char *pat_bytes = (const unsigned char *) pat;
  size_t pat_len = strlen (pat);
  const unsigned char *repl_bytes = (const unsigned char *) repl;
  size_t repl_len = strlen (repl);
  unsigned char *pat_decoded = NULL, *repl_decoded = NULL;
  if (hex_mode)
    {
      const char *err;
      size_t pl, rl;
      pat_decoded = bp_hex_decode (pat, &pl, &err);
      if (!pat_decoded) { builtin_error ("PATTERN: %s", err); builtin_usage (); return EX_USAGE; }
      repl_decoded = bp_hex_decode (repl, &rl, &err);
      if (!repl_decoded)
        {
          free (pat_decoded);
          builtin_error ("REPLACEMENT: %s", err);
          builtin_usage ();
          return EX_USAGE;
        }
      pat_bytes = pat_decoded; pat_len = pl;
      repl_bytes = repl_decoded; repl_len = rl;
      flags &= ~(PCRE2_UTF | PCRE2_UCP);
    }

  pcre2_code *code;
  int hex_owned_code = 0;
  if (hex_mode)
    {
      int errcode;
      PCRE2_SIZE erroffset;
      code = pcre2_compile (pat_bytes, pat_len, flags,
                            &errcode, &erroffset, NULL);
      if (!code)
        {
          char buf[256];
          pcre2_get_error_message (errcode, (PCRE2_UCHAR *) buf, sizeof buf);
          builtin_error ("pcre2 compile at offset %zu: %s", (size_t) erroffset, buf);
          free (pat_decoded); free (repl_decoded);
          return EXECUTION_FAILURE;
        }
      hex_owned_code = 1;
    }
  else
    {
      code = bp_compile (pat, flags);
      if (!code) return EXECUTION_FAILURE;
    }

  PCRE2_SIZE outsz_init = 4096;
  int status = EXECUTION_SUCCESS;
  size_t repl_rewritten_len = 0;
  unsigned char *repl_rewritten =
      bp_rewrite_subst_replacement (repl_bytes, repl_len, &repl_rewritten_len);
  if (!repl_rewritten)
    {
      if (hex_owned_code) pcre2_code_free (code);
      free (pat_decoded); free (repl_decoded);
      builtin_error ("sed: out of memory rewriting replacement");
      return EXECUTION_FAILURE;
    }

  for (int fi = 0; fi == 0 || fi < nfiles; fi++)
    {
      FILE *f;
      const char *fname;
      if (nfiles == 0) { f = stdin; fname = "-"; }
      else { fname = files[fi]; f = fopen (fname, "r"); }
      if (!f) { builtin_error ("%s: %s", fname, strerror (errno)); continue; }

      char *line = NULL;
      size_t linecap = 0;
      ssize_t n;
      while ((n = getline (&line, &linecap, f)) > 0)
        {
          size_t mlen = (size_t) n;
          int had_newline = 0;
          if (mlen > 0 && line[mlen - 1] == '\n')
            {
              had_newline = 1;
              mlen--;
            }
          const unsigned char *subject = (const unsigned char *) line;
          PCRE2_SIZE subject_len = (PCRE2_SIZE) mlen;
          unsigned char *subject_decoded = NULL;
          if (hex_mode)
            {
              const char *err;
              char *hex_line = malloc (mlen + 1);
              if (!hex_line)
                {
                  builtin_error ("sed: out of memory decoding hex input");
                  status = EXECUTION_FAILURE;
                  break;
                }
              memcpy (hex_line, line, mlen);
              hex_line[mlen] = '\0';
              size_t decoded_len;
              subject_decoded = bp_hex_decode (hex_line, &decoded_len, &err);
              free (hex_line);
              if (!subject_decoded)
                {
                  builtin_error ("STRING: %s", err);
                  builtin_usage ();
                  status = EX_USAGE;
                  break;
                }
              subject = subject_decoded;
              subject_len = (PCRE2_SIZE) decoded_len;
            }
          PCRE2_SIZE outlen = outsz_init;
          PCRE2_UCHAR *outbuf = malloc (outlen);
          if (!outbuf)
            {
              free (subject_decoded);
              builtin_error ("sed: out of memory");
              status = EXECUTION_FAILURE;
              break;
            }
          /* pcre2_substitute runs the matcher internally; pass the same bounded
             match context used by match/find-all. */
          pcre2_match_context *mctx = bp_match_ctx ();
          int rc = pcre2_substitute (code, subject, subject_len,
                                     0, PCRE2_SUBSTITUTE_GLOBAL,
                                     NULL, mctx,
                                     repl_rewritten, repl_rewritten_len,
                                     outbuf, &outlen);
          while (rc == PCRE2_ERROR_NOMEMORY)
            {
              outlen *= 2;
              PCRE2_UCHAR *newbuf = realloc (outbuf, outlen);
              if (!newbuf)
                {
                  free (subject_decoded);
                  free (outbuf);
                  outbuf = NULL;
                  builtin_error ("sed: out of memory");
                  status = EXECUTION_FAILURE;
                  goto sed_line_done;
                }
              outbuf = newbuf;
              rc = pcre2_substitute (code, subject, subject_len,
                                     0, PCRE2_SUBSTITUTE_GLOBAL,
                                     NULL, mctx,
                                     repl_rewritten, repl_rewritten_len,
                                     outbuf, &outlen);
            }
          if (rc < 0 && rc != PCRE2_ERROR_NOMATCH)
            {
              char buf[256];
              pcre2_get_error_message (rc, (PCRE2_UCHAR *) buf, sizeof buf);
              builtin_error ("sed: %s", buf);
              status = EXECUTION_FAILURE;
            }
          else if (rc == PCRE2_ERROR_NOMATCH)
            {
              if (hex_mode)
                {
                  char *hex = bp_hex_encode (subject, (size_t) subject_len);
                  if (hex) { fputs (hex, stdout); free (hex); }
                  if (had_newline) putchar ('\n');
                }
              else
                {
                  fwrite (line, 1, (size_t) n, stdout);  /* pass through unchanged */
                }
            }
          else
            {
              if (hex_mode)
                {
                  char *hex = bp_hex_encode (outbuf, (size_t) outlen);
                  if (hex) { fputs (hex, stdout); free (hex); }
                  if (had_newline) putchar ('\n');
                }
              else
                {
                  fwrite (outbuf, 1, outlen, stdout);
                  if (had_newline) putchar ('\n');
                }
            }
sed_line_done:
          free (subject_decoded);
          free (outbuf);
          if (status != EXECUTION_SUCCESS) break;
        }
      free (line);
      if (f != stdin) fclose (f);
      if (status != EXECUTION_SUCCESS) break;
      if (nfiles == 0) break;
    }
  if (hex_owned_code) pcre2_code_free (code);
  free (repl_rewritten);
  free (pat_decoded); free (repl_decoded);
  return status;
}

/* ---- Bash entry ---------------------------------------------------- */

extern char *pcre_doc[];

int
pcre_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  /* Top-level --help/-h/help: print the doc array (same surface
     `help pcre' uses). Without these, --help fell through to the
     "unknown subcommand" arm — confusing for a verb-grammar tool. */
  if (strcmp (cmd, "--help") == 0 || strcmp (cmd, "-h") == 0
      || strcmp (cmd, "help") == 0) {
    for (char **lp = pcre_doc; *lp; lp++)
      puts (*lp);
    return EXECUTION_SUCCESS;
  }
  if (strcmp (cmd, "match")    == 0) return bp_match_cmd (args);
  if (strcmp (cmd, "subst")    == 0) return bp_subst_cmd (args);
  if (strcmp (cmd, "find-all") == 0) return bp_find_all_cmd (args);
  if (strcmp (cmd, "grep")     == 0) return bp_grep_cmd (args);
  if (strcmp (cmd, "sed")      == 0) return bp_sed_cmd (args);
  builtin_error ("unknown subcommand: %s", cmd);
  builtin_usage ();
  return EX_USAGE;
}

char *pcre_doc[] = {
  "Perl-compatible regex via libpcre2-8 (no JIT).",
  "",
  "    pcre match PATTERN STRING [-i -m -s -x -U -b -X]",
  "                                      → exit 0/1; populates",
  "                                        BPCRE_MATCH[0..N]",
  "                                      → -X: PATTERN/STRING are hex,",
  "                                        captures emitted as hex too",
  "                                        (NUL-safe; bytes via binhex).",
  "    pcre subst PATTERN REPL STRING [-g] [flags]",
  "                                      → result on stdout",
  "                                      → \\$1..\\$9 backrefs in REPL",
  "    pcre find-all PATTERN STRING [flags]",
  "                                      → one match per line",
  "    pcre grep PATTERN [FILE...] [flags]",
  "                                      → grep -P equivalent",
  "    pcre sed PATTERN REPL [FILE...] [flags]",
  "                                      → per-line s/PATTERN/REPL/g",
  "",
  "Flags: -i caseless, -m multiline, -s dotall, -x extended,",
  "       -U ungreedy default, -b bytes (disable UTF-8), -g global subst,",
  "       -X hex-input mode (match + subst + sed — NUL-safe; output hex-encoded).",
  "",
  "Pattern cache: 16-entry LRU. Repeated use of the same regex skips",
  "compilation. Replacement uses PCRE2 default $1..$N syntax.",
  (char *)NULL
};

struct builtin pcre_struct = {
  "pcre",
  pcre_builtin,
  BUILTIN_ENABLED,
  pcre_doc,
  "pcre match|subst|find-all|grep|sed PATTERN [...] [flags]",
  0
};
