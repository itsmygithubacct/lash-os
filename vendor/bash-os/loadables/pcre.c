/* SPDX-License-Identifier: MIT */
/* pcre.c — Perl-compatible regex via libpcre2-8. Loadable for bash.
 *
 * bash's `[[ STR =~ REGEX ]]` is POSIX ERE only — no lookahead, no
 * backrefs in search, no Unicode property classes, no non-greedy
 * quantifiers. PCRE2 is the de-facto standard outside bash; pcre
 * exposes match / substitute / find-all / grep / sed against PCRE2
 * (linked library version, no JIT).
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
 *                    PCRE2 line selection. Reads stdin if no files.
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
 *     /docs/sol-pcre.md
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
#include <stdint.h>
#include <sys/stat.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "loadables.h"
#include "arrayfunc.h"

/* ---- Pattern cache (LRU) ------------------------------------------- */
#define BP_CACHE_SIZE 16

typedef struct {
  char       *pattern;
  size_t      pattern_len;
  pcre2_match_data *data;
  uint32_t    flags;
  pcre2_code *code;
  uint64_t    last_used;
} bp_cache_entry;

static bp_cache_entry g_cache[BP_CACHE_SIZE];
static uint64_t       g_cache_clock = 0;
static pcre2_match_context *g_match_ctx;

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

/* Malformed/overflowing limits use the bounded defaults, never wrap to zero. */
static uint32_t
bp_limit (const char *name, uint32_t fallback)
{
  const char *e = getenv (name);
  if (!e || !*e) return fallback;
  for (const char *p = e; *p; p++) if (*p < '0' || *p > '9') return fallback;
  char *end;
  errno = 0;
  unsigned long v = strtoul (e, &end, 10);
  return errno || *end || !v || v > UINT32_MAX ? fallback : (uint32_t) v;
}

static pcre2_match_context *
bp_match_ctx (void)
{
  if (!g_match_ctx) g_match_ctx = pcre2_match_context_create (NULL);
  if (!g_match_ctx) { builtin_error ("out of memory"); return NULL; }
  pcre2_set_match_limit (g_match_ctx, bp_limit ("BASHPCRE_MATCH_LIMIT", BP_DEFAULT_MATCH_LIMIT));
  pcre2_set_depth_limit (g_match_ctx, bp_limit ("BASHPCRE_DEPTH_LIMIT", BP_DEFAULT_DEPTH_LIMIT));
  pcre2_set_heap_limit (g_match_ctx, 16384); /* KiB; bound retained backtracking frames. */
  return g_match_ctx;
}

void
pcre_builtin_unload (char *name)
{
  (void) name;
  for (int i = 0; i < BP_CACHE_SIZE; i++) {
    free (g_cache[i].pattern);
    pcre2_match_data_free (g_cache[i].data);
    pcre2_code_free (g_cache[i].code);
  }
  memset (g_cache, 0, sizeof g_cache);
  g_cache_clock = 0;
  pcre2_match_context_free (g_match_ctx);
  g_match_ctx = NULL;
}

static void
bp_match_error (int rc)
{
  if (rc < 0 && rc != PCRE2_ERROR_NOMATCH) {
    PCRE2_UCHAR message[256];
    pcre2_get_error_message (rc, message, sizeof message);
    builtin_error ("match: %s", (char *) message);
  }
}

static pcre2_code *
bp_compile_bytes (const unsigned char *pattern, size_t len, uint32_t flags)
{
  for (int i = 0; i < BP_CACHE_SIZE; i++)
    if (g_cache[i].pattern && g_cache[i].flags == flags
        && g_cache[i].pattern_len == len && !memcmp (g_cache[i].pattern, pattern, len)) {
      g_cache[i].last_used = ++g_cache_clock;
      return g_cache[i].code;
    }
  int errcode;
  PCRE2_SIZE erroffset;
  pcre2_code *code = pcre2_compile (pattern, len, flags, &errcode, &erroffset, NULL);
  if (!code) {
    PCRE2_UCHAR buf[256];
    pcre2_get_error_message (errcode, buf, sizeof buf);
    builtin_error ("pcre2 compile at offset %zu: %s", (size_t) erroffset, (char *) buf);
    return NULL;
  }
  char *key = malloc (len + 1);
  pcre2_match_data *data = pcre2_match_data_create_from_pattern (code, NULL);
  if (!key || !data) {
    free (key); pcre2_match_data_free (data); pcre2_code_free (code);
    builtin_error ("out of memory"); return NULL;
  }
  memcpy (key, pattern, len); key[len] = 0;
  int victim = 0;
  for (int i = 0; i < BP_CACHE_SIZE; i++) {
    if (!g_cache[i].pattern) { victim = i; break; }
    if (g_cache[i].last_used < g_cache[victim].last_used) victim = i;
  }
  free (g_cache[victim].pattern);
  pcre2_match_data_free (g_cache[victim].data);
  pcre2_code_free (g_cache[victim].code);
  g_cache[victim] = (bp_cache_entry) { .pattern = key, .pattern_len = len,
    .flags = flags, .code = code, .data = data, .last_used = ++g_cache_clock };
  return code;
}

static pcre2_code *
bp_compile (const char *pattern, uint32_t flags)
{
  return bp_compile_bytes ((const unsigned char *) pattern, strlen (pattern), flags);
}

/* Commands are synchronous; cached match data can be reused until eviction.
   Cache entries own both code and match data. Callers must not free either. */
static pcre2_match_data *
bp_data (pcre2_code *code)
{
  for (int i = 0; i < BP_CACHE_SIZE; i++)
    if (g_cache[i].code == code) return g_cache[i].data;
  return NULL;
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
      if (!strcmp (w, "--")) break;
      if (w[0] == '-' && w[1] && w[2]) return -1;
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
  int n = 0, literal = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!literal && !strcmp (w, "--")) { literal = 1; continue; }
      if (!literal && w[0] == '-' && w[1] && !w[2]) continue;  /* short flag */
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
      if (!strcmp (w, "--")) break;
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
  if (n > (SIZE_MAX - 1) / 2) return NULL;
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
  SHELL_VAR *old = find_variable_noref ("BPCRE_MATCH");
  if (old && (readonly_p (old) || noassign_p (old) || nameref_p (old))) {
    builtin_error ("BPCRE_MATCH must be a writable array (not a nameref)");
    return EXECUTION_FAILURE;
  }
  if (old && unbind_variable ("BPCRE_MATCH") != 0) return EXECUTION_FAILURE;

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
      /* Hex transport selects bytes mode. */
      flags &= ~(PCRE2_UTF | PCRE2_UCP);
    }

  pcre2_code *code = bp_compile_bytes (pat_bytes, pat_len, flags);
  if (!code) { free (pat_decoded); free (sub_decoded); return EXECUTION_FAILURE; }
  pcre2_match_data *md = bp_data (code);
  pcre2_match_context *ctx = bp_match_ctx ();
  if (!ctx) { free (pat_decoded); free (sub_decoded); return EXECUTION_FAILURE; }
  int rc = pcre2_match (code, sub_bytes, slen, 0, 0, md, ctx);

  if (rc < 0)
    {
      bp_match_error (rc);
      free (pat_decoded); free (sub_decoded);
      return EXECUTION_FAILURE;
    }

  PCRE2_SIZE *ovec = pcre2_get_ovector_pointer (md);
  SHELL_VAR *arr = find_or_make_array_variable ("BPCRE_MATCH", 1);
  if (!arr) {
    free (pat_decoded); free (sub_decoded);
    return EXECUTION_FAILURE;
  }
  VUNSETATTR (arr, att_invisible);
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
        if (!piece) { free (pat_decoded); free (sub_decoded); return EXECUTION_FAILURE; }
        memcpy (piece, sub_bytes + s, e - s);
        piece[e - s] = '\0';
      }
      if (!piece) { free (pat_decoded); free (sub_decoded); return EXECUTION_FAILURE; }
      array_insert (a, i, piece);
      free (piece);
    }

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
  if (in_len > (SIZE_MAX - 16) / 4) return NULL;
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
      /* Hex transport selects bytes mode. */
      flags &= ~(PCRE2_UTF | PCRE2_UCP);
    }

  pcre2_code *code = bp_compile_bytes (pat_bytes, pat_len, flags);
  if (!code) { free (pat_decoded); free (rep_decoded); free (sub_decoded); return EXECUTION_FAILURE; }
  PCRE2_SIZE outlen = slen * 2 + 256;
  PCRE2_UCHAR *outbuf = malloc (outlen);
  if (!outbuf) { free (pat_decoded); free (rep_decoded); free (sub_decoded); return EXECUTION_FAILURE; }
  uint32_t opts = PCRE2_SUBSTITUTE_OVERFLOW_LENGTH | (global ? PCRE2_SUBSTITUTE_GLOBAL : 0);
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

      free (pat_decoded); free (rep_decoded); free (sub_decoded);
      builtin_error ("subst: out of memory rewriting replacement");
      return EXECUTION_FAILURE;
    }
  /* pcre2_substitute runs the matcher internally; pass the same bounded
     match context used by match/find-all so catastrophic patterns fail closed. */
  pcre2_match_context *mctx = bp_match_ctx ();
  if (!mctx) { free (outbuf); free (rep_rewritten); free (pat_decoded); free (rep_decoded); free (sub_decoded); return EXECUTION_FAILURE; }
  int rc = pcre2_substitute (code, sub_bytes, slen,
                             0, opts, bp_data (code), mctx,
                             rep_rewritten, rep_rewritten_len,
                             outbuf, &outlen);
  if (rc == PCRE2_ERROR_NOMEMORY)
    {
      PCRE2_UCHAR *next = outlen == PCRE2_UNSET ? NULL : realloc (outbuf, outlen);
      if (!next) {
        free (outbuf); free (rep_rewritten); free (pat_decoded); free (rep_decoded); free (sub_decoded);
        builtin_error ("subst: out of memory"); return EXECUTION_FAILURE;
      }
      outbuf = next;
      rc = pcre2_substitute (code, sub_bytes, slen,
                             0, opts, bp_data (code), mctx,
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

      free (pat_decoded); free (rep_decoded); free (sub_decoded);
      return EXECUTION_FAILURE;
    }
  if (hex_mode)
    {
      char *hex = bp_hex_encode (outbuf, (size_t) outlen);
      if (hex) { fputs (hex, stdout); free (hex); }
      else {
        builtin_error ("out of memory encoding output");
        free (outbuf); free (pat_decoded); free (rep_decoded); free (sub_decoded);
        return EXECUTION_FAILURE;
      }
    }
  else
    {
      fwrite (outbuf, 1, outlen, stdout);
    }
  putchar ('\n');
  free (outbuf);

  free (pat_decoded); free (rep_decoded); free (sub_decoded);
  return EXECUTION_SUCCESS;
}

/* ---- find-all: print every match ----------------------------------- */
static int
bp_find_all_cmd (WORD_LIST *args)
{
  if (bp_has_flag (args, 'X')) { builtin_error ("find-all does not support -X"); return EX_USAGE; }
  uint32_t flags;
  if (bp_parse_flags (args, &flags) < 0)
    { builtin_error ("unknown flag"); builtin_usage (); return EX_USAGE; }
  const char *pos[4];
  int n = bp_positional (args, pos, 4);
  if (n != 2) { builtin_error ("find-all needs PATTERN STRING"); builtin_usage (); return EX_USAGE; }

  pcre2_code *code = bp_compile (pos[0], flags);
  if (!code) return EXECUTION_FAILURE;
  pcre2_match_data *md = bp_data (code);

  const char *s = pos[1];
  PCRE2_SIZE slen = strlen (s);
  PCRE2_SIZE off = 0;
  uint32_t match_opts = 0;
  int hits = 0, error = 0;
  pcre2_match_context *ctx = bp_match_ctx ();
  if (!ctx) return EXECUTION_FAILURE;
  uint32_t newline;
  pcre2_pattern_info (code, PCRE2_INFO_ALLOPTIONS, &flags);
  pcre2_pattern_info (code, PCRE2_INFO_NEWLINE, &newline);
  while (off <= slen)
    {
      int rc = pcre2_match (code, (PCRE2_SPTR) s, slen, off, match_opts, md, ctx);
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
          if (off + 1 < slen && s[off] == '\r' && s[off + 1] == '\n'
              && (newline == PCRE2_NEWLINE_CRLF || newline == PCRE2_NEWLINE_ANY || newline == PCRE2_NEWLINE_ANYCRLF)) off++;
          off = bp_advance_subject_offset ((const unsigned char *) s, slen,
                                           off, flags);
          match_opts = 0;
          continue;
        }
      if (rc < 0) { bp_match_error (rc); error = 1; break; }
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

  return hits > 0 && !error ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ---- grep: stream lines, print matching ---------------------------- */
#define BP_GREP_OUT_SIZE (64 * 1024)

typedef struct {
  char data[BP_GREP_OUT_SIZE];
  size_t used;
  int buffered;
} bp_grep_output;

static void
bp_grep_flush (bp_grep_output *out)
{
  if (out->used) {
    fwrite (out->data, 1, out->used, stdout);
    out->used = 0;
  }
}

/* Bash line-buffers stdout. Batch regular-file output only: terminals
   and live input streams retain immediate line delivery and write errors. */
static void
bp_grep_write (bp_grep_output *out, const char *data, size_t len)
{
  if (!out->buffered) { fwrite (data, 1, len, stdout); return; }
  if (len > sizeof out->data - out->used) bp_grep_flush (out);
  if (len > sizeof out->data) { fwrite (data, 1, len, stdout); return; }
  memcpy (out->data + out->used, data, len);
  out->used += len;
}

/* A plain ASCII pattern has exactly literal substring semantics. Keep
   PCRE2 for flags that change its meaning and for explicitly configured
   match limits, whose error behavior also belongs to the regex engine. */
static size_t
bp_grep_literal_length (const char *pattern, uint32_t flags)
{
  const char *limit = getenv ("BASHPCRE_MATCH_LIMIT");
  const char *depth = getenv ("BASHPCRE_DEPTH_LIMIT");
  if ((flags & (PCRE2_CASELESS | PCRE2_EXTENDED))
      || (limit && *limit) || (depth && *depth)) return 0;
  size_t n = 0;
  for (; pattern[n]; n++) {
    unsigned char c = (unsigned char) pattern[n];
    if (c >= 0x80 || c == '\n' || strchr ("\\.^$*+?[](){}|", c)) return 0;
  }
  return n;
}

static int
bp_grep_ascii (const char *p, size_t n)
{
  size_t i = 0;
  for (; i + sizeof (uint64_t) <= n; i += sizeof (uint64_t)) {
    uint64_t word;
    memcpy (&word, p + i, sizeof word);
    if (word & UINT64_C(0x8080808080808080)) return 0;
  }
  for (; i < n; i++) if ((unsigned char) p[i] >= 0x80) return 0;
  return 1;
}

static const char *
bp_grep_literal_match (const char *line, size_t len, const char *pat, size_t plen)
{
  if (plen > len) return 0;
  const char *p = line, *end = line + len - plen + 1;
  while (p < end) {
    p = memchr (p, (unsigned char) pat[0], (size_t) (end - p));
    if (!p) break;
    if (!memcmp (p, pat, plen)) return p;
    p++;
  }
  return 0;
}

/* Regular-file literal searches can find selected lines directly in a
   block. Non-ASCII UTF windows still use PCRE2 per line, so invalid UTF is
   rejected exactly as before. The retained tail may grow for a long line. */
static int
bp_grep_engine_error (int rc)
{
  if (rc >= 0 || rc == PCRE2_ERROR_NOMATCH
      || (rc <= PCRE2_ERROR_UTF8_ERR1 && rc >= PCRE2_ERROR_UTF8_ERR21)) return 0;
  bp_match_error (rc);
  return 1;
}

static int
bp_grep_literal_file (FILE *f, const char *pat, size_t plen, uint32_t flags,
                      pcre2_code *code, pcre2_match_data *md,
                      pcre2_match_context *ctx, bp_grep_output *out, int *matched)
{
  size_t cap = 64 * 1024, used = 0;
  char *buf = malloc (cap);
  if (!buf) { builtin_error ("out of memory"); return -1; }
  while (!ferror (stdout)) {
    if (used == cap) {
      if (cap > SIZE_MAX / 2) { free (buf); builtin_error ("line too long"); return -1; }
      char *next = realloc (buf, cap * 2);
      if (!next) { free (buf); builtin_error ("out of memory"); return -1; }
      buf = next; cap *= 2;
    }
    size_t n = fread (buf + used, 1, cap - used, f);
    if (!n) break;
    used += n;
    char *last = memrchr (buf, '\n', used);
    if (!last) continue;
    size_t complete = (size_t) (last - buf) + 1, pos = 0;
    if (!(flags & PCRE2_UTF) || bp_grep_ascii (buf, complete)) {
      size_t begin = 0, end = 0;
      while (pos < complete) {
        const char *hit = bp_grep_literal_match (buf + pos, complete - pos, pat, plen);
        if (!hit) break;
        const char *before = memrchr (buf + pos, '\n', (size_t) (hit - buf - pos));
        size_t first = before ? (size_t) (before - buf) + 1 : pos;
        const char *after = memchr (hit, '\n', complete - (size_t) (hit - buf));
        size_t next = (size_t) (after - buf) + 1;
        if (first != end) {
          if (end > begin) bp_grep_write (out, buf + begin, end - begin);
          begin = first;
        }
        end = next;
        pos = next;
        *matched = 1;
      }
      if (end > begin) bp_grep_write (out, buf + begin, end - begin);
    } else {
      while (pos < complete) {
        char *after = memchr (buf + pos, '\n', complete - pos);
        size_t len = (size_t) (after - buf - pos);
        int rc = pcre2_match (code, (PCRE2_SPTR) buf + pos, len, 0, 0, md, ctx);
        if (bp_grep_engine_error (rc)) { free (buf); return -1; }
        if (rc >= 0) {
          bp_grep_write (out, buf + pos, len + 1);
          *matched = 1;
        }
        pos += len + 1;
      }
    }
    used -= complete;
    if (used) memmove (buf, buf + complete, used);
  }
  if (used && !ferror (f) && !ferror (stdout)) {
    int hit = (!(flags & PCRE2_UTF) || bp_grep_ascii (buf, used))
      ? bp_grep_literal_match (buf, used, pat, plen) != NULL
      : pcre2_match (code, (PCRE2_SPTR) buf, used, 0, 0, md, ctx) >= 0;
    if (hit) {
      bp_grep_write (out, buf, used);
      bp_grep_write (out, "\n", 1);
      *matched = 1;
    }
  }
  free (buf);
  return 0;
}

static int
bp_grep_cmd (WORD_LIST *args)
{
  if (bp_has_flag (args, 'X')) { builtin_error ("grep does not support -X"); return EX_USAGE; }
  uint32_t flags;
  if (bp_parse_flags (args, &flags) < 0)
    { builtin_error ("unknown flag"); builtin_usage (); return EX_USAGE; }
  /* Positional: PATTERN [FILE...]. Files default to stdin. */
  const char *pat = NULL;
  int nfiles = 0, literal_args = 0;
  const char *files[16];
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!literal_args && !strcmp (w, "--")) { literal_args = 1; continue; }
      if (!literal_args && w[0] == '-' && w[1] && !w[2]) continue;
      if (!pat) pat = w;
      else if (nfiles < 16) files[nfiles++] = w;
      else { builtin_error ("at most 16 file operands supported"); return EX_USAGE; }
    }
  if (!pat) { builtin_error ("grep needs PATTERN"); builtin_usage (); return EX_USAGE; }

  pcre2_code *code = bp_compile (pat, flags);
  if (!code) return EXECUTION_FAILURE;
  pcre2_match_data *md = bp_data (code);
  if (!md) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
  /* Environment limits cannot change while this synchronous command runs. */
  pcre2_match_context *ctx = bp_match_ctx ();
  if (!ctx) return EXECUTION_FAILURE;
  size_t literal_len = bp_grep_literal_length (pat, flags);
  bp_grep_output out;
  out.used = 0;
  out.buffered = 0;
  int terminal = isatty (STDOUT_FILENO);
  int matched = 0, io_error = 0, read_error = 0;
  int show_filename = nfiles > 1;

  for (int fi = 0; fi == 0 || fi < nfiles; fi++)
    {
      FILE *f;
      const char *fname;
      if (nfiles == 0) {
        /* A fresh stream prevents sticky EOF/read-ahead state in Bash's
           process-lifetime stdin from crossing redirected invocations. */
        int fd = dup (STDIN_FILENO);
        f = fd < 0 ? NULL : fdopen (fd, "r");
        if (!f && fd >= 0) close (fd);
        fname = "-";
      }
      else { fname = files[fi]; f = fopen (fname, "r"); }
      if (!f) { builtin_error ("%s: %s", fname, strerror (errno)); read_error = 1; continue; }

      char *line = NULL;
      size_t linecap = 0;
      ssize_t n;
      struct stat sb;
      int regular = fstat (fileno (f), &sb) == 0 && S_ISREG (sb.st_mode);
      out.buffered = regular && !terminal;
      if (literal_len && !show_filename && out.buffered) {
        if (bp_grep_literal_file (f, pat, literal_len, flags, code, md, ctx,
                                  &out, &matched) < 0) io_error = 1;
      }
      else while ((n = getline (&line, &linecap, f)) > 0)
        {
          /* Strip trailing newline for match (re-add on print). */
          size_t mlen = (size_t) n;
          if (mlen > 0 && line[mlen - 1] == '\n') mlen--;
          int rc;
          if (literal_len && (!(flags & PCRE2_UTF) || bp_grep_ascii (line, mlen)))
            rc = bp_grep_literal_match (line, mlen, pat, literal_len) ? 1 : PCRE2_ERROR_NOMATCH;
          else
            rc = pcre2_match (code, (PCRE2_SPTR) line, mlen, 0, 0, md, ctx);
          if (bp_grep_engine_error (rc)) { read_error = 1; break; }
          if (rc >= 0)
            {
              if (show_filename) {
                bp_grep_write (&out, fname, strlen (fname));
                bp_grep_write (&out, ":", 1);
              }
              bp_grep_write (&out, line, (size_t) n);
              if (n > 0 && line[n - 1] != '\n') bp_grep_write (&out, "\n", 1);
              matched = 1;
              if (ferror (stdout)) { io_error = 1; break; }
            }
        }
      /* A file that cannot be read (a directory, say) fails the command but
         does not stop the search; only output and allocation errors do. */
      if (ferror (f)) { builtin_error ("%s: read error: %s", fname, strerror (errno)); read_error = 1; }
      free (line);
      if (fclose (f) != 0) read_error = 1;
      /* Finish this file before opening another potentially blocking input. */
      bp_grep_flush (&out);
      if (ferror (stdout)) io_error = 1;
      if (io_error || nfiles == 0) break;
    }
  bp_grep_flush (&out);
  if (fflush (stdout) == EOF || ferror (stdout)) {
    builtin_error ("write error: %s", strerror (errno));
    clearerr (stdout);
    io_error = 1;
  }

  return matched && !io_error && !read_error ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
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
  int nfiles = 0, literal_args = 0;
  const char *files[16];
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!literal_args && !strcmp (w, "--")) { literal_args = 1; continue; }
      if (!literal_args && w[0] == '-' && w[1] && !w[2]) continue;
      if      (!pat)  pat = w;
      else if (!repl) repl = w;
      else if (nfiles < 16) files[nfiles++] = w;
      else { builtin_error ("at most 16 file operands supported"); return EX_USAGE; }
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

  pcre2_code *code = bp_compile_bytes (pat_bytes, pat_len, flags);
  if (!code) { free (pat_decoded); free (repl_decoded); return EXECUTION_FAILURE; }
  pcre2_match_context *mctx = bp_match_ctx ();
  if (!mctx) { free (pat_decoded); free (repl_decoded); return EXECUTION_FAILURE; }
  PCRE2_SIZE outsz_init = 4096;
  int status = EXECUTION_SUCCESS;
  size_t repl_rewritten_len = 0;
  unsigned char *repl_rewritten =
      bp_rewrite_subst_replacement (repl_bytes, repl_len, &repl_rewritten_len);
  if (!repl_rewritten)
    {

      free (pat_decoded); free (repl_decoded);
      builtin_error ("sed: out of memory rewriting replacement");
      return EXECUTION_FAILURE;
    }

  for (int fi = 0; fi == 0 || fi < nfiles; fi++)
    {
      FILE *f;
      const char *fname;
      if (nfiles == 0) {
        int fd = dup (STDIN_FILENO);
        f = fd < 0 ? NULL : fdopen (fd, "r");
        if (!f && fd >= 0) close (fd);
        fname = "-";
      }
      else { fname = files[fi]; f = fopen (fname, "r"); }
      if (!f) { builtin_error ("%s: %s", fname, strerror (errno)); status = EXECUTION_FAILURE; continue; }

      char *line = NULL;
      size_t linecap = 0;
      ssize_t n;
      int line_error = 0;
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
              if (memchr (line, 0, mlen)) { builtin_error ("STRING: hex input has NUL byte"); status = EX_USAGE; line_error = 1; break; }
              char *hex_line = malloc (mlen + 1);
              if (!hex_line)
                {
                  builtin_error ("sed: out of memory decoding hex input");
                  status = EXECUTION_FAILURE; line_error = 1;
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
                  status = EX_USAGE; line_error = 1;
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
              status = EXECUTION_FAILURE; line_error = 1;
              break;
            }
          /* pcre2_substitute runs the matcher internally; pass the same bounded
             match context used by match/find-all. */
          int rc = pcre2_substitute (code, subject, subject_len,
                                     0, PCRE2_SUBSTITUTE_GLOBAL | PCRE2_SUBSTITUTE_OVERFLOW_LENGTH,
                                     bp_data (code), mctx,
                                     repl_rewritten, repl_rewritten_len,
                                     outbuf, &outlen);
          if (rc == PCRE2_ERROR_NOMEMORY)
            {
              PCRE2_UCHAR *newbuf = outlen == PCRE2_UNSET ? NULL : realloc (outbuf, outlen);
              if (!newbuf)
                {
                  free (outbuf);
                  outbuf = NULL;
                  builtin_error ("sed: out of memory");
                  status = EXECUTION_FAILURE; line_error = 1;
                  goto sed_line_done;
                }
              outbuf = newbuf;
              rc = pcre2_substitute (code, subject, subject_len,
                                     0, PCRE2_SUBSTITUTE_GLOBAL | PCRE2_SUBSTITUTE_OVERFLOW_LENGTH,
                                     bp_data (code), mctx,
                                     repl_rewritten, repl_rewritten_len,
                                     outbuf, &outlen);
            }
          if (rc < 0 && rc != PCRE2_ERROR_NOMATCH)
            {
              char buf[256];
              pcre2_get_error_message (rc, (PCRE2_UCHAR *) buf, sizeof buf);
              builtin_error ("sed: %s", buf);
              status = EXECUTION_FAILURE; line_error = 1;
            }
          else if (rc == PCRE2_ERROR_NOMATCH)
            {
              if (hex_mode)
                {
                  char *hex = bp_hex_encode (subject, (size_t) subject_len);
                  if (hex) { fputs (hex, stdout); free (hex); }
                  else { builtin_error ("out of memory encoding output"); status = EXECUTION_FAILURE; line_error = 1; }
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
                  else { builtin_error ("out of memory encoding output"); status = EXECUTION_FAILURE; line_error = 1; }
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
          if (ferror (stdout)) { status = EXECUTION_FAILURE; line_error = 1; }
          if (line_error) break;
        }
      free (line);
      if (ferror (f)) { builtin_error ("%s: read error: %s", fname, strerror (errno)); status = EXECUTION_FAILURE; }
      if (fclose (f) != 0) status = EXECUTION_FAILURE;
      if (line_error || ferror (stdout)) break;
      if (nfiles == 0) break;
    }

  free (repl_rewritten);
  free (pat_decoded); free (repl_decoded);
  return status;
}

/* ---- Bash entry ---------------------------------------------------- */

extern char *pcre_doc[];

static int
bp_dispatch (WORD_LIST *list)
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

int
pcre_builtin (WORD_LIST *list)
{
  int status = bp_dispatch (list);
  if (fflush (stdout) == EOF || ferror (stdout)) {
    builtin_error ("write error: %s", strerror (errno));
    clearerr (stdout);
    return EXECUTION_FAILURE;
  }
  return status;
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
  "                                      → PCRE2 line selection",
  "    pcre sed PATTERN REPL [FILE...] [flags]",
  "                                      → per-line s/PATTERN/REPL/g",
  "",
  "Flags: -i caseless, -m multiline, -s dotall, -x extended,",
  "       -U ungreedy default, -b bytes (disable UTF-8), -g global subst,",
  "       -X hex-input mode (match + subst + sed — NUL-safe; output hex-encoded).",
  "",
  "Pattern cache: 16-entry binary-safe LRU with reusable match data.",
  "Repeated patterns skip compilation. Replacement uses $1..$N syntax.",
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
