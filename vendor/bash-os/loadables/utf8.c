/* SPDX-License-Identifier: MIT */
/* utf8.c — Unicode case-mapping + cluster-aware string ops as bash
 * builtins (Stage 26 v1).
 *
 * v1 shipped the libgrapheme-direct verbs:
 *   utf8 lower TEXT [-V VAR]      grapheme_to_lowercase_utf8
 *   utf8 upper TEXT [-V VAR]      grapheme_to_uppercase_utf8
 *   utf8 title TEXT [-V VAR]      grapheme_to_titlecase_utf8
 *   utf8 length TEXT [-T MODE]    counts; MODE ∈ grapheme|codepoint|byte
 *   utf8 slice TEXT START END [-T MODE] [-V VAR]
 *                                     substring with cluster/codepoint/byte/
 *                                     display-width bounds
 *
 * Stage 26 full adds generated Unicode 17.0.0 normalization and
 * casefold tables, Hangul algorithmic normalization, canonical combining
 * class reordering, and malformed UTF-8 replacement.
 *
 * Stage 26 v3 (2026-05-07): refactor — extract bu_normalize_buf and
 * bu_casefold_buf helpers; bu_cmp_cmd routes -N FORM and -i through the
 * same helpers as the verbs (fixes -i fold matching when the input has
 * any character beyond a bare "ß"). Latin-1 NFC table extended to
 * 30 pairs (added î/Î, ï/Ï, ò/Ò, ô/Ô, õ/Õ, ù/Ù, û/Û, ý/Ý, ÿ/Ÿ).
 * NFKC fullwidth folding extended into U+FF41..U+FF5D.
 *
 * Stage 26 v4 (2026-05-08): expand the compact table into common
 * Latin Extended-A precomposed letters used by Central/Eastern European
 * text, add simple Extended-A casefold pairs, and add a few high-value
 * compatibility folds (NBSP, superscript digits, Latin presentation
 * ligatures). Still intentionally table-lite, not full UCD.
 *
 * Stage 26 v5 (2026-05-08): extend the same compact coverage across
 * additional Czech/Slovak/Polish/Hungarian letters and stroke/bar
 * casefolds (`Đ/đ`, `Ħ/ħ`, `Ł/ł`, `Ŧ/ŧ`) that do not decompose
 * canonically but do need case-insensitive compare behavior.
 *
 * Stage 26 v6 (2026-05-08): add compact Greek support: monotonic tonos
 * compose/decompose pairs for uppercase/lowercase vowels, and simple
 * casefolds for the basic uppercase Greek alphabet plus accented
 * uppercase vowels. Full locale-sensitive casing is still out of scope.
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
#include <locale.h>
#include <wchar.h>

#include "loadables.h"
#include "_libgrapheme_grapheme.h"
#include "_libgrapheme_utf8_norm_data.h"
#include "_bashutf8_width_data.h"

/* Generic "case-map via libgrapheme" handler. mapper is one of the
   grapheme_to_{lower,upper,title}case_utf8 functions, all sharing the
   signature (src, src_len, dest, dest_len) → bytes-needed. */
typedef size_t (*bu_mapper) (const char *, size_t, char *, size_t);

/* RFC-3629-strict single-codepoint decoder (defined below). Forward-
   declared so bu_length_cmd's codepoint counter can route through it. */
static uint32_t bu_decode_one (const unsigned char *s, size_t n, size_t *used);

static int
bu_emit_or_bind (const char *var, const char *s, size_t n)
{
    if (var) {
        char *buf = malloc (n + 1);
        if (!buf) return EXECUTION_FAILURE;
        memcpy (buf, s, n);
        buf[n] = '\0';
        builtin_bind_variable ((char *) var, buf, 0);
        free (buf);
    } else {
        fwrite (s, 1, n, stdout);
        fputc ('\n', stdout);
    }
    return EXECUTION_SUCCESS;
}

static int
bu_case_cmd (bu_mapper mapper, const char *verb, WORD_LIST *args)
{
    if (!args) {
        builtin_error ("%s: TEXT [-V VAR]", verb);
        return EX_USAGE;
    }
    const char *text = args->word->word;
    size_t in_len = strlen (text);
    const char *var = NULL;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        if (!strcmp (p->word->word, "-V") && p->next) {
            var = p->next->word->word; p = p->next;
        }
    }
    /* Two-call sizing: probe with NULL/0 to get required length.
       libgrapheme's destlen INCLUDES the NUL terminator slot — pass
       need+1 so the writer has room for need bytes of content plus
       the trailing NUL. Passing destlen=need would truncate the
       final byte. */
    size_t need = mapper (text, in_len, NULL, 0);
    char *out = malloc (need + 1);
    if (!out) {
        builtin_error ("%s: malloc failed", verb);
        return EXECUTION_FAILURE;
    }
    size_t got = mapper (text, in_len, out, need + 1);
    int rc = bu_emit_or_bind (var, out, got);
    free (out);
    return rc;
}

static int
bu_decode_width_one (const char *s, size_t n, size_t *used, uint32_t *cp)
{
    const unsigned char *p = (const unsigned char *) s;
    if (n == 0) return -1;
    if (p[0] < 0x80) {
        *used = 1; *cp = p[0]; return 0;
    }
    if ((p[0] & 0xe0) == 0xc0 && n >= 2 && (p[1] & 0xc0) == 0x80) {
        uint32_t v = ((uint32_t)(p[0] & 0x1f) << 6) | (uint32_t)(p[1] & 0x3f);
        if (v >= 0x80) { *used = 2; *cp = v; return 0; }
    } else if ((p[0] & 0xf0) == 0xe0 && n >= 3 &&
               (p[1] & 0xc0) == 0x80 && (p[2] & 0xc0) == 0x80) {
        uint32_t v = ((uint32_t)(p[0] & 0x0f) << 12) |
                     ((uint32_t)(p[1] & 0x3f) << 6) |
                     (uint32_t)(p[2] & 0x3f);
        if (v >= 0x800 && !(v >= 0xd800 && v <= 0xdfff)) {
            *used = 3; *cp = v; return 0;
        }
    } else if ((p[0] & 0xf8) == 0xf0 && n >= 4 &&
               (p[1] & 0xc0) == 0x80 && (p[2] & 0xc0) == 0x80 &&
               (p[3] & 0xc0) == 0x80) {
        uint32_t v = ((uint32_t)(p[0] & 0x07) << 18) |
                     ((uint32_t)(p[1] & 0x3f) << 12) |
                     ((uint32_t)(p[2] & 0x3f) << 6) |
                     (uint32_t)(p[3] & 0x3f);
        if (v >= 0x10000 && v <= 0x10ffff) {
            *used = 4; *cp = v; return 0;
        }
    }
    *used = 1;
    *cp = 0xfffd;
    return 0;
}

static size_t
bu_width_lookup (uint32_t cp, int amb_wide)
{
    size_t lo = 0, hi = BU_WIDTH_RANGE_COUNT;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const bu_width_range *r = &bu_width_ranges[mid];
        if (cp < r->lo)
            hi = mid;
        else if (cp > r->hi)
            lo = mid + 1;
        else
            return r->w == BU_WIDTH_AMBIGUOUS ? (amb_wide ? 2 : 1) : r->w;
    }
    return 1;
}

static int
bu_is_variation_selector (uint32_t cp)
{
    return cp >= 0xfe00 && cp <= 0xfe0f;
}

static int
bu_is_skin_tone_modifier (uint32_t cp)
{
    return cp >= 0x1f3fb && cp <= 0x1f3ff;
}

static int
bu_is_regional_indicator (uint32_t cp)
{
    return cp >= 0x1f1e6 && cp <= 0x1f1ff;
}

static size_t
bu_display_width (const char *text, size_t n, int amb_wide)
{
    size_t width = 0;
    for (size_t i = 0; i < n; ) {
        size_t used = 1;
        uint32_t cp = 0xfffd;
        bu_decode_width_one (text + i, n - i, &used, &cp);
        size_t cpw = bu_width_lookup (cp, amb_wide);
        if (bu_is_regional_indicator (cp) && i + used < n) {
            size_t rused = 1;
            uint32_t rcp = 0;
            bu_decode_width_one (text + i + used, n - i - used, &rused, &rcp);
            if (bu_is_regional_indicator (rcp)) {
                width += 2;
                i += used + rused;
                continue;
            }
        }
        if (cpw == 2) {
            size_t j = i + used;
            int consumed_tail = 0;
            while (j < n) {
                size_t zused = 1, eused = 1;
                uint32_t zcp = 0, ecp = 0;
                bu_decode_width_one (text + j, n - j, &zused, &zcp);
                if (bu_is_variation_selector (zcp) || bu_is_skin_tone_modifier (zcp)) {
                    j += zused;
                    consumed_tail = 1;
                    continue;
                }
                if (zcp != 0x200d || j + zused >= n)
                    break;
                bu_decode_width_one (text + j + zused, n - j - zused, &eused, &ecp);
                if (bu_width_lookup (ecp, amb_wide) != 2)
                    break;
                consumed_tail = 1;
                j += zused + eused;
            }
            width += 2;
            if (consumed_tail) {
                i = j;
                continue;
            }
        } else {
            if (cpw == 1 && i + used < n) {
                size_t vused = 1;
                uint32_t vcp = 0;
                bu_decode_width_one (text + i + used, n - i - used, &vused, &vcp);
                if (bu_is_variation_selector (vcp)) {
                    width += (vcp == 0xfe0f) ? 2 : cpw;
                    i += used + vused;
                    continue;
                }
            }
            width += cpw;
        }
        i += used;
    }
    return width;
}

static size_t
bu_display_width_locale (const char *text, size_t n)
{
    size_t width = 0;
    mbstate_t st;

    (void) setlocale (LC_CTYPE, "");
    memset (&st, 0, sizeof st);

    for (size_t i = 0; i < n; ) {
        wchar_t wc = 0;
        size_t used = mbrtowc (&wc, text + i, n - i, &st);

        if (used == (size_t) -2 || used == (size_t) -1) {
            memset (&st, 0, sizeof st);
            width += 1;
            i++;
            continue;
        }
        if (used == 0)
            used = 1;

        int w = wcwidth (wc);
        width += w < 0 ? 0 : (size_t) w;
        i += used;
    }

    return width;
}

typedef enum {
    BU_WIDTH_TABLE_NARROW = 0,
    BU_WIDTH_TABLE_EAW = 1,
    BU_WIDTH_LOCALE = 2
} bu_width_mode;

static int
bu_parse_width_mode (const char *verb, const char *lmode, bu_width_mode *wm)
{
    if (!strcmp (lmode, "wcwidth")) {
        *wm = BU_WIDTH_TABLE_NARROW;
        return 0;
    }
    if (!strcmp (lmode, "eaw-default")) {
        *wm = BU_WIDTH_TABLE_EAW;
        return 0;
    }
    if (!strcmp (lmode, "locale") || !strcmp (lmode, "libc")) {
        *wm = BU_WIDTH_LOCALE;
        return 0;
    }

    builtin_error ("%s: -L must be wcwidth|eaw-default|locale|libc (got '%s')",
                   verb, lmode);
    return -1;
}

static size_t
bu_display_width_selected (const char *text, size_t n, bu_width_mode wm)
{
    if (wm == BU_WIDTH_LOCALE)
        return bu_display_width_locale (text, n);
    return bu_display_width (text, n, wm == BU_WIDTH_TABLE_EAW);
}

/* length grapheme: walk cluster boundaries.
   length codepoint: walk UTF-8 lead bytes.
   length byte: strlen.
   length width: count display cells using the selected width backend. */
static int
bu_length_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("length: TEXT [-T MODE] [-L wcwidth|eaw-default|locale|libc]"); return EX_USAGE; }
    const char *text = args->word->word;
    size_t n = strlen (text);
    const char *mode = "grapheme";
    bu_width_mode width_mode = BU_WIDTH_TABLE_NARROW;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        if (!strcmp (p->word->word, "-T") && p->next) {
            mode = p->next->word->word; p = p->next;
        } else if (!strcmp (p->word->word, "-L") && p->next) {
            const char *lmode = p->next->word->word; p = p->next;
            if (bu_parse_width_mode ("length", lmode, &width_mode) < 0)
                return EX_USAGE;
        }
    }
    size_t count = 0;
    if (!strcmp (mode, "byte")) {
        count = n;
    } else if (!strcmp (mode, "width")) {
        count = bu_display_width_selected (text, n, width_mode);
    } else if (!strcmp (mode, "codepoint")) {
        /* RFC-3629 decode via bu_decode_one so that each maximal-subpart
           of an ill-formed sequence counts as one U+FFFD replacement
           codepoint — Python bytes.decode("utf-8","replace") parity per
           the INVALID UTF-8 POLICY in docs/bash/utf8.txt. For
           well-formed UTF-8 this equals the old non-continuation-byte
           count, so valid-string counts are unchanged. */
        for (size_t i = 0; i < n; ) {
            size_t used = 0;
            (void) bu_decode_one ((const unsigned char *) text + i, n - i, &used);
            if (used == 0) break;
            count++;
            i += used;
        }
    } else if (!strcmp (mode, "grapheme")) {
        size_t pos = 0;
        while (pos < n) {
            size_t step = grapheme_next_character_break_utf8 (text + pos, n - pos);
            if (step == 0) break;
            count++;
            pos += step;
        }
    } else {
        builtin_error ("length: -T must be grapheme|codepoint|byte|width (got '%s')", mode);
        return EX_USAGE;
    }
    printf ("%zu\n", count);
    return EXECUTION_SUCCESS;
}

/* slice TEXT START END [-T MODE] [-L wcwidth|eaw-default|locale|libc] [-V VAR]
   Bash-style negative indices not supported in v1. */
static int
bu_slice_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next) {
        builtin_error ("slice: TEXT START END [-T MODE] [-L wcwidth|eaw-default|locale|libc] [-V VAR]");
        return EX_USAGE;
    }
    const char *text = args->word->word;
    long start = atol (args->next->word->word);
    long end   = atol (args->next->next->word->word);
    if (start < 0 || end < start) {
        builtin_error ("slice: 0 <= START <= END required");
        return EX_USAGE;
    }
    size_t n = strlen (text);
    const char *mode = "grapheme";
    const char *var = NULL;
    bu_width_mode width_mode = BU_WIDTH_TABLE_NARROW;
    for (WORD_LIST *p = args->next->next->next; p; p = p->next) {
        if (!strcmp (p->word->word, "-T") && p->next) {
            mode = p->next->word->word; p = p->next;
        } else if (!strcmp (p->word->word, "-L") && p->next) {
            const char *lmode = p->next->word->word; p = p->next;
            if (bu_parse_width_mode ("slice", lmode, &width_mode) < 0)
                return EX_USAGE;
        } else if (!strcmp (p->word->word, "-V") && p->next) {
            var = p->next->word->word; p = p->next;
        }
    }

    size_t byte_start = 0, byte_end = 0;
    if (!strcmp (mode, "byte")) {
        byte_start = (size_t) start;
        byte_end   = (size_t) end;
        if (byte_end > n) byte_end = n;
        if (byte_start > n) byte_start = n;
    } else if (!strcmp (mode, "codepoint")) {
        size_t i = 0, count = 0;
        while (i < n) {
            unsigned char b = (unsigned char) text[i];
            if ((b & 0xC0) != 0x80) {
                if (count == (size_t) start) byte_start = i;
                if (count == (size_t) end)   { byte_end = i; break; }
                count++;
            }
            i++;
        }
        if ((size_t) end > count) byte_end = n;
    } else if (!strcmp (mode, "grapheme")) {
        size_t pos = 0, count = 0;
        while (pos < n) {
            if (count == (size_t) start) byte_start = pos;
            if (count == (size_t) end)   { byte_end = pos; break; }
            size_t step = grapheme_next_character_break_utf8 (text + pos, n - pos);
            if (step == 0) break;
            pos += step;
            count++;
        }
        if (byte_end == 0 && (size_t) end > count) byte_end = n;
        if (byte_end == 0 && (size_t) end == count) byte_end = pos;
    } else if (!strcmp (mode, "width")) {
        size_t pos = 0, cell = 0;
        int have_start = 0;
        while (pos < n) {
            size_t step = grapheme_next_character_break_utf8 (text + pos, n - pos);
            if (step == 0) break;
            size_t w = bu_display_width_selected (text + pos, step, width_mode);
            size_t next_cell = cell + w;

            if (!have_start && cell >= (size_t) start) {
                byte_start = pos;
                have_start = 1;
            }
            if (next_cell > (size_t) end) {
                byte_end = have_start ? pos : byte_start;
                break;
            }
            byte_end = pos + step;
            pos += step;
            cell = next_cell;
        }
        if (!have_start) {
            byte_start = n;
            byte_end = n;
        } else if (pos >= n && byte_end == 0 && (size_t) end >= cell) {
            byte_end = n;
        }
    } else {
        builtin_error ("slice: -T must be grapheme|codepoint|byte|width (got '%s')", mode);
        return EX_USAGE;
    }
    if (byte_end < byte_start) byte_end = byte_start;
    return bu_emit_or_bind (var, text + byte_start, byte_end - byte_start);
}

static int
bu_append (char **buf, size_t *len, size_t *cap, const char *s, size_t n)
{
    if (*len + n + 1 > *cap) {
        while (*len + n + 1 > *cap) *cap *= 2;
        char *nb = realloc (*buf, *cap);
        if (!nb) return -1;
        *buf = nb;
    }
    memcpy (*buf + *len, s, n);
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

typedef struct {
    uint32_t *v;
    size_t len;
    size_t cap;
} bu_cpvec;

static int
bu_cp_append (bu_cpvec *vec, uint32_t cp)
{
    if (vec->len + 1 > vec->cap) {
        size_t ncap = vec->cap ? vec->cap * 2 : 32;
        uint32_t *nv = realloc (vec->v, ncap * sizeof nv[0]);
        if (!nv) return -1;
        vec->v = nv;
        vec->cap = ncap;
    }
    vec->v[vec->len++] = cp;
    return 0;
}

static int
bu_cp_extend (bu_cpvec *vec, const uint32_t *seq, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (bu_cp_append (vec, seq[i]) < 0) return -1;
    return 0;
}

static uint32_t
bu_decode_one (const unsigned char *s, size_t n, size_t *used)
{
    if (n == 0) { *used = 0; return 0; }
    unsigned char b0 = s[0];
    if (b0 < 0x80) { *used = 1; return b0; }

    uint32_t cp = 0;
    size_t need = 0;
    if ((b0 & 0xe0) == 0xc0) { cp = b0 & 0x1f; need = 2; }
    else if ((b0 & 0xf0) == 0xe0) { cp = b0 & 0x0f; need = 3; }
    else if ((b0 & 0xf8) == 0xf0) { cp = b0 & 0x07; need = 4; }
    else { *used = 1; return 0xfffdu; }

    if (n < need) { *used = 1; return 0xfffdu; }
    for (size_t i = 1; i < need; i++) {
        if ((s[i] & 0xc0) != 0x80) { *used = 1; return 0xfffdu; }
        cp = (cp << 6) | (uint32_t) (s[i] & 0x3f);
    }
    if ((need == 2 && cp < 0x80) ||
        (need == 3 && cp < 0x800) ||
        (need == 4 && cp < 0x10000) ||
        (cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff) {
        *used = 1;
        return 0xfffdu;
    }
    *used = need;
    return cp;
}

static int
bu_utf8_append_cp (char **buf, size_t *len, size_t *cap, uint32_t cp)
{
    char tmp[4];
    size_t n = 0;
    if (cp <= 0x7f) {
        tmp[n++] = (char) cp;
    } else if (cp <= 0x7ff) {
        tmp[n++] = (char) (0xc0 | (cp >> 6));
        tmp[n++] = (char) (0x80 | (cp & 0x3f));
    } else if (cp <= 0xffff) {
        tmp[n++] = (char) (0xe0 | (cp >> 12));
        tmp[n++] = (char) (0x80 | ((cp >> 6) & 0x3f));
        tmp[n++] = (char) (0x80 | (cp & 0x3f));
    } else {
        tmp[n++] = (char) (0xf0 | (cp >> 18));
        tmp[n++] = (char) (0x80 | ((cp >> 12) & 0x3f));
        tmp[n++] = (char) (0x80 | ((cp >> 6) & 0x3f));
        tmp[n++] = (char) (0x80 | (cp & 0x3f));
    }
    return bu_append (buf, len, cap, tmp, n);
}

static const bu_ucd_decomp *
bu_find_decomp (uint32_t cp)
{
    size_t lo = 0, hi = BU_UCD_DECOMP_COUNT;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        uint32_t m = bu_ucd_decomp_table[mid].cp;
        if (m == cp) return &bu_ucd_decomp_table[mid];
        if (m < cp) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

static const bu_ucd_fold *
bu_find_fold (uint32_t cp)
{
    size_t lo = 0, hi = BU_UCD_FOLD_COUNT;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        uint32_t m = bu_ucd_fold_table[mid].cp;
        if (m == cp) return &bu_ucd_fold_table[mid];
        if (m < cp) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

static uint8_t
bu_ccc (uint32_t cp)
{
    size_t lo = 0, hi = BU_UCD_CCC_COUNT;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        uint32_t m = bu_ucd_ccc_table[mid].cp;
        if (m == cp) return bu_ucd_ccc_table[mid].ccc;
        if (m < cp) lo = mid + 1; else hi = mid;
    }
    return 0;
}

static int
bu_find_comp (uint32_t first, uint32_t second, uint32_t *composed)
{
    size_t lo = 0, hi = BU_UCD_COMP_COUNT;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const bu_ucd_comp *r = &bu_ucd_comp_table[mid];
        if (r->first == first && r->second == second) {
            *composed = r->composed;
            return 1;
        }
        if (r->first < first || (r->first == first && r->second < second)) lo = mid + 1;
        else hi = mid;
    }
    return 0;
}

#define BU_HANGUL_SBASE 0xAC00u
#define BU_HANGUL_LBASE 0x1100u
#define BU_HANGUL_VBASE 0x1161u
#define BU_HANGUL_TBASE 0x11A7u
#define BU_HANGUL_LCOUNT 19u
#define BU_HANGUL_VCOUNT 21u
#define BU_HANGUL_TCOUNT 28u
#define BU_HANGUL_NCOUNT (BU_HANGUL_VCOUNT * BU_HANGUL_TCOUNT)
#define BU_HANGUL_SCOUNT (BU_HANGUL_LCOUNT * BU_HANGUL_NCOUNT)

static int
bu_decompose_cp (uint32_t cp, int compat, bu_cpvec *out, int depth)
{
    if (depth > 32) return bu_cp_append (out, cp);

    if (cp >= BU_HANGUL_SBASE && cp < BU_HANGUL_SBASE + BU_HANGUL_SCOUNT) {
        uint32_t sidx = cp - BU_HANGUL_SBASE;
        uint32_t l = BU_HANGUL_LBASE + sidx / BU_HANGUL_NCOUNT;
        uint32_t v = BU_HANGUL_VBASE + (sidx % BU_HANGUL_NCOUNT) / BU_HANGUL_TCOUNT;
        uint32_t t = BU_HANGUL_TBASE + sidx % BU_HANGUL_TCOUNT;
        if (bu_cp_append (out, l) < 0 || bu_cp_append (out, v) < 0) return -1;
        if (t != BU_HANGUL_TBASE && bu_cp_append (out, t) < 0) return -1;
        return 0;
    }

    const bu_ucd_decomp *d = bu_find_decomp (cp);
    if (d && (compat || !d->compat)) {
        const uint32_t *seq = &bu_ucd_decomp_data[d->off];
        for (size_t i = 0; i < d->len; i++)
            if (bu_decompose_cp (seq[i], compat, out, depth + 1) < 0) return -1;
        return 0;
    }
    return bu_cp_append (out, cp);
}

static void
bu_reorder_canonical (bu_cpvec *vec)
{
    for (size_t i = 1; i < vec->len; i++) {
        uint8_t c = bu_ccc (vec->v[i]);
        if (c == 0) continue;
        size_t j = i;
        while (j > 0) {
            uint8_t pc = bu_ccc (vec->v[j - 1]);
            if (pc == 0 || pc <= c) break;
            uint32_t tmp = vec->v[j - 1];
            vec->v[j - 1] = vec->v[j];
            vec->v[j] = tmp;
            j--;
        }
    }
}

static int
bu_compose_hangul (uint32_t a, uint32_t b, uint32_t *out)
{
    if (a >= BU_HANGUL_LBASE && a < BU_HANGUL_LBASE + BU_HANGUL_LCOUNT &&
        b >= BU_HANGUL_VBASE && b < BU_HANGUL_VBASE + BU_HANGUL_VCOUNT) {
        *out = BU_HANGUL_SBASE + ((a - BU_HANGUL_LBASE) * BU_HANGUL_VCOUNT +
                                  (b - BU_HANGUL_VBASE)) * BU_HANGUL_TCOUNT;
        return 1;
    }
    if (a >= BU_HANGUL_SBASE && a < BU_HANGUL_SBASE + BU_HANGUL_SCOUNT &&
        ((a - BU_HANGUL_SBASE) % BU_HANGUL_TCOUNT) == 0 &&
        b > BU_HANGUL_TBASE && b < BU_HANGUL_TBASE + BU_HANGUL_TCOUNT) {
        *out = a + (b - BU_HANGUL_TBASE);
        return 1;
    }
    return 0;
}

static void
bu_compose_canonical (bu_cpvec *vec)
{
    if (vec->len < 2) return;
    size_t starter = 0;
    uint8_t last_ccc = 0;

    for (size_t i = 1; i < vec->len; i++) {
        uint8_t c = bu_ccc (vec->v[i]);
        uint32_t composed = 0;
        int blocked = (last_ccc != 0 && last_ccc >= c);
        if (!blocked && (bu_compose_hangul (vec->v[starter], vec->v[i], &composed) ||
                         bu_find_comp (vec->v[starter], vec->v[i], &composed))) {
            vec->v[starter] = composed;
            memmove (&vec->v[i], &vec->v[i + 1], (vec->len - i - 1) * sizeof vec->v[0]);
            vec->len--;
            i--;
            continue;
        }
        if (c == 0) {
            starter = i;
            last_ccc = 0;
        } else {
            last_ccc = c;
        }
    }
}

static int
bu_encode_vec (const bu_cpvec *vec, char **out_buf, size_t *out_len)
{
    size_t cap = vec->len * 4 + 1, len = 0;
    char *out = malloc (cap ? cap : 1);
    if (!out) return -1;
    out[0] = '\0';
    for (size_t i = 0; i < vec->len; i++) {
        if (bu_utf8_append_cp (&out, &len, &cap, vec->v[i]) < 0) {
            free (out);
            return -1;
        }
    }
    *out_buf = out;
    *out_len = len;
    return 0;
}

/* Casefold TEXT into a freshly-allocated buffer. Returns 0 + sets
 * *out_buf / *out_len; -1 on alloc failure. Caller frees *out_buf.
 * Stage 26 full: Unicode 17 CaseFolding.txt status C+F table. */
static int
bu_casefold_buf (const char *text, char **out_buf, size_t *out_len)
{
    bu_cpvec folded = {0};
    size_t n = strlen (text);
    for (size_t i = 0; i < n; ) {
        size_t used = 0;
        uint32_t cp = bu_decode_one ((const unsigned char *) text + i, n - i, &used);
        if (used == 0) break;
        const bu_ucd_fold *f = bu_find_fold (cp);
        if (f) {
            if (bu_cp_extend (&folded, &bu_ucd_fold_data[f->off], f->len) < 0) {
                free (folded.v);
                return -1;
            }
        } else if (bu_cp_append (&folded, cp) < 0) {
            free (folded.v);
            return -1;
        }
        i += used;
    }
    int rc = bu_encode_vec (&folded, out_buf, out_len);
    free (folded.v);
    return rc;
}

static int
bu_casefold_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("casefold: TEXT [-V VAR]"); return EX_USAGE; }
    const char *text = args->word->word;
    const char *var = NULL;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        if (!strcmp (p->word->word, "-V") && p->next) {
            var = p->next->word->word; p = p->next;
        }
    }
    char *out = NULL;
    size_t len = 0;
    if (bu_casefold_buf (text, &out, &len) < 0)
        return EXECUTION_FAILURE;
    int rc = bu_emit_or_bind (var, out, len);
    free (out);
    return rc;
}

/* Normalize TEXT under FORM into a freshly-allocated buffer using Unicode 17
 * decomposition data, canonical combining-class reorder, canonical
 * composition, and Hangul algorithmic normalization. Returns 0 on success,
 * -2 on bad form, -1 on allocation failure. */
static int
bu_normalize_buf (const char *form, const char *text, char **out_buf, size_t *out_len)
{
    int compat = (!strcmp (form, "NFKC") || !strcmp (form, "NFKD"));
    int compose = (!strcmp (form, "NFC") || !strcmp (form, "NFKC"));
    int decompose = (!strcmp (form, "NFD") || !strcmp (form, "NFKD"));
    if (!compat && !compose && !decompose) return -2;

    bu_cpvec norm = {0};
    size_t n = strlen (text);
    for (size_t i = 0; i < n; ) {
        size_t used = 0;
        uint32_t cp = bu_decode_one ((const unsigned char *) text + i, n - i, &used);
        if (used == 0) break;
        if (bu_decompose_cp (cp, compat, &norm, 0) < 0) {
            free (norm.v);
            return -1;
        }
        i += used;
    }

    bu_reorder_canonical (&norm);
    if (compose) bu_compose_canonical (&norm);
    int rc = bu_encode_vec (&norm, out_buf, out_len);
    free (norm.v);
    return rc;
}

static int
bu_normalize_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("normalize FORM TEXT [-V VAR]"); return EX_USAGE; }
    const char *form = args->word->word;
    const char *text = args->next->word->word;
    const char *var = NULL;
    for (WORD_LIST *p = args->next->next; p; p = p->next) {
        if (!strcmp (p->word->word, "-V") && p->next) {
            var = p->next->word->word; p = p->next;
        }
    }
    char *out = NULL; size_t len = 0;
    int nrc = bu_normalize_buf (form, text, &out, &len);
    if (nrc < 0) {
        if (nrc == -2) {
            builtin_error ("normalize: FORM must be NFC|NFD|NFKC|NFKD");
            return EX_USAGE;
        }
        return EXECUTION_FAILURE;
    }
    int rc = bu_emit_or_bind (var, out, len);
    free (out);
    return rc;
}

static int
bu_cmp_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("cmp A B [-i] [-N FORM]"); return EX_USAGE; }
    const char *a = args->word->word, *b = args->next->word->word;
    int fold = 0;
    const char *norm = NULL;
    for (WORD_LIST *p = args->next->next; p; p = p->next) {
        if (!strcmp (p->word->word, "-i")) fold = 1;
        else if (!strcmp (p->word->word, "-N") && p->next) { p = p->next; norm = p->word->word; }
    }
    /* Stage 26 v3: pipe both sides through the same normalize/casefold
     * helpers as the dedicated verbs. The previous fold path had
     * hardcoded one-string strcmp matches that only worked when the
     * entire input equaled "ß"; routing through bu_casefold_buf fixes
     * it for full Latin-1 + Greek sigma. */
    char *aa = NULL, *bb = NULL;
    size_t la = 0, lb = 0;

    if (norm) {
        int nra = bu_normalize_buf (norm, a, &aa, &la);
        int nrb = nra < 0 ? 0 : bu_normalize_buf (norm, b, &bb, &lb);
        if (nra < 0 || nrb < 0) {
            if (nra == -2 || nrb == -2) {
                builtin_error ("cmp: -N must be NFC|NFD|NFKC|NFKD");
                free (aa); free (bb);
                return EX_USAGE;
            }
            free (aa); free (bb);
            return EXECUTION_FAILURE;
        }
    } else {
        aa = strdup (a); la = aa ? strlen (aa) : 0;
        bb = strdup (b); lb = bb ? strlen (bb) : 0;
        if (!aa || !bb) { free (aa); free (bb); return EXECUTION_FAILURE; }
    }

    if (fold) {
        char *fa = NULL, *fb = NULL; size_t fla = 0, flb = 0;
        if (bu_casefold_buf (aa, &fa, &fla) < 0 ||
            bu_casefold_buf (bb, &fb, &flb) < 0) {
            free (aa); free (bb); free (fa); free (fb);
            return EXECUTION_FAILURE;
        }
        free (aa); free (bb);
        aa = fa; bb = fb; la = fla; lb = flb;
    }

    /* Length-then-bytewise: handles embedded NUL safely (both helpers
     * NUL-terminate, so strcmp would also work, but len-aware is more
     * robust against future buffer-handling changes). */
    int c = (la != lb) ? (la < lb ? -1 : 1) : memcmp (aa, bb, la);
    free (aa); free (bb);
    return c == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

int
utf8_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "lower"))
        return bu_case_cmd (grapheme_to_lowercase_utf8, "lower", args);
    if (!strcmp (cmd, "upper"))
        return bu_case_cmd (grapheme_to_uppercase_utf8, "upper", args);
    if (!strcmp (cmd, "title"))
        return bu_case_cmd (grapheme_to_titlecase_utf8, "title", args);
    if (!strcmp (cmd, "length"))
        return bu_length_cmd (args);
    if (!strcmp (cmd, "slice"))
        return bu_slice_cmd (args);
    if (!strcmp (cmd, "normalize"))
        return bu_normalize_cmd (args);
    if (!strcmp (cmd, "casefold"))
        return bu_casefold_cmd (args);
    if (!strcmp (cmd, "cmp"))
        return bu_cmp_cmd (args);
    builtin_error ("unknown verb: %s "
                   "(try lower/upper/title/length/slice/normalize/casefold/cmp)", cmd);
    return EX_USAGE;
}

char *utf8_doc[] = {
    "Unicode case-mapping and cluster-aware string ops (libgrapheme-backed).",
    "",
    "    utf8 lower TEXT [-V VAR]    proper Unicode lowercase",
    "    utf8 upper TEXT [-V VAR]    proper Unicode uppercase",
    "    utf8 title TEXT [-V VAR]    titlecase",
    "    utf8 length TEXT [-T MODE] [-L wcwidth|eaw-default|locale|libc]",
    "                                     count grapheme|codepoint|byte|width",
    "    utf8 slice TEXT START END [-T MODE] [-L wcwidth|eaw-default|locale|libc] [-V VAR]",
    "                                     substring with cluster-aware indexing",
    "",
    "    utf8 normalize FORM TEXT [-V VAR]  Unicode 17 NFC/NFD/NFKC/NFKD",
    "    utf8 casefold TEXT [-V VAR]        Unicode 17 full/common casefold",
    "    utf8 cmp A B [-i] [-N FORM]        compare with optional fold/normalize",
    "",
    "normalize/casefold/cmp/width share generated Unicode 17 UCD tables",
    "plus Hangul algorithmic normalization; width -L eaw-default widens",
    "East Asian Ambiguous codepoints; collation remains out of scope.",
    (char *)NULL
};

struct builtin utf8_struct = {
    "utf8",
    utf8_builtin,
    BUILTIN_ENABLED,
    utf8_doc,
    "utf8 lower|upper|title|length|slice|normalize|casefold|cmp ARGS",
    0
};
