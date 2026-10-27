/* SPDX-License-Identifier: MIT */
/* tac.c — GNU-style tac(1): concatenate and print files in reverse.
 *
 *   tac [OPTION]... [FILE]...
 *
 * Write each FILE to standard output, last record first. Records default to
 * lines (separator '\n'). With no FILE, or when FILE is '-', read stdin.
 *
 * Options (short options cluster; long options may be abbreviated):
 *   -b, --before          attach the separator BEFORE each record, not after
 *   -r, --regex           treat the separator string as a GNU Emacs regex
 *   -s, --separator=SEP   use SEP as the record separator (default newline)
 *   -h, --help / -V, --version
 *
 * Seekable inputs are scanned backward; pipes use an owned temporary spool.
 * Literal and regex separators follow GNU tac's read windows. Regexes use a
 * bounded streaming matcher; on glibc, constructs it cannot match exactly
 * use re_search over GNU's window-plus-pending-record buffer. A nullable
 * '+' of \` ^ \< \> beside an empty alternative is spelled XX* before that
 * call, because glibc does not return on the original. Other anchor pluses
 * stay as written: GNU finishes them, and the spelled span can differ. A
 * nullable '+' that mixes a hang anchor with \' \b or \B is refused. A
 * back-reference keeps the original pattern.
 * Output is batched without changing Bash's stdio state.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include <stdint.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <locale.h>
#include <langinfo.h>

#include "loadables.h"
#include "bl-output.h"

/* Input and record sizes never determine the literal scanner's allocation.
   Keep record offsets and reread their bytes in forward order when emitting. */
#define TAC_BLOCK 65536

typedef struct {
    int fd;
    off_t end, base;
    size_t used, capacity;
    char *data;
} tac_input;

static int
tac_read_at (int fd, char *data, size_t length, off_t offset)
{
    while (length) {
        ssize_t n = pread (fd, data, length, offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (!n) errno = EIO; return -1; }
        data += n; length -= n; offset += n;
    }
    return 0;
}

/* The scan cache usually contains the entire record. A separate fixed buffer
   handles huge records without disturbing the backward search cache. */
static int
tac_output_range (tac_input *in, off_t start, off_t end, bl_output *out)
{
    char buffer[TAC_BLOCK];
    while (start < end && !out->error) {
        if (start >= in->base && start < in->base + (off_t) in->used) {
            off_t stop = in->base + (off_t) in->used;
            if (stop > end) stop = end;
            bl_output_write (out, in->data + (size_t) (start - in->base),
                             (size_t) (stop - start));
            start = stop;
        } else {
            size_t n = end - start > TAC_BLOCK ? TAC_BLOCK : (size_t) (end - start);
            if (tac_read_at (in->fd, buffer, n, start) < 0) return -1;
            bl_output_write (out, buffer, n);
            start += n;
        }
    }
    return out->error ? -1 : 0;
}

/* Rightmost separator start in [lo, hi) whose body lies in [lo, past).
   A body may extend past hi by slen-1 bytes; those bytes are still file
   bytes GNU kept from the previous window. Returns 1 and stores the
   offset, 0 if none, or -1 on a read error. */
static int
tac_find_literal (tac_input *in, const char *needle, size_t slen,
                  off_t lo, off_t hi, off_t past, off_t *found)
{
    if (hi > past) hi = past;
    while (hi > lo) {
        off_t span = hi - lo;
        off_t chunk = span > TAC_BLOCK ? (off_t) TAC_BLOCK : span;
        off_t start = hi - chunk;
        off_t read_end = hi - 1 + (off_t) slen;
        if (read_end > past) read_end = past;
        if (read_end <= start) { hi = start; continue; }
        size_t n = (size_t) (read_end - start);
        /* Successive records search leftwards through the same block, so
           reread only when the span leaves it, and then a whole block. */
        if (start < in->base || read_end > in->base + (off_t) in->used) {
            off_t base = read_end > (off_t) in->capacity
                ? read_end - (off_t) in->capacity : 0;
            if (tac_read_at (in->fd, in->data, (size_t) (read_end - base), base) < 0)
                return -1;
            in->base = base;
            in->used = (size_t) (read_end - base);
        }
        char *data = in->data + (size_t) (start - in->base);
        size_t limit = (size_t) (hi - start);
        if (limit > n) limit = n;
        while (limit) {
            char *match = memrchr (data, (unsigned char) needle[0], limit);
            if (!match) break;
            size_t pos = (size_t) (match - data);
            if (slen <= n && pos <= n - slen
                && (slen == 1 || !memcmp (match, needle, slen))) {
                *found = start + (off_t) pos;
                return 1;
            }
            limit = pos;
        }
        hi = start;
    }
    return 0;
}

/* GNU tac 9.7 aligns an 8192-byte window on the file (larger when the
   separator or the pending record requires it). Within a window the
   rightmost matches do not overlap. A match that begins on the window
   base is kept across the next read, so a self-overlapping separator
   one byte to its left is emitted too. *read_size survives across files
   in one invocation, as GNU's does. The search buffer stays one block
   plus the separator; record bytes are reread when printed. */
static int
tac_literal (tac_input *in, const char *sep, int before, size_t *read_size,
             bl_output *out)
{
    size_t slen = strlen (sep);
    if (!slen) slen = 1;       /* An empty argument selects NUL. */
    if (!*read_size || slen > SIZE_MAX - TAC_BLOCK) { errno = EOVERFLOW; return -1; }
    while (slen >= *read_size / 2) {
        if (*read_size > SIZE_MAX / 2) { errno = EOVERFLOW; return -1; }
        *read_size *= 2;
    }
    in->capacity = TAC_BLOCK + slen;
    in->data = malloc (in->capacity);
    if (!in->data) return -1;
    if (!in->end) return 0;

    size_t rs = *read_size;
    uintmax_t rem = (uintmax_t) in->end % rs;
    off_t win_base = rem ? in->end - (off_t) rem : in->end - (off_t) rs;
    off_t win_len = in->end - win_base;
    off_t past = in->end;
    off_t match_cursor = (slen - 1 > (size_t) in->end)
        ? (off_t) -1 : in->end - (off_t) (slen - 1);
    int first = 1;

    while (!out->error) {
        off_t found = 0;
        int got = 0;
        if (match_cursor > win_base) {
            off_t hi = match_cursor;
            off_t win_end = win_base + win_len;
            if (hi > win_end) hi = win_end;
            got = tac_find_literal (in, sep, slen, win_base, hi, past, &found);
            if (got < 0) return -1;
        }
        if (!got) {
            if (win_base == 0)
                return tac_output_range (in, 0, past, out);
            if ((uintmax_t) (past - win_base) > *read_size) {
                if (*read_size > SIZE_MAX / 2) { errno = EOVERFLOW; return -1; }
                *read_size *= 2;
            }
            off_t old_base = win_base;
            if ((uintmax_t) win_base >= *read_size) {
                win_base -= (off_t) *read_size;
                win_len = (off_t) *read_size;
            } else {
                *read_size = (size_t) win_base;
                win_len = win_base;
                win_base = 0;
            }
            match_cursor = old_base;
            continue;
        }
        if (!before) {
            off_t match_end = found + (off_t) slen;
            if (!(first && match_end == past)
                && tac_output_range (in, match_end, past, out) < 0)
                return -1;
            past = match_end;
            first = 0;
        } else if (tac_output_range (in, found, past, out) < 0) {
            return -1;
        } else {
            past = found;
        }
        match_cursor = (slen > (size_t) found + 1)
            ? (off_t) -1 : found - (off_t) (slen - 1);
    }
    return out->error ? -1 : 0;
}

/* A single byte atom, optionally repeated, can always match at the rightmost
   matching byte (or at the rightmost byte at all for a nullable atom). This
   scanner is also available on libcs without the GNU regex API. Complex
   patterns must go through the general matcher, never a dialect guess. */
typedef struct { unsigned char member[256]; int nullable; } tac_atom;

static int
tac_byte_atom (const char *pattern, tac_atom *atom)
{
    if (MB_CUR_MAX != 1) return 0;
    size_t end = strlen (pattern);
    atom->nullable = 0;
    if (end && strchr ("*+?", pattern[end - 1])) {
        atom->nullable = pattern[end - 1] != '+';
        end--;
    }
    memset (atom->member, 0, sizeof atom->member);
    if (end == 1 && !strchr (".[]^$\\*+?", pattern[0])) {
        atom->member[(unsigned char) pattern[0]] = 1;
        return 1;
    }
    if (end == 1 && pattern[0] == '.') {
        memset (atom->member, 1, sizeof atom->member);
        atom->member['\n'] = 0;
        return 1;
    }
    if (end >= 3 && pattern[0] == '[' && pattern[end - 1] == ']') {
        size_t first = pattern[1] == '^' ? 2 : 1;
        if (first + 1 >= end) return 0;
        for (size_t i = first; i + 1 < end; i++) {
            unsigned char c = (unsigned char) pattern[i];
            if (c == '[' || c == ']' || c == '\\' || c == '-') return 0;
            atom->member[c] = 1;
        }
        if (first == 2)
            for (size_t i = 0; i < sizeof atom->member; i++) atom->member[i] ^= 1;
        return 1;
    }
    return 0;
}

static int
tac_regex_atom (tac_input *in, const tac_atom *atom, int before, bl_output *out)
{
    in->data = malloc (TAC_BLOCK);
    if (!in->data) return -1;
    off_t search_end = in->end, record_end = in->end;
    while (search_end > 0 && !out->error) {
        in->base = search_end > TAC_BLOCK ? search_end - TAC_BLOCK : 0;
        in->used = (size_t) (search_end - in->base);
        if (tac_read_at (in->fd, in->data, in->used, in->base) < 0) return -1;
        for (size_t i = in->used; i > 0 && !out->error; ) {
            --i;
            int match = atom->member[(unsigned char) in->data[i]];
            if (!match && !atom->nullable) continue;
            off_t boundary = in->base + i + (before ? 0 : match);
            if (tac_output_range (in, boundary, record_end, out) < 0) return -1;
            record_end = boundary;
        }
        search_end = in->base;
    }
    return tac_output_range (in, 0, record_end, out);
}

/* GNU tac compiles a -r separator with re_syntax_options == 0, i.e.
   RE_SYNTAX_EMACS, and asks re_search for the rightmost match start in the
   current window, then the longest match from that start. The parser below
   follows glibc's tokenizer and grammar for that syntax: context-dependent
   '^', '$' and repetition characters, \( \) \| groups, \w \W \s \S, word and
   buffer anchors, and brackets without character classes or intervals.
   It only accepts what it can match exactly. Back-references, collating and
   equivalence elements, non-C collation ranges and the remaining multibyte
   constructs are reported as unsupported; on glibc those use re_search.
   A nullable '+' of \` ^ \< or \> beside an empty alternative is spelled
   XX* first: the original does not return. Other anchor pluses stay on
   the original, which GNU finishes. A nullable '+' that mixes a hang
   anchor with \' \b or \B is refused. */

#define TAC_RE_TREE_MAX 4096
#define TAC_RE_NEST_MAX 200
#define TAC_DFA_BUDGET (1 << 20)

/* glibc's anchor constraint and context bits. */
enum {
    TC_NEXT_WORD = 0x4, TC_NEXT_NOTWORD = 0x8, TC_PREV_WORD = 0x10,
    TC_PREV_NOTWORD = 0x20, TC_NEXT_NEWLINE = 0x40, TC_PREV_NEWLINE = 0x80,
    TC_NEXT_ENDBUF = 0x100, TC_PREV_BEGBUF = 0x200,
    TC_WORD_DELIM = 0x400, TC_NOT_WORD_DELIM = 0x800
};
/* How a '+' that contains one of those anchors has to be searched.
   TM_DIFF: GNU finishes the original and XX* can disagree (\' \b \B).
   TM_HANG: a nullable '+' does not return (\` ^ \< \>). '$' is neither. */
enum { TM_DIFF = 1, TM_HANG = 2 };

static unsigned
tac_anchor_class (unsigned short anchor)
{
    if (anchor == TC_NEXT_ENDBUF || anchor == TC_WORD_DELIM
        || anchor == TC_NOT_WORD_DELIM)
        return TM_DIFF;
    if (anchor == TC_PREV_BEGBUF || anchor == TC_PREV_NEWLINE
        || anchor == (TC_PREV_NOTWORD | TC_NEXT_WORD)
        || anchor == (TC_PREV_WORD | TC_NEXT_NOTWORD))
        return TM_HANG;
    return 0;
}
enum { TX_WORD = 1, TX_NEWLINE = 2, TX_BEGBUF = 4, TX_ENDBUF = 8 };
/* Byte classes; TB_BUF stands for the start or end of the search buffer. */
enum { TB_OTHER, TB_WORD, TB_NEWLINE, TB_BUF };

enum { TT_SET, TT_ASSERT, TT_CAT, TT_ALT, TT_STAR, TT_PLUS, TT_OPT };
typedef struct {
    unsigned char type;
    unsigned short constraint;
    int a, b;
    unsigned char mark;         /* TM_DIFF / TM_HANG, else zero. */
} tac_tree;

enum {
    TE_OK, TE_BADPAT, TE_EESCAPE, TE_ESUBREG, TE_EBRACK, TE_EPAREN,
    TE_ERANGE, TE_ESPACE, TE_ERPAREN, TE_UNSUPPORTED
};
#ifndef __GLIBC__
static const char *const tac_re_errors[] = {
    "Success", "Invalid regular expression", "Trailing backslash",
    "Invalid back reference", "Unmatched [, [^, [:, [., or [=",
    "Unmatched ( or \\(", "Invalid range end", "Memory exhausted",
    "Unmatched ) or \\)", "unsupported"
};
#endif

enum {
    TK_END, TK_CHAR, TK_BACKSLASH, TK_ALT, TK_BACKREF, TK_ANCHOR, TK_WORD,
    TK_NOTWORD, TK_SPACE, TK_NOTSPACE, TK_OPEN, TK_CLOSE, TK_STAR, TK_PLUS,
    TK_QUESTION, TK_BRACKET, TK_PERIOD
};
typedef struct { int type; size_t len, at, chars; unsigned char c; unsigned short anchor; } tac_token;

typedef struct {
    const unsigned char *s;
    size_t len, pos;
    tac_tree *tree;
    uint64_t (*set)[4];
    int ntree, cap, nsub, depth, err, utf8, c_collate;
    unsigned completed;
    unsigned char word[256], space[256];
} tac_parser;

static size_t
tac_utf8_length (const unsigned char *s, size_t n)
{
    /* Strict UTF-8: anything glibc might decode differently is refused. */
    unsigned char c = s[0];
    size_t len = c < 0x80 ? 1 : c >= 0xc2 && c <= 0xdf ? 2
               : c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
    if (!len || len > n) return 0;
    for (size_t i = 1; i < len; i++)
        if ((s[i] & 0xc0) != 0x80) return 0;
    if ((c == 0xe0 && s[1] < 0xa0) || (c == 0xed && s[1] > 0x9f)
        || (c == 0xf0 && s[1] < 0x90) || (c == 0xf4 && s[1] > 0x8f))
        return 0;
    return len;
}

static int
tac_tree_new (tac_parser *ps, int type, int a, int b)
{
    if (ps->err) return -1;
    if (ps->ntree == TAC_RE_TREE_MAX) { ps->err = TE_UNSUPPORTED; return -1; }
    if (ps->ntree == ps->cap) {
        int cap = ps->cap ? ps->cap * 2 : 64;
        tac_tree *tree = realloc (ps->tree, (size_t) cap * sizeof *tree);
        if (tree) ps->tree = tree;
        uint64_t (*set)[4] = realloc (ps->set, (size_t) cap * sizeof *set);
        if (set) ps->set = set;
        if (!tree || !set) { ps->err = TE_ESPACE; return -1; }
        ps->cap = cap;
    }
    int n = ps->ntree++;
    ps->tree[n] = (tac_tree) { (unsigned char) type, 0, a, b, 0 };
    memset (ps->set[n], 0, sizeof ps->set[n]);
    return n;
}

static int
tac_tree_byte (tac_parser *ps, unsigned char c)
{
    int n = tac_tree_new (ps, TT_SET, -1, -1);
    if (n >= 0) ps->set[n][c >> 6] |= (uint64_t) 1 << (c & 63);
    return n;
}

static int
tac_tree_class (tac_parser *ps, const unsigned char *member, int invert)
{
    int n = tac_tree_new (ps, TT_SET, -1, -1);
    if (n >= 0)
        for (int c = 0; c < 256; c++)
            if (!member[c] != !invert)
                ps->set[n][c >> 6] |= (uint64_t) 1 << (c & 63);
    return n;
}

/* glibc peek_token for syntax 0, with RE_CARET_ANCHORS_HERE as 'caret'. */
static void
tac_peek (tac_parser *ps, tac_token *t, int caret)
{
    size_t i = ps->pos;
    t->anchor = 0; t->len = 1; t->at = i; t->chars = 1;
    if (i >= ps->len) { t->type = TK_END; t->len = 0; return; }
    unsigned char c = ps->s[i];
    t->c = c;
    t->type = TK_CHAR;
    if (c == '\\') {
        if (i + 1 >= ps->len) { t->type = TK_BACKSLASH; return; }
        unsigned char c2 = ps->s[i + 1];
        t->c = c2; t->len = 2; t->at = i + 1;
        switch (c2) {
        case '|': t->type = TK_ALT; break;
        case '1': case '2': case '3': case '4': case '5':
        case '6': case '7': case '8': case '9': t->type = TK_BACKREF; break;
        case '<': t->type = TK_ANCHOR; t->anchor = TC_PREV_NOTWORD | TC_NEXT_WORD; break;
        case '>': t->type = TK_ANCHOR; t->anchor = TC_PREV_WORD | TC_NEXT_NOTWORD; break;
        case 'b': t->type = TK_ANCHOR; t->anchor = TC_WORD_DELIM; break;
        case 'B': t->type = TK_ANCHOR; t->anchor = TC_NOT_WORD_DELIM; break;
        case '`': t->type = TK_ANCHOR; t->anchor = TC_PREV_BEGBUF; break;
        case '\'': t->type = TK_ANCHOR; t->anchor = TC_NEXT_ENDBUF; break;
        case 'w': t->type = TK_WORD; break;
        case 'W': t->type = TK_NOTWORD; break;
        case 's': t->type = TK_SPACE; break;
        case 'S': t->type = TK_NOTSPACE; break;
        case '(': t->type = TK_OPEN; break;
        case ')': t->type = TK_CLOSE; break;
        default:
            if (c2 >= 0x80 && ps->utf8) {
                t->chars = tac_utf8_length (ps->s + i + 1, ps->len - i - 1);
                t->len = 1 + t->chars;
            }
        }
        return;
    }
    switch (c) {
    case '*': t->type = TK_STAR; break;
    case '+': t->type = TK_PLUS; break;
    case '?': t->type = TK_QUESTION; break;
    case '[': t->type = TK_BRACKET; break;
    case '.': t->type = TK_PERIOD; break;
    case '^':
        if (caret || i == 0) { t->type = TK_ANCHOR; t->anchor = TC_PREV_NEWLINE; }
        break;
    case '$':
        if (i + 1 != ps->len) {
            tac_token next;
            ps->pos++;
            tac_peek (ps, &next, 0);
            ps->pos--;
            if (next.type != TK_ALT && next.type != TK_CLOSE) break;
        }
        t->type = TK_ANCHOR; t->anchor = TC_NEXT_NEWLINE;
        break;
    default:
        if (c >= 0x80 && ps->utf8) t->len = t->chars = tac_utf8_length (ps->s + i, ps->len - i);
    }
}

static void
tac_fetch (tac_parser *ps, tac_token *t, int caret)
{
    tac_peek (ps, t, caret);
    ps->pos += t->len;
}

/* glibc peek_token_bracket for syntax 0: no backslash escapes or classes. */
enum { TBK_END, TBK_CHAR, TBK_CLOSE, TBK_NONMATCH, TBK_RANGE, TBK_SYMBOL };

static int
tac_peek_bracket (tac_parser *ps, unsigned char *c, size_t *len)
{
    size_t i = ps->pos;
    *len = 1;
    if (i >= ps->len) { *len = 0; return TBK_END; }
    *c = ps->s[i];
    if (*c >= 0x80 && ps->utf8) { ps->err = TE_UNSUPPORTED; return TBK_END; }
    switch (*c) {
    case '[':
        if (i + 1 < ps->len && (ps->s[i + 1] == '.' || ps->s[i + 1] == '=')) {
            /* Collating and equivalence elements are locale lookups. */
            ps->err = TE_UNSUPPORTED;
            return TBK_END;
        }
        return TBK_CHAR;
    case ']': return TBK_CLOSE;
    case '^': return TBK_NONMATCH;
    case '-':
        /* glibc rewinds its input inconsistently around "---". */
        if (i + 2 < ps->len && ps->s[i + 1] == '-' && ps->s[i + 2] == '-') {
            ps->err = TE_UNSUPPORTED;
            return TBK_END;
        }
        return TBK_RANGE;
    }
    return TBK_CHAR;
}

static int
tac_parse_bracket (tac_parser *ps)
{
    uint64_t set[4] = {0, 0, 0, 0};
    unsigned char c = 0, c2 = 0;
    size_t len, len2;
    int invert = 0, first = 1;
    int type = tac_peek_bracket (ps, &c, &len);
    if (ps->err) return -1;
    if (type == TBK_END) { ps->err = TE_BADPAT; return -1; }
    if (type == TBK_NONMATCH) {
        invert = 1;
        ps->pos += len;
        type = tac_peek_bracket (ps, &c, &len);
        if (ps->err) return -1;
        if (type == TBK_END) { ps->err = TE_BADPAT; return -1; }
    }
    if (type == TBK_CLOSE) type = TBK_CHAR;
    for (;;) {
        int low = c, high = c, range = 0;
        ps->pos += len;
        if (type == TBK_RANGE && !first) {
            /* A later '-' may only be the last element. */
            int next = tac_peek_bracket (ps, &c2, &len2);
            if (ps->err) return -1;
            if (next != TBK_CLOSE) { ps->err = TE_ERANGE; return -1; }
        }
        first = 0;
        type = tac_peek_bracket (ps, &c, &len);
        if (ps->err) return -1;
        if (type == TBK_END) { ps->err = TE_EBRACK; return -1; }
        if (type == TBK_RANGE) {
            ps->pos += len;
            int end = tac_peek_bracket (ps, &c2, &len2);
            if (ps->err) return -1;
            if (end == TBK_END) { ps->err = TE_EBRACK; return -1; }
            if (end == TBK_CLOSE) {
                ps->pos -= len;          /* The final '-' is literal. */
                type = TBK_CHAR;
            } else {
                range = 1;
                high = c2;
                ps->pos += len2;
                type = tac_peek_bracket (ps, &c, &len);
                if (ps->err) return -1;
            }
        }
        if (range && (!ps->c_collate || ps->utf8)) { ps->err = TE_UNSUPPORTED; return -1; }
        for (int x = low; x <= high; x++) set[x >> 6] |= (uint64_t) 1 << (x & 63);
        if (type == TBK_END) { ps->err = TE_EBRACK; return -1; }
        if (type == TBK_CLOSE) break;
    }
    ps->pos += len;
    if (invert && ps->utf8) { ps->err = TE_UNSUPPORTED; return -1; }
    int n = tac_tree_new (ps, TT_SET, -1, -1);
    if (n >= 0)
        for (int i = 0; i < 4; i++) ps->set[n][i] = invert ? ~set[i] : set[i];
    return n;
}

static int tac_parse_alternatives (tac_parser *, tac_token *, int);

static int
tac_parse_expression (tac_parser *ps, tac_token *t, int nest)
{
    int tree = -1;
    switch (t->type) {
    case TK_CHAR: case TK_STAR: case TK_PLUS: case TK_QUESTION:
        /* A leading repetition character is an ordinary character. */
        if (!t->chars) { ps->err = TE_UNSUPPORTED; return -1; }
        if (t->chars > 1 && !ps->utf8) { ps->err = TE_UNSUPPORTED; return -1; }
        tree = tac_tree_byte (ps, ps->s[t->at]);
        for (size_t i = 1; i < t->chars; i++)
            tree = tac_tree_new (ps, TT_CAT, tree, tac_tree_byte (ps, ps->s[t->at + i]));
        break;
    case TK_OPEN: {
        int group = ps->nsub++;
        if (++ps->depth > TAC_RE_NEST_MAX) { ps->err = TE_UNSUPPORTED; return -1; }
        tac_fetch (ps, t, 1);
        if (t->type != TK_CLOSE) {
            tree = tac_parse_alternatives (ps, t, nest + 1);
            if (!ps->err && t->type != TK_CLOSE) ps->err = TE_EPAREN;
        }
        ps->depth--;
        if (group < 9) ps->completed |= 1u << group;
        break;
    }
    case TK_BRACKET: tree = tac_parse_bracket (ps); break;
    case TK_BACKREF:
        if (!(ps->completed & (1u << (t->c - '1')))) { ps->err = TE_ESUBREG; return -1; }
        ps->err = TE_UNSUPPORTED;       /* Not a regular language. */
        return -1;
    case TK_CLOSE: ps->err = TE_ERPAREN; return -1;
    case TK_ANCHOR:
        if (ps->utf8 && (t->anchor & (TC_PREV_WORD | TC_PREV_NOTWORD | TC_WORD_DELIM
                                      | TC_NOT_WORD_DELIM))) {
            ps->err = TE_UNSUPPORTED;   /* Word context uses wide characters. */
            return -1;
        }
        if (t->anchor == TC_WORD_DELIM || t->anchor == TC_NOT_WORD_DELIM) {
            int delim = t->anchor == TC_WORD_DELIM;
            int x = tac_tree_new (ps, TT_ASSERT, -1, -1);
            int y = tac_tree_new (ps, TT_ASSERT, -1, -1);
            if (ps->err) return -1;
            ps->tree[x].constraint = delim ? TC_PREV_NOTWORD | TC_NEXT_WORD
                                           : TC_PREV_WORD | TC_NEXT_WORD;
            ps->tree[y].constraint = delim ? TC_PREV_WORD | TC_NEXT_NOTWORD
                                           : TC_PREV_NOTWORD | TC_NEXT_NOTWORD;
            tree = tac_tree_new (ps, TT_ALT, x, y);
            /* Mark the alternation, not the expanded asserts: those
               constraints are the same bits as \< and \>. */
            if (tree >= 0) ps->tree[tree].mark = TM_DIFF;
        } else {
            tree = tac_tree_new (ps, TT_ASSERT, -1, -1);
            if (tree >= 0) {
                ps->tree[tree].constraint = t->anchor;
                ps->tree[tree].mark = (unsigned char) tac_anchor_class (t->anchor);
            }
        }
        /* An anchor is never repeated: a following '*' is literal. */
        tac_fetch (ps, t, 0);
        return tree;
    case TK_PERIOD:
        if (ps->utf8) { ps->err = TE_UNSUPPORTED; return -1; }
        tree = tac_tree_new (ps, TT_SET, -1, -1);
        if (tree >= 0) {
            memset (ps->set[tree], 0xff, sizeof ps->set[tree]);
            ps->set[tree][0] &= ~((uint64_t) 1 << '\n');
        }
        break;
    case TK_WORD: case TK_NOTWORD: case TK_SPACE: case TK_NOTSPACE:
        if (ps->utf8) { ps->err = TE_UNSUPPORTED; return -1; }
        tree = tac_tree_class (ps, t->type == TK_WORD || t->type == TK_NOTWORD
                               ? ps->word : ps->space,
                               t->type == TK_NOTWORD || t->type == TK_NOTSPACE);
        break;
    case TK_ALT: case TK_END: return -1;
    case TK_BACKSLASH: ps->err = TE_EESCAPE; return -1;
    }
    if (ps->err) return -1;
    tac_fetch (ps, t, 0);
    while (t->type == TK_STAR || t->type == TK_PLUS || t->type == TK_QUESTION) {
        int type = t->type == TK_STAR ? TT_STAR : t->type == TK_PLUS ? TT_PLUS : TT_OPT;
        tac_fetch (ps, t, 0);
        if (tree >= 0) tree = tac_tree_new (ps, type, tree, -1);
        if (ps->err) return -1;
    }
    return tree;
}

static int
tac_parse_branch (tac_parser *ps, tac_token *t, int nest)
{
    int tree = tac_parse_expression (ps, t, nest);
    while (!ps->err && t->type != TK_ALT && t->type != TK_END
           && (!nest || t->type != TK_CLOSE)) {
        int next = tac_parse_expression (ps, t, nest);
        if (tree < 0) tree = next;
        else if (next >= 0) tree = tac_tree_new (ps, TT_CAT, tree, next);
    }
    return ps->err ? -1 : tree;
}

static int
tac_parse_alternatives (tac_parser *ps, tac_token *t, int nest)
{
    unsigned initial = ps->completed;
    int tree = tac_parse_branch (ps, t, nest);
    while (!ps->err && t->type == TK_ALT) {
        int branch = -1;
        tac_fetch (ps, t, 1);
        if (t->type != TK_ALT && t->type != TK_END && (!nest || t->type != TK_CLOSE)) {
            unsigned accumulated = ps->completed;
            ps->completed = initial;
            branch = tac_parse_branch (ps, t, nest);
            ps->completed |= accumulated;
        }
        tree = tac_tree_new (ps, TT_ALT, tree, branch);
    }
    return ps->err ? -1 : tree;
}

static int
tac_tree_nullable (const tac_parser *ps, int n)
{
    if (n < 0) return 1;
    const tac_tree *t = &ps->tree[n];
    switch (t->type) {
    case TT_SET: return 0;
    case TT_CAT: return tac_tree_nullable (ps, t->a) && tac_tree_nullable (ps, t->b);
    case TT_ALT: return tac_tree_nullable (ps, t->a) || tac_tree_nullable (ps, t->b);
    case TT_PLUS: return tac_tree_nullable (ps, t->a);
    default: return 1;
    }
}

static unsigned
tac_tree_marks (const tac_parser *ps, int n)
{
    if (n < 0) return 0;
    const tac_tree *t = &ps->tree[n];
    unsigned marks = t->mark;
    switch (t->type) {
    case TT_CAT: case TT_ALT:
        return marks | tac_tree_marks (ps, t->a) | tac_tree_marks (ps, t->b);
    case TT_STAR: case TT_PLUS: case TT_OPT:
        return marks | tac_tree_marks (ps, t->a);
    default:
        return marks;
    }
}

/* True when the subexpression matches no bytes. A '*' of a byte is not
   one of these: it can also consume, and GNU finishes that plus. */
static int
tac_cannot_consume (const tac_parser *ps, int n)
{
    if (n < 0) return 1;
    const tac_tree *t = &ps->tree[n];
    switch (t->type) {
    case TT_SET: return 0;
    case TT_CAT: case TT_ALT:
        return tac_cannot_consume (ps, t->a) && tac_cannot_consume (ps, t->b);
    case TT_STAR: case TT_PLUS: case TT_OPT:
        return tac_cannot_consume (ps, t->a);
    default:
        return 1;
    }
}

/* An alternative that matches empty, contains no anchor, and matches no
   bytes. \(\|\`b\)+ has one. \(\`\|a*\)+ does not: a* can consume. */
static int
tac_is_bare (const tac_parser *ps, int n)
{
    if (n < 0) return 1;
    /* '$' consumes nothing and carries no hang/diff mark. It is still an
       anchor, not the empty alternative beside \` ^ \< \>. */
    if (ps->tree[n].type == TT_ASSERT) return 0;
    return tac_tree_nullable (ps, n) && tac_tree_marks (ps, n) == 0
        && tac_cannot_consume (ps, n);
}

static int
tac_has_bare_alt (const tac_parser *ps, int n)
{
    if (n < 0) return 1;
    const tac_tree *t = &ps->tree[n];
    switch (t->type) {
    case TT_ALT:
        return tac_is_bare (ps, t->a) || tac_is_bare (ps, t->b)
            || tac_has_bare_alt (ps, t->a) || tac_has_bare_alt (ps, t->b);
    case TT_CAT: case TT_STAR: case TT_PLUS: case TT_OPT:
        return tac_has_bare_alt (ps, t->a)
            || ((t->type == TT_CAT) && tac_has_bare_alt (ps, t->b));
    default:
        return 0;
    }
}

/* The Thompson plus is the XX* span. That span is the one that returns for
   a nullable '+' of \` ^ \< \> beside an anchor-free empty alternative.
   It disagrees with GNU for \' \b \B, for a non-nullable hang-anchor '+',
   and for a nullable hang-anchor '+' that has no such alternative
   (GNU finishes \(\`+?\|\s\)+ and returns the input unchanged). */
static int
tac_tree_bad_plus (const tac_parser *ps, int n)
{
    if (n < 0) return 0;
    const tac_tree *t = &ps->tree[n];
    if (t->type == TT_PLUS) {
        unsigned marks = tac_tree_marks (ps, t->a);
        int loop = tac_tree_nullable (ps, t->a) && (marks & TM_HANG)
            && !(marks & TM_DIFF) && tac_has_bare_alt (ps, t->a);
        if ((marks & (TM_DIFF | TM_HANG)) && !loop) return 1;
    }
    switch (t->type) {
    case TT_CAT: case TT_ALT:
        return tac_tree_bad_plus (ps, t->a) || tac_tree_bad_plus (ps, t->b);
    case TT_STAR: case TT_PLUS: case TT_OPT:
        return tac_tree_bad_plus (ps, t->a);
    default:
        return 0;
    }
}

/* ---- Thompson NFA and two lazily built DFAs ---- */

enum { TN_SET, TN_SPLIT, TN_ASSERT, TN_MATCH };

typedef struct {
    int words, nctx, count, cap;
    unsigned generation;
    uint64_t *bits;
    int32_t *next;
    unsigned char *live;
    int32_t *hash;
    size_t mask;
} tac_dfa;

typedef struct {
    int count, start, match, words, has_assert;
    unsigned char *type;
    int *out, *out2;
    unsigned short *constraint;
    uint64_t (*set)[4];
    int *sets, nsets;
    int *pred_index, *pred;
    uint64_t *setmask, *scratch, *seen;
    int *stack;
    unsigned char klass[256];
    tac_dfa back, forward;
    int32_t start_id[16];
    unsigned start_generation[16];
    char *block, *fblock;
    off_t block_base, fblock_base;
    size_t block_used, fblock_used;
} tac_engine;

static int
tac_node_new (tac_engine *e, int type, int out, int out2)
{
    int n = e->count++;
    e->type[n] = (unsigned char) type;
    e->out[n] = out;
    e->out2[n] = out2;
    e->constraint[n] = 0;
    return n;
}

/* Build tree T in front of continuation NEXT and return its entry node. */
static int
tac_node_build (tac_engine *e, const tac_parser *ps, int t, int next)
{
    if (t < 0) return next;
    const tac_tree *tree = &ps->tree[t];
    int n, body;
    switch (tree->type) {
    case TT_SET:
        n = tac_node_new (e, TN_SET, next, -1);
        memcpy (e->set[n], ps->set[t], sizeof e->set[n]);
        return n;
    case TT_ASSERT:
        n = tac_node_new (e, TN_ASSERT, next, -1);
        e->constraint[n] = tree->constraint;
        e->has_assert = 1;
        return n;
    case TT_CAT:
        return tac_node_build (e, ps, tree->a, tac_node_build (e, ps, tree->b, next));
    case TT_ALT:
        body = tac_node_build (e, ps, tree->a, next);
        return tac_node_new (e, TN_SPLIT, body, tac_node_build (e, ps, tree->b, next));
    case TT_OPT:
        return tac_node_new (e, TN_SPLIT, tac_node_build (e, ps, tree->a, next), next);
    default:                    /* TT_STAR, TT_PLUS */
        n = tac_node_new (e, TN_SPLIT, -1, next);
        body = tac_node_build (e, ps, tree->a, n);
        e->out[n] = body;
        return tree->type == TT_PLUS ? body : n;
    }
}

#define TAC_BIT(b, n) (((b)[(n) >> 6] >> ((n) & 63)) & 1)
#define TAC_SETBIT(b, n) ((b)[(n) >> 6] |= (uint64_t) 1 << ((n) & 63))

static int
tac_satisfied (unsigned constraint, int prev, int next)
{
    static const unsigned char prev_context[4] = { 0, TX_WORD, TX_NEWLINE, TX_NEWLINE | TX_BEGBUF };
    static const unsigned char next_context[4] = { 0, TX_WORD, TX_NEWLINE, TX_NEWLINE | TX_ENDBUF };
    unsigned p = prev_context[prev], n = next_context[next];
    return !(((constraint & TC_PREV_WORD) && !(p & TX_WORD))
             || ((constraint & TC_PREV_NOTWORD) && (p & TX_WORD))
             || ((constraint & TC_PREV_NEWLINE) && !(p & TX_NEWLINE))
             || ((constraint & TC_PREV_BEGBUF) && !(p & TX_BEGBUF))
             || ((constraint & TC_NEXT_WORD) && !(n & TX_WORD))
             || ((constraint & TC_NEXT_NOTWORD) && (n & TX_WORD))
             || ((constraint & TC_NEXT_NEWLINE) && !(n & TX_NEWLINE))
             || ((constraint & TC_NEXT_ENDBUF) && !(n & TX_ENDBUF)));
}

static int
tac_dfa_init (tac_dfa *d, int words, int nctx)
{
    size_t per = (size_t) words * 8 + (size_t) nctx * 256 * 4 + 1 + 16;
    size_t cap = TAC_DFA_BUDGET / per;
    if (cap < 8) cap = 8;
    size_t slots = 16;
    while (slots < cap * 2) slots *= 2;
    d->words = words; d->nctx = nctx; d->cap = (int) cap; d->count = 0;
    d->generation = 1;
    d->bits = malloc (cap * (size_t) words * 8);
    d->next = malloc (cap * (size_t) nctx * 256 * sizeof *d->next);
    d->live = malloc (cap);
    d->hash = malloc (slots * sizeof *d->hash);
    d->mask = slots - 1;
    if (!d->bits || !d->next || !d->live || !d->hash) return -1;
    memset (d->hash, 0xff, slots * sizeof *d->hash);
    return 0;
}

static void
tac_dfa_free (tac_dfa *d)
{
    free (d->bits); free (d->next); free (d->live); free (d->hash);
}

/* Return the id of state BITS, adding it. A full cache is discarded first,
   so memory stays fixed; *flushed tells the caller old ids are invalid. */
static int32_t
tac_dfa_intern (tac_dfa *d, const uint64_t *bits, const uint64_t *setmask, int *flushed)
{
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < d->words; i++) h = (h ^ bits[i]) * 1099511628211ULL;
    for (size_t slot = (size_t) h & d->mask;; slot = (slot + 1) & d->mask) {
        int32_t id = d->hash[slot];
        if (id < 0) break;
        if (!memcmp (d->bits + (size_t) id * d->words, bits, (size_t) d->words * 8))
            return id;
    }
    if (d->count == d->cap) {
        d->count = 0;
        d->generation++;
        memset (d->hash, 0xff, (d->mask + 1) * sizeof *d->hash);
        *flushed = 1;
    }
    int32_t id = d->count++;
    memcpy (d->bits + (size_t) id * d->words, bits, (size_t) d->words * 8);
    memset (d->next + (size_t) id * d->nctx * 256, 0xff, (size_t) d->nctx * 256 * sizeof *d->next);
    d->live[id] = 0;
    for (int i = 0; i < d->words; i++) if (bits[i] & setmask[i]) d->live[id] = 1;
    size_t slot = (size_t) h & d->mask;
    while (d->hash[slot] >= 0) slot = (slot + 1) & d->mask;
    d->hash[slot] = id;
    return id;
}

/* Forward closure: the SET and MATCH nodes reachable from the nodes on the
   stack without consuming a byte, at a position with the given context. */
static void
tac_closure_forward (tac_engine *e, int depth, int prev, int next, uint64_t *result)
{
    memset (result, 0, (size_t) e->words * 8);
    memset (e->seen, 0, (size_t) e->words * 8);
    while (depth) {
        int n = e->stack[--depth];
        if (n < 0 || TAC_BIT (e->seen, n)) continue;
        TAC_SETBIT (e->seen, n);
        switch (e->type[n]) {
        case TN_SET: case TN_MATCH: TAC_SETBIT (result, n); break;
        case TN_SPLIT:
            e->stack[depth++] = e->out[n];
            e->stack[depth++] = e->out2[n];
            break;
        case TN_ASSERT:
            if (tac_satisfied (e->constraint[n], prev, next)) e->stack[depth++] = e->out[n];
            break;
        }
    }
}

/* Backward closure: every node from which a node in LIVE (SET nodes that can
   consume the next byte and still finish) or MATCH is reachable here. */
static void
tac_closure_backward (tac_engine *e, const uint64_t *live, int prev, int next, uint64_t *result)
{
    int depth = 0;
    memset (result, 0, (size_t) e->words * 8);
    e->stack[depth++] = e->match;
    for (int i = 0; i < e->nsets; i++)
        if (TAC_BIT (live, e->sets[i])) e->stack[depth++] = e->sets[i];
    while (depth) {
        int n = e->stack[--depth];
        if (TAC_BIT (result, n)) continue;
        TAC_SETBIT (result, n);
        for (int i = e->pred_index[n]; i < e->pred_index[n + 1]; i++) {
            int p = e->pred[i];
            if (e->type[p] == TN_ASSERT && !tac_satisfied (e->constraint[p], prev, next))
                continue;
            if (!TAC_BIT (result, p)) e->stack[depth++] = p;
        }
    }
}

/* One step right to left from position p (state: live SET nodes at p) over
   the byte b = s[p - 1]. Returns (state at p - 1) << 1 | (match starts at p). */
static int32_t
tac_step_backward (tac_engine *e, int32_t id, int next, unsigned char b)
{
    tac_dfa *d = &e->back;
    size_t index = ((size_t) id * d->nctx + (d->nctx > 1 ? (size_t) next : 0)) * 256 + b;
    if (d->next[index] >= 0) return d->next[index];
    uint64_t *reach = e->scratch, *live = e->scratch + e->words;
    tac_closure_backward (e, d->bits + (size_t) id * d->words, e->klass[b], next, reach);
    int start = TAC_BIT (reach, e->start);
    memset (live, 0, (size_t) e->words * 8);
    for (int i = 0; i < e->nsets; i++) {
        int q = e->sets[i];
        if (TAC_BIT (e->set[q], b) && TAC_BIT (reach, e->out[q])) TAC_SETBIT (live, q);
    }
    int flushed = 0;
    int32_t target = tac_dfa_intern (d, live, e->setmask, &flushed);
    int32_t value = target << 1 | start;
    if (!flushed) d->next[index] = value;
    return value;
}

/* One step left to right over b = s[p], with NEXT the class after it.
   Returns (state at p + 1) << 1 | (a match ends at p + 1). */
static int32_t
tac_step_forward (tac_engine *e, int32_t id, int next, unsigned char b)
{
    tac_dfa *d = &e->forward;
    size_t index = ((size_t) id * d->nctx + (d->nctx > 1 ? (size_t) next : 0)) * 256 + b;
    if (d->next[index] >= 0) return d->next[index];
    const uint64_t *bits = d->bits + (size_t) id * d->words;
    int depth = 0;
    for (int i = 0; i < e->nsets; i++) {
        int q = e->sets[i];
        if (TAC_BIT (bits, q) && TAC_BIT (e->set[q], b)) e->stack[depth++] = e->out[q];
    }
    tac_closure_forward (e, depth, e->klass[b], next, e->scratch);
    int match = TAC_BIT (e->scratch, e->match);
    int flushed = 0;
    int32_t target = tac_dfa_intern (d, e->scratch, e->setmask, &flushed);
    int32_t value = target << 1 | match;
    if (!flushed) d->next[index] = value;
    return value;
}

static void
tac_engine_free (tac_engine *e)
{
    free (e->type); free (e->out); free (e->out2); free (e->constraint);
    free (e->set); free (e->sets); free (e->pred_index); free (e->pred);
    free (e->setmask); free (e->scratch); free (e->seen); free (e->stack);
    free (e->block); free (e->fblock);
    tac_dfa_free (&e->back); tac_dfa_free (&e->forward);
    memset (e, 0, sizeof *e);
}

/* Compile PATTERN. Returns TE_OK, a glibc-equivalent syntax error, or
   TE_UNSUPPORTED when the bounded matcher cannot guarantee GNU results. */
static int
tac_engine_compile (tac_engine *e, const char *pattern)
{
    tac_parser ps;
    memset (&ps, 0, sizeof ps);
    memset (e, 0, sizeof *e);
    ps.s = (const unsigned char *) pattern;
    ps.len = strlen (pattern);
    const char *ctype = setlocale (LC_CTYPE, NULL), *collate = setlocale (LC_COLLATE, NULL);
    int c_ctype = ctype && (!strcmp (ctype, "C") || !strcmp (ctype, "POSIX"));
    ps.c_collate = collate && (!strcmp (collate, "C") || !strcmp (collate, "POSIX"));
    if (MB_CUR_MAX > 1) {
        const char *codeset = nl_langinfo (CODESET);
        if (!codeset || strcmp (codeset, "UTF-8")) return TE_UNSUPPORTED;
        ps.utf8 = 1;
    } else if (!c_ctype) {
        return TE_UNSUPPORTED;
    }
    for (int c = 0; c < 256; c++) {
        ps.word[c] = c < 128 ? isalnum (c) || c == '_' : 0;
        ps.space[c] = c < 128 && isspace (c);
    }
    tac_token t;
    tac_fetch (&ps, &t, 1);
    int root = tac_parse_alternatives (&ps, &t, 0);
    /* Matches must start on character boundaries in a UTF-8 locale; an
       empty match need not, so nullable patterns stay with glibc there. */
    if (!ps.err && ps.utf8 && tac_tree_nullable (&ps, root)) ps.err = TE_UNSUPPORTED;
    if (!ps.err && tac_tree_bad_plus (&ps, root)) ps.err = TE_UNSUPPORTED;
    if (ps.err) { free (ps.tree); free (ps.set); return ps.err; }

    int max = 2 * ps.ntree + 2;
    e->type = malloc ((size_t) max);
    e->out = malloc ((size_t) max * sizeof *e->out);
    e->out2 = malloc ((size_t) max * sizeof *e->out2);
    e->constraint = malloc ((size_t) max * sizeof *e->constraint);
    e->set = malloc ((size_t) max * sizeof *e->set);
    if (!e->type || !e->out || !e->out2 || !e->constraint || !e->set) goto nomem;
    e->match = tac_node_new (e, TN_MATCH, -1, -1);
    e->start = tac_node_build (e, &ps, root, e->match);
    free (ps.tree); free (ps.set); ps.tree = NULL; ps.set = NULL;

    int m = e->count;
    e->words = (m + 63) / 64;
    e->sets = malloc ((size_t) m * sizeof *e->sets);
    e->pred_index = calloc ((size_t) m + 1, sizeof *e->pred_index);
    e->pred = malloc ((size_t) 2 * m * sizeof *e->pred + 1);
    e->setmask = calloc ((size_t) e->words, 8);
    e->scratch = malloc ((size_t) e->words * 16);
    e->seen = malloc ((size_t) e->words * 8);
    e->stack = malloc ((size_t) 3 * m * sizeof *e->stack + 8);
    e->block = malloc (TAC_BLOCK);
    e->fblock = malloc (TAC_BLOCK);
    if (!e->sets || !e->pred_index || !e->pred || !e->setmask || !e->scratch
        || !e->seen || !e->stack || !e->block || !e->fblock)
        goto nomem;
    for (int n = 0; n < m; n++) {
        if (e->type[n] == TN_SET) { e->sets[e->nsets++] = n; TAC_SETBIT (e->setmask, n); }
        if (e->type[n] == TN_SPLIT || e->type[n] == TN_ASSERT) {
            e->pred_index[e->out[n] + 1]++;
            if (e->type[n] == TN_SPLIT) e->pred_index[e->out2[n] + 1]++;
        }
    }
    for (int n = 0; n < m; n++) e->pred_index[n + 1] += e->pred_index[n];
    {
        int *fill = e->stack;   /* Temporary insertion cursors. */
        memcpy (fill, e->pred_index, (size_t) m * sizeof *fill);
        for (int n = 0; n < m; n++)
            if (e->type[n] == TN_SPLIT || e->type[n] == TN_ASSERT) {
                e->pred[fill[e->out[n]]++] = n;
                if (e->type[n] == TN_SPLIT) e->pred[fill[e->out2[n]]++] = n;
            }
    }
    for (int c = 0; c < 256; c++)
        e->klass[c] = c == '\n' ? TB_NEWLINE : ps.word[c] ? TB_WORD : TB_OTHER;
    int nctx = e->has_assert ? 4 : 1;
    if (tac_dfa_init (&e->back, e->words, nctx) < 0
        || tac_dfa_init (&e->forward, e->words, nctx) < 0)
        goto nomem;
    e->block_used = e->fblock_used = 0;
    return TE_OK;
nomem:
    free (ps.tree); free (ps.set);
    tac_engine_free (e);
    return TE_ESPACE;
}

/* A match starts inside the block the backward scan just read; only longer
   matches continue into a separate forward block. */
static int
tac_engine_byte (tac_engine *e, tac_input *in, off_t pos)
{
    if (pos >= e->block_base && pos < e->block_base + (off_t) e->block_used)
        return (unsigned char) e->block[pos - e->block_base];
    if (pos < e->fblock_base || pos >= e->fblock_base + (off_t) e->fblock_used) {
        off_t n = in->end - pos > TAC_BLOCK ? TAC_BLOCK : in->end - pos;
        if (tac_read_at (in->fd, e->fblock, (size_t) n, pos) < 0) return -1;
        e->fblock_base = pos;
        e->fblock_used = (size_t) n;
    }
    return (unsigned char) e->fblock[pos - e->fblock_base];
}

/* re_search (subject [B, E), start E - 1, range 1 - (E - B)) without
   holding the subject: scan right to left for the rightmost position where
   the reversed automaton reaches the start node, then extend the longest
   match from there. Memory is fixed by the pattern. */
static int
tac_engine_search (void *matcher, tac_input *in, off_t B, off_t E, off_t past,
                   off_t *found_start, off_t *found_end)
{
    tac_engine *e = matcher;
    (void) past;
    uint64_t *empty = e->scratch + e->words;
    memset (empty, 0, (size_t) e->words * 8);
    int flushed = 0;
    int32_t state = tac_dfa_intern (&e->back, empty, e->setmask, &flushed);
    int next = TB_BUF, prev;
    off_t p = E;
    while (p > B) {
        if (p - 1 < e->block_base || p - 1 >= e->block_base + (off_t) e->block_used) {
            off_t low = p > TAC_BLOCK ? p - TAC_BLOCK : 0;
            if (tac_read_at (in->fd, e->block, (size_t) (p - low), low) < 0) return -1;
            e->block_base = low;
            e->block_used = (size_t) (p - low);
            /* Records just above a match usually come from this block. */
            in->data = e->block; in->base = low; in->used = e->block_used;
        }
        const unsigned char *at = (const unsigned char *) e->block + (p - e->block_base);
        const int32_t *table = e->back.next;
        size_t nctx = (size_t) e->back.nctx;
        off_t stop = e->block_base > B ? e->block_base : B;
        while (p > stop) {
            unsigned char b = *--at;
            int32_t value = table[((size_t) state * nctx + (nctx > 1 ? (size_t) next : 0)) * 256 + b];
            if (value < 0) value = tac_step_backward (e, state, next, b);
            if ((value & 1) && p < E) { prev = e->klass[b]; goto found; }
            state = value >> 1;
            next = e->klass[b];
            p--;
        }
    }
    {
        /* At B the previous context is the buffer start. */
        uint64_t *reach = e->scratch;
        tac_closure_backward (e, e->back.bits + (size_t) state * e->words, TB_BUF, next, reach);
        if (!TAC_BIT (reach, e->start)) return 0;
        prev = TB_BUF;
    }
found:
    *found_start = p;
    {
        int key = prev * 4 + next;
        int32_t id = e->start_id[key];
        if (e->start_generation[key] != e->forward.generation) {
            e->stack[0] = e->start;
            tac_closure_forward (e, 1, prev, next, e->scratch);
            flushed = 0;
            id = tac_dfa_intern (&e->forward, e->scratch, e->setmask, &flushed);
            e->start_id[key] = id;
            e->start_generation[key] = e->forward.generation;
        }
        off_t last = TAC_BIT (e->forward.bits + (size_t) id * e->words, e->match) ? p : -1;
        while (p < E && e->forward.live[id]) {
            int b = tac_engine_byte (e, in, p);
            if (b < 0) return -1;
            int after = TB_BUF;
            if (p + 1 < E) {
                int c = tac_engine_byte (e, in, p + 1);
                if (c < 0) return -1;
                after = e->klass[c];
            }
            const tac_dfa *d = &e->forward;
            int32_t value = d->next[((size_t) id * d->nctx + (d->nctx > 1 ? (size_t) after : 0))
                                    * 256 + (unsigned char) b];
            if (value < 0) value = tac_step_forward (e, id, after, (unsigned char) b);
            id = value >> 1;
            p++;
            if (value & 1) last = p;
        }
        if (last < 0) { errno = EINVAL; return -1; }
        *found_end = last;
    }
    return 1;
}

#ifdef __GLIBC__
/* The general fallback for back-references and multibyte constructs keeps
   GNU's own buffer: the current window plus the unprinted record. */
typedef struct {
    regex_t *re;
    struct re_registers regs;
    char *data;
    size_t capacity;
    off_t base;
    int loaded;
} tac_gnu;

static int
tac_gnu_search (void *matcher, tac_input *in, off_t B, off_t E, off_t past,
                off_t *found_start, off_t *found_end)
{
    tac_gnu *g = matcher;
    if (!g->loaded || B < g->base) {
        off_t keep = g->loaded ? past - g->base : 0;
        uintmax_t need = (uintmax_t) (past - B);
        if (need > SIZE_MAX) { errno = ENOMEM; return -1; }
        if (need > g->capacity) {
            size_t capacity = g->capacity + g->capacity / 2;
            if (capacity < need) capacity = (size_t) need;
            char *data = realloc (g->data, capacity);
            if (!data) return -1;
            g->data = data; g->capacity = capacity;
        }
        off_t low = g->loaded ? g->base : past;
        if (keep > 0) memmove (g->data + (low - B), g->data, (size_t) keep);
        if (tac_read_at (in->fd, g->data, (size_t) (low - B), B) < 0) return -1;
        g->base = B;
        g->loaded = 1;
        in->data = g->data; in->base = B; in->used = (size_t) (past - B);
    }
    if ((uintmax_t) (E - B) > INT_MAX) { errno = EFBIG; return -2; }
    regoff_t length = (regoff_t) (E - B);
    regoff_t found = re_search (g->re, g->data + (B - g->base), length, length - 1,
                                1 - length, &g->regs);
    if (found == -2) { errno = ENOMEM; return -3; }
    if (found < 0) return 0;
    *found_start = B + g->regs.start[0];
    *found_end = B + g->regs.end[0];
    return 1;
}
#endif

/* GNU tac_seekable's regex loop. The window is aligned on the file, grows
   while the pending record exceeds it, and its size carries over to later
   files. A failed search widens the window to the left and searches the
   whole pending record again, so the buffer-relative anchors match GNU. */
static int
tac_regex_windows (tac_input *in, size_t *read_size, int before, bl_output *out,
                   int (*search) (void *, tac_input *, off_t, off_t, off_t, off_t *, off_t *),
                   void *matcher)
{
    if (!in->end) return 0;
    uintmax_t remainder = (uintmax_t) in->end % *read_size;
    off_t B = remainder ? in->end - (off_t) remainder : in->end - (off_t) *read_size;
    off_t past = in->end, E = in->end;
    while (!out->error) {
        off_t start = 0, end = 0;
        int got = E > B ? search (matcher, in, B, E, past, &start, &end) : 0;
        if (got < 0) return got;
        if (!got) {
            if (!B) return tac_output_range (in, 0, past, out);
            if ((uintmax_t) (past - B) > *read_size) {
                if (*read_size > SIZE_MAX / 2) { errno = EOVERFLOW; return -1; }
                *read_size *= 2;
            }
            if ((uintmax_t) B >= *read_size) B -= (off_t) *read_size;
            else { *read_size = (size_t) B; B = 0; }
            E = past;
            continue;
        }
        off_t boundary = before ? start : end;
        if (tac_output_range (in, boundary, past, out) < 0) return -1;
        past = boundary;
        E = start;
    }
    return -1;
}

/* A pipe spool belongs exclusively to this call. Unlink immediately: normal
   errors, output failures and process exit cannot leave a pathname behind. */
static int
tac_spool (int fd)
{
    const char *tmpdir = getenv ("TMPDIR");
    if (!tmpdir || !*tmpdir) tmpdir = "/tmp";
    size_t n = strlen (tmpdir);
    if (n > SIZE_MAX - 24) { errno = EOVERFLOW; return -1; }
    char *name = malloc (n + 24);
    if (!name) return -1;
    snprintf (name, n + 24, "%s/tac.XXXXXX", tmpdir);
    int spool = mkstemp (name);
    if (spool >= 0 && unlink (name) < 0) {
        int error = errno; close (spool); spool = -1; errno = error;
    }
    free (name);
    if (spool < 0) return -1;
    if (fcntl (spool, F_SETFD, FD_CLOEXEC) < 0) goto fail;
    char buffer[TAC_BLOCK];
    for (;;) {
        ssize_t count = read (fd, buffer, sizeof buffer);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) break;
        if (!count) return spool;
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write (spool, buffer + offset, (size_t) (count - offset));
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) { if (!written) errno = EIO; goto fail; }
            offset += written;
        }
    }
fail:
    { int error = errno; close (spool); errno = error; }
    return -1;
}

enum { TAC_LITERAL, TAC_ATOM, TAC_ENGINE, TAC_GNU };

typedef struct {
    const char *sep;
    int before, mode;
    size_t read_size;
    tac_atom atom;
    tac_engine engine;
#ifdef __GLIBC__
    tac_gnu gnu;
#endif
} tac_job;

/* Returns 0, -1 with errno for a file error, or -2/-3 for GNU's fatal
   "record too large" and regex search failures. */
static int
tac_file (int fd, tac_job *job, bl_output *out)
{
    int spool = -1;
    struct stat st;
    if (fstat (fd, &st) < 0) return -1;
    off_t end = lseek (fd, 0, SEEK_END);
    if (end == 0 && S_ISREG (st.st_mode)) {
        char byte;
        ssize_t n;
        do n = pread (fd, &byte, 1, 0); while (n < 0 && errno == EINTR);
        if (n <= 0) return n < 0 ? -1 : 0;
    }
    /* Zero-size special files can still supply bytes (e.g. procfs). Reading
       them into the same owned spool also catches directory/read errors. */
    if (end < 0 || !S_ISREG (st.st_mode) || !end) {
        if (end >= 0 && lseek (fd, 0, SEEK_SET) < 0) return -1;
        spool = tac_spool (fd);
        if (spool < 0) return -1;
        fd = spool;
        end = lseek (fd, 0, SEEK_END);
        if (end < 0) { int error = errno; close (fd); errno = error; return -1; }
    }
    tac_input in = { .fd = fd, .end = end };
    int rc;
    switch (job->mode) {
    case TAC_ATOM:
        rc = tac_regex_atom (&in, &job->atom, job->before, out);
        free (in.data);
        break;
    case TAC_ENGINE:
        /* The engine's caches hold bytes of the previous descriptor. */
        job->engine.block_used = job->engine.fblock_used = 0;
        rc = tac_regex_windows (&in, &job->read_size, job->before, out,
                                tac_engine_search, &job->engine);
        in.data = NULL;         /* Borrowed engine block. */
        break;
#ifdef __GLIBC__
    case TAC_GNU:
        job->gnu.loaded = 0;
        rc = tac_regex_windows (&in, &job->read_size, job->before, out,
                                tac_gnu_search, &job->gnu);
        break;
#endif
    default:
        rc = tac_literal (&in, job->sep, job->before, &job->read_size, out);
        free (in.data);
    }
    int error = errno;
    if (spool >= 0 && close (spool) < 0 && !rc) return -1;
    errno = error;
    return rc;
}

static void
tac_help (void)
{
    puts ("Concatenate and print files in reverse (last record first).");
    puts ("");
    puts ("    tac [OPTION]... [FILE]...");
    puts ("");
    puts ("    -b, --before          attach the separator before each record");
    puts ("    -r, --regex           the separator is a GNU Emacs regex");
    puts ("    -s, --separator=SEP   record separator (default newline)");
    puts ("    -h, --help / -V, --version");
}

static const struct { const char *name; int arg, id; } tac_longopts[] = {
    { "before", 0, 'b' }, { "regex", 0, 'r' }, { "separator", 1, 's' },
    { "help", 0, 'h' }, { "version", 0, 'V' }, { NULL, 0, 0 }
};

#ifdef __GLIBC__
/* glibc compiles X+ by copying X and then mis-evaluates anchors in the
   copy. That copy is where set_regs fails to finish when X can match empty
   and contains \` ^ \< or \>. Those nullable pluses are spelled XX*.
   \' \b and \B finish on the original pattern, and XX* can disagree, so
   they are not rewritten. A nullable '+' that contains both is refused:
   the original may not return, and the spelling can disagree when it does.
   A '+' of \` ^ \< \> is left as written unless it is nullable and one
   alternative is empty: GNU finishes the other shapes and can disagree
   with XX*. Duplicating a group renumbers captures,
   so a back-reference keeps the original pattern. Returns 1 and a malloc'd
   pattern, 0 to keep the original, or -1 when a rewrite cannot be finished. */
#define TAC_SPELL_MAX (1 << 20)
#define TAC_SPELL_DEPTH 2000

typedef struct {
    char *buf;
    size_t len, cap;
    int changed, backref, failed, depth;
} tac_spell;

typedef struct {
    int nullable, anchor, atom;
    unsigned marks;
    int pure, has_pure;         /* pure: empty, no anchor, no bytes. */
} tac_spell_piece;

static int spell_expr (tac_spell *, tac_parser *, tac_token *, int, tac_spell_piece *);
static int spell_branch (tac_spell *, tac_parser *, tac_token *, int, tac_spell_piece *);
static int spell_alts (tac_spell *, tac_parser *, tac_token *, int, tac_spell_piece *);

static int
spell_reserve (tac_spell *sp, size_t more)
{
    if (sp->failed) return -1;
    if (more > TAC_SPELL_MAX || sp->len > TAC_SPELL_MAX - more) {
        sp->failed = 1;
        return -1;
    }
    if (sp->len + more <= sp->cap) return 0;
    size_t cap = sp->cap ? sp->cap : 64;
    while (cap < sp->len + more) {
        if (cap > TAC_SPELL_MAX / 2) { cap = TAC_SPELL_MAX; break; }
        cap *= 2;
    }
    if (cap < sp->len + more) { sp->failed = 1; return -1; }
    char *buf = realloc (sp->buf, cap);
    if (!buf) { sp->failed = 1; return -1; }
    sp->buf = buf;
    sp->cap = cap;
    return 0;
}

static int
spell_put (tac_spell *sp, const void *bytes, size_t n)
{
    if (spell_reserve (sp, n)) return -1;
    if (n) memcpy (sp->buf + sp->len, bytes, n);
    sp->len += n;
    return 0;
}

static int
spell_emit_token (tac_spell *sp, const tac_parser *ps, const tac_token *t)
{
    if (!t->len || ps->pos < t->len) { sp->failed = 1; return -1; }
    return spell_put (sp, ps->s + (ps->pos - t->len), t->len);
}

/* A previous rewrite left a concatenation. A following quantifier must
   bind to all of it, not to the trailing '*'. */
static int
spell_wrap (tac_spell *sp, size_t start)
{
    size_t len = sp->len - start;
    if (spell_reserve (sp, 4)) return -1;
    memmove (sp->buf + start + 2, sp->buf + start, len);
    sp->buf[start] = '\\';
    sp->buf[start + 1] = '(';
    sp->buf[start + 2 + len] = '\\';
    sp->buf[start + 3 + len] = ')';
    sp->len += 4;
    return 0;
}

static int
spell_dup (tac_spell *sp, size_t start)
{
    size_t len = sp->len - start;
    if (spell_reserve (sp, len)) return -1;
    if (len) memcpy (sp->buf + sp->len, sp->buf + start, len);
    sp->len += len;
    return 0;
}

static void
spell_fetch (tac_parser *ps, tac_token *t, int caret)
{
    tac_peek (ps, t, caret);
    if (t->type != TK_END && !t->len) t->len = 1;
    ps->pos += t->len;
}

/* Copy a bracket glibc has already accepted. '^', '*', '+' and anchors
   inside it are literals. '[.' and '[=' run to their closers; '---' is
   three literal minuses, which is the case the bounded matcher declines. */
static int
spell_bracket (tac_spell *sp, tac_parser *ps, tac_token *t)
{
    if (spell_emit_token (sp, ps, t)) return -1;
    const unsigned char *s = ps->s;
    size_t n = ps->len, i = ps->pos;
    if (i < n && s[i] == '^') i++;
    if (i < n && s[i] == ']') i++;
    while (i < n && s[i] != ']') {
        if (s[i] == '[' && i + 1 < n && (s[i + 1] == '.' || s[i + 1] == '=')) {
            unsigned char kind = s[i + 1];
            i += 2;
            while (i + 1 < n && !(s[i] == kind && s[i + 1] == ']')) i++;
            if (i + 1 >= n) { sp->failed = 1; return -1; }
            i += 2;
            continue;
        }
        if (s[i] == '-' && i + 2 < n && s[i + 1] == '-' && s[i + 2] == '-') {
            i += 3;
            continue;
        }
        i++;
    }
    if (i >= n || s[i] != ']') { sp->failed = 1; return -1; }
    i++;
    if (spell_put (sp, s + ps->pos, i - ps->pos)) return -1;
    ps->pos = i;
    spell_fetch (ps, t, 0);
    return 0;
}

static int
spell_expr (tac_spell *sp, tac_parser *ps, tac_token *t, int nest, tac_spell_piece *out)
{
    if (++sp->depth > TAC_SPELL_DEPTH) { sp->failed = 1; return -1; }
    size_t start = sp->len;
    int nullable = 0, anchor = 0, atom = 1, early = 0;
    int pure = 0, has_pure = 0;
    unsigned marks = 0;
    if (t->type == TK_ALT || t->type == TK_END) {
        nullable = 1;
        pure = 1;
        has_pure = 1;
        early = 1;
    } else if (t->type == TK_CLOSE || t->type == TK_BACKSLASH) {
        sp->failed = 1;
    } else if (t->type == TK_ANCHOR) {
        unsigned short kind = t->anchor;
        if (!spell_emit_token (sp, ps, t)) spell_fetch (ps, t, 0);
        nullable = 1;
        anchor = 1;
        marks = tac_anchor_class (kind);
        early = 1;              /* A following '*+?' is a literal atom. */
    } else if (t->type == TK_BRACKET) {
        if (spell_bracket (sp, ps, t)) sp->failed = 1;
    } else if (t->type == TK_OPEN) {
        if (!spell_emit_token (sp, ps, t)) {
            spell_fetch (ps, t, 1);
            tac_spell_piece inner = { 1, 0, 1, 0, 1, 1 };
            if (t->type != TK_CLOSE && spell_alts (sp, ps, t, nest + 1, &inner))
                sp->failed = 1;
            else if (t->type != TK_CLOSE)
                sp->failed = 1;
            else if (!spell_emit_token (sp, ps, t))
                spell_fetch (ps, t, 0);
            nullable = inner.nullable;
            anchor = inner.anchor;
            marks = inner.marks;
            pure = inner.pure;
            has_pure = inner.has_pure;
        }
    } else {
        if (t->type == TK_BACKREF) sp->backref = 1;
        if (!spell_emit_token (sp, ps, t)) spell_fetch (ps, t, 0);
    }
    if (!early && !sp->failed) {
        while (t->type == TK_STAR || t->type == TK_PLUS || t->type == TK_QUESTION) {
            int op = t->type;
            if (!atom) {
                if (spell_wrap (sp, start)) break;
                atom = 1;
            }
            if (op == TK_PLUS && anchor) {
                int diff = (marks & TM_DIFF) != 0;
                int hang = (marks & TM_HANG) != 0;
                if (nullable && diff && hang) {
                    /* The original can fail to return, and XX* can disagree. */
                    sp->failed = 1;
                    break;
                }
                if ((nullable && hang && !diff && has_pure) || (!diff && !hang)) {
                    /* A nullable \` ^ \< \> beside a pure empty alternative,
                       or a '$' plus: XX* is what returns. Nullable iff X is. */
                    if (spell_dup (sp, start) || spell_put (sp, "*", 1)) break;
                    sp->changed = 1;
                    atom = 0;
                } else {
                    /* GNU finishes this '+'. Keep it so the search sees it. */
                    char ch = '+';
                    if (spell_put (sp, &ch, 1)) break;
                    atom = 1;
                }
            } else {
                char ch = op == TK_STAR ? '*' : op == TK_PLUS ? '+' : '?';
                if (spell_put (sp, &ch, 1)) break;
                if (op != TK_PLUS) nullable = 1;
                atom = 1;
            }
            spell_fetch (ps, t, 0);
        }
    }
    sp->depth--;
    out->nullable = nullable;
    out->anchor = anchor;
    out->atom = atom;
    out->marks = marks;
    out->pure = pure;
    out->has_pure = has_pure;
    return sp->failed ? -1 : 0;
}

static int
spell_branch (tac_spell *sp, tac_parser *ps, tac_token *t, int nest, tac_spell_piece *out)
{
    tac_spell_piece part;
    if (spell_expr (sp, ps, t, nest, &part)) return -1;
    int nullable = part.nullable, anchor = part.anchor, count = 1;
    int pure = part.pure, has_pure = part.has_pure;
    unsigned marks = part.marks;
    while (!sp->failed && t->type != TK_ALT && t->type != TK_END
           && !(nest && t->type == TK_CLOSE)) {
        if (spell_expr (sp, ps, t, nest, &part)) return -1;
        nullable = nullable && part.nullable;
        anchor = anchor || part.anchor;
        pure = pure && part.pure;
        has_pure = has_pure || part.has_pure;
        marks |= part.marks;
        count++;
    }
    out->nullable = nullable;
    out->anchor = anchor;
    out->atom = count == 1;
    out->marks = marks;
    out->pure = pure;
    out->has_pure = has_pure;
    return sp->failed ? -1 : 0;
}

static int
spell_alts (tac_spell *sp, tac_parser *ps, tac_token *t, int nest, tac_spell_piece *out)
{
    if (spell_branch (sp, ps, t, nest, out)) return -1;
    while (!sp->failed && t->type == TK_ALT) {
        if (spell_emit_token (sp, ps, t)) return -1;
        spell_fetch (ps, t, 1);
        tac_spell_piece right = { 1, 0, 1, 0, 1, 1 };
        if (t->type != TK_ALT && t->type != TK_END && !(nest && t->type == TK_CLOSE)) {
            if (spell_branch (sp, ps, t, nest, &right)) return -1;
        }
        {
            int left_pure = out->pure, right_pure = right.pure;
            out->nullable = out->nullable || right.nullable;
            out->anchor = out->anchor || right.anchor;
            out->marks |= right.marks;
            /* Pure only when neither side can match a byte. has_pure when
               either side is the empty alternative, or contains one. */
            out->pure = left_pure && right_pure;
            out->has_pure = out->has_pure || right.has_pure || left_pure || right_pure;
            out->atom = 0;
        }
    }
    return sp->failed ? -1 : 0;
}

/* True when a parse we could not finish might still be the looping shape.
   A false positive refuses the separator; a search is not attempted. */
static int
spell_might_loop (const char *s)
{
    int plus = 0, anchor = 0;
    for (const unsigned char *p = (const unsigned char *) s; *p; p++) {
        if (*p == '+' || *p == '^' || *p == '$') {
            if (*p == '+') plus = 1;
            else anchor = 1;
        } else if (*p == '\\' && p[1]) {
            if (strchr ("`'<bB>", p[1])) anchor = 1;
            p++;
        }
    }
    return plus && anchor;
}

static int
tac_spell_anchor_plus (const char *pattern, char **out)
{
    *out = NULL;
    tac_spell sp;
    memset (&sp, 0, sizeof sp);
    tac_parser ps;
    memset (&ps, 0, sizeof ps);
    ps.s = (const unsigned char *) pattern;
    ps.len = strlen (pattern);
    if (MB_CUR_MAX > 1) {
        const char *codeset = nl_langinfo (CODESET);
        if (codeset && !strcmp (codeset, "UTF-8")) ps.utf8 = 1;
    }
    tac_token t;
    spell_fetch (&ps, &t, 1);
    tac_spell_piece piece;
    int rc = spell_alts (&sp, &ps, &t, 0, &piece);
    int bad = rc < 0 || sp.failed || t.type != TK_END;
    if (bad || !sp.changed || sp.backref) {
        int refuse = !sp.backref && ((bad && sp.changed) || (bad && spell_might_loop (pattern)));
        free (sp.buf);
        return refuse ? -1 : 0;
    }
    if (spell_reserve (&sp, 1)) { free (sp.buf); return -1; }
    sp.buf[sp.len] = '\0';
    *out = sp.buf;
    return 1;
}
#endif

/* Select the matcher once per invocation. Returns 0 or an exit status. */
static int
tac_prepare (tac_job *job, int regex, regex_t *re)
{
    if (!regex) return 0;
    if (!*job->sep) { builtin_error ("separator cannot be empty"); return EXECUTION_FAILURE; }
#ifdef __GLIBC__
    /* glibc decides validity exactly as GNU tac does. re_syntax_options
       belongs to the process, including Bash's own regex users. */
    re->fastmap = malloc (256);
    if (!re->fastmap) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
    reg_syntax_t saved = re_set_syntax (RE_SYNTAX_EMACS);
    const char *error = re_compile_pattern (job->sep, strlen (job->sep), re);
    re_set_syntax (saved);
    if (error) { builtin_error ("%s", error); return EXECUTION_FAILURE; }
    job->gnu.re = re;
#endif
    if (tac_byte_atom (job->sep, &job->atom)) { job->mode = TAC_ATOM; return 0; }
    int status = tac_engine_compile (&job->engine, job->sep);
    if (status == TE_OK) { job->mode = TAC_ENGINE; return 0; }
    if (status == TE_ESPACE) { builtin_error ("memory exhausted"); return EXECUTION_FAILURE; }
#ifdef __GLIBC__
    /* The original pattern is already compiled. Replace it only when the
       spelling differs, and do not search a '+' the spelling could not
       finish: that is the call that does not return. */
    if (status == TE_UNSUPPORTED) {
        char *spelled = NULL;
        int spell = tac_spell_anchor_plus (job->sep, &spelled);
        if (spell < 0) {
            builtin_error ("this regex separator cannot be matched safely");
            return EXECUTION_FAILURE;
        }
        if (spell > 0) {
            regfree (re);
            memset (re, 0, sizeof *re);
            re->fastmap = malloc (256);
            if (!re->fastmap) {
                free (spelled);
                builtin_error ("out of memory");
                return EXECUTION_FAILURE;
            }
            reg_syntax_t saved = re_set_syntax (RE_SYNTAX_EMACS);
            const char *error = re_compile_pattern (spelled, strlen (spelled), re);
            re_set_syntax (saved);
            free (spelled);
            if (error) { builtin_error ("%s", error); return EXECUTION_FAILURE; }
            job->gnu.re = re;
        }
    }
    job->mode = TAC_GNU;
    return 0;
#else
    if (status == TE_UNSUPPORTED)
        builtin_error ("this regex separator requires the GNU regex API on this build");
    else
        builtin_error ("%s", tac_re_errors[status]);
    return EXECUTION_FAILURE;
#endif
}

int
tac_builtin (WORD_LIST *list)
{
    tac_job job;
    memset (&job, 0, sizeof job);
    job.sep = "\n";
    job.read_size = 8192;
    int regex = 0, end_opts = 0, posix = getenv ("POSIXLY_CORRECT") != NULL;
    /* Collect file operands after parsing options, as GNU getopt permutes. */
    char **files = NULL; int n_files = 0, cap_files = 0;
    int rc = EXECUTION_SUCCESS;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        int id = 0;
        const char *value = NULL;
        if (end_opts || w[0] != '-' || !w[1]) {
            if (n_files == cap_files) {
                int nc = cap_files ? cap_files * 2 : 8;
                char **nf = realloc (files, (size_t) nc * sizeof *files);
                if (!nf) { builtin_error ("out of memory"); free (files); return EXECUTION_FAILURE; }
                files = nf; cap_files = nc;
            }
            files[n_files++] = (char *) w;
            if (posix) end_opts = 1;
            continue;
        }
        if (w[1] == '-') {
            if (!w[2]) { end_opts = 1; continue; }
            const char *name = w + 2, *eq = strchr (name, '=');
            size_t length = eq ? (size_t) (eq - name) : strlen (name);
            int match = -1;
            for (int i = 0; tac_longopts[i].name; i++)
                if (!strncmp (tac_longopts[i].name, name, length)) {
                    match = i;   /* Initial letters differ: prefixes are unique. */
                    break;
                }
            if (match < 0) {
                builtin_error ("unrecognized option '%s'", w);
                builtin_usage (); free (files); return EXECUTION_FAILURE;
            }
            id = tac_longopts[match].id;
            if (tac_longopts[match].arg) {
                if (eq) value = eq + 1;
                else if (p->next) { p = p->next; value = p->word->word; }
                else {
                    builtin_error ("option '--%s' requires an argument", tac_longopts[match].name);
                    builtin_usage (); free (files); return EXECUTION_FAILURE;
                }
            } else if (eq) {
                builtin_error ("option '--%s' doesn't allow an argument", tac_longopts[match].name);
                builtin_usage (); free (files); return EXECUTION_FAILURE;
            }
        }
        /* Short options cluster (-br); -s takes the rest of the word or the
           next word. A long option runs this loop once with its id. */
        for (const char *c = w + 1; id || *c; c++) {
            int option = id ? id : *c;
            if (!id && option == 's') {
                if (c[1]) value = c + 1;
                else if (p->next) { p = p->next; value = p->word->word; }
                else {
                    builtin_error ("option requires an argument -- 's'");
                    builtin_usage (); free (files); return EXECUTION_FAILURE;
                }
            }
            switch (option) {
            case 'b': job.before = 1; break;
            case 'r': regex = 1; break;
            case 's': job.sep = value; break;
            case 'h': tac_help (); free (files); return EXECUTION_SUCCESS;
            case 'V':
                puts ("tac 1.0 (bash-loadable, coreutils-compatible)");
                free (files); return EXECUTION_SUCCESS;
            default:
                builtin_error ("invalid option -- '%c'", option);
                builtin_usage (); free (files); return EXECUTION_FAILURE;
            }
            if (id || option == 's') break;
        }
    }

    regex_t re;
    memset (&re, 0, sizeof re);
    int status = tac_prepare (&job, regex, &re);
    if (!status) {
        bl_output out;
        bl_output_init (&out, stdout);
        /* A closed stdout must be diagnosed before open/mkstemp can reuse fd 1.
           Otherwise a pipe spool opened there would silently receive output. */
        if (!out.error) {
            int flags = fcntl (out.fd, F_GETFL);
            if (flags < 0) out.error = errno;
            else if ((flags & O_ACCMODE) == O_RDONLY) out.error = EBADF;
        }
        for (int i = 0; i < (n_files ? n_files : 1) && !out.error; i++) {
            const char *name = n_files ? files[i] : "-";
            int owned = strcmp (name, "-") != 0;
            int fd = owned ? open (name, O_RDONLY | O_CLOEXEC) : STDIN_FILENO;
            if (fd < 0) { builtin_error ("%s: %s", name, strerror (errno)); rc = EXECUTION_FAILURE; continue; }
            int result = tac_file (fd, &job, &out);
            if (result == -2 || result == -3) {
                /* GNU tac exits here without reading later operands. */
                builtin_error (result == -2 ? "record too large"
                               : "error in regular expression search");
                rc = EXECUTION_FAILURE;
                if (owned) close (fd);
                break;
            }
            if (result < 0) {
                if (!out.error) builtin_error ("%s: %s", name, strerror (errno));
                rc = EXECUTION_FAILURE;
            }
            if (owned && close (fd) < 0) {
                builtin_error ("%s: %s", name, strerror (errno)); rc = EXECUTION_FAILURE;
            }
        }
        bl_output_flush (&out);
        if (out.error) {
            builtin_error ("write error: %s", strerror (out.error));
            rc = EXECUTION_FAILURE;
        }
    } else {
        rc = status;
    }
#ifdef __GLIBC__
    if (regex) {
        regfree (&re);
        free (job.gnu.regs.start); free (job.gnu.regs.end);
        free (job.gnu.data);
    }
#endif
    if (job.mode == TAC_ENGINE) tac_engine_free (&job.engine);
    free (files);
    return rc;
}

char *tac_doc[] = {
    "Concatenate and print files in reverse (last record first).",
    "",
    "    tac [OPTION]... [FILE]...",
    "",
    "Records default to lines. With no FILE (or '-'), read standard input.",
    "",
    "Options:",
    "    -b, --before          attach the separator before each record",
    "    -r, --regex           the separator is a GNU Emacs regex",
    "    -s, --separator=SEP   record separator (default newline)",
    "    -h, --help            show this help",
    "    -V, --version         show version",
    (char *)NULL
};

struct builtin tac_struct = {
    "tac",
    tac_builtin,
    BUILTIN_ENABLED,
    tac_doc,
    "tac [OPTION]... [FILE]...",
    0
};
