/* bashsed.c — POSIX-shape sed(1) as a bash builtin.
 *
 * Phase A of bash-os shell-ergonomics. v1 covers the patterns that
 * 95% of one-liner sed usage needs: substitution (with capture
 * groups), delete/print/quit/=, address ranges, hold buffer,
 * labels/branches, blocks, in-place editing.
 *
 * Commands supported:
 *   [ADDR1[,ADDR2]] s/REGEX/REPLACE/[gipnN]
 *   [ADDR] d                 delete current line
 *   [ADDR] p                 print current line
 *   [ADDR] q                 quit immediately
 *   [ADDR] !COMMAND          apply COMMAND to lines NOT in addr
 *   [ADDR] =                 print line number
 *   [ADDR] h / H             copy/append pattern to hold buffer
 *   [ADDR] g / G             copy/append hold to pattern
 *   [ADDR] x                 swap pattern and hold
 *   [ADDR] a TEXT            append TEXT after current line
 *   [ADDR] i TEXT            insert TEXT before current line
 *   [ADDR] c TEXT            replace addressed range with TEXT
 *   [ADDR] y/SET1/SET2/      transliterate (1:1 byte map; sets same length)
 *   [ADDR] n                 next: print pattern, replace with next line
 *   [ADDR] N                 append next input line to pattern space
 *   [ADDR] D                 delete to first \n in pattern, restart cycle
 *   [ADDR] P                 print to first \n in pattern
 *   [ADDR] l [WIDTH]         print pattern space with escapes
 *   [ADDR] z                 empty the pattern space
 *   [ADDR] e [COMMAND]       run pattern space / COMMAND (gated, see below)
 *   v [VERSION]              require GNU sed 4.9 compatibility level
 *   [ADDR] :LABEL            label
 *   [ADDR] b LABEL           unconditional branch
 *   [ADDR] t LABEL           branch if last s/// matched
 *   [ADDR] {COMMANDS}        block grouping
 *
 * Addresses:
 *   $          last line
 *   N          line number
 *   /REGEX/    regex match (also \cREGEXc with any delimiter c)
 *   ADDR1,ADDR2  range
 *
 * Replace string supports & (whole match) and \1..\9 (capture groups).
 *
 * Flags:
 *   -i [SUFFIX]   in-place edit; SUFFIX (if non-empty) saves backup
 *   -e SCRIPT     append SCRIPT (multiple allowed; semicolon-joined)
 *   -f FILE       read commands from FILE
 *   -E / -r       extended regex (default is BRE)
 *   -s            separate input files (also implied by -i)
 *   -n            suppress default print
 *   -u            unbuffered output
 *   -l WIDTH      default l-command width (zero disables wrapping)
 *   -z            NUL-separated records (--null-data)
 *   -b            accepted for GNU compatibility (no text mode on POSIX)
 *   --sandbox     reject e, r, R, w and W commands
 *   --follow-symlinks  -i edits, and F names, the final symlink target
 *   --posix and --debug are not implemented and are rejected.
 *
 * Security: e / s///e shell execution is disabled unless
 * BASHSED_ALLOW_EXEC=1 is set.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#if defined (__GLIBC__) && !defined (BASHSED_PORTABLE_REGEX)
# include <regex.h>
#else
# include "sed-regex.h"
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <termios.h>
#if defined (__linux__)
# include <sys/syscall.h>
#endif

#include "loadables.h"
#include "quit.h"
#include "trap.h"

/* Address kinds. */
typedef enum { BS_ADDR_NONE, BS_ADDR_LINE, BS_ADDR_LAST, BS_ADDR_REGEX,
               BS_ADDR_STEP,
               BS_ADDR_PLUS,   /* addr2 only: ,+N  -> end = start + N */
               BS_ADDR_MULT    /* addr2 only: ,~N  -> end = next multiple of N after start */
             } bs_addrkind;

typedef struct bs_prog bs_prog;

typedef struct {
    bs_addrkind kind;
    long        line;        /* for ADDR_LINE; "first" for ADDR_STEP */
    long        step;        /* for ADDR_STEP (GNU first~step) */
    regex_t     re;          /* for ADDR_REGEX */
    bs_prog    *prog;        /* bounded matcher; kept off glibc set_regs */
    int         re_ok;
} bs_addr;

/* Command kinds. */
typedef enum {
    BS_S, BS_D, BS_P, BS_Q, BS_BIGQ, BS_EQ,
    BS_H, BS_HUP, BS_G, BS_GUP, BS_X,
    BS_LABEL, BS_B, BS_T, BS_BIGT,   /* BS_BIGT = T: branch if NO s/// matched */
    BS_BLOCK_OPEN, BS_BLOCK_CLOSE,
    BS_A, BS_I, BS_C,    /* append / insert / change text */
    BS_R,                /* r FILE: append the file's contents after the line */
    BS_W,                /* w FILE: write the pattern space to a file */
    BS_BIGW,             /* W FILE: write only the first line of pattern space */
    BS_BIGR,             /* R FILE: read one line per cycle from a file */
    BS_F,                /* F: print the current input filename */
    BS_E,                /* e: execute pattern space via /bin/sh -c */
    BS_Y,                 /* y/SET1/SET2/ transliterate */
    BS_N_CMD, BS_NUP_CMD, /* n / N: refill or append next input line */
    BS_D_LO, BS_P_LO,     /* D / P: head-line delete / print (multi-line ops) */
    BS_L_CMD,             /* l: print pattern with escapes */
    BS_Z                  /* z: empty the pattern space */
} bs_cmdkind;

typedef struct {
    bs_cmdkind kind;
    bs_addr    addr1;        /* optional */
    bs_addr    addr2;        /* optional (range) */
    int        has_a1, has_a2;
    int        negate;       /* ! prefix */
    /* s/// */
    regex_t    s_re;
    bs_prog   *s_prog;
    int        s_re_ok;
    char      *s_literal;    /* nonempty ASCII regex without operators */
    size_t     s_literal_len, s_repl_len;
    int        s_repl_literal;
    int        s_needed_sub;
    int        s_empty_re;   /* s//repl/ : reuse the last regex at runtime */
    char      *s_repl;       /* replacement, may contain & and \1..\9 */
    int        s_global;     /* g flag */
    int        s_print;      /* p flag */
    int        s_n;          /* N flag (substitute Nth match — simplified) */
    int        s_icase;      /* i flag */
    int        s_multiline;  /* m/M flag: ^/$ match at embedded newlines */
    int        s_exec;       /* e flag: execute resulting pattern space */
    long       l_width;     /* -1 uses the invocation default */
    int        q_code;       /* q/Q exit code (default 0) */
    char      *s_wfile;      /* s///w FILE : write substituted line to FILE */
    /* labels / branches */
    char      *label;
    int        target_idx;   /* resolved during second pass; -1 if unresolved */
    /* block grouping */
    int        block_close_idx;
    /* a/i/c text */
    char      *text;
    /* y/SET1/SET2/ — 256-byte translation table; y_active=1 if populated. */
    unsigned char y_table[256];
    int        y_active;
} bs_cmd;

typedef struct {
    char  *str;
    size_t len;
    size_t cap;
    int    failed;   /* once set, all further ops become no-ops */
} bs_string;

static int bs_runtime_error;
static long bs_list_width;
/* Record separator: newline, or NUL with -z. GNU also uses it to join
   N/G/H, split P/D/W, and end =, l, i, c and F output; a text stays
   newline-terminated. */
static char bs_delim = '\n';
static int bs_io_error;
static int bs_unbuffered;
static int bs_sandbox;          /* --sandbox: reject e, r, R, w, W at parse time */
static int bs_follow_symlinks;  /* --follow-symlinks: edit and name link targets */
static int bs_interrupt_signal;

static int
bs_interrupted (void)
{
    if (terminating_signal) bs_interrupt_signal = terminating_signal;
    else if (interrupt_state) bs_interrupt_signal = SIGINT;
    /* Noninteractive Bash can queue a trap without setting interrupt_state.
       Defer running it until all invocation-owned resources are released. */
    else if (*(volatile int *) &trapped_signal_received) {
        const int signals[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT };
        for (size_t i = 0; i < sizeof signals / sizeof *signals; i++)
            if (signal_is_pending (signals[i])) { bs_interrupt_signal = signals[i]; break; }
    }
    return bs_interrupt_signal != 0;
}

/* A repeated group that can match empty makes glibc set_regs loop when
   re_search is called with registers (nmatch > 1) and one alternative is an
   anchor (^, \`, \<, \>) followed by a consumer. The global-substitute retry
   is that call. A single capturing group of anchors, literals and the GNU
   classes \s \S \w \W is matched here, so that call is never made. \b and \B
   are not anchors for this test: re_search returns, and this matcher does
   not reproduce its spans. The same shape with a consumer this matcher
   cannot reproduce, and every nested or prefixed form of it, is compiled
   and marked unsafe. A substitution searches an unsafe pattern with one
   register. No match cannot enter set_regs. A one-register hit is refused:
   filling the other registers does not return on subjects such as ab, and
   that span is not the substitution. An address passes no registers and
   runs. \' is not one of those anchors. One table,
   filled after the command array stops moving, lets an empty s// reuse the
   program stored for the last regex. */
#define BS_ATOM_LIT    0
#define BS_ATOM_BOL    1
#define BS_ATOM_EOL    2
#define BS_ATOM_BOS    3
#define BS_ATOM_EOS    4
#define BS_ATOM_WSTART 5
#define BS_ATOM_WEND   6
#define BS_ATOM_WB     7
#define BS_ATOM_WNB    8
#define BS_ATOM_SPACE  9   /* \s */
#define BS_ATOM_NSPACE 10  /* \S */
#define BS_ATOM_WORD   11  /* \w */
#define BS_ATOM_NWORD  12  /* \W */
#define BS_MAX_ATOMS   24
#define BS_MAX_ALTS    12
#define BS_PROG_MAX    64

struct bs_prog {
    struct { unsigned char kind, lit; } atoms[BS_MAX_ALTS][BS_MAX_ATOMS];
    unsigned char natoms[BS_MAX_ALTS];
    int nalts, qmin, qmax, icase, newline, word;
};

static struct { const regex_t *re; bs_prog *prog; } bs_prog_map[BS_PROG_MAX];
static int bs_prog_n, bs_prog_made;
/* Patterns whose register fill may not return. Searched with one register. */
static const regex_t *bs_unsafe_re[BS_PROG_MAX];
static int bs_unsafe_n;

static void
bs_unsafe_note (const regex_t *re)
{
    if (bs_unsafe_n < BS_PROG_MAX) bs_unsafe_re[bs_unsafe_n++] = re;
}

static int
bs_unsafe_p (const regex_t *re)
{
    for (int i = 0; i < bs_unsafe_n; i++)
        if (bs_unsafe_re[i] == re) return 1;
    return 0;
}

static void
bs_prog_bind (bs_cmd *cmds, int n)
{
    bs_prog_n = 0;
    for (int i = 0; i < n; i++) {
        bs_cmd *c = &cmds[i];
        if (c->addr1.prog && bs_prog_n < BS_PROG_MAX)
            bs_prog_map[bs_prog_n++] = (typeof (bs_prog_map[0])) { &c->addr1.re, c->addr1.prog };
        if (c->addr2.prog && bs_prog_n < BS_PROG_MAX)
            bs_prog_map[bs_prog_n++] = (typeof (bs_prog_map[0])) { &c->addr2.re, c->addr2.prog };
        if (c->s_prog && bs_prog_n < BS_PROG_MAX)
            bs_prog_map[bs_prog_n++] = (typeof (bs_prog_map[0])) { &c->s_re, c->s_prog };
    }
}

static bs_prog *
bs_prog_lookup (const regex_t *re)
{
    for (int i = 0; i < bs_prog_n; i++)
        if (bs_prog_map[i].re == re) return bs_prog_map[i].prog;
    return NULL;
}

typedef struct {
    const char *s;
    size_t n, i;
    int ext, dangerous, bad, record, simple, word, hang;
    bs_prog prog;
} bs_re_scan;

static int bs_re_end (const bs_re_scan *sc)
{
    return sc->i >= sc->n;
}
static int bs_re_alt (const bs_re_scan *sc)
{
    if (bs_re_end (sc)) return 0;
    if (sc->ext) return sc->s[sc->i] == '|';
    return sc->s[sc->i] == '\\' && sc->i + 1 < sc->n && sc->s[sc->i + 1] == '|';
}
static int bs_re_group_end (const bs_re_scan *sc)
{
    if (bs_re_end (sc)) return 0;
    if (sc->ext) return sc->s[sc->i] == ')';
    return sc->s[sc->i] == '\\' && sc->i + 1 < sc->n && sc->s[sc->i + 1] == ')';
}

/* Bracket expression in a length-bounded pattern. 0 closes, -1 runs off the end. */
static int
bs_re_skip_class (bs_re_scan *sc)
{
    size_t i = sc->i + 1;
    if (i < sc->n && sc->s[i] == '^') i++;
    int first = 1, state = 0;
    char marker = 0;
    for (;;) {
        if (i >= sc->n) return -1;
        unsigned char c = (unsigned char) sc->s[i];
        if (state == 0) {
            if (c == ']' && !first) { sc->i = i + 1; return 0; }
            if (c == '[') state = 1;
            first = 0; i++;
        } else if (state == 1) {
            if (c == ':' || c == '.' || c == '=') { marker = (char) c; state = 2; i++; }
            else if (c == ']') { sc->i = i + 1; return 0; }
            else { state = 0; i++; }
        } else if (state == 2) {
            if (c == (unsigned char) marker) state = 3;
            i++;
        } else if (c == ']') { state = 0; i++; }
        else if (c == (unsigned char) marker) i++;
        else { state = 2; i++; }
    }
}

static int
bs_re_quant (bs_re_scan *sc, int *qmin, int *qmax)
{
    *qmin = 1; *qmax = 1;
    if (bs_re_end (sc)) return 0;
    size_t save = sc->i;
    int bre_brace = 0;
    char c = sc->s[sc->i];
    if (!sc->ext && c == '\\' && sc->i + 1 < sc->n) {
        char e = sc->s[sc->i + 1];
        if (e == '+') { *qmin = 1; *qmax = -1; sc->i += 2; return 1; }
        if (e == '?') { *qmin = 0; *qmax = 1; sc->i += 2; return 1; }
        if (e == '{') { bre_brace = 1; sc->i += 2; }
        else return 0;
    } else if (sc->ext && c == '*') { *qmin = 0; *qmax = -1; sc->i++; return 1; }
    else if (sc->ext && c == '+') { *qmin = 1; *qmax = -1; sc->i++; return 1; }
    else if (sc->ext && c == '?') { *qmin = 0; *qmax = 1; sc->i++; return 1; }
    else if (sc->ext && c == '{') sc->i++;
    else if (!sc->ext && c == '*') { *qmin = 0; *qmax = -1; sc->i++; return 1; }
    else return 0;
    if (sc->i >= sc->n || !isdigit ((unsigned char) sc->s[sc->i])) {
        sc->i = save; return 0;
    }
    int lo = 0, hi = 0, any = 0;
    while (sc->i < sc->n && isdigit ((unsigned char) sc->s[sc->i])) {
        lo = lo * 10 + (sc->s[sc->i++] - '0');
        if (lo > 1000000) { sc->bad = 1; return 0; }
    }
    hi = lo;
    if (sc->i < sc->n && sc->s[sc->i] == ',') {
        sc->i++;
        if (sc->i < sc->n && isdigit ((unsigned char) sc->s[sc->i])) {
            hi = 0;
            while (sc->i < sc->n && isdigit ((unsigned char) sc->s[sc->i])) {
                hi = hi * 10 + (sc->s[sc->i++] - '0');
                if (hi > 1000000) { sc->bad = 1; return 0; }
            }
        } else { hi = -1; any = 1; }
    }
    int closed = 0;
    if (bre_brace) {
        if (sc->i + 1 < sc->n && sc->s[sc->i] == '\\' && sc->s[sc->i + 1] == '}') {
            sc->i += 2; closed = 1;
        }
    } else if (sc->i < sc->n && sc->s[sc->i] == '}') { sc->i++; closed = 1; }
    if (!closed || (hi >= 0 && hi < lo)) { sc->i = save; sc->bad = 1; return 0; }
    *qmin = lo; *qmax = any ? -1 : hi;
    (void) any;
    return 1;
}

typedef struct {
    int nullable, anchor;
    int hang;         /* hang-anchor followed by a consumer, or a nested one */
    int hang_anchor;  /* ^, \`, \< or \> */
    int consumed;     /* this atom can consume a byte */
} bs_re_info;

static bs_re_info bs_re_expr (bs_re_scan *sc);

static int
bs_re_push (bs_re_scan *sc, int alt, int kind, unsigned char lit)
{
    if (!sc->record) return 0;
    if (alt >= BS_MAX_ALTS || sc->prog.natoms[alt] >= BS_MAX_ATOMS) {
        sc->simple = 0; return -1;
    }
    int k = sc->prog.natoms[alt]++;
    sc->prog.atoms[alt][k].kind = (unsigned char) kind;
    sc->prog.atoms[alt][k].lit = lit;
    return 0;
}

static int
bs_re_hang_group (bs_re_scan *sc, bs_re_info *info, bs_re_info inner)
{
    int qmin, qmax, present = bs_re_quant (sc, &qmin, &qmax);
    int repeating = present && (qmax < 0 || qmax > 1);
    if (repeating && inner.nullable && inner.anchor) sc->dangerous = 1;
    if (repeating && inner.nullable && inner.hang) sc->hang = 1;
    info->anchor = inner.anchor;
    info->hang = inner.hang;
    info->nullable = qmin == 0 || inner.nullable;
    info->consumed = 1;
    return 0;
}

static bs_re_info
bs_re_atom (bs_re_scan *sc, int alt, int first)
{
    bs_re_info info = { 0, 0 };
    if (bs_re_end (sc) || bs_re_alt (sc) || bs_re_group_end (sc)) {
        info.nullable = 1; return info;
    }
    unsigned char c = (unsigned char) sc->s[sc->i];
    if (c == '[') {
        if (bs_re_skip_class (sc) < 0) sc->bad = 1;
        sc->simple = 0;
        info.consumed = 1;
    } else if (c == '(' && sc->ext) {
        sc->i++;
        int rec = sc->record, simple = sc->simple;
        sc->record = 0;
        bs_re_info inner = bs_re_expr (sc);
        sc->record = rec; sc->simple = simple ? sc->simple : 0;
        if (!bs_re_group_end (sc)) { sc->bad = 1; return info; }
        sc->i++;
        sc->simple = 0;
        bs_re_hang_group (sc, &info, inner);
        return info;
    } else if (!sc->ext && c == '\\' && sc->i + 1 < sc->n && sc->s[sc->i + 1] == '(') {
        sc->i += 2;
        int rec = sc->record, simple = sc->simple;
        sc->record = 0;
        bs_re_info inner = bs_re_expr (sc);
        sc->record = rec;
        if (!bs_re_group_end (sc)) { sc->bad = 1; return info; }
        sc->i += 2;
        sc->simple = 0;
        (void) simple;
        bs_re_hang_group (sc, &info, inner);
        return info;
    } else if (c == '\\' && sc->i + 1 < sc->n) {
        char e = sc->s[sc->i + 1];
        if (e == '\'') {
            /* \' is an end anchor in the regex engine. It does not make
               set_regs loop, and matching it as a literal is wrong. */
            sc->i += 2;
            sc->simple = 0;
        } else if (e == 's' || e == 'S' || e == 'w' || e == 'W') {
            int ck = e == 's' ? BS_ATOM_SPACE : e == 'S' ? BS_ATOM_NSPACE
                   : e == 'w' ? BS_ATOM_WORD : BS_ATOM_NWORD;
            sc->i += 2;
            sc->word = 1; /* multibyte class width is not guessed here */
            info.consumed = 1;
            bs_re_push (sc, alt, ck, 0);
        } else if (e >= '1' && e <= '9') {
            sc->i += 2; sc->simple = 0; info.nullable = 1; info.consumed = 1;
        } else if (e == '`' || e == '<' || e == '>' || e == 'b' || e == 'B') {
            int kind = e == '`' ? BS_ATOM_BOS : e == '<' ? BS_ATOM_WSTART
                     : e == '>' ? BS_ATOM_WEND : e == 'b' ? BS_ATOM_WB : BS_ATOM_WNB;
            sc->i += 2; info.nullable = 1;
            /* \b and \B return from re_search. Marking them as anchors would
               direct-match the group, and that span is not glibc's. */
            if (kind != BS_ATOM_WB && kind != BS_ATOM_WNB) info.anchor = 1;
            if (kind == BS_ATOM_BOS || kind == BS_ATOM_WSTART || kind == BS_ATOM_WEND)
                info.hang_anchor = 1;
            if (kind >= BS_ATOM_WSTART) sc->word = 1;
            bs_re_push (sc, alt, kind, 0);
        } else {
            sc->i += 2; info.consumed = 1;
            bs_re_push (sc, alt, BS_ATOM_LIT, (unsigned char) e);
        }
    } else if (c == '\\') { sc->bad = 1; return info; }
    else if (c == '^' && first) {
        sc->i++; info.nullable = 1; info.anchor = 1; info.hang_anchor = 1;
        bs_re_push (sc, alt, BS_ATOM_BOL, 0);
    } else if (c == '$') {
        bs_re_scan look = *sc; look.i++;
        if (bs_re_end (&look) || bs_re_alt (&look) || bs_re_group_end (&look)) {
            sc->i++; info.nullable = 1; info.anchor = 1;
            bs_re_push (sc, alt, BS_ATOM_EOL, 0);
        } else { sc->i++; info.consumed = 1; bs_re_push (sc, alt, BS_ATOM_LIT, '$'); }
    } else if (c == '.' ) { sc->i++; sc->simple = 0; info.consumed = 1; }
    else if (c == '*' || (sc->ext && (c == '+' || c == '?' || c == '{'))) {
        sc->i++; info.consumed = 1; bs_re_push (sc, alt, BS_ATOM_LIT, c);
    } else {
        sc->i++; info.consumed = 1; bs_re_push (sc, alt, BS_ATOM_LIT, c);
    }
    int qmin, qmax;
    if (bs_re_quant (sc, &qmin, &qmax)) {
        sc->simple = 0;
        if (qmin == 0) info.nullable = 1;
    }
    return info;
}

static bs_re_info
bs_re_branch (bs_re_scan *sc, int alt)
{
    bs_re_info info = { 1, 0 };
    int first = 1, any = 0, seen_hang = 0;
    if (sc->record) sc->prog.natoms[alt] = 0;
    while (!bs_re_end (sc) && !bs_re_alt (sc) && !bs_re_group_end (sc) && !sc->bad) {
        bs_re_info atom = bs_re_atom (sc, alt, first);
        if (bs_re_end (sc) && !any && atom.nullable && !atom.anchor && first) break;
        any = 1; first = 0;
        info.nullable = info.nullable && atom.nullable;
        info.anchor = info.anchor || atom.anchor;
        if (atom.hang || (seen_hang && atom.consumed)) info.hang = 1;
        if (atom.hang_anchor) seen_hang = 1;
        if (sc->bad) break;
        /* An empty atom result at a delimiter means the branch ended. */
        if (bs_re_end (sc) || bs_re_alt (sc) || bs_re_group_end (sc)) break;
    }
    return info;
}

static bs_re_info
bs_re_expr (bs_re_scan *sc)
{
    int alt = 0;
    bs_re_info info = bs_re_branch (sc, alt);
    while (bs_re_alt (sc) && !sc->bad) {
        sc->i += sc->ext ? 1 : 2;
        alt++;
        if (sc->record && alt >= BS_MAX_ALTS) sc->simple = 0;
        bs_re_info more = bs_re_branch (sc, alt < BS_MAX_ALTS ? alt : 0);
        info.nullable = info.nullable || more.nullable;
        info.anchor = info.anchor || more.anchor;
        info.hang = info.hang || more.hang;
    }
    if (sc->record) sc->prog.nalts = sc->simple ? alt + 1 : 0;
    return info;
}

/* 1: *out is a bounded program. 0: the engine can run it. -1: refuse. */
static int
bs_regex_guard (const char *pat, size_t len, int flags, bs_prog **out)
{
    *out = NULL;
    bs_re_scan sc;
    memset (&sc, 0, sizeof sc);
    sc.s = pat; sc.n = len; sc.ext = (flags & REG_EXTENDED) != 0; sc.simple = 1;
    int whole = 0;
    if ((sc.ext && len && pat[0] == '(') ||
        (!sc.ext && len > 1 && pat[0] == '\\' && pat[1] == '(')) {
        sc.record = 1;
        sc.i = sc.ext ? 1 : 2;
        bs_re_info inner = bs_re_expr (&sc);
        int closed = bs_re_group_end (&sc);
        if (closed) sc.i += sc.ext ? 1 : 2;
        int qmin = 1, qmax = 1, present = 0;
        if (closed && !sc.bad) present = bs_re_quant (&sc, &qmin, &qmax);
        int repeating = present && (qmax < 0 || qmax > 1);
        if (closed && sc.i == len && !sc.bad) {
            whole = 1;
            if (repeating && inner.nullable && inner.anchor) sc.dangerous = 1;
            if (repeating && inner.nullable && inner.hang) sc.hang = 1;
            if (sc.dangerous && sc.simple) {
                sc.prog.qmin = qmin; sc.prog.qmax = qmax;
                sc.prog.icase = (flags & REG_ICASE) != 0;
                sc.prog.newline = (flags & REG_NEWLINE) && bs_delim == '\n';
                sc.prog.word = sc.word;
            } else sc.simple = 0;
        } else sc.simple = 0;
        if (!(whole && sc.dangerous && sc.simple)) {
            /* Nested or surrounding pieces still need a danger pass. */
            bs_re_scan all;
            memset (&all, 0, sizeof all);
            all.s = pat; all.n = len; all.ext = sc.ext; all.simple = 1;
            bs_re_expr (&all);
            if (all.dangerous) sc.dangerous = 1;
            if (all.hang) sc.hang = 1;
            if (all.bad) sc.bad = 1;
            sc.simple = 0;
        }
    } else {
        bs_re_expr (&sc);
    }
    if (sc.bad && !sc.dangerous && !sc.hang) return 0;
    if (sc.dangerous && whole && sc.simple && !sc.bad) {
        /* A multibyte locale still runs this matcher. A pattern-space byte
           at or above 0x80 is refused at search time for a word or
           case-insensitive program, whose classes are single bytes. */
        if (bs_prog_made >= BS_PROG_MAX) return -1;
        bs_prog *copy = malloc (sizeof *copy);
        if (!copy) return -1;
        *copy = sc.prog;
        *out = copy;
        return 1;
    }
    /* 2: compile it, but a substitution must not fill more than one register.
       A repeated anchor with no consumer, such as ([a]|^)+ or b(|^)+, still
       finishes and returns 0. */
    if (sc.hang) return 2;
    return 0;
}

static int
bs_isword (unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z') || c == '_';
}

static int
bs_anchor_ok (const bs_prog *prog, int kind, const char *str,
              size_t beg, size_t end, size_t pos)
{
    int has_prev = pos > beg, has_cur = pos < end;
    unsigned char prev = has_prev ? (unsigned char) str[pos - 1] : 0;
    unsigned char cur = has_cur ? (unsigned char) str[pos] : 0;
    int wordprev = has_prev && bs_isword (prev);
    int wordcur = has_cur && bs_isword (cur);
    int boundary = (!wordprev && wordcur) || (wordprev && !wordcur);
    switch (kind) {
        case BS_ATOM_BOL: return pos == beg || (prog->newline && has_prev && prev == '\n');
        case BS_ATOM_EOL: return pos == end || (prog->newline && has_cur && cur == '\n');
        case BS_ATOM_BOS: return pos == beg;
        case BS_ATOM_EOS: return pos == end;
        case BS_ATOM_WSTART: return !wordprev && wordcur;
        case BS_ATOM_WEND: return wordprev && !wordcur;
        case BS_ATOM_WB: return boundary;
        case BS_ATOM_WNB: return !boundary;
        default: return 0;
    }
}

static int
bs_alt_len (const bs_prog *prog, int alt, int from, const char *str, size_t beg, size_t end,
            size_t pos, size_t *out, int wend_consume)
{
    size_t cur = pos;
    int n = prog->natoms[alt];
    for (int i = from; i < n; i++) {
        unsigned char kind = prog->atoms[alt][i].kind;
        if (kind == BS_ATOM_LIT) {
            if (cur >= end) return -1;
            unsigned char got = (unsigned char) str[cur];
            unsigned char want = prog->atoms[alt][i].lit;
            if (got != want) {
                if (!prog->icase || tolower (got) != tolower (want)) return -1;
            }
            cur++;
        } else if (kind == BS_ATOM_SPACE || kind == BS_ATOM_NSPACE
                   || kind == BS_ATOM_WORD || kind == BS_ATOM_NWORD) {
            if (cur >= end) return -1;
            unsigned char got = (unsigned char) str[cur];
            int ok = kind == BS_ATOM_SPACE ? isspace (got)
                   : kind == BS_ATOM_NSPACE ? !isspace (got)
                   : kind == BS_ATOM_WORD ? bs_isword (got) : !bs_isword (got);
            if (!ok) return -1;
            cur++;
        } else if (wend_consume && kind == BS_ATOM_WEND && i + 1 < n
                   && (prog->atoms[alt][i + 1].kind == BS_ATOM_LIT
                       || prog->atoms[alt][i + 1].kind >= BS_ATOM_SPACE)
                   && cur > beg && bs_isword ((unsigned char) str[cur - 1])
                   && !bs_anchor_ok (prog, kind, str, beg, end, cur)) {
            /* glibc consumes the next atom when \> fails between two word
               characters, except for an unlimited empty repeat (* and {0,}).
               There \> is false, so the group matches empty and the byte
               stays outside the match. A final \> stays zero-width. \< and
               ^ keep the strict test. */
            continue;
        } else if (!bs_anchor_ok (prog, kind, str, beg, end, cur)) return -1;
    }
    *out = cur - pos;
    return 0;
}

/* True when an anchor rejects this position but that alternative's
   consuming suffix still matches. A substitution asks for registers, and
   a finite repeat must fail there: glibc's register fill does not accept
   the empty completion, and it does not then match at a later position.
   An address passes no registers, so it must not use this result. */
static int
bs_consumer_blocked (const bs_prog *prog, const char *str, size_t beg, size_t end,
                     size_t pos)
{
    for (int a = 0; a < prog->nalts; a++) {
        int n = prog->natoms[a];
        int i = 0;
        while (i < n) {
            unsigned char k = prog->atoms[a][i].kind;
            if (k == BS_ATOM_LIT || k >= BS_ATOM_SPACE) break;
            i++;
        }
        if (i == 0 || i >= n) continue;
        size_t full = 0, tail = 0;
        if (bs_alt_len (prog, a, 0, str, beg, end, pos, &full, 1) == 0) continue;
        if (bs_alt_len (prog, a, i, str, beg, end, pos, &tail, 1) == 0 && tail > 0)
            return 1;
    }
    return 0;
}

/* Greedy leftmost match of the one group at pos. Empty repetitions stop:
   an unlimited quantifier does not take a trailing empty iteration once the
   minimum is met, and a finite one records that empty iteration as the group.
   registers is true when the caller asked for match offsets (nmatch > 0).
   Returns -1 only then, when a finite repeat hits a blocked consumer: that
   attempt and every later position fail. An address passes registers 0 and
   keeps the empty iteration, which is the nmatch 0 match. 0 is no match at
   this position. 1 is a match. */
static int
bs_prog_at (const bs_prog *prog, const char *str, size_t beg, size_t end, size_t pos,
            size_t *mend, size_t *gso, size_t *geo, int *gset, int registers)
{
    size_t cur = pos;
    int reps = 0, group = 0;
    size_t so = pos, eo = pos;
    for (;;) {
        if (prog->qmax >= 0 && reps >= prog->qmax) break;
        int best = -1;
        for (int a = 0; a < prog->nalts; a++) {
            size_t len = 0;
            if (bs_alt_len (prog, a, 0, str, beg, end, cur, &len,
                            prog->qmin > 0 || prog->qmax >= 0) == 0
                && (int) len > best)
                best = (int) len;
        }
        if (best < 0) break;
        if (best == 0) {
            if (registers && prog->qmax >= 0
                && bs_consumer_blocked (prog, str, beg, end, cur))
                return -1;
            if (reps >= prog->qmin && prog->qmax < 0) break;
            so = cur; eo = cur; group = 1;
            if (prog->qmax >= 0 && reps >= prog->qmin) { reps = prog->qmax; break; }
            reps++;
            if (prog->qmax < 0 && reps >= prog->qmin) break;
            continue;
        }
        so = cur; eo = cur + (size_t) best; group = 1;
        cur = eo; reps++;
    }
    if (reps < prog->qmin) return 0;
    *mend = cur; *gset = group;
    if (group) { *gso = so; *geo = eo; }
    return 1;
}

static int
bs_prog_find (const bs_prog *prog, const char *str, size_t beg, size_t start, size_t end,
              size_t nmatch, regmatch_t *matches, size_t off)
{
    if (start > end) return REG_NOMATCH;
    /* Byte classes are not GNU sed's multibyte word or case classes.
       ASCII text matches the C locale. A higher byte is refused. */
    if ((prog->word || prog->icase) && MB_CUR_MAX > 1) {
        for (size_t i = beg; i < end; i++) {
            if ((unsigned char) str[i] >= 0x80) {
                builtin_error ("regex may hang; refusing pattern");
                bs_runtime_error = 1;
                return REG_ESPACE;
            }
        }
    }
    for (size_t pos = start; ; pos++) {
        size_t mend = pos, gso = 0, geo = 0;
        int gset = 0;
        int at = bs_prog_at (prog, str, beg, end, pos, &mend, &gso, &geo, &gset,
                             nmatch > 0);
        if (at < 0) return REG_NOMATCH;
        if (at > 0) {
            if (nmatch > 0 && matches) {
                matches[0].rm_so = (regoff_t) pos - (regoff_t) off;
                matches[0].rm_eo = (regoff_t) mend - (regoff_t) off;
            }
            if (nmatch > 1 && matches) {
                matches[1].rm_so = gset ? (regoff_t) gso - (regoff_t) off : -1;
                matches[1].rm_eo = gset ? (regoff_t) geo - (regoff_t) off : -1;
            }
            for (size_t i = 2; i < nmatch && matches; i++)
                matches[i].rm_so = matches[i].rm_eo = -1;
            return 0;
        }
        if (pos == end) break;
    }
    return REG_NOMATCH;
}

/* Compile the selected sed dialect. GNU libc exposes the same length-aware
   regex interface used by GNU sed, including dot matching embedded NULs.
   Other libcs use the private, vendored GNU engine. Never leave process-global regex
   syntax changed: later shell expressions and loadables share this process.
   Returns -2 when the pattern is refused; the refusal is already reported. */
static int
bs_compile_re (regex_t *re, const char *pat, size_t len, int flags, bs_prog **prog_out)
{
    bs_prog *prog = NULL;
    *prog_out = NULL;
    int guard = bs_regex_guard (pat, len, flags, &prog);
    if (guard < 0) {
        free (prog);
        builtin_error ("regex may hang; refusing pattern: %s", pat);
        return -2;
    }
    reg_syntax_t syntax = flags & REG_EXTENDED
        ? RE_SYNTAX_POSIX_EXTENDED : RE_SYNTAX_POSIX_BASIC;
    syntax &= ~(RE_DOT_NOT_NULL | RE_UNMATCHED_RIGHT_PAREN_ORD);
    syntax |= RE_NO_POSIX_BACKTRACKING;
    /* GNU sed gives case-sensitive patterns a fastmap: searches then skip
       positions whose first byte cannot start a match. */
    re->buffer = NULL; re->allocated = 0; re->translate = NULL; re->fastmap = NULL;
    if (flags & REG_ICASE) syntax |= RE_ICASE;
    else if (!(re->fastmap = malloc (256))) { free (prog); return -1; }
    if (flags & REG_NEWLINE) {
        syntax &= ~RE_DOT_NEWLINE;
        syntax |= RE_HAT_LISTS_NOT_NEWLINE;
    }
    reg_syntax_t saved = re_set_syntax (syntax);
    const char *error = re_compile_pattern (pat, len, re);
    re_set_syntax (saved);
    /* With -z, bs_search emulates M by searching each NUL-terminated
       record; newline is then ordinary for the anchors (GNU sed). */
    re->newline_anchor = (flags & REG_NEWLINE) && bs_delim == '\n';
    if (error) { free (prog); regfree (re); memset (re, 0, sizeof *re); return -1; }
    if (prog) bs_prog_made++;
    if (guard == 2) {
        if (bs_unsafe_n >= BS_PROG_MAX) {
            free (prog);
            regfree (re);
            memset (re, 0, sizeof *re);
            builtin_error ("regex may hang; refusing pattern: %s", pat);
            return -2;
        }
        bs_unsafe_note (re);
    }
    *prog_out = prog;
    return 0;

}

/* Preserve the entire subject, including the character preceding the search
   offset (word boundaries and multiline anchors depend on it). Matches are
   returned relative to off for the replacement expander. */
static int
bs_search (regex_t *re, const char *str, size_t len, size_t off,
           size_t nmatch, regmatch_t *matches)
{
    if (len > INT_MAX) { bs_runtime_error = 1; return REG_ESPACE; }
    regoff_t starts[10], ends[10];
    for (int i = 0; i < 10; i++) starts[i] = ends[i] = -1;
    struct re_registers regs = { 10, starts, ends };
    re->regs_allocated = REGS_FIXED;
    size_t beg = 0, start = off, end = len;
    regoff_t result;
    /* The M flag compiles with RE_HAT_LISTS_NOT_NEWLINE (and only then).
       Under -z, GNU sed matches such a regex within one NUL-separated record
       at a time, so ^ and $ anchor at record boundaries. */
    int split = bs_delim != '\n' && (re->syntax & RE_HAT_LISTS_NOT_NEWLINE);
    if (split && off > 0) {
        const char *eol = memrchr (str, bs_delim, off);
        if (eol) beg = (size_t) (eol - str) + 1;
    }
    /* The only sed search with nmatch > 1 is s/// (ten registers). Address
       matches pass nmatch 0. A bounded program replaces both, so set_regs is
       never entered for a pattern that can loop there. */
    bs_prog *prog = bs_prog_lookup (re);
    for (;;) {
        if (split) {
            const char *e = memchr (str + start, bs_delim, len - start);
            end = e ? (size_t) (e - str) : len;
        }
        if (prog) {
            int found = bs_prog_find (prog, str, beg, start, end, nmatch, matches, off);
            if (bs_runtime_error || found == 0 || end == len) return found;
            beg = start = end + 1;
            continue;
        }
        /* One register does not enter set_regs. No match is a real miss
           (the walk cannot run). A hit is refused: the one-register span is
           not the group's match, and filling the other registers may not
           return. nmatch 0, used by addresses, never takes this path. */
        if (nmatch > 1 && bs_unsafe_p (re)) {
            regoff_t one_so = -1, one_eo = -1;
            struct re_registers one = { 1, &one_so, &one_eo };
            re->regs_allocated = REGS_FIXED;
            result = re_search (re, str + beg, (regoff_t) (end - beg),
                                (regoff_t) (start - beg), (regoff_t) (end - start), &one);
            if (result == -2) { bs_runtime_error = 1; return REG_ESPACE; }
            if (result >= 0) {
                builtin_error ("regex may hang; refusing pattern");
                bs_runtime_error = 1;
                return REG_ESPACE;
            }
            if (end == len) return REG_NOMATCH;
            beg = start = end + 1;
            continue;
        }
        result = re_search (re, str + beg, (regoff_t) (end - beg), (regoff_t) (start - beg),
                            (regoff_t) (end - start), nmatch ? &regs : NULL);
        if (result == -2) { bs_runtime_error = 1; return REG_ESPACE; }
        if (result >= 0 || end == len) break;
        beg = start = end + 1;
    }
    if (result < 0) return REG_NOMATCH;
    for (size_t i = 0; i < nmatch; i++) {
        matches[i].rm_so = starts[i] < 0 ? -1 : starts[i] + (regoff_t) beg - (regoff_t) off;
        matches[i].rm_eo = ends[i] < 0 ? -1 : ends[i] + (regoff_t) beg - (regoff_t) off;
    }
    return 0;

}

/* GNU sed numeric escapes can represent NUL in regexes and replacements. */
static int
bs_numeric_escape (const char **pp, unsigned char *value)
{
    const char *p = *pp;
    int base, limit;
    if (*p == 'c' && p[1]) {
        *value = (unsigned char) toupper ((unsigned char) p[1]) ^ 64;
        *pp = p + 2; return 1;
    }
    if (*p == 'x') { base = 16; limit = 2; }
    else if (*p == 'o') { base = 8; limit = 3; }
    else if (*p == 'd') { base = 10; limit = 3; }
    else return 0;
    const char *start = ++p;
    unsigned n = 0;
    while (p - start < limit) {
        unsigned char ch = *p;
        int digit = ch >= '0' && ch <= '9' ? ch - '0'
            : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10
            : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : base;
        if (digit >= base) break;
        n = n * base + digit; p++;
    }
    if (p == start) return 0;
    *value = (unsigned char) n; *pp = p;
    return 1;
}

/* Script text cannot contain NUL. Decode common sed regex escapes without
   changing BRE/ERE operators. An escaped delimiter is stripped before any
   other escape is considered, so that character keeps its plain regex
   meaning (`s.a\.b.X.` has an active dot; `sn\nnXn` matches a letter n),
   matching GNU sed. */
static char *
bs_regex_text (const char *pat, char delim, int extended, size_t *len)
{
    (void) extended;
    char *out = strdup (pat);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; pat[i]; i++) {
        if (pat[i] == '\\' && pat[i + 1]) {
            char ch = pat[++i];
            if (ch == delim) { out[j++] = ch; continue; }
            const char *end = pat + i;
            unsigned char value;
            if (bs_numeric_escape (&end, &value)) {
                out[j++] = (char) value; i = end - pat - 1; continue;
            }
            switch (ch) {
                case 'n': out[j++] = '\n'; continue;
                case 't': out[j++] = '\t'; continue;
                case 'r': out[j++] = '\r'; continue;
                case 'a': out[j++] = '\a'; continue;
                case 'f': out[j++] = '\f'; continue;
                case 'v': out[j++] = '\v'; continue;
            }
            out[j++] = '\\';
            out[j++] = ch;
        } else out[j++] = pat[i];
    }
    out[j] = 0;
    *len = j;
    return out;
}

/* In a replacement, an escaped delimiter is that literal character rather
   than an escape (`s1a1[\1]1` inserts "1", `snan\nn` inserts "n"), except
   `\&`, which already denotes a literal ampersand. Returns the new length. */
static size_t
bs_repl_text (char *repl, char delim)
{
    char *w = repl;
    for (const char *r = repl; *r; r++) {
        if (*r == '\\' && r[1]) {
            if (r[1] == delim && delim != '&') { *w++ = delim; r++; continue; }
            *w++ = *r++;
        }
        *w++ = *r;
    }
    *w = '\0';
    return (size_t) (w - repl);
}

static void
bs_str_init (bs_string *s) { s->str = NULL; s->len = 0; s->cap = 0; s->failed = 0; }
static void
bs_str_free (bs_string *s) { free (s->str); s->str = NULL; s->len = s->cap = 0; s->failed = 0; }
static int
bs_str_reserve (bs_string *s, size_t n)
{
    if (s->failed) return -1;
    if (n + 1 < n) { s->failed = 1; return -1; }   /* SIZE_MAX overflow */
    if (s->cap >= n + 1) return 0;
    size_t nc = s->cap ? s->cap : 64;
    while (nc < n + 1) {
        if (nc > SIZE_MAX / 2) { s->failed = 1; return -1; }
        nc *= 2;
    }
    char *p = realloc (s->str, nc);
    if (!p) { s->failed = 1; return -1; }
    s->str = p; s->cap = nc;
    return 0;
}
static int
bs_str_set (bs_string *s, const char *src, size_t srclen)
{
    if (s->failed) return -1;
    if (bs_str_reserve (s, srclen) < 0) return -1;
    memcpy (s->str, src, srclen);
    s->str[srclen] = '\0';
    s->len = srclen;
    return 0;
}
static int
bs_str_append (bs_string *s, const char *src, size_t srclen)
{
    if (s->failed) return -1;
    if (srclen > SIZE_MAX - s->len) { s->failed = 1; return -1; }
    if (bs_str_reserve (s, s->len + srclen) < 0) return -1;
    memcpy (s->str + s->len, src, srclen);
    s->len += srclen;
    s->str[s->len] = '\0';
    return 0;
}

typedef struct {
    FILE *fp;
    int missing_newline;
} bs_output;

static bs_output bs_stdout, bs_stderr;
/* `w /dev/stdout` shares the stream but, as in GNU sed, keeps its own
   pending-newline state. */
static bs_output bs_wstdout, bs_wstderr;

/* An unterminated pattern stays unterminated until another record is printed
   to the same output during this invocation (for example, p plus auto-print). */
static void
bs_emit (bs_output *out, const char *data, size_t len, int newline)
{
    if (out->missing_newline) fputc (bs_delim, out->fp);
    if (len) fwrite (data, 1, len, out->fp);
    if (newline) fputc (bs_delim, out->fp);
    out->missing_newline = !newline;
    if (bs_unbuffered) fflush (out->fp);
}

/* Append-file bytes are verbatim, including an unterminated final record.
   q flushes even an empty queue, terminating any pending pattern output. */
static void
bs_flush_queue (bs_output *out, bs_string *queue, int *pending)
{
    if (out->missing_newline) fputc (bs_delim, out->fp);
    if (queue->len) fwrite (queue->str, 1, queue->len, out->fp);
    out->missing_newline = 0;
    *pending = 0;
    queue->len = 0;
    if (queue->str) queue->str[0] = '\0';
    fflush (out->fp);
}

static void
bs_l_emit_token (FILE *out, const char *tok, size_t len, size_t *col, long width)
{
    if (width > 0 && *col + len >= (size_t) width)
    {
        fputc ('\\', out);
        fputc (bs_delim, out);
        *col = 0;
    }
    fwrite (tok, 1, len, out);
    *col += len;
}

static void
bs_l_emit (FILE *out, const char *s, size_t len, long width)
{
    size_t col = 0;
    for (size_t i = 0; i < len; i++)
    {
        unsigned char ch = (unsigned char) s[i];
        char oct[5];
        const char *tok = NULL;
        switch (ch)
        {
            case '\\': tok = "\\\\"; break;
            case '\a': tok = "\\a"; break;
            case '\b': tok = "\\b"; break;
            case '\f': tok = "\\f"; break;
            case '\n': tok = "\\n"; break;
            case '\r': tok = "\\r"; break;
            case '\t': tok = "\\t"; break;
            case '\v': tok = "\\v"; break;
            default:
                if (ch >= 0x20 && ch < 0x7f)
                {
                    char c = (char) ch;
                    bs_l_emit_token (out, &c, 1, &col, width);
                    continue;
                }
                snprintf (oct, sizeof oct, "\\%03o", ch);
                tok = oct;
                break;
        }
        bs_l_emit_token (out, tok, strlen (tok), &col, width);
    }
    fputc ('$', out);
    fputc (bs_delim, out);
    if (bs_unbuffered) fflush (out);
}

/* Parse a single address from *psp. Advances *psp past the address.
   Returns 1 if an address was parsed, 0 if none, -1 on error. */
/* Decode one y/// set up to (but not consuming) the unescaped delimiter,
   resolving POSIX escapes (\n \t \r \a \f \v \\ and \<delim>). Leaves *pp at
   the delimiter. Returns 0 on success, -1 on overflow. */
static int
bs_y_decode (const char **pp, char delim, unsigned char *out, size_t cap, size_t *outlen)
{
    const char *p = *pp;
    size_t n = 0;
    while (*p && *p != delim) {
        unsigned char ch;
        if (*p == '\\' && p[1] == delim) {
            ch = (unsigned char) delim; p += 2;
        } else if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
                case 'n': ch = '\n'; break;
                case 't': ch = '\t'; break;
                case 'r': ch = '\r'; break;
                case 'a': ch = '\a'; break;
                case 'f': ch = '\f'; break;
                case 'v': ch = '\v'; break;
                case '\\': ch = '\\'; break;
                /* \<delim> or any other escaped char: take it literally. */
                default:  ch = (unsigned char) *p; break;
            }
            p++;
        } else {
            ch = (unsigned char) *p; p++;
        }
        if (n >= cap) return -1;
        out[n++] = ch;
    }
    *pp = p; *outlen = n;
    return 0;
}

/* Reject numeric overflow before arithmetic; malformed scripts must not
   leave undefined state in the persistent shell. */
static int
bs_number (const char **pp, long *out)
{
    const char *p = *pp;
    long n = 0;
    if (!isdigit ((unsigned char) *p)) return -1;
    while (isdigit ((unsigned char) *p)) {
        int digit = *p++ - '0';
        if (n > (LONG_MAX - digit) / 10) {
            builtin_error ("number too large"); return -1;
        }
        n = n * 10 + digit;
    }
    *pp = p; *out = n;
    return 0;
}

/* A bracket expression in an address or s/// regex. The caller is at '['.
   Returns the byte after the closing ']', or NULL if the class runs into a
   newline or the end of the script. A delimiter inside the class is data.
   ']' right after '[' or '[^' is literal; a named class [:.= runs until the
   matching :] .] =] and does not close early. A backslash does not protect
   ']' here, matching GNU sed. */
static const char *
bs_scan_bracket (const char *p)
{
    if (*p != '[') return NULL;
    p++;
    if (*p == '^') p++;
    int first = 1, state = 0;
    char marker = 0;
    for (;;) {
        unsigned char c = (unsigned char) *p;
        if (c == 0 || c == '\n') return NULL;
        if (state == 0) {
            if (c == ']' && !first) return p + 1;
            if (c == '[') state = 1;
            first = 0;
            p++;
        } else if (state == 1) {
            if (c == ':' || c == '.' || c == '=') { marker = (char) c; state = 2; p++; }
            else if (c == ']') return p + 1;
            else { state = 0; p++; }
        } else if (state == 2) {
            if (c == (unsigned char) marker) state = 3;
            p++;
        } else if (c == ']') { state = 0; p++; }
        else if (c == (unsigned char) marker) p++;
        else { state = 2; p++; }
    }
}

/* Scan a regex until an unescaped delimiter that is not inside a bracket
   expression. On success *pp is the delimiter and *start is the regex.
   A newline ends the script text and is unterminated, as in GNU sed. */
static int
bs_scan_regex_delim (const char **pp, char delim, const char **start)
{
    const char *p = *pp;
    *start = p;
    while (*p && *p != '\n') {
        /* The delimiter ends the regex even when it is a backslash
           (`s\a\b\` and `\a\p`). An escaped delimiter is a backslash
           followed by that delimiter, so the escape test comes second. */
        if (*p == delim) { *pp = p; return 0; }
        if (*p == '\\') {
            if (!p[1] || p[1] == '\n') return -1;
            p += 2;
            continue;
        }
        if (*p == '[') {
            const char *end = bs_scan_bracket (p);
            if (!end) return -1;
            p = end;
            continue;
        }
        p++;
    }
    return -1;
}

static int
bs_text_push (char **buf, size_t *len, size_t *cap, char ch)
{
    if (*len + 1 >= *cap) {
        size_t nc = *cap ? *cap * 2 : 64;
        if (nc < *cap) return -1;
        char *nb = realloc (*buf, nc);
        if (!nb) return -1;
        *buf = nb;
        *cap = nc;
    }
    (*buf)[(*len)++] = ch;
    return 0;
}

/* After a command, GNU sed allows only a comment, ';', newline, '}' or the
   end of the script. '}' stays so the next iteration can parse it. '{' is
   the exception: the following command needs no separator. 'v' is the other
   exception: its token already stopped on a blank, and that blank is the
   separator before the next command. */
static int
bs_finish_cmd (const char **pp)
{
    const char *p = *pp;
    for (;;) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '#') break;
        while (*p && *p != '\n') p++;
    }
    if (*p && *p != '\n' && *p != ';' && *p != '}') {
        builtin_error ("extra characters after command");
        return -1;
    }
    *pp = p;
    return 0;
}

static int
bs_parse_addr (const char **psp, bs_addr *a, int extended)
{
    const char *p = *psp;
    while (*p == ' ' || *p == '\t') p++;
    a->kind = BS_ADDR_NONE; a->re_ok = 0;
    if (*p == '$') { a->kind = BS_ADDR_LAST; *psp = p + 1; return 1; }
    /* GNU relative end-addresses (valid only as addr2): ,+N and ,~N. */
    if (*p == '+' || *p == '~') {
        int mult = (*p == '~');
        p++;
        long n = 0;
        if (bs_number (&p, &n) < 0) return -1;
        a->kind = mult ? BS_ADDR_MULT : BS_ADDR_PLUS;
        a->step = n;
        *psp = p;
        return 1;
    }
    if (*p >= '0' && *p <= '9')
    {
        a->kind = BS_ADDR_LINE;
        long n = 0;
        if (bs_number (&p, &n) < 0) return -1;
        a->line = n;
        /* GNU step address: first~step (e.g. 1~2 = every other line). */
        if (*p == '~') {
            p++;
            long st = 0;
            if (bs_number (&p, &st) < 0) return -1;
            a->kind = BS_ADDR_STEP;
            a->step = st;
        }
        *psp = p;
        return 1;
    }
    /* /REGEX/ or \cREGEXc with any delimiter c except newline. */
    if (*p == '/' || *p == '\\')
    {
        char delim = *p == '/' ? '/' : p[1];
        if (!delim || delim == '\n') { builtin_error ("unterminated address regex"); return -1; }
        p += *p == '/' ? 1 : 2;
        const char *start = p;
        if (bs_scan_regex_delim (&p, delim, &start) < 0) {
            builtin_error ("unterminated regex address"); return -1;
        }
        size_t rlen = (size_t) (p - start);
        char *pat_raw = strndup (start, rlen);
        if (!pat_raw) return -1;
        char *pat = bs_regex_text (pat_raw, delim, extended, &rlen);
        free (pat_raw);
        if (!pat) return -1;
        int flags = extended ? REG_EXTENDED : 0;
        p++;
        while (*p == 'I' || *p == 'M') {
            if (*p++ == 'I') flags |= REG_ICASE;
            else flags |= REG_NEWLINE;
        }
        if (!rlen && (flags & (REG_ICASE | REG_NEWLINE))) {
            builtin_error ("cannot specify modifiers on empty regexp"); free (pat); return -1;
        }
        int cre = rlen ? bs_compile_re (&a->re, pat, rlen, flags, &a->prog) : 0;
        if (cre != 0) {
            if (cre != -2) builtin_error ("bad regex in address: %s", pat);
            free (pat); return -1;
        }
        free (pat);
        a->kind = BS_ADDR_REGEX;
        a->re_ok = rlen != 0;
        *psp = p;
        return 1;
    }
    return 0;
}

/* Most recently used regex (address or s///), for POSIX empty-regex reuse
   (`s//repl/`, `//addr`). Reset at the start of each invocation. */
static regex_t *bs_last_re = NULL;

/* q/Q quit signalling: when a q/Q command runs, the whole stream editor stops
   (across all input files) and exits with bs_quit_code. Reset by the builtin
   before processing. */
static int bs_quit_signaled = 0;
static int bs_quit_code = 0;
static int bs_runtime_error = 0;

static int
bs_exec_allowed (void)
{
    const char *v = getenv ("BASHSED_ALLOW_EXEC");
    return v && strcmp (v, "1") == 0;
}

static int
bs_exec_capture (const char *cmd, bs_string *out, int strip)
{
    FILE *fp;
    char buf[4096];
    size_t got;

    bs_str_set (out, "", 0);
    if (!bs_exec_allowed ()) {
        builtin_error ("e command requires BASHSED_ALLOW_EXEC=1");
        bs_runtime_error = 1;
        return -1;
    }

    fp = popen (cmd ? cmd : "", "r");
    if (!fp) {
        builtin_error ("e command failed: %s", strerror (errno));
        bs_runtime_error = 1;
        return -1;
    }

    while ((got = fread (buf, 1, sizeof buf, fp)) > 0)
        bs_str_append (out, buf, got);
    pclose (fp);

    /* GNU sed drops one trailing record separator (NUL with -z). */
    if (strip && out->len > 0 && out->str[out->len - 1] == bs_delim)
        out->str[--out->len] = '\0';
    if (out->failed) {
        bs_runtime_error = 1;
        return -1;
    }
    return 0;
}

/* Write-stream table for `w FILE` / `s///w FILE`. Each distinct path is opened
   once (truncating) and shared across commands and input files (GNU semantics);
   closed by the builtin at the end. */
#define BS_MAX_WSTREAMS 64
static struct { char *path; bs_output out; } bs_wstreams[BS_MAX_WSTREAMS];
static int bs_n_wstreams = 0;

static bs_output *
bs_get_wstream (const char *path)
{
    if (!path || !*path) return NULL;
    if (!strcmp (path, "/dev/stdout")) return &bs_wstdout;
    if (!strcmp (path, "/dev/stderr")) return &bs_wstderr;
    for (int i = 0; i < bs_n_wstreams; i++)
        if (!strcmp (bs_wstreams[i].path, path)) return &bs_wstreams[i].out;
    if (bs_n_wstreams >= BS_MAX_WSTREAMS) { bs_io_error = 4; bs_runtime_error = 1; return NULL; }
    FILE *fp = fopen (path, "w");   /* truncate on first use */
    if (!fp) {
        builtin_error ("%s: %s", path, strerror (errno));
        bs_io_error = 4; bs_runtime_error = 1;
        return NULL;
    }
    char *copy = strdup (path);
    if (!copy) { fclose (fp); bs_io_error = 4; bs_runtime_error = 1; return NULL; }
    bs_wstreams[bs_n_wstreams].path = copy;
    bs_wstreams[bs_n_wstreams].out = (bs_output) { fp, 0 };
    return &bs_wstreams[bs_n_wstreams++].out;
}

static int
bs_close_wstreams (void)
{
    int failed = 0;
    for (int i = 0; i < bs_n_wstreams; i++) {
        FILE *fp = bs_wstreams[i].out.fp;
        int error = ferror (fp);
        if (fclose (fp) != 0 || error) {
            builtin_error ("%s: write error", bs_wstreams[i].path);
            failed = 1;
        }
        free (bs_wstreams[i].path);
        bs_wstreams[i].path = NULL; bs_wstreams[i].out.fp = NULL;
    }
    bs_n_wstreams = 0;
    return failed ? -1 : 0;
}

/* Read-stream table for `R FILE`: each path keeps a persistent handle so
   successive R commands consume successive lines. */
#define BS_MAX_RSTREAMS 64
static struct { char *path; FILE *fp; } bs_rstreams[BS_MAX_RSTREAMS];
static int bs_n_rstreams = 0;

static FILE *
bs_get_rstream (const char *path)
{
    if (!path || !*path) return NULL;
    for (int i = 0; i < bs_n_rstreams; i++)
        if (!strcmp (bs_rstreams[i].path, path)) return bs_rstreams[i].fp;
    if (bs_n_rstreams >= BS_MAX_RSTREAMS) return NULL;
    FILE *fp = fopen (path, "r");   /* NULL handle is cached so we don't retry */
    bs_rstreams[bs_n_rstreams].path = strdup (path);
    bs_rstreams[bs_n_rstreams].fp = fp;
    bs_n_rstreams++;
    return fp;
}

static void
bs_close_rstreams (void)
{
    for (int i = 0; i < bs_n_rstreams; i++) {
        if (bs_rstreams[i].fp) fclose (bs_rstreams[i].fp);
        free (bs_rstreams[i].path);
        bs_rstreams[i].path = NULL; bs_rstreams[i].fp = NULL;
    }
    bs_n_rstreams = 0;
}

static int
bs_addr_match (bs_addr *a, long lineno, int is_last, const char *line, size_t len)
{
    if (a->kind == BS_ADDR_REGEX && a->re_ok)
        bs_last_re = &a->re;   /* track for empty-regex reuse */
    switch (a->kind)
    {
        case BS_ADDR_NONE: return 0;
        case BS_ADDR_LINE: return lineno == a->line;
        case BS_ADDR_STEP:
            /* first~step: match lines first, first+step, first+2*step, …
               step<=0 degenerates to just the single line `first` (GNU). */
            if (a->step <= 0) return lineno == a->line;
            return lineno >= a->line && (lineno - a->line) % a->step == 0;
        case BS_ADDR_LAST: return is_last;
        case BS_ADDR_REGEX:
            if (!bs_last_re) {
                builtin_error ("no previous regular expression");
                bs_runtime_error = 1;
                return 0;
            }
            return bs_search (bs_last_re, line, len, 0, 0, NULL) == 0;
    }
    return 0;
}

/* Free per-command resources. */
static void
bs_cmd_free (bs_cmd *c)
{
    free (c->addr1.prog);
    free (c->addr2.prog);
    free (c->s_prog);
    if (c->addr1.re_ok) regfree (&c->addr1.re);
    if (c->addr2.re_ok) regfree (&c->addr2.re);
    if (c->s_re_ok)     regfree (&c->s_re);
    free (c->s_repl);
    free (c->s_literal);
    free (c->label);
    free (c->text);
    free (c->s_wfile);
    memset (c, 0, sizeof *c);
}

/* GNU sed accepts a v token when strverscmp(token, "4.9") is not positive.
   A local copy keeps the same order on libcs that have no strverscmp. */
static int
bs_strverscmp (const char *s1, const char *s2)
{
    const unsigned char *p1 = (const unsigned char *) s1;
    const unsigned char *p2 = (const unsigned char *) s2;
    static const uint8_t next_state[] = {
        0x0, 0x3, 0x9, 0x0, 0x3, 0x3, 0x0, 0x6, 0x6, 0x0, 0x6, 0x9
    };
    static const int8_t result_type[] = {
        2, 2, 2, 2, 3, 2, 2, 2, 2,
        2, -1, -1, 1, 3, 3, 1, 3, 3,
        2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 1, 1, -1, 2, 2, -1, 2, 2
    };
    if (p1 == p2) return 0;
    unsigned char c1 = *p1++, c2 = *p2++;
    int state = (c1 == '0') + (isdigit (c1) != 0);
    int diff;
    while ((diff = c1 - c2) == 0) {
        if (c1 == '\0') return diff;
        state = next_state[state];
        c1 = *p1++; c2 = *p2++;
        state += (c1 == '0') + (isdigit (c1) != 0);
    }
    state = result_type[state * 3 + ((c2 == '0') + (isdigit (c2) != 0))];
    switch (state) {
        case 2: return diff;
        case 3:
            while (isdigit (*p1++))
                if (!isdigit (*p2++)) return 1;
            return isdigit (*p2) ? -1 : diff;
        default: return state;
    }
}

/* Parse the entire script into a flat command list. Returns malloc'd
   array; *out_n is the count. Returns -1 on parse error. */
static int
bs_parse_script (const char *script, bs_cmd **out_cmds, int *out_n, int extended)
{
    int cap = 16, n = 0, status = -1;
    bs_prog_made = 0;
    bs_unsafe_n = 0;
    bs_cmd *cmds = calloc ((size_t) cap + 1, sizeof *cmds);
    if (!cmds) return -1;
    const char *p = script;
    while (*p)
    {
        if (n == cap)
        {
            if (cap > INT_MAX / 2 || (size_t) cap > SIZE_MAX / sizeof *cmds / 2) goto err;
            int new_cap = cap * 2;
            bs_cmd *bigger = realloc (cmds, ((size_t) new_cap + 1) * sizeof *cmds);
            if (!bigger) goto err;
            cmds = bigger;
            memset (cmds + n, 0, (size_t) (new_cap + 1 - n) * sizeof *cmds);
            cap = new_cap;
        }
        bs_cmd *c = &cmds[n];

        /* skip whitespace + separators */
        while (*p == ' ' || *p == '\t' || *p == ';' || *p == '\n') p++;
        if (!*p) break;

        /* Comment? */
        if (*p == '#') { while (*p && *p != '\n') p++; continue; }

        /* Parse address(es). */
        int got_a = bs_parse_addr (&p, &c->addr1, extended);
        if (got_a < 0) goto err;
        c->has_a1 = got_a;
        if (c->has_a1 && *p == ',')
        {
            p++;
            int got2 = bs_parse_addr (&p, &c->addr2, extended);
            if (got2 <= 0) { builtin_error ("missing range end"); goto err; }
            c->has_a2 = got2;
        }
        while (*p == ' ' || *p == '\t') p++;

        /* ! ? */
        if (*p == '!') { c->negate = 1; p++; while (*p == ' ' || *p == '\t') p++; }

        if (!*p) { builtin_error ("missing command"); goto err; }
        /* Command character. */
        char op = *p++;
        if (bs_sandbox && strchr ("erRwW", op)) {
            builtin_error ("e/r/w commands disabled in sandbox mode"); goto err;
        }
        switch (op)
        {
            case 's':
            {
                c->kind = BS_S;
                if (!*p || *p == '\n') { builtin_error ("s/// missing delimiter"); goto err; }
                char delim = *p++;
                /* regex: brackets hide the delimiter; the replacement does not */
                const char *re_start = p;
                if (bs_scan_regex_delim (&p, delim, &re_start) < 0) {
                    builtin_error ("s/// unterminated regex"); goto err;
                }
                size_t rlen = (size_t) (p - re_start);
                char *pat = strndup (re_start, rlen);
                if (!pat) goto err;
                p++;   /* skip delim */
                /* replacement */
                const char *rep_start = p;
                while (*p && *p != delim) {
                    if (*p == '\\' && p[1]) p++;
                    p++;
                }
                if (*p != delim) { free (pat); builtin_error ("s/// unterminated replace"); goto err; }
                size_t replen = (size_t) (p - rep_start);
                c->s_repl = strndup (rep_start, replen);
                if (!c->s_repl) { free (pat); goto err; }
                replen = bs_repl_text (c->s_repl, delim);
                for (const char *r = c->s_repl; *r; r++) {
                    if (*r == '\\' && r[1]) {
                        r++;
                        if (*r >= '1' && *r <= '9' && *r - '0' > c->s_needed_sub)
                            c->s_needed_sub = *r - '0';
                    }
                }
                c->s_repl_len = replen;
                c->s_repl_literal = strpbrk (c->s_repl, "&\\") == NULL;
                p++;   /* skip closing delim */
                /* flags */
                while (*p && *p != ';' && *p != '\n')
                {
                    if      (*p == 'g') c->s_global = 1;
                    else if (*p == 'p') c->s_print = 1;
                    else if (*p == 'i' || *p == 'I') c->s_icase = 1;
                    else if (*p == 'm' || *p == 'M') c->s_multiline = 1;
                    else if ((*p == 'e' || *p == 'w') && bs_sandbox) {
                        free (pat); builtin_error ("e/r/w commands disabled in sandbox mode"); goto err;
                    }
                    else if (*p == 'e') c->s_exec = 1;
                    else if (*p == 'w') {
                        /* w FILE must be the LAST flag: rest of line = filename. */
                        p++;
                        while (*p == ' ' || *p == '\t') p++;
                        const char *wf = p;
                        while (*p && *p != '\n') p++;
                        c->s_wfile = strndup (wf, (size_t) (p - wf));
                        break;
                    }
                    else if (*p >= '0' && *p <= '9') {
                        long occurrence;
                        if (bs_number (&p, &occurrence) < 0 || occurrence > INT_MAX || occurrence == 0) {
                            free (pat); builtin_error ("invalid substitution occurrence"); goto err;
                        }
                        c->s_n = (int) occurrence;
                        continue;
                    }
                    else if (*p == ' ' || *p == '\t') { /* skip — fall through to p++ */ }
                    else break;
                    p++;
                }
                int rflags = extended ? REG_EXTENDED : 0;
                if (c->s_icase) rflags |= REG_ICASE;
                /* m/M: ^ and $ match at embedded newlines in the pattern
                   space (REG_NEWLINE), like GNU sed's multiline flag. */
                if (c->s_multiline) rflags |= REG_NEWLINE;
                if (rlen == 0) {
                    free (pat);
                    if (c->s_icase || c->s_multiline) {
                        builtin_error ("cannot specify modifiers on empty regexp");
                        goto err;
                    }
                    c->s_empty_re = 1;
                    break;
                }
                char *pat_compat = bs_regex_text (pat, delim, extended, &rlen);
                free (pat);
                if (!pat_compat) goto err;
                int cre = bs_compile_re (&c->s_re, pat_compat, rlen, rflags, &c->s_prog);
                if (cre != 0) {
                    if (cre != -2) builtin_error ("s/// bad regex: %s", pat_compat);
                    free (pat_compat); goto err;
                }
                c->s_re_ok = 1;
                if ((size_t) c->s_needed_sub > c->s_re.re_nsub) {
                    builtin_error ("invalid backreference in replacement"); free (pat_compat); goto err;
                }
                if (!c->s_icase && *pat_compat && !memchr (pat_compat, 0, rlen)
                    && strpbrk (pat_compat, "\\.^$*+?[](){}|") == NULL) {
                    const unsigned char *q = (const unsigned char *) pat_compat;
                    while (*q && *q < 0x80) q++;
                    if (!*q) {
                        c->s_literal = pat_compat;
                        c->s_literal_len = strlen (pat_compat);
                        pat_compat = NULL;
                    }
                }
                free (pat_compat);
                break;
            }
            case 'd': c->kind = BS_D; break;
            case 'p': c->kind = BS_P; break;
            case 'q': case 'Q':
                c->kind = (op == 'q') ? BS_Q : BS_BIGQ;  /* Q quits without auto-print */
                /* optional exit code: q N / Q N (POSIX). Default 0. */
                while (*p == ' ' || *p == '\t') p++;
                if (*p >= '0' && *p <= '9') {
                    long code;
                    if (bs_number (&p, &code) < 0 || code > INT_MAX) {
                        builtin_error ("invalid quit code"); goto err;
                    }
                    c->q_code = code & 0xff;
                }
                break;
            case '=': c->kind = BS_EQ; break;
            case 'F': c->kind = BS_F; break;   /* print current input filename */
            case 'e': {
                /* e: execute the pattern space; e COMMAND runs COMMAND.
                   Whitespace and then end-of-script or a newline selects the
                   pattern-space form and does not consume that newline.
                   Otherwise the command reads through an unescaped newline.
                   Escapes match GNU text ('\n' '\\' '\xHH' '\cX', and a
                   backslash-newline continuation). An escaped backslash does
                   not continue the line. A trailing backslash is dropped.
                   ';' and '}' are command text, not sed syntax. */
                c->kind = BS_E;
                while (*p == ' ' || *p == '\t') p++;
                if (!*p || *p == '\n') break;
                char *buf = NULL;
                size_t len = 0, cap = 0;
                int oom = 0;
                while (*p && *p != '\n') {
                    if (*p == '\\' && p[1] == '\n') {
                        if (bs_text_push (&buf, &len, &cap, '\n') < 0) { oom = 1; break; }
                        p += 2;
                        while (*p == ' ' || *p == '\t') p++;
                        continue;
                    }
                    if (*p == '\\' && p[1]) {
                        const char *end = p + 1;
                        unsigned char value;
                        if (bs_numeric_escape (&end, &value)) {
                            if (bs_text_push (&buf, &len, &cap, (char) value) < 0) { oom = 1; break; }
                            p = end;
                            continue;
                        }
                        char e = p[1];
                        char decoded = e;
                        int known = 1;
                        switch (e) {
                            case 'a': decoded = '\a'; break;
                            case 'f': decoded = '\f'; break;
                            case 'n': decoded = '\n'; break;
                            case 'r': decoded = '\r'; break;
                            case 't': decoded = '\t'; break;
                            case 'v': decoded = '\v'; break;
                            case '\\': decoded = '\\'; break;
                            default: known = 0; break;
                        }
                        if (bs_text_push (&buf, &len, &cap, known ? decoded : e) < 0) {
                            oom = 1; break;
                        }
                        p += 2;
                        continue;
                    }
                    if (*p == '\\') { p++; break; }   /* a trailing backslash is dropped */
                    if (bs_text_push (&buf, &len, &cap, *p++) < 0) { oom = 1; break; }
                }
                if (oom || (len && bs_text_push (&buf, &len, &cap, '\0') < 0)) {
                    free (buf); goto err;
                }
                c->text = buf;
                break;
            }
            case 'z': c->kind = BS_Z; break;
            case 'v': {
                /* v [VERSION]: GNU reads one label token and accepts it when
                   strverscmp(token, "4.9") is not positive. An empty token
                   (bare v, or v ended by ';' '}' newline or '#') is accepted.
                   The character that ends the token stays for the next command. */
                c->kind = BS_LABEL;
                while (*p == ' ' || *p == '\t') p++;
                const char *s = p;
                while (*p && *p != ' ' && *p != '\t' && *p != ';' && *p != '\n'
                       && *p != '}' && *p != '#')
                    p++;
                if (p == s) break;
                char *tok = strndup (s, (size_t) (p - s));
                if (!tok) goto err;
                int newer = bs_strverscmp (tok, "4.9") > 0;
                free (tok);
                if (newer) {
                    builtin_error ("expected newer version of sed"); goto err;
                }
                break;
            }
            case 'h': c->kind = BS_H; break;
            case 'H': c->kind = BS_HUP; break;
            case 'g': c->kind = BS_G; break;
            case 'G': c->kind = BS_GUP; break;
            case 'x': c->kind = BS_X; break;
            case 'n': c->kind = BS_N_CMD; break;
            case 'N': c->kind = BS_NUP_CMD; break;
            case 'D': c->kind = BS_D_LO; break;
            case 'P': c->kind = BS_P_LO; break;
            case 'l':
                c->kind = BS_L_CMD;
                c->l_width = -1;
                while (*p == ' ' || *p == '\t') p++;
                if (*p >= '0' && *p <= '9' && bs_number (&p, &c->l_width) < 0) {
                    builtin_error ("invalid list width"); goto err;
                }
                break;
            case ':':
                c->kind = BS_LABEL;
                while (*p == ' ' || *p == '\t') p++;
                {
                    const char *s = p;
                    while (*p && *p != ' ' && *p != '\t' && *p != ';' && *p != '\n') p++;
                    c->label = strndup (s, (size_t) (p - s));
                }
                break;
            case 'r': case 'R': {
                /* r FILE: append the whole file after the line. R FILE: append
                   ONE line per cycle (sequential). Filename = rest of line. */
                c->kind = (op == 'r') ? BS_R : BS_BIGR;
                while (*p == ' ' || *p == '\t') p++;
                const char *s = p;
                while (*p && *p != '\n') p++;
                c->text = strndup (s, (size_t) (p - s));
                break;
            }
            case 'w': case 'W': {
                /* w FILE: write the pattern space to FILE; W: only its first
                   line (up to the first embedded newline). Rest of line=FILE. */
                c->kind = (op == 'w') ? BS_W : BS_BIGW;
                while (*p == ' ' || *p == '\t') p++;
                const char *s = p;
                while (*p && *p != '\n') p++;
                c->text = strndup (s, (size_t) (p - s));
                break;
            }
            case 'b': case 't': case 'T':
                c->kind = (op == 'b') ? BS_B : (op == 't') ? BS_T : BS_BIGT;
                while (*p == ' ' || *p == '\t') p++;
                {
                    const char *s = p;
                    while (*p && *p != ';' && *p != '\n') p++;
                    /* trim trailing space */
                    const char *e = p;
                    while (e > s && (e[-1] == ' ' || e[-1] == '\t')) e--;
                    c->label = strndup (s, (size_t) (e - s));
                    c->target_idx = -1;
                }
                break;
            case '{': c->kind = BS_BLOCK_OPEN;  break;
            case '}': c->kind = BS_BLOCK_CLOSE; break;
            case 'y':
                c->kind = BS_Y;
                {
                    /* y/SET1/SET2/ — sets (with POSIX escapes decoded) must be
                       the same length. */
                    char delim = *p;
                    if (!delim || delim == '\n') { builtin_error ("y: missing delimiter"); goto err; }
                    p++;
                    unsigned char set1[256], set2[256];
                    size_t l1 = 0, l2 = 0;
                    if (bs_y_decode (&p, delim, set1, sizeof set1, &l1) < 0)
                        { builtin_error ("y: SET1 too long"); goto err; }
                    if (*p != delim) { builtin_error ("y: missing 2nd delim"); goto err; }
                    p++;
                    if (bs_y_decode (&p, delim, set2, sizeof set2, &l2) < 0)
                        { builtin_error ("y: SET2 too long"); goto err; }
                    if (*p != delim) { builtin_error ("y: missing 3rd delim"); goto err; }
                    p++;
                    if (l1 != l2) { builtin_error ("y: SET1 and SET2 must be same length"); goto err; }
                    /* identity table, then map SET1[i] -> SET2[i]. */
                    for (int i = 0; i < 256; i++) c->y_table[i] = (unsigned char) i;
                    for (size_t i = 0; i < l1; i++)
                        c->y_table[set1[i]] = set2[i];
                    c->y_active = 1;
                }
                break;
            case 'a': case 'i': case 'c':
                /* a/i/c TEXT: text starts after optional `\` continuation
                   or whitespace.  bash-os accepts the single-line form
                   `aTEXT` and `a TEXT`.  Per spec §1.19 edit 3 in
                   `COREUTILS-IMPLEMENTATION-STEPS.md:886-913`, the
                   parser honors backslash-newline continuation: a
                   trailing `\` immediately before a literal `\n` in the
                   script folds into a literal newline in the output
                   text, and scanning continues on the next line.
                   Un-continued `\n` or `;` terminates the TEXT. */
                c->kind = (op == 'a') ? BS_A : (op == 'i') ? BS_I : BS_C;
                {
                    /* Skip optional leading whitespace and `\` continuation. */
                    if (*p == '\\') {
                        p++;
                        /* POSIX/GNU `a\<newline>text` form: a backslash
                           immediately followed by a newline means the text
                           begins on the next line — consume that newline. */
                        if (*p == '\n') p++;
                    }
                    while (*p == ' ' || *p == '\t') p++;
                    /* First pass: scan to the end of the (possibly
                       continued) TEXT.  A `\n` is the terminator unless
                       the immediately-preceding source byte is `\\`,
                       in which case the pair `\\\n` is a continuation
                       and we keep scanning. */
                    const char *s = p;
                    while (*p) {
                        if (*p == ';') break;
                        if (*p == '\n') {
                            if (p > s && p[-1] == '\\') {
                                p++;          /* swallow the LF; keep scanning */
                                continue;
                            }
                            break;
                        }
                        p++;
                    }
                    /* Second pass: copy [s..p), replacing every two-
                       byte sequence `\\\n` with a single `\n`.  Output
                       length is bounded above by the input length so
                       one malloc is enough. */
                    size_t total = (size_t) (p - s);
                    c->text = malloc (total + 1);
                    if (!c->text) goto err;
                    size_t out_i = 0;
                    for (size_t i = 0; i < total; i++) {
                        if (i + 1 < total && s[i] == '\\' && s[i + 1] == '\n') {
                            c->text[out_i++] = '\n';
                            i++;              /* skip the consumed LF */
                        } else {
                            c->text[out_i++] = s[i];
                        }
                    }
                    c->text[out_i] = '\0';
                }
                break;
            default:
                if (op >= 0x20 && op < 0x7f)
                    builtin_error ("unknown command: %c", op);
                else
                    builtin_error ("unknown command: 0x%02x", (unsigned) op);
                goto err;
        }
        if (op != '{' && op != 'v' && bs_finish_cmd (&p) < 0) goto err;
        n++;
    }

    /* Resolve labels. */
    for (int i = 0; i < n; i++)
    {
        if (cmds[i].kind == BS_B || cmds[i].kind == BS_T || cmds[i].kind == BS_BIGT)
        {
            if (!cmds[i].label || !*cmds[i].label) continue;  /* branch to end */
            int found = -1;
            for (int j = 0; j < n; j++)
            {
                if (cmds[j].kind == BS_LABEL &&
                    cmds[j].label && !strcmp (cmds[j].label, cmds[i].label))
                {
                    found = j; break;
                }
            }
            if (found < 0) {
                builtin_error ("undefined label: %s", cmds[i].label);
                status = -4;   /* GNU sed exits 4 when the branch target is missing */
                goto err;
            }
            cmds[i].target_idx = found;
        }
    }
    /* Reject stray closing braces as well as unmatched opening braces. */
    int block_depth = 0;
    for (int i = 0; i < n; i++) {
        if (cmds[i].kind == BS_BLOCK_OPEN) block_depth++;
        else if (cmds[i].kind == BS_BLOCK_CLOSE && --block_depth < 0) {
            builtin_error ("unexpected }"); goto err;
        }
    }
    /* Resolve {...} matching close indexes. */
    for (int i = 0; i < n; i++)
    {
        if (cmds[i].kind == BS_BLOCK_OPEN)
        {
            int depth = 1, j;
            for (j = i + 1; j < n && depth > 0; j++)
            {
                if (cmds[j].kind == BS_BLOCK_OPEN) depth++;
                else if (cmds[j].kind == BS_BLOCK_CLOSE) depth--;
            }
            if (depth != 0) {
                builtin_error ("unbalanced { ... }");
                goto err;
            }
            cmds[i].block_close_idx = j - 1;
        }
    }

    *out_cmds = cmds; *out_n = n;
    return 0;
err:
    for (int i = 0; i <= n; i++) bs_cmd_free (&cmds[i]);
    free (cmds);
    return status;
}

/* Append a buffer to `out` applying GNU sed replacement case conversion.
   *mode is the active span ('U'/'L'/0 from \U \L \E); *one is a one-shot
   ('u'/'l'/0 from \u \l) consumed on the first emitted character. The
   one-shot takes precedence over the span for that one character. A chunk
   of length 0 leaves *one pending for the next chunk (matches GNU). */
static void
bs_case_append (bs_string *out, const char *s, size_t n, int *mode, int *one)
{
    for (size_t i = 0; i < n; i++) {
        char ch = s[i];
        if (*one == 'u')      { ch = (char) toupper ((unsigned char) ch); *one = 0; }
        else if (*one == 'l') { ch = (char) tolower ((unsigned char) ch); *one = 0; }
        else if (*mode == 'U') ch = (char) toupper ((unsigned char) ch);
        else if (*mode == 'L') ch = (char) tolower ((unsigned char) ch);
        bs_str_append (out, &ch, 1);
    }
}

/* Emit the replacement string for one match (expanding & and \1..\9).
   `off` is the absolute offset within pat->str that m[*] are relative to.
   Honors GNU sed case-conversion directives \U \L \u \l \E. */
static void
bs_emit_replace (bs_cmd *c, bs_string *pat, regmatch_t *m, size_t off, bs_string *out)
{
    if (c->s_repl_literal) {
        bs_str_append (out, c->s_repl, c->s_repl_len);
        return;
    }

    int mode = 0;   /* 0 / 'U' / 'L' : \U \L span, ended by \E */
    int one  = 0;   /* 0 / 'u' / 'l' : \u \l one-shot */
    for (const char *r = c->s_repl; *r; r++)
    {
        if (*r == '\\' && r[1] >= '1' && r[1] <= '9') {
            int idx = r[1] - '0';
            r++;
            if (m[idx].rm_so >= 0) {
                size_t s = (size_t) m[idx].rm_so + off;
                size_t e = (size_t) m[idx].rm_eo + off;
                bs_case_append (out, pat->str + s, e - s, &mode, &one);
            }
        }
        else if (*r == '\\' && r[1]) {
            r++;
            const char *end = r;
            unsigned char value;
            if (bs_numeric_escape (&end, &value)) {
                char ch = (char) value;
                bs_case_append (out, &ch, 1, &mode, &one);
                r = end - 1; continue;
            }
            /* Case-conversion directives (GNU sed). */
            switch (*r) {
                case 'U': mode = 'U'; continue;
                case 'L': mode = 'L'; continue;
                case 'E': mode = 0;   continue;
                case 'u': one  = 'u'; continue;
                case 'l': one  = 'l'; continue;
            }
            /* Recognized escape sequences: \n \t \\ ; everything else
               passes through as the literal character (matches GNU sed). */
            char e_ch;
            switch (*r) {
                case 'n': e_ch = '\n'; break;
                case 't': e_ch = '\t'; break;
                case 'r': e_ch = '\r'; break;
                case 'a': e_ch = '\a'; break;
                case 'f': e_ch = '\f'; break;
                case 'v': e_ch = '\v'; break;
                case '\\': e_ch = '\\'; break;
                default:  e_ch = *r;   break;
            }
            bs_case_append (out, &e_ch, 1, &mode, &one);
        }
        else if (*r == '&') {
            size_t s = (size_t) m[0].rm_so + off;
            size_t e = (size_t) m[0].rm_eo + off;
            bs_case_append (out, pat->str + s, e - s, &mode, &one);
        }
        else {
            bs_case_append (out, r, 1, &mode, &one);
        }
    }
}

/* Substitution output buffer, reused across calls and swapped with the
   pattern space on success; released when the invocation ends. */
static bs_string bs_s_scratch;

/* Literal search. For short needles, memchr plus memcmp avoids the per-call
   setup of some libcs' two-way memmem (musl), with at most nl comparisons per
   candidate; longer needles keep memmem's linear bound. */
static const char *
bs_find (const char *h, size_t hl, const char *n, size_t nl)
{
    if (nl > hl) return NULL;
    if (nl > 32) return memmem (h, hl, n, nl);
    const char *end = h + (hl - nl) + 1;
    while (h < end) {
        const char *p = memchr (h, (unsigned char) n[0], (size_t) (end - h));
        if (!p) return NULL;
        if (!memcmp (p + 1, n + 1, nl - 1)) return p;
        h = p + 1;
    }
    return NULL;
}

/* Apply s/// to pattern space. Returns 1 if matched (and substituted).
   s///e output loses one trailing record separator. GNU sed's shortcut for
   an empty replacement whose first match starts a non-global substitution
   or ends the pattern space also marks the result as a complete record;
   *chomped mirrors that. */
static int
bs_apply_s (bs_cmd *c, bs_string *pat, int *chomped)
{
    regmatch_t m[10];
    int matched_any = 0;
    size_t off = 0;
    /* Effective regex: an empty s// reuses the last regex used at runtime. */
    regex_t *re = c->s_empty_re ? bs_last_re : &c->s_re;
    if (!re) { builtin_error ("no previous regular expression"); bs_runtime_error = 1; return -1; }
    bs_last_re = re;
    if ((size_t) c->s_needed_sub > re->re_nsub) {
        builtin_error ("invalid backreference in replacement"); bs_runtime_error = 1; return -1;
    }
    bs_string out = bs_s_scratch;
    out.len = 0; out.failed = 0;
    if (bs_str_reserve (&out, pat->len) < 0) {
        bs_s_scratch = out; bs_s_scratch.failed = 0;
        bs_runtime_error = 1; return -1;
    }
    out.str[0] = '\0';
    /* A byte search is equivalent for ASCII subjects in every locale and
       for arbitrary byte subjects in a single-byte locale. Keep the regex
       engine for multibyte text, including invalid encoding sequences. */
    int literal = c->s_literal != NULL;
    if (literal && MB_CUR_MAX > 1) {
        for (size_t i = 0; i < pat->len; i++)
            if ((unsigned char) pat->str[i] >= 0x80) { literal = 0; break; }
    }

    /* POSIX/GNU occurrence semantics. `s_n` is the numeric flag (0 if absent):
         s///        -> replace occurrence 1 only      (start=1, !global)
         s///g       -> replace all from occurrence 1  (start=1, global)
         s///N       -> replace occurrence N only      (start=N, !global)
         s///Ng      -> replace occurrence N and after (start=N, global)
       Occurrences before `start` are copied through unchanged. */
    int start = c->s_n > 0 ? c->s_n : 1;
    int idx = 0;                       /* 1-based occurrence counter */
    size_t last_end = (size_t) -1;     /* abs end of previous match (none yet) */
    int completes = 0;                 /* GNU empty-replacement shortcut */
    int first = 1;

    while (off <= pat->len)
    {
        if (literal) {
            const char *hit = bs_find (pat->str + off, pat->len - off,
                                       c->s_literal, c->s_literal_len);
            if (!hit) break;
            m[0].rm_so = (regoff_t) (hit - pat->str - off);
            m[0].rm_eo = m[0].rm_so + (regoff_t) c->s_literal_len;
            if (!c->s_repl_literal)
                for (int i = 1; i < 10; i++) m[i].rm_so = m[i].rm_eo = -1;
        }
        else if (bs_search (re, pat->str, pat->len, off, 10, m) != 0) {
            if (bs_runtime_error) {
                out.len = 0; out.failed = 0;
                bs_s_scratch = out;
                return -1;
            }
            break;
        }
        if (first) {
            first = 0;
            completes = c->s_repl_len == 0 && c->s_n <= 1
                && ((m[0].rm_so == 0 && !c->s_global) || (size_t) m[0].rm_eo == pat->len);
        }
        /* GNU/POSIX: an empty match is suppressed when it sits exactly at the
           end of the previous match (prevents a spurious extra replacement
           when a star-quantified pattern matches non-empty then empty at the
           same spot). Copy the lead-up + one char and skip. */
        if (m[0].rm_so == m[0].rm_eo
            && (size_t) (off + m[0].rm_so) == last_end)
        {
            if (m[0].rm_so > 0)
                bs_str_append (&out, pat->str + off, (size_t) m[0].rm_so);
            off += (size_t) m[0].rm_so;
            if (off < pat->len) {
                bs_str_append (&out, pat->str + off, 1); off++;
            }
            else off = pat->len + 1;
            continue;
        }
        idx++;
        int do_sub = (idx >= start) && (c->s_global || idx == start);
        int last_for_nonglobal = (do_sub && !c->s_global);  /* stop after this one */

        if (m[0].rm_so == m[0].rm_eo)
        {
            /* zero-width match: first copy any text BEFORE the match position
               (e.g. `$` matches empty at end-of-string, rm_so > 0), then
               (optionally) emit the replacement, then advance one char to
               avoid an infinite loop. POSIX/GNU: 's/X<star>/Y/g' on "ab"
               produces "YaYbY"; 's/$/!/' on "abc" produces "abc!". */
            if (m[0].rm_so > 0)
                bs_str_append (&out, pat->str + off, (size_t) m[0].rm_so);
            if (do_sub) { bs_emit_replace (c, pat, m, off, &out); matched_any = 1; }
            off += (size_t) m[0].rm_so;   /* advance to the match position */
            last_end = off;               /* this empty match ends here */
            if (last_for_nonglobal)
            {
                if (off < pat->len) bs_str_append (&out, pat->str + off, pat->len - off);
                off = pat->len + 1;
                break;
            }
            if (off < pat->len) {
                bs_str_append (&out, pat->str + off, 1); off++;
            } else off++;
            continue;
        }
        /* Append the lead-up. */
        bs_str_append (&out, pat->str + off, (size_t) m[0].rm_so);
        if (do_sub) { bs_emit_replace (c, pat, m, off, &out); matched_any = 1; }
        else        /* occurrence skipped (< Nth): copy it through verbatim */
            bs_str_append (&out, pat->str + off + (size_t) m[0].rm_so,
                           (size_t) (m[0].rm_eo - m[0].rm_so));
        off += (size_t) m[0].rm_eo;
        last_end = off;                   /* non-empty match ends here */
        if (last_for_nonglobal)
        {
            /* Append rest of pattern. */
            if (off < pat->len) bs_str_append (&out, pat->str + off, pat->len - off);
            off = pat->len + 1;
            break;
        }
    }
    if (matched_any && !out.failed)
    {
        if (off <= pat->len)
            bs_str_append (&out, pat->str + off, pat->len - off);
        if (!out.failed) {
            if (c->s_exec) {
                bs_string exec_out;
                bs_str_init (&exec_out);
                int failed = bs_exec_capture (out.str, &exec_out, 1) < 0;
                if (!failed) bs_str_set (pat, exec_out.str ? exec_out.str : "", exec_out.len);
                bs_str_free (&exec_out);
                bs_s_scratch = out;
                if (failed) return -1;
                if (completes) *chomped = 1;
                return matched_any;
            }
            bs_string old = *pat;
            *pat = out;
            out = old;
        }
    }
    /* An allocation failure must not pass for an unchanged pattern space. */
    int failed = out.failed;
    out.len = 0; out.failed = 0;
    bs_s_scratch = out;
    if (failed) { bs_runtime_error = 1; return -1; }
    return matched_any;
}

/* --follow-symlinks: resolve PATH one link at a time the way GNU sed names
   it: a relative target is taken relative to the link's directory, so F can
   report "sub/../file". Returns a malloc'd name, or NULL after reporting. */
static char *
bs_follow (const char *path)
{
    char *cur = strdup (path);
    for (int depth = 0; cur; depth++) {
        struct stat sb;
        if (lstat (cur, &sb) != 0) {
            builtin_error ("couldn't follow symlink %s: %s", cur, strerror (errno));
            break;
        }
        if (!S_ISLNK (sb.st_mode)) return cur;
        if (depth >= 40) {
            builtin_error ("couldn't follow symlink %s: %s", path, strerror (ELOOP));
            break;
        }
        size_t cap = 128;
        char *target = NULL;
        ssize_t n;
        for (;;) {
            char *bigger = cap <= SIZE_MAX / 2 ? realloc (target, cap) : NULL;
            if (!bigger) { n = -1; errno = ENOMEM; break; }
            target = bigger;
            n = readlink (cur, target, cap);
            if (n < 0 || (size_t) n < cap) break;
            cap *= 2;
        }
        if (n < 0) {
            builtin_error ("couldn't readlink %s: %s", cur, strerror (errno));
            free (target); break;
        }
        target[n] = '\0';
        const char *slash = strrchr (cur, '/');
        char *next = target;
        if (target[0] != '/' && slash) {
            size_t dir = (size_t) (slash - cur) + 1;
            next = malloc (dir + (size_t) n + 1);
            if (next) { memcpy (next, cur, dir); memcpy (next + dir, target, (size_t) n + 1); }
            free (target);
        }
        free (cur);
        cur = next;
    }
    free (cur);
    return NULL;
}

/* One invocation edits a concatenation of operands. Only -s and -i start
   separate cycles. Input ownership, stdio reconciliation and output buffering
   live here so n/N and dollar lookahead can cross empty/error operands too. */
typedef struct {
    FILE *fp;
    const char **files;
    int count, next, owned, use_stdin, seekable, error, buffer_output;
    const char *name;
    char *resolved;      /* --follow-symlinks name of the current operand */
    bs_output *out;
    FILE *buffered;
} bs_input;

static void
bs_input_close (bs_input *in)
{
    if (!in->fp) return;
    if (ferror (in->fp) && !bs_interrupted ()) {
        builtin_error ("%s: read error: %s", in->name, strerror (errno));
        in->error = 4;
    }
    if (!in->owned) { in->fp = NULL; return; }
    if (in->buffered) {
        if (fclose (in->buffered) != 0) in->error = 4;
        in->buffered = NULL;
        in->out->fp = stdout;
    }
    if (in->use_stdin && in->seekable && fseeko (in->fp, 0, SEEK_CUR) != 0)
        in->error = 4;
    if (fclose (in->fp) != 0) in->error = 4;
    in->fp = NULL;
}

static int
bs_input_open (bs_input *in)
{
    while (in->next < in->count && !bs_interrupted ()) {
        in->name = in->files[in->next++];
        in->use_stdin = !strcmp (in->name, "-");
        free (in->resolved); in->resolved = NULL;
        if (bs_follow_symlinks && !in->use_stdin) {
            if (!(in->resolved = bs_follow (in->name))) { in->error = 4; return 0; }
            in->name = in->resolved;
        }
        int fd = in->use_stdin ? dup (STDIN_FILENO) : open (in->name, O_RDONLY);
        in->fp = fd < 0 ? NULL : fdopen (fd, "r");
        if (!in->fp) {
            builtin_error ("%s: %s", in->name, strerror (errno));
            if (fd >= 0) close (fd);
            if (in->use_stdin) in->error = 4;
            else if (in->error < 2) in->error = 2;
            continue;
        }
        in->owned = 1;
        in->seekable = lseek (fd, 0, SEEK_CUR) != (off_t) -1;
        if (!in->seekable) setvbuf (in->fp, NULL, _IONBF, 0);
        struct stat sb;
        if (in->buffer_output && fstat (fd, &sb) == 0 && S_ISREG (sb.st_mode)
            && fflush (stdout) == 0) {
            int outfd = dup (STDOUT_FILENO);
            in->buffered = outfd < 0 ? NULL : fdopen (outfd, "w");
            if (in->buffered) in->out->fp = in->buffered;
            else if (outfd >= 0) close (outfd);
        }
        return 1;
    }
    return 0;
}

static ssize_t
bs_input_read (bs_input *in, char **line, size_t *cap)
{
    for (;;) {
        if (bs_interrupted () || in->error >= 4) return -1;
        if (ferror (in->out->fp)) { bs_io_error = 4; return -1; }
        if (!in->fp && !bs_input_open (in)) return -1;
        ssize_t n = getdelim (line, cap, bs_delim, in->fp);
        if (n >= 0) return n;
        bs_input_close (in);
    }
}

/* No byte removed from a Linux pipe may be lost to the next shell reader.
   tee duplicates one byte to a private pipe, leaving the source untouched.
   Like getc, it waits for data or EOF when a live producer has no data yet. */
static int
bs_input_peek (bs_input *in)
{
    struct stat sb;
    int fd = fileno (in->fp);
    if (!in->seekable && fstat (fd, &sb) == 0) {
#if defined (__linux__) && defined (SYS_tee) && !defined (BASHSED_PORTABLE_PEEK)
        if (S_ISFIFO (sb.st_mode)) {
            int probe[2];
            if (pipe (probe) != 0) { in->error = 4; return EOF; }
            ssize_t n;
            do n = syscall (SYS_tee, fd, probe[1], 1, 0); while (n < 0 && errno == EINTR && !bs_interrupted ());
            close (probe[0]); close (probe[1]);
            if (n < 0) in->error = 4;
            return n > 0 ? 0 : EOF;
        }
#endif
        if (S_ISSOCK (sb.st_mode)) {
            char byte;
            ssize_t n;
            do n = recv (fd, &byte, 1, MSG_PEEK); while (n < 0 && errno == EINTR && !bs_interrupted ());
            if (n < 0) in->error = 4;
            return n > 0 ? 0 : EOF;
        }
#if defined (FIONREAD)
        if (S_ISFIFO (sb.st_mode) || isatty (fd)) {
            struct pollfd ready = { fd, POLLIN, 0 };
            int timeout = -1, raw_threshold = 0;
            struct termios settings;
            if (isatty (fd) && tcgetattr (fd, &settings) == 0
                && !(settings.c_lflag & ICANON)) {
                if (settings.c_cc[VMIN] == 0)
                    timeout = settings.c_cc[VTIME] * 100;
                else if (settings.c_cc[VMIN] > 1) {
                    /* A one-byte read needs only one byte, but poll can wait
                       for VMIN bytes. Recheck the count without changing the
                       caller's terminal settings or consuming its input. */
                    timeout = 50;
                    raw_threshold = 1;
                }
            }
            for (;;) {
                int available = 0;
                if (bs_interrupted ()) return EOF;
                if (ioctl (fd, FIONREAD, &available) < 0) {
                    in->error = 4; return EOF;
                }
                if (available > 0) return 0;
                int rc;
                do rc = poll (&ready, 1, timeout); while (rc < 0 && errno == EINTR && !bs_interrupted ());
                if (rc < 0 || ioctl (fd, FIONREAD, &available) < 0) {
                    in->error = 4; return EOF;
                }
                if (available > 0) return 0;
                if (rc == 0 && raw_threshold) continue;
                /* Readable canonical tty with zero bytes denotes an EOF
                   marker; a drained pipe reports POLLHUP. */
                return EOF;
            }
        }
#endif
    }
    int ch = getc (in->fp);
    if (ch != EOF) ungetc (ch, in->fp);
    return ch;
}

static int
bs_input_last (bs_input *in)
{
    for (;;) {
        if (bs_interrupted () || in->error >= 4) return 1;
        if (!in->fp && !bs_input_open (in)) return 1;
        if (bs_input_peek (in) != EOF) return 0;
        bs_input_close (in);
    }
}

static int
bs_input_addr_match (bs_addr *addr, long lineno, int *is_last,
                     const bs_string *pat, bs_input *in)
{
    if (addr->kind == BS_ADDR_LAST && *is_last < 0)
        *is_last = bs_input_last (in);
    if (in->error >= 4) { bs_runtime_error = 1; return 0; }
    return bs_addr_match (addr, lineno, *is_last > 0, pat->str, pat->len);
}

/* Run the script over an input stream. Returns 0 on success. */
static int
bs_run (bs_cmd *cmds, int n_cmds, bs_input *in, bs_output *out, int suppress_default)
{
    char *cur = NULL;
    size_t cur_cap = 0;
    ssize_t rd;
    int pat_nl = 1, hold_nl = 1, append_pending = 0;

    bs_string pat, hold, a_queue;
    bs_str_init (&pat); bs_str_init (&hold); bs_str_init (&a_queue);

    bs_runtime_error = 0;

    /* range_active[i]: 1 if a 2-address range is currently open for cmd i.
       range_end[i]: computed end line for ,+N / ,~N relative end-addresses. */
    int *range_active = calloc ((size_t) n_cmds, sizeof *range_active);
    long *range_end = calloc ((size_t) n_cmds, sizeof *range_end);

    /* GNU `0,/re/`: a range whose start address is line 0 is active from the
       very first line, so addr2 (a regex) can close it on line 1 — unlike
       `1,/re/`, where addr2 is not tested until line 2. Pre-open these. */
    if (range_active)
        for (int i = 0; i < n_cmds; i++)
            if (cmds[i].has_a1 && cmds[i].has_a2
                && cmds[i].addr1.kind == BS_ADDR_LINE && cmds[i].addr1.line == 0
                && cmds[i].addr2.kind == BS_ADDR_REGEX)
                range_active[i] = 1;

    if (n_cmds && (!range_active || !range_end)) {
        bs_runtime_error = 1;
        goto done;
    }
    long lineno = 0;
    while ((rd = bs_input_read (in, &cur, &cur_cap)) >= 0)
    {
        lineno++;
        pat_nl = rd > 0 && cur[rd - 1] == bs_delim;
        int is_last = -1;
        bs_str_set (&pat, cur, (size_t) rd - pat_nl);

        int last_subst = 0;
        int suppress_this_line = 0;   /* set by BS_C */
    restart_script:
        for (int ci = 0; ci < n_cmds; ci++)
        {
            if (bs_interrupted ()) { bs_runtime_error = 1; goto done; }
            if (ferror (out->fp)) goto done;
            bs_cmd *c = &cmds[ci];

            /* Address matching. */
            int addr_match = 1;
            if (c->has_a1 && !c->has_a2)
            {
                addr_match = bs_input_addr_match (&c->addr1, lineno, &is_last, &pat, in);
            }
            else if (c->has_a1 && c->has_a2)
            {
                if (range_active[ci])
                {
                    addr_match = 1;
                    int close;
                    if (c->addr2.kind == BS_ADDR_PLUS || c->addr2.kind == BS_ADDR_MULT)
                        close = (lineno >= range_end[ci]);
                    else if (c->addr2.kind == BS_ADDR_LINE)
                        close = lineno >= c->addr2.line;
                    else
                        close = bs_input_addr_match (&c->addr2, lineno, &is_last, &pat, in);
                    if (close) range_active[ci] = 0;
                }
                else if (bs_input_addr_match (&c->addr1, lineno, &is_last, &pat, in))
                {
                    addr_match = 1;
                    range_active[ci] = 1;
                    if (c->addr2.kind == BS_ADDR_PLUS) {
                        /* ,+N : end N lines after addr1; +0 = single line. */
                        range_end[ci] = c->addr2.step > LONG_MAX - lineno ? LONG_MAX : lineno + c->addr2.step;
                        if (lineno >= range_end[ci]) range_active[ci] = 0;
                    }
                    else if (c->addr2.kind == BS_ADDR_MULT) {
                        /* ,~N : next multiple of N strictly after addr1. */
                        long N = c->addr2.step;
                        if (N <= 0) range_active[ci] = 0;
                        else range_end[ci] = N > LONG_MAX - (lineno / N) * N ? LONG_MAX : (lineno / N + 1) * N;
                    }
                    /* A regexp end-address is only tested from the line AFTER
                       addr1 (POSIX/GNU), so it can never close the range on the
                       opening line. A line-number/$ end-address may yield a
                       single-line range when it already holds here. */
                    else if (c->addr2.kind == BS_ADDR_LINE && lineno >= c->addr2.line)
                        range_active[ci] = 0;
                    else if (c->addr2.kind != BS_ADDR_REGEX
                        && bs_input_addr_match (&c->addr2, lineno, &is_last, &pat, in))
                        range_active[ci] = 0;
                }
                else addr_match = 0;
            }
            if (bs_runtime_error) goto done;
            if (c->negate) addr_match = !addr_match;
            if (!addr_match) {
                /* For BLOCK_OPEN with no match, skip to matching close. */
                if (c->kind == BS_BLOCK_OPEN) ci = c->block_close_idx;
                continue;
            }

            switch (c->kind)
            {
                case BS_S:
                {
                    int substituted = bs_apply_s (c, &pat, &pat_nl);
                    if (substituted < 0) goto done;
                    last_subst |= substituted;
                    if (substituted && c->s_print) {
                        bs_emit (out, pat.str, pat.len, pat_nl);
                    }
                    /* s///w FILE: on a successful substitution, write the
                       resulting pattern space to FILE. */
                    if (substituted && c->s_wfile) {
                        bs_output *wf = bs_get_wstream (c->s_wfile);
                        if (wf) bs_emit (wf, pat.str, pat.len, pat_nl);
                    }
                    break;
                }
                case BS_D:
                    /* Skip to next input line. */
                    pat.len = 0;
                    if (pat.str) pat.str[0] = '\0';
                    goto next_line;
                case BS_P:
                    bs_emit (out, pat.str, pat.len, pat_nl);
                    break;
                case BS_Q:
                    if (!suppress_default) {
                        bs_emit (out, pat.str, pat.len, pat_nl);
                    }
                    bs_flush_queue (out, &a_queue, &append_pending);
                    bs_quit_signaled = 1; bs_quit_code = c->q_code;
                    goto done;
                case BS_BIGQ:
                    /* Q: quit immediately WITHOUT auto-printing the line. */
                    bs_quit_signaled = 1; bs_quit_code = c->q_code;
                    goto done;
                case BS_EQ:
                    if (out->missing_newline) fputc (bs_delim, out->fp);
                    fprintf (out->fp, "%ld", lineno);
                    fputc (bs_delim, out->fp);
                    if (bs_unbuffered) fflush (out->fp);
                    out->missing_newline = 0;
                    break;
                case BS_F:
                    /* Print the current input filename ("-" for stdin). */
                    bs_emit (out, in->name ? in->name : "-",
                             strlen (in->name ? in->name : "-"), 1);
                    break;
                case BS_E: {
                    bs_string exec_out;
                    bs_str_init (&exec_out);
                    if (bs_exec_capture (c->text ? c->text : pat.str ? pat.str : "",
                                         &exec_out, !c->text) < 0) {
                        bs_str_free (&exec_out);
                        goto done;
                    }
                    if (c->text) {
                        /* e COMMAND: its output precedes this cycle's output. */
                        if (out->missing_newline) fputc (bs_delim, out->fp);
                        out->missing_newline = 0;
                        if (exec_out.len) fwrite (exec_out.str, 1, exec_out.len, out->fp);
                        if (bs_unbuffered) fflush (out->fp);
                    } else {
                        /* The result is a complete record even if the input
                           record was not (GNU sed). */
                        bs_str_set (&pat, exec_out.str ? exec_out.str : "", exec_out.len);
                        pat_nl = 1;
                    }
                    bs_str_free (&exec_out);
                    break;
                }
                case BS_Z:
                    pat.len = 0;
                    if (pat.str) pat.str[0] = '\0';
                    break;
                case BS_H:
                    bs_str_set (&hold, pat.str, pat.len);
                    hold_nl = pat_nl;
                    break;
                case BS_HUP:
                    bs_str_append (&hold, &bs_delim, 1);
                    bs_str_append (&hold, pat.str, pat.len);
                    hold_nl = pat_nl;
                    break;
                case BS_G:
                    bs_str_set (&pat, hold.str ? hold.str : "", hold.len);
                    pat_nl = hold_nl;
                    break;
                case BS_GUP:
                    bs_str_append (&pat, &bs_delim, 1);
                    bs_str_append (&pat, hold.str ? hold.str : "", hold.len);
                    pat_nl = hold_nl;
                    break;
                case BS_X:
                {
                    bs_string tmp = pat; pat = hold; hold = tmp;
                    int tmp_nl = pat_nl; pat_nl = hold_nl; hold_nl = tmp_nl;
                    break;
                }
                case BS_LABEL:
                case BS_BLOCK_OPEN:
                case BS_BLOCK_CLOSE:
                    break;
                case BS_B:
                    if (c->target_idx >= 0) ci = c->target_idx;
                    else ci = n_cmds;       /* branch to end */
                    break;
                case BS_T:
                    if (last_subst) {
                        last_subst = 0;
                        if (c->target_idx >= 0) ci = c->target_idx;
                        else ci = n_cmds;
                    }
                    break;
                case BS_BIGT:
                    /* Branch if NO s/// has succeeded since the last input line
                       or branch taken. The flag is reset when the branch is
                       taken (it is already 0 here) — mirror of BS_T. */
                    if (!last_subst) {
                        if (c->target_idx >= 0) ci = c->target_idx;
                        else ci = n_cmds;
                    }
                    last_subst = 0;
                    break;
                case BS_I:
                    /* Insert: emit text immediately (before pat prints). */
                    if (c->text) bs_emit (out, c->text, strlen (c->text), 1);
                    break;
                case BS_Y:
                    /* Transliterate per the y_table. */
                    if (c->y_active && pat.str) {
                        for (size_t i = 0; i < pat.len; i++)
                            pat.str[i] = (char) c->y_table[(unsigned char) pat.str[i]];
                    }
                    break;
                case BS_P_LO:
                    /* Print pattern up to first \n (or whole pattern if none). */
                    if (pat.str) {
                        size_t i = 0;
                        while (i < pat.len && pat.str[i] != bs_delim) i++;
                        bs_emit (out, pat.str, i, i < pat.len || pat_nl);
                    }
                    break;
                case BS_L_CMD:
                    /* Print pattern with sed l-command escapes. */
                    if (pat.str) {
                        if (out->missing_newline) fputc (bs_delim, out->fp);
                        bs_l_emit (out->fp, pat.str, pat.len,
                                   c->l_width < 0 ? bs_list_width : c->l_width);
                        out->missing_newline = 0;
                    }
                    break;
                case BS_N_CMD:
                    if (!suppress_default) {
                        bs_emit (out, pat.str, pat.len, pat_nl);
                    }
                    if (append_pending) bs_flush_queue (out, &a_queue, &append_pending);
                    rd = bs_input_read (in, &cur, &cur_cap);
                    if (rd < 0) goto done;
                    lineno++;
                    pat_nl = rd > 0 && cur[rd - 1] == bs_delim;
                    is_last = -1;
                    last_subst = 0;
                    bs_str_set (&pat, cur, (size_t) rd - pat_nl);
                    suppress_this_line = 0;
                    break;
                case BS_NUP_CMD:
                    /* GNU checks EOF before draining the append queue. At
                       EOF, print the current pattern before queued r/R data. */
                    if (bs_input_last (in)) {
                        if (in->error >= 4 || bs_interrupted ()) goto done;
                        if (!suppress_default) bs_emit (out, pat.str, pat.len, pat_nl);
                        if (append_pending) bs_flush_queue (out, &a_queue, &append_pending);
                        goto done;
                    }
                    if (append_pending) bs_flush_queue (out, &a_queue, &append_pending);
                    rd = bs_input_read (in, &cur, &cur_cap);
                    if (rd < 0) {
                        if (!suppress_default) bs_emit (out, pat.str, pat.len, pat_nl);
                        goto done;
                    }
                    bs_str_append (&pat, &bs_delim, 1);
                    pat_nl = rd > 0 && cur[rd - 1] == bs_delim;
                    bs_str_append (&pat, cur, (size_t) rd - pat_nl);
                    lineno++;
                    is_last = -1;
                    last_subst = 0;
                    break;
                case BS_D_LO:
                    if (pat.str) {
                        char *nl = memchr (pat.str, bs_delim, pat.len);
                        if (nl) {
                            size_t drop = (size_t) (nl - pat.str) + 1;
                            size_t rest = pat.len - drop;
                            memmove (pat.str, pat.str + drop, rest);
                            pat.str[rest] = '\0';
                            pat.len = rest;
                            suppress_this_line = 0;
                            goto restart_script;
                        }
                    }
                    pat.len = 0;
                    if (pat.str) pat.str[0] = '\0';
                    goto next_line;
                    break;
                case BS_A:
                    append_pending = 1;
                    /* Append: queue text for emission after pat default-print. */
                    if (c->text) {
                        bs_str_append (&a_queue, c->text, strlen (c->text));
                        bs_str_append (&a_queue, "\n", 1);
                    }
                    break;
                case BS_R:
                    append_pending = 1;
                    /* r FILE: queue the file's contents (verbatim) after the
                       line. A missing/unreadable file is silently ignored
                       (matches GNU sed). */
                    if (c->text && *c->text) {
                        FILE *rf = fopen (c->text, "r");
                        if (rf) {
                            char rbuf[4096]; size_t got;
                            while ((got = fread (rbuf, 1, sizeof rbuf, rf)) > 0)
                                bs_str_append (&a_queue, rbuf, got);
                            fclose (rf);
                        }
                    }
                    break;
                case BS_W: {
                    /* w FILE: preserve the pattern space line ending. */
                    bs_output *wf = bs_get_wstream (c->text);
                    if (wf) bs_emit (wf, pat.str, pat.len, pat_nl);
                    break;
                }
                case BS_BIGW: {
                    /* W FILE: write only the first line of the pattern space
                       (up to the first embedded newline). */
                    bs_output *wf = bs_get_wstream (c->text);
                    if (wf) {
                        const char *nl = memchr (pat.str, bs_delim, pat.len);
                        size_t flen = nl ? (size_t) (nl - pat.str) : pat.len;
                        bs_emit (wf, pat.str, flen, nl != NULL || pat_nl);
                    }
                    break;
                }
                case BS_BIGR: {
                    /* R FILE: queue the NEXT line from FILE after this cycle.
                       Successive R calls consume successive lines; EOF / a
                       missing file is silently ignored (matches GNU). */
                    FILE *rf = bs_get_rstream (c->text);
                    if (rf) {
                        char *rl = NULL; size_t rcap = 0;
                        ssize_t rn = getdelim (&rl, &rcap, bs_delim, rf);
                        if (rn > 0) {
                            append_pending = 1;
                            bs_str_append (&a_queue, rl, (size_t) rn);
                        }
                        free (rl);
                    }
                    break;
                }
                case BS_C:
                    /* Change: replace pat with text. For single-address,
                       always; for range, emit only when range closes
                       (i.e. addr_match was true and range_active is now 0). */
                    if (c->has_a2 && range_active[ci]) {
                        /* Mid-range: suppress pat-print but don't emit text yet. */
                        suppress_this_line = 1;
                    } else {
                        /* End of range OR single-address: emit text, suppress pat. */
                        if (c->text) bs_emit (out, c->text, strlen (c->text), 1);
                        suppress_this_line = 1;
                    }
                    break;
            }
        }
        if (!suppress_default && !suppress_this_line) {
            bs_emit (out, pat.str, pat.len, pat_nl);
        }
    next_line:
        if (append_pending) bs_flush_queue (out, &a_queue, &append_pending);
    }
done:
    if (in->error || bs_interrupted ()) bs_runtime_error = 1;
    if (fflush (out->fp) == EOF || ferror (out->fp)) {
        builtin_error ("write error: %s", strerror (errno));
        bs_runtime_error = 1; bs_io_error = 4;
    }
    if (pat.failed || hold.failed || a_queue.failed) bs_runtime_error = 1;
    bs_str_free (&pat); bs_str_free (&hold); bs_str_free (&a_queue);
    free (range_active);
    free (range_end);
    free (cur);
    return bs_runtime_error ? -1 : 0;
}

/* Parent directory of an in-place edit, pinned by descriptor. Every temp,
   backup and replacement uses this dirfd, and the entry's identity is checked
   again before those names are changed. */
typedef struct {
    int dirfd;
    char *name;
    dev_t dir_dev, ent_dev;
    ino_t dir_ino, ent_ino;
} bs_anchor;

static char *
bs_readlink_dup (int dirfd, const char *name)
{
    size_t cap = 128;
    char *target = NULL;
    for (;;) {
        if (cap > SIZE_MAX / 2) { free (target); errno = ENOMEM; return NULL; }
        char *bigger = realloc (target, cap);
        if (!bigger) { free (target); errno = ENOMEM; return NULL; }
        target = bigger;
        ssize_t n = readlinkat (dirfd, name, target, cap);
        if (n < 0) { int err = errno; free (target); errno = err; return NULL; }
        if ((size_t) n < cap) { target[n] = '\0'; return target; }
        cap *= 2;
    }
}

/* Walk PATH from dirfd. dirfd is consumed. Intermediate symlinks are resolved
   with readlinkat against the directory that holds them: an absolute target
   restarts at /, a relative target (including "..") continues from that
   directory. The final component is followed only when follow_final is set.
   depth counts symlink hops. */
static int
bs_walk (int dirfd, const char *path, int follow_final, int depth, bs_anchor *out)
{
    if (path[0] == '/') {
        close (dirfd);
        dirfd = openat (AT_FDCWD, "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dirfd < 0) return -1;
        while (*path == '/') path++;
    }
    const char *p = path;
    if (!*p) { close (dirfd); errno = EINVAL; return -1; }
    for (;;) {
        while (*p == '/') p++;
        if (!*p) { close (dirfd); errno = EINVAL; return -1; }
        const char *start = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t) (p - start);
        if (len > 255) { close (dirfd); errno = ENAMETOOLONG; return -1; }
        char comp[256];
        memcpy (comp, start, len);
        comp[len] = '\0';
        while (*p == '/') p++;
        int is_last = *p == '\0';
        if (comp[0] == '.' && comp[1] == '\0') {
            if (is_last) { close (dirfd); errno = EINVAL; return -1; }
            continue;
        }
        struct stat st;
        if (fstatat (dirfd, comp, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            int err = errno; close (dirfd); errno = err; return -1;
        }
        if (S_ISLNK (st.st_mode) && (!is_last || follow_final)) {
            if (depth >= 40) { close (dirfd); errno = ELOOP; return -1; }
            char *target = bs_readlink_dup (dirfd, comp);
            if (!target) { int err = errno; close (dirfd); errno = err; return -1; }
            if (*p) {
                size_t tlen = strlen (target), rlen = strlen (p);
                if (tlen > SIZE_MAX - rlen - 2) {
                    free (target); close (dirfd); errno = ENAMETOOLONG; return -1;
                }
                char *joined = malloc (tlen + 1 + rlen + 1);
                if (!joined) { free (target); close (dirfd); errno = ENOMEM; return -1; }
                memcpy (joined, target, tlen);
                joined[tlen] = '/';
                memcpy (joined + tlen + 1, p, rlen + 1);
                free (target);
                int rc = bs_walk (dirfd, joined, follow_final, depth + 1, out);
                free (joined);
                return rc;
            }
            int rc = bs_walk (dirfd, target, follow_final, depth + 1, out);
            free (target);
            return rc;
        }
        if (!is_last) {
            int next = openat (dirfd, comp, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (next < 0) { int err = errno; close (dirfd); errno = err; return -1; }
            close (dirfd);
            dirfd = next;
            continue;
        }
        struct stat ds;
        if (fstat (dirfd, &ds) != 0) { int err = errno; close (dirfd); errno = err; return -1; }
        out->name = strdup (comp);
        if (!out->name) { close (dirfd); errno = ENOMEM; return -1; }
        out->dirfd = dirfd;
        out->dir_dev = ds.st_dev; out->dir_ino = ds.st_ino;
        out->ent_dev = st.st_dev; out->ent_ino = st.st_ino;
        return 0;
    }
}

static int
bs_anchor_same (const bs_anchor *a)
{
    struct stat ds, es;
    if (fstat (a->dirfd, &ds) != 0) return 0;
    if (ds.st_dev != a->dir_dev || ds.st_ino != a->dir_ino) return 0;
    if (fstatat (a->dirfd, a->name, &es, AT_SYMLINK_NOFOLLOW) != 0) return 0;
    if (es.st_dev != a->ent_dev || es.st_ino != a->ent_ino) return 0;
    return 1;
}

/* In-place edit of one operand. The parent directory is held open and every
   replacement is descriptor-relative, so renaming that directory cannot
   redirect the write. --follow-symlinks resolves the final link the same way
   and still reports GNU's logical name. Without it, the final symlink is read
   through and the directory entry itself is replaced. */
static int
bs_inplace (bs_cmd *cmds, int n_cmds, const char *path, const char *suffix, int suppress_default)
{
    char *logical = NULL;
    const char *display = path;
    if (bs_follow_symlinks) {
        if (!(logical = bs_follow (path))) { bs_io_error = 4; return -1; }
        display = logical;
    }
    bs_anchor anc = { .dirfd = -1 };
    int root = openat (AT_FDCWD, path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        bs_io_error = 4; free (logical); return -1;
    }
    if (bs_walk (root, path[0] == '/' ? path + 1 : path, bs_follow_symlinks, 0, &anc) < 0) {
        int err = errno;
        builtin_error ("%s: %s", path, strerror (err));
        /* Opening a missing operand is status 2; other path errors are 4. */
        bs_io_error = (err == ENOENT || err == EACCES) ? 2 : 4;
        free (logical); return -1;
    }

    /* Nonblocking open cannot wait for a FIFO writer. The final component is
       followed for the read even when the directory entry is the symlink that
       will be replaced. */
    int infd = openat (anc.dirfd, anc.name, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (infd < 0) {
        builtin_error ("%s: %s", display, strerror (errno));
        if (bs_io_error < 2) bs_io_error = 2;
        goto fail;
    }
    struct stat src_st;
    if (fstat (infd, &src_st) != 0 || !S_ISREG (src_st.st_mode)) {
        builtin_error ("-i: not a regular file: %s", display);
        close (infd); bs_io_error = 4; goto fail;
    }
    int infl = fcntl (infd, F_GETFL);
    FILE *in = infl < 0 || fcntl (infd, F_SETFL, infl & ~O_NONBLOCK) < 0
        ? NULL : fdopen (infd, "r");
    if (!in) {
        builtin_error ("%s: %s", display, strerror (errno));
        close (infd); bs_io_error = 4; goto fail;
    }

    int rc = -1, fd = -1;
    FILE *out = NULL;
    char tmpname[64] = "";
    for (int n = 0; n < 1000; n++) {
        snprintf (tmpname, sizeof tmpname, ".bsed%d-%d", (int) getpid (), n);
        fd = openat (anc.dirfd, tmpname, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd >= 0 || errno != EEXIST) break;
    }
    if (fd < 0) {
        builtin_error ("%s: %s", display, strerror (errno));
        bs_io_error = 4; goto done;
    }
    out = fdopen (fd, "w");
    if (!out) { close (fd); unlinkat (anc.dirfd, tmpname, 0); bs_io_error = 4; goto done; }

    bs_output output = { out, 0 };
    bs_input input = { .fp = in, .name = display, .out = &output };
    rc = bs_run (cmds, n_cmds, &input, &output, suppress_default);
    if (input.error) bs_io_error = input.error;
    bs_close_rstreams ();
    int close_failed = fclose (in) != 0;
    in = NULL;
    if (close_failed) { rc = -1; bs_io_error = 4; }
    if (fchmod (fd, src_st.st_mode & 07777) < 0)
        builtin_warning ("fchmod %s: %s", display, strerror (errno));
    if (fchown (fd, src_st.st_uid, src_st.st_gid) < 0 && errno != EPERM)
        builtin_warning ("fchown %s: %s", display, strerror (errno));
    if (fclose (out) != 0) { rc = -1; bs_io_error = 4; }
    out = NULL;
    if (rc < 0) { unlinkat (anc.dirfd, tmpname, 0); goto done; }

    rc = -1;
    if (!bs_anchor_same (&anc)) {
        unlinkat (anc.dirfd, tmpname, 0);
        builtin_error ("%s: changed while editing", display);
        bs_io_error = 4; goto done;
    }
    if (suffix && *suffix) {
        if (strchr (suffix, '/')) {
            unlinkat (anc.dirfd, tmpname, 0);
            builtin_error ("backup suffix must stay in the same directory");
            bs_io_error = 4; goto done;
        }
        char bak[320];
        int bw = snprintf (bak, sizeof bak, "%s%s", anc.name, suffix);
        if (bw < 0 || (size_t) bw >= sizeof bak) {
            unlinkat (anc.dirfd, tmpname, 0);
            builtin_error ("backup path too long"); bs_io_error = 4; goto done;
        }
        if (renameat (anc.dirfd, anc.name, anc.dirfd, bak) != 0) {
            builtin_error ("rename %s -> %s: %s", display, bak, strerror (errno));
            unlinkat (anc.dirfd, tmpname, 0); bs_io_error = 4; goto done;
        }
    }
    if (renameat (anc.dirfd, tmpname, anc.dirfd, anc.name) != 0) {
        builtin_error ("rename %s: %s", display, strerror (errno));
        unlinkat (anc.dirfd, tmpname, 0); bs_io_error = 4; goto done;
    }
    rc = 0;
done:
    if (in) fclose (in);
    if (anc.dirfd >= 0) close (anc.dirfd);
    free (anc.name);
    free (logical);
    return rc;
fail:
    if (anc.dirfd >= 0) close (anc.dirfd);
    free (anc.name);
    free (logical);
    return -1;
}

int
sed_builtin (WORD_LIST *list)
{
    int suppress_default = 0, extended = 0, separate = 0;
    int inplace = 0, unbuffered = 0;
    bs_list_width = 70; bs_io_error = 0; bs_unbuffered = 0; bs_interrupt_signal = 0;
    bs_delim = '\n'; bs_sandbox = 0; bs_follow_symlinks = 0;
    char inplace_suffix[64] = {0};
    char *script = NULL;
    FILE *script_file = NULL;
    size_t script_cap = 0, script_len = 0;
    int n_files = 0, files_cap = 8;
    const char **files = malloc ((size_t) files_cap * sizeof *files);
    if (!files) return EXECUTION_FAILURE;

    /* Append text to the script buffer. */
    #define APP_SCRIPT(text, tlen, separator) do { \
        size_t chunk_len = (tlen); \
        if (chunk_len > SIZE_MAX - 2 || script_len > SIZE_MAX - chunk_len - 2) { \
            if (script_file) fclose (script_file); \
            free (files); free (script); return 4; \
        } \
        size_t need = script_len + chunk_len + 2; \
        if (script_cap < need) { \
            size_t nc = script_cap ? script_cap : 256; \
            while (nc < need) { if (nc > SIZE_MAX / 2) { nc = need; break; } nc *= 2; } \
            char *ns = realloc (script, nc); \
            if (!ns) { if (script_file) fclose (script_file); free (files); free (script); return 4; } \
            script = ns; script_cap = nc; \
        } \
        if ((separator) && script_len > 0) { script[script_len++] = '\n'; } \
        memcpy (script + script_len, (text), chunk_len); \
        script_len += chunk_len; \
        script[script_len] = '\0'; \
    } while (0)

    int script_seen = 0, options = 1;
    WORD_LIST *p = list;
    while (p)
    {
        const char *w = p->word->word;
        if (options && !strcmp (w, "--")) { options = 0; goto next_word; }
        if (options && w[0] == '-' && w[1] != '\0')
        {
            if (!strcmp (w, "--help") || !strcmp (w, "--version")) {
                if (w[2] == 'v')
                    puts ("sed (bash-os loadable) 1.0\n"
                          "GNU sed 4.9 command subset; see sed --help.");
                else {
                    puts ("bashsed: stream editor");
                    puts ("Usage: bashsed [-bnsiEuz] [-l WIDTH] [-e SCRIPT] [-f FILE] [SCRIPT] [INPUT ...]");
                    puts ("Long options: --sandbox --follow-symlinks --null-data --version");
                }
                free (files); free (script);
                int failed = fflush (stdout) == EOF || ferror (stdout);
                clearerr (stdout);
                return failed ? 4 : EXECUTION_SUCCESS;
            }
            /* GNU long spellings and attached option arguments. */
            const char *long_value = NULL;
            if (!strcmp (w, "--quiet") || !strcmp (w, "--silent")) w = "-n";
            else if (!strcmp (w, "--separate")) w = "-s";
            else if (!strcmp (w, "--regexp-extended")) w = "-E";
            else if (!strcmp (w, "--unbuffered")) w = "-u";
            else if (!strcmp (w, "--expression")) w = "-e";
            else if (!strncmp (w, "--expression=", 13)) { long_value = w + 13; w = "-e"; }
            else if (!strcmp (w, "--file")) w = "-f";
            else if (!strncmp (w, "--file=", 7)) { long_value = w + 7; w = "-f"; }
            else if (!strcmp (w, "--line-length")) w = "-l";
            else if (!strncmp (w, "--line-length=", 14)) { long_value = w + 14; w = "-l"; }
            else if (!strcmp (w, "--in-place")) w = "-i";
            else if (!strncmp (w, "--in-place=", 11)) { long_value = w + 11; w = "-i"; }
            else if (!strcmp (w, "--null-data") || !strcmp (w, "--zero-terminated")) w = "-z";
            else if (!strcmp (w, "--binary")) w = "-b";
            else if (!strcmp (w, "--sandbox")) { bs_sandbox = 1; goto next_word; }
            else if (!strcmp (w, "--follow-symlinks")) { bs_follow_symlinks = 1; goto next_word; }
            else if (w[1] == '-') {
                /* Includes --posix and --debug, which are not implemented. */
                builtin_error ("unsupported option: %s", w);
                builtin_usage ();
                free (files); free (script);
                return 1;
            }
            for (const char *c = w + 1; *c; c++)
            {
                switch (*c)
                {
                    case 'n': suppress_default = 1; break;
                    case 'E': case 'r': extended = 1; break;
                    case 's': separate = 1; break;
                    case 'u': unbuffered = 1; break;
                    case 'z': bs_delim = '\0'; break;
                    case 'b': break;   /* --binary: no text mode on POSIX */
                    case 'i': {
                        inplace = 1;
                        const char *suffix = long_value ? long_value : c + 1;
                        size_t slen = strlen (suffix);
                        if (slen >= sizeof inplace_suffix) {
                            builtin_error ("-i suffix too long");
                            free (files); free (script); return 1;
                        }
                        memcpy (inplace_suffix, suffix, slen + 1);
                        goto next_word;
                    }
                    case 'e': case 'f': case 'l': {
                        char opt = *c;
                        const char *value = long_value ? long_value : c[1] ? c + 1 : NULL;
                        if (!value) {
                            if (!p->next) {
                                builtin_error ("-%c needs an argument", opt);
                                free (files); free (script); return 1;
                            }
                            p = p->next;
                            value = p->word->word;
                        }
                        if (opt == 'l') {
                            const char *end = value;
                            if (bs_number (&end, &bs_list_width) < 0 || *end) {
                                builtin_error ("invalid list width");
                                free (files); free (script); return 1;
                            }
                        } else if (opt == 'e') {
                            APP_SCRIPT (value, strlen (value), 1);
                            script_seen = 1;
                        } else {
                            FILE *sf = script_file = fopen (value, "r");
                            if (!sf) {
                                builtin_error ("-f %s: %s", value, strerror (errno));
                                free (files); free (script); return 4;
                            }
                            char buf[4096];
                            size_t rd;
                            int first = 1;
                            while ((rd = fread (buf, 1, sizeof buf, sf)) > 0) {
                                APP_SCRIPT (buf, rd, first);
                                first = 0;
                            }
                            int failed = ferror (sf);
                            if (fclose (sf) != 0) failed = 1;
                            script_file = NULL;
                            if (failed) {
                                builtin_error ("-f %s: read error", value);
                                free (files); free (script); return 4;
                            }
                            script_seen = 1;
                        }
                        goto next_word;
                    }
                    default:
                        builtin_error ("unknown flag: -%c", *c);
                        builtin_usage ();
                        free (files); free (script);
                        return 1;
                }
            }
        }
        else
        {
            if (!script_seen)
            {
                APP_SCRIPT (w, strlen (w), 1);
                script_seen = 1;
            }
            else
            {
                if (n_files == files_cap) {
                    if (files_cap > INT_MAX / 2 || (size_t) files_cap > SIZE_MAX / sizeof *files / 2)
                        { free (files); free (script); return EXECUTION_FAILURE; }
                    int new_cap = files_cap * 2;
                    const char **bigger = realloc (files, (size_t) new_cap * sizeof *files);
                    if (!bigger) { free (files); free (script); return EXECUTION_FAILURE; }
                    files = bigger;
                    files_cap = new_cap;
                }
                files[n_files++] = w;
            }
        }
    next_word:
        p = p->next;
    }

    if (!script_seen) { free (files); free (script); builtin_error ("no script"); return 1; }

    if (!script) { script = strdup (""); if (!script) { free (files); return 4; } }
    if (script[0] == '#' && script[1] == 'n') suppress_default = 1;
    if (inplace && !n_files) {
        builtin_error ("no input files"); free (files); free (script); return 4;
    }
    bs_cmd *cmds = NULL; int n_cmds = 0;
    int parsed = bs_parse_script (script, &cmds, &n_cmds, extended);
    if (parsed < 0) {
        free (files); free (script);
        return -parsed;
    }
    bs_prog_bind (cmds, n_cmds);

    /* A script that only uses its main input/output can buffer regular
       file output. Auxiliary streams and execution retain their original
       ordering and may block, so keep immediate stdout delivery for them. */
    bs_unbuffered = unbuffered;
    int buffer_output = !unbuffered && !isatty (STDOUT_FILENO);
    for (int i = 0; i < n_cmds; i++) {
        bs_cmd *c = &cmds[i];
        if (c->kind == BS_R || c->kind == BS_BIGR
            || c->kind == BS_W || c->kind == BS_BIGW || c->kind == BS_E
            || c->s_wfile || c->s_exec) {
            buffer_output = 0;
            break;
        }
    }
    int rc = EXECUTION_SUCCESS;
    bs_stdout = (bs_output) { stdout, 0 };
    bs_stderr = (bs_output) { stderr, 0 };
    bs_wstdout = (bs_output) { stdout, 0 };
    bs_wstderr = (bs_output) { stderr, 0 };
    bs_quit_signaled = 0; bs_quit_code = 0; bs_last_re = NULL;
    /* GNU opens write destinations even when no input or no match reaches
       their command. Keep handles invocation-owned for error recovery. */
    for (int i = 0; i < n_cmds; i++) {
        bs_cmd *c = &cmds[i];
        if (c->kind == BS_W || c->kind == BS_BIGW) bs_get_wstream (c->text);
        if (c->s_wfile) bs_get_wstream (c->s_wfile);
    }
    if (bs_io_error) rc = bs_io_error;
    else if (inplace)
    {
        for (int i = 0; i < n_files; i++) {
            if (bs_inplace (cmds, n_cmds, files[i], inplace_suffix, suppress_default) < 0)
                rc = EXECUTION_FAILURE;
            if (bs_quit_signaled) {
                if (rc == EXECUTION_SUCCESS) rc = bs_quit_code;
                break;
            }
        }
    }
    else
    {
        const char *standard_input = "-";
        int count = n_files ? n_files : 1;
        const char **operands = n_files ? files : &standard_input;
        for (int i = 0; i < count; ) {
            bs_input input = { .files = operands + i, .count = separate ? 1 : count,
                               .out = &bs_stdout, .buffer_output = buffer_output };
            if (bs_run (cmds, n_cmds, &input, &bs_stdout, suppress_default) < 0)
                rc = EXECUTION_FAILURE;
            bs_input_close (&input);
            free (input.resolved);
            if (input.error) rc = input.error;
            if (bs_quit_signaled) {
                if (rc == EXECUTION_SUCCESS) rc = bs_quit_code;
                break;
            }
            if (!separate) break;
            bs_close_rstreams ();
            i++;
        }
    }

    if (bs_close_wstreams () < 0) rc = 4;
    if (fflush (stdout) == EOF || ferror (stdout)) rc = 4;
    if (fflush (stderr) == EOF || ferror (stderr)) rc = 4;
    clearerr (stdout);
    clearerr (stderr);
    bs_close_rstreams ();   /* close any `R` input files */
    bs_str_free (&bs_s_scratch);
    for (int i = 0; i < n_cmds; i++) bs_cmd_free (&cmds[i]);
    free (cmds);
    free (files);
    free (script);
    if (bs_io_error) rc = bs_io_error;
    if (bs_interrupt_signal && signal_is_trapped (bs_interrupt_signal)) {
        rc = 128 + bs_interrupt_signal;
        if (bs_interrupt_signal == SIGINT) interrupt_state = 0;
        /* The executor runs the pending trap after this return. */
    }
    QUIT;
    return rc;
}

char *sed_doc[] = {
    "POSIX-shape sed(1) — stream editor.",
    "",
    "    bashsed [-bnsiEuz] [-l WIDTH] [-e SCRIPT] [-f FILE] [SCRIPT] [INPUT ...]",
    "",
    "Commands: s/// (capture groups), d p q Q =, h H g G x z,",
    "          a/i/c TEXT, y/SET1/SET2/, n N D P l [WIDTH],",
    "          r/R FILE, w/W FILE, F, e [COMMAND] (gated), v,",
    "          :LABEL, b LABEL, t/T LABEL, { ... }, ! prefix.",
    "Addresses: $, N, FIRST~STEP, /REGEX/, \\cREGEXc, ADDR1,ADDR2, ADDR1,+N, ADDR1,~N.",
    "Replace: & = whole match; \\1..\\9 = capture groups.",
    "",
    "Flags:",
    "    -n            suppress default print",
    "    -u            unbuffered output",
    "    -l WIDTH      l-command width (zero disables wrapping)",
    "    -i [SUFFIX]   in-place edit; SUFFIX saves backup",
    "    -e SCRIPT     append SCRIPT (multiple OK)",
    "    -f FILE       read commands from FILE",
    "    -E / -r       extended regex (default BRE)",
    "    -s            separate input files (implied by -i)",
    "    -z            NUL-separated records (--null-data)",
    "    --sandbox     reject e, r, R, w and W commands",
    "    --follow-symlinks  edit and name symlink targets",
    "",
    "Security: e and s///e shell execution require BASHSED_ALLOW_EXEC=1.",
    (char *)NULL
};

struct builtin bashsed_struct = {
    "bashsed",
    sed_builtin,
    BUILTIN_ENABLED,
    sed_doc,
    "bashsed [-bnsiEuz] [-l WIDTH] [-e SCRIPT] [-f FILE] [SCRIPT] [INPUT ...]",
    0
};
