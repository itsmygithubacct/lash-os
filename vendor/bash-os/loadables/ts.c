/* SPDX-License-Identifier: MIT */
/* ts.c — tree-sitter runtime API loadable (Stages 7.A + 7.B).
 *
 * 7.A: vendor the tree-sitter runtime (~12K LoC across _tree_sitter/),
 *      expose a minimal verb surface that proves the runtime compiles
 *      and links.
 * 7.B: vendor at least one grammar (JSON; ~1K LoC under _ts_json/),
 *      register via the language-table, expose `ts parse -L LANG`
 *      that emits the root-node sexp.
 *
 * Future sub-stages add query/cursor walks (7.C), hl wrapper that
 * applies a highlight .scm query → SGR ranges (7.D), and nano
 * render-side integration (7.E).
 *
 * Verbs:
 *   ts version              print runtime ABI + lib version
 *   ts language-list        compiled-in grammars
 *   ts parse -L LANG        parse stdin via LANG → root-node sexp
 *   ts query / highlight / cursor-walk, and the handle API
 *   (parse-tree / edit / root / node-* / free) — see ts_doc below.
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
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>

#include "loadables.h"
#include "_tree_sitter_api.h"

/* ---- Handle design (Stage 7.C closure) -------------------------------
 *
 * Handles are SELF-DESCRIBING strings:
 *
 *   Tree (= root node):  T<idx>g<gen>
 *   Descendant node:     T<idx>g<gen>:<i1>,<i2>,...
 *
 * Only the tree pool is shared state; nodes encode their location as
 * a path of child indices from root. Resolving a node walks that path
 * fresh each call.
 *
 * Why not a node pool too? bash subshells (pipes / process subst /
 * command substitution) fork the loadable's static memory, allocations
 * inside the subshell never propagate back to the parent. A path-based
 * node handle survives any capture pattern — `kids=$(ts
 * node-children $T1)` works because each emitted child handle re-
 * resolves against the parent's still-live tree slot.
 *
 * Generation counter on the tree slot defeats the freed-slot-reuse
 * class of bug: free + alloc bumps the gen so old handles fail to
 * resolve.
 */
#define BASHTS_TREE_POOL_MAX 32

struct bashts_lang;

/* A slot keeps the source its tree was parsed from: highlight/query -t
   and node-text need the bytes, and `ts edit` needs the old text to
   turn byte offsets into the TSPoints ts_tree_edit requires. */
struct bashts_tree_slot {
    int       in_use;
    TSTree   *tree;
    uint32_t  gen;
    const struct bashts_lang *lang;
    char     *src;
    uint32_t  srclen;
};

static struct bashts_tree_slot bashts_tree_pool[BASHTS_TREE_POOL_MAX];

/* Generation 0 is never issued, so "T<i>g0" never resolves. */
static void
bashts_bump_gen (struct bashts_tree_slot *s)
{
    s->gen += 1;
    if (s->gen == 0) s->gen = 1;
}

static int
bashts_tree_alloc (TSTree *tree, const struct bashts_lang *lang,
                   char *src, uint32_t srclen)
{
    for (int i = 0; i < BASHTS_TREE_POOL_MAX; i++) {
        struct bashts_tree_slot *s = &bashts_tree_pool[i];
        if (!s->in_use) {
            s->in_use = 1;
            s->tree   = tree;
            s->lang   = lang;
            s->src    = src;
            s->srclen = srclen;
            bashts_bump_gen (s);
            return i;
        }
    }
    return -1;
}

/* Canonical unsigned decimal: digits only, no sign, no leading zero
   (except "0" itself), no overflow. One spelling per handle. */
static int
bashts_parse_u32 (const char *p, const char **end, uint32_t *out)
{
    if (*p < '0' || *p > '9') return -1;
    if (p[0] == '0' && p[1] >= '0' && p[1] <= '9') return -1;
    uint64_t v = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (uint64_t) (*p - '0');
        if (v > UINT32_MAX) return -1;
        p++;
    }
    *end = p;
    *out = (uint32_t) v;
    return 0;
}

/* Parse "T<idx>g<gen>" → tree_idx with gen check. The handle MAY have
   trailing ":<path>" — path bytes are returned via *path_out (NULL if
   absent). Returns -1 on miss. */
static int
bashts_resolve_tree_with_path (const char *handle, const char **path_out)
{
    if (path_out) *path_out = NULL;
    if (!handle || handle[0] != 'T') return -1;
    const char *p = handle + 1;
    uint32_t idx, gen;
    if (bashts_parse_u32 (p, &p, &idx) < 0 || idx >= BASHTS_TREE_POOL_MAX) return -1;
    if (*p != 'g') return -1;
    if (bashts_parse_u32 (p + 1, &p, &gen) < 0) return -1;
    /* Either end-of-string (root handle) or ':' followed by path. */
    if (*p != 0 && *p != ':') return -1;
    if (!bashts_tree_pool[idx].in_use) return -1;
    if (gen != bashts_tree_pool[idx].gen) return -1;
    if (path_out && *p == ':') *path_out = p + 1;
    return (int) idx;
}

/* Walk path "i1,i2,..." of absolute child indices (anonymous children
   included) from root. Sets *err = 1 on parse / out-of-bounds. */
static TSNode
bashts_walk_path (TSNode root, const char *path, int *err)
{
    *err = 0;
    if (!path || !*path) return root;
    TSNode cur = root;
    const char *p = path;
    while (*p) {
        uint32_t i;
        if (bashts_parse_u32 (p, &p, &i) < 0) { *err = 1; return cur; }
        if (i >= ts_node_child_count (cur)) { *err = 1; return cur; }
        cur = ts_node_child (cur, i);
        if (*p == ',' && p[1]) p++;
        else if (*p != 0) { *err = 1; return cur; }
    }
    return cur;
}

/* Resolve full node handle → (tree_idx, TSNode). Returns -1 on fail. */
static int
bashts_resolve_node (const char *handle, TSNode *out)
{
    const char *path = NULL;
    int t = bashts_resolve_tree_with_path (handle, &path);
    if (t < 0) return -1;
    TSNode root = ts_tree_root_node (bashts_tree_pool[t].tree);
    int err = 0;
    *out = bashts_walk_path (root, path, &err);
    if (err) return -1;
    return t;
}

static void
bashts_format_tree_handle (int idx, char *buf, size_t bufsz)
{
    snprintf (buf, bufsz, "T%dg%u", idx, (unsigned) bashts_tree_pool[idx].gen);
}

/* Builtins write through the shell's stdio; flush so a full disk, a
   closed pipe or /dev/full is reported as a failing status. */
static int
bashts_finish_output (const char *verb, int rc)
{
    if (fflush (stdout) == 0 && !ferror (stdout)) return rc;
    builtin_error ("%s: write error: %s", verb, strerror (errno ? errno : EIO));
    clearerr (stdout);
    return EXECUTION_FAILURE;
}

/* Handles are text, so reject destinations that transform values or evaluate
   array subscripts. Follow only scalar namerefs, with a cycle/depth bound. */
static int
bashts_bind_handle (const char *name, const char *value)
{
    const char *target = name;
    for (int depth = 0; depth < 64; depth++) {
        if (!target || !legal_identifier (target)) break;
        SHELL_VAR *v = find_variable_noref (target);
        if (v && (readonly_p (v) || noassign_p (v) || array_p (v) || assoc_p (v)
                  || integer_p (v) || uppercase_p (v) || lowercase_p (v) || capcase_p (v)
                  || v->dynamic_value || v->assign_func)) break;
        if (v && nameref_p (v)) { target = nameref_cell (v); continue; }
        char *copy = strdup (target);
        if (!copy) return -1;
        v = builtin_bind_variable (copy, (char *) value, 0);
        free (copy);
        return v && !readonly_p (v) && !noassign_p (v) ? 0 : -1;
    }
    builtin_error ("expected a writable text scalar variable: %s", name);
    return -1;
}

/* Each vendored grammar exposes a single ts_<lang>(void) function
   that returns its TSLanguage*. Forward-declare here. The grammar
   itself lives in scripts/loadables/_ts_<lang>/grammar.c — the
   patch-bash-loadables.sh flatten copies it as _ts_<lang>_grammar.c
   and the linker pulls in the symbol. */
extern const TSLanguage *tree_sitter_json            (void);
extern const TSLanguage *tree_sitter_toml            (void);
extern const TSLanguage *tree_sitter_bash            (void);
extern const TSLanguage *tree_sitter_markdown        (void);
extern const TSLanguage *tree_sitter_markdown_inline (void);

/* Curated highlight .scm queries baked into the binary. Vendored
   from upstream tree-sitter-<lang>/queries/highlights.scm and
   copied verbatim — keeps bash-os self-contained, no runtime
   dependency on a queries dir. Stage 7.D. */
static const char json_highlights_scm[] =
    "(pair\n"
    "  key: (_) @string.special.key)\n"
    "(string) @string\n"
    "(number) @number\n"
    "[\n"
    "  (null)\n"
    "  (true)\n"
    "  (false)\n"
    "] @constant.builtin\n"
    "(escape_sequence) @escape\n"
    "(comment) @comment\n";

/* TOML highlight subset — captures-only patterns from upstream
   tree-sitter-toml/queries/highlights.scm. The full upstream query
   includes punctuation/bracket patterns that match literal tokens
   (`"."`, `","`, `"["`); those compile fine but contribute mostly
   structural color we don't currently render meaningfully. We keep
   only the semantic captures. */
static const char toml_highlights_scm[] =
    "(bare_key) @property\n"
    "(quoted_key) @string\n"
    "(boolean) @constant.builtin\n"
    "(comment) @comment\n"
    "(string) @string\n"
    "(integer) @number\n"
    "(float) @number\n"
    "(offset_date_time) @string.special\n"
    "(local_date_time) @string.special\n"
    "(local_date) @string.special\n"
    "(local_time) @string.special\n";

typedef const TSLanguage *(*bashts_lang_fn) (void);
struct bashts_lang {
    const char *name;
    bashts_lang_fn get;
    const char *highlight_scm;   /* curated .scm; NULL = no highlights */
};

/* Bash highlight subset — node-type captures only. The
   `[ "if" "then" ... ] @keyword` literal-anon-token set that
   nvim-treesitter ships does NOT compile against this grammar version
   (TSQueryErrorNodeType at offset of "function"); the bash grammar's
   keyword tokens aren't addressable from queries as string literals.
   We rely on parent-node captures instead — coarser but stable. */
static const char bash_highlights_scm[] =
    "(comment) @comment\n"
    "(string) @string\n"
    "(raw_string) @string\n"
    "(ansi_c_string) @string\n"
    "(translated_string) @string\n"
    "(number) @number\n"
    "(variable_name) @variable\n"
    "(simple_expansion) @variable\n"
    "(command_name) @function\n"
    "(function_definition name: (word) @function)\n";

/* Markdown highlight subset — block grammar. tree-sitter-markdown
   ships block + inline as separate parsers. The block parser captures
   fenced/indented code, link refs, thematic breaks. The inline parser
   (registered separately as `markdown_inline`) covers emphasis, code
   spans, autolinks, and reference-link forms. Operators that want
   full Markdown rendering parse the same buffer through both grammars
   and merge captures by byte range. (Stage 7.B inline parser landed
   2026-05-07 PM as a follow-up to the original block-only deferral.) */
static const char markdown_highlights_scm[] =
    "(fenced_code_block) @string\n"
    "(indented_code_block) @string\n"
    "(link_destination) @string.special\n"
    "(link_title) @string\n"
    "(thematic_break) @comment\n";

/* Markdown inline grammar highlights. Captures cover the "what's
   between the block boundaries" surface that nvim-treesitter renders
   as emphasis, code spans, links, autolinks, escapes, raw HTML, and
   strikethrough. The capture-name vocabulary mirrors the existing
   SGR rule families (`string`, `string.special`, `escape`, `comment`,
   `function`) plus three new `emphasis.*` families introduced for this
   grammar (mapped to italic/bold/strikethrough SGR codes below). */
static const char markdown_inline_highlights_scm[] =
    "(emphasis) @emphasis\n"
    "(strong_emphasis) @emphasis.strong\n"
    "(strikethrough) @emphasis.strike\n"
    "(code_span) @string\n"
    "(link_text) @function\n"
    "(link_destination) @string.special\n"
    "(link_title) @string\n"
    "(uri_autolink) @string.special\n"
    "(email_autolink) @string.special\n"
    "(image_description) @function\n"
    "(html_tag) @comment\n"
    "(latex_span_delimiter) @comment\n"
    "(backslash_escape) @escape\n"
    "(entity_reference) @escape\n"
    "(numeric_character_reference) @escape\n";

static const struct bashts_lang bashts_languages[] = {
    { "json",            tree_sitter_json,            json_highlights_scm            },
    { "toml",            tree_sitter_toml,            toml_highlights_scm            },
    { "bash",            tree_sitter_bash,            bash_highlights_scm            },
    { "markdown",        tree_sitter_markdown,        markdown_highlights_scm        },
    { "markdown_inline", tree_sitter_markdown_inline, markdown_inline_highlights_scm },
    { NULL,              NULL,                        NULL                           }
};

/* Capture name → SGR code lookup. The capture-name vocabulary mirrors
   nvim-treesitter's convention: dotted names with the most-specific
   leaf first (e.g. `string.special.key`). We do longest-prefix match
   so `string.special.key` resolves before falling back to `string`.
   v1 uses 16-color SGR codes that vt's palette already renders. */
struct bashts_sgr_rule { const char *prefix; const char *code; };

static const struct bashts_sgr_rule bashts_sgr_rules[] = {
    /* Order matters: longest prefix first. */
    { "string.special.key", "1;36" },     /* bold cyan — JSON keys */
    { "string.special",     "1;35" },     /* bold magenta — TOML dates */
    { "string",             "32"   },     /* green */
    /* Markdown inline emphasis variants (Stage 7.B 2026-05-07 PM).
       Most modern terminals render SGR 3/9; ones that don't drop them
       silently which is fine — this is best-effort presentation, not
       semantics. Listed before the `string`/`number` block since none
       of those share a prefix with `emphasis.*`, but kept here as a
       cluster for readability. */
    { "emphasis.strong",    "1"    },     /* bold */
    { "emphasis.strike",    "9"    },     /* strikethrough */
    { "emphasis",           "3"    },     /* italic */
    { "number",             "33"   },     /* yellow */
    { "constant.builtin",   "35"   },     /* magenta */
    { "escape",             "1;33" },     /* bold yellow */
    { "comment",            "90"   },     /* grey */
    { "property",           "1;36" },     /* bold cyan — TOML bare keys */
    { "keyword",            "35"   },
    { "function",           "36"   },
    { "type",               "34"   },     /* blue */
    { "variable",           "37"   },
    { NULL,                 NULL   }
};

static const char *
bashts_sgr_for_capture (const char *cap, uint32_t cap_len)
{
    /* Pre-compute name-len for prefix match. */
    for (const struct bashts_sgr_rule *r = bashts_sgr_rules; r->prefix; r++) {
        size_t plen = strlen (r->prefix);
        if (cap_len < plen) continue;
        if (memcmp (cap, r->prefix, plen) == 0) return r->code;
    }
    return "37";  /* default: white */
}

/* `ts version` — prints runtime ABI version + library version.
 * Useful for verifying the linker actually pulled in the runtime. */
static int
bashts_version_cmd (WORD_LIST *args)
{
    (void) args;
    printf ("tree-sitter ABI: %u (min: %u)\n",
            (unsigned) TREE_SITTER_LANGUAGE_VERSION,
            (unsigned) TREE_SITTER_MIN_COMPATIBLE_LANGUAGE_VERSION);
    /* Smoke test: actually call into the runtime so the linker
       proves it's reachable. */
    TSParser *p = ts_parser_new ();
    if (!p) {
        builtin_error ("ts_parser_new returned NULL");
        return EXECUTION_FAILURE;
    }
    ts_parser_delete (p);
    printf ("runtime: ts_parser_new/delete round-trip OK\n");
    return bashts_finish_output ("version", EXECUTION_SUCCESS);
}

/* `ts language-list` — names of compiled-in grammars. */
static int
bashts_language_list_cmd (WORD_LIST *args)
{
    (void) args;
    for (const struct bashts_lang *l = bashts_languages; l->name; l++)
        printf ("%s\n", l->name);
    return bashts_finish_output ("language-list", EXECUTION_SUCCESS);
}

/* Slurp stdin into a malloc'd buffer. Returns 0 on success with
   *out and *len set; -1 on read error. */
static int
bashts_slurp_fd (int fd, char **out, size_t *len)
{
    size_t cap = 4096, used = 0;
    char *buf = malloc (cap);
    if (!buf) return -1;
    ssize_t n;
    while ((n = read (fd, buf + used, cap - used)) > 0) {
        used += (size_t) n;
        if (used == cap) {
            cap *= 2;
            char *nb = realloc (buf, cap);
            if (!nb) { free (buf); return -1; }
            buf = nb;
        }
    }
    if (n < 0) { free (buf); return -1; }
    *out = buf;
    *len = used;
    return 0;
}

static int
bashts_slurp_stdin (char **out, size_t *len)
{
    return bashts_slurp_fd (STDIN_FILENO, out, len);
}

/* `ts parse -L LANG` — parse stdin via LANG grammar, emit the
   root-node S-expression on stdout. Useful smoke test that the
   grammar + runtime are correctly wired; future sub-stage 7.C adds
   richer query/cursor verbs on top. */
static int
bashts_parse_cmd (WORD_LIST *args)
{
    const char *lang_name = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-L") && p->next) {
            p = p->next; lang_name = p->word->word;
        } else {
            builtin_error ("parse: unexpected arg: %s", w);
            return EX_USAGE;
        }
    }
    if (!lang_name) {
        builtin_error ("parse: -L LANG required (try `ts language-list`)");
        return EX_USAGE;
    }
    const TSLanguage *language = NULL;
    for (const struct bashts_lang *l = bashts_languages; l->name; l++) {
        if (!strcmp (l->name, lang_name)) { language = l->get (); break; }
    }
    if (!language) {
        builtin_error ("parse: unknown language: %s", lang_name);
        return EX_USAGE;
    }

    char *src = NULL;
    size_t srclen = 0;
    if (bashts_slurp_stdin (&src, &srclen) < 0) {
        builtin_error ("parse: stdin read failed");
        return EXECUTION_FAILURE;
    }

    TSParser *parser = ts_parser_new ();
    if (!ts_parser_set_language (parser, language)) {
        builtin_error ("parse: ts_parser_set_language failed (ABI mismatch?)");
        ts_parser_delete (parser);
        free (src);
        return EXECUTION_FAILURE;
    }
    TSTree *tree = ts_parser_parse_string (parser, NULL, src, (uint32_t) srclen);
    if (!tree) {
        builtin_error ("parse: ts_parser_parse_string returned NULL");
        ts_parser_delete (parser);
        free (src);
        return EXECUTION_FAILURE;
    }
    TSNode root = ts_tree_root_node (tree);
    char *sexp = ts_node_string (root);
    if (sexp) {
        printf ("%s\n", sexp);
        free (sexp);
    }
    ts_tree_delete (tree);
    ts_parser_delete (parser);
    free (src);
    return bashts_finish_output ("parse", EXECUTION_SUCCESS);
}

/* Resolve LANG name → TSLanguage*. NULL on miss. */
static const TSLanguage *
bashts_find_language (const char *name)
{
    for (const struct bashts_lang *l = bashts_languages; l->name; l++)
        if (!strcmp (l->name, name)) return l->get ();
    return NULL;
}

/* `ts query -L LANG -q QUERY` — compile QUERY against LANG's grammar,
 * parse stdin, run the query against the parse tree, emit one line per
 * capture in the format:
 *
 *     CAPTURE_NAME L1:C1-L2:C2 BYTES
 *
 * Where L/C are 1-indexed line/column from TSPoint, BYTES is the raw
 * captured text (truncated at the next newline for safety; queries
 * commonly capture multi-line nodes via the literal text being part
 * of the source — we want one line per capture).
 *
 * This is the primitive Stage 7.D hl wraps to apply a highlight .scm
 * file → SGR span ranges, and Stage 7.E nano calls per render.
 */
static int
bashts_query_cmd (WORD_LIST *args)
{
    const char *lang_name = NULL, *query_src = NULL, *tree_h = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-L") && p->next) { p = p->next; lang_name  = p->word->word; }
        else if (!strcmp (w, "-q") && p->next) { p = p->next; query_src = p->word->word; }
        else if (!strcmp (w, "-t") && p->next) { p = p->next; tree_h    = p->word->word; }
        else { builtin_error ("query: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!lang_name && !tree_h) { builtin_error ("query: -L LANG or -t TREE required"); return EX_USAGE; }
    if (!query_src)  { builtin_error ("query: -q QUERY required");  return EX_USAGE; }

    struct bashts_tree_slot *slot = NULL;
    const TSLanguage *language = NULL;
    if (tree_h) {
        const char *path = NULL;
        int t = bashts_resolve_tree_with_path (tree_h, &path);
        if (t < 0 || path) {
            builtin_error ("query: invalid tree handle: %s", tree_h);
            return EX_USAGE;
        }
        slot = &bashts_tree_pool[t];
        if (lang_name && strcmp (lang_name, slot->lang->name)) {
            builtin_error ("query: tree %s was parsed as %s, not %s",
                           tree_h, slot->lang->name, lang_name);
            return EX_USAGE;
        }
        language = slot->lang->get ();
    } else {
        language = bashts_find_language (lang_name);
        if (!language) {
            builtin_error ("query: unknown language: %s", lang_name);
            return EX_USAGE;
        }
    }

    /* Compile the query. Errors carry an offset + error-type code so we
       can give an actionable hint. */
    uint32_t qerr_off = 0;
    TSQueryError qerr = TSQueryErrorNone;
    TSQuery *query = ts_query_new (language, query_src,
                                   (uint32_t) strlen (query_src),
                                   &qerr_off, &qerr);
    if (!query) {
        const char *kind = "?";
        switch (qerr) {
        case TSQueryErrorSyntax:    kind = "syntax";    break;
        case TSQueryErrorNodeType:  kind = "node-type"; break;
        case TSQueryErrorField:     kind = "field";     break;
        case TSQueryErrorCapture:   kind = "capture";   break;
        case TSQueryErrorStructure: kind = "structure"; break;
        case TSQueryErrorLanguage:  kind = "language";  break;
        default:                    kind = "?";         break;
        }
        builtin_error ("query: %s error at byte %u of query", kind, qerr_off);
        return EXECUTION_FAILURE;
    }

    char *src = NULL;
    size_t srclen = 0;
    TSTree *tree = NULL;
    if (slot) {
        src = slot->src;
        srclen = slot->srclen;
        tree = slot->tree;
    } else {
        if (bashts_slurp_stdin (&src, &srclen) < 0) {
            builtin_error ("query: stdin read failed");
            ts_query_delete (query);
            return EXECUTION_FAILURE;
        }
        TSParser *parser = ts_parser_new ();
        if (!ts_parser_set_language (parser, language)) {
            builtin_error ("query: ts_parser_set_language failed");
            ts_parser_delete (parser);
            ts_query_delete (query);
            free (src);
            return EXECUTION_FAILURE;
        }
        tree = ts_parser_parse_string (parser, NULL, src, (uint32_t) srclen);
        ts_parser_delete (parser);
        if (!tree) {
            builtin_error ("query: parse failed");
            ts_query_delete (query);
            free (src);
            return EXECUTION_FAILURE;
        }
    }
    TSNode root = ts_tree_root_node (tree);

    TSQueryCursor *cursor = ts_query_cursor_new ();
    ts_query_cursor_exec (cursor, query, root);

    /* Iterate matches; each match has 0-N captures. Emit one line per
       capture in match order (the raw primitive; precedence is applied
       by highlight, not here). */
    TSQueryMatch match;
    while (ts_query_cursor_next_match (cursor, &match)) {
        for (uint16_t i = 0; i < match.capture_count; i++) {
            TSQueryCapture cap = match.captures[i];
            uint32_t name_len = 0;
            const char *name = ts_query_capture_name_for_id (
                query, cap.index, &name_len);
            TSPoint sp = ts_node_start_point (cap.node);
            TSPoint ep = ts_node_end_point (cap.node);
            uint32_t sb = ts_node_start_byte (cap.node);
            uint32_t eb = ts_node_end_byte  (cap.node);
            /* Truncate captured text at the first newline so output stays
               line-oriented. Real callers use the byte range to slice the
               original buffer themselves. */
            uint32_t txt_end = sb;
            while (txt_end < eb && txt_end < (uint32_t) srclen && src[txt_end] != '\n')
                txt_end++;
            printf ("%.*s %u:%u-%u:%u %u-%u %.*s\n",
                    (int) name_len, name,
                    (unsigned) (sp.row + 1), (unsigned) (sp.column + 1),
                    (unsigned) (ep.row + 1), (unsigned) (ep.column + 1),
                    sb, eb,
                    (int) (txt_end - sb), src + sb);
        }
    }

    ts_query_cursor_delete (cursor);
    ts_query_delete (query);
    if (!slot) {
        ts_tree_delete (tree);
        free (src);
    }
    return bashts_finish_output ("query", EXECUTION_SUCCESS);
}

/* ---- Capture precedence ---------------------------------------------
 *
 * A highlight query routinely captures one byte more than once: a JSON
 * object key matches both `(pair key: (_) @string.special.key)` and
 * `(string) @string`; an escape_sequence sits inside its string; a bash
 * variable_name sits inside its simple_expansion. Each byte gets exactly
 * one class, chosen by this total order — never by the order in which
 * the query cursor happens to enumerate matches:
 *
 *   1. the narrower capture wins (nested node beats its ancestor);
 *   2. equal spans: the pattern that comes first in the query wins
 *      (tree-sitter-highlight's rule, and the order the vendored
 *      highlights.scm files are written in — specific before generic);
 *   3. same pattern: the capture name declared first in the query wins;
 *   4. equal everything but position (partial overlap): earlier start.
 *
 * Captures are sorted weakest-first and painted in that order, so each
 * byte ends up owned by the strongest capture covering it.
 */
struct bashts_cap {
    uint32_t sb, eb;
    uint32_t pattern;
    uint32_t id;
};

static int
bashts_cap_weakest_first (const void *va, const void *vb)
{
    const struct bashts_cap *a = va, *b = vb;
    uint32_t la = a->eb - a->sb, lb = b->eb - b->sb;
    if (la != lb) return la > lb ? -1 : 1;
    if (a->pattern != b->pattern) return a->pattern > b->pattern ? -1 : 1;
    if (a->id != b->id) return a->id > b->id ? -1 : 1;
    if (a->sb != b->sb) return a->sb > b->sb ? -1 : 1;
    return 0;
}

/* Source order for -A listings: start, then outermost first, then
   query order. */
static int
bashts_cap_source_order (const void *va, const void *vb)
{
    const struct bashts_cap *a = va, *b = vb;
    if (a->sb != b->sb) return a->sb < b->sb ? -1 : 1;
    if (a->eb != b->eb) return a->eb > b->eb ? -1 : 1;
    if (a->pattern != b->pattern) return a->pattern < b->pattern ? -1 : 1;
    if (a->id != b->id) return a->id < b->id ? -1 : 1;
    return 0;
}

/* Run QUERY over ROOT and collect every non-empty capture, clamped to
   SRCLEN. Returns 0, or -1 on allocation failure. */
static int
bashts_collect_captures (const TSQuery *query, TSNode root, uint32_t srclen,
                         struct bashts_cap **out, size_t *count)
{
    size_t n = 0, cap = 256;
    struct bashts_cap *v = malloc (cap * sizeof *v);
    TSQueryCursor *cursor = ts_query_cursor_new ();
    if (!v || !cursor) { free (v); if (cursor) ts_query_cursor_delete (cursor); return -1; }
    ts_query_cursor_exec (cursor, query, root);
    TSQueryMatch match;
    while (ts_query_cursor_next_match (cursor, &match)) {
        for (uint16_t i = 0; i < match.capture_count; i++) {
            TSNode node = match.captures[i].node;
            uint32_t sb = ts_node_start_byte (node);
            uint32_t eb = ts_node_end_byte   (node);
            if (eb > srclen) eb = srclen;
            if (sb >= eb) continue;
            if (n == cap) {
                struct bashts_cap *nv = realloc (v, 2 * cap * sizeof *v);
                if (!nv) { free (v); ts_query_cursor_delete (cursor); return -1; }
                v = nv; cap *= 2;
            }
            v[n].sb = sb;
            v[n].eb = eb;
            v[n].pattern = match.pattern_index;
            v[n].id = match.captures[i].index;
            n++;
        }
    }
    ts_query_cursor_delete (cursor);
    *out = v;
    *count = n;
    return 0;
}

/* owner[b] = winning capture id + 1 for byte b, 0 where uncaptured.
   Reorders CAPS. */
static void
bashts_resolve_owners (struct bashts_cap *caps, size_t n, uint32_t *owner)
{
    qsort (caps, n, sizeof *caps, bashts_cap_weakest_first);
    for (size_t i = 0; i < n; i++)
        for (uint32_t b = caps[i].sb; b < caps[i].eb; b++)
            owner[b] = caps[i].id + 1;
}

/* Compiled highlight queries, one per language, built on first use and
   kept for the life of the shell: a TSQuery is immutable once built,
   and nano re-highlights on every edit. */
static TSQuery *bashts_hl_query_cache[sizeof bashts_languages / sizeof bashts_languages[0]];

static TSQuery *
bashts_highlight_query (const struct bashts_lang *l, uint32_t *off, TSQueryError *err)
{
    size_t k = (size_t) (l - bashts_languages);
    if (!bashts_hl_query_cache[k])
        bashts_hl_query_cache[k] = ts_query_new (l->get (), l->highlight_scm,
                                                 (uint32_t) strlen (l->highlight_scm),
                                                 off, err);
    return bashts_hl_query_cache[k];
}

static const struct bashts_lang *
bashts_find_lang_entry (const char *name)
{
    for (const struct bashts_lang *l = bashts_languages; l->name; l++)
        if (!strcmp (l->name, name)) return l;
    return NULL;
}

static TSTree *
bashts_parse_with (const struct bashts_lang *l, const TSTree *old,
                   const char *src, uint32_t srclen)
{
    TSParser *parser = ts_parser_new ();
    if (!parser) return NULL;
    TSTree *tree = NULL;
    if (ts_parser_set_language (parser, l->get ()))
        tree = ts_parser_parse_string (parser, old, src, srclen);
    ts_parser_delete (parser);
    return tree;
}

/* Resolve per-byte winning capture ids for LANG over (TREE, SRC).
   *owner_out is calloc'd with srclen+1 entries. Returns 0 or -1. */
static int
bashts_highlight_owners (const struct bashts_lang *l, TSTree *tree,
                         uint32_t srclen, uint32_t **owner_out,
                         TSQuery **query_out)
{
    uint32_t off = 0;
    TSQueryError qerr = TSQueryErrorNone;
    TSQuery *query = bashts_highlight_query (l, &off, &qerr);
    if (!query) return -1;
    struct bashts_cap *caps = NULL;
    size_t n = 0;
    if (bashts_collect_captures (query, ts_tree_root_node (tree), srclen, &caps, &n) < 0)
        return -1;
    uint32_t *owner = calloc ((size_t) srclen + 1, sizeof *owner);
    if (!owner) { free (caps); return -1; }
    bashts_resolve_owners (caps, n, owner);
    free (caps);
    *owner_out = owner;
    *query_out = query;
    return 0;
}

static const char *
bashts_owner_name (const TSQuery *query, uint32_t owner, uint32_t *len)
{
    return ts_query_capture_name_for_id (query, owner - 1, len);
}

/* Stage 7.E — public helper for direct C-level callers (nano during
 * bn_render). Caller provides `sgr_at[srclen]` (zero-initialized); each
 * captured byte gets the SGR code of its winning capture, by the
 * precedence order above, so nano paints exactly what `ts highlight`
 * renders. Returns 0 on success, -1 on bad lang / parse failure. The
 * pointers stay valid for the lifetime of this loadable (they're
 * `static const char[]` literals).
 */
int
bashts_compute_sgr_map (const char *lang, const char *src, size_t srclen,
                       const char **sgr_at)
{
    if (!lang || !src || !sgr_at || srclen > UINT32_MAX) return -1;
    const struct bashts_lang *langent = bashts_find_lang_entry (lang);
    if (!langent || !langent->highlight_scm) return -1;
    TSTree *tree = bashts_parse_with (langent, NULL, src, (uint32_t) srclen);
    if (!tree) return -1;
    uint32_t *owner = NULL;
    TSQuery *query = NULL;
    int rc = bashts_highlight_owners (langent, tree, (uint32_t) srclen, &owner, &query);
    ts_tree_delete (tree);
    if (rc < 0) return -1;
    uint32_t ncap = ts_query_capture_count (query);
    const char **sgr_by_owner = calloc ((size_t) ncap + 1, sizeof *sgr_by_owner);
    if (!sgr_by_owner) { free (owner); return -1; }
    for (uint32_t id = 0; id < ncap; id++) {
        uint32_t len = 0;
        const char *name = ts_query_capture_name_for_id (query, id, &len);
        sgr_by_owner[id + 1] = bashts_sgr_for_capture (name, len);
    }
    for (size_t b = 0; b < srclen; b++)
        if (owner[b]) sgr_at[b] = sgr_by_owner[owner[b]];
    free (sgr_by_owner);
    free (owner);
    return 0;
}

/* Incremental highlighting for an editor that redraws after edits.
 * *STATE (NULL at first) keeps the last tree for LANG and a copy of its
 * source. SRC is the whole current text; the changed span is found by
 * comparing it with the stored copy (shared prefix and suffix), so any
 * sequence of edits, undo included, is one ts_tree_edit and an incremental
 * reparse. Captures are then collected only for matches intersecting
 * [LO, HI), and each byte in that range gets the SGR code of its winning
 * capture in sgr_at[0 .. HI - LO) (zeroed by the caller), by the same
 * precedence as bashts_compute_sgr_map, so a byte's colour equals the
 * full map's. Returns 0, or -1 with *STATE released.
 *
 * bashts_sgr_range_budget bounds the reparse to BUDGET_US microseconds
 * (< 0: no bound). The bash grammar marks top-level statements fragile,
 * so tree-sitter cannot reuse anything after an edit and a reparse costs
 * the rest of the file. When the budget runs out, *PENDING is set and the
 * colours come from the old tree with the edits applied to its positions
 * (unchanged text keeps its colour, inserted text takes its enclosing
 * node's); before any tree exists they are all zero. bashts_sgr_continue
 * resumes the halted parse, and once it returns 1 the next call gives
 * the full map's colours again. A new text abandons a halted parse. */
struct bashts_sgr_state {
    const struct bashts_lang *lang;
    TSTree *tree;               /* parsed tree, or the edited old one if pending */
    char *src;                  /* the text the tree's positions refer to */
    uint32_t srclen;
    TSParser *parser;           /* holds a halted parse while pending */
    int pending;
};

void
bashts_sgr_state_free (void **state)
{
    struct bashts_sgr_state *st = state ? *state : NULL;
    if (!st) return;
    if (st->parser) ts_parser_delete (st->parser);
    if (st->tree) ts_tree_delete (st->tree);
    free (st->src);
    free (st);
    *state = NULL;
}

static TSPoint
bashts_point_fast (const char *src, uint32_t off)
{
    TSPoint pt = { 0, 0 };
    const char *p = src, *end = src + off, *nl;
    while (p < end && (nl = memchr (p, '\n', (size_t) (end - p)))) {
        pt.row++;
        p = nl + 1;
    }
    pt.column = (uint32_t) (end - p);
    return pt;
}

static const char *
bashts_state_read (void *payload, uint32_t byte, TSPoint pt, uint32_t *got)
{
    const struct bashts_sgr_state *st = payload;
    (void) pt;
    if (byte >= st->srclen) { *got = 0; return ""; }
    *got = st->srclen - byte;
    return st->src + byte;
}

static int64_t
bashts_now_us (void)
{
    struct timespec ts;
    clock_gettime (CLOCK_MONOTONIC, &ts);
    return (int64_t) ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

struct bashts_deadline { int64_t at; int fired; };

static bool
bashts_past_deadline (TSParseState *ps)
{
    struct bashts_deadline *d = ps->payload;
    if (bashts_now_us () < d->at) return false;
    d->fired = 1;
    return true;
}

/* Run (or resume) the pending parse for at most BUDGET_US (< 0: to the
   end). Returns 1 when it finished, 0 when the deadline halted it, -1
   on failure (which no later call would cure). */
static int
bashts_state_advance (struct bashts_sgr_state *st, long budget_us)
{
    if (!st->pending) return 1;
    if (!st->parser) {
        st->parser = ts_parser_new ();
        if (!st->parser) return -1;
        if (!ts_parser_set_language (st->parser, st->lang->get ())) return -1;
    }
    struct bashts_deadline dl = { bashts_now_us () + (budget_us < 0 ? 0 : budget_us), 0 };
    TSParseOptions opt = { &dl, budget_us < 0 ? NULL : bashts_past_deadline };
    TSInput in = { st, bashts_state_read, TSInputEncodingUTF8, NULL };
    TSTree *tree = ts_parser_parse_with_options (st->parser, st->tree, in, opt);
    if (!tree) return dl.fired ? 0 : -1;
    if (st->tree) ts_tree_delete (st->tree);
    st->tree = tree;
    st->pending = 0;
    return 1;
}

int
bashts_sgr_continue (void **state, long budget_us)
{
    struct bashts_sgr_state *st = state ? *state : NULL;
    if (!st) return -1;
    int r = bashts_state_advance (st, budget_us);
    if (r < 0) bashts_sgr_state_free (state);
    return r;
}

int bashts_sgr_range_budget (void **state, const char *lang, const char *src,
                             size_t srclen, size_t lo, size_t hi,
                             const char **sgr_at, long budget_us, int *pending);

int
bashts_sgr_range (void **state, const char *lang, const char *src, size_t srclen,
                  size_t lo, size_t hi, const char **sgr_at)
{
    return bashts_sgr_range_budget (state, lang, src, srclen, lo, hi, sgr_at, -1, NULL);
}

int
bashts_sgr_range_budget (void **state, const char *lang, const char *src,
                         size_t srclen, size_t lo, size_t hi,
                         const char **sgr_at, long budget_us, int *pending)
{
    if (pending) *pending = 0;
    if (!state || !lang || !src || !sgr_at || srclen > UINT32_MAX || srclen == SIZE_MAX || lo > hi || hi > srclen)
        return -1;
    const struct bashts_lang *l = bashts_find_lang_entry (lang);
    if (!l || !l->highlight_scm) { bashts_sgr_state_free (state); return -1; }
    struct bashts_sgr_state *st = *state;
    if (st && st->lang != l) { bashts_sgr_state_free (state); st = NULL; }
    if (!st) {
        st = calloc (1, sizeof *st);
        if (!st) return -1;
        st->lang = l;
        *state = st;
    }
    uint32_t n = (uint32_t) srclen;
    int same = st->src && st->srclen == n && memcmp (st->src, src, n) == 0;
    if (!same) {
        char *copy = malloc ((size_t) n + 1);
        if (!copy) { bashts_sgr_state_free (state); return -1; }
        memcpy (copy, src, n);
        /* A halted parse read the old text; start over from the tree. */
        if (st->parser) ts_parser_reset (st->parser);
        if (st->tree) {
            uint32_t pre = 0, max = st->srclen < n ? st->srclen : n;
            while (max - pre >= 4096 && memcmp (st->src + pre, src + pre, 4096) == 0)
                pre += 4096;
            while (pre < max && st->src[pre] == src[pre]) pre++;
            uint32_t suf = 0;
            while (max - pre - suf >= 4096
                   && memcmp (st->src + st->srclen - suf - 4096, src + n - suf - 4096, 4096) == 0)
                suf += 4096;
            while (suf < max - pre
                   && st->src[st->srclen - 1 - suf] == src[n - 1 - suf]) suf++;
            TSInputEdit e;
            e.start_byte    = pre;
            e.old_end_byte  = st->srclen - suf;
            e.new_end_byte  = n - suf;
            e.start_point   = bashts_point_fast (src, pre);
            e.old_end_point = bashts_point_fast (st->src, e.old_end_byte);
            e.new_end_point = bashts_point_fast (src, e.new_end_byte);
            ts_tree_edit (st->tree, &e);
        }
        free (st->src);
        st->src = copy;
        st->srclen = n;
        st->pending = 1;
    }
    int adv = bashts_state_advance (st, budget_us);
    if (adv < 0) { bashts_sgr_state_free (state); return -1; }
    if (pending) *pending = st->pending;
    if (hi == lo || !st->tree) return 0;

    uint32_t off = 0;
    TSQueryError qerr = TSQueryErrorNone;
    TSQuery *query = bashts_highlight_query (l, &off, &qerr);
    if (!query) return -1;
    size_t nc = 0, cap = 256;
    struct bashts_cap *v = malloc (cap * sizeof *v);
    TSQueryCursor *cursor = ts_query_cursor_new ();
    uint32_t ncap = ts_query_capture_count (query);
    const char **sgr_by_id = calloc ((size_t) ncap + 1, sizeof *sgr_by_id);
    if (!v || !cursor || !sgr_by_id) {
        free (v); free (sgr_by_id);
        if (cursor) ts_query_cursor_delete (cursor);
        return -1;
    }
    ts_query_cursor_set_byte_range (cursor, (uint32_t) lo, (uint32_t) hi);
    ts_query_cursor_exec (cursor, query, ts_tree_root_node (st->tree));
    TSQueryMatch match;
    int rc = 0;
    while (rc == 0 && ts_query_cursor_next_match (cursor, &match)) {
        for (uint16_t i = 0; i < match.capture_count; i++) {
            TSNode node = match.captures[i].node;
            uint32_t sb = ts_node_start_byte (node), eb = ts_node_end_byte (node);
            if (eb > n) eb = n;
            if (sb >= eb) continue;
            if (nc == cap) {
                struct bashts_cap *nv = realloc (v, 2 * cap * sizeof *v);
                if (!nv) { rc = -1; break; }
                v = nv; cap *= 2;
            }
            v[nc].sb = sb; v[nc].eb = eb;
            v[nc].pattern = match.pattern_index;
            v[nc].id = match.captures[i].index;
            nc++;
        }
    }
    ts_query_cursor_delete (cursor);
    if (rc == 0) {
        for (uint32_t id = 0; id < ncap; id++) {
            uint32_t len = 0;
            const char *name = ts_query_capture_name_for_id (query, id, &len);
            sgr_by_id[id] = bashts_sgr_for_capture (name, len);
        }
        /* Weakest first, so the strongest capture covering a byte paints
           it last: the order bashts_resolve_owners uses. */
        qsort (v, nc, sizeof *v, bashts_cap_weakest_first);
        for (size_t i = 0; i < nc; i++) {
            uint32_t a = v[i].sb > lo ? v[i].sb : (uint32_t) lo;
            uint32_t b = v[i].eb < hi ? v[i].eb : (uint32_t) hi;
            for (uint32_t k = a; k < b; k++) sgr_at[k - lo] = sgr_by_id[v[i].id];
        }
    }
    free (v);
    free (sgr_by_id);
    return rc;
}

#define BASHTS_HL_RENDER 0
#define BASHTS_HL_SPANS  1   /* -S: resolved, non-overlapping spans */
#define BASHTS_HL_ALL    2   /* -A: every capture, source order */

/* Emit highlight output for (TREE, SRC) in MODE. */
static int
bashts_highlight_emit (const struct bashts_lang *l, TSTree *tree,
                       const char *src, uint32_t srclen, int mode)
{
    uint32_t off = 0;
    TSQueryError qerr = TSQueryErrorNone;
    TSQuery *query = bashts_highlight_query (l, &off, &qerr);
    if (!query) {
        builtin_error ("highlight: baked-in query for %s failed to compile (offset=%u, code=%d) — bug in the vendored .scm",
                       l->name, off, (int) qerr);
        return EXECUTION_FAILURE;
    }

    if (mode == BASHTS_HL_ALL) {
        struct bashts_cap *caps = NULL;
        size_t n = 0;
        if (bashts_collect_captures (query, ts_tree_root_node (tree), srclen, &caps, &n) < 0) {
            builtin_error ("highlight: malloc failed");
            return EXECUTION_FAILURE;
        }
        qsort (caps, n, sizeof *caps, bashts_cap_source_order);
        for (size_t i = 0; i < n; i++) {
            if (i && !bashts_cap_source_order (&caps[i - 1], &caps[i])) continue;
            uint32_t len = 0;
            const char *name = ts_query_capture_name_for_id (query, caps[i].id, &len);
            printf ("%u-%u %s %.*s\n", caps[i].sb, caps[i].eb,
                    bashts_sgr_for_capture (name, len), (int) len, name);
        }
        free (caps);
        return bashts_finish_output ("highlight", EXECUTION_SUCCESS);
    }

    uint32_t *owner = NULL;
    if (bashts_highlight_owners (l, tree, srclen, &owner, &query) < 0) {
        builtin_error ("highlight: malloc failed");
        return EXECUTION_FAILURE;
    }

    /* Walk maximal runs of one owner. Spans name the class; rendering
       only switches SGR when the code itself changes. */
    const char *cur = NULL;
    uint32_t b = 0;
    while (b < srclen) {
        uint32_t o = owner[b], e = b + 1;
        while (e < srclen && owner[e] == o) e++;
        const char *sgr = NULL;
        uint32_t len = 0;
        const char *name = NULL;
        if (o) {
            name = bashts_owner_name (query, o, &len);
            sgr = bashts_sgr_for_capture (name, len);
        }
        if (mode == BASHTS_HL_SPANS) {
            if (o) printf ("%u-%u %s %.*s\n", b, e, sgr, (int) len, name);
        } else {
            if (!(sgr == cur || (sgr && cur && !strcmp (sgr, cur)))) {
                if (cur) fputs ("\033[0m", stdout);
                if (sgr) printf ("\033[%sm", sgr);
                cur = sgr;
            }
            fwrite (src + b, 1, e - b, stdout);
        }
        b = e;
    }
    if (cur) fputs ("\033[0m", stdout);
    free (owner);
    return bashts_finish_output ("highlight", EXECUTION_SUCCESS);
}

/* `ts highlight -L LANG [-S|-A]` / `ts highlight -t TREE [-S|-A]` —
 * Stage 7.D. Parses stdin with LANG (or reuses a parse-tree handle and
 * its stored source), runs the curated highlight .scm baked into the
 * binary, and emits:
 *   default: source bytes with inline SGR escapes, one class per byte
 *   -S:      resolved span lines `BS-BE SGR_CODE NAME`, non-overlapping,
 *            ascending, one line per maximal run of one winning capture
 *   -A:      every capture before precedence (same format), sorted by
 *            start, outermost first, then query order
 * Byte offsets are 0-based and half-open, in bytes not characters.
 */
int
bashts_highlight_fd (const char *lang_name, int span_mode, int fd)
{
    if (!lang_name || !*lang_name) {
        builtin_error ("highlight: -L LANG required");
        return EX_USAGE;
    }
    const struct bashts_lang *langent = bashts_find_lang_entry (lang_name);
    if (!langent) {
        builtin_error ("highlight: unknown language: %s", lang_name);
        return EX_USAGE;
    }
    if (!langent->highlight_scm) {
        builtin_error ("highlight: no highlight queries shipped for %s", lang_name);
        return EXECUTION_FAILURE;
    }

    char *src = NULL;
    size_t srclen = 0;
    if (bashts_slurp_fd (fd, &src, &srclen) < 0) {
        builtin_error ("highlight: input read failed");
        return EXECUTION_FAILURE;
    }
    if (srclen > UINT32_MAX) {
        builtin_error ("highlight: input exceeds 4 GiB");
        free (src);
        return EXECUTION_FAILURE;
    }
    TSTree *tree = bashts_parse_with (langent, NULL, src, (uint32_t) srclen);
    if (!tree) {
        builtin_error ("highlight: parse failed");
        free (src);
        return EXECUTION_FAILURE;
    }
    int rc = bashts_highlight_emit (langent, tree, src, (uint32_t) srclen, span_mode);
    ts_tree_delete (tree);
    free (src);
    return rc;
}

static int
bashts_highlight_cmd (WORD_LIST *args)
{
    const char *lang_name = NULL, *tree_h = NULL;
    int mode = BASHTS_HL_RENDER;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-L") && p->next) { p = p->next; lang_name = p->word->word; }
        else if (!strcmp (w, "-t") && p->next) { p = p->next; tree_h = p->word->word; }
        else if (!strcmp (w, "-S")) mode = BASHTS_HL_SPANS;
        else if (!strcmp (w, "-A")) mode = BASHTS_HL_ALL;
        else { builtin_error ("highlight: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!tree_h) {
        if (!lang_name) {
            builtin_error ("highlight: -L LANG or -t TREE required");
            return EX_USAGE;
        }
        return bashts_highlight_fd (lang_name, mode, STDIN_FILENO);
    }
    const char *path = NULL;
    int t = bashts_resolve_tree_with_path (tree_h, &path);
    if (t < 0 || path) {
        builtin_error ("highlight: invalid tree handle: %s", tree_h);
        return EX_USAGE;
    }
    struct bashts_tree_slot *s = &bashts_tree_pool[t];
    if (lang_name && strcmp (lang_name, s->lang->name)) {
        builtin_error ("highlight: tree %s was parsed as %s, not %s",
                       tree_h, s->lang->name, lang_name);
        return EX_USAGE;
    }
    if (!s->lang->highlight_scm) {
        builtin_error ("highlight: no highlight queries shipped for %s", s->lang->name);
        return EXECUTION_FAILURE;
    }
    return bashts_highlight_emit (s->lang, s->tree, s->src, s->srclen, mode);
}

/* `ts cursor-walk -L LANG [-n] [-d MAXDEPTH]` — Stage 7.C closure.
 * Reads stdin, parses with LANG, walks the tree depth-first via
 * TSTreeCursor, emits one line per visited node:
 *
 *     DEPTH NODE_TYPE START_ROW:START_COL-END_ROW:END_COL START_BYTE-END_BYTE
 *
 * Flags:
 *   -L LANG     required — grammar to parse against
 *   -n          named nodes only (skip anon tokens like `(`, `;`, `if`)
 *   -d MAX      cap depth at MAX (root is depth 0); deeper nodes
 *               are still traversed for sibling movement but not emitted
 *
 * No tree/node handle table is allocated — the verb owns the parse +
 * cursor for its lifetime, so callers don't have to manage handles.
 * The handle-based `parse-into` / `root` / `node-*` / `free` API
 * (spec 7.C lines 1080-1083) remains future work; this verb covers the
 * common "give me everything in source order" use case without it.
 */
static int
bashts_cursor_walk_cmd (WORD_LIST *args)
{
    const char *lang_name = NULL;
    int named_only = 0;
    int max_depth = -1;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-L") && p->next) { p = p->next; lang_name = p->word->word; }
        else if (!strcmp (w, "-n")) named_only = 1;
        else if (!strcmp (w, "-d") && p->next) {
            p = p->next;
            const char *e = NULL;
            uint32_t d;
            if (bashts_parse_u32 (p->word->word, &e, &d) < 0 || *e || d > INT32_MAX) {
                builtin_error ("cursor-walk: invalid depth: %s", p->word->word);
                return EX_USAGE;
            }
            max_depth = (int) d;
        }
        else { builtin_error ("cursor-walk: unknown arg: %s", w); return EX_USAGE; }
    }
    if (!lang_name) {
        builtin_error ("cursor-walk: -L LANG required (try `ts language-list`)");
        return EX_USAGE;
    }
    const TSLanguage *lang = bashts_find_language (lang_name);
    if (!lang) {
        builtin_error ("cursor-walk: unknown language: %s", lang_name);
        return EX_USAGE;
    }

    char *src = NULL;
    size_t srclen = 0;
    if (bashts_slurp_stdin (&src, &srclen) < 0) {
        builtin_error ("cursor-walk: stdin read failed");
        return EXECUTION_FAILURE;
    }

    TSParser *parser = ts_parser_new ();
    if (!ts_parser_set_language (parser, lang)) {
        builtin_error ("cursor-walk: ts_parser_set_language failed");
        ts_parser_delete (parser); free (src);
        return EXECUTION_FAILURE;
    }
    TSTree *tree = ts_parser_parse_string (parser, NULL, src, (uint32_t) srclen);
    if (!tree) {
        builtin_error ("cursor-walk: parse failed");
        ts_parser_delete (parser); free (src);
        return EXECUTION_FAILURE;
    }
    TSNode root = ts_tree_root_node (tree);
    TSTreeCursor cursor = ts_tree_cursor_new (root);

    int depth = 0;
    /* Iterative depth-first: emit current, descend if possible, else
       advance to next sibling, else ascend until a sibling exists. */
    for (;;) {
        TSNode node = ts_tree_cursor_current_node (&cursor);
        int is_named = ts_node_is_named (node);
        if ((!named_only || is_named)
            && (max_depth < 0 || depth <= max_depth)) {
            const char *type = ts_node_type (node);
            TSPoint sp = ts_node_start_point (node);
            TSPoint ep = ts_node_end_point   (node);
            uint32_t sb = ts_node_start_byte (node);
            uint32_t eb = ts_node_end_byte   (node);
            printf ("%d %s %u:%u-%u:%u %u-%u\n",
                    depth, type,
                    (unsigned) (sp.row + 1), (unsigned) (sp.column + 1),
                    (unsigned) (ep.row + 1), (unsigned) (ep.column + 1),
                    sb, eb);
        }
        if (ts_tree_cursor_goto_first_child (&cursor)) { depth++; continue; }
        while (!ts_tree_cursor_goto_next_sibling (&cursor)) {
            if (!ts_tree_cursor_goto_parent (&cursor)) {
                ts_tree_cursor_delete (&cursor);
                ts_tree_delete (tree);
                ts_parser_delete (parser);
                free (src);
                return bashts_finish_output ("cursor-walk", EXECUTION_SUCCESS);
            }
            depth--;
        }
    }
}

/* ---- Handle-based node API (Stage 7.C closure) -------------------- */

/* `ts parse-tree -L LANG -t TREE_VAR` — parse stdin, store TSTree*
   and a copy of the source in the tree pool, bind the handle string
   ("T<idx>g<gen>") to TREE_VAR. The tree handle ALSO functions as the
   root-node handle (since every node handle is a tree handle + path;
   root has empty path). Caller MUST eventually `ts free TREE_VAR`. */
static int
bashts_parse_tree_cmd (WORD_LIST *args)
{
    const char *lang_name = NULL, *var = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-L") && p->next) { p = p->next; lang_name = p->word->word; }
        else if (!strcmp (w, "-t") && p->next) { p = p->next; var       = p->word->word; }
        else { builtin_error ("parse-tree: unknown arg: %s", w); return EX_USAGE; }
    }
    if (!lang_name) { builtin_error ("parse-tree: -L LANG required"); return EX_USAGE; }
    if (!var)       { builtin_error ("parse-tree: -t TREE_VAR required"); return EX_USAGE; }
    if (!legal_identifier (var)) { builtin_error ("parse-tree: `%s': not a valid identifier", var); return EX_USAGE; }
    const struct bashts_lang *lang = bashts_find_lang_entry (lang_name);
    if (!lang) { builtin_error ("parse-tree: unknown language: %s", lang_name); return EX_USAGE; }

    char *src = NULL; size_t srclen = 0;
    if (bashts_slurp_stdin (&src, &srclen) < 0) {
        builtin_error ("parse-tree: stdin read failed");
        return EXECUTION_FAILURE;
    }
    if (srclen > UINT32_MAX) {
        builtin_error ("parse-tree: input exceeds 4 GiB");
        free (src);
        return EXECUTION_FAILURE;
    }
    TSTree *tree = bashts_parse_with (lang, NULL, src, (uint32_t) srclen);
    if (!tree) {
        builtin_error ("parse-tree: parse returned NULL");
        free (src);
        return EXECUTION_FAILURE;
    }
    int idx = bashts_tree_alloc (tree, lang, src, (uint32_t) srclen);
    if (idx < 0) {
        ts_tree_delete (tree);
        free (src);
        builtin_error ("parse-tree: tree pool exhausted (%d slots)",
                       BASHTS_TREE_POOL_MAX);
        return EXECUTION_FAILURE;
    }
    char buf[32];
    bashts_format_tree_handle (idx, buf, sizeof buf);
    if (bashts_bind_handle (var, buf) < 0) {
        struct bashts_tree_slot *s = &bashts_tree_pool[idx];
        ts_tree_delete (tree);
        free (src);
        s->tree = NULL; s->src = NULL; s->srclen = 0; s->lang = NULL;
        s->in_use = 0;
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

/* Row/column (0-based, column in bytes) of byte OFF in SRC. */
static TSPoint
bashts_point_at (const char *src, uint32_t off)
{
    TSPoint pt = { 0, 0 };
    for (uint32_t i = 0; i < off; i++) {
        if (src[i] == '\n') { pt.row++; pt.column = 0; }
        else pt.column++;
    }
    return pt;
}

static int
bashts_parse_offset (const char *verb, const char *w, uint32_t *out)
{
    const char *e = NULL;
    if (bashts_parse_u32 (w, &e, out) < 0 || *e) {
        builtin_error ("%s: invalid byte offset: %s", verb, w);
        return -1;
    }
    return 0;
}

/* `ts edit TREE START OLD_END NEW_END -t TREE_VAR` — incremental
   reparse. stdin is the complete new source; bytes [START, OLD_END) of
   the stored source were replaced by [START, NEW_END) of the new one.
   The range must describe the difference exactly (shared prefix and
   suffix are verified), so the edited tree is never inconsistent with
   its text. The old tree is edited with ts_tree_edit and passed to the
   parser so unchanged subtrees are reused. On success the slot's
   generation advances: every handle into the old tree, root and node
   paths alike, stops resolving, and TREE_VAR receives the new handle.
   On failure the slot is unchanged. */
static int
bashts_edit_cmd (WORD_LIST *args)
{
    const char *tree_h = NULL, *var = NULL, *nums[3] = { NULL, NULL, NULL };
    int nn = 0;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-t") && p->next) { p = p->next; var = p->word->word; }
        else if (!tree_h) tree_h = w;
        else if (nn < 3) nums[nn++] = w;
        else { builtin_error ("edit: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!tree_h || nn != 3) {
        builtin_error ("edit: usage: ts edit TREE START OLD_END NEW_END -t TREE_VAR");
        return EX_USAGE;
    }
    if (!var) { builtin_error ("edit: -t TREE_VAR required"); return EX_USAGE; }
    if (!legal_identifier (var)) { builtin_error ("edit: `%s': not a valid identifier", var); return EX_USAGE; }
    const char *path = NULL;
    int t = bashts_resolve_tree_with_path (tree_h, &path);
    if (t < 0 || path) { builtin_error ("edit: invalid tree handle: %s", tree_h); return EX_USAGE; }
    uint32_t start, old_end, new_end;
    if (bashts_parse_offset ("edit", nums[0], &start) < 0
        || bashts_parse_offset ("edit", nums[1], &old_end) < 0
        || bashts_parse_offset ("edit", nums[2], &new_end) < 0)
        return EX_USAGE;

    struct bashts_tree_slot *s = &bashts_tree_pool[t];
    char *src = NULL; size_t srclen = 0;
    if (bashts_slurp_stdin (&src, &srclen) < 0) {
        builtin_error ("edit: stdin read failed");
        return EXECUTION_FAILURE;
    }
    if (srclen > UINT32_MAX
        || start > old_end || old_end > s->srclen
        || start > new_end || new_end > srclen
        || s->srclen - old_end != srclen - new_end
        || memcmp (s->src, src, start)
        || memcmp (s->src + old_end, src + new_end, srclen - new_end)) {
        builtin_error ("edit: range %u-%u -> %u-%u does not describe the change from %u to %zu bytes",
                       start, old_end, start, new_end, s->srclen, srclen);
        free (src);
        return EX_USAGE;
    }

    TSInputEdit e;
    e.start_byte     = start;
    e.old_end_byte   = old_end;
    e.new_end_byte   = new_end;
    e.start_point    = bashts_point_at (s->src, start);
    e.old_end_point  = bashts_point_at (s->src, old_end);
    e.new_end_point  = bashts_point_at (src, new_end);
    TSTree *old = ts_tree_copy (s->tree);
    ts_tree_edit (old, &e);
    TSTree *tree = bashts_parse_with (s->lang, old, src, (uint32_t) srclen);
    ts_tree_delete (old);
    if (!tree) {
        builtin_error ("edit: reparse failed");
        free (src);
        return EXECUTION_FAILURE;
    }
    /* Publish the next handle before discarding the old state. A rejected
       output variable must leave both old handles and source usable. */
    uint32_t old_gen = s->gen;
    bashts_bump_gen (s);
    char buf[32];
    bashts_format_tree_handle (t, buf, sizeof buf);
    if (bashts_bind_handle (var, buf) < 0) {
        s->gen = old_gen;
        ts_tree_delete (tree);
        free (src);
        return EXECUTION_FAILURE;
    }
    ts_tree_delete (s->tree);
    free (s->src);
    s->tree = tree;
    s->src = src;
    s->srclen = (uint32_t) srclen;
    return EXECUTION_SUCCESS;
}

/* `ts root TREE -h NODE_VAR` — bind NODE_VAR to the tree's
   handle (which IS the root handle in the path-based scheme). Kept
   as a verb for spec API symmetry; could be elided by callers who
   just use the tree handle directly. */
static int
bashts_root_cmd (WORD_LIST *args)
{
    const char *tree_h = NULL, *var = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!tree_h) { tree_h = w; continue; }
        if (!strcmp (w, "-h") && p->next) { p = p->next; var = p->word->word; }
        else { builtin_error ("root: unknown arg: %s", w); return EX_USAGE; }
    }
    if (!tree_h) { builtin_error ("root: TREE handle required"); return EX_USAGE; }
    if (!var)    { builtin_error ("root: -h NODE_VAR required"); return EX_USAGE; }
    if (!legal_identifier (var)) { builtin_error ("root: `%s': not a valid identifier", var); return EX_USAGE; }
    /* Validate that the tree handle resolves before binding. */
    const char *path = NULL;
    if (bashts_resolve_tree_with_path (tree_h, &path) < 0 || path) {
        builtin_error ("root: invalid tree handle: %s", tree_h);
        return EX_USAGE;
    }
    return bashts_bind_handle (var, tree_h) == 0
        ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* Resolve the single NODE argument of a node-* verb. */
static int
bashts_node_arg (const char *verb, WORD_LIST *args, TSNode *node)
{
    if (!args) { builtin_error ("%s: NODE handle required", verb); return -1; }
    if (args->next) { builtin_error ("%s: unexpected arg: %s", verb, args->next->word->word); return -1; }
    int t = bashts_resolve_node (args->word->word, node);
    if (t < 0) builtin_error ("%s: invalid node handle: %s", verb, args->word->word);
    return t;
}

/* `ts node-type NODE` — walk NODE's path from root, print type. */
static int
bashts_node_type_cmd (WORD_LIST *args)
{
    TSNode node;
    if (bashts_node_arg ("node-type", args, &node) < 0) return EX_USAGE;
    const char *type = ts_node_type (node);
    printf ("%s\n", type ? type : "");
    return bashts_finish_output ("node-type", EXECUTION_SUCCESS);
}

/* `ts node-range NODE` — walk path, emit "sr sc er ec sb eb" (rows and
   columns 1-based, columns counted in bytes; byte offsets 0-based). */
static int
bashts_node_range_cmd (WORD_LIST *args)
{
    TSNode node;
    if (bashts_node_arg ("node-range", args, &node) < 0) return EX_USAGE;
    TSPoint sp = ts_node_start_point (node);
    TSPoint ep = ts_node_end_point   (node);
    uint32_t sb = ts_node_start_byte (node);
    uint32_t eb = ts_node_end_byte   (node);
    printf ("%u %u %u %u %u %u\n",
            (unsigned) (sp.row + 1), (unsigned) (sp.column + 1),
            (unsigned) (ep.row + 1), (unsigned) (ep.column + 1),
            sb, eb);
    return bashts_finish_output ("node-range", EXECUTION_SUCCESS);
}

/* `ts node-sexp NODE` — the node's S-expression. */
static int
bashts_node_sexp_cmd (WORD_LIST *args)
{
    TSNode node;
    if (bashts_node_arg ("node-sexp", args, &node) < 0) return EX_USAGE;
    char *sexp = ts_node_string (node);
    if (!sexp) { builtin_error ("node-sexp: out of memory"); return EXECUTION_FAILURE; }
    printf ("%s\n", sexp);
    free (sexp);
    return bashts_finish_output ("node-sexp", EXECUTION_SUCCESS);
}

/* `ts node-text NODE` — the node's source bytes, exactly, no newline. */
static int
bashts_node_text_cmd (WORD_LIST *args)
{
    TSNode node;
    int t = bashts_node_arg ("node-text", args, &node);
    if (t < 0) return EX_USAGE;
    const struct bashts_tree_slot *s = &bashts_tree_pool[t];
    uint32_t sb = ts_node_start_byte (node), eb = ts_node_end_byte (node);
    if (eb > s->srclen) eb = s->srclen;
    if (sb < eb) fwrite (s->src + sb, 1, eb - sb, stdout);
    return bashts_finish_output ("node-text", EXECUTION_SUCCESS);
}

/* `ts node-children NODE [-n]` — walk to NODE, enumerate children,
   emit one fully-qualified handle per line. Each child handle is the
   parent handle with the child's absolute index appended to the path,
   so a handle names one node whichever listing produced it; -n only
   filters out the anonymous children. */
static int
bashts_node_children_cmd (WORD_LIST *args)
{
    const char *node_h = NULL;
    int named_only = 0;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-n")) { named_only = 1; }
        else if (!node_h) { node_h = w; }
        else { builtin_error ("node-children: unknown arg: %s", w); return EX_USAGE; }
    }
    if (!node_h) { builtin_error ("node-children: NODE handle required"); return EX_USAGE; }
    TSNode parent;
    if (bashts_resolve_node (node_h, &parent) < 0) {
        builtin_error ("node-children: invalid node handle: %s", node_h);
        return EX_USAGE;
    }
    uint32_t cnt = ts_node_child_count (parent);
    /* Determine if the input handle already has a `:path` suffix or is
       the bare tree handle. Suffix decides whether to append `,i` or
       `:i` for each child. If has_path but the path is empty (handle
       ends with ':'), emit indices with NO leading comma. */
    const char *colon = strchr (node_h, ':');
    const char *sep = !colon ? ":" : colon[1] == 0 ? "" : ",";
    for (uint32_t i = 0; i < cnt; i++) {
        if (named_only && !ts_node_is_named (ts_node_child (parent, i))) continue;
        printf ("%s%s%u\n", node_h, sep, i);
    }
    return bashts_finish_output ("node-children", EXECUTION_SUCCESS);
}

/* `ts free TREE` — free TSTree* and its source, mark slot unused.
   Existing handles stop resolving (in_use flag false; the next alloc
   bumps the generation, so a reused slot never matches them). */
static int
bashts_free_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("free: TREE handle required"); return EX_USAGE; }
    const char *path = NULL;
    int t = bashts_resolve_tree_with_path (args->word->word, &path);
    if (t < 0 || path) { builtin_error ("free: invalid tree handle: %s", args->word->word); return EX_USAGE; }
    struct bashts_tree_slot *s = &bashts_tree_pool[t];
    ts_tree_delete (s->tree);
    free (s->src);
    s->tree   = NULL;
    s->src    = NULL;
    s->srclen = 0;
    s->lang   = NULL;
    s->in_use = 0;
    return EXECUTION_SUCCESS;
}

int
ts_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;

    if (!strcmp (cmd, "version"))         return bashts_version_cmd        (args);
    if (!strcmp (cmd, "language-list"))   return bashts_language_list_cmd  (args);
    if (!strcmp (cmd, "parse"))           return bashts_parse_cmd          (args);
    if (!strcmp (cmd, "query"))           return bashts_query_cmd          (args);
    if (!strcmp (cmd, "highlight"))       return bashts_highlight_cmd      (args);
    if (!strcmp (cmd, "cursor-walk"))     return bashts_cursor_walk_cmd    (args);
    if (!strcmp (cmd, "parse-tree"))      return bashts_parse_tree_cmd     (args);
    if (!strcmp (cmd, "root"))            return bashts_root_cmd           (args);
    if (!strcmp (cmd, "node-type"))       return bashts_node_type_cmd      (args);
    if (!strcmp (cmd, "node-range"))      return bashts_node_range_cmd     (args);
    if (!strcmp (cmd, "node-children"))   return bashts_node_children_cmd  (args);
    if (!strcmp (cmd, "node-sexp"))       return bashts_node_sexp_cmd      (args);
    if (!strcmp (cmd, "node-text"))       return bashts_node_text_cmd      (args);
    if (!strcmp (cmd, "edit"))            return bashts_edit_cmd           (args);
    if (!strcmp (cmd, "free"))            return bashts_free_cmd           (args);
    builtin_error ("unknown verb: %s "
                   "(try version/language-list/parse/query/highlight/"
                   "cursor-walk/parse-tree/edit/root/node-type/node-range/"
                   "node-children/node-sexp/node-text/free)", cmd);
    return EX_USAGE;
}

char *ts_doc[] = {
    "tree-sitter parsing runtime.",
    "",
    "    ts version              print runtime ABI + library version",
    "    ts language-list        names of compiled-in grammars",
    "    ts parse -L LANG        parse stdin, print the root S-expression",
    "    ts query -L LANG -q Q   run query Q, one line per capture",
    "    ts query -t TREE -q Q   same, over a parse-tree handle",
    "    ts highlight -L LANG [-S|-A]  curated highlights.scm over stdin",
    "    ts highlight -t TREE [-S|-A]  same, over a parse-tree handle",
    "                  default: SGR-rendered source; -S: resolved spans",
    "                  BS-BE SGR NAME; -A: every capture before precedence",
    "    ts cursor-walk -L LANG [-n] [-d N]  depth-first dump of every node",
    "    ts parse-tree -L LANG -t VAR        parse stdin, bind a tree handle",
    "    ts edit TREE START OLD_END NEW_END -t VAR",
    "                  incremental reparse of the new source on stdin",
    "    ts root TREE -h VAR     bind the root node handle",
    "    ts node-type|node-range|node-sexp|node-text NODE",
    "    ts node-children NODE [-n]          child handles (-n: named only)",
    "    ts free TREE            release a tree; its handles stop resolving",
    "",
    "Each highlighted byte takes one class: the narrowest capture wins,",
    "then the earlier query pattern, then the earlier capture name.",
    "Offsets are 0-based bytes; edit bumps the tree's generation.",
    (char *) NULL
};

struct builtin ts_struct = {
    "ts",
    ts_builtin,
    BUILTIN_ENABLED,
    ts_doc,
    "ts <verb> [args...]",
    0
};
