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
 *
 * Reserved (errors with "not yet implemented"):
 *   ts query / cursor / walk
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

struct bashts_tree_slot {
    int       in_use;
    TSTree   *tree;
    uint32_t  gen;
};

static struct bashts_tree_slot bashts_tree_pool[BASHTS_TREE_POOL_MAX];

static int
bashts_tree_alloc (TSTree *tree)
{
    for (int i = 0; i < BASHTS_TREE_POOL_MAX; i++) {
        if (!bashts_tree_pool[i].in_use) {
            bashts_tree_pool[i].in_use = 1;
            bashts_tree_pool[i].tree   = tree;
            bashts_tree_pool[i].gen   += 1;
            return i;
        }
    }
    return -1;
}

/* Parse "T<idx>g<gen>" → tree_idx with gen check. The handle MAY have
   trailing ":<path>" — path bytes are returned via *path_out (NULL if
   absent). Returns -1 on miss. */
static int
bashts_resolve_tree_with_path (const char *handle, const char **path_out)
{
    if (path_out) *path_out = NULL;
    if (!handle || handle[0] != 'T') return -1;
    char *end1 = NULL;
    long idx = strtol (handle + 1, &end1, 10);
    if (idx < 0 || idx >= BASHTS_TREE_POOL_MAX) return -1;
    if (!end1 || *end1 != 'g') return -1;
    char *end2 = NULL;
    long gen = strtol (end1 + 1, &end2, 10);
    if (!end2) return -1;
    /* Either end-of-string (root handle) or ':' followed by path. */
    if (*end2 != 0 && *end2 != ':') return -1;
    if (!bashts_tree_pool[idx].in_use) return -1;
    if ((uint32_t) gen != bashts_tree_pool[idx].gen) return -1;
    if (path_out && *end2 == ':') *path_out = end2 + 1;
    return (int) idx;
}

/* Walk path "i1,i2,..." from root, returning the resolved node.
   Sets *err = 1 on parse / out-of-bounds. */
static TSNode
bashts_walk_path (TSNode root, const char *path, int named_only, int *err)
{
    *err = 0;
    if (!path || !*path) return root;
    TSNode cur = root;
    const char *p = path;
    while (*p) {
        char *end = NULL;
        long i = strtol (p, &end, 10);
        if (end == p || i < 0) { *err = 1; return cur; }
        uint32_t cnt = named_only
            ? ts_node_named_child_count (cur)
            : ts_node_child_count       (cur);
        if ((uint32_t) i >= cnt) { *err = 1; return cur; }
        cur = named_only
            ? ts_node_named_child (cur, (uint32_t) i)
            : ts_node_child       (cur, (uint32_t) i);
        p = end;
        if (*p == ',') p++;
        else if (*p != 0) { *err = 1; return cur; }
    }
    return cur;
}

/* Resolve full node handle → (tree_idx, TSNode). Returns -1 on fail. */
static int
bashts_resolve_node (const char *handle, int named_only, TSNode *out)
{
    const char *path = NULL;
    int t = bashts_resolve_tree_with_path (handle, &path);
    if (t < 0) return -1;
    TSNode root = ts_tree_root_node (bashts_tree_pool[t].tree);
    int err = 0;
    *out = bashts_walk_path (root, path, named_only, &err);
    if (err) return -1;
    return t;
}

static void
bashts_format_tree_handle (int idx, char *buf, size_t bufsz)
{
    snprintf (buf, bufsz, "T%dg%u", idx, (unsigned) bashts_tree_pool[idx].gen);
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
    return EXECUTION_SUCCESS;
}

/* `ts language-list` — names of compiled-in grammars. */
static int
bashts_language_list_cmd (WORD_LIST *args)
{
    (void) args;
    for (const struct bashts_lang *l = bashts_languages; l->name; l++)
        printf ("%s\n", l->name);
    return EXECUTION_SUCCESS;
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
    return EXECUTION_SUCCESS;
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
    const char *lang_name = NULL, *query_src = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-L") && p->next) { p = p->next; lang_name  = p->word->word; }
        else if (!strcmp (w, "-q") && p->next) { p = p->next; query_src = p->word->word; }
        else { builtin_error ("query: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!lang_name)  { builtin_error ("query: -L LANG required");   return EX_USAGE; }
    if (!query_src)  { builtin_error ("query: -q QUERY required");  return EX_USAGE; }

    const TSLanguage *language = bashts_find_language (lang_name);
    if (!language) {
        builtin_error ("query: unknown language: %s", lang_name);
        return EX_USAGE;
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
    TSTree *tree = ts_parser_parse_string (parser, NULL, src, (uint32_t) srclen);
    if (!tree) {
        builtin_error ("query: parse failed");
        ts_parser_delete (parser);
        ts_query_delete (query);
        free (src);
        return EXECUTION_FAILURE;
    }
    TSNode root = ts_tree_root_node (tree);

    TSQueryCursor *cursor = ts_query_cursor_new ();
    ts_query_cursor_exec (cursor, query, root);

    /* Iterate matches; each match has 0-N captures. Emit one line per
       capture, ordered by their byte position. */
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
    ts_tree_delete (tree);
    ts_parser_delete (parser);
    ts_query_delete (query);
    free (src);
    return EXECUTION_SUCCESS;
}

/* Stage 7.E — public helper. Same logic as the highlight verb's
 * span-painting loop, but exposed for direct C-level callers (notably
 * nano during bn_render). Caller provides `sgr_at[srclen]`
 * (zero-initialized); we paint per-byte SGR-code pointers from the
 * static rule table. Returns 0 on success, -1 on bad lang / parse
 * failure. The pointers in sgr_at remain valid for the lifetime of
 * this loadable (they're `static const char[]` literals).
 */
int
bashts_compute_sgr_map (const char *lang, const char *src, size_t srclen,
                       const char **sgr_at)
{
    if (!lang || !src || !sgr_at) return -1;
    const struct bashts_lang *langent = NULL;
    for (const struct bashts_lang *l = bashts_languages; l->name; l++)
        if (!strcmp (l->name, lang)) { langent = l; break; }
    if (!langent || !langent->highlight_scm) return -1;

    uint32_t qerr_off = 0;
    TSQueryError qerr = TSQueryErrorNone;
    TSQuery *query = ts_query_new (langent->get (), langent->highlight_scm,
                                   (uint32_t) strlen (langent->highlight_scm),
                                   &qerr_off, &qerr);
    if (!query) return -1;

    TSParser *parser = ts_parser_new ();
    ts_parser_set_language (parser, langent->get ());
    TSTree *tree = ts_parser_parse_string (parser, NULL, src, (uint32_t) srclen);
    if (!tree) { ts_query_delete (query); ts_parser_delete (parser); return -1; }
    TSNode root = ts_tree_root_node (tree);

    TSQueryCursor *cursor = ts_query_cursor_new ();
    ts_query_cursor_exec (cursor, query, root);
    TSQueryMatch match;
    while (ts_query_cursor_next_match (cursor, &match)) {
        for (uint16_t i = 0; i < match.capture_count; i++) {
            TSQueryCapture cap = match.captures[i];
            uint32_t name_len = 0;
            const char *name = ts_query_capture_name_for_id (
                query, cap.index, &name_len);
            uint32_t bs = ts_node_start_byte (cap.node);
            uint32_t be = ts_node_end_byte   (cap.node);
            if (be > srclen) be = (uint32_t) srclen;
            const char *sgr = bashts_sgr_for_capture (name, name_len);
            for (uint32_t b = bs; b < be; b++) sgr_at[b] = sgr;
        }
    }
    ts_query_cursor_delete (cursor);
    ts_tree_delete (tree);
    ts_parser_delete (parser);
    ts_query_delete (query);
    return 0;
}

/* `ts highlight -L LANG [-S]` — Stage 7.D. Reads stdin, parses with
 * LANG's grammar, runs the curated highlight .scm baked into the
 * binary, and emits either:
 *   default: source bytes with inline SGR escapes around captures
 *   -S:      span-list lines `BS-BE SGR_CODE NAME` for callers that
 *            apply colors themselves (nano during render)
 *
 * Algorithm: walk captures, paint each byte with the most-specific
 * (latest in match order) SGR code. Walk source emitting SGR
 * transitions inline.
 */
int
bashts_highlight_fd (const char *lang_name, int span_mode, int fd)
{
    if (!lang_name || !*lang_name) {
        builtin_error ("highlight: -L LANG required");
        return EX_USAGE;
    }
    const struct bashts_lang *langent = NULL;
    for (const struct bashts_lang *l = bashts_languages; l->name; l++)
        if (!strcmp (l->name, lang_name)) { langent = l; break; }
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

    uint32_t qerr_off = 0;
    TSQueryError qerr = TSQueryErrorNone;
    TSQuery *query = ts_query_new (langent->get (), langent->highlight_scm,
                                   (uint32_t) strlen (langent->highlight_scm),
                                   &qerr_off, &qerr);
    if (!query) {
        builtin_error ("highlight: baked-in query for %s failed to compile (offset=%u, code=%d) — bug in the vendored .scm",
                       lang_name, qerr_off, (int) qerr);
        free (src);
        return EXECUTION_FAILURE;
    }

    TSParser *parser = ts_parser_new ();
    ts_parser_set_language (parser, langent->get ());
    TSTree *tree = ts_parser_parse_string (parser, NULL, src, (uint32_t) srclen);
    if (!tree) {
        builtin_error ("highlight: parse failed");
        ts_parser_delete (parser); ts_query_delete (query); free (src);
        return EXECUTION_FAILURE;
    }
    TSNode root = ts_tree_root_node (tree);

    const char **sgr_at = calloc (srclen + 1, sizeof *sgr_at);
    if (!sgr_at) {
        builtin_error ("highlight: malloc failed");
        ts_tree_delete (tree); ts_parser_delete (parser);
        ts_query_delete (query); free (src);
        return EXECUTION_FAILURE;
    }

    TSQueryCursor *cursor = ts_query_cursor_new ();
    ts_query_cursor_exec (cursor, query, root);
    TSQueryMatch match;
    while (ts_query_cursor_next_match (cursor, &match)) {
        for (uint16_t i = 0; i < match.capture_count; i++) {
            TSQueryCapture cap = match.captures[i];
            uint32_t name_len = 0;
            const char *name = ts_query_capture_name_for_id (
                query, cap.index, &name_len);
            uint32_t bs = ts_node_start_byte (cap.node);
            uint32_t be = ts_node_end_byte   (cap.node);
            if (be > srclen) be = (uint32_t) srclen;
            const char *sgr = bashts_sgr_for_capture (name, name_len);
            if (span_mode) {
                printf ("%u-%u %s %.*s\n",
                        bs, be, sgr, (int) name_len, name);
            } else {
                for (uint32_t b = bs; b < be; b++)
                    sgr_at[b] = sgr;
            }
        }
    }
    ts_query_cursor_delete (cursor);
    ts_tree_delete (tree);
    ts_parser_delete (parser);
    ts_query_delete (query);

    if (!span_mode) {
        const char *cur = NULL;
        for (size_t b = 0; b < srclen; b++) {
            const char *s = sgr_at[b];
            if (s != cur) {
                if (cur) printf ("\033[0m");
                if (s)   printf ("\033[%sm", s);
                cur = s;
            }
            putchar (src[b]);
        }
        if (cur) printf ("\033[0m");
    }

    free (sgr_at);
    free (src);
    return EXECUTION_SUCCESS;
}

static int
bashts_highlight_cmd (WORD_LIST *args)
{
    const char *lang_name = NULL;
    int span_mode = 0;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-L") && p->next) { p = p->next; lang_name = p->word->word; }
        else if (!strcmp (w, "-S")) span_mode = 1;
        else { builtin_error ("highlight: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!lang_name) {
        builtin_error ("highlight: -L LANG required");
        return EX_USAGE;
    }
    return bashts_highlight_fd (lang_name, span_mode, STDIN_FILENO);
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
        else if (!strcmp (w, "-d") && p->next) { p = p->next; max_depth = atoi (p->word->word); }
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
                return EXECUTION_SUCCESS;
            }
            depth--;
        }
    }
}

/* ---- Handle-based node API (Stage 7.C closure) -------------------- */

/* `ts parse-tree -L LANG -t TREE_VAR` — parse stdin, store TSTree*
   in the tree pool, bind the handle string ("T<idx>g<gen>") to
   TREE_VAR. The tree handle ALSO functions as the root-node handle
   (since every node handle is a tree handle + path; root has empty
   path). Caller MUST eventually `ts free TREE_VAR`. */
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
    const TSLanguage *lang = bashts_find_language (lang_name);
    if (!lang) { builtin_error ("parse-tree: unknown language: %s", lang_name); return EX_USAGE; }

    char *src = NULL; size_t srclen = 0;
    if (bashts_slurp_stdin (&src, &srclen) < 0) {
        builtin_error ("parse-tree: stdin read failed");
        return EXECUTION_FAILURE;
    }
    TSParser *parser = ts_parser_new ();
    if (!ts_parser_set_language (parser, lang)) {
        builtin_error ("parse-tree: ts_parser_set_language failed");
        ts_parser_delete (parser); free (src);
        return EXECUTION_FAILURE;
    }
    TSTree *tree = ts_parser_parse_string (parser, NULL, src, (uint32_t) srclen);
    ts_parser_delete (parser);
    free (src);
    if (!tree) {
        builtin_error ("parse-tree: parse returned NULL");
        return EXECUTION_FAILURE;
    }
    int idx = bashts_tree_alloc (tree);
    if (idx < 0) {
        ts_tree_delete (tree);
        builtin_error ("parse-tree: tree pool exhausted (%d slots)",
                       BASHTS_TREE_POOL_MAX);
        return EXECUTION_FAILURE;
    }
    char buf[32];
    bashts_format_tree_handle (idx, buf, sizeof buf);
    builtin_bind_variable ((char *) var, buf, 0);
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
    /* Validate that the tree handle resolves before binding. */
    if (bashts_resolve_tree_with_path (tree_h, NULL) < 0) {
        builtin_error ("root: invalid tree handle: %s", tree_h);
        return EX_USAGE;
    }
    builtin_bind_variable ((char *) var, (char *) tree_h, 0);
    return EXECUTION_SUCCESS;
}

/* `ts node-type NODE` — walk NODE's path from root, print type. */
static int
bashts_node_type_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("node-type: NODE handle required"); return EX_USAGE; }
    TSNode node;
    /* Use named-only mode for path walk consistent with how children
       were emitted; we infer that here by checking if any path component
       was emitted by node-children — but since path indices in the
       handle are agnostic to mode, we walk in the same mode that
       children used. Default: anon-included (matches node-children's
       default). */
    if (bashts_resolve_node (args->word->word, 0, &node) < 0) {
        builtin_error ("node-type: invalid node handle: %s", args->word->word);
        return EX_USAGE;
    }
    const char *type = ts_node_type (node);
    printf ("%s\n", type ? type : "");
    return EXECUTION_SUCCESS;
}

/* `ts node-range NODE` — walk path, emit "sr sc er ec sb eb". */
static int
bashts_node_range_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("node-range: NODE handle required"); return EX_USAGE; }
    TSNode node;
    if (bashts_resolve_node (args->word->word, 0, &node) < 0) {
        builtin_error ("node-range: invalid node handle");
        return EX_USAGE;
    }
    TSPoint sp = ts_node_start_point (node);
    TSPoint ep = ts_node_end_point   (node);
    uint32_t sb = ts_node_start_byte (node);
    uint32_t eb = ts_node_end_byte   (node);
    printf ("%u %u %u %u %u %u\n",
            (unsigned) (sp.row + 1), (unsigned) (sp.column + 1),
            (unsigned) (ep.row + 1), (unsigned) (ep.column + 1),
            sb, eb);
    return EXECUTION_SUCCESS;
}

/* `ts node-children NODE [-n]` — walk to NODE, enumerate children,
   emit one fully-qualified handle per line. Each child handle is the
   parent handle with the child index appended to the path component. */
static int
bashts_node_children_cmd (WORD_LIST *args)
{
    const char *node_h = NULL;
    int named_only = 0;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!node_h && w[0] == 'T') { node_h = w; }
        else if (!strcmp (w, "-n")) { named_only = 1; }
        else { builtin_error ("node-children: unknown arg: %s", w); return EX_USAGE; }
    }
    if (!node_h) { builtin_error ("node-children: NODE handle required"); return EX_USAGE; }
    TSNode parent;
    if (bashts_resolve_node (node_h, named_only, &parent) < 0) {
        builtin_error ("node-children: invalid node handle: %s", node_h);
        return EX_USAGE;
    }
    uint32_t cnt = named_only
        ? ts_node_named_child_count (parent)
        : ts_node_child_count       (parent);
    /* Determine if the input handle already has a `:path` suffix or is
       the bare tree handle. Suffix decides whether to append `,i` or
       `:i` for each child. */
    const char *colon = strchr (node_h, ':');
    int has_path = (colon != NULL);
    /* If has_path but the path is empty (handle ends with ':'), still
       emit children with comma-separated indices but NO leading comma. */
    int path_is_empty = has_path && colon[1] == 0;
    for (uint32_t i = 0; i < cnt; i++) {
        if (!has_path) {
            printf ("%s:%u\n", node_h, i);
        } else if (path_is_empty) {
            printf ("%s%u\n", node_h, i);
        } else {
            printf ("%s,%u\n", node_h, i);
        }
    }
    return EXECUTION_SUCCESS;
}

/* `ts free TREE` — free TSTree* and mark slot unused. Existing
   handles stop resolving (in_use flag false; gen bump on next alloc
   for additional safety). */
static int
bashts_free_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("free: TREE handle required"); return EX_USAGE; }
    int t = bashts_resolve_tree_with_path (args->word->word, NULL);
    if (t < 0) { builtin_error ("free: invalid tree handle: %s", args->word->word); return EX_USAGE; }
    ts_tree_delete (bashts_tree_pool[t].tree);
    bashts_tree_pool[t].tree   = NULL;
    bashts_tree_pool[t].in_use = 0;
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
    if (!strcmp (cmd, "free"))            return bashts_free_cmd           (args);
    builtin_error ("unknown verb: %s "
                   "(try version/language-list/parse/query/highlight/"
                   "cursor-walk/parse-tree/root/node-type/node-range/"
                   "node-children/free)", cmd);
    return EX_USAGE;
}

char *ts_doc[] = {
    "tree-sitter parsing runtime.",
    "",
    "    ts version              print runtime ABI + library version",
    "    ts language-list        names of compiled-in grammars",
    "    ts parse -L LANG        parse stdin via LANG grammar (7.B)",
    "    ts query -L LANG -q Q   run S-expression query against parse tree",
    "    ts highlight -L LANG    apply curated highlights.scm to stdin",
    "    ts cursor-walk -L LANG  depth-first dump of every node",
    "                  [-n] [-d N]    -n: named only; -d N: cap depth at N",
    "",
    "v0 ships the tree-sitter runtime (~12K LoC vendored) so dependent",
    "stages (7.B grammar vendoring, 7.C parse/query, 7.D hl,",
    "7.E nano render-side highlight) land directly against the C API",
    "instead of being prototyped in bash and ported later.",
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
