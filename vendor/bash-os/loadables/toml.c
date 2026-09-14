/* SPDX-License-Identifier: MIT */
/* toml.c — TOML parser/emitter for bash-os (Phase J.2).
 *
 * Wraps cktan/tomlc17 (vendored under _tomlc17/, flattened to
 * builtins/_tomlc17_*.c at build time). Sibling of json.
 *
 * Verbs:
 *   toml parse FILE [-V VAR_PREFIX]
 *       Parse FILE, bind every leaf as <PREFIX>_<UPPER_DOTTED_KEY>=value.
 *       Booleans → 0/1 (Q4=a). Datetimes → ISO 8601 string (Q3=a).
 *       Arrays of tables → <PREFIX>_<KEY>__N_<FIELD>; scalar arrays →
 *       <PREFIX>_<KEY>_LEN + <PREFIX>_<KEY>_<N>.
 *       Optional: -A ASSOC_VAR also binds full TOML paths into a bash
 *       associative array without changing -V output.
 *
 *   toml get FILE KEY [-V VAR]
 *       Print (or bind) the scalar at KEY. Dotted keys + bracket
 *       indexing: server.port, entry[0].name.
 *
 *   toml keys FILE [PREFIX]
 *       List keys at the table identified by PREFIX (or top-level).
 *
 *   toml type FILE KEY
 *       Print: string|int|float|bool|datetime|array|table|unknown.
 *
 *   toml count FILE KEY
 *       For an array (or array-of-tables): print element count.
 *
 *   toml validate FILE
 *       Exit 0 if valid TOML, 1 if not (error to stderr).
 *
 *   toml emit FILE [-F FD]
 *       Reparse FILE and re-emit TOML from the parsed tree.
 *
 *   toml emit -V VAR_PREFIX [-F FD]
 *       Emit a valid TOML document from prior parse-bound vars. This is
 *       string-oriented: bash variables do not retain TOML type/table
 *       metadata.
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
#include <strings.h>
#include <errno.h>
#include <ctype.h>

#include "loadables.h"
#include "_tomlc17_tomlc17.h"

/* ---- helpers ---- */

/* Read whole file into malloc'd buffer (NUL-terminated). */
static char *
bt_slurp (const char *path, size_t *out_len)
{
    FILE *fp = fopen (path, "rb");
    if (!fp) {
        builtin_error ("%s: %s", path, strerror (errno));
        return NULL;
    }
    fseek (fp, 0, SEEK_END);
    long sz = ftell (fp);
    fseek (fp, 0, SEEK_SET);
    if (sz < 0) { fclose (fp); return NULL; }
    char *buf = malloc ((size_t) sz + 1);
    if (!buf) { fclose (fp); return NULL; }
    size_t got = fread (buf, 1, (size_t) sz, fp);
    fclose (fp);
    buf[got] = '\0';
    *out_len = got;
    return buf;
}

/* Append SRC to DST_BUF + DST_LEN, growing the buffer. */
static int
bt_append (char **buf, size_t *len, size_t *cap, const char *src)
{
    size_t sl = strlen (src);
    if (*len + sl + 1 > *cap) {
        size_t nc = (*cap ? *cap * 2 : 256);
        while (nc < *len + sl + 1) nc *= 2;
        char *nb = realloc (*buf, nc);
        if (!nb) return -1;
        *buf = nb;
        *cap = nc;
    }
    memcpy (*buf + *len, src, sl);
    *len += sl;
    (*buf)[*len] = '\0';
    return 0;
}

/* Convert bash var-name component: uppercase + replace non-[A-Z0-9_] with _ */
static void
bt_var_segment (const char *src, char *dst, size_t dstsz)
{
    size_t i = 0;
    for (const char *p = src; *p && i + 1 < dstsz; p++) {
        char c = *p;
        if (c >= 'a' && c <= 'z') c = c - 'a' + 'A';
        else if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
            /* keep */
        } else {
            c = '_';
        }
        dst[i++] = c;
    }
    dst[i] = '\0';
}

/* ISO 8601 date/time emission. */
static void
bt_emit_datetime (toml_datum_t d, char *out, size_t outsz)
{
    /* Build "YYYY-MM-DDTHH:MM:SS.ffffff[+/-]HH:MM" or partial. */
    int has_date = (d.type == TOML_DATE || d.type == TOML_DATETIME ||
                    d.type == TOML_DATETIMETZ);
    int has_time = (d.type == TOML_TIME || d.type == TOML_DATETIME ||
                    d.type == TOML_DATETIMETZ);
    int has_tz   = (d.type == TOML_DATETIMETZ);
    char buf[128];
    int pos = 0;
    if (has_date) {
        pos += snprintf (buf + pos, sizeof buf - pos, "%04d-%02d-%02d",
                         d.u.ts.year, d.u.ts.month, d.u.ts.day);
    }
    if (has_time) {
        if (has_date) buf[pos++] = 'T';
        pos += snprintf (buf + pos, sizeof buf - pos, "%02d:%02d:%02d",
                         d.u.ts.hour, d.u.ts.minute, d.u.ts.second);
        if (d.u.ts.usec) {
            pos += snprintf (buf + pos, sizeof buf - pos, ".%06d", d.u.ts.usec);
        }
    }
    if (has_tz) {
        int tz = d.u.ts.tz;
        if (tz == 0) {
            pos += snprintf (buf + pos, sizeof buf - pos, "Z");
        } else {
            char sign = (tz >= 0) ? '+' : '-';
            int abs_tz = tz < 0 ? -tz : tz;
            pos += snprintf (buf + pos, sizeof buf - pos, "%c%02d:%02d",
                             sign, abs_tz / 60, abs_tz % 60);
        }
    }
    snprintf (out, outsz, "%s", buf);
}

/* Type-name string for `type` verb. */
static const char *
bt_type_name (toml_type_t t)
{
    switch (t) {
    case TOML_STRING:      return "string";
    case TOML_INT64:       return "int";
    case TOML_FP64:        return "float";
    case TOML_BOOLEAN:     return "bool";
    case TOML_DATE:
    case TOML_TIME:
    case TOML_DATETIME:
    case TOML_DATETIMETZ:  return "datetime";
    case TOML_ARRAY:       return "array";
    case TOML_TABLE:       return "table";
    default:               return "unknown";
    }
}

static int
bt_bare_key (const char *s)
{
    if (!s || !*s) return 0;
    for (const unsigned char *p = (const unsigned char *) s; *p; p++)
        if (!(isalnum (*p) || *p == '_' || *p == '-')) return 0;
    return 1;
}

static void
bt_format_key_segment (const char *s, char *out, size_t outsz)
{
    size_t n = 0;
    if (bt_bare_key (s)) {
        snprintf (out, outsz, "%s", s);
        return;
    }
    if (outsz == 0) return;
    out[n++] = '"';
    for (const unsigned char *p = (const unsigned char *) (s ? s : "");
         *p && n + 2 < outsz; p++) {
        if (*p == '\\' || *p == '"') {
            if (n + 3 >= outsz) break;
            out[n++] = '\\';
            out[n++] = (char) *p;
        } else if (*p == '\n') {
            if (n + 3 >= outsz) break;
            out[n++] = '\\'; out[n++] = 'n';
        } else if (*p == '\r') {
            if (n + 3 >= outsz) break;
            out[n++] = '\\'; out[n++] = 'r';
        } else if (*p == '\t') {
            if (n + 3 >= outsz) break;
            out[n++] = '\\'; out[n++] = 't';
        } else if (*p < 0x20) {
            if (n + 7 >= outsz) break;
            n += (size_t) snprintf (out + n, outsz - n, "\\u%04x", (unsigned) *p);
        } else {
            out[n++] = (char) *p;
        }
    }
    if (n + 1 < outsz) out[n++] = '"';
    out[n] = '\0';
}

static void
bt_join_path (const char *path, const char *key, char *out, size_t outsz)
{
    char seg[512];
    bt_format_key_segment (key, seg, sizeof seg);
    if (path && path[0])
        snprintf (out, outsz, "%s.%s", path, seg);
    else
        snprintf (out, outsz, "%s", seg);
}

/* Convert a leaf datum to a string representation for bash binding.
   Returns 0 on success, -1 on alloc failure. */
static int
bt_leaf_str (toml_datum_t v, char *out, size_t outsz)
{
    switch (v.type) {
    case TOML_STRING:
        snprintf (out, outsz, "%s", v.u.str.ptr ? v.u.str.ptr : "");
        return 0;
    case TOML_INT64:
        snprintf (out, outsz, "%lld", (long long) v.u.int64);
        return 0;
    case TOML_FP64:
        snprintf (out, outsz, "%g", v.u.fp64);
        return 0;
    case TOML_BOOLEAN:
        snprintf (out, outsz, "%d", v.u.boolean ? 1 : 0);
        return 0;
    case TOML_DATE:
    case TOML_TIME:
    case TOML_DATETIME:
    case TOML_DATETIMETZ:
        bt_emit_datetime (v, out, outsz);
        return 0;
    default:
        out[0] = '\0';
        return 0;
    }
}

/* Recursively walk a TOML datum, binding each leaf as a bash var
   <prefix>_<path>. For arrays of tables: <prefix>_<KEY>__N_<FIELD>.
   For scalar arrays: <prefix>_<KEY>_LEN + <prefix>_<KEY>_<N>. */
static int
bt_walk_bind (toml_datum_t node, const char *prefix, const char *path)
{
    char fullkey[1024];
    if (path[0] == '\0') snprintf (fullkey, sizeof fullkey, "%s", prefix);
    else                 snprintf (fullkey, sizeof fullkey, "%s_%s", prefix, path);

    if (node.type == TOML_TABLE) {
        for (int i = 0; i < node.u.tab.size; i++) {
            char seg[256], child_path[1024];
            bt_var_segment (node.u.tab.key[i], seg, sizeof seg);
            if (path[0] == '\0') snprintf (child_path, sizeof child_path, "%s", seg);
            else                 snprintf (child_path, sizeof child_path, "%s_%s", path, seg);
            if (bt_walk_bind (node.u.tab.value[i], prefix, child_path) < 0) return -1;
        }
        return 0;
    }
    if (node.type == TOML_ARRAY) {
        /* Distinguish array-of-tables from scalar array. */
        int is_aot = (node.u.arr.size > 0 && node.u.arr.elem[0].type == TOML_TABLE);
        char count_buf[32];
        snprintf (count_buf, sizeof count_buf, "%d", node.u.arr.size);
        /* <fullkey>_LEN binding — useful for both shapes. */
        char len_var[1100];
        snprintf (len_var, sizeof len_var, "%s_LEN", fullkey);
        builtin_bind_variable (len_var, count_buf, 0);
        for (int i = 0; i < node.u.arr.size; i++) {
            char child_path[1024];
            if (is_aot) {
                /* <KEY>__<I>_<FIELD> */
                if (path[0] == '\0') snprintf (child_path, sizeof child_path, "_%d", i);
                else                 snprintf (child_path, sizeof child_path, "%s__%d", path, i);
            } else {
                if (path[0] == '\0') snprintf (child_path, sizeof child_path, "%d", i);
                else                 snprintf (child_path, sizeof child_path, "%s_%d", path, i);
            }
            if (node.u.arr.elem[i].type == TOML_TABLE) {
                if (bt_walk_bind (node.u.arr.elem[i], prefix, child_path) < 0) return -1;
            } else {
                /* Scalar: bind <fullkey>_<i> */
                char val[4096];
                bt_leaf_str (node.u.arr.elem[i], val, sizeof val);
                char vname[1100];
                if (path[0] == '\0')
                    snprintf (vname, sizeof vname, "%s_%d", prefix, i);
                else
                    snprintf (vname, sizeof vname, "%s_%s_%d", prefix, path, i);
                builtin_bind_variable (vname, val, 0);
            }
        }
        return 0;
    }
    /* Leaf (scalar). */
    char val[4096];
    bt_leaf_str (node, val, sizeof val);
    builtin_bind_variable (fullkey, val, 0);
    return 0;
}

#if defined (ARRAY_VARS)
static int
bt_assoc_bind_one (SHELL_VAR *v, const char *name, const char *key, const char *value)
{
    return bind_assoc_variable (v, name, savestring ((char *) key),
                                value ? value : "", ASS_FORCE) != 0 ? 0 : -1;
}

static int
bt_walk_bind_assoc (toml_datum_t node, SHELL_VAR *v, const char *name,
                    const char *path)
{
    if (node.type == TOML_TABLE) {
        for (int i = 0; i < node.u.tab.size; i++) {
            char child_path[1024];
            if (path[0] == '\0')
                snprintf (child_path, sizeof child_path, "%s", node.u.tab.key[i]);
            else
                snprintf (child_path, sizeof child_path, "%s.%s", path, node.u.tab.key[i]);
            if (bt_walk_bind_assoc (node.u.tab.value[i], v, name, child_path) < 0)
                return -1;
        }
        return 0;
    }
    if (node.type == TOML_ARRAY) {
        char count_key[1100], count_buf[32];
        snprintf (count_key, sizeof count_key, "%s.len", path);
        snprintf (count_buf, sizeof count_buf, "%d", node.u.arr.size);
        if (bt_assoc_bind_one (v, name, count_key, count_buf) < 0) return -1;
        for (int i = 0; i < node.u.arr.size; i++) {
            char child_path[1024];
            snprintf (child_path, sizeof child_path, "%s[%d]", path, i);
            if (node.u.arr.elem[i].type == TOML_TABLE) {
                if (bt_walk_bind_assoc (node.u.arr.elem[i], v, name, child_path) < 0)
                    return -1;
            } else {
                char val[4096];
                bt_leaf_str (node.u.arr.elem[i], val, sizeof val);
                if (bt_assoc_bind_one (v, name, child_path, val) < 0) return -1;
            }
        }
        return 0;
    }
    if (path[0]) {
        char val[4096];
        bt_leaf_str (node, val, sizeof val);
        return bt_assoc_bind_one (v, name, path, val);
    }
    return 0;
}

static int
bt_bind_assoc (toml_datum_t root, const char *name)
{
    if (!name) return 0;
    if (valid_identifier ((char *) name) == 0) { sh_invalidid ((char *) name); return -1; }
    SHELL_VAR *v = find_or_make_array_variable ((char *) name, 3);
    if (v == 0 || readonly_p (v) || noassign_p (v)) return -1;
    if (assoc_p (v) == 0) { builtin_error ("%s: not an associative array", name); return -1; }
    if (invisible_p (v)) VUNSETATTR (v, att_invisible);
    assoc_flush (assoc_cell (v));
    return bt_walk_bind_assoc (root, v, name, "");
}
#else
static int
bt_bind_assoc (toml_datum_t root, const char *name)
{
    (void) root;
    if (name) builtin_error ("parse: associative arrays not enabled in this bash");
    return name ? -1 : 0;
}
#endif

static int
bt_hex_value (unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int
bt_read_hex_scalar (const char **pp, int ndigits, unsigned int *out)
{
    const char *p = *pp;
    unsigned int cp = 0;

    for (int i = 0; i < ndigits; i++) {
        int hv;

        if (*p == '\0') return -1;
        hv = bt_hex_value ((unsigned char) *p);
        if (hv < 0) return -1;
        cp = (cp << 4) | (unsigned int) hv;
        p++;
    }
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
        return -1;
    *pp = p;
    *out = cp;
    return 0;
}

static int
bt_append_utf8_scalar (char *piece, size_t piecesz, size_t *n, unsigned int cp)
{
    unsigned char bytes[4];
    size_t nb;

    if (cp <= 0x7f) {
        bytes[0] = (unsigned char) cp;
        nb = 1;
    } else if (cp <= 0x7ff) {
        bytes[0] = (unsigned char) (0xc0 | (cp >> 6));
        bytes[1] = (unsigned char) (0x80 | (cp & 0x3f));
        nb = 2;
    } else if (cp <= 0xffff) {
        bytes[0] = (unsigned char) (0xe0 | (cp >> 12));
        bytes[1] = (unsigned char) (0x80 | ((cp >> 6) & 0x3f));
        bytes[2] = (unsigned char) (0x80 | (cp & 0x3f));
        nb = 3;
    } else {
        bytes[0] = (unsigned char) (0xf0 | (cp >> 18));
        bytes[1] = (unsigned char) (0x80 | ((cp >> 12) & 0x3f));
        bytes[2] = (unsigned char) (0x80 | ((cp >> 6) & 0x3f));
        bytes[3] = (unsigned char) (0x80 | (cp & 0x3f));
        nb = 4;
    }
    if (*n + nb >= piecesz) return -1;
    memcpy (piece + *n, bytes, nb);
    *n += nb;
    return 0;
}

static int
bt_read_quoted_key (const char **pp, char *piece, size_t piecesz)
{
    const char quote = **pp;
    const char *p = *pp + 1;
    size_t n = 0;

    while (*p && *p != quote) {
        unsigned char c = (unsigned char) *p++;
        if (quote == '"' && c == '\\') {
            unsigned int cp;

            c = (unsigned char) *p++;
            switch (c) {
            case 'b': c = '\b'; break;
            case 't': c = '\t'; break;
            case 'n': c = '\n'; break;
            case 'f': c = '\f'; break;
            case 'r': c = '\r'; break;
            case '"': c = '"'; break;
            case '\\': c = '\\'; break;
            case 'u':
                if (bt_read_hex_scalar (&p, 4, &cp) < 0 ||
                    bt_append_utf8_scalar (piece, piecesz, &n, cp) < 0)
                    return -1;
                continue;
            case 'U':
                if (bt_read_hex_scalar (&p, 8, &cp) < 0 ||
                    bt_append_utf8_scalar (piece, piecesz, &n, cp) < 0)
                    return -1;
                continue;
            default: return -1;
            }
        }
        if (n + 1 >= piecesz) return -1;
        piece[n++] = (char) c;
    }
    if (*p != quote) return -1;
    piece[n] = '\0';
    *pp = p + 1;
    return 0;
}

/* Resolve a multipart key with optional bracket indexing into a datum.
   Examples: "title", "server.port", "entry[0].name", "\"key.with.dot\"". */
static toml_datum_t
bt_seek (toml_datum_t root, const char *key)
{
    toml_datum_t cur = root;
    const char *p = key;
    while (*p) {
        /* Read identifier or [N]. */
        if (*p == '[') {
            p++;
            int idx = 0;
            while (*p >= '0' && *p <= '9') { idx = idx * 10 + (*p - '0'); p++; }
            if (*p != ']') { toml_datum_t bad = {0}; return bad; }
            p++;
            if (cur.type != TOML_ARRAY || idx < 0 || idx >= cur.u.arr.size) {
                toml_datum_t bad = {0}; return bad;
            }
            cur = cur.u.arr.elem[idx];
            if (*p == '.') p++;
            continue;
        }
        char piece[256];
        if (*p == '"' || *p == '\'') {
            if (bt_read_quoted_key (&p, piece, sizeof piece) < 0)
                { toml_datum_t bad = {0}; return bad; }
        } else {
            const char *start = p;
            while (*p && *p != '.' && *p != '[') p++;
            size_t len = (size_t) (p - start);
            if (len >= sizeof piece) { toml_datum_t bad = {0}; return bad; }
            memcpy (piece, start, len); piece[len] = '\0';
        }
        cur = toml_get (cur, piece);
        if (cur.type == TOML_UNKNOWN) return cur;
        if (*p == '.') p++;
    }
    return cur;
}

/* ---- verb implementations ---- */

static int
bt_parse_cmd (WORD_LIST *args)
{
    const char *file = NULL, *prefix = NULL, *assoc_var = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-V") == 0 && p->next) { prefix = p->next->word->word; p = p->next; }
        else if ((strcmp (w, "-A") == 0 || strcmp (w, "--assoc") == 0) && p->next) {
            assoc_var = p->next->word->word; p = p->next;
        }
        else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("parse: unknown flag %s", w); builtin_usage (); return EX_USAGE;
        } else {
            if (file) { builtin_error ("parse: too many args"); builtin_usage (); return EX_USAGE; }
            file = w;
        }
    }
    if (!file) { builtin_error ("parse: FILE required"); builtin_usage (); return EX_USAGE; }
    if (!prefix) prefix = "TOML";

    size_t len;
    char *src = bt_slurp (file, &len);
    if (!src) return EXECUTION_FAILURE;
    toml_result_t r = toml_parse (src, (int) len);
    free (src);
    if (!r.ok) {
        builtin_error ("parse %s: %s", file, r.errmsg);
        toml_free (r);
        return EXECUTION_FAILURE;
    }
    int rc = EXECUTION_SUCCESS;
    if (bt_walk_bind (r.toptab, prefix, "") < 0) rc = EXECUTION_FAILURE;
    if (assoc_var && bt_bind_assoc (r.toptab, assoc_var) < 0) rc = EXECUTION_FAILURE;
    toml_free (r);
    return rc;
}

static int
bt_get_cmd (WORD_LIST *args)
{
    const char *file = NULL, *key = NULL, *var = NULL;
    int npos = 0;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-V") == 0 && p->next) { var = p->next->word->word; p = p->next; }
        else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("get: unknown flag %s", w); builtin_usage (); return EX_USAGE;
        } else {
            if (npos == 0) file = w;
            else if (npos == 1) key = w;
            else { builtin_error ("get: too many args"); builtin_usage (); return EX_USAGE; }
            npos++;
        }
    }
    if (!file || !key) { builtin_error ("get: FILE KEY required"); builtin_usage (); return EX_USAGE; }

    size_t len;
    char *src = bt_slurp (file, &len);
    if (!src) return EXECUTION_FAILURE;
    toml_result_t r = toml_parse (src, (int) len);
    free (src);
    if (!r.ok) { builtin_error ("parse %s: %s", file, r.errmsg); toml_free (r); return EXECUTION_FAILURE; }
    toml_datum_t v = bt_seek (r.toptab, key);
    if (v.type == TOML_UNKNOWN) {
        toml_free (r);
        return EXECUTION_FAILURE;
    }
    char val[4096];
    bt_leaf_str (v, val, sizeof val);
    if (var) builtin_bind_variable ((char *) var, val, 0);
    else     printf ("%s\n", val);
    toml_free (r);
    return EXECUTION_SUCCESS;
}

static int
bt_keys_cmd (WORD_LIST *args)
{
    const char *file = NULL, *prefix_key = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!file) file = w;
        else if (!prefix_key) prefix_key = w;
        else { builtin_error ("keys: too many args"); builtin_usage (); return EX_USAGE; }
    }
    if (!file) { builtin_error ("keys: FILE required"); builtin_usage (); return EX_USAGE; }

    size_t len;
    char *src = bt_slurp (file, &len);
    if (!src) return EXECUTION_FAILURE;
    toml_result_t r = toml_parse (src, (int) len);
    free (src);
    if (!r.ok) { builtin_error ("parse %s: %s", file, r.errmsg); toml_free (r); return EXECUTION_FAILURE; }
    toml_datum_t target = prefix_key ? bt_seek (r.toptab, prefix_key) : r.toptab;
    if (target.type != TOML_TABLE) {
        toml_free (r);
        builtin_error ("keys: %s is not a table", prefix_key ? prefix_key : "<top>");
        return EXECUTION_FAILURE;
    }
    for (int i = 0; i < target.u.tab.size; i++) {
        printf ("%s\n", target.u.tab.key[i]);
    }
    toml_free (r);
    return EXECUTION_SUCCESS;
}

static int
bt_type_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("type: FILE KEY"); builtin_usage (); return EX_USAGE; }
    const char *file = args->word->word;
    const char *key = args->next->word->word;
    size_t len;
    char *src = bt_slurp (file, &len);
    if (!src) return EXECUTION_FAILURE;
    toml_result_t r = toml_parse (src, (int) len);
    free (src);
    if (!r.ok) { builtin_error ("parse %s: %s", file, r.errmsg); toml_free (r); return EXECUTION_FAILURE; }
    toml_datum_t v = bt_seek (r.toptab, key);
    printf ("%s\n", bt_type_name (v.type));
    toml_free (r);
    return v.type == TOML_UNKNOWN ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bt_count_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("count: FILE KEY"); builtin_usage (); return EX_USAGE; }
    const char *file = args->word->word;
    const char *key = args->next->word->word;
    size_t len;
    char *src = bt_slurp (file, &len);
    if (!src) return EXECUTION_FAILURE;
    toml_result_t r = toml_parse (src, (int) len);
    free (src);
    if (!r.ok) { builtin_error ("parse %s: %s", file, r.errmsg); toml_free (r); return EXECUTION_FAILURE; }
    toml_datum_t v = bt_seek (r.toptab, key);
    if (v.type != TOML_ARRAY) {
        toml_free (r);
        builtin_error ("count: %s is not an array", key);
        return EXECUTION_FAILURE;
    }
    printf ("%d\n", v.u.arr.size);
    toml_free (r);
    return EXECUTION_SUCCESS;
}

static int
bt_validate_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("validate: FILE"); builtin_usage (); return EX_USAGE; }
    const char *file = args->word->word;
    size_t len;
    char *src = bt_slurp (file, &len);
    if (!src) return EXECUTION_FAILURE;
    toml_result_t r = toml_parse (src, (int) len);
    free (src);
    if (!r.ok) {
        builtin_error ("invalid toml: %s", r.errmsg);
        toml_free (r);
        return EXECUTION_FAILURE;
    }
    toml_free (r);
    return EXECUTION_SUCCESS;
}

static int bt_emit_quoted (char **buf, size_t *blen, size_t *bcap, const char *s);
static int bt_emit_value (char **buf, size_t *blen, size_t *bcap, toml_datum_t v);

static int
bt_emit_inline_table (char **buf, size_t *blen, size_t *bcap, toml_datum_t v)
{
    char tmp[4096];
    if (bt_append (buf, blen, bcap, "{ ") < 0) return -1;
    for (int i = 0; i < v.u.tab.size; i++) {
        if (i > 0 && bt_append (buf, blen, bcap, ", ") < 0) return -1;
        bt_format_key_segment (v.u.tab.key[i], tmp, sizeof tmp);
        if (bt_append (buf, blen, bcap, tmp) < 0) return -1;
        if (bt_append (buf, blen, bcap, " = ") < 0) return -1;
        if (bt_emit_value (buf, blen, bcap, v.u.tab.value[i]) < 0) return -1;
    }
    return bt_append (buf, blen, bcap, " }");
}

static int
bt_emit_array_value (char **buf, size_t *blen, size_t *bcap, toml_datum_t v)
{
    if (bt_append (buf, blen, bcap, "[") < 0) return -1;
    for (int i = 0; i < v.u.arr.size; i++) {
        if (i > 0 && bt_append (buf, blen, bcap, ", ") < 0) return -1;
        if (bt_emit_value (buf, blen, bcap, v.u.arr.elem[i]) < 0) return -1;
    }
    return bt_append (buf, blen, bcap, "]");
}

static int
bt_emit_value (char **buf, size_t *blen, size_t *bcap, toml_datum_t v)
{
    char tmp[4096];
    switch (v.type) {
    case TOML_STRING:
        return bt_emit_quoted (buf, blen, bcap, v.u.str.ptr ? v.u.str.ptr : "");
    case TOML_INT64:
        snprintf (tmp, sizeof tmp, "%lld", (long long) v.u.int64);
        return bt_append (buf, blen, bcap, tmp);
    case TOML_FP64:
        snprintf (tmp, sizeof tmp, "%g", v.u.fp64);
        return bt_append (buf, blen, bcap, tmp);
    case TOML_BOOLEAN:
        return bt_append (buf, blen, bcap, v.u.boolean ? "true" : "false");
    case TOML_DATE:
    case TOML_TIME:
    case TOML_DATETIME:
    case TOML_DATETIMETZ:
        bt_emit_datetime (v, tmp, sizeof tmp);
        return bt_append (buf, blen, bcap, tmp);
    case TOML_ARRAY:
        return bt_emit_array_value (buf, blen, bcap, v);
    case TOML_TABLE:
        return bt_emit_inline_table (buf, blen, bcap, v);
    default:
        return bt_append (buf, blen, bcap, "\"\"");
    }
}

/* Recursively walk a datum, emitting TOML text. Tables become section
   headers; scalars become "key = value" lines. */
static int
bt_emit_walk (toml_datum_t node, const char *path,
              char **buf, size_t *blen, size_t *bcap, int top_level)
{
    char tmp[4096];
    if (node.type == TOML_TABLE) {
        /* Emit scalars first, then nested tables. */
        if (!top_level && path[0]) {
            snprintf (tmp, sizeof tmp, "\n[%s]\n", path);
            if (bt_append (buf, blen, bcap, tmp) < 0) return -1;
        }
        /* First pass: scalars + arrays-of-scalars */
        for (int i = 0; i < node.u.tab.size; i++) {
            const char *k = node.u.tab.key[i];
            toml_datum_t v = node.u.tab.value[i];
            if (v.type == TOML_TABLE) continue;
            if (v.type == TOML_ARRAY && v.u.arr.size > 0 &&
                v.u.arr.elem[0].type == TOML_TABLE) continue;
            bt_format_key_segment (k, tmp, sizeof tmp);
            if (bt_append (buf, blen, bcap, tmp) < 0) return -1;
            if (bt_append (buf, blen, bcap, " = ") < 0) return -1;
            if (bt_emit_value (buf, blen, bcap, v) < 0) return -1;
            if (bt_append (buf, blen, bcap, "\n") < 0) return -1;
        }
        /* Second pass: nested tables (after top-level scalars) */
        for (int i = 0; i < node.u.tab.size; i++) {
            const char *k = node.u.tab.key[i];
            toml_datum_t v = node.u.tab.value[i];
            if (v.type == TOML_TABLE) {
                char child_path[1024];
                bt_join_path (path, k, child_path, sizeof child_path);
                if (bt_emit_walk (v, child_path, buf, blen, bcap, 0) < 0) return -1;
            } else if (v.type == TOML_ARRAY && v.u.arr.size > 0 &&
                       v.u.arr.elem[0].type == TOML_TABLE) {
                /* Array of tables */
                char child_path[1024];
                bt_join_path (path, k, child_path, sizeof child_path);
                for (int j = 0; j < v.u.arr.size; j++) {
                    snprintf (tmp, sizeof tmp, "\n[[%s]]\n", child_path);
                    if (bt_append (buf, blen, bcap, tmp) < 0) return -1;
                    if (bt_emit_walk (v.u.arr.elem[j], child_path, buf, blen, bcap, 1) < 0)
                        return -1;
                }
            }
        }
    }
    return 0;
}

static const char *
bt_var_value (const char *name)
{
    SHELL_VAR *v = find_variable (name);
    if (!v) return NULL;
    return get_variable_value (v);
}

static int
bt_decimal_string (const char *s)
{
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9') return 0;
    return 1;
}

static int
bt_suffix_is_index (const char *key, char *base, size_t basesz)
{
    const char *us = strrchr (key, '_');
    if (!us || us == key || !bt_decimal_string (us + 1)) return 0;
    size_t n = (size_t) (us - key);
    if (n + 1 > basesz) return 0;
    memcpy (base, key, n);
    base[n] = '\0';
    return 1;
}

static int
bt_key_is_len (const char *key, char *base, size_t basesz)
{
    size_t n = strlen (key);
    if (n <= 4 || strcmp (key + n - 4, "_LEN") != 0) return 0;
    n -= 4;
    if (n + 1 > basesz) return 0;
    memcpy (base, key, n);
    base[n] = '\0';
    return 1;
}

static int
bt_emit_quoted (char **buf, size_t *blen, size_t *bcap, const char *s)
{
    if (bt_append (buf, blen, bcap, "\"") < 0) return -1;
    for (const unsigned char *p = (const unsigned char *) (s ? s : ""); *p; p++) {
        char tmp[8];
        switch (*p) {
        case '\\': if (bt_append (buf, blen, bcap, "\\\\") < 0) return -1; break;
        case '"':  if (bt_append (buf, blen, bcap, "\\\"") < 0) return -1; break;
        case '\n': if (bt_append (buf, blen, bcap, "\\n") < 0) return -1; break;
        case '\r': if (bt_append (buf, blen, bcap, "\\r") < 0) return -1; break;
        case '\t': if (bt_append (buf, blen, bcap, "\\t") < 0) return -1; break;
        default:
            if (*p < 0x20) {
                snprintf (tmp, sizeof tmp, "\\u%04x", (unsigned) *p);
                if (bt_append (buf, blen, bcap, tmp) < 0) return -1;
            } else {
                tmp[0] = (char) *p; tmp[1] = '\0';
                if (bt_append (buf, blen, bcap, tmp) < 0) return -1;
            }
        }
    }
    return bt_append (buf, blen, bcap, "\"");
}

static int
bt_emit_vars (const char *prefix, int fd)
{
    char pfx[256];
    snprintf (pfx, sizeof pfx, "%s_", prefix);
    char **names = all_variables_matching_prefix (pfx);
    if (!names || !names[0]) {
        if (names) strvec_dispose (names);
        builtin_error ("emit -V: no variables match prefix %s", pfx);
        return EXECUTION_FAILURE;
    }

    char *buf = NULL;
    size_t blen = 0, bcap = 0;
    size_t pfxlen = strlen (pfx);
    char tmp[1024], base[512], probe[768];

    for (int i = 0; names[i]; i++) {
        const char *key = names[i] + pfxlen;
        if (!bt_key_is_len (key, base, sizeof base)) continue;
        const char *len_s = bt_var_value (names[i]);
        if (!bt_decimal_string (len_s)) continue;
        int n = atoi (len_s);
        snprintf (tmp, sizeof tmp, "%s = [", base);
        if (bt_append (&buf, &blen, &bcap, tmp) < 0) goto oom;
        for (int j = 0; j < n; j++) {
            snprintf (probe, sizeof probe, "%s%s_%d", pfx, base, j);
            const char *val = bt_var_value (probe);
            if (j > 0 && bt_append (&buf, &blen, &bcap, ", ") < 0) goto oom;
            if (bt_emit_quoted (&buf, &blen, &bcap, val ? val : "") < 0) goto oom;
        }
        if (bt_append (&buf, &blen, &bcap, "]\n") < 0) goto oom;
    }

    for (int i = 0; names[i]; i++) {
        const char *key = names[i] + pfxlen;
        if (bt_key_is_len (key, base, sizeof base)) continue;
        if (bt_suffix_is_index (key, base, sizeof base)) {
            snprintf (probe, sizeof probe, "%s%s_LEN", pfx, base);
            if (bt_var_value (probe)) continue;
        }
        snprintf (tmp, sizeof tmp, "%s = ", key);
        if (bt_append (&buf, &blen, &bcap, tmp) < 0) goto oom;
        if (bt_emit_quoted (&buf, &blen, &bcap, bt_var_value (names[i])) < 0) goto oom;
        if (bt_append (&buf, &blen, &bcap, "\n") < 0) goto oom;
    }

    int rc = EXECUTION_SUCCESS;
    if (write (fd, buf, blen) != (ssize_t) blen) {
        builtin_error ("emit -V: write: %s", strerror (errno));
        rc = EXECUTION_FAILURE;
    }
    free (buf);
    strvec_dispose (names);
    return rc;

oom:
    free (buf);
    strvec_dispose (names);
    return EXECUTION_FAILURE;
}

/* emit -F FD : re-emit a parsed TOML doc.
 * Note: tomlc17's parsed tree is freed after each parse — to support
 * round-trip, this verb takes FILE (the source file) and re-parses
 * before emitting. `emit -V PREFIX` re-emits the scalar/array variable
 * shape produced by `parse -V PREFIX`. */
static int
bt_emit_cmd (WORD_LIST *args)
{
    const char *file = NULL, *var_prefix = NULL;
    int fd = STDOUT_FILENO;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-F") == 0 && p->next) {
            fd = atoi (p->next->word->word); p = p->next;
        } else if (strcmp (w, "-V") == 0 && p->next) {
            var_prefix = p->next->word->word; p = p->next;
        } else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("emit: unknown flag %s", w); builtin_usage (); return EX_USAGE;
        } else {
            if (file) { builtin_error ("emit: too many args"); builtin_usage (); return EX_USAGE; }
            file = w;
        }
    }
    if (var_prefix) {
        if (file) { builtin_error ("emit: FILE is not accepted with -V"); builtin_usage (); return EX_USAGE; }
        return bt_emit_vars (var_prefix, fd);
    }
    if (!file) { builtin_error ("emit: FILE required"); builtin_usage (); return EX_USAGE; }
    size_t len;
    char *src = bt_slurp (file, &len);
    if (!src) return EXECUTION_FAILURE;
    toml_result_t r = toml_parse (src, (int) len);
    free (src);
    if (!r.ok) { builtin_error ("parse %s: %s", file, r.errmsg); toml_free (r); return EXECUTION_FAILURE; }

    char *buf = NULL;
    size_t blen = 0, bcap = 0;
    int rc = bt_emit_walk (r.toptab, "", &buf, &blen, &bcap, 1);
    toml_free (r);
    if (rc < 0) { free (buf); return EXECUTION_FAILURE; }
    if (write (fd, buf, blen) != (ssize_t) blen) {
        free (buf);
        builtin_error ("emit: write: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    free (buf);
    return EXECUTION_SUCCESS;
}

int
toml_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "parse"))    return bt_parse_cmd (args);
    if (!strcmp (cmd, "get"))      return bt_get_cmd (args);
    if (!strcmp (cmd, "keys"))     return bt_keys_cmd (args);
    if (!strcmp (cmd, "type"))     return bt_type_cmd (args);
    if (!strcmp (cmd, "count"))    return bt_count_cmd (args);
    if (!strcmp (cmd, "validate")) return bt_validate_cmd (args);
    if (!strcmp (cmd, "emit"))     return bt_emit_cmd (args);
    builtin_error ("unknown verb: %s", cmd);
    builtin_usage ();
    return EX_USAGE;
}

char *toml_doc[] = {
    "TOML v1.1.0 parser + emitter (vendored cktan/tomlc17).",
    "",
    "    toml parse FILE [-V VAR_PREFIX]",
    "        Bind every leaf as <PREFIX>_<UPPER_DOTTED_KEY>=value.",
    "        Booleans → 0/1; datetimes → ISO 8601.",
    "        Optional -A/--assoc VAR binds full keys into associative array VAR.",
    "    toml get FILE KEY [-V VAR]",
    "        Print or bind one scalar. Dotted/bracket: a.b[0].c",
    "    toml keys FILE [PREFIX_KEY]",
    "        List keys of the table at PREFIX_KEY (default: top).",
    "    toml type FILE KEY",
    "        → string|int|float|bool|datetime|array|table|unknown",
    "    toml count FILE KEY",
    "        For an array (or array-of-tables): element count.",
    "    toml validate FILE",
    "        Exit 0 if valid, 1 otherwise (error to stderr).",
    "    toml emit FILE [-F FD]",
    "        Re-emit FILE as canonical TOML (round-trip).",
    "    toml emit -V VAR_PREFIX [-F FD]",
    "        Emit valid TOML from parse-bound bash vars; type/table lossy.",
    (char *)NULL
};

struct builtin toml_struct = {
    "toml",
    toml_builtin,
    BUILTIN_ENABLED,
    toml_doc,
    "toml parse|get|keys|type|count|validate|emit ARGS",
    0
};
