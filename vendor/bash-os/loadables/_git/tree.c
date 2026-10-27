/* SPDX-License-Identifier: MIT */
/* _git/tree.c — trees: building them from the index, and reading them back.
 * See tree.h.
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

#include "loadables.h"

#include "index.h"
#include "odb.h"
#include "tree.h"

/* One entry of the tree being built. */
typedef struct {
    char *name;
    char mode[8];
    unsigned char sha[20];
    int is_dir;
} bgit_tree_entry;

/* git's order: bytes, with a directory compared as though its name ended
   in '/'. That is what puts "a.b" before "a/b"'s tree in the same place git
   does. */
static int
bgit_tree_entry_cmp (const void *va, const void *vb)
{
    const bgit_tree_entry *a = va, *b = vb;
    size_t la = strlen (a->name), lb = strlen (b->name);
    size_t n = la < lb ? la : lb;
    int c = memcmp (a->name, b->name, n);
    if (c) return c;
    if (la == lb) return 0;
    int ca = la > n ? (unsigned char) a->name[n] : (a->is_dir ? '/' : 0);
    int cb = lb > n ? (unsigned char) b->name[n] : (b->is_dir ? '/' : 0);
    return ca - cb;
}

static void
bgit_tree_entries_free (bgit_tree_entry *entries, size_t n)
{
    for (size_t i = 0; i < n; i++) free (entries[i].name);
    free (entries);
}

static int
bgit_tree_entries_push (bgit_tree_entry **entries, size_t *n, size_t *cap,
                        const char *name, size_t name_len, const char *mode,
                        const unsigned char *sha, int is_dir)
{
    if (*n == *cap) {
        size_t next = *cap ? *cap * 2 : 16;
        bgit_tree_entry *grown = realloc (*entries, next * sizeof *grown);
        if (!grown) return -1;
        *entries = grown;
        *cap = next;
    }
    bgit_tree_entry *e = &(*entries)[*n];
    e->name = malloc (name_len + 1);
    if (!e->name) return -1;
    memcpy (e->name, name, name_len);
    e->name[name_len] = '\0';
    snprintf (e->mode, sizeof e->mode, "%s", mode);
    memcpy (e->sha, sha, 20);
    e->is_dir = is_dir;
    (*n)++;
    return 0;
}

/* Build the tree for the entries under PREFIX, writing subtrees first.
   *POS walks the sorted index; it stops at the first entry outside PREFIX. */
static int
bgit_write_tree_at (bgit_odb *odb, const char *objects_dir,
                    const bgit_index_entry *entries, size_t n, size_t *pos,
                    const char *prefix, size_t prefix_len, char out[41])
{
    bgit_tree_entry *children = NULL;
    size_t count = 0, cap = 0;
    (void) prefix;

    while (*pos < n) {
        const bgit_index_entry *entry = &entries[*pos];
        if (prefix_len && strncmp (entry->path, prefix, prefix_len) != 0)
            break;
        const char *rest = entry->path + prefix_len;
        const char *slash = strchr (rest, '/');
        if (!slash) {
            char mode[8];
            snprintf (mode, sizeof mode, "%o", entry->mode);
            if (bgit_tree_entries_push (&children, &count, &cap, rest,
                                        strlen (rest), mode, entry->sha, 0) < 0)
                goto fail;
            (*pos)++;
            continue;
        }
        /* A directory: recurse over every entry sharing this prefix. */
        size_t dir_len = (size_t) (slash - rest) + 1;   /* including '/' */
        char sub_prefix[4096];
        if (prefix_len + dir_len >= sizeof sub_prefix) goto fail;
        memcpy (sub_prefix, entry->path, prefix_len + dir_len);
        sub_prefix[prefix_len + dir_len] = '\0';
        char sub_sha[41];
        if (bgit_write_tree_at (odb, objects_dir, entries, n, pos, sub_prefix,
                                prefix_len + dir_len, sub_sha) < 0)
            goto fail;
        unsigned char binary[20];
        if (bgit_hex_to_sha (sub_sha, binary) < 0) goto fail;
        if (bgit_tree_entries_push (&children, &count, &cap, rest, dir_len - 1,
                                    "40000", binary, 1) < 0)
            goto fail;
    }

    if (count > 1)
        qsort (children, count, sizeof *children, bgit_tree_entry_cmp);

    /* Serialize "<mode> <name>\0<20 bytes>" for each entry. */
    size_t body_cap = 256, body_len = 0;
    unsigned char *body = malloc (body_cap);
    if (!body) goto fail;
    for (size_t i = 0; i < count; i++) {
        size_t need = strlen (children[i].mode) + 1 + strlen (children[i].name) + 1 + 20;
        if (body_len + need > body_cap) {
            while (body_len + need > body_cap) body_cap *= 2;
            unsigned char *grown = realloc (body, body_cap);
            if (!grown) { free (body); goto fail; }
            body = grown;
        }
        size_t mode_len = strlen (children[i].mode);
        memcpy (body + body_len, children[i].mode, mode_len);
        body_len += mode_len;
        body[body_len++] = ' ';
        size_t name_len = strlen (children[i].name);
        memcpy (body + body_len, children[i].name, name_len);
        body_len += name_len;
        body[body_len++] = '\0';
        memcpy (body + body_len, children[i].sha, 20);
        body_len += 20;
    }
    int rc = bgit_write_object (objects_dir, "tree", body, body_len, 1, out);
    free (body);
    bgit_tree_entries_free (children, count);
    return rc;
fail:
    bgit_tree_entries_free (children, count);
    return -1;
}

int
bgit_write_tree (bgit_odb *odb, const char *objects_dir,
                 const bgit_index_entry *entries, size_t n, char out[41])
{
    for (size_t i = 0; i < n; i++) {
        if (((entries[i].flags >> 12) & 0x3) != 0) {
            builtin_error ("%s: unmerged (%s)", entries[i].path, "cannot write a tree");
            return -1;
        }
    }
    size_t pos = 0;
    return bgit_write_tree_at (odb, objects_dir, entries, n, &pos, "", 0, out);
}

/* The type a tree entry's mode implies. */
static const char *
bgit_tree_type (const char *mode)
{
    if (!strcmp (mode, "40000") || !strcmp (mode, "040000")) return "tree";
    if (!strcmp (mode, "160000")) return "commit";
    return "blob";
}

int
bgit_tree_walk (bgit_odb *odb, const char *tree_sha, const char *prefix,
                int recursive, int show_trees, bgit_tree_fn fn, void *ctx)
{
    enum bgit_type type;
    unsigned char *data = NULL;
    size_t len = 0;
    if (bgit_odb_read (odb, tree_sha, &type, &data, &len) < 0) return -1;
    if (type != BGIT_TREE) { free (data); return -1; }
    int rc = 0;
    size_t pos = 0;
    while (pos < len) {
        size_t mode_start = pos;
        while (pos < len && data[pos] != ' ') pos++;
        if (pos >= len) { rc = -1; break; }
        size_t mode_len = pos - mode_start;
        char mode[16];
        if (mode_len >= sizeof mode) { rc = -1; break; }
        memcpy (mode, data + mode_start, mode_len);
        mode[mode_len] = '\0';
        pos++;
        size_t name_start = pos;
        while (pos < len && data[pos] != '\0') pos++;
        if (pos >= len) { rc = -1; break; }
        size_t name_len = pos - name_start;
        /* A tree entry is one component, never an index-style path.
           Validate before recursion or callbacks can use it on disk. */
        if (!bgit_index_path_valid ((const char *) data + name_start) ||
            memchr (data + name_start, '/', name_len)) {
            builtin_error ("invalid tree entry name '%s'", data + name_start);
            rc = -1;
            break;
        }
        pos++;
        if (pos + 20 > len) { rc = -1; break; }
        char hex[41];
        bgit_sha_to_hex (data + pos, hex);
        pos += 20;

        char path[4096];
        if (snprintf (path, sizeof path, "%s%.*s", prefix ? prefix : "",
                      (int) name_len, (const char *) (data + name_start)) >=
            (int) sizeof path) {
            rc = -1;
            break;
        }
        const char *kind = bgit_tree_type (mode);
        int is_tree = !strcmp (kind, "tree");
        if (!is_tree || !recursive || show_trees) {
            rc = fn (ctx, mode, kind, hex, path);
            if (rc) break;
        }
        if (is_tree && recursive) {
            char sub_prefix[4096];
            if (snprintf (sub_prefix, sizeof sub_prefix, "%s/", path) >=
                (int) sizeof sub_prefix) {
                rc = -1;
                break;
            }
            rc = bgit_tree_walk (odb, hex, sub_prefix, recursive, show_trees,
                                 fn, ctx);
            if (rc) break;
        }
    }
    free (data);
    return rc;
}

/* Collect a tree into index entries. */
struct bgit_read_tree_ctx {
    bgit_index_entry *entries;
    size_t n, cap;
};

static int
bgit_read_tree_entry (void *vctx, const char *mode, const char *type,
                      const char *sha, const char *path)
{
    struct bgit_read_tree_ctx *ctx = vctx;
    if (!strcmp (type, "tree")) return 0;
    if (ctx->n == ctx->cap) {
        size_t next = ctx->cap ? ctx->cap * 2 : 32;
        bgit_index_entry *grown = realloc (ctx->entries, next * sizeof *grown);
        if (!grown) return -1;
        ctx->entries = grown;
        ctx->cap = next;
    }
    bgit_index_entry *e = &ctx->entries[ctx->n];
    memset (e, 0, sizeof *e);
    e->mode = (uint32_t) strtoul (mode, NULL, 8);
    if (bgit_hex_to_sha (sha, e->sha) < 0) return -1;
    size_t len = strlen (path);
    e->flags = (uint16_t) (len > 0xFFF ? 0xFFF : len);
    e->path = strdup (path);
    if (!e->path) return -1;
    ctx->n++;
    return 0;
}

int
bgit_read_tree (bgit_odb *odb, const char *tree_sha, bgit_index_entry **entries,
                size_t *n)
{
    struct bgit_read_tree_ctx ctx = {0};
    if (bgit_tree_walk (odb, tree_sha, "", 1, 0, bgit_read_tree_entry, &ctx) < 0) {
        bgit_index_free_entries (ctx.entries, ctx.n);
        return -1;
    }
    if (ctx.n > 1)
        qsort (ctx.entries, ctx.n, sizeof *ctx.entries, bgit_index_path_cmp);
    *entries = ctx.entries;
    *n = ctx.n;
    return 0;
}
