/* SPDX-License-Identifier: MIT */
/* undo.c — undo/redo stack for buf handles.
 *
 * Phase V V-2 of bash-os editor primitives. Operates as a side-channel
 * on a buf handle: callers tell undo what they DID after each
 * mutation; undo records the inverse. `undo` applies the inverse
 * via buf's public C API; `redo` re-applies the forward op.
 *
 * Grouping: adjacent byte insert/delete records coalesce automatically
 * within a short typing window. begin-group / end-group wraps a series
 * of record calls into a single composite undo step (type 'G'),
 * analogous to GNU nano's grouping of paste, replace-all, and
 * auto-indent operations.
 *
 * Verbs:
 *   undo new -h HVAR -B BUF_SLOT [-d DEPTH]
 *       Create undo state tied to buf slot BUF_SLOT. Slot int -> HVAR.
 *       Default depth cap: 100 ops in each of undo and redo stacks.
 *
 *   undo record HANDLE TYPE LINENO [COL] TEXT [-X]
 *       Record what just happened. TYPE:
 *         I  - inserted line LINENO with TEXT  (inverse: delete LINENO)
 *         D  - deleted line LINENO whose content was TEXT
 *                                              (inverse: insert TEXT @ LINENO)
 *         C  - changed line LINENO from TEXT to <whatever's there now>
 *                                              (inverse: replace LINENO with TEXT)
 *         A  - inserted TEXT at byte COL in line LINENO
 *                                              (inverse: delete-at LINENO COL len(TEXT))
 *         R  - removed TEXT at byte COL in line LINENO
 *                                              (inverse: insert-at LINENO COL TEXT)
 *       -X: TEXT is hex-encoded (NUL-safe).
 *
 *       record clears the redo stack - once you make a new change,
 *       the future timeline is gone. When inside a begin-group/end-group
 *       block, record appends to the internal group buffer instead; the
 *       redo-clearing happens atomically when end-group pushes the
 *       composite op.
 *
 *   undo begin-group HANDLE
 *       Open a group. Subsequent record calls accumulate. Undo will
 *       reverse all recorded ops as a single step.
 *
 *   undo end-group HANDLE
 *       Close the group and push the composite op onto the undo stack.
 *       An empty group (no record calls) is a no-op.
 *
 *   undo undo HANDLE      Pop top of undo, apply inverse, push to redo.
 *   undo redo HANDLE      Pop redo, re-apply, push back to undo.
 *   undo clear HANDLE     Empty both stacks (and any open group).
 *   undo depth HANDLE     Print "UNDO_AVAIL REDO_AVAIL".
 *   undo free HANDLE      Release the state + slot.
 *
 * --- LICENSE ---
 * MIT License - same boilerplate as binhex.c.
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
#include <sys/time.h>

#include "loadables.h"

/* ---- buf public C API (declared extern in buf.c) -------------- */
extern int bb_pub_n_lines (int slot);
extern int bb_pub_get_line (int slot, size_t index,
                            const unsigned char **out_bytes, size_t *out_len);
extern int bb_pub_insert_line (int slot, size_t index,
                               const unsigned char *bytes, size_t len);
extern int bb_pub_delete_line (int slot, size_t index);
extern int bb_pub_insert_at (int slot, size_t index, size_t col,
                             const unsigned char *bytes, size_t len);
extern int bb_pub_delete_at (int slot, size_t index, size_t col, size_t n);
extern int bb_pub_set_dirty (int slot, int dirty);

#define BU_HANDLES_MAX 32
#define BU_DEFAULT_DEPTH 100
#define BU_GROUP_USEC 1500000L

typedef struct {
    char           type;     /* 'I', 'D', 'C' */
    long           lineno;
    long           col;      /* byte column for 'A'/'R'; 0 otherwise */
    unsigned char *payload;  /* malloc'd; for D: deleted text; for C: prior text */
    size_t         paylen;
} bu_op;

typedef struct {
    int      buf_slot;
    bu_op   *undo_stack;
    size_t   undo_n, undo_cap;
    bu_op   *redo_stack;
    size_t   redo_n, redo_cap;
    size_t   max_depth;
    /* Grouping state */
    int      in_group;
    bu_op   *group_ops;     /* sub-ops accumulated during group */
    size_t   group_n, group_cap;
    long     last_record_sec;
    long     last_record_usec;
} bu_state;

static bu_state *bu_handles[BU_HANDLES_MAX] = {0};

static int
bu_alloc_handle (bu_state *s)
{
    for (int i = 0; i < BU_HANDLES_MAX; i++) {
        if (!bu_handles[i]) { bu_handles[i] = s; return i; }
    }
    return -1;
}

static bu_state *
bu_get (const char *s)
{
    char *end;
    long h = strtol (s, &end, 10);
    if (*end != '\0' || h < 0 || h >= BU_HANDLES_MAX) return NULL;
    return bu_handles[h];
}

static int
bu_get_index (const char *s)
{
    char *end;
    long h = strtol (s, &end, 10);
    if (*end != '\0' || h < 0 || h >= BU_HANDLES_MAX) return -1;
    return (int) h;
}

static unsigned char *
bu_hex_decode (const char *hex, size_t *out_len)
{
    size_t hl = strlen (hex);
    if (hl % 2 != 0) return NULL;
    size_t bl = hl / 2;
    unsigned char *out = malloc (bl + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < bl; i++) {
        int hi = hex[2*i], lo = hex[2*i+1];
        hi = (hi >= '0' && hi <= '9') ? hi - '0'
             : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10
             : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
        lo = (lo >= '0' && lo <= '9') ? lo - '0'
             : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10
             : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) { free (out); return NULL; }
        out[i] = (unsigned char) ((hi << 4) | lo);
    }
    out[bl] = '\0';
    *out_len = bl;
    return out;
}

/* Push op onto stack, growing as needed. Returns 0 on success. Honors
   max_depth by dropping the oldest entry (front-shift). */
static int
bu_push (bu_op **stack, size_t *n, size_t *cap, size_t max_depth, bu_op op)
{
    if (*n + 1 > *cap) {
        if (*cap > SIZE_MAX / 2 / sizeof (bu_op)) return -1;
        size_t nc = (*cap ? *cap * 2 : 16);
        bu_op *ns = realloc (*stack, nc * sizeof (bu_op));
        if (!ns) return -1;
        *stack = ns;
        *cap = nc;
    }
    if (*n >= max_depth) {
        /* Drop oldest. */
        free ((*stack)[0].payload);
        memmove (*stack, *stack + 1, (*n - 1) * sizeof (bu_op));
        (*n)--;
    }
    (*stack)[(*n)++] = op;
    return 0;
}

static void
bu_clear_stack (bu_op *stack, size_t n)
{
    for (size_t i = 0; i < n; i++) free (stack[i].payload);
}

static long
bu_now_usec (void)
{
    struct timeval tv;
    if (gettimeofday (&tv, NULL) < 0)
        return 0;
    return (long) tv.tv_sec * 1000000L + (long) tv.tv_usec;
}

/* ---- Grouping helpers ---- */

/* Serialize an array of sub-ops into a malloc'd byte buffer for
   storage in a type 'G' op's payload.

   Wire format:
     uint32_t count    (N)
     N × {
       uint8_t  type   ('I'/'D'/'C')
       int32_t  lineno
       int32_t  col
       uint32_t paylen
       uint8_t  payload[paylen]
     }

   Returns NULL on allocation failure. */
static unsigned char *
bu_serialize_group (const bu_op *ops, size_t n, size_t *out_len)
{
    /* Compute total byte count. */
    size_t total = 4;  /* count */
    if (n > UINT32_MAX) return NULL;
    for (size_t i = 0; i < n; i++) {
        if (ops[i].paylen > UINT32_MAX || total > SIZE_MAX - 13 ||
            ops[i].paylen > SIZE_MAX - total - 13) return NULL;
        total += 1 + 4 + 4 + 4 + ops[i].paylen;
    }
    unsigned char *buf = malloc (total);
    if (!buf) return NULL;
    size_t off = 0;
    uint32_t n32 = (uint32_t) n;
    memcpy (buf + off, &n32, 4); off += 4;
    for (size_t i = 0; i < n; i++) {
        buf[off++] = (unsigned char) ops[i].type;
        int32_t ln32 = (int32_t) ops[i].lineno;
        int32_t col32 = (int32_t) ops[i].col;
        uint32_t pl32 = (uint32_t) ops[i].paylen;
        memcpy (buf + off, &ln32, 4); off += 4;
        memcpy (buf + off, &col32, 4); off += 4;
        memcpy (buf + off, &pl32, 4); off += 4;
        if (ops[i].paylen) memcpy (buf + off, ops[i].payload, ops[i].paylen);
        off += ops[i].paylen;
    }
    *out_len = total;
    return buf;
}

/* Deserialize the payload of a type 'G' op back into an array of
   sub-ops. Caller must free each sub-op's payload then free the
   returned array. Returns NULL on parse error. */
static bu_op *
bu_deserialize_group (const unsigned char *data, size_t len, size_t *out_n)
{
    if (len < 4) return NULL;
    uint32_t n;
    memcpy (&n, data, 4);
    if (n > 1024*1024) return NULL;  /* sanity cap */
    size_t off = 4;

    bu_op *ops = calloc ((size_t) n, sizeof (bu_op));
    if (!ops) return NULL;

    for (uint32_t i = 0; i < n; i++) {
        if (off + 1 + 4 + 4 + 4 > len) {
            for (uint32_t j = 0; j < i; j++) free (ops[j].payload);
            free (ops);
            return NULL;
        }
        ops[i].type = (char) data[off++];
        int32_t ln32;
        memcpy (&ln32, data + off, 4); off += 4;
        ops[i].lineno = (long) ln32;
        int32_t col32;
        memcpy (&col32, data + off, 4); off += 4;
        ops[i].col = (long) col32;
        uint32_t pl32;
        memcpy (&pl32, data + off, 4); off += 4;
        if (off + (size_t) pl32 > len) {
            for (uint32_t j = 0; j < i; j++) free (ops[j].payload);
            free (ops);
            return NULL;
        }
        ops[i].paylen = (size_t) pl32;
        if (pl32 > 0) {
            ops[i].payload = malloc ((size_t) pl32);
            if (!ops[i].payload) {
                for (uint32_t j = 0; j < i; j++) free (ops[j].payload);
                free (ops);
                return NULL;
            }
            memcpy (ops[i].payload, data + off, (size_t) pl32);
            off += pl32;
        } else {
            ops[i].payload = NULL;
        }
    }
    *out_n = (size_t) n;
    return ops;
}

/* Selectively free sub-ops array without freeing the array itself. */
static void
bu_free_subops (bu_op *ops, size_t n)
{
    if (!ops) return;
    for (size_t i = 0; i < n; i++) free (ops[i].payload);
}

static int
bu_try_coalesce_byte_op (bu_state *s, bu_op *op, long now)
{
    if (s->in_group || s->redo_n != 0 || s->undo_n == 0)
        return 0;
    if (op->type != 'A' && op->type != 'R')
        return 0;
    long last = s->last_record_sec * 1000000L + s->last_record_usec;
    if (last <= 0 || now <= 0 || now - last > BU_GROUP_USEC)
        return 0;

    bu_op *prev = &s->undo_stack[s->undo_n - 1];
    if (prev->type != op->type || prev->lineno != op->lineno)
        return 0;

    if (op->type == 'A') {
        if (op->col != prev->col + (long) prev->paylen)
            return 0;
        unsigned char *np = realloc (prev->payload, prev->paylen + op->paylen + 1);
        if (!np) return -1;
        prev->payload = np;
        memcpy (prev->payload + prev->paylen, op->payload, op->paylen);
        prev->paylen += op->paylen;
        prev->payload[prev->paylen] = '\0';
        free (op->payload);
        op->payload = NULL;
        s->last_record_sec = now / 1000000L;
        s->last_record_usec = now % 1000000L;
        return 1;
    }

    /* Delete-key style: repeatedly delete at the same byte column. */
    if (op->col == prev->col) {
        unsigned char *np = realloc (prev->payload, prev->paylen + op->paylen + 1);
        if (!np) return -1;
        prev->payload = np;
        memcpy (prev->payload + prev->paylen, op->payload, op->paylen);
        prev->paylen += op->paylen;
        prev->payload[prev->paylen] = '\0';
        free (op->payload);
        op->payload = NULL;
        s->last_record_sec = now / 1000000L;
        s->last_record_usec = now % 1000000L;
        return 1;
    }

    /* Backspace style: each removed byte is immediately before the
       previous deletion span, so prepend and move the span start left. */
    if (op->col + (long) op->paylen == prev->col) {
        unsigned char *np = malloc (prev->paylen + op->paylen + 1);
        if (!np) return -1;
        memcpy (np, op->payload, op->paylen);
        memcpy (np + op->paylen, prev->payload, prev->paylen);
        np[prev->paylen + op->paylen] = '\0';
        free (prev->payload);
        prev->payload = np;
        prev->paylen += op->paylen;
        prev->col = op->col;
        free (op->payload);
        op->payload = NULL;
        s->last_record_sec = now / 1000000L;
        s->last_record_usec = now % 1000000L;
        return 1;
    }

    return 0;
}

/* Record an op either to the open group buffer (if in_group) or to
   the undo stack (normal mode). Returns 0 on success. */
static int
bu_record_op (bu_state *s, bu_op op)
{
    long now = bu_now_usec ();
    if (s->in_group) {
        if (s->group_n + 1 > s->group_cap) {
            size_t nc = (s->group_cap ? s->group_cap * 2 : 16);
            bu_op *ns = realloc (s->group_ops, nc * sizeof (bu_op));
            if (!ns) return -1;
            s->group_ops = ns;
            s->group_cap = nc;
        }
        s->group_ops[s->group_n++] = op;
        return 0;
    }
    int merged = bu_try_coalesce_byte_op (s, &op, now);
    if (merged < 0)
        return -1;
    if (merged > 0)
        return 0;
    s->last_record_sec = now / 1000000L;
    s->last_record_usec = now % 1000000L;
    return bu_push (&s->undo_stack, &s->undo_n, &s->undo_cap, s->max_depth, op);
}

/* ---- verb implementations ---- */

static int
bu_new_cmd (WORD_LIST *args)
{
    const char *hvar = NULL;
    int buf_slot = -1;
    size_t depth = BU_DEFAULT_DEPTH;
    const char *env_depth = getenv ("BASHNANO_UNDO_DEPTH");
    if (env_depth && *env_depth) {
        char *end = NULL;
        long v = strtol (env_depth, &end, 10);
        if (end && *end == '\0' && v >= 1)
            depth = (size_t) v;
    }

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-h") == 0 && p->next) { hvar = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-B") == 0 && p->next) {
            buf_slot = atoi (p->next->word->word); p = p->next;
        }
        else if (strcmp (w, "-d") == 0 && p->next) {
            long v = strtol (p->next->word->word, NULL, 10);
            if (v < 1) { builtin_error ("new: depth must be >= 1"); return EX_USAGE; }
            depth = (size_t) v; p = p->next;
        }
        else { builtin_error ("new: unexpected arg '%s'", w); return EX_USAGE; }
    }
    if (buf_slot < 0) { builtin_error ("new: -B BUF_SLOT required"); return EX_USAGE; }
    if (bb_pub_n_lines (buf_slot) < 0) {
        builtin_error ("new: buf slot %d invalid", buf_slot);
        return EX_USAGE;
    }
    bu_state *s = calloc (1, sizeof (bu_state));
    if (!s) { builtin_error ("calloc"); return EXECUTION_FAILURE; }
    s->buf_slot = buf_slot;
    s->max_depth = depth;
    int slot = bu_alloc_handle (s);
    if (slot < 0) {
        free (s);
        builtin_error ("new: handle table full");
        return EXECUTION_FAILURE;
    }
    char buf[16];
    snprintf (buf, sizeof buf, "%d", slot);
    if (hvar) builtin_bind_variable ((char *) hvar, buf, 0);
    else      printf ("%s\n", buf);
    return EXECUTION_SUCCESS;
}

static int
bu_record_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next || !args->next->next->next) {
        builtin_error ("record: HANDLE TYPE LINENO [COL] TEXT [-X]");
        return EX_USAGE;
    }
    bu_state *s = bu_get (args->word->word);
    if (!s) { builtin_error ("record: bad handle"); return EX_USAGE; }
    const char *type_s = args->next->word->word;
    if (!type_s[0] || type_s[1] != '\0') {
        builtin_error ("record: TYPE must be one of I/D/C/A/R"); return EX_USAGE;
    }
    char type = type_s[0];
    if (type != 'I' && type != 'D' && type != 'C' &&
        type != 'A' && type != 'R') {
        builtin_error ("record: unknown TYPE '%c'", type); return EX_USAGE;
    }
    long lineno = strtol (args->next->next->word->word, NULL, 10);
    long col = 0;
    WORD_LIST *text_node = args->next->next->next;
    if (type == 'A' || type == 'R') {
        if (!text_node || !text_node->next) {
            builtin_error ("record: TYPE %c needs LINENO COL TEXT", type);
            return EX_USAGE;
        }
        col = strtol (text_node->word->word, NULL, 10);
        if (col < 0) { builtin_error ("record: COL must be >= 0"); return EX_USAGE; }
        text_node = text_node->next;
    }
    const char *text = text_node->word->word;
    int hex_mode = 0;
    for (WORD_LIST *p = text_node->next; p; p = p->next) {
        if (strcmp (p->word->word, "-X") == 0) hex_mode = 1;
    }

    bu_op op;
    op.type = type;
    op.lineno = lineno;
    op.col = col;
    if (hex_mode) {
        op.payload = bu_hex_decode (text, &op.paylen);
        if (!op.payload) { builtin_error ("record: bad hex"); return EX_USAGE; }
    } else {
        op.paylen = strlen (text);
        op.payload = malloc (op.paylen + 1);
        if (!op.payload) { builtin_error ("malloc"); return EXECUTION_FAILURE; }
        memcpy (op.payload, text, op.paylen);
        op.payload[op.paylen] = '\0';
    }
    if (bu_record_op (s, op) < 0) {
        free (op.payload);
        builtin_error ("record: push failed");
        return EXECUTION_FAILURE;
    }
    /* Clear redo only when NOT in a group — end-group owns that step. */
    if (!s->in_group) {
        bu_clear_stack (s->redo_stack, s->redo_n);
        s->redo_n = 0;
    }
    return EXECUTION_SUCCESS;
}

static int
bu_begin_group_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("begin-group: HANDLE"); return EX_USAGE; }
    bu_state *s = bu_get (args->word->word);
    if (!s) { builtin_error ("begin-group: bad handle"); return EX_USAGE; }
    if (s->in_group) {
        builtin_error ("begin-group: already in a group");
        return EX_USAGE;
    }
    s->in_group = 1;
    s->last_record_sec = s->last_record_usec = 0;
    /* Clear any stale group buffer. */
    bu_free_subops (s->group_ops, s->group_n);
    s->group_n = 0;
    return EXECUTION_SUCCESS;
}

static int
bu_end_group_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("end-group: HANDLE"); return EX_USAGE; }
    bu_state *s = bu_get (args->word->word);
    if (!s) { builtin_error ("end-group: bad handle"); return EX_USAGE; }
    if (!s->in_group) {
        builtin_error ("end-group: not in a group");
        return EX_USAGE;
    }
    s->in_group = 0;
    s->last_record_sec = s->last_record_usec = 0;

    /* Empty group is a no-op. */
    if (s->group_n == 0) return EXECUTION_SUCCESS;

    /* Serialize sub-ops into a composite 'G' op. */
    size_t serial_len;
    unsigned char *serial = bu_serialize_group (s->group_ops, s->group_n, &serial_len);
    if (!serial) {
        builtin_error ("end-group: alloc");
        return EXECUTION_FAILURE;
    }

    bu_op gop;
    gop.type = 'G';
    gop.lineno = 0;
    gop.col = 0;
    gop.payload = serial;
    gop.paylen = serial_len;

    int rc = bu_push (&s->undo_stack, &s->undo_n, &s->undo_cap, s->max_depth, gop);
    if (rc < 0) {
        free (serial);
        builtin_error ("end-group: push failed");
        return EXECUTION_FAILURE;
    }

    /* New composite op invalidates the redo timeline (same contract as
       record outside a group). */
    bu_clear_stack (s->redo_stack, s->redo_n);
    s->redo_n = 0;

    /* Free the group buffer (sub-op payloads). */
    bu_free_subops (s->group_ops, s->group_n);
    s->group_n = 0;
    return EXECUTION_SUCCESS;
}

/* Helper: for a single sub-op being undone inside a group, apply the
   inverse operation to the buffer and build the corresponding forward
   sub-op for the redo group.

   For I (insert):   undo = delete-line(lineno);  redo = I(lineno, payload)
   For D (delete):   undo = insert(lineno, payload);  redo = D(lineno, payload)
   For C (change):   undo = capture current, replace with payload; redo = C(lineno, captured)

   Returns 0 on success. *out_redo is filled; caller must manage its
   payload. */
static int
bu_apply_inverse (bu_state *s, const bu_op *op, bu_op *out_redo)
{
    out_redo->payload = NULL;
    out_redo->type = op->type;
    out_redo->lineno = op->lineno;
    out_redo->col = op->col;
    out_redo->paylen = 0;

    if (op->type == 'I') {
        /* Inverse: delete line that was inserted. */
        if (bb_pub_delete_line (s->buf_slot, (size_t) op->lineno) < 0)
            return -1;
        /* Redo: re-insert same text. */
        out_redo->payload = malloc (op->paylen + 1);
        if (out_redo->payload && op->paylen > 0) {
            memcpy (out_redo->payload, op->payload, op->paylen);
            out_redo->payload[op->paylen] = '\0';
            out_redo->paylen = op->paylen;
        }
    } else if (op->type == 'D') {
        /* Inverse: insert the deleted line back. */
        if (bb_pub_insert_line (s->buf_slot, (size_t) op->lineno,
                                op->payload, op->paylen) < 0)
            return -1;
        /* Redo: delete it again. */
        out_redo->payload = malloc (op->paylen + 1);
        if (out_redo->payload && op->paylen > 0) {
            memcpy (out_redo->payload, op->payload, op->paylen);
            out_redo->payload[op->paylen] = '\0';
            out_redo->paylen = op->paylen;
        }
    } else if (op->type == 'C') {
        /* Inverse: capture current, replace with prior. */
        const unsigned char *current;
        size_t current_len;
        if (bb_pub_get_line (s->buf_slot, (size_t) op->lineno,
                             &current, &current_len) < 0)
            return -1;
        /* Capture current content as the redo forward-op payload. */
        out_redo->payload = malloc (current_len + 1);
        if (!out_redo->payload) return -1;
        memcpy (out_redo->payload, current, current_len);
        out_redo->payload[current_len] = '\0';
        out_redo->paylen = current_len;
        /* Replace with prior. */
        if (bb_pub_delete_line (s->buf_slot, (size_t) op->lineno) < 0) {
            free (out_redo->payload);
            out_redo->payload = NULL;
            return -1;
        }
        if (bb_pub_insert_line (s->buf_slot, (size_t) op->lineno,
                                op->payload, op->paylen) < 0) {
            free (out_redo->payload);
            out_redo->payload = NULL;
            return -1;
        }
    } else if (op->type == 'A') {
        if (bb_pub_delete_at (s->buf_slot, (size_t) op->lineno,
                              (size_t) op->col, op->paylen) < 0)
            return -1;
        out_redo->payload = malloc (op->paylen + 1);
        if (!out_redo->payload) return -1;
        memcpy (out_redo->payload, op->payload, op->paylen);
        out_redo->payload[op->paylen] = '\0';
        out_redo->paylen = op->paylen;
    } else if (op->type == 'R') {
        if (bb_pub_insert_at (s->buf_slot, (size_t) op->lineno,
                              (size_t) op->col, op->payload, op->paylen) < 0)
            return -1;
        out_redo->payload = malloc (op->paylen + 1);
        if (!out_redo->payload) return -1;
        memcpy (out_redo->payload, op->payload, op->paylen);
        out_redo->payload[op->paylen] = '\0';
        out_redo->paylen = op->paylen;
    }
    return 0;
}

/* Helper: for a single sub-op being redone inside a group, apply the
   forward operation and build the corresponding inverse sub-op for the
   undo group. */
static int
bu_apply_forward (bu_state *s, const bu_op *op, bu_op *out_inverse)
{
    out_inverse->payload = NULL;
    out_inverse->type = op->type;
    out_inverse->lineno = op->lineno;
    out_inverse->col = op->col;
    out_inverse->paylen = 0;

    if (op->type == 'I') {
        if (bb_pub_insert_line (s->buf_slot, (size_t) op->lineno,
                                op->payload, op->paylen) < 0)
            return -1;
        /* Inverse for undo: delete. */
        out_inverse->payload = malloc (op->paylen + 1);
        if (out_inverse->payload && op->paylen > 0) {
            memcpy (out_inverse->payload, op->payload, op->paylen);
            out_inverse->payload[op->paylen] = '\0';
            out_inverse->paylen = op->paylen;
        }
    } else if (op->type == 'D') {
        if (bb_pub_delete_line (s->buf_slot, (size_t) op->lineno) < 0)
            return -1;
        out_inverse->payload = malloc (op->paylen + 1);
        if (out_inverse->payload && op->paylen > 0) {
            memcpy (out_inverse->payload, op->payload, op->paylen);
            out_inverse->payload[op->paylen] = '\0';
            out_inverse->paylen = op->paylen;
        }
    } else if (op->type == 'C') {
        /* Forward: capture current, replace with new content. */
        const unsigned char *current;
        size_t current_len;
        if (bb_pub_get_line (s->buf_slot, (size_t) op->lineno,
                             &current, &current_len) < 0)
            return -1;
        out_inverse->payload = malloc (current_len + 1);
        if (!out_inverse->payload) return -1;
        memcpy (out_inverse->payload, current, current_len);
        out_inverse->payload[current_len] = '\0';
        out_inverse->paylen = current_len;
        if (bb_pub_delete_line (s->buf_slot, (size_t) op->lineno) < 0) {
            free (out_inverse->payload);
            out_inverse->payload = NULL;
            return -1;
        }
        if (bb_pub_insert_line (s->buf_slot, (size_t) op->lineno,
                                op->payload, op->paylen) < 0) {
            free (out_inverse->payload);
            out_inverse->payload = NULL;
            return -1;
        }
    } else if (op->type == 'A') {
        if (bb_pub_insert_at (s->buf_slot, (size_t) op->lineno,
                              (size_t) op->col, op->payload, op->paylen) < 0)
            return -1;
        out_inverse->payload = malloc (op->paylen + 1);
        if (!out_inverse->payload) return -1;
        memcpy (out_inverse->payload, op->payload, op->paylen);
        out_inverse->payload[op->paylen] = '\0';
        out_inverse->paylen = op->paylen;
    } else if (op->type == 'R') {
        if (bb_pub_delete_at (s->buf_slot, (size_t) op->lineno,
                              (size_t) op->col, op->paylen) < 0)
            return -1;
        out_inverse->payload = malloc (op->paylen + 1);
        if (!out_inverse->payload) return -1;
        memcpy (out_inverse->payload, op->payload, op->paylen);
        out_inverse->payload[op->paylen] = '\0';
        out_inverse->paylen = op->paylen;
    }
    return 0;
}

/* Undo a composite group op. Applies sub-op inverses in reverse order,
   builds a redo group from the forward equivalents. */
static int
bu_undo_group_cmd (bu_state *s, bu_op *op)
{
    size_t n;
    bu_op *subs = bu_deserialize_group (op->payload, op->paylen, &n);
    if (!subs) {
        builtin_error ("undo: corrupt group op");
        return EXECUTION_FAILURE;
    }

    /* Apply inverses in reverse order, building redo sub-ops. */
    bu_op *redo_subs = calloc (n, sizeof (bu_op));
    if (!redo_subs) {
        bu_free_subops (subs, n);
        free (subs);
        builtin_error ("undo: alloc");
        return EXECUTION_FAILURE;
    }

    int ok = 1;
    for (size_t i = n; i > 0; i--) {
        if (bu_apply_inverse (s, &subs[i - 1], &redo_subs[i - 1]) < 0) {
            builtin_error ("undo: group sub-op %zu failed", i - 1);
            ok = 0;
            break;
        }
    }
    bu_free_subops (subs, n);
    free (subs);

    if (!ok) {
        /* Clean up any redo_subs that were allocated. */
        bu_free_subops (redo_subs, n);
        free (redo_subs);
        return EXECUTION_FAILURE;
    }

    /* Serialize redo sub-ops as a 'G' for the redo stack. */
    size_t serial_len;
    unsigned char *serial = bu_serialize_group (redo_subs, n, &serial_len);
    bu_free_subops (redo_subs, n);
    free (redo_subs);
    if (!serial) {
        builtin_error ("undo: alloc");
        return EXECUTION_FAILURE;
    }

    bu_op redo_gop;
    redo_gop.type = 'G';
    redo_gop.lineno = 0;
    redo_gop.col = 0;
    redo_gop.payload = serial;
    redo_gop.paylen = serial_len;

    if (bu_push (&s->redo_stack, &s->redo_n, &s->redo_cap, s->max_depth, redo_gop) < 0) {
        free (serial);
        builtin_error ("undo: redo push failed");
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

/* Redo a composite group op. Applies forward sub-ops in order,
   builds an undo group from the inverse equivalents. */
static int
bu_redo_group_cmd (bu_state *s, bu_op *op)
{
    size_t n;
    bu_op *subs = bu_deserialize_group (op->payload, op->paylen, &n);
    if (!subs) {
        builtin_error ("redo: corrupt group op");
        return EXECUTION_FAILURE;
    }

    bu_op *undo_subs = calloc (n, sizeof (bu_op));
    if (!undo_subs) {
        bu_free_subops (subs, n);
        free (subs);
        builtin_error ("redo: alloc");
        return EXECUTION_FAILURE;
    }

    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        if (bu_apply_forward (s, &subs[i], &undo_subs[i]) < 0) {
            builtin_error ("redo: group sub-op %zu failed", i);
            ok = 0;
            break;
        }
    }
    bu_free_subops (subs, n);
    free (subs);

    if (!ok) {
        bu_free_subops (undo_subs, n);
        free (undo_subs);
        return EXECUTION_FAILURE;
    }

    size_t serial_len;
    unsigned char *serial = bu_serialize_group (undo_subs, n, &serial_len);
    bu_free_subops (undo_subs, n);
    free (undo_subs);
    if (!serial) {
        builtin_error ("redo: alloc");
        return EXECUTION_FAILURE;
    }

    bu_op undo_gop;
    undo_gop.type = 'G';
    undo_gop.lineno = 0;
    undo_gop.col = 0;
    undo_gop.payload = serial;
    undo_gop.paylen = serial_len;

    if (bu_push (&s->undo_stack, &s->undo_n, &s->undo_cap, s->max_depth, undo_gop) < 0) {
        free (serial);
        builtin_error ("redo: undo push failed");
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bu_undo_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("undo: HANDLE"); return EX_USAGE; }
    bu_state *s = bu_get (args->word->word);
    if (!s) { builtin_error ("undo: bad handle"); return EX_USAGE; }
    if (s->undo_n == 0) return EXECUTION_FAILURE;  /* nothing to undo */
    s->last_record_sec = s->last_record_usec = 0;

    /* Handle composite group op. */
    if (s->undo_stack[s->undo_n - 1].type == 'G') {
        bu_op gop = s->undo_stack[--s->undo_n];
        int rc = bu_undo_group_cmd (s, &gop);
        free (gop.payload);
        return rc;
    }

    bu_op op = s->undo_stack[--s->undo_n];

    /* Apply inverse via buf C API, then push the original op
       (so it captures what was undone) onto redo stack. The inverse
       depends on op.type. */
    int rc = -1;
    bu_op redo_op = op;
    redo_op.payload = NULL;  /* re-allocated below where needed */

    if (op.type == 'I') {
        /* We had inserted line at LINENO with payload. To undo: delete it. */
        rc = bb_pub_delete_line (s->buf_slot, (size_t) op.lineno);
        /* Redo: re-insert. Keep the payload — duplicate. */
        redo_op.payload = malloc (op.paylen + 1);
        if (redo_op.payload) {
            memcpy (redo_op.payload, op.payload, op.paylen);
            redo_op.payload[op.paylen] = '\0';
            redo_op.paylen = op.paylen;
        }
    } else if (op.type == 'D') {
        /* We had deleted line at LINENO; payload was the deleted text.
           To undo: insert it back. */
        rc = bb_pub_insert_line (s->buf_slot, (size_t) op.lineno, op.payload, op.paylen);
        redo_op.payload = malloc (op.paylen + 1);
        if (redo_op.payload) {
            memcpy (redo_op.payload, op.payload, op.paylen);
            redo_op.payload[op.paylen] = '\0';
            redo_op.paylen = op.paylen;
        }
    } else if (op.type == 'C') {
        /* Changed line LINENO. payload was the prior content. To undo:
           capture current content into redo, then delete + insert prior. */
        const unsigned char *current; size_t current_len;
        if (bb_pub_get_line (s->buf_slot, (size_t) op.lineno, &current, &current_len) < 0) {
            free (op.payload);
            builtin_error ("undo C: line vanished?");
            return EXECUTION_FAILURE;
        }
        redo_op.payload = malloc (current_len + 1);
        if (!redo_op.payload) {
            free (op.payload);
            return EXECUTION_FAILURE;
        }
        memcpy (redo_op.payload, current, current_len);
        redo_op.payload[current_len] = '\0';
        redo_op.paylen = current_len;
        /* Replace current with prior. */
        if (bb_pub_delete_line (s->buf_slot, (size_t) op.lineno) < 0) {
            free (redo_op.payload); free (op.payload);
            return EXECUTION_FAILURE;
        }
        rc = bb_pub_insert_line (s->buf_slot, (size_t) op.lineno, op.payload, op.paylen);
    } else if (op.type == 'A') {
        rc = bb_pub_delete_at (s->buf_slot, (size_t) op.lineno,
                               (size_t) op.col, op.paylen);
        redo_op.payload = malloc (op.paylen + 1);
        if (redo_op.payload) {
            memcpy (redo_op.payload, op.payload, op.paylen);
            redo_op.payload[op.paylen] = '\0';
            redo_op.paylen = op.paylen;
        }
    } else if (op.type == 'R') {
        rc = bb_pub_insert_at (s->buf_slot, (size_t) op.lineno,
                               (size_t) op.col, op.payload, op.paylen);
        redo_op.payload = malloc (op.paylen + 1);
        if (redo_op.payload) {
            memcpy (redo_op.payload, op.payload, op.paylen);
            redo_op.payload[op.paylen] = '\0';
            redo_op.paylen = op.paylen;
        }
    }
    free (op.payload);
    if (rc < 0) {
        free (redo_op.payload);
        builtin_error ("undo: buf op failed");
        return EXECUTION_FAILURE;
    }
    /* Push redo_op (without growing past max_depth — same logic). */
    if (bu_push (&s->redo_stack, &s->redo_n, &s->redo_cap, s->max_depth, redo_op) < 0) {
        free (redo_op.payload);
    }
    return EXECUTION_SUCCESS;
}

static int
bu_redo_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("redo: HANDLE"); return EX_USAGE; }
    bu_state *s = bu_get (args->word->word);
    if (!s) { builtin_error ("redo: bad handle"); return EX_USAGE; }
    if (s->redo_n == 0) return EXECUTION_FAILURE;
    s->last_record_sec = s->last_record_usec = 0;

    /* Handle composite group op. */
    if (s->redo_stack[s->redo_n - 1].type == 'G') {
        bu_op gop = s->redo_stack[--s->redo_n];
        int rc = bu_redo_group_cmd (s, &gop);
        free (gop.payload);
        return rc;
    }

    bu_op op = s->redo_stack[--s->redo_n];

    int rc = -1;
    bu_op back = op;
    back.payload = NULL;

    if (op.type == 'I') {
        rc = bb_pub_insert_line (s->buf_slot, (size_t) op.lineno, op.payload, op.paylen);
        back.payload = malloc (op.paylen + 1);
        if (back.payload) {
            memcpy (back.payload, op.payload, op.paylen);
            back.payload[op.paylen] = '\0';
            back.paylen = op.paylen;
        }
    } else if (op.type == 'D') {
        rc = bb_pub_delete_line (s->buf_slot, (size_t) op.lineno);
        back.payload = malloc (op.paylen + 1);
        if (back.payload) {
            memcpy (back.payload, op.payload, op.paylen);
            back.payload[op.paylen] = '\0';
            back.paylen = op.paylen;
        }
    } else if (op.type == 'C') {
        const unsigned char *current; size_t current_len;
        if (bb_pub_get_line (s->buf_slot, (size_t) op.lineno, &current, &current_len) < 0) {
            free (op.payload);
            return EXECUTION_FAILURE;
        }
        back.payload = malloc (current_len + 1);
        if (!back.payload) { free (op.payload); return EXECUTION_FAILURE; }
        memcpy (back.payload, current, current_len);
        back.payload[current_len] = '\0';
        back.paylen = current_len;
        if (bb_pub_delete_line (s->buf_slot, (size_t) op.lineno) < 0) {
            free (back.payload); free (op.payload);
            return EXECUTION_FAILURE;
        }
        rc = bb_pub_insert_line (s->buf_slot, (size_t) op.lineno, op.payload, op.paylen);
    } else if (op.type == 'A') {
        rc = bb_pub_insert_at (s->buf_slot, (size_t) op.lineno,
                               (size_t) op.col, op.payload, op.paylen);
        back.payload = malloc (op.paylen + 1);
        if (back.payload) {
            memcpy (back.payload, op.payload, op.paylen);
            back.payload[op.paylen] = '\0';
            back.paylen = op.paylen;
        }
    } else if (op.type == 'R') {
        rc = bb_pub_delete_at (s->buf_slot, (size_t) op.lineno,
                               (size_t) op.col, op.paylen);
        back.payload = malloc (op.paylen + 1);
        if (back.payload) {
            memcpy (back.payload, op.payload, op.paylen);
            back.payload[op.paylen] = '\0';
            back.paylen = op.paylen;
        }
    }
    free (op.payload);
    if (rc < 0) {
        free (back.payload);
        return EXECUTION_FAILURE;
    }
    if (bu_push (&s->undo_stack, &s->undo_n, &s->undo_cap, s->max_depth, back) < 0) {
        free (back.payload);
    }
    return EXECUTION_SUCCESS;
}

static int
bu_clear_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("clear: HANDLE"); return EX_USAGE; }
    bu_state *s = bu_get (args->word->word);
    if (!s) { builtin_error ("clear: bad handle"); return EX_USAGE; }
    bu_clear_stack (s->undo_stack, s->undo_n);
    bu_clear_stack (s->redo_stack, s->redo_n);
    s->undo_n = s->redo_n = 0;
    s->last_record_sec = s->last_record_usec = 0;
    /* Also clear any open group buffer. */
    bu_free_subops (s->group_ops, s->group_n);
    s->group_n = 0;
    s->in_group = 0;
    return EXECUTION_SUCCESS;
}

static int
bu_depth_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("depth: HANDLE"); return EX_USAGE; }
    bu_state *s = bu_get (args->word->word);
    if (!s) { builtin_error ("depth: bad handle"); return EX_USAGE; }
    printf ("%zu %zu\n", s->undo_n, s->redo_n);
    return EXECUTION_SUCCESS;
}

static int
bu_free_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("free: HANDLE"); return EX_USAGE; }
    int idx = bu_get_index (args->word->word);
    if (idx < 0 || !bu_handles[idx]) return EX_USAGE;
    bu_state *s = bu_handles[idx];
    bu_clear_stack (s->undo_stack, s->undo_n);
    bu_clear_stack (s->redo_stack, s->redo_n);
    bu_free_subops (s->group_ops, s->group_n);
    free (s->undo_stack);
    free (s->redo_stack);
    free (s->group_ops);
    free (s);
    bu_handles[idx] = NULL;
    return EXECUTION_SUCCESS;
}

int
undo_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "new"))          return bu_new_cmd (args);
    if (!strcmp (cmd, "record"))       return bu_record_cmd (args);
    if (!strcmp (cmd, "begin-group"))  return bu_begin_group_cmd (args);
    if (!strcmp (cmd, "end-group"))    return bu_end_group_cmd (args);
    if (!strcmp (cmd, "undo"))         return bu_undo_cmd (args);
    if (!strcmp (cmd, "redo"))         return bu_redo_cmd (args);
    if (!strcmp (cmd, "clear"))        return bu_clear_cmd (args);
    if (!strcmp (cmd, "depth"))        return bu_depth_cmd (args);
    if (!strcmp (cmd, "free"))         return bu_free_cmd (args);
    builtin_error ("unknown verb: %s", cmd);
    return EX_USAGE;
}

char *undo_doc[] = {
    "Undo/redo stack tied to a buf handle.",
    "",
    "    undo new -h HVAR -B BUF_SLOT [-d DEPTH]",
    "    undo record HANDLE TYPE LINENO [COL] TEXT [-X]",
    "        TYPE: I line inserted / D line deleted / C changed-from-TEXT",
    "              A bytes inserted at COL / R bytes removed at COL",
    "    undo begin-group HANDLE    start grouping records as one step",
    "    undo end-group HANDLE      close group, push composite op",
    "    undo undo HANDLE      apply inverse, push to redo",
    "    undo redo HANDLE      reapply, push back to undo",
    "    undo clear HANDLE",
    "    undo depth HANDLE     print 'UNDO_AVAIL REDO_AVAIL'",
    "    undo free HANDLE",
    "",
    "Mutations through buf must be paired with `record` calls",
    "by the caller. record clears redo history (new branch) unless",
    "inside a begin-group/end-group block. Adjacent A/R byte records",
    "within 1.5s coalesce automatically so typed runs and repeated",
    "delete/backspace undo as one unit. begin-group and end-group wrap",
    "multiple records into a single composite undo step, matching GNU",
    "nano's grouping of paste, search-and-replace, and auto-indent.",
    "",
    "UTF-8 / NUL policy: TEXT is treated as an opaque byte string and",
    "LINENO and COL are byte-buffer-indexed. Use `record ... -X` to feed",
    "NUL-bearing or arbitrary-binary TEXT (hex transit). undo does",
    "not interpret UTF-8 — buf's byte-indexed semantics apply.",
    (char *)NULL
};

struct builtin undo_struct = {
    "undo",
    undo_builtin,
    BUILTIN_ENABLED,
    undo_doc,
    "undo new|record|begin-group|end-group|undo|redo|clear|depth|free ARGS",
    0
};
