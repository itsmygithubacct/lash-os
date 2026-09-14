/* wasm_stub.c — replaces wasm_store.c when bash-os ships tree-sitter
 *               WITHOUT the WebAssembly grammar runtime.
 *
 * tree-sitter's parser.c + language.c reference ts_wasm_*_call_*
 * functions and ts_language_is_wasm() unconditionally — they're
 * gated by `if (ts_language_is_wasm(self->language))` at runtime,
 * not by `#if TREE_SITTER_FEATURE_WASM`. So we can't just drop
 * wasm_store.c and -DTREE_SITTER_FEATURE_WASM=0; we'd get linker
 * errors.
 *
 * Stub strategy: provide each ts_wasm_* symbol with a no-op or
 * abort body. The runtime gate `ts_language_is_wasm()` here returns
 * false unconditionally, so the real wasm code paths in parser.c
 * never execute, and the stubs that COULD be called (retain/release)
 * are inert no-ops.
 *
 * Saves ~1940 LoC + the wasmtime dependency.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "api.h"
#include "wasm_store.h"

bool ts_language_is_wasm (const TSLanguage *self)
{
    (void) self;
    return false;
}

void ts_wasm_language_retain  (const TSLanguage *self) { (void) self; }
void ts_wasm_language_release (const TSLanguage *self) { (void) self; }

/* The remaining ts_wasm_*_call_* functions are gated by
 * `if (ts_language_is_wasm(...))` in parser.c — since our stub
 * returns false, they're never invoked. But the linker still wants
 * the symbols to exist. abort() makes any actual reachability bug
 * loud. */
bool ts_wasm_store_start (TSWasmStore *s, TSLexer *l, const TSLanguage *L)
{ (void) s; (void) l; (void) L; abort (); }

void ts_wasm_store_reset (TSWasmStore *s)
{ (void) s; abort (); }

bool ts_wasm_store_has_error (const TSWasmStore *s)
{ (void) s; return false; }

bool ts_wasm_store_call_lex_main (TSWasmStore *s, TSStateId st)
{ (void) s; (void) st; abort (); }

bool ts_wasm_store_call_lex_keyword (TSWasmStore *s, TSStateId st)
{ (void) s; (void) st; abort (); }

uint32_t ts_wasm_store_call_scanner_create (TSWasmStore *s)
{ (void) s; abort (); }

void ts_wasm_store_call_scanner_destroy (TSWasmStore *s, uint32_t a)
{ (void) s; (void) a; abort (); }

bool ts_wasm_store_call_scanner_scan (TSWasmStore *s, uint32_t a, uint32_t v)
{ (void) s; (void) a; (void) v; abort (); }

uint32_t ts_wasm_store_call_scanner_serialize (TSWasmStore *s, uint32_t a, char *b)
{ (void) s; (void) a; (void) b; abort (); }

void ts_wasm_store_call_scanner_deserialize (TSWasmStore *s, uint32_t a,
                                             const char *b, unsigned l)
{ (void) s; (void) a; (void) b; (void) l; abort (); }

/* Public API: declared in api.h. parser.c calls ts_wasm_store_delete
 * unconditionally inside ts_parser_delete() for cleanup. With no
 * wasm support, the parser's internal wasm_store pointer is always
 * NULL — the call is a no-op. */
void ts_wasm_store_delete (TSWasmStore *self) { (void) self; }

/* The remaining api.h ts_wasm_* are not referenced by the
 * non-wasm runtime, but provide stubs so external linkers don't
 * complain if a future loadable accidentally references them.
 * Signatures must match api.h exactly. */
TSWasmStore *ts_wasm_store_new (TSWasmEngine *e, TSWasmError *err)
{ (void) e; (void) err; return NULL; }

const TSLanguage *ts_wasm_store_load_language (TSWasmStore *s, const char *n,
                                               const char *b, uint32_t l, TSWasmError *err)
{ (void) s; (void) n; (void) b; (void) l; (void) err; return NULL; }

size_t ts_wasm_store_language_count (const TSWasmStore *s)
{ (void) s; return 0; }
