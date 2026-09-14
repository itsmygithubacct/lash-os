/* SPDX-License-Identifier: MIT */
/* vec.c — typed dense numeric arrays as bash builtins (Stage 25).
 *
 * Closes the "bash arrays are slow for numerics" ceiling. Native bash
 * arrays are O(n) string-typed; summing 100K integers takes seconds.
 * vec gives microsecond-class numerics.
 *
 * Six element types — i32, i64, u32, u64, f32, f64 — cover ~95% of
 * numeric workloads. Allocations are 64-byte-aligned via aligned_alloc
 * so future SIMD work doesn't need alignment branches.
 *
 * Verbs:
 *   new -T TYPE -N LEN [-h H_VAR]   allocate; LEN cells, zeroed
 *   free H                          release
 *   set H IDX VAL                   write one cell
 *   get H IDX                       read one cell (decimal)
 *   len H                           print element count
 *   type H                          print type name
 *   backend                         print selected backend (scalar/sse2/avx2)
 *   fill H VAL                      broadcast fill
 *   sum  H                          scalar reduction
 *   mean H
 *   min  H
 *   max  H
 *   from-array -T TYPE NAME [-h H]  import indexed bash array
 *   to-array H NAME                 export to indexed bash array
 *   copy SRC [-h H]                 checked same-type copy
 *   slice SRC START LEN [-h H]      checked same-type range copy
 *   add|sub|mul|div A B             in-place mixed-type arithmetic
 *   mod A B                         integer in-place modulo
 *   scale H S                       in-place A[i] *= S
 *   axpy A X Y                      in-place Y[i] += A * X[i]
 *   dot A B                         scalar dot product
 *   cmp A B OP [-h H]               u32 mask, OP eq/ne/lt/le/gt/ge
 *   where MASK A B [-h H]           select A/B cells into a new vector
 *   count-nonzero|any|all H         predicates
 *   var|std H                       population variance/stddev
 *   save H PATH; load PATH [-h H]   binary persistence
 *   convert SRC -T TYPE [-h H_VAR]  checked copy to a new vector type
 *
 * SIMD intrinsics are deliberately not required for correctness. SSE2 and
 * runtime-gated AVX2 accelerate selected deterministic reductions while scalar
 * paths remain the fallback and correctness oracle.
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
#include <inttypes.h>
#include <limits.h>
#include <float.h>
#include <math.h>
#if defined (__SSE2__)
#  include <emmintrin.h>
#  include <xmmintrin.h>
#  define BVEC_HAVE_SSE2 1
#endif
#if (defined (__GNUC__) || defined (__clang__)) && (defined (__x86_64__) || defined (__i386__))
#  include <immintrin.h>
#  define BVEC_HAVE_AVX2_TARGET 1
#endif

#include "loadables.h"

enum bvec_type {
    BVEC_I32, BVEC_I64,
    BVEC_U32, BVEC_U64,
    BVEC_F32, BVEC_F64,
    BVEC_TYPE_COUNT
};

static const char *bv_type_names[BVEC_TYPE_COUNT] = {
    "i32", "i64", "u32", "u64", "f32", "f64"
};

static size_t bv_type_size (enum bvec_type t)
{
    switch (t) {
        case BVEC_I32: case BVEC_U32: case BVEC_F32: return 4;
        case BVEC_I64: case BVEC_U64: case BVEC_F64: return 8;
        default: return 0;
    }
}

static int
bv_host_is_be (void)
{
    const uint16_t x = 0x0102;
    return *(const unsigned char *) &x == 0x01;
}

static uint32_t
bv_bswap32 (uint32_t x)
{
    return __builtin_bswap32 (x);
}

static uint64_t
bv_bswap64 (uint64_t x)
{
    return __builtin_bswap64 (x);
}

static int bv_parse_type (const char *s, enum bvec_type *out)
{
    for (int i = 0; i < BVEC_TYPE_COUNT; i++) {
        if (strcmp (s, bv_type_names[i]) == 0) { *out = (enum bvec_type) i; return 0; }
    }
    return -1;
}

typedef struct {
    enum bvec_type type;
    size_t len;
    void *data;
} bvec_t;

#define BVEC_HANDLES_MAX 32
#define BVEC_MAX_BYTES (64ULL * 1024ULL * 1024ULL)
static bvec_t *bv_handles[BVEC_HANDLES_MAX];

static int bv_alloc_handle (bvec_t *v)
{
    for (int i = 0; i < BVEC_HANDLES_MAX; i++) {
        if (!bv_handles[i]) { bv_handles[i] = v; return i; }
    }
    return -1;
}

static bvec_t *bv_get (const char *s)
{
    char *end;
    long h = strtol (s, &end, 10);
    if (*end != '\0' || h < 0 || h >= BVEC_HANDLES_MAX) return NULL;
    return bv_handles[h];
}

static int
bv_parse_nonnegative_size (const char *s, size_t *out)
{
    char *end;
    unsigned long long v;

    if (!s || *s == '\0' || *s == '-')
        return -1;
    errno = 0;
    v = strtoull (s, &end, 0);
    if (errno == ERANGE || *end != '\0' || v > SIZE_MAX)
        return -1;
    *out = (size_t) v;
    return 0;
}

static int
bv_parse_index (const char *s, size_t len, size_t *out)
{
    size_t idx;

    if (bv_parse_nonnegative_size (s, &idx) != 0 || idx >= len)
        return -1;
    *out = idx;
    return 0;
}

/* Generic scalar parsing: signed/unsigned/float per type. Returns 0 on
   success, -1 on parse failure. */
static int
bv_parse_value (enum bvec_type t, const char *s, void *out)
{
    char *end;
    switch (t) {
    case BVEC_I32: { errno = 0; long long v = strtoll (s, &end, 0);
        if (errno == ERANGE || *end || v < INT32_MIN || v > INT32_MAX) return -1;
        *(int32_t *) out = (int32_t) v; return 0; }
    case BVEC_I64: { errno = 0; long long v = strtoll (s, &end, 0);
        if (errno == ERANGE || *end) return -1;
        *(int64_t *) out = (int64_t) v; return 0; }
    case BVEC_U32: { errno = 0; unsigned long long v = strtoull (s, &end, 0);
        if (*s == '-' || errno == ERANGE || *end || v > UINT32_MAX) return -1;
        *(uint32_t *) out = (uint32_t) v; return 0; }
    case BVEC_U64: { errno = 0; unsigned long long v = strtoull (s, &end, 0);
        if (*s == '-' || errno == ERANGE || *end) return -1;
        *(uint64_t *) out = (uint64_t) v; return 0; }
    case BVEC_F32: { errno = 0; double v = strtod (s, &end);
        if (errno == ERANGE || *end || !isfinite (v) || v > FLT_MAX || v < -FLT_MAX) return -1;
        *(float *) out = (float) v; return 0; }
    case BVEC_F64: { errno = 0; double v = strtod (s, &end);
        if (errno == ERANGE || *end || !isfinite (v)) return -1;
        *(double *) out = v; return 0; }
    default: return -1;
    }
}

static void
bv_print_cell (enum bvec_type t, const void *p)
{
    switch (t) {
    case BVEC_I32: printf ("%" PRId32 "\n", *(const int32_t *) p); break;
    case BVEC_I64: printf ("%" PRId64 "\n", *(const int64_t *) p); break;
    case BVEC_U32: printf ("%" PRIu32 "\n", *(const uint32_t *) p); break;
    case BVEC_U64: printf ("%" PRIu64 "\n", *(const uint64_t *) p); break;
    case BVEC_F32: printf ("%g\n",          *(const float   *) p); break;
    case BVEC_F64: printf ("%g\n",          *(const double  *) p); break;
    default: break;
    }
}

static long double
bv_cell_as_long_double (enum bvec_type t, const void *p)
{
    switch (t) {
    case BVEC_I32: return (long double) *(const int32_t *) p;
    case BVEC_I64: return (long double) *(const int64_t *) p;
    case BVEC_U32: return (long double) *(const uint32_t *) p;
    case BVEC_U64: return (long double) *(const uint64_t *) p;
    case BVEC_F32: return (long double) *(const float *) p;
    case BVEC_F64: return (long double) *(const double *) p;
    default: return 0.0L;
    }
}

static int
bv_long_double_is_integral (long double v)
{
    long double ip;

    return modfl (v, &ip) == 0.0L;
}

static int
bv_store_long_double (enum bvec_type t, long double v, void *p)
{
    if (!isfinite (v))
        return -1;
    switch (t) {
    case BVEC_I32:
        if (!bv_long_double_is_integral (v) || v < (long double) INT32_MIN || v > (long double) INT32_MAX)
            return -1;
        *(int32_t *) p = (int32_t) v;
        return 0;
    case BVEC_I64:
        if (!bv_long_double_is_integral (v) || v < (long double) INT64_MIN || v > (long double) INT64_MAX)
            return -1;
        *(int64_t *) p = (int64_t) v;
        return 0;
    case BVEC_U32:
        if (!bv_long_double_is_integral (v) || v < 0.0L || v > (long double) UINT32_MAX)
            return -1;
        *(uint32_t *) p = (uint32_t) v;
        return 0;
    case BVEC_U64:
        if (!bv_long_double_is_integral (v) || v < 0.0L || v > (long double) UINT64_MAX)
            return -1;
        *(uint64_t *) p = (uint64_t) v;
        return 0;
    case BVEC_F32:
        if (v > (long double) FLT_MAX || v < -(long double) FLT_MAX)
            return -1;
        *(float *) p = (float) v;
        return 0;
    case BVEC_F64:
        if (v > (long double) DBL_MAX || v < -(long double) DBL_MAX)
            return -1;
        *(double *) p = (double) v;
        return 0;
    default:
        return -1;
    }
}

static void
bv_cell_to_string (enum bvec_type t, const void *p, char *buf, size_t buflen)
{
    switch (t) {
    case BVEC_I32: snprintf (buf, buflen, "%" PRId32, *(const int32_t *) p); break;
    case BVEC_I64: snprintf (buf, buflen, "%" PRId64, *(const int64_t *) p); break;
    case BVEC_U32: snprintf (buf, buflen, "%" PRIu32, *(const uint32_t *) p); break;
    case BVEC_U64: snprintf (buf, buflen, "%" PRIu64, *(const uint64_t *) p); break;
    case BVEC_F32: snprintf (buf, buflen, "%g", *(const float *) p); break;
    case BVEC_F64: snprintf (buf, buflen, "%g", *(const double *) p); break;
    default: snprintf (buf, buflen, "0"); break;
    }
}

static int
bv_validate_finite_cells (enum bvec_type t, const void *data, size_t len,
                          const char *verb)
{
    if (t != BVEC_F32 && t != BVEC_F64)
        return 0;

    size_t esz = bv_type_size (t);
    for (size_t i = 0; i < len; i++) {
        long double v = bv_cell_as_long_double (t, (const char *) data + i * esz);
        if (!isfinite (v)) {
            builtin_error ("%s: non-finite %s value at index %zu",
                           verb, bv_type_names[t], i);
            return -1;
        }
    }
    return 0;
}

static void *
bv_aligned_zalloc (size_t len, enum bvec_type type)
{
    size_t esz = bv_type_size (type);
    if (len > SIZE_MAX / esz || len > (size_t) (BVEC_MAX_BYTES / esz))
        return NULL;
    size_t bytes = len * esz;
    size_t aligned_bytes = (bytes + 63) & ~(size_t) 63;
    if (aligned_bytes < bytes)
        return NULL;
    if (aligned_bytes == 0)
        aligned_bytes = 64;
    void *data = aligned_alloc (64, aligned_bytes);
    if (data)
        memset (data, 0, aligned_bytes);
    return data;
}

static int
bv_take_handle (enum bvec_type type, size_t len, void *data, const char *hvar,
                const char *verb)
{
    bvec_t *v = calloc (1, sizeof (bvec_t));
    if (!v) {
        free (data);
        builtin_error ("%s: calloc", verb);
        return EXECUTION_FAILURE;
    }
    v->type = type;
    v->len = len;
    v->data = data;
    int slot = bv_alloc_handle (v);
    if (slot < 0) {
        free (data);
        free (v);
        builtin_error ("%s: handle table full", verb);
        return EXECUTION_FAILURE;
    }
    char buf[16];
    snprintf (buf, sizeof (buf), "%d", slot);
    if (hvar)
        builtin_bind_variable ((char *) hvar, buf, 0);
    else
        printf ("%s\n", buf);
    return EXECUTION_SUCCESS;
}

static long double
bv_sqrt_long_double (long double x)
{
    if (x <= 0.0L)
        return 0.0L;
    long double g = x >= 1.0L ? x : 1.0L;
    for (int i = 0; i < 64; i++)
        g = (g + x / g) / 2.0L;
    return g;
}

static int
bv_same_len (const char *verb, bvec_t *a, bvec_t *b)
{
    if (a->len != b->len) {
        builtin_error ("%s: length mismatch (A=%zu B=%zu)", verb, a->len, b->len);
        return -1;
    }
    return 0;
}

#if defined (BVEC_HAVE_SSE2)
static long double
bv_sum_i32_sse (const int32_t *a, size_t len)
{
    size_t i = 0;
    __m128i zero = _mm_setzero_si128 ();
    __m128i acc_lo = _mm_setzero_si128 ();
    __m128i acc_hi = _mm_setzero_si128 ();
    for (; i + 3 < len; i += 4) {
        __m128i v = _mm_load_si128 ((const __m128i *) (a + i));
        __m128i sign = _mm_cmpgt_epi32 (zero, v);
        __m128i lo = _mm_unpacklo_epi32 (v, sign);
        __m128i hi = _mm_unpackhi_epi32 (v, sign);
        acc_lo = _mm_add_epi64 (acc_lo, lo);
        acc_hi = _mm_add_epi64 (acc_hi, hi);
    }
    int64_t lanes[4];
    _mm_storeu_si128 ((__m128i *) &lanes[0], acc_lo);
    _mm_storeu_si128 ((__m128i *) &lanes[2], acc_hi);
    long double sum = (long double) lanes[0] + lanes[1] + lanes[2] + lanes[3];
    for (; i < len; i++)
        sum += (long double) a[i];
    return sum;
}

static long double
bv_sum_u32_sse (const uint32_t *a, size_t len)
{
    size_t i = 0;
    __m128i zero = _mm_setzero_si128 ();
    __m128i acc_lo = _mm_setzero_si128 ();
    __m128i acc_hi = _mm_setzero_si128 ();
    for (; i + 3 < len; i += 4) {
        __m128i v = _mm_load_si128 ((const __m128i *) (a + i));
        __m128i lo = _mm_unpacklo_epi32 (v, zero);
        __m128i hi = _mm_unpackhi_epi32 (v, zero);
        acc_lo = _mm_add_epi64 (acc_lo, lo);
        acc_hi = _mm_add_epi64 (acc_hi, hi);
    }
    uint64_t lanes[4];
    _mm_storeu_si128 ((__m128i *) &lanes[0], acc_lo);
    _mm_storeu_si128 ((__m128i *) &lanes[2], acc_hi);
    long double sum = (long double) lanes[0] + lanes[1] + lanes[2] + lanes[3];
    for (; i < len; i++)
        sum += (long double) a[i];
    return sum;
}

static long double
bv_sum_f32_sse (const float *a, size_t len)
{
    size_t i = 0;
    __m128 acc = _mm_setzero_ps ();
    for (; i + 3 < len; i += 4)
        acc = _mm_add_ps (acc, _mm_load_ps (a + i));
    float lanes[4];
    _mm_storeu_ps (lanes, acc);
    long double sum = (long double) lanes[0] + lanes[1] + lanes[2] + lanes[3];
    for (; i < len; i++)
        sum += (long double) a[i];
    return sum;
}

static long double
bv_sum_f64_sse (const double *a, size_t len)
{
    size_t i = 0;
    __m128d acc = _mm_setzero_pd ();
    for (; i + 1 < len; i += 2)
        acc = _mm_add_pd (acc, _mm_load_pd (a + i));
    double lanes[2];
    _mm_storeu_pd (lanes, acc);
    long double sum = (long double) lanes[0] + lanes[1];
    for (; i < len; i++)
        sum += (long double) a[i];
    return sum;
}

static long double
bv_dot_f32_sse (const float *a, const float *b, size_t len)
{
    size_t i = 0;
    __m128 acc = _mm_setzero_ps ();
    for (; i + 3 < len; i += 4)
        acc = _mm_add_ps (acc, _mm_mul_ps (_mm_load_ps (a + i), _mm_load_ps (b + i)));
    float lanes[4];
    _mm_storeu_ps (lanes, acc);
    long double sum = (long double) lanes[0] + lanes[1] + lanes[2] + lanes[3];
    for (; i < len; i++)
        sum += (long double) a[i] * (long double) b[i];
    return sum;
}

static long double
bv_dot_f64_sse (const double *a, const double *b, size_t len)
{
    size_t i = 0;
    __m128d acc = _mm_setzero_pd ();
    for (; i + 1 < len; i += 2)
        acc = _mm_add_pd (acc, _mm_mul_pd (_mm_load_pd (a + i), _mm_load_pd (b + i)));
    double lanes[2];
    _mm_storeu_pd (lanes, acc);
    long double sum = (long double) lanes[0] + lanes[1];
    for (; i < len; i++)
        sum += (long double) a[i] * (long double) b[i];
    return sum;
}

static float
bv_min_f32_sse (const float *a, size_t len)
{
    size_t i = 1;
    __m128 acc = _mm_set1_ps (a[0]);
    for (; i + 3 < len; i += 4)
        acc = _mm_min_ps (acc, _mm_loadu_ps (a + i));
    float lanes[4];
    _mm_storeu_ps (lanes, acc);
    float m = lanes[0];
    for (size_t j = 1; j < 4; j++) if (lanes[j] < m) m = lanes[j];
    for (; i < len; i++) if (a[i] < m) m = a[i];
    return m;
}

static float
bv_max_f32_sse (const float *a, size_t len)
{
    size_t i = 1;
    __m128 acc = _mm_set1_ps (a[0]);
    for (; i + 3 < len; i += 4)
        acc = _mm_max_ps (acc, _mm_loadu_ps (a + i));
    float lanes[4];
    _mm_storeu_ps (lanes, acc);
    float m = lanes[0];
    for (size_t j = 1; j < 4; j++) if (lanes[j] > m) m = lanes[j];
    for (; i < len; i++) if (a[i] > m) m = a[i];
    return m;
}

static double
bv_min_f64_sse (const double *a, size_t len)
{
    size_t i = 1;
    __m128d acc = _mm_set1_pd (a[0]);
    for (; i + 1 < len; i += 2)
        acc = _mm_min_pd (acc, _mm_loadu_pd (a + i));
    double lanes[2];
    _mm_storeu_pd (lanes, acc);
    double m = lanes[0] < lanes[1] ? lanes[0] : lanes[1];
    for (; i < len; i++) if (a[i] < m) m = a[i];
    return m;
}

static double
bv_max_f64_sse (const double *a, size_t len)
{
    size_t i = 1;
    __m128d acc = _mm_set1_pd (a[0]);
    for (; i + 1 < len; i += 2)
        acc = _mm_max_pd (acc, _mm_loadu_pd (a + i));
    double lanes[2];
    _mm_storeu_pd (lanes, acc);
    double m = lanes[0] > lanes[1] ? lanes[0] : lanes[1];
    for (; i < len; i++) if (a[i] > m) m = a[i];
    return m;
}
#endif

static const char *
bv_backend_env (void)
{
    const char *e = getenv ("BASHVEC_BACKEND");
    return e && *e ? e : "auto";
}

static int
bv_backend_env_allows (const char *name)
{
    const char *e = bv_backend_env ();
    if (!strcmp (e, "auto") || !strcmp (e, name))
        return 1;
    if (!strcmp (e, "scalar") || !strcmp (e, "sse2") || !strcmp (e, "off"))
        return 0;
    return 0;
}

#if defined (BVEC_HAVE_AVX2_TARGET)
static int
bv_avx2_runtime_available (void)
{
    __builtin_cpu_init ();
    return __builtin_cpu_supports ("avx2") != 0;
}

static int
bv_use_avx2 (void)
{
    return bv_backend_env_allows ("avx2") && bv_avx2_runtime_available ();
}

__attribute__ ((target ("avx2")))
static long double
bv_sum_i32_avx2 (const int32_t *a, size_t len)
{
    size_t i = 0;
    __m256i acc_lo = _mm256_setzero_si256 ();
    __m256i acc_hi = _mm256_setzero_si256 ();
    for (; i + 7 < len; i += 8) {
        __m256i v = _mm256_loadu_si256 ((const __m256i *) (a + i));
        __m128i lo128 = _mm256_castsi256_si128 (v);
        __m128i hi128 = _mm256_extracti128_si256 (v, 1);
        acc_lo = _mm256_add_epi64 (acc_lo, _mm256_cvtepi32_epi64 (lo128));
        acc_hi = _mm256_add_epi64 (acc_hi, _mm256_cvtepi32_epi64 (hi128));
    }
    int64_t lanes[8];
    _mm256_storeu_si256 ((__m256i *) &lanes[0], acc_lo);
    _mm256_storeu_si256 ((__m256i *) &lanes[4], acc_hi);
    long double sum = 0.0L;
    for (size_t j = 0; j < 8; j++)
        sum += (long double) lanes[j];
    for (; i < len; i++)
        sum += (long double) a[i];
    return sum;
}

__attribute__ ((target ("avx2")))
static long double
bv_sum_u32_avx2 (const uint32_t *a, size_t len)
{
    size_t i = 0;
    __m256i acc_lo = _mm256_setzero_si256 ();
    __m256i acc_hi = _mm256_setzero_si256 ();
    for (; i + 7 < len; i += 8) {
        __m256i v = _mm256_loadu_si256 ((const __m256i *) (a + i));
        __m128i lo128 = _mm256_castsi256_si128 (v);
        __m128i hi128 = _mm256_extracti128_si256 (v, 1);
        acc_lo = _mm256_add_epi64 (acc_lo, _mm256_cvtepu32_epi64 (lo128));
        acc_hi = _mm256_add_epi64 (acc_hi, _mm256_cvtepu32_epi64 (hi128));
    }
    uint64_t lanes[8];
    _mm256_storeu_si256 ((__m256i *) &lanes[0], acc_lo);
    _mm256_storeu_si256 ((__m256i *) &lanes[4], acc_hi);
    long double sum = 0.0L;
    for (size_t j = 0; j < 8; j++)
        sum += (long double) lanes[j];
    for (; i < len; i++)
        sum += (long double) a[i];
    return sum;
}

__attribute__ ((target ("avx2")))
static int32_t
bv_min_i32_avx2 (const int32_t *a, size_t len)
{
    size_t i = 1;
    __m256i acc = _mm256_set1_epi32 (a[0]);
    for (; i + 7 < len; i += 8)
        acc = _mm256_min_epi32 (acc, _mm256_loadu_si256 ((const __m256i *) (a + i)));
    int32_t lanes[8];
    _mm256_storeu_si256 ((__m256i *) lanes, acc);
    int32_t m = lanes[0];
    for (size_t j = 1; j < 8; j++) if (lanes[j] < m) m = lanes[j];
    for (; i < len; i++) if (a[i] < m) m = a[i];
    return m;
}

__attribute__ ((target ("avx2")))
static int32_t
bv_max_i32_avx2 (const int32_t *a, size_t len)
{
    size_t i = 1;
    __m256i acc = _mm256_set1_epi32 (a[0]);
    for (; i + 7 < len; i += 8)
        acc = _mm256_max_epi32 (acc, _mm256_loadu_si256 ((const __m256i *) (a + i)));
    int32_t lanes[8];
    _mm256_storeu_si256 ((__m256i *) lanes, acc);
    int32_t m = lanes[0];
    for (size_t j = 1; j < 8; j++) if (lanes[j] > m) m = lanes[j];
    for (; i < len; i++) if (a[i] > m) m = a[i];
    return m;
}

__attribute__ ((target ("avx2")))
static uint32_t
bv_min_u32_avx2 (const uint32_t *a, size_t len)
{
    size_t i = 1;
    __m256i acc = _mm256_set1_epi32 ((int) a[0]);
    for (; i + 7 < len; i += 8)
        acc = _mm256_min_epu32 (acc, _mm256_loadu_si256 ((const __m256i *) (a + i)));
    uint32_t lanes[8];
    _mm256_storeu_si256 ((__m256i *) lanes, acc);
    uint32_t m = lanes[0];
    for (size_t j = 1; j < 8; j++) if (lanes[j] < m) m = lanes[j];
    for (; i < len; i++) if (a[i] < m) m = a[i];
    return m;
}

__attribute__ ((target ("avx2")))
static uint32_t
bv_max_u32_avx2 (const uint32_t *a, size_t len)
{
    size_t i = 1;
    __m256i acc = _mm256_set1_epi32 ((int) a[0]);
    for (; i + 7 < len; i += 8)
        acc = _mm256_max_epu32 (acc, _mm256_loadu_si256 ((const __m256i *) (a + i)));
    uint32_t lanes[8];
    _mm256_storeu_si256 ((__m256i *) lanes, acc);
    uint32_t m = lanes[0];
    for (size_t j = 1; j < 8; j++) if (lanes[j] > m) m = lanes[j];
    for (; i < len; i++) if (a[i] > m) m = a[i];
    return m;
}

__attribute__ ((target ("avx2")))
static float
bv_min_f32_avx2 (const float *a, size_t len)
{
    size_t i = 1;
    __m256 acc = _mm256_set1_ps (a[0]);
    for (; i + 7 < len; i += 8)
        acc = _mm256_min_ps (acc, _mm256_loadu_ps (a + i));
    float lanes[8];
    _mm256_storeu_ps (lanes, acc);
    float m = lanes[0];
    for (size_t j = 1; j < 8; j++) if (lanes[j] < m) m = lanes[j];
    for (; i < len; i++) if (a[i] < m) m = a[i];
    return m;
}

__attribute__ ((target ("avx2")))
static float
bv_max_f32_avx2 (const float *a, size_t len)
{
    size_t i = 1;
    __m256 acc = _mm256_set1_ps (a[0]);
    for (; i + 7 < len; i += 8)
        acc = _mm256_max_ps (acc, _mm256_loadu_ps (a + i));
    float lanes[8];
    _mm256_storeu_ps (lanes, acc);
    float m = lanes[0];
    for (size_t j = 1; j < 8; j++) if (lanes[j] > m) m = lanes[j];
    for (; i < len; i++) if (a[i] > m) m = a[i];
    return m;
}

__attribute__ ((target ("avx2")))
static double
bv_min_f64_avx2 (const double *a, size_t len)
{
    size_t i = 1;
    __m256d acc = _mm256_set1_pd (a[0]);
    for (; i + 3 < len; i += 4)
        acc = _mm256_min_pd (acc, _mm256_loadu_pd (a + i));
    double lanes[4];
    _mm256_storeu_pd (lanes, acc);
    double m = lanes[0];
    for (size_t j = 1; j < 4; j++) if (lanes[j] < m) m = lanes[j];
    for (; i < len; i++) if (a[i] < m) m = a[i];
    return m;
}

__attribute__ ((target ("avx2")))
static double
bv_max_f64_avx2 (const double *a, size_t len)
{
    size_t i = 1;
    __m256d acc = _mm256_set1_pd (a[0]);
    for (; i + 3 < len; i += 4)
        acc = _mm256_max_pd (acc, _mm256_loadu_pd (a + i));
    double lanes[4];
    _mm256_storeu_pd (lanes, acc);
    double m = lanes[0];
    for (size_t j = 1; j < 4; j++) if (lanes[j] > m) m = lanes[j];
    for (; i < len; i++) if (a[i] > m) m = a[i];
    return m;
}

__attribute__ ((target ("avx2")))
static size_t
bv_count_nonzero_i32_avx2 (const int32_t *a, size_t len)
{
    size_t i = 0, n = 0;
    __m256i zero = _mm256_setzero_si256 ();
    for (; i + 7 < len; i += 8) {
        __m256i eq = _mm256_cmpeq_epi32 (_mm256_loadu_si256 ((const __m256i *) (a + i)), zero);
        n += 8u - (size_t) __builtin_popcount ((unsigned) _mm256_movemask_ps (_mm256_castsi256_ps (eq)));
    }
    for (; i < len; i++) if (a[i] != 0) n++;
    return n;
}

__attribute__ ((target ("avx2")))
static size_t
bv_count_nonzero_i64_avx2 (const int64_t *a, size_t len)
{
    size_t i = 0, n = 0;
    __m256i zero = _mm256_setzero_si256 ();
    for (; i + 3 < len; i += 4) {
        __m256i eq = _mm256_cmpeq_epi64 (_mm256_loadu_si256 ((const __m256i *) (a + i)), zero);
        n += 4u - (size_t) __builtin_popcount ((unsigned) _mm256_movemask_pd (_mm256_castsi256_pd (eq)));
    }
    for (; i < len; i++) if (a[i] != 0) n++;
    return n;
}

__attribute__ ((target ("avx2")))
static size_t
bv_count_nonzero_f32_avx2 (const float *a, size_t len)
{
    size_t i = 0, n = 0;
    __m256 zero = _mm256_setzero_ps ();
    for (; i + 7 < len; i += 8) {
        __m256 eq = _mm256_cmp_ps (_mm256_loadu_ps (a + i), zero, _CMP_EQ_OQ);
        n += 8u - (size_t) __builtin_popcount ((unsigned) _mm256_movemask_ps (eq));
    }
    for (; i < len; i++) if (a[i] != 0.0f) n++;
    return n;
}

__attribute__ ((target ("avx2")))
static size_t
bv_count_nonzero_f64_avx2 (const double *a, size_t len)
{
    size_t i = 0, n = 0;
    __m256d zero = _mm256_setzero_pd ();
    for (; i + 3 < len; i += 4) {
        __m256d eq = _mm256_cmp_pd (_mm256_loadu_pd (a + i), zero, _CMP_EQ_OQ);
        n += 4u - (size_t) __builtin_popcount ((unsigned) _mm256_movemask_pd (eq));
    }
    for (; i < len; i++) if (a[i] != 0.0) n++;
    return n;
}
#else
static int
bv_use_avx2 (void)
{
    return 0;
}
#endif

static const char *
bv_selected_backend_name (void)
{
    if (bv_use_avx2 ())
        return "avx2";
#if defined (BVEC_HAVE_SSE2)
    if (bv_backend_env_allows ("sse2"))
        return "sse2";
#endif
    return "scalar";
}

/* Per-type helpers via X-macro for the reductions/ops loops. Keeps
   the verb dispatchers tight. */
#define BV_FOREACH_INT_TYPE(X)        \
    X (BVEC_I32, int32_t,  PRId32)    \
    X (BVEC_I64, int64_t,  PRId64)    \
    X (BVEC_U32, uint32_t, PRIu32)    \
    X (BVEC_U64, uint64_t, PRIu64)
#define BV_FOREACH_FLOAT_TYPE(X)      \
    X (BVEC_F32, float)               \
    X (BVEC_F64, double)

/* ---- verbs ---- */

static int
bv_new_cmd (WORD_LIST *args)
{
    const char *type_str = NULL;
    const char *len_str = NULL;
    size_t len = 0;
    const char *hvar = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-T") && p->next) { type_str = p->next->word->word; p = p->next; }
        else if (!strcmp (w, "-N") && p->next) { len_str = p->next->word->word; p = p->next; }
        else if (!strcmp (w, "-h") && p->next) { hvar = p->next->word->word; p = p->next; }
        else { builtin_error ("new: unexpected '%s'", w); return EX_USAGE; }
    }
    if (!type_str || !len_str) {
        builtin_error ("new: -T TYPE -N LEN [-h H_VAR] required"); return EX_USAGE;
    }
    enum bvec_type t;
    if (bv_parse_type (type_str, &t) != 0) {
        builtin_error ("new: unknown type '%s' (try i32/i64/u32/u64/f32/f64)", type_str);
        return EX_USAGE;
    }
    if (bv_parse_nonnegative_size (len_str, &len) != 0) {
        builtin_error ("new: invalid length '%s'", len_str);
        return EX_USAGE;
    }
    size_t esz = bv_type_size (t);
    if (len > SIZE_MAX / esz || len > (size_t) (BVEC_MAX_BYTES / esz)) {
        builtin_error ("new: dimension too large");
        return EX_USAGE;
    }
    size_t bytes = len * esz;
    /* aligned_alloc requires size to be a multiple of alignment. */
    size_t aligned_bytes = (bytes + 63) & ~(size_t) 63;
    if (aligned_bytes < bytes) {
        builtin_error ("new: dimension too large");
        return EX_USAGE;
    }
    if (aligned_bytes == 0) aligned_bytes = 64;
    void *data = aligned_alloc (64, aligned_bytes);
    if (!data) { builtin_error ("new: aligned_alloc failed"); return EXECUTION_FAILURE; }
    memset (data, 0, aligned_bytes);
    bvec_t *v = calloc (1, sizeof (bvec_t));
    if (!v) { free (data); builtin_error ("new: calloc"); return EXECUTION_FAILURE; }
    v->type = t; v->len = len; v->data = data;
    int slot = bv_alloc_handle (v);
    if (slot < 0) {
        free (data); free (v);
        builtin_error ("new: handle table full"); return EXECUTION_FAILURE;
    }
    char buf[16]; snprintf (buf, sizeof (buf), "%d", slot);
    if (hvar) builtin_bind_variable ((char *) hvar, buf, 0);
    else      printf ("%s\n", buf);
    return EXECUTION_SUCCESS;
}

static int
bv_free_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("free: HANDLE"); return EX_USAGE; }
    char *end;
    long h = strtol (args->word->word, &end, 10);
    if (*end || h < 0 || h >= BVEC_HANDLES_MAX || !bv_handles[h]) return EX_USAGE;
    free (bv_handles[h]->data);
    free (bv_handles[h]);
    bv_handles[h] = NULL;
    return EXECUTION_SUCCESS;
}

static int
bv_len_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("len: HANDLE"); return EX_USAGE; }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("len: bad handle"); return EX_USAGE; }
    printf ("%zu\n", v->len);
    return EXECUTION_SUCCESS;
}

static int
bv_type_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("type: HANDLE"); return EX_USAGE; }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("type: bad handle"); return EX_USAGE; }
    printf ("%s\n", bv_type_names[v->type]);
    return EXECUTION_SUCCESS;
}

static int
bv_backend_cmd (WORD_LIST *args)
{
    if (args) { builtin_error ("backend: no arguments"); return EX_USAGE; }
    printf ("%s\n", bv_selected_backend_name ());
    return EXECUTION_SUCCESS;
}

static int
bv_set_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next) {
        builtin_error ("set: HANDLE IDX VAL"); return EX_USAGE;
    }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("set: bad handle"); return EX_USAGE; }
    size_t idx;
    if (bv_parse_index (args->next->word->word, v->len, &idx) != 0) {
        builtin_error ("set: index %s out of bounds [0, %zu)", args->next->word->word, v->len);
        return EX_USAGE;
    }
    char buf[16];
    if (bv_parse_value (v->type, args->next->next->word->word, buf) != 0) {
        builtin_error ("set: cannot parse '%s' as %s",
                       args->next->next->word->word, bv_type_names[v->type]);
        return EX_USAGE;
    }
    memcpy ((char *) v->data + idx * bv_type_size (v->type),
            buf, bv_type_size (v->type));
    return EXECUTION_SUCCESS;
}

static int
bv_get_cmd (WORD_LIST *args)
{
    if (!args || !args->next) {
        builtin_error ("get: HANDLE IDX"); return EX_USAGE;
    }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("get: bad handle"); return EX_USAGE; }
    size_t idx;
    if (bv_parse_index (args->next->word->word, v->len, &idx) != 0) {
        builtin_error ("get: index %s out of bounds [0, %zu)", args->next->word->word, v->len);
        return EX_USAGE;
    }
    bv_print_cell (v->type, (char *) v->data + idx * bv_type_size (v->type));
    return EXECUTION_SUCCESS;
}

static int
bv_fill_cmd (WORD_LIST *args)
{
    if (!args || !args->next) {
        builtin_error ("fill: HANDLE VAL"); return EX_USAGE;
    }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("fill: bad handle"); return EX_USAGE; }
    char buf[16];
    if (bv_parse_value (v->type, args->next->word->word, buf) != 0) {
        builtin_error ("fill: cannot parse '%s' as %s",
                       args->next->word->word, bv_type_names[v->type]);
        return EX_USAGE;
    }
    size_t esz = bv_type_size (v->type);
    for (size_t i = 0; i < v->len; i++)
        memcpy ((char *) v->data + i * esz, buf, esz);
    return EXECUTION_SUCCESS;
}

/* Reductions. Print the result; type follows the input vec. */
static int
bv_sum_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("sum: HANDLE"); return EX_USAGE; }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("sum: bad handle"); return EX_USAGE; }
    if (v->len == 0) { printf ("0\n"); return EXECUTION_SUCCESS; }
    switch (v->type) {
    case BVEC_I32: { const int32_t *a = v->data;
#if defined (BVEC_HAVE_AVX2_TARGET)
        if (bv_use_avx2 ()) {
            printf ("%.0Lf\n", bv_sum_i32_avx2 (a, v->len)); return EXECUTION_SUCCESS;
        }
#endif
#if defined (BVEC_HAVE_SSE2)
        printf ("%.0Lf\n", bv_sum_i32_sse (a, v->len)); return EXECUTION_SUCCESS;
#else
        int64_t acc = 0; for (size_t i = 0; i < v->len; i++) { int64_t r; if (__builtin_add_overflow (acc, (int64_t) a[i], &r)) { builtin_error ("sum: i32 accumulator overflow at index %zu", i); return EX_USAGE; } acc = r; } printf ("%" PRId64 "\n", acc); return EXECUTION_SUCCESS;
#endif
    }
    case BVEC_I64: { int64_t acc = 0; const int64_t *a = v->data; for (size_t i = 0; i < v->len; i++) { int64_t r; if (__builtin_add_overflow (acc, a[i], &r)) { builtin_error ("sum: i64 accumulator overflow at index %zu", i); return EX_USAGE; } acc = r; } printf ("%" PRId64 "\n", acc); return EXECUTION_SUCCESS; }
    case BVEC_U32: { const uint32_t *a = v->data;
#if defined (BVEC_HAVE_AVX2_TARGET)
        if (bv_use_avx2 ()) {
            printf ("%.0Lf\n", bv_sum_u32_avx2 (a, v->len)); return EXECUTION_SUCCESS;
        }
#endif
#if defined (BVEC_HAVE_SSE2)
        printf ("%.0Lf\n", bv_sum_u32_sse (a, v->len)); return EXECUTION_SUCCESS;
#else
        uint64_t acc = 0; for (size_t i = 0; i < v->len; i++) { uint64_t r; if (__builtin_add_overflow (acc, (uint64_t) a[i], &r)) { builtin_error ("sum: u32 accumulator overflow at index %zu", i); return EX_USAGE; } acc = r; } printf ("%" PRIu64 "\n", acc); return EXECUTION_SUCCESS;
#endif
    }
    case BVEC_U64: { uint64_t acc = 0; const uint64_t *a = v->data; for (size_t i = 0; i < v->len; i++) { uint64_t r; if (__builtin_add_overflow (acc, a[i], &r)) { builtin_error ("sum: u64 accumulator overflow at index %zu", i); return EX_USAGE; } acc = r; } printf ("%" PRIu64 "\n", acc); return EXECUTION_SUCCESS; }
    case BVEC_F32: {
        const float *a = v->data;
#if defined (BVEC_HAVE_SSE2)
        long double acc = bv_sum_f32_sse (a, v->len);
#else
        long double acc = 0.0L; for (size_t i = 0; i < v->len; i++) acc += (long double) a[i];
#endif
        if (acc > (long double) DBL_MAX || acc < -(long double) DBL_MAX) { builtin_error ("sum: f32 accumulator overflow"); return EX_USAGE; }
        printf ("%g\n", (double) acc); return EXECUTION_SUCCESS; }
    case BVEC_F64: {
        const double *a = v->data;
#if defined (BVEC_HAVE_SSE2)
        long double acc = bv_sum_f64_sse (a, v->len);
#else
        long double acc = 0.0L; for (size_t i = 0; i < v->len; i++) acc += (long double) a[i];
#endif
        if (acc > (long double) DBL_MAX || acc < -(long double) DBL_MAX) { builtin_error ("sum: f64 accumulator overflow"); return EX_USAGE; }
        printf ("%g\n", (double) acc); return EXECUTION_SUCCESS; }
    default: return EXECUTION_FAILURE;
    }
}

static int
bv_min_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("min: HANDLE"); return EX_USAGE; }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("min: bad handle"); return EX_USAGE; }
    if (v->len == 0) { printf ("0\n"); return EXECUTION_SUCCESS; }
    switch (v->type) {
    case BVEC_I32: { const int32_t *a = v->data;
#if defined (BVEC_HAVE_AVX2_TARGET)
        if (bv_use_avx2 ()) { printf ("%" PRId32 "\n", bv_min_i32_avx2 (a, v->len)); return EXECUTION_SUCCESS; }
#endif
        int32_t acc = a[0]; for (size_t i = 1; i < v->len; i++) if (a[i] < acc) acc = a[i]; printf ("%" PRId32 "\n", acc); return EXECUTION_SUCCESS; }
    case BVEC_I64: { const int64_t *a = v->data; int64_t acc = a[0]; for (size_t i = 1; i < v->len; i++) if (a[i] < acc) acc = a[i]; printf ("%" PRId64 "\n", acc); return EXECUTION_SUCCESS; }
    case BVEC_U32: { const uint32_t *a = v->data;
#if defined (BVEC_HAVE_AVX2_TARGET)
        if (bv_use_avx2 ()) { printf ("%" PRIu32 "\n", bv_min_u32_avx2 (a, v->len)); return EXECUTION_SUCCESS; }
#endif
        uint32_t acc = a[0]; for (size_t i = 1; i < v->len; i++) if (a[i] < acc) acc = a[i]; printf ("%" PRIu32 "\n", acc); return EXECUTION_SUCCESS; }
    case BVEC_U64: { const uint64_t *a = v->data; uint64_t acc = a[0]; for (size_t i = 1; i < v->len; i++) if (a[i] < acc) acc = a[i]; printf ("%" PRIu64 "\n", acc); return EXECUTION_SUCCESS; }
    case BVEC_F32: { const float *a = v->data;
#if defined (BVEC_HAVE_AVX2_TARGET)
        if (bv_use_avx2 ()) { printf ("%g\n", bv_min_f32_avx2 (a, v->len)); return EXECUTION_SUCCESS; }
#endif
#if defined (BVEC_HAVE_SSE2)
        printf ("%g\n", bv_min_f32_sse (a, v->len)); return EXECUTION_SUCCESS;
#else
        float acc = a[0]; for (size_t i = 1; i < v->len; i++) if (a[i] < acc) acc = a[i]; printf ("%g\n", acc); return EXECUTION_SUCCESS;
#endif
    }
    case BVEC_F64: { const double *a = v->data;
#if defined (BVEC_HAVE_AVX2_TARGET)
        if (bv_use_avx2 ()) { printf ("%g\n", bv_min_f64_avx2 (a, v->len)); return EXECUTION_SUCCESS; }
#endif
#if defined (BVEC_HAVE_SSE2)
        printf ("%g\n", bv_min_f64_sse (a, v->len)); return EXECUTION_SUCCESS;
#else
        double acc = a[0]; for (size_t i = 1; i < v->len; i++) if (a[i] < acc) acc = a[i]; printf ("%g\n", acc); return EXECUTION_SUCCESS;
#endif
    }
    default: return EXECUTION_FAILURE;
    }
}

static int
bv_max_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("max: HANDLE"); return EX_USAGE; }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("max: bad handle"); return EX_USAGE; }
    if (v->len == 0) { printf ("0\n"); return EXECUTION_SUCCESS; }
    switch (v->type) {
    case BVEC_I32: { const int32_t *a = v->data;
#if defined (BVEC_HAVE_AVX2_TARGET)
        if (bv_use_avx2 ()) { printf ("%" PRId32 "\n", bv_max_i32_avx2 (a, v->len)); return EXECUTION_SUCCESS; }
#endif
        int32_t acc = a[0]; for (size_t i = 1; i < v->len; i++) if (a[i] > acc) acc = a[i]; printf ("%" PRId32 "\n", acc); return EXECUTION_SUCCESS; }
    case BVEC_I64: { const int64_t *a = v->data; int64_t acc = a[0]; for (size_t i = 1; i < v->len; i++) if (a[i] > acc) acc = a[i]; printf ("%" PRId64 "\n", acc); return EXECUTION_SUCCESS; }
    case BVEC_U32: { const uint32_t *a = v->data;
#if defined (BVEC_HAVE_AVX2_TARGET)
        if (bv_use_avx2 ()) { printf ("%" PRIu32 "\n", bv_max_u32_avx2 (a, v->len)); return EXECUTION_SUCCESS; }
#endif
        uint32_t acc = a[0]; for (size_t i = 1; i < v->len; i++) if (a[i] > acc) acc = a[i]; printf ("%" PRIu32 "\n", acc); return EXECUTION_SUCCESS; }
    case BVEC_U64: { const uint64_t *a = v->data; uint64_t acc = a[0]; for (size_t i = 1; i < v->len; i++) if (a[i] > acc) acc = a[i]; printf ("%" PRIu64 "\n", acc); return EXECUTION_SUCCESS; }
    case BVEC_F32: { const float *a = v->data;
#if defined (BVEC_HAVE_AVX2_TARGET)
        if (bv_use_avx2 ()) { printf ("%g\n", bv_max_f32_avx2 (a, v->len)); return EXECUTION_SUCCESS; }
#endif
#if defined (BVEC_HAVE_SSE2)
        printf ("%g\n", bv_max_f32_sse (a, v->len)); return EXECUTION_SUCCESS;
#else
        float acc = a[0]; for (size_t i = 1; i < v->len; i++) if (a[i] > acc) acc = a[i]; printf ("%g\n", acc); return EXECUTION_SUCCESS;
#endif
    }
    case BVEC_F64: { const double *a = v->data;
#if defined (BVEC_HAVE_AVX2_TARGET)
        if (bv_use_avx2 ()) { printf ("%g\n", bv_max_f64_avx2 (a, v->len)); return EXECUTION_SUCCESS; }
#endif
#if defined (BVEC_HAVE_SSE2)
        printf ("%g\n", bv_max_f64_sse (a, v->len)); return EXECUTION_SUCCESS;
#else
        double acc = a[0]; for (size_t i = 1; i < v->len; i++) if (a[i] > acc) acc = a[i]; printf ("%g\n", acc); return EXECUTION_SUCCESS;
#endif
    }
    default: return EXECUTION_FAILURE;
    }
}

static int
bv_mean_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("mean: HANDLE"); return EX_USAGE; }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("mean: bad handle"); return EX_USAGE; }
    if (v->len == 0) { printf ("0\n"); return EXECUTION_SUCCESS; }
    double acc = 0.0;
    switch (v->type) {
    case BVEC_I32: { const int32_t  *a = v->data; for (size_t i = 0; i < v->len; i++) acc += (double) a[i]; break; }
    case BVEC_I64: { const int64_t  *a = v->data; for (size_t i = 0; i < v->len; i++) acc += (double) a[i]; break; }
    case BVEC_U32: { const uint32_t *a = v->data; for (size_t i = 0; i < v->len; i++) acc += (double) a[i]; break; }
    case BVEC_U64: { const uint64_t *a = v->data; for (size_t i = 0; i < v->len; i++) acc += (double) a[i]; break; }
    case BVEC_F32: { const float    *a = v->data; for (size_t i = 0; i < v->len; i++) acc += (double) a[i]; break; }
    case BVEC_F64: { const double   *a = v->data; for (size_t i = 0; i < v->len; i++) acc += a[i]; break; }
    default: return EXECUTION_FAILURE;
    }
    if (!isfinite (acc)) {
        builtin_error ("mean: accumulator overflow");
        return EX_USAGE;
    }
    printf ("%g\n", acc / (double) v->len);
    return EXECUTION_SUCCESS;
}

enum bvec_binop { BVEC_OP_ADD, BVEC_OP_SUB, BVEC_OP_MUL, BVEC_OP_DIV, BVEC_OP_MOD };

static int
bv_apply_binop (const char *verb, WORD_LIST *args, enum bvec_binop op)
{
    if (!args || !args->next) {
        builtin_error ("%s: A B (in-place on A)", verb);
        return EX_USAGE;
    }
    bvec_t *a = bv_get (args->word->word);
    bvec_t *b = bv_get (args->next->word->word);
    if (!a || !b) { builtin_error ("%s: bad handle", verb); return EX_USAGE; }
    if (bv_same_len (verb, a, b) != 0)
        return EX_USAGE;

    size_t aesz = bv_type_size (a->type);
    size_t besz = bv_type_size (b->type);
    for (size_t i = 0; i < a->len; i++) {
        char *ap = (char *) a->data + i * aesz;
        const char *bp = (const char *) b->data + i * besz;
        long double av = bv_cell_as_long_double (a->type, ap);
        long double bv = bv_cell_as_long_double (b->type, bp);
        long double r;
        switch (op) {
        case BVEC_OP_ADD: r = av + bv; break;
        case BVEC_OP_SUB: r = av - bv; break;
        case BVEC_OP_MUL: r = av * bv; break;
        case BVEC_OP_DIV:
            if (bv == 0.0L) { builtin_error ("%s: divide by zero at index %zu", verb, i); return EX_USAGE; }
            r = av / bv;
            break;
        case BVEC_OP_MOD:
            if (a->type == BVEC_F32 || a->type == BVEC_F64 || b->type == BVEC_F32 || b->type == BVEC_F64) {
                builtin_error ("%s: modulo requires integer vectors", verb);
                return EX_USAGE;
            }
            if (bv == 0.0L) { builtin_error ("%s: modulo by zero at index %zu", verb, i); return EX_USAGE; }
            if (!bv_long_double_is_integral (av) || !bv_long_double_is_integral (bv))
                return EX_USAGE;
            r = (long double) ((int64_t) av % (int64_t) bv);
            break;
        default:
            return EXECUTION_FAILURE;
        }
        if (bv_store_long_double (a->type, r, ap) != 0) {
            builtin_error ("%s: cannot store result in %s at index %zu",
                           verb, bv_type_names[a->type], i);
            return EX_USAGE;
        }
    }
    return EXECUTION_SUCCESS;
}

/* In-place A[i] += B[i]. Mixed source types are accepted when the result
   can be represented in A's type. */
static int
bv_add_cmd (WORD_LIST *args)
{
    return bv_apply_binop ("add", args, BVEC_OP_ADD);
}

static int bv_sub_cmd (WORD_LIST *args) { return bv_apply_binop ("sub", args, BVEC_OP_SUB); }
static int bv_mul_cmd (WORD_LIST *args) { return bv_apply_binop ("mul", args, BVEC_OP_MUL); }
static int bv_div_cmd (WORD_LIST *args) { return bv_apply_binop ("div", args, BVEC_OP_DIV); }
static int bv_mod_cmd (WORD_LIST *args) { return bv_apply_binop ("mod", args, BVEC_OP_MOD); }

static int
bv_promote_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next) {
        builtin_error ("promote: A B OP -T TYPE [-h H_VAR]");
        return EX_USAGE;
    }
    bvec_t *a = bv_get (args->word->word);
    bvec_t *b = bv_get (args->next->word->word);
    const char *op = args->next->next->word->word;
    const char *type_str = NULL;
    const char *hvar = NULL;
    if (!a || !b) { builtin_error ("promote: bad handle"); return EX_USAGE; }
    if (bv_same_len ("promote", a, b) != 0) return EX_USAGE;
    for (WORD_LIST *p = args->next->next->next; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-T") && p->next) { type_str = p->next->word->word; p = p->next; }
        else if (!strcmp (w, "-h") && p->next) { hvar = p->next->word->word; p = p->next; }
        else { builtin_error ("promote: unexpected '%s'", w); return EX_USAGE; }
    }
    if (!type_str) { builtin_error ("promote: -T TYPE required"); return EX_USAGE; }
    enum bvec_type dst_type;
    if (bv_parse_type (type_str, &dst_type) != 0) {
        builtin_error ("promote: unknown type '%s' (try i32/i64/u32/u64/f32/f64)", type_str);
        return EX_USAGE;
    }
    enum bvec_binop bop;
    if (!strcmp (op, "add")) bop = BVEC_OP_ADD;
    else if (!strcmp (op, "sub")) bop = BVEC_OP_SUB;
    else if (!strcmp (op, "mul")) bop = BVEC_OP_MUL;
    else if (!strcmp (op, "div")) bop = BVEC_OP_DIV;
    else if (!strcmp (op, "mod")) bop = BVEC_OP_MOD;
    else { builtin_error ("promote: OP must be add|sub|mul|div|mod"); return EX_USAGE; }
    if (bop == BVEC_OP_MOD &&
        (a->type == BVEC_F32 || a->type == BVEC_F64 ||
         b->type == BVEC_F32 || b->type == BVEC_F64 ||
         dst_type == BVEC_F32 || dst_type == BVEC_F64)) {
        builtin_error ("promote: mod requires integer input and output types");
        return EX_USAGE;
    }

    void *data = bv_aligned_zalloc (a->len, dst_type);
    if (!data) { builtin_error ("promote: dimension too large or allocation failed"); return EXECUTION_FAILURE; }
    size_t aesz = bv_type_size (a->type), besz = bv_type_size (b->type);
    size_t desz = bv_type_size (dst_type);
    for (size_t i = 0; i < a->len; i++) {
        long double av = bv_cell_as_long_double (a->type, (const char *) a->data + i * aesz);
        long double bv = bv_cell_as_long_double (b->type, (const char *) b->data + i * besz);
        long double r;
        switch (bop) {
        case BVEC_OP_ADD: r = av + bv; break;
        case BVEC_OP_SUB: r = av - bv; break;
        case BVEC_OP_MUL: r = av * bv; break;
        case BVEC_OP_DIV:
            if (bv == 0.0L) { free (data); builtin_error ("promote: divide by zero at index %zu", i); return EX_USAGE; }
            r = av / bv; break;
        case BVEC_OP_MOD:
            if (bv == 0.0L) { free (data); builtin_error ("promote: modulo by zero at index %zu", i); return EX_USAGE; }
            if (!bv_long_double_is_integral (av) || !bv_long_double_is_integral (bv)) {
                free (data); builtin_error ("promote: modulo requires integral values at index %zu", i); return EX_USAGE;
            }
            r = (long double) ((int64_t) av % (int64_t) bv);
            break;
        default:
            free (data); return EXECUTION_FAILURE;
        }
        if (bv_store_long_double (dst_type, r, (char *) data + i * desz) != 0) {
            free (data);
            builtin_error ("promote: cannot store result in %s at index %zu",
                           bv_type_names[dst_type], i);
            return EX_USAGE;
        }
    }
    return bv_take_handle (dst_type, a->len, data, hvar, "promote");
}

static int
bv_scale_cmd (WORD_LIST *args)
{
    if (!args || !args->next) {
        builtin_error ("scale: HANDLE S"); return EX_USAGE;
    }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("scale: bad handle"); return EX_USAGE; }
    char *end;
    errno = 0;
    double s = strtod (args->next->word->word, &end);
    if (errno == ERANGE || *end || !isfinite (s)) { builtin_error ("scale: cannot parse '%s'", args->next->word->word); return EX_USAGE; }
    switch (v->type) {
    case BVEC_I32: { int32_t  *xa = v->data; for (size_t i = 0; i < v->len; i++) { long double r = (long double) xa[i] * (long double) s; if (!isfinite ((double) r) || r < (long double) INT32_MIN || r > (long double) INT32_MAX) { builtin_error ("scale: i32 overflow at index %zu", i); return EX_USAGE; } xa[i] = (int32_t) r; } break; }
    case BVEC_I64: { int64_t  *xa = v->data; for (size_t i = 0; i < v->len; i++) { long double r = (long double) xa[i] * (long double) s; if (!isfinite ((double) r) || r < (long double) INT64_MIN || r > (long double) INT64_MAX) { builtin_error ("scale: i64 overflow at index %zu", i); return EX_USAGE; } xa[i] = (int64_t) r; } break; }
    case BVEC_U32: { uint32_t *xa = v->data; for (size_t i = 0; i < v->len; i++) { long double r = (long double) xa[i] * (long double) s; if (!isfinite ((double) r) || r < 0.0L || r > (long double) UINT32_MAX) { builtin_error ("scale: u32 overflow at index %zu", i); return EX_USAGE; } xa[i] = (uint32_t) r; } break; }
    case BVEC_U64: { uint64_t *xa = v->data; for (size_t i = 0; i < v->len; i++) { long double r = (long double) xa[i] * (long double) s; if (!isfinite ((double) r) || r < 0.0L || r > (long double) UINT64_MAX) { builtin_error ("scale: u64 overflow at index %zu", i); return EX_USAGE; } xa[i] = (uint64_t) r; } break; }
    case BVEC_F32: { float    *xa = v->data; for (size_t i = 0; i < v->len; i++) { long double r = (long double) xa[i] * (long double) s; if (!isfinite ((double) r) || r > (long double) FLT_MAX || r < -(long double) FLT_MAX) { builtin_error ("scale: f32 overflow at index %zu", i); return EX_USAGE; } xa[i] = (float) r; } break; }
    case BVEC_F64: { double   *xa = v->data; for (size_t i = 0; i < v->len; i++) { long double r = (long double) xa[i] * (long double) s; if (!isfinite ((double) r) || r > (long double) DBL_MAX || r < -(long double) DBL_MAX) { builtin_error ("scale: f64 overflow at index %zu", i); return EX_USAGE; } xa[i] = (double) r; } break; }
    default: return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bv_convert_cmd (WORD_LIST *args)
{
    const char *src_str;
    const char *type_str = NULL;
    const char *hvar = NULL;
    enum bvec_type dst_type;
    bvec_t *src;
    size_t src_esz, dst_esz, bytes, aligned_bytes;
    void *data;
    bvec_t *dst;
    int slot;
    char buf[16];

    if (!args) { builtin_error ("convert: SRC -T TYPE [-h H_VAR]"); return EX_USAGE; }
    src_str = args->word->word;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-T") && p->next) { type_str = p->next->word->word; p = p->next; }
        else if (!strcmp (w, "-h") && p->next) { hvar = p->next->word->word; p = p->next; }
        else { builtin_error ("convert: unexpected '%s'", w); return EX_USAGE; }
    }
    if (!type_str) { builtin_error ("convert: SRC -T TYPE [-h H_VAR] required"); return EX_USAGE; }
    src = bv_get (src_str);
    if (!src) { builtin_error ("convert: bad handle"); return EX_USAGE; }
    if (bv_parse_type (type_str, &dst_type) != 0) {
        builtin_error ("convert: unknown type '%s' (try i32/i64/u32/u64/f32/f64)", type_str);
        return EX_USAGE;
    }

    src_esz = bv_type_size (src->type);
    dst_esz = bv_type_size (dst_type);
    if (src->len > SIZE_MAX / dst_esz || src->len > (size_t) (BVEC_MAX_BYTES / dst_esz)) {
        builtin_error ("convert: dimension too large");
        return EX_USAGE;
    }
    bytes = src->len * dst_esz;
    aligned_bytes = (bytes + 63) & ~(size_t) 63;
    if (aligned_bytes < bytes) { builtin_error ("convert: dimension too large"); return EX_USAGE; }
    if (aligned_bytes == 0) aligned_bytes = 64;
    data = aligned_alloc (64, aligned_bytes);
    if (!data) { builtin_error ("convert: aligned_alloc failed"); return EXECUTION_FAILURE; }
    memset (data, 0, aligned_bytes);

    for (size_t i = 0; i < src->len; i++) {
        long double v = bv_cell_as_long_double (src->type, (const char *) src->data + i * src_esz);
        if (bv_store_long_double (dst_type, v, (char *) data + i * dst_esz) != 0) {
            free (data);
            builtin_error ("convert: cannot convert %s to %s at index %zu",
                           bv_type_names[src->type], bv_type_names[dst_type], i);
            return EX_USAGE;
        }
    }

    dst = calloc (1, sizeof (bvec_t));
    if (!dst) { free (data); builtin_error ("convert: calloc"); return EXECUTION_FAILURE; }
    dst->type = dst_type;
    dst->len = src->len;
    dst->data = data;
    slot = bv_alloc_handle (dst);
    if (slot < 0) {
        free (data); free (dst);
        builtin_error ("convert: handle table full"); return EXECUTION_FAILURE;
    }
    snprintf (buf, sizeof (buf), "%d", slot);
    if (hvar) builtin_bind_variable ((char *) hvar, buf, 0);
    else printf ("%s\n", buf);
    return EXECUTION_SUCCESS;
}

static int
bv_copy_like (const char *verb, bvec_t *src, size_t start, size_t len,
              const char *hvar)
{
    if (start > src->len || len > src->len - start) {
        builtin_error ("%s: slice out of bounds", verb);
        return EX_USAGE;
    }
    void *data = bv_aligned_zalloc (len, src->type);
    if (!data) { builtin_error ("%s: dimension too large or allocation failed", verb); return EXECUTION_FAILURE; }
    size_t esz = bv_type_size (src->type);
    memcpy (data, (const char *) src->data + start * esz, len * esz);
    return bv_take_handle (src->type, len, data, hvar, verb);
}

static int
bv_copy_cmd (WORD_LIST *args)
{
    const char *hvar = NULL;
    if (!args) { builtin_error ("copy: SRC [-h H_VAR]"); return EX_USAGE; }
    bvec_t *src = bv_get (args->word->word);
    if (!src) { builtin_error ("copy: bad handle"); return EX_USAGE; }
    for (WORD_LIST *p = args->next; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-h") && p->next) { hvar = p->next->word->word; p = p->next; }
        else { builtin_error ("copy: unexpected '%s'", w); return EX_USAGE; }
    }
    return bv_copy_like ("copy", src, 0, src->len, hvar);
}

static int
bv_slice_cmd (WORD_LIST *args)
{
    const char *hvar = NULL;
    size_t start, len;
    if (!args || !args->next || !args->next->next) {
        builtin_error ("slice: SRC START LEN [-h H_VAR]");
        return EX_USAGE;
    }
    bvec_t *src = bv_get (args->word->word);
    if (!src) { builtin_error ("slice: bad handle"); return EX_USAGE; }
    if (bv_parse_nonnegative_size (args->next->word->word, &start) != 0 ||
        bv_parse_nonnegative_size (args->next->next->word->word, &len) != 0) {
        builtin_error ("slice: invalid START/LEN");
        return EX_USAGE;
    }
    for (WORD_LIST *p = args->next->next->next; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-h") && p->next) { hvar = p->next->word->word; p = p->next; }
        else { builtin_error ("slice: unexpected '%s'", w); return EX_USAGE; }
    }
    return bv_copy_like ("slice", src, start, len, hvar);
}

static int
bv_dot_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("dot: A B"); return EX_USAGE; }
    bvec_t *a = bv_get (args->word->word);
    bvec_t *b = bv_get (args->next->word->word);
    if (!a || !b) { builtin_error ("dot: bad handle"); return EX_USAGE; }
    if (bv_same_len ("dot", a, b) != 0) return EX_USAGE;
#if defined (BVEC_HAVE_SSE2)
    if (a->type == BVEC_F32 && b->type == BVEC_F32) {
        long double acc = bv_dot_f32_sse ((const float *) a->data, (const float *) b->data, a->len);
        if (!isfinite (acc)) { builtin_error ("dot: accumulator overflow"); return EX_USAGE; }
        printf ("%.17Lg\n", acc);
        return EXECUTION_SUCCESS;
    }
    if (a->type == BVEC_F64 && b->type == BVEC_F64) {
        long double acc = bv_dot_f64_sse ((const double *) a->data, (const double *) b->data, a->len);
        if (!isfinite (acc)) { builtin_error ("dot: accumulator overflow"); return EX_USAGE; }
        printf ("%.17Lg\n", acc);
        return EXECUTION_SUCCESS;
    }
#endif
    size_t aesz = bv_type_size (a->type), besz = bv_type_size (b->type);
    long double acc = 0.0L;
    for (size_t i = 0; i < a->len; i++) {
        acc += bv_cell_as_long_double (a->type, (const char *) a->data + i * aesz) *
               bv_cell_as_long_double (b->type, (const char *) b->data + i * besz);
        if (!isfinite (acc)) { builtin_error ("dot: accumulator overflow at index %zu", i); return EX_USAGE; }
    }
    printf ("%.17Lg\n", acc);
    return EXECUTION_SUCCESS;
}

static int
bv_axpy_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next) {
        builtin_error ("axpy: A X Y (in-place Y[i] += A * X[i])");
        return EX_USAGE;
    }
    char *end;
    errno = 0;
    long double alpha = strtold (args->word->word, &end);
    if (errno == ERANGE || *end || !isfinite (alpha)) {
        builtin_error ("axpy: bad scalar '%s'", args->word->word);
        return EX_USAGE;
    }
    bvec_t *x = bv_get (args->next->word->word);
    bvec_t *y = bv_get (args->next->next->word->word);
    if (!x || !y) { builtin_error ("axpy: bad handle"); return EX_USAGE; }
    if (bv_same_len ("axpy", x, y) != 0) return EX_USAGE;
    size_t xesz = bv_type_size (x->type), yesz = bv_type_size (y->type);
    for (size_t i = 0; i < y->len; i++) {
        const char *xp = (const char *) x->data + i * xesz;
        char *yp = (char *) y->data + i * yesz;
        long double r = bv_cell_as_long_double (y->type, yp) +
                        alpha * bv_cell_as_long_double (x->type, xp);
        if (bv_store_long_double (y->type, r, yp) != 0) {
            builtin_error ("axpy: cannot store result in %s at index %zu",
                           bv_type_names[y->type], i);
            return EX_USAGE;
        }
    }
    return EXECUTION_SUCCESS;
}

static int
bv_count_nonzero_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("count-nonzero: H"); return EX_USAGE; }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("count-nonzero: bad handle"); return EX_USAGE; }
#if defined (BVEC_HAVE_AVX2_TARGET)
    if (bv_use_avx2 ()) {
        switch (v->type) {
        case BVEC_I32: printf ("%zu\n", bv_count_nonzero_i32_avx2 ((const int32_t *) v->data, v->len)); return EXECUTION_SUCCESS;
        case BVEC_I64: printf ("%zu\n", bv_count_nonzero_i64_avx2 ((const int64_t *) v->data, v->len)); return EXECUTION_SUCCESS;
        case BVEC_U32: printf ("%zu\n", bv_count_nonzero_i32_avx2 ((const int32_t *) v->data, v->len)); return EXECUTION_SUCCESS;
        case BVEC_U64: printf ("%zu\n", bv_count_nonzero_i64_avx2 ((const int64_t *) v->data, v->len)); return EXECUTION_SUCCESS;
        case BVEC_F32: printf ("%zu\n", bv_count_nonzero_f32_avx2 ((const float *) v->data, v->len)); return EXECUTION_SUCCESS;
        case BVEC_F64: printf ("%zu\n", bv_count_nonzero_f64_avx2 ((const double *) v->data, v->len)); return EXECUTION_SUCCESS;
        default: break;
        }
    }
#endif
    size_t esz = bv_type_size (v->type), n = 0;
    for (size_t i = 0; i < v->len; i++)
        if (bv_cell_as_long_double (v->type, (const char *) v->data + i * esz) != 0.0L)
            n++;
    printf ("%zu\n", n);
    return EXECUTION_SUCCESS;
}

static int
bv_anyall_cmd (const char *verb, WORD_LIST *args, int want_all)
{
    if (!args) { builtin_error ("%s: H", verb); return EX_USAGE; }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("%s: bad handle", verb); return EX_USAGE; }
    size_t esz = bv_type_size (v->type);
    int result = want_all ? 1 : 0;
    for (size_t i = 0; i < v->len; i++) {
        int nz = bv_cell_as_long_double (v->type, (const char *) v->data + i * esz) != 0.0L;
        if (want_all && !nz) { result = 0; break; }
        if (!want_all && nz) { result = 1; break; }
    }
    printf ("%d\n", result);
    return EXECUTION_SUCCESS;
}

static int
bv_var_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("var: H"); return EX_USAGE; }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("var: bad handle"); return EX_USAGE; }
    if (v->len == 0) { printf ("0\n"); return EXECUTION_SUCCESS; }
    size_t esz = bv_type_size (v->type);
    long double mean = 0.0L, acc = 0.0L;
    for (size_t i = 0; i < v->len; i++)
        mean += bv_cell_as_long_double (v->type, (const char *) v->data + i * esz);
    mean /= (long double) v->len;
    if (!isfinite (mean)) { builtin_error ("var: accumulator overflow"); return EX_USAGE; }
    for (size_t i = 0; i < v->len; i++) {
        long double d = bv_cell_as_long_double (v->type, (const char *) v->data + i * esz) - mean;
        acc += d * d;
        if (!isfinite (acc)) { builtin_error ("var: accumulator overflow at index %zu", i); return EX_USAGE; }
    }
    printf ("%.17Lg\n", acc / (long double) v->len);
    return EXECUTION_SUCCESS;
}

static int
bv_std_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("std: H"); return EX_USAGE; }
    bvec_t *v = bv_get (args->word->word);
    if (!v) { builtin_error ("std: bad handle"); return EX_USAGE; }
    if (v->len == 0) { printf ("0\n"); return EXECUTION_SUCCESS; }
    size_t esz = bv_type_size (v->type);
    long double mean = 0.0L, acc = 0.0L;
    for (size_t i = 0; i < v->len; i++)
        mean += bv_cell_as_long_double (v->type, (const char *) v->data + i * esz);
    mean /= (long double) v->len;
    if (!isfinite (mean)) { builtin_error ("std: accumulator overflow"); return EX_USAGE; }
    for (size_t i = 0; i < v->len; i++) {
        long double d = bv_cell_as_long_double (v->type, (const char *) v->data + i * esz) - mean;
        acc += d * d;
        if (!isfinite (acc)) { builtin_error ("std: accumulator overflow at index %zu", i); return EX_USAGE; }
    }
    printf ("%.17Lg\n", bv_sqrt_long_double (acc / (long double) v->len));
    return EXECUTION_SUCCESS;
}

static int
bv_cmp_cmd (WORD_LIST *args)
{
    const char *hvar = NULL;
    if (!args || !args->next || !args->next->next) {
        builtin_error ("cmp: A B OP [-h H_VAR]");
        return EX_USAGE;
    }
    bvec_t *a = bv_get (args->word->word);
    bvec_t *b = bv_get (args->next->word->word);
    const char *op = args->next->next->word->word;
    if (!a || !b) { builtin_error ("cmp: bad handle"); return EX_USAGE; }
    if (bv_same_len ("cmp", a, b) != 0) return EX_USAGE;
    for (WORD_LIST *p = args->next->next->next; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-h") && p->next) { hvar = p->next->word->word; p = p->next; }
        else { builtin_error ("cmp: unexpected '%s'", w); return EX_USAGE; }
    }
    void *data = bv_aligned_zalloc (a->len, BVEC_U32);
    if (!data) { builtin_error ("cmp: allocation failed"); return EXECUTION_FAILURE; }
    size_t aesz = bv_type_size (a->type), besz = bv_type_size (b->type);
    uint32_t *out = data;
    for (size_t i = 0; i < a->len; i++) {
        long double av = bv_cell_as_long_double (a->type, (const char *) a->data + i * aesz);
        long double bv = bv_cell_as_long_double (b->type, (const char *) b->data + i * besz);
        int ok;
        if (!strcmp (op, "eq")) ok = av == bv;
        else if (!strcmp (op, "ne")) ok = av != bv;
        else if (!strcmp (op, "lt")) ok = av < bv;
        else if (!strcmp (op, "le")) ok = av <= bv;
        else if (!strcmp (op, "gt")) ok = av > bv;
        else if (!strcmp (op, "ge")) ok = av >= bv;
        else { free (data); builtin_error ("cmp: unknown op '%s'", op); return EX_USAGE; }
        out[i] = ok ? 1U : 0U;
    }
    return bv_take_handle (BVEC_U32, a->len, data, hvar, "cmp");
}

static int
bv_where_cmd (WORD_LIST *args)
{
    const char *hvar = NULL;
    if (!args || !args->next || !args->next->next) {
        builtin_error ("where: MASK A B [-h H_VAR]");
        return EX_USAGE;
    }
    bvec_t *mask = bv_get (args->word->word);
    bvec_t *a = bv_get (args->next->word->word);
    bvec_t *b = bv_get (args->next->next->word->word);
    if (!mask || !a || !b) { builtin_error ("where: bad handle"); return EX_USAGE; }
    if (a->type != b->type) { builtin_error ("where: A and B must share type"); return EX_USAGE; }
    if (mask->len != a->len || a->len != b->len) {
        builtin_error ("where: length mismatch");
        return EX_USAGE;
    }
    for (WORD_LIST *p = args->next->next->next; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-h") && p->next) { hvar = p->next->word->word; p = p->next; }
        else { builtin_error ("where: unexpected '%s'", w); return EX_USAGE; }
    }
    void *data = bv_aligned_zalloc (a->len, a->type);
    if (!data) { builtin_error ("where: allocation failed"); return EXECUTION_FAILURE; }
    size_t mesz = bv_type_size (mask->type), esz = bv_type_size (a->type);
    for (size_t i = 0; i < a->len; i++) {
        int take_a = bv_cell_as_long_double (mask->type, (const char *) mask->data + i * mesz) != 0.0L;
        memcpy ((char *) data + i * esz,
                (take_a ? (const char *) a->data : (const char *) b->data) + i * esz,
                esz);
    }
    return bv_take_handle (a->type, a->len, data, hvar, "where");
}

#define BVEC_FILE_MAGIC_V1 "BASHVEC1"
#define BVEC_FILE_MAGIC_V2 "BASHVEC2"
#define BVEC_FILE_VERSION 2u
#define BVEC_ENDIAN_LE 0u
#define BVEC_ENDIAN_BE 1u

static void
bv_bswap_cells (enum bvec_type type, void *data, size_t len)
{
    size_t esz = bv_type_size (type);
    for (size_t i = 0; i < len; i++) {
        unsigned char *p = (unsigned char *) data + i * esz;
        if (esz == 4) {
            uint32_t x;
            memcpy (&x, p, sizeof x);
            x = bv_bswap32 (x);
            memcpy (p, &x, sizeof x);
        } else if (esz == 8) {
            uint64_t x;
            memcpy (&x, p, sizeof x);
            x = bv_bswap64 (x);
            memcpy (p, &x, sizeof x);
        }
    }
}

static int
bv_save_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("save: H PATH"); return EX_USAGE; }
    bvec_t *v = bv_get (args->word->word);
    const char *path = args->next->word->word;
    if (!v) { builtin_error ("save: bad handle"); return EX_USAGE; }
    FILE *fp = fopen (path, "wb");
    if (!fp) { builtin_error ("save: %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
    uint32_t type = (uint32_t) v->type;
    uint64_t len = (uint64_t) v->len;
    unsigned char version = BVEC_FILE_VERSION;
    unsigned char endian = bv_host_is_be () ? BVEC_ENDIAN_BE : BVEC_ENDIAN_LE;
    size_t esz = bv_type_size (v->type);
    int ok = fwrite (BVEC_FILE_MAGIC_V2, 1, 8, fp) == 8 &&
             fwrite (&version, 1, 1, fp) == 1 &&
             fwrite (&endian, 1, 1, fp) == 1 &&
             fwrite (&type, sizeof type, 1, fp) == 1 &&
             fwrite (&len, sizeof len, 1, fp) == 1 &&
             fwrite (v->data, esz, v->len, fp) == v->len;
    if (fclose (fp) != 0) ok = 0;
    if (!ok) { builtin_error ("save: write failed"); return EXECUTION_FAILURE; }
    return EXECUTION_SUCCESS;
}

static int
bv_load_cmd (WORD_LIST *args)
{
    const char *hvar = NULL;
    if (!args) { builtin_error ("load: PATH [-h H_VAR]"); return EX_USAGE; }
    const char *path = args->word->word;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-h") && p->next) { hvar = p->next->word->word; p = p->next; }
        else { builtin_error ("load: unexpected '%s'", w); return EX_USAGE; }
    }
    FILE *fp = fopen (path, "rb");
    if (!fp) { builtin_error ("load: %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
    char magic[8];
    uint32_t raw_type;
    uint64_t raw_len;
    int swap = 0;
    if (fread (magic, 1, 8, fp) != 8) {
        fclose (fp);
        builtin_error ("load: bad vec file");
        return EX_USAGE;
    }
    if (memcmp (magic, BVEC_FILE_MAGIC_V1, 8) == 0) {
        if (fread (&raw_type, sizeof raw_type, 1, fp) != 1 ||
            fread (&raw_len, sizeof raw_len, 1, fp) != 1) {
            fclose (fp);
            builtin_error ("load: bad vec file");
            return EX_USAGE;
        }
    } else if (memcmp (magic, BVEC_FILE_MAGIC_V2, 8) == 0) {
        unsigned char version = 0, endian = 0;
        if (fread (&version, 1, 1, fp) != 1 ||
            fread (&endian, 1, 1, fp) != 1 ||
            version != BVEC_FILE_VERSION ||
            (endian != BVEC_ENDIAN_LE && endian != BVEC_ENDIAN_BE) ||
            fread (&raw_type, sizeof raw_type, 1, fp) != 1 ||
            fread (&raw_len, sizeof raw_len, 1, fp) != 1) {
            fclose (fp);
            builtin_error ("load: bad vec file");
            return EX_USAGE;
        }
        swap = ((endian == BVEC_ENDIAN_BE) != bv_host_is_be ());
        if (swap) {
            raw_type = bv_bswap32 (raw_type);
            raw_len = bv_bswap64 (raw_len);
        }
    } else {
        fclose (fp);
        builtin_error ("load: bad vec file");
        return EX_USAGE;
    }
    if (raw_type >= BVEC_TYPE_COUNT || raw_len > SIZE_MAX) {
        fclose (fp);
        builtin_error ("load: bad vec file");
        return EX_USAGE;
    }
    enum bvec_type type = (enum bvec_type) raw_type;
    size_t len = (size_t) raw_len, esz = bv_type_size (type);
    void *data = bv_aligned_zalloc (len, type);
    if (!data) { fclose (fp); builtin_error ("load: dimension too large"); return EXECUTION_FAILURE; }
    if (fread (data, esz, len, fp) != len) {
        free (data);
        fclose (fp);
        builtin_error ("load: truncated data");
        return EX_USAGE;
    }
    fclose (fp);
    if (swap)
        bv_bswap_cells (type, data, len);
    if (bv_validate_finite_cells (type, data, len, "load") != 0) {
        free (data);
        return EX_USAGE;
    }
    return bv_take_handle (type, len, data, hvar, "load");
}

static int
bv_from_array_cmd (WORD_LIST *args)
{
    const char *type_str = NULL, *name = NULL, *hvar = NULL;
    enum bvec_type type;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-T") && p->next) { type_str = p->next->word->word; p = p->next; }
        else if (!strcmp (w, "-h") && p->next) { hvar = p->next->word->word; p = p->next; }
        else if (!name) name = w;
        else { builtin_error ("from-array: unexpected '%s'", w); return EX_USAGE; }
    }
    if (!type_str || !name) { builtin_error ("from-array: -T TYPE NAME [-h H_VAR]"); return EX_USAGE; }
    if (bv_parse_type (type_str, &type) != 0) { builtin_error ("from-array: unknown type '%s'", type_str); return EX_USAGE; }
    SHELL_VAR *var = find_variable ((char *) name);
    if (!var || array_p (var) == 0) { builtin_error ("from-array: %s is not an indexed array", name); return EX_USAGE; }
    ARRAY *arr = array_cell (var);
    size_t len = (size_t) array_num_elements (arr);
    void *data = bv_aligned_zalloc (len, type);
    if (!data) { builtin_error ("from-array: allocation failed"); return EXECUTION_FAILURE; }
    size_t esz = bv_type_size (type);
    for (size_t i = 0; i < len; i++) {
        char *s = array_reference (arr, (arrayind_t) i);
        if (!s || bv_parse_value (type, s, (char *) data + i * esz) != 0) {
            free (data);
            builtin_error ("from-array: cannot parse %s[%zu] as %s", name, i, bv_type_names[type]);
            return EX_USAGE;
        }
    }
    return bv_take_handle (type, len, data, hvar, "from-array");
}

static int
bv_to_array_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("to-array: H NAME"); return EX_USAGE; }
    bvec_t *v = bv_get (args->word->word);
    const char *name = args->next->word->word;
    if (!v) { builtin_error ("to-array: bad handle"); return EX_USAGE; }
    if (!valid_identifier ((char *) name)) { sh_invalidid ((char *) name); return EX_USAGE; }
    unbind_variable ((char *) name);
    SHELL_VAR *var = find_or_make_array_variable ((char *) name, 1);
    if (!var) return EXECUTION_FAILURE;
    ARRAY *arr = array_cell (var);
    size_t esz = bv_type_size (v->type);
    for (size_t i = 0; i < v->len; i++) {
        char buf[64];
        bv_cell_to_string (v->type, (const char *) v->data + i * esz, buf, sizeof buf);
        array_insert (arr, (arrayind_t) i, buf);
    }
    return EXECUTION_SUCCESS;
}

/* ===== NumPy .npy interchange (1-D, C-order, fixed-width numeric only) =====
 * BASHVEC2 stays the native format. .npy is bounded import/export for simple
 * one-dimensional i32/i64/u32/u64/f32/f64 arrays. Out of scope (fail-closed):
 * .npz, mmap, multidim/Fortran order, object/string/struct/unicode dtypes.
 */
#define BVEC_NPY_HDR_MAX 65535u   /* bound the header before any allocation */

static const char *bv_npy_typecode (enum bvec_type t)
{
    switch (t) {
    case BVEC_I32: return "i4"; case BVEC_I64: return "i8";
    case BVEC_U32: return "u4"; case BVEC_U64: return "u8";
    case BVEC_F32: return "f4"; case BVEC_F64: return "f8";
    default: return NULL;
    }
}

/* parse a numpy descr ('<i4','>f8','=i8','i4') -> type + big-endian flag.
   Returns 0 on a supported dtype, -1 (fail-closed) on anything else. */
static int bv_npy_parse_descr (const char *d, enum bvec_type *out, int *is_be)
{
    if (!d || !d[0]) return -1;
    int be;
    const char *p = d;
    switch (p[0]) {
    case '<': be = 0; p++; break;
    case '>': be = 1; p++; break;
    case '=': be = bv_host_is_be (); p++; break;
    case '|': return -1;                       /* 1-byte/na — unsupported */
    default:  be = bv_host_is_be (); break;     /* no prefix -> native */
    }
    if (strlen (p) != 2) return -1;             /* exactly kind+size, no trailing */
    enum bvec_type t;
    if      (!strcmp (p, "i4")) t = BVEC_I32;
    else if (!strcmp (p, "i8")) t = BVEC_I64;
    else if (!strcmp (p, "u4")) t = BVEC_U32;
    else if (!strcmp (p, "u8")) t = BVEC_U64;
    else if (!strcmp (p, "f4")) t = BVEC_F32;
    else if (!strcmp (p, "f8")) t = BVEC_F64;
    else return -1;
    *out = t; *is_be = be;
    return 0;
}

/* locate "'key'" then the following ':' and return a pointer past spaces. */
static const char *bv_npy_after_key (const char *hdr, const char *key)
{
    const char *k = strstr (hdr, key);
    if (!k) return NULL;
    k = strchr (k + strlen (key), ':');
    if (!k) return NULL;
    k++;
    while (*k == ' ') k++;
    return k;
}

static int
bv_export_npy_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("export-npy: H PATH"); return EX_USAGE; }
    bvec_t *v = bv_get (args->word->word);
    const char *path = args->next->word->word;
    if (!v) { builtin_error ("export-npy: bad handle"); return EX_USAGE; }
    const char *tc = bv_npy_typecode (v->type);
    if (!tc) { builtin_error ("export-npy: unsupported dtype"); return EX_USAGE; }
    size_t esz = bv_type_size (v->type);

    /* deterministic little-endian descr; stable key order */
    char dict[96];
    int dn = snprintf (dict, sizeof dict,
                       "{'descr': '<%s', 'fortran_order': False, 'shape': (%zu,), }",
                       tc, v->len);
    if (dn < 0 || (size_t) dn >= sizeof dict) { builtin_error ("export-npy: header"); return EXECUTION_FAILURE; }
    /* pad with spaces + trailing '\n' so (10 + headerlen) % 64 == 0 (v1.0) */
    size_t base = (size_t) dn + 1;             /* dict + '\n' */
    size_t pad = (64 - ((10 + base) % 64)) % 64;
    size_t headerlen = base + pad;             /* dict + pad spaces + '\n' */
    if (headerlen > 0xffff) { builtin_error ("export-npy: header too large"); return EXECUTION_FAILURE; }

    FILE *fp = fopen (path, "wb");
    if (!fp) { builtin_error ("export-npy: %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
    unsigned char ver[2] = { 1, 0 };
    unsigned char hl[2] = { (unsigned char) (headerlen & 0xff), (unsigned char) ((headerlen >> 8) & 0xff) };
    int ok = fwrite ("\x93NUMPY", 1, 6, fp) == 6 &&
             fwrite (ver, 1, 2, fp) == 2 &&
             fwrite (hl, 1, 2, fp) == 2 &&
             fwrite (dict, 1, (size_t) dn, fp) == (size_t) dn;
    for (size_t i = 0; ok && i < pad; i++) ok = (fputc (' ', fp) != EOF);
    if (ok) ok = (fputc ('\n', fp) != EOF);
    if (ok) {
        if (bv_host_is_be () && v->len) {       /* export LE: byteswap a copy */
            void *tmp = malloc (v->len * esz);
            if (!tmp) ok = 0;
            else { memcpy (tmp, v->data, v->len * esz); bv_bswap_cells (v->type, tmp, v->len);
                   ok = (fwrite (tmp, esz, v->len, fp) == v->len); free (tmp); }
        } else {
            ok = (v->len == 0) || (fwrite (v->data, esz, v->len, fp) == v->len);
        }
    }
    if (fclose (fp) != 0) ok = 0;
    if (!ok) { builtin_error ("export-npy: write failed"); return EXECUTION_FAILURE; }
    return EXECUTION_SUCCESS;
}

static int
bv_import_npy_cmd (WORD_LIST *args)
{
    const char *hvar = NULL;
    if (!args) { builtin_error ("import-npy: PATH [-h H_VAR]"); return EX_USAGE; }
    const char *path = args->word->word;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-h") && p->next) { hvar = p->next->word->word; p = p->next; }
        else { builtin_error ("import-npy: unexpected '%s'", w); return EX_USAGE; }
    }
    FILE *fp = fopen (path, "rb");
    if (!fp) { builtin_error ("import-npy: %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }

    unsigned char magic[6], ver[2];
    if (fread (magic, 1, 6, fp) != 6 || memcmp (magic, "\x93NUMPY", 6) != 0 ||
        fread (ver, 1, 2, fp) != 2) {
        fclose (fp); builtin_error ("import-npy: bad .npy magic"); return EX_USAGE;
    }
    unsigned long headerlen;
    if (ver[0] == 1 && ver[1] == 0) {
        unsigned char b[2];
        if (fread (b, 1, 2, fp) != 2) { fclose (fp); builtin_error ("import-npy: bad header len"); return EX_USAGE; }
        headerlen = (unsigned long) b[0] | ((unsigned long) b[1] << 8);
    } else if (ver[0] == 2 && ver[1] == 0) {
        unsigned char b[4];
        if (fread (b, 1, 4, fp) != 4) { fclose (fp); builtin_error ("import-npy: bad header len"); return EX_USAGE; }
        headerlen = (unsigned long) b[0] | ((unsigned long) b[1] << 8) |
                    ((unsigned long) b[2] << 16) | ((unsigned long) b[3] << 24);
    } else {
        fclose (fp); builtin_error ("import-npy: unsupported .npy version %u.%u", ver[0], ver[1]); return EX_USAGE;
    }
    if (headerlen == 0 || headerlen > BVEC_NPY_HDR_MAX) {
        fclose (fp); builtin_error ("import-npy: header size out of bounds"); return EX_USAGE;
    }
    char *hdr = malloc (headerlen + 1);
    if (!hdr) { fclose (fp); builtin_error ("import-npy: oom"); return EXECUTION_FAILURE; }
    if (fread (hdr, 1, headerlen, fp) != headerlen) {
        free (hdr); fclose (fp); builtin_error ("import-npy: truncated header"); return EX_USAGE;
    }
    hdr[headerlen] = '\0';

    /* narrow header parse: fortran_order / descr / shape (no Python eval) */
    enum bvec_type type; int is_be = 0;
    const char *q = bv_npy_after_key (hdr, "'fortran_order'");
    if (!q || strncmp (q, "False", 5) != 0) {
        free (hdr); fclose (fp); builtin_error ("import-npy: only C-order (fortran_order False) supported"); return EX_USAGE;
    }
    q = bv_npy_after_key (hdr, "'descr'");
    if (!q || *q != '\'') { free (hdr); fclose (fp); builtin_error ("import-npy: missing descr"); return EX_USAGE; }
    q++;
    char descr[16]; size_t dk = 0;
    while (*q && *q != '\'' && dk < sizeof descr - 1) descr[dk++] = *q++;
    if (*q != '\'') { free (hdr); fclose (fp); builtin_error ("import-npy: bad descr"); return EX_USAGE; }
    descr[dk] = '\0';
    if (bv_npy_parse_descr (descr, &type, &is_be) != 0) {
        free (hdr); fclose (fp); builtin_error ("import-npy: unsupported dtype '%s'", descr); return EX_USAGE;
    }
    q = bv_npy_after_key (hdr, "'shape'");
    if (!q || *q != '(') { free (hdr); fclose (fp); builtin_error ("import-npy: missing shape"); return EX_USAGE; }
    q++; while (*q == ' ') q++;
    if (*q == ')') { free (hdr); fclose (fp); builtin_error ("import-npy: 0-d shape unsupported"); return EX_USAGE; }
    errno = 0; char *end; unsigned long long n = strtoull (q, &end, 10);
    if (end == q || errno) { free (hdr); fclose (fp); builtin_error ("import-npy: bad shape"); return EX_USAGE; }
    q = end; while (*q == ' ') q++;
    if (*q != ',') { free (hdr); fclose (fp); builtin_error ("import-npy: only 1-D shape supported"); return EX_USAGE; }
    q++; while (*q == ' ') q++;
    if (*q != ')') { free (hdr); fclose (fp); builtin_error ("import-npy: only 1-D shape supported"); return EX_USAGE; }
    free (hdr);

    size_t esz = bv_type_size (type);
    if (n != 0 && n > BVEC_MAX_BYTES / esz) { fclose (fp); builtin_error ("import-npy: array too large"); return EX_USAGE; }
    size_t count = (size_t) n;

    void *data = bv_aligned_zalloc (count, type);
    if (!data) { fclose (fp); builtin_error ("import-npy: empty or oversized array"); return EX_USAGE; }
    if (fread (data, esz, count, fp) != count) {
        free (data); fclose (fp); builtin_error ("import-npy: truncated payload"); return EX_USAGE;
    }
    if (fgetc (fp) != EOF) {   /* exact file-size match: no trailing bytes */
        free (data); fclose (fp); builtin_error ("import-npy: trailing bytes after payload"); return EX_USAGE;
    }
    fclose (fp);
    if (is_be != bv_host_is_be ()) bv_bswap_cells (type, data, count);
    if (bv_validate_finite_cells (type, data, count, "import-npy") != 0) {
        free (data); return EX_USAGE;
    }
    return bv_take_handle (type, count, data, hvar, "import-npy");
}

int
vec_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "new"))   return bv_new_cmd   (args);
    if (!strcmp (cmd, "free"))  return bv_free_cmd  (args);
    if (!strcmp (cmd, "len"))   return bv_len_cmd   (args);
    if (!strcmp (cmd, "type"))  return bv_type_cmd  (args);
    if (!strcmp (cmd, "backend")) return bv_backend_cmd (args);
    if (!strcmp (cmd, "set"))   return bv_set_cmd   (args);
    if (!strcmp (cmd, "get"))   return bv_get_cmd   (args);
    if (!strcmp (cmd, "fill"))  return bv_fill_cmd  (args);
    if (!strcmp (cmd, "from-array")) return bv_from_array_cmd (args);
    if (!strcmp (cmd, "to-array")) return bv_to_array_cmd (args);
    if (!strcmp (cmd, "sum"))   return bv_sum_cmd   (args);
    if (!strcmp (cmd, "mean"))  return bv_mean_cmd  (args);
    if (!strcmp (cmd, "var"))   return bv_var_cmd   (args);
    if (!strcmp (cmd, "std"))   return bv_std_cmd   (args);
    if (!strcmp (cmd, "min"))   return bv_min_cmd   (args);
    if (!strcmp (cmd, "max"))   return bv_max_cmd   (args);
    if (!strcmp (cmd, "count-nonzero")) return bv_count_nonzero_cmd (args);
    if (!strcmp (cmd, "any"))   return bv_anyall_cmd ("any", args, 0);
    if (!strcmp (cmd, "all"))   return bv_anyall_cmd ("all", args, 1);
    if (!strcmp (cmd, "copy"))  return bv_copy_cmd  (args);
    if (!strcmp (cmd, "slice")) return bv_slice_cmd (args);
    if (!strcmp (cmd, "add"))   return bv_add_cmd   (args);
    if (!strcmp (cmd, "sub"))   return bv_sub_cmd   (args);
    if (!strcmp (cmd, "mul"))   return bv_mul_cmd   (args);
    if (!strcmp (cmd, "div"))   return bv_div_cmd   (args);
    if (!strcmp (cmd, "mod"))   return bv_mod_cmd   (args);
    if (!strcmp (cmd, "promote")) return bv_promote_cmd (args);
    if (!strcmp (cmd, "scale")) return bv_scale_cmd (args);
    if (!strcmp (cmd, "axpy"))  return bv_axpy_cmd  (args);
    if (!strcmp (cmd, "dot"))   return bv_dot_cmd   (args);
    if (!strcmp (cmd, "cmp"))   return bv_cmp_cmd   (args);
    if (!strcmp (cmd, "where")) return bv_where_cmd (args);
    if (!strcmp (cmd, "save"))  return bv_save_cmd  (args);
    if (!strcmp (cmd, "load"))  return bv_load_cmd  (args);
    if (!strcmp (cmd, "export-npy")) return bv_export_npy_cmd (args);
    if (!strcmp (cmd, "import-npy")) return bv_import_npy_cmd (args);
    if (!strcmp (cmd, "convert")) return bv_convert_cmd (args);
    builtin_error ("unknown verb: %s "
                   "(try new/free/len/type/backend/set/get/fill/from-array/to-array/sum/mean/var/std/min/max/"
                   "count-nonzero/any/all/copy/slice/add/sub/mul/div/mod/promote/scale/axpy/dot/cmp/where/"
                   "save/load/export-npy/import-npy/convert)", cmd);
    return EX_USAGE;
}

char *vec_doc[] = {
    "Typed dense numeric arrays + scalar reductions/ops.",
    "",
    "    vec new -T TYPE -N LEN [-h H_VAR]   types: i32/i64/u32/u64/f32/f64",
    "    vec free H",
    "    vec set H IDX VAL                   one-cell write",
    "    vec get H IDX                       one-cell read (decimal)",
    "    vec len H                           element count",
    "    vec type H                          type name",
    "    vec backend                         selected backend: avx2/sse2/scalar",
    "    vec fill H VAL                      broadcast",
    "    vec from-array -T TYPE NAME [-h H]  import indexed bash array",
    "    vec to-array H NAME                 export indexed bash array",
    "    vec sum|mean|var|std|min|max H      scalar reduction",
    "    vec count-nonzero|any|all H         predicates",
    "    vec copy SRC [-h H]                 copy vector",
    "    vec slice SRC START LEN [-h H]      copy range",
    "    vec add|sub|mul|div|mod A B         in-place mixed numeric op",
    "    vec promote A B OP -T TYPE [-h H]   new vector, OP add/sub/mul/div/mod",
    "    vec scale H S                       in-place A[i] *= S",
    "    vec axpy A X Y                      in-place Y[i] += A * X[i]",
    "    vec dot A B                         dot product",
    "    vec cmp A B OP [-h H]               u32 mask: eq/ne/lt/le/gt/ge",
    "    vec where MASK A B [-h H]           select cells by mask",
    "    vec save H PATH | load PATH [-h H]  binary persistence",
    "    vec export-npy H PATH                NumPy .npy (1-D, C-order)",
    "    vec import-npy PATH [-h H_VAR]       import .npy (i/u/f 4/8 only)",
    "    vec convert SRC -T TYPE [-h H_VAR]  checked copy to new type",
    "",
    "save writes BASHVEC2 with version and endian marker; load accepts",
    "BASHVEC1 legacy native files and BASHVEC2 cross-endian files.",
    "Scalar loops are the correctness backend; selected reductions use",
    "SSE2/AVX2 when compile/runtime gates allow, with scalar fallback.",
    (char *)NULL
};

struct builtin vec_struct = {
    "vec",
    vec_builtin,
    BUILTIN_ENABLED,
    vec_doc,
    "vec new|free|len|type|backend|set|get|fill|from-array|to-array|sum|mean|var|std|min|max|count-nonzero|any|all|copy|slice|add|sub|mul|div|mod|promote|scale|axpy|dot|cmp|where|save|load|export-npy|import-npy|convert ARGS",
    0
};
