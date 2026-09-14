/* _mbedtls/x25519.c — Curve25519 X25519 (Stage 19.B primitive #4).
 *
 * Self-contained reference implementation. Field representation:
 * 5 × uint64_t limbs in radix 2^51 (each limb ≤ 2^52 between
 * reductions; full reduction collapses to canonical 256-bit form).
 *
 * Algorithms:
 *   - fmul: 5x5 schoolbook with the 19-folding reduction (each
 *     coefficient at i ≥ 5 contributes via 19 × c into limb (i - 5))
 *   - fsq: optimized squaring with the doubled cross-terms folded in
 *   - finvert: z^(p-2) via the standard 11-multiplication addition
 *     chain from supercop's ref10 (Bernstein/Lange)
 *   - Montgomery ladder (RFC 7748 §5): 255 iterations, constant-time
 *     cswap on the bit
 *
 * Cross-check: bashcrypto x25519-shared-mbedtls against RFC 7748 §6.1
 * vector + a fresh keypair round-trip.
 *
 * SPDX-License-Identifier: MIT
 */
#include "x25519.h"
#include <stdint.h>
#include <string.h>

typedef uint64_t fe[5];

#define MASK51  ((uint64_t) ((1ULL << 51) - 1))

/* Decode 32-byte little-endian as 5 × 51-bit limbs. The high bit of
 * the input is masked off per RFC 7748 §5 (X25519 uses only 255 bits
 * of the encoded u-coordinate). */
static void fe_frombytes(fe h, const unsigned char s[32])
{
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0;
    for (int i = 0; i < 8; i++) {
        t0 |= ((uint64_t) s[i      ]) << (8 * i);
        t1 |= ((uint64_t) s[i +  8]) << (8 * i);
        t2 |= ((uint64_t) s[i + 16]) << (8 * i);
        t3 |= ((uint64_t) s[i + 24]) << (8 * i);
    }
    t3 &= 0x7FFFFFFFFFFFFFFFULL;   /* clear bit 255 */
    h[0] =  t0                              & MASK51;
    h[1] = (t0 >> 51 | t1 << 13)            & MASK51;
    h[2] = (t1 >> 38 | t2 << 26)            & MASK51;
    h[3] = (t2 >> 25 | t3 << 39)            & MASK51;
    h[4] =  t3 >> 12;
}

/* Encode field element to 32-byte little-endian, fully reduced. */
static void fe_tobytes(unsigned char s[32], const fe h)
{
    /* Carry-propagate so each limb is canonical, then add 19 to test
       if h ≥ p; if so subtract p, else keep. */
    uint64_t t[5];
    for (int i = 0; i < 5; i++) t[i] = h[i];

    uint64_t carry;
    for (int round = 0; round < 2; round++) {
        carry = t[0] >> 51; t[0] &= MASK51; t[1] += carry;
        carry = t[1] >> 51; t[1] &= MASK51; t[2] += carry;
        carry = t[2] >> 51; t[2] &= MASK51; t[3] += carry;
        carry = t[3] >> 51; t[3] &= MASK51; t[4] += carry;
        carry = t[4] >> 51; t[4] &= MASK51; t[0] += 19 * carry;
    }

    /* Conditional subtract of p = 2^255 - 19. Add 19 + 2^255 then
       carry — if result fits, subtract failed (h < p), so keep
       original; else use shifted-out result. */
    uint64_t u[5];
    u[0] = t[0] + 19;
    u[1] = t[1] + (u[0] >> 51); u[0] &= MASK51;
    u[2] = t[2] + (u[1] >> 51); u[1] &= MASK51;
    u[3] = t[3] + (u[2] >> 51); u[2] &= MASK51;
    u[4] = t[4] + (u[3] >> 51); u[3] &= MASK51;
    /* If u[4] has bit 255 set, then h + 19 ≥ 2^255 so h ≥ p — use u
       (which is h - p mod 2^255). Else use t. */
    if (u[4] & (1ULL << 51)) {
        u[4] &= MASK51;
        for (int i = 0; i < 5; i++) t[i] = u[i];
    }

    /* Pack 5 × 51-bit limbs into 32 bytes little-endian. */
    uint64_t o0 = (t[0]      ) | (t[1] << 51);
    uint64_t o1 = (t[1] >> 13) | (t[2] << 38);
    uint64_t o2 = (t[2] >> 26) | (t[3] << 25);
    uint64_t o3 = (t[3] >> 39) | (t[4] << 12);
    for (int i = 0; i < 8; i++) s[i      ] = (unsigned char) (o0 >> (8 * i));
    for (int i = 0; i < 8; i++) s[i +  8] = (unsigned char) (o1 >> (8 * i));
    for (int i = 0; i < 8; i++) s[i + 16] = (unsigned char) (o2 >> (8 * i));
    for (int i = 0; i < 8; i++) s[i + 24] = (unsigned char) (o3 >> (8 * i));
}

static void fe_copy(fe h, const fe f) { for (int i = 0; i < 5; i++) h[i] = f[i]; }

static void fe_0(fe h)
{
    h[0] = h[1] = h[2] = h[3] = h[4] = 0;
}

static void fe_1(fe h)
{
    h[0] = 1; h[1] = h[2] = h[3] = h[4] = 0;
}

/* Constant-time conditional swap: if b == 1, swap f and g. */
static void fe_cswap(fe f, fe g, unsigned int b)
{
    uint64_t mask = (uint64_t) (-(int64_t) (b & 1));
    for (int i = 0; i < 5; i++) {
        uint64_t x = mask & (f[i] ^ g[i]);
        f[i] ^= x;
        g[i] ^= x;
    }
}

static void fe_add(fe h, const fe f, const fe g)
{
    for (int i = 0; i < 5; i++) h[i] = f[i] + g[i];
}

/* h = f - g. Add 2*p to f first to keep all limbs positive.
 * 2*p limbs (in radix 2^51): [0xFFFFFFFFFFFDA, 0xFFFFFFFFFFFFE × 4]. */
static void fe_sub(fe h, const fe f, const fe g)
{
    h[0] = f[0] + 0xFFFFFFFFFFFDAULL - g[0];
    h[1] = f[1] + 0xFFFFFFFFFFFFEULL - g[1];
    h[2] = f[2] + 0xFFFFFFFFFFFFEULL - g[2];
    h[3] = f[3] + 0xFFFFFFFFFFFFEULL - g[3];
    h[4] = f[4] + 0xFFFFFFFFFFFFEULL - g[4];
}

/* Multiply: h = f · g mod p. Uses uint128 intermediates for the 5x5
 * schoolbook accumulation; the 19-fold reduction folds limbs at
 * positions 5-9 back into 0-4. */
static void fe_mul(fe h, const fe f, const fe g)
{
    __uint128_t r0, r1, r2, r3, r4;
    uint64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    uint64_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];

    /* Pre-multiply g1..g4 by 19 so that limbs at index ≥ 5 fold via
       multiplication by 19 (the curve constant from p = 2^255 - 19). */
    uint64_t g1_19 = 19 * g1;
    uint64_t g2_19 = 19 * g2;
    uint64_t g3_19 = 19 * g3;
    uint64_t g4_19 = 19 * g4;

    r0 = (__uint128_t) f0 * g0
       + (__uint128_t) f1 * g4_19
       + (__uint128_t) f2 * g3_19
       + (__uint128_t) f3 * g2_19
       + (__uint128_t) f4 * g1_19;
    r1 = (__uint128_t) f0 * g1
       + (__uint128_t) f1 * g0
       + (__uint128_t) f2 * g4_19
       + (__uint128_t) f3 * g3_19
       + (__uint128_t) f4 * g2_19;
    r2 = (__uint128_t) f0 * g2
       + (__uint128_t) f1 * g1
       + (__uint128_t) f2 * g0
       + (__uint128_t) f3 * g4_19
       + (__uint128_t) f4 * g3_19;
    r3 = (__uint128_t) f0 * g3
       + (__uint128_t) f1 * g2
       + (__uint128_t) f2 * g1
       + (__uint128_t) f3 * g0
       + (__uint128_t) f4 * g4_19;
    r4 = (__uint128_t) f0 * g4
       + (__uint128_t) f1 * g3
       + (__uint128_t) f2 * g2
       + (__uint128_t) f3 * g1
       + (__uint128_t) f4 * g0;

    /* Carry-propagate. Each limb keeps 51 bits; carry-out goes to next. */
    uint64_t c;
    c = (uint64_t) (r0 >> 51); h[0] = (uint64_t) r0 & MASK51; r1 += c;
    c = (uint64_t) (r1 >> 51); h[1] = (uint64_t) r1 & MASK51; r2 += c;
    c = (uint64_t) (r2 >> 51); h[2] = (uint64_t) r2 & MASK51; r3 += c;
    c = (uint64_t) (r3 >> 51); h[3] = (uint64_t) r3 & MASK51; r4 += c;
    c = (uint64_t) (r4 >> 51); h[4] = (uint64_t) r4 & MASK51; h[0] += 19 * c;
    c = h[0] >> 51;            h[0] &= MASK51;                h[1] += c;
}

/* Square: h = f · f mod p. Could be optimized with 2*cross-term
 * folding but for a reference impl we just call fe_mul. */
static void fe_sq(fe h, const fe f)
{
    fe_mul(h, f, f);
}

/* Multiply by 121665 (the X25519 a24 constant, (a+2)/4 for Montgomery
 * curve y^2 = x^3 + 486662 x^2 + x). */
static void fe_mul_121665(fe h, const fe f)
{
    __uint128_t r0 = (__uint128_t) f[0] * 121665;
    __uint128_t r1 = (__uint128_t) f[1] * 121665;
    __uint128_t r2 = (__uint128_t) f[2] * 121665;
    __uint128_t r3 = (__uint128_t) f[3] * 121665;
    __uint128_t r4 = (__uint128_t) f[4] * 121665;

    uint64_t c;
    c = (uint64_t) (r0 >> 51); h[0] = (uint64_t) r0 & MASK51; r1 += c;
    c = (uint64_t) (r1 >> 51); h[1] = (uint64_t) r1 & MASK51; r2 += c;
    c = (uint64_t) (r2 >> 51); h[2] = (uint64_t) r2 & MASK51; r3 += c;
    c = (uint64_t) (r3 >> 51); h[3] = (uint64_t) r3 & MASK51; r4 += c;
    c = (uint64_t) (r4 >> 51); h[4] = (uint64_t) r4 & MASK51; h[0] += 19 * c;
    c = h[0] >> 51;            h[0] &= MASK51;                h[1] += c;
}

/* Inverse via Fermat: z^(p-2) where p-2 = 2^255 - 21. Standard
 * 254-step addition chain (11 mults + lots of squares). Adapted
 * from supercop ref10 / curve25519-donna. */
static void fe_invert(fe out, const fe z)
{
    fe t0, t1, t2, t3;

    fe_sq(t0, z);
    fe_sq(t1, t0); fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sq(t2, t1); for (int i = 1; i < 5;   i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1); for (int i = 1; i < 10;  i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2); for (int i = 1; i < 20;  i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2); for (int i = 1; i < 10;  i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1); for (int i = 1; i < 50;  i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2); for (int i = 1; i < 100; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2); for (int i = 1; i < 50;  i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1); for (int i = 1; i < 5;   i++) fe_sq(t1, t1);
    fe_mul(out, t1, t0);
}

/* Montgomery ladder for scalar multiplication on Curve25519.
 * Computes [scalar] · point, returning the u-coordinate result. */
static void scalarmult(unsigned char out[32],
                       const unsigned char scalar[32],
                       const unsigned char point[32])
{
    /* Clamp scalar per RFC 7748 §5. */
    unsigned char e[32];
    memcpy(e, scalar, 32);
    e[ 0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    fe x1, x2, z2, x3, z3;
    fe_frombytes(x1, point);
    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    unsigned int swap = 0;
    for (int t = 254; t >= 0; t--) {
        unsigned int b = (e[t / 8] >> (t % 8)) & 1;
        swap ^= b;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;

        /* RFC 7748 §5 ladder step. */
        fe A, AA, B, BB, E, C, D, DA, CB;
        fe_add(A, x2, z2); fe_sq(AA, A);
        fe_sub(B, x2, z2); fe_sq(BB, B);
        fe_sub(E, AA, BB);
        fe_add(C, x3, z3);
        fe_sub(D, x3, z3);
        fe_mul(DA, D, A);
        fe_mul(CB, C, B);
        fe_add(x3, DA, CB); fe_sq(x3, x3);
        fe_sub(z3, DA, CB); fe_sq(z3, z3); fe_mul(z3, z3, x1);
        fe_mul(x2, AA, BB);
        fe_mul_121665(z2, E);
        fe_add(z2, z2, AA);
        fe_mul(z2, E, z2);
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    /* Output = x2 / z2. */
    fe z2inv;
    fe_invert(z2inv, z2);
    fe_mul(x2, x2, z2inv);
    fe_tobytes(out, x2);
}

int mbedtls_x25519(unsigned char shared[32],
                   const unsigned char scalar[32],
                   const unsigned char point[32])
{
    scalarmult(shared, scalar, point);
    return 0;
}

int mbedtls_x25519_base(unsigned char public_key[32],
                        const unsigned char private_key[32])
{
    static const unsigned char base[32] = { 9, 0 };
    scalarmult(public_key, private_key, base);
    return 0;
}
