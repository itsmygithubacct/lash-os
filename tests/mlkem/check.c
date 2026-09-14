/* Deterministic test inputs only: compare the complete ML-KEM round trip. */
#include <stdint.h>
#include <string.h>
#include "_libssh_mlkem_native.h"

/* Clang uses an i65 intermediate for signed inputs and an unsigned result. */
__attribute__((noinline)) static int checked_multiply(uint64_t *out, int32_t a, int32_t b) {
    uint64_t product;
    int overflow = __builtin_mul_overflow(a, b, &product);
    if (!overflow) *out = product;
    return overflow;
}
static volatile int32_t multiply_inputs[][2] = {
    {0, INT32_MIN}, {-1, 1}, {-1, -1}, {INT32_MIN, -1},
    {INT32_MIN, INT32_MIN}, {INT32_MAX, INT32_MAX}, {INT32_MIN, INT32_MAX}
};
static int checked_integer_cases(void) {
    const uint64_t expected[] = {
        0, UINT64_MAX, 1, UINT64_C(2147483648),
        UINT64_C(4611686018427387904), UINT64_C(4611686014132420609), UINT64_MAX
    };
    const int overflow[] = {0, 1, 0, 0, 0, 0, 1};
    for (unsigned i = 0; i < sizeof(expected)/sizeof(expected[0]); ++i) {
        uint64_t value = UINT64_MAX;
        if (checked_multiply(&value, multiply_inputs[i][0], multiply_inputs[i][1]) != overflow[i] ||
            value != expected[i]) return 4;
    }
    return 0;
}

static uint64_t fingerprint(const void *data, size_t size, uint64_t hash) {
    const unsigned char *p = data;
    while (size--) { hash ^= *p++; hash *= UINT64_C(1099511628211); }
    return hash;
}
int mlkem_check(uint64_t *digest) {
    if (checked_integer_cases()) return 4;
    uint8_t seed[64], coins[32], recovered[32];
    for (unsigned i = 0; i < sizeof(seed); ++i) seed[i] = i;
    for (unsigned i = 0; i < sizeof(coins); ++i) coins[i] = 127-i;
    libcrux_ml_kem_mlkem768_MlKem768KeyPair pair =
        libcrux_ml_kem_mlkem768_portable_generate_key_pair(seed);
    if (!libcrux_ml_kem_mlkem768_portable_validate_public_key(&pair.pk)) return 2;
    tuple_c2 encapsulated = libcrux_ml_kem_mlkem768_portable_encapsulate(&pair.pk, coins);
    libcrux_ml_kem_mlkem768_portable_decapsulate(&pair.sk, &encapsulated.fst, recovered);
    if (memcmp(recovered, encapsulated.snd, sizeof(recovered))) return 3;
    uint64_t h = fingerprint(pair.pk.value, sizeof(pair.pk.value), UINT64_C(14695981039346656037));
    h = fingerprint(encapsulated.fst.value, sizeof(encapsulated.fst.value), h);
    *digest = fingerprint(recovered, sizeof(recovered), h);
    return 0;
}
