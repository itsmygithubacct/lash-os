/* _mbedtls/ecdsa_p256.c — compact P-256 ECDSA facade. */
#include "ecdsa_p256.h"
#include "p256-m.h"
#include <string.h>

static void
wipe(unsigned char *buf, size_t len)
{
    volatile unsigned char *p = buf;
    while (len--) *p++ = 0;
}

int
mbedtls_ecdsa_p256_keygen(unsigned char sk[32])
{
    unsigned char pub[64];
    int ret = p256_gen_keypair(sk, pub);
    wipe(pub, sizeof pub);
    return ret == P256_SUCCESS ? 0 : -1;
}

int
mbedtls_ecdsa_p256_public(unsigned char pk65[65], const unsigned char sk[32])
{
    unsigned char pub[64];
    int ret = p256_public_from_private(pub, sk);
    if (ret != P256_SUCCESS) return -1;
    pk65[0] = 0x04;
    memcpy(pk65 + 1, pub, sizeof pub);
    return 0;
}

int
mbedtls_ecdsa_p256_sign_raw(unsigned char sig64[64],
                            const unsigned char sk[32],
                            const unsigned char *digest, size_t digest_len)
{
    int ret = p256_ecdsa_sign(sig64, sk, digest, digest_len);
    return ret == P256_SUCCESS ? 0 : -1;
}

int
mbedtls_ecdsa_p256_verify_raw(const unsigned char pk65[65],
                              const unsigned char sig64[64],
                              const unsigned char *digest, size_t digest_len)
{
    if (pk65[0] != 0x04) return -1;
    int ret = p256_ecdsa_verify(sig64, pk65 + 1, digest, digest_len);
    return ret == P256_SUCCESS ? 0 : -1;
}
