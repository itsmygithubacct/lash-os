#include "asn1.h"
#include <string.h>

int mbedtls_asn1_get_mpi_bytes(unsigned char **p, const unsigned char *end,
                               const unsigned char **out_p, size_t *out_len)
{
    size_t len;
    int ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_INTEGER);
    if (ret != 0) return ret;
    if (len == 0) return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    if ((**p & 0x80) != 0) return MBEDTLS_ERR_ASN1_INVALID_DATA;
    if (len > 1 && **p == 0) { (*p)++; len--; }
    *out_p = *p;
    *out_len = len;
    *p += len;
    return 0;
}


int mbedtls_asn1_get_oid(unsigned char **p, const unsigned char *end,
                         mbedtls_asn1_buf *out)
{
    int ret = mbedtls_asn1_get_tag(p, end, &out->len, MBEDTLS_ASN1_OID);
    if (ret != 0) return ret;
    out->tag = MBEDTLS_ASN1_OID;
    out->p = *p;
    *p += out->len;
    return 0;
}

int mbedtls_asn1_get_null(unsigned char **p, const unsigned char *end)
{
    size_t len;
    int ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_NULL);
    if (ret != 0) return ret;
    return len == 0 ? 0 : MBEDTLS_ERR_ASN1_INVALID_LENGTH;
}

int mbedtls_asn1_get_bit_string(unsigned char **p, const unsigned char *end,
                                mbedtls_asn1_buf *out, int *unused_bits)
{
    mbedtls_asn1_bitstring bs;
    int ret = mbedtls_asn1_get_bitstring(p, end, &bs);
    if (ret != 0) return ret;
    out->tag = MBEDTLS_ASN1_BIT_STRING;
    out->p = bs.p;
    out->len = bs.len;
    if (unused_bits) *unused_bits = bs.unused_bits;
    return 0;
}

int mbedtls_asn1_oid_eq(const mbedtls_asn1_buf *a, const unsigned char *b, size_t blen)
{
    if (a->len != blen) return 1;
    return memcmp(a->p, b, blen);
}
