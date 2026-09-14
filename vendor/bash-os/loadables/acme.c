/* SPDX-License-Identifier: MIT */
/* acme.c — JOSE/JWS + JWK primitives for ACME (RFC 8555).
 *
 * Server-gap slice B from SERVER-GAP-WIREGUARD-ACME-PLAN.md.
 *
 * This loadable holds only the cryptographically-sensitive verbs.
 * The operator-facing ACME state machine (directory, account-create,
 * order, challenge, respond, finalize, issue) lives in
 * rootfs/bash-os/acme.sh, which wires these primitives to
 * curl + json + crypto x509-csr.
 *
 * Verbs:
 *   acme jwk-thumbprint -k SK_HEX
 *       SHA-256(canonical-JSON({crv,kty,x,y}))  base64url-encoded
 *       — RFC 7638 §3 for ES256/P-256.  Used by ACME's keyAuthorization
 *       (RFC 8555 §8.1).
 *
 *   acme key-authorization TOKEN -k SK_HEX
 *       Emit  TOKEN + "." + jwk-thumbprint  (RFC 8555 §8.1).
 *
 *   acme jws-sign -k SK_HEX --url URL --nonce N
 *                     [--kid KID | --jwk] [-d DATA | -f FILE]
 *       Produce the JSON flattened JWS (RFC 7515 §7.2.2 form ACME
 *       uses): {"protected":B64U,"payload":B64U,"signature":B64U}.
 *       --kid sets the protected header `kid` (post-newAccount calls).
 *       --jwk inlines the JWK (used by newAccount + revokeCert).
 *       -d/-f provide the request body; empty for POST-as-GET (ACME
 *       servers expect `"payload":""` for those).
 *
 *   acme jwk-public -k SK_HEX
 *       Emit the JWK JSON for the account key
 *       ({"crv":"P-256","kty":"EC","x":...,"y":...}).
 *
 *   acme jws-extract-key-authorization TOKEN -k SK_HEX
 *       Alias for key-authorization, mirrors the verb name commonly
 *       used in ACME tutorials.
 *
 * Determinism:
 *   jwk-public / jwk-thumbprint / key-authorization / jws-extract-key-authorization
 *     fully deterministic given inputs (byte-identical to RFC 7638 §3 and
 *     RFC 8555 §8.1 reference implementations such as python cryptography
 *     + authlib).
 *   jws-sign
 *     the JOSE framing (protected header + payload) is byte-stable, but the
 *     ECDSA signature varies per call — the underlying signer is
 *     p256-m's `p256_ecdsa_sign` which uses random nonces (NOT RFC 6979
 *     deterministic-ECDSA). Each signature is a valid ECDSA-P256 signature
 *     over SHA-256(protected||"."||payload) and verifies against the
 *     derived public key. RFC 8555 doesn't require determinism, so ACME
 *     interop is unaffected; callers that need byte-stable JWS must hash
 *     or pin the (protected,payload) pair instead of the whole envelope.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>

#include "loadables.h"
#include "_mbedtls_base64.h"
#include "_mbedtls_sha256.h"
#include "_mbedtls_ecdsa_p256.h"

#define BA_KEY_LEN 32
#define BA_PUB_LEN 65   /* uncompressed: 0x04 || X(32) || Y(32) */

/* ----- small helpers, parallel to crypto.c's bc_* helpers ----- */

static int
ba_hexval (unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int
ba_unhex (const char *hex, unsigned char *out, size_t outsz)
{
    size_t o = 0; int hi = -1;
    for (const char *p = hex; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') continue;
        int v = ba_hexval ((unsigned char) *p);
        if (v < 0) return -1;
        if (hi < 0) { hi = v; continue; }
        if (o >= outsz) return -1;
        out[o++] = (unsigned char) ((hi << 4) | v);
        hi = -1;
    }
    if (hi >= 0) return -1;
    return (int) o;
}

static int
ba_write_all (const unsigned char *buf, size_t n)
{
    size_t left = n; const unsigned char *p = buf;
    while (left > 0) {
        ssize_t w = write (STDOUT_FILENO, p, left);
        if (w < 0) { if (errno == EINTR) continue;
                     builtin_error ("write: %s", strerror (errno)); return -1; }
        p += w; left -= (size_t) w;
    }
    return 0;
}

static int
ba_slurp_file (const char *path, unsigned char **out, size_t *out_len)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { builtin_error ("open %s: %s", path, strerror (errno)); return -1; }
    size_t cap = 4096, len = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) { close (fd); builtin_error ("malloc"); return -1; }
    for (;;) {
        if (len == cap) { cap *= 2;
            unsigned char *n = realloc (buf, cap);
            if (!n) { free (buf); close (fd); builtin_error ("realloc"); return -1; }
            buf = n; }
        ssize_t r = read (fd, buf + len, cap - len);
        if (r < 0) { if (errno == EINTR) continue;
                     free (buf); close (fd);
                     builtin_error ("read %s: %s", path, strerror (errno)); return -1; }
        if (r == 0) break;
        len += (size_t) r;
    }
    close (fd);
    *out = buf; *out_len = len;
    return 0;
}

/* Base64URL encode (no padding) — RFC 4648 §5, JOSE convention. */
static int
ba_base64url_encode (const unsigned char *in, size_t inlen, char *out, size_t outsz)
{
    size_t b64_len = 0;
    mbedtls_base64_encode (NULL, 0, &b64_len, in, inlen);
    if (b64_len + 1 > outsz) return -1;
    int rc = mbedtls_base64_encode ((unsigned char *) out, outsz, &b64_len, in, inlen);
    if (rc != 0) return -1;
    out[b64_len] = 0;
    /* +/= → -/_/ (no padding) */
    char *r = out, *w = out;
    while (*r) {
        if (*r == '+') { *w++ = '-'; r++; }
        else if (*r == '/') { *w++ = '_'; r++; }
        else if (*r == '=') { r++; }
        else { *w++ = *r++; }
    }
    *w = 0;
    return (int) (w - out);
}

/* SHA-256 over a buffer; mbedtls streaming with init/update/finish. */
static int
ba_sha256 (const unsigned char *in, size_t inlen, unsigned char out[32])
{
    mbedtls_sha256_context hc;
    mbedtls_sha256_init (&hc);
    int rc = mbedtls_sha256_starts (&hc, 0);
    if (rc == 0) rc = mbedtls_sha256_update (&hc, in, inlen);
    if (rc == 0) rc = mbedtls_sha256_finish (&hc, out);
    mbedtls_sha256_free (&hc);
    return rc;
}

/* Derive ECDSA-P256 public key (X,Y) from a 32-byte private key.
   Output: x[32], y[32] from the uncompressed pub65[0..65]. */
static int
ba_ecdsa_p256_xy (const unsigned char sk[BA_KEY_LEN],
                  unsigned char x[32], unsigned char y[32])
{
    unsigned char pub[BA_PUB_LEN];
    int rc = mbedtls_ecdsa_p256_public (pub, sk);
    if (rc != 0) return rc;
    if (pub[0] != 0x04) return -1;  /* mbedtls always returns uncompressed */
    memcpy (x, pub + 1, 32);
    memcpy (y, pub + 33, 32);
    return 0;
}

/* ----- jwk-public ------------------------------------------------ */

/* Emit the canonical (RFC 7638 §3) JWK JSON to stdout:
       {"crv":"P-256","kty":"EC","x":"…","y":"…"}
   Keys appear in lexicographic order — required for the thumbprint
   hash to be byte-stable.  */
static int
ba_emit_jwk (const unsigned char x[32], const unsigned char y[32])
{
    char xb[64], yb[64];
    if (ba_base64url_encode (x, 32, xb, sizeof xb) < 0) { builtin_error ("jwk: encode x failed"); return -1; }
    if (ba_base64url_encode (y, 32, yb, sizeof yb) < 0) { builtin_error ("jwk: encode y failed"); return -1; }
    printf ("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", xb, yb);
    return 0;
}

static int
ba_jwk_public_cmd (WORD_LIST *args)
{
    const char *sk_hex = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-k")) {
            if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
            p = p->next; sk_hex = p->word->word;
        } else { builtin_error ("jwk-public: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!sk_hex) { builtin_error ("jwk-public: -k SK_HEX required"); return EX_USAGE; }
    unsigned char sk[BA_KEY_LEN], x[32], y[32];
    if (ba_unhex (sk_hex, sk, sizeof sk) != BA_KEY_LEN)
        { builtin_error ("jwk-public: SK must be 32 bytes hex"); return EX_USAGE; }
    if (ba_ecdsa_p256_xy (sk, x, y) != 0)
        { builtin_error ("jwk-public: invalid private key"); return EXECUTION_FAILURE; }
    if (ba_emit_jwk (x, y) < 0) return EXECUTION_FAILURE;
    putchar ('\n');
    return EXECUTION_SUCCESS;
}

/* ----- jwk-thumbprint ------------------------------------------- */

/* Build the same canonical JWK string into `buf` (no trailing NL).
   Returns bytes written (excluding NUL), or -1 on overflow. */
static int
ba_jwk_canonical (char *buf, size_t bufsz,
                  const unsigned char x[32], const unsigned char y[32])
{
    char xb[64], yb[64];
    if (ba_base64url_encode (x, 32, xb, sizeof xb) < 0) return -1;
    if (ba_base64url_encode (y, 32, yb, sizeof yb) < 0) return -1;
    int n = snprintf (buf, bufsz,
                      "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", xb, yb);
    if (n < 0 || (size_t) n >= bufsz) return -1;
    return n;
}

static int
ba_jwk_thumbprint_cmd (WORD_LIST *args)
{
    const char *sk_hex = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-k")) {
            if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
            p = p->next; sk_hex = p->word->word;
        } else { builtin_error ("jwk-thumbprint: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!sk_hex) { builtin_error ("jwk-thumbprint: -k SK_HEX required"); return EX_USAGE; }
    unsigned char sk[BA_KEY_LEN], x[32], y[32];
    if (ba_unhex (sk_hex, sk, sizeof sk) != BA_KEY_LEN)
        { builtin_error ("jwk-thumbprint: SK must be 32 bytes hex"); return EX_USAGE; }
    if (ba_ecdsa_p256_xy (sk, x, y) != 0)
        { builtin_error ("jwk-thumbprint: invalid private key"); return EXECUTION_FAILURE; }
    char canonical[256];
    int n = ba_jwk_canonical (canonical, sizeof canonical, x, y);
    if (n < 0) { builtin_error ("jwk-thumbprint: encode failed"); return EXECUTION_FAILURE; }
    unsigned char digest[32];
    if (ba_sha256 ((unsigned char *) canonical, (size_t) n, digest) != 0)
        { builtin_error ("jwk-thumbprint: sha256 failed"); return EXECUTION_FAILURE; }
    char b64[64];
    if (ba_base64url_encode (digest, 32, b64, sizeof b64) < 0)
        { builtin_error ("jwk-thumbprint: base64url encode failed"); return EXECUTION_FAILURE; }
    printf ("%s\n", b64);
    return EXECUTION_SUCCESS;
}

/* ----- key-authorization (RFC 8555 §8.1) ------------------------ */

/* TOKEN + "." + base64url(SHA256(canonical-JWK))  */
static int
ba_key_authorization_cmd (WORD_LIST *args)
{
    const char *sk_hex = NULL, *token = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-k")) {
            if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
            p = p->next; sk_hex = p->word->word;
        } else if (w[0] != '-' && !token) {
            token = w;
        } else { builtin_error ("key-authorization: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!token || !sk_hex) {
        builtin_error ("key-authorization: TOKEN -k SK_HEX required"); return EX_USAGE;
    }
    unsigned char sk[BA_KEY_LEN], x[32], y[32];
    if (ba_unhex (sk_hex, sk, sizeof sk) != BA_KEY_LEN)
        { builtin_error ("key-authorization: SK must be 32 bytes hex"); return EX_USAGE; }
    if (ba_ecdsa_p256_xy (sk, x, y) != 0)
        { builtin_error ("key-authorization: invalid private key"); return EXECUTION_FAILURE; }
    char canonical[256];
    int n = ba_jwk_canonical (canonical, sizeof canonical, x, y);
    if (n < 0) { builtin_error ("key-authorization: encode failed"); return EXECUTION_FAILURE; }
    unsigned char digest[32];
    if (ba_sha256 ((unsigned char *) canonical, (size_t) n, digest) != 0)
        { builtin_error ("key-authorization: sha256 failed"); return EXECUTION_FAILURE; }
    char tp[64];
    if (ba_base64url_encode (digest, 32, tp, sizeof tp) < 0)
        { builtin_error ("key-authorization: b64u encode failed"); return EXECUTION_FAILURE; }
    printf ("%s.%s\n", token, tp);
    return EXECUTION_SUCCESS;
}

/* ----- jws-sign ------------------------------------------------- */

/* Convert a 64-byte raw ECDSA signature (r||s, big-endian) into the
   JOSE-defined fixed-length form (RFC 7515 §3.4 / RFC 7518 §3.4): for
   ES256 it's literally the same r||s 64-byte form, so no conversion
   needed.  We base64url-encode directly. */

static int
ba_jws_sign_cmd (WORD_LIST *args)
{
    const char *sk_hex = NULL, *kid = NULL, *url = NULL, *nonce = NULL;
    const char *data_inline = NULL, *data_file = NULL;
    int use_jwk = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-k"))         { if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
                                          p = p->next; sk_hex = p->word->word; }
        else if (!strcmp (w, "--kid")) { if (!p->next) { builtin_error ("--kid needs URL"); return EX_USAGE; }
                                          p = p->next; kid = p->word->word; }
        else if (!strcmp (w, "--jwk")) use_jwk = 1;
        else if (!strcmp (w, "--url")) { if (!p->next) { builtin_error ("--url needs URL"); return EX_USAGE; }
                                          p = p->next; url = p->word->word; }
        else if (!strcmp (w, "--nonce")) { if (!p->next) { builtin_error ("--nonce needs N"); return EX_USAGE; }
                                            p = p->next; nonce = p->word->word; }
        else if (!strcmp (w, "-d"))    { if (!p->next) { builtin_error ("-d needs DATA"); return EX_USAGE; }
                                          p = p->next; data_inline = p->word->word; }
        else if (!strcmp (w, "-f"))    { if (!p->next) { builtin_error ("-f needs FILE"); return EX_USAGE; }
                                          p = p->next; data_file = p->word->word; }
        else { builtin_error ("jws-sign: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!sk_hex || !url || !nonce) {
        builtin_error ("jws-sign: -k SK_HEX, --url URL, --nonce N are required");
        return EX_USAGE;
    }
    if (use_jwk && kid) {
        builtin_error ("jws-sign: --jwk and --kid are mutually exclusive");
        return EX_USAGE;
    }
    if (!use_jwk && !kid) {
        /* Default to --jwk for first-time newAccount; otherwise the
           operator must always pass --kid (we don't infer).  Be
           explicit. */
        builtin_error ("jws-sign: exactly one of --kid KID or --jwk required");
        return EX_USAGE;
    }

    unsigned char sk[BA_KEY_LEN], x[32], y[32];
    if (ba_unhex (sk_hex, sk, sizeof sk) != BA_KEY_LEN)
        { builtin_error ("jws-sign: SK must be 32 bytes hex"); return EX_USAGE; }
    if (ba_ecdsa_p256_xy (sk, x, y) != 0)
        { builtin_error ("jws-sign: invalid private key"); return EXECUTION_FAILURE; }

    /* Compose the protected header.  We deliberately do not escape
       URL/KID/NONCE — RFC 8555 specifies these are URL-safe ASCII and
       Let's Encrypt's nonce is base64url alphabet.  If the caller
       feeds bogus inputs they will see a JWS decode error from the
       ACME server, which is preferable to silent JSON corruption. */
    char header[2048];
    if (use_jwk) {
        char jwk[256];
        int jn = ba_jwk_canonical (jwk, sizeof jwk, x, y);
        if (jn < 0) { builtin_error ("jws-sign: jwk encode failed"); return EXECUTION_FAILURE; }
        int n = snprintf (header, sizeof header,
                "{\"alg\":\"ES256\",\"jwk\":%s,\"nonce\":\"%s\",\"url\":\"%s\"}",
                jwk, nonce, url);
        if (n < 0 || (size_t) n >= sizeof header)
            { builtin_error ("jws-sign: header too long"); return EXECUTION_FAILURE; }
    } else {
        int n = snprintf (header, sizeof header,
                "{\"alg\":\"ES256\",\"kid\":\"%s\",\"nonce\":\"%s\",\"url\":\"%s\"}",
                kid, nonce, url);
        if (n < 0 || (size_t) n >= sizeof header)
            { builtin_error ("jws-sign: header too long"); return EXECUTION_FAILURE; }
    }

    /* Read payload bytes (may be empty = POST-as-GET). */
    unsigned char *payload = NULL; size_t payload_len = 0;
    if (data_file) {
        if (ba_slurp_file (data_file, &payload, &payload_len) < 0) return EXECUTION_FAILURE;
    } else if (data_inline) {
        payload_len = strlen (data_inline);
        payload = malloc (payload_len + 1);
        if (!payload) { builtin_error ("malloc"); return EXECUTION_FAILURE; }
        memcpy (payload, data_inline, payload_len);
    } else {
        payload = malloc (1); if (payload) payload[0] = 0;
        payload_len = 0;
    }

    /* base64url(header) and base64url(payload).  Worst-case is
       4/3 * payload_len + 2.  Bound the payload at 64 KB. */
    if (payload_len > 65536) {
        free (payload);
        builtin_error ("jws-sign: payload too large (>64 KB)");
        return EXECUTION_FAILURE;
    }
    size_t header_len = strlen (header);
    char *h64 = malloc (((header_len + 2) / 3) * 4 + 4);
    char *p64 = malloc (((payload_len + 2) / 3) * 4 + 4);
    if (!h64 || !p64) {
        free (h64); free (p64); free (payload);
        builtin_error ("malloc"); return EXECUTION_FAILURE;
    }
    int h64_n = ba_base64url_encode ((unsigned char *) header, header_len, h64, ((header_len + 2)/3)*4 + 4);
    int p64_n = ba_base64url_encode (payload, payload_len, p64, ((payload_len + 2)/3)*4 + 4);
    free (payload);
    if (h64_n < 0 || p64_n < 0) {
        free (h64); free (p64);
        builtin_error ("jws-sign: base64url encode failed"); return EXECUTION_FAILURE;
    }

    /* Signing input: h64 + "." + p64 */
    size_t si_len = (size_t) h64_n + 1 + (size_t) p64_n;
    unsigned char *si = malloc (si_len);
    if (!si) { free (h64); free (p64); builtin_error ("malloc"); return EXECUTION_FAILURE; }
    memcpy (si, h64, (size_t) h64_n);
    si[h64_n] = '.';
    memcpy (si + h64_n + 1, p64, (size_t) p64_n);

    unsigned char digest[32], sig_raw[64];
    if (ba_sha256 (si, si_len, digest) != 0) {
        free (si); free (h64); free (p64);
        builtin_error ("jws-sign: sha256 failed"); return EXECUTION_FAILURE;
    }
    free (si);
    if (mbedtls_ecdsa_p256_sign_raw (sig_raw, sk, digest, 32) != 0) {
        free (h64); free (p64);
        builtin_error ("jws-sign: ecdsa sign failed"); return EXECUTION_FAILURE;
    }

    char sig64[128];
    if (ba_base64url_encode (sig_raw, 64, sig64, sizeof sig64) < 0) {
        free (h64); free (p64);
        builtin_error ("jws-sign: signature b64u failed"); return EXECUTION_FAILURE;
    }

    /* Flattened-JSON JWS, single line (ACME servers don't care about
       internal whitespace; this is the most compact form). */
    printf ("{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}\n",
            h64, p64, sig64);
    free (h64); free (p64);
    return EXECUTION_SUCCESS;
}

/* ----- builtin entry -------------------------------------------- */

int
acme_builtin (WORD_LIST *list)
{
    if (list == 0) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;

    if (!strcmp (cmd, "jwk-thumbprint"))     return ba_jwk_thumbprint_cmd (args);
    if (!strcmp (cmd, "jwk-public"))         return ba_jwk_public_cmd (args);
    if (!strcmp (cmd, "key-authorization"))  return ba_key_authorization_cmd (args);
    if (!strcmp (cmd, "jws-extract-key-authorization"))
                                              return ba_key_authorization_cmd (args);
    if (!strcmp (cmd, "jws-sign"))           return ba_jws_sign_cmd (args);

    builtin_error ("unknown subcommand: %s", cmd);
    builtin_usage ();
    return EX_USAGE;
}

char *acme_doc[] = {
    "JOSE/JWS + JWK primitives for ACME (RFC 8555).",
    "",
    "Subcommands:",
    "    acme jwk-public         -k SK_HEX",
    "                                emit canonical {crv,kty,x,y} JWK JSON",
    "    acme jwk-thumbprint     -k SK_HEX",
    "                                base64url(SHA-256(canonical JWK)) (RFC 7638)",
    "    acme key-authorization  TOKEN -k SK_HEX",
    "                                TOKEN + '.' + thumbprint (RFC 8555 §8.1)",
    "    acme jws-sign           -k SK_HEX --url URL --nonce N",
    "                                [--kid KID | --jwk] [-d DATA | -f FILE]",
    "                                emit flattened JSON JWS for an ACME POST",
    "",
    "The operator-facing state machine (directory, account, order,",
    "challenge, finalize, issue, renew) lives in",
    "rootfs/bash-os/acme.sh — these C verbs are the crypto core.",
    (char *) NULL
};

struct builtin acme_struct = {
    "acme",
    acme_builtin,
    BUILTIN_ENABLED,
    acme_doc,
    "acme SUBCOMMAND [FLAGS...]",
    0
};
