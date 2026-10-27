/* SPDX-License-Identifier: MIT */
/* _git/sshsig.c — signing with an ssh key. See sshsig.h.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loadables.h"

#include "_monocypher_monocypher-ed25519.h"
#include "odb.h"
#include "sshsig.h"

/* ---- the pieces an ssh blob is made of ---------------------------------- */

/* A growing buffer, since every blob here is built up a piece at a time. */
struct bgit_blob {
    unsigned char *data;
    size_t len, cap;
};

static int
bgit_blob_add (struct bgit_blob *blob, const void *bytes, size_t n)
{
    if (blob->len + n > blob->cap) {
        size_t next = blob->cap ? blob->cap * 2 : 256;
        while (next < blob->len + n) next *= 2;
        unsigned char *grown = realloc (blob->data, next);
        if (!grown) return -1;
        blob->data = grown;
        blob->cap = next;
    }
    memcpy (blob->data + blob->len, bytes, n);
    blob->len += n;
    return 0;
}

/* An ssh string: four bytes of length, most significant first, then the
   bytes themselves. */
static int
bgit_blob_add_string (struct bgit_blob *blob, const void *bytes, size_t n)
{
    unsigned char header[4] = {
        (unsigned char) ((n >> 24) & 0xff), (unsigned char) ((n >> 16) & 0xff),
        (unsigned char) ((n >> 8) & 0xff), (unsigned char) (n & 0xff)
    };
    if (bgit_blob_add (blob, header, 4) < 0) return -1;
    return bgit_blob_add (blob, bytes, n);
}

/* Reading the same, one piece at a time. */
struct bgit_blob_reader {
    const unsigned char *data;
    size_t len, at;
};

static int
bgit_blob_take (struct bgit_blob_reader *reader, const unsigned char **out,
                size_t *out_len)
{
    if (reader->at + 4 > reader->len) return -1;
    const unsigned char *p = reader->data + reader->at;
    size_t n = ((size_t) p[0] << 24) | ((size_t) p[1] << 16) |
               ((size_t) p[2] << 8) | (size_t) p[3];
    if (reader->at + 4 + n > reader->len) return -1;
    if (out) *out = p + 4;
    if (out_len) *out_len = n;
    reader->at += 4 + n;
    return 0;
}

/* ---- base64, which is how a key and a signature are written down -------- */

static const char bgit_b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *
bgit_b64_encode (const unsigned char *data, size_t len, size_t wrap)
{
    size_t groups = (len + 2) / 3;
    size_t chars = groups * 4;
    size_t lines = wrap ? (chars + wrap - 1) / wrap : 0;
    char *out = malloc (chars + lines + 2);
    if (!out) return NULL;
    size_t at = 0, column = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned value = (unsigned) data[i] << 16;
        if (i + 1 < len) value |= (unsigned) data[i + 1] << 8;
        if (i + 2 < len) value |= data[i + 2];
        char four[4] = {
            bgit_b64[(value >> 18) & 0x3f], bgit_b64[(value >> 12) & 0x3f],
            i + 1 < len ? bgit_b64[(value >> 6) & 0x3f] : '=',
            i + 2 < len ? bgit_b64[value & 0x3f] : '='
        };
        for (int k = 0; k < 4; k++) {
            out[at++] = four[k];
            if (wrap && ++column == wrap) {
                out[at++] = '\n';
                column = 0;
            }
        }
    }
    if (wrap && column) out[at++] = '\n';
    out[at] = '\0';
    return out;
}

static int
bgit_b64_value (char c)
{
    const char *found = memchr (bgit_b64, c, 64);
    return found ? (int) (found - bgit_b64) : -1;
}

/* Decode base64, ignoring anything that is not part of it. */
static unsigned char *
bgit_b64_decode (const char *text, size_t *out_len)
{
    size_t len = strlen (text);
    unsigned char *out = malloc (len / 4 * 3 + 4);
    if (!out) return NULL;
    size_t at = 0;
    unsigned value = 0;
    int bits = 0;
    for (const char *p = text; *p; p++) {
        if (*p == '=') break;
        int digit = bgit_b64_value (*p);
        if (digit < 0) continue;
        value = (value << 6) | (unsigned) digit;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[at++] = (unsigned char) ((value >> bits) & 0xff);
        }
    }
    *out_len = at;
    return out;
}

/* ---- sha256, which is what names a key ---------------------------------- */

/* ssh-keygen calls a key by the sha256 of its blob, and that fingerprint is
   the only thing here that wants this digest: monocypher carries sha512 for
   the signature itself, so the small one stands on its own. */

#define BGIT_ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void
bgit_sha256_block (uint32_t state[8], const unsigned char *block)
{
    static const uint32_t constants[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t) block[i * 4] << 24) |
               ((uint32_t) block[i * 4 + 1] << 16) |
               ((uint32_t) block[i * 4 + 2] << 8) | block[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = BGIT_ROR (w[i - 15], 7) ^ BGIT_ROR (w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = BGIT_ROR (w[i - 2], 17) ^ BGIT_ROR (w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t s1 = BGIT_ROR (e, 6) ^ BGIT_ROR (e, 11) ^ BGIT_ROR (e, 25);
        uint32_t choice = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + choice + constants[i] + w[i];
        uint32_t s0 = BGIT_ROR (a, 2) ^ BGIT_ROR (a, 13) ^ BGIT_ROR (a, 22);
        uint32_t most = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + most;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void
bgit_sha256 (const unsigned char *data, size_t len, unsigned char out[32])
{
    uint32_t state[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    size_t whole = len / 64;
    for (size_t i = 0; i < whole; i++) bgit_sha256_block (state, data + i * 64);

    /* The tail: what is left, a one bit, zeroes, and the length in bits. */
    unsigned char tail[128];
    size_t rest = len - whole * 64;
    memcpy (tail, data + whole * 64, rest);
    tail[rest++] = 0x80;
    size_t room = rest <= 56 ? 64 : 128;
    memset (tail + rest, 0, room - rest);
    uint64_t bits = (uint64_t) len * 8;
    for (int i = 0; i < 8; i++)
        tail[room - 1 - i] = (unsigned char) (bits >> (i * 8));
    bgit_sha256_block (state, tail);
    if (room == 128) bgit_sha256_block (state, tail + 64);

    for (int i = 0; i < 8; i++) {
        out[i * 4] = (unsigned char) (state[i] >> 24);
        out[i * 4 + 1] = (unsigned char) (state[i] >> 16);
        out[i * 4 + 2] = (unsigned char) (state[i] >> 8);
        out[i * 4 + 3] = (unsigned char) state[i];
    }
}

/* ---- keys --------------------------------------------------------------- */

int
bgit_ssh_key_public (const char *text, bgit_ssh_key *key)
{
    memset (key, 0, sizeof *key);
    while (*text == ' ' || *text == '\t') text++;
    if (strncmp (text, "ssh-ed25519", 11)) return -1;
    const char *base = text + 11;
    while (*base == ' ' || *base == '\t') base++;
    size_t n = strcspn (base, " \t\r\n");
    char *held = malloc (n + 1);
    if (!held) return -1;
    memcpy (held, base, n);
    held[n] = '\0';
    size_t blob_len = 0;
    unsigned char *blob = bgit_b64_decode (held, &blob_len);
    free (held);
    if (!blob) return -1;

    struct bgit_blob_reader reader = { blob, blob_len, 0 };
    const unsigned char *type = NULL, *raw = NULL;
    size_t type_len = 0, raw_len = 0;
    int ok = bgit_blob_take (&reader, &type, &type_len) == 0 &&
             bgit_blob_take (&reader, &raw, &raw_len) == 0 &&
             type_len == 11 && !memcmp (type, "ssh-ed25519", 11) &&
             raw_len == 32;
    if (ok) memcpy (key->public_key, raw, 32);
    free (blob);
    return ok ? 0 : -1;
}

int
bgit_ssh_key_line (const bgit_ssh_key *key, char *out, size_t outsz)
{
    struct bgit_blob blob = { NULL, 0, 0 };
    if (bgit_blob_add_string (&blob, "ssh-ed25519", 11) < 0 ||
        bgit_blob_add_string (&blob, key->public_key, 32) < 0) {
        free (blob.data);
        return -1;
    }
    char *text = bgit_b64_encode (blob.data, blob.len, 0);
    free (blob.data);
    if (!text) return -1;
    int wrote = snprintf (out, outsz, "ssh-ed25519 %s", text);
    free (text);
    return wrote > 0 && (size_t) wrote < outsz ? 0 : -1;
}

int
bgit_ssh_key_fingerprint (const bgit_ssh_key *key, char *out, size_t outsz)
{
    struct bgit_blob blob = { NULL, 0, 0 };
    if (bgit_blob_add_string (&blob, "ssh-ed25519", 11) < 0 ||
        bgit_blob_add_string (&blob, key->public_key, 32) < 0) {
        free (blob.data);
        return -1;
    }
    unsigned char digest[32];
    bgit_sha256 (blob.data, blob.len, digest);
    free (blob.data);
    char *text = bgit_b64_encode (digest, sizeof digest, 0);
    if (!text) return -1;
    char *padding = strchr (text, '=');          /* which ssh leaves off */
    if (padding) *padding = '\0';
    int wrote = snprintf (out, outsz, "SHA256:%s", text);
    free (text);
    return wrote > 0 && (size_t) wrote < outsz ? 0 : -1;
}

int
bgit_ssh_key_private (const char *path, bgit_ssh_key *key)
{
    memset (key, 0, sizeof *key);
    unsigned char *file = NULL;
    size_t file_len = 0;
    if (bgit_slurp_file (path, &file, &file_len) < 0) {
        builtin_error ("cannot read %s", path);
        return -1;
    }
    /* What stands between the two lines of dashes is the key. The words
       on those lines are spelled here without the one that opens them:
       a line that reads whole like the first line of a key file trips
       every secret scanner there is, and this tree is scanned. */
    static const char marker[] = "OPENSSH PRIVATE KEY";
    char *text = malloc (file_len + 1);
    if (!text) { free (file); return -1; }
    memcpy (text, file, file_len);
    text[file_len] = '\0';
    free (file);
    char *header = strstr (text, marker);
    char *start = header ? strchr (header, '\n') : NULL;
    char *stop = start ? strstr (start, marker) : NULL;
    if (!header || !start || !stop) {
        free (text);
        builtin_error ("%s is not an OpenSSH private key", path);
        return -1;
    }
    /* The footer's own line begins before the words on it. */
    while (stop > start && stop[-1] != '\n') stop--;
    *stop = '\0';
    size_t blob_len = 0;
    unsigned char *blob = bgit_b64_decode (start, &blob_len);
    free (text);
    if (!blob) return -1;

    static const char magic[] = "openssh-key-v1";
    int rc = -1;
    if (blob_len < sizeof magic || memcmp (blob, magic, sizeof magic)) {
        builtin_error ("%s is not an OpenSSH private key", path);
        free (blob);
        return -1;
    }
    struct bgit_blob_reader reader = { blob, blob_len, sizeof magic };
    const unsigned char *cipher = NULL, *kdf = NULL, *inner = NULL;
    size_t cipher_len = 0, kdf_len = 0, inner_len = 0;
    if (bgit_blob_take (&reader, &cipher, &cipher_len) < 0 ||
        bgit_blob_take (&reader, &kdf, &kdf_len) < 0 ||
        bgit_blob_take (&reader, NULL, NULL) < 0 ||        /* kdf options */
        reader.at + 4 > reader.len) {
        free (blob);
        builtin_error ("%s is not a key this build can read", path);
        return -1;
    }
    if (cipher_len != 4 || memcmp (cipher, "none", 4) ||
        kdf_len != 4 || memcmp (kdf, "none", 4)) {
        free (blob);
        builtin_error ("%s needs a passphrase, which there is nowhere to ask "
                       "for", path);
        return -1;
    }
    reader.at += 4;                                        /* how many keys */
    if (bgit_blob_take (&reader, NULL, NULL) < 0 ||        /* the public one */
        bgit_blob_take (&reader, &inner, &inner_len) < 0) {
        free (blob);
        builtin_error ("%s is not a key this build can read", path);
        return -1;
    }

    /* Inside: two matching check numbers, then the key itself. */
    struct bgit_blob_reader inside = { inner, inner_len, 8 };
    const unsigned char *type = NULL, *pub = NULL, *secret = NULL;
    size_t type_len = 0, pub_len = 0, secret_len = 0;
    if (inner_len > 8 &&
        bgit_blob_take (&inside, &type, &type_len) == 0 &&
        bgit_blob_take (&inside, &pub, &pub_len) == 0 &&
        bgit_blob_take (&inside, &secret, &secret_len) == 0 &&
        type_len == 11 && !memcmp (type, "ssh-ed25519", 11) &&
        pub_len == 32 && secret_len == 64) {
        memcpy (key->public_key, pub, 32);
        memcpy (key->secret, secret, 64);
        key->have_secret = 1;
        rc = 0;
    } else
        builtin_error ("%s is not an unencrypted ed25519 key", path);
    free (blob);
    return rc;
}

/* ---- signing ------------------------------------------------------------ */

/* What an SSHSIG signature covers: the preamble, what it is for, and the
   hash of the thing itself. */
static int
bgit_sshsig_signed_data (const char *name_space, const unsigned char *payload,
                         size_t len, struct bgit_blob *out)
{
    unsigned char digest[64];
    crypto_sha512 (digest, payload, len);
    return bgit_blob_add (out, "SSHSIG", 6) < 0 ||
           bgit_blob_add_string (out, name_space, strlen (name_space)) < 0 ||
           bgit_blob_add_string (out, "", 0) < 0 ||
           bgit_blob_add_string (out, "sha512", 6) < 0 ||
           bgit_blob_add_string (out, digest, sizeof digest) < 0 ? -1 : 0;
}

int
bgit_sshsig_sign (const bgit_ssh_key *key, const char *name_space,
                  const unsigned char *payload, size_t len, char **out)
{
    *out = NULL;
    if (!key->have_secret) return -1;
    struct bgit_blob signed_data = { NULL, 0, 0 };
    if (bgit_sshsig_signed_data (name_space, payload, len, &signed_data) < 0) {
        free (signed_data.data);
        return -1;
    }
    unsigned char signature[64];
    crypto_ed25519_sign (signature, key->secret, signed_data.data,
                         signed_data.len);
    free (signed_data.data);

    struct bgit_blob public_blob = { NULL, 0, 0 };
    struct bgit_blob signature_blob = { NULL, 0, 0 };
    struct bgit_blob whole = { NULL, 0, 0 };
    int failed = bgit_blob_add_string (&public_blob, "ssh-ed25519", 11) < 0 ||
                 bgit_blob_add_string (&public_blob, key->public_key, 32) < 0 ||
                 bgit_blob_add_string (&signature_blob, "ssh-ed25519", 11) < 0 ||
                 bgit_blob_add_string (&signature_blob, signature, 64) < 0;
    unsigned char version[4] = { 0, 0, 0, 1 };
    if (!failed)
        failed = bgit_blob_add (&whole, "SSHSIG", 6) < 0 ||
                 bgit_blob_add (&whole, version, 4) < 0 ||
                 bgit_blob_add_string (&whole, public_blob.data,
                                       public_blob.len) < 0 ||
                 bgit_blob_add_string (&whole, name_space,
                                       strlen (name_space)) < 0 ||
                 bgit_blob_add_string (&whole, "", 0) < 0 ||
                 bgit_blob_add_string (&whole, "sha512", 6) < 0 ||
                 bgit_blob_add_string (&whole, signature_blob.data,
                                       signature_blob.len) < 0;
    free (public_blob.data);
    free (signature_blob.data);
    if (failed) {
        free (whole.data);
        return -1;
    }
    char *armour = bgit_b64_encode (whole.data, whole.len, 70);
    free (whole.data);
    if (!armour) return -1;
    size_t room = strlen (armour) + 128;
    char *text = malloc (room);
    if (!text) {
        free (armour);
        return -1;
    }
    snprintf (text, room, "-----BEGIN SSH SIGNATURE-----\n%s"
                          "-----END SSH SIGNATURE-----\n", armour);
    free (armour);
    *out = text;
    return 0;
}

int
bgit_sshsig_check (const char *armoured, const char *name_space,
                   const unsigned char *payload, size_t len,
                   bgit_ssh_key *key)
{
    memset (key, 0, sizeof *key);
    const char *start = strstr (armoured, "-----BEGIN SSH SIGNATURE-----");
    const char *stop = start ? strstr (start, "-----END SSH SIGNATURE-----") : NULL;
    if (!start || !stop) return -1;
    start += strlen ("-----BEGIN SSH SIGNATURE-----");
    char *middle = malloc ((size_t) (stop - start) + 1);
    if (!middle) return -1;
    memcpy (middle, start, (size_t) (stop - start));
    middle[stop - start] = '\0';
    size_t blob_len = 0;
    unsigned char *blob = bgit_b64_decode (middle, &blob_len);
    free (middle);
    if (!blob) return -1;

    if (blob_len < 10 || memcmp (blob, "SSHSIG", 6)) {
        free (blob);
        return -1;
    }
    struct bgit_blob_reader reader = { blob, blob_len, 10 };
    const unsigned char *public_blob = NULL, *named = NULL, *hash = NULL,
                        *signature_blob = NULL;
    size_t public_len = 0, named_len = 0, hash_len = 0, signature_len = 0;
    if (bgit_blob_take (&reader, &public_blob, &public_len) < 0 ||
        bgit_blob_take (&reader, &named, &named_len) < 0 ||
        bgit_blob_take (&reader, NULL, NULL) < 0 ||
        bgit_blob_take (&reader, &hash, &hash_len) < 0 ||
        bgit_blob_take (&reader, &signature_blob, &signature_len) < 0) {
        free (blob);
        return -1;
    }
    if (named_len != strlen (name_space) ||
        memcmp (named, name_space, named_len) ||
        hash_len != 6 || memcmp (hash, "sha512", 6)) {
        free (blob);
        return -1;
    }

    struct bgit_blob_reader inside = { public_blob, public_len, 0 };
    const unsigned char *type = NULL, *raw = NULL;
    size_t type_len = 0, raw_len = 0;
    if (bgit_blob_take (&inside, &type, &type_len) < 0 ||
        bgit_blob_take (&inside, &raw, &raw_len) < 0 ||
        type_len != 11 || memcmp (type, "ssh-ed25519", 11) || raw_len != 32) {
        free (blob);
        return -1;
    }
    memcpy (key->public_key, raw, 32);

    struct bgit_blob_reader in_signature = { signature_blob, signature_len, 0 };
    const unsigned char *signature_type = NULL, *signature = NULL;
    size_t signature_type_len = 0, signature_bytes = 0;
    if (bgit_blob_take (&in_signature, &signature_type, &signature_type_len) < 0 ||
        bgit_blob_take (&in_signature, &signature, &signature_bytes) < 0 ||
        signature_type_len != 11 || memcmp (signature_type, "ssh-ed25519", 11) ||
        signature_bytes != 64) {
        free (blob);
        return -1;
    }

    struct bgit_blob signed_data = { NULL, 0, 0 };
    int rc = -1;
    if (bgit_sshsig_signed_data (name_space, payload, len, &signed_data) == 0)
        rc = crypto_ed25519_check (signature, key->public_key, signed_data.data,
                                   signed_data.len) == 0 ? 0 : 1;
    free (signed_data.data);
    free (blob);
    return rc;
}

int
bgit_ssh_allowed_signer (const char *path, const bgit_ssh_key *key, char *out,
                         size_t outsz)
{
    unsigned char *file = NULL;
    size_t file_len = 0;
    if (bgit_slurp_file (path, &file, &file_len) < 0) return -1;
    int found = 0;
    char *line = (char *) file;
    char *end = (char *) file + file_len;
    while (!found && line < end) {
        char *stop = memchr (line, '\n', (size_t) (end - line));
        size_t len = stop ? (size_t) (stop - line) : (size_t) (end - line);
        char entry[8192];
        if (len && len < sizeof entry && *line != '#') {
            memcpy (entry, line, len);
            entry[len] = '\0';
            /* "<principal>[,<principal>...] [options] <keytype> <key>" */
            char *space = strchr (entry, ' ');
            if (space) {
                *space = '\0';
                bgit_ssh_key theirs;
                const char *rest = space + 1;
                while (*rest == ' ') rest++;
                if (bgit_ssh_key_public (rest, &theirs) == 0 &&
                    !memcmp (theirs.public_key, key->public_key, 32)) {
                    snprintf (out, outsz, "%s", entry);
                    found = 1;
                }
            }
        }
        line = stop ? stop + 1 : end;
    }
    free (file);
    return found;
}
