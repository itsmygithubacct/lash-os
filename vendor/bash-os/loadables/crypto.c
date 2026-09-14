/* SPDX-License-Identifier: MIT */
/* crypto.c - cryptographic primitives via mbedTLS and monocypher,
 * exposed as a Bash loadable builtin.
 *
 * Hashes, MACs, AEAD, HKDF, PBKDF2, random. PEM/DER (Phase F) and TLS (Phase G) layer on
 * later.
 *
 * Subcommand dispatch (see `crypto --help` for full grammar):
 *
 *   sha256 / sha384 / sha512 / sha1 / md5 / blake2b / shake256
 *       Read bytes from stdin, write digest to stdout (raw bytes).
 *       -x emits hex (var-storable). FILE arg redirects from a file
 *       for fixed-size hashes. shake256 accepts -n BYTES.
 *
 *   hmac-sha256 / hmac-sha512  -k KEY [-x]
 *       Key is hex-encoded on the CLI (NUL-safe through bash vars).
 *
 *   aes-gcm / chacha20-poly1305  -e|-d  -k KEY  -n NONCE  [-A AAD]
 *       AEAD with auth-tag appended to ciphertext. AAD optional.
 *       AES-GCM: 16-byte key, 12-byte nonce. ChaCha20-Poly1305: 32-byte
 *       key, 12-byte nonce.
 *   aes-siv-cmac  -e|-d  -k KEY  [-A AAD]... [-x]
 *       AEAD_AES_SIV_CMAC_256 for NTS. KEY is 32 bytes, split into
 *       AES-CMAC/S2V and AES-CTR subkeys. Encrypt emits SIV||ciphertext.
 *
 *   ed25519-keygen [-x]
 *       Emit a 32-byte private key on stdout (raw or -x hex).
 *
 *   ed25519-sign  -k SK_HEX
 *   ed25519-verify -k PK_HEX -s SIG_HEX
 *       Read message from stdin. sign writes 64-byte sig (raw or -x).
 *       verify exits 0 on valid, 1 on invalid.
 *   ed448-verify -k PK_HEX -s SIG_HEX
 *       Verification-only RFC 8032 Ed448.
 *
 *   x25519-keygen [-x]
 *   x25519-pub    -k SK_HEX  [-x]
 *   x25519-shared -p PK_HEX -k SK_HEX  [-x]
 *
 *   hkdf   -a HASH -s SALT_HEX -k IKM_HEX -L LEN [-x]
 *   pbkdf2 -a HASH -s SALT_HEX -p PASSWORD -i ITER -L LEN [-x]
 *
 *   random N [-x]
 *       N bytes from /dev/urandom (kernel CSPRNG). Default raw,
 *       -x for hex.
 *
 *   nts-ke HOST[:PORT] [-c CA_PEM] [-s SNI] [--emit-keys]
 *       NTS-KE over TLS with ALPN ntske/1 and RFC 8915 key export.
 *
 * NUL safety: hex-encoded keys/nonces/salts/sigs ride through bash
 * variables without NUL-stripping. Raw byte output goes through stdout
 * which is FD-safe. The loadable un-hexes inputs internally.
 *
 * --- LICENSE ---
 * MIT License
 *
 * Copyright (c) 2026 bash_linux contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software. See the
 * full MIT text for the standard disclaimer.
 *
 * Note: when compiled and statically linked into GNU Bash, the resulting
 * combined binary is a derivative work of bash and is governed by GPL-3+
 * (bash's license). MIT for this source file is GPL-3+-compatible.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <termios.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>      /* mlock/munlock for argon2id work_area */
#include <sys/time.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/syscall.h>   /* SYS_getrandom */

/* getrandom(2) syscall number fallback for toolchains whose headers predate
 * it. x86_64=318, aarch64=278. Normally <sys/syscall.h> already defines it;
 * the guard just keeps the key-grade RNG below buildable on both shipped
 * arches without pulling in musl's <sys/random.h> (which is not always on the
 * patched bash build's -I path — see uuidgen.c). */
#ifndef SYS_getrandom
#  if defined(__x86_64__)
#    define SYS_getrandom 318
#  elif defined(__aarch64__)
#    define SYS_getrandom 278
#  endif
#endif

/* Vendored monocypher (Phase F.5) for RFC 8032 Ed25519 sign/verify.
 * Ed25519 stays on monocypher by design; monocypher's `optional/`
 * subset provides crypto_ed25519_{key_pair,sign,check} matching
 * RFC 8032 (SHA-512 hash, not the BLAKE2b default). After
 * patch-bash-loadables.sh's helper-flatten pass the header lives at
 * `builtins/_monocypher_monocypher-ed25519.h`. The source paths
 * resolve by relative include from this file (already in builtins/). */
#include "_monocypher_monocypher-ed25519.h"
#include "_bashos_authcrypto_argon2id.h"

/* Stage 19.A: thin mbedTLS bridge via flattened _mbedtls/ tree. Only the
   version-string accessors are wired in 19.A.2 — Stage 19.B will pull
   in the TLS state machine (vendor/mbedtls/library/ssl_*.c) + PSA core
   (vendor/mbedtls/tf-psa-crypto/core/) + builtin crypto drivers
   (vendor/mbedtls/tf-psa-crypto/drivers/builtin/src/). */
#ifndef MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS 1
#endif
#include "_mbedtls_version.h"
/* Stage 19.B starter: SHA-256 via mbedtls API. Self-contained
   FIPS 180-4 implementation extracted from upstream — proves the
   "one verb at a time" migration path past the 19.A version-bridge. */
#include "_mbedtls_sha256.h"
/* Stage 19.B primitive #2: HMAC-SHA256 (FIPS 198-1) wrapping the
   mbedtls SHA-256 primitives. Self-contained; bypasses upstream's
   md.c dispatch layer (which adds 200+ LoC of generic-hash glue we
   don't need until further hashes are migrated). */
#include "_mbedtls_hmac.h"
#include "_mbedtls_sha512.h"
#include "_mbedtls_hmac_sha512.h"
#include "_mbedtls_sha3.h"
#include "_mbedtls_sha1.h"
#include "_mbedtls_hmac_sha1.h"
#include "_mbedtls_md5.h"
#include "_mbedtls_hmac_md5.h"
#include "_mbedtls_chacha20.h"
#include "_mbedtls_poly1305.h"
#include "_mbedtls_chachapoly.h"
#include "_mbedtls_rsa_min.h"
#include "_mbedtls_asn1.h"
#include "_mbedtls_x509_crt_min.h"
#include "_mbedtls_x509_chain.h"
#include "_mbedtls_tls13_keys.h"
/* Stage 19.B primitive #4: HKDF-SHA256 (RFC 5869), layered on the
   staged mbedTLS HMAC-SHA256 helper. */
#include "_mbedtls_hkdf.h"
/* Stage 19.B primitive #5: ECDSA-P256 via mbedTLS p256-m. */
#include "_mbedtls_ecdsa_p256.h"
/* Stage 19.F: generic ECDSA verify path for DNSSEC P-384/SHA-384. */
#include "_mbedtls_ecdsa.h"
/* §8 DNSSEC crypto-signer prereqs: full RSA context (keygen + PKCS#1 v1.5
   sign) for DNSSEC algs 5/7/8/10, and ECDSA-P-384 sign (alg 14). The full
   mbedTLS rsa.h has a distinct include guard (TF_PSA_CRYPTO_MBEDTLS_PRIVATE_RSA_H)
   from the verify-only shim's MBEDTLS_RSA_H, so both coexist; it pulls in
   bignum.h + md.h, already used by ecdsa.h above. rsa_alt_helpers.h gives
   mbedtls_rsa_deduce_crt() so we can hydrate DP/DQ/QP from P,Q,D on import
   (this trimmed rsa.c lacks mbedtls_rsa_complete/import_raw). */
#include "_mbedtls_rsa.h"
#include "_mbedtls_rsa_alt_helpers.h"
#include "_mbedtls_bignum.h"
#include "_mbedtls_base64.h"
#include "_mbedtls_pem.h"
/* Server-gap slice B prereq: ASN.1 writer for hand-rolled PKCS#10 CSR. */
#include "_mbedtls_asn1write.h"
/* Stage 19.B primitive #3: AES-128/256 ECB (encrypt only) + GCM
   AEAD wrapping it. Together implement RFC 5116 + NIST SP 800-38D. */
#include "_mbedtls_aes.h"
#include "_mbedtls_gcm.h"
/* Stage 19.B primitive #5: X25519 ECDH (RFC 7748 §5). Self-contained
   reference impl with 5x51 limb field arithmetic + Montgomery ladder
   (constant-time cswap). */
#include "_mbedtls_x25519.h"

#include "_bashcrypto_aead.h"
#include "loadables.h"

/* ---- helpers ----------------------------------------------------- */

static int
bc_hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Decode a hex string into bytes. Returns the byte count, or -1 on bad
 * input. `out` must be at least strlen(hex)/2 bytes. Tolerates
 * whitespace in the hex string. */
static int
bc_unhex (const char *hex, unsigned char *out, size_t outsz)
{
  size_t o = 0;
  int hi = -1;
  for (const char *p = hex; *p; p++)
    {
      if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') continue;
      int v = bc_hexval ((unsigned char) *p);
      if (v < 0) return -1;
      if (hi < 0) { hi = v; continue; }
      if (o >= outsz) return -1;
      out[o++] = (unsigned char) ((hi << 4) | v);
      hi = -1;
    }
  if (hi >= 0) return -1;   /* odd nibble count */
  return (int) o;
}

/* Print bytes as hex to stdout, no trailing newline. */
static void
bc_print_hex (const unsigned char *buf, size_t n)
{
  static const char d[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++)
    {
      putchar (d[(buf[i] >> 4) & 0xf]);
      putchar (d[buf[i] & 0xf]);
    }
}

/* Write all of `buf` to stdout (raw bytes, FD-safe). */
static int
bc_write_all (const unsigned char *buf, size_t n)
{
  size_t left = n;
  const unsigned char *p = buf;
  while (left > 0)
    {
      ssize_t w = write (STDOUT_FILENO, p, left);
      if (w < 0)
        {
          if (errno == EINTR) continue;
          builtin_error ("write: %s", strerror (errno));
          return -1;
        }
      p += w;
      left -= (size_t) w;
    }
  return 0;
}

/* Slurp an FD into a malloc'd buffer. *out_len gets the byte count. */
static int
bc_slurp_fd (int fd, unsigned char **out_buf, size_t *out_len)
{
  size_t cap = 4096, len = 0;
  unsigned char *buf = malloc (cap);
  if (!buf) { builtin_error ("malloc"); return -1; }
  for (;;)
    {
      if (len == cap)
        {
          cap *= 2;
          unsigned char *n = realloc (buf, cap);
          if (!n) { free (buf); builtin_error ("realloc"); return -1; }
          buf = n;
        }
      ssize_t r = read (fd, buf + len, cap - len);
      if (r < 0) { if (errno == EINTR) continue;
                   free (buf); builtin_error ("read: %s", strerror (errno));
                   return -1; }
      if (r == 0) break;
      len += (size_t) r;
    }
  *out_buf = buf;
  *out_len = len;
  return 0;
}

/* Fill buf with key-grade CSPRNG bytes via getrandom(2), which BLOCKS until
 * the kernel CSPRNG is fully seeded. There is deliberately NO /dev/urandom
 * fallback: on a fresh, entropy-poor boot /dev/urandom returns immediately
 * with possibly-unseeded bytes, which is exactly the race (bl-keygen running
 * before "crng init done") this avoids. ENOSYS is impossible on the shipped
 * 6.12 kernel, so the only normal blocking is the one-time wait for the crng
 * to seed. Returns 0 on success, -1 on failure with builtin_error() emitted. */
static int
bc_random_bytes (unsigned char *buf, size_t n)
{
  size_t got = 0;
  while (got < n)
    {
      long r = syscall (SYS_getrandom, buf + got, n - got, 0);
      if (r > 0) { got += (size_t) r; continue; }
      if (r < 0 && errno == EINTR) continue;
      builtin_error ("getrandom: %s", r < 0 ? strerror (errno) : "short read");
      return -1;
    }
  return 0;
}

/* Emit `buf`/`len` as either hex (if hex_out) + newline or raw bytes. */
static int
bc_emit (const unsigned char *buf, size_t len, int hex_out)
{
  if (hex_out)
    {
      bc_print_hex (buf, len);
      putchar ('\n');
      if (fflush (stdout) != 0 || ferror (stdout))
        {
          builtin_error ("write error");
          return -1;
        }
      return 0;
    }
  if (bc_write_all (buf, len) < 0) return -1;
  return 0;
}

/* Emit to a bash variable instead of stdout. var_name=NULL falls back
 * to bc_emit. Used by primitives that pass `-o VARNAME` to skip the
 * `$(…)` fork that command-substitution forces. Hex-only — binding raw
 * bytes to a bash variable is fragile (NUL bytes terminate strings). */
static int
bc_emit_to (const unsigned char *buf, size_t len, int hex_out, const char *var_name)
{
  if (!var_name) return bc_emit (buf, len, hex_out);
  if (!hex_out) { builtin_error ("-o VARNAME requires -x (hex output)"); return -1; }
  char *hex = malloc (len * 2 + 1);
  if (!hex) { builtin_error ("malloc: %s", strerror (errno)); return -1; }
  static const char nibble[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++)
    {
      hex[i*2]   = nibble[buf[i] >> 4];
      hex[i*2+1] = nibble[buf[i] & 0xf];
    }
  hex[len*2] = '\0';
  builtin_bind_variable ((char *) var_name, hex, 0);
  free (hex);
  return 0;
}



/* Ed25519 (sign / verify / keygen). */
static int
bc_ed25519_keygen (WORD_LIST *args)
{
  int hex_out = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    if (strcmp (p->word->word, "-x") == 0) hex_out = 1;
    else { builtin_error ("unexpected arg: %s", p->word->word); return EX_USAGE; }
  unsigned char sk[32];
  if (bc_random_bytes (sk, 32) < 0) return EXECUTION_FAILURE;
  return bc_emit (sk, 32, hex_out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* Phase F.5 — Ed25519 sign/verify via vendored monocypher's RFC 8032
 * subset (crypto_ed25519_*, SHA-512 based — matches openssl, libsodium,
 * NaCl, and the rest of the world). */

static int
bc_ed25519_pub_cmd (WORD_LIST *args)
{
  int hex_out = 0;
  const char *seed_hex = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (strcmp (w, "-x") == 0) hex_out = 1;
      else if (strcmp (w, "-k") == 0)
        { if (!p->next) { builtin_error ("-k needs SEED_HEX"); return EX_USAGE; }
          p = p->next; seed_hex = p->word->word; }
      else { builtin_error ("unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!seed_hex) { builtin_error ("ed25519-pub needs -k SEED_HEX (32 bytes)"); return EX_USAGE; }

  uint8_t seed[32];
  if (bc_unhex (seed_hex, seed, sizeof seed) != 32)
    { builtin_error ("SEED must be 32 bytes hex"); return EX_USAGE; }

  /* monocypher's crypto_ed25519_key_pair derives the 64-byte expanded
     secret (= seed + pubkey) and 32-byte public key in one call. We
     emit only the pubkey; the expanded secret stays on the stack and
     gets wiped before return. */
  uint8_t sk_full[64];
  uint8_t pk[32];
  crypto_ed25519_key_pair (sk_full, pk, seed);
  crypto_wipe (sk_full, 64);
  crypto_wipe (seed, 32);
  return bc_emit (pk, 32, hex_out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bc_ed25519_sign (WORD_LIST *args)
{
  int hex_out = 0;
  const char *seed_hex = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (strcmp (w, "-x") == 0) hex_out = 1;
      else if (strcmp (w, "-k") == 0)
        { if (!p->next) { builtin_error ("-k needs SEED_HEX"); return EX_USAGE; }
          p = p->next; seed_hex = p->word->word; }
      else { builtin_error ("unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!seed_hex) { builtin_error ("ed25519-sign needs -k SEED_HEX (32 bytes)"); return EX_USAGE; }

  uint8_t seed[32];
  if (bc_unhex (seed_hex, seed, sizeof seed) != 32)
    { builtin_error ("SEED must be 32 bytes hex"); return EX_USAGE; }

  /* Build the 64-byte secret key (seed || pubkey) inline. */
  uint8_t sk_full[64];
  uint8_t pk[32];
  crypto_ed25519_key_pair (sk_full, pk, seed);

  unsigned char *msg; size_t mlen;
  if (bc_slurp_fd (STDIN_FILENO, &msg, &mlen) < 0)
    {
      crypto_wipe (sk_full, 64);
      crypto_wipe (seed, 32);
      return EXECUTION_FAILURE;
    }

  uint8_t sig[64];
  crypto_ed25519_sign (sig, sk_full, msg, mlen);

  crypto_wipe (sk_full, 64);
  crypto_wipe (seed, 32);
  free (msg);

  return bc_emit (sig, 64, hex_out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bc_ed25519_verify (WORD_LIST *args)
{
  const char *pk_hex = NULL, *sig_hex = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (strcmp (w, "-k") == 0)
        { if (!p->next) { builtin_error ("-k needs PK_HEX"); return EX_USAGE; }
          p = p->next; pk_hex = p->word->word; }
      else if (strcmp (w, "-s") == 0)
        { if (!p->next) { builtin_error ("-s needs SIG_HEX"); return EX_USAGE; }
          p = p->next; sig_hex = p->word->word; }
      else { builtin_error ("unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!pk_hex || !sig_hex)
    { builtin_error ("ed25519-verify needs -k PK_HEX -s SIG_HEX"); return EX_USAGE; }

  uint8_t pk[32], sig[64];
  if (bc_unhex (pk_hex, pk, sizeof pk) != 32)
    { builtin_error ("PK must be 32 bytes hex"); return EX_USAGE; }
  if (bc_unhex (sig_hex, sig, sizeof sig) != 64)
    { builtin_error ("SIG must be 64 bytes hex"); return EX_USAGE; }

  unsigned char *msg; size_t mlen;
  if (bc_slurp_fd (STDIN_FILENO, &msg, &mlen) < 0) return EXECUTION_FAILURE;

  /* monocypher returns 0 on valid, non-zero on invalid. Translate to
     bash exit-code conventions (0 = success). No stdout on success
     either way; caller checks $?. */
  int rc = crypto_ed25519_check (sig, pk, msg, mlen);
  free (msg);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bc_shake256_bytes (const unsigned char *msg, size_t mlen,
                   unsigned char *out, size_t out_len)
{
  mbedtls_sha3_context ctx;
  mbedtls_sha3_init (&ctx);
  if (mbedtls_sha3_starts (&ctx, MBEDTLS_SHA3_SHAKE256) != 0)
    { mbedtls_sha3_free (&ctx); return -1; }
  if (mlen && mbedtls_sha3_update (&ctx, msg, mlen) != 0)
    { mbedtls_sha3_free (&ctx); return -1; }
  int rc = mbedtls_sha3_finish (&ctx, out, out_len);
  mbedtls_sha3_free (&ctx);
  return rc == 0 ? 0 : -1;
}

static int
bc_shake256_cmd (WORD_LIST *args)
{
  int hex_out = 0;
  size_t out_len = 64;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-x") == 0) hex_out = 1;
      else if (strcmp (w, "-n") == 0)
        {
          if (!p->next) { builtin_error ("shake256: -n needs BYTES"); return EX_USAGE; }
          p = p->next;
          char *end = NULL;
          unsigned long v = strtoul (p->word->word, &end, 10);
          if (end == p->word->word || *end != '\0' || v == 0 || v > 65536)
            { builtin_error ("shake256: BYTES must be 1..65536"); return EX_USAGE; }
          out_len = (size_t) v;
        }
      else { builtin_error ("shake256: unexpected arg: %s", w); return EX_USAGE; }
    }

  unsigned char *msg = NULL;
  size_t mlen = 0;
  if (bc_slurp_fd (STDIN_FILENO, &msg, &mlen) < 0) return EXECUTION_FAILURE;
  unsigned char *out = malloc (out_len);
  if (!out)
    {
      free (msg);
      builtin_error ("malloc");
      return EXECUTION_FAILURE;
    }
  int rc = bc_shake256_bytes (msg, mlen, out, out_len);
  free (msg);
  if (rc != 0)
    {
      free (out);
      builtin_error ("shake256: hash failed");
      return EXECUTION_FAILURE;
    }
  rc = bc_emit (out, out_len, hex_out);
  free (out);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

typedef struct {
  mbedtls_mpi p;
  mbedtls_mpi d;
  mbedtls_mpi l;
  mbedtls_mpi sqrt_exp;
  mbedtls_mpi bx;
  mbedtls_mpi by;
} bc_ed448_ctx;

typedef struct {
  mbedtls_mpi x;
  mbedtls_mpi y;
  mbedtls_mpi z;
} bc_ed448_point;

static void
bc_ed448_ctx_init (bc_ed448_ctx *c)
{
  mbedtls_mpi_init (&c->p);
  mbedtls_mpi_init (&c->d);
  mbedtls_mpi_init (&c->l);
  mbedtls_mpi_init (&c->sqrt_exp);
  mbedtls_mpi_init (&c->bx);
  mbedtls_mpi_init (&c->by);
}

static void
bc_ed448_ctx_free (bc_ed448_ctx *c)
{
  mbedtls_mpi_free (&c->p);
  mbedtls_mpi_free (&c->d);
  mbedtls_mpi_free (&c->l);
  mbedtls_mpi_free (&c->sqrt_exp);
  mbedtls_mpi_free (&c->bx);
  mbedtls_mpi_free (&c->by);
}

static int
bc_ed448_ctx_load (bc_ed448_ctx *c)
{
  int rc = 0;
  mbedtls_mpi two224;
  mbedtls_mpi_init (&two224);

  if ((rc = mbedtls_mpi_lset (&c->p, 1)) != 0) goto cleanup;
  if ((rc = mbedtls_mpi_shift_l (&c->p, 448)) != 0) goto cleanup;
  if ((rc = mbedtls_mpi_lset (&two224, 1)) != 0) goto cleanup;
  if ((rc = mbedtls_mpi_shift_l (&two224, 224)) != 0) goto cleanup;
  if ((rc = mbedtls_mpi_sub_mpi (&c->p, &c->p, &two224)) != 0) goto cleanup;
  if ((rc = mbedtls_mpi_sub_int (&c->p, &c->p, 1)) != 0) goto cleanup;

  if ((rc = mbedtls_mpi_copy (&c->d, &c->p)) != 0) goto cleanup;
  if ((rc = mbedtls_mpi_sub_int (&c->d, &c->d, 39081)) != 0) goto cleanup;

  if ((rc = mbedtls_mpi_copy (&c->sqrt_exp, &c->p)) != 0) goto cleanup;
  if ((rc = mbedtls_mpi_add_int (&c->sqrt_exp, &c->sqrt_exp, 1)) != 0) goto cleanup;
  if ((rc = mbedtls_mpi_shift_r (&c->sqrt_exp, 2)) != 0) goto cleanup;

  if ((rc = mbedtls_mpi_read_string (&c->l, 16,
        "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3")) != 0) goto cleanup;
  if ((rc = mbedtls_mpi_read_string (&c->bx, 16,
        "4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E")) != 0) goto cleanup;
  if ((rc = mbedtls_mpi_read_string (&c->by, 16,
        "693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14")) != 0) goto cleanup;

cleanup:
  mbedtls_mpi_free (&two224);
  return rc == 0 ? 0 : -1;
}

static void
bc_ed448_point_init (bc_ed448_point *p)
{
  mbedtls_mpi_init (&p->x);
  mbedtls_mpi_init (&p->y);
  mbedtls_mpi_init (&p->z);
}

static void
bc_ed448_point_free (bc_ed448_point *p)
{
  mbedtls_mpi_free (&p->x);
  mbedtls_mpi_free (&p->y);
  mbedtls_mpi_free (&p->z);
}

static int
bc_ed448_point_copy (bc_ed448_point *r, const bc_ed448_point *p)
{
  int rc;
  if ((rc = mbedtls_mpi_copy (&r->x, &p->x)) != 0) return rc;
  if ((rc = mbedtls_mpi_copy (&r->y, &p->y)) != 0) return rc;
  return mbedtls_mpi_copy (&r->z, &p->z);
}

static int
bc_ed448_point_zero (bc_ed448_point *p)
{
  int rc;
  if ((rc = mbedtls_mpi_lset (&p->x, 0)) != 0) return rc;
  if ((rc = mbedtls_mpi_lset (&p->y, 1)) != 0) return rc;
  return mbedtls_mpi_lset (&p->z, 1);
}

static int
bc_ed448_point_base (bc_ed448_point *p, const bc_ed448_ctx *c)
{
  int rc;
  if ((rc = mbedtls_mpi_copy (&p->x, &c->bx)) != 0) return rc;
  if ((rc = mbedtls_mpi_copy (&p->y, &c->by)) != 0) return rc;
  return mbedtls_mpi_lset (&p->z, 1);
}

static int
bc_ed448_fmod (mbedtls_mpi *r, const bc_ed448_ctx *c)
{
  return mbedtls_mpi_mod_mpi (r, r, &c->p);
}

static int
bc_ed448_fadd (mbedtls_mpi *r, const mbedtls_mpi *a,
               const mbedtls_mpi *b, const bc_ed448_ctx *c)
{
  int rc;
  if ((rc = mbedtls_mpi_add_mpi (r, a, b)) != 0) return rc;
  return bc_ed448_fmod (r, c);
}

static int
bc_ed448_fsub (mbedtls_mpi *r, const mbedtls_mpi *a,
               const mbedtls_mpi *b, const bc_ed448_ctx *c)
{
  int rc;
  if ((rc = mbedtls_mpi_sub_mpi (r, a, b)) != 0) return rc;
  return bc_ed448_fmod (r, c);
}

static int
bc_ed448_fmul (mbedtls_mpi *r, const mbedtls_mpi *a,
               const mbedtls_mpi *b, const bc_ed448_ctx *c)
{
  int rc;
  if ((rc = mbedtls_mpi_mul_mpi (r, a, b)) != 0) return rc;
  return bc_ed448_fmod (r, c);
}

static int
bc_ed448_fsqr (mbedtls_mpi *r, const mbedtls_mpi *a, const bc_ed448_ctx *c)
{
  return bc_ed448_fmul (r, a, a, c);
}

static int
bc_ed448_fneg (mbedtls_mpi *r, const mbedtls_mpi *a, const bc_ed448_ctx *c)
{
  if (mbedtls_mpi_cmp_int (a, 0) == 0)
    return mbedtls_mpi_lset (r, 0);
  return bc_ed448_fsub (r, &c->p, a, c);
}

static int
bc_ed448_finv (mbedtls_mpi *r, const mbedtls_mpi *a, const bc_ed448_ctx *c)
{
  mbedtls_mpi exp;
  int rc;
  mbedtls_mpi_init (&exp);
  if ((rc = mbedtls_mpi_copy (&exp, &c->p)) != 0) goto cleanup;
  if ((rc = mbedtls_mpi_sub_int (&exp, &exp, 2)) != 0) goto cleanup;
  rc = mbedtls_mpi_exp_mod (r, a, &exp, &c->p, NULL);
cleanup:
  mbedtls_mpi_free (&exp);
  return rc;
}

static int
bc_ed448_fsqrt (mbedtls_mpi *r, const mbedtls_mpi *a, const bc_ed448_ctx *c)
{
  int rc = 0;
  mbedtls_mpi chk;
  mbedtls_mpi_init (&chk);
  if ((rc = mbedtls_mpi_exp_mod (r, a, &c->sqrt_exp, &c->p, NULL)) != 0)
    goto cleanup;
  if ((rc = bc_ed448_fsqr (&chk, r, c)) != 0) goto cleanup;
  rc = (mbedtls_mpi_cmp_mpi (&chk, a) == 0) ? 0 : -1;
cleanup:
  mbedtls_mpi_free (&chk);
  return rc;
}

static int
bc_ed448_point_add (bc_ed448_point *r, const bc_ed448_point *p,
                    const bc_ed448_point *q, const bc_ed448_ctx *c)
{
  int rc = 0;
  mbedtls_mpi xcp, ycp, zcp, b, e, f, g, t1, t2, t3;
  mbedtls_mpi_init (&xcp); mbedtls_mpi_init (&ycp); mbedtls_mpi_init (&zcp);
  mbedtls_mpi_init (&b); mbedtls_mpi_init (&e); mbedtls_mpi_init (&f);
  mbedtls_mpi_init (&g); mbedtls_mpi_init (&t1); mbedtls_mpi_init (&t2);
  mbedtls_mpi_init (&t3);

  if ((rc = bc_ed448_fmul (&xcp, &p->x, &q->x, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&ycp, &p->y, &q->y, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&zcp, &p->z, &q->z, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fsqr (&b, &zcp, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&t1, &xcp, &ycp, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&e, &c->d, &t1, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fsub (&f, &b, &e, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fadd (&g, &b, &e, c)) != 0) goto cleanup;

  if ((rc = bc_ed448_fadd (&t1, &p->x, &p->y, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fadd (&t2, &q->x, &q->y, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&t3, &t1, &t2, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fsub (&t3, &t3, &xcp, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fsub (&t3, &t3, &ycp, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&t1, &zcp, &f, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&r->x, &t1, &t3, c)) != 0) goto cleanup;

  if ((rc = bc_ed448_fsub (&t1, &ycp, &xcp, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&t2, &zcp, &g, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&r->y, &t2, &t1, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&r->z, &f, &g, c)) != 0) goto cleanup;

cleanup:
  mbedtls_mpi_free (&xcp); mbedtls_mpi_free (&ycp); mbedtls_mpi_free (&zcp);
  mbedtls_mpi_free (&b); mbedtls_mpi_free (&e); mbedtls_mpi_free (&f);
  mbedtls_mpi_free (&g); mbedtls_mpi_free (&t1); mbedtls_mpi_free (&t2);
  mbedtls_mpi_free (&t3);
  return rc;
}

static int
bc_ed448_point_double (bc_ed448_point *r, const bc_ed448_point *p,
                       const bc_ed448_ctx *c)
{
  int rc = 0;
  mbedtls_mpi x1s, y1s, z1s, xys, f, j, t1, t2;
  mbedtls_mpi_init (&x1s); mbedtls_mpi_init (&y1s); mbedtls_mpi_init (&z1s);
  mbedtls_mpi_init (&xys); mbedtls_mpi_init (&f); mbedtls_mpi_init (&j);
  mbedtls_mpi_init (&t1); mbedtls_mpi_init (&t2);

  if ((rc = bc_ed448_fsqr (&x1s, &p->x, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fsqr (&y1s, &p->y, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fsqr (&z1s, &p->z, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fadd (&xys, &p->x, &p->y, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fadd (&f, &x1s, &y1s, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fadd (&t1, &z1s, &z1s, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fsub (&j, &f, &t1, c)) != 0) goto cleanup;

  if ((rc = bc_ed448_fsqr (&t1, &xys, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fsub (&t1, &t1, &x1s, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fsub (&t1, &t1, &y1s, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&r->x, &t1, &j, c)) != 0) goto cleanup;

  if ((rc = bc_ed448_fsub (&t2, &x1s, &y1s, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&r->y, &f, &t2, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&r->z, &f, &j, c)) != 0) goto cleanup;

cleanup:
  mbedtls_mpi_free (&x1s); mbedtls_mpi_free (&y1s); mbedtls_mpi_free (&z1s);
  mbedtls_mpi_free (&xys); mbedtls_mpi_free (&f); mbedtls_mpi_free (&j);
  mbedtls_mpi_free (&t1); mbedtls_mpi_free (&t2);
  return rc;
}

static int
bc_ed448_point_scalar_mul (bc_ed448_point *r, const bc_ed448_point *p,
                           const mbedtls_mpi *s, const bc_ed448_ctx *c)
{
  int rc = 0;
  bc_ed448_point acc, cur, tmp;
  bc_ed448_point_init (&acc);
  bc_ed448_point_init (&cur);
  bc_ed448_point_init (&tmp);

  if ((rc = bc_ed448_point_zero (&acc)) != 0) goto cleanup;
  if ((rc = bc_ed448_point_copy (&cur, p)) != 0) goto cleanup;

  size_t bits = mbedtls_mpi_bitlen (s);
  for (size_t i = 0; i < bits; i++)
    {
      if (mbedtls_mpi_get_bit (s, i))
        {
          if ((rc = bc_ed448_point_add (&tmp, &acc, &cur, c)) != 0) goto cleanup;
          if ((rc = bc_ed448_point_copy (&acc, &tmp)) != 0) goto cleanup;
        }
      if ((rc = bc_ed448_point_double (&tmp, &cur, c)) != 0) goto cleanup;
      if ((rc = bc_ed448_point_copy (&cur, &tmp)) != 0) goto cleanup;
    }
  rc = bc_ed448_point_copy (r, &acc);

cleanup:
  bc_ed448_point_free (&acc);
  bc_ed448_point_free (&cur);
  bc_ed448_point_free (&tmp);
  return rc;
}

static int
bc_ed448_point_decode (bc_ed448_point *r, const unsigned char enc[57],
                       const bc_ed448_ctx *c)
{
  int rc = 0;
  unsigned char yenc[57];
  mbedtls_mpi y2, num, den, deni, x2, chk, negx;
  mbedtls_mpi_init (&y2); mbedtls_mpi_init (&num); mbedtls_mpi_init (&den);
  mbedtls_mpi_init (&deni); mbedtls_mpi_init (&x2); mbedtls_mpi_init (&chk);
  mbedtls_mpi_init (&negx);

  memcpy (yenc, enc, sizeof yenc);
  int sign = (yenc[56] >> 7) & 1;
  yenc[56] &= 0x7f;
  if ((rc = mbedtls_mpi_read_binary_le (&r->y, yenc, sizeof yenc)) != 0) goto cleanup;
  if (mbedtls_mpi_cmp_mpi (&r->y, &c->p) >= 0) { rc = -1; goto cleanup; }

  if ((rc = bc_ed448_fsqr (&y2, &r->y, c)) != 0) goto cleanup;
  if ((rc = mbedtls_mpi_lset (&chk, 1)) != 0) goto cleanup;
  if ((rc = bc_ed448_fsub (&num, &y2, &chk, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&den, &c->d, &y2, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fsub (&den, &den, &chk, c)) != 0) goto cleanup;
  if (mbedtls_mpi_cmp_int (&den, 0) == 0) { rc = -1; goto cleanup; }
  if ((rc = bc_ed448_finv (&deni, &den, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&x2, &num, &deni, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fsqrt (&r->x, &x2, c)) != 0) goto cleanup;

  int xsign = mbedtls_mpi_get_bit (&r->x, 0);
  if (mbedtls_mpi_cmp_int (&r->x, 0) == 0 && sign != xsign)
    { rc = -1; goto cleanup; }
  if (xsign != sign)
    {
      if ((rc = bc_ed448_fneg (&negx, &r->x, c)) != 0) goto cleanup;
      if ((rc = mbedtls_mpi_copy (&r->x, &negx)) != 0) goto cleanup;
    }
  rc = mbedtls_mpi_lset (&r->z, 1);

cleanup:
  mbedtls_mpi_free (&y2); mbedtls_mpi_free (&num); mbedtls_mpi_free (&den);
  mbedtls_mpi_free (&deni); mbedtls_mpi_free (&x2); mbedtls_mpi_free (&chk);
  mbedtls_mpi_free (&negx);
  crypto_wipe (yenc, sizeof yenc);
  return rc == 0 ? 0 : -1;
}

static int
bc_ed448_point_eq (int *eq, const bc_ed448_point *a, const bc_ed448_point *b,
                   const bc_ed448_ctx *c)
{
  int rc = 0;
  mbedtls_mpi ax, bx, ay, by;
  mbedtls_mpi_init (&ax); mbedtls_mpi_init (&bx);
  mbedtls_mpi_init (&ay); mbedtls_mpi_init (&by);
  if ((rc = bc_ed448_fmul (&ax, &a->x, &b->z, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&bx, &b->x, &a->z, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&ay, &a->y, &b->z, c)) != 0) goto cleanup;
  if ((rc = bc_ed448_fmul (&by, &b->y, &a->z, c)) != 0) goto cleanup;
  *eq = (mbedtls_mpi_cmp_mpi (&ax, &bx) == 0 &&
         mbedtls_mpi_cmp_mpi (&ay, &by) == 0);
cleanup:
  mbedtls_mpi_free (&ax); mbedtls_mpi_free (&bx);
  mbedtls_mpi_free (&ay); mbedtls_mpi_free (&by);
  return rc;
}

static int
bc_ed448_hash_challenge (mbedtls_mpi *h, const unsigned char rraw[57],
                         const unsigned char araw[57],
                         const unsigned char *msg, size_t mlen,
                         const bc_ed448_ctx *c)
{
  static const unsigned char dom4[] = {
    'S','i','g','E','d','4','4','8', 0, 0
  };
  unsigned char out[114];
  int rc = 0;
  mbedtls_sha3_context sh;
  mbedtls_sha3_init (&sh);
  if ((rc = mbedtls_sha3_starts (&sh, MBEDTLS_SHA3_SHAKE256)) != 0) goto cleanup;
  if ((rc = mbedtls_sha3_update (&sh, dom4, sizeof dom4)) != 0) goto cleanup;
  if ((rc = mbedtls_sha3_update (&sh, rraw, 57)) != 0) goto cleanup;
  if ((rc = mbedtls_sha3_update (&sh, araw, 57)) != 0) goto cleanup;
  if (mlen && (rc = mbedtls_sha3_update (&sh, msg, mlen)) != 0) goto cleanup;
  if ((rc = mbedtls_sha3_finish (&sh, out, sizeof out)) != 0) goto cleanup;
  if ((rc = mbedtls_mpi_read_binary_le (h, out, sizeof out)) != 0) goto cleanup;
  rc = mbedtls_mpi_mod_mpi (h, h, &c->l);

cleanup:
  mbedtls_sha3_free (&sh);
  crypto_wipe (out, sizeof out);
  return rc == 0 ? 0 : -1;
}

static int
bc_ed448_verify_raw (const unsigned char pk[57], const unsigned char sig[114],
                     const unsigned char *msg, size_t mlen)
{
  int rc = 0, eq = 0;
  bc_ed448_ctx c;
  bc_ed448_point r, a, b, ah, rhs, lhs, tmp;
  mbedtls_mpi s, h;

  bc_ed448_ctx_init (&c);
  bc_ed448_point_init (&r);
  bc_ed448_point_init (&a);
  bc_ed448_point_init (&b);
  bc_ed448_point_init (&ah);
  bc_ed448_point_init (&rhs);
  bc_ed448_point_init (&lhs);
  bc_ed448_point_init (&tmp);
  mbedtls_mpi_init (&s);
  mbedtls_mpi_init (&h);

  if ((rc = bc_ed448_ctx_load (&c)) != 0) goto cleanup;
  if ((rc = bc_ed448_point_decode (&r, sig, &c)) != 0) goto invalid;
  if ((rc = bc_ed448_point_decode (&a, pk, &c)) != 0) goto invalid;
  if ((rc = mbedtls_mpi_read_binary_le (&s, sig + 57, 57)) != 0) goto cleanup;
  if (mbedtls_mpi_cmp_mpi (&s, &c.l) >= 0) goto invalid;
  if ((rc = bc_ed448_hash_challenge (&h, sig, pk, msg, mlen, &c)) != 0) goto cleanup;
  if ((rc = bc_ed448_point_base (&b, &c)) != 0) goto cleanup;
  if ((rc = bc_ed448_point_scalar_mul (&lhs, &b, &s, &c)) != 0) goto cleanup;
  if ((rc = bc_ed448_point_scalar_mul (&ah, &a, &h, &c)) != 0) goto cleanup;
  if ((rc = bc_ed448_point_add (&rhs, &r, &ah, &c)) != 0) goto cleanup;

  for (int i = 0; i < 2; i++)
    {
      if ((rc = bc_ed448_point_double (&tmp, &lhs, &c)) != 0) goto cleanup;
      if ((rc = bc_ed448_point_copy (&lhs, &tmp)) != 0) goto cleanup;
      if ((rc = bc_ed448_point_double (&tmp, &rhs, &c)) != 0) goto cleanup;
      if ((rc = bc_ed448_point_copy (&rhs, &tmp)) != 0) goto cleanup;
    }
  if ((rc = bc_ed448_point_eq (&eq, &lhs, &rhs, &c)) != 0) goto cleanup;
  rc = eq ? 0 : 1;
  goto cleanup;

invalid:
  rc = 1;

cleanup:
  bc_ed448_ctx_free (&c);
  bc_ed448_point_free (&r);
  bc_ed448_point_free (&a);
  bc_ed448_point_free (&b);
  bc_ed448_point_free (&ah);
  bc_ed448_point_free (&rhs);
  bc_ed448_point_free (&lhs);
  bc_ed448_point_free (&tmp);
  mbedtls_mpi_free (&s);
  mbedtls_mpi_free (&h);
  return rc;
}


static int
bc_ed448_verify (WORD_LIST *args)
{
  const char *pk_hex = NULL, *sig_hex = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (strcmp (w, "-k") == 0)
        { if (!p->next) { builtin_error ("-k needs PK_HEX"); return EX_USAGE; }
          p = p->next; pk_hex = p->word->word; }
      else if (strcmp (w, "-s") == 0)
        { if (!p->next) { builtin_error ("-s needs SIG_HEX"); return EX_USAGE; }
          p = p->next; sig_hex = p->word->word; }
      else { builtin_error ("unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!pk_hex || !sig_hex)
    { builtin_error ("ed448-verify needs -k PK_HEX -s SIG_HEX"); return EX_USAGE; }

  uint8_t pk[57], sig[114];
  if (bc_unhex (pk_hex, pk, sizeof pk) != 57)
    { builtin_error ("PK must be 57 bytes hex"); return EX_USAGE; }
  if (bc_unhex (sig_hex, sig, sizeof sig) != 114)
    { builtin_error ("SIG must be 114 bytes hex"); return EX_USAGE; }

  unsigned char *msg; size_t mlen;
  if (bc_slurp_fd (STDIN_FILENO, &msg, &mlen) < 0) return EXECUTION_FAILURE;
  int rc = bc_ed448_verify_raw (pk, sig, msg, mlen);
  free (msg);
  crypto_wipe (pk, sizeof pk);
  crypto_wipe (sig, sizeof sig);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* X25519 keygen; pub/shared are mbedTLS-backed below. */
static int
bc_x25519_keygen (WORD_LIST *args)
{
  int hex_out = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    if (strcmp (p->word->word, "-x") == 0) hex_out = 1;
    else { builtin_error ("unexpected arg: %s", p->word->word); return EX_USAGE; }
  unsigned char sk[32];
  if (bc_random_bytes (sk, 32) < 0) return EXECUTION_FAILURE;
  /* RFC 7748 clamping. */
  sk[0]  &= 248;
  sk[31] &= 127;
  sk[31] |= 64;
  return bc_emit (sk, 32, hex_out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}




/* Generic HKDF/PBKDF2 on the mbedTLS-backed hash/HMAC helpers. */
typedef struct {
  const char *name;
  size_t out_size;
  size_t block_size;
  int (*hmac)(const unsigned char *, size_t, const unsigned char *, size_t, unsigned char *);
} bc_mbed_hash_entry;

static const bc_mbed_hash_entry bc_mbed_hashes[] = {
  { "sha256", 32,  64, mbedtls_hmac_sha256 },
  { "sha384", 48, 128, mbedtls_hmac_sha384 },
  { "sha512", 64, 128, mbedtls_hmac_sha512 },
  { "sha1",   20,  64, mbedtls_hmac_sha1   },
  { "md5",    16,  64, mbedtls_hmac_md5    },
  { NULL, 0, 0, NULL }
};

static const bc_mbed_hash_entry *
bc_find_mbed_hash (const char *name)
{
  for (const bc_mbed_hash_entry *e = bc_mbed_hashes; e->name; e++)
    if (strcmp (e->name, name) == 0) return e;
  return NULL;
}

static int
bc_hkdf_mbed (const bc_mbed_hash_entry *he,
              const unsigned char *salt, size_t salt_len,
              const unsigned char *ikm, size_t ikm_len,
              const unsigned char *info, size_t info_len,
              unsigned char *out, size_t out_len)
{
  if (out_len == 0 || out_len > 255 * he->out_size) return -1;
  unsigned char zero_salt[128];
  if (!salt || salt_len == 0)
    { memset (zero_salt, 0, he->out_size); salt = zero_salt; salt_len = he->out_size; }
  unsigned char prk[64];
  if (he->hmac (salt, salt_len, ikm, ikm_len, prk) != 0) return -1;
  unsigned char t[64];
  size_t tlen = 0, pos = 0;
  unsigned int ctr = 1;
  while (pos < out_len)
    {
      unsigned char msg[64 + 256 + 1];
      if (tlen + info_len + 1 > sizeof msg) { crypto_wipe (msg, sizeof msg); return -1; }
      memcpy (msg, t, tlen);
      if (info_len) memcpy (msg + tlen, info, info_len);
      msg[tlen + info_len] = (unsigned char) ctr++;
      if (he->hmac (prk, he->out_size, msg, tlen + info_len + 1, t) != 0) { crypto_wipe (msg, sizeof msg); return -1; }
      tlen = he->out_size;
      size_t take = out_len - pos < tlen ? out_len - pos : tlen;
      memcpy (out + pos, t, take);
      pos += take;
      crypto_wipe (msg, sizeof msg);
    }
  crypto_wipe (prk, sizeof prk);
  crypto_wipe (t, sizeof t);
  return 0;
}

static int
bc_hkdf_cmd (WORD_LIST *args)
{
  int hex_out = 0;
  const char *hash_name = "sha256";
  const char *salt_hex = NULL, *ikm_hex = NULL, *info_hex = NULL;
  size_t out_len = 32;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (strcmp (w, "-x") == 0) hex_out = 1;
      else if (strcmp (w, "-a") == 0) { if (!p->next) { builtin_error("-a needs HASH"); return EX_USAGE; } p = p->next; hash_name = p->word->word; }
      else if (strcmp (w, "-s") == 0) { if (!p->next) { builtin_error("-s needs SALT"); return EX_USAGE; } p = p->next; salt_hex = p->word->word; }
      else if (strcmp (w, "-k") == 0) { if (!p->next) { builtin_error("-k needs IKM"); return EX_USAGE; } p = p->next; ikm_hex = p->word->word; }
      else if (strcmp (w, "-i") == 0) { if (!p->next) { builtin_error("-i needs INFO"); return EX_USAGE; } p = p->next; info_hex = p->word->word; }
      else if (strcmp (w, "-L") == 0) { if (!p->next) { builtin_error("-L needs LEN"); return EX_USAGE; } p = p->next; out_len = (size_t) atoi (p->word->word); }
      else { builtin_error ("unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!ikm_hex) { builtin_error ("hkdf needs -k IKM_HEX"); return EX_USAGE; }
  const bc_mbed_hash_entry *he = bc_find_mbed_hash (hash_name);
  if (!he) { builtin_error ("unknown hash: %s", hash_name); return EX_USAGE; }
  unsigned char salt[256], ikm[256], info[256];
  int slen = salt_hex ? bc_unhex (salt_hex, salt, sizeof salt) : 0;
  int ilen = bc_unhex (ikm_hex, ikm, sizeof ikm);
  int finlen = info_hex ? bc_unhex (info_hex, info, sizeof info) : 0;
  if (slen < 0 || ilen < 0 || finlen < 0) { builtin_error ("bad hex"); return EX_USAGE; }
  if (out_len == 0 || out_len > 1024 || out_len > 255 * he->out_size) { builtin_error ("LEN out of range"); return EX_USAGE; }
  unsigned char out[1024];
  if (bc_hkdf_mbed (he, salt, (size_t) slen, ikm, (size_t) ilen, info, (size_t) finlen, out, out_len) != 0)
    { crypto_wipe (out, sizeof out); builtin_error ("hkdf derive failed"); return EXECUTION_FAILURE; }
  int hkdf_rc = bc_emit (out, out_len, hex_out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  crypto_wipe (out, sizeof out);
  crypto_wipe (salt, sizeof salt);
  crypto_wipe (ikm, sizeof ikm);
  crypto_wipe (info, sizeof info);
  return hkdf_rc;
}

static int
bc_pbkdf2_cmd (WORD_LIST *args)
{
  int hex_out = 0;
  const char *hash_name = "sha256";
  const char *salt_hex = NULL, *password = NULL;
  int iter = 0;
  size_t out_len = 32;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (strcmp (w, "-x") == 0) hex_out = 1;
      else if (strcmp (w, "-a") == 0) { if (!p->next) { builtin_error("-a needs HASH"); return EX_USAGE; } p = p->next; hash_name = p->word->word; }
      else if (strcmp (w, "-s") == 0) { if (!p->next) { builtin_error("-s needs SALT"); return EX_USAGE; } p = p->next; salt_hex = p->word->word; }
      else if (strcmp (w, "-p") == 0) { if (!p->next) { builtin_error("-p needs PASSWORD"); return EX_USAGE; } p = p->next; password = p->word->word; }
      else if (strcmp (w, "-i") == 0) { if (!p->next) { builtin_error("-i needs ITER"); return EX_USAGE; } p = p->next; iter = atoi (p->word->word); }
      else if (strcmp (w, "-L") == 0) { if (!p->next) { builtin_error("-L needs LEN"); return EX_USAGE; } p = p->next; out_len = (size_t) atoi (p->word->word); }
      else { builtin_error ("unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!password || !salt_hex || iter <= 0 || out_len == 0)
    { builtin_error ("pbkdf2 needs -p PW -s SALT -i ITER -L LEN"); return EX_USAGE; }
  if (out_len > 1024 || iter > 10000000) { builtin_error ("pbkdf2 parameters out of range"); return EX_USAGE; }
  const bc_mbed_hash_entry *he = bc_find_mbed_hash (hash_name);
  if (!he) { builtin_error ("unknown hash: %s", hash_name); return EX_USAGE; }
  unsigned char salt[256];
  int slen = bc_unhex (salt_hex, salt, sizeof salt);
  if (slen < 0) { builtin_error ("bad hex in -s SALT"); return EX_USAGE; }
  unsigned char out[1024];
  size_t produced = 0;
  uint32_t block = 1;
  while (produced < out_len)
    {
      unsigned char U[64], T[64], msg[260];
      if ((size_t) slen + 4 > sizeof msg) return EX_USAGE;
      memcpy (msg, salt, (size_t) slen);
      msg[slen + 0] = (unsigned char) (block >> 24);
      msg[slen + 1] = (unsigned char) (block >> 16);
      msg[slen + 2] = (unsigned char) (block >> 8);
      msg[slen + 3] = (unsigned char) block;
      if (he->hmac ((const unsigned char *) password, strlen (password), msg, (size_t) slen + 4, U) != 0)
        { crypto_wipe (out, sizeof out); crypto_wipe (U, sizeof U); crypto_wipe (T, sizeof T); crypto_wipe (msg, sizeof msg); return EXECUTION_FAILURE; }
      memcpy (T, U, he->out_size);
      for (int j = 1; j < iter; j++)
        {
          if (he->hmac ((const unsigned char *) password, strlen (password), U, he->out_size, U) != 0)
            { crypto_wipe (out, sizeof out); crypto_wipe (U, sizeof U); crypto_wipe (T, sizeof T); crypto_wipe (msg, sizeof msg); return EXECUTION_FAILURE; }
          for (size_t k = 0; k < he->out_size; k++) T[k] ^= U[k];
        }
      size_t take = out_len - produced < he->out_size ? out_len - produced : he->out_size;
      memcpy (out + produced, T, take);
      produced += take;
      block++;
      crypto_wipe (U, sizeof U);
      crypto_wipe (T, sizeof T);
      crypto_wipe (msg, sizeof msg);
    }
  int pbkdf2_rc = bc_emit (out, out_len, hex_out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  crypto_wipe (out, sizeof out);
  return pbkdf2_rc;
}

static int
bc_random_cmd (WORD_LIST *args)
{
  int hex_out = 0;
  long n = -1;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (strcmp (w, "-x") == 0) hex_out = 1;
      else
        {
          char *end;
          long v = strtol (w, &end, 10);
          if (*end != '\0' || v <= 0 || v > 1024 * 1024)
            { builtin_error ("random: N must be 1..1048576"); return EX_USAGE; }
          n = v;
        }
    }
  if (n < 0) { builtin_error ("random: missing N"); return EX_USAGE; }
  unsigned char *buf = malloc ((size_t) n);
  if (!buf) { builtin_error ("malloc"); return EXECUTION_FAILURE; }
  if (bc_random_bytes (buf, (size_t) n) < 0) { free (buf); return EXECUTION_FAILURE; }
  int rc = bc_emit (buf, (size_t) n, hex_out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  free (buf);
  return rc;
}

/* ---- Secret handles (Stage 34) -------------------------------------- */

#define BC_SECRET_POOL_MAX 16
#define BC_SECRET_MAX 4096

typedef struct {
  int in_use;
  unsigned int gen;
  unsigned char *bytes;
  size_t len;
  size_t cap;
  int locked;
} bc_secret_slot;

static bc_secret_slot bc_secret_pool[BC_SECRET_POOL_MAX];
static unsigned int bc_secret_next_gen = 1;
static int bc_secret_atexit_registered = 0;

static void
bc_secret_free_slot (bc_secret_slot *s)
{
  if (!s->bytes)
    {
      memset (s, 0, sizeof *s);
      return;
    }
  crypto_wipe (s->bytes, s->cap);
  if (s->locked) munlock (s->bytes, s->cap);
  free (s->bytes);
  memset (s, 0, sizeof *s);
}

static void
bc_secret_cleanup (void)
{
  for (int i = 0; i < BC_SECRET_POOL_MAX; i++)
    bc_secret_free_slot (&bc_secret_pool[i]);
}

static int
bc_secret_parse_handle (const char *h, int *idx, unsigned int *gen)
{
  char *end = NULL;
  long i = strtol (h, &end, 10);
  if (end == h || *end != ':' || i < 0 || i >= BC_SECRET_POOL_MAX)
    return -1;
  char *gend = NULL;
  unsigned long g = strtoul (end + 1, &gend, 10);
  if (gend == end + 1 || *gend != '\0' || g == 0)
    return -1;
  *idx = (int) i;
  *gen = (unsigned int) g;
  return 0;
}

static bc_secret_slot *
bc_secret_get (const char *handle)
{
  int idx;
  unsigned int gen;
  if (bc_secret_parse_handle (handle, &idx, &gen) < 0)
    return NULL;
  bc_secret_slot *s = &bc_secret_pool[idx];
  if (!s->in_use || s->gen != gen || !s->bytes)
    return NULL;
  return s;
}

int
bashcrypto_secret_write_fd (const char *handle, int fd)
{
  bc_secret_slot *s = bc_secret_get (handle);
  if (!s)
    {
      builtin_error ("secret-write-fd: invalid handle");
      return -1;
    }
  const unsigned char *p = s->bytes;
  size_t left = s->len;
  while (left > 0)
    {
      ssize_t w = write (fd, p, left);
      if (w < 0 && errno == EINTR)
        continue;
      if (w < 0)
        {
          builtin_error ("secret-write-fd: write: %s", strerror (errno));
          return -1;
        }
      if (w == 0)
        {
          builtin_error ("secret-write-fd: short write");
          return -1;
        }
      p += w;
      left -= (size_t) w;
    }
  return 0;
}

static int
bc_secret_alloc (const unsigned char *bytes, size_t len, char *handle, size_t handle_sz)
{
  if (len > BC_SECRET_MAX)
    {
      builtin_error ("secret-read: secret too large");
      return -1;
    }
  int idx = -1;
  for (int i = 0; i < BC_SECRET_POOL_MAX; i++)
    if (!bc_secret_pool[i].in_use) { idx = i; break; }
  if (idx < 0)
    {
      builtin_error ("secret pool exhausted");
      return -1;
    }

  unsigned char *buf = malloc (BC_SECRET_MAX);
  if (!buf)
    {
      builtin_error ("secret alloc: %s", strerror (errno));
      return -1;
    }
  memset (buf, 0, BC_SECRET_MAX);
  memcpy (buf, bytes, len);

  bc_secret_slot *s = &bc_secret_pool[idx];
  bc_secret_free_slot (s);
  s->bytes = buf;
  s->len = len;
  s->cap = BC_SECRET_MAX;
  s->locked = (mlock (buf, BC_SECRET_MAX) == 0);
  s->in_use = 1;
  s->gen = bc_secret_next_gen++;
  if (bc_secret_next_gen == 0) bc_secret_next_gen = 1;

  if (!bc_secret_atexit_registered)
    {
      atexit (bc_secret_cleanup);
      bc_secret_atexit_registered = 1;
    }

  snprintf (handle, handle_sz, "%d:%u", idx, s->gen);
  return 0;
}

static int
bc_secret_read_bytes (const char *prompt, int no_echo, unsigned char *out, size_t *out_len)
{
  int fd = STDIN_FILENO;
  int close_fd = 0;
  FILE *prompt_fp = stderr;

  if (no_echo || prompt)
    {
      int tty = open ("/dev/tty", O_RDWR | O_CLOEXEC);
      if (tty >= 0)
        {
          fd = tty;
          close_fd = 1;
          int prompt_fd = dup (tty);
          if (prompt_fd >= 0) {
            FILE *fp = fdopen (prompt_fd, "w");
            if (fp) prompt_fp = fp;
            else close (prompt_fd);
          }
        }
    }

  struct termios oldt;
  int have_tty = 0;
  if (no_echo && tcgetattr (fd, &oldt) == 0)
    {
      struct termios nt = oldt;
      nt.c_lflag &= ~(ECHO);
      if (tcsetattr (fd, TCSAFLUSH, &nt) == 0)
        have_tty = 1;
    }

  if (prompt)
    {
      fputs (prompt, prompt_fp);
      fflush (prompt_fp);
    }

  size_t len = 0;
  while (len < BC_SECRET_MAX)
    {
      unsigned char c;
      ssize_t r = read (fd, &c, 1);
      if (r < 0)
        {
          if (errno == EINTR) continue;
          if (have_tty) tcsetattr (fd, TCSAFLUSH, &oldt);
          if (prompt_fp != stderr) fclose (prompt_fp);
          if (close_fd) close (fd);
          builtin_error ("secret-read: %s", strerror (errno));
          return -1;
        }
      if (r == 0 || c == '\n' || c == '\r')
        break;
      out[len++] = c;
    }

  if (have_tty)
    {
      tcsetattr (fd, TCSAFLUSH, &oldt);
      if (prompt) fputc ('\n', prompt_fp);
    }
  if (prompt_fp != stderr) fclose (prompt_fp);
  if (close_fd) close (fd);

  if (len == BC_SECRET_MAX)
    {
      builtin_error ("secret-read: secret too large");
      return -1;
    }
  *out_len = len;
  return 0;
}

static int
bc_argon2id_raw (const unsigned char *pass, size_t pass_len,
                 const unsigned char *salt, size_t salt_len,
                 uint32_t passes, uint32_t mem_kib, uint32_t lanes,
                 unsigned char *out, size_t out_len, int quiet_mlock)
{
  if (passes < 1 || lanes < 1 || mem_kib < 8 * lanes ||
      out_len == 0 || out_len > 1024 || salt_len < 8)
    return -1;

  return bashos_auth_argon2id_raw (pass, pass_len, salt, salt_len,
                                   passes, mem_kib, lanes, out, out_len,
                                   quiet_mlock, "crypto");
}

typedef struct {
  uint32_t passes;
  uint32_t mem_kib;
  uint32_t lanes;
  unsigned char salt[64];
  size_t salt_len;
  unsigned char hash[1024];
  size_t hash_len;
} bc_phc_argon2id;

static int
bc_parse_argon2id_phc (const char *phc, bc_phc_argon2id *out)
{
  memset (out, 0, sizeof *out);
  if (strncmp (phc, "$argon2id$v=19$m=", 17) != 0)
    return -1;
  const char *p = phc + 17;
  char *end = NULL;
  unsigned long m = strtoul (p, &end, 10);
  if (end == p || strncmp (end, ",t=", 3) != 0) return -1;
  p = end + 3;
  unsigned long t = strtoul (p, &end, 10);
  if (end == p || strncmp (end, ",p=", 3) != 0) return -1;
  p = end + 3;
  unsigned long lanes = strtoul (p, &end, 10);
  if (end == p || *end != '$') return -1;
  p = end + 1;

  const char *salt_end = strchr (p, '$');
  if (!salt_end) return -1;
  size_t salt_hex_len = (size_t) (salt_end - p);
  if (salt_hex_len == 0 || salt_hex_len >= sizeof out->salt * 2 + 1)
    return -1;
  char salt_hex[sizeof out->salt * 2 + 1];
  memcpy (salt_hex, p, salt_hex_len);
  salt_hex[salt_hex_len] = '\0';

  const char *hash_hex = salt_end + 1;
  size_t hash_hex_len = strlen (hash_hex);
  if (hash_hex_len == 0 || hash_hex_len > sizeof out->hash * 2)
    return -1;

  int slen = bc_unhex (salt_hex, out->salt, sizeof out->salt);
  int hlen = bc_unhex (hash_hex, out->hash, sizeof out->hash);
  if (slen < 8 || hlen <= 0)
    return -1;

  out->passes = (uint32_t) t;
  out->mem_kib = (uint32_t) m;
  out->lanes = (uint32_t) lanes;
  out->salt_len = (size_t) slen;
  out->hash_len = (size_t) hlen;
  if (out->passes < 1 || out->lanes < 1 || out->mem_kib < 8 * out->lanes)
    return -1;
  return 0;
}

static int
bc_secret_read_cmd (WORD_LIST *args)
{
  const char *var_name = NULL;
  const char *prompt = NULL;
  int no_echo = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-h") == 0)
        { if (!p->next) { builtin_error ("secret-read: -h needs VARNAME"); return EX_USAGE; } p = p->next; var_name = p->word->word; }
      else if (strcmp (w, "-p") == 0)
        { if (!p->next) { builtin_error ("secret-read: -p needs PROMPT"); return EX_USAGE; } p = p->next; prompt = p->word->word; }
      else if (strcmp (w, "--no-echo") == 0) no_echo = 1;
      else { builtin_error ("secret-read: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!var_name)
    {
      builtin_error ("secret-read needs -h VARNAME");
      return EX_USAGE;
    }

  unsigned char tmp[BC_SECRET_MAX];
  size_t len = 0;
  if (bc_secret_read_bytes (prompt, no_echo, tmp, &len) < 0)
    return EXECUTION_FAILURE;

  char handle[32];
  int rc = bc_secret_alloc (tmp, len, handle, sizeof handle);
  crypto_wipe (tmp, sizeof tmp);
  if (rc < 0) return EXECUTION_FAILURE;
  builtin_bind_variable ((char *) var_name, handle, 0);
  return EXECUTION_SUCCESS;
}

static int
bc_secret_scrub_cmd (WORD_LIST *args)
{
  if (!args || args->next)
    {
      builtin_error ("secret-scrub needs HANDLE");
      return EX_USAGE;
    }
  bc_secret_slot *s = bc_secret_get (args->word->word);
  if (!s)
    {
      builtin_error ("secret-scrub: invalid handle");
      return EXECUTION_FAILURE;
    }
  bc_secret_free_slot (s);
  return EXECUTION_SUCCESS;
}

static int
bc_secret_len_cmd (WORD_LIST *args)
{
  if (!args || args->next)
    {
      builtin_error ("secret-len needs HANDLE");
      return EX_USAGE;
    }
  bc_secret_slot *s = bc_secret_get (args->word->word);
  if (!s)
    {
      builtin_error ("secret-len: invalid handle");
      return EXECUTION_FAILURE;
    }
  printf ("%lu\n", (unsigned long) s->len);
  return EXECUTION_SUCCESS;
}

static int
bc_secret_verify_cmd (WORD_LIST *args)
{
  if (!args || !args->next || args->next->next)
    {
      builtin_error ("secret-verify needs HANDLE_A HANDLE_B");
      return EX_USAGE;
    }
  bc_secret_slot *a = bc_secret_get (args->word->word);
  bc_secret_slot *b = bc_secret_get (args->next->word->word);
  if (!a || !b) return EXECUTION_FAILURE;
  if (a->len != b->len) return EXECUTION_FAILURE;
  volatile unsigned char diff = 0;
  for (size_t i = 0; i < a->len; i++)
    diff |= (unsigned char) (a->bytes[i] ^ b->bytes[i]);
  return diff == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bc_secret_pwhash_cmd (WORD_LIST *args)
{
  const char *handle = NULL;
  uint32_t passes = 3, mem_kib = 65536, lanes = 1;
  size_t out_len = 32;
  int quiet_mlock = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-Q") == 0) quiet_mlock = 1;
      else if (strcmp (w, "-t") == 0) { if (!p->next) { builtin_error ("secret-pwhash: -t needs PASSES"); return EX_USAGE; } p = p->next; passes = (uint32_t) atoi (p->word->word); }
      else if (strcmp (w, "-m") == 0) { if (!p->next) { builtin_error ("secret-pwhash: -m needs MEM_KIB"); return EX_USAGE; } p = p->next; mem_kib = (uint32_t) atoi (p->word->word); }
      else if (strcmp (w, "-l") == 0) { if (!p->next) { builtin_error ("secret-pwhash: -l needs LANES"); return EX_USAGE; } p = p->next; lanes = (uint32_t) atoi (p->word->word); }
      else if (strcmp (w, "-L") == 0) { if (!p->next) { builtin_error ("secret-pwhash: -L needs LEN"); return EX_USAGE; } p = p->next; out_len = (size_t) atoi (p->word->word); }
      else if (!handle) handle = w;
      else { builtin_error ("secret-pwhash: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!handle)
    {
      builtin_error ("secret-pwhash needs HANDLE");
      return EX_USAGE;
    }
  bc_secret_slot *s = bc_secret_get (handle);
  if (!s) return EXECUTION_FAILURE;
  if (out_len == 0 || out_len > 1024 || passes < 1 || lanes < 1 || mem_kib < 8 * lanes)
    {
      builtin_error ("secret-pwhash: invalid Argon2id parameters");
      return EX_USAGE;
    }

  unsigned char salt[16], hash[1024];
  if (bc_random_bytes (salt, sizeof salt) < 0)
    return EXECUTION_FAILURE;
  if (bc_argon2id_raw (s->bytes, s->len, salt, sizeof salt, passes, mem_kib,
                       lanes, hash, out_len, quiet_mlock) < 0)
    return EXECUTION_FAILURE;

  printf ("$argon2id$v=19$m=%u,t=%u,p=%u$", mem_kib, passes, lanes);
  bc_print_hex (salt, sizeof salt);
  putchar ('$');
  bc_print_hex (hash, out_len);
  putchar ('\n');
  crypto_wipe (hash, sizeof hash);
  crypto_wipe (salt, sizeof salt);
  return EXECUTION_SUCCESS;
}

static int
bc_secret_pwverify_cmd (WORD_LIST *args)
{
  if (!args || !args->next || args->next->next)
    {
      builtin_error ("secret-pwverify needs HANDLE PHC");
      return EX_USAGE;
    }
  bc_secret_slot *s = bc_secret_get (args->word->word);
  if (!s) return EXECUTION_FAILURE;

  bc_phc_argon2id phc;
  if (bc_parse_argon2id_phc (args->next->word->word, &phc) < 0)
    {
      builtin_error ("secret-pwverify: unsupported or malformed PHC");
      return EX_USAGE;
    }

  unsigned char got[1024];
  if (bc_argon2id_raw (s->bytes, s->len, phc.salt, phc.salt_len,
                       phc.passes, phc.mem_kib, phc.lanes,
                       got, phc.hash_len, 1) < 0)
    return EXECUTION_FAILURE;

  volatile unsigned char diff = 0;
  for (size_t i = 0; i < phc.hash_len; i++)
    diff |= (unsigned char) (got[i] ^ phc.hash[i]);
  crypto_wipe (got, sizeof got);
  crypto_wipe (&phc, sizeof phc);
  return diff == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bc_secret_hkdf_cmd (WORD_LIST *args)
{
  const char *handle = NULL;
  const char *salt_hex = NULL;
  const char *info_hex = NULL;
  const char *var_name = NULL;
  size_t out_len = 32;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-S") == 0)
        { if (!p->next) { builtin_error ("secret-hkdf: -S needs SALT_HEX"); return EX_USAGE; } p = p->next; salt_hex = p->word->word; }
      else if (strcmp (w, "-I") == 0)
        { if (!p->next) { builtin_error ("secret-hkdf: -I needs INFO_HEX"); return EX_USAGE; } p = p->next; info_hex = p->word->word; }
      else if (strcmp (w, "-L") == 0)
        { if (!p->next) { builtin_error ("secret-hkdf: -L needs LEN"); return EX_USAGE; } p = p->next; out_len = (size_t) atoi (p->word->word); }
      else if (strcmp (w, "-h") == 0)
        { if (!p->next) { builtin_error ("secret-hkdf: -h needs VARNAME"); return EX_USAGE; } p = p->next; var_name = p->word->word; }
      else if (!handle) handle = w;
      else { builtin_error ("secret-hkdf: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!handle || !var_name)
    {
      builtin_error ("secret-hkdf needs HANDLE -h OUT_VAR");
      return EX_USAGE;
    }
  if (out_len == 0 || out_len > BC_SECRET_MAX)
    {
      builtin_error ("secret-hkdf: LEN must be 1..%d", BC_SECRET_MAX);
      return EX_USAGE;
    }
  bc_secret_slot *s = bc_secret_get (handle);
  if (!s) return EXECUTION_FAILURE;

  unsigned char salt[256], info[256];
  int salt_len = salt_hex ? bc_unhex (salt_hex, salt, sizeof salt) : 0;
  int info_len = info_hex ? bc_unhex (info_hex, info, sizeof info) : 0;
  if (salt_len < 0 || info_len < 0)
    {
      builtin_error ("secret-hkdf: bad hex");
      return EX_USAGE;
    }

  unsigned char *out = malloc (out_len);
  if (!out) { builtin_error ("secret-hkdf: malloc"); return EXECUTION_FAILURE; }
  const bc_mbed_hash_entry *he = bc_find_mbed_hash ("sha256");
  if (!he || bc_hkdf_mbed (he, salt, (size_t) salt_len, s->bytes, s->len,
                           info, (size_t) info_len, out, out_len) != 0)
    { free (out); builtin_error ("secret-hkdf: derive failed"); return EXECUTION_FAILURE; }

  char new_handle[32];
  int rc = bc_secret_alloc (out, out_len, new_handle, sizeof new_handle);
  crypto_wipe (out, out_len);
  free (out);
  if (rc < 0) return EXECUTION_FAILURE;
  builtin_bind_variable ((char *) var_name, new_handle, 0);
  return EXECUTION_SUCCESS;
}

/* ---- PEM / DER / X.509 (mbedTLS canonical) ----------------------- */

static int
bc_pem_to_der (const unsigned char *in, size_t inlen,
               const char *want_type,
               unsigned char **out, size_t *out_len, char *out_type)
{
  int is_pem = 0;
  for (size_t i = 0; i + 11 <= inlen && i < 64; i++)
    if (memcmp (in + i, "-----BEGIN ", 11) == 0) { is_pem = 1; break; }
  if (!is_pem)
    return -1;

  char type_buf[96];
  const char *type = want_type ? want_type : "CERTIFICATE";
  if (strlen (type) > 70) return -1;
  snprintf (type_buf, sizeof type_buf, "-----BEGIN %s-----", type);
  char footer[96];
  snprintf (footer, sizeof footer, "-----END %s-----", type);

  unsigned char *nul = malloc (inlen + 1);
  if (!nul) return -1;
  memcpy (nul, in, inlen);
  nul[inlen] = '\0';

  mbedtls_pem_context ctx;
  mbedtls_pem_init (&ctx);
  size_t used = 0, blen = 0;
  int rc = mbedtls_pem_read_buffer (&ctx, type_buf, footer, nul, NULL, 0, &used);
  char any_type[80];
  if (rc != 0 && !want_type)
    {
      const char *begin = strstr ((const char *) nul, "-----BEGIN ");
      const char *end = begin ? strstr (begin + 11, "-----") : NULL;
      if (begin && end && end > begin + 11 && (size_t)(end - (begin + 11)) < sizeof any_type)
        {
          size_t n = (size_t)(end - (begin + 11));
          memcpy (any_type, begin + 11, n); any_type[n] = '\0';
          snprintf (type_buf, sizeof type_buf, "-----BEGIN %s-----", any_type);
          snprintf (footer, sizeof footer, "-----END %s-----", any_type);
          mbedtls_pem_free (&ctx);
          mbedtls_pem_init (&ctx);
          rc = mbedtls_pem_read_buffer (&ctx, type_buf, footer, nul, NULL, 0, &used);
          type = any_type;
        }
    }
  free (nul);
  if (rc != 0)
    { mbedtls_pem_free (&ctx); return -1; }

  const unsigned char *buf = mbedtls_pem_get_buffer (&ctx, &blen);
  *out = malloc (blen ? blen : 1);
  if (!*out) { mbedtls_pem_free (&ctx); return -1; }
  memcpy (*out, buf, blen);
  *out_len = blen;
  if (out_type)
    {
      strncpy (out_type, type, 79);
      out_type[79] = '\0';
    }
  mbedtls_pem_free (&ctx);
  return 0;
}

static int
bc_pem_decode_cmd (WORD_LIST *args)
{
  const char *want_type = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-t") == 0)
        { if (!p->next) { builtin_error("-t needs TYPE"); return EX_USAGE; }
          p = p->next; want_type = p->word->word; }
      else { builtin_error ("unexpected arg: %s", w); return EX_USAGE; }
    }
  unsigned char *in; size_t inlen;
  if (bc_slurp_fd (STDIN_FILENO, &in, &inlen) < 0) return EXECUTION_FAILURE;
  int has_pem_header = 0;
  for (size_t i = 0; i + 11 <= inlen; i++)
    {
      if (memcmp (in + i, "-----BEGIN ", 11) == 0)
        { has_pem_header = 1; break; }
    }
  if (!has_pem_header)
    { free (in); builtin_error ("pem-decode: no matching object found"); return EXECUTION_FAILURE; }
  unsigned char *der; size_t derlen; char tname[80];
  if (bc_pem_to_der (in, inlen, want_type, &der, &derlen, tname) < 0)
    { free (in); builtin_error ("pem-decode: no matching object found"); return EXECUTION_FAILURE; }
  free (in);
  if (!want_type && tname[0]) fprintf (stderr, "pem-decode: extracted object type: %s\n", tname);
  int rc = bc_write_all (der, derlen) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  free (der);
  return rc;
}

static int
bc_pem_encode_cmd (WORD_LIST *args)
{
  const char *type_name = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-t") == 0)
        { if (!p->next) { builtin_error("-t needs TYPE"); return EX_USAGE; }
          p = p->next; type_name = p->word->word; }
      else { builtin_error ("unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!type_name) { builtin_error ("pem-encode requires -t TYPE"); return EX_USAGE; }
  unsigned char *in; size_t inlen;
  if (bc_slurp_fd (STDIN_FILENO, &in, &inlen) < 0) return EXECUTION_FAILURE;
  size_t b64_len = 0;
  mbedtls_base64_encode (NULL, 0, &b64_len, in, inlen);
  unsigned char *b64 = malloc (b64_len + 4);
  if (!b64) { free (in); builtin_error ("malloc"); return EXECUTION_FAILURE; }
  int rc = mbedtls_base64_encode (b64, b64_len + 4, &b64_len, in, inlen);
  free (in);
  if (rc != 0) { free (b64); builtin_error ("pem-encode: base64 failed"); return EXECUTION_FAILURE; }
  printf ("-----BEGIN %s-----\n", type_name);
  for (size_t i = 0; i < b64_len; i += 64)
    {
      size_t n = b64_len - i < 64 ? b64_len - i : 64;
      bc_write_all (b64 + i, n);
      putchar ('\n');
    }
  printf ("-----END %s-----\n", type_name);
  free (b64);
  return EXECUTION_SUCCESS;
}

/* ---- base64url (RFC 4648 §5) and PKCS#10 CSR ------------------------ *
 *
 * base64url is RFC 4648 §5: standard alphabet with `+` → `-` and `/` →
 * `_`, plus the option to strip `=` padding. Used by JWS/JOSE (RFC 7515)
 * which ACME's account-key signature requires.
 *
 * x509-csr emits a PKCS#10 (RFC 2986) certificate signing request with
 * an ECDSA-P256 public key + SAN extension listing the given domains,
 * signed with ECDSA-with-SHA256. The CSR is hand-rolled via mbedTLS
 * asn1_write_* helpers — adding upstream's full x509write_csr.c would
 * widen the link surface by ~3500 LoC (per the scope plan's risk
 * register), and PKCS#10 is structurally simple enough to compose
 * directly: a SubjectPublicKeyInfo, an attribute list with a SAN
 * extensionRequest, and an ECDSA signature over the encoded CRI body.
 */

/* Forward decl: defined later in this file (line ~1745). */
static size_t bc_ecdsa_raw_to_asn1_local (unsigned char *sig, size_t sig_len);

/* ASN.1 OID bodies (no tag/length, body only — mbedtls_asn1_write_oid
   prepends those). */
static const unsigned char BC_OID_EC_PUBLIC_KEY[]   = { 0x2a,0x86,0x48,0xce,0x3d,0x02,0x01 };          /* 1.2.840.10045.2.1 */
static const unsigned char BC_OID_PRIME256V1[]      = { 0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07 };     /* 1.2.840.10045.3.1.7 */
static const unsigned char BC_OID_ECDSA_W_SHA256[]  = { 0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02 };     /* 1.2.840.10045.4.3.2 */
static const unsigned char BC_OID_COMMON_NAME[]     = { 0x55,0x04,0x03 };                              /* 2.5.4.3 */
static const unsigned char BC_OID_EXT_REQUEST[]     = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x0e };/* 1.2.840.113549.1.9.14 */
static const unsigned char BC_OID_SUBJECT_ALT_NAME[] = { 0x55,0x1d,0x11 };                             /* 2.5.29.17 */

#define BC_ASN1_CHK(rc) do { int _r = (rc); if (_r < 0) return _r; total += (size_t)_r; } while (0)

/* `crypto base64url -e|-d [--pad|--no-pad]` — RFC 4648 §5.
 *
 * Encode: default no-pad (JOSE/JWS convention).  Pass `--pad` to keep
 *         the trailing `=` characters.
 * Decode: trailing `=` padding is optional on input; rejects characters
 *         outside the URL-safe alphabet.
 *
 * Bytes flow on stdin/stdout — no `-x` hex toggle since JWS payloads
 * are typically multi-line JSON, not hex.
 */
static int
bc_base64url_cmd (WORD_LIST *args)
{
  int encode = 0, decode = 0, pad = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (!strcmp (w, "-e") || !strcmp (w, "--encode")) encode = 1;
      else if (!strcmp (w, "-d") || !strcmp (w, "--decode")) decode = 1;
      else if (!strcmp (w, "--pad"))                          pad = 1;
      else if (!strcmp (w, "--no-pad"))                       pad = 0;
      else { builtin_error ("base64url: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (encode == decode)
    { builtin_error ("base64url: exactly one of -e or -d required"); return EX_USAGE; }

  unsigned char *in; size_t inlen;
  if (bc_slurp_fd (STDIN_FILENO, &in, &inlen) < 0) return EXECUTION_FAILURE;

  if (encode)
    {
      size_t b64_len = 0;
      mbedtls_base64_encode (NULL, 0, &b64_len, in, inlen);
      unsigned char *b64 = malloc (b64_len + 4);
      if (!b64) { free (in); builtin_error ("malloc"); return EXECUTION_FAILURE; }
      int rc = mbedtls_base64_encode (b64, b64_len + 4, &b64_len, in, inlen);
      free (in);
      if (rc != 0) { free (b64); builtin_error ("base64url: encode failed"); return EXECUTION_FAILURE; }
      size_t out_len = b64_len;
      for (size_t i = 0; i < out_len; i++)
        {
          if (b64[i] == '+') b64[i] = '-';
          else if (b64[i] == '/') b64[i] = '_';
        }
      if (!pad)
        while (out_len > 0 && b64[out_len - 1] == '=') out_len--;
      int wrc = bc_write_all (b64, out_len);
      free (b64);
      return wrc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }

  /* Decode: accept input with or without `=` padding. Pre-translate
     `-` → `+`, `_` → `/`, strip whitespace, then pad to a multiple of
     4 with `=` so mbedtls_base64_decode (standard-alphabet) accepts it. */
  unsigned char *norm = malloc (inlen + 4);
  if (!norm) { free (in); builtin_error ("malloc"); return EXECUTION_FAILURE; }
  size_t nlen = 0;
  for (size_t i = 0; i < inlen; i++)
    {
      unsigned char c = in[i];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
      if (c == '-') c = '+';
      else if (c == '_') c = '/';
      else if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='))
        { free (in); free (norm); builtin_error ("base64url: invalid char '%c'", in[i]); return EX_USAGE; }
      norm[nlen++] = c;
    }
  free (in);
  while (nlen % 4) norm[nlen++] = '=';
  size_t out_len = 0;
  mbedtls_base64_decode (NULL, 0, &out_len, norm, nlen);
  unsigned char *out = malloc (out_len ? out_len : 1);
  if (!out) { free (norm); builtin_error ("malloc"); return EXECUTION_FAILURE; }
  int rc = mbedtls_base64_decode (out, out_len, &out_len, norm, nlen);
  free (norm);
  if (rc != 0) { free (out); builtin_error ("base64url: decode failed"); return EXECUTION_FAILURE; }
  int wrc = bc_write_all (out, out_len);
  free (out);
  return wrc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* Build the CertificationRequestInfo (CRI) ASN.1 body backward into
   `buf` starting at the buffer end.  On success returns a pointer to
   the first encoded byte and writes the encoded length to *out_len.  */
static unsigned char *
bc_csr_build_cri (unsigned char *buf, size_t buf_sz,
                  const unsigned char pub65[65],
                  const char *cn,
                  const char *const *dns_names, size_t n_dns,
                  size_t *out_len)
{
  unsigned char *p = buf + buf_sz;
  size_t total = 0;
  int rc;

  /* --- attributes [0] SET extensionRequest SubjectAltName ---------- */
  /* GeneralNames ::= SEQUENCE OF GeneralName; dNSName is [2] IMPLICIT IA5String. */
  size_t gn_total = 0;
  for (size_t i = n_dns; i-- > 0; )
    {
      const char *d = dns_names[i];
      size_t dl = strlen (d);
      rc = mbedtls_asn1_write_raw_buffer (&p, buf, (const unsigned char *) d, dl);
      if (rc < 0) return NULL;
      gn_total += (size_t) rc;
      /* [2] IMPLICIT (context-specific primitive, tag number 2) */
      rc = mbedtls_asn1_write_len (&p, buf, dl);  if (rc < 0) return NULL; gn_total += (size_t) rc;
      rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2); if (rc < 0) return NULL; gn_total += (size_t) rc;
    }
  /* wrap GeneralNames as SEQUENCE */
  rc = mbedtls_asn1_write_len (&p, buf, gn_total); if (rc < 0) return NULL; gn_total += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (rc < 0) return NULL; gn_total += (size_t) rc;

  /* wrap GeneralNames bytes as OCTET STRING (extnValue) */
  size_t san_total = gn_total;
  rc = mbedtls_asn1_write_len (&p, buf, gn_total); if (rc < 0) return NULL; san_total += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_OCTET_STRING); if (rc < 0) return NULL; san_total += (size_t) rc;

  /* extnID OID = subjectAltName */
  rc = mbedtls_asn1_write_oid (&p, buf, (const char *) BC_OID_SUBJECT_ALT_NAME, sizeof BC_OID_SUBJECT_ALT_NAME);
  if (rc < 0) return NULL; san_total += (size_t) rc;

  /* wrap Extension as SEQUENCE { extnID, extnValue } */
  rc = mbedtls_asn1_write_len (&p, buf, san_total); if (rc < 0) return NULL; san_total += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (rc < 0) return NULL; san_total += (size_t) rc;

  /* wrap Extensions as SEQUENCE OF Extension */
  rc = mbedtls_asn1_write_len (&p, buf, san_total); if (rc < 0) return NULL; san_total += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (rc < 0) return NULL; san_total += (size_t) rc;

  /* wrap as SET (attribute value set) */
  rc = mbedtls_asn1_write_len (&p, buf, san_total); if (rc < 0) return NULL; san_total += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
  if (rc < 0) return NULL; san_total += (size_t) rc;

  /* prepend extensionRequest OID */
  rc = mbedtls_asn1_write_oid (&p, buf, (const char *) BC_OID_EXT_REQUEST, sizeof BC_OID_EXT_REQUEST);
  if (rc < 0) return NULL; san_total += (size_t) rc;

  /* wrap as SEQUENCE { OID extensionRequest, SET extensions } */
  rc = mbedtls_asn1_write_len (&p, buf, san_total); if (rc < 0) return NULL; san_total += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (rc < 0) return NULL; san_total += (size_t) rc;

  /* wrap the single attribute in [0] IMPLICIT SET (attributes field) */
  rc = mbedtls_asn1_write_len (&p, buf, san_total); if (rc < 0) return NULL; san_total += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0);
  if (rc < 0) return NULL; san_total += (size_t) rc;

  total += san_total;

  /* --- SubjectPublicKeyInfo --------------------------------------- */
  /* subjectPublicKey BIT STRING: 0x00 (unused-bits) || pub65.
     Writing backward, so first push the raw pub65, then the leading
     0x00, then the length (covering 66 bytes), then the BIT STRING tag. */
  size_t spki = 0;
  rc = mbedtls_asn1_write_raw_buffer (&p, buf, pub65, 65); if (rc < 0) return NULL; spki += (size_t) rc;
  if (p <= buf) return NULL;
  p--; *p = 0x00; spki += 1;       /* unused-bits prefix */
  rc = mbedtls_asn1_write_len (&p, buf, 66); if (rc < 0) return NULL; spki += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_BIT_STRING); if (rc < 0) return NULL; spki += (size_t) rc;

  /* AlgorithmIdentifier: SEQUENCE { OID ecPublicKey, OID prime256v1 } */
  /* parameter (named curve) — written first into the backward buffer */
  rc = mbedtls_asn1_write_oid (&p, buf, (const char *) BC_OID_PRIME256V1, sizeof BC_OID_PRIME256V1);
  if (rc < 0) return NULL;
  /* Note: mbedtls_asn1_write_algorithm_identifier's return value
     already includes par_len (the parameter bytes we just wrote), so
     do NOT add the prime256v1 write's rc to spki — the next call
     accounts for it. */
  rc = mbedtls_asn1_write_algorithm_identifier (&p, buf,
        (const char *) BC_OID_EC_PUBLIC_KEY, sizeof BC_OID_EC_PUBLIC_KEY,
        sizeof BC_OID_PRIME256V1 + 2);  /* parameters already written length */
  if (rc < 0) return NULL; spki += (size_t) rc;

  /* wrap SPKI as SEQUENCE */
  rc = mbedtls_asn1_write_len (&p, buf, spki); if (rc < 0) return NULL; spki += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (rc < 0) return NULL; spki += (size_t) rc;
  total += spki;

  /* --- subject Name (SEQUENCE OF SET OF AttributeTypeAndValue) ---- */
  size_t subj = 0;
  size_t cnlen = strlen (cn);
  rc = mbedtls_asn1_write_utf8_string (&p, buf, cn, cnlen);
  if (rc < 0) return NULL; subj += (size_t) rc;
  rc = mbedtls_asn1_write_oid (&p, buf, (const char *) BC_OID_COMMON_NAME, sizeof BC_OID_COMMON_NAME);
  if (rc < 0) return NULL; subj += (size_t) rc;
  rc = mbedtls_asn1_write_len (&p, buf, subj); if (rc < 0) return NULL; subj += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (rc < 0) return NULL; subj += (size_t) rc;     /* AttributeTypeAndValue */
  rc = mbedtls_asn1_write_len (&p, buf, subj); if (rc < 0) return NULL; subj += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
  if (rc < 0) return NULL; subj += (size_t) rc;     /* RDN */
  rc = mbedtls_asn1_write_len (&p, buf, subj); if (rc < 0) return NULL; subj += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (rc < 0) return NULL; subj += (size_t) rc;     /* Name */
  total += subj;

  /* --- version (INTEGER 0) ---------------------------------------- */
  rc = mbedtls_asn1_write_int (&p, buf, 0); if (rc < 0) return NULL;
  total += (size_t) rc;

  /* wrap CRI as SEQUENCE */
  rc = mbedtls_asn1_write_len (&p, buf, total); if (rc < 0) return NULL; total += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (rc < 0) return NULL; total += (size_t) rc;

  *out_len = total;
  return p;
}

/* SHA-256 a buffer (slot-init streaming since we don't have a one-shot
   helper). */
static int
bc_sha256_buf (const unsigned char *in, size_t ilen, unsigned char out[32])
{
  mbedtls_sha256_context hc;
  mbedtls_sha256_init (&hc);
  int rc = mbedtls_sha256_starts (&hc, 0);
  if (rc == 0) rc = mbedtls_sha256_update (&hc, in, ilen);
  if (rc == 0) rc = mbedtls_sha256_finish (&hc, out);
  mbedtls_sha256_free (&hc);
  return rc;
}

/* `crypto x509-csr -k SK_HEX -d DOMAIN [-d DOMAIN ...] [--cn CN] [--der]`
 *
 * Produce a PKCS#10 (RFC 2986) CSR for an ECDSA-P256 key with a SAN
 * extension listing the given domains.  Default output is PEM
 * (`-----BEGIN CERTIFICATE REQUEST-----`); `--der` emits raw DER on
 * stdout (use for direct ACME `finalize` upload).
 *
 * If `--cn CN` is omitted, the Subject CommonName is the first `-d`
 * domain (mirrors openssl req's default-from-SAN behaviour).
 */
static int
bc_x509_csr_cmd (WORD_LIST *args)
{
  const char *sk_hex = NULL, *cn = NULL;
  const char *dns[32];
  size_t n_dns = 0;
  int want_der = 0;

  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-k"))
        { if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
          p = p->next; sk_hex = p->word->word; }
      else if (!strcmp (w, "-d"))
        { if (!p->next) { builtin_error ("-d needs DOMAIN"); return EX_USAGE; }
          p = p->next;
          if (n_dns >= sizeof dns / sizeof dns[0])
            { builtin_error ("x509-csr: too many -d domains (max %zu)", sizeof dns / sizeof dns[0]); return EX_USAGE; }
          dns[n_dns++] = p->word->word; }
      else if (!strcmp (w, "--cn") || !strcmp (w, "-n"))
        { if (!p->next) { builtin_error ("--cn needs CN"); return EX_USAGE; }
          p = p->next; cn = p->word->word; }
      else if (!strcmp (w, "--der"))
        want_der = 1;
      else
        { builtin_error ("x509-csr: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!sk_hex) { builtin_error ("x509-csr: -k SK_HEX required (32-byte ECDSA-P256 private key)"); return EX_USAGE; }
  if (n_dns == 0) { builtin_error ("x509-csr: at least one -d DOMAIN required"); return EX_USAGE; }

  unsigned char sk[32], pub[65];
  if (bc_unhex (sk_hex, sk, sizeof sk) != 32)
    { builtin_error ("x509-csr: SK must be 32 bytes hex"); return EX_USAGE; }
  if (mbedtls_ecdsa_p256_public (pub, sk) != 0)
    { builtin_error ("x509-csr: invalid private key"); return EXECUTION_FAILURE; }

  if (!cn) cn = dns[0];

  /* 8 KB scratch buffer — generous for one CN + up to 32 SANs. */
  unsigned char scratch[8192];
  size_t cri_len = 0;
  unsigned char *cri = bc_csr_build_cri (scratch, sizeof scratch,
                                         pub, cn, dns, n_dns, &cri_len);
  if (!cri) { builtin_error ("x509-csr: ASN.1 encode failed (buffer too small?)"); return EXECUTION_FAILURE; }

  /* Hash + sign the CRI body. */
  unsigned char digest[32];
  if (bc_sha256_buf (cri, cri_len, digest) != 0)
    { builtin_error ("x509-csr: sha256 failed"); return EXECUTION_FAILURE; }

  unsigned char sig_raw[64], sig_der[80];
  if (mbedtls_ecdsa_p256_sign_raw (sig_raw, sk, digest, 32) != 0)
    { builtin_error ("x509-csr: sign failed"); return EXECUTION_FAILURE; }
  memcpy (sig_der, sig_raw, 64);
  size_t sig_der_len = bc_ecdsa_raw_to_asn1_local (sig_der, 64);
  if (sig_der_len == 0)
    { builtin_error ("x509-csr: signature ASN.1 conversion failed"); return EXECUTION_FAILURE; }

  /* Compose the final CertificationRequest SEQUENCE.  We can't write
     it backward into `scratch` because `cri` already occupies the tail
     and its absolute position must not shift (we hash the original
     bytes).  Build a second scratch and memcpy.  */
  unsigned char outbuf[10240];
  unsigned char *q = outbuf + sizeof outbuf;
  size_t outer = 0;
  int rc;

  /* signature BIT STRING: 0x00 unused-bits || sig_der bytes.
     Same backward-write convention as the SPKI BIT STRING above: raw,
     then the 0x00 prefix, then length, then tag. */
  rc = mbedtls_asn1_write_raw_buffer (&q, outbuf, sig_der, sig_der_len); if (rc < 0) goto enc_fail;
  outer += (size_t) rc;
  if (q <= outbuf) goto enc_fail;
  q--; *q = 0x00; outer += 1;
  rc = mbedtls_asn1_write_len (&q, outbuf, sig_der_len + 1); if (rc < 0) goto enc_fail;
  outer += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&q, outbuf, MBEDTLS_ASN1_BIT_STRING); if (rc < 0) goto enc_fail;
  outer += (size_t) rc;

  /* signatureAlgorithm SEQUENCE { OID ecdsaWithSHA256 } (no params) */
  rc = mbedtls_asn1_write_algorithm_identifier_ext (&q, outbuf,
        (const char *) BC_OID_ECDSA_W_SHA256, sizeof BC_OID_ECDSA_W_SHA256,
        0, 0);
  if (rc < 0) goto enc_fail;
  outer += (size_t) rc;

  /* CRI bytes verbatim */
  rc = mbedtls_asn1_write_raw_buffer (&q, outbuf, cri, cri_len); if (rc < 0) goto enc_fail;
  outer += (size_t) rc;

  /* wrap as outer SEQUENCE */
  rc = mbedtls_asn1_write_len (&q, outbuf, outer); if (rc < 0) goto enc_fail;
  outer += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&q, outbuf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (rc < 0) goto enc_fail;
  outer += (size_t) rc;

  if (want_der)
    return bc_write_all (q, outer) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;

  /* PEM-wrap. */
  size_t b64_len = 0;
  mbedtls_base64_encode (NULL, 0, &b64_len, q, outer);
  unsigned char *b64 = malloc (b64_len + 4);
  if (!b64) { builtin_error ("malloc"); return EXECUTION_FAILURE; }
  if (mbedtls_base64_encode (b64, b64_len + 4, &b64_len, q, outer) != 0)
    { free (b64); builtin_error ("x509-csr: base64 failed"); return EXECUTION_FAILURE; }
  printf ("-----BEGIN CERTIFICATE REQUEST-----\n");
  for (size_t i = 0; i < b64_len; i += 64)
    {
      size_t n = b64_len - i < 64 ? b64_len - i : 64;
      bc_write_all (b64 + i, n);
      putchar ('\n');
    }
  printf ("-----END CERTIFICATE REQUEST-----\n");
  free (b64);
  return EXECUTION_SUCCESS;

enc_fail:
  builtin_error ("x509-csr: outer ASN.1 encode failed");
  return EXECUTION_FAILURE;
}

static const char *sig_alg_name(mbedtls_sig_alg_t a);

static int
bc_x509_info_cmd (WORD_LIST *args)
{
  (void) args;
  unsigned char *in; size_t inlen;
  if (bc_slurp_fd (STDIN_FILENO, &in, &inlen) < 0) return EXECUTION_FAILURE;
  unsigned char *der = NULL; size_t derlen = 0;
  if (bc_pem_to_der (in, inlen, "CERTIFICATE", &der, &derlen, NULL) < 0)
    { der = malloc (inlen ? inlen : 1); if (!der) { free (in); return EXECUTION_FAILURE; } memcpy (der, in, inlen); derlen = inlen; }
  free (in);
  mbedtls_x509_crt_min crt;
  int rc = mbedtls_x509_crt_min_parse (der, derlen, &crt);
  if (rc != 0) { free (der); builtin_error ("x509-info: decode error code=%d", rc); return EXECUTION_FAILURE; }
  printf ("key_type:        %s\n", crt.pk_type == MBEDTLS_PK_RSA ? "RSA" : crt.pk_type == MBEDTLS_PK_ECDSA ? "EC" : "unknown");
  if (crt.pk_type == MBEDTLS_PK_RSA)
    { printf ("rsa_modulus_bits: %zu\n", crt.rsa_n.len * 8); printf ("rsa_e_len:       %zu bytes\n", crt.rsa_e.len); }
  else if (crt.pk_type == MBEDTLS_PK_ECDSA)
    { printf ("ec_qlen:         %zu bytes\n", crt.ec_pub.len); }
  printf ("signer_hash:     %s\n", sig_alg_name (crt.sig_alg));
  printf ("isCA:            unknown\n");
  printf ("subject_dn_len:  %zu bytes (raw ASN.1)\n", crt.subject.len);
  if (crt.subject.len > 0)
    { printf ("subject_dn_hex:  "); bc_print_hex (crt.subject.p, crt.subject.len); putchar ('\n'); }
  free (der);
  return EXECUTION_SUCCESS;
}

static int
bc_tcp_connect_timeout (const char *host, int port, int timeout_ms)
{
  char portstr[8];
  snprintf (portstr, sizeof portstr, "%d", port);
  struct addrinfo hints = { 0 }, *res = NULL;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  /* getaddrinfo can return EAI_AGAIN — a *temporary* resolver failure that
   * literally means "try again". Under QEMU slirp the built-in DNS forwarder is
   * intermittently flaky on some names (e.g. downloads.claude.ai EAI_AGAINs on
   * one query but resolves on a retry), which otherwise fails the whole TLS
   * connection (curl: "tls subshell failed"). Retry a few times with a short
   * backoff; permanent errors (EAI_NONAME, ...) still fail at once.
   * BASHCRYPTO_DNS_RETRIES tunes the attempt count (default 6, range 1-20). */
  int gerr;
  int dns_tries = 6;
  { const char *e = getenv ("BASHCRYPTO_DNS_RETRIES");
    if (e && *e) { int v = atoi (e); if (v >= 1 && v <= 20) dns_tries = v; } }
  for (int attempt = 0; ; attempt++)
    {
      res = NULL;
      gerr = getaddrinfo (host, portstr, &hints, &res);
      if (gerr != EAI_AGAIN || attempt + 1 >= dns_tries) break;
      int ms = 200 + attempt * 200; if (ms > 1000) ms = 1000;  /* 200,400,..,1000 */
      poll (NULL, 0, ms);
    }
  if (gerr != 0) { builtin_error ("getaddrinfo(%s:%d): %s", host, port, gai_strerror (gerr)); return -1; }
  int fd = -1;
  for (struct addrinfo *p = res; p; p = p->ai_next)
    {
      fd = socket (p->ai_family, p->ai_socktype, p->ai_protocol);
      if (fd < 0) continue;
      if (timeout_ms <= 0)
        {
          if (connect (fd, p->ai_addr, p->ai_addrlen) == 0) break;
          close (fd); fd = -1;
          continue;
        }

      int flags = fcntl (fd, F_GETFL, 0);
      if (flags < 0 || fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
        { close (fd); fd = -1; continue; }
      if (connect (fd, p->ai_addr, p->ai_addrlen) == 0)
        {
          (void) fcntl (fd, F_SETFL, flags);
          break;
        }
      if (errno == EINPROGRESS)
        {
          struct pollfd pf = { .fd = fd, .events = POLLOUT };
          int pr;
          do { pr = poll (&pf, 1, timeout_ms); } while (pr < 0 && errno == EINTR);
          if (pr > 0)
            {
              int soerr = 0;
              socklen_t sl = sizeof soerr;
              if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) == 0 && soerr == 0)
                {
                  (void) fcntl (fd, F_SETFL, flags);
                  break;
                }
              if (soerr) errno = soerr;
            }
          else if (pr == 0)
            errno = ETIMEDOUT;
        }
      close (fd); fd = -1;
    }
  freeaddrinfo (res);
  if (fd < 0) { builtin_error ("connect %s:%d: %s", host, port, strerror (errno)); return -1; }
  return fd;
}

static int
bc_set_socket_timeout_ms (int fd, int timeout_ms)
{
  if (timeout_ms <= 0)
    return 0;
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  if (setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0 ||
      setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) < 0)
    {
      builtin_error ("tls connect: set socket timeout: %s", strerror (errno));
      return -1;
    }
  return 0;
}

static int
bc_slurp_fd_cap (int fd, unsigned char **out_buf, size_t *out_len, size_t cap_limit)
{
  size_t cap = 4096, len = 0;
  if (cap_limit > 0 && cap > cap_limit)
    cap = cap_limit;
  unsigned char *buf = malloc (cap ? cap : 1);
  if (!buf) { builtin_error ("malloc"); return -1; }
  for (;;)
    {
      if (cap_limit > 0 && len >= cap_limit)
        {
          unsigned char probe;
          ssize_t r;
          do { r = read (fd, &probe, 1); } while (r < 0 && errno == EINTR);
          if (r > 0)
            {
              free (buf);
              builtin_error ("tls connect: stdin exceeds --max-request=%zu", cap_limit);
              return -1;
            }
          if (r < 0)
            {
              free (buf);
              builtin_error ("read: %s", strerror (errno));
              return -1;
            }
          break;
        }
      if (len == cap)
        {
          size_t ncap = cap * 2;
          if (cap_limit > 0 && ncap > cap_limit)
            ncap = cap_limit;
          if (ncap <= cap)
            ncap = cap + 1;
          unsigned char *n = realloc (buf, ncap);
          if (!n) { free (buf); builtin_error ("realloc"); return -1; }
          buf = n;
          cap = ncap;
        }
      size_t want = cap - len;
      if (cap_limit > 0 && want > cap_limit - len)
        want = cap_limit - len;
      ssize_t r = read (fd, buf + len, want);
      if (r < 0)
        {
          if (errno == EINTR) continue;
          free (buf); builtin_error ("read: %s", strerror (errno));
          return -1;
        }
      if (r == 0) break;
      len += (size_t) r;
    }
  *out_buf = buf;
  *out_len = len;
  return 0;
}

/* ============================================================== *
 * Stage 19: mbedTLS TLS-1.2/1.3 client implementation.           *
 *                                                                 *
 * Wires the upstream mbedtls_ssl_* state machine through the same *
 * --print-cipher / -c CA_PEM / -s SNI / -k surface as the legacy  *
 * client. mbedTLS is now the only TLS backend.                    *
 * ============================================================== */

#include "_mbedtls_ssl.h"
#include "_mbedtls_ssl_ciphersuites.h"
#include "_mbedtls_x509_crt.h"
#include "_mbedtls_net_sockets.h"
#include "_mbedtls_error.h"
#include "_mbedtls_crypto.h"
#include "_bashldap_tls.h"

/* I/O callbacks for mbedtls_ssl_set_bio. The opaque ctx is a `int *`
   pointing at the TCP socket fd. Returns bytes read/written or a
   negative MBEDTLS_ERR_SSL_WANT_* on EAGAIN. */
static int
bc_mbedtls_recv (void *ctx, unsigned char *buf, size_t len)
{
    int fd = (int) (intptr_t) ctx;
    ssize_t n;
    do { n = read (fd, buf, len); } while (n < 0 && errno == EINTR);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return (int) n;
}

static int
bc_mbedtls_send (void *ctx, const unsigned char *buf, size_t len)
{
    int fd = (int) (intptr_t) ctx;
    ssize_t n;
    do { n = write (fd, buf, len); } while (n < 0 && errno == EINTR);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return (int) n;
}

int
bc_tls_handshake (int sock, const char *sni, const char *ca_path, int insecure,
                  mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf,
                  mbedtls_x509_crt *ca)
{
  psa_status_t psa_rc = psa_crypto_init ();
  if (psa_rc != PSA_SUCCESS) {
      builtin_error ("tls-mbedtls: psa init failed (%d)", (int) psa_rc);
      return -1;
  }

  /* Trust anchors. Auto-load /etc/ssl/cert.pem (full+ inheritance) when
     -c is unset. */
  const char *ca_real = ca_path;
  if (!ca_real && !insecure) {
      if (access ("/etc/ssl/cert.pem", R_OK) == 0)
          ca_real = "/etc/ssl/cert.pem";
      else if (access ("/etc/ssl/certs/ca-certificates.crt", R_OK) == 0)
          ca_real = "/etc/ssl/certs/ca-certificates.crt";
  }
  if (ca_real) {
      int ca_rc = mbedtls_x509_crt_parse_file (ca, ca_real);
      if (ca_rc < 0) {
          builtin_error ("tls-mbedtls: failed to parse CA bundle %s (rc=%d)", ca_real, ca_rc);
          return -1;
      }
  } else if (!insecure) {
      builtin_error ("tls-mbedtls: no trust anchors. Pass -c CA_PEM or rely on /etc/ssl/cert.pem.");
      return -1;
  }

  if (mbedtls_ssl_config_defaults (conf, MBEDTLS_SSL_IS_CLIENT,
                                   MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
      builtin_error ("tls-mbedtls: config_defaults failed");
      return -1;
  }
  mbedtls_ssl_conf_authmode (conf,
      insecure ? MBEDTLS_SSL_VERIFY_NONE : MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain (conf, ca, NULL);

  int setup_rc = mbedtls_ssl_setup (ssl, conf);
  if (setup_rc != 0) {
      builtin_error ("tls-mbedtls: ssl_setup failed (rc=%d)", setup_rc);
      return -1;
  }
  if (mbedtls_ssl_set_hostname (ssl, sni) != 0) {
      builtin_error ("tls-mbedtls: set_hostname failed");
      return -1;
  }
  mbedtls_ssl_set_bio (ssl, (void *) (intptr_t) sock, bc_mbedtls_send, bc_mbedtls_recv, NULL);

  int hs;
  while ((hs = mbedtls_ssl_handshake (ssl)) != 0) {
      if (hs == MBEDTLS_ERR_SSL_WANT_READ || hs == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      char buf[128];
      uint32_t vr = mbedtls_ssl_get_verify_result (ssl);
      mbedtls_strerror (hs, buf, sizeof buf);
      builtin_error ("tls-mbedtls: handshake failed: %s (-0x%04x) state=%d verify=0x%08x", buf, -hs, ssl->MBEDTLS_PRIVATE(state), (unsigned) vr);
      /* When the certificate-chain verifier produced flags, decode them
         to human-readable strings so operators don't have to interpret
         the bitmask by hand. mbedtls_x509_crt_verify_info emits one
         "<prefix><reason>\n" line per bit set (expired / CN-mismatch /
         not-trusted / revoked / unknown-CA / ...). 0xFFFFFFFFu is
         "no verify result available" — skip in that case. */
      if (vr != 0 && vr != (uint32_t) -1) {
          char vrbuf[512];
          int vrlen = mbedtls_x509_crt_verify_info (vrbuf, sizeof vrbuf,
                                                    "tls-mbedtls: verify: ", vr);
          if (vrlen > 0) {
              /* verify_info NUL-terminates and includes trailing newlines.
                 Write the whole buffer in one shot to stderr. */
              fwrite (vrbuf, 1, (size_t) vrlen, stderr);
          }
      }
      return -1;
  }

  return 0;
}

/* mbedTLS TLS-1.2/1.3 client. */
static int
bc_tls_connect_mbedtls_cmd (WORD_LIST *args)
{
  const char *host_port = NULL;
  const char *ca_path = NULL;
  const char *sni = NULL;
  int insecure = 0;
  int print_cipher = 0;
  int io_timeout_ms = 0;
  size_t max_request = 1024 * 1024;

  for (WORD_LIST *p = args; p; p = p->next) {
      const char *w = p->word->word;
      if      (strcmp (w, "-c") == 0) { if (!p->next) { builtin_error("-c needs CA_PEM"); return EX_USAGE; } p = p->next; ca_path = p->word->word; }
      else if (strcmp (w, "-s") == 0) { if (!p->next) { builtin_error("-s needs SNI"); return EX_USAGE; } p = p->next; sni = p->word->word; }
      else if (strcmp (w, "-k") == 0) insecure = 1;
      else if (strcmp (w, "--print-cipher") == 0) print_cipher = 1;
      else if (strcmp (w, "--read-timeout") == 0 || strcmp (w, "--connect-timeout") == 0)
        {
          char *end = NULL;
          long v;
          if (!p->next) { builtin_error ("%s needs MS", w); return EX_USAGE; }
          p = p->next;
          errno = 0;
          v = strtol (p->word->word, &end, 10);
          if (errno || !end || *end || v < 0 || v > 3600000)
            { builtin_error ("%s must be 0..3600000 milliseconds", w); return EX_USAGE; }
          io_timeout_ms = (int) v;
        }
      else if (strcmp (w, "--max-request") == 0)
        {
          char *end = NULL;
          unsigned long long v;
          if (!p->next) { builtin_error ("--max-request needs BYTES"); return EX_USAGE; }
          p = p->next;
          errno = 0;
          v = strtoull (p->word->word, &end, 10);
          if (errno || !end || *end || v > 64ULL * 1024ULL * 1024ULL)
            { builtin_error ("--max-request must be 0..67108864 bytes"); return EX_USAGE; }
          max_request = (size_t) v;
        }
      else if (host_port == NULL)     host_port = w;
      else { builtin_error ("unexpected arg: %s", w); return EX_USAGE; }
  }
  if (!host_port) { builtin_error ("tls connect HOST:PORT required"); return EX_USAGE; }

  /* Split HOST:PORT. */
  char host[256] = { 0 };
  int port = 0;
  const char *colon = strrchr (host_port, ':');
  if (!colon) { builtin_error ("tls connect: HOST:PORT format expected"); return EX_USAGE; }
  size_t hlen = (size_t) (colon - host_port);
  if (hlen >= sizeof host) { builtin_error ("host too long"); return EX_USAGE; }
  memcpy (host, host_port, hlen); host[hlen] = '\0';
  port = atoi (colon + 1);
  if (port <= 0 || port > 65535) { builtin_error ("bad port: %s", colon + 1); return EX_USAGE; }
  if (!sni) sni = host;

  /* Slurp a bounded request from stdin. The default 1 MiB cap prevents an
     accidental huge pipe from turning TLS connect into unbounded heap growth;
     --max-request 0 restores the old unbounded behavior for explicit callers. */
  unsigned char *req; size_t req_len;
  if (bc_slurp_fd_cap (STDIN_FILENO, &req, &req_len, max_request) < 0) return EXECUTION_FAILURE;

  /* TCP connect. */
  int sock = bc_tcp_connect_timeout (host, port, io_timeout_ms);
  if (sock < 0) { free (req); return EXECUTION_FAILURE; }
  if (bc_set_socket_timeout_ms (sock, io_timeout_ms) < 0)
    { free (req); close (sock); return EXECUTION_FAILURE; }

  /* mbedTLS context init. */
  mbedtls_ssl_context     ssl;
  mbedtls_ssl_config      conf;
  mbedtls_x509_crt        ca;

  mbedtls_ssl_init (&ssl);
  mbedtls_ssl_config_init (&conf);
  mbedtls_x509_crt_init (&ca);

  int rc = EXECUTION_SUCCESS;
  if (bc_tls_handshake (sock, sni, ca_path, insecure, &ssl, &conf, &ca) < 0)
    { rc = EXECUTION_FAILURE; goto cleanup; }

  if (print_cipher) {
      const char *cs = mbedtls_ssl_get_ciphersuite (&ssl);
      int csid = mbedtls_ssl_get_ciphersuite_id (cs ? cs : "");
      fprintf (stderr, "tls: cipher_suite=0x%04X %s\n",
               (unsigned) csid, cs ? cs : "(unknown)");
  }

  /* Send request. */
  size_t off = 0;
  while (off < req_len) {
      int w = mbedtls_ssl_write (&ssl, req + off, req_len - off);
      if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      if (w < 0) {
          builtin_error ("tls-mbedtls: write failed (-0x%04x)", -w);
          rc = EXECUTION_FAILURE; goto cleanup;
      }
      off += (size_t) w;
  }

  /* Read response until close_notify or peer EOF. */
  for (;;) {
      unsigned char buf[8192];
      int r = mbedtls_ssl_read (&ssl, buf, sizeof buf);
      if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) break;
      if (r <= 0) break;
      bc_write_all (buf, (size_t) r);
  }
  mbedtls_ssl_close_notify (&ssl);

cleanup:
  free (req);
  mbedtls_ssl_free (&ssl);
  mbedtls_ssl_config_free (&conf);
  mbedtls_x509_crt_free (&ca);
  if (sock >= 0) close (sock);
  return rc;
}

/* ============================================================== *
 * NTS-KE (RFC 8915) client + record codec for ntp.            *
 * ============================================================== */

#define BC_NTS_KE_PORT 4460
#define BC_NTS_NTP_PORT 123
#define BC_NTS_PROTO_NTPV4 0
#define BC_NTS_AEAD_AES_SIV_CMAC_256 15

static char *
bc_xstrndup (const char *s, size_t n)
{
  char *p = malloc (n + 1);
  if (!p) return NULL;
  memcpy (p, s, n);
  p[n] = '\0';
  return p;
}

static int
bc_nts_split_host_port (const char *spec, char **host_out, int *port_out)
{
  const char *host = spec, *port = NULL;
  size_t host_len;
  *host_out = NULL;
  *port_out = BC_NTS_KE_PORT;
  if (!spec || !*spec) return -1;

  if (spec[0] == '[') {
      const char *end = strchr (spec, ']');
      if (!end) return -1;
      host = spec + 1;
      host_len = (size_t) (end - host);
      if (end[1] == ':' && end[2]) port = end + 2;
      else if (end[1] != '\0') return -1;
  } else {
      const char *colon = strrchr (spec, ':');
      if (colon && strchr (spec, ':') == colon) {
          host_len = (size_t) (colon - spec);
          port = colon + 1;
      } else {
          host_len = strlen (spec);
      }
  }

  if (host_len == 0 || host_len > 255) return -1;
  if (port) {
      char *endp = NULL;
      long v;
      errno = 0;
      v = strtol (port, &endp, 10);
      if (errno || !endp || *endp || v < 1 || v > 65535) return -1;
      *port_out = (int) v;
  }
  *host_out = bc_xstrndup (host, host_len);
  return *host_out ? 0 : -1;
}

static void
bc_put_u16 (unsigned char *p, unsigned v)
{
  p[0] = (unsigned char) ((v >> 8) & 0xff);
  p[1] = (unsigned char) (v & 0xff);
}

static unsigned
bc_get_u16 (const unsigned char *p)
{
  return ((unsigned) p[0] << 8) | (unsigned) p[1];
}

static size_t
bc_nts_ke_request (unsigned char out[18])
{
  unsigned char *p = out;
  bc_put_u16 (p, 0x8001); bc_put_u16 (p + 2, 2); bc_put_u16 (p + 4, BC_NTS_PROTO_NTPV4); p += 6;
  bc_put_u16 (p, 0x8004); bc_put_u16 (p + 2, 2); bc_put_u16 (p + 4, BC_NTS_AEAD_AES_SIV_CMAC_256); p += 6;
  bc_put_u16 (p, 0x8000); bc_put_u16 (p + 2, 0); p += 4;
  return (size_t) (p - out);
}

void
bc_nts_ke_result_free (struct bc_nts_ke_result *r)
{
  if (!r) return;
  free (r->ntp_host);
  r->ntp_host = NULL;
  for (size_t i = 0; i < r->cookie_count && i < BC_NTS_MAX_COOKIES; i++) {
      if (r->cookies[i]) {
          crypto_wipe (r->cookies[i], r->cookie_lens[i]);
          free (r->cookies[i]);
          r->cookies[i] = NULL;
      }
      r->cookie_lens[i] = 0;
  }
  crypto_wipe (r->c2s, sizeof r->c2s);
  crypto_wipe (r->s2c, sizeof r->s2c);
  r->cookie_count = 0;
  r->ntp_port = 0;
  r->aead_id = 0;
}

static int
bc_nts_ke_response_has_eom (const unsigned char *buf, size_t len)
{
  size_t off = 0;
  while (off + 4 <= len) {
      unsigned type = bc_get_u16 (buf + off) & 0x7fff;
      unsigned rlen = bc_get_u16 (buf + off + 2);
      off += 4;
      if (off + rlen > len) return 0;
      if (type == 0) return 1;
      off += rlen;
  }
  return 0;
}

static int
bc_nts_ke_parse_response (const unsigned char *buf, size_t len,
                          const char *default_host,
                          struct bc_nts_ke_result *out)
{
  int saw_eom = 0, saw_ntpv4 = 0, saw_aead = 0;
  memset (out, 0, sizeof *out);
  out->ntp_port = BC_NTS_NTP_PORT;
  if (default_host) {
      out->ntp_host = strdup (default_host);
      if (!out->ntp_host) return -1;
  }

  for (size_t off = 0; off + 4 <= len; ) {
      unsigned raw_type = bc_get_u16 (buf + off);
      unsigned critical = raw_type & 0x8000;
      unsigned type = raw_type & 0x7fff;
      unsigned rlen = bc_get_u16 (buf + off + 2);
      const unsigned char *body = buf + off + 4;
      off += 4;
      if (off + rlen > len) { bc_nts_ke_result_free (out); return -1; }

      if (type == 0) { saw_eom = 1; break; }
      else if (type == 1) {
          for (unsigned i = 0; i + 1 < rlen; i += 2)
              if (bc_get_u16 (body + i) == BC_NTS_PROTO_NTPV4) saw_ntpv4 = 1;
      } else if (type == 2) {
          builtin_error ("nts-ke: server returned error code %u", rlen >= 2 ? bc_get_u16 (body) : 0);
          bc_nts_ke_result_free (out); return -1;
      } else if (type == 3) {
          /* Warnings are advisory. */
      } else if (type == 4) {
          if (rlen >= 2 && bc_get_u16 (body) == BC_NTS_AEAD_AES_SIV_CMAC_256) {
              saw_aead = 1;
              out->aead_id = BC_NTS_AEAD_AES_SIV_CMAC_256;
          }
      } else if (type == 5) {
          if (rlen > 0 && out->cookie_count < BC_NTS_MAX_COOKIES) {
              unsigned char *c = malloc (rlen);
              if (!c) { bc_nts_ke_result_free (out); return -1; }
              memcpy (c, body, rlen);
              out->cookies[out->cookie_count] = c;
              out->cookie_lens[out->cookie_count] = rlen;
              out->cookie_count++;
          }
      } else if (type == 6) {
          char *h = bc_xstrndup ((const char *) body, rlen);
          if (!h) { bc_nts_ke_result_free (out); return -1; }
          free (out->ntp_host);
          out->ntp_host = h;
      } else if (type == 7) {
          if (rlen != 2) { bc_nts_ke_result_free (out); return -1; }
          unsigned port = bc_get_u16 (body);
          if (port < 1 || port > 65535) { bc_nts_ke_result_free (out); return -1; }
          out->ntp_port = (int) port;
      } else if (critical) {
          builtin_error ("nts-ke: unrecognized critical record %u", type);
          bc_nts_ke_result_free (out); return -1;
      }
      off += rlen;
  }

  if (!saw_eom || !saw_ntpv4 || !saw_aead || out->cookie_count == 0 || !out->ntp_host) {
      bc_nts_ke_result_free (out);
      return -1;
  }
  return 0;
}

int
bc_nts_ke_run (const char *host_port, const char *ca_path, const char *sni,
               int timeout_ms, struct bc_nts_ke_result *out)
{
#if !defined(MBEDTLS_SSL_ALPN) || !defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
  (void) host_port; (void) ca_path; (void) sni; (void) timeout_ms; (void) out;
  builtin_error ("nts-ke: mbedTLS ALPN/exporter support is not enabled");
  return -1;
#else
  char *host = NULL;
  int port = 0;
  int sock = -1;
  unsigned char response[65536];
  size_t response_len = 0;
  int ret = -1;

  memset (out, 0, sizeof *out);
  if (bc_nts_split_host_port (host_port, &host, &port) < 0) {
      builtin_error ("nts-ke: bad HOST[:PORT]");
      return -1;
  }
  if (!sni) sni = host;
  if (timeout_ms <= 0) timeout_ms = 5000;

  sock = bc_tcp_connect_timeout (host, port, timeout_ms);
  if (sock < 0) goto cleanup_host;
  if (bc_set_socket_timeout_ms (sock, timeout_ms) < 0) goto cleanup_host;

  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt ca;
  mbedtls_ssl_init (&ssl);
  mbedtls_ssl_config_init (&conf);
  mbedtls_x509_crt_init (&ca);

  psa_status_t psa_rc = psa_crypto_init ();
  if (psa_rc != PSA_SUCCESS) {
      builtin_error ("nts-ke: psa init failed (%d)", (int) psa_rc);
      goto cleanup_tls;
  }

  const char *ca_real = ca_path;
  if (!ca_real) {
      if (access ("/etc/ssl/cert.pem", R_OK) == 0)
          ca_real = "/etc/ssl/cert.pem";
      else if (access ("/etc/ssl/certs/ca-certificates.crt", R_OK) == 0)
          ca_real = "/etc/ssl/certs/ca-certificates.crt";
  }
  if (!ca_real) {
      builtin_error ("nts-ke: no trust anchors. Pass -c CA_PEM or install /etc/ssl/cert.pem.");
      goto cleanup_tls;
  }
  int ca_rc = mbedtls_x509_crt_parse_file (&ca, ca_real);
  if (ca_rc < 0) {
      builtin_error ("nts-ke: failed to parse CA bundle %s (rc=%d)", ca_real, ca_rc);
      goto cleanup_tls;
  }
  if (mbedtls_ssl_config_defaults (&conf, MBEDTLS_SSL_IS_CLIENT,
                                   MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
      builtin_error ("nts-ke: config_defaults failed");
      goto cleanup_tls;
  }
  mbedtls_ssl_conf_authmode (&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain (&conf, &ca, NULL);
  static const char *const nts_alpn[] = { "ntske/1", NULL };
  if (mbedtls_ssl_conf_alpn_protocols (&conf, nts_alpn) != 0) {
      builtin_error ("nts-ke: ALPN setup failed");
      goto cleanup_tls;
  }
  if (mbedtls_ssl_setup (&ssl, &conf) != 0) {
      builtin_error ("nts-ke: ssl_setup failed");
      goto cleanup_tls;
  }
  if (mbedtls_ssl_set_hostname (&ssl, sni) != 0) {
      builtin_error ("nts-ke: set_hostname failed");
      goto cleanup_tls;
  }
  mbedtls_ssl_set_bio (&ssl, &sock, bc_mbedtls_send, bc_mbedtls_recv, NULL);

  int hs;
  while ((hs = mbedtls_ssl_handshake (&ssl)) != 0) {
      if (hs == MBEDTLS_ERR_SSL_WANT_READ || hs == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      char errbuf[128];
      uint32_t vr = mbedtls_ssl_get_verify_result (&ssl);
      mbedtls_strerror (hs, errbuf, sizeof errbuf);
      builtin_error ("nts-ke: handshake failed: %s (-0x%04x) verify=0x%08x", errbuf, -hs, (unsigned) vr);
      goto cleanup_tls;
  }
  const char *alpn = mbedtls_ssl_get_alpn_protocol (&ssl);
  if (!alpn || strcmp (alpn, "ntske/1") != 0) {
      builtin_error ("nts-ke: ALPN mismatch (%s)", alpn ? alpn : "none");
      goto cleanup_tls;
  }

  unsigned char req[18];
  size_t req_len = bc_nts_ke_request (req);
  for (size_t off = 0; off < req_len; ) {
      int w = mbedtls_ssl_write (&ssl, req + off, req_len - off);
      if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      if (w < 0) { builtin_error ("nts-ke: write failed (-0x%04x)", -w); goto cleanup_tls; }
      off += (size_t) w;
  }

  while (response_len < sizeof response) {
      unsigned char buf[1024];
      int r = mbedtls_ssl_read (&ssl, buf, sizeof buf);
      if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) break;
      if (r <= 0) break;
      if (response_len + (size_t) r > sizeof response) {
          builtin_error ("nts-ke: response too large");
          goto cleanup_tls;
      }
      memcpy (response + response_len, buf, (size_t) r);
      response_len += (size_t) r;
      if (bc_nts_ke_response_has_eom (response, response_len)) break;
  }
  if (bc_nts_ke_parse_response (response, response_len, host, out) < 0) {
      builtin_error ("nts-ke: invalid response");
      goto cleanup_tls;
  }

  const char label[] = "EXPORTER-network-time-security";
  unsigned char ctx[5] = { 0, 0, 0, BC_NTS_AEAD_AES_SIV_CMAC_256, 0 };
  if (mbedtls_ssl_export_keying_material (&ssl, out->c2s, sizeof out->c2s,
                                          label, strlen (label), ctx, sizeof ctx, 1) != 0) {
      builtin_error ("nts-ke: C2S exporter failed");
      bc_nts_ke_result_free (out);
      goto cleanup_tls;
  }
  ctx[4] = 1;
  if (mbedtls_ssl_export_keying_material (&ssl, out->s2c, sizeof out->s2c,
                                          label, strlen (label), ctx, sizeof ctx, 1) != 0) {
      builtin_error ("nts-ke: S2C exporter failed");
      bc_nts_ke_result_free (out);
      goto cleanup_tls;
  }

  ret = 0;

cleanup_tls:
  mbedtls_ssl_close_notify (&ssl);
  mbedtls_ssl_free (&ssl);
  mbedtls_ssl_config_free (&conf);
  mbedtls_x509_crt_free (&ca);
cleanup_host:
  if (sock >= 0) close (sock);
  free (host);
  return ret;
#endif
}

static int
bc_nts_ke_cmd (WORD_LIST *args)
{
  const char *host_port = NULL, *ca_path = NULL, *sni = NULL, *parse_hex = NULL;
  int timeout_ms = 5000, emit_keys = 0, request_hex = 0;
  for (WORD_LIST *p = args; p; p = p->next) {
      const char *w = p->word->word;
      if (strcmp (w, "-c") == 0) { if (!p->next) { builtin_error ("nts-ke: -c needs CA_PEM"); return EX_USAGE; } p = p->next; ca_path = p->word->word; }
      else if (strcmp (w, "-s") == 0) { if (!p->next) { builtin_error ("nts-ke: -s needs SNI"); return EX_USAGE; } p = p->next; sni = p->word->word; }
      else if (strcmp (w, "--timeout") == 0) { if (!p->next) return EX_USAGE; p = p->next; timeout_ms = atoi (p->word->word); if (timeout_ms <= 0) timeout_ms = 5000; }
      else if (strcmp (w, "--emit-keys") == 0) emit_keys = 1;
      else if (strcmp (w, "--request-hex") == 0) request_hex = 1;
      else if (strcmp (w, "--parse-response-hex") == 0) { if (!p->next) return EX_USAGE; p = p->next; parse_hex = p->word->word; }
      else if (!host_port) host_port = w;
      else { builtin_error ("nts-ke: unexpected arg: %s", w); return EX_USAGE; }
  }

  if (request_hex) {
      unsigned char req[18];
      bc_print_hex (req, bc_nts_ke_request (req));
      putchar ('\n');
      return EXECUTION_SUCCESS;
  }

  struct bc_nts_ke_result r;
  if (parse_hex) {
      size_t cap = strlen (parse_hex) / 2 + 1;
      unsigned char *buf = malloc (cap ? cap : 1);
      if (!buf) return EXECUTION_FAILURE;
      int n = bc_unhex (parse_hex, buf, cap ? cap : 1);
      if (n < 0) { free (buf); builtin_error ("nts-ke: bad response hex"); return EX_USAGE; }
      if (bc_nts_ke_parse_response (buf, (size_t) n, host_port ? host_port : "nts.example", &r) < 0) {
          free (buf); builtin_error ("nts-ke: invalid response"); return EXECUTION_FAILURE;
      }
      free (buf);
  } else {
      if (!host_port) { builtin_error ("nts-ke HOST[:PORT] required"); return EX_USAGE; }
      if (bc_nts_ke_run (host_port, ca_path, sni, timeout_ms, &r) < 0)
          return EXECUTION_FAILURE;
  }

  printf ("aead=%u\nntp_server=%s\nntp_port=%d\ncookies=%zu\n",
          r.aead_id, r.ntp_host ? r.ntp_host : "", r.ntp_port, r.cookie_count);
  if (emit_keys) {
      printf ("c2s="); bc_print_hex (r.c2s, sizeof r.c2s); putchar ('\n');
      printf ("s2c="); bc_print_hex (r.s2c, sizeof r.s2c); putchar ('\n');
  }
  for (size_t i = 0; i < r.cookie_count; i++) {
      printf ("cookie%zu=", i);
      bc_print_hex (r.cookies[i], r.cookie_lens[i]);
      putchar ('\n');
  }
  bc_nts_ke_result_free (&r);
  return EXECUTION_SUCCESS;
}




static size_t
bc_ecdsa_raw_to_asn1_local (unsigned char *sig, size_t sig_len)
{
  if (sig_len != 64) return 0;
  unsigned char r[33], ss[33];
  size_t r0 = 0, s0 = 0;
  while (r0 < 32 && sig[r0] == 0) r0++;
  while (s0 < 32 && sig[32 + s0] == 0) s0++;
  size_t rlen = 32 - r0, slen = 32 - s0;
  if (rlen == 0) { r[0] = 0; rlen = 1; }
  else { memcpy (r, sig + r0, rlen); if (r[0] & 0x80) { memmove (r + 1, r, rlen); r[0] = 0; rlen++; } }
  if (slen == 0) { ss[0] = 0; slen = 1; }
  else { memcpy (ss, sig + 32 + s0, slen); if (ss[0] & 0x80) { memmove (ss + 1, ss, slen); ss[0] = 0; slen++; } }
  size_t total = 2 + rlen + 2 + slen;
  if (total + 2 > 80 || total > 127) return 0;
  unsigned char out[80];
  size_t p = 0;
  out[p++] = 0x30; out[p++] = (unsigned char) total;
  out[p++] = 0x02; out[p++] = (unsigned char) rlen; memcpy (out + p, r, rlen); p += rlen;
  out[p++] = 0x02; out[p++] = (unsigned char) slen; memcpy (out + p, ss, slen); p += slen;
  memcpy (sig, out, p);
  return p;
}

static size_t
bc_ecdsa_asn1_to_raw_local (unsigned char *sig, size_t sig_len)
{
  if (sig_len < 8 || sig[0] != 0x30 || sig[1] + 2 != sig_len) return 0;
  size_t p = 2;
  if (sig[p++] != 0x02) return 0;
  size_t rlen = sig[p++];
  if (p + rlen >= sig_len) return 0;
  const unsigned char *r = sig + p; p += rlen;
  if (sig[p++] != 0x02) return 0;
  size_t slen = sig[p++];
  if (p + slen != sig_len) return 0;
  const unsigned char *ss = sig + p;
  while (rlen > 0 && *r == 0) { r++; rlen--; }
  while (slen > 0 && *ss == 0) { ss++; slen--; }
  if (rlen > 32 || slen > 32) return 0;
  unsigned char out[64]; memset (out, 0, sizeof out);
  memcpy (out + (32 - rlen), r, rlen);
  memcpy (out + 32 + (32 - slen), ss, slen);
  memcpy (sig, out, sizeof out);
  return 64;
}

/* ---- ECDSA over NIST P-256 (mbedTLS p256-m) ------------------------- */

static int
bc_sha256_mbedtls_stdin (unsigned char digest[32])
{
  mbedtls_sha256_context hc;
  mbedtls_sha256_init (&hc);
  if (mbedtls_sha256_starts (&hc, 0) != 0)
    { mbedtls_sha256_free (&hc); return -1; }

  unsigned char buf[8192];
  ssize_t n;
  while ((n = read (STDIN_FILENO, buf, sizeof buf)) > 0)
    if (mbedtls_sha256_update (&hc, buf, (size_t) n) != 0)
      { mbedtls_sha256_free (&hc); return -1; }
  if (n < 0)
    { mbedtls_sha256_free (&hc); builtin_error ("stdin read: %s", strerror (errno)); return -1; }

  int rc = mbedtls_sha256_finish (&hc, digest);
  mbedtls_sha256_free (&hc);
  return rc;
}

static int
bc_sha384_mbedtls_stdin (unsigned char digest[48])
{
  mbedtls_sha512_context hc;
  mbedtls_sha512_init (&hc);
  if (mbedtls_sha512_starts (&hc, 1) != 0)
    { mbedtls_sha512_free (&hc); return -1; }

  unsigned char buf[8192];
  ssize_t n;
  while ((n = read (STDIN_FILENO, buf, sizeof buf)) > 0)
    if (mbedtls_sha512_update (&hc, buf, (size_t) n) != 0)
      { mbedtls_sha512_free (&hc); return -1; }
  if (n < 0)
    { mbedtls_sha512_free (&hc); builtin_error ("stdin read: %s", strerror (errno)); return -1; }

  int rc = mbedtls_sha512_finish (&hc, digest);
  mbedtls_sha512_free (&hc);
  return rc;
}

static int
bc_ecdsa_p256_mbedtls_keygen (WORD_LIST *args)
{
  int hex_out = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    if (strcmp (p->word->word, "-x") == 0) hex_out = 1;
    else { builtin_error ("ecdsa-p256-keygen-mbedtls: unexpected arg: %s", p->word->word); return EX_USAGE; }

  unsigned char sk[32];
  if (mbedtls_ecdsa_p256_keygen (sk) != 0)
    { builtin_error ("ecdsa-p256-keygen-mbedtls: keygen failed"); return EXECUTION_FAILURE; }
  return bc_emit (sk, sizeof sk, hex_out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bc_ecdsa_p256_mbedtls_pub (WORD_LIST *args)
{
  int hex_out = 0;
  const char *sk_hex = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (strcmp (w, "-x") == 0) hex_out = 1;
      else if (strcmp (w, "-k") == 0)
        { if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
          p = p->next; sk_hex = p->word->word; }
      else { builtin_error ("ecdsa-p256-pub-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!sk_hex) { builtin_error ("ecdsa-p256-pub-mbedtls needs -k SK_HEX"); return EX_USAGE; }
  unsigned char sk[32], pk[65];
  if (bc_unhex (sk_hex, sk, sizeof sk) != 32)
    { builtin_error ("ecdsa-p256-pub-mbedtls: SK must be 32 bytes hex"); return EX_USAGE; }
  if (mbedtls_ecdsa_p256_public (pk, sk) != 0)
    { builtin_error ("ecdsa-p256-pub-mbedtls: invalid private key"); return EXECUTION_FAILURE; }
  return bc_emit (pk, sizeof pk, hex_out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bc_ecdsa_p256_mbedtls_key_pem (WORD_LIST *args)
{
  const char *sk_hex = NULL;
  int want_der = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-k"))
        { if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
          p = p->next; sk_hex = p->word->word; }
      else if (!strcmp (w, "--der"))
        want_der = 1;
      else { builtin_error ("ecdsa-p256-key-pem: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!sk_hex) { builtin_error ("ecdsa-p256-key-pem needs -k SK_HEX"); return EX_USAGE; }

  unsigned char sk[32], pub[65];
  if (bc_unhex (sk_hex, sk, sizeof sk) != 32)
    { builtin_error ("ecdsa-p256-key-pem: SK must be 32 bytes hex"); return EX_USAGE; }
  if (mbedtls_ecdsa_p256_public (pub, sk) != 0)
    { builtin_error ("ecdsa-p256-key-pem: invalid private key"); return EXECUTION_FAILURE; }

  unsigned char buf[512];
  unsigned char *p = buf + sizeof buf;
  size_t total = 0;
  int rc;

  /* publicKey [1] EXPLICIT BIT STRING */
  size_t pub_total = 0;
  rc = mbedtls_asn1_write_raw_buffer (&p, buf, pub, sizeof pub); if (rc < 0) goto enc_fail;
  pub_total += (size_t) rc;
  if (p <= buf) goto enc_fail;
  p--; *p = 0x00; pub_total += 1; /* unused-bits prefix */
  rc = mbedtls_asn1_write_len (&p, buf, sizeof pub + 1); if (rc < 0) goto enc_fail;
  pub_total += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_BIT_STRING); if (rc < 0) goto enc_fail;
  pub_total += (size_t) rc;
  rc = mbedtls_asn1_write_len (&p, buf, pub_total); if (rc < 0) goto enc_fail;
  pub_total += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1);
  if (rc < 0) goto enc_fail;
  pub_total += (size_t) rc;
  total += pub_total;

  /* parameters [0] EXPLICIT namedCurve OID prime256v1 */
  size_t param_total = 0;
  rc = mbedtls_asn1_write_oid (&p, buf,
        (const char *) BC_OID_PRIME256V1, sizeof BC_OID_PRIME256V1);
  if (rc < 0) goto enc_fail;
  param_total += (size_t) rc;
  rc = mbedtls_asn1_write_len (&p, buf, param_total); if (rc < 0) goto enc_fail;
  param_total += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0);
  if (rc < 0) goto enc_fail;
  param_total += (size_t) rc;
  total += param_total;

  rc = mbedtls_asn1_write_octet_string (&p, buf, sk, sizeof sk); if (rc < 0) goto enc_fail;
  total += (size_t) rc;
  rc = mbedtls_asn1_write_int (&p, buf, 1); if (rc < 0) goto enc_fail;
  total += (size_t) rc;
  rc = mbedtls_asn1_write_len (&p, buf, total); if (rc < 0) goto enc_fail;
  total += (size_t) rc;
  rc = mbedtls_asn1_write_tag (&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (rc < 0) goto enc_fail;
  total += (size_t) rc;

  if (want_der)
    return bc_write_all (p, total) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;

  size_t b64_len = 0;
  mbedtls_base64_encode (NULL, 0, &b64_len, p, total);
  unsigned char *b64 = malloc (b64_len + 4);
  if (!b64) { builtin_error ("malloc"); return EXECUTION_FAILURE; }
  if (mbedtls_base64_encode (b64, b64_len + 4, &b64_len, p, total) != 0)
    { free (b64); builtin_error ("ecdsa-p256-key-pem: base64 failed"); return EXECUTION_FAILURE; }
  printf ("-----BE"
  "GIN EC PRIVATE KEY-----\n");
  for (size_t i = 0; i < b64_len; i += 64)
    {
      size_t n = b64_len - i < 64 ? b64_len - i : 64;
      bc_write_all (b64 + i, n);
      putchar ('\n');
    }
  printf ("-----END EC PRIVATE KEY-----\n");
  free (b64);
  return EXECUTION_SUCCESS;

enc_fail:
  builtin_error ("ecdsa-p256-key-pem: ASN.1 encode failed");
  return EXECUTION_FAILURE;
}

static int
bc_ecdsa_p256_mbedtls_sign (WORD_LIST *args)
{
  int hex_out = 0, asn1 = 0;
  const char *sk_hex = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (strcmp (w, "-x") == 0) hex_out = 1;
      else if (strcmp (w, "-A") == 0) asn1 = 1;
      else if (strcmp (w, "-k") == 0)
        { if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
          p = p->next; sk_hex = p->word->word; }
      else { builtin_error ("ecdsa-p256-sign-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!sk_hex) { builtin_error ("ecdsa-p256-sign-mbedtls needs -k SK_HEX"); return EX_USAGE; }

  unsigned char sk[32], digest[32], sig[80];
  if (bc_unhex (sk_hex, sk, sizeof sk) != 32)
    { builtin_error ("ecdsa-p256-sign-mbedtls: SK must be 32 bytes hex"); return EX_USAGE; }
  if (bc_sha256_mbedtls_stdin (digest) != 0)
    { builtin_error ("ecdsa-p256-sign-mbedtls: sha256 failed"); return EXECUTION_FAILURE; }
  if (mbedtls_ecdsa_p256_sign_raw (sig, sk, digest, sizeof digest) != 0)
    { builtin_error ("ecdsa-p256-sign-mbedtls: sign failed"); return EXECUTION_FAILURE; }

  size_t sig_len = 64;
  if (asn1)
    {
      sig_len = bc_ecdsa_raw_to_asn1_local (sig, sig_len);
      if (sig_len == 0)
        { builtin_error ("ecdsa-p256-sign-mbedtls: ASN.1 conversion failed"); return EXECUTION_FAILURE; }
    }
  return bc_emit (sig, sig_len, hex_out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bc_ecdsa_p256_mbedtls_verify (WORD_LIST *args)
{
  int asn1 = 0;
  const char *pk_hex = NULL, *sig_hex = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (strcmp (w, "-A") == 0) asn1 = 1;
      else if (strcmp (w, "-k") == 0)
        { if (!p->next) { builtin_error ("-k needs PK_HEX"); return EX_USAGE; }
          p = p->next; pk_hex = p->word->word; }
      else if (strcmp (w, "-s") == 0)
        { if (!p->next) { builtin_error ("-s needs SIG_HEX"); return EX_USAGE; }
          p = p->next; sig_hex = p->word->word; }
      else { builtin_error ("ecdsa-p256-verify-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!pk_hex || !sig_hex)
    { builtin_error ("ecdsa-p256-verify-mbedtls needs -k PK_HEX -s SIG_HEX"); return EX_USAGE; }

  unsigned char pk[65], sig[80], digest[32];
  if (bc_unhex (pk_hex, pk, sizeof pk) != 65)
    { builtin_error ("ecdsa-p256-verify-mbedtls: PK must be 65 bytes hex"); return EX_USAGE; }
  int sig_len = bc_unhex (sig_hex, sig, sizeof sig);
  if (sig_len < 0)
    { builtin_error ("ecdsa-p256-verify-mbedtls: bad SIG hex"); return EX_USAGE; }
  if (asn1)
    {
      sig_len = (int) bc_ecdsa_asn1_to_raw_local (sig, (size_t) sig_len);
      if (sig_len != 64) return EXECUTION_FAILURE;
    }
  else if (sig_len != 64)
    { builtin_error ("ecdsa-p256-verify-mbedtls: raw SIG must be 64 bytes"); return EX_USAGE; }

  if (bc_sha256_mbedtls_stdin (digest) != 0)
    { builtin_error ("ecdsa-p256-verify-mbedtls: sha256 failed"); return EXECUTION_FAILURE; }
  return mbedtls_ecdsa_p256_verify_raw (pk, sig, digest, sizeof digest) == 0
    ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bc_ecdsa_p384_mbedtls_verify (WORD_LIST *args)
{
  const char *pk_hex = NULL, *sig_hex = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-k") == 0)
        { if (!p->next) { builtin_error ("-k needs PK_HEX"); return EX_USAGE; }
          p = p->next; pk_hex = p->word->word; }
      else if (strcmp (w, "-s") == 0)
        { if (!p->next) { builtin_error ("-s needs SIG_HEX"); return EX_USAGE; }
          p = p->next; sig_hex = p->word->word; }
      else { builtin_error ("ecdsa-p384-verify-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!pk_hex || !sig_hex)
    { builtin_error ("ecdsa-p384-verify-mbedtls needs -k PK_HEX -s SIG_HEX"); return EX_USAGE; }

  unsigned char pk_raw[97], sig[96], digest[48];
  int pk_len = bc_unhex (pk_hex, pk_raw, sizeof pk_raw);
  if (pk_len == 96)
    {
      memmove (pk_raw + 1, pk_raw, 96);
      pk_raw[0] = 0x04;
      pk_len = 97;
    }
  else if (pk_len != 97)
    {
      builtin_error ("ecdsa-p384-verify-mbedtls: PK must be 96-byte X||Y or 97-byte uncompressed hex");
      return EX_USAGE;
    }
  if (pk_raw[0] != 0x04)
    {
      builtin_error ("ecdsa-p384-verify-mbedtls: PK must be an uncompressed point");
      return EX_USAGE;
    }
  if (bc_unhex (sig_hex, sig, sizeof sig) != 96)
    { builtin_error ("ecdsa-p384-verify-mbedtls: raw SIG must be 96 bytes"); return EX_USAGE; }

  if (bc_sha384_mbedtls_stdin (digest) != 0)
    { builtin_error ("ecdsa-p384-verify-mbedtls: sha384 failed"); return EXECUTION_FAILURE; }

  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi r, s;
  mbedtls_ecp_group_init (&grp);
  mbedtls_ecp_point_init (&Q);
  mbedtls_mpi_init (&r);
  mbedtls_mpi_init (&s);
  int rc = mbedtls_ecp_group_load (&grp, MBEDTLS_ECP_DP_SECP384R1);
  if (rc == 0) rc = mbedtls_ecp_point_read_binary (&grp, &Q, pk_raw, (size_t) pk_len);
  if (rc == 0) rc = mbedtls_mpi_read_binary (&r, sig, 48);
  if (rc == 0) rc = mbedtls_mpi_read_binary (&s, sig + 48, 48);
  if (rc == 0) rc = mbedtls_ecdsa_verify (&grp, digest, sizeof digest, &Q, &r, &s);
  mbedtls_mpi_free (&s);
  mbedtls_mpi_free (&r);
  mbedtls_ecp_point_free (&Q);
  mbedtls_ecp_group_free (&grp);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ---- ECDSA over NIST P-384 (mbedTLS generic ecp/ecdsa) ------------- *
 * DNSSEC algorithm 14 (ECDSAP384SHA384, RFC 6605). Mirrors the P-256
 * verb family but on secp384r1 + SHA-384, emitting raw r||s (96 bytes).
 * The P-256 family uses mbedTLS's specialised p256-m fast path; there is
 * no p384-m, so these route through the generic mbedtls_ecp / mbedtls_ecdsa
 * machinery already linked for bc_ecdsa_p384_mbedtls_verify(). */

/* f_rng adapter: mbedTLS sign/keygen take a (ctx, buf, len) RNG callback.
 * Back it with the same /dev/urandom CSPRNG the rest of crypto uses. */
static int
bc_mbedtls_rng (void *ctx, unsigned char *buf, size_t len)
{
  (void) ctx;
  return bc_random_bytes (buf, len) == 0 ? 0 : -1;
}

static int
bc_ecdsa_p384_mbedtls_keygen (WORD_LIST *args)
{
  int hex_out = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    if (strcmp (p->word->word, "-x") == 0) hex_out = 1;
    else { builtin_error ("ecdsa-p384-keygen-mbedtls: unexpected arg: %s", p->word->word); return EX_USAGE; }

  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point Q;
  mbedtls_ecp_group_init (&grp);
  mbedtls_mpi_init (&d);
  mbedtls_ecp_point_init (&Q);

  int rc = mbedtls_ecp_group_load (&grp, MBEDTLS_ECP_DP_SECP384R1);
  if (rc == 0) rc = mbedtls_ecp_gen_keypair (&grp, &d, &Q, bc_mbedtls_rng, NULL);
  unsigned char sk[48];
  if (rc == 0) rc = mbedtls_mpi_write_binary (&d, sk, sizeof sk);

  mbedtls_ecp_point_free (&Q);
  mbedtls_mpi_free (&d);
  mbedtls_ecp_group_free (&grp);

  if (rc != 0)
    { builtin_error ("ecdsa-p384-keygen-mbedtls: keygen failed"); return EXECUTION_FAILURE; }
  return bc_emit (sk, sizeof sk, hex_out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bc_ecdsa_p384_mbedtls_pub (WORD_LIST *args)
{
  int hex_out = 0;
  const char *sk_hex = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (strcmp (w, "-x") == 0) hex_out = 1;
      else if (strcmp (w, "-k") == 0)
        { if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
          p = p->next; sk_hex = p->word->word; }
      else { builtin_error ("ecdsa-p384-pub-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!sk_hex) { builtin_error ("ecdsa-p384-pub-mbedtls needs -k SK_HEX"); return EX_USAGE; }

  unsigned char sk[48];
  if (bc_unhex (sk_hex, sk, sizeof sk) != 48)
    { builtin_error ("ecdsa-p384-pub-mbedtls: SK must be 48 bytes hex"); return EX_USAGE; }

  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point Q;
  mbedtls_ecp_group_init (&grp);
  mbedtls_mpi_init (&d);
  mbedtls_ecp_point_init (&Q);

  unsigned char pk[97];
  size_t olen = 0;
  int rc = mbedtls_ecp_group_load (&grp, MBEDTLS_ECP_DP_SECP384R1);
  if (rc == 0) rc = mbedtls_mpi_read_binary (&d, sk, sizeof sk);
  /* Q = d * G */
  if (rc == 0) rc = mbedtls_ecp_mul (&grp, &Q, &d, &grp.G, bc_mbedtls_rng, NULL);
  if (rc == 0) rc = mbedtls_ecp_point_write_binary (&grp, &Q,
                       MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pk, sizeof pk);

  mbedtls_ecp_point_free (&Q);
  mbedtls_mpi_free (&d);
  mbedtls_ecp_group_free (&grp);

  if (rc != 0 || olen != 97)
    { builtin_error ("ecdsa-p384-pub-mbedtls: invalid private key"); return EXECUTION_FAILURE; }
  return bc_emit (pk, olen, hex_out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bc_ecdsa_p384_mbedtls_sign (WORD_LIST *args)
{
  int hex_out = 0;
  const char *sk_hex = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (strcmp (w, "-x") == 0) hex_out = 1;
      else if (strcmp (w, "-k") == 0)
        { if (!p->next) { builtin_error ("-k needs SK_HEX"); return EX_USAGE; }
          p = p->next; sk_hex = p->word->word; }
      else { builtin_error ("ecdsa-p384-sign-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!sk_hex) { builtin_error ("ecdsa-p384-sign-mbedtls needs -k SK_HEX"); return EX_USAGE; }

  unsigned char sk[48], digest[48], sig[96];
  if (bc_unhex (sk_hex, sk, sizeof sk) != 48)
    { builtin_error ("ecdsa-p384-sign-mbedtls: SK must be 48 bytes hex"); return EX_USAGE; }
  if (bc_sha384_mbedtls_stdin (digest) != 0)
    { builtin_error ("ecdsa-p384-sign-mbedtls: sha384 failed"); return EXECUTION_FAILURE; }

  mbedtls_ecp_group grp;
  mbedtls_mpi d, r, s;
  mbedtls_ecp_group_init (&grp);
  mbedtls_mpi_init (&d);
  mbedtls_mpi_init (&r);
  mbedtls_mpi_init (&s);

  int rc = mbedtls_ecp_group_load (&grp, MBEDTLS_ECP_DP_SECP384R1);
  if (rc == 0) rc = mbedtls_mpi_read_binary (&d, sk, sizeof sk);
  if (rc == 0) rc = mbedtls_ecdsa_sign (&grp, &r, &s, &d, digest, sizeof digest,
                                        bc_mbedtls_rng, NULL);
  /* DNSSEC RRSIG wire format: fixed-width big-endian r||s, 48 bytes each. */
  if (rc == 0) rc = mbedtls_mpi_write_binary (&r, sig, 48);
  if (rc == 0) rc = mbedtls_mpi_write_binary (&s, sig + 48, 48);

  mbedtls_mpi_free (&s);
  mbedtls_mpi_free (&r);
  mbedtls_mpi_free (&d);
  mbedtls_ecp_group_free (&grp);

  if (rc != 0)
    { builtin_error ("ecdsa-p384-sign-mbedtls: sign failed"); return EXECUTION_FAILURE; }
  return bc_emit (sig, sizeof sig, hex_out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ---- RSA PKCS#1 v1.5 (mbedTLS full rsa.c) -------------------------- *
 * DNSSEC algorithms 5/7 (RSASHA1, RSASHA1-NSEC3-SHA1), 8 (RSASHA256),
 * 10 (RSASHA512). PKCS#1 v1.5 EMSA. Key material is the standard RSA
 * private quintuple (N, E, D, P, Q) — the same parameters BIND's
 * dnssec-keygen emits. We hydrate the CRT params (DP/DQ/QP) via
 * mbedtls_rsa_deduce_crt() because this trimmed rsa.c has no
 * mbedtls_rsa_complete/import_raw entry point. */

/* Map a -H NAME token to the mbedTLS md type + digest size used for
 * PKCS#1 v1.5. Returns 0 on success, -1 on unknown name. */
static int
bc_rsa_md_from_name (const char *name, mbedtls_md_type_t *md, size_t *dlen)
{
  if      (!strcmp (name, "sha1"))   { *md = MBEDTLS_MD_SHA1;   *dlen = 20; }
  else if (!strcmp (name, "sha256")) { *md = MBEDTLS_MD_SHA256; *dlen = 32; }
  else if (!strcmp (name, "sha384")) { *md = MBEDTLS_MD_SHA384; *dlen = 48; }
  else if (!strcmp (name, "sha512")) { *md = MBEDTLS_MD_SHA512; *dlen = 64; }
  else return -1;
  return 0;
}

/* Hash the bytes in (msg,mlen) into `digest` with the named algorithm,
 * reusing the same SHA primitives the rest of crypto links. */
static void
bc_rsa_hash_buf (mbedtls_md_type_t md, const unsigned char *msg, size_t mlen,
                 unsigned char *digest)
{
  switch (md)
    {
    case MBEDTLS_MD_SHA1:   mbedtls_sha1   (msg, mlen, digest);    break;
    case MBEDTLS_MD_SHA256: mbedtls_sha256 (msg, mlen, digest, 0); break;
    case MBEDTLS_MD_SHA384: mbedtls_sha512 (msg, mlen, digest, 1); break;
    case MBEDTLS_MD_SHA512: mbedtls_sha512 (msg, mlen, digest, 0); break;
    default: break;
    }
}

static int
bc_rsa_keygen (WORD_LIST *args)
{
  int bits = 2048, exponent = 65537;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-b"))
        { if (!p->next) { builtin_error ("-b needs BITS"); return EX_USAGE; }
          p = p->next; bits = atoi (p->word->word); }
      else if (!strcmp (w, "-e"))
        { if (!p->next) { builtin_error ("-e needs EXPONENT"); return EX_USAGE; }
          p = p->next; exponent = atoi (p->word->word); }
      else { builtin_error ("rsa-keygen: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (bits < 1024 || bits > 4096 || (bits % 8) != 0)
    { builtin_error ("rsa-keygen: BITS must be 1024..4096, multiple of 8"); return EX_USAGE; }

  mbedtls_rsa_context ctx;
  mbedtls_rsa_init (&ctx);
  int rc = mbedtls_rsa_gen_key (&ctx, bc_mbedtls_rng, NULL,
                                (unsigned int) bits, exponent);
  if (rc != 0)
    { mbedtls_rsa_free (&ctx); builtin_error ("rsa-keygen: gen_key failed (rc=%d)", rc); return EXECUTION_FAILURE; }

  /* Emit N,E,D,P,Q as labelled hex lines. Field widths are the natural
     big-endian size of each MPI (no fixed padding) so a reader can feed
     them straight back into rsa-pkcs1-sign. */
  unsigned char buf[1024];
  struct { const char *tag; const mbedtls_mpi *mpi; } fields[] = {
    { "n", &ctx.N }, { "e", &ctx.E }, { "d", &ctx.D },
    { "p", &ctx.P }, { "q", &ctx.Q },
  };
  for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++)
    {
      size_t n = mbedtls_mpi_size (fields[i].mpi);
      if (n == 0 || n > sizeof buf)
        { mbedtls_rsa_free (&ctx); builtin_error ("rsa-keygen: MPI export failed"); return EXECUTION_FAILURE; }
      if (mbedtls_mpi_write_binary (fields[i].mpi, buf, n) != 0)
        { mbedtls_rsa_free (&ctx); builtin_error ("rsa-keygen: MPI export failed"); return EXECUTION_FAILURE; }
      printf ("%s:", fields[i].tag);
      bc_print_hex (buf, n);
      putchar ('\n');
    }
  mbedtls_rsa_free (&ctx);
  return EXECUTION_SUCCESS;
}

static int
bc_rsa_pkcs1_sign (WORD_LIST *args)
{
  const char *n_hex = NULL, *e_hex = NULL, *d_hex = NULL,
             *p_hex = NULL, *q_hex = NULL, *hash_name = "sha256";
  int hex_out = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (!strcmp (w, "-x")) hex_out = 1;
      else if (!strcmp (w, "-n") && p->next) { p = p->next; n_hex = p->word->word; }
      else if (!strcmp (w, "-e") && p->next) { p = p->next; e_hex = p->word->word; }
      else if (!strcmp (w, "-d") && p->next) { p = p->next; d_hex = p->word->word; }
      else if (!strcmp (w, "-p") && p->next) { p = p->next; p_hex = p->word->word; }
      else if (!strcmp (w, "-q") && p->next) { p = p->next; q_hex = p->word->word; }
      else if (!strcmp (w, "-H") && p->next) { p = p->next; hash_name = p->word->word; }
      else { builtin_error ("rsa-pkcs1-sign: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!n_hex || !e_hex || !d_hex || !p_hex || !q_hex)
    { builtin_error ("rsa-pkcs1-sign needs -n N -e E -d D -p P -q Q (private quintuple)"); return EX_USAGE; }

  mbedtls_md_type_t md;
  size_t dlen;
  if (bc_rsa_md_from_name (hash_name, &md, &dlen) != 0)
    { builtin_error ("rsa-pkcs1-sign: -H must be sha1|sha256|sha384|sha512"); return EX_USAGE; }

  static unsigned char nb[1024], eb[16], db[1024], pb[768], qb[768];
  int nl = bc_unhex (n_hex, nb, sizeof nb);
  int el = bc_unhex (e_hex, eb, sizeof eb);
  int dl = bc_unhex (d_hex, db, sizeof db);
  int pl = bc_unhex (p_hex, pb, sizeof pb);
  int ql = bc_unhex (q_hex, qb, sizeof qb);
  if (nl <= 0 || el <= 0 || dl <= 0 || pl <= 0 || ql <= 0)
    { builtin_error ("rsa-pkcs1-sign: bad hex in key parameters"); return EX_USAGE; }

  mbedtls_rsa_context ctx;
  mbedtls_rsa_init (&ctx);
  int rc = mbedtls_rsa_set_padding (&ctx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
  if (rc == 0) rc = mbedtls_mpi_read_binary (&ctx.N, nb, (size_t) nl);
  if (rc == 0) rc = mbedtls_mpi_read_binary (&ctx.E, eb, (size_t) el);
  if (rc == 0) rc = mbedtls_mpi_read_binary (&ctx.D, db, (size_t) dl);
  if (rc == 0) rc = mbedtls_mpi_read_binary (&ctx.P, pb, (size_t) pl);
  if (rc == 0) rc = mbedtls_mpi_read_binary (&ctx.Q, qb, (size_t) ql);
  /* Hydrate CRT params DP/DQ/QP from P,Q,D (no rsa_complete in this build). */
  if (rc == 0) rc = mbedtls_rsa_deduce_crt (&ctx.P, &ctx.Q, &ctx.D,
                                            &ctx.DP, &ctx.DQ, &ctx.QP);
  if (rc == 0) { ctx.len = (size_t) nl; rc = mbedtls_rsa_check_privkey (&ctx); }
  if (rc != 0)
    { mbedtls_rsa_free (&ctx); builtin_error ("rsa-pkcs1-sign: invalid key (rc=%d)", rc); return EX_USAGE; }

  unsigned char *msg; size_t mlen;
  if (bc_slurp_fd (STDIN_FILENO, &msg, &mlen) < 0)
    { mbedtls_rsa_free (&ctx); return EXECUTION_FAILURE; }
  unsigned char digest[64];
  bc_rsa_hash_buf (md, msg, mlen, digest);
  free (msg);

  size_t siglen = mbedtls_rsa_get_len (&ctx);
  unsigned char *sig = malloc (siglen);
  if (!sig) { mbedtls_rsa_free (&ctx); builtin_error ("malloc"); return EXECUTION_FAILURE; }
  rc = mbedtls_rsa_pkcs1_sign (&ctx, bc_mbedtls_rng, NULL, md,
                               (unsigned int) dlen, digest, sig);
  mbedtls_rsa_free (&ctx);
  if (rc != 0)
    { free (sig); builtin_error ("rsa-pkcs1-sign: sign failed (rc=%d)", rc); return EXECUTION_FAILURE; }

  int erc = bc_emit (sig, siglen, hex_out);
  free (sig);
  return erc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ---- Argon2id (monocypher) ------------------------------------------ */
/* RFC 9106. Memory-hard password-hashing KDF; supersedes scrypt for
 * password storage. We expose Argon2id specifically (the recommended
 * variant — Argon2d is GPU-resistant only, Argon2i is timing-resistant
 * only; id is both).
 *
 * Defaults (RFC 9106 §4 second recommendation, "moderate"):
 *   t = 3 passes, m = 65536 KiB (64 MiB), p = 1 lane, output 32 bytes
 *
 * Caller can tune via -t / -m / -l / -L. Memory must be >= 8 * lanes
 * (monocypher constraint) — enforced before call.
 */
static int
bc_argon2id_cmd (WORD_LIST *args)
{
  int hex_out = 0, quiet_mlock = 0;
  const char *salt_hex = NULL, *password = NULL, *var_out = NULL;
  uint32_t passes = 3, mem_kib = 65536, lanes = 1;
  size_t out_len = 32;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if      (strcmp (w, "-x") == 0) hex_out = 1;
      /* -Q: silence mlock-failure warning. Useful when the caller
         already knows mlock won't succeed (non-root, embedded hosts). */
      else if (strcmp (w, "-Q") == 0) quiet_mlock = 1;
      else if (strcmp (w, "-p") == 0) { if (!p->next) { builtin_error("-p needs PASSWORD"); return EX_USAGE; } p = p->next; password = p->word->word; }
      else if (strcmp (w, "-s") == 0) { if (!p->next) { builtin_error("-s needs SALT"); return EX_USAGE; } p = p->next; salt_hex = p->word->word; }
      else if (strcmp (w, "-t") == 0) { if (!p->next) { builtin_error("-t needs PASSES"); return EX_USAGE; } p = p->next; passes = (uint32_t) atoi (p->word->word); }
      else if (strcmp (w, "-m") == 0) { if (!p->next) { builtin_error("-m needs MEM_KIB"); return EX_USAGE; } p = p->next; mem_kib = (uint32_t) atoi (p->word->word); }
      else if (strcmp (w, "-l") == 0) { if (!p->next) { builtin_error("-l needs LANES"); return EX_USAGE; } p = p->next; lanes = (uint32_t) atoi (p->word->word); }
      else if (strcmp (w, "-L") == 0) { if (!p->next) { builtin_error("-L needs LEN"); return EX_USAGE; } p = p->next; out_len = (size_t) atoi (p->word->word); }
      /* -o VARNAME: bind the hex output to a shell variable instead of
         writing to stdout. Skips the `$(…)` fork in the caller. Hex
         only (raw bytes don't round-trip through a bash variable). */
      else if (strcmp (w, "-o") == 0) { if (!p->next) { builtin_error("-o needs VARNAME"); return EX_USAGE; } p = p->next; var_out = p->word->word; }
      else { builtin_error ("unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!password || !salt_hex)
    { builtin_error ("argon2id needs -p PW -s SALT_HEX"); return EX_USAGE; }
  if (passes < 1)            { builtin_error ("passes must be >= 1"); return EX_USAGE; }
  if (passes > 10)           { builtin_error ("passes must be <= 10"); return EX_USAGE; }
  if (lanes < 1)             { builtin_error ("lanes must be >= 1"); return EX_USAGE; }
  if (lanes > 8)             { builtin_error ("lanes must be <= 8"); return EX_USAGE; }
  if (mem_kib > 262144)      { builtin_error ("mem_kib must be <= 262144"); return EX_USAGE; }
  if (mem_kib < 8 * lanes)   { builtin_error ("mem_kib must be >= 8 * lanes (%u)", 8 * lanes); return EX_USAGE; }
  if (out_len == 0 || out_len > 1024) { builtin_error ("LEN must be 1..1024"); return EX_USAGE; }

  unsigned char salt[64];
  int salt_len = bc_unhex (salt_hex, salt, sizeof salt);
  if (salt_len < 0) { builtin_error ("bad salt hex"); return EX_USAGE; }
  if (salt_len < 8) { builtin_error ("salt should be >= 8 bytes (RFC 9106 §3.1; 16 recommended)"); return EX_USAGE; }

  unsigned char out[1024];
  if (bashos_auth_argon2id_raw ((const unsigned char *) password,
                                strlen (password), salt, (size_t) salt_len,
                                passes, mem_kib, lanes, out, out_len,
                                quiet_mlock, "crypto") < 0)
    return EXECUTION_FAILURE;

  int rc = bc_emit_to (out, out_len, hex_out, var_out);
  crypto_wipe (out, sizeof out);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ---- Constant-time compare (verify-ct) ----------------------------- */
/* Bash's `[[ a == b ]]` short-circuits on the first mismatching byte;
 * comparing a derived hash to a stored hash that way leaks the prefix
 * length via timing. verify-ct compares two equal-length hex-encoded
 * buffers in constant time — exit 0 on equality, 1 on inequality, with
 * the running time independent of WHERE the mismatch falls.
 *
 * Length mismatch is NOT a timing leak (the lengths are not secret),
 * so we short-circuit on that with a fast fail.
 *
 * For the canonical fixed sizes (16/32/64 bytes — Poly1305 tag, SHA-256
 * digest, SHA-512 digest / Ed25519 sig) we delegate to monocypher's
 * crypto_verify16/32/64, which are individually constant-time and
 * register-only. For arbitrary lengths we run a byte-loop with an
 * OR-accumulator: every byte is touched exactly once, and the result
 * is the OR of all per-byte XORs.
 */
static int
bc_verify_ct_cmd (WORD_LIST *args)
{
  const char *p[2];
  int n = 0;
  for (WORD_LIST *p_ = args; p_; p_ = p_->next)
    {
      if (n >= 2) { builtin_error ("verify-ct: extra arg %s", p_->word->word); return EX_USAGE; }
      p[n++] = p_->word->word;
    }
  if (n != 2) { builtin_error ("verify-ct needs HEX_A HEX_B"); return EX_USAGE; }

  size_t la = strlen (p[0]), lb = strlen (p[1]);
  /* Reject non-equal hex lengths — lengths aren't secret. */
  if (la != lb) return EXECUTION_FAILURE;
  if (la & 1)   { builtin_error ("verify-ct: hex length must be even"); return EX_USAGE; }
  size_t bytes = la / 2;
  if (bytes == 0) return EXECUTION_SUCCESS;  /* both empty == equal */

  /* Decode into stack buffers up to 256 bytes; spill to malloc above that. */
  unsigned char a_stack[256], b_stack[256];
  unsigned char *a = a_stack, *b = b_stack;
  unsigned char *a_heap = NULL, *b_heap = NULL;
  if (bytes > sizeof a_stack)
    {
      a_heap = malloc (bytes); b_heap = malloc (bytes);
      if (!a_heap || !b_heap)
        { free (a_heap); free (b_heap); builtin_error ("verify-ct: oom"); return EXECUTION_FAILURE; }
      a = a_heap; b = b_heap;
    }

  if (bc_unhex (p[0], a, bytes) != (int) bytes ||
      bc_unhex (p[1], b, bytes) != (int) bytes)
    {
      free (a_heap); free (b_heap);
      builtin_error ("verify-ct: bad hex");
      return EX_USAGE;
    }

  int eq;
  if      (bytes == 16) eq = (crypto_verify16 (a, b) == 0);
  else if (bytes == 32) eq = (crypto_verify32 (a, b) == 0);
  else if (bytes == 64) eq = (crypto_verify64 (a, b) == 0);
  else
    {
      /* Generic constant-time byte-XOR-OR. Compiler must not be allowed
         to short-circuit; volatile accumulator + explicit loop bound
         keeps it honest under -O2. */
      volatile unsigned char acc = 0;
      for (size_t i = 0; i < bytes; i++)
        acc |= (unsigned char) (a[i] ^ b[i]);
      eq = (acc == 0);
    }

  /* Wipe the decoded buffers — verify-ct is typically called with
     secret-derived material (password hashes, MACs). */
  crypto_wipe (a, bytes);
  crypto_wipe (b, bytes);
  free (a_heap); free (b_heap);

  return eq ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ---- mbedTLS bridge (Stage 19.A.2) --------------------------------- */

/* `crypto mbedtls-version` — print the linked mbedTLS version. Verb
   exists ONLY to prove the _mbedtls/ flatten + linker wiring; it has no
   crypto effect. Stage 19.B replaces this stub-vicinity with real PSA-
   backed primitives + the TLS state machine. */
static int
bc_mbedtls_version_cmd (WORD_LIST *args)
{
  int show_full = 0;
  int show_num  = 0;
  for (; args; args = args->next)
    {
      const char *w = args->word->word;
      if (!strcmp (w, "-f"))      show_full = 1;
      else if (!strcmp (w, "-n")) show_num = 1;
      else if (!strcmp (w, "--")) { args = args->next; break; }
      else { builtin_error ("mbedtls-version: unknown arg: %s", w); return EX_USAGE; }
    }
  if (show_full && show_num)
    {
      builtin_error ("mbedtls-version: -f and -n are mutually exclusive");
      return EX_USAGE;
    }
  if (show_num)
    {
      /* Format MMNNPP00 as 0xMMNNPP00 — matches the upstream
         MBEDTLS_VERSION_NUMBER convention so callers can binary-compare
         the integer against MBEDTLS_VERSION_MAJOR/MINOR/PATCH macros. */
      printf ("0x%08x\n", mbedtls_version_get_number ());
      return EXECUTION_SUCCESS;
    }
  const char *s = show_full ? mbedtls_version_get_string_full ()
                            : mbedtls_version_get_string ();
  if (!s) { builtin_error ("mbedtls-version: linker returned NULL"); return EXECUTION_FAILURE; }
  printf ("%s\n", s);
  return EXECUTION_SUCCESS;
}

/* `crypto sha256-mbedtls [-x] [FILE]` — Stage 19.B SHA-256 via
   the mbedtls API. Reads FILE (or stdin if absent), writes 32 raw
   bytes (or 64 hex chars with -x) to stdout. Proves the "one verb at
   a time" migration path: same user-facing semantics as `crypto
   sha256` but routes through the mbedtls API surface staged in
   _mbedtls/sha256.{c,h}. Stage 19.D consolidates this by switching
   the bare verb to this implementation. */
static int
bc_sha256_mbedtls_cmd (WORD_LIST *args)
{
    int hex_mode = 0;
    const char *path = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-x")) hex_mode = 1;
        else if (!path)             path = w;
        else { builtin_error ("sha256-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    int fd = 0;  /* stdin */
    if (path) {
        fd = open (path, O_RDONLY);
        if (fd < 0) { builtin_error ("sha256-mbedtls: open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
    }
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init (&ctx);
    if (mbedtls_sha256_starts (&ctx, 0) != 0) {
        builtin_error ("sha256-mbedtls: starts failed");
        if (path) close (fd); mbedtls_sha256_free (&ctx);
        return EXECUTION_FAILURE;
    }
    unsigned char buf[8192];
    ssize_t n;
    while ((n = read (fd, buf, sizeof buf)) > 0) {
        if (mbedtls_sha256_update (&ctx, buf, (size_t) n) != 0) {
            builtin_error ("sha256-mbedtls: update failed");
            if (path) close (fd); mbedtls_sha256_free (&ctx);
            return EXECUTION_FAILURE;
        }
    }
    if (path) close (fd);
    if (n < 0) {
        builtin_error ("sha256-mbedtls: read: %s", strerror (errno));
        mbedtls_sha256_free (&ctx);
        return EXECUTION_FAILURE;
    }
    unsigned char digest[32];
    int rc = mbedtls_sha256_finish (&ctx, digest);
    mbedtls_sha256_free (&ctx);
    if (rc != 0) { builtin_error ("sha256-mbedtls: finish failed"); return EXECUTION_FAILURE; }
    if (hex_mode) {
        char hex[65];
        for (int i = 0; i < 32; i++) snprintf (hex + i*2, 3, "%02x", digest[i]);
        hex[64] = 0;
        printf ("%s\n", hex);
    } else {
        fwrite (digest, 1, 32, stdout);
    }
    if (fflush (stdout) != 0 || ferror (stdout)) {
        builtin_error ("write error");
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

/* `crypto hmac-sha256-mbedtls -k KEY_HEX [-x] [FILE]` — Stage 19.B
   HMAC-SHA256 via the mbedtls primitive. Reads FILE (or stdin); KEY
   is hex-encoded on the CLI so it survives bash variables without

   `crypto hmac-sha256`). Output: 32 raw bytes (or 64 hex with -x). */
static int
bc_hmac_sha256_mbedtls_cmd (WORD_LIST *args)
{
    int hex_mode = 0;
    const char *key_hex = NULL;
    const char *path    = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-x"))             hex_mode = 1;
        else if (!strcmp (w, "-k") && p->next)  { p = p->next; key_hex = p->word->word; }
        else if (!path)                          path = w;
        else { builtin_error ("hmac-sha256-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!key_hex) { builtin_error ("hmac-sha256-mbedtls: -k KEY_HEX required"); return EX_USAGE; }

    size_t kxlen = strlen (key_hex);
    if (kxlen & 1) { builtin_error ("hmac-sha256-mbedtls: KEY_HEX length must be even"); return EX_USAGE; }
    size_t keylen = kxlen / 2;
    unsigned char key_stack[256];
    unsigned char *key = key_stack;
    unsigned char *key_heap = NULL;
    if (keylen > sizeof key_stack) {
        key_heap = malloc (keylen);
        if (!key_heap) { builtin_error ("hmac-sha256-mbedtls: oom"); return EXECUTION_FAILURE; }
        key = key_heap;
    }
    if (bc_unhex (key_hex, key, keylen) != (int) keylen) {
        builtin_error ("hmac-sha256-mbedtls: bad hex in KEY");
        free (key_heap);
        return EX_USAGE;
    }

    int fd = 0;
    if (path) {
        fd = open (path, O_RDONLY);
        if (fd < 0) {
            builtin_error ("hmac-sha256-mbedtls: open %s: %s", path, strerror (errno));
            free (key_heap);
            return EXECUTION_FAILURE;
        }
    }

    mbedtls_hmac_sha256_context ctx;
    mbedtls_hmac_sha256_init (&ctx);
    int rc = mbedtls_hmac_sha256_starts (&ctx, key, keylen);
    if (rc != 0) {
        builtin_error ("hmac-sha256-mbedtls: starts failed");
        if (path) close (fd);
        mbedtls_hmac_sha256_free (&ctx); free (key_heap);
        return EXECUTION_FAILURE;
    }

    unsigned char buf[8192];
    ssize_t n;
    while ((n = read (fd, buf, sizeof buf)) > 0) {
        if (mbedtls_hmac_sha256_update (&ctx, buf, (size_t) n) != 0) {
            builtin_error ("hmac-sha256-mbedtls: update failed");
            if (path) close (fd);
            mbedtls_hmac_sha256_free (&ctx); free (key_heap);
            return EXECUTION_FAILURE;
        }
    }
    if (path) close (fd);
    if (n < 0) {
        builtin_error ("hmac-sha256-mbedtls: read: %s", strerror (errno));
        mbedtls_hmac_sha256_free (&ctx); free (key_heap);
        return EXECUTION_FAILURE;
    }

    unsigned char tag[32];
    rc = mbedtls_hmac_sha256_finish (&ctx, tag);
    mbedtls_hmac_sha256_free (&ctx);
    free (key_heap);
    if (rc != 0) { builtin_error ("hmac-sha256-mbedtls: finish failed"); return EXECUTION_FAILURE; }

    if (hex_mode) {
        char hex[65];
        for (int i = 0; i < 32; i++) snprintf (hex + i*2, 3, "%02x", tag[i]);
        hex[64] = 0;
        printf ("%s\n", hex);
    } else {
        fwrite (tag, 1, 32, stdout);
    }
    return EXECUTION_SUCCESS;
}

/* ---- SHA-512 / HMAC-SHA512 (mbedTLS) -------------------------------- */

static int
bc_sha384_mbedtls_cmd (WORD_LIST *args)
{
    int hex_mode = 0;
    const char *path = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-x")) hex_mode = 1;
        else if (!path)             path = w;
        else { builtin_error ("sha384-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    int fd = 0;
    if (path) {
        fd = open (path, O_RDONLY);
        if (fd < 0) { builtin_error ("sha384-mbedtls: open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
    }
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init (&ctx);
    if (mbedtls_sha512_starts (&ctx, 1) != 0) {
        builtin_error ("sha384-mbedtls: starts failed");
        if (path) close (fd); mbedtls_sha512_free (&ctx);
        return EXECUTION_FAILURE;
    }
    unsigned char buf[8192];
    ssize_t n;
    while ((n = read (fd, buf, sizeof buf)) > 0) {
        if (mbedtls_sha512_update (&ctx, buf, (size_t) n) != 0) {
            builtin_error ("sha384-mbedtls: update failed");
            if (path) close (fd); mbedtls_sha512_free (&ctx);
            return EXECUTION_FAILURE;
        }
    }
    if (path) close (fd);
    if (n < 0) {
        builtin_error ("sha384-mbedtls: read: %s", strerror (errno));
        mbedtls_sha512_free (&ctx);
        return EXECUTION_FAILURE;
    }
    unsigned char digest[64];
    int rc = mbedtls_sha512_finish (&ctx, digest);
    mbedtls_sha512_free (&ctx);
    if (rc != 0) { builtin_error ("sha384-mbedtls: finish failed"); return EXECUTION_FAILURE; }

    if (hex_mode) {
        char hex[97];
        for (int i = 0; i < 48; i++) snprintf (hex + i*2, 3, "%02x", digest[i]);
        hex[96] = 0;
        printf ("%s\n", hex);
    } else {
        fwrite (digest, 1, 48, stdout);
    }
    return EXECUTION_SUCCESS;
}

static int
bc_sha512_mbedtls_cmd (WORD_LIST *args)
{
    int hex_mode = 0;
    const char *path = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-x")) hex_mode = 1;
        else if (!path)             path = w;
        else { builtin_error ("sha512-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    int fd = 0;
    if (path) {
        fd = open (path, O_RDONLY);
        if (fd < 0) { builtin_error ("sha512-mbedtls: open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
    }
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init (&ctx);
    if (mbedtls_sha512_starts (&ctx, 0) != 0) {
        builtin_error ("sha512-mbedtls: starts failed");
        if (path) close (fd); mbedtls_sha512_free (&ctx);
        return EXECUTION_FAILURE;
    }
    unsigned char buf[8192];
    ssize_t n;
    while ((n = read (fd, buf, sizeof buf)) > 0) {
        if (mbedtls_sha512_update (&ctx, buf, (size_t) n) != 0) {
            builtin_error ("sha512-mbedtls: update failed");
            if (path) close (fd); mbedtls_sha512_free (&ctx);
            return EXECUTION_FAILURE;
        }
    }
    if (path) close (fd);
    if (n < 0) {
        builtin_error ("sha512-mbedtls: read: %s", strerror (errno));
        mbedtls_sha512_free (&ctx);
        return EXECUTION_FAILURE;
    }
    unsigned char digest[64];
    int rc = mbedtls_sha512_finish (&ctx, digest);
    mbedtls_sha512_free (&ctx);
    if (rc != 0) { builtin_error ("sha512-mbedtls: finish failed"); return EXECUTION_FAILURE; }

    if (hex_mode) {
        char hex[129];
        for (int i = 0; i < 64; i++) snprintf (hex + i*2, 3, "%02x", digest[i]);
        hex[128] = 0;
        printf ("%s\n", hex);
    } else {
        fwrite (digest, 1, 64, stdout);
    }
    return EXECUTION_SUCCESS;
}

static int
bc_hmac_sha512_mbedtls_cmd (WORD_LIST *args)
{
    int hex_mode = 0;
    const char *key_hex = NULL;
    const char *path    = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-x"))             hex_mode = 1;
        else if (!strcmp (w, "-k") && p->next)  { p = p->next; key_hex = p->word->word; }
        else if (!path)                          path = w;
        else { builtin_error ("hmac-sha512-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!key_hex) { builtin_error ("hmac-sha512-mbedtls: -k KEY_HEX required"); return EX_USAGE; }

    size_t kxlen = strlen (key_hex);
    if (kxlen & 1) { builtin_error ("hmac-sha512-mbedtls: KEY_HEX length must be even"); return EX_USAGE; }
    size_t keylen = kxlen / 2;
    unsigned char key_stack[256];
    unsigned char *key = key_stack;
    unsigned char *key_heap = NULL;
    if (keylen > sizeof key_stack) {
        key_heap = malloc (keylen);
        if (!key_heap) { builtin_error ("hmac-sha512-mbedtls: oom"); return EXECUTION_FAILURE; }
        key = key_heap;
    }
    if (bc_unhex (key_hex, key, keylen) != (int) keylen) {
        builtin_error ("hmac-sha512-mbedtls: bad hex in KEY");
        free (key_heap);
        return EX_USAGE;
    }

    int fd = 0;
    if (path) {
        fd = open (path, O_RDONLY);
        if (fd < 0) {
            builtin_error ("hmac-sha512-mbedtls: open %s: %s", path, strerror (errno));
            free (key_heap);
            return EXECUTION_FAILURE;
        }
    }

    mbedtls_hmac_sha512_context ctx;
    mbedtls_hmac_sha512_init (&ctx);
    int rc = mbedtls_hmac_sha512_starts (&ctx, key, keylen);
    if (rc != 0) {
        builtin_error ("hmac-sha512-mbedtls: starts failed");
        if (path) close (fd);
        mbedtls_hmac_sha512_free (&ctx); free (key_heap);
        return EXECUTION_FAILURE;
    }

    unsigned char buf[8192];
    ssize_t n;
    while ((n = read (fd, buf, sizeof buf)) > 0) {
        if (mbedtls_hmac_sha512_update (&ctx, buf, (size_t) n) != 0) {
            builtin_error ("hmac-sha512-mbedtls: update failed");
            if (path) close (fd);
            mbedtls_hmac_sha512_free (&ctx); free (key_heap);
            return EXECUTION_FAILURE;
        }
    }
    if (path) close (fd);
    if (n < 0) {
        builtin_error ("hmac-sha512-mbedtls: read: %s", strerror (errno));
        mbedtls_hmac_sha512_free (&ctx); free (key_heap);
        return EXECUTION_FAILURE;
    }

    unsigned char tag[64];
    rc = mbedtls_hmac_sha512_finish (&ctx, tag);
    mbedtls_hmac_sha512_free (&ctx);
    free (key_heap);
    if (rc != 0) { builtin_error ("hmac-sha512-mbedtls: finish failed"); return EXECUTION_FAILURE; }

    if (hex_mode) {
        char hex[129];
        for (int i = 0; i < 64; i++) snprintf (hex + i*2, 3, "%02x", tag[i]);
        hex[128] = 0;
        printf ("%s\n", hex);
    } else {
        fwrite (tag, 1, 64, stdout);
    }
    return EXECUTION_SUCCESS;
}

/* ---- BLAKE2b (monocypher) ------------------------------------------ */

static int
bc_blake2b_cmd (WORD_LIST *args)
{
    int hex_mode = 0;
    const char *path = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-x")) hex_mode = 1;
        else if (!path)             path = w;
        else { builtin_error ("blake2b: unexpected arg: %s", w); return EX_USAGE; }
    }
    int fd = 0;
    if (path) {
        fd = open (path, O_RDONLY);
        if (fd < 0) { builtin_error ("blake2b: open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
    }

    crypto_blake2b_ctx ctx;
    crypto_blake2b_init (&ctx, 64);
    unsigned char buf[8192];
    ssize_t n;
    while ((n = read (fd, buf, sizeof buf)) > 0)
        crypto_blake2b_update (&ctx, buf, (size_t) n);
    if (path) close (fd);
    if (n < 0) {
        builtin_error ("blake2b: read: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }

    unsigned char digest[64];
    crypto_blake2b_final (&ctx, digest);
    if (hex_mode) {
        char hex[129];
        for (int i = 0; i < 64; i++) snprintf (hex + i*2, 3, "%02x", digest[i]);
        hex[128] = 0;
        printf ("%s\n", hex);
    } else {
        fwrite (digest, 1, 64, stdout);
    }
    return EXECUTION_SUCCESS;
}

/* ---- SHA-1 / HMAC-SHA1 (mbedTLS) ----------------------------------- */

static int
bc_sha1_mbedtls_cmd (WORD_LIST *args)
{
    int hex_mode = 0;
    const char *path = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-x")) hex_mode = 1;
        else if (!path)             path = w;
        else { builtin_error ("sha1-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    int fd = 0;
    if (path) {
        fd = open (path, O_RDONLY);
        if (fd < 0) { builtin_error ("sha1-mbedtls: open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
    }
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init (&ctx);
    mbedtls_sha1_starts (&ctx);
    unsigned char buf[8192]; ssize_t n;
    while ((n = read (fd, buf, sizeof buf)) > 0) {
        if (mbedtls_sha1_update (&ctx, buf, (size_t) n) != 0) {
            builtin_error ("sha1-mbedtls: update failed");
            if (path) close (fd); mbedtls_sha1_free (&ctx);
            return EXECUTION_FAILURE;
        }
    }
    if (path) close (fd);
    if (n < 0) { builtin_error ("sha1-mbedtls: read: %s", strerror (errno)); mbedtls_sha1_free (&ctx); return EXECUTION_FAILURE; }
    unsigned char digest[20];
    mbedtls_sha1_finish (&ctx, digest);
    mbedtls_sha1_free (&ctx);
    if (hex_mode) {
        char hex[41];
        for (int i = 0; i < 20; i++) snprintf (hex + i*2, 3, "%02x", digest[i]);
        hex[40] = 0; printf ("%s\n", hex);
    } else {
        fwrite (digest, 1, 20, stdout);
    }
    return EXECUTION_SUCCESS;
}

static int
bc_hmac_sha1_mbedtls_cmd (WORD_LIST *args)
{
    int hex_mode = 0;
    const char *key_hex = NULL, *path = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-x")) hex_mode = 1;
        else if (!strcmp (w, "-k") && p->next) { p = p->next; key_hex = p->word->word; }
        else if (!path) path = w;
        else { builtin_error ("hmac-sha1-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!key_hex) { builtin_error ("hmac-sha1-mbedtls: -k KEY_HEX required"); return EX_USAGE; }
    size_t kxlen = strlen (key_hex);
    if (kxlen & 1) { builtin_error ("hmac-sha1-mbedtls: KEY_HEX length must be even"); return EX_USAGE; }
    size_t keylen = kxlen / 2;
    unsigned char key_stack[256], *key = key_stack, *key_heap = NULL;
    if (keylen > sizeof key_stack) {
        key_heap = malloc (keylen);
        if (!key_heap) { builtin_error ("hmac-sha1-mbedtls: oom"); return EXECUTION_FAILURE; }
        key = key_heap;
    }
    if (bc_unhex (key_hex, key, keylen) != (int) keylen) {
        builtin_error ("hmac-sha1-mbedtls: bad hex in KEY"); free (key_heap); return EX_USAGE;
    }
    int fd = 0;
    if (path) {
        fd = open (path, O_RDONLY);
        if (fd < 0) { builtin_error ("hmac-sha1-mbedtls: open %s: %s", path, strerror (errno)); free (key_heap); return EXECUTION_FAILURE; }
    }
    mbedtls_hmac_sha1_context ctx;
    mbedtls_hmac_sha1_init (&ctx);
    if (mbedtls_hmac_sha1_starts (&ctx, key, keylen) != 0) {
        builtin_error ("hmac-sha1-mbedtls: starts failed");
        if (path) close (fd); mbedtls_hmac_sha1_free (&ctx); free (key_heap);
        return EXECUTION_FAILURE;
    }
    unsigned char buf[8192]; ssize_t n;
    while ((n = read (fd, buf, sizeof buf)) > 0) {
        if (mbedtls_hmac_sha1_update (&ctx, buf, (size_t) n) != 0) {
            builtin_error ("hmac-sha1-mbedtls: update failed");
            if (path) close (fd); mbedtls_hmac_sha1_free (&ctx); free (key_heap);
            return EXECUTION_FAILURE;
        }
    }
    if (path) close (fd);
    if (n < 0) { builtin_error ("hmac-sha1-mbedtls: read: %s", strerror (errno)); mbedtls_hmac_sha1_free (&ctx); free (key_heap); return EXECUTION_FAILURE; }
    unsigned char tag[20];
    mbedtls_hmac_sha1_finish (&ctx, tag);
    mbedtls_hmac_sha1_free (&ctx);
    free (key_heap);
    if (hex_mode) {
        char hex[41];
        for (int i = 0; i < 20; i++) snprintf (hex + i*2, 3, "%02x", tag[i]);
        hex[40] = 0; printf ("%s\n", hex);
    } else {
        fwrite (tag, 1, 20, stdout);
    }
    return EXECUTION_SUCCESS;
}

/* ---- MD5 / HMAC-MD5 (mbedTLS) -------------------------------------- */

static int
bc_md5_mbedtls_cmd (WORD_LIST *args)
{
    int hex_mode = 0;
    const char *path = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-x")) hex_mode = 1;
        else if (!path)             path = w;
        else { builtin_error ("md5-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    int fd = 0;
    if (path) {
        fd = open (path, O_RDONLY);
        if (fd < 0) { builtin_error ("md5-mbedtls: open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
    }
    mbedtls_md5_context ctx;
    mbedtls_md5_init (&ctx);
    mbedtls_md5_starts (&ctx);
    unsigned char buf[8192]; ssize_t n;
    while ((n = read (fd, buf, sizeof buf)) > 0) {
        if (mbedtls_md5_update (&ctx, buf, (size_t) n) != 0) {
            builtin_error ("md5-mbedtls: update failed");
            if (path) close (fd); mbedtls_md5_free (&ctx);
            return EXECUTION_FAILURE;
        }
    }
    if (path) close (fd);
    if (n < 0) { builtin_error ("md5-mbedtls: read: %s", strerror (errno)); mbedtls_md5_free (&ctx); return EXECUTION_FAILURE; }
    unsigned char digest[16];
    mbedtls_md5_finish (&ctx, digest);
    mbedtls_md5_free (&ctx);
    if (hex_mode) {
        char hex[33];
        for (int i = 0; i < 16; i++) snprintf (hex + i*2, 3, "%02x", digest[i]);
        hex[32] = 0; printf ("%s\n", hex);
    } else {
        fwrite (digest, 1, 16, stdout);
    }
    return EXECUTION_SUCCESS;
}

static int
bc_hmac_md5_mbedtls_cmd (WORD_LIST *args)
{
    int hex_mode = 0;
    const char *key_hex = NULL, *path = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-x")) hex_mode = 1;
        else if (!strcmp (w, "-k") && p->next) { p = p->next; key_hex = p->word->word; }
        else if (!path) path = w;
        else { builtin_error ("hmac-md5-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!key_hex) { builtin_error ("hmac-md5-mbedtls: -k KEY_HEX required"); return EX_USAGE; }
    size_t kxlen = strlen (key_hex);
    if (kxlen & 1) { builtin_error ("hmac-md5-mbedtls: KEY_HEX length must be even"); return EX_USAGE; }
    size_t keylen = kxlen / 2;
    unsigned char key_stack[256], *key = key_stack, *key_heap = NULL;
    if (keylen > sizeof key_stack) {
        key_heap = malloc (keylen);
        if (!key_heap) { builtin_error ("hmac-md5-mbedtls: oom"); return EXECUTION_FAILURE; }
        key = key_heap;
    }
    if (bc_unhex (key_hex, key, keylen) != (int) keylen) {
        builtin_error ("hmac-md5-mbedtls: bad hex in KEY"); free (key_heap); return EX_USAGE;
    }
    int fd = 0;
    if (path) {
        fd = open (path, O_RDONLY);
        if (fd < 0) { builtin_error ("hmac-md5-mbedtls: open %s: %s", path, strerror (errno)); free (key_heap); return EXECUTION_FAILURE; }
    }
    mbedtls_hmac_md5_context ctx;
    mbedtls_hmac_md5_init (&ctx);
    if (mbedtls_hmac_md5_starts (&ctx, key, keylen) != 0) {
        builtin_error ("hmac-md5-mbedtls: starts failed");
        if (path) close (fd); mbedtls_hmac_md5_free (&ctx); free (key_heap);
        return EXECUTION_FAILURE;
    }
    unsigned char buf[8192]; ssize_t n;
    while ((n = read (fd, buf, sizeof buf)) > 0) {
        if (mbedtls_hmac_md5_update (&ctx, buf, (size_t) n) != 0) {
            builtin_error ("hmac-md5-mbedtls: update failed");
            if (path) close (fd); mbedtls_hmac_md5_free (&ctx); free (key_heap);
            return EXECUTION_FAILURE;
        }
    }
    if (path) close (fd);
    if (n < 0) { builtin_error ("hmac-md5-mbedtls: read: %s", strerror (errno)); mbedtls_hmac_md5_free (&ctx); free (key_heap); return EXECUTION_FAILURE; }
    unsigned char tag[16];
    mbedtls_hmac_md5_finish (&ctx, tag);
    mbedtls_hmac_md5_free (&ctx);
    free (key_heap);
    if (hex_mode) {
        char hex[33];
        for (int i = 0; i < 16; i++) snprintf (hex + i*2, 3, "%02x", tag[i]);
        hex[32] = 0; printf ("%s\n", hex);
    } else {
        fwrite (tag, 1, 16, stdout);
    }
    return EXECUTION_SUCCESS;
}

/* ---- X.509 cert parse + self-sig verify (mbedTLS) ------------------ */
/*
 * `crypto x509-parse-mbedtls [-p|-v]` — read DER from stdin, print
 * fields. With `-v`, additionally verify the cert's signature against
 * its own pubkey (only meaningful for self-signed certs / roots).
 *
 * This is the building block for full chain validation: callers feed
 * each cert in turn, then hash issuer's TBS and verify with the next
 * cert's pubkey up the chain.
 */
static const char *sig_alg_name(mbedtls_sig_alg_t a)
{
    switch (a) {
        case MBEDTLS_SIG_RSA_SHA256:   return "rsa-sha256";
        case MBEDTLS_SIG_RSA_SHA384:   return "rsa-sha384";
        case MBEDTLS_SIG_RSA_SHA512:   return "rsa-sha512";
        case MBEDTLS_SIG_RSA_SHA1:     return "rsa-sha1";
        case MBEDTLS_SIG_ECDSA_SHA256: return "ecdsa-sha256";
        case MBEDTLS_SIG_ECDSA_SHA384: return "ecdsa-sha384";
        case MBEDTLS_SIG_ECDSA_SHA512: return "ecdsa-sha512";
        default:                       return "unknown";
    }
}

static int
bc_x509_parse_mbedtls_cmd (WORD_LIST *args)
{
    int verify = 0;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-v") || !strcmp (w, "--verify-self")) verify = 1;
        else if (!strcmp (w, "-p") || !strcmp (w, "--print")) verify = 0;
        else { builtin_error ("x509-parse-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }

    /* Slurp DER from stdin. */
    unsigned char *der; size_t derlen;
    if (bc_slurp_fd (STDIN_FILENO, &der, &derlen) < 0) return EXECUTION_FAILURE;

    mbedtls_x509_crt_min crt;
    int rc = mbedtls_x509_crt_min_parse (der, derlen, &crt);
    if (rc != 0) {
        free (der);
        builtin_error ("x509-parse-mbedtls: parse failed (rc=%d)", rc);
        return EXECUTION_FAILURE;
    }

    /* Print key fields. */
    printf ("version: v%d\n", crt.version);
    printf ("serial: ");
    for (size_t i = 0; i < crt.serial.len; i++) printf ("%02x", crt.serial.p[i]);
    printf ("\n");
    printf ("not_before: %.*s\n", (int) crt.not_before_raw.len, crt.not_before_raw.p);
    printf ("not_after:  %.*s\n", (int) crt.not_after_raw.len, crt.not_after_raw.p);
    printf ("sig_alg: %s\n", sig_alg_name (crt.sig_alg));
    printf ("pk_type: %s\n",
            crt.pk_type == MBEDTLS_PK_RSA   ? "rsa" :
            crt.pk_type == MBEDTLS_PK_ECDSA ? "ecdsa" : "unknown");
    if (crt.pk_type == MBEDTLS_PK_RSA) {
        printf ("rsa_modulus_bits: %zu\n", crt.rsa_n.len * 8);
        printf ("rsa_e: ");
        for (size_t i = 0; i < crt.rsa_e.len; i++) printf ("%02x", crt.rsa_e.p[i]);
        printf ("\n");
    } else if (crt.pk_type == MBEDTLS_PK_ECDSA) {
        printf ("ec_curve_oid: ");
        for (size_t i = 0; i < crt.ec_curve_oid.len; i++) printf ("%02x", crt.ec_curve_oid.p[i]);
        printf ("\n");
        printf ("ec_pub_bytes: %zu\n", crt.ec_pub.len);
    }
    printf ("tbs_offset: %zu\n", (size_t) (crt.tbs.p - crt.raw.p));
    printf ("tbs_length: %zu\n", crt.tbs.len);

    int ret_code = EXECUTION_SUCCESS;

    if (verify) {
        if (crt.pk_type == MBEDTLS_PK_RSA &&
            (crt.sig_alg == MBEDTLS_SIG_RSA_SHA256 ||
             crt.sig_alg == MBEDTLS_SIG_RSA_SHA384 ||
             crt.sig_alg == MBEDTLS_SIG_RSA_SHA512 ||
             crt.sig_alg == MBEDTLS_SIG_RSA_SHA1)) {
            unsigned char digest[64]; size_t dlen = 0;
            mbedtls_rsa_md_id_t md_id = MBEDTLS_RSA_MD_SHA256;
            switch (crt.sig_alg) {
                case MBEDTLS_SIG_RSA_SHA256: md_id = MBEDTLS_RSA_MD_SHA256; dlen = 32; mbedtls_sha256 (crt.tbs.p, crt.tbs.len, digest, 0); break;
                case MBEDTLS_SIG_RSA_SHA384: md_id = MBEDTLS_RSA_MD_SHA384; dlen = 48; mbedtls_sha512 (crt.tbs.p, crt.tbs.len, digest, 1); break;
                case MBEDTLS_SIG_RSA_SHA512: md_id = MBEDTLS_RSA_MD_SHA512; dlen = 64; mbedtls_sha512 (crt.tbs.p, crt.tbs.len, digest, 0); break;
                case MBEDTLS_SIG_RSA_SHA1:   md_id = MBEDTLS_RSA_MD_SHA1;   dlen = 20; mbedtls_sha1 (crt.tbs.p, crt.tbs.len, digest); break;
                default: break;
            }
            int vrc = mbedtls_rsa_min_pkcs1_verify (crt.rsa_n.p, crt.rsa_n.len,
                                                crt.rsa_e.p, crt.rsa_e.len,
                                                md_id, digest, dlen, crt.sig_value.p);
            printf ("self_sig_verify: %s\n", vrc == 0 ? "VALID" : "INVALID");
            ret_code = vrc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        } else {
            printf ("self_sig_verify: SKIP (only RSA-SHAxxx self-verify supported in this build)\n");
        }
    }

    free (der);
    return ret_code;
}

/* ---- X.509 chain validate (mbedTLS) -------------------------------- */
/*
 * `crypto x509-chain-verify-mbedtls -c CHAIN_DER -t TRUST_DER [--time TS]`
 *
 * Read leaf cert from -c, trust anchor from -t, validate the
 * 1-element chain. Pass --time to override the validity-window check
 * (default: time(NULL); pass 0 to skip the check entirely).
 *
 * Output: prints `valid` or `invalid flags=0xNN` to stdout.
 * Returns 0 on valid, 1 on invalid.
 *
 * Multi-cert chains can be added by switching `-c` to a directory or a
 * concatenated DER blob; current shape covers the self-signed and
 * "leaf signed directly by root" cases.
 */
static int
bc_x509_chain_verify_mbedtls_cmd (WORD_LIST *args)
{
    const char *chain_path = NULL, *trust_path = NULL;
    int64_t override_time = -1;  /* -1 = use time(NULL) */

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-c") && p->next) { p = p->next; chain_path = p->word->word; }
        else if (!strcmp (w, "-t") && p->next) { p = p->next; trust_path = p->word->word; }
        else if (!strcmp (w, "--time") && p->next) {
            p = p->next; override_time = (int64_t) strtoll (p->word->word, NULL, 10);
        }
        else { builtin_error ("x509-chain-verify-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!chain_path || !trust_path) {
        builtin_error ("x509-chain-verify-mbedtls: -c CHAIN_DER -t TRUST_DER required");
        return EX_USAGE;
    }

    /* Read both files. */
    unsigned char *chain_buf, *trust_buf;
    size_t chain_len, trust_len;
    int fd = open (chain_path, O_RDONLY);
    if (fd < 0) { builtin_error ("open %s: %s", chain_path, strerror (errno)); return EXECUTION_FAILURE; }
    if (bc_slurp_fd (fd, &chain_buf, &chain_len) < 0) { close (fd); return EXECUTION_FAILURE; }
    close (fd);

    fd = open (trust_path, O_RDONLY);
    if (fd < 0) { free (chain_buf); builtin_error ("open %s: %s", trust_path, strerror (errno)); return EXECUTION_FAILURE; }
    if (bc_slurp_fd (fd, &trust_buf, &trust_len) < 0) { close (fd); free (chain_buf); return EXECUTION_FAILURE; }
    close (fd);

    mbedtls_x509_crt_min chain_crt, trust_crt;
    int rc = mbedtls_x509_crt_min_parse (chain_buf, chain_len, &chain_crt);
    if (rc != 0) {
        free (chain_buf); free (trust_buf);
        builtin_error ("x509-chain-verify-mbedtls: parse chain (rc=%d)", rc);
        return EXECUTION_FAILURE;
    }
    rc = mbedtls_x509_crt_min_parse (trust_buf, trust_len, &trust_crt);
    if (rc != 0) {
        free (chain_buf); free (trust_buf);
        builtin_error ("x509-chain-verify-mbedtls: parse trust (rc=%d)", rc);
        return EXECUTION_FAILURE;
    }

    int64_t now = (override_time >= 0) ? override_time : (int64_t) time (NULL);
    uint32_t flags = 0;
    rc = mbedtls_x509_chain_verify (&chain_crt, 1, &trust_crt, 1, now, &flags);

    if (rc == 0 && flags == 0) {
        printf ("valid\n");
    } else {
        printf ("invalid flags=0x%02x", (unsigned) flags);
        if (flags & MBEDTLS_X509_BADCRT_NOT_TRUSTED)       printf (" NOT_TRUSTED");
        if (flags & MBEDTLS_X509_BADCRT_EXPIRED)           printf (" EXPIRED");
        if (flags & MBEDTLS_X509_BADCRT_NOT_YET_VALID)     printf (" NOT_YET_VALID");
        if (flags & MBEDTLS_X509_BADCRT_NAME_CHAIN_BROKEN) printf (" NAME_CHAIN_BROKEN");
        if (flags & MBEDTLS_X509_BADCRT_BAD_SIG)           printf (" BAD_SIG");
        if (flags & MBEDTLS_X509_BADCRT_BAD_PK)            printf (" BAD_PK");
        if (flags & MBEDTLS_X509_BADCRT_INTERNAL_ERROR)    printf (" INTERNAL_ERROR");
        printf ("\n");
    }

    free (chain_buf); free (trust_buf);
    return (rc == 0 && flags == 0) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ---- RSA-PKCS1.5 verify (mbedTLS) ---------------------------------- */
/* `crypto rsa-verify-mbedtls -n MOD_HEX -e EXP_HEX -s SIG_HEX -a HASH < message`
 *   Returns 0 if valid, 1 if invalid.
 *   HASH ∈ {sha1, sha256, sha384, sha512}.
 *   Hashes the stdin message and verifies the PKCS#1 v1.5 signature.
 */
static int
bc_rsa_verify_mbedtls_cmd (WORD_LIST *args)
{
    const char *mod_hex = NULL, *exp_hex = NULL, *sig_hex = NULL, *hash_name = "sha256";
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-n") && p->next) { p = p->next; mod_hex = p->word->word; }
        else if (!strcmp (w, "-e") && p->next) { p = p->next; exp_hex = p->word->word; }
        else if (!strcmp (w, "-s") && p->next) { p = p->next; sig_hex = p->word->word; }
        else if (!strcmp (w, "-a") && p->next) { p = p->next; hash_name = p->word->word; }
        else { builtin_error ("rsa-verify-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!mod_hex || !exp_hex || !sig_hex) {
        builtin_error ("rsa-verify-mbedtls: -n MOD_HEX -e EXP_HEX -s SIG_HEX required");
        return EX_USAGE;
    }

    /* Decode modulus, exponent, signature. */
    unsigned char modulus[1024], expon[16], signature[1024];
    int mod_len = bc_unhex (mod_hex, modulus, sizeof modulus);
    int exp_len = bc_unhex (exp_hex, expon,   sizeof expon);
    int sig_len = bc_unhex (sig_hex, signature, sizeof signature);
    if (mod_len <= 0)              { builtin_error ("rsa-verify-mbedtls: bad MOD_HEX"); return EX_USAGE; }
    if (exp_len <= 0)              { builtin_error ("rsa-verify-mbedtls: bad EXP_HEX"); return EX_USAGE; }
    if (sig_len <= 0)              { builtin_error ("rsa-verify-mbedtls: bad SIG_HEX"); return EX_USAGE; }
    if (sig_len != mod_len)        {
        builtin_error ("rsa-verify-mbedtls: SIG length (%d) != modulus length (%d)", sig_len, mod_len);
        return EX_USAGE;
    }

    /* Pick hash and compute digest of stdin. */
    mbedtls_rsa_md_id_t md_id;
    unsigned char digest[64];
    size_t digest_len = 0;
    if (!strcmp (hash_name, "sha256")) {
        md_id = MBEDTLS_RSA_MD_SHA256; digest_len = 32;
    } else if (!strcmp (hash_name, "sha384")) {
        md_id = MBEDTLS_RSA_MD_SHA384; digest_len = 48;
    } else if (!strcmp (hash_name, "sha512")) {
        md_id = MBEDTLS_RSA_MD_SHA512; digest_len = 64;
    } else if (!strcmp (hash_name, "sha1")) {
        md_id = MBEDTLS_RSA_MD_SHA1;   digest_len = 20;
    } else {
        builtin_error ("rsa-verify-mbedtls: unknown hash '%s' (sha1, sha256, sha384, sha512)", hash_name);
        return EX_USAGE;
    }

    unsigned char *msg; size_t mlen;
    if (bc_slurp_fd (STDIN_FILENO, &msg, &mlen) < 0) return EXECUTION_FAILURE;

    if (md_id == MBEDTLS_RSA_MD_SHA256)      mbedtls_sha256 (msg, mlen, digest, 0);
    else if (md_id == MBEDTLS_RSA_MD_SHA512) mbedtls_sha512 (msg, mlen, digest, 0);
    else if (md_id == MBEDTLS_RSA_MD_SHA384) mbedtls_sha512 (msg, mlen, digest, 1);
    else if (md_id == MBEDTLS_RSA_MD_SHA1)   mbedtls_sha1   (msg, mlen, digest);
    free (msg);

    int rc = mbedtls_rsa_min_pkcs1_verify (modulus, (size_t) mod_len,
                                       expon,   (size_t) exp_len,
                                       md_id, digest, digest_len, signature);
    return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ---- AES-SIV-CMAC AEAD (RFC 5297 / NTS AEAD id 15) ---------------- */

static int
bc_ct_memcmp (const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= (unsigned char) (a[i] ^ b[i]);
    return diff;
}

static void
bc_dbl_128 (const unsigned char in[16], unsigned char out[16])
{
    unsigned char carry = 0;
    for (int i = 15; i >= 0; i--) {
        unsigned char next = (unsigned char) (in[i] >> 7);
        out[i] = (unsigned char) ((in[i] << 1) | carry);
        carry = next;
    }
    if (carry)
        out[15] ^= 0x87;
}

static int
bc_cmac_aes128 (const unsigned char key[16],
                const unsigned char *in, size_t in_len,
                unsigned char out[16])
{
    unsigned char l[16], k1[16], k2[16], x[16], y[16], m_last[16];
    unsigned char zero[16] = { 0 };
    mbedtls_aes_context aes;
    mbedtls_aes_init (&aes);
    int rc = mbedtls_aes_setkey_enc (&aes, key, 128);
    if (rc == 0)
        rc = mbedtls_aes_crypt_ecb (&aes, MBEDTLS_AES_ENCRYPT, zero, l);
    if (rc != 0) {
        mbedtls_aes_free (&aes);
        crypto_wipe (l, sizeof l);
        return -1;
    }

    bc_dbl_128 (l, k1);
    bc_dbl_128 (k1, k2);

    size_t n = (in_len + 15) / 16;
    int complete = (in_len > 0 && (in_len % 16) == 0);
    if (n == 0)
        n = 1;

    if (complete) {
        memcpy (m_last, in + ((n - 1) * 16), 16);
        for (size_t i = 0; i < 16; i++)
            m_last[i] ^= k1[i];
    } else {
        size_t last_len = in_len % 16;
        memset (m_last, 0, sizeof m_last);
        if (last_len > 0)
            memcpy (m_last, in + ((n - 1) * 16), last_len);
        m_last[last_len] = 0x80;
        for (size_t i = 0; i < 16; i++)
            m_last[i] ^= k2[i];
    }

    memset (x, 0, sizeof x);
    for (size_t block = 0; block + 1 < n; block++) {
        const unsigned char *m = in + block * 16;
        for (size_t i = 0; i < 16; i++)
            y[i] = (unsigned char) (x[i] ^ m[i]);
        rc = mbedtls_aes_crypt_ecb (&aes, MBEDTLS_AES_ENCRYPT, y, x);
        if (rc != 0)
            break;
    }
    if (rc == 0) {
        for (size_t i = 0; i < 16; i++)
            y[i] = (unsigned char) (x[i] ^ m_last[i]);
        rc = mbedtls_aes_crypt_ecb (&aes, MBEDTLS_AES_ENCRYPT, y, out);
    }

    mbedtls_aes_free (&aes);
    crypto_wipe (l, sizeof l);
    crypto_wipe (k1, sizeof k1);
    crypto_wipe (k2, sizeof k2);
    crypto_wipe (x, sizeof x);
    crypto_wipe (y, sizeof y);
    crypto_wipe (m_last, sizeof m_last);
    return rc == 0 ? 0 : -1;
}

static int
bc_s2v (const unsigned char k1[16],
        const struct bc_aead_iov *ad, size_t ad_count,
        const unsigned char *pt, size_t pt_len,
        unsigned char siv[16])
{
    static const unsigned char zero[16] = { 0 };
    unsigned char d[16], tmp[16], block[16];

    if (bc_cmac_aes128 (k1, zero, sizeof zero, d) < 0)
        return -1;

    for (size_t i = 0; i < ad_count; i++) {
        if (bc_cmac_aes128 (k1, ad[i].ptr, ad[i].len, tmp) < 0) {
            crypto_wipe (d, sizeof d);
            crypto_wipe (tmp, sizeof tmp);
            return -1;
        }
        bc_dbl_128 (d, d);
        for (size_t j = 0; j < 16; j++)
            d[j] ^= tmp[j];
    }

    if (pt_len >= 16) {
        unsigned char *m = malloc (pt_len);
        if (!m) {
            crypto_wipe (d, sizeof d);
            crypto_wipe (tmp, sizeof tmp);
            builtin_error ("oom");
            return -1;
        }
        memcpy (m, pt, pt_len);
        for (size_t j = 0; j < 16; j++)
            m[pt_len - 16 + j] ^= d[j];
        int rc = bc_cmac_aes128 (k1, m, pt_len, siv);
        crypto_wipe (m, pt_len);
        free (m);
        crypto_wipe (d, sizeof d);
        crypto_wipe (tmp, sizeof tmp);
        return rc;
    }

    memset (block, 0, sizeof block);
    if (pt_len > 0)
        memcpy (block, pt, pt_len);
    block[pt_len] = 0x80;
    bc_dbl_128 (d, d);
    for (size_t j = 0; j < 16; j++)
        block[j] ^= d[j];

    int rc = bc_cmac_aes128 (k1, block, sizeof block, siv);
    crypto_wipe (d, sizeof d);
    crypto_wipe (tmp, sizeof tmp);
    crypto_wipe (block, sizeof block);
    return rc;
}

static int
bc_aes_siv_ctr_crypt (const unsigned char k2[16],
                      const unsigned char siv[16],
                      const unsigned char *in, size_t in_len,
                      unsigned char *out)
{
    unsigned char ctr[16], stream_block[16];
    memcpy (ctr, siv, sizeof ctr);
    ctr[8] &= 0x7f;
    ctr[12] &= 0x7f;
    memset (stream_block, 0, sizeof stream_block);

    mbedtls_aes_context aes;
    mbedtls_aes_init (&aes);
    int rc = mbedtls_aes_setkey_enc (&aes, k2, 128);
    for (size_t off = 0; rc == 0 && off < in_len; ) {
        rc = mbedtls_aes_crypt_ecb (&aes, MBEDTLS_AES_ENCRYPT, ctr, stream_block);
        if (rc != 0)
            break;
        size_t n = in_len - off;
        if (n > 16)
            n = 16;
        for (size_t i = 0; i < n; i++)
            out[off + i] = (unsigned char) (in[off + i] ^ stream_block[i]);
        off += n;
        for (int i = 15; i >= 0; i--) {
            ctr[i]++;
            if (ctr[i] != 0)
                break;
        }
    }
    mbedtls_aes_free (&aes);
    crypto_wipe (ctr, sizeof ctr);
    crypto_wipe (stream_block, sizeof stream_block);
    return rc == 0 ? 0 : -1;
}

int
bc_aes_siv_cmac_seal (const unsigned char key[32],
                      const struct bc_aead_iov *ad, size_t ad_count,
                      const unsigned char *pt, size_t pt_len,
                      unsigned char **out, size_t *out_len)
{
    if (!key || !out || !out_len || (!pt && pt_len > 0) ||
        (!ad && ad_count > 0))
        return -1;
    if (pt_len > ((size_t) -1) - 16)
        return -1;

    size_t n = pt_len + 16;
    unsigned char *buf = malloc (n ? n : 1);
    if (!buf) {
        builtin_error ("oom");
        return -1;
    }

    if (bc_s2v (key, ad, ad_count, pt, pt_len, buf) < 0 ||
        bc_aes_siv_ctr_crypt (key + 16, buf, pt, pt_len, buf + 16) < 0) {
        crypto_wipe (buf, n ? n : 1);
        free (buf);
        return -1;
    }

    *out = buf;
    *out_len = n;
    return 0;
}

int
bc_aes_siv_cmac_open (const unsigned char key[32],
                      const struct bc_aead_iov *ad, size_t ad_count,
                      const unsigned char *in, size_t in_len,
                      unsigned char **pt, size_t *pt_len)
{
    if (!key || !in || !pt || !pt_len || (!ad && ad_count > 0))
        return -1;
    if (in_len < 16)
        return -1;

    const unsigned char *siv = in;
    const unsigned char *ct = in + 16;
    size_t ct_len = in_len - 16;
    unsigned char *buf = malloc (ct_len ? ct_len : 1);
    unsigned char got[16];
    if (!buf) {
        builtin_error ("oom");
        return -1;
    }

    if (bc_aes_siv_ctr_crypt (key + 16, siv, ct, ct_len, buf) < 0 ||
        bc_s2v (key, ad, ad_count, buf, ct_len, got) < 0 ||
        bc_ct_memcmp (siv, got, sizeof got) != 0) {
        crypto_wipe (buf, ct_len ? ct_len : 1);
        free (buf);
        crypto_wipe (got, sizeof got);
        return -1;
    }

    crypto_wipe (got, sizeof got);
    *pt = buf;
    *pt_len = ct_len;
    return 0;
}

static void
bc_aead_iov_free (struct bc_aead_iov *ad, size_t ad_count)
{
    if (!ad)
        return;
    for (size_t i = 0; i < ad_count; i++) {
        if (ad[i].ptr) {
            crypto_wipe ((unsigned char *) ad[i].ptr, ad[i].len);
            free ((unsigned char *) ad[i].ptr);
        }
    }
    free (ad);
}

static int
bc_aes_siv_ad_append (struct bc_aead_iov **ad, size_t *ad_count,
                      const char *hex)
{
    size_t cap = strlen (hex) / 2 + 1;
    unsigned char *buf = malloc (cap ? cap : 1);
    if (!buf) {
        builtin_error ("oom");
        return -1;
    }
    int len = bc_unhex (hex, buf, cap ? cap : 1);
    if (len < 0) {
        free (buf);
        builtin_error ("aes-siv-cmac: bad hex in -A AAD");
        return -1;
    }
    struct bc_aead_iov *next = realloc (*ad, (*ad_count + 1) * sizeof **ad);
    if (!next) {
        crypto_wipe (buf, (size_t) len);
        free (buf);
        builtin_error ("oom");
        return -1;
    }
    *ad = next;
    (*ad)[*ad_count].ptr = buf;
    (*ad)[*ad_count].len = (size_t) len;
    (*ad_count)++;
    return 0;
}

static int
bc_aes_siv_decode_main_hex (unsigned char *in, size_t inlen,
                            unsigned char **out, size_t *outlen)
{
    char *hex = malloc (inlen + 1);
    if (!hex) {
        builtin_error ("oom");
        return -1;
    }
    memcpy (hex, in, inlen);
    hex[inlen] = '\0';
    size_t cap = inlen / 2 + 1;
    unsigned char *buf = malloc (cap ? cap : 1);
    if (!buf) {
        free (hex);
        builtin_error ("oom");
        return -1;
    }
    int len = bc_unhex (hex, buf, cap ? cap : 1);
    free (hex);
    if (len < 0) {
        free (buf);
        builtin_error ("aes-siv-cmac: bad hex input");
        return -1;
    }
    *out = buf;
    *outlen = (size_t) len;
    return 0;
}

static int
bc_aes_siv_cmac_cmd (WORD_LIST *args)
{
    int encrypt = -1;
    int hex_mode = 0;
    const char *key_hex = NULL;
    struct bc_aead_iov *ad = NULL;
    size_t ad_count = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-e")) {
            if (encrypt != -1) {
                builtin_error ("aes-siv-cmac: -e and -d are mutually exclusive");
                bc_aead_iov_free (ad, ad_count);
                return EX_USAGE;
            }
            encrypt = 1;
        }
        else if (!strcmp (w, "-d")) {
            if (encrypt != -1) {
                builtin_error ("aes-siv-cmac: -e and -d are mutually exclusive");
                bc_aead_iov_free (ad, ad_count);
                return EX_USAGE;
            }
            encrypt = 0;
        }
        else if (!strcmp (w, "-x")) hex_mode = 1;
        else if (!strcmp (w, "-k") && p->next) { p = p->next; key_hex = p->word->word; }
        else if (!strcmp (w, "-A") && p->next) {
            p = p->next;
            if (bc_aes_siv_ad_append (&ad, &ad_count, p->word->word) < 0) {
                bc_aead_iov_free (ad, ad_count);
                return EX_USAGE;
            }
        }
        else { builtin_error ("aes-siv-cmac: unexpected arg: %s", w); bc_aead_iov_free (ad, ad_count); return EX_USAGE; }
    }

    if (encrypt < 0 || !key_hex) {
        builtin_error ("aes-siv-cmac needs -e|-d -k KEY_HEX [-A AAD_HEX]... [-x]");
        bc_aead_iov_free (ad, ad_count);
        return EX_USAGE;
    }

    unsigned char key[32];
    if (bc_unhex (key_hex, key, sizeof key) != 32) {
        builtin_error ("aes-siv-cmac: KEY must be 32 bytes");
        bc_aead_iov_free (ad, ad_count);
        crypto_wipe (key, sizeof key);
        return EX_USAGE;
    }

    unsigned char *raw = NULL, *in = NULL, *out = NULL;
    size_t raw_len = 0, in_len = 0, out_len = 0;
    if (bc_slurp_fd (STDIN_FILENO, &raw, &raw_len) < 0) {
        bc_aead_iov_free (ad, ad_count);
        crypto_wipe (key, sizeof key);
        return EXECUTION_FAILURE;
    }

    if (hex_mode) {
        if (bc_aes_siv_decode_main_hex (raw, raw_len, &in, &in_len) < 0) {
            free (raw);
            bc_aead_iov_free (ad, ad_count);
            crypto_wipe (key, sizeof key);
            return EX_USAGE;
        }
        crypto_wipe (raw, raw_len);
        free (raw);
    } else {
        in = raw;
        in_len = raw_len;
    }

    int rc;
    if (encrypt) {
        rc = bc_aes_siv_cmac_seal (key, ad, ad_count, in, in_len, &out, &out_len);
        crypto_wipe (in, in_len);
        free (in);
        if (rc < 0) {
            builtin_error ("aes-siv-cmac: encrypt failed");
            bc_aead_iov_free (ad, ad_count);
            crypto_wipe (key, sizeof key);
            return EXECUTION_FAILURE;
        }
        rc = (bc_emit (out, out_len, hex_mode) == 0) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        free (out);
    } else {
        if (in_len < 16) {
            free (in);
            bc_aead_iov_free (ad, ad_count);
            crypto_wipe (key, sizeof key);
            builtin_error ("aes-siv-cmac: ciphertext too short to contain SIV");
            return EXECUTION_FAILURE;
        }
        rc = bc_aes_siv_cmac_open (key, ad, ad_count, in, in_len, &out, &out_len);
        free (in);
        if (rc < 0) {
            bc_aead_iov_free (ad, ad_count);
            crypto_wipe (key, sizeof key);
            builtin_error ("aes-siv-cmac: tag mismatch");
            return EXECUTION_FAILURE;
        }
        rc = (bc_emit (out, out_len, hex_mode) == 0) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        crypto_wipe (out, out_len ? out_len : 1);
        free (out);
    }

    bc_aead_iov_free (ad, ad_count);
    crypto_wipe (key, sizeof key);
    return rc;
}

/* ---- AEAD nonce-reuse guard ---------------------------------------- */

/* Process-static (key-fingerprint, nonce) tracker. When
 * BASHCRYPTO_NONCE_GUARD=1 is set, bc_nonce_record is called on
 * every AEAD encrypt; a duplicate (keyfp, nonce) pair refuses the
 * encrypt and returns rc 1 with a diagnostic.
 *
 * The fingerprint is SHA-256(key) so the table never stores raw key
 * bytes. The table is bounded at BC_NONCE_GUARD_MAX entries — when
 * full, refuses further encrypts (fail-closed: better to alert the
 * operator than silently let the GCM/ChaCha20-Poly1305 nonce-reuse
 * keystream-XOR break slip through).
 *
 * Per-process scope: protects within a single bash session. Cross-
 * process protection would need a file/IPC store — out of scope. */
#define BC_NONCE_GUARD_MAX 256
struct bc_nonce_entry {
    unsigned char keyfp[32];
    unsigned char nonce[16];
    size_t nonce_len;
};
static struct bc_nonce_entry bc_nonce_seen[BC_NONCE_GUARD_MAX];
static size_t bc_nonce_seen_count;

static int
bc_nonce_guard_enabled (void)
{
    const char *v = getenv ("BASHCRYPTO_NONCE_GUARD");
    if (!v || !*v) return 0;
    if (v[0] == '0' && v[1] == '\0') return 0;
    return 1;
}

/* Returns 0 on first-seen-and-stored, -1 on duplicate, -2 on table full. */
static int
bc_nonce_record (const unsigned char *key, size_t klen,
                 const unsigned char *nonce, size_t nlen)
{
    if (nlen > sizeof bc_nonce_seen[0].nonce) return -1;
    unsigned char fp[32];
    mbedtls_sha256 (key, klen, fp, 0);
    for (size_t i = 0; i < bc_nonce_seen_count; i++) {
        if (memcmp (bc_nonce_seen[i].keyfp, fp, 32) == 0 &&
            bc_nonce_seen[i].nonce_len == nlen &&
            memcmp (bc_nonce_seen[i].nonce, nonce, nlen) == 0)
            return -1;
    }
    if (bc_nonce_seen_count >= BC_NONCE_GUARD_MAX) return -2;
    memcpy (bc_nonce_seen[bc_nonce_seen_count].keyfp, fp, 32);
    memcpy (bc_nonce_seen[bc_nonce_seen_count].nonce, nonce, nlen);
    bc_nonce_seen[bc_nonce_seen_count].nonce_len = nlen;
    bc_nonce_seen_count++;
    return 0;
}

/* ---- ChaCha20-Poly1305 AEAD (mbedTLS) ------------------------------ */

static int
bc_chacha20_poly1305_mbedtls_cmd (WORD_LIST *args)
{
    int encrypt = -1;
    const char *key_hex = NULL, *nonce_hex = NULL, *aad_hex = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-e")) encrypt = 1;
        else if (!strcmp (w, "-d")) encrypt = 0;
        else if (!strcmp (w, "-k") && p->next) { p = p->next; key_hex   = p->word->word; }
        else if (!strcmp (w, "-n") && p->next) { p = p->next; nonce_hex = p->word->word; }
        else if (!strcmp (w, "-A") && p->next) { p = p->next; aad_hex   = p->word->word; }
        else { builtin_error ("chacha20-poly1305-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (encrypt < 0 || !key_hex || !nonce_hex) {
        builtin_error ("chacha20-poly1305-mbedtls needs -e|-d -k KEY -n NONCE");
        return EX_USAGE;
    }

    unsigned char key[32], nonce[12], aad[256];
    int klen = bc_unhex (key_hex, key, sizeof key);
    int nlen = bc_unhex (nonce_hex, nonce, sizeof nonce);
    int alen = aad_hex ? bc_unhex (aad_hex, aad, sizeof aad) : 0;
    if (klen != 32)  { builtin_error ("chacha20-poly1305-mbedtls: KEY must be 32 bytes"); return EX_USAGE; }
    if (nlen != 12)  { builtin_error ("chacha20-poly1305-mbedtls: NONCE must be 12 bytes"); return EX_USAGE; }
    if (alen < 0)    { builtin_error ("chacha20-poly1305-mbedtls: bad hex in -A AAD"); return EX_USAGE; }

    unsigned char *in; size_t inlen;
    if (bc_slurp_fd (STDIN_FILENO, &in, &inlen) < 0) return EXECUTION_FAILURE;

    if (encrypt) {
        if (bc_nonce_guard_enabled ()) {
            int g = bc_nonce_record (key, (size_t) klen, nonce, (size_t) nlen);
            if (g == -1) {
                builtin_error ("chacha20-poly1305-mbedtls: BASHCRYPTO_NONCE_GUARD: (key, nonce 0x%02x%02x...) reuse detected — refusing encrypt", nonce[0], nonce[1]);
                crypto_wipe (in, inlen); free (in);
                crypto_wipe (key, sizeof key); crypto_wipe (nonce, sizeof nonce); crypto_wipe (aad, sizeof aad);
                return EXECUTION_FAILURE;
            }
            if (g == -2) {
                builtin_error ("chacha20-poly1305-mbedtls: BASHCRYPTO_NONCE_GUARD: in-process tracker full (%d entries) — refusing encrypt", BC_NONCE_GUARD_MAX);
                crypto_wipe (in, inlen); free (in);
                crypto_wipe (key, sizeof key); crypto_wipe (nonce, sizeof nonce); crypto_wipe (aad, sizeof aad);
                return EXECUTION_FAILURE;
            }
        }
        unsigned char *ct  = malloc (inlen);
        unsigned char tag[16];
        if (!ct && inlen > 0) { crypto_wipe (in, inlen); free (in); builtin_error ("oom"); return EXECUTION_FAILURE; }
        mbedtls_chachapoly_context cp;
        mbedtls_chachapoly_init (&cp);
        int rc = mbedtls_chachapoly_setkey (&cp, key);
        if (rc == 0)
            rc = mbedtls_chachapoly_encrypt_and_tag (&cp, inlen, nonce,
                                                     aad, (size_t) alen,
                                                     in, ct, tag);
        mbedtls_chachapoly_free (&cp);
        crypto_wipe (in, inlen);                /* plaintext input → wipe */
        free (in);
        if (rc != 0) {
            free (ct);
            builtin_error ("chacha20-poly1305-mbedtls: encrypt failed (rc=%d)", rc);
            crypto_wipe (key, sizeof key);
            crypto_wipe (nonce, sizeof nonce);
            crypto_wipe (aad, sizeof aad);
            return EXECUTION_FAILURE;
        }
        if (inlen > 0) bc_write_all (ct, inlen);
        bc_write_all (tag, 16);
        free (ct);
        crypto_wipe (key, sizeof key);
        crypto_wipe (nonce, sizeof nonce);
        crypto_wipe (aad, sizeof aad);
        return EXECUTION_SUCCESS;
    } else {
        if (inlen < 16) {
            free (in);
            builtin_error ("chacha20-poly1305-mbedtls: ciphertext too short (need >= 16 for tag)");
            crypto_wipe (key, sizeof key);
            crypto_wipe (nonce, sizeof nonce);
            crypto_wipe (aad, sizeof aad);
            return EXECUTION_FAILURE;
        }
        size_t ct_len = inlen - 16;
        unsigned char *pt  = malloc (ct_len ? ct_len : 1);
        if (!pt) { free (in); builtin_error ("oom"); return EXECUTION_FAILURE; }
        const unsigned char *ct  = in;
        const unsigned char *tag = in + ct_len;
        mbedtls_chachapoly_context cp;
        mbedtls_chachapoly_init (&cp);
        int rc = mbedtls_chachapoly_setkey (&cp, key);
        if (rc == 0)
            rc = mbedtls_chachapoly_auth_decrypt (&cp, ct_len, nonce,
                                                  aad, (size_t) alen,
                                                  tag, ct, pt);
        mbedtls_chachapoly_free (&cp);
        if (rc != 0) {
            /* Wipe any partial plaintext mbedtls may have written before
               auth failure was detected. */
            crypto_wipe (pt, ct_len ? ct_len : 1);
            free (pt); free (in);
            builtin_error ("chacha20-poly1305-mbedtls: tag mismatch");
            crypto_wipe (key, sizeof key);
            crypto_wipe (nonce, sizeof nonce);
            crypto_wipe (aad, sizeof aad);
            return EXECUTION_FAILURE;
        }
        if (ct_len > 0) bc_write_all (pt, ct_len);
        crypto_wipe (pt, ct_len ? ct_len : 1);  /* plaintext output → wipe */
        free (pt); free (in);
        crypto_wipe (key, sizeof key);
        crypto_wipe (nonce, sizeof nonce);
        crypto_wipe (aad, sizeof aad);
        return EXECUTION_SUCCESS;
    }
}

/* `crypto hkdf-sha256-mbedtls -s SALT_HEX -k IKM_HEX [-i INFO_HEX]
 *                               -L LEN [-x]`
 * Stage 19.B HKDF via the mbedTLS HMAC-SHA256 primitive. Implements
 * RFC 5869 extract-and-expand with SHA-256. SALT and INFO are optional
 * hex strings; omitted salt follows RFC 5869 and uses HashLen zero bytes
 * for Extract. Output length is 1..8160 bytes (255 * SHA256 output). */
static int
bc_hkdf_sha256_mbedtls_cmd (WORD_LIST *args)
{
    int hex_mode = 0;
    const char *salt_hex = NULL, *ikm_hex = NULL, *info_hex = NULL;
    size_t out_len = 32;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-x"))             hex_mode = 1;
        else if (!strcmp (w, "-s") && p->next)  { p = p->next; salt_hex = p->word->word; }
        else if (!strcmp (w, "-k") && p->next)  { p = p->next; ikm_hex  = p->word->word; }
        else if (!strcmp (w, "-i") && p->next)  { p = p->next; info_hex = p->word->word; }
        else if (!strcmp (w, "-L") && p->next)  {
            char *end = NULL;
            unsigned long v;
            p = p->next;
            errno = 0;
            v = strtoul (p->word->word, &end, 10);
            if (errno || end == p->word->word || *end != '\0' ||
                v == 0 || v > MBEDTLS_HKDF_SHA256_MAX_OUTPUT) {
                builtin_error ("hkdf-sha256-mbedtls: LEN must be 1..%u",
                               MBEDTLS_HKDF_SHA256_MAX_OUTPUT);
                return EX_USAGE;
            }
            out_len = (size_t) v;
        }
        else { builtin_error ("hkdf-sha256-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }

    if (!ikm_hex) {
        builtin_error ("hkdf-sha256-mbedtls: -k IKM_HEX required");
        return EX_USAGE;
    }

    size_t salt_cap = salt_hex ? strlen (salt_hex) / 2 + 1 : 0;
    size_t ikm_cap  = strlen (ikm_hex) / 2 + 1;
    size_t info_cap = info_hex ? strlen (info_hex) / 2 + 1 : 0;
    unsigned char *salt = salt_cap ? malloc (salt_cap) : NULL;
    unsigned char *ikm  = ikm_cap  ? malloc (ikm_cap)  : NULL;
    unsigned char *info = info_cap ? malloc (info_cap) : NULL;
    unsigned char *out  = malloc (out_len);
    if ((salt_cap && !salt) || !ikm || (info_cap && !info) || !out) {
        builtin_error ("hkdf-sha256-mbedtls: oom");
        free (salt); free (ikm); free (info); free (out);
        return EXECUTION_FAILURE;
    }

    int salt_len = salt_hex ? bc_unhex (salt_hex, salt, salt_cap) : 0;
    int ikm_len  = bc_unhex (ikm_hex, ikm, ikm_cap);
    int info_len = info_hex ? bc_unhex (info_hex, info, info_cap) : 0;
    if (salt_len < 0 || ikm_len < 0 || info_len < 0) {
        builtin_error ("hkdf-sha256-mbedtls: bad hex");
        free (salt); free (ikm); free (info); free (out);
        return EX_USAGE;
    }

    int rc = mbedtls_hkdf_sha256 (salt, (size_t) salt_len,
                                  ikm, (size_t) ikm_len,
                                  info, (size_t) info_len,
                                  out, out_len);
    if (rc != 0) {
        builtin_error ("hkdf-sha256-mbedtls: derive failed");
        free (salt); free (ikm); free (info); free (out);
        return EXECUTION_FAILURE;
    }

    rc = (bc_emit (out, out_len, hex_mode) == 0) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    free (salt); free (ikm); free (info); free (out);
    return rc;
}

/* `crypto aes-gcm-mbedtls -e|-d -k KEY_HEX -n NONCE_HEX [-A AAD_HEX]`
 * Stage 19.B AEAD via the mbedtls AES-GCM primitive.
 * Encrypt: stdin → ciphertext + 16-byte tag on stdout.
 * Decrypt: stdin (ciphertext || tag) → plaintext on stdout, rc 1 on
 * tag mismatch (output buffer is zeroed before write). KEY: 32 or 64
 * hex chars (AES-128 / AES-256). NONCE: 24 hex chars (12 bytes per
 * RFC 5116). */
static int
bc_aes_gcm_mbedtls_cmd (WORD_LIST *args)
{
    int encrypt = -1;
    const char *key_hex = NULL, *nonce_hex = NULL, *aad_hex = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-e")) encrypt = 1;
        else if (!strcmp (w, "-d")) encrypt = 0;
        else if (!strcmp (w, "-k") && p->next) { p = p->next; key_hex   = p->word->word; }
        else if (!strcmp (w, "-n") && p->next) { p = p->next; nonce_hex = p->word->word; }
        else if (!strcmp (w, "-A") && p->next) { p = p->next; aad_hex   = p->word->word; }
        else { builtin_error ("aes-gcm-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (encrypt < 0 || !key_hex || !nonce_hex) {
        builtin_error ("aes-gcm-mbedtls needs -e|-d -k KEY_HEX -n NONCE_HEX");
        return EX_USAGE;
    }

    unsigned char key[32], nonce[16], aad[256];
    int klen = bc_unhex (key_hex,   key,   sizeof key);
    int nlen = bc_unhex (nonce_hex, nonce, sizeof nonce);
    int alen = aad_hex ? bc_unhex (aad_hex, aad, sizeof aad) : 0;
    if (klen != 16 && klen != 32) {
        builtin_error ("aes-gcm-mbedtls: KEY must be 16 or 32 bytes (AES-128 / AES-256)");
        return EX_USAGE;
    }
    if (nlen != 12) {
        builtin_error ("aes-gcm-mbedtls: NONCE must be 12 bytes (24 hex chars)");
        return EX_USAGE;
    }
    if (alen < 0) { builtin_error ("aes-gcm-mbedtls: bad hex in -A AAD"); return EX_USAGE; }

    /* Slurp stdin. */
    unsigned char *in = NULL;
    size_t inlen = 0;
    if (bc_slurp_fd (STDIN_FILENO, &in, &inlen) < 0) return EXECUTION_FAILURE;

    int rc;
    if (encrypt) {
        if (bc_nonce_guard_enabled ()) {
            int g = bc_nonce_record (key, (size_t) klen, nonce, (size_t) nlen);
            if (g == -1) {
                builtin_error ("aes-gcm-mbedtls: BASHCRYPTO_NONCE_GUARD: (key, nonce 0x%02x%02x...) reuse detected — refusing encrypt", nonce[0], nonce[1]);
                crypto_wipe (in, inlen); free (in);
                return EXECUTION_FAILURE;
            }
            if (g == -2) {
                builtin_error ("aes-gcm-mbedtls: BASHCRYPTO_NONCE_GUARD: in-process tracker full (%d entries) — refusing encrypt", BC_NONCE_GUARD_MAX);
                crypto_wipe (in, inlen); free (in);
                return EXECUTION_FAILURE;
            }
        }
        /* output: ciphertext (inlen bytes) || 16-byte tag. */
        unsigned char *out = malloc (inlen + 16);
        if (!out) { crypto_wipe (in, inlen); free (in); builtin_error ("oom"); return EXECUTION_FAILURE; }
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init (&gcm);
        int grc = mbedtls_gcm_setkey (&gcm, MBEDTLS_CIPHER_ID_AES,
                                      key, klen * 8u);
        if (grc == 0)
            grc = mbedtls_gcm_crypt_and_tag (&gcm, MBEDTLS_GCM_ENCRYPT, inlen,
                                             nonce, (size_t) nlen,
                                             aad, (size_t) alen,
                                             in, out, 16, out + inlen);
        mbedtls_gcm_free (&gcm);
        crypto_wipe (in, inlen);                /* plaintext input → wipe */
        if (grc != 0) {
            builtin_error ("aes-gcm-mbedtls: encrypt failed");
            free (in); free (out);
            return EXECUTION_FAILURE;
        }
        rc = (bc_write_all (out, inlen + 16) == 0) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        free (out);
    } else {
        /* input is (ciphertext || 16-byte tag); split. */
        if (inlen < 16) {
            builtin_error ("aes-gcm-mbedtls: input too short to contain tag");
            free (in);
            return EXECUTION_FAILURE;
        }
        size_t clen = inlen - 16;
        unsigned char *out = malloc (clen);
        if (!out) { builtin_error ("oom"); free (in); return EXECUTION_FAILURE; }
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init (&gcm);
        int dec = mbedtls_gcm_setkey (&gcm, MBEDTLS_CIPHER_ID_AES,
                                      key, klen * 8u);
        if (dec == 0)
            dec = mbedtls_gcm_auth_decrypt (&gcm, clen,
                                            nonce, (size_t) nlen,
                                            aad, (size_t) alen,
                                            in + clen, 16, in, out);
        mbedtls_gcm_free (&gcm);
        if (dec == MBEDTLS_ERR_GCM_AUTH_FAILED) {
            /* mbedTLS may have written partial plaintext before tag check
               failed — wipe before free per the documented contract. */
            crypto_wipe (out, clen);
            builtin_error ("aes-gcm-mbedtls: tag mismatch");
            free (in); free (out);
            return EXECUTION_FAILURE;
        }
        if (dec != 0) {
            crypto_wipe (out, clen);
            builtin_error ("aes-gcm-mbedtls: decrypt failed");
            free (in); free (out);
            return EXECUTION_FAILURE;
        }
        rc = (bc_write_all (out, clen) == 0) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        crypto_wipe (out, clen);                /* plaintext output → wipe */
        free (out);
    }
    free (in);
    /* sensitive locals on stack — wipe before return so the frame
       can't be scraped by a subsequent malloc caller. */
    crypto_wipe (key, sizeof key);
    crypto_wipe (nonce, sizeof nonce);
    crypto_wipe (aad, sizeof aad);
    return rc;
}

/* `crypto x25519-shared-mbedtls -k SK_HEX -p PK_HEX [-x]`
 * Stage 19.B X25519 ECDH (RFC 7748). Computes shared = clamp(SK) · PK.
 * Both inputs are 32-byte little-endian hex (64 hex chars). Output:

 * `crypto x25519-shared`. */
static int
bc_x25519_shared_mbedtls_cmd (WORD_LIST *args)
{
    int hex_mode = 0;
    const char *sk_hex = NULL, *pk_hex = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-x")) hex_mode = 1;
        else if (!strcmp (w, "-k") && p->next) { p = p->next; sk_hex = p->word->word; }
        else if (!strcmp (w, "-p") && p->next) { p = p->next; pk_hex = p->word->word; }
        else { builtin_error ("x25519-shared-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!sk_hex || !pk_hex) {
        builtin_error ("x25519-shared-mbedtls needs -k SK_HEX -p PK_HEX");
        return EX_USAGE;
    }
    unsigned char sk[32], pk[32], shared[32];
    if (bc_unhex (sk_hex, sk, sizeof sk) != 32) {
        builtin_error ("x25519-shared-mbedtls: SK_HEX must be 32 bytes (64 hex chars)");
        return EX_USAGE;
    }
    if (bc_unhex (pk_hex, pk, sizeof pk) != 32) {
        builtin_error ("x25519-shared-mbedtls: PK_HEX must be 32 bytes (64 hex chars)");
        return EX_USAGE;
    }
    if (mbedtls_x25519 (shared, sk, pk) != 0) {
        builtin_error ("x25519-shared-mbedtls: scalarmult failed");
        return EXECUTION_FAILURE;
    }
    if (hex_mode) {
        char hex[65];
        for (int i = 0; i < 32; i++) snprintf (hex + i*2, 3, "%02x", shared[i]);
        hex[64] = 0;
        printf ("%s\n", hex);
    } else {
        fwrite (shared, 1, 32, stdout);
    }
    return EXECUTION_SUCCESS;
}

/* `crypto x25519-pub-mbedtls -k SK_HEX [-x]` — derive the public
 * key from a private key (pub = clamp(sk) · 9). */
static int
bc_x25519_pub_mbedtls_cmd (WORD_LIST *args)
{
    int hex_mode = 0;
    const char *sk_hex = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-x")) hex_mode = 1;
        else if (!strcmp (w, "-k") && p->next) { p = p->next; sk_hex = p->word->word; }
        else { builtin_error ("x25519-pub-mbedtls: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!sk_hex) { builtin_error ("x25519-pub-mbedtls: -k SK_HEX required"); return EX_USAGE; }
    unsigned char sk[32], pk[32];
    if (bc_unhex (sk_hex, sk, sizeof sk) != 32) {
        builtin_error ("x25519-pub-mbedtls: SK_HEX must be 32 bytes (64 hex chars)");
        return EX_USAGE;
    }
    if (mbedtls_x25519_base (pk, sk) != 0) {
        builtin_error ("x25519-pub-mbedtls: scalarmult failed");
        return EXECUTION_FAILURE;
    }
    if (hex_mode) {
        char hex[65];
        for (int i = 0; i < 32; i++) snprintf (hex + i*2, 3, "%02x", pk[i]);
        hex[64] = 0;
        printf ("%s\n", hex);
    } else {
        fwrite (pk, 1, 32, stdout);
    }
    return EXECUTION_SUCCESS;
}

/* ---- bash builtin entry --------------------------------------------- */

extern char *crypto_doc[];

int
crypto_builtin (WORD_LIST *list)
{
  if (list == 0) { builtin_usage (); return (EX_USAGE); }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;

  /* The header comment points users at `--help' for the full subcommand
     grammar, but the dispatch below has no `--help' / `-h' / `help' arm —
     they would otherwise fall through to "unknown subcommand". Print the
     doc array (same surface `help crypto' uses) instead. */
  if (strcmp (cmd, "--help") == 0 || strcmp (cmd, "-h") == 0
      || strcmp (cmd, "help") == 0) {
    for (char **lp = crypto_doc; *lp; lp++)
      puts (*lp);
    return EXECUTION_SUCCESS;
  }

  /* Stage 19.C — mbedTLS is the only crypto crypto/TLS backend. */
  if (strcmp (cmd, "sha256") == 0
   || strcmp (cmd, "sha256-mbedtls") == 0)        return bc_sha256_mbedtls_cmd      (args);
  if (strcmp (cmd, "sha512") == 0
   || strcmp (cmd, "sha512-mbedtls") == 0)        return bc_sha512_mbedtls_cmd      (args);
  if (strcmp (cmd, "sha384") == 0
   || strcmp (cmd, "sha384-mbedtls") == 0)        return bc_sha384_mbedtls_cmd      (args);
  if (strcmp (cmd, "blake2b") == 0)               return bc_blake2b_cmd             (args);
  if (strcmp (cmd, "sha1") == 0
   || strcmp (cmd, "sha1-mbedtls") == 0)          return bc_sha1_mbedtls_cmd        (args);
  if (strcmp (cmd, "md5") == 0
   || strcmp (cmd, "md5-mbedtls") == 0)           return bc_md5_mbedtls_cmd         (args);
  if (strcmp (cmd, "shake256") == 0)              return bc_shake256_cmd            (args);
  if (strcmp (cmd, "hmac-sha256") == 0
   || strcmp (cmd, "hmac-sha256-mbedtls") == 0)   return bc_hmac_sha256_mbedtls_cmd (args);
  if (strcmp (cmd, "hmac-sha512") == 0
   || strcmp (cmd, "hmac-sha512-mbedtls") == 0)   return bc_hmac_sha512_mbedtls_cmd (args);
  if (strcmp (cmd, "hmac-sha1") == 0
   || strcmp (cmd, "hmac-sha1-mbedtls") == 0)     return bc_hmac_sha1_mbedtls_cmd   (args);
  if (strcmp (cmd, "hmac-md5") == 0
   || strcmp (cmd, "hmac-md5-mbedtls") == 0)      return bc_hmac_md5_mbedtls_cmd    (args);
  if (strcmp (cmd, "hkdf-sha256") == 0
   || strcmp (cmd, "hkdf-sha256-mbedtls") == 0)   return bc_hkdf_sha256_mbedtls_cmd (args);
  if (strcmp (cmd, "aes-gcm") == 0
   || strcmp (cmd, "aes-gcm-mbedtls") == 0)       return bc_aes_gcm_mbedtls_cmd     (args);
  if (strcmp (cmd, "aes-siv-cmac") == 0
   || strcmp (cmd, "aes-siv-cmac-mbedtls") == 0)  return bc_aes_siv_cmac_cmd        (args);
  if (strcmp (cmd, "nts-ke") == 0)                 return bc_nts_ke_cmd              (args);
  if (strcmp (cmd, "chacha20-poly1305") == 0
   || strcmp (cmd, "chacha20-poly1305-mbedtls") == 0) return bc_chacha20_poly1305_mbedtls_cmd (args);
  if (strcmp (cmd, "rsa-verify") == 0
   || strcmp (cmd, "rsa-verify-mbedtls") == 0)        return bc_rsa_verify_mbedtls_cmd (args);
  if (strcmp (cmd, "x509-parse-mbedtls") == 0)        return bc_x509_parse_mbedtls_cmd (args);
  if (strcmp (cmd, "x509-chain-verify-mbedtls") == 0) return bc_x509_chain_verify_mbedtls_cmd (args);
  if (strcmp (cmd, "x25519-pub") == 0
   || strcmp (cmd, "x25519-pub-mbedtls") == 0)    return bc_x25519_pub_mbedtls_cmd    (args);
  if (strcmp (cmd, "x25519-shared") == 0
   || strcmp (cmd, "x25519-shared-mbedtls") == 0) return bc_x25519_shared_mbedtls_cmd (args);
  if (strcmp (cmd, "ecdsa-p256-keygen") == 0
   || strcmp (cmd, "ecdsa-p256-keygen-mbedtls") == 0) return bc_ecdsa_p256_mbedtls_keygen (args);
  if (strcmp (cmd, "ecdsa-p256-pub") == 0
   || strcmp (cmd, "ecdsa-p256-pub-mbedtls")    == 0) return bc_ecdsa_p256_mbedtls_pub    (args);
  if (strcmp (cmd, "ecdsa-p256-key-pem") == 0) return bc_ecdsa_p256_mbedtls_key_pem (args);
  if (strcmp (cmd, "ecdsa-p256-sign") == 0
   || strcmp (cmd, "ecdsa-p256-sign-mbedtls")   == 0) return bc_ecdsa_p256_mbedtls_sign   (args);
  if (strcmp (cmd, "ecdsa-p256-verify") == 0
   || strcmp (cmd, "ecdsa-p256-verify-mbedtls") == 0) return bc_ecdsa_p256_mbedtls_verify (args);
  if (strcmp (cmd, "ecdsa-p384-verify") == 0
   || strcmp (cmd, "ecdsa-p384-verify-mbedtls") == 0) return bc_ecdsa_p384_mbedtls_verify (args);
  if (strcmp (cmd, "ecdsa-p384-keygen") == 0
   || strcmp (cmd, "ecdsa-p384-keygen-mbedtls") == 0) return bc_ecdsa_p384_mbedtls_keygen (args);
  if (strcmp (cmd, "ecdsa-p384-pub") == 0
   || strcmp (cmd, "ecdsa-p384-pub-mbedtls")    == 0) return bc_ecdsa_p384_mbedtls_pub    (args);
  if (strcmp (cmd, "ecdsa-p384-sign") == 0
   || strcmp (cmd, "ecdsa-p384-sign-mbedtls")   == 0) return bc_ecdsa_p384_mbedtls_sign   (args);
  if (strcmp (cmd, "rsa-keygen") == 0)                 return bc_rsa_keygen (args);
  if (strcmp (cmd, "rsa-pkcs1-sign") == 0
   || strcmp (cmd, "rsa-sign") == 0)                   return bc_rsa_pkcs1_sign (args);

  /* mbedTLS is canonical; legacy backend aliases are intentionally absent. */

  if (strncmp (cmd, "hmac-", 5) == 0)
    { builtin_error ("unknown or unsupported hmac: %s", cmd + 5); builtin_usage (); return EX_USAGE; }

  /* mbedTLS-routed primitives are dispatched above. */

  if (strcmp (cmd, "ed25519-keygen")     == 0) return bc_ed25519_keygen (args);
  if (strcmp (cmd, "ed25519-pub")        == 0) return bc_ed25519_pub_cmd (args);
  if (strcmp (cmd, "ed25519-sign")       == 0) return bc_ed25519_sign (args);
  if (strcmp (cmd, "ed25519-verify")     == 0) return bc_ed25519_verify (args);
  if (strcmp (cmd, "ed448-verify")       == 0) return bc_ed448_verify (args);

  if (strcmp (cmd, "x25519-keygen")      == 0) return bc_x25519_keygen (args);

  if (strcmp (cmd, "hkdf")               == 0) return bc_hkdf_cmd (args);
  if (strcmp (cmd, "pbkdf2")             == 0) return bc_pbkdf2_cmd (args);
  if (strcmp (cmd, "secret-read")        == 0) return bc_secret_read_cmd (args);
  if (strcmp (cmd, "secret-scrub")       == 0) return bc_secret_scrub_cmd (args);
  if (strcmp (cmd, "secret-len")         == 0) return bc_secret_len_cmd (args);
  if (strcmp (cmd, "secret-verify")      == 0) return bc_secret_verify_cmd (args);
  if (strcmp (cmd, "secret-pwhash")      == 0) return bc_secret_pwhash_cmd (args);
  if (strcmp (cmd, "secret-pwverify")    == 0) return bc_secret_pwverify_cmd (args);
  if (strcmp (cmd, "secret-hkdf")        == 0) return bc_secret_hkdf_cmd (args);
  if (strcmp (cmd, "argon2id")           == 0) return bc_argon2id_cmd (args);
  if (strcmp (cmd, "verify-ct")          == 0) return bc_verify_ct_cmd (args);
  if (strcmp (cmd, "random")             == 0) return bc_random_cmd (args);

  if (strcmp (cmd, "pem-decode")         == 0) return bc_pem_decode_cmd (args);
  if (strcmp (cmd, "pem-encode")         == 0) return bc_pem_encode_cmd (args);
  if (strcmp (cmd, "x509-info")          == 0) return bc_x509_info_cmd (args);
  if (strcmp (cmd, "base64url")          == 0) return bc_base64url_cmd (args);
  if (strcmp (cmd, "x509-csr")           == 0) return bc_x509_csr_cmd (args);

  /* `tls` is a multi-arg subcommand: tls connect HOST:PORT [...]
     Stage 19.B-core (2026-05-07): bare `connect` routes to the
     mbedTLS state machine; `connect-mbedtls` is an explicit alias for the bare form. */
  if (strcmp (cmd, "tls") == 0)
    {
      if (!args) { builtin_error ("tls: missing operation (try `tls connect`)"); builtin_usage (); return EX_USAGE; }
      const char *op = args->word->word;
      if (strcmp (op, "connect") == 0
       || strcmp (op, "connect-mbedtls") == 0) return bc_tls_connect_mbedtls_cmd (args->next);
      builtin_error ("tls: unknown operation: %s (try `connect` or `connect-mbedtls`)", op);
      builtin_usage ();
      return EX_USAGE;
    }

  /* Stage 19.A.2 proof-of-link verb against the _mbedtls/ flattened dir. */
  if (strcmp (cmd, "mbedtls-version") == 0) return bc_mbedtls_version_cmd (args);
  /* sha256-mbedtls + hmac/hkdf-sha256-mbedtls dispatched earlier (must run
     before the `hmac-` prefix matcher to avoid bad routing). */

  builtin_error ("unknown subcommand: %s", cmd);
  builtin_usage ();
  return (EX_USAGE);
}

char *crypto_doc[] = {
  "Cryptographic primitives via mbedTLS (canonical) and monocypher.",
  "  mbedTLS backs hashes, HMAC, HKDF, PBKDF2, AEAD, X25519, ECDSA P-256/P-384,",
  "    RSA verify, PEM/X.509, random, and TLS connect.",
  "  monocypher remains intentionally retained for Ed25519 and Argon2id.",
  "",
  "Subcommands:",
  "    sha256 / sha384 / sha512 / sha1 / md5 / blake2b  [-x] [FILE]",
  "    shake256 [-n BYTES] [-x] < msg",
  "    hmac-sha256 / hmac-sha512 / hmac-sha1 / hmac-md5 -k KEY_HEX [-x]",
  "    hkdf-sha256  -s SALT_HEX -k IKM_HEX [-i INFO_HEX] -L LEN [-x]",
  "    hkdf  -a HASH -s SALT_HEX -k IKM_HEX [-i INFO_HEX] -L LEN [-x]",
  "    pbkdf2  -a HASH -s SALT_HEX -p PASSWORD -i ITER -L LEN [-x]",
  "    aes-gcm  -e|-d -k KEY -n NONCE [-A AAD]",
  "    aes-siv-cmac  -e|-d -k KEY [-A AAD]... [-x]   # AEAD_AES_SIV_CMAC_256",
  "    chacha20-poly1305  -e|-d -k KEY -n NONCE [-A AAD]",
  "    x25519-keygen [-x]",
  "    x25519-pub  -k SK_HEX [-x]",
  "    x25519-shared  -p PK_HEX -k SK_HEX [-x]",
  "    ecdsa-p256-keygen [-x]",
  "    ecdsa-p256-pub  -k SK_HEX [-x]",
  "    ecdsa-p256-key-pem  -k SK_HEX [--der]",
  "    ecdsa-p256-sign  -k SK_HEX [-A] [-x] < msg",
  "    ecdsa-p256-verify  -k PK_HEX -s SIG_HEX [-A] < msg",
  "    ecdsa-p384-verify  -k PK_HEX -s SIG_HEX < msg",
  "    ecdsa-p384-keygen [-x]                            # DNSSEC alg 14",
  "    ecdsa-p384-pub  -k SK_HEX [-x]",
  "    ecdsa-p384-sign  -k SK_HEX [-x] < msg             # SHA-384, raw r||s",
  "    rsa-keygen [-b BITS=2048] [-e EXP=65537]          # emits n:/e:/d:/p:/q: hex",
  "    rsa-pkcs1-sign  -n N -e E -d D -p P -q Q -H sha1|sha256|sha512 [-x] < msg",
  "                 # DNSSEC algs 5/7/8/10, PKCS#1 v1.5",
  "    ed25519-keygen [-x]",
  "    ed25519-pub  -k SEED_HEX [-x]",
  "    ed25519-sign  -k SEED_HEX [-x] < msg > sig",
  "    ed25519-verify  -k PK_HEX -s SIG_HEX < msg",
  "    ed448-verify    -k PK_HEX -s SIG_HEX < msg",
  "    argon2id  -p PW -s SALT_HEX [-t PASSES=3] [-m MEM_KIB=65536]",
  "              [-l LANES=1] [-L LEN=32] [-x] [-o VARNAME]",
  "    secret-read / secret-scrub / secret-len / secret-verify",
  "    secret-pwhash / secret-pwverify / secret-hkdf",
  "    verify-ct HEX_A HEX_B",
  "    random N [-x]",
  "    pem-decode [-t TYPE]",
  "    pem-encode -t TYPE",
  "    x509-info",
  "    base64url  -e|-d  [--pad|--no-pad]   # RFC 4648 §5, JOSE/JWS",
  "    x509-csr   -k SK_HEX -d DOMAIN [-d ...] [--cn CN] [--der]",
  "                 PKCS#10 CSR (ECDSA-P256 + SAN); PEM by default",
  "    tls connect HOST:PORT [-c CA_PEM] [-s SNI] [-k] [--print-cipher]",
  "        [--connect-timeout MS] [--read-timeout MS] [--max-request BYTES]",
  "    tls connect-mbedtls HOST:PORT [...]  # explicit alias for connect",
  "    nts-ke HOST[:PORT] [-c CA_PEM] [-s SNI] [--emit-keys]",
  "        NTS-KE over TLS/ALPN ntske/1; default port 4460.",
  "",
  "TLS cipher suites:",
  "    TLS 1.3: TLS_AES_128_GCM_SHA256 (0x1301),",
  "             TLS_AES_256_GCM_SHA384 (0x1302),",
  "             TLS_CHACHA20_POLY1305_SHA256 (0x1303)",
  "    TLS 1.2: ECDHE-RSA/ECDSA with CHACHA20-POLY1305 or AES-GCM.",
  "",
  "Common flags:",
  "    -x        hex output (var-storable; no NULs)",
  "    -k HEX    hex-encoded key/SK",
  "    -n HEX    hex-encoded nonce/IV",
  "    -s HEX    hex-encoded salt",
  "    -t TYPE   PEM banner type (CERTIFICATE / RSA PRIVATE KEY / etc.)",
  "",
  "All keys/nonces/salts are hex on the CLI so they ride through bash",
  "variables without NUL-stripping. Raw byte output goes to stdout.",
  (char *) NULL
};

struct builtin crypto_struct = {
  "crypto",
  crypto_builtin,
  BUILTIN_ENABLED,
  crypto_doc,
  "crypto SUBCOMMAND [FLAGS...]",
  0
};
