/* SPDX-License-Identifier: MIT */
#include <config.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "_monocypher_monocypher-ed25519.h"
#include "_bashos_authcrypto_argon2id.h"
#ifdef BASHOS_AUTHCRYPTO_STANDALONE
#define builtin_error(...) fprintf (stderr, __VA_ARGS__)
#else
#include "loadables.h"
#endif

int
bashos_auth_argon2id_raw (const unsigned char *pass, size_t pass_len,
                          const unsigned char *salt, size_t salt_len,
                          uint32_t passes, uint32_t mem_kib, uint32_t lanes,
                          unsigned char *out, size_t out_len,
                          int quiet_mlock, const char *warn_prefix)
{
  if (!pass || !salt || !out ||
      passes < 1 || lanes < 1 || mem_kib < 8 * lanes ||
      out_len == 0 || out_len > 1024 || salt_len < 8)
    return -1;

  size_t work_bytes = (size_t) mem_kib * 1024;
  void *work = malloc (work_bytes);
  if (!work)
    {
      builtin_error ("argon2id: out of memory (%u KiB requested)", mem_kib);
      return -1;
    }

  int locked = (mlock (work, work_bytes) == 0);
  if (!locked && !quiet_mlock && warn_prefix && *warn_prefix)
    fprintf (stderr, "%s: argon2id work area not mlocked: %s\n",
             warn_prefix, strerror (errno));

  crypto_argon2_config cfg = {
    .algorithm = CRYPTO_ARGON2_ID,
    .nb_blocks = mem_kib,
    .nb_passes = passes,
    .nb_lanes  = lanes,
  };
  crypto_argon2_inputs in = {
    .pass = pass,
    .salt = salt,
    .pass_size = (uint32_t) pass_len,
    .salt_size = (uint32_t) salt_len,
  };

  crypto_argon2 (out, (uint32_t) out_len, work, cfg, in,
                 crypto_argon2_no_extras);

  crypto_wipe (work, work_bytes);
  if (locked)
    munlock (work, work_bytes);
  free (work);
  return 0;
}
