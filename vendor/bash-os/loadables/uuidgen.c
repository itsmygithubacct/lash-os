/* SPDX-License-Identifier: MIT */
/* uuidgen.c — UUIDv1 / UUIDv3 / UUIDv4 / UUIDv5 / UUIDv6 / UUIDv7 generator (ML-T2-12).
 *
 * Mirrors util-linux uuidgen(1)'s default + -r + -t + -m + -s + -6 + -7
 * verbs. Random bytes come from getrandom(2) on Linux 3.17+ (the
 * canonical CSPRNG syscall) with a /dev/urandom fallback for environments
 * where getrandom is unavailable (qemu-user without LINUX_VERSION_CODE,
 * old kernels, etc.).
 *
 * Verbs:
 *   uuidgen            random UUIDv4 (default)
 *   uuidgen -r         random UUIDv4 (explicit; util-linux compat)
 *   uuidgen --random   long form of -r
 *   uuidgen -t         time-based UUIDv1
 *   uuidgen --time     long form of -t
 *   uuidgen -m         name-based UUIDv3 (MD5)
 *   uuidgen --md5      long form of -m
 *   uuidgen -s         name-based UUIDv5 (SHA-1)
 *   uuidgen --sha1     long form of -s
 *   uuidgen -n NS      namespace UUID or @dns/@url/@oid/@x500
 *   uuidgen -N NAME    namespace name
 *   uuidgen -6         reordered-time UUIDv6
 *   uuidgen --time-v6  long form of -6
 *   uuidgen -7         Unix-time UUIDv7
 *   uuidgen --time-v7  long form of -7
 *   uuidgen -x NAME    interpret -N name as a hex string (util-linux -x)
 *   uuidgen --hex      long form of -x
 *   uuidgen -h         show usage
 *   uuidgen --version  show version
 *
 * v4 layout (RFC 4122 §4.4):
 *   xxxxxxxx-xxxx-4xxx-Vxxx-xxxxxxxxxxxx
 *   - 16 CSPRNG bytes
 *   - byte 6 high nibble forced to 0x4 (version)
 *   - byte 8 high two bits forced to 0b10 (variant; V ∈ {8,9,a,b})
 *
 * v1 layout (RFC 4122 §4.2):
 *   time_low (4) - time_mid (2) - time_hi_and_version (2)
 *   - clock_seq_hi_and_reserved (1) - clock_seq_low (1) - node (6)
 *
 *   - Timestamp = 100-ns intervals since 1582-10-15 UTC. From wall-clock
 *     ns we add the constant 0x01B21DD213814000 (gap between 1582-10-15
 *     and 1970-01-01 in 100-ns ticks).
 *   - time_hi high nibble = 0x1 (version).
 *   - clock_seq_hi top two bits = 0b10 (variant).
 *   - node: 6 random bytes with multicast bit set (LSB of MSB byte = 1)
 *     per RFC 4122 §4.5 — "if a system does not have a unique address,
 *     [generate] N random... bits. Setting the multicast bit of this
 *     field ensures it cannot conflict with addresses obtained from
 *     network cards." We do not attempt to read a hardware MAC.
 *
 * v3/v5 layout (RFC 9562 §5.3 / §5.5, inherited from RFC 4122):
 *   hash(namespace_uuid_bytes || name_bytes), first 16 hash bytes with
 *   version nibble set to 3 (MD5) or 5 (SHA-1) and variant set to 10b.
 *   Built-in namespace aliases match libuuid/util-linux: @dns, @url,
 *   @oid, @x500.
 *
 * v6 layout (RFC 9562 §5.6):
 *   reordered v1 timestamp (most-significant bits first) - version 6 -
 *   clock sequence - node
 *   - Timestamp source, clock sequence, and random multicast node match v1.
 *   - The 60-bit timestamp is rearranged as high 32 bits, middle 16 bits,
 *     then low 12 bits after the version nibble.
 *
 * v7 layout (RFC 9562 §5.7):
 *   unix_ts_ms (48 bits) - version 7 - rand_a (12 bits) -
 *   variant 10b - rand_b (62 bits)
 *   - Timestamp = Unix epoch milliseconds in network byte order.
 *   - rand_a / rand_b are CSPRNG-derived; we do not maintain a
 *     monotonic counter inside a millisecond tick.
 *
 * Source counterpart: research/refs/util-linux/misc-utils/uuidgen.c
 * + util-linux/libuuid/src/gen_uuid.c.
 *
 * Companion wrapper: /bash-os/uuidgen.sh.
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
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
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
#include <limits.h>
#include <stdint.h>
#include <time.h>
#include <sys/syscall.h>

#include "_mbedtls_md5.h"
#include "_mbedtls_sha1.h"
#include "loadables.h"

/* getrandom(2) syscall number — preferred over <sys/random.h> here
   because musl's <sys/random.h> may not be in the include path under
   the patched bash build's -I order. Direct syscall(SYS_getrandom, ...)
   is portable across glibc and musl. */
#ifndef SYS_getrandom
#  if defined(__x86_64__)
#    define SYS_getrandom 318
#  endif
#endif

/* Fill BUF with N CSPRNG bytes. getrandom(2) first; /dev/urandom on
   ENOSYS or any other failure path. Returns 0 on success, -1 on
   failure with builtin_error() already emitted. */
static int
bu_random_bytes (unsigned char *buf, size_t n)
{
#ifdef SYS_getrandom
  size_t got = 0;
  while (got < n)
    {
      long r = syscall (SYS_getrandom, buf + got, n - got, 0);
      if (r > 0) { got += (size_t) r; continue; }
      if (r < 0 && errno == EINTR) continue;
      break;  /* fall through to /dev/urandom */
    }
  if (got == n) return 0;
#endif

  int fd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    {
      builtin_error ("/dev/urandom: %s", strerror (errno));
      return -1;
    }
  size_t ugot = 0;
  while (ugot < n)
    {
      ssize_t r = read (fd, buf + ugot, n - ugot);
      if (r > 0) { ugot += (size_t) r; continue; }
      if (r < 0 && errno == EINTR) continue;
      close (fd);
      builtin_error ("/dev/urandom: short read (%zu/%zu)", ugot, n);
      return -1;
    }
  close (fd);
  return 0;
}

static void
bu_format (unsigned char u[16])
{
  printf ("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
          "%02x%02x%02x%02x%02x%02x\n",
          u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
          u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

static int
bu_hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
bu_parse_uuid (const char *s, unsigned char out[16])
{
  unsigned char tmp[16];
  size_t n = 0;
  int hi = -1;

  if (s == NULL || *s == '\0')
    return -1;

  if (*s == '{')
    s++;

  for (const char *p = s; *p; p++)
    {
      if (*p == '}' && p[1] == '\0')
        break;
      if (*p == '-')
        continue;
      int v = bu_hexval ((unsigned char) *p);
      if (v < 0)
        return -1;
      if (hi < 0)
        {
          hi = v;
          continue;
        }
      if (n >= sizeof tmp)
        return -1;
      tmp[n++] = (unsigned char) ((hi << 4) | v);
      hi = -1;
    }

  if (hi >= 0 || n != sizeof tmp)
    return -1;

  memcpy (out, tmp, sizeof tmp);
  return 0;
}

static int
bu_namespace_bytes (const char *ns, unsigned char out[16])
{
  static const unsigned char ns_dns[16] = {
    0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
    0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
  };
  static const unsigned char ns_url[16] = {
    0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1,
    0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
  };
  static const unsigned char ns_oid[16] = {
    0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1,
    0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
  };
  static const unsigned char ns_x500[16] = {
    0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1,
    0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
  };

  if (ns == NULL)
    return -1;
  if (!strcmp (ns, "@dns") || !strcmp (ns, "dns"))
    { memcpy (out, ns_dns, sizeof ns_dns); return 0; }
  if (!strcmp (ns, "@url") || !strcmp (ns, "url"))
    { memcpy (out, ns_url, sizeof ns_url); return 0; }
  if (!strcmp (ns, "@oid") || !strcmp (ns, "oid"))
    { memcpy (out, ns_oid, sizeof ns_oid); return 0; }
  if (!strcmp (ns, "@x500") || !strcmp (ns, "x500"))
    { memcpy (out, ns_x500, sizeof ns_x500); return 0; }

  return bu_parse_uuid (ns, out);
}

static int
bu_v4 (void)
{
  unsigned char u[16];
  if (bu_random_bytes (u, sizeof u) < 0)
    return EXECUTION_FAILURE;
  u[6] = (unsigned char) ((u[6] & 0x0F) | 0x40);   /* version = 4 */
  u[8] = (unsigned char) ((u[8] & 0x3F) | 0x80);   /* variant = 10b */
  bu_format (u);
  return EXECUTION_SUCCESS;
}

static int
bu_v1 (void)
{
  struct timespec ts;
  if (clock_gettime (CLOCK_REALTIME, &ts) < 0)
    {
      builtin_error ("clock_gettime: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }

  /* 100-ns intervals since 1582-10-15. */
  uint64_t t100 = (uint64_t) ts.tv_sec * 10000000ULL
                + (uint64_t) ts.tv_nsec / 100ULL
                + 0x01B21DD213814000ULL;

  uint32_t time_low = (uint32_t) (t100 & 0xFFFFFFFFULL);
  uint16_t time_mid = (uint16_t) ((t100 >> 32) & 0xFFFFULL);
  uint16_t time_hi_and_version =
      (uint16_t) (((t100 >> 48) & 0x0FFFULL) | 0x1000ULL);

  unsigned char clock_and_node[8];
  if (bu_random_bytes (clock_and_node, sizeof clock_and_node) < 0)
    return EXECUTION_FAILURE;

  unsigned char u[16];
  u[0] = (unsigned char) ((time_low >> 24) & 0xFF);
  u[1] = (unsigned char) ((time_low >> 16) & 0xFF);
  u[2] = (unsigned char) ((time_low >>  8) & 0xFF);
  u[3] = (unsigned char) ((time_low >>  0) & 0xFF);
  u[4] = (unsigned char) ((time_mid >> 8) & 0xFF);
  u[5] = (unsigned char) ((time_mid >> 0) & 0xFF);
  u[6] = (unsigned char) ((time_hi_and_version >> 8) & 0xFF);
  u[7] = (unsigned char) ((time_hi_and_version >> 0) & 0xFF);

  /* clock_seq_hi: top 2 bits = variant 10b; remaining 6 = random. */
  u[8] = (unsigned char) ((clock_and_node[0] & 0x3F) | 0x80);
  /* clock_seq_low: 8 random bits. */
  u[9] = clock_and_node[1];
  /* node: 6 random bytes; multicast bit (LSB of MSB) = 1 per RFC 4122. */
  u[10] = (unsigned char) (clock_and_node[2] | 0x01);
  u[11] = clock_and_node[3];
  u[12] = clock_and_node[4];
  u[13] = clock_and_node[5];
  u[14] = clock_and_node[6];
  u[15] = clock_and_node[7];

  bu_format (u);
  return EXECUTION_SUCCESS;
}

static int
bu_name_based (int version, const char *ns_arg, const char *name, int is_hex)
{
  unsigned char ns[16];
  if (bu_namespace_bytes (ns_arg, ns) < 0)
    {
      builtin_error ("bad namespace: %s", ns_arg ? ns_arg : "(null)");
      return EX_USAGE;
    }
  if (name == NULL)
    {
      builtin_error ("-N/--name is required for name-based UUIDs");
      return EX_USAGE;
    }

  /* -x/--hex: the name is a hex string to be decoded to raw bytes before
     hashing (util-linux unhex()).  An odd length or any non-hex digit is an
     error.  Without -x the name is hashed verbatim. */
  const unsigned char *msg = (const unsigned char *) name;
  size_t name_len = strlen (name);
  unsigned char *hexbuf = NULL;
  if (is_hex)
    {
      if (name_len % 2 != 0)
        {
          builtin_error ("not a valid hex string");
          return EX_USAGE;
        }
      hexbuf = (unsigned char *) malloc (name_len / 2 + 1);
      if (hexbuf == NULL)
        {
          builtin_error ("memory allocation failed");
          return EXECUTION_FAILURE;
        }
      for (size_t i = 0; i < name_len; i += 2)
        {
          int hi = bu_hexval ((unsigned char) name[i]);
          int lo = bu_hexval ((unsigned char) name[i + 1]);
          if (hi < 0 || lo < 0)
            {
              free (hexbuf);
              builtin_error ("not a valid hex string");
              return EX_USAGE;
            }
          hexbuf[i / 2] = (unsigned char) ((hi << 4) | lo);
        }
      msg = hexbuf;
      name_len /= 2;
    }

  unsigned char digest[20];
  if (version == 3)
    {
      mbedtls_md5_context ctx;
      mbedtls_md5_init (&ctx);
      if (mbedtls_md5_starts (&ctx) != 0
          || mbedtls_md5_update (&ctx, ns, sizeof ns) != 0
          || mbedtls_md5_update (&ctx, msg, name_len) != 0
          || mbedtls_md5_finish (&ctx, digest) != 0)
        {
          mbedtls_md5_free (&ctx);
          free (hexbuf);
          builtin_error ("md5 failed");
          return EXECUTION_FAILURE;
        }
      mbedtls_md5_free (&ctx);
    }
  else
    {
      mbedtls_sha1_context ctx;
      mbedtls_sha1_init (&ctx);
      if (mbedtls_sha1_starts (&ctx) != 0
          || mbedtls_sha1_update (&ctx, ns, sizeof ns) != 0
          || mbedtls_sha1_update (&ctx, msg, name_len) != 0
          || mbedtls_sha1_finish (&ctx, digest) != 0)
        {
          mbedtls_sha1_free (&ctx);
          free (hexbuf);
          builtin_error ("sha1 failed");
          return EXECUTION_FAILURE;
        }
      mbedtls_sha1_free (&ctx);
    }
  free (hexbuf);

  unsigned char u[16];
  memcpy (u, digest, sizeof u);
  u[6] = (unsigned char) ((u[6] & 0x0F) | (version << 4));
  u[8] = (unsigned char) ((u[8] & 0x3F) | 0x80);
  bu_format (u);
  return EXECUTION_SUCCESS;
}

static int
bu_v6 (void)
{
  struct timespec ts;
  if (clock_gettime (CLOCK_REALTIME, &ts) < 0)
    {
      builtin_error ("clock_gettime: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }

  /* 100-ns intervals since 1582-10-15, rearranged per RFC 9562 v6. */
  uint64_t t100 = (uint64_t) ts.tv_sec * 10000000ULL
                + (uint64_t) ts.tv_nsec / 100ULL
                + 0x01B21DD213814000ULL;

  uint32_t time_high = (uint32_t) ((t100 >> 28) & 0xFFFFFFFFULL);
  uint16_t time_mid = (uint16_t) ((t100 >> 12) & 0xFFFFULL);
  uint16_t time_low_and_version =
      (uint16_t) ((t100 & 0x0FFFULL) | 0x6000ULL);

  unsigned char clock_and_node[8];
  if (bu_random_bytes (clock_and_node, sizeof clock_and_node) < 0)
    return EXECUTION_FAILURE;

  unsigned char u[16];
  u[0] = (unsigned char) ((time_high >> 24) & 0xFF);
  u[1] = (unsigned char) ((time_high >> 16) & 0xFF);
  u[2] = (unsigned char) ((time_high >>  8) & 0xFF);
  u[3] = (unsigned char) ((time_high >>  0) & 0xFF);
  u[4] = (unsigned char) ((time_mid >> 8) & 0xFF);
  u[5] = (unsigned char) ((time_mid >> 0) & 0xFF);
  u[6] = (unsigned char) ((time_low_and_version >> 8) & 0xFF);
  u[7] = (unsigned char) ((time_low_and_version >> 0) & 0xFF);

  u[8] = (unsigned char) ((clock_and_node[0] & 0x3F) | 0x80);
  u[9] = clock_and_node[1];
  u[10] = (unsigned char) (clock_and_node[2] | 0x01);
  u[11] = clock_and_node[3];
  u[12] = clock_and_node[4];
  u[13] = clock_and_node[5];
  u[14] = clock_and_node[6];
  u[15] = clock_and_node[7];

  bu_format (u);
  return EXECUTION_SUCCESS;
}

static int
bu_v7 (void)
{
  struct timespec ts;
  if (clock_gettime (CLOCK_REALTIME, &ts) < 0)
    {
      builtin_error ("clock_gettime: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }

  uint64_t ms = (uint64_t) ts.tv_sec * 1000ULL
              + (uint64_t) ts.tv_nsec / 1000000ULL;

  unsigned char rnd[10];
  if (bu_random_bytes (rnd, sizeof rnd) < 0)
    return EXECUTION_FAILURE;

  unsigned char u[16];
  u[0] = (unsigned char) ((ms >> 40) & 0xFF);
  u[1] = (unsigned char) ((ms >> 32) & 0xFF);
  u[2] = (unsigned char) ((ms >> 24) & 0xFF);
  u[3] = (unsigned char) ((ms >> 16) & 0xFF);
  u[4] = (unsigned char) ((ms >>  8) & 0xFF);
  u[5] = (unsigned char) ((ms >>  0) & 0xFF);

  /* Version 7 followed by 12 bits of rand_a. */
  u[6] = (unsigned char) ((rnd[0] & 0x0F) | 0x70);
  u[7] = rnd[1];
  /* Variant 10b followed by 62 bits of rand_b. */
  u[8] = (unsigned char) ((rnd[2] & 0x3F) | 0x80);
  u[9] = rnd[3];
  u[10] = rnd[4];
  u[11] = rnd[5];
  u[12] = rnd[6];
  u[13] = rnd[7];
  u[14] = rnd[8];
  u[15] = rnd[9];

  bu_format (u);
  return EXECUTION_SUCCESS;
}

static int
bu_parse_count (const char *s, unsigned int *out)
{
  char *end = NULL;
  unsigned long v;

  if (s == NULL || *s == '\0')
    return -1;

  errno = 0;
  v = strtoul (s, &end, 10);
  if (errno != 0 || end == s || *end != '\0' || v > UINT_MAX)
    return -1;

  *out = (unsigned int) v;
  return 0;
}

extern char *uuidgen_doc[];

int
uuidgen_builtin (WORD_LIST *list)
{
  int mode = 4;
  int mode_set = 0;
  unsigned int count = 1;
  const char *namespace_arg = NULL;
  const char *name_arg = NULL;
  int is_hex = 0;

  for (WORD_LIST *p = list; p; )
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-r") || !strcmp (w, "--random"))
        {
          if (mode_set && mode != 4)
            {
              builtin_error ("UUID version options are mutually exclusive");
              builtin_usage ();
              return EX_USAGE;
            }
          mode = 4;
          mode_set = 1;
          p = p->next;
        }
      else if (!strcmp (w, "-t") || !strcmp (w, "--time"))
        {
          if (mode_set && mode != 1)
            {
              builtin_error ("UUID version options are mutually exclusive");
              builtin_usage ();
              return EX_USAGE;
            }
          mode = 1;
          mode_set = 1;
          p = p->next;
        }
      else if (!strcmp (w, "-m") || !strcmp (w, "--md5"))
        {
          if (mode_set && mode != 3)
            {
              builtin_error ("UUID version options are mutually exclusive");
              builtin_usage ();
              return EX_USAGE;
            }
          mode = 3;
          mode_set = 1;
          p = p->next;
        }
      else if (!strcmp (w, "-s") || !strcmp (w, "--sha1"))
        {
          if (mode_set && mode != 5)
            {
              builtin_error ("UUID version options are mutually exclusive");
              builtin_usage ();
              return EX_USAGE;
            }
          mode = 5;
          mode_set = 1;
          p = p->next;
        }
      else if (!strcmp (w, "-6") || !strcmp (w, "--time-v6"))
        {
          if (mode_set && mode != 6)
            {
              builtin_error ("UUID version options are mutually exclusive");
              builtin_usage ();
              return EX_USAGE;
            }
          mode = 6;
          mode_set = 1;
          p = p->next;
        }
      else if (!strcmp (w, "-n") || !strcmp (w, "--namespace"))
        {
          if (p->next == NULL)
            {
              builtin_error ("%s requires a namespace", w);
              builtin_usage ();
              return EX_USAGE;
            }
          namespace_arg = p->next->word->word;
          p = p->next->next;
        }
      else if (!strncmp (w, "--namespace=", 12))
        {
          namespace_arg = w + 12;
          p = p->next;
        }
      else if (!strcmp (w, "-N") || !strcmp (w, "--name"))
        {
          if (p->next == NULL)
            {
              builtin_error ("%s requires a name", w);
              builtin_usage ();
              return EX_USAGE;
            }
          name_arg = p->next->word->word;
          p = p->next->next;
        }
      else if (!strncmp (w, "--name=", 7))
        {
          name_arg = w + 7;
          p = p->next;
        }
      else if (!strcmp (w, "-7") || !strcmp (w, "--time-v7"))
        {
          if (mode_set && mode != 7)
            {
              builtin_error ("UUID version options are mutually exclusive");
              builtin_usage ();
              return EX_USAGE;
            }
          mode = 7;
          mode_set = 1;
          p = p->next;
        }
      else if (!strcmp (w, "-C") || !strcmp (w, "--count"))
        {
          if (p->next == NULL)
            {
              builtin_error ("%s requires a count", w);
              builtin_usage ();
              return EX_USAGE;
            }
          if (bu_parse_count (p->next->word->word, &count) < 0)
            {
              builtin_error ("invalid count: %s", p->next->word->word);
              builtin_usage ();
              return EX_USAGE;
            }
          p = p->next->next;
        }
      else if (!strncmp (w, "-C", 2) && w[2] != '\0')
        {
          if (bu_parse_count (w + 2, &count) < 0)
            {
              builtin_error ("invalid count: %s", w + 2);
              builtin_usage ();
              return EX_USAGE;
            }
          p = p->next;
        }
      else if (!strncmp (w, "--count=", 8))
        {
          if (bu_parse_count (w + 8, &count) < 0)
            {
              builtin_error ("invalid count: %s", w + 8);
              builtin_usage ();
              return EX_USAGE;
            }
          p = p->next;
        }
      else if (!strcmp (w, "-x") || !strcmp (w, "--hex"))
        {
          is_hex = 1;
          p = p->next;
        }
      else if (!strcmp (w, "-h") || !strcmp (w, "--help"))
        {
          for (int i = 0; uuidgen_doc[i]; i++)
            printf ("%s\n", uuidgen_doc[i]);
          return EXECUTION_SUCCESS;
        }
      else if (!strcmp (w, "--version"))
        {
          puts ("uuidgen 0.1 (bash-os loadable)");
          return EXECUTION_SUCCESS;
        }
      else if (!strcmp (w, "--"))
        {
          /* End-of-options marker; remaining words are unexpected. */
          if (p->next)
            {
              builtin_error ("unexpected argument: %s", p->next->word->word);
              builtin_usage ();
              return EX_USAGE;
            }
          break;
        }
      else
        {
          builtin_error ("unknown option: %s (try -h for usage)", w);
          builtin_usage ();
          return EX_USAGE;
        }
    }

  if (namespace_arg != NULL && mode != 3 && mode != 5)
    {
      builtin_error ("-n/--namespace requires -m/--md5 or -s/--sha1");
      builtin_usage ();
      return EX_USAGE;
    }
  if (name_arg != NULL && mode != 3 && mode != 5)
    {
      builtin_error ("-N/--name requires -m/--md5 or -s/--sha1");
      builtin_usage ();
      return EX_USAGE;
    }
  if ((mode == 3 || mode == 5) && namespace_arg == NULL)
    {
      builtin_error ("-n/--namespace is required for name-based UUIDs");
      builtin_usage ();
      return EX_USAGE;
    }
  if ((mode == 3 || mode == 5) && name_arg == NULL)
    {
      builtin_error ("-N/--name is required for name-based UUIDs");
      builtin_usage ();
      return EX_USAGE;
    }

  for (unsigned int i = 0; i < count; i++)
    {
      int rc;
      if (mode == 1)
        rc = bu_v1 ();
      else if (mode == 3)
        rc = bu_name_based (3, namespace_arg, name_arg, is_hex);
      else if (mode == 5)
        rc = bu_name_based (5, namespace_arg, name_arg, is_hex);
      else if (mode == 6)
        rc = bu_v6 ();
      else if (mode == 7)
        rc = bu_v7 ();
      else
        rc = bu_v4 ();
      if (rc != EXECUTION_SUCCESS)
        return rc;
    }

  return EXECUTION_SUCCESS;
}

char *uuidgen_doc[] = {
  "Generate a UUID (RFC 4122).",
  "",
  "    uuidgen [-r | --random]    random UUIDv4 (default)",
  "    uuidgen  -t | --time       time-based UUIDv1",
  "    uuidgen  -m | --md5        name-based UUIDv3 (requires -n/-N)",
  "    uuidgen  -s | --sha1       name-based UUIDv5 (requires -n/-N)",
  "    uuidgen  -n | --namespace  namespace UUID or @dns/@url/@oid/@x500",
  "    uuidgen  -N | --name NAME  name for UUIDv3/UUIDv5",
  "    uuidgen  -6 | --time-v6    reordered-time UUIDv6",
  "    uuidgen  -7 | --time-v7    Unix-time UUIDv7",
  "    uuidgen  -C | --count NUM  generate NUM UUIDs",
  "    uuidgen  -x | --hex        interpret -N name as a hex string",
  "    uuidgen  -h | --help       show this help",
  "    uuidgen  --version         show version",
  "",
  "v4 layout: xxxxxxxx-xxxx-4xxx-Vxxx-xxxxxxxxxxxx where V is one of",
  "8/9/a/b (variant bits) and the rest is CSPRNG-derived.",
  "",
  "v1 layout: time_low-time_mid-1xxx-Vxxx-<node>; timestamp is 100-ns",
  "intervals since 1582-10-15 UTC; node is 6 random bytes with the",
  "multicast bit set (per RFC 4122 §4.5 — no MAC lookup).",
  "",
  "v3/v5 layout: hash(namespace UUID bytes || name bytes), first 16",
  "digest bytes with version nibble 3 (MD5) or 5 (SHA-1), variant 10b.",
  "",
  "v6 layout: reordered v1 timestamp, version nibble 6, variant bits",
  "10b, and the same random multicast-node policy as v1.",
  "",
  "v7 layout: 48-bit Unix epoch milliseconds, version nibble 7,",
  "variant bits 10b, and CSPRNG-derived rand_a/rand_b bits.",
  "",
  "Randomness: getrandom(2) on Linux 3.17+, /dev/urandom fallback.",
  (char *) NULL
};

struct builtin uuidgen_struct = {
  "uuidgen",
  uuidgen_builtin,
  BUILTIN_ENABLED,
  uuidgen_doc,
  "uuidgen [-r|--random | -t|--time | -m|--md5 -n NS -N NAME | -s|--sha1 -n NS -N NAME | -6|--time-v6 | -7|--time-v7] [-C NUM|--count NUM] [-x|--hex] [-h|--help|--version]",
  0
};
