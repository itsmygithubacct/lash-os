/* SPDX-License-Identifier: MIT */
/* ldap.c - small LDAPv3 BER client for bash-os.
 *
 * Implements the minimal NSS/userdb surface:
 *   ldap search -H URI -b BASE_DN [-D DN] [-w PW|-y PWFILE|-W]
 *       [-Z|-ZZ] [-c CA_PEM] [-s SNI] [-k] [--scope sub|one|base]
 *       [--timeout MS] FILTER [ATTR...]
 *   ldap whoami -H URI -D DN {-w PW|-y PWFILE|-W} [...]
 *
 * Test-only verbs:
 *   ldap encode-test bind DN PASSWORD
 *   ldap encode-test search BASE FILTER [ATTR...]
 *   ldap decode-test HEX
 *   ldap filter-test FILTER
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
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>

#ifndef MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS 1
#endif
#include "_mbedtls_asn1.h"
#include "_mbedtls_asn1write.h"
#include "_mbedtls_ssl.h"
#include "_mbedtls_error.h"
#include "_mbedtls_x509_crt.h"
#include "_bashldap_tls.h"

#include "loadables.h"

#define BL_LDAP_MAX_MSG      (256U * 1024U)
#define BL_LDAP_MAX_FILTER_DEPTH 16
#define BL_LDAP_STARTTLS_OID "1.3.6.1.4.1.1466.20037"
#define BL_LDAP_WHOAMI_OID   "1.3.6.1.4.1.4203.1.11.3"

extern char *ldap_doc[];

typedef struct bl_buf {
  unsigned char *data;
  size_t len;
  size_t cap;
} bl_buf;

typedef struct bl_uri {
  char host[256];
  int port;
  int implicit_tls;
} bl_uri;

typedef struct bl_conn {
  int sock;
  int tls;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt ca;
} bl_conn;

static void
bl_buf_free (bl_buf *b)
{
  if (b && b->data)
    free (b->data);
  if (b) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
  }
}

static int
bl_buf_reserve (bl_buf *b, size_t add)
{
  if (add > BL_LDAP_MAX_MSG || b->len > BL_LDAP_MAX_MSG - add) {
    builtin_error ("ldap: BER message exceeds %u bytes", BL_LDAP_MAX_MSG);
    return -1;
  }
  if (b->len + add <= b->cap)
    return 0;
  size_t ncap = b->cap ? b->cap * 2 : 128;
  while (ncap < b->len + add) {
    if (ncap > BL_LDAP_MAX_MSG / 2)
      ncap = BL_LDAP_MAX_MSG;
    else
      ncap *= 2;
    if (ncap < b->len + add && ncap == BL_LDAP_MAX_MSG)
      return -1;
  }
  unsigned char *ndata = (unsigned char *) realloc (b->data, ncap);
  if (!ndata) {
    builtin_error ("ldap: out of memory");
    return -1;
  }
  b->data = ndata;
  b->cap = ncap;
  return 0;
}

static int
bl_buf_append (bl_buf *b, const void *data, size_t len)
{
  if (len == 0)
    return 0;
  if (bl_buf_reserve (b, len) < 0)
    return -1;
  memcpy (b->data + b->len, data, len);
  b->len += len;
  return 0;
}

static int
bl_buf_append_byte (bl_buf *b, unsigned char c)
{
  return bl_buf_append (b, &c, 1);
}

static int
bl_put_len (bl_buf *b, size_t len)
{
  unsigned char tmp[sizeof (size_t) + 1];
  size_t n = 0;

  if (len > BL_LDAP_MAX_MSG)
    return -1;
  if (len < 128)
    return bl_buf_append_byte (b, (unsigned char) len);
  while (len) {
    tmp[sizeof tmp - 1 - n] = (unsigned char) (len & 0xff);
    len >>= 8;
    n++;
  }
  if (n > 4)
    return -1;
  if (bl_buf_append_byte (b, (unsigned char) (0x80U | n)) < 0)
    return -1;
  return bl_buf_append (b, tmp + sizeof tmp - n, n);
}

static int
bl_put_tlv (bl_buf *b, unsigned char tag, const unsigned char *val, size_t len)
{
  if (bl_buf_append_byte (b, tag) < 0 || bl_put_len (b, len) < 0)
    return -1;
  return bl_buf_append (b, val, len);
}

static int
bl_put_wrap (bl_buf *b, unsigned char tag, const bl_buf *inner)
{
  return bl_put_tlv (b, tag, inner->data, inner->len);
}

static int
bl_put_string (bl_buf *b, unsigned char tag, const char *s)
{
  size_t len = s ? strlen (s) : 0;
  return bl_put_tlv (b, tag, (const unsigned char *) (s ? s : ""), len);
}

static int
bl_put_bool (bl_buf *b, int value)
{
  unsigned char v = value ? 0xff : 0x00;
  return bl_put_tlv (b, 0x01, &v, 1);
}

static int
bl_put_int_tag (bl_buf *b, unsigned char tag, int value)
{
  unsigned char tmp[5];
  size_t n = 0;
  unsigned int v;

  if (value < 0)
    return -1;
  v = (unsigned int) value;
  do {
    tmp[sizeof tmp - 1 - n] = (unsigned char) (v & 0xff);
    v >>= 8;
    n++;
  } while (v);
  if (tmp[sizeof tmp - n] & 0x80) {
    tmp[sizeof tmp - 1 - n] = 0;
    n++;
  }
  return bl_put_tlv (b, tag, tmp + sizeof tmp - n, n);
}

static int
bl_put_int (bl_buf *b, int value)
{
  return bl_put_int_tag (b, 0x02, value);
}

static int
bl_put_enum (bl_buf *b, int value)
{
  return bl_put_int_tag (b, 0x0a, value);
}

static int
bl_put_hex (const unsigned char *data, size_t len)
{
  static const char hx[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    putchar (hx[data[i] >> 4]);
    putchar (hx[data[i] & 0x0f]);
  }
  putchar ('\n');
  return 0;
}

static int
bl_hex_val (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static unsigned char *
bl_hex_decode (const char *hex, size_t *out_len)
{
  size_t n = 0, j = 0;
  unsigned char *out;

  for (const char *p = hex; *p; p++)
    if (!isspace ((unsigned char) *p))
      n++;
  if (n == 0 || (n & 1)) {
    builtin_error ("ldap: hex input must have an even byte count");
    return NULL;
  }
  out = (unsigned char *) malloc (n / 2);
  if (!out) {
    builtin_error ("ldap: out of memory");
    return NULL;
  }
  int hi = -1;
  for (const char *p = hex; *p; p++) {
    if (isspace ((unsigned char) *p))
      continue;
    int v = bl_hex_val ((unsigned char) *p);
    if (v < 0) {
      builtin_error ("ldap: non-hex byte in input");
      free (out);
      return NULL;
    }
    if (hi < 0)
      hi = v;
    else {
      out[j++] = (unsigned char) ((hi << 4) | v);
      hi = -1;
    }
  }
  *out_len = j;
  return out;
}

static int
bl_escape_copy (bl_buf *b, const char *s, size_t len)
{
  for (size_t i = 0; i < len; i++) {
    if (s[i] == '\\' && i + 2 < len
        && bl_hex_val ((unsigned char) s[i + 1]) >= 0
        && bl_hex_val ((unsigned char) s[i + 2]) >= 0) {
      int v = (bl_hex_val ((unsigned char) s[i + 1]) << 4)
              | bl_hex_val ((unsigned char) s[i + 2]);
      unsigned char c = (unsigned char) v;
      if (bl_buf_append_byte (b, c) < 0)
        return -1;
      i += 2;
    } else if (s[i] == '\\' && i + 1 < len) {
      if (bl_buf_append_byte (b, (unsigned char) s[i + 1]) < 0)
        return -1;
      i++;
    } else if (bl_buf_append_byte (b, (unsigned char) s[i]) < 0) {
      return -1;
    }
  }
  return 0;
}

typedef struct bl_filter_parser {
  const char *s;
  size_t pos;
  size_t len;
} bl_filter_parser;

static int bl_filter_parse_one (bl_filter_parser *fp, bl_buf *out, int depth);

static int
bl_filter_parse_assertion (bl_filter_parser *fp, bl_buf *out)
{
  size_t attr_start = fp->pos;
  while (fp->pos < fp->len && fp->s[fp->pos] != '='
         && fp->s[fp->pos] != '(' && fp->s[fp->pos] != ')')
    fp->pos++;
  if (fp->pos == attr_start || fp->pos >= fp->len || fp->s[fp->pos] != '=') {
    builtin_error ("ldap: malformed LDAP filter assertion");
    return -1;
  }
  size_t attr_len = fp->pos - attr_start;
  fp->pos++;

  bl_buf val = { 0 };
  int has_star = 0;
  while (fp->pos < fp->len && fp->s[fp->pos] != ')') {
    if (fp->s[fp->pos] == '(') {
      bl_buf_free (&val);
      builtin_error ("ldap: malformed LDAP filter value");
      return -1;
    }
    if (fp->s[fp->pos] == '*')
      has_star = 1;
    if (fp->s[fp->pos] == '\\' && fp->pos + 1 < fp->len) {
      size_t start = fp->pos;
      fp->pos++;
      if (fp->pos + 1 < fp->len
          && bl_hex_val ((unsigned char) fp->s[fp->pos]) >= 0
          && bl_hex_val ((unsigned char) fp->s[fp->pos + 1]) >= 0)
        fp->pos += 2;
      else
        fp->pos++;
      if (bl_escape_copy (&val, fp->s + start, fp->pos - start) < 0) {
        bl_buf_free (&val);
        return -1;
      }
      continue;
    }
    if (bl_buf_append_byte (&val, (unsigned char) fp->s[fp->pos++]) < 0) {
      bl_buf_free (&val);
      return -1;
    }
  }
  if (fp->pos >= fp->len || fp->s[fp->pos] != ')') {
    bl_buf_free (&val);
    builtin_error ("ldap: unbalanced LDAP filter");
    return -1;
  }

  if (val.len == 1 && val.data[0] == '*') {
    int rc = bl_put_tlv (out, 0x87, (const unsigned char *) fp->s + attr_start, attr_len);
    bl_buf_free (&val);
    return rc;
  }

  bl_buf body = { 0 };
  if (bl_put_tlv (&body, 0x04, (const unsigned char *) fp->s + attr_start, attr_len) < 0) {
    bl_buf_free (&val);
    bl_buf_free (&body);
    return -1;
  }

  if (!has_star) {
    if (bl_put_tlv (&body, 0x04, val.data, val.len) < 0
        || bl_put_wrap (out, 0xa3, &body) < 0) {
      bl_buf_free (&val);
      bl_buf_free (&body);
      return -1;
    }
    bl_buf_free (&val);
    bl_buf_free (&body);
    return 0;
  }

  bl_buf parts = { 0 }, seq = { 0 };
  size_t seg_start = 0;
  int emitted = 0;
  for (size_t i = 0; i <= val.len; i++) {
    if (i != val.len && val.data[i] != '*')
      continue;
    size_t seg_len = i - seg_start;
    if (seg_len > 0) {
      unsigned char tag;
      if (seg_start == 0 && val.data[0] != '*')
        tag = 0x80;
      else if (i == val.len && val.data[val.len - 1] != '*')
        tag = 0x82;
      else
        tag = 0x81;
      if (bl_put_tlv (&parts, tag, val.data + seg_start, seg_len) < 0) {
        bl_buf_free (&val);
        bl_buf_free (&body);
        bl_buf_free (&parts);
        bl_buf_free (&seq);
        return -1;
      }
      emitted = 1;
    }
    seg_start = i + 1;
  }
  if (!emitted) {
    bl_buf_free (&val);
    bl_buf_free (&body);
    bl_buf_free (&parts);
    bl_buf_free (&seq);
    builtin_error ("ldap: malformed substring filter");
    return -1;
  }
  if (bl_put_wrap (&seq, 0x30, &parts) < 0
      || bl_buf_append (&body, seq.data, seq.len) < 0
      || bl_put_wrap (out, 0xa4, &body) < 0) {
    bl_buf_free (&val);
    bl_buf_free (&body);
    bl_buf_free (&parts);
    bl_buf_free (&seq);
    return -1;
  }
  bl_buf_free (&val);
  bl_buf_free (&body);
  bl_buf_free (&parts);
  bl_buf_free (&seq);
  return 0;
}

static int
bl_filter_parse_one (bl_filter_parser *fp, bl_buf *out, int depth)
{
  if (depth > BL_LDAP_MAX_FILTER_DEPTH) {
    builtin_error ("ldap: LDAP filter nesting too deep");
    return -1;
  }
  if (fp->pos >= fp->len || fp->s[fp->pos] != '(') {
    builtin_error ("ldap: LDAP filter must start with '('");
    return -1;
  }
  fp->pos++;
  if (fp->pos >= fp->len) {
    builtin_error ("ldap: truncated LDAP filter");
    return -1;
  }

  if (fp->s[fp->pos] == '&' || fp->s[fp->pos] == '|') {
    unsigned char tag = fp->s[fp->pos] == '&' ? 0xa0 : 0xa1;
    bl_buf children = { 0 };
    int count = 0;
    fp->pos++;
    while (fp->pos < fp->len && fp->s[fp->pos] == '(') {
      if (bl_filter_parse_one (fp, &children, depth + 1) < 0) {
        bl_buf_free (&children);
        return -1;
      }
      count++;
    }
    if (count == 0 || fp->pos >= fp->len || fp->s[fp->pos] != ')') {
      bl_buf_free (&children);
      builtin_error ("ldap: malformed LDAP compound filter");
      return -1;
    }
    fp->pos++;
    int rc = bl_put_wrap (out, tag, &children);
    bl_buf_free (&children);
    return rc;
  }

  if (fp->s[fp->pos] == '!') {
    bl_buf child = { 0 };
    fp->pos++;
    if (bl_filter_parse_one (fp, &child, depth + 1) < 0) {
      bl_buf_free (&child);
      return -1;
    }
    if (fp->pos >= fp->len || fp->s[fp->pos] != ')') {
      bl_buf_free (&child);
      builtin_error ("ldap: malformed LDAP not filter");
      return -1;
    }
    fp->pos++;
    int rc = bl_put_wrap (out, 0xa2, &child);
    bl_buf_free (&child);
    return rc;
  }

  int rc = bl_filter_parse_assertion (fp, out);
  if (rc == 0)
    fp->pos++;
  return rc;
}

static int
bl_compile_filter (const char *filter, bl_buf *out)
{
  bl_filter_parser fp;
  if (!filter || !*filter) {
    builtin_error ("ldap: empty LDAP filter");
    return -1;
  }
  fp.s = filter;
  fp.pos = 0;
  fp.len = strlen (filter);
  if (bl_filter_parse_one (&fp, out, 0) < 0)
    return -1;
  if (fp.pos != fp.len) {
    builtin_error ("ldap: trailing bytes after LDAP filter");
    return -1;
  }
  return 0;
}

static int
bl_encode_envelope (int msgid, unsigned char op_tag, const bl_buf *op_body, bl_buf *out)
{
  bl_buf content = { 0 }, op = { 0 };
  int rc = -1;
  if (bl_put_int (&content, msgid) < 0)
    goto done;
  if (bl_put_wrap (&op, op_tag, op_body) < 0)
    goto done;
  if (bl_buf_append (&content, op.data, op.len) < 0)
    goto done;
  rc = bl_put_wrap (out, 0x30, &content);
done:
  bl_buf_free (&content);
  bl_buf_free (&op);
  return rc;
}

static int
bl_encode_bind (int msgid, const char *dn, const char *pw, bl_buf *out)
{
  bl_buf body = { 0 };
  int rc = -1;
  if (bl_put_int (&body, 3) < 0
      || bl_put_string (&body, 0x04, dn ? dn : "") < 0
      || bl_put_string (&body, 0x80, pw ? pw : "") < 0)
    goto done;
  rc = bl_encode_envelope (msgid, 0x60, &body, out);
done:
  bl_buf_free (&body);
  return rc;
}

static int
bl_encode_extended (int msgid, const char *oid, bl_buf *out)
{
  bl_buf body = { 0 };
  int rc = -1;
  if (bl_put_string (&body, 0x80, oid) < 0)
    goto done;
  rc = bl_encode_envelope (msgid, 0x77, &body, out);
done:
  bl_buf_free (&body);
  return rc;
}

static int
bl_scope_value (const char *scope)
{
  if (!scope || strcmp (scope, "sub") == 0)
    return 2;
  if (strcmp (scope, "one") == 0)
    return 1;
  if (strcmp (scope, "base") == 0)
    return 0;
  return -1;
}

static int
bl_encode_search (int msgid, const char *base, const char *scope,
                  const char *filter, char **attrs, int nattrs, bl_buf *out)
{
  bl_buf body = { 0 }, f = { 0 }, attr_body = { 0 }, attr_seq = { 0 };
  int sval = bl_scope_value (scope);
  int rc = -1;
  if (sval < 0) {
    builtin_error ("ldap: scope must be sub, one, or base");
    return -1;
  }
  if (bl_compile_filter (filter, &f) < 0)
    goto done;
  for (int i = 0; i < nattrs; i++) {
    if (bl_put_string (&attr_body, 0x04, attrs[i]) < 0)
      goto done;
  }
  if (bl_put_wrap (&attr_seq, 0x30, &attr_body) < 0)
    goto done;
  if (bl_put_string (&body, 0x04, base ? base : "") < 0
      || bl_put_enum (&body, sval) < 0
      || bl_put_enum (&body, 0) < 0
      || bl_put_int (&body, 0) < 0
      || bl_put_int (&body, 0) < 0
      || bl_put_bool (&body, 0) < 0
      || bl_buf_append (&body, f.data, f.len) < 0
      || bl_buf_append (&body, attr_seq.data, attr_seq.len) < 0)
    goto done;
  rc = bl_encode_envelope (msgid, 0x63, &body, out);
done:
  bl_buf_free (&body);
  bl_buf_free (&f);
  bl_buf_free (&attr_body);
  bl_buf_free (&attr_seq);
  return rc;
}

typedef struct bl_tlv {
  unsigned char tag;
  const unsigned char *val;
  size_t len;
} bl_tlv;

typedef struct bl_reader {
  const unsigned char *p;
  const unsigned char *end;
} bl_reader;

static int
bl_get_tlv (bl_reader *r, bl_tlv *t)
{
  if (r->p >= r->end) {
    builtin_error ("ldap: truncated BER");
    return -1;
  }
  t->tag = *r->p++;
  if (r->p >= r->end) {
    builtin_error ("ldap: truncated BER length");
    return -1;
  }
  unsigned char lb = *r->p++;
  size_t len = 0;
  if (lb == 0x80) {
    builtin_error ("ldap: indefinite-length BER is rejected");
    return -1;
  }
  if ((lb & 0x80) == 0) {
    len = lb;
  } else {
    size_t n = lb & 0x7f;
    if (n == 0 || n > 4 || (size_t) (r->end - r->p) < n) {
      builtin_error ("ldap: malformed BER length");
      return -1;
    }
    if (*r->p == 0) {
      builtin_error ("ldap: non-minimal BER length is rejected");
      return -1;
    }
    for (size_t i = 0; i < n; i++)
      len = (len << 8) | *r->p++;
  }
  if (len > BL_LDAP_MAX_MSG || (size_t) (r->end - r->p) < len) {
    builtin_error ("ldap: BER length exceeds available data");
    return -1;
  }
  if (t->tag == 0x24) {
    builtin_error ("ldap: constructed OCTET STRING BER is rejected");
    return -1;
  }
  t->val = r->p;
  t->len = len;
  r->p += len;
  return 0;
}

static int
bl_tlv_int (const bl_tlv *t, unsigned char tag, int *out)
{
  int v = 0;
  if (t->tag != tag || t->len == 0 || t->len > 4 || (t->val[0] & 0x80)) {
    builtin_error ("ldap: malformed integer/enum BER");
    return -1;
  }
  for (size_t i = 0; i < t->len; i++)
    v = (v << 8) | t->val[i];
  *out = v;
  return 0;
}

static char *
bl_tlv_string (const bl_tlv *t, unsigned char tag)
{
  char *s;
  if (t->tag != tag || (t->tag & 0x20)) {
    builtin_error ("ldap: malformed OCTET STRING BER");
    return NULL;
  }
  s = (char *) malloc (t->len + 1);
  if (!s) {
    builtin_error ("ldap: out of memory");
    return NULL;
  }
  memcpy (s, t->val, t->len);
  s[t->len] = '\0';
  return s;
}

static int
bl_decode_ldap_message (const unsigned char *data, size_t len, FILE *out,
                        int *op_tag, int *result_code, char **response_value)
{
  bl_reader r, outer, op_reader, attrs, part, vals;
  bl_tlv top, t, op, at, setv;
  int msgid = 0;

  if (len > BL_LDAP_MAX_MSG) {
    builtin_error ("ldap: message exceeds cap");
    return -1;
  }
  r.p = data;
  r.end = data + len;
  if (bl_get_tlv (&r, &top) < 0 || top.tag != 0x30 || r.p != r.end) {
    builtin_error ("ldap: expected LDAPMessage SEQUENCE");
    return -1;
  }
  outer.p = top.val;
  outer.end = top.val + top.len;
  if (bl_get_tlv (&outer, &t) < 0 || bl_tlv_int (&t, 0x02, &msgid) < 0)
    return -1;
  (void) msgid;
  if (bl_get_tlv (&outer, &op) < 0 || outer.p != outer.end) {
    builtin_error ("ldap: malformed LDAP protocolOp");
    return -1;
  }
  if (op_tag)
    *op_tag = op.tag;
  if (result_code)
    *result_code = -1;
  if (response_value)
    *response_value = NULL;

  op_reader.p = op.val;
  op_reader.end = op.val + op.len;
  if (op.tag == 0x64) {
    char *dn;
    if (bl_get_tlv (&op_reader, &t) < 0)
      return -1;
    dn = bl_tlv_string (&t, 0x04);
    if (!dn)
      return -1;
    if (out)
      fprintf (out, "dn: %s\n", dn);
    free (dn);
    if (bl_get_tlv (&op_reader, &t) < 0 || t.tag != 0x30) {
      builtin_error ("ldap: malformed SearchResultEntry attributes");
      return -1;
    }
    attrs.p = t.val;
    attrs.end = t.val + t.len;
    while (attrs.p < attrs.end) {
      char *name;
      if (bl_get_tlv (&attrs, &at) < 0 || at.tag != 0x30) {
        builtin_error ("ldap: malformed SearchResultEntry attribute");
        return -1;
      }
      part.p = at.val;
      part.end = at.val + at.len;
      if (bl_get_tlv (&part, &t) < 0)
        return -1;
      name = bl_tlv_string (&t, 0x04);
      if (!name)
        return -1;
      if (bl_get_tlv (&part, &setv) < 0 || setv.tag != 0x31 || part.p != part.end) {
        free (name);
        builtin_error ("ldap: malformed SearchResultEntry values");
        return -1;
      }
      vals.p = setv.val;
      vals.end = setv.val + setv.len;
      while (vals.p < vals.end) {
        char *value;
        if (bl_get_tlv (&vals, &t) < 0) {
          free (name);
          return -1;
        }
        value = bl_tlv_string (&t, 0x04);
        if (!value) {
          free (name);
          return -1;
        }
        if (out)
          fprintf (out, "%s: %s\n", name, value);
        free (value);
      }
      free (name);
    }
    return op_reader.p == op_reader.end ? 0 : -1;
  }

  if (op.tag == 0x61 || op.tag == 0x65 || op.tag == 0x78) {
    char *diag = NULL;
    int rc;
    if (bl_get_tlv (&op_reader, &t) < 0 || bl_tlv_int (&t, 0x0a, &rc) < 0)
      return -1;
    if (result_code)
      *result_code = rc;
    if (bl_get_tlv (&op_reader, &t) < 0) return -1;
    diag = bl_tlv_string (&t, 0x04);
    if (!diag) return -1;
    if (bl_get_tlv (&op_reader, &t) < 0) { free (diag); return -1; }
    char *msg = bl_tlv_string (&t, 0x04);
    if (!msg) { free (diag); return -1; }
    if (out) {
      fprintf (out, "resultCode: %d\n", rc);
      if (*msg)
        fprintf (out, "diagnosticMessage: %s\n", msg);
    }
    free (diag);
    free (msg);
    while (op_reader.p < op_reader.end) {
      if (bl_get_tlv (&op_reader, &t) < 0)
        return -1;
      if (t.tag == 0x8b) {
        char *rv = bl_tlv_string (&t, 0x8b);
        if (!rv)
          return -1;
        if (out) {
          if (strncmp (rv, "dn:", 3) == 0)
            fprintf (out, "%s\n", rv);
          else
            fprintf (out, "responseValue: %s\n", rv);
        }
        if (response_value)
          *response_value = rv;
        else
          free (rv);
      }
    }
    return 0;
  }

  builtin_error ("ldap: unsupported LDAP protocolOp 0x%02x", op.tag);
  return -1;
}

/* Parser fuzzing uses the same BER/filter code without network entry points. */
#ifndef BASH_OS_LDAP_PARSER_ONLY
static int
bl_parse_uri (const char *uri, bl_uri *out)
{
  const char *p;
  const char *slash;
  const char *colon;
  size_t hlen;

  memset (out, 0, sizeof *out);
  if (strncmp (uri, "ldaps://", 8) == 0) {
    out->implicit_tls = 1;
    out->port = 636;
    p = uri + 8;
  } else if (strncmp (uri, "ldap://", 7) == 0) {
    out->implicit_tls = 0;
    out->port = 389;
    p = uri + 7;
  } else {
    builtin_error ("ldap: URI must start with ldap:// or ldaps://");
    return -1;
  }
  slash = strchr (p, '/');
  colon = strchr (p, ':');
  if (slash && colon && colon > slash)
    colon = NULL;
  hlen = colon ? (size_t) (colon - p) : slash ? (size_t) (slash - p) : strlen (p);
  if (hlen == 0 || hlen >= sizeof out->host) {
    builtin_error ("ldap: bad LDAP URI host");
    return -1;
  }
  memcpy (out->host, p, hlen);
  out->host[hlen] = '\0';
  if (colon) {
    char *end = NULL;
    long port = strtol (colon + 1, &end, 10);
    if ((slash && end != slash) || (!slash && (!end || *end))
        || port <= 0 || port > 65535) {
      builtin_error ("ldap: bad LDAP URI port");
      return -1;
    }
    out->port = (int) port;
  }
  return 0;
}

static int
bl_set_timeout (int fd, int ms)
{
  if (ms <= 0)
    return 0;
  struct timeval tv;
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  if (setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0
      || setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) < 0) {
    builtin_error ("ldap: setsockopt timeout: %s", strerror (errno));
    return -1;
  }
  return 0;
}

static int
bl_tcp_connect (const char *host, int port, int timeout_ms)
{
  char pbuf[16];
  struct addrinfo hints, *res = NULL, *ai;
  int fd = -1;
  int gai;

  snprintf (pbuf, sizeof pbuf, "%d", port);
  memset (&hints, 0, sizeof hints);
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  gai = getaddrinfo (host, pbuf, &hints, &res);
  if (gai != 0) {
    builtin_error ("ldap: getaddrinfo %s: %s", host, gai_strerror (gai));
    return -1;
  }
  for (ai = res; ai; ai = ai->ai_next) {
    fd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0)
      continue;
    (void) bl_set_timeout (fd, timeout_ms);
    if (connect (fd, ai->ai_addr, ai->ai_addrlen) == 0)
      break;
    close (fd);
    fd = -1;
  }
  freeaddrinfo (res);
  if (fd < 0)
    builtin_error ("ldap: connect %s:%d failed", host, port);
  return fd;
}

static void
bl_conn_init (bl_conn *c)
{
  c->sock = -1;
  c->tls = 0;
  mbedtls_ssl_init (&c->ssl);
  mbedtls_ssl_config_init (&c->conf);
  mbedtls_x509_crt_init (&c->ca);
}

static void
bl_conn_close (bl_conn *c)
{
  if (c->tls)
    mbedtls_ssl_close_notify (&c->ssl);
  if (c->sock >= 0)
    close (c->sock);
  mbedtls_ssl_free (&c->ssl);
  mbedtls_ssl_config_free (&c->conf);
  mbedtls_x509_crt_free (&c->ca);
  c->sock = -1;
  c->tls = 0;
}

static int
bl_conn_tls (bl_conn *c, const char *sni, const char *ca_path, int insecure)
{
  if (bc_tls_handshake (c->sock, sni, ca_path, insecure, &c->ssl, &c->conf, &c->ca) < 0)
    return -1;
  c->tls = 1;
  return 0;
}

static int
bl_conn_write_all (bl_conn *c, const unsigned char *data, size_t len)
{
  size_t off = 0;
  while (off < len) {
    ssize_t n;
    if (c->tls) {
      int w = mbedtls_ssl_write (&c->ssl, data + off, len - off);
      if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE)
        continue;
      if (w < 0) {
        builtin_error ("ldap: TLS write failed (-0x%04x)", -w);
        return -1;
      }
      n = w;
    } else {
      do { n = write (c->sock, data + off, len - off); }
      while (n < 0 && errno == EINTR);
      if (n < 0) {
        builtin_error ("ldap: write failed: %s", strerror (errno));
        return -1;
      }
    }
    if (n == 0) {
      builtin_error ("ldap: short write");
      return -1;
    }
    off += (size_t) n;
  }
  return 0;
}

static int
bl_conn_read_exact (bl_conn *c, unsigned char *data, size_t len)
{
  size_t off = 0;
  while (off < len) {
    ssize_t n;
    if (c->tls) {
      int r = mbedtls_ssl_read (&c->ssl, data + off, len - off);
      if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
        continue;
      if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r == 0) {
        builtin_error ("ldap: TLS peer closed");
        return -1;
      }
      if (r < 0) {
        builtin_error ("ldap: TLS read failed (-0x%04x)", -r);
        return -1;
      }
      n = r;
    } else {
      do { n = read (c->sock, data + off, len - off); }
      while (n < 0 && errno == EINTR);
      if (n < 0) {
        builtin_error ("ldap: read failed: %s", strerror (errno));
        return -1;
      }
      if (n == 0) {
        builtin_error ("ldap: peer closed");
        return -1;
      }
    }
    off += (size_t) n;
  }
  return 0;
}

static int
bl_conn_read_message (bl_conn *c, bl_buf *out)
{
  unsigned char hdr[6];
  size_t hlen = 2, len = 0;

  if (bl_conn_read_exact (c, hdr, 2) < 0)
    return -1;
  if (hdr[1] == 0x80) {
    builtin_error ("ldap: indefinite-length BER is rejected");
    return -1;
  }
  if ((hdr[1] & 0x80) == 0) {
    len = hdr[1];
  } else {
    size_t n = hdr[1] & 0x7f;
    if (n == 0 || n > 4) {
      builtin_error ("ldap: malformed BER length");
      return -1;
    }
    if (bl_conn_read_exact (c, hdr + 2, n) < 0)
      return -1;
    hlen += n;
    if (hdr[2] == 0) {
      builtin_error ("ldap: non-minimal BER length is rejected");
      return -1;
    }
    for (size_t i = 0; i < n; i++)
      len = (len << 8) | hdr[2 + i];
  }
  if (len > BL_LDAP_MAX_MSG) {
    builtin_error ("ldap: LDAP message exceeds cap");
    return -1;
  }
  if (bl_buf_append (out, hdr, hlen) < 0)
    return -1;
  if (bl_buf_reserve (out, len) < 0)
    return -1;
  if (bl_conn_read_exact (c, out->data + out->len, len) < 0)
    return -1;
  out->len += len;
  return 0;
}

static char *
bl_read_file_cap (const char *path, size_t cap)
{
  int fd = open (path, O_RDONLY);
  char *buf;
  size_t len = 0;
  if (fd < 0) {
    builtin_error ("ldap: open %s: %s", path, strerror (errno));
    return NULL;
  }
  buf = (char *) malloc (cap + 1);
  if (!buf) {
    close (fd);
    builtin_error ("ldap: out of memory");
    return NULL;
  }
  for (;;) {
    ssize_t n = read (fd, buf + len, cap - len);
    if (n < 0 && errno == EINTR)
      continue;
    if (n < 0) {
      builtin_error ("ldap: read %s: %s", path, strerror (errno));
      close (fd);
      free (buf);
      return NULL;
    }
    if (n == 0)
      break;
    len += (size_t) n;
    if (len == cap) {
      builtin_error ("ldap: password file too large");
      close (fd);
      free (buf);
      return NULL;
    }
  }
  close (fd);
  while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
    len--;
  buf[len] = '\0';
  return buf;
}

static char *
bl_read_password_tty (void)
{
  FILE *tty = fopen ("/dev/tty", "r");
  char tmp[1024];
  char *out;
  if (!tty) {
    builtin_error ("ldap: cannot open /dev/tty for -W");
    return NULL;
  }
  fputs ("LDAP Password: ", stderr);
  fflush (stderr);
  if (!fgets (tmp, sizeof tmp, tty)) {
    fclose (tty);
    builtin_error ("ldap: password read failed");
    return NULL;
  }
  fclose (tty);
  tmp[strcspn (tmp, "\r\n")] = '\0';
  out = strdup (tmp);
  if (!out)
    builtin_error ("ldap: out of memory");
  memset (tmp, 0, sizeof tmp);
  return out;
}

static int
bl_send_and_read_result (bl_conn *c, const bl_buf *msg, int expect_tag, FILE *out)
{
  bl_buf reply = { 0 };
  int op = 0, rc = -1;
  int ret = -1;
  if (bl_conn_write_all (c, msg->data, msg->len) < 0)
    return -1;
  if (bl_conn_read_message (c, &reply) < 0)
    goto done;
  if (bl_decode_ldap_message (reply.data, reply.len, out, &op, &rc, NULL) < 0)
    goto done;
  if (op != expect_tag) {
    builtin_error ("ldap: unexpected LDAP response op 0x%02x", op);
    goto done;
  }
  ret = rc == 0 ? 0 : -1;
done:
  bl_buf_free (&reply);
  return ret;
}

typedef struct bl_cli {
  const char *uri;
  const char *base;
  const char *bind_dn;
  const char *pw_arg;
  const char *pw_file;
  const char *ca_path;
  const char *sni;
  const char *scope;
  int read_pw_tty;
  int insecure;
  int starttls;
  int starttls_required;
  int timeout_ms;
  const char *filter;
  char **attrs;
  int nattrs;
} bl_cli;

static int
bl_parse_common (int argc, char **argv, int need_base, bl_cli *cfg, int *first_pos)
{
  memset (cfg, 0, sizeof *cfg);
  cfg->scope = "sub";
  cfg->timeout_ms = 0;
  int i;
  for (i = 0; i < argc; i++) {
    const char *w = argv[i];
    if (strcmp (w, "-H") == 0) {
      if (++i >= argc) { builtin_error ("ldap: -H needs URI"); return -1; }
      cfg->uri = argv[i];
    } else if (strcmp (w, "-b") == 0) {
      if (++i >= argc) { builtin_error ("ldap: -b needs BASE_DN"); return -1; }
      cfg->base = argv[i];
    } else if (strcmp (w, "-D") == 0) {
      if (++i >= argc) { builtin_error ("ldap: -D needs BIND_DN"); return -1; }
      cfg->bind_dn = argv[i];
    } else if (strcmp (w, "-w") == 0) {
      if (++i >= argc) { builtin_error ("ldap: -w needs PASSWORD"); return -1; }
      cfg->pw_arg = argv[i];
    } else if (strcmp (w, "-y") == 0) {
      if (++i >= argc) { builtin_error ("ldap: -y needs PWFILE"); return -1; }
      cfg->pw_file = argv[i];
    } else if (strcmp (w, "-W") == 0) {
      cfg->read_pw_tty = 1;
    } else if (strcmp (w, "-Z") == 0) {
      cfg->starttls = 1;
    } else if (strcmp (w, "-ZZ") == 0) {
      cfg->starttls = 1;
      cfg->starttls_required = 1;
    } else if (strcmp (w, "-c") == 0) {
      if (++i >= argc) { builtin_error ("ldap: -c needs CA_PEM"); return -1; }
      cfg->ca_path = argv[i];
    } else if (strcmp (w, "-s") == 0) {
      if (++i >= argc) { builtin_error ("ldap: -s needs SNI"); return -1; }
      cfg->sni = argv[i];
    } else if (strcmp (w, "-k") == 0) {
      cfg->insecure = 1;
    } else if (strcmp (w, "--scope") == 0) {
      if (++i >= argc) { builtin_error ("ldap: --scope needs sub|one|base"); return -1; }
      cfg->scope = argv[i];
    } else if (strcmp (w, "--timeout") == 0) {
      char *end = NULL;
      long v;
      if (++i >= argc) { builtin_error ("ldap: --timeout needs MS"); return -1; }
      errno = 0;
      v = strtol (argv[i], &end, 10);
      if (errno || !end || *end || v < 0 || v > 3600000) {
        builtin_error ("ldap: --timeout must be 0..3600000 milliseconds");
        return -1;
      }
      cfg->timeout_ms = (int) v;
    } else if (w[0] == '-') {
      builtin_error ("ldap: unknown option %s", w);
      return -1;
    } else {
      break;
    }
  }
  if (!cfg->uri) { builtin_error ("ldap: -H URI is required"); return -1; }
  if (need_base && !cfg->base) { builtin_error ("ldap: -b BASE_DN is required"); return -1; }
  if (!!cfg->pw_arg + !!cfg->pw_file + cfg->read_pw_tty > 1) {
    builtin_error ("ldap: choose only one of -w, -y, or -W");
    return -1;
  }
  *first_pos = i;
  return 0;
}

static char *
bl_cli_password (const bl_cli *cfg)
{
  if (cfg->pw_arg)
    return strdup (cfg->pw_arg);
  if (cfg->pw_file)
    return bl_read_file_cap (cfg->pw_file, 65536);
  if (cfg->read_pw_tty)
    return bl_read_password_tty ();
  return strdup ("");
}

static int
bl_open_session (const bl_cli *cfg, bl_conn *c, bl_uri *u)
{
  if (bl_parse_uri (cfg->uri, u) < 0)
    return -1;
  c->sock = bl_tcp_connect (u->host, u->port, cfg->timeout_ms);
  if (c->sock < 0)
    return -1;
  if (u->implicit_tls) {
    const char *sni = cfg->sni ? cfg->sni : u->host;
    if (bl_conn_tls (c, sni, cfg->ca_path, cfg->insecure) < 0)
      return -1;
  }
  return 0;
}

static int
bl_maybe_starttls (const bl_cli *cfg, bl_conn *c, const bl_uri *u, int *msgid)
{
  bl_buf req = { 0 };
  int ret = 0;
  if (!cfg->starttls || u->implicit_tls)
    return 0;
  if (bl_encode_extended ((*msgid)++, BL_LDAP_STARTTLS_OID, &req) < 0)
    return -1;
  if (bl_send_and_read_result (c, &req, 0x78, NULL) < 0) {
    if (cfg->starttls_required) {
      bl_buf_free (&req);
      builtin_error ("ldap: StartTLS required but negotiation failed");
      return -1;
    }
    ret = 0;
  } else {
    const char *sni = cfg->sni ? cfg->sni : u->host;
    if (bl_conn_tls (c, sni, cfg->ca_path, cfg->insecure) < 0)
      ret = -1;
  }
  bl_buf_free (&req);
  return ret;
}

static int
bl_bind_if_needed (const bl_cli *cfg, bl_conn *c, int *msgid)
{
  bl_buf bind = { 0 };
  char *pw = NULL;
  int ret = 0;
  if (!cfg->bind_dn)
    return 0;
  pw = bl_cli_password (cfg);
  if (!pw)
    return -1;
  if (bl_encode_bind ((*msgid)++, cfg->bind_dn, pw, &bind) < 0
      || bl_send_and_read_result (c, &bind, 0x61, NULL) < 0)
    ret = -1;
  memset (pw, 0, strlen (pw));
  free (pw);
  bl_buf_free (&bind);
  return ret;
}

static int
bl_cmd_search (int argc, char **argv)
{
  bl_cli cfg;
  int pos, msgid = 1;
  bl_uri uri;
  bl_conn c;
  bl_buf search = { 0 }, reply = { 0 };
  int final_rc = EXECUTION_FAILURE;

  if (bl_parse_common (argc, argv, 1, &cfg, &pos) < 0)
    return EX_USAGE;
  if (pos >= argc) {
    builtin_error ("ldap: search FILTER is required");
    return EX_USAGE;
  }
  cfg.filter = argv[pos++];
  cfg.attrs = argv + pos;
  cfg.nattrs = argc - pos;

  bl_conn_init (&c);
  if (bl_open_session (&cfg, &c, &uri) < 0)
    goto done;
  if (bl_maybe_starttls (&cfg, &c, &uri, &msgid) < 0)
    goto done;
  if (bl_bind_if_needed (&cfg, &c, &msgid) < 0)
    goto done;
  if (bl_encode_search (msgid, cfg.base, cfg.scope, cfg.filter, cfg.attrs, cfg.nattrs, &search) < 0)
    goto done;
  if (bl_conn_write_all (&c, search.data, search.len) < 0)
    goto done;
  for (;;) {
    int op = 0, rc = -1;
    reply.len = 0;
    if (bl_conn_read_message (&c, &reply) < 0)
      goto done;
    if (bl_decode_ldap_message (reply.data, reply.len, stdout, &op, &rc, NULL) < 0)
      goto done;
    if (op == 0x65) {
      final_rc = rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
      break;
    }
    if (op != 0x64) {
      builtin_error ("ldap: unexpected search response op 0x%02x", op);
      goto done;
    }
  }

done:
  bl_buf_free (&search);
  bl_buf_free (&reply);
  bl_conn_close (&c);
  return final_rc;
}

static int
bl_cmd_whoami (int argc, char **argv)
{
  bl_cli cfg;
  int pos, msgid = 1;
  bl_uri uri;
  bl_conn c;
  bl_buf who = { 0 }, reply = { 0 };
  int final_rc = EXECUTION_FAILURE;

  if (bl_parse_common (argc, argv, 0, &cfg, &pos) < 0)
    return EX_USAGE;
  if (pos != argc) {
    builtin_error ("ldap: unexpected whoami arguments");
    return EX_USAGE;
  }
  if (!cfg.bind_dn) {
    builtin_error ("ldap: whoami requires -D BIND_DN");
    return EX_USAGE;
  }
  if (!cfg.pw_arg && !cfg.pw_file && !cfg.read_pw_tty) {
    builtin_error ("ldap: whoami requires -w, -y, or -W");
    return EX_USAGE;
  }

  bl_conn_init (&c);
  if (bl_open_session (&cfg, &c, &uri) < 0)
    goto done;
  if (bl_maybe_starttls (&cfg, &c, &uri, &msgid) < 0)
    goto done;
  if (bl_bind_if_needed (&cfg, &c, &msgid) < 0)
    goto done;
  if (bl_encode_extended (msgid, BL_LDAP_WHOAMI_OID, &who) < 0)
    goto done;
  if (bl_conn_write_all (&c, who.data, who.len) < 0)
    goto done;
  if (bl_conn_read_message (&c, &reply) < 0)
    goto done;
  int op = 0, rc = -1;
  if (bl_decode_ldap_message (reply.data, reply.len, stdout, &op, &rc, NULL) < 0)
    goto done;
  if (op == 0x78 && rc == 0)
    final_rc = EXECUTION_SUCCESS;

done:
  bl_buf_free (&who);
  bl_buf_free (&reply);
  bl_conn_close (&c);
  return final_rc;
}

static int
bl_words_to_argv (WORD_LIST *list, int *argc_out, char ***argv_out)
{
  int argc = 0;
  char **argv;
  for (WORD_LIST *p = list; p; p = p->next)
    argc++;
  argv = (char **) calloc ((size_t) argc + 1, sizeof (char *));
  if (!argv) {
    builtin_error ("ldap: out of memory");
    return -1;
  }
  int i = 0;
  for (WORD_LIST *p = list; p; p = p->next)
    argv[i++] = p->word->word;
  *argc_out = argc;
  *argv_out = argv;
  return 0;
}

static int
bl_cmd_encode_test (int argc, char **argv)
{
  bl_buf out = { 0 };
  int rc = EXECUTION_FAILURE;
  if (argc < 1) {
    builtin_error ("ldap: encode-test needs bind|search");
    return EX_USAGE;
  }
  if (strcmp (argv[0], "bind") == 0) {
    if (argc != 3) {
      builtin_error ("ldap: encode-test bind DN PASSWORD");
      return EX_USAGE;
    }
    if (bl_encode_bind (1, argv[1], argv[2], &out) == 0)
      rc = EXECUTION_SUCCESS;
  } else if (strcmp (argv[0], "search") == 0) {
    if (argc < 3) {
      builtin_error ("ldap: encode-test search BASE FILTER [ATTR...]");
      return EX_USAGE;
    }
    if (bl_encode_search (2, argv[1], "sub", argv[2], argv + 3, argc - 3, &out) == 0)
      rc = EXECUTION_SUCCESS;
  } else {
    builtin_error ("ldap: encode-test needs bind|search");
    return EX_USAGE;
  }
  if (rc == EXECUTION_SUCCESS)
    bl_put_hex (out.data, out.len);
  bl_buf_free (&out);
  return rc;
}

static int
bl_cmd_decode_test (int argc, char **argv)
{
  size_t len = 0;
  unsigned char *data;
  int rc;
  if (argc != 1) {
    builtin_error ("ldap: decode-test HEX");
    return EX_USAGE;
  }
  data = bl_hex_decode (argv[0], &len);
  if (!data)
    return EXECUTION_FAILURE;
  rc = bl_decode_ldap_message (data, len, stdout, NULL, NULL, NULL) == 0
       ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  free (data);
  return rc;
}

static int
bl_cmd_filter_test (int argc, char **argv)
{
  bl_buf out = { 0 };
  int rc;
  if (argc != 1) {
    builtin_error ("ldap: filter-test FILTER");
    return EX_USAGE;
  }
  rc = bl_compile_filter (argv[0], &out) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (rc == EXECUTION_SUCCESS)
    bl_put_hex (out.data, out.len);
  bl_buf_free (&out);
  return rc;
}

int
ldap_builtin (WORD_LIST *list)
{
  int argc;
  char **argv;
  int rc;

  if (bl_words_to_argv (list, &argc, &argv) < 0)
    return EXECUTION_FAILURE;
  if (argc == 0 || strcmp (argv[0], "--help") == 0) {
    for (char **lp = ldap_doc; *lp; lp++)
      puts (*lp);
    free (argv);
    return argc == 0 ? EX_USAGE : EXECUTION_SUCCESS;
  }

  if (strcmp (argv[0], "search") == 0)
    rc = bl_cmd_search (argc - 1, argv + 1);
  else if (strcmp (argv[0], "whoami") == 0)
    rc = bl_cmd_whoami (argc - 1, argv + 1);
  else if (strcmp (argv[0], "encode-test") == 0)
    rc = bl_cmd_encode_test (argc - 1, argv + 1);
  else if (strcmp (argv[0], "decode-test") == 0)
    rc = bl_cmd_decode_test (argc - 1, argv + 1);
  else if (strcmp (argv[0], "filter-test") == 0)
    rc = bl_cmd_filter_test (argc - 1, argv + 1);
  else {
    builtin_error ("ldap: unknown subcommand %s", argv[0]);
    rc = EX_USAGE;
  }
  free (argv);
  return rc;
}

char *ldap_doc[] = {
  "Small LDAPv3 BER client for bash-os NSS and userdb providers.",
  "",
  "Subcommands:",
  "    search -H URI -b BASE_DN [-D BIND_DN] [-w PW|-y PWFILE|-W]",
  "        [-Z|-ZZ] [-c CA_PEM] [-s SNI] [-k] [--scope sub|one|base]",
  "        [--timeout MS] FILTER [ATTR...]",
  "    whoami -H URI -D BIND_DN {-w PW|-y PWFILE|-W} [...]",
  "",
  "URI schemes: ldap://host[:389] and ldaps://host[:636].",
  "ldaps:// uses TLS immediately; ldap:// with -Z/-ZZ sends StartTLS before bind.",
  "-ZZ fails closed if StartTLS does not complete. TLS verification is required",
  "by default, with the same CA auto-load path as crypto tls connect.",
  "",
  "Supported filters: equality, present, and/or/not, and substring.",
  "Supported operations: simple bind, search, StartTLS, and WhoAmI.",
  (char *) NULL
};

struct builtin ldap_struct = {
  "ldap",
  ldap_builtin,
  BUILTIN_ENABLED,
  ldap_doc,
  "ldap search|whoami [FLAGS...]",
  0
};

#endif /* BASH_OS_LDAP_PARSER_ONLY */
