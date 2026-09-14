/* SPDX-License-Identifier: MIT */
/* uudecode.c — decode traditional uuencode (`begin MODE NAME`) and
 *                   base64-uuencode (`begin-base64 MODE NAME`) streams.
 *
 * Reference: refs/sbase/uudecode.c. sbase auto-detects the format from
 * the header line: `begin` → DEC()-character traditional uuencode,
 * `begin-base64` → standard base64 lines terminated by `====`. -m is
 * advertised but unused (sbase always autodetects); we accept it for
 * argv compatibility.
 *
 *   uudecode [-m] [-o OUT] [FILE]
 *
 * FILE = "-" or omitted reads stdin. -o "-" or "/dev/stdout" writes to
 * stdout (does not chmod). Otherwise the output path defaults to the
 * filename baked into the begin line, with chmod() to the begin mode.
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include "loadables.h"

static int
b64val (int c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

/* Decode one base64 line; returns 0 / 1 on success / malformed. */
static int
decode_b64_line (const char *s, FILE *out)
{
  int q[4], n = 0, pad = 0;
  for (; *s; s++)
    {
      if (isspace ((unsigned char) *s)) continue;
      if (*s == '=') { q[n++] = 0; pad++; }
      else
	{
	  int v = b64val ((unsigned char) *s);
	  if (v < 0) return 1;
	  q[n++] = v;
	}
      if (n == 4)
	{
	  unsigned x = ((unsigned) q[0] << 18) | ((unsigned) q[1] << 12)
		     | ((unsigned) q[2] <<  6) |  (unsigned) q[3];
	  fputc ((x >> 16) & 0xff, out);
	  if (pad < 2) fputc ((x >>  8) & 0xff, out);
	  if (pad < 1) fputc ( x        & 0xff, out);
	  n = pad = 0;
	}
    }
  return 0;
}

/* Traditional uuencode: each line begins with a length byte (DEC(*p));
 * the rest is 4-char groups encoding 3 bytes each. End-of-data is a
 * count==0 line (literal "`\n" or " \n"), followed by `end`. */
#define UU_DEC(c)    (((c) - ' ') & 077)
#define UU_IS_DEC(c) (((c) - ' ') >= 0 && ((c) - ' ') <= 077 + 1)

static int
decode_uu_line (const char *p, int *done, FILE *out)
{
  int i;
  unsigned ch;

  if ((i = UU_DEC (*p)) <= 0) { *done = 1; return 0; }
  for (++p; i > 0; p += 4, i -= 3)
    {
      if (!UU_IS_DEC (p[0]) || !UU_IS_DEC (p[1]))
	return 1;
      if (i >= 3)
	{
	  if (!UU_IS_DEC (p[2]) || !UU_IS_DEC (p[3]))
	    return 1;
	  ch = UU_DEC (p[0]) << 2 | UU_DEC (p[1]) >> 4; fputc (ch & 0xff, out);
	  ch = UU_DEC (p[1]) << 4 | UU_DEC (p[2]) >> 2; fputc (ch & 0xff, out);
	  ch = UU_DEC (p[2]) << 6 | UU_DEC (p[3]);      fputc (ch & 0xff, out);
	}
      else
	{
	  if (i >= 1)
	    { ch = UU_DEC (p[0]) << 2 | UU_DEC (p[1]) >> 4; fputc (ch & 0xff, out); }
	  if (i >= 2)
	    {
	      if (!UU_IS_DEC (p[2])) return 1;
	      ch = UU_DEC (p[1]) << 4 | UU_DEC (p[2]) >> 2; fputc (ch & 0xff, out);
	    }
	}
    }
  return 0;
}

int
uudecode_builtin (WORD_LIST *list)
{
  const char *src = NULL, *override = NULL;
  FILE *in = stdin, *out = NULL;
  char line[8192], kind[32], name[4096];
  unsigned mode = 0644;
  int is_b64;

  /* Argv parse: accept -m (no-op, sbase parity) and -o OUT before FILE. */
  while (list && list->word->word[0] == '-' && list->word->word[1])
    {
      const char *w = list->word->word;
      if (!strcmp (w, "-"))
	break;	/* "-" alone is the stdin FILE marker */
      if (!strcmp (w, "-m"))
	{ list = list->next; continue; }
      if (!strcmp (w, "-o"))
	{
	  if (!list->next)
	    { builtin_error ("-o requires output"); return EX_USAGE; }
	  override = list->next->word->word;
	  list = list->next->next;
	  continue;
	}
      if (!strcmp (w, "--"))
	{ list = list->next; break; }
      builtin_error ("invalid option: %s", w);
      builtin_usage ();
      return EX_USAGE;
    }
  if (list) src = list->word->word;

  if (src && strcmp (src, "-"))
    {
      in = fopen (src, "r");
      if (!in)
	{ builtin_error ("%s: %s", src, strerror (errno)); return EXECUTION_FAILURE; }
    }
  do
    {
      if (!fgets (line, sizeof line, in))
	{
	  builtin_error ("no begin line");
	  if (in != stdin) fclose (in);
	  return EXECUTION_FAILURE;
	}
    }
  while (strncmp (line, "begin ", 6) && strncmp (line, "begin-base64 ", 13));

  is_b64 = !strncmp (line, "begin-base64 ", 13);
  if (sscanf (line, "%31s %o %4095s", kind, &mode, name) != 3)
    {
      builtin_error ("bad begin line");
      if (in != stdin) fclose (in);
      return EXECUTION_FAILURE;
    }

  /* Output: -o overrides; "-" or "/dev/stdout" goes to stdout untouched. */
  const char *outpath = override ? override : name;
  int out_is_stdout = !strcmp (outpath, "-") || !strcmp (outpath, "/dev/stdout");
  out = out_is_stdout ? stdout : fopen (outpath, "wb");
  if (!out)
    {
      builtin_error ("%s: %s", outpath, strerror (errno));
      if (in != stdin) fclose (in);
      return EXECUTION_FAILURE;
    }

  if (is_b64)
    {
      while (fgets (line, sizeof line, in))
	{
	  if (!strncmp (line, "====", 4))
	    break;
	  if (decode_b64_line (line, out))
	    {
	      builtin_error ("invalid base64 data");
	      if (!out_is_stdout) { fclose (out); unlink (outpath); }
	      if (in != stdin) fclose (in);
	      return EXECUTION_FAILURE;
	    }
	}
    }
  else
    {
      int done = 0;
      while (!done && fgets (line, sizeof line, in))
	{
	  if (!strncmp (line, "end", 3) && (line[3] == '\n' || line[3] == '\r' || line[3] == 0))
	    break;
	  if (decode_uu_line (line, &done, out))
	    {
	      builtin_error ("invalid uuencode data");
	      if (!out_is_stdout) { fclose (out); unlink (outpath); }
	      if (in != stdin) fclose (in);
	      return EXECUTION_FAILURE;
	    }
	}
    }

  if (!out_is_stdout)
    {
      fclose (out);
      chmod (outpath, mode);
    }
  else
    fflush (out);
  if (in != stdin) fclose (in);
  return EXECUTION_SUCCESS;
}

char *uudecode_doc[] = {
  "Decode traditional uuencode and base64-uuencode streams.",
  "",
  "    uudecode [-m] [-o OUT] [FILE]",
  "",
  "Format is auto-detected from the begin line: 'begin MODE NAME'",
  "selects traditional uuencode, 'begin-base64 MODE NAME' selects base64.",
  "FILE = '-' or omitted reads stdin. -o '-' or '/dev/stdout' writes to",
  "stdout; otherwise the path comes from the begin line (or -o) and is",
  "chmod'd to the begin mode. -m is accepted as a no-op (sbase parity).",
  (char *) NULL
};

struct builtin uudecode_struct = {
  "uudecode", uudecode_builtin, BUILTIN_ENABLED, uudecode_doc,
  "uudecode [-m] [-o OUT] [FILE]", 0
};
