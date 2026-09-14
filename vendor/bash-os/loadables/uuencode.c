/* SPDX-License-Identifier: MIT */
/* uuencode.c - uuencode/base64 encoder. */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include "loadables.h"

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* base64 body (-m): like sbase/sharutils, wrap every 45 input bytes
   (60 output chars) on its own line. */
static int enc_b64(FILE *in) {
    unsigned char buf[45];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        size_t i;
        for (i = 0; i + 3 <= n; i += 3) {
            unsigned v = ((unsigned)buf[i] << 16) | ((unsigned)buf[i+1] << 8) | buf[i+2];
            putchar(b64[(v >> 18) & 63]); putchar(b64[(v >> 12) & 63]);
            putchar(b64[(v >> 6) & 63]);  putchar(b64[v & 63]);
        }
        if (i < n) {                       /* 1 or 2 trailing bytes */
            size_t rem = n - i;
            unsigned v = ((unsigned)buf[i] << 16) | (rem > 1 ? (unsigned)buf[i+1] << 8 : 0);
            putchar(b64[(v >> 18) & 63]);
            putchar(b64[(v >> 12) & 63]);
            putchar(rem > 1 ? b64[(v >> 6) & 63] : '=');
            putchar('=');
        }
        putchar('\n');
    }
    return ferror(in) ? 1 : 0;
}

/* classic uu body: traditional 3-byte→4-char encoding, length-prefixed
   45-byte lines, value 0 mapped to backtick (sbase/sharutils variant),
   terminated by a backtick line and "end". */
static int enc_classic(FILE *in) {
    unsigned char buf[45], *p;
    size_t n;
    int ch;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        ch = ' ' + (int)(n & 0x3f);
        putchar(ch == ' ' ? '`' : ch);
        ssize_t r = (ssize_t) n;
        for (p = buf; r > 0; r -= 3, p += 3) {
            unsigned char b0 = p[0];
            unsigned char b1 = (r < 2) ? 0 : p[1];
            unsigned char b2 = (r < 3) ? 0 : p[2];
            ch = ' ' + ((b0 >> 2) & 0x3f);                      putchar(ch == ' ' ? '`' : ch);
            ch = ' ' + (((b0 << 4) | ((b1 >> 4) & 0xf)) & 0x3f); putchar(ch == ' ' ? '`' : ch);
            ch = ' ' + (((b1 << 2) | ((b2 >> 6) & 0x3)) & 0x3f); putchar(ch == ' ' ? '`' : ch);
            ch = ' ' + (b2 & 0x3f);                              putchar(ch == ' ' ? '`' : ch);
        }
        putchar('\n');
    }
    if (ferror(in)) return 1;
    printf("`\nend\n");
    return 0;
}

int uuencode_builtin(WORD_LIST *list) {
    int base64_mode = 0; const char *src = NULL, *name = NULL; FILE *f = stdin; struct stat st; int mode = 0644;
    if (list && !strcmp(list->word->word, "-m")) { base64_mode = 1; list = list->next; }
    if (!list) { builtin_error("usage: uuencode [-m] [file] decode_path"); return EX_USAGE; }
    if (list->next) { src = list->word->word; name = list->next->word->word; }
    else { name = list->word->word; }
    if (src && strcmp(src, "-")) {
        f = fopen(src, "rb");
        if (!f) { builtin_error("%s: %s", src, strerror(errno)); return EXECUTION_FAILURE; }
    }
    /* A named FILE operand reports its real perms; stdin uses the default file
       creation mode 0666 & ~umask (matches GNU sharutils uuencode, which does
       NOT fstat a pipe — fstat'ing a pipe would wrongly yield 0600). */
    if (f != stdin) {
        if (fstat(fileno(f), &st) == 0) mode = st.st_mode & 0777;
    } else {
        mode_t um = umask(0); umask(um);
        mode = 0666 & ~um;
    }
    printf(base64_mode ? "begin-base64 %o %s\n" : "begin %o %s\n", mode, name);
    /* stdin's FILE persists between builtin calls; a stale EOF flag would
       encode an empty body and still report success. */
    clearerr(f);
    int rc = base64_mode ? enc_b64(f) : enc_classic(f);
    if (base64_mode) printf("====\n");   /* classic trailer is emitted by enc_classic */
    if (f != stdin) fclose(f);
    return rc ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

char *uuencode_doc[] = {"Encode FILE or stdin in uuencode format (classic uu, or base64 with -m).", "    uuencode [-m] [FILE] NAME", (char *)NULL};
struct builtin uuencode_struct = {"uuencode", uuencode_builtin, BUILTIN_ENABLED, uuencode_doc, "uuencode [-m] [FILE] NAME", 0};
