/* SPDX-License-Identifier: MIT */
/* pax.c — upstream bash-os bashpax.c, vendored 2026-09-05 with the injector-visible
 * symbols renamed bashpax_builtin/bashpax_doc -> pax_builtin/pax_doc so the
 * command name is the POSIX one (third_party/bashy-box/SNAPSHOT.md). */
/* bashpax.c - POSIX ustar list/create/extract subset.
 *
 * D06 archive-format expansion: typeflag-aware extraction (directories,
 * symlinks, hardlinks), parent-dir creation, mtime preservation, ustar
 * checksum validation, and truncation detection on read; directory and
 * symlink emit on write. POSIX PAX headers ('x','g') and GNU long-name /
 * long-link headers ('L','K') are consumed on read. Device/fifo typeflags
 * are rejected with a clear diagnostic rather than being silently
 * mishandled. Sees `D04` hardening pass for the original
 * `..` rejection (which still applies to all member names and link
 * targets).
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <limits.h>
#include "loadables.h"

static unsigned long octal(const char *s, size_t n){
    char b[32]; size_t j=0;
    for(size_t i=0;i<n&&j<sizeof(b)-1;i++) if(s[i]>='0'&&s[i]<='7') b[j++]=s[i];
    b[j]=0; return j?strtoul(b,NULL,8):0;
}
/* Write v as n-1 octal digits. A value that does not fit is clamped to the
   field's maximum — write_member has already emitted the exact value in a PAX
   extended header for the fields that can overflow (size, uid, gid). */
static void put_octal(char *dst, size_t n, unsigned long v){
    unsigned long max = (1UL << (3 * (n - 1))) - 1;
    if(v > max) v = max;
    snprintf(dst,n,"%0*lo",(int)n-1,v); dst[n-1]='\0';
}
#define PAX_EXT_SIZE 1
#define PAX_EXT_UID  2
#define PAX_EXT_GID  4
/* Which numeric fields of st overflow their ustar octal field. */
static int pax_numeric_ext(const struct stat *st, int regular){
    int f = 0;
    if(regular && (unsigned long long)st->st_size > 077777777777ULL) f |= PAX_EXT_SIZE;   /* 11 octal digits */
    if((unsigned long)st->st_uid > 07777777UL) f |= PAX_EXT_UID;                            /* 7 octal digits */
    if((unsigned long)st->st_gid > 07777777UL) f |= PAX_EXT_GID;
    return f;
}
/* Skip N bytes of the archive. fseek only works on a seekable file; on a
   pipe (cat x.tar | pax -r, ssh host cat x.tar | pax) it fails and leaves
   the stream where it was, so every later header read is misaligned. */
static int skip_bytes(FILE *f, unsigned long n){
    if(n == 0) return 0;
    if(fseek(f, (long)n, SEEK_CUR) == 0) return 0;
    unsigned char sink[4096];
    while(n){
        size_t want = n > sizeof sink ? sizeof sink : (size_t)n;
        size_t got = fread(sink, 1, want, f);
        if(got == 0) return -1;
        n -= got;
    }
    return 0;
}
static int zero_block(const unsigned char *b){ for(int i=0;i<512;i++) if(b[i]) return 0; return 1; }
static void name_from_hdr(char *out, unsigned char *h){
    char name[101], pref[156];
    memcpy(name,h,100); name[100]=0;
    memcpy(pref,h+345,155); pref[155]=0;
    if(pref[0]) snprintf(out,257,"%s/%s",pref,name); else snprintf(out,257,"%s",name);
}
static int unsafe_path(const char *name){
    if(!name||!*name||name[0]=='/') return 1;
    const char *p=name;
    while(*p){
        while(*p=='/') p++;
        const char *q=p;
        while(*q&&*q!='/') q++;
        if(q-p==2&&p[0]=='.'&&p[1]=='.') return 1;
        p=q;
    }
    return 0;
}

/* ustar checksum: sum of all 512 header bytes with the 8-byte checksum
   field treated as ASCII spaces during the sum. Returns 1 if the stored
   value matches, 0 if it does not. */
static int hdr_checksum_ok(const unsigned char *h){
    unsigned long stored = octal((const char *)h+148, 8);
    unsigned long sum = 0;
    for(int i=0;i<512;i++) sum += (i>=148 && i<156) ? (unsigned char)' ' : h[i];
    return sum == stored;
}

struct pax_meta {
    char *path, *linkpath;
    unsigned long size;
    time_t mtime;
    int has_size, has_mtime;
    int typeflag;
};

static void pax_meta_free(struct pax_meta *m){
    free(m->path); free(m->linkpath); memset(m, 0, sizeof *m);
}

static int pax_meta_copy(struct pax_meta *dst, const struct pax_meta *src){
    pax_meta_free(dst);
    if(src->path){ dst->path = strdup(src->path); if(!dst->path) return -1; }
    if(src->linkpath){ dst->linkpath = strdup(src->linkpath); if(!dst->linkpath) return -1; }
    dst->size = src->size; dst->mtime = src->mtime;
    dst->has_size = src->has_size; dst->has_mtime = src->has_mtime;
    dst->typeflag = src->typeflag;
    return 0;
}

static int pax_parse_decimal_ulong(const char *s, unsigned long *out){
    char *e; errno = 0; unsigned long v = strtoul(s, &e, 10);
    if(errno || e == s || (*e && *e != '\n')) return -1;
    *out = v; return 0;
}

static int pax_parse_time(const char *s, time_t *out){
    char *e; errno = 0; double v = strtod(s, &e);
    if(errno || e == s || (*e && *e != '\n')) return -1;
    *out = (time_t)v; return 0;
}

static int pax_set_string(char **dst, const char *val, size_t n){
    char *p = malloc(n + 1);
    if(!p) return -1;
    memcpy(p, val, n); p[n] = 0;
    free(*dst); *dst = p; return 0;
}

static int pax_parse_records(const char *body, size_t len, struct pax_meta *m){
    size_t pos = 0;
    while(pos < len && body[pos]){
        char *e; errno = 0; unsigned long reclen = strtoul(body + pos, &e, 10);
        if(errno || e == body + pos || *e != ' ' || reclen == 0 || pos + reclen > len){
            builtin_error("malformed pax extended header record");
            return -1;
        }
        char *line = (char *)body + pos;
        char *kv = e + 1;
        char *nl = line + reclen - 1;
        if(*nl != '\n'){
            builtin_error("malformed pax extended header record: missing newline");
            return -1;
        }
        char *eq = memchr(kv, '=', (size_t)(nl - kv));
        if(eq){
            size_t klen = (size_t)(eq - kv), vlen = (size_t)(nl - eq - 1);
            const char *val = eq + 1;
            if(klen == 4 && !memcmp(kv, "path", 4)){
                if(pax_set_string(&m->path, val, vlen) < 0) return -1;
            } else if(klen == 8 && !memcmp(kv, "linkpath", 8)){
                if(pax_set_string(&m->linkpath, val, vlen) < 0) return -1;
            } else if(klen == 4 && !memcmp(kv, "size", 4)){
                char tmp[64]; if(vlen >= sizeof tmp) return -1;
                memcpy(tmp, val, vlen); tmp[vlen] = 0;
                if(pax_parse_decimal_ulong(tmp, &m->size) < 0) return -1;
                m->has_size = 1;
            } else if(klen == 5 && !memcmp(kv, "mtime", 5)){
                char tmp[64]; if(vlen >= sizeof tmp) return -1;
                memcpy(tmp, val, vlen); tmp[vlen] = 0;
                if(pax_parse_time(tmp, &m->mtime) < 0) return -1;
                m->has_mtime = 1;
            } else if(klen == 8 && !memcmp(kv, "typeflag", 8) && vlen){
                m->typeflag = (unsigned char)val[0];
            }
        }
        pos += reclen;
    }
    return 0;
}

static void trim_gnu_long_body(char *body, unsigned long sz){
    while(sz > 0 && (body[sz - 1] == '\0' || body[sz - 1] == '\n'))
        body[--sz] = '\0';
}

static int read_padded_body(FILE *f, unsigned long sz, char **out){
    char *body = calloc(sz + 1, 1);
    if(!body) return -1;
    if(sz && fread(body, 1, sz, f) != sz){ free(body); return -1; }
    unsigned long pad = (512 - (sz % 512)) % 512;
    if(pad && skip_bytes(f, pad) < 0){ free(body); return -1; }
    *out = body; return 0;
}

/* Create any missing parent directories of path (think mkdir -p). */
static int mkpath_parents(const char *path, mode_t dir_mode){
    char buf[512]; size_t n = strlen(path);
    if(n >= sizeof buf) return -1;
    memcpy(buf, path, n+1);
    for(char *p = buf+1; *p; p++){
        if(*p == '/'){ *p = 0;
            if(mkdir(buf, dir_mode) < 0 && errno != EEXIST) return -1;
            *p = '/'; }
    }
    return 0;
}

static int set_mtime(const char *path, time_t mtime, int is_symlink){
    struct timespec ts[2];
    ts[0].tv_sec = 0; ts[0].tv_nsec = UTIME_OMIT;
    ts[1].tv_sec = mtime; ts[1].tv_nsec = 0;
    return utimensat(AT_FDCWD, path, ts, is_symlink ? AT_SYMLINK_NOFOLLOW : 0);
}

static int pax_list_extract(const char *archive, int extract, int verbose){
    FILE *f = archive ? fopen(archive,"rb") : stdin;
    if(!f){ builtin_error("%s: %s", archive?archive:"(stdin)", strerror(errno)); return EXECUTION_FAILURE; }
    unsigned char h[512]; int rc=EXECUTION_SUCCESS; int zero_seen=0;
    struct pax_meta global = {0}, local = {0};
    while(1){
        size_t got = fread(h,1,512,f);
        if(got == 0){
            if(!zero_seen){ builtin_error("archive truncated: no end-of-archive marker"); rc = EXECUTION_FAILURE; }
            break;
        }
        if(got != 512){ builtin_error("archive truncated: short header read (%zu of 512)", got); rc = EXECUTION_FAILURE; break; }
        if(zero_block(h)){ zero_seen = 1; break; }
        if(memcmp(h+257,"ustar",5)){ builtin_error("bad ustar magic"); rc=EXECUTION_FAILURE; break; }
        if(!hdr_checksum_ok(h)){ builtin_error("bad ustar header checksum"); rc=EXECUTION_FAILURE; break; }

        char hdrname[257]; name_from_hdr(hdrname, h);
        unsigned long sz = octal((char*)h+124,12);
        unsigned mode = octal((char*)h+100,8);
        time_t mtime = (time_t)octal((char*)h+136, 12);
        int typeflag = h[156] ? h[156] : '0';
        char linkname[101]; memcpy(linkname, h+157, 100); linkname[100]=0;
        long body_padded = ((long)sz+511L)/512L*512L;
        int has_body = (typeflag=='0' || typeflag=='\0' || typeflag=='7');

        if(typeflag == 'x' || typeflag == 'g'){
            char *body = NULL;
            if(read_padded_body(f, sz, &body) < 0){
                builtin_error("%s: archive truncated in pax extended header", hdrname);
                rc = EXECUTION_FAILURE; break;
            }
            struct pax_meta *target = typeflag == 'g' ? &global : &local;
            if(typeflag == 'x') pax_meta_free(&local);
            if(pax_parse_records(body, (size_t)sz, target) < 0) rc = EXECUTION_FAILURE;
            free(body);
            continue;
        }
        if(typeflag == 'L' || typeflag == 'K'){
            char *body = NULL;
            if(read_padded_body(f, sz, &body) < 0){
                builtin_error("%s: archive truncated in GNU extended header", hdrname);
                rc = EXECUTION_FAILURE; break;
            }
            trim_gnu_long_body(body, sz);
            if(typeflag == 'L'){
                pax_meta_free(&local);
                if(pax_set_string(&local.path, body, strlen(body)) < 0) rc = EXECUTION_FAILURE;
            } else {
                if(pax_set_string(&local.linkpath, body, strlen(body)) < 0) rc = EXECUTION_FAILURE;
            }
            free(body);
            continue;
        }

        struct pax_meta eff = {0};
        if(pax_meta_copy(&eff, &global) < 0){ rc = EXECUTION_FAILURE; break; }
        if(local.path){ free(eff.path); eff.path = local.path; local.path = NULL; }
        if(local.linkpath){ free(eff.linkpath); eff.linkpath = local.linkpath; local.linkpath = NULL; }
        if(local.has_size){ eff.size = local.size; eff.has_size = 1; }
        if(local.has_mtime){ eff.mtime = local.mtime; eff.has_mtime = 1; }
        if(local.typeflag) eff.typeflag = local.typeflag;
        pax_meta_free(&local);

        const char *name = eff.path ? eff.path : hdrname;
        const char *ln = eff.linkpath ? eff.linkpath : linkname;
        if(eff.has_size){ if(eff.size > (unsigned long)LONG_MAX - 1024UL){ builtin_error("%s: member size out of range", name); rc = EXECUTION_FAILURE; pax_meta_free(&eff); break; }
            sz = eff.size; body_padded = ((long)sz+511L)/512L*512L; has_body = (typeflag=='0' || typeflag=='\0' || typeflag=='7'); }
        if(eff.has_mtime) mtime = eff.mtime;
        if(eff.typeflag){ typeflag = eff.typeflag; has_body = (typeflag=='0' || typeflag=='\0' || typeflag=='7'); }

        if(!extract){
            if(verbose) printf("%c %06o %lu %s\n", typeflag, mode, sz, name);
            else printf("%s\n", name);
            if(has_body) skip_bytes(f, body_padded);
            pax_meta_free(&eff);
            continue;
        }

        if(unsafe_path(name)){
            builtin_error("%s: unsafe archive path", name); rc = EXECUTION_FAILURE;
            if(has_body) skip_bytes(f, body_padded);
            pax_meta_free(&eff);
            continue;
        }

        switch(typeflag){
        case '5': {  /* directory */
            if(mkpath_parents(name, 0755) < 0){
                builtin_error("%s: mkdir parent: %s", name, strerror(errno)); rc = EXECUTION_FAILURE; break;
            }
            if(mkdir(name, mode & 0777) < 0 && errno != EEXIST){
                builtin_error("%s: %s", name, strerror(errno)); rc = EXECUTION_FAILURE; break;
            }
            set_mtime(name, mtime, 0);
            break;
        }
        case '2': {  /* symlink */
            if(ln[0]==0 || ln[0]=='/' || unsafe_path(ln)){
                builtin_error("%s: unsafe or empty symlink target '%s'", name, ln); rc = EXECUTION_FAILURE; break;
            }
            mkpath_parents(name, 0755);
            unlink(name);
            if(symlink(ln, name) < 0){
                builtin_error("%s: symlink: %s", name, strerror(errno)); rc = EXECUTION_FAILURE; break;
            }
            set_mtime(name, mtime, 1);
            break;
        }
        case '1': {  /* hardlink */
            if(ln[0]==0 || ln[0]=='/' || unsafe_path(ln)){
                builtin_error("%s: unsafe or empty hardlink target '%s'", name, ln); rc = EXECUTION_FAILURE; break;
            }
            mkpath_parents(name, 0755);
            unlink(name);
            if(link(ln, name) < 0){
                builtin_error("%s: link to %s: %s", name, ln, strerror(errno)); rc = EXECUTION_FAILURE; break;
            }
            break;
        }
        case '3': case '4': case '6':
            builtin_error("%s: unsupported typeflag '%c' (device/fifo)", name, typeflag);
            rc = EXECUTION_FAILURE;
            break;
        case 'x': case 'g':
            builtin_error("%s: extended header typeflag '%c' not supported", name, typeflag);
            rc = EXECUTION_FAILURE;
            skip_bytes(f, body_padded);
            break;
        case '0': case '\0': case '7':
        default: {
            mkpath_parents(name, 0755);
            if(unlink(name) < 0 && errno != ENOENT && errno != EISDIR){
                builtin_error("%s: %s", name, strerror(errno)); rc = EXECUTION_FAILURE;
                skip_bytes(f, body_padded); break;
            }
            FILE *o = fopen(name, "wb");
            if(!o){
                builtin_error("%s: %s", name, strerror(errno)); rc = EXECUTION_FAILURE;
                skip_bytes(f, body_padded); break;
            }
            unsigned long left = sz; unsigned char buf[4096]; int short_body = 0;
            while(left){
                size_t want = left > sizeof buf ? sizeof buf : (size_t)left;
                size_t n = fread(buf,1,want,f);
                if(n==0){ short_body = 1; break; }
                fwrite(buf,1,n,o); left -= n;
            }
            fclose(o);
            if(short_body){ builtin_error("%s: archive truncated in member body", name); rc = EXECUTION_FAILURE; break; }
            chmod(name, mode & 0777);
            set_mtime(name, mtime, 0);
            unsigned long pad = (512 - (sz % 512)) % 512;
            if(pad) skip_bytes(f, pad);
            break;
        }
        }
        pax_meta_free(&eff);
    }
    pax_meta_free(&global); pax_meta_free(&local);
    if(f != stdin) fclose(f);
    return rc;
}

/* Build a ustar header for `path` and write it. Body bytes (regular
   files only) are written by the caller. */
static int write_header(FILE *out, const char *path, const struct stat *st, char typeflag, const char *linktarget){
    unsigned char h[512]; memset(h, 0, sizeof h);
    const char *base = path;
    size_t plen = strlen(path);
    if(plen > 100){
        const char *slash = strrchr(path, '/');
        if(slash && strlen(slash+1) <= 100){
            size_t pl = slash - path;
            if(pl > 155){ builtin_error("%s: name too long for ustar (prefix > 155)", path); return -1; }
            memcpy(h+345, path, pl);
            base = slash + 1;
        } else {
            builtin_error("%s: name too long for ustar (no split point fitting 100/155)", path); return -1;
        }
    }
    size_t blen = strlen(base);
    memcpy(h, base, blen > 100 ? 100 : blen);

    unsigned long body_size = (typeflag=='0' || typeflag=='x' || typeflag=='g') ? (unsigned long)st->st_size : 0UL;
    put_octal((char*)h+100, 8, (unsigned long)(st->st_mode & 07777));
    put_octal((char*)h+108, 8, (unsigned long)st->st_uid);
    put_octal((char*)h+116, 8, (unsigned long)st->st_gid);
    put_octal((char*)h+124, 12, body_size);
    put_octal((char*)h+136, 12, (unsigned long)st->st_mtime);
    memset(h+148, ' ', 8);
    h[156] = typeflag;
    if(linktarget && (typeflag=='2' || typeflag=='1')){
        size_t llen = strlen(linktarget);
        if(llen > 100){ builtin_error("%s: link target too long for ustar (>100)", path); return -1; }
        memcpy(h+157, linktarget, llen);
    }
    memcpy(h+257, "ustar", 6); memcpy(h+263, "00", 2);
    unsigned sum = 0; for(int i=0;i<512;i++) sum += h[i];
    snprintf((char*)h+148, 8, "%06o", sum); h[154]='\0'; h[155]=' ';
    fwrite(h, 1, 512, out);
    return 0;
}

static int append_bytes(char **buf, size_t *len, size_t *cap, const char *s, size_t n){
    if(*len + n + 1 > *cap){
        size_t nc = *cap ? *cap * 2 : 128;
        while(nc < *len + n + 1) nc *= 2;
        char *p = realloc(*buf, nc);
        if(!p) return -1;
        *buf = p; *cap = nc;
    }
    memcpy(*buf + *len, s, n);
    *len += n; (*buf)[*len] = 0;
    return 0;
}

static int append_pax_record(char **buf, size_t *len, size_t *cap, const char *key, const char *val){
    size_t kvlen = strlen(key) + 1 + strlen(val) + 1;
    char tmp[64];
    int digits = 1, reclen;
    do {
        reclen = digits + 1 + (int)kvlen;
        snprintf(tmp, sizeof tmp, "%d", reclen);
        digits = (int)strlen(tmp);
    } while(reclen != digits + 1 + (int)kvlen);
    if(append_bytes(buf, len, cap, tmp, strlen(tmp)) < 0) return -1;
    if(append_bytes(buf, len, cap, " ", 1) < 0) return -1;
    if(append_bytes(buf, len, cap, key, strlen(key)) < 0) return -1;
    if(append_bytes(buf, len, cap, "=", 1) < 0) return -1;
    if(append_bytes(buf, len, cap, val, strlen(val)) < 0) return -1;
    return append_bytes(buf, len, cap, "\n", 1);
}

static const char *pax_fallback_name(const char *path){
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    return *b && strlen(b) <= 100 ? b : "pax-member";
}

static int ustar_name_ok(const char *path){
    size_t plen = strlen(path);
    if(plen <= 100) return 1;
    const char *slash = strrchr(path, '/');
    return slash && strlen(slash + 1) <= 100 && (size_t)(slash - path) <= 155;
}

/* Emit a PAX extended header ('x') for the records the ustar header cannot
   hold: the path when want_path, the link target when given, and each numeric
   field flagged in numext. name is the member's path, used to name the header. */
static int write_pax_ext(FILE *out, const char *name, int want_path, const char *linktarget, const struct stat *st, int numext){
    char *body = NULL; size_t len = 0, cap = 0; char num[32];
    if(want_path && append_pax_record(&body, &len, &cap, "path", name) < 0){ free(body); return -1; }
    if(linktarget && append_pax_record(&body, &len, &cap, "linkpath", linktarget) < 0){ free(body); return -1; }
    if(numext & PAX_EXT_SIZE){ snprintf(num, sizeof num, "%llu", (unsigned long long)st->st_size); if(append_pax_record(&body, &len, &cap, "size", num) < 0){ free(body); return -1; } }
    if(numext & PAX_EXT_UID){ snprintf(num, sizeof num, "%lu", (unsigned long)st->st_uid); if(append_pax_record(&body, &len, &cap, "uid", num) < 0){ free(body); return -1; } }
    if(numext & PAX_EXT_GID){ snprintf(num, sizeof num, "%lu", (unsigned long)st->st_gid); if(append_pax_record(&body, &len, &cap, "gid", num) < 0){ free(body); return -1; } }
    if(!body) return 0;
    struct stat xst = *st;
    xst.st_mode = 0644;
    xst.st_size = (off_t)len;
    xst.st_uid = 0; xst.st_gid = 0;           /* the header record itself must fit ustar */
    char xname[160];
    snprintf(xname, sizeof xname, "PaxHeaders/%.88s", pax_fallback_name(name));
    if(write_header(out, xname, &xst, 'x', NULL) < 0){ free(body); return -1; }
    fwrite(body, 1, len, out);
    long pad = (512 - ((long)len % 512)) % 512;
    for(long i = 0; i < pad; i++) fputc(0, out);
    free(body);
    return 0;
}

/* path_join3 is defined later; forward-declare it for the directory recursion
   in write_member below. */
static int path_join3(char *out, size_t outsz, const char *a, const char *b);

/* -d (POSIX pax "do not descend directories"); reset per invocation in
   pax_builtin. When 0 (default), write_member recurses into directories
   so `pax -w .` archives the full tree like GNU tar. */
static int bp_no_recurse = 0;

static int write_member(FILE *out, const char *path){
    struct stat st;
    if(lstat(path, &st) < 0){ builtin_error("%s: %s", path, strerror(errno)); return 1; }

    const char *stored_path = ustar_name_ok(path) ? path : pax_fallback_name(path);
    int need_path_ext = !ustar_name_ok(path);

    int numext = pax_numeric_ext(&st, S_ISREG(st.st_mode));

    if(S_ISDIR(st.st_mode)){
        if((need_path_ext || numext) && write_pax_ext(out, path, need_path_ext, NULL, &st, numext) < 0) return 1;
        if(write_header(out, stored_path, &st, '5', NULL) < 0) return 1;
        if(bp_no_recurse) return 0;
        DIR *d = opendir(path);
        if(!d){ builtin_error("%s: %s", path, strerror(errno)); return 1; }
        int rc = 0; struct dirent *de;
        while((de = readdir(d)) != NULL){
            if(!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
            char child[1024];
            if(path_join3(child, sizeof child, path, de->d_name) < 0){ builtin_error("%s/%s: path too long", path, de->d_name); rc = 1; continue; }
            rc |= write_member(out, child);
        }
        closedir(d);
        return rc;
    }
    if(S_ISLNK(st.st_mode)){
        char tgt[1024] = {0};
        ssize_t r = readlink(path, tgt, sizeof tgt - 1);
        if(r < 0){ builtin_error("%s: readlink: %s", path, strerror(errno)); return 1; }
        tgt[r] = 0;
        int need_link_ext = strlen(tgt) > 100;
        if((need_path_ext || need_link_ext || numext) && write_pax_ext(out, path, need_path_ext, need_link_ext ? tgt : NULL, &st, numext) < 0) return 1;
        return write_header(out, stored_path, &st, '2', need_link_ext ? "" : tgt) < 0 ? 1 : 0;
    }
    if(!S_ISREG(st.st_mode)){
        builtin_error("%s: unsupported file type for ustar", path); return 1;
    }

    if((need_path_ext || numext) && write_pax_ext(out, path, need_path_ext, NULL, &st, numext) < 0) return 1;
    if(write_header(out, stored_path, &st, '0', NULL) < 0) return 1;
    FILE *in = fopen(path, "rb");
    if(!in){ builtin_error("%s: %s", path, strerror(errno)); return 1; }
    unsigned char buf[4096]; size_t r;
    while((r = fread(buf, 1, sizeof buf, in)) > 0) fwrite(buf, 1, r, out);
    fclose(in);
    long pad = (512 - ((long)st.st_size % 512)) % 512;
    for(long i = 0; i < pad; i++) fputc(0, out);
    return 0;
}

static int pax_write(const char *archive, WORD_LIST *files){
    FILE *out = archive ? fopen(archive,"wb") : stdout;
    if(!out){ builtin_error("%s: %s", archive, strerror(errno)); return EXECUTION_FAILURE; }
    int rc = 0;
    for(; files; files = files->next) rc |= write_member(out, files->word->word);
    unsigned char z[1024]; memset(z, 0, sizeof z);
    fwrite(z, 1, sizeof z, out);
    if(out != stdout) fclose(out);
    return rc ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int copy_file_bytes(const char *src, const char *dst, const struct stat *st){
    FILE *in = fopen(src, "rb");
    if(!in){ builtin_error("%s: %s", src, strerror(errno)); return 1; }
    mkpath_parents(dst, 0755);
    FILE *out = fopen(dst, "wb");
    if(!out){ builtin_error("%s: %s", dst, strerror(errno)); fclose(in); return 1; }
    unsigned char buf[8192]; size_t n; int rc = 0;
    while((n = fread(buf, 1, sizeof buf, in)) > 0){
        if(fwrite(buf, 1, n, out) != n){ builtin_error("%s: write: %s", dst, strerror(errno)); rc = 1; break; }
    }
    if(ferror(in)){ builtin_error("%s: read: %s", src, strerror(errno)); rc = 1; }
    fclose(in);
    if(fclose(out) != 0){ builtin_error("%s: close: %s", dst, strerror(errno)); rc = 1; }
    if(!rc){
        chmod(dst, st->st_mode & 0777);
        set_mtime(dst, st->st_mtime, 0);
    }
    return rc;
}

static int path_join3(char *out, size_t outsz, const char *a, const char *b){
    size_t al = strlen(a);
    int slash = (al && a[al-1] != '/');
    return snprintf(out, outsz, "%s%s%s", a, slash ? "/" : "", b) < (int)outsz ? 0 : -1;
}

static int copy_tree(const char *src, const char *dstroot){
    if(unsafe_path(src)){ builtin_error("%s: unsafe copy-mode path", src); return 1; }
    char dst[1024];
    if(path_join3(dst, sizeof dst, dstroot, src) < 0){ builtin_error("%s: destination path too long", src); return 1; }

    struct stat st;
    if(lstat(src, &st) < 0){ builtin_error("%s: %s", src, strerror(errno)); return 1; }
    if(S_ISDIR(st.st_mode)){
        if(mkpath_parents(dst, 0755) < 0){ builtin_error("%s: mkdir parent: %s", dst, strerror(errno)); return 1; }
        if(mkdir(dst, st.st_mode & 0777) < 0 && errno != EEXIST){ builtin_error("%s: %s", dst, strerror(errno)); return 1; }
        DIR *d = opendir(src);
        if(!d){ builtin_error("%s: %s", src, strerror(errno)); return 1; }
        int rc = 0; struct dirent *de;
        while((de = readdir(d)) != NULL){
            if(!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
            char child[1024];
            if(path_join3(child, sizeof child, src, de->d_name) < 0){ builtin_error("%s/%s: path too long", src, de->d_name); rc = 1; continue; }
            rc |= copy_tree(child, dstroot);
        }
        closedir(d);
        set_mtime(dst, st.st_mtime, 0);
        return rc;
    }
    if(S_ISLNK(st.st_mode)){
        char tgt[512];
        ssize_t r = readlink(src, tgt, sizeof tgt - 1);
        if(r < 0){ builtin_error("%s: readlink: %s", src, strerror(errno)); return 1; }
        tgt[r] = 0;
        if(tgt[0] == '/' || unsafe_path(tgt)){ builtin_error("%s: unsafe symlink target '%s'", src, tgt); return 1; }
        mkpath_parents(dst, 0755);
        unlink(dst);
        if(symlink(tgt, dst) < 0){ builtin_error("%s: symlink: %s", dst, strerror(errno)); return 1; }
        set_mtime(dst, st.st_mtime, 1);
        return 0;
    }
    if(S_ISREG(st.st_mode)) return copy_file_bytes(src, dst, &st);
    builtin_error("%s: unsupported file type for copy mode", src);
    return 1;
}

static int pax_copy(WORD_LIST *files){
    int count = 0;
    WORD_LIST *last = NULL;
    for(WORD_LIST *p = files; p; p = p->next){ count++; last = p; }
    if(count < 2){ builtin_error("-rw copy mode needs FILE... DIRECTORY"); return EX_USAGE; }
    const char *dstroot = last->word->word;
    struct stat dstst;
    if(stat(dstroot, &dstst) < 0 || !S_ISDIR(dstst.st_mode)){
        builtin_error("%s: destination is not a directory", dstroot);
        return EXECUTION_FAILURE;
    }
    int rc = 0;
    for(WORD_LIST *p = files; p && p != last; p = p->next)
        rc |= copy_tree(p->word->word, dstroot);
    return rc ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

int pax_builtin(WORD_LIST *list){
    int mode=0, verbose=0; const char *archive=NULL; WORD_LIST *files=NULL;
    bp_no_recurse=0;
    while(list){
        char *w=list->word->word;
        if(!strcmp(w,"-v")) verbose=1;
        else if(!strcmp(w,"-d")) bp_no_recurse=1;
        else if(!strcmp(w,"-f")){
            if(!list->next){ builtin_error("-f needs archive"); return EX_USAGE; }
            list=list->next; archive=list->word->word;
        }
        else if(!strcmp(w,"-w")) mode=1;
        else if(!strcmp(w,"-r")) mode=2;
        else if(!strcmp(w,"-rw")||!strcmp(w,"-wr")) mode=3;
        else { files=list; break; }
        list=list->next;
    }
    if(mode==1) return pax_write(archive,files);
    if(mode==2) return pax_list_extract(archive,1,verbose);
    if(mode==3) return pax_copy(files);
    return pax_list_extract(archive,0,verbose);
}

char *pax_doc[] = {
    "POSIX pax ustar subset: list, -w create, -r extract, -rw copy.",
    "    bashpax [-v] [-f ARCHIVE] | bashpax -w -f ARCHIVE FILE... | bashpax -r -f ARCHIVE | bashpax -rw FILE... DIR",
    (char*)NULL
};
struct builtin bashpax_struct = {"bashpax",pax_builtin,BUILTIN_ENABLED,pax_doc,"bashpax [-r|-w] [-v] [-f ARCHIVE] [FILE...]",0};
struct builtin pax_struct    = {"pax",   pax_builtin,BUILTIN_ENABLED,pax_doc,"pax [-r|-w] [-v] [-f ARCHIVE] [FILE...]",0};
