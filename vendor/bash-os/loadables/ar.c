/* SPDX-License-Identifier: MIT */
/* ar.c - small ar(1) archive loadable.
 *
 * D06 archive-format expansion: deterministic writes by default (matches
 * `binutils ar -D`: zero uid/gid/mtime, mode normalized to 0644/0755),
 * with `-U` to opt back into real metadata; GNU long-name strtab (`//`
 * member with `/NN` offsets) supported on read; symbol-table `/` member
 * skipped on read; `fmag` magic at offset 58 validated on every header
 * to catch corrupt/truncated archives before they cause garbage output.
 * A `/N` long-name reference whose offset falls outside the loaded `//`
 * strtab (or whose archive contains no strtab at all) is rejected with a
 * clear diagnostic rather than silently degrading to an empty filename.
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include "loadables.h"

#define AR_MAGIC      "!<arch>\n"
#define AR_MAGIC_LEN  8
#define AR_FMAG       "`\n"

struct ar_hdr { char name[16], mtime[12], uid[6], gid[6], mode[8], size[10], fmag[2]; };

struct ar_member {
    struct ar_hdr h;
    unsigned char *data;
    long size;
};

struct ar_symbol {
    char *name;
    size_t member_index;
};

struct ar_symvec {
    struct ar_symbol *v;
    size_t n;
    size_t cap;
};

/* Parse a right-padded decimal field into a long. */
static long decfield(const char *s, size_t n) {
    char b[32]; if (n >= sizeof b) n = sizeof b - 1;
    memcpy(b, s, n); b[n]=0;
    while(n>0 && (b[n-1]==' '||b[n-1]==0)){ b[n-1]=0; n--; }
    return strtol(b, NULL, 10);
}
/* Trim a 16-byte name field at the first '/' or space. */
static void clean_name(char *dst, const char *src) {
    size_t n=0; while(n<16 && src[n] && src[n]!=' ' && src[n]!='/') { dst[n]=src[n]; n++; } dst[n]=0;
}
static int check_magic(FILE *f) { char m[AR_MAGIC_LEN]; rewind(f); return fread(m,1,AR_MAGIC_LEN,f)==AR_MAGIC_LEN && !memcmp(m,AR_MAGIC,AR_MAGIC_LEN); }

static uint16_t rd16(const unsigned char *p, int le) {
    if (le) return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
static uint32_t rd32(const unsigned char *p, int le) {
    if (le) return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static uint64_t rd64(const unsigned char *p, int le) {
    if (le) return (uint64_t)rd32(p, 1) | ((uint64_t)rd32(p + 4, 1) << 32);
    return ((uint64_t)rd32(p, 0) << 32) | (uint64_t)rd32(p + 4, 0);
}
static void wr32be(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)((v >> 24) & 0xff);
    p[1] = (unsigned char)((v >> 16) & 0xff);
    p[2] = (unsigned char)((v >> 8) & 0xff);
    p[3] = (unsigned char)(v & 0xff);
}

static int symvec_add(struct ar_symvec *sv, const char *name, size_t member_index) {
    char *copy;
    if (!name || !*name) return 0;
    if (sv->n == sv->cap) {
        size_t nc = sv->cap ? sv->cap * 2 : 16;
        struct ar_symbol *nv = realloc(sv->v, nc * sizeof(*nv));
        if (!nv) return -1;
        sv->v = nv;
        sv->cap = nc;
    }
    copy = strdup(name);
    if (!copy) return -1;
    sv->v[sv->n].name = copy;
    sv->v[sv->n].member_index = member_index;
    sv->n++;
    return 0;
}

static void symvec_free(struct ar_symvec *sv) {
    if (!sv) return;
    for (size_t i = 0; i < sv->n; i++) free(sv->v[i].name);
    free(sv->v);
    sv->v = NULL; sv->n = sv->cap = 0;
}

static int member_is_symtab(const struct ar_hdr *h) {
    return h->name[0]=='/' && (h->name[1]==' ' || h->name[1]==0);
}

static int member_is_strtab(const struct ar_hdr *h) {
    return h->name[0]=='/' && h->name[1]=='/';
}

static int elf_collect_symbols(const unsigned char *data, size_t len,
                               size_t member_index, struct ar_symvec *sv) {
    int cls, le;
    uint64_t shoff;
    uint16_t shentsize, shnum;
    if (len < 16 || data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F')
        return 0;
    cls = data[4];
    le = (data[5] == 1);
    if ((cls != 1 && cls != 2) || (data[5] != 1 && data[5] != 2)) return 0;
    if (cls == 1) {
        if (len < 52) return 0;
        shoff = rd32(data + 32, le);
        shentsize = rd16(data + 46, le);
        shnum = rd16(data + 48, le);
    } else {
        if (len < 64) return 0;
        shoff = rd64(data + 40, le);
        shentsize = rd16(data + 58, le);
        shnum = rd16(data + 60, le);
    }
    if (shentsize == 0 || shnum == 0 || shoff > len) return 0;
    if (shoff + (uint64_t)shentsize * shnum > len) return 0;

    for (uint16_t si = 0; si < shnum; si++) {
        const unsigned char *sh = data + shoff + (uint64_t)si * shentsize;
        uint32_t type, link;
        uint64_t off, size, entsize;
        if (cls == 1) {
            if (shentsize < 40) continue;
            type = rd32(sh + 4, le);
            off = rd32(sh + 16, le);
            size = rd32(sh + 20, le);
            link = rd32(sh + 24, le);
            entsize = rd32(sh + 36, le);
        } else {
            if (shentsize < 64) continue;
            type = rd32(sh + 4, le);
            link = rd32(sh + 40, le);
            off = rd64(sh + 24, le);
            size = rd64(sh + 32, le);
            entsize = rd64(sh + 56, le);
        }
        if (type != 2 || entsize == 0 || link >= shnum) continue; /* SHT_SYMTAB */
        if (off > len || size > len || off + size > len) continue;

        const unsigned char *strsh = data + shoff + (uint64_t)link * shentsize;
        uint64_t stroff, strsize;
        if (cls == 1) {
            if (shentsize < 40) continue;
            stroff = rd32(strsh + 16, le);
            strsize = rd32(strsh + 20, le);
        } else {
            if (shentsize < 64) continue;
            stroff = rd64(strsh + 24, le);
            strsize = rd64(strsh + 32, le);
        }
        if (stroff > len || strsize > len || stroff + strsize > len) continue;
        const char *strtab = (const char *)(data + stroff);
        size_t nsyms = (size_t)(size / entsize);
        for (size_t j = 0; j < nsyms; j++) {
            const unsigned char *sym = data + off + (uint64_t)j * entsize;
            uint32_t name;
            unsigned char info;
            uint16_t shndx;
            if (cls == 1) {
                if (entsize < 16) continue;
                name = rd32(sym, le);
                info = sym[12];
                shndx = rd16(sym + 14, le);
            } else {
                if (entsize < 24) continue;
                name = rd32(sym, le);
                info = sym[4];
                shndx = rd16(sym + 6, le);
            }
            unsigned bind = info >> 4;
            if ((bind == 1 || bind == 2) && shndx != 0 && name < strsize) {
                const char *sname = strtab + name;
                if (memchr(sname, '\0', (size_t)strsize - name) &&
                    symvec_add(sv, sname, member_index) < 0)
                    return -1;
            }
        }
    }
    return 0;
}

/* GNU strtab lookup: long name starts at `off` and ends at the first
   '/' or '\n'. Returns 0 on success, -1 if off is out of bounds for the
   provided strtab (corrupt /N reference). */
static int longname_from_strtab(char *dst, size_t dstn, long off, const char *strtab, size_t tablen){
    if(off < 0 || (size_t)off >= tablen){ if(dstn) dst[0]=0; return -1; }
    size_t i=0; size_t j=(size_t)off;
    while(j<tablen && i+1<dstn && strtab[j]!='/' && strtab[j]!='\n'){ dst[i++]=strtab[j++]; }
    dst[i]=0;
    return 0;
}

static int list_or_extract(const char *arch, int extract, WORD_LIST *want) {
    FILE *f = fopen(arch, "rb"); if (!f) { builtin_error("%s: %s", arch, strerror(errno)); return EXECUTION_FAILURE; }
    if (!check_magic(f)) { builtin_error("%s: bad ar magic", arch); fclose(f); return EXECUTION_FAILURE; }
    struct ar_hdr h; int rc = EXECUTION_SUCCESS;
    char *strtab = NULL; size_t strtab_len = 0;
    for (;;) {
        size_t nr = fread(&h,1,sizeof h,f);
        if (nr == 0) {
            if (ferror(f)) { builtin_error("%s: read error", arch); rc = EXECUTION_FAILURE; }
            break;
        }
        if (nr != sizeof h) {
            builtin_error("%s: file format not recognized", arch);
            rc = EXECUTION_FAILURE; break;
        }
        if(memcmp(h.fmag, AR_FMAG, 2)){
            builtin_error("%s: file format not recognized", arch);
            rc = EXECUTION_FAILURE; break;
        }
        long sz = decfield(h.size, sizeof h.size);
        if(sz < 0){ builtin_error("%s: corrupt ar header (bad size)", arch); rc = EXECUTION_FAILURE; break; }

        /* GNU strtab member: header name "//" */
        if(h.name[0]=='/' && h.name[1]=='/'){
            free(strtab);
            strtab = (char *)malloc((size_t)sz + 1);
            if(!strtab){ builtin_error("out of memory"); rc=EXECUTION_FAILURE; break; }
            if(fread(strtab,1,sz,f) != (size_t)sz){
                builtin_error("%s: short read on strtab", arch);
                free(strtab); strtab=NULL; rc=EXECUTION_FAILURE; break;
            }
            strtab_len = (size_t)sz;
            if(sz & 1) fseek(f, 1, SEEK_CUR);
            continue;
        }
        /* Symbol table member: header name "/" (single slash followed by spaces) */
        if(h.name[0]=='/' && (h.name[1]==' '||h.name[1]==0)){
            fseek(f, sz + (sz & 1), SEEK_CUR);
            continue;
        }

        char name[256];
        if(h.name[0]=='/' && h.name[1]>='0' && h.name[1]<='9'){
            char numbuf[16]; size_t k=0;
            for(size_t i=1; i<16 && h.name[i]>='0' && h.name[i]<='9'; i++) numbuf[k++]=h.name[i];
            numbuf[k]=0;
            long off = strtol(numbuf, NULL, 10);
            if(!strtab){
                builtin_error("%s: long-name /N reference without `//` strtab", arch);
                rc = EXECUTION_FAILURE; break;
            }
            if(longname_from_strtab(name, sizeof name, off, strtab, strtab_len) < 0){
                builtin_error("%s: corrupt strtab reference (offset %ld, strtab size %zu)",
                              arch, off, strtab_len);
                rc = EXECUTION_FAILURE; break;
            }
        } else {
            clean_name(name, h.name);
        }

        int ok = !want;
        for (WORD_LIST *p=want; p; p=p->next) if (!strcmp(p->word->word, name)) ok=1;
        if (extract && ok) {
            /* Read the whole member before creating/truncating the dest so a
               short body cannot leave a truncated regular file. Check fwrite
               and fclose: fputc to /dev/full used to report success. */
            unsigned char *buf = NULL;
            if (sz > 0) {
                buf = malloc((size_t)sz);
                if (!buf) { builtin_error("out of memory"); rc=EXECUTION_FAILURE; break; }
                if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
                    builtin_error("%s: file format not recognized", arch);
                    free(buf); rc=EXECUTION_FAILURE; break;
                }
            }
            FILE *o = fopen(name, "wb");
            if (!o) {
                builtin_error("%s: %s", name, strerror(errno));
                rc = EXECUTION_FAILURE;
            } else {
                int wr_fail = 0;
                int saved = 0;
                if (sz > 0 && (fwrite(buf, 1, (size_t)sz, o) != (size_t)sz || ferror(o))) {
                    wr_fail = 1;
                    saved = errno;
                }
                if (fclose(o) != 0 && !wr_fail) {
                    wr_fail = 1;
                    saved = errno;
                }
                if (wr_fail) {
                    builtin_error("%s: %s", name, saved ? strerror(saved) : "write error");
                    unlink(name);
                    rc = EXECUTION_FAILURE;
                }
            }
            free(buf);
        } else {
            if (!extract && ok) printf("%s\n", name);
            if (sz > 0) fseek(f, sz, SEEK_CUR);
        }
        if (sz & 1) fseek(f, 1, SEEK_CUR);
    }
    free(strtab);
    fclose(f); return rc;
}

/* Write a single member header + body. Deterministic mode zeros
   uid/gid/mtime and normalizes mode to 0644 (0755 if any exec bit
   was set in source). Called only for names ≤ 15 chars (long names
   are handled by replace() via GNU `//` strtab emit). */
static int write_one(FILE *out, const char *path, int deterministic) {
    struct stat st; FILE *in = fopen(path,"rb");
    if (!in || stat(path,&st)<0) { builtin_error("%s: %s", path, strerror(errno)); if(in)fclose(in); return -1; }
    const char *base = strrchr(path,'/'); base = base ? base+1 : path;
    char nbuf[17]; snprintf(nbuf, sizeof nbuf, "%.15s/", base);
    long mtime = deterministic ? 0L : (long)st.st_mtime;
    int uid    = deterministic ? 0  : (int)st.st_uid;
    int gid    = deterministic ? 0  : (int)st.st_gid;
    unsigned mode = (unsigned)(st.st_mode & 0777);
    if(deterministic) mode = (mode & 0111) ? 0755 : 0644;
    fprintf(out, "%-16s%-12ld%-6d%-6d%-8o%-10ld`\n",
            nbuf, mtime, uid, gid, mode, (long)st.st_size);
    int c; while((c=fgetc(in))!=EOF) fputc(c,out);
    if (st.st_size & 1) fputc('\n',out);
    fclose(in);
    return 0;
}

/* Replace archive with new members. If any member basename exceeds 15
   chars, builds a GNU `//` strtab and emits long-name members via /N
   offset references (matching the read-side GNU strtab support). */
static int replace(const char *arch, WORD_LIST *files, int deterministic) {
    FILE *out = fopen(arch, "wb");
    if (!out) { builtin_error("%s: %s", arch, strerror(errno)); return EXECUTION_FAILURE; }
    fputs(AR_MAGIC, out);

    /* Pass 1: detect long names. */
    int need_strtab = 0;
    for (WORD_LIST *p = files; p; p = p->next) {
        const char *base = strrchr(p->word->word, '/');
        base = base ? base + 1 : p->word->word;
        if (strlen(base) > 15) { need_strtab = 1; break; }
    }

    if (!need_strtab) {
        /* Fast path — all names fit in the 16-byte header field. */
        for (WORD_LIST *p = files; p; p = p->next) {
            if (write_one(out, p->word->word, deterministic) < 0) { fclose(out); return EXECUTION_FAILURE; }
        }
        fclose(out);
        return EXECUTION_SUCCESS;
    }

    /* Build GNU strtab: each long name stored as basename + '/'. */
    size_t tab_size = 0;
    for (WORD_LIST *p = files; p; p = p->next) {
        const char *base = strrchr(p->word->word, '/');
        base = base ? base + 1 : p->word->word;
        size_t blen = strlen(base);
        if (blen > 15) tab_size += blen + 2;  /* GNU entry: name + '/' + '\n' */
    }

    char *strtab = malloc(tab_size + 1);
    if (!strtab) { fclose(out); return EXECUTION_FAILURE; }

    size_t pos = 0;
    int n_long = 0;
    for (WORD_LIST *p = files; p; p = p->next) {
        const char *base = strrchr(p->word->word, '/');
        base = base ? base + 1 : p->word->word;
        size_t blen = strlen(base);
        if (blen > 15) {
            memcpy(strtab + pos, base, blen);
            strtab[pos + blen] = '/';
            strtab[pos + blen + 1] = '\n';   /* GNU terminates each entry with "/\n" */
            pos += blen + 2;
            n_long++;
        }
    }
    strtab[pos] = 0;

    /* Track per-file strtab offset for the write pass. */
    long *offsets = malloc((size_t)n_long * sizeof(long));
    if (!offsets) { free(strtab); fclose(out); return EXECUTION_FAILURE; }
    pos = 0;
    int idx = 0;
    for (WORD_LIST *p = files; p; p = p->next) {
        const char *base = strrchr(p->word->word, '/');
        base = base ? base + 1 : p->word->word;
        size_t blen = strlen(base);
        if (blen > 15) {
            offsets[idx++] = (long)pos;
            pos += blen + 2;
        }
    }

    /* Pad strtab data to even byte count. */
    size_t tab_data_len = tab_size;
    if (tab_data_len % 2) tab_data_len++;  /* even pad for ar format */

    /* Write `//` strtab member. GNU ar leaves this member's
       mtime/uid/gid/mode fields BLANK (space-filled) — it is a string
       table, not a real file — and populates only the name, size, and
       trailing magic. Filling them with 0/0/0/644 (the normal file-header
       path) produced an archive that differed from `ar -D` byte-for-byte. */
    fprintf(out, "%-16s%-12s%-6s%-6s%-8s%-10zu`\n",
            "//", "", "", "", "", tab_data_len);
    fwrite(strtab, 1, tab_size, out);
    if (tab_data_len > tab_size) fputc('\n', out);

    /* Pass 2: write each member, using /N references for long names. */
    idx = 0;
    for (WORD_LIST *p = files; p; p = p->next) {
        const char *base = strrchr(p->word->word, '/');
        base = base ? base + 1 : p->word->word;
        size_t blen = strlen(base);

        if (blen > 15) {
            /* Write member with /N name reference into the strtab. */
            long off = offsets[idx++];
            struct stat st;
            FILE *in = fopen(p->word->word, "rb");
            if (!in || stat(p->word->word, &st) < 0) {
                builtin_error("%s: %s", p->word->word, strerror(errno));
                if (in) fclose(in);
                free(strtab); free(offsets); fclose(out);
                return EXECUTION_FAILURE;
            }
            char nbuf[17]; snprintf(nbuf, sizeof nbuf, "/%-15ld", off);
            long mtime = deterministic ? 0L : (long)st.st_mtime;
            int uid    = deterministic ? 0  : (int)st.st_uid;
            int gid    = deterministic ? 0  : (int)st.st_gid;
            unsigned mode = (unsigned)(st.st_mode & 0777);
            if(deterministic) mode = (mode & 0111) ? 0755 : 0644;
            fprintf(out, "%-16s%-12ld%-6d%-6d%-8o%-10ld`\n",
                    nbuf, mtime, uid, gid, mode, (long)st.st_size);
            int c; while((c=fgetc(in))!=EOF) fputc(c,out);
            if (st.st_size & 1) fputc('\n',out);
            fclose(in);
        } else {
            if (write_one(out, p->word->word, deterministic) < 0) {
                free(strtab); free(offsets); fclose(out);
                return EXECUTION_FAILURE;
            }
        }
    }

    free(strtab);
    free(offsets);
    fclose(out);
    return EXECUTION_SUCCESS;
}

static void free_members(struct ar_member *members, size_t n) {
    if (!members) return;
    for (size_t i = 0; i < n; i++) free(members[i].data);
    free(members);
}

static int append_member(struct ar_member **members, size_t *n, size_t *cap,
                         const struct ar_hdr *h, const unsigned char *data, long size) {
    if (*n == *cap) {
        size_t nc = *cap ? *cap * 2 : 8;
        struct ar_member *nv = realloc(*members, nc * sizeof(*nv));
        if (!nv) return -1;
        *members = nv;
        *cap = nc;
    }
    (*members)[*n].h = *h;
    (*members)[*n].size = size;
    (*members)[*n].data = NULL;
    if (size > 0) {
        (*members)[*n].data = malloc((size_t)size);
        if (!(*members)[*n].data) return -1;
        memcpy((*members)[*n].data, data, (size_t)size);
    }
    (*n)++;
    return 0;
}

static int read_members_without_symtab(const char *arch, struct ar_member **out_members, size_t *out_n) {
    FILE *f = fopen(arch, "rb");
    if (!f) { builtin_error("%s: %s", arch, strerror(errno)); return EXECUTION_FAILURE; }
    if (!check_magic(f)) { builtin_error("%s: bad ar magic", arch); fclose(f); return EXECUTION_FAILURE; }

    struct ar_member *members = NULL;
    size_t n = 0, cap = 0;
    struct ar_hdr h;
    int rc = EXECUTION_SUCCESS;

    for (;;) {
        size_t nr = fread(&h, 1, sizeof h, f);
        if (nr == 0) {
            if (ferror(f)) { builtin_error("%s: read error", arch); rc = EXECUTION_FAILURE; }
            break;
        }
        if (nr != sizeof h) {
            builtin_error("%s: file format not recognized", arch);
            rc = EXECUTION_FAILURE; break;
        }
        if (memcmp(h.fmag, AR_FMAG, 2)) {
            builtin_error("%s: file format not recognized", arch);
            rc = EXECUTION_FAILURE; break;
        }
        long sz = decfield(h.size, sizeof h.size);
        if (sz < 0) { builtin_error("%s: corrupt ar header (bad size)", arch); rc = EXECUTION_FAILURE; break; }
        unsigned char *buf = NULL;
        if (sz > 0) {
            buf = malloc((size_t)sz);
            if (!buf) { builtin_error("out of memory"); rc = EXECUTION_FAILURE; break; }
            if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
                builtin_error("%s: short read on member", arch);
                free(buf); rc = EXECUTION_FAILURE; break;
            }
        }
        if (sz & 1) fseek(f, 1, SEEK_CUR);
        if (!member_is_symtab(&h)) {
            if (append_member(&members, &n, &cap, &h, buf, sz) < 0) {
                builtin_error("out of memory");
                free(buf); rc = EXECUTION_FAILURE; break;
            }
        }
        free(buf);
    }

    fclose(f);
    if (rc != EXECUTION_SUCCESS) { free_members(members, n); return rc; }
    *out_members = members;
    *out_n = n;
    return EXECUTION_SUCCESS;
}

static int write_symtab_member(FILE *out, const struct ar_symvec *sv,
                               const long *member_offsets, int deterministic) {
    size_t names_len = 0;
    for (size_t i = 0; i < sv->n; i++) names_len += strlen(sv->v[i].name) + 1;
    size_t body_len = 4 + sv->n * 4 + names_len;
    unsigned char *body = malloc(body_len ? body_len : 1);
    if (!body) { builtin_error("out of memory"); return -1; }

    wr32be(body, (uint32_t)sv->n);
    for (size_t i = 0; i < sv->n; i++) {
        if (member_offsets[sv->v[i].member_index] < 0 ||
            member_offsets[sv->v[i].member_index] > 0xffffffffL) {
            builtin_error("archive too large for 32-bit ar symbol table offsets");
            free(body); return -1;
        }
        wr32be(body + 4 + i * 4, (uint32_t)member_offsets[sv->v[i].member_index]);
    }
    size_t pos = 4 + sv->n * 4;
    for (size_t i = 0; i < sv->n; i++) {
        size_t l = strlen(sv->v[i].name) + 1;
        memcpy(body + pos, sv->v[i].name, l);
        pos += l;
    }

    long mtime = deterministic ? 0L : (long)time(NULL);
    /* GNU ar writes the `/` symbol-table member with mode 0 (not 0644);
       it is an index, not a file. */
    fprintf(out, "%-16s%-12ld%-6d%-6d%-8o%-10zu`\n",
            "/", mtime, 0, 0, 0, body_len);
    fwrite(body, 1, body_len, out);
    if (body_len & 1) fputc('\n', out);
    free(body);
    return 0;
}

static int refresh_symtab(const char *arch, int deterministic) {
    struct ar_member *members = NULL;
    size_t n = 0;
    int rc = read_members_without_symtab(arch, &members, &n);
    if (rc != EXECUTION_SUCCESS) return rc;

    struct ar_symvec sv = {0};
    for (size_t i = 0; i < n; i++) {
        if (!member_is_strtab(&members[i].h) &&
            elf_collect_symbols(members[i].data, (size_t)members[i].size, i, &sv) < 0) {
            builtin_error("out of memory");
            symvec_free(&sv); free_members(members, n);
            return EXECUTION_FAILURE;
        }
    }

    size_t names_len = 0;
    for (size_t i = 0; i < sv.n; i++) names_len += strlen(sv.v[i].name) + 1;
    size_t sym_body_len = 4 + sv.n * 4 + names_len;
    size_t sym_total_len = sizeof(struct ar_hdr) + sym_body_len + (sym_body_len & 1);

    long *offsets = calloc(n ? n : 1, sizeof(*offsets));
    if (!offsets) {
        builtin_error("out of memory");
        symvec_free(&sv); free_members(members, n);
        return EXECUTION_FAILURE;
    }
    long off = AR_MAGIC_LEN + (long)sym_total_len;
    for (size_t i = 0; i < n; i++) {
        offsets[i] = off;
        off += (long)sizeof(struct ar_hdr) + members[i].size + (members[i].size & 1);
    }

    FILE *out = fopen(arch, "wb");
    if (!out) {
        builtin_error("%s: %s", arch, strerror(errno));
        free(offsets); symvec_free(&sv); free_members(members, n);
        return EXECUTION_FAILURE;
    }
    fputs(AR_MAGIC, out);
    if (write_symtab_member(out, &sv, offsets, deterministic) < 0) {
        fclose(out); free(offsets); symvec_free(&sv); free_members(members, n);
        return EXECUTION_FAILURE;
    }
    for (size_t i = 0; i < n; i++) {
        fwrite(&members[i].h, 1, sizeof members[i].h, out);
        if (members[i].size > 0) fwrite(members[i].data, 1, (size_t)members[i].size, out);
        if (members[i].size & 1) fputc('\n', out);
    }
    fclose(out);
    free(offsets);
    symvec_free(&sv);
    free_members(members, n);
    return EXECUTION_SUCCESS;
}

static int quick_append(const char *arch, WORD_LIST *files, int deterministic) {
    FILE *out = fopen(arch, "r+b");
    if (!out) {
        out = fopen(arch, "wb");
        if (!out) {
            builtin_error("%s: %s", arch, strerror(errno));
            return EXECUTION_FAILURE;
        }
        fputs(AR_MAGIC, out);
    } else {
        if (!check_magic(out)) {
            builtin_error("%s: bad ar magic", arch);
            fclose(out);
            return EXECUTION_FAILURE;
        }
        if (fseek(out, 0, SEEK_END) < 0) {
            builtin_error("%s: %s", arch, strerror(errno));
            fclose(out);
            return EXECUTION_FAILURE;
        }
    }

    for (WORD_LIST *p = files; p; p = p->next) {
        if (write_one(out, p->word->word, deterministic) < 0) {
            fclose(out);
            return EXECUTION_FAILURE;
        }
    }
    fclose(out);
    return EXECUTION_SUCCESS;
}

int ar_builtin(WORD_LIST *list) {
    int deterministic = 1;  /* Match GNU `ar -D` default since binutils 2.18+. */
    if (list && list->word && list->word->word &&
        (!strcmp(list->word->word, "--help") || !strcmp(list->word->word, "-h"))) {
        builtin_usage();
        return EXECUTION_SUCCESS;
    }
    while(list && list->word && list->word->word
          && list->word->word[0]=='-' && list->word->word[1]
          && (list->word->word[1]=='D' || list->word->word[1]=='U')
          && list->word->word[2]==0){
        deterministic = (list->word->word[1]=='D');
        list = list->next;
    }
    if (!list || !list->next) { builtin_error("usage: ar [-D|-U] -t|-x|-r|-q|-s|s archive [file...]"); return EX_USAGE; }
    char *op=list->word->word; char *arch=list->next->word->word; WORD_LIST *rest=list->next->next;
    /* binutils-style combined op: first letter (after an optional leading '-')
       is the operation; the rest are modifiers (c=create-silently, v=verbose,
       u=update, s=write-symtab, a/b/i=positioning, D/U=deterministic toggle).
       So `ar rc lib.a m.txt` and `ar rcs ...` work, not just bare `r`/`t`. */
    if (op[0]=='-' && op[1]) op++;
    char opkey = op[0];
    int want_symtab = 0;
    for (const char *m = op+1; *m; m++) {
        switch (*m) {
            case 'c': case 'v': case 'u': case 'a': case 'b':
            case 'i': case 'l': case 'o': case 'P': case 'T':
                break;                         /* accepted; no behavioral change here */
            case 's': want_symtab = 1; break;
            case 'D': deterministic = 1; break;
            case 'U': deterministic = 0; break;
            default:
                builtin_error("unknown modifier: %c", *m); builtin_usage(); return EX_USAGE;
        }
    }
    switch (opkey) {
        case 't': return list_or_extract(arch,0,rest);
        case 'x': return list_or_extract(arch,1,rest);
        case 'r': { if(!rest){builtin_error("r needs files"); return EX_USAGE;}
                    int rc=replace(arch,rest,deterministic);
                    if (rc==EXECUTION_SUCCESS && want_symtab) rc=refresh_symtab(arch,deterministic);
                    return rc; }
        case 'q': { if(!rest){builtin_error("q needs files"); return EX_USAGE;}
                    int rc=quick_append(arch,rest,deterministic);
                    if (rc==EXECUTION_SUCCESS && want_symtab) rc=refresh_symtab(arch,deterministic);
                    return rc; }
        case 's': if(rest){builtin_error("s takes only archive"); builtin_usage(); return EX_USAGE;}
                  return refresh_symtab(arch,deterministic);
        default: builtin_error("unknown operation: %s", op); builtin_usage(); return EX_USAGE;
    }
}

char *ar_doc[] = {
    "Create, list, or extract simple ar archives. Writes are deterministic",
    "by default (zero uid/gid/mtime, normalized mode); pass -U to preserve",
    "real metadata. GNU `//` strtab emitted on write for names > 15 chars;",
    "reads understand `//` strtab long-name references. `q`/`-q` quick-appends",
    "members without replacing existing names. `s`/`-s` refreshes",
    "the archive symbol table from defined global/weak ELF symbols.",
    "    ar [-D|-U] -t|-x|-r|-q|-s|s ARCHIVE [FILE...]",
    (char *)NULL
};
struct builtin ar_struct = {"ar", ar_builtin, BUILTIN_ENABLED, ar_doc, "ar [-D|-U] -t|-x|-r|-q|-s|s ARCHIVE [FILE...]", 0};
