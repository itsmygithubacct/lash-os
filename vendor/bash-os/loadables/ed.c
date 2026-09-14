/* SPDX-License-Identifier: MIT */
/* ed.c - small ed(1)-style line editor loadable. */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include "loadables.h"

struct snap { char **v; size_t n; size_t cur; size_t mark[26]; int dirty; };
struct undo { struct snap *v; size_t n, cap, max; };
struct buf { char **v; size_t n, cap; size_t cur; size_t mark[26]; char *file; int dirty; struct undo undo; };
#define BASHED_UNDO_DEFAULT_MAX 1024
static size_t undo_max(void){ const char*s=getenv("BASHED_UNDO_MAX"); if(!s||!*s)return BASHED_UNDO_DEFAULT_MAX; char*e; unsigned long v=strtoul(s,&e,10); if(*e||v<1)return BASHED_UNDO_DEFAULT_MAX; if(v>BASHED_UNDO_DEFAULT_MAX)v=BASHED_UNDO_DEFAULT_MAX; return (size_t)v; }
static void freesnap(struct snap*s){ for(size_t i=0;i<s->n;i++) free(s->v[i]); free(s->v); memset(s,0,sizeof *s); }
static void freeundo(struct undo*u){ for(size_t i=0;i<u->n;i++) freesnap(&u->v[i]); free(u->v); memset(u,0,sizeof *u); }
static void freebuf(struct buf *b){ for(size_t i=0;i<b->n;i++) free(b->v[i]); free(b->v); free(b->file); memset(b,0,sizeof *b); }
static void clear_lines(struct buf*b){ for(size_t i=0;i<b->n;i++) free(b->v[i]); free(b->v); b->v=NULL; b->n=b->cap=0; b->cur=0; }
static int clonesnap(struct snap*s,const struct buf*b){ memset(s,0,sizeof *s); if(b->n){ s->v=calloc(b->n,sizeof*s->v); if(!s->v)return 1; for(size_t i=0;i<b->n;i++){ s->v[i]=strdup(b->v[i]); if(!s->v[i]){freesnap(s);return 1;} } } s->n=b->n; s->cur=b->cur; memcpy(s->mark,b->mark,sizeof s->mark); s->dirty=b->dirty; return 0; }
static int remember(struct buf*b){ if(!b->undo.max)b->undo.max=undo_max(); if(!b->undo.max)return 0; struct snap s; if(clonesnap(&s,b))return 1; if(b->undo.n==b->undo.max){ freesnap(&b->undo.v[0]); memmove(b->undo.v,b->undo.v+1,(b->undo.n-1)*sizeof*b->undo.v); b->undo.n--; } if(b->undo.n+1>b->undo.cap){ size_t nc=b->undo.cap?b->undo.cap*2:16; if(nc>b->undo.max)nc=b->undo.max; struct snap*nv=realloc(b->undo.v,nc*sizeof*nv); if(!nv){freesnap(&s);return 1;} b->undo.v=nv; b->undo.cap=nc; } b->undo.v[b->undo.n++]=s; return 0; }
static int undo_once(struct buf*b){ if(!b->undo.n)return 1; struct snap s=b->undo.v[--b->undo.n]; clear_lines(b); b->v=s.v; b->n=s.n; b->cap=s.n; b->cur=s.cur; memcpy(b->mark,s.mark,sizeof b->mark); b->dirty=s.dirty; memset(&s,0,sizeof s); return 0; }
static void freebuf_all(struct buf*b){ freeundo(&b->undo); freebuf(b); }
/* POSIX ed -s: suppress the byte/line counts printed by r/w/W. */
static int bashed_silent=0;
static int setfile(struct buf*b,const char*path){ char*p=strdup(path); if(!p)return 1; free(b->file); b->file=p; return 0; }
static int push(struct buf*b,const char*s,size_t pos){ if(b->n+1>b->cap){size_t nc=b->cap?b->cap*2:64;char**nv=realloc(b->v,nc*sizeof*nv);if(!nv)return 1;b->v=nv;b->cap=nc;} if(pos>b->n)pos=b->n; memmove(b->v+pos+1,b->v+pos,(b->n-pos)*sizeof*b->v); b->v[pos]=strdup(s); if(!b->v[pos])return 1; for(size_t i=0;i<26;i++)if(b->mark[i]>pos)b->mark[i]++; b->n++; b->cur=pos+1; b->dirty=1; return 0; }
static int load(struct buf*b,const char*path){ FILE*f=fopen(path,"r"); if(!f){ if(errno==ENOENT)return setfile(b,path); builtin_error("%s: %s",path,strerror(errno)); return 1;} char*line=NULL;size_t cap=0;ssize_t r; while((r=getline(&line,&cap,f))!=-1){ if(r&&line[r-1]=='\n')line[r-1]=0; if(push(b,line,b->n)){free(line);fclose(f);return 1;} b->dirty=0;} free(line); fclose(f); if(setfile(b,path))return 1; b->cur=b->n; return 0; }
/* POSIX ed: 'w' prints the number of BYTES written, not lines. */
static int writebuf_mode(struct buf*b,const char*path,const char*mode){ if(!path||!*path)path=b->file; if(!path||!*path){builtin_error("no current filename");return 1;} FILE*f=fopen(path,mode); if(!f){builtin_error("%s: %s",path,strerror(errno));return 1;} size_t bytes=0; for(size_t i=0;i<b->n;i++){ fprintf(f,"%s\n",b->v[i]); bytes+=strlen(b->v[i])+1; } fclose(f); if(setfile(b,path))return 1; if(mode[0]=='w')b->dirty=0; if(!bashed_silent)printf("%zu\n",bytes); return 0; }
static int writebuf(struct buf*b,const char*path){ return writebuf_mode(b,path,"w"); }
static int find_re(struct buf*b,const char*pat,int back,size_t*out){ if(!b->n)return 1; regex_t re; if(regcomp(&re,pat,REG_NOSUB))return 1; size_t start=b->cur?b->cur:1; if(back){ for(size_t i=start-1;i>=1;i--){ if(!regexec(&re,b->v[i-1],0,NULL,0)){*out=i;regfree(&re);return 0;} if(i==1)break; } for(size_t i=b->n;i>=start;i--){ if(!regexec(&re,b->v[i-1],0,NULL,0)){*out=i;regfree(&re);return 0;} if(i==1)break; } } else { for(size_t i=start+1;i<=b->n;i++) if(!regexec(&re,b->v[i-1],0,NULL,0)){*out=i;regfree(&re);return 0;} for(size_t i=1;i<=start&&i<=b->n;i++) if(!regexec(&re,b->v[i-1],0,NULL,0)){*out=i;regfree(&re);return 0;} } regfree(&re); return 1; }
static int addr(struct buf*b,const char*s,size_t*out){ if(!s||!*s||!strcmp(s,".")){*out=b->cur?b->cur:1;return 0;} if(!strcmp(s,"$")){*out=b->n;return 0;} if(s[0]=='\''&&s[1]>='a'&&s[1]<='z'&&!s[2]&&b->mark[s[1]-'a']){*out=b->mark[s[1]-'a'];return 0;} if((s[0]=='+'||s[0]=='-')&&(s[1]>='0'&&s[1]<='9')){ char*e; long v=strtol(s+1,&e,10); long base=b->cur?b->cur:1, n=s[0]=='+'?base+v:base-v; if(*e||n<0||(size_t)n>b->n)return 1; *out=(size_t)n; return 0; } size_t l=strlen(s); if(l>=2&&((s[0]=='/'&&s[l-1]=='/')||(s[0]=='?'&&s[l-1]=='?'))){ char*pat=malloc(l-1); int rc; if(!pat)return 1; memcpy(pat,s+1,l-2); pat[l-2]=0; rc=find_re(b,pat,s[0]=='?',out); free(pat); return rc; } char*e; long v=strtol(s,&e,10); if(*e||v<0||(size_t)v>b->n){return 1;} *out=(size_t)v; return 0; }
/* GNU/POSIX ed: ',' alone means 1,$; ';' alone means .,$. Other empty sides
   still fall through to addr() (which defaults missing to '.'). */
static int range(struct buf*b,char*spec,size_t*a,size_t*z){ char*c=strchr(spec,','),*sc=strchr(spec,';'); if(sc&&(!c||sc<c))c=sc; if(c){ char sep=*c; *c=0; if(!*spec && !*(c+1)){ *a=(sep==',')?1:(b->cur?b->cur:1); *z=b->n; if(sep==';')b->cur=*a; } else { if(addr(b,spec,a))return 1; if(sep==';')b->cur=*a; if(addr(b,c+1,z))return 1; } } else { if(addr(b,spec,a))return 1; *z=*a; } return *a<=*z && *z<=b->n ? 0 : 1; }
static int del(struct buf*b,size_t a,size_t z){ if(a<1||z>b->n||a>z)return 1; size_t n=z-a+1; for(size_t i=a-1;i<z;i++)free(b->v[i]); memmove(b->v+a-1,b->v+z,(b->n-z)*sizeof*b->v); for(size_t i=0;i<26;i++){ if(b->mark[i]>=a&&b->mark[i]<=z)b->mark[i]=0; else if(b->mark[i]>z)b->mark[i]-=n; } b->n-=n; b->cur=a<=b->n?a:b->n; b->dirty=1; return 0; }
static int read_insert(struct buf*b,size_t pos){ char*line=NULL;size_t cap=0;ssize_t r; while((r=getline(&line,&cap,stdin))!=-1){ if(r&&line[r-1]=='\n')line[r-1]=0; if(!strcmp(line,"."))break; if(push(b,line,pos++)){free(line);return 1;} } free(line); return 0; }
static int read_file(struct buf*b,size_t pos,const char*path){ FILE*f=fopen(path,"r"); if(!f){builtin_error("%s: %s",path,strerror(errno));return 1;} char*line=NULL;size_t cap=0,bytes=0;ssize_t r; while((r=getline(&line,&cap,f))!=-1){ bytes+=(size_t)r; /* GNU ed: r reports BYTES read, not lines */ if(r&&line[r-1]=='\n')line[r-1]=0; if(push(b,line,pos++)){free(line);fclose(f);return 1;} } free(line); fclose(f); if(!bashed_silent)printf("%zu\n",bytes); return 0; }
static char *find_command_char(char*p,char c);
static int parse_sub(char *cmd,char **spec,char **pat,char **repl,int *global,int *print){ char*s=find_command_char(cmd,'s'); if(!s||!s[1])return 1; *s=0; *spec=cmd; char d=s[1],*p=s+2,*q=p; while(*q&&*q!=d)q++; if(*q!=d)return 1; *q++=0; *pat=p; p=q; while(*q&&*q!=d)q++; if(*q!=d)return 1; *q++=0; *repl=p; *global=0; *print=0; for(;*q;q++){ if(*q=='g')*global=1; else if(*q=='p')*print=1; else return 1; } return 0; }
static char *skip_addr_token(char*p){ if(!*p)return p; if(*p=='/'||*p=='?'){ char d=*p++; while(*p&&*p!=d)p++; if(*p==d)p++; return p; } if(*p=='\''&&p[1]>='a'&&p[1]<='z')return p+2; if(*p=='.'||*p=='$')return p+1; if((*p=='+'||*p=='-')&&p[1]>='0'&&p[1]<='9')p++; while(*p>='0'&&*p<='9')p++; return p; }
static char *find_command_char(char*p,char c){ p=skip_addr_token(p); if(*p==',')p=skip_addr_token(p+1); return *p==c?p:NULL; }
static int append_mem(char **buf,size_t *len,size_t *cap,const char*s,size_t n){ if(*len+n+1>*cap){ size_t nc=*cap?*cap*2:64; while(nc<*len+n+1)nc*=2; char*nv=realloc(*buf,nc); if(!nv)return 1; *buf=nv; *cap=nc; } memcpy(*buf+*len,s,n); *len+=n; (*buf)[*len]=0; return 0; }
static int append_repl(char **buf,size_t *len,size_t *cap,const char*r,const char*line,regmatch_t m){ for(const char*p=r;*p;p++){ if(*p=='&'){ if(append_mem(buf,len,cap,line+m.rm_so,(size_t)(m.rm_eo-m.rm_so)))return 1; } else if(*p=='\\'&&p[1]){ p++; if(append_mem(buf,len,cap,p,1))return 1; } else if(append_mem(buf,len,cap,p,1))return 1; } return 0; }
static int subst_one(char **line,const char*pat,const char*repl,int global){ regex_t re; if(regcomp(&re,pat,0))return -1; const char*src=*line; size_t off=0,len=0,cap=0,nsub=0; char*out=NULL; regmatch_t m; while(!regexec(&re,src+off,1,&m,0)){ size_t so=off+(size_t)m.rm_so, eo=off+(size_t)m.rm_eo; if(append_mem(&out,&len,&cap,src+off,so-off)||append_repl(&out,&len,&cap,repl,src,m)){free(out);regfree(&re);return -1;} nsub++; off=eo; if(!global)break; if(eo==so){ if(src[off]){ if(append_mem(&out,&len,&cap,src+off,1)){free(out);regfree(&re);return -1;} off++; } else break; } } regfree(&re); if(!nsub){free(out);return 0;} if(append_mem(&out,&len,&cap,src+off,strlen(src+off))){free(out);return -1;} free(*line); *line=out; return (int)nsub; }
static int subst_range(struct buf*b,size_t a,size_t z,const char*pat,const char*repl,int global){ size_t hits=0; if(a<1||z>b->n||a>z)return 1; for(size_t i=a;i<=z;i++){ int n=subst_one(&b->v[i-1],pat,repl,global); if(n<0)return 1; if(n)hits+=(size_t)n,b->cur=i; } if(!hits)return 1; b->dirty=1; return 0; }
static void print_l(const char*s){ for(;*s;s++){ unsigned char c=(unsigned char)*s; if(c=='\\')printf("\\\\"); else if(c=='\t')printf("\\t"); else if(c<32||c==127)printf("\\%03o",c); else putchar(c); } puts("$"); }
static int join_range(struct buf*b,size_t a,size_t z){ if(a<1||z>b->n||a>z)return 1; size_t len=0; for(size_t i=a;i<=z;i++)len+=strlen(b->v[i-1]); char*s=malloc(len+1); if(!s)return 1; s[0]=0; for(size_t i=a;i<=z;i++)strcat(s,b->v[i-1]); for(size_t i=a;i<=z;i++)free(b->v[i-1]); b->v[a-1]=s; memmove(b->v+a,b->v+z,(b->n-z)*sizeof*b->v); size_t n=z-a; for(size_t i=0;i<26;i++){ if(b->mark[i]>a&&b->mark[i]<=z)b->mark[i]=a; else if(b->mark[i]>z)b->mark[i]-=n; } b->n-=n; b->cur=a; b->dirty=1; return 0; }
static int copy_range_after(struct buf*b,size_t a,size_t z,size_t dest,int move){ if(a<1||z>b->n||a>z||dest>b->n)return 1; if(move&&dest>=a&&dest<=z)return 1; size_t n=z-a+1; char**tmp=calloc(n,sizeof*tmp); if(!tmp)return 1; for(size_t i=0;i<n;i++){ tmp[i]=strdup(b->v[a-1+i]); if(!tmp[i]){ for(size_t j=0;j<i;j++)free(tmp[j]); free(tmp); return 1; } } if(move){ if(del(b,a,z)){ for(size_t i=0;i<n;i++)free(tmp[i]); free(tmp); return 1; } if(dest>z)dest-=n; } for(size_t i=0;i<n;i++){ if(push(b,tmp[i],dest+i)){ for(size_t j=i;j<n;j++)free(tmp[j]); free(tmp); return 1; } free(tmp[i]); } free(tmp); b->cur=dest+n; b->dirty=1; return 0; }

int ed_builtin(WORD_LIST *list){
    struct buf b={0}; int rc=EXECUTION_SUCCESS; bashed_silent=0; if(list&&(!strcmp(list->word->word,"-s"))){ bashed_silent=1; list=list->next; } if(list && load(&b,list->word->word)){freebuf(&b);return EXECUTION_FAILURE;}
    char *cmd=NULL; size_t cap=0; ssize_t r;
    while((r=getline(&cmd,&cap,stdin))!=-1){ if(r&&cmd[r-1]=='\n')cmd[r-1]=0; if(!*cmd)continue; char op=cmd[strlen(cmd)-1]; char spec[128]; strncpy(spec,cmd,sizeof spec-1); spec[sizeof spec-1]=0; spec[strlen(spec)-1]=0; size_t a,z;
        if(!strcmp(cmd,"q")){ if(b.dirty){fprintf(stderr,"?\n"); b.dirty=0; continue;} break; }
        if(!strcmp(cmd,"Q")) break;
        if(cmd[0]=='w' && (cmd[1]==0||cmd[1]==' ')){ if(writebuf(&b,cmd[1]==' '?cmd+2:NULL)) rc=EXECUTION_FAILURE; continue; }
        if(cmd[0]=='W' && (cmd[1]==0||cmd[1]==' ')){ if(writebuf_mode(&b,cmd[1]==' '?cmd+2:NULL,"a")) rc=EXECUTION_FAILURE; continue; }
        if(cmd[0]=='e' && cmd[1]==' '){ freeundo(&b.undo); freebuf(&b); memset(&b,0,sizeof b); if(load(&b,cmd+2)) rc=EXECUTION_FAILURE; continue; }
        if(cmd[0]=='f' && (cmd[1]==0||cmd[1]==' ')){ if(cmd[1]==' '&&setfile(&b,cmd+2)){rc=EXECUTION_FAILURE;continue;} if(b.file)printf("%s\n",b.file); else {fprintf(stderr,"?\n");rc=EXECUTION_FAILURE;} continue; }
        if(!strcmp(cmd,"u")){ if(undo_once(&b)){fprintf(stderr,"?\n");rc=EXECUTION_FAILURE;} continue; }
        if(!strcmp(cmd,"a")){ if(remember(&b)||read_insert(&b,b.cur)) rc=EXECUTION_FAILURE; continue; }
        if(!strcmp(cmd,"i")){ if(remember(&b)||read_insert(&b,b.cur?b.cur-1:0)) rc=EXECUTION_FAILURE; continue; }
        if(!strcmp(cmd,"c")){ a=b.cur; z=b.cur; if(remember(&b)||del(&b,a,z)||read_insert(&b,a-1)) rc=EXECUTION_FAILURE; continue; }
        if(find_command_char(cmd,'s')){ char *ss,*pat,*repl; int g,pr; if(parse_sub(cmd,&ss,&pat,&repl,&g,&pr)||range(&b,*ss?ss:".",&a,&z)){fprintf(stderr,"?\n");rc=EXECUTION_FAILURE;continue;} if(remember(&b)||subst_range(&b,a,z,pat,repl,g)){fprintf(stderr,"?\n");rc=EXECUTION_FAILURE;continue;} if(pr){ for(size_t i=a;i<=z;i++)printf("%s\n",b.v[i-1]); } continue; }
        { char *rp=find_command_char(cmd,'r'); if(rp&&rp[1]==' '){ *rp=0; if(!*cmd){a=b.n;z=a;} else if(range(&b,cmd,&a,&z)){fprintf(stderr,"?\n");rc=EXECUTION_FAILURE;continue;} if(!rp[2]){fprintf(stderr,"?\n");rc=EXECUTION_FAILURE;continue;} (void)z; if(remember(&b)||read_file(&b,a,rp+2)) rc=EXECUTION_FAILURE; continue; } }
        { char *kp=find_command_char(cmd,'k'); if(kp&&kp[1]>='a'&&kp[1]<='z'&&!kp[2]){ *kp=0; if(range(&b,*cmd?cmd:".",&a,&z)){fprintf(stderr,"?\n");rc=EXECUTION_FAILURE;continue;} b.mark[kp[1]-'a']=z; b.cur=z; continue; } }
        if(op=='j'){ if(range(&b,*spec?spec:".",&a,&z)){fprintf(stderr,"?\n");rc=EXECUTION_FAILURE;continue;} if(remember(&b)||join_range(&b,a,z))rc=EXECUTION_FAILURE; continue; }
        { char *mp=find_command_char(cmd,'m'),*tp=find_command_char(cmd,'t'); char *xp=mp?mp:tp; if(xp&&xp[1]){ char c=*xp; *xp=0; if(range(&b,*cmd?cmd:".",&a,&z)||addr(&b,xp+1,&b.cur)){fprintf(stderr,"?\n");rc=EXECUTION_FAILURE;continue;} size_t dest=b.cur; if(remember(&b)||copy_range_after(&b,a,z,dest,c=='m'))rc=EXECUTION_FAILURE; continue; } }
        if(op=='d'||op=='p'||op=='n'||op=='='||op=='l'){ if(range(&b,spec,&a,&z)){fprintf(stderr,"?\n");rc=EXECUTION_FAILURE;continue;} if(op=='d'){ if(remember(&b)||del(&b,a,z))rc=EXECUTION_FAILURE; } else if(op=='=') printf("%zu\n",z); else { for(size_t i=a;i<=z;i++){ if(op=='n')printf("%zu\t",i); if(op=='l')print_l(b.v[i-1]); else printf("%s\n",b.v[i-1]); } b.cur=z; } continue; }
        /* POSIX ed: a bare address command (e.g. "1", "$", "+2", "/pat/")
           sets the current line and prints it. Try range() on the whole cmd;
           if it resolves, treat it as an implicit print. */
        { size_t la, lz; char raw[128]; strncpy(raw,cmd,sizeof raw-1); raw[sizeof raw-1]=0; if(!range(&b,raw,&la,&lz) && lz>=1 && lz<=b.n){ b.cur=lz; printf("%s\n",b.v[lz-1]); continue; } }
        fprintf(stderr,"?\n"); rc=EXECUTION_FAILURE;
    }
    free(cmd); freebuf_all(&b); return rc;
}
char *ed_doc[]={"Small ed-style editor: a/i/c/d/j/k/l/m/t/p/n/s/r/f/w/W/q/e/u with basic, relative, mark, and BRE search addresses.","    ed [-s] [FILE]","Undo history is capped at 1024 entries by default; BASHED_UNDO_MAX may lower it.",(char*)NULL};
struct builtin ed_struct={"ed",ed_builtin,BUILTIN_ENABLED,ed_doc,"ed [-s] [FILE]",0};
