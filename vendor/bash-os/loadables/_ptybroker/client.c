/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "transport.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
extern char **environ;

int64_t pb_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
int pb_wait(int fd, short events, int64_t deadline) {
    struct pollfd p = {fd, events, 0};
    int64_t left = deadline - pb_now();
    int r = poll(&p, 1, left > 0 ? (int)left : 0);
    if (r == 0) { errno = ETIMEDOUT; return -1; }
    if (r < 0) return -1;
    if (p.revents & events) return 0;
    errno = ECONNRESET; return -1;
}
int pb_valid_id(const char *id) {
    size_t n = id ? strlen(id) : 0;
    if (!n || n > PB_ID_MAX || id[0] == '.') return 0;
    for (size_t i=0; i<n; ++i)
        if (!((id[i]>='a' && id[i]<='z') || (id[i]>='A' && id[i]<='Z') ||
              (id[i]>='0' && id[i]<='9') || id[i]=='_' || id[i]=='-' || id[i]=='.')) return 0;
    return 1;
}
int pb_check_root(const char *root, int create) {
    struct stat st;
    if (!root || root[0]!='/' || strlen(root)>90 || root[strlen(root)-1]=='/') { errno=EINVAL; return -1; }
    if (create) {
        if(mkdir(root,0700)==0) {
            if(chmod(root,0700)<0)return -1;
        } else if(errno!=EEXIST)return -1;
    }
    if (lstat(root,&st)<0) return -1;
    if (!S_ISDIR(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode & 0777)!=0700) {
        errno=EACCES; return -1;
    }
    return 0;
}
int pb_path(const char *root, const char *id, char *out, size_t cap) {
    if (!pb_valid_id(id)) { errno=EINVAL; return -1; }
    int n=snprintf(out,cap,"%s/%s/control.sock",root,id);
    if (n<0 || (size_t)n>=cap) { errno=ENAMETOOLONG; return -1; }
    return 0;
}
int pb_connect(const char *root, const char *id) {
    struct sockaddr_un a = {.sun_family=AF_UNIX};
    char dir[108]; struct stat st;
    if (pb_check_root(root,0)<0 || pb_path(root,id,a.sun_path,sizeof a.sun_path)<0) return -1;
    snprintf(dir,sizeof dir,"%s/%s",root,id);
    if (lstat(dir,&st)<0) return -1;
    if (!S_ISDIR(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&0777)!=0700) {errno=EACCES;return -1;}
    if (lstat(a.sun_path,&st)<0) return -1;
    if (!S_ISSOCK(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&0777)!=0600) {errno=EACCES;return -1;}
    int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if (fd<0) return -1;
    if (connect(fd,(struct sockaddr *)&a,sizeof a)<0) goto fail;
    struct ucred cred; socklen_t len=sizeof cred;
    if (getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&cred,&len)<0) goto fail;
    if (cred.uid!=geteuid()) {errno=EACCES;goto fail;}
    return fd;
fail: {int e=errno;close(fd);errno=e;return -1;}
}
int pb_packet_send(int fd, const struct pb_packet *p, int64_t until) {
    if (p->size>PB_CHUNK) {errno=EMSGSIZE;return -1;}
    for (;;) {
        ssize_t n=send(fd,p,PB_HEADER+p->size,MSG_NOSIGNAL);
        if (n>=0) {
            if ((size_t)n==PB_HEADER+p->size) return 0;
            errno=EPROTO;return -1;
        }
        if (errno!=EAGAIN && errno!=EWOULDBLOCK) return -1;
        if (pb_wait(fd,POLLOUT,until)<0) return -1;
    }
}
int pb_packet_recv(int fd, struct pb_packet *p, int64_t until) {
    for (;;) {
        ssize_t n=recv(fd,p,sizeof *p,MSG_TRUNC);
        if (n>=0) {
            if (!n) {errno=ECONNRESET;return -1;}
            if ((size_t)n<PB_HEADER || (size_t)n>sizeof *p || p->magic!=PB_MAGIC ||
                p->size>PB_CHUNK || (size_t)n!=PB_HEADER+p->size) {errno=EPROTO;return -1;}
            return 0;
        }
        if (errno!=EAGAIN && errno!=EWOULDBLOCK) return -1;
        if (pb_wait(fd,POLLIN,until)<0) return -1;
    }
}
int pb_fd_write(int fd, const void *data, size_t size, int64_t until) {
    int flags=fcntl(fd,F_GETFL), rc=-1, e;
    sigset_t blocked,old,pending;
    sigemptyset(&blocked);sigaddset(&blocked,SIGPIPE);
    if(flags<0 || sigpending(&pending)<0 || sigprocmask(SIG_BLOCK,&blocked,&old)<0)return -1;
    if(fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0) {
        e=errno;(void)sigprocmask(SIG_SETMASK,&old,NULL);errno=e;return -1;
    }
    const unsigned char *p=data;
    while (size) {
        ssize_t n=write(fd,p,size);
        if (n>0) {p+=n;size-=(size_t)n;continue;}
        if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) {
            if (pb_wait(fd,POLLOUT,until)==0) continue;
        } else if (!n) errno=EIO;
        goto done;
    }
    rc=0;
done:
    e=errno;
    if(rc<0 && e==EPIPE && !sigismember(&pending,SIGPIPE)) {
        struct timespec zero={0};(void)sigtimedwait(&blocked,NULL,&zero);
    }
    if(fcntl(fd,F_SETFL,flags)<0 && rc==0){e=errno;rc=-1;}
    (void)sigprocmask(SIG_SETMASK,&old,NULL);
    errno=e;return rc;
}
static int request(const char *root,const char *id,struct pb_packet *p,int keep,int timeout) {
    int fd=pb_connect(root,id); if(fd<0)return -1;
    uint32_t want=p->type+PB_REPLY;
    p->magic=PB_MAGIC;
    int64_t until=pb_now()+timeout;
    if(pb_packet_send(fd,p,until)<0 || pb_packet_recv(fd,p,until)<0) goto fail;
    if(p->type!=want) {errno=EPROTO;goto fail;}
    if(p->error) {errno=(int)p->error;goto fail;}
    if(keep)return fd;
    close(fd); return 0;
fail: {int e=errno;close(fd);errno=e;return -1;}
}
int pb_status(const char *root,const char *id,struct pb_status *s) {
    struct pb_packet p={.type=PB_STATUS};
    if(request(root,id,&p,0,PB_TIMEOUT)<0)return -1;
    if(p.size!=sizeof *s){errno=EPROTO;return -1;}
    memcpy(s,p.data,sizeof *s);return 0;
}
int pb_resize(const char *root,const char *id,unsigned rows,unsigned cols) {
    if(!rows || rows>65535 || !cols || cols>65535){errno=EINVAL;return -1;}
    uint32_t size[2]={rows,cols};
    struct pb_packet p={.type=PB_RESIZE,.size=sizeof size};
    memcpy(p.data,size,sizeof size);return request(root,id,&p,0,PB_TIMEOUT);
}
int pb_send(const char *root,const char *id,const void *data,size_t n) {
    if(n>PB_CHUNK){errno=EMSGSIZE;return -1;}
    struct pb_packet p={.type=PB_INPUT,.size=(uint32_t)n};
    if(n)memcpy(p.data,data,n);
    return request(root,id,&p,0,PB_TIMEOUT);
}
int pb_attach(const char *root,const char *id,int role,int *fd,struct pb_status *s) {
    if(role!=PB_CONTROL && role!=PB_OBSERVE){errno=EINVAL;return -1;}
    struct pb_packet p={.type=role==PB_CONTROL?PB_OPEN_CONTROL:PB_OPEN_OBSERVER};
    int f=request(root,id,&p,1,PB_TIMEOUT);
    if(f<0)return -1;
    if(p.size!=sizeof *s){close(f);errno=EPROTO;return -1;}
    memcpy(s,p.data,sizeof *s);*fd=f;return 0;
}
int pb_receive(int fd,struct pb_event *event,int timeout) {
    if(timeout<0 || timeout>60000){errno=EINVAL;return -1;}
    struct pb_packet p;
    if(pb_packet_recv(fd,&p,pb_now()+timeout)<0)return -1;
    if(p.type<PB_OUTPUT || p.type>PB_GAP || p.error){errno=EPROTO;return -1;}
    event->type=p.type;event->size=p.size;event->offset=p.offset;
    memcpy(event->data,p.data,p.size);return 0;
}
int pb_capture(const char *root,const char *id,int fd) {
    struct pb_status s;
    if(pb_status(root,id,&s)<0)return -1;
    int64_t until=pb_now()+PB_TIMEOUT;
    for(uint64_t off=s.oldest;off<s.next;) {
        struct pb_packet p={.type=PB_CAPTURE,.offset=off,.size=sizeof s.next};
        memcpy(p.data,&s.next,sizeof s.next);
        if(pb_now()>=until){errno=ETIMEDOUT;return -1;}
        if(request(root,id,&p,0,(int)(until-pb_now()))<0)return -1;
        if(!p.size || p.offset!=off || p.size>s.next-off){errno=EPROTO;return -1;}
        if(pb_fd_write(fd,p.data,p.size,until)<0)return -1;
        off+=p.size;
    }
    return 0;
}
int pb_terminate(const char *root,const char *id) {
    struct pb_packet p={.type=PB_TERMINATE};
    return request(root,id,&p,0,6000);
}
int pb_start(const struct pb_start_options *o,struct pb_status *s) {
    char socket_path[108],self[PATH_MAX],rows[16],cols[16];
    if(!o || !o->argv || !o->argv[0] || !o->cwd || o->cwd[0]!='/' ||
       !o->rows || o->rows>65535 || !o->cols || o->cols>65535) {errno=EINVAL;return -1;}
    if(pb_path(o->root,o->id,socket_path,sizeof socket_path)<0 || pb_check_root(o->root,1)<0)return -1;
    const char *shell=o->shell;
    if(!shell) {
        ssize_t n=readlink("/proc/self/exe",self,sizeof self-1);
        if(n<0 || (size_t)n>=sizeof self-1){errno=ENAMETOOLONG;return -1;}
        self[n]=0;shell=self;
    }
    snprintf(rows,sizeof rows,"%u",o->rows);snprintf(cols,sizeof cols,"%u",o->cols);
    size_t argc=0,envc=0;
    while(o->argv[argc])if(++argc>1024){errno=E2BIG;return -1;}
    while(environ[envc])++envc;
    char **av=calloc(argc+20,sizeof *av),**env=calloc(envc+2,sizeof *env);
    if(!av || !env){free(av);free(env);return -1;}
    size_t n=0,k=0;
    av[n++]=(char *)shell;av[n++]="--noprofile";av[n++]="--norc";av[n++]="-p";av[n++]="-c";
    av[n++]="if [[ -n $1 ]]; then enable -f \"$1\" ptybroker || exit 126; fi; shift; ptybroker serve \"$@\"";
    av[n++]="ptybroker-service";av[n++]=(char *)(o->loadable?o->loadable:"");
    av[n++]=(char *)o->root;av[n++]=(char *)o->id;av[n++]=rows;av[n++]=cols;av[n++]=(char *)o->cwd;
    for(size_t i=0;i<argc;++i)av[n++]=o->argv[i];
    for(size_t i=0;i<envc;++i) {
        const char *v=environ[i];
        if(!strncmp(v,"BASH_ENV=",9)||!strncmp(v,"ENV=",4)||!strncmp(v,"BASH_FUNC_",10)||
           !strncmp(v,"SHELLOPTS=",10)||!strncmp(v,"BASHOPTS=",9)||
           !strncmp(v,"BASH_PTYBROKER_SERVICE=",sizeof "BASH_PTYBROKER_SERVICE="-1))continue;
        env[k++]=environ[i];
    }
    env[k++]="BASH_PTYBROKER_SERVICE=1";
    int pipefd[2];
    if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,pipefd)<0){free(av);free(env);return -1;}
    /* Move both ends above the ready descriptor before constructing actions. */
    int rd=fcntl(pipefd[0],F_DUPFD_CLOEXEC,10),wr=fcntl(pipefd[1],F_DUPFD_CLOEXEC,10);
    close(pipefd[0]);close(pipefd[1]);
    if(rd<0||wr<0){int e=errno;if(rd>=0)close(rd);if(wr>=0)close(wr);free(av);free(env);errno=e;return -1;}
    posix_spawn_file_actions_t fa;posix_spawnattr_t attr;
    posix_spawn_file_actions_init(&fa);posix_spawnattr_init(&attr);
    int err=posix_spawn_file_actions_addopen(&fa,0,"/dev/null",O_RDWR,0);
    if(!err)err=posix_spawn_file_actions_adddup2(&fa,0,1);
    if(!err)err=posix_spawn_file_actions_adddup2(&fa,0,2);
    if(!err)err=posix_spawn_file_actions_adddup2(&fa,wr,3);
    if(!err)err=posix_spawn_file_actions_addclosefrom_np(&fa,4);
    sigset_t mask,defs;sigemptyset(&mask);sigfillset(&defs);
    sigdelset(&defs,SIGKILL);sigdelset(&defs,SIGSTOP);
    if(!err)err=posix_spawnattr_setsigmask(&attr,&mask);
    if(!err)err=posix_spawnattr_setsigdefault(&attr,&defs);
    if(!err)err=posix_spawnattr_setflags(&attr,POSIX_SPAWN_SETSIGMASK|POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_SETSID);
    pid_t pid=-1;
    if(!err)err=posix_spawn(&pid,shell,&fa,&attr,av,env);
    posix_spawn_file_actions_destroy(&fa);posix_spawnattr_destroy(&attr);
    close(wr);free(av);free(env);
    if(err){close(rd);errno=err;return -1;}
    int result=-1,e=0;
    /* The service cannot finish successful startup until this socket accepts
     * the creator's acknowledgement. EOF or timeout cancels the new session. */
    int64_t until=pb_now()+PB_TIMEOUT;
    if(pb_wait(rd,POLLIN,until)==0) {
        struct pb_ready ready;
        ssize_t got=recv(rd,&ready,sizeof ready,MSG_TRUNC);
        if(got==(ssize_t)sizeof ready) {
            if(ready.error)errno=ready.error;
            else if(send(rd,"G",1,MSG_NOSIGNAL)==1){*s=ready.status;result=0;}
        } else errno=ECHILD;
    }
    e=errno;
    if(result<0) {
        int pidfd=(int)syscall(SYS_pidfd_open,pid,0);
        close(rd);rd=-1;
        if(pidfd>=0) {
            int64_t cleanup=pb_now()+5000;
            while(pb_wait(pidfd,POLLIN,cleanup)<0 && errno==EINTR && pb_now()<cleanup) {}
            close(pidfd);
        }
        (void)waitpid(pid,NULL,WNOHANG);
    }
    if(rd>=0)close(rd);
    errno=e;return result;
}
