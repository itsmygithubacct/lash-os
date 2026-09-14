/* SPDX-License-Identifier: MIT
 * One independently executed, headless service per PTY. The bounded memory
 * history is an explicit byte capture, never a terminal-state checkpoint.
 */
#define _GNU_SOURCE
#include "transport.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define PB_CLIENTS 32
#define PB_OBSERVERS 8
#define PB_QUEUE (256u * 1024u)
#define PB_INPUT_LIMIT (1024u * 1024u)
struct pb_message { struct pb_message *next; size_t size; unsigned char data[]; };
struct pb_peer {
    int fd, role, closing, terminating;
    int64_t opened;
    size_t queued;
    struct pb_message *head, *tail;
};
struct pb_server {
    int listener, master, eof, exit_sent, ready, stopping, child_live;
    pid_t child;
    int exit_status;
    unsigned rows, cols;
    int64_t stop_at;
    uint64_t next;
    size_t input_head, input_size;
    unsigned char *history, *input;
    struct pb_peer peers[PB_CLIENTS];
};
static volatile sig_atomic_t pb_stop_signal;
static void stop_signal(int sig) { (void)sig; pb_stop_signal=1; }
static void peer_close(struct pb_peer *p) {
    if(p->fd>=0)close(p->fd);
    while(p->head){struct pb_message *m=p->head;p->head=m->next;free(m);}
    memset(p,0,sizeof *p);p->fd=-1;
}
static int queue(struct pb_peer *p,uint32_t type,uint32_t error,uint64_t offset,
                 const void *data,size_t size) {
    size_t total=PB_HEADER+size;
    if(p->fd<0)return -1;
    if(size>PB_CHUNK || total>PB_QUEUE-p->queued){peer_close(p);return -1;}
    struct pb_message *m=malloc(sizeof *m+total);
    if(!m){peer_close(p);return -1;}
    m->next=NULL;m->size=total;
    struct pb_packet h={.magic=PB_MAGIC,.type=type,.size=(uint32_t)size,.error=error,.offset=offset};
    memcpy(m->data,&h,PB_HEADER);if(size)memcpy(m->data+PB_HEADER,data,size);
    if(p->tail)p->tail->next=m;else p->head=m;
    p->tail=m;p->queued+=total;return 0;
}
static void flush_peer(struct pb_peer *p) {
    /* Per-tick quota prevents one socket from monopolizing the service. */
    for(int i=0;i<4 && p->head;++i) {
        struct pb_message *m=p->head;
        ssize_t n=send(p->fd,m->data,m->size,MSG_NOSIGNAL);
        if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR))return;
        if(n<0 || (size_t)n!=m->size){peer_close(p);return;}
        p->head=m->next;if(!p->head)p->tail=NULL;
        p->queued-=m->size;free(m);
    }
    if(p->closing && !p->head)peer_close(p);
}
static struct pb_status status_of(struct pb_server *s) {
    struct pb_status st={0};
    st.broker_pid=getpid();st.child_pid=s->child;st.running=s->child_live;
    st.stopping=s->stopping;st.exit_status=s->exit_status;
    st.rows=s->rows;st.cols=s->cols;st.next=s->next;
    st.oldest=s->next>PB_HISTORY?s->next-PB_HISTORY:0;
    for(int i=0;i<PB_CLIENTS;++i)if(s->peers[i].fd>=0) {
        if(s->peers[i].role==PB_CONTROL)st.controller++;
        if(s->peers[i].role==PB_OBSERVE)st.observers++;
    }
    return st;
}
static void broadcast(struct pb_server *s,uint32_t type,uint64_t offset,const void *data,size_t n) {
    for(int i=0;i<PB_CLIENTS;++i)if(s->peers[i].role && s->peers[i].fd>=0)
        (void)queue(&s->peers[i],type,0,offset,data,n);
}
static void begin_stop(struct pb_server *s) {
    if(!s->stopping){s->stopping=1;s->stop_at=pb_now();}
}
static void request_redraw(struct pb_server *s) {
    pid_t fg=tcgetpgrp(s->master);
    if(fg<=1)return;
    int fd=(int)syscall(SYS_pidfd_open,fg,0);
    if(fd<0)return;
    if(getsid(fg)==s->child)
        (void)syscall(SYS_pidfd_send_signal,fd,SIGWINCH,NULL,0);
    close(fd);
}
/* Only signal unreaped direct children, through a pidfd. A subreaper adopts
 * grandchildren as their parents exit; escalation continues after the original
 * PTY child has exited, including children that created a new session. */
static int signal_children(int sig) {
    char path[96],buf[65536];
    snprintf(path,sizeof path,"/proc/self/task/%ld/children",(long)getpid());
    int f=open(path,O_RDONLY|O_CLOEXEC);if(f<0)return -1;
    ssize_t n=read(f,buf,sizeof buf-1);int e=errno;close(f);errno=e;
    if(n<0)return -1;
    buf[n]=0;
    char *p=buf;
    while(*p) {
        char *end;long id=strtol(p,&end,10);if(end==p)break;p=end;
        if(id<=1)continue;
        int pf=(int)syscall(SYS_pidfd_open,(pid_t)id,0);
        if(pf<0)continue;
        /* Validate ancestry after obtaining the stable identity. */
        snprintf(path,sizeof path,"/proc/%ld/status",id);
        FILE *info=fopen(path,"re");int owned=0;
        if(info) {
            char line[256];long parent;
            while(fgets(line,sizeof line,info))
                if(sscanf(line,"PPid: %ld",&parent)==1){owned=parent==(long)getpid();break;}
            fclose(info);
        }
        if(owned)(void)syscall(SYS_pidfd_send_signal,pf,sig,NULL,0);
        close(pf);
    }
    return 0;
}
static int reap_children(struct pb_server *s) {
    for(;;) {
        int st;pid_t p=waitpid(-1,&st,WNOHANG);
        if(p==0)return 1;
        if(p<0)return errno==ECHILD?0:1;
        if(p==s->child) {
            s->child_live=0;
            s->exit_status=WIFEXITED(st)?WEXITSTATUS(st):WIFSIGNALED(st)?128+WTERMSIG(st):255;
        }
    }
}
static int spawn_pty(struct pb_server *s,const struct pb_start_options *o) {
    int master=posix_openpt(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
    if(master<0)return -1;
    if(grantpt(master)<0||unlockpt(master)<0){int e=errno;close(master);errno=e;return -1;}
    char slave_name[128];
    int err=ptsname_r(master,slave_name,sizeof slave_name);
    if(err){close(master);errno=err;return -1;}
    int child_error[2];
    if(pipe2(child_error,O_CLOEXEC)<0){int e=errno;close(master);errno=e;return -1;}
    pid_t pid=fork();
    if(pid<0){int e=errno;close(master);close(child_error[0]);close(child_error[1]);errno=e;return -1;}
    if(pid==0) {
        close(child_error[0]);
        int slave=-1;
        if(setsid()<0 || (slave=open(slave_name,O_RDWR|O_NOCTTY))<0 || ioctl(slave,TIOCSCTTY,0)<0)goto child_fail;
        struct winsize ws={.ws_row=(unsigned short)o->rows,.ws_col=(unsigned short)o->cols};
        if(ioctl(slave,TIOCSWINSZ,&ws)<0 || chdir(o->cwd)<0)goto child_fail;
        if(dup2(slave,0)<0||dup2(slave,1)<0||dup2(slave,2)<0)goto child_fail;
        if(slave>2)close(slave);
        close(master);
        struct sigaction sa={.sa_handler=SIG_DFL};sigemptyset(&sa.sa_mask);
        for(int i=1;i<NSIG;++i)if(i!=SIGKILL && i!=SIGSTOP)(void)sigaction(i,&sa,NULL);
        sigset_t mask;sigemptyset(&mask);(void)sigprocmask(SIG_SETMASK,&mask,NULL);
        unsetenv("BASH_PTYBROKER_SERVICE");
        execvp(o->argv[0],o->argv);
child_fail: err=errno;(void)write(child_error[1],&err,sizeof err);_exit(127);
    }
    close(child_error[1]);s->child=pid;s->child_live=1;s->master=master;
    if(pb_wait(child_error[0],POLLIN|POLLHUP,pb_now()+PB_TIMEOUT)<0) {
        err=errno;close(child_error[0]);errno=err;return -1;
    }
    ssize_t n=read(child_error[0],&err,sizeof err);close(child_error[0]);
    if(n==0)return 0;
    errno=n==(ssize_t)sizeof err?err:EIO;return -1;
}
static void handle_request(struct pb_server *s,struct pb_peer *c) {
    struct pb_packet p;
    ssize_t n=recv(c->fd,&p,sizeof p,MSG_TRUNC);
    if(n<0 && (errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return;
    if(n<(ssize_t)PB_HEADER || (size_t)n>sizeof p || p.magic!=PB_MAGIC || p.error ||
       p.size>PB_CHUNK || (size_t)n!=PB_HEADER+p.size || c->role || c->closing || c->terminating) {
        peer_close(c);return;
    }
    struct pb_status st=status_of(s);
    uint32_t reply=p.type+PB_REPLY;
    c->closing=1;
    switch(p.type) {
    case PB_STATUS:
        if(p.size)break;
        (void)queue(c,reply,0,0,&st,sizeof st);return;
    case PB_OPEN_CONTROL: case PB_OPEN_OBSERVER:
        if(p.size)break;
        if(s->stopping){(void)queue(c,reply,ESHUTDOWN,0,NULL,0);return;}
        if((p.type==PB_OPEN_CONTROL && st.controller) ||
           (p.type==PB_OPEN_OBSERVER && st.observers>=PB_OBSERVERS)) {
            (void)queue(c,reply,EBUSY,0,NULL,0);return;
        }
        c->closing=0;c->role=p.type==PB_OPEN_CONTROL?PB_CONTROL:PB_OBSERVE;
        st=status_of(s);
        (void)queue(c,reply,0,s->next,&st,sizeof st);
        (void)queue(c,PB_ATTACHED,0,s->next,&st,sizeof st);
        if(s->next)(void)queue(c,PB_GAP,0,st.oldest,&st,sizeof st);
        if(!s->child_live && s->eof)(void)queue(c,PB_EXIT,0,s->next,&st,sizeof st);
        if(c->role==PB_CONTROL && !s->eof)request_redraw(s);
        return;
    case PB_RESIZE: {
        if(p.size!=2*sizeof(uint32_t))break;
        uint32_t size[2];memcpy(size,p.data,sizeof size);
        if(!size[0]||!size[1]||size[0]>65535||size[1]>65535)break;
        if(s->eof||s->stopping){(void)queue(c,reply,EPIPE,0,NULL,0);return;}
        struct winsize ws={.ws_row=(unsigned short)size[0],.ws_col=(unsigned short)size[1]};
        if(ioctl(s->master,TIOCSWINSZ,&ws)<0){(void)queue(c,reply,errno,0,NULL,0);return;}
        if(s->rows==size[0] && s->cols==size[1])request_redraw(s);
        s->rows=size[0];s->cols=size[1];st=status_of(s);
        broadcast(s,PB_GEOMETRY,s->next,&st,sizeof st);
        (void)queue(c,reply,0,0,NULL,0);return;
    }
    case PB_INPUT:
        if(s->eof || s->stopping){(void)queue(c,reply,EPIPE,0,NULL,0);return;}
        if(p.size>PB_INPUT_LIMIT-s->input_size){(void)queue(c,reply,EAGAIN,0,NULL,0);return;}
        for(size_t i=0;i<p.size;++i)s->input[(s->input_head+s->input_size+i)%PB_INPUT_LIMIT]=p.data[i];
        s->input_size+=p.size;(void)queue(c,reply,0,0,NULL,0);return;
    case PB_CAPTURE: {
        uint64_t end;
        if(p.size!=sizeof end)break;
        memcpy(&end,p.data,sizeof end);
        if(p.offset<st.oldest){(void)queue(c,reply,EOVERFLOW,st.oldest,NULL,0);return;}
        if(end>s->next || end<p.offset)break;
        size_t count=(size_t)(end-p.offset);if(count>PB_CHUNK)count=PB_CHUNK;
        for(size_t i=0;i<count;++i)p.data[i]=s->history[(p.offset+i)%PB_HISTORY];
        (void)queue(c,reply,0,p.offset,p.data,count);return;
    }
    case PB_TERMINATE:
        if(p.size)break;
        c->closing=0;c->terminating=1;begin_stop(s);return;
    default: break;
    }
    (void)queue(c,reply,EINVAL,0,NULL,0);
}
static void accept_peers(struct pb_server *s) {
    for(int n=0;n<8;++n) {
        int fd=accept4(s->listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);
        if(fd<0)return;
        struct ucred cred;socklen_t len=sizeof cred;
        if(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&cred,&len)<0 || cred.uid!=geteuid()) {close(fd);continue;}
        int slot=-1;
        for(int i=0;i<PB_CLIENTS;++i)if(s->peers[i].fd<0){slot=i;break;}
        if(slot<0){close(fd);continue;}
        s->peers[slot].fd=fd;s->peers[slot].opened=pb_now();
    }
}
static void forward_output(struct pb_server *s) {
    for(int tick=0;tick<4;++tick) {
        unsigned char buf[PB_CHUNK];ssize_t n=read(s->master,buf,sizeof buf);
        if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR))return;
        if(n<=0){s->eof=1;s->input_size=0;return;}
        uint64_t off=s->next;
        for(ssize_t i=0;i<n;++i)s->history[(s->next+(uint64_t)i)%PB_HISTORY]=buf[i];
        s->next+=(uint64_t)n;
        broadcast(s,PB_OUTPUT,off,buf,(size_t)n);
    }
}
static void forward_input(struct pb_server *s) {
    if(!s->input_size)return;
    size_t n=PB_INPUT_LIMIT-s->input_head;
    if(n>s->input_size)n=s->input_size;
    if(n>PB_CHUNK)n=PB_CHUNK;
    ssize_t w=write(s->master,s->input+s->input_head,n);
    if(w>0){s->input_head=(s->input_head+(size_t)w)%PB_INPUT_LIMIT;s->input_size-=(size_t)w;}
    else if(w<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)s->input_size=0;
}
int pb_serve(const struct pb_start_options *o,int ready_fd) {
    struct pb_server s={.listener=-1,.master=-1,.exit_status=-1};
    for(int i=0;i<PB_CLIENTS;++i)s.peers[i].fd=-1;
    struct sockaddr_un addr={.sun_family=AF_UNIX};
    char dir[108];int dirfd=-1,own_socket=0,result=-1,saved=0;
    struct stat directory_identity={0},socket_identity={0};
    pb_stop_signal=0;
    struct sigaction sa={.sa_handler=stop_signal};sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGTERM,&sa,NULL);(void)sigaction(SIGINT,&sa,NULL);
    sa.sa_handler=SIG_IGN;(void)sigaction(SIGHUP,&sa,NULL);(void)sigaction(SIGPIPE,&sa,NULL);
    sa.sa_handler=SIG_DFL;(void)sigaction(SIGCHLD,&sa,NULL);
    sigset_t mask;sigemptyset(&mask);(void)sigprocmask(SIG_SETMASK,&mask,NULL);
    (void)fcntl(ready_fd,F_SETFD,FD_CLOEXEC);
    if(pb_path(o->root,o->id,addr.sun_path,sizeof addr.sun_path)<0 || pb_check_root(o->root,0)<0)goto done;
    snprintf(dir,sizeof dir,"%s/%s",o->root,o->id);
    if(mkdir(dir,0700)<0)goto done;
    if(lstat(dir,&directory_identity)<0)goto done;
    if(chmod(dir,0700)<0)goto done;
    dirfd=open(dir,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(dirfd<0 || fstat(dirfd,&directory_identity)<0)goto done;
    if(prctl(PR_SET_CHILD_SUBREAPER,1)<0)goto done;
    /* pidfds are required for identity-safe shutdown, not a best-effort option. */
    int pf=(int)syscall(SYS_pidfd_open,getpid(),0);if(pf<0)goto done;
    int sigcheck=(int)syscall(SYS_pidfd_send_signal,pf,0,NULL,0);saved=errno;close(pf);errno=saved;
    if(sigcheck<0)goto done;
    s.history=malloc(PB_HISTORY);s.input=malloc(PB_INPUT_LIMIT);
    if(!s.history||!s.input)goto done;
    s.listener=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if(s.listener<0)goto done;
    mode_t old=umask(0077);
    int bound=bind(s.listener,(struct sockaddr *)&addr,sizeof addr);
    saved=errno;umask(old);errno=saved;
    if(bound<0)goto done;
    own_socket=1;
    if(fstatat(dirfd,"control.sock",&socket_identity,AT_SYMLINK_NOFOLLOW)<0)goto done;
    if(chmod(addr.sun_path,0600)<0||listen(s.listener,32)<0)goto done;
    s.rows=o->rows;s.cols=o->cols;
    if(spawn_pty(&s,o)<0)goto done;
    struct pb_ready ready={.error=0,.status=status_of(&s)};
    if(send(ready_fd,&ready,sizeof ready,MSG_NOSIGNAL)!=(ssize_t)sizeof ready)goto done;
    char acknowledgement;
    if(pb_wait(ready_fd,POLLIN,pb_now()+PB_TIMEOUT)<0 ||
       recv(ready_fd,&acknowledgement,1,MSG_TRUNC)!=1 || acknowledgement!='G') {
        errno=ECANCELED;goto done;
    }
    close(ready_fd);ready_fd=-1;s.ready=1;
    for(;;) {
        int any=reap_children(&s);
        if(pb_stop_signal)begin_stop(&s);
        if(s.stopping) {
            if(!any)break;
            if(signal_children(pb_now()-s.stop_at<1500?SIGTERM:SIGKILL)<0)goto done;
        }
        if(!s.child_live && s.eof && !s.exit_sent) {
            struct pb_status st=status_of(&s);broadcast(&s,PB_EXIT,s.next,&st,sizeof st);s.exit_sent=1;
        }
        struct pollfd polls[PB_CLIENTS+2];
        polls[0]=(struct pollfd){s.listener,POLLIN,0};
        polls[1]=(struct pollfd){s.eof?-1:s.master,(short)(POLLIN|(s.input_size?POLLOUT:0)),0};
        for(int i=0;i<PB_CLIENTS;++i) {
            struct pb_peer *c=&s.peers[i];
            if(c->fd>=0 && !c->role && !c->terminating && pb_now()-c->opened>500)peer_close(c);
            polls[i+2]=(struct pollfd){c->fd,(short)(POLLIN|(c->head?POLLOUT:0)),0};
        }
        int r=poll(polls,PB_CLIENTS+2,50);
        if(r<0){if(errno==EINTR)continue;goto done;}
        /* Service commands before output, including under a continuous flood. */
        for(int i=0;i<PB_CLIENTS;++i) {
            struct pb_peer *c=&s.peers[i];short re=polls[i+2].revents;
            if(c->fd<0)continue;
            if(re&POLLIN)handle_request(&s,c);
            if(c->fd>=0 && (re&(POLLERR|POLLHUP|POLLNVAL)))peer_close(c);
            if(c->fd>=0 && c->head)flush_peer(c);
        }
        if(polls[0].revents&POLLIN)accept_peers(&s);
        if(polls[1].revents&POLLOUT)forward_input(&s);
        if(polls[1].revents&(POLLIN|POLLHUP|POLLERR))forward_output(&s);
    }
    result=0;
done:
    saved=errno;
    if(s.child>0 && reap_children(&s)) {
        begin_stop(&s);
        /* Failed startup takes the same descendant-aware cleanup path. */
        while(reap_children(&s)) {
            (void)signal_children(pb_now()-s.stop_at<1500?SIGTERM:SIGKILL);
            (void)poll(NULL,0,20);
        }
    }
    if(s.master>=0)close(s.master);
    if(s.listener>=0)close(s.listener);
    /* Remove ownership before replying; immediate ID reuse is safe. */
    struct stat current;
    if(own_socket && dirfd>=0 && fstatat(dirfd,"control.sock",&current,AT_SYMLINK_NOFOLLOW)==0 &&
       current.st_dev==socket_identity.st_dev && current.st_ino==socket_identity.st_ino)
        (void)unlinkat(dirfd,"control.sock",0);
    if(directory_identity.st_ino && lstat(dir,&current)==0 && current.st_dev==directory_identity.st_dev &&
       current.st_ino==directory_identity.st_ino)(void)rmdir(dir);
    if(dirfd>=0)close(dirfd);
    for(int i=0;i<PB_CLIENTS;++i) {
        struct pb_peer *c=&s.peers[i];
        if(c->fd>=0 && c->terminating) {
            struct pb_packet p={.magic=PB_MAGIC,.type=PB_REPLY+PB_TERMINATE,
                                .error=result? (uint32_t)(saved?saved:EIO):0};
            (void)pb_packet_send(c->fd,&p,pb_now()+100);
        }
        peer_close(c);
    }
    if(ready_fd>=0) {
        struct pb_ready failure={.error=saved?saved:EIO};
        (void)send(ready_fd,&failure,sizeof failure,MSG_NOSIGNAL);close(ready_fd);
    }
    free(s.history);free(s.input);errno=saved;return result;
}
