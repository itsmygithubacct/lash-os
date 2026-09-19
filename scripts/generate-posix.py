#!/usr/bin/env python3
"""Generate checked, typed RPC wrappers for ordinary Linux services."""
from pathlib import Path
import argparse,json,re,sys
ROOT=Path(__file__).resolve().parents[1]
# name, return C type, parameters (type, name, host-marshalling), optional native expression
functions = [
 ('chown','int',[('const char *','path','string'),('uid_t','owner','value'),('gid_t','group','value')]),
 ('lchown','int',[('const char *','path','string'),('uid_t','owner','value'),('gid_t','group','value')]),
 ('fchown','int',[('int','descriptor','fd'),('uid_t','owner','value'),('gid_t','group','value')]),
 ('truncate','int',[('const char *','path','string'),('off_t','length','value')]),
 ('ftruncate','int',[('int','descriptor','fd'),('off_t','length','value')]),
 ('pread','ssize_t',[('int','descriptor','fd'),('void *','buffer','bytes:count'),('size_t','count','value'),('off_t','offset','value')]),
 ('pwrite','ssize_t',[('int','descriptor','fd'),('const void *','buffer','bytes:count'),('size_t','count','value'),('off_t','offset','value')]),
 ('readlinkat','ssize_t',[('int','directory','dirfd'),('const char *','path','string'),('char *','buffer','bytes:size'),('size_t','size','value')]),
 ('unlinkat','int',[('int','directory','dirfd'),('const char *','path','string'),('int','flags','atflags')]),
 ('flock','int',[('int','descriptor','fd'),('int','operation','value')]),
 ('posix_fallocate','int',[('int','descriptor','fd'),('off_t','offset','value'),('off_t','length','value')]),
 ('mknod','int',[('const char *','path','string'),('mode_t','mode','value'),('dev_t','device','value')]),
 ('utimes','int',[('const char *','path','string'),('const struct timeval *','times','optional:2*sizeof(struct timeval)')]),
 ('futimens','int',[('int','descriptor','fd'),('const struct timespec *','times','optional:2*sizeof(struct timespec)')]),
 ('getsid','pid_t',[('pid_t','process','value')]),
 ('getpriority','int',[('int','which','value'),('id_t','who','value')]),
 ('setpriority','int',[('int','which','value'),('id_t','who','value'),('int','priority','value')]),
 ('sethostname','int',[('const char *','name','bytes:length'),('size_t','length','value')]),
 ('gethostid','long',[]),
 ('sched_get_priority_max','int',[('int','policy','value')]),
 ('sched_get_priority_min','int',[('int','policy','value')]),
 ('sched_getaffinity','int',[('pid_t','process','value'),('size_t','size','value'),('cpu_set_t *','mask','bytes:size')]),
 ('sched_setaffinity','int',[('pid_t','process','value'),('size_t','size','value'),('const cpu_set_t *','mask','bytes:size')]),
 ('socket','int',[('int','domain','value'),('int','type','value'),('int','protocol','value')]),
 ('bind','int',[('int','descriptor','fd'),('const struct sockaddr *','address','bytes:length'),('socklen_t','length','value')]),
 ('connect','int',[('int','descriptor','fd'),('const struct sockaddr *','address','bytes:length'),('socklen_t','length','value')]),
 ('listen','int',[('int','descriptor','fd'),('int','backlog','value')]),
 ('shutdown','int',[('int','descriptor','fd'),('int','how','value')]),
 ('send','ssize_t',[('int','descriptor','fd'),('const void *','buffer','bytes:size'),('size_t','size','value'),('int','flags','value')]),
 ('recv','ssize_t',[('int','descriptor','fd'),('void *','buffer','bytes:size'),('size_t','size','value'),('int','flags','value')]),
 ('sendto','ssize_t',[('int','descriptor','fd'),('const void *','buffer','bytes:size'),('size_t','size','value'),('int','flags','value'),('const struct sockaddr *','address','optional:length'),('socklen_t','length','value')]),
 ('setsockopt','int',[('int','descriptor','fd'),('int','level','value'),('int','option','value'),('const void *','value','bytes:length'),('socklen_t','length','value')]),
 ('getrandom','ssize_t',[('void *','buffer','bytes:size'),('size_t','size','value'),('unsigned int','flags','value')]),
 ('inotify_init1','int',[('int','flags','openflags')]),
 ('inotify_add_watch','int',[('int','descriptor','fd'),('const char *','path','string'),('uint32_t','mask','value')]),
 ('inotify_rm_watch','int',[('int','descriptor','fd'),('int','watch','value')]),
 ('posix_openpt','int',[('int','flags','openflags')]),
 ('grantpt','int',[('int','descriptor','fd')]),
 ('unlockpt','int',[('int','descriptor','fd')]),
 ('ptsname_r','int',[('int','descriptor','fd'),('char *','buffer','bytes:size'),('size_t','size','value')]),
 ('ttyname_r','int',[('int','descriptor','fd'),('char *','buffer','bytes:size'),('size_t','size','value')]),
 ('tcflow','int',[('int','descriptor','fd'),('int','action','value')]),
 ('shm_unlink','int',[('const char *','name','string')]),
 ('clock_settime','int',[('clockid_t','clock','clock'),('const struct timespec *','value','bytes:sizeof(struct timespec)')]),
 ('adjtime','int',[('const struct timeval *','delta','optional:sizeof(struct timeval)'),('struct timeval *','old','optional:sizeof(struct timeval)')]),
 ('reboot','int',[('int','command','value')]),
 ('swapon','int',[('const char *','path','string'),('int','flags','value')]),
 ('swapoff','int',[('const char *','path','string')]),
 ('umount2','int',[('const char *','path','string'),('int','flags','value')]),
 ('setns','int',[('int','descriptor','fd'),('int','type','value')]),
 ('unshare','int',[('int','flags','value')]),
]
functions += [
 ('rename','int',[('const char *','old','string'),('const char *','new','string')]),
 ('memfd_create','int',[('const char *','name','string'),('unsigned','flags','value')]),
 ('shm_open','int',[('const char *','name','string'),('int','flags','openflags'),('mode_t','mode','value')]),
 ('mount','int',[('const char *','source','optstring'),('const char *','target','string'),('const char *','type','optstring'),('unsigned long','flags','value'),('const void *','data','optstring')]),
 ('initgroups','int',[('const char *','user','string'),('gid_t','group','value')]),
 ('setgroups','int',[('int','count','value'),('const gid_t *','groups','bytes:count*sizeof(gid_t)')]),
 ('setuid','int',[('uid_t','id','value')]),
 ('setgid','int',[('gid_t','id','value')]),
 ('setresuid','int',[('uid_t','r','value'),('uid_t','e','value'),('uid_t','s','value')]),
 ('setresgid','int',[('gid_t','r','value'),('gid_t','e','value'),('gid_t','s','value')]),
 ('setitimer','int',[('int','which','value'),('const struct itimerval *','value','optional:sizeof(struct itimerval)'),('struct itimerval *','old','optional:sizeof(struct itimerval)')]),
 ('statvfs','int',[('const char *','path','string'),('struct statvfs *','out','bytes:sizeof(struct statvfs)')]),
 ('fstatvfs','int',[('int','descriptor','fd'),('struct statvfs *','out','bytes:sizeof(struct statvfs)')]),
 ('epoll_create1','int',[('int','flags','openflags')]),
 ('epoll_wait','int',[('int','descriptor','fd'),('struct epoll_event *','events','bytes:count*sizeof(struct epoll_event)'),('int','count','value'),('int','timeout','value')]),
 ('adjtimex','int',[('struct timex *','value','bytes:sizeof(struct timex)')]),
 ('sched_yield','int',[]),
 ('pause','int',[]),
 ('mlock','int',[('const void *','address','bytes:size'),('size_t','size','value')]),
 ('munlock','int',[('const void *','address','bytes:size'),('size_t','size','value')]),
 ('mlockall','int',[('int','flags','value')]),
 ('munlockall','int',[]),
 ('msgget','int',[('key_t','key','value'),('int','flags','value')]),
 ('shmget','int',[('key_t','key','value'),('size_t','size','value'),('int','flags','value')]),
 ('semget','int',[('key_t','key','value'),('int','count','value'),('int','flags','value')]),
]
functions += [
 ('chroot','int',[('const char *','path','string')]),
 ('utimensat','int',[('int','directory','dirfd'),('const char *','path','string'),('const struct timespec *','times','optional:2*sizeof(struct timespec)'),('int','flags','atflags')]),
 ('clock_getres','int',[('clockid_t','clock','clock'),('struct timespec *','value','optional:sizeof(struct timespec)')]),
 ('times','clock_t',[('struct tms *','value','optional:sizeof(struct tms)')]),
 ('faccessat','int',[('int','directory','dirfd'),('const char *','path','string'),('int','mode','value'),('int','flags','atflags')]),
]
for prefix in ['', 'l', 'f']:
    leading=[('int','descriptor','fd')] if prefix=='f' else [('const char *','path','string')]
    functions += [
      (prefix+'getxattr','ssize_t',leading+[('const char *','name','string'),('void *','value','optional:size'),('size_t','size','value')]),
      (prefix+'setxattr','int',leading+[('const char *','name','string'),('const void *','value','optional:size'),('size_t','size','value'),('int','flags','value')]),
      (prefix+'listxattr','ssize_t',leading+[('char *','list','optional:size'),('size_t','size','value')]),
      (prefix+'removexattr','int',leading+[('const char *','name','string')]),
    ]
for name,result,parameters in functions:
    for index,(t,n,k) in enumerate(parameters):
        if k in {'string','optstring'} and (n=='path' or name=='rename' or (name=='mount' and n in {'source','target'})):
            parameters[index]=(t,n,'path' if k=='string' else 'optpath')
nofollow_paths={'lchown','readlinkat','unlinkat','rename','mknod','lgetxattr','lsetxattr','llistxattr','lremovexattr'}
fd_returns={'socket','inotify_init1','posix_openpt','memfd_create','shm_open','epoll_create1'}
error_returns={'posix_fallocate','ptsname_r','ttyname_r'}
# Guest and host layouts differ here; misc_guest.h and misc_host.h convert them.
converted={'utimes','adjtime','setitimer','statvfs','fstatvfs','epoll_wait','adjtimex'}
host_converted=converted|{'setsockopt'}
# Structures still passed unchanged need one 64-bit Linux layout on both sides.
raw_layouts={
 'struct timespec':['sizeof(struct timespec) == 16','sizeof(((struct timespec *)0)->tv_nsec) == 8'],
 'struct tms':['sizeof(struct tms) == 32'],
 'gid_t':['sizeof(gid_t) == 4'],
}
layouts=[]
for name,result,parameters in functions:
    for t,n,k in parameters:
        for layout in re.findall(r'sizeof\(([^)]+)\)',k) if name not in converted else []:
            if layout not in raw_layouts:
                sys.exit(f'{name}: declare the Linux ABI layout of {layout} or convert it')
            if layout not in layouts:layouts.append(layout)
checks=''.join(f'_Static_assert({check}, "Linux ABI layout: {layout}");\n' for layout in layouts for check in raw_layouts[layout])
banner='/* Generated by scripts/generate-posix.py. */\n'
guest=banner+checks
host=banner+checks+'static int64_t service_posix(struct bridge_host *h, struct posix_request *request) {\n    uint64_t *a=request->args;\n    switch(request->operation) {\n'
header='#pragma once\n#include <stdint.h>\nstruct posix_request { uint64_t operation, args[6]; };\nenum posix_operation {\n'
for ordinal,(name,result,parameters) in enumerate(functions,1):
    header+=f'    PX_{name.upper()} = {ordinal},\n'
    signature=', '.join(t+' '+n for t,n,k in parameters) or 'void'
    packed=[]
    for t,n,k in parameters:
        packed.append('pack_flags('+n+')' if k=='openflags' else '(uintptr_t)'+n if '*' in t else '(uint64_t)'+n)
    packed+=['0']*(6-len(packed))
    if name in converted:
        pass
    elif name in {'setuid','setgid','setresuid','setresgid'}:
        guest+=f'{result} {name}({signature}) {{\n    int rc=posix_bridge(PX_{name.upper()}, '+', '.join(packed)+');\n    return rc;\n}\n'
    elif name in error_returns:
        guest+=f'{result} {name}({signature}) {{\n    int rc=posix_bridge(PX_{name.upper()}, '+', '.join(packed)+');\n    return rc<0?errno:rc;\n}\n'
    else:
        guest+=f'{result} {name}({signature}) {{\n    return posix_bridge(PX_{name.upper()}, '+', '.join(packed)+');\n}\n'
    if name in host_converted:
        continue
    host+=f'    case PX_{name.upper()}: {{\n'
    # Scalars first so dynamic lengths can refer to the argument's name.
    for index,(t,n,k) in enumerate(parameters):
        if k=='value':host+=f'        {t} {n}=({t})a[{index}];\n'
    for index,(t,n,k) in enumerate(parameters):
        if k=='fd':host+=f'        int {n}=fd(h,(int)a[{index}]); if({n}<0)return -1;\n'
        elif k=='dirfd':host+=f'        int {n}=(int)a[{index}]==-2?AT_FDCWD:fd(h,(int)a[{index}]); if({n}<0&&{n}!=AT_FDCWD)return -1;\n'
        elif k=='optstring':host+=f'        {t} {n}=a[{index}]?string(h,a[{index}]):NULL; if(a[{index}]&&!{n})return -1;\n'
        elif k=='string':host+=f'        {t} {n}=string(h,a[{index}]); if(!{n})return -1;\n'
        elif k in {'path','optpath'}:
            at_index=next((i for i,(_,_,kind) in enumerate(parameters) if kind=='atflags'),None)
            follow='0' if name in nofollow_paths else f'!(at_flags(a[{at_index}]) & AT_SYMLINK_NOFOLLOW)' if at_index is not None else '1'
            expression=f'path_string_mode(h,a[{index}],{n}_storage,{follow})'
            host+=f'        char {n}_storage[BRIDGE_PATH_SIZE];\n'
            if k=='optpath':host+=f'        {t} {n}=a[{index}]?{expression}:NULL; if(a[{index}]&&!{n})return -1;\n'
            else:host+=f'        {t} {n}={expression}; if(!{n})return -1;\n'
        elif k=='clock':host+=f'        clockid_t {n}=native_clock(a[{index}]); if({n}<0){{errno=EINVAL;return -1;}}\n'
        elif k=='atflags':host+=f'        int {n}=at_flags(a[{index}]); if({n}<0)return -1;\n'
        elif k=='openflags':host+=f'        int {n}=open_flags(a[{index}]);\n'
        elif k.startswith(('bytes:','optional:')):
            size=k.split(':',1)[1]
            if k.startswith('optional:'):host+=f'        {t} {n}=a[{index}]?memory(h,a[{index}],{size}):NULL; if(a[{index}]&&!{n})return -1;\n'
            else:host+=f'        {t} {n}=memory(h,a[{index}],{size}); if(!{n}&&({size})!=0)return -1;\n'
    call=name+'('+', '.join(n for t,n,k in parameters)+')'
    if name in fd_returns:host+=f'        return save_fd(h,{call},0);\n'
    elif name in error_returns:host+=f'        int error={call}; if(error){{errno=error;return -1;}}return 0;\n'
    else:host+=f'        return {call};\n'
    host+='    }\n'
header+='};\n'
host+='    default: return service_posix_extra(h,request);\n    }\n}\n'
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--host-only',action='store_true',help='Regenerate the host side without touching guest build inputs')
args=parser.parse_args()
if not args.host_only:
    (ROOT/'include/posix_generated.h').write_text(header)
    (ROOT/'src/posix_generated_guest.h').write_text(guest)
(ROOT/'src/posix_generated_host.h').write_text(host)
(ROOT/'config/posix-functions.json').write_text(json.dumps(functions,indent=2)+'\n')
print(f'Generated {len(functions)} typed POSIX adapters')
