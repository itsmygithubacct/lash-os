#pragma once
/* Picolibc/Capsule differences from the native configure probes. */
#undef HAVE_POSIX_SIGSETJMP
#undef HAVE_SYS_ERRLIST
#undef HAVE_SYS_SIGLIST
#undef HAVE_DECL_SYS_SIGLIST
#define HAVE_DECL_SYS_SIGLIST 0
#undef HAVE_DLOPEN
#undef HAVE_DLCLOSE
#undef HAVE_DLSYM
#undef HAVE_DLERROR
#undef HAVE_GETHOSTBYNAME
#undef HAVE_ARC4RANDOM
#undef HAVE_ARC4RANDOM_UNIFORM
#undef HAVE_EACCESS
#undef HAVE_EUIDACCESS
#undef HAVE_GLIBC_STDIO_EXT
#undef HAVE_STDIO_EXT_H
#undef HAVE_STRUCT_DIRENT_D_FILENO
#undef HAVE_STRUCT_TM_TM_ZONE
#undef HAVE_TM_ZONE
#undef HAVE_DECL___FPURGE
#define HAVE_DECL___FPURGE 1
#undef HAVE___FPURGE
#define HAVE___FPURGE 1
#undef HAVE_DECL_FFLUSH_UNLOCKED
#define HAVE_DECL_FFLUSH_UNLOCKED 0
#undef HAVE_DECL_FPUTS_UNLOCKED
#define HAVE_DECL_FPUTS_UNLOCKED 0
#undef HAVE_DECL_FWRITE_UNLOCKED
#define HAVE_DECL_FWRITE_UNLOCKED 0
#define CONF_HOSTTYPE "bpf"
#define CONF_OSTYPE "linux-capsule"
#define CONF_MACHTYPE "bpf-linux-capsule"
#define CONF_VENDOR "linux-bash-os"
#define LOCALEDIR "/usr/share/locale"
#define PACKAGE "bash"
