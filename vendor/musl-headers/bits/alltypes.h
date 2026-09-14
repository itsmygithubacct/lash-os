/* Type compatibility for musl's Linux extension headers. */
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <wchar.h>
#include <locale.h>
#include <stdarg.h>
#define __BYTE_ORDER 1234
#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#define __LONG_MAX 0x7fffffffffffffffL

#if defined(__NEED_fsblkcnt_t) && !defined(__DEFINED_fsblkcnt_t)
typedef unsigned long fsblkcnt_t;
#define __DEFINED_fsblkcnt_t
#endif

#if defined(__NEED_fsfilcnt_t) && !defined(__DEFINED_fsfilcnt_t)
typedef unsigned long fsfilcnt_t;
#define __DEFINED_fsfilcnt_t
#endif

#if defined(__NEED_pthread_t) && !defined(__DEFINED_pthread_t)
typedef unsigned long pthread_t;
#define __DEFINED_pthread_t
#endif

#if defined(__NEED_pthread_t) && !defined(__DEFINED_pthread_t)
typedef struct __pthread * pthread_t;
#define __DEFINED_pthread_t
#endif

#if defined(__NEED_pthread_once_t) && !defined(__DEFINED_pthread_once_t)
typedef int pthread_once_t;
#define __DEFINED_pthread_once_t
#endif

#if defined(__NEED_pthread_key_t) && !defined(__DEFINED_pthread_key_t)
typedef unsigned pthread_key_t;
#define __DEFINED_pthread_key_t
#endif

#if defined(__NEED_pthread_spinlock_t) && !defined(__DEFINED_pthread_spinlock_t)
typedef int pthread_spinlock_t;
#define __DEFINED_pthread_spinlock_t
#endif

#if defined(__NEED_pthread_mutexattr_t) && !defined(__DEFINED_pthread_mutexattr_t)
typedef struct { unsigned __attr; } pthread_mutexattr_t;
#define __DEFINED_pthread_mutexattr_t
#endif

#if defined(__NEED_pthread_condattr_t) && !defined(__DEFINED_pthread_condattr_t)
typedef struct { unsigned __attr; } pthread_condattr_t;
#define __DEFINED_pthread_condattr_t
#endif

#if defined(__NEED_pthread_barrierattr_t) && !defined(__DEFINED_pthread_barrierattr_t)
typedef struct { unsigned __attr; } pthread_barrierattr_t;
#define __DEFINED_pthread_barrierattr_t
#endif

#if defined(__NEED_pthread_rwlockattr_t) && !defined(__DEFINED_pthread_rwlockattr_t)
typedef struct { unsigned __attr[2]; } pthread_rwlockattr_t;
#define __DEFINED_pthread_rwlockattr_t
#endif

#if defined(__NEED___isoc_va_list) && !defined(__DEFINED___isoc_va_list)
typedef __builtin_va_list __isoc_va_list;
#define __DEFINED___isoc_va_list
#endif

#if defined(__NEED_struct_iovec) && !defined(__DEFINED_struct_iovec)
struct iovec { void *iov_base; size_t iov_len; };
#define __DEFINED_struct_iovec
#endif

#if defined(__NEED_socklen_t) && !defined(__DEFINED_socklen_t)
typedef unsigned socklen_t;
#define __DEFINED_socklen_t
#endif

#if defined(__NEED_sa_family_t) && !defined(__DEFINED_sa_family_t)
typedef unsigned short sa_family_t;
#define __DEFINED_sa_family_t
#endif

#if defined(__NEED_pthread_attr_t) && !defined(__DEFINED_pthread_attr_t)
typedef struct { union { int __i[sizeof(long)==8?14:9]; volatile int __vi[sizeof(long)==8?14:9]; unsigned long __s[sizeof(long)==8?7:9]; } __u; } pthread_attr_t;
#define __DEFINED_pthread_attr_t
#endif

#if defined(__NEED_pthread_mutex_t) && !defined(__DEFINED_pthread_mutex_t)
typedef struct { union { int __i[sizeof(long)==8?10:6]; volatile int __vi[sizeof(long)==8?10:6]; volatile void *volatile __p[sizeof(long)==8?5:6]; } __u; } pthread_mutex_t;
#define __DEFINED_pthread_mutex_t
#endif

#if defined(__NEED_pthread_cond_t) && !defined(__DEFINED_pthread_cond_t)
typedef struct { union { int __i[12]; volatile int __vi[12]; void *__p[12*sizeof(int)/sizeof(void*)]; } __u; } pthread_cond_t;
#define __DEFINED_pthread_cond_t
#endif

#if defined(__NEED_pthread_rwlock_t) && !defined(__DEFINED_pthread_rwlock_t)
typedef struct { union { int __i[sizeof(long)==8?14:8]; volatile int __vi[sizeof(long)==8?14:8]; void *__p[sizeof(long)==8?7:8]; } __u; } pthread_rwlock_t;
#define __DEFINED_pthread_rwlock_t
#endif

#if defined(__NEED_pthread_barrier_t) && !defined(__DEFINED_pthread_barrier_t)
typedef struct { union { int __i[sizeof(long)==8?8:5]; volatile int __vi[sizeof(long)==8?8:5]; void *__p[sizeof(long)==8?4:5]; } __u; } pthread_barrier_t;
#define __DEFINED_pthread_barrier_t
#endif
