/* Single-thread library primitives. Creating workers and loading native code are
 * deliberately unsupported: native function pointers cannot execute in eBPF. */
#include <errno.h>
#include <pthread.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
static char dynamic_error[] =
    "linux-bash-os: native .so plugins are deferred; rebuild the builtin into the eBPF image";
static int dynamic_pending;
void *dlopen(const char *path, int flags) {
    (void)path;
    (void)flags;
    dynamic_pending = 1;
    errno = ENOTSUP;
    return NULL;
}
void *dlsym(void *handle, const char *name) {
    (void)handle;
    (void)name;
    dynamic_pending = 1;
    errno = ENOTSUP;
    return NULL;
}
int dlclose(void *handle) {
    (void)handle;
    dynamic_pending = 1;
    errno = ENOTSUP;
    return -1;
}
char *dlerror(void) {
    if (!dynamic_pending)
        return NULL;
    dynamic_pending = 0;
    return dynamic_error;
}
int dladdr(const void *address, Dl_info *info) {
    (void)address;
    if (info)
        memset(info, 0, sizeof(*info));
    return 0;
}
/* The static libssh build probes for a dynamic section before calling dladdr. */
uintptr_t _DYNAMIC[2];
pthread_t pthread_self(void) {
    return (pthread_t)(uintptr_t)getpid();
}
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*entry)(void *),
                   void *arg) {
    (void)thread;
    (void)attr;
    (void)entry;
    (void)arg;
    return ENOTSUP;
}
int pthread_join(pthread_t thread, void **result) {
    (void)thread;
    (void)result;
    return ENOTSUP;
}
struct guest_mutex {
    int type, count;
};
_Static_assert(sizeof(pthread_mutex_t) >= sizeof(struct guest_mutex), "mutex storage");
int pthread_mutexattr_init(pthread_mutexattr_t *attr) {
    memset(attr, 0, sizeof(*attr));
    return 0;
}
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr) {
    (void)attr;
    return 0;
}
int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type) {
    if (type < 0 || type > 2)
        return EINVAL;
    memcpy(attr, &type, sizeof(type));
    return 0;
}
int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    memset(mutex, 0, sizeof(*mutex));
    if (attr)
        memcpy(mutex, attr, sizeof(int));
    return 0;
}
int pthread_mutex_destroy(pthread_mutex_t *mutex) {
    return ((struct guest_mutex *)mutex)->count ? EBUSY : 0;
}
int pthread_mutex_trylock(pthread_mutex_t *mutex) {
    struct guest_mutex *m = (void *)mutex;
    if (m->count && m->type != PTHREAD_MUTEX_RECURSIVE)
        return EBUSY;
    m->count++;
    return 0;
}
int pthread_mutex_lock(pthread_mutex_t *mutex) {
    int rc = pthread_mutex_trylock(mutex);
    return rc == EBUSY ? EDEADLK : rc;
}
int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    struct guest_mutex *m = (void *)mutex;
    if (!m->count)
        return EPERM;
    m->count--;
    return 0;
}
int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
    (void)attr;
    memset(cond, 0, sizeof(*cond));
    return 0;
}
int pthread_cond_destroy(pthread_cond_t *cond) {
    (void)cond;
    return 0;
}
int pthread_cond_signal(pthread_cond_t *cond) {
    (void)cond;
    return 0;
}
int pthread_cond_broadcast(pthread_cond_t *cond) {
    (void)cond;
    return 0;
}
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    (void)cond;
    (void)mutex;
    return ENOTSUP;
}
