/* Picolibc exit() runs atexit handlers before the process bridge. */
#include "bpf_capsule.h"
extern void linux_bash_process_exit(int) __attribute__((noreturn));
__attribute__((noreturn)) void _exit(int status) {
    linux_bash_process_exit(status);
}
__attribute__((noreturn)) void abort(void) {
    capsule_exit(134);
}
