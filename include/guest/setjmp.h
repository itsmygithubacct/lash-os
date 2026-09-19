#pragma once
#include_next <setjmp.h>
/* Leaving a guest signal handler by longjmp must release the handler's
 * dispatch guard, much as siglongjmp restores the native signal mask. */
void linux_bash_signal_longjmp(void);
#undef longjmp
#define longjmp(env, value) (linux_bash_signal_longjmp(), __bpf_capsule_longjmp(env, value))
