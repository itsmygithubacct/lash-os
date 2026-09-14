#pragma once
#include_next <sys/prctl.h>

/* Fixed-width call packing preserves the types of all supplied arguments. */
#include <stdint.h>
int linux_bash_prctl(long, uint64_t, uint64_t, uint64_t, uint64_t);
#define LBO_prctl_1(a0) linux_bash_prctl((long)(a0),0,0,0,0)
#define LBO_prctl_2(a0,a1) linux_bash_prctl((long)(a0),(uint64_t)(uintptr_t)(a1),0,0,0)
#define LBO_prctl_3(a0,a1,a2) linux_bash_prctl((long)(a0),(uint64_t)(uintptr_t)(a1),(uint64_t)(uintptr_t)(a2),0,0)
#define LBO_prctl_4(a0,a1,a2,a3) linux_bash_prctl((long)(a0),(uint64_t)(uintptr_t)(a1),(uint64_t)(uintptr_t)(a2),(uint64_t)(uintptr_t)(a3),0)
#define LBO_prctl_5(a0,a1,a2,a3,a4) linux_bash_prctl((long)(a0),(uint64_t)(uintptr_t)(a1),(uint64_t)(uintptr_t)(a2),(uint64_t)(uintptr_t)(a3),(uint64_t)(uintptr_t)(a4))
#define LBO_prctl_PICK(_1,_2,_3,_4,_5,NAME,...) NAME
#define prctl(...) LBO_prctl_PICK(__VA_ARGS__,LBO_prctl_5,LBO_prctl_4,LBO_prctl_3,LBO_prctl_2,LBO_prctl_1)(__VA_ARGS__)
