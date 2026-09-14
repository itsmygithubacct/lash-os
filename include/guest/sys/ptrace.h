#pragma once
#include_next <sys/ptrace.h>

/* Fixed-width call packing preserves the types of all supplied arguments. */
#include <stdint.h>
long linux_bash_ptrace(long, uint64_t, uint64_t, uint64_t);
#define LBO_ptrace_1(a0) linux_bash_ptrace((long)(a0),0,0,0)
#define LBO_ptrace_2(a0,a1) linux_bash_ptrace((long)(a0),(uint64_t)(uintptr_t)(a1),0,0)
#define LBO_ptrace_3(a0,a1,a2) linux_bash_ptrace((long)(a0),(uint64_t)(uintptr_t)(a1),(uint64_t)(uintptr_t)(a2),0)
#define LBO_ptrace_4(a0,a1,a2,a3) linux_bash_ptrace((long)(a0),(uint64_t)(uintptr_t)(a1),(uint64_t)(uintptr_t)(a2),(uint64_t)(uintptr_t)(a3))
#define LBO_ptrace_PICK(_1,_2,_3,_4,NAME,...) NAME
#define ptrace(...) LBO_ptrace_PICK(__VA_ARGS__,LBO_ptrace_4,LBO_ptrace_3,LBO_ptrace_2,LBO_ptrace_1)(__VA_ARGS__)
