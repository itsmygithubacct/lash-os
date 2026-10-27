#pragma once
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <ucontext.h>

/* A signal can arrive after the queue check but before read/write enters the
 * kernel. Keep that small interval in assembly so the recorder can redirect
 * an interrupted entry to EINTR. Once the syscall has returned, its result
 * (including a partial transfer) must survive signal delivery. This also
 * cancels the kernel's SA_RESTART rewind so guest handlers can run.
 *
 * No descriptor flags are changed: O_NONBLOCK belongs to the shared open file
 * description, and changing it would affect other processes using the file. */
static volatile sig_atomic_t signal_io_active, signal_io_interrupted;
extern long signal_io_syscall(long number, int fd, void *buffer, size_t count,
                              const volatile sig_atomic_t *interrupted);
extern const char signal_io_begin[], signal_io_end[], signal_io_cancel[];

#if defined(__x86_64__)
__asm__(".pushsection .text\n"
        ".global signal_io_syscall, signal_io_begin, signal_io_end, signal_io_cancel\n"
        ".hidden signal_io_syscall, signal_io_begin, signal_io_end, signal_io_cancel\n"
        ".type signal_io_syscall,@function\n"
        "signal_io_syscall:\n"
        "mov %rdi,%rax\n"
        "mov %rsi,%rdi\n"
        "mov %rdx,%rsi\n"
        "mov %rcx,%rdx\n"
        "signal_io_begin:\n"
        "cmpl $0,(%r8)\n"
        "jne signal_io_cancel\n"
        "syscall\n"
        "signal_io_end:\n"
        "ret\n"
        "signal_io_cancel:\n"
        "mov $-4,%rax\n"
        "ret\n"
        ".size signal_io_syscall,.-signal_io_syscall\n"
        ".popsection\n");
#elif defined(__aarch64__)
__asm__(".pushsection .text\n"
        ".balign 4\n"
        ".global signal_io_syscall, signal_io_begin, signal_io_end, signal_io_cancel\n"
        ".hidden signal_io_syscall, signal_io_begin, signal_io_end, signal_io_cancel\n"
        ".type signal_io_syscall,%function\n"
        "signal_io_syscall:\n"
        "mov x8,x0\n"
        "mov x0,x1\n"
        "mov x1,x2\n"
        "mov x2,x3\n"
        "signal_io_begin:\n"
        "ldr w9,[x4]\n"
        "cbnz w9,signal_io_cancel\n"
        "svc #0\n"
        "signal_io_end:\n"
        "ret\n"
        "signal_io_cancel:\n"
        "mov x0,#-4\n"
        "ret\n"
        ".size signal_io_syscall,.-signal_io_syscall\n"
        ".popsection\n");
#elif defined(__riscv) && __riscv_xlen == 64
__asm__(".pushsection .text\n"
        ".balign 4\n"
        ".global signal_io_syscall, signal_io_begin, signal_io_end, signal_io_cancel\n"
        ".hidden signal_io_syscall, signal_io_begin, signal_io_end, signal_io_cancel\n"
        ".type signal_io_syscall,@function\n"
        "signal_io_syscall:\n"
        "mv a7,a0\n"
        "mv a0,a1\n"
        "mv a1,a2\n"
        "mv a2,a3\n"
        "signal_io_begin:\n"
        "lw t0,0(a4)\n"
        "bnez t0,signal_io_cancel\n"
        "ecall\n"
        "signal_io_end:\n"
        "ret\n"
        "signal_io_cancel:\n"
        "li a0,-4\n"
        "ret\n"
        ".size signal_io_syscall,.-signal_io_syscall\n"
        ".popsection\n");
#else
#error Unsupported signal I/O architecture
#endif

static void interrupt_signal_io(void *context) {
    if (!signal_io_active)
        return;
    signal_io_interrupted = 1;
    if (!context)
        return;
    ucontext_t *frame = context;
#if defined(__x86_64__)
    uintptr_t pc = frame->uc_mcontext.gregs[REG_RIP];
#elif defined(__aarch64__)
    uintptr_t pc = frame->uc_mcontext.pc;
#else
    uintptr_t pc = frame->uc_mcontext.__gregs[REG_PC];
#endif
    if (pc < (uintptr_t)signal_io_begin || pc >= (uintptr_t)signal_io_end)
        return;
#if defined(__x86_64__)
    frame->uc_mcontext.gregs[REG_RIP] = (uintptr_t)signal_io_cancel;
#elif defined(__aarch64__)
    frame->uc_mcontext.pc = (uintptr_t)signal_io_cancel;
#else
    frame->uc_mcontext.__gregs[REG_PC] = (uintptr_t)signal_io_cancel;
#endif
}
