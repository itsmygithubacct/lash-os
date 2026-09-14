/* SPDX-License-Identifier: MIT */
/* strace.c — minimal ptrace(2) syscall tracer (ML-T4-01 / Stage missing-
 * loadables T4). Bash-os debug tool. Strace upstream is 50KLoC+; the
 * full thing is out of scope. This is a focused subset that decodes
 * the ~50 most-common Linux syscalls for x86_64/aarch64 and prints them
 * to stderr in roughly strace-compatible shape, including a bounded set
 * of common flag/mode/signal argument decoders.
 *
 * --- SCOPE / SUBSET ---
 *
 * Architecture: x86_64 and aarch64. musl-static.
 *
 * Decoded syscalls (~50; rest print as `syscall_NNN(...)`):
 *   I/O      : read, write, pread64, pwrite64, readv, writev, lseek,
 *              dup, dup2, dup3, pipe, pipe2, fcntl, ioctl
 *   File     : open, openat, close, access, faccessat, stat, fstat,
 *              lstat, newfstatat, getdents64, unlink, unlinkat
 *   Mem      : mmap, mprotect, munmap, brk
 *   Proc     : execve, exit, exit_group, wait4, getpid, getppid,
 *              clone, fork, vfork
 *   Sig      : rt_sigaction, rt_sigprocmask, kill, tgkill
 *   Misc     : arch_prctl, set_tid_address, set_robust_list, prlimit64,
 *              getuid, geteuid, getgid, getegid
 *
 * Output shape per call (stderr):
 *   syscallname(decoded-args) = return-value
 *
 * --- VERBS ---
 *
 *   strace [-f] [-T] [--summary|-c] [-o FILE] [-e trace=LIST] -- COMMAND [ARG...]
 *       Fork+exec COMMAND. Trace it; print one line per syscall to
 *       stderr (or -o FILE). LIST is a comma-separated set of syscall
 *       names or numbers to print. -f enables PTRACE_O_TRACEFORK |
 *       TRACEVFORK | TRACECLONE so children are followed.
 *
 *   strace [-f] [-T] [--summary|-c] [-o FILE] [-e trace=LIST] -p PID
 *       Attach to an existing PID, trace until it exits or the trace is
 *       interrupted, then detach on tracer-side failure paths.
 *
 *   strace --version
 *       Print the subset signature.
 *
 *   strace --help
 *       Brief help.
 *
 * --- LIMITS ---
 *
 * - Strings are decoded by PTRACE_PEEKDATA word reads up to a fixed
 *   80-byte cap then "..." truncated. Embedded NULs terminate the
 *   string. No quoting of unprintable bytes beyond `\n \t \r`.
 * - argv[] / envp[] for execve are not enumerated; only the path is
 *   decoded. This matches what the acceptance test asserts.
 * - openat-family dirfd args decode AT_FDCWD; other dirfd values print
 *   numerically.
 * - struct stat / struct timespec / sockaddr decoders are NOT
 *   implemented; pointer args show as 0xADDR.
 * - Signals delivered to the tracee mid-syscall are forwarded with
 *   `--- SIG... ---` shape, but signo decoding is symbolic for the
 *   common ones only (SIGINT/SIGTERM/SIGSEGV/SIGCHLD).
 * - `-p PID` enumerates `/proc/PID/task` on Linux and attaches already-existing
 *   threads present at attach time. Threads created after attach require `-f`.
 *
 * --- LICENSE ---
 * MIT — same boilerplate shape as other project-local loadables.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <elf.h>

#include "loadables.h"

#define BASHSTRACE_VERSION "0.6 (x86_64/aarch64 ~50-syscall subset, common flag decoders, attach threads)"

/* PTRACE_O_TRACESYSGOOD distinguishes syscall-stops (signo == SIGTRAP|0x80)
 * from real SIGTRAP. Without it we'd have to disambiguate by inspecting
 * the syscall register, which is racier on enter-vs-exit transitions. */
#ifndef PTRACE_O_TRACESYSGOOD
# define PTRACE_O_TRACESYSGOOD 0x00000001
#endif
#ifndef PTRACE_O_TRACEFORK
# define PTRACE_O_TRACEFORK 0x00000002
#endif
#ifndef PTRACE_O_TRACEVFORK
# define PTRACE_O_TRACEVFORK 0x00000004
#endif
#ifndef PTRACE_O_TRACECLONE
# define PTRACE_O_TRACECLONE 0x00000008
#endif
#ifndef PTRACE_O_TRACEEXEC
# define PTRACE_O_TRACEEXEC 0x00000010
#endif
#ifndef PTRACE_O_TRACEEXIT
# define PTRACE_O_TRACEEXIT 0x00000040
#endif

#ifndef NT_PRSTATUS
# define NT_PRSTATUS 1
#endif

/* Architecture syscall-register adapters normalize the active task into this
 * neutral shape before filtering/printing. */
struct bs_syscall_regs {
    long nr;
    unsigned long args[6];
    long ret;
};

#if defined(__aarch64__)
/* musl exposes the kernel regset through ptrace GETREGSET on aarch64, but not
 * every build environment provides a convenient user_pt_regs declaration. */
struct bs_aarch64_user_pt_regs {
    unsigned long long regs[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};
#endif

/* --- syscall-name table (sparse; gaps print as "syscall_NNN") --------- */

struct bs_sc_def {
    int nr;
    const char *name;
    /* argmask: per-arg decoder; lowest 4 bits per arg, six args max.
     * 0=hex/long, 1=string (pointer), 2=fd, 3=int, 4=oflags, 5=ptr,
     * 6=dirfd (AT_FDCWD aware), 7=lseek whence, 8=file mode,
     * 9=access mask, 10=mmap prot, 11=mmap flags, 12=signal,
     * 13=rt_sigprocmask how, 14=fcntl cmd, 15=misc flags.
     * We pack 6 nybbles into a uint32; arg N is at bits (N*4..N*4+3). */
    unsigned int argmask;
    int nargs;
};

enum {
    BS_LONG  = 0,
    BS_STR   = 1,
    BS_FD    = 2,
    BS_INT   = 3,
    BS_OFLG  = 4,
    BS_PTR   = 5,
    BS_DIRFD = 6,
    BS_SEEK  = 7,
    BS_MODE  = 8,
    BS_ACCESS = 9,
    BS_PROT  = 10,
    BS_MMAPF = 11,
    BS_SIG   = 12,
    BS_SIGHOW = 13,
    BS_FCNTL = 14,
    BS_FLAGS = 15,
};

/* Pack up to six arg-kind nybbles into one unsigned int. Function-style
 * macros only — these have to evaluate at file scope as part of the
 * `bs_sc_table` initializer, so a real function call would not work. */
#define M1(a)               ((unsigned)(a))
#define M2(a,b)             ((unsigned)(a) | ((unsigned)(b) << 4))
#define M3(a,b,c)           (M2(a,b) | ((unsigned)(c) << 8))
#define M4(a,b,c,d)         (M3(a,b,c) | ((unsigned)(d) << 12))
#define M5(a,b,c,d,e)       (M4(a,b,c,d) | ((unsigned)(e) << 16))
#define M6(a,b,c,d,e,f)     (M5(a,b,c,d,e) | ((unsigned)(f) << 20))

/* x86_64 syscall numbers per arch/x86/entry/syscalls/syscall_64.tbl.
 * argmask MN packs N kind-nybbles; nargs is the natural-language count
 * for printing (which may exceed the decoded args). */
static const struct bs_sc_def bs_sc_table_x86_64[] = {
    {   0, "read",            M3(BS_FD, BS_PTR, BS_LONG),               3 },
    {   1, "write",           M3(BS_FD, BS_PTR, BS_LONG),               3 },
    {   2, "open",            M3(BS_STR, BS_OFLG, BS_INT),              3 },
    {   3, "close",           M1(BS_FD),                                1 },
    {   4, "stat",            M2(BS_STR, BS_PTR),                       2 },
    {   5, "fstat",           M2(BS_FD, BS_PTR),                        2 },
    {   6, "lstat",           M2(BS_STR, BS_PTR),                       2 },
    {   8, "lseek",           M3(BS_FD, BS_LONG, BS_SEEK),              3 },
    {   9, "mmap",            M6(BS_PTR, BS_LONG, BS_PROT, BS_MMAPF, BS_FD, BS_LONG), 6 },
    {  10, "mprotect",        M3(BS_PTR, BS_LONG, BS_PROT),             3 },
    {  11, "munmap",          M2(BS_PTR, BS_LONG),                      2 },
    {  12, "brk",             M1(BS_PTR),                               1 },
    {  13, "rt_sigaction",    M3(BS_SIG, BS_PTR, BS_PTR),               4 },
    {  14, "rt_sigprocmask",  M3(BS_SIGHOW, BS_PTR, BS_PTR),            4 },
    {  16, "ioctl",           M3(BS_FD, BS_LONG, BS_LONG),              3 },
    {  17, "pread64",         M3(BS_FD, BS_PTR, BS_LONG),               4 },
    {  18, "pwrite64",        M3(BS_FD, BS_PTR, BS_LONG),               4 },
    {  19, "readv",           M3(BS_FD, BS_PTR, BS_INT),                3 },
    {  20, "writev",          M3(BS_FD, BS_PTR, BS_INT),                3 },
    {  21, "access",          M2(BS_STR, BS_ACCESS),                    2 },
    {  22, "pipe",            M1(BS_PTR),                               1 },
    {  32, "dup",             M1(BS_FD),                                1 },
    {  33, "dup2",            M2(BS_FD, BS_FD),                         2 },
    {  39, "getpid",          0,                                        0 },
    {  56, "clone",           M3(BS_LONG, BS_PTR, BS_PTR),              5 },
    {  57, "fork",            0,                                        0 },
    {  58, "vfork",           0,                                        0 },
    {  59, "execve",          M2(BS_STR, BS_PTR),                       3 },
    {  60, "exit",            M1(BS_INT),                               1 },
    {  61, "wait4",           M3(BS_INT, BS_PTR, BS_INT),               4 },
    {  62, "kill",            M2(BS_INT, BS_SIG),                       2 },
    {  72, "fcntl",           M2(BS_FD, BS_FCNTL),                      3 },
    { 102, "getuid",          0,                                        0 },
    { 104, "getgid",          0,                                        0 },
    { 107, "geteuid",         0,                                        0 },
    { 108, "getegid",         0,                                        0 },
    { 110, "getppid",         0,                                        0 },
    { 158, "arch_prctl",      M2(BS_INT, BS_PTR),                       2 },
    { 200, "tgkill",          M3(BS_INT, BS_INT, BS_SIG),               3 },
    { 217, "getdents64",      M3(BS_FD, BS_PTR, BS_LONG),               3 },
    { 218, "set_tid_address", M1(BS_PTR),                               1 },
    { 231, "exit_group",      M1(BS_INT),                               1 },
    { 257, "openat",          M4(BS_DIRFD, BS_STR, BS_OFLG, BS_MODE),   4 },
    { 262, "newfstatat",      M4(BS_DIRFD, BS_STR, BS_PTR, BS_FLAGS),   4 },
    { 263, "unlinkat",        M3(BS_DIRFD, BS_STR, BS_FLAGS),           3 },
    { 269, "faccessat",       M3(BS_DIRFD, BS_STR, BS_ACCESS),          3 },
    { 273, "set_robust_list", M2(BS_PTR, BS_LONG),                      2 },
    { 293, "pipe2",           M2(BS_PTR, BS_INT),                       2 },
    { 302, "prlimit64",       M4(BS_INT, BS_INT, BS_PTR, BS_PTR),       4 },
    { 318, "getrandom",       M3(BS_PTR, BS_LONG, BS_FLAGS),            3 },
    {  -1, NULL,              0,                                        0 }
};

/* aarch64 syscall numbers per include/uapi/asm-generic/unistd.h. The arm64
 * table intentionally omits x86_64-only legacy names such as open/stat/lstat,
 * fork/vfork, dup2, pipe, and arch_prctl. */
static const struct bs_sc_def bs_sc_table_aarch64[] = {
    {  23, "dup",             M1(BS_FD),                                1 },
    {  24, "dup3",            M3(BS_FD, BS_FD, BS_INT),                 3 },
    {  25, "fcntl",           M2(BS_FD, BS_FCNTL),                      3 },
    {  29, "ioctl",           M3(BS_FD, BS_LONG, BS_LONG),              3 },
    {  34, "mkdirat",         M3(BS_DIRFD, BS_STR, BS_MODE),            3 },
    {  35, "unlinkat",        M3(BS_DIRFD, BS_STR, BS_FLAGS),           3 },
    {  37, "linkat",          M4(BS_DIRFD, BS_STR, BS_DIRFD, BS_STR),   5 },
    {  38, "renameat",        M4(BS_DIRFD, BS_STR, BS_DIRFD, BS_STR),   4 },
    {  47, "faccessat",       M3(BS_DIRFD, BS_STR, BS_ACCESS),          3 },
    {  56, "openat",          M4(BS_DIRFD, BS_STR, BS_OFLG, BS_MODE),   4 },
    {  57, "close",           M1(BS_FD),                                1 },
    {  59, "pipe2",           M2(BS_PTR, BS_INT),                       2 },
    {  62, "lseek",           M3(BS_FD, BS_LONG, BS_SEEK),              3 },
    {  63, "read",            M3(BS_FD, BS_PTR, BS_LONG),               3 },
    {  64, "write",           M3(BS_FD, BS_PTR, BS_LONG),               3 },
    {  65, "readv",           M3(BS_FD, BS_PTR, BS_INT),                3 },
    {  66, "writev",          M3(BS_FD, BS_PTR, BS_INT),                3 },
    {  67, "pread64",         M3(BS_FD, BS_PTR, BS_LONG),               4 },
    {  68, "pwrite64",        M3(BS_FD, BS_PTR, BS_LONG),               4 },
    {  78, "readlinkat",      M4(BS_DIRFD, BS_STR, BS_PTR, BS_LONG),    4 },
    {  79, "newfstatat",      M4(BS_DIRFD, BS_STR, BS_PTR, BS_INT),     4 },
    {  80, "fstat",           M2(BS_FD, BS_PTR),                        2 },
    {  93, "exit",            M1(BS_INT),                               1 },
    {  94, "exit_group",      M1(BS_INT),                               1 },
    { 113, "clock_gettime",   M2(BS_INT, BS_PTR),                       2 },
    { 130, "tgkill",          M3(BS_INT, BS_INT, BS_SIG),               3 },
    { 131, "tkill",           M2(BS_INT, BS_SIG),                       2 },
    { 134, "rt_sigaction",    M3(BS_SIG, BS_PTR, BS_PTR),               4 },
    { 135, "rt_sigprocmask",  M3(BS_SIGHOW, BS_PTR, BS_PTR),            4 },
    { 160, "uname",           M1(BS_PTR),                               1 },
    { 169, "gettimeofday",    M2(BS_PTR, BS_PTR),                       2 },
    { 172, "getpid",          0,                                        0 },
    { 173, "getppid",         0,                                        0 },
    { 174, "getuid",          0,                                        0 },
    { 175, "geteuid",         0,                                        0 },
    { 176, "getgid",          0,                                        0 },
    { 177, "getegid",         0,                                        0 },
    { 178, "gettid",          0,                                        0 },
    { 214, "brk",             M1(BS_PTR),                               1 },
    { 215, "munmap",          M2(BS_PTR, BS_LONG),                      2 },
    { 220, "clone",           M3(BS_LONG, BS_PTR, BS_PTR),              5 },
    { 221, "execve",          M2(BS_STR, BS_PTR),                       3 },
    { 222, "mmap",            M6(BS_PTR, BS_LONG, BS_PROT, BS_MMAPF, BS_FD, BS_LONG), 6 },
    { 226, "mprotect",        M3(BS_PTR, BS_LONG, BS_PROT),             3 },
    { 233, "madvise",         M3(BS_PTR, BS_LONG, BS_FLAGS),            3 },
    { 260, "wait4",           M3(BS_INT, BS_PTR, BS_INT),               4 },
    { 261, "prlimit64",       M4(BS_INT, BS_INT, BS_PTR, BS_PTR),       4 },
    { 278, "getrandom",       M3(BS_PTR, BS_LONG, BS_FLAGS),            3 },
    { 293, "rseq",            M4(BS_PTR, BS_LONG, BS_FLAGS, BS_LONG),   4 },
    {  -1, NULL,              0,                                        0 }
};

static const struct bs_sc_def *
bs_active_sc_table(void)
{
#if defined(__aarch64__)
    return bs_sc_table_aarch64;
#else
    return bs_sc_table_x86_64;
#endif
}

static const struct bs_sc_def *
bs_lookup(int nr)
{
    const struct bs_sc_def *table = bs_active_sc_table();
    for (int i = 0; table[i].name; i++)
        if (table[i].nr == nr) return &table[i];
    return NULL;
}

static int
bs_lookup_nr(const char *name, int *nr_out)
{
    if (!name || !*name) return -1;
    if (!strncmp(name, "syscall_", 8))
        name += 8;
    char *end = NULL;
    errno = 0;
    long v = strtol(name, &end, 10);
    if (!errno && end && *end == '\0' && v >= 0 && v < 512) {
        *nr_out = (int)v;
        return 0;
    }
    const struct bs_sc_def *table = bs_active_sc_table();
    for (int i = 0; table[i].name; i++) {
        if (!strcmp(table[i].name, name)) {
            *nr_out = table[i].nr;
            return 0;
        }
    }
    return -1;
}

/* --- output sink ------------------------------------------------------ */
/* We buffer at line granularity to keep tracer+tracee interleavings
 * readable when -f follows children. */
static FILE *bs_out = NULL;
static volatile sig_atomic_t bs_stop = 0;
static volatile sig_atomic_t bs_stop_sig = 0;

static void bs_emit(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(bs_out, fmt, ap);
    va_end(ap);
    fflush(bs_out);
}

static void
bs_stop_handler(int signo)
{
    bs_stop = 1;
    bs_stop_sig = signo;
}

/* --- string peek ------------------------------------------------------ */
/* Read NUL-terminated string from tracee at `addr`, up to MAX bytes.
 * Buffer is caller-owned; result is always NUL-terminated. */
static void
bs_peek_string(pid_t pid, unsigned long addr, char *buf, size_t cap)
{
    size_t off = 0;
    buf[0] = '\0';
    if (addr == 0) return;
    while (off + sizeof(long) <= cap) {
        errno = 0;
        long w = ptrace(PTRACE_PEEKDATA, pid, addr + off, NULL);
        if (errno) { buf[off] = '\0'; return; }
        memcpy(buf + off, &w, sizeof(long));
        for (size_t i = 0; i < sizeof(long); i++) {
            if (buf[off + i] == '\0') return;  /* hit NUL inside this word */
        }
        off += sizeof(long);
    }
    buf[cap - 1] = '\0';
}

/* Print a quoted-string representation suitable for the trace line.
 * - At most 80 bytes shown; truncated as "..." past that.
 * - \n \t \r as backslash escapes; everything else printable as-is;
 *   non-printables shown as \xNN. */
static void
bs_print_quoted(unsigned long addr, pid_t pid)
{
    if (addr == 0) { bs_emit("NULL"); return; }
    char raw[256];
    bs_peek_string(pid, addr, raw, sizeof(raw));
    size_t n = strlen(raw);
    size_t cap = n > 80 ? 80 : n;
    fputc('"', bs_out);
    for (size_t i = 0; i < cap; i++) {
        unsigned char c = (unsigned char)raw[i];
        switch (c) {
            case '\n': fputs("\\n", bs_out); break;
            case '\t': fputs("\\t", bs_out); break;
            case '\r': fputs("\\r", bs_out); break;
            case '\\': fputs("\\\\", bs_out); break;
            case '"':  fputs("\\\"", bs_out); break;
            default:
                if (c >= 32 && c < 127) fputc(c, bs_out);
                else fprintf(bs_out, "\\x%02x", c);
        }
    }
    fputc('"', bs_out);
    if (n > 80) fputs("...", bs_out);
}

/* --- arg printer ------------------------------------------------------ */

static void
bs_print_or_list(const char **sep, const char *name)
{
    bs_emit("%s%s", *sep, name);
    *sep = "|";
}

static void
bs_print_mode(unsigned long mode)
{
    bs_emit("0%lo", mode & 07777UL);
}

static void
bs_print_access_mask(unsigned long mask)
{
    if (mask == F_OK) {
        bs_emit("F_OK");
        return;
    }
    const char *sep = "";
    if (mask & R_OK) bs_print_or_list(&sep, "R_OK");
    if (mask & W_OK) bs_print_or_list(&sep, "W_OK");
    if (mask & X_OK) bs_print_or_list(&sep, "X_OK");
    mask &= ~(unsigned long)(R_OK | W_OK | X_OK);
    if (mask) bs_emit("%s0x%lx", sep, mask);
}

static void
bs_print_prot(unsigned long prot)
{
    if (prot == PROT_NONE) {
        bs_emit("PROT_NONE");
        return;
    }
    const char *sep = "";
    if (prot & PROT_READ)  bs_print_or_list(&sep, "PROT_READ");
    if (prot & PROT_WRITE) bs_print_or_list(&sep, "PROT_WRITE");
    if (prot & PROT_EXEC)  bs_print_or_list(&sep, "PROT_EXEC");
    prot &= ~(unsigned long)(PROT_READ | PROT_WRITE | PROT_EXEC);
    if (prot) bs_emit("%s0x%lx", sep, prot);
}

static void
bs_print_mmap_flags(unsigned long flags)
{
    const char *sep = "";
#ifdef MAP_SHARED
    if ((flags & MAP_SHARED) == MAP_SHARED) bs_print_or_list(&sep, "MAP_SHARED");
#endif
#ifdef MAP_PRIVATE
    if ((flags & MAP_PRIVATE) == MAP_PRIVATE) bs_print_or_list(&sep, "MAP_PRIVATE");
#endif
#ifdef MAP_FIXED
    if (flags & MAP_FIXED) bs_print_or_list(&sep, "MAP_FIXED");
#endif
#ifdef MAP_ANONYMOUS
    if (flags & MAP_ANONYMOUS) bs_print_or_list(&sep, "MAP_ANONYMOUS");
#elif defined(MAP_ANON)
    if (flags & MAP_ANON) bs_print_or_list(&sep, "MAP_ANON");
#endif
#ifdef MAP_GROWSDOWN
    if (flags & MAP_GROWSDOWN) bs_print_or_list(&sep, "MAP_GROWSDOWN");
#endif
#ifdef MAP_DENYWRITE
    if (flags & MAP_DENYWRITE) bs_print_or_list(&sep, "MAP_DENYWRITE");
#endif
#ifdef MAP_EXECUTABLE
    if (flags & MAP_EXECUTABLE) bs_print_or_list(&sep, "MAP_EXECUTABLE");
#endif
#ifdef MAP_LOCKED
    if (flags & MAP_LOCKED) bs_print_or_list(&sep, "MAP_LOCKED");
#endif
#ifdef MAP_POPULATE
    if (flags & MAP_POPULATE) bs_print_or_list(&sep, "MAP_POPULATE");
#endif
#ifdef MAP_NONBLOCK
    if (flags & MAP_NONBLOCK) bs_print_or_list(&sep, "MAP_NONBLOCK");
#endif
#ifdef MAP_STACK
    if (flags & MAP_STACK) bs_print_or_list(&sep, "MAP_STACK");
#endif
#ifdef MAP_HUGETLB
    if (flags & MAP_HUGETLB) bs_print_or_list(&sep, "MAP_HUGETLB");
#endif
    unsigned long known = 0;
#ifdef MAP_SHARED
    known |= MAP_SHARED;
#endif
#ifdef MAP_PRIVATE
    known |= MAP_PRIVATE;
#endif
#ifdef MAP_FIXED
    known |= MAP_FIXED;
#endif
#ifdef MAP_ANONYMOUS
    known |= MAP_ANONYMOUS;
#elif defined(MAP_ANON)
    known |= MAP_ANON;
#endif
#ifdef MAP_GROWSDOWN
    known |= MAP_GROWSDOWN;
#endif
#ifdef MAP_DENYWRITE
    known |= MAP_DENYWRITE;
#endif
#ifdef MAP_EXECUTABLE
    known |= MAP_EXECUTABLE;
#endif
#ifdef MAP_LOCKED
    known |= MAP_LOCKED;
#endif
#ifdef MAP_POPULATE
    known |= MAP_POPULATE;
#endif
#ifdef MAP_NONBLOCK
    known |= MAP_NONBLOCK;
#endif
#ifdef MAP_STACK
    known |= MAP_STACK;
#endif
#ifdef MAP_HUGETLB
    known |= MAP_HUGETLB;
#endif
    flags &= ~known;
    if (flags) bs_emit("%s0x%lx", sep, flags);
    else if (!*sep) bs_emit("0");
}

static const char *
bs_signal_name(long sig)
{
    switch ((int)sig) {
        case SIGHUP:  return "SIGHUP";
        case SIGINT:  return "SIGINT";
        case SIGQUIT: return "SIGQUIT";
        case SIGILL:  return "SIGILL";
        case SIGABRT: return "SIGABRT";
        case SIGFPE:  return "SIGFPE";
        case SIGKILL: return "SIGKILL";
        case SIGSEGV: return "SIGSEGV";
        case SIGPIPE: return "SIGPIPE";
        case SIGALRM: return "SIGALRM";
        case SIGTERM: return "SIGTERM";
        case SIGUSR1: return "SIGUSR1";
        case SIGUSR2: return "SIGUSR2";
        case SIGCHLD: return "SIGCHLD";
        case SIGCONT: return "SIGCONT";
        case SIGSTOP: return "SIGSTOP";
        case SIGTSTP: return "SIGTSTP";
        case SIGTTIN: return "SIGTTIN";
        case SIGTTOU: return "SIGTTOU";
        default:      return NULL;
    }
}

static void
bs_print_signal(long sig)
{
    const char *name = bs_signal_name(sig);
    if (name) bs_emit("%s", name);
    else bs_emit("%ld", sig);
}

static void
bs_print_sigmask_how(long how)
{
    switch ((int)how) {
        case SIG_BLOCK:   bs_emit("SIG_BLOCK"); break;
        case SIG_UNBLOCK: bs_emit("SIG_UNBLOCK"); break;
        case SIG_SETMASK: bs_emit("SIG_SETMASK"); break;
        default:          bs_emit("%ld", how); break;
    }
}

static void
bs_print_fcntl_cmd(long cmd)
{
    switch ((int)cmd) {
        case F_DUPFD:    bs_emit("F_DUPFD"); break;
        case F_GETFD:    bs_emit("F_GETFD"); break;
        case F_SETFD:    bs_emit("F_SETFD"); break;
        case F_GETFL:    bs_emit("F_GETFL"); break;
        case F_SETFL:    bs_emit("F_SETFL"); break;
        case F_GETLK:    bs_emit("F_GETLK"); break;
        case F_SETLK:    bs_emit("F_SETLK"); break;
        case F_SETLKW:   bs_emit("F_SETLKW"); break;
#ifdef F_DUPFD_CLOEXEC
        case F_DUPFD_CLOEXEC: bs_emit("F_DUPFD_CLOEXEC"); break;
#endif
        default:         bs_emit("%ld", cmd); break;
    }
}

static void
bs_print_misc_flags(unsigned long flags)
{
    const char *sep = "";
#ifdef AT_SYMLINK_NOFOLLOW
    if (flags & AT_SYMLINK_NOFOLLOW) bs_print_or_list(&sep, "AT_SYMLINK_NOFOLLOW");
#endif
#ifdef AT_REMOVEDIR
    if (flags & AT_REMOVEDIR) bs_print_or_list(&sep, "AT_REMOVEDIR");
#endif
#ifdef AT_EACCESS
    if (flags & AT_EACCESS) bs_print_or_list(&sep, "AT_EACCESS");
#endif
#ifdef AT_EMPTY_PATH
    if (flags & AT_EMPTY_PATH) bs_print_or_list(&sep, "AT_EMPTY_PATH");
#endif
#ifdef WNOHANG
    if (flags & WNOHANG) bs_print_or_list(&sep, "WNOHANG");
#endif
#ifdef WUNTRACED
    if (flags & WUNTRACED) bs_print_or_list(&sep, "WUNTRACED");
#endif
#ifdef WCONTINUED
    if (flags & WCONTINUED) bs_print_or_list(&sep, "WCONTINUED");
#endif
#ifdef GRND_NONBLOCK
    if (flags & GRND_NONBLOCK) bs_print_or_list(&sep, "GRND_NONBLOCK");
#endif
#ifdef GRND_RANDOM
    if (flags & GRND_RANDOM) bs_print_or_list(&sep, "GRND_RANDOM");
#endif
    unsigned long known = 0;
#ifdef AT_SYMLINK_NOFOLLOW
    known |= AT_SYMLINK_NOFOLLOW;
#endif
#ifdef AT_REMOVEDIR
    known |= AT_REMOVEDIR;
#endif
#ifdef AT_EACCESS
    known |= AT_EACCESS;
#endif
#ifdef AT_EMPTY_PATH
    known |= AT_EMPTY_PATH;
#endif
#ifdef WNOHANG
    known |= WNOHANG;
#endif
#ifdef WUNTRACED
    known |= WUNTRACED;
#endif
#ifdef WCONTINUED
    known |= WCONTINUED;
#endif
#ifdef GRND_NONBLOCK
    known |= GRND_NONBLOCK;
#endif
#ifdef GRND_RANDOM
    known |= GRND_RANDOM;
#endif
    flags &= ~known;
    if (flags) bs_emit("%s0x%lx", sep, flags);
    else if (!*sep) bs_emit("0");
}

static void
bs_print_arg(int kind, unsigned long val, pid_t pid)
{
    switch (kind) {
        case BS_FD:
            bs_emit("%d", (int)(long)val);
            break;
        case BS_DIRFD:
            if ((int)(long)val == AT_FDCWD)
                bs_emit("AT_FDCWD");
            else
                bs_emit("%d", (int)(long)val);
            break;
        case BS_SEEK:
            switch ((int)(long)val) {
                case SEEK_SET: bs_emit("SEEK_SET"); break;
                case SEEK_CUR: bs_emit("SEEK_CUR"); break;
                case SEEK_END: bs_emit("SEEK_END"); break;
                default:       bs_emit("%d", (int)(long)val); break;
            }
            break;
        case BS_INT:
            bs_emit("%d", (int)(long)val);
            break;
        case BS_STR:
            bs_print_quoted(val, pid);
            break;
        case BS_OFLG: {
            /* Decode the common O_* combinations. */
            unsigned long f = val;
            int acc = f & 3;
            const char *accs = acc == 0 ? "O_RDONLY"
                             : acc == 1 ? "O_WRONLY"
                             : acc == 2 ? "O_RDWR"   : "O_ACCMODE";
            bs_emit("%s", accs);
            if (f & 0x40)     bs_emit("|O_CREAT");
            if (f & 0x80)     bs_emit("|O_EXCL");
            if (f & 0x200)    bs_emit("|O_TRUNC");
            if (f & 0x400)    bs_emit("|O_APPEND");
            if (f & 0x800)    bs_emit("|O_NONBLOCK");
            if (f & 0x80000)  bs_emit("|O_CLOEXEC");
            if (f & 0x10000)  bs_emit("|O_DIRECTORY");
            break;
        }
        case BS_MODE:
            bs_print_mode(val);
            break;
        case BS_ACCESS:
            bs_print_access_mask(val);
            break;
        case BS_PROT:
            bs_print_prot(val);
            break;
        case BS_MMAPF:
            bs_print_mmap_flags(val);
            break;
        case BS_SIG:
            bs_print_signal((long)val);
            break;
        case BS_SIGHOW:
            bs_print_sigmask_how((long)val);
            break;
        case BS_FCNTL:
            bs_print_fcntl_cmd((long)val);
            break;
        case BS_FLAGS:
            bs_print_misc_flags(val);
            break;
        case BS_PTR:
        case BS_LONG:
        default:
            if (val == 0) bs_emit("NULL");
            else if ((long)val > -4096L && (long)val < 4096L)
                bs_emit("%ld", (long)val);
            else
                bs_emit("0x%lx", val);
            break;
    }
}

static int
bs_read_syscall_regs(pid_t pid, struct bs_syscall_regs *out)
{
    memset(out, 0, sizeof(*out));
#if defined(__x86_64__)
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0)
        return -1;
    out->nr = (long)r.orig_rax;
    out->args[0] = r.rdi;
    out->args[1] = r.rsi;
    out->args[2] = r.rdx;
    out->args[3] = r.r10;
    out->args[4] = r.r8;
    out->args[5] = r.r9;
    out->ret = (long)r.rax;
    return 0;
#elif defined(__aarch64__)
    struct bs_aarch64_user_pt_regs r;
    struct iovec iov;
    memset(&r, 0, sizeof(r));
    iov.iov_base = &r;
    iov.iov_len = sizeof(r);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov) < 0)
        return -1;
    out->nr = (long)r.regs[8];
    for (int i = 0; i < 6; i++)
        out->args[i] = (unsigned long)r.regs[i];
    out->ret = (long)r.regs[0];
    return 0;
#else
    errno = ENOSYS;
    (void)pid;
    return -1;
#endif
}

static int
bs_is_entry_stop(const struct bs_syscall_regs *r)
{
    return r->ret == -ENOSYS;
}

static int
bs_is_exit_syscall(long nr)
{
    const struct bs_sc_def *d = bs_lookup((int)nr);
    return d && (!strcmp(d->name, "exit") || !strcmp(d->name, "exit_group"));
}

/* --- syscall printer -------------------------------------------------- */
static void
bs_print_elapsed(double elapsed_sec)
{
    if (elapsed_sec >= 0.0)
        bs_emit(" <%.6f>", elapsed_sec);
}

static void
bs_print_syscall(pid_t pid, const struct bs_syscall_regs *r, int on_exit, double elapsed_sec)
{
    int nr = (int)r->nr;
    const struct bs_sc_def *d = bs_lookup(nr);

    if (!on_exit) {
        if (d) {
            bs_emit("[pid %d] %s(", (int)pid, d->name);
            int n = d->nargs;
            if (n > 6) n = 6;
            for (int i = 0; i < n; i++) {
                if (i) bs_emit(", ");
                int kind = (d->argmask >> (i * 4)) & 0xf;
                bs_print_arg(kind, r->args[i], pid);
            }
            bs_emit(")");
        } else {
            bs_emit("[pid %d] syscall_%d(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)",
                    (int)pid, nr, r->args[0], r->args[1], r->args[2],
                    r->args[3], r->args[4], r->args[5]);
        }
        return;
    }

    /* on_exit: append the return-value tail. exit/exit_group never
     * resume to syscall-exit; the caller skips this branch for them. */
    long ret = r->ret;
    if (ret < 0 && ret >= -4096L) {
        bs_emit(" = -1 errno=%ld", -ret);
    } else if (d && (!strcmp(d->name, "mmap") || !strcmp(d->name, "brk"))) {
        bs_emit(" = 0x%lx", (unsigned long)ret);
    } else {
        bs_emit(" = %ld", ret);
    }
    bs_print_elapsed(elapsed_sec);
    bs_emit("\n");
}

/* --- tracer core ------------------------------------------------------ */

struct bs_state {
    int follow;     /* -f */
    int timing;     /* -T: append per-syscall elapsed time */
    int summary;    /* --summary / -c: counts/errors table, suppress per-call lines */
    int filter_enabled;
    unsigned char trace_filter[512];
    struct {
        unsigned long calls;
        unsigned long errors;
    } summary_counts[512];
    /* Per-PID syscall-entry tracking; tiny linear table covers a few
     * hundred PIDs which is more than enough for `strace echo hi`. */
    struct {
        pid_t pid;
        int in_syscall;
        int printed_entry;
        long last_nr;
        struct timespec enter_ts;
    } slots[256];
    int nslots;
};

static const char *
bs_syscall_name(int nr, char *buf, size_t bufsz)
{
    const struct bs_sc_def *d = bs_lookup(nr);
    if (d) return d->name;
    snprintf(buf, bufsz, "syscall_%d", nr);
    return buf;
}

struct bs_child_guard {
    struct sigaction old_chld;
    sigset_t oldmask;
};

static int
bs_child_guard_begin(struct bs_child_guard *g)
{
    struct sigaction dfl;
    sigset_t block;
    memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    if (sigaction(SIGCHLD, &dfl, &g->old_chld) < 0)
        return -1;
    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &block, &g->oldmask) < 0) {
        sigaction(SIGCHLD, &g->old_chld, NULL);
        return -1;
    }
    return 0;
}

static void
bs_child_guard_parent_end(struct bs_child_guard *g)
{
    sigprocmask(SIG_SETMASK, &g->oldmask, NULL);
    sigaction(SIGCHLD, &g->old_chld, NULL);
}

static void
bs_child_guard_child_end(struct bs_child_guard *g)
{
    sigprocmask(SIG_SETMASK, &g->oldmask, NULL);
}

static int
bs_live_slots(struct bs_state *st)
{
    int n = 0;
    for (int i = 0; i < st->nslots; i++)
        if (st->slots[i].pid > 0) n++;
    return n;
}

static int
bs_slot_for(struct bs_state *st, pid_t pid)
{
    for (int i = 0; i < st->nslots; i++)
        if (st->slots[i].pid == pid) return i;
    if (st->nslots >= 256) return -1;
    int i = st->nslots++;
    st->slots[i].pid = pid;
    st->slots[i].in_syscall = 0;
    st->slots[i].printed_entry = 0;
    st->slots[i].last_nr = -1;
    memset(&st->slots[i].enter_ts, 0, sizeof st->slots[i].enter_ts);
    return i;
}

static double
bs_elapsed_since(const struct timespec *start)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1.0;
    time_t sec = now.tv_sec - start->tv_sec;
    long nsec = now.tv_nsec - start->tv_nsec;
    if (nsec < 0) { sec--; nsec += 1000000000L; }
    return (double)sec + (double)nsec / 1000000000.0;
}

static int
bs_should_print(struct bs_state *st, long nr)
{
    if (!st->filter_enabled)
        return 1;
    if (nr < 0 || nr >= 512)
        return 0;
    return st->trace_filter[nr] != 0;
}

static int
bs_parse_trace_filter(struct bs_state *st, const char *spec)
{
    if (!spec || !*spec) {
        builtin_error("-e trace=: empty syscall list");
        return EX_USAGE;
    }
    if (!strncmp(spec, "trace=", 6))
        spec += 6;
    if (!strcmp(spec, "all")) {
        st->filter_enabled = 0;
        memset(st->trace_filter, 0, sizeof(st->trace_filter));
        return EXECUTION_SUCCESS;
    }
    st->filter_enabled = 1;
    memset(st->trace_filter, 0, sizeof(st->trace_filter));
    if (!strcmp(spec, "none"))
        return EXECUTION_SUCCESS;

    char *copy = strdup(spec);
    if (!copy) {
        builtin_error("out of memory");
        return EXECUTION_FAILURE;
    }
    int rc = EXECUTION_SUCCESS;
    for (char *tok = strtok(copy, ","); tok; tok = strtok(NULL, ",")) {
        int nr = -1;
        if (bs_lookup_nr(tok, &nr) < 0) {
            builtin_error("-e trace=: unknown syscall '%s'", tok);
            rc = EX_USAGE;
            break;
        }
        st->trace_filter[nr] = 1;
    }
    free(copy);
    return rc;
}

static void
bs_summary_record(struct bs_state *st, long nr, long ret, int has_ret)
{
    if (nr < 0 || nr >= 512) return;
    if (!bs_should_print(st, nr)) return;
    st->summary_counts[nr].calls++;
    if (has_ret && ret < 0 && ret >= -4096L)
        st->summary_counts[nr].errors++;
}

static void
bs_print_summary(struct bs_state *st)
{
    bs_emit("%-18s %8s %8s\n", "syscall", "calls", "errors");
    for (int nr = 0; nr < 512; nr++) {
        if (!st->summary_counts[nr].calls) continue;
        char namebuf[32];
        bs_emit("%-18s %8lu %8lu\n",
                bs_syscall_name(nr, namebuf, sizeof namebuf),
                st->summary_counts[nr].calls,
                st->summary_counts[nr].errors);
    }
}

static int
bs_set_trace_options(struct bs_state *st, pid_t pid)
{
    long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC;
    if (st->follow)
        opts |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, opts) < 0) {
        builtin_error("PTRACE_SETOPTIONS: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static void
bs_detach_all(struct bs_state *st)
{
    for (int i = 0; i < st->nslots; i++) {
        if (st->slots[i].pid > 0) {
            ptrace(PTRACE_DETACH, st->slots[i].pid, NULL, NULL);
            st->slots[i].pid = -1;
        }
    }
}

static int
bs_enumerate_tasks(pid_t pid, pid_t *tasks, int max_tasks)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%ld/task", (long)pid);
    DIR *dir = opendir(path);
    if (!dir) {
        tasks[0] = pid;
        return 1;
    }

    int n = 0;
    int have_pid = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        char *end = NULL;
        errno = 0;
        long v = strtol(de->d_name, &end, 10);
        if (errno || !end || *end != '\0' || v <= 0)
            continue;
        if ((pid_t)v == pid)
            have_pid = 1;
        if (n < max_tasks)
            tasks[n++] = (pid_t)v;
    }
    closedir(dir);

    if (!have_pid && n < max_tasks)
        tasks[n++] = pid;
    if (n == 0) {
        tasks[0] = pid;
        n = 1;
    }
    return n;
}

static int
bs_trace_loop(struct bs_state *st, pid_t root, int attached_root)
{
    int status;
    int exit_code = 0;
    int alive = bs_live_slots(st);
    if (alive <= 0) {
        bs_slot_for(st, root);
        alive = 1;
    }

    while (alive > 0) {
        pid_t w = waitpid(-1, &status, __WALL);
        if (w < 0) {
            if (errno == EINTR) {
                if (bs_stop && attached_root) {
                    bs_detach_all(st);
                    if (!st->summary)
                        bs_emit("[pid %d] +++ detached on signal %d +++\n",
                                (int)root, (int)bs_stop_sig);
                    return 128 + (bs_stop_sig ? bs_stop_sig : SIGINT);
                }
                continue;
            }
            if (errno == ECHILD) break;
            if (attached_root)
                bs_detach_all(st);
            builtin_error("waitpid: %s", strerror(errno));
            return EXECUTION_FAILURE;
        }
        int slot = bs_slot_for(st, w);

        if (WIFEXITED(status)) {
            if (!st->summary)
                bs_emit("[pid %d] +++ exited with %d +++\n", (int)w, WEXITSTATUS(status));
            if (w == root) exit_code = WEXITSTATUS(status);
            if (slot >= 0) st->slots[slot].pid = -1;
            alive--;
            continue;
        }
        if (WIFSIGNALED(status)) {
            if (!st->summary)
                bs_emit("[pid %d] +++ killed by signal %d +++\n", (int)w, WTERMSIG(status));
            if (w == root) exit_code = 128 + WTERMSIG(status);
            if (slot >= 0) st->slots[slot].pid = -1;
            alive--;
            continue;
        }
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            int deliver = 0;
            if (sig == (SIGTRAP | 0x80)) {
                /* Syscall-stop. */
                struct bs_syscall_regs r;
                if (bs_read_syscall_regs(w, &r) == 0 && slot >= 0) {
                    int entry_stop = bs_is_entry_stop(&r);
                    if (!st->slots[slot].in_syscall && !entry_stop) {
                        /* Attach can begin with an unpaired syscall-exit stop. */
                    } else if (!st->slots[slot].in_syscall || entry_stop) {
                        st->slots[slot].printed_entry = bs_should_print(st, r.nr);
                        if (st->timing && st->slots[slot].printed_entry)
                            clock_gettime(CLOCK_MONOTONIC, &st->slots[slot].enter_ts);
                        if (st->slots[slot].printed_entry && !st->summary)
                            bs_print_syscall(w, &r, 0, -1.0);
                        st->slots[slot].in_syscall = 1;
                        st->slots[slot].last_nr = r.nr;
                        /* exit / exit_group never return; flush the
                         * line now so the trace ends with the call. */
                        if (st->slots[slot].printed_entry && bs_is_exit_syscall(r.nr)) {
                            if (st->summary)
                                bs_summary_record(st, r.nr, 0, 0);
                            else
                                {
                                    bs_emit(" = ?");
                                    if (st->timing)
                                        bs_print_elapsed(bs_elapsed_since(&st->slots[slot].enter_ts));
                                    bs_emit("\n");
                                }
                            st->slots[slot].in_syscall = 0;
                            st->slots[slot].printed_entry = 0;
                        }
                    } else {
                        if (st->slots[slot].printed_entry) {
                            if (st->summary)
                                bs_summary_record(st, st->slots[slot].last_nr, r.ret, 1);
                            else
                                bs_print_syscall(w, &r, 1,
                                                 st->timing ? bs_elapsed_since(&st->slots[slot].enter_ts) : -1.0);
                        }
                        st->slots[slot].in_syscall = 0;
                        st->slots[slot].printed_entry = 0;
                    }
                }
            } else if (status >> 16 == PTRACE_EVENT_FORK
                    || status >> 16 == PTRACE_EVENT_VFORK
                    || status >> 16 == PTRACE_EVENT_CLONE) {
                unsigned long new_pid = 0;
                ptrace(PTRACE_GETEVENTMSG, w, NULL, &new_pid);
                if (!st->summary)
                    bs_emit("[pid %d] +++ new child %lu +++\n", (int)w, new_pid);
                bs_slot_for(st, (pid_t)new_pid);
                alive++;
            } else if (status >> 16 == PTRACE_EVENT_EXEC) {
                if (!st->summary)
                    bs_emit("[pid %d] +++ exec +++\n", (int)w);
            } else {
                /* Real signal: forward to tracee on resume. */
                if (!st->summary)
                    bs_emit("[pid %d] --- signal %d ---\n", (int)w, sig);
                deliver = sig;
            }
            if (ptrace(PTRACE_SYSCALL, w, NULL, (void *)(long)deliver) < 0) {
                /* Tracee may have died between our wait and resume; that's
                 * fine — we'll observe its exit on the next waitpid. */
                if (errno != ESRCH)
                    bs_emit("[pid %d] PTRACE_SYSCALL: %s\n", (int)w, strerror(errno));
            }
        }
    }

    if (st->summary)
        bs_print_summary(st);
    return exit_code;
}

static int
bs_run_exec(struct bs_state *st, char **argv)
{
    struct bs_child_guard guard;
    if (bs_child_guard_begin(&guard) < 0) {
        builtin_error("SIGCHLD guard: %s", strerror(errno));
        return EXECUTION_FAILURE;
    }
    pid_t child = fork();
    if (child < 0) {
        bs_child_guard_parent_end(&guard);
        builtin_error("fork: %s", strerror(errno));
        return EXECUTION_FAILURE;
    }
    if (child == 0) {
        bs_child_guard_child_end(&guard);
        /* Tracee. */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            fprintf(stderr, "strace: PTRACE_TRACEME: %s\n", strerror(errno));
            _exit(127);
        }
        /* Stop self so the parent can attach options before resumption. */
        raise(SIGSTOP);
        execvp(argv[0], argv);
        fprintf(stderr, "strace: execvp %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }

    /* Parent / tracer. */
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        bs_child_guard_parent_end(&guard);
        builtin_error("waitpid: %s", strerror(errno));
        return EXECUTION_FAILURE;
    }
    if (!WIFSTOPPED(status)) {
        bs_child_guard_parent_end(&guard);
        builtin_error("child did not stop as expected (status=0x%x)", status);
        return EXECUTION_FAILURE;
    }

    if (bs_set_trace_options(st, child) < 0) {
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
            ;
        bs_child_guard_parent_end(&guard);
        return EXECUTION_FAILURE;
    }
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) {
        bs_child_guard_parent_end(&guard);
        builtin_error("PTRACE_SYSCALL kick: %s", strerror(errno));
        return EXECUTION_FAILURE;
    }

    int exit_code = bs_trace_loop(st, child, 0);
    bs_child_guard_parent_end(&guard);
    return exit_code;
}

static int
bs_run_attach(struct bs_state *st, pid_t pid)
{
    if (pid <= 0) {
        builtin_error("-p: PID must be > 0");
        return EX_USAGE;
    }
    struct sigaction sa, old_int, old_term;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = bs_stop_handler;
    sigemptyset(&sa.sa_mask);
    bs_stop = 0;
    bs_stop_sig = 0;
    sigaction(SIGINT, &sa, &old_int);
    sigaction(SIGTERM, &sa, &old_term);

#define BS_ATTACH_RETURN(_rc) do {                 \
        sigaction(SIGINT, &old_int, NULL);         \
        sigaction(SIGTERM, &old_term, NULL);       \
        return (_rc);                              \
    } while (0)

    pid_t tasks[256];
    int ntasks = bs_enumerate_tasks(pid, tasks, 256);
    int attached = 0;

    for (int i = 0; i < ntasks; i++) {
        pid_t tid = tasks[i];
        if (bs_slot_for(st, tid) < 0) {
            bs_detach_all(st);
            builtin_error("-p: too many tasks under PID %ld", (long)pid);
            BS_ATTACH_RETURN(EXECUTION_FAILURE);
        }
        if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) < 0) {
            if (errno == ESRCH && tid != pid) {
                int slot = bs_slot_for(st, tid);
                if (slot >= 0) st->slots[slot].pid = -1;
                continue;
            }
            builtin_error("PTRACE_ATTACH %ld: %s", (long)tid, strerror(errno));
            int rc = errno == ESRCH ? EX_USAGE : EXECUTION_FAILURE;
            bs_detach_all(st);
            BS_ATTACH_RETURN(rc);
        }
        attached++;
    }

    if (attached == 0) {
        builtin_error("PTRACE_ATTACH %ld: no live tasks", (long)pid);
        BS_ATTACH_RETURN(EX_USAGE);
    }

    for (int i = 0; i < st->nslots; i++) {
        pid_t tid = st->slots[i].pid;
        if (tid <= 0)
            continue;
        int status;
        while (waitpid(tid, &status, __WALL) < 0) {
            if (errno == EINTR) {
                if (bs_stop) {
                    bs_detach_all(st);
                    BS_ATTACH_RETURN(128 + (bs_stop_sig ? bs_stop_sig : SIGINT));
                }
                continue;
            }
            bs_detach_all(st);
            builtin_error("waitpid attach %ld: %s", (long)tid, strerror(errno));
            BS_ATTACH_RETURN(EXECUTION_FAILURE);
        }
        if (!WIFSTOPPED(status)) {
            bs_detach_all(st);
            builtin_error("attached task %ld did not stop as expected (status=0x%x)",
                          (long)tid, status);
            BS_ATTACH_RETURN(EXECUTION_FAILURE);
        }
        if (bs_set_trace_options(st, tid) < 0) {
            bs_detach_all(st);
            BS_ATTACH_RETURN(EXECUTION_FAILURE);
        }
    }

    for (int i = 0; i < st->nslots; i++) {
        pid_t tid = st->slots[i].pid;
        if (tid <= 0)
            continue;
        if (ptrace(PTRACE_SYSCALL, tid, NULL, NULL) < 0) {
            bs_detach_all(st);
            builtin_error("PTRACE_SYSCALL kick %ld: %s", (long)tid, strerror(errno));
            BS_ATTACH_RETURN(EXECUTION_FAILURE);
        }
    }
    int rc = bs_trace_loop(st, pid, 1);
    BS_ATTACH_RETURN(rc);
#undef BS_ATTACH_RETURN
}

/* --- builtin entry ---------------------------------------------------- */

int
strace_builtin(WORD_LIST *list)
{
    struct bs_state st;
    memset(&st, 0, sizeof(st));
    const char *out_path = NULL;
    pid_t attach_pid = -1;
    bs_out = stderr;

    WORD_LIST *p = list;
    while (p) {
        const char *w = p->word->word;
        if (!strcmp(w, "--")) { p = p->next; break; }
        if (!strcmp(w, "-f")) { st.follow = 1; p = p->next; continue; }
        if (!strcmp(w, "-T")) { st.timing = 1; p = p->next; continue; }
        if (!strcmp(w, "--summary") || !strcmp(w, "-c")) {
            st.summary = 1;
            p = p->next;
            continue;
        }
        if (!strcmp(w, "-e")) {
            p = p->next;
            if (!p) { builtin_error("-e requires trace=LIST"); builtin_usage(); return EX_USAGE; }
            int frc = bs_parse_trace_filter(&st, p->word->word);
            if (frc != EXECUTION_SUCCESS) { builtin_usage(); return frc; }
            p = p->next;
            continue;
        }
        if (!strncmp(w, "-e", 2) && w[2] != '\0') {
            int frc = bs_parse_trace_filter(&st, w + 2);
            if (frc != EXECUTION_SUCCESS) { builtin_usage(); return frc; }
            p = p->next;
            continue;
        }
        if (!strncmp(w, "--trace=", 8)) {
            int frc = bs_parse_trace_filter(&st, w + 8);
            if (frc != EXECUTION_SUCCESS) { builtin_usage(); return frc; }
            p = p->next;
            continue;
        }
        if (!strcmp(w, "-o")) {
            p = p->next;
            if (!p) { builtin_error("-o requires FILE"); builtin_usage(); return EX_USAGE; }
            out_path = p->word->word;
            p = p->next;
            continue;
        }
        if (!strcmp(w, "-p")) {
            char *end = NULL;
            long v;
            p = p->next;
            if (!p) { builtin_error("-p requires PID"); builtin_usage(); return EX_USAGE; }
            errno = 0;
            v = strtol(p->word->word, &end, 10);
            if (errno || !end || *end != '\0' || v <= 0) {
                builtin_error("-p: bad PID: %s", p->word->word);
                builtin_usage();
                return EX_USAGE;
            }
            if (attach_pid > 0) {
                builtin_error("-p specified more than once");
                builtin_usage();
                return EX_USAGE;
            }
            attach_pid = (pid_t)v;
            p = p->next;
            continue;
        }
        if (!strncmp(w, "-p", 2) && w[2] != '\0') {
            char *end = NULL;
            long v;
            errno = 0;
            v = strtol(w + 2, &end, 10);
            if (errno || !end || *end != '\0' || v <= 0) {
                builtin_error("-p: bad PID: %s", w + 2);
                builtin_usage();
                return EX_USAGE;
            }
            if (attach_pid > 0) {
                builtin_error("-p specified more than once");
                builtin_usage();
                return EX_USAGE;
            }
            attach_pid = (pid_t)v;
            p = p->next;
            continue;
        }
        if (!strcmp(w, "--version")) {
            printf("strace %s\n", BASHSTRACE_VERSION);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp(w, "--help") || !strcmp(w, "-h")) {
            builtin_usage();
            return EXECUTION_SUCCESS;
        }
        if (w[0] == '-' && w[1] != '\0') {
            builtin_error("unknown flag: %s (try --help)", w);
            builtin_usage();
            return EX_USAGE;
        }
        break;
    }

    if (attach_pid > 0 && p) {
        builtin_error("-p PID cannot be combined with COMMAND");
        builtin_usage();
        return EX_USAGE;
    }

    if (attach_pid < 0 && (!p || !p->word || !p->word->word)) {
        builtin_error("COMMAND required");
        builtin_usage();
        return EX_USAGE;
    }

    /* Pack the tail into a NULL-terminated argv. */
    int n = 0;
    char **argv = NULL;
    if (attach_pid < 0) {
        for (WORD_LIST *q = p; q; q = q->next) n++;
        argv = malloc(sizeof(char *) * (n + 1));
        if (!argv) { builtin_error("out of memory"); return EXECUTION_FAILURE; }
        int i = 0;
        for (WORD_LIST *q = p; q; q = q->next) argv[i++] = q->word->word;
        argv[n] = NULL;
    }

    if (out_path) {
        bs_out = fopen(out_path, "w");
        if (!bs_out) {
            builtin_error("open %s: %s", out_path, strerror(errno));
            free(argv);
            return EXECUTION_FAILURE;
        }
    }

    int rc = attach_pid > 0 ? bs_run_attach(&st, attach_pid) : bs_run_exec(&st, argv);

    if (out_path && bs_out) { fclose(bs_out); bs_out = stderr; }
    free(argv);
    return rc < 0 ? EXECUTION_FAILURE : (rc == 0 ? EXECUTION_SUCCESS : rc);
}

char *strace_doc[] = {
    "Minimal ptrace(2) syscall tracer (x86_64/aarch64, ~50-syscall decoded subset).",
    "",
    "    strace [-f] [-T] [--summary|-c] [-o FILE] [-e trace=LIST] -- COMMAND [ARG...]",
    "        Fork+exec COMMAND under PTRACE_SYSCALL. One trace line per",
    "        syscall enter+exit to stderr (or FILE). LIST is comma-separated",
    "        syscall names or numbers. -f follows children via",
    "        PTRACE_O_TRACEFORK|VFORK|CLONE.",
    "        -T appends per-syscall elapsed time in seconds.",
    "        --summary / -c suppresses per-call lines and prints calls/errors.",
    "    strace [-f] [-T] [--summary|-c] [-o FILE] [-e trace=LIST] -p PID",
    "        Attach to PID and trace it until exit. On Linux, existing threads",
    "        under /proc/PID/task are attached at startup.",
    "    strace --version",
    "        Print the subset version signature.",
    "",
    "Decoded syscalls cover the common ~50: read/write/open/close/execve",
    "and friends, with common flag/mode/signal arguments rendered",
    "symbolically. Others render as `syscall_NNN(0xa0, 0xa1, ...)`.",
    "String pointers (path, buf) are quoted up to 80 bytes; longer strings",
    "are truncated. argv[]/envp[] for execve are not enumerated. ptrace",
    "requires either CAP_SYS_PTRACE or yama.ptrace_scope <= 1.",
    (char *)NULL
};

struct builtin strace_struct = {
    "strace",
    strace_builtin,
    BUILTIN_ENABLED,
    strace_doc,
    "strace [-f] [-T] [--summary|-c] [-o FILE] [-e trace=LIST] [-p PID | -- COMMAND [ARG...]]",
    0
};
