/* bashxargs.c — POSIX xargs(1) as a bash builtin.
 *
 * Phase A.4 of bash-os shell-ergonomics. Reads arguments from stdin
 * and runs CMD with them in batches.
 *
 *   bashxargs [-0] [-r] [-t] [-p] [-n MAX] [-L MAX] [-P MAX]
 *             [-s SIZE] [-I REPL] CMD [ARG...]
 *
 *   -0       NUL-separated input (pairs with `bashfind ... -print0`)
 *   -r       no-run-if-empty
 *   -t       echo command before each invocation
 *   -p       prompt before each invocation (implies -t)
 *   -n MAX   max-args-per-invocation (default: as many as fit)
 *   -L MAX   max nonblank logical input lines per invocation
 *   -P MAX   run up to MAX invocations in parallel
 *   -s SIZE  max command-line bytes per invocation, counting the
 *            template words (CMD + its initial args), each input arg,
 *            and one terminating-NUL byte per word (POSIX/GNU xargs).
 *            Overrides the internal min(ARG_MAX/2, 65536) heuristic.
 *   -I REPL  substitute REPL with each input arg, run CMD once per
 *            input (implies -n 1)
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <ctype.h>
#include <limits.h>
#if defined (_POSIX_SPAWN) && _POSIX_SPAWN >= 0
#  include <spawn.h>
#  if defined (__linux__) && defined (__GLIBC__)
#    include <gnu/libc-version.h>
#  endif
#endif

#include "loadables.h"
#include "command-run.h"

/* This parent-side stdio optimization also stays instrumented in sanitizer
   builds. An older libc or a process that has created threads uses fgetc. */
#if defined (__GLIBC__) && defined (__GNUC__)
#  if __GLIBC_PREREQ (2, 32)
#    define BX_SINGLE_THREADED_STDIO 1
extern char __libc_single_threaded __attribute__ ((weak));
extern FILE _IO_2_1_stdin_ __attribute__ ((weak));
#  endif
#endif

/* The private-stack launcher requires known Linux/glibc LP64 ABIs. Keep
   other targets and instrumented builds on posix_spawn/fork. */
#if defined (__has_feature)
#  if __has_feature (address_sanitizer) || __has_feature (thread_sanitizer) || \
      __has_feature (memory_sanitizer)
#    define BX_SPAWN_INSTRUMENTED 1
#  endif
#endif
#if defined (__SANITIZE_ADDRESS__) || defined (__SANITIZE_THREAD__) || \
    defined (__SANITIZE_MEMORY__)
#  define BX_SPAWN_INSTRUMENTED 1
#endif
#if defined (__linux__) && defined (__GLIBC__) && defined (__LP64__) && \
    (defined (__x86_64__) || defined (__aarch64__)) && \
    defined (__GNUC__) && !defined (BX_SPAWN_INSTRUMENTED)
#  if __GLIBC_PREREQ (2, 34) && defined (_POSIX_SPAWN) && _POSIX_SPAWN >= 0
#    define BX_PRIVATE_SPAWN 1
#    include <stdint.h>
#    include <sys/mman.h>
#    include <dlfcn.h>
#    include <fcntl.h>
#    include <wchar.h>
#    include <asm/unistd.h>
#    if defined (__aarch64__)
#      include <sys/auxv.h>
#    endif
#  endif
#endif

/* GNU/BSD xargs exit status folding. POSIX leaves "some other error" to the
   implementation; we mirror GNU so `lc_tap_compare` against /usr/bin/xargs
   has a chance of agreement and so callers can distinguish kinds of failure.

       0       all invocations succeeded
       123     any invocation exited 1..125
       124     a child exited with status 255 (fatal: stop reading input)
       125     a child was terminated by a signal (fatal)
       126     the command was found but could not be executed
       127     the command was not found
       1       bashxargs itself hit a fatal error (parse, I/O, fork) */
#define BX_OK         0
#define BX_ANY_FAIL   123
#define BX_FATAL_255  124
#define BX_SIGNALED   125
#define BX_NOEXEC     126
#define BX_NOTFOUND   127
#define BX_BAD        1

/* Promote `cur` to `add` if `add` is "worse." The ordering reflects
   POSIX-ish severity (not numeric): notfound/noexec/signaled/fatal_255
   are sticky, then any_fail, then ok. */
static int
bx_fold (int cur, int add)
{
    if (cur == 0) return add;
    if (add == 0) return cur;
    /* Higher severity always wins; both nonzero collapse on max. */
    if (add == BX_NOTFOUND || cur == BX_NOTFOUND) return BX_NOTFOUND;
    if (add == BX_NOEXEC   || cur == BX_NOEXEC)   return BX_NOEXEC;
    if (add == BX_SIGNALED || cur == BX_SIGNALED) return BX_SIGNALED;
    if (add == BX_FATAL_255 || cur == BX_FATAL_255) return BX_FATAL_255;
    return BX_ANY_FAIL;
}

static int
bx_is_fatal (int rc)
{
    return rc == BX_FATAL_255 || rc == BX_SIGNALED
        || rc == BX_NOEXEC    || rc == BX_NOTFOUND;
}

static int
bx_parse_positive_int (const char *s, int *out)
{
    char *end = NULL;
    long n;

    errno = 0;
    n = strtol (s, &end, 10);
    if (errno || end == s || *end || n <= 0 || n > INT_MAX)
        return -1;
    *out = (int) n;
    return 0;
}

static int
bx_parse_positive_long (const char *s, long *out)
{
    char *end = NULL;
    long n;

    errno = 0;
    n = strtol (s, &end, 10);
    if (errno || end == s || *end || n <= 0)
        return -1;
    *out = n;
    return 0;
}

static int
bx_prompt_yes (char **argv, int n)
{
    FILE *tty = fopen ("/dev/tty", "r");
    FILE *in = tty ? tty : stdin;
    for (int i = 0; i < n; i++) fprintf (stderr, "%s%s", i ? " " : "", argv[i]);
    fputs (" ?...", stderr);
    fflush (stderr);

    char ans[16];
    int yes = 0;
    if (fgets (ans, sizeof ans, in))
        yes = (ans[0] == 'y' || ans[0] == 'Y');
    if (tty) fclose (tty);
    return yes;
}

/* Read one input arg.  In normal POSIX xargs mode, unquoted blanks split
   arguments and quotes/backslashes group or escape bytes.  In line_mode
   (-I), consume one full line/item as the replacement argument. */
typedef struct {
    char *data;
    size_t capacity;
} bx_arg_buffer;

/* Argument boundaries and logical line boundaries are independent. A
   trailing unquoted (or escaped) blank continues the current logical line;
   empty physical lines do not consume -L's count. NUL mode counts records. */
typedef struct {
    size_t line;
    int nonblank, trailing_blank;
} bx_input_state;

static void
bx_input_separator (bx_input_state *input, int c)
{
    if (c == '\n') {
        if (input->nonblank && !input->trailing_blank) {
            input->line++;
            input->nonblank = 0;
        }
    } else
        input->trailing_blank = 1;
}

static inline int
bx_read_byte (FILE *in)
{
#if defined (BX_SINGLE_THREADED_STDIO)
    /* Cookie streams may require locking even before creating threads.
       Keep their fgetc path; ordinary stdin uses the same refill/EOF/error
       body inline, with a fresh single-thread check for every byte. */
    if (in == &_IO_2_1_stdin_ && &__libc_single_threaded &&
        *(volatile char *) &__libc_single_threaded)
        return getc_unlocked (in);
#endif
    return fgetc (in);
}

static char *
bx_read_arg_into (FILE *in, int nul_sep, int line_mode, int *errp,
                  bx_arg_buffer *storage, int plain_span,
                  bx_input_state *input, size_t *arg_line)
{
    /* GNU's separators are blanks and newline, not vertical whitespace. */
# define BX_ARG_ISSPACE(c) ((c) == ' ' || (c) == '\t' || (c) == '\n')
#if !defined (BX_SINGLE_THREADED_STDIO) || !defined (__GLIBC__)
    (void) plain_span;
#endif
    size_t cap = storage->capacity, len;
    char *buf = storage->data;
    if (!buf) {
        cap = 64;
        buf = malloc (cap);
        if (!buf) return NULL;
        storage->data = buf;
        storage->capacity = cap;
    }
    int c;

    len = 0;
    if (!nul_sep) {
        while ((c = bx_read_byte (in)) != EOF && BX_ARG_ISSPACE (c))
            bx_input_separator (input, c);
        if (c == EOF) return NULL;
    } else {
        c = bx_read_byte (in);
        if (c == EOF) return NULL;
    }
    if (arg_line) *arg_line = input->line;

    int quote = 0;
    for (;;) {
        if (c == EOF) break;
        if (nul_sep) {
            if (c == '\0') { input->line++; break; }
        } else {
            if (c == '\n' && quote) {
                if (errp) *errp = quote;
                return NULL;
            }
            if (!quote && (c == '\n' || (!line_mode && BX_ARG_ISSPACE (c)))) {
                bx_input_separator (input, c);
                break;
            }
            input->nonblank = 1;
            input->trailing_blank = (c == ' ' || c == '\t');
            if (c == '\'' || c == '"') {
                if (!quote) { quote = c; c = bx_read_byte (in); continue; }
                if (quote == c) { quote = 0; c = bx_read_byte (in); continue; }
            } else if (c == '\\' && !quote) {
                c = bx_read_byte (in);
                /* GNU discards a final escape at EOF, retaining the word. */
                if (c == EOF) break;
                input->trailing_blank = (c == ' ' || c == '\t');
            }
        }
        if (len + 1 >= cap) {
            if (cap > (size_t) -1 / 2) return NULL;
            size_t new_cap = cap * 2;
            char *nb = realloc (buf, new_cap);
            if (!nb) return NULL;
            buf = nb;
            storage->data = buf;
            storage->capacity = cap = new_cap;
        }
        buf[len++] = (char) c;
#if defined (BX_SINGLE_THREADED_STDIO) && defined (__GLIBC__)
        /* The caller's ordinary interval excludes nonlocal signal exits.
           A plain run in the current input buffer invokes no refill,
           conversion, or allocation callback. Commit only that run;
           syntax and buffer boundaries retain the scalar path. */
        if (plain_span && !nul_sep && !line_mode && !quote && cap - len > 1 &&
            in == &_IO_2_1_stdin_ && &__libc_single_threaded &&
            *(volatile char *) &__libc_single_threaded) {
            const unsigned char *first = (const unsigned char *) in->_IO_read_ptr;
            const unsigned char *end = (const unsigned char *) in->_IO_read_end;
            const unsigned char *next = first;
            size_t room = cap - len - 1;
            while (next < end && (size_t) (next - first) < room) {
                unsigned char byte = *next;
                if (BX_ARG_ISSPACE (byte) || byte == '\'' || byte == '"' || byte == '\\')
                    break;
                buf[len++] = (char) byte;
                next++;
            }
            if (next != first) input->trailing_blank = 0;
            in->_IO_read_ptr = (char *) next;
        }
#endif
        c = bx_read_byte (in);
    }

    if (quote && !nul_sep) {
        if (errp) *errp = quote;
        return NULL;
    }

    if (c == EOF && len == 0) return NULL;
    buf[len] = '\0';
    return buf;
#undef BX_ARG_ISSPACE
}

static char *
bx_read_arg (FILE *in, int nul_sep, int line_mode, int *errp)
{
    bx_arg_buffer storage = { 0 };
    bx_input_state input = { 0 };
    char *arg = bx_read_arg_into (in, nul_sep, line_mode, errp, &storage, 0,
                                  &input, NULL);
    if (!arg) free (storage.data);
    return arg;
}

typedef struct {
    bx_arg_buffer *args;
    bx_arg_buffer lookahead;
    char **argv;
    size_t capacity;
} bx_batch_buffers;

static void
bx_batch_buffers_cleanup (void *arg)
{
    bx_batch_buffers *buffers = arg;
    for (size_t i = 0; i < buffers->capacity; i++) free (buffers->args[i].data);
    free (buffers->args);
    free (buffers->lookahead.data);
    free (buffers->argv);
}

static int
bx_batch_reserve (bx_batch_buffers *buffers, size_t capacity, int tmpl_n)
{
    if (capacity > (size_t) INT_MAX - (size_t) tmpl_n ||
        capacity > (size_t) -1 / sizeof *buffers->args ||
        capacity + (size_t) tmpl_n + 1 > (size_t) -1 / sizeof *buffers->argv)
        return -1;
    bx_arg_buffer *args = realloc (buffers->args, capacity * sizeof *args);
    if (!args) return -1;
    memset (args + buffers->capacity, 0,
            (capacity - buffers->capacity) * sizeof *args);
    buffers->args = args;
    buffers->capacity = capacity;
    char **argv = realloc (buffers->argv,
                           (capacity + (size_t) tmpl_n + 1) * sizeof *argv);
    if (!argv) return -1;
    buffers->argv = argv;
    return 0;
}

/* Dispositions do not change while this synchronous builtin is running:
   Bash defers trap commands, and invoked builtins run only in forked children.
   Reuse spawn attributes across batches; child masks still vary between the
   serial and parallel paths and are applied at each launch. */
typedef struct {
    int prepared;
    int mask_error;
    int sigchld_taken;          /* a wait consumed a pending SIGCHLD */
    int stdin_ready;            /* 1: descriptors below are open; -1: unavailable */
    int stdin_copy;             /* the shell's standard input, or -1 when closed */
    int null_fd;                /* /dev/null, given to each command */
#if defined (_POSIX_SPAWN) && _POSIX_SPAWN >= 0
    posix_spawnattr_t attr;
#endif
#if defined (BX_PRIVATE_SPAWN)
    void *stack_map;
    size_t stack_map_size, stack_size, stack_guard;
    uint64_t clone_defaults, clone_ignores;
    uint64_t clone_minimal_defaults;
    int clone_unavailable, sanitizer_state;
    int clone_default_scan;
    uint64_t mask_base;
    int mask_active, mask_interval;
    int streams_flushed;
    char *compact_env[17], *compact_argv[17];
    char compact_text[1024];
    size_t compact_env_bytes;
    /* Zero means unchecked; positive means complete; negative keeps the
       original environment. Only the active ordinary interval caches it. */
    int compact_env_status;
#endif
} bx_spawn_state;


static inline int
bx_plain_span_allowed (const bx_spawn_state *state)
{
#if defined (BX_PRIVATE_SPAWN)
    return state->mask_interval && state->clone_default_scan > 0;
#else
    (void) state;
    return 0;
#endif
}

static void
bx_spawn_state_free (bx_spawn_state *state)
{
    if (state->stdin_ready > 0) {
        close (state->null_fd);
        if (state->stdin_copy >= 0) close (state->stdin_copy);
        state->stdin_ready = 0;
    }
#if defined (BX_PRIVATE_SPAWN)
    if (state->stack_map) munmap (state->stack_map, state->stack_map_size);
#endif
#if defined (_POSIX_SPAWN) && _POSIX_SPAWN >= 0
    if (state->prepared > 0) posix_spawnattr_destroy (&state->attr);
#else
    (void) state;
#endif
}

static void
bx_spawn_state_cleanup (void *state)
{
    bx_spawn_state_free ((bx_spawn_state *) state);
}

#if defined (BX_PRIVATE_SPAWN)
extern void __asan_init (void) __attribute__ ((weak));
extern void __tsan_init (void) __attribute__ ((weak));
extern void __msan_init (void) __attribute__ ((weak));
extern void __ubsan_handle_type_mismatch_v1 (void) __attribute__ ((weak));
extern FILE _IO_2_1_stdout_ __attribute__ ((weak));
extern FILE _IO_2_1_stderr_ __attribute__ ((weak));
extern void *__libc_malloc (size_t) __attribute__ ((weak));
extern void *__libc_calloc (size_t, size_t) __attribute__ ((weak));
extern void *__libc_realloc (void *, size_t) __attribute__ ((weak));
extern void __libc_free (void *) __attribute__ ((weak));

/* Linux clone3 version-zero argument layout: eight aligned 64-bit words.
   CLEAR_SIGHAND is required, never silently retried with weaker flags. */
struct bx_clone_args {
    uint64_t flags, pidfd, child_tid, parent_tid;
    uint64_t exit_signal, stack, stack_size, tls;
};
struct bx_clone_child_args {
    char **argv, **env;
    uint64_t mask, defaults, ignores;
    volatile int error;
};
struct bx_kernel_sigaction {
    uint64_t handler, flags, restorer, mask;
};
static const struct bx_kernel_sigaction bx_kernel_default_action = { 0, 0, 0, 0 };
static const struct bx_kernel_sigaction bx_kernel_ignore_action = { 1, 0, 0, 0 };

/* These original trampolines switch to the kernel-selected private stack
   only in the child. The parent returns on its original stack. Calls to
   the fixed child target are direct, with ABI stack alignment maintained. */
extern long bos_xargs_clone3_start (struct bx_clone_args *, size_t,
                                   struct bx_clone_child_args *)
    __attribute__ ((visibility ("hidden")));
#if defined (__x86_64__)
__asm__ (
    ".pushsection .text\n"
    ".globl bos_xargs_clone3_start\n.hidden bos_xargs_clone3_start\n"
    ".type bos_xargs_clone3_start,@function\n"
    "bos_xargs_clone3_start:\n"
    "endbr64\n"
    "mov $435,%eax\n"
    "syscall\n"
    "test %rax,%rax\n"
    "jnz 1f\n"
    "mov %rdx,%rdi\n"
    "call bos_xargs_clone_child\n"
    "ud2\n"
    "1: ret\n"
    ".size bos_xargs_clone3_start,.-bos_xargs_clone3_start\n"
    ".popsection\n");
#else
__asm__ (
    ".pushsection .text\n.balign 4\n"
    ".globl bos_xargs_clone3_start\n.hidden bos_xargs_clone3_start\n"
    ".type bos_xargs_clone3_start,%function\n"
    "bos_xargs_clone3_start:\n"
    "hint #34\n"
    "mov x8,#435\n"
    "svc #0\n"
    "cbnz x0,1f\n"
    "mov x0,x2\n"
    "bl bos_xargs_clone_child\n"
    "brk #0\n"
    "1: ret\n"
    ".size bos_xargs_clone3_start,.-bos_xargs_clone3_start\n"
    ".popsection\n");
#endif

static inline __attribute__ ((always_inline)) long
bx_kernel_call4 (long number, long first, long second, long third, long fourth)
{
#if defined (__x86_64__)
    long result;
    register long arg4 __asm__ ("r10") = fourth;
    __asm__ volatile ("syscall" : "=a" (result)
                      : "0" (number), "D" (first), "S" (second),
                        "d" (third), "r" (arg4)
                      : "rcx", "r11", "memory", "cc");
    return result;
#else
    register long callno __asm__ ("x8") = number;
    register long arg1 __asm__ ("x0") = first;
    register long arg2 __asm__ ("x1") = second;
    register long arg3 __asm__ ("x2") = third;
    register long arg4 __asm__ ("x3") = fourth;
    __asm__ volatile ("svc #0" : "+r" (arg1)
                      : "r" (callno), "r" (arg2), "r" (arg3), "r" (arg4)
                      : "memory", "cc");
    return arg1;
#endif
}

/* The saved mask includes the invocation's SIGCHLD block. Restore it
   before any callback can change a disposition: blocked ignored signals
   may become pending, and must be discarded while still ignored. Keep
   ownership on failure so normal cleanup or Bash unwind can retry. */
static int
bx_restore_private_mask (bx_spawn_state *state)
{
    if (state->mask_active) {
        long result = bx_kernel_call4 (__NR_rt_sigprocmask, SIG_SETMASK,
                         (long) &state->mask_base, 0, sizeof state->mask_base);
        if (result < 0) {
            state->mask_error = 1;
            errno = (int) -result;
            return -1;
        }
        state->mask_active = state->mask_interval = 0;
    }
    return 0;
}
#endif

static int
bx_end_mask_interval (bx_spawn_state *state)
{
#if defined (BX_PRIVATE_SPAWN)
    /* Discard the snapshot before any restoration attempt or callback,
       including when mask restoration fails and cleanup must retry. */
    state->compact_env_status = 0;
    state->compact_env_bytes = 0;
    state->clone_default_scan = -1;
    return bx_restore_private_mask (state);
#else
    (void) state;
    return 0;
#endif
}

static void
bx_mask_interval_cleanup (void *data)
{
    bx_spawn_state *state = data;
    int saved_errno = errno;
    /* A failed restoration is never reported as success. Retry here
       before resource cleanup; the outer original-mask guard also runs. */
    for (int attempt = 0; attempt < 3; attempt++)
        if (bx_end_mask_interval (state) == 0) break;
    errno = saved_errno;
}

static int
bx_report_read_error (bx_spawn_state *state, int error)
{
    if (bx_end_mask_interval (state) < 0) return -1;
    if (error == '\\') builtin_error ("unterminated escape in input");
    else builtin_error ("unmatched %c quote in input", error);
    return 0;
}

#if defined (BX_PRIVATE_SPAWN)

/* A cached disposition snapshot is safe only when no parent callback can
   change it before the next launch. SIGCHLD stays blocked for the whole
   invocation; reject every other caught handler, even if currently blocked.
   Require ordinary byte-oriented standard streams and glibc allocators to
   exclude cookie, conversion and allocation callbacks. Trace/prompt/parallel
   modes are excluded; continuing diagnostics and fork invalidate the proof
   before printf/atfork callbacks can affect another launch. Full required
   maps remain untouched. */
static void
bx_prepare_minimal_defaults (bx_spawn_state *state, uint64_t old_mask)
{
    if (!(old_mask & (UINT64_C (1) << (SIGCHLD - 1))))
        state->clone_default_scan = -1;
    if (state->clone_default_scan) return;
    state->clone_default_scan = -1;
    int saved_errno = errno;
    /* Since 2.34, main-libc allocators no longer invoke legacy hooks.
       libc_malloc_debug and replacement allocators have different public
       entries, so retain the complete maps for those implementations. */
    const char *version = gnu_get_libc_version ();
    if (version[0] != '2' || version[1] != '.' ||
        strtoul (version + 2, NULL, 10) < 34 ||
        !__libc_malloc || !__libc_calloc || !__libc_realloc || !__libc_free ||
        malloc != __libc_malloc || calloc != __libc_calloc ||
        realloc != __libc_realloc || free != __libc_free)
        goto done;
    if (stdin != &_IO_2_1_stdin_ || stdout != &_IO_2_1_stdout_ ||
        stderr != &_IO_2_1_stderr_)
        goto done;
    FILE *streams[] = { stdin, stdout, stderr };
    for (size_t i = 0; i < sizeof streams / sizeof streams[0]; i++) {
        int fd = fileno (streams[i]);
        if (fd < 0 || fcntl (fd, F_GETFD) < 0 || fwide (streams[i], 0) > 0)
            goto done;
    }
    uint64_t ignored = 0;
    for (int sig = 1; sig <= 64; sig++) {
        struct bx_kernel_sigaction action;
        /* Query the kernel directly, including glibc-reserved 32/33. */
        if (bx_kernel_call4 (__NR_rt_sigaction, sig, 0, (long) &action,
                             sizeof (uint64_t)) < 0)
            goto done;
        if (action.handler == 1)
            ignored |= UINT64_C (1) << (sig - 1);
        else if (action.handler != 0 && sig != SIGCHLD)
            goto done;
    }
    state->clone_minimal_defaults = state->clone_defaults & ignored;
    state->clone_default_scan = 1;
done:
    errno = saved_errno;
}

/* No libc, Bash, TLS, allocation, stack protector, or instrumentation may
   run on this shared-VM child path. Sanitized processes never select it. */
static void __attribute__ ((used, noinline, noreturn, no_stack_protector,
                           no_instrument_function, no_profile_instrument_function,
                           no_sanitize ("undefined")))
bos_xargs_clone_child (struct bx_clone_child_args *args)
{
    uint64_t defaults = args->defaults;
    long result = 0;
    while (defaults) {
        int sig = __builtin_ctzll (defaults) + 1;
        defaults &= defaults - 1;
        result = bx_kernel_call4 (__NR_rt_sigaction, sig,
                    (long) &bx_kernel_default_action, 0, sizeof (uint64_t));
        if (result < 0) goto failed;
    }
    uint64_t ignores = args->ignores;
    while (ignores) {
        int sig = __builtin_ctzll (ignores) + 1;
        ignores &= ignores - 1;
        result = bx_kernel_call4 (__NR_rt_sigaction, sig,
                    (long) &bx_kernel_ignore_action, 0, sizeof (uint64_t));
        if (result < 0) goto failed;
    }
    result = bx_kernel_call4 (__NR_rt_sigprocmask, SIG_SETMASK,
                             (long) &args->mask, 0, sizeof (uint64_t));
    if (result < 0) goto failed;
    result = bx_kernel_call4 (__NR_execve, (long) args->argv[0],
                             (long) args->argv, (long) args->env, 0);
failed:
    args->error = result < 0 ? (int) -result : ECHILD;
    bx_kernel_call4 (__NR_exit, 127, 0, 0, 0);
    __builtin_trap ();
}


static int
bx_try_private_spawn (pid_t *pid, char **argv, const sigset_t *mask,
                      bx_spawn_state *state)
{
    if (state->clone_unavailable || argv[0][0] != '/' ||
        !&__libc_single_threaded || !__libc_single_threaded)
        return 0;
    /* Weak references cover static runtimes; lookup also detects a runtime
       loaded after this object was relocated. Check once per invocation:
       Bash traps defer and child builtins fork; dlopen from a C signal
       handler is not supported async-signal-safe behavior. */
    if (!state->sanitizer_state)
        state->sanitizer_state =
            (__asan_init || __tsan_init || __msan_init || __ubsan_handle_type_mismatch_v1 ||
             dlsym (RTLD_DEFAULT, "__asan_init") || dlsym (RTLD_DEFAULT, "__tsan_init") ||
             dlsym (RTLD_DEFAULT, "__msan_init") ||
             dlsym (RTLD_DEFAULT, "__ubsan_handle_type_mismatch_v1")) ? -1 : 1;
    if (state->sanitizer_state < 0) return 0;
#if defined (__aarch64__)
    /* HWCAP2_SME (Linux arm64 UAPI bit 23): conservatively exclude CPUs
       whose active streaming/ZA state would require extra clone handling. */
    if (getauxval (AT_HWCAP2) & (1UL << 23)) return 0;
#endif
    long result;
    if (!state->mask_interval) {
        uint64_t all_signals = UINT64_MAX;
        result = bx_kernel_call4 (__NR_rt_sigprocmask, SIG_BLOCK,
                     (long) &all_signals, (long) &state->mask_base,
                     sizeof state->mask_base);
        if (result < 0) return 0;
        state->mask_active = 1;
    }
    if (!state->stack_map) {
        long page_size = sysconf (_SC_PAGESIZE);
        if (page_size <= 0 || page_size > 1024 * 1024) goto unavailable;
        size_t guard = (size_t) page_size;
        size_t usable = ((65536 + guard - 1) / guard) * guard;
        size_t total = usable + 2 * guard;
        void *mapping = mmap (NULL, total, PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
        if (mapping == MAP_FAILED) goto unavailable;
        state->stack_map = mapping;
        state->stack_map_size = total;
        state->stack_size = usable;
        state->stack_guard = guard;
        if (mprotect ((char *) mapping + guard, usable, PROT_READ | PROT_WRITE) < 0) {
            state->clone_unavailable = 1;
            goto unavailable;
        }
    }
    bx_prepare_minimal_defaults (state, state->mask_base);
    if (!state->mask_interval && state->clone_default_scan > 0) {
        uint64_t supplemental = state->clone_minimal_defaults & ~state->mask_base;
        /* Linux signals 32..64 are realtime, including glibc's reserved
           32/33. Do not retain newly blocked realtime signals: queuing
           them would change ignore behavior and consume queue resources. */
        if (!(supplemental & ~UINT64_C (0x7fffffff))) {
            uint64_t interval_mask = state->mask_base | supplemental;
            result = bx_kernel_call4 (__NR_rt_sigprocmask, SIG_SETMASK,
                         (long) &interval_mask, 0, sizeof interval_mask);
            if (result < 0) goto unavailable;
            state->mask_interval = 1;
        }
    }
    struct bx_clone_child_args child = {
        argv, export_env, 0,
        state->clone_default_scan > 0 ? state->clone_minimal_defaults : state->clone_defaults,
        state->clone_ignores, 0
    };
    /* Native LP64 glibc stores the kernel's 64 signal bits first. */
    memcpy (&child.mask, mask, sizeof child.mask);
    struct bx_clone_args args = {
        .flags = UINT64_C (0x100) | UINT64_C (0x4000) | UINT64_C (0x100000000),
        .exit_signal = SIGCHLD,
        .stack = (uint64_t) (uintptr_t) ((char *) state->stack_map + state->stack_guard),
        .stack_size = state->stack_size
    };
    /* Keep bounded argument/environment copies together in the invocation
       state. An active ordinary interval excludes parent environment
       mutations, so its completed environment snapshot can be reused. Argv
       is copied afresh on every launch, and export rebuilding and callbacks
       end the interval before they run. Never replace Bash's owned data. */
    char **compact_env = state->compact_env;
    char **compact_argv = state->compact_argv;
    char *compact_text = state->compact_text;
    if (state->clone_default_scan > 0) {
        char **originals[2] = { export_env, argv };
        char **copies[2] = { compact_env, compact_argv };
        size_t used = 0;
        size_t first_vector = 0;
        int cache_env = state->mask_interval && state->clone_default_scan > 0;
        if (cache_env && state->compact_env_status) {
            if (state->compact_env_status > 0) {
                child.env = compact_env;
                used = state->compact_env_bytes;
            }
            first_vector = 1;
        }
        for (size_t vector = first_vector; vector < 2; vector++) {
            if (vector == 0) {
                state->compact_env_status = cache_env ? -1 : 0;
                state->compact_env_bytes = 0;
            }
            if (!originals[vector]) continue;
            size_t count = 0, end = used;
            while (originals[vector][count]) {
                if (count == 16) goto next_vector;
                copies[vector][count] = compact_text + end;
                const char *entry = originals[vector][count];
                for (;;) {
                    if (end - used == 512) goto next_vector;
                    char byte = *entry++;
                    compact_text[end++] = byte;
                    if (!byte) break;
                }
                count++;
            }
            copies[vector][count] = NULL;
            if (vector == 0) {
                child.env = compact_env;
                if (cache_env) {
                    state->compact_env_status = 1;
                    state->compact_env_bytes = end;
                }
            } else {
                child.argv = compact_argv;
            }
            used = end;
next_vector:
            ; /* An oversized vector keeps its original pointers. */
        }
    }
    /* No allocations, symbol resolution, or signal handlers may intervene
       between this final threading check and clone3. */
    if (!*(volatile char *) &__libc_single_threaded) goto unavailable;
#if defined (__x86_64__)
    /* The private child stack is not used while a shadow stack is active. */
    unsigned long shadow_stack = 0;
    result = bx_kernel_call4 (__NR_arch_prctl, 0x5005 /* ARCH_SHSTK_STATUS */,
                             (long) &shadow_stack, 0, 0);
    if (result != 0 || shadow_stack != 0) goto unavailable;
#endif
    result = bos_xargs_clone3_start (&args, sizeof args, &child);
    if (result > 0 && child.error) {
        int status;
        while (waitpid ((pid_t) result, &status, 0) < 0 && errno == EINTR) { }
    }
    if (result > 0 && !child.error) {
        *pid = (pid_t) result;
        /* This child may already have executed: return its exact PID
           even if transient-mask restoration failed, and wait for it. */
        if (!state->mask_interval) bx_restore_private_mask (state);
        return 1;
    }
    if (result == -ENOSYS || result == -EINVAL || result == -EPERM)
        state->clone_unavailable = 1;
unavailable:
    return bx_end_mask_interval (state) < 0 ? -1 : 0;
}
#endif

#if defined (_POSIX_SPAWN) && _POSIX_SPAWN >= 0
static int
bx_spawn_needs_full_defaults (void)
{
#if defined (__linux__) && defined (__GLIBC__)
    /* Before 2.38, Linux glibc queries each unspecified disposition in
       every spawn child, then also installs SIG_DFL for ordinary defaults.
       Supplying those defaults once avoids the repeated queries. Newer
       glibc can clear handlers with clone3, so keep its default set small.
       Use the running libc version, not the headers used for compilation. */
    const char *version = gnu_get_libc_version ();
    return version[0] == '2' && version[1] == '.' &&
           strtoul (version + 2, NULL, 10) < 38;
#else
    return 0;
#endif
}
#endif

/* An external executable does not need a writable copy of Bash's address
   space or its child-side builtin cleanup. Set spawn dispositions to what
   bos_prepare_child followed by exec would produce. Untrapped, ordinary
   signals already have the right exec semantics: caught handlers become
   default and inherited ignores remain ignored.

   Interactive terminating-signal restoration and active job-control pipes
   need Bash's full child cleanup, so those contexts retain fork. POSIX spawn
   cannot install SIG_IGN explicitly; if Bash would restore an ignore that
   the parent does not currently have, retain fork there too. */
static int
bx_try_spawn_external (pid_t *pid, char **argv, const sigset_t *mask,
                       bx_spawn_state *state)
{
#if defined (_POSIX_SPAWN) && _POSIX_SPAWN >= 0
    extern SigHandler *original_signals[NSIG];
    if (interactive_shell || job_control ||
        (!strchr (argv[0], '/') && builtin_address_internal (argv[0], 0)))
        return 0;
#if defined (PGRP_PIPE)
    int pipes[2];
    save_pgrp_pipe (pipes, 0);
    if (pipes[0] >= 0 || pipes[1] >= 0) return 0;
#endif
    if (state->prepared < 0) return 0;
    if (!state->prepared) {
        sigset_t defaults;
        int full_defaults = bx_spawn_needs_full_defaults ();
        sigemptyset (&defaults);
        for (int sig = 1; sig < NSIG; sig++) {
            int trapped = signal_is_trapped (sig);
            if (!trapped && !signal_is_special (sig)) {
                if (full_defaults && sig != SIGKILL && sig != SIGSTOP) {
                    struct sigaction current;
                    if (sigaction (sig, NULL, &current) < 0) {
                        /* glibc reserves signals 32/33 for its own use;
                           leave unsupported/internal signals to libc. */
                        if (errno != EINVAL) goto unavailable;
                    } else if (current.sa_handler != SIG_IGN &&
                               sigaddset (&defaults, sig) < 0 && errno != EINVAL) {
                        goto unavailable;
                    }
                }
                continue;
            }
            SigHandler *handler = original_signals[sig];
            if (trapped && signal_is_ignored (sig))
                handler = SIG_IGN;
            else if (trapped && signal_is_async_ignored (sig) && handler == SIG_IGN)
                handler = SIG_DFL;
            if (handler == IMPOSSIBLE_TRAP_HANDLER) goto unavailable;
            if (handler == SIG_IGN) {
                struct sigaction current;
                if (sigaction (sig, NULL, &current) < 0 || current.sa_handler != SIG_IGN)
                    goto unavailable;
#if defined (BX_PRIVATE_SPAWN)
                if (sig <= 64)
                    state->clone_ignores |= UINT64_C (1) << (sig - 1);
#endif
            } else {
                struct sigaction current;
                if (sigaction (sig, NULL, &current) < 0) goto unavailable;
                /* Spawn already resets caught handlers before exec, and
                   exec preserves default dispositions. Only an inherited
                   ignore needs an explicit transition to SIG_DFL. */
                if (full_defaults || current.sa_handler == SIG_IGN)
                    sigaddset (&defaults, sig);
#if defined (BX_PRIVATE_SPAWN)
                /* Preserve every Bash-required default independently of
                   the disposition observed while preparing attributes. */
                if (sig <= 64)
                    state->clone_defaults |= UINT64_C (1) << (sig - 1);
#endif
            }
        }
        if (posix_spawnattr_init (&state->attr) != 0) goto unavailable;
        int err = posix_spawnattr_setsigdefault (&state->attr, &defaults);
        if (!err) err = posix_spawnattr_setflags (&state->attr,
                          POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
        if (err) {
            posix_spawnattr_destroy (&state->attr);
            goto unavailable;
        }
        state->prepared = 1;
    }
#if defined (BX_PRIVATE_SPAWN)
    int private_result = bx_try_private_spawn (pid, argv, mask, state);
    if (private_result != 0) return private_result;
#endif
    if (bx_end_mask_interval (state) < 0) return -1;
    int err = posix_spawnattr_setsigmask (&state->attr, mask);
    if (!err) {
        if (strchr (argv[0], '/'))
            err = posix_spawn (pid, argv[0], NULL, &state->attr, argv, export_env);
        else
            err = posix_spawnp (pid, argv[0], NULL, &state->attr, argv, export_env);
    }
    if (!err) return 1;
    /* In particular, execvp's ENOEXEC shell-script fallback is intentional.
       The existing child path also preserves its 126/127 diagnostics and
       status handling for every other spawn/exec failure. */
    return 0;
unavailable:
    state->prepared = -1;
#else
    (void) pid; (void) argv; (void) mask; (void) state;
#endif
    return 0;
}

/* GNU xargs gives each command /dev/null as its standard input, so it cannot
   consume arguments still waiting to be read. Every launch path copies the
   descriptor table when it creates the child, so descriptor 0 points at
   /dev/null only while a child is being started. Both saved descriptors sit
   at 10 or above, clear of Bash's redirections, and close on exec. */
static int
bx_stdin_detach (bx_spawn_state *state)
{
    if (!state->stdin_ready) {
        state->stdin_ready = -1;
        int copy = fcntl (STDIN_FILENO, F_DUPFD_CLOEXEC, 10);
        if (copy >= 0 || errno == EBADF) {
            int opened = open ("/dev/null", O_RDONLY | O_CLOEXEC);
            int null_fd = opened < 0 ? -1 : fcntl (opened, F_DUPFD_CLOEXEC, 10);
            if (opened >= 0) close (opened);
            if (null_fd >= 0) {
                state->stdin_copy = copy;
                state->null_fd = null_fd;
                state->stdin_ready = 1;
            } else if (copy >= 0)
                close (copy);
        }
    }
    return state->stdin_ready > 0 && dup2 (state->null_fd, STDIN_FILENO) == STDIN_FILENO;
}

static void
bx_stdin_attach (const bx_spawn_state *state, int detached)
{
    if (!detached) return;
    int saved = errno;
    if (state->stdin_copy >= 0) dup2 (state->stdin_copy, STDIN_FILENO);
    else close (STDIN_FILENO);
    errno = saved;
}

static pid_t
bx_launch (char **argv, const sigset_t *mask, bx_spawn_state *state)
{
#if defined (BX_PRIVATE_SPAWN)
    /* Exported dynamic variables may run application callbacks during a
       rebuild. The first rebuild precedes the disposition snapshot. */
    if (state->clone_default_scan > 0 && array_needs_making &&
        bx_end_mask_interval (state) < 0)
        return -1;
#endif
    maybe_make_export_env ();
    /* Only the ordinary active interval excludes every parent output or
       callback between launches. Retry both streams after any failed flush
       and after every invalidation; the first launch always flushes. */
#if defined (BX_PRIVATE_SPAWN)
    if (!state->mask_interval || !state->streams_flushed) {
        int out = fflush (stdout);
        int err = fflush (stderr);
        state->streams_flushed = out == 0 && err == 0;
    }
#else
    fflush (stdout);
    fflush (stderr);
#endif
    pid_t pid;
    int detached = bx_stdin_detach (state);
    int launched = bx_try_spawn_external (&pid, argv, mask, state);
    if (launched != 0) {
        bx_stdin_attach (state, detached);
        return launched > 0 ? pid : -1;
    }
    /* fork may run application-registered parent atfork callbacks. */
    if (bx_end_mask_interval (state) < 0) {
        bx_stdin_attach (state, detached);
        return -1;
    }
    pid = fork ();
    if (pid == 0) {
        bos_prepare_child ();
        sigprocmask (SIG_SETMASK, mask, NULL);
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
        int code = (errno == ENOENT || errno == ENOTDIR) ? 127 : 126;
        fprintf (stderr, "bashxargs: %s: %s\n", argv[0], strerror (errno));
        _exit (code);
    }
    bx_stdin_attach (state, detached);
    return pid;
}

/* Run argv[0..n-1]. Returns one of BX_OK / BX_ANY_FAIL / BX_FATAL_255 /
   BX_SIGNALED / BX_NOEXEC / BX_NOTFOUND / BX_BAD. The child encodes its
   own failure to exec: exit 126 = found-but-cannot-exec, exit 127 =
   not-found. Anything else maps directly to its WEXITSTATUS.

   Bash installs its own SIGCHLD handler (waitchld) which calls
   WAITPID(-1, ...) and reaps ANY unwaited child — including ones a
   loadable fork()s directly. The caller blocks SIGCHLD for the whole
   invocation so Bash cannot steal our statuses. Restoring that mask
   once also avoids running Bash's reaper after every already-waited
   serial child. MASK is the separately selected child's mask. */
static int
bx_run (char **argv, int n, int tflag, bx_spawn_state *state,
        const sigset_t *mask)
{
    if (tflag) {
        for (int i = 0; i < n; i++) fprintf (stderr, "%s%s", i ? " " : "", argv[i]);
        fputc ('\n', stderr);
    }
    pid_t pid = bx_launch (argv, mask, state);
    if (pid > 0) {
        int status = 0;
        int wr;
        while ((wr = waitpid (pid, &status, 0)) < 0 && errno == EINTR) { }
        if (state->mask_error) return BX_BAD;
        if (wr < 0) {
            /* Either ECHILD (someone else reaped — defensive: shouldn't
               happen with SIGCHLD blocked) or a real error. Report it
               and fold to BX_BAD so the caller surfaces a fault rather
               than reading garbage out of `status`. */
            if (bx_end_mask_interval (state) < 0) return BX_BAD;
            builtin_error ("waitpid(%ld): %s", (long) pid, strerror (errno));
            return BX_BAD;
        }
        if (WIFSIGNALED (status)) {
            if (bx_end_mask_interval (state) < 0) return BX_BAD;
            int sig = WTERMSIG (status);
            fprintf (stderr, "bashxargs: %s: terminated by signal %d\n",
                     argv[0], sig);
            return BX_SIGNALED;
        }
        if (WIFEXITED (status)) {
            int s = WEXITSTATUS (status);
            if (s == 0)   return BX_OK;
            if (s == 127) return BX_NOTFOUND;
            if (s == 126) return BX_NOEXEC;
            if (s == 255) {
                if (bx_end_mask_interval (state) < 0) return BX_BAD;
                builtin_error ("%s: exited with status 255; aborting", argv[0]);
                return BX_FATAL_255;
            }
            return BX_ANY_FAIL;
        }
        return BX_ANY_FAIL;
    }
    if (state->mask_error) return BX_BAD;
    builtin_error ("fork: %s", strerror (errno));
    return BX_BAD;
}

static void
bx_restore_signal_mask (void *mask)
{
    int saved_errno = errno;
    sigprocmask (SIG_SETMASK, (const sigset_t *) mask, NULL);
    errno = saved_errno;
}

static pid_t
bx_spawn (char **argv, int n, int tflag, bx_spawn_state *state)
{
    if (tflag) {
        for (int i = 0; i < n; i++) fprintf (stderr, "%s%s", i ? " " : "", argv[i]);
        fputc ('\n', stderr);
    }

    sigset_t empty;
    sigemptyset (&empty);
    pid_t pid = bx_launch (argv, &empty, state);
    if (pid < 0 && !state->mask_error)
        builtin_error ("fork: %s", strerror (errno));
    (void)n;
    return pid;
}

/* A successful child still needs reaping if its transient mask restore
   failed. Keep its exact PID without invoking a replacement allocator. */
static void
bx_record_spawn (pid_t pid, const char *cmd, pid_t *pids, char **cmds,
                 int *count, const bx_spawn_state *state)
{
    pids[*count] = pid;
    cmds[(*count)++] = state->mask_error ? NULL : strdup (cmd);
}

static int
bx_status_to_rc (const char *cmd, int status)
{
    if (WIFSIGNALED (status)) {
        int sig = WTERMSIG (status);
        fprintf (stderr, "bashxargs: %s: terminated by signal %d\n", cmd, sig);
        return BX_SIGNALED;
    }
    if (WIFEXITED (status)) {
        int s = WEXITSTATUS (status);
        if (s == 0)   return BX_OK;
        if (s == 127) return BX_NOTFOUND;
        if (s == 126) return BX_NOEXEC;
        if (s == 255) {
            builtin_error ("%s: exited with status 255; aborting", cmd);
            return BX_FATAL_255;
        }
        return BX_ANY_FAIL;
    }
    return BX_ANY_FAIL;
}

/* Wait for one of this invocation's children. Waiting on any child would
   also collect the shell's own background jobs and lose their statuses.
   SIGCHLD stays blocked for the whole call, so an exit leaves it pending and
   sigtimedwait wakes for it; the timeout only bounds a missed wakeup. A
   consumed SIGCHLD is raised again before the call returns to Bash. */
static int
bx_wait_one (pid_t *pids, char **cmds, int *n_pids, int *fatal,
             bx_spawn_state *state)
{
    sigset_t chld;
    sigemptyset (&chld);
    sigaddset (&chld, SIGCHLD);
    while (*n_pids > 0) {
        for (int i = 0; i < *n_pids; i++) {
            int status = 0, rc;
            pid_t pid = waitpid (pids[i], &status, WNOHANG);
            if (pid == 0) continue;
            if (pid < 0) {
                if (errno == EINTR) { i--; continue; }
                builtin_error ("waitpid(%ld): %s", (long) pids[i], strerror (errno));
                rc = BX_BAD;
            } else
                rc = bx_status_to_rc (cmds[i], status);
            free (cmds[i]);
            pids[i] = pids[*n_pids - 1];
            cmds[i] = cmds[*n_pids - 1];
            (*n_pids)--;
            if (bx_is_fatal (rc)) *fatal = 1;
            return rc;
        }
        struct timespec timeout = { 1, 0 };
        if (sigtimedwait (&chld, NULL, &timeout) == SIGCHLD)
            state->sigchld_taken = 1;
    }
    return BX_OK;
}

int
xargs_builtin (WORD_LIST *list)
{
    int nul_sep = 0, rflag = 0, tflag = 0, pflag = 0;
    int max_n = 0, max_l = 0, max_p = 1;
    /* Reading stdin in the shell process leaves the EOF flag set for the next
       invocation, which would then build no command lines and exit 0. */
    clearerr (stdin);
    long s_flag = 0;          /* -s SIZE: 0 = unset (use default cap). */
    char *Iflag = NULL;

    /* Parse flags. */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashxargs 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-0")) { nul_sep = 1; list = list->next; continue; }
        if (!strcmp (w, "-r")) { rflag = 1; list = list->next; continue; }
        if (!strcmp (w, "-t")) { tflag = 1; list = list->next; continue; }
        if (!strcmp (w, "-p")) { pflag = 1; tflag = 1; list = list->next; continue; }
        if (w[1] == 'n' && w[2]) {
            if (bx_parse_positive_int (w + 2, &max_n) != 0) {
                builtin_error ("-n needs a positive count");
                builtin_usage ();
                return EX_USAGE;
            }
            if (max_l || (Iflag && max_n != 1)) {
                builtin_error ("warning: -n overrides previous -L or -I");
                max_l = 0;
                Iflag = NULL;
            }
            if (Iflag && max_n == 1) max_n = 0;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-n")) {
            if (!list->next) { builtin_error ("-n needs MAX"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (bx_parse_positive_int (list->word->word, &max_n) != 0) {
                builtin_error ("-n needs a positive count");
                builtin_usage ();
                return EX_USAGE;
            }
            if (max_l || (Iflag && max_n != 1)) {
                builtin_error ("warning: -n overrides previous -L or -I");
                max_l = 0;
                Iflag = NULL;
            }
            if (Iflag && max_n == 1) max_n = 0;
            list = list->next;
            continue;
        }
        if (w[1] == 'L' && w[2]) {
            if (bx_parse_positive_int (w + 2, &max_l) != 0) {
                builtin_error ("-L needs a positive count");
                builtin_usage ();
                return EX_USAGE;
            }
            if (max_n || Iflag) {
                builtin_error ("warning: -L overrides previous -n or -I");
                max_n = 0;
                Iflag = NULL;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-L")) {
            if (!list->next) { builtin_error ("-L needs MAX"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (bx_parse_positive_int (list->word->word, &max_l) != 0) {
                builtin_error ("-L needs a positive count");
                builtin_usage ();
                return EX_USAGE;
            }
            if (max_n || Iflag) {
                builtin_error ("warning: -L overrides previous -n or -I");
                max_n = 0;
                Iflag = NULL;
            }
            list = list->next;
            continue;
        }
        if (w[1] == 'P' && w[2]) {
            if (bx_parse_positive_int (w + 2, &max_p) != 0) {
                builtin_error ("-P needs a positive count");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-P")) {
            if (!list->next) { builtin_error ("-P needs MAX"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (bx_parse_positive_int (list->word->word, &max_p) != 0) {
                builtin_error ("-P needs a positive count");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (w[1] == 's' && w[2]) {
            if (bx_parse_positive_long (w + 2, &s_flag) != 0) {
                builtin_error ("-s needs a positive byte count");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-s")) {
            if (!list->next) { builtin_error ("-s needs SIZE"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (bx_parse_positive_long (list->word->word, &s_flag) != 0) {
                builtin_error ("-s needs a positive byte count");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (w[1] == 'I' && w[2]) {
            Iflag = (char *) (w + 2);
            if (max_n || max_l) {
                builtin_error ("warning: -I overrides previous -n or -L");
                max_n = max_l = 0;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-I")) {
            if (!list->next) { builtin_error ("-I needs REPL"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            Iflag = list->word->word;
            if (max_n || max_l) {
                builtin_error ("warning: -I overrides previous -n or -L");
                max_n = max_l = 0;
            }
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    /* Build template argv. Default if no CMD: /bin/echo. */
    int tmpl_n = 0;
    for (WORD_LIST *p = list; p; p = p->next) tmpl_n++;
    char **tmpl;
    int default_echo = 0;
    if (tmpl_n == 0) {
        tmpl = malloc (2 * sizeof *tmpl);
        if (!tmpl) return EXECUTION_FAILURE;
        tmpl[0] = (char *) "/bin/echo";
        tmpl[1] = NULL;
        tmpl_n = 1;
        default_echo = 1;
    } else {
        tmpl = malloc ((size_t) (tmpl_n + 1) * sizeof *tmpl);
        if (!tmpl) return EXECUTION_FAILURE;
        int i = 0;
        for (WORD_LIST *p = list; p; p = p->next) tmpl[i++] = p->word->word;
        tmpl[tmpl_n] = NULL;
    }

    bx_spawn_state spawn_state = { 0 };
#if defined (BX_PRIVATE_SPAWN)
    /* Formatted trace/prompt output and continuing parallel diagnostics
       can invoke application-registered printf conversion callbacks. */
    if (tflag || pflag || max_p > 1) spawn_state.clone_default_scan = -1;
#endif
    bx_batch_buffers buffers = { 0 };
    int rc = BX_OK;
    int got_any = 0;
    int too_long = 0;         /* a command line exceeded the byte limit */
    int pool_n = 0, pool_fatal = 0;
    pid_t *pool_pids = NULL;
    char **pool_cmds = NULL;
    sigset_t block_chld, prev_mask;
    int parallel = max_p > 1;
    if (parallel) {
        pool_pids = calloc ((size_t) max_p, sizeof *pool_pids);
        pool_cmds = calloc ((size_t) max_p, sizeof *pool_cmds);
        if (!pool_pids || !pool_cmds) {
            free (pool_pids); free (pool_cmds); free (tmpl);
            return BX_BAD;
        }
    }
    /* Register restoration before changing the mask, including for Bash
       non-local unwinds. Children receive their separate original/empty
       masks; only this invocation's parent defers SIGCHLD delivery. */
    if (sigprocmask (SIG_SETMASK, NULL, &prev_mask) < 0) {
        builtin_error ("sigprocmask: %s", strerror (errno));
        free (pool_pids); free (pool_cmds); free (tmpl);
        return BX_BAD;
    }
    begin_unwind_frame ("bashxargs-signal-mask");
    add_unwind_protect (bx_restore_signal_mask, &prev_mask);
    add_unwind_protect (bx_spawn_state_cleanup, &spawn_state);
    add_unwind_protect (bx_batch_buffers_cleanup, &buffers);
    add_unwind_protect (bx_mask_interval_cleanup, &spawn_state);
    sigemptyset (&block_chld);
    sigaddset (&block_chld, SIGCHLD);
    if (sigprocmask (SIG_BLOCK, &block_chld, NULL) < 0) {
        builtin_error ("sigprocmask: %s", strerror (errno));
        rc = BX_BAD;
        goto cleanup;
    }

    /* GNU xargs refuses a command line whose bytes, counting every argument
       and its terminating NUL, exceed -s SIZE or its 131072-byte buffer. It
       runs the lines already complete, reports "argument line too long" and
       exits 1 rather than launching the oversized command. */
    size_t line_limit = s_flag > 0 ? (size_t) s_flag : 131072;
    size_t tmpl_bytes = 0;
    for (int i = 0; i < tmpl_n; i++) tmpl_bytes += strlen (tmpl[i]) + 1;

    if (Iflag) {
        /* -I REPL: run CMD once per input, with REPL replaced by the input. */
        char *arg;
        int read_error = 0;
        while ((arg = bx_read_arg (stdin, nul_sep, 1, &read_error)) != NULL) {
            got_any = 1;
            char **argv = malloc ((size_t) (tmpl_n + 1) * sizeof *argv);
            if (!argv) { free (arg); break; }
            size_t Ilen = strlen (Iflag);
            size_t alen = strlen (arg);
            for (int i = 0; i < tmpl_n; i++) {
                /* Replace EVERY occurrence of REPL in tmpl[i] with arg.
                   GNU xargs parity: `-I X echo a-X-b-X` with input "foo"
                   yields "echo a-foo-b-foo", not "echo a-foo-b-X". The
                   scan advances past each substitution so a REPL byte
                   that appears inside the input itself does NOT trigger
                   re-substitution (also GNU parity).  Empty REPL → no
                   substitution (avoids an infinite strstr loop and keeps
                   the diagnostic clean; GNU xargs rejects it as "command
                   too long"). */
                if (Ilen == 0) {
                    argv[i] = strdup (tmpl[i]);
                    continue;
                }
                const char *src = tmpl[i];
                size_t nocc = 0;
                const char *scan = src;
                const char *hit;
                while ((hit = strstr (scan, Iflag)) != NULL) {
                    nocc++;
                    scan = hit + Ilen;
                }
                if (nocc == 0) {
                    argv[i] = strdup (tmpl[i]);
                    continue;
                }
                size_t outlen = strlen (src) + nocc * alen - nocc * Ilen;
                char *out = malloc (outlen + 1);
                if (!out) {
                    /* Allocation failure: fall back to template-as-is
                       so the run continues; the missing substitution
                       will surface as a child error. */
                    argv[i] = strdup (tmpl[i]);
                    continue;
                }
                const char *p = src;
                char *o = out;
                while ((hit = strstr (p, Iflag)) != NULL) {
                    size_t lhs = (size_t) (hit - p);
                    memcpy (o, p, lhs); o += lhs;
                    memcpy (o, arg, alen); o += alen;
                    p = hit + Ilen;
                }
                memcpy (o, p, strlen (p) + 1);
                argv[i] = out;
            }
            argv[tmpl_n] = NULL;
            size_t line_bytes = 0;
            for (int i = 0; i < tmpl_n; i++) line_bytes += (argv[i] ? strlen (argv[i]) : 0) + 1;
            if (line_bytes > line_limit) {
                builtin_error ("argument line too long");
                too_long = 1;
                for (int i = 0; i < tmpl_n; i++) free (argv[i]);
                free (argv);
                free (arg);
                break;
            }
            int r = BX_OK;
            if (!pflag || bx_prompt_yes (argv, tmpl_n)) {
                if (parallel) {
                    while (pool_n >= max_p) {
                        r = bx_wait_one (pool_pids, pool_cmds, &pool_n, &pool_fatal, &spawn_state);
                        rc = bx_fold (rc, r);
                        if (pool_fatal) break;
                    }
                    if (!pool_fatal) {
                        pid_t pid = bx_spawn (argv, tmpl_n, tflag, &spawn_state);
                        if (pid < 0) { r = BX_BAD; rc = bx_fold (rc, r); }
                        else bx_record_spawn (pid, argv[0], pool_pids, pool_cmds,
                                              &pool_n, &spawn_state);
                    }
                } else {
                    r = bx_run (argv, tmpl_n, tflag, &spawn_state, &prev_mask);
                    rc = bx_fold (rc, r);
                }
            }
            if (spawn_state.mask_error) bx_mask_interval_cleanup (&spawn_state);
            for (int i = 0; i < tmpl_n; i++) free (argv[i]);
            free (argv);
            free (arg);
            if (spawn_state.mask_error) { rc = BX_BAD; goto cleanup; }
            /* GNU xargs aborts after a fatal child (signaled, 255, or
               exec failure). Drop the rest of stdin and stop. */
            if (bx_is_fatal (r) || pool_fatal) break;
        }
        if (read_error) {
            if (bx_report_read_error (&spawn_state, read_error) < 0) {
                rc = BX_BAD;
                goto cleanup;
            }
            rc = bx_fold (rc, BX_BAD);
        }
    } else {
        /* Batch mode: collect args up to max_n (or per-batch byte limit).
           Default cap is min(ARG_MAX/2, 65536); -s SIZE overrides it.
           The accumulator (`batch_bytes`) tracks input-arg bytes only,
           so when -s is given we subtract the template overhead
           (sum of strlen(tmpl[i])+1) once up front. If the template
           already meets or exceeds SIZE, no input can fit — diagnose
           and exit EX_USAGE, matching GNU "argument list too long". */
        long arg_max = sysconf (_SC_ARG_MAX);
        if (arg_max <= 0) arg_max = 131072;
        size_t cap_bytes;
        if (s_flag > 0) {
            if ((size_t) s_flag <= tmpl_bytes) {
                builtin_error ("-s %ld: argument list too long (template alone needs %zu bytes)",
                               s_flag, tmpl_bytes);
                rc = EX_USAGE;
                goto cleanup;
            }
            cap_bytes = (size_t) s_flag - tmpl_bytes;
        } else {
            cap_bytes = (size_t) arg_max / 2;
            if (cap_bytes > 65536) cap_bytes = 65536;
        }

        size_t batch_n = 0;
        size_t batch_bytes = 0;
        size_t batch_line = 0, arg_line = 0;
        bx_input_state input = { 0 };
        if (bx_batch_reserve (&buffers, 64, tmpl_n) < 0) {
            rc = BX_BAD;
            goto cleanup;
        }
        for (int i = 0; i < tmpl_n; i++) buffers.argv[i] = tmpl[i];
        char *arg;
        int read_error = 0;
        int aborted_fatal = 0;
        /* Keep the existing one-argument lookahead: read before deciding
           whether the preceding batch must run, including fatal stops.
           Swapping its storage with each slot reuses argument capacities
           without copying bytes or overwriting the batch being launched. */
        while ((arg = bx_read_arg_into (stdin, nul_sep, 0, &read_error,
                                       &buffers.lookahead,
                                       bx_plain_span_allowed (&spawn_state),
                                       &input, &arg_line)) != NULL) {
            got_any = 1;
            size_t alen = strlen (arg) + 1;
            int flush = 0;
            if (max_n > 0 && (int) batch_n >= max_n) flush = 1;
            if (max_l > 0 && batch_n > 0 &&
                arg_line - batch_line >= (size_t) max_l) flush = 1;
            /* -L implies GNU's -x: do not split a logical batch to fit -s. */
            if (max_l > 0 && !flush && batch_n > 0 &&
                batch_bytes + alen > cap_bytes) {
                if (bx_end_mask_interval (&spawn_state) < 0) {
                    rc = BX_BAD;
                    goto cleanup;
                }
                builtin_error ("argument list too long");
                too_long = 1;
                batch_n = 0;
                break;
            }
            if (batch_n > 0 && batch_bytes + alen > cap_bytes) flush = 1;
            if (flush) {
                /* Build argv = template + batch. */
                int total = tmpl_n + (int) batch_n;
                char **argv = buffers.argv;
                for (size_t i = 0; i < batch_n; i++) argv[tmpl_n + i] = buffers.args[i].data;
                argv[total] = NULL;
                int r = BX_OK;
                if (!pflag || bx_prompt_yes (argv, total)) {
                    if (parallel) {
                        while (pool_n >= max_p) {
                            r = bx_wait_one (pool_pids, pool_cmds, &pool_n, &pool_fatal, &spawn_state);
                            rc = bx_fold (rc, r);
                            if (pool_fatal) break;
                        }
                        if (!pool_fatal) {
                            pid_t pid = bx_spawn (argv, total, tflag, &spawn_state);
                            if (pid < 0) { r = BX_BAD; rc = bx_fold (rc, r); }
                            else bx_record_spawn (pid, argv[0], pool_pids, pool_cmds,
                                              &pool_n, &spawn_state);
                        }
                    } else {
                        r = bx_run (argv, total, tflag, &spawn_state, &prev_mask);
                        rc = bx_fold (rc, r);
                    }
                }
                batch_n = 0; batch_bytes = 0;
                if (spawn_state.mask_error) { rc = BX_BAD; goto cleanup; }
                if (bx_is_fatal (r) || pool_fatal) { aborted_fatal = 1; break; }
            }
            /* The batch before it has already run. Stop without launching. */
            if (tmpl_bytes + alen > line_limit) {
                builtin_error ("argument line too long");
                too_long = 1;
                break;
            }
            if (batch_n >= buffers.capacity) {
                if (bx_batch_reserve (&buffers, buffers.capacity * 2, tmpl_n) < 0) {
                    rc = BX_BAD;
                    goto cleanup;
                }
            }
            if (batch_n == 0) batch_line = arg_line;
            bx_arg_buffer spare = buffers.args[batch_n];
            buffers.args[batch_n++] = buffers.lookahead;
            /* Retain the small initial allocation, but do not let large
               arguments accumulate spare capacity across later batches. */
            if (spare.capacity > 64) {
                free (spare.data);
                spare.data = NULL;
                spare.capacity = 0;
            }
            buffers.lookahead = spare;
            batch_bytes += alen;
        }
        if (read_error) {
            if (bx_report_read_error (&spawn_state, read_error) < 0) {
                rc = BX_BAD;
                goto cleanup;
            }
            rc = bx_fold (rc, BX_BAD);
        }
        /* GNU -L only runs complete logical batches after a parse error.
           Ordinary -n mode still flushes its successfully parsed words. */
        if (read_error && max_l > 0 &&
            input.line - batch_line < (size_t) max_l)
            batch_n = 0;
        /* Final flush — only if we didn't abort on a fatal child. */
        if (!aborted_fatal && batch_n > 0) {
            int total = tmpl_n + (int) batch_n;
            char **argv = buffers.argv;
            for (size_t i = 0; i < batch_n; i++) argv[tmpl_n + i] = buffers.args[i].data;
            argv[total] = NULL;
            int r = BX_OK;
            if (!pflag || bx_prompt_yes (argv, total)) {
                if (parallel) {
                    while (pool_n >= max_p) {
                        r = bx_wait_one (pool_pids, pool_cmds, &pool_n, &pool_fatal, &spawn_state);
                        rc = bx_fold (rc, r);
                        if (pool_fatal) break;
                    }
                    if (!pool_fatal) {
                        pid_t pid = bx_spawn (argv, total, tflag, &spawn_state);
                        if (pid < 0) { r = BX_BAD; rc = bx_fold (rc, r); }
                        else bx_record_spawn (pid, argv[0], pool_pids, pool_cmds,
                                              &pool_n, &spawn_state);
                    }
                } else {
                    r = bx_run (argv, total, tflag, &spawn_state, &prev_mask);
                    rc = bx_fold (rc, r);
                }
            }
        }
    }

    /* A successful empty read runs CMD once unless -r or -I suppresses it.
       A parse error must not fall through to an empty-input invocation. */
    if (!got_any && !rflag && !Iflag && rc == BX_OK) {
        char **argv = malloc ((size_t) (tmpl_n + 1) * sizeof *argv);
        if (!argv) { rc = bx_fold (rc, BX_BAD); goto cleanup; }
        for (int i = 0; i < tmpl_n; i++) argv[i] = tmpl[i];
        argv[tmpl_n] = NULL;
        int r = BX_OK;
        if (!pflag || bx_prompt_yes (argv, tmpl_n)) {
            /* The existing no-input parallel case runs synchronously
               with the pool's SIGCHLD guard included in its child mask. */
            sigset_t once_mask = prev_mask;
            if (parallel) sigaddset (&once_mask, SIGCHLD);
            r = bx_run (argv, tmpl_n, tflag, &spawn_state, &once_mask);
            rc = bx_fold (rc, r);
        }
        if (spawn_state.mask_error) bx_mask_interval_cleanup (&spawn_state);
        free (argv);
    }

cleanup:
    bx_mask_interval_cleanup (&spawn_state);
    if (spawn_state.mask_error) rc = BX_BAD;
    if (parallel && spawn_state.mask_error) {
        /* A transient-mask failure may follow a successful launch. Reap
           every recorded child without allocation or formatted diagnostics;
           missing command metadata in this path is intentional. */
        while (pool_n > 0) {
            int status;
            pool_n--;
            while (waitpid (pool_pids[pool_n], &status, 0) < 0 && errno == EINTR) { }
            if (pool_cmds[pool_n]) free (pool_cmds[pool_n]);
        }
    } else while (parallel && pool_n > 0) {
        int r = bx_wait_one (pool_pids, pool_cmds, &pool_n, &pool_fatal, &spawn_state);
        rc = bx_fold (rc, r);
    }
    if (parallel) {
        free (pool_pids);
        free (pool_cmds);
    }

    /* GNU exits 1 at once; here the commands already started were waited for. */
    if (too_long) rc = BX_BAD;
    if (default_echo) free (tmpl); else free (tmpl);
    /* Still blocked: Bash handles it once the mask is restored. */
    if (spawn_state.sigchld_taken) raise (SIGCHLD);
    run_unwind_frame ("bashxargs-signal-mask");
    return rc;
}

char *xargs_doc[] = {
    "Run an enabled builtin or external command for each argument batch.",
    "Build and run command lines from stdin.",
    "",
    "    bashxargs [-0rtp] [-n MAX] [-L MAX] [-P MAX] [-s SIZE]",
    "              [-I REPL] [CMD [ARG...]]",
    "    bashxargs --help | --version",
    "",
    "    -0        NUL-separated input (pair with `find -print0`)",
    "    -r        no-run-if-empty",
    "    -t        echo command before run",
    "    -p        prompt before run (yes/no)",
    "    -n MAX    max args per invocation",
    "    -L MAX    max nonblank logical input lines per invocation",
    "    -P MAX    run up to MAX invocations in parallel",
    "    -s SIZE   max command-line bytes per invocation (POSIX/GNU)",
    "    -I REPL   substitute REPL with input arg; run once per input",
    (char *)NULL
};

struct builtin bashxargs_struct = {
    "bashxargs",
    xargs_builtin,
    BUILTIN_ENABLED,
    xargs_doc,
    "bashxargs [-0rtp] [-n MAX] [-L MAX] [-P MAX] [-s SIZE] [-I REPL] [CMD [ARG...]]",
    0
};
