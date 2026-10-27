/* SPDX-License-Identifier: MIT */
/* Real Perl in the shell process, linked with a static libperl. */
#include <config.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(BASHOS_PERL_MODULE)
#include <dlfcn.h>
#endif
#if defined(__linux__)
#include <sys/prctl.h>
#endif
#include "loadables.h"
#include "unwind_prot.h"
#include "_perl_engine.h"

extern char **environ;

typedef struct {
    char **argv, **env, **saved_env;
    char *locale;
    locale_t thread_locale;
    struct sigaction signals[NSIG];
    unsigned char valid_signal[NSIG];
    sigset_t mask;
    int fd[3], fd_flags[3], status_flags[3], cwd;
    int have_mask, have_umask, have_env, errors;
    pid_t pid;
    mode_t mask_value;
#if defined(__linux__)
    char comm[16];
    int have_comm;
#endif
} bp_state;

static int bp_busy;

static char **
bp_copy_vector(char **source)
{
    size_t count = 0;
    char **copy;
    while (source && source[count])
        count++;
    copy = xmalloc((count + 1) * sizeof(*copy));
    for (size_t i = 0; i < count; i++)
        copy[i] = savestring(source[i]);
    copy[count] = NULL;
    return copy;
}

static void
bp_free_vector(char **vector)
{
    if (vector) {
        for (size_t i = 0; vector[i]; i++)
            free(vector[i]);
        free(vector);
    }
}

static void
bp_restore(bp_state *state)
{
    sigset_t all;
    sigfillset(&all);
    if (state->have_mask && sigprocmask(SIG_BLOCK, &all, NULL) < 0)
        state->errors = 1;
    bos_perl_abort();
    if (state->have_env)
        environ = state->saved_env;
    state->have_env = 0;
    bos_perl_env_cleanup();
    if (state->cwd >= 0) {
        if (fchdir(state->cwd) < 0)
            state->errors = 1;
        close(state->cwd);
        state->cwd = -1;
    }
    if (state->have_umask)
        umask(state->mask_value);
    for (int fd = 0; fd < 3; fd++) {
        if (state->fd[fd] >= 0) {
            if (dup2(state->fd[fd], fd) < 0 ||
                fcntl(fd, F_SETFD, state->fd_flags[fd]) < 0 ||
                fcntl(fd, F_SETFL, state->status_flags[fd]) < 0)
                state->errors = 1;
            close(state->fd[fd]);
            state->fd[fd] = -1;
        } else if (state->fd_flags[fd] == -1) {
            close(fd);
        }
    }
    clearerr(stdin);
    clearerr(stdout);
    clearerr(stderr);
    if (state->locale && !setlocale(LC_ALL, state->locale))
        state->errors = 1;
    if (state->thread_locale && !uselocale(state->thread_locale))
        state->errors = 1;
#if defined(__linux__)
    if (state->have_comm && prctl(PR_SET_NAME, state->comm) < 0)
        state->errors = 1;
#endif
    for (int sig = 1; sig < NSIG; sig++)
        if (state->valid_signal[sig] && sigaction(sig, &state->signals[sig], NULL) < 0)
            state->errors = 1;
    bp_free_vector(state->argv);
    bp_free_vector(state->env);
    free(state->locale);
    state->argv = state->env = NULL;
    state->locale = NULL;
    bp_busy = 0;
    if (state->have_mask) {
        state->have_mask = 0;
        if (sigprocmask(SIG_SETMASK, &state->mask, NULL) < 0)
            state->errors = 1;
    }
}

static void
bp_unwind(void *opaque)
{
    bp_state *state = (bp_state *)opaque;
    bp_restore(state);
    free(state);
}

int
bashperl_builtin(WORD_LIST *list)
{
    bp_state *state;
    char **argv;
    const char *locale;
    int argc, status = EXECUTION_FAILURE;
    if (bp_busy) {
        builtin_error("recursive interpreter invocation is not supported");
        return EXECUTION_FAILURE;
    }
    state = xmalloc(sizeof(*state));
    memset(state, 0, sizeof(*state));
    state->cwd = -1;
    state->pid = getpid();
    for (int fd = 0; fd < 3; fd++) {
        state->fd[fd] = -1;
        state->fd_flags[fd] = -2;
    }
    bp_busy = 1;
    begin_unwind_frame("bashperl-state");
    add_unwind_protect(bp_unwind, (char *)state);
    maybe_make_export_env();
    state->env = bp_copy_vector(export_env);
    argv = make_builtin_argv(list, &argc);
    state->argv = bp_copy_vector(argv);
    free(argv);
    for (int fd = 0; fd < 3; fd++) {
        state->fd_flags[fd] = fcntl(fd, F_GETFD);
        if (state->fd_flags[fd] < 0) {
            if (errno == EBADF)
                continue;
            goto unavailable;
        }
        state->status_flags[fd] = fcntl(fd, F_GETFL);
        state->fd[fd] = fcntl(fd, F_DUPFD_CLOEXEC, 10);
        if (state->status_flags[fd] < 0 || state->fd[fd] < 0)
            goto unavailable;
    }
    {
        int cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (cwd < 0)
            goto unavailable;
        state->cwd = fcntl(cwd, F_DUPFD_CLOEXEC, 10);
        close(cwd);
        if (state->cwd < 0)
            goto unavailable;
    }
    if (sigprocmask(SIG_SETMASK, NULL, &state->mask) < 0)
        goto unavailable;
    state->have_mask = 1;
    for (int sig = 1; sig < NSIG; sig++) {
        if (sig == SIGKILL || sig == SIGSTOP)
            continue;
        if (sigaction(sig, NULL, &state->signals[sig]) == 0)
            state->valid_signal[sig] = 1;
        else if (errno != EINVAL)
            goto unavailable;
    }
    locale = setlocale(LC_ALL, NULL);
    if (!locale)
        goto unavailable;
    state->locale = savestring(locale);
    state->thread_locale = uselocale((locale_t)0);
    state->mask_value = umask(0);
    umask(state->mask_value);
    state->have_umask = 1;
#if defined(__linux__)
    state->have_comm = prctl(PR_GET_NAME, state->comm) == 0;
#endif
    if (fflush(stdout) == EOF || fflush(stderr) == EOF)
        goto unavailable;
    state->saved_env = environ;
    environ = state->env;
    state->have_env = 1;
    status = bos_perl_run(argc, state->argv);
    if (getpid() != state->pid) {
        /* A Perl fork child finishes its Perl program, never the surrounding
           Bash script. Avoid the shell's inherited process-exit callbacks. */
        fflush(stdout);
        fflush(stderr);
        _exit(status);
    }
    goto done;
unavailable:
    builtin_error("cannot prepare interpreter: %s", strerror(errno));
done:
    bp_restore(state);
    discard_unwind_frame("bashperl-state");
    if (state->errors) {
        builtin_error("could not restore shell process state");
        status = EXECUTION_FAILURE;
    }
    free(state);
    if (bos_perl_take_interrupt())
        raise(SIGINT);
    return status;
}

#if defined(BASHOS_PERL_MODULE)
int
bashperl_builtin_load(char *name)
{
    Dl_info info;
    void *existing = dlsym(RTLD_DEFAULT, "perl_alloc");
    void *ours = dlsym(RTLD_DEFAULT, "bos_perl_run");
    void *handle;
    (void)name;
    if (existing && ours != (void *)bos_perl_run) {
        builtin_error("a different embedded Perl is already loaded");
        return 0;
    }
    /* Bash loads modules with RTLD_LOCAL. XS extensions need the Perl API
       in the global symbol scope, just as when libperl is in the executable. */
    if (!dladdr((void *)bashperl_builtin_load, &info) ||
        !(handle = dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD | RTLD_GLOBAL))) {
        builtin_error("cannot expose the Perl API for XS modules");
        return 0;
    }
    dlclose(handle);
    return 1;
}
#endif

void
bashperl_builtin_unload(char *name)
{
    (void)name;
    bos_perl_abort();
}

char *bashperl_doc[] = {
    "Run real Perl in the current shell process.",
    "",
    "Accepts Perl options, -e programs, script files, standard input and ARGV.",
    "Each invocation has a fresh interpreter. Its exit status includes END blocks.",
    "The shell's exported variables are copied into Perl's environment.",
    "Standard descriptors, signals, environment, cwd, umask and locale are restored.",
    "Use a shell subshell for process isolation of Perl or native XS modules.",
    (char *)0
};

struct builtin bashperl_struct = {
    "bashperl", bashperl_builtin, BUILTIN_ENABLED, bashperl_doc,
    "bashperl [PERL-OPTION ...] [-e PROGRAM | SCRIPT] [ARG ...]", 0
};
