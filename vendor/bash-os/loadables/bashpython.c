/* SPDX-License-Identifier: MIT */
/* Real Python, linked with a static libpython, run in a child of the shell. */
#include <config.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(BASHOS_PYTHON_MODULE)
#include <dlfcn.h>
#endif
#include "loadables.h"
#include "command-run.h"
#include "_python_engine.h"

extern char **environ;

#if defined(BASHOS_PYTHON_MODULE)
/* <root>/usr/lib/bash-os/loadables/bashpython.so finds its standard library
   in <root>/usr/lib/bash-os/share/bashpython, where pkg installs it. */
static char bpy_home[PATH_MAX];
#elif defined(BASHOS_PYTHON_HOME)
static const char bpy_home[] = BASHOS_PYTHON_HOME;
#else
static const char bpy_home[] = "";
#endif

int
bashpython_builtin(WORD_LIST *list)
{
    struct sigaction ignore, old_int, old_quit, old_chld, dfl;
    sigset_t chld, old_mask;
    char **argv;
    int argc, wstatus;
    pid_t pid;

    maybe_make_export_env();
    argv = make_builtin_argv(list, &argc);
    if (fflush(stdout) == EOF || fflush(stderr) == EOF) {
        builtin_error("cannot flush output: %s", strerror(errno));
        free(argv);
        return EXECUTION_FAILURE;
    }
    /* Keep Bash's SIGCHLD handler from reaping the child before we wait. */
    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigaction(SIGCHLD, &dfl, &old_chld);
    sigprocmask(SIG_BLOCK, &chld, &old_mask);

    pid = fork();
    if (pid == 0) {
        /* The interpreter never touches the shell: it runs, then this process
           exits without returning to the Bash code that forked it. */
        bos_prepare_child();
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        environ = export_env;
        _exit(bos_python_run(argc, argv, bpy_home) & 255);
    }
    free(argv);
    if (pid < 0) {
        int saved = errno;
        sigaction(SIGCHLD, &old_chld, NULL);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        builtin_error("fork: %s", strerror(saved));
        return EXECUTION_FAILURE;
    }
    /* Like system(): the child alone reacts to keyboard interrupts. */
    memset(&ignore, 0, sizeof(ignore));
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    sigaction(SIGINT, &ignore, &old_int);
    sigaction(SIGQUIT, &ignore, &old_quit);
    while (waitpid(pid, &wstatus, 0) < 0) {
        if (errno != EINTR) {
            wstatus = 0;
            builtin_error("waitpid: %s", strerror(errno));
            break;
        }
    }
    sigaction(SIGINT, &old_int, NULL);
    sigaction(SIGQUIT, &old_quit, NULL);
    sigaction(SIGCHLD, &old_chld, NULL);
    sigprocmask(SIG_SETMASK, &old_mask, NULL);
    if (WIFSIGNALED(wstatus)) {
        /* An interrupted Python interrupts the shell, as it would for python3. */
        if (WTERMSIG(wstatus) == SIGINT)
            raise(SIGINT);
        return 128 + WTERMSIG(wstatus);
    }
    return WEXITSTATUS(wstatus);
}

#if defined(BASHOS_PYTHON_MODULE)
int
bashpython_builtin_load(char *name)
{
    Dl_info info;
    char *slash;
    (void)name;
    if (!dladdr((void *)bashpython_builtin_load, &info) || !info.dli_fname ||
        strlen(info.dli_fname) >= sizeof(bpy_home)) {
        builtin_error("cannot locate the loaded module");
        return 0;
    }
    strcpy(bpy_home, info.dli_fname);
    slash = strrchr(bpy_home, '/');
    if (slash)
        slash[1] = '\0';
    else
        strcpy(bpy_home, "./");
    if (strlen(bpy_home) + sizeof("../share/bashpython") > sizeof(bpy_home)) {
        builtin_error("module path is too long");
        return 0;
    }
    strcat(bpy_home, "../share/bashpython");
    {
        char resolved[PATH_MAX];
        if (realpath(bpy_home, resolved))
            strcpy(bpy_home, resolved);
    }
    return 1;
}
#endif

char *bashpython_doc[] = {
    "Run real Python in a child of the current shell.",
    "",
    "Accepts python3 options, -c programs, -m modules, script files, standard",
    "input and the interactive prompt. Each invocation is a separate process",
    "that runs the embedded interpreter; it shares nothing with the next one.",
    "The shell's exported variables form Python's environment. The exit status",
    "is Python's; an unhandled KeyboardInterrupt also interrupts the shell.",
    (char *)0
};

struct builtin bashpython_struct = {
    "bashpython", bashpython_builtin, BUILTIN_ENABLED, bashpython_doc,
    "bashpython [PYTHON-OPTION ...] [-c COMMAND | -m MODULE | SCRIPT | -] [ARG ...]", 0
};
