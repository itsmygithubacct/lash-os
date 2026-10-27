/* SPDX-License-Identifier: MIT */
/* Fresh embedded Perl interpreters, using Perl's public embedding API. */
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <bashperl-xs.h>
#include "engine.h"

#ifndef MULTIPLICITY
#error bashperl requires Perl configured with -Dusemultiplicity
#endif

static PerlInterpreter *active_perl;
static int system_ready;
static int interrupted;
static int quiesce_failed;

static void
bos_perl_quiesce(pTHX_ void *unused)
{
    sigset_t all;
    PERL_UNUSED_CONTEXT;
    PERL_UNUSED_ARG(unused);
    /* Registered first, called last: END blocks, object destructors, and XS
       exit callbacks still receive signals. Block them before Perl frees its
       signal data and interpreter; Bash restores its handlers and mask next. */
    sigfillset(&all);
    quiesce_failed = sigprocmask(SIG_BLOCK, &all, NULL) < 0;
}

static XS(bos_perl_interrupt)
{
    dXSARGS;
    PERL_UNUSED_VAR(items);
    interrupted = 1;
    Perl_my_exit(aTHX_ 128 + SIGINT);
}

static void
bos_perl_xs_init(pTHX)
{
    struct sigaction action;
    bos_perl_static_xs_init(aTHX);
    /* Use Perl's deferred signal dispatch so an interrupt leaves its stacks
       through Perl's own exit handler. A program can replace this handler. */
    if (sigaction(SIGINT, NULL, &action) == 0 && action.sa_handler != SIG_IGN) {
        CV *handler = newXS("BashPerl::_interrupt", bos_perl_interrupt, __FILE__);
        HV *signals = get_hv("SIG", GV_ADD);
        SV **slot = hv_fetch(signals, "INT", 3, 1);
        sv_setsv(*slot, sv_2mortal(newRV_inc((SV *)handler)));
        SvSETMAGIC(*slot);
    }
}

int
bos_perl_run(int argc, char **argv)
{
    PerlInterpreter *my_perl;
    int parsed, status;
    interrupted = 0;
    quiesce_failed = 0;
    if (!system_ready) {
        /* argv and environ belong to this invocation, never to Bash. */
        PERL_SYS_INIT3(&argc, &argv, &environ);
        system_ready = 1;
        /* The runtime module is NODELETE, so this callback remains mapped.
           System initialization spans the process, including enable -d/-f. */
        if (atexit(bos_perl_shutdown) != 0) {
            bos_perl_shutdown();
            return 1;
        }
    }
    my_perl = perl_alloc();
    if (!my_perl)
        return 1;
    active_perl = my_perl;
    PERL_SET_CONTEXT(my_perl);
    perl_construct(my_perl);
    call_atexit(bos_perl_quiesce, NULL);
    PL_perl_destruct_level = 1;
    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
    /* $0 must never overwrite the shell's argument or environment storage. */
    PL_origalen = 1;
    parsed = perl_parse(my_perl, bos_perl_xs_init, argc, argv, NULL);
    if (parsed == 0)
        perl_run(my_perl);
    /* Includes compile failures, explicit exit, and END block status. */
    status = perl_destruct(my_perl);
    active_perl = NULL;
    perl_free(my_perl);
    PERL_SET_CONTEXT(NULL);
    return quiesce_failed ? 1 : status & 255;
}

int
bos_perl_take_interrupt(void)
{
    int result = interrupted;
    interrupted = 0;
    return result;
}

void
bos_perl_abort(void)
{
    PerlInterpreter *my_perl = active_perl;
    if (!my_perl)
        return;
    active_perl = NULL;
    PERL_SET_CONTEXT(my_perl);
    /* A Bash unwind must not start another user END block. */
    PL_exit_flags &= ~PERL_EXIT_DESTRUCT_END;
    PL_perl_destruct_level = 1;
    perl_destruct(my_perl);
    perl_free(my_perl);
    PERL_SET_CONTEXT(NULL);
}

void
bos_perl_shutdown(void)
{
    bos_perl_abort();
    if (system_ready) {
        PERL_SYS_TERM();
        system_ready = 0;
    }
}
