/* SPDX-License-Identifier: MIT */
#ifndef BASHOS_PERL_ENGINE_H
#define BASHOS_PERL_ENGINE_H

/* Keep Perl's headers and their macros out of the Bash translation unit. */
int bos_perl_run(int argc, char **argv);
int bos_perl_take_interrupt(void);
void bos_perl_abort(void);
void bos_perl_shutdown(void);
void bos_perl_env_cleanup(void);

#endif
