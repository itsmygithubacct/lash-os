/* SPDX-License-Identifier: MIT */
#ifndef BASHOS_PYTHON_ENGINE_H
#define BASHOS_PYTHON_ENGINE_H

/* Keep Python's headers and their macros out of the Bash translation unit. */
int bos_python_run(int argc, char **argv, const char *home);
char *bos_python_env_getenv(const char *name);

#endif
