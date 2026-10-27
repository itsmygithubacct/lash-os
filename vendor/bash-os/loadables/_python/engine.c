/* SPDX-License-Identifier: MIT */
/* Python's full command line, in a process that exists for one invocation. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "engine.h"

int
bos_python_run(int argc, char **argv, const char *home)
{
    PyConfig config;
    PyStatus status;
    PyConfig_InitPythonConfig(&config);
    /* Parse options, -c, -m, a script or standard input exactly as python3 does. */
    status = PyConfig_SetBytesArgv(&config, argc, argv);
    /* An explicit PYTHONHOME wins, as it does for python3. */
    if (!PyStatus_Exception(status) && home && *home && !bos_python_env_getenv("PYTHONHOME"))
        status = PyConfig_SetBytesString(&config, &config.home, home);
    if (!PyStatus_Exception(status))
        status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) {
        if (PyStatus_IsExit(status))
            return status.exitcode;
        Py_ExitStatusException(status);
    }
    /* Returns the exit status; an unhandled KeyboardInterrupt ends the
       process with SIGINT, as it does for python3. */
    return Py_RunMain();
}
