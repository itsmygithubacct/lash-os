#include <stdio.h>
#include <stdio-bufio.h>
#include <unistd.h>

/* Picolibc bufio needs storage even for unbuffered streams. One byte avoids
 * reading ahead on stdin and makes stdout/stderr usable before Bash sets
 * their buffering mode, including for early --help/--version/error exits. */
static char input_byte, output_byte, error_byte;
static struct __file_bufio input_stream =
    FDEV_SETUP_BUFIO(STDIN_FILENO, &input_byte, 1, read, NULL, lseek, NULL, __SRD, 0);
static struct __file_bufio output_stream =
    FDEV_SETUP_BUFIO(STDOUT_FILENO, &output_byte, 1, NULL, write, lseek, NULL, __SWR, 0);
static struct __file_bufio error_stream =
    FDEV_SETUP_BUFIO(STDERR_FILENO, &error_byte, 1, NULL, write, lseek, NULL, __SWR, 0);

/* Override Capsule's weak, zero-capacity standard streams. */
FILE *const stdin = (FILE *)&input_stream;
FILE *const stdout = (FILE *)&output_stream;
FILE *const stderr = (FILE *)&error_stream;
