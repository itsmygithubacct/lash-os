#include <stdio.h>
#include <stdio-bufio.h>
#include <unistd.h>

/* Bufio input needs storage even when reads should be unbuffered. Keeping
 * exactly one byte avoids reading ahead across commands that share fd 0. */
static char input_byte;
static struct __file_bufio input_stream =
    FDEV_SETUP_BUFIO(STDIN_FILENO, &input_byte, 1, read, NULL, lseek, NULL, __SRD, 0);

/* Override the weak, zero-capacity standard input in Capsule's platform. */
FILE *const stdin = (FILE *)&input_stream;
