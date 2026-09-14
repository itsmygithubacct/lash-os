#include "error.h"
void mbedtls_strerror(int ret, char *buf, size_t buflen)
{
    (void) ret;
    if (buflen != 0) buf[0] = 0;
}
