#pragma once
#include <string.h>
int linux_bash_xsi_strerror_r(int, char *, size_t);
#define strerror_r linux_bash_xsi_strerror_r
