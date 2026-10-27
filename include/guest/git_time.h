#pragma once
#include <time.h>

/* Picolibc's calendar layout has only the nine standard integer fields.
 * Keep its ABI intact and provide GNU timezone fields to Git's source files. */
struct linux_bash_tm {
    int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year;
    int tm_wday, tm_yday, tm_isdst;
    long tm_gmtoff;
    const char *tm_zone;
};
struct linux_bash_tm *linux_bash_gmtime_r(const time_t *, struct linux_bash_tm *);
struct linux_bash_tm *linux_bash_localtime_r(const time_t *, struct linux_bash_tm *);
time_t linux_bash_mktime(struct linux_bash_tm *);
time_t linux_bash_timegm(struct linux_bash_tm *);
size_t linux_bash_strftime(char *, size_t, const char *, const struct linux_bash_tm *);

#ifndef LASHOS_TIME_IMPLEMENTATION
#define tm linux_bash_tm
#define gmtime_r linux_bash_gmtime_r
#define localtime_r linux_bash_localtime_r
#define mktime linux_bash_mktime
#define timegm linux_bash_timegm
#define strftime linux_bash_strftime
#endif
