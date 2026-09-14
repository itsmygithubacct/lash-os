#pragma once
#include_next <unistd.h>
int getresuid(uid_t *, uid_t *, uid_t *);
int getresgid(gid_t *, gid_t *, gid_t *);
int setresuid(uid_t, uid_t, uid_t);
int setresgid(gid_t, gid_t, gid_t);

pid_t getpgid(pid_t);
pid_t getpgrp(void);
int setpgid(pid_t, pid_t);
int setpgrp(void);
pid_t setsid(void);
pid_t tcgetpgrp(int);
int tcsetpgrp(int, pid_t);

int posix_openpt(int);
int grantpt(int);
int unlockpt(int);
char *ptsname(int);
int ptsname_r(int, char *, size_t);

#define _SC_NPROCESSORS_CONF 1000
#define _SC_NPROCESSORS_ONLN 1001
int posix_fallocate(int, off_t, off_t);

#define _SC_PHYS_PAGES 1002
