#ifndef LASH_SANDBOX_HOST_H
#define LASH_SANDBOX_HOST_H
struct sandbox_options {
    int mode; /* 0: OS identity, 1: VM, -1: host */
    unsigned memory_mib, cpus;
    int network, stats;
};
int sandbox_installed_os(void);
int sandbox_run(int argc, char **argv, const struct sandbox_options *options);
int sandbox_number(const char *text, unsigned minimum, unsigned maximum, unsigned *value);
#endif
