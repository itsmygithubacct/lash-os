#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_capsule.h"
#include "kernel_control.h"

volatile struct kernel_control control SEC(".data.ctrl");
extern int bash_kernel_main(int, char **, char **);

static void run_bash(void) {
    capsule_exit(bash_kernel_main(control.argc, control.argv, control.envp));
}

SEC("syscall")
int bash_start(void) {
    control.result = capsule_call_void(run_bash);
    return 0;
}

SEC("syscall")
int bash_continue(void) {
    control.result = capsule_continue_void(control.result.continuation);
    return 0;
}

char _license[] SEC("license") = "GPL";
