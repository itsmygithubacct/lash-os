#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_capsule.h"
#include "control.h"
volatile struct mlkem_state mlkem_state SEC(".data.test");
static void run_check(void) {
    uint64_t digest = 0;
    int check = mlkem_check(&digest);
    mlkem_state.digest = digest;
    mlkem_state.check = check;
}
SEC("syscall") int mlkem_start(void) {
    mlkem_state.result = capsule_call_void(run_check); return 0;
}
SEC("syscall") int mlkem_continue(void) {
    mlkem_state.result = capsule_continue_void(mlkem_state.result.continuation); return 0;
}
char _license[] SEC("license") = "GPL";
