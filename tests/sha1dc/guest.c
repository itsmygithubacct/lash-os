#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_capsule.h"
#include "control.h"
volatile struct sha1dc_state sha1dc_state SEC(".data.test");
static void run_check(void) {
    uint64_t digest = 0;
    int check = sha1dc_check(&digest);
    sha1dc_state.digest = digest;
    sha1dc_state.check = check;
}
SEC("syscall") int sha1dc_start(void) {
    sha1dc_state.result = capsule_call_void(run_check);
    return 0;
}
SEC("syscall") int sha1dc_continue(void) {
    sha1dc_state.result = capsule_continue_void(sha1dc_state.result.continuation);
    return 0;
}
char _license[] SEC("license") = "GPL";
