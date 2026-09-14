#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include "bpf_capsule_host.h"
#include "control.h"
#include "mlkem.skel.h"
int main(void) {
    struct mlkem *s = mlkem__open();
    struct bpf_capsule capsule = {0}; int rc = 1;
    if (!s) return rc;
    if (bpf_capsule_configure(&capsule,s->obj,(struct bpf_capsule_config){.fiber_count=1,.heap_bytes=16ULL<<20}) ||
        bpf_object__load_skeleton(s->skeleton) ||
        bpf_capsule_attach_freplace(&capsule,s->skeleton->data,s->skeleton->data_sz) ||
        bpf_capsule_initialize(&capsule)) goto done;
    volatile struct mlkem_state *state = &s->data_test->mlkem_state;
    int fd = bpf_program__fd(s->progs.mlkem_start);
    for (unsigned i=0;i<100000;i++) {
        struct bpf_test_run_opts opt = {.sz=sizeof(opt)};
        if (bpf_prog_test_run_opts(fd,&opt)) { perror("run"); goto done; }
        if (state->result.status==CAPSULE_OK) {
            rc=state->check;
            printf("MLKEM check=%d fingerprint=%016llx\n",rc,(unsigned long long)state->digest);
            goto done;
        }
        if (state->result.status!=CAPSULE_PENDING) {
            fprintf(stderr,"Capsule status=%d code=%lld\n",state->result.status,(long long)state->result.code);
            goto done;
        }
        fd=bpf_program__fd(s->progs.mlkem_continue);
    }
    fprintf(stderr,"MLKEM test exceeded continuation limit\n");
done:
    bpf_capsule_release(&capsule); mlkem__destroy(s); return rc;
}
