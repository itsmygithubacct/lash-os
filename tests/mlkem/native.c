#include <stdint.h>
#include <stdio.h>
int mlkem_check(uint64_t *digest);
int main(void) {
    uint64_t digest = 0; int rc = mlkem_check(&digest);
    printf("MLKEM check=%d fingerprint=%016llx\n", rc, (unsigned long long)digest);
    return rc;
}
