#include <stdint.h>
#include <stdio.h>
int sha1dc_check(uint64_t *digest);
int main(void) {
    uint64_t digest = 0;
    int rc = sha1dc_check(&digest);
    printf("SHA1DC check=%d fingerprint=%016llx\n", rc, (unsigned long long)digest);
    return rc;
}
