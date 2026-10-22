/*
 * ave2_probe_create.c — brute-force sel1 create size gates on-device
 *
 * macOS evidence says in>=0x920 / out>=0x28 passes. On iOS 26.0.1 we get
 * trap=0xe00002c2 with an all-zero out buffer — the wrapper rejects before
 * the inner handler writes anything. Sweep in/out size combos to find the
 * shape this build's external-method table expects.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>

#include "iokit_dyn.h"
#include "ave2_wire.h"

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    if (iodyn_init() != 0) { printf("[-] iodyn\n"); return 3; }

    void *m = p_IOServiceMatching("AppleAVE2Driver");
    io_service_t svc = p_IOServiceGetMatchingService(IODYN_MAIN_PORT, m);
    if (!svc) { printf("[-] no service\n"); return 1; }
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = p_IOServiceOpen(svc, mach_task_self(), 1, &conn);
    if (kr != KERN_SUCCESS) { printf("[-] open: 0x%x\n", kr); return 2; }
    printf("[+] opened 0x%x\n", conn);

    static uint8_t in[0x2000];
    memset(in, 0, sizeof(in));
    memcpy(in + AVE2_CREATE_OFF_VERSION, "904.76.7", 8);
    *(int32_t *)(in + AVE2_CREATE_OFF_ENCTYPE) = 1;
    *(int32_t *)(in + 0x910) = 1;
    *(int32_t *)(in + 0x914) = 1;
    *(uint64_t *)(in + 0x808) = 0x7000000000000001ULL;

    uint8_t out[0x400];

    const size_t insizes[]  = {0x920, 0x1000, 0x1a0a0, 0x2000, 0x930};
    const size_t outsizes[] = {0x28, 0x20, 0x30, 0x40, 0x100, 0x1c};

    for (int ii = 0; ii < 5; ii++) {
        for (int oo = 0; oo < 6; oo++) {
            size_t isz = insizes[ii], osz = outsizes[oo];
            memset(out, 0xAA, sizeof(out));
            kern_return_t k = p_IOConnectCallStructMethod(conn, AVE2_SEL_CREATE,
                                                          in, isz, out, &osz);
            uint32_t st = osz >= 0x1c ? *(uint32_t *)(out + 0x18) : 0;
            uint64_t ck = osz >= 8 ? *(uint64_t *)(out + 0) : 0;
            int nonzero = 0;
            for (size_t q = 0; q < osz && q < 0x40; q++) if (out[q] != 0xAA && out[q] != 0) { nonzero = 1; break; }
            printf("in=0x%04zx out=0x%02zx -> trap=0x%08x status=0x%08x cookie=%016llx out-touched=%d\n",
                   isz, osz, k, st, (unsigned long long)ck, nonzero);
        }
    }
    p_IOServiceClose(conn);
    p_IOObjectRelease(svc);
    return 0;
}
