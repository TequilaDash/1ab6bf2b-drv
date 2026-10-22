/*
 * ave2_probe_create.c v3 — in-size ladder + memory-type sweep for sel1
 *
 * v2 finding: sel 1..10 dispatch (c2), sel 0/11/12 unsupported (c7).
 * c2 with untouched out = size/shape gate failing at the wrapper.
 * Sweep in-size finely and also try IOConnectCallMethod (generic trap)
 * to see if the struct route is even the right transport on iOS 26.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>

#include "iokit_dyn.h"
#include "ave2_wire.h"

typedef kern_return_t (*fp_IOConnectCallMethod)(io_connect_t, uint32_t,
                                                const uint64_t *, uint32_t,
                                                const void *, size_t,
                                                uint64_t *, uint32_t *,
                                                void *, size_t *);

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    if (iodyn_init() != 0) { printf("[-] iodyn\n"); return 3; }

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    fp_IOConnectCallMethod p_CallMethod =
        (fp_IOConnectCallMethod)dlsym(h, "IOConnectCallMethod");

    void *m = p_IOServiceMatching("AppleAVE2Driver");
    io_service_t svc = p_IOServiceGetMatchingService(IODYN_MAIN_PORT, m);
    if (!svc) { printf("[-] no service\n"); return 1; }
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = p_IOServiceOpen(svc, mach_task_self(), 1, &conn);
    if (kr != KERN_SUCCESS) { printf("[-] open: 0x%x\n", kr); return 2; }
    printf("[+] opened 0x%x\n\n", conn);

    static uint8_t in[0x2000];
    memset(in, 0, sizeof(in));
    memcpy(in + AVE2_CREATE_OFF_VERSION, "904.76.7", 8);
    *(int32_t *)(in + AVE2_CREATE_OFF_ENCTYPE) = 1;
    *(int32_t *)(in + 0x910) = 1;
    *(int32_t *)(in + 0x914) = 1;
    *(uint64_t *)(in + 0x808) = 0x7000000000000001ULL;

    uint8_t out[0x400];

    printf("=== sel1 struct in-size ladder ===\n");
    size_t sizes[] = {0x920, 0x921, 0x928, 0x930, 0x940, 0x980, 0xA00, 0xB00,
                      0xC00, 0xE00, 0x1000, 0x1400, 0x1800, 0x1C00, 0x2000};
    for (int i = 0; i < 15; i++) {
        size_t isz = sizes[i], osz = 0x100;
        memset(out, 0, sizeof(out));
        kern_return_t k = p_IOConnectCallStructMethod(conn, 1, in, isz, out, &osz);
        int touched = 0;
        for (size_t q = 0; q < osz; q++) if (out[q]) { touched = 1; break; }
        printf("  in=0x%04zx -> 0x%08x osz=%zu touched=%d\n", isz, k, osz, touched);
        if (touched) {
            printf("    out hex: ");
            for (size_t q = 0; q < osz && q < 0x28; q++) printf("%02x", out[q]);
            printf("\n");
        }
    }

    if (p_CallMethod) {
        printf("\n=== sel1 via generic IOConnectCallMethod (struct payload) ===\n");
        uint64_t sc_out[8] = {0};
        uint32_t sc_cnt = 8;
        size_t osz = 0x100;
        memset(out, 0, sizeof(out));
        kern_return_t k = p_CallMethod(conn, 1, NULL, 0, in, 0x920, sc_out, &sc_cnt, out, &osz);
        printf("  -> 0x%08x scnt=%u osz=%zu out0=%016llx\n", k, sc_cnt, osz,
               (unsigned long long)sc_out[0]);
        printf("  struct-out: ");
        for (size_t q = 0; q < osz && q < 0x28; q++) printf("%02x", out[q]);
        printf("\n");

        printf("\n=== sel1 via generic IOConnectCallMethod (scalar only) ===\n");
        uint64_t sc_in[4] = {0x920, 0x100000, 0, 0};
        sc_cnt = 8; osz = 0x100;
        memset(out, 0, sizeof(out));
        k = p_CallMethod(conn, 1, sc_in, 4, NULL, 0, sc_out, &sc_cnt, out, &osz);
        printf("  -> 0x%08x scnt=%u osz=%zu sc0=%016llx sc1=%016llx\n", k, sc_cnt, osz,
               (unsigned long long)sc_out[0], (unsigned long long)sc_out[1]);
    }

    p_IOServiceClose(conn);
    p_IOObjectRelease(svc);
    return 0;
}
