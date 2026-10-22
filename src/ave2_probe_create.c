/*
 * ave2_probe_create.c v2 — selector sweep to map the iOS 26 external-method
 * table: which selectors exist (Unsupported = hole) vs dispatch (other codes).
 *
 * v1 finding: ALL in/out size combos return trap=0xe00002c2 with untouched out
 * buffer => rejection happens before the handler. Possibilities:
 *   a) sel1 not valid on iOS build (different selector numbering)
 *   b) scalar args required (IOConnectCallMethod vs StructMethod routing)
 *   c) async-only dispatch
 * This sweep distinguishes (a) from (b/c) by error-code fingerprint.
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
    printf("[+] opened 0x%x\n\n", conn);

    static uint8_t in[0x1a0a0];
    memset(in, 0, sizeof(in));
    memcpy(in + AVE2_CREATE_OFF_VERSION, "904.76.7", 8);
    *(int32_t *)(in + AVE2_CREATE_OFF_ENCTYPE) = 1;
    *(int32_t *)(in + 0x910) = 1;
    *(int32_t *)(in + 0x914) = 1;
    *(uint64_t *)(in + 0x808) = 0x7000000000000001ULL;

    uint8_t out[0x400];

    printf("=== struct-method selector sweep (in=0x920) ===\n");
    for (uint32_t sel = 0; sel <= 12; sel++) {
        size_t osz = 0x100;
        memset(out, 0, sizeof(out));
        kern_return_t k = p_IOConnectCallStructMethod(conn, sel, in, 0x920, out, &osz);
        printf("  sel=%2u struct  -> 0x%08x outsz=%3zu out0=%016llx\n",
               sel, k, osz,
               (unsigned long long)(osz >= 8 ? *(uint64_t *)out : 0));
    }

    printf("\n=== scalar-method selector sweep (0 scalars in, 8 out) ===\n");
    for (uint32_t sel = 0; sel <= 12; sel++) {
        uint64_t sc_out[8] = {0};
        uint32_t sc_cnt = 8;
        kern_return_t k = p_IOConnectCallScalarMethod(conn, sel, NULL, 0, sc_out, &sc_cnt);
        printf("  sel=%2u scalar  -> 0x%08x cnt=%u out0=%016llx\n",
               sel, k, sc_cnt, (unsigned long long)sc_out[0]);
    }

    /* also try scalar-method with one scalar arg (some wrappers route by arg cnt) */
    printf("\n=== scalar-method with 1 input scalar ===\n");
    for (uint32_t sel = 0; sel <= 12; sel++) {
        uint64_t sc_in[1] = {0};
        uint64_t sc_out[8] = {0};
        uint32_t sc_cnt = 8;
        kern_return_t k = p_IOConnectCallScalarMethod(conn, sel, sc_in, 1, sc_out, &sc_cnt);
        printf("  sel=%2u scalar1 -> 0x%08x cnt=%u\n", sel, k, sc_cnt);
    }

    p_IOServiceClose(conn);
    p_IOObjectRelease(svc);
    return 0;
}
