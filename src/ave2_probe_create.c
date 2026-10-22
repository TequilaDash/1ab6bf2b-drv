/*
 * ave2_probe_create.c v5 — iOS 26.0.1 exact-size create probe
 *
 * v4 finding: every sel1..10 probe returned c2 (0xe00002c2) with untouched out,
 * regardless of in-size (0x920..0x2000) or transport. kernelcache RE of
 * 26.0.1 (2026-10-22) solved it: the iOS dispatch-table row for sel1 create is
 * in=0x6f0 out=0x28 and the kernel dispatcher enforces BOTH sizes with
 * EQUALITY before the handler ever runs (the handler's own mismatch path would
 * return 0xe00002bc — never observed). macOS sizes never matched → wall of c2.
 *
 * v5 sends the exact 0x6f0 layout decoded from AVE_UCCmd_CheckParam_Open
 * (0x1b98274) + Open continuation (0x1b9b504); offsets in ave2_wire.h
 * AVE2_IOS_CREATE_*. Optional follow-up configure (sel4) behind env
 * AVE2_CONFIGURE=1, only meaningful after create succeeds.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>

#include "iokit_dyn.h"
#include "ave2_wire.h"
#include "ave2_profiles.h"

static const char *krname(kern_return_t k) {
    switch (k) {
    case 0:              return "KERN_SUCCESS";
    case 0xe00002c2u:    return "c2 BadArgument (dispatcher size/type gate)";
    case 0xe00002c7u:    return "c7 Unsupported (selector range)";
    case 0xe00002bcu:    return "0xbc (handler-side mismatch / async gate)";
    case 0xfffffc09u:    return "0xfffffc09 version mismatch";
    case 0xfffffc17u:    return "0xfffffc17 param/validation family";
    case 0xfffffc0du:    return "0xfffffc0d wrong state (no session)";
    default:             return "";
    }
}

static void dump_out(const uint8_t *out, size_t osz, size_t n) {
    size_t m = osz < n ? osz : n;
    int touched = 0;
    for (size_t q = 0; q < osz; q++) if (out[q]) { touched = 1; break; }
    printf("  osz=%zu touched=%d", osz, touched);
    if (touched) {
        printf(" out:");
        for (size_t q = 0; q < m; q++) printf("%02x", out[q]);
    }
    printf("\n");
}

static void build_create_input(uint8_t *in, size_t cap, uint64_t counter, int32_t mode) {
    memset(in, 0, cap);
    /* echo canaries — the handler copies in+0x08/0x10 back to out+0x08/0x10 */
    *(uint64_t *)(in + 0x08) = 0x4142434445464748ULL;
    *(uint64_t *)(in + 0x10) = 0x3132333435363738ULL;
    memcpy(in + AVE2_IOS_CREATE_OFF_VERSION, "904.76.7", 8); /* + 7 zero bytes = full 0xf compare */
    /* DPM @0x8c: three u64 slots stay ZERO (bit-gated checks, zeros pass)   */
    /* DLB @0xac: count 0, [+0xb0] 0  -> short-circuit OK                    */
    *(uint64_t *)(in + AVE2_IOS_CREATE_OFF_LOGCNT) = counter; /* must exceed kernel static, monotonic */
    /* log blob @0x5e0..0x6e0 stays zero */
    *(int32_t *)(in + AVE2_IOS_CREATE_OFF_LOGLVL) = 1;
    *(int32_t *)(in + AVE2_IOS_CREATE_OFF_LOGNUM) = 1;
    *(int32_t *)(in + AVE2_IOS_CREATE_OFF_MODE)   = mode;
}

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
    static uint8_t out[0x400];
    uint64_t counter = 0x0000700000000001ULL;
    /* each successful create STORES the counter into a kernel static
     * (0x1b2c6c8) until reboot; a rerun in the same boot must exceed it.
     * Override with AVE2_LOGCNT (hex or dec). */
    const char *e = getenv("AVE2_LOGCNT");
    if (e != NULL && e[0]) counter = strtoull(e, NULL, 0);

    printf("=== sel1 create SYNC exact 0x6f0/0x28 (iOS layout) ===\n");
    build_create_input(in, AVE2_IOS_CREATE_IN_SIZE, counter, 1);
    size_t osz = AVE2_IOS_CREATE_OUT_SIZE;
    memset(out, 0, sizeof(out));
    kern_return_t k = p_IOConnectCallStructMethod(conn, 1, in, AVE2_IOS_CREATE_IN_SIZE, out, &osz);
    printf("  -> 0x%08x %s ", k, krname(k)); dump_out(out, osz, 0x28);

    if (k == 0xe00002c2u) {
        printf("\n=== retry: out-size 0x100 (dispatcher >= out) ===\n");
        osz = 0x100;
        memset(out, 0, sizeof(out));
        k = p_IOConnectCallStructMethod(conn, 1, in, AVE2_IOS_CREATE_IN_SIZE, out, &osz);
        printf("  -> 0x%08x %s ", k, krname(k)); dump_out(out, osz, 0x28);
    }

    if (k != 0) {
        printf("\n=== retry: mode=2 ===\n");
        build_create_input(in, AVE2_IOS_CREATE_IN_SIZE, ++counter, 2);
        osz = AVE2_IOS_CREATE_OUT_SIZE;
        memset(out, 0, sizeof(out));
        k = p_IOConnectCallStructMethod(conn, 1, in, AVE2_IOS_CREATE_IN_SIZE, out, &osz);
        printf("  -> 0x%08x %s ", k, krname(k)); dump_out(out, osz, 0x28);
    }

    if (k != 0) {
        printf("\n=== retry: ASYNC struct exact 0x6f0 ===\n");
        build_create_input(in, AVE2_IOS_CREATE_IN_SIZE, ++counter, 1);
        iodyn_async_ref_t aref; memset(aref, 0, sizeof(aref));
        aref[0] = (uint64_t)wake;
        osz = AVE2_IOS_CREATE_OUT_SIZE;
        memset(out, 0, sizeof(out));
        k = p_IOConnectCallAsyncStructMethod(conn, 1, wake, aref, 1,
                                             in, AVE2_IOS_CREATE_IN_SIZE, out, &osz);
        printf("  -> 0x%08x %s ", k, krname(k)); dump_out(out, osz, 0x28);
    }

    int created = (k == 0);
    printf("\n[create %s]\n", created ? "OK — session handle in out+0x00" : "FAILED");

    if ((e = getenv("AVE2_CONFIGURE")) != NULL && e[0] == '1') {
        if (!created) {
            printf("\n=== sel4 configure skipped (create failed) ===\n");
        } else {
            printf("\n=== sel4 configure ASYNC exact 0x1a0a0/0x20 (LRB geometry) ===\n");
            const ave2_profile_t *prof = ave2_profile_get(0);
            static uint8_t cin[0x1a0a0];
            memset(cin, 0, sizeof(cin));
            *(int64_t  *)(cin + 0x10) = 0;                       /* dataCnt >= 0 */
            *(int64_t  *)(cin + 0x18) = 0;                       /* mode0   >= 0 */
            *(int64_t  *)(cin + 0x20) = 0;                       /* mode1   >= 0 */
            *(int32_t  *)(cin + AVE2_OFF_WIDTH)      = (int32_t)prof->w;
            *(int32_t  *)(cin + AVE2_OFF_HEIGHT)     = (int32_t)prof->h;
            *(int32_t  *)(cin + AVE2_MODE5_OFF_P6)   = 2;        /* chroma 4:2:0 */
            *(int32_t  *)(cin + AVE2_MODE5_OFF_P8)   = 10;       /* 10-bit       */
            *(uint8_t  *)(cin + AVE2_MODE5_OFF_P9FLAG) = 0;      /* bit0 == 0    */
            *(int32_t  *)(cin + AVE2_OFF_NUMVIEWS)   = 1;
            *(int32_t  *)(cin + AVE2_OFF_NUMLAYERS)  = 1;
            iodyn_async_ref_t aref; memset(aref, 0, sizeof(aref));
            aref[0] = (uint64_t)wake;
            osz = 0x20;
            memset(out, 0, sizeof(out));
            kern_return_t k2 = p_IOConnectCallAsyncStructMethod(conn, 4, wake, aref, 1,
                                                                cin, 0x1a0a0, out, &osz);
            printf("  async -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x20);
            printf("  [if this returned 0/0xfffffc0d without panic, check dmesg/syslog next]\n");
        }
    }

    printf("\n=== sel2 destroy SYNC exact 0x28/0x20 (control) ===\n");
    {
        uint8_t din[0x28] = {0};
        osz = 0x20;
        memset(out, 0, sizeof(out));
        kern_return_t k3 = p_IOConnectCallStructMethod(conn, 2, din, 0x28, out, &osz);
        printf("  -> 0x%08x %s ", k3, krname(k3)); dump_out(out, osz, 0x20);
    }

    mach_port_destroy(mach_task_self(), wake);
    p_IOServiceClose(conn);
    p_IOObjectRelease(svc);
    return created ? 42 : 5;
}
