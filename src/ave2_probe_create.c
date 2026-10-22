/*
 * ave2_probe_create.c v10 — descriptor-path discrimination matrix
 *
 * Kernel+trap RE (2026-10-23) established:
 *  - MIG trap family builds IOExternalMethodArguments{version=2}: raw
 *    structureInput lands at +0x30 only for in-band structs (<=4096);
 *    bigger structs ride the OOL descriptor at +0x40.
 *  - Kernel externalMethod precheck compares dispatch-row sizes EXACTLY
 *    (raw size OR descriptor length) -> mismatch = 0xe00002c2.
 *  - sel4 (0x1b9c7d4) has TWO 0xe00002bc exits: (1) both inputs
 *    NULL, (2) descriptor map step +0xe8(desc,0x1000) returned NULL
 *    ("faild to prepare memory"). Device sees bc with untouched out ->
 *    descriptor delivered but map failed. sel5 returns 0xe00002d9
 *    (Busy) from the same +0xd8 prepare slot -> unexplained asymmetry.
 * v10 probes (each vs a fresh session):
 *  [1] sel6 0x30/0x20      raw-delivery control (expect NOT bc)
 *  [2] sel4 0x1a0a0/0x20   baseline (expect bc)
 *  [3] sel4 0x1a09c/0x20   one short of exact (expect c2 if precheck seen)
 *  [4] sel4 0x1004/0x20    just over in-band cap (MIG err vs c2 vs bc)
 *  [5] sel4 0x0ffc/0x20    just under cap (expect c2)
 *  [6] sel5 0x1a0b0/0x150  baseline (expect d9)
 *  [7] sel5 0x1a0a0/0x150  wrong size for sel5 (d9-before-gate vs c2)
 *  [8] sel4 async baseline (expect bc)
 *  [9] SetNotificationPort type sweep 0..4 (arm async machinery)
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

    static const int modes[] = {0,1,2,3,4,5,6,7,8,9,10}; /* v9 sweep */
    int created = 0;
    size_t osz = AVE2_IOS_CREATE_OUT_SIZE;
    kern_return_t k = 0;
    for (size_t mi = 0; mi < sizeof(modes)/sizeof(modes[0]) && !created; mi++) {
        printf("\n=== create mode=%d SYNC exact 0x6f0/0x28 ===\n", modes[mi]);
        build_create_input(in, AVE2_IOS_CREATE_IN_SIZE, ++counter, modes[mi]); /* v9: sweep mode */
        osz = AVE2_IOS_CREATE_OUT_SIZE;
        memset(out, 0, sizeof(out));
        k = p_IOConnectCallStructMethod(conn, 1, in, AVE2_IOS_CREATE_IN_SIZE, out, &osz);
        printf("  -> 0x%08x %s ", k, krname(k)); dump_out(out, osz, 0x28);
        created = (k == 0);
    }
    printf("\n[create sweep %s]\n", created ? "OK — session handle in out+0x00" : "ALL modes FAILED");

    if ((e = getenv("AVE2_CONFIGURE")) != NULL && e[0] == '1') {
        if (!created) {
            printf("\n=== configure experiments skipped (create failed) ===\n");
        } else {
            fp_IOConnectSetNotificationPort p_SetNotif =
                (fp_IOConnectSetNotificationPort)dlsym(iodyn_handle, "IOConnectSetNotificationPort");
            printf("\n[SetNotificationPort dlsym: %s]\n", p_SetNotif ? "ok" : "NULL");

            static uint8_t cin[0x1a0c0];
            static uint8_t sin6[0x30];
#define CFGFILL() do { \
                memset(cin,0,sizeof(cin)); \
                memcpy(cin + 0x00, "905.40.1", 8); \
                memcpy(cin + 0x28, "905.40.1", 8); \
                *(int32_t  *)(cin + AVE2_OFF_WIDTH)      = (int32_t)prof->w; \
                *(int32_t  *)(cin + AVE2_OFF_HEIGHT)     = (int32_t)prof->h; \
                *(int32_t  *)(cin + AVE2_MODE5_OFF_P6)   = 2; \
                *(int32_t  *)(cin + AVE2_MODE5_OFF_P8)   = 10; \
                *(uint8_t  *)(cin + AVE2_MODE5_OFF_P9FLAG) = 0; \
                *(int32_t  *)(cin + AVE2_OFF_NUMVIEWS)   = 1; \
                *(int32_t  *)(cin + AVE2_OFF_NUMLAYERS)  = 1; \
            } while(0)
            kern_return_t k2; size_t osz; iodyn_async_ref_t aref;
            const ave2_profile_t *prof = ave2_profile_get(0);
            printf("\n=== v10 descriptor-path matrix (session live) ===\n");

            /* [1] sel6 raw-delivery control: 0x30/0x20 zeros */
            memset(sin6,0,sizeof(sin6)); osz = 0x20; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallStructMethod(conn, 6, sin6, 0x30, out, &osz);
            printf("  [1 sel6 0x30/0x20]      -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x20);

            /* [2] sel4 baseline 0x1a0a0/0x20 */
            CFGFILL(); osz = 0x20; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallStructMethod(conn, 4, cin, 0x1a0a0, out, &osz);
            printf("  [2 sel4 0x1a0a0/0x20]   -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x20);

            /* [3] sel4 one byte short */
            CFGFILL(); osz = 0x20; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallStructMethod(conn, 4, cin, 0x1a09c, out, &osz);
            printf("  [3 sel4 0x1a09c/0x20]   -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x20);

            /* [4] sel4 just over in-band cap */
            CFGFILL(); osz = 0x20; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallStructMethod(conn, 4, cin, 0x1004, out, &osz);
            printf("  [4 sel4 0x1004/0x20]    -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x20);

            /* [5] sel4 just under cap */
            CFGFILL(); osz = 0x20; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallStructMethod(conn, 4, cin, 0x0ffc, out, &osz);
            printf("  [5 sel4 0x0ffc/0x20]    -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x20);

            /* [6] sel5 baseline 0x1a0b0/0x150 */
            CFGFILL(); osz = 0x150; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallStructMethod(conn, 5, cin, 0x1a0b0, out, &osz);
            printf("  [6 sel5 0x1a0b0/0x150]  -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x150);

            /* [7] sel5 with sel4's exact size (d9-before-gate vs c2) */
            CFGFILL(); osz = 0x150; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallStructMethod(conn, 5, cin, 0x1a0a0, out, &osz);
            printf("  [7 sel5 0x1a0a0/0x150]  -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x150);

            /* [8] sel4 async baseline with real wake port */
            CFGFILL(); memset(aref,0,sizeof(aref)); aref[0]=(uint64_t)wake;
            osz = 0x20; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallAsyncStructMethod(conn, 4, wake, aref, 1, cin, 0x1a0a0, out, &osz);
            printf("  [8 sel4 async 0x1a0a0]  -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x20);

            /* [9] SetNotificationPort type sweep (arm async machinery) */
            if (p_SetNotif) {
                for (uint32_t t = 0; t <= 4; t++) {
                    kern_return_t kn = p_SetNotif(conn, t, wake);
                    printf("  [9 SetNotificationPort type=%u] -> 0x%08x %s\n", t, kn, krname(kn));
                }
            }
#undef CFGFILL
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
