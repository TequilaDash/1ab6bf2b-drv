/*
 * ave2_probe_create.c v11 — descriptor-map wall discrimination
 *
 * v10 facts (device):
 *  - dispatcher precheck sees OOL descriptor length EXACTLY (ladder c2) -> row match at 0x1a0a0
 *  - sel4 exact -> 0xbc, out untouched (kext map step NULL / "faild to prepare memory")
 *  - sel5 exact -> 0xe00002d9 = translate(AVE -1011) (session-state reject, raw path)
 *  - sel6 raw   -> 0xe00002d9 (control; reaches AVE session)
 * Theory under test (v11): IOMemoryDescriptor::map wire-gate denies the probe
 *  task (no wired memory allowance) -> mlock a big buffer first; plus ordering
 *  and repeatability checks (state pollution vs clean first-call).
 * v11 probes (fresh session each, LOGCNT monotonic):
 *  [A] sel4 exact FIRST call (no mlock)          baseline reorder test
 *  [B] mlock 256MB, touch, then sel4 exact       wire-allowance theory
 *  [C] sel4 exact twice in a row                 repeatability
 *  [D] sel5 exact after mlock                    d9 -> ?
 *  [E] sel6 raw after mlock (control)            d9 expected
 *  [F] sel4 async + real wake port after mlock
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <errno.h>

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
            printf("\n=== v11 descriptor-map wall matrix (session live) ===\n");

            /* [A] sel4 exact as FIRST call after create */
            CFGFILL(); osz = 0x20; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallStructMethod(conn, 4, cin, 0x1a0a0, out, &osz);
            printf("  [A sel4 first 0x1a0a0/0x20] -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x20);

            /* [B] mlock 256MB then sel4 exact */
            {
                const size_t WIRE = 256ull<<20;
                void *wb = malloc(WIRE);
                int locked = -1;
                if (wb) {
                    memset(wb, 0xAB, WIRE); /* fault in */
                    locked = mlock(wb, WIRE);
                    printf("  [B] mlock 256MB -> %d (errno=%d)\n", locked, locked?errno:0);
                }
                CFGFILL(); osz = 0x20; memset(out,0,sizeof(out));
                k2 = p_IOConnectCallStructMethod(conn, 4, cin, 0x1a0a0, out, &osz);
                printf("  [B sel4 after mlock]        -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x20);
                if (wb && locked==0) munlock(wb, WIRE);
                free(wb);
            }

            /* [C] sel4 exact twice in a row */
            CFGFILL(); osz = 0x20; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallStructMethod(conn, 4, cin, 0x1a0a0, out, &osz);
            printf("  [C1 sel4 repeat]            -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x20);
            CFGFILL(); osz = 0x20; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallStructMethod(conn, 4, cin, 0x1a0a0, out, &osz);
            printf("  [C2 sel4 repeat2]           -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x20);

            /* [D] sel5 exact after mlock experiment */
            CFGFILL(); osz = 0x150; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallStructMethod(conn, 5, cin, 0x1a0b0, out, &osz);
            printf("  [D sel5 0x1a0b0/0x150]      -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x150);

            /* [E] sel6 raw control */
            memset(sin6,0,sizeof(sin6)); osz = 0x20; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallStructMethod(conn, 6, sin6, 0x30, out, &osz);
            printf("  [E sel6 0x30/0x20]          -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x20);

            /* [F] sel4 async with real wake port */
            CFGFILL(); memset(aref,0,sizeof(aref)); aref[0]=(uint64_t)wake;
            osz = 0x20; memset(out,0,sizeof(out));
            k2 = p_IOConnectCallAsyncStructMethod(conn, 4, wake, aref, 1, cin, 0x1a0a0, out, &osz);
            printf("  [F sel4 async 0x1a0a0]      -> 0x%08x %s ", k2, krname(k2)); dump_out(out, osz, 0x20);

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
