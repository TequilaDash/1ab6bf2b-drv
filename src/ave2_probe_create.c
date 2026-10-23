/*
 * ave2_probe_create.c v20 - wake-port drain + sel7..10 probes
 *
 * v19: async sel4/5/6 == sync results (bc / 0xe0000001). sel3 async
 * succeeds and mutates UC state (sel5/6: d9 -> 0xe0000001). Working
 * theory now: sel3 async registers the wake port and the AVE session
 * answers arrive AS MESSAGES on the wake port. Drain it.
 *
 * X1 create -> sel3 async -> drain -> sel4 sync -> sel4 async -> drain
 * X2 create -> sel3 async -> sel6 sync -> drain
 * X3 create -> sel7/8/9/10 sync struct 0x30 (never tried)
 * X4 no create: sel6 sync -> sel3 async -> sel6 sync
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>
#include "iokit_dyn.h"
#include "ave2_wire.h"

#define MACH_RCV_MSG_V 0x00000002u
#define MACH_RCV_TIMEOUT_V 0x00000100u

static const char *krname(kern_return_t k) {
    switch (k) {
    case 0:           return "KERN_SUCCESS";
    case 0xe00002c2u: return "c2";
    case 0xe00002c7u: return "c7";
    case 0xe00002bcu: return "0xbc";
    case 0xe00002d8u: return "0xd8";
    case 0xe00002d9u: return "0xd9";
    case 0xe0000001u: return "0xe0000001";
    default:          return "";
    }
}

static void dump_out(const uint8_t *out, size_t osz, size_t n) {
    size_t m = osz < n ? osz : n;
    int allz = 1;
    for (size_t q = 0; q < osz; q++) if (out[q]) { allz = 0; break; }
    printf("    osz=%zu allzero=%d out:", osz, allz);
    for (size_t q = 0; q < m; q++) printf("%02x", out[q]);
    printf("\n");
}

static mach_port_t wake;

static void drain(const char *tag) {
    for (int i = 0; i < 3; i++) {
        uint8_t buf[0x1100];
        memset(buf, 0, sizeof(buf));
        mach_msg_header_t *h = (mach_msg_header_t *)buf;
        kern_return_t kr = mach_msg(h, MACH_RCV_MSG_V | MACH_RCV_TIMEOUT_V, 0,
                                    sizeof(buf), wake, 1500, MACH_PORT_NULL);
        if (kr != 0) { printf("  [%s drain %d] 0x%08x\n", tag, i, kr); return; }
        printf("  [%s drain %d] MSG id=0x%x size=%u bits=0x%x:",
               tag, i, h->msgh_id, h->msgh_size, h->msgh_bits);
        size_t n = h->msgh_size < 0x48 ? h->msgh_size : 0x48;
        for (size_t q = 0; q < n; q++) printf("%02x", buf[q]);
        printf("\n");
    }
}

static uint8_t  cin[0x1a0c0];
static uint8_t  in[0x6f0];
static uint8_t  out[0x400];
static uint64_t counter = 0x0000700000002000ULL;

static io_service_t svc;

static kern_return_t create_session(io_service_t s, io_connect_t *conn) {
    *conn = MACH_PORT_NULL;
    kern_return_t kr = p_IOServiceOpen(s, mach_task_self(), 1, conn);
    if (kr != 0) { printf("    open fail 0x%08x\n", kr); return kr; }
    memset(in, 0, AVE2_IOS_CREATE_IN_SIZE);
    *(uint64_t *)(in + 0x08) = 0x4142434445464748ULL;
    *(uint64_t *)(in + 0x10) = 0x3132333435363738ULL;
    memcpy(in + AVE2_IOS_CREATE_OFF_VERSION, "904.76.7", 8);
    *(uint64_t *)(in + AVE2_IOS_CREATE_OFF_LOGCNT) = ++counter;
    *(int32_t *)(in + AVE2_IOS_CREATE_OFF_LOGLVL) = 1;
    *(int32_t *)(in + AVE2_IOS_CREATE_OFF_LOGNUM) = 1;
    *(int32_t *)(in + AVE2_IOS_CREATE_OFF_MODE)   = 1;
    size_t osz = AVE2_IOS_CREATE_OUT_SIZE;
    memset(out, 0, sizeof(out));
    kern_return_t k1 = p_IOConnectCallStructMethod(*conn, 1, in, AVE2_IOS_CREATE_IN_SIZE, out, &osz);
    printf("    create -> 0x%08x\n", k1);
    return k1;
}

static void destroy_close(io_connect_t c) {
    uint8_t din[0x28] = {0}; size_t o = 0x20; memset(out, 0, sizeof(out));
    kern_return_t kr = p_IOConnectCallStructMethod(c, 2, din, 0x28, out, &o);
    printf("    destroy -> 0x%08x\n", kr);
    p_IOServiceClose(c);
}

static kern_return_t sel3_async(io_connect_t c) {
    uint8_t din[0x40];
    memset(din, 0, sizeof(din));
    memcpy(din, "904.76.7", 8);
    iodyn_async_ref_t aref; memset(aref, 0, sizeof(aref));
    aref[0] = 0x1;
    memset(out, 0xAA, sizeof(out));
    size_t o = 0x20;
    kern_return_t kr = p_IOConnectCallAsyncStructMethod(c, 3, wake, aref, 8, din, 0x38, out, &o);
    printf("    sel3 async -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x20);
    return kr;
}

static void fill_cfg(int w, int h, int p6) {
    memset(cin, 0, sizeof(cin));
    memcpy(cin + 0x00, "904.76.7", 8);
    memcpy(cin + 0x28, "904.76.7", 8);
    *(int32_t *)(cin + AVE2_OFF_WIDTH)     = w;
    *(int32_t *)(cin + AVE2_OFF_HEIGHT)    = h;
    *(int32_t *)(cin + AVE2_MODE5_OFF_P6)  = p6;
    *(int32_t *)(cin + AVE2_MODE5_OFF_P8)  = 10;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (iodyn_init() != 0) { printf("[-] iodyn\n"); return 3; }
    void *m = p_IOServiceMatching("AppleAVE2Driver");
    svc = p_IOServiceGetMatchingService(IODYN_MAIN_PORT, m);
    if (!svc) { printf("[-] no service\n"); return 1; }
    const char *e = getenv("AVE2_LOGCNT");
    if (e != NULL && e[0]) counter = strtoull(e, NULL, 0);
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wake);
    if (kr != 0) { printf("[-] port alloc\n"); return 5; }
    io_connect_t c;

    printf("\n=== X1 create -> sel3 async -> drain -> sel4 sync -> sel4 async -> drain ===\n");
    if (create_session(svc, &c) == 0) {
        sel3_async(c);
        drain("post-sel3");
        fill_cfg(1920, 1080, 2);
        memset(out, 0xAA, sizeof(out));
        size_t o = 0x20;
        kr = p_IOConnectCallStructMethod(c, 4, cin, 0x1a0a0, out, &o);
        printf("    sel4 sync -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x20);
        iodyn_async_ref_t aref; memset(aref, 0, sizeof(aref)); aref[0] = 0x2;
        memset(out, 0xAA, sizeof(out)); o = 0x20;
        kr = p_IOConnectCallAsyncStructMethod(c, 4, wake, aref, 8, cin, 0x1a0a0, out, &o);
        printf("    sel4 async -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x20);
        drain("post-sel4");
        destroy_close(c);
    }

    printf("\n=== X2 create -> sel3 async -> sel6 sync -> drain ===\n");
    if (create_session(svc, &c) == 0) {
        sel3_async(c);
        uint8_t din[0x40]; memset(din, 0, sizeof(din)); memcpy(din, "904.76.7", 8);
        memset(out, 0xAA, sizeof(out));
        size_t o = 0x20;
        kr = p_IOConnectCallStructMethod(c, 6, din, 0x30, out, &o);
        printf("    sel6 sync -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x20);
        drain("post-sel6");
        destroy_close(c);
    }

    printf("\n=== X3 create -> sel7..10 sync struct 0x30 ===\n");
    if (create_session(svc, &c) == 0) {
        uint8_t din[0x40]; memset(din, 0, sizeof(din)); memcpy(din, "904.76.7", 8);
        for (uint32_t s = 7; s <= 10; s++) {
            memset(out, 0xAA, sizeof(out));
            size_t o = 0x20;
            kr = p_IOConnectCallStructMethod(c, s, din, 0x30, out, &o);
            printf("    sel%u sync -> 0x%08x %s\n", s, kr, krname(kr)); dump_out(out, o, 0x20);
        }
        destroy_close(c);
    }

    printf("\n=== X4 no create: sel6 sync -> sel3 async -> sel6 sync ===\n");
    if (p_IOServiceOpen(svc, mach_task_self(), 1, &c) == 0) {
        uint8_t din[0x40]; memset(din, 0, sizeof(din)); memcpy(din, "904.76.7", 8);
        memset(out, 0xAA, sizeof(out));
        size_t o = 0x20;
        kr = p_IOConnectCallStructMethod(c, 6, din, 0x30, out, &o);
        printf("    sel6 sync (no create) -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x20);
        sel3_async(c);
        memset(out, 0xAA, sizeof(out)); o = 0x20;
        kr = p_IOConnectCallStructMethod(c, 6, din, 0x30, out, &o);
        printf("    sel6 sync (post sel3) -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x20);
        p_IOServiceClose(c);
    }

    p_IOObjectRelease(svc);
    return 42;
}
