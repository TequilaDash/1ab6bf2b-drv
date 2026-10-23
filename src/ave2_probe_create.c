/*
 * ave2_probe_create.c v18 — notification-port chain
 *
 * v17 facts: kernel precheck maps row+8 (scalarInCnt=0) <-> args+0x28; any
 * scalars -> c2 for ALL AVE2 selectors. sel3's handler REQUIRES args+0x8 /
 * +0x10 / +0x18 non-NULL (= asyncReference array + count) -> sel3 is an
 * ASYNC-ONLY method (likely "register wake port" writing [UC+0x100]).
 * v17 V11 (SetNotificationPort with task port) killed the probe (device ok).
 *
 * W1 open->create->sel3 async(wake=alloc'd receive port) -> sel6 -> sel4 -> sel5
 * W2 open->create->IOConnectSetNotificationPort(type=0, alloc'd port) -> sel4 -> sel6
 * W3 open->sel3 async (no create) -> create -> sel4
 * W4 open->create->SetNotificationPort types 0..3, proper port, LAST (risky)
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
static uint64_t counter = 0x0000700000000F00ULL;

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

static kern_return_t sel4_call(io_connect_t c) {
    memset(cin, 0, sizeof(cin));
    memcpy(cin + 0x00, "904.76.7", 8);
    memcpy(cin + 0x28, "904.76.7", 8);
    *(int32_t *)(cin + AVE2_OFF_WIDTH)  = 1920;
    *(int32_t *)(cin + AVE2_OFF_HEIGHT) = 1080;
    memset(out, 0xAA, sizeof(out));
    size_t o = 0x20;
    kern_return_t kr = p_IOConnectCallStructMethod(c, 4, cin, 0x1a0a0, out, &o);
    printf("    sel4 -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
    return kr;
}

static kern_return_t sel5_call(io_connect_t c) {
    memset(cin, 0, sizeof(cin));
    memcpy(cin + 0x00, "904.76.7", 8);
    memcpy(cin + 0x28, "904.76.7", 8);
    *(int32_t *)(cin + AVE2_OFF_WIDTH)  = 1920;
    *(int32_t *)(cin + AVE2_OFF_HEIGHT) = 1080;
    memset(out, 0xAA, sizeof(out));
    size_t o = 0x150;
    kern_return_t kr = p_IOConnectCallStructMethod(c, 5, cin, 0x1a0b0, out, &o);
    printf("    sel5 -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
    return kr;
}

static kern_return_t sel6_call(io_connect_t c) {
    uint8_t din[0x40];
    memset(din, 0, sizeof(din));
    memcpy(din, "904.76.7", 8);
    memset(out, 0xAA, sizeof(out));
    size_t o = 0x20;
    kern_return_t kr = p_IOConnectCallStructMethod(c, 6, din, 0x30, out, &o);
    printf("    sel6 -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
    return kr;
}

/* sel3 async: struct 0x38 in + wake port + async refs */
static kern_return_t sel3_async(io_connect_t c, mach_port_t wake) {
    uint8_t din[0x40];
    memset(din, 0, sizeof(din));
    memcpy(din, "904.76.7", 8);
    iodyn_async_ref_t aref; memset(aref, 0, sizeof(aref));
    aref[0] = 0x1;
    memset(out, 0xAA, sizeof(out));
    size_t o = 0x20;
    kern_return_t kr = p_IOConnectCallAsyncStructMethod(c, 3, wake, aref, 8, din, 0x38, out, &o);
    printf("    sel3 async -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
    return kr;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (iodyn_init() != 0) { printf("[-] iodyn\n"); return 3; }
    void *m = p_IOServiceMatching("AppleAVE2Driver");
    io_service_t svc = p_IOServiceGetMatchingService(IODYN_MAIN_PORT, m);
    if (!svc) { printf("[-] no service\n"); return 1; }
    const char *e = getenv("AVE2_LOGCNT");
    if (e != NULL && e[0]) counter = strtoull(e, NULL, 0);
    kern_return_t kr;
    io_connect_t c;
    mach_port_t wake = MACH_PORT_NULL;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wake);
    printf("mach_port_allocate -> 0x%08x wake=0x%x\n", kr, wake);
    if (kr != 0) return 5;

    printf("\n=== W1 create -> sel3 async -> sel6 -> sel4 -> sel5 ===\n");
    if (create_session(svc, &c) == 0) {
        sel3_async(c, wake);
        sel6_call(c);
        sel4_call(c);
        sel5_call(c);
        destroy_close(c);
    }

    printf("\n=== W2 create -> SetNotificationPort(type=0, recv port) -> sel4 -> sel6 ===\n");
    if (create_session(svc, &c) == 0) {
        kr = p_IOConnectSetNotificationPort(c, 0, wake);
        printf("    SetNotificationPort(0) -> 0x%08x %s\n", kr, krname(kr));
        sel4_call(c);
        sel6_call(c);
        destroy_close(c);
    }

    printf("\n=== W3 sel3 async (no create) -> create -> sel4 ===\n");
    {
        c = MACH_PORT_NULL;
        kr = p_IOServiceOpen(svc, mach_task_self(), 1, &c);
        if (kr == 0) {
            sel3_async(c, wake);
            if (create_session(svc, &c) == 0 || 1) {
                /* create_session reopened on same conn handle: it calls
                 * IOServiceOpen again — avoid; just call create input on c */
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
                kern_return_t k1 = p_IOConnectCallStructMethod(c, 1, in, AVE2_IOS_CREATE_IN_SIZE, out, &osz);
                printf("    create(2nd) -> 0x%08x\n", k1);
                if (k1 == 0) { sel4_call(c); }
            }
            destroy_close(c);
        }
    }

    printf("\n=== W4 SetNotificationPort types 0..3 (proper recv port, risky, LAST) ===\n");
    if (create_session(svc, &c) == 0) {
        for (uint32_t t = 0; t < 4; t++) {
            kr = p_IOConnectSetNotificationPort(c, t, wake);
            printf("    SetNotificationPort(type=%u) -> 0x%08x %s\n", t, kr, krname(kr));
            fflush(stdout);
        }
        sel4_call(c);
        destroy_close(c);
    }

    p_IOObjectRelease(svc);
    return 42;
}
