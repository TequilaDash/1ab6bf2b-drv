/*
 * ave2_probe_create.c v17 — scalar-requirement hypothesis
 *
 * v16: sel3 requires args+0x8/+0x10/+0x18 non-NULL (SCALAR INPUTS) —
 * IOConnectCallStructMethod sends none -> sel3 bc out untouched.
 * sel6..sel10 -> d9 out untouched (unexplained). Hypothesis: some selectors
 * require scalars; mixed IOConnectCallMethod(scalars+struct) supplies them.
 *
 * V1  sel2 CallMethod + 3 zero scalars          (control, expect 0)
 * V2  sel6 CallStructMethod                     (control, expect d9)
 * V3  sel6 CallMethod + 3 zero scalars
 * V4  sel3 CallMethod + 3 zero scalars
 * V5  sel3 CallMethod + scalars (1,2,3)
 * V6  sel7..10 CallMethod + 3 zero scalars
 * V7  sel4 CallStructMethod (control, expect bc)
 * V8  sel4 CallMethod + 3 zero scalars (OOL struct)
 * V9  sel4 CallMethod + scalars (1,2,3) (OOL)
 * V10 sel5 CallMethod + 3 zero scalars (OOL)
 * V11 SetNotificationPort types 0..3 (info)
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
static uint64_t counter = 0x0000700000000E00ULL;

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

/* mixed call: nscalars + struct */
static kern_return_t call_mixed(io_connect_t c, uint32_t sel, const uint64_t *sc,
                                uint32_t nsc, size_t isz, size_t osz) {
    uint8_t din[0x40];
    memset(din, 0, sizeof(din));
    memcpy(din, "904.76.7", 8);
    memset(out, 0xAA, sizeof(out));
    uint64_t so[8]; uint32_t soc = 0;
    size_t o = osz;
    kern_return_t kr = p_IOConnectCallMethod(c, sel, sc, nsc, din, isz, so, &soc, out, &o);
    printf("    sel%u sc=%u -> 0x%08x %s soCnt=%u\n", sel, nsc, kr, krname(kr), soc);
    dump_out(out, o, osz < 0x24 ? osz : 0x24);
    return kr;
}

static kern_return_t call_struct(io_connect_t c, uint32_t sel, size_t isz, size_t osz) {
    uint8_t din[0x40];
    memset(din, 0, sizeof(din));
    memcpy(din, "904.76.7", 8);
    memset(out, 0xAA, sizeof(out));
    size_t o = osz;
    kern_return_t kr = p_IOConnectCallStructMethod(c, sel, din, isz, out, &o);
    printf("    sel%u struct -> 0x%08x %s\n", sel, kr, krname(kr));
    dump_out(out, o, osz < 0x24 ? osz : 0x24);
    return kr;
}

static void fill_cfg(void) {
    memset(cin, 0, sizeof(cin));
    memcpy(cin + 0x00, "904.76.7", 8);
    memcpy(cin + 0x28, "904.76.7", 8);
    *(int32_t *)(cin + AVE2_OFF_WIDTH)  = 1920;
    *(int32_t *)(cin + AVE2_OFF_HEIGHT) = 1080;
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

    printf("\n=== V1 sel2 CallMethod + 3 zero scalars (control) ===\n");
    if (create_session(svc, &c) == 0) {
        uint64_t sc[3] = {0, 0, 0};
        call_mixed(c, 2, sc, 3, 0x28, 0x20);
        destroy_close(c);
    }

    printf("\n=== V2 sel6 CallStructMethod (control) ===\n");
    if (create_session(svc, &c) == 0) {
        call_struct(c, 6, 0x30, 0x20);
        destroy_close(c);
    }

    printf("\n=== V3 sel6 CallMethod + 3 zero scalars ===\n");
    if (create_session(svc, &c) == 0) {
        uint64_t sc[3] = {0, 0, 0};
        call_mixed(c, 6, sc, 3, 0x30, 0x20);
        destroy_close(c);
    }

    printf("\n=== V4 sel3 CallMethod + 3 zero scalars ===\n");
    if (create_session(svc, &c) == 0) {
        uint64_t sc[3] = {0, 0, 0};
        call_mixed(c, 3, sc, 3, 0x38, 0x20);
        destroy_close(c);
    }

    printf("\n=== V5 sel3 CallMethod + scalars(1,2,3) ===\n");
    if (create_session(svc, &c) == 0) {
        uint64_t sc[3] = {1, 2, 3};
        call_mixed(c, 3, sc, 3, 0x38, 0x20);
        destroy_close(c);
    }

    printf("\n=== V6 sel7..10 CallMethod + 3 zero scalars ===\n");
    if (create_session(svc, &c) == 0) {
        uint64_t sc[3] = {0, 0, 0};
        call_mixed(c, 7, sc, 3, 0x30, 0x20);
        call_mixed(c, 8, sc, 3, 0x30, 0x20);
        call_mixed(c, 9, sc, 3, 0x30, 0x20);
        call_mixed(c, 10, sc, 3, 0x30, 0x20);
        destroy_close(c);
    }

    printf("\n=== V7 sel4 CallStructMethod (control) ===\n");
    if (create_session(svc, &c) == 0) {
        fill_cfg();
        memset(out, 0xAA, sizeof(out)); size_t o = 0x20;
        kr = p_IOConnectCallStructMethod(c, 4, cin, 0x1a0a0, out, &o);
        printf("    sel4 -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
        destroy_close(c);
    }

    printf("\n=== V8 sel4 CallMethod + 3 zero scalars (OOL) ===\n");
    if (create_session(svc, &c) == 0) {
        fill_cfg();
        uint64_t sc[3] = {0, 0, 0};
        memset(out, 0xAA, sizeof(out)); size_t o = 0x20;
        kr = p_IOConnectCallMethod(c, 4, sc, 3, cin, 0x1a0a0, NULL, NULL, out, &o);
        printf("    sel4 -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
        destroy_close(c);
    }

    printf("\n=== V9 sel4 CallMethod + scalars(1,2,3) (OOL) ===\n");
    if (create_session(svc, &c) == 0) {
        fill_cfg();
        uint64_t sc[3] = {1, 2, 3};
        memset(out, 0xAA, sizeof(out)); size_t o = 0x20;
        kr = p_IOConnectCallMethod(c, 4, sc, 3, cin, 0x1a0a0, NULL, NULL, out, &o);
        printf("    sel4 -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
        destroy_close(c);
    }

    printf("\n=== V10 sel5 CallMethod + 3 zero scalars (OOL 0x1a0b0) ===\n");
    if (create_session(svc, &c) == 0) {
        fill_cfg();
        uint64_t sc[3] = {0, 0, 0};
        memset(out, 0xAA, sizeof(out)); size_t o = 0x150;
        kr = p_IOConnectCallMethod(c, 5, sc, 3, cin, 0x1a0b0, NULL, NULL, out, &o);
        printf("    sel5 -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
        destroy_close(c);
    }

    printf("\n=== V11 SetNotificationPort types 0..3 ===\n");
    if (create_session(svc, &c) == 0) {
        mach_port_t wake = mach_task_self();
        for (uint32_t t = 0; t < 4; t++) {
            kr = p_IOConnectSetNotificationPort(c, t, wake);
            printf("    SetNotificationPort(type=%u) -> 0x%08x %s\n", t, kr, krname(kr));
        }
        destroy_close(c);
    }

    p_IOObjectRelease(svc);
    return 42;
}
