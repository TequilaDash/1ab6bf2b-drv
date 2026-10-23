/*
 * ave2_probe_create.c v16 — in-band selector recon (no OOL)
 *
 * v15 proved sel4 bc is parameter-independent. All sel4/sel5 calls are OOL
 * (in > 0x1000 -> kernel trap builds a memory descriptor). The OOL object
 * path (prepare -> map) is opaque from the outside. sel6..sel10 take in=0x30
 * (in-band, raw structureInput) so they run the RAW path: gate -> checker ->
 * session call -> translate -> out WRITTEN (out+0x18 = raw AVE status).
 * Reading those raw AVE codes maps the session machine state directly.
 *
 * E1 sel6  with session      E2 sel5 sync with session (OOL, expect d9?)
 * E3 sel4 sync with session  (OOL, expect bc)
 * E4 sel6  NO session        (expect d9 + out+0x18 written = -1011 raw)
 * E5..E8 sel7/8/9/10 with session
 * E9  sel3 with session (0x38, in-band)
 * E10 destroy then sel6 (dead session)
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
    case 0xe00002beu:    return "0xbe";
    case 0xe00002bfu:    return "0xbf";
    case 0xe00002c0u:    return "0xc0";
    case 0xe00002cau:    return "0xca";
    case 0xe00002dbu:    return "0xdb";
    case 0xe00002e7u:    return "0xe7";
    case 0xe00002e8u:    return "0xe8";
    case 0xe00002e9u:    return "0xe9";
    case 0xe00002edu:    return "0xed";
    case 0xe00002f0u:    return "0xf0";
    case 0xe00002d5u:    return "0xd5";
    case 0xe00002d6u:    return "0xd6";
    case 0xe0000001u:    return "0x01";
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
static uint64_t counter = 0x0000700000000D00ULL;

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

static kern_return_t call_inband(io_connect_t c, uint32_t sel, size_t isz, size_t osz) {
    uint8_t din[0x40];
    memset(din, 0, sizeof(din));
    memcpy(din, "904.76.7", 8);
    memset(out, 0xAA, sizeof(out));
    size_t o = osz;
    kern_return_t kr = p_IOConnectCallStructMethod(c, sel, din, isz, out, &o);
    printf("    sel%u -> 0x%08x %s\n", sel, kr, krname(kr));
    dump_out(out, o, osz < 0x24 ? osz : 0x24);
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

    printf("\n=== E1 sel6 with session ===\n");
    { io_connect_t c; if (create_session(svc, &c) == 0) {
        call_inband(c, 6, 0x30, 0x20);
        uint8_t din[0x28] = {0}; size_t o = 0x20; memset(out, 0, sizeof(out));
        kr = p_IOConnectCallStructMethod(c, 2, din, 0x28, out, &o);
        printf("    destroy -> 0x%08x\n", kr);
        p_IOServiceClose(c); } }

    printf("\n=== E2 sel5 sync with session (OOL 0x1a0b0/0x150) ===\n");
    { io_connect_t c; if (create_session(svc, &c) == 0) {
        memset(cin, 0, sizeof(cin));
        memcpy(cin + 0x00, "904.76.7", 8); memcpy(cin + 0x28, "904.76.7", 8);
        *(int32_t *)(cin + AVE2_OFF_WIDTH) = 1920; *(int32_t *)(cin + AVE2_OFF_HEIGHT) = 1080;
        memset(out, 0xAA, sizeof(out)); size_t o = 0x150;
        kr = p_IOConnectCallStructMethod(c, 5, cin, 0x1a0b0, out, &o);
        printf("    sel5 -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
        uint8_t din[0x28] = {0}; o = 0x20; memset(out, 0, sizeof(out));
        kr = p_IOConnectCallStructMethod(c, 2, din, 0x28, out, &o);
        printf("    destroy -> 0x%08x\n", kr);
        p_IOServiceClose(c); } }

    printf("\n=== E3 sel4 sync with session (OOL 0x1a0a0/0x20) ===\n");
    { io_connect_t c; if (create_session(svc, &c) == 0) {
        memset(cin, 0, sizeof(cin));
        memcpy(cin + 0x00, "904.76.7", 8); memcpy(cin + 0x28, "904.76.7", 8);
        *(int32_t *)(cin + AVE2_OFF_WIDTH) = 1920; *(int32_t *)(cin + AVE2_OFF_HEIGHT) = 1080;
        memset(out, 0xAA, sizeof(out)); size_t o = 0x20;
        kr = p_IOConnectCallStructMethod(c, 4, cin, 0x1a0a0, out, &o);
        printf("    sel4 -> 0x%08x %s\n", kr, krname(kr)); dump_out(out, o, 0x24);
        uint8_t din[0x28] = {0}; o = 0x20; memset(out, 0, sizeof(out));
        kr = p_IOConnectCallStructMethod(c, 2, din, 0x28, out, &o);
        printf("    destroy -> 0x%08x\n", kr);
        p_IOServiceClose(c); } }

    printf("\n=== E4 sel6 NO session ===\n");
    { io_connect_t c = MACH_PORT_NULL;
      kr = p_IOServiceOpen(svc, mach_task_self(), 1, &c);
      if (kr == 0) { call_inband(c, 6, 0x30, 0x20); p_IOServiceClose(c); } }

    printf("\n=== E5-E8 sel7..sel10 with session ===\n");
    { io_connect_t c; if (create_session(svc, &c) == 0) {
        call_inband(c, 7, 0x30, 0x20);
        call_inband(c, 8, 0x30, 0x20);
        call_inband(c, 9, 0x30, 0x20);
        call_inband(c, 10, 0x30, 0x20);
        uint8_t din[0x28] = {0}; size_t o = 0x20; memset(out, 0, sizeof(out));
        kr = p_IOConnectCallStructMethod(c, 2, din, 0x28, out, &o);
        printf("    destroy -> 0x%08x\n", kr);
        p_IOServiceClose(c); } }

    printf("\n=== E9 sel3 with session ===\n");
    { io_connect_t c; if (create_session(svc, &c) == 0) {
        call_inband(c, 3, 0x38, 0x20);
        uint8_t din[0x28] = {0}; size_t o = 0x20; memset(out, 0, sizeof(out));
        kr = p_IOConnectCallStructMethod(c, 2, din, 0x28, out, &o);
        printf("    destroy -> 0x%08x\n", kr);
        p_IOServiceClose(c); } }

    printf("\n=== E10 destroy then sel6 (dead session) ===\n");
    { io_connect_t c; if (create_session(svc, &c) == 0) {
        uint8_t din[0x28] = {0}; size_t o = 0x20; memset(out, 0, sizeof(out));
        kr = p_IOConnectCallStructMethod(c, 2, din, 0x28, out, &o);
        printf("    destroy -> 0x%08x\n", kr);
        call_inband(c, 6, 0x30, 0x20);
        p_IOServiceClose(c); } }

    p_IOObjectRelease(svc);
    return 42;
}
