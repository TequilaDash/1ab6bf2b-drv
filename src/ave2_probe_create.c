/*
 * ave2_probe_create.c v14 — descriptor-path discriminator matrix
 *
 * Established (v7-v13): create(sel1, 0x6f0/0x28, version "904.76.7" @+0x28,
 * monotonic log counter) = KERN_SUCCESS. sel4 configure (0x1a0a0/0x20,
 * exact size) = 0xe00002bc with out UNTOUCHED. sel5 (0x1a0b0/0x150) =
 * 0xe00002d9. Static RE (kernelcache 26.0.1): the trap turns >0x1000 MIG
 * data_t into OOL descriptors (withAddressRange flags 0x20002 in / 1 out)
 * and never pre-maps; the kext object path calls desc->vt[0xd8](0) then
 * desc->vt[0xe8](0x1000=IOMemoryWrapper) and maps NULL -> bc exit2.
 * Apple's own client uses IOConnectCallStructMethod only -> same OOL path.
 *
 * v14 fixes the configure version string ("904.76.7" @+0x28 AND @+0x00 —
 * the iOS checker 0x1b98d30 memcmps in+0x28 against "904.76.7", we used
 * to send macOS "905.40.1") and runs a discriminator matrix:
 *   D1 sel4 OOL with out prefill 0xAA   (is out really untouched?)
 *   D2 sel4 twice back-to-back          (stateful effect on same UC?)
 *   D3 sel5 -> sel4 -> sel5             (order/state coupling)
 *   D6 sel4 x8 repeats                  (determinism / map-registry memory)
 *   D7 sel4 async + wake port           (async dispatch variant)
 *   D8 sel2 async                       (inband async)
 *   D5 sel2 destroy after create        (state readback: fc0d expected)
 *   D4 sel2 destroy on FRESH 2nd conn   (raw inband path sanity, expect 0)
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
    case 0xe00002c2u:    return "c2 BadArgument (dispatcher size gate)";
    case 0xe00002c7u:    return "c7 Unsupported";
    case 0xe00002bcu:    return "0xbc (kext map-NULL exit / mismatch)";
    case 0xe00002d8u:    return "0xd8 (AVE -1009 / IOMemoryDescriptor busy)";
    case 0xe00002d9u:    return "0xd9 (AVE -1011 prepare-busy)";
    case 0xfffffc09u:    return "0xfffffc09 version mismatch";
    case 0xfffffc17u:    return "0xfffffc17 param/validation";
    case 0xfffffc0du:    return "0xfffffc0d wrong state (no session)";
    default:             return "";
    }
}

/* dump out: always print first n bytes + whether all-zero */
static void dump_out(const uint8_t *out, size_t osz, size_t n) {
    size_t m = osz < n ? osz : n;
    int allz = 1;
    for (size_t q = 0; q < osz; q++) if (out[q]) { allz = 0; break; }
    printf("  osz=%zu allzero=%d out[0..%zu]:", osz, allz, m);
    for (size_t q = 0; q < m; q++) printf("%02x", out[q]);
    printf("\n");
}

static void build_create_input(uint8_t *in, size_t cap, uint64_t counter, int32_t mode) {
    memset(in, 0, cap);
    *(uint64_t *)(in + 0x08) = 0x4142434445464748ULL;
    *(uint64_t *)(in + 0x10) = 0x3132333435363738ULL;
    memcpy(in + AVE2_IOS_CREATE_OFF_VERSION, "904.76.7", 8);
    *(uint64_t *)(in + AVE2_IOS_CREATE_OFF_LOGCNT) = counter;
    *(int32_t *)(in + AVE2_IOS_CREATE_OFF_LOGLVL) = 1;
    *(int32_t *)(in + AVE2_IOS_CREATE_OFF_LOGNUM) = 1;
    *(int32_t *)(in + AVE2_IOS_CREATE_OFF_MODE)   = mode;
}

static fp_IOConnectSetNotificationPort p_SetNotif;
static const ave2_profile_t *prof;

static uint8_t  cin[0x1a0c0];
static uint8_t  out[0x400];
static uint64_t counter = 0x0000700000000001ULL;

/* v14: iOS configure version = "904.76.7" at BOTH +0x00 and +0x28 */
#define CFGFILL() do { \
        memset(cin, 0, sizeof(cin)); \
        memcpy(cin + 0x00, "904.76.7", 8); \
        memcpy(cin + 0x28, "904.76.7", 8); \
        *(int32_t  *)(cin + AVE2_OFF_WIDTH)        = (int32_t)prof->w; \
        *(int32_t  *)(cin + AVE2_OFF_HEIGHT)       = (int32_t)prof->h; \
        *(int32_t  *)(cin + AVE2_MODE5_OFF_P6)     = 2; \
        *(int32_t  *)(cin + AVE2_MODE5_OFF_P8)     = 10; \
        *(uint8_t  *)(cin + AVE2_MODE5_OFF_P9FLAG) = 0; \
        *(int32_t  *)(cin + AVE2_OFF_NUMVIEWS)     = 1; \
        *(int32_t  *)(cin + AVE2_OFF_NUMLAYERS)    = 1; \
    } while (0)

static kern_return_t call4(io_connect_t c, uint8_t *o, size_t *osz, int prefill) {
    CFGFILL();
    memset(o, prefill ? 0xAA : 0, sizeof(out));
    *osz = 0x20;
    return p_IOConnectCallStructMethod(c, 4, cin, 0x1a0a0, o, osz);
}

static kern_return_t call5(io_connect_t c, uint8_t *o, size_t *osz, int prefill) {
    CFGFILL();
    memset(o, prefill ? 0xAA : 0, sizeof(out));
    *osz = 0x150;
    return p_IOConnectCallStructMethod(c, 5, cin, 0x1a0b0, o, osz);
}

static kern_return_t call2(io_connect_t c, uint8_t *o, size_t *osz) {
    uint8_t din[0x28] = {0};
    memset(o, 0, sizeof(out));
    *osz = 0x20;
    return p_IOConnectCallStructMethod(c, 2, din, 0x28, o, osz);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    if (iodyn_init() != 0) { printf("[-] iodyn\n"); return 3; }
    p_SetNotif = (fp_IOConnectSetNotificationPort)dlsym(iodyn_handle, "IOConnectSetNotificationPort");
    prof = ave2_profile_get(0);
    printf("[*] profile %dx%d  SetNotif=%s\n", prof->w, prof->h, p_SetNotif ? "ok" : "NULL");

    void *m = p_IOServiceMatching("AppleAVE2Driver");
    io_service_t svc = p_IOServiceGetMatchingService(IODYN_MAIN_PORT, m);
    if (!svc) { printf("[-] no service\n"); return 1; }
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = p_IOServiceOpen(svc, mach_task_self(), 1, &conn);
    if (kr != KERN_SUCCESS) { printf("[-] open: 0x%x\n", kr); return 2; }
    printf("[+] conn1 0x%x\n\n", conn);

    mach_port_t wake = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wake);

    static uint8_t in[0x1a0a0];
    const char *e = getenv("AVE2_LOGCNT");
    if (e != NULL && e[0]) counter = strtoull(e, NULL, 0);

    int created = 0;
    for (int mode = 0; mode <= 10 && !created; mode++) {
        printf("=== create mode=%d 0x6f0/0x28 ===\n", mode);
        build_create_input(in, AVE2_IOS_CREATE_IN_SIZE, ++counter, mode);
        size_t osz = AVE2_IOS_CREATE_OUT_SIZE;
        memset(out, 0, sizeof(out));
        kern_return_t k = p_IOConnectCallStructMethod(conn, 1, in, AVE2_IOS_CREATE_IN_SIZE, out, &osz);
        printf("  -> 0x%08x %s ", k, krname(k)); dump_out(out, osz, 0x28);
        created = (k == 0);
    }
    printf("\n[create %s]\n", created ? "OK" : "FAILED");

    if ((e = getenv("AVE2_CONFIGURE")) != NULL && e[0] == '1' && created) {
        kern_return_t k; size_t osz;
        printf("\n=== D1 sel4 OOL 0x1a0a0/0x20, out prefill 0xAA ===\n");
        k = call4(conn, out, &osz, 1);
        printf("  [D1] -> 0x%08x %s\n", k, krname(k)); dump_out(out, osz, 0x20);

        printf("\n=== D2 sel4 again (same conn) ===\n");
        k = call4(conn, out, &osz, 1);
        printf("  [D2] -> 0x%08x %s\n", k, krname(k)); dump_out(out, osz, 0x20);

        printf("\n=== D3 order: sel5 -> sel4 -> sel5 ===\n");
        k = call5(conn, out, &osz, 1);
        printf("  [D3.a sel5] -> 0x%08x %s\n", k, krname(k)); dump_out(out, osz, 0x150);
        k = call4(conn, out, &osz, 1);
        printf("  [D3.b sel4] -> 0x%08x %s\n", k, krname(k)); dump_out(out, osz, 0x20);
        k = call5(conn, out, &osz, 1);
        printf("  [D3.c sel5] -> 0x%08x %s\n", k, krname(k)); dump_out(out, osz, 0x150);

        printf("\n=== D6 sel4 x8 determinism ===\n");
        { kern_return_t seen[16]; int cnt[16], n = 0;
          for (int i = 0; i < 8; i++) {
            k = call4(conn, out, &osz, 0);
            int f = -1;
            for (int j = 0; j < n; j++) if (seen[j] == k) { f = j; break; }
            if (f < 0 && n < 16) { seen[n] = k; cnt[n] = 1; n++; }
            else if (f >= 0) cnt[f]++;
            printf("  [D6.%d] 0x%08x\n", i + 1, k);
          }
          printf("  [D6 summary]");
          for (int j = 0; j < n; j++) printf(" 0x%08x x%d", seen[j], cnt[j]);
          printf("\n");
        }

        printf("\n=== D7 sel4 async + wake port ===\n");
        {
            iodyn_async_ref_t aref = {0x41414141, 0, 0, 0, 0, 0, 0, 0};
            kern_return_t kn = p_SetNotif ? p_SetNotif(conn, 0, wake) : -1;
            printf("  SetNotificationPort(type0) -> 0x%08x\n", kn);
            CFGFILL(); memset(out, 0xAA, sizeof(out)); osz = 0x20;
            k = p_IOConnectCallAsyncStructMethod(conn, 4, wake, aref, 8, cin, 0x1a0a0, out, &osz);
            printf("  [D7] -> 0x%08x %s\n", k, krname(k)); dump_out(out, osz, 0x20);
        }

        printf("\n=== D8 sel2 async ===\n");
        {
            uint8_t din[0x28] = {0};
            iodyn_async_ref_t aref = {0x42424242, 0, 0, 0, 0, 0, 0, 0};
            memset(out, 0, sizeof(out)); osz = 0x20;
            k = p_IOConnectCallAsyncStructMethod(conn, 2, wake, aref, 8, din, 0x28, out, &osz);
            printf("  [D8] -> 0x%08x %s\n", k, krname(k)); dump_out(out, osz, 0x20);
        }

        printf("\n=== D5 sel2 destroy AFTER create (state readback) ===\n");
        k = call2(conn, out, &osz);
        printf("  [D5] -> 0x%08x %s\n", k, krname(k)); dump_out(out, osz, 0x20);

        printf("\n=== D4 fresh 2nd conn: sel2 destroy with NO create ===\n");
        {
            io_connect_t c2 = MACH_PORT_NULL;
            kr = p_IOServiceOpen(svc, mach_task_self(), 1, &c2);
            printf("  open2 -> 0x%08x conn2=0x%x\n", kr, c2);
            if (kr == 0) {
                k = call2(c2, out, &osz);
                printf("  [D4] -> 0x%08x %s\n", k, krname(k)); dump_out(out, osz, 0x20);
                k = call4(c2, out, &osz, 0);
                printf("  [D4b sel4 no-create] -> 0x%08x %s\n", k, krname(k)); dump_out(out, osz, 0x20);
                p_IOServiceClose(c2);
            }
        }
    }

    printf("\n=== final sel2 destroy (main conn) ===\n");
    { size_t osz; kern_return_t k = call2(conn, out, &osz);
      printf("  -> 0x%08x %s\n", k, krname(k)); dump_out(out, osz, 0x20); }

    mach_port_destroy(mach_task_self(), wake);
    p_IOServiceClose(conn);
    p_IOObjectRelease(svc);
    return created ? 42 : 5;
}
