/*
 * ave2_probe_create.c v21 - enctype discrimination matrix
 *
 * v20: wake-port drain = MACH_RCV_TIMED_OUT (no messages). Dead end.
 * KEY RE-READ: translate table @0x24b148 maps AVE -1000 -> 0xbc !!
 * So device bc may be translate(AVE -1000) from the session machine,
 * NOT the kext gate constructor. And v15 P8 (enctype=1) was the ONLY
 * non-bc variant (c2 = translate(-1001)) -> enctype field is live.
 *
 * v21 matrix (fresh session per group, full out dump every call):
 *  S1 create m1: A2 enctype1/static/1920 | A4 enctype0 | A5 enctype2
 *  S2 create m1: A1 enctype1/ANON-mmap/1920 | A3 enctype1/anon/64656x8080
 *  S3 create m2: A2'
 *  S4 create m1 + sel3 async: A2''
 *  S5 no create: A2'''
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include "iokit_dyn.h"
#include "ave2_wire.h"

static const char *krname(kern_return_t k) {
    switch (k) {
    case 0:           return "KERN_SUCCESS";
    case 0xe00002c2u: return "c2(-1001?)";
    case 0xe00002c7u: return "c7";
    case 0xe00002bcu: return "bc(-1000?)";
    case 0xe00002d8u: return "d8(-1009)";
    case 0xe00002d9u: return "d9(-1011)";
    case 0xe0000001u: return "0xe0000001(-1015)";
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

static uint8_t  stat_in[0x1a0c0];
static uint8_t  anon_in[0x1a0c0];
static uint8_t  in[0x6f0];
static uint8_t  out[0x400];
static uint64_t counter = 0x0000700000004005ULL;
static io_service_t svc;

static kern_return_t create_session(int mode, io_connect_t *conn) {
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
    *(int32_t *)(in + AVE2_IOS_CREATE_OFF_MODE)   = mode;
    {
        const char *cp = getenv("AVE2_CPATCH");
        if (cp != NULL && cp[0]) apply_patch(in, cp);
    }
    size_t osz = AVE2_IOS_CREATE_OUT_SIZE;
    memset(out, 0, sizeof(out));
    kern_return_t k1 = p_IOConnectCallStructMethod(*conn, 1, in, AVE2_IOS_CREATE_IN_SIZE, out, &osz);
    printf("    create m%d -> 0x%08x\n", mode, k1);
    return k1;
}

static void destroy_close(io_connect_t c) {
    uint8_t din[0x28] = {0}; size_t o = 0x20; memset(out, 0, sizeof(out));
    kern_return_t kr = p_IOConnectCallStructMethod(c, 2, din, 0x28, out, &o);
    printf("    destroy -> 0x%08x\n", kr);
    p_IOServiceClose(c);
}

/* which: 0=static, 1=anon mmap */
static void fill_cfg(int which, int w, int h, int p6, int enctype, int slices, int p7) {
    uint8_t *buf = which == 0 ? stat_in : anon_in;
    memset(buf, 0, sizeof(stat_in));
    memcpy(buf + 0x00, "904.76.7", 8);
    memcpy(buf + 0x28, "904.76.7", 8);
    *(int32_t *)(buf + AVE2_OFF_WIDTH)     = w;
    *(int32_t *)(buf + AVE2_OFF_HEIGHT)    = h;
    *(int32_t *)(buf + AVE2_MODE5_OFF_P6)  = p6;
    *(int32_t *)(buf + AVE2_MODE5_OFF_P8)  = 10;
    *(int32_t *)(buf + AVE2_OFF_ENCTYPE)   = enctype;
    *(int32_t *)(buf + AVE2_OFF_SLICES)    = slices;
    *(int32_t *)(buf + AVE2_MODE5_OFF_P7)  = p7;
}


static void sel3_async(io_connect_t c, mach_port_t wake) {
    uint8_t din[0x40];
    memset(din, 0, sizeof(din));
    memcpy(din, "904.76.7", 8);
    iodyn_async_ref_t aref; memset(aref, 0, sizeof(aref));
    aref[0] = 0x1;
    memset(out, 0xAA, sizeof(out));
    size_t o = 0x20;
    kern_return_t kr = p_IOConnectCallAsyncStructMethod(c, 3, wake, aref, 8, din, 0x38, out, &o);
    printf("    sel3 async -> 0x%08x\n", kr);
}

/* ---- v24 generic field-patch infra (env-driven, no assumptions) ---- */

/* AVE2_PATCH="0x3204:2;0x2f64:3" -> write u32 LE at each offset */
static void apply_patch(uint8_t *buf, const char *spec) {
    if (spec == NULL || !spec[0]) return;
    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s", spec);
    char *save = NULL;
    for (char *tok = strtok_r(tmp, ";,", &save); tok; tok = strtok_r(NULL, ";,", &save)) {
        char *colon = strchr(tok, ':');
        if (!colon) { printf("    [patch] bad token %s\n", tok); continue; }
        *colon = 0;
        unsigned long off = strtoul(tok, NULL, 0);
        uint32_t val = (uint32_t)strtoul(colon + 1, NULL, 0);
        if (off + 4 > 0x1a0a0) { printf("    [patch] off %lx OOR\n", off); continue; }
        *(uint32_t *)(buf + off) = val;
        printf("    [patch] +0x%lx = 0x%08x\n", off, val);
    }
}

static void sel4_p(const char *tag, io_connect_t c, int which, size_t isz, const char *patch) {
    uint8_t *buf = which == 0 ? stat_in : anon_in;
    apply_patch(buf, patch);
    memset(out, 0xAA, sizeof(out));
    size_t o = 0x20;
    kern_return_t kr = p_IOConnectCallStructMethod(c, 4, buf, isz, out, &o);
    printf("    [%s] sel4 -> 0x%08x %s\n", tag, kr, krname(kr));
    dump_out(out, o, 0x20);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (iodyn_init() != 0) { printf("[-] iodyn\n"); return 3; }
    void *m = p_IOServiceMatching("AppleAVE2Driver");
    svc = p_IOServiceGetMatchingService(IODYN_MAIN_PORT, m);
    if (!svc) { printf("[-] no service\n"); return 1; }
    const char *e = getenv("AVE2_LOGCNT");
    if (e != NULL && e[0]) counter = strtoull(e, NULL, 0);
    void *anon = mmap(NULL, sizeof(anon_in), PROT_READ | PROT_WRITE,
                      MAP_ANON | MAP_PRIVATE, -1, 0);
    if (anon == MAP_FAILED) { printf("[-] mmap\n"); return 4; }
    memset(anon, 0, sizeof(anon_in));
    mach_port_t wake = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wake);
    io_connect_t c;
    kern_return_t kr;

    const char *test = getenv("AVE2_TEST");
    if (test != NULL && strcmp(test, "generic") == 0) {
        /* generic single/multi config crawler */
        int mode   = getenv("AVE2_CREATE_MODE") ? atoi(getenv("AVE2_CREATE_MODE")) : 1;
        int no_create = getenv("AVE2_NO_CREATE") ? atoi(getenv("AVE2_NO_CREATE")) : 0;
        int use_sel3  = getenv("AVE2_SEL3") ? atoi(getenv("AVE2_SEL3")) : 0;
        int w      = getenv("AVE2_W")  ? atoi(getenv("AVE2_W"))  : 1920;
        int h      = getenv("AVE2_H")  ? atoi(getenv("AVE2_H"))  : 1080;
        int p6     = getenv("AVE2_P6") ? atoi(getenv("AVE2_P6")) : 2;
        int p8     = getenv("AVE2_P8") ? atoi(getenv("AVE2_P8")) : 10;
        int slices = getenv("AVE2_SLICES") ? atoi(getenv("AVE2_SLICES")) : 0;
        int p7     = getenv("AVE2_P7") ? atoi(getenv("AVE2_P7")) : 0;
        int enc    = getenv("AVE2_ENC") ? atoi(getenv("AVE2_ENC")) : 1;
        int which  = getenv("AVE2_ANON") ? atoi(getenv("AVE2_ANON")) : 0;
        size_t isz = getenv("AVE2_SELSZ") ? (size_t)strtoul(getenv("AVE2_SELSZ"), NULL, 0) : 0x1a0a0;
        int repeat = getenv("AVE2_REPEAT") ? atoi(getenv("AVE2_REPEAT")) : 1;
        const char *patch = getenv("AVE2_PATCH");
        printf("=== generic w=%d h=%d p6=%d p8=%d sl=%d p7=%d enc=%d isz=0x%zx rep=%d ===\n",
               w, h, p6, p8, slices, p7, enc, isz, repeat);
        for (int i = 0; i < repeat; i++) {
            printf("--- rep %d ---\n", i);
            if (no_create) {
                if (p_IOServiceOpen(svc, mach_task_self(), 1, &c) != 0) { printf("[-] open\n"); break; }
            } else {
                if (create_session(mode, &c) != 0) break;
            }
            if (use_sel3) sel3_async(c, wake);
            fill_cfg(which, w, h, p6, enc, slices, p7);
            char tag[64];
            snprintf(tag, sizeof(tag), "g%d", i);
            sel4_p(tag, c, which, isz, patch);
            if (!no_create) destroy_close(c);
            else p_IOServiceClose(c);
        }
    } else {
        /* default battery: enctype sweep + no-create ladder */
        printf("\n=== S1 create m1: enctype sweep (static) ===\n");
        if (create_session(1, &c) == 0) {
            fill_cfg(0, 1920, 1080, 2, 1, 0, 0); sel4_p("e1/full", c, 0, 0x1a0a0, NULL);
            fill_cfg(0, 1920, 1080, 2, 0, 0, 0); sel4_p("e0/full", c, 0, 0x1a0a0, NULL);
            fill_cfg(0, 1920, 1080, 2, 2, 0, 0); sel4_p("e2/full", c, 0, 0x1a0a0, NULL);
            destroy_close(c);
        }
        printf("\n=== S5 no create: gate ladder ===\n");
        if (p_IOServiceOpen(svc, mach_task_self(), 1, &c) == 0) {
            fill_cfg(0, 1920, 1080, 2, 0, 0, 0); sel4_p("S5/P6e0", c, 0, 0x38, NULL);
            fill_cfg(0, 1920, 1080, 2, 0, 0, 0); sel4_p("S5/P7e0", c, 0, 0x28, NULL);
            fill_cfg(0, 1920, 1080, 2, 1, 0, 0); sel4_p("S5/P6e1", c, 0, 0x38, NULL);
            fill_cfg(0, 1920, 1080, 2, 1, 0, 0); sel4_p("S5/P7e1", c, 0, 0x28, NULL);
            p_IOServiceClose(c);
        }
    }

    munmap(anon, sizeof(anon_in));
    if (wake) mach_port_deallocate(mach_task_self(), wake);
    p_IOObjectRelease(svc);
    return 42;
}
