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
#include <unistd.h>
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
static int g_opentype = 1;
static uint64_t counter = 0x0000700000004005ULL;
static void apply_patch(uint8_t *buf, const char *spec); /* fwd: used by create_session */
static io_service_t svc;

static kern_return_t create_session(int mode, io_connect_t *conn) {
    *conn = MACH_PORT_NULL;
    kern_return_t kr = p_IOServiceOpen(svc, mach_task_self(), g_opentype, conn);
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
    g_opentype = getenv("AVE2_OPENTYPE") ? atoi(getenv("AVE2_OPENTYPE")) : 1;
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
                if (p_IOServiceOpen(svc, mach_task_self(), g_opentype, &c) != 0) { printf("[-] open\n"); break; }
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
    } else if (test != NULL && strcmp(test, "modesweep") == 0) {
        /* v25: create mode matrix 1..5 x enc 1/2, sel4 probe after each successful create */
        const char *patch = getenv("AVE2_MS_PATCH");
        printf("=== modesweep create m1..5 x enc1/2, sel4 after each success ===\n");
        for (int m = 1; m <= 5; m++) {
            for (int e = 1; e <= 2; e++) {
                printf("--- mode %d enc %d ---\n", m, e);
                if (create_session(m, &c) != 0) continue;
                fill_cfg(0, 1920, 1080, 2, e, 0, 0);
                sel4_p("ms", c, 0, 0x1a0a0, patch);
                destroy_close(c);
            }
        }
    } else if (test != NULL && strcmp(test, "lrbscan") == 0) {
        /* v26: locate LRB param block {flags@o,B@o+8,C@o+c,D@o+10,E@o+14} inside create input window 0x28..0x228.
           WorkPool OpenTask reads task+0x2c block; cmd payload comes from the 0x200 memcpy'd region. */
        const char *patch = getenv("AVE2_MS_PATCH");
        printf("=== lrbscan: probe LRB block origin in create input ===\n");
        for (int o = 0x28; o + 0x18 <= 0x228; o += 4) {
            if (create_session(1, &c) != 0) { printf("[-] create fail at o=0x%x\n", o); break; }
            fill_cfg(0, 1920, 1080, 2, 1, 0, 0);
            *(uint32_t *)(stat_in + o)        = 1;         /* flags -> s=2 */
            *(uint32_t *)(stat_in + o + 0x8)  = 0x10000;   /* B */
            *(uint32_t *)(stat_in + o + 0xc)  = 0x10000;   /* C */
            *(uint32_t *)(stat_in + o + 0x10) = 4;         /* D */
            *(uint32_t *)(stat_in + o + 0x14) = 4;         /* E */
            sel4_p("lb", c, 0, 0x1a0a0, patch);
            destroy_close(c);
        }
        printf("=== lrbscan done ===\n");
    } else if (test != NULL && strcmp(test, "statesweep") == 0) {
        /* v27: after configure success, walk sel5/6/7/8/9/10 to map the encoder state machine */
        const char *patch = getenv("AVE2_MS_PATCH");
        int m = getenv("AVE2_CREATE_MODE") ? atoi(getenv("AVE2_CREATE_MODE")) : 1;
        printf("=== statesweep mode %d: create->sel4->sel5/6/7/8/9/10 ===\n", m);
        if (create_session(m, &c) != 0) { printf("[-] create\n"); return 42; }
        fill_cfg(0, 1920, 1080, 2, 1, 0, 0);
        sel4_p("st", c, 0, 0x1a0a0, patch);
        { uint8_t d5[0x1a0b0]; memset(d5,0,sizeof(d5)); memcpy(d5,"904.76.7",8);
          *(int32_t *)(d5 + AVE2_OFF_WIDTH) = 1920; *(int32_t *)(d5 + AVE2_OFF_HEIGHT) = 1080;
          *(int32_t *)(d5 + AVE2_OFF_ENCTYPE) = 1; *(int32_t *)(d5 + AVE2_OFF_SLICES) = 1;
          uint8_t o5[0x150]; size_t o5z = 0x150; memset(o5, 0xAA, sizeof(o5));
          kern_return_t k5 = p_IOConnectCallStructMethod(c, 5, d5, sizeof(d5), o5, &o5z);
          printf("    sel5 -> 0x%08x osz=%zu out0:", k5, o5z);
          for (size_t q = 0; q < 16 && q < o5z; q++) printf("%02x", o5[q]);
          printf("\n"); }
        { uint8_t d6[0x30]; memset(d6,0,sizeof(d6)); memcpy(d6,"904.76.7",8);
          uint8_t o6[0x20]; size_t o6z = 0x20; memset(o6, 0xAA, sizeof(o6));
          kern_return_t k6 = p_IOConnectCallStructMethod(c, 6, d6, sizeof(d6), o6, &o6z);
          printf("    sel6 -> 0x%08x osz=%zu out0:", k6, o6z);
          for (size_t q = 0; q < 16 && q < o6z; q++) printf("%02x", o6[q]);
          printf("\n"); }
        for (int sel = 7; sel <= 10; sel++) {
            uint8_t d7[0x30]; memset(d7,0,sizeof(d7)); memcpy(d7,"904.76.7",8);
            *(int32_t *)(d7 + 0x08) = 1;
            uint8_t o7[0x20]; size_t o7z = 0x20; memset(o7, 0xAA, sizeof(o7));
            kern_return_t k7 = p_IOConnectCallStructMethod(c, sel, d7, sizeof(d7), o7, &o7z);
            printf("    sel%d -> 0x%08x osz=%zu out0:", sel, k7, o7z);
            for (size_t q = 0; q < 16 && q < o7z; q++) printf("%02x", o7[q]);
            printf("\n"); }
        destroy_close(c);
    } else if (test != NULL && strcmp(test, "s2reg") == 0) {
        /* v31: real-client sequence = create -> sel2(session register) -> sel4 -> sel5.
           media-toolbox report section4: sel2 in 0x28: +0x00 cookie(this[0]), +0x08/+0x10=0,
           +0x18=0x7088980A magic, +0x20=timestamp; out 0x20 overlaps in+0x10. */
        const char *patch = getenv("AVE2_MS_PATCH");
        printf("=== s2reg: create -> sel2(register) -> sel4 -> sel5 ===\n");
        static const char *ckname[] = {"out0", "out1", "zero", "magic"};
        for (int ck = 0; ck < 4; ck++) {
            printf("--- s2reg cookie=%d (%s) ---\n", ck, ckname[ck]);
            if (create_session(1, &c) != 0) { printf("[-] create\n"); break; }
            printf("    [create out] ");
            for (size_t q = 0; q < 0x28; q++) printf("%02x", out[q]);
            printf("\n");
            uint64_t cookie;
            switch (ck) {
            case 0: cookie = *(uint64_t *)(out + 0x00); break;
            case 1: cookie = *(uint64_t *)(out + 0x08); break;
            case 2: cookie = 0; break;
            default: cookie = 0x7088980AULL; break;
            }
            uint8_t io2[0x30]; memset(io2, 0, sizeof(io2));
            *(uint64_t *)(io2 + 0x00) = cookie;
            *(uint64_t *)(io2 + 0x18) = 0x7088980AULL;
            *(uint64_t *)(io2 + 0x20) = (uint64_t)mach_absolute_time();
            size_t in2z = 0x28, o2z = 0x20;
            kern_return_t k2 = p_IOConnectCallStructMethod(c, 2, io2, in2z, io2 + 0x10, &o2z);
            printf("    [sel2] -> 0x%08x buf(+0x10):", k2);
            for (size_t q = 0; q < 0x20; q++) printf("%02x", io2[0x10 + q]);
            printf("\n");
            fill_cfg(0, 1920, 1080, 2, 1, 0, 0);
            sel4_p("s2pre", c, 0, 0x1a0a0, patch);
            uint8_t d5[0x1a0b0]; memset(d5, 0, sizeof(d5)); memcpy(d5, stat_in, 0x1a0a0);
            *(uint32_t *)(d5 + 0x28) = 1;
            uint8_t o5[0x150]; size_t o5z = 0x150; memset(o5, 0xAA, sizeof(o5));
            kern_return_t k5 = p_IOConnectCallStructMethod(c, 5, d5, sizeof(d5), o5, &o5z);
            printf("    [s5] sel5 -> 0x%08x osz=%zu out0:", k5, o5z);
            for (size_t q = 0; q < 16 && q < o5z; q++) printf("%02x", o5[q]);
            printf("\n");
            destroy_close(c);
        }
        printf("=== s2reg done ===\n");
    } else if (test != NULL && strcmp(test, "start5") == 0) {
        /* v28: sel5 UCStart matrix. kext verifier 0x1b98f14 requires:
           0x1b98084 s64 nonneg (in+0x10/+0x18/+0x20), [in+0x28] u32 != 0,
           [in+0x1A0A8] u32 nonneg. Then Configure(state==1) deep chain runs. */
        const char *patch = getenv("AVE2_MS_PATCH");
        int m = getenv("AVE2_CREATE_MODE") ? atoi(getenv("AVE2_CREATE_MODE")) : 1;
        printf("=== start5: create m%d -> sel4 -> sel5 matrix ===\n", m);
        for (int casei = 0; casei < 8; casei++) {
            printf("--- s5 case %d ---\n", casei);
            if (create_session(m, &c) != 0) { printf("[-] create\n"); break; }
            fill_cfg(0, 1920, 1080, 2, 1, 0, 0);
            sel4_p("s5pre", c, 0, 0x1a0a0, patch);
            { /* v29: dump full sel4 out (0x20) — checker return @+0x18 may be a token for sel5 */
              uint8_t d4[0x1a0a0]; memset(d4,0,sizeof(d4)); memcpy(d4,stat_in,0x1a0a0);
              const char *mp2 = patch; if (mp2) apply_patch(d4, mp2);
              uint8_t o4[0x20]; size_t o4z=0x20; memset(o4,0xAA,sizeof(o4));
              kern_return_t k4 = p_IOConnectCallStructMethod(c, 4, d4, sizeof(d4), o4, &o4z);
              printf("    [s5pre-full] sel4 -> 0x%08x out:", k4);
              for (size_t q = 0; q < 0x20; q++) printf("%02x", o4[q]);
              printf("\n"); }
            uint8_t d5[0x1a0b0]; memset(d5, 0, sizeof(d5));
            memcpy(d5, stat_in, 0x1a0a0);
            switch (casei) {
            case 0: *(uint32_t *)(d5 + 0x28) = 1; *(uint32_t *)(d5 + 0x1a0a8) = 0; break;
            case 1: *(uint32_t *)(d5 + 0x28) = 0; break; /* expect early reject */
            case 2: *(uint32_t *)(d5 + 0x28) = 1; *(uint32_t *)(d5 + 0x1a0a8) = 1; break;
            case 3: *(uint32_t *)(d5 + 0x28) = 0x40; break;
            case 4: *(uint32_t *)(d5 + 0x28) = 1; *(uint32_t *)(d5 + 0x1a0a8) = 0;
                    *(int32_t *)(d5 + 0x1a0a0) = 1; break;
            case 5: *(uint32_t *)(d5 + 0x28) = 1; *(uint32_t *)(d5 + 0x1a0a8) = 0;
                    *(int32_t *)(d5 + 0x1a0a4) = 1; break;
            case 6: *(uint32_t *)(d5 + 0x28) = 1; *(uint32_t *)(d5 + 0x1a0a8) = 0;
                    *(int32_t *)(d5 + AVE2_OFF_ENCTYPE) = 2; break;
            case 7: *(uint32_t *)(d5 + 0x28) = 1; *(uint32_t *)(d5 + 0x1a0a8) = 0;
                    *(int32_t *)(d5 + AVE2_OFF_WIDTH) = 4096;
                    *(int32_t *)(d5 + AVE2_OFF_HEIGHT) = 2160; break;
            }
            { /* v30: firmware async command drain — sleep + optional sel4 re-fire before sel5 */
              const char *dl = getenv("AVE2_S5DELAY");
              const char *rn = getenv("AVE2_S5RESEL4");
              int ms = dl ? atoi(dl) : 0;
              int re = rn ? atoi(rn) : 0;
              if (ms > 0) usleep(ms * 1000);
              for (int r = 0; r < re; r++) {
                  uint8_t d4[0x1a0a0]; memset(d4,0,sizeof(d4)); memcpy(d4,stat_in,0x1a0a0);
                  const char *mp3 = patch; if (mp3) apply_patch(d4, mp3);
                  uint8_t o4[0x20]; size_t o4z=0x20; memset(o4,0xAA,sizeof(o4));
                  kern_return_t k4 = p_IOConnectCallStructMethod(c, 4, d4, sizeof(d4), o4, &o4z);
                  if (ms > 0) usleep(ms * 1000);
                  printf("    [refire %d] sel4 -> 0x%08x\n", r, k4);
              }
            }
            uint8_t o5[0x150]; size_t o5z = 0x150; memset(o5, 0xAA, sizeof(o5));
            kern_return_t k5 = p_IOConnectCallStructMethod(c, 5, d5, sizeof(d5), o5, &o5z);
            printf("    [s5-%d] sel5 -> 0x%08x osz=%zu out0:", casei, k5, o5z);
            for (size_t q = 0; q < 16 && q < o5z; q++) printf("%02x", o5[q]);
            printf("\n");
            sel4_p("s5post", c, 0, 0x1a0a0, NULL);
            { uint8_t d6[0x30]; memset(d6,0,sizeof(d6)); memcpy(d6,"904.76.7",8);
              uint8_t o6[0x20]; size_t o6z=0x20; memset(o6,0xAA,sizeof(o6));
              kern_return_t k6 = p_IOConnectCallStructMethod(c, 6, d6, 0x30, o6, &o6z);
              printf("    [s5-%d] sel6 -> 0x%08x\n", casei, k6); }
            destroy_close(c);
        }

        { /* v29: field probe scan — set one u32=1 at off, watch sel5 error move */
          static const uint32_t offs[] = {0,4,8,0xc,0x10,0x14,0x18,0x1c,0x20,0x24,0x2c,0x30,0x34,0x38,0x3c,0x40,0x48,0x50,0x60,0x80,0xa0,0x200,0x9c4,0x9cc,0x9ec,0x1a0a8};
          for (unsigned i = 0; i < sizeof(offs)/sizeof(offs[0]); i++) {
              if (create_session(m, &c) != 0) { printf("[-] create\n"); break; }
              fill_cfg(0, 1920, 1080, 2, 1, 0, 0);
              sel4_p("sp", c, 0, 0x1a0a0, patch);
              uint8_t d5[0x1a0b0]; memset(d5, 0, sizeof(d5));
              memcpy(d5, stat_in, 0x1a0a0);
              *(uint32_t *)(d5 + 0x28) = 1;
              *(uint32_t *)(d5 + offs[i]) = 1;
              uint8_t o5[0x150]; size_t o5z = 0x150; memset(o5, 0xAA, sizeof(o5));
              kern_return_t k5 = p_IOConnectCallStructMethod(c, 5, d5, sizeof(d5), o5, &o5z);
              printf("    [scan +%#x] sel5 -> 0x%08x out0:", offs[i], k5);
              for (size_t q = 0; q < 8 && q < o5z; q++) printf("%02x", o5[q]);
              printf("\n");
              destroy_close(c);
          }
        }
        printf("=== start5 done ===\n");
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
        if (p_IOServiceOpen(svc, mach_task_self(), g_opentype, &c) == 0) {
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
