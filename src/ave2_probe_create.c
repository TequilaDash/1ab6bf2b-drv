/*
 * ave2_probe_create.c v15 — sel4 configure parameter sweep (fresh conn per case)
 *
 * v14 findings (device): sel4 with live session = 0xe00002bc x8 deterministic,
 * out 100%% untouched (0xAA prefill intact) -> the out-write after the kext
 * checker is conditional, so bc is most plausibly translate(<unmapped AVE
 * session error>). sel4 with NO session = 0xe00002d9 (= fc0d -1011 no-session).
 * sel5 = 0xe00002d9 with session, sel2 = 0 everywhere. Async == sync.
 *
 * v15 question: is bc structural (missing/invalid cfg fields) or param-driven
 * (dimension/p6 rejection)? Sweep 11 parameter sets, each on a FRESH
 * open->create->sel4->destroy->close cycle so session state never leaks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>

#include "iokit_dyn.h"
#include "ave2_wire.h"
#include "ave2_profiles.h"

static const char *krname(kern_return_t k) {
    switch (k) {
    case 0:              return "KERN_SUCCESS";
    case 0xe00002c2u:    return "c2 dispatcher size gate";
    case 0xe00002c7u:    return "c7 Unsupported";
    case 0xe00002bcu:    return "0xbc unmapped-AVE / gate";
    case 0xe00002d8u:    return "0xd8 throttled/busy";
    case 0xe00002d9u:    return "0xd9 no-session (-1011) / NotAttached";
    case 0xfffffc09u:    return "fc09 version";
    case 0xfffffc17u:    return "fc17 param";
    case 0xfffffc0du:    return "fc0d state";
    default:             return "";
    }
}

static void dump_out(const uint8_t *out, size_t osz, size_t n) {
    size_t m = osz < n ? osz : n;
    int allz = 1;
    for (size_t q = 0; q < osz; q++) if (out[q]) { allz = 0; break; }
    printf("  osz=%zu allzero=%d out:", osz, allz);
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

static uint8_t  cin[0x1a0c0];
static uint8_t  in[0x6f0];
static uint8_t  out[0x400];
static uint64_t counter = 0x0000700000000C00ULL;

typedef struct {
    const char *tag;
    int w, h, p6, p8, views, layers, slices, p7, enctype;
    uint64_t timeout;
} pcase_t;

static void fill_cfg(const pcase_t *c) {
    memset(cin, 0, sizeof(cin));
    memcpy(cin + 0x00, "904.76.7", 8);
    memcpy(cin + 0x28, "904.76.7", 8);
    *(int32_t  *)(cin + AVE2_OFF_WIDTH)     = c->w;
    *(int32_t  *)(cin + AVE2_OFF_HEIGHT)    = c->h;
    *(int32_t  *)(cin + AVE2_MODE5_OFF_P6)  = c->p6;
    *(int32_t  *)(cin + AVE2_MODE5_OFF_P8)  = c->p8;
    *(uint8_t  *)(cin + AVE2_MODE5_OFF_P9FLAG) = 0;
    *(int32_t  *)(cin + AVE2_OFF_NUMVIEWS)  = c->views;
    *(int32_t  *)(cin + AVE2_OFF_NUMLAYERS) = c->layers;
    if (c->slices)  *(int32_t *)(cin + AVE2_OFF_SLICES)  = c->slices;
    if (c->p7)      *(int32_t *)(cin + AVE2_MODE5_OFF_P7) = c->p7;
    if (c->enctype) *(int32_t *)(cin + AVE2_OFF_ENCTYPE) = c->enctype;
    if (c->timeout) *(uint64_t *)(cin + 0x18) = c->timeout;
}

static kern_return_t call4(io_connect_t c, size_t *osz) {
    memset(out, 0xAA, sizeof(out));
    *osz = 0x20;
    return p_IOConnectCallStructMethod(c, 4, cin, 0x1a0a0, out, osz);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (iodyn_init() != 0) { printf("[-] iodyn\n"); return 3; }

    void *m = p_IOServiceMatching("AppleAVE2Driver");
    io_service_t svc = p_IOServiceGetMatchingService(IODYN_MAIN_PORT, m);
    if (!svc) { printf("[-] no service\n"); return 1; }

    const char *e = getenv("AVE2_LOGCNT");
    if (e != NULL && e[0]) counter = strtoull(e, NULL, 0);

    /* the baseline brute/overflow pair from the upstream analysis, plus legal
     * anchors to separate structural vs param failure */
    static const pcase_t cases[] = {
        /*  tag           w      h     p6 p8 views layers slices p7 enc timeout */
        { "P0 baseline-overflow-64656x8080-p6=2", 64656, 8080, 2, 10, 1, 1, 0, 0, 0, 0 },
        { "P1 legal-1920x1080-p6=2",              1920, 1080, 2, 10, 1, 1, 0, 0, 0, 0 },
        { "P2 legal-1920x1080-p6=3",              1920, 1080, 3, 10, 1, 1, 0, 0, 0, 0 },
        { "P3 brute-65424x5264-p6=3",            65424, 5264, 3, 10, 1, 1, 0, 0, 0, 0 },
        { "P4 overflow-64656x8080-p6=3",          64656, 8080, 3, 10, 1, 1, 0, 0, 0, 0 },
        { "P5 baseline+timeout=1e9",              64656, 8080, 2, 10, 1, 1, 0, 0, 0, 1000000000ULL },
        { "P6 legal+slices=1",                    1920, 1080, 2, 10, 1, 1, 1, 0, 0, 0 },
        { "P7 legal+p7=1",                        1920, 1080, 2, 10, 1, 1, 0, 1, 0, 0 },
        { "P8 legal+enctype=1",                   1920, 1080, 2, 10, 1, 1, 0, 0, 1, 0 },
        { "P9 tiny-16x16-p6=2",                     16,   16, 2, 10, 1, 1, 0, 0, 0, 0 },
        { "P10 legal-views2-layers2",             1920, 1080, 2, 10, 2, 2, 0, 0, 0, 0 },
    };

    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        const pcase_t *c = &cases[i];
        printf("\n=== %s (%dx%d p6=%d) ===\n", c->tag, c->w, c->h, c->p6);
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr = p_IOServiceOpen(svc, mach_task_self(), 1, &conn);
        if (kr != 0) { printf("  open fail 0x%08x\n", kr); continue; }
        /* create (mode 1 = the only iOS-accepted session mode besides 2) */
        build_create_input(in, AVE2_IOS_CREATE_IN_SIZE, ++counter, 1);
        size_t osz = AVE2_IOS_CREATE_OUT_SIZE;
        memset(out, 0, sizeof(out));
        kern_return_t k1 = p_IOConnectCallStructMethod(conn, 1, in, AVE2_IOS_CREATE_IN_SIZE, out, &osz);
        printf("  create -> 0x%08x %s\n", k1, krname(k1));
        if (k1 == 0) {
            fill_cfg(c);
            kern_return_t k4 = call4(conn, &osz);
            printf("  sel4   -> 0x%08x %s\n", k4, krname(k4));
            dump_out(out, osz, 0x20);
            if (k4 == 0) {
                printf("  *** CONFIGURE SUCCESS — session configured ***\n");
                /* probe follow-ups immediately */
                uint8_t din6[0x30] = {0};
                memset(out, 0xAA, sizeof(out)); osz = 0x20;
                kern_return_t k6 = p_IOConnectCallStructMethod(conn, 6, din6, 0x30, out, &osz);
                printf("  sel6   -> 0x%08x %s\n", k6, krname(k6)); dump_out(out, osz, 0x20);
            }
        }
        /* destroy + close (fresh state for next case) */
        { uint8_t din[0x28] = {0}; memset(out, 0, sizeof(out)); osz = 0x20;
          kern_return_t k2 = p_IOConnectCallStructMethod(conn, 2, din, 0x28, out, &osz);
          printf("  destroy -> 0x%08x\n", k2); }
        p_IOServiceClose(conn);
    }

    /* no-session reference on a 12th conn */
    printf("\n=== REF no-session sel4 (fresh conn, no create) ===\n");
    {
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr = p_IOServiceOpen(svc, mach_task_self(), 1, &conn);
        if (kr == 0) {
            static const pcase_t ref = { "REF legal", 1920, 1080, 2, 10, 1, 1, 0, 0, 0, 0 };
            fill_cfg(&ref);
            size_t osz;
            kern_return_t k4 = call4(conn, &osz);
            printf("  sel4   -> 0x%08x %s\n", k4, krname(k4));
            dump_out(out, osz, 0x20);
            p_IOServiceClose(conn);
        }
    }

    p_IOObjectRelease(svc);
    return 42;
}
