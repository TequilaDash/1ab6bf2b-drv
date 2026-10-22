/*
 * ave2_scan.c v4 — diagnose WHY matching fails under rootless jb
 *
 * v3 showed even IOMobileFramebuffer (always resident) returns none =>
 * IOServiceMatching/GetMatchingService is broken in this context, not AVE2.
 *
 * v4 tests alternate discovery paths:
 *   1. IOServiceCopyMatchingServices  (plural variant, different trap path)
 *   2. IORegistryEntryFromPath        (direct path lookup, bypasses matching)
 *   3. IOServiceGetMatchingService with mach_host_self vs 0 master port
 *   4. notifications port (IOServiceAddMatchingNotification needs CF — skip)
 *
 * Path 2 is the key: /IODeviceTree and /IOService registry paths are stable.
 * AVE2 lives somewhere under /arm-io/ on Apple platforms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>

#include "iokit_dyn.h"

typedef kern_return_t (*fp_IOServiceCopyMatchingServices)(void *, mach_port_t *, uint32_t *);
typedef io_registry_entry_t (*fp_IORegistryEntryFromPath)(mach_port_t, const io_string_t);
typedef kern_return_t (*fp_IORegistryEntryGetPath)(io_registry_entry_t, const char *, io_string_t);
typedef kern_return_t (*fp_IOIteratorNextV)(mach_port_t, io_object_t *);

static fp_IOServiceCopyMatchingServices  p_CopyMatching;
static fp_IORegistryEntryFromPath        p_EntryFromPath;
static fp_IORegistryEntryGetPath         p_EntryGetPath;
static fp_IOIteratorNextV                p_IterNextV;

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    if (iodyn_init() != 0) { printf("[-] iodyn failed\n"); return 3; }

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    p_CopyMatching = (fp_IOServiceCopyMatchingServices)dlsym(h, "IOServiceCopyMatchingServices");
    p_EntryFromPath = (fp_IORegistryEntryFromPath)dlsym(h, "IORegistryEntryFromPath");
    p_EntryGetPath  = (fp_IORegistryEntryGetPath)dlsym(h, "IORegistryEntryGetPath");
    p_IterNextV     = (fp_IOIteratorNextV)dlsym(h, "IOIteratorNext");
    printf("dlsym: copy=%p frompath=%p getpath=%p\n",
           (void*)p_CopyMatching, (void*)p_EntryFromPath, (void*)p_EntryGetPath);

    /* --- test 1: plural matching on a control service --- */
    printf("\n=== IOServiceCopyMatchingServices (control: IOMobileFramebuffer) ===\n");
    if (p_CopyMatching) {
        void *m = p_IOServiceMatching("IOMobileFramebuffer");
        printf("  matching dict: %p\n", m);
        if (m) {
            mach_port_t iter = MACH_PORT_NULL;
            uint32_t cnt = 0;
            kern_return_t kr = p_CopyMatching(m, &iter, &cnt);
            printf("  copy: 0x%x count=%u\n", kr, cnt);
            if (kr == KERN_SUCCESS && iter) {
                io_object_t obj;
                kern_return_t ik = p_IterNextV(iter, &obj);
                if (ik == KERN_SUCCESS && obj) {
                    printf("  copy first-hit: 0x%x
", obj);
                    p_IOObjectRelease(obj);
                }
            }
        }
    }

    /* --- test 2: registry path lookup (bypasses matching entirely) --- */
    printf("\n=== IORegistryEntryFromPath probes ===\n");
    if (p_EntryFromPath) {
        const char *paths[] = {
            "IOService:/",
            "IODeviceTree:/",
            "IOService:/AppleAVE2Driver",
            "IOService:/arm-io/AppleAVE2Driver",
            "IODeviceTree:/arm-io",
            "IOService:/arm-io",
            NULL,
        };
        for (int i = 0; paths[i]; i++) {
            io_registry_entry_t e = p_EntryFromPath(IODYN_MAIN_PORT, paths[i]);
            printf("  %-36s : %s (0x%x)\n", paths[i], e ? "FOUND" : "none", e);
            if (e) {
                if (p_EntryGetPath) {
                    char buf[512] = {0};
                    kern_return_t kr = p_EntryGetPath(e, "IOService", buf);
                    if (kr == KERN_SUCCESS) printf("    path: %s\n", buf);
                }
                p_IOObjectRelease(e);
            }
        }
    }

    /* --- test 3: master port variants on matching --- */
    printf("\n=== matching with different master ports ===\n");
    {
        void *m = p_IOServiceMatching("IOMobileFramebuffer");
        if (m) {
            io_service_t s1 = p_IOServiceGetMatchingService(mach_host_self(), m);
            printf("  host_self : %s\n", s1 ? "FOUND" : "none");
            if (s1) p_IOObjectRelease(s1);
        }
        m = p_IOServiceMatching("IOMobileFramebuffer");
        if (m) {
            io_service_t s2 = p_IOServiceGetMatchingService(0, m);
            printf("  port 0    : %s\n", s2 ? "FOUND" : "none");
            if (s2) p_IOObjectRelease(s2);
        }
        m = p_IOServiceMatching("IOMobileFramebuffer");
        if (m) {
            io_service_t s3 = p_IOServiceGetMatchingService(mach_task_self(), m);
            printf("  task_self : %s\n", s3 ? "FOUND" : "none");
            if (s3) p_IOObjectRelease(s3);
        }
    }

    return 0;
}
