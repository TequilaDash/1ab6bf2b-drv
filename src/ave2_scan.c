/*
 * ave2_scan.c — probe IOKit service matching for AVE candidates (iOS)
 *
 * IORegistryCreateIterator returns kIOReturnNotPrivileged (0xe00002c1) on
 * iOS even with our entitlement set, but IOServiceMatching +
 * IOServiceGetMatchingService works (the exploit reached it and got a clean
 * "not found"). So: probe a wide candidate list via matching only.
 *
 * v2 also tries opening each found service with several client types to
 * fingerprint which one exposes the AVE2UserClient external-method table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>

#include "iokit_dyn.h"

static const char *cands[] = {
    /* exact names used across iOS/macOS versions */
    "AppleAVE2Driver",
    "AppleAVE2",
    "AppleAVE",
    "AppleAVE3Driver",
    "AppleAVE2V2Driver",
    "AppleAVE2DriverV2",
    "AppleAVE2UserClient",
    "AppleAVE2V1Driver",
    /* generic encoder candidates */
    "AppleH16AVE",
    "AppleAVE2_h16",
    "com.apple.DriverKit.AppleAVE2",
    NULL,
};

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    if (iodyn_init() != 0) { printf("[-] iodyn failed\n"); return 3; }

    printf("=== AVE service matching probes ===\n");
    io_service_t found = MACH_PORT_NULL;
    const char *found_name = NULL;

    for (int i = 0; cands[i]; i++) {
        void *m = p_IOServiceMatching(cands[i]);
        if (!m) {
            printf("  %-38s : matching=NULL\n", cands[i]);
            continue;
        }
        io_service_t s = p_IOServiceGetMatchingService(IODYN_MAIN_PORT, m);
        printf("  %-38s : %s\n", cands[i], s ? "FOUND" : "none");
        if (s && !found) { found = s; found_name = cands[i]; }
        else if (s) p_IOObjectRelease(s);
    }

    if (!found) {
        printf("\n[-] no AVE service found via matching — kext may be load-on-demand\n");
        printf("    (AppleAVE2 loads when first encoder client opens; try Video app)\n");
        return 1;
    }

    printf("\n=== open probes on %s ===\n", found_name);
    for (uint32_t type = 0; type <= 5; type++) {
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr = p_IOServiceOpen(found, mach_task_self(), type, &conn);
        if (kr == KERN_SUCCESS) {
            printf("  type=%u OPENED conn=0x%x — probe sel0 shape\n", type, conn);
            /* probe selector 0 with a tiny struct: shape of the error tells us
             * whether an external method table exists */
            uint8_t ob[0x20]; size_t osz = sizeof(ob);
            uint8_t ib[0x10]; memset(ib, 0, sizeof(ib));
            kern_return_t kr2 = p_IOConnectCallStructMethod(conn, 0, ib, sizeof(ib), ob, &osz);
            printf("    sel0 struct probe: 0x%x (0x%x=Unsupported means empty table)\n",
                   kr2, IODYNUnsupported);
            p_IOServiceClose(conn);
        } else {
            printf("  type=%u open: 0x%x\n", type, kr);
        }
    }
    p_IOObjectRelease(found);
    return 0;
}
