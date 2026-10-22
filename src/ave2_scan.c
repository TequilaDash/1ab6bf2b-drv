/*
 * ave2_scan.c — enumerate IORegistry planes for AVE-related services (iOS)
 *
 * Built to answer one question on-device: what is the actual AppleAVE2
 * service / user-client name on iOS 26.0.1, so the exploit can match it.
 * macOS uses "AppleAVE2Driver"; iOS may differ.
 *
 * Build: see Makefile target 'scan'. Run as root on device.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>

#include "iokit_dyn.h"

/* dlsym the registry iteration APIs we need */
typedef kern_return_t (*fp_IORegistryCreateIterator)(mach_port_t, const char *, uint32_t, mach_port_t *);
typedef kern_return_t (*fp_IOIteratorNext)(mach_port_t, io_object_t *);
typedef kern_return_t (*fp_IORegistryEntryGetName)(io_object_t, char *);
typedef kern_return_t (*fp_IOObjectConformsTo)(io_object_t, const char *);
typedef mach_port_t   (*fp_IORegistryGetRootEntry)(mach_port_t);
typedef kern_return_t (*fp_IORegistryEntryGetChildIterator)(io_object_t, const char *, mach_port_t *);

static fp_IORegistryCreateIterator        p_CreateIterator;
static fp_IOIteratorNext                  p_IterNext;
static fp_IORegistryEntryGetName          p_GetName;
static fp_IOObjectConformsTo              p_ConformsTo;

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    if (iodyn_init() != 0) { printf("[-] iodyn failed\n"); return 3; }

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    p_CreateIterator = (fp_IORegistryCreateIterator)dlsym(h, "IORegistryCreateIterator");
    p_IterNext       = (fp_IOIteratorNext)dlsym(h, "IOIteratorNext");
    p_GetName        = (fp_IORegistryEntryGetName)dlsym(h, "IORegistryEntryGetName");
    p_ConformsTo     = (fp_IOObjectConformsTo)dlsym(h, "IOObjectConformsTo");
    if (!p_CreateIterator || !p_IterNext || !p_GetName || !p_ConformsTo) {
        printf("[-] dlsym registry APIs failed\n");
        return 4;
    }

    mach_port_t iter = MACH_PORT_NULL;
    kern_return_t kr = p_CreateIterator(IODYN_MAIN_PORT, "IOService", 0, &iter);
    if (kr != KERN_SUCCESS) {
        printf("[-] IORegistryCreateIterator: 0x%x\n", kr);
        return 1;
    }

    int hits = 0, total = 0;
    io_object_t obj;
    while ((kr = p_IterNext(iter, &obj)) == KERN_SUCCESS && obj != MACH_PORT_NULL) {
        char name[128] = {0};
        p_GetName(obj, name);
        total++;
        if (strstr(name, "AVE") || strstr(name, "ave") ||
            strstr(name, "Codec") || strstr(name, "encoder") ||
            strstr(name, "Encoder")) {
            printf("HIT: %s\n", name);
            hits++;
        }
        p_IOObjectRelease(obj);
        if (total > 20000) break; /* safety cap */
    }
    printf("\n=== scanned %d services, %d AVE/encoder hits ===\n", total, hits);

    /* direct matching probes */
    const char *cands[] = {
        "AppleAVE2Driver", "AppleAVE2", "AppleAVE", "AppleAVE3Driver",
        "AppleAVE2UserClient", "AppleAVE2V2Driver", NULL
    };
    printf("\n=== direct matching probes ===\n");
    for (int i = 0; cands[i]; i++) {
        void *m = p_IOServiceMatching(cands[i]);
        if (!m) { printf("  %-22s : matching==NULL\n", cands[i]); continue; }
        io_service_t s = p_IOServiceGetMatchingService(IODYN_MAIN_PORT, m);
        printf("  %-22s : %s (0x%x)\n", cands[i], s ? "FOUND" : "none", s);
        if (s) p_IOObjectRelease(s);
    }
    return 0;
}
