/*
 * ave2_poll.c — poll sel1 create continuously; exit when it succeeds
 *
 * Rationale: AppleAVE2 on iOS is lazily instantiated — the registry
 * personality answers matching + open, but the UC methods return c2
 * (untouched out) until the driver actually starts, which happens on the
 * first HW-encode session (camera record / video playback).
 * Run this in background, record a video, watch it flip.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>
#include <unistd.h>
#include <time.h>

#include "iokit_dyn.h"
#include "ave2_wire.h"

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    if (iodyn_init() != 0) { printf("[-] iodyn\n"); return 3; }

    void *m = p_IOServiceMatching("AppleAVE2Driver");
    io_service_t svc = p_IOServiceGetMatchingService(IODYN_MAIN_PORT, m);
    if (!svc) { printf("[-] no service\n"); return 1; }
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = p_IOServiceOpen(svc, mach_task_self(), 1, &conn);
    if (kr != KERN_SUCCESS) { printf("[-] open: 0x%x\n", kr); return 2; }
    printf("[+] opened 0x%x — polling sel1 create every 1s (record a video now!)\n", conn);

    static uint8_t in[0x920];
    memset(in, 0, sizeof(in));
    memcpy(in + AVE2_CREATE_OFF_VERSION, "904.76.7", 8);
    *(int32_t *)(in + AVE2_CREATE_OFF_ENCTYPE) = 1;
    *(int32_t *)(in + 0x910) = 1;
    *(int32_t *)(in + 0x914) = 1;

    uint8_t out[0x100];
    uint64_t idx = 0x7000000000000000ULL;

    for (int iter = 0; iter < 3600; iter++) {
        *(uint64_t *)(in + 0x808) = ++idx;
        size_t osz = sizeof(out);
        memset(out, 0, sizeof(out));
        kern_return_t k = p_IOConnectCallStructMethod(conn, 1, in, 0x920, out, &osz);
        int touched = 0;
        for (size_t q = 0; q < osz; q++) if (out[q]) { touched = 1; break; }

        if (iter % 10 == 0)
            printf("[%4d] trap=0x%08x touched=%d\n", iter, k, touched);

        if (k == KERN_SUCCESS || touched) {
            printf("\n[!!!] FLIP at iter %d: trap=0x%08x\n", iter, k);
            printf("  out: ");
            for (size_t q = 0; q < osz && q < 0x28; q++) printf("%02x", out[q]);
            printf("\n");
            if (osz >= 0x28) {
                printf("  cookie=0x%016llx id=0x%016llx status=0x%08x\n",
                       (unsigned long long)*(uint64_t *)(out + 0x00),
                       (unsigned long long)*(uint64_t *)(out + 0x20),
                       (unsigned long long)*(uint32_t *)(out + 0x18));
            }
            p_IOServiceClose(conn);
            p_IOObjectRelease(svc);
            return 0;
        }
        sleep(1);
    }
    printf("[-] no flip in 3600s\n");
    p_IOServiceClose(conn);
    p_IOObjectRelease(svc);
    return 1;
}
