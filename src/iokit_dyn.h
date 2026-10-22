/*
 * iokit_dyn.h — dlopen-based IOKit bindings (macOS + iOS unified)
 *
 * iOS SDK ships only a partial IOKit header set; macOS and iOS SDKs disagree
 * on kIOMainPortDefault availability. dlopen + dlsym removes every SDK
 * dependency and keeps one source tree building on both targets.
 *
 * Callers must compile as plain arm64 (not arm64e): dlsym-returned function
 * pointers are not ptrauth-signed, so calling them from arm64e code would
 * fail the signed-branch check. The exploit does not need arm64e userspace.
 */

#ifndef IOKIT_DYN_H
#define IOKIT_DYN_H

#include <dlfcn.h>
#include <mach/mach.h>
#include <stdint.h>

typedef mach_port_t io_object_t;
typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
typedef mach_port_t io_registry_entry_t;
typedef mach_port_t io_iterator_t;

/* kIOReturn / kIO constants we rely on (from IOReturn.h, replicated) */
#define IODYN_SUCCESS              0x00000000u
#define IODYN_ERROR                0xbcdefbcdu /* not used for dispatch */
#define IODYNBadArgument           0xe00002c2u
#define IODYNNotAttached           0xe00002d9u
#define IODYNNoDevice              0xe00002bdu
#define IODYNUnsupported           0xe00002c6u
#define IODYNInternal              0xe00002bcu /* also the async-gate reject seen on 905.40.1 */

static void *iodyn_handle;

typedef void         *(*fp_IOServiceMatching)(const char *);
typedef io_service_t  (*fp_IOServiceGetMatchingService)(mach_port_t, void *);
typedef kern_return_t (*fp_IOServiceOpen)(io_service_t, task_t, uint32_t, io_connect_t *);
typedef kern_return_t (*fp_IOServiceClose)(io_connect_t);
typedef kern_return_t (*fp_IOObjectRelease)(io_object_t);
typedef kern_return_t (*fp_IOConnectCallStructMethod)(io_connect_t, uint32_t,
                                                      const void *, size_t,
                                                      void *, size_t *);
typedef kern_return_t (*fp_IOConnectCallAsyncStructMethod)(io_connect_t, uint32_t,
                                                           mach_port_t, uint64_t *,
                                                           uint32_t,
                                                           const void *, size_t,
                                                           void *, size_t *);

static fp_IOServiceMatching              p_IOServiceMatching;
static fp_IOServiceGetMatchingService    p_IOServiceGetMatchingService;
static fp_IOServiceOpen                  p_IOServiceOpen;
static fp_IOServiceClose                 p_IOServiceClose;
static fp_IOObjectRelease                p_IOObjectRelease;
static fp_IOConnectCallStructMethod      p_IOConnectCallStructMethod;
static fp_IOConnectCallAsyncStructMethod p_IOConnectCallAsyncStructMethod;

/* async ref type: io_user_reference_t[8] */
typedef uint64_t iodyn_async_ref_t[8];

static int iodyn_init(void) {
    if (iodyn_handle) return 0;
    iodyn_handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    if (!iodyn_handle) return -1;
    p_IOServiceMatching              = (fp_IOServiceMatching)dlsym(iodyn_handle, "IOServiceMatching");
    p_IOServiceGetMatchingService    = (fp_IOServiceGetMatchingService)dlsym(iodyn_handle, "IOServiceGetMatchingService");
    p_IOServiceOpen                  = (fp_IOServiceOpen)dlsym(iodyn_handle, "IOServiceOpen");
    p_IOServiceClose                 = (fp_IOServiceClose)dlsym(iodyn_handle, "IOServiceClose");
    p_IOObjectRelease                = (fp_IOObjectRelease)dlsym(iodyn_handle, "IOObjectRelease");
    p_IOConnectCallStructMethod      = (fp_IOConnectCallStructMethod)dlsym(iodyn_handle, "IOConnectCallStructMethod");
    p_IOConnectCallAsyncStructMethod = (fp_IOConnectCallAsyncStructMethod)dlsym(iodyn_handle, "IOConnectCallAsyncStructMethod");
    if (!p_IOServiceMatching || !p_IOServiceGetMatchingService || !p_IOServiceOpen ||
        !p_IOServiceClose || !p_IOObjectRelease || !p_IOConnectCallStructMethod ||
        !p_IOConnectCallAsyncStructMethod) {
        return -2;
    }
    return 0;
}

/* main port: on iOS the ONLY working value is 0 (kIOMainPortDefault).
 * mach_host_self() and mach_task_self() both return "none" (verified on
 * iPhone12,1 / 26.0.1, scan v4 evidence). */
#define IODYN_MAIN_PORT 0

#endif /* IOKIT_DYN_H */
