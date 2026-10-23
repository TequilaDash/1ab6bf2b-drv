/*
 * ave2_iokit_hook.c v1 - in-process IOKit hook dylib for the REAL AVE2 client
 *
 * The genuine Apple hardware-encoder client does NOT run in our process: on
 * iOS the VideoToolbox/AVFoundation encode path is
 *
 *   our process (VideoToolbox) --XPC--> com.apple.videocodecd --IOConnect-->
 *   AppleAVE2Driver (kernel)
 *
 * (verified on the device: "com.apple.videocodecd" is spawned the moment our
 * encoder session is created, and our in-process interpose sees zero
 * IOConnect traffic, while the driver session is really opened.)
 *
 * This dylib is therefore injected INTO videocodecd:
 *
 *   launchctl setenv DYLD_INSERT_LIBRARIES /var/root/ave2_iokit_hook.dylib
 *   killall videocodecd        # launchd respawns it with the hook
 *
 * It interposes IOConnectCallStructMethod / IOConnectCallAsyncStructMethod /
 * IOConnectCallMethod through the dyld __DATA,__interpose table and writes
 * the RAW structure input of every call to /var/mobile/ave2dump/ so the
 * genuine sel4 (configure, 0x1a0a0) and sel5 (UCStart, 0x1a0b0) inputs can
 * be recovered byte for byte.
 *
 * Everything is done with open()/write() (no stdio) and a plain log file, so
 * it works inside a daemon with no controlling terminal.
 *
 * Build:
 *   xcrun clang -O2 -g -arch arm64 -isysroot "$SDK" -dynamiclib \
 *     -miphoneos-version-min=15.0 src/ave2_iokit_hook.c -o ave2_iokit_hook \
 *     -framework IOKit
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/stat.h>
#include <mach/mach.h>

#define HOOK_DUMP_DIR  "/var/mobile/ave2dump"
#define HOOK_LOG_FILE  HOOK_DUMP_DIR "/hook.log"

typedef mach_port_t hook_conn_t;

typedef kern_return_t (*hook_fp_struct)(hook_conn_t, uint32_t, const void *, size_t,
                                        void *, size_t *);
typedef kern_return_t (*hook_fp_async)(hook_conn_t, uint32_t, mach_port_t, uint64_t *,
                                       uint32_t, const void *, size_t, void *, size_t *);
typedef kern_return_t (*hook_fp_method)(hook_conn_t, uint32_t, const uint64_t *, uint32_t,
                                         const void *, size_t, uint64_t *, uint32_t *,
                                         void *, size_t *);

extern kern_return_t IOConnectCallStructMethod(hook_conn_t, uint32_t, const void *,
                                                size_t, void *, size_t *);
extern kern_return_t IOConnectCallAsyncStructMethod(hook_conn_t, uint32_t, mach_port_t,
                                                    uint64_t *, uint32_t, const void *,
                                                    size_t, void *, size_t *);
extern kern_return_t IOConnectCallMethod(hook_conn_t, uint32_t, const uint64_t *, uint32_t,
                                          const void *, size_t, uint64_t *, uint32_t *,
                                          void *, size_t *);

static hook_fp_struct  g_real_struct;
static hook_fp_async   g_real_async;
static hook_fp_method  g_real_method;
static int             g_seq;
static int             g_ready;
static __thread int    g_in_hook;

static void hlog(const char *fmt, ...)
{
    char b[768];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    int fd = open(HOOK_LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    ssize_t w = write(fd, b, (size_t)n);
    (void)w;
    close(fd);
}

static void hdump(const char *kind, uint32_t sel, const void *in, size_t inSize,
                  size_t outSize)
{
    if (!g_ready) return;
    if (!in || inSize == 0) {
        hlog("[hook] %s sel=%u in=%zu out=%zu (no input)\n", kind, sel, inSize, outSize);
        return;
    }
    char path[640];
    int n = snprintf(path, sizeof(path),
                     HOOK_DUMP_DIR "/%s_%s_sel%u_in%zu_out%zu_%03d.bin",
                     kind, kind, sel, inSize, outSize, ++g_seq);
    if (n <= 0) return;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        hlog("[hook] open(%s) failed errno=%d\n", path, errno);
        return;
    }
    const char *p = (const char *)in;
    size_t left = inSize;
    while (left) {
        ssize_t w = write(fd, p, left);
        if (w <= 0) break;
        p += w;
        left -= (size_t)w;
    }
    close(fd);
    hlog("[hook] dumped %s\n", path);
}

static kern_return_t my_IOConnectCallStructMethod(hook_conn_t c, uint32_t sel,
                                                   const void *in, size_t inSize,
                                                   void *out, size_t *outSize)
{
    hdump("struct", sel, in, inSize, outSize ? *outSize : (size_t)0);
    if (g_in_hook || !g_real_struct) return KERN_FAILURE;
    g_in_hook = 1;
    kern_return_t r = g_real_struct(c, sel, in, inSize, out, outSize);
    g_in_hook = 0;
    return r;
}

static kern_return_t my_IOConnectCallAsyncStructMethod(hook_conn_t c, uint32_t sel,
                                                        mach_port_t wake, uint64_t *ref,
                                                        uint32_t refType,
                                                        const void *in, size_t inSize,
                                                        void *out, size_t *outSize)
{
    hdump("async", sel, in, inSize, outSize ? *outSize : (size_t)0);
    if (g_in_hook || !g_real_async) return KERN_FAILURE;
    g_in_hook = 1;
    kern_return_t r = g_real_async(c, sel, wake, ref, refType, in, inSize, out, outSize);
    g_in_hook = 0;
    return r;
}

static kern_return_t my_IOConnectCallMethod(hook_conn_t c, uint32_t sel,
                                             const uint64_t *in, uint32_t inCount,
                                             const void *inStruct, size_t inStructSize,
                                             uint64_t *out, uint32_t *outCount,
                                             void *outStruct, size_t *outStructSize)
{
    hdump("method", sel, inStruct, inStructSize,
          outStructSize ? *outStructSize : (size_t)0);
    if (g_in_hook || !g_real_method) return KERN_FAILURE;
    g_in_hook = 1;
    kern_return_t r = g_real_method(c, sel, in, inCount, inStruct, inStructSize,
                                    out, outCount, outStruct, outStructSize);
    g_in_hook = 0;
    return r;
}

__attribute__((used)) static struct {
    const void *replacement;
    const void *replacee;
} _interposers[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)my_IOConnectCallStructMethod,      (const void *)IOConnectCallStructMethod },
    { (const void *)my_IOConnectCallAsyncStructMethod, (const void *)IOConnectCallAsyncStructMethod },
    { (const void *)my_IOConnectCallMethod,            (const void *)IOConnectCallMethod },
};

__attribute__((constructor)) static void hook_ctor(void)
{
    mkdir(HOOK_DUMP_DIR, 0755);

    void *self_s = (void *)my_IOConnectCallStructMethod;
    void *self_a = (void *)my_IOConnectCallAsyncStructMethod;
    void *self_m = (void *)my_IOConnectCallMethod;

    void *link_s = (void *)IOConnectCallStructMethod;
    void *next_s = dlsym(RTLD_NEXT, "IOConnectCallStructMethod");
    void *lib_s = NULL;
    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                     RTLD_NOW | RTLD_LOCAL);
    if (h) lib_s = dlsym(h, "IOConnectCallStructMethod");

    if (link_s && link_s != self_s) g_real_struct = (hook_fp_struct)link_s;
    else if (next_s && next_s != self_s) g_real_struct = (hook_fp_struct)next_s;
    else if (lib_s && lib_s != self_s) g_real_struct = (hook_fp_struct)lib_s;

    void *link_a = (void *)IOConnectCallAsyncStructMethod;
    void *next_a = dlsym(RTLD_NEXT, "IOConnectCallAsyncStructMethod");
    void *lib_a = h ? dlsym(h, "IOConnectCallAsyncStructMethod") : NULL;
    if (link_a && link_a != self_a) g_real_async = (hook_fp_async)link_a;
    else if (next_a && next_a != self_a) g_real_async = (hook_fp_async)next_a;
    else if (lib_a && lib_a != self_a) g_real_async = (hook_fp_async)lib_a;

    void *link_m = (void *)IOConnectCallMethod;
    void *next_m = dlsym(RTLD_NEXT, "IOConnectCallMethod");
    void *lib_m = h ? dlsym(h, "IOConnectCallMethod") : NULL;
    if (link_m && link_m != self_m) g_real_method = (hook_fp_method)link_m;
    else if (next_m && next_m != self_m) g_real_method = (hook_fp_method)next_m;
    else if (lib_m && lib_m != self_m) g_real_method = (hook_fp_method)lib_m;

    g_ready = 1;
    hlog("[hook] loaded pid=%d struct=%p async=%p method=%p "
         "(link=%p next=%p lib=%p)\n",
         (int)getpid(), (void *)g_real_struct, (void *)g_real_async, (void *)g_real_method,
         link_s, next_s, lib_s);
}
