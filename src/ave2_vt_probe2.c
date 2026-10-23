/*
 * ave2_vt_probe2.c v1 - real-client AVE2 sel4/sel5 input capture
 *
 * Why this exists
 * ---------------
 * Our hand-rolled AVE2 client (src/ave2_probe_create.c) can drive
 *   sel1 create (in 0x6f0)   -> KERN_SUCCESS
 *   sel3 async  (in 0x38)    -> KERN_SUCCESS
 *   sel4 configure (in 0x1a0a0) -> KERN_SUCCESS
 * but sel5 (IO_Start) always answers 0xe0000001 (-1015) because the 0x40
 * parameter block at in+0x228 (which carries the LRB parameters at
 * +0x254(flags) +0x25c(B) +0x260(C) +0x264(D) +0x268(E)) is all zero in
 * our synthetic input, and the kext validates those fields strictly.
 * Guessing them breaks sel4 instead.
 *
 * So: let the REAL client walk the chain.  A real hardware H.264 encode
 * (VideoToolbox / AVFoundation) makes Apple's own client code issue the
 * genuine sel4 (configure, 0x1a0a0) and sel5 (UCStart, 0x1a0b0) structures
 * through the IOKit MIG-OOL transport.  We intercept those calls
 * *in-process* with a dyld __interpose table and dump the raw structure
 * input bytes before the real function runs.
 *
 * What it does
 * ------------
 *   1. Interposes IOConnectCallStructMethod, IOConnectCallAsyncStructMethod
 *      and IOConnectCallMethod (dyld __DATA,__interpose).  For every call
 *      the selector, input size, output size and the FULL structure input
 *      are written to /var/root/ave2dump/ with open()/write() (no stdio:
 *      stdio file writes misbehave in this environment), then the genuine
 *      implementation is invoked.
 *   2. Phase "vt": VTCompressionSession (H.264, hardware required) ->
 *      encode up to 30 frames -> complete.  Session creation alone already
 *      makes the real client send its configure structure.
 *   3. Phase "aw": AVAssetWriter + AVAssetWriterInputPixelBufferAdaptor
 *      writing a real 30 frame 640x480 MP4 (the adaptor owns the pixel
 *      buffer pool, so no CVPixelBufferPoolCreatePixelBuffer -6662).
 *   4. Prints the dump file paths plus every selector/size pair, and the
 *      manifest path.
 *
 * Build (workflow mirrors ave2_vt_probe; NOTE the -x objective-c, the file
 * carries Objective-C for AVFoundation):
 *   xcrun clang -O2 -g -arch arm64 -isysroot "$SDK" -x objective-c \
 *     -miphoneos-version-min=15.0 \
 *     src/ave2_vt_probe2.c -o ave2_vt_probe2 \
 *     -framework AVFoundation -framework VideoToolbox -framework CoreMedia \
 *     -framework CoreVideo -framework Foundation -framework IOKit
 *
 * Exit codes: 0 = ran through (>=1 dump written), 1 = ran but nothing was
 * intercepted, 2 = no frame encoded at all.
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

#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <VideoToolbox/VideoToolbox.h>
#import <VideoToolbox/VTCompressionProperties.h>

#define AVE2_DUMP_DIR   "/var/root/ave2dump"
#define AVE2_MANIFEST   AVE2_DUMP_DIR "/manifest.txt"
#define AVE2_OUT_MP4    "/tmp/ave2_vt_probe2.mp4"
#define AVE2_W          640
#define AVE2_H          480
#define AVE2_FRAMES     30

/* ------------------------------------------------------------------ */
/* IOKit interposition                                                 */
/* ------------------------------------------------------------------ */
typedef mach_port_t ave2_conn_t;

typedef kern_return_t (*ave2_fp_struct)(ave2_conn_t, uint32_t, const void *, size_t,
                                        void *, size_t *);
typedef kern_return_t (*ave2_fp_async)(ave2_conn_t, uint32_t, mach_port_t, uint64_t *,
                                       uint32_t, const void *, size_t, void *, size_t *);
typedef kern_return_t (*ave2_fp_method)(ave2_conn_t, uint32_t, const uint64_t *, uint32_t,
                                         const void *, size_t, uint64_t *, uint32_t *,
                                         void *, size_t *);

/* Declared by hand: the iOS SDK ships only a partial IOKit header set and we
 * must not depend on it, but we DO need the symbols at link time so that the
 * __interpose table has a real replacee address. */
extern kern_return_t IOConnectCallStructMethod(ave2_conn_t, uint32_t, const void *,
                                                size_t, void *, size_t *);
extern kern_return_t IOConnectCallAsyncStructMethod(ave2_conn_t, uint32_t, mach_port_t,
                                                    uint64_t *, uint32_t, const void *,
                                                    size_t, void *, size_t *);
extern kern_return_t IOConnectCallMethod(ave2_conn_t, uint32_t, const uint64_t *, uint32_t,
                                          const void *, size_t, uint64_t *, uint32_t *,
                                          void *, size_t *);

static ave2_fp_struct  g_real_struct;
static ave2_fp_async   g_real_async;
static ave2_fp_method  g_real_method;
static char            g_phase[24] = "boot";
static int             g_seq;
static int             g_ndumped;
static int             g_resolved;
static __thread int    g_in_hook;

static void emitf(const char *fmt, ...)
{
    char b[640];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    if (n > 0) {
        ssize_t r = write(1, b, (size_t)n);
        (void)r;
    }
}

/* raw structure input -> file (open/write only, no stdio) */
static void dump_call(const char *kind, uint32_t sel,
                      const void *in, size_t inSize, size_t outSize)
{
    char path[640];
    int n = snprintf(path, sizeof(path),
                     "%s/%s_%s_sel%u_in%zu_out%zu_%03d.bin",
                     AVE2_DUMP_DIR, g_phase, kind, sel, inSize, outSize, ++g_seq);
    if (n <= 0) return;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        emitf("[dump] open(%s) failed errno=%d\n", path, errno);
        return;
    }
    if (in && inSize) {
        const char *p = (const char *)in;
        size_t left = inSize;
        while (left) {
            ssize_t w = write(fd, p, left);
            if (w <= 0) break;
            p += w;
            left -= (size_t)w;
        }
    }
    close(fd);
    g_ndumped++;

    int mfd = open(AVE2_MANIFEST, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (mfd >= 0) {
        char line[768];
        int m = snprintf(line, sizeof(line),
                         "phase=%s kind=%s sel=%u in=%zu out=%zu file=%s\n",
                         g_phase, kind, sel, inSize, outSize, path);
        if (m > 0) {
            ssize_t w = write(mfd, line, (size_t)m);
            (void)w;
        }
        close(mfd);
    }
    emitf("[dump] phase=%s kind=%s sel=%u in=%zu out=%zu file=%s\n",
          g_phase, kind, sel, inSize, outSize, path);
}

static kern_return_t my_IOConnectCallStructMethod(ave2_conn_t c, uint32_t sel,
                                                   const void *in, size_t inSize,
                                                   void *out, size_t *outSize)
{
    dump_call("struct", sel, in, inSize, outSize ? *outSize : (size_t)0);
    if (g_in_hook) return KERN_FAILURE;          /* would recurse: bail out */
    g_in_hook = 1;
    kern_return_t r = g_real_struct ? g_real_struct(c, sel, in, inSize, out, outSize)
                                     : KERN_FAILURE;
    g_in_hook = 0;
    return r;
}

static kern_return_t my_IOConnectCallAsyncStructMethod(ave2_conn_t c, uint32_t sel,
                                                        mach_port_t wake, uint64_t *ref,
                                                        uint32_t refType,
                                                        const void *in, size_t inSize,
                                                        void *out, size_t *outSize)
{
    dump_call("async", sel, in, inSize, outSize ? *outSize : (size_t)0);
    if (g_in_hook) return KERN_FAILURE;
    g_in_hook = 1;
    kern_return_t r = g_real_async ? g_real_async(c, sel, wake, ref, refType,
                                                  in, inSize, out, outSize)
                                   : KERN_FAILURE;
    g_in_hook = 0;
    return r;
}

static kern_return_t my_IOConnectCallMethod(ave2_conn_t c, uint32_t sel,
                                             const uint64_t *in, uint32_t inCount,
                                             const void *inStruct, size_t inStructSize,
                                             uint64_t *out, uint32_t *outCount,
                                             void *outStruct, size_t *outStructSize)
{
    dump_call("method", sel, inStruct, inStructSize,
              outStructSize ? *outStructSize : (size_t)0);
    if (g_in_hook) return KERN_FAILURE;
    g_in_hook = 1;
    kern_return_t r = g_real_method ? g_real_method(c, sel, in, inCount,
                                                    inStruct, inStructSize,
                                                    out, outCount,
                                                    outStruct, outStructSize)
                                    : KERN_FAILURE;
    g_in_hook = 0;
    return r;
}

/* dyld interpose table: {replacement, replacee} */
__attribute__((used)) static struct {
    const void *replacement;
    const void *replacee;
} _interposers[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)my_IOConnectCallStructMethod,       (const void *)IOConnectCallStructMethod },
    { (const void *)my_IOConnectCallAsyncStructMethod,  (const void *)IOConnectCallAsyncStructMethod },
    { (const void *)my_IOConnectCallMethod,             (const void *)IOConnectCallMethod },
};

static void resolve_real(void)
{
    if (g_resolved) return;
    g_resolved = 1;

    void *self_s = (void *)my_IOConnectCallStructMethod;
    void *self_a = (void *)my_IOConnectCallAsyncStructMethod;
    void *self_m = (void *)my_IOConnectCallMethod;

    void *link_s = (void *)IOConnectCallStructMethod;
    void *next_s = dlsym(RTLD_NEXT, "IOConnectCallStructMethod");
    void *lib_s  = NULL;

    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                     RTLD_NOW | RTLD_LOCAL);
    if (h) lib_s = dlsym(h, "IOConnectCallStructMethod");

    if (link_s && link_s != self_s) g_real_struct = (ave2_fp_struct)link_s;
    else if (next_s && next_s != self_s) g_real_struct = (ave2_fp_struct)next_s;
    else if (lib_s && lib_s != self_s) g_real_struct = (ave2_fp_struct)lib_s;

    void *link_a = (void *)IOConnectCallAsyncStructMethod;
    void *next_a = dlsym(RTLD_NEXT, "IOConnectCallAsyncStructMethod");
    void *lib_a  = h ? dlsym(h, "IOConnectCallAsyncStructMethod") : NULL;
    if (link_a && link_a != self_a) g_real_async = (ave2_fp_async)link_a;
    else if (next_a && next_a != self_a) g_real_async = (ave2_fp_async)next_a;
    else if (lib_a && lib_a != self_a) g_real_async = (ave2_fp_async)lib_a;

    void *link_m = (void *)IOConnectCallMethod;
    void *next_m = dlsym(RTLD_NEXT, "IOConnectCallMethod");
    void *lib_m  = h ? dlsym(h, "IOConnectCallMethod") : NULL;
    if (link_m && link_m != self_m) g_real_method = (ave2_fp_method)link_m;
    else if (next_m && next_m != self_m) g_real_method = (ave2_fp_method)next_m;
    else if (lib_m && lib_m != self_m) g_real_method = (ave2_fp_method)lib_m;

    emitf("[interpose] self struct=0x%lx async=0x%lx method=0x%lx\n",
          (unsigned long)self_s, (unsigned long)self_a, (unsigned long)self_m);
    emitf("[interpose] replacee struct=0x%lx async=0x%lx method=0x%lx\n",
          (unsigned long)link_s, (unsigned long)link_a, (unsigned long)link_m);
    emitf("[interpose] RTLD_NEXT struct=0x%lx async=0x%lx method=0x%lx\n",
          (unsigned long)next_s, (unsigned long)next_a, (unsigned long)next_m);
    emitf("[interpose] dlopen   struct=0x%lx async=0x%lx method=0x%lx\n",
          (unsigned long)lib_s, (unsigned long)lib_a, (unsigned long)lib_m);
    emitf("[interpose] resolved struct=%s async=%s method=%s\n",
          g_real_struct ? "yes" : "NO", g_real_async ? "yes" : "NO",
          g_real_method ? "yes" : "NO");
    if (link_s == self_s) {
        emitf("[interpose] WARNING replacee==self: dyld interpose table may be inert\n");
    }
}

__attribute__((constructor)) static void ave2_ctor(void)
{
    mkdir("/var/root", 0755);
    mkdir(AVE2_DUMP_DIR, 0755);
    resolve_real();
    emitf("[interpose] ready, dump dir=%s\n", AVE2_DUMP_DIR);
}

/* ------------------------------------------------------------------ */
/* pixel buffer helpers                                               */
/* ------------------------------------------------------------------ */
static void fill_nv12(CVPixelBufferRef pb, int idx)
{
    if (!pb) return;
    if (CVPixelBufferLockBaseAddress(pb, 0) != kCVReturnSuccess) return;

    uint8_t *y = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    size_t yrow = CVPixelBufferGetBytesPerRowOfPlane(pb, 0);
    size_t yw = CVPixelBufferGetWidthOfPlane(pb, 0);
    size_t yh = CVPixelBufferGetHeightOfPlane(pb, 0);
    if (y) {
        for (size_t r = 0; r < yh; r++) {
            uint8_t *row = y + r * yrow;
            for (size_t c = 0; c < yw; c++)
                row[c] = (uint8_t)((c + r + idx * 7) & 0xff);
        }
    }
    uint8_t *uv = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    if (uv) {
        size_t uvrow = CVPixelBufferGetBytesPerRowOfPlane(pb, 1);
        size_t uvw = CVPixelBufferGetWidthOfPlane(pb, 1);
        size_t uvh = CVPixelBufferGetHeightOfPlane(pb, 1);
        for (size_t r = 0; r < uvh; r++)
            memset(uv + r * uvrow, 128, uvw * 2);
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);
}

static NSDictionary *pb_attributes(int w, int h)
{
    NSNumber *fmt = @(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange);
    NSNumber *nwd = @(w);
    NSNumber *nht = @(h);
    /* NOTE: kCVPixelBufferIOSurfacePropertiesKey must NOT be set here.
     * On this device CVPixelBufferCreate with an empty IOSurface property
     * dict fails with kCVReturnAllocationFailed (-6662); without the key it
     * succeeds (verified in the "diag" phase). */
    return @{
        (__bridge NSString *)kCVPixelBufferPixelFormatTypeKey : fmt,
        (__bridge NSString *)kCVPixelBufferWidthKey : nwd,
        (__bridge NSString *)kCVPixelBufferHeightKey : nht
    };
}

static CVPixelBufferRef make_pixel_buffer(CVPixelBufferPoolRef pool, NSDictionary *attrs)
{
    CVPixelBufferRef pb = NULL;
    if (pool) {
        CVReturn cvr = CVPixelBufferPoolCreatePixelBuffer(NULL, pool, &pb);
        if (cvr == kCVReturnSuccess && pb) return pb;
        emitf("[pb] pool create -> %d\n", (int)cvr);
        pb = NULL;
    }
    CVReturn cvr = CVPixelBufferCreate(NULL, AVE2_W, AVE2_H,
                                       kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                       (__bridge CFDictionaryRef)attrs, &pb);
    if (cvr == kCVReturnSuccess && pb) return pb;
    emitf("[pb] CVPixelBufferCreate -> %d\n", (int)cvr);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* phase 0: environment diagnostics                                   */
/* ------------------------------------------------------------------ */
static void run_diag_phase(void)
{
    @autoreleasepool {
        strcpy(g_phase, "diag");
        emitf("[diag] === environment diagnostics ===\n");

        uint32_t fmts[3] = {
            kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
            kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
            kCVPixelFormatType_32BGRA,
        };
        for (int i = 0; i < 3; i++) {
            NSMutableDictionary *a = [NSMutableDictionary dictionary];
            a[(__bridge NSString *)kCVPixelBufferPixelFormatTypeKey] = @(fmts[i]);
            a[(__bridge NSString *)kCVPixelBufferWidthKey] = @(AVE2_W);
            a[(__bridge NSString *)kCVPixelBufferHeightKey] = @(AVE2_H);

            CVPixelBufferRef pb = NULL;
            CVReturn cvr = CVPixelBufferCreate(NULL, AVE2_W, AVE2_H, fmts[i],
                                               (__bridge CFDictionaryRef)a, &pb);
            emitf("[diag] CVPixelBufferCreate fmt=0x%08x plain           -> %d\n",
                  fmts[i], (int)cvr);
            if (pb) CFRelease(pb);

            pb = NULL;
            a[(__bridge NSString *)kCVPixelBufferIOSurfacePropertiesKey] = @{};
            cvr = CVPixelBufferCreate(NULL, AVE2_W, AVE2_H, fmts[i],
                                      (__bridge CFDictionaryRef)a, &pb);
            emitf("[diag] CVPixelBufferCreate fmt=0x%08x +IOSurfaceProps -> %d\n",
                  fmts[i], (int)cvr);
            if (pb) CFRelease(pb);
        }
    }
}

/* ------------------------------------------------------------------ */
/* phase 1: VTCompressionSession                                      */
/* ------------------------------------------------------------------ */
static void vt_output_cb(void *refCon, void *srcFrameRefCon, OSStatus status,
                         VTEncodeInfoFlags infoFlags, CMSampleBufferRef sb)
{
    (void)refCon; (void)srcFrameRefCon; (void)status; (void)infoFlags; (void)sb;
}

static void run_vt_phase(void)
{
    @autoreleasepool {
        strcpy(g_phase, "vt");
        emitf("[vt] === phase vt: VTCompressionSession %dx%d x%d (hw required) ===\n",
              AVE2_W, AVE2_H, AVE2_FRAMES);

        /* The hardware-acceleration spec keys live behind
         * "#if !TARGET_OS_IPHONE" in VTCompressionProperties.h, so the
         * CFStringRef constant does not exist in the iOS SDK.  The key is a
         * plain string; use the literal so the binary stays linkable. */
        NSDictionary *encSpec = @{ @"RequireHardwareAcceleratedVideoEncoder" : @YES };
        NSDictionary *srcAttrs = pb_attributes(AVE2_W, AVE2_H);

        VTCompressionSessionRef session = NULL;
        OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault,
                                                 AVE2_W, AVE2_H,
                                                 kCMVideoCodecType_H264,
                                                 (__bridge CFDictionaryRef)encSpec,
                                                 (__bridge CFDictionaryRef)srcAttrs,
                                                 NULL, vt_output_cb, NULL, &session);
        emitf("[vt] VTCompressionSessionCreate -> %d\n", (int)st);
        if (st != 0 || !session) {
            emitf("[vt] no session\n");
            return;
        }

        /* "UsingHardwareAcceleratedVideoEncoder" is behind the
         * "#if !TARGET_OS_IPHONE" guard in VTCompressionProperties.h, so
         * query it with the literal key. */
        {
            CFTypeRef hw = NULL;
            VTSessionCopyProperty(session,
                                  CFSTR("UsingHardwareAcceleratedVideoEncoder"),
                                  NULL, (void **)&hw);
            emitf("[vt] UsingHardwareAcceleratedVideoEncoder = %s\n",
                  hw ? (CFBooleanGetValue((CFBooleanRef)hw) ? "YES" : "NO")
                     : "(nil)");
            if (hw) CFRelease(hw);
        }

        CVPixelBufferPoolRef pool = VTCompressionSessionGetPixelBufferPool(session);
        emitf("[vt] session pool = %p\n", (void *)pool);

        int submitted = 0;
        for (int i = 0; i < AVE2_FRAMES; i++) {
            CVPixelBufferRef pb = make_pixel_buffer(pool, srcAttrs);
            if (!pb) {
                emitf("[vt] frame %d: no pixel buffer\n", i);
                continue;
            }
            fill_nv12(pb, i);
            CMTime pts = CMTimeMake(i, 30);
            CMTime dur = CMTimeMake(1, 30);
            VTEncodeInfoFlags info = 0;
            st = VTCompressionSessionEncodeFrame(session, pb, pts, dur, NULL,
                                                 (void *)(intptr_t)i, &info);
            if (st == 0) submitted++;
            else emitf("[vt] frame %d encode -> %d\n", i, (int)st);
            CVPixelBufferRelease(pb);
        }
        emitf("[vt] submitted=%d/%d\n", submitted, AVE2_FRAMES);

        VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        emitf("[vt] phase done\n");
    }
}

/* ------------------------------------------------------------------ */
/* phase 2: AVAssetWriter                                             */
/* ------------------------------------------------------------------ */
static int run_aw_phase(BOOL require_hw)
{
    int rc = 0;
    @autoreleasepool {
        strcpy(g_phase, "aw");
        emitf("[aw] === phase aw: AVAssetWriter %dx%d x%d (hw=%d) ===\n",
              AVE2_W, AVE2_H, AVE2_FRAMES, (int)require_hw);

        NSError *err = nil;
        [[NSFileManager defaultManager] removeItemAtPath:@(AVE2_OUT_MP4) error:NULL];
        NSURL *url = [NSURL fileURLWithPath:@(AVE2_OUT_MP4)];
        AVAssetWriter *writer = [AVAssetWriter assetWriterWithURL:url
                                                        fileType:AVFileTypeMPEG4
                                                           error:&err];
        if (!writer) {
            emitf("[aw] assetWriterWithURL failed: %s\n",
                  [[err description] UTF8String] ?: "?");
            return rc;
        }

        NSMutableDictionary *videoSettings = [NSMutableDictionary dictionary];
        videoSettings[AVVideoCodecKey] = AVVideoCodecTypeH264;
        videoSettings[AVVideoWidthKey] = @(AVE2_W);
        videoSettings[AVVideoHeightKey] = @(AVE2_H);
        videoSettings[AVVideoCompressionPropertiesKey] = @{
            AVVideoAverageBitRateKey: @(800000),
            AVVideoProfileLevelKey: AVVideoProfileLevelH264HighAutoLevel,
        };
        /* NOTE: AVVideoEncoderSpecificationKey is macOS-only (iOS rejects it
         * with NSInvalidArgumentException), so the AVAssetWriter path never
         * sets an encoder spec - on iOS VideoToolbox picks the hardware
         * encoder by itself. */
        (void)require_hw;

        AVAssetWriterInput *input = [AVAssetWriterInput assetWriterInputWithMediaType:AVMediaTypeVideo
                                                                        outputSettings:videoSettings];
        input.expectsMediaDataInRealTime = NO;
        if (![writer canAddInput:input]) {
            emitf("[aw] cannot add input\n");
            return rc;
        }
        [writer addInput:input];

        NSDictionary *attrs = pb_attributes(AVE2_W, AVE2_H);
        AVAssetWriterInputPixelBufferAdaptor *adaptor =
            [AVAssetWriterInputPixelBufferAdaptor assetWriterInputPixelBufferAdaptorWithAssetWriterInput:input
                                                                              sourcePixelBufferAttributes:attrs];
        CVPixelBufferPoolRef pool = adaptor.pixelBufferPool;
        emitf("[aw] adaptor pool = %p\n", (void *)pool);

        if (![writer startWriting]) {
            emitf("[aw] startWriting failed: %s\n",
                  [[[writer error] description] UTF8String]);
            return rc;
        }
        [writer startSessionAtSourceTime:kCMTimeZero];

        int appended = 0;
        for (int i = 0; i < AVE2_FRAMES; i++) {
            int spins = 0;
            while (!input.isReadyForMoreMediaData && spins < 5000) {
                usleep(1000);
                spins++;
            }
            CVPixelBufferRef pb = make_pixel_buffer(pool, attrs);
            if (!pb) {
                emitf("[aw] frame %d: no pixel buffer\n", i);
                continue;
            }
            fill_nv12(pb, i);
            CMTime pts = CMTimeMake(i, 30);
            BOOL ok = [adaptor appendPixelBuffer:pb withPresentationTime:pts];
            if (ok) appended++;
            else emitf("[aw] frame %d append failed: %s\n", i,
                       [[[writer error] description] UTF8String]);
            CVPixelBufferRelease(pb);
        }
        emitf("[aw] appended=%d/%d\n", appended, AVE2_FRAMES);
        [input markAsFinished];

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [writer finishWritingWithCompletionHandler:^{ dispatch_semaphore_signal(sem); }];
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 30ull * NSEC_PER_SEC));

        emitf("[aw] writer status=%ld error=%s\n", (long)writer.status,
              [[[writer error] description] UTF8String] ?: "(none)");
        if (writer.status == AVAssetWriterStatusCompleted) rc = 1;
    }
    return rc;
}

/* ------------------------------------------------------------------ */
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    mkdir(AVE2_DUMP_DIR, 0755);
    resolve_real();

    emitf("[probe] ave2_vt_probe2 start (pid=%d)\n", (int)getpid());
    emitf("[probe] dump dir   = %s\n", AVE2_DUMP_DIR);
    emitf("[probe] manifest   = %s\n", AVE2_MANIFEST);

    run_diag_phase();
    run_vt_phase();

    int aw_hw = run_aw_phase(YES);
    if (!aw_hw) {
        emitf("[aw] retrying without hardware requirement\n");
        run_aw_phase(NO);
    }

    emitf("[probe] dumps written = %d\n", g_ndumped);
    emitf("[probe] manifest: %s\n", AVE2_MANIFEST);

    /* list what we produced */
    {
        int fd = open(AVE2_MANIFEST, O_RDONLY);
        if (fd >= 0) {
            char buf[8192];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = 0;
                emitf("[probe] ---- manifest ----\n%s", buf);
            }
            close(fd);
        } else {
            emitf("[probe] no manifest (nothing intercepted)\n");
        }
    }

    emitf("[probe] end\n");
    return g_ndumped > 0 ? 0 : 1;
}
