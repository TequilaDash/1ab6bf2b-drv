/*
 * ave2_vt_probe.c v1 - VTCompressionSession real-encode control probe
 *
 * Purpose: on-device control experiment for the AVE2 map/wall work
 * (journal 2026-10-22/23). Apple's own client path is
 * MediaToolbox -> videocodecd (XPC) -> AppleAVE2Driver over the SAME
 * MIG OOL struct transport we drive by hand in ave2_probe_create.c.
 * This probe drives the PUBLIC API instead (VTCompressionSession,
 * H264, hardware encoder hard-required), lets a real encode run,
 * then dumps the unified log for AVE/videocodecd/mediatoolbox events
 * so the two paths can be compared (wire budget, descriptor flags,
 * entitlements, session lifecycle).
 *
 * Sequence:
 *   1. VTCompressionSessionCreate  H264 1280x720,
 *      RequireHardwareAcceleratedVideoEncoder = true.
 *      Every VTStatus printed on its own line.
 *   2. 30 gradient frames from the session CVPixelBufferPool (420v),
 *      submitted one by one via VTCompressionSessionEncodeFrame;
 *      per-frame OSStatus + infoFlags printed.
 *   3. Session kept alive 10 s: stderr prints "VT_SESSION_ALIVE i/10"
 *      once per second. (Alive window runs BEFORE Complete/End: the
 *      session must be alive while VT_SESSION_ALIVE prints, and the
 *      mid-stream output callbacks fire during the hold.)
 *   4. VTCompressionSessionCompleteFrames + End, then callback stats.
 *   5. system("log show --last 3m --style compact --predicate
 *      'eventMessage CONTAINS[c] \"AVE\" OR process == \"videocodecd\"
 *      OR process CONTAINS[c] \"mediatoolbox\"' > /var/root/vt_log.txt
 *      2>&1") and print the first 100 lines of vt_log.txt. Runs even
 *      if earlier steps failed (baseline log is still evidence).
 *
 * Build (workflow mirrors ave2_probe_create):
 *   xcrun clang -O2 -g -arch arm64 -isysroot "$SDK" \
 *     -miphoneos-version-min=14.0 src/ave2_vt_probe.c -o ave2_vt_probe \
 *     -framework VideoToolbox -framework CoreMedia \
 *     -framework CoreVideo -framework Foundation
 *
 * Exit codes: 42 = ran through (create ok, >=1 frame submitted,
 * complete+end issued; callback count in stdout). 2 = create failed,
 * 3 = no pixel buffers obtainable, 4 = all submissions failed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <VideoToolbox/VideoToolbox.h>
#include <dlfcn.h>
#include <CoreMedia/CoreMedia.h>
#include <CoreVideo/CoreVideo.h>

#define VT_W          1280
#define VT_H          720
#define VT_FRAMES     30
#define VT_ALIVE_SECS 10
#define VT_LOG_PATH   "/var/root/vt_log.txt"

static const char *kLogShowCmd =
    "log show --last 3m --style compact "
    "--predicate 'eventMessage CONTAINS[c] \"AVE\" OR "
    "process == \"videocodecd\" OR "
    "process CONTAINS[c] \"mediatoolbox\"' "
    "> " VT_LOG_PATH " 2>&1";

/* output-callback bookkeeping (invoked on the session's internal queue) */
static volatile uint32_t g_cb_fired       = 0;
static volatile int32_t  g_cb_last_status = 0;
static volatile uint32_t g_cb_sample_null = 0;

static void vt_output_cb(void *refCon, void *sourceFrameRefCon,
                         OSStatus status, VTEncodeInfoFlags infoFlags,
                         CMSampleBufferRef sampleBuffer)
{
    long idx = (long)(intptr_t)sourceFrameRefCon;
    g_cb_fired++;
    g_cb_last_status = (int32_t)status;
    if (!sampleBuffer) g_cb_sample_null++;
    fprintf(stderr, "[cb] frame=%ld status=%d(0x%08x) info=0x%x sample=%p\n",
            idx, (int)status, (unsigned)status, (unsigned)infoFlags,
            (void *)sampleBuffer);
    (void)refCon;
}

/* fill a 420v buffer: Y = moving diagonal gradient, UV = neutral 128 */
static void fill_gradient_420v(CVPixelBufferRef pb, long idx)
{
    if (CVPixelBufferLockBaseAddress(pb, 0) != kCVReturnSuccess) return;

    uint8_t *ybase = CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    size_t   yrow  = CVPixelBufferGetBytesPerRowOfPlane(pb, 0);
    size_t   yw    = CVPixelBufferGetWidthOfPlane(pb, 0);
    size_t   yh    = CVPixelBufferGetHeightOfPlane(pb, 0);
    if (ybase) {
        for (size_t y = 0; y < yh; y++) {
            uint8_t *row = ybase + y * yrow;
            for (size_t x = 0; x < yw; x++)
                row[x] = (uint8_t)((x + y + idx * 8) & 0xff);
        }
    }

    uint8_t *uvbase = CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    size_t   uvrow  = CVPixelBufferGetBytesPerRowOfPlane(pb, 1);
    size_t   uvw    = CVPixelBufferGetWidthOfPlane(pb, 1);
    size_t   uvh    = CVPixelBufferGetHeightOfPlane(pb, 1);
    if (uvbase) {
        for (size_t y = 0; y < uvh; y++) {
            uint8_t *row = uvbase + y * uvrow;
            for (size_t x = 0; x < uvw * 2; x++) row[x] = 128;
        }
    }

    CVPixelBufferUnlockBaseAddress(pb, 0);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    int submitted_ok = 0;
    int created = 0;
    int ended = 0;
    int rc_final = 42;

    { const char *dl = getenv("AVE2_VT_DELAY");
      if (dl) { int sec = atoi(dl); if (sec > 0) { printf("[vt] delay %d s\n", sec); fflush(stdout); sleep(sec); } } }
    printf("[vt] === ave2_vt_probe v1: %dx%d, %d frames ===\n",
           VT_W, VT_H, VT_FRAMES);

    /* ---- encoder specification: hardware only ---- */
    CFMutableDictionaryRef enc_spec = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 2,
        &kCFCopyStringDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(enc_spec,
        kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder,
        kCFBooleanTrue);
    printf("[vt] spec: %s = true\n",
        CFStringGetCStringPtr(
            kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder,
            kCFStringEncodingUTF8)
            ? CFStringGetCStringPtr(
                  kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder,
                  kCFStringEncodingUTF8)
            : "(unprintable key)");

    /* ---- source pixel buffer attributes: 420v + IOSurface ---- */
    int w = VT_W, h = VT_H;
    const char *mode = getenv("AVE2_VT_CODEC"); if (!mode) mode = "h264";
    int VT_W2 = getenv("AVE2_VT_W") ? atoi(getenv("AVE2_VT_W")) : VT_W;
    int VT_H2 = getenv("AVE2_VT_H") ? atoi(getenv("AVE2_VT_H")) : VT_H;
    w = VT_W2; h = VT_H2;

    int hevc = (strstr(mode, "hevc") != NULL);
    int multipass = (strstr(mode, "mp") != NULL);
    uint32_t fmt = hevc ? kCVPixelFormatType_420YpCbCr10BiPlanarVideoRange : kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange;
    CFNumberRef fmtnum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &fmt);
    CFNumberRef wnum   = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &w);
    CFNumberRef hnum   = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &h);
    CFMutableDictionaryRef iosurf = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, NULL, NULL);
    const void *skeys[] = {
        kCVPixelBufferPixelFormatTypeKey, kCVPixelBufferWidthKey,
        kCVPixelBufferHeightKey,          kCVPixelBufferIOSurfacePropertiesKey
    };
    const void *svals[] = { fmtnum, wnum, hnum, iosurf };
    CFDictionaryRef src_attrs = CFDictionaryCreate(
        kCFAllocatorDefault, skeys, svals, 4,
        &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(fmtnum); CFRelease(wnum); CFRelease(hnum); CFRelease(iosurf);

    /* ---- 1) create ---- */
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, VT_W2, VT_H2, hevc ? kCMVideoCodecType_HEVC : kCMVideoCodecType_H264,
        enc_spec, src_attrs, NULL, vt_output_cb, NULL, &session);
    printf("[vt] VTCompressionSessionCreate -> %d (%s)\n",
           (int)st, st == 0 ? "noErr" : "FAIL");
    if (st != 0 || !session) {
        rc_final = 2;
        goto run_log; /* log show still runs: baseline evidence */
    }
    created = 1;
    if (hevc) {
        CFStringRef pl = kVTProfileLevel_HEVC_Main10_AutoLevel;
        if (multipass) {
            VTSessionSetProperty(session, CFSTR("EnableMultiPassEncoding"), kCFBooleanTrue);
            int32_t npass = 2;
            CFNumberRef npr = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &npass);
            VTSessionSetProperty(session, CFSTR("NumberOfPasses"), npr);
            CFRelease(npr);
        }
        VTSessionSetProperty(session, kVTCompressionPropertyKey_ProfileLevel, pl);
        printf("[vt] codec=hevc multipass=%d profile=Main10\n", multipass);
    } else printf("[vt] codec=h264\n");


    /* ---- 2) pool + 30 gradient frames ---- */
    CVPixelBufferPoolRef pool = VTCompressionSessionGetPixelBufferPool(session);
    printf("[vt] VTCompressionSessionGetPixelBufferPool -> %p%s\n",
           (void *)pool, pool ? "" : " (NULL -> fallback CVPixelBufferCreate)");

    for (long i = 0; i < VT_FRAMES; i++) {
        CVPixelBufferRef pb = NULL;
        CVReturn cvr;
        if (pool)
            cvr = CVPixelBufferPoolCreatePixelBuffer(kCFAllocatorDefault, pool, &pb);
        else
            cvr = CVPixelBufferCreate(kCFAllocatorDefault, VT_W2, VT_H2, fmt,
                                      src_attrs, &pb);
        if (cvr != kCVReturnSuccess || !pb) {
            printf("[frame %2ld] buffer create -> %d FAIL\n", i, (int)cvr);
            continue;
        }
        fill_gradient_420v(pb, i);
        CMTime pts = CMTimeMake(i, 30);
        CMTime dur = CMTimeMake(1, 30);
        VTEncodeInfoFlags info = 0;
        st = VTCompressionSessionEncodeFrame(session, pb, pts, dur, NULL,
                                             (void *)(intptr_t)i, &info);
        printf("[frame %2ld] VTCompressionSessionEncodeFrame -> %d (%s) info=0x%x\n",
               i, (int)st, st == 0 ? "ok" : "FAIL", (unsigned)info);
        CVPixelBufferRelease(pb); /* session retained it on success */
        if (st == 0) submitted_ok++;
    }
    printf("[vt] submitted_ok = %d/%d\n", submitted_ok, VT_FRAMES);
    if (submitted_ok == 0) {
        rc_final = 4; /* keep going: alive window is what matters for overlap */
    }

    /* ---- 3) keep the session alive 10 s (BEFORE Complete/End), unconditional ---- */
    {
        FILE *af = fopen("/var/root/vt_alive.txt", "w");
        time_t t0 = time(NULL);
        if (af) fprintf(af, "ALIVE_START %lld\n", (long long)t0);
        printf("[vt] holding session alive %d s (callbacks may fire now)\n",
               VT_ALIVE_SECS);
        for (int i = 1; i <= VT_ALIVE_SECS; i++) {
            fprintf(stderr, "VT_SESSION_ALIVE %d/%d\n", i, VT_ALIVE_SECS);
            if (af) fprintf(af, "ALIVE_TICK %lld %d\n", (long long)time(NULL), i), fflush(af);
            sleep(1);
        }
        if (af) { fprintf(af, "ALIVE_END %lld\n", (long long)time(NULL)); fclose(af); }
    }

end_session:
    /* ---- 4) complete + end + callback stats ---- */
    if (created) {
        st = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
        printf("[vt] VTCompressionSessionCompleteFrames -> %d (%s)\n",
               (int)st, st == 0 ? "noErr" : "FAIL");
        VTCompressionSessionInvalidate(session);
        printf("[vt] VTCompressionSessionInvalidate done\n");
        ended = 1;
    }
    printf("[vt] output callback fired = %u times, last_status = %d, "
           "sample_null = %u\n",
           (unsigned)g_cb_fired, (int)g_cb_last_status,
           (unsigned)g_cb_sample_null);
    if (session) { CFRelease(session); session = NULL; }

run_log:
    /* ---- 5) unified log dump + first 100 lines ---- */
    printf("[log] cmd: %s\n", kLogShowCmd);
        int (*sys_fn)(const char *) = (int (*)(const char *))dlsym(RTLD_DEFAULT, "system");
        int src = sys_fn ? sys_fn(kLogShowCmd) : -1;
    FILE *f = fopen(VT_LOG_PATH, "r");
    if (!f) {
        printf("[log] fopen(%s) failed\n", VT_LOG_PATH);
    } else {
        char line[1024];
        int n = 0;
        printf("[log] ---- %s first 100 lines ----\n", VT_LOG_PATH);
        while (n < 100 && fgets(line, sizeof(line), f)) {
            fputs(line, stdout);
            n++;
        }
        printf("[log] ---- printed %d line(s) ----\n", n);
        fclose(f);
    }

    CFRelease(src_attrs);
    CFRelease(enc_spec);
    (void)ended;
    printf("[vt] exit %d (42 = ran through)\n", rc_final);
    return rc_final;
}
