# Makefile — AppleAVE2 KRW exploit build (iOS + macOS)
#
# 用法 (macOS, Xcode 已安装):
#   make            # exploit + reach
#   make exploit   # ave2_exploit (arm64, iOS-ready)
#   make reach     # poc_ave2_reach
#   make ipa       # 打包 ave2_exploit.ipa (需 ldid)
#   make clean
#
# 说明:
#   - 架构改为 arm64 (非 arm64e): iokit_dyn.h 用 dlsym 取函数指针,
#     arm64e 的签名分支会拒绝对未签名指针的调用。
#   - IOKit 走 dlopen, 无需 SDK IOKit 头文件, iOS/macOS 同源码。
#   - 去掉 -fembed-bitcode (新版 Xcode 已废弃)。

SDK ?= $(shell xcrun --sdk iphoneos --show-sdk-path)
CLANG ?= xcrun clang
ARCH ?= arm64
MINOS ?= -miphoneos-version-min=14.0

CFLAGS := -O2 -g -arch $(ARCH) -isysroot "$(SDK)" $(MINOS)
LDLIBS := -framework CoreFoundation

SRC := src/ave2_exploit.c src/ave2_wire.h src/iokit_dyn.h src/ave2_profiles.h
REACH := src/poc_ave2_reach.c src/ave2_wire.h

.PHONY: all exploit reach ipa clean

all: exploit reach

exploit: ave2_exploit
reach: poc_ave2_reach

ave2_exploit: src/ave2_exploit.c src/ave2_wire.h src/iokit_dyn.h src/ave2_profiles.h
	$(CLANG) $(CFLAGS) $< -o $@ $(LDLIBS)

poc_ave2_reach: src/poc_ave2_reach.c src/ave2_wire.h
	$(CLANG) $(CFLAGS) -framework IOKit -framework CoreFoundation $< -o $@

ipa: ave2_exploit
	@which ldid >/dev/null 2>&1 || { echo "ldid not found — install: brew install ldid"; exit 1; }
	@chmod +x scripts/make_ipa.sh
	./scripts/make_ipa.sh ave2_exploit ave2_exploit.ipa

clean:
	rm -f ave2_exploit poc_ave2_reach ave2_exploit.ipa
