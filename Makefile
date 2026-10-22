# Makefile — AppleAVE2 KRW exploit build
#
# 用法 (macOS, Xcode 已安装):
#   make            # 构建默认目标
#   make exploit   # 构建 ave2_exploit
#   make reach     # 构建 poc_ave2_reach
#   make all       # 两个都构建
#   make clean
#
# 要求: Xcode Command Line Tools (xcrun clang + iphoneos SDK)

SDK ?= $(shell xcrun --sdk iphoneos --show-sdk-path)
CLANG ?= xcrun clang
ARCH ?= arm64e

CFLAGS := -O0 -g -arch $(ARCH) -isysroot "$(SDK)" -fembed-bitcode
FRAMES := -framework IOKit -framework CoreFoundation

SRC := src/ave2_exploit.c src/ave2_wire.h
REACH := src/poc_ave2_reach.c src/ave2_wire.h

.PHONY: all exploit reach clean

all: exploit reach

exploit: ave2_exploit
reach: poc_ave2_reach

ave2_exploit: $(SRC)
	$(CLANG) $(CFLAGS) $(FRAMES) $< -o $@

poc_ave2_reach: $(REACH)
	$(CLANG) $(CFLAGS) $(FRAMES) $< -o $@

clean:
	rm -f ave2_exploit poc_ave2_reach
