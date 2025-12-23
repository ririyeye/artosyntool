#!/bin/bash
set -euo pipefail

# rustup target add armv7-unknown-linux-gnueabihf

TOOLCHAIN=${TOOLCHAIN:-/opt/toolchain/gcc-linaro-5.4.1-2017.05-x86_64_arm-linux-gnueabihf/bin}
STRIP=${STRIP:-$TOOLCHAIN/arm-linux-gnueabihf-strip}
STRIP_FLAGS=${STRIP_FLAGS:--s}
OPT_LEVEL=${OPT_LEVEL:-z}
# 动态链接版本：去掉 crt-static 与 -static，仅保留 LTO + 体积优化
BASE_RUSTFLAGS="-C lto -C opt-level=$OPT_LEVEL"
RUSTFLAGS="${RUSTFLAGS:-} ${BASE_RUSTFLAGS}"

if [ ! -x "$STRIP" ]; then
	echo "WARN: strip 不存在或不可执行: $STRIP" >&2
fi

CC_armv7_unknown_linux_gnueabihf=$TOOLCHAIN/arm-linux-gnueabihf-gcc \
 CXX_armv7_unknown_linux_gnueabihf=$TOOLCHAIN/arm-linux-gnueabihf-g++ \
 AR_armv7_unknown_linux_gnueabihf=$TOOLCHAIN/arm-linux-gnueabihf-ar \
 CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=$TOOLCHAIN/arm-linux-gnueabihf-gcc \
 RUSTFLAGS="$RUSTFLAGS" \
cargo build -p logcat --release --target armv7-unknown-linux-gnueabihf --no-default-features

if [ -x "$STRIP" ]; then
	$STRIP $STRIP_FLAGS target/armv7-unknown-linux-gnueabihf/release/logcat
else
	echo "SKIP strip: 未找到 $STRIP" >&2
fi