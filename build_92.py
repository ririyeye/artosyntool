#!/usr/bin/env python3
"""
构建 logcat 到 armv7-unknown-linux-gnueabihf 目标平台
用法: python3 build_92.py
"""

import os
import subprocess
import sys
import shutil

# rustup target add armv7-unknown-linux-gnueabihf

TOOLCHAIN = os.environ.get(
    "TOOLCHAIN",
    "/opt/toolchain/gcc-linaro-5.4.1-2017.05-x86_64_arm-linux-gnueabihf/bin",
)
STRIP = os.environ.get("STRIP", f"{TOOLCHAIN}/arm-linux-gnueabihf-strip")
STRIP_FLAGS = os.environ.get("STRIP_FLAGS", "-s")
OPT_LEVEL = os.environ.get("OPT_LEVEL", "z")

# 动态链接版本：去掉 crt-static 与 -static，仅保留 LTO + 体积优化
BASE_RUSTFLAGS = f"-C lto -C opt-level={OPT_LEVEL}"
RUSTFLAGS = f"{os.environ.get('RUSTFLAGS', '')} {BASE_RUSTFLAGS}".strip()

TARGET = "armv7-unknown-linux-gnueabihf"
OUTPUT_BINARY = f"target/{TARGET}/release/logcat"


def main():
    # 检查 strip 工具
    strip_available = os.path.isfile(STRIP) and os.access(STRIP, os.X_OK)
    if not strip_available:
        print(f"WARN: strip 不存在或不可执行: {STRIP}", file=sys.stderr)

    # 设置交叉编译环境变量
    env = os.environ.copy()
    env.update(
        {
            f"CC_{TARGET.replace('-', '_')}": f"{TOOLCHAIN}/arm-linux-gnueabihf-gcc",
            f"CXX_{TARGET.replace('-', '_')}": f"{TOOLCHAIN}/arm-linux-gnueabihf-g++",
            f"AR_{TARGET.replace('-', '_')}": f"{TOOLCHAIN}/arm-linux-gnueabihf-ar",
            f"CARGO_TARGET_{TARGET.upper().replace('-', '_')}_LINKER": f"{TOOLCHAIN}/arm-linux-gnueabihf-gcc",
            "RUSTFLAGS": RUSTFLAGS,
        }
    )

    # 执行 cargo build
    cmd = [
        "cargo",
        "build",
        "-p",
        "logcat",
        "--release",
        "--target",
        TARGET,
        "--no-default-features",
    ]

    print(f"执行: {' '.join(cmd)}")
    result = subprocess.run(cmd, env=env)
    if result.returncode != 0:
        print(f"构建失败，退出码: {result.returncode}", file=sys.stderr)
        sys.exit(result.returncode)

    # Strip 二进制文件
    if strip_available:
        strip_cmd = [STRIP] + STRIP_FLAGS.split() + [OUTPUT_BINARY]
        print(f"执行: {' '.join(strip_cmd)}")
        result = subprocess.run(strip_cmd)
        if result.returncode != 0:
            print(f"strip 失败，退出码: {result.returncode}", file=sys.stderr)
            sys.exit(result.returncode)
    else:
        print(f"SKIP strip: 未找到 {STRIP}", file=sys.stderr)

    print(f"构建完成: {OUTPUT_BINARY}")


if __name__ == "__main__":
    main()
