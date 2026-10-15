#!/usr/bin/env bash
# Builds the comparison corpus. Output binaries are committed so results do
# not drift with the local toolchain; rerun only when sources change.
set -euo pipefail
cd "$(dirname "$0")"
SRC=src
OUT=binaries
mkdir -p "$OUT"

build() { # name cmd...
    local name=$1; shift
    if "$@" -o "$OUT/$name" 2>"$OUT/$name.log"; then
        rm -f "$OUT/$name.log"
        echo "built $name"
    else
        echo "SKIP $name (see $OUT/$name.log)"
    fi
}

for cc in gcc clang; do
    for opt in O0 O2; do
        build basic-x86_64-$cc-$opt $cc -$opt -g0 -fno-stack-protector $SRC/basic.c
        build basic-x86_64-$cc-$opt-stripped $cc -$opt -g0 -s -fno-stack-protector $SRC/basic.c
    done
done
build objects-x86_64-gxx-O2 g++ -O2 -g0 $SRC/objects.cpp
build objects-x86_64-gxx-O2-stripped g++ -O2 -g0 -s $SRC/objects.cpp
build basic-x86_64-gcc-O2-static-stripped gcc -O2 -g0 -s -static $SRC/basic.c

FS="-ffreestanding -fno-builtin -nostdlib -fno-stack-protector -fno-pic -fuse-ld=lld -g0"
build freestanding-i386-clang-O2 clang --target=i386-linux-gnu -O2 $FS -static $SRC/freestanding.c
build freestanding-aarch64-clang-O2 clang --target=aarch64-linux-gnu -O2 $FS -static $SRC/freestanding.c
build freestanding-aarch64-clang-O0 clang --target=aarch64-linux-gnu -O0 $FS -static $SRC/freestanding.c
build freestanding-x86_64-clang-O2 clang --target=x86_64-linux-gnu -O2 $FS -static $SRC/freestanding.c
build freestanding-x86_64-pe-clang-O2.exe clang --target=x86_64-pc-windows-msvc -O2 -ffreestanding -fno-builtin \
    -nostdlib -fuse-ld=lld -Wl,/entry:_start -Wl,/subsystem:console $SRC/freestanding.c
build freestanding-i386-pe-clang-O2.exe clang --target=i686-pc-windows-msvc -O2 -ffreestanding -fno-builtin \
    -nostdlib -fuse-ld=lld -Wl,/entry:_start -Wl,/subsystem:console $SRC/freestanding.c
