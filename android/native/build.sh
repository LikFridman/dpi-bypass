#!/usr/bin/env bash
# Сборка движков для Android: hev-socks5-tunnel (JNI-библиотека) и byedpi (исполняемый файл).
# Использование: native/build.sh <папка с исходниками byedpi и hev-socks5-tunnel>
set -euo pipefail
SRC="$(cd "$1" && pwd)"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$HERE/app/src/main/jniLibs"
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_LATEST_HOME:-}}"
API=26
[ -d "$NDK" ] || { echo "NDK не найден"; exit 1; }
TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
ABIS="arm64-v8a armeabi-v7a x86_64"

# --- hev-socks5-tunnel ---
rm -rf "$SRC/hevproj" && mkdir -p "$SRC/hevproj" && ln -s "$SRC/hev" "$SRC/hevproj/jni"
"$NDK/ndk-build" -C "$SRC/hevproj" NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk \
  NDK_APPLICATION_MK=jni/Application.mk APP_ABI="$ABIS" APP_PLATFORM=android-$API \
  APP_CFLAGS="-O3 -DPKGNAME=com/likfridman/dpibypass -DCLSNAME=TProxyService" -j"$(nproc)"

# --- byedpi ---
for pair in arm64-v8a:aarch64-linux-android armeabi-v7a:armv7a-linux-androideabi x86_64:x86_64-linux-android; do
  abi="${pair%%:*}"; tgt="${pair##*:}"
  mkdir -p "$OUT/$abi"
  cp "$SRC/hevproj/libs/$abi/libhev-socks5-tunnel.so" "$OUT/$abi/"
  make -C "$SRC/byedpi" clean >/dev/null
  make -C "$SRC/byedpi" CC="$TC/${tgt}${API}-clang" LDFLAGS="-s -Wl,-z,max-page-size=16384" -j"$(nproc)"
  cp "$SRC/byedpi/ciadpi" "$OUT/$abi/libciadpi.so"
  chmod +x "$OUT/$abi/libciadpi.so"
done
ls -la "$OUT"/*
