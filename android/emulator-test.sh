#!/usr/bin/env bash
# Проверка APK в эмуляторе Android (GitHub Actions): самопроверка движков, VPN, снимки экрана.
set -x
PKG=com.likfridman.dpibypass
adb install -r dpi-bypass.apk || exit 1
adb shell appops set $PKG ACTIVATE_VPN allow
adb shell pm grant $PKG android.permission.POST_NOTIFICATIONS || true
adb logcat -c
adb shell am start -n $PKG/.MainActivity --ez selftest true
for i in $(seq 1 90); do adb logcat -d -s DPI_SELFTEST:I | grep -q "RESULT" && break; sleep 2; done
adb logcat -d -s DPI_SELFTEST:I dpi-bypass:I | tee android-selftest.txt
# запрос из оболочки эмулятора идёт через туннель обхода (оболочка не исключена из VPN)
adb shell 'printf "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n" | toybox nc -w 15 example.com 80 | head -1' | tee -a android-selftest.txt
mkdir -p docs/screens
sleep 4
adb exec-out screencap -p > docs/screens/android-home.png
for p in sites log set; do
  adb shell am start -n $PKG/.MainActivity --es page $p
  sleep 3
  adb exec-out screencap -p > docs/screens/android-$p.png
done
adb shell am start -n $PKG/.MainActivity --es page home
ls -la docs/screens
grep -q "RESULT OK" android-selftest.txt
