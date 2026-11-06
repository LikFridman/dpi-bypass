#!/usr/bin/env bash
# Проверка APK в эмуляторе Android (GitHub Actions): самопроверка движков, VPN, снимки экрана.
set -x
PKG=com.likfridman.dpibypass
adb install -r dpi-bypass.apk || exit 1
adb shell appops set $PKG ACTIVATE_VPN allow
adb shell pm grant $PKG android.permission.POST_NOTIFICATIONS || true
adb logcat -c
adb shell am start -n $PKG/.MainActivity --ez selftest true
for i in $(seq 1 420); do adb logcat -d -s DPI_SELFTEST:I | grep -q "RESULT" && break; sleep 2; done
adb logcat -d -s DPI_SELFTEST:I dpi-bypass:I | tee android-selftest.txt
# падения приложения и процесса страницы
adb logcat -d -b crash | tee -a android-selftest.txt
if adb logcat -d -b crash | grep -q "$PKG"; then echo "FAIL приложение падало (см. выше)" | tee -a android-selftest.txt; fi
adb shell pidof $PKG >/dev/null && echo "OK   процесс приложения жив" | tee -a android-selftest.txt || echo "FAIL процесс приложения завершился" | tee -a android-selftest.txt
# почему процесс завершился (система хранит причину) и системный журнал вокруг сбоя
echo "--- exit-info ---" | tee -a android-selftest.txt
adb shell dumpsys activity exit-info $PKG 2>/dev/null | head -60 | tee -a android-selftest.txt
echo "--- logcat (ошибки) ---" | tee -a android-selftest.txt
adb logcat -d '*:E' | grep -v "DPI_SELFTEST" | tail -150 | tee -a android-selftest.txt
adb logcat -d | grep -E "DEBUG|libc|tombstone|hev|tproxy|$PKG|AndroidRuntime|lowmemorykiller|ActivityManager: (Kill|Process)" | tail -120 | tee -a android-selftest.txt
# запрос из оболочки эмулятора идёт через туннель обхода (оболочка не исключена из VPN)
sleep 5
echo "--- запросы из оболочки эмулятора (идут через туннель обхода) ---" | tee -a android-selftest.txt
adb shell 'which nc toybox; printf "GET / HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n" | nc -w 15 1.1.1.1 80 | head -1' 2>&1 | tee -a android-selftest.txt
adb shell 'printf "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n" | nc -w 15 example.com 80 | head -1' 2>&1 | tee -a android-selftest.txt
adb shell dumpsys connectivity | grep -i "VPN" | head -3 | tee -a android-selftest.txt
mkdir -p docs/screens
sleep 4
adb exec-out screencap -p > docs/screens/android-home.png
for p in sites tg log set; do
  adb shell am start -n $PKG/.MainActivity --es page $p
  sleep 3
  adb exec-out screencap -p > docs/screens/android-$p.png
done
adb shell am start -n $PKG/.MainActivity --es page home
ls -la docs/screens
grep -q "RESULT OK" android-selftest.txt && ! grep -q "^FAIL" android-selftest.txt
