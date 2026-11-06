# dpi-bypass

<p align="center">
  <a href="https://github.com/LikFridman/dpi-bypass/raw/main/dpi-bypass.exe"><img alt="Windows" src="https://img.shields.io/badge/%E2%AC%87%20%D0%A1%D0%BA%D0%B0%D1%87%D0%B0%D1%82%D1%8C%20%D0%B4%D0%BB%D1%8F-Windows-2f7bff?style=for-the-badge&logo=windows&logoColor=white"></a>
  &nbsp;
  <a href="https://github.com/LikFridman/dpi-bypass/raw/main/dpi-bypass.apk"><img alt="Android" src="https://img.shields.io/badge/%E2%AC%87%20%D0%A1%D0%BA%D0%B0%D1%87%D0%B0%D1%82%D1%8C%20%D0%B4%D0%BB%D1%8F-Android-34a853?style=for-the-badge&logo=android&logoColor=white"></a>
</p>

Локальный обход DPI без внешнего сервера: диагностика блокировок по стадиям, автоподбор стратегий, сторож с переподбором, MTProto-прокси для Telegram с WebSocket-транспортом и поиском публичных прокси.

| | Windows | Android |
|---|---|---|
| Движок | [zapret](https://github.com/bol-van/zapret) `winws` + WinDivert | пул [byedpi](https://github.com/hufrea/byedpi) + свой SOCKS5-маршрутизатор за `VpnService` / [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) |
| Требования | Win10+ x64, права администратора (драйвер WinDivert) | Android 8.0+ (API 26), arm64 / armv7 / x86_64 |
| Telegram | локальный MTProto-прокси `127.0.0.1:1443` | то же, `libtgproxy.so` (общее Go-ядро) |
| UI | WebView2, трей, автозапуск через планировщик | WebView, плитка QS, автозапуск при загрузке |

## Пайплайн

1. **Baseline без обхода** — для каждого сервиса и каждого его адреса: DNS (системный, при подмене — DoH) → TCP:443 → TLS → чтение до 96 КБ. Результат классифицируется: `dns`, `tcp` (блок по IP, обходом не лечится), `tls` (сброс/зависание на SNI), `data`, `throttle` (обрыв после N КБ).
2. **Подбор** — перебор стратегий только по сервисам со стадией `tls`/`data`/`throttle`. Первыми идут пресет провайдера по ASN (Windows) или ранее сработавшие на устройстве (Android). Сервисы жадно покрываются минимальным набором стратегий: на Windows — профили winws с отдельными hostlist, на Android — отдельные процессы byedpi, между которыми маршрутизатор раскладывает соединения по SNI.
   **YouTube** проверяется по скорости, а не по факту ответа: через API плеера (`youtubei/v1/player`, клиенты ANDROID_VR/IOS) берётся прямая ссылка на поток googlevideo и качается до 8 МБ за 6 с. Если без обхода < 600 КБ/с, YouTube считается замедленным и идёт в подбор. Из стратегий, которые его открыли, для него берётся самая быстрая.
3. **Сторож** — проверка раз в 60 с; если ≥ половины сервисов дважды подряд не отвечает — переподбор (не чаще раза в 10 мин). Перезапуск движка при падении, реакция на смену VPN/адаптера.
4. **Автосписок** (Windows) — новые заблокированные домены попадают в `auto-hostlist`, для них раз в 30 мин подбирается своя стратегия.
5. **Обновления** — стратегии, сервисы, пресеты, адрес отчётов и источники прокси приходят из [`update/update.json`](update/update.json) без пересборки (raw.githubusercontent → jsDelivr).

**Проверка с нагрузкой** (Go, пакет `check`): сервис считается рабочим, только если тянет данные, — ТСПУ часто пропускают начало соединения и рвут его после ~16 КБ. YouTube — видео с googlevideo, Discord — WebSocket-шлюз `gateway.discord.gg` (HELLO) и JS-бандл с CDN, остальные — страница и крупный файл с CDN сервиса, Telegram — `req_pq` к DC2. Стадии: `dns`, `tcp`, `tls`, `data`, `throttle` (обрыв после N КБ), `http`.

**Подбор на Android:** быстрый прогон 36 стратегий с облегчённой нагрузкой → для непокрытых сервисов глубокий поиск (split/disorder/oob/disoob/tlsrec на 5 позициях, fake с TTL 2–12, затем сочетания сработавших приёмов) → полная проверка трёх лучших для каждого сервиса и выбор по скорости → план с минимумом процессов byedpi. Найденные глубоким поиском стратегии сохраняются.

**Ручной выбор:** клик по сервису (Sites) — все стратегии с результатами последних проверок (✓ скорость / ✗ стадия, `~` — облегчённая проверка), **Test** — полная проверка одной стратегии на этом сервисе, **Use** — закрепить (автоподбор её не трогает), **Auto** — вернуть автоматический выбор. **Ping all** — полная проверка всех сервисов через текущую конфигурацию. Журнал: Summary / Errors / All.

Статус сайта в UI: `42 ms` — время TCP-хендшейка с сервером при успешной проверке через обход; `none` — нет ответа (причина и стадия в журнале); `via VPN` — Telegram через SOCKS VPN-клиента.

## Windows

| Режим | Поведение |
|---|---|
| No VPN | VPN-клиенты закрываются, обход на всём трафике |
| With VPN | VPN не трогается. При TUN — `--wf-iface` на физический адаптер, IP серверов VPN в `--ipset-exclude`; Telegram может идти через локальный SOCKS VPN-клиента |

VPN детектируется по процессам (Toolhelp32), TCP-слушателям (`GetExtendedTcpTable`), адаптерам и маршруту по умолчанию (`GetBestInterface`). Для TUN-клиентов пишется `vpn-direct-domains.txt` — домены для правил Direct.

```
dpi-bypass.exe                 GUI
dpi-bypass.exe console         TUI-меню
dpi-bypass.exe 1|2|3           No VPN | With VPN | stop
dpi-bypass.exe check           диагностика
dpi-bypass.exe deep <host>     глубокий перебор (~300 комбинаций desync)
dpi-bypass.exe tune            стратегии для новых доменов автосписка
dpi-bypass.exe update          самообновление (sha256)
dpi-bypass.exe reset           сброс config.json и автосписка
dpi-bypass.exe selftest        самопроверка (используется в CI)
```

`dpi-bypass-data/`: `sites.txt` (сервисы: `Имя | проверяемые хосты | домены`), `config.json`, `settings.json`, `lists/auto-hostlist.txt`, `telegram-proxies.txt`, `telegram-worker.txt`, `vpn-direct-domains.txt`, `reports/`, `log.txt`.

`winws.exe` и `WinDivert64.sys` часто помечаются Защитником как HackTool — добавь каталог в исключения (раздел **Defender**).

## Android

```
VpnService (весь трафик, v4+v6; приложение исключено) → hev-socks5-tunnel (JNI) → маршрутизатор :1090
   TCP:  SNI / HTTP Host → byedpi своей группы (:1081…) или по умолчанию (:1080)
   TCP к сетям Telegram → byedpi; при сбоях (2 соединения без ответа за 2 мин) /24 уходит
         в прозрачный WebSocket к kwsN.web.telegram.org на 15 мин — без прокси в самом Telegram
   UDP 443 (QUIC) → drop: клиенты сразу переходят на TCP, где работает desync
   UDP 50000–65535 (голос Discord) → byedpi :1089 с --udp-fake 6
   прочий UDP (DNS и т.п.) → напрямую
```

Маршрутизатор и Telegram-прокси — одно Go-ядро (`libtgproxy.so`). 36 стратегий byedpi, первыми идут варианты без подмены TTL: у мобильных операторов fake-пакеты с малым TTL часто не доходят до DPI. В Settings: Block QUIC, Discord voice (UDP), режим Telegram `auto` / `ws` / `direct`. Одновременно активен только один VPN, поэтому обход замещает другой VPN-клиент.

## Telegram

Локальный MTProto-прокси (obfuscated2, секрет `dd`). Маршруты по порядку, сломанный маршрут уходит в конец очереди на 3 мин:

1. **WebSocket** `wss://kwsN.web.telegram.org/apiws` — транспорт веб-клиента; на Android через byedpi, на Windows через winws.
2. **Cloudflare Worker** — свой релей WS при блокировке IP Telegram ([`cloudflare-worker.js`](cloudflare-worker.js)).
3. **Запасные прокси** — `tg://proxy` (plain / `dd` / FakeTLS `ee`, hex и base64) или `socks5://`.
4. **TCP** напрямую к DC.
5. **SOCKS VPN-клиента** (Windows, With VPN) — raw TCP и WS.

**Public proxies** — при старте и раз в 30 мин скачиваются публичные списки ([Argh94/Proxy-List](https://github.com/Argh94/Proxy-List), [SoliSpirit/mtproto](https://github.com/SoliSpirit/mtproto), [ALIILAPRO/MTProtoProxy](https://github.com/ALIILAPRO/MTProtoProxy), [Kudts/mtproto](https://github.com/Kudts/mtproto); переопределяются `tg_proxy_sources` в `update.json`). До 300 кандидатов проверяются параллельно настоящим `req_pq_multi` к DC2 через сам прокси (с FakeTLS-хендшейком и проверкой HMAC сервера). Топ перепроверяется, выводятся 3 с минимальной задержкой: **Use** — запасной маршрут локального прокси, **Open** — добавить в Telegram напрямую. MTProto шифрует трафик до серверов Telegram, оператор прокси видит только IP клиента.

## Отчёты

Обязательный акцепт [пользовательского соглашения](AGREEMENT.md) при первом запуске. Технический отчёт уходит при каждом подключении, при ошибках, падениях (со стеком) и вручную (Settings → Send report). Состав: сеть (IP, ASN, DNS, MTU, адаптеры), система и устройство, VPN, результаты всех проверенных стратегий, по-адресные результаты проверок, аргументы и вывод winws/byedpi, маршруты Telegram, журнал (имя пользователя, компьютера и пути вырезаются). Приёмник — Cloudflare Worker + D1 ([`report-worker/`](report-worker)), хранение 90 дней. Неотправленные отчёты копятся локально (до 20).

## Сборка

CI ([`build.yml`](.github/workflows/build.yml)) на каждый push:
- **windows-latest:** `go vet`, `go test`, сборка с ресурсами (goversioninfo), `selftest` (все стратегии в winws, полная конфигурация, пинг сервисов, запрос к Telegram через прокси, поиск публичных прокси, сборка отчёта), `uitest` (WebView2).
- **ubuntu + эмулятор API 34:** byedpi и hev-socks5-tunnel через NDK из зафиксированных коммитов, `tgproxy` (Go, `CGO_ENABLED=0`) для трёх ABI, APK, самопроверка в эмуляторе (все стратегии, пул byedpi + маршрутизатор, YouTube в своей группе, Telegram MTProto и WebSocket, скорость YouTube, VPN-туннель, отчёт, UI).

Бинарники коммитит бот в `main`.

```sh
go test ./...
GOOS=windows go build -ldflags "-H windowsgui" -o dpi-bypass.exe .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o libtgproxy.so ./cmd/tgproxy
```

## Благодарности

- [zapret](https://github.com/bol-van/zapret), [zapret-win-bundle](https://github.com/bol-van/zapret-win-bundle) — bol-van
- [WinDivert](https://github.com/basil00/WinDivert) — basil00
- [byedpi](https://github.com/hufrea/byedpi) — hufrea
- [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) — heiher
- [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) — Flowseal (идея WS-транспорта для Telegram; здесь своя реализация)
- [go-webview2](https://github.com/jchv/go-webview2) — jchv
- [goversioninfo](https://github.com/josephspurrier/goversioninfo) — josephspurrier
- авторы публичных списков MTProto-прокси (см. раздел Telegram)

[MIT](LICENSE)
