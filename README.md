# dpi-bypass

<p align="center">
  <a href="https://github.com/LikFridman/dpi-bypass/raw/main/dpi-bypass.exe"><img alt="Скачать для Windows" src="https://img.shields.io/badge/%E2%AC%87%20%D0%A1%D0%BA%D0%B0%D1%87%D0%B0%D1%82%D1%8C%20%D0%B4%D0%BB%D1%8F-Windows-2f7bff?style=for-the-badge&logo=windows&logoColor=white"></a>
  &nbsp;
  <a href="https://github.com/LikFridman/dpi-bypass/raw/main/dpi-bypass.apk"><img alt="Скачать для Android" src="https://img.shields.io/badge/%E2%AC%87%20%D0%A1%D0%BA%D0%B0%D1%87%D0%B0%D1%82%D1%8C%20%D0%B4%D0%BB%D1%8F-Android-34a853?style=for-the-badge&logo=android&logoColor=white"></a>
</p>

Обход DPI-блокировок (YouTube, Discord и др.) без VPN-сервера. Сам подбирает рабочий способ обхода.

## Windows

1. Скачай [dpi-bypass.exe](https://github.com/LikFridman/dpi-bypass/raw/main/dpi-bypass.exe) и положи в отдельную папку.
2. Запусти и разреши права администратора.
3. Выбери режим «Без VPN» или «Вместе с VPN» и включи переключатель.

Если Защитник удаляет файлы, добавь папку программы в исключения (в программе: «Защитник»).

## Android

1. Скачай [dpi-bypass.apk](https://github.com/LikFridman/dpi-bypass/raw/main/dpi-bypass.apk) и установи (разреши установку из неизвестных источников).
2. Включи переключатель и разреши VPN.

На Android одновременно работает только один VPN, поэтому обход заменяет другой VPN, пока включён.

## Что умеет

- Автоподбор стратегии и раз в минуту проверка сайтов.
- Работа вместе с VPN-клиентами (Happ и др.) на Windows.
- Прокси для Telegram Desktop.
- Глубокая проверка для сайтов, которые не открываются.
- Автозапуск, трей и плитка в шторке, свой фон, обновление в один клик.

## Сборка

Exe и APK собираются и проверяются в [GitHub Actions](../../actions).

Движки: [zapret](https://github.com/bol-van/zapret) (Windows), [byedpi](https://github.com/hufrea/byedpi) и [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) (Android).
