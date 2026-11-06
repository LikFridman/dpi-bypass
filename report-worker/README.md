# Сервер отчётов (Cloudflare Worker + D1)

Принимает технические отчёты от dpi-bypass (Windows и Android), хранит их 90 дней и показывает на странице с поиском. Бесплатного тарифа Cloudflare хватает: D1 даёт 100 000 записей в день.

## Настройка (один раз, ~10 минут)

1. Зарегистрируйся на [dash.cloudflare.com](https://dash.cloudflare.com) (бесплатно).
2. **База:** Storage & Databases → **D1 SQL Database** → Create → имя `dpi-reports` → Create. Таблицы Worker создаст сам.
3. **Worker:** Compute (Workers) → Workers & Pages → **Create** → Start with Hello World → имя `dpi-reports` → Deploy.
4. **Код:** Edit code → удали всё → вставь содержимое [`worker.js`](worker.js) → **Deploy**.
5. **Связать базу:** страница Worker'а → Settings → **Bindings** → Add → D1 database → Variable name `DB`, база `dpi-reports` → Deploy.
6. **Пароль для просмотра:** Settings → **Variables and Secrets** → Add → Type: **Secret**, Name `ADMIN_KEY`, Value — длинный случайный пароль → Deploy.
7. Скопируй адрес Worker'а, например `https://dpi-reports.имя.workers.dev`, и пришли его (или впиши в [`update/update.json`](../update/update.json) в поле `report_url`). Программы подхватят адрес сами, обновлять exe и APK не нужно.

## Просмотр

Открой `https://dpi-reports.имя.workers.dev/?key=ТВОЙ_ADMIN_KEY`:
- список последних отчётов: время, номер, платформа, IP, провайдер, сколько сайтов отвечает, ошибки, итог;
- поиск по IP, провайдеру, номеру отчёта или сайту, фильтр Windows/Android и по поводу (connect / error / manual);
- клик по строке — полный отчёт в JSON.

API (тоже с `?key=`): `GET /api/reports`, `GET /api/report/НОМЕР`, `DELETE /api/report/НОМЕР` — удалить отчёт по просьбе пользователя.

## Что приходит

См. [AGREEMENT.md](../AGREEMENT.md), раздел 2. Кроме того, что присылает программа, Worker сам добавляет IP, страну, город и провайдера по данным Cloudflare (поле `server`).

## Защита

- принимается только JSON до 256 КБ с полем `app.platform`;
- не больше 30 отчётов в час с одного IP;
- читать и удалять отчёты можно только с `ADMIN_KEY`; без ключа страница отвечает «ok».
