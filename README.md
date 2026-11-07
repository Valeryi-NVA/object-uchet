# ОбъектУчёт

Full-stack приложение для учёта объектов, выездов, цеховых смен, расходов и зарплаты.

## Локальный запуск

1. Создайте PostgreSQL-базу и скопируйте `.env.example` в `.env`.
2. Укажите `DATABASE_URL`.
3. Выполните:

```powershell
npm.cmd install
npm.cmd start
```

Приложение будет доступно по адресу `http://localhost:10000`.

## Публикация на Render

Файл `render.yaml` описывает web service и PostgreSQL database. Подключите Git-репозиторий в Render и создайте Blueprint из корня проекта. Render установит зависимости командой `npm ci` и запустит `npm start`.

## Архитектура

- `server.js` — Express API, серверные сессии, валидация, роли и PostgreSQL.
- `public/index.html` — пользовательский интерфейс.
- `schema.sql` — SQL-схема для ручной инициализации базы.
- `index2.html` — исходный файл до миграции, сохранён для сравнения и отката.

Авторизация использует HttpOnly-cookie и `scrypt`. PIN и состояние приложения больше не хранятся в `localStorage`.
