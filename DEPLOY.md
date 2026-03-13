# DAT Mailer v2 — Railway Deployment Guide

## Крок 1 — Підготовка git репо

```bash
cd /Users/bohdanbezverkhyi/Downloads/project_v2_online

git init
git add .
git commit -m "feat: initial DAT Mailer v2"

# Створи репо на GitHub (назви dat-mailer-v2), потім:
git remote add origin https://github.com/YOUR_USERNAME/dat-mailer-v2.git
git push -u origin main
```

> `.env` і `*.db` ігноруються — вони не потраплять в репо.

---

## Крок 2 — Створення проекту на Railway

1. Зайди на **[railway.app](https://railway.app)** → **New Project**
2. **Deploy from GitHub repo** → вибери `dat-mailer-v2`
3. Railway автоматично визначить Python і встановить залежності

---

## Крок 3 — Environment Variables (ОБОВ'ЯЗКОВО)

В Railway: **твій сервіс → Variables → Add Variables**

| Variable | Значення | Як отримати |
|---|---|---|
| `SECRET_KEY` | довгий рандомний рядок | `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `ENCRYPTION_KEY` | Fernet ключ | `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `ADMIN_EMAIL` | `bbkey777@gmail.com` | твій email |
| `ADMIN_PASSWORD` | твій пароль | мін. 8 символів |

### Опціонально (але рекомендовано):

| Variable | Значення | Навіщо |
|---|---|---|
| `REDIS_URL` | автоматично Railway | Rate limiting між restarts |

> **Redis:** Railway dashboard → твій проект → **+ New** → **Redis** → Railway сам додасть `REDIS_URL` у Variables.

### НЕ потрібно вручну встановлювати:
- `DATABASE_URL` — Railway додає автоматично при підключенні PostgreSQL
- `PORT` — Railway додає автоматично

---

## Крок 4 — PostgreSQL база даних

1. Railway dashboard → твій проект → **+ New** → **PostgreSQL**
2. Railway автоматично встановить `DATABASE_URL` у Variables сервісу
3. При наступному deploy `flask db upgrade` (releaseCommand) застосує всі міграції

---

## Крок 5 — Перший deploy

Railway автоматично:
1. Встановить залежності з `requirements.txt`
2. Запустить `FLASK_APP=wsgi.py flask db upgrade` (всі таблиці)
3. Запустить `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --timeout 120`
4. Створить адмін-акаунт з `ADMIN_EMAIL` / `ADMIN_PASSWORD`

---

## Крок 6 — Перевірка після deploy

| Що перевірити | URL |
|---|---|
| App доступний | `https://your-app.railway.app/` |
| Редірект на логін | має редіректити на `/login` |
| Логін адміна | `bbkey777@gmail.com` + пароль |
| Адмін панель | `https://your-app.railway.app/admin` |

---

## Додати юзера

1. `/admin` → **Invite User** → введи email → **Send Invite**
2. Юзер отримає посилання (або скопіюй вручну з поля нижче форми)
3. Юзер реєструється → отримує `free` plan
4. В адмін панелі можеш змінити plan на `starter` або `pro`

---

## Pre-deploy checklist

```
[ ] SECRET_KEY встановлено (не дефолтний random — при рестарті сесії скидаються)
[ ] ENCRYPTION_KEY встановлено (інакше Gmail паролі зберігатимуться нешифровано)
[ ] ADMIN_EMAIL встановлено
[ ] ADMIN_PASSWORD встановлено (мін. 8 символів)
[ ] PostgreSQL підключено (DATABASE_URL з'явиться автоматично)
[ ] Redis підключено (опціонально, але рекомендовано для production)
[ ] .gitignore перевірено — .env, *.db, userdata/ ігноруються
[ ] dat_mailer_dev.db НЕ потрапив в git репо
```

---

## Troubleshooting

| Проблема | Рішення |
|---|---|
| `flask db upgrade` fails | Перевір `DATABASE_URL` в Variables |
| Login не працює | Перевір `ADMIN_EMAIL` / `ADMIN_PASSWORD` в Variables |
| Rate limit не зберігається | Підключи Redis (крок 4) |
| Gmail не відправляє | Перевір Gmail App Password в Settings сервісу |
| `Invalid token` для шифрування | `ENCRYPTION_KEY` має бути валідним Fernet ключем (base64, 44 символи) |
