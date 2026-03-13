# DAT Mailer Online — Claude Code Context

## Що це
Flask веб-застосунок для автоматизації freight email outreach.
Версія v2 з invite-only авторизацією, мультиюзерністю, PostgreSQL.

## Структура
```
app.py              — головний Flask файл (маршрути, логіка)
app/models.py       — SQLAlchemy моделі (User, Invitation, Send, Reply, FollowUp, ...)
app/extensions.py   — db, migrate ініціалізація
templates/
  index.html        — весь фронтенд (vanilla JS)
  admin.html        — адмін панель
  login.html        — логін
  register.html     — реєстрація по invite-токену
migrations/         — Alembic міграції
wsgi.py             — gunicorn entry point
requirements.txt
```

## Деплой
- Платформа: **Railway**
- Репо: `https://github.com/777-cmd1/DAT`
- Команда деплою: `git push origin main` → Railway передеплоює автоматично
- БД: PostgreSQL (Railway підключає через `DATABASE_URL`)
- Міграції: `flask db upgrade` (запускається автоматично через `releaseCommand`)

## Локальний запуск
```bash
cd ~/Downloads/project_v2_online
python app.py       # порт 8090
```
Локально використовує SQLite (`dat_mailer_dev.db`).

## Environment Variables (Railway)
| Variable | Призначення |
|---|---|
| `SECRET_KEY` | Flask session ключ |
| `ENCRYPTION_KEY` | Fernet — шифрування Gmail паролів |
| `ADMIN_EMAIL` | Email першого адміна |
| `ADMIN_PASSWORD` | Пароль першого адміна |
| `DATABASE_URL` | PostgreSQL (Railway додає автоматично) |
| `REDIS_URL` | Rate limiting (Railway Redis, опціонально) |

## Авторизація
- Invite-only: адмін надсилає invite → юзер реєструється за токеном
- Сесії через Flask session + CSRF токени
- `@login_required` / `@admin_required` декоратори

## Ключові моделі
- `User` — юзери, поля: id (UUID), email, role (admin/free/starter/pro)
- `Invitation` — invite токени, `invited_by` = FK до `users.id` (UUID!)
- `EmailAccount` — Gmail акаунти юзерів (зашифровані паролі)
- `Send` / `Reply` / `FollowUp` — відправки та відповіді
- `Workspace` — неймспейс для даних юзера

## Відомі нюанси
- `invited_by` в `Invitation` — це UUID (`users.id`), не email. Використовувати `current_user_id()`
- Dev SQLite не перевіряє FK constraints, PostgreSQL перевіряє — тестувати критичні речі на prod-like БД
- `_send_invite_email()` silently fails якщо Gmail не налаштований — invite все одно зберігається в БД, посилання можна скопіювати з таблиці

## Адмін панель
URL: `/admin`
- Invite User → Send Invite → копіюй посилання з Copy Link
- Управління юзерами, статистика, акаунти
