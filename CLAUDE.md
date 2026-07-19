# DAT Mailer Online — Claude Code Context

## Що це
Flask веб-застосунок для автоматизації freight email outreach.
Версія v2 з invite-only авторизацією, мультиюзерністю, PostgreSQL.
Production URL: **https://dat-production-c105.up.railway.app**

## Структура
```
app.py              — головний Flask файл (маршрути, логіка)
app/models.py       — SQLAlchemy моделі (User, Invitation, Send, Reply, FollowUp, ...)
app/extensions.py   — db, migrate ініціалізація
templates/
  index.html        — весь фронтенд (vanilla JS) — також містить JS-парсер parseDatText()
  admin.html        — адмін панель
  login.html        — логін
  register.html     — реєстрація по invite-токену
migrations/         — Alembic міграції
wsgi.py             — gunicorn entry point
tests/test_parser.py — pytest тести для parse_dat_text()
requirements.txt
```

## Деплой
- Платформа: **Railway**, проект **aware-joy**
- Репо: `https://github.com/777-cmd1/DAT`
- Деплой: `git push origin main` → Railway передеплоює автоматично (~1 хв)
- БД: PostgreSQL (Railway підключає через `DATABASE_URL`)
- Міграції: `flask db upgrade` (запускається автоматично через `releaseCommand`)
- **GitHub App встановлено** — Claude може пушити в репо напряму через `git push origin main`

## Парсинг лоудів — КЛЮЧОВА ЛОГІКА

### Два формати лоудбордів
Застосунок парсить два різних формати:

**1. DAT** — простий формат (назва компанії, origin, destination, equip, дата, email)
**2. Truckstop** — детальні картки (відрізняються структурою: містять "Days to Pay", "Additional Stops", "Estimated Fuel Cost")

### Python-парсер (app.py)
- `parse_truckstop_text(text)` — структурний парсер для Truckstop-карток
- `parse_dat_text(text)` — головна функція; якщо бачить маркери Truckstop → делегує до `parse_truckstop_text()`
- Детекція Truckstop: `re.search(r'(?i)\bdays to pay\b', text) and re.search(r'(?i)\b(?:additional stops|estimated fuel cost)\b', text)`
- Результат: `{email, origin, destination, date, equip, length, weight, company, contact}`
- `_build_subject(load)` — будує тему імейлу: `"Origin to Destination, date, equip, length"`
- `_EQUIP_LABELS` — словник кодів: `V→Van, F→Flatbed, RGN→RGN` тощо

### JS-парсер (templates/index.html, функція parseDatText)
- **Окремий парсер у браузері** — заповнює Review Queue (UI)
- Регекси: `_CITY_RE`, `_EQUIP_RE`, `_DATE_RE`, `_WT_RE`, `_LEN_RE`
- `_CITY_RE = /^([A-Z][a-zA-Z\s\.]+,\s*[A-Z]{2})(?:\s+[\d,]+\s*mi\b)?(?:\s*\(\d*\))?$/`
  - Суфікс `N mi` дозволено — Truckstop додає дистанцію до назви міста (`Laredo, TX 1 mi`)
- `_EQUIP_RE = /\b(FSDV|FSDVR|SDL|SV|RGN|LB|MX|HS|AC|TN|PO|VM|VR|FD|SD|V|F|R)\b/g`
  - Включає всі Truckstop-коди
- Origin/destination: беруться передостаннє і останнє місто з блоку (`cities[length-2]`, `cities[length-1]`)
- **Важливо**: JS-парсер показує дані у черзі, Python-парсер будує subject відправленого імейлу

### Truckstop-специфічні нюанси
- Origin-рядок може містити суфікс відстані: `"Laredo, TX 19 mi"` → origin = `"Laredo, TX"`
- Equip-коди багатосимвольні: `FSDV` (Flatbed/Step Deck/Van), `SDL` (Step Deck/Lowboy), `SV` (Step/Van)
- Company = рядок перед "Days to Pay ..."
- Contact = рядок перед номером телефону (або перед email якщо нема телефону)
- Телефони з `Ext`: `(785) 748-2700 Ext 3` — розпізнається як телефон, не контакт
- `Days to Pay N/AEXP R` — валідний формат (N/A = не вказано)

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
- `_send_invite_email()` silently fails якщо Gmail не налаштований — invite все одно зберігається в БД
- Після деплою браузер може кешувати старий JS — користувачу треба Ctrl+Shift+R якщо бачить старе

## Адмін панель
URL: `/admin`
- Invite User → Send Invite → копіюй посилання з Copy Link
- Управління юзерами, статистика, акаунти

## Reply triage (напівавтомат) — додано 2026-07
- `classify_reply_text()` в app.py: категорії negative/gave_info/rate_request/auto_reply;
  цитати відрізаються (`_strip_quoted`), Re:-теми не дають сигналів; keywords —
  workspace-конфіг, stored НАБОРИ обʼєднуються з дефолтами (`get_filter_keywords`).
- Режими off/suggest/auto на категорію (`get_triage_modes`, дефолт suggest, OOO=auto).
- Block — тільки вручну. Check Gmail пересканує всю живу чергу (самолікування словника).

## Follow-up каденс — додано 2026-07
- Залізне правило: активний контакт завжди має next_followup_at (`_schedule_touch`,
  хуки в reply-stop / stage-move / normalize-sweep). Лічильники Overdue/Today рахують
  БУДЬ-ЯКИЙ активний контакт з датою (enabled-прапорці гейтять лише авто-відправку).
- `Workspace.get_cadence()`: {stage_id: {days, mode}}; touch_hour ('auto' = найкраща
  година відповідей); шедулер Path 3 = авто-дотики, Path 4 = тижневий дайджест (Пн).
- 🔥 attention_at: відповідь від контакта стадії ≥2; OOO-автопауза: +7 днів.
- UI: Today's touches панель, швидкі дії на канбані, таймлайн (`/api/followups/timeline`).

## Dashboard
Головна сторінка: `/api/dashboard` (спільне `_dashboard_data` з дайджестом) —
дії дня, воронка 7/30д з івент-логу, здоровʼя бази, activity 14д, top lanes.

## Процес деплою (конвенція цього репо)
- Розробка на робочій гілці → тести → пуш → **деплой у main ТІЛЬКИ після апрува юзера**.
- Перед деплоєм створюється rollback-гілка `rollback/<name>`; відкат = force-push її в main.
- Запарковано: `wave/b-smart-templates` (змінні шаблонів {contact_name}/{last_rate}/...).
- Повний контекст для нових сесій/інших моделей: **docs/PROJECT_OVERVIEW.md**.

## Тести
```bash
python -m pytest tests/test_parser.py tests/test_triage.py tests/test_touch.py tests/test_pipeline_kanban.py -q
```
Пофайлово зелені (~100). Повний прогін `tests/` має передіснуючі флейки ізоляції —
ганяти пофайлово. JS: `node --check` на витягнутих <script> з index.html.
