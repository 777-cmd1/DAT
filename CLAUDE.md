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
- Railway щоразу ставить залежності заново: SQLAlchemy зафіксований `<2.1` (2.1 бере psycopg 3 для
  `postgresql://` → застосунок не стартує, healthcheck failure 2026-10-01); `_sqlalchemy_db_url` явно
  ставить `+psycopg2`. Нові залежності — з верхньою межею версії.

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
- Цитати: `_QUOTE_MARKERS` (зокрема перенесене «On …⏎wrote:», Outlook-риска `____`, рядки `>`);
  `_strip_quoted` = свій текст для тріажу/рейтів; `_quote_split` → `quote_at/quote_from/quote_mine` у /api/replies —
  картка показує текст відповіді, процитований лист згорнутий («Your email» / «Quoted email · адреса»).

## Follow-up каденс — додано 2026-07
- Залізне правило: активний контакт завжди має next_followup_at (`_schedule_touch`,
  хуки в reply-stop / stage-move / normalize-sweep). Лічильники Overdue/Today рахують
  БУДЬ-ЯКИЙ активний контакт з датою (enabled-прапорці гейтять лише авто-відправку).
- `Workspace.get_cadence()`: {stage_id: {days, mode}}; touch_hour ('auto' = найкраща
  година відповідей); шедулер Path 3 = авто-дотики, Path 4 = тижневий дайджест (Пн).
- 🔥 attention_at: відповідь від контакта стадії ≥2; OOO-автопауза: +7 днів.
- UI: Today's touches — сегмент-фільтр (`filter=touches`, бакет у `_fu_urgency`: due до локальної
  півночі + 🔥) і блок угорі таблиці з Send/+1d/+3d/+7d/Skip; швидкі дії на канбані; таймлайн
  (`/api/followups/timeline`). Окремої панелі більше нема.

## Insights (замість Dashboard / Analytics / Intelligence) — 2026-10
Стартова сторінка — **Send** (над чергою — тонкий рядок «Today X of N sent · replies · quota»).
`#/insights/<overview|lanes|domains|timing>`; старі `#/dashboard`, `#/stats`, `#/intelligence` редіректять.
Overview бере `/api/dashboard` (спільне `_dashboard_data` з дайджестом) + `/api/stats`. Один перемикач періоду
(Today / 7 / 30 days / All time) на Overview і Timing: `/api/stats?period=today|week|month|lifetime`, воронка
`funnel['today'|'7'|'30'|'all']` — ті самі локальні дні.
Send: після вставки поле DAT згортається в рядок (Edit розгортає); у черзі під статусом — причина пропуску,
тема листа — в підказці рядка (`buildSubject` = дзеркало `_build_subject`). Картка відправки: літачок на смузі,
відлік до наступного листа (`/api/send-status` → `next_in/next_total/next_email`), рядки черги живо міняють
статус (Queued → Sending… → Sent), лог з локальним часом (`at`), стан «Done» з тривалістю; переживає перезавантаження.
Сцена з траком (`truckSceneHtml` / `truckScene(road, frac, mode, sign, opts)`, CSS `.tk-*`): виїзд зі стартового доку,
стовпчик на кожен лист (≤20; помилка — конус), причіп за еквіпментом (`_truckEquip`: van/reefer/flat), фари вночі,
заїзд у фінальний док; той самий компонент у масовій відправці Follow-up (`#fuRoad`). Розмір трака — `--tw`.
ETA (`_spEta`: реальний темп між листами або `delay_avg` зі /api/send-status), підказки й клік на стовпчиках →
рядок черги (`focusQueueRow`), стоп-сигнали/аварійка/просідання, пейзаж з паралаксом (пауза, коли трак стоїть),
небо за темою, жовта осьова + білі крайові лінії, конверти з доку на фініші.
Дизайн-система: токени тем у першому `<style>` + шар «DESIGN SYSTEM (2026-10)» в кінці; семантика
кольорів accent=дія, red=проблема, yellow=увага, green=успіх, blue=інфо; одна головна кнопка на екран.
Undo: Pause / Block (Follow-up, і bulk), Ignore / Block (Replies), прибрати рейт — `toastUndo(msg, commit, revert)`:
дія чекає 5 с і лише тоді йде на сервер (pagehide → одразу, fetch keepalive); Undo = просто відкат вигляду.
Рух — 150-200 мс, лише функціональний; reduced-motion шанується і в JS. Сайдбар згортається (`sb-collapsed`).

## Інваріанти циклу 2026-09 (деталі — docs/PROJECT_OVERVIEW.md)
- Автовідправка: `pipeline_config.auto_send_enabled` — головний вимикач усіх авто-шляхів;
  шедулер перед відправкою сам перевіряє реплаї (`_prefetch_replies_before_sending`).
- Overdue/Today — тільки через `_fu_urgency(uid)`; reply rate — тільки `_reply_cohort` + `_reply_rate`.
- Відповідь колеги (писали dispatch@abc.com, відповів john@abc.com) — норма: `_ColleagueReplyMatcher`
  приймає її (тред Gmail або корпоративний домен + маршрут у темі), `Reply.matched_recipient` = кому писали;
  зупиняє дрип цього контакта і рахується в reply rate.
- Дата відповіді = Gmail internalDate (`_gmail_internal_date`); старі рядки виправляє `_backfill_reply_dates`
  (`replies.date_checked`). Пам'ять рейтів: `extract_rates` → `rate_quotes` (лінія + еквіпмент з нашого листа,
  `_rate_quote_load`), звіт `/api/intelligence/rates` → секція Rate history на Intelligence.
- «Сьогодні» — за поясом юзера (`pipeline_config.timezone`, `_user_tz`, `_local_day_start`);
  фіксована touch_hour — локальна година. БД-час лишається naive UTC.
- Імʼя контакта в UI — `FollowupContact.display_name` (JS `fuName/fuSub`).
- `replies`: UNIQUE (user_id, msg_id); будь-який пошук за msg_id — з фільтром user_id.
- Зміни схеми для проду — рантайм-міграції при старті в app.py (Alembic на Railway не покладатися).

## Процес деплою (конвенція цього репо)
- Розробка на робочій гілці → тести → пуш → **деплой у main ТІЛЬКИ після апрува юзера**.
- Перед деплоєм створюється rollback-гілка `rollback/<name>`; відкат = force-push її в main.
- Запарковано: `wave/b-smart-templates` (змінні шаблонів {contact_name}/{last_rate}/...).
- Повний контекст для нових сесій/інших моделей: **docs/PROJECT_OVERVIEW.md**.

## Тести
```bash
python -m pytest tests/test_parser.py tests/test_triage.py tests/test_touch.py tests/test_pipeline_kanban.py -q
```
Пофайлово зелені (~280, 23 файли, весь прогін ~1.5 хв). Повний прогін `tests/` має передіснуючі флейки ізоляції —
ганяти пофайлово. JS: `node --check` на витягнутих <script> з index.html.
conftest блокує реальний SMTP (`_no_real_smtp`): у понеділок шедулер шле дайджест, і без заглушки тест висить.
