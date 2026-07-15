# DAT Mailer — повний огляд проєкту (handoff)

> Цей документ — самодостатній контекст для будь-якого AI-асистента або розробника.
> Актуальний станом на 2026-07-08. Основне джерело правди — код у репо `777-cmd1/DAT`.

## Що це
Flask веб-застосунок для автоматизації freight email outreach (агент Landstar шле
перевізникам пропозиції по лоудах з DAT/Truckstop, обробляє відповіді, веде follow-up).
- Prod: **https://dat-production-c105.up.railway.app** (Railway, проєкт aware-joy)
- Деплой: `git push origin main` → авторебілд ~1 хв. Міграції: Alembic (`flask db upgrade`
  через releaseCommand) + runtime `ALTER TABLE ADD COLUMN` список у `app.py` (`_migrations`).
- БД: PostgreSQL на проді, SQLite в dev/тестах. Авторизація invite-only, мультиюзер (Workspace).

## Стек і структура
```
app.py              — весь бекенд (маршрути, парсери, тріаж, каденс, шедулер)
app/models.py       — SQLAlchemy моделі + дефолтні конфіги пайплайна
templates/index.html — весь фронтенд (vanilla JS, одна сторінка, all-in-one)
tests/              — pytest: test_parser, test_triage, test_touch, test_pipeline_kanban, ...
```

## Основні підсистеми (в порядку робочого циклу користувача)

### 1. Send — парсинг і відправка
- `parse_dat_text()` / `parse_truckstop_text()` — парсять текст лоудборда в лоуди
  `{email, origin, destination, date, equip, ...}`; JS-дублікат `parseDatText()` в index.html
  для Review Queue. Відправка через Gmail API (OAuth) з фолбеком на SMTP app-password.
- Send-джоби: `SendJob` + воркер-тред; startup recovery позначає застряглі джоби error.

### 2. Replies — тріаж вхідних (напівавтомат)
- `classify_reply_text(subject, body, filters, keywords)` — чистий класифікатор:
  категорії `negative` / `gave_info` / `rate_request` / `auto_reply`.
  Пріоритет: auto_reply > negative > rate_request > gave_info.
  Цитати (`-----Original Message-----`, `On ... wrote:`, `From: ...@`) відрізаються
  (`_strip_quoted`); `Re:`-теми не дають структурних сигналів (це луна власного аутрічу).
  Структурні сигнали gave_info: $-суми, lbs, PU/DEL, FCFS, місто-штат, дати, NN ft (поріг: ≥3).
- Ключові слова — workspace-конфіг (`Workspace.get_filter_keywords()`), stored НАБОРИ
  обʼєднуються з дефолтними для built-in фільтрів (щоб оновлення словника доходили всім).
- Режими на категорію (`get_triage_modes()`): off / suggest / **auto**. Дефолт: suggest
  (крім auto_reply=auto). Suggest = лист лишається в New з бейджем; auto = дія одразу.
- Дії: negative/auto_reply → Ignore (Block ТІЛЬКИ вручну — свідоме рішення);
  gave_info/rate_request → follow_up + контакт у пайплайні + стадія з `auto_advance_to`.
- UI: чипи категорій з лічильниками, bulk «Ignore all» / «Follow-up all», стрічка
  Auto-processed з Undo, перескан усієї черги при кожному Check Gmail (самолікування
  після зміни словника). `##TSK_ID##...##` в тілах — службові маркери, ігноруються.
- OOO-автопауза: auto_reply від контакта пайплайна → next touch +7 днів, 🔥 знімається.

### 3. Follow-up — каденс-двигун («залізне правило»)
- Модель `FollowupContact`: стадії дрипа `fu1..fu3` + kanban `pipeline_stage` (1-5:
  Follow Pending / Got info (1st) / Got info 2 / Regular info / Booked; конфігурується).
- **Залізне правило: активний контакт завжди має `next_followup_at`** або терміналь.
  `_schedule_touch(fc, ws, force, stagger)` — серце: ставить дотик за каденсом стадії
  (`Workspace.get_cadence()`: {stage_id: {days, mode: manual/auto/off}}), stagger
  розкидає беклог по вікну, годину бере з `touch_hour` конфіга ('auto' = топ-година
  відповідей юзера, `_best_reply_hour`, фолбек 14 UTC).
- Хуки: reply-stop (відповідь зупиняє дрип І планує дотик + 🔥 `attention_at` для стадії ≥2),
  переходи стадій, завершення дрипа, лінивий sweep у `_normalize_followup_contact`.
- Лічильники Overdue/Today: **будь-який активний контакт з датою** (прапорці enabled
  керують лише авто-відправкою). Шедулер (15-хв тред): Path 0-2 дрип/одноразові/recurring,
  Path 3 авто-дотики (mode=auto), Path 4 тижневий дайджест (Пн ≥06:00 UTC, дедуп по даті).
- UI: панель «Today's touches» (скрол, згортання) з Send touch/+1/+3/+7/Skip;
  швидкі дії на канбан-картках; таймлайн контакту (`/api/followups/timeline`) —
  drawer з усією історією (відправки, відповіді з текстом, події стадій, нотатки).

### 4. Dashboard — головна сторінка
`/api/dashboard` (спільний `_dashboard_data(uid)` з дайджестом): Touches today / 🔥 /
Replies pending; воронка 7/30д (Sent→Replied→Got info→Repeat→Booked, з івент-логу);
здоровʼя (no_next_step, rotting 14д+, reply rate, avg touches→booked); activity 14д;
top lanes. Графіки — inline SVG, палітра з dataviz-валідатора, тема light/dark.

## Ключові API (нові відносно старої документації)
```
GET  /api/dashboard                    — всі блоки головної
GET  /api/replies?view=&cat=           — тріаж-черга, counts.categories
POST /api/replies/bulk-triage          — {category, action: ignore|followup|restore}
GET  /api/replies/auto-processed       — стрічка Undo
POST /api/replies/undo-auto            — відкат авто-дії
GET/PUT /api/followups/pipeline-config — stages, reply_filters, filter_keywords,
                                         triage_modes, cadence, touch_hour, digest_enabled
POST /api/followups/touch              — {id, action: snooze|skip|clear_attention, days}
GET  /api/followups/timeline?id=       — обʼєднана історія контакта
POST /api/followups/action             — send-now (дрип) / free-send (дотик) / ...
```

## Важливі колонки, додані останнім циклом
- `replies`: triage_category, triage_confidence, auto_processed, auto_action,
  reply_filter_key, auto_advanced, classified_at
- `followup_contacts`: touch_enabled, attention_at, pipeline_stage
- Конфіг workspace — JSON `workspaces.pipeline_config`: stages, reply_filters,
  filter_keywords, triage_modes, cadence, touch_hour, digest_enabled, last_digest_at

## Конвенції процесу
- Розробка на гілці `claude/kind-mayer-8okh8d`; **деплой тільки після апрува користувача**
  (merge --no-ff у main). Перед кожним деплоєм — rollback-гілка `rollback/<name>`
  (pre-triage, triage-v1..v4, pre-cadence, cadence-v1, pre-dashboard, pre-waveA/C/D...).
- Відкат: `git push --force origin rollback/<name>:main` або Railway Redeploy.
- **Запарковано**: гілка `wave/b-smart-templates` — змінні шаблонів {contact_name},
  {last_rate}, {last_route}, {days_since_reply} (реалізовано + тести; юзер відклав).
- Беклог: Фаза 4 — AI-класифікація вільного тексту (Claude Haiku) для реплаїв, які не
  ловляться правилами; merge контактів по домену; hotkeys у Today's touches.

## Тести
```
python -m pytest tests/ -q          # УВАГА: повний прогін має передіснуючі флейки ізоляції
python -m pytest tests/test_triage.py tests/test_touch.py tests/test_pipeline_kanban.py -q
```
Пофайлово все зелене (~100 тестів). JS перевіряється: `node --check` на витягнутих <script>.

## Відомі нюанси
- Dev SQLite не перевіряє FK, PostgreSQL перевіряє. Після деплою користувачу треба
  Ctrl+Shift+R (кеш JS). `invited_by` = UUID users.id. Gmail-паролі шифруються Fernet.
- Юзер працює з вимкненою авто-відправкою FU (default_enabled=false) — шле руками
  через Send Now / Send touch; тому «дата = зобовʼязання» в лічильниках критична.
