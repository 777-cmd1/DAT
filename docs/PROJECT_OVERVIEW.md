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
  Path 3 авто-дотики (mode=auto), Path 4 тижневий дайджест (Пн ≥06:00 за поясом юзера, дедуп по локальній даті).
- UI: «Today's touches» — сегмент-фільтр (`filter=touches`, бакет `_fu_urgency`) і блок угорі
  таблиці (due до локальної півночі + 🔥) з Send/+1d/+3d/+7d/Skip; State злитий у Stage
  (показується, лише коли не Active); Last activity = остання подія (Replied / You emailed);
  швидкі дії на канбан-картках; таймлайн контакту (`/api/followups/timeline`) —
  drawer з усією історією (відправки, відповіді з текстом, події стадій, нотатки).

### 4. Insights — одна сторінка замість Dashboard / Analytics / Intelligence (2026-10)
Вкладки `#/insights/overview|lanes|domains|timing` (старі хеші редіректять). Overview:
воронка 7/30д плитками з конверсією між кроками (з `/api/dashboard`, спільний
`_dashboard_data(uid)` з дайджестом), здоровʼя бази, activity 14д — два малі графіки
(відправки і відповіді окремо, ніколи дві осі), якість відповідей. Lanes & Rates: rate requests,
Rate history (sparkline + «last $X vs avg»), сигнали, таблиця ліній. Стартова сторінка застосунку —
Send; декоративні віджети Send (Broadcast Pulse, Automation Impact, Quota) замінив рядок статусу.

## Ключові API (нові відносно старої документації)
```
GET  /api/dashboard                    — всі блоки головної
GET  /api/replies?view=&cat=           — тріаж-черга, counts.categories
POST /api/replies/bulk-triage          — {category, action: ignore|followup|restore}
GET  /api/replies/auto-processed       — стрічка Undo
POST /api/replies/undo-auto            — відкат авто-дії
GET/PUT /api/followups/pipeline-config — stages, reply_filters, filter_keywords,
                                         triage_modes, cadence, touch_hour, digest_enabled,
                                         auto_send_enabled, drip_auto_enabled, timezone,
                                         auto_send_preview (GET/PUT відповідь); PUT приймає
                                         лише передані ключі (вкладки Settings шлють своє)
POST /api/followups/touch              — {id, action: snooze|skip|clear_attention, days}
GET  /api/followups/timeline?id=       — обʼєднана історія контакта
POST /api/followups/action             — send-now (дрип) / free-send (дотик) / ...
```

## Важливі колонки, додані останнім циклом
- `replies`: triage_category, triage_confidence, auto_processed, auto_action,
  reply_filter_key, auto_advanced, classified_at
- `followup_contacts`: touch_enabled, attention_at, pipeline_stage
- Конфіг workspace — JSON `workspaces.pipeline_config`: stages, reply_filters,
  filter_keywords, triage_modes, cadence, touch_hour, digest_enabled, last_digest_at,
  auto_send_enabled (головний вимикач), timezone (IANA)
- `users.session_version` (logout/скидання пароля вбиває всі сесії);
  `replies`: UNIQUE (user_id, msg_id) замість глобального UNIQUE (msg_id)

## Цикл 2026-09 (аудит → пакети 2, 1, 3, 5, 4)
- **Безпека**: OAuth `state` обовʼязковий; `/health` без адреси Redis; ProxyFix
  (Railway = 1 хоп, `PROXY_HOPS` перевизначає); ліміти на reset-request (IP + email).
- **Безпечна автовідправка**: перед кожним запуском шедулер сам тягне реплаї
  (`_prefetch_replies_before_sending`, збій → утримання авто-відправок юзера);
  `auto_send_enabled` гейтить шляхи 0–3; авто-дрип за замовчуванням вимкнений;
  bounce → Stop List + Block; Block однаковий з Replies і Follow-up.
- **UX**: адреси `#/page` (Back/Reload), старт — Dashboard; Settings на вкладках
  Account / Sending / Automation / Pipeline, у кожної свій Save; банер
  «Auto-send ON: ~N за 24 год» (`_auto_send_preview`); `FollowupContact.display_name`
  — одне імʼя скрізь; таблиця показує стадію пайплайну і реальний наступний дотик;
  словник термінів (виграш = **Booked**, в Analytics Follow-up/Needs Action/Ignored).
- **Цілісність**: одне визначення Overdue/Today (`_fu_urgency`) для списку, лічильників
  і select-all; **reply rate** = частка унікальних контактів, яким писали у вікні, що
  відповіли з початку вікна — самі або через колегу (`_reply_cohort` + `_reply_rate`, 0..100%) — Dashboard,
  Analytics, Intelligence, дайджест; пояс юзера (`_user_tz`, `_local_day_start`) для
  «сьогодні», фіксованої години дотику й дайджесту (квоти й адмінка — UTC);
  авто-FU3 одразу ставить дотик.
- **Відповіді колег**: раніше лист від адреси, на яку не писали, відкидався при завантаженні.
  Тепер `_ColleagueReplyMatcher` приймає його, якщо він у Gmail-треді нашого листа до відомого
  контакта, або з того ж корпоративного домену з маршрутом нашого листа в темі (публічні пошти й
  власний домен — тільки через тред). `replies.matched_recipient` = адреса, якій писали.
- **Пам'ять рейтів** (2026-10): рейти з відповідей (від $300; $/mi окремо; detention/TONU/lumper/hr
  відкидаються) → `rate_quotes` з лінією й еквіпментом листа, на який відповіли; Intelligence → Rate
  history (фільтри місто/еквіпмент/період, ✕ прибирає хибний рядок). Дата = коли відповідь прийшла
  (Gmail internalDate; старі відповіді виправляються фоном на Check Gmail).
- Міграції схеми на проді — у рантаймі при старті (`_migrations`,
  `_migrate_reply_msg_id_per_user`); перевірено на локальному PostgreSQL 16.

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
Пофайлово все зелене (~250 тестів, 22 файли). JS перевіряється: `node --check` на витягнутих <script>.

## Відомі нюанси
- Dev SQLite не перевіряє FK, PostgreSQL перевіряє. Після деплою користувачу треба
  Ctrl+Shift+R (кеш JS). `invited_by` = UUID users.id. Gmail-паролі шифруються Fernet.
- Юзер працює з вимкненою авто-відправкою FU (default_enabled=false) — шле руками
  через Send Now / Send touch; тому «дата = зобовʼязання» в лічильниках критична.
