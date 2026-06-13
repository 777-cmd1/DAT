# SETUP — робота над DAT Mailer з будь-якого комп'ютера

Покрокова інструкція, щоб підняти проєкт на новій машині, працювати локально
й безпечно деплоїти. Прод живе на Railway, код — на GitHub
(`https://github.com/777-cmd1/DAT`).

---

## 1. Що потрібно на новому комп'ютері

- **Git** (на macOS вже є; перевір `git --version`)
- **Python 3.12+** (обов'язково — код використовує `datetime.UTC`, на 3.11 і нижче не запуститься)
  - macOS: `brew install python@3.12`
- **Personal Access Token** від GitHub (той самий `ghp_...`, що вже створений) —
  потрібен для `clone` / `push` приватного репо

---

## 2. Перший раз: клонувати й налаштувати

```bash
# забрати код (куди завгодно, напр. у домашню теку)
git clone https://github.com/777-cmd1/DAT.git
cd DAT

# віртуальне середовище + залежності
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

> Коли git попросить логін — `Username` це твій GitHub-нік (`777-cmd1`),
> `Password` це Personal Access Token (`ghp_...`), **не** звичайний пароль.

---

## 3. Запуск локально

```bash
.venv/bin/python app.py
```

Відкриється на **http://localhost:8090**, працює на локальній **SQLite**
(`dat_mailer_dev.db`) — повністю окремо від прода. Тут можна експериментувати
без ризику для реальних даних.

### Створити локального адміна (для входу)

```bash
.venv/bin/python - <<'EOF'
import importlib.util, sys, os
sys.path.insert(0, os.getcwd()); os.environ['DISABLE_SCHEDULER']='1'
spec = importlib.util.spec_from_file_location('_dat','app.py')
m = importlib.util.module_from_spec(spec); sys.modules['_dat']=m; spec.loader.exec_module(m)
from app.models import User
with m.app.app_context():
    if not User.query.filter_by(email='admin@local.dev').first():
        u = User(email='admin@local.dev', name='Local Admin',
                 password=m.hash_password('admin12345'), role='admin', invited_by='system')
        m.db.session.add(u); m.db.session.flush()
        m.get_or_create_workspace(u.id, name='Admin Workspace'); m.db.session.commit()
        print('created admin@local.dev / admin12345')
    else: print('already exists')
EOF
```

Логін: `admin@local.dev` / `admin12345`

### Залити демо-дані (необов'язково, для тестів)

```bash
.venv/bin/python scripts/seed_demo.py
```

Додає ~360 відправок, відповіді, follow-up'и тощо у локальну БД.
Скрипт **відмовляється** працювати, якщо виставлений `DATABASE_URL`, тому
випадково зачепити прод неможливо.

---

## 4. Щоденний git-цикл

**Перед** роботою — завжди підтягни останнє (щоб машини не розходились):

```bash
git pull origin main
```

**Після** змін:

```bash
git add -A
git commit -m "короткий опис змін"
git push origin main        # → Railway автоматично передеплоїть
```

> Кожен `push` у `main` запускає деплой на Railway. Якщо хочеш зберегти зміни,
> але **не** деплоїти одразу — працюй в окремій гілці:
> `git checkout -b моя-фіча`, комить туди, а в `main` вливай, коли готово.

---

## 5. Запустити тести

```bash
.venv/bin/python -m pytest tests/ -q
```

Має бути «passed». Ганяй перед кожним push у `main`.

---

## 6. Прод (Railway) — довідка

- Деплой: будь-який `git push origin main` → Railway сам білдить і піднімає
- БД: PostgreSQL (Railway підключає через `DATABASE_URL`)
- Обов'язкові env-змінні (вкладка **Variables** у Railway):
  `SECRET_KEY`, `ENCRYPTION_KEY`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`
  (без `SECRET_KEY`/`ENCRYPTION_KEY` застосунок навмисно не стартане)
- URL сайту: Railway → сервіс → **Settings → Networking → Domains**
- Логи й статус деплою: Railway → сервіс → **Deployments**

### Якщо деплой впав
Railway → **Deployments** → відкрий деплой → **Logs** → дивись останню помилку.
Швидкий відкат на попередній робочий стан:

```bash
git revert -m 1 <хеш-merge-комміту>
git push origin main
```

---

## 7. Не комітити в репо

Локальна БД і середовище не повинні потрапляти в git (вони вже в `.gitignore`):
`.venv/`, `dat_mailer_dev.db`. Якщо `git status` показує їх — не додавай.

---

## Швидка шпаргалка

```bash
git pull origin main                    # підтягнути останнє
.venv/bin/python app.py                 # запустити локально (:8090)
.venv/bin/python -m pytest tests/ -q    # тести
git add -A && git commit -m "..."       # зберегти зміни
git push origin main                    # задеплоїти
```
