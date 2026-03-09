# DAT Mailer — Deployment Guide

## Deploy to Railway in 5 steps

### 1. Підготуй репозиторій
```bash
# Перенеси всі файли в одну папку:
dat-mailer/
├── app.py              ← новий (з auth)
├── requirements.txt
├── Procfile
├── railway.json
├── create_admin.py
└── templates/
    ├── index.html      ← твій оригінальний файл
    ├── login.html      ← новий
    ├── register.html   ← новий
    └── admin.html      ← новий

# Ініціалізуй git
git init
git add .
git commit -m "Initial deploy"
```

### 2. Задеплой на Railway
1. Зайди на [railway.app](https://railway.app) → New Project
2. **Deploy from GitHub repo** → підключи свій репо
3. Або: Install Railway CLI → `railway up`

### 3. Встанови Environment Variables
В Railway dashboard → твій сервіс → Variables:

```
SECRET_KEY=будь-який-довгий-рандомний-рядок (напр: openssl rand -hex 32)
ADMIN_EMAIL=твій@email.com
```

### 4. Створи свій адмін акаунт
Після деплою в Railway Shell (або локально з тими ж файлами):
```bash
python create_admin.py
```
Введи email (має збігатися з ADMIN_EMAIL), ім'я, пароль.

### 5. Перший вхід
- Відкрий твій Railway URL
- Логінься своїм email/паролем
- Зайди на `/admin` → запроси перших юзерів

---

## Важливо про дані

Railway **скидає файлову систему** при кожному редеплої.
Тобто `sent_log.csv`, `replies.json`, `users.json` і т.д. — **зникнуть**.

### Рішення (вибери одне):

**A. Railway Volume (найпростіше)**
- В Railway: New → Volume → attach до сервісу
- Змінна: `DATA_DIR=/data`
- В `app.py` зміни `BASE_DIR` на `os.environ.get('DATA_DIR', BASE_DIR)`

**B. Просто backup перед деплоєм**
- Завантажуй `.json` і `.csv` файли перед оновленням
- Завантажуй назад після деплою через Railway Shell

---

## Додати юзера (після деплою)

1. Зайди на `yourapp.railway.app/admin`
2. Введи email нового юзера → Send Invite
3. Система надішле email з посиланням для реєстрації
4. Юзер переходить по посиланню → вводить ім'я та пароль → готово
