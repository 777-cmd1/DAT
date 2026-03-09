"""DAT Mailer Web App — with invite-only auth"""
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import re, csv, os, json, smtplib, random, threading, time, imaplib, secrets, hashlib
import email as email_lib
from datetime import datetime, date, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header as decode_email_header
from collections import Counter
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE    = os.path.join(BASE_DIR, "config.json")
LOG_FILE       = os.path.join(BASE_DIR, "sent_log.csv")
STOP_FILE      = os.path.join(BASE_DIR, "stop_list.txt")
TEMPLATES_FILE = os.path.join(BASE_DIR, "templates.json")
REPLIES_FILE   = os.path.join(BASE_DIR, "replies.json")
FOLLOWUPS_FILE = os.path.join(BASE_DIR, "followups.json")
USERS_FILE     = os.path.join(BASE_DIR, "users.json")
INVITES_FILE   = os.path.join(BASE_DIR, "invites.json")

# Your admin email — change this to your email
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'your@email.com')

send_state = {"running":False,"total":0,"current":0,"sent":0,"errors":0,"skipped":0,"log":[],"done":False}
DEFAULT_CONFIG = {"gmail_address":"","gmail_app_password":"","your_name":"","your_company":"","your_phone":"","delay_min":20,"delay_max":45}

# ─── AUTH HELPERS ──────────────────────────────────────────────────────────────

def hash_password(password):
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{h}"

def verify_password(password, stored):
    try:
        salt, h = stored.split(':')
        return hashlib.sha256((salt + password).encode()).hexdigest() == h
    except:
        return False

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f: return json.load(f)
    return []

def save_users(users):
    with open(USERS_FILE, 'w') as f: json.dump(users, f, indent=2)

def get_user(email):
    return next((u for u in load_users() if u['email'].lower() == email.lower()), None)

def load_invites():
    if os.path.exists(INVITES_FILE):
        with open(INVITES_FILE) as f: return json.load(f)
    return []

def save_invites(invites):
    with open(INVITES_FILE, 'w') as f: json.dump(invites, f, indent=2)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_email' not in session:
            if request.is_json:
                return jsonify({'error': 'Not authenticated'}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('user_email', '').lower() != ADMIN_EMAIL.lower():
            if request.is_json:
                return jsonify({'error': 'Admin only'}), 403
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET'])
def login_page():
    if 'user_email' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.json
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    user = get_user(email)
    if not user or not verify_password(password, user['password']):
        return jsonify({'error': 'Invalid email or password'}), 401
    session['user_email'] = user['email']
    session['user_name'] = user.get('name', email)
    return jsonify({'ok': True, 'name': user.get('name', email)})

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/auth/me', methods=['GET'])
def api_me():
    if 'user_email' not in session:
        return jsonify({'authenticated': False}), 401
    is_admin = session['user_email'].lower() == ADMIN_EMAIL.lower()
    return jsonify({'authenticated': True, 'email': session['user_email'], 'name': session.get('user_name'), 'is_admin': is_admin})

@app.route('/register/<token>', methods=['GET'])
def register_page(token):
    invites = load_invites()
    invite = next((i for i in invites if i['token'] == token and not i.get('used')), None)
    if not invite:
        return render_template('login.html', error='Invalid or expired invite link.')
    return render_template('register.html', token=token, email=invite['email'])

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.json
    token = data.get('token')
    password = data.get('password') or ''
    name = (data.get('name') or '').strip()

    invites = load_invites()
    invite = next((i for i in invites if i['token'] == token and not i.get('used')), None)
    if not invite:
        return jsonify({'error': 'Invalid or expired invite'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    email = invite['email'].lower()
    users = load_users()
    if any(u['email'].lower() == email for u in users):
        return jsonify({'error': 'Account already exists'}), 400

    users.append({
        'email': email,
        'name': name or email,
        'password': hash_password(password),
        'invited_by': invite.get('invited_by'),
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
    })
    save_users(users)

    # Mark invite as used
    for i in invites:
        if i['token'] == token:
            i['used'] = True
            i['used_at'] = datetime.now().strftime('%Y-%m-%d %H:%M')
    save_invites(invites)

    session['user_email'] = email
    session['user_name'] = name or email
    return jsonify({'ok': True})

# ─── ADMIN ROUTES ─────────────────────────────────────────────────────────────

@app.route('/admin')
@login_required
@admin_required
def admin_page():
    return render_template('admin.html')

@app.route('/api/admin/users', methods=['GET'])
@login_required
@admin_required
def api_admin_users():
    users = load_users()
    safe = [{'email': u['email'], 'name': u.get('name'), 'created_at': u.get('created_at'), 'invited_by': u.get('invited_by')} for u in users]
    return jsonify(safe)

@app.route('/api/admin/invite', methods=['POST'])
@login_required
@admin_required
def api_admin_invite():
    data = request.json
    email = (data.get('email') or '').strip().lower()
    if not email or '@' not in email:
        return jsonify({'error': 'Invalid email'}), 400

    # Check if already a user
    if get_user(email):
        return jsonify({'error': 'User already exists'}), 400

    token = secrets.token_urlsafe(32)
    invites = load_invites()
    # Remove old unused invites for same email
    invites = [i for i in invites if not (i['email'].lower() == email and not i.get('used'))]
    invites.append({
        'token': token,
        'email': email,
        'invited_by': session['user_email'],
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
        'used': False,
    })
    save_invites(invites)

    # Send invite email
    base_url = request.host_url.rstrip('/')
    invite_url = f"{base_url}/register/{token}"
    _send_invite_email(email, invite_url)

    return jsonify({'ok': True, 'invite_url': invite_url})

@app.route('/api/admin/invites', methods=['GET'])
@login_required
@admin_required
def api_admin_invites():
    return jsonify(load_invites())

@app.route('/api/admin/users/delete', methods=['POST'])
@login_required
@admin_required
def api_admin_delete_user():
    email = (request.json.get('email') or '').lower()
    if email == ADMIN_EMAIL.lower():
        return jsonify({'error': 'Cannot delete admin'}), 400
    users = [u for u in load_users() if u['email'].lower() != email]
    save_users(users)
    return jsonify({'ok': True})

def _send_invite_email(to_email, invite_url):
    """Send invite email using the configured Gmail account."""
    try:
        cfg = load_config()
        if not cfg.get('gmail_address') or not cfg.get('gmail_app_password'):
            return False
        msg = MIMEMultipart()
        msg['From'] = cfg['gmail_address']
        msg['To'] = to_email
        msg['Subject'] = "You've been invited to DAT Mailer"
        body = f"""Hi,

You've been invited to use DAT Mailer — a freight outreach automation tool.

Click the link below to create your account:
{invite_url}

This link expires after first use.

Best regards,
DAT Mailer Team"""
        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(cfg['gmail_address'], cfg['gmail_app_password'])
            s.sendmail(cfg['gmail_address'], to_email, msg.as_string())
        return True
    except:
        return False

# ─── CONFIG ───────────────────────────────────────────────────────────────────

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f: return {**DEFAULT_CONFIG, **json.load(f)}
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    with open(CONFIG_FILE,'w') as f: json.dump(cfg,f,indent=2)

DEFAULT_TEMPLATES = [
    "Hi,\n\nAre you still working on this load?\nPlease provide more info.\n\nThanks,\n{name}\n{company} | {phone}",
    "Hello,\n\nLoad from {origin} to {destination}, is it still available?\nPlease provide more details.\n\nThank you,\n{name}\n{company} | {phone}",
    "Hello,\n\nSaw your load posting — is this still active?\nPlease advise details.\n\nThanks,\n{name}\n{company} | {phone}",
]

def load_templates():
    if os.path.exists(TEMPLATES_FILE):
        with open(TEMPLATES_FILE) as f: data = json.load(f)
        if isinstance(data, list): return data
        if isinstance(data, dict): return data.get('outreach', DEFAULT_TEMPLATES.copy())
    return DEFAULT_TEMPLATES.copy()

def save_templates_file(t):
    with open(TEMPLATES_FILE,'w') as f: json.dump(t,f,indent=2)

def render_template_text(tmpl, load, cfg):
    return tmpl.format(name=cfg.get("your_name",""),company=cfg.get("your_company",""),
        phone=cfg.get("your_phone",""),origin=load.get("origin",""),
        destination=load.get("destination",""),date=load.get("date",""),equip=load.get("equip",""))

def load_stop_list():
    be, bd = set(), set()
    if not os.path.exists(STOP_FILE): return be, bd
    with open(STOP_FILE,encoding='utf-8') as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith('#'): continue
            if line.lower().startswith('domain:'): bd.add(line[7:].strip().lower())
            elif line.lower().startswith('email:'): be.add(line[6:].strip().lower())
            elif '@' in line: be.add(line.lower())
    return be, bd

def get_stop_list_raw():
    entries=[]
    if not os.path.exists(STOP_FILE): return entries
    with open(STOP_FILE,encoding='utf-8') as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith('#'): continue
            if line.lower().startswith('domain:'): entries.append({"type":"domain","value":line[7:].strip()})
            elif line.lower().startswith('email:'): entries.append({"type":"email","value":line[6:].strip()})
            elif '@' in line: entries.append({"type":"email","value":line})
    return entries

def write_stop_list(entries):
    with open(STOP_FILE,'w',encoding='utf-8') as f:
        f.write("# STOP LIST\n")
        for e in entries:
            f.write(f"{'domain' if e['type']=='domain' else 'email'}:{e['value'].strip().lower()}\n")

def is_blocked(email, be, bd):
    em=email.strip().lower()
    if em in be: return True
    dom=em.split('@')[-1] if '@' in em else ''
    return bool(dom and dom in bd)

LOG_FIELDS=['timestamp','email','origin','destination','date','equip','weight','company','status','variant']

def load_sent_log():
    all_sent,sent_today=set(),set()
    today=date.today().strftime('%Y-%m-%d')
    if not os.path.exists(LOG_FILE): return all_sent,sent_today
    with open(LOG_FILE,newline='',encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if row.get('status')!='sent': continue
            em=row.get('email','').lower().strip()
            orig=row.get('origin','').strip()
            dest=row.get('destination','').strip()
            ts=row.get('timestamp','')
            day=ts[:10] if len(ts)>=10 else ''
            all_sent.add(f"{em}|{orig}|{dest}")
            if day==today: sent_today.add(em)
    return all_sent,sent_today

def append_log(load, status, variant=0):
    exists=os.path.exists(LOG_FILE)
    with open(LOG_FILE,'a',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=LOG_FIELDS)
        if not exists: w.writeheader()
        w.writerow({'timestamp':datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'email':load['email'],'origin':load['origin'],'destination':load['destination'],
            'date':load['date'],'equip':load['equip'],'weight':load.get('weight',''),
            'company':load.get('company',''),'status':status,'variant':variant})

def get_log_rows():
    if not os.path.exists(LOG_FILE): return []
    rows=[]
    with open(LOG_FILE,newline='',encoding='utf-8') as f:
        for row in csv.DictReader(f):
            rows.append({k:(v if v is not None else '') for k,v in row.items()})
    return list(reversed(rows))

def load_replies():
    if os.path.exists(REPLIES_FILE):
        with open(REPLIES_FILE) as f: return json.load(f)
    return []

def save_replies(replies):
    with open(REPLIES_FILE,'w') as f: json.dump(replies,f,indent=2,ensure_ascii=False)

def decode_str(s):
    if s is None: return ""
    parts=decode_email_header(s)
    result=[]
    for part,enc in parts:
        if isinstance(part,bytes): result.append(part.decode(enc or 'utf-8',errors='replace'))
        else: result.append(str(part))
    return " ".join(result)

def get_email_body(msg):
    body=""
    if msg.is_multipart():
        for part in msg.walk():
            ct=part.get_content_type()
            disp=str(part.get("Content-Disposition",""))
            if ct=="text/plain" and "attachment" not in disp:
                try: body=part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8',errors='replace'); break
                except: pass
    else:
        try: body=msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8',errors='replace')
        except: pass
    lines,clean=body.split('\n'),[]
    for line in lines:
        if line.startswith('>') or (line.startswith('On ') and 'wrote:' in line): break
        clean.append(line)
    return '\n'.join(clean).strip()[:1000]

def get_known_emails():
    known=set()
    if not os.path.exists(LOG_FILE): return known
    with open(LOG_FILE,newline='',encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if row.get('email'): known.add(row['email'].lower().strip())
    return known

def get_route_for_email(email_addr):
    email_addr=email_addr.lower().strip()
    last=None
    if not os.path.exists(LOG_FILE): return ""
    with open(LOG_FILE,newline='',encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if row.get('email','').lower().strip()==email_addr: last=row
    if last: return f"{last.get('origin','')} → {last.get('destination','')}"
    return ""

_last_fetch_time = 0

def fetch_replies_from_gmail():
    global _last_fetch_time
    cfg=load_config()
    if not cfg.get('gmail_address') or not cfg.get('gmail_app_password'): return {'error':'Gmail not configured'}
    now = time.time()
    if now - _last_fetch_time < 60:
        wait = int(60 - (now - _last_fetch_time))
        return {'error': f'Please wait {wait}s before checking again', 'rate_limited': True}
    _last_fetch_time = now
    known=get_known_emails()
    existing=load_replies()
    existing_ids={r['msg_id'] for r in existing}
    new_replies=[]
    try:
        mail=imaplib.IMAP4_SSL('imap.gmail.com')
        mail.login(cfg['gmail_address'],cfg['gmail_app_password'])
        mail.select('INBOX')
        import email.utils
        since_date = (datetime.now() - timedelta(days=30)).strftime('%d-%b-%Y')
        _,data=mail.search(None, f'SINCE {since_date}')
        msg_ids=data[0].split()[-100:]
        for mid in reversed(msg_ids):
            try:
                _,msg_data=mail.fetch(mid,'(BODY.PEEK[])')
                if not msg_data or not msg_data[0]: continue
                raw=msg_data[0][1]
                msg=email_lib.message_from_bytes(raw)
                msg_id=msg.get('Message-ID',str(mid))
                if msg_id in existing_ids: continue
                from_addr=decode_str(msg.get('From',''))
                em=re.search(r'[\w.+\-]+@[\w.\-]+\.\w+',from_addr)
                if not em: continue
                sender=em.group().lower()
                if sender not in known: continue
                new_replies.append({'msg_id':msg_id,'email':sender,'from':from_addr,
                    'subject':decode_str(msg.get('Subject','')),'date':msg.get('Date',''),
                    'body':get_email_body(msg),'route':get_route_for_email(sender),
                    'status':'new','received_at':datetime.now().strftime('%Y-%m-%d %H:%M')})
            except Exception: continue
        mail.logout()
    except Exception as e: return {'error':str(e)}
    all_replies=new_replies+existing
    save_replies(all_replies)
    return {'new':len(new_replies),'total':len(all_replies)}

def get_stats():
    empty={"total":0,"sent":0,"errors":0,"today":0,"by_day":[],"by_variant":[],"by_hour":[],
           "top_recipients":[],"top_routes":[],"replied_emails":[],"replied_domains":[],"response_rate":{}}
    if not os.path.exists(LOG_FILE): return empty
    today_str=date.today().strftime('%Y-%m-%d')
    total=sent=errors=today_count=0
    by_day,by_var,by_em,by_route,by_hr=Counter(),Counter(),Counter(),Counter(),Counter()
    with open(LOG_FILE,newline='',encoding='utf-8') as f:
        for row in csv.DictReader(f):
            total+=1
            st=row.get('status','')
            ts=row.get('timestamp','')
            day=ts[:10] if len(ts)>=10 else 'unknown'
            hr=ts[11:13] if len(ts)>=13 else '00'
            if st=='sent':
                sent+=1; by_day[day]+=1; by_var[str(row.get('variant','?'))]+=1; by_hr[hr]+=1
                if day==today_str: today_count+=1
                em=row.get('email','').lower().strip()
                orig=row.get('origin','').strip(); dest=row.get('destination','').strip()
                if em: by_em[em]+=1
                if orig and dest: by_route[f"{orig} → {dest}"]+=1
            elif st=='error': errors+=1
    replies=load_replies()
    tr=len(replies)
    interested=sum(1 for r in replies if r.get('status')=='interested')
    not_int=sum(1 for r in replies if r.get('status')=='not_interested')
    new_r=sum(1 for r in replies if r.get('status')=='new')
    rr=round(100*tr/sent,1) if sent>0 else 0
    rc,rs,dc=Counter(),{},Counter()
    for r in replies:
        em=r.get('email','').lower().strip()
        if em:
            rc[em]+=1; rs[em]=r.get('status','new')
            if '@' in em: dc[em.split('@')[1]]+=1
    return {
        "total":total,"sent":sent,"errors":errors,"today":today_count,
        "by_day":[{"date":d,"count":c} for d,c in sorted(by_day.items())[-14:]],
        "by_variant":[{"variant":v,"count":c} for v,c in sorted(by_var.items())],
        "by_hour":[{"hour":f"{h:02d}:00","count":by_hr.get(f"{h:02d}",0)} for h in range(24)],
        "top_recipients":[{"email":e,"count":c} for e,c in by_em.most_common(10)],
        "top_routes":[{"route":r,"count":c} for r,c in by_route.most_common(10)],
        "replied_emails":[{"email":e,"count":c,"status":rs.get(e,'new')} for e,c in rc.most_common()],
        "replied_domains":[{"domain":d,"count":c} for d,c in dc.most_common()],
        "response_rate":{"total_replies":tr,"interested":interested,"not_interested":not_int,"new":new_r,"pct":rr},
    }

# ── AUTOMATION IMPACT ───────────────────────────────────────────────────────
AI_MANUAL_SEC = 40
AI_BATCH_SIZE = 30
AI_BATCH_SETUP_SEC = 20
AI_DELAY_PER_EMAIL_SEC = 10
AI_ACTIONS_PER_EMAIL = 4
AI_WORKDAY_HOURS = 8

def _ai_format_duration(seconds):
    seconds = max(0, float(seconds or 0))
    if seconds < 60: return f"{round(seconds)}s"
    if seconds < 3600:
        minutes = seconds / 60
        if abs(minutes - round(minutes)) < 0.05: return f"{int(round(minutes))} min"
        return f"{minutes:.1f} min"
    hours = seconds / 3600
    return f"{hours:.1f} hr"

def _ai_calc_from_count(emails_sent):
    emails_sent = int(emails_sent or 0)
    batches = (emails_sent + AI_BATCH_SIZE - 1) // AI_BATCH_SIZE if emails_sent else 0
    manual_time_sec = emails_sent * AI_MANUAL_SEC
    auto_time_sec = batches * AI_BATCH_SETUP_SEC + emails_sent * AI_DELAY_PER_EMAIL_SEC
    time_saved_sec = max(0, manual_time_sec - auto_time_sec)
    manual_actions_avoided = emails_sent * AI_ACTIONS_PER_EMAIL
    manual_speed = round(60 / AI_MANUAL_SEC, 1)
    auto_speed = round(emails_sent / (auto_time_sec / 60), 1) if auto_time_sec else 0
    speed_multiplier = round(manual_time_sec / auto_time_sec, 1) if auto_time_sec else 0
    hours_saved = round(time_saved_sec / 3600, 1)
    working_days_saved = round(hours_saved / AI_WORKDAY_HOURS, 1)
    return {
        'emails_sent': emails_sent, 'batches': batches,
        'manual_time_sec': manual_time_sec, 'auto_time_sec': auto_time_sec,
        'time_saved_sec': time_saved_sec, 'manual_actions_avoided': manual_actions_avoided,
        'manual_speed': manual_speed, 'auto_speed': auto_speed,
        'speed_multiplier': speed_multiplier, 'hours_saved': hours_saved,
        'working_days_saved': working_days_saved,
        'manual_time_fmt': _ai_format_duration(manual_time_sec),
        'auto_time_fmt': _ai_format_duration(auto_time_sec),
        'time_saved_fmt': _ai_format_duration(time_saved_sec),
    }

def get_automation_impact():
    today = date.today()
    week_start = today - timedelta(days=today.weekday())
    daily_counts = Counter()
    hourly_counts = Counter()
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, newline='', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                if row.get('status') != 'sent': continue
                ts = (row.get('timestamp') or '').strip()
                if len(ts) < 13: continue
                daily_counts[ts[:10]] += 1
                hourly_counts[ts[11:13]] += 1
    lifetime_count = sum(daily_counts.values())
    today_key = today.strftime('%Y-%m-%d')
    week_total = sum(c for d, c in daily_counts.items()
        if len(d) == 10 and datetime.strptime(d, '%Y-%m-%d').date() >= week_start)
    daily_rows = []
    for d in sorted(daily_counts.keys())[-14:]:
        calc = _ai_calc_from_count(daily_counts[d])
        calc.update({'date': d, 'emails': daily_counts[d], 'actions_avoided': calc['manual_actions_avoided']})
        daily_rows.append(calc)
    best_day = None
    if daily_rows:
        best = max(daily_rows, key=lambda r: r['time_saved_sec'])
        best_day = {'date': best['date'], 'emails': best['emails'], 'time_saved_fmt': best['time_saved_fmt']}
    peak_hour = None
    if hourly_counts:
        peak = max(hourly_counts.items(), key=lambda kv: kv[1])[0]
        peak_hour = f"{peak}:00"
    return {
        'today': _ai_calc_from_count(daily_counts.get(today_key, 0)),
        'week': _ai_calc_from_count(week_total),
        'lifetime': _ai_calc_from_count(lifetime_count),
        'daily': daily_rows,
        'best_day': best_day,
        'peak_hour': peak_hour,
    }

def parse_dat_text(text):
    loads = []
    email_pattern = re.compile(r'[\w.+\-]+@[\w.\-]+\.\w+')
    lines = text.strip().split('\n')
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        emails = email_pattern.findall(line)
        if emails:
            load = {'email': emails[0], 'origin': '', 'destination': '', 'date': '', 'equip': '', 'weight': '', 'length': '', 'company': ''}
            context = '\n'.join(lines[max(0, i-5):i+3])
            origin_match = re.search(r'([A-Z][a-zA-Z\s]+,\s*[A-Z]{2})\s*(?:to|→|->)\s*([A-Z][a-zA-Z\s]+,\s*[A-Z]{2})', context)
            if origin_match:
                load['origin'] = origin_match.group(1).strip()
                load['destination'] = origin_match.group(2).strip()
            date_match = re.search(r'\b(\d{1,2}/\d{1,2}(?:/\d{2,4})?)\b', context)
            if date_match: load['date'] = date_match.group(1)
            equip_match = re.search(r'\b(Van|Reefer|Flatbed|Step\s*Deck|RGN|Tanker|Auto|Dray|Power\s*Only)\b', context, re.I)
            if equip_match: load['equip'] = equip_match.group(1)
            weight_match = re.search(r'(\d[\d,]+)\s*(?:lbs?|pounds?)', context, re.I)
            if weight_match: load['weight'] = weight_match.group(1).replace(',', '')
            loads.append(load)
        i += 1
    return loads

def send_one_email(to_email, subject, body, cfg):
    try:
        msg = MIMEMultipart()
        msg['From'] = cfg['gmail_address']
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(cfg['gmail_address'], cfg['gmail_app_password'])
            s.sendmail(cfg['gmail_address'], to_email, msg.as_string())
        return True, None
    except Exception as e: return False, str(e)

def run_send_job(loads, cfg, templates):
    global send_state
    send_state.update({"running":True,"done":False,"total":len(loads),"current":0,"sent":0,"errors":0,"skipped":0,"log":[]})
    _, sent_today_csv = load_sent_log()
    session_sent = set()
    for i, load in enumerate(loads):
        send_state["current"] = i + 1
        em = load['email'].lower().strip()
        if em in sent_today_csv or em in session_sent:
            send_state["skipped"] += 1
            send_state["log"].append({"time":datetime.now().strftime('%H:%M:%S'),"status":"skipped","variant":0,"email":load["email"],"error":"already sent today"})
            continue
        tmpl = random.choice(templates); vi = templates.index(tmpl) + 1
        body = render_template_text(tmpl, load, cfg)
        parts = [load['origin'], load['destination'], load['date'], load['equip'], load.get('length',''), load.get('weight','')]
        subject = " | ".join(p for p in parts if p)
        ok, err = send_one_email(load['email'], subject, body, cfg)
        ts = datetime.now().strftime('%H:%M:%S'); st = 'sent' if ok else 'error'
        append_log(load, st, vi)
        if ok:
            session_sent.add(em)
            send_state["sent"] += 1
        else:
            send_state["errors"] += 1
        send_state["log"].append({"time":ts,"status":st,"variant":vi,"email":load["email"],"error":err or ""})
        if i < len(loads) - 1:
            time.sleep(random.randint(cfg.get("delay_min", 20), cfg.get("delay_max", 45)))
    send_state.update({"running": False, "done": True})

# ─── API ROUTES (all protected) ───────────────────────────────────────────────

@app.route('/api/config', methods=['GET'])
@login_required
def api_get_config():
    cfg = load_config(); safe = {k:v for k,v in cfg.items() if k != 'gmail_app_password'}
    safe['has_password'] = bool(cfg.get('gmail_app_password')); return jsonify(safe)

@app.route('/api/config', methods=['POST'])
@login_required
def api_save_config():
    data = request.json; cfg = load_config()
    for k in ['gmail_address','gmail_app_password','your_name','your_company','your_phone','delay_min','delay_max']:
        if k in data and data[k] != '': cfg[k] = data[k]
    save_config(cfg); return jsonify({"ok": True})

@app.route('/api/templates', methods=['GET'])
@login_required
def api_get_templates(): return jsonify(load_templates())

@app.route('/api/templates', methods=['POST'])
@login_required
def api_save_templates():
    outreach = request.json.get("templates", [])
    existing = {}
    if os.path.exists(TEMPLATES_FILE):
        with open(TEMPLATES_FILE) as f: existing = json.load(f)
    if isinstance(existing, list): existing = {}
    existing['outreach'] = outreach
    with open(TEMPLATES_FILE, 'w') as f: json.dump(existing, f, indent=2)
    return jsonify({"ok": True})

@app.route('/api/stop-list', methods=['GET'])
@login_required
def api_get_stop(): return jsonify(get_stop_list_raw())

@app.route('/api/stop-list', methods=['POST'])
@login_required
def api_save_stop(): write_stop_list(request.json.get("entries", [])); return jsonify({"ok": True})

@app.route('/api/parse', methods=['POST'])
@login_required
def api_parse():
    raw = request.json.get("text", "")
    if not raw: return jsonify({"error": "No text"}), 400
    all_loads = parse_dat_text(raw)
    be, bd = load_stop_list(); all_sent, sent_today = load_sent_log()
    result = []; stats = {"total":len(all_loads),"new":0,"skip_today":0,"skip_dup":0,"skip_stop":0}
    for l in all_loads:
        key = f"{l['email']}|{l['origin']}|{l['destination']}"
        if is_blocked(l['email'], be, bd): l['skip'] = 'stop_list'; stats["skip_stop"] += 1
        elif l['email'].lower() in sent_today: l['skip'] = 'today'; stats["skip_today"] += 1
        elif key in all_sent: l['skip'] = 'duplicate'; stats["skip_dup"] += 1
        else: l['skip'] = None; stats["new"] += 1
        result.append(l)
    return jsonify({"loads": result, "stats": stats})

@app.route('/api/send', methods=['POST'])
@login_required
def api_send():
    global send_state
    if send_state["running"]: return jsonify({"error": "Already running"}), 400
    loads = request.json.get("loads", [])
    if not loads: return jsonify({"error": "No loads"}), 400
    cfg = load_config()
    if not cfg.get("gmail_address") or not cfg.get("gmail_app_password"): return jsonify({"error": "Gmail not configured"}), 400
    t = threading.Thread(target=run_send_job, args=(loads, cfg, load_templates())); t.daemon = True; t.start()
    return jsonify({"ok": True, "total": len(loads)})

@app.route('/api/send-status', methods=['GET'])
@login_required
def api_send_status(): return jsonify(send_state)

@app.route('/api/automation-impact', methods=['GET'])
@login_required
def api_automation_impact(): return jsonify(get_automation_impact())

@app.route('/api/stats', methods=['GET'])
@login_required
def api_stats(): return jsonify(get_stats())

@app.route('/api/log', methods=['GET'])
@login_required
def api_log(): return jsonify(get_log_rows())

@app.route('/api/replies', methods=['GET'])
@login_required
def api_get_replies(): return jsonify(load_replies())

@app.route('/api/replies/fetch', methods=['POST'])
@login_required
def api_fetch_replies(): return jsonify(fetch_replies_from_gmail())

@app.route('/api/replies/status', methods=['POST'])
@login_required
def api_reply_status():
    data = request.json; msg_id = data.get('msg_id'); status = data.get('status')
    add_to_stop = data.get('add_to_stop', False)
    replies = load_replies(); reply_obj = None
    for r in replies:
        if r['msg_id'] == msg_id:
            r['status'] = status; reply_obj = r; break
    save_replies(replies)
    if reply_obj:
        stage_map = {'new':'replied','interested':'interested','not_interested':'lost'}
        upsert_pipeline(reply_obj.get('email',''), {
            'stage': stage_map.get(status, 'replied'),
            'company': reply_obj.get('from','').split('<')[0].strip(),
            'route': reply_obj.get('route',''),
        })
    if status == 'interested' and reply_obj:
        add_to_followups(reply_obj)
    if add_to_stop and reply_obj:
        entries = get_stop_list_raw()
        em = reply_obj.get('email','')
        if em and not any(e['value'] == em for e in entries):
            entries.append({'type':'email','value':em}); write_stop_list(entries)
    return jsonify({'ok': True})

@app.route('/')
@login_required
def index(): return render_template('index.html')

# ─── FOLLOW-UPS ───────────────────────────────────────────────────────────────
def load_followups():
    if os.path.exists(FOLLOWUPS_FILE):
        with open(FOLLOWUPS_FILE) as f: return json.load(f)
    return []

def save_followups(fus):
    with open(FOLLOWUPS_FILE, 'w') as f: json.dump(fus, f, indent=2, ensure_ascii=False)

def add_to_followups(reply):
    fus = load_followups()
    if any(fu['email'] == reply['email'] for fu in fus):
        for fu in fus:
            if fu['email'] == reply['email']:
                fu['reply_subject'] = reply.get('subject','')
                fu['route'] = reply.get('route','')
                break
        save_followups(fus); return
    fus.append({
        'email': reply['email'], 'from': reply.get('from', reply['email']),
        'route': reply.get('route',''), 'reply_subject': reply.get('subject',''),
        'reply_msg_id': reply.get('msg_id',''), 'level': 'FU1', 'status': 'pending',
        'added_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
        'last_contact': reply.get('received_at', datetime.now().strftime('%Y-%m-%d %H:%M')),
        'last_fu_sent': None, 'notes': '',
    })
    save_followups(fus)

def send_followup_email(fu, template_text, cfg):
    try:
        msg = MIMEMultipart()
        msg['From'] = cfg['gmail_address']; msg['To'] = fu['email']
        msg['Subject'] = 'Re: ' + fu['reply_subject'] if fu.get('reply_subject') else 'Follow-up'
        if fu.get('reply_msg_id'):
            msg['In-Reply-To'] = fu['reply_msg_id']; msg['References'] = fu['reply_msg_id']
        body = template_text.format(
            name=cfg.get('your_name',''), company=cfg.get('your_company',''),
            phone=cfg.get('your_phone',''), route=fu.get('route',''),
            origin=fu.get('route','').split('→')[0].strip() if '→' in fu.get('route','') else '',
            destination=fu.get('route','').split('→')[1].strip() if '→' in fu.get('route','') else '',
        )
        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(cfg['gmail_address'], cfg['gmail_app_password'])
            s.sendmail(cfg['gmail_address'], fu['email'], msg.as_string())
        return True, None
    except Exception as e: return False, str(e)

LEVEL_PROGRESSION = {'FU1': 'FU2', 'FU2': 'FU3', 'FU3': 'closed'}

def get_fu_templates():
    if os.path.exists(TEMPLATES_FILE):
        with open(TEMPLATES_FILE) as f: data = json.load(f)
        if isinstance(data, dict): return data.get('followup', {})
    return {
        'FU1': "Hi,\n\nJust wanted to follow up — are you working on any loads this week?\n\nThank you,\n{name}\n{company} | {phone}",
        'FU2': "Hello,\n\nFollowing up again — do you have any loads available?\n\nThanks,\n{name}\n{company} | {phone}",
        'FU3': "Hi,\n\nLast follow-up — if you have loads in the future, please reach out.\n\nBest,\n{name}\n{company} | {phone}",
    }

@app.route('/api/followups', methods=['GET'])
@login_required
def api_get_followups(): return jsonify(load_followups())

@app.route('/api/followups/send', methods=['POST'])
@login_required
def api_send_followup():
    data = request.json; emails = data.get('emails', [])
    cfg = load_config()
    if not cfg.get('gmail_address') or not cfg.get('gmail_app_password'):
        return jsonify({'error': 'Gmail not configured'}), 400
    fu_templates = get_fu_templates(); fus = load_followups(); results = []
    for fu in fus:
        if fu['email'] not in emails: continue
        if fu['status'] == 'closed': continue
        level = fu.get('level', 'FU1')
        tmpl = fu_templates.get(level, fu_templates.get('FU1', ''))
        ok, err = send_followup_email(fu, tmpl, cfg)
        if ok:
            fu['last_fu_sent'] = datetime.now().strftime('%Y-%m-%d %H:%M')
            fu['last_contact'] = fu['last_fu_sent']; fu['status'] = 'sent'
            next_level = LEVEL_PROGRESSION.get(level, 'closed')
            fu['level'] = next_level
            if next_level == 'closed': fu['status'] = 'closed'
        results.append({'email': fu['email'], 'ok': ok, 'error': err or '', 'new_level': fu.get('level')})
    save_followups(fus)
    return jsonify({'results': results})

@app.route('/api/followups/update', methods=['POST'])
@login_required
def api_update_followup():
    data = request.json; email = data.get('email'); fus = load_followups()
    for fu in fus:
        if fu['email'] == email:
            if 'status' in data: fu['status'] = data['status']
            if 'level' in data: fu['level'] = data['level']
            if 'notes' in data: fu['notes'] = data['notes']
            break
    save_followups(fus); return jsonify({'ok': True})

@app.route('/api/followups/delete', methods=['POST'])
@login_required
def api_delete_followup():
    email = request.json.get('email')
    save_followups([f for f in load_followups() if f['email'] != email])
    return jsonify({'ok': True})

@app.route('/api/fu-templates', methods=['GET'])
@login_required
def api_get_fu_templates(): return jsonify(get_fu_templates())

@app.route('/api/fu-templates', methods=['POST'])
@login_required
def api_save_fu_templates():
    data = request.json; existing = {}
    if os.path.exists(TEMPLATES_FILE):
        with open(TEMPLATES_FILE) as f: existing = json.load(f)
    if isinstance(existing, list): existing = {'outreach': existing}
    existing['followup'] = data
    with open(TEMPLATES_FILE, 'w') as f: json.dump(existing, f, indent=2)
    return jsonify({'ok': True})

# ── PIPELINE ──────────────────────────────────────────────────────────────────
PIPELINE_FILE = os.path.join(BASE_DIR, 'pipeline.json')
STAGES = ['new_lead', 'contacted', 'replied', 'interested', 'deal', 'lost']

def load_pipeline():
    if os.path.exists(PIPELINE_FILE):
        with open(PIPELINE_FILE) as f: return json.load(f)
    return []

def save_pipeline(contacts):
    with open(PIPELINE_FILE, 'w') as f: json.dump(contacts, f, indent=2)

def upsert_pipeline(email, updates):
    contacts = load_pipeline()
    existing = next((c for c in contacts if c['email'].lower() == email.lower()), None)
    if existing:
        existing.update(updates); existing['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M')
    else:
        new_contact = {'email': email, 'company': updates.get('company',''), 'route': updates.get('route',''),
            'stage': updates.get('stage','new_lead'), 'notes': '', 'deal_value': '',
            'added_at': datetime.now().strftime('%Y-%m-%d %H:%M'), 'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M')}
        new_contact.update(updates); contacts.append(new_contact)
    save_pipeline(contacts)
    return existing or contacts[-1]

@app.route('/api/pipeline', methods=['GET'])
@login_required
def api_get_pipeline(): return jsonify(load_pipeline())

@app.route('/api/pipeline/add', methods=['POST'])
@login_required
def api_add_pipeline():
    d = request.json; contact = upsert_pipeline(d['email'], d)
    return jsonify({'ok': True, 'contact': contact})

@app.route('/api/pipeline/update', methods=['POST'])
@login_required
def api_update_pipeline():
    d = request.json; email = d.get('email'); contacts = load_pipeline()
    for c in contacts:
        if c['email'].lower() == email.lower():
            for k, v in d.items():
                if k != 'email': c[k] = v
            c['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M')
    save_pipeline(contacts); return jsonify({'ok': True})

@app.route('/api/pipeline/delete', methods=['POST'])
@login_required
def api_delete_pipeline():
    email = request.json.get('email')
    save_pipeline([c for c in load_pipeline() if c['email'].lower() != email.lower()])
    return jsonify({'ok': True})

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    # Create admin user if no users exist
    if not load_users() and ADMIN_EMAIL != 'your@email.com':
        print(f"No users found. Creating admin account for {ADMIN_EMAIL}")
        print("Set ADMIN_PASSWORD env var or use /api/admin/invite to invite users")
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
