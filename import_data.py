"""
DAT Mailer v2 — Data Import Script
Migrates existing JSON/CSV files from a v1 userdata directory into PostgreSQL.

Usage:
  python3 import_data.py --user your@email.com --src ~/Downloads/dat-webapp/
  python3 import_data.py --user your@email.com --src ~/path/to/userdata/safe_name/
"""
import argparse, csv, json, os, sys
from datetime import datetime

# Bootstrap Flask app context
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv
load_dotenv()

from app import app
from app.extensions import db
from app.models import (User, EmailAccount, Send, Reply, FollowUp,
                        PipelineContact, StopListEntry, Template)

def parse_dt(s, fmt='%Y-%m-%d %H:%M'):
    if not s: return None
    for f in (fmt, '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try: return datetime.strptime(str(s).strip(), f)
        except ValueError: pass
    return None


def import_for_user(email, src_dir):
    with app.app_context():
        user = User.query.filter_by(email=email.lower()).first()
        if not user:
            print(f"✗ User not found: {email}")
            sys.exit(1)
        uid = user.id
        print(f"→ Importing into user: {email} (id={uid})")

        # ── CONFIG ──────────────────────────────────────────────────────────
        cfg_file = os.path.join(src_dir, 'config.json')
        if os.path.exists(cfg_file):
            with open(cfg_file) as f: cfg = json.load(f)
            acct = EmailAccount.query.filter_by(user_id=uid).first()
            if not acct:
                acct = EmailAccount(user_id=uid)
                db.session.add(acct)
            acct.gmail_address  = cfg.get('gmail_address', '')
            acct.gmail_password = cfg.get('gmail_app_password', '')
            acct.your_name      = cfg.get('your_name', '')
            acct.your_company   = cfg.get('your_company', '')
            acct.your_phone     = cfg.get('your_phone', '')
            acct.delay_min      = int(cfg.get('delay_min', 20))
            acct.delay_max      = int(cfg.get('delay_max', 45))
            db.session.commit()
            print("  ✓ config.json")

        # ── SENT LOG ────────────────────────────────────────────────────────
        log_file = os.path.join(src_dir, 'sent_log.csv')
        if os.path.exists(log_file):
            imported = 0
            with open(log_file, newline='', encoding='utf-8') as f:
                for row in csv.DictReader(f):
                    db.session.add(Send(
                        user_id=uid,
                        recipient_email=row.get('email', ''),
                        origin=row.get('origin', ''), destination=row.get('destination', ''),
                        load_date=row.get('date', ''), equipment=row.get('equip', ''),
                        weight=row.get('weight', ''), company=row.get('company', ''),
                        template_variant=int(row.get('variant', 1) or 1),
                        status=row.get('status', 'sent'),
                        sent_at=parse_dt(row.get('timestamp', ''), '%Y-%m-%d %H:%M:%S') or datetime.utcnow(),
                    ))
                    imported += 1
            db.session.commit()
            print(f"  ✓ sent_log.csv → {imported} sends")

        # ── REPLIES ─────────────────────────────────────────────────────────
        replies_file = os.path.join(src_dir, 'replies.json')
        if os.path.exists(replies_file):
            with open(replies_file) as f: replies = json.load(f)
            imported = 0
            for r in replies:
                if Reply.query.filter_by(msg_id=r.get('msg_id','')).first(): continue
                db.session.add(Reply(
                    user_id=uid, msg_id=r.get('msg_id', f"import-{imported}"),
                    from_email=r.get('email', ''), from_name=r.get('from', ''),
                    subject=r.get('subject', ''), body=r.get('body', ''),
                    route=r.get('route', ''), status=r.get('status', 'new'),
                    received_at=parse_dt(r.get('received_at', '')) or datetime.utcnow(),
                ))
                imported += 1
            db.session.commit()
            print(f"  ✓ replies.json → {imported} replies")

        # ── FOLLOW-UPS ──────────────────────────────────────────────────────
        fu_file = os.path.join(src_dir, 'followups.json')
        if os.path.exists(fu_file):
            with open(fu_file) as f: fus = json.load(f)
            imported = 0
            for fu in fus:
                if FollowUp.query.filter_by(user_id=uid, contact_email=fu.get('email','')).first(): continue
                db.session.add(FollowUp(
                    user_id=uid, contact_email=fu.get('email',''),
                    contact_name=fu.get('from',''), route=fu.get('route',''),
                    reply_subject=fu.get('reply_subject',''),
                    reply_msg_id=fu.get('reply_msg_id',''),
                    level=fu.get('level','FU1'), status=fu.get('status','pending'),
                    notes=fu.get('notes',''),
                    added_at=parse_dt(fu.get('added_at','')) or datetime.utcnow(),
                    last_contact=parse_dt(fu.get('last_contact','')),
                    last_fu_sent=parse_dt(fu.get('last_fu_sent','')),
                ))
                imported += 1
            db.session.commit()
            print(f"  ✓ followups.json → {imported} follow-ups")

        # ── PIPELINE ────────────────────────────────────────────────────────
        pipeline_file = os.path.join(src_dir, 'pipeline.json')
        if os.path.exists(pipeline_file):
            with open(pipeline_file) as f: contacts = json.load(f)
            imported = 0
            for c in contacts:
                if PipelineContact.query.filter_by(user_id=uid, email=c.get('email','')).first(): continue
                db.session.add(PipelineContact(
                    user_id=uid, email=c.get('email','').lower(),
                    company=c.get('company',''), route=c.get('route',''),
                    stage=c.get('stage','new_lead'), notes=c.get('notes',''),
                    added_at=parse_dt(c.get('added_at','')) or datetime.utcnow(),
                    updated_at=parse_dt(c.get('updated_at','')) or datetime.utcnow(),
                ))
                imported += 1
            db.session.commit()
            print(f"  ✓ pipeline.json → {imported} contacts")

        # ── STOP LIST ───────────────────────────────────────────────────────
        stop_file = os.path.join(src_dir, 'stop_list.txt')
        if os.path.exists(stop_file):
            imported = 0
            with open(stop_file, encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    if line.lower().startswith('domain:'):
                        t, v = 'domain', line[7:].strip().lower()
                    elif line.lower().startswith('email:'):
                        t, v = 'email', line[6:].strip().lower()
                    elif '@' in line:
                        t, v = 'email', line.lower()
                    else: continue
                    if StopListEntry.query.filter_by(user_id=uid, type=t, value=v).first(): continue
                    db.session.add(StopListEntry(user_id=uid, type=t, value=v))
                    imported += 1
            db.session.commit()
            print(f"  ✓ stop_list.txt → {imported} entries")

        print("\n✓ Import complete.")


if __name__ == '__main__':
    p = argparse.ArgumentParser(description='Import v1 data into v2 database')
    p.add_argument('--user', required=True, help='User email to import data for')
    p.add_argument('--src',  required=True, help='Source directory (dat-webapp/ or userdata/email/)')
    args = p.parse_args()
    import_for_user(args.user, os.path.expanduser(args.src))
