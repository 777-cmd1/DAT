"""Seed the local dev DB with realistic demo data for admin@local.dev.
Usage: .venv/bin/python scripts/seed_demo.py
Never run against production — refuses if DATABASE_URL is set.
"""
import importlib.util, os, random, sys, uuid
from datetime import datetime, timedelta, UTC

if os.environ.get('DATABASE_URL'):
    sys.exit('DATABASE_URL is set — refusing to seed a non-dev database')

os.environ.setdefault('DISABLE_SCHEDULER', '1')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
spec = importlib.util.spec_from_file_location('_dat', os.path.join(ROOT, 'app.py'))
m = importlib.util.module_from_spec(spec)
sys.modules['_dat'] = m
spec.loader.exec_module(m)

from app.models import (User, Send, Reply, FollowupContact, PipelineContact,
                        StopListEntry, UsageEvent, Workspace)

LANES = [
    ('Laredo, TX', 'Chicago, IL'), ('Dallas, TX', 'Atlanta, GA'),
    ('Houston, TX', 'Memphis, TN'), ('El Paso, TX', 'Phoenix, AZ'),
    ('San Antonio, TX', 'Denver, CO'), ('Savannah, GA', 'Nashville, TN'),
    ('Long Beach, CA', 'Salt Lake City, UT'), ('Newark, NJ', 'Columbus, OH'),
    ('Miami, FL', 'Charlotte, NC'), ('Kansas City, MO', 'Minneapolis, MN'),
]
EQUIP = ['V', 'R', 'F', 'SD', 'PO']
COMPANIES = ['Apex Freight', 'BlueLine Logistics', 'Cargomax', 'DeltaHaul',
             'Eagle Trans', 'FreightWorks', 'GoldStar Carriers', 'Horizon Loads',
             'Interstate Pro', 'Jetline Freight', 'Keystone Cargo', 'Liberty Hauling']
FIRST = ['mike', 'sarah', 'john', 'lisa', 'dave', 'anna', 'tom', 'kate', 'rob', 'amy']
REPLY_BODIES = [
    'Yes, the load is still available. Can you do it for $2,800 all in?',
    'Covered already, but send me your MC — we have similar lanes weekly.',
    'What is your rate? Truck needs to be there by 8am.',
    'Not interested, please remove me from your list.',
    'Still working on it. Call me at the office.',
    'We have loads out of that area every Monday — interested?',
]

def email_for(i, company):
    dom = company.lower().replace(' ', '') + '.com'
    return f'{random.choice(FIRST)}.{i}@{dom}'

def utcnow():
    return datetime.now(UTC).replace(tzinfo=None)

with m.app.app_context():
    admin = User.query.filter_by(email='admin@local.dev').first()
    if not admin:
        sys.exit('admin@local.dev not found — create it first')
    ws = Workspace.query.filter_by(owner_id=admin.id).first()
    uid, wsid = admin.id, ws.id
    now = utcnow()
    rng = random.Random(42)

    if Send.query.filter_by(user_id=uid).count() > 50:
        sys.exit('Looks already seeded — aborting to avoid duplicates')

    # ── Sends: ~420 over the last 30 days, weekday-weighted ──────────────────
    sends = []
    for d in range(30):
        day = now - timedelta(days=d)
        if day.weekday() >= 5 and rng.random() < .7:
            continue
        for _ in range(rng.randint(8, 24)):
            company = rng.choice(COMPANIES)
            o, dst = rng.choice(LANES)
            status = rng.choices(['sent', 'error', 'skipped'], weights=[92, 4, 4])[0]
            ts = day.replace(hour=rng.randint(8, 17), minute=rng.randint(0, 59))
            sends.append(Send(
                user_id=uid, workspace_id=wsid,
                recipient_email=email_for(rng.randint(1, 99), company),
                origin=o, destination=dst,
                load_date=(day + timedelta(days=rng.randint(1, 4))).strftime('%m/%d'),
                equipment=rng.choice(EQUIP), weight=f'{rng.randint(28, 46)},000 lbs',
                company=company, template_variant=rng.randint(1, 3),
                status=status, sent_at=ts,
                error_msg='SMTP timeout' if status == 'error' else None,
            ))
    m.db.session.add_all(sends)

    # ── Usage events (quota history) ─────────────────────────────────────────
    by_day = {}
    for s in sends:
        if s.status == 'sent':
            by_day[s.sent_at.date()] = by_day.get(s.sent_at.date(), 0) + 1
    for day, cnt in by_day.items():
        m.db.session.add(UsageEvent(user_id=uid, workspace_id=wsid,
                                    event_type='email_sent', count=cnt, period_date=day))

    # ── Replies: ~36, mixed statuses ──────────────────────────────────────────
    sent_pool = [s for s in sends if s.status == 'sent']
    for i, s in enumerate(rng.sample(sent_pool, 36)):
        st = rng.choices(['new', 'interested', 'not_interested'], weights=[40, 35, 25])[0]
        m.db.session.add(Reply(
            user_id=uid, workspace_id=wsid,
            msg_id=f'<demo-{uuid.uuid4()}@mail.gmail.com>',
            thread_id=f'thread{1000+i}',
            from_email=s.recipient_email,
            from_name=s.company,
            subject=f'Re: {s.origin} to {s.destination}, {s.load_date}',
            body=rng.choice(REPLY_BODIES),
            route=f'{s.origin} → {s.destination}',
            status=st,
            received_at=s.sent_at + timedelta(hours=rng.randint(1, 48)),
        ))

    # ── Follow-up contacts across states/stages ───────────────────────────────
    fu_specs = (
        [('active', 'fu1_scheduled')] * 6 + [('active', 'fu2_scheduled')] * 4 +
        [('active', 'fu3_scheduled')] * 3 + [('active', 'completed_fu3')] * 2 +
        [('warm', 'fu2_sent')] * 3 + [('loads', 'fu1_sent')] * 2 +
        [('paused', 'fu2_scheduled')] * 2 + [('blocked', 'fu1_sent')] * 1 +
        [('closed', 'completed_fu3')] * 2
    )
    for i, (state, stage) in enumerate(fu_specs):
        s = rng.choice(sent_pool)
        nfa = now + timedelta(days=rng.randint(-1, 5)) if state == 'active' and stage.endswith('_scheduled') else None
        m.db.session.add(FollowupContact(
            user_id=uid, workspace_id=wsid,
            contact_email=f'fu{i}.' + s.recipient_email,
            contact_name=rng.choice(FIRST).title() + ' ' + rng.choice(['Smith', 'Jones', 'Lee', 'Brown']),
            company_name=s.company, state=state, stage=stage,
            is_followup_enabled=(state == 'active'),
            next_followup_at=nfa,
            last_followup_sent_at=now - timedelta(days=rng.randint(1, 6)) if 'sent' in stage or stage == 'completed_fu3' else None,
            initial_email_sent_at=now - timedelta(days=rng.randint(5, 20)),
            current_route=f'{s.origin} → {s.destination}',
            reply_subject=f'Re: {s.origin} to {s.destination}',
            created_at=now - timedelta(days=rng.randint(5, 25)),
        ))

    # ── Pipeline ───────────────────────────────────────────────────────────────
    stages = ['new_lead', 'contacted', 'replied', 'interested', 'deal', 'lost']
    for i in range(14):
        s = rng.choice(sent_pool)
        st = rng.choice(stages)
        m.db.session.add(PipelineContact(
            user_id=uid, workspace_id=wsid,
            email=f'pipe{i}.' + s.recipient_email, company=s.company,
            route=f'{s.origin} → {s.destination}', stage=st,
            deal_value=rng.choice([None, 1800, 2400, 3100, 4500]) if st in ('interested', 'deal') else None,
            notes='Weekly lane, prefers morning pickups.' if rng.random() < .4 else '',
        ))

    # ── Stop list ──────────────────────────────────────────────────────────────
    for i in range(5):
        m.db.session.add(StopListEntry(user_id=uid, workspace_id=wsid, type='email',
                                       value=f'unsubscribed{i}@example.com', reason='asked to be removed'))
    m.db.session.add(StopListEntry(user_id=uid, workspace_id=wsid, type='domain',
                                   value='nospamfreight.com', reason='complaint'))

    m.db.session.commit()
    print(f'Seeded: {len(sends)} sends, 36 replies, {len(fu_specs)} follow-ups, 14 pipeline, 6 stop-list')
