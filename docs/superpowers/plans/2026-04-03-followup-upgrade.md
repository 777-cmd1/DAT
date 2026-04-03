# Follow-up System Upgrade — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the Follow-up system with bulk selection, two send modes (sequence/free), one-time + recurring scheduling, and an expandable FU template pool with random selection.

**Architecture:** Three-layer change — (1) add recurring fields to FollowupContact model + DB migration, (2) extend backend actions/routes and scheduler, (3) update frontend with checkboxes, bulk bar, schedule modal, and template management. All changes are additive; existing sequence logic is preserved.

**Tech Stack:** Flask, SQLAlchemy, PostgreSQL (Railway), vanilla JS, single-file frontend (templates/index.html)

**Spec:** docs/superpowers/specs/2026-04-03-followup-upgrade-design.md

---

## Task 1: Add Recurring Fields to FollowupContact + DB Migration

**Files:**
- Modify: app/models.py — add 3 columns to FollowupContact, update to_dict()

- [ ] **Step 1: Add columns to FollowupContact**

In app/models.py, after line 271 (updated_at column), add:

```python
    recurring_enabled = db.Column(db.Boolean, default=False, nullable=False, server_default='false')
    recurring_days    = db.Column(db.String(20))   # "0,2,4" = Mon/Wed/Fri
    recurring_time    = db.Column(db.String(5))    # "HH:MM" UTC
```

- [ ] **Step 2: Add new fields to to_dict()**

In app/models.py inside to_dict() (after the 'reply_subject' key), add:

```python
            'recurring_enabled': self.recurring_enabled,
            'recurring_days':    self.recurring_days or '',
            'recurring_time':    self.recurring_time or '',
```

- [ ] **Step 3: Run DB migration**

```bash
cd /Users/bohdanbezverkhyi/Downloads/project_v2_online
flask db migrate -m "add recurring fields to followup_contacts"
flask db upgrade
```

Expected: migration file created in migrations/versions/, upgrade applies without error.

If Flask-Migrate is not initialized: flask db init first.

If migrations folder does not exist or alembic is not configured, add columns directly via a startup script:
```python
with app.app_context():
    from sqlalchemy import text
    db.session.execute(text("ALTER TABLE followup_contacts ADD COLUMN IF NOT EXISTS recurring_enabled BOOLEAN NOT NULL DEFAULT FALSE"))
    db.session.execute(text("ALTER TABLE followup_contacts ADD COLUMN IF NOT EXISTS recurring_days VARCHAR(20)"))
    db.session.execute(text("ALTER TABLE followup_contacts ADD COLUMN IF NOT EXISTS recurring_time VARCHAR(5)"))
    db.session.commit()
```

- [ ] **Step 4: Verify columns exist**

```bash
flask shell
>>> from app.models import FollowupContact
>>> FollowupContact.__table__.columns.keys()
# Must include: recurring_enabled, recurring_days, recurring_time
```

- [ ] **Step 5: Commit**

```bash
git add app/models.py migrations/
git commit -m "feat: add recurring fields to FollowupContact model"
```

---

## Task 2: Fix Send Now Bug + Add Random Template Helper

**Files:**
- Modify: app.py — send-now handler (lines 2994-3002), add helper near line 3379

- [ ] **Step 1: Fix EmailAccount attribute names in send-now handler**

In app.py at lines 2994-3002, replace the template_key/template_text lookup and cfg dict:

```python
        # Replace lines 2994-2996 (old template lookup):
        template_text = _get_random_fu_template(uid)
        if not template_text:
            return jsonify(error='No active follow-up templates. Add at least one before sending.'), 400

        acct = EmailAccount.query.filter_by(user_id=uid).first()
        if not acct:
            return jsonify(error='No email account configured'), 400

        # Replace lines 3001-3002 (wrong attribute names):
        cfg = {'name': acct.your_name or '', 'company': acct.your_company or '',
               'phone': acct.your_phone or '', 'route': fc.current_route or ''}
```

- [ ] **Step 2: Add _get_random_fu_template() helper**

Add this function immediately before _run_scheduled_followups (around line 3386):

```python
def _get_random_fu_template(uid):
    """Pick a random active follow-up template body for the given user.
    Falls back to DEFAULT_FU_TEMPLATES pool if no custom templates exist."""
    import random
    from app.models import Template
    rows = Template.query.filter_by(user_id=uid, type='followup', is_active=True).all()
    if rows:
        return random.choice(rows).body or ''
    return random.choice(list(DEFAULT_FU_TEMPLATES.values()))
```

- [ ] **Step 3: Commit**

```bash
git add app.py
git commit -m "fix: correct EmailAccount field names in send-now, add random template picker"
```

---

## Task 3: New Single-Contact Actions (free-send, schedule-once, set-recurring, stop-recurring)

**Files:**
- Modify: app.py — api_followups_action() (lines 2988-3052)

- [ ] **Step 1: Add _next_recurring_datetime() helper**

Add alongside _get_random_fu_template() (before _run_scheduled_followups):

```python
def _next_recurring_datetime(recurring_days, recurring_time):
    """Return next UTC datetime matching one of recurring_days at recurring_time (UTC).
    recurring_days: comma-separated weekday ints string, 0=Mon...6=Sun
    recurring_time: "HH:MM" UTC
    Checks today first — if today matches and time is still future, schedules today.
    """
    from datetime import timedelta
    days = [int(d) for d in recurring_days.split(',') if d.strip().isdigit()]
    if not days:
        raise ValueError(f'recurring_days is empty or invalid: {recurring_days!r}')
    h, m = map(int, recurring_time.split(':'))
    now = datetime.utcnow()
    for offset in range(0, 8):
        candidate = (now + timedelta(days=offset)).replace(
            hour=h, minute=m, second=0, microsecond=0)
        if candidate.weekday() in days and candidate > now:
            return candidate
    raise ValueError(f'No valid day found — unreachable with valid input: days={days}')
```

- [ ] **Step 2: Add new action handlers inside api_followups_action()**

In app.py, inside api_followups_action(), add new elif branches before the final else at line 3046 (insert after the send-now block at line 3032):

```python
    elif action == 'free-send':
        if fc.state in ('blocked', 'closed'):
            return jsonify(error='Cannot send to blocked or closed contact'), 400
        template_text = _get_random_fu_template(uid)
        if not template_text:
            return jsonify(error='No active follow-up templates. Add at least one before sending.'), 400
        acct = EmailAccount.query.filter_by(user_id=uid).first()
        if not acct:
            return jsonify(error='No email account configured'), 400
        cfg = {'name': acct.your_name or '', 'company': acct.your_company or '',
               'phone': acct.your_phone or '', 'route': fc.current_route or ''}
        fu_dict = {'contact_email': fc.contact_email, 'reply_subject': fc.reply_subject or '',
                   'reply_msg_id': fc.reply_msg_id or '', 'current_route': fc.current_route or ''}
        ok, err = send_followup_email(fu_dict, template_text, cfg, uid=uid)
        if not ok:
            _record_event(fc, 'free_send', actor_user_id=uid,
                          metadata_json=json.dumps({'error': err}), notes='Send failed')
            db.session.commit()
            return jsonify(error=f'Send failed: {err}'), 500
        now = datetime.utcnow()
        fc.is_followup_enabled = False
        fc.last_followup_sent_at = now
        fc.last_activity_at = now
        _record_event(fc, 'free_send', actor_user_id=uid,
                      from_stage=fc.stage, to_stage=fc.stage)
        db.session.commit()
        return jsonify(ok=True, contact=fc.to_dict())

    elif action == 'schedule-once':
        if fc.state in ('blocked', 'closed'):
            return jsonify(error='Cannot schedule blocked or closed contact'), 400
        dt_str = data.get('scheduled_at', '')
        if not dt_str:
            return jsonify(error='scheduled_at is required (ISO8601 UTC)'), 400
        try:
            from datetime import timedelta
            scheduled_at = datetime.fromisoformat(dt_str.replace('Z', '+00:00')).replace(tzinfo=None)
            if scheduled_at < datetime.utcnow() + timedelta(minutes=1):
                return jsonify(error='scheduled_at must be at least 1 minute in the future'), 400
        except (ValueError, TypeError):
            return jsonify(error='Invalid scheduled_at format — use ISO8601 UTC'), 400
        fc.next_followup_at = scheduled_at
        _record_event(fc, 'scheduled_once', actor_user_id=uid,
                      notes=f'Scheduled for {scheduled_at.strftime("%Y-%m-%d %H:%M")} UTC')
        db.session.commit()
        return jsonify(ok=True, contact=fc.to_dict())

    elif action == 'set-recurring':
        if fc.state in ('blocked', 'closed'):
            return jsonify(error='Cannot set recurring for blocked or closed contact'), 400
        r_days = (data.get('recurring_days') or '').strip()
        r_time = (data.get('recurring_time') or '').strip()
        if not r_days:
            return jsonify(error='recurring_days is required'), 400
        try:
            parsed_days = [int(d) for d in r_days.split(',') if d.strip()]
            if not parsed_days or any(d < 0 or d > 6 for d in parsed_days):
                raise ValueError
        except (ValueError, TypeError):
            return jsonify(error='recurring_days must be comma-separated integers 0-6'), 400
        import re as _re
        if not _re.match(r'^\d{2}:\d{2}$', r_time):
            return jsonify(error='recurring_time must be HH:MM'), 400
        fc.recurring_enabled = True
        fc.recurring_days    = r_days
        fc.recurring_time    = r_time
        fc.next_followup_at  = _next_recurring_datetime(r_days, r_time)
        _record_event(fc, 'recurring_set', actor_user_id=uid,
                      notes=f'Recurring days={r_days} time={r_time} UTC')
        db.session.commit()
        return jsonify(ok=True, contact=fc.to_dict())

    elif action == 'stop-recurring':
        fc.recurring_enabled = False
        _record_event(fc, 'recurring_stopped', actor_user_id=uid)
        db.session.commit()
        return jsonify(ok=True, contact=fc.to_dict())
```

- [ ] **Step 3: Commit**

```bash
git add app.py
git commit -m "feat: add free-send, schedule-once, set-recurring, stop-recurring actions"
```

---

## Task 4: Update Bulk-Action Endpoint

**Files:**
- Modify: app.py — api_followups_bulk_action() (lines 3055-3078)

- [ ] **Step 1: Add EmailAccount import to bulk-action function**

At the top of api_followups_bulk_action(), add to the existing imports line:
```python
    from app.models import FollowupContact, EmailAccount
```

- [ ] **Step 2: Replace bulk-action handler body (lines 3065-3077)**

Replace the for-loop body with an expanded version that handles all new actions. The logic mirrors Task 3 but loops over ids[]:

For each contact in ids:
- pause/resume/warm/loads/block/close: call _transition_state() (existing logic, keep as-is)
- send-now: check eligibility (active + scheduled stage + is_followup_enabled), call _get_random_fu_template(), send via send_followup_email(), advance stage via STAGE_PROGRESSION
- free-send: check not blocked/closed, call _get_random_fu_template(), send, set is_followup_enabled=False
- schedule-once: check not blocked/closed, parse scheduled_at from data.get('scheduled_at'), set fc.next_followup_at
- set-recurring: check not blocked/closed, validate r_days/r_time from data, call _next_recurring_datetime(), set fields
- stop-recurring: set fc.recurring_enabled = False
- unknown: append error

After loop: db.session.commit(), return jsonify(results=results, sent=ok_count, skipped=skip_count)

See Task 3 Step 2 for exact per-contact code patterns — replicate them inside the loop.

- [ ] **Step 3: Commit**

```bash
git add app.py
git commit -m "feat: extend bulk-action endpoint with send-now, free-send, schedule, recurring"
```

---

## Task 5: Add GET /api/followups/ids Route

**Files:**
- Modify: app.py — add new route after api_followups_list() (~line 2934)

- [ ] **Step 1: Add the route**

Add after the closing of api_followups_list() (after line 2933):

```python
@app.route('/api/followups/ids')
@login_required
def api_followups_ids():
    """Return all contact IDs matching current filters (for select-all-filtered)."""
    from app.models import FollowupContact
    uid = _current_user_id()
    q = FollowupContact.query.filter_by(user_id=uid)
    state_f = request.args.get('state')
    stage_f = request.args.get('stage')
    special = request.args.get('filter')
    search  = request.args.get('q', '').strip().lower()
    if state_f and state_f in VALID_STATES:
        q = q.filter_by(state=state_f)
    if stage_f:
        stage_map = {'FU1': ['fu1_scheduled', 'fu1_sent'], 'FU2': ['fu2_scheduled', 'fu2_sent'],
                     'FU3': ['fu3_scheduled', 'fu3_sent'], 'Done': ['completed_fu3']}
        stages = stage_map.get(stage_f, [])
        if stages:
            q = q.filter(FollowupContact.stage.in_(stages))
    if search:
        q = q.filter(db.or_(
            FollowupContact.contact_email.ilike(f'%{search}%'),
            FollowupContact.contact_name.ilike(f'%{search}%'),
            FollowupContact.company_name.ilike(f'%{search}%'),
        ))
    now = datetime.utcnow()
    if special == 'needs_action':
        q = q.filter(FollowupContact.stage == 'completed_fu3', FollowupContact.state == 'active')
    elif special == 'overdue':
        q = q.filter(FollowupContact.next_followup_at < now, FollowupContact.state == 'active',
                     FollowupContact.is_followup_enabled == True)
    elif special == 'due_today':
        end_of_day = now.replace(hour=23, minute=59, second=59)
        q = q.filter(FollowupContact.next_followup_at <= end_of_day,
                     FollowupContact.next_followup_at >= now,
                     FollowupContact.state == 'active', FollowupContact.is_followup_enabled == True)
    ids = [row[0] for row in q.with_entities(FollowupContact.id).all()]
    return jsonify(ids=ids)
```

- [ ] **Step 2: Commit**

```bash
git add app.py
git commit -m "feat: add GET /api/followups/ids for select-all-filtered"
```

---

## Task 6: Update Scheduler — Random Template + Recurring Path

**Files:**
- Modify: app.py — _run_scheduled_followups() (lines 3386-3465)

- [ ] **Step 1: Update Path 1 to use random template**

In _run_scheduled_followups(), replace lines 3419-3421:
```python
                # Old:
                # template_key = STAGE_TO_TEMPLATE[fc.stage]
                # templates = _get_fu_templates_for_user(fc.user_id)
                # template_text = templates.get(template_key, DEFAULT_FU_TEMPLATES.get(template_key, ''))
                # New:
                template_text = _get_random_fu_template(fc.user_id)
                if not template_text:
                    continue
```

- [ ] **Step 2: Add Path 2 (recurring) at end of _run_scheduled_followups()**

After the existing "if sent_total:" log line, add:

```python
        if sent_total:
            app.logger.info(f'FU scheduler (sequence): sent {sent_total} follow-ups')

        # PATH 2: Recurring contacts
        processed_ids = {fc.id for fc in contacts}
        try:
            rq = FollowupContact.query.filter(
                FollowupContact.state == 'active',
                FollowupContact.recurring_enabled == True,
                FollowupContact.next_followup_at <= now,
            )
            try:
                recurring_contacts = rq.with_for_update(skip_locked=True).all()
            except Exception:
                recurring_contacts = rq.all()
        except Exception as e:
            app.logger.error(f'FU recurring scheduler query error: {e}')
            return sent_total

        sent_recurring = 0
        for fc in recurring_contacts:
            if fc.id in processed_ids:
                continue
            try:
                if fc.state != 'active' or not fc.recurring_enabled:
                    continue
                acct = EmailAccount.query.filter_by(user_id=fc.user_id).first()
                if not acct:
                    continue
                template_text = _get_random_fu_template(fc.user_id)
                if not template_text:
                    continue
                cfg = {'name': acct.your_name or '', 'company': acct.your_company or '',
                       'phone': acct.your_phone or '', 'route': fc.current_route or ''}
                fu_dict = {'contact_email': fc.contact_email, 'reply_subject': fc.reply_subject or '',
                           'reply_msg_id': fc.reply_msg_id or '', 'current_route': fc.current_route or ''}
                ok, err = send_followup_email(fu_dict, template_text, cfg, uid=fc.user_id)
                if ok:
                    fc.last_followup_sent_at = now
                    fc.last_activity_at = now
                    try:
                        fc.next_followup_at = _next_recurring_datetime(
                            fc.recurring_days, fc.recurring_time)
                    except ValueError:
                        fc.recurring_enabled = False
                    _record_event(fc, 'recurring_sent', actor_type='scheduler',
                                  from_stage=fc.stage, to_stage=fc.stage)
                    sent_recurring += 1
                else:
                    _record_event(fc, 'recurring_sent', actor_type='scheduler',
                                  from_stage=fc.stage, to_stage=fc.stage,
                                  metadata_json=json.dumps({'error': str(err)}),
                                  notes='Send failed - will retry')
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'FU recurring scheduler error for {fc.contact_email}: {e}')

        if sent_recurring:
            app.logger.info(f'FU scheduler (recurring): sent {sent_recurring} follow-ups')
        return sent_total + sent_recurring
```

Note: the old `return sent_total` at line 3465 must be removed and replaced by `return sent_total + sent_recurring` above.

- [ ] **Step 3: Commit**

```bash
git add app.py
git commit -m "feat: update scheduler with random template + recurring path"
```

---

## Task 7: Remove FU Template Level Restriction

**Files:**
- Modify: app.py — find any validation restricting level to FU1/FU2/FU3

- [ ] **Step 1: Search for restriction**

```bash
grep -n "FU1.*FU2.*FU3\|level.*in\|level not in" app.py
```

- [ ] **Step 2: Remove restriction if found**

If any route validates `level in ('FU1','FU2','FU3')` for type='followup' templates, remove that check. Any non-empty string level is valid.

- [ ] **Step 3: Verify /api/templates POST accepts type=followup**

```bash
grep -n "api/templates\|def api_templates" app.py | head -15
```

Confirm the POST handler exists and returns id, name, level, body, is_active in response. If GET /api/templates does not support ?type= filtering, add:
```python
type_f = request.args.get('type')
if type_f:
    q = q.filter_by(type=type_f)
```

- [ ] **Step 4: Commit if changed**

```bash
git add app.py
git commit -m "feat: allow custom level names for follow-up templates"
```

---

## Task 8: Frontend — Selection State + Checkboxes

**Files:**
- Modify: templates/index.html — JS near line 3894, renderFuContacts() near line 4027, CSS

- [ ] **Step 1: Add selection state and helper functions**

After line 3894 (let _fuDropdownContactId = null;), add:

```javascript
let selectedFuIds = new Set();
let _fuTotalFilteredCount = 0;

function toggleFuSelect(id, ev) {
  ev.stopPropagation();
  selectedFuIds.has(id) ? selectedFuIds.delete(id) : selectedFuIds.add(id);
  renderFuSelection();
}
function selectAllVisibleFu() {
  fuContacts.forEach(c => selectedFuIds.add(c.id));
  renderFuSelection();
}
async function selectAllFilteredFu() {
  const params = buildFuFilterParams();
  try {
    const res = await fetch('/api/followups/ids?' + params.toString());
    const d = await res.json();
    d.ids.forEach(id => selectedFuIds.add(id));
    _fuTotalFilteredCount = d.ids.length;
  } catch(e) {}
  renderFuSelection();
}
function clearFuSelection() {
  selectedFuIds.clear();
  renderFuSelection();
}
function buildFuFilterParams() {
  const p = new URLSearchParams();
  if (fuStageFilter)   p.set('stage',  fuStageFilter);
  if (fuStateFilter)   p.set('state',  fuStateFilter);
  if (fuSpecialFilter) p.set('filter', fuSpecialFilter);
  const s = (document.getElementById('fuSearch')?.value||'').trim();
  if (s) p.set('q', s);
  return p;
}
function renderFuSelection() {
  const n = selectedFuIds.size;
  const bar = document.getElementById('fuBulkBar');
  if (!bar) return;
  bar.style.display = n > 0 ? 'flex' : 'none';
  const lbl = bar.querySelector('.fu-bulk-count');
  if (lbl) lbl.textContent = n + ' selected';
  const selBtn = bar.querySelector('.fu-bulk-sel-all-filtered');
  if (selBtn) {
    const show = n > 0 && _fuTotalFilteredCount > fuContacts.length;
    selBtn.style.display = show ? '' : 'none';
    selBtn.textContent = 'Select all filtered (' + _fuTotalFilteredCount + ')';
  }
  document.querySelectorAll('.fu-card-checkbox').forEach(cb => {
    const isSel = selectedFuIds.has(cb.dataset.id);
    cb.checked = isSel;
    cb.closest('.fu-card').classList.toggle('fu-selected', isSel);
  });
}
```

- [ ] **Step 2: Update renderFuContacts() card template to add checkbox**

In the card template string (line ~4066), change the opening:
```javascript
    // Before:
    return `<div class="${cardCls}" id="fu-card-${c.id}">
      <div class="fu-card-left">
    // After:
    const isSelected = selectedFuIds.has(c.id);
    if (isSelected) cardCls += ' fu-selected';
    return `<div class="${cardCls}" id="fu-card-${c.id}">
      <label class="fu-cb-wrap" onclick="event.stopPropagation()">
        <input type="checkbox" class="fu-card-checkbox" data-id="${c.id}"
               ${isSelected ? 'checked' : ''} onchange="toggleFuSelect('${c.id}',event)">
      </label>
      <div class="fu-card-left">
```

Also update _fuTotalFilteredCount in loadFollowups() after setting fuContacts:
```javascript
    _fuTotalFilteredCount = fuContacts.length;
```

- [ ] **Step 3: Add CSS**

Find the .fu-card CSS block and add after it:
```css
.fu-cb-wrap { display:flex;align-items:center;padding:0 8px 0 4px;cursor:pointer; }
.fu-card-checkbox { width:15px;height:15px;cursor:pointer;accent-color:var(--accent); }
.fu-card.fu-selected { border-color:var(--accent);background:color-mix(in srgb,var(--accent) 6%,var(--surface)); }
```

- [ ] **Step 4: Commit**

```bash
git add templates/index.html
git commit -m "feat: add bulk selection state and checkboxes to FU contact cards"
```

---

## Task 9: Frontend — Bulk Action Bar

**Files:**
- Modify: templates/index.html — Follow-up tab HTML (~line 2054), JS

- [ ] **Step 1: Add bulk bar HTML**

Inside #fuContactsTab, after the closing div of fu-filters (~line 2053), add:

```html
<div id="fuBulkBar" style="display:none;align-items:center;gap:8px;padding:8px 12px;background:var(--surface);border:1px solid var(--accent);border-radius:8px;margin-bottom:10px;flex-wrap:wrap">
  <button style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:16px;padding:2px 4px" onclick="clearFuSelection()">&#x2715;</button>
  <span class="fu-bulk-count" style="font-size:13px;font-weight:600;color:var(--text)">0 selected</span>
  <button class="fu-bulk-sel-all-filtered" style="display:none;font-size:12px;color:var(--accent);background:none;border:none;cursor:pointer;text-decoration:underline" onclick="selectAllFilteredFu()"></button>
  <div style="width:1px;height:20px;background:var(--border);margin:0 4px"></div>
  <button class="fu-bulk-action-btn" onclick="bulkFuAction('send-now')">Send Now</button>
  <button class="fu-bulk-action-btn" onclick="bulkFuAction('free-send')">Free Send</button>
  <button class="fu-bulk-action-btn" onclick="openFuScheduleModal()">Schedule</button>
  <button class="fu-bulk-action-btn" onclick="bulkFuAction('pause')">Pause</button>
  <button class="fu-bulk-action-btn" style="color:#dc2626" onclick="bulkFuAction('block')">Block</button>
</div>
```

- [ ] **Step 2: Add .fu-bulk-action-btn CSS**

```css
.fu-bulk-action-btn { padding:5px 12px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--text);font-size:13px;cursor:pointer; }
.fu-bulk-action-btn:hover { border-color:var(--accent);color:var(--accent); }
```

- [ ] **Step 3: Add bulkFuAction() JS function**

After fuDropdownAction(), add:

```javascript
async function bulkFuAction(action, extraData) {
  const ids = [...selectedFuIds];
  if (!ids.length) return;
  const body = Object.assign({ids, action}, extraData || {});
  try {
    const res = await fetch('/api/followups/bulk-action', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body)
    });
    const data = await res.json();
    const okN = typeof data.sent === 'number' ? data.sent : (data.results||[]).filter(r=>r.ok).length;
    const skipN = typeof data.skipped === 'number' ? data.skipped : ids.length - okN;
    toast(skipN > 0 ? 'Done: ' + okN + ' sent, ' + skipN + ' skipped' : 'Done: ' + okN + ' contacts');
    clearFuSelection();
    await loadFollowups();
  } catch(e) { toast('Error: ' + e.message, true); }
}
```

- [ ] **Step 4: Commit**

```bash
git add templates/index.html
git commit -m "feat: add bulk action bar to Follow-up tab"
```

---

## Task 10: Frontend — Schedule Modal

**Files:**
- Modify: templates/index.html — add modal HTML near other modals, add JS

- [ ] **Step 1: Add schedule modal HTML**

Find where fuAddModal or fuDropdown are defined in the HTML. Add the schedule modal nearby:

```html
<div id="fuScheduleModal" class="modal-overlay" onclick="if(event.target===this)closeFuScheduleModal()" style="display:none">
  <div class="modal-box" style="max-width:420px">
    <div class="modal-header">
      <span class="modal-title">Schedule Follow-ups</span>
      <button class="modal-close" onclick="closeFuScheduleModal()">&#x2715;</button>
    </div>
    <div style="display:flex;border-bottom:1px solid var(--border)">
      <button id="fuSchedTabOnce" class="fu-sched-tab active" onclick="setFuSchedTab('once')">One-time</button>
      <button id="fuSchedTabRecurring" class="fu-sched-tab" onclick="setFuSchedTab('recurring')">Recurring</button>
    </div>
    <div id="fuSchedPanelOnce" style="padding:16px">
      <label class="form-label">Date &amp; Time <small style="color:var(--muted)">(UTC)</small></label>
      <input type="datetime-local" id="fuSchedDatetime" class="form-input" style="width:100%">
      <button class="btn btn-primary" style="margin-top:14px;width:100%" onclick="submitFuScheduleOnce()">
        Schedule for <span id="fuSchedCount">0</span> selected
      </button>
    </div>
    <div id="fuSchedPanelRecurring" style="display:none;padding:16px">
      <label class="form-label">Days <small style="color:var(--muted)">(UTC)</small></label>
      <div style="display:flex;gap:6px;flex-wrap:wrap" id="fuDayPicker">
        <button class="fu-day-btn" data-day="0" onclick="toggleFuDay(this)">Mon</button>
        <button class="fu-day-btn" data-day="1" onclick="toggleFuDay(this)">Tue</button>
        <button class="fu-day-btn" data-day="2" onclick="toggleFuDay(this)">Wed</button>
        <button class="fu-day-btn" data-day="3" onclick="toggleFuDay(this)">Thu</button>
        <button class="fu-day-btn" data-day="4" onclick="toggleFuDay(this)">Fri</button>
        <button class="fu-day-btn" data-day="5" onclick="toggleFuDay(this)">Sat</button>
        <button class="fu-day-btn" data-day="6" onclick="toggleFuDay(this)">Sun</button>
      </div>
      <label class="form-label" style="margin-top:12px">Time <small style="color:var(--muted)">(UTC)</small></label>
      <input type="time" id="fuSchedTime" value="08:00" class="form-input" style="width:120px">
      <div style="display:flex;gap:10px;margin-top:14px">
        <button class="btn btn-primary" style="flex:1" onclick="submitFuSetRecurring()">Set recurring (<span class="fu-sched-cnt-r">0</span> selected)</button>
        <button class="btn btn-secondary" onclick="submitFuStopRecurring()">Stop recurring</button>
      </div>
    </div>
  </div>
</div>
```

- [ ] **Step 2: Add schedule modal CSS**

```css
.fu-sched-tab { flex:1;padding:10px;background:none;border:none;border-bottom:2px solid transparent;cursor:pointer;font-size:14px;color:var(--muted); }
.fu-sched-tab.active { border-bottom-color:var(--accent);color:var(--text);font-weight:600; }
.fu-day-btn { padding:6px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--text);cursor:pointer;font-size:13px; }
.fu-day-btn.active { background:var(--accent);color:#fff;border-color:var(--accent); }
```

- [ ] **Step 3: Add schedule modal JS**

```javascript
function openFuScheduleModal(tab) {
  const n = selectedFuIds.size;
  if (!n) { toast('Select contacts first', true); return; }
  document.getElementById('fuScheduleModal').style.display = 'flex';
  document.getElementById('fuSchedCount').textContent = n;
  document.querySelectorAll('.fu-sched-cnt-r').forEach(el => { el.textContent = n; });
  setFuSchedTab(tab || 'once');
}
function closeFuScheduleModal() {
  document.getElementById('fuScheduleModal').style.display = 'none';
}
function setFuSchedTab(tab) {
  document.getElementById('fuSchedTabOnce').classList.toggle('active', tab === 'once');
  document.getElementById('fuSchedTabRecurring').classList.toggle('active', tab === 'recurring');
  document.getElementById('fuSchedPanelOnce').style.display   = tab === 'once'      ? '' : 'none';
  document.getElementById('fuSchedPanelRecurring').style.display = tab === 'recurring' ? '' : 'none';
}
function toggleFuDay(btn) { btn.classList.toggle('active'); }
async function submitFuScheduleOnce() {
  const val = document.getElementById('fuSchedDatetime').value;
  if (!val) { toast('Pick a date and time', true); return; }
  const scheduled_at = val + ':00Z';
  closeFuScheduleModal();
  await bulkFuAction('schedule-once', { scheduled_at });
}
async function submitFuSetRecurring() {
  const days = [...document.querySelectorAll('#fuDayPicker .fu-day-btn.active')]
    .map(b => b.dataset.day).join(',');
  if (!days) { toast('Select at least one day', true); return; }
  const time = document.getElementById('fuSchedTime').value;
  closeFuScheduleModal();
  await bulkFuAction('set-recurring', { recurring_days: days, recurring_time: time });
}
async function submitFuStopRecurring() {
  closeFuScheduleModal();
  await bulkFuAction('stop-recurring');
}
```

- [ ] **Step 4: Commit**

```bash
git add templates/index.html
git commit -m "feat: add schedule modal (one-time + recurring tabs) to Follow-up"
```

---

## Task 11: Frontend — Per-Contact Dropdown New Items + Recurring Badge

**Files:**
- Modify: templates/index.html — toggleFuDropdown() (~line 4101), fuDropdownAction(), renderFuContacts()

- [ ] **Step 1: Add new items to per-contact dropdown**

In toggleFuDropdown(), inside the items building block, before the "Add Note" separator (around line 4123), add:

```javascript
  if (!isTerminal) {
    items += '<div class="fu-dd-sep"></div>';
    items += '<button class="fu-dd-item" onclick="fuDropdownAction(\'free-send\')"><i class="ph-bold ph-paper-plane-tilt"></i> Free Send</button>';
    items += '<button class="fu-dd-item" onclick="fuDropdownSched(\'once\')"><i class="ph-bold ph-calendar"></i> Schedule once</button>';
    items += '<button class="fu-dd-item" onclick="fuDropdownSched(\'recurring\')"><i class="ph-bold ph-repeat"></i> Set recurring</button>';
    if (c.recurring_enabled) {
      items += '<button class="fu-dd-item" onclick="fuDropdownAction(\'stop-recurring\')"><i class="ph-bold ph-stop-circle"></i> Stop recurring</button>';
    }
  }
```

- [ ] **Step 2: Add fuDropdownSched() helper**

Add after fuDropdownAction():

```javascript
function fuDropdownSched(tab) {
  const id = _fuDropdownContactId;
  document.getElementById('fuDropdown').classList.remove('open');
  _fuDropdownContactId = null;
  if (!id) return;
  // Temporarily select just this contact for the modal
  const prev = new Set(selectedFuIds);
  selectedFuIds.clear();
  selectedFuIds.add(id);
  openFuScheduleModal(tab);
  // Restore original selection after modal is handled by submit functions
  // (submit functions call clearFuSelection which resets, so no restore needed)
}
```

- [ ] **Step 3: Handle free-send and stop-recurring in fuDropdownAction()**

In fuDropdownAction(), before the final fuAction() call at the bottom, add:

```javascript
  if (action === 'free-send' || action === 'stop-recurring') {
    const prev = new Set(selectedFuIds);
    selectedFuIds.clear();
    selectedFuIds.add(id);
    await bulkFuAction(action);
    selectedFuIds = prev;
    renderFuSelection();
    return;
  }
```

- [ ] **Step 4: Add recurring badge to card template in renderFuContacts()**

In the card template, inside the fu-card-badges div, add after the state badge:

```javascript
    const recurBadge = c.recurring_enabled
      ? '<span title="Recurring: ' + esc(c.recurring_days) + ' at ' + esc(c.recurring_time) + ' UTC" style="font-size:12px">&#x1F501;</span>'
      : '';
    // Insert recurBadge inside .fu-card-badges
```

- [ ] **Step 5: Commit**

```bash
git add templates/index.html
git commit -m "feat: add free-send, schedule, recurring items to FU dropdown + recurring badge"
```

---

## Task 12: Frontend — Follow-up Templates "+ Add Template" UI

**Files:**
- Modify: templates/index.html — Follow-up Templates section (~line 2228)

- [ ] **Step 1: Locate the existing FU templates section**

Find the section containing the text "Follow-up Templates" (around line 2230) with 3 textareas (fu-tmpl-1, fu-tmpl-2, fu-tmpl-3) and the "Save Follow-up Templates" button.

- [ ] **Step 2: Add extra templates section after the Save button**

After the Save button closing tag (after line ~2253):

```html
<div style="margin-top:20px;border-top:1px solid var(--border);padding-top:16px">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
    <span style="font-size:13px;font-weight:600;color:var(--text)">Additional Templates (random pool)</span>
    <button class="btn btn-secondary" style="font-size:12px;padding:4px 10px" onclick="openAddFuTmplForm()">+ Add Template</button>
  </div>
  <div id="fuExtraTmplList"></div>
  <div id="fuAddTmplForm" style="display:none;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;margin-top:8px">
    <input id="fuTmplName" class="form-input" placeholder="Template name" style="width:100%;margin-bottom:8px">
    <textarea id="fuTmplBody" class="form-input" rows="4" placeholder="Template body..." style="width:100%;font-family:monospace;font-size:12px"></textarea>
    <div style="display:flex;gap:8px;margin-top:8px">
      <button class="btn btn-primary" style="font-size:12px" onclick="saveNewFuTmpl()">Save</button>
      <button class="btn btn-secondary" style="font-size:12px" onclick="closeAddFuTmplForm()">Cancel</button>
    </div>
  </div>
</div>
```

- [ ] **Step 3: Add JS for extra templates**

```javascript
async function loadExtraFuTmpls() {
  try {
    const res = await fetch('/api/templates?type=followup');
    const data = await res.json();
    const extras = (data.templates || data || []).filter(t =>
      !['FU1','FU2','FU3'].includes(t.level) && t.is_active !== false
    );
    const el = document.getElementById('fuExtraTmplList');
    if (!el) return;
    if (!extras.length) {
      el.textContent = 'No additional templates yet.';
      el.style.cssText = 'font-size:12px;color:var(--muted)';
      return;
    }
    el.style.cssText = '';
    el.textContent = '';
    extras.forEach(t => {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)';
      const name = document.createElement('span');
      name.style.cssText = 'font-size:13px;flex:1';
      name.textContent = t.name || t.level || '';
      const del = document.createElement('button');
      del.style.cssText = 'background:none;border:none;color:var(--muted);cursor:pointer;font-size:16px';
      del.title = 'Delete';
      del.textContent = '\u00d7';
      del.onclick = () => deleteFuExtraTmpl(t.id);
      row.appendChild(name);
      row.appendChild(del);
      el.appendChild(row);
    });
  } catch(e) {}
}
function openAddFuTmplForm() { document.getElementById('fuAddTmplForm').style.display = ''; }
function closeAddFuTmplForm() {
  document.getElementById('fuAddTmplForm').style.display = 'none';
  document.getElementById('fuTmplName').value = '';
  document.getElementById('fuTmplBody').value = '';
}
async function saveNewFuTmpl() {
  const name = document.getElementById('fuTmplName').value.trim();
  const body = document.getElementById('fuTmplBody').value.trim();
  if (!name || !body) { toast('Name and body required', true); return; }
  await fetch('/api/templates', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({name, level: name, body, type: 'followup', is_active: true})});
  toast('Template saved');
  closeAddFuTmplForm();
  await loadExtraFuTmpls();
}
async function deleteFuExtraTmpl(id) {
  if (!confirm('Delete this template?')) return;
  await fetch('/api/templates/' + id, {method:'DELETE'});
  toast('Template deleted');
  await loadExtraFuTmpls();
}
```

- [ ] **Step 4: Call loadExtraFuTmpls() when settings tab opens**

Find where the settings/templates tab is initialized (search for loadTemplates or the settings tab open handler) and add a call to loadExtraFuTmpls() alongside it.

- [ ] **Step 5: Commit**

```bash
git add templates/index.html
git commit -m "feat: add extra FU templates management UI with random pool support"
```

---

## Task 13: End-to-End Smoke Test + Deploy

- [ ] **Step 1: Deploy to Railway**

```bash
git push origin main
```

Wait for Railway build to complete (~2 min).

- [ ] **Step 2: Smoke test Send Now**

Open Follow-up tab, find a contact in fu1_scheduled state, click "Send Now". Verify email sent and stage advances to fu2_scheduled.

- [ ] **Step 3: Smoke test Free Send**

Click ... on a contact, click "Free Send". Verify email sent, stage unchanged, is_followup_enabled becomes False.

- [ ] **Step 4: Smoke test bulk selection + bulk send**

Check 3 contacts. Verify bulk bar appears with "3 selected". Click "Free Send". Verify all 3 sent.

- [ ] **Step 5: Smoke test Select All Filtered**

Apply a filter (e.g., Active only). Click "Select all filtered (N)" in bulk bar. Verify count matches filtered total.

- [ ] **Step 6: Smoke test Schedule Once**

Select contacts, click "Schedule", One-time tab, pick tomorrow 08:00, confirm. Verify next_followup_at updated in contact cards.

- [ ] **Step 7: Smoke test Set Recurring**

Select contacts, "Schedule", Recurring tab, toggle Mon/Wed/Fri, set 08:00, "Set recurring". Verify recurring badge appears on cards.

- [ ] **Step 8: Smoke test Add Template**

Settings, Follow-up Templates, "+ Add Template", fill name and body, Save. Verify template appears in list.

- [ ] **Step 9: Final commit**

```bash
git add .
git commit -m "chore: follow-up upgrade complete"
```
