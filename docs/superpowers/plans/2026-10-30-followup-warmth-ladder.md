# Follow-up Warmth Ladder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the calendar-driven follow-up drip with an event-driven ladder where a broker sending load information moves a contact up a rung, patience is spent per attempt and refilled only by a load, and the daily screen is a funnel scoreboard instead of a 277-row queue.

**Architecture:** All ladder decisions live in a new pure module `app/ladder.py` — rung from load count, next touch date, attempt budget, reply interpretation — with no Flask or DB dependencies, so it is tested directly. `app.py` keeps the wiring: the scheduler path calls the module to decide when to send, the reply hook calls it to decide what a reply means, and new endpoints serve the scoreboard and tier list. The frontend adds a scoreboard view to the existing Follow-up page in `templates/index.html`, with the existing table reachable one click deeper.

**Tech Stack:** Flask 3, SQLAlchemy 2, PostgreSQL (prod) / SQLite (dev), vanilla JS in a single template, pytest.

**Spec:** `docs/superpowers/specs/2026-10-30-followup-warmth-ladder-design.md`

## Global Constraints

- Production schema changes ship through the inline `_migrations` list in `app.py` (near `('followup_contacts', 'send_fail_count', ...)`). An Alembic-only column took production down on 2026-10-20. Alembic files are optional; the inline entry is not.
- Column types must be valid on both PostgreSQL and SQLite, e.g. `"VARCHAR(20) NOT NULL DEFAULT 'cold'"`.
- Every new send path goes through the existing `_record_send_failure(fc, event_type, err, now)` backoff. A dead OAuth token previously produced 368k retry rows and an outage.
- The engine stays behind the existing kill switch `Workspace.fu_auto_enabled`.
- Replies page, its triage categories and its keyword sets are untouched. The deferral-versus-refusal split happens inside Follow-up, reading `Reply.triage_category` plus the reply text.
- A broker **sending load information** advances a rung; booking does not. One rung step per load *conversation* — dedupe by `Reply.thread_id`, falling back to contact + calendar day.
- Attempt budgets: 3 with no load received; 4-5 once a load has been received. Replies never refill the budget; only a load does.
- Cadence: touch 1 the next day, touch 2 three days later, touch 3+ weekly. HOT weekly from the first touch. CLIENT is never scheduled.
- There is no runtime silence brake. The 90-day rule exists only in the migration task.
- Frontend is vanilla JS inside `templates/index.html`; no build step. Verify with `node --check` on the extracted `<script>`.
- Tests run per file: `python -m pytest tests/test_x.py -q` using `.venv/bin/python`.

## Review Focus

- **A reply from an `excluded` contact must not resurrect them.** The spec says excluded is the owner's permanent decision; an inbound email must leave them excluded. Test in Task 3.
- **A deferral that parses to a past date must not schedule a send in the past.** "next week" read from an email fetched late would otherwise make the contact instantly overdue — the pile the redesign exists to remove. Test in Task 1.
- **A load arriving for an `auto_paused` contact must count the load but schedule nothing.** Pausing is the owner's override and must survive good news. Test in Task 3.
- **A `client` contact must never be given a scheduled touch**, even after a load — CLIENT leaves automation entirely. Test in Task 4.
- **The same reply processed twice must not count two loads.** Gmail re-fetches overlap; naive counting inflates rungs. Test in Task 3.

---

### Task 1: Ladder rules module

**Files:**
- Create: `app/ladder.py`
- Test: `tests/test_ladder_rules.py`

**Interfaces:**
- Consumes: nothing (pure module, stdlib only)
- Produces:
  - `RUNGS = ('cold', 'neutral', 'warm', 'hot', 'client')`
  - `OFF_LADDER = ('dormant', 'excluded')`
  - `LADDER_DEFAULTS: dict` with keys `first_touch_days=1`, `second_touch_days=3`, `weekly_days=7`, `budget_no_load=3`, `budget_engaged=5`, `hot_weekly=True`, `higher_rung_patience=True`
  - `rung_for(load_count: int, replied: bool) -> str`
  - `budget_for(rung: str, cfg: dict) -> int`
  - `next_touch_at(rung: str, attempt: int, now: datetime, cfg: dict) -> datetime | None`
  - `parse_deferral(text: str, now: datetime) -> datetime | None`
  - `interpret_reply(category: str | None, text: str, now: datetime) -> tuple[str, datetime | None]` returning kind in `('load', 'refusal', 'deferral', 'unknown')`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_ladder_rules.py
from datetime import datetime, timedelta
from app import ladder

NOW = datetime(2026, 11, 2, 9, 0, 0)

def test_rung_from_load_count():
    assert ladder.rung_for(0, replied=False) == 'cold'
    assert ladder.rung_for(0, replied=True) == 'neutral'
    assert ladder.rung_for(1, replied=True) == 'warm'
    assert ladder.rung_for(2, replied=True) == 'hot'
    assert ladder.rung_for(9, replied=True) == 'hot'   # client is set deliberately, never derived

def test_budget_grows_once_a_load_arrived():
    cfg = dict(ladder.LADDER_DEFAULTS)
    assert ladder.budget_for('neutral', cfg) == 3
    assert ladder.budget_for('cold', cfg) == 3
    assert ladder.budget_for('warm', cfg) == 5
    assert ladder.budget_for('hot', cfg) == 5

def test_cadence_next_day_then_three_then_weekly():
    cfg = dict(ladder.LADDER_DEFAULTS)
    assert ladder.next_touch_at('neutral', 0, NOW, cfg) == NOW + timedelta(days=1)
    assert ladder.next_touch_at('neutral', 1, NOW, cfg) == NOW + timedelta(days=3)
    assert ladder.next_touch_at('neutral', 2, NOW, cfg) == NOW + timedelta(days=7)

def test_hot_is_weekly_from_the_first_touch():
    cfg = dict(ladder.LADDER_DEFAULTS)
    assert ladder.next_touch_at('hot', 0, NOW, cfg) == NOW + timedelta(days=7)

def test_client_is_never_scheduled():
    assert ladder.next_touch_at('client', 0, NOW, dict(ladder.LADDER_DEFAULTS)) is None

def test_higher_rung_patience_can_be_switched_off():
    cfg = dict(ladder.LADDER_DEFAULTS); cfg['higher_rung_patience'] = False
    assert ladder.budget_for('hot', cfg) == 3

def test_parse_deferral_reads_the_stated_time():
    assert ladder.parse_deferral('check back next week', NOW) == NOW + timedelta(days=7)
    assert ladder.parse_deferral('try us next month', NOW) == NOW + timedelta(days=30)
    assert ladder.parse_deferral('nothing right now', NOW) is None

def test_deferral_never_lands_in_the_past():
    stale = ladder.parse_deferral('next week', NOW - timedelta(days=30))
    assert stale is None or stale > NOW - timedelta(days=30)

def test_interpret_reply_splits_deferral_from_refusal():
    assert ladder.interpret_reply('gave_info', 'we have a load Laredo to Dallas', NOW)[0] == 'load'
    assert ladder.interpret_reply('negative', 'remove me from your list', NOW)[0] == 'refusal'
    # the phrases the shared `declined` keyword set wrongly marks negative
    for text in ('nothing this week', 'no loads this week', 'nothing right now', 'we are covered'):
        assert ladder.interpret_reply('negative', text, NOW)[0] == 'deferral', text
    assert ladder.interpret_reply(None, 'ok', NOW)[0] == 'unknown'
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_ladder_rules.py -q`
Expected: FAIL — `No module named 'app.ladder'`

- [ ] **Step 3: Implement `app/ladder.py`**

Pure stdlib. `interpret_reply` checks the deferral phrase list **before** honouring a `negative` category, since the shared keyword set misclassifies those; everything else maps category directly. `parse_deferral` recognises "next week", "next month", "in N days/weeks", and explicit month-day dates, and returns `None` rather than any datetime at or before `now`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_ladder_rules.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/ladder.py tests/test_ladder_rules.py
git commit -m "feat: ladder rules module — rungs, cadence, budget, reply interpretation"
```

---

### Task 2: Contact schema for the ladder

**Files:**
- Modify: `app/models.py` — `FollowupContact`, after `send_fail_count`
- Modify: `app.py` — inline `_migrations` list
- Test: `tests/test_ladder_schema.py`

**Interfaces:**
- Produces on `FollowupContact`: `rung: str` (default `'cold'`), `load_count: int` (default 0), `touch_attempt: int` (default 0), `auto_paused: bool` (default False), `last_load_at: datetime | None`, `exit_reason: str | None`. All six exposed in `to_dict()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ladder_schema.py
def test_new_contact_starts_cold_with_empty_counters(app, db):
    fc = _make_contact(db)                     # helper mirrors tests/test_touch.py::_fc
    assert (fc.rung, fc.load_count, fc.touch_attempt) == ('cold', 0, 0)
    assert fc.auto_paused is False
    assert fc.last_load_at is None and fc.exit_reason is None

def test_to_dict_exposes_ladder_fields(app, db):
    d = _make_contact(db).to_dict()
    for key in ('rung', 'load_count', 'touch_attempt', 'auto_paused', 'exit_reason'):
        assert key in d
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_ladder_schema.py -q`
Expected: FAIL — `AttributeError: 'FollowupContact' object has no attribute 'rung'`

- [ ] **Step 3: Add the columns and the inline migration entries**

Columns carry `server_default` so existing rows are valid. Inline entries, appended to `_migrations`:

```python
('followup_contacts', 'rung',          "VARCHAR(20) NOT NULL DEFAULT 'cold'"),
('followup_contacts', 'load_count',    'INTEGER NOT NULL DEFAULT 0'),
('followup_contacts', 'touch_attempt', 'INTEGER NOT NULL DEFAULT 0'),
('followup_contacts', 'auto_paused',   'BOOLEAN NOT NULL DEFAULT FALSE'),
('followup_contacts', 'last_load_at',  'TIMESTAMP'),
('followup_contacts', 'exit_reason',   'VARCHAR(40)'),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_ladder_schema.py tests/test_touch.py -q`
Expected: PASS

- [ ] **Step 5: Verify the inline migration applies to a table without the columns**

Build a SQLite DB whose `followup_contacts` lacks the six columns, boot the app against it, and assert all six exist afterwards with `rung='cold'` on a pre-existing row. Keep the script under the scratchpad, not the repo.

- [ ] **Step 6: Commit**

```bash
git add app/models.py app.py tests/test_ladder_schema.py
git commit -m "feat: ladder columns on FollowupContact via inline migrations"
```

---

### Task 3: Replies move contacts up the ladder

**Files:**
- Modify: `app.py` — `_check_reply_stops_followup(reply_email, user_id)` at ~line 6828
- Test: `tests/test_ladder_replies.py`

**Interfaces:**
- Consumes: `ladder.interpret_reply`, `ladder.rung_for`, `ladder.next_touch_at`, `ladder.budget_for` (Task 1); the columns from Task 2.
- Produces: `_apply_reply_to_ladder(fc, reply, ws, now) -> str` in `app.py`, returning the kind it applied (`'load'`, `'refusal'`, `'deferral'`, `'unknown'`). Called from `_check_reply_stops_followup`, which gains a `reply` argument; its one caller at ~line 3319 passes the `Reply` row it already has.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_ladder_replies.py
def test_load_reply_raises_the_rung_and_resets_the_budget(app, db):
    fc = _contact(db, rung='neutral', touch_attempt=2)
    _reply(db, fc, category='gave_info', body='we have a load Laredo to Dallas', thread='t1')
    assert (fc.rung, fc.load_count, fc.touch_attempt) == ('warm', 1, 0)
    assert fc.last_load_at is not None

def test_second_load_reaches_hot():
    # two loads in different threads → hot, load_count 2

def test_same_thread_twice_counts_one_load(app, db):
    # Review Focus: Gmail re-fetch must not inflate the rung
    fc = _contact(db, rung='neutral')
    _reply(db, fc, category='gave_info', body='load Laredo to Dallas', thread='t1')
    _reply(db, fc, category='gave_info', body='still open, can you cover', thread='t1')
    assert (fc.load_count, fc.rung) == (1, 'warm')

def test_refusal_stops_the_contact(app, db):
    fc = _contact(db, rung='warm')
    _reply(db, fc, category='negative', body='remove me from your list')
    assert fc.rung == 'dormant' and fc.exit_reason == 'refused'
    assert fc.next_followup_at is None

def test_deferral_schedules_their_date_and_does_not_raise_the_rung(app, db):
    fc = _contact(db, rung='neutral')
    _reply(db, fc, category='negative', body='nothing this week, try next week')
    assert fc.rung == 'neutral' and fc.load_count == 0
    assert fc.next_followup_at > _app._utcnow()

def test_excluded_contact_is_not_resurrected_by_a_reply(app, db):
    # Review Focus
    fc = _contact(db, rung='excluded')
    _reply(db, fc, category='gave_info', body='we have a load')
    assert fc.rung == 'excluded' and fc.next_followup_at is None

def test_dormant_contact_returns_on_an_inbound_reply(app, db):
    fc = _contact(db, rung='dormant', load_count=1, exit_reason='exhausted')
    _reply(db, fc, category='gave_info', body='we have a load', thread='t9')
    assert fc.rung == 'hot' and fc.exit_reason is None

def test_load_for_a_paused_contact_counts_but_schedules_nothing(app, db):
    # Review Focus
    fc = _contact(db, rung='warm', auto_paused=True)
    _reply(db, fc, category='gave_info', body='another load', thread='t2')
    assert (fc.load_count, fc.rung) == (2, 'hot')
    assert fc.next_followup_at is None

def test_unparseable_reply_raises_attention_and_changes_nothing(app, db):
    fc = _contact(db, rung='warm', load_count=1)
    _reply(db, fc, category=None, body='ok')
    assert (fc.rung, fc.load_count) == ('warm', 1)
    assert fc.attention_at is not None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_ladder_replies.py -q`
Expected: FAIL — `_apply_reply_to_ladder` undefined

- [ ] **Step 3: Implement `_apply_reply_to_ladder(fc, reply, ws, now)` and call it from `_check_reply_stops_followup`**

Order of checks: `excluded` returns immediately; then `interpret_reply`. A load dedupes against the contact's existing load events by `thread_id` (falling back to contact + day) before incrementing `load_count`, recomputes `rung` via `rung_for`, clears `exit_reason`, resets `touch_attempt`, and schedules via `next_touch_at` unless the rung is `client` or `auto_paused` is set. A refusal sets `dormant` with `exit_reason='refused'` and clears the schedule. A deferral keeps the rung and sets the returned date. Unknown sets `attention_at`. Every branch writes a `FollowupEvent` through the existing `_record_event`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_ladder_replies.py tests/test_triage.py tests/test_followup_recovery.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app.py tests/test_ladder_replies.py
git commit -m "feat: replies advance the ladder, deferrals split from refusals"
```

---

### Task 4: Scheduler sends on the ladder

**Files:**
- Modify: `app.py` — `_run_scheduled_followups()` drip path
- Test: `tests/test_ladder_scheduler.py`

**Interfaces:**
- Consumes: Task 1 rules, Task 2 columns, existing `_record_send_failure`, existing `Workspace.fu_auto_enabled` gate.
- Produces: `_run_ladder_touches(now) -> int` in `app.py`, returning touches sent; called from `_run_scheduled_followups` in place of the stage-drip query.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_ladder_scheduler.py
def test_due_contact_is_sent_and_the_attempt_is_spent(app, db, monkeypatch):
    fc = _contact(db, rung='neutral', touch_attempt=0, next_followup_at=past())
    _run(); assert fc.touch_attempt == 1 and fc.next_followup_at > now()

def test_budget_exhaustion_goes_dormant_with_a_reason(app, db, monkeypatch):
    fc = _contact(db, rung='neutral', touch_attempt=2, next_followup_at=past())  # 3rd of 3
    _run()
    assert fc.rung == 'dormant' and fc.exit_reason == 'exhausted'
    assert fc.next_followup_at is None

def test_a_load_refills_the_budget_but_replies_do_not(app, db, monkeypatch):
    # neutral contact at attempt 3 that only replied stays dormant after _run()

def test_client_is_never_sent_to(app, db, monkeypatch):
    # Review Focus
    fc = _contact(db, rung='client', next_followup_at=past())
    sent = _run(); assert sent == 0 and fc.touch_attempt == 0

def test_paused_contact_is_skipped_but_kept(app, db, monkeypatch):
    fc = _contact(db, rung='warm', auto_paused=True, next_followup_at=past())
    assert _run() == 0 and fc.rung == 'warm'

def test_excluded_and_dormant_are_never_sent_to(app, db, monkeypatch):
    for r in ('excluded', 'dormant'):
        assert _run_for(_contact(db, rung=r, next_followup_at=past())) == 0

def test_kill_switch_still_stops_everything(app, db, monkeypatch):
    # workspace fu_auto_enabled=False → 0 sent, nothing mutated

def test_send_failure_uses_the_existing_backoff(app, db, monkeypatch):
    # send_followup_email → (False, 'invalid_grant'); assert send_fail_count == 1
    # and next_followup_at moved out, not left due
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_ladder_scheduler.py -q`
Expected: FAIL — `_run_ladder_touches` undefined

- [ ] **Step 3: Implement `_run_ladder_touches(now)`**

Query active, non-paused contacts whose `rung` is in `('cold','neutral','warm','hot')` with `next_followup_at <= now`, joined to `Workspace` on `fu_auto_enabled == True` exactly as the current drip query does. For each: if `touch_attempt >= budget_for(rung, cfg)` set `dormant` with `exit_reason='exhausted'`, clear the schedule, record an event, and skip. Otherwise send, increment `touch_attempt`, and set the next date from `next_touch_at`. Failures go to `_record_send_failure` and leave the attempt unspent.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_ladder_scheduler.py tests/test_drip_gate.py tests/test_send_failure_backoff.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app.py tests/test_ladder_scheduler.py
git commit -m "feat: scheduler sends on ladder rhythm and spends the attempt budget"
```

---

### Task 5: Per-rung email content

**Files:**
- Modify: `app.py` — template selection used by Task 4
- Test: `tests/test_ladder_templates.py`

**Interfaces:**
- Consumes: existing `Template` model (`level` is free-form `String(50)`), existing `_get_fu_template_for_stage`.
- Produces: `_template_for_rung(uid, rung, fc) -> str | None` in `app.py`.

Read `wave/b-smart-templates` (commit `bccc496`) before writing: it already carries contact-variable substitution and may supply most of this.

- [ ] **Step 1: Write the failing tests**

```python
def test_rung_template_is_preferred_over_the_general_pool(app, db):
    # Template(level='WARM') exists → chosen for a warm contact

def test_falls_back_to_the_general_pool_when_no_rung_template(app, db):
    # only a General template exists → returned, no crash

def test_warm_body_can_reference_the_contact_lane(app, db):
    fc = _contact(db, rung='warm', current_route='Laredo, TX -> Dallas, TX')
    body = _app._template_for_rung(fc.user_id, 'warm', fc)
    assert 'Laredo, TX -> Dallas, TX' in body     # template uses {route}

def test_missing_variable_does_not_crash_the_send(app, db):
    # template references {last_rate} with no rate on the contact → renders, no KeyError
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_ladder_templates.py -q`
Expected: FAIL

- [ ] **Step 3: Implement `_template_for_rung` and wire it into Task 4's send**

Rung name uppercased is the template `level` (`WARM`, `HOT`, `NEUTRAL`, `COLD`). Fall back to the general pool when absent. Substitution tolerates missing variables.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_ladder_templates.py tests/test_templates.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app.py tests/test_ladder_templates.py
git commit -m "feat: per-rung follow-up templates with contact variables"
```

---

### Task 6: Funnel and needs-you API

**Files:**
- Modify: `app.py` — new routes beside the existing `/api/followups/*` block
- Test: `tests/test_ladder_api.py`

**Interfaces:**
- Produces:
  - `GET /api/followups/funnel` → `{rungs: {cold,neutral,warm,hot,client,dormant,excluded}, conversion: [{rung, reached, pct_of_previous, lost, lost_reasons}], totals: {entered, lost, end_to_end_pct, avg_days_between_loads, loads_this_month}}`
  - `GET /api/followups/needs-you` → `{items: [{id, contact_email, contact_name, rung, reason, detail}]}` with `reason` in `('client_silent','promised_not_delivered','promised_load_vanished','unparsed_reply')`
  - `GET /api/followups/activity?hours=24` → `{sent, raised, quieted, stopped}`

- [ ] **Step 1: Write the failing tests**

```python
def test_funnel_counts_each_rung(app, db, client):
    # 2 warm, 1 hot, 3 dormant → counts match, other rungs zero

def test_conversion_reports_absolute_numbers_not_only_percentages(app, db, client):
    row = _get('/api/followups/funnel')['conversion'][1]
    assert 'reached' in row and 'lost' in row and isinstance(row['reached'], int)

def test_needs_you_lists_an_unparsed_reply(app, db, client):
    # contact with attention_at set and no automatic action → reason 'unparsed_reply'

def test_needs_you_lists_a_vanished_load_promise(app, db, client):
    # reply promising a load, no load since, older than the promise window

def test_needs_you_is_empty_on_a_quiet_day(app, db, client):
    assert _get('/api/followups/needs-you')['items'] == []

def test_endpoints_are_scoped_to_the_signed_in_user(app, db, client):
    # another user's contacts never appear

def test_activity_counts_the_last_day(app, db, client):
    # events written 1h ago counted, 48h ago not
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_ladder_api.py -q`
Expected: FAIL — 404

- [ ] **Step 3: Implement the three routes**

All `@login_required`, scoped by `_current_user_id()`, read-only. Conversion counts contacts that ever reached each rung from `FollowupEvent` history; `lost_reasons` groups `exit_reason`. "Promised a load and vanished" is a reply whose text matched a promise phrase with no load counted since and the promise older than two days — define the phrase list in `app/ladder.py` next to the deferral list. "Client silent unusually long" is a `client` contact whose days since `last_reply_at` exceed twice its own median reply gap, minimum 14 days.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_ladder_api.py tests/test_followup_isolation.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app.py app/ladder.py tests/test_ladder_api.py
git commit -m "feat: funnel, needs-you and activity endpoints"
```

---

### Task 7: Tier list and manual overrides API

**Files:**
- Modify: `app.py` — extend `/api/followups` and `/api/followups/action`
- Test: `tests/test_ladder_actions.py`

**Interfaces:**
- Produces: `GET /api/followups?rung=warm` filtering by rung, each row carrying `rung`, `load_count`, `touch_attempt`, `budget`, `next_followup_at`, `next_touch_reason`, `auto_paused`. New `action` values on `POST /api/followups/action`: `pause-auto`, `resume-auto`, `set-rung`, `exclude`. All available in `POST /api/followups/bulk-action`.

- [ ] **Step 1: Write the failing tests**

```python
def test_list_filters_by_rung(app, db, client):
    # ?rung=warm returns only warm contacts

def test_row_explains_why_the_next_touch_is_when_it_is(app, db, client):
    # next_touch_reason reads like 'touch 3' / 'they asked for next week' / 'auto paused'

def test_pause_auto_keeps_the_contact_but_stops_sending(app, db, client):
    # auto_paused True, rung unchanged, next_followup_at cleared

def test_resume_auto_reschedules_from_the_current_rung(app, db, client):
    # next_followup_at set again from next_touch_at

def test_set_rung_is_recorded_as_a_manual_event(app, db, client):
    # rung changes and a FollowupEvent with actor_type='user' exists

def test_exclude_is_permanent_and_clears_the_schedule(app, db, client):
    # rung 'excluded', exit_reason 'excluded', next_followup_at None

def test_bulk_actions_apply_to_every_selected_contact(app, db, client):
    # two ids → both paused
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_ladder_actions.py -q`
Expected: FAIL

- [ ] **Step 3: Implement the filter and the four actions**

Reuse the existing action-dispatch shape in `api_followups_action`; each new action records an event with `actor_type='user'`. `budget` in the row payload comes from `ladder.budget_for`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_ladder_actions.py tests/test_followup_dedup.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app.py tests/test_ladder_actions.py
git commit -m "feat: rung filter and manual override actions"
```

---

### Task 8: Funnel scoreboard screen

**Files:**
- Modify: `templates/index.html` — Follow-up page markup, CSS, JS
- Reference: `.superpowers/brainstorm/31699-1793384212/content/page.html`

**Interfaces:**
- Consumes: Task 6 endpoints.
- Produces: `loadFuFunnel()`, `renderFuFunnel(data)`, `renderNeedsYou(items)` in the page script; the Follow-up sidebar badge reads the needs-you count.

- [ ] **Step 1: Build the scoreboard as the default Follow-up view**

Rung strip in the approved order CLIENT, HOT, WARM, NEUTRAL, COLD, with DORMANT and EXCLUDED beside it; conversion in absolute numbers with per-step losses; needs-you list with its reason text; the day's activity line. Match the mockup and the existing CSS variables. Each tier calls into Task 9's list.

- [ ] **Step 2: Verify the extracted script parses**

Run `node --check` over the extracted `<script>` (same approach as earlier fixes).
Expected: OK

- [ ] **Step 3: Verify in the browser against seeded data**

Start the dev server, sign in, confirm counts match the API payload and that the sidebar badge shows the needs-you count rather than the queue size. Screenshot it.

- [ ] **Step 4: Commit**

```bash
git add templates/index.html
git commit -m "feat: Follow-up funnel scoreboard replaces the queue as the default view"
```

---

### Task 9: Tier drill-down and contact history

**Files:**
- Modify: `templates/index.html`
- Reference: `.superpowers/brainstorm/31699-1793384212/content/drilldown.html`

**Interfaces:**
- Consumes: Task 7 endpoints, existing `/api/followups/timeline`.
- Produces: `openFuTier(rung)`, `renderFuTierRow(contact)`, `toggleFuHistory(id)`.

- [ ] **Step 1: Build the tier list**

Tabs across all rungs including DORMANT and EXCLUDED. Columns: contact, rung, loads, attempt ("2 of 5"), next touch with its reason, lane. Row actions: send now, postpone, history, move to inactive, pause/resume automation. Checkbox bulk bar reusing the existing selection code.

- [ ] **Step 2: Expand a row into its history**

Each touch with date and the text that was sent, plus every rung change and its cause, from `/api/followups/timeline`.

- [ ] **Step 3: Verify the extracted script parses**

Run `node --check`. Expected: OK

- [ ] **Step 4: Verify in the browser**

Open a tier from the scoreboard, expand a row, run pause then resume on a contact and confirm the next-touch cell changes accordingly. Screenshot.

- [ ] **Step 5: Commit**

```bash
git add templates/index.html
git commit -m "feat: tier drill-down with history and per-contact overrides"
```

---

### Task 10: Migrate the existing contacts

**Files:**
- Create: `scripts/migrate_to_ladder.py`
- Test: `tests/test_ladder_migration.py`

**Interfaces:**
- Produces: `place_contacts_on_ladder(workspace_id, now, dry_run=True) -> dict` in `scripts/migrate_to_ladder.py`, returning counts per resulting rung.

- [ ] **Step 1: Write the failing tests**

```python
def test_rung_comes_from_counted_load_conversations(app, db):
    # contact with gave_info replies in 2 threads → load_count 2, rung 'hot'

def test_inactive_beyond_ninety_days_starts_dormant(app, db):
    # 3 loads but last_activity_at 120 days ago → rung 'dormant', exit_reason 'stale'

def test_manual_states_are_never_overridden(app, db):
    # state 'blocked' → 'excluded'; 'closed' → 'excluded'
    # state 'loads' and 'warm' → out of automation, auto_paused True, not scheduled

def test_dry_run_changes_nothing(app, db):
    # counts returned, no column mutated

def test_rerunning_is_idempotent(app, db):
    # second run produces the same rungs and does not double load_count
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_ladder_migration.py -q`
Expected: FAIL

- [ ] **Step 3: Implement `place_contacts_on_ladder`**

Count each contact's load conversations from its `gave_info` replies, deduped by `thread_id` then contact+day, exactly as Task 3 does. Derive the rung, then apply the two safety rules in order: manual states win first, then anything with no activity for 90 days becomes `dormant` with `exit_reason='stale'`. Write a best-effort `exit_reason` for contacts already out of play so the conversion panel is not blank. Default `dry_run=True`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_ladder_migration.py -q`
Expected: PASS

- [ ] **Step 5: Dry-run against a production snapshot and report the distribution**

Run with `dry_run=True` against the live database read-only, and report counts per rung to the owner before any write. Expect roughly two dozen live contacts and the rest dormant.

- [ ] **Step 6: Commit**

```bash
git add scripts/migrate_to_ladder.py tests/test_ladder_migration.py
git commit -m "feat: place existing contacts on the ladder from reply history"
```

---

### Task 11: Ladder settings

**Files:**
- Modify: `app.py` — `/api/followups/pipeline-config` GET and PUT
- Modify: `templates/index.html` — Settings → Touch cadence block
- Test: `tests/test_ladder_settings.py`

**Interfaces:**
- Consumes: `ladder.LADDER_DEFAULTS` (Task 1).
- Produces: `_ladder_cfg(ws) -> dict` in `app.py`, merging `Workspace.pipeline_config['ladder']` over `LADDER_DEFAULTS`. Tasks 3, 4, 6 and 7 call it instead of using `LADDER_DEFAULTS` directly. `pipeline-config` gains a `ladder` object carrying the same keys.

The spec requires every cadence and patience number to be a setting, and `higher_rung_patience` to be switchable off entirely. Without this task the engine reads hard-coded defaults.

- [ ] **Step 1: Write the failing tests**

```python
def test_defaults_apply_when_nothing_is_saved(app, db):
    assert _app._ladder_cfg(ws)['budget_no_load'] == 3

def test_saved_values_override_defaults(app, db, client):
    client.put('/api/followups/pipeline-config', json={'ladder': {'budget_no_load': 2}})
    cfg = _app._ladder_cfg(ws)
    assert cfg['budget_no_load'] == 2 and cfg['weekly_days'] == 7   # untouched keys keep defaults

def test_higher_rung_patience_can_be_switched_off_from_settings(app, db, client):
    client.put('/api/followups/pipeline-config', json={'ladder': {'higher_rung_patience': False}})
    assert ladder.budget_for('hot', _app._ladder_cfg(ws)) == 3

def test_nonsense_values_are_rejected_not_stored(app, db, client):
    client.put('/api/followups/pipeline-config', json={'ladder': {'budget_no_load': -5, 'weekly_days': 9999}})
    cfg = _app._ladder_cfg(ws)
    assert cfg['budget_no_load'] >= 1 and cfg['weekly_days'] <= 365

def test_existing_cadence_and_digest_settings_still_round_trip(app, db, client):
    # the ladder object must not disturb touch_hour, digest_enabled or drip_auto_enabled
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_ladder_settings.py -q`
Expected: FAIL — `_ladder_cfg` undefined

- [ ] **Step 3: Implement `_ladder_cfg(ws)` and the config round-trip**

Clamp on write: integers at least 1, day intervals at most 365, budgets at most 20. Unknown keys are dropped. Replace direct `LADDER_DEFAULTS` reads in Tasks 3, 4, 6 and 7 with `_ladder_cfg(ws)`.

- [ ] **Step 4: Add the knobs to the Settings page**

Extend the existing Touch cadence block beside `plDripAuto`: first-touch days, second-touch days, weekly days, budget without a load, budget once engaged, and a checkbox for extra patience at higher rungs. Save through `savePipelineConfig()`, which already skips non-stage rows.

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_ladder_settings.py tests/test_settings_tabs.py tests/test_drip_gate.py -q`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add app.py templates/index.html tests/test_ladder_settings.py
git commit -m "feat: ladder cadence and patience are workspace settings"
```

---

### Task 12: Retire the stage drip

**Files:**
- Modify: `app.py` — old drip path, `STAGE_TO_TEMPLATE` users
- Modify: `CLAUDE.md` — the "Follow-up каденс" section
- Test: existing suites

**Interfaces:**
- Consumes: Tasks 3, 4 in place and green.

- [ ] **Step 1: Remove the stage-drip scheduling path now superseded**

`_run_scheduled_followups` keeps paths 0 and 2 (one-time and recurring, both user-initiated) and the ladder path. The old stage query, `_schedule_touch` cadence scheduling and `completed_fu3` progression come out. `stage`, `pipeline_stage` and the kanban stay in the schema and UI for now — removing them is out of scope.

- [ ] **Step 2: Run the full suite**

Run: `.venv/bin/python -m pytest tests/ -q -p no:randomly`
Expected: PASS. Delete or rewrite tests that assert the removed stage progression, keeping anything that still describes live behaviour.

- [ ] **Step 3: Update CLAUDE.md**

Replace the stage-cadence description with the ladder: rungs, rhythm, budget, the kill switch, and a pointer to the spec and this plan.

- [ ] **Step 4: Commit**

```bash
git add app.py CLAUDE.md tests/
git commit -m "refactor: retire the stage drip in favour of the ladder"
```
