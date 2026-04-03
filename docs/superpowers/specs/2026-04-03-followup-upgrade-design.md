# Follow-up System Upgrade — Design Spec
**Date:** 2026-04-03
**Status:** Approved (v2 — post spec-review)

---

## Overview

Upgrade the Follow-up system for reliable daily operational use. Core changes: bulk selection, two send modes (sequence vs free), flexible scheduling (one-time + recurring), and an expandable template pool with random selection.

---

## Audit Summary

### What's Working
- Auto-scheduler daemon (15-min interval), FU1→FU2→FU3 stage progression
- Filtering, search, state transitions (pause/resume/block/close/warm/loads)
- Per-contact actions, event logging, workspace settings
- Existing `Template` model (`type='followup'`, `level='FU1/FU2/FU3'`) already stores FU templates

### Root Causes Found

| # | Problem | Root Cause | Location |
|---|---------|-----------|----------|
| 1 | Send Now broken | `acct.sender_name` / `.company_name` / `.phone` don't exist on `EmailAccount` — should be `acct.your_name` / `.your_company` / `.your_phone`. **Scoped to EmailAccount object only** — `FollowupContact.company_name` at other lines is correct. | app.py:3001–3002 |
| 2 | No bulk send | `/api/followups/bulk-action` only handles state transitions | app.py:3071 |
| 3 | No bulk scheduling | No schedule actions, no UI | app.py, index.html |
| 4 | No recurring | No recurring fields on model, scheduler doesn't support it | models.py, app.py |
| 5 | No bulk selection UI | No checkboxes, no `selectedFuIds` state, no bulk action bar | index.html |

---

## Data Model Changes

### FollowupContact — 3 new fields

```python
recurring_enabled = db.Column(db.Boolean, default=False)
recurring_days    = db.Column(db.String(20))   # "0,2,4" = Mon/Wed/Fri (0=Mon…6=Sun); validated non-empty on save
recurring_time    = db.Column(db.String(5))    # "HH:MM" stored as UTC; UI must submit UTC
```

`is_followup_enabled` (existing) controls only the **FU sequence** (FU1→FU2→FU3). `recurring_enabled` controls **recurring sends** independently. The two systems are separate — a contact can have sequence disabled and recurring enabled simultaneously.

`to_dict()` must include all three new fields so the frontend can display recurring status and pre-fill the modal.

### Template model — extend existing (no new table)

The existing `Template` model (`type='followup'`, `level` field) already stores FU templates. **No new table created.** Changes:
- Remove the constraint that only `level IN ('FU1','FU2','FU3')` is valid — allow any string level name (e.g., 'FU4', 'FU-General')
- Add `+ Add Template` UI to the existing Follow-up Templates section
- Template selection at send time: pick **random active template** from `Template.query.filter_by(user_id=uid, type='followup', is_active=True)`. No subject field — FU emails are reply-thread sends using `fc.reply_subject`.
- Existing FU1/FU2/FU3 templates remain as-is in the existing table.

**Template selection by mode:**
- **Sequence Send** — picks random from pool (stage still advances FU1→FU2→FU3 to track count; template content is random)
- **Free Send** — picks random from pool, stage unchanged
- **Recurring Send** — picks random from pool, stage unchanged
- **Empty pool guard** — if no active templates exist, action returns `{"ok": false, "error": "No active follow-up templates. Add at least one before sending."}` before attempting any sends

---

## Backend Changes

### 1. Fix Send Now (app.py:3001) — EmailAccount only

```python
# Before (wrong — these fields don't exist on EmailAccount):
cfg = {'name': acct.sender_name or '', 'company': acct.company_name or '', 'phone': acct.phone or ''}
# After (correct EmailAccount field names):
cfg = {'name': acct.your_name or '', 'company': acct.your_company or '', 'phone': acct.your_phone or ''}
```

### 2. Two Send Modes

| Mode | Action | Stage | Auto-FU Sequence | Recurring |
|------|--------|-------|-----------------|-----------|
| Sequence Send | `send-now` (existing) | Advances FU1→FU2→FU3 | Continues | Unaffected |
| Free Send | `free-send` (new) | Unchanged | `is_followup_enabled=False` (stops sequence) | Unaffected |

### 3. New Actions — `/api/followups/action` and `/api/followups/bulk-action`

**`free-send`**
- Pick random active template, send, set `is_followup_enabled=False`, log event `type='free_send'`
- Eligible: `state not in ('blocked', 'closed')` and active template pool non-empty

**`schedule-once`**
- Set `next_followup_at` to provided datetime (ISO8601 UTC string from frontend)
- Minimum: 1 minute in future. No maximum.
- Eligible: `state not in ('blocked', 'closed')`
- Log event `type='scheduled_once'`

**`set-recurring`**
- Payload: `{ recurring_days: "0,2,4", recurring_time: "08:00" }` — time in UTC
- Validate: `recurring_days` non-empty, time format HH:MM, days 0–6
- Set `recurring_enabled=True`, store fields, calculate first `next_followup_at` via `_next_recurring_datetime()`
- Eligible: `state not in ('blocked', 'closed')`
- If contact is `paused`/`warm`/`loads`: save recurring config but scheduler won't fire until state returns to `active`
- Log event `type='recurring_set'`

**`stop-recurring`**
- Set `recurring_enabled=False`, log event `type='recurring_stopped'`

All four new actions are supported in both single (`/action`) and bulk (`/bulk-action`) endpoints.

### 4. New Route: `GET /api/followups/ids`

Required for "select all filtered" frontend feature. Accepts same query params as `GET /api/followups` (`state`, `stage`, `filter`, `q`) but returns only IDs:

```json
{ "ids": ["abc123", "def456", ...] }
```

No pagination — returns all matching IDs for the current filter.

### 5. Scheduler — Two Independent Paths

The existing `_run_scheduled_followups()` is extended with a **second query path** for recurring contacts:

**Path 1 — Sequence path (existing, unchanged):**
```python
contacts = FollowupContact.query.filter(
    FollowupContact.state == 'active',
    FollowupContact.is_followup_enabled == True,
    FollowupContact.stage.in_(['fu1_scheduled','fu2_scheduled','fu3_scheduled']),
    FollowupContact.next_followup_at <= now,
).with_for_update(skip_locked=True).all()
```
After send: advances stage via `STAGE_PROGRESSION`, recalculates `next_followup_at` by delay days. Template: random from pool.

**Path 2 — Recurring path (new):**
```python
recurring = FollowupContact.query.filter(
    FollowupContact.state == 'active',
    FollowupContact.recurring_enabled == True,
    FollowupContact.next_followup_at <= now,
).with_for_update(skip_locked=True).all()
```
After send: stage unchanged, recalculate `next_followup_at` via `_next_recurring_datetime()`. Template: random from pool. Log event `type='recurring_sent'`.

A contact can appear in both paths on the same run only if it has both `is_followup_enabled=True` (sequence active) and `recurring_enabled=True`. To avoid double-send, skip Path 2 for contacts already processed in Path 1 within the same run (track by ID in a local set).

### 6. Recurring Next-Date Logic

```python
def _next_recurring_datetime(recurring_days: str, recurring_time: str) -> datetime:
    """Return next UTC datetime matching one of recurring_days at recurring_time (UTC).
    recurring_days: comma-separated weekday ints, 0=Mon…6=Sun
    recurring_time: "HH:MM" UTC

    Starts checking from today (offset=0) — if today's weekday matches and
    the scheduled time is still in the future, schedules for today.
    Otherwise finds the next matching weekday (up to 7 days ahead).
    """
    days = [int(d) for d in recurring_days.split(',') if d.strip().isdigit()]
    if not days:
        raise ValueError(f"recurring_days is empty or invalid: {recurring_days!r}")
    h, m = map(int, recurring_time.split(':'))
    now = datetime.utcnow()
    for offset in range(0, 8):
        candidate = (now + timedelta(days=offset)).replace(hour=h, minute=m, second=0, microsecond=0)
        if candidate.weekday() in days and candidate > now:
            return candidate
    raise ValueError(f"No valid day found in recurring_days={recurring_days!r} — this should be unreachable with valid input")
```

**Timezone rule:** `recurring_time` is always stored and interpreted as **UTC**. The frontend time picker must include a visible `(UTC)` label. No user-timezone field added at this stage.

**Re-activation behavior:** When `set-recurring` is called on a paused/warm/loads contact, `next_followup_at` is computed immediately. If the contact remains inactive past that datetime, the scheduler will fire immediately upon the contact becoming active again (rather than waiting for the next scheduled day). This is the intended behavior — re-activation triggers a send ASAP, then recurring resumes on the normal schedule.

### 7. Follow-up Templates CRUD Routes

Reuse existing `/api/templates` routes with `type='followup'`. Only needed change: remove server-side validation that restricts level to FU1/FU2/FU3. The UI allows creating templates with any name.

```
GET    /api/templates?type=followup     list all FU templates for user
POST   /api/templates                   create (body includes type='followup')
PUT    /api/templates/<id>              update
DELETE /api/templates/<id>              soft delete (is_active=False)
```

---

## Frontend Changes

### 1. Bulk Selection State

```javascript
let selectedFuIds = new Set();

function toggleFuSelect(id) {
    selectedFuIds.has(id) ? selectedFuIds.delete(id) : selectedFuIds.add(id);
    renderFuSelection();
}
function selectAllVisibleFu() {
    fuContacts.forEach(c => selectedFuIds.add(c.id));
    renderFuSelection();
}
async function selectAllFilteredFu() {
    // Fetch all IDs matching current filters from /api/followups/ids
    const params = buildFuFilterParams();
    const res = await fetch('/api/followups/ids?' + params);
    const { ids } = await res.json();
    ids.forEach(id => selectedFuIds.add(id));
    renderFuSelection();
}
function clearFuSelection() { selectedFuIds.clear(); renderFuSelection(); }
```

### 2. Checkbox on Each Contact Card

Small checkbox top-left of each card. Selected cards get a highlighted border. Selection state survives filter changes (IDs remain in Set even if contact scrolls off).

### 3. Bulk Action Bar

Appears when `selectedFuIds.size > 0`, fixed below filters:
```
[✕]  12 selected  [Select all filtered (47)]  |  [▶ Send Now]  [📤 Free Send]  [📅 Schedule]  [⏸ Pause]  [🚫 Block]
```

"Select all filtered (N)" button appears only when visible count < total filtered count.

### 4. Schedule Modal — One modal, two tabs

**One-time tab:**
```
📅 Date: [date input]    🕐 Time: [08:00] (UTC)
[Schedule for N selected]
```
Frontend converts local datetime to ISO8601 UTC before submitting.

**Recurring tab:**
```
Days: [Mon] [Tue] [Wed] [Thu] [Fri] [Sat] [Sun]   ← toggle buttons, multi-select
Time: [08:00] (UTC)
[Set recurring for N selected]   [Stop recurring for N selected]
```

### 5. Per-Contact Dropdown — New Items

Added to existing `···` dropdown:
- **Free Send** — sends now, stops sequence auto-FU
- **Schedule once** — opens One-time tab pre-filled
- **Set recurring** — opens Recurring tab
- **Stop recurring** (shown only if `recurring_enabled=true`)

### 6. Follow-up Templates Section

Extends existing Follow-up Templates UI:
- List of templates with Name, body preview, active toggle, Edit / Delete buttons
- **+ Add Template** button — inline form or small modal (matches Outreach Templates UX)
- Templates can have any name (not restricted to FU1/FU2/FU3)
- No subject field — FU emails are reply-thread sends

---

## Send Eligibility Rules

**Sequence Send (`send-now`):**
- `state = 'active'`
- `stage in ('fu1_scheduled', 'fu2_scheduled', 'fu3_scheduled')`
- `is_followup_enabled = True`
- Active template pool non-empty

**Free Send (`free-send`):**
- `state not in ('blocked', 'closed')`
- Active template pool non-empty

**Schedule Once / Set Recurring:**
- `state not in ('blocked', 'closed')`
- Recurring config saved even for paused/warm/loads contacts; scheduler only fires when `state = 'active'`

**Recurring scheduler fires when:**
- `state = 'active'`
- `recurring_enabled = True`
- `next_followup_at <= now`

**Recurring stops when:**
- Contact becomes `blocked` or `closed` (scheduler skips; `recurring_enabled` remains True until user explicitly stops)
- User calls `stop-recurring`

**Bulk action ineligible contacts:** skipped individually with per-contact error in response summary. Eligible contacts proceed. Summary returned: `{ sent: 8, skipped: 2, errors: [...] }`.

---

## Files Changed

| File | Changes |
|------|---------|
| `app.py` | Fix EmailAccount attr bug; add `free-send`, `schedule-once`, `set-recurring`, `stop-recurring` actions to single + bulk endpoints; add `GET /api/followups/ids`; update scheduler with two paths + random template selection; remove level restriction on FU templates |
| `models.py` | Add `recurring_enabled`, `recurring_days`, `recurring_time` to FollowupContact; add fields to `to_dict()`; DB migration |
| `templates/index.html` | Add checkboxes, `selectedFuIds` state, bulk action bar, `selectAllFilteredFu()`, schedule modal with two tabs, per-contact dropdown items, Follow-up Templates "+ Add" UI |

---

## Final User Flow

**Send Now (single):** Click "Send Now" on card → random template sent → stage advances → auto-FU continues.

**Free Send (single):** `···` → "Free Send" → random template sent → stage unchanged → sequence auto-FU disabled.

**Bulk Send Now:** Select contacts → "Send Now" in bar → eligible contacts get sequence send, ineligible skipped → summary shown.

**Bulk Free Send:** Select contacts → "Free Send" in bar → all eligible get random template, sequence disabled → summary.

**Schedule Once:** Select → "Schedule" → One-time tab → pick date + UTC time → confirm → `next_followup_at` set for all selected.

**Recurring Mon/Wed/Fri 08:00 UTC:** Select → "Schedule" → Recurring tab → toggle Mon/Wed/Fri → set 08:00 → "Set recurring" → scheduler auto-sends on those days, recalculates next occurrence after each send.

**Stop Recurring:** Select → "Schedule" → Recurring tab → "Stop recurring" OR `···` → "Stop recurring".

**Add Template:** Follow-up Templates section → "+ Add Template" → fill name + body → Save → immediately available for random selection.
