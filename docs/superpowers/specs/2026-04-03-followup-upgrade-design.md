# Follow-up System Upgrade — Design Spec
**Date:** 2026-04-03
**Status:** Approved

---

## Overview

Upgrade the Follow-up system for reliable daily operational use. The core change is adding bulk selection, two send modes (sequence vs free), flexible scheduling (one-time + recurring), and an expandable template pool with random selection.

---

## Audit Summary

### What's Working
- Auto-scheduler daemon (15-min interval), FU1→FU2→FU3 stage progression
- Filtering, search, state transitions (pause/resume/block/close/warm/loads)
- Per-contact actions, event logging, workspace settings

### Root Causes Found

| # | Problem | Root Cause | Location |
|---|---------|-----------|----------|
| 1 | Send Now broken | `acct.sender_name` / `.company_name` / `.phone` don't exist — should be `acct.your_name` / `.your_company` / `.your_phone` | app.py:3001–3002 |
| 2 | No bulk send | `/api/followups/bulk-action` only handles state transitions, no `send-now` | app.py:3071 |
| 3 | No bulk scheduling | No `schedule-once` or `set-recurring` actions, no UI | app.py, index.html |
| 4 | No recurring | No recurring fields on model, scheduler doesn't support it | models.py, app.py |
| 5 | No bulk selection UI | No checkboxes, no `selectedFuIds` state, no bulk action bar | index.html |

---

## Data Model Changes

### FollowupContact — 3 new fields

```python
recurring_enabled = db.Column(db.Boolean, default=False)
recurring_days    = db.Column(db.String(20))   # "0,2,4" = Mon/Wed/Fri (0=Mon…6=Sun)
recurring_time    = db.Column(db.String(5))    # "08:00"
```

`is_followup_enabled` (existing) is reused: free send sets it to `False` → scheduler skips the contact automatically.

### FollowupTemplate — new table

```python
class FollowupTemplate(db.Model):
    id             = db.Column(db.String, primary_key=True, default=lambda: str(uuid4()))
    user_id        = db.Column(db.String, db.ForeignKey('user.id'))
    workspace_id   = db.Column(db.String, db.ForeignKey('workspace.id'))
    name           = db.Column(db.String(100))
    subject_tpl    = db.Column(db.String(300))
    body_tpl       = db.Column(db.Text)
    is_active      = db.Column(db.Boolean, default=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
```

- Replaces hardcoded FU1/FU2/FU3 template keys
- Every send (auto or manual) picks a **random active template** from the pool
- Existing FU1/FU2/FU3 template data migrated to this table on first run

---

## Backend Changes

### 1. Fix Send Now (app.py:3001)
```python
# Before:
cfg = {'name': acct.sender_name or '', 'company': acct.company_name or '', 'phone': acct.phone or ''}
# After:
cfg = {'name': acct.your_name or '', 'company': acct.your_company or '', 'phone': acct.your_phone or ''}
```

### 2. Two Send Modes

| Mode | Action | Stage | Auto-FU |
|------|--------|-------|---------|
| Sequence Send | `send-now` (existing) | Advances FU1→FU2→FU3 | Continues |
| Free Send | `free-send` (new) | Unchanged | `is_followup_enabled=False` |

### 3. New Actions — `/api/followups/action` and `/api/followups/bulk-action`

- **`free-send`** — pick random active template, send, set `is_followup_enabled=False`, log event
- **`schedule-once`** — set `next_followup_at` to provided datetime, log event
- **`set-recurring`** — set `recurring_enabled=True`, `recurring_days`, `recurring_time`, calculate first `next_followup_at`, log event
- **`stop-recurring`** — set `recurring_enabled=False`, log event

All new actions supported in both single and bulk endpoints.

### 4. Scheduler Updates (`_run_scheduled_followups`)

- Template selection: pick random `FollowupTemplate` where `is_active=True` and `user_id` matches
- After successful send:
  - If `recurring_enabled=True` → calculate next `next_followup_at` from `recurring_days` + `recurring_time`
  - If `recurring_enabled=False` → existing FU1→FU2→FU3 stage progression
- Safety: skip contacts where `state in ('blocked', 'closed', 'paused', 'warm', 'loads')`

### 5. Recurring Next-Date Logic

```python
def _next_recurring_datetime(recurring_days: str, recurring_time: str) -> datetime:
    """Return next UTC datetime matching one of the recurring_days at recurring_time."""
    days = [int(d) for d in recurring_days.split(',')]
    h, m = map(int, recurring_time.split(':'))
    now = datetime.utcnow()
    for offset in range(1, 8):
        candidate = now + timedelta(days=offset)
        if candidate.weekday() in days:
            return candidate.replace(hour=h, minute=m, second=0, microsecond=0)
    return now + timedelta(days=1)  # fallback
```

### 6. Follow-up Templates CRUD Routes

```
GET    /api/followup-templates          list all for current user
POST   /api/followup-templates          create new template
PUT    /api/followup-templates/<id>     update template
DELETE /api/followup-templates/<id>     delete (soft: is_active=False)
```

---

## Frontend Changes

### 1. Bulk Selection State

```javascript
let selectedFuIds = new Set();

function toggleFuSelect(id) { ... }
function selectAllVisibleFu() { ... }
function selectAllFilteredFu() { ... }  // fetches all matching IDs from backend
function clearFuSelection() { selectedFuIds.clear(); renderFuSelection(); }
```

### 2. Checkbox on Each Contact Card

Small checkbox top-left of each card. Visual highlight on selected cards (subtle border/bg).

### 3. Bulk Action Bar

Appears when `selectedFuIds.size > 0`:
```
[✕ Clear]  12 selected  [▶ Send Now]  [📤 Free Send]  [📅 Schedule]  [⏸ Pause]  [🚫 Block]
```

### 4. Schedule Modal

One modal with two tabs:

**One-time tab:**
```
📅 Date: [date input]    🕐 Time: [08:00]
[Schedule for all selected]
```

**Recurring tab:**
```
Days: [Mon] [Tue] [Wed] [Thu] [Fri] [Sat] [Sun]  (multi-select toggles)
Time: [08:00]
[Set recurring]   [Stop recurring for selected]
```

### 5. Per-Contact Dropdown — New Items

Added to existing `···` dropdown:
- **Free Send** — sends now, stops auto-FU
- **Schedule once** — opens One-time tab of modal pre-filled for this contact
- **Set recurring** — opens Recurring tab of modal
- **Stop recurring** — clears recurring fields

### 6. Follow-up Templates Section

New sub-section in Settings (or dedicated Templates tab in Follow-up):
- List of templates with Name, Subject preview, Active toggle
- **Edit** inline or modal
- **Delete** (soft delete)
- **+ Add Template** button
- Mirrors Outreach Templates UI pattern

---

## Send Eligibility Rules

**Can receive Sequence Send (`send-now`):**
- `state = 'active'`
- `stage in ('fu1_scheduled', 'fu2_scheduled', 'fu3_scheduled')`
- `is_followup_enabled = True`
- At least one active FollowupTemplate exists

**Can receive Free Send (`free-send`):**
- `state not in ('blocked', 'closed')`
- At least one active FollowupTemplate exists

**Can be Scheduled:**
- `state not in ('blocked', 'closed')`

**Recurring runs for:**
- `state = 'active'`
- `recurring_enabled = True`
- `is_followup_enabled = True`

**Recurring stops when:**
- Contact becomes `blocked`, `closed`, `paused`, `warm`, or `loads`
- User explicitly calls `stop-recurring`

---

## Files Changed

| File | Changes |
|------|---------|
| `app.py` | Fix Send Now attr bug; add `free-send`, `schedule-once`, `set-recurring`, `stop-recurring` actions; update scheduler for random template + recurring; add CRUD routes for FollowupTemplate |
| `models.py` | Add `recurring_enabled`, `recurring_days`, `recurring_time` to FollowupContact; add FollowupTemplate model; migration |
| `templates/index.html` | Add checkboxes, `selectedFuIds` state, bulk action bar, schedule modal, per-contact dropdown items, Follow-up Templates section |

---

## Final User Flow

**Send Now (single):** Click "Send Now" on card → sends FU in sequence → stage advances → next date auto-calculated.

**Free Send (single):** Click `···` → "Free Send" → sends random template → stage unchanged → auto-FU disabled for this contact.

**Bulk Send Now:** Select contacts → "Send Now" in bar → sends sequence FU to all eligible → ineligible contacts skipped with summary.

**Schedule Once:** Select contacts → "Schedule" → One-time tab → pick date/time → confirm → `next_followup_at` updated for all selected.

**Set Recurring Mon/Wed/Fri 08:00:** Select contacts → "Schedule" → Recurring tab → toggle Mon, Wed, Fri → set 08:00 → "Set recurring" → scheduler auto-sends on those days.

**Stop Recurring:** Select contacts → "Schedule" → Recurring tab → "Stop recurring for selected" OR per-contact `···` → "Stop recurring".

**Manage Templates:** Settings → Follow-up Templates → "+ Add Template" → fill name/subject/body → Save. All follow-ups now pick randomly from active templates.
