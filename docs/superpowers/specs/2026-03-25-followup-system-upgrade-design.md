# Follow-up System Upgrade — Design Spec

**Date:** 2026-03-25
**Status:** Draft
**Scope:** Data model, scheduler, state machine, API, UI, analytics

---

## 1. Overview

Upgrade Follow-ups from a simple FU1 → FU2 → FU3 flow into a proper contact lifecycle system with:
- Separated follow-up **stages** and contact **states**
- Manual control actions
- Event history (audit trail)
- Configurable settings per workspace
- Follow-up conversion analytics
- New entry points (manual add + from replies)

The system must remain simple and optimized for daily use by freight brokers.

---

## 2. Data Model

### 2.1 `followup_contacts` (new table, replaces `follow_ups`)

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| id | String (UUID) | uuid4 | PK |
| user_id | String FK → User | | NOT NULL |
| workspace_id | String FK → Workspace | | NOT NULL |
| contact_email | String | | NOT NULL |
| contact_name | String | | nullable |
| company_name | String | | nullable |
| state | String | 'active' | Enum: active / paused / warm / loads / blocked / closed |
| stage | String | 'fu1_scheduled' | Enum: initial / fu1_scheduled / fu1_sent / fu2_scheduled / fu2_sent / fu3_scheduled / fu3_sent / completed_fu3 |
| is_followup_enabled | Boolean | True | Auto-send toggle |
| next_followup_at | DateTime | | When scheduler should send next FU |
| last_followup_sent_at | DateTime | | When last FU was actually sent |
| last_reply_at | DateTime | | When contact last replied |
| last_activity_at | DateTime | | Any activity (send/reply) |
| initial_email_sent_at | DateTime | | When first outreach was sent |
| fu1_sent_at | DateTime | | |
| fu2_sent_at | DateTime | | |
| fu3_sent_at | DateTime | | |
| completed_fu3_at | DateTime | | |
| loads_at | DateTime | | When marked as loads |
| warm_at | DateTime | | When marked as warm |
| blocked_at | DateTime | | |
| closed_at | DateTime | | |
| paused_at | DateTime | | |
| resumed_at | DateTime | | |
| block_reason | String | | nullable |
| pause_reason | String | | nullable |
| close_reason | String | | nullable |
| source_thread_id | String | | Gmail thread ID (if from reply) |
| source_reply_id | String | | Reply record ID (if from reply) |
| current_route | String | | Freight route |
| notes | Text | | User notes |
| created_at | DateTime | utcnow | |
| updated_at | DateTime | utcnow | Auto-update on change |

**Indexes:**
- `(workspace_id, state)`
- `(workspace_id, stage)`
- `(workspace_id, next_followup_at)`
- `(workspace_id, contact_email)` — unique within workspace
- `(user_id, state)`

### 2.2 `followup_events` (new table)

| Field | Type | Notes |
|-------|------|-------|
| id | String (UUID) | PK |
| followup_contact_id | String FK → followup_contacts | CASCADE delete |
| workspace_id | String FK | For direct queries |
| event_type | String | state_change / stage_advance / manual_send / auto_send / reply_detected / created / note_added |
| from_state | String | nullable |
| to_state | String | nullable |
| from_stage | String | nullable |
| to_stage | String | nullable |
| event_at | DateTime | utcnow |
| actor_type | String | user / system / scheduler |
| actor_user_id | String | nullable |
| metadata_json | Text | JSON — error details, template used, etc. |
| notes | String | nullable |

**Index:** `(followup_contact_id, event_at)`

### 2.3 `followup_settings` (new table)

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| id | String (UUID) | | PK |
| workspace_id | String FK → Workspace | | UNIQUE |
| fu1_delay_days | Integer | 3 | Days before FU1 auto-send |
| fu2_delay_days | Integer | 5 | Days before FU2 auto-send |
| fu3_delay_days | Integer | 7 | Days before FU3 auto-send |
| auto_stop_on_reply | Boolean | True | Stop FU when reply detected |
| default_followup_enabled | Boolean | True | Default for new contacts |
| created_at | DateTime | utcnow | |
| updated_at | DateTime | utcnow | |

### 2.4 Migration Strategy

**Approach:** Full migration — create new tables, migrate data from `follow_ups`, drop old table.

**Mapping (old → new):**

| Old field | New field | Transformation |
|-----------|-----------|---------------|
| level=FU1, status=pending | stage=fu1_scheduled, state=active | is_followup_enabled=True |
| level=FU1, status=sent | stage=fu1_sent, state=active | is_followup_enabled=True |
| level=FU2, status=pending | stage=fu2_scheduled, state=active | |
| level=FU2, status=sent | stage=fu2_sent, state=active | |
| level=FU3, status=pending | stage=fu3_scheduled, state=active | |
| level=FU3, status=sent | stage=fu3_sent, state=active | |
| level=closed, status=closed | stage=completed_fu3, state=closed | |
| status=paused | state=paused | is_followup_enabled=False |
| status=failed | state=active | is_followup_enabled=True, last_error in notes |
| contact_email | contact_email | |
| contact_name | contact_name | |
| route | current_route | |
| last_contact | last_activity_at | |
| last_fu_sent | last_followup_sent_at | |
| added_at | created_at | |
| auto_enabled | is_followup_enabled | |
| scheduled_at | next_followup_at | |
| reply_msg_id | source_thread_id | |
| notes | notes | |

**Old `Workspace.fu_auto_enabled`** migrates to `followup_settings.default_followup_enabled`.

**Templates** remain unchanged — FU1/FU2/FU3 template names stay as-is. Scheduler maps stage to template name.

---

## 3. State Machine

### 3.1 Contact State (business state)

```
active  → paused, warm, loads, blocked, closed
paused  → active, warm, loads, blocked, closed
warm    → (terminal)
loads   → (terminal)
blocked → (terminal)
closed  → (terminal)
```

Terminal states cannot transition to other states. To re-engage a contact, the user creates a new follow-up contact record.

### 3.2 Follow-up Stage (sequence position)

```
initial → fu1_scheduled → fu1_sent → fu2_scheduled → fu2_sent → fu3_scheduled → fu3_sent → completed_fu3
```

Stage only moves forward. Never backwards.

### 3.3 What Stops Follow-ups

| Trigger | Action |
|---------|--------|
| Reply detected | `is_followup_enabled=false`, `last_reply_at=now`, `next_followup_at=null`. State stays active. |
| User pauses | `state=paused`, `is_followup_enabled=false`, `paused_at=now`, `next_followup_at=null` |
| User marks warm | `state=warm`, `is_followup_enabled=false`, `warm_at=now`, `next_followup_at=null` |
| User marks loads | `state=loads`, `is_followup_enabled=false`, `loads_at=now`, `next_followup_at=null` |
| User blocks | `state=blocked`, `is_followup_enabled=false`, `blocked_at=now`, `next_followup_at=null` |
| User closes | `state=closed`, `is_followup_enabled=false`, `closed_at=now`, `next_followup_at=null` |
| Completed FU3 | `stage=completed_fu3`, `is_followup_enabled=false`, `completed_fu3_at=now`, `next_followup_at=null`. State stays active. |

### 3.4 Invalid Transitions

The backend must reject:
- Any transition FROM terminal states (warm, loads, blocked, closed)
- Stage moving backwards
- `send-now` when state is not active
- `resume` when state is not paused

---

## 4. Scheduler Logic

### 4.1 Query Filter

Scheduler processes ONLY contacts where:
- `state = 'active'`
- `is_followup_enabled = True`
- `next_followup_at <= utcnow()`

### 4.2 Send Process

1. Load contact, verify still eligible
2. Determine template from stage: `fu1_scheduled → FU1`, `fu2_scheduled → FU2`, `fu3_scheduled → FU3`
3. Send email via `send_followup_email()`
4. On success:
   - Set `*_sent_at` timestamp for current stage
   - Advance stage to `*_sent`
   - If next stage exists: advance to `*_scheduled`, set `next_followup_at = now + delay`
   - If FU3 just sent: set `stage=completed_fu3`, `is_followup_enabled=false`, `completed_fu3_at=now`, `next_followup_at=null`
   - Update `last_followup_sent_at = now`, `last_activity_at = now`
   - Create `followup_events` record (event_type=auto_send, actor_type=scheduler)
5. On failure:
   - Store error in `followup_events` metadata_json
   - Do NOT change stage or state
   - Scheduler will retry on next cycle

### 4.3 Delay Configuration

Delays come from `followup_settings` for the workspace. Fallback to defaults if no settings record exists: FU1=3d, FU2=5d, FU3=7d.

### 4.4 Concurrency Safety

Maintain existing `SELECT FOR UPDATE SKIP LOCKED` pattern. Per-contact commits.

### 4.5 Stage → Template Mapping

| Stage being processed | Template key | After send stage |
|----------------------|-------------|-----------------|
| fu1_scheduled | FU1 | fu1_sent → fu2_scheduled |
| fu2_scheduled | FU2 | fu2_sent → fu3_scheduled |
| fu3_scheduled | FU3 | fu3_sent → completed_fu3 |

---

## 5. Entry Points

### 5.1 From Reply (existing, adapted)

When user marks a reply as "follow_up":
1. Check if `followup_contacts` record exists for this email+workspace
2. If exists: skip (don't create duplicate)
3. If not: create with `stage=fu1_scheduled`, `state=active`, `is_followup_enabled=true`
4. Set `next_followup_at = now + fu1_delay_days`
5. Auto-fill: `contact_name`, `company_name`, `current_route` from reply/send data
6. Set `source_thread_id`, `source_reply_id`
7. Create `followup_events` record (event_type=created, actor_type=user)

### 5.2 Manual Add (new)

From the "Add Contact" modal on the Follow-up page:

**Option A — Manual email entry:**
1. User enters email, optionally name and company
2. Check duplicates within workspace
3. Create `followup_contacts` with `stage=fu1_scheduled`, `state=active`
4. Set `next_followup_at = now + fu1_delay_days`
5. Create event record

**Option B — Pick from sent emails:**
1. API endpoint `/api/followups/candidates?q=search` returns recent sent emails not already in follow-ups
2. User clicks "Add" on a candidate
3. Auto-fill name, company, route from Send record
4. Same creation flow as Option A

---

## 6. Reply Detection Integration

### 6.1 Auto-stop on Reply

When `fetch_replies_from_gmail()` detects a reply from a contact that exists in `followup_contacts`:
1. Set `is_followup_enabled = false`
2. Set `last_reply_at = now`
3. Set `next_followup_at = null`
4. Set `last_activity_at = now`
5. State remains `active` — user decides what to do
6. Create `followup_events` record (event_type=reply_detected, actor_type=system)

This only applies if `followup_settings.auto_stop_on_reply = true` (default).

---

## 7. API Routes

### 7.1 New/Changed Endpoints

| Route | Method | Description |
|-------|--------|-------------|
| `/api/followups` | GET | List contacts with filters: `?state=&stage=&filter=&q=` |
| `/api/followups/add` | POST | Add contact (manual or from reply) |
| `/api/followups/action` | POST | Single action: pause/resume/warm/loads/block/close/send-now |
| `/api/followups/bulk-action` | POST | Bulk action for multiple contact IDs |
| `/api/followups/delete` | POST | Delete contact |
| `/api/followups/notes` | POST | Update notes |
| `/api/followups/analytics` | GET | Funnel + outcomes + conversion data |
| `/api/followups/candidates` | GET | Sent emails available for adding to FU: `?q=search` |
| `/api/settings/followup` | GET/POST | Workspace FU settings (delays, auto_stop) |
| `/api/fu-templates` | GET/POST | Unchanged |

### 7.2 Removed Endpoints (replaced)

| Old Route | Replaced By |
|-----------|-------------|
| `/api/followups/send` | `/api/followups/action` with `action=send-now` |
| `/api/followups/update` | `/api/followups/action` + `/api/followups/notes` |
| `/api/followups/toggle-auto` | `/api/followups/action` with `action=pause/resume` |
| `/api/followups/reschedule` | Removed — scheduler manages timing automatically |
| `/api/settings/fu-auto` | `/api/settings/followup` (expanded) |

### 7.3 Response: `/api/followups` (GET)

```json
{
  "contacts": [
    {
      "id": "uuid",
      "contact_email": "broker@example.com",
      "contact_name": "John",
      "company_name": "ABC Freight",
      "state": "active",
      "stage": "fu2_scheduled",
      "is_followup_enabled": true,
      "next_followup_at": "2026-03-28T09:00:00Z",
      "last_activity_at": "2026-03-25T14:00:00Z",
      "last_reply_at": null,
      "current_route": "Chicago, IL → Dallas, TX",
      "notes": "..."
    }
  ],
  "counts": {
    "total": 45,
    "active": 30,
    "paused": 5,
    "warm": 3,
    "loads": 4,
    "blocked": 2,
    "closed": 1,
    "needs_action": 3,
    "overdue": 2
  }
}
```

### 7.4 Request: `/api/followups/action` (POST)

```json
{
  "id": "contact-uuid",
  "action": "pause|resume|warm|loads|block|close|send-now",
  "reason": "optional reason text"
}
```

**Action rules:**
- `send-now`: requires `state=active`, sends next scheduled FU immediately
- `pause`: requires `state=active`
- `resume`: requires `state=paused`, sets `is_followup_enabled=true`, recalculates `next_followup_at`
- `warm`: requires `state=active|paused`
- `loads`: requires `state=active|paused`
- `block`: requires `state=active|paused`, stores `block_reason`
- `close`: requires `state=active|paused`, stores `close_reason`

All actions create `followup_events` records.

### 7.5 Request: `/api/followups/add` (POST)

```json
{
  "email": "broker@company.com",
  "name": "John Smith",
  "company": "ABC Freight",
  "route": "Chicago, IL → Dallas, TX",
  "source_reply_id": "optional-reply-uuid"
}
```

Returns 409 if contact email already exists in workspace.

### 7.6 Response: `/api/followups/analytics` (GET)

```json
{
  "funnel": {
    "initial": 100,
    "fu1": 85,
    "fu2": 60,
    "fu3": 35,
    "completed_fu3": 20
  },
  "outcomes": {
    "loads": 12,
    "warm": 8,
    "blocked": 5,
    "closed": 3
  },
  "conversion_by_stage": {
    "fu1_to_loads": 4,
    "fu2_to_loads": 5,
    "fu3_to_loads": 3
  }
}
```

**Funnel counts:** Based on `followup_events` with `event_type=stage_advance` or `event_type=auto_send`. Count contacts that reached each stage at any point (not just current state).

**Outcomes:** Count contacts currently in each terminal state + warm.

**Conversion by stage:** From `followup_events`: contacts whose last `stage_advance` before `state_change` to loads was at FU1/FU2/FU3.

### 7.7 Response: `/api/followups/candidates` (GET)

```json
{
  "candidates": [
    {
      "email": "dispatch@fastlane.com",
      "name": "Fast Lane Trucking",
      "company": "Fast Lane Trucking",
      "route": "Chicago, IL → Dallas, TX",
      "sent_at": "2026-03-23T10:00:00Z"
    }
  ]
}
```

Query: recent Send records for current user, excluding emails already in `followup_contacts`. Supports `?q=` search filter. Limited to 30 results, ordered by `sent_at DESC`.

---

## 8. Frontend — Follow-up Page

### 8.1 Page Structure

```
┌─────────────────────────────────────────────────┐
│ Follow-up                    [+ Add Contact]    │
│ Contact lifecycle & follow-up sequences         │
├─────────────────────────────────────────────────┤
│ [Contacts]  [Analytics]                         │
├─────────────────────────────────────────────────┤
│ [Search...] [All|FU1|FU2|FU3|Done] │            │
│             [Active|Paused|Warm|Loads|Bl|Cl]    │
│             [Needs Action(3)|Overdue|Due Today]  │
├─────────────────────────────────────────────────┤
│ Total:45  Active:30  FU1:12  FU2:10  ...        │
├─────────────────────────────────────────────────┤
│ ┌─ Contact Card ────────────────────────────┐   │
│ │ Company          [FU2][Active]  Next FU    │   │
│ │ email@...                       Tomorrow   │   │
│ │                                [Send][...] │   │
│ └───────────────────────────────────────────┘   │
│ (more cards...)                                  │
└─────────────────────────────────────────────────┘
```

### 8.2 Tabs

- **Contacts** — main list with filters and actions
- **Analytics** — funnel, outcomes, conversion charts

### 8.3 Filters

**Stage filters:** All / FU1 / FU2 / FU3 / Done (completed_fu3)
**State filters:** Active / Paused / Warm / Loads / Blocked / Closed
**Special filters:** Needs Action (completed_fu3 + state=active) / Overdue (next_followup_at < now) / Due Today
**Search:** By email, company name (client-side filter)

Only one filter active per group. Stage and state filters can combine.

### 8.4 Contact Card Row

| Section | Content |
|---------|---------|
| Left | `company_name` (bold), `contact_email` (muted) |
| Center | Stage badge (FU1 blue / FU2 yellow / FU3 red / Done purple), State badge (Active green / Paused yellow / Warm orange / Loads green / Blocked red / Closed gray) |
| Right | Next FU date (with overdue highlighting), Last activity date |
| Actions | Primary button (context-dependent) + "..." secondary menu |

### 8.5 Smart Primary Button

| Condition | Button | Color |
|-----------|--------|-------|
| state=active, has scheduled FU | Send Now | green |
| state=active, completed_fu3 | Loads | green |
| state=paused | Resume | green |
| terminal state (warm/loads/blocked/closed) | (hidden) | — |

### 8.6 Secondary Actions Menu ("...")

Available based on current state:
- **Pause** (if active)
- **Resume** (if paused)
- **Mark as Warm** (if active/paused)
- **Mark as Loads** (if active/paused)
- **Block** (if active/paused)
- **Close** (if active/paused)
- **Add Note** (always)
- **Delete** (always)

### 8.7 Visual Hierarchy

- **Overdue contacts:** red-tinted border
- **Needs Action (completed_fu3):** purple-tinted border
- **Paused:** row at 60% opacity
- **Terminal states (warm/loads/blocked/closed):** row at 50% opacity

### 8.8 Add Contact Modal

Two sections separated by "or pick from sent emails" divider:

**Top:** Manual entry — email input + Add button, optional name/company fields below
**Bottom:** Search sent emails + scrollable list of candidates with "Add" buttons. Contacts already in FU shown dimmed with "Already in FU" label.

### 8.9 Analytics Tab

Three sections:

**1. Sequence Funnel:** Horizontal bars showing Initial → FU1 → FU2 → FU3 → Completed with counts, percentages, and drop-off indicators between stages.

**2. Outcomes:** 2x2 grid of cards showing counts for Loads (green), Warm (orange), Blocked (red), Closed (gray).

**3. Conversion to Loads by Stage:** Horizontal bars showing how many contacts converted to Loads after FU1, FU2, FU3, plus total Loads conversion rate.

---

## 9. Performance Requirements

- All list queries filter by `workspace_id` using indexed columns
- Counts computed via SQL `COUNT` with `GROUP BY`, not Python loops
- Analytics queries use `followup_events` table with indexed `followup_contact_id`
- Candidates query uses `NOT IN (SELECT contact_email FROM followup_contacts WHERE workspace_id=...)` or LEFT JOIN
- No N+1 queries — batch load related data
- Scheduler uses `SELECT FOR UPDATE SKIP LOCKED` (PostgreSQL) with per-contact commits

---

## 10. Migration Safety

### 10.1 Steps

1. Create new tables (`followup_contacts`, `followup_events`, `followup_settings`)
2. Migrate data from `follow_ups` → `followup_contacts` using mapping from Section 2.4
3. Create `followup_settings` from `Workspace.fu_auto_enabled`
4. Verify migration: count records, spot-check data
5. Update all routes to use new tables
6. Drop old `follow_ups` table
7. Remove `Workspace.fu_auto_enabled` field

### 10.2 Rollback

Keep old `follow_ups` table during development (on feature branch). Only drop after production verification.

### 10.3 Branch Strategy

All work on `feature/followup-v2` branch. Old system on `main` continues to work. Merge only when fully tested.

---

## 11. Breaking Changes

- All `/api/followups/*` endpoints change request/response format
- Frontend follow-up page fully rewritten
- Old `follow_ups` table replaced by `followup_contacts`
- `Workspace.fu_auto_enabled` replaced by `followup_settings`
- Reply status "follow_up" handler creates `followup_contacts` instead of `FollowUp`

---

## 12. User Flow Summary

1. **Contact enters system:** User marks reply as "follow_up" OR manually adds from Follow-up page
2. **Auto follow-ups begin:** Scheduler sends FU1 after delay, then FU2, then FU3
3. **Reply detected:** Follow-ups stop, user sees contact needs decision
4. **After FU3 completed:** Contact shown in "Needs Action" filter, user chooses: Loads / Warm / Block / Close
5. **Manual intervention anytime:** User can Pause/Resume, mark as Warm/Loads, Block, Close at any stage
6. **Analytics:** User reviews funnel to see conversion rates and where contacts drop off
