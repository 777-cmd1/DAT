# Admin Activity Analytics Dashboard — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the admin panel from lifetime-only totals to a period-aware activity analytics dashboard with time filters, top users, inactivity indicators, and sortable accounts table.

**Architecture:** Modify two existing admin endpoints (`/api/admin/stats/overview` and `/api/admin/stats/accounts`) to accept a `?period=` query param and return period-filtered SQL-aggregated data. Rewrite the `templates/admin.html` frontend to add a period filter bar, 7 overview cards, top users section, and enhanced accounts table with sort and inactivity dots.

**Tech Stack:** Flask, SQLAlchemy (PostgreSQL), Jinja2 HTML template, vanilla JS

**Spec:** `docs/superpowers/specs/2026-03-24-admin-activity-analytics-design.md`

**Security note:** The admin panel uses an `esc()` helper function to HTML-escape all user-supplied data before rendering. All dynamic content inserted via innerHTML is escaped through this function. This is a pre-existing pattern in the codebase — see `templates/admin.html` line 758. The admin panel is only accessible to authenticated admin users (`@admin_required` decorator).

---

### Task 1: Backend — Add `_admin_date_range` helper and rewrite `/api/admin/stats/overview`

**Files:**
- Modify: `app.py` lines 713-742 (replace `api_admin_stats_overview`)

- [ ] **Step 1: Add `_admin_date_range` helper function**

Add this function before the overview route (around line 712):

```python
def _admin_date_range(period: str):
    """Return (start_dt, end_dt) for admin period filter. All times UTC."""
    now = datetime.utcnow()
    today = now.date()
    if period == 'today':
        return datetime.combine(today, datetime.min.time()), now
    elif period == 'yesterday':
        y = today - timedelta(days=1)
        return datetime.combine(y, datetime.min.time()), datetime.combine(today, datetime.min.time())
    elif period == '7d':
        return datetime.combine(today - timedelta(days=7), datetime.min.time()), now
    elif period == '30d':
        return datetime.combine(today - timedelta(days=30), datetime.min.time()), now
    else:  # 'total'
        return None, None
```

- [ ] **Step 2: Rewrite `api_admin_stats_overview`**

Replace the entire function body (lines 716-742). The new version accepts `?period=` query param and returns 7 metric fields + top_users + plans. Uses SQL COUNT with date range filters instead of Python loops. See spec for full response contract.

Key queries:
- `total_users`: COUNT(users) — no date filter
- `active_users`: COUNT(DISTINCT user_id) from sends WHERE sent_at in range
- `sends`: COUNT(sends) WHERE status='sent' AND sent_at in range
- `replies`: COUNT(replies) WHERE received_at in range
- `followups`: COUNT(follow_ups) WHERE status='sent' AND last_fu_sent in range
- `top_users`: GROUP BY user_id ORDER BY count DESC LIMIT 3, enriched with email + reply count

- [ ] **Step 3: Verify syntax**

Run: `python3 -c "import ast; ast.parse(open('app.py').read()); print('OK')"`

- [ ] **Step 4: Commit**

```bash
git add app.py
git commit -m "feat(admin): rewrite overview endpoint with period filter and top users"
```

---

### Task 2: Backend — Rewrite `/api/admin/stats/accounts` with period filter

**Files:**
- Modify: `app.py` lines 745-790 (replace `api_admin_stats_accounts`)

- [ ] **Step 1: Rewrite `api_admin_stats_accounts`**

Replace the entire function body. The new version:
- Accepts `?period=` query param
- Uses batch queries with `.in_(user_ids)` + `group_by` instead of per-user N+1 loops
- Returns period-aware `sends`, `replies`, `reply_rate`, `followups` per user
- Adds `days_inactive` (computed server-side from last_activity)
- Uses `google_refresh_token` for `email_connected` (not `gmail_address`)
- Removes `quota_used_today`, `quota_limit`, `sends_total`, `sends_today` (quota stays in detail modal)

Batch query approach:
1. Load all users, collect user_ids
2. Batch workspace lookup: `Workspace.query.filter(owner_id.in_(user_ids))`
3. Batch email account lookup: `EmailAccount.query.filter(user_id.in_(user_ids))`
4. Batch sends: `GROUP BY user_id` with date filter → `sends_map`
5. Batch replies: `GROUP BY user_id` with date filter → `replies_map`
6. Batch follow-ups: `GROUP BY user_id` with date filter → `fu_map`
7. Batch last activity: `MAX(sent_at) GROUP BY user_id` (always lifetime) → `last_act_map`
8. Build result array from maps

- [ ] **Step 2: Verify syntax**

Run: `python3 -c "import ast; ast.parse(open('app.py').read()); print('OK')"`

- [ ] **Step 3: Commit**

```bash
git add app.py
git commit -m "feat(admin): rewrite accounts endpoint with period filter and batch queries"
```

---

### Task 3: Frontend — Period filter bar, overview cards, top users (HTML + CSS)

**Files:**
- Modify: `templates/admin.html` — CSS section (add new styles)
- Modify: `templates/admin.html` — Overview section HTML (lines 282-299)

- [ ] **Step 1: Add new CSS classes**

After line 244 (before `@media`), add CSS for:
- `.period-bar` + `.period-btn` — period filter pill buttons
- `.section-title` — section header with accent bar
- `.top-users-grid` + `.top-card` + `.top-rank` + `.top-info` — top users cards
- `.activity-dot` variants — green/yellow/orange/red dots
- `.last-active-cell` — flex container for dot + label
- `tr.row-muted td` — opacity 0.5 for inactive users
- `th.sortable` / `th.sorted` + `.sort-icon` — sortable column headers
- `.all-time-badge` — small "ALL TIME" label on static cards

- [ ] **Step 2: Update stat-grid to 7 columns**

Change `.stat-grid` from `repeat(5, 1fr)` to `repeat(7, 1fr)` with 12px gap.
Update responsive breakpoint to `repeat(4, 1fr)`.

- [ ] **Step 3: Replace Overview section HTML**

Replace lines 282-299 with new HTML containing:
- Period filter bar with 5 buttons (Total/Today/Yesterday/7d/30d)
- 7 stat cards (Total Users with ALL TIME badge, Active Users, Sends, Replies, Reply Rate, Follow-ups, Inactive)
- Plan distribution pills (unchanged)
- Top Users section with title + grid container

- [ ] **Step 4: Commit**

```bash
git add templates/admin.html
git commit -m "feat(admin): add period filter bar, 7 overview cards, top users HTML/CSS"
```

---

### Task 4: Frontend — Rewrite JS for overview, period switching, top users

**Files:**
- Modify: `templates/admin.html` — JS section (lines 400-438)

- [ ] **Step 1: Add period state + setPeriod + rewrite loadOverview**

Replace JS state variables and functions:
- Add `currentPeriod = 'today'` and `PERIOD_LABELS` map
- Add `setPeriod(period)` — updates button active state, invalidates caches, reloads current tab
- Update `switchTab(tab)` — hides period bar on Invites, moves bar between Overview/Accounts
- Rewrite `loadOverview()` — fetches with `?period=${currentPeriod}`, populates 7 cards + top users grid
- All dynamic content escaped via existing `esc()` function

- [ ] **Step 2: Commit**

```bash
git add templates/admin.html
git commit -m "feat(admin): JS for period switching, overview data loading, top users rendering"
```

---

### Task 5: Frontend — Rewrite accounts table with sort, inactivity dots, period columns

**Files:**
- Modify: `templates/admin.html` — Accounts section HTML (lines 301-331)
- Modify: `templates/admin.html` — loadAccounts JS (lines 441-490)

- [ ] **Step 1: Replace Accounts section HTML**

New table headers: Email (sortable), Plan, Sends (sortable), Replies (sortable), Reply Rate (sortable), Follow-ups (sortable), Gmail, Last Active (sortable), Joined, Remove. Total 10 columns.

- [ ] **Step 2: Add inactivity helper + sort logic + rewrite loadAccounts**

Add `getInactivityInfo(daysInactive)` — returns `{dot, label, muted}` based on days_inactive value.

Add `sortAccounts(col)` — toggles sort direction, sorts accountsData array, calls renderAccountsTable, updates header indicators.

Rewrite `loadAccounts()` — fetches with `?period=${currentPeriod}`, stores data, calls sortAccounts.

Add `renderAccountsTable()` — builds table rows with:
- Activity dot + relative label in Last Active column
- Reply rate with color coding (green >=10%, yellow >=5%, muted otherwise)
- `row-muted` class on rows with 7+ days inactive
- All user data escaped via `esc()` function

- [ ] **Step 3: Commit**

```bash
git add templates/admin.html
git commit -m "feat(admin): accounts table with sort, inactivity dots, period-aware columns"
```

---

### Task 6: Frontend — Fix account detail modal to match backend response structure

**Files:**
- Modify: `templates/admin.html` — openAccountModal JS (lines 504-637)

- [ ] **Step 1: Fix modal data access to match nested backend response**

The backend returns nested structure (`d.user.email`, `d.workspace.plan`, `d.quota.used`) but the frontend currently accesses flat keys (`d.email`, `d.plan`, `d.quota_used_today`). Fix all access patterns:

- `d.email` → `d.user.email`
- `d.name` → `d.user.name`
- `d.plan` → `d.workspace.plan`
- `d.created_at` → `d.user.created_at`
- `d.workspace_name` → `d.workspace.name`
- `d.quota_used_today` → `d.quota.used`
- `d.quota_limit` → `d.quota.limit`
- `d.replies_by_status` → `d.replies`
- `d.followups_by_status` → `d.followups`

Remove the "Booked" reply status reference (line 600) — replace with "Total" showing `d.replies.total`.

- [ ] **Step 2: Commit**

```bash
git add templates/admin.html
git commit -m "fix(admin): align modal data access with nested backend response structure"
```

---

### Task 7: Verify and deploy

**Files:**
- `app.py`
- `templates/admin.html`

- [ ] **Step 1: Verify Python syntax**

Run: `python3 -c "import ast; ast.parse(open('app.py').read()); print('OK')"`

- [ ] **Step 2: Manual verification checklist**

1. `/api/admin/stats/overview?period=today` returns correct JSON
2. `/api/admin/stats/overview?period=total` returns lifetime totals
3. `/api/admin/stats/accounts?period=today` returns array with correct fields
4. Admin page shows period filter with 5 buttons
5. Overview shows 7 cards + plan pills + top users
6. Clicking period buttons refreshes data
7. Accounts table has sortable headers
8. Inactive users (7d+) have muted rows
9. Activity dots show correct colors
10. Account detail modal still works
11. Invites tab hides period filter

- [ ] **Step 3: Deploy**

```bash
git push origin main
```

- [ ] **Step 4: Clean up mockup file**

```bash
rm mockup_admin.html
git add -u && git commit -m "chore: remove admin mockup file"
```
