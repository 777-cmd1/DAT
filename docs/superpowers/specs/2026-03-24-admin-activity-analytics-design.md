# Admin Activity Analytics Dashboard — Design Spec

## Summary

Upgrade the Admin panel from lifetime-only totals to a period-aware activity analytics dashboard. Admin can filter by time period (Today/Yesterday/7d/30d/Total), see top performers, identify inactive users, and sort accounts by activity metrics.

## Architecture

### Data Model

Metrics are split into three categories:

**A) Static/Lifetime (never filtered by period):**
- Total Users count
- Joined date
- Plan (free/starter/pro) — resolved via `Workspace.owner_id`. Non-owner users default to `free` (current data model has no membership table; 1 user = 1 workspace in practice)
- Gmail connection status — defined as `bool(acct.google_refresh_token)` (OAuth token presence, not gmail_address)
- Workspace identity

**B) Period-Based (filtered by selected period):**
- Sends count
- Replies count
- Reply Rate (replies / sends %)
- Follow-ups sent count (filtered by `last_fu_sent`, status='sent')
- Active Users count — "Active" means sent at least one email in the period. Login-only or reply-management activity does not count.
- Inactive Accounts count (total_users - active_users)

**C) Inactivity-Derived (computed from last activity timestamp):**
- Active today: last send within today (`days_inactive = 0`)
- Recent: last activity 1-3 days ago (`days_inactive <= 3`, green dot)
- Inactive 3-7d: yellow dot, not muted
- Inactive 7-14d: orange dot, row muted
- Inactive 14d+: red dot, row muted

### Period Filter

One global filter at page level. Options: `Total | Today | Yesterday | 7 days | 30 days`.

- Affects Overview tab (cards + top users) and Accounts tab (table columns)
- Invites tab ignores the filter (static data)
- Default selection: Today
- Stored client-side (JS variable), not persisted

### Backend

**Modified endpoint:** `GET /api/admin/stats/overview?period=today`

Accepts query param `period`: `total | today | yesterday | 7d | 30d`

Returns:
```json
{
  "total_users": 12,
  "active_users": 5,
  "sends": 347,
  "replies": 28,
  "reply_rate": 8.1,
  "followups": 14,
  "inactive_accounts": 3,
  "plans": {"free": 6, "starter": 3, "pro": 3},
  "top_users": [
    {
      "email": "bohdan@ufcagency.com",
      "sends": 142,
      "replies": 12,
      "reply_rate": 8.5
    }
  ]
}
```

Query logic:
- Compute date range from `period` param using `_admin_date_range()` (all times UTC)
- `total_users`: `COUNT(users)` (no date filter)
- `active_users`: `COUNT(DISTINCT user_id)` from sends WHERE sent_at in range
- `sends`: `COUNT(sends)` WHERE status='sent' AND sent_at in range
- `replies`: `COUNT(replies)` WHERE received_at in range
- `reply_rate`: replies / sends * 100
- `followups`: `COUNT(follow_ups)` WHERE last_fu_sent in range AND status='sent'
- `inactive_accounts`: total_users - active_users
- `top_users`: top 3 users by sends in period (SQL GROUP BY + ORDER BY + LIMIT 3)

All queries use SQL aggregation. No Python loops over all rows.

**Breaking changes from old overview response:**
- Removed: `total_workspaces` (redundant, 1:1 with users), `sends_today` (replaced by period-aware `sends`), `replies_total` (replaced by `replies`), `active_users_24h` (replaced by `active_users`)
- Added: `reply_rate`, `followups`, `inactive_accounts`, `top_users`
- Frontend element IDs (`ov-ws`, `ov-sends`, `ov-replies`, `ov-active`) will be replaced with new ones

**Modified endpoint:** `GET /api/admin/stats/accounts?period=today`

Accepts same `period` param.

Returns array with period-aware activity columns:
```json
[{
  "user_id": "uuid",
  "email": "user@example.com",
  "name": "User Name",
  "workspace_name": "Workspace",
  "plan": "free",
  "created_at": "2025-01-10",
  "sends": 142,
  "replies": 12,
  "reply_rate": 8.5,
  "followups": 5,
  "email_connected": true,
  "last_activity": "2025-03-24T14:30:00",
  "days_inactive": 0
}]
```

**Breaking changes from old accounts response:**
- Removed: `sends_total`, `sends_today` (replaced by period-aware `sends`), `quota_used_today`, `quota_limit` (quota info moved to detail modal only — admin rarely needs per-row quota)
- Added: `replies`, `reply_rate`, `followups`, `days_inactive`
- `replies_total`, `followups_total` renamed to `replies`, `followups` (now period-aware)

Query logic:
- One main query joining users with aggregated sends/replies/followups for the period
- `last_activity`: MAX(sent_at) from sends for each user (always lifetime, not filtered)
- `days_inactive`: computed server-side from last_activity vs `datetime.utcnow()`
- Use subqueries or LEFT JOINs to get per-user counts in one pass
- Avoid N+1: do NOT iterate users and query each individually

**Existing endpoint preserved:** `GET /api/admin/stats/account/<user_id>` unchanged (detail modal keeps quota info).

### Frontend

**Period Filter Bar:**
- Row of pill buttons below tabs: `Total | Today | Yesterday | 7 days | 30 days`
- Active state: filled accent background
- Clicking a period re-fetches overview + accounts data with `?period=X`
- Hidden when Invites tab is active

**Overview Cards (7):**
1. Total Users — static, "ALL TIME" badge
2. Active Users — green value, sub: "of N total"
3. Sends — accent value
4. Replies — blue value
5. Reply Rate — yellow value, sub: "replies / sends"
6. Follow-ups — default value
7. Inactive — red value

All cards except Total Users update when period changes.

**Top Users Section:**
- Title: "Top Users — {period label}"
- 3 cards (top 3 from top_users array, backend returns exactly 3)
- Each card: rank badge (gold/silver/bronze), email, sends/replies/rate
- Grid: 3 columns

**Accounts Table:**
- Sortable column headers (click to sort asc/desc)
- Columns: Email, Plan, Sends, Replies, Reply Rate, Follow-ups, Gmail, Last Active, Joined, Remove
- Sends/Replies/Reply Rate/Follow-ups reflect selected period
- Last Active column: activity dot + relative text
  - Green dot: active today or within 3 days
  - Yellow dot: 3-7 days inactive
  - Orange dot: 7-14 days inactive
  - Red dot: 14+ days inactive or never active
- Rows with 7+ days inactive get `opacity: 0.5` (muted)
- Client-side sorting via JS (no backend re-fetch needed)

## Components

### Period Helper (backend)

```python
def _admin_date_range(period: str):
    """Return (start_dt, end_dt) for the given period string. All times UTC."""
    now = datetime.utcnow()
    today = now.date()  # UTC date, not local
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
        return None, None  # no date filter
```

### Sort Logic (frontend)

```javascript
let sortCol = 'sends', sortDir = 'desc';
function sortAccounts(col) {
  if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
  else { sortCol = col; sortDir = 'desc'; }
  accountsData.sort((a, b) => {
    let va = a[col] ?? '', vb = b[col] ?? '';
    if (typeof va === 'string') return sortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
    va = va ?? -1; vb = vb ?? -1;
    return sortDir === 'asc' ? va - vb : vb - va;
  });
  renderAccounts();
}
```

### Inactivity Logic (frontend)

```javascript
function getInactivityInfo(daysInactive) {
  if (daysInactive === null || daysInactive === undefined) return { dot: 'inactive-14d', label: 'Never', muted: true };
  if (daysInactive === 0) return { dot: 'active-today', label: 'Today', muted: false };
  if (daysInactive <= 3) return { dot: 'active-today', label: `${daysInactive}d ago`, muted: false };
  if (daysInactive <= 7) return { dot: 'inactive-3d', label: `${daysInactive}d ago`, muted: false };
  if (daysInactive <= 14) return { dot: 'inactive-7d', label: `${daysInactive}d ago`, muted: true };
  return { dot: 'inactive-14d', label: `${daysInactive}d ago`, muted: true };
}
```

## Files Changed

| File | Change |
|------|--------|
| `app.py` | Modify `/api/admin/stats/overview` and `/api/admin/stats/accounts` to accept `period` param, use SQL aggregation with date ranges, add `_admin_date_range()` helper, add top_users to overview response |
| `templates/admin.html` | Add period filter bar, replace overview cards (7 new cards), add top users section, update accounts table (reply rate + follow-ups columns, sort headers, inactivity dots), add JS sort/filter/period logic |

## Performance

- All queries use SQL `COUNT`, `GROUP BY`, date range filtering — no Python loops
- Accounts endpoint: single pass with LEFT JOINs or subqueries per user (not N+1)
- Top users: SQL `ORDER BY COUNT DESC LIMIT 3`
- No caching needed — admin panel is low-traffic (only admin uses it)
- Existing account detail modal endpoint unchanged
- Existing index `ix_sends_user_sent` on `(user_id, sent_at)` covers per-user date-filtered queries

## Edge Cases

- User with 0 sends ever: `last_activity = NULL`, `days_inactive = NULL` → red dot, "Never", muted
- Period = Total: no date filter on any query, shows lifetime totals
- Reply Rate with 0 sends: show "—" not "0%" or "NaN"
- New user registered today with no sends: active_users does NOT count them (activity = sends only)
- Null values in sort: null-coalesced to empty string or -1 to prevent NaN in comparisons
- Non-owner users: shown with plan='free' and workspace_name from their own workspace (if exists) or '--'

## Known Limitations

- Workspace/plan model: currently 1 user = 1 workspace (owner). No membership table for invited-to-workspace users. If multi-user workspaces are needed later, a `WorkspaceMember` model should be added.
- "Active" definition: only counts email sends, not logins or reply-checking. This matches the app's core value (outreach volume).
