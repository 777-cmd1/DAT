# Admin Activity Analytics Dashboard — Design Spec

## Summary

Upgrade the Admin panel from lifetime-only totals to a period-aware activity analytics dashboard. Admin can filter by time period (Today/Yesterday/7d/30d/Total), see top performers, identify inactive users, and sort accounts by activity metrics.

## Architecture

### Data Model

Metrics are split into three categories:

**A) Static/Lifetime (never filtered by period):**
- Total Users count
- Joined date
- Plan (free/starter/pro)
- Gmail connection status
- Workspace identity

**B) Period-Based (filtered by selected period):**
- Sends count
- Replies count
- Reply Rate (replies / sends %)
- Follow-ups count
- Active Users count
- Inactive Accounts count

**C) Inactivity-Derived (computed from last activity):**
- Active today: last send/reply within today
- Inactive 3d: last activity 3-7 days ago
- Inactive 7d: last activity 7-14 days ago (row muted)
- Inactive 14d+: last activity >14 days ago (row muted)

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
- Compute date range from `period` param
- `total_users`: `COUNT(users)` (no date filter)
- `active_users`: `COUNT(DISTINCT user_id)` from sends WHERE sent_at in range
- `sends`: `COUNT(sends)` WHERE status='sent' AND sent_at in range
- `replies`: `COUNT(replies)` WHERE received_at in range
- `reply_rate`: replies / sends * 100
- `followups`: `COUNT(follow_ups)` WHERE added_at in range
- `inactive_accounts`: total_users - active_users
- `top_users`: top 5 users by sends in period (SQL GROUP BY + ORDER BY + LIMIT 5)

All queries use SQL aggregation. No Python loops over all rows.

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

Query logic:
- One main query joining users with aggregated sends/replies/followups for the period
- `last_activity`: MAX(sent_at) from sends for each user (always lifetime, not filtered)
- `days_inactive`: computed from last_activity vs now
- Use subqueries or LEFT JOINs to get per-user counts in one pass
- Avoid N+1: do NOT iterate users and query each individually

**Existing endpoint preserved:** `GET /api/admin/stats/account/<user_id>` unchanged (detail modal).

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
- 3 cards (top 3 from top_users array)
- Each card: rank badge (gold/silver/bronze), email, sends/replies/rate
- Grid: 3 columns

**Accounts Table:**
- Sortable column headers (click to sort asc/desc)
- Columns: Email, Plan, Sends, Replies, Reply Rate, Follow-ups, Gmail, Last Active, Joined, Remove
- Sends/Replies/Reply Rate/Follow-ups reflect selected period
- Last Active column: activity dot + relative text
  - Green dot: active today
  - Yellow dot: 3-7 days inactive
  - Orange dot: 7-14 days inactive
  - Red dot: 14+ days inactive
- Rows with 7+ days inactive get `opacity: 0.5` (muted)
- Client-side sorting via JS (no backend re-fetch needed)

## Components

### Period Helper (backend)

```python
def _admin_date_range(period: str):
    """Return (start_dt, end_dt) for the given period string."""
    today = date.today()
    if period == 'today':
        return datetime.combine(today, datetime.min.time()), datetime.utcnow()
    elif period == 'yesterday':
        y = today - timedelta(days=1)
        return datetime.combine(y, datetime.min.time()), datetime.combine(today, datetime.min.time())
    elif period == '7d':
        return datetime.combine(today - timedelta(days=7), datetime.min.time()), datetime.utcnow()
    elif period == '30d':
        return datetime.combine(today - timedelta(days=30), datetime.min.time()), datetime.utcnow()
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
    let va = a[col], vb = b[col];
    if (typeof va === 'string') return sortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
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
| `app.py` | Modify `/api/admin/stats/overview` and `/api/admin/stats/accounts` to accept `period` param, use SQL aggregation with date ranges, add top_users to overview response |
| `templates/admin.html` | Add period filter bar, update overview cards (7 cards), add top users section, update accounts table (new columns, sort, inactivity dots), add JS sort/filter logic |

## Performance

- All queries use SQL `COUNT`, `GROUP BY`, `DATE()` filtering — no Python loops
- Accounts endpoint: single pass with LEFT JOINs or subqueries per user (not N+1)
- Top users: SQL `ORDER BY COUNT DESC LIMIT 5`
- No caching needed — admin panel is low-traffic (only admin uses it)
- Existing account detail modal endpoint unchanged

## Edge Cases

- User with 0 sends ever: `last_activity = NULL`, `days_inactive = NULL` → red dot, "Never", muted
- Period = Total: no date filter on any query, shows lifetime totals
- Reply Rate with 0 sends: show "—" not "0%" or "NaN"
- New user registered today with no sends: active_users does NOT count them (activity = sends only)
