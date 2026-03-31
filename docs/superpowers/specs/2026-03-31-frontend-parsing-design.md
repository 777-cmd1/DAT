# Frontend Parsing Design

## Goal

Move DAT text parsing from backend (`/api/parse`) to the browser (vanilla JS) to eliminate network round-trip latency. Parsing should feel instant after page load.

## Problem

Current flow adds ~800–1000ms perceived delay per parse:
- 600ms debounce
- 150–300ms Railway network round-trip
- ~30ms backend processing

The backend already caches DB reads (sent log, stop list) with TTL, so the bottleneck is purely the network.

## Solution

Split into two independent flows:

### Flow 1 — Preload (once per Send tab open)
`GET /api/parse-context` returns all data the browser needs to classify loads:
```json
{
  "all_sent":     ["email@x.com|Chicago, IL|Atlanta, GA", ...],
  "sent_today":   ["email@x.com", ...],
  "stop_emails":  ["blocked@x.com", ...],
  "stop_domains": ["spammer.com", ...]
}
```
Stored in JS variable `_parseCtx`. Refreshed after each send job completes.

### Flow 2 — Parse (on text input, synchronous)
`parseDat()` calls local JS functions only — no fetch. Debounce reduced from 600ms → 150ms.

## Files to Change

| File | Change |
|------|--------|
| `app.py` | Add `GET /api/parse-context` route (~20 lines), reuses existing `load_sent_log()` + `load_stop_list()` with their TTL cache |
| `templates/index.html` | Add `_parseCtx`, `loadParseContext()`, `parseDatText()`, `classifyLoads()`. Rewrite `parseDat()` to be synchronous. Reduce debounce to 150ms. |

`/api/parse` is kept unchanged as fallback.

## Backend: `/api/parse-context`

```python
@app.route('/api/parse-context', methods=['GET'])
@login_required
def api_parse_context():
    be, bd = load_stop_list()          # already cached (TTL 300s)
    all_sent, sent_today = load_sent_log()  # already cached (TTL 90s)
    return jsonify({
        'all_sent':    list(all_sent),
        'sent_today':  list(sent_today),
        'stop_emails': list(be),
        'stop_domains': list(bd),
    })
```

Reuses existing caches — no extra DB load.

## Frontend JS

### Regex patterns (ported 1:1 from Python)

**Critical:** `_EMAIL_RE` has NO `/g` flag — it is used per-line like Python `.search()`. A `/g` regex in JS tracks `lastIndex` state across calls, which would cause every other line to be missed in a loop. All other patterns have `/g` because they are consumed by `_last()` which collects all matches.

```javascript
const _EMAIL_RE      = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/;
const _DATE_RE       = /\d{1,2}\/\d{1,2}(?:\s*-\s*\d{1,2}\/\d{1,2})?/g;
const _DATE_MONTH_RE = /(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}/g;
const _LEN_RE        = /\d{2,3}\s*ft/g;
const _WT_RE         = /[\d,]+\s*lbs/g;
const _EQUIP_RE      = /\b(VM|VR|FD|SD|V|F|R)\b/g;
const _EQUIP_WORD_RE = /\b(Van Air-Ride|Van or Reefer|Flatbed|Reefer|Van)\b/gi;
const _CITY_RE       = /^([A-Z][a-zA-Z\s\.]+,?\s+[A-Z]{2})(?:\s*\(\d*\))?$/;
const _MONTH_TO_NUM  = {Jan:'1',Feb:'2',Mar:'3',Apr:'4',May:'5',Jun:'6',
                        Jul:'7',Aug:'8',Sep:'9',Oct:'10',Nov:'11',Dec:'12'};
const _EQUIP_WORD_MAP = {'van':'V','reefer':'R','flatbed':'F','van or reefer':'VR','van air-ride':'V'};
const _NOT_CITY = new Set([
  'Full','Partial','Canceled','Equipment','Load','Truck',
  'Length','Weight','Commodity','Reference ID','Van','Reefer',
  'Flatbed','CONTACT INFORMATION','COMMENTS','VIEW ROUTE',
  'Van Air-Ride','Van or Reefer','Post now','Trip',
]);
```

### `_parseCtx` — parse context store

```javascript
let _parseCtx = { all_sent: new Set(), sent_today: new Set(), stop_emails: new Set(), stop_domains: new Set() };
```

### `loadParseContext()` — fetches and hydrates `_parseCtx`

```javascript
async function loadParseContext() {
  const res = await fetch('/api/parse-context');
  const d = await res.json();
  _parseCtx = {
    all_sent:     new Set(d.all_sent),
    sent_today:   new Set(d.sent_today),
    stop_emails:  new Set(d.stop_emails),
    stop_domains: new Set(d.stop_domains),
  };
}
```

Called when Send tab button is clicked (existing tab-switch handler). Called again after send job completes (polling detects `done: true`). Called after stop list saved (existing save success handler).

### `parseDatText(text)` — pure parse, no classification

Ports `parse_dat_text()` from Python exactly, including these non-trivial constructs:

**`_last(regex, txt)` helper** — equivalent to Python's inner `_last()` (returns last match in text):
```javascript
function _last(regex, txt) {
  regex.lastIndex = 0;  // reset /g regex before each use
  let m, last = null;
  while ((m = regex.exec(txt)) !== null) last = m;
  return last;
}
```

**`_M(str)` fake match object** — used when value is derived without regex (month-name date, equip word map):
```javascript
function _M(s) { return { group: () => s }; }
```

**City matching** — `_CITY_RE` applied to each individual stripped line of `block` (not `block_text`), matching Python's `for bl in block: cm = _CITY_RE.match(bl.strip())`.

**Tab-expansion pre-processing** — before the main loop, split each raw line on `\t` and flatten into individual tokens (same as Python lines 1881–1887). Both newline-per-field and tab-per-field DAT formats must work.

**Company walk** — walks backwards from email line (up to 8 lines), skipping phone numbers, section headers, emails, number-heavy lines, weights, lengths, DAT keywords, short all-caps codes, commodity ALL-CAPS lines, and EXT lines — exactly replicating Python's 7-rule skip sequence. Note: Python uses `_WT_RE.match(cand)` (prefix match). In JS use `_WT_RE.test(cand)` with `regex.lastIndex = 0` reset; practically identical for real data since weight/length strings start at the beginning of candidate lines.

Returns array of load objects `{email, origin, destination, date, equip, length, weight, company}`. No skip field at this stage.

### `classifyLoads(loads)` — applies skip logic using `_parseCtx`

```javascript
function classifyLoads(loads) {
  const stats = {total: loads.length, new: 0, skip_today: 0, skip_dup: 0, skip_sent: 0, skip_stop: 0};
  const seenInBatch = new Set();
  for (const l of loads) {
    const em = l.email.toLowerCase().trim();
    const dom = em.includes('@') ? em.split('@').slice(-1)[0] : '';  // slice(-1)[0] = Python's split('@')[-1]
    const key = `${em}|${l.origin}|${l.destination}`;
    if (_parseCtx.stop_emails.has(em) || (dom && _parseCtx.stop_domains.has(dom))) {
      l.skip = 'stop_list'; stats.skip_stop++;
    } else if (_parseCtx.sent_today.has(em)) {
      l.skip = 'today'; stats.skip_today++;
    } else if (seenInBatch.has(em)) {
      l.skip = 'in_batch'; stats.skip_dup++;
    } else if (_parseCtx.all_sent.has(key)) {
      l.skip = 'sent'; stats.skip_sent++;
    } else {
      l.skip = null; stats.new++; seenInBatch.add(em);
    }
  }
  return {loads, stats};
}
```

### Updated `parseDat()` — synchronous

```javascript
function parseDat() {
  const text = document.getElementById('datText').value.trim();
  if (!text) { toast('Paste DAT text first', true); return; }
  const loads = parseDatText(text);
  const data = classifyLoads(loads);
  parsedLoads = data.loads;
  sessionStorage.removeItem('dat_loads');
  sessionStorage.removeItem('dat_checked');
  renderParseResults(data);
  document.getElementById('parseResults').style.display = 'block';
}
```

`debounceParse` debounce reduced from 600ms → 150ms.

## Data Size Estimate

Even with 1000 sent emails, `all_sent` is ~1000 strings × ~50 chars = ~50KB JSON. Fetched once, stored as a `Set` for O(1) lookups.

## When to Refresh `_parseCtx`

| Trigger | Action |
|---------|--------|
| Send tab button clicked | Call `loadParseContext()` in tab-switch handler | Covers first open and re-open |
| Send job completes | Call in polling loop when `status.done === true` | So next parse sees new "Sent today" |
| Stop list saved | Call in `saveStopList()` success callback | So blocked emails excluded immediately |

**Known limitation:** Context is per-tab. Two browser tabs open simultaneously will not share state. Acceptable for a single-user-per-account SaaS app.

## What Changes Visually

Nothing — output is identical. Only speed changes: parsing goes from ~1s to ~150ms debounce + <5ms JS execution.

## Not in Scope

- Removing `/api/parse` (kept as-is)
- Changing render logic
- Pagination or virtualization of the loads table
