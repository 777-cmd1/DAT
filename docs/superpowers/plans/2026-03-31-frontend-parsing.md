# Frontend Parsing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move DAT text parsing from backend `/api/parse` to vanilla JS in the browser, eliminating the ~800–1000ms network round-trip on every parse.

**Architecture:** Add `GET /api/parse-context` backend endpoint that returns sent-log and stop-list data (already cached). In the frontend, port `parse_dat_text()` to JS as `parseDatText()`, add `classifyLoads()` using a local `_parseCtx` store, and rewrite `parseDat()` to call these synchronously instead of fetching. Load `_parseCtx` once when the Send tab opens and refresh it after sends and stop-list saves.

**Tech Stack:** Vanilla JS in `templates/index.html`, Flask route in `app.py`, existing TTL cache (`_cache_get`/`_cache_set`).

---

### Task 1: Add `/api/parse-context` backend route

**Files:**
- Modify: `app.py` — insert before the `@app.route('/api/parse', ...)` line (~line 2423)

- [ ] **Step 1: Insert the route**

Find this line in `app.py`:
```python
@app.route('/api/parse', methods=['POST'])
```
Insert immediately before it:
```python
@app.route('/api/parse-context', methods=['GET'])
@login_required
def api_parse_context():
    be, bd = load_stop_list()           # TTL-cached (300s)
    all_sent, sent_today = load_sent_log()  # TTL-cached (90s)
    return jsonify({
        'all_sent':     list(all_sent),
        'sent_today':   list(sent_today),
        'stop_emails':  list(be),
        'stop_domains': list(bd),
    })

```

- [ ] **Step 2: Verify the route works**

Start the app locally (`flask run --port 8080`) and run in browser console after logging in:
```javascript
fetch('/api/parse-context').then(r=>r.json()).then(console.log)
```
Expected: object with keys `all_sent`, `sent_today`, `stop_emails`, `stop_domains` — all arrays.

- [ ] **Step 3: Commit**

```bash
git add app.py
git commit -m "feat(parse): add /api/parse-context endpoint"
```

---

### Task 2: Add JS regex constants, helpers, and `_parseCtx` store

**Files:**
- Modify: `templates/index.html` — JS section, insert just before the `// ── PARSE ──` comment (~line 2854)

- [ ] **Step 1: Locate insertion point**

Find this comment in `templates/index.html`:
```javascript
// ── PARSE ────────────────────────────────────────────────────────────────────
let parsedLoads = [];
```

- [ ] **Step 2: Insert constants and helpers immediately before that comment**

```javascript
// ── PARSE CONSTANTS ──────────────────────────────────────────────────────────
// _EMAIL_RE has NO /g flag — used per-line like Python .search().
// /g regexes track lastIndex across calls and would skip every other line in a loop.
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

// Parse context: loaded once per Send tab open, refreshed after sends/stop-list saves
let _parseCtx = { all_sent: new Set(), sent_today: new Set(), stop_emails: new Set(), stop_domains: new Set() };

async function loadParseContext() {
  try {
    const res = await fetch('/api/parse-context');
    const d = await res.json();
    _parseCtx = {
      all_sent:     new Set(d.all_sent),
      sent_today:   new Set(d.sent_today),
      stop_emails:  new Set(d.stop_emails),
      stop_domains: new Set(d.stop_domains),
    };
  } catch(e) { /* fail silently — parsing still works, classification just uses empty sets */ }
}

// Returns last regex match in txt. Resets lastIndex before scanning (required for /g regexes).
function _parseLast(regex, txt) {
  regex.lastIndex = 0;
  let m, last = null;
  while ((m = regex.exec(txt)) !== null) last = m;
  return last;
}
// Fake match object for cases where value is derived without a regex (month dates, equip word map).
function _parseM(s) { return { group: () => s }; }

```

- [ ] **Step 3: Verify no JS errors**

Open browser console. Run:
```javascript
console.log(typeof loadParseContext, typeof _parseLast, _NOT_CITY.has('Full'))
```
Expected: `"function" "function" true`

---

### Task 3: Add `parseDatText()` — JS port of Python's `parse_dat_text()`

**Files:**
- Modify: `templates/index.html` — add directly after `_parseM` (still before `// ── PARSE ──`)

- [ ] **Step 1: Insert `parseDatText` function**

```javascript
function parseDatText(text) {
  // Tab-expand: split tab-separated lines into individual tokens (handles both DAT formats)
  const rawLines = text.trim().split('\n');
  const lines = [];
  for (const l of rawLines) {
    if (l.includes('\t')) {
      for (const t of l.split('\t')) { if (t.trim()) lines.push(t.trim()); }
    } else if (l.trim()) {
      lines.push(l.trim());
    }
  }

  const loads = [], seen = new Set();
  for (let i = 0; i < lines.length; i++) {
    const lineStr = lines[i];
    const emailM = _EMAIL_RE.exec(lineStr);
    if (!emailM) continue;
    const email = emailM[0].toLowerCase();

    // Lookback 30 lines (detailed DAT view has ~20 lines per load)
    const block = lines.slice(Math.max(0, i - 30), i);
    const blockText = block.join(' ');

    // Date: numeric first (3/23), then month name (Mar 23)
    let dateM = _parseLast(_DATE_RE, blockText);
    if (!dateM) {
      const monthM = _parseLast(_DATE_MONTH_RE, blockText);
      if (monthM) {
        const parts = monthM[0].split(/\s+/);
        dateM = _parseM(`${_MONTH_TO_NUM[parts[0]] || '?'}/${parts[1]}`);
      }
    }

    const lenM = _parseLast(_LEN_RE, blockText);
    const wtM  = _parseLast(_WT_RE, blockText);
    let   eqM  = _parseLast(_EQUIP_RE, blockText);
    if (!eqM) {
      const eqWord = _parseLast(_EQUIP_WORD_RE, blockText);
      if (eqWord) {
        const mapped = _EQUIP_WORD_MAP[eqWord[0].toLowerCase()];
        if (mapped) eqM = _parseM(mapped);
      }
    }

    // Cities: match "City, ST" per individual line in block (not blockText)
    const cities = [];
    for (const bl of block) {
      const cm = _CITY_RE.exec(bl.trim());
      if (cm && cm[1].length < 35 && !_NOT_CITY.has(cm[1].trim())) {
        cities.push(cm[1].trim());
      }
    }
    let origin = '', destination = '';
    if (cities.length >= 2)      { origin = cities[cities.length - 2]; destination = cities[cities.length - 1]; }
    else if (cities.length === 1) { origin = cities[0]; }

    // Company: walk backwards up to 7 lines (j > i-8, same as Python range(i-1, max(0,i-8), -1))
    let company = '';
    for (let j = i - 1; j > Math.max(0, i - 8); j--) {
      const cand = lines[j].trim();
      if (!cand) continue;
      if (/^[\(\)\d\s\-\+\.x]+$/.test(cand)) continue;
      if (['CONTACT INFORMATION','COMMENTS','VIEW ROUTE'].includes(cand.toUpperCase())) continue;
      if (cand.includes('@')) continue;
      if (/^[\d\$,.\s/\-*%a-z]+$/.test(cand)) continue;
      _WT_RE.lastIndex = 0; if (_WT_RE.test(cand)) continue;
      _LEN_RE.lastIndex = 0; if (_LEN_RE.test(cand)) continue;
      if (_NOT_CITY.has(cand)) continue;
      if (/^[A-Z0-9]{3,12}$/.test(cand)) continue;
      if (/^[A-Z\s]{3,30}$/.test(cand) && !/[a-z]/.test(cand) && cand.split(/\s+/).length <= 3) continue;
      if (/^(?:EXT|ext)\b/.test(cand)) continue;
      company = cand;
      break;
    }

    // Fallback origin if no cities found
    if (!origin) {
      for (const bl of block) {
        const bls = bl.trim();
        if (_NOT_CITY.has(bls)) continue;
        if (/^[A-Z][a-zA-Z\s]{2,25}$/.test(bls)) { origin = bls; break; }
      }
    }

    const key = `${email}|${origin}|${destination}`;
    if (seen.has(key)) continue;
    seen.add(key);
    loads.push({
      email, origin, destination,
      date:   dateM ? dateM.group() : '',
      equip:  eqM   ? eqM.group()   : '',
      length: lenM  ? lenM[0]       : '',
      weight: wtM   ? wtM[0]        : '',
      company,
    });
  }
  return loads;
}
```

- [ ] **Step 2: Smoke test in browser console**

Paste a sample DAT block in the Send textarea, then run:
```javascript
parseDatText(document.getElementById('datText').value)
```
Expected: array of load objects with correct `email`, `origin`, `destination`, `date`, `equip`. Compare with what `/api/parse` returns for the same text.

---

### Task 4: Add `classifyLoads()` function

**Files:**
- Modify: `templates/index.html` — add after `parseDatText`, before `// ── PARSE ──`

- [ ] **Step 1: Insert `classifyLoads` function**

```javascript
function classifyLoads(loads) {
  const stats = {total: loads.length, new: 0, skip_today: 0, skip_dup: 0, skip_sent: 0, skip_stop: 0};
  const seenInBatch = new Set();
  for (const l of loads) {
    const em  = l.email.toLowerCase().trim();
    const dom = em.includes('@') ? em.split('@').slice(-1)[0] : ''; // same as Python split('@')[-1]
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

- [ ] **Step 2: Smoke test in browser console**

```javascript
classifyLoads(parseDatText(document.getElementById('datText').value))
```
Expected: `{loads: [...], stats: {total:N, new:N, ...}}` — stats counts should add up to total.

---

### Task 5: Rewrite `parseDat()` and reduce debounce

**Files:**
- Modify: `templates/index.html` — lines ~2857–2874

- [ ] **Step 1: Reduce debounce 600ms → 150ms**

Find:
```javascript
  _parseTimer = setTimeout(() => parseDat(), 600); // 600ms debounce
```
Replace with:
```javascript
  _parseTimer = setTimeout(() => parseDat(), 150); // 150ms — instant since parsing is local
```

- [ ] **Step 2: Replace `parseDat()` to call local functions**

Find and replace the entire `parseDat` function:

Old:
```javascript
async function parseDat() {
  const text = document.getElementById('datText').value.trim();
  if (!text) { toast('Paste DAT text first', true); return; }
  const res = await fetch('/api/parse', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text})});
  const data = await res.json();
  parsedLoads = data.loads;
  sessionStorage.removeItem('dat_loads');
  sessionStorage.removeItem('dat_checked');
  renderParseResults(data);
  document.getElementById('parseResults').style.display = 'block';
}
```

New:
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

- [ ] **Step 3: Verify in browser**

Paste a DAT block. Table should render within ~150ms. Check DevTools → Network: no request to `/api/parse` should appear.

- [ ] **Step 4: Commit**

```bash
git add templates/index.html
git commit -m "feat(parse): port parseDatText + classifyLoads to JS, make parseDat synchronous"
```

---

### Task 6: Wire `loadParseContext()` to refresh triggers

**Files:**
- Modify: `templates/index.html`
  - `nav()` function ~line 2441
  - `pollStatus()` function ~line 3036
  - `addStop()` ~line 3217
  - `removeStop()` ~line 3222

- [ ] **Step 1: Call `loadParseContext()` when Send tab opens**

In `nav()`, find:
```javascript
    loadDailyStats();
    loadQuota();
    loadAutomationImpact();
```
Add `loadParseContext();` as the next line:
```javascript
    loadDailyStats();
    loadQuota();
    loadAutomationImpact();
    loadParseContext();
```

- [ ] **Step 2: Call `loadParseContext()` when send job completes**

In `pollStatus()`, find:
```javascript
    loadDailyStats();
    const ld2 = document.getElementById('bpLiveDot');
```
Add `loadParseContext();` between them:
```javascript
    loadDailyStats();
    loadParseContext();
    const ld2 = document.getElementById('bpLiveDot');
```

- [ ] **Step 3: Call `loadParseContext()` after stop list changes**

In `addStop()`, find:
```javascript
  renderStop(); toast('Added to stop list');
```
Replace with:
```javascript
  renderStop(); toast('Added to stop list'); loadParseContext();
```

In `removeStop()`, find:
```javascript
  renderStop(); toast('Removed');
```
Replace with:
```javascript
  renderStop(); toast('Removed'); loadParseContext();
```

- [ ] **Step 4: Verify refresh works**

Parse a batch. Send it. When send completes, paste the same text again — sent emails should now show "Sent today" chips, not "New".

- [ ] **Step 5: Commit**

```bash
git add templates/index.html
git commit -m "feat(parse): wire loadParseContext to Send tab open, send complete, stop list save"
```

---

### Task 7: End-to-end verification and push

- [ ] **Step 1: Test parsing speed**

Paste 20–30 loads. Table should render within ~150ms. No `/api/parse` in Network tab.

- [ ] **Step 2: Test stop list blocking**

Add an email to Stop List. Return to Send, re-paste — that email shows "Blocked" chip immediately (without needing to reload).

- [ ] **Step 3: Test duplicate detection**

Paste text with the same email twice. Second row shows "Duplicate" + "Use this" button.

- [ ] **Step 4: Test sent-today detection**

Send a batch. Re-paste same text. Sent emails show "Sent today", not "New".

- [ ] **Step 5: Push**

```bash
git push
```

---

## Summary of Changes

| File | What changes |
|------|-------------|
| `app.py` | Add `GET /api/parse-context` route (20 lines) |
| `templates/index.html` | Add regex constants, `_parseCtx`, `loadParseContext()`, `_parseLast()`, `_parseM()`, `parseDatText()`, `classifyLoads()` |
| `templates/index.html` | Rewrite `parseDat()` — remove fetch, call local functions |
| `templates/index.html` | Debounce 600ms → 150ms |
| `templates/index.html` | Wire `loadParseContext()` to 4 call sites |
