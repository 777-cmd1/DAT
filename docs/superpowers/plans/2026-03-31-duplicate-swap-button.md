# Duplicate Swap Button Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a small "Use this" button on `in_batch` duplicate rows so the user can swap which load for a given email is active (selected for sending).

**Architecture:** Frontend-only change to `templates/index.html`. The `parsedLoads` array is the source of truth. Clicking "Use this" on a duplicate row mutates two entries in `parsedLoads` (swap `skip` values), then calls `renderLoads()` to re-render the full table.

**Tech Stack:** Vanilla JS, existing `parsedLoads` global array, existing `renderLoads()` / `updateSelectedCount()` functions.

---

### Task 1: Add `swapDuplicate(idx)` function

**Files:**
- Modify: `templates/index.html` — JS section, after `updateSelectedCount()` (~line 2952)

- [ ] **Step 1: Locate insertion point**

Find the line in `templates/index.html` that reads:
```javascript
// Update line count in textarea footer
function updateDatMeta() {
```
This is the insertion point — add the new function immediately before it.

- [ ] **Step 2: Insert `swapDuplicate` function**

```javascript
function swapDuplicate(idx) {
  const load = parsedLoads[idx];
  if (!load || load.skip !== 'in_batch') return;
  // Find the currently active load for the same email
  const em = load.email.toLowerCase();
  const activeIdx = parsedLoads.findIndex((l, i) => i !== idx && l.email.toLowerCase() === em && !l.skip);
  if (activeIdx === -1) return; // no active counterpart found — nothing to swap
  // Swap skip values
  parsedLoads[activeIdx].skip = 'in_batch';
  parsedLoads[idx].skip = null;
  renderLoads(parsedLoads);
}
```

- [ ] **Step 3: Verify function is reachable**

Open browser console after parsing a paste with duplicate emails, run:
```javascript
swapDuplicate(1)
```
Expected: no error (may be no-op if index 1 isn't `in_batch`).

---

### Task 2: Add "Use this" button to `in_batch` row template

**Files:**
- Modify: `templates/index.html` — `renderLoads()` function, the `return \`<tr...>\`` template (~line 2925)

- [ ] **Step 1: Locate the status cell in the row template**

Find the last `<td>` in the row template inside `renderLoads()`:
```javascript
      <td><span class="chip ${chipCls}" ...>${chipLabel}</span></td>
    </tr>`;
```

- [ ] **Step 2: Replace that `<td>` to add the swap button for `in_batch` rows**

Replace:
```javascript
      <td><span class="chip ${chipCls}" style="display:inline-flex;align-items:center;gap:4px"><i class="ph-bold ${chipIcon}" style="font-size:10px"></i>${chipLabel}</span></td>
    </tr>`;
```

With:
```javascript
      <td>
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:nowrap">
          <span class="chip ${chipCls}" style="display:inline-flex;align-items:center;gap:4px"><i class="ph-bold ${chipIcon}" style="font-size:10px"></i>${chipLabel}</span>
          ${l.skip === 'in_batch' ? `<button onclick="swapDuplicate(${i})" style="font-size:10px;padding:2px 8px;background:var(--surface2);color:var(--text2);border:1px solid var(--border);border-radius:5px;cursor:pointer;white-space:nowrap;font-weight:600" title="Use this load instead">Use this</button>` : ''}
        </div>
      </td>
    </tr>`;
```

- [ ] **Step 3: Verify button appears**

Parse a paste with duplicate emails. Check that grey "Use this" button appears next to "Duplicate" chip on `in_batch` rows. Button should NOT appear on `sent`, `today`, `stop_list`, or `null` rows.

---

### Task 3: Manual end-to-end test

- [ ] **Step 1: Parse a paste with duplicate emails**

Use the Send page. Paste text that contains 2+ loads with the same email address (e.g. `devin.banks@echo.com` appearing multiple times).

Expected: First load → "New" + checked. Second load → "Duplicate" + unchecked + "Use this" button.

- [ ] **Step 2: Click "Use this" on a duplicate row**

Expected:
- The duplicate row becomes "New" + checked + enabled checkbox
- The previously active row becomes "Duplicate" + unchecked + disabled checkbox + "Use this" button
- Selected count updates correctly

- [ ] **Step 3: Click Send Selected**

Expected: Only the newly-active row is sent (confirmed in live log). The swapped-out row is not sent.

- [ ] **Step 4: Verify 3-way group works**

If 3 loads share the same email (A=active, B=dup, C=dup):
- Click "Use this" on B → B becomes active, A becomes dup, C stays dup
- Click "Use this" on C → C becomes active, B becomes dup (because B was the active one at that point... wait — actually A was set to dup in previous swap, B is now active)

Confirm `swapDuplicate` correctly finds `parsedLoads.findIndex(l => !l.skip && same email)` regardless of which was originally first.

---

### Task 4: Commit

- [ ] **Step 1: Commit**

```bash
git add templates/index.html
git commit -m "feat(send): add 'Use this' swap button for in_batch duplicate loads"
```

---

## Summary of changes

| File | Change |
|------|--------|
| `templates/index.html` | Add `swapDuplicate(idx)` JS function |
| `templates/index.html` | Add "Use this" button to `in_batch` row template in `renderLoads()` |
