# Follow-up redesign: the warmth ladder

**Date:** 2026-10-30
**Status:** approved design, not yet planned
**Supersedes:** the stage-cadence follow-up engine described in CLAUDE.md
("Follow-up каденс — додано 2026-07")

---

## Why this exists

The follow-up system does not produce sales, so the owner turned its
automation off and fell back to sending one bulk batch a month by hand. A
monthly batch reaches people long after they stopped thinking about us, and
the queue became a pile: 277 contacts, 171 "today's touches", 160 overdue,
most rows showing "No next step". The page stopped being a tool and became
a reminder of work not done.

The product bug underneath: **the system schedules by calendar, but freight
relationships move by events.** A broker who just sent us a load to quote is
briefly interested in sending another; five days later that moment is gone.
Nothing in the system reacts to the one signal that matters.

The owner's model, confirmed by his own manual results: when a broker sends
one load our way, the chance of a second is meaningfully higher; after two,
higher still; a broker who keeps sending becomes a client and needs no
automation at all because there is daily contact. Value sits in moving
people up that ladder fast, and in dropping everyone else quickly.

## Goals

1. **Follow-ups lead to a load or stop.** Every automatic email exists to
   provoke the next load. If it isn't working, the contact falls out.
2. **The owner does nothing on a normal day.** Zero manual work is the
   target. 20-30 contacts a day is the ceiling on how many he is willing
   to *review by eye* — it is not a cap on sending.
3. **Simple.** The daily screen answers "how is my funnel and what needs
   me", not "here are 171 rows".
4. **Warmth is earned and visible.** Rung = loads received. The owner can
   see at a glance how many people sit at each rung and how many fall out
   between rungs.

## Non-goals

- Changing how contacts enter follow-up. Entry stays manual, from the
  Replies page, as it works today. Out of scope.
- **Changing the Replies page, its triage categories, or its keyword
  sets.** Decided explicitly: the owner does not want his Negative chip or
  its selection to change. Any deferral-versus-refusal distinction is made
  *inside* Follow-up, reading the same classifier output.
- Outreach sending (`/api/send`, the Send page) — untouched.
- Multi-user policy. Every workspace gets the same engine; settings are
  per workspace as they are now.

## Anti-goals

These make the project a failure even if it ships and works:

- **Emailing cold people.** The owner's stated reason he would switch it
  off again. Default behaviour must be to stop, not to continue.
- **A queue that accumulates.** If the daily screen trends toward hundreds
  of rows demanding attention, the redesign failed.
- **Silent automation.** He disabled the previous engine partly because it
  acted without visible account. He must be able to see what it did and
  override any of it.
- **Taking away manual control.** Every contact must remain inspectable
  and overridable by hand. (He raised this directly when a mockup implied
  the table was gone.)

## The model

### What counts as a load — decided

**A broker sending us load information counts.** "We have a load Laredo →
Dallas, can you cover?" moves the contact up a rung, whether or not we end
up hauling it. Booking is *not* the trigger.

This was the single most consequential open question and the owner settled
it directly. It is consistent with his existing stage names ("Got info
(1st)", "Got info 2 (Repeat)", "Regular info"), and it means the existing
`gave_info` output of `classify_reply_text` is the right signal.

The existing manual `state='loads'` ("Booked") stays what it is today: a
hand-set decision by the owner, separate from the ladder.

**Counting rule (builder's call, flagged to the owner):** one rung step per
load *conversation*, not per message. The production data holds 603
`gave_info` replies across 289 contacts — a three-message back-and-forth
about a single load must not read as three loads. Dedupe by thread where a
thread id exists, otherwise by contact and day. The builder may refine
this; naive per-message counting is wrong and would put much of the queue
at HOT on day one.

### Rungs

| Rung | Meaning |
|---|---|
| `COLD` | in follow-up, nothing since entry |
| `NEUTRAL` | replied since entry, no load yet (includes "maybe next week") |
| `WARM` | sent 1 load |
| `HOT` | sent 2 or more loads |
| `CLIENT` | steady shipper — **leaves automation entirely**, daily human contact |

Two states sit off the ladder:

| State | Meaning |
|---|---|
| `DORMANT` | attempts exhausted. Not deleted. Returns to its rung automatically if the contact writes in. |
| `EXCLUDED` | owner's decision, never contact again. Manual only. |

Display order, left to right, is most valuable first: CLIENT, HOT, WARM,
NEUTRAL, COLD. The owner chose temperature naming over load-count naming
("1 LOAD", "REPEAT") for readability, and chose this order explicitly.

**Note on COLD (builder's call):** contacts are created from a Reply
(`add_to_followups`), so everyone in follow-up has replied at least once by
construction. COLD is therefore defined as *no reply since entering
follow-up* — the entry reply does not count as engagement inside the
ladder. If the builder finds this makes COLD structurally near-empty in
practice, collapsing it into NEUTRAL is acceptable; the owner wants a
"cold" bucket but has not tied himself to this definition.

### Rhythm

- Touch 1: **the next day** after the contact enters follow-up.
- Touch 2: **2-3 days** after touch 1.
- Touch 3 and later: **weekly**.

Speed is the point at the bottom of the ladder: the owner believes
next-day follow-up is where conversion is won, versus the monthly batch he
does today.

**Higher rungs (builder's call):** "more attempts, less often". Suggested
defaults — WARM on the same rhythm as above, HOT weekly from the first
touch, CLIENT scheduled not at all (but still watched, so "a CLIENT silent
unusually long" can fire). All intervals are settings.

### Patience

| Situation | Attempts |
|---|---|
| No load received | **3, then DORMANT** |
| A load received | budget resets, and higher rungs get 1-2 more (4-5) |

**Replies do not buy more attempts.** Decided by the owner: a contact who
answers three times with "nothing right now" has had three attempts and
should not be written to again. Only a *load* resets the budget. This keeps
polite-but-unproductive conversations from running forever, which is the
largest hole the funnel audit showed (people who talk and never ship).

All of these are settings, including the extra attempts for higher rungs,
which must be switchable off entirely.

**There is no global silence brake.** An earlier draft had a 15-day
silence rule; the owner removed it ("приберемо це правило поки"). The
attempt budget is the only stopping mechanism at runtime. Migration has its
own, separate rule below.

### Reply handling

Replies drive everything, automatically — the owner's explicit wish
("система має помітити сама і підняти"):

- **Load information received** → rung up, load count +1, attempt budget
  resets, next touch on the new rung's rhythm.
- **Refusal** → stop.
- **Deferral with a date** — "we'll look next week" — is *not* a refusal
  and *not* warmth. The stated time becomes the next touch date, and it
  consumes no extra patience beyond the normal budget. The owner confirmed
  this pattern often turns into a load later.
- **Unparseable** → no automatic action; surfaces in "Needs you".

**Deferrals must be split from refusals inside Follow-up.** Today
`classify_reply_text` has no deferral category, and the `declined` keyword
set behind category `negative` contains exactly the phrases the owner calls
deferrals: *nothing this week*, *no loads this week*, *nothing right now*,
*not at this time*, *we are covered*. Treating those as refusals would stop
the very contacts he most wants kept. Because Replies is a non-goal, the
split happens on the Follow-up side: the engine re-reads the reply text (or
a Follow-up-local classifier) and decides deferral versus refusal without
altering the shared keyword sets, the Negative chip, or what Replies shows.

Feasibility is established: production holds 603 replies classified
`gave_info` for this owner, 49 `rate_request`, 40 `negative`, and only 112
unclassified.

### Email content

A touch must reference what that broker actually did. Generic text is what
the current "General / All Services" template does and it does not sell.
For a contact who sent a load, the email should reference it and drive to
the next one. The owner listed the angles he uses by hand:

- how often lanes like that one come up for them
- whether they have other loads right now
- whether they have other lanes — we have trucks sitting in that city
- our services: hazmat, LTL, Mexico, Canada, high-value loads

Content therefore varies by rung and draws on the contact's own history
(their lane, their last load). The parked branch `wave/b-smart-templates`
(commit `bccc496`, template variables `{contact_name}` / `{last_rate}` / …)
is the natural starting point; the builder should check it before writing
anything new. `Template.level` is a free-form `String(50)`, so per-rung
template slots need no schema change.

## What the owner sees

Two screens. The first is a scoreboard, not a task list.

### Funnel page (default)

1. **Rung strip** — CLIENT / HOT / WARM / NEUTRAL / COLD with counts, and
   DORMANT / EXCLUDED beside them. Each tier clicks through to its list.
2. **Needs you** — short list, normally near-empty. Four reasons qualify,
   all confirmed by the owner:
   - a CLIENT silent unusually long for them
   - promised something and didn't deliver
   - **promised a load and vanished** (he added this one specifically)
   - a reply the classifier could not parse
3. **Conversion, in absolute numbers.** The owner rejected percentages
   alone: "30 43 42% нічого неясно хто це і що це". Each step shows how
   many people reached it, the percentage *of the previous step*, and
   **how many dropped out there and why**. Totals: end-to-end conversion,
   total lost, average gap between loads, loads this month.
4. **What the system did in the last day** — touches sent, rungs raised,
   contacts quieted, contacts stopped, linking to a log. This exists to
   rebuild trust in automation he previously switched off.

The sidebar badge shows the "Needs you" count, not the queue size. 3, not 277.

**Drop-out reasons (builder's call):** nothing records an exit reason
today. Store one from the engine forward, and at migration derive a
best-effort reason from existing events and replies, so the panel is not
blank for weeks on the page whose whole job is rebuilding trust. Derived
history should be visibly distinguishable from reasons recorded live if
that proves cheap.

### Tier list (one click deeper)

Everything the current table does, reachable from any tier including
DORMANT and EXCLUDED. Per contact: rung, loads received, attempt ("2 of
5"), next touch date **with the reason** ("tomorrow 09:00 — touch 3", "13
Nov — they asked for next week", "auto paused — you stopped it 2 Nov"),
lane.

Row expands into history: each touch with the date and **the text that was
sent**, plus every rung change and what caused it.

Per-row actions: send now, postpone, history, move to inactive, and
**pause automation for this contact** without removing it. Bulk via
checkboxes, as today.

Mockups for both screens:
`.superpowers/brainstorm/31699-1793384212/content/` — `page.html` (funnel)
and `drilldown.html` (tier list) are the approved pair; `tiers.html`,
`dashboard.html` and `funnel-v2.html` are earlier iterations kept for
reference.

## Migration

289 existing contacts are placed on rungs from history, not reset — the
owner's choice. Rung comes from counting that contact's load conversations
(see the counting rule above).

**Two safety rules, both builder's calls serving the anti-goal:**

1. **Stale contacts start DORMANT.** 264 of 289 have had no activity for
   over 90 days; only 25 are fresh. Placing them on rungs and switching
   automation on would email people silent for months — precisely the
   anti-goal. Anything inactive beyond 90 days starts DORMANT whatever its
   rung, and wakes itself if the contact writes in. (This is a migration
   rule only. The owner removed the runtime silence brake; this is not it
   returning by the back door, and it is called out here so he can reject
   it.)
2. **Manual decisions are never overridden.** `TERMINAL_STATES =
   {'warm', 'loads', 'blocked', 'closed'}` currently means "out of
   automation", and those values were set by hand. A contact the owner
   marked Booked or Closed must not be placed on a rung and emailed.
   Mapping: `blocked`/`closed` → EXCLUDED, `warm`/`loads` → keep out of
   automation (DORMANT, or CLIENT where the history supports it) and let
   him opt them back in deliberately.

The current `pipeline_stage` kanban values are not a useful source: 182 of
289 sit in stage 1 and only 11 are above stage 2, because advancing was
manual and never happened.

Realistically a couple of dozen contacts enter live rotation; the rest wait
to wake themselves up.

## Constraints

- Flask + SQLAlchemy, PostgreSQL in production (Railway), SQLite in dev.
- **Production schema changes ship through the inline `_migrations` list in
  `app.py`.** The Alembic `releaseCommand` does not migrate the live
  database; a column delivered only via Alembic took production down on
  2026-10-20. Alembic files may be written for fresh installs but never
  instead of the inline entry.
- Single gunicorn worker; scheduler is a daemon thread on a 15-minute tick.
- **Failed sends must use the existing backoff** (`_record_send_failure`).
  A dead OAuth token previously caused 368k retry rows, 236MB of bloat and
  an outage on 2026-10-27. Any new send path inherits this.
- The drip kill switch (`Workspace.fu_auto_enabled`) exists and must keep
  working; this engine sits behind it.
- Frontend is vanilla JS inside `templates/index.html`. No build step.
- Tests run per file (`python -m pytest tests/test_x.py -q`); full-suite
  isolation flakes are pre-existing.

## Left to the builder

- Data model: whether rung is a stored column, a derived value, or both;
  how the load count is maintained and kept consistent.
- Where the rung engine lives relative to the existing
  `_run_scheduled_followups` paths, and whether the four current send
  paths collapse into one.
- How "promised a load and vanished" and "silent unusually long for them"
  are detected — both need a definition the builder proposes.
- Deferral date extraction from reply text ("next week", "after the 15th").
- How per-rung email content is composed, and how much comes from
  `wave/b-smart-templates`.
- Settings surface: which knobs appear in the UI versus sensible defaults.
- Whether old `pipeline_stage` / kanban is removed or kept alongside.

## Open decisions deliberately not made

- Exact attempt counts beyond the owner's figures (3 without a load, 4-5
  once engaged). Production history cannot calibrate these: the owner
  states he never used the system properly, and the data confirms it.
- Whether CLIENT is reached automatically at a load threshold or marked by
  hand.
