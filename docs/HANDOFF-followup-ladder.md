# Handoff — warmth-ladder branch

Written 2026-11-05 for whoever continues this work (another agent or a later session).
Everything you need is in this file or in the repo. **The SDD workspace under
`.superpowers/` is git-ignored and does NOT travel with the branch** — the ledger,
the task briefs and the per-task reports exist only on the machine that produced
them. This file is the committed substitute.

---

## 1. What this branch is

It replaces the stage-based follow-up drip (FU1 → FU2 → FU3) with a **warmth ladder**.

- Spec: `docs/superpowers/specs/2026-10-30-followup-warmth-ladder-design.md`
- Plan: `docs/superpowers/plans/2026-10-30-followup-warmth-ladder.md` (12 tasks)
- Rules engine: `app/ladder.py` (pure stdlib, no Flask import — keep it that way)
- Architecture summary: the "Follow-up: драбина теплоти" section of `CLAUDE.md`

A contact sits on a rung — `cold → neutral → warm → hot → client` — plus the
off-ladder states `dormant` (with an `exit_reason`) and `excluded`. **Only a load
raises a rung**: a broker sending load information, one step per conversation, not
per email. Attempts are budgeted (3 with no load, 5 once a load has arrived) and
only a load refills the budget.

Branch: `worktree-followup-ladder`, 36 commits, +11 262 / −839 across 34 files.
Working tree clean at `505e48b`.

## 2. State right now

All 12 planned tasks are implemented, reviewed and fix-looped. Each task went
through: implement → independent review → fix round(s) → scoped re-review.

| # | Task | Head commit |
|---|---|---|
| 1 | Ladder rules module | `0f20bbc` |
| 2 | Columns on `FollowupContact` | `fc09e42` |
| 3 | Replies move contacts up | `8a7bedc` |
| 4 | Scheduler sends on the ladder | `5629a4c` |
| 5 | Per-rung email copy | `6201cab` |
| 6 | Funnel / needs-you / activity API | `d85c5a1` |
| 7 | Tier list + manual overrides | `5cd3537` |
| 8 | Funnel scoreboard screen | `89641a1` |
| 9 | Tier drill-down + history | `9dc1480` |
| 10 | Migration of existing contacts | `7325697` |
| 11 | Ladder settings + the on-switch | `befe945` |
| 12 | Retire the stage drip | `505e48b` |

Nothing is merged to `main`. Nothing is deployed. **Both engine switches ship OFF.**

## 3. START HERE — Task 12, fix round 2

Four one-line fixes, all found by the round-1 re-review, none applied yet
(the session hit a usage limit before the implementer edited anything).

1. **A failed bulk `set-recurring` places an unplaced contact on the ladder.**
   `is_followup_enabled` is cleared *before* `_next_recurring_datetime` can raise.
   With bad or empty `recurring_days` the row errors out, but the flag is already
   gone and `recurring_enabled` stays `True`; the next normalise pass resets the bad
   recurring and then dates the contact on its rung. → Clear the flag **after**
   `_next_recurring_datetime` succeeds. The single-action path already validates first.

2. **Order the capped paths oldest-first.** The Path 0 (one-time) and Path 2
   (recurring) queries have no `ORDER BY`, so when the daily cap bites, *which*
   contacts go out is arbitrary. The ladder is deliberately oldest-first.
   → `.order_by(next_followup_at)` on both.

3. **Deploy-day undercount in the shared cap.** Success events those paths wrote
   before commit `08e7334` have `notes IS NULL` and are not counted, so the shared
   total can exceed the cap on deploy day only. → Also count
   `event_type in (scheduled_once_sent, recurring_sent) AND notes IS NULL`.
   Failure events always carry notes, so nothing failed is miscounted.

4. **`resume-auto` should clear `scheduled_once`.** A one-time contact parked on a
   dead token keeps `scheduled_once=True` with a null date, and `_schedule_touch`
   returns early for such contacts — so after a resume it sits dateless until the
   owner also cancels the schedule. A dead end he has no reason to expect.

Then: run the covering tests one file at a time, `node --check` on the extracted
`<script>`, and a div count on any page touched.

## 4. Then — finish the branch

1. **Final whole-branch review** on the most capable model available. The diff is
   ~11 k lines; expect it to find something and budget one fix round.
2. **Finishing**: rollback branch `rollback/<name>` created from `main` BEFORE the
   merge, then merge → push → Railway redeploys itself in about a minute.

**Do not merge to `main` and do not deploy without the owner's explicit approval.**
That is this repo's standing convention (see `CLAUDE.md` → "Процес деплою").

## 5. Hard rules — breaking one of these has already caused an outage

- **Production schema changes ship through the inline `_migrations` list in
  `app.py`, never through Alembic alone.** Alembic's `releaseCommand` does not
  migrate the live Railway database. A column delivered only via Alembic took
  production down on 2026-10-20. Column types must be valid on PostgreSQL *and*
  SQLite. The migration loop swallows every DDL error as "column already exists",
  so a broken entry is silent — `tests/test_ladder_migration.py` has a regression
  test that builds a legacy-shaped table and runs the real loop; keep it working.
- **Every automatic send sits behind all three gates plus the cap**:
  `Workspace.fu_auto_enabled`, `Workspace.ladder_auto_enabled` (default OFF),
  `pipeline_config.auto_send_enabled`, and `ladder.daily_cap` (default 25 per
  workspace per local day, shared across the ladder, one-time and recurring paths).
  The owner once received ~249 follow-ups in a day from automation he believed was
  off. Any new send path that escapes a gate is the same bug again.
- **Every send failure goes through `_record_send_failure`** and honours its
  `gave_up` return (5 failures → park the contact). A dead OAuth token once produced
  368 595 retry rows and filled the database.
- **`excluded` is permanent and `refused` is a decision.** No path may email either.
  `exclude` also writes the Stop List entry, which is what makes it bind the Send
  page's cold outreach too. Only a load, or the owner's own `set-rung`, brings a
  refused contact back.
- **`_ladder_set_next` is the only place the ladder's `next_followup_at` is written.**
  Direct assignment is a defect.
- **`app/ladder.py` stays pure stdlib.** Flask and DB wiring live in `app.py`.
- **Tests run per file** (`.venv/bin/python -m pytest tests/test_x.py -q`). The full
  `tests/` run has pre-existing isolation flakes. 38 test files.
- Frontend is vanilla JS in `templates/index.html`, no build step; verify with
  `node --check` on the extracted `<script>`. **A missing `</div>` in that file
  blanks every page after the broken one** — count divs.

## 6. Decisions already made — do not re-litigate

These were each argued out across review rounds. Re-opening them costs a day.

- **Revival from `dormant` resets `touch_attempt`.** This looks like it contradicts
  "replies never refill the budget; only a load does". It does not: that rule is
  about a contact who is still *live*, where it stops someone buying unlimited
  touches by saying "maybe later" forever. The budget exists to stop us chasing
  someone who never answers; once they answer, its premise is gone.
- **An MC / insurance request is not a refusal.** The `negative` triage bucket
  contains the `mc_request` filter, so "Sure, send me your MC and insurance" — a
  broker opening a carrier packet, the strongest buying signal there is — classified
  as a refusal. It now routes to the unknown/needs-you outcome, in `app/ladder.py`
  via `PACKET_REQUEST_FILTERS` and `interpret_reply(..., filter_key=)`. On the test
  snapshot this was **17 of 55** contacts the migration would otherwise have parked
  as "they asked us to stop".
- **The Replies page, its categories and its keyword sets are untouched.** The
  deferral-versus-refusal and the packet-versus-refusal splits both live inside
  Follow-up, reading `Reply.triage_category` plus the text.
- **The migration's silence rule is an option, default 90 days, and the owner will
  run it with `--silence-days 0`.** His words: the contacts are not silent because
  they ignored him, they are silent because he never followed them up
  ("це не вони мовчать пів року, це я не робив фоллоуапи їм"). At 0 the distribution
  on a 289-contact snapshot is cold 158 / neutral 26 / warm 35 / hot 9 / client 4 /
  dormant 51 / excluded 6, and the 51 remaining dormant are **all refusals**.
- **A manual send spends no attempt** but is recorded in history. The budget governs
  what the machine does on its own.
- **The funnel's 30-day cohort is "contacts in play"** — entered in the window or
  carrying any `ladder_*` event in it — not a birth cohort. Never caption those rows
  "reached this month".
- **`counts.warm` is the legacy contact *state*, not the warm rung.** Rung counts
  come from the separate `rung_counts` block.
- **The old `stage` / `fu*_sent_at` columns are kept as history.** Nothing moves them
  any more. `is_followup_enabled=True` now means only "not yet placed on the ladder",
  and no path sends such a contact.

## 7. Deploy sequence

Order matters: between deploy and migration the book is inert (nothing sends),
which is the safe direction but surprising if unexpected.

1. Create the rollback branch from `main`, merge, push. Railway redeploys (~1 min).
2. **Dry run the migration on production, without `--apply`:**
   `python scripts/migrate_to_ladder.py --workspace <id> --silence-days 0 --verbose`
   Read the distribution. It has never been run against PostgreSQL — only SQLite —
   so this run is also the first real test of it.
3. **The owner reads the refused list** (`--verbose` names every contact parked as
   `refused`). The keyword classifier has false positives; this is his check that no
   live lead was buried.
4. Apply: same command with `--apply`.
5. Open the Follow-up page, read the funnel.
6. Turn on the two switches (Follow-up page or Settings → Automation). The confirm
   states how many go out today under the cap and how many days the backlog takes.
7. Watch the first scheduler tick (it runs every 15 minutes).

Known imprecision: the "drains in N days" figure only counts contacts due within
24 hours, so it understates a large backlog. The cap still bounds the sending.

## 8. Known follow-ups, not started

- **Analytics tab** (owner-requested): still the stage-drip model — "Sequence Funnel",
  "FU1/FU2/FU3 Sent", "Conversion to Booked by Stage", Outcomes Booked/Warm/Blocked/
  Closed. It no longer invents history (manual sends stopped writing a stage), but it
  measures an engine that no longer exists and contradicts the Funnel tab beside it.
- **The email text is not in the contact history.** No event stores what was sent, so
  the history shows date, kind and attempt plus a note pointing at Gmail's Sent
  folder. The approved design promised the owner the actual sentences. Sized at about
  a day: have `send_followup_email` return `{subject, body[:300]}`, stash it in the
  `metadata_json` of the success events (~8 call sites), expose it from the timeline
  route and render it. Table impact is negligible — only successful sends carry a
  snippet, and the 368 k-row incident was failure events.
- Smaller deferred items are listed in the per-task reports, which are local-only
  (see the note at the top).

## 9. How the work was run

Each task: a fresh implementer, then an independent reviewer with the task brief,
the implementer's report and a diff package; findings became a fix round; then a
scoped re-review verified the fixes against the tree rather than the report. That
process caught, among others: a refusal rule that never read refusals, an opt-out
that could be undone by writing in, a screen that said "nothing happened" while
automation was off, an unbounded first send wave, and the MC-request misread above.

If you continue with a different process, keep the one habit that produced those:
**verify against the code, not against the previous agent's report.** Several
reports on this branch asserted the opposite of what their own code did.

---

## 10. Which tests cover Task 12, and how to know a fix is real

Covering files for the four pending fixes, run one at a time with
`.venv/bin/python -m pytest tests/<file> -q`:

```
tests/test_drip_retired.py        tests/test_ladder_scheduler.py
tests/test_drip_gate.py           tests/test_ladder_actions.py
tests/test_send_failure_backoff.py  tests/test_ladder_api.py
tests/test_followup_bulk_send.py  tests/test_settings_tabs.py
tests/test_touch.py               tests/test_safe_autosend.py
```

**Prove each fix with a mutation check before you commit it.** Revert your own
change, confirm the test you just wrote fails, then restore it. This is the single
habit that did the most work on this branch: a test that still passes with the fix
removed is not a test of that fix, and four such tests were caught and rejected here
before they reached a commit. The same check also catches the subtler failure — a
fix that is present in your editor but not in the tree, which happened once on this
branch when an interrupted test sweep silently reverted a guard and the author's own
verification missed it because they grepped for what they expected to find.

## 11. Who reviews the work

Every change on this branch was read by a reviewer that had **not** written it and
did not see the author's reasoning — only the brief, the author's report and the
diff — and was told to verify claims against the code, because several reports here
asserted the opposite of what their own code did.

If you are both writing and reviewing, you lose that. Two ways to keep it:

- Run a genuinely separate review pass with fresh eyes: read the diff against the
  requirement, not against your memory of writing it, and trace callers rather than
  reading the deletion.
- Or hand the diff back for review elsewhere before merging.

The final whole-branch review in section 4 is **not** a substitute for reviewing
these four fixes: it is one pass over ~11 k lines and will not catch a one-line
ordering bug in a path it is not looking at.

---

## 12. Work log — append here, do not rewrite

This file is read first by whoever picks the branch up next, so it is also where
you leave your trail. **After each piece of work, append one entry.** Do not edit
earlier entries; if you were wrong, say so in a new one.

What an entry needs, in a few lines:

- **Date, who** (which agent or session).
- **What changed**, with the commit SHAs. The code is in git; do not restate it.
- **What you decided** that the next person could otherwise re-open — and *why*,
  plus what it costs if the decision turns out wrong. A decision without its reason
  gets re-litigated.
- **What you left undone or deliberately did not do**, and where it now belongs.
- **Anything you found that contradicts this document.** Sections 1-11 were written
  on 2026-11-05 and are not re-verified by anyone; if the code has moved, the code
  is right and this file is stale. Say so here rather than quietly working around it.

Keep it short. The ground truth is `git log` and the diffs — this log exists so the
next reader knows *why*, not *what*.

### Entries

**2026-11-05 — Claude (Opus 5), handing off.** Branch at `dce3bde` / `7d7906b`,
tree clean, 12 planned tasks implemented and reviewed, nothing merged, nothing
deployed, both engine switches OFF. Next work is section 3 (Task 12 fix round 2,
four one-line fixes, none applied), then section 4. Decisions of record are in
section 6; the rules in section 5 each correspond to a real production incident.
Left undone deliberately: the Analytics rebuild and the sent-email text in history
(section 8), both owner-visible and both sized, neither blocking deploy.


**2026-11-05 — Codex, Task 12 round 2 implementation (`7a45021`, base `b7f8ad8`).**
Validate the bulk recurring date before *any* contact mutation: section 3.1's suggested
flag-only move is insufficient because normalisation clears that flag while recurring
remains enabled. Cost if wrong: a rejected request can silently enrol a contact.
Kept the existing resume guard in `_ladder_redate` (`cab67e85`) instead of duplicating
it: section 3.4 and my initial claim that all four fixes were absent are stale; the
caller already clears the lost one-time schedule. Cost if wrong: a resumed contact
stays dateless. Added regression coverage for validation, both query orders and legacy
cap events; retained the existing resume test. All five targeted mutations (each
query separately) failed assertions, with source restored after each. Baseline fixed
`test_drip_retired.py`: 47 passed; `test_ladder_actions.py`: 89 passed. Full covering
sweep and separate review completion are logged next. No merge/push/deploy.


**2026-11-05 — Codex, separate scoped review and verification of `7a45021` (implementation log `9168c7e`).**
Re-read the committed diff against section 3 and traced bulk commit/normalisation,
query -> cap -> send, historical event writers before `08e7334`, and resume -> redate.
No remaining finding in this scoped change. All 10 section-10 files passed separately:
351 tests; extracted JS passed `node --check`; unchanged index divs 770/770; diff check clean.
Mutation evidence: removing bulk validation failed 3 cases; removing each ORDER BY
failed its own case; removing NULL-note counting failed 2; removing the existing
resume guard failed 1. Restored code passed the subsequent full covering sweep.
Kept Path 0 before Path 2, ordering within each path as requested; a global queue
would change existing priority (cost of retaining priority: recurring can wait behind
one-time sends). No new resume assignment: its existing guard is proven, not assumed.
Additional contradiction to section 5: `_owned`/`_allowed` on Path 0/2 do not require
`ladder_auto_enabled`; `test_drip_gate.py::test_scheduled_once_and_recurring_send_when_the_switch_is_on`
expects sends with its default OFF. Left this for the whole-branch review, not silently
changed in the scoped patch: cost if section 5 is intended literally is sending while
the ladder switch is OFF. Whole-branch review remains undone; this pass is not it.
Sections 8 items, production/PostgreSQL validation, merge, push and deploy remain undone.
