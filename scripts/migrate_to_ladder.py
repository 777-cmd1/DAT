#!/usr/bin/env python3
"""Place a workspace's existing follow-up contacts on the warmth ladder. Run once.

The old drip knew only "which follow-up is next". The ladder knows how warm a
broker is, and only a broker sending load information makes them warmer. This
script reads what each contact already did and puts them on the rung their own
history earns — nothing is invented, and nothing the owner decided by hand is
overridden.

The rules, in the order they are applied to one contact:

  1. Already `excluded` — the owner's permanent decision. Left untouched; not
     even its load history is counted. Nothing in here ever moves a contact out
     of `excluded`, and nothing puts one there by inference.
  2. Already off the ladder (`dormant`) — stays off. A broker who asked us to
     stop must not be revived by a migration.
  3. The rung its history earns, by replaying its replies oldest to newest the
     way the live hook applies them. Each reply is read with `interpret_reply`,
     over the stored triage category or — when the row has none, as pre-triage
     rows do — the category `classify_reply_text` recovers from its text, which
     is exactly what app.py does before calling `interpret_reply`.
     * `load` → one more load conversation, keyed by `load_conversation_key`
       (thread id, else address + day) and counted through the same
       `_ladder_record_load` / `_ladder_load_counted` pair the live hook uses,
       so a later live reply in an old thread cannot count the same load twice.
       A load also cancels an earlier refusal, as a live load would.
     * `refusal` → the contact is out: `dormant` / `exit_reason='refused'`.
     * `deferral` / `unknown` → no rung effect beyond having replied at all.
     `replied` = any stored reply, or `last_reply_at`; both lift `cold` to
     `neutral`. `rung_for(load_count, replied)` then gives the rung, and the
     result never lowers a rung that is already set (a `set-rung` the owner made
     by hand, or a step the live hook already took).
  4. The owner's decision in the legacy state machine wins over 3:
     `blocked` → `excluded`, `closed` → `excluded`, `loads` → `client`,
     and `loads`/`warm` are taken out of automation (`auto_paused`).
  5. Silence. Nothing has happened for `--silence-days` (default 90) → `dormant`
     / `stale`. `--silence-days 0` turns the rule off: a long-silent contact then
     stays on the rung its history earns and is dated like any other live one.
     This brake exists ONLY here: the running engine has no silence rule, so
     a long-dead base is parked once, at migration time, and never again. It
     never touches `client` or `excluded`, on or off, and a refusal parks a
     contact either way — that is a decision, not a timeout.
  6. Anything off the ladder carries an `exit_reason`, so the conversion panel
     can say why it is out rather than showing a blank group, and goes through
     `_ladder_stop_all`: the one-time and recurring senders do not read the rung,
     so leaving their flags set would keep mailing a contact we just parked.
     A migration-set `excluded` is also written to the Stop List, which is what
     makes it permanent for every sender.

Then the drip stops owning the contact: `is_followup_enabled` goes False (the
drip scheduler requires it True, the ladder scheduler requires it False, so
exactly one engine can ever date and send to a contact). `stage` is left alone
— it is the readable history of what the drip sent, and the owner's manual
"send follow-up" button reads it. A one-time or recurring send the owner
scheduled, and a date a broker asked us to come back on, keep their own dates; a
contact that keeps its date is reported, with the reason, in the dry run. First
touches are staggered deterministically by contact id over a window that widens
with the population, so the whole backlog does not land on one morning.

Nothing here sends mail or widens what sends: both `fu_auto_enabled` and
`ladder_auto_enabled` are untouched, and every date goes through
`_ladder_set_next`, which refuses a date to anyone who must not get one.

Usage:
    python scripts/migrate_to_ladder.py --list
    python scripts/migrate_to_ladder.py --workspace <id>            # dry run
    python scripts/migrate_to_ladder.py --workspace <id> --verbose
    python scripts/migrate_to_ladder.py --workspace <id> --silence-days 0
    python scripts/migrate_to_ladder.py --workspace <id> --apply    # writes
"""
import argparse
import importlib.util
import os
import sys
from datetime import timedelta

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:          # run as a script, sys.path[0] is scripts/
    sys.path.insert(0, _ROOT)

from app import ladder as _ladder   # noqa: E402

# A contact nothing has happened with for this long is parked as dormant/stale
# rather than given a fresh budget of attempts. The DEFAULT, overridable per run
# with --silence-days (0 turns the rule off entirely). Deliberately not in
# app/ladder.py: there is no silence brake in the running engine, and putting
# the number there would imply one.
SILENCE_DAYS = 90

# The legacy state machine's terminal states, as the ladder reads them.
_STATE_EXCLUDES = {'blocked': 'blocked', 'closed': 'closed'}
_STATE_PAUSES = ('loads', 'warm')       # the owner's own "this one worked" marks

# First touches are pushed up to a window of days past the date their rung implies,
# deterministically by contact id. The window is at least _STAGGER_DAYS and widens
# with the population so no more than ~_STAGGER_PER_DAY first touches fall on one
# day: with the silence rule off the whole base lands on live rungs at once, and a
# few hundred mails queued for one morning is the silhouette of 2026-07-25 (249 in
# a day). It only ever moves a touch LATER — a migration is a backlog being eased
# in, and pulling a touch earlier than its rung says would be wrong.
_STAGGER_DAYS = 7
_STAGGER_PER_DAY = 20
_STAGGER_MAX_DAYS = 30

_MIGRATION_EVENT = 'migrated_to_ladder'
_RUNG_VALUES = _ladder.RUNGS + _ladder.OFF_LADDER
_APP = None


def _app_module():
    """app.py, reusing the copy wsgi/the test suite already imported.

    Loading it twice would build a second Flask app and a second engine.
    """
    global _APP
    if _APP is None:
        for name in ('_dat_mailer_app', '_dat_app'):
            if name in sys.modules:
                _APP = sys.modules[name]
                return _APP
        spec = importlib.util.spec_from_file_location('_dat_app', os.path.join(_ROOT, 'app.py'))
        mod = importlib.util.module_from_spec(spec)
        sys.modules['_dat_app'] = mod       # app/ would shadow app.py otherwise
        spec.loader.exec_module(mod)
        _APP = mod
    return _APP


def _reply_at(reply, fc, now):
    """When a reply arrived. Older rows can be missing it; fall back, never crash."""
    return reply.received_at or fc.created_at or now


def _last_seen(fc, replies, now):
    """The most recent thing known to have happened with this contact, or None.

    `last_activity_at` was not backfilled on every row, so every timestamp the
    contact carries counts, and so does the date of any reply it received.
    """
    times = [fc.last_activity_at, fc.last_reply_at, fc.last_load_at,
             fc.last_followup_sent_at, fc.fu3_sent_at, fc.fu2_sent_at, fc.fu1_sent_at,
             fc.initial_email_sent_at, fc.created_at]
    times += [_reply_at(r, fc, now) for r in replies]
    times = [t for t in times if t is not None]
    return max(times) if times else None


def _stagger_window(count):
    """Days to spread `count` first touches over: wide enough that no more than
    ~_STAGGER_PER_DAY land on one day, never narrower than _STAGGER_DAYS."""
    needed = -(-max(0, count) // _STAGGER_PER_DAY)          # ceil
    return max(_STAGGER_DAYS, min(_STAGGER_MAX_DAYS, needed))


def _stagger(contact_id, window):
    """0..window-1 extra days, deterministic by id (as `_schedule_touch` does)."""
    try:
        return int(str(contact_id).replace('-', '')[:8], 16) % max(1, window)
    except (ValueError, TypeError):
        return 0


def _reply_kind(reply, ws, now):
    """What this reply means, read exactly as the live hook reads it.

    `_ladder_reply_triage` is the hook's own category/filter-key lookup (it
    recovers either one from the text when the row is missing it), and
    `interpret_reply` is the hook's own rule — so this is the same
    implementation and not a second copy of it.
    """
    app_mod = _app_module()
    category, filter_key = app_mod._ladder_reply_triage(reply, ws)
    kind, _resume_at = _ladder.interpret_reply(
        category, app_mod._strip_quoted(reply.body), now, filter_key=filter_key)
    return kind


def _not_lower(current, derived):
    """The higher of the two rungs. The history may only raise what is set: a rung
    the owner chose by hand, or one the live hook already climbed, is never undone."""
    if current not in _ladder.RUNGS:
        return derived
    return max(current, derived, key=_ladder.RUNGS.index)


def _rescued_ids(uid, rows):
    """contact id -> when the owner last moved it by hand (`manual_set_rung`).

    A rerun re-derives the refusal from the same replies every time, so without
    this the owner's correction of a misread reply would be undone by the next run.
    """
    app_mod = _app_module()
    from app.models import FollowupContact as FC, FollowupEvent as FE
    from sqlalchemy import func
    out, ids = {}, [fc.id for fc in rows]
    for i in range(0, len(ids), 400):
        rowset = app_mod.db.session.query(
            FE.followup_contact_id, func.max(FE.event_at)).join(
            FC, FE.followup_contact_id == FC.id).filter(
            FC.user_id == uid, FE.followup_contact_id.in_(ids[i:i + 400]),
            FE.event_type == 'manual_set_rung').group_by(FE.followup_contact_id)
        out.update({cid: at for cid, at in rowset})
    return out


def _plan_contact(fc, replies, ws, now, deferred, silence_days, rescued_at=None):
    """What this contact should become. Pure reads — nothing is written here, so a
    dry run and a real run decide identically. None means "leave it alone".

    `silence_days` of 0 turns rule 5 off: a long-silent contact then stays on the
    rung its history earns instead of being parked. Nothing else about rule 5
    changes — an already-dormant contact stays dormant, `client` and `excluded`
    are exempt either way, and a refusal is a decision rather than a timeout, so
    it still parks the contact.
    """
    app_mod = _app_module()
    current = fc.rung if fc.rung in _RUNG_VALUES else None   # a legacy value counts as unset
    if current == 'excluded':
        return None                                 # rule 1: permanent, and not even read

    # rule 3: replay the replies oldest first, the way the live hook applies them.
    seen, convs, refused, newest = set(), [], False, None
    for r in sorted(replies, key=lambda r: _reply_at(r, fc, now)):
        at = _reply_at(r, fc, now)
        newest = at if newest is None else max(newest, at)
        kind = _reply_kind(r, ws, now)
        if kind == 'refusal':
            refused = True
            continue
        if kind != 'load':
            continue                                # deferral/unknown: only "replied"
        key = _ladder.load_conversation_key(r.thread_id, fc.contact_email, at)
        if key in seen:
            # a later message in a conversation this replay already saw: a no-op,
            # exactly as the live hook's "already counted" early return is. It must
            # not undo a refusal that arrived after the conversation was counted.
            continue
        seen.add(key)
        refused = False     # the load conversation revives them, as a live load does
        convs.append((key, at))
    fresh = [(k, at) for k, at in convs if not app_mod._ladder_load_counted(fc, k)]
    load_count = (fc.load_count or 0) + len(fresh)
    replied = bool(replies) or fc.last_reply_at is not None

    exit_reason = fc.exit_reason
    auto_paused = bool(fc.auto_paused)
    if current in _ladder.OFF_LADDER:
        rung = current                              # rule 2: already out of play, stays out
    else:
        rung = _not_lower(current, _ladder.rung_for(load_count, replied))
    # The owner's hand beats the classifier's guess: once he has moved this contact
    # by hand after its newest reply, a rerun must not re-park it on that reply.
    rescued = bool(rescued_at and newest is not None and rescued_at > newest)
    if refused and not rescued:
        rung, exit_reason = 'dormant', 'refused'    # they asked us to stop

    state = (fc.state or '').strip().lower()        # rule 4: the owner's own mark wins
    if state in _STATE_EXCLUDES:
        rung, exit_reason = 'excluded', _STATE_EXCLUDES[state]
    elif state == 'loads':
        rung = 'client'
    if state in _STATE_PAUSES:
        auto_paused = True

    last = _last_seen(fc, replies, now)
    silent = bool(silence_days) and (last is None
                                     or last <= now - timedelta(days=silence_days))
    if silent and rung in _ladder.RUNGS and rung != 'client':
        rung, exit_reason = 'dormant', 'stale'      # rule 5

    if rung in _ladder.OFF_LADDER:                  # rule 6
        if not exit_reason:
            exit_reason = 'stale' if silent else 'manual'
    elif exit_reason != 'send_failed':
        exit_reason = None                          # back in play: only the pause keeps its reason

    # A date is only replaced when it is a drip leftover. A one-time or recurring
    # send the owner scheduled, a day a broker asked us to come back on, and a date
    # an engine already owns all keep theirs. `touch_enabled` with ANY date — not
    # only a future one — is held, so a second run cannot silently clear the Overdue
    # bucket. (A contact landing off the ladder loses all of it in `_apply_plan`.)
    keeps = ('scheduled_once' if fc.scheduled_once else
             'recurring' if fc.recurring_enabled else
             'deferral' if fc.id in deferred else
             'already dated' if fc.touch_enabled and fc.next_followup_at else None)
    if rung in _ladder.OFF_LADDER:
        keeps = None                   # it loses every schedule in `_apply_plan`
    # Will this contact be given a fresh ladder date? Same conditions
    # `_ladder_set_next` applies, so the stagger window can be sized before any write.
    dates = (keeps is None and rung in _ladder.RUNGS and rung != 'client'
             and not auto_paused and state == 'active')
    # The Stop List gates the Send page's INITIAL outreach too, so only an
    # exclusion that came from a Block earns one — the app's own `close` action
    # deliberately does not stop-list, and a legacy `closed` contact must keep
    # receiving new DAT load mail. (`current == 'excluded'` cannot reach here:
    # rule 1 returns above. It is named so the intent survives a later edit.)
    stop_list = rung == 'excluded' and (state == 'blocked' or current == 'excluded')
    return {'from_rung': fc.rung, 'rung': rung, 'load_count': load_count,
            'new_loads': fresh, 'exit_reason': exit_reason, 'auto_paused': auto_paused,
            'keeps_date': keeps, 'redate': keeps is None, 'dates': dates,
            'stop_list': stop_list, 'last_seen': last}


_PLACED = ('rung', 'load_count', 'exit_reason', 'auto_paused', 'is_followup_enabled',
           'scheduled_once', 'recurring_enabled')


def _apply_plan(fc, plan, ws, now, window=_STAGGER_DAYS):
    """Write one planned placement, and log what it replaced."""
    app_mod = _app_module()
    before = {'rung': fc.rung, 'load_count': fc.load_count, 'last_load_at':
              fc.last_load_at.isoformat() if fc.last_load_at else None,
              'exit_reason': fc.exit_reason,
              'auto_paused': fc.auto_paused, 'state': fc.state, 'stage': fc.stage,
              'is_followup_enabled': fc.is_followup_enabled,
              'scheduled_once': fc.scheduled_once, 'recurring_enabled': fc.recurring_enabled,
              'recurring_days': fc.recurring_days, 'recurring_time': fc.recurring_time,
              'touch_enabled': fc.touch_enabled,
              'next_followup_at': fc.next_followup_at.isoformat() if fc.next_followup_at else None}
    fc.rung = plan['rung']
    fc.load_count = plan['load_count']
    fc.exit_reason = plan['exit_reason']
    fc.auto_paused = plan['auto_paused']
    if plan['new_loads']:
        newest = max(at for _, at in plan['new_loads'])
        if fc.last_load_at is None or fc.last_load_at < newest:
            fc.last_load_at = newest
    # One master from here on: the drip scheduler only takes is_followup_enabled
    # rows, the ladder scheduler only takes rows without it.
    fc.is_followup_enabled = False
    listed = False
    if fc.rung in _ladder.OFF_LADDER:
        # the one-time and recurring senders do not read the rung, so a date left
        # on a contact we just parked would still be mailed
        app_mod._ladder_stop_all(fc)
        if plan['stop_list']:
            # the Stop List is what makes `excluded` permanent for every sender,
            # including the Send page's initial outreach — hence only for a contact
            # the owner had actually blocked (see the plan's `stop_list`)
            listed = app_mod._add_to_stop_list(fc.user_id, fc.contact_email,
                                               reason=app_mod._EXCLUDE_STOP_REASON)
    elif plan['redate']:
        due = _ladder.next_touch_at(fc.rung, fc.touch_attempt or 0, now,
                                    _ladder.LADDER_DEFAULTS)
        if due is not None:
            due += timedelta(days=_stagger(fc.id, window))
        app_mod._ladder_set_next(fc, due, ws)
    for key, at in plan['new_loads']:
        evt = app_mod._ladder_record_load(fc, key, plan['from_rung'], notes='load from reply history')
        evt.event_at = at           # the day it really arrived, not migration day
    if not listed and all(before[f] == getattr(fc, f) for f in _PLACED):
        return None                 # already where it belongs: nothing to log
    return app_mod._record_event(
        fc, _MIGRATION_EVENT, actor_type='system',
        from_state=plan['from_rung'], to_state=fc.rung,
        metadata_json=app_mod.json.dumps({'before': before, 'stop_list_added': listed}),
        notes=f'placed on the ladder from {len(plan["new_loads"])} '
              f'load conversation(s) in its history')


def place_contacts_on_ladder(workspace_id, now, dry_run=True, silence_days=SILENCE_DAYS):
    """Put one workspace's contacts on the rung their history earns.

    Returns the distribution: counts per resulting rung, the rung changes, how
    many load conversations were counted, how many keep the date they already
    have and why, the stagger window, and one row per contact. `dry_run` (the
    default) decides everything and writes nothing — not a column, not an event,
    not even a dirty object in the session.

    `silence_days` is the 90-day park rule's threshold; 0 turns it off, so a
    long-silent contact stays on the rung its history earns. A refusal still
    parks a contact either way: that is a decision, not a timeout.

    Every query is scoped to this workspace AND its owner: a sweep across
    workspaces is the one bug this must never have.
    """
    app_mod = _app_module()
    db = app_mod.db
    from app.models import FollowupContact, Workspace

    ws = db.session.get(Workspace, workspace_id)
    if ws is None:
        raise ValueError(f'no such workspace: {workspace_id!r}')
    uid = ws.owner_id

    rows = FollowupContact.query.filter_by(workspace_id=ws.id, user_id=uid).order_by(
        FollowupContact.created_at).all()
    foreign = FollowupContact.query.filter_by(workspace_id=ws.id).count() - len(rows)
    if foreign:
        app_mod.app.logger.warning(
            'workspace %s has %d contact(s) owned by another user: not touched', ws.id, foreign)

    replies = app_mod._replies_by_contact(uid, rows)
    deferred = app_mod._ladder_deferred_ids(uid, rows)   # a date a broker asked for

    rescued = _rescued_ids(uid, rows)                    # moved by hand since its last reply

    out = {'workspace_id': ws.id, 'dry_run': bool(dry_run), 'total': len(rows),
           'placed': 0, 'skipped': 0, 'loads_counted': 0, 'foreign': foreign, 'failed': [],
           'silence_days': int(silence_days or 0), 'new_dates': 0, 'stagger_days': 0,
           'stop_listed': 0, 'rungs': {r: 0 for r in _RUNG_VALUES},
           'exits': {}, 'moves': {}, 'keeps_date': {}, 'rows': []}

    # Decide every contact first: the stagger window has to be sized against the
    # whole population, which with the silence rule off is most of the base.
    plans = []
    for fc in rows:
        mine = replies.get(fc.id, [])
        try:
            plans.append((fc, _plan_contact(fc, mine, ws, now, deferred, silence_days,
                                            rescued.get(fc.id)), len(mine)))
        except Exception:
            out['failed'].append(fc.contact_email)
            app_mod.app.logger.exception('ladder placement failed for %s', fc.contact_email)
    out['new_dates'] = sum(1 for _, p, _ in plans if p is not None and p['dates'])
    out['stagger_days'] = window = _stagger_window(out['new_dates'])

    for fc, plan, n_replies in plans:
        if plan is None:
            out['skipped'] += 1
            out['rungs']['excluded'] += 1
            key = f'excluded/{fc.exit_reason or "unspecified"}'
            out['exits'][key] = out['exits'].get(key, 0) + 1
            continue
        if not dry_run:
            try:
                # a savepoint per contact: one bad row is skipped by name instead of
                # taking the other 288 down with a traceback
                with db.session.begin_nested():
                    _apply_plan(fc, plan, ws, now, window)
            except Exception:
                out['failed'].append(fc.contact_email)
                app_mod.app.logger.exception('ladder placement failed for %s', fc.contact_email)
                continue
        out['placed'] += 1
        out['loads_counted'] += len(plan['new_loads'])
        out['rungs'][plan['rung']] += 1
        if plan['stop_list']:
            out['stop_listed'] += 1
        if plan['rung'] in _ladder.OFF_LADDER:
            key = f'{plan["rung"]}/{plan["exit_reason"] or "unspecified"}'
            out['exits'][key] = out['exits'].get(key, 0) + 1
        if plan['rung'] != plan['from_rung']:
            move = f'{plan["from_rung"]} -> {plan["rung"]}'
            out['moves'][move] = out['moves'].get(move, 0) + 1
        if plan['keeps_date']:
            out['keeps_date'][plan['keeps_date']] = \
                out['keeps_date'].get(plan['keeps_date'], 0) + 1
        out['rows'].append({
            'email': fc.contact_email, 'from_rung': plan['from_rung'], 'rung': plan['rung'],
            'loads': plan['load_count'], 'new_loads': len(plan['new_loads']),
            'exit_reason': plan['exit_reason'], 'auto_paused': plan['auto_paused'],
            'keeps_date': plan['keeps_date'], 'state': fc.state, 'replies': n_replies,
            'last_seen': plan['last_seen'].isoformat() if plan['last_seen'] else None,
        })
    if not dry_run:
        db.session.commit()
    return out


# ── command line ─────────────────────────────────────────────────────────────

def _print_report(out, verbose=False):
    head = 'DRY RUN — nothing written' if out['dry_run'] else 'APPLIED'
    print(f'\n{head}  ·  workspace {out["workspace_id"]}')
    # placed + left alone + failed must account for every contact, or the rung
    # table below is quietly missing somebody
    print(f'  contacts             {out["total"]}  '
          f'= placed {out["placed"]} + left alone (excluded) {out["skipped"]}'
          f' + failed {len(out["failed"])}')
    print(f'  load conversations counted {out["loads_counted"]}')
    sil = out['silence_days']
    print('  silence rule         ' + (f'park after {sil} days of silence' if sil
                                       else 'OFF (nobody is parked for silence)'))
    kept = sum(out['keeps_date'].values())
    detail = ', '.join(f'{why} {n}' for why, n in sorted(out['keeps_date'].items()))
    print(f'  keeping their current date {kept}' + (f'  ({detail})' if detail else ''))
    print(f'  given a new date     {out["new_dates"]}'
          + (f', spread over {out["stagger_days"]} days' if out['new_dates'] else ''))
    if out['foreign']:
        print(f'  !! {out["foreign"]} contact(s) owned by another user: not touched')
    if out['failed']:
        print(f'  !! {len(out["failed"])} contact(s) could not be placed and were skipped:')
        for email in out['failed']:
            print(f'       {email}')
    print('\n  resulting rungs')
    for rung in _RUNG_VALUES:
        print(f'    {rung:<9} {out["rungs"][rung]:>5}')
    if out['exits']:
        # "dormant" is two very different piles: a timeout he may want to undo,
        # and brokers who asked us to stop. He must not have to grep for that.
        print('\n  off the ladder, by reason')
        for key, n in sorted(out['exits'].items(), key=lambda kv: (-kv[1], kv[0])):
            print(f'    {key:<22} {n:>5}')
        print(f'    on the Stop List       {out["stop_listed"]:>5}'
              f'  (of {sum(n for k, n in out["exits"].items() if k.startswith("excluded/"))}'
              f' excluded; a Block, never a Close)')
    if out['moves']:
        print('\n  rung changes')
        for move, n in sorted(out['moves'].items(), key=lambda kv: -kv[1]):
            print(f'    {move:<22} {n:>5}')
    if verbose:
        print('\n  per contact')
        for r in out['rows']:
            bits = [f'{r["email"]:<34}', f'{r["from_rung"]:>8} -> {r["rung"]:<8}',
                    f'loads {r["loads"]}', f'replies {r["replies"]}', f'state {r["state"]}']
            if r['exit_reason']:
                bits.append(f'exit {r["exit_reason"]}')
            if r['auto_paused']:
                bits.append('auto-paused')
            if r['keeps_date']:
                bits.append(f'keeps date ({r["keeps_date"]})')
            print('    ' + '  '.join(bits))
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--workspace', help='workspace id to place (required unless --list)')
    ap.add_argument('--list', action='store_true', help='list workspaces and exit')
    ap.add_argument('--apply', action='store_true', help='write the placement (default: dry run)')
    ap.add_argument('--verbose', action='store_true', help='one line per contact')
    ap.add_argument('--silence-days', type=int, default=SILENCE_DAYS, metavar='N',
                    help=f'park a contact with no activity for N days as dormant/stale '
                         f'(default {SILENCE_DAYS}; 0 parks nobody for silence)')
    args = ap.parse_args(argv)
    if args.silence_days < 0:
        ap.error('--silence-days cannot be negative (0 turns the rule off)')

    app_mod = _app_module()
    with app_mod.app.app_context():
        from app.models import FollowupContact, Workspace
        if args.list or not args.workspace:
            print('\nworkspaces')
            for ws in Workspace.query.order_by(Workspace.created_at).all():
                n = FollowupContact.query.filter_by(workspace_id=ws.id).count()
                print(f'  {ws.id}  {n:>5} contacts  {ws.name}  (owner {ws.owner_id})')
            if not args.workspace:
                print('\nPass --workspace <id>. Without --apply it is a dry run.\n')
                return 1
            return 0
        try:
            out = place_contacts_on_ladder(args.workspace, app_mod._utcnow(),
                                           dry_run=not args.apply,
                                           silence_days=args.silence_days)
        except ValueError as e:
            print(f'\n{e}  —  run --list to see the workspace ids\n')
            return 1
        _print_report(out, verbose=args.verbose)
        if out['dry_run']:
            print('Re-run with --apply to write it. Back the database up first:\n'
                  '  pg_dump "$DATABASE_URL" > before-ladder.sql\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
