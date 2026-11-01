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
  3. The rung its history earns. `load_count` = the load conversations in its
     `gave_info` replies, deduped exactly as the live reply hook dedupes them
     (`load_conversation_key`: thread id, else address + day) and counted
     through the same `_ladder_record_load` / `_ladder_load_counted` pair, so a
     later live reply in an old thread cannot count the same load twice.
     `replied` = any stored reply from them, or `last_reply_at`: rows older than
     the triage system carry no category but are still answers. The result never
     lowers a rung that is already set (a `set-rung` the owner made by hand, or
     a step the live hook already took).
  4. The owner's decision in the legacy state machine wins over 3:
     `blocked` → `excluded`, `closed` → `excluded`, `loads` → `client`,
     and `loads`/`warm` are taken out of automation (`auto_paused`).
  5. Silence. Nothing has happened for SILENCE_DAYS → `dormant` / `stale`.
     This brake exists ONLY here: the running engine has no silence rule, so
     a long-dead base is parked once, at migration time, and never again.
  6. Anything off the ladder carries an `exit_reason`, so the conversion panel
     can say why it is out rather than showing a blank group.

Then the drip stops owning the contact: `is_followup_enabled` goes False (the
drip scheduler requires it True, the ladder scheduler requires it False, so
exactly one engine can ever date and send to a contact). `stage` is left alone
— it is the readable history of what the drip sent, and the owner's manual
"send follow-up" button reads it. A one-time or recurring send the owner
scheduled, and a date a broker asked us to come back on, keep their own dates.

Nothing here sends mail or widens what sends: both `fu_auto_enabled` and
`ladder_auto_enabled` are untouched, and every date goes through
`_ladder_set_next`, which refuses a date to anyone who must not get one.

Usage:
    python scripts/migrate_to_ladder.py --list
    python scripts/migrate_to_ladder.py --workspace <id>            # dry run
    python scripts/migrate_to_ladder.py --workspace <id> --verbose
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
# rather than given a fresh budget of attempts. Deliberately not in
# app/ladder.py: there is no silence brake in the running engine, and putting
# the number there would imply one.
SILENCE_DAYS = 90

# The legacy state machine's terminal states, as the ladder reads them.
_STATE_EXCLUDES = {'blocked': 'blocked', 'closed': 'closed'}
_STATE_PAUSES = ('loads', 'warm')       # the owner's own "this one worked" marks

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


def _not_lower(current, derived):
    """The higher of the two rungs. The history may only raise what is set: a rung
    the owner chose by hand, or one the live hook already climbed, is never undone."""
    if current not in _ladder.RUNGS:
        return derived
    return max(current, derived, key=_ladder.RUNGS.index)


def _plan_contact(fc, replies, now, deferred):
    """What this contact should become. Pure reads — nothing is written here, so a
    dry run and a real run decide identically. None means "leave it alone"."""
    app_mod = _app_module()
    current = fc.rung if fc.rung in _RUNG_VALUES else None   # a legacy value counts as unset
    if current == 'excluded':
        return None                                 # rule 1: permanent, and not even read

    # rule 3a: the load conversations in the history, oldest first, deduped the
    # way the live hook dedupes them and counted through the same pair.
    seen, convs = set(), []
    for r in sorted(replies, key=lambda r: _reply_at(r, fc, now)):
        if r.triage_category != 'gave_info':
            continue
        at = _reply_at(r, fc, now)
        key = _ladder.load_conversation_key(r.thread_id, fc.contact_email, at)
        if key in seen:
            continue
        seen.add(key)
        convs.append((key, at))
    fresh = [(k, at) for k, at in convs if not app_mod._ladder_load_counted(fc, k)]
    load_count = (fc.load_count or 0) + len(fresh)
    replied = bool(replies) or fc.last_reply_at is not None

    exit_reason = fc.exit_reason
    auto_paused = bool(fc.auto_paused)
    if current in _ladder.OFF_LADDER:
        rung = current                              # rule 2: already out of play, stays out
    else:
        rung = _not_lower(current, _ladder.rung_for(load_count, replied))   # rule 3b

    state = (fc.state or '').strip().lower()        # rule 4: the owner's own mark wins
    if state in _STATE_EXCLUDES:
        rung, exit_reason = 'excluded', _STATE_EXCLUDES[state]
    elif state == 'loads':
        rung = 'client'
    if state in _STATE_PAUSES:
        auto_paused = True

    last = _last_seen(fc, replies, now)
    silent = last is None or last <= now - timedelta(days=SILENCE_DAYS)
    if silent and rung in _ladder.RUNGS and rung != 'client':
        rung, exit_reason = 'dormant', 'stale'      # rule 5

    if rung in _ladder.OFF_LADDER:                  # rule 6
        if not exit_reason:
            exit_reason = 'stale' if silent else 'manual'
    elif exit_reason != 'send_failed':
        exit_reason = None                          # back in play: only the pause keeps its reason

    # A date is only replaced when it is a drip leftover: a one-time or recurring
    # send the owner scheduled, a day a broker asked us to come back on, and a
    # live date an engine already owns all keep theirs (which also makes a second
    # run of this script a no-op).
    held = bool(fc.touch_enabled and fc.next_followup_at and fc.next_followup_at > now)
    return {'from_rung': fc.rung, 'rung': rung, 'load_count': load_count,
            'new_loads': fresh, 'exit_reason': exit_reason, 'auto_paused': auto_paused,
            'redate': not (fc.scheduled_once or fc.recurring_enabled
                           or fc.id in deferred or held),
            'last_seen': last}


_PLACED = ('rung', 'load_count', 'exit_reason', 'auto_paused', 'is_followup_enabled')


def _apply_plan(fc, plan, ws, now):
    """Write one planned placement, and log what it replaced."""
    app_mod = _app_module()
    before = {'rung': fc.rung, 'load_count': fc.load_count, 'exit_reason': fc.exit_reason,
              'auto_paused': fc.auto_paused, 'state': fc.state, 'stage': fc.stage,
              'is_followup_enabled': fc.is_followup_enabled,
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
    if plan['redate']:
        app_mod._ladder_set_next(fc, _ladder.next_touch_at(
            fc.rung, fc.touch_attempt or 0, now, _ladder.LADDER_DEFAULTS), ws)
    for key, at in plan['new_loads']:
        evt = app_mod._ladder_record_load(fc, key, plan['from_rung'], notes='load from reply history')
        evt.event_at = at           # the day it really arrived, not migration day
    if all(before[f] == getattr(fc, f) for f in _PLACED):
        return None                 # already where it belongs: nothing to log
    return app_mod._record_event(fc, _MIGRATION_EVENT, actor_type='system',
                                 from_state=plan['from_rung'], to_state=fc.rung,
                                 metadata_json=app_mod.json.dumps({'before': before}),
                                 notes=f'placed on the ladder from {len(plan["new_loads"])} '
                                       f'load conversation(s) in its history')


def place_contacts_on_ladder(workspace_id, now, dry_run=True):
    """Put one workspace's contacts on the rung their history earns.

    Returns the distribution: counts per resulting rung, the rung changes, how
    many load conversations were counted, and one row per contact. `dry_run`
    (the default) decides everything and writes nothing — not a column, not an
    event, not even a dirty object in the session.

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

    out = {'workspace_id': ws.id, 'dry_run': bool(dry_run), 'placed': 0, 'skipped': 0,
           'loads_counted': 0, 'foreign': foreign,
           'rungs': {r: 0 for r in _RUNG_VALUES}, 'moves': {}, 'rows': []}
    for fc in rows:
        mine = replies.get(fc.id, [])
        plan = _plan_contact(fc, mine, now, deferred)
        if plan is None:
            out['skipped'] += 1
            out['rungs']['excluded'] += 1
            continue
        out['placed'] += 1
        out['loads_counted'] += len(plan['new_loads'])
        out['rungs'][plan['rung']] += 1
        if plan['rung'] != plan['from_rung']:
            move = f'{plan["from_rung"]} -> {plan["rung"]}'
            out['moves'][move] = out['moves'].get(move, 0) + 1
        out['rows'].append({
            'email': fc.contact_email, 'from_rung': plan['from_rung'], 'rung': plan['rung'],
            'loads': plan['load_count'], 'new_loads': len(plan['new_loads']),
            'exit_reason': plan['exit_reason'], 'auto_paused': plan['auto_paused'],
            'state': fc.state, 'replies': len(mine),
            'last_seen': plan['last_seen'].isoformat() if plan['last_seen'] else None,
        })
        if not dry_run:
            _apply_plan(fc, plan, ws, now)
    if not dry_run:
        db.session.commit()
    return out


# ── command line ─────────────────────────────────────────────────────────────

def _print_report(out, verbose=False):
    head = 'DRY RUN — nothing written' if out['dry_run'] else 'APPLIED'
    print(f'\n{head}  ·  workspace {out["workspace_id"]}')
    print(f'  contacts placed      {out["placed"]}')
    print(f'  left alone (excluded) {out["skipped"]}')
    print(f'  load conversations counted {out["loads_counted"]}')
    if out['foreign']:
        print(f'  !! {out["foreign"]} contact(s) owned by another user: not touched')
    print('\n  resulting rungs')
    for rung in _RUNG_VALUES:
        print(f'    {rung:<9} {out["rungs"][rung]:>5}')
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
            print('    ' + '  '.join(bits))
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--workspace', help='workspace id to place (required unless --list)')
    ap.add_argument('--list', action='store_true', help='list workspaces and exit')
    ap.add_argument('--apply', action='store_true', help='write the placement (default: dry run)')
    ap.add_argument('--verbose', action='store_true', help='one line per contact')
    args = ap.parse_args(argv)

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
                                           dry_run=not args.apply)
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
