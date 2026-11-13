#!/usr/bin/env python3
"""Point every follow-up contact at its newest reply. Run once, after the deploy that
made the live hook keep the conversation current.

`source_thread_id`, `reply_msg_id` and `reply_subject` used to be written when a contact
was created and never again, so a broker who wrote in August and again in October kept
the August thread: a follow-up asking "do you have another load?" arrived in the wrong
conversation, under the first lane's subject. The live hook now moves those fields with
every inbound reply — but only from the moment it shipped. A base that has been running
for months carries the old values until each broker happens to write in again, and the
first automatic wave would go out into those old threads.

Every reply is already stored, so the newest one per contact can simply be read back.
A reply counts for a contact when it came FROM them, or when a colleague answered on
their behalf (`matched_recipient` — the address we had written to), which is the same
rule the contact's own history uses.

Writes nothing without --apply. Scoped to one workspace, like the ladder migration:
a sweep across workspaces is the one bug this must never have.

  python scripts/backfill_conversations.py --list
  python scripts/backfill_conversations.py --workspace <id> --verbose
  python scripts/backfill_conversations.py --workspace <id> --apply
"""
import argparse
import importlib.util
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_APP = None


def _app_module():
    """app.py, loaded by path: `import app` would find the app/ package instead."""
    global _APP
    if _APP is None:
        os.environ.setdefault('DISABLE_SCHEDULER', '1')
        sys.path.insert(0, _ROOT)
        spec = importlib.util.spec_from_file_location('_dat_app', os.path.join(_ROOT, 'app.py'))
        mod = importlib.util.module_from_spec(spec)
        sys.modules['_dat_app'] = mod
        spec.loader.exec_module(mod)
        _APP = mod
    return _APP


def newest_replies(uid, emails):
    """{contact email: newest Reply} for these addresses, by the same matching rule the
    contact's history uses: their own reply, or a colleague's on their behalf."""
    app_mod = _app_module()
    db = app_mod.db
    from app.models import Reply
    wanted = {e.lower() for e in emails if e}
    if not wanted:
        return {}
    rows = Reply.query.filter(
        Reply.user_id == uid,
        db.or_(db.func.lower(Reply.from_email).in_(list(wanted)),
               db.func.lower(Reply.matched_recipient).in_(list(wanted))),
    ).order_by(Reply.received_at.desc().nullslast()).all()
    out = {}
    for r in rows:                                   # newest first: the first hit wins
        for addr in {(r.from_email or '').lower(), (r.matched_recipient or '').lower()}:
            if addr in wanted and addr not in out:
                out[addr] = r
    return out


def backfill(workspace_id, dry_run=True):
    """Move each contact onto its newest reply's conversation.

    Returns the counts and one row per contact that would move, so the owner can read
    what changes before anything is written.
    """
    app_mod = _app_module()
    db = app_mod.db
    from app.models import FollowupContact, Workspace
    ws = db.session.get(Workspace, workspace_id)
    if ws is None:
        raise ValueError(f'No workspace {workspace_id!r}')
    contacts = FollowupContact.query.filter_by(workspace_id=ws.id).all()
    replies = newest_replies(ws.owner_id, [c.contact_email for c in contacts])

    rows, moved, no_reply, already = [], 0, 0, 0
    for fc in contacts:
        reply = replies.get((fc.contact_email or '').lower())
        if reply is None:
            no_reply += 1
            continue
        before = (fc.source_thread_id or '', fc.reply_msg_id or '', fc.reply_subject or '')
        # the live helper, so the backfill cannot drift from what the hook does
        changed = app_mod._followup_track_conversation(
            fc, getattr(reply, 'thread_id', '') or '', getattr(reply, 'msg_id', '') or '',
            getattr(reply, 'subject', '') or '')
        if not changed:
            already += 1
            continue
        moved += 1
        rows.append({
            'email': fc.contact_email, 'rung': fc.rung,
            'from_subject': before[2], 'to_subject': fc.reply_subject or '',
            'from_thread': before[0], 'to_thread': fc.source_thread_id or '',
            'at': reply.received_at,
        })
    if dry_run:
        db.session.rollback()
    else:
        db.session.commit()
    return {'workspace_id': ws.id, 'dry_run': dry_run, 'total': len(contacts),
            'moved': moved, 'already_current': already, 'no_reply_stored': no_reply,
            'rows': rows}


def _print_report(out, verbose=False):
    print(f'\n{"DRY RUN — nothing written" if out["dry_run"] else "APPLIED"}'
          f'  ·  workspace {out["workspace_id"]}')
    print(f'  contacts            {out["total"]}  = moved {out["moved"]}'
          f' + already current {out["already_current"]}'
          f' + no reply stored {out["no_reply_stored"]}')
    if verbose:
        print('\n  per contact')
        for r in out['rows']:
            when = r['at'].strftime('%Y-%m-%d') if r['at'] else '(no date)'
            print(f'    {r["email"]:<34} {str(r["rung"]):<8} {when}')
            print(f'        subject  {r["from_subject"] or "(none)"!r}')
            print(f'              -> {r["to_subject"] or "(none)"!r}')
    elif out['rows']:
        print('\n  run with --verbose to read which conversation each one moves to')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--workspace', help='workspace id to backfill (required unless --list)')
    ap.add_argument('--list', action='store_true', help='list workspaces and exit')
    ap.add_argument('--apply', action='store_true', help='write it (default: dry run)')
    ap.add_argument('--verbose', action='store_true', help='one block per contact that moves')
    args = ap.parse_args(argv)

    app_mod = _app_module()
    with app_mod.app.app_context():
        from app.models import FollowupContact, Workspace
        if args.list or not args.workspace:
            print('\nworkspaces')
            for ws in Workspace.query.order_by(Workspace.created_at).all():
                n = FollowupContact.query.filter_by(workspace_id=ws.id).count()
                print(f'  {ws.id}  {n:>5} contacts  {ws.name}')
            if not args.workspace:
                print('\nPass --workspace <id>. Without --apply it is a dry run.\n')
                return 1
            return 0
        try:
            out = backfill(args.workspace, dry_run=not args.apply)
        except ValueError as e:
            print(f'\n{e}  —  run --list to see the workspace ids\n')
            return 1
        _print_report(out, verbose=args.verbose)
        if out['dry_run']:
            print('\nRe-run with --apply to write it.\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
