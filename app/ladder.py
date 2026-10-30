"""Follow-up warmth ladder: pure rules.

Decides which rung a contact sits on, when the next touch is due, how many
attempts a rung allows, and what an incoming broker reply means.

Standard library only: no Flask, no SQLAlchemy, no imports from app.py. Every
function is deterministic given its arguments, so it is testable without a
database and safe to call from the scheduler, the reply hook and migrations.
"""
import re
from datetime import datetime, timedelta

RUNGS = ('cold', 'neutral', 'warm', 'hot', 'client')
OFF_LADDER = ('dormant', 'excluded')

LADDER_DEFAULTS = {
    'first_touch_days': 1,
    'second_touch_days': 3,
    'weekly_days': 7,
    'budget_no_load': 3,
    'budget_engaged': 5,
    'hot_weekly': True,
    'higher_rung_patience': True,
}

# "next month" is a flat 30 days, not a calendar month: it keeps the result
# strictly after `now` and independent of month lengths.
_MONTH_DAYS = 30
# A stated time further out than this is almost certainly misread text.
_MAX_DEFERRAL = timedelta(days=366)


def _cfg(cfg):
    """Overlay a possibly partial settings dict on the defaults."""
    merged = dict(LADDER_DEFAULTS)
    if cfg:
        merged.update(cfg)
    return merged


def _check_rung(rung):
    if rung not in RUNGS and rung not in OFF_LADDER:
        raise ValueError(f'unknown rung: {rung!r}')


def rung_for(load_count: int, replied: bool) -> str:
    """Derived rung. 'client' is set deliberately and never returned here."""
    if load_count >= 2:
        return 'hot'
    if load_count == 1:
        return 'warm'
    return 'neutral' if replied else 'cold'


def budget_for(rung: str, cfg: dict) -> int:
    """Follow-up attempts allowed on a rung. Rungs that are never scheduled get 0."""
    _check_rung(rung)
    cfg = _cfg(cfg)
    if rung in ('cold', 'neutral'):
        return cfg['budget_no_load']
    if rung in ('warm', 'hot'):
        return cfg['budget_engaged'] if cfg['higher_rung_patience'] else cfg['budget_no_load']
    return 0


def next_touch_at(rung: str, attempt: int, now: datetime, cfg: dict):
    """When the next touch is due after `attempt` touches already made, or None."""
    _check_rung(rung)
    if attempt < 0:
        raise ValueError('attempt must be >= 0')
    if rung == 'client' or rung in OFF_LADDER:
        return None
    cfg = _cfg(cfg)
    if rung == 'hot' and cfg['hot_weekly']:
        days = cfg['weekly_days']
    elif attempt == 0:
        days = cfg['first_touch_days']
    elif attempt == 1:
        days = cfg['second_touch_days']
    else:
        days = cfg['weekly_days']
    return now + timedelta(days=days)


def load_conversation_key(thread_id, contact_email: str, sent_at: datetime) -> str:
    """Stable key for one load conversation: the thread id, else email + day.

    Lets callers count one load per conversation rather than per message.
    """
    thread = (thread_id or '').strip()
    if thread:
        return f'thread:{thread}'
    return f'email:{(contact_email or "").strip().lower()}:{sent_at.date().isoformat()}'


_NUMBER_WORDS = {
    'a': 1, 'an': 1, 'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6,
    'seven': 7, 'eight': 8, 'nine': 9, 'ten': 10, 'eleven': 11, 'twelve': 12,
}
_MONTHS = {
    'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
    'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12,
}
_MONTH_NAME = (r'(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|'
               r'aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)')
_NEXT_WEEK = re.compile(r'\bnext\s+week\b')
_NEXT_MONTH = re.compile(r'\bnext\s+month\b')
_IN_N = re.compile(
    r'\bin\s+(\d{1,3}|' + '|'.join(_NUMBER_WORDS) + r')\s+(day|week|month)s?\b')
_MONTH_DAY = re.compile(_MONTH_NAME + r'\.?\s+(\d{1,2})(?:st|nd|rd|th)?(?!\d)')
_DAY_MONTH = re.compile(r'\b(\d{1,2})(?:st|nd|rd|th)?\s+(?:of\s+)?' + _MONTH_NAME + r'\b')


def _explicit_date(month_word: str, day: int, now: datetime):
    month = _MONTHS[month_word[:3]]
    try:
        candidate = now.replace(month=month, day=day)
        if candidate.date() < now.date():
            candidate = candidate.replace(year=now.year + 1)
    except ValueError:      # e.g. February 30
        return None
    return candidate


def parse_deferral(text: str, now: datetime):
    """The time a broker asked us to come back, or None.

    Never returns a datetime at or before `now`: a past date would make the
    contact instantly overdue, so None is returned instead.
    """
    t = (text or '').lower()
    result = None

    m = _IN_N.search(t)
    if m:
        raw, unit = m.groups()
        n = int(raw) if raw.isdigit() else _NUMBER_WORDS[raw]
        result = now + timedelta(days=n * {'day': 1, 'week': 7, 'month': _MONTH_DAYS}[unit])
    elif _NEXT_WEEK.search(t):
        result = now + timedelta(days=7)
    elif _NEXT_MONTH.search(t):
        result = now + timedelta(days=_MONTH_DAYS)
    else:
        m = _MONTH_DAY.search(t)
        if m:
            result = _explicit_date(m.group(1), int(m.group(2)), now)
        else:
            m = _DAY_MONTH.search(t)
            if m:
                result = _explicit_date(m.group(2), int(m.group(1)), now)

    if result is None or result <= now or result - now > _MAX_DEFERRAL:
        return None
    return result


# The shared triage keyword set files these "not now" phrases under 'negative'
# (and must not be edited), so interpret_reply tells them apart itself.
_DEFERRAL_PHRASES = (
    'nothing this week', 'no loads this week', 'nothing right now',
    'nothing at this time', 'not at this time',
    'we are covered', "we're covered", 'all covered', 'load is covered',
    "it's covered", 'already covered',
)
# Unambiguous "stop contacting me" wording. Wins over any deferral phrase.
_REFUSAL_PHRASES = (
    'remove me', 'unsubscribe', 'take me off', 'stop contacting',
    "don't contact", 'do not contact', 'dont contact', 'dnu', 'do not use',
)


def interpret_reply(category, text: str, now: datetime):
    """Classify a broker reply as (kind, resume_at).

    kind is one of 'load', 'refusal', 'deferral', 'unknown'. resume_at is only
    set for a 'deferral' that states a time, and is always after `now`.
    """
    t = (text or '').lower()
    if category in (None, 'negative'):
        if any(p in t for p in _REFUSAL_PHRASES):
            return 'refusal', None
        stated = parse_deferral(t, now)
        if stated is not None or any(p in t for p in _DEFERRAL_PHRASES):
            return 'deferral', stated
        return ('refusal', None) if category == 'negative' else ('unknown', None)
    if category == 'gave_info':
        return 'load', None
    return 'unknown', None
