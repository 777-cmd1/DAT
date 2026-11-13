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
    # A load means the owner is now working that deal himself — reading it, quoting it,
    # answering. Asking "do you have another load?" the next morning lands in the middle
    # of that conversation. This is how long the ladder stands back afterwards.
    'quiet_days_after_load': 7,
    'hot_weekly': True,
    'higher_rung_patience': True,
    # Most touches the scheduler sends per local day, per workspace. Without it, switching
    # the ladder on mails the whole overdue backlog in one pass and, since every contact is
    # then re-dated by the same rule, the whole cohort comes due together again.
    'daily_cap': 25,
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
_MONTH_DAY = re.compile(r'\b' + _MONTH_NAME + r'\.?\s+(\d{1,2})(?:st|nd|rd|th)?(?!\d)')
# "may" is left out of the day-first form: "1 may work" is prose, not 1 May.
_MONTH_NAME_NO_MAY = _MONTH_NAME.replace('|may|', '|')
_DAY_MONTH = re.compile(r'\b(\d{1,2})(?:st|nd|rd|th)?\s+(?:of\s+)?' + _MONTH_NAME_NO_MAY + r'\b')
# A date already past this year is only read as next year's when the text says
# "come back later": otherwise it is an incidental date ("signed on Oct 12").
_FORWARD_CUE = re.compile(r'\b(after|until|till|back)\b')


def _norm(text) -> str:
    """Lowercase, fold curly apostrophes to straight, collapse all whitespace."""
    t = (text or '').lower().replace('’', "'").replace('‘', "'")
    return ' '.join(t.split())


def _explicit_date(month_word: str, day: int, now: datetime, roll_forward: bool):
    month = _MONTHS[month_word[:3]]
    try:
        candidate = now.replace(month=month, day=day)
        if candidate.date() < now.date():
            if not roll_forward:
                return None
            candidate = candidate.replace(year=now.year + 1)
    except ValueError:      # e.g. February 30
        return None
    return candidate


def parse_deferral(text: str, now: datetime):
    """The time a broker asked us to come back, or None.

    Never returns a datetime at or before `now`: a past date would make the
    contact instantly overdue, so None is returned instead.
    """
    t = _norm(text)
    result = None
    roll = bool(_FORWARD_CUE.search(t))

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
            result = _explicit_date(m.group(1), int(m.group(2)), now, roll)
        else:
            m = _DAY_MONTH.search(t)
            if m:
                result = _explicit_date(m.group(2), int(m.group(1)), now, roll)

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
# Reply filters that sit in the shared 'negative' bucket but are not a "no" to us.
# "Send me your MC and insurance" is a broker opening a carrier packet — the
# hottest reply in the book. The Replies page files it under Negative because its
# recommended action there is Ignore; the ladder must not read that as a refusal,
# so it goes to the human instead. Same shape as the deferral split below: the
# shared keyword sets are never edited, Follow-up tells the cases apart itself.
PACKET_REQUEST_FILTERS = ('mc_request',)


def is_packet_request(category, filter_key) -> bool:
    """True when this reply's triage says it is a broker asking for our packet.

    Only says what the filter says; it does not read the words, so a reply that
    also asks us to stop still comes out of `interpret_reply` as a refusal.
    Callers that want "a packet ask and nothing worse" check both.
    """
    return category in (None, 'negative') and filter_key in PACKET_REQUEST_FILTERS


def interpret_reply(category, text: str, now: datetime, filter_key=None):
    """Classify a broker reply as (kind, resume_at).

    kind is one of 'load', 'refusal', 'deferral', 'unknown'. resume_at is only
    set for a 'deferral' that states a time, and is always after `now`.

    `filter_key` is the triage filter that matched (`Reply.reply_filter_key`, or
    `classify_reply_text`'s `filter_key`). It is what tells a carrier-packet ask
    apart from a real "no" inside the shared 'negative' bucket.
    """
    t = _norm(text)    # real mail has curly apostrophes and hard-wrapped lines
    if category in (None, 'negative'):
        if any(p in t for p in _REFUSAL_PHRASES):
            return 'refusal', None
        stated = parse_deferral(t, now)
        if stated is not None or any(p in t for p in _DEFERRAL_PHRASES):
            return 'deferral', stated
        if filter_key in PACKET_REQUEST_FILTERS:
            return 'unknown', None      # they want our packet: the owner answers it
        return ('refusal', None) if category == 'negative' else ('unknown', None)
    if category == 'gave_info':
        return 'load', None
    return 'unknown', None


# ── "Needs you": promises that were not kept, and a client gone quiet ────────
# A promise only becomes a worry once it is overdue; one older than the horizon
# stops being listed so the list cannot grow without bound.
PROMISE_GRACE_DAYS = 2
PROMISE_HORIZON_DAYS = 30
# A client is silent when it has been quiet for twice its own usual gap, but never
# before this many days.
SILENCE_FLOOR_DAYS = 14
SILENCE_FACTOR = 2

# "I'll send you a load": the broker commits to freight, not merely to reply.
_LOAD_PROMISE_PHRASES = (
    'send you a load', 'send you loads', 'send you some loads', 'send you a few loads',
    'send you more loads', 'send you some freight', 'send you freight', 'send you something',
    'send a load your way', 'send loads your way', 'send some loads your way',
    'have a load for you', 'have loads for you', 'have something for you',
    'load coming your way', 'loads coming your way',
    'give you a load', 'give you some loads', 'get you a load', 'get you some loads',
)
# A commitment to hand over something concrete other than freight.
_OTHER_PROMISE_PHRASES = (
    'send you the rate', 'send you a rate', 'send you rates', 'send you our rate',
    'send you the quote', 'send you a quote', 'send you the details', 'send you details',
    'send you the info', 'send you more info', 'send you the lane', 'send you our lanes',
    'send over the rate', 'send over the details', 'send over the info',
    'get you a rate', 'get you the rate', 'get you a quote', 'get you the details',
    'get back to you with',
)
# What precedes a phrase, within its own clause, and makes it something other
# than a promise: a refusal ("can't send you a load"), an offer or question
# ("want me to send you the rates?"), a condition ("let you know if I have a
# load for you") or a hedge ("I wish I could", "hopefully we can").
_NOT_A_PROMISE = re.compile(
    r"\b(?:not|never|no|cannot|unable)\b|n't\b|"
    r"\b(?:want me to|would you like|do you|should i|shall i|can i|may i|"
    r"if you|if i|if we|let you know if|wish|would love|i'd love|hopefully)\b")
# A clause ends at punctuation, a spaced or long dash, or a "but"/"however".
_CLAUSE_END = re.compile(r'[.!?;,\u2013\u2014]|\s-+\s|\b(?:but|however)\b')
# "No problem, I'll send you a load" is a yes, not a no.
_NO_PROBLEM = re.compile(r'\bno (?:problem|worries|issue)s?\b')
# A condition tacked on after the phrase: "I can send you a load if you need one".
# Where the promise's own clause stops going forward: a clause end, or an "and" that
# starts a new thought ("a load and if you need more just ask").
_AFTER_END = re.compile(_CLAUSE_END.pattern + r'|\band\b')
# Only the offer forms: "if you can cover it" or "if you have a truck" is a real commitment.
_CONDITION_AFTER = re.compile(r"\bif you(?:'d| would)? (?:need|want|like)\b")
_LOOKBACK = 40


def _promised(t: str, phrases) -> bool:
    for phrase in phrases:
        start = t.find(phrase)
        while start != -1:
            before = t[max(0, start - _LOOKBACK):start]
            ends = list(_CLAUSE_END.finditer(before))
            if ends:
                before = before[ends[-1].end():]
            after = t[start + len(phrase):start + len(phrase) + _LOOKBACK]
            nxt = _AFTER_END.search(after)
            if nxt:
                after = after[:nxt.start()]
            if (not _NOT_A_PROMISE.search(_NO_PROBLEM.sub(' ', before))
                    and not _CONDITION_AFTER.search(after)):
                return True
            start = t.find(phrase, start + 1)
    return False


def promise_kind(text):
    """What the broker promised in this reply: 'load', 'other', or None.

    'load' wins when both appear. `text` should be the reply's own words, with
    quoted mail already cut off.
    """
    t = _norm(text)
    if _promised(t, _LOAD_PROMISE_PHRASES):
        return 'load'
    if _promised(t, _OTHER_PROMISE_PHRASES):
        return 'other'
    return None


def silence_threshold_days(gaps) -> float:
    """Days of silence after which a client is unusually quiet, given the days
    between its past replies: twice their median, never less than the floor."""
    ordered = sorted(gaps)
    if not ordered:
        return SILENCE_FLOOR_DAYS
    mid = len(ordered) // 2
    median = ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2
    return max(SILENCE_FLOOR_DAYS, SILENCE_FACTOR * median)
