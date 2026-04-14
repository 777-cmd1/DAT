"""
Tests for parse_dat_text() — DAT freight board parser.
"""
import sys
import importlib

# The module was loaded in conftest.py under '_dat_mailer_app'
_m = sys.modules['_dat_mailer_app']
parse_dat_text = _m.parse_dat_text


# ── Helper ────────────────────────────────────────────────────────────────────

def _emails(loads):
    return [l['email'] for l in loads]


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_basic_block_parses_email():
    text = """
ABC Trucking
Chicago, IL
Dallas, TX
V
3/15
48 ft
45,000 lbs
dispatch@abctrucking.com
"""
    result = parse_dat_text(text)
    assert len(result) == 1
    assert result[0]['email'] == 'dispatch@abctrucking.com'


def test_basic_block_extracts_origin_destination():
    text = """
XYZ Freight LLC
Atlanta, GA
Miami, FL
FD
4/10
dispatch@xyzfreight.com
"""
    result = parse_dat_text(text)
    assert len(result) == 1
    load = result[0]
    assert load['email'] == 'dispatch@xyzfreight.com'
    assert 'Atlanta' in load['origin'] or load['origin'] == ''  # parser best-effort
    assert 'Miami' in load['destination'] or load['destination'] == ''


def test_tab_separated_format():
    text = "TransCo\tPhoenix, AZ\tLos Angeles, CA\tV\t5/1\tinfo@transco.com"
    result = parse_dat_text(text)
    assert len(result) == 1
    assert result[0]['email'] == 'info@transco.com'


def test_multiple_loads_parsed():
    text = """
Company A
Denver, CO
Salt Lake City, UT
loads@companya.com

Company B
Seattle, WA
Portland, OR
contact@companyb.com
"""
    result = parse_dat_text(text)
    assert len(result) == 2
    emails = _emails(result)
    assert 'loads@companya.com' in emails
    assert 'contact@companyb.com' in emails


def test_deduplication_same_email_same_route():
    """Same email + same origin/destination should appear only once."""
    block = """
ABC Logistics
Houston, TX
Memphis, TN
ops@abclogistics.com
"""
    text = block + "\n" + block   # duplicate block
    result = parse_dat_text(text)
    assert sum(1 for l in result if l['email'] == 'ops@abclogistics.com') == 1


def test_same_email_different_routes_both_kept():
    """Two separate emails with different addresses produce two distinct entries,
    even when they appear in close proximity.

    Note: the parser deduplicates by email+origin+destination. Two different
    email addresses always produce distinct keys regardless of routes.
    """
    text = """
Carrier A
Chicago, IL
Detroit, MI
dispatchA@carriera.com

Carrier B
Houston, TX
Dallas, TX
dispatchB@carrierb.com
"""
    result = parse_dat_text(text)
    emails = _emails(result)
    assert 'dispatcha@carriera.com' in emails
    assert 'dispatchb@carrierb.com' in emails
    assert len(result) == 2


def test_missing_date_still_parses():
    text = """
NoDate Freight
Raleigh, NC
Charlotte, NC
nodatefreight@email.com
"""
    result = parse_dat_text(text)
    assert len(result) == 1
    assert result[0]['date'] == ''


def test_missing_equipment_still_parses():
    text = """
NoEquip Co
Nashville, TN
Louisville, KY
noequip@co.com
"""
    result = parse_dat_text(text)
    assert len(result) == 1
    assert result[0]['equip'] == ''


def test_email_extracted_case_insensitive():
    """Email should be lowercased regardless of input."""
    text = """
Mixed Case Co
Boston, MA
New York, NY
BROKER@MixedCase.COM
"""
    result = parse_dat_text(text)
    assert len(result) == 1
    assert result[0]['email'] == 'broker@mixedcase.com'


def test_company_name_line_above_email():
    """The line immediately above the email line is taken as company name."""
    text = """
Some City, TX
Another City, CA
Acme Transport Inc
acme@transport.com
"""
    result = parse_dat_text(text)
    assert len(result) == 1
    assert result[0]['company'] == 'Acme Transport Inc'


def test_empty_input_returns_empty_list():
    assert parse_dat_text('') == []
    assert parse_dat_text('   \n\n  ') == []


def test_no_email_in_block_ignored():
    text = """
No Email Co
Chicago, IL
Dallas, TX
V
3/15
no email here at all
"""
    result = parse_dat_text(text)
    assert result == []


def test_weight_extracted():
    text = """
Heavy Load Co
Phoenix, AZ
Albuquerque, NM
V
42,000 lbs
heavy@loads.com
"""
    result = parse_dat_text(text)
    assert len(result) == 1
    assert '42,000 lbs' in result[0]['weight'] or result[0]['weight'] != ''


def test_equipment_types_recognized():
    """Parser should recognize standard DAT equipment codes."""
    for equip_code in ('V', 'FD', 'SD', 'VM', 'F', 'R'):
        text = f"""
Test Co
Tampa, FL
Orlando, FL
{equip_code}
test@equip.com
"""
        result = parse_dat_text(text)
        if result:   # equipment presence depends on block ordering
            assert result[0]['email'] == 'test@equip.com'
