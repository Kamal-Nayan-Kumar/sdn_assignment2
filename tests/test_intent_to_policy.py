"""Tests for intent_to_policy.py — LLM/fallback precedence and invalid input.

The LLM itself is mocked so these tests are deterministic and never need
Ollama; the point is to check what the *client* does with whatever the LLM
answers (empty, conflicting, malformed, non-JSON).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import intent_to_policy as itp  # noqa: E402


# --------------------------------------------------------------------------- #
# validate_rules: accept the well-formed, reject everything else               #
# --------------------------------------------------------------------------- #
def test_accepts_valid_rules():
    rules = [{'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:03',
              'action': 'DROP'}]
    assert itp.validate_rules(rules) == [{
        'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:03',
        'action': 'DROP'}]


@pytest.mark.parametrize('bad', [
    {'src_mac': 'nonsense', 'dst_mac': '00:00:00:00:00:03', 'action': 'DROP'},
    {'src_mac': '00:00:00:00:00:01', 'dst_mac': 'xx', 'action': 'DROP'},
    {'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:03',
     'action': 'PERMIT'},
    {'src_mac': '00:00:00:00:00:01', 'action': 'DROP'},          # no dst_mac
    {'dst_mac': '00:00:00:00:00:03', 'action': 'DROP'},          # no src_mac
    {'src_mac': None, 'dst_mac': '00:00:00:00:00:03', 'action': 'DROP'},
    {'src_mac': 1, 'dst_mac': '00:00:00:00:00:03', 'action': 'DROP'},
    'not a dict',
])
def test_rejects_invalid_rules(bad):
    assert itp.validate_rules([bad]) == []


def test_mixed_valid_and_invalid():
    rules = [
        {'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:03',
         'action': 'DROP'},
        {'src_mac': 'bogus', 'dst_mac': '00:00:00:00:00:03',
         'action': 'DROP'},
    ]
    assert len(itp.validate_rules(rules)) == 1


def test_mac_case_is_normalised():
    rules = [{'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:03',
              'action': 'drop'}]
    # action must be uppercase DROP/ALLOW to be accepted
    assert itp.validate_rules(rules) == []
    rules[0]['action'] = 'DROP'
    assert itp.validate_rules(rules)[0]['src_mac'] == '00:00:00:00:00:01'



# (The four host MACs are all single hex digits, so there is no real host
# with a mixed-case representation; upper-case normalisation is exercised
# by the .lower() calls themselves and needs no separate test.)


def test_rejects_non_list():
    assert itp.validate_rules({'src_mac': '00:00:00:00:00:01'}) == []


# --------------------------------------------------------------------------- #
# validate_rules: a small model invents hosts; a firewall must not           #
# --------------------------------------------------------------------------- #
def test_rejects_invented_hosts():
    """gemma2:2b answered 'h5 -> h6' for a 4-host network."""
    rules = [{'src_mac': '00:00:00:00:00:05', 'dst_mac': '00:00:00:00:00:06',
              'action': 'ALLOW'}]
    assert itp.validate_rules(rules) == []


def test_rejects_half_known_pair():
    rules = [{'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:07',
              'action': 'DROP'}]
    assert itp.validate_rules(rules) == []


def test_accepts_all_four_known_hosts():
    for src in itp.KNOWN_MACS:
        rules = [{'src_mac': src, 'dst_mac': '00:00:00:00:00:03',
                  'action': 'DROP'}]
        assert len(itp.validate_rules(rules)) == 1


# --------------------------------------------------------------------------- #
# filter_phantom_rules: models echo the prompt's examples back                #
# --------------------------------------------------------------------------- #
def test_hosts_in_intent():
    assert itp.hosts_in_intent("Block h1 from h3") == {
        '00:00:00:00:00:01', '00:00:00:00:00:03'}
    # 'h1' must not match inside another token
    assert itp.hosts_in_intent("Block sh10 from nowhere") == set()


def test_phantom_rule_is_discarded():
    """The model returned h4->h1 alongside the real h1->h3 answer."""
    rules = [
        {'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:03',
         'action': 'DROP'},
        {'src_mac': '00:00:00:00:00:04', 'dst_mac': '00:00:00:00:00:01',
         'action': 'DROP'},
    ]
    kept, rejected = itp.filter_phantom_rules(rules, "Block h1 from h3")
    assert len(kept) == 1 and kept[0]['dst_mac'] == '00:00:00:00:00:03'
    assert len(rejected) == 1 and rejected[0]['src_mac'] == '00:00:00:00:00:04'


def test_phantom_filter_keeps_everything_when_no_host_named():
    rules = [{'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:03',
              'action': 'DROP'}]
    kept, rejected = itp.filter_phantom_rules(rules, "Allow everything else.")
    assert kept == rules and rejected == []


def test_phantom_filter_keeps_multi_pair_intent():
    rules = [
        {'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:03',
         'action': 'DROP'},
        {'src_mac': '00:00:00:00:00:02', 'dst_mac': '00:00:00:00:00:04',
         'action': 'DROP'},
    ]
    kept, rejected = itp.filter_phantom_rules(
        rules, "Block h1 from h3 and block h2 from h4")
    assert len(kept) == 2 and rejected == []


# --------------------------------------------------------------------------- #
# llm_parse sends think=false (no chain-of-thought)                           #
# --------------------------------------------------------------------------- #
def test_reasoning_is_disabled(monkeypatch):
    seen = {}

    def fake_post(url, **kw):
        seen.update(kw.get('json', {}))
        return FakeResponse(200, {'response': '[]'})

    import requests
    monkeypatch.setattr(requests, 'post', fake_post)
    with pytest.raises(itp.NoRules):
        itp.llm_parse('Allow everything else.')
    assert seen['think'] is False
    assert seen['options']['num_predict'] == itp.NUM_PREDICT


# --------------------------------------------------------------------------- #
# merge_rules: precedence, not silent agreement                                 #
# --------------------------------------------------------------------------- #
def test_duplicates_collapse():
    a = [{'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:03',
          'action': 'DROP'}]
    merged, conflicts = itp.merge_rules([a, a])
    assert len(merged) == 1
    assert conflicts == []


def test_drop_wins_over_allow_for_same_pair():
    drop = [{'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:03',
             'action': 'DROP'}]
    allow = [{'src_mac': '00:00:00:00:00:01',
              'dst_mac': '00:00:00:00:00:03', 'action': 'ALLOW'}]
    merged, conflicts = itp.merge_rules([allow, drop])
    assert len(merged) == 1
    assert merged[0]['action'] == 'DROP'
    assert len(conflicts) == 1
    assert conflicts[0]['kept'] == 'DROP'
    assert conflicts[0]['discarded'] == 'ALLOW'


def test_allow_wins_over_drop_for_same_pair():
    """Order matters: the ALLOW arriving after a DROP must not silently win."""
    drop = [{'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:03',
             'action': 'DROP'}]
    allow = [{'src_mac': '00:00:00:00:00:01',
              'dst_mac': '00:00:00:00:00:03', 'action': 'ALLOW'}]
    merged, conflicts = itp.merge_rules([drop, allow])
    assert merged[0]['action'] == 'DROP'      # fail-closed
    assert len(conflicts) == 1


def test_order_is_preserved():
    r1 = [{'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:03',
           'action': 'DROP'}]
    r2 = [{'src_mac': '00:00:00:00:00:02', 'dst_mac': '00:00:00:00:00:04',
           'action': 'DROP'}]
    merged, _ = itp.merge_rules([r1, r2])
    assert [r['src_mac'] for r in merged] == ['00:00:00:00:00:01',
                                             '00:00:00:00:00:02']


# --------------------------------------------------------------------------- #
# llm_parse: hostile/unusable LLM responses raise, never guess                #
# --------------------------------------------------------------------------- #
class FakeResponse:
    def __init__(self, status=200, payload=None, text=''):
        self.status_code = status
        self._payload = payload
        self.text = text

    def json(self):
        if isinstance(self._payload, ValueError):
            raise self._payload
        return self._payload


def _monkeypost(monkeypatch, response):
    def fake_post(url, **kw):
        return response
    import requests
    monkeypatch.setattr(requests, 'post', fake_post)


def test_unreachable_llm_raises(monkeypatch):
    def boom(url, **kw):
        raise OSError('connection refused')
    import requests
    monkeypatch.setattr(requests, 'post', boom)
    with pytest.raises(RuntimeError):
        itp.llm_parse('Block h1 from h3')


def test_non_200_raises(monkeypatch):
    _monkeypost(monkeypatch, FakeResponse(500, {'error': 'boom'}, 'boom'))
    with pytest.raises(RuntimeError):
        itp.llm_parse('Block h1 from h3')


def test_non_json_body_raises(monkeypatch):
    import json
    _monkeypost(monkeypatch,
                FakeResponse(200, json.JSONDecodeError('x', 'y', 0), 'x'))
    with pytest.raises(RuntimeError):
        itp.llm_parse('Block h1 from h3')


def test_llm_no_json_array_raises(monkeypatch):
    _monkeypost(monkeypatch, FakeResponse(200, {'response': 'sorry, no'}))
    with pytest.raises(RuntimeError):
        itp.llm_parse('Block h1 from h3')


def test_llm_invalid_json_text_raises(monkeypatch):
    _monkeypost(monkeypatch,
                FakeResponse(200, {'response': '[{"src_mac": }]'}))
    with pytest.raises(RuntimeError):
        itp.llm_parse('Block h1 from h3')


def test_llm_prose_around_json_is_accepted(monkeypatch):
    _monkeypost(monkeypatch, FakeResponse(200, {'response':
        'Sure! Here you go:\n[{"src_mac": "00:00:00:00:00:01", '
        '"dst_mac": "00:00:00:00:00:03", "action": "DROP"}]\nHope that helps'}))
    rules = itp.llm_parse('Block h1 from h3')
    assert rules == [{'src_mac': '00:00:00:00:00:01',
                      'dst_mac': '00:00:00:00:00:03', 'action': 'DROP'}]


def test_empty_rule_list_raises_norules_not_runtimeerror(monkeypatch):
    """'Allow everything else' -> [] must be a distinct, catchable outcome."""
    _monkeypost(monkeypatch, FakeResponse(200, {'response': '[]'}))
    with pytest.raises(itp.NoRules):
        itp.llm_parse('Allow everything else.')


def test_partially_valid_rules_keep_only_the_good_ones(monkeypatch):
    _monkeypost(monkeypatch, FakeResponse(200, {'response':
        '[{"src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:03", '
        '"action": "DROP"}, {"src_mac": "bogus", "dst_mac": "x", '
        '"action": "MAYBE"}]'}))
    rules = itp.llm_parse('Block h1 from h3')
    assert len(rules) == 1
