import pytest

from malwarescan.engine import yara_lite as y


def _one(src: str) -> y.Rule:
    rules = y.compile_rules(src)
    assert len(rules) == 1
    return rules[0]


def test_text_string_match_and_condition():
    r = _one('rule A { strings: $a = "needle" $b = "pin" condition: $a and $b }')
    assert r.match(b"a needle and a pin") == ["$a", "$b"]
    assert r.match(b"only needle here") == []


def test_nocase_and_fullword():
    r = _one('rule B { strings: $a = "exec" nocase fullword condition: any of them }')
    assert r.match(b"EXEC now")
    assert r.match(b"preexecute") == []  # not a full word


def test_hex_string_with_wildcards():
    r = _one("rule C { strings: $h = { 4D 5A ?? 00 } condition: $h }")
    assert r.match(bytes([0x4D, 0x5A, 0x99, 0x00]))
    assert not r.match(bytes([0x4D, 0x5B, 0x00, 0x00]))


def test_regex_string():
    r = _one(r'rule D { strings: $r = /ab+c/ condition: $r }')
    assert r.match(b"xxabbbcxx")


def test_count_quantifier_and_set_of():
    r = _one('rule E { strings: $a = "one" $b = "two" $c = "three" condition: 2 of ($a,$b,$c) }')
    assert r.match(b"one two") and not r.match(b"one only")
    r2 = _one('rule F { strings: $x1 = "p" $x2 = "q" $y = "r" condition: all of ($x*) }')
    assert r2.match(b"p q") and not r2.match(b"p")


def test_filesize_units():
    r = _one('rule G { strings: $a = "x" condition: $a and filesize < 10KB }')
    assert r.match(b"x")
    assert not r.match(b"x" * 20_000)


def test_unsupported_construct_is_rejected_not_ignored():
    with pytest.raises(y.RuleSyntaxError):
        y.compile_rules("rule broken { strings: condition: oops }")


def test_meta_parsed():
    r = _one('rule H { meta: severity = "high" strings: $a = "z" condition: $a }')
    assert r.meta["severity"] == "high"
