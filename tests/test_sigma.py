import pytest

from rulehunter.sigma_lite import RuleError, parse_rule

EV = {"Image": "C:\\Windows\\System32\\certutil.exe",
      "CommandLine": "CertUtil -URLCache -f http://x/a.exe a.exe", "ParentImage": "C:\\cmd.exe"}


def rule(det: str) -> str:
    return "title: t\nlogsource: {product: windows}\ndetection:\n" + det


def test_contains_is_case_insensitive():
    r = parse_rule(rule("  sel:\n    CommandLine|contains: urlcache\n  condition: sel"))
    assert r.matches(EV)


def test_endswith_and_list_values_are_or():
    r = parse_rule(rule("  sel:\n    Image|endswith: ['\\nope.exe', '\\certutil.exe']\n  condition: sel"))
    assert r.matches(EV)


def test_contains_all():
    yes = parse_rule(rule("  sel:\n    CommandLine|contains|all: ['urlcache', 'http']\n  condition: sel"))
    no = parse_rule(rule("  sel:\n    CommandLine|contains|all: ['urlcache', 'ftp']\n  condition: sel"))
    assert yes.matches(EV) and not no.matches(EV)


def test_condition_and_not_parentheses():
    r = parse_rule(rule("  a:\n    Image|endswith: '\\certutil.exe'\n"
                        "  f:\n    ParentImage|contains: cmd\n"
                        "  condition: a and not (f)"))
    assert not r.matches(EV)


def test_one_of_and_all_of():
    det = ("  sel_a:\n    Image|contains: certutil\n  sel_b:\n    CommandLine|contains: zzz\n")
    assert parse_rule(rule(det + "  condition: 1 of sel_*")).matches(EV)
    assert not parse_rule(rule(det + "  condition: all of them")).matches(EV)


def test_regex_modifier():
    r = parse_rule(rule("  sel:\n    CommandLine|re: '-url\\w+\\s+-f'\n  condition: sel"))
    assert r.matches(EV)


@pytest.mark.parametrize("bad", [
    "not: [valid",                                                      # YAML error
    "title: t\nlogsource: {}\n",                                       # missing detection
    rule("  sel:\n    Hostname: x\n  condition: sel"),                 # unknown field
    rule("  sel:\n    Image|wildcard: x\n  condition: sel"),           # unknown modifier
    rule("  sel:\n    Image: x\n  condition: other"),                  # unknown selection
    rule("  sel:\n    Image|re: '" + "a" * 300 + "'\n  condition: sel"),  # regex too long
    rule("  sel:\n    Image|re: '('\n  condition: sel"),               # bad regex
    rule("  sel:\n    Image: x\n  condition: sel and"),                # dangling operator
    "x" * 5000,                                                        # too large
])
def test_validator_rejects(bad):
    with pytest.raises(RuleError):
        parse_rule(bad)
