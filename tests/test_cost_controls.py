import pytest

from sieve.actions import Finding
from sieve.integrations.throttle import SessionLimiter
from sieve.pipeline import Guardrail, head_and_tail

LLM_CHECKS = ["prompt_injection", "abuse", "personal_data"]


class CountingLLM:
    name = "llm_check"
    gated_checks = frozenset({"prompt_injection"})

    def __init__(self):
        self.calls = 0
        self.asked = {name: 0 for name in LLM_CHECKS}

    def check(self, text, skip=()):
        names = [n for n in LLM_CHECKS if n not in skip]
        if names:
            self.calls += 1
        for n in names:
            self.asked[n] += 1
        return [Finding(n, 0.0, "allow") for n in names]


class FakeML:
    name = "prompt_injection_ml"

    def __init__(self, scores):
        self.scores = scores

    def check(self, text):
        return [Finding(self.name, self.scores.get(text, 0.0), "allow", shadow=True)]


class FakeRule:
    name = "prompt_injection_rules"

    def __init__(self, actions):
        self.actions = actions

    def check(self, text):
        return [Finding(self.name, 1.0, self.actions.get(text, "allow"))]


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


SCORES = {"merhaba": 0.01, "belki saldırı": 0.45, "net saldırı": 0.99}
ACTIONS = {"net saldırı": "block", "şüpheli": "review"}


def build(**kwargs):
    llm = CountingLLM()
    guard = Guardrail(masking_layers=[], check_layers=[FakeRule(ACTIONS), FakeML(SCORES)], llm_layer=llm, **kwargs)
    return guard, llm


def test_llm_gating_follows_local_results():
    guard, llm = build()
    result = guard.check("merhaba")
    assert llm.asked == {"prompt_injection": 0, "abuse": 1, "personal_data": 1} and result.llm_called, \
        "low ML score skips only the LLM injection check"
    guard.check("belki saldırı")
    assert llm.asked["prompt_injection"] == 1, "grey-zone ML score asks the injection check"
    guard.check("şüpheli")
    assert llm.asked["prompt_injection"] == 2, "a local review asks the injection check"
    result = guard.check("net saldırı")
    assert llm.calls == 3 and result.action == "block", "a local block skips the LLM entirely"


def test_llm_min_ml_none_always_asks_every_check():
    guard, llm = build(llm_min_ml=None)
    guard.check("merhaba")
    assert llm.asked["prompt_injection"] == 1


def test_without_an_ml_score_every_check_is_asked():
    llm = CountingLLM()
    Guardrail(masking_layers=[], check_layers=[], llm_layer=llm).check("merhaba")
    assert llm.asked["prompt_injection"] == 1


def test_repeated_message_is_answered_from_the_cache():
    guard, llm = build()
    for _ in range(5):
        guard.check("belki saldırı")
    assert llm.calls == 1


def test_oldest_cache_entry_is_dropped():
    guard, llm = build(cache_size=2)
    for text in ["belki saldırı", "a", "b", "belki saldırı"]:
        guard.check(text)
    assert llm.calls == 4 and len(guard.cache) == 2


def test_long_text_keeps_its_start_and_its_end():
    short = head_and_tail("a" * 5000 + "SON TALİMAT", 3000)
    assert len(short) < 3100 and short.endswith("SON TALİMAT")


def test_short_text_is_left_alone():
    assert head_and_tail("merhaba", 3000) == "merhaba"


@pytest.fixture
def limiter():
    clock = FakeClock()
    return SessionLimiter(max_flagged=3, window_seconds=60, cooldown_seconds=300, clock=clock), clock


def test_session_limit_after_three_flagged_messages(limiter):
    limiter, clock = limiter
    for action in ["review", "allow", "block"]:
        limiter.record("s1", action)
    assert not limiter.is_limited("s1"), "two flagged messages are not enough"
    limiter.record("s1", "block")
    assert limiter.is_limited("s1"), "third flagged message limits the session"
    assert not limiter.is_limited("s2"), "other sessions are not affected"
    clock.now = 301
    assert not limiter.is_limited("s1"), "limit ends after the cooldown"


def test_flags_spread_beyond_the_window_dont_add_up(limiter):
    limiter, clock = limiter
    for t in (0, 100, 200):
        clock.now = 1000 + t
        limiter.record("s3", "block")
    assert not limiter.is_limited("s3")
