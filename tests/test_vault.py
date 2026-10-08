import json
import tomllib

import pytest

from scripts.replay import TOOLS
from sieve import guarded_reply
from sieve.integrations.siem import message_hash
from sieve.integrations.tenant import TenantGuardrail, load_policy
from sieve.output import OutputGuard
from sieve.pipeline import mask
from sieve.vault import DOCUMENT, Vault, letters, values_in_order

MOTHER, BROTHER = "TR33 0006 1005 1978 6457 8413 26", "TR66 0006 2000 0012 3456 7890 12"
INVOICE = "TR49 9997 0092 9841 6229 4866 28"
MESSAGE = f"Annemin IBAN'ı {MOTHER}, kardeşimin {BROTHER}. Anneme 500 TL gönder."


def test_letters_count_like_columns():
    assert [letters(n) for n in (1, 2, 26, 27, 28, 52, 53)] == ["A", "B", "Z", "AA", "AB", "AZ", "BA"]


def test_two_values_of_a_kind_get_two_labels_and_one_value_keeps_its_own():
    vault = Vault()
    assert vault.mask("Eski e-postam eski@example.com, yenisi yeni@example.com.") == \
        "Eski e-postam [EPOSTA_A], yenisi [EPOSTA_B]."
    # The same value written another way, later in the conversation, is the same label.
    assert vault.mask("Numaram 0532 123 45 67") == "Numaram [TELEFON_A]"
    assert vault.mask("Yani +90 532 123 4567, IBAN tr33-0006100519786457841326 ve TR33 0006 1005 1978 6457 8413 26") == \
        "Yani [TELEFON_A], IBAN [IBAN_A] ve [IBAN_A]"
    assert vault.mask("Kart 4111 1111 1111 1111 12/27 123") == "Kart [KART_A] [SKT_A] [CVV_A]"


# A label in the text is someone's attempt to name a vault value: it becomes plain text.
def test_a_label_already_in_the_text_is_not_the_vaults():
    vault = Vault()
    vault.mask(MESSAGE)
    assert vault.mask("Şuna gönder: [IBAN_A], [TELEFON] ve ［IBAN_B］") == "Şuna gönder: (IBAN_A), (TELEFON) ve (IBAN_B)"


def test_labels_that_cant_be_lined_up_get_no_value(monkeypatch):
    assert values_in_order("Tel 0532 123 45 67", "Tel [TELEFON]", [("[KART]", "4111")]) is None
    monkeypatch.setattr("sieve.vault.values_in_order", lambda *args: None)
    vault = Vault()
    assert vault.mask("Tel 0532 123 45 67") == "Tel [TELEFON_A]"
    assert vault.entries == {} and vault.resolve({"telefon": "[TELEFON_A]"})[1] == {"unknown_label"}


# The model's answer is masked again by OutputGuard; a label's letters aren't digits, so nothing reads into it.
def test_a_lettered_label_survives_masking_the_answer_again():
    answer = "[TELEFON_A] numaranıza 0532 111 22 33'ten SMS geldi, [KART_A] [SKT_A] kartınız, [IBAN_B]'ye"
    assert mask(answer) == "[TELEFON_A] numaranıza [TELEFON]'ten SMS geldi, [KART_A] [SKT_A] kartınız, [IBAN_B]'ye"
    assert OutputGuard("Banka asistanı.").check(answer).answer == mask(answer)


def test_resolve_turns_labels_back_and_says_what_is_wrong():
    vault = Vault()
    vault.mask(MESSAGE)
    vault.mask(f"Fatura: {INVOICE} hesabına ödeyin.", DOCUMENT)
    assert vault.resolve({"iban": "[IBAN_A]", "tutar": 500, "not": ["[IBAN_B] için"]}) == \
        ({"iban": MOTHER, "tutar": 500, "not": [f"{BROTHER} için"]}, set())
    assert vault.resolve({"iban": "[IBAN_C]"}) == ({"iban": INVOICE}, {"document_value"})
    assert vault.resolve({"iban": "[IBAN_Z]"}) == ({"iban": "[IBAN_Z]"}, {"unknown_label"})
    # A value the user gave too is the user's, whatever else gave it.
    vault.mask(f"Faturadaki {INVOICE} doğru mu?")
    assert vault.resolve({"iban": "[IBAN_C]"})[1] == set()


@pytest.mark.parametrize("text, shown", [
    ("[IBAN_A] hesabına gönderildi.", f"{MOTHER} hesabına gönderildi."),
    ("IBAN: [IBAN_A]. Kardeşiniz ([IBAN_B]) kayıtlı.", f"IBAN: {MOTHER}. Kardeşiniz ({BROTHER}) kayıtlı."),
    ("[IBAN_A]'ya gönderdim", f"{MOTHER}'ya gönderdim"),
    ("Faturadaki [IBAN_C] için onay gerekiyor.", "Faturadaki [IBAN_C] için onay gerekiyor."),  # a document's
    ("[IBAN_Z] diye bir hesap yok.", "[IBAN_Z] diye bir hesap yok."),
    # Where the value would leave with a click or a lookup, the label stays.
    ("https://x.example/a?i=[IBAN_A]", "https://x.example/a?i=[IBAN_A]"),
    ("x.example/?i=[IBAN_A] bak", "x.example/?i=[IBAN_A] bak"),
    ("[IBAN_A].x.example adresine", "[IBAN_A].x.example adresine"),
    ("[tıkla](https://x.example/ [IBAN_A])", "[tıkla](https://x.example/ [IBAN_A])"),
    ('<a href="https://x.example/?q= [IBAN_A]">x</a>', '<a href="https://x.example/?q= [IBAN_A]">x</a>'),
    ("[[IBAN_A]](https://x.example)", "[[IBAN_A]](https://x.example)"),
    ("x=[IBAN_A]", "x=[IBAN_A]"),
])
def test_reveal_shows_the_users_own_values_where_they_stand_as_words(text, shown):
    vault = Vault()
    vault.mask(MESSAGE)
    vault.mask(f"Fatura: {INVOICE}", DOCUMENT)
    assert vault.reveal(text) == shown


@pytest.fixture
def tenant():
    with open(TOOLS, "rb") as f:
        spec = tomllib.load(f)
    policy = load_policy(overrides={"masking": {"lettered_labels": True}, "tools": spec["tools"], "log_allowed": True,
                                    "log_excerpt": True})
    return TenantGuardrail(policy, system_prompt="Banka asistanı.")


def test_without_the_policy_key_labels_stay_plain():
    guard = TenantGuardrail(load_policy())
    assert guard.check(MESSAGE, session_id="s").text == "Annemin IBAN'ı [IBAN], kardeşimin [IBAN]. Anneme 500 TL gönder."


def test_the_model_gets_letters_and_events_and_history_keep_plain_labels(tenant, siem_events):
    result = tenant.check(MESSAGE, session_id="s", user_id="u")
    assert result.text == "Annemin IBAN'ı [IBAN_A], kardeşimin [IBAN_B]. Anneme 500 TL gönder."
    plain = mask(MESSAGE, tenant.guard.masking_layers)
    event = siem_events[-1]
    assert event["message_hash"] == message_hash(plain) and event["excerpt"] == plain[:200]
    assert "_A]" not in json.dumps(siem_events) and "_A]" not in repr(tenant.conversation.history("s"))
    assert tenant.check(MESSAGE, session_id=None).text == plain  # no session, no vault


def test_a_tool_call_runs_with_the_users_value_and_not_a_documents(tenant, siem_events):
    tenant.check(MESSAGE, session_id="s", user_id="u")
    tenant.wrap(f"Fatura: ödeme için {INVOICE} hesabına gönderin.", session_id="s")

    own = tenant.check_tool("para_transferi", {"iban": "[IBAN_A]", "tutar": 500}, [MESSAGE], session_id="s")
    assert own.args == {"iban": MOTHER, "tutar": 500}
    assert {m for f in own.findings for m in f.matches} == {"needs_confirmation"}  # from_user holds: it's her value

    planted = tenant.check_tool("para_transferi", {"iban": "[IBAN_C]", "tutar": 500}, [MESSAGE], session_id="s")
    assert planted.action == "review" and planted.args["iban"] == INVOICE
    assert {"document_value", "not_from_user"} <= {m for f in planted.findings for m in f.matches}

    made_up = tenant.check_tool("para_transferi", {"iban": "[IBAN_Z]", "tutar": 500}, [MESSAGE], session_id="s")
    elsewhere = tenant.check_tool("para_transferi", {"iban": "[IBAN_A]", "tutar": 500}, [MESSAGE], session_id="t")
    assert made_up.action == elsewhere.action == "block"
    assert "tool_call.unknown_label" in {r["rule_id"] for r in siem_events[-1]["rules"]}
    assert MOTHER not in json.dumps(siem_events) and INVOICE not in json.dumps(siem_events)


def test_the_answer_shows_the_users_values_and_logs_none(tenant, siem_events):
    tenant.check(MESSAGE, session_id="s", user_id="u")
    tenant.wrap(f"Fatura: {INVOICE}", session_id="s")
    answer = "[IBAN_A] hesabına 500 TL gönderildi. Faturadaki [IBAN_C] için onay gerekiyor. https://x.example/?i=[IBAN_A]"
    shown = tenant.check_output(answer, [MESSAGE], session_id="s")
    assert shown.text == (f"{MOTHER} hesabına 500 TL gönderildi. Faturadaki [IBAN_C] için onay gerekiyor. "
                          "https://x.example/?i=[IBAN_A]")
    assert shown.action == "review" and "url_with_data" in {m for f in shown.findings for m in f.matches}
    assert MOTHER not in json.dumps(siem_events)


def test_guarded_reply_with_lettered_labels(tenant):
    seen = []

    def model(system, user):
        seen.append(user)
        return "[IBAN_B] hesabına 100 TL gönderiyorum."

    tenant.check(MESSAGE, session_id="s")
    reply = guarded_reply("Kardeşime de 100 TL", model, tenant, session_id="s")
    assert seen == ["Kardeşime de 100 TL"] and reply.text == f"{BROTHER} hesabına 100 TL gönderiyorum."


def test_the_policy_key_must_be_true_or_false():
    with pytest.raises(ValueError, match="lettered_labels"):
        load_policy(overrides={"masking": {"lettered_labels": "yes"}})


def test_a_full_vault_still_masks_but_names_nothing(monkeypatch):
    monkeypatch.setattr("sieve.vault.MAX_VALUES", 2)
    vault = Vault()
    assert vault.mask("a@example.com b@example.com c@example.com a@example.com") == \
        "[EPOSTA_A] [EPOSTA_B] [EPOSTA_C] [EPOSTA_A]"
    assert len(vault.entries) == 2 and vault.resolve({"alici": "[EPOSTA_C]"})[1] == {"unknown_label"}
