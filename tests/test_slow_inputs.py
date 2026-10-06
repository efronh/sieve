# Inputs that used to take seconds or minutes because a pattern or a loop rescanned the text from every
# start (TH-11). Each now takes milliseconds; the bound is loose so a slow CI machine doesn't fail it.
import time

import pytest

from scripts.replay import tool_guard
from sieve.checks.code_payloads import CodePayloadLayer
from sieve.checks.prompt_injection import PromptInjectionLayer
from sieve.masking import credentials
from sieve.output import OutputGuard
from sieve.pipeline import Guardrail, mask

LIMIT = 2.0


def seconds(fn, *args):
    start = time.perf_counter()
    fn(*args)
    return time.perf_counter() - start


# Masking reads the whole message: a lookalike digit looked its word up again each time.
@pytest.mark.parametrize("unit", ["ı", "|", "o"])
def test_masking_a_long_word_of_lookalike_digits(unit):
    assert seconds(mask, unit * (200_000 // len(unit))) < LIMIT  # 8,000 "ı" took over 20 s in Guardrail.check


@pytest.mark.parametrize("unit", ["a-", "a.", "x+"])
def test_masking_a_long_run_of_scheme_characters(unit):
    assert seconds(credentials.URL_PASSWORD.findall, unit * 100_000) < LIMIT


# Tool arguments reach the code rules whole.
@pytest.mark.parametrize("text", ["й" * 50_000, "\n" * 200_000, "wget " * 40_000, "{" * 50_000,
                                  "{{" + "self " * 50_000],
                         ids=["word", "newlines", "wget", "braces", "keywords"])
def test_code_rules_on_a_long_argument(text):
    assert seconds(CodePayloadLayer().check, text) < LIMIT


def test_a_fake_system_line_check_on_many_blank_lines():
    assert seconds(PromptInjectionLayer().check, "\n" * 40_000) < LIMIT


@pytest.mark.parametrize("unit", ["<a ", "[", "[a](b ", "\n[", "[a](", "<img src=x "])
def test_output_links_on_unclosed_markup(unit):
    guard = OutputGuard("Sen bir banka asistanısın.", ["ornekbank.com.tr"])
    assert seconds(guard.check, unit * (400_000 // len(unit))) < LIMIT  # an answer can be long


@pytest.mark.parametrize("unit", ["ı", "|", "on", "system:", "<script"])
def test_a_long_message_end_to_end(unit):
    guard = Guardrail(cache_size=0, check_layers=[PromptInjectionLayer(), CodePayloadLayer()])
    assert seconds(guard.check, unit * (8_000 // len(unit))) < LIMIT


def test_a_long_tool_argument_end_to_end():
    tools = tool_guard(use_ml=False)
    attack = tools.check("sikayet_kaydi_ac", {"konu": "Kart", "aciklama": "admin'--"}, [], user_id="u1")
    assert "code_payloads" in [f.check for f in attack.findings]  # aciklama goes to the code rules
    assert seconds(tools.check, "sikayet_kaydi_ac", {"konu": "Kart", "aciklama": "й" * 50_000}, [], "u2") < LIMIT
