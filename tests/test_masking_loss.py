# What masking takes that it shouldn't (scripts/evaluate_masking_loss.py). Every piece masked in benign text has a
# verdict in corpus/pii/review/benign_masks.jsonl, and a wrong one that's still masked is one listed here, with why.
import pytest

from scripts.evaluate_masking_loss import benign_texts, load_review, masked_in_benign, merged_values, verdict

ACCOUNT = "an account number: personal data, masked under the phone label"
KNOWN_WRONG = {
    ("[TELEFON]", "0312 555 12 34"): "the bank's own number in an answer; masking can't tell whose number it is",
    ("[TELEFON]", "5009905162"): ACCOUNT,
    ("[TELEFON]", "5415126883"): ACCOUNT,
    ("[TELEFON]", "5551234567"): ACCOUNT,
    ("[TELEFON]", "5566778899"): ACCOUNT,
    ("[TELEFON]", "5239128490"): ACCOUNT,
}


@pytest.fixture(scope="module")
def found():
    texts, _ = benign_texts()
    return masked_in_benign(texts)


def test_every_piece_masked_in_benign_text_has_a_verdict(found):
    review = load_review()
    assert len(found) > 100
    assert sorted({(p["label"], p["value"]) for p in found} - set(review)) == []


def test_no_piece_is_masked_wrongly_unless_known(found):
    review = load_review()
    wrong = {(p["label"], p["value"]) for p in found if verdict(review, p) != "right"}
    assert wrong - set(KNOWN_WRONG) == set()


def test_merged_values_count_different_values_under_one_label():
    rows, _ = merged_values({"x": [
        ["Eski e-postam eski@example.com.", "Yenisi yeni@example.com."],  # two addresses, both [EPOSTA]
        ["Numaram 0532 111 22 33.", "Yani +90 532 111 2233."],          # one number written twice
        ["Merhaba."],
    ]})
    assert rows["x"] == {"conversations": 3, "with_mask": 2, "merged": 1}
