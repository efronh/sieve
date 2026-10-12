from scripts.compare_families import chunks, matched_thresholds, summarize


def row(entry, family, sieve, score, group=None):
    return {"id": f"{entry}-{score}", "family": family, "group": group or f"{entry}-{score}", "entry": entry,
            "sieve": sieve, "score": score}


# The baseline gets as many false alarms as Sieve has at that entry point, no more.
def test_the_matched_threshold_allows_as_many_false_alarms_as_sieve_has():
    rows = [row("guardrail", "BEN", True, 0.9), row("guardrail", "BEN", False, 0.8), row("guardrail", "BEN", False, 0.1),
            row("document", "BEN", False, 0.7), row("document", "BEN", False, 0.2),
            row("guardrail", "PI-OVR", True, 0.85), row("document", "PI-IND", True, 0.75)]
    thresholds = matched_thresholds(rows)
    assert 0.8 < thresholds["guardrail"] < 0.85 and 0.7 < thresholds["document"] < 0.75
    _, families, false_alarms = summarize(rows)
    assert false_alarms["guardrail"]["matched"]["flagged"] == false_alarms["guardrail"]["sieve"]["flagged"] == 1
    assert false_alarms["document"]["matched"]["flagged"] == 0
    assert families["PI-OVR"]["matched"]["flagged"] == families["PI-IND"]["matched"]["flagged"] == 1
    assert families["PI-OVR"]["shipped"]["flagged"] == 1 and false_alarms["guardrail"]["shipped"]["flagged"] == 2


def test_long_text_is_read_in_overlapping_pieces():
    text = "a" * 3000
    pieces = chunks(text)
    assert all(len(p) <= 1200 for p in pieces) and "".join(p[:1000] for p in pieces[:-1]) + pieces[-1] == text
    assert chunks("kısa") == ["kısa"]


# With no benign records at an entry point there's nothing to match the threshold on.
def test_no_benign_records_no_matched_rate():
    thresholds, families, _ = summarize([row("chain", "TOOL-CHAIN", True, 0.9)])
    assert thresholds["chain"] is None and families["TOOL-CHAIN"]["matched"]["of"] == 0
