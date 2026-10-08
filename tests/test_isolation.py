# Who sees what (THREAT_MODEL.md, "Who sees what"). The checks read the message as it came, but what they read
# leaves them only through their result; the model gets the masked message under a system prompt that's the same
# for every request; events and session memory hold masked text only. Run over the whole attack corpus, through
# every entry point, as an app would call them.
import json
import logging
import re
import sys
import tomllib
from types import SimpleNamespace

import pytest
from conftest import _Capture

from scripts.evaluate_masking import load as load_pii
from scripts.replay import SYSTEM_PROMPT, TOOLS
from scripts.replay import load as load_corpus
from sieve import Guardrail, guarded_reply
from sieve.integrations.siem import to_cef
from sieve.integrations.tenant import TenantGuardrail, load_policy
from sieve.output import SAFE_REPLY
from sieve.reply import BLOCKED_MESSAGE

# A word no check knows, added to every text the corpus sends in. It may come out only where the masked text is
# meant to: the prompt, the answer, the app's own copy of a flagged document part, an event's excerpt.
TAINT = "Zümrütkaplumbağa"
TAINTED = re.compile(r"z[uü]mr[uü]tkaplumba[gğ]a", re.IGNORECASE)  # also after the checks' ASCII folding
ANSWER = "Size nasıl yardımcı olabilirim?"

# Audit events (docs.python.org/3/library/audit_events.html) that read or write outside the process.
IO_EVENTS = ("open", "os.", "shutil.", "socket.", "subprocess.", "urllib.", "http.", "ftplib.", "smtplib.",
             "webbrowser.", "ctypes.", "sqlite3.")
watch = SimpleNamespace(on=False, seen=[])


# An audit hook can't be removed, so it stays for the session and records only while watch.on.
def record_io(event, args):
    if watch.on and event.startswith(IO_EVENTS):
        watch.seen.append((event, str(args)[:80]))


sys.addaudithook(record_io)


def tainted(value):
    if isinstance(value, str):
        return f"{value} {TAINT}"
    if isinstance(value, dict):
        return {k: tainted(v) for k, v in value.items()}
    if isinstance(value, list):
        return [tainted(v) for v in value]
    return value


# A JSON document stays JSON, so its values are still read one by one.
def tainted_document(text):
    try:
        return json.dumps(tainted(json.loads(text)), ensure_ascii=False)
    except ValueError:
        return tainted(text)


def taint(record):
    record = dict(record)
    for key in ("turns", "user_data"):
        if key in record:
            record[key] = tainted(record[key])
    if "text" in record:
        record["text"] = tainted_document(record["text"]) if record["carrier"] in ("document", "tool_chain") \
            else tainted(record["text"])
    if "calls" in record:
        record["calls"] = [dict(c, args=tainted(c["args"])) for c in record["calls"]]
    return record


def corpus_tenant(**overrides):
    with open(TOOLS, "rb") as f:
        spec = tomllib.load(f)
    policy = load_policy(overrides={"tools": spec["tools"], "url_check": {"allowed_hosts": spec["allowed_hosts"]},
                                    "log_allowed": True, **overrides})
    return TenantGuardrail(policy, system_prompt=SYSTEM_PROMPT.read_text(encoding="utf-8"))


class Model:
    def __init__(self, answer=ANSWER):
        self.answer, self.calls = answer, []

    def __call__(self, system, user):
        self.calls.append((system, user))
        return self.answer


# Every check the record's carrier goes through, the way an app calls them: messages and answers through
# guarded_reply, documents and tool calls on their own. Returns what came back and what the model was given.
def send(tenant, record):
    who = {"session_id": record["id"], "user_id": record["id"]}
    carrier, results, prompts = record["carrier"], [], []

    def reply(message, model, **args):
        result = guarded_reply(message, model, tenant, **who, **args)
        results.append(result)
        if result.model_called:
            prompts.append((message, *model.calls[-1]))  # (message, system, user)

    if carrier == "plain_text":
        reply(record["text"], Model())
    elif carrier == "conversation":
        model = Model()
        for turn in record["turns"]:
            reply(turn, model)
    elif carrier == "model_answer":  # the user's last message, then the record's text as the answer
        reply(record["user_data"][-1], Model(record["text"]), user_data=record["user_data"])
    if carrier in ("document", "tool_chain"):
        results.append(tenant.check_document(record["text"], **who))
    for call in record.get("calls", ()):
        results.append(tenant.check_tool(call["tool"], call["args"], record["user_data"], **who))
    return results, prompts


@pytest.fixture(scope="module")
def corpus_run():
    records = [taint(r) for r in load_corpus()]
    capture, logger = _Capture(), logging.getLogger("sieve.siem")
    saved = logger.handlers, logger.level
    logger.handlers, logger.level = [capture], logging.INFO
    try:
        warm = corpus_tenant()
        for r in records:  # imports, codecs and models some checks load on first use
            send(warm, r)
        capture.events.clear()

        tenant = corpus_tenant()  # an empty cache, so every check runs again
        results, prompts = [], []
        watch.seen.clear()
        watch.on = True
        try:
            for r in records:
                got, given = send(tenant, r)
                results += got
                prompts += given
        finally:
            watch.on = False
        return SimpleNamespace(tenant=tenant, results=results, prompts=prompts, events=list(capture.events),
                               io=list(watch.seen))
    finally:
        logger.handlers, logger.level = saved


def test_the_whole_corpus_went_through_every_entry_point(corpus_run):
    directions = {e["direction"] for e in corpus_run.events}
    assert directions == {"input", "document", "tool", "output"}
    assert len(corpus_run.prompts) > 300 and {r.action for r in corpus_run.results} == {"allow", "review", "block"}


# The checks read the raw message, but nothing they read can leave the process while they run: no file, socket
# or subprocess. Events go out through logging, to whatever handler the app sets up (here, a list).
def test_no_check_reads_or_writes_outside_the_process(corpus_run):
    assert corpus_run.io == []


def findings_of(result):
    if hasattr(result, "model_called"):  # a Reply: the input check, and the answer check if the model was asked
        return result.checked.findings + (result.shown.findings if result.shown else [])
    return result.findings


# A finding names rules and counts; it never quotes the text. So a result handed to the app, or an event,
# can't carry the message by way of a finding.
def test_findings_never_quote_the_text(corpus_run):
    quoted = [f for r in corpus_run.results for f in findings_of(r) if TAINTED.search(repr(f))]
    assert quoted == []
    reasons = [reason for r in corpus_run.results for reason in getattr(r, "reasons", ())]
    assert reasons and not any(TAINTED.search(reason) for reason in reasons)


def test_events_carry_no_text_without_an_excerpt(corpus_run):
    assert corpus_run.events and not corpus_run.tenant.policy.log_excerpt
    leaked = [e["event_id"] for e in corpus_run.events
              if TAINTED.search(json.dumps(e, ensure_ascii=False)) or TAINTED.search(to_cef(e))]
    assert leaked == []


# The model's prompt is a function of the message alone: what a guard with no checks at all would give it,
# under the same system prompt every time. Nothing a check found, no score, no rule, no decision gets in, so a
# model that repeats its context can't tell the user what the guard saw.
def test_the_model_gets_the_masked_message_and_nothing_the_checks_found(corpus_run):
    tenant = corpus_run.tenant
    no_checks = Guardrail(masking_layers=tenant.guard.masking_layers, check_layers=[], cache_size=0)
    differs = [message for message, _, user in corpus_run.prompts if user != no_checks.check(message).text]
    assert differs == []
    assert {system for _, system, _ in corpus_run.prompts} == {tenant.system_prompt}
    operator_prompt = SYSTEM_PROMPT.read_text(encoding="utf-8")
    assert tenant.system_prompt.startswith(operator_prompt.strip()) and tenant.output.canary in tenant.system_prompt


# The user learns the decision, not the reason: one fixed message for a blocked message, one for a blocked answer.
def test_a_blocked_user_sees_a_fixed_message(corpus_run):
    blocked = [r for r in corpus_run.results if hasattr(r, "model_called") and r.action == "block"]
    assert blocked and {r.text for r in blocked if not r.model_called} == {BLOCKED_MESSAGE}
    assert {r.text for r in blocked if r.model_called} <= {SAFE_REPLY}


TC, PHONE = "10000000146", "0532 111 22 33"


# Personal data the masking catches in a message must not reach an event by another way, in any direction, even
# with excerpts on; the user and session IDs (here a TC number and a phone number) go in keyed. Session memory
# keeps masked text too. A value the masking misses in a message (corpus/pii/baseline.json) isn't counted here:
# that's a masking miss, and it reaches the model as well.
def test_no_personal_data_the_masking_catches_reaches_an_event_or_session_memory(siem_events):
    tenant = corpus_tenant(log_excerpt=True)
    no_checks = Guardrail(masking_layers=tenant.guard.masking_layers, check_layers=[], cache_size=0)
    caught = []
    for record in load_pii():
        values = [p["value"] for p in record["pii"] if p["value"] not in no_checks.check(record["text"]).text]
        if not values:
            continue
        caught += values
        siem_events.clear()
        who = {"session_id": PHONE, "user_id": TC}
        tenant.check(record["text"], **who)
        tenant.check_document(record["text"], **who)
        tenant.check_tool("sikayet_kaydi_ac", {"konu": "Talep", "aciklama": record["text"]}, **who)
        tenant.check_output(record["text"], user_data=[], **who)
        assert {e["direction"] for e in siem_events} == {"input", "document", "tool", "output"}
        for event in siem_events:
            logged = json.dumps(event, ensure_ascii=False) + to_cef(event)
            # Three digits (a CVV) turn up in hashes and timings by chance: short values count in the text only.
            text = " ".join([event["excerpt"] or ""] + [r["detail"] or "" for r in event["rules"]])
            leaked = [v for v in values + [TC, PHONE] if v in (logged if len(v) >= 6 else text)]
            assert not leaked, (record["id"], event["direction"], leaked)
        # The split-attack window keeps the last few messages of the session.
        history = repr(tenant.conversation.history(PHONE))
        assert not [v for v in values if v in history], (record["id"], "session memory")
    assert len(caught) > 100

    cache = repr(tenant.guard.cache)
    assert "[TC_KIMLIK]" in cache and not [v for v in caught if len(v) >= 6 and v in cache]
