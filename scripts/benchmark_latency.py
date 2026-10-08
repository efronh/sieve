# How long each stage of a check takes, and what the checks add to a request (TH-11, README).
#   python -m scripts.benchmark_latency                    # default setup: TF-IDF, BERTurk when TF-IDF is unsure
#   SIEVE_CASCADE=0 python -m scripts.benchmark_latency    # TF-IDF alone, as in CI
# Everything goes through a TenantGuardrail with the default policy, as an app would call it: the 1,500
# customer-service messages in their conversations (normal traffic), the corpus's attack messages, the ticket
# exports as documents, the corpus's tool calls and model answers. Prints median, p95 and p99 per stage and in
# total, and what the input and output checks add to a request at a few model latencies. Writes
# results/latency.json.
import argparse
import json
import logging
import platform
import statistics
import time
import tomllib

from scripts.evaluate_documents import ticket_exports
from scripts.replay import CANARY, SYSTEM_PROMPT, TOOLS, benign_conversations, load
from sieve.integrations.tenant import TenantGuardrail, load_policy
from sieve.ml.injection import MLInjectionLayer
from sieve.paths import RESULTS, ROOT

OUT = RESULTS / "latency.json"
# Typical times for a hosted model to answer, to put the checks' time next to: a short answer from a small
# model, a usual one, a long one.
MODEL_MS = (500, 1500, 4000)


def percentile(values, p):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(p / 100 * (len(ordered) - 1)))]


# rows: [(total ms, {stage: ms}, BERTurk ran)]
def summary(rows):
    totals = [total for total, _, _ in rows]
    stages = sorted({stage for _, timings, _ in rows for stage in timings})
    spent = sum(totals) or 1
    return {
        "count": len(rows),
        "total": {"median": statistics.median(totals), "p95": percentile(totals, 95), "p99": percentile(totals, 99),
                  "mean": statistics.mean(totals)},
        "stages": {stage: {"median": statistics.median([t.get(stage, 0.0) for _, t, _ in rows]),
                           "p95": percentile([t.get(stage, 0.0) for _, t, _ in rows], 95),
                           "share": sum(t.get(stage, 0.0) for _, t, _ in rows) / spent} for stage in stages},
        "berturk_share": sum(bert for _, _, bert in rows) / max(len(rows), 1),
    }


def timed(check):
    start = time.perf_counter()
    result = check()
    total = (time.perf_counter() - start) * 1000
    bert = any(getattr(f, "level", None) == "tfidf+bert" for f in result.findings)
    return total, result.timings, bert


def run():
    with open(TOOLS, "rb") as f:
        tools = tomllib.load(f)
    policy = load_policy(overrides={"tools": tools["tools"], "url_check": {"allowed_hosts": tools["allowed_hosts"]}})
    tenant = TenantGuardrail(policy, system_prompt=SYSTEM_PROMPT.read_text(encoding="utf-8"), canary=CANARY)
    logging.getLogger("sieve.siem").addHandler(logging.NullHandler())
    ml = next((layer for layer in tenant.guard.check_layers if isinstance(layer, MLInjectionLayer)), None)
    if ml is not None and ml.cascade:
        ml.stage.predict(["Merhaba"])  # BERTurk loads on first use; keep that out of the timings

    records = load()
    results = {}
    results["normal messages"] = [timed(lambda: tenant.check(turn, session_id=f"c{i}"))
                                  for i, turns in enumerate(benign_conversations()) for turn in turns]
    results["attack messages"] = [timed(lambda: tenant.check(r["text"], session_id=r["id"])) for r in records
                                  if r["carrier"] == "plain_text" and r["family"] != "BEN"]
    results["documents"] = [timed(lambda: tenant.check_document("\n\n".join(parts))) for parts in ticket_exports()]
    results["tool calls"] = [timed(lambda: tenant.check_tool(c["tool"], c["args"], r["user_data"], user_id=r["id"]))
                             for r in records if r["carrier"] == "tool_call" for c in r["calls"]]
    results["answers"] = [timed(lambda: tenant.check_output(r["text"], r["user_data"])) for r in records
                          if r["carrier"] == "model_answer"]
    return {name: summary(rows) for name, rows in results.items()}, ml


def report(summaries):
    for name, s in summaries.items():
        t = s["total"]
        bert = f", BERTurk ran for {s['berturk_share']:.0%}" if s["berturk_share"] else ""
        print(f"\n{name} ({s['count']}): median {t['median']:.2f} ms, p95 {t['p95']:.2f}, p99 {t['p99']:.2f}, "
              f"mean {t['mean']:.2f}{bert}")
        print(f"  {'stage':24} {'median':>8} {'p95':>8} {'share':>6}")
        for stage, v in sorted(s["stages"].items(), key=lambda kv: -kv[1]["share"]):
            print(f"  {stage:24} {v['median']:8.3f} {v['p95']:8.3f} {v['share']:6.0%}")

    # One request: a normal message in, an answer out.
    checks = summaries["normal messages"]["total"]["median"] + summaries["answers"]["total"]["median"]
    checks_p95 = summaries["normal messages"]["total"]["p95"] + summaries["answers"]["total"]["p95"]
    print(f"\na request (normal message in, answer out): checks add {checks:.1f} ms at the median, "
          f"{checks_p95:.1f} ms at p95")
    for model in MODEL_MS:
        print(f"  with a model taking {model:>5} ms: {checks / (model + checks):.1%} of the request "
              f"({checks_p95 / (model + checks_p95):.1%} at p95)")
    return checks, checks_p95


def main():
    argparse.ArgumentParser().parse_args()
    summaries, ml = run()
    checks, checks_p95 = report(summaries)
    setup = {"cascade": bool(ml and ml.cascade), "machine": platform.machine(), "processor": platform.processor(),
             "python": platform.python_version()}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"setup": setup, "summaries": summaries,
                   "request": {"median_ms": checks, "p95_ms": checks_p95,
                               "share_of_request": {str(m): checks / (m + checks) for m in MODEL_MS}}},
                  f, ensure_ascii=False, indent=1, default=float)
        f.write("\n")
    print(f"\nwrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
