# Sieve's versions measured with one yardstick: each commit's sieve/ package and policies, today's scripts, corpus,
# held-out set and model. Detection (precision, recall, false alarms, misses) per entry point and on the sealed set,
# what the bypass suite gets through, latency (median, p95, p99) and what each run costs the machine (CPU time, peak
# memory, a cold start). A version is run in a copy of its own files, in processes of its own.
#   python -m scripts.benchmark_versions                         # main and every commit since, TF-IDF alone (as CI)
#   python -m scripts.benchmark_versions main HEAD --cascade     # chosen refs, BERTurk on
# Writes results/versions.json and .md (versions_cascade.* with --cascade). The sealed set gives counts only, as
# replay --holdout does. The numbers are the machine's: compare versions within one file, not across machines.
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from sieve.paths import RESULTS, ROOT


def outputs(cascade):
    name = "versions_cascade" if cascade else "versions"
    return RESULTS / f"{name}.json", RESULTS / f"{name}.md"


SHARED = ["corpus", "data", "holdout", "models", "scripts"]  # the yardstick: today's, whatever the version
FROM_VERSION = ["sieve", "policies", "pyproject.toml"]
STEPS = {
    "replay": ["scripts.replay", "--split", "test"],
    "holdout": ["scripts.replay", "--holdout"],
    "bypass": ["scripts.bypass_suite"],
    "latency": ["scripts.benchmark_latency"],
    "startup": ["scripts.benchmark_versions", "--probe"],
}
ENTRIES = ["guardrail", "document", "tool", "output", "conversation"]


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


def default_refs():
    base = git("merge-base", "main", "HEAD")
    return [base] + git("rev-list", "--reverse", f"{base}..HEAD").split()


def checkout(ref, into):
    archive = subprocess.run(["git", "archive", ref, *FROM_VERSION], cwd=ROOT, capture_output=True, check=True).stdout
    subprocess.run(["tar", "-x", "-C", str(into)], input=archive, check=True)
    for name in SHARED:
        if name == "scripts":
            shutil.copytree(ROOT / name, into / name, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            (into / name).symlink_to(ROOT / name)
    (into / "results").mkdir()


# (exit code, seconds, CPU seconds, peak memory in MB, output) of one step, in a process of its own.
def run_step(cwd, args, env):
    start = time.perf_counter()
    process = subprocess.Popen([sys.executable, "-m", *args], cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    output = process.stdout.read()
    _, status, usage = os.wait4(process.pid, 0)
    process.returncode = os.waitstatus_to_exitcode(status)
    peak = usage.ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024)  # bytes on macOS, KB on Linux
    return process.returncode, time.perf_counter() - start, usage.ru_utime + usage.ru_stime, peak, output


def read(path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def detection(summary):
    keys = ("attacks", "flagged", "benign", "false_alarms", "recall", "precision", "fpr", "fnr", "f1")
    return {k: summary.get(k) for k in keys}


def measure(ref, cascade):
    with tempfile.TemporaryDirectory(prefix="sieve-version-") as tmp:
        tmp = Path(tmp)
        checkout(ref, tmp)
        env = dict(os.environ, PYTHONPATH=str(tmp), SIEVE_CASCADE="1" if cascade else "0")
        steps = {}
        for name, args in STEPS.items():
            code, seconds, cpu, peak, output = run_step(tmp, args, env)
            steps[name] = {"exit": code, "seconds": round(seconds, 2), "cpu_seconds": round(cpu, 2),
                           "peak_mb": round(peak, 1)}
            if name == "startup":
                steps[name] |= json.loads(output.strip().splitlines()[-1])
        replay, holdout = read(tmp / "results" / "replay.json"), read(tmp / "results" / "holdout.json")
        bypass, latency = read(tmp / "results" / "bypass.json"), read(tmp / "results" / "latency.json")
    families = {}
    for key, counts in (bypass or {}).get("summary", {}).items():
        family = families.setdefault(key.split("/")[0], {"total": 0, "lost": 0})
        family["total"] += sum(counts.values())
        family["lost"] += counts.get("lost", 0)
    return {
        "ref": ref,
        "commit": git("rev-parse", "--short", ref),
        "subject": git("log", "-1", "--format=%s", ref),
        "entries": {e: detection(s) for e, s in (replay or {}).get("summary", {}).items()},
        "holdout": {k: detection(v) for k, v in (holdout or {}).get("summary", {}).items()},
        "bypass": families,
        "latency": {k: v["total"] for k, v in (latency or {}).get("summaries", {}).items()},
        "steps": steps,
    }


# Run inside a version's copy: how long importing it and building a guard takes, and the memory it holds then.
def probe():
    import resource

    start = time.perf_counter()
    from sieve.integrations.tenant import TenantGuardrail, load_policy

    imported = time.perf_counter()
    guard = TenantGuardrail(load_policy())
    built = time.perf_counter()
    guard.check("Kartım ne zaman gelir?")
    first = time.perf_counter()
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024)
    print(json.dumps({"import_s": round(imported - start, 3), "build_s": round(built - imported, 3),
                      "first_check_ms": round(1000 * (first - built), 2), "ready_mb": round(rss, 1)}))


def pct(x):
    return "–" if x is None else f"{100 * x:.0f}%"


def ms(x):
    return "–" if x is None else f"{x:.2f}" if x < 10 else f"{x:.0f}"


def markdown(rows, cascade):
    ml = "TF-IDF → BERTurk" if cascade else "TF-IDF alone, as in CI"
    lines = [f"# Sieve versions, one yardstick ({ml})", "",
             "Each version's `sieve/` and `policies/`, today's scripts, corpus, sealed set and model. "
             "Recall / false-alarm rate on the corpus's test split; the sealed set in counts only.", "",
             "## Detection", "",
             "| Version | " + " | ".join(ENTRIES) + " | Sealed set: recall / FPR / F1 | `deepset_tr` recall |",
             "|---|" + "---|" * (len(ENTRIES) + 2)]
    for r in rows:
        cells = []
        for e in ENTRIES:
            d = r["entries"].get(e)
            cells.append("–" if not d else f"{pct(d['recall'])} / {pct(d['fpr'])}" if d["benign"] else pct(d["recall"]))
        h, deep = r["holdout"].get("all"), r["holdout"].get("deepset_tr")
        sealed = "–" if not h else f"{pct(h['recall'])} / {pct(h['fpr'])} / {h['f1']:.2f}"
        lines.append(f"| `{r['commit']}` {r['subject'][:48]} | " + " | ".join(cells)
                     + f" | {sealed} | {pct(deep['recall']) if deep else '–'} |")
    families = list(dict.fromkeys(f for r in rows for f in r["bypass"]))
    lines += ["", "## Bypass suite: rewrites let through", "",
              "| Version | " + " | ".join(families) + " |", "|---|" + "---|" * len(families)]
    for r in rows:
        cells = [f"{r['bypass'][f]['lost']} / {r['bypass'][f]['total']}" if f in r["bypass"] else "–" for f in families]
        lines.append(f"| `{r['commit']}` | " + " | ".join(cells) + " |")
    workloads = list(dict.fromkeys(w for r in rows for w in r["latency"]))
    lines += ["", "## Latency (ms, median / p95) and cost", "",
              "| Version | " + " | ".join(workloads) + " | Cold start (s) | Memory ready (MB) | Peak memory (MB) | CPU (s) |",
              "|---|" + "---|" * (len(workloads) + 4)]
    for r in rows:
        cells = [f"{ms(r['latency'][w]['median'])} / {ms(r['latency'][w]['p95'])}" if w in r["latency"] else "–"
                 for w in workloads]
        s = r["steps"]
        start = s["startup"]
        cold = start.get("import_s", 0) + start.get("build_s", 0)
        lines.append(f"| `{r['commit']}` | " + " | ".join(cells)
                     + f" | {cold:.2f} | {start.get('ready_mb', '–')} | {max(x['peak_mb'] for x in s.values())} "
                     + f"| {sum(x['cpu_seconds'] for x in s.values()):.0f} |")
    lines += ["", "Peak memory is the largest of the runs (replay, sealed set, bypass suite, latency, start); CPU is "
              "their sum. A dash: that version's run didn't produce the number."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(prog="python -m scripts.benchmark_versions")
    parser.add_argument("refs", nargs="*", help="git refs, oldest first; default: main's merge base and every commit since")
    parser.add_argument("--cascade", action="store_true", help="BERTurk on (slower; needs sentence-transformers)")
    parser.add_argument("--probe", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.probe:
        return probe()
    rows = []
    for ref in args.refs or default_refs():
        print(f"measuring {ref} ...", flush=True)
        rows.append(measure(ref, args.cascade))
    RESULTS.mkdir(exist_ok=True)
    out_json, out_md = outputs(args.cascade)
    out_json.write_text(json.dumps({"cascade": args.cascade, "versions": rows}, ensure_ascii=False, indent=1) + "\n",
                        encoding="utf-8")
    out_md.write_text(markdown(rows, args.cascade), encoding="utf-8")
    print(out_md.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
