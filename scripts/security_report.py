# One security report from what the CI checks wrote to results/: the attack replay, the bypass suite, known
# vulnerabilities in the locked dependencies (pip-audit), the code scan (bandit), secrets in the git history (gitleaks)
# and the slow-pattern fuzzer. A check whose output is missing is reported as not run, never as clean.
#   python -m scripts.security_report               # results/security_report.md, and the CI job's summary
#   python -m scripts.security_report --strict      # exits 1 if any check failed or didn't run
import argparse
import json
import os
import sys

from sieve.paths import RESULTS, ROOT

REPORT = RESULTS / "security_report.md"
PASS, FAIL, MISSING = "pass", "FAIL", "not run"


def load(name):
    path = RESULTS / name
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if name.endswith(".json") else text


def percent(x):
    return "n/a" if x is None else f"{100 * x:.0f}%"


def replay_section(replay):
    if replay is None:
        return MISSING, "", ["The attack replay didn't run (`python -m scripts.replay --baseline check`)."]
    lines = ["| Entry point | Attacks flagged | Recall | Normal flagged | Precision | F1 | p95 ms |",
             "|---|---|---|---|---|---|---|"]
    for entry, s in replay["summary"].items():
        f1 = "n/a" if s.get("f1") is None else f"{s['f1']:.2f}"
        lines.append(f"| {entry} | {s['flagged']}/{s['attacks']} | {percent(s.get('recall'))} | "
                     f"{s['false_alarms']}/{s['benign']} | {percent(s.get('precision'))} | {f1} | {s['ms']['p95']:.1f} |")
    ml = "with BERTurk" if replay["config"].get("cascade") else "TF-IDF without BERTurk"
    return PASS, f"{replay['split']} split, {ml}", lines


def bypass_section(bypass):
    if bypass is None:
        return MISSING, "", ["The bypass suite didn't run (`python -m scripts.bypass_suite --baseline check`)."]
    families = {}
    for key, counts in bypass["summary"].items():
        family = key.split("/")[0]
        total = families.setdefault(family, {"kept": 0, "downgraded": 0, "lost": 0})
        for outcome, n in counts.items():
            total[outcome] += n
    lines = ["| Family | Rewrites | Still caught | Downgraded | Let through |", "|---|---|---|---|---|"]
    for family, c in families.items():
        lines.append(f"| {family} | {sum(c.values())} | {c['kept']} | {c['downgraded']} | {c['lost']} |")
    return PASS, "each rewrite of an attack the plain check catches", lines


def audit_section(audit):
    if audit is None:
        return MISSING, "", ["pip-audit didn't run (`pip-audit -r requirements-lock.txt --no-deps -f json`)."]
    found = [(d["name"], d["version"], v["id"], ", ".join(v.get("fix_versions", [])) or "none")
             for d in audit["dependencies"] for v in d.get("vulns", [])]
    lines = [f"{len(audit['dependencies'])} locked packages checked."]
    if found:
        lines += ["", "| Package | Version | Advisory | Fixed in |", "|---|---|---|---|"]
        lines += [f"| {n} | {v} | {i} | {f} |" for n, v, i, f in found]
    return (FAIL if found else PASS), f"{len(found)} known vulnerabilities", lines


def bandit_section(bandit):
    if bandit is None:
        return MISSING, "", ["bandit didn't run (`bandit -r sieve -f json`)."]
    issues = bandit["results"]
    lines = [f"{bandit['metrics']['_totals']['loc']} lines of `sieve/` scanned; "
             f"{bandit['metrics']['_totals'].get('skipped_tests', 0)} findings marked `# nosec` with a reason."]
    if issues:
        lines += ["", "| Test | Severity | Where |", "|---|---|---|"]
        lines += [f"| {i['test_id']} {i['test_name']} | {i['issue_severity']} | "
                  f"{os.path.relpath(i['filename'], ROOT)}:{i['line_number']} |" for i in issues]
    return (FAIL if issues else PASS), f"{len(issues)} findings", lines


def gitleaks_section(leaks):
    if leaks is None:
        return MISSING, "", ["gitleaks didn't run (`gitleaks git --report-format json`)."]
    lines = ["The whole git history, with only the synthetic test secrets in `.gitleaks.toml` allowed."]
    if leaks:
        lines += ["", "| Rule | File | Commit |", "|---|---|---|"]
        lines += [f"| {f['RuleID']} | {f['File']}:{f['StartLine']} | {f['Commit'][:7]} |" for f in leaks]
    return (FAIL if leaks else PASS), f"{len(leaks)} secrets", lines


def fuzz_section(fuzz):
    if fuzz is None:
        return MISSING, "", ["The fuzzer didn't run (`python -m scripts.fuzz_slow_inputs --patterns`)."]
    reported = next((line.strip() for line in fuzz.splitlines() if line.strip().endswith("reported")), "")
    clean = reported.startswith("0 ")
    return (PASS if clean else FAIL), reported or "no summary", ["```", fuzz.strip()[-1500:], "```"]


SECTIONS = [
    ("Attack replay", "replay.json", replay_section),
    ("Bypass suite", "bypass.json", bypass_section),
    ("Dependencies (pip-audit)", "pip_audit.json", audit_section),
    ("Code (bandit)", "bandit.json", bandit_section),
    ("Secrets (gitleaks)", "gitleaks.json", gitleaks_section),
    ("Slow patterns (fuzzer)", "fuzz.txt", fuzz_section),
]


def build():
    rows, body = [], []
    for title, name, section in SECTIONS:
        status, summary, lines = section(load(name))
        rows.append((title, status, summary))
        body += ["", f"## {title}", ""] + lines
    head = ["# Sieve security report", "", "| Check | Status | |", "|---|---|---|"]
    head += [f"| {t} | {s} | {m} |" for t, s, m in rows]
    return "\n".join(head + body) + "\n", rows


def main():
    parser = argparse.ArgumentParser(prog="python -m scripts.security_report")
    parser.add_argument("--strict", action="store_true", help="exit 1 if a check failed or didn't run")
    args = parser.parse_args()
    report, rows = build()
    RESULTS.mkdir(exist_ok=True)
    REPORT.write_text(report, encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(report)
    print(report)
    if args.strict and any(status != PASS for _, status, _ in rows):
        sys.exit(1)


if __name__ == "__main__":
    main()
