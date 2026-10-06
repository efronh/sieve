# Looks for inputs that make Sieve slow: a pattern or a loop that rescans the text from every start (TH-11).
#   python -m scripts.fuzz_slow_inputs               # every pattern, then every entry point (a few minutes)
#   python -m scripts.fuzz_slow_inputs --patterns    # only the patterns
#
# Each compiled pattern in sieve/ gets long runs of single characters, pairs and short pieces (the pattern's own
# words among them), at two lengths. One that takes over 3 times longer at twice the length, and over 20 ms, is
# reported. Then each entry point gets long runs of the same kind, also at two lengths. Slow but linear isn't
# reported (masking a long run of digits is, at about 13 µs a character); the slowest time is printed. Passing
# isn't a proof: only these shapes are tried. Exits 1 when something is reported. Needs SIGALRM (not Windows).
import argparse
import importlib
import logging
import pkgutil
import re
import signal
import sys
import time

import sieve
from scripts.replay import tool_guard
from sieve.documents import DocumentGuard
from sieve.ml.injection import MLInjectionLayer
from sieve.output import OutputGuard
from sieve.pipeline import Guardrail, mask

PATTERN_LENGTH = 4_000
GROWTH = 3
MIN_SECONDS = 0.02
MIN_ENTRY_SECONDS = 0.2
TIMEOUT = 10
SPECIAL = list("a1 .-<>[](){}\"':/@=;#\n!|$%&*+,?\\_~\tA")
PIECES = list("ışİüйé\u200b\u00a0^`") + [
    "<a ", "[a](b ", "[a](", "{{a", "{{ ", "a://", "://", "wget ", "curl ", "a'--", "' ;", "'\n", "\n# ", "\n  ", "## ",
    "<!-", "a=\"", "[[a", "](", "a@b", "a@a.", "1.1", "1-1", "1 1", "aa ", "a-a", "..a", "%2e", "../", "&&a", "$(a",
    "on=", "TR1", "+90", "0 5", "1111", "a:a@", "http", "www.", "a.com", "?a=", "&a=", "#a", "\\x", "\\u0", "o1", "ıl",
]
# Entry point -> length of its longer inputs. A message is checked up to 8,000 characters but masked whole.
LENGTHS = {"message": 8_000, "masking": 200_000, "document": 50_000, "tool argument": 50_000, "answer": 100_000}


class TooSlow(BaseException):  # not an Exception, so the checks' fail-closed handlers don't swallow it
    pass


def stop(*_):
    raise TooSlow


def seconds(fn, text, timeout=TIMEOUT):
    signal.signal(signal.SIGALRM, stop)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    start = time.perf_counter()
    try:
        fn(text)
        return time.perf_counter() - start
    except TooSlow:
        return float("inf")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def repeated(piece, length):
    return (piece * (length // len(piece) + 1))[:length]


# Every compiled pattern in sieve's modules and in the guards' objects -> where it was found.
def patterns(guards):
    found, seen = {}, set()

    def walk(obj, where, depth=0):
        if id(obj) in seen or depth > 6:
            return
        seen.add(id(obj))
        if isinstance(obj, re.Pattern):
            found.setdefault(obj, where)
        elif isinstance(obj, dict):
            for key, value in obj.items():
                walk(value, f"{where}[{key!r}]"[:100], depth + 1)
        elif isinstance(obj, (list, tuple, set, frozenset)):
            for i, value in enumerate(obj):
                walk(value, f"{where}[{i}]", depth + 1)
        elif isinstance(obj, type) and obj.__module__.startswith("sieve"):
            for key, value in vars(obj).items():
                walk(value, f"{obj.__name__}.{key}", depth + 1)
        elif type(obj).__module__.startswith("sieve") and hasattr(obj, "__dict__"):
            walk(type(obj), where, depth + 1)
            for key, value in vars(obj).items():
                walk(value, f"{where}.{key}", depth + 1)

    for info in pkgutil.walk_packages(sieve.__path__, "sieve."):
        module = importlib.import_module(info.name)
        for name, value in vars(module).items():
            if not (isinstance(value, type) and value.__module__ != module.__name__):
                walk(value, f"{info.name}.{name}")
    for guard in guards:
        walk(guard, type(guard).__name__)
    return found


def check_patterns(guards):
    reported = []
    pairs = [a + b for a in SPECIAL for b in SPECIAL]
    for pattern, where in patterns(guards).items():
        words = sorted(set(re.findall(r"[^\W\d_]{2,}", pattern.pattern)))[:40]
        pieces = SPECIAL + pairs + PIECES + [w + end for w in words for end in ("", " ", "a")]
        worst = None
        for piece in pieces:
            for end in ("", "!"):
                small = seconds(lambda t: list(pattern.finditer(t)), repeated(piece, PATTERN_LENGTH) + end, 3)
                if small < MIN_SECONDS / GROWTH:
                    continue
                large = seconds(lambda t: list(pattern.finditer(t)), repeated(piece, 2 * PATTERN_LENGTH) + end, 3)
                if large > MIN_SECONDS and large > GROWTH * small and (worst is None or large > worst[1]):
                    worst = (piece + end, large, small)
        if worst:
            reported.append(where)
            print(f"  {where}: {worst[0]!r} x{PATTERN_LENGTH}: {worst[2] * 1000:.0f} ms, "
                  f"x{2 * PATTERN_LENGTH}: {worst[1] * 1000:.0f} ms\n    {pattern.pattern[:150]!r}")
    return reported


# ({entry point: check}, [the guards behind them])
def entry_points():
    guard = Guardrail(cache_size=0)
    ml = next((layer for layer in guard.check_layers if isinstance(layer, MLInjectionLayer)), None)
    documents = DocumentGuard(["ornekbank.com.tr"], ml_layer=ml, use_ml=ml is not None)
    tools = tool_guard(ml_layer=ml, use_ml=ml is not None)
    if ml is not None and ml.cascade:
        ml.stage.predict(["Merhaba"])  # BERTurk loads on first use; keep that out of the timings
    output = OutputGuard("Sen Ornekbank'ın asistanısın. Kart bilgisi isteme.", ["ornekbank.com.tr"],
                         canary="KNR-5e1f0c9a2b7d")
    return {
        "message": guard.check,
        "masking": mask,
        "document": documents.check,
        "tool argument": lambda text: tools.check("sikayet_kaydi_ac", {"konu": "Kart", "aciklama": text}, [], "u"),
        "answer": lambda text: output.check(text, user_data=[]),
    }, [guard, documents, tools, output]


def check_entry_points(checks):
    reported = []
    for name, check in checks.items():
        check("Merhaba")
        length, slowest, growing = LENGTHS[name], (0.0, ""), []
        for piece in SPECIAL + PIECES:
            small = seconds(check, repeated(piece, length // 2))
            large = seconds(check, repeated(piece, length)) if small < TIMEOUT else float("inf")
            slowest = max(slowest, (large, piece))
            if large > MIN_ENTRY_SECONDS and large > GROWTH * small:
                growing.append(f"{piece!r} {small:.2f} s -> {large:.2f} s")
        print(f"  {name:14} {length:>7,} characters: slowest {slowest[0]:.2f} s ({slowest[1]!r})"
              + "".join(f"\n    grows faster than the text: {g}" for g in growing))
        if growing:
            reported.append(name)
    return reported


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--patterns", action="store_true", help="only the patterns")
    args = parser.parse_args()
    logging.disable(logging.WARNING)
    checks, guards = entry_points()
    print("patterns that grow faster than the text:")
    reported = check_patterns(guards)
    print(f"  {len(reported)} reported")
    if not args.patterns:
        print("\nentry points (half the length, then the full length):")
        reported += check_entry_points(checks)
    sys.exit(1 if reported else 0)


if __name__ == "__main__":
    main()
