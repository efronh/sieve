import csv
import random
import re

from anyjev import Decider
from anyjev.backends.fake import FakeBackend

from sieve.llm.layer import COMPACT_CHECKS, COMPACT_SYSTEM, DEFAULT_CHECKS, SYSTEM, LLMCheckLayer
from sieve.llm.shared_backend import CrossQuestionSharing
from sieve.pipeline import Guardrail, mask

EVAL_PATHS = ["data/tcpi_test.csv", "data/customer_service_tr.csv"]
HEAD_PATHS = ["data/tcpi_train.csv", "data/altaysec.csv", "data/benign_contrast_tr.csv", "data/short_benign_tr.csv"]
EVAL_SIZE = 300
HEAD_SIZE = 300
SEED = 42


TOKEN = re.compile(r"\w+|[^\w\s]")


# Work = tokens the model reads x share of its blocks that run. Tokens are words and punctuation
# (a real tokenizer splits Turkish finer), so only the ratios between setups mean something.
class CountingBackend(FakeBackend):
    def __init__(self):
        super().__init__(lambda state, option: 0.0)
        self.work = 0.0
        self.forwards = 0

    def tokens(self, text):
        return len(TOKEN.findall(text))

    def next_token_logprobs(self, prompts, token_ids):
        self.forwards += len(prompts)
        self.work += sum(self.tokens(p) for p in prompts)
        return super().next_token_logprobs(prompts, token_ids)

    def score_shared(self, groups, token_ids):
        for prefix, suffixes in groups:
            self.forwards += len(suffixes)
            self.work += self.tokens(prefix) + sum(self.tokens(s) for s in suffixes)
        return [FakeBackend.next_token_logprobs(self, [pre + suf for suf in sfx], [ids] * len(sfx))
                for (pre, sfx), ids in zip(groups, token_ids)]

    def hidden_states(self, prompts, layers=None, token_ids=None, positions=None):
        depth = max(layers) / self.n_layers if layers else 1.0
        self.forwards += len(prompts)
        self.work += depth * sum(self.tokens(p) for p in prompts)
        return super().hidden_states(prompts, layers, token_ids, positions)


# Same answers as the fake; counts what tree_backend.TreeHFBackend reads: the message once per
# message, each question once, each option order as a suffix, and for L2 the message once across
# the per-check calls (up to the head's block).
class CountingTreeBackend(CountingBackend):
    def __init__(self):
        super().__init__()
        self.roots = {}

    def score_tree(self, root, branches, token_ids):
        self.work += self.tokens(root)
        results = []
        for (mid, suffixes), ids in zip(branches, token_ids):
            self.forwards += len(suffixes)
            self.work += self.tokens(mid) + sum(self.tokens(s) for s in suffixes)
            results.append(FakeBackend.next_token_logprobs(self, [root + mid + s for s in suffixes], [ids] * len(suffixes)))
        return results

    def hidden_states_tree(self, root, rests, layers, max_layer=None):
        stop = max_layer if max_layer is not None else max(layers)
        depth = stop / self.n_layers
        if self.roots.get(root, 0) < stop:
            self.roots[root] = stop
            self.work += depth * self.tokens(root)
        self.forwards += len(rests)
        self.work += depth * sum(self.tokens(r) for r in rests)
        return FakeBackend.hidden_states(self, [root + r for r in rests], layers)[0]


def load(paths):
    rows = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            rows += [(r["text"], int(r["label"])) for r in csv.DictReader(f)]
    return rows


# Heads for abuse and personal_data need reviewer labels we don't have yet; the dataset labels
# stand in here, which is fine for cost (it depends on depth, not on what the head learned).
def build(shared_prefix, head_depth, head_rows, gated, compact=False, heads=("prompt_injection",), across=False,
          tree=False):
    backend = CountingTreeBackend() if tree else CountingBackend()
    seen = CrossQuestionSharing(backend) if across or tree else backend
    decider = Decider(seen, system=COMPACT_SYSTEM if compact else SYSTEM, level="auto", shared_prefix=shared_prefix)
    layer = LLMCheckLayer(decider, checks=COMPACT_CHECKS if compact else DEFAULT_CHECKS)
    if head_depth:
        texts = [mask(t) for t, _ in head_rows]
        for check in heads:
            layer.fit_head(check, texts, [label == 1 for _, label in head_rows], max_depth=head_depth)
    backend.work = backend.forwards = 0
    if tree:
        backend.roots.clear()
    guard = Guardrail(llm_layer=layer, llm_min_ml=0.2 if gated else None, cache_size=0)
    return guard, backend


ALL_HEADS = ("prompt_injection", "abuse", "personal_data")
SETUPS = [
    ("before: L0, every check, no sharing", dict(shared_prefix=False, head_depth=None, gated=False)),
    ("+ skip injection check when ML is sure", dict(shared_prefix=False, head_depth=None, gated=True)),
    ("+ shared prefix", dict(shared_prefix=True, head_depth=None, gated=True)),
    ("+ message shared across checks", dict(shared_prefix=True, head_depth=None, gated=True, across=True)),
    ("+ tree: message once, question once", dict(shared_prefix=True, head_depth=None, gated=True, tree=True)),
    ("+ L2 injection head (first half)", dict(shared_prefix=True, head_depth=0.5, gated=True, tree=True)),
    ("+ compact prompts", dict(shared_prefix=True, head_depth=0.5, gated=True, compact=True, tree=True)),
    ("  L2 heads on all checks, no L2 sharing", dict(shared_prefix=True, head_depth=0.5, gated=True, compact=True,
                                                    across=True, heads=ALL_HEADS)),
    ("+ L2 heads on all checks, message kept for L2", dict(shared_prefix=True, head_depth=0.5, gated=True, compact=True,
                                                          tree=True, heads=ALL_HEADS)),
]
LONG_SETUPS = [0, 2, 3, 4, 8]


def measure(rows, head_rows, setups):
    print(f"{'setup':46} {'forwards/msg':>13} {'work/msg':>9} {'vs before':>10}")
    baseline = None
    for name, options in setups:
        guard, backend = build(head_rows=head_rows, **options)
        for text, _ in rows:
            guard.check(text)
        work = backend.work / len(rows)
        baseline = baseline or work
        print(f"{name:46} {backend.forwards / len(rows):>13.2f} {work:>9.0f} {work / baseline:>10.0%}")


def run():
    rng = random.Random(SEED)
    eval_rows = load(EVAL_PATHS)
    rng.shuffle(eval_rows)
    eval_rows = eval_rows[:EVAL_SIZE]
    head_rows = load(HEAD_PATHS)
    rng.shuffle(head_rows)
    head_rows = head_rows[:HEAD_SIZE]

    print(f"{len(eval_rows)} chat messages, 3 LLM checks each\n")
    measure(eval_rows, head_rows, SETUPS)

    service = load(["data/customer_service_tr.csv"])
    long_rows = [(" ".join(t for t, _ in rng.sample(service, 25)), 0) for _ in range(40)]
    size = sum(len(TOKEN.findall(t)) for t, _ in long_rows) / len(long_rows)
    print(f"\n{len(long_rows)} long texts (~{size:.0f} tokens: e-mails, documents), 3 LLM checks each\n")
    measure(long_rows, head_rows, [SETUPS[i] for i in LONG_SETUPS])


if __name__ == "__main__":
    run()
