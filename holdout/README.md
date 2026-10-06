# Sealed held-out set

Attacks and benign messages that nobody who changes Sieve's rules or models has read. They're never trained on and never looked at one by one. `python -m scripts.replay --holdout` sends each through `Guardrail()` and prints only counts: per source, and per the source's own category labels. It never prints an ID or a text. The counts go to `results/holdout.json`.

The rest of the corpus (`corpus/`) is mostly white-box: written knowing the rules. This set is what the detection numbers should be judged on.

## Rules

- Don't open the files here. `scripts/import_holdout.py` writes them and prints only counts.
- Don't change a rule, a threshold or the model because of a number from this set. Improve on `corpus/` (dev records) and measure here afterwards.
- Never train on it. It isn't in `scripts/train_injection.py`, and the import drops anything close to a training text.
- If a record ever has to be read (a broken label, say), it leaves this set: move it to `corpus/` as dev.

## Sources

| File | Source | Revision | License | What's in it |
|---|---|---|---|---|
| `pi1k.jsonl` | [3nesdeniz/turkish-prompt-injection-1k](https://huggingface.co/datasets/3nesdeniz/turkish-prompt-injection-1k), test split | `1cbd115` | CC-BY-4.0 | 79 attacks, 34 look-alike benign messages, from human-written templates |
| `deepset_tr.jsonl` | [beratcmn/turkish-prompt-injections](https://huggingface.co/datasets/beratcmn/turkish-prompt-injections), train and test | `c40c38f` | Apache-2.0 | 258 attacks, 345 benign; a Turkish translation of [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) |
| `patterns_tr.jsonl` | [fevziegeyurtsevenler/turkish-prompt-injection](https://huggingface.co/datasets/fevziegeyurtsevenler/turkish-prompt-injection) | `fae488a` | CC-BY-4.0 | 107 attack patterns with categories |
| `user_attacks.txt`, `user_benign.txt` | Written by the project's owner without looking at the rules | — | MIT | One message per line |

The import dropped 57 repeated texts and 1 text close to a training text (more than half its character 4-grams shared). The labels are the sources' own.

How independent the sources are:
- `pi1k` and `patterns_tr` come from people around AltaySec. Their v0.2 dataset is in the training data, and TCPI, whose test split is the README's held-out set, has the same author as `pi1k`. None of the texts is a near copy, but the style may be close.
- `deepset_tr` has no link to anything Sieve was built on.

The replay reports each source separately for this reason.

## Adding your own

Write attacks into `user_attacks.txt` and normal messages that look like attacks into `user_benign.txt`, one per line, without reading `sieve/checks/` or `corpus/` first. Write as a customer or an attacker would talk to a bank's assistant. Lines starting with `#` are notes and are skipped. Then run `python -m scripts.replay --holdout`; they're reported as the source `user`.
