# Sieve versions, one yardstick (TF-IDF → BERTurk)

Each version's `sieve/` and `policies/`, today's scripts, corpus, sealed set and model. Recall / false-alarm rate on the corpus's test split; the sealed set in counts only.

## Detection

| Version | guardrail | document | tool | output | conversation | Sealed set: recall / FPR / F1 | `deepset_tr` recall |
|---|---|---|---|---|---|---|---|
| `3085fc1` Decide and log the four TenantGuardrail entry po | 74% / 3% | 75% / 2% | 89% / 0% | 86% / 9% | 91% / 0% | 57% / 2% / 0.72 | 26% |
| `f3b305b` Add a CI security job: locked dependencies, CVEs | 80% / 4% | 78% / 2% | 89% / 0% | 90% / 9% | 93% / 0% | 68% / 2% / 0.80 | 45% |

## Bypass suite: rewrites let through

| Version | encoding | unicode | script | structure | language | document | session | exfiltration | leak | personal_data | tool |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `3085fc1` | 755 / 2024 | 429 / 2816 | 170 / 176 | 402 / 528 | 55 / 76 | 367 / 3910 | 71 / 1056 | 2 / 30 | 53 / 114 | 3 / 13 | 3 / 96 |
| `f3b305b` | 316 / 2093 | 92 / 2912 | 0 / 182 | 81 / 546 | 53 / 76 | 7 / 4002 | 35 / 1092 | 0 / 30 | 0 / 114 | 1 / 13 | 1 / 96 |

## Latency (ms, median / p95) and cost

| Version | normal messages | attack messages | documents | tool calls | answers | Cold start (s) | Memory ready (MB) | Peak memory (MB) | CPU (s) |
|---|---|---|---|---|---|---|---|---|---|
| `3085fc1` | 0.55 / 0.93 | 12 / 17 | 51 / 55 | 0.29 / 11 | 0.17 / 0.52 | 0.69 | 161.9 | 598.7 | 142 |
| `f3b305b` | 0.95 / 2.31 | 23 / 43 | 15 / 18 | 0.38 / 12 | 0.64 / 1.26 | 0.69 | 161.8 | 1287.3 | 184 |

Peak memory is the largest of the runs (replay, sealed set, bypass suite, latency, start); CPU is their sum. A dash: that version's run didn't produce the number.
