# Sieve versions, one yardstick (TF-IDF alone, as in CI)

Each version's `sieve/` and `policies/`, today's scripts, corpus, sealed set and model. Recall / false-alarm rate on the corpus's test split; the sealed set in counts only.

## Detection

| Version | guardrail | document | tool | output | conversation | Sealed set: recall / FPR / F1 | `deepset_tr` recall |
|---|---|---|---|---|---|---|---|
| `3085fc1` Decide and log the four TenantGuardrail entry po | 68% / 3% | 70% / 3% | 89% / 0% | 86% / 9% | 82% / 0% | 56% / 3% / 0.71 | 27% |
| `b2f0252` Keep a failing part or a malformed policy from o | 68% / 3% | 70% / 3% | 89% / 0% | 86% / 9% | 82% / 0% | 56% / 3% / 0.71 | 27% |
| `7046649` Mask long runs of digits 2.7 times faster, with  | 68% / 3% | 70% / 3% | 89% / 0% | 86% / 9% | 82% / 0% | 56% / 3% / 0.71 | 27% |
| `185f9ae` Bound what one request can cost Sieve | 68% / 3% | 70% / 3% | 89% / 0% | 86% / 9% | 82% / 0% | 56% / 3% / 0.71 | 27% |
| `60d8e52` Measure each trick on attacks Sieve already catc | 71% / 3% | 73% / 3% | 89% / 0% | 86% / 9% | 82% / 0% | 56% / 3% / 0.71 | 27% |
| `fa6a999` Test answers and tool calls the same way, and cl | 71% / 3% | 73% / 3% | 89% / 0% | 90% / 9% | 82% / 0% | 56% / 3% / 0.71 | 27% |
| `0bdb41b` Check everything Sieve writes for the secrets it | 71% / 3% | 73% / 3% | 89% / 0% | 90% / 9% | 82% / 0% | 56% / 3% / 0.71 | 27% |
| `9a8169d` Read messages by sentence and conversations by p | 76% / 3% | 73% / 3% | 89% / 0% | 90% / 9% | 86% / 0% | 68% / 4% / 0.79 | 45% |
| `f3b305b` Add a CI security job: locked dependencies, CVEs | 76% / 3% | 73% / 3% | 89% / 0% | 90% / 9% | 86% / 0% | 68% / 4% / 0.79 | 45% |

## Bypass suite: rewrites let through

| Version | encoding | unicode | script | structure | language | document | session | exfiltration | leak | personal_data | tool |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `3085fc1` | 814 / 1817 | 356 / 2528 | 154 / 158 | 378 / 474 | 59 / 76 | 375 / 3588 | 62 / 948 | 2 / 30 | 53 / 114 | 3 / 13 | 3 / 96 |
| `b2f0252` | 814 / 1817 | 356 / 2528 | 154 / 158 | 378 / 474 | 59 / 76 | 375 / 3588 | 62 / 948 | 2 / 30 | 53 / 114 | 3 / 13 | 3 / 96 |
| `7046649` | 814 / 1817 | 356 / 2528 | 154 / 158 | 378 / 474 | 59 / 76 | 375 / 3588 | 62 / 948 | 2 / 30 | 53 / 114 | 3 / 13 | 3 / 96 |
| `185f9ae` | 814 / 1817 | 356 / 2528 | 154 / 158 | 378 / 474 | 59 / 76 | 375 / 3588 | 62 / 948 | 2 / 30 | 53 / 114 | 3 / 13 | 3 / 96 |
| `60d8e52` | 238 / 1817 | 66 / 2528 | 0 / 158 | 378 / 474 | 57 / 76 | 9 / 3634 | 62 / 948 | 2 / 30 | 40 / 114 | 3 / 13 | 3 / 96 |
| `fa6a999` | 238 / 1817 | 66 / 2528 | 0 / 158 | 378 / 474 | 57 / 76 | 9 / 3634 | 62 / 948 | 0 / 30 | 0 / 114 | 1 / 13 | 1 / 96 |
| `0bdb41b` | 238 / 1817 | 66 / 2528 | 0 / 158 | 378 / 474 | 57 / 76 | 9 / 3634 | 62 / 948 | 0 / 30 | 0 / 114 | 1 / 13 | 1 / 96 |
| `9a8169d` | 320 / 1955 | 78 / 2720 | 0 / 170 | 106 / 510 | 55 / 76 | 13 / 3772 | 44 / 1020 | 0 / 30 | 0 / 114 | 1 / 13 | 1 / 96 |
| `f3b305b` | 320 / 1955 | 78 / 2720 | 0 / 170 | 106 / 510 | 55 / 76 | 13 / 3772 | 44 / 1020 | 0 / 30 | 0 / 114 | 1 / 13 | 1 / 96 |

## Latency (ms, median / p95) and cost

| Version | normal messages | attack messages | documents | tool calls | answers | Cold start (s) | Memory ready (MB) | Peak memory (MB) | CPU (s) |
|---|---|---|---|---|---|---|---|---|---|
| `3085fc1` | 0.53 / 0.90 | 0.47 / 0.81 | 2.33 / 3.23 | 0.26 / 0.63 | 0.17 / 0.51 | 0.67 | 152.5 | 211.5 | 22 |
| `b2f0252` | 0.53 / 0.92 | 0.47 / 0.81 | 2.43 / 3.28 | 0.26 / 0.65 | 0.17 / 0.52 | 0.67 | 158.9 | 212.0 | 22 |
| `7046649` | 0.53 / 0.92 | 0.49 / 0.86 | 2.36 / 3.27 | 0.26 / 0.63 | 0.18 / 0.52 | 0.67 | 166.3 | 214.7 | 22 |
| `185f9ae` | 0.53 / 0.91 | 0.48 / 0.84 | 2.26 / 3.13 | 0.27 / 0.65 | 0.17 / 0.52 | 0.67 | 153.0 | 202.9 | 22 |
| `60d8e52` | 0.59 / 1.00 | 0.53 / 0.99 | 2.71 / 3.67 | 0.37 / 0.84 | 0.20 / 0.56 | 0.67 | 163.2 | 214.8 | 26 |
| `fa6a999` | 0.59 / 1.01 | 0.53 / 1.00 | 2.68 / 3.73 | 0.37 / 0.84 | 0.65 / 1.28 | 0.68 | 160.0 | 219.5 | 26 |
| `0bdb41b` | 0.58 / 1.01 | 0.52 / 0.97 | 2.75 / 3.69 | 0.37 / 0.82 | 0.64 / 1.25 | 0.67 | 163.2 | 201.0 | 26 |
| `9a8169d` | 0.94 / 2.28 | 0.74 / 1.73 | 2.67 / 3.69 | 0.37 / 0.82 | 0.65 / 1.26 | 0.67 | 160.2 | 215.9 | 35 |
| `f3b305b` | 0.93 / 2.29 | 0.72 / 1.71 | 2.70 / 3.68 | 0.37 / 0.83 | 0.64 / 1.28 | 0.68 | 153.5 | 210.1 | 35 |

Peak memory is the largest of the runs (replay, sealed set, bypass suite, latency, start); CPU is their sum. A dash: that version's run didn't produce the number.
