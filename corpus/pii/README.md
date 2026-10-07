# Personal data for masking

Messages with personal data that masking must hide before the model sees it, and numbers that must stay. `python -m scripts.evaluate_masking` sends each through `mask()` and, inside a support-ticket export, through `DocumentGuard.wrap()`, and reports per label. Results and what was fixed: [TH-08](../../THREAT_MODEL.md#th-08-personal-data-leaving-in-prompts-or-logs).

```json
{"id": "PII-TC-002", "kind": "TC", "language": "tr", "source": "claude", "split": "test",
 "text": "Kimlik no: 100 000 040 38", "pii": [{"value": "100 000 040 38", "label": "[TC_KIMLIK]"}], "keep": [],
 "note": "groups of three"}
```

- `pii`: each value as written in the text, and the label it must be masked with. It counts as masked only when one replaced piece holds all of it.
- `keep`: values in the text that must still be there afterwards. A `BEN` record has only these.
- `split`: `dev` once a masking rule was changed after reading the record, or when it was written with the fix. The report counts test and dev apart.

Every value is synthetic: TC numbers in the 10000000xxx test range, IBANs with bank codes no bank has (999xx), cards on test ranges (411111…, 555555…, 9792 00…, 3700…), the unused 0599 mobile prefix, `example.com` addresses, keys made up or taken from vendors' documentation. The messages were written with Claude after reading `sieve/masking/`, so they're white-box.

`baseline.json` lists every value masked and every number left alone; `tests/test_masking_corpus.py` fails when one isn't any more. After an intended change: `python -m scripts.evaluate_masking --baseline update`.
