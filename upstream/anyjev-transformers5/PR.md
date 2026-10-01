**Title:** HFBackend block loop: support transformers 5 (fixes #4)

---

Fixes #4. On transformers 5 the L2 block loop raised `TypeError` from
`create_causal_mask(input_embeds=...)`, which `Decider._features` does not catch, so every L2 decision failed.

**Change**

- `HFBackend._accepts(fn, name)`: whether a function takes a keyword argument, read from its signature.
- `_prepare`: passes `inputs_embeds` or `input_embeds`, and `cache_position` only when `create_causal_mask`
  takes it.
- `_run_layers`: passes `past_key_values` or `past_key_value`, and `cache_position` only when the decoder
  layer takes it. On 4.57 this also removes the `past_key_value` deprecation warning.
- The behaviour on transformers 4.53+ is unchanged: the same arguments reach the same functions.

**Tests**

- `tests/test_hf_block_loop.py`: the block loop against the plain forward at block 1 and at the final norm,
  on prompts of different lengths (left-padded batch), and an L2 decision that reports `early_stop=True`.
  Tiny random Llama on CPU, `@pytest.mark.engine`, skipped without torch (the marker is registered in
  `pyproject.toml`).
- Without the fix the new test fails on 5.17.0 and passes on 4.57.6; with it, both pass.

| transformers | `ruff check ...` | `pytest -q` | `scripts/exit_parity.py` (tiny Llama, fp32, CPU) |
|---|---|---|---|
| 4.57.6 | pass | 89 passed | PASS, max\|dh\| 0 |
| 5.17.0 | pass | 89 passed | PASS, max\|dh\| 0 |
| numpy only | pass | new test skipped | not run |

Python 3.13.11, torch 2.14.0, macOS arm64. No bench numbers change: this only restores the code path
on transformers 5.

28 lines added, 7 removed, plus the test file. One line in `CHANGELOG.md`.

<!-- Keep this line only if it is true for you: -->
Prepared with the help of an AI coding assistant; I reviewed the change and ran every command above.
