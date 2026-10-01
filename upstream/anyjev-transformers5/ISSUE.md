**Title:** L2 decisions fail on transformers 5: `create_causal_mask()` got an unexpected keyword argument `input_embeds`

---

**What happens**

On transformers 5.x every L2 decision raises. `HFBackend._prepare` calls
`create_causal_mask(input_embeds=..., cache_position=...)`, but transformers 5 renamed the argument to
`inputs_embeds` and dropped `cache_position`:

```
TypeError: create_causal_mask() got an unexpected keyword argument 'input_embeds'. Did you mean 'inputs_embeds'?
```

`Decider._features` only falls back to the full forward on `NotImplementedError`, so the `TypeError`
propagates and `decide(..., level="L2")` / `fit_head` fail instead of losing the early stop.

`_run_layers` has the same kind of drift: it passes `past_key_value=` to the decoder layer. On 4.57 that
works through a deprecation shim (with a warning); on 5.x the layer takes `past_key_values`, and the old
name lands in `**kwargs`.

**Reproduce** (CPU, tiny random model, a few seconds)

```python
from anyjev.backends.hf import HFBackend

be = HFBackend("hf-internal-testing/tiny-random-LlamaForCausalLM", device="cpu", dtype="float32")
be.hidden_states_to(["hello"], [1], max_layer=1)   # TypeError on transformers 5.17.0
```

`python scripts/exit_parity.py --model hf-internal-testing/tiny-random-LlamaForCausalLM --device cpu`
fails the same way on 5.17.0 and passes on 4.57.6.

**Environment:** anyjev `main` at a59a69e, Python 3.13.11, torch 2.14.0, transformers 5.17.0
(4.57.6 for comparison), macOS arm64, CPU.

**Proposed fix** (small, I have it ready): in `_prepare` and `_run_layers`, pass `inputs_embeds` /
`input_embeds`, `past_key_values` / `past_key_value` and `cache_position` according to what the installed
function's signature accepts, rather than by version number. Plus a test that compares the block loop with
the plain forward on the tiny model, marked `@pytest.mark.engine` and skipped without torch. Happy to open
the PR if that approach works for you.
