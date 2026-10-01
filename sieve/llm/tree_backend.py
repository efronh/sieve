import copy
from collections import OrderedDict

import numpy as np
import torch
from anyjev.backends.hf import HFBackend

ROOT_CACHE_SIZE = 8


# score_tree / hidden_states_tree for CrossQuestionSharing. Own block loop for L2 because
# AnyJev's starts a fresh cache on every call. Pieces are cut from one tokenization of the
# full prompt (sentencepiece adds a space per encode call); if a cut misses a token
# boundary we score the full prompt instead.
class TreeHFBackend(HFBackend):
    def __init__(self, *args, root_cache_size=ROOT_CACHE_SIZE, **kwargs):
        super().__init__(*args, **kwargs)
        self.root_cache_size = root_cache_size
        self.roots = OrderedDict()
        self.tree_fallbacks = 0
        self.root_hits = 0

    def split_ids(self, text, cuts):
        enc = self.tokenizer(text, add_special_tokens=False, return_offsets_mapping=True)
        starts = {start: i for i, (start, _) in enumerate(enc["offset_mapping"])}
        ids, parts, prev = enc["input_ids"], [], 0
        for cut in cuts:
            if cut not in starts:
                return None
            parts.append(ids[prev:starts[cut]])
            prev = starts[cut]
        parts.append(ids[prev:])
        return parts

    def forward(self, ids, cache, start):
        ids = torch.as_tensor([ids], device=self.model.device)
        positions = torch.arange(start, start + ids.shape[1], device=self.model.device)[None]
        out = self.model.model(input_ids=ids, position_ids=positions, past_key_values=cache, use_cache=True)
        return out.past_key_values

    def score_tree(self, root, branches, token_ids):
        results = []
        root_ids, root_cache = None, None
        for (mid, suffixes), ids in zip(branches, token_ids):
            pieces = [self.split_ids(root + mid + s, [len(root), len(root) + len(mid)]) for s in suffixes]
            exact = all(p is not None and p[0] and p[1] for p in pieces)
            if exact and root_ids is not None:
                exact = all(p[0] == root_ids for p in pieces)
            if exact:
                exact = all(p[1] == pieces[0][1] and p[2] for p in pieces)
            if not exact:
                self.tree_fallbacks += 1
                results.append(self.next_token_logprobs([root + mid + s for s in suffixes], [ids] * len(suffixes)))
                continue

            with torch.no_grad():
                if root_ids is None:
                    root_ids = pieces[0][0]
                    root_cache = self.forward(root_ids, None, 0)
                mid_ids = pieces[0][1]
                cache = self.forward(mid_ids, copy.deepcopy(root_cache), len(root_ids))
                results.append(self.score_suffixes(cache, len(root_ids) + len(mid_ids), [p[2] for p in pieces], ids))
        return results

    def score_suffixes(self, cache, start, suffix_ids, ids):
        k = len(suffix_ids)
        cache = self._repeat_cache(cache, k)
        width = max(len(s) for s in suffix_ids)
        pad = self.tokenizer.pad_token_id or 0
        tokens = torch.full((k, width), pad, dtype=torch.long)
        mask = torch.zeros((k, start + width), dtype=torch.long)
        mask[:, :start] = 1
        last = []
        for row, s in enumerate(suffix_ids):
            tokens[row, :len(s)] = torch.as_tensor(s)
            mask[row, start:start + len(s)] = 1
            last.append(len(s) - 1)
        device = self.model.device
        positions = start + torch.arange(width, device=device)[None].repeat(k, 1)
        out = self.model.model(input_ids=tokens.to(device), attention_mask=mask.to(device), position_ids=positions,
                               past_key_values=cache, use_cache=True)
        hidden = out.last_hidden_state[torch.arange(k, device=device), torch.as_tensor(last, device=device)]
        lp = torch.log_softmax(self._project(hidden), dim=-1)
        label_ids = torch.as_tensor(list(ids), device=device)
        return [lp[row, label_ids].cpu().numpy().astype(np.float64) for row in range(k)]

    # L2
    def masks(self, embeds, attention_mask, cache, positions):
        from transformers.masking_utils import create_causal_mask

        kw = dict(config=self.model.config, inputs_embeds=embeds, attention_mask=attention_mask,
                  past_key_values=cache, position_ids=positions)
        masks = {"full_attention": create_causal_mask(**kw)}
        if any(getattr(layer, "attention_type", "") == "sliding_attention" for layer in self.model.model.layers):
            from transformers.masking_utils import create_sliding_window_causal_mask
            masks["sliding_attention"] = create_sliding_window_causal_mask(**kw)
        return masks

    def run_blocks(self, ids, cache, start, stop, capture=None):
        inner = self.model.model
        device = self.model.device
        ids = torch.as_tensor([ids], device=device)
        positions = torch.arange(start, start + ids.shape[1], device=device)[None]
        embeds = h = inner.embed_tokens(ids)
        if capture is not None:
            capture(0, embeds)
        attention_mask = torch.ones((1, start + ids.shape[1]), dtype=torch.long, device=device)
        masks = self.masks(embeds, attention_mask, cache, positions)
        rope = inner.rotary_emb(embeds, positions)
        for i in range(stop):
            layer = inner.layers[i]
            out = layer(h, attention_mask=masks[getattr(layer, "attention_type", "full_attention")],
                        position_ids=positions, past_key_values=cache, use_cache=True, position_embeddings=rope)
            h = out[0] if isinstance(out, tuple) else out
            if capture is not None:
                capture(i + 1, h)
        return h

    # A root cached to a shallower block is rebuilt, not resumed: the causal mask reads the
    # past length from block 0, which a half-filled cache would get wrong for the deeper blocks.
    def root_state(self, root_ids, stop):
        from transformers import DynamicCache

        key = tuple(root_ids)
        entry = self.roots.get(key)
        if entry is not None and entry["depth"] >= stop:
            self.roots.move_to_end(key)
            self.root_hits += 1
            return entry["cache"]

        cache = DynamicCache(config=self.model.config)
        self.run_blocks(root_ids, cache, 0, stop)
        self.roots[key] = {"cache": cache, "depth": stop}
        self.roots.move_to_end(key)
        if len(self.roots) > self.root_cache_size:
            self.roots.popitem(last=False)
        return cache

    def hidden_states_tree(self, root, rests, layers, max_layer=None):
        from transformers import DynamicCache

        n_blocks = self.n_layers
        layers = [(n_blocks + 1 + i) if i < 0 else i for i in layers]
        stop = min(n_blocks, max_layer if max_layer is not None else max(layers))
        feats = np.zeros((len(rests), len(layers), self.hidden_size), dtype=np.float32)

        for row, rest in enumerate(rests):
            if root:
                pieces = self.split_ids(root + rest, [len(root)])
            else:
                pieces = [[], self.tokenizer.encode(rest, add_special_tokens=False)]
            if pieces is None or (root and not pieces[0]) or not pieces[1]:
                self.tree_fallbacks += 1
                feats[row] = self.hidden_states([root + rest], layers)[0][0]
                continue

            root_ids, rest_ids = pieces
            captured = {}

            def grab(i, h):
                if i in layers:
                    captured[i] = h

            with torch.no_grad():
                if root_ids:
                    cache = copy.deepcopy(self.root_state(root_ids, stop))
                else:
                    cache = DynamicCache(config=self.model.config)
                h = self.run_blocks(rest_ids, cache, len(root_ids), stop, capture=grab)
                if n_blocks in layers:
                    captured[n_blocks] = self.model.model.norm(h)
            for li, layer in enumerate(layers):
                feats[row, li] = captured[layer][0, -1].float().cpu().numpy()
        return feats

    def hidden_states_to(self, prompts, layers, token_ids=None, positions=None, max_layer=None, lens_ids=None):
        if token_ids is not None or positions is not None or lens_ids is not None:
            feats, lps, pos_feats = self.hidden_states(prompts, layers, token_ids, positions)
            return feats, lps, pos_feats, None
        return self.hidden_states_tree("", prompts, layers, max_layer), [None] * len(prompts), None, None
