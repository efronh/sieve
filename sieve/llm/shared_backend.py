import os
from collections import defaultdict

import numpy as np

# AnyJev's prompt layout: system prompt, "State:", the message, a blank line, then the question.
QUESTION_START = "\n\nQuestion: "


# The last one is ours: a message could contain the same text, but our question always follows it.
def split_at_question(prompt):
    i = prompt.rfind(QUESTION_START)
    if i < 0:
        return None, prompt
    return prompt[:i + 2], prompt[i + 2:]


def reads(prefix, suffixes):
    return len(prefix) + sum(len(s) for s in suffixes)


# AnyJev re-reads the system prompt + message for every check; this shares that prefix.
# Uses score_tree / hidden_states_tree when the backend has them (tree_backend.py),
# otherwise merges a message's groups if that reads fewer chars.
class CrossQuestionSharing:
    def __init__(self, backend):
        self.backend = backend

    def __getattr__(self, name):
        return getattr(self.backend, name)

    def score_shared(self, groups, token_ids):
        if hasattr(self.backend, "score_tree"):
            return self.score_as_tree(groups, token_ids)
        return self.score_merged(groups, token_ids)

    def score_as_tree(self, groups, token_ids):
        trees, alone = defaultdict(list), []
        for gi, (prefix, _) in enumerate(groups):
            root, _ = split_at_question(prefix)
            if root is None:
                alone.append(gi)
            else:
                trees[root].append(gi)

        results = [None] * len(groups)
        for root, members in trees.items():
            branches = [(groups[gi][0][len(root):], groups[gi][1]) for gi in members]
            scored = self.backend.score_tree(root, branches, [token_ids[gi] for gi in members])
            for gi, lps in zip(members, scored):
                results[gi] = lps
        if alone:
            scored = self.backend.score_shared([groups[gi] for gi in alone], [token_ids[gi] for gi in alone])
            for gi, lps in zip(alone, scored):
                results[gi] = lps
        return results

    def score_merged(self, groups, token_ids):
        by_labels = defaultdict(list)
        for gi, ids in enumerate(token_ids):
            by_labels[tuple(ids)].append(gi)

        merged, sources = [], []
        for ids, members in by_labels.items():
            prefixes = [groups[gi][0] for gi in members]
            cut = os.path.commonprefix(prefixes).rfind("\n") + 1
            separate = sum(reads(*groups[gi]) for gi in members)
            together = reads(prefixes[0][:cut], [groups[gi][0][cut:] + s for gi in members for s in groups[gi][1]])
            if len(members) < 2 or cut == 0 or together >= separate:
                for gi in members:
                    merged.append((groups[gi], list(ids)))
                    sources.append([(gi, k) for k in range(len(groups[gi][1]))])
                continue

            suffixes, source = [], []
            for gi in members:
                prefix, group_suffixes = groups[gi]
                for k, suffix in enumerate(group_suffixes):
                    suffixes.append(prefix[cut:] + suffix)
                    source.append((gi, k))
            merged.append(((prefixes[0][:cut], suffixes), list(ids)))
            sources.append(source)

        scored = self.backend.score_shared([g for g, _ in merged], [ids for _, ids in merged])
        results = [[None] * len(suffixes) for _, suffixes in groups]
        for source, lps in zip(sources, scored):
            for (gi, k), lp in zip(source, lps):
                results[gi][k] = lp
        return results

    def hidden_states_to(self, prompts, layers, token_ids=None, positions=None, max_layer=None, lens_ids=None):
        plain = token_ids is not None or positions is not None or lens_ids is not None
        if plain or not hasattr(self.backend, "hidden_states_tree"):
            if hasattr(self.backend, "hidden_states_to"):
                return self.backend.hidden_states_to(prompts, layers, token_ids, positions, max_layer, lens_ids)
            feats, lps, pos_feats = self.backend.hidden_states(prompts, layers, token_ids, positions)
            return feats, lps, pos_feats, None

        by_root = defaultdict(list)
        for i, prompt in enumerate(prompts):
            root, rest = split_at_question(prompt)
            by_root[root or ""].append((i, rest if root else prompt))

        feats = None
        for root, items in by_root.items():
            part = self.backend.hidden_states_tree(root, [rest for _, rest in items], layers, max_layer)
            if feats is None:
                feats = np.zeros((len(prompts),) + part.shape[1:], dtype=np.float32)
            for (i, _), row in zip(items, part):
                feats[i] = row
        return feats, [None] * len(prompts), None, None
