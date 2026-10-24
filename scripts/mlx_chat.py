# A local chat model for scripts/llm_attacks.py, run in its own process with a Python that has mlx-lm (Apple
# silicon), so Sieve's environment doesn't need it:
#   /path/to/mlx/python scripts/mlx_chat.py mlx-community/aya-23-8B-4bit
# Reads one JSON object a line, {"system": ..., "user": ..., "max_tokens": ...}, and writes one back:
# {"text": ..., "ms": ..., "tokens": ...}. Greedy decoding, so an answer is the same each run.
import json
import sys
import time

from mlx_lm import generate, load


def main():
    model, tokenizer = load(sys.argv[1])
    print(json.dumps({"ready": True}), flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        messages = [{"role": "system", "content": request["system"]}, {"role": "user", "content": request["user"]}]
        prompt = tokenizer.apply_chat_template(messages, add_generation_prompt=True, tokenize=False)
        start = time.perf_counter()
        text = generate(model, tokenizer, prompt=prompt, max_tokens=request["max_tokens"])
        ms = (time.perf_counter() - start) * 1000
        print(json.dumps({"text": text, "ms": round(ms, 1), "tokens": len(tokenizer.encode(text))}), flush=True)


if __name__ == "__main__":
    main()
