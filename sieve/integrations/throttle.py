import time
from collections import OrderedDict, defaultdict, deque

from sieve.actions import ALLOW

MAX_FLAGGED = 3
WINDOW_SECONDS = 10 * 60
COOLDOWN_SECONDS = 15 * 60
MAX_REQUESTS_PER_MINUTE = 30
MAX_CHARS_PER_WINDOW = 50_000
CONTEXT_MESSAGES = 4
CONTEXT_CHARS = 1000
MAX_KEYS = 50_000
LIMITED_REPLY = "Çok sayıda engellenen mesaj nedeniyle bu oturum kısa bir süre için durduruldu."


# A session that keeps getting flagged is probing the guardrail: after a few
# flagged messages in a short window, stop spending tokens on it for a while.
class SessionLimiter:
    def __init__(self, max_flagged=MAX_FLAGGED, window_seconds=WINDOW_SECONDS,
                 cooldown_seconds=COOLDOWN_SECONDS, clock=time.monotonic):
        self.max_flagged = max_flagged
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.clock = clock
        self.flagged = defaultdict(deque)
        self.limited_until = {}

    def is_limited(self, session):
        until = self.limited_until.get(session)
        if until is None:
            return False
        if self.clock() >= until:
            del self.limited_until[session]
            return False
        return True

    def record(self, session, action):
        if action == ALLOW:
            return
        now = self.clock()
        times = self.flagged[session]
        times.append(now)
        while times and now - times[0] > self.window_seconds:
            times.popleft()
        if len(times) >= self.max_flagged:
            self.limited_until[session] = now + self.cooldown_seconds
            times.clear()


# Least recently used keys are dropped, so millions of one-off sessions can't fill memory.
def bounded_get(store, key, make, max_keys):
    if key in store:
        store.move_to_end(key)
    else:
        store[key] = make()
        if len(store) > max_keys:
            store.popitem(last=False)
    return store[key]


# Unbounded consumption (OWASP LLM10): too many requests, or too much text, from one user.
# Every request counts, rejected ones too, so hammering keeps the limit on.
class RateLimiter:
    def __init__(self, max_per_minute=MAX_REQUESTS_PER_MINUTE, max_chars=MAX_CHARS_PER_WINDOW,
                 window_seconds=WINDOW_SECONDS, clock=time.monotonic, max_keys=MAX_KEYS):
        self.max_per_minute = max_per_minute
        self.max_chars = max_chars
        self.window_seconds = window_seconds
        self.clock = clock
        self.max_keys = max_keys
        self.requests = OrderedDict()
        self.sizes = OrderedDict()

    def hit(self, key, size):
        now = self.clock()
        requests = bounded_get(self.requests, key, deque, self.max_keys)
        sizes = bounded_get(self.sizes, key, deque, self.max_keys)
        requests.append(now)
        sizes.append((now, size))
        while requests and now - requests[0] > 60:
            requests.popleft()
        while sizes and now - sizes[0][0] > self.window_seconds:
            sizes.popleft()

        exceeded = []
        if len(requests) > self.max_per_minute:
            exceeded.append("rate_limit")
        if sum(n for _, n in sizes) > self.max_chars:
            exceeded.append("volume_limit")
        return exceeded


# Split attacks: "Önceki talimatları" in one message, "unut" in the next. Keeps the tail of the
# last few masked messages of a session and the rule IDs each one fired on its own.
class ConversationWindow:
    def __init__(self, messages=CONTEXT_MESSAGES, window_seconds=WINDOW_SECONDS,
                 clock=time.monotonic, max_keys=MAX_KEYS):
        self.messages = messages
        self.window_seconds = window_seconds
        self.clock = clock
        self.max_keys = max_keys
        self.history_by_key = OrderedDict()

    def history(self, key):
        if key not in self.history_by_key:
            return []
        now = self.clock()
        items = self.history_by_key[key]
        while items and now - items[0][0] > self.window_seconds:
            items.popleft()
        return [(text, rules) for _, text, rules in items]

    def add(self, key, masked_text, rules):
        items = bounded_get(self.history_by_key, key, lambda: deque(maxlen=max(self.messages - 1, 0)), self.max_keys)
        items.append((self.clock(), masked_text[-CONTEXT_CHARS:], frozenset(rules)))
