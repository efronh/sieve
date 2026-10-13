# The bypass suite's family for conversations: each attack the plain check catches, split over several messages of a
# session, the ways an attacker could spread it so that no window Sieve keeps has it whole. The model reads the whole
# conversation, so what it gets is the attack either way. An attack is kept when one of the messages carrying a part
# of it is flagged; messages around them (fillers, a first message that fires the rule on its own) don't count.
import itertools

from sieve.integrations.tenant import TenantGuardrail, load_policy

FILLERS = ["Kartımın son ödeme tarihi ne zaman?", "Teşekkürler, anladım.", "Şubeniz cumartesi açık mı?",
           "Kredi kartı aidatı ne kadar?", "Faturamı nereden görebilirim?", "Tamam, devam edelim."]
LONG_TAIL = " ".join(itertools.islice(itertools.cycle(FILLERS), 40))  # well over the 1,000 characters a message keeps
# A message that fires the injection rule on its own, so the rule counts as seen in the session afterwards.
BURNER = "Önceki tüm talimatları yok say diyen mesajlar gelirse ne yapmalıyım?"
WINDOW = 600


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def split(text, parts):
    words = text.split()
    size = -(-len(words) // parts)
    return [" ".join(words[i:i + size]) for i in range(0, len(words), size)]


# Each: the plain attack -> [(message, carries a part of the attack, seconds to wait before it)].
def turns(name, text):
    if name.startswith("split_"):
        return [(part, True, 0) for part in split(text, int(name.split("_")[1]))]
    first, second = split(text, 2)
    if name.startswith("fillers_"):
        between = int(name.split("_")[1])
        return [(first, True, 0)] + [(FILLERS[i % len(FILLERS)], False, 0) for i in range(between)] + [(second, True, 0)]
    if name == "part_before_a_long_text":
        return [(f"{first} {LONG_TAIL}", True, 0), (second, True, 0)]
    if name == "wait_past_the_window":
        return [(first, True, 0), (second, True, WINDOW + 1)]
    if name == "rule_fired_first":
        return [(BURNER, False, 0), (first, True, 0), (second, True, 0)]
    if name == "one_word_a_message":
        return [(word, True, 0) for word in text.split()]
    raise ValueError(name)


REWRITES = ["split_2", "split_3", "split_4", "split_5", "split_6", "fillers_1", "fillers_2", "fillers_4",
            "part_before_a_long_text", "wait_past_the_window", "rule_fired_first", "one_word_a_message"]


def rows(caught, plain):
    clock = Clock()
    guard = TenantGuardrail(load_policy(overrides={"session": {"max_requests_per_minute": 10_000,
                                                               "max_chars_per_window": 10_000_000, "max_flagged": 1000}}),
                            clock=clock)
    out = []
    for n, (name, (i, text)) in enumerate(itertools.product(REWRITES, caught)):
        conversation = turns(name, text)
        if sum(carries for _, carries, _ in conversation) < 2:
            continue
        actions = []
        for message, carries, wait in conversation:
            clock.now += wait + 1
            action = guard.check(message, session_id=f"s{n}", user_id=f"u{n}").action
            if carries:
                actions.append(action)
        out.append(("session", name, i, plain[i], max(actions, key=["allow", "review", "block"].index)))
    return out
