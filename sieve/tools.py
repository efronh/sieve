# Checks a tool call the model wants to make, before the app runs it.
#   tools = ToolGuard({"para_transferi": {"params": {"iban": "str", "tutar": "number"}, "max": {"tutar": 50000},
#                                         "from_user": ["iban"], "confirm": True}})
#   r = tools.check("para_transferi", {"iban": iban, "tutar": 100}, user_data=[user_message])
from dataclasses import dataclass, field

from sieve.actions import ALLOW, BLOCK, REVIEW, Finding, worst_action
from sieve.checks.code_payloads import CodePayloadLayer
from sieve.checks.prompt_injection import PromptInjectionLayer
from sieve.checks.urls import URLCheckLayer
from sieve.output import PLAIN_URL, carries_data, data_key, host_of, mask_and_collect, only_letters_and_digits, same_data
from sieve.pipeline import LAYERS

TYPES = {"str": (str,), "number": (int, float), "integer": (int,), "bool": (bool,)}
SPEC_KEYS = {"params", "optional", "min", "max", "from_user", "confirm"}
CHECK = "tool_call"


@dataclass
class ToolResult:
    action: str
    findings: list = field(default_factory=list)
    reasons: list = field(default_factory=list)  # one line per problem, e.g. to tell the model why a call was refused


# Typos in a spec must fail loudly: a misspelled limit would silently allow any amount.
def spec_problems(name, spec):
    problems = [f"tool {name!r}: unknown key {k!r}" for k in spec if k not in SPEC_KEYS]
    params = spec.get("params", {})
    problems += [f"tool {name!r}: {p!r} has unknown type {t!r}" for p, t in params.items() if t not in TYPES]
    for key in ("optional", "from_user", "min", "max"):
        problems += [f"tool {name!r}: {key} names unknown parameter {p!r}" for p in spec.get(key, ()) if p not in params]
    for key in ("min", "max"):
        problems += [f"tool {name!r}: {key} of {p!r} needs a number parameter" for p in spec.get(key, {})
                     if params.get(p) not in ("number", "integer")]
    return problems


def has_type(value, name):
    # bool is an int in Python, but True isn't an amount.
    return isinstance(value, TYPES[name]) and (name == "bool" or not isinstance(value, bool))


def strings_in(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in strings_in(v)]
    return []


# Whether the user typed this value themselves: as is (spaces and case aside), or as the same
# personal data written another way (0532... and +90 532... are the same phone number).
def given_by_user(value, texts):
    flat = only_letters_and_digits(str(value))
    if flat and any(flat in only_letters_and_digits(t) for t in texts):
        return True
    values = mask_and_collect(str(value), LAYERS)[1]
    known = [data_key(v) for t in texts for v in mask_and_collect(t, LAYERS)[1]]
    return bool(values) and all(any(same_data(data_key(v), k) for k in known) for v in values)


class ToolGuard:
    def __init__(self, tools, allowed_hosts=()):
        problems = [p for name, spec in tools.items() for p in spec_problems(name, spec)]
        if problems:
            raise ValueError("; ".join(problems))
        self.tools = tools
        self.allowed_hosts = {h.lower() for h in allowed_hosts}
        # Arguments reach another system (a database, a mail, another agent), so the input rules apply to them too.
        self.content_layers = [PromptInjectionLayer(), CodePayloadLayer(), URLCheckLayer(allowed_hosts)]

    def is_allowed(self, url):
        host = host_of(url)
        return any(host == h or host.endswith("." + h) for h in self.allowed_hosts)

    def policy_problems(self, spec, args, user_data):
        params = spec.get("params", {})
        problems = []
        for key, value in args.items():
            if key not in params:
                problems.append(("bad_arguments", BLOCK, f"{key}: unknown parameter"))
            elif not has_type(value, params[key]):
                problems.append(("bad_arguments", BLOCK, f"{key}: expected {params[key]}"))
        problems += [("bad_arguments", BLOCK, f"{key}: missing") for key in params
                     if key not in args and key not in spec.get("optional", ())]

        for key, limit in spec.get("max", {}).items():
            if has_type(args.get(key), "number") and args[key] > limit:
                problems.append(("out_of_range", BLOCK, f"{key}: {args[key]} > {limit}"))
        for key, limit in spec.get("min", {}).items():
            if has_type(args.get(key), "number") and args[key] < limit:
                problems.append(("out_of_range", BLOCK, f"{key}: {args[key]} < {limit}"))

        # Without user_data nothing can be verified, so these go to review (fail closed).
        texts = [user_data] if isinstance(user_data, str) else list(user_data or ())
        problems += [("not_from_user", REVIEW, f"{key}: not in the user's messages") for key in spec.get("from_user", ())
                     if key in args and not given_by_user(args[key], texts)]

        for text in strings_in(args):
            if any(not self.is_allowed(url) and carries_data(url) for url in PLAIN_URL.findall(text)):
                problems.append(("url_with_data", REVIEW, "link carrying data in an argument"))
        if spec.get("confirm"):
            problems.append(("needs_confirmation", REVIEW, "needs the user's confirmation"))
        return problems

    def check(self, name, args, user_data=None):
        spec = self.tools.get(name)
        if spec is None:
            return ToolResult(BLOCK, [Finding(CHECK, 1.0, BLOCK, ["unknown_tool"])], [f"unknown tool {name!r}"])

        problems = self.policy_problems(spec, args, user_data)
        findings = []
        if problems:
            action = worst_action([Finding(CHECK, 1.0, a) for _, a, _ in problems])
            findings.append(Finding(CHECK, 1.0, action, sorted({m for m, _, _ in problems})))

        for text in strings_in(args):
            for layer in self.content_layers:
                findings += [f for f in layer.check(text) if f.matches]

        reasons = [reason for _, _, reason in problems]
        reasons += [f"{f.check}: {', '.join(f.matches)}" for f in findings if f.check != CHECK and f.action != ALLOW]
        return ToolResult(worst_action(findings), findings, reasons)
