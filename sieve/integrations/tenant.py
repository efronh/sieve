# Per-tenant TOML policy (layers, modes, rule exceptions); decisions go to siem.py.
#   guard = TenantGuardrail(load_policy("example_bank"))
import json
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path

from sieve.actions import ACTION_ORDER, ALLOW, BLOCK, REVIEW, Finding, worst_action
from sieve.integrations.siem import emit, fired, to_event
from sieve.integrations.throttle import ConversationWindow, RateLimiter, SessionLimiter
from sieve.paths import POLICIES
from sieve.pipeline import LAYERS, Guardrail, GuardrailResult, default_check_layers, mask
from sieve.rules import RULES, rule_ids
from sieve.tools import CHECK as TOOL_CHECK
from sieve.tools import ToolGuard, ToolResult, spec_problems

POLICY_DIR = POLICIES
MODES = ("enforce", "monitor")
LAYER_MODES = ("enforce", "shadow", "off")
KEYS = {"version", "mode", "max_check_chars", "log_excerpt", "log_allowed", "disabled_rules", "masking", "layers",
        "session", "url_check", "tools"}
SESSION_KEYS = {"max_requests_per_minute", "max_chars_per_window", "max_flagged", "cooldown_seconds",
                "window_seconds", "context_messages"}
SESSION_CHECKS = {"session", "session_split"}  # both follow the "session" layer mode


@dataclass(frozen=True)
class Policy:
    tenant: str
    version: str
    mode: str
    max_check_chars: int
    log_excerpt: bool
    log_allowed: bool
    disabled_rules: frozenset
    masking: dict
    layers: dict
    session: dict
    allowed_hosts: tuple
    tools: dict


def merge(base, override):
    result = dict(base)
    for key, value in override.items():
        result[key] = merge(base[key], value) if isinstance(value, dict) and isinstance(base.get(key), dict) else value
    return result


def read_toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


# Typos in a policy must fail loudly: a misspelled rule ID would silently keep the rule on.
def validate(data, source):
    problems = [f"unknown key {k!r}" for k in data if k not in KEYS]
    if data["mode"] not in MODES:
        problems.append(f"mode must be one of {MODES}")

    masking_names = {layer.name for layer in LAYERS}
    problems += [f"unknown masking layer {k!r}" for k in data["masking"] if k not in masking_names]

    check_names = {layer.name for layer in default_check_layers()} | {"prompt_injection_ml", "session", TOOL_CHECK}
    problems += [f"unknown layer {k!r}" for k in data["layers"] if k not in check_names]
    problems += [f"layer {k!r}: mode must be one of {LAYER_MODES}" for k, v in data["layers"].items() if v not in LAYER_MODES]

    problems += [f"unknown rule {r!r}" for r in data["disabled_rules"] if r not in RULES]
    problems += [f"unknown session key {k!r}" for k in data.get("session", {}) if k not in SESSION_KEYS]
    problems += [p for name, spec in data.get("tools", {}).items() for p in spec_problems(name, spec)]
    if problems:
        raise ValueError(f"{source}: " + "; ".join(problems))


def load_policy(tenant="default", directory=POLICY_DIR, overrides=None):
    directory = Path(directory)
    data = read_toml(directory / "default.toml")
    if tenant != "default":
        data = merge(data, read_toml(directory / f"{tenant}.toml"))
    if overrides:
        data = merge(data, overrides)
    validate(data, f"policy {tenant!r}")

    return Policy(
        tenant=tenant,
        version=data["version"],
        mode=data["mode"],
        max_check_chars=data["max_check_chars"],
        log_excerpt=data["log_excerpt"],
        log_allowed=data["log_allowed"],
        disabled_rules=frozenset(data["disabled_rules"]),
        masking=data["masking"],
        layers=data["layers"],
        session=data.get("session", {}),
        allowed_hosts=tuple(data.get("url_check", {}).get("allowed_hosts", [])),
        tools=data.get("tools", {}),
    )


def build_guardrail(policy):
    masking = [layer for layer in LAYERS if policy.masking.get(layer.name, True)]

    checks = []
    for layer in default_check_layers():
        mode = policy.layers.get(layer.name, "enforce")
        if mode == "off":
            continue
        if layer.name == "url_check":
            layer.allowed_hosts = {h.lower() for h in policy.allowed_hosts}
        if layer.name == "prompt_injection_ml":
            layer.shadow = mode == "shadow"
        checks.append(layer)

    return Guardrail(masking_layers=masking, check_layers=checks, max_check_chars=policy.max_check_chars)


# What the layer wanted before shadow mode or an exception; the ML layer's own shadow mode
# records it as "would_review" in matches.
def intended_action(finding):
    if finding.would_action:
        return finding.would_action
    marker = next((m for m in finding.matches if m.startswith("would_")), None)
    return marker[len("would_"):] if marker else finding.action


def as_allowed(finding, **flags):
    return Finding(finding.check, finding.probability, ALLOW, finding.matches, finding.level,
                   would_action=finding.action, **flags)


def layer_of(check):
    return "session" if check in SESSION_CHECKS else check


class TenantGuardrail:
    def __init__(self, policy, guardrail=None, clock=time.monotonic):
        self.policy = policy
        self.guard = guardrail or build_guardrail(policy)

        limits = policy.session
        self.session_on = policy.layers.get("session", "enforce") != "off"
        window = limits.get("window_seconds", 600)
        self.rate = RateLimiter(limits.get("max_requests_per_minute", 30), limits.get("max_chars_per_window", 50_000),
                                window, clock)
        self.limiter = SessionLimiter(limits.get("max_flagged", 3), window, limits.get("cooldown_seconds", 900), clock)
        self.context_messages = limits.get("context_messages", 4)
        self.conversation = ConversationWindow(self.context_messages, window, clock)
        self.tools = ToolGuard(policy.tools, policy.allowed_hosts)

    def apply_policy(self, finding):
        if finding.action == ALLOW:
            return finding
        if self.policy.layers.get(layer_of(finding.check)) == "shadow":
            return as_allowed(finding, shadow=True)
        # Only when every rule in the finding is disabled: a partial exception can't
        # recompute the score, so the finding stands (fail closed).
        if all(rule_id in self.policy.disabled_rules for rule_id, _ in rule_ids(finding)):
            return as_allowed(finding, suppressed=True)
        return finding

    def enforced_rule(self, rule_id, check):
        return self.policy.layers.get(layer_of(check), "enforce") == "enforce" and rule_id not in self.policy.disabled_rules

    # Rule IDs in these findings (shadow layers, disabled rules and, if asked, allowed findings don't count).
    def local_rules(self, findings, flagged_only=False):
        return {rule_id for f in findings if fired(f) and not f.shadow and not (flagged_only and f.action == ALLOW)
                for rule_id, _ in rule_ids(f) if self.enforced_rule(rule_id, f.check)}

    # Rules that fire on the last few messages joined but on none of them alone.
    def split_attack(self, session, result):
        history = self.conversation.history(session)
        if self.context_messages < 2 or not history:
            return []

        joined = "\n".join([text for text, _ in history] + [result.text])[-self.guard.max_check_chars:]
        joined_findings = []
        for layer in self.guard.check_layers:
            joined_findings += layer.check(joined)

        seen = set().union(*(rules for _, rules in history)) | self.local_rules(result.findings)
        new = sorted(self.local_rules(joined_findings, flagged_only=True) - seen)
        if not new:
            return []
        # Joining messages can pair words that were never meant together, so review, never block.
        return [Finding("session_split", 1.0, REVIEW, new)]

    # Findings after shadow modes and exceptions, the action, and the action ignoring shadow/exceptions/monitor mode.
    def decide(self, findings):
        findings = [self.apply_policy(f) for f in findings]
        would_action = max((intended_action(f) for f in findings), key=ACTION_ORDER.get, default=ALLOW)
        action = ALLOW if self.policy.mode == "monitor" else worst_action(findings)
        return findings, action, would_action

    # A tool call the model wants to make; see tools.py. Logged with direction "tool", arguments masked.
    def check_tool(self, name, args, user_data=None, session_id=None, user_id=None):
        start = time.perf_counter()
        result = self.tools.check(name, args, user_data)
        found = [f for f in result.findings if self.policy.layers.get(f.check) != "off"]
        findings, action, would_action = self.decide(found)

        if would_action != ALLOW or self.policy.log_allowed:
            call = f"{name} {json.dumps(args, ensure_ascii=False, sort_keys=True, default=str)}"
            logged = GuardrailResult(mask(call, self.guard.masking_layers), action, findings)
            emit(to_event(logged, would_action, self.policy, original=call, session_id=session_id, user_id=user_id,
                          direction="tool", latency_ms=(time.perf_counter() - start) * 1000))
        return ToolResult(action, findings, result.reasons)

    def check(self, text, session_id=None, user_id=None, direction="input"):
        start = time.perf_counter()
        who = user_id if user_id is not None else session_id
        track = self.session_on and direction == "input" and who is not None

        session_findings = []
        if track:
            names = self.rate.hit(who, len(text))
            if self.limiter.is_limited(who):
                names.append("repeat_offender")
            if names:
                session_findings.append(Finding("session", 1.0, BLOCK, names))

        result = self.guard.check(text)
        if track and session_id is not None:
            session_findings += self.split_attack(session_id, result)

        findings, action, would_action = self.decide(list(result.findings) + session_findings)

        if track:
            # Monitor mode still counts what would have been flagged; session findings themselves don't.
            self.limiter.record(who, worst_action([f for f in findings if f.check not in SESSION_CHECKS]))
            if session_id is not None and self.context_messages >= 2:
                # A reported split counts as seen, so the next messages don't report the same pair again.
                reported = {m for f in session_findings if f.check == "session_split" for m in f.matches}
                self.conversation.add(session_id, result.text, self.local_rules(result.findings) | reported)

        result = GuardrailResult(result.text, action, findings)

        if would_action != ALLOW or self.policy.log_allowed:
            emit(to_event(result, would_action, self.policy, original=text, session_id=session_id, user_id=user_id,
                          direction=direction, latency_ms=(time.perf_counter() - start) * 1000))
        return result
