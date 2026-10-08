# Per-tenant TOML policy (layers, modes, rule exceptions); decisions go to siem.py.
#   guard = TenantGuardrail(load_policy("example_bank"))
import json
import logging
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path

from sieve.actions import ACTION_ORDER, ALLOW, BLOCK, ERROR_CHECK, REVIEW, Finding, action_for, error_finding, worst_action
from sieve.checks.indirect import IndirectInjectionLayer
from sieve.documents import DocumentGuard, DocumentResult
from sieve.integrations.siem import emit, fired, to_event
from sieve.integrations.throttle import ConversationWindow, RateLimiter, SessionLimiter
from sieve.ml.injection import MLInjectionLayer, unavailable_reason
from sieve.output import OUTPUT_CHECKS, SAFE_REPLY, OutputGuard, OutputResult
from sieve.paths import POLICIES
from sieve.pipeline import LAYERS, Guardrail, GuardrailResult, default_check_layers, mask
from sieve.rules import RULES, rule_ids
from sieve.timing import add, since
from sieve.tools import CHECK as TOOL_CHECK
from sieve.tools import ToolGuard, ToolResult, spec_problems

POLICY_DIR = POLICIES
MODES = ("enforce", "monitor")
LAYER_MODES = ("enforce", "shadow", "off")
KEYS = {"version", "mode", "on_error", "max_check_chars", "log_excerpt", "log_allowed", "disabled_rules", "masking",
        "layers", "thresholds", "actions", "session", "url_check", "tools"}
# Layers that report a score: a policy can set where review and block start ([thresholds.<layer>]), and the
# decision is made again from the score. The other checks (tool specs, answers, sessions) decide by rule.
SCORED_LAYERS = ("tampering", "prompt_injection_rules", "code_payloads", "url_check", "indirect_injection",
                 "prompt_injection_ml")
NEVER = "never"  # block_at = "never": the layer can review but not block
# What a check that raises means: block (fail closed, the default), review, or allow (fail open, still logged).
ON_ERROR = ("block", "review", "allow")
SESSION_KEYS = {"max_requests_per_minute", "max_chars_per_window", "max_flagged", "cooldown_seconds",
                "window_seconds", "context_messages"}
SESSION_CHECKS = {"session", "session_split"}  # both follow the "session" layer mode

logger = logging.getLogger("sieve")


@dataclass(frozen=True)
class Policy:
    tenant: str
    version: str
    mode: str
    on_error: str
    max_check_chars: int
    log_excerpt: bool
    log_allowed: bool
    disabled_rules: frozenset
    masking: dict
    layers: dict
    thresholds: dict
    actions: dict
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
    if data.get("on_error", "block") not in ON_ERROR:
        problems.append(f"on_error must be one of {ON_ERROR}")
    if ERROR_CHECK in data["disabled_rules"]:
        problems.append(f"{ERROR_CHECK} can't be disabled; set on_error instead")

    masking_names = {layer.name for layer in LAYERS}
    problems += [f"unknown masking layer {k!r}" for k in data["masking"] if k not in masking_names]

    check_names = {layer.name for layer in default_check_layers()} | {"prompt_injection_ml", "session", TOOL_CHECK,
                                                                      IndirectInjectionLayer.name, *OUTPUT_CHECKS}
    problems += [f"unknown layer {k!r}" for k in data["layers"] if k not in check_names]
    problems += [f"layer {k!r}: mode must be one of {LAYER_MODES}" for k, v in data["layers"].items() if v not in LAYER_MODES]

    problems += [f"unknown rule {r!r}" for r in data["disabled_rules"] if r not in RULES]
    problems += threshold_problems(data.get("thresholds", {}))
    problems += action_problems(data.get("actions", {}))
    problems += [f"unknown session key {k!r}" for k in data.get("session", {}) if k not in SESSION_KEYS]
    problems += [p for name, spec in data.get("tools", {}).items() for p in spec_problems(name, spec)]
    if problems:
        raise ValueError(f"{source}: " + "; ".join(problems))


def is_share(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < value <= 1


def action_problems(actions):
    problems = [f"[actions]: unknown rule {r!r}" for r in actions if r not in RULES]
    problems += [f"[actions] {r!r} must be one of {tuple(ACTION_ORDER)}" for r, a in actions.items() if a not in ACTION_ORDER]
    if ERROR_CHECK in actions:
        problems.append(f"[actions]: {ERROR_CHECK} can't be set; set on_error instead")
    return problems


# Both ends have to be written: a layer's own defaults differ, and half a pair would be easy to misread.
def threshold_problems(thresholds):
    problems = []
    for layer, limits in thresholds.items():
        if layer not in SCORED_LAYERS:
            problems.append(f"thresholds: {layer!r} isn't a layer with a score; one of {SCORED_LAYERS}")
        elif not isinstance(limits, dict) or set(limits) != {"review_at", "block_at"}:
            problems.append(f"thresholds.{layer}: needs review_at and block_at, nothing else")
        elif not is_share(limits["review_at"]):
            problems.append(f"thresholds.{layer}: review_at must be above 0 and at most 1")
        elif limits["block_at"] != NEVER and not (is_share(limits["block_at"]) and limits["block_at"] >= limits["review_at"]):
            problems.append(f"thresholds.{layer}: block_at must be \"never\" or between review_at and 1")
    return problems


def load_policy(tenant="default", directory=POLICY_DIR, overrides=None):
    directory = Path(directory)
    data = read_toml(directory / "default.toml")
    if tenant != "default":
        data = merge(data, read_toml(directory / f"{tenant}.toml"))
    if overrides:
        data = merge(data, overrides)
    validate(data, f"policy {tenant!r}")
    # Loosening is the policy's call, but it shouldn't go unnoticed: a rule that no longer counts, a layer
    # that can no longer block.
    loosened = sorted(f"{rule} = allow" for rule, action in data.get("actions", {}).items() if action == ALLOW)
    loosened += sorted(f"{layer} never blocks" for layer, limits in data.get("thresholds", {}).items()
                       if limits.get("block_at") == NEVER)
    if loosened:
        logger.warning("policy %r loosens: %s", tenant, "; ".join(loosened))

    return Policy(
        tenant=tenant,
        version=data["version"],
        mode=data["mode"],
        on_error=data.get("on_error", "block"),
        max_check_chars=data["max_check_chars"],
        log_excerpt=data["log_excerpt"],
        log_allowed=data["log_allowed"],
        disabled_rules=frozenset(data["disabled_rules"]),
        masking=data["masking"],
        layers=data["layers"],
        thresholds=data.get("thresholds", {}),
        actions=data.get("actions", {}),
        session=data.get("session", {}),
        allowed_hosts=tuple(data.get("url_check", {}).get("allowed_hosts", [])),
        tools=data.get("tools", {}),
    )


def build_guardrail(policy):
    # A policy that wants the ML layer but can't have it must not quietly run without it (fail closed at
    # startup); running without it has to be written down as "off".
    ml_mode = policy.layers.get(MLInjectionLayer.name, "enforce")
    if ml_mode != "off" and not MLInjectionLayer.is_available():
        raise ValueError(f"policy {policy.tenant!r}: prompt_injection_ml is {ml_mode!r} but unavailable "
                         f"({unavailable_reason() or 'not available'}); set [layers] prompt_injection_ml = \"off\" "
                         "to run without it")
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
    # system_prompt (and an optional fixed canary) are for the answer check: give the model guard.system_prompt.
    def __init__(self, policy, guardrail=None, clock=time.monotonic, system_prompt="", canary=None):
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
        # The same ML layer as for messages, so its shadow mode and "off" apply to documents and tool arguments too.
        ml = next((layer for layer in self.guard.check_layers if layer.name == MLInjectionLayer.name), None)
        self.tools = ToolGuard(policy.tools, policy.allowed_hosts, ml_layer=ml, use_ml=ml is not None)
        # Documents and answers are masked with the same layers as messages, so the policy's [masking] applies.
        self.documents = DocumentGuard(policy.allowed_hosts, ml_layer=ml, use_ml=ml is not None,
                                       masking_layers=self.guard.masking_layers)
        self.output = OutputGuard(system_prompt, policy.allowed_hosts, masking_layers=self.guard.masking_layers,
                                  canary=canary)

    @property
    def system_prompt(self):
        return self.output.system_prompt

    # How a finding becomes a decision; docs/operations.md, "Karar nasıl veriliyor".
    def apply_policy(self, finding):
        finding = self.apply_actions(self.apply_thresholds(finding))
        if finding.action == ALLOW:
            return finding
        if finding.check == ERROR_CHECK:
            return self.apply_on_error(finding)
        if self.policy.layers.get(layer_of(finding.check)) == "shadow":
            return as_allowed(finding, shadow=True)
        # Only when every rule in the finding is disabled: a partial exception can't
        # recompute the score, so the finding stands (fail closed).
        if all(rule_id in self.policy.disabled_rules for rule_id, _ in rule_ids(finding)):
            return as_allowed(finding, suppressed=True)
        return finding

    # The policy's own thresholds for a scored layer: the layer reports, the policy decides.
    def apply_thresholds(self, finding):
        limits = self.policy.thresholds.get(finding.check)
        if not limits:
            return finding
        block_at = float("inf") if limits["block_at"] == NEVER else limits["block_at"]
        action = action_for(finding.probability, limits["review_at"], block_at)
        return Finding(finding.check, finding.probability, action, finding.matches, finding.level, finding.shadow,
                       finding.would_action, finding.suppressed)

    # The policy's own action for a rule: the check reports what fired, the policy decides what it means. A
    # finding whose rules all have one gets the worst of them. One whose rules only some have can only go up:
    # the others' own actions aren't known any more (fail closed). A finding that fired nothing, like a quiet
    # ML score, has nothing to decide, so "prompt_injection_ml = block" doesn't block every message.
    def apply_actions(self, finding):
        if not self.policy.actions or not fired(finding):
            return finding
        rules = [rule_id for rule_id, _ in rule_ids(finding)]
        chosen = [self.policy.actions[r] for r in rules if r in self.policy.actions]
        if not chosen:
            return finding
        action = max(chosen if len(chosen) == len(rules) else chosen + [finding.action], key=ACTION_ORDER.get)
        if action == ALLOW and finding.action != ALLOW:
            return as_allowed(finding, suppressed=True)
        return Finding(finding.check, finding.probability, action, finding.matches, finding.level, finding.shadow,
                       finding.would_action, finding.suppressed)

    # A failed layer that the policy has in shadow or off wouldn't decide anything anyway; for the others,
    # on_error says what an unchecked message gets.
    def apply_on_error(self, finding):
        layer = finding.matches[0].split(":")[0] if finding.matches else ""
        mode = self.policy.layers.get(layer)
        if mode in ("shadow", "off"):
            return as_allowed(finding, shadow=mode == "shadow", suppressed=mode == "off")
        if self.policy.on_error != BLOCK:
            return Finding(finding.check, finding.probability, self.policy.on_error, finding.matches,
                           would_action=BLOCK)
        return finding

    def enforced_rule(self, rule_id, check):
        return self.policy.layers.get(layer_of(check), "enforce") == "enforce" and rule_id not in self.policy.disabled_rules

    # Rule IDs in these findings (shadow layers, disabled rules and, if asked, allowed findings don't count).
    def local_rules(self, findings, flagged_only=False):
        return {rule_id for f in findings if fired(f) and not f.shadow and not (flagged_only and f.action == ALLOW)
                for rule_id, _ in rule_ids(f) if self.enforced_rule(rule_id, f.check)}

    # Rules that fire on the last few messages joined but on none of them alone. A layer that fails on the joined
    # text is a layer_error like any other, for on_error to decide; the other layers still run.
    def split_attack(self, session, result):
        history = self.conversation.history(session)
        if self.context_messages < 2 or not history:
            return []

        joined = "\n".join([text for text, _ in history] + [result.text])[-self.guard.max_check_chars:]
        joined_findings, errors = [], []
        for layer in self.guard.check_layers:
            try:
                joined_findings += layer.check(joined)
            except Exception as e:
                errors.append(error_finding(layer.name, e))

        seen = set().union(*(rules for _, rules in history)) | self.local_rules(result.findings)
        new = sorted(self.local_rules(joined_findings, flagged_only=True) - seen)
        if not new:
            return errors
        # Joining messages can pair words that were never meant together, so review, never block.
        return errors + [Finding("session_split", 1.0, REVIEW, new)]

    # Findings after shadow modes and exceptions, the action, and the action ignoring shadow/exceptions/monitor mode.
    def decide(self, findings):
        findings = [self.apply_policy(f) for f in findings]
        would_action = max((intended_action(f) for f in findings), key=ACTION_ORDER.get, default=ALLOW)
        action = ALLOW if self.policy.mode == "monitor" else worst_action(findings)
        return findings, action, would_action

    # When the policy code itself raises, the policy can't be trusted: always block, whatever on_error says.
    def failed(self, error, direction, session_id, user_id):
        logger.warning("sieve: %s check failed with %s", direction, type(error).__name__)
        result = GuardrailResult("", BLOCK, [error_finding("policy", error)])
        try:
            emit(to_event(result, BLOCK, self.policy, original="", session_id=session_id, user_id=user_id,
                          direction=direction))
        except Exception:
            pass  # the event may be what failed; the decision stands
        return result

    def check_tool(self, name, args, user_data=None, session_id=None, user_id=None):
        try:
            return self.run_tool(name, args, user_data, session_id, user_id)
        except Exception as e:
            failure = self.failed(e, "tool", session_id, user_id)
            return ToolResult(BLOCK, failure.findings, [f"the check failed: {type(e).__name__}"])

    def check_document(self, text, session_id=None, user_id=None):
        try:
            return self.run_document(text, session_id, user_id)
        except Exception as e:
            return DocumentResult(BLOCK, self.failed(e, "document", session_id, user_id).findings)

    # The model's answer, checked by OutputGuard and then the policy, like a message. Masking and link
    # cleaning always apply; the policy decides whether the answer is shown, reviewed or replaced. An
    # answer whose check failed is never shown, whatever on_error says: there's no checked text to show.
    def check_output(self, answer, user_data=None, session_id=None, user_id=None):
        try:
            return self.run_output(answer, user_data, session_id, user_id)
        except Exception as e:
            return OutputResult(SAFE_REPLY, BLOCK, self.failed(e, "output", session_id, user_id).findings)

    def run_output(self, answer, user_data=None, session_id=None, user_id=None):
        start = time.perf_counter()
        result = self.output.check(answer, user_data)
        timings, policy_start = dict(result.timings), time.perf_counter()
        found = [f for f in result.findings if self.policy.layers.get(f.check) != "off"]
        findings, action, would_action = self.decide(found)
        timings["policy"] = since(policy_start)
        text = SAFE_REPLY if action == BLOCK or result.answer == SAFE_REPLY else result.answer

        if would_action != ALLOW or self.policy.log_allowed:
            logged = GuardrailResult(result.answer, action, findings)
            emit(to_event(logged, would_action, self.policy, original=answer, session_id=session_id, user_id=user_id,
                          direction="output", latency_ms=since(start), timings=timings))
        return OutputResult(text, action, findings, answer=result.answer, timings=timings)

    def check(self, text, session_id=None, user_id=None, direction="input"):
        try:
            return self.run(text, session_id, user_id, direction)
        except Exception as e:
            return self.failed(e, direction, session_id, user_id)

    # A tool call the model wants to make; see tools.py. Logged with direction "tool", arguments masked.
    def run_tool(self, name, args, user_data=None, session_id=None, user_id=None):
        start = time.perf_counter()
        # Totals (max_total, max_calls) count per user, like the session limits.
        who = user_id if user_id is not None else session_id
        result = self.tools.check(name, args, user_data, user_id=who)
        timings, policy_start = dict(result.timings), time.perf_counter()
        found = [f for f in result.findings if self.policy.layers.get(f.check) != "off"]
        findings, action, would_action = self.decide(found)
        timings["policy"] = since(policy_start)

        if would_action != ALLOW or self.policy.log_allowed:
            call = f"{name} {json.dumps(args, ensure_ascii=False, sort_keys=True, default=str)}"
            logged = GuardrailResult(mask(call, self.guard.masking_layers), action, findings)
            emit(to_event(logged, would_action, self.policy, original=call, session_id=session_id, user_id=user_id,
                          direction="tool", latency_ms=since(start), timings=timings))
        return ToolResult(action, findings, result.reasons, timings)

    # A document the model will read (retrieved page, e-mail, tool result); see documents.py.
    def run_document(self, text, session_id=None, user_id=None):
        start = time.perf_counter()
        result = self.documents.check(text)
        timings, policy_start = dict(result.timings), time.perf_counter()
        found = [f for f in result.findings if self.policy.layers.get(f.check) != "off"]
        findings, action, would_action = self.decide(found)
        timings["policy"] = since(policy_start)

        if would_action != ALLOW or self.policy.log_allowed:
            logged = GuardrailResult(mask(text, self.guard.masking_layers), action, findings)
            emit(to_event(logged, would_action, self.policy, original=text, session_id=session_id, user_id=user_id,
                          direction="document", latency_ms=since(start), timings=timings))
        return DocumentResult(action, findings, result.flagged_parts, timings)

    def run(self, text, session_id=None, user_id=None, direction="input"):
        start = time.perf_counter()
        who = user_id if user_id is not None else session_id
        track = self.session_on and direction == "input" and who is not None

        session_findings, session_timing = [], {}
        session_start = time.perf_counter()
        if track:
            names = self.rate.hit(who, len(text))
            if self.limiter.is_limited(who):
                names.append("repeat_offender")
            if names:
                session_findings.append(Finding("session", 1.0, BLOCK, names))
        add(session_timing, "session", session_start)

        result = self.guard.check(text)
        timings = dict(result.timings)
        session_start = time.perf_counter()
        if track and session_id is not None:
            session_findings += self.split_attack(session_id, result)
        add(session_timing, "session", session_start)

        policy_start = time.perf_counter()
        findings, action, would_action = self.decide(list(result.findings) + session_findings)
        timings["policy"] = since(policy_start)

        session_start = time.perf_counter()
        if track:
            # Monitor mode still counts what would have been flagged. Only this message's own findings count (decide
            # keeps the order, so they come first): not the session's, and not a check failing on the history,
            # which says nothing about this message.
            self.limiter.record(who, worst_action(findings[:len(result.findings)]))
            if session_id is not None and self.context_messages >= 2:
                # A reported split counts as seen, so the next messages don't report the same pair again.
                reported = {m for f in session_findings if f.check == "session_split" for m in f.matches}
                self.conversation.add(session_id, result.text, self.local_rules(result.findings) | reported)
        add(session_timing, "session", session_start)
        if track:
            timings.update(session_timing)

        result = GuardrailResult(result.text, action, findings, timings=timings)

        if would_action != ALLOW or self.policy.log_allowed:
            emit(to_event(result, would_action, self.policy, original=text, session_id=session_id, user_id=user_id,
                          direction=direction, latency_ms=since(start), timings=timings))
        return result
