from dataclasses import dataclass, field
from typing import Optional

ALLOW, REVIEW, BLOCK = "allow", "review", "block"
ACTION_ORDER = {ALLOW: 0, REVIEW: 1, BLOCK: 2}


@dataclass
class Finding:
    check: str
    probability: float
    action: str
    matches: list = field(default_factory=list)
    level: Optional[str] = None
    shadow: bool = False  # logged only, never changes the result
    would_action: Optional[str] = None  # the action before shadow mode or a policy exception
    suppressed: bool = False  # every rule in it is disabled by the tenant policy


def action_for(score, review_at, block_at):
    if score >= block_at:
        return BLOCK
    if score >= review_at:
        return REVIEW
    return ALLOW


def worst_action(findings):
    return max((f.action for f in findings), key=ACTION_ORDER.get, default=ALLOW)
