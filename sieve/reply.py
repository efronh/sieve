# The order Sieve's guarantees depend on, in one call: the model is asked only when the input check
# didn't block or fail, and its answer reaches the user only through OutputGuard.
#   out = OutputGuard(SYSTEM_PROMPT)
#   reply = guarded_reply(message, ask_model, Guardrail(), out)   # ask_model(system, user) -> str
#   show(reply.text)                                              # reply.action: allow / review / block
# With a TenantGuardrail, leave output_guard out: the answer then goes through its policy too.
#   reply = guarded_reply(message, ask_model, TenantGuardrail(policy, system_prompt=SYSTEM_PROMPT),
#                         session_id=session, user_id=user)
# The guards fail closed on their own; this also holds for any other guard object passed in.
from dataclasses import dataclass
from typing import Optional

from sieve.actions import BLOCK, error_finding, worst_action
from sieve.output import SAFE_REPLY, OutputResult
from sieve.pipeline import GuardrailResult

BLOCKED_MESSAGE = "Bu mesaj güvenlik nedeniyle işlenemedi."


@dataclass
class Reply:
    text: str  # what to show the user
    action: str  # the worse of the input and the output decision
    model_called: bool
    checked: GuardrailResult  # the input check
    shown: Optional[OutputResult] = None  # the output check, if the model was asked


# check_args go to guard.check, e.g. session_id and user_id for a TenantGuardrail, and to its answer
# check. user_data is what this user may see, for the new-personal-data check; by default, their own
# message. An error from ask_model itself isn't caught: no unchecked text can come of it.
def guarded_reply(message, ask_model, guard, output_guard=None, user_data=None, **check_args):
    if output_guard is None:  # a TenantGuardrail checks answers itself, through its policy
        system_prompt = guard.system_prompt

        def check_answer(answer, user_data):
            return guard.check_output(answer, user_data, **check_args)
    else:
        system_prompt, check_answer = output_guard.system_prompt, output_guard.check

    try:
        checked = guard.check(message, **check_args)
    except Exception as e:
        checked = GuardrailResult("", BLOCK, [error_finding("input", e)])
    if checked.action == BLOCK:
        return Reply(BLOCKED_MESSAGE, BLOCK, False, checked)

    answer = ask_model(system_prompt, checked.text)
    try:
        shown = check_answer(answer, [message] if user_data is None else user_data)
    except Exception as e:
        shown = OutputResult(SAFE_REPLY, BLOCK, [error_finding("output", e)])
    return Reply(shown.text, worst_action([checked, shown]), True, checked, shown)
