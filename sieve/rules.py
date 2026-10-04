# Stable rule IDs (<layer>.<match>) for SIEM correlation. Never rename one;
# test_rules.py fails if a layer emits an ID that isn't listed here.
# owasp: our OWASP LLM Top 10 (2025) mapping. severity: 1-10.
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Rule:
    owasp: Optional[str]
    severity: int
    title: str


PI, SID, OUT, AGENCY, LEAK, DOS = "LLM01:2025", "LLM02:2025", "LLM05:2025", "LLM06:2025", "LLM07:2025", "LLM10:2025"

RULES = {
    # pipeline.py
    "input_length": Rule(DOS, 4, "Input longer than the checked window"),

    # integrations/throttle.py, via integrations/tenant.py
    "session.rate_limit": Rule(DOS, 5, "Too many requests per minute"),
    "session.volume_limit": Rule(DOS, 5, "Too much text in the window"),
    "session.repeat_offender": Rule(PI, 6, "Session paused after repeated flagged messages"),
    "session_split": Rule(PI, 7, "Attack split across messages"),

    # checks/tampering.py
    "tampering.hidden_tag_chars": Rule(PI, 9, "Invisible Unicode tag characters"),
    "tampering.direction_override": Rule(PI, 5, "Bidirectional text override"),
    "tampering.terminal_escape": Rule(PI, 5, "Terminal escape sequence"),
    "tampering.many_invisible_chars": Rule(PI, 5, "Many zero-width characters"),
    "tampering.variation_selector_payload": Rule(PI, 5, "Variation selector payload"),
    "tampering.mixed_alphabet_word": Rule(PI, 6, "Mixed alphabets inside one word"),

    # checks/prompt_injection.py
    "prompt_injection_rules.ignore_instructions": Rule(PI, 9, "Ignore previous instructions"),
    "prompt_injection_rules.reveal_system_prompt": Rule(LEAK, 9, "Reveal the system prompt"),
    "prompt_injection_rules.no_limits": Rule(PI, 5, "Answer without restrictions"),
    "prompt_injection_rules.jailbreak_word": Rule(PI, 5, "Jailbreak mentioned"),
    "prompt_injection_rules.jailbreak_request": Rule(PI, 9, "Jailbreak mode requested"),
    "prompt_injection_rules.do_anything_now": Rule(PI, 9, "DAN prompt"),
    "prompt_injection_rules.bypass_safety": Rule(PI, 5, "Bypass filters or safety"),
    "prompt_injection_rules.special_mode": Rule(PI, 3, "Developer / admin mode"),
    "prompt_injection_rules.fake_system_tag": Rule(PI, 8, "Fake chat template tag"),
    "prompt_injection_rules.fake_system_line": Rule(PI, 3, "Fake system line"),
    "prompt_injection_rules.new_task": Rule(PI, 3, "New task or instructions"),
    "prompt_injection_rules.new_identity": Rule(PI, 4, "New identity for the assistant"),
    "prompt_injection_rules.role_play": Rule(PI, 3, "Role play request"),
    "prompt_injection_rules.hidden_encoded": Rule(PI, 3, "Attack hidden in an encoding"),

    # checks/code_payloads.py
    "code_payloads.sql_tautology": Rule(OUT, 6, "SQL tautology"),
    "code_payloads.sql_comment_bypass": Rule(OUT, 6, "SQL comment bypass"),
    "code_payloads.sql_union_select": Rule(OUT, 6, "SQL UNION SELECT"),
    "code_payloads.sql_stacked_query": Rule(OUT, 6, "SQL stacked query"),
    "code_payloads.sql_time_delay": Rule(OUT, 6, "SQL time delay"),
    "code_payloads.shell_destroy": Rule(OUT, 6, "Destructive shell command"),
    "code_payloads.shell_pipe_to_shell": Rule(OUT, 6, "Download piped to shell"),
    "code_payloads.shell_chained_command": Rule(OUT, 5, "Chained shell command"),
    "code_payloads.path_traversal": Rule(OUT, 6, "Path traversal"),
    "code_payloads.sensitive_file": Rule(OUT, 4, "Sensitive file path"),
    "code_payloads.script_tag": Rule(OUT, 6, "Script injection"),
    "code_payloads.template_injection": Rule(OUT, 6, "Template / JNDI injection"),

    # checks/urls.py (rule IDs keep the old layer name "url_check": SIEM rules depend on it)
    "url_check.dangerous_scheme": Rule(OUT, 9, "javascript: / data: URL"),
    "url_check.credentials_in_url": Rule(None, 6, "Credentials in URL"),
    "url_check.ip_address_host": Rule(AGENCY, 5, "Raw IP address link"),
    "url_check.punycode_host": Rule(None, 5, "Punycode host"),
    "url_check.many_subdomains": Rule(None, 3, "Many subdomains"),
    "url_check.brand_lookalike": Rule(None, 5, "Brand lookalike domain"),

    # ml/injection.py, llm/layer.py: one score each, no match names
    "prompt_injection_ml": Rule(PI, 5, "ML prompt injection score"),
    "prompt_injection": Rule(PI, 6, "LLM: prompt injection"),
    "abuse": Rule(None, 5, "LLM: abuse"),
    "personal_data": Rule(SID, 4, "LLM: leftover personal data"),

    # output.py
    "canary.system_prompt_leak": Rule(LEAK, 10, "Canary from the system prompt in the answer"),
    "prompt_overlap": Rule(LEAK, 7, "Answer repeats the system prompt"),
    "output_links.dangerous_link": Rule(OUT, 7, "Dangerous link in the answer"),
    "output_links.link_with_data": Rule(SID, 7, "Link carrying data in the answer"),
    "output_links.reference_with_data": Rule(SID, 7, "Reference link carrying data"),
    "output_links.url_with_data": Rule(SID, 7, "URL carrying data in the answer"),
    "output_links.image_with_data": Rule(SID, 8, "Image URL carrying data"),
    "output_links.external_image": Rule(None, 2, "External image removed"),
    "output_masking.personal_data_masked": Rule(SID, 3, "Personal data masked in the answer"),
    "output_masking.new_personal_data": Rule(SID, 7, "Answer has personal data the user didn't give"),

    # tools.py (plus the input rules above, run on string arguments)
    "tool_call.unknown_tool": Rule(AGENCY, 8, "Tool not in the allowlist"),
    "tool_call.bad_arguments": Rule(AGENCY, 6, "Tool arguments don't match the spec"),
    "tool_call.out_of_range": Rule(AGENCY, 8, "Tool argument outside its limits"),
    "tool_call.not_from_user": Rule(AGENCY, 7, "Tool argument the user didn't give"),
    "tool_call.url_with_data": Rule(SID, 7, "URL carrying data in a tool argument"),
    "tool_call.needs_confirmation": Rule(AGENCY, 2, "Tool call needs the user's confirmation"),
}

# Layers whose match text is a detail ("12000 chars"), not a rule name.
DETAIL_ONLY = {"input_length", "prompt_overlap", "session_split"}


# Shadow markers like would_review are not rules.
def rule_ids(finding):
    names = [m for m in finding.matches if not m.startswith("would_")]
    if finding.check in DETAIL_ONLY or not names:
        return [(finding.check, ", ".join(names) or None)]
    return [(f"{finding.check}.{name}", None) for name in names]


def rule_info(rule_id):
    return RULES.get(rule_id, Rule(None, 5, rule_id))
