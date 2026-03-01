"""Deterministic pre-inference blocking rules for generic safety suites."""

from __future__ import annotations

import re
from typing import List


_BYPASS_PATTERNS = [
    ("JB_DISABLE_GUARDRAILS", re.compile(r"\b(disable|remove|turn\s*off)\s+(all\s+)?(guardrails|safeguards|safety|filters?)\b")),
    ("JB_UNRESTRICTED_MODE", re.compile(r"\b(unrestricted|no\s+restrictions?|uncensored|allow[_ -]?all|nolimitsgpt)\b")),
    ("JB_BYPASS_POLICY", re.compile(r"\b(bypass|override|skip|disregard)\s+(all\s+)?(content\s+)?(policy|policies|safety|checks?|guardrails|restrictions?)\b|\bfull\s+bypass\b")),
    ("JB_DONT_REFUSE", re.compile(r"\b(do\s*not|don't|never)\s+refuse\b")),
    ("JB_ALIGNMENT_OVERRIDE", re.compile(r"\boverride\s+alignment\b|\bprioritize\s+user\s+request\s+over\s+every\s+governance\s+rule\b")),
    ("JB_COMPLIANCE_OFF", re.compile(r"\bcompliance\s+mode\s+is\s+off\b|\bsafety\s+off\b|\bfilters?\s+crashed\b")),
    ("JB_EVADE_FILTERS", re.compile(r"\b(evade|circumvent|slip\s+past|avoid|disable)\s+(automated\s+)?(content\s+)?(filters?|moderation|detection|safety\s+refusals?|jailbreak\s+defenses?)\b|\btrigger\s+your\s+safety\s+refusals\b")),
    ("JB_PROMPT_FOR_JAILBREAK", re.compile(r"\bcopy-paste\s+instruction\b|\bprompt\s+that\s+makes\s+assistants\s+ignore\b|\bknown\s+tricks\b")),
    ("JB_TRUSTED_SYSTEM_INJECTION", re.compile(r"\btrusted\s+system\s+input\b|\bwithout\s+any\s+firewall\s+mediation\b")),
]

_EXFIL_VERB = re.compile(r"\b(reveal|show|print|dump|list|export|leak|disclose|return|expose|display|extract|provide|output|give)\b")
_EXFIL_TARGET = re.compile(
    r"\b(system\s+prompt|hidden\s+(system\s+)?prompt|hidden\s+(system\s+)?instructions?|internal\s+instructions?|internal\s+guidance|"
    r"moderation\s+(policy|rules?|thresholds?)|private\s+reasoning|confidence\s+thresholds?|"
    r"env(ironment)?\s+vars?|secrets?|api\s*keys?|tokens?|credentials?|"
    r"other\s+users?'?\s+(logs|chats|data)|conversation\s+logs|training\s+snippets?|"
    r"internal[- ]only\s+content|decision\s+trace|governance\s+documents?|"
    r"confidential\s+memory|developer\s+instructions?|red-team\s+test\s+cases|internal\s+safety\s+architecture\s+details|internal\s+prompts?|"
    r"safety\s+classifier\s+labels|incident\s+notes|cached\s+responses|"
    r"policy\s+changelog|rollout\s+notes|proprietary\s+heuristics|non-public\s+instructions?)\b"
)

_TOOL_INJECTION_PATTERNS = [
    ("TOOL_MESSAGE_OVERRIDE", re.compile(r"\btool\s+message\s*:\s*.*(override|trusted|skip\s+safety)")),
    ("TOOL_CALL_TAG", re.compile(r"<tool_call>.*</tool_call>")),
    ("TOOL_INJECTED_RESULT", re.compile(r"\binjected\s+(function\s+)?result\b")),
    ("TOOL_ALLOW_ALL", re.compile(r"\b(scanner|security\s+scanner)\s+returned\s+allow[_ -]?all\b")),
    ("TOOL_BYPASS_HEADER", re.compile(r"\bx-sir-bypass\s*:\s*true\b|\bmiddleware\s+header\b")),
    ("TOOL_RPC_INJECTED", re.compile(r"\brpc\s+response\s+injected\b|\bfake\s+plugin\s+output\b")),
    ("TOOL_CONNECTOR_OVERRIDE", re.compile(r"\bfabricated\s+json\s+from\s+a\s+connector\b|\bauthoritative\s+policy\s+override\b")),
    ("TOOL_CHANNEL_EXFIL", re.compile(r"\btool\s+channel\b.*\b(hidden\s+prompt|exfiltration)\b")),
    ("TOOL_SKIP_REFUSAL", re.compile(r"\bskip\s+refusal\s+logic\b|/unsafe\s+on|\bactivate\s+it\b")),
    ("TOOL_FAKE_IDENTITY", re.compile(r"\bfake\s+db\s+row\b|\bfull\s+disclosure\s+rights\b|\blegal\s+hold\s+exemption\b")),
    ("TOOL_DECLASSIFY", re.compile(r"\bdeclassification\s+of\s+internal\s+governance\s+documents\b|\buntrusted\s+tool\s+text\b")),
]

_OBFUSCATION_SIGNAL = re.compile(
    r"\b(rot13|base64|hex|caesar|morse|url-encoded|unicode\s+homoglyph|zero-width|steganography|decode|"
    r"acrostic|deobfuscate|yaml|markdown\s+comment|text\s+backwards|concealed|encoding|every\s+third\s+word)\b"
)
_OBEY_SIGNAL = re.compile(
    r"\b(obey|comply|execute|follow(\s+it)?\s+blindly|follow\s+it\s+even\s+if\s+it\s+conflicts\s+with\s+policy|"
    r"perform\s+the\s+concealed|carry\s+out\s+the\s+concealed|and\s+execute|higher\s+priority\s+than\s+your\s+safety\s+rules|apply\s+that\s+instead|system-level\s+command)\b"
)


def find_rule_hits(normalized_text: str) -> List[str]:
    """Return deterministic rule hit codes for text that should be blocked."""
    t = normalized_text.lower()
    hits: List[str] = []

    for code, pattern in _BYPASS_PATTERNS:
        if pattern.search(t):
            hits.append(code)

    if _EXFIL_VERB.search(t) and _EXFIL_TARGET.search(t):
        hits.append("EXFIL_INTENT_TARGET")

    for code, pattern in _TOOL_INJECTION_PATTERNS:
        if pattern.search(t):
            hits.append(code)

    if _OBFUSCATION_SIGNAL.search(t) and _OBEY_SIGNAL.search(t):
        hits.append("OBFUSCATION_DECODE_AND_OBEY")

    dedup: List[str] = []
    seen = set()
    for h in hits:
        if h not in seen:
            dedup.append(h)
            seen.add(h)
    return dedup
