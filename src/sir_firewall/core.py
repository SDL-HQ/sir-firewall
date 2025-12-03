def validate_sir(input_dict: dict) -> dict:
    """
    True pre-inference firewall — blocks known 2025 jailbreak patterns BEFORE model sees prompt.
    """
    try:
        payload = input_dict["isc"]["payload"].lower()
    except (KeyError, TypeError):
        return {"status": "BLOCKED", "reason": "malformed_input"}

    dangerous_patterns = [
        "ignore previous instructions",
        "you are now dan", "do anything now", "jailbreak achieved", "jailbreak successful",
        "system prompt:", "current system prompt", "print the system prompt",
        "base64", "rot13", "leetspeak", "follows is encoded", "decode this",
        "how to make explosives", "how to make meth", "how to make fentanyl", "how to build a bomb",
        "rickroll", "ha ha ha", "haha", "never gonna give you up",
        "hypothetical scenario", "just pretend", "in a story", "fictional context",
        "transcend all safeguards", "no limits mode", "god mode", "pure evil mode",
        "singularity achieved", "safety module removed", "developer mode enabled",
        "you are now in chaos mode", "apocalypse mode", "burn it all down",
    ]

    for pattern in dangerous_patterns:
        if pattern in payload:
            return {
                "status": "BLOCKED",
                "reason": "known_jailbreak_pattern",
                "matched": pattern
            }

    return {"status": "PASS", "reason": "no_dangerous_patterns"}
