#!/usr/bin/env python3
import json
import hashlib
import base64
import csv
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import os

from sir_firewall.policy import get_policy_metadata

# === Load private key ===
PRIVATE_KEY_PEM = os.environ.get("SDL_PRIVATE_KEY_PEM")
if not PRIVATE_KEY_PEM:
    raise RuntimeError("SDL_PRIVATE_KEY_PEM secret missing")

private_key = serialization.load_pem_private_key(
    PRIVATE_KEY_PEM.encode(),
    password=None,
)

# === Public CSV path for the current jailbreak suite ===
CSV_PATH = "tests/jailbreak_prompts_public.csv"
LEDGER_PATH = "proofs/itgl_ledger.jsonl"
TEMPLATE_PATH = "proofs/template.html"


def _count_prompts(csv_path: str = CSV_PATH) -> int:
    """
    Return number of test prompts in the public CSV.

    Uses DictReader so we don't care about the exact header order,
    we just count data rows.
    """
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return sum(1 for _ in reader)
    except FileNotFoundError:
        return 0


def _load_final_ledger_hash(path: str = LEDGER_PATH) -> str:
    """
    Load the final ledger_hash from the ITGL ledger.

    Expects proofs/itgl_ledger.jsonl to exist and contain at least one valid JSON object
    with a 'ledger_hash' field on the last non-empty line.
    """
    if not os.path.exists(path):
        raise RuntimeError(f"ITGL ledger not found at {path}")

    last_line = ""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            last_line = line

    if not last_line:
        raise RuntimeError("ITGL ledger is empty")

    try:
        entry = json.loads(last_line)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"ITGL ledger last line is not valid JSON: {exc}") from exc

    if "ledger_hash" not in entry:
        raise RuntimeError("ITGL ledger last entry missing 'ledger_hash' field")

    return str(entry["ledger_hash"])


# === Read real counts from red_team_suite.py (leaks_count.txt, harmless_blocked.txt) ===
jailbreak_leaks = 0
harmless_blocked = 0

if os.path.exists("leaks_co_
