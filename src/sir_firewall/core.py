# src/sir_firewall/core.py

import base64
import codecs
import hashlib
import json
import re
import time
from typing import Any, Dict, List, Tuple

# Deliberately unused — kept as a loud reminder that we win without it
USE_SEMANTIC_CHECK = False

# ---------------------------------------------------------------------------
# Configuration (v1 defaults — safe but iterative)
# ---------------------------------------------------------------------------

# Required ISC envelope fields
REQUIRED_ISC_FIELDS = ["version", "template_id", "payload", "checksum", "signature"]

# Allow-listed ISC templates
ALLOWED_TEMPLATES = {
    "HIPAA-ISC-v1",
    "EU-AI-Act-ISC-v1",
    "PCI-DSS-ISC-v1",
}

# Simple friction limits by template (rough token caps)
MAX_FRICTION_BY_TEMPLATE = {
    "HIPAA-ISC-v1": 1500,
    "EU-AI-Act-ISC-v1": 2000,
    "PCI-DSS-ISC-v1": 1200,
}

# Fail-closed on malformed / disallowed ISC?
STRICT_ISC_ENFORCEMENT = True

# Enforce checksum strictly
CHECKSUM_ENFORCED = True

# Enforce RSA signature strictly (leave False until keys are wired)
CRYPTO_ENFORCED = False

# Fill with real PEM strings before enabling CRYPTO_ENFORCED
PUBLIC_KEYS: Dict[str, str] = {
    # "default": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki...\n-----END PUBLIC KEY-----",
}

# Genesis hash for ITGL chain
GENESIS_HASH = "0" * 64

# Optional cryptography — graceful fallback
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    _CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover
    _CRYPTO_AVAILABLE = False


# ---------------------------------------------------------------------------
# Obfuscation normalisation
# ---------------------------------------------------------------------------

def normalize_obfuscation(text: str) -> str:
    """
    Normalise common obfuscation tricks:
    - Zero-width / exotic whitespace
    - Base64 blobs that
