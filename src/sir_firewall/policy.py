import json
import os
import hashlib
from pathlib import Path
from typing import Any, Dict, Tuple


class PolicyLoadError(RuntimeError):
    """Raised when a policy cannot be loaded in non-dev mode."""


def _default_policy_path() -> Path:
    """
    Resolve the default policy file location.

    Repo layout is assumed to be:
    repo_root/
      policy/isc_policy.json
      src/sir_firewall/policy.py  (this file)
    """
    # sir_firewall/ -> src/ -> repo_root/
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "policy" / "isc_policy.json"


def _load_policy_dict() -> Tuple[Dict[str, Any], Path]:
    """Load the policy JSON from disk, respecting SIR_POLICY_PATH override."""
    env_path = os.getenv("SIR_POLICY_PATH")
    if env_path:
        path = Path(env_path).expanduser().resolve()
    else:
        path = _default_policy_path()

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise PolicyLoadError("Policy file must contain a JSON object at the top level.")

    return data, path


def _normalise_policy_bytes(policy: Dict[str, Any]) -> bytes:
    """
    Normalise policy for hashing:
    - stable key ordering
    - no extra whitespace
    """
    return json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _dev_mode_stub() -> Dict[str, Any]:
    """
    Minimal stub policy used only when:
    - policy file is missing or invalid, AND
    - SIR_DEV_MODE=1 is set in the environment.

    This keeps local development usable without hiding failures in governance mode.
    """
    return {
        "version": "DEV-MODE",
        "templates": {
            "DEV": {
                "description": "Development-only stub policy",
                "friction_cap": 0,
            }
        },
        "flags": {
            "STRICT_ISC_ENFORCEMENT": False,
            "CHECKSUM_ENFORCED": False,
            "CRYPTO_ENFORCED": False,
        },
        "rules": {
            "danger_words": [],
            "safety_phrases": [],
            "high_risk_patterns": [],
        },
    }


def _initialise_policy() -> Tuple[Dict[str, Any], str, str, Path]:
    """
    Load policy + metadata at import time.

    Behaviour:
    - In normal mode: failure to load policy raises PolicyLoadError.
    - In DEV mode (SIR_DEV_MODE=1): fall back to stub policy with hash/version markers.
    """
    dev_mode = os.getenv("SIR_DEV_MODE") == "1"

    try:
        policy_dict, path = _load_policy_dict()
    except (FileNotFoundError, json.JSONDecodeError, PolicyLoadError) as exc:
        if not dev_mode:
            raise PolicyLoadError(f"Failed to load ISC policy: {exc}") from exc
        policy_dict = _dev_mode_stub()
        path = Path("<DEV-MODE-POLICY>")

    version = str(policy_dict.get("version", "unknown"))
    policy_hash = hashlib.sha256(_normalise_policy_bytes(policy_dict)).hexdigest()

    return policy_dict, version, policy_hash, path


# Import-time load so downstream code can just read the metadata.
POLICY, POLICY_VERSION, POLICY_HASH, POLICY_PATH = _initialise_policy()


def get_policy_metadata() -> Dict[str, str]:
    """
    Convenience accessor for cert generation / logging.
    """
    return {
        "version": POLICY_VERSION,
        "hash": POLICY_HASH,
        "path": str(POLICY_PATH),
    }
