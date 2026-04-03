#!/usr/bin/env python3
"""Rotate SIR signing keys offline and update key registry."""

from __future__ import annotations

import argparse
import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DEFAULT_REGISTRY = Path("spec/pubkeys/key_registry.v1.json")
DEFAULT_CURRENT_PUB = Path("spec/sdl.pub")
DEFAULT_PUBKEY_DIR = Path("spec/pubkeys")


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_registry(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _new_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv_pem, pub_pem


def main() -> int:
    ap = argparse.ArgumentParser(description="Rotate signing keys and update key registry.")
    ap.add_argument("--registry", default=str(DEFAULT_REGISTRY), help="Key registry JSON path.")
    ap.add_argument("--current-pub", default=str(DEFAULT_CURRENT_PUB), help="Canonical current public key path.")
    ap.add_argument("--pubkey-dir", default=str(DEFAULT_PUBKEY_DIR), help="Directory for historical pubkeys.")
    ap.add_argument("--key-id", help="New key id (default: sdl-<UTC stamp>).")
    ap.add_argument("--private-out", help="Optional private key output path.")
    args = ap.parse_args()

    now = _utc_now_z()
    new_key_id = (args.key_id or f"sdl-{now.replace(':', '').replace('-', '')}").strip()
    registry_path = Path(args.registry)
    registry = _load_registry(registry_path)
    keys = registry.get("keys")
    if not isinstance(keys, list):
        raise SystemExit("ERROR: key registry keys must be a list")

    priv_pem, pub_pem = _new_keypair()

    active_count = 0
    for entry in keys:
        if isinstance(entry, dict) and entry.get("status") == "active":
            entry["status"] = "retired"
            entry.setdefault("valid_until_utc", now)
            active_count += 1

    keys.append(
        {
            "key_id": new_key_id,
            "pubkey_pem": pub_pem,
            "pubkey_base64": base64.b64encode(pub_pem.encode("utf-8")).decode("ascii"),
            "created_utc": now,
            "valid_from_utc": now,
            "status": "active",
            "revocation_reason": "",
        }
    )

    registry["version"] = "v1"
    registry["keys"] = keys
    _write_json(registry_path, registry)

    pubkey_dir = Path(args.pubkey_dir)
    pubkey_dir.mkdir(parents=True, exist_ok=True)
    key_pub_path = pubkey_dir / f"{new_key_id}.pub"
    key_pub_path.write_text(pub_pem, encoding="utf-8")

    current_pub_path = Path(args.current_pub)
    current_pub_path.write_text(pub_pem, encoding="utf-8")

    private_out = Path(args.private_out) if args.private_out else pubkey_dir / f"{new_key_id}.private.pem"
    private_out.write_text(priv_pem, encoding="utf-8")

    print(f"OK: rotated keys; retired active keys: {active_count}")
    print(f"OK: new key_id={new_key_id}")
    print(f"OK: registry updated -> {registry_path}")
    print(f"OK: current public key -> {current_pub_path}")
    print(f"OK: historical public key -> {key_pub_path}")
    print(f"OK: private key -> {private_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
