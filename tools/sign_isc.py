#!/usr/bin/env python3
"""Sign an ISC envelope for offline validate_sir testing/integration."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def _load_private_key(args: argparse.Namespace) -> Any:
    pem = ""
    if args.private_key_file:
        pem = Path(args.private_key_file).read_text(encoding="utf-8")
    else:
        pem = os.getenv("SDL_PRIVATE_KEY_PEM", "")
    if not pem.strip():
        raise SystemExit("ERROR: provide --private-key-file or SDL_PRIVATE_KEY_PEM")
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


def main() -> int:
    ap = argparse.ArgumentParser(description="Sign ISC JSON and emit validate_sir-compatible envelope.")
    ap.add_argument("--in", dest="in_path", required=True, help="Input ISC JSON (either {isc:{...}} or raw isc object).")
    ap.add_argument("--out", dest="out_path", required=True, help="Output path for signed envelope JSON.")
    ap.add_argument("--private-key-file", help="PEM private key path (fallback: SDL_PRIVATE_KEY_PEM env).")
    ap.add_argument("--key-id", default=(os.getenv("SDL_SIGNING_KEY_ID") or "default"), help="Signing key id.")
    args = ap.parse_args()

    key = _load_private_key(args)
    raw = json.loads(Path(args.in_path).read_text(encoding="utf-8"))
    isc = raw.get("isc") if isinstance(raw, dict) and isinstance(raw.get("isc"), dict) else raw
    if not isinstance(isc, dict):
        raise SystemExit("ERROR: input must be ISC object or envelope with top-level 'isc'")

    payload = str(isc.get("payload", ""))
    if not payload:
        raise SystemExit("ERROR: isc.payload is required")

    checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    signature = key.sign(payload.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())

    signed_isc: Dict[str, Any] = dict(isc)
    signed_isc["checksum"] = checksum
    signed_isc["signature"] = base64.b64encode(signature).decode("ascii")
    signed_isc["key_id"] = args.key_id

    out = {"isc": signed_isc}
    Path(args.out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_path).write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"OK: wrote signed ISC envelope -> {args.out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
