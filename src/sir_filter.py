# --- ADD AT TOP ---
from hmac import compare_digest
MAX_INPUT_BYTES = 1_048_576  # 1MB

# --- REPLACE validate_sir() ---
def validate_sir(input_data: Any) -> Dict[str, Any]:
    try:
        # EARLY SIZE GUARD
        if isinstance(input_data, str) and len(input_data.encode()) > MAX_INPUT_BYTES:
            return reject("Input exceeds size limit")

        input_json = json.loads(input_data) if isinstance(input_data, str) else input_data
        isc = input_json.get("isc", {})
        
        required = ["version", "template_id", "provenance", "payload", "checksum"]
        if not all(k in isc for k in required):
            return reject("Missing required ISC fields")

        # WHITELIST
        if isc["template_id"] not in WHITELIST:
            return reject("Unapproved governance template")

        # CANONICAL ENVELOPE (for checksum + signature)
        envelope_parts = [
            str(isc["version"]),
            isc["template_id"],
            isc["checksum"],
            isc["payload"]
        ]
        envelope = "|".join(envelope_parts).encode('utf-8')

        # SHA256 CHECKSUM
        expected = f"sha256:{hashlib.sha256(isc['payload'].encode()).hexdigest()}"
        if not compare_digest(isc["checksum"], expected):
            return reject("Payload checksum mismatch")

        # SIGNATURE OVER ENVELOPE
        prov = isc["provenance"]
        public_key = serialization.load_pem_public_key(prov["public_key"].encode())
        sig_b64 = prov["signature"].split(":", 1)[1] if ":" in prov["signature"] else prov["signature"]
        signature = base64.b64decode(sig_b64)

        public_key.verify(
            signature,
            envelope,  # ← NOW SIGNED
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        if prov["issuer"] != "Structural Design Labs (SDL Limited)":
            return reject("Unauthorized issuer provenance")

        if count_tokens(isc["payload"]) > 1000:
            return reject("Suspicious complexity")

        return allow(isc)

    except Exception as e:
        return reject(f"Validation error: {e}")
