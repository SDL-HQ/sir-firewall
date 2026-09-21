import ast
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sir_firewall.evidence_paths import canonical_ledger_path

ROOT = Path(__file__).resolve().parents[1]


def _load_generator(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools/generate_certificate.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ledger(path: Path, final_hash: str) -> str:
    head = hashlib.sha256(("GENESIS" + final_hash).encode()).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "ts": "2026-09-21T00:00:00Z", "prompt_index": 0,
        "prev_hash": "GENESIS", "final_hash": final_hash, "ledger_hash": head,
    }) + "\n", encoding="utf-8")
    return "sha256:" + head


def _ledger_rows(path: Path, values: list[str]) -> str:
    previous = "GENESIS"
    rows = []
    for index, value in enumerate(values):
        head = hashlib.sha256((previous + value).encode()).hexdigest()
        rows.append({
            "ts": "2026-09-21T00:00:00Z", "prompt_index": index,
            "prev_hash": previous, "final_hash": value, "ledger_hash": head,
        })
        previous = head
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return "sha256:" + previous


def _setup_run(tmp_path: Path, ledger_path: Path, run_id: str = "binding-run") -> None:
    (tmp_path / "proofs").mkdir(exist_ok=True)
    (tmp_path / "proofs/run_summary.json").write_text(json.dumps({
        "suite_name": "binding-test", "suite_path": "missing.csv",
        "suite_hash": "sha256:" + "1" * 64, "prompts_tested": 1,
        "run_id": run_id, "ledger_path": str(ledger_path.relative_to(tmp_path)),
        "proof_class": "FIREWALL_ONLY_AUDIT",
        "provider_call_attempts": 0, "provider_call_successes": 0,
        "provider_call_failures": 0,
    }), encoding="utf-8")


def _key(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setenv("SDL_PRIVATE_KEY_PEM", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode())
    return key


def test_generator_hash_source_is_verified_ledger_not_environment_or_text_file():
    tree = ast.parse((ROOT / "tools/generate_certificate.py").read_text(encoding="utf-8"))
    assignments = [node for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign))]
    hash_values = []
    for node in assignments:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = {n.id for target in targets for n in ast.walk(target) if isinstance(n, ast.Name)}
        if "itgl_final_hash" in names:
            hash_values.append(node.value)
    assert hash_values
    forbidden = [
        call for value in hash_values for call in ast.walk(value)
        if isinstance(call, ast.Call) and (
            (isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
             and call.func.value.id == "os" and call.func.attr == "getenv")
            or (isinstance(call.func, ast.Name) and call.func.id == "_read_text")
        )
    ]
    assert forbidden == []


def test_two_ledgers_generate_distinct_bound_certificates(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _key(monkeypatch)
    generator = _load_generator("generator_two_ledgers")
    ledger_a = canonical_ledger_path("run-a", tmp_path / "proofs/runs")
    ledger_b = canonical_ledger_path("run-b", tmp_path / "proofs/runs")
    head_a, head_b = _ledger(ledger_a, "a" * 64), _ledger(ledger_b, "b" * 64)

    _setup_run(tmp_path, ledger_a, "run-a")
    generator.main()
    cert_a = json.loads((tmp_path / "proofs/local-audit.json").read_text())
    _setup_run(tmp_path, ledger_b, "run-b")
    generator.main()
    cert_b = json.loads((tmp_path / "proofs/local-audit.json").read_text())

    assert cert_a["itgl_final_hash"] == head_a
    assert cert_b["itgl_final_hash"] == head_b
    assert cert_a["itgl_final_hash"] != cert_b["itgl_final_hash"]
    assert cert_a["itgl_row_count"] == cert_b["itgl_row_count"] == 1


def test_generation_fails_closed_when_ledger_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _key(monkeypatch)
    missing = canonical_ledger_path("binding-run", tmp_path / "proofs/runs")
    _setup_run(tmp_path, missing)
    generator = _load_generator("generator_missing_ledger")
    with pytest.raises(RuntimeError, match="ledger verification failed"):
        generator.main()
    assert not list((tmp_path / "proofs").glob("*.json")) or list((tmp_path / "proofs").glob("*.json")) == [tmp_path / "proofs/run_summary.json"]
    assert not (tmp_path / "proofs/archive").exists()


def test_certificate_verifier_ledger_binding_exit_code(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    key = _key(monkeypatch)
    matching = canonical_ledger_path("binding-run", tmp_path / "proofs/runs")
    other = tmp_path / "other.jsonl"
    _ledger(matching, "c" * 64)
    _ledger(other, "d" * 64)
    _setup_run(tmp_path, matching)
    generator = _load_generator("generator_verify_binding")
    generator.main()
    cert = tmp_path / "proofs/local-audit.json"
    pubkey = tmp_path / "public.pem"
    pubkey.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    base = [sys.executable, str(ROOT / "tools/verify_certificate.py"), str(cert),
            "--pubkey", str(pubkey), "--key-registry", str(tmp_path / "absent.json")]
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    assert subprocess.run(base + ["--ledger", str(matching)], cwd=ROOT, env=env).returncode == 0
    mismatch = subprocess.run(
        base + ["--ledger", str(other)], cwd=ROOT, env=env, capture_output=True, text=True
    )
    assert mismatch.returncode == 7
    assert "terminal hash mismatch" in mismatch.stderr


def test_generation_rejects_ledger_path_for_different_run_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _key(monkeypatch)
    wrong = canonical_ledger_path("other-run", tmp_path / "proofs/runs")
    _ledger(wrong, "e" * 64)
    _setup_run(tmp_path, wrong, "expected-run")
    generator = _load_generator("generator_wrong_run_identity")
    with pytest.raises(RuntimeError, match="ledger identity mismatch"):
        generator.main()
    assert not (tmp_path / "proofs/archive").exists()


def test_generation_rejects_detached_ledger_override_without_explicit_allowance(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _key(monkeypatch)
    canonical = canonical_ledger_path("binding-run", tmp_path / "proofs/runs")
    detached = tmp_path / "detached.jsonl"
    _ledger(canonical, "f" * 64)
    _ledger(detached, "f" * 64)
    _setup_run(tmp_path, canonical)
    generator = _load_generator("generator_detached_refused")
    with pytest.raises(RuntimeError, match="detached ITGL ledger refused"):
        generator.main(str(detached))
    assert not (tmp_path / "proofs/archive").exists()


def test_generation_marks_explicitly_allowed_detached_ledger(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _key(monkeypatch)
    canonical = canonical_ledger_path("binding-run", tmp_path / "proofs/runs")
    detached = tmp_path / "detached.jsonl"
    _ledger(canonical, "7" * 64)
    detached_head = _ledger(detached, "8" * 64)
    _setup_run(tmp_path, canonical)
    generator = _load_generator("generator_detached_allowed")
    generator.main(str(detached), allow_detached_ledger=True)
    cert = json.loads((tmp_path / "proofs/local-audit.json").read_text())
    assert cert["detached_ledger"] is True
    assert cert["itgl_final_hash"] == detached_head


def test_generation_marks_canonical_ledger_as_not_detached(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _key(monkeypatch)
    canonical = canonical_ledger_path("binding-run", tmp_path / "proofs/runs")
    _ledger(canonical, "9" * 64)
    _setup_run(tmp_path, canonical)
    generator = _load_generator("generator_attached_mark")
    generator.main()
    cert = json.loads((tmp_path / "proofs/local-audit.json").read_text())
    assert cert["detached_ledger"] is False


@pytest.mark.parametrize("variant", ["strict-prefix", "trailing-row-removed", "reordered", "different-rows"])
def test_certificate_verifier_rejects_isolated_wrong_ledger(tmp_path, monkeypatch, variant):
    monkeypatch.chdir(tmp_path)
    key = _key(monkeypatch)
    matching = canonical_ledger_path("binding-run", tmp_path / "proofs/runs")
    values = ["1" * 64, "2" * 64, "3" * 64]
    _ledger_rows(matching, values)
    _setup_run(tmp_path, matching)
    summary_path = tmp_path / "proofs/run_summary.json"
    summary = json.loads(summary_path.read_text())
    summary["prompts_tested"] = 3
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    generator = _load_generator(f"generator_isolation_{variant}")
    generator.main()

    candidate = tmp_path / f"{variant}.jsonl"
    if variant == "strict-prefix":
        _ledger_rows(candidate, values[:1])
    elif variant == "trailing-row-removed":
        _ledger_rows(candidate, values[:-1])
    elif variant == "reordered":
        original = matching.read_text().splitlines()
        candidate.write_text("\n".join([original[1], original[0], original[2]]) + "\n")
    else:
        _ledger_rows(candidate, ["4" * 64, "5" * 64, "6" * 64])

    pubkey = tmp_path / "public.pem"
    pubkey.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    result = subprocess.run([
        sys.executable, str(ROOT / "tools/verify_certificate.py"),
        str(tmp_path / "proofs/local-audit.json"), "--pubkey", str(pubkey),
        "--key-registry", str(tmp_path / "absent.json"), "--ledger", str(candidate),
    ], cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode == 7
