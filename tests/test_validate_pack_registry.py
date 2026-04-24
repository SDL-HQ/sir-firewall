import importlib.util
import json
from pathlib import Path


def _load_validator_module():
    module_path = Path(__file__).resolve().parents[1] / "tools" / "validate_pack_registry.py"
    spec = importlib.util.spec_from_file_location("validate_pack_registry", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_validate_registry_accepts_internal_visibility(tmp_path):
    validator = _load_validator_module()
    registry_path = tmp_path / "pack_registry.v1.json"
    suite_path = tmp_path / "suite.csv"
    suite_path.write_text("id,prompt,expected,note,category\nx,hello,allow,n,benign\n", encoding="utf-8")

    registry_path.write_text(
        json.dumps(
            {
                "registry_version": "v1",
                "packs": [
                    {
                        "pack_id": "canary_fail",
                        "schema": "csv_single_turn_v1",
                        "risk_class": "baseline",
                        "status": "draft",
                        "version": "1.0.0",
                        "suite_path": str(suite_path),
                        "hash_binds_to": "decoded_prompt_content",
                        "pack_class": "domain",
                        "visibility": "internal",
                        "maturity": "demo",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    errors = validator.validate_registry(registry_path)
    assert errors == []
