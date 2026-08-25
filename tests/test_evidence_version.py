import importlib.util
from pathlib import Path

import sir_firewall


ROOT = Path(__file__).resolve().parents[1]


def _load_tool(name: str):
    path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_certificate_generator_uses_package_version():
    generator = _load_tool("generate_certificate")

    assert generator._sir_firewall_version() == sir_firewall.__version__ == "2.2.1"


def test_local_audit_uses_package_version():
    local_audit = _load_tool("local_audit")

    assert local_audit._sir_version() == sir_firewall.__version__ == "2.2.1"
