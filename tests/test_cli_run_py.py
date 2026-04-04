import importlib.util
from pathlib import Path


def _load_cli_module():
    module_path = Path(__file__).resolve().parents[1] / "src" / "sir_firewall" / "cli.py"
    spec = importlib.util.spec_from_file_location("sir_firewall_cli", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_run_py_invokes_subprocess_from_repo_root(monkeypatch):
    cli = _load_cli_module()
    captured = {}

    def _fake_call(cmd, cwd):
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        return 0

    monkeypatch.setattr(cli.subprocess, "call", _fake_call)

    rc = cli._run_py("tools/verify_certificate.py", ["--help"])

    assert rc == 0
    assert captured["cmd"][1] == str(cli.ROOT / "tools/verify_certificate.py")
    assert captured["cwd"] == cli.ROOT
