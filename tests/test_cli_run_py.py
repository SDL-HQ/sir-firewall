import importlib.util
import json
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


def test_scenario_summary_update_warns_for_invalid_json(tmp_path, monkeypatch, capsys):
    cli = _load_cli_module()
    monkeypatch.setattr(cli, "ROOT", tmp_path)

    proofs_dir = tmp_path / "proofs"
    proofs_dir.mkdir(parents=True)
    (proofs_dir / "run_summary.json").write_text("{bad-json", encoding="utf-8")

    monkeypatch.setattr(cli, "_run_py", lambda *_args, **_kwargs: 0)
    ns = cli.argparse.Namespace(
        mode="scenario",
        pack=None,
        suite=None,
        scenario=None,
        model=None,
        template=None,
        no_model_calls=False,
    )

    rc = cli._cmd_run(ns)

    captured = capsys.readouterr()
    assert rc == 0
    assert "WARNING: failed to update scenario summary" in captured.err
    assert "run_summary.json" in captured.err


def test_scenario_summary_update_warns_for_write_error(tmp_path, monkeypatch, capsys):
    cli = _load_cli_module()
    monkeypatch.setattr(cli, "ROOT", tmp_path)

    proofs_dir = tmp_path / "proofs"
    proofs_dir.mkdir(parents=True)
    summary_path = proofs_dir / "run_summary.json"
    summary_path.write_text(json.dumps({"proof_class": "FIREWALL_ONLY_AUDIT"}), encoding="utf-8")

    monkeypatch.setattr(cli, "_run_py", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(cli.Path, "write_text", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")))
    ns = cli.argparse.Namespace(
        mode="scenario",
        pack=None,
        suite=None,
        scenario=None,
        model=None,
        template=None,
        no_model_calls=False,
    )

    rc = cli._cmd_run(ns)

    captured = capsys.readouterr()
    assert rc == 0
    assert "WARNING: failed to update scenario summary" in captured.err
