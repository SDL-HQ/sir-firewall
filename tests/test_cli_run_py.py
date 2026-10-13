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

    def _fake_call(cmd, cwd=None, **kwargs):
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
        scenario="tests/scenario_packs/scenario_injection_chain.json",
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
    summary_path.write_text(
        json.dumps({"proof_class": "FIREWALL_ONLY_AUDIT", "scenario_id": "s1", "scenario_hash": "sha256:abc"}),
        encoding="utf-8",
    )

    monkeypatch.setattr(cli, "_run_py", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(cli.Path, "write_text", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")))
    ns = cli.argparse.Namespace(
        mode="scenario",
        pack=None,
        suite=None,
        scenario="tests/scenario_packs/scenario_injection_chain.json",
        model=None,
        template=None,
        no_model_calls=False,
    )

    rc = cli._cmd_run(ns)

    captured = capsys.readouterr()
    assert rc == 0
    assert "WARNING: failed to update scenario summary" in captured.err


def test_scenario_mode_rejects_suite_input(monkeypatch, capsys):
    cli = _load_cli_module()
    monkeypatch.setattr(cli, "_run_py", lambda *_args, **_kwargs: 0)
    ns = cli.argparse.Namespace(
        mode="scenario",
        pack=None,
        suite="tests/domain_packs/generic_safety.csv",
        scenario=None,
        model=None,
        template=None,
        no_model_calls=False,
    )

    rc = cli._cmd_run(ns)

    captured = capsys.readouterr()
    assert rc == 2
    assert "does not support --suite" in captured.err


def test_scenario_mode_rejects_non_scenario_pack(monkeypatch, capsys):
    cli = _load_cli_module()
    monkeypatch.setattr(
        cli,
        "_load_registry",
        lambda: {"packs": [{"pack_id": "generic_safety", "schema": "csv_single_turn_v1"}]},
    )
    monkeypatch.setattr(cli, "_run_py", lambda *_args, **_kwargs: 0)
    ns = cli.argparse.Namespace(
        mode="scenario",
        pack="generic_safety",
        suite=None,
        scenario=None,
        model=None,
        template=None,
        no_model_calls=False,
    )

    rc = cli._cmd_run(ns)

    captured = capsys.readouterr()
    assert rc == 2
    assert "requires a scenario_json_v1 pack" in captured.err


def test_scenario_mode_unknown_pack_points_to_pack_discovery(monkeypatch, capsys):
    cli = _load_cli_module()
    monkeypatch.setattr(cli, "_load_registry", lambda: {"packs": [{"pack_id": "generic_safety", "schema": "csv_single_turn_v1"}]})
    monkeypatch.setattr(cli, "_run_py", lambda *_args, **_kwargs: 0)
    ns = cli.argparse.Namespace(
        mode="scenario",
        pack="does_not_exist",
        suite=None,
        scenario=None,
        model=None,
        template=None,
        no_model_calls=False,
    )

    rc = cli._cmd_run(ns)

    captured = capsys.readouterr()
    assert rc == 2
    assert "unknown pack_id does_not_exist" in captured.err
    assert "sir packs list" in captured.err
    assert "sir packs show <pack_id>" in captured.err
    assert captured.err.count("unknown pack_id does_not_exist") == 1


def test_live_mode_requires_xai_api_key(monkeypatch, capsys):
    cli = _load_cli_module()
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    ns = cli.argparse.Namespace(
        mode="live",
        pack=None,
        suite=None,
        scenario=None,
        model=None,
        template=None,
        no_model_calls=False,
    )

    rc = cli._cmd_run(ns)

    captured = capsys.readouterr()
    assert rc == 2
    assert "LIVE mode requires your own provider credentials (XAI_API_KEY)" in captured.err


def test_live_mode_requires_litellm(monkeypatch, capsys):
    cli = _load_cli_module()
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setattr(cli.importlib.util, "find_spec", lambda _name: None)
    ns = cli.argparse.Namespace(
        mode="live",
        pack=None,
        suite=None,
        scenario=None,
        model=None,
        template=None,
        no_model_calls=False,
    )

    rc = cli._cmd_run(ns)

    captured = capsys.readouterr()
    assert rc == 2
    assert "LIVE mode requires litellm installed" in captured.err


def test_benchmark_run_invokes_paired_runner(monkeypatch):
    cli = _load_cli_module()
    captured = {}

    def _fake_run(script_rel, args):
        captured["script_rel"] = script_rel
        captured["args"] = list(args)
        return 0

    monkeypatch.setattr(cli, "_run_py", _fake_run)
    ns = cli.argparse.Namespace(
        mode="audit",
        pack="generic_safety",
        suite=None,
        scenario=None,
        model="xai/grok-3-beta",
        template="EU-AI-Act-ISC-v1",
        no_model_calls=False,
        pair_key="pk-1",
    )

    rc = cli._cmd_benchmark_run(ns)

    assert rc == 0
    assert captured["script_rel"] == "tools/run_paired_benchmark.py"
    assert "--pack" in captured["args"]
    assert "--pair-key" in captured["args"]


def test_packs_list_shows_active_suites_and_what_they_enforce_under(monkeypatch, capsys):
    """Filtered on status, and carrying the enforcement pack.

    This asserted visibility filtering until 13 October 2026, which hid
    `mental_health_clinical`. That suite is `encoded` so its prompts are not in
    plaintext, which is a reason about content, and this command prints none.
    Its existence was already published in docs/rule-coverage.md and on
    docs/domain-packs.html, so the listing disagreed with two public surfaces
    and protected nothing.

    The enforcement column answers the backlog row *`sir packs list` presents
    registry discoverability as execution availability*: a reader can no longer
    assume a suite enforces under a pack of its own name, because four of them
    do not.
    """
    cli = _load_cli_module()
    monkeypatch.setattr(
        cli,
        "_load_registry",
        lambda: {
            "packs": [
                {"pack_id": "generic_safety", "schema": "csv_single_turn_v1", "status": "active", "visibility": "public"},
                {"pack_id": "mental_health_clinical", "schema": "csv_single_turn_v1", "status": "active", "visibility": "encoded", "enforcement_pack": "generic_safety"},
                {"pack_id": "canary_fail", "schema": "csv_single_turn_v1", "status": "draft", "visibility": "internal"},
            ]
        },
    )

    rc = cli._cmd_packs_list(cli.argparse.Namespace())

    captured = capsys.readouterr()
    assert rc == 0
    assert "generic_safety\tcsv_single_turn_v1\tactive\tpublic\tgeneric_safety" in captured.out
    assert (
        "mental_health_clinical\tcsv_single_turn_v1\tactive\tencoded\tgeneric_safety"
        in captured.out
    ), "an active encoded suite must be listed; the command prints no prompt content"
    assert "canary_fail" not in captured.out, (
        "the deliberate failure fixture is draft and is not a suite to select"
    )


def test_packs_list_names_the_enforcement_pack_for_every_active_registry_entry(capsys):
    """Against the real registry, not a fixture.

    The fixture above would pass if the column were hard-coded, and the entries
    that enforce under another name are the reason the column exists.

    The first version of this test asserted that at least four rows differed
    from their own pack_id, which is not what its name claims. A mutation
    dropping a same-named active entry such as `support_operator_override` left
    four differing rows and passed. An independent review found that, not this
    test. The expectation is derived from the registry now, so every active
    entry must appear with the enforcement pack the registry resolves for it,
    and omitting any entry fails.
    """
    cli = _load_cli_module()

    registry = cli._load_registry()
    expected = {
        str(entry["pack_id"]): (
            str(entry.get("enforcement_pack") or "").strip() or str(entry["pack_id"])
        )
        for entry in registry["packs"]
        if str(entry.get("status") or "").strip() == "active"
    }
    assert expected, "the registry declares no active suites, so this asserts nothing"

    rc = cli._cmd_packs_list(cli.argparse.Namespace())
    lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]

    assert rc == 0

    # Positional, and asserted as positional. The column count is part of the
    # published output contract: README.md and tests/domain_packs/README.md both
    # describe what this command prints, so adding or reordering a column should
    # fail here and be a deliberate change rather than a silent one.
    rows = {}
    for line in lines:
        parts = line.split("\t")
        assert len(parts) == 5, (
            "the listing's column count changed, which is a change to a "
            f"documented output contract: {line!r}"
        )
        rows[parts[0]] = parts[4]

    assert rows == expected, (
        "the listing does not agree with the registry on which suites are "
        "active or what they enforce under.\n"
        f"  missing from listing: {sorted(set(expected) - set(rows))}\n"
        f"  listed but not active: {sorted(set(rows) - set(expected))}\n"
        f"  wrong enforcement pack: "
        f"{ {k: (rows[k], expected[k]) for k in set(rows) & set(expected) if rows[k] != expected[k]} }"
    )

    differing = {k: v for k, v in expected.items() if k != v}
    assert differing, (
        "no active suite enforces under a pack of another name, so the "
        "enforcement column carries no information and the backlog row it "
        "closes would be open again"
    )


def test_packs_show_keeps_explicit_lookup_for_internal(monkeypatch, capsys):
    cli = _load_cli_module()
    monkeypatch.setattr(
        cli,
        "_load_registry",
        lambda: {
            "packs": [
                {"pack_id": "canary_fail", "schema": "csv_single_turn_v1", "status": "draft", "visibility": "internal"}
            ]
        },
    )

    rc = cli._cmd_packs_show(cli.argparse.Namespace(pack_id="canary_fail"))

    captured = capsys.readouterr()
    assert rc == 0
    assert '"pack_id": "canary_fail"' in captured.out
    assert '"visibility": "internal"' in captured.out
