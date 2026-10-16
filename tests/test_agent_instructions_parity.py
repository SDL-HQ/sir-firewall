"""CLAUDE.md and AGENTS.md must not drift apart.

Different agents read different filenames by convention: Claude Code reads
CLAUDE.md, Codex reads AGENTS.md. Keeping two copies of the same guidance is
the duplicated-identity pattern this repository has been bitten by before, so
the copies are asserted byte-identical rather than trusted to stay in step.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_claude_and_agents_instructions_are_identical():
    claude = ROOT / "CLAUDE.md"
    agents = ROOT / "AGENTS.md"
    assert claude.is_file(), "CLAUDE.md is missing"
    assert agents.is_file(), "AGENTS.md is missing"
    assert claude.read_bytes() == agents.read_bytes(), (
        "CLAUDE.md and AGENTS.md have diverged. They are read by different "
        "agents and must carry the same guidance; copy one over the other."
    )


def test_every_workflow_uses_one_version_of_each_action():
    """Drift between workflows is how a deprecation reaches production.

    Five workflows were on `actions/checkout@v6` while the release gate was
    still on v4 and the generated window's workflow was too, so GitHub warned
    that Node 20 is deprecated and those two were being forced onto Node 24.
    Nothing compared the workflows with each other, so the two that lagged
    only surfaced in a run log a person happened to read.

    The generator's workflow template counts, because it becomes a real
    workflow in a public repository that nothing in this suite would otherwise
    see.
    """
    import re

    root = Path(__file__).resolve().parents[1]
    sources = list((root / ".github" / "workflows").glob("*.yml"))
    text = "\n".join(p.read_text(encoding="utf-8") for p in sources)
    text += (root / "tools" / "generate_shop_window.py").read_text(encoding="utf-8")

    versions = {}
    for action, version in re.findall(r"uses: ([\w-]+/[\w-]+)@v(\d+)", text):
        versions.setdefault(action, set()).add(int(version))

    mixed = {action: sorted(v) for action, v in versions.items() if len(v) > 1}
    assert not mixed, (
        "these actions are pinned to more than one major version across the "
        f"workflows, so one of them is older than the project knows: {mixed}"
    )
