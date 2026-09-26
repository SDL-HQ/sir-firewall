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
