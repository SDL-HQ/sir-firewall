"""What can reach the production signing key.

docs/key-custody.md tells a reviewer that signing is confined to one workflow
and one branch. That claim decides how much the rest of the custody story is
worth, so it is pinned here rather than left as prose. Until 6 October 2026 the
same document had to admit that `dev` was also signing-capable; the tests below
are what stop that coming back silently.
"""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"

SECRET = "secrets.SDL_PRIVATE_KEY_PEM"
SIGNING_WORKFLOW = "audit-and-sign.yml"


def _triggers(document: dict) -> dict:
    """YAML 1.1 parses a bare `on:` key as the boolean True."""
    for key in ("on", True):
        if key in document:
            return document[key] or {}
    return {}


def _workflow(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def test_only_one_workflow_can_reach_the_production_signing_key() -> None:
    reaching = sorted(
        path.name
        for path in WORKFLOWS.glob("*.yml")
        if SECRET in path.read_text(encoding="utf-8")
    )
    assert reaching == [SIGNING_WORKFLOW], (
        "the production signing secret is reachable from more than the signing "
        f"workflow: {reaching}. Every workflow added here widens what can "
        "produce a signature that verifies against the published registry."
    )


def test_only_main_signs_on_push() -> None:
    push = _triggers(_workflow(SIGNING_WORKFLOW)).get("push") or {}
    branches = push.get("branches") or []
    assert branches == ["main"], (
        f"the signing workflow runs on push to {branches}. Only main is "
        "protected by the Protect Main ruleset, so any other branch here means "
        "anyone able to push to that branch can cause a signature with the "
        "production key."
    )


def test_the_signing_key_id_travels_with_the_secret() -> None:
    """A rotation that moved the secret and not the variable would stamp every
    certificate `default` while signing with the new key. The workflow has to
    supply the id, so the two are changed together or the mismatch is loud."""
    text = (WORKFLOWS / SIGNING_WORKFLOW).read_text(encoding="utf-8")
    assert re.search(r"SDL_SIGNING_KEY_ID:\s*\$\{\{\s*vars\.SDL_SIGNING_KEY_ID", text), (
        "the signing workflow does not set SDL_SIGNING_KEY_ID from a "
        "repository variable, so certificates would fall back to the 'default' "
        "key id regardless of which key actually signed them."
    )


def test_pull_request_runs_cannot_sign_with_the_production_key() -> None:
    """A certificate produced in a pull request must not verify against the
    published registry. The acceptance workflow generates an ephemeral key
    instead of reading the secret."""
    text = (WORKFLOWS / "r1-cli-acceptance.yml").read_text(encoding="utf-8")
    assert SECRET not in text
    assert "SDL_PRIVATE_KEY_PEM" in text, (
        "the acceptance workflow no longer provides an ephemeral signing key; "
        "check what it signs with now"
    )


def test_every_workflow_that_signs_declares_why_it_may() -> None:
    """Any future workflow reaching the secret must be a deliberate addition.
    This fails the moment one appears, which is the point."""
    for path in sorted(WORKFLOWS.glob("*.yml")):
        if path.name == SIGNING_WORKFLOW:
            continue
        text = path.read_text(encoding="utf-8")
        assert "SDL_PRIVATE_KEY_PEM: ${{ secrets" not in text, (
            f"{path.name} reads the production signing secret. If that is "
            "intended, update docs/key-custody.md and this test together, "
            "because the custody document tells reviewers it cannot happen."
        )
