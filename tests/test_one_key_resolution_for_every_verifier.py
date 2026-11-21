"""One key resolution, called by every verifier: a named key is resolved through the registry or not at all.

Until 21 November 2026 `key_registry.py` shared the primitives and each of the
three verifiers wrote the sequence that calls them: is there a registry, find
the entry, ask the revocation rule, fall back or refuse, and after the
signature the anchored set or the key file. Three copies with the same inputs
and nothing comparing them. Measured on the tree before this change:

- `--require-registry` with no readable registry returned 1 from the
  certificate verifier, 3 from the receipt verifier and 5 from the baseline
  record verifier, and by each tool's own table none of the three is right;
- without that flag, a registry that was missing or unreadable was a warning
  and a check against a public key file, with no revocation rule in it;
- a document naming a key the registry does not have was refused by the
  certificate verifier at exit 1, verified against `--pubkey` by the receipt
  verifier when the file was typed, and verified against the public key file
  by the baseline record verifier without a word.

All of it is one rule now. A document that names a key is checked against the
registry's entry for that key and against nothing else, and there is no flag
that changes that. Where the registry cannot be read, or was read and does not
have the key, nothing was checked: that is a fact about the reader's bundle
and not about the document, and it is exit 6 from all three.

One difference is deliberate and is asserted, so that it stays a decision:
only a certificate may name no key, and then a public key file is a second
candidate, held to the registry after the signature.

Breaking this: write a registry lookup back into a verifier, map
REGISTRY_UNAVAILABLE or KEY_NOT_IN_REGISTRY to anything but 6, or offer a key
from a file for a document that names its key.
"""

import base64
import copy
import hashlib
import inspect
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from document_signing import payload_hash, sign_document  # noqa: E402
from key_registry import (  # noqa: E402
    ANCHORED_FIELD,
    IMPLICIT_KEY_ID,
    KEY_FILE_UNREADABLE,
    KEY_ID_MALFORMED,
    KEY_NOT_HONOURED,
    KEY_NOT_IN_REGISTRY,
    REGISTRY_UNAVAILABLE,
    KeyRefused,
    load_registry,
    refusal_after_signature,
    resolve_keys,
)

REGISTRY = REPO / "spec" / "pubkeys" / "key_registry.v1.json"
KEY_FILE = REPO / "spec" / "sdl.pub"
RUNS = REPO / "docs" / "runs"
CERTIFICATE = RUNS / "20261026-114228-317580-gh40317017323-d8bd37b6606d" / "audit.json"
BASELINE = RUNS / "20261015-092557-107124-gh38712792514-670d9d4222c2" / "baseline.json"
WORKFLOW = REPO / ".github" / "workflows" / "r1-cli-acceptance.yml"
CHECK_NOT_PERFORMED = 6
A_NAME_THE_REGISTRY_LACKS = "a-name-the-registry-does-not-have"
REMOVED_FLAG = "--allow-missing-" + "registry"
VERIFIERS = ("verify_certificate.py", "verify_archive_receipt.py", "verify_baseline_record.py")
#: What only `key_registry.py` may call. A verifier that names one has started its own sequence.
PRIMITIVES = (
    "find_registry_key",
    "revocation_allows_proof",
    "anchored_set_refusal",
    "key_file_refusal",
    "public_key_pem_from_entry",
    "load_pem_public_key",
)


def _published(path):
    if not path.is_file():
        pytest.skip(f"published document not present: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _run(tool, *argv, cwd=REPO):
    return subprocess.run([sys.executable, str(REPO / "tools" / tool), *map(str, argv)], capture_output=True, text=True, cwd=cwd)


@pytest.fixture(scope="module")
def key(tmp_path_factory):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    key_file = tmp_path_factory.mktemp("key") / "their.pub"
    key_file.write_text(public, encoding="utf-8")
    return private, pem, public, key_file


def _registry(tmp_path, name, *entries):
    registry = copy.deepcopy(load_registry(REGISTRY))
    registry["keys"].extend(entries)
    path = tmp_path / f"registry-{name}.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    return path


def _unreadable(tmp_path):
    path = tmp_path / "unreadable.json"
    path.write_text("{ not json", encoding="utf-8")
    return path


def _resolve(document, registry_path, **options):
    return resolve_keys(document, registry_path=Path(registry_path), **options)


def _refused(document, registry_path, **options):
    with pytest.raises(KeyRefused) as caught:
        _resolve(document, registry_path, **options)
    return caught.value


def _resigned(published, private_pem, key_id=None, **changes):
    document = {k: v for k, v in published.items() if k not in ("signature", "payload_hash", "signing_key_id")}
    if key_id:
        document["signing_key_id"] = key_id
    document.update(changes)
    return sign_document(document, private_pem)


def _receipt_archive(tmp_path, name, private, key_id):
    canonical = lambda d: json.dumps(d, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")  # noqa: E731
    sha = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()  # noqa: E731
    archive = tmp_path / name
    archive.mkdir()
    body = f"a file of {name}\n".encode()
    (archive / "a.txt").write_bytes(body)
    manifest = {"files": [{"path": "a.txt", "sha256": sha(body), "size_bytes": len(body)}]}
    (archive / "manifest.json").write_text(json.dumps(manifest))
    receipt = {"run_id": "20260101-000000-000000-gh1-000000000000", "repository": "test", "commit_sha": "0" * 40, "ci_run_url": "none",
               "manifest_hash": sha(canonical(manifest)), "run_folder_hash": sha(f"a.txt:{sha(body)}".encode()),
               "timestamp_utc": "2026-01-01T00:00:00Z", "signing_key_id": key_id}
    payload = canonical(receipt)
    receipt["payload_hash"] = sha(payload)
    receipt["signature"] = base64.b64encode(private.sign(payload, padding.PKCS1v15(), hashes.SHA256())).decode()
    (archive / "archive_receipt.json").write_text(json.dumps(receipt))
    return archive


# --- the structure ----------------------------------------------------------------


@pytest.mark.parametrize("verifier", VERIFIERS)
def test_no_verifier_writes_the_sequence_itself(verifier):
    source = (REPO / "tools" / verifier).read_text(encoding="utf-8")
    assert "resolve_keys(" in source and "refusal_after_signature(" in source
    written_again = [name for name in PRIMITIVES if name in source]
    assert not written_again, f"{verifier} calls {written_again}, which only key_registry.py's one resolution may"


@pytest.mark.parametrize("verifier", VERIFIERS)
def test_a_refusal_about_the_readers_bundle_is_exit_six_in_every_verifier(verifier):
    namespace = {}
    source = (REPO / "tools" / verifier).read_text(encoding="utf-8")
    start = source.index("KEY_REFUSAL_EXIT = {")
    table = source[start : source.index("}", start) + 1]
    exec(  # noqa: S102 - the table as the verifier wrote it, with the names it uses
        table,
        {
            "REGISTRY_UNAVAILABLE": REGISTRY_UNAVAILABLE,
            "KEY_FILE_UNREADABLE": KEY_FILE_UNREADABLE,
            "KEY_NOT_HONOURED": KEY_NOT_HONOURED,
            "KEY_NOT_IN_REGISTRY": KEY_NOT_IN_REGISTRY,
            "KEY_ID_MALFORMED": KEY_ID_MALFORMED,
            "REVOCATION_FAILURE": 10,
            "SIGNATURE_CHECK_RAISED": 6,
            "SIGNATURE_FAILED": 5,
        },
        namespace,
    )
    exits = namespace["KEY_REFUSAL_EXIT"]
    assert exits[REGISTRY_UNAVAILABLE] == CHECK_NOT_PERFORMED
    assert exits[KEY_NOT_IN_REGISTRY] == CHECK_NOT_PERFORMED
    # Only the certificate verifier is ever handed a key from a file.
    assert exits.get(KEY_FILE_UNREADABLE, CHECK_NOT_PERFORMED) == CHECK_NOT_PERFORMED
    assert (KEY_FILE_UNREADABLE in exits) == (verifier == "verify_certificate.py")


def test_there_is_no_flag_and_no_argument_that_offers_a_file_for_a_named_key():
    # A flag that asked for the old fallback by name was built on 21 November
    # 2026 and withdrawn before it merged. The registry is not something a
    # reader may opt out of, because without it a signature says that someone
    # signed the document and not who.
    parameters = set(inspect.signature(resolve_keys).parameters)
    assert parameters == {"document", "registry_path", "require_registry", "implicit_key_id", "pubkey_path"}

    for relative in (*(f"tools/{verifier}" for verifier in VERIFIERS), "tools/verify_evidence.py", "tools/key_registry.py",
                     "src/sir_firewall/cli.py", ".github/workflows/r1-cli-acceptance.yml", ".github/workflows/audit-and-sign.yml"):
        assert REMOVED_FLAG not in (REPO / relative).read_text(encoding="utf-8"), relative

    _published(CERTIFICATE), _published(BASELINE)
    for verifier, (target, *rest) in _commands().items():
        asked = _run(verifier, target, *rest, REMOVED_FLAG)
        assert asked.returncode == 2 and "unrecognized arguments" in asked.stderr, verifier


# --- a registry that can be read is required ------------------------------------------------


@pytest.mark.parametrize("state", ["unavailable", "unreadable"])
def test_no_readable_registry_is_a_refusal_whatever_else_is_passed(state, tmp_path):
    registry = tmp_path / "absent.json" if state == "unavailable" else _unreadable(tmp_path)
    named = {"signing_key_id": "sdl-2026-10-06"}

    for document, implicit in ((named, None), ({}, IMPLICIT_KEY_ID)):
        for options in ({}, {"require_registry": True}, {"pubkey_path": KEY_FILE}):
            refused = _refused(document, registry, implicit_key_id=implicit, **options)
            assert refused.kind == REGISTRY_UNAVAILABLE
            assert f"key registry {state}" in str(refused) and "nothing about this document was verified" in str(refused)


def test_an_entry_whose_key_cannot_be_read_is_an_unreadable_registry(tmp_path):
    registry = _registry(tmp_path, "bad-entry", {"key_id": "broken", "pubkey_pem": "not a key", "status": "active"})
    refused = _refused({"signing_key_id": "broken"}, registry)
    assert refused.kind == REGISTRY_UNAVAILABLE and "entry key_id='broken'" in str(refused)


def test_a_key_file_that_cannot_be_read_is_about_the_bundle_and_not_the_document(tmp_path):
    # The one place a file is read: beside the implicit entry, for a certificate naming no key.
    refused = _refused({}, REGISTRY, implicit_key_id=IMPLICIT_KEY_ID, pubkey_path=tmp_path / "no.pub")
    assert refused.kind == KEY_FILE_UNREADABLE and "failed to load public key" in str(refused)


# --- a named key is the registry's or it is nobody's ---------------------------------------------


def test_a_named_key_the_registry_lacks_is_refused_and_no_file_stands_in(key):
    # Three policies until 21 November 2026, one per verifier. One now, and
    # nothing a caller passes makes a file a candidate for a named key.
    _, _, _, key_file = key
    unlisted = {"signing_key_id": A_NAME_THE_REGISTRY_LACKS}
    for options in ({}, {"pubkey_path": key_file}, {"require_registry": True}, {"pubkey_path": key_file, "require_registry": True},
                    {"pubkey_path": key_file, "implicit_key_id": IMPLICIT_KEY_ID}):
        refused = _refused(unlisted, REGISTRY, **options)
        assert refused.kind == KEY_NOT_IN_REGISTRY
        assert str(refused) == f"signing_key_id not found in key registry: {A_NAME_THE_REGISTRY_LACKS}"


def test_a_named_key_the_registry_has_is_the_only_candidate(key):
    _, _, _, key_file = key
    for options in ({}, {"pubkey_path": key_file}, {"pubkey_path": key_file, "implicit_key_id": IMPLICIT_KEY_ID}):
        (only,) = _resolve({"signing_key_id": "sdl-2026-10-06"}, REGISTRY, **options)
        assert only.entry["key_id"] == "sdl-2026-10-06"
        assert only.source == f"key registry {REGISTRY} entry signing_key_id=sdl-2026-10-06"


# --- what is deliberately different, kept as a decision ----------------------------------------


def test_only_a_certificate_may_name_no_key():
    # The field postdates the certificates that lack it. They are resolved as
    # the registry's implicit entry, with the public key file as a second
    # candidate, and --require-registry removes the second.
    as_certificate = _resolve({}, REGISTRY, implicit_key_id=IMPLICIT_KEY_ID, pubkey_path=KEY_FILE)
    assert [candidate.entry is not None for candidate in as_certificate] == [True, False]
    assert f"entry key_id={IMPLICIT_KEY_ID} (the certificate carries no signing_key_id" in as_certificate[0].source
    assert as_certificate[1].source == f"--pubkey {KEY_FILE}"
    strict = _resolve({}, REGISTRY, implicit_key_id=IMPLICIT_KEY_ID, pubkey_path=KEY_FILE, require_registry=True)
    assert [candidate.entry is not None for candidate in strict] == [True]

    # A receipt or a baseline record names its key or is not one.
    assert _refused({}, REGISTRY).kind == KEY_ID_MALFORMED
    assert _refused({"signing_key_id": ""}, REGISTRY, implicit_key_id=IMPLICIT_KEY_ID).kind == KEY_ID_MALFORMED


def test_a_certificate_naming_no_key_beside_a_registry_with_no_implicit_entry(key, tmp_path):
    # Someone else's registry. Their key file is all there is, and with
    # registry keys only there is nothing.
    _, _, public, key_file = key
    theirs = tmp_path / "theirs.json"
    theirs.write_text(json.dumps({"keys": [{"key_id": "theirs", "pubkey_pem": public, "status": "active"}]}), encoding="utf-8")
    (only,) = _resolve({}, theirs, implicit_key_id=IMPLICIT_KEY_ID, pubkey_path=key_file)
    assert (only.entry, only.source) == (None, f"--pubkey {key_file}")
    for options in ({"require_registry": True, "pubkey_path": key_file}, {}):
        assert _refused({}, theirs, implicit_key_id=IMPLICIT_KEY_ID, **options).kind == KEY_NOT_IN_REGISTRY


def test_every_published_certificate_naming_no_key_resolves_as_it_did():
    # 43 of them on 21 November 2026. No count is asserted, because the archive grows.
    nameless = []
    for path in sorted(RUNS.glob("*/audit.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        if "signing_key_id" not in document:
            nameless.append(document)
    if not nameless:
        pytest.skip("no published certificate without a signing_key_id in this checkout")
    for document in nameless:
        first, second = _resolve(document, REGISTRY, implicit_key_id=IMPLICIT_KEY_ID, pubkey_path=KEY_FILE)
        assert first.entry["key_id"] == IMPLICIT_KEY_ID
        assert first.source == (
            f"key registry {REGISTRY} entry key_id={IMPLICIT_KEY_ID} "
            "(the certificate carries no signing_key_id; the field postdates it)"
        )
        assert (second.entry, second.source) == (None, f"--pubkey {KEY_FILE}")


def test_the_two_halves_are_one_question(key, tmp_path):
    # Before the signature the revocation rule is asked and told the anchored
    # check follows. After it, that check is made, of the entry or of the key.
    private, pem, public, key_file = key
    old = sign_document({"run_id": "r", "timestamp_utc": "2026-01-01T00:00:00Z", "signing_key_id": "gone"}, pem)
    new = sign_document({"run_id": "r", "timestamp_utc": "2026-11-21T00:00:00Z", "signing_key_id": "gone"}, pem)
    entry = {"key_id": "gone", "pubkey_pem": public, "status": "revoked", "revoked_utc": "2026-10-06T00:00:00Z"}

    refused = _refused(new, _registry(tmp_path, "no-set", entry))
    assert refused.kind == KEY_NOT_HONOURED and str(refused).startswith("revoked-key verification failure: ")

    anchored = _registry(tmp_path, "anchored", {**entry, ANCHORED_FIELD: [payload_hash(old)]})
    (candidate,) = _resolve(new, anchored)
    ask = dict(registry_path=anchored, document=new)
    assert refusal_after_signature(candidate, computed_payload_hash=payload_hash(old), **ask) is None
    assert refusal_after_signature(candidate, computed_payload_hash=payload_hash(new), **ask).startswith(
        "revoked-key verification failure: "
    )

    # The same key, arriving from a file beside a certificate that names no key.
    nameless = sign_document({"run_id": "r", "timestamp_utc": "2026-11-21T00:00:00Z"}, pem)
    _, from_file = _resolve(nameless, anchored, implicit_key_id=IMPLICIT_KEY_ID, pubkey_path=key_file)
    assert from_file.entry is None
    assert refusal_after_signature(
        from_file, registry_path=anchored, document=nameless, computed_payload_hash=payload_hash(nameless)
    ).startswith("key-file verification failure: ")


# --- end to end: one condition, one exit code ---------------------------------------------------


def _archive_of(path):
    return path.parent


def _commands():
    return {
        "verify_certificate.py": (CERTIFICATE, "--no-ledger"),
        "verify_archive_receipt.py": (_archive_of(CERTIFICATE),),
        "verify_baseline_record.py": (BASELINE, "--no-ledger"),
    }


@pytest.mark.parametrize("verifier", VERIFIERS)
@pytest.mark.parametrize("flags", [(), ("--require-registry",), ("--pubkey", KEY_FILE)], ids=["by default", "--require-registry", "--pubkey"])
def test_no_readable_registry_is_exit_six_from_all_three(verifier, flags, tmp_path):
    # The three commands that returned 1, 3 and 5, and the three that passed with a warning.
    target, *rest = _commands()[verifier]
    _published(CERTIFICATE), _published(BASELINE)
    result = _run(verifier, target, *rest, *flags, "--key-registry", tmp_path / "does-not-exist.json")
    assert result.returncode == CHECK_NOT_PERFORMED, result.stderr
    assert "key registry unavailable" in result.stderr and "nothing about this document was verified" in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("flags", [(), ("--require-registry",), ("--pubkey", None)], ids=["by default", "--require-registry", "--pubkey"])
def test_a_named_key_the_registry_lacks_is_exit_six_from_all_three(flags, key, tmp_path):
    # The three commands that returned 1, 2 or 0, and 5 or 0. Each document
    # here is signed by the key in the file, so each would verify against it.
    private, pem, _, key_file = key
    flags = tuple(key_file if flag is None else flag for flag in flags)
    certificate = tmp_path / "audit.json"
    certificate.write_text(json.dumps(_resigned(_published(CERTIFICATE), pem, A_NAME_THE_REGISTRY_LACKS)), encoding="utf-8")
    record = tmp_path / "baseline.json"
    record.write_text(json.dumps(_resigned(_published(BASELINE), pem, A_NAME_THE_REGISTRY_LACKS)), encoding="utf-8")
    archive = _receipt_archive(tmp_path, "archive", private, A_NAME_THE_REGISTRY_LACKS)

    for verifier, argv in (
        ("verify_certificate.py", (certificate, "--no-ledger")),
        ("verify_archive_receipt.py", (archive,)),
        ("verify_baseline_record.py", (record, "--no-ledger")),
    ):
        result = _run(verifier, *argv, *flags)
        assert result.returncode == CHECK_NOT_PERFORMED, (verifier, result.stderr)
        assert result.stderr == f"ERROR: signing_key_id not found in key registry: {A_NAME_THE_REGISTRY_LACKS}\n", verifier
        assert result.stdout == "", verifier


def test_the_one_command_reports_a_bundle_fact_as_unknown_and_not_as_failed(key, tmp_path):
    # It read 1, 3 and 5 from the three tools as failures of the document.
    _, _, public, _ = key
    _published(CERTIFICATE)
    someone_elses = tmp_path / "someone-elses.json"
    someone_elses.write_text(json.dumps({"keys": [{"key_id": "theirs", "pubkey_pem": public, "status": "active"}]}), encoding="utf-8")
    for document in (CERTIFICATE, BASELINE):
        _published(document)
        for registry in (tmp_path / "does-not-exist.json", someone_elses):
            result = _run("verify_evidence.py", _archive_of(document), "--key-registry", registry)
            assert result.returncode == 1, result.stdout + result.stderr
            assert "FAILED" not in result.stdout and "NOT ESTABLISHED" in result.stdout
            # And it is not worded as a signature that was checked and failed.
            assert "signature did not verify" not in result.stdout, result.stdout
            assert re.search(r"UNKNOWN signing trust +the signature check could not be performed", result.stdout), result.stdout


def test_the_documented_bundle_verifies_and_one_that_lost_its_registry_does_not(tmp_path):
    # The eight paths README.md lists for a minimal copied bundle, and one archive.
    _published(CERTIFICATE)
    for relative in (
        "tools/verify_certificate.py",
        "tools/verify_itgl.py",
        "tools/verify_archive_receipt.py",
        "tools/itgl.py",
        "tools/key_registry.py",
        "spec/sdl.pub",
        "spec/pubkeys/key_registry.v1.json",
        "spec/pubkeys/key_registry.v1.schema.json",
    ):
        (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / relative).write_bytes((REPO / relative).read_bytes())
    archive = tmp_path / "archive"
    for source in _archive_of(CERTIFICATE).rglob("*"):
        if source.is_file():
            destination = archive / source.relative_to(_archive_of(CERTIFICATE))
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())

    def verify(*flags):
        return subprocess.run(
            [sys.executable, "tools/verify_certificate.py", "archive/audit.json", "--ledger", "archive/proofs/itgl_ledger.jsonl", *flags],
            capture_output=True, text=True, cwd=tmp_path,
        )

    def receipt():
        return subprocess.run(
            [sys.executable, "tools/verify_archive_receipt.py", "archive"], capture_output=True, text=True, cwd=tmp_path
        )

    documented = verify()
    assert documented.returncode == 0, documented.stderr
    assert "key registry spec/pubkeys/key_registry.v1.json entry signing_key_id=" in documented.stdout
    assert verify("--require-registry").stdout == documented.stdout
    assert receipt().returncode == 0

    (tmp_path / "spec" / "pubkeys" / "key_registry.v1.json").unlink()
    assert verify().returncode == CHECK_NOT_PERFORMED
    assert verify("--require-registry").returncode == CHECK_NOT_PERFORMED
    assert verify("--pubkey", "spec/sdl.pub").returncode == CHECK_NOT_PERFORMED
    assert receipt().returncode == CHECK_NOT_PERFORMED


def test_the_receipt_verifier_asks_the_candidate_and_not_a_manifest_row(key, tmp_path):
    # The near miss of 19 November, in the form it would take now: the loop
    # over the manifest's files binds `entry`, and the check after the
    # signature has to be asked of the key's entry.
    private, _, public, _ = key
    archive = _receipt_archive(tmp_path, "later", private, "gone")
    registry = _registry(
        tmp_path, "revoked",
        {"key_id": "gone", "pubkey_pem": public, "status": "revoked", "revoked_utc": "2026-10-06T00:00:00Z", ANCHORED_FIELD: []},
    )
    refused = _run("verify_archive_receipt.py", archive, "--key-registry", registry)
    assert refused.returncode == 2 and "revoked-key verification failure" in refused.stderr


# --- our own callers carry a registry ---------------------------------------------------------


def test_the_required_workflow_verifies_through_the_registry_it_wrote():
    # Five lines of this workflow verified with the CI key against a registry
    # path chosen because it did not exist. That worked through the fallback,
    # and nothing here can run a workflow, so what is held is what can be
    # read: every verification names the registry the same job enrolled its
    # key in, and the key id the job signs with is the one enrolled.
    text = WORKFLOW.read_text(encoding="utf-8")
    written = re.findall(r'pathlib\.Path\("([^"]+)"\)\.write_text\(json\.dumps\(\{\s*"keys"', text)
    assert len(written) == 1, written
    (registry,) = written
    assert f"SDL_KEY_REGISTRY={registry}" in text

    enrolled = re.search(r'"key_id": "([^"]+)"', text).group(1)
    assert f"SDL_SIGNING_KEY_ID={enrolled}" in text

    verifications = [line for line in text.splitlines() if "sir verify" in line]
    assert len(verifications) >= 5
    for line in verifications:
        assert f"--key-registry {registry} " in line, line


def test_no_key_material_reaches_anything_the_two_functions_hand_back_to_be_printed(key, tmp_path):
    # Both take key material and return sentences a verifier prints, which is
    # the shape a taint analysis flags. What they return is asserted here, so
    # a dismissal of that finding rests on a test and not on a paragraph.
    private, pem, public, key_file = key
    old = sign_document({"run_id": "r", "timestamp_utc": "2026-01-01T00:00:00Z", "signing_key_id": "gone"}, pem)
    new = sign_document({"run_id": "r", "timestamp_utc": "2026-11-21T00:00:00Z", "signing_key_id": "gone"}, pem)
    nameless = sign_document({"run_id": "r", "timestamp_utc": "2026-11-21T00:00:00Z"}, pem)
    revoked = {"key_id": "gone", "pubkey_pem": public, "status": "revoked", "revoked_utc": "2026-10-06T00:00:00Z"}
    anchored = _registry(tmp_path, "anchored", {**revoked, ANCHORED_FIELD: [payload_hash(old)]})
    unlisted = dict(new, signing_key_id=A_NAME_THE_REGISTRY_LACKS)

    printed = [
        str(_refused(new, tmp_path / "absent.json")),
        str(_refused(new, _unreadable(tmp_path))),
        str(_refused(new, _registry(tmp_path, "no-set", revoked))),
        str(_refused(unlisted, anchored, pubkey_path=key_file)),
        str(_refused(nameless, anchored, implicit_key_id=IMPLICIT_KEY_ID, pubkey_path=tmp_path / "no.pub")),
        str(_refused({"signing_key_id": "broken"}, _registry(tmp_path, "bad", {"key_id": "broken", "pubkey_pem": "not a key"}))),
    ]
    (by_name,) = _resolve(new, anchored)
    implicit, from_file = _resolve(nameless, anchored, implicit_key_id=IMPLICIT_KEY_ID, pubkey_path=key_file)
    printed += [by_name.source, implicit.source, from_file.source]
    printed.append(refusal_after_signature(by_name, registry_path=anchored, document=new, computed_payload_hash=payload_hash(new)))
    printed.append(
        refusal_after_signature(from_file, registry_path=anchored, document=nameless, computed_payload_hash=payload_hash(nameless))
    )
    assert all(isinstance(sentence, str) and sentence for sentence in printed)

    material = [line for line in (pem + public).splitlines() if line and not line.startswith("-----")]
    for sentence in printed:
        assert "BEGIN" not in sentence
        assert not [line for line in material if line in sentence], "a line of key material reached something a verifier prints"
