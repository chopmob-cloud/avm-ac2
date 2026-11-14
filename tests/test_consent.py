"""avm-ac2 tests: consent binding on REAL Algorand and Voi mainnet captures.

The fixtures are the ones `avm-mesh` ships in its own `examples/`, imported
through the installed `avm-mesh` package rather than copied here, so this suite
cannot drift from the captures the parent project validates against.

Every capture is pinned by SHA-256. The chain evidence is real; the consent keys
are generated per test, because the mainnet accounts' private keys are not ours
to hold -- and pretending otherwise is precisely the defect this package exists to
avoid. Where a test needs the "payer approved" path it constructs a keypair it
owns and says so.
"""
import base64
import gzip
import hashlib
import json
import os
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from avm_ac2 import (
    LEVEL_CONSENSUS,
    LEVEL_CONSENT,
    LEVEL_NONE,
    LEVEL_SENDER,
    ConsentAttestation,
    build_consent,
    consent_digest,
    consent_level,
    consent_payload,
    sender_from_bundle,
    verify_consent,
)
from avm_mesh import MeshError, sealed
from avm_mesh.receipt import _verify_bundle_dict
from avm_proofpack.verify import TrustedVoters

#: Locate the captures through the installed avm-mesh, so this package tests
#: against the same artefacts the parent ships. A wheel install has no examples/
#: directory, so fall back to an explicit env var and skip loudly if absent.
import avm_mesh  # noqa: E402

_PKG_DIR = pathlib.Path(avm_mesh.__file__).resolve().parent
_ENV = os.environ.get("AVM_MESH_EXAMPLES")
CANDIDATES = ([pathlib.Path(_ENV)] if _ENV else []) + [
    _PKG_DIR.parents[1] / "examples",           # editable install: repo/examples
    pathlib.Path(__file__).resolve().parents[3] / "avm-mesh" / "examples",
]

ALGORAND_GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="
VOI_GENESIS = "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="

PINS = {
    "proofpack-66457600.json":
        "2f1dfad4286362d5294beacfcc8304233f9f177804852b261b207e2f0e3cdfe9",
    "voi-proofpack-24213754.json.gz":
        "5ba9ffb8a97da8ea477a5c22e929bc89af954479ad306b003b09375c84a8fc57",
}


def _examples() -> pathlib.Path:
    for c in CANDIDATES:
        if (c / "proofpack-66457600.json").exists():
            return c
    pytest.skip("avm-mesh example captures not found; set AVM_MESH_EXAMPLES")


def _load(name: str) -> dict:
    path = _examples() / name
    raw = path.read_bytes()
    text = gzip.decompress(raw).decode() if name.endswith(".gz") else raw.decode()
    return json.loads(text)


def _anchor(bundle: dict) -> TrustedVoters:
    prev = bundle["previous_state_proof_message"]
    return TrustedVoters(base64.b64decode(prev["voters_commitment_b64"]),
                         int(prev["ln_proven_weight"]))


@pytest.fixture(scope="module")
def algorand():
    bundle = _load("proofpack-66457600.json")
    report = _verify_bundle_dict(bundle, _anchor(bundle),
                                 base64.b64decode(ALGORAND_GENESIS))
    assert report.trust_root == "stake_attested"
    return bundle, report


@pytest.fixture(scope="module")
def voi():
    bundle = _load("voi-proofpack-24213754.json.gz")
    report = _verify_bundle_dict(bundle, _anchor(bundle),
                                 base64.b64decode(VOI_GENESIS))
    assert report.trust_root == "stake_attested"
    return bundle, report


def _settlement(report) -> dict:
    """A settlement built from the report's own verified values."""
    return {"chain": report.genesis_id, "txid": report.txid,
            "round": report.round, "amount": "0", "asset": 586896}


def _keypair():
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _seal(settlement, bundle, *, sk, pk):
    consent = build_consent(
        did="did:key:z6MkTestController", sig_hint="raw-ed25519",
        public_key_b64=base64.b64encode(pk).decode(),
        signature_b64=base64.b64encode(sk.sign(consent_payload(settlement))).decode(),
        settlement=settlement,
    )
    return sealed.seal({"version": 1, "settlement": settlement, "ac2_consent": consent},
                       bundle, "mem://t", trusted_voters=_anchor(bundle)), consent


# ------------------------------------------------------------------ both chains

@pytest.mark.parametrize("name", ["algorand", "voi"])
def test_the_sender_is_read_from_authenticated_bytes_on_both_chains(name, request):
    """The binding input is a fact about the chain, not a field a producer chose."""
    bundle, report = request.getfixturevalue(name)
    sender = sender_from_bundle(bundle, report.genesis_id)

    assert isinstance(sender, bytes) and len(sender) == 32
    assert report.genesis_id == {"algorand": "mainnet-v1.0",
                                 "voi": "voimain-v1.0"}[name]


@pytest.mark.parametrize("name", ["algorand", "voi"])
def test_binding_succeeds_when_consent_key_is_the_sender(name, request):
    """The pass path on both chains, with a key this test owns."""
    bundle, report = request.getfixturevalue(name)
    settlement = _settlement(report)
    sk, pk = _keypair()

    envelope, _ = _seal(settlement, bundle, sk=sk, pk=pk)
    out = verify_consent(envelope, expected_sender=pk)
    assert out["level"] == LEVEL_SENDER, out

    combined = consent_level(envelope, report, expected_sender=pk)
    assert combined["level"] == LEVEL_CONSENSUS, combined


@pytest.mark.parametrize("name", ["algorand", "voi"])
def test_a_consent_from_a_foreign_key_is_refused_on_both_chains(name, request):
    """An approval by someone who did not pay must not pass as sender-bound."""
    bundle, report = request.getfixturevalue(name)
    settlement = _settlement(report)
    sk, pk = _keypair()

    envelope, _ = _seal(settlement, bundle, sk=sk, pk=pk)
    # Valid signature, but not the payer.
    assert verify_consent(envelope)["level"] == LEVEL_CONSENT

    sender = sender_from_bundle(bundle, report.genesis_id)
    with pytest.raises(MeshError) as exc:
        verify_consent(envelope, expected_sender=sender)
    assert "not the key that authorised this transaction" in str(exc.value)


@pytest.mark.parametrize("name", ["algorand", "voi"])
def test_a_consent_cannot_be_replayed_onto_another_settlement(name, request):
    bundle, report = request.getfixturevalue(name)
    settlement = _settlement(report)
    sk, pk = _keypair()
    _, consent = _seal(settlement, bundle, sk=sk, pk=pk)

    forged = sealed.seal(
        {"version": 1, "settlement": dict(settlement, amount="999999"), 
         "ac2_consent": consent},
        bundle, "mem://t", trusted_voters=_anchor(bundle))
    with pytest.raises(MeshError) as exc:
        verify_consent(forged)
    assert "different settlement payload" in str(exc.value)


# ---------------------------------------------------------------- fail-closed

def test_editing_the_consent_breaks_the_content_hash(algorand):
    from avm_ac2 import canonical_bytes

    bundle, report = algorand
    settlement = _settlement(report)
    sk, pk = _keypair()
    envelope, _ = _seal(settlement, bundle, sk=sk, pk=pk)

    content = json.loads(base64.b64decode(envelope["canonical_bytes_b64"]))
    content["ac2_consent"]["did"] = "did:key:z6MkAttacker"
    envelope["canonical_bytes_b64"] = base64.b64encode(canonical_bytes(content)).decode()

    with pytest.raises(MeshError) as exc:
        verify_consent(envelope)
    assert "content hash mismatch" in str(exc.value)


def test_a_bad_signature_is_refused(algorand):
    bundle, report = algorand
    settlement = _settlement(report)
    _, pk = _keypair()
    consent = build_consent(
        did="did:key:z6MkX", sig_hint="raw-ed25519",
        public_key_b64=base64.b64encode(pk).decode(),
        signature_b64=base64.b64encode(b"\x00" * 64).decode(),
        settlement=settlement)
    envelope = sealed.seal(
        {"version": 1, "settlement": settlement, "ac2_consent": consent},
        bundle, "mem://t", trusted_voters=_anchor(bundle))
    with pytest.raises(MeshError) as exc:
        verify_consent(envelope)
    assert "does not verify" in str(exc.value)


def test_no_consent_reports_none_and_never_a_pass(algorand):
    """Absence must be visible: 'nothing found' is not 'verified'."""
    bundle, report = algorand
    settlement = _settlement(report)
    envelope = sealed.seal({"version": 1, "settlement": settlement},
                           bundle, "mem://t", trusted_voters=_anchor(bundle))
    out = verify_consent(envelope)
    assert out["level"] == LEVEL_NONE
    with pytest.raises(MeshError):
        verify_consent(envelope, require=True)


def test_unknown_consent_version_is_refused_by_name():
    with pytest.raises(MeshError) as exc:
        ConsentAttestation.from_dict({
            "version": 99, "did": "did:key:x", "sig_hint": "raw-ed25519",
            "public_key": "AA==", "signature": "AA==",
            "signed_payload_sha256": "0" * 64})
    assert "unsupported ac2_consent version 99" in str(exc.value)


def test_unknown_chain_is_refused_not_guessed(algorand):
    """A chain with no effect profile must not inherit a sender-binding claim."""
    bundle, _ = algorand
    with pytest.raises(MeshError) as exc:
        sender_from_bundle(bundle, "hedera-mainnet")
    assert "no effect profile" in str(exc.value)


def test_consent_digest_covers_every_settlement_field():
    """Changing any settlement field must change the signed payload."""
    base = {"chain": "mainnet-v1.0", "txid": "A" * 52, "round": 1,
            "amount": "0", "asset": 586896}
    reference = consent_digest(base)
    for field, value in [("chain", "voimain-v1.0"), ("txid", "B" * 52),
                         ("round", 2), ("amount", "1"), ("asset", 1)]:
        assert consent_digest(dict(base, **{field: value})) != reference, field


@pytest.mark.parametrize("name,expected", list(PINS.items()))
def test_captures_are_the_ones_this_suite_was_written_against(name, expected):
    raw = (_examples() / name).read_bytes()
    data = gzip.decompress(raw) if name.endswith(".gz") else raw
    assert hashlib.sha256(data).hexdigest() == expected
