"""The CLI must dispatch on consent flavour, not assume the canonical one.

Two flavours verify against different preimages. A CLI that hard-codes the
canonical path reports ``none`` for a correctly-signed transaction-bound receipt,
which reads as "no consent present" on a receipt that has one. That false negative
was live until this file existed.
"""
import base64
import gzip
import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from avm_ac2 import TXN_CONSENT_KEY, build_txn_consent, build_consent, consent_payload
from avm_ac2.cli import main
from avm_mesh import sealed
from avm_proofpack.verify import TrustedVoters

HERE = pathlib.Path(__file__).resolve().parent
CAPTURES = HERE / "captures"
VOI = "voi-proofpack-24213754.json.gz"
VOI_GENESIS = "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="
CHAIN = "voimain-v1.0"


def _bundle():
    return json.load(gzip.open(CAPTURES / VOI, "rt"))


def _anchor(b):
    prev = b["previous_state_proof_message"]
    return TrustedVoters(base64.b64decode(prev["voters_commitment_b64"]),
                         int(prev["ln_proven_weight"]))


def _settlement(b):
    return {"chain": CHAIN, "txid": b["transaction"]["txid"],
            "round": b["transaction"]["round"], "amount": "0", "asset": 586896}


def _write(tmp_path, envelope):
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    return str(path)


def test_cli_reports_transaction_bound_flavour(tmp_path, capsys):
    """The path that reaches sender_bound on its own.

    A transaction-bound consent is sender-bound BY CONSTRUCTION: the signing key is
    the sending account. So this receipt reaches the level without the caller doing
    any key comparison.
    """
    flavour = "transaction_bound"
    b = _bundle()
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    if flavour == "transaction_bound":
        from avm_ac2 import signing_preimage
        block = build_txn_consent(
            did="did:key:z6MkCli", public_key_b64=base64.b64encode(pk).decode(),
            signature_b64=base64.b64encode(sk.sign(signing_preimage(b, CHAIN))).decode(),
            bundle=b, genesis_id=CHAIN)
        content = {"version": 1, "settlement": _settlement(b), TXN_CONSENT_KEY: block}
    else:
        settlement = _settlement(b)
        block = build_consent(
            did="did:key:z6MkCli", sig_hint="raw-ed25519",
            public_key_b64=base64.b64encode(pk).decode(),
            signature_b64=base64.b64encode(sk.sign(consent_payload(settlement))).decode(),
            settlement=settlement)
        content = {"version": 1, "settlement": settlement, "ac2_consent": block}

    envelope = sealed.seal(content, b, VOI, trusted_voters=_anchor(b))
    rc = main(["verify", _write(tmp_path, envelope),
               "--evidence", str(CAPTURES), "--genesis", VOI_GENESIS,
               "--min-level", "sender_bound"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert flavour in out, out
    assert "sender_bound" in out


def test_cli_reports_canonical_flavour_without_claiming_sender_binding(tmp_path, capsys):
    """The canonical flavour's level depends on whether the caller asked for binding.

    Supplying --evidence means "bind to the authenticated sender", so a consent made
    with a key that is not the payer is REFUSED rather than quietly downgraded. Omit
    the evidence and the same receipt honestly reports consent_present. Both halves
    are asserted, because the refusal alone could pass for a broken verifier.
    """
    b = _bundle()
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    settlement = _settlement(b)
    block = build_consent(
        did="did:key:z6MkCli", sig_hint="raw-ed25519",
        public_key_b64=base64.b64encode(pk).decode(),
        signature_b64=base64.b64encode(sk.sign(consent_payload(settlement))).decode(),
        settlement=settlement)
    envelope = sealed.seal({"version": 1, "settlement": settlement,
                            "ac2_consent": block},
                           b, VOI, trusted_voters=_anchor(b))
    receipt = _write(tmp_path, envelope)

    # No evidence => no sender binding attempted => the honest weaker level.
    rc = main(["verify", receipt, "--min-level", "consent_present"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "canonical_payload" in out
    assert "consent_present" in out

    # Evidence supplied => sender binding is required => a non-payer is refused.
    rc2 = main(["verify", receipt, "--evidence", str(CAPTURES),
                "--genesis", VOI_GENESIS])
    assert rc2 == 2
    assert "not the key that authorised" in capsys.readouterr().err


def test_cli_refuses_a_transaction_bound_receipt_without_evidence(tmp_path, capsys):
    """Without the bundle the preimage cannot be rebuilt, so it must refuse."""
    b = _bundle()
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    from avm_ac2 import signing_preimage
    block = build_txn_consent(
        did="did:key:z6MkCli", public_key_b64=base64.b64encode(pk).decode(),
        signature_b64=base64.b64encode(sk.sign(signing_preimage(b, CHAIN))).decode(),
        bundle=b, genesis_id=CHAIN)
    envelope = sealed.seal({"version": 1, "settlement": _settlement(b),
                            TXN_CONSENT_KEY: block},
                           b, VOI, trusted_voters=_anchor(b))
    rc = main(["verify", _write(tmp_path, envelope)])
    assert rc == 2
    assert "needs --evidence" in capsys.readouterr().err
