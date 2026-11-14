"""End-to-end AC2 consent binding, on real Algorand AND Voi mainnet captures.

    python examples/ac2_consent_demo.py

Per chain it:
  1. verifies the checked-in mainnet capture against a pinned genesis and anchor,
  2. reads the payer out of the AUTHENTICATED SignedTxnInBlock,
  3. seals a receipt carrying an AC2 consent block,
  4. verifies the consent and prints the level reached,
  5. shows three refusals: a foreign key, a replay, and an edit after sealing.

READ THIS BEFORE QUOTING THE OUTPUT
-----------------------------------
The demo generates the consent keypair, because the mainnet accounts' private keys
are not ours. So step 4 proves the *machinery* on real chain evidence; the "payer
approved" half uses a key the demo holds. The output says so on every run.
"""
from __future__ import annotations

import base64
import gzip
import json
import pathlib
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = pathlib.Path(__file__).resolve().parents[1]
try:
    import avm_ac2  # noqa: F401
except ImportError:  # pragma: no cover - developer convenience
    sys.path.insert(0, str(ROOT / "src"))

from avm_ac2 import (  # noqa: E402
    LEVEL_CONSENSUS, LEVEL_SENDER, build_consent, consent_level, consent_payload,
    sender_from_bundle, verify_consent,
)
from avm_mesh import MeshError, sealed  # noqa: E402
from avm_mesh.receipt import _verify_bundle_dict  # noqa: E402
from avm_proofpack.verify import TrustedVoters  # noqa: E402

#: The captures live in the avm-mesh checkout beside this one, or wherever
#: AVM_MESH_EXAMPLES points. Located rather than assumed, so a missing fixture
#: fails loudly instead of quietly skipping both chains.
CANDIDATES = [
    ROOT.parent / "avm-mesh" / "examples",
    ROOT.parent / "worktrees" / "avm-mesh-main" / "examples",
]

CHAINS = [
    ("Algorand mainnet", "proofpack-66457600.json",
     "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="),
    ("Voi mainnet", "voi-proofpack-24213754.json.gz",
     "r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk="),
]


def examples_dir() -> pathlib.Path:
    env = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else None
    for c in ([env] if env else []) + CANDIDATES:
        if c and (c / "proofpack-66457600.json").exists():
            return c
    raise SystemExit("cannot find the avm-mesh example captures; pass the directory "
                     "as argv[1] or set AVM_MESH_EXAMPLES")


def load(path: pathlib.Path) -> dict:
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw).decode() if path.suffix == ".gz"
                      else raw.decode())


def anchor_for(bundle: dict) -> TrustedVoters:
    prev = bundle["previous_state_proof_message"]
    return TrustedVoters(base64.b64decode(prev["voters_commitment_b64"]),
                         int(prev["ln_proven_weight"]))


def run_chain(label, path, genesis_b64, bundle, report) -> bool:
    print(f"\n{'=' * 72}\n{label}\n{'=' * 72}")
    settlement = {"chain": report.genesis_id, "txid": report.txid,
                  "round": report.round, "amount": "0", "asset": 586896}

    sender = sender_from_bundle(bundle, report.genesis_id)
    print(f"  [1] evidence verified: {report.genesis_id}  "
          f"txid {report.txid[:16]}... round {report.round} ({report.trust_root})")
    print(f"  [2] payer from authenticated STIB: "
          f"{base64.b32encode(sender).decode().rstrip('=')}")

    ok = True
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    consent = build_consent(
        did="did:key:z6MkDemoController", sig_hint="raw-ed25519",
        public_key_b64=base64.b64encode(pk).decode(),
        signature_b64=base64.b64encode(sk.sign(consent_payload(settlement))).decode(),
        settlement=settlement)
    envelope = sealed.seal({"version": 1, "settlement": settlement,
                            "ac2_consent": consent}, bundle, "mem://demo",
                           trusted_voters=anchor_for(bundle))

    out = verify_consent(envelope, expected_sender=pk)
    print(f"  [3] consent verified, level: {out['level']}")
    ok &= out["level"] == LEVEL_SENDER

    combined = consent_level(envelope, report, expected_sender=pk)
    print(f"  [4] with the proofpack: {combined['level']}")
    ok &= combined["level"] == LEVEL_CONSENSUS

    try:
        verify_consent(envelope, expected_sender=sender)
        print("  [5] WRONG-KEY CHECK FAILED (a foreign consent was accepted)")
        ok = False
    except MeshError as exc:
        print(f"  [5] payer binding enforced: {str(exc)[:58]}...")

    replayed = sealed.seal({"version": 1,
                            "settlement": dict(settlement, amount="999999999"),
                            "ac2_consent": consent}, bundle, "mem://demo",
                           trusted_voters=anchor_for(bundle))
    try:
        verify_consent(replayed)
        print("  [6] REPLAY CHECK FAILED (a consent for another settlement passed)")
        ok = False
    except MeshError as exc:
        print(f"  [6] replay refused: {str(exc)[:58]}...")

    from avm_ac2 import canonical_bytes
    content = json.loads(base64.b64decode(envelope["canonical_bytes_b64"]))
    content["ac2_consent"]["did"] = "did:key:z6MkAttacker"
    edited = dict(envelope)
    edited["canonical_bytes_b64"] = base64.b64encode(canonical_bytes(content)).decode()
    try:
        verify_consent(edited)
        print("  [7] TAMPER CHECK FAILED (an edited consent passed)")
        ok = False
    except MeshError as exc:
        print(f"  [7] edit detected: {str(exc)[:58]}...")

    print(f"  --> {'PASS' if ok else 'FAIL'} on {report.genesis_id}")
    print(f"      NOTE: the consent key is generated by this demo "
          f"({base64.b32encode(pk).decode().rstrip('=')[:10]}...), not the real")
    print(f"      payer. The chain evidence is real; the approval is synthetic.")
    return ok


def main() -> int:
    where = examples_dir()
    print(f"AC2 <-> avm-mesh consent binding, on real mainnet captures ({where})")
    results = []
    for label, name, genesis_b64 in CHAINS:
        bundle = load(where / name)
        report = _verify_bundle_dict(bundle, anchor_for(bundle),
                                     base64.b64decode(genesis_b64))
        results.append(run_chain(label, where / name, genesis_b64, bundle, report))

    print(f"\n{'=' * 72}")
    if all(results):
        print("RESULT: PASS -- consent binding works on Algorand and Voi; "
              "every refusal held")
        return 0
    print("RESULT: FAIL -- see the FAIL line above")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
