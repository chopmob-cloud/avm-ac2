"""``avm-ac2`` -- check the AC2 consent inside a sealed settlement receipt.

Three read-only subcommands:

    avm-ac2 payload <settlement.json>                     bytes to be signed
    avm-ac2 verify  <sealed.json> --evidence <dir> [...]  full report
    avm-ac2 level   <sealed.json> --evidence <dir> [...]  one line

``verify`` and ``level`` re-derive the sender from the bundle's authenticated
``SignedTxnInBlock`` rather than accepting it from the receipt, because a value a
receipt asserts about itself is not evidence for itself.
"""
from __future__ import annotations

import argparse
import base64
import json
import pathlib
import sys

from avm_mesh import MeshError
from avm_mesh.receipt import create_receipt, verify_receipt

from .consent import consent_level, consent_payload
from .txn_consent import TXN_CONSENT_KEY, verify_txn_consent

LEVEL_ORDER = ["none", "consent_present", "sender_bound", "consensus_bound"]


def _read_json(path: str) -> dict:
    """Read a JSON document, transparently handling gzip.

    Proofpacks are routinely stored gzipped (``*.json.gz``), and a plain
    ``read_text`` on one dies with a UnicodeDecodeError on the gzip magic byte
    ``0x8b`` — which reads like a corrupt fixture rather than an unhandled
    format. Sniff the magic number instead of trusting the extension, because a
    capture can be named either way.
    """
    raw = pathlib.Path(path).read_bytes()
    if raw[:2] == b"\x1f\x8b":
        import gzip

        raw = gzip.decompress(raw)
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise MeshError(f"{path} does not contain a JSON object")
    return data


def _resolve_from(directory: str):
    """Resolve a proofpack from a directory, refusing to leave it.

    One path component, and the resolved path must stay inside the directory: the
    uri comes from the receipt, which is the untrusted input here.
    """
    root = pathlib.Path(directory).resolve()

    def resolve(uri: str) -> dict:
        name = str(uri).rsplit("/", 1)[-1]
        if not name or name.startswith(".") or "/" in name or "\\" in name:
            raise MeshError(f"refusing to resolve a path-like uri: {uri!r}")
        candidate = (root / name).resolve()
        if candidate != root and root not in candidate.parents:
            raise MeshError(f"resolved path escapes the evidence directory: {uri!r}")
        if not candidate.is_file():
            raise MeshError(f"no evidence file for {uri!r} in {root}")
        return _read_json(str(candidate))

    return resolve


def _cmd_payload(args: argparse.Namespace) -> int:
    sys.stdout.write(consent_payload(_read_json(args.settlement)).decode("utf-8"))
    sys.stdout.write("\n")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    envelope = _read_json(args.receipt)

    report = None
    bundle = None
    if args.evidence:
        from avm_proofpack.verify import TrustedVoters

        content = json.loads(base64.b64decode(envelope["canonical_bytes_b64"]).decode())
        attestation = content.get("consensus_attestation") or {}
        uri = attestation.get("evidence_uri")
        if not uri:
            raise MeshError("sealed receipt carries no consensus attestation to resolve")

        voter = None
        if args.voters_commitment and args.ln_proven_weight is not None:
            voter = TrustedVoters(base64.b64decode(args.voters_commitment.encode()),
                                  int(args.ln_proven_weight))
        bundle = _resolve_from(args.evidence)(uri)
        # Public path: build a receipt over the resolved bundle, then verify it.
        # The report (chain, txid, round, tier) comes out of the verification,
        # never off the receipt's own claims.
        receipt = create_receipt(bundle, uri, trusted_voters=voter)
        report = verify_receipt(
            receipt,
            lambda _u: bundle,
            trusted_voters=voter,
            expected_genesis_hash_b64=args.genesis,
        )

    # Two consent flavours exist and they verify against different preimages. The
    # CLI must dispatch on which block is present rather than assuming the
    # canonical one: reporting 'none' for a valid transaction-bound consent
    # would be a false negative on a correctly signed receipt.
    import base64 as _b64
    import json as _json
    _content = _json.loads(_b64.b64decode(envelope["canonical_bytes_b64"]))
    if TXN_CONSENT_KEY in _content:
        if bundle is None or report is None:
            raise MeshError(
                "a transaction-bound consent needs --evidence and a resolvable "
                "proofpack to rebuild the signed preimage"
            )
        out = verify_txn_consent(envelope, bundle, report.genesis_id,
                                 require=args.require)
        out["flavour"] = "transaction_bound"
    else:
        out = consent_level(envelope, report, bundle=bundle, require=args.require)
        out["flavour"] = "canonical_payload"

    if args.json:
        print(json.dumps({**out, "settlement_tier": getattr(report, "trust_root", None)},
                         indent=2, sort_keys=True))
    else:
        print(f"consent level: {out['level']}  ({out.get('flavour', '-')})")
        if report is not None:
            print(f"settlement:    {report.genesis_id} {report.txid[:16]}... "
                  f"round {report.round} ({report.trust_root})")
        print(f"controller:    {out.get('did') or '-'}")
        print(f"why:           {out['reason']}")

    if args.min_level and LEVEL_ORDER.index(out["level"]) < LEVEL_ORDER.index(args.min_level):
        print(f"below required level {args.min_level}: {out['level']}", file=sys.stderr)
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="avm-ac2",
        description="Check AC2 consent inside a sealed avm-mesh settlement receipt.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pay = sub.add_parser("payload", help="print the exact bytes a controller signs")
    pay.add_argument("settlement", help="JSON file describing the settlement")
    pay.set_defaults(func=_cmd_payload)

    for name, help_text in (("verify", "verify consent and print a report"),
                            ("level", "same check, report only the level")):
        v = sub.add_parser(name, help=help_text)
        v.add_argument("receipt", help="sealed receipt JSON")
        v.add_argument("--evidence", default=None,
                       help="directory holding the proofpack the attestation names")
        v.add_argument("--genesis", default=None,
                       help="pinned genesis hash, base64 (checked against the header)")
        v.add_argument("--voters-commitment", default=None,
                       help="trusted voters commitment, base64")
        v.add_argument("--ln-proven-weight", type=int, default=None)
        v.add_argument("--require", action="store_true",
                       help="fail if the receipt carries no consent block")
        v.add_argument("--min-level", default=None, choices=LEVEL_ORDER,
                       help="exit non-zero unless at least this level was reached")
        v.add_argument("--json", action="store_true", help="machine-readable output")
        v.set_defaults(func=_cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (MeshError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
