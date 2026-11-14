#!/usr/bin/env python3
"""Assert the settlement captures are the bytes their digests were taken over.

The captures in ``tests/captures`` are pinned by SHA-256 in the test suite. A
checkout-time rewrite — most commonly a line-ending rule — changes those bytes and
the assertion fails *inside a test*, where it reads like a verification bug rather
than an environment problem. This script fails earlier and says which file moved.

Run it from the repository root, or with ``--repo`` pointing at it.
"""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys

#: SHA-256 of each capture exactly as captured. Changing a capture means changing
#: this table, which is the point: a silent drift becomes a failing build.
EXPECTED = {
    "proofpack-66457600.json":
        "2f1dfad4286362d5294beacfcc8304233f9f177804852b261b207e2f0e3cdfe9",
    "voi-proofpack-24213754.json.gz":
        "94bd5e249f39f062790c7afa5193235369f0cc04e0f7b0a8318043e90876580f",
}


def check(repo: pathlib.Path) -> int:
    base = repo / "tests" / "captures"
    failures = 0
    for name, want in EXPECTED.items():
        path = base / name
        if not path.is_file():
            print(f"{name}: MISSING at {path}")
            failures += 1
            continue
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        if got == want:
            print(f"{name}: OK")
        else:
            print(f"{name}: CHANGED\n  expected {want}\n  got      {got}")
            failures += 1
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="repository root")
    args = parser.parse_args(argv)
    return check(pathlib.Path(args.repo).resolve())


if __name__ == "__main__":
    raise SystemExit(main())
