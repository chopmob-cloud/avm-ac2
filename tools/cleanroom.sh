#!/bin/sh
# Clean-room gate for avm-ac2. Runs INSIDE the container, against the installed wheel.
#
#   sh /work/ac2/tools/cleanroom.sh /work/ac2
#
# Exits non-zero if anything is unproven rather than merely unsuccessful:
#   - a wheel is missing from the artefact set
#   - any test SKIPS (a skip means an input was not staged, not that the code is fine)
#   - pytest collects suspiciously little (an import error aborts collection)
#   - the shipped example does not drive BOTH chains
#   - a refusal check in the example fails
#
# A stage that could not run must fail: reporting PASS for work that did not
# happen is worse than a red result, because the run then certifies it.

set -u

WORK="${1:-/work/ac2}"
ART="$WORK/artefacts"
SRC="$WORK/src/avm-ac2"
AC2_SRC="$WORK/src/avm-ac2"
VENV="$WORK/venv"

# The captures ship inside this repository (tests/captures), so a missing one is a
# packaging defect rather than an unstaged input. EXAMPLES points at them, and
# REQUIRED_EXAMPLES below asserts the files, not the directory.
EXAMPLES="$AC2_SRC/tests/captures"
REQUIRED_EXAMPLES="$EXAMPLES"

FAILED=0
verdict() {  # verdict <rc> <stage>
    if [ "$1" -eq 0 ]; then
        echo "PASS  $2"
    else
        echo "FAIL  $2"
        FAILED=1
    fi
}

echo "=== 1. artefact set ==="
for wheel in "$ART"/avm_ac2-*.whl "$ART"/avm_mesh-*.whl "$ART"/avm_proofpack-*.whl \
             "$ART"/avm_effectproof-*.whl "$ART"/cryptography-*.whl "$ART"/cffi-*.whl; do
    [ -f "$wheel" ] || { echo "MISSING $wheel"; FAILED=1; }
done
for cap in proofpack-66457600.json voi-proofpack-24213754.json.gz; do
    [ -f "$EXAMPLES/$cap" ] || { echo "MISSING capture $EXAMPLES/$cap (ships in the repo)"; FAILED=1; }
done
[ -f "$SRC/pyproject.toml" ] || { echo "MISSING $SRC/pyproject.toml"; FAILED=1; }
[ -f "$SRC/README.md" ] || { echo "MISSING $SRC/README.md"; FAILED=1; }
verdict $FAILED "artefacts and captures staged"
[ "$FAILED" -eq 0 ] || { echo "ABORT: install would be meaningless"; exit 1; }

echo "=== 2. offline install ==="
rm -rf "$VENV"
python -m venv "$VENV" >/dev/null 2>&1
# avm-ac2 declares avm-mesh and cryptography as hard dependencies, so the install
# proves the closure rather than hand-listing it here.
"$VENV"/bin/pip install -q --no-index --find-links "$ART" avm_ac2 pytest >/tmp/install.log 2>&1
verdict $? "offline install from wheels only"

EXPECTED_VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$SRC/pyproject.toml" | head -1 | tr -d '\r')
[ -n "$EXPECTED_VERSION" ] || { echo "cannot read version from $SRC/pyproject.toml"; exit 1; }
INSTALLED_VERSION=$("$VENV"/bin/pip show avm-ac2 2>/dev/null | sed -n 's/^Version: //p' | tr -d '\r')
if [ "$INSTALLED_VERSION" = "$EXPECTED_VERSION" ]; then
    verdict 0 "installed wheel matches source version $EXPECTED_VERSION"
else
    echo "      expected $EXPECTED_VERSION, installed ${INSTALLED_VERSION:-<none>}"
    verdict 1 "installed wheel does not match source version"
fi

# The sibling must be the version this package was validated against, and must
# come from the wheel rather than a source tree: importing from /work/src would
# exercise files instead of the artefact a user receives.
"$VENV"/bin/python - "$WORK" <<'PY'
import sys, pathlib
work = pathlib.Path(sys.argv[1])
import avm_mesh, avm_ac2, cryptography
for mod in (avm_mesh, avm_ac2):
    p = pathlib.Path(mod.__file__).resolve()
    ok = "site-packages" in str(p) and "/work/src" not in str(p)
    print(f"      {mod.__name__} {getattr(mod,'__version__','?')} from {p}"
          f"{'' if ok else '   <-- NOT from site-packages'}")
    if not ok:
        sys.exit(1)
print(f"      cryptography {cryptography.__version__}")
PY
verdict $? "packages imported from the installed wheels, not the staged source"

echo "=== 3. suite (skips are failures) ==="
# The captures are found through AVM_MESH_EXAMPLES so the suite reads the staged
# artefacts rather than skipping for want of them.
AVM_MESH_EXAMPLES="$EXAMPLES" "$VENV"/bin/python -m pytest "$SRC/tests" -q \
    --junitxml=/tmp/j.xml >/tmp/pytest.log 2>&1
verdict $? "suite passed"
"$VENV"/bin/python - "$SRC" <<'PY'
# xml.etree (not defusedxml): /tmp/j.xml is written by the pytest process two
# lines above from our own staged tests. Never fetched, never external.
import sys, re, pathlib
import xml.etree.ElementTree as ET

src = sys.argv[1]
root = ET.parse("/tmp/j.xml").getroot()
suite = root if root.tag == "testsuite" else root.find("testsuite")
tests = int(suite.get("tests", 0))
skipped = int(suite.get("skipped", 0))
failures = int(suite.get("failures", 0)) + int(suite.get("errors", 0))
print(f"      {tests} tests, {skipped} skipped, {failures} failed/errored")

if tests == 0:
    print("FAIL  pytest collected nothing"); sys.exit(1)
if failures:
    print("FAIL  pytest reported failures or collection errors"); sys.exit(1)
if skipped:
    print("FAIL  tests skipped: an input was not staged"); sys.exit(1)

defined = sum(len(re.findall(r"(?m)^\s*def test_",
                             p.read_text(encoding="utf-8", errors="replace")))
              for p in pathlib.Path(src, "tests").rglob("test_*.py"))
if defined and tests < defined * 0.5:
    print(f"FAIL  collected {tests} against {defined} defined: collection truncated")
    sys.exit(1)
sys.exit(0)
PY
verdict $? "no tests skipped, and collection was complete"

echo "=== 4. the shipped example drives both chains ==="
# Run the example against the INSTALLED wheel. It prefers an installed avm_ac2
# over its own source tree, so this exercises the artefact.
"$VENV"/bin/python "$AC2_SRC/examples/ac2_consent_demo.py" "$EXAMPLES" >/tmp/demo.log 2>&1
DEMO_RC=$?
grep -E "^(  \[|  -->|RESULT)" /tmp/demo.log || tail -10 /tmp/demo.log
grep -q "mainnet-v1.0" /tmp/demo.log && grep -q "voimain-v1.0" /tmp/demo.log \
    || { echo "      the example did not run on BOTH chains"; DEMO_RC=1; }
grep -qE "\] .*CHECK FAILED" /tmp/demo.log && { echo "      a refusal check failed"; DEMO_RC=1; }
grep -q "RESULT: PASS" /tmp/demo.log || { echo "      the example did not report PASS"; DEMO_RC=1; }
verdict $DEMO_RC "consent binding on Algorand and Voi, on the installed wheel"

echo "=== 5. CLI entry point ==="
"$VENV"/bin/avm-ac2 --help >/tmp/cli.log 2>&1
verdict $? "avm-ac2 entry point runs"
# settlement-voi.json lives in examples/, NOT in tests/captures/ -- pointing this
# at $EXAMPLES made the stage fail for a path mistake, which reads like a broken
# CLI. The captures directory holds only the two proofpacks.
"$VENV"/bin/avm-ac2 payload "$AC2_SRC/examples/settlement-voi.json" >/tmp/payload.log 2>&1
[ -s /tmp/payload.log ] && grep -q "settlement-consent" /tmp/payload.log
verdict $? "avm-ac2 payload emits the canonical consent bytes"

echo
if [ "$FAILED" -ne 0 ]; then
    echo "CLEAN-ROOM FAILED"
    exit 1
fi
echo "CLEAN-ROOM GREEN"
