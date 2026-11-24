# avm-ac2

[![PyPI](https://img.shields.io/pypi/v/avm-ac2)](https://pypi.org/project/avm-ac2/) [![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

**Proof of who authorised a settlement, bound to proof that it settled** — on
Algorand and Voi, verifiable offline.

An `avm-mesh` receipt proves *what settled*: a transaction was final, and what it
did, anchored in the chain's own consensus. It says nothing about *who authorised
it*. [AC2](https://github.com/algorandfoundation/ac2) (the Algorand Foundation's
Agentic Communication and Control protocol) is the other half — a consent and
signing-delegation channel where an agent asks a controller's wallet to sign a
payload and gets a signature back, never the key.

`avm-ac2` joins them. Neither protocol is modified: the consent travels inside the
sealed receipt's existing `content` dict, which `avm_mesh.sealed.seal` hashes
*before* inserting the consensus attestation, so the block is covered by
`content_hash` and cannot be edited, swapped or stripped without breaking LEVEL 1.

## What it proves — and what it refuses to claim

An AC2 `SigningResponse` body carries exactly `signature`, `public_key`,
`address` and `key_type`. There is **no WebAuthn material in it** — no
`authenticatorData`, no `clientDataJSON`, no `credentialId`, no attestation
object. The Draft spec's Pattern 2 diagram mentions constraints "expiry, scope",
but no normative field carries either.

**So a third party holding only an AC2 response cannot tell a hardware passkey
from a software key.** The spec's design goal is that the *wallet* requires user
verification; that is a claim about the wallet's behaviour, and the message does
not let a verifier re-check it.

This package therefore never says "hardware-bound" and never says "a human
approved". It reports one of four levels, and returns the reason alongside it:

| Level | Established | **Not** established |
|---|---|---|
| `none` | no consent block present | — |
| `consent_present` | the holder of `public_key` signed **this** settlement's canonical payload | that a human, or a passkey, was involved |
| `sender_bound` | that key **is** the authenticated transaction sender | still not a passkey — only that the payer signed |
| `consensus_bound` | additionally the settlement reached `stake_attested` | that goods shipped |

`sender_bound` is the property worth having: it collapses "someone approved this"
and "this was paid" into one key, so the approval and the payment cannot be
substituted for each other, and the payer cannot be misrepresented.

## Why the payer is the signer, not the agent

AC2's whole design is that the agent cannot sign. In an x402 flow the agent holds
a *delegated* signature and submits it; the account that funds the transaction is
the controller's. AC2's `address` field — the Algorand account bound to the
passkey by the Liquid Extension — is therefore the natural payer, and
`address == sender` is the binding to check. A wallet that signs from a different
account than it advertised fails, which is intended: the alternative is trusting
the agent's word about who paid whom.

## Install

```bash
pip install avm-ac2
```

`avm-ac2` 0.1.0 is on PyPI. Installing from the repository still works and tracks
`main` rather than the release:

```bash
pip install "git+https://github.com/chopmob-cloud/avm-ac2@main"
```

`avm-mesh` supplies the sealed-receipt format and its canonicaliser, so this
package extends it rather than duplicating either. `cryptography` is a direct
dependency (not an extra): every caller here verifies an Ed25519 signature, so
there is no dependency-light path to protect.

## Use

```python
import base64
from avm_ac2 import build_consent, consent_level, consent_payload, sender_from_bundle
from avm_mesh import sealed

settlement = {"chain": report.genesis_id, "txid": report.txid,
              "round": report.round, "amount": "0", "asset": 586896}

# 1. Ask the controller to sign consent_payload(settlement) over AC2, then build
#    the block from the SigningResponse. The agent never holds the key.
consent = build_consent(
    did=resp.from_did, sig_hint="raw-ed25519",
    public_key_b64=resp.body.public_key, signature_b64=resp.body.signature,
    settlement=settlement,
)

# 2. Seal it: the consent lands inside the bytes content_hash covers.
envelope = sealed.seal(
    {"version": 1, "settlement": settlement, "ac2_consent": consent},
    bundle, evidence_uri, trusted_voters=anchor,
)

# 3. Anyone verifies, with the sender re-derived from the authenticated STIB.
out = consent_level(envelope, report, bundle=bundle)
print(out["level"], out["reason"])
```

### Command line

```bash
avm-ac2 payload settlement.json                    # exact bytes to be signed
avm-ac2 verify  receipt.json --evidence ./bundles --genesis "$GENESIS" \
                --voters-commitment "$VC" --ln-proven-weight N
avm-ac2 level   receipt.json --min-level sender_bound    # exits 2 if below
```

### Validation

#### Clean-room validation (this package, standalone)

Run in a fresh `python:3.12-slim` container, installing with `--no-index` from a local wheel set so
nothing is fetched, against the **installed wheels** rather than the source tree:

| Stage | Result |
|---|---|
| Artefacts and captures staged | PASS |
| Offline install from wheels only (`avm-ac2` → `avm-mesh` → `avm-proofpack` → `avm-effectproof`) | PASS |
| Installed version matches `pyproject.toml` (`0.1.0`) | PASS |
| Both packages import from `site-packages`, not `/work/src` | PASS |
| Suite | **44 tests, 0 skipped, 0 failed** |
| Shipped example drives both chains on the installed wheel | **PASS** |
| `avm-ac2` entry point runs; `payload` emits canonical bytes | PASS |
| **CLEAN-ROOM GREEN** | 9 PASS, 0 FAIL across 5 stages |

#### Mutation check (inside that same container)

Removing the sender comparison from the *installed* `consent.py` in `site-packages` turned the suite red:

```
FAILED test_a_consent_from_a_foreign_key_is_refused_on_both_chains[algorand]
FAILED test_a_consent_from_a_foreign_key_is_refused_on_both_chains[voi]
2 failed, 14 passed
```

Restoring the file returned it to `20 passed`. The guard is load-bearing, not merely present.

#### Local, on both chains

`tests/test_consent.py` — **20 passed** on Python 3.12, driving the shipped
`avm_mesh.sealed.seal` and the real captures:

| Chain | Capture | Genesis pin | Tier reached | Sender read from STIB |
|---|---|---|---|---|
| Algorand mainnet | `avm-mesh/examples/proofpack-66457600.json` | `wGHE2Pwdv…` | `stake_attested` | `Q34SYPNGP7CW77LIAYNNUZV7Q6GRSUJVKMIAPOJFG3TZULNJGPRA` |
| Voi mainnet | `avm-mesh/examples/voi-proofpack-24213754.json.gz` | `r20fSQI8g…` | `stake_attested` | `3S6DAF3YX3RDIS4FV2QIPIKGHAPZ52OPOTR6NR25O7RYHTYMBSDQ` |

Both captures ship in [`tests/captures/`](tests/captures) and are pinned by SHA-256, so this suite runs
from a fresh clone with no sibling checkout. The Voi digest is the same one `avm-mesh`'s own
`test_voi_chain.py` pins, so the two suites agree on the artefact. They are marked `-text` in
`.gitattributes`, because a checkout that normalises the bytes breaks a hash assertion on one platform
only. Per chain the tests cover: the sender read from
authenticated bytes, a successful binding, refusal of a foreign key, refusal of a replayed consent,
refusal of an edited consent, absence reported as `none`, an unknown version refused by name, an unknown
chain refused rather than guessed, and a digest that changes when any settlement field changes.

#### Also validated as part of `avm-mesh`

The same module also ships as `avm_mesh.ac2` inside
[`avm-mesh`](https://github.com/chopmob-cloud/avm-mesh), whose own clean-room gate is green including an
AC2 stage: **567 tests, 0 skipped, 0 failed**, with the consent binding passing on both chains against the
installed wheel. This package is the same code with a narrower dependency and a CLI.

### Interop with the real AC2 stack

A same-language round trip proves only that my encoder agrees with my decoder, so
the seam is tested against bytes produced by the **real** AC2 conventions:

`tests/interop/interop_emit.mjs` uses Node's `base64url` and a JCS encoder of the
kind the reference implementation ships. `tests/test_interop_ac2.py` then requires
the Python side to accept that output.

This found a live defect. AC2's stack emits **base64url**; `base64.b64decode(...,
validate=True)` rejects `-` and `_`, so a genuine AC2 signature was refused as "not
valid base64". Every prior test encoded with Python's standard alphabet and decoded
with the same alphabet, so none of them could see it. The decoder now accepts both
alphabets strictly — characters outside both are still refused — and reverting that
one line turns 2 tests red.

It also pins that the two implementations agree on the canonical payload **byte for
byte**, not merely in digest: an independent JCS implementation must produce exactly
the bytes this package signs.

| Interop check | Result |
|---|---|
| Real base64url signature verifies | PASS |
| Node and Python agree on canonical bytes and digest | PASS |
| Standard base64 still accepted | PASS |
| Tampered url-alphabet signature still refused | PASS |
| Characters outside both alphabets refused | PASS |

**What the SDK and service documentation establish:** `agent.request` is
documented as *verb-agnostic*, so a request is not restricted to transactions; the
SDK's signing path is payload-agnostic, single-use and thread-bound; and the request
schema carries `display_hint` for previewing payloads it does not recognise.
The AC2 service and SDK therefore **permit** an arbitrary canonical payload.

**What no test here can establish:** that the *shipped wallet application* will
approve a payload it does not recognise as a transaction or a message. That is a
product policy inside the mobile app, not something the protocol or the SDK
publishes. It requires a physical device and a real account.

So the accurate claim is: **the mechanism and the wire encoding are tested against
the real stack; the wallet's approval policy for a non-transaction payload is
unverified.** An integration against a live wallet may find that the app shows the
payload as opaque, or declines it — in which case the fallback is to carry the
consent over the transaction signature the wallet already produces
(`sig_hint: transaction-algorand`), which needs no new wallet behaviour.

## Two consent flavours

The package ships two ways to bind a consent, because they depend on different
things and one of them has no dependency on wallet policy.

### 1. Canonical-payload consent (`avm_ac2.consent`)

The controller signs the settlement as a canonical JSON envelope. Rich — the
consent covers the amount, asset and chain exactly as the receipt describes them —
but it asks the wallet to approve a payload that is not a transaction.

### 2. Transaction-bound consent (`avm_ac2.txn_consent`)

The consent is carried over the **transaction signature the wallet already
produces** when it approves a payment (`sig_hint: transaction-algorand`), so
nothing new is asked of the wallet. This is the fallback for the case where a
wallet declines to approve an opaque payload.

The preimage is `"TX" + canonically-encoded(restored Transaction)`, where the
genesis fields consensus strips on encode are restored on decode. That derivation
is **verified, not assumed**: `preimage_digest()` must reproduce the bundle's own
`transaction.txid`, and the tests assert it on both chains. An earlier version
re-encoded the STIB's `txn` map directly, omitting `gen`/`gh`, and produced a
confident 52-character base32 string that was simply the wrong transaction — the
txid equality is what caught it.

| | canonical-payload | transaction-bound |
|---|---|---|
| Wallet must approve an opaque payload | **yes** | no |
| Binds consent to amount/asset as described | yes | no — binds to the transaction |
| Reaches `sender_bound` | by key comparison | **by construction** |
| Needs `txn_consent.signing_preimage` | — | yes, verified against `txid` |

Neither proves a hardware passkey was used: that limit is shared and comes from the
AC2 wire format, not from the choice of flavour.

### Integrator warning: do not build the payload with a transaction constructor

`algokit-utils`' `bytesForSigning.transaction` drops the `gen` (genesis id string)
key while keeping `gh` (the genesis hash), because on the *constructor* path it
expects a node to fill that back in. A payload built that way is **not** the
transaction the chain committed to: on the real Voi capture, removing `gen` changes
the txid from `75LUFZZNQNOPS3SLQRHZZKZIECEEVGGP4N3ZZ2UU2UKFFJU5WG4A` to
`XGEHZIIAVMQ64YVG3GOWUO4YG3OAQMZE4O2NGZDXNCQOXDFYGTVQ`.

Use `avm_ac2.txn_consent.signing_preimage(bundle, chain)` to produce the payload.
It restores `gen` and is checked against the bundle's own `transaction.txid` on both
chains, so a wrong preimage fails loudly instead of producing a confident wrong
transaction. `tests/test_txn_consent.py` pins this, including an assertion that the
gen-less form does *not* reproduce the txid.

This does not affect the wallet: it signs the bytes it is handed, not bytes it
builds. It affects the agent, which is the side this package is for.

### What is *not* demonstrated

- **No signature has been produced by a real wallet.** Every consent in this
  repository is generated by a test or the demo. The chain evidence is real; the
  approval is synthetic, and the tests and demo output say so on every run.
- **One capture per chain, one endpoint.** This proves the mechanism, not witness
  independence.
- **AC2 is a Draft.** The wire fields here are from `ac2-sdk` 1.0.0 and the
  `ac2.md` Draft as published. If the SDK starts carrying WebAuthn material,
  `consent_present` could honestly become a stronger claim — that would be a new
  consent version, never a reinterpretation of version 1.

## Licence

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
