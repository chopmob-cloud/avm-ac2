"""avm-ac2 -- AC2 consent, bound to an avm-mesh settlement.

The seam in one sentence: **avm-mesh proves what settled, AC2 proves who
approved, and this package makes the second checkable against the first.**

Neither protocol is changed. ``avm-mesh`` gains no new wire format, and AC2 gains
no new message type: the consent travels inside the sealed receipt's existing
``content`` dict, which is hashed before the consensus attestation is inserted,
so the block is covered by ``content_hash`` and cannot be edited, swapped or
stripped without breaking LEVEL 1.

Read :mod:`avm_ac2.consent` for what each level proves and -- more importantly --
what it deliberately does not.
"""
from .consent import (
    AC2_CONSENT_KEY,
    AC2_CONSENT_VERSION,
    LEVELS,
    LEVEL_CONSENSUS,
    LEVEL_CONSENT,
    LEVEL_NONE,
    LEVEL_SENDER,
    ConsentAttestation,
    build_consent,
    canonical_bytes,
    consent_digest,
    consent_level,
    consent_payload,
    sender_from_bundle,
    verify_consent,
)

# Transaction-bound consent: the fallback that needs no arbitrary-payload
# approval from the wallet. Same guarantees where it applies, different preimage.
from .txn_consent import (
    TXN_CONSENT_KEY,
    TXN_CONSENT_VERSION,
    build_txn_consent,
    preimage_digest,
    signing_preimage,
    verify_txn_consent,
)

__all__ = [
    "AC2_CONSENT_KEY",
    "AC2_CONSENT_VERSION",
    "LEVELS",
    "LEVEL_NONE",
    "LEVEL_CONSENT",
    "LEVEL_SENDER",
    "LEVEL_CONSENSUS",
    "ConsentAttestation",
    "build_consent",
    "canonical_bytes",
    "consent_digest",
    "consent_level",
    "consent_payload",
    "sender_from_bundle",
    "verify_consent",
    "TXN_CONSENT_KEY",
    "TXN_CONSENT_VERSION",
    "build_txn_consent",
    "preimage_digest",
    "signing_preimage",
    "verify_txn_consent",
]
__version__ = "0.1.0"
