# Changelog

## 0.1.0 — 2026-11-17

First release. AC2 consent bound to an avm-mesh settlement: proof of *who authorised*
a transaction, on Algorand and Voi.

The consent block lives inside the sealed receipt's existing `content`, so it is covered
by the receipt's `content_hash` and cannot be edited, swapped or stripped without
breaking the seal. Three trust levels, and nothing more than the bytes support:

| Level | Established | Deliberately not claimed |
|---|---|---|
| `consent_present` | the holder of `public_key` signed **this** settlement's canonical payload | a human, or a hardware passkey |
| `sender_bound` | that key **is** the authenticated transaction sender (read from the STIB) | still not a passkey |
| `consensus_bound` | additionally the settlement reached `stake_attested` | that goods shipped |

An AC2 `SigningResponse` carries `signature`, `public_key`, `address`, `key_type` — no
`authenticatorData`, no `clientDataJSON`, no `credentialId` — so a third party cannot
distinguish a hardware passkey from a software key. The module never says it can.

- Console script `avm-ac2` with `payload`, `verify` and `level`.
- Dependency floor `avm-mesh>=0.13.5`: the first version whose `crossnode` does not
  report one provider under two hostnames as corroborated.
- Clean room on `python:3.12-slim`, offline install from a local wheel set: 44 tests,
  0 skipped, 0 failed; the shipped example drives consent binding on both chains.
