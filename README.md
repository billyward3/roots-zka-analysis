# Roots ZKA: A Formal Security Analysis

A reconstruction and formal-security treatment of the zero-knowledge architecture (ZKA)
originally designed for **Roots**, a lifetime family photo-sharing app. The encryption
layer was fully designed and partially built, then deferred for market reasons before the
cryptographic primitives were ever implemented for real. This repository takes that design
seriously: it reconstructs the protocol precisely, models it, states its security goals as
formal claims, and either proves them or exhibits attacks. Where the original (**v1**) fails
a claim, a strengthened (**v2**) design is proposed and re-analyzed.

This is a *reconstruct-then-strengthen* exercise. The goal is not to ship the original
design but to understand exactly what it guaranteed, what it did not, and what a version
that survives formal analysis looks like.

## Why this system is interesting

Most end-to-end-encrypted systems are messaging systems, and messaging crypto is built
around **forward secrecy**: a new participant must not be able to read old messages, and
old keys are deleted as soon as possible. Roots is the inverse. Its product promise is
**lifetime retention**, so a family member who joins in 2030 is *supposed* to inherit the
entire history back to 2024. The protocol therefore contains a mechanism (historical key
distribution) whose entire job is to undo what forward secrecy would otherwise enforce.
Reasoning precisely about a system that deliberately inverts the central guarantee of the
protocols it borrows from is the intellectual core of this work.

## What the analysis targets

Security goals stated as formal claims (full definitions in [`spec/PROTOCOL_V1.md`](spec/PROTOCOL_V1.md)):

- **Content confidentiality** against the server, the database, and the network.
- **Access-control soundness**: only parties holding a key bundle for a context can decrypt.
- **Revocation correctness**: a removed member cannot decrypt content from later epochs.
- **Bounded forward secrecy**: precisely what past content is and is not protected.
- **Handoff authentication**: a new member receives the genuine context keys, not an
  attacker's substitute.
- **Server zero-knowledge**: the server learns nothing about plaintext beyond declared leakage.

## Method

A layered approach, because no single tool covers all of it honestly:

| Layer | Tool | What it establishes |
|---|---|---|
| Protocol + access-control state machine | **Tamarin** (symbolic, Dolev-Yao) | secrecy, authentication, and revocation lemmas over evolving epoch/membership state |
| Envelope construction (DEK/KEK, AES-KW + AES-GCM) | game-based reduction (hand, optionally CryptoVerif) | content confidentiality reduces to standard AEAD / key-wrap security |
| Reference implementation of the primitives | tested Dart/TS code | the proofs correspond to runnable, known-answer-tested code |

## Layout

```
spec/      reconstructed v1 protocol spec, and (later) the strengthened v2 spec
model/     Tamarin models (v1 and v2)
proofs/    game-based argument for the envelope core
impl/      tested reference implementation of the cryptographic primitives
analysis/  threat model, results, attacks found, v2 rationale (the writeup)
assets/    diagrams / animation of the key hierarchy and member-add / rotation flows
```

## Status

v1 reconstruction done and partially machine-checked. Current results (`analysis/RESULTS.md`):

- **Envelope core is confidential** — Tamarin all-traces proof (`model/v1_core.spthy`), matched
  by the game-based reduction (`proofs/ENVELOPE_ARGUMENT.md`).
- **The v1 key handoff breaks** — `handoff_key_secrecy` is **falsified** (`model/v1.spthy`): with
  no member compromise, a malicious server substitutes the newcomer's public key and recovers the
  family epoch key. A dual key-injection attack is also confirmed.

Next: model revocation/rotation (G3/G4) and recovery (G7), then the strengthened `spec/PROTOCOL_V2.md`
(key transparency / verified handoff) and re-analysis.

Requires `tamarin-prover` (1.12+) to reproduce; see `analysis/RESULTS.md`.

## Provenance

Reconstructed from the original design documents (now archived). This repository contains
no application code and no secrets; it is a standalone analysis artifact.
