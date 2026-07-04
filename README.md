# Roots ZKA: a formal security analysis

Roots is a family photo-sharing app built around a permanent shared archive. Its encryption layer, a
zero-knowledge architecture (ZKA), was designed and partially built, then shelved for market reasons
before the primitives were implemented for real. This repository reconstructs that design and checks
it against formal security goals. Most of the goals hold. One does not: the member-onboarding handoff
falls to a key-substitution attack, which a revised handoff repairs. The repository does not ship the
encryption layer; it records what the design guaranteed and where it failed.

## Summary

The analysis found a key-substitution attack against the server, which the design named as its
primary adversary. The original documents state that the server cannot impersonate users, yet every
public key is submitted to and served by that same server with no out-of-band verification. Tamarin
turns that gap into a concrete trace: during member onboarding a malicious server substitutes its own
key, the admin wraps the family epoch key under it, and the server recovers the key and reads all
family content. No member is compromised in the attack.

The encryption construction underneath is sound, shown both by a Tamarin proof and a game-based
reduction. The failure is in key distribution. A revised handoff, named Heirloom, adds a
key-transparency log and authenticated delivery, and Tamarin verifies that it closes both the
extraction and injection variants. A version that authenticates only the newcomer's key still falls,
so both parts of the fix are necessary. Heirloom is the only mechanism this project names; the
surrounding envelope is a standard construction.

Every claim here is machine-checked: Tamarin for the protocol, a game-based reduction for the
encryption core, and a Rust reference implementation whose tests reproduce the attack and the fix.

![The v1 handoff attack, in which a malicious server substitutes a key and recovers the family epoch key, beside the v2 fix, in which a transparency log and signed handoff defeat the same adversary.](assets/handoff_v1_v2.png)

## Forward secrecy, inverted

Messaging protocols like Signal are designed for forward secrecy: someone who joins a conversation
should not be able to read messages sent before they arrived, and keys are discarded once they are no
longer needed. Roots has the opposite requirement. It gives family members a permanent archive, so a
member who joins in 2030 is expected to read photos shared in 2024. Its key distribution therefore
has to hand new members the keys to content that predates them. Much of this analysis concerns what
that requirement costs and whether the original design met it securely.

## Results

The full table, traces, and reproduction commands are in [`analysis/RESULTS.md`](analysis/RESULTS.md).

| Claim | Where | Verdict |
|---|---|---|
| Envelope confidentiality (content secret vs server, database, network) | `v1_core.spthy` + `proofs/ENVELOPE_ARGUMENT.md` | verified (two methods) |
| Revocation: a removed member cannot read later epochs | `v1_rotation.spthy` | verified |
| Bounded forward secrecy: epochs are independent | `v1_rotation.spthy` | verified |
| Recovery: mnemonic and password both unlock, secret otherwise | `v1_recovery.spthy` | verified |
| **v1 handoff key secrecy** | `v1.spthy` | **falsified (the attack)** |
| v1 handoff key injection (the dual attack) | `v1.spthy` | reachable (attack exists) |
| v2 handoff key secrecy | `v2.spthy` | verified (the fix) |
| v2 no key injection | `v2.spthy` | verified (the fix) |
| v2 partial fix (newcomer key only) | `v2_extraction.spthy` | falsified (both fixes needed) |

## Reproducing

The quickest check is the reference implementation, where the v1 attack and the v2 defense are
ordinary tests.

```
cd impl
cargo test          # 14 tests: standard KAT vectors, envelope obligations, v1 attack, v2 fix
```

The test `v1_malicious_server_recovers_epoch_key` asserts that the attack succeeds, meaning the
malicious server recovers the family key; the v2 tests show the same adversary failing.
[`impl/README.md`](impl/README.md) maps each test to the claim it checks. The code needs a recent
stable Rust (edition 2024 dependencies; tested on 1.96).

Re-checking the proofs needs `tamarin-prover` 1.12 or later:

```
tamarin-prover --prove model/v1_core.spthy                  # envelope confidentiality
tamarin-prover --prove model/v1_rotation.spthy              # revocation + forward secrecy
tamarin-prover --prove model/v1_recovery.spthy              # recovery
tamarin-prover --prove=handoff_key_secrecy model/v1.spthy   # the break (falsified)
tamarin-prover --prove model/v2.spthy                       # the fix (verified)
```

## Method

The analysis works in three layers.

| Layer | Tool | What it establishes |
|---|---|---|
| Protocol + membership state machine | Tamarin (symbolic, Dolev-Yao) | secrecy, authentication, and revocation over evolving epoch/membership state |
| Encryption core (DEK/KEK, AES-KW + AES-GCM) | game-based reduction, by hand | content confidentiality reduces to standard AEAD and key-wrap security |
| Reference implementation | Rust (`impl/`), 14 tests | primitives are the standard ones (known-answer vectors), the envelope obligations hold, and the attack and fix run as code |

## Repository layout

```
spec/      reconstructed v1 protocol spec + strengthened v2 spec
model/     Tamarin models (v1 broken, v2 fixed)
proofs/    game-based argument for the encryption core
impl/      Rust reference implementation and tests
analysis/  threat model, full results, attack traces, v2 rationale
assets/    diagrams of the key hierarchy and the handoff attack/fix
```

## Scope and limitations

**This is a security-analysis artifact, not audited cryptographic software.** The reconstructed v1 is
a broken design, and it is left broken. The v2 Heirloom design has not been independently audited, and
the reference code is written for clarity rather than deployment. Do not use any of it in production.

- The symbolic model assumes perfect cryptography (the Dolev-Yao model). It establishes that the
  protocol logic admits no key-substitution trace; computational security of the encryption core is
  covered separately by the game-based argument.
- The handoff's ECDH-then-wrap is modelled as public-key encryption to the newcomer's key. This is a
  standard abstraction of the same trust relation and captures the unauthenticated-key attack. A model
  using the full Diffie-Hellman equational theory establishes the same property but does not terminate
  under the automatic prover without a custom oracle, which is left as future work.
  [`analysis/RESULTS.md`](analysis/RESULTS.md) has the details.
- In the original system the primitives were mocked on the client, and only the backend orchestration
  and data model were built and tested. The original documents describe "forward secrecy" and an
  "MLS-style tree" that the implemented design, a flat per-member epoch-key wrapping, did not provide.
  This repository analyzes the design as reconstructed and marks where the reconstruction resolves an
  ambiguity ([`spec/PROTOCOL_V1.md`](spec/PROTOCOL_V1.md) §11).

Reconstructed from the original design documents, now archived. Contains no application code and no
secrets.
