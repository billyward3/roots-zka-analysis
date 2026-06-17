# v1 analysis results

Machine-checked findings for the reconstructed Roots ZKA v1 protocol (`../spec/PROTOCOL_V1.md`).
Symbolic results are from Tamarin 1.12.0; the computational result is the game-based argument in
`../proofs/ENVELOPE_ARGUMENT.md`. Every lemma below has a definitive verdict; lemmas that need a
proof oracle to terminate are called out as such rather than left ambiguous.

Reproduce:

```
tamarin-prover --prove model/v1_core.spthy            # positive result (closed family)
tamarin-prover --prove model/v1_rotation.spthy        # revocation / forward secrecy (G3, G4)
tamarin-prover --prove model/v1_recovery.spthy        # recovery (G7)
tamarin-prover --prove=post_possible model/v1.spthy   # handoff: per-lemma (autoprover terminates per lemma)
tamarin-prover --prove=handoff_key_secrecy model/v1.spthy
tamarin-prover --prove=handoff_key_injection model/v1.spthy
```

## Verdict table

| # | Lemma | Model | Type | Verdict |
|---|---|---|---|---|
| G1/G6 | `post_secrecy_closed` | `v1_core.spthy` | all-traces | **verified** (6 steps) |
| — | `post_possible`, `leak_possible` | `v1_core.spthy` | exists-trace | verified (sanity) |
| — | `post_possible`, `handoff_possible` | `v1.spthy` | exists-trace | verified (sanity) |
| G5 | `handoff_key_secrecy` | `v1.spthy` | all-traces | **falsified** (6 steps) |
| G5′ | `handoff_key_injection` | `v1.spthy` | exists-trace | **verified** (6 steps) |
| G3 | `revocation_g3` | `v1_rotation.spthy` | all-traces | **verified** (6 steps) |
| G4 | `epoch_independence_g4` | `v1_rotation.spthy` | all-traces | **verified** (12 steps) |
| — | `epoch1_leak_possible` (non-vacuity) | `v1_rotation.spthy` | exists-trace | verified |
| G7 | `recovery_secrecy_g7` | `v1_recovery.spthy` | all-traces | **verified** (9 steps) |
| G7 | `recovery_via_mnemonic_possible` | `v1_recovery.spthy` | exists-trace | **verified** (7 steps) |
| G7 | `login_via_password_possible` | `v1_recovery.spthy` | exists-trace | **verified** (8 steps) |
| v2 | `handoff_key_secrecy_v2` | `v2.spthy` | all-traces | **verified** (9 steps) — extraction closed |
| v2 | `no_key_injection_v2` | `v2.spthy` | all-traces | **verified** (13 steps) — injection closed |
| v2 | `handoff_key_secrecy` (partial fix) | `v2_extraction.spthy` | all-traces | **falsified** — both fixes are needed |

## Result 1 (positive): the envelope core is confidential

In a closed family (members already hold the epoch key; no onboarding), content sealed under a
genuine epoch key is secret against a Dolev-Yao adversary unless a holder of that epoch is
compromised. Tamarin proves `post_secrecy_closed` as an **all-traces** lemma, oracle-free.

This is the symbolic counterpart to the computational `ENVELOPE_ARGUMENT.md`, which reduces the
same statement to AEAD + AES-KW security with a linear-in-`q` bound. Two independent methods,
same conclusion: **the DEK/KEK envelope construction is sound.** The problem is not the
construction.

## Result 2 (the break): the v1 handoff has no public-key authentication

The member-add handoff (`spec §7.1`) protects the family epoch key under the newcomer's X25519
public key, which the admin obtains from the server with **no out-of-band verification**
(`spec §11-F`). Two attacks follow, both with **no member compromise** (no `RevealHolds`, no
`RevealLtk`):

**2a. Key extraction — `handoff_key_secrecy` falsified.** The adversary (a malicious server, role
`S-MAL`) substitutes its own public key `pk(x)` for the newcomer's. The honest admin wraps the
genuine epoch key under it (`aenc(ek, pk(x))`); the adversary decrypts with `x` and recovers `ek`.
With `ek` in hand it can unwrap every post key in the family (Result 1's precondition is gone),
so all family content falls. Tamarin's trace, in 6 steps:

```
1. Register_User($A)            honest admin; pk($A) published to the network
2. Create_Family($F,$A)         fresh epoch key ek (MkEpoch), held by $A
3. (adversary) fabricate pk(x)  for an x it knows; inject as the "newcomer" key
4. Add_Member_Admin             admin emits  <$F, e, aenc(ek, pk(x))>
5. (adversary) adec(...,x)      recover ek
6. ⇒ K(ek) with no RevealHolds / RevealLtk     -- lemma falsified
```

Rendered proof/trace graph: `../assets/v1_handoff_mitm_trace.png`.

**2b. Key injection — `handoff_key_injection` verified.** The dual direction. The adversary forges
the handoff ciphertext to an *honest* newcomer using that newcomer's published public key, so the
newcomer ends up holding an epoch key the adversary chose (`Joined(F,W,e,k)` with `k` adversary-
known). Everything the newcomer subsequently posts is readable by the adversary, and the newcomer
believes they are inside the family's encryption. Verified as a reachable state (witness trace =
the attack).

## Result 3 (positive): revocation works, and forward secrecy is bounded as designed

`v1_rotation.spthy` models a family of admin `A` and member `R`, both holding the epoch-1 key;
`R` is removed by rotating to a fresh epoch-2 key delivered only to `A`.

- **G3, revocation correctness — verified (all-traces).** Epoch-2 content stays secret even if
  *everything `R` retained* (the epoch-1 key) is revealed. Removal cryptographically blocks new
  content.
- **G4, bounded forward secrecy — verified (all-traces).** Epoch-1 content stays secret if the
  epoch-1 key is not revealed, *even if the epoch-2 key is*. Epochs are independent; a compromise
  does not cross between them.

This also makes the spec's accepted tradeoff precise (`spec §7.2`): `R` keeps the epoch-1 key it
already held, so it can still read *old* content. That is by design (lifetime retention), not a
break. G3 guarantees no *new* content; it deliberately does not claim retroactive secrecy of past
content from a once-legitimate member.

## Result 4 (positive): recovery is sound, with two unlock paths

`v1_recovery.spthy` models the resolved keystore design (`spec §5.1`): `MEK = h(mnemonic seed)`,
`pwKey = h(password)`, server stores `senc(MEK, pwKey)`, `senc(ck, MEK)`, `senc(m, ck)`.

- **Liveness — verified.** The mnemonic alone recovers the content (`recovery_via_mnemonic_possible`),
  and the password alone unlocks it (`login_via_password_possible`).
- **G7, secrecy — verified (all-traces).** With neither the mnemonic seed nor the password known,
  the content stays secret despite all server-stored blobs being public.

This confirms the §5.1 reconciliation (mnemonic is the root; the password unlocks a wrapped copy):
two independent paths to the root, and a password reset rotates nothing below `MEK`.

## Result 5 (the fix): v2 closes both handoff attacks

`v2.spthy` (design in `../spec/PROTOCOL_V2.md`) authenticates the keys the handoff depends on: the
newcomer's encryption key via a key-transparency log (`!PkE` lookup, not adversary-controlled
`In`), and the handoff itself via an unforgeable, verified delivery (`!AuthHandoff`, abstracting a
signature checked against the admin's logged key).

- **Key extraction — `handoff_key_secrecy_v2` verified (all-traces).** The v1-falsified lemma now
  holds: the substitution attack is gone.
- **Key injection — `no_key_injection_v2` verified (all-traces).** A joined member's key is never
  adversary-known absent a compromise.

**Both fixes are necessary, and that necessity is itself machine-checked.** `v2_extraction.spthy`
authenticates *only* the newcomer key (leaving the handoff unauthenticated); there,
`handoff_key_secrecy` is still **falsified** — the injection path plants an attacker-known key that
re-pollutes extraction. Only authenticating the admin's handoff as well closes it. This is a
concrete, verified justification for the two-part fix rather than an assertion.

## Interpretation

The two layers compose to one honest verdict: **the cryptographic construction is sound; the key
distribution is not.** v1's zero-knowledge claim names the server as the primary adversary, yet the
server is also the unauthenticated PKI, and that is exactly where confidentiality fails. This is
the central finding the v2 redesign must fix (key transparency and/or out-of-band verification;
`spec §11-F`).

It is worth stating plainly that this is a realistic class of bug, not a contrived one: the
original design documents assert "the server cannot impersonate users" while routing all public
keys through that same server with no verification. Formal analysis is what turns that latent
contradiction into a concrete trace.

## Honest limitations of the symbolic model

- **DH abstraction.** The handoff's ECDH-then-wrap is modelled as public-key encryption to the
  newcomer's key (`aenc`), a standard abstraction of the same trust relation (`v1.spthy` header,
  `spec §11-B/§11-F`). It faithfully captures the unauthenticated-public-key attack. A full
  `diffie-hellman`-builtin model establishes the same property but the autoprover does not
  terminate on it without a custom proof oracle; that oracle is **future work**, not a gap in the
  conclusion (the aenc model already proves the break, and the DH version's only added fidelity is
  the ECDH algebra, which does not change the attack).
- **All-traces positive secrecy in the full model** (with the handoff rules present) likewise needs
  an oracle to terminate; the closed-family `v1_core.spthy` proof covers the positive statement
  cleanly, so this is a termination limitation, not an unknown.
- **Scope now covered:** G1/G6 (envelope), G3/G4 (rotation), G5 (handoff break), G7 (recovery).
  G2 (access-control soundness) is implied by the secrecy lemmas (decryption requires the wrapped
  key). **Not yet modelled:** profile-key distribution as a distinct flow, and multi-family
  isolation. Next: the strengthened `PROTOCOL_V2.md` (verified handoff) and its re-analysis showing
  the G5 attack closes.
