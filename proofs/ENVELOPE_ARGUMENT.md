# Envelope confidentiality: a game-based argument (v1 core)

> Computational-layer companion to the symbolic Tamarin model. The symbolic model
> (`../model/v1.spthy`) reasons about the protocol and its access-control state machine in the
> Dolev-Yao abstraction, treating encryption as a perfect black box. This document does the
> complementary thing: it argues, in the computational model, that the **envelope construction
> itself** (post key as DEK, epoch key as KEK) achieves content confidentiality assuming only
> standard security of its primitives. Together they cover both "is the protocol logic right"
> and "is the cryptographic core sound."
>
> **Status:** proof sketch with explicit game hops, scoped to the closed-family case (claim G1
> with no member onboarding). The handoff hole is out of scope here by design; it is the
> symbolic layer's result. Tightening the concrete bounds is future work.

---

## 1. What is being proved

Recall the envelope (spec §5, §6.1): bulk content `m` is sealed under a fresh per-post key
`postKey` with AES-256-GCM; `postKey` is then wrapped under the family epoch key `epochKey`
with AES-KW; both ciphertexts are published. This is a textbook **KEM-DEM / hybrid** shape with
the KEM replaced by a symmetric key-wrap under a shared group key.

We show: an adversary that sees any number of posts wrapped under an epoch key it does not hold,
and never compromises a holder of that epoch key, cannot distinguish the encrypted content from
encryption of equal-length random data. This is the computational statement behind **G1** (and,
against a passive server, **G6**).

## 2. Primitives and assumptions

- **DEM:** AES-256-GCM, modelled as an `AEAD` scheme `(Enc, Dec)`. Assumption: **IND-CPA** for
  the headline result; **IND-CCA / authenticated-encryption (AE)** when we also want integrity
  (tamper-evidence of media). GCM with unique random 96-bit IVs per key meets AE under the
  standard PRF/CTR assumptions; we take AE as given.
- **Key wrap (KEM-analogue):** AES-KW, modelled as a deterministic AE scheme `(Wrap, Unwrap)`
  for key-length messages. Assumption: AES-KW is a secure **deterministic AE** / wrap (the RFC
  3394 KW security notion: indistinguishability of wrapped keys + unforgeability). We use the
  indistinguishability direction.
- **Keys:** `epochKey` and each `postKey` are independent uniform 256-bit strings (`gen()`),
  faithful to the model. Crucially, each `postKey` is **used once** (fresh per post), so the DEM
  is only ever asked to encrypt under a key the adversary never sees, exactly once.

IV discipline matters and is assumed: GCM is catastrophically broken under IV reuse with the
same key. Because `postKey` is per-post and each variant gets a fresh random IV (spec §4.3, §6.1),
the "(key, IV) never repeats" precondition holds. This is recorded as a proof obligation on the
implementation (`../impl`), not merely an assumption.

## 3. Security game

`G1-Conf` (closed family, single epoch; the multi-post, multi-epoch case follows by a standard
hybrid over posts and a separate argument per epoch key):

1. Challenger samples `epochKey <- gen()`. The adversary never receives it and never corrupts a
   holder (modelled: no `RevealHolds`/`RevealLtk` for this epoch, matching the lemma hypotheses).
2. Adversary submits post requests; for each it may submit two equal-length plaintexts
   `(m0, m1)`. Challenger fixes a secret bit `b` and, per request:
   - `postKey <- gen()`
   - `c_dem <- Enc(postKey, m_b)` with a fresh IV
   - `c_wrap <- Wrap(epochKey, postKey)`
   - returns `(c_dem, c_wrap)`.
3. Adversary outputs `b'`. Advantage `Adv = |Pr[b'=b] - 1/2|`.

Claim: `Adv` is negligible.

## 4. Game hops

Let `q` be the number of post queries.

- **Game 0.** The real game `G1-Conf` above.

- **Game 1 (replace wraps).** Replace every `c_wrap = Wrap(epochKey, postKey_i)` with
  `Wrap(epochKey, r_i)` for an independent random `r_i` of key length. Because `epochKey` is
  unknown to the adversary and used only inside `Wrap`, any distinguishing between Game 0 and
  Game 1 yields a distinguisher against AES-KW indistinguishability under an unknown key.
  `|Pr[win_1] - Pr[win_0]| <= Adv^{KW}_{indist}(B_1)`, with `B_1` making `q` wrap queries.

  *Effect:* after this hop the wrapped ciphertexts are independent of the real `postKey_i`. The
  only place `postKey_i` now appears is inside the DEM ciphertext.

- **Game 2 (replace DEM, hybrid over the q posts).** Replace each `c_dem = Enc(postKey_i, m_b)`
  with `Enc(postKey_i, 0^{|m_b|})`. Each `postKey_i` is fresh, secret, and used for exactly one
  encryption, so each replacement is a single IND-CPA challenge. By a standard hybrid over the
  `q` posts, `|Pr[win_2] - Pr[win_1]| <= q * Adv^{AEAD}_{IND-CPA}(B_2)`.

  *Effect:* in Game 2 the challenger's output is independent of `b` (both `c_dem` and `c_wrap`
  are now independent of `m_b`). Hence `Pr[win_2] = 1/2`.

- **Conclusion.**
  `Adv <= Adv^{KW}_{indist}(B_1) + q * Adv^{AEAD}_{IND-CPA}(B_2)`,
  negligible under the stated assumptions. ∎ (sketch)

For integrity (an adversary must not be able to forge a media blob that decrypts to attacker-
chosen content under an honest member's view), the same decomposition with the **AE/INT-CTXT**
notions of GCM and the **unforgeability** of AES-KW gives the corresponding statement; omitted
here for brevity.

## 5. What this does and does not establish

**Establishes.** The v1 envelope core is confidential under standard assumptions, with a clean
linear-in-`q` bound, provided the epoch key stays uncompromised and IVs never repeat per key.
This is the computational backbone of G1/G6 for the closed-family case.

**Does not establish, by design.**
- **The handoff.** Nothing here authenticates how a newcomer obtains `epochKey`. The symbolic
  model shows v1's handoff fails to keep `epochKey` secret against an active server. That breaks
  the precondition of this theorem (epoch key uncompromised) the moment a member is onboarded.
  The two layers compose to the honest overall verdict: *the construction is sound; the key
  distribution is not.*
- **Forward secrecy / revocation.** Out of scope here; G3/G4 are epoch-state-machine properties
  handled symbolically.
- **Metadata.** Confidentiality is of `m`, not of the declared leakage in spec §10.

## 6. Proof obligations exported to the implementation

1. `postKey` is sampled fresh per post from a CSPRNG; never reused.
2. Each AES-GCM encryption uses a fresh random 96-bit IV; `(postKey, IV)` never repeats.
3. AES-KW is used for key wrapping (not AES-GCM with a static IV); wrap inputs are exactly
   key-length.
4. Epoch keys are 256-bit CSPRNG output, independent across epochs.

These become known-answer / property tests in `../impl`, so the assumptions the proof rests on
are checked against runnable code.
