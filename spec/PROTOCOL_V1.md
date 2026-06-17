# Roots ZKA v1 — Reconstructed Protocol Specification

> **Status:** reconstruction of the original design (v1). This is the faithful "as designed"
> protocol that the formal analysis targets. Strengthening lives in a separate `PROTOCOL_V2.md`
> once v1 analysis is complete.
>
> **Reconstruction discipline.** Statements drawn directly from the original design documents
> are unmarked. Statements that fill a gap the originals left underspecified are marked
> **[INFERRED]** and collected in §11 so the modeling never silently assumes more than the
> design stated. The point of a formal spec is to make every such choice explicit, because a
> proof is only as honest as its assumptions.

---

## 1. Purpose and scope

This document specifies, precisely enough to formalize, the zero-knowledge architecture (ZKA)
designed for Roots: a system in which a server stores and routes ciphertext it can never read,
while a changing group of family members retain shared read access to content across the full
history of the group.

In scope: the cryptographic protocol and its access-control state machine — key hierarchy,
content encryption, member addition (including historical access), member removal (key
rotation), profile-key distribution, and searchable encryption.

Out of scope for v1 reconstruction: transport security (assumed TLS), the application-level
authorization layer (assumed to behave as specified), UX, and storage tiering. These are
modeled only as far as the adversary model in §7 requires.

---

## 2. Notation and cryptographic primitives

| Notation | Meaning |
|---|---|
| `x ‖ y` | concatenation |
| `{m}_k` | authenticated symmetric encryption of `m` under key `k` (AEAD) |
| `wrap(k, K)` | deterministic-or-randomized key wrap of key `k` under KEK `K` |
| `unwrap(c, K)` | inverse of `wrap` |
| `DH(a, B)` | X25519 scalar mult of private `a` with public `B` |
| `H(·)`, `KDF(·)` | hash / key-derivation function |
| `MAC(m, k)` | keyed hash (blind-index tag) |
| `pk(s)` | public key for secret `s` |
| `gen()` | fresh random key / nonce of the appropriate length |

Primitives fixed by the design:

- **AEAD (bulk):** `AES-256-GCM`, random 96-bit IV per encryption, IV prepended to ciphertext.
  Used for post metadata, every media variant, folder names, and profile data.
- **Key wrap (KEK over DEK):** `AES-KW` (RFC 3394) for wrapping content/context keys.
  **[INFERRED]** AES-GCM is used in some doc snippets and AES-KW in others; v1 is specified as
  AES-KW for key wrapping and AES-GCM for data. §11-A.
- **Password KDF:** `Argon2id`, parameters `t=3, m=64 MiB, p=1`, 32-byte output. Produces a
  *password key* `pwKey` that unlocks the root key `MEK`, not the root key itself (§5.1).
- **Key exchange:** `X25519` ECDH; the shared secret is passed through `KDF` with a domain label
  before use as a wrapping key, never used raw. **[RESOLVED §11-B].**
- **Blind index / MAC:** `HMAC-SHA256` keyed by a per-context indexing key.
- **Recovery:** `BIP39` 24-word mnemonic; its seed is the canonical root from which `MEK` is
  derived. The password path merely unlocks a wrapped copy of the same `MEK`. **[RESOLVED §11-C]**,
  detailed in §5.1.

Random values (`gen()`) are assumed uniform and independent. All asymmetric and symmetric
keys are of the standard length for their primitive.

---

## 3. Parties and identifiers

- **User `U`** — a person with a device holding secret key material. Identified by `uid`.
- **Member** — a user in the context of a specific family, with a `role ∈ {admin, member}`
  and a `status ∈ {pending, claimed, approved_pending_keys, active, removed}`.
- **Admin** — a member with `role = admin`; the only party permitted to approve joins,
  distribute keys, and rotate epochs.
- **Family `F`** — a group; the unit of shared access and (in the product) billing.
- **Server `S`** — Firebase Cloud Functions + Firestore + Cloud Storage. Stores all state,
  routes all messages, enforces application-level authorization. **Never holds plaintext keys
  or content by design.**

The reconstruction models a single family unless stated; multi-family profile keys (§9) are
the one place cross-family structure matters.

---

## 4. State

### 4.1 Client (per user `U`), in memory or secure storage

```
MEK_U                              root key; recovered from mnemonic, or unwrapped with pwKey (§5.1)
pwKey                              Argon2id(password, salt_U); unlocks MEK_U, never a root itself
sk_U^dh, pk_U^dh                   X25519 long-term identity keypair (sk_U^dh wrapped under MEK_U) [§11-D]
{ epochKey[F][e] }                 family epoch keys U can currently unwrap
{ folderKey[φ], folderIndexKey[φ] }
PDK_U                              U's profile data key
indexKey[F]                        family indexing key (for blind indexes)  [INFERRED §11-E]
```

### 4.2 Server, per family `F` (`/families/{F}`)

```
members:   { uid: { role, status, joinedAt, pendingExpiresAt? } }
currentEpochId: e*
```

Epoch keys (`/families/{F}/epochKeys/{e}`):

```
keyBundles: { uid: wrap(epochKey[F][e], KEK_for_uid) }     # one wrapped copy per member
createdAt
```

Historical keys for an onboarding member (`/families/{F}/members/{uid}/historicalKeys/{e}`):

```
wrappedKeyBundle: wrap(epochKey[F][e], KEK_for_uid)
distributedBy, distributedAt
```

### 4.3 Server, per post (`/posts/{postId}`)

```
authorId, createdAt
origin:        { type, id }
accessControl: { families:[...], users:[...], folders:[...] }   # logical ACL
encryptedKeyBundles: {                                          # the envelope
  "family:F":  wrap(postKey, epochKey[F][e]),
  "user:V":    wrap(postKey, KEK_UV),
  "folder:φ":  wrap(postKey, folderKey[φ])
}
encryptedMetadata: {metadata}_postKey
media: [ { type, blurHash (plaintext), encryptedMetadata,
           variants: { thumbnail|compressed|full_resolution: { storagePath } } } ]
searchableIndexes: { "family:F": { tags:[MAC...], type:[MAC...], people:[...] }, ... }
```

Media blobs at `posts/{postId}/media/{idx}/{variant}.enc` are `IV ‖ {variantBytes}_postKey`.
`blurHash` is the single plaintext visual element (a low-resolution placeholder).

### 4.4 Server, per user (`/users/{uid}`)

```
displayName, email                 # plaintext (operational)
salt_U                             # Argon2id salt
wrappedMEK:         wrap(MEK_U, pwKey)        # password-unlock path; mnemonic is the recovery path
wrappedIdentityKey: wrap(sk_U^dh, MEK_U)      # identity secret, syncs across devices via MEK_U
pk_U^dh                            # published X25519 public key (UNVERIFIED in v1 — see G5, §11-F)
encryptedProfileData: {profile}_PDK
profileKeyBundles: { "family:F": { wrappedPDK: wrap(PDK_U, epochKey[F][e]), epochId } }
```

---

## 5. Key hierarchy

```
BIP39 mnemonic ──seed,KDF──▶ MEK_U (root)      password ──Argon2id──▶ pwKey ──unwraps──▶ MEK_U
   │
   ├─▶ wraps U's long-term secrets at rest (identity key sk_U^dh)          [§11-D]
   │
   ├─▶ Family Epoch Key  epochKey[F][e]        (symmetric, per family, per epoch)
   │       distribution: one wrapped copy per member in keyBundles
   │       wraps ▶ Post Keys, Profile Data Keys, Folder Keys
   │
   ├─▶ Profile Data Key  PDK_U                 (symmetric, one per user)
   │       wrapped once per family under that family's current epoch key
   │       encrypts ▶ encryptedProfileData
   │
   └─▶ Post Key  postKey                       (symmetric, random, one per post)
           wrapped once per access context (family / user / folder)
           encrypts ▶ post metadata + all media variants (shared key, per-variant IV)

Folder Key       folderKey[φ]                  encrypts folder name; wraps post keys for φ
Folder Index Key folderIndexKey[φ]             keys the blind index for folder φ
Family Index Key indexKey[F]                   keys the blind index for family F   [INFERRED §11-E]
```

**Design invariant (envelope model):** bulk data is encrypted exactly once under a fresh DEK;
access is granted by adding wrapped copies of that DEK, never by re-encrypting bulk data.
Re-encryption happens only on revocation (§7.2), and even then only of context metadata and
indexes, never of media.

### 5.1 Root key, password unlock, and recovery (resolved)

The originals stated both that "the MEK is derived from the password via Argon2id" and that
"the MEK can be regenerated from a BIP39 mnemonic." These cannot both hold literally: an Argon2id
output is not reproducible from an independent mnemonic. v1 reconciles them with the standard
keystore pattern, which is also the design that makes password changes cheap:

- `MEK_U` is the user's **root key**, and the BIP39 mnemonic seed is its canonical source:
  `MEK_U := KDF(BIP39seed(mnemonic), "roots/mek")`, fixed at signup.
- The password never produces the root. It produces a *password key*
  `pwKey := Argon2id(password, salt_U)`, used only to store a wrapped copy `wrap(MEK_U, pwKey)`
  on the server for convenient login.
- **Login:** fetch `wrap(MEK_U, pwKey)`, derive `pwKey`, unwrap `MEK_U`.
- **Recovery:** rederive `MEK_U` directly from the mnemonic, then re-wrap under a fresh `pwKey`.
- A password change re-wraps only `MEK_U`; nothing below it in the hierarchy is touched. This is
  the reason to separate the root key from the password key, and why v1 rejects the literal
  "MEK = Argon2id(password)" reading.

Consequence for the model: recovery (claim G7) is a statement about the mnemonic, and a password
reset rotates no key below `MEK_U`.

---

## 6. Content protocols

### 6.1 P-CREATE — post creation (envelope encryption)

Author `U` in family `F` at epoch `e`:

```
1.  postKey   := gen()
2.  ct_meta   := {metadata}_postKey
3.  for each variant v:  ct_v := IV_v ‖ {variantBytes_v}_postKey   (fresh IV_v)
4.  for each searchable field f:  idx_f := MAC(value_f, indexKey[F])
5.  bundle["family:F"] := wrap(postKey, epochKey[F][e])
        (and one wrap per additional context in accessControl)
6.  U → S (signed URLs): request upload locations for ct_v
7.  U → CloudStorage:    PUT ct_v
8.  U → S (createPost):  { accessControl, encryptedKeyBundles=bundle,
                           encryptedMetadata=ct_meta, media, searchableIndexes }
9.  S: validate structure + author's membership/permission; store opaquely.
```

The server validates only *shape* (base64 well-formedness, ECDH key structure, minimum wrapped
sizes) and *authorization* (is `U` an active member with `CREATE_POSTS`). It performs no
cryptographic operation on the content.

### 6.2 P-READ — decryption

Reader `V` with access to context `c` (e.g. `family:F` at epoch `e`):

```
1.  fetch post; select bundle[c]
2.  postKey := unwrap(bundle[c], contextKey_c)        # contextKey_c already on V's device
3.  metadata := decrypt(encryptedMetadata, postKey)
4.  for each needed variant v: fetch ct_v; variantBytes_v := decrypt(ct_v, postKey)
```

`V` can read iff `V` can unwrap at least one entry of `encryptedKeyBundles`. This is the
cryptographic access-control statement (claim G2, §8).

### 6.3 P-SEARCH — blind-index query

```
Query for term t in context c:  tag := MAC(t, indexKey_c);  S runs array-contains(tag).
```

The server matches opaque tags, never the term. Accepted leakage in §10.

---

## 7. Membership protocols

### 7.1 P-ADD — adding a member (the central flow)

Combines an admin-approved onboarding handshake with **historical key distribution**, the
mechanism that grants a newcomer access to content created before they joined.

```
Phase 1 — claim
  invitee W → S: claim(invitationId, pk_W^dh)         # publishes W's X25519 public key
  S: invitation.status := claimed; record inviteeId=W, pk_W^dh

Phase 2 — approve
  admin A → S: approve(invitationId)
  S: members[W] := { role: member, status: approved_pending_keys,
                     pendingExpiresAt: now + 7 days }

Phase 3 — key handoff + historical distribution (client-driven, server is a dumb writer)
  A: fetch pk_W^dh from S
  A: ss := KDF(DH(sk_A^dh, pk_W^dh))                  # ECDH shared secret  [INFERRED §11-B]
  A: for each epoch e in 1..e*:  hk[e] := wrap(epochKey[F][e], ss)
  A: (optionally) profileBundle := wrap(PDK exchange material, ss)
  A → S (postHistoricalKeys): { familyId:F, newMemberId:W, keyBundles: hk }

Phase 4 — activate (atomic)
  S: assert A has DISTRIBUTE_KEYS; assert members[W].status == approved_pending_keys
     assert not expired; assert keys not already distributed
  S: write hk[e] to historicalKeys subcollection for W
  S: members[W].status := active
```

Post-conditions: `W` can derive `ss`, unwrap every `hk[e]`, and thereby read all content of
`F` at every epoch up to `e*`. No bulk data is re-encrypted.

**Critical observation for analysis.** `A` obtains `pk_W^dh` *from the server*. Nothing in v1
authenticates that public key out of band (no safety numbers, no key-transparency log). This
is the focus of claim G5 (§8) and the predicted v1 attack.

### 7.2 P-REMOVE — removing a member (epoch rotation)

Removing `R` from `F` requires a full key rotation, because `R` still holds `epochKey[F][e*]`.

```
1.  admin A: epochKey[F][e*+1] := gen()                       # new epoch
2.  A: for each remaining member M:  keyBundles'[M] := wrap(epochKey[F][e*+1], KEK_M)
3.  A: re-encrypt context metadata (e.g. folder names) under the new key
4.  A: recompute every blind index in F under a fresh indexKey[F]   (most expensive step)
5.  A → S: atomic batch { new epochKeys/{e*+1}.keyBundles', re-encrypted metadata,
                          recomputed indexes };  S sets currentEpochId := e*+1
6.  S (separately, immediate): remove R from accessControl / members (logical revocation)
```

**Accepted v1 tradeoff (stated in the originals):** rotation runs as an async background task,
so there is a window in which logical revocation has happened but cryptographic rotation has
not. Also, `R` retains the ability to decrypt content from epochs ≤ `e*` that they already
held. v1 provides *revocation of future content*, not retroactive secrecy of past content.
This is exactly what claims G3 and G4 (§8) pin down.

### 7.3 P-PROFILE — profile data key distribution

```
On join (extends P-ADD phase 3):
  W: PDK_W := gen() (if new);  encryptedProfileData := {profile}_PDK_W
  W → A (via ss):  PDK_W wrapped under ss
  A: unwrap PDK_W; profileKeyBundles[W]["family:F"] := { wrap(PDK_W, epochKey[F][e*]), e* }

On read of W's profile by family member V:
  V: unwrap profileKeyBundles[W]["family:F"] with epochKey[F][e*]; decrypt encryptedProfileData

On rotation: re-wrap every member's PDK under the new epoch key (part of P-REMOVE step 2/5).
```

Multi-family isolation: `PDK_W` is wrapped *independently per family*. Compromise of one
family's epoch key never exposes `W`'s profile to another family. This is the design's main
divergence from single-identity (Signal) and single-mailbox (Proton) models.

---

## 8. Security goals (formal claims)

Each claim is phrased to become either a Tamarin lemma (symbolic) or a game-based statement
(computational). "The adversary" is the §9 adversary. `learns(X)` means the adversary can
compute `X`.

- **G1 — Content confidentiality.** For any post `P` with `encryptedKeyBundles` over context
  set `C`, if the adversary corrupts no party able to unwrap any `c ∈ C` (transitively, up the
  hierarchy), then it does not learn `P`'s metadata or any media variant. *Computational:
  reduces to AEAD + key-wrap security; Symbolic: secrecy lemma.*
- **G2 — Access-control soundness.** A party can decrypt `P` iff it can unwrap some entry of
  `encryptedKeyBundles[P]`. No `accessControl` list membership grants plaintext without the
  corresponding key. *Symbolic.*
- **G3 — Revocation correctness (future content).** After `R` is removed and epoch advances to
  `e+1`, `R` cannot decrypt any post created at epoch ≥ `e+1`, even given all of `R`'s prior
  state. *Symbolic, over the rotation state machine.*
- **G4 — Bounded forward secrecy (explicit non-claim).** Compromise of `epochKey[F][e]` reveals
  exactly the content of epoch `e` (and, via historical distribution, content of any epoch the
  compromised member legitimately held). It does **not** reveal content of epochs the member
  never held. v1 makes no per-post or per-time forward-secrecy claim beyond epoch granularity.
  *Stated as a precise boundary, not a guarantee to maximize.*
- **G5 — Handoff authentication.** In P-ADD, the key material `W` ends up holding is the genuine
  `epochKey[F][·]` produced by an honest admin, not a value chosen or relayed by a corrupted
  server. *Symbolic. This is the claim v1 is expected to FAIL (server-as-PKI MITM).*
- **G6 — Server zero-knowledge.** An honest-but-curious server that follows the protocol learns
  nothing about plaintext content beyond the declared leakage of §10. *Symbolic secrecy of all
  content terms against a server-role adversary; informs the computational statement.*
- **G7 — Recovery soundness.** A user holding only the BIP39 mnemonic can regenerate `MEK_U`
  and recover access to all contexts whose keys are wrapped (transitively) under `MEK_U`, and an
  adversary without the mnemonic gains nothing from its existence. *Computational/symbolic.*

---

## 9. Adversary model (Dolev-Yao, with corruptions)

The network is fully adversary-controlled (inject, drop, reorder, read). On top of standard
Dolev-Yao, the model includes targeted corruptions, each exposing exactly that party's secrets:

- **Honest-but-curious server (`S-HBC`)** — follows the protocol but reads all stored state and
  all messages. Primary adversary; the system's whole premise is to defeat it. Targets G1, G6.
- **Malicious server (`S-MAL`)** — additionally deviates: may substitute stored values, reorder
  writes, and (crucially) serve chosen public keys. Targets G5.
- **Removed member (`M-REM`)** — a once-honest member who retains all state held up to removal.
  Targets G3, G4.
- **Compromised member device (`M-CMP`)** — exposes one member's current keys. Bounds blast
  radius; targets G1/G4 boundaries.
- **Compromised admin (`A-CMP`)** — exposes an admin's keys; since admins re-wrap plaintext
  epoch keys for everyone, this is the worst single-party compromise. Used to quantify the
  trusted-admin assumption (a v1 weakness to be addressed in v2).

Out of scope: endpoint malware beyond the modeled key exposure, side channels, denial of
service, and traffic-analysis beyond the structural metadata named in §10.

---

## 10. Declared / accepted leakage (v1)

The design knowingly accepts the following. The formal model treats these as adversary inputs,
not violations.

1. **Social graph and structure.** `members`, `accessControl` lists, post authorship, folder
   membership, timestamps, and counts are plaintext (operational metadata).
2. **Blind-index equality + low-cardinality enumeration.** Equal terms produce equal tags
   (query-pattern leakage). For low-cardinality fields (e.g. post `type ∈ {moment, memory,
   milestone}`), anyone with the context indexing key can enumerate all values and label every
   post's category. Content stays confidential; the category does not.
3. **BlurHash.** A low-resolution color placeholder per image is plaintext by design.
4. **Object sizes and counts.** Ciphertext lengths and variant counts are visible.
5. **`displayName`, `email`.** Stored plaintext for operation.

---

## 11. Resolved reconstruction decisions

Where the originals were underspecified or self-contradictory, v1 adopts the most defensible
reading so the model never assumes more than a precise design states. Each decision records its
rationale and, where relevant, the v2 improvement it motivates. (The original owner did not
recall the intended choice on these; resolving them is part of the analysis.)

- **A. Wrap vs AEAD for key wrapping.** *Decision:* AES-KW (RFC 3394) for wrapping keys, AES-GCM
  for bulk data. The originals used both inconsistently; splitting by role is the conventional,
  cleanly-reducible choice. *v2:* consider a single AEAD-based wrap that binds the access-context
  label (`family:F`, `folder:φ`, …) into associated data, so a wrapped key cannot be replayed
  into a different context entry.
- **B. ECDH shared-secret derivation.** *Decision:* `ss := KDF(DH(sk, pk), "roots/ecdh/v1" ‖
  uid_sender ‖ uid_receiver)`. Raw `DH` output is never used as a key, and binding both identities
  into the label prevents unknown-key-share confusion. *v2:* unchanged in principle; combined with
  the ephemeral-key change in (D).
- **C. Mnemonic vs password root.** *Decision:* resolved in §5.1 — the mnemonic seed is the root,
  the password unlocks a wrapped copy. Rejects the impossible "MEK = Argon2id(password) AND
  recoverable from a separate mnemonic" literal reading.
- **D. Identity-key scheme.** *Decision:* one long-term X25519 identity keypair per user; secret
  wrapped under `MEK_U` (so it follows the user across devices), public key published. This is
  faithful to the actual data model, which carries exactly one public key per user; the
  "device/ephemeral keys" language in the originals was MLS-flavored aspiration never realized.
  *Consequence:* the P-ADD handoff uses long-term keys on both sides, so the handoff channel has
  no forward secrecy. *v2:* X3DH-style ephemeral prekeys and per-device identity keys.
- **E. Family indexing key.** *Decision:* a per-family `indexKey[F]`, distributed alongside the
  epoch-key bundle and rotated on member removal (P-REMOVE step 4), distinct from each
  `folderIndexKey[φ]`. Without rotation, a removed member could still run blind-index queries.
- **F. Public-key authenticity.** *Decision:* **none** in v1, faithful to the originals — public
  keys are submitted to and served by the server with no out-of-band check. This is deliberate, so
  that G5 tests the real design rather than a charitable one. *v2:* a key-transparency log
  (append-only, auditable) and/or safety-number verification; this is the primary v2 fix.

---

## 12. What the analysis will do next

1. Encode §4–§7 as a Tamarin model (`model/v1.spthy`): rules for the membership/epoch state
   machine and the message flows; lemmas for G1–G7.
2. Expect G1–G4, G6, G7 to hold under `S-HBC` / `M-REM`, and **G5 to fail under `S-MAL`** with a
   concrete MITM trace. Capture the trace.
3. Write the game-based argument (`proofs/`) reducing G1 to AEAD + AES-KW security for the
   envelope core.
4. Use the failures and the trusted-admin cost (`A-CMP`) to motivate `PROTOCOL_V2.md`.
