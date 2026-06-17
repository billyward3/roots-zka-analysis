# Roots ZKA v2 — Strengthened Protocol (the "what I'd do now")

> The strengthening half of reconstruct-then-strengthen. v1 (`PROTOCOL_V1.md`) was analysed and
> found to have a sound cryptographic core but a broken key distribution: the member-add handoff
> trusts public keys the server delivers without verification, which a malicious server exploits
> two ways (`../analysis/RESULTS.md`, Result 2). v2 keeps everything that was proved sound and
> replaces only the handoff trust model.
>
> Every change here is motivated by a specific v1 finding, and the headline ones are machine-checked
> (`../model/v2.spthy`).

---

## 1. What v2 changes, and why

The v1 break is entirely about **unauthenticated public keys**. v1 names the server as the primary
adversary, yet routes every public key through that same server with no out-of-band check (v1
§11-F). Two attacks follow (both with no member compromise):

- **Key extraction** (`handoff_key_secrecy` falsified): the server substitutes the newcomer's
  public key; the admin wraps the real epoch key under it; the server decrypts.
- **Key injection** (`handoff_key_injection` verified): the server forges a handoff to an honest
  newcomer, who then holds an attacker-chosen key.

v2 closes both by **authenticating the keys involved in the handoff**. Nothing else about v1
changes: the envelope, epoch rotation, and recovery were all proved sound and are retained.

## 2. The mechanisms

### 2.1 Key transparency log (server cannot equivocate)

The server publishes every user's identity public keys in an **append-only, publicly auditable
transparency log** (CONIKS / Key Transparency style: a Merkle prefix tree with periodic signed
tree heads). Clients verify **inclusion proofs** (my key is in the log) and **consistency proofs**
(the log is append-only, never rewritten). A server that serves a substituted key must either put
it in the log (where the victim's own client detects a key it never published) or present a split
view (which consistency-proof gossip detects). This converts "the server is an unauthenticated
PKI" into "the server is a transparent PKI that cannot equivocate undetectably."

### 2.2 Out-of-band safety numbers (the human check)

For the high-value step of forming a connection, the two parties may compare a **safety number**
(a hash of both identity keys) over an out-of-band channel (in person, phone), Signal-style. This
is the belt-and-suspenders check that does not depend on the log infrastructure being audited.

### 2.3 Signed, verified handoff

The admin **signs** the handoff (the wrapped epoch key bound to family, epoch, and recipient) with
its identity signing key. The newcomer **verifies** that signature against the admin's
**transparency-logged** signing key before accepting. The newcomer's encryption key, used by the
admin to wrap, is likewise taken from the log (not from an unauthenticated channel).

**Both halves are required.** Authenticating only the newcomer's key is insufficient: the injection
path remains and re-pollutes extraction. This is not a hand-wave — it is a machine-checked negative
result (`../model/v2_extraction.spthy`: with only the newcomer key authenticated,
`handoff_key_secrecy` is still **falsified**). Authenticating the admin's handoff (so forged
handoffs are rejected) is what closes it.

## 3. What is proved (`../model/v2.spthy`)

Modelled as: authentic newcomer key = a transparency-log lookup (`!PkE`), authentic handoff =
an unforgeable delivery the newcomer verifies (`!AuthHandoff`, abstracting the signature-checked
handoff). The wrapped key is still placed on the wire, so confidentiality faces a real network
adversary.

| Lemma | v1 | v2 |
|---|---|---|
| `handoff_key_secrecy` (extraction) | **falsified** | **verified** (all-traces, 9 steps) |
| `no_key_injection` (injection) | reachable (verified attack) | **verified** secure (all-traces, 13 steps) |
| partial fix only (`v2_extraction.spthy`) | — | **falsified** — proves both fixes are needed |

So the exact two attacks that broke v1 are machine-checked to be closed in v2, under no member
compromise.

## 4. Further improvements (designed; deeper modelling is future work)

These came out of the v1 analysis but are not the headline break; recorded as the rest of the
"what I'd do now."

- **Forward-secret handoff (v1 §11-D).** v1 uses long-term identity keys on both sides of the
  handoff, so the handoff channel has no forward secrecy. v2 adds X3DH-style **ephemeral prekeys**:
  a compromise of long-term keys later does not expose epoch keys handed off earlier.
- **Context-bound key wrap (v1 §11-A).** Replace the role-split AES-KW with an **AEAD wrap that
  binds the access-context label** (`family:F`, `folder:φ`, …) into associated data, so a wrapped
  key cannot be replayed into a different context's bundle entry.
- **Reduced admin trust.** In v1 every onboarding routes plaintext epoch keys through an admin's
  device (a single high-value compromise, adversary `A-CMP`). Options: distribute the
  re-wrapping across a threshold of admins, or move to a proper group-key agreement (MLS/TreeKEM)
  where no single party re-wraps for everyone.
- **True forward secrecy vs retention.** v1's epoch model gives coarse forward secrecy and, by
  design, lets new members inherit history (the retention requirement). v2 keeps that product
  property but makes the boundary explicit and auditable, rather than implicit.

## 5. What v2 deliberately does NOT change

The cryptographic core that v1 analysis proved sound is retained verbatim: the per-post DEK / epoch-
KEK envelope (G1/G6), epoch rotation and revocation (G3/G4), and the mnemonic-root recovery keystore
(G7). v2 is a key-distribution fix, not a redesign.
