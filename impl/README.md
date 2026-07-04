# `impl/`: reference implementation

A small Rust crate that makes the analysis in this repository checkable against running code. It
implements the cryptographic primitives and the two handoff designs, not the Roots application. Every
primitive follows a decision in [`../spec/PROTOCOL_V1.md`](../spec/PROTOCOL_V1.md) §11, and every test
corresponds to a claim or assumption from the formal layer.

The formal layer establishes two things: the protocol logic is sound in the symbolic model, and the
envelope reduces to standard AEAD and key-wrap security in the computational model. This crate checks
that an implementation meets the assumptions those results depend on, and that the handoff attack and
its fix behave as the models predict.

## Running the tests

```
cargo test          # 14 tests: 4 known-answer, 6 obligation/property, 4 attack/defense
cargo clippy        # clean
```

Requires a recent stable Rust (edition 2024 dependencies; tested on 1.96).

## Layout

| File | Role |
|------|------|
| `src/primitives.rs` | AES-256-GCM, AES-KW, X25519 + labeled KDF, HMAC blind index (spec §11-A,B,E) |
| `src/envelope.rs`   | Post-key / epoch-key envelope; enforces obligations 1, 2, 4 |
| `src/keystore.rs`   | Mnemonic-root MEK with password-wrapped copy (spec §5.1, §11-C) |
| `src/handoff.rs`    | v1 (unauthenticated) and v2 Heirloom (transparency log + signed) handoff |

## How the tests map to the analysis

Each test corresponds to a specific claim.

### Known-answer tests (`tests/kat.rs`)

These pin the primitives to published standard vectors, so the constructions are the standardized
ones rather than lookalikes.

| Test | Pins to |
|------|---------|
| `aes_kw_rfc3394_256bit` | RFC 3394 §4.6 wrap vector |
| `x25519_rfc7748` | RFC 7748 §6.1 DH vector |
| `bip39_trezor_vector` | BIP39 Trezor seed vector |
| `mek_is_deterministic_from_mnemonic` | recovery goal G7 (deterministic root) |

### Property tests (`tests/properties.rs`)

These check the four obligations exported by
[`../proofs/ENVELOPE_ARGUMENT.md`](../proofs/ENVELOPE_ARGUMENT.md) §6, along with the AEAD guarantees
the argument assumes.

| Test | Discharges |
|------|-----------|
| `obligation1_post_keys_are_fresh` | Obligation 1: fresh post key per post |
| `obligation2_nonces_never_repeat` | Obligation 2: fresh IV, `(postKey, IV)` never repeats |
| `obligation4_epoch_keys_independent` | Obligation 4: 256-bit independent epoch keys |
| `envelope_roundtrip` | Obligation 3 roundtrip + envelope layering |
| `aead_detects_tampering` | AEAD integrity (forged ciphertext must not decrypt) |
| `aead_binds_aad` | AEAD context binding via associated data |

Obligation 3's shape (AES-KW rather than AES-GCM for keys) is structural: `wrap_post_key` can only
call AES-KW, and `envelope_roundtrip` asserts the 40-byte wrap length that AES-KW produces.

### Attack and defense (`tests/attack.rs`)

| Test | Mirrors |
|------|---------|
| `v1_malicious_server_recovers_epoch_key` | `model/v1.spthy` `handoff_key_secrecy` = **FALSIFIED** |
| `v2_transparency_log_blocks_substitution` | `model/v2.spthy` `handoff_key_secrecy_v2` = **VERIFIED** |
| `v2_rejects_forged_handoff` | `model/v2.spthy` `no_key_injection_v2` = **VERIFIED** |
| `v2_log_is_append_only` | the append-only directory the fix depends on |

`v1_malicious_server_recovers_epoch_key` asserts that the attack succeeds: a malicious directory
substitutes its key, the admin wraps the epoch key to the attacker, and the attacker recovers it,
matching the falsified lemma. The v2 tests show the same adversary defeated by the two-part fix, an
append-only key lookup and a signed handoff, which `model/v2_extraction.spthy` shows must be applied
together.

## Scope and limitations

The crate is written for clarity and to support the analysis. It uses the vetted RustCrypto and dalek
crates for the primitives, but does not provide end-to-end constant-time handling, key zeroization on
every path, or the full P-ADD/P-REMOVE state machine. The transparency log is a plain append-only
map, which captures the one property the security argument needs, no equivocation on a published key,
without the machinery of a real CONIKS deployment.
