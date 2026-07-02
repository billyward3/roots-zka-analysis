# `impl/` — reference implementation

A small runnable Rust crate whose only job is to make the analysis in this repo checkable against
real code. It is not a re-implementation of the Roots app. Every primitive matches a decision in
[`../spec/PROTOCOL_V1.md`](../spec/PROTOCOL_V1.md) §11, and every test discharges something the
formal layer assumes or claims.

The through-line of the whole artifact:

> Tamarin says the protocol logic is sound (v2). The game-based argument says the envelope reduces
> to standard AEAD + AES-KW security. This crate says a real implementation actually satisfies those
> assumptions, and the handoff attack and its fix behave in code exactly as the models predict.

## Run it

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
| `src/handoff.rs`    | v1 (unauthenticated) and v2 (transparency log + signed) handoff |

## Test-to-proof map

This is the point of the crate. Each test names the formal claim it grounds.

### Known-answer tests (`tests/kat.rs`) — the primitives are the standard ones

| Test | Pins to |
|------|---------|
| `aes_kw_rfc3394_256bit` | RFC 3394 §4.6 wrap vector |
| `x25519_rfc7748` | RFC 7748 §6.1 DH vector |
| `bip39_trezor_vector` | BIP39 Trezor seed vector |
| `mek_is_deterministic_from_mnemonic` | recovery goal G7 (deterministic root) |

### Property tests (`tests/properties.rs`) — the envelope argument's obligations hold

These are the four obligations exported by [`../proofs/ENVELOPE_ARGUMENT.md`](../proofs/ENVELOPE_ARGUMENT.md) §6,
plus the AEAD guarantees that argument assumes.

| Test | Discharges |
|------|-----------|
| `obligation1_post_keys_are_fresh` | Obligation 1: fresh post key per post |
| `obligation2_nonces_never_repeat` | Obligation 2: fresh IV, `(postKey, IV)` never repeats |
| `obligation4_epoch_keys_independent` | Obligation 4: 256-bit independent epoch keys |
| `envelope_roundtrip` | Obligation 3 roundtrip + envelope layering |
| `aead_detects_tampering` | AEAD integrity (forged ciphertext must not decrypt) |
| `aead_binds_aad` | AEAD context binding via associated data |

Obligation 3's *shape* (AES-KW, not GCM, for keys) is structural: `wrap_post_key` can only call
AES-KW, and `envelope_roundtrip` asserts the 40-byte wrap length that AES-KW produces.

### Attack / defense (`tests/attack.rs`) — the models, in code

| Test | Mirrors |
|------|---------|
| `v1_malicious_server_recovers_epoch_key` | `model/v1.spthy` `handoff_key_secrecy` = **FALSIFIED** |
| `v2_transparency_log_blocks_substitution` | `model/v2.spthy` `handoff_key_secrecy_v2` = **VERIFIED** |
| `v2_rejects_forged_handoff` | `model/v2.spthy` `no_key_injection_v2` = **VERIFIED** |
| `v2_log_is_append_only` | the mechanism (append-only directory) behind the fix |

`v1_malicious_server_recovers_epoch_key` deliberately **asserts the attack succeeds**: a malicious
directory substitutes its key, the honest admin wraps the epoch key to the attacker, and the
attacker recovers it. That is the falsified lemma made concrete. The v2 tests then show the same
adversary defeated by the two-part fix (append-only key lookup + signed handoff), which
`model/v2_extraction.spthy` proves must be applied together.

## Scope and honesty

This is a clarity-first reference, not hardened production code. It uses vetted RustCrypto/dalek
crates for the primitives, but it does not implement constant-time handling end to end, secure key
zeroization on every path, or the full P-ADD/P-REMOVE state machine. The transparency log is modeled
as an append-only map to capture the one property the security argument needs (no equivocation on a
published key), not as a real CONIKS Merkle deployment.
