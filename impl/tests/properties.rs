//! Property tests for the four proof obligations exported by `proofs/ENVELOPE_ARGUMENT.md` §6,
//! plus the AEAD guarantees the envelope argument assumes. Each test names the obligation it
//! discharges so the mapping to the proof is explicit.

use std::collections::HashSet;

use proptest::prelude::*;
use roots_zka::envelope::{open_post, seal_post, unwrap_post_key, wrap_post_key, EpochKey, PostKey};
use roots_zka::primitives::{aead_open, aead_seal};

/// Obligation 1: `postKey` is sampled fresh per post and never reused. Over many draws, all keys
/// are distinct.
#[test]
fn obligation1_post_keys_are_fresh() {
    let mut seen = HashSet::new();
    for _ in 0..10_000 {
        assert!(seen.insert(PostKey::generate().0), "post key collision: not freshly sampled");
    }
}

/// Obligation 2: each seal draws a fresh 96-bit IV, so `(postKey, IV)` never repeats even when the
/// same key seals the same plaintext repeatedly.
#[test]
fn obligation2_nonces_never_repeat() {
    let key = PostKey::generate();
    let mut nonces = HashSet::new();
    for _ in 0..10_000 {
        let sealed = seal_post(&key, b"aad", b"same plaintext every time");
        assert!(nonces.insert(sealed.nonce), "nonce reuse under a fixed post key");
    }
}

/// Obligation 4: epoch keys are 256-bit and independent across epochs.
#[test]
fn obligation4_epoch_keys_independent() {
    let mut seen = HashSet::new();
    for _ in 0..10_000 {
        let k = EpochKey::generate().0;
        assert_eq!(k.len(), 32, "epoch key must be 256-bit");
        assert!(seen.insert(k), "epoch key collision: not independent");
    }
}

proptest! {
    /// Obligation 3 (roundtrip) + envelope layering: any post body seals and re-opens under a post
    /// key that was itself wrapped/unwrapped under an epoch key.
    #[test]
    fn envelope_roundtrip(plaintext in proptest::collection::vec(any::<u8>(), 0..2048), aad in proptest::collection::vec(any::<u8>(), 0..64)) {
        let epoch = EpochKey::generate();
        let post_key = PostKey::generate();

        let wrapped = wrap_post_key(&epoch, &post_key);
        prop_assert_eq!(wrapped.len(), 40, "AES-KW wrap of a 32-byte key is 40 bytes");
        let recovered = unwrap_post_key(&epoch, &wrapped).unwrap();

        let sealed = seal_post(&recovered, &aad, &plaintext);
        let opened = open_post(&recovered, &aad, &sealed).unwrap();
        prop_assert_eq!(opened, plaintext);
    }

    /// AEAD integrity: flipping any ciphertext byte makes opening fail. The envelope argument leans
    /// on this (a forged ciphertext must not decrypt).
    #[test]
    fn aead_detects_tampering(plaintext in proptest::collection::vec(any::<u8>(), 1..512), idx in any::<usize>()) {
        let key = PostKey::generate();
        let sealed = seal_post(&key, b"ctx", &plaintext);
        let mut ct = sealed.ciphertext.clone();
        let i = idx % ct.len();
        ct[i] ^= 0x01;
        let tampered = roots_zka::envelope::SealedPost { nonce: sealed.nonce, ciphertext: ct };
        prop_assert!(open_post(&key, b"ctx", &tampered).is_err());
    }

    /// AEAD context binding: opening with different associated data fails. This is what lets `aad`
    /// bind a post to its family/post id.
    #[test]
    fn aead_binds_aad(plaintext in proptest::collection::vec(any::<u8>(), 0..512)) {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let ct = aead_seal(&key, &nonce, b"family:A", &plaintext);
        prop_assert!(aead_open(&key, &nonce, b"family:B", &ct).is_err());
        prop_assert_eq!(aead_open(&key, &nonce, b"family:A", &ct).unwrap(), plaintext);
    }
}
