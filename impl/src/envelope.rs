//! Envelope encryption: the confidentiality core whose security is argued in
//! `proofs/ENVELOPE_ARGUMENT.md` and machine-checked as `post_secrecy_closed` in
//! `model/v1_core.spthy`.
//!
//! Layering (spec §5): a per-post `PostKey` seals the post body; the post key is wrapped under the
//! per-family rotating `EpochKey`. This module is where obligations 1, 2, and 4 are enforced.

use rand::rngs::OsRng;
use rand::RngCore;

use crate::primitives::{aead_open, aead_seal, kw_unwrap, kw_wrap, CryptoError, Key};

/// Per-family key-encrypting key. Rotates on member removal (see `handoff`/rotation).
#[derive(Clone)]
pub struct EpochKey(pub Key);

/// Per-post data-encryption key. Sampled fresh per post and never reused (obligation 1).
pub struct PostKey(pub Key);

/// A sealed post: the fresh nonce travels with the ciphertext.
pub struct SealedPost {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

fn fresh_key() -> Key {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

impl EpochKey {
    /// 256-bit CSPRNG output, independent across epochs (obligation 4).
    pub fn generate() -> Self {
        EpochKey(fresh_key())
    }
}

impl PostKey {
    /// Obligation 1: fresh per post, from the OS CSPRNG.
    pub fn generate() -> Self {
        PostKey(fresh_key())
    }
}

/// Seal a post body under a post key. A fresh 96-bit nonce is drawn here, so `(postKey, nonce)`
/// never repeats across calls (obligation 2). `aad` binds context (e.g. `post_id`, `family_id`).
pub fn seal_post(post_key: &PostKey, aad: &[u8], plaintext: &[u8]) -> SealedPost {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = aead_seal(&post_key.0, &nonce, aad, plaintext);
    SealedPost { nonce, ciphertext }
}

pub fn open_post(post_key: &PostKey, aad: &[u8], sealed: &SealedPost) -> Result<Vec<u8>, CryptoError> {
    aead_open(&post_key.0, &sealed.nonce, aad, &sealed.ciphertext)
}

/// Wrap a post key under an epoch key with AES-KW (obligation 3: keys are wrapped, not GCM-sealed).
pub fn wrap_post_key(epoch: &EpochKey, post_key: &PostKey) -> Vec<u8> {
    kw_wrap(&epoch.0, &post_key.0).expect("a 32-byte post key is a valid AES-KW input")
}

pub fn unwrap_post_key(epoch: &EpochKey, wrapped: &[u8]) -> Result<PostKey, CryptoError> {
    let bytes = kw_unwrap(&epoch.0, wrapped)?;
    let arr: Key = bytes.as_slice().try_into().map_err(|_| CryptoError("unwrapped post key wrong length"))?;
    Ok(PostKey(arr))
}
