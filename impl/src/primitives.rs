//! Cryptographic primitives, one function per role, chosen to match `spec/PROTOCOL_V1.md` §11.
//!
//! Deliberate role split (decision §11-A): AES-KW wraps *keys*, AES-256-GCM seals *data*. Keeping
//! them apart is what makes the envelope argument in `proofs/ENVELOPE_ARGUMENT.md` reduce cleanly.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_kw::KekAes256;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// Fixed-size symmetric key. All keys in the system are 256-bit (obligation 4).
pub type Key = [u8; 32];

#[derive(Debug, PartialEq, Eq)]
pub struct CryptoError(pub &'static str);

// --- AES-256-GCM: bulk data sealing (spec §11-A) ---------------------------------------------

/// Seal `plaintext` under `key` with a caller-supplied 96-bit `nonce`, binding `aad`.
///
/// The nonce is a parameter on purpose: obligation 2 (fresh IV per encryption) is the *caller's*
/// duty and is enforced one level up in `envelope::seal_post`. Returns `ciphertext || tag`.
pub fn aead_seal(key: &Key, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("AES-GCM encryption is infallible for valid inputs")
}

/// Open a `ciphertext || tag` produced by [`aead_seal`]. Fails on a wrong key, tampered
/// ciphertext, or mismatched `aad`.
pub fn aead_open(key: &Key, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError("AEAD authentication failed"))
}

// --- AES-KW (RFC 3394): key wrapping (spec §11-A) --------------------------------------------

/// Wrap key material under a 256-bit key-encrypting key. Input length must be a multiple of 8
/// bytes and at least 16 (an RFC 3394 constraint, obligation 3). Output is `input_len + 8`.
pub fn kw_wrap(kek: &Key, key_material: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let kek = KekAes256::new(kek.into());
    let mut out = vec![0u8; key_material.len() + 8];
    kek.wrap(key_material, &mut out)
        .map_err(|_| CryptoError("AES-KW wrap failed (input not a valid key length)"))?;
    Ok(out)
}

/// Reverse [`kw_wrap`]. Fails if the integrity check value does not verify.
pub fn kw_unwrap(kek: &Key, wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if wrapped.len() < 16 {
        return Err(CryptoError("AES-KW ciphertext too short"));
    }
    let kek = KekAes256::new(kek.into());
    let mut out = vec![0u8; wrapped.len() - 8];
    kek.unwrap(wrapped, &mut out)
        .map_err(|_| CryptoError("AES-KW unwrap failed (integrity check)"))?;
    Ok(out)
}

// --- X25519 ECDH with labeled KDF (spec §11-B) -----------------------------------------------

/// Public key for a raw X25519 secret scalar: `pk = x25519(sk, basepoint)`.
pub fn x25519_public(secret: &Key) -> Key {
    x25519(*secret, X25519_BASEPOINT_BYTES)
}

/// Raw X25519 Diffie-Hellman. Never used directly as a key; feed it to [`ecdh_kdf`].
pub fn x25519_dh(secret: &Key, their_public: &Key) -> Key {
    x25519(*secret, *their_public)
}

/// Derive a key-encrypting key from a raw DH output, binding both identities into the label so a
/// shared secret cannot be reinterpreted between unrelated peers (spec §11-B, unknown-key-share).
///
/// `ss := HKDF-SHA256(dh, info = "roots/ecdh/v1" || sender_uid || receiver_uid)`.
pub fn ecdh_kdf(dh: &Key, sender_uid: &[u8], receiver_uid: &[u8]) -> Key {
    let hk = Hkdf::<Sha256>::new(None, dh);
    let mut info = Vec::with_capacity(14 + sender_uid.len() + receiver_uid.len());
    info.extend_from_slice(b"roots/ecdh/v1");
    info.extend_from_slice(sender_uid);
    info.extend_from_slice(receiver_uid);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("32 is a valid HKDF-SHA256 output length");
    okm
}

// --- HMAC-SHA256 blind index (spec §11-E, §6.3) ----------------------------------------------

/// Keyed blind-index tag for a searchable value. Determinism is the point: equal values under the
/// same context key produce equal tags, which is what lets the server run `array-contains` without
/// learning the plaintext. Rotating the context key (P-REMOVE step 4) invalidates old tags.
pub fn blind_index(index_key: &Key, value: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(index_key).expect("HMAC accepts any key length");
    mac.update(value);
    mac.finalize().into_bytes().into()
}
