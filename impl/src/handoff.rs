//! Historical key handoff: how a newly added member receives the family epoch key so they can read
//! pre-join content (P-ADD, spec §7.1). This is the inversion of Signal: lifetime retention *needs*
//! newcomers to inherit history, so there is no forward secrecy to hide behind here.
//!
//! This module implements both designs so `tests/attack.rs` can run them side by side:
//!
//! * [`v1_admin_wrap`] / [`v1_newcomer_unwrap`] mirror `model/v1.spthy`, where the newcomer's
//!   public key is whatever the (untrusted) server hands the admin. `handoff_key_secrecy` is
//!   FALSIFIED there, and [`v1_admin_wrap`] reproduces that trace against a malicious directory.
//! * [`v2_admin_wrap`] / [`v2_newcomer_unwrap`] mirror `model/v2.spthy`: the newcomer key comes
//!   from an append-only transparency log the newcomer can audit, and the handoff is signed by the
//!   admin's transparency-logged key. Both fixes are required (`model/v2_extraction.spthy` shows a
//!   partial fix stays FALSIFIED), so both are present here.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::primitives::{ecdh_kdf, kw_unwrap, kw_wrap, x25519_dh, CryptoError, Key};

/// The wrapped epoch key plus the admin public key the newcomer needs to redo the DH.
pub struct HandoffV1 {
    pub wrapped_epoch: Vec<u8>,
    pub admin_public: Key,
}

/// v1 wrap: admin derives a KEK from DH with `newcomer_public` and wraps the epoch key under it.
///
/// The vulnerability is entirely in the *provenance* of `newcomer_public`. In v1 it is read off the
/// server directory with no out-of-band check (spec §11-F). If the server substitutes its own key,
/// the admin wraps the epoch key to the attacker. This function is faithful to that: it wraps to
/// whatever public key it is given.
pub fn v1_admin_wrap(
    admin_secret: &Key,
    admin_public: &Key,
    admin_uid: &[u8],
    newcomer_uid: &[u8],
    newcomer_public: &Key,
    epoch_key: &Key,
) -> HandoffV1 {
    let dh = x25519_dh(admin_secret, newcomer_public);
    let kek = ecdh_kdf(&dh, admin_uid, newcomer_uid);
    let wrapped_epoch = kw_wrap(&kek, epoch_key).expect("32-byte epoch key is valid AES-KW input");
    HandoffV1 { wrapped_epoch, admin_public: *admin_public }
}

/// v1 unwrap performed by the newcomer (or by anyone who holds the matching secret).
pub fn v1_newcomer_unwrap(
    newcomer_secret: &Key,
    newcomer_uid: &[u8],
    admin_uid: &[u8],
    handoff: &HandoffV1,
) -> Result<Key, CryptoError> {
    let dh = x25519_dh(newcomer_secret, &handoff.admin_public);
    let kek = ecdh_kdf(&dh, admin_uid, newcomer_uid);
    let bytes = kw_unwrap(&kek, &handoff.wrapped_epoch)?;
    bytes.as_slice().try_into().map_err(|_| CryptoError("unwrapped epoch key wrong length"))
}

// --- v2: transparency log + signed handoff ---------------------------------------------------

/// Append-only public-key directory (CONIKS-style, modeled minimally): first write for a uid wins,
/// so the server cannot equivocate on an already-published key. This is the trust anchor v1 lacked.
#[derive(Default)]
pub struct TransparencyLog {
    enc_keys: HashMap<Vec<u8>, Key>,
    sig_keys: HashMap<Vec<u8>, VerifyingKey>,
}

impl TransparencyLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a user's encryption and signing public keys. Append-only: re-publishing a different
    /// key for an existing uid is rejected, which is what stops silent key substitution.
    pub fn publish(&mut self, uid: &[u8], enc_public: Key, sig_public: VerifyingKey) -> Result<(), CryptoError> {
        if self.enc_keys.contains_key(uid) {
            return Err(CryptoError("transparency log is append-only: uid already has a key"));
        }
        self.enc_keys.insert(uid.to_vec(), enc_public);
        self.sig_keys.insert(uid.to_vec(), sig_public);
        Ok(())
    }

    pub fn enc_key(&self, uid: &[u8]) -> Option<Key> {
        self.enc_keys.get(uid).copied()
    }

    pub fn sig_key(&self, uid: &[u8]) -> Option<VerifyingKey> {
        self.sig_keys.get(uid).copied()
    }
}

/// A v2 handoff carries a signature over the wrapped key and the bound context.
pub struct HandoffV2 {
    pub wrapped_epoch: Vec<u8>,
    pub admin_public: Key,
    pub signature: Signature,
}

fn v2_transcript(admin_public: &Key, newcomer_uid: &[u8], wrapped_epoch: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(b"roots/handoff/v2");
    t.extend_from_slice(admin_public);
    t.extend_from_slice(newcomer_uid);
    t.extend_from_slice(wrapped_epoch);
    t
}

/// v2 wrap (fix 1 + fix 2). The admin looks the newcomer's encryption key up **in the transparency
/// log** rather than trusting a raw server channel, then signs the handoff with its signing key.
pub fn v2_admin_wrap(
    admin_secret: &Key,
    admin_public: &Key,
    admin_uid: &[u8],
    admin_signing: &SigningKey,
    newcomer_uid: &[u8],
    log: &TransparencyLog,
    epoch_key: &Key,
) -> Result<HandoffV2, CryptoError> {
    let newcomer_public = log.enc_key(newcomer_uid).ok_or(CryptoError("newcomer not in transparency log"))?;
    let dh = x25519_dh(admin_secret, &newcomer_public);
    let kek = ecdh_kdf(&dh, admin_uid, newcomer_uid);
    let wrapped_epoch = kw_wrap(&kek, epoch_key).expect("32-byte epoch key is valid AES-KW input");
    let signature = admin_signing.sign(&v2_transcript(admin_public, newcomer_uid, &wrapped_epoch));
    Ok(HandoffV2 { wrapped_epoch, admin_public: *admin_public, signature })
}

/// v2 unwrap. The newcomer verifies the handoff signature against the admin's **transparency-logged**
/// signing key before unwrapping, which rejects a forged/injected handoff (the `no_key_injection_v2`
/// property). Substitution of the newcomer's own key is prevented upstream by the append-only log.
pub fn v2_newcomer_unwrap(
    newcomer_secret: &Key,
    newcomer_uid: &[u8],
    admin_uid: &[u8],
    log: &TransparencyLog,
    handoff: &HandoffV2,
) -> Result<Key, CryptoError> {
    let admin_sig_key = log.sig_key(admin_uid).ok_or(CryptoError("admin not in transparency log"))?;
    let transcript = v2_transcript(&handoff.admin_public, newcomer_uid, &handoff.wrapped_epoch);
    admin_sig_key
        .verify(&transcript, &handoff.signature)
        .map_err(|_| CryptoError("handoff signature verification failed"))?;
    let dh = x25519_dh(newcomer_secret, &handoff.admin_public);
    let kek = ecdh_kdf(&dh, admin_uid, newcomer_uid);
    let bytes = kw_unwrap(&kek, &handoff.wrapped_epoch)?;
    bytes.as_slice().try_into().map_err(|_| CryptoError("unwrapped epoch key wrong length"))
}
