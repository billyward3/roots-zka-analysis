//! The handoff attack, in runnable form. These tests are the code counterpart of the Tamarin
//! verdicts: v1 is broken exactly where `model/v1.spthy` says it is, and v2 closes it exactly as
//! `model/v2.spthy` says. A malicious directory server is the adversary in both.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use roots_zka::handoff::{
    v1_admin_wrap, v1_newcomer_unwrap, v2_admin_wrap, v2_newcomer_unwrap, TransparencyLog,
};
use roots_zka::primitives::{x25519_public, Key};

fn fresh_x25519() -> (Key, Key) {
    use rand::RngCore;
    let mut sk = [0u8; 32];
    OsRng.fill_bytes(&mut sk);
    let pk = x25519_public(&sk);
    (sk, pk)
}

/// v1, `handoff_key_secrecy` = FALSIFIED. A malicious server substitutes its own public key for the
/// newcomer's during P-ADD. The honest admin wraps the family epoch key to the attacker, who then
/// recovers it. There is no out-of-band check to stop this (spec §11-F).
#[test]
fn v1_malicious_server_recovers_epoch_key() {
    let admin_uid = b"admin";
    let newcomer_uid = b"newcomer";

    let (admin_sk, admin_pk) = fresh_x25519();
    let (_newcomer_sk, _newcomer_pk) = fresh_x25519(); // the honest key the admin *should* receive
    let (attacker_sk, attacker_pk) = fresh_x25519(); // the key a malicious server serves instead

    let epoch_key: Key = [0x42; 32];

    // The admin believes it is wrapping to the newcomer, but the server handed it attacker_pk.
    let handoff = v1_admin_wrap(&admin_sk, &admin_pk, admin_uid, newcomer_uid, &attacker_pk, &epoch_key);

    // The attacker, holding the matching secret, recovers the epoch key. Confidentiality is lost.
    let recovered = v1_newcomer_unwrap(&attacker_sk, newcomer_uid, admin_uid, &handoff).unwrap();
    assert_eq!(recovered, epoch_key, "v1: malicious server must be able to recover the epoch key");
}

/// v2, `handoff_key_secrecy_v2` = VERIFIED. The admin looks the newcomer's key up in the append-only
/// transparency log instead of trusting a raw server channel. The server cannot equivocate on an
/// already-published key, so the substitution has no effect: the epoch key is wrapped to the genuine
/// newcomer and the attacker cannot recover it.
#[test]
fn v2_transparency_log_blocks_substitution() {
    let admin_uid = b"admin";
    let newcomer_uid = b"newcomer";

    let (admin_sk, admin_pk) = fresh_x25519();
    let admin_signing = SigningKey::generate(&mut OsRng);
    let (newcomer_sk, newcomer_pk) = fresh_x25519();
    let newcomer_signing = SigningKey::generate(&mut OsRng);
    let (attacker_sk, _attacker_pk) = fresh_x25519();

    // Both parties publish once. Append-only: the server cannot later swap the newcomer's key.
    let mut log = TransparencyLog::new();
    log.publish(admin_uid, admin_pk, admin_signing.verifying_key()).unwrap();
    log.publish(newcomer_uid, newcomer_pk, newcomer_signing.verifying_key()).unwrap();

    let epoch_key: Key = [0x42; 32];
    let handoff = v2_admin_wrap(&admin_sk, &admin_pk, admin_uid, &admin_signing, newcomer_uid, &log, &epoch_key).unwrap();

    // The genuine newcomer recovers the epoch key.
    let recovered = v2_newcomer_unwrap(&newcomer_sk, newcomer_uid, admin_uid, &log, &handoff).unwrap();
    assert_eq!(recovered, epoch_key, "v2: genuine newcomer must recover the epoch key");

    // The attacker's secret no longer matches the key the epoch was wrapped to.
    let attacker_attempt = v2_newcomer_unwrap(&attacker_sk, newcomer_uid, admin_uid, &log, &handoff);
    assert!(attacker_attempt.is_err(), "v2: attacker must not recover the epoch key");
}

/// The append-only property itself: a server trying to overwrite a published key is rejected. This
/// is the mechanism that makes substitution impossible in the first place.
#[test]
fn v2_log_is_append_only() {
    let (_sk, pk) = fresh_x25519();
    let (_sk2, pk2) = fresh_x25519();
    let signing = SigningKey::generate(&mut OsRng);

    let mut log = TransparencyLog::new();
    log.publish(b"newcomer", pk, signing.verifying_key()).unwrap();
    let overwrite = log.publish(b"newcomer", pk2, signing.verifying_key());
    assert!(overwrite.is_err(), "transparency log must reject key overwrite");
}

/// v2, `no_key_injection_v2` = VERIFIED. A forged handoff (server injecting its own wrapped key,
/// not signed by the admin's logged key) is rejected at signature verification, so an honest
/// newcomer never accepts an attacker-chosen epoch key.
#[test]
fn v2_rejects_forged_handoff() {
    let admin_uid = b"admin";
    let newcomer_uid = b"newcomer";

    let (admin_sk, admin_pk) = fresh_x25519();
    let admin_signing = SigningKey::generate(&mut OsRng);
    let (newcomer_sk, newcomer_pk) = fresh_x25519();
    let newcomer_signing = SigningKey::generate(&mut OsRng);

    let mut log = TransparencyLog::new();
    log.publish(admin_uid, admin_pk, admin_signing.verifying_key()).unwrap();
    log.publish(newcomer_uid, newcomer_pk, newcomer_signing.verifying_key()).unwrap();

    // The attacker forges a handoff signed with its OWN key, not the admin's logged key.
    let attacker_signing = SigningKey::generate(&mut OsRng);
    let forged = v2_admin_wrap(&admin_sk, &admin_pk, admin_uid, &attacker_signing, newcomer_uid, &log, &[0xAA; 32]).unwrap();

    let result = v2_newcomer_unwrap(&newcomer_sk, newcomer_uid, admin_uid, &log, &forged);
    assert!(result.is_err(), "v2: forged handoff must fail signature verification");
}
