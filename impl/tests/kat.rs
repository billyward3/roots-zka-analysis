//! Known-answer tests: pin each primitive to a *published* standard vector. This is what lets a
//! reader trust that these are the real standardized constructions and not lookalikes.

use bip39::Mnemonic;
use hex_literal::hex;
use roots_zka::keystore::mek_from_mnemonic;
use roots_zka::primitives::{kw_unwrap, kw_wrap, x25519_dh, x25519_public};

/// RFC 3394 §4.6: wrap 256 bits of key data with a 256-bit KEK.
#[test]
fn aes_kw_rfc3394_256bit() {
    let kek = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    let key_data = hex!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
    let expected = hex!(
        "28C9F404C4B810F4CBCCB35CFB87F826"
        "3F5786E2D80ED326CBC7F0E71A99F43B"
        "FB988B9B7A02DD21"
    );
    let wrapped = kw_wrap(&kek, &key_data).unwrap();
    assert_eq!(wrapped.as_slice(), &expected[..], "RFC 3394 wrap vector mismatch");
    let unwrapped = kw_unwrap(&kek, &wrapped).unwrap();
    assert_eq!(unwrapped.as_slice(), &key_data[..], "RFC 3394 unwrap roundtrip mismatch");
}

/// RFC 7748 §6.1: X25519 Diffie-Hellman test vector (Alice/Bob).
#[test]
fn x25519_rfc7748() {
    let alice_sk = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_pk = hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_sk = hex!("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_pk = hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    assert_eq!(x25519_public(&alice_sk), alice_pk, "Alice public key derivation");
    assert_eq!(x25519_public(&bob_sk), bob_pk, "Bob public key derivation");
    assert_eq!(x25519_dh(&alice_sk, &bob_pk), shared, "Alice-side shared secret");
    assert_eq!(x25519_dh(&bob_sk, &alice_pk), shared, "Bob-side shared secret");
}

/// BIP39 Trezor test vector: all-zero entropy with passphrase "TREZOR" yields a fixed seed. This
/// pins the recovery root so a change to the mnemonic path would be caught.
#[test]
fn bip39_trezor_vector() {
    let entropy = [0u8; 16];
    let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    assert_eq!(
        mnemonic.to_string(),
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about",
        "BIP39 mnemonic for zero entropy",
    );
    let expected_seed = hex!(
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    );
    assert_eq!(mnemonic.to_seed("TREZOR"), expected_seed, "BIP39 seed vector");
}

/// The MEK is a deterministic function of the mnemonic: same words in, same root key out. This is
/// the mechanical fact behind recovery goal G7.
#[test]
fn mek_is_deterministic_from_mnemonic() {
    let entropy = [0u8; 32];
    let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    let a = mek_from_mnemonic(&mnemonic, "");
    let b = mek_from_mnemonic(&mnemonic, "");
    assert_eq!(a.0, b.0, "MEK derivation must be deterministic");
}
