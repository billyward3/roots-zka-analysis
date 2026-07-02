//! The mnemonic-root keystore that resolves the contradictory v1 documentation (spec §5.1, §11-C).
//!
//! The originals claimed both "MEK = Argon2id(password)" and "MEK is recoverable from a BIP39
//! mnemonic," which cannot both hold. Resolution: the **mnemonic seed is the root**, and the
//! password only unlocks a *wrapped copy* of the MEK. Losing the password never loses the account;
//! the mnemonic always regenerates the same MEK. This is what `recovery_secrecy_g7` checks.

use argon2::Argon2;
use bip39::Mnemonic;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::primitives::{kw_unwrap, kw_wrap, CryptoError, Key};

/// The user's root Master Encryption Key. Canonical source is the mnemonic seed.
pub struct Mek(pub Key);

/// `MEK_U := HKDF-SHA256(seed = BIP39seed(mnemonic), info = "roots/mek")`. Fixed at signup and
/// reproducible forever from the 24 words alone (obligation behind G7).
pub fn mek_from_mnemonic(mnemonic: &Mnemonic, passphrase: &str) -> Mek {
    let seed = mnemonic.to_seed(passphrase);
    let hk = Hkdf::<Sha256>::new(None, &seed);
    let mut mek = [0u8; 32];
    hk.expand(b"roots/mek", &mut mek).expect("32 is a valid HKDF-SHA256 output length");
    Mek(mek)
}

/// `pwKey := Argon2id(password, salt)` with the spec's parameters (t=3, m=64 MiB, p=1). This key
/// is *only* ever used to wrap/unwrap the stored MEK copy; it is never a root itself (spec §5.1).
pub fn pwkey_from_password(password: &[u8], salt: &[u8]) -> Result<Key, CryptoError> {
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| CryptoError("bad Argon2 params"))?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut pwkey = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut pwkey)
        .map_err(|_| CryptoError("Argon2id derivation failed"))?;
    Ok(pwkey)
}

/// Store the MEK under the password-derived key: `wrap(MEK, pwKey)` (AES-KW).
pub fn wrap_mek(mek: &Mek, pwkey: &Key) -> Vec<u8> {
    kw_wrap(pwkey, &mek.0).expect("a 32-byte MEK is a valid AES-KW input")
}

/// Password login path: unwrap the stored MEK. Wrong password fails the AES-KW integrity check.
pub fn unwrap_mek(wrapped: &[u8], pwkey: &Key) -> Result<Mek, CryptoError> {
    let bytes = kw_unwrap(pwkey, wrapped)?;
    let arr: Key = bytes.as_slice().try_into().map_err(|_| CryptoError("unwrapped MEK wrong length"))?;
    Ok(Mek(arr))
}
