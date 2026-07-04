//! # roots-zka: reference implementation
//!
//! A small, runnable implementation of the Roots zero-knowledge-architecture primitives. It
//! connects the formal analysis to running code:
//!
//! * every primitive matches a decision in `spec/PROTOCOL_V1.md` §11;
//! * `tests/kat.rs` pins the primitives to published standard vectors (RFC 3394, RFC 7748, BIP39);
//! * `tests/properties.rs` checks the four proof obligations from `proofs/ENVELOPE_ARGUMENT.md` §6;
//! * `tests/attack.rs` reproduces the v1 handoff MITM (`model/v1.spthy`, FALSIFIED) and shows the
//!   v2 handoff rejecting it (`model/v2.spthy`, VERIFIED).
//!
//! See `impl/README.md` for the test-to-proof map.

pub mod envelope;
pub mod handoff;
pub mod keystore;
pub mod primitives;
