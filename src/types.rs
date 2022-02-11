//! A few convenience types, extending [`sodalite`].
//!
//! The type aliases for `[u8]` are intended to help with documentation readibility.
//!
//! The [`SafeSecureSeed`] wrapper is intended to act as a type-safe barrier to remind that only
//! cryptographically secure random bytes should be wrapped in it.

use crate::macros::type_wrapper;

/// An unencrypted message.
pub type Plaintext = [u8];

/// An encrypted message.
pub type Ciphertext = [u8];

/// An unsigned message.
pub type UnsignedMessage = [u8];

/// A signed message, bundled with its signature.
pub type SignedMessage = [u8];

/// A signature-verified message.
pub type VerifiedMessage = [u8];

/// A cryptographically secure seed value.
///
/// The seed should be uniformly random and generated with a secure random number generator.
pub type SecureSeed = [u8; 32];

type_wrapper!(SafeSecureSeed, SecureSeed);
