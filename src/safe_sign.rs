//! Public-key signatures based using the `crypto_sign` API.
//!
//! # Security model
//!
//! From <https://nacl.cr.yp.to/sign.html>:
//!
//! ## Message lengths
//!
//! > See [Validation] regarding safe message lengths.
//!
//! [Validation]: https://nacl.cr.yp.to/valid.html

use alloc::boxed::Box;
use alloc::vec;

use sodalite::SignPublicKey;

use crate::macros::newtype_wrapper;
use crate::types::{SafeSecureSeed, SignedMessage, UnsignedMessage, VerifiedMessage};

newtype_wrapper!(SafeSignPublicKey, sodalite::SignPublicKey);
newtype_wrapper!(SafeSignSecretKey, sodalite::SignSecretKey);

/// Generate a new random secret key and corresponding public key.
#[cfg(feature = "rand")]
pub fn safe_sign_keypair() -> (SafeSignPublicKey, SafeSignSecretKey) {
    let mut public_key = SignPublicKey::default();
    let mut secret_key = sign_secret_key_default();
    sodalite::sign_keypair(&mut public_key, &mut secret_key);
    (public_key.into(), secret_key.into())
}

/// Derive a secret key and corresponding public key for the given seed.
///
/// The `seed` should be uniformly random and generated with a secure random number generator.
pub fn safe_sign_keypair_seed(seed: &SafeSecureSeed) -> (SafeSignPublicKey, SafeSignSecretKey) {
    let mut public_key = SignPublicKey::default();
    let mut secret_key = sign_secret_key_default();
    sodalite::sign_keypair_seed(&mut public_key, &mut secret_key, seed.as_ref());
    (public_key.into(), secret_key.into())
}

/// Sign a message using `secret_key`.
///
/// This wraps [`sodalite::sign_attached`].
pub fn safe_sign_attached(
    unsigned_message: &UnsignedMessage,
    secret_key: &SafeSignSecretKey,
) -> Box<SignedMessage> {
    // Precondition: Output buffer size must match input buffer plus signature size
    let mut signed_message = vec![0_u8; unsigned_message.len() + sodalite::SIGN_LEN];

    sodalite::sign_attached(&mut signed_message, unsigned_message, secret_key.as_ref());

    signed_message.into()
}

/// Verify a message signed `secret_key`.
///
/// This wraps [`sodalite::sign_attached_open`].
pub fn safe_sign_attached_open(
    signed_message: &SignedMessage,
    public_key: &SafeSignPublicKey,
) -> Option<Box<VerifiedMessage>> {
    // Precondition: Output buffer size must match input buffer
    let mut verified_message = vec![0_u8; signed_message.len()];

    let verified_len =
        sodalite::sign_attached_open(&mut verified_message, signed_message, public_key.as_ref())
            .ok()?;

    assert!(verified_len <= verified_message.len());
    verified_message.truncate(verified_len);

    Some(verified_message.into())
}

/// XXX: Work around Rust providing [`Default`] only for arrays up to size 32.
fn sign_secret_key_default() -> sodalite::SignSecretKey {
    [u8::default(); sodalite::SIGN_SECRET_KEY_LEN]
}

#[cfg(test)]
mod tests {
    use alloc::format; // required by proptest macros

    use proptest::prelude::*;
    use proptest::test_runner::TestCaseResult;

    use super::*;
    use crate::types::SecureSeed;

    /// Property: [`safe_sign_attached`] and [`safe_sign_attached_open`] form a bijection.
    #[test]
    fn prop_box_bijection() {
        proptest!(|(seed: SecureSeed, message: Box<UnsignedMessage>)| {
            check(seed.into(),  message)?;
        });

        fn check(seed: SafeSecureSeed, unsigned_message: Box<UnsignedMessage>) -> TestCaseResult {
            let (signer_pk, signer_sk) = safe_sign_keypair_seed(&seed);

            let signed_message = safe_sign_attached(&unsigned_message, &signer_sk);
            let verified_message = safe_sign_attached_open(&signed_message, &signer_pk)
                .expect("safe_sign_attached_open failed");

            prop_assert_eq!(verified_message, unsigned_message);

            Ok(())
        }
    }
}
