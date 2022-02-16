//! Secret-key authenticated encryption using the `crypto_secretbox` API.
//!
//! # Security model
//!
//! From <https://nacl.cr.yp.to/secretbox.html>:
//!
//! ## Nonce requirements
//!
//! > It is the caller's responsibility to ensure the uniqueness of nonces—for example,
//! > by using nonce 1 for the first message, nonce 2 for the second message, etc.
//! > Nonces are long enough that randomly generated nonces have negligible risk of collision.
//!
//! ## Message lengths
//!
//! > See [Validation] regarding safe message lengths.
//!
//! [Validation]: https://nacl.cr.yp.to/valid.html
use alloc::boxed::Box;
use alloc::vec;
use core::option::Option;

use crate::macros::newtype_wrapper;
use crate::padding_constants;
use crate::padding_helpers::{pad_zeroes, unpad_zeroes};
use crate::types::{Ciphertext, Plaintext};

newtype_wrapper!(SafeSecretboxKey, sodalite::SecretboxKey);
newtype_wrapper!(SafeSecretboxNonce, sodalite::SecretboxNonce);

/// Encrypt and authenticate a message using `key`.
///
/// This wraps [`sodalite::secretbox`].
pub fn safe_secretbox(
    plaintext: &Plaintext,
    nonce: &SafeSecretboxNonce,
    key: &SafeSecretboxKey,
) -> Box<Ciphertext> {
    // Pad plaintext for input to `crypto_secretbox`.
    //
    // <https://nacl.cr.yp.to/secretbox.html>:
    // > The caller must ensure, before calling the C NaCl `crypto_secretbox` function,
    // > that the first `crypto_secretbox_ZEROBYTES` bytes of the message m are all 0.
    let padded_plaintext = pad_zeroes(padding_constants::SECRETBOX_ZEROBYTES, plaintext);

    // Precondition: Output buffer size must match input buffer
    let mut padded_ciphertext = vec![0_u8; padded_plaintext.len()];

    sodalite::secretbox(
        &mut padded_ciphertext,
        &padded_plaintext,
        nonce.as_ref(),
        key.as_ref(),
    )
    // Safety: This should be infallible.
    .expect("safe_secretbox: secretbox failed!");

    // Unpad ciphertext output of `crypto_secretbox`.
    //
    // <https://nacl.cr.yp.to/secretbox.html>:
    // > The `crypto_secretbox` function ensures that the first `crypto_secretbox_BOXZEROBYTES`
    // > bytes of the ciphertext c are all 0.
    unpad_zeroes(padding_constants::SECRETBOX_BOXZEROBYTES, padded_ciphertext)
        // Safety: This should be infallible.
        .expect("safe_secretbox: unpad_zeroes failed!")
}

/// Decrypt and verify a message using `key`.
///
/// This wraps [`sodalite::secretbox_open`].
pub fn safe_secretbox_open(
    ciphertext: &Ciphertext,
    nonce: &SafeSecretboxNonce,
    key: &SafeSecretboxKey,
) -> Option<Box<Plaintext>> {
    // Pad ciphertext for input to `crypto_secretbox_open`.
    //
    // <https://nacl.cr.yp.to/box.html>:
    // > The caller must ensure, before calling the `crypto_secretbox_open` function,
    // > that the first `crypto_secretbox_BOXZEROBYTES` bytes of the ciphertext c are all 0.
    let padded_ciphertext = pad_zeroes(padding_constants::BOX_BOXZEROBYTES, ciphertext);

    // Precondition: Output buffer size must match input buffer
    let mut padded_plaintext = vec![0_u8; padded_ciphertext.len()];

    sodalite::secretbox_open(
        &mut padded_plaintext,
        &padded_ciphertext,
        nonce.as_ref(),
        key.as_ref(),
    )
    .ok()?;

    // Unpad plaintext output of `crypto_secretbox_open`.
    //
    // <https://nacl.cr.yp.to/box.html>:
    // > The `crypto_secretbox_open` function ensures (in case of success) that the first
    // > `crypto_secretbox_ZEROBYTES` bytes of the plaintext m are all 0.
    unpad_zeroes(padding_constants::BOX_ZEROBYTES, padded_plaintext)
}

#[cfg(test)]
mod tests {
    use alloc::format; // required by proptest macros

    use proptest::prelude::*;
    use proptest::test_runner::TestCaseResult;
    use sodalite::{SecretboxKey, SecretboxNonce};

    use super::*;

    /// Property: [`safe_secretbox`] and [`safe_secretbox_open`] form a bijection.
    #[test]
    fn prop_secretbox_bijection() {
        proptest!(|(key: SecretboxKey, nonce: SecretboxNonce, message: Box<Plaintext>)| {
            check(key.into(), nonce.into(), message)?;
        });

        fn check(
            key: SafeSecretboxKey,
            nonce: SafeSecretboxNonce,
            message: Box<Plaintext>,
        ) -> TestCaseResult {
            let ciphertext = safe_secretbox(&message, &nonce, &key);
            let plaintext =
                safe_secretbox_open(&ciphertext, &nonce, &key).expect("safe_secretbox_open failed");

            prop_assert_eq!(plaintext, message);

            Ok(())
        }
    }
}
