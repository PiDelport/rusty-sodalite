//! Public-key authenticated encryption using the `crypto_box` API.
//!
//! # Security model
//!
//! From <https://nacl.cr.yp.to/box.html>:
//!
//! ## Nonce requirements
//!
//! > Distinct messages between the same {sender, receiver} set are required to have distinct
//! > nonces. For example, the lexicographically smaller public key can use nonce 1 for its first
//! > message to the other key, nonce 3 for its second message, nonce 5 for its third message,
//! > etc., while the lexicographically larger public key uses nonce 2 for its first message to the
//! > other key, nonce 4 for its second message, nonce 6 for its third message, etc. Nonces are
//! > long enough that randomly generated nonces have negligible risk of collision.
//! >
//! > There is no harm in having the same nonce for different messages if the {sender, receiver}
//! > sets are different. This is true even if the sets overlap. For example, a sender can use the
//! > same nonce for two different messages if the messages are sent to two different public keys.
//!
//! ## Non-repudiation
//!
//! > The `crypto_box` function is not meant to provide non-repudiation. On the contrary: the
//! > `crypto_box` function _guarantees_ repudiability. A receiver can freely modify a boxed
//! > message, and therefore cannot convince third parties that this particular message came from
//! > the sender. The sender and receiver are nevertheless protected against forgeries by other
//! > parties. In the terminology of
//! > <https://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c>, `crypto_box` uses
//! > "public-key authenticators" rather than "public-key signatures."
//! >
//! > Users who want public verifiability (or receiver-assisted public verifiability) should
//! > instead use signatures (or signcryption). Signature support is a high priority for NaCl; a
//! > signature API will be described in subsequent NaCl documentation.
//!
//! ## Message lengths
//!
//! > See [Validation] regarding safe message lengths.
//!
//! [Validation]: https://nacl.cr.yp.to/valid.html
use alloc::boxed::Box;
use alloc::vec;
use core::option::Option;

use sodalite::{BoxPublicKey, BoxSecretKey};

use crate::macros::type_wrapper;
use crate::padding_constants;
use crate::padding_helpers::{pad_zeroes, unpad_zeroes};
use crate::types::{Ciphertext, Plaintext, SafeSecureSeed};

type_wrapper!(SafeBoxPublicKey, sodalite::BoxPublicKey);
type_wrapper!(SafeBoxSecretKey, sodalite::BoxSecretKey);
type_wrapper!(SafeBoxNonce, sodalite::BoxNonce);

/// Generate a new random secret key and corresponding public key.
#[cfg(feature = "rand")]
pub fn safe_box_keypair() -> (SafeBoxPublicKey, SafeBoxSecretKey) {
    let mut public_key = BoxPublicKey::default();
    let mut secret_key = BoxSecretKey::default();
    sodalite::box_keypair(&mut public_key, &mut secret_key);
    (public_key.into(), secret_key.into())
}

/// Derive a secret key and corresponding public key for the given seed.
pub fn safe_box_keypair_seed(seed: &SafeSecureSeed) -> (SafeBoxPublicKey, SafeBoxSecretKey) {
    let mut public_key = BoxPublicKey::default();
    let mut secret_key = BoxSecretKey::default();
    sodalite::box_keypair_seed(&mut public_key, &mut secret_key, seed.as_ref());
    (public_key.into(), secret_key.into())
}

/// Encrypt and authenticate a message from `secret_key` to `public_key`.
///
/// This wraps [`sodalite::box_`].
pub fn safe_box(
    plaintext: &Plaintext,
    nonce: &SafeBoxNonce,
    public_key: &SafeBoxPublicKey,
    secret_key: &SafeBoxSecretKey,
) -> Box<Ciphertext> {
    // Pad plaintext for input to `crypto_box`.
    //
    // <https://nacl.cr.yp.to/box.html>:
    // > The caller must ensure, before calling the C NaCl `crypto_box` function,
    // > that the first `crypto_box_ZEROBYTES` bytes of the message m are all 0.
    let padded_plaintext = pad_zeroes(padding_constants::BOX_ZEROBYTES, plaintext);

    // Precondition: Output buffer size must match input buffer
    let mut padded_ciphertext = vec![0_u8; padded_plaintext.len()];

    sodalite::box_(
        &mut padded_ciphertext,
        &padded_plaintext,
        nonce.as_ref(),
        public_key.as_ref(),
        secret_key.as_ref(),
    )
    // Safety: This should be infallible.
    .expect("safe_box: box_ failed!");

    // Unpad ciphertext output of `crypto_box`.
    //
    // <https://nacl.cr.yp.to/box.html>:
    // > The `crypto_box` function ensures that the first `crypto_box_BOXZEROBYTES` bytes
    // > of the ciphertext c are all 0.
    unpad_zeroes(padding_constants::BOX_BOXZEROBYTES, padded_ciphertext)
        // Safety: This should be infallible.
        .expect("safe_box: unpad_zeroes failed!")
}

/// Decrypt and verify a message from `public_key` to `secret_key`.
///
/// This wraps [`sodalite::box_open`].
pub fn safe_box_open(
    ciphertext: &Ciphertext,
    nonce: &SafeBoxNonce,
    public_key: &SafeBoxPublicKey,
    secret_key: &SafeBoxSecretKey,
) -> Option<Box<Plaintext>> {
    // Pad ciphertext for input to `crypto_box_open`.
    //
    // <https://nacl.cr.yp.to/box.html>:
    // > The caller must ensure, before calling the `crypto_box_open` function,
    // > that the first `crypto_box_BOXZEROBYTES` bytes of the ciphertext c are all 0.
    let padded_ciphertext = pad_zeroes(padding_constants::BOX_BOXZEROBYTES, ciphertext);

    // Precondition: Output buffer size must match input buffer
    let mut padded_plaintext = vec![0_u8; padded_ciphertext.len()];

    sodalite::box_open(
        &mut padded_plaintext,
        &padded_ciphertext,
        nonce.as_ref(),
        public_key.as_ref(),
        secret_key.as_ref(),
    )
    .ok()?;

    // Unpad plaintext output of `crypto_box_open`.
    //
    // <https://nacl.cr.yp.to/box.html>:
    // > The `crypto_box_open` function ensures (in case of success) that the first
    // > `crypto_box_ZEROBYTES` bytes of the plaintext m are all 0.
    unpad_zeroes(padding_constants::BOX_ZEROBYTES, padded_plaintext)
}

#[cfg(test)]
mod tests {
    use alloc::format; // required by proptest macros

    use proptest::prelude::*;
    use proptest::test_runner::TestCaseResult;
    use sodalite::BoxNonce;

    use super::*;
    use crate::types::{Plaintext, SecureSeed};

    /// Property: [`safe_box`] and [`safe_box_open`] form a bijection.
    #[test]
    fn prop_box_bijection() {
        proptest!(|(our_seed: SecureSeed, their_seed: SecureSeed, nonce: BoxNonce, message: Box<Plaintext>)| {
            prop_assume!(our_seed != their_seed);
            check(our_seed.into(), their_seed.into(), nonce.into(), message)?;
        });

        fn check(
            sender_seed: SafeSecureSeed,
            receiver_seed: SafeSecureSeed,
            nonce: SafeBoxNonce,
            message: Box<Plaintext>,
        ) -> TestCaseResult {
            let (sender_pk, sender_sk) = safe_box_keypair_seed(&sender_seed);
            let (receiver_pk, receiver_sk) = safe_box_keypair_seed(&receiver_seed);

            let ciphertext = safe_box(&message, &nonce, &receiver_pk, &sender_sk);
            let plaintext = safe_box_open(&ciphertext, &nonce, &sender_pk, &receiver_sk)
                .expect("safe_box_open failed");

            prop_assert_eq!(plaintext, message);

            Ok(())
        }
    }
}
