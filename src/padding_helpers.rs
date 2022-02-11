//! Helpers for handling the zero padding required by the low-level NaCl API.

use alloc::boxed::Box;
use alloc::vec;

/// Add a prefix of `size` zeroes to an unpadded value.
pub(crate) fn pad_zeroes(size: usize, unpadded: impl AsRef<[u8]>) -> Box<[u8]> {
    let padding = vec![0; size];
    [padding.as_ref(), unpadded.as_ref()]
        .concat()
        .into_boxed_slice()
}

/// Check and remove a prefix of `size` zeroes from a padded value.
///
/// Return `None` if `size` exceeds the length of `padded`,
/// or if the padding contains any non-zero bytes.
pub(crate) fn unpad_zeroes(size: usize, padded: impl AsRef<[u8]>) -> Option<Box<[u8]>> {
    let padded = padded.as_ref();
    if size <= padded.len() {
        // Safety: split_at requires size <= padded.len()
        let (padding, unpadded) = padded.split_at(size);
        if padding.iter().all(|&b| b == 0) {
            Some(Box::from(unpadded))
        } else {
            None // padding is not all zeroes
        }
    } else {
        None // padding size exceeds padded message size
    }
}

#[cfg(test)]
mod tests {
    use alloc::format; // required by proptest macros

    use proptest::prelude::*;
    use proptest::test_runner::TestCaseResult;

    use super::*;

    /// The maximum padding size to test.
    const MAX_PADDING_SIZE: usize = 10_000;

    /// Property: [`pad_zeroes`] with zero-sized padding is an identity function.
    #[test]
    fn prop_add_prefix_identity() {
        proptest!(|(value: Box<[u8]>)| {
            prop_assert_eq!(pad_zeroes(0, &value), value);
        });
    }

    /// Property: [`unpad_zeroes`] with zero-sized padding is an identity function.
    #[test]
    fn prop_remove_prefix_identity() {
        proptest!(|(value: Box<[u8]>)| {
            prop_assert_eq!(unpad_zeroes(0, &value), Some(value));
        });
    }

    /// Property: [`pad_zeroes`] adds padding with the correct size and content.
    #[test]
    fn prop_add_prefix_size_content() {
        proptest!(|(size in 0..MAX_PADDING_SIZE, value: Box<[u8]>)| {
            check(size, &value)?;
        });

        fn check(size: usize, value: &[u8]) -> TestCaseResult {
            let padded = pad_zeroes(size, value);
            prop_assert_eq!(padded.len(), value.len() + size);
            let expected_padding = vec![0; size];
            prop_assert_eq!(padded.split_at(size), (expected_padding.as_slice(), value));
            Ok(())
        }
    }

    /// Property: [`pad_zeroes`] and [`unpad_zeroes`] form a bijection.
    #[test]
    fn prop_add_remove_prefix_bijection() {
        proptest!(|(size in 0..MAX_PADDING_SIZE, value: Box<[u8]>)| {
            check(size, value)?;
        });

        fn check(size: usize, value: Box<[u8]>) -> TestCaseResult {
            let padded = pad_zeroes(size, &value);
            let unpadded = unpad_zeroes(size, padded);
            prop_assert_eq!(unpadded, Some(value));
            Ok(())
        }
    }

    /// Property: [`unpad_zeroes`] fails if the padding size exceeds the value size.
    #[test]
    fn prop_remove_prefix_invalid_size() {
        proptest!(|(size in 1..MAX_PADDING_SIZE, value: Box<[u8]>)| {
            let too_big = value.len() + size;
            prop_assert_eq!(unpad_zeroes(too_big, &value), None);
        });
    }

    /// Property: [`unpad_zeroes`] fails if the padding isn't zero.
    #[test]
    fn prop_remove_prefix_nonzero_padding() {
        proptest!(|(invalid_padding: Box<[u8]>, value: Box<[u8]>)| {
            // Invalid padding contains at least one non-zero byte.
            prop_assume!(invalid_padding.iter().any(|&byte| byte != 0));
            check(&invalid_padding, &value)?;
        });

        fn check(invalid_padding: &[u8], value: &[u8]) -> TestCaseResult {
            let invalid_padded = [invalid_padding, value].concat();
            prop_assert_eq!(unpad_zeroes(invalid_padding.len(), &invalid_padded), None);
            Ok(())
        }
    }
}
