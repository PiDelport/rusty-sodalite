//! Padding-related constants for the C NaCl API.
//!
//! Values referenced from: <https://tweetnacl.cr.yp.to/20140427/tweetnacl.h>
//!
//! TODO: sodalite should expose these padding constants?

/// Amount of zero padding needed for `crypto_box` plaintext.
pub const BOX_ZEROBYTES: usize = 32;

/// Amount of zero padding needed for `crypto_box` ciphertext.
pub const BOX_BOXZEROBYTES: usize = 16;

/// Amount of zero padding needed for `crypto_secretbox` plaintext.
pub const SECRETBOX_ZEROBYTES: usize = 32;

/// Amount of zero padding needed for `crypto_secretbox` ciphertext.
pub const SECRETBOX_BOXZEROBYTES: usize = 16;
