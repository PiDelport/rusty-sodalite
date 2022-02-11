//!
//! # External documentation
//!
//! - https://tweetnacl.cr.yp.to/
//! - https://nacl.cr.yp.to/

#![no_std]

extern crate alloc;

pub mod padding_constants;
pub mod safe_box;
pub mod safe_secretbox;
pub mod safe_sign;
pub mod types;

pub(crate) mod macros;
pub(crate) mod padding_helpers;
