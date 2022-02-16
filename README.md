# Rusty Sodalite

Rusty Sodalite wraps the [Sodalite] Rust source port of [TweetNaCl] with a [Sodium]-style API.

[Sodalite]: https://crates.io/crates/sodalite
[TweetNaCl]: https://tweetnacl.cr.yp.to/
[Sodium]: https://doc.libsodium.org/

## Features

✨ **Small, pure Rust, `no_std`**

Like [Sodalite], Rusty Sodalite uses no C code or FFI bindings, and does not depend on `std`.
making it suitable for constrained and embedded targets.

✨ **Interoperable with TweetNaCl**

Rusty Sodalite interoperates with [TweetNaCl], and ports such as [TweetNaCl.js].

[TweetNaCl.js]: https://tweetnacl.js.org/

✨ **Ergonomic and safe**

Rusty Sodalite's provides an API that leverages Rust for safety and ease of use.

## Related work

### NaCl compatible

📦 [nacl-compat](https://github.com/RustCrypto/nacl-compat)
provides some limited NaCl compatibility based on the RustCrypto libraries.

📦 [dryoc](https://github.com/brndnmtthws/dryoc)
provides a rich implementation the Sodium API in pure Rust.

🚧 (Unmaintained) [knuckle](https://github.com/erik/knuckle)
provides Rust bindings to TweetNaCl.

🚧 (Unmaintained) [microsalt](https://github.com/goldenMetteyya/microsalt)
is a rough Rust source port of TweetNaCl, referencing rust_sodium, Sodalite, and Knuckle.

### Sodium bindings

📦 [alkali](https://github.com/tom25519/alkali)
follows sodiumoxide to provide Rust bindings to Sodium.

🚧 (Unmaintained) [sodiumoxide](https://github.com/sodiumoxide/sodiumoxide)
(also forked as 🚧 [rust_sodium](https://github.com/maidsafe/rust_sodium))
provides Rust bindings to Sodium.

🚧 (Unmaintained) [monosodium](https://github.com/peterhj/monosodium)
provides plain, C-style Rust bindings to Sodium.

### Not NaCl compatible

📦 [salty](https://github.com/ycrypto/salty)
mashes up TweetNaCl with ed25519-dalek for microcontroller use cases.

📦 [Orion](https://github.com/orion-rs/orion)
provides pure Rust implementations of NaCl-like functionality.

📦 [monocypher](https://monocypher.org/)
(Rust bindings: [monocypher-rs](https://github.com/jan-schreib/monocypher-rs))
follows TweetNaCl as a simple, compact C implementation.
