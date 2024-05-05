# [base16](https://crates.io/crates/base16) (hex) encoding for Rust.

[![Docs](https://docs.rs/base16/badge.svg)](https://docs.rs/base16)
[![codecov](https://codecov.io/gh/thomcc/rust-base16/branch/master/graph/badge.svg)](https://codecov.io/gh/thomcc/rust-base16)

This is a base16 (e.g. hexadecimal) encoding and decoding library which was initially written with an emphasis on performance.

The bulk of this was written before Rust added SIMD, and I haven't gotten around to adding that. When I wrote it, it was the fastest non-SIMD impl, but I haven't done any comparison recently.

## Usage

Add `base16 = "0.2"` to Cargo.toml, then:

```rust
fn main() {
    let original_msg = "Foobar";
    let hex_string = base16::encode_lower(original_msg);
    assert_eq!(hex_string, "466f6f626172");
    let decoded = base16::decode(&hex_string).unwrap();
    assert_eq!(String::from_utf8(decoded).unwrap(), original_msg);
}
```

More usage examples in the [docs](https://docs.rs/base16).

## `no_std` Usage

This crate supports use in `no_std` configurations using the following knobs.

- The `"alloc"` feature, which is on by default, adds a number of helpful functions
  that require use of the [`alloc`](https://doc.rust-lang.org/alloc/index.html) crate,
  but not the rest of `std`. This is `no_std` compatible.
    - Each function documents if it requires use of the `alloc` feature.
- The `"std"` feature, which is not on by default, enables the `"alloc"` feature, and
  additionally makes `base16::DecodeError` implement the `std::error::Error` trait.

For clarity, this means that by default, we assume you are okay with use of the global allocator. This can be disabled as follows:

```toml
[dependencies]
base16 = { version = "0.2", default-features = false }
```

If you just want the core `base16` functionality and none of the helpers, then
you should turn off all features.

```toml
[dependencies]
# Turn of use of `std` and `alloc`.
base16 = { version = "0.2", default-features = false }
```

Both of these configurations are `no_std` compatible.

# License

Public domain, as explained by [the Unlicense](./UNLICENSE). Alternatively, you can use either of the typical rusty MIT/Apache-2.0 combination.
