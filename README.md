# [base16](https://crates.io/crates/base16) (hex) encoding for Rust.

[![Docs](https://docs.rs/base16/badge.svg)](https://docs.rs/base16)

This is a base16 (e.g. hexadecimal) encoding and decoding library which was initially written with an emphasis on performance.

This was before Rust added SIMD, and I haven't gotten around to adding that. It's still probably the fastest non-SIMD impl, but that doesn't say much.

## Usage

Add `base16 = "0.1"` to Cargo.toml, then:

```rust
extern crate base16;

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

As of 0.1.2, this crate by default has the `std` feature enabled, however, it
may be turned off, allowing it to be used in no_std envionments. Not all
functions are available without the stdlib, but each function should document whether or not it is.

# License

Dual MIT/Apache2 (whichever you prefer) since that seems hip for Rust code.
