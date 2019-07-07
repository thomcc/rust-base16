# 0.2.0

- `encode_byte` now returns `[u8; 2]` instead of `(u8, u8)`, as in practice this
  tends to be more convenient.

- The use of `std` which requires the `alloc` trait has been split into the
  `alloc` feature.

- `base16` has been relicensed as CC0-1.0 from dual MIT/Apache-2.0.
