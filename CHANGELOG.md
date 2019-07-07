# 0.2.0

- `encode_byte` now returns `[u8; 2]` instead of `(u8, u8)`, as in practice this
  tends to be more convenient.

- The use of `std` which requires the `alloc` trait has been split into the
  `alloc` feature.

