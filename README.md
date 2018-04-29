# base16 (hex) encoding for Rust.

This is a base16 (e.g. hexadecimal) encoding and decoding library with an emphasis on performance. At the time of this writing, it's faster than the competitors that I could find.

It provides a few variants which will allow you to completly control it's allocation behavior (encode/decode into slice, encode/decode into buffer growing as needed, etc).

