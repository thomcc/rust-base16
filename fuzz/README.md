# Running fuzz tests

```sh
cargo install cargo-fuzz
# fuzz `decode`
cargo fuzz run decode
# fuzz `encode`
cargo fuzz run encode
```
