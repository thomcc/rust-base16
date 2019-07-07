# Running fuzz tests

```sh
cargo install afl
cargo afl build
# fuzz `decode`
cargo afl fuzz -i in -o out target/debug/decode
# fuzz `encode`
cargo afl fuzz -i in -o out target/debug/encode
```
