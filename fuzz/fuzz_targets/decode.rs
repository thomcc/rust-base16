#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate base16;

fuzz_target!(|data: &[u8]| {
    // Likely invalid.
    let _ = base16::decode(data);
});
