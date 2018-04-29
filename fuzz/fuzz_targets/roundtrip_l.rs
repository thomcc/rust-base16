#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate base16;

fuzz_target!(|data: &[u8]| {
    let enc = base16::encode_lower(data);
    let dec = base16::decode(&enc).unwrap();
    assert_eq!(data, dec.as_slice());
});
