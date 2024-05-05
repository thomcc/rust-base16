#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if !data.is_empty() {
        let cfg = if (data[0] & 1) == 0 {
            base16::EncodeLower
        } else {
            base16::EncodeUpper
        };
        let data = &data[1..];
        let enc = base16::encode_config(data, cfg);
        let dec = base16::decode(&enc).unwrap();
        assert_eq!(data, dec.as_slice());
    }
});
