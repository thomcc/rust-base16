
#[macro_use]
extern crate afl;

fn main() {
    fuzz!(|data: &[u8]| {
        // Likely invalid.
        let _ = base16::decode(data);
    });
}
