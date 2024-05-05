use divan::*;

fn rand_enc_input(sz: usize) -> (Vec<u8>, base16::EncConfig) {
    use rand::prelude::*;
    let mut rng = thread_rng();
    let mut vec = vec![0u8; sz];
    let cfg = if rng.gen::<bool>() {
        base16::EncodeUpper
    } else {
        base16::EncodeLower
    };
    rng.fill_bytes(&mut vec);
    (vec, cfg)
}

fn rand_hex_string(size: usize) -> String {
    use rand::prelude::*;
    let mut rng = thread_rng();
    let mut s = String::with_capacity(size);
    let chars: &[u8] = b"0123456789abcdefABCDEF";
    while s.len() < size {
        s.push(*chars.choose(&mut rng).unwrap() as char);
    }
    s
}
const SIZES: &[usize] = &[3, 16, 64, 256, 1024];

#[divan::bench(args = SIZES)]
fn bench_decode(bencher: Bencher, len: usize) {
    bencher
        .counter(len * 2)
        .with_inputs(|| rand_hex_string(len * 2))
        .bench_values(|inp| base16::decode(&inp));
}

#[divan::bench(args = SIZES)]
fn bench_encode(bencher: Bencher, len: usize) {
    bencher
        .counter(len)
        .with_inputs(|| rand_enc_input(len))
        .bench_values(|(inp, c)| base16::encode_config(&inp, c));
}

#[divan::bench(args = SIZES)]
fn bench_decode_buf(bencher: Bencher, len: usize) {
    bencher
        .counter(len * 2)
        .with_inputs(|| (rand_hex_string(len * 2), Vec::<u8>::with_capacity(len)))
        .bench_values(|(inp, mut buf)| {
            let r = base16::decode_buf(&inp, &mut buf);
            divan::black_box(buf.as_mut_ptr());
            r
        });
}

#[divan::bench(args = SIZES)]
fn bench_encode_buf(bencher: Bencher, len: usize) {
    bencher
        .counter(len)
        .with_inputs(|| (rand_enc_input(len), String::with_capacity(len * 2)))
        .bench_values(|((inp, c), mut buf)| {
            let r = base16::encode_config_buf(&inp, c, &mut buf);
            divan::black_box(buf.as_mut_ptr());
            r
        });
}

#[divan::bench(args = SIZES)]
fn bench_decode_slice(bencher: Bencher, len: usize) {
    bencher
        .counter(len * 2)
        .with_inputs(|| (rand_hex_string(len * 2), vec![0u8; len]))
        .bench_values(|(inp, mut buf)| {
            let r = base16::decode_slice(&inp, &mut buf[..]);
            divan::black_box(buf.as_mut_ptr());
            r
        });
}

#[divan::bench(args = SIZES)]
fn bench_encode_slice(bencher: Bencher, len: usize) {
    bencher
        .counter(len)
        .with_inputs(|| (rand_enc_input(len), vec![0u8; len * 2]))
        .bench_values(|((inp, c), mut buf)| {
            let r = base16::encode_config_slice(&inp, c, &mut buf);
            divan::black_box(buf.as_mut_ptr());
            r
        });
}

fn main() {
    divan::main();
}
