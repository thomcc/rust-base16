#![feature(test)]

extern crate base16;
extern crate rand;
extern crate test;

use rand::Rng;

#[inline]
fn rand_enc_cfg<R: rand::Rng>(rng: &mut R) -> base16::EncConfig {
    if rng.gen::<bool>() {
        base16::EncodeUpper
    } else {
        base16::EncodeLower
    }
}

fn do_bench_encode_to_string(b: &mut test::Bencher, sz: usize, testfn: fn(&[u8], base16::EncConfig) -> String) {
    b.bytes = sz as u64;
    let mut bytes = vec![0u8; sz];
    let mut r = rand::weak_rng();
    r.fill_bytes(&mut bytes);
    let cfg = rand_enc_cfg(&mut r);
    b.iter(|| {
        let result = testfn(test::black_box(&bytes),
                            test::black_box(cfg));
        test::black_box(result)
    });
}

fn do_bench_encode_buf(b: &mut test::Bencher,
                       sz: usize,
                       testfn: fn(&[u8], base16::EncConfig, &mut String) -> usize)
{
    b.bytes = sz as u64;
    let mut bytes = vec![0u8; sz];
    let mut r = rand::weak_rng();
    r.fill_bytes(&mut bytes);
    let cfg = rand_enc_cfg(&mut r);
    let mut buf = String::with_capacity(2 * sz);
    b.iter(|| {
        buf.truncate(0);
        let result = testfn(test::black_box(&bytes),
                            test::black_box(cfg),
                            test::black_box(&mut buf));
        test::black_box(result);
    });
}

fn do_bench_encode_slice(b: &mut test::Bencher,
                         sz: usize,
                         testfn: fn(&[u8], base16::EncConfig, &mut [u8]) -> usize)
{
    b.bytes = sz as u64;
    let mut bytes = vec![0u8; sz];
    let mut r = rand::weak_rng();
    r.fill_bytes(&mut bytes);
    let cfg = rand_enc_cfg(&mut r);
    let mut buf = vec![0u8; 2 * sz];
    b.iter(|| {
        let result = testfn(test::black_box(&bytes),
                            test::black_box(cfg),
                            test::black_box(&mut buf));
        test::black_box(result)
    });
}

#[bench] fn bench_enc_str_tiny(b: &mut test::Bencher) { do_bench_encode_to_string(b, 3, base16::encode_config) }
#[bench] fn bench_enc_str_small(b: &mut test::Bencher) { do_bench_encode_to_string(b, 16, base16::encode_config) }
#[bench] fn bench_enc_str_medium(b: &mut test::Bencher) { do_bench_encode_to_string(b, 1024, base16::encode_config) }
#[bench] fn bench_enc_str_big(b: &mut test::Bencher) { do_bench_encode_to_string(b, 1024*1024, base16::encode_config) }

#[bench] fn bench_enc_buf_tiny(b: &mut test::Bencher) { do_bench_encode_buf(b, 3, base16::encode_config_buf) }
#[bench] fn bench_enc_buf_small(b: &mut test::Bencher) { do_bench_encode_buf(b, 16, base16::encode_config_buf) }
#[bench] fn bench_enc_buf_medium(b: &mut test::Bencher) { do_bench_encode_buf(b, 1024, base16::encode_config_buf) }
#[bench] fn bench_enc_buf_big(b: &mut test::Bencher) { do_bench_encode_buf(b, 1024*1024, base16::encode_config_buf) }

#[bench] fn bench_enc_slice_tiny(b: &mut test::Bencher) { do_bench_encode_slice(b, 3, base16::encode_config_slice) }
#[bench] fn bench_enc_slice_small(b: &mut test::Bencher) { do_bench_encode_slice(b, 16, base16::encode_config_slice) }
#[bench] fn bench_enc_slice_medium(b: &mut test::Bencher) { do_bench_encode_slice(b, 1024, base16::encode_config_slice) }
#[bench] fn bench_enc_slice_big(b: &mut test::Bencher) { do_bench_encode_slice(b, 1024*1024, base16::encode_config_slice) }
