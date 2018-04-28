//! This is a base16 (e.g. hexadecimal) encoding and decoding library with
//! an emphasis on performance. The API is very similar and inspired by
//! the base64 crate's API, however it's less complex (base16 is much more
//! simple than base64).
//!
//! # Encoding
//!
//! The config options at the moment are limited to the output case (upper vs
//! lower).
//!
//! | Function                       | Output                       | Allocates               |
//! | ------------------------------ | ---------------------------- | ----------------------- |
//! | `encode_upper`, `encode_lower` | Returns a new `String`       | Always                  |
//! | `encode_config`                | Returns a new `String`       | Always                  |
//! | `encode_config_buf`            | Appends to provided `String` | If buffer needs to grow |
//! | `encode_config_slice`          | Writes to provided `&[u8]`   | Never                   |
//!
//! # Decoding
//!
//! Note that there are no config options (In the future one might be added
//! to restrict the input character set, but it's not clear to me that this is
//! useful).
//!
//! | Function        | Output                        | Allocates               |
//! | --------------- | ----------------------------- | ----------------------- |
//! | `decode`        | Returns a new `Vec<u8>`       | Always                  |
//! | `decode_buf`    | Appends to provided `Vec<u8>` | If buffer needs to grow |
//! | `decode_slice`  | Writes to provided `&[u8]`    | Never                   |
//!

#![deny(missing_docs)]

use std::{mem, fmt, error};

/// Configuration options for encoding. Just specifies whether or not output
/// should be uppercase or lowercase.
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EncConfig {
    /// Encode using lower case characters for hex values >= 10
    EncodeLower = b'a',
    /// Encode using upper case characters for hex values >= 10
    EncodeUpper = b'A',
}

pub use EncConfig::*;

#[inline(always)]
fn encoded_size(source_len: usize) -> usize {
    const USIZE_TOP_BIT: usize = 1usize << (mem::size_of::<usize>() * 8 - 1);
    assert!((source_len & USIZE_TOP_BIT) == 0,
            "usize overflow when computing size of destination ({} < {})");
    source_len << 1
}

// Unsafe since it doesn't check dst's size in release builds.
#[inline(always)]
unsafe fn encode_slice(src: &[u8], cfg: EncConfig, dst: &mut [u8]) {
    static HEX_UPPER: &'static [u8] = b"0123456789ABCDEF";
    static HEX_LOWER: &'static [u8] = b"0123456789abcdef";
    let lut = if cfg == EncodeLower { HEX_LOWER } else { HEX_UPPER };
    debug_assert!(dst.len() == encoded_size(src.len()));
    let mut i = 0;
    for &byte in src.iter() {
        let x = byte >> 4;
        let y = byte & 0xf;
        let b0 = *lut.get_unchecked(x as usize);// if x < 10 { b'0' + x } else { (cfg as u8) + (x - 10) };
        let b1 = *lut.get_unchecked(y as usize);// if y < 10 { b'0' + y } else { (cfg as u8) + (y - 10) };
        *dst.get_unchecked_mut(i + 0) = b0;
        *dst.get_unchecked_mut(i + 1) = b1;
        i += 2;
    }
}

#[inline(always)]
fn encode_to_string(bytes: &[u8], cfg: EncConfig) -> String {
    let size = encoded_size(bytes.len());
    let mut result = String::with_capacity(size);
    unsafe {
        let mut buf = result.as_mut_vec();
        buf.set_len(size);
        encode_slice(bytes, cfg, &mut buf);
    }
    result
}

#[inline(always)]
unsafe fn grow_vec_uninitialized(v: &mut Vec<u8>, grow_by: usize) {
    v.reserve(grow_by);
    let new_len = v.len() + grow_by;
    debug_assert!(new_len <= v.capacity());
    v.set_len(new_len);
}

/// Encode bytes as base16, using lower case characters for nibbles between
/// 10 and 15 (`a` through `f`).
///
/// This is equivalent to `base16::encode_config(bytes, base16::EncodeUpper)`.
///
/// # Example
///
/// ```
/// assert_eq!(base16::encode_lower(b"Hello World"), "48656c6c6f20576f726c64");
/// assert_eq!(base16::encode_lower(&[0xff, 0xcc, 0xaa]), "ffccaa");
/// ```
#[inline]
pub fn encode_lower<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    encode_to_string(input.as_ref(), EncodeLower)
}

/// Encode bytes as base16, using upper case characters for nibbles between
/// 10 and 15 (`A` through `F`).
///
/// This is equivalent to `base16::encode_config(bytes, base16::EncodeUpper)`.
///
/// # Example
///
/// ```
/// assert_eq!(base16::encode_upper(b"Hello World"), "48656C6C6F20576F726C64");
/// assert_eq!(base16::encode_upper(&[0xff, 0xcc, 0xaa]), "FFCCAA");
/// ```
#[inline]
pub fn encode_upper<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    encode_to_string(input.as_ref(), EncodeUpper)
}


/// Encode `input` into a string using the listed config. The resulting
/// string contains `input.len() * 2` bytes.
///
/// # Example
///
/// ```
/// let data = vec![1, 2, 3, 0xaa, 0xbb, 0xcc];
/// assert_eq!(base16::encode_config(&data, base16::EncodeLower), "010203aabbcc");
/// assert_eq!(base16::encode_config(&data, base16::EncodeUpper), "010203AABBCC");
/// ```
#[inline]
pub fn encode_config<T: ?Sized + AsRef<[u8]>>(input: &T, cfg: EncConfig) -> String {
    encode_to_string(input.as_ref(), cfg)
}

/// Encode `input` into the end of the provided buffer. Returns the number of
/// bytes that were written.
///
/// Only allocates when `dst.size() + (input.len() * 2) >= dst.capacity()`.
///
/// # Example
///
/// ```
/// let messages = &["Taako, ", "Merle, ", "Magnus"];
/// let mut buffer = String::new();
/// for msg in messages {
///     let bytes_written = base16::encode_config_buf(msg.as_bytes(),
///                                                   base16::EncodeUpper,
///                                                   &mut buffer);
///     assert_eq!(bytes_written, msg.len() * 2);
/// }
/// assert_eq!(buffer, "5461616B6F2C204D65726C652C204D61676E7573");
/// ```
#[inline]
pub fn encode_config_buf<T: ?Sized + AsRef<[u8]>>(input: &T,
                                                  cfg: EncConfig,
                                                  dst: &mut String) -> usize {
    let src = input.as_ref();
    let bytes_to_write = encoded_size(src.len());
    unsafe {
        let mut dst_bytes = dst.as_mut_vec();
        let cur_size = dst_bytes.len();
        grow_vec_uninitialized(&mut dst_bytes, bytes_to_write);
        encode_slice(src, cfg, &mut dst_bytes.get_unchecked_mut(cur_size..));
    }
    bytes_to_write
}

/// Write bytes as base16 into the provided output buffer. Never allocates.
///
/// This is useful if you wish to avoid allocation entirely (e.g. your
/// destination buffer is on the stack), or control it precisely.
///
/// # Panics
///
/// Panics if the desination buffer is insufficiently large.
///
/// # Example
///
/// ```
/// // Writing to a statically sized buffer on the stack.
/// let message = b"Wu-Tang Killa Bees";
/// let mut buffer = [0u8; 1024];
///
/// let wrote = base16::encode_config_slice(message,
///                                         base16::EncodeLower,
///                                         &mut buffer);
///
/// assert_eq!(message.len() * 2, wrote);
/// assert_eq!(String::from_utf8(buffer[..wrote].into()).unwrap(),
///            "57752d54616e67204b696c6c612042656573");
///
/// // Appending to an existing buffer is possible too.
/// let wrote2 = base16::encode_config_slice(b": The Swarm",
///                                          base16::EncodeLower,
///                                          &mut buffer[wrote..]);
/// let write_end = wrote + wrote2;
/// assert_eq!(String::from_utf8(buffer[..write_end].into()).unwrap(),
///            "57752d54616e67204b696c6c6120426565733a2054686520537761726d");
/// ```
#[inline]
pub fn encode_config_slice<T: ?Sized + AsRef<[u8]>>(input: &T,
                                                    cfg: EncConfig,
                                                    dst: &mut [u8]) -> usize {
    let src = input.as_ref();
    let need_size = encoded_size(src.len());
    assert!(dst.len() >= need_size,
            "Destination is not large enough to encode input: {} < {}",
            dst.len(), need_size);
    unsafe {
        encode_slice(src, cfg, dst.get_unchecked_mut(..need_size));
    }
    need_size
}

/// Represents a problem with the data we want to decode.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeError {
    /// An invalid byte was found in the input (bytes must be `[0-9a-fA-F]`)
    InvalidByte {
        /// The index at which the problematic byte was found.
        index: usize,
        /// The byte that we cannot decode.
        byte: u8
    },
    /// The length of the input not a multiple of two
    InvalidLength {
        /// The input length.
        length: usize
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecodeError::InvalidByte { index, byte } => {
                write!(f, "Invalid byte `b{:?}`, at index {}.",
                       byte as char, index)
            }
            DecodeError::InvalidLength { length } =>
                write!(f, "Base16 data cannot have length {} (must be even)",
                       length),
        }
    }
}

impl error::Error for DecodeError {
    fn description(&self) -> &str {
        match *self {
            DecodeError::InvalidByte { .. } => "Illegal byte in base16 data",
            DecodeError::InvalidLength { .. } => "Illegal length for base16 data",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

unsafe fn decode_slice_raw(src: &[u8], dst: &mut[u8]) -> Result<(), usize> {
    static LUT: [i8; 256] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,
         6,  7,  8,  9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1
    ];
    debug_assert!(src.len() / 2 == dst.len());
    debug_assert!((src.len() & 1) == 0);
    let mut si = 0;
    let mut di = 0;
    while si < src.len() {
        let s0 = *src.get_unchecked(si);
        let s1 = *src.get_unchecked(si + 1);
        let r0 = *LUT.get_unchecked(s0 as usize);
        let r1 = *LUT.get_unchecked(s1 as usize);
        if (r0 | r1) < 0 {
            return Err(if r0 < 0 { si } else { si + 1 });
        }
        *dst.get_unchecked_mut(di) = ((r0 << 4) | r1) as u8;
        si += 2;
        di += 1;
    }
    Ok(())
}

/// Decode bytes from base16, and return a new `Vec<u8>` containing the results.
///
/// # Example
///
/// ```
/// assert_eq!(base16::decode("48656c6c6f20576f726c64".as_bytes()).unwrap(),
///            b"Hello World".to_vec());
/// assert_eq!(base16::decode(b"deadBEEF").unwrap(),
///            vec![0xde, 0xad, 0xbe, 0xef]);
/// // Error cases:
/// assert_eq!(base16::decode(b"Not Hexadecimal!"),
///            Err(base16::DecodeError::InvalidByte { byte: b'N', index: 0 }));
/// assert_eq!(base16::decode(b"a"),
///            Err(base16::DecodeError::InvalidLength { length: 1 }));
/// ```
#[inline]
pub fn decode<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, DecodeError> {
    let src = input.as_ref();
    if (src.len() & 1) != 0 {
        return Err(DecodeError::InvalidLength { length: src.len() });
    }
    let need_size = src.len() >> 1;
    let mut dst = Vec::with_capacity(need_size);
    let res = unsafe {
        dst.set_len(need_size);
        decode_slice_raw(src, &mut dst)
    };
    match res {
        Ok(()) => Ok(dst),
        Err(index) => Err(DecodeError::InvalidByte { index, byte: src[index] })
    }
}


/// Decode bytes from base16, and appends into the provided buffer. Only
/// allocates if the buffer could not fit the data. Returns the number of bytes
/// written.
///
/// In the case of an error, the buffer should remain the same size.
///
/// # Example
///
/// ```
/// let mut result = Vec::new();
/// assert_eq!(base16::decode_buf(b"4d61646f6b61", &mut result).unwrap(), 6);
/// assert_eq!(base16::decode_buf(b"486F6D757261", &mut result).unwrap(), 6);
/// assert_eq!(String::from_utf8(result).unwrap(), "MadokaHomura");
/// ```
#[inline]
pub fn decode_buf<T: ?Sized + AsRef<[u8]>>(input: &T, v: &mut Vec<u8>) -> Result<usize, DecodeError> {
    let src = input.as_ref();
    if (src.len() & 1) != 0 {
        return Err(DecodeError::InvalidLength { length: src.len() });
    }
    let need_size = src.len() >> 1;
    let current_size = v.len();
    let res = unsafe {
        grow_vec_uninitialized(v, need_size);
        decode_slice_raw(src, &mut v[current_size..])
    };
    match res {
        Ok(()) => Ok(need_size),
        Err(index) => {
            v.truncate(current_size);
            Err(DecodeError::InvalidByte { index, byte: src[index] })
        }
    }
}

/// Decode bytes from base16, and write into the provided buffer. Never
/// allocates.
///
/// In the case of a decoder error, the output is not specified, but in practice
/// will remain untouched for an `InvalidLength` error, and will contain the
/// decoded input up to the problem byte in the case of an InvalidByte error.
///
/// # Panics
///
/// Panics if the provided buffer is not large enough for the input.
///
/// # Example
/// ```
/// let msg = "476f6f642072757374206c6962726172696573207573652073696c6c79206578616d706c6573";
/// let mut buf = [0u8; 1024];
/// assert_eq!(base16::decode_slice(&msg[..], &mut buf).unwrap(), 38);
/// assert_eq!(&buf[..38], b"Good rust libraries use silly examples".as_ref());
///
/// let msg2 = b"2E20416C736F2C20616E696D65207265666572656e636573";
/// assert_eq!(base16::decode_slice(&msg2[..], &mut buf[38..]).unwrap(), 24);
/// assert_eq!(&buf[38..62], b". Also, anime references".as_ref());
/// ```
#[inline]
pub fn decode_slice<T: ?Sized + AsRef<[u8]>>(input: &T, out: &mut [u8]) -> Result<usize, DecodeError> {
    let src = input.as_ref();
    if (src.len() & 1) != 0 {
        return Err(DecodeError::InvalidLength { length: src.len() });
    }
    let need_size = src.len() >> 1;
    assert!(out.len() >= need_size,
            "Destination buffer not large enough for decoded input {} < {}",
            out.len(), need_size);
    let res = unsafe { decode_slice_raw(src, &mut out[..need_size]) };
    match res {
        Ok(()) => Ok(need_size),
        Err(index) => Err(DecodeError::InvalidByte { index, byte: src[index] })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    static ALL_LOWER: &'static[&'static str] = &[
        "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b",
        "0c", "0d", "0e", "0f", "10", "11", "12", "13", "14", "15", "16", "17",
        "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", "20", "21", "22", "23",
        "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
        "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b",
        "3c", "3d", "3e", "3f", "40", "41", "42", "43", "44", "45", "46", "47",
        "48", "49", "4a", "4b", "4c", "4d", "4e", "4f", "50", "51", "52", "53",
        "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
        "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b",
        "6c", "6d", "6e", "6f", "70", "71", "72", "73", "74", "75", "76", "77",
        "78", "79", "7a", "7b", "7c", "7d", "7e", "7f", "80", "81", "82", "83",
        "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
        "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b",
        "9c", "9d", "9e", "9f", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
        "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af", "b0", "b1", "b2", "b3",
        "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
        "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb",
        "cc", "cd", "ce", "cf", "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
        "d8", "d9", "da", "db", "dc", "dd", "de", "df", "e0", "e1", "e2", "e3",
        "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
        "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb",
        "fc", "fd", "fe", "ff",
    ];

    static ALL_UPPER: &'static[&'static str] = &[
        "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B",
        "0C", "0D", "0E", "0F", "10", "11", "12", "13", "14", "15", "16", "17",
        "18", "19", "1A", "1B", "1C", "1D", "1E", "1F", "20", "21", "22", "23",
        "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F",
        "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B",
        "3C", "3D", "3E", "3F", "40", "41", "42", "43", "44", "45", "46", "47",
        "48", "49", "4A", "4B", "4C", "4D", "4E", "4F", "50", "51", "52", "53",
        "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F",
        "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B",
        "6C", "6D", "6E", "6F", "70", "71", "72", "73", "74", "75", "76", "77",
        "78", "79", "7A", "7B", "7C", "7D", "7E", "7F", "80", "81", "82", "83",
        "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
        "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B",
        "9C", "9D", "9E", "9F", "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7",
        "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF", "B0", "B1", "B2", "B3",
        "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",
        "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB",
        "CC", "CD", "CE", "CF", "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7",
        "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF", "E0", "E1", "E2", "E3",
        "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",
        "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB",
        "FC", "FD", "FE", "FF",
    ];

    #[test]
    fn test_exhaustive_bytes_encode() {
        for i in 0..256 {
            assert_eq!(&encode_lower(&[i as u8]), ALL_LOWER[i]);
            assert_eq!(&encode_upper(&[i as u8]), ALL_UPPER[i]);
        }
    }

    #[test]
    fn test_exhaustive_bytes_decode() {
        for i in 0..16 {
            for j in 0..16 {
                let all_cases = format!("{0:x}{1:x}{0:x}{1:X}{0:X}{1:x}{0:X}{1:X}", i, j);
                let byte = i * 16 + j;
                let expect = &[byte, byte, byte, byte];
                assert_eq!(&decode(&all_cases).unwrap(), expect,
                           "Failed for {}", all_cases);
            }
        }
        for b in 0..256 {
            let i = b as u8;
            let expected = match i {
                b'0' | b'1' | b'2' | b'3' | b'4' | b'5' | b'6' | b'7' | b'8' | b'9' => Ok(vec![i - b'0']),
                b'a' | b'b' | b'c' | b'd' | b'e' | b'f' => Ok(vec![i - b'a' + 10]),
                b'A' | b'B' | b'C' | b'D' | b'E' | b'F' => Ok(vec![i - b'A' + 10]),
                _ => Err(DecodeError::InvalidByte { byte: i, index: 1 })
            };
            assert_eq!(decode(&[b'0', i]), expected);
        }
    }

    #[test]
    #[should_panic]
    fn test_panic_slice_encode() {
        let mut slice = [0u8; 8];
        encode_config_slice(b"Yuasa", EncodeLower, &mut slice);
    }

    #[test]
    #[should_panic]
    fn test_panic_slice_decode() {
        let mut slice = [0u8; 32];
        let input = b"4920646f6e277420636172652074686174206d7563682061626f757420504d4d4d20544248";
        let _ignore = decode_slice(&input[..], &mut slice);
    }

    #[test]
    fn test_enc_slice_exact_fit() {
        let mut slice = [0u8; 12];
        let res = encode_config_slice(b"abcdef", EncodeLower, &mut slice);
        assert_eq!(res, 12);
        assert_eq!(&slice, b"616263646566")
    }

    #[test]
    fn test_decode_errors() {
        let mut buf = decode(b"686f6d61646f6b61").unwrap();
        let orig = buf.clone();

        assert_eq!(buf.len(), 8);

        assert_eq!(decode_buf(b"abc", &mut buf),
                   Err(DecodeError::InvalidLength { length: 3 }));
        assert_eq!(buf, orig);

        assert_eq!(decode_buf(b"6d61646f686f6d75g_", &mut buf),
                   Err(DecodeError::InvalidByte { byte: b'g', index: 16 }));
        assert_eq!(buf, orig);
    }

    // Most functions are tested in examples, coverage should be good now.
}

