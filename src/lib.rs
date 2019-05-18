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

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

#[cfg(not(feature = "std"))]
extern crate core as std;

/// Configuration options for encoding. Just specifies whether or not output
/// should be uppercase or lowercase.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EncConfig {
    /// Encode using lower case characters for hex values >= 10
    EncodeLower,
    /// Encode using upper case characters for hex values >= 10
    EncodeUpper,
}

pub use EncConfig::*;

#[inline(always)]
fn encoded_size(source_len: usize) -> usize {
    const USIZE_TOP_BIT: usize = 1usize << (std::mem::size_of::<usize>() * 8 - 1);
    if (source_len & USIZE_TOP_BIT) != 0 {
        usize_overflow(source_len)
    }
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
        let b0 = *lut.get_unchecked(x as usize);
        let b1 = *lut.get_unchecked(y as usize);
        *dst.get_unchecked_mut(i + 0) = b0;
        *dst.get_unchecked_mut(i + 1) = b1;
        i += 2;
    }
}

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
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
///
/// # Availability
///
/// This function is only available when the `std` feature is enabled.
#[cfg(feature = "std")]
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
///
/// # Availability
///
/// This function is only available when the `std` feature is enabled.
#[cfg(feature = "std")]
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
///
/// # Availability
///
/// This function is only available when the `std` feature is enabled.
#[cfg(feature = "std")]
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
/// # Availability
///
/// This function is only available when the `std` feature is enabled.
#[cfg(feature = "std")]
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
/// # Availability
///
/// This function is available whether or not the `std` feature is enabled.
#[inline]
pub fn encode_config_slice<T: ?Sized + AsRef<[u8]>>(input: &T,
                                                    cfg: EncConfig,
                                                    dst: &mut [u8]) -> usize {
    let src = input.as_ref();
    let need_size = encoded_size(src.len());
    if dst.len() < need_size {
        dest_too_small_enc(dst.len(), need_size);
    }
    unsafe {
        encode_slice(src, cfg, dst.get_unchecked_mut(..need_size));
    }
    need_size
}

/// Encode a single character as hex, returning a tuple containing the two
/// encoded bytes in big-endian order -- the order the characters would be in
/// when written out (e.g. the top nibble is the first item in the tuple)
///
/// # Example
/// ```
/// assert_eq!(base16::encode_byte(0xff, base16::EncodeLower), [b'f', b'f']);
/// assert_eq!(base16::encode_byte(0xa0, base16::EncodeUpper), [b'A', b'0']);
/// assert_eq!(base16::encode_byte(3, base16::EncodeUpper), [b'0', b'3']);
/// ```
/// # Availability
///
/// This function is available whether or not the `std` feature is enabled.
#[inline]
pub fn encode_byte(byte: u8, cfg: EncConfig) -> [u8; 2] {
    static HEX_UPPER: &'static [u8] = b"0123456789ABCDEF";
    static HEX_LOWER: &'static [u8] = b"0123456789abcdef";
    let lut = if cfg == EncodeLower { HEX_LOWER } else { HEX_UPPER };
    let lo = unsafe { *lut.get_unchecked((byte & 15) as usize) };
    let hi = unsafe { *lut.get_unchecked((byte >> 4) as usize) };
    [hi, lo]
}

/// Convenience wrapper for `base16::encode_byte(byte, base16::EncodeLower)`
///
/// See also `base16::encode_byte_u`.
///
/// # Example
/// ```
/// assert_eq!(base16::encode_byte_l(0xff), [b'f', b'f']);
/// assert_eq!(base16::encode_byte_l(30), [b'1', b'e']);
/// assert_eq!(base16::encode_byte_l(0x2d), [b'2', b'd']);
/// ```
/// # Availability
///
/// This function is available whether or not the `std` feature is enabled.
#[inline]
pub fn encode_byte_l(byte: u8) -> [u8; 2] {
    encode_byte(byte, EncodeLower)
}

/// Convenience wrapper for `base16::encode_byte(byte, base16::EncodeUpper)`
///
/// See also `base16::encode_byte_l`.
///
/// # Example
/// ```
/// assert_eq!(base16::encode_byte_u(0xff), [b'F', b'F']);
/// assert_eq!(base16::encode_byte_u(30), [b'1', b'E']);
/// assert_eq!(base16::encode_byte_u(0x2d), [b'2', b'D']);
/// ```
/// # Availability
///
/// This function is available whether or not the `std` feature is enabled.
#[inline]
pub fn encode_byte_u(byte: u8) -> [u8; 2] {
    encode_byte(byte, EncodeUpper)
}

/// Represents a problem with the data we want to decode.
///
/// This implements `std::error::Error` and `std::fmt::Display` if the `std`
/// feature is enabled, but only `std::fmt::Display` if it is not.
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

#[cold]
fn invalid_length(length: usize) -> DecodeError {
    DecodeError::InvalidLength { length }
}

#[cold]
fn invalid_byte(index: usize, src: &[u8]) -> DecodeError {
    DecodeError::InvalidByte { index, byte: src[index] }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn description(&self) -> &str {
        match *self {
            DecodeError::InvalidByte { .. } => "Illegal byte in base16 data",
            DecodeError::InvalidLength { .. } => "Illegal length for base16 data",
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}

#[inline]
unsafe fn do_decode_slice_raw(src: &[u8], dst: &mut[u8]) -> isize {
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
        let s1 = *src.get_unchecked(si.wrapping_add(1));
        let r0 = *LUT.get_unchecked(s0 as usize);
        let r1 = *LUT.get_unchecked(s1 as usize);
        if (r0 | r1) >= 0 {
            *dst.get_unchecked_mut(di) = ((r0 << 4) | r1) as u8;
            si = si.wrapping_add(2);
            di = di.wrapping_add(1);
        } else {
            // This is annoying (but resulted in a 20% speed boost), but we
            // return the earliest byte that can be the problem byte, and sort
            // it out in the caller.
            return si as isize;
        }
    }
    -1
}

#[inline]
unsafe fn decode_slice_raw(src: &[u8], dst: &mut[u8]) -> Result<(), usize> {
    let bad_idx = do_decode_slice_raw(src, dst);
    if bad_idx < 0 {
        Ok(())
    } else {
        Err(raw_decode_err(bad_idx as usize, src))
    }
}

#[cold]
#[inline(never)]
fn raw_decode_err(idx: usize, src: &[u8]) -> usize {
    let b0 = src[idx];
    if decode_byte(b0).is_none() {
        idx
    } else {
        idx + 1
    }
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
/// # Availability
///
/// This function is only available when the `std` feature is enabled.
#[cfg(feature = "std")]
#[inline]
pub fn decode<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, DecodeError> {
    let src = input.as_ref();
    if (src.len() & 1) != 0 {
        return Err(invalid_length(src.len()));
    }
    let need_size = src.len() >> 1;
    let mut dst = Vec::with_capacity(need_size);
    let res = unsafe {
        dst.set_len(need_size);
        decode_slice_raw(src, &mut dst)
    };
    match res {
        Ok(()) => Ok(dst),
        Err(index) => Err(invalid_byte(index, src))
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
/// # Availability
///
/// This function is only available when the `std` feature is enabled.
#[cfg(feature = "std")]
#[inline]
pub fn decode_buf<T: ?Sized + AsRef<[u8]>>(input: &T, v: &mut Vec<u8>) -> Result<usize, DecodeError> {
    let src = input.as_ref();
    if (src.len() & 1) != 0 {
        return Err(invalid_length(src.len()));
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
            Err(invalid_byte(index, src))
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
/// # Availability
///
/// This function is available whether or not the `std` feature is enabled.
#[inline]
pub fn decode_slice<T: ?Sized + AsRef<[u8]>>(input: &T, out: &mut [u8]) -> Result<usize, DecodeError> {
    let src = input.as_ref();
    if (src.len() & 1) != 0 {
        return Err(invalid_length(src.len()));
    }
    let need_size = src.len() >> 1;
    if out.len() < need_size {
        dest_too_small_dec(out.len(), need_size);
    }
    let res = unsafe { decode_slice_raw(src, &mut out[..need_size]) };
    match res {
        Ok(()) => Ok(need_size),
        Err(index) => Err(invalid_byte(index, src))
    }
}

/// Decode a single character as hex.
///
/// Returns `None` for values outside the ASCII hex range.
///
/// # Example
/// ```
/// assert_eq!(base16::decode_byte(b'a'), Some(10));
/// assert_eq!(base16::decode_byte(b'B'), Some(11));
/// assert_eq!(base16::decode_byte(b'0'), Some(0));
/// assert_eq!(base16::decode_byte(b'q'), None);
/// assert_eq!(base16::decode_byte(b'x'), None);
/// ```
/// # Availability
///
/// This function is available whether or not the `std` feature is enabled.
#[inline]
pub fn decode_byte(c: u8) -> Option<u8> {
    if c.wrapping_sub(b'0') <= 9 {
        Some(c.wrapping_sub(b'0'))
    } else if c.wrapping_sub(b'a') < 6 {
        Some(c.wrapping_sub(b'a') + 10)
    } else if c.wrapping_sub(b'A') < 6 {
        Some(c.wrapping_sub(b'A') + 10)
    } else {
        None
    }
}

// Outlined assertions.
#[inline(never)]
#[cold]
fn usize_overflow(len: usize) -> ! {
    panic!("usize overflow when computing size of destination: {}", len);
}

#[cold]
#[inline(never)]
fn dest_too_small_enc(dst_len: usize, need_size: usize) -> ! {
    panic!("Destination is not large enough to encode input: {} < {}", dst_len, need_size);
}

#[cold]
#[inline(never)]
fn dest_too_small_dec(dst_len: usize, need_size: usize) -> ! {
    panic!("Destination buffer not large enough for decoded input {} < {}", dst_len, need_size);
}

#[cfg(test)]
mod test {
    use super::*;
    const ALL_LOWER: &[&str] = &[
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

    const ALL_UPPER: &[&str] = &[
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

    #[cfg(feature = "std")]
    #[test]
    fn test_exhaustive_bytes_encode() {
        for i in 0..256 {
            assert_eq!(&encode_lower(&[i as u8]), ALL_LOWER[i]);
            assert_eq!(&encode_upper(&[i as u8]), ALL_UPPER[i]);
        }
    }

    #[cfg(feature = "std")]
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

    #[cfg(feature = "std")]
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

    #[test]
    fn test_encode_byte() {
        for i in 0..256 {
            let byte = i as u8;
            let su = ALL_UPPER[byte as usize].as_bytes();
            let sl = ALL_LOWER[byte as usize].as_bytes();
            let tu = encode_byte(byte, EncodeUpper);
            let tl = encode_byte(byte, EncodeLower);

            assert_eq!(tu[0], su[0]);
            assert_eq!(tu[1], su[1]);

            assert_eq!(tl[0], sl[0]);
            assert_eq!(tl[1], sl[1]);

            assert_eq!(tu, encode_byte_u(byte));
            assert_eq!(tl, encode_byte_l(byte));
        }
    }

    const HEX_TO_VALUE: &[(u8, u8)] = &[
        (b'0', 0x0), (b'1', 0x1), (b'2', 0x2), (b'3', 0x3), (b'4', 0x4),
        (b'5', 0x5), (b'6', 0x6), (b'7', 0x7), (b'8', 0x8), (b'9', 0x9),
        (b'a', 0xa), (b'b', 0xb), (b'c', 0xc), (b'd', 0xd), (b'e', 0xe), (b'f', 0xf),
        (b'A', 0xA), (b'B', 0xB), (b'C', 0xC), (b'D', 0xD), (b'E', 0xE), (b'F', 0xF),
    ];

    #[test]
    fn test_decode_byte() {
        let mut expected = [None::<u8>; 256];
        for &(k, v) in HEX_TO_VALUE {
            expected[k as usize] = Some(v);
        }
        for i in 0..256 {
            assert_eq!(decode_byte(i as u8), expected[i]);
        }
    }

    // Most functions are tested in examples, coverage should be good now.
}

