
use crate::{Result, Error};
use super::{REPRESENTATIVE_LENGTH, PUBLIC_KEY_LENGTH};

use libc::{size_t, int32_t};
use getrandom::getrandom;

pub(crate) const DECODE_FAILURE: &'static str = "elligator2 decode failed";

const MASK_UNSET_BYTE: u8 = 0x3f;
const MASK_SET_BYTE: u8 = 0xC0;


#[no_mangle]
extern "C" {

    // Takes as input a 32-byte little endian string (technically 255 bits
    // padded to 32 bytes)
    //
    // Returns 0 if string could not be decoded, i.e., does not correspond to
    // an elliptic curve point (highly unlikely). If possible, outputs 32 byte
    // x-coord of curve25519 point corresponding to input string
    fn _decode_c(out: *mut u8, input: *const u8) -> int32_t;

    // Takes as input 32 byte little endian encodable curve25519 point;
    // high order bit is sign of y value
    // Outputs 255-bit (little endian) uniform-looking 32-byte string
    // Returns 0 if point could not be encoded as a string, returns 1 otherwise
    fn _encode_c(out: *mut u8, input: *const u8) -> int32_t;
}


pub fn encode(pubkey: [u8; PUBLIC_KEY_LENGTH]) -> Option<[u8; REPRESENTATIVE_LENGTH]> {
    let mut out = [0_u8; REPRESENTATIVE_LENGTH];
    let ret_code = unsafe {
        _encode_c(out.as_mut_ptr(), pubkey.as_ptr())
    };

    if ret_code == 0 {
        // failed to encode to a point on the curve
        return None
    }
    let mut mask_byte = [0_u8];
    getrandom(&mut mask_byte);

    out[31] |= MASK_SET_BYTE & mask_byte[0];

    Some(out)
}

pub fn decode(repres: [u8; REPRESENTATIVE_LENGTH]) -> Result<[u8; PUBLIC_KEY_LENGTH]> {
    let mut out = [0_u8; PUBLIC_KEY_LENGTH];
    let mut r_sign_cleared = repres;
    r_sign_cleared[31] &= MASK_UNSET_BYTE;
    let ret_code = unsafe {
        _decode_c(out.as_mut_ptr(), r_sign_cleared.as_ptr())
    };

    if ret_code == 0 {
        // failed to decode
        return Err(Error::Crypto(DECODE_FAILURE.into()))
    }

    Ok(out)
}

