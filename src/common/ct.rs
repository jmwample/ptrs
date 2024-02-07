//! Constant-time utilities.
use subtle::{Choice, ConstantTimeEq};

/// Convert a boolean into a Choice.
///
/// This isn't necessarily a good idea or constant-time.
pub(crate) fn bool_to_choice(v: bool) -> Choice {
    Choice::from(u8::from(v))
}

/// Return true if two slices are equal.  Performs its operation in constant
/// time, but returns a bool instead of a subtle::Choice.
pub(crate) fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    let choice = a.ct_eq(b);
    choice.unwrap_u8() == 1
}

