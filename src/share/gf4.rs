//! This module implements the 4-bit finite field `GF(2^4)`.
//!
//! The field modulus is `X^4+X+1`.
//!
//! There are two data types:
//! - [GF4] contains a single field element.
//! - [BsGF4] contains two field elements packed for efficiency.
//!
//! Multiplication is implemented using lookup tables.

use std::{
    borrow::Borrow,
    fmt::{Debug, Formatter},
    ops::{Add, AddAssign, Mul, Neg, Sub},
};

use itertools::Itertools;
use rand::{CryptoRng, Rng};
use sha2::Digest;

use super::{gf4_bs_table, Field, FieldDigestExt, FieldRngExt};

/// An element of `GF(2^4) := GF(2)[X] / X^4+X+1`.
///
/// An element is represented as a byte where the top 4 bits are always 0.
#[derive(Copy, Clone, Default, PartialEq)]
pub struct GF4(u8);

#[rustfmt::skip]
const MUL_E_TABLE: [u8; 16] = [
    0x00, 0x0e, 0x0f, 0x01, 0x0d, 0x03, 0x02, 0x0c, 0x09, 0x07, 0x06, 0x08, 0x04, 0x0a, 0x0b, 0x05,
];

#[rustfmt::skip]
const SQ_TABLE: [u8; 16] = [
    0x00, 0x01, 0x04, 0x05, 0x03, 0x02, 0x07, 0x06, 0x0c, 0x0d, 0x08, 0x09, 0x0f, 0x0e, 0x0b, 0x0a,
];

#[rustfmt::skip]
const MUL_TABLE: [[u8; 16]; 16] = [
    [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, ],
    [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, ],
    [ 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x03, 0x01, 0x07, 0x05, 0x0b, 0x09, 0x0f, 0x0d, ],
    [ 0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, ],
    [ 0x00, 0x04, 0x08, 0x0c, 0x03, 0x07, 0x0b, 0x0f, 0x06, 0x02, 0x0e, 0x0a, 0x05, 0x01, 0x0d, 0x09, ],
    [ 0x00, 0x05, 0x0a, 0x0f, 0x07, 0x02, 0x0d, 0x08, 0x0e, 0x0b, 0x04, 0x01, 0x09, 0x0c, 0x03, 0x06, ],
    [ 0x00, 0x06, 0x0c, 0x0a, 0x0b, 0x0d, 0x07, 0x01, 0x05, 0x03, 0x09, 0x0f, 0x0e, 0x08, 0x02, 0x04, ],
    [ 0x00, 0x07, 0x0e, 0x09, 0x0f, 0x08, 0x01, 0x06, 0x0d, 0x0a, 0x03, 0x04, 0x02, 0x05, 0x0c, 0x0b, ],
    [ 0x00, 0x08, 0x03, 0x0b, 0x06, 0x0e, 0x05, 0x0d, 0x0c, 0x04, 0x0f, 0x07, 0x0a, 0x02, 0x09, 0x01, ],
    [ 0x00, 0x09, 0x01, 0x08, 0x02, 0x0b, 0x03, 0x0a, 0x04, 0x0d, 0x05, 0x0c, 0x06, 0x0f, 0x07, 0x0e, ], 
    [ 0x00, 0x0a, 0x07, 0x0d, 0x0e, 0x04, 0x09, 0x03, 0x0f, 0x05, 0x08, 0x02, 0x01, 0x0b, 0x06, 0x0c, ], 
    [ 0x00, 0x0b, 0x05, 0x0e, 0x0a, 0x01, 0x0f, 0x04, 0x07, 0x0c, 0x02, 0x09, 0x0d, 0x06, 0x08, 0x03, ],
    [ 0x00, 0x0c, 0x0b, 0x07, 0x05, 0x09, 0x0e, 0x02, 0x0a, 0x06, 0x01, 0x0d, 0x0f, 0x03, 0x04, 0x08, ],
    [ 0x00, 0x0d, 0x09, 0x04, 0x01, 0x0c, 0x08, 0x05, 0x02, 0x0f, 0x0b, 0x06, 0x03, 0x0e, 0x0a, 0x07, ],
    [ 0x00, 0x0e, 0x0f, 0x01, 0x0d, 0x03, 0x02, 0x0c, 0x09, 0x07, 0x06, 0x08, 0x04, 0x0a, 0x0b, 0x05, ],
    [ 0x00, 0x0f, 0x0d, 0x02, 0x09, 0x06, 0x04, 0x0b, 0x01, 0x0e, 0x0c, 0x03, 0x08, 0x07, 0x05, 0x0a, ],
];

impl GF4 {
    /// Generates a new element of `GF(2^4)` from a byte.
    ///
    /// The top 4 bits are ignored.
    pub fn new(x: u8) -> Self {
        GF4(x & 0x0F)
    }

    /// Generates a new element of `GF(2^4)` from a byte without any checks.
    ///  
    /// May have undefined behavior if the top 4-bits are set.
    pub fn new_unchecked(x: u8) -> Self {
        GF4(x)
    }

    /// Returns a binary representation of the field element.
    pub fn as_u8(self) -> u8 {
        self.0
    }

    /// Squares the field element.
    pub fn square(&self) -> Self {
        Self(SQ_TABLE[self.0 as usize])
    }

    // Multiplies the field element by `0xE`.
    pub fn mul_e(&self) -> Self {
        Self(MUL_E_TABLE[self.0 as usize])
    }

    /// Packs two field elements of GF4 into a single byte.
    #[inline]
    pub fn pack(ah: GF4, al: GF4) -> u8 {
        (ah.0 << 4) + al.0
    }

    /// Unpacks a byte into two field elements.
    #[inline]
    pub fn unpack(b: u8) -> (GF4, GF4) {
        //here we abuse the fact that new ignores the high bits.
        (GF4::new(b >> 4), GF4::new(b))
    }
}

impl Field for GF4 {
    const NBYTES: usize = 1;

    const ZERO: GF4 = Self(0);

    const ONE: GF4 = Self(1);

    fn serialized_size(n_elements: usize) -> usize {
        if n_elements % 2 == 0 {
            n_elements / 2
        } else {
            n_elements / 2 + 1
        }
    }

    fn is_zero(&self) -> bool {
        self.0 == 0
    }

    fn as_byte_vec(it: impl IntoIterator<Item = impl Borrow<Self>>, _len: usize) -> Vec<u8> {
        it.into_iter()
            .chunks(2)
            .into_iter()
            .map(|mut gfs| {
                let el1 = gfs.next().unwrap(); // this cannot be empty
                let el2 = match gfs.next() {
                    Some(el2) => *el2.borrow(),
                    None => Self::ZERO,
                };
                Self::pack(*el1.borrow(), el2)
            })
            .collect()
    }

    fn from_byte_vec(v: Vec<u8>, len: usize) -> Vec<Self> {
        let mut res = Vec::with_capacity(len);
        let full = len / 2;
        let mut i = 0;
        while i < full {
            let (el1, el2) = Self::unpack(v[i]);
            res.push(el1);
            res.push(el2);
            i += 1;
        }
        if full != v.len() {
            // there is one more GF4
            let (el1, _) = Self::unpack(v[v.len() - 1]);
            res.push(el1);
        }
        res
    }

    fn from_byte_slice(v: Vec<u8>, dest: &mut [Self]) {
        let full = dest.len() / 2;
        let mut i = 0;
        let mut j = 0;
        while i < full {
            let (el1, el2) = Self::unpack(v[i]);
            dest[j] = el1;
            dest[j + 1] = el2;
            i += 1;
            j += 2;
        }
        if full != v.len() {
            // there is one more GF4
            let (el1, _) = Self::unpack(v[v.len() - 1]);
            dest[j] = el1;
        }
    }
}

impl Add for GF4 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl AddAssign for GF4 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl Sub for GF4 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

/// Additive Inverse
impl Neg for GF4 {
    type Output = GF4;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Mul for GF4 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(MUL_TABLE[self.0 as usize][rhs.0 as usize])
    }
}

impl Debug for GF4 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "GF4(0x{:01x})", self.0 & 0x0F)
    }
}

impl<R: Rng + CryptoRng> FieldRngExt<GF4> for R {
    fn generate(&mut self, n: usize) -> Vec<GF4> {
        let mut r = vec![0; n];
        self.fill_bytes(&mut r);
        r.into_iter().map(GF4::new).collect()
    }

    fn fill(&mut self, buf: &mut [GF4]) {
        let mut v = vec![0u8; buf.len()];
        self.fill_bytes(&mut v);
        buf.iter_mut().zip(v).for_each(|(x, r)| x.0 = r & 0x0F)
    }
}

impl<D: Digest> FieldDigestExt<GF4> for D {
    fn update(&mut self, message: &[GF4]) {
        for x in message {
            self.update([x.0]);
        }
    }
}

/// Two elements of `GF(2^4) := GF(2)[X] / X^4+X+1` packed into a single byte.
///
/// The top 4 bits are the first element.
#[derive(Clone, Copy, PartialEq, Default)]
pub struct BsGF4(u8);

impl BsGF4 {
    /// Generates a new packed element from two [GF4].
    pub fn new(el1: GF4, el2: GF4) -> Self {
        Self(el1.as_u8() << 4 | el2.as_u8())
    }

    /// Unpacks an element into two [GF4].
    pub fn unpack(self) -> (GF4, GF4) {
        (GF4::new_unchecked(self.0 >> 4), GF4::new(self.0))
    }

    /// Squares both elements.
    pub fn square(self) -> Self {
        Self(gf4_bs_table::SQUARE_TABLE[self.0 as usize])
    }

    // Squares both elements and multiplies both with `0xE`.
    pub fn square_mul_e(self) -> Self {
        Self(gf4_bs_table::SQUARE_MUL_E_TABLE[self.0 as usize])
    }
}

impl Field for BsGF4 {
    const NBYTES: usize = 1;

    const ZERO: Self = Self(0x00);

    const ONE: Self = Self(0x11);

    fn is_zero(&self) -> bool {
        self.0 == 0
    }
    fn serialized_size(n_elements: usize) -> usize {
        n_elements
    }
    fn as_byte_vec(it: impl IntoIterator<Item = impl Borrow<Self>>, _len: usize) -> Vec<u8> {
        it.into_iter().map(|el| el.borrow().0).collect()
    }
    fn from_byte_vec(v: Vec<u8>, _len: usize) -> Vec<Self> {
        v.into_iter().map(Self).collect()
    }
    fn from_byte_slice(v: Vec<u8>, dest: &mut [Self]) {
        dest.iter_mut().zip(v).for_each(|(dst, b)| *dst = Self(b));
    }
}

impl AddAssign for BsGF4 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0
    }
}

impl Neg for BsGF4 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        self
    }
}

impl Mul for BsGF4 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self(gf4_bs_table::MULT_TABLE[self.0 as usize][rhs.0 as usize])
    }
}

impl Sub for BsGF4 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Add for BsGF4 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl<R: Rng + CryptoRng> FieldRngExt<BsGF4> for R {
    fn fill(&mut self, buf: &mut [BsGF4]) {
        let mut v = vec![0u8; buf.len()];
        self.fill_bytes(&mut v);
        buf.iter_mut().zip(v).for_each(|(x, r)| x.0 = r)
    }
    fn generate(&mut self, n: usize) -> Vec<BsGF4> {
        let mut r = vec![0; n];
        self.fill_bytes(&mut r);
        r.into_iter().map(BsGF4).collect()
    }
}

impl<D: Digest> FieldDigestExt<BsGF4> for D {
    fn update(&mut self, message: &[BsGF4]) {
        for x in message {
            self.update([x.0]);
        }
    }
}

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use crate::share::{Field, FieldRngExt};

    use super::{BsGF4, GF4};

    #[test]
    fn test_bsgf4_mul() {
        let mut rng = thread_rng();
        let a: Vec<GF4> = rng.generate(2);
        let b: Vec<GF4> = rng.generate(2);
        let c: Vec<GF4> = a.iter().zip(b.iter()).map(|(a, b)| *a * *b).collect();
        let ap = BsGF4::new(a[0], a[1]);
        let bp = BsGF4::new(b[0], b[1]);
        let cp = ap * bp;
        assert_eq!((c[0], c[1]), cp.unpack())
    }

    #[test]
    fn test_debug_format() {
        let x = GF4(0x0a);
        assert_eq!(format!("{:?}", x), "GF4(0xa)", "Format should match.")
    }

    #[test]
    fn test_packing() {
        let x = GF4(0x0f);
        let y = GF4(0x01);
        let b = GF4::pack(x, y);
        assert_eq!((x, y), GF4::unpack(b), "Packing and unpacking should work.")
    }

    #[test]
    fn test_mul_e() {
        let e = GF4(0xe);
        for x in 0..16 {
            assert_eq!(
                e * GF4(x),
                GF4(x).mul_e(),
                "Multiplication should match lookup."
            )
        }
    }

    #[test]
    fn serialization() {
        let mut rng = thread_rng();
        let list_even: Vec<GF4> = rng.generate(500);
        let list_odd: Vec<GF4> = rng.generate(45);

        assert_eq!(
            list_even,
            GF4::from_byte_vec(
                GF4::as_byte_vec(&list_even, list_even.len()),
                list_even.len()
            )
        );
        assert_eq!(
            list_odd,
            GF4::from_byte_vec(GF4::as_byte_vec(&list_odd, list_odd.len()), list_odd.len())
        );

        let mut slice_even = [GF4::ZERO; 500];
        let mut slice_odd = [GF4::ZERO; 45];

        GF4::from_byte_slice(
            GF4::as_byte_vec(&list_even, list_even.len()),
            &mut slice_even,
        );
        assert_eq!(&list_even, &slice_even);

        GF4::from_byte_slice(GF4::as_byte_vec(&list_odd, list_odd.len()), &mut slice_odd);
        assert_eq!(&list_odd, &slice_odd);
    }
}
