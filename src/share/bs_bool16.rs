use std::{borrow::Borrow, ops::{Add, AddAssign, Mul, Neg, Sub}};

use itertools::Itertools;
use rand::{CryptoRng, Rng};
use sha2::Digest;

use super::{Field, FieldDigestExt, FieldRngExt};

/// a bit-sliced vector of 16 booleans
/// or mathematically, this is an element in F_2^16
/// this means, addition, multiplicaiton is done **element-wise**
#[derive(Clone,Copy,Default,PartialEq, Debug)]
pub struct BsBool16(u16);

impl BsBool16 {
    /// bit 0 in bits will be the first element in the vector, bit 1 in bits the second...
    pub fn new(bits: u16) -> Self {
        Self(bits)
    }

    pub fn one() -> Self {
        Self(0xffff)
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    } 
}

impl Field for BsBool16 {
    fn serialized_size(n_elements: usize) -> usize {
        2*n_elements
    }

    fn zero() -> Self {
        Self(0)
    }

    fn is_zero(&self) -> bool {
        self.0 == 0
    }

    fn as_byte_vec(it: impl IntoIterator<Item= impl Borrow<Self>>, _len: usize) -> Vec<u8> {
        it.into_iter().flat_map(|el| [el.borrow().0 as u8, (el.borrow().0 >> 8) as u8]).collect()
    }

    fn from_byte_vec(v: Vec<u8>, _len: usize) -> Vec<Self> {
        debug_assert!(v.len() % 2 == 0);
        v.into_iter().chunks(2).into_iter().map(|mut chunk| {
            let low = chunk.next().unwrap() as u16;
            let high = chunk.next().unwrap() as u16;
            Self(low | (high << 8))
        }).collect()
    }

    fn from_byte_slice(v: Vec<u8>, dest: &mut [Self]) {
        debug_assert_eq!(v.len(), 2*dest.len());
        dest.iter_mut().zip(v.into_iter().chunks(2).into_iter()).for_each(|(dst, mut chunk)| {
            let low = chunk.next().unwrap() as u16;
            let high = chunk.next().unwrap() as u16;
            dst.0 = low | (high << 8);
        });
    }
}

impl Neg for BsBool16 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(self.0)
    }
}

impl Mul for BsBool16 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl Sub for BsBool16 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Add for BsBool16 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl AddAssign for BsBool16 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl<R: Rng + CryptoRng> FieldRngExt<BsBool16> for R {

    fn fill(&mut self, buf: &mut [BsBool16]) {
        for i in 0..buf.len()/2 {
            let rng = self.next_u32();
            buf[2*i].0 = rng as u16;
            buf[2*i+1].0 = (rng >> 16) as u16;
        }
        if buf.len() % 2 != 0 {
            let rng = self.next_u32();
            buf[buf.len()-1].0 = rng as u16;
        }
    }

    fn generate(&mut self, n: usize) -> Vec<BsBool16> {
        let mut v = vec![BsBool16::zero(); n];
        for i in 0..n/2 {
            let rng = self.next_u32();
            v[2*i].0 = rng as u16;
            v[2*i+1].0 = (rng >> 16) as u16;
        }
        if n % 2 != 0 {
            let rng = self.next_u32();
            v[n-1].0 = rng as u16;
        }
        v
    }
}

impl<D: Digest> FieldDigestExt<BsBool16> for D {
    fn update(&mut self, message: &[BsBool16]) {
        for m in message {
            self.update(&[m.0 as u8, (m.0 >> 8) as u8]);
        }
    }
}