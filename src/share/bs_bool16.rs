//! This module implements the 16-bit vector field `GF(2)^16`.
//!
//! This can also be seen as a bit-sliced vector of 16 booleans.
use std::{
    borrow::Borrow,
    ops::{Add, AddAssign, Mul, Neg, Sub},
};

use itertools::Itertools;
use rand::{CryptoRng, Rng};
use crate::rep3_core::{network::NetSerializable, party::{DigestExt, RngExt}, share::HasZero};
use sha2::Digest;

use super::Field;

/// A vector in `GF(2)^16`, i.e., a bit-sliced vector of 16 booleans.
///
/// *Note*: Addition and multiplication is done **element-wise**.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct BsBool16(u16);

impl BsBool16 {
    /// Bit `0` in bits will be the first element in the vector, bit `1` in bits the second.
    pub fn new(bits: u16) -> Self {
        Self(bits)
    }

    /// Returns a binary representation of the vector.
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

impl Field for BsBool16 {
    const NBYTES: usize = 2;

    /// Each component is one
    const ONE: Self = Self(0xffff);

    fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl HasZero for BsBool16 {
    const ZERO: Self = Self(0x0000);
}

impl NetSerializable for BsBool16 {
    fn serialized_size(n_elements: usize) -> usize {
        2 * n_elements
    }

    fn as_byte_vec(it: impl IntoIterator<Item = impl Borrow<Self>>, _len: usize) -> Vec<u8> {
        it.into_iter()
            .flat_map(|el| [el.borrow().0 as u8, (el.borrow().0 >> 8) as u8])
            .collect()
    }

    fn as_byte_vec_slice(elements: &[Self]) -> Vec<u8> {
        let mut res = vec![0u8; Self::serialized_size(elements.len())];
        for i in 0..elements.len() {
            res[2*i] = elements[i].0 as u8;
            res[2*i+1] = (elements[i].0 >> 8) as u8;
        }
        res
    }

    fn from_byte_vec(v: Vec<u8>, _len: usize) -> Vec<Self> {
        debug_assert!(v.len() % 2 == 0);
        v.into_iter()
            .chunks(2)
            .into_iter()
            .map(|mut chunk| {
                let low = chunk.next().unwrap() as u16;
                let high = chunk.next().unwrap() as u16;
                Self(low | (high << 8))
            })
            .collect()
    }

    fn from_byte_slice(v: Vec<u8>, dest: &mut [Self]) {
        debug_assert_eq!(v.len(), 2 * dest.len());
        dest.iter_mut().zip(v.chunks(2)).for_each(|(dst, chunk)| {
            let low = chunk[0] as u16;
            let high = chunk[1] as u16;
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
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl Sub for BsBool16 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Add for BsBool16 {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl AddAssign for BsBool16 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl RngExt for BsBool16 {
    fn fill<R: Rng + CryptoRng>(rng: &mut R, buf: &mut [Self]) {
        for i in 0..buf.len() / 2 {
            let rng = rng.next_u32();
            buf[2 * i].0 = rng as u16;
            buf[2 * i + 1].0 = (rng >> 16) as u16;
        }
        if buf.len() % 2 != 0 {
            let rng = rng.next_u32();
            buf[buf.len() - 1].0 = rng as u16;
        }
    }

    fn generate<R: Rng + CryptoRng>(rng: &mut R, n: usize) -> Vec<Self> {
        let mut v = vec![BsBool16::ZERO; n];
        for i in 0..n / 2 {
            let rng = rng.next_u32();
            v[2 * i].0 = rng as u16;
            v[2 * i + 1].0 = (rng >> 16) as u16;
        }
        if n % 2 != 0 {
            let rng = rng.next_u32();
            v[n - 1].0 = rng as u16;
        }
        v
    }
}

impl DigestExt for BsBool16 {
    fn update<D: Digest>(digest: &mut D, message: &[Self]) {
        for m in message {
            digest.update([m.0 as u8, (m.0 >> 8) as u8]);
        }
    }
}

#[cfg(test)]
mod test {
    use crate::share::bs_bool16::BsBool16;
    use rand::thread_rng;
    use crate::rep3_core::{network::NetSerializable, party::RngExt, share::HasZero};

    #[test]
    fn serialization() {
        let mut rng = thread_rng();
        let list_even: Vec<BsBool16> = BsBool16::generate(&mut rng, 500);
        let list_odd: Vec<BsBool16> = BsBool16::generate(&mut rng, 45);

        assert_eq!(
            list_even,
            BsBool16::from_byte_vec(
                BsBool16::as_byte_vec(&list_even, list_even.len()),
                list_even.len()
            )
        );
        assert_eq!(
            list_odd,
            BsBool16::from_byte_vec(
                BsBool16::as_byte_vec(&list_odd, list_odd.len()),
                list_odd.len()
            )
        );

        let mut slice_even = [BsBool16::ZERO; 500];
        let mut slice_odd = [BsBool16::ZERO; 45];

        BsBool16::from_byte_slice(
            BsBool16::as_byte_vec(&list_even, list_even.len()),
            &mut slice_even,
        );
        assert_eq!(&list_even, &slice_even);

        BsBool16::from_byte_slice(
            BsBool16::as_byte_vec(&list_odd, list_odd.len()),
            &mut slice_odd,
        );
        assert_eq!(&list_odd, &slice_odd);
    }
}
