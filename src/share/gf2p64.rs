use std::{borrow::Borrow, fmt::{Debug, Formatter}, ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub}};

use itertools::Itertools;
use rand::{CryptoRng, Rng};
use sha2::Digest;

use super::{Field, FieldDigestExt, FieldRngExt, Invertible};

/// An element of GF(2^64) := GF(2)[X] / X^64+X^4+X^3+X+1
/// 
/// An element is represented as a byte where the top 4 bits are always 0.
#[derive(Copy, Clone, Default, PartialEq)]
pub struct GF2p64(u64);

impl GF2p64 {
    pub fn new<T>(x:T) -> Self where u64: From<T> {
        GF2p64(u64::from(x))
    }

    /// A 64-bit vector representing the irreducible polynomial X^64+X^4+X^3+X+1
    const MODULUS: u64 = 0x80_00_00_00_00_00_00_1B;

    /// MODULUS - X^64 = X^4+X^3+X+1
    const MOD_MINUS_XN: u64 = 0x00_00_00_00_00_00_00_1B;

    /// Multiply an element by X (i.e. by 0x0000000000000002)
    /// This is essentially a left shift of the bit-vector mod MODULUS
    /// not constant time
    fn mul_by_X(&mut self) {
        let high_bit = self.0 >> (Self::NBITS - 1);
        self.0 = self.0 << 1;
        if high_bit != 0 {
            self.0 ^= Self::MOD_MINUS_XN;
        }
    }

    /// Multiply using addition
    fn mul_using_add(mut self, other: &Self) -> Self {
        let mut result = Self::ZERO;
        for i in 0..Self::NBITS {
            if other.0 & (1 << i) != 0 {
                result.0 ^= self.0
            }
            self.mul_by_X()
        }
        result
    }

    /// Carry propagation for CLMUL (cf. https://github.com/gendx/horcrux/blob/main/horcrux/src/gf2n.rs)
    #[cfg(any(
        test,
        all(
            feature = "clmul",
            target_arch = "x86_64",
            target_feature = "sse2",
            target_feature = "pclmulqdq"
        ),
        all(
            feature = "clmul",
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "aes"
        )
    ))]
    fn propagate_carries(mut word: u64, carry: u64) -> Self {
        let mut c = carry;
        while c != 0 {
            word ^= c ^ (c << 4) ^ (c << 3) ^ (c << 1);
            c = (c >> (Self::NBITS - 4)) ^ (c >> (Self::NBITS - 3)) ^ (c >> (Self::NBITS - 1))
        }
        Self(word)
    }

    /// Multiply using CLMUL (cf. https://github.com/gendx/horcrux/blob/main/horcrux/src/gf2n.rs)
    #[cfg(all(
        feature = "clmul",
        target_arch = "x86_64",
        target_feature = "sse2",
        target_feature = "pclmulqdq"
    ))]
    fn mul_clmul_u64(&self, other: &Self) -> Self {
        use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128};

        let mut word = 0u64;
        let mut carry = 0u64;

        let x: __m128i = unsafe { _mm_set_epi64x(0, self.0 as i64) };
        let y: __m128i = unsafe { _mm_set_epi64x(0, other.0 as i64) };
        let clmul: __m128i = unsafe { _mm_clmulepi64_si128(x, y, 0) };
        let mut cc: [u64; 2] = [0u64, 0u64];
        unsafe { _mm_storeu_si128(&mut cc as *mut _ as *mut __m128i, clmul) };

        let word = cc[0];
        let carry = cc[1];

        Self::propagate_carries(word, carry)
    }

    /// Multiply using CLMUL (cf. https://github.com/gendx/horcrux/blob/main/horcrux/src/gf2n.rs)
    #[cfg(all(
        feature = "clmul",
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "aes"
    ))]
    fn mul_clmul_u64(&self, other: &Self) -> Self {
        use std::arch::aarch64::vmull_p64;
        let clmul: u128 = unsafe { vmull_p64(self.0, other.0) };
        let word = clmul as u64;
        let carry = (clmul >> 64) as u64;
        Self::propagate_carries(word, carry)
    }
}

impl Field for GF2p64 {

    const NBYTES: usize = 8;

    const ZERO: Self = Self(0u64);

    const ONE: Self = Self(1u64);

    fn is_zero(&self) -> bool {
        self.0 == 0u64
    }

    fn as_byte_vec(it: impl IntoIterator<Item= impl Borrow<Self>>) -> Vec<u8> {
        // Using big-endian encoding
        it.into_iter().flat_map(|gf| gf.borrow().0.to_be_bytes()).collect()
    }

    fn from_byte_vec(v: Vec<u8>) -> Vec<Self> {
        debug_assert!(v.len() % Self::NBYTES == 0);
        v.into_iter().chunks(Self::NBYTES).into_iter().map(|mut c| {
            let x = u64::from_be_bytes(c.collect::<Vec<u8>>().try_into().expect("chunk with incorrect length"));
            Self(x)
        }).collect()
    }

    fn from_byte_slice(v: Vec<u8>, dest: &mut [Self]) {
        debug_assert_eq!(v.len(), Self::NBYTES*dest.len());
        dest.iter_mut().zip(v.into_iter().chunks(Self::NBYTES).into_iter()).for_each(|(dst, mut c)| {
            dst.0 = u64::from_be_bytes(c.collect::<Vec<u8>>().try_into().expect("chunk with incorrect length"));
        })
    }

}


impl Invertible for GF2p64 {
    /// Multiplicative inverse
    fn inverse(self) -> Self {
        if self == Self::ZERO {
            return self
        }
        let mut p = self;
        // Compute x^(2^n - 2)
        let mut result = Self::ONE;
        for _ in 1..Self::NBITS {
            p = p * p;
            result *= p;
        }
        result
    }
}

impl Add for GF2p64 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
    
}

impl AddAssign for GF2p64 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl Sub for GF2p64 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

/// Additive Inverse
impl Neg for GF2p64 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Mul for GF2p64 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        #[cfg(any(
            all(
                feature = "clmul",
                target_arch = "x86_64",
                target_feature = "sse2",
                target_feature = "pclmulqdq"
            ),
            all(
                feature = "clmul",
                target_arch = "aarch64",
                target_feature = "neon",
                target_feature = "aes"
            )
        ))]
        {
            return Self::mul_clmul_u64(&self, &rhs);
        }
        //Fall back 
        self.mul_using_add(&rhs)
    }
}

impl MulAssign for GF2p64 {
    fn mul_assign(&mut self, rhs: Self) {
        *self  = *self * rhs
    }
}

impl Debug for GF2p64 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "GF2p64(0x{:016x})", self.0)
    }
}

impl<R: Rng + CryptoRng> FieldRngExt<GF2p64> for R {
    fn generate(&mut self, n: usize) -> Vec<GF2p64> {
        let mut r = vec![0; n*GF2p64::NBYTES];
        self.fill_bytes(&mut r);
        GF2p64::from_byte_vec(r)
    }

    fn fill(&mut self, buf: &mut [GF2p64]) {
        let mut v = vec![0u8; buf.len()*GF2p64::NBYTES];
        self.fill_bytes(&mut v);
        GF2p64::from_byte_slice(v, buf)
    }
}

impl<D: Digest> FieldDigestExt<GF2p64> for D {
    fn update(&mut self, message: &[GF2p64]) {
        for x in message {
            self.update(&x.0.to_be_bytes());
        }
    }
}



#[cfg(test)]
mod test {
    use crate::share::{Field, Invertible};

    use super::GF2p64;

    fn get_test_values() -> Vec<GF2p64> {
        vec![GF2p64(0), GF2p64(1), GF2p64(0xffffffffffffffff), GF2p64(0xfffffffffeffffff)]
    }

    fn get_non_zero_test_values() -> Vec<GF2p64> {
        vec![GF2p64(1), GF2p64(0xffffffffffffffff), GF2p64(0xfffffffffeffffff)]
    }

    #[test]
    fn test_mul() {
        let test_elements = get_test_values();
        for &x in &test_elements {
            for &y in &test_elements {
                //println!("{0:?} * {1:?} = {2:?} = {3:?}",x,y,x*y,y*x);
                assert_eq!(x*y, y*x)
            }
        }
        let zero = GF2p64::ZERO;
        for &x in &test_elements {
            assert_eq!(x*zero,zero)
        }
        for &x in &test_elements[1..] {
            assert_eq!(x*GF2p64::ONE, x)
        }
    }

    #[test]
    fn test_inverse(){
        let test_values = get_non_zero_test_values();
        for x in test_values {
            let inv_x = x.inverse();
            assert_eq!(x*inv_x,GF2p64::ONE);
            assert_eq!(inv_x*x,GF2p64::ONE)
        }
    }

    
    #[test]
    fn test_serialization() {
        let v = vec![GF2p64(0x1),GF2p64(0xffffffffffffffff),GF2p64(0x3),GF2p64(0x123456781234578)];
        let as_bytes = GF2p64::as_byte_vec(v.iter());
        let v_new = GF2p64::from_byte_vec(as_bytes);
        assert_eq!(v_new, v);
    }

}
