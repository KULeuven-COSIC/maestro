use std::{borrow::Borrow, fmt::{Debug, Formatter}, ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub}};

use itertools::Itertools;
use rand::{CryptoRng, Rng};
use sha2::Digest;

use super::{gf4::GF4, gf8::GF8, Field, FieldDigestExt, FieldRngExt, Invertible};

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

trait GF2p64Subfield {
    fn embed(self) -> GF2p64;
}

const GF8_EB_TABLE: [u64; 256] = [0x0000000000000000, 0x0000000000000001, 0x033ce8beddc8a656, 0x033ce8beddc8a657, 0x512620375ed2a108, 0x512620375ed2a109, 0x521ac889831a075e, 0x521ac889831a075f, 0x0c9e636090aafc01, 0x0c9e636090aafc00, 0x0fa28bde4d625a57, 0x0fa28bde4d625a56, 0x5db84357ce785d09, 0x5db84357ce785d08, 0x5e84abe913b0fb5f, 0x5e84abe913b0fb5e, 0xba4f3cd82801769c, 0xba4f3cd82801769d, 0xb973d466f5c9d0ca, 0xb973d466f5c9d0cb, 0xeb691cef76d3d794, 0xeb691cef76d3d795, 0xe855f451ab1b71c2, 0xe855f451ab1b71c3, 0xb6d15fb8b8ab8a9d, 0xb6d15fb8b8ab8a9c, 0xb5edb70665632ccb, 0xb5edb70665632cca, 0xe7f77f8fe6792b95, 0xe7f77f8fe6792b94, 0xe4cb97313bb18dc3, 0xe4cb97313bb18dc2, 0xba26e7904adb4a47, 0xba26e7904adb4a46, 0xb91a0f2e9713ec11, 0xb91a0f2e9713ec10, 0xeb00c7a71409eb4f, 0xeb00c7a71409eb4e, 0xe83c2f19c9c14d19, 0xe83c2f19c9c14d18, 0xb6b884f0da71b646, 0xb6b884f0da71b647, 0xb5846c4e07b91010, 0xb5846c4e07b91011, 0xe79ea4c784a3174e, 0xe79ea4c784a3174f, 0xe4a24c79596bb118, 0xe4a24c79596bb119, 0x0069db4862da3cdb, 0x0069db4862da3cda, 0x035533f6bf129a8d, 0x035533f6bf129a8c, 0x514ffb7f3c089dd3, 0x514ffb7f3c089dd2, 0x527313c1e1c03b85, 0x527313c1e1c03b84, 0x0cf7b828f270c0da, 0x0cf7b828f270c0db, 0x0fcb50962fb8668c, 0x0fcb50962fb8668d, 0x5dd1981faca261d2, 0x5dd1981faca261d3, 0x5eed70a1716ac784, 0x5eed70a1716ac785, 0x467698598926dc01, 0x467698598926dc00, 0x454a70e754ee7a57, 0x454a70e754ee7a56, 0x1750b86ed7f47d09, 0x1750b86ed7f47d08, 0x146c50d00a3cdb5f, 0x146c50d00a3cdb5e, 0x4ae8fb39198c2000, 0x4ae8fb39198c2001, 0x49d41387c4448656, 0x49d41387c4448657, 0x1bcedb0e475e8108, 0x1bcedb0e475e8109, 0x18f233b09a96275e, 0x18f233b09a96275f, 0xfc39a481a127aa9d, 0xfc39a481a127aa9c, 0xff054c3f7cef0ccb, 0xff054c3f7cef0cca, 0xad1f84b6fff50b95, 0xad1f84b6fff50b94, 0xae236c08223dadc3, 0xae236c08223dadc2, 0xf0a7c7e1318d569c, 0xf0a7c7e1318d569d, 0xf39b2f5fec45f0ca, 0xf39b2f5fec45f0cb, 0xa181e7d66f5ff794, 0xa181e7d66f5ff795, 0xa2bd0f68b29751c2, 0xa2bd0f68b29751c3, 0xfc507fc9c3fd9646, 0xfc507fc9c3fd9647, 0xff6c97771e353010, 0xff6c97771e353011, 0xad765ffe9d2f374e, 0xad765ffe9d2f374f, 0xae4ab74040e79118, 0xae4ab74040e79119, 0xf0ce1ca953576a47, 0xf0ce1ca953576a46, 0xf3f2f4178e9fcc11, 0xf3f2f4178e9fcc10, 0xa1e83c9e0d85cb4f, 0xa1e83c9e0d85cb4e, 0xa2d4d420d04d6d19, 0xa2d4d420d04d6d18, 0x461f4311ebfce0da, 0x461f4311ebfce0db, 0x4523abaf3634468c, 0x4523abaf3634468d, 0x17396326b52e41d2, 0x17396326b52e41d3, 0x14058b9868e6e784, 0x14058b9868e6e785, 0x4a8120717b561cdb, 0x4a8120717b561cda, 0x49bdc8cfa69eba8d, 0x49bdc8cfa69eba8c, 0x1ba700462584bdd3, 0x1ba700462584bdd2, 0x189be8f8f84c1b85, 0x189be8f8f84c1b84, 0x4418ae808b28bdd0, 0x4418ae808b28bdd1, 0x4724463e56e01b86, 0x4724463e56e01b87, 0x153e8eb7d5fa1cd8, 0x153e8eb7d5fa1cd9, 0x160266090832ba8e, 0x160266090832ba8f, 0x4886cde01b8241d1, 0x4886cde01b8241d0, 0x4bba255ec64ae787, 0x4bba255ec64ae786, 0x19a0edd74550e0d9, 0x19a0edd74550e0d8, 0x1a9c05699898468f, 0x1a9c05699898468e, 0xfe579258a329cb4c, 0xfe579258a329cb4d, 0xfd6b7ae67ee16d1a, 0xfd6b7ae67ee16d1b, 0xaf71b26ffdfb6a44, 0xaf71b26ffdfb6a45, 0xac4d5ad12033cc12, 0xac4d5ad12033cc13, 0xf2c9f1383383374d, 0xf2c9f1383383374c, 0xf1f51986ee4b911b, 0xf1f51986ee4b911a, 0xa3efd10f6d519645, 0xa3efd10f6d519644, 0xa0d339b1b0993013, 0xa0d339b1b0993012, 0xfe3e4910c1f3f797, 0xfe3e4910c1f3f796, 0xfd02a1ae1c3b51c1, 0xfd02a1ae1c3b51c0, 0xaf1869279f21569f, 0xaf1869279f21569e, 0xac24819942e9f0c9, 0xac24819942e9f0c8, 0xf2a02a7051590b96, 0xf2a02a7051590b97, 0xf19cc2ce8c91adc0, 0xf19cc2ce8c91adc1, 0xa3860a470f8baa9e, 0xa3860a470f8baa9f, 0xa0bae2f9d2430cc8, 0xa0bae2f9d2430cc9, 0x447175c8e9f2810b, 0x447175c8e9f2810a, 0x474d9d76343a275d, 0x474d9d76343a275c, 0x155755ffb7202003, 0x155755ffb7202002, 0x166bbd416ae88655, 0x166bbd416ae88654, 0x48ef16a879587d0a, 0x48ef16a879587d0b, 0x4bd3fe16a490db5c, 0x4bd3fe16a490db5d, 0x19c9369f278adc02, 0x19c9369f278adc03, 0x1af5de21fa427a54, 0x1af5de21fa427a55, 0x026e36d9020e61d1, 0x026e36d9020e61d0, 0x0152de67dfc6c787, 0x0152de67dfc6c786, 0x534816ee5cdcc0d9, 0x534816ee5cdcc0d8, 0x5074fe508114668f, 0x5074fe508114668e, 0x0ef055b992a49dd0, 0x0ef055b992a49dd1, 0x0dccbd074f6c3b86, 0x0dccbd074f6c3b87, 0x5fd6758ecc763cd8, 0x5fd6758ecc763cd9, 0x5cea9d3011be9a8e, 0x5cea9d3011be9a8f, 0xb8210a012a0f174d, 0xb8210a012a0f174c, 0xbb1de2bff7c7b11b, 0xbb1de2bff7c7b11a, 0xe9072a3674ddb645, 0xe9072a3674ddb644, 0xea3bc288a9151013, 0xea3bc288a9151012, 0xb4bf6961baa5eb4c, 0xb4bf6961baa5eb4d, 0xb78381df676d4d1a, 0xb78381df676d4d1b, 0xe5994956e4774a44, 0xe5994956e4774a45, 0xe6a5a1e839bfec12, 0xe6a5a1e839bfec13, 0xb848d14948d52b96, 0xb848d14948d52b97, 0xbb7439f7951d8dc0, 0xbb7439f7951d8dc1, 0xe96ef17e16078a9e, 0xe96ef17e16078a9f, 0xea5219c0cbcf2cc8, 0xea5219c0cbcf2cc9, 0xb4d6b229d87fd797, 0xb4d6b229d87fd796, 0xb7ea5a9705b771c1, 0xb7ea5a9705b771c0, 0xe5f0921e86ad769f, 0xe5f0921e86ad769e, 0xe6cc7aa05b65d0c9, 0xe6cc7aa05b65d0c8, 0x0207ed9160d45d0a, 0x0207ed9160d45d0b, 0x013b052fbd1cfb5c, 0x013b052fbd1cfb5d, 0x5321cda63e06fc02, 0x5321cda63e06fc03, 0x501d2518e3ce5a54, 0x501d2518e3ce5a55, 0x0e998ef1f07ea10b, 0x0e998ef1f07ea10a, 0x0da5664f2db6075d, 0x0da5664f2db6075c, 0x5fbfaec6aeac0003, 0x5fbfaec6aeac0002, 0x5c8346787364a655, 0x5c8346787364a654];


impl GF2p64Subfield for GF8 {
    fn embed(self) -> GF2p64 {
        return GF2p64(GF8_EB_TABLE[self.0 as usize])
    }
}

const GF4_EB_TABLE: [u64; 16] = [0x0000000000000000, 0x0000000000000001, 0xa181e7d66f5ff794, 0xa181e7d66f5ff795, 0xb848d14948d52b96, 0xb848d14948d52b97, 0x19c9369f278adc02, 0x19c9369f278adc03, 0xfc39a481a127aa9d, 0xfc39a481a127aa9c, 0x5db84357ce785d09, 0x5db84357ce785d08, 0x447175c8e9f2810b, 0x447175c8e9f2810a, 0xe5f0921e86ad769f, 0xe5f0921e86ad769e];

impl GF2p64Subfield for GF4 {
    fn embed(self) -> GF2p64 {
        return GF2p64(GF4_EB_TABLE[self.as_u8() as usize])
    }
}

#[cfg(test)]
mod test {
    use crate::share::{gf2p64::GF2p64Subfield, gf4::GF4, gf8::GF8, Field, Invertible};

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

    #[test]
    fn test_gf8_embedding() {
        for i in 0..255 {
            let x = GF8(i);
            for j in 0..255 {
                let y = GF8(j);
                assert_eq!((x+y).embed(), x.embed() + y.embed());
                assert_eq!((x*y).embed(), x.embed() * y.embed())
            }
        }
    }

    #[test]
    fn test_gf4_embedding() {
        for i in 0..16 {
            let x = GF4::new_unchecked(i);
            for j in 0..16 {
                let y = GF4::new_unchecked(j);
                assert_eq!((x+y).embed(), x.embed() + y.embed());
                assert_eq!((x*y).embed(), x.embed() * y.embed())
            }
        }
    }

}
