//! This module provides implementations of various finite [Field]s and replicated secret sharing.
//!
//! The provided field operations are **not constant-time**.
pub mod bs_bool16;
pub mod gf2p64;
pub mod gf4;
mod gf4_bs_table;
pub mod gf8;
mod gf8_tables;
pub mod wol;

use std::ops::{Add, AddAssign, Mul, Neg, Sub};

use crate::rep3_core::network::NetSerializable;
use crate::rep3_core::party::RngExt;
use crate::rep3_core::share::{HasZero, RssShare};

/// A finite field.
pub trait Field:
    Default
    + HasZero
    + NetSerializable
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + Clone
    + Copy
    + PartialEq
    + AddAssign
    + RngExt
{
    // + AsRef<[u8]>
    /// The field size in byte
    const NBYTES: usize;

    // /// Returns the size in byte of a serialization of n_elements many field elements
    // fn serialized_size(n_elements: usize) -> usize;

    /// The field size in bits
    const NBITS: usize = 8 * Self::NBYTES;

    // /// Zero the neutral element of addition
    // const ZERO: Self;

    /// One the neutral element of multiplication
    const ONE: Self;

    /// Returns if the value is zero
    fn is_zero(&self) -> bool;

    // /// Serializes the field elements
    // fn as_byte_vec(it: impl IntoIterator<Item = impl Borrow<Self>>, len: usize) -> Vec<u8>;

    // /// Deserializes field elements from a byte vector
    // fn from_byte_vec(v: Vec<u8>, len: usize) -> Vec<Self>;

    // /// Deserializes field elements from a byte vector into a slice
    // fn from_byte_slice(v: Vec<u8>, dest: &mut [Self]);
}

/// Field that provide a method to compute multiplicative inverses.
pub trait Invertible: Field {
    /// Multiplicative Inverse (zero may map to zero)
    fn inverse(self) -> Self;
}

/// Extension field of `GF(2)` that provides `2` as a constant.
pub trait HasTwo: Field {
    /// The polynomial `X` of degree `1` in the field over `GF(2)`,
    /// i.e.,  `2` if one considers a binary representation of field elements.
    const TWO: Self;
}

/// Field that provides methods to compute inner products.
pub trait InnerProduct: Field {
    /// Computes the dot product of vectors `x` and `y`.
    ///
    /// This function assumes that both vectors are of equal length.
    fn inner_product(a: &[Self], b: &[Self]) -> Self;

    /// Computes the (weak) dot product of replicated sharing vectors `[[x]]` and `[[y]]`.
    ///
    /// The result is a sum sharing of the inner product.
    /// This function assumes that both vectors are of equal length.    
    fn weak_inner_product(a: &[RssShare<Self>], b: &[RssShare<Self>]) -> Self;

    /// Computes the dot product of vectors x and y given as replicated shares 
    /// considering only elements at even positions (0,2,4,6,...).
    /// The result is a sum sharing.
    ///
    /// This function assumes that both vectors are of equal length.    
    fn weak_inner_product2(a: &[RssShare<Self>], b: &[RssShare<Self>]) -> Self;

    /// Computes the dot product of vectors x' and y' where
    /// `
    /// x'[i] = x[2i] + (x[2i] + x[2i+1])* Self::TWO, and
    /// y'[i] = y[2i] + (y[2i] + y[2i+1])* Self::TWO
    /// `
    /// and x, y are given as replicated shares.
    fn weak_inner_product3(a: &[RssShare<Self>], b: &[RssShare<Self>]) -> Self;
}

#[cfg(any(test, feature = "benchmark-helper"))]
pub mod test {
    use crate::share::gf4::GF4;
    use crate::share::gf8::GF8;
    use rand::{thread_rng, CryptoRng, Rng};
    use crate::rep3_core::party::RngExt;
    use crate::rep3_core::share::{RssShare, RssShareVec};
    use std::borrow::Borrow;
    use std::fmt::Debug;
    use itertools::Itertools;

    use super::Field;

    pub fn consistent<F: Field + Debug>(
        share1: &RssShare<F>,
        share2: &RssShare<F>,
        share3: &RssShare<F>,
    ) {
        assert_eq!(
            share1.sii, share2.si,
            "share1 and share2 are inconsistent: share1={:?}, share2={:?}, share3={:?}",
            share1, share2, share3
        );
        assert_eq!(
            share2.sii, share3.si,
            "share2 and share3 are inconsistent: share1={:?}, share2={:?}, share3={:?}",
            share1, share2, share3
        );
        assert_eq!(
            share3.sii, share1.si,
            "share1 and share3 are inconsistent: share1={:?}, share2={:?}, share3={:?}",
            share1, share2, share3
        );
    }

    pub fn assert_eq<F: Field + Debug>(
        share1: RssShare<F>,
        share2: RssShare<F>,
        share3: RssShare<F>,
        value: F,
    ) {
        let actual = share1.si + share2.si + share3.si;
        assert_eq!(actual, value, "Expected {:?}, got {:?}", value, actual);
    }

    pub fn consistent_vector<F: Field + PartialEq + Debug>(share1: &[RssShare<F>], share2: &[RssShare<F>], share3: &[RssShare<F>]) {
        assert_eq!(share1.len(), share2.len());
        assert_eq!(share1.len(), share3.len());
        for (s1, (s2,s3)) in share1.iter().zip(share2.iter().zip(share3)) {
            consistent(s1, s2, s3);
        }
    }

    pub fn assert_eq_vector<F: Field + Debug>(share1: impl IntoIterator<Item=RssShare<F>>, share2: impl IntoIterator<Item=RssShare<F>>, share3: impl IntoIterator<Item=RssShare<F>>, values: impl IntoIterator<Item=F>) {
        for (s1, (s2, (s3, v))) in share1.into_iter().zip_eq(share2.into_iter().zip_eq(share3.into_iter().zip_eq(values))) {
            assert_eq(s1, s2, s3, v);
        }
    }

    pub fn secret_share<F: Field, R: Rng + CryptoRng>(
        rng: &mut R,
        x: &F,
    ) -> (RssShare<F>, RssShare<F>, RssShare<F>) {
        let r = F::generate(rng, 2);
        let x1 = RssShare::from(x.clone() - r[0] - r[1], r[0]);
        let x2 = RssShare::from(r[0], r[1]);
        let x3 = RssShare::from(r[1], x.clone() - r[0] - r[1]);
        (x1, x2, x3)
    }

    pub fn secret_share_vector<F: Field, R: Rng + CryptoRng>(
        rng: &mut R,
        elements: impl IntoIterator<Item = impl Borrow<F>>,
    ) -> (RssShareVec<F>, RssShareVec<F>, RssShareVec<F>) {
        let (s1, (s2, s3)) = elements
            .into_iter()
            .map(|value| {
                let (s1, s2, s3) = secret_share(rng, value.borrow());
                (s1, (s2, s3))
            })
            .unzip();
        (s1, s2, s3)
    }

    pub fn random_secret_shared_vector<F: Field>(
        n: usize,
    ) -> (Vec<F>, RssShareVec<F>, RssShareVec<F>, RssShareVec<F>) {
        let mut rng = thread_rng();
        let x: Vec<F> = RngExt::generate(&mut rng, n);
        let (s1, s2, s3) = secret_share_vector(&mut rng, x.iter());

        (x, s1, s2, s3)
    }

    #[test]
    fn cmul_gf8() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let x: Vec<GF8> = GF8::generate(&mut rng, N);
        let c: Vec<GF8> = GF8::generate(&mut rng, N);

        for i in 0..N {
            let (x1, x2, x3) = secret_share::<GF8, _>(&mut rng, &x[i]);
            let cx1 = x1 * c[i].clone();
            let cx2 = x2 * c[i].clone();
            let cx3 = x3 * c[i].clone();

            consistent(&cx1, &cx2, &cx3);
            assert_eq(cx1, cx2, cx3, x[i] * c[i]);
        }
    }

    #[test]
    fn cmul_gf4() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let x: Vec<GF4> = GF4::generate(&mut rng, N);
        let c: Vec<GF4> = GF4::generate(&mut rng, N);

        for i in 0..N {
            let (x1, x2, x3) = secret_share(&mut rng, &x[i]);
            let cx1 = x1 * c[i].clone();
            let cx2 = x2 * c[i].clone();
            let cx3 = x3 * c[i].clone();

            consistent(&cx1, &cx2, &cx3);
            assert_eq(cx1, cx2, cx3, x[i] * c[i]);
        }
    }
}
