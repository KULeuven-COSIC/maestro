pub mod bs_bool16;
pub mod gf2p64;
pub mod gf4;
mod gf4_bs_table;
pub mod gf8;
mod gf8_tables;
pub mod wol;

use std::borrow::Borrow;
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Neg, Sub};

pub trait Field:
    Default
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + Clone
    + Copy
    + PartialEq
    + AddAssign
{
    // + AsRef<[u8]>
    /// The field size in byte
    const NBYTES: usize;

    /// Returns the size in byte of a serialization of n_elements many field elements
    fn serialized_size(n_elements: usize) -> usize;

    /// The field size in bits
    const NBITS: usize = 8 * Self::NBYTES;

    /// Zero the neutral element of addition
    const ZERO: Self;

    /// One the neutral element of multiplication
    const ONE: Self;

    // Returns if the value is zero
    fn is_zero(&self) -> bool;

    fn as_byte_vec(it: impl IntoIterator<Item = impl Borrow<Self>>, len: usize) -> Vec<u8>;

    fn from_byte_vec(v: Vec<u8>, len: usize) -> Vec<Self>;

    fn from_byte_slice(v: Vec<u8>, dest: &mut [Self]);
}

pub trait Invertible: Field {
    /// Multiplicative Inverse (zero may map to zero)
    fn inverse(self) -> Self;
}

pub trait HasTwo: Field {
    /// Multiplicative Inverse (zero may map to zero)
    const TWO: Self;
}

#[derive(Clone, Debug)]
pub struct RssShare<F: Field> {
    pub si: F,
    pub sii: F,
}

impl<F: Field> RssShare<F> {
    pub fn from(si: F, sii: F) -> Self {
        Self { si, sii }
    }

    pub fn mul_by_sc(self, scalar: F) -> Self {
        Self {
            si: self.si * scalar,
            sii: self.sii * scalar,
        }
    }
}

impl<F: Field> Add<Self> for RssShare<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        RssShare {
            si: self.si + rhs.si,
            sii: self.sii + rhs.sii,
        }
    }
}

impl<F: Field> Sub<Self> for RssShare<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        RssShare {
            si: self.si - rhs.si,
            sii: self.sii - rhs.sii,
        }
    }
}

impl<F: Field> Mul<F> for RssShare<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        RssShare {
            si: self.si * rhs.clone(),
            sii: self.sii * rhs,
        }
    }
}

impl<F: Field> AddAssign for RssShare<F> {
    fn add_assign(&mut self, rhs: Self) {
        self.si += rhs.si;
        self.sii += rhs.sii;
    }
}

impl<F: Field + Copy> Copy for RssShare<F> {}

pub trait FieldRngExt<F: Field> {
    fn generate(&mut self, n: usize) -> Vec<F>;
    fn fill(&mut self, buf: &mut [F]);
}

pub trait FieldDigestExt<F: Field> {
    fn update(&mut self, message: &[F]);
}

#[cfg(any(test, feature = "benchmark-helper"))]
pub mod test {
    use crate::share::gf4::GF4;
    use crate::share::gf8::GF8;
    use crate::share::{Field, FieldRngExt, RssShare};
    use rand::{rngs::ThreadRng, thread_rng, CryptoRng, Rng};
    use std::borrow::Borrow;
    use std::fmt::Debug;

    pub fn consistent<F: Field + PartialEq + Debug>(
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

    pub fn assert_eq<F: Field + PartialEq + Debug>(
        share1: RssShare<F>,
        share2: RssShare<F>,
        share3: RssShare<F>,
        value: F,
    ) {
        let actual = share1.si + share2.si + share3.si;
        assert_eq!(actual, value, "Expected {:?}, got {:?}", value, actual);
    }

    pub fn secret_share<F: Field, R: Rng + CryptoRng + FieldRngExt<F>>(
        rng: &mut R,
        x: &F,
    ) -> (RssShare<F>, RssShare<F>, RssShare<F>) {
        let r = rng.generate(2);
        let x1 = RssShare::from(x.clone() - r[0] - r[1], r[0]);
        let x2 = RssShare::from(r[0], r[1]);
        let x3 = RssShare::from(r[1], x.clone() - r[0] - r[1]);
        (x1, x2, x3)
    }

    pub fn secret_share_vector<F: Field, R: Rng + CryptoRng>(
        rng: &mut R,
        elements: impl IntoIterator<Item = impl Borrow<F>>,
    ) -> (Vec<RssShare<F>>, Vec<RssShare<F>>, Vec<RssShare<F>>)
    where
        R: FieldRngExt<F>,
    {
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
    ) -> (Vec<F>, Vec<RssShare<F>>, Vec<RssShare<F>>, Vec<RssShare<F>>)
    where
        ThreadRng: FieldRngExt<F>,
    {
        let mut rng = thread_rng();
        let x: Vec<F> = FieldRngExt::generate(&mut rng, n);
        let (s1, s2, s3) = secret_share_vector(&mut rng, x.iter());

        (x, s1, s2, s3)
    }

    #[test]
    fn cmul_gf8() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let x: Vec<GF8> = rng.generate(N);
        let c: Vec<GF8> = rng.generate(N);

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
        let x: Vec<GF4> = rng.generate(N);
        let c: Vec<GF4> = rng.generate(N);

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
