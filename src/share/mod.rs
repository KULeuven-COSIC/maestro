pub mod gf8;
mod gf8_tables;
pub mod gf4;
pub mod wol;

use std::io;
use std::ops::{Add, Mul, Neg, Sub};

pub trait Field: Default + Add<Output=Self> + Sub<Output=Self> + Mul<Output=Self> + Neg<Output=Self> + Clone + Copy  { // + AsRef<[u8]>
    /// Returns the field size in byte
    fn size() -> usize;
    /// Returns zero value
    fn zero() -> Self;

    // Returns if the value is zero
    fn is_zero(&self) -> bool;

    fn as_byte_vec<'a, I: IntoIterator<Item=&'a Self>>(it: I) -> Vec<u8> where Self: 'a;

    fn from_byte_vec(v: Vec<u8>) -> Vec<Self>;

    fn from_byte_slice(v: Vec<u8>, dest: &mut [Self]);
}

pub trait FieldVectorCommChannel<F: Field> {
    fn write_vector(&mut self, vector: &[F]) -> io::Result<()>;
    fn read_vector(&mut self, buffer: &mut [F]) -> io::Result<()>;
}

#[derive(Clone)]
pub struct RssShare<F: Field> {
    pub si: F,
    pub sii: F
}

impl<F: Field> RssShare<F> {
    pub fn from(si: F, sii: F) -> Self {
        Self {si,sii}
    }

}

impl<F: Field> Add<Self> for RssShare<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        RssShare {
            si: self.si + rhs.si,
            sii: self.sii + rhs.sii
        }
    }
}

impl<F: Field> Sub<Self> for RssShare<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        RssShare {
            si: self.si - rhs.si,
            sii: self.sii - rhs.sii
        }
    }
}

impl<F: Field> Mul<F> for RssShare<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        RssShare {
            si: self.si * rhs.clone(),
            sii:self.sii * rhs
        }
    }
}

impl<F: Field+Copy> Copy for RssShare<F> {}

pub trait FieldRngExt<F: Field> {
    fn generate(&mut self, n: usize) -> Vec<F>;
    fn fill(&mut self, buf: &mut [F]);
}

pub trait FieldDigestExt<F: Field> {
    fn update(&mut self, message: &[F]);
}

#[cfg(test)]
pub mod test {
    use std::fmt::Debug;
    use rand::{CryptoRng, Rng, thread_rng};
    use crate::share::gf4::GF4;
    use crate::share::{Field, FieldRngExt, RssShare};
    use crate::share::gf8::GF8;

    pub fn consistent<F: Field + PartialEq + Debug>(share1: &RssShare<F>, share2: &RssShare<F>, share3: &RssShare<F>) {
        assert_eq!(share1.sii, share2.si);
        assert_eq!(share2.sii, share3.si);
        assert_eq!(share3.sii, share1.si);
    }

    pub fn assert_eq<F: Field + PartialEq + Debug>(share1: RssShare<F>, share2: RssShare<F>, share3: RssShare<F>, value: F) {
        let actual = share1.si + share2.si + share3.si;
        assert_eq!(actual, value);
    }

    pub fn secret_share<F: Field, R: Rng + CryptoRng + FieldRngExt<F>>(rng: &mut R, x: &F) -> (RssShare<F>, RssShare<F>, RssShare<F>) {
        let r = rng.generate(2);
        let x1 = RssShare::from(x.clone() - r[0] - r[1], r[0]);
        let x2 = RssShare::from(r[0], r[1]);
        let x3 = RssShare::from(r[1], x.clone() - r[0] - r[1]);
        (x1,x2,x3)
    }

    #[test]
    fn cmul_gf8() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let x:Vec<GF8> = rng.generate(N);
        let c:Vec<GF8> = rng.generate(N);

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
        let x:Vec<GF4> = rng.generate(N);
        let c:Vec<GF4> = rng.generate(N);

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