use std::{borrow::Borrow, ops::{Add, AddAssign, Mul, Neg, Sub}};

use itertools::Itertools;
use rand::{CryptoRng, Rng};
use sha2::Digest;

use crate::{party::{error::MpcResult, ArithmeticBlackBox}, share::{gf8::GF8, Field, FieldDigestExt, FieldRngExt, RssShare}};

// a bit-wise xor shared ring element mod 2^64
// encoded as little endian
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct Z64Bool(u64);

impl Field for Z64Bool {
    const NBYTES: usize = 8;

    fn serialized_size(n_elements: usize) -> usize {
        n_elements * Self::NBYTES
    }

    const ZERO: Self = Self(0);

    const ONE: Self = Self(1);

    fn is_zero(&self) -> bool {
        self.0 == 0
    }

    fn as_byte_vec(it: impl IntoIterator<Item= impl Borrow<Self>>, _len: usize) -> Vec<u8> {
        it.into_iter().flat_map(|z64| z64.borrow().to_owned().0.to_le_bytes().into_iter()).collect()
    }
    fn from_byte_slice(v: Vec<u8>, dest: &mut [Self]) {
        debug_assert!(v.len() % 8 == 0);
        debug_assert_eq!(dest.len()*8, v.len());
        dest.iter_mut().zip(v.into_iter().chunks(8).into_iter()).for_each(|(dst, mut chunk)| {
            let (b0,b1,b2,b3,b4,b5,b6,b7) = chunk.next_tuple().unwrap();
            *dst = Self(u64::from_le_bytes([b0,b1,b2,b3,b4,b5,b6,b7]));
        });
    }

    fn from_byte_vec(v: Vec<u8>, _len: usize) -> Vec<Self> {
        v.into_iter().chunks(8).into_iter().map(|mut chunk| {
            let (b0,b1,b2,b3,b4,b5,b6,b7) = chunk.next_tuple().unwrap();
            Self(u64::from_le_bytes([b0,b1,b2,b3,b4,b5,b6,b7]))
        }).collect()
    }
}

impl Neg for Z64Bool {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(!self.0)
    }
}
impl Mul for Z64Bool {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}
impl Add for Z64Bool {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}
impl AddAssign for Z64Bool {
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}
impl Sub for Z64Bool {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl<R: Rng + CryptoRng> FieldRngExt<Z64Bool> for R {
    fn fill(&mut self, buf: &mut [Z64Bool]) {
        for b in buf {
            b.0 = self.next_u64().to_le()
        }
    }
    fn generate(&mut self, n: usize) -> Vec<Z64Bool> {
        let mut v = vec![Z64Bool::ZERO; n];
        <Self as FieldRngExt<Z64Bool>>::fill(self, &mut v);
        v
    }
}

impl<D: Digest> FieldDigestExt<Z64Bool> for D {
    fn update(&mut self, message: &[Z64Bool]) {
        for m in message {
            self.update(&m.0.to_le_bytes());
        }
    }
}

// impl FieldVectorCommChannel<Z64Bool> for CommChannel {
//     fn write_vector(&mut self, vector: &[Z64Bool]) -> std::io::Result<()> {
//         let mut buf = vec![0u8; 8*vector.len()];
//         for (i,v) in vector.iter().enumerate() {
//             let bytes = v.0.to_le_bytes();
//             buf[8*i..8*i+8].copy_from_slice(&bytes);
//         }
//         self.write(&buf)
//     }
//     fn read_vector(&mut self, buffer: &mut [Z64Bool]) -> std::io::Result<()> {
//         let mut buf = vec![0u8; 8*buffer.len()];
//         self.read(&mut buf)?;
//         for (i, bytes) in buf.chunks_exact(8).enumerate() {
//             let mut arr = [0u8; 8];
//             arr.copy_from_slice(bytes);
//             buffer[i].0 = u64::from_le_bytes(arr);
//         }
//         Ok(())
//     }
// }

fn bit_slice(dst: &mut Vec<Z64Bool>, a: &[Z64Bool], index: usize) {
    dst.clear();
    let n_full = a.len() / 64;
    for i in 0..n_full {
        let mut el = 0u64;
        // we add reversed
        for j in (0..64).rev() {
            el <<= 1;
            el |= (a[64*i+j].0 >> index) & 0x1;
        }
        dst.push(Z64Bool(el));
    }
    let remainder = a.len() % 64;
    if remainder > 0 {
        let mut el = 0u64;
        // we add reversed
        for j in (0..remainder).rev() {
            el <<= 1;
            el |= (a[64*n_full+j].0 >> index) & 0x1;
        }
        dst.push(Z64Bool(el));
    }
}

fn unbit_slice(dst: &mut Vec<Z64Bool>, bitslice: &Vec<Z64Bool>, index: usize) {
    let n_full = dst.len() / 64;
    for i in 0..n_full {
        let mut bit = bitslice[i].0;
        for j in 0..64 {
            dst[64*i+j].0 |= (bit & 0x1) << index;
            bit >>= 1;
        }
    }
    let remainder = dst.len() % 64;
    if remainder > 0 {
        let mut bit = bitslice[n_full].0;
        for j in 0..remainder {
            dst[64*n_full+j].0 |= (bit & 0x1) << index;
            bit >>= 1;
        }
    }
}

fn conv_neg<'a>(it: impl Iterator<Item=&'a Z64Bool>) -> Vec<u64> {
    it.map(|el| {
        let neg = -i64::from_le(el.0 as i64);
        neg as u64
    }).collect()
}

fn conv<'a>(it: impl Iterator<Item=&'a Z64Bool>) -> Vec<u64> {
    it.map(|el| u64::from_le(el.0)).collect()
}

/// Converts RSS shares of bytes (that are shared via XOR) into RSS shares in Z_64 (the integers mod 2^64)
/// 8 consecutive bytes are grouped and interpreted as Z_64 element in little endian order; the last group is padded with zero
/// i.e. let b0, ..., b7, b8, b9 be the bytes in that order in the iterator
/// then two elements are created z1 = (b0 b1 ... b7) and z2 = (b8 b9 0 ... 0)
/// for each element, this function outputs a respective share z_1, z_2 and z_3, respectively
/// s.t. z_1 + z_2 + z_3 = (b0_1 b1_1 ... b7_1) XOR (b0_2 b1_2 ... b7_2) XOR (b0_3 b1_3 ... b7_3)
/// where '+' is addition in the ring
pub fn convert_boolean_to_ring<Protocol: ArithmeticBlackBox<Z64Bool>>(party: &mut Protocol, party_index: usize, bytes: impl Iterator<Item = RssShare<GF8>>) -> MpcResult<(Vec<u64>,Vec<u64>)> {
    // convert bytes into Z64 using little endian
    let (el_si, el_sii): (Vec<_>, Vec<_>) = bytes.chunks(8).into_iter().map(|chunk| {
        let chunk: Vec<_> = chunk.collect();
        let mut bytes_si = [0u8; 8];
        let mut bytes_sii = [0u8; 8];
        for (i, rss) in chunk.iter().enumerate() {
            bytes_si[i] = rss.si.0;
            bytes_sii[i] = rss.sii.0;
        }
        (Z64Bool(u64::from_le_bytes(bytes_si)), Z64Bool(u64::from_le_bytes(bytes_sii)))
    }).unzip();
    // draw two random values r1, r2
    let n = el_si.len();
    let r1: (Vec<_>, Vec<_>) = party.generate_random(n).into_iter().map(|rss| (rss.si, rss.sii)).unzip();
    let r2: (Vec<_>, Vec<_>) = party.generate_random(n).into_iter().map(|rss| (rss.si, rss.sii)).unzip();
    // compute el + r1 + r2
    let (tmp_i, tmp_ii) = ripple_carry_adder(party, &el_si, &el_sii, &r1.0, &r1.1)?;
    let (r3_i, r3_ii) = ripple_carry_adder(party, &tmp_i, &tmp_ii, &r2.0, &r2.1)?;

    // to_p1 = r1||r2
    let to_p1 = r1.0.iter().zip(&r1.1)
        .chain(r2.0.iter().zip(&r2.1))
        .map(|(si, sii)| RssShare::from(*si, *sii))
        .collect_vec();
    // to_p2 = r2||r3
    let to_p2 = r2.0.iter().zip(&r2.1)
        .chain(r3_i.iter().zip(&r3_ii))
        .map(|(si, sii)| RssShare::from(*si, *sii))
        .collect_vec();
    // to_p3 = r3||r1
    let to_p3 = r3_i.into_iter().zip(r3_ii)
        .chain(r1.0.into_iter().zip(r1.1))
        .map(|(si, sii)| RssShare::from(si, sii))
        .collect_vec();
    // open r1 to P1, r2 to P2, r3 to P3
    let my_share = party.output_to(&to_p1, &to_p2, &to_p3)?;
    let si = my_share.iter().take(n);
    let sii = my_share.iter().skip(n);
    // negate r1, r2 locally
    Ok(match party_index {
        0 => (conv_neg(si), conv_neg(sii)),
        1 => (conv_neg(si), conv(sii)),
        2 => (conv(si), conv_neg(sii)),
        _ => unreachable!()
    })
}

fn rss_zero(n: usize) -> (Vec<Z64Bool>, Vec<Z64Bool>) {
    (vec![Z64Bool::ZERO; n], vec![Z64Bool::ZERO; n])
}

fn rss_pos<'a>(it: impl Iterator<Item=u64>, first: bool) -> (Vec<Z64Bool>, Vec<Z64Bool>) {
    it.map(move |el| {
        if first {
            (Z64Bool(el.to_le()), Z64Bool::ZERO)
        }else{
            (Z64Bool::ZERO, Z64Bool(el.to_le()))
        }
    }).unzip()
}

pub fn convert_ring_to_boolean<Protocol: ArithmeticBlackBox<Z64Bool>>(party: &mut Protocol, party_index: usize, elements_si: &[u64], elements_sii: &[u64]) -> MpcResult<Vec<RssShare<GF8>>> {
    // convert shares locally
    let si: (Vec<_>, Vec<_>) = rss_pos(elements_si.iter().copied(), true);
    let sii: (Vec<_>, Vec<_>) = rss_pos(elements_sii.iter().copied(), false);
    let (s1, s2, s3) = match party_index {
        0 => (si, sii, rss_zero(elements_si.len())),
        1 => (rss_zero(elements_si.len()), si, sii),
        2 => (sii, rss_zero(elements_si.len()), si),
        _ => unreachable!()
    };

    let tmp = ripple_carry_adder(party, &s1.0, &s1.1, &s2.0, &s2.1)?;
    let res = ripple_carry_adder(party, &tmp.0, &tmp.1, &s3.0, &s3.1)?;

    Ok(res.0.into_iter().zip(res.1).map(|(si, sii)| {
        let bi = si.0.to_le_bytes();
        let bii = sii.0.to_le_bytes();
        (0..8).map(move |i| RssShare::from(GF8(bi[i]), GF8(bii[i])))
    }).flatten().collect())

}


fn ripple_carry_adder<Protocol: ArithmeticBlackBox<Z64Bool>>(party: &mut Protocol, a_i: &[Z64Bool], a_ii: &[Z64Bool], b_i: &[Z64Bool], b_ii: &[Z64Bool]) -> MpcResult<(Vec<Z64Bool>,Vec<Z64Bool>)> {
    debug_assert_eq!(a_i.len(), a_ii.len());
    debug_assert_eq!(a_i.len(), b_i.len());
    debug_assert_eq!(a_i.len(), b_ii.len());
    
    let mut carry_si = vec![Z64Bool::ZERO; a_i.len() / 64 + 1];
    let mut carry_sii = vec![Z64Bool::ZERO; a_i.len() / 64 + 1];
    let mut slice_a_i = vec![Z64Bool::ZERO; a_i.len() / 64 + 1];
    let mut slice_a_ii = vec![Z64Bool::ZERO; a_i.len() / 64 + 1];
    let mut slice_b_i = vec![Z64Bool::ZERO; a_i.len() / 64 + 1];
    let mut slice_b_ii = vec![Z64Bool::ZERO; a_i.len() / 64 + 1];
    let mut slice_c_i = vec![Z64Bool::ZERO; a_i.len() / 64 + 1];
    let mut slice_c_ii = vec![Z64Bool::ZERO; a_i.len() / 64 + 1];

    let mut result_i = vec![Z64Bool::ZERO; a_i.len()];
    let mut result_ii = vec![Z64Bool::ZERO; a_i.len()];
    for i in 0..64 {
        bit_slice(&mut slice_a_i, a_i, i);
        bit_slice(&mut slice_a_ii, a_ii, i);
        bit_slice(&mut slice_b_i, b_i, i);
        bit_slice(&mut slice_b_ii, b_ii, i);
        let n = slice_a_i.len();
        // c[i] = a[i] XOR b[i] XOR carry[i-1]
        //carry[i] = (a[i] XOR carry[i-1]) AND (b[i] XOR carry[i-1]) XOR carry[i-1]
        for j in 0..n {
            slice_c_i[j] = slice_a_i[j] + slice_b_i[j] + carry_si[j];
            slice_c_ii[j] = slice_a_ii[j] + slice_b_ii[j] + carry_sii[j];

            slice_a_i[j] += carry_si[j];
            slice_a_ii[j] += carry_sii[j];
            slice_b_i[j] += carry_si[j];
            slice_b_ii[j] += carry_sii[j];
        }
        unbit_slice(&mut result_i, &slice_c_i, i);
        unbit_slice(&mut result_ii, &slice_c_ii, i);
        party.mul(&mut slice_c_i, &mut slice_c_ii, &slice_a_i, &slice_a_ii, &slice_b_i, &slice_b_ii)?;
        for j in 0..n {
            carry_si[j] += slice_c_i[j];
            carry_sii[j] += slice_c_ii[j];
        }
    }


    Ok((result_i, result_ii))
}


#[cfg(test)]
pub mod test {
    use itertools::{izip, Itertools};
    use rand::{thread_rng, CryptoRng, Rng};
    use crate::share::Field;
    use crate::{chida::online::test::ChidaSetup, conversion::{convert_boolean_to_ring, convert_ring_to_boolean, ripple_carry_adder}, party::{test::TestSetup, ArithmeticBlackBox}, share::{gf8::GF8, test::{consistent_vector, secret_share_vector}, FieldRngExt, RssShare}};

    use super::{bit_slice, unbit_slice, Z64Bool};


    #[test]
    fn bitslicing() {
        let mut rng = thread_rng();
        let mut slices = (0..64).map(|_| Vec::<Z64Bool>::new()).collect_vec();
        for n in vec![1, 5, 64, 100, 128, 196, 200] {
            let el: Vec<Z64Bool> = rng.generate(n);
            // bit-slice
            for (i, slice) in slices.iter_mut().enumerate() {
                bit_slice(slice, &el, i);
            }
            // undo
            let mut actual = vec![Z64Bool::ZERO; n];
            for (i, slice) in slices.iter().enumerate() {
                unbit_slice(&mut actual, slice, i)
            }
            assert_eq!(el, actual);
        }
    }

    fn random_u64<R: Rng + CryptoRng>(rng: &mut R, n: usize) -> Vec<u64> {
        (0..n).map(|_| rng.next_u64()).collect()
    }

    fn ripple_carry_adder_u64<P: ArithmeticBlackBox<Z64Bool>, S: TestSetup<P>>(setup: S) {
        let mut rng = thread_rng();
        const N: usize = 100;
        let a = random_u64(&mut rng, N);
        let b = random_u64(&mut rng, N);

        let a_shares = secret_share_vector(&mut rng, a.iter().map(|v| Z64Bool(*v)));
        // consistent_vector(&a_shares.0, &a_shares.1, &a_shares.2);
        let b_shares = secret_share_vector(&mut rng, b.iter().map(|v| Z64Bool(*v)));
        // consistent_vector(&b_shares.0, &b_shares.1, &b_shares.2);

        let program = |a: Vec<RssShare<Z64Bool>>, b: Vec<RssShare<Z64Bool>>| {
            move |p: &mut P| {
                let (a_i, a_ii): (Vec<_>, Vec<_>) = a.into_iter().map(|rss| (rss.si, rss.sii)).unzip();
                let (b_i, b_ii): (Vec<_>, Vec<_>) = b.into_iter().map(|rss| (rss.si, rss.sii)).unzip();
                ripple_carry_adder(p, &a_i, &a_ii, &b_i, &b_ii).unwrap()
            }
        };

        let (h1, h2, h3) = S::localhost_setup(program(a_shares.0, b_shares.0), program(a_shares.1, b_shares.1), program(a_shares.2, b_shares.2));
        let (res1, _) = h1.join().unwrap();
        let (res2, _) = h2.join().unwrap();
        let (res3, _) = h3.join().unwrap();

        let res1 = res1.0.into_iter().zip_eq(res1.1).map(|(si, sii)| RssShare::from(si, sii)).collect_vec();
        let res2 = res2.0.into_iter().zip_eq(res2.1).map(|(si, sii)| RssShare::from(si, sii)).collect_vec();
        let res3 = res3.0.into_iter().zip_eq(res3.1).map(|(si, sii)| RssShare::from(si, sii)).collect_vec();

        consistent_vector(&res1, &res2, &res3);
        assert_eq!(a.len(), res1.len());
        assert_eq!(a.len(), res2.len());
        assert_eq!(a.len(), res3.len());

        for (r1, r2, r3, ai, bi) in izip!(res1, res2, res3, a, b) {
            // reconstruct
            let c = r1.si + r2.si + r3.si;
            assert_eq!(ai.overflowing_add(bi).0, c.0);
        }
    }

    #[test]
    fn ripple_carry_adder_u64_chida() {
        ripple_carry_adder_u64(ChidaSetup)
    }

    fn consistent_u64(s1i: &[u64], s1ii: &[u64], s2i: &[u64], s2ii: &[u64], s3i: &[u64], s3ii: &[u64]) {
        assert_eq!(s1i.len(), s1ii.len());
        assert_eq!(s1i.len(), s2i.len());
        assert_eq!(s1i.len(), s2ii.len());
        assert_eq!(s1i.len(), s3i.len());
        assert_eq!(s1i.len(), s3ii.len());

        assert_eq!(s1i, s3ii);
        assert_eq!(s1ii, s2i);
        assert_eq!(s2ii, s3i);
    }

    fn conv_bool_to_ring<P: ArithmeticBlackBox<Z64Bool>, S: TestSetup<P>>(setup: S) {
        let mut rng = thread_rng();
        const N: usize = 100;
        let a = random_u64(&mut rng, N);
        let a_as_le_bytes = a.iter().map(|ai| ai.to_le_bytes().into_iter()).flatten().map(|b| GF8(b)).collect_vec();
        let shares = secret_share_vector(&mut rng, a_as_le_bytes.into_iter());
        let program = |share: Vec<RssShare<GF8>>, i: usize| {
            move |p: &mut P| {
                convert_boolean_to_ring(p, i, share.into_iter()).unwrap()
            }
        };
        let (h1, h2, h3) = S::localhost_setup(program(shares.0, 0), program(shares.1, 1), program(shares.2, 2));
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap();

        assert_eq!(a.len(), r1.0.len());
        consistent_u64(&r1.0, &r1.1, &r2.0, &r2.1, &r3.0, &r3.1);

        for (ai, r1i, r2i, r3i) in izip!(a, r1.0, r2.0, r3.0) {
            assert_eq!(ai, r1i.overflowing_add(r2i).0.overflowing_add(r3i).0);
        }
    }

    #[test]
    fn conv_bool_to_ring_chida() {
        conv_bool_to_ring(ChidaSetup)
    }

    pub fn secret_share_vector_ring<R: Rng + CryptoRng>(rng: &mut R, values: &[u64]) -> (Vec<u64>,Vec<u64>,Vec<u64>) {
        let s1 = random_u64(rng, values.len());
        let s2 = random_u64(rng, values.len());
        let s3 = izip!(values, &s1, &s2).map(|(v, r1, r2)| v.overflowing_sub(*r1).0.overflowing_sub(*r2).0).collect_vec();
        (s1, s2, s3)
    }

    fn conv_ring_to_bool<P: ArithmeticBlackBox<Z64Bool>, S: TestSetup<P>>(setup: S) {
        let mut rng = thread_rng();
        const N: usize = 100;
        let a = random_u64(&mut rng, N);
        let shares = secret_share_vector_ring(&mut rng, &a);

        let program = |share_i: Vec<u64>, share_ii: Vec<u64>, i: usize| {
            move |p: &mut P| {
                convert_ring_to_boolean(p, i,&share_i, &share_ii).unwrap()
            }
        };
        let (h1,h2,h3) = S::localhost_setup(program(shares.0.clone(), shares.1.clone(), 0), program(shares.1, shares.2.clone(), 1), program(shares.2, shares.0, 2));
        let (b1, _) = h1.join().unwrap();
        let (b2, _) = h2.join().unwrap();
        let (b3, _) = h3.join().unwrap();

        assert_eq!(8*a.len(), b1.len());
        assert_eq!(8*a.len(), b2.len());
        assert_eq!(8*a.len(), b3.len());
        consistent_vector(&b1, &b2, &b3);
        for (ai, b1i, b2i, b3i) in izip!(a, b1.chunks_exact(8), b2.chunks_exact(8), b3.chunks_exact(8)) {
            let b = izip!(b1i, b2i, b3i).map(|(x1, x2, x3)| (x1.si + x2.si + x3.si).0).collect_vec();
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&b);
            assert_eq!(ai.to_le_bytes(), arr);
        }
    }

    #[test]
    fn conv_ring_to_bool_chida() {
        conv_ring_to_bool(ChidaSetup)
    }
}