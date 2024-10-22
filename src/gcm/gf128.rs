use std::{borrow::Borrow, ops::{Add, AddAssign, Mul, Neg, Sub}};
use itertools::{izip, Itertools};
use ghash::{GHash, universal_hash::{KeyInit, UniversalHash}};
use rand::{Rng, CryptoRng};
use rayon::{iter::{IndexedParallelIterator, ParallelIterator}, slice::{ParallelSlice, ParallelSliceMut}};
use sha2::Digest;

use crate::{rep3_core::{network::NetSerializable, party::{DigestExt, RngExt}, share::{HasZero, RssShare}}, share::{gf2p64::{GF2p64, GF2p64InnerProd}, gf8::GF8, Field}, util::mul_triple_vec::{MulTripleEncoder, MulTripleVector}};

#[derive(Copy, Clone, Debug, PartialEq, Eq)] //, TransparentWrapper)]
#[repr(transparent)]
pub struct GF128([u8; 16]);

impl GF128 {
    pub fn into_gf8(self) -> Vec<GF8> {
        self.0.into_iter().map(|b| GF8(b)).collect()
    }

    /// Computes the isomorphism sending self to aX + b where a, b are [GF2p64] elements.
    /// Returns (a,b)
    pub fn into_gf2p64p2(self) -> (GF2p64, GF2p64) {
        let mut a = 0u64;
        let mut b = 0u64;
        let mut map_idx = 0;
        for i in 0..16 {
            for j in 0..8 {
                let cond = if ((self.0[i] >> (7-j)) & 0x1) > 0 { u64::MAX } else { 0u64 };
                // let bit = ((self.0[i] >> (7-j)) & 0x1) as u64;
                a ^= cond & MAP_A[map_idx];
                b ^= cond & MAP_B[map_idx];
                map_idx += 1;
            }
        }
        return (GF2p64::new(a), GF2p64::new(b));
    }
}

// these maps send alpha^i to phi(alpha)^i where alpha is the root in GF128
const MAP_A: [u64; 128] = [0x0000000000000000, 0xfea5501f298475b3, 0x045bedbabe115943, 0xee733ec0720440d4, 0x44e5acb10a2ca1a9, 0x40bb8c8598405f09, 0x0e19c767601b2151, 0xeb728b141abebf0d, 0xb1f319fdef77f341, 0xfe9e86e9357f46a4, 0xf146a1b1d623c1f1, 0x0f866f205d769ed6, 0x131c1c9975c7ccc6, 0xa0fee5b5516252ac, 0x1bf2823e83e21aa0, 0x1680594efec287ca, 0xe349126248d91030, 0xf52fd690bbfe52da, 0x050bc94fd1cf5e8a, 0x17ecda1c64a5a9df, 0x560eb5dffc1ce25b, 0x585630eccf67c814, 0x1650d4c99a533d14, 0xf63f4699381258f0, 0x0e664c654c268dcf, 0xedc541e31e8508ff, 0xbd06141f0ca9f2a1, 0x1adb8920e74c591d, 0x5db5536ec128341c, 0xf40a97c9aa29bb46, 0x4f8e9005edcfe758, 0x1b83a5207f4d8cc0, 0x0c36e79a1a6dd92d, 0x5cff3b39e6c2decf, 0x43ee3e547bde8a05, 0x056c20d7e6cd5dfc, 0x50aa56e5678ef743, 0xe60acc4a7b7ac886, 0x0ed05f6629ed4d25, 0xb887a30a0313beac, 0xff8c064ae2a87d59, 0xaa509c93a9635bf7, 0xfd94bec927471a7b, 0xf33adbbac54a7796, 0x5b99ba026fe677cb, 0xbc9f5ae2578c6c7e, 0x039c7102a09a889a, 0xecf8f4820e23c1f7, 0x174dd9c9f7208dfe, 0xf38d89c8ff12256f, 0x1a3831bbb05c4963, 0x5b1c082f11ecdd72, 0xb03b459d4fb4585c, 0xba73f2fc3b0cc81b, 0x49be7de1d79a6d51, 0x0b34394d6fb29277, 0xfc6cb2eaae66da57, 0x07b570d4f8c6fd60, 0x42f402eb9f85668e, 0xaaad43b47f124394, 0xe350974f8f1510f0, 0x5baa15d8865e6924, 0x08e4d020edfb3c00, 0x4889168d054f3349, 0x0634628a4c80d9fd, 0xff5cb0a9cffea8e0, 0xf863500320e32195, 0xbcbd7bd5a40d30f8, 0xa5354a483059aaba, 0x1b06027d3a3ab11c, 0x55be8b217d563f97, 0xb25aa90010eecbb6, 0xbf13eaf9ffce0db5, 0x5db2f4e539c2da09, 0x089913ef2731f6f9, 0x10e5fef212ecafe1, 0x035a3f50bc57d9cd, 0x48bd9efc4db34692, 0xb1c3c0c4e92342a6, 0x53ebb7d2792abf5a, 0x54058330148ca7ac, 0xa27bf52f477bff44, 0xeeecbf03cd338e38, 0x404796b4bb53b0e3, 0x0478caa3b15f63df, 0x4af5ca2f45c72fef, 0x576661ef78a4f0f9, 0xf15437e6b8236f57, 0xb9e489c9a4b95032, 0x4ae608c381514399, 0xa1639c56b9fb0962, 0xbe497fe1fdfac4c6, 0x44719d35875b4128, 0xbfca4260af46459c, 0x1b2305c256b79538, 0x1eb16eca9b58b752, 0x4fd3b36c2d8d238f, 0xa1829c384af5d34a, 0x5224c669c2cd62d4, 0xfef397af4ddf3268, 0x58ac6090675ca5b2, 0xa1cc942979c66974, 0xacb6482057917e18, 0x59d180c4d2f61b26, 0xa75534a6a0edcd61, 0xbc570d17ca949320, 0xb4e8c720572b016f, 0xbe646d91418547d9, 0xe7c8f159d43d0d01, 0xa9b56516c2e4e2b8, 0x12e233b430dea27e, 0xa9e19bd99dcca634, 0x4425cf62e62f0bf8, 0xe22036cde8c9e152, 0x5481e6be92567eb0, 0xa89fb2ead9bfc3c5, 0xf13e46a1147f5af8, 0xec23d154661f9806, 0xbfffaa6ea074f7fa, 0x0fb1237462189ed2, 0x5c23aa17dbc6e246, 0x212a684d854704e3, 0xeda5bbf80eed69cb, 0xb9dbc46777e564c0, 0x529648f26e506c00, 0x48a41aac7c0b06f3, 0xb6d7d68e1fdfd731, 0x2f92b27ff2fb8819];
const MAP_B: [u64; 128] = [0x0000000000000001, 0x85c3195f39261632, 0xa99cc47526bb3fe1, 0x4b116d4a85eed2d0, 0x5a42b25b095fcc57, 0x5c852c75ea428bf9, 0xc6c94fd21e462839, 0xcc104158eb710e7d, 0x65bb2e791096abda, 0x103d82e847dfa24f, 0xe9804f271e1c59b8, 0xd9cbb0b3ec928db3, 0x830fc7d05ec13184, 0x452ebdb16ccac5a4, 0x0aa0788b44ec52cc, 0x377c889c7678669a, 0xddcda0d12d1ec6c5, 0x130534cb014f5a2c, 0x45eaf192f874d57e, 0x59baa00b34641057, 0x9ed864fda2e7aaf3, 0x94392af479aaf672, 0x842365440c7c1de5, 0x550f2a0fa5be27db, 0x21dcd93b5a27cfd9, 0xdec83b99a9c8994c, 0x7a1040fbd739a617, 0xfc51dd0297b6d1cc, 0x6cbef354fbd5c14a, 0x224986e7b372d87d, 0xa95313392248b1e1, 0x634e3c2e2df3090c, 0xdeed3b8217739d5c, 0x24c4f0b1fc7df04f, 0x67c21b5d7a1c9f27, 0x6089a6388b2027a7, 0x6b2d2bf10b8db4db, 0x2d42ce5043092579, 0x19d3582598713a35, 0xc4c11d10f50e4e90, 0x9899b2505af4c23a, 0xe565926f081e36d3, 0x899b4eaf3b4f18ac, 0x5f1aba8aaff678df, 0x50dfeee0bad42ea8, 0xbab501f8c583a9e0, 0xaa8a433473233cc4, 0x5e43a103be22be3e, 0x83b4cf7367c3843f, 0xde86486a0edbfdb3, 0x63db7e157a088d1e, 0x72310119f03fd5bc, 0xfafd6933ded47557, 0x648866df215d6645, 0xa0fe38ee0ad13173, 0x4b49e2d12fdcf3dd, 0x4a108cd25b89b9da, 0x11ce459f0873a45b, 0x36972402a405567d, 0xf712e4851809be2c, 0xaf9135dddd6ef2a9, 0x199ba92e4e0d884f, 0xc22f3c7460fd87d7, 0xd302c6e9ef9c4634, 0xc6193d033fd19634, 0x0e08eb44127805da, 0xb1562ae39f0769b3, 0xc330e005b380d111, 0x5a30543f0614084f, 0xa3472f06805f4af2, 0x9d582c125ecc3d68, 0x0643e376e71160e3, 0x83e093d16ff80254, 0xa172fdc069b50a23, 0x41f1e29d3774e628, 0x1dc70688b406638f, 0xf9cff7b854e30fa9, 0xa470dba0fbbfe35c, 0x0caab92b90362546, 0xb5659a2f7187cb66, 0xaf0ddd37dd4efbf9, 0x810f5db570d9e8c1, 0x08b9a5dd03c78a59, 0x0eaa4d63241ed006, 0x2e80b9fbffc77fe8, 0x52ce7e693210398c, 0x2ecdbec91c3a24cb, 0x670d6774409f35d0, 0x5d2b1401af3dd61a, 0xce7d7afb7ba1975e, 0x7e6bc6caf711ed55, 0x0f2bb521767b86df, 0x6aaf311dedf75ded, 0x120596e724907e53, 0xc1801bfbcdecad99, 0x92ed3546e22947da, 0xfe1ea9b0cf534a73, 0xbf6c0ea53fc69c91, 0x04ee7375ec2dcc76, 0xeeb3b9bbde7ac06f, 0x7dfe58703c9448ee, 0xb2691272904c3efa, 0x590df122b6afaae6, 0x7990ffc086523d5a, 0xa43fe72c52dafb6c, 0xf57e017da54ec973, 0xdf29b7dc2f9ddfd9, 0x691cbc0706f4587f, 0x8111608a4709fbb8, 0xefd3d434d2a7ca0e, 0x432179cb9221a008, 0xc15312bfe34a6105, 0x720ac0d44d0905ba, 0x3b16414b44bb46a2, 0xf96e0ca335981ee8, 0xb272203153a6c2f8, 0x03e0484927b5c7cf, 0x551655d3705b5bd6, 0xbf87fa4fc46c7ea8, 0xf7a8848540f3e259, 0xc2b8aeb0426a6a68, 0xdb94a51daab822ae, 0x7dbac869fbca3641, 0xd4ba4d7fb386a478, 0x8d21bc6254ca3564, 0xd5d4027ceeb1e7f9, 0xff3535db05a369eb, 0xab86c8779d369e18];

impl Field for GF128 {
    const NBYTES: usize = 16;

    const ONE: Self = GF128([0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    fn is_zero(&self) -> bool {
        return self.0.iter().all(|x| *x == 0);
    }
}

impl HasZero for GF128 {
    const ZERO: Self = GF128([0u8; 16]);
}

impl NetSerializable for GF128 {
    fn serialized_size(n_elements: usize) -> usize {
        n_elements * Self::NBYTES
    }

    fn as_byte_vec(it: impl IntoIterator<Item = impl Borrow<Self>>, len: usize) -> Vec<u8> {
        let mut vec = Vec::with_capacity(Self::serialized_size(len));
        it.into_iter().for_each(|gf| {
            let arr = gf.borrow().0;
            vec.extend_from_slice(&arr);
        });
        vec
    }

    fn as_byte_vec_slice(elements: &[Self]) -> Vec<u8> {
        let mut res = vec![0u8; Self::serialized_size(elements.len())];
        res.chunks_exact_mut(Self::NBYTES).zip_eq(elements).for_each(|(dst, gf)| {
            dst.copy_from_slice(&gf.0);
        });
        res
    }

    fn from_byte_slice(v: Vec<u8>, dest: &mut [Self]) {
        debug_assert_eq!(dest.len()*16, v.len());
        dest.iter_mut().zip(v.into_iter().chunks(16).into_iter()).for_each(|(dst, chunk)| {
            chunk.into_iter().enumerate().for_each(|(i,byte)| {
                dst.0[i] = byte;
            });
        });
    }

    fn from_byte_vec(v: Vec<u8>, _len: usize) -> Vec<Self> {
        debug_assert!(v.len()%16 == 0);
        v.into_iter().chunks(16).into_iter().map(|chunk| {
            let mut bytes = [0u8; 16];
            bytes.iter_mut().zip(chunk.into_iter()).for_each(|(dst,byte)| *dst = byte);
            Self(bytes)
        }).collect()
    }
}

impl Default for GF128 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl Add for GF128 {
    type Output = GF128;
    
    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl AddAssign for GF128 {
    fn add_assign(&mut self, rhs: Self) {
        for i in 0..16 {
            self.0[i] ^= rhs.0[i];
        }
    }
}

impl Sub for GF128 {
    type Output = GF128;
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl Neg for GF128 {
    type Output = GF128;
    fn neg(self) -> Self::Output {
        self
    }
}

impl Mul for GF128 {
    type Output = GF128;
    fn mul(self, rhs: Self) -> Self::Output {
        // use GHASH to realize GF(2^128) multiplication
        // the first input block in GHASH is computed as Y = X * H
        // so we set self as key and rhs as input
        // and obtain Y from the output of the hash
        let mut hasher = GHash::new(&self.0.into());
        let block: ghash::Block = rhs.0.into();
        hasher.update(&[block]);
        let result = hasher.finalize();
        GF128(result.into())
    }
}

#[derive(Debug, PartialEq)]
pub struct TryFromGF128SliceError;

impl TryFrom<&[GF8]> for GF128 {
    type Error = TryFromGF128SliceError;
    fn try_from(value: &[GF8]) -> Result<Self, Self::Error> {
        if value.len() != 16 { return Err(TryFromGF128SliceError)}
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            bytes[i] = value[i].0;
        }
        Ok(GF128(bytes))
    }
}

impl TryFrom<&[u8]> for GF128 {
    type Error = TryFromGF128SliceError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 16 { return Err(TryFromGF128SliceError)}
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(value);
        Ok(GF128(bytes))
    }
}

// unsafe impl TransparentWrapper<[u8; 16]> for GF128 {}

impl RngExt for GF128 {
    fn fill<R: Rng + CryptoRng>(rng: &mut R, buf: &mut [Self]) {
        for gf in buf {
            rng.fill_bytes(&mut gf.0);
        }
    }

    fn generate<R: Rng + CryptoRng>(rng: &mut R, n: usize) -> Vec<Self> {
        let mut v = vec![Self::ZERO; n];
        Self::fill(rng, &mut v);
        v
    }
}

impl DigestExt for GF128 {
    fn update<D: Digest>(digest: &mut D, message: &[Self]) {
        for m in message {
            digest.update(m.0);
        }
    }
}

impl From<[GF8; 16]> for GF128 {
    fn from(value: [GF8; 16]) -> Self {
        let mut arr = [0u8; 16];
        arr.iter_mut().zip(value).for_each(|(dst, src)| *dst = src.0);
        Self(arr)
    }
}

impl From<[u8; 16]> for GF128 {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

/// Encodes multiplication triples in [GF128] as two inner product triples in [GF2p64]
/// via the isomorphism [GF128::into_gf2p64p2].
pub struct GF128TripleEncoder<'a>(pub &'a mut MulTripleVector<GF128>);

fn encode_gf128(x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], zi: &mut GF2p64InnerProd, zii: &mut GF2p64InnerProd, weight: &mut GF2p64, rand: GF2p64, ai: &[GF128], aii: &[GF128], bi: &[GF128], bii: &[GF128], ci: &[GF128], cii: &[GF128]) {
    let mut local_weight = *weight;
    izip!(x.chunks_exact_mut(5), y.chunks_exact_mut(5), ai, aii, bi, bii, ci, cii)
        .for_each(|(x, y, ai, aii, bi, bii, ci, cii)| {
            let (ai1, ai0) = ai.into_gf2p64p2();
            let (aii1, aii0) = aii.into_gf2p64p2();
            let (bi1, bi0) = bi.into_gf2p64p2();
            let (bii1, bii0) = bii.into_gf2p64p2();

            let (ci1, ci0) = ci.into_gf2p64p2();
            let (cii1, cii0) = cii.into_gf2p64p2();
            
            // inner product triple (a1*b0 + a0*b1 + a1*b1) = c1
            let rai1 = local_weight * ai1;
            let raii1 = local_weight * aii1;
            x[0].si = rai1;
            x[0].sii = raii1;
            x[1].si = local_weight * ai0;
            x[1].sii = local_weight * aii0;
            x[2].si = rai1;
            x[2].sii = raii1;

            y[0].si = bi0;
            y[0].sii = bii0;
            y[1].si = bi1;
            y[1].sii = bii1;
            y[2].si = bi1;
            y[2].sii = bii1;
            zi.add_prod(&ci1, &local_weight);
            zii.add_prod(&cii1, &local_weight);
            local_weight *= rand;

            // inner product triple (a0 * b0 + a1 * b1 * 2^61) = c0
            x[3].si = local_weight * ai0;
            x[3].sii = local_weight * aii0;
            x[4].si = local_weight * ai1;
            x[4].sii = local_weight * aii1;
            
            y[3].si = bi0;
            y[3].sii = bii0;
            y[4].si = GF2p64::new(1u64 << 61) * bi1;
            y[4].sii = GF2p64::new(1u64 << 61) * bii1;
            zi.add_prod(&ci0, &local_weight);
            zii.add_prod(&cii0, &local_weight);
            local_weight *= rand;
    });
    *weight = local_weight;
}

impl<'a> MulTripleEncoder for GF128TripleEncoder<'a> {
    fn len_triples_in(&self) -> usize {
        self.0.len()
    }

    fn len_triples_out(&self) -> usize {
        5*self.0.len()
    }

    fn add_triples(&mut self, x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], zi: &mut GF2p64InnerProd, zii: &mut GF2p64InnerProd, weight: &mut GF2p64, rand: GF2p64) {
        encode_gf128(x, y, zi, zii, weight, rand, self.0.ai(), self.0.aii(), self.0.bi(), self.0.bii(), self.0.ci(), self.0.cii());
    }

    fn add_triples_par(&mut self, x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], z: &mut RssShare<GF2p64>, weight: GF2p64, rand: &[GF2p64], chunk_size: usize) {
        debug_assert_eq!(x.len(), 5 * self.0.ai().len(), "ai");
        let zvec: Vec<_> = 
        x.par_chunks_mut(chunk_size * 5)
            .zip_eq(y.par_chunks_mut(chunk_size * 5))
            .zip_eq(self.0.ai().par_chunks(chunk_size))
            .zip_eq(self.0.aii().par_chunks(chunk_size))
            .zip_eq(self.0.bi().par_chunks(chunk_size))
            .zip_eq(self.0.bii().par_chunks(chunk_size))
            .zip_eq(self.0.ci().par_chunks(chunk_size))
            .zip_eq(self.0.cii().par_chunks(chunk_size))
            .zip_eq(rand)
            .map(|((((((((x, y), ai), aii), bi), bii), ci), cii), r)| {
                let mut local_weight = weight;
                let mut zi = GF2p64InnerProd::new();
                let mut zii = GF2p64InnerProd::new();
                encode_gf128(x, y, &mut zi, &mut zii, &mut local_weight, *r, ai, aii, bi, bii, ci, cii);
                RssShare::from(zi.sum(), zii.sum())
            }).collect();
            zvec.into_iter().for_each(|zi| *z = *z + zi);
    }

    fn clear(&mut self) {
        self.0.clear();
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use crate::{gcm::gf128::{GF128TripleEncoder, TryFromGF128SliceError}, rep3_core::share::HasZero, share::{gf2p64::GF2p64, gf8::GF8, Field}, util::mul_triple_vec::{test::{check_correct_encoding, check_correct_encoding_par, generate_and_fill_random_triples}, MulTripleVector}};

    use super::GF128;

    #[test]
    fn gf128_one() {
        let xs: [GF128; 10] = [
            GF128([0xa0, 0x0d, 0x26, 0xf5, 0x21, 0x5c, 0x8c, 0x4c, 0xf2, 0x98, 0xbc, 0xcb, 0x21, 0x3f, 0x2c, 0x97]),
            GF128([0x87, 0xd0, 0x92, 0x6c, 0x5d, 0x31, 0x28, 0xa6, 0xd9, 0x9e, 0x43, 0xfd, 0x3a, 0xab, 0x93, 0xda]),
            GF128([0x39, 0x3a, 0x50, 0x5a, 0x96, 0xdc, 0x27, 0x89, 0x76, 0xe3, 0x55, 0x17, 0xa2, 0x01, 0x2e, 0x2b]),
            GF128([0xd2, 0xc0, 0x17, 0x30, 0x71, 0xbe, 0x56, 0xca, 0x5d, 0x99, 0xc8, 0x98, 0x46, 0xdc, 0xf2, 0x7f]),
            GF128([0x17, 0x44, 0x59, 0xad, 0xa0, 0x00, 0xb6, 0x96, 0xe3, 0x0c, 0x2d, 0x07, 0x0e, 0x5c, 0x32, 0x60]),
            GF128([0x9c, 0x49, 0x90, 0x8e, 0x87, 0x66, 0x59, 0xe4, 0x01, 0xa2, 0xfc, 0x47, 0x7f, 0x70, 0x46, 0x16]),
            GF128([0xb4, 0x1f, 0x43, 0xd4, 0x20, 0xf9, 0x6c, 0x83, 0x06, 0x99, 0x8a, 0x93, 0x75, 0x3c, 0xf3, 0x13]),
            GF128([0x05, 0x04, 0xa1, 0x8c, 0x6b, 0xfa, 0x72, 0x6c, 0x9d, 0xee, 0x33, 0x9c, 0x5f, 0xf8, 0xb2, 0x93]),
            GF128([0x18, 0xf5, 0x69, 0xb7, 0x6f, 0x55, 0x3c, 0x76, 0xee, 0x46, 0x89, 0xe4, 0x83, 0x7e, 0xf7, 0x88]),
            GF128([0x82, 0x19, 0x16, 0x6d, 0x93, 0x08, 0xd9, 0xb1, 0xf6, 0x8c, 0x4e, 0xd6, 0x85, 0x81, 0x6a, 0x1e]),
        ];
        // mul by GF128::ONE is the mult. identity
        for el in xs {
            assert_eq!(el, el * GF128::ONE);
        }
    }

    #[test]
    fn gf128_mul() {
        let xs: [GF128; 10] = [
            GF128([0xa0, 0x0d, 0x26, 0xf5, 0x21, 0x5c, 0x8c, 0x4c, 0xf2, 0x98, 0xbc, 0xcb, 0x21, 0x3f, 0x2c, 0x97]),
            GF128([0x87, 0xd0, 0x92, 0x6c, 0x5d, 0x31, 0x28, 0xa6, 0xd9, 0x9e, 0x43, 0xfd, 0x3a, 0xab, 0x93, 0xda]),
            GF128([0x39, 0x3a, 0x50, 0x5a, 0x96, 0xdc, 0x27, 0x89, 0x76, 0xe3, 0x55, 0x17, 0xa2, 0x01, 0x2e, 0x2b]),
            GF128([0xd2, 0xc0, 0x17, 0x30, 0x71, 0xbe, 0x56, 0xca, 0x5d, 0x99, 0xc8, 0x98, 0x46, 0xdc, 0xf2, 0x7f]),
            GF128([0x17, 0x44, 0x59, 0xad, 0xa0, 0x00, 0xb6, 0x96, 0xe3, 0x0c, 0x2d, 0x07, 0x0e, 0x5c, 0x32, 0x60]),
            GF128([0x9c, 0x49, 0x90, 0x8e, 0x87, 0x66, 0x59, 0xe4, 0x01, 0xa2, 0xfc, 0x47, 0x7f, 0x70, 0x46, 0x16]),
            GF128([0xb4, 0x1f, 0x43, 0xd4, 0x20, 0xf9, 0x6c, 0x83, 0x06, 0x99, 0x8a, 0x93, 0x75, 0x3c, 0xf3, 0x13]),
            GF128([0x05, 0x04, 0xa1, 0x8c, 0x6b, 0xfa, 0x72, 0x6c, 0x9d, 0xee, 0x33, 0x9c, 0x5f, 0xf8, 0xb2, 0x93]),
            GF128([0x18, 0xf5, 0x69, 0xb7, 0x6f, 0x55, 0x3c, 0x76, 0xee, 0x46, 0x89, 0xe4, 0x83, 0x7e, 0xf7, 0x88]),
            GF128([0x82, 0x19, 0x16, 0x6d, 0x93, 0x08, 0xd9, 0xb1, 0xf6, 0x8c, 0x4e, 0xd6, 0x85, 0x81, 0x6a, 0x1e]),
        ];
        let ys: [GF128; 10] = [
            GF128([0xf6, 0xd3, 0x55, 0x67, 0x29, 0x91, 0x5d, 0x98, 0x58, 0xe6, 0xfc, 0xdb, 0xe4, 0xf4, 0x64, 0x68]),
            GF128([0x8d, 0xf9, 0x55, 0x21, 0x02, 0x30, 0xd2, 0x79, 0x3c, 0xa1, 0xcf, 0x42, 0x23, 0x3a, 0x60, 0x99]),
            GF128([0x8e, 0xb5, 0x80, 0x37, 0xc7, 0xdd, 0x4f, 0x20, 0x45, 0x4c, 0x7b, 0x2a, 0xc0, 0x5f, 0x12, 0x4e]),
            GF128([0x5a, 0x68, 0xef, 0xdb, 0x18, 0xc2, 0xd4, 0x54, 0x64, 0xa4, 0x96, 0x07, 0x5f, 0x76, 0x21, 0x6d]),
            GF128([0xac, 0xa1, 0xa4, 0x74, 0x80, 0x74, 0x14, 0x45, 0x40, 0x0f, 0x6f, 0x81, 0x6e, 0x02, 0xcf, 0xc8]),
            GF128([0x6a, 0x3f, 0x25, 0x82, 0x82, 0xf9, 0x56, 0xe6, 0x1f, 0xed, 0x6e, 0x7e, 0xe3, 0x8f, 0x6b, 0x90]),
            GF128([0x31, 0x10, 0x05, 0x31, 0x04, 0x98, 0x76, 0x45, 0xa7, 0x66, 0xc6, 0x17, 0x68, 0x16, 0x5f, 0x52]),
            GF128([0xd5, 0x04, 0x54, 0x58, 0xfe, 0xaa, 0xbe, 0x9d, 0x18, 0x2d, 0x9b, 0xfc, 0x3c, 0x07, 0x8d, 0xed]),
            GF128([0x96, 0x13, 0x1f, 0x1b, 0xab, 0x16, 0x60, 0xd3, 0xfb, 0xa6, 0x6a, 0xe3, 0x3c, 0xc9, 0x36, 0x12]),
            GF128([0xce, 0x8a, 0x6a, 0x4d, 0xb4, 0xa9, 0x6a, 0xcd, 0xd6, 0x06, 0xca, 0x93, 0x8c, 0xd7, 0x81, 0x23]),
        ];
        let expected: [GF128; 10] = [
            GF128([0xd8, 0x38, 0xea, 0x96, 0xc2, 0x58, 0x48, 0x8a, 0x6b, 0xdb, 0xda, 0x8c, 0xdd, 0x94, 0xfb, 0xb4]),
            GF128([0x18, 0xfc, 0x9d, 0xd5, 0x0a, 0x26, 0xfb, 0x6f, 0x39, 0x7c, 0xd6, 0xe0, 0xf0, 0xaf, 0xeb, 0x7e]),
            GF128([0x60, 0xd1, 0x99, 0x32, 0x3d, 0x55, 0x76, 0xe8, 0xe4, 0x4c, 0x6c, 0x9e, 0xf7, 0x82, 0x47, 0xc7]),
            GF128([0xd0, 0xda, 0x30, 0x07, 0x9e, 0x18, 0xfa, 0x04, 0xab, 0x3b, 0xc8, 0x41, 0xe6, 0xef, 0x54, 0x6d]),
            GF128([0x07, 0xd2, 0x06, 0x06, 0xf5, 0xc3, 0x13, 0x83, 0x8a, 0x7c, 0x48, 0x8f, 0x44, 0xcd, 0xd7, 0xc9]),
            GF128([0xad, 0xd3, 0xb8, 0x8c, 0x33, 0xfc, 0xf0, 0xa8, 0xdf, 0x30, 0x67, 0xc0, 0x48, 0x6b, 0x87, 0x20]),
            GF128([0xf4, 0xfe, 0xff, 0x9a, 0x70, 0x9d, 0x37, 0x4b, 0x28, 0xf0, 0x42, 0x62, 0x09, 0x89, 0xa6, 0x8a]),
            GF128([0x49, 0x2c, 0x61, 0x2f, 0x8e, 0xf3, 0x73, 0x74, 0x2c, 0xfd, 0x2c, 0x75, 0xe1, 0xfc, 0x75, 0xe6]),
            GF128([0x94, 0x4e, 0xa2, 0x5e, 0xc5, 0x60, 0xc0, 0xcb, 0x1b, 0x07, 0x37, 0xf4, 0x39, 0xf2, 0xff, 0x17]),
            GF128([0x54, 0x38, 0x17, 0xd0, 0xd0, 0xcc, 0x4c, 0xec, 0x58, 0x0f, 0x4d, 0x0a, 0xac, 0x9a, 0x11, 0xd9]),
        ];

        for (x,(y,expected)) in xs.into_iter().zip_eq(ys.into_iter().zip_eq(expected)) {
            assert_eq!(x * y, expected);
        }
    }

    #[test]
    fn from_gf8_array() {
        let expected = GF128([0xa0, 0x0d, 0x26, 0xf5, 0x21, 0x5c, 0x8c, 0x4c, 0xf2, 0x98, 0xbc, 0xcb, 0x21, 0x3f, 0x2c, 0x97]);
        let actual = GF128::from([GF8(0xa0), GF8(0x0d), GF8(0x26), GF8(0xf5), GF8(0x21), GF8(0x5c), GF8(0x8c), GF8(0x4c), GF8(0xf2), GF8(0x98), GF8(0xbc), GF8(0xcb), GF8(0x21), GF8(0x3f), GF8(0x2c), GF8(0x97)]);
        assert_eq!(expected, actual);
    }

    #[test]
    fn from_u8_array() {
        let expected = GF128([0xa0, 0x0d, 0x26, 0xf5, 0x21, 0x5c, 0x8c, 0x4c, 0xf2, 0x98, 0xbc, 0xcb, 0x21, 0x3f, 0x2c, 0x97]);
        let actual = GF128::from([0xa0, 0x0d, 0x26, 0xf5, 0x21, 0x5c, 0x8c, 0x4c, 0xf2, 0x98, 0xbc, 0xcb, 0x21, 0x3f, 0x2c, 0x97]);
        assert_eq!(expected, actual);
    }

    #[test]
    fn try_from_gf8_slice() {
        let expected = GF128([0xa0, 0x0d, 0x26, 0xf5, 0x21, 0x5c, 0x8c, 0x4c, 0xf2, 0x98, 0xbc, 0xcb, 0x21, 0x3f, 0x2c, 0x97]);
        let slice = [GF8(0xa0), GF8(0x0d), GF8(0x26), GF8(0xf5), GF8(0x21), GF8(0x5c), GF8(0x8c), GF8(0x4c), GF8(0xf2), GF8(0x98), GF8(0xbc), GF8(0xcb), GF8(0x21), GF8(0x3f), GF8(0x2c), GF8(0x97)];
        let actual = GF128::try_from(slice.as_slice());
        assert_eq!(Ok(expected), actual);

        let slice_too_short = [GF8(0xa0), GF8(0x0d), GF8(0x26), GF8(0xf5), GF8(0x21), GF8(0x5c), GF8(0x8c), GF8(0x4c), GF8(0xf2), GF8(0x98), GF8(0xbc), GF8(0xcb), GF8(0x21), GF8(0x3f), GF8(0x2c)];
        assert_eq!(Err(TryFromGF128SliceError), GF128::try_from(slice_too_short.as_slice()));

        let slice_empty: &[GF8] = &[];
        assert_eq!(Err(TryFromGF128SliceError), GF128::try_from(slice_empty));

        let slice_too_long = [GF8(0xa0), GF8(0x0d), GF8(0x26), GF8(0xf5), GF8(0x21), GF8(0x5c), GF8(0x8c), GF8(0x4c), GF8(0xf2), GF8(0x98), GF8(0xbc), GF8(0xcb), GF8(0x21), GF8(0x3f), GF8(0x2c), GF8(0x97), GF8(0x56)];
        assert_eq!(Err(TryFromGF128SliceError), GF128::try_from(slice_too_long.as_slice()));
    }

    #[test]
    fn try_from_u8_slice() {
        let expected = GF128([0xa0, 0x0d, 0x26, 0xf5, 0x21, 0x5c, 0x8c, 0x4c, 0xf2, 0x98, 0xbc, 0xcb, 0x21, 0x3f, 0x2c, 0x97]);
        let actual = GF128::from([0xa0, 0x0d, 0x26, 0xf5, 0x21, 0x5c, 0x8c, 0x4c, 0xf2, 0x98, 0xbc, 0xcb, 0x21, 0x3f, 0x2c, 0x97]);
        assert_eq!(expected, actual);

        let slice_too_short = [0xa0, 0x0d, 0x26, 0xf5, 0x21, 0x5c, 0x8c, 0x4c, 0xf2, 0x98, 0xbc, 0xcb, 0x21, 0x3f, 0x2c];
        assert_eq!(Err(TryFromGF128SliceError), GF128::try_from(slice_too_short.as_slice()));

        let slice_empty: &[u8] = &[];
        assert_eq!(Err(TryFromGF128SliceError), GF128::try_from(slice_empty));

        let slice_too_long = [0xa0, 0x0d, 0x26, 0xf5, 0x21, 0x5c, 0x8c, 0x4c, 0xf2, 0x98, 0xbc, 0xcb, 0x21, 0x3f, 0x2c, 0x97, 0x33];
        assert_eq!(Err(TryFromGF128SliceError), GF128::try_from(slice_too_long.as_slice()));
    }

    #[test]
    fn into_gf2p64p2() {
        // maps zero to zero, one to one
        let zero_gf128 = GF128::ZERO;
        assert_eq!(zero_gf128.into_gf2p64p2(), (GF2p64::ZERO, GF2p64::ZERO));
        assert_eq!(GF128::ONE.into_gf2p64p2(), (GF2p64::ZERO, GF2p64::ONE));

        let x = GF128([0xa0, 0x0d, 0x26, 0xf5, 0x21, 0x5c, 0x8c, 0x4c, 0xf2, 0x98, 0xbc, 0xcb, 0x21, 0x3f, 0x2c, 0x97]);
        let y = GF128([0xf6, 0xd3, 0x55, 0x67, 0x29, 0x91, 0x5d, 0x98, 0x58, 0xe6, 0xfc, 0xdb, 0xe4, 0xf4, 0x64, 0x68]);
        let z = GF128([0xd8, 0x38, 0xea, 0x96, 0xc2, 0x58, 0x48, 0x8a, 0x6b, 0xdb, 0xda, 0x8c, 0xdd, 0x94, 0xfb, 0xb4]);

        let (a,b) = x.into_gf2p64p2();
        let (c,d) = y.into_gf2p64p2();
        let (e,f) = z.into_gf2p64p2();

        // (aX + b)(cX + d) mod (X^2 + X + 2^61) = (ad + bc + ac) X + (bd + ac*2^61)
        let e_actual = a*d + b*c + a*c;
        let f_actual = b*d + GF2p64::new(1u64 << 61) * a * c;
        assert_eq!(e, e_actual);
        assert_eq!(f, f_actual);
    }

    #[test]
    fn gf128_encoder_correct() {
        const N: usize = 100;
        // collect N correct triples
        let mut rec1 = MulTripleVector::new();
        let mut rec2 = MulTripleVector::new();
        let mut rec3 = MulTripleVector::new();

        generate_and_fill_random_triples::<GF128, _>(&mut rec1, &mut rec2, &mut rec3, N);
        assert_eq!(rec1.len(), N);
        assert_eq!(rec2.len(), N);
        assert_eq!(rec3.len(), N);

        // now test if the encoding is correct
        check_correct_encoding(GF128TripleEncoder(&mut rec1), GF128TripleEncoder(&mut rec2), GF128TripleEncoder(&mut rec3), 5*N, false);

        // now test if the encoding is correct when encoding in parallel
        check_correct_encoding_par(GF128TripleEncoder(&mut rec1), GF128TripleEncoder(&mut rec2), GF128TripleEncoder(&mut rec3), 5*N);
    }
}