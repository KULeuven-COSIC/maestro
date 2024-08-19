use itertools::{izip, Itertools};
use rep3_core::share::{HasZero, RssShare};

use crate::share::{bs_bool16::BsBool16, gf2p64::{embed_gf4p4_deg2, embed_gf4p4_deg3, GF2p64, GF2p64InnerProd, GF2p64Subfield}, gf4::BsGF4, Field};
use rayon::{iter::{IndexedParallelIterator, ParallelIterator}, slice::{ParallelSlice, ParallelSliceMut}};

pub trait MulTripleRecorder<F: Field> {
    /// "Child" recorder type for multi-threading
    type ThreadMulTripleRecorder: MulTripleRecorder<F> + Sized + Send;

    /// A size hint for the number of expected triples
    fn reserve_for_more_triples(&mut self, n: usize);

    /// Record a (2,3)-shared multiplication triple a*b = c
    fn record_mul_triple(&mut self, a_i: &[F], a_ii: &[F], b_i: &[F], b_ii: &[F], c_i: &[F], c_ii: &[F]);

    /// Creates "child" recorders for multi-threading (one for each element in ranges). The child recorders will be used
    /// by threads to record their observed multiplication triples
    /// ranges: Vec of start, end_exclusive of the range that this thread will cover
    fn create_thread_mul_triple_recorder(&self, range_start: usize, range_end: usize) -> Self::ThreadMulTripleRecorder;

    /// Records the multiplication triples from all the "child" recorders in this
    fn join_thread_mul_triple_recorders(&mut self, recorders: Vec<Self::ThreadMulTripleRecorder>);
}

pub trait BitStringMulTripleRecorder {
    /// Record a (2,3)-shared bit times bitstring multiplication triple a*b = c
    /// where a is a bit and b, c are a bitstring of the same length encoded as concatenations of simd_len blocks for each bit in the bitstring
    /// e.g. b0|b1|... where b0 is a vector of the lsbits of the bitstring
    fn record_bit_bitstring_triple(&mut self, simd_len: usize, a_i: &[BsBool16], a_ii: &[BsBool16], b_i: &[BsBool16], b_ii: &[BsBool16], c_i: &[BsBool16], c_ii: &[BsBool16]);
}

pub trait MulTripleEncoder {
    /// Returns how many [GF2p64] multiplication triples this instance encodes/outputs
    fn len_triples_out(&self) -> usize;

    /// Returns how many [GF2p64] multiplication triples this instance contains to encode
    fn len_triples_in(&self) -> usize;

    /// Encodes the stored triples in this instance as inner product triples z = sum x * y
    fn add_triples(&mut self, x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], zi: &mut GF2p64InnerProd, zii: &mut GF2p64InnerProd, weight: &mut GF2p64, rand: GF2p64);

    /// Encodes the stored triples in this instance as inner product triples z = sum x * y in parallel processing input triples in chunk_size chunks
    fn add_triples_par(&mut self, x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], z: &mut RssShare<GF2p64>, weight: GF2p64, rand: &[GF2p64], chunk_size: usize);

    /// Clears the triples stored in this instance
    fn clear(&mut self);
}

#[derive(Debug, Clone, Copy)]
pub struct NoMulTripleRecording;
impl<F: Field> MulTripleRecorder<F> for NoMulTripleRecording {
    type ThreadMulTripleRecorder = Self;
    fn reserve_for_more_triples(&mut self, _n: usize) {
        // do nothing
    }

    fn record_mul_triple(&mut self, _a_i: &[F], _a_ii: &[F], _b_i: &[F], _b_ii: &[F], _c_i: &[F], _c_ii: &[F]) {
        // do nothing
    }

    fn create_thread_mul_triple_recorder(&self, _range_start: usize, _range_end: usize) -> Self::ThreadMulTripleRecorder {
        Self {}
    }

    fn join_thread_mul_triple_recorders(&mut self, _recorders: Vec<Self::ThreadMulTripleRecorder>) {
        // do nothing
    }
}

impl BitStringMulTripleRecorder for NoMulTripleRecording {
    fn record_bit_bitstring_triple(&mut self, _simd_len: usize, _a_i: &[BsBool16], _a_ii: &[BsBool16], _b_i: &[BsBool16], _b_ii: &[BsBool16], _c_i: &[BsBool16], _c_ii: &[BsBool16]) {
        // do nothing
    }
}

pub struct MulTripleVector<F> {
    // s.t. a*b = c
    ai: Vec<F>,
    aii: Vec<F>,
    bi: Vec<F>,
    bii: Vec<F>,
    ci: Vec<F>,
    cii: Vec<F>,
}

impl<F: Clone> MulTripleVector<F> {
    pub fn new() -> Self {
        Self {
            ai: Vec::new(),
            aii: Vec::new(),
            bi: Vec::new(),
            bii: Vec::new(),
            ci: Vec::new(),
            cii: Vec::new(),
        }
    }

    pub fn from_vecs(ai: Vec<F>, aii: Vec<F>, bi: Vec<F>, bii: Vec<F>, ci: Vec<F>, cii: Vec<F>) -> Self {
        debug_assert_eq!(ai.len(), aii.len());
        debug_assert_eq!(ai.len(), bi.len());
        debug_assert_eq!(ai.len(), bii.len());
        debug_assert_eq!(ai.len(), ci.len());
        debug_assert_eq!(ai.len(), cii.len());
        Self { ai, aii, bi, bii, ci, cii }
    }

    pub fn len(&self) -> usize {
        self.ai.len()
    }

    pub fn shrink(&mut self, new_length: usize) {
        self.ai.truncate(new_length);
        self.aii.truncate(new_length);
        self.bi.truncate(new_length);
        self.bii.truncate(new_length);
        self.ci.truncate(new_length);
        self.cii.truncate(new_length);
    }

    /// Also clears the allocated capacity
    pub fn clear(&mut self) {
        self.ai = Vec::new();
        self.aii = Vec::new();
        self.bi = Vec::new();
        self.bii = Vec::new();
        self.ci = Vec::new();
        self.cii = Vec::new();
    }

    fn append(&mut self, mut other: Self) {
        self.ai.append(&mut other.ai);
        self.aii.append(&mut other.aii);
        self.bi.append(&mut other.bi);
        self.bii.append(&mut other.bii);
        self.ci.append(&mut other.ci);
        self.cii.append(&mut other.cii);
    }

    pub fn ai(&self) -> &[F] { &self.ai }
    pub fn aii(&self) -> &[F] { &self.aii }
    pub fn bi(&self) -> &[F] { &self.bi }
    pub fn bii(&self) -> &[F] { &self.bii }
    pub fn ci(&self) -> &[F] { &self.ci }
    pub fn cii(&self) -> &[F] { &self.cii }

    fn rss_iter(xi: Vec<F>, xii: Vec<F>) -> impl ExactSizeIterator<Item=RssShare<F>> where F: Field {
        xi.into_iter().zip(xii).map(|(si,sii)| RssShare::from(si, sii))
    }

    fn drain_rss_iter<'a>(xi: &'a mut Vec<F>, xii: &'a mut Vec<F>) -> impl ExactSizeIterator<Item=RssShare<F>> + 'a where F: Field {
        xi.drain(..).zip(xii.drain(..)).map(|(si,sii)| RssShare::from(si, sii))
    }

    pub fn into_rss_iter(self) -> impl ExactSizeIterator<Item =(RssShare<F>, RssShare<F>, RssShare<F>)> where F: Field {
        izip!(Self::rss_iter(self.ai, self.aii), Self::rss_iter(self.bi, self.bii), Self::rss_iter(self.ci, self.cii))
    }

    pub fn drain_into_rss_iter<'a>(&'a mut self) -> impl ExactSizeIterator<Item =(RssShare<F>, RssShare<F>, RssShare<F>)> + 'a where F: Field {
        izip!(Self::drain_rss_iter(&mut self.ai, &mut self.aii), Self::drain_rss_iter(&mut self.bi, &mut self.bii), Self::drain_rss_iter(&mut self.ci, &mut self.cii))
    }

    pub fn as_mut_slices(&mut self) -> (&mut[F], &mut[F], &mut[F], &mut[F], &mut[F], &mut[F]) {
        (&mut self.ai, &mut self.aii, &mut self.bi, &mut self.bii, &mut self.ci, &mut self.cii)
    }
}

impl<F: Field + Send> MulTripleRecorder<F> for MulTripleVector<F> {
    type ThreadMulTripleRecorder = Self;
    fn reserve_for_more_triples(&mut self, n: usize) {
        self.ai.reserve_exact(n);
        self.aii.reserve_exact(n);
        self.bi.reserve_exact(n);
        self.bii.reserve_exact(n);
        self.ci.reserve_exact(n);
        self.cii.reserve_exact(n);
    }
    
    fn record_mul_triple(&mut self, a_i: &[F], a_ii: &[F], b_i: &[F], b_ii: &[F], c_i: &[F], c_ii: &[F]) {
        self.ai.extend_from_slice(a_i);
        self.aii.extend_from_slice(a_ii);
        self.bi.extend_from_slice(b_i);
        self.bii.extend_from_slice(b_ii);
        self.ci.extend_from_slice(c_i);
        self.cii.extend_from_slice(c_ii);
    }

    fn create_thread_mul_triple_recorder(&self, _range_start: usize, _range_end: usize) -> Self::ThreadMulTripleRecorder {
        Self::new()
    }

    fn join_thread_mul_triple_recorders(&mut self, recorders: Vec<Self::ThreadMulTripleRecorder>) {
        let n_triples = recorders.iter().map(|v| v.len()).sum();
        self.reserve_for_more_triples(n_triples);
        recorders.into_iter().for_each(|v| self.append(v));
    }
}

impl BitStringMulTripleRecorder for MulTripleVector<GF2p64> {
    fn record_bit_bitstring_triple(&mut self, simd_len: usize, a_i: &[BsBool16], a_ii: &[BsBool16], b_i: &[BsBool16], b_ii: &[BsBool16], c_i: &[BsBool16], c_ii: &[BsBool16]) {
        debug_assert_eq!(a_i.len(), a_ii.len());
        debug_assert_eq!(simd_len, a_i.len());

        let bitlen = b_i.len()/simd_len;
        let mut from = 0;
        let mut to = usize::min(bitlen, 64);
        while from < to {
            for ai in a_i {
                GF2p64::extend_from_bit(&mut self.ai, ai);
            }
            for aii in a_ii {
                GF2p64::extend_from_bit(&mut self.aii, aii);
            }
            GF2p64::extend_from_bitstring(&mut self.bi, &b_i[simd_len*from..simd_len*to], simd_len);
            GF2p64::extend_from_bitstring(&mut self.bii, &b_ii[simd_len*from..simd_len*to], simd_len);
            GF2p64::extend_from_bitstring(&mut self.ci, &c_i[simd_len*from..simd_len*to], simd_len);
            GF2p64::extend_from_bitstring(&mut self.cii, &c_ii[simd_len*from..simd_len*to], simd_len);

            from = to;
            to = from + usize::min(bitlen-to, 64);
        }
    }
}

macro_rules! mul_triple_encoder_impl {
    ($encode_name:ident, $yield_size:literal) => {

            fn len_triples_in(&self) -> usize {
                self.0.len()
            }

            fn len_triples_out(&self) -> usize {
                self.0.len() * $yield_size
            }
            fn add_triples(&mut self, x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], zi: &mut GF2p64InnerProd, zii: &mut GF2p64InnerProd, weight: &mut GF2p64, rand: GF2p64) {
                let mut local_weight = *weight;
                let mut encoded_c = [RssShare::from(GF2p64::ZERO, GF2p64::ZERO); $yield_size];
                izip!(x.chunks_exact_mut($yield_size), y.chunks_exact_mut($yield_size), &self.0.ai, &self.0.aii, &self.0.bi, &self.0.bii, &self.0.ci, &self.0.cii)
                    .for_each(|(x, y, ai, aii, bi, bii, ci, cii)| {
                        $encode_name(x, y, &mut encoded_c, *ai, *aii, *bi, *bii, *ci, *cii);
                        for i in 0..$yield_size {
                            x[i] = x[i] * local_weight;
                            zi.add_prod(&encoded_c[i].si, &local_weight);
                            zii.add_prod(&encoded_c[i].sii, &local_weight);
                            local_weight *= rand;
                        }
                });
                *weight = local_weight;
            }
            fn add_triples_par(&mut self, x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], z: &mut RssShare<GF2p64>, weight: GF2p64, rand: &[GF2p64], chunk_size: usize) {
                debug_assert_eq!(x.len(), $yield_size * self.0.ai.len(), "ai");
                let zvec: Vec<_> = 
                x.par_chunks_mut(chunk_size * $yield_size)
                    .zip_eq(y.par_chunks_mut(chunk_size * $yield_size))
                    .zip_eq(self.0.ai.par_chunks(chunk_size))
                    .zip_eq(self.0.aii.par_chunks(chunk_size))
                    .zip_eq(self.0.bi.par_chunks(chunk_size))
                    .zip_eq(self.0.bii.par_chunks(chunk_size))
                    .zip_eq(self.0.ci.par_chunks(chunk_size))
                    .zip_eq(self.0.cii.par_chunks(chunk_size))
                    .zip_eq(rand)
                    .map(|((((((((x, y), ai), aii), bi), bii), ci), cii), r)| {
                        let mut local_weight = weight;
                        let mut encoded_c = [RssShare::from(GF2p64::ZERO, GF2p64::ZERO); $yield_size];
                        let mut zi = GF2p64InnerProd::new();
                        let mut zii = GF2p64InnerProd::new();
                        izip!(x.chunks_exact_mut($yield_size), y.chunks_exact_mut($yield_size), ai, aii, bi, bii, ci, cii)
                            .for_each(|(x, y, ai, aii, bi, bii, ci, cii)| {
                                $encode_name(x, y, &mut encoded_c, *ai, *aii, *bi, *bii, *ci, *cii);
                                for i in 0..$yield_size {
                                    x[i] = x[i] * local_weight;
                                    zi.add_prod(&encoded_c[i].si, &local_weight);
                                    zii.add_prod(&encoded_c[i].sii, &local_weight);
                                    local_weight *= *r;
                                }
                        });
                        RssShare::from(zi.sum(), zii.sum())
                    }).collect();
                    zvec.into_iter().for_each(|zi| *z = *z + zi);
            }

            fn clear(&mut self) {
                self.0.clear();
            }
    };
}
pub struct GF2p64Encoder<'a>(pub &'a mut MulTripleVector<GF2p64>);

#[inline]
fn encode_gf2p64(dst_a: &mut [RssShare<GF2p64>], dst_b: &mut [RssShare<GF2p64>], dst_c: &mut [RssShare<GF2p64>; 1], ai: GF2p64, aii: GF2p64, bi: GF2p64, bii: GF2p64, ci: GF2p64, cii: GF2p64) {
    dst_a[0].si = ai;
    dst_a[0].sii = aii;
    dst_b[0].si = bi;
    dst_b[0].sii = bii;
    dst_c[0].si = ci;
    dst_c[0].sii = cii;
}

impl<'a> MulTripleEncoder for GF2p64Encoder<'a> {
    mul_triple_encoder_impl!(encode_gf2p64, 1);
}

pub struct GF2p64SubfieldEncoder<'a, F: GF2p64Subfield>(pub &'a mut MulTripleVector<F>);

#[inline]
fn encode_gf2p64_subfield<F: GF2p64Subfield>(dst_a: &mut [RssShare<GF2p64>], dst_b: &mut [RssShare<GF2p64>], dst_c: &mut [RssShare<GF2p64>; 1], ai: F, aii: F, bi: F, bii: F, ci: F, cii: F) {
    dst_a[0].si = ai.embed();
    dst_a[0].sii = aii.embed();
    dst_b[0].si = bi.embed();
    dst_b[0].sii = bii.embed();
    dst_c[0].si = ci.embed();
    dst_c[0].sii = cii.embed();
}

impl<'a, F: GF2p64Subfield + Sync> MulTripleEncoder for GF2p64SubfieldEncoder<'a, F> {
    mul_triple_encoder_impl!(encode_gf2p64_subfield, 1);
}

pub struct BsBool16Encoder<'a>(pub &'a mut MulTripleVector<BsBool16>);
#[inline]
fn encode_bsbool16(dst_a: &mut [RssShare<GF2p64>], dst_b: &mut [RssShare<GF2p64>], dst_c: &mut [RssShare<GF2p64>; 16], ai: BsBool16, aii: BsBool16, bi: BsBool16, bii: BsBool16, ci: BsBool16, cii: BsBool16) {
    let ai = gf2_embed(ai);
    let aii = gf2_embed(aii);
    let bi = gf2_embed(bi);
    let bii = gf2_embed(bii);
    let ci = gf2_embed(ci);
    let cii = gf2_embed(cii);
    for j in 0..16 {
        dst_a[j].si = ai[j];
        dst_a[j].sii = aii[j];
        dst_b[j].si = bi[j];
        dst_b[j].sii = bii[j];
        dst_c[j].si = ci[j];
        dst_c[j].sii = cii[j];
    }
}

impl<'a> MulTripleEncoder for BsBool16Encoder<'a> {
    mul_triple_encoder_impl!(encode_bsbool16, 16);
}

fn gf2_embed(s:BsBool16) -> [GF2p64;16] {
    let mut res = [GF2p64::ZERO;16];
    let s = s.as_u16();
    res.iter_mut().enumerate().for_each(|(i,r)| {
        if s & 1 << i != 0 {
            *r = GF2p64::ONE;
        }
    });
    res
}

pub struct BsGF4Encoder<'a>(pub &'a mut MulTripleVector<BsGF4>);

#[inline]
fn encode_bsgf4(dst_a: &mut [RssShare<GF2p64>], dst_b: &mut [RssShare<GF2p64>], dst_c: &mut [RssShare<GF2p64>; 2], ai: BsGF4, aii: BsGF4, bi: BsGF4, bii: BsGF4, ci: BsGF4, cii: BsGF4) {
    let (ai1, ai2) = ai.unpack();
    let (aii1, aii2) = aii.unpack();
    dst_a[0].si = ai1.embed();
    dst_a[0].sii = aii1.embed();
    dst_a[1].si = ai2.embed();
    dst_a[1].sii = aii2.embed();

    let (bi1, bi2) = bi.unpack();
    let (bii1, bii2) = bii.unpack();
    dst_b[0].si = bi1.embed();
    dst_b[0].sii = bii1.embed();
    dst_b[1].si = bi2.embed();
    dst_b[1].sii = bii2.embed();
    
    let (ci1, ci2) = ci.unpack();
    let (cii1, cii2) = cii.unpack();
    dst_c[0].si = ci1.embed();
    dst_c[0].sii = cii1.embed();
    dst_c[1].si = ci2.embed();
    dst_c[1].sii = cii2.embed();
}

impl<'a> MulTripleEncoder for BsGF4Encoder<'a> {
    mul_triple_encoder_impl!(encode_bsgf4, 2);
}

pub trait GF4p4TripleRecorder {
    /// Records multiplication triples: (x0 + x1 * alpha) * (y0 + y1 * alpha) = z0 + (z1 * alpha) + (z2 * alpha^2)
    /// where x0, x1, y0, y1, z0, z1, z2 are elements in (2,3) shares in [GF4].
    fn record_mul_triple(&mut self, x0_i: BsGF4, x0_ii: BsGF4, x1_i: BsGF4, x1_ii: BsGF4, y0_i: BsGF4, y0_ii: BsGF4, y1_i: BsGF4, y1_ii: BsGF4, z0_i: BsGF4, z0_ii: BsGF4, z1_i: BsGF4, z1_ii: BsGF4, z2_i: BsGF4, z2_ii: BsGF4);
}

/// Records multiplication triples: (x0 + x1 * alpha) * (y0 + y1 * alpha) = z0 + (z1 * alpha) + (z2 * alpha^2)
/// where x0, x1, y0, y1, z0, z1, z2 are elements in (2,3) shares in [GF4].
pub struct GF4p4TripleVector {
    a: Vec<RssShare<GF2p64>>,
    b: Vec<RssShare<GF2p64>>,
    c: Vec<RssShare<GF2p64>>,
}

impl GF4p4TripleVector {
    pub fn new() -> Self {
        Self {
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.a.len()
    }

    pub fn reserve_for_more_triples(&mut self, n: usize) {
        self.a.reserve_exact(n);
        self.b.reserve_exact(n);
        self.c.reserve_exact(n);
    }

    pub fn clear(&mut self) {
        self.a.clear();
        self.b.clear();
        self.c.clear();
    }

    pub fn create_thread_mul_triple_recorders(&mut self, task_sizes: &[usize]) -> Vec<GF4P4TripleVectorChild> {
        let total_range = task_sizes.iter().sum();
        // get a slice of total_range elements
        self.a.append(&mut vec![RssShare::from(GF2p64::ZERO, GF2p64::ZERO); total_range]);
        self.b.append(&mut vec![RssShare::from(GF2p64::ZERO, GF2p64::ZERO); total_range]);
        self.c.append(&mut vec![RssShare::from(GF2p64::ZERO, GF2p64::ZERO); total_range]);

        let len = self.a.len();

        let mut a_slice = &mut self.a[len-total_range..];
        let mut b_slice = &mut self.b[len-total_range..];
        let mut c_slice = &mut self.c[len-total_range..];

        let mut res = Vec::new();
        for len in task_sizes {
            let (front_a, back_a) = a_slice.split_at_mut(*len);
            a_slice = back_a;
            let (front_b, back_b) = b_slice.split_at_mut(*len);
            b_slice = back_b;
            let (front_c, back_c) = c_slice.split_at_mut(*len);
            c_slice = back_c;
            res.push(GF4P4TripleVectorChild::new(front_a, front_b, front_c));
        }
        res
    }
}

impl GF4p4TripleRecorder for GF4p4TripleVector {
    /// Records multiplication triples: (x0 + x1 * alpha) * (y0 + y1 * alpha) = z0 + (z1 * alpha) + (z2 * alpha^2)
    /// where x0, x1, y0, y1, z0, z1, z2 are elements in (2,3) shares in [GF4].
    fn record_mul_triple(&mut self, x0_i: BsGF4, x0_ii: BsGF4, x1_i: BsGF4, x1_ii: BsGF4, y0_i: BsGF4, y0_ii: BsGF4, y1_i: BsGF4, y1_ii: BsGF4, z0_i: BsGF4, z0_ii: BsGF4, z1_i: BsGF4, z1_ii: BsGF4, z2_i: BsGF4, z2_ii: BsGF4) {
        let (x0_i_h, x0_i_l) = x0_i.unpack();
        let (x0_ii_h, x0_ii_l) = x0_ii.unpack();
        let (x1_i_h, x1_i_l) = x1_i.unpack();
        let (x1_ii_h, x1_ii_l) = x1_ii.unpack();
        self.a.push(RssShare::from(embed_gf4p4_deg2(x0_i_l, x1_i_l), embed_gf4p4_deg2(x0_ii_l, x1_ii_l)));
        self.a.push(RssShare::from(embed_gf4p4_deg2(x0_i_h, x1_i_h), embed_gf4p4_deg2(x0_ii_h, x1_ii_h)));

        let (y0_i_h, y0_i_l) = y0_i.unpack();
        let (y0_ii_h, y0_ii_l) = y0_ii.unpack();
        let (y1_i_h, y1_i_l) = y1_i.unpack();
        let (y1_ii_h, y1_ii_l) = y1_ii.unpack();
        self.b.push(RssShare::from(embed_gf4p4_deg2(y0_i_l, y1_i_l), embed_gf4p4_deg2(y0_ii_l, y1_ii_l)));
        self.b.push(RssShare::from(embed_gf4p4_deg2(y0_i_h, y1_i_h), embed_gf4p4_deg2(y0_ii_h, y1_ii_h)));

        let (z0_i_h, z0_i_l) = z0_i.unpack();
        let (z0_ii_h, z0_ii_l) = z0_ii.unpack();
        let (z1_i_h, z1_i_l) = z1_i.unpack();
        let (z1_ii_h, z1_ii_l) = z1_ii.unpack();
        let (z2_i_h, z2_i_l) = z2_i.unpack();
        let (z2_ii_h, z2_ii_l) = z2_ii.unpack();
        self.c.push(RssShare::from(embed_gf4p4_deg3(z0_i_l, z1_i_l, z2_i_l), embed_gf4p4_deg3(z0_ii_l, z1_ii_l, z2_ii_l)));
        self.c.push(RssShare::from(embed_gf4p4_deg3(z0_i_h, z1_i_h, z2_i_h), embed_gf4p4_deg3(z0_ii_h, z1_ii_h, z2_ii_h)));
    }
}

pub struct GF4P4TripleVectorChild<'a>{
    a: &'a mut [RssShare<GF2p64>],
    b: &'a mut [RssShare<GF2p64>],
    c: &'a mut [RssShare<GF2p64>],
    idx: usize,
}

impl<'a> GF4P4TripleVectorChild<'a> {
    fn new(a: &'a mut [RssShare<GF2p64>], b: &'a mut [RssShare<GF2p64>], c: &'a mut [RssShare<GF2p64>]) -> Self {
        Self { a, b, c, idx: 0 }
    }
}

impl<'a> GF4p4TripleRecorder for GF4P4TripleVectorChild<'a> {
    /// Records multiplication triples: (x0 + x1 * alpha) * (y0 + y1 * alpha) = z0 + (z1 * alpha) + (z2 * alpha^2)
    /// where x0, x1, y0, y1, z0, z1, z2 are elements in (2,3) shares in [GF4].
    fn record_mul_triple(&mut self, x0_i: BsGF4, x0_ii: BsGF4, x1_i: BsGF4, x1_ii: BsGF4, y0_i: BsGF4, y0_ii: BsGF4, y1_i: BsGF4, y1_ii: BsGF4, z0_i: BsGF4, z0_ii: BsGF4, z1_i: BsGF4, z1_ii: BsGF4, z2_i: BsGF4, z2_ii: BsGF4) {
        let (x0_i_h, x0_i_l) = x0_i.unpack();
        let (x0_ii_h, x0_ii_l) = x0_ii.unpack();
        let (x1_i_h, x1_i_l) = x1_i.unpack();
        let (x1_ii_h, x1_ii_l) = x1_ii.unpack();
        self.a[self.idx] = RssShare::from(embed_gf4p4_deg2(x0_i_l, x1_i_l), embed_gf4p4_deg2(x0_ii_l, x1_ii_l));
        self.a[self.idx+1] = RssShare::from(embed_gf4p4_deg2(x0_i_h, x1_i_h), embed_gf4p4_deg2(x0_ii_h, x1_ii_h));

        let (y0_i_h, y0_i_l) = y0_i.unpack();
        let (y0_ii_h, y0_ii_l) = y0_ii.unpack();
        let (y1_i_h, y1_i_l) = y1_i.unpack();
        let (y1_ii_h, y1_ii_l) = y1_ii.unpack();
        self.b[self.idx] = RssShare::from(embed_gf4p4_deg2(y0_i_l, y1_i_l), embed_gf4p4_deg2(y0_ii_l, y1_ii_l));
        self.b[self.idx+1] = RssShare::from(embed_gf4p4_deg2(y0_i_h, y1_i_h), embed_gf4p4_deg2(y0_ii_h, y1_ii_h));

        let (z0_i_h, z0_i_l) = z0_i.unpack();
        let (z0_ii_h, z0_ii_l) = z0_ii.unpack();
        let (z1_i_h, z1_i_l) = z1_i.unpack();
        let (z1_ii_h, z1_ii_l) = z1_ii.unpack();
        let (z2_i_h, z2_i_l) = z2_i.unpack();
        let (z2_ii_h, z2_ii_l) = z2_ii.unpack();
        self.c[self.idx] = RssShare::from(embed_gf4p4_deg3(z0_i_l, z1_i_l, z2_i_l), embed_gf4p4_deg3(z0_ii_l, z1_ii_l, z2_ii_l));
        self.c[self.idx+1] = RssShare::from(embed_gf4p4_deg3(z0_i_h, z1_i_h, z2_i_h), embed_gf4p4_deg3(z0_ii_h, z1_ii_h, z2_ii_h));
        self.idx += 2;
    }
}

pub struct GF4p4TripleEncoder<'a>(pub &'a mut GF4p4TripleVector);

/// Encodes multiplication triples: (x0 + x1 * alpha) * (y0 + y1 * alpha) = z0 + (z1 * alpha) + (z2 * alpha^2)
/// where x0, x1, y0, y1, z0, z1, z2 are elements in (2,3) shares in [GF4].
impl<'a> MulTripleEncoder for GF4p4TripleEncoder<'a> {
    fn len_triples_in(&self) -> usize {
        self.0.len()
    }

    fn len_triples_out(&self) -> usize {
        self.0.len()
    }

    fn add_triples(&mut self, x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], zi: &mut GF2p64InnerProd, zii: &mut GF2p64InnerProd, weight: &mut GF2p64, rand: GF2p64) {
        let mut local_weight = *weight;
        x.copy_from_slice(&self.0.a);
        y.copy_from_slice(&self.0.b);
        izip!(x.iter_mut(), self.0.c.iter()).for_each(|(xi, c)| {
            *xi = *xi * local_weight;
            zi.add_prod(&c.si, &local_weight);
            zii.add_prod(&c.sii, &local_weight);
            local_weight *= rand;
        });
    }

    fn add_triples_par(&mut self, x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], z: &mut RssShare<GF2p64>, weight: GF2p64, rand: &[GF2p64], chunk_size: usize) {
        x.copy_from_slice(&self.0.a);
        y.copy_from_slice(&self.0.b);
        let zvec: Vec<RssShare<GF2p64>> = x.par_chunks_exact_mut(chunk_size)
            .zip_eq(self.0.c.par_chunks_exact_mut(chunk_size))
            .zip_eq(rand)
            .map(|((x_chunk, c_chunk), r)| {
                let mut local_weight = weight;
                let mut zi = GF2p64InnerProd::new();
                let mut zii = GF2p64InnerProd::new();
                x_chunk.iter_mut().zip_eq(c_chunk).for_each(|(xi, ci)| {
                    *xi = *xi * local_weight;
                    zi.add_prod(&ci.si, &local_weight);
                    zii.add_prod(&ci.sii, &local_weight);
                    local_weight *= *r;
                });
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
    use itertools::{izip, Itertools};
    use rand::thread_rng;
    use rep3_core::{party::RngExt, share::HasZero};
    use crate::{share::{bs_bool16::BsBool16, gf2p64::GF2p64, gf4::BsGF4, Field}, util::mul_triple_vec::{BitStringMulTripleRecorder, GF4p4TripleRecorder, GF4p4TripleVector, MulTripleVector}};


    #[test]
    fn record_bit_bitstring_triple_simple() {
        let mut rec = MulTripleVector::new();

        // add a single bit
        rec.record_bit_bitstring_triple(1, &[BsBool16::new(1)], &[BsBool16::new(0)], &[BsBool16::new(1)], &[BsBool16::new(0)], &[BsBool16::new(1)], &[BsBool16::new(1)]);
        assert_eq!(rec.len(), 16);
        assert_eq!(rec.ai[0], GF2p64::ONE);
        assert_eq!(rec.aii[0], GF2p64::ZERO);
        assert_eq!(rec.bi[0], GF2p64::ONE);
        assert_eq!(rec.bii[0], GF2p64::ZERO);
        assert_eq!(rec.ci[0], GF2p64::ONE);
        assert_eq!(rec.cii[0], GF2p64::ONE);
        for i in 1..16 {
            assert_eq!(rec.ai[i], GF2p64::ZERO);
            assert_eq!(rec.aii[i], GF2p64::ZERO);
            assert_eq!(rec.bi[i], GF2p64::ZERO);
            assert_eq!(rec.bii[i], GF2p64::ZERO);
            assert_eq!(rec.ci[i], GF2p64::ZERO);
            assert_eq!(rec.cii[i], GF2p64::ZERO);
        }

        let mut rec = MulTripleVector::new();
        // add a bitstring of size 4
        rec.record_bit_bitstring_triple(1, &[BsBool16::new(1)], &[BsBool16::new(0)], &[BsBool16::new(1), BsBool16::new(1), BsBool16::new(0), BsBool16::new(1)], &[BsBool16::new(0), BsBool16::new(1), BsBool16::new(0), BsBool16::new(0)], &[BsBool16::new(1), BsBool16::new(0), BsBool16::new(1), BsBool16::new(0)], &[BsBool16::new(1), BsBool16::new(1), BsBool16::new(1), BsBool16::new(1)]);
        assert_eq!(rec.len(), 16);
        assert_eq!(rec.ai[0], GF2p64::ONE);
        assert_eq!(rec.aii[0], GF2p64::ZERO);
        assert_eq!(rec.bi[0], GF2p64::new(0b1011u64));
        assert_eq!(rec.bii[0], GF2p64::new(0b0010u64));
        assert_eq!(rec.ci[0], GF2p64::new(0b0101u64));
        assert_eq!(rec.cii[0], GF2p64::new(0b1111u64));
        for i in 1..16 {
            assert_eq!(rec.ai[i], GF2p64::ZERO);
            assert_eq!(rec.aii[i], GF2p64::ZERO);
            assert_eq!(rec.bi[i], GF2p64::ZERO);
            assert_eq!(rec.bii[i], GF2p64::ZERO);
            assert_eq!(rec.ci[i], GF2p64::ZERO);
            assert_eq!(rec.cii[i], GF2p64::ZERO);
        }

        let mut rec = MulTripleVector::new();
        // add a bistring of size 65
        let bs_65 = (0..65).map(|_| BsBool16::new(1)).collect_vec();
        rec.record_bit_bitstring_triple(1, &[BsBool16::new(1)], &[BsBool16::new(0)], &bs_65, &bs_65, &bs_65, &bs_65);
        // this should add 2 triples (in blocks of 16)
        assert_eq!(rec.len(), 32);
        assert_eq!(rec.ai[0], GF2p64::ONE);
        assert_eq!(rec.aii[0], GF2p64::ZERO);
        assert_eq!(rec.bi[0], GF2p64::new(u64::MAX));
        assert_eq!(rec.bii[0], GF2p64::new(u64::MAX));
        assert_eq!(rec.ci[0], GF2p64::new(u64::MAX));
        assert_eq!(rec.cii[0], GF2p64::new(u64::MAX));

        assert_eq!(rec.ai[16], GF2p64::ONE);
        assert_eq!(rec.aii[16], GF2p64::ZERO);
        assert_eq!(rec.bi[16], GF2p64::new(1u64));
        assert_eq!(rec.bii[16], GF2p64::new(1u64));
        assert_eq!(rec.ci[16], GF2p64::new(1u64));
        assert_eq!(rec.cii[16], GF2p64::new(1u64));
        for i in (1..16).chain(17..32) {
            assert_eq!(rec.ai[i], GF2p64::ZERO);
            assert_eq!(rec.aii[i], GF2p64::ZERO);
            assert_eq!(rec.bi[i], GF2p64::ZERO);
            assert_eq!(rec.bii[i], GF2p64::ZERO);
            assert_eq!(rec.ci[i], GF2p64::ZERO);
            assert_eq!(rec.cii[i], GF2p64::ZERO);
        }
    }

    #[test]
    fn record_bit_bitstring_triple_simd() {
        let mut rec = MulTripleVector::new();

        // add a single bit
        // now we are encoding (1,0) * (1,0) = (1,1) and (1,1) * (0,1) = (0,0)
        rec.record_bit_bitstring_triple(2, &[BsBool16::new(1), BsBool16::new(1)], &[BsBool16::new(0), BsBool16::new(1)], &[BsBool16::new(1), BsBool16::new(0)], &[BsBool16::new(0), BsBool16::new(1)], &[BsBool16::new(1), BsBool16::new(0)], &[BsBool16::new(1), BsBool16::new(0)]);
        assert_eq!(rec.len(), 32);
        // trip1 (1,0) * (1,0) = (1,1)
        assert_eq!(rec.ai[0], GF2p64::ONE);
        assert_eq!(rec.aii[0], GF2p64::ZERO);
        assert_eq!(rec.bi[0], GF2p64::ONE);
        assert_eq!(rec.bii[0], GF2p64::ZERO);
        assert_eq!(rec.ci[0], GF2p64::ONE);
        assert_eq!(rec.cii[0], GF2p64::ONE);
        // trip2 (1,1) * (0,1) = (0,0)
        assert_eq!(rec.ai[16], GF2p64::ONE);
        assert_eq!(rec.aii[16], GF2p64::ONE);
        assert_eq!(rec.bi[16], GF2p64::ZERO);
        assert_eq!(rec.bii[16], GF2p64::ONE);
        assert_eq!(rec.ci[16], GF2p64::ZERO);
        assert_eq!(rec.cii[16], GF2p64::ZERO);

        for i in (1..16).chain(17..32) {
            assert_eq!(rec.ai[i], GF2p64::ZERO);
            assert_eq!(rec.aii[i], GF2p64::ZERO);
            assert_eq!(rec.bi[i], GF2p64::ZERO);
            assert_eq!(rec.bii[i], GF2p64::ZERO);
            assert_eq!(rec.ci[i], GF2p64::ZERO);
            assert_eq!(rec.cii[i], GF2p64::ZERO);
        }

        let mut rec = MulTripleVector::new();
        // add 2 bitstrings of size 4 (1,0) * (1011,0010) = (0101,1111) and (0,1) * (0000,1101) = (0110,1110)
        rec.record_bit_bitstring_triple(2, &[BsBool16::new(1), BsBool16::new(0)], &[BsBool16::new(0), BsBool16::new(1)], 
        &[BsBool16::new(1), BsBool16::new(0), BsBool16::new(1), BsBool16::new(0), BsBool16::new(0), BsBool16::new(0), BsBool16::new(1), BsBool16::new(0)], 
        &[BsBool16::new(0), BsBool16::new(1), BsBool16::new(1), BsBool16::new(0), BsBool16::new(0), BsBool16::new(1), BsBool16::new(0), BsBool16::new(1)], 
        &[BsBool16::new(1), BsBool16::new(0), BsBool16::new(0), BsBool16::new(1), BsBool16::new(1), BsBool16::new(1), BsBool16::new(0), BsBool16::new(0)],
         &[BsBool16::new(1), BsBool16::new(0), BsBool16::new(1), BsBool16::new(1), BsBool16::new(1), BsBool16::new(1), BsBool16::new(1), BsBool16::new(1)]);
        assert_eq!(rec.len(), 32);
        // (1,0) * (1011,0010) = (0101,1111)
        assert_eq!(rec.ai[0], GF2p64::ONE);
        assert_eq!(rec.aii[0], GF2p64::ZERO);
        assert_eq!(rec.bi[0], GF2p64::new(0b1011u64));
        assert_eq!(rec.bii[0], GF2p64::new(0b0010u64));
        assert_eq!(rec.ci[0], GF2p64::new(0b0101u64));
        assert_eq!(rec.cii[0], GF2p64::new(0b1111u64));
        // (0,1) * (0000,1101) = (0110,1110)
        assert_eq!(rec.ai[16], GF2p64::ZERO);
        assert_eq!(rec.aii[16], GF2p64::ONE);
        assert_eq!(rec.bi[16], GF2p64::new(0b0000u64));
        assert_eq!(rec.bii[16], GF2p64::new(0b1101u64));
        assert_eq!(rec.ci[16], GF2p64::new(0b0110u64));
        assert_eq!(rec.cii[16], GF2p64::new(0b1110u64));

        for i in (1..16).chain(17..32) {
            assert_eq!(rec.ai[i], GF2p64::ZERO);
            assert_eq!(rec.aii[i], GF2p64::ZERO);
            assert_eq!(rec.bi[i], GF2p64::ZERO);
            assert_eq!(rec.bii[i], GF2p64::ZERO);
            assert_eq!(rec.ci[i], GF2p64::ZERO);
            assert_eq!(rec.cii[i], GF2p64::ZERO);
        }

        let mut rec = MulTripleVector::new();
        // add 2 bistrings of size 65 (1,0) * (111....1, 111...1) = (111...1, 111...1) and (1,1) * (1^33 0^32, 1^33 0^32) = (1^33 0^32, 1^33 0^32)
        let bs_65 = (0..65).map(|_| BsBool16::new(1)).collect_vec();
        let bs_65_half = (0..32).map(|_| BsBool16::new(0)).chain((0..33).map(|_| BsBool16::new(1)));
        let input = bs_65.into_iter().zip(bs_65_half).flat_map(|(simd1, simd2)| [simd1, simd2]).collect_vec();
        rec.record_bit_bitstring_triple(2, &[BsBool16::new(1), BsBool16::new(1)], &[BsBool16::new(0), BsBool16::new(1)], &input, &input, &input, &input);
        // this should add 2 triples (in blocks of 16)
        assert_eq!(rec.len(), 64);

        // (1,0) * (111....1, 111...1) = (111...1, 111...1)
        assert_eq!(rec.ai[0], GF2p64::ONE);
        assert_eq!(rec.aii[0], GF2p64::ZERO);
        assert_eq!(rec.bi[0], GF2p64::new(u64::MAX));
        assert_eq!(rec.bii[0], GF2p64::new(u64::MAX));
        assert_eq!(rec.ci[0], GF2p64::new(u64::MAX));
        assert_eq!(rec.cii[0], GF2p64::new(u64::MAX));

        assert_eq!(rec.ai[32], GF2p64::ONE);
        assert_eq!(rec.aii[32], GF2p64::ZERO);
        assert_eq!(rec.bi[32], GF2p64::new(1u64));
        assert_eq!(rec.bii[32], GF2p64::new(1u64));
        assert_eq!(rec.ci[32], GF2p64::new(1u64));
        assert_eq!(rec.cii[32], GF2p64::new(1u64));

        // (1,1) * (1^33 0^32, 1^33 0^32) = (1^33 0^32, 1^33 0^32)
        assert_eq!(rec.ai[16], GF2p64::ONE);
        assert_eq!(rec.aii[16], GF2p64::ONE);
        assert_eq!(rec.bi[16], GF2p64::new(0xFFFFFFFF00000000u64));
        assert_eq!(rec.bii[16], GF2p64::new(0xFFFFFFFF00000000u64));
        assert_eq!(rec.ci[16], GF2p64::new(0xFFFFFFFF00000000u64));
        assert_eq!(rec.cii[16], GF2p64::new(0xFFFFFFFF00000000u64));

        assert_eq!(rec.ai[48], GF2p64::ONE);
        assert_eq!(rec.aii[48], GF2p64::ONE);
        assert_eq!(rec.bi[48], GF2p64::new(1u64));
        assert_eq!(rec.bii[48], GF2p64::new(1u64));
        assert_eq!(rec.ci[48], GF2p64::new(1u64));
        assert_eq!(rec.cii[48], GF2p64::new(1u64));

        for i in (1..16).chain(17..32).chain(33..48).chain(49..64) {
            assert_eq!(rec.ai[i], GF2p64::ZERO);
            assert_eq!(rec.aii[i], GF2p64::ZERO);
            assert_eq!(rec.bi[i], GF2p64::ZERO);
            assert_eq!(rec.bii[i], GF2p64::ZERO);
            assert_eq!(rec.ci[i], GF2p64::ZERO);
            assert_eq!(rec.cii[i], GF2p64::ZERO);
        }
    }

    #[test]
    fn record_gf4p4_triple() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let a = BsGF4::generate(&mut rng, N);
        let b = BsGF4::generate(&mut rng, N);
        let c = BsGF4::generate(&mut rng, N);
        let d = BsGF4::generate(&mut rng, N);
        let mut rec = GF4p4TripleVector::new();
        rec.reserve_for_more_triples(2*N);
        izip!(a,b,c,d).for_each(|(a,b,c,d)| {
            // test correct multiplication
            //(a + b*alpha) * (c + d*alpha) = a*c + (a*d + b*c)*alpha + b*d*alpha^2
            rec.record_mul_triple(a, BsGF4::ZERO, b, BsGF4::ZERO, c, BsGF4::ZERO, d, BsGF4::ZERO, a*c, BsGF4::ZERO, a*d + b*c, BsGF4::ZERO, b*d, BsGF4::ZERO);
        });

        debug_assert_eq!(rec.a.len(), 2*N);
        debug_assert_eq!(rec.b.len(), 2*N);
        debug_assert_eq!(rec.c.len(), 2*N);

        izip!(rec.a, rec.b, rec.c).for_each(|(a, b, c)| {
            assert_eq!(c.si, a.si * b.si);
        })
    }
}