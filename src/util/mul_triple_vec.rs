use itertools::{izip, Itertools};
use crate::{conversion::Z64Bool, rep3_core::share::{HasZero, RssShare}};
use std::{array, fmt::Debug, ops::{Index, IndexMut}};
use crate::share::{bs_bool16::BsBool16, gf2p64::{embed_gf2_deg012, embed_gf2_deg036, embed_gf2_deg8, embed_gf4p4_deg2, embed_gf4p4_deg3, GF2p64, GF2p64InnerProd, GF2p64Subfield}, gf4::BsGF4, Field};
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

pub trait Ohv16TripleRecorder {
    /// "Child" recorder type for multi-threading
    type ThreadMulTripleRecorder<'a>: Ohv16TripleRecorder + Sized + Send where Self: 'a;

    fn record_gf2p9_triple_a(&mut self, b0i: &[BsBool16], b0ii: &[BsBool16], b1i: &[BsBool16], b1ii: &[BsBool16], b2i: &[BsBool16], b2ii: &[BsBool16]);
    fn record_gf2p9_triple_b(&mut self, b0i: &[BsBool16], b0ii: &[BsBool16], b3i: &[BsBool16], b3ii: &[BsBool16], b6i: &[BsBool16], b6ii: &[BsBool16]);
    fn record_gf2p9_triple_c(&mut self, bi: [&[BsBool16]; 9], bii: [&[BsBool16]; 9]);
    /// Creates "child" recorders for multi-threading (one for each element in ranges). The child recorders will be used
    /// by threads to record their observed multiplication triples
    /// ranges: Vec of start, end_exclusive of the range that this thread will cover
    fn create_thread_mul_triple_recorders(&mut self, task_sizes: &[usize]) -> Vec<Self::ThreadMulTripleRecorder<'_>>;
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

pub struct GenericMulTripleVector<T, const N: usize>([Vec<T>; N]);

pub struct GenericMulTripleVectorSlice<'a, T, const N: usize>{
    slice: [&'a mut [T]; N],
    idx: usize,
}

impl<'a, T: Copy + Debug, const N: usize> GenericMulTripleVectorSlice<'a, T, N> {
    fn new(refs: Vec<&'a mut [T]>) -> Self {
        Self { slice: refs.try_into().unwrap(), idx: 0}
    }

    /// Appends contents of each slice in src to the respective slice contained.
    pub fn extend_from_slice(&mut self, src: [&[T]; N]) {
        debug_assert!(src.iter().map(|s| s.len()).all_equal());
        let len = src[0].len();
        for i in 0..N {
            self.slice[i][self.idx..self.idx+len].copy_from_slice(src[i]);
        }
        self.idx += len;
    }
}

impl<T: Copy + Debug + HasZero, const N: usize> GenericMulTripleVector<T, N> {
    pub fn new() -> Self {
        assert!(N > 0);
        Self(array::from_fn(|_| Vec::new()))
    }

    pub fn len(&self) -> usize {
        debug_assert!(self.0.iter().map(|v|v.len()).all_equal());
        self.0[0].len()
    }

    /// Also clears the allocated capacity
    pub fn clear(&mut self) {
        self.0 = array::from_fn(|_| Vec::new());
    }

    pub fn reserve_exact(&mut self, n: usize) {
        for i in 0..N {
            self.0[i].reserve_exact(n);
        }
    }

    /// Appends sum(task_sizes) new (empty) triples and returns mutable slices to each part of the
    /// new triples (each with length task_sizes[i])
    pub fn create_slice(&mut self, task_sizes: &[usize]) -> Vec<GenericMulTripleVectorSlice<T, N>> {
        let total_range = task_sizes.iter().sum();
        // get a slice of total_range elements
        for i in 0..N {
            self.0[i].extend_from_slice(&vec![T::ZERO; total_range]);
        }

        let len = self.len();
        let mut slice: Vec<_> = self.0.iter_mut().map(|sl| &mut sl[len-total_range..]).collect();
        let mut res = Vec::new();
        for len in task_sizes {
            let (front, back): (Vec<_>, Vec<_>) = slice.into_iter()
                .map(|sl| sl.split_at_mut(*len))
                .unzip();
            slice = back;
            res.push(GenericMulTripleVectorSlice::new(front));
        }
        res
    }
}

fn zip_eq9<T: Copy, const N: usize>(v: &[Vec<T>; N], start: usize) -> impl Iterator<Item=[T;9]> + '_ {
    izip!(v[start].iter().copied(), v[start+1].iter().copied(), v[start+2].iter().copied(), v[start+3].iter().copied(), v[start+4].iter().copied(), v[start+5].iter().copied(), v[start+6].iter().copied(), v[start+7].iter().copied(), v[start+8].iter().copied())
        .map(|t| t.into())
}

fn zip_eq9_slice<T: Copy, const N: usize>(v: [&[T]; N], start: usize) -> impl Iterator<Item=[T;9]> + '_ {
    izip!(v[start].iter().copied(), v[start+1].iter().copied(), v[start+2].iter().copied(), v[start+3].iter().copied(), v[start+4].iter().copied(), v[start+5].iter().copied(), v[start+6].iter().copied(), v[start+7].iter().copied(), v[start+8].iter().copied())
        .map(|t| t.into())
}

fn par_zip_eq9<T: Copy + Sync>(v: &GenericMulTripleVector<T, 18>, chunk_size: usize, start: usize) -> impl IndexedParallelIterator<Item=[&[T];9]> + '_ {
    v.0[start].par_chunks(chunk_size).zip_eq(v.0[start+1].par_chunks(chunk_size))
    .zip_eq(v.0[start+2].par_chunks(chunk_size))
    .zip_eq(v.0[start+3].par_chunks(chunk_size))
    .zip_eq(v.0[start+4].par_chunks(chunk_size))
    .zip_eq(v.0[start+5].par_chunks(chunk_size))
    .zip_eq(v.0[start+6].par_chunks(chunk_size))
    .zip_eq(v.0[start+7].par_chunks(chunk_size))
    .zip_eq(v.0[start+8].par_chunks(chunk_size))
    .map(|((((((((t0,t1), t2, ), t3), t4), t5), t6), t7), t8)| [t0, t1, t2, t3, t4, t5, t6, t7, t8])
}


impl<T, const N:usize> Index<usize> for GenericMulTripleVector<T, N> {
    type Output = Vec<T>;
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T, const N: usize> IndexMut<usize> for GenericMulTripleVector<T, N> {
    
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<'a, T, const N: usize> Index<usize> for GenericMulTripleVectorSlice<'a, T, N> {
    type Output = [T];
    fn index(&self, index: usize) -> &Self::Output {
        &self.slice[index]
    }
}

impl<'a, T, const N: usize> IndexMut<usize> for GenericMulTripleVectorSlice<'a, T, N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.slice[index]
    }
}

pub struct Ohv16TripleVector {
    a: GenericMulTripleVector<BsBool16, 6>, // 0,1,2 are si, 3,4,5 are sii
    b: GenericMulTripleVector<BsBool16, 6>, // 0,1,2 are si, 3,4,5 are sii
    c: GenericMulTripleVector<BsBool16, 18>, // 0-8 are si, 9-17 are sii
}

pub struct Ohv16TripleVectorSlice<'a> {
    a: GenericMulTripleVectorSlice<'a, BsBool16, 6>,
    b: GenericMulTripleVectorSlice<'a, BsBool16, 6>,
    c: GenericMulTripleVectorSlice<'a, BsBool16, 18>,
}

impl Ohv16TripleVector {
    pub fn new() -> Self {
        Self { a: GenericMulTripleVector::new(), b: GenericMulTripleVector::new(), c: GenericMulTripleVector::new() }
    }

    pub fn len(&self) -> usize {
        debug_assert_eq!(self.a.len(), self.b.len());
        debug_assert_eq!(self.a.len(), self.c.len());
        self.a.len()
    }

    pub fn reserve_for_more_triples(&mut self, n: usize) {
        self.a.reserve_exact(n);
        self.b.reserve_exact(n);
        self.c.reserve_exact(n);
    }
}

impl Ohv16TripleRecorder for Ohv16TripleVector {
    type ThreadMulTripleRecorder<'a> = Ohv16TripleVectorSlice<'a>;
    fn record_gf2p9_triple_a(&mut self, b0i: &[BsBool16], b0ii: &[BsBool16], b1i: &[BsBool16], b1ii: &[BsBool16], b2i: &[BsBool16], b2ii: &[BsBool16]) {
        self.a[0].extend_from_slice(b0i);
        self.a[1].extend_from_slice(b1i);
        self.a[2].extend_from_slice(b2i);
        self.a[3].extend_from_slice(b0ii);
        self.a[4].extend_from_slice(b1ii);
        self.a[5].extend_from_slice(b2ii);
    }
    fn record_gf2p9_triple_b(&mut self, b0i: &[BsBool16], b0ii: &[BsBool16], b3i: &[BsBool16], b3ii: &[BsBool16], b6i: &[BsBool16], b6ii: &[BsBool16]) {
        self.b[0].extend_from_slice(b0i);
        self.b[1].extend_from_slice(b3i);
        self.b[2].extend_from_slice(b6i);
        self.b[3].extend_from_slice(b0ii);
        self.b[4].extend_from_slice(b3ii);
        self.b[5].extend_from_slice(b6ii);
    }
    fn record_gf2p9_triple_c(&mut self, bi: [&[BsBool16]; 9], bii: [&[BsBool16]; 9]) {
        for i in 0..9 {
            self.c[i].extend_from_slice(bi[i]);
        }
        for i in 0..9 {
            self.c[9+i].extend_from_slice(bii[i]);
        }
    }
    fn create_thread_mul_triple_recorders(&mut self, task_sizes: &[usize]) -> Vec<Self::ThreadMulTripleRecorder<'_>> {
        izip!(self.a.create_slice(task_sizes), self.b.create_slice(task_sizes), self.c.create_slice(task_sizes)).map(|(a, b, c)| {
            Ohv16TripleVectorSlice { a, b, c }
        }).collect()
    }
}

impl<'a> Ohv16TripleRecorder for Ohv16TripleVectorSlice<'a> {
    type ThreadMulTripleRecorder<'b> = Ohv16TripleVectorSlice<'b> where Self: 'b;
    fn record_gf2p9_triple_a(&mut self, b0i: &[BsBool16], b0ii: &[BsBool16], b1i: &[BsBool16], b1ii: &[BsBool16], b2i: &[BsBool16], b2ii: &[BsBool16]) {
        self.a.extend_from_slice([b0i, b1i, b2i, b0ii, b1ii, b2ii]);
    }
    fn record_gf2p9_triple_b(&mut self, b0i: &[BsBool16], b0ii: &[BsBool16], b3i: &[BsBool16], b3ii: &[BsBool16], b6i: &[BsBool16], b6ii: &[BsBool16]) {
        self.b.extend_from_slice([b0i, b3i, b6i, b0ii, b3ii, b6ii]);
    }
    fn record_gf2p9_triple_c(&mut self, bi: [&[BsBool16]; 9], bii: [&[BsBool16]; 9]) {
        let [b0i, b1i, b2i, b3i, b4i, b5i, b6i, b7i, b8i] = bi;
        let [b0ii, b1ii, b2ii, b3ii, b4ii, b5ii, b6ii, b7ii, b8ii] = bii;
        self.c.extend_from_slice([b0i, b1i, b2i, b3i, b4i, b5i, b6i, b7i, b8i, b0ii, b1ii, b2ii, b3ii, b4ii, b5ii, b6ii, b7ii, b8ii]);
    }
    fn create_thread_mul_triple_recorders(&mut self, _task_sizes: &[usize]) -> Vec<Self::ThreadMulTripleRecorder<'_>> {
        unimplemented!()
    }
}

pub struct Ohv16TripleEncoder<'a>(pub &'a mut Ohv16TripleVector);

impl<'a> MulTripleEncoder for Ohv16TripleEncoder<'a> {
    fn len_triples_in(&self) -> usize {
        self.0.len()
    }
    fn len_triples_out(&self) -> usize {
        16 * self.0.len()
    }
    fn add_triples(&mut self, x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], zi: &mut GF2p64InnerProd, zii: &mut GF2p64InnerProd, weight: &mut GF2p64, rand: GF2p64) {
        let mut si = [GF2p64::ZERO; 16];
        let mut sii = [GF2p64::ZERO; 16];
        izip!(x.chunks_exact_mut(16), &self.0.a[0], &self.0.a[1], &self.0.a[2], &self.0.a[3], &self.0.a[4], &self.0.a[5]).for_each(|(dst, a0i, a1i, a2i, a0ii, a1ii, a2ii)| {
            embed_gf2_deg012(&mut si, *a0i, *a1i, *a2i);
            embed_gf2_deg012(&mut sii, *a0ii, *a1ii, *a2ii);
            for i in 0..16 {
                dst[i].si = si[i];
                dst[i].sii = sii[i];
            }
        });

        izip!(y.chunks_exact_mut(16), &self.0.b[0], &self.0.b[1], &self.0.b[2], &self.0.b[3], &self.0.b[4], &self.0.b[5]).for_each(|(dst, b0i, b1i, b2i, b0ii, b1ii, b2ii)| {
            embed_gf2_deg036(&mut si, *b0i, *b1i, *b2i);
            embed_gf2_deg036(&mut sii, *b0ii, *b1ii, *b2ii);
            for i in 0..16 {
                dst[i].si = si[i];
                dst[i].sii = sii[i];
            }
        });
        let mut local_weight = *weight;
        izip!(x.chunks_exact_mut(16), zip_eq9(&self.0.c.0, 0), zip_eq9(&self.0.c.0, 9)).for_each(|(x_chunks, ci, cii)| {
            embed_gf2_deg8(&mut si, ci[0], ci[1], ci[2], ci[3], ci[4], ci[5], ci[6], ci[7], ci[8]);
            embed_gf2_deg8(&mut sii, cii[0], cii[1], cii[2], cii[3], cii[4], cii[5], cii[6], cii[7], cii[8]);
            for i in 0..16 {
                x_chunks[i] = x_chunks[i] * local_weight;
                zi.add_prod(&si[i], &local_weight);
                zii.add_prod(&sii[i], &local_weight);
                local_weight *= rand;
            }
        });
        *weight = local_weight;
    }
    fn add_triples_par(&mut self, x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], z: &mut RssShare<GF2p64>, weight: GF2p64, rand: &[GF2p64], chunk_size: usize) {
        x.par_chunks_mut(16*chunk_size).zip_eq(self.0.a[0].par_chunks(chunk_size))
        .zip_eq(self.0.a[1].par_chunks(chunk_size))
        .zip_eq(self.0.a[2].par_chunks(chunk_size))
        .zip_eq(self.0.a[3].par_chunks(chunk_size))
        .zip_eq(self.0.a[4].par_chunks(chunk_size))
        .zip_eq(self.0.a[5].par_chunks(chunk_size))
        .for_each(|((((((x, a0i), a1i), a2i), a0ii), a1ii), a2ii)| {
            let mut si = [GF2p64::ZERO; 16];
            let mut sii = [GF2p64::ZERO; 16];
            izip!(x.chunks_exact_mut(16), a0i, a1i, a2i, a0ii, a1ii, a2ii).for_each(|(dst, a0i, a1i, a2i, a0ii, a1ii, a2ii)| {
                embed_gf2_deg012(&mut si, *a0i, *a1i, *a2i);
                embed_gf2_deg012(&mut sii, *a0ii, *a1ii, *a2ii);
                for i in 0..16 {
                    dst[i].si = si[i];
                    dst[i].sii = sii[i];
                }
            });
        });

        y.par_chunks_mut(16*chunk_size).zip_eq(self.0.b[0].par_chunks(chunk_size))
        .zip_eq(self.0.b[1].par_chunks(chunk_size))
        .zip_eq(self.0.b[2].par_chunks(chunk_size))
        .zip_eq(self.0.b[3].par_chunks(chunk_size))
        .zip_eq(self.0.b[4].par_chunks(chunk_size))
        .zip_eq(self.0.b[5].par_chunks(chunk_size))
        .for_each(|((((((y, b0i), b1i), b2i), b0ii), b1ii), b2ii)| {
            let mut si = [GF2p64::ZERO; 16];
            let mut sii = [GF2p64::ZERO; 16];
            izip!(y.chunks_exact_mut(16), b0i, b1i, b2i, b0ii, b1ii, b2ii).for_each(|(dst, b0i, b1i, b2i, b0ii, b1ii, b2ii)| {
                embed_gf2_deg036(&mut si, *b0i, *b1i, *b2i);
                embed_gf2_deg036(&mut sii, *b0ii, *b1ii, *b2ii);
                for i in 0..16 {
                    dst[i].si = si[i];
                    dst[i].sii = sii[i];
                }
            });
        });

        let z_vec: Vec<_> = x.par_chunks_mut(16*chunk_size).zip_eq(par_zip_eq9(&self.0.c, chunk_size, 0))
        .zip_eq(par_zip_eq9(&self.0.c, chunk_size, 9))
        .zip_eq(rand)
        .map(|(((x, ci), cii), rand)| {
            let mut zi = GF2p64InnerProd::new();
            let mut zii = GF2p64InnerProd::new();
            let mut local_weight = weight;
            let mut si = [GF2p64::ZERO; 16];
            let mut sii = [GF2p64::ZERO; 16];
            izip!(x.chunks_exact_mut(16), zip_eq9_slice(ci, 0), zip_eq9_slice(cii, 0)).for_each(|(x_chunks, ci, cii)| {
                embed_gf2_deg8(&mut si, ci[0], ci[1], ci[2], ci[3], ci[4], ci[5], ci[6], ci[7], ci[8]);
                embed_gf2_deg8(&mut sii, cii[0], cii[1], cii[2], cii[3], cii[4], cii[5], cii[6], cii[7], cii[8]);
                for i in 0..16 {
                    x_chunks[i] = x_chunks[i] * local_weight;
                    zi.add_prod(&si[i], &local_weight);
                    zii.add_prod(&sii[i], &local_weight);
                    local_weight *= *rand;
                }
            });
            RssShare::from(zi.sum(), zii.sum())
        }).collect();
        z_vec.into_iter().for_each(|zi| *z += zi);
    }

    fn clear(&mut self) {
        self.0.a.clear();
        self.0.b.clear();
        self.0.c.clear();
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
        let zvec: Vec<RssShare<GF2p64>> = x.par_chunks_mut(chunk_size)
            .zip_eq(self.0.c.par_chunks_mut(chunk_size))
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

pub struct Z64TripleEncoder<'a>(pub &'a mut MulTripleVector<Z64Bool>);

#[inline]
fn encode_z64(dst_a: &mut [RssShare<GF2p64>], dst_b: &mut [RssShare<GF2p64>], dst_c: &mut [RssShare<GF2p64>; 64], ai: Z64Bool, aii: Z64Bool, bi: Z64Bool, bii: Z64Bool, ci: Z64Bool, cii: Z64Bool) {
    #[inline]
    fn embed_bit(dst: &mut RssShare<GF2p64>, xi: Z64Bool, xii: Z64Bool, i: usize) {
        dst.si = if ((xi.0 >> i) & 0x1) == 0 {GF2p64::ZERO} else {GF2p64::ONE};
        dst.sii = if ((xii.0 >> i) & 0x1) == 0 {GF2p64::ZERO} else {GF2p64::ONE};
    }
    
    for i in 0..64 {
        embed_bit(&mut dst_a[i], ai, aii, i);
        embed_bit(&mut dst_b[i], bi, bii, i);
        embed_bit(&mut dst_c[i], ci, cii, i);
    }
}

impl<'a> MulTripleEncoder for Z64TripleEncoder<'a> {
    mul_triple_encoder_impl!(encode_z64, 64);
}

#[cfg(test)]
pub mod test {
    use std::slice;

    use itertools::{izip, Itertools};
    use rand::{thread_rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use crate::rep3_core::{party::{MainParty, RngExt}, share::{HasZero, RssShare}, test::localhost_setup};
    use crate::{share::{bs_bool16::BsBool16, gf2p64::{GF2p64, GF2p64InnerProd}, gf4::BsGF4, gf8::GF8, test::{consistent, secret_share, secret_share_vector}, Field}, util::mul_triple_vec::{BitStringMulTripleRecorder, BsBool16Encoder, BsGF4Encoder, GF2p64Encoder, GF2p64SubfieldEncoder, GF4p4TripleRecorder, GF4p4TripleVector, MulTripleRecorder, MulTripleVector, Ohv16TripleEncoder, Ohv16TripleRecorder, Ohv16TripleVector}};
    use crate::share::test::assert_eq;
    use super::{GenericMulTripleVector, MulTripleEncoder};


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

    pub fn check_correct_encoding<Enc: MulTripleEncoder>(mut enc1: Enc, mut enc2: Enc, mut enc3: Enc, n_expected_triples: usize, check_weight: bool) {
        assert_eq!(enc1.len_triples_in(), enc2.len_triples_in());
        assert_eq!(enc1.len_triples_in(), enc3.len_triples_in());
        assert_eq!(enc1.len_triples_out(), enc2.len_triples_out());
        assert_eq!(enc1.len_triples_out(), enc3.len_triples_out());
        assert_eq!(enc1.len_triples_out(), n_expected_triples);
        let mut x1 = vec![RssShare::ZERO; enc1.len_triples_out()];
        let mut x2 = vec![RssShare::ZERO; enc1.len_triples_out()];
        let mut x3 = vec![RssShare::ZERO; enc1.len_triples_out()];

        let mut y1 = vec![RssShare::ZERO; enc1.len_triples_out()];
        let mut y2 = vec![RssShare::ZERO; enc1.len_triples_out()];
        let mut y3 = vec![RssShare::ZERO; enc1.len_triples_out()];

        let mut rng = thread_rng();
        let (weight, rand) = GF2p64::generate(&mut rng, 2).into_iter().collect_tuple().unwrap();
        assert!(weight != GF2p64::ZERO);
        assert!(rand != GF2p64::ZERO);

        let mut z1i = GF2p64InnerProd::new();
        let mut z1ii = GF2p64InnerProd::new();
        let mut z2i = GF2p64InnerProd::new();
        let mut z2ii = GF2p64InnerProd::new();
        let mut z3i = GF2p64InnerProd::new();
        let mut z3ii = GF2p64InnerProd::new();

        let mut weight1 = weight;
        enc1.add_triples(&mut x1, &mut y1, &mut z1i, &mut z1ii, &mut weight1, rand);
        if check_weight {
            // check that enc1 changed weight
            let expected_weight = (0..enc1.len_triples_out()).fold(weight, |acc, _| acc * rand);
            assert_eq!(weight1, expected_weight);
        }

        let mut weight2 = weight;
        enc2.add_triples(&mut x2, &mut y2, &mut z2i, &mut z2ii, &mut weight2, rand);
        if check_weight {
            assert_eq!(weight1, weight2);
        }

        let mut weight3 = weight;
        enc3.add_triples(&mut x3, &mut y3, &mut z3i, &mut z3ii, &mut weight3, rand);
        if check_weight {
            assert_eq!(weight1, weight3);
        }

        let mut x_y_sum = GF2p64InnerProd::new();
        // check correct inner product
        izip!(x1, x2, x3, y1, y2, y3).for_each(|(x1, x2, x3, y1, y2, y3)| {
            consistent(&x1, &x2, &x3);
            consistent(&y1, &y2, &y3);
            let x = x1.si + x2.si + x3.si;
            let y = y1.si + y2.si + y3.si;
            x_y_sum.add_prod(&x, &y);
        });
        let x_y_sum = x_y_sum.sum();
        let z1 = RssShare::from(z1i.sum(), z1ii.sum());
        let z2 = RssShare::from(z2i.sum(), z2ii.sum());
        let z3 = RssShare::from(z3i.sum(), z3ii.sum());
        consistent(&z1, &z2, &z3);
        assert_eq(z1, z2, z3, x_y_sum);
    }

    pub fn check_correct_encoding_par<Enc: MulTripleEncoder + Send>(enc1: Enc, enc2: Enc, enc3: Enc, n_expected_triples: usize) {
        assert_eq!(enc1.len_triples_in(), enc2.len_triples_in());
        assert_eq!(enc1.len_triples_in(), enc3.len_triples_in());
        assert_eq!(enc1.len_triples_out(), enc2.len_triples_out());
        assert_eq!(enc1.len_triples_out(), enc3.len_triples_out());
        assert_eq!(enc1.len_triples_out(), n_expected_triples);

        let program = |mut enc: Enc, weight: GF2p64| {
            move |p: &mut MainParty| {
                // seed a PRNG to get the same rand
                let mut rng = ChaCha20Rng::seed_from_u64(373244654435);
                let mut x = vec![RssShare::ZERO; enc.len_triples_out()];
                let mut y = vec![RssShare::ZERO; enc.len_triples_out()];
                let mut z = RssShare::ZERO;
                let chunk_size = p.chunk_size_for_task(enc.len_triples_in());
                let rand = GF2p64::generate(&mut rng, p.num_worker_threads());
                enc.add_triples_par(&mut x, &mut y, &mut z, weight, &rand, chunk_size);
                (x, y, z)
            }
        };

        let mut rng = thread_rng();
        let weight = GF2p64::generate(&mut rng, 1)[0];
        assert!(weight != GF2p64::ZERO);
        
        let (((x1, y1, z1), _), ((x2, y2, z2), _), ((x3, y3, z3), _)) = 
            localhost_setup(program(enc1, weight), program(enc2, weight), program(enc3, weight), Some(3));

        let mut x_y_sum = GF2p64InnerProd::new();
        // check correct inner product
        izip!(x1, x2, x3, y1, y2, y3).for_each(|(x1, x2, x3, y1, y2, y3)| {
            consistent(&x1, &x2, &x3);
            consistent(&y1, &y2, &y3);
            let x = x1.si + x2.si + x3.si;
            let y = y1.si + y2.si + y3.si;
            x_y_sum.add_prod(&x, &y);
        });
        let x_y_sum = x_y_sum.sum();
        consistent(&z1, &z2, &z3);
        assert_eq(z1, z2, z3, x_y_sum);
    }

    pub fn generate_and_fill_random_triples<F: Field, R: MulTripleRecorder<F>>(rec1: &mut R, rec2: &mut R, rec3: &mut R, n: usize) {
        let mut rng = thread_rng();

        let x = F::generate(&mut rng, n);
        let y = F::generate(&mut rng, n);
        let z = x.iter().zip_eq(y.iter()).map(|(xi, yi)| *xi * *yi).collect_vec();
        let (x1, x2, x3) = secret_share_vector(&mut rng, x);
        let (y1, y2, y3) = secret_share_vector(&mut rng, y);
        let (z1, z2, z3) = secret_share_vector(&mut rng, z);
        record_mul_triple(rec1, x1, y1, z1);
        record_mul_triple(rec2, x2, y2, z2);
        record_mul_triple(rec3, x3, y3, z3);
    }

    fn record_mul_triple<F: Field, R: MulTripleRecorder<F>>(rec: &mut R, x: Vec<RssShare<F>>, y: Vec<RssShare<F>>, z: Vec<RssShare<F>>) {
        let (xi, xii): (Vec<_>, Vec<_>) = x.into_iter().map(|rss| (rss.si, rss.sii)).unzip();
        let (yi, yii): (Vec<_>, Vec<_>) = y.into_iter().map(|rss| (rss.si, rss.sii)).unzip();
        let (zi, zii): (Vec<_>, Vec<_>) = z.into_iter().map(|rss| (rss.si, rss.sii)).unzip();
        rec.record_mul_triple(&xi, &xii, &yi, &yii, &zi, &zii);
    }

    #[test]
    fn gf2p64_encoder_correct() {
        const N: usize = 100;
        // collect N correct triples
        let mut rec1 = MulTripleVector::new();
        let mut rec2 = MulTripleVector::new();
        let mut rec3 = MulTripleVector::new();
        generate_and_fill_random_triples(&mut rec1, &mut rec2, &mut rec3, N);
        assert_eq!(rec1.len(), N);
        assert_eq!(rec2.len(), N);
        assert_eq!(rec3.len(), N);

        // now test if the encoding is correct
        check_correct_encoding(GF2p64Encoder(&mut rec1), GF2p64Encoder(&mut rec2), GF2p64Encoder(&mut rec3), N, true);

        // now test if the encoding is correct when encoding in parallel
        check_correct_encoding_par(GF2p64Encoder(&mut rec1), GF2p64Encoder(&mut rec2), GF2p64Encoder(&mut rec3), N);
    }

    #[test]
    fn gf2p64_subfield_encoder_gf8_correct() {
        const N: usize = 100;
        // collect N correct triples
        let mut rec1 = MulTripleVector::new();
        let mut rec2 = MulTripleVector::new();
        let mut rec3 = MulTripleVector::new();

        generate_and_fill_random_triples::<GF8, _>(&mut rec1, &mut rec2, &mut rec3, N);
        assert_eq!(rec1.len(), N);
        assert_eq!(rec2.len(), N);
        assert_eq!(rec3.len(), N);

        // now test if the encoding is correct
        check_correct_encoding(GF2p64SubfieldEncoder(&mut rec1), GF2p64SubfieldEncoder(&mut rec2), GF2p64SubfieldEncoder(&mut rec3), N, true);

        // now test if the encoding is correct when encoding in parallel
        check_correct_encoding_par(GF2p64SubfieldEncoder(&mut rec1), GF2p64SubfieldEncoder(&mut rec2), GF2p64SubfieldEncoder(&mut rec3), N);
    }

    #[test]
    fn bsbool16_encoder_correct() {
        const N: usize = 100;
        // collect N correct triples
        let mut rec1 = MulTripleVector::new();
        let mut rec2 = MulTripleVector::new();
        let mut rec3 = MulTripleVector::new();

        generate_and_fill_random_triples::<BsBool16, _>(&mut rec1, &mut rec2, &mut rec3, N);
        assert_eq!(rec1.len(), N);
        assert_eq!(rec2.len(), N);
        assert_eq!(rec3.len(), N);

        // now test if the encoding is correct
        check_correct_encoding(BsBool16Encoder(&mut rec1), BsBool16Encoder(&mut rec2), BsBool16Encoder(&mut rec3), 16*N, true);

        // now test if the encoding is correct when encoding in parallel
        check_correct_encoding_par(BsBool16Encoder(&mut rec1), BsBool16Encoder(&mut rec2), BsBool16Encoder(&mut rec3), 16*N);
    }

    #[test]
    fn bs_gf4_encoder_correct() {
        const N: usize = 100;
        // collect N correct triples
        let mut rec1 = MulTripleVector::new();
        let mut rec2 = MulTripleVector::new();
        let mut rec3 = MulTripleVector::new();

        generate_and_fill_random_triples::<BsGF4, _>(&mut rec1, &mut rec2, &mut rec3, N);
        assert_eq!(rec1.len(), N);
        assert_eq!(rec2.len(), N);
        assert_eq!(rec3.len(), N);

        // now test if the encoding is correct
        check_correct_encoding(BsGF4Encoder(&mut rec1), BsGF4Encoder(&mut rec2), BsGF4Encoder(&mut rec3), 2*N, true);

        // now test if the encoding is correct when encoding in parallel
        check_correct_encoding_par(BsGF4Encoder(&mut rec1), BsGF4Encoder(&mut rec2), BsGF4Encoder(&mut rec3), 2*N);
    }

    #[test]
    fn ohv16_triple_vector_encoder_correct() {
        const N: usize = 100;
        let mut rec1 = Ohv16TripleVector::new();
        let mut rec2 = Ohv16TripleVector::new();
        let mut rec3 = Ohv16TripleVector::new();
        
        let mut rng = thread_rng();
        let r0 = BsBool16::generate(&mut rng, N);
        let r1 = BsBool16::generate(&mut rng, N);
        let r2 = BsBool16::generate(&mut rng, N);
        let r3 = BsBool16::generate(&mut rng, N);
        let r4 = BsBool16::generate(&mut rng, N);
        let r5 = BsBool16::generate(&mut rng, N);

        izip!(r0, r1, r2, r3, r4, r5).for_each(|(r0, r1, r2, r3, r4, r5)| {
            let expected = [r0*r3, r1*r3, r2*r3, r0*r4, r1*r4, r2*r4, r0*r5, r1*r5, r2*r5];
            let r0 = secret_share(&mut rng, &r0);
            let r1 = secret_share(&mut rng, &r1);
            let r2 = secret_share(&mut rng, &r2);
            let r3 = secret_share(&mut rng, &r3);
            let r4 = secret_share(&mut rng, &r4);
            let r5 = secret_share(&mut rng, &r5);
            rec1.record_gf2p9_triple_a(&[r0.0.si], &[r0.0.sii], &[r1.0.si], &[r1.0.sii], &[r2.0.si], &[r2.0.sii]);
            rec2.record_gf2p9_triple_a(&[r0.1.si], &[r0.1.sii], &[r1.1.si], &[r1.1.sii], &[r2.1.si], &[r2.1.sii]);
            rec3.record_gf2p9_triple_a(&[r0.2.si], &[r0.2.sii], &[r1.2.si], &[r1.2.sii], &[r2.2.si], &[r2.2.sii]);

            rec1.record_gf2p9_triple_b(&[r3.0.si], &[r3.0.sii], &[r4.0.si], &[r4.0.sii], &[r5.0.si], &[r5.0.sii]);
            rec2.record_gf2p9_triple_b(&[r3.1.si], &[r3.1.sii], &[r4.1.si], &[r4.1.sii], &[r5.1.si], &[r5.1.sii]);
            rec3.record_gf2p9_triple_b(&[r3.2.si], &[r3.2.sii], &[r4.2.si], &[r4.2.sii], &[r5.2.si], &[r5.2.sii]);

            let mut expected_i = (Vec::new(), Vec::new(), Vec::new());
            let mut expected_ii = (Vec::new(), Vec::new(), Vec::new());
            expected.into_iter().for_each(|s| {
                let (s1, s2, s3) = secret_share(&mut rng, &s);
                expected_i.0.push(s1.si);
                expected_ii.0.push(s1.sii);
                expected_i.1.push(s2.si);
                expected_ii.1.push(s2.sii);
                expected_i.2.push(s3.si);
                expected_ii.2.push(s3.sii);
            });
            fn record_gf2p9_triple_c(rec: &mut Ohv16TripleVector, expected_i: Vec<BsBool16>, expected_ii: Vec<BsBool16>) {
                let expected_i: [_; 9] = expected_i.iter().map(|x| slice::from_ref(x)).collect_vec().try_into().unwrap();
                let expected_ii: [_; 9] = expected_ii.iter().map(|x| slice::from_ref(x)).collect_vec().try_into().unwrap();
                rec.record_gf2p9_triple_c(expected_i, expected_ii);
            }
            record_gf2p9_triple_c(&mut rec1, expected_i.0, expected_ii.0);
            record_gf2p9_triple_c(&mut rec2, expected_i.1, expected_ii.1);
            record_gf2p9_triple_c(&mut rec3, expected_i.2, expected_ii.2);
        });

        // now test if the encoding is correct
        check_correct_encoding(Ohv16TripleEncoder(&mut rec1), Ohv16TripleEncoder(&mut rec2), Ohv16TripleEncoder(&mut rec3), 16*N, true);

        // now test if the encoding is correct when encoding in parallel
        check_correct_encoding_par(Ohv16TripleEncoder(&mut rec1), Ohv16TripleEncoder(&mut rec2), Ohv16TripleEncoder(&mut rec3), 16*N);
    }

    #[test]
    fn vector_slice_extend_from_slice() {
        let mut vec = GenericMulTripleVector::<GF8, 2>::new();
        // allocate 1024
        vec.reserve_exact(1024);
        assert_eq!(vec[0].capacity(), 1024);
        assert_eq!(vec[1].capacity(), 1024);

        let slices = vec.create_slice(&[123, 456]);

        assert_eq!(slices.len(), 2);
        assert_eq!(slices[0][0].len(), 123);
        assert_eq!(slices[0][1].len(), 123);
        assert_eq!(slices[1][0].len(), 456);
        assert_eq!(slices[1][1].len(), 456);

        // the slices can be filled
        let src123_1 = vec![GF8(0x12); 56];
        let src123_2 = vec![GF8(0x12); 123-56];
        let src456 = vec![GF8(0x45); 450];

        let mut it = slices.into_iter();
        let mut sl0 = it.next().unwrap();
        let mut sl1 = it.next().unwrap();
        
        sl0.extend_from_slice([&src123_1, &src123_1]);
        sl1.extend_from_slice([&src456, &src456]);
        sl0.extend_from_slice([&src123_2, &src123_2]);
        
        // drop the slices to read the vec again
        drop(sl0);
        drop(sl1);

        // creating slices doesn't increase the capacity in this case since 123+456 < 1024
        assert_eq!(vec[0].capacity(), 1024);
        assert_eq!(vec[1].capacity(), 1024);

        assert_eq!(&vec.0[0][0..123], &vec![GF8(0x12); 123]);
        assert_eq!(&vec.0[0][123..123+450], &vec![GF8(0x45); 450]);
        assert_eq!(&vec.0[1][0..123], &vec![GF8(0x12); 123]);
        assert_eq!(&vec.0[1][123..123+450], &vec![GF8(0x45); 450]);
    }
}