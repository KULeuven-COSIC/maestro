use itertools::izip;
use rep3_core::share::RssShare;

use crate::share::{bs_bool16::BsBool16, gf2p64::GF2p64, Field};

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

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use rep3_core::share::HasZero;
    use crate::{share::{bs_bool16::BsBool16, gf2p64::GF2p64, Field}, util::mul_triple_vec::{BitStringMulTripleRecorder, MulTripleVector}};


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
}