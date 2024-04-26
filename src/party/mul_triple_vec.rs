use itertools::izip;

use crate::share::{Field, RssShare};

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