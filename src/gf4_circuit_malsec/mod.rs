
use itertools::{izip, Itertools};
use rayon::{iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator}, slice::ParallelSliceMut};

use crate::{aes::AesVariant, chida, rep3_core::{network::{task::IoLayerOwned, ConnectedParty}, party::{broadcast::{Broadcast, BroadcastContext}, error::{MpcError, MpcResult}, MainParty, Party}, share::{HasZero, RssShare}}, util::mul_triple_vec::{GF4p4TripleEncoder, GF4p4TripleRecorder, GF4p4TripleVector}, wollut16_malsec::online::{un_wol_bitslice_gf4, wol_bitslice_gf4}};
use crate::{aes::GF8InvBlackBox, furukawa, gf4_circuit, share::{gf4::BsGF4, gf8::GF8}, util::{mul_triple_vec::{BsGF4Encoder, MulTripleRecorder, MulTripleVector}, ArithmeticBlackBox}, wollut16_malsec};

mod offline;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum MultCheckType {
    /// recursive mult. check at the end of the online phase
    Recursive { check_after_sbox: bool, use_gf4p4_check: bool},
    /// recursive mult. check to create beaver triples, then sacrifice
    RecursiveBeaver,
    /// Bucket cut-and-choose to create beaver triples, then sacrifice
    BucketBeaver,
}

pub struct GF4CircuitASParty {
    inner: MainParty,
    broadcast_context: BroadcastContext,
    gf4_triples_to_check: MulTripleVector<BsGF4>,
    gf4p4_triples_to_check: GF4p4TripleVector,
    check_type: MultCheckType,
    gf4_beaver_triples: MulTripleVector<BsGF4>,
}

impl GF4CircuitASParty {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>, prot_str: Option<String>, check_type: MultCheckType) -> MpcResult<Self> {

        MainParty::setup(connected, n_worker_threads, prot_str).map(|party| Self {
            inner: party,
            broadcast_context: BroadcastContext::new(),
            gf4_triples_to_check: MulTripleVector::new(),
            gf4p4_triples_to_check: GF4p4TripleVector::new(),
            check_type,
            gf4_beaver_triples: MulTripleVector::new(),
        })
    }

    pub fn verify_multiplications(&mut self) -> MpcResult<()> {
        if self.gf4_triples_to_check.len() > 0 {
            match self.check_type {
                MultCheckType::Recursive { .. } => {
                    let res = if self.inner.has_multi_threading() {
                        wollut16_malsec::mult_verification::verify_multiplication_triples_mt(&mut self.inner, &mut self.broadcast_context, &mut [&mut BsGF4Encoder(&mut self.gf4_triples_to_check), &mut GF4p4TripleEncoder(&mut self.gf4p4_triples_to_check)], false)
                    }else{
                        wollut16_malsec::mult_verification::verify_multiplication_triples(&mut self.inner, &mut self.broadcast_context, &mut [&mut BsGF4Encoder(&mut self.gf4_triples_to_check), &mut GF4p4TripleEncoder(&mut self.gf4p4_triples_to_check)], false)
                    };
                    match res {
                        Ok(true) => Ok(()),
                        Ok(false) => Err(MpcError::MultCheck),
                        Err(err) => Err(err),
                    }
                },
                MultCheckType::RecursiveBeaver | MultCheckType::BucketBeaver => {
                    let n = self.gf4_triples_to_check.len();
                    if self.gf4_beaver_triples.len() < n {
                        panic!("Not enough beaver triples left to sacrifice!");
                    }
                    let from = self.gf4_beaver_triples.len() - n;
                    let (ai, aii, bi, bii, ci, cii) = self.gf4_beaver_triples.as_mut_slices();
                    let res = if self.inner.has_multi_threading() {
                        furukawa::offline::sacrifice_mt(&mut self.inner, n, 1, self.gf4_triples_to_check.ai(), self.gf4_triples_to_check.aii(), self.gf4_triples_to_check.bi(), self.gf4_triples_to_check.bii(), self.gf4_triples_to_check.ci(), self.gf4_triples_to_check.cii(), &mut ai[from..], &mut aii[from..], &mut bi[from..], &mut bii[from..], &mut ci[from..], &mut cii[from..])
                    }else{
                        furukawa::offline::sacrifice(&mut self.inner, n, 1, self.gf4_triples_to_check.ai(), self.gf4_triples_to_check.aii(), self.gf4_triples_to_check.bi(), self.gf4_triples_to_check.bii(), self.gf4_triples_to_check.ci(), self.gf4_triples_to_check.cii(), &mut ai[from..], &mut aii[from..], &mut bi[from..], &mut bii[from..], &mut ci[from..], &mut cii[from..])
                    };
                    self.gf4_beaver_triples.shrink(from);
                    res
                }
            }
        }else{
            Ok(())
        }
    }
}

impl ArithmeticBlackBox<GF8> for GF4CircuitASParty {

    fn pre_processing(&mut self, _n_multiplications: usize) -> MpcResult<()> {
       // nothing to do
        Ok(())
    }

    fn io(&self) -> &IoLayerOwned {
        self.inner.io()
    }

    fn constant(&self, value: GF8) -> RssShare<GF8> {
        self.inner.constant(value)
    }

    fn generate_random(&mut self, n: usize) -> Vec<RssShare<GF8>> {
        self.inner.generate_random(n)
    }

    fn generate_alpha(&mut self, n: usize) -> impl Iterator<Item=GF8> {
        self.inner.generate_alpha(n)
    }

    fn input_round(&mut self, _my_input: &[GF8]) -> MpcResult<(Vec<RssShare<GF8>>, Vec<RssShare<GF8>>, Vec<RssShare<GF8>>)> {
        unimplemented!()
    }

    fn mul(&mut self, _ci: &mut [GF8], _cii: &mut [GF8], _ai: &[GF8], _aii: &[GF8], _bi: &[GF8], _bii: &[GF8]) -> MpcResult<()> {
        unimplemented!()
    }

    fn output_round(&mut self, si: &[GF8], sii: &[GF8]) -> MpcResult<Vec<GF8>> {
        self.inner.open_rss(&mut self.broadcast_context, si, sii)
    }

    fn output_to(&mut self, to_p1: &[RssShare<GF8>], to_p2: &[RssShare<GF8>], to_p3: &[RssShare<GF8>]) -> MpcResult<Vec<GF8>> {
        self.inner.open_rss_to_multiple(&mut self.broadcast_context, to_p1, to_p2, to_p3)
    }

    fn finalize(&mut self) -> MpcResult<()> {
        self.verify_multiplications()?;
        let context = std::mem::replace(&mut self.broadcast_context, BroadcastContext::new());
        self.inner.compare_view(context)
    }
}

impl GF8InvBlackBox for GF4CircuitASParty {
    fn constant(&self, value: GF8) -> RssShare<GF8> {
        self.inner.constant(value)
    }
    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize, variant: AesVariant) -> MpcResult<()> {
        let n_mul_ks = (variant.n_ks_sboxes() * n_keys * 5)/2; //  5 mult. per S-box (but 2 GF4 elements are packed together)
        let n_mul = (16 * variant.n_rounds() * n_blocks * 5)/2; // 16 S-boxes per round, X rounds, 5 mult. per S-box (but 2 GF4 elements are packed together)
        // allocate more memory for triples
        match self.check_type {
            MultCheckType::Recursive { use_gf4p4_check: true, .. } => {
                let n_mul_ks_gf4 = variant.n_ks_sboxes() * n_keys; // 2 mult. per S-box (but 2 GF4 elements are packed together)
                let n_mul_gf4 = (16 * variant.n_rounds() * n_blocks * 2)/2; // 16 S-boxes per round, X rounds, 2 mult. per S-box (but 2 GF4 elements are packed together)
                let n_mul_ks_gf4p4 = variant.n_ks_sboxes() * n_keys; // 1 triple per S-box (but 2 GF4 elements are packed together)
                let n_mul_gf4p4 = 16 * variant.n_rounds() * n_blocks; // 16 S-boxes per round, X rounds, 1 triple per S-box (but 2 GF4 elements are packed together)
                self.gf4_triples_to_check.reserve_for_more_triples(n_mul_gf4 + n_mul_ks_gf4);
                self.gf4p4_triples_to_check.reserve_for_more_triples(n_mul_gf4p4 + n_mul_ks_gf4p4);
            },
            _ => self.gf4_triples_to_check.reserve_for_more_triples(n_mul_ks + n_mul),
        };
        match self.check_type {
            MultCheckType::Recursive { .. } => (), // no additional preprocessing
            MultCheckType::RecursiveBeaver => {
                // compute n_mul_ks + n_mul many beaver triples and check them using recursive check
                self.gf4_beaver_triples.reserve_for_more_triples(n_mul_ks + n_mul);
                offline::prepare_beaver_triples_recursive_check(&mut self.inner, &mut self.gf4_beaver_triples, &mut self.broadcast_context, n_mul_ks + n_mul)?;
            },
            MultCheckType::BucketBeaver => {
                // compute n_mul_ks + n_mul many beaver triples and check them using cut-and-choose
                offline::prepare_beaver_triples_bucket(&mut self.inner, &mut self.gf4_beaver_triples, n_mul_ks + n_mul)?;
            }
        }
        Ok(())
    }
    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        if self.inner.has_multi_threading() && si.len() >= 2 * self.inner.num_worker_threads() {
            match self.check_type {
                MultCheckType::Recursive { use_gf4p4_check: true, .. } => {
                    gf8_inv_via_gf4_mul_gf4p4_check_mt(&mut self.inner, &mut self.gf4_triples_to_check, &mut self.gf4p4_triples_to_check, si, sii)?
                },
                _ => gf4_circuit::gf8_inv_via_gf4_mul_opt_mt(&mut self.inner, &mut self.gf4_triples_to_check, si, sii)?,
            }
        } else {
            match self.check_type {
                MultCheckType::Recursive { use_gf4p4_check: true, .. } => {
                    gf8_inv_via_gf4_mul_gf4p4_check_no_sync(&mut self.inner, &mut self.gf4_triples_to_check, &mut self.gf4p4_triples_to_check, si, sii)?;
                    self.inner.wait_for_completion();
                },
                _ => gf4_circuit::gf8_inv_via_gf4_mul_opt(&mut self.inner, &mut self.gf4_triples_to_check, si, sii)?
            }
        }
        if let MultCheckType::Recursive { check_after_sbox: true, .. } = self.check_type {
            self.verify_multiplications()?;
        }
        Ok(())
    }
    fn main_party_mut(&mut self) -> &mut MainParty {
        &mut self.inner
    }
}

pub fn gf8_inv_via_gf4_mul_gf4p4_check_mt<Rec: MulTripleRecorder<BsGF4>>(party: &mut MainParty, gf4_triple_rec: &mut Rec, gf4p4_triple_rec: &mut GF4p4TripleVector, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
    debug_assert_eq!(si.len(), sii.len());
    let ranges = party.split_range_equally_even(si.len());
    let mul_triple_lengths = ranges.iter().map(|(start, end)| (end-start)).collect_vec();
    let recorders = gf4p4_triple_rec.create_thread_mul_triple_recorders(&mul_triple_lengths);
    let chunk_size = ranges[0].1 - ranges[0].0;
    let mut threads = party.create_thread_parties_with_additional_data(ranges, |start, end| (Some(gf4_triple_rec.create_thread_mul_triple_recorder(start, end)), None));
    threads.iter_mut().zip_eq(recorders).for_each(|(tp, rec)| tp.additional_data.1 = Some(rec));

    
    let child_recorders: Vec<_> = 
    party.run_in_threadpool(|| {
        threads.into_par_iter().zip_eq(si.par_chunks_mut(chunk_size)).zip_eq(sii.par_chunks_mut(chunk_size))
            .map(|((mut thread_party, si), sii)| {
                let mut gf4_triple_rec = thread_party.additional_data.0.take().unwrap();
                let mut gf4p4_triple_rec = thread_party.additional_data.1.take().unwrap();
                let res = gf8_inv_via_gf4_mul_gf4p4_check_no_sync(&mut thread_party, &mut gf4_triple_rec, &mut gf4p4_triple_rec, si, sii);
                res.map(|()| gf4_triple_rec)
        }).collect()
    })?;

    gf4_triple_rec.join_thread_mul_triple_recorders(child_recorders);
    party.wait_for_completion();
    Ok(())
}

pub fn gf8_inv_via_gf4_mul_gf4p4_check_no_sync<P: Party, Rec: MulTripleRecorder<BsGF4>, Rec2: GF4p4TripleRecorder>(
    party: &mut P,
    gf4_triple_rec: &mut Rec,
    gf4p4_triple_rec: &mut Rec2,
    si: &mut [GF8],
    sii: &mut [GF8],
) -> MpcResult<()> {
    debug_assert_eq!(si.len(), sii.len());

    // Step 1: WOL-conversion
    let (ah_i, mut al_i) = wol_bitslice_gf4(si);
    let (ah_ii, mut al_ii) = wol_bitslice_gf4(sii);

    let n = ah_i.len();

    // compute v = (e*ah^2 + (ah*al) + al^2)
    let mut vi = vec![BsGF4::default(); n];
    let mut vii = vec![BsGF4::default(); n];
    chida::online::mul_no_sync(party, &mut vi, &mut vii, &ah_i, &ah_ii, &al_i, &al_ii)?;

    izip!(vi.iter_mut(), &ah_i, &al_i).for_each(|(dst, ah, al)| {
        *dst += ah.square_mul_e() + al.square();
    });
    izip!(vii.iter_mut(), &ah_ii, &al_ii).for_each(|(dst, ah, al)| {
        *dst += ah.square_mul_e() + al.square();
    });

    // compute v^2
    let vp2_si = vi.iter().map(|x| x.square()).collect_vec();
    let vp2_sii = vii.iter().map(|x| x.square()).collect_vec();

    // compute v^-1 via v^2 * v^4 * v^8
    let mut vp4_si = vp2_si.iter().map(|x| x.square()).collect_vec();
    let mut vp4_sii = vp2_sii.iter().map(|x| x.square()).collect_vec();

    let mut vp6_si = vec![BsGF4::default(); n];
    let mut vp6_sii = vec![BsGF4::default(); n];
    chida::online::mul_no_sync(
        party,
        &mut vp6_si,
        &mut vp6_sii,
        &vp2_si,
        &vp2_sii,
        &vp4_si,
        &vp4_sii,
    )?;
    gf4_triple_rec.record_mul_triple(&vp2_si, &vp2_sii, &vp4_si, &vp4_sii, &vp6_si, &vp6_sii);

    vp4_si.iter_mut().for_each(|x| *x = x.square());
    vp4_sii.iter_mut().for_each(|x| *x = x.square());
    let vp8_si = vp4_si;
    let vp8_sii = vp4_sii;

    let mut v_inv_i = vp2_si;
    let mut v_inv_ii = vp2_sii;
    chida::online::mul_no_sync(
        party,
        &mut v_inv_i,
        &mut v_inv_ii,
        &vp6_si,
        &vp6_sii,
        &vp8_si,
        &vp8_sii,
    )?;
    gf4_triple_rec.record_mul_triple(&vp6_si, &vp6_sii, &vp8_si, &vp8_sii, &v_inv_i, &v_inv_ii);

    // compute bh = ah * v_inv and bl = (ah + al) * v_inv
    let mut bh_bl_i = vec![BsGF4::default(); 2 * n];
    let mut bh_bl_ii = vec![BsGF4::default(); 2 * n];

    let v_inv_v_inv_i = append_slice(&v_inv_i, &v_inv_i);
    let v_inv_v_inv_ii = append_slice(&v_inv_ii, &v_inv_ii);
    al_i.iter_mut()
        .zip(ah_i.iter())
        .for_each(|(dst, ah)| *dst += *ah);
    al_ii
        .iter_mut()
        .zip(ah_ii.iter())
        .for_each(|(dst, ah)| *dst += *ah);
    let ah_al_i = append_vec(ah_i, al_i);
    let ah_al_ii = append_vec(ah_ii, al_ii);
    chida::online::mul_no_sync(
        party,
        &mut bh_bl_i,
        &mut bh_bl_ii,
        &ah_al_i,
        &ah_al_ii,
        &v_inv_v_inv_i,
        &v_inv_v_inv_ii,
    )?;
    // Step 7 Preparation for multiplication triples for verification
    izip!(vi, vii, &ah_al_i[..n], &ah_al_ii[..n], &ah_al_i[n..], &ah_al_ii[n..], v_inv_i, v_inv_ii, &bh_bl_i[..n], &bh_bl_ii[..n], &bh_bl_i[n..], &bh_bl_ii[n..])
        .for_each(|(vi, vii, ahi, ahii, ali, alii, v_invi, v_invii, bh_i, bh_ii, bl_i, bl_ii)| {
            // al contains (al + ah), so subtract ah again
            let ali = *ali + *ahi;
            let alii = *alii + *ahii;
            // Compute [a_h * a_l] := [v] + (e * a_h^2) + a_l^2
            let ah_times_al_i = vi + ahi.square_mul_e() + ali.square();
            let ah_times_al_ii = vii + ahii.square_mul_e() + alii.square();

            // Store ([ah] + alpha*[al]) * ([al] + alpha*[v_inv]) = [ah * al] + alpha*[bh + al^2] + alpha^2 * [bl + bh]
            gf4p4_triple_rec.record_mul_triple(*ahi, *ahii, ali, alii, ali, alii, v_invi, v_invii, 
                ah_times_al_i, ah_times_al_ii, *bh_i + ali.square(), *bh_ii + alii.square(), *bl_i + *bh_i, *bl_ii + *bh_ii);
    });

    un_wol_bitslice_gf4(&bh_bl_i[..n], &bh_bl_i[n..], si);
    un_wol_bitslice_gf4(&bh_bl_ii[..n], &bh_bl_ii[n..], sii);

    Ok(())
}

/// Concatenates two vectors
#[inline]
fn append_vec<F: HasZero + Copy>(a: Vec<F>, b: Vec<F>) -> Vec<F> {
    let mut res = vec![F::ZERO; a.len() + b.len()];
    res[..a.len()].copy_from_slice(&a);
    res[a.len()..].copy_from_slice(&b);
    res
}

#[inline]
fn append_slice<F: HasZero + Copy>(a: &[F], b: &[F]) -> Vec<F> {
    let mut res = vec![F::ZERO; a.len() + b.len()];
    res[..a.len()].copy_from_slice(a);
    res[a.len()..].copy_from_slice(b);
    res
}

#[cfg(test)]
mod test {
    use crate::aes::test::{test_aes128_keyschedule_gf8, test_aes128_no_keyschedule_gf8, test_aes256_keyschedule_gf8, test_aes256_no_keyschedule_gf8, test_inv_aes128_no_keyschedule_gf8, test_sub_bytes};
    use crate::rep3_core::{network::ConnectedParty, test::{localhost_connect, TestSetup}};

    use super::{GF4CircuitASParty, MultCheckType};


    fn localhost_setup_gf4_circuit_as<T1: Send, F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1, T2: Send, F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2, T3: Send, F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3>(f1: F1, f2: F2, f3: F3, n_worker_threads: Option<usize>, check_type: MultCheckType) -> ((T1,GF4CircuitASParty), (T2,GF4CircuitASParty), (T3,GF4CircuitASParty)) {
        fn adapter<T, Fx: FnOnce(&mut GF4CircuitASParty)->T>(conn: ConnectedParty, f: Fx, n_worker_threads: Option<usize>, check_type: MultCheckType) -> (T,GF4CircuitASParty) {
            let mut party = GF4CircuitASParty::setup(conn, n_worker_threads, None, check_type).unwrap();
            let t = f(&mut party);
            // party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(move |conn_party| adapter(conn_party, f1, n_worker_threads, check_type), move |conn_party| adapter(conn_party, f2, n_worker_threads, check_type), move |conn_party| adapter(conn_party, f3, n_worker_threads, check_type))
    }

    pub struct GF4CircuitAsSetup;
    impl TestSetup<GF4CircuitASParty> for GF4CircuitAsSetup {
        fn localhost_setup<
                    T1: Send,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3,
                >(f1: F1, f2: F2, f3: F3) -> (
                    (T1, GF4CircuitASParty),
                    (T2, GF4CircuitASParty),
                    (T3, GF4CircuitASParty),
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, None, MultCheckType::Recursive { check_after_sbox: false, use_gf4p4_check: false })
        }

        fn localhost_setup_multithreads<
                    T1: Send,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3,
                >(n_worker_threads: usize, f1: F1, f2: F2, f3: F3) -> (
                    (T1, GF4CircuitASParty),
                    (T2, GF4CircuitASParty),
                    (T3, GF4CircuitASParty),
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, Some(n_worker_threads), MultCheckType::Recursive { check_after_sbox: false, use_gf4p4_check: false })
        }
    }

    #[test]
    fn sub_bytes() {
        test_sub_bytes::<GF4CircuitAsSetup,_>(None)
    }

    #[test]
    fn sub_bytes_mt() {
        const N_THREADS: usize = 3;
        test_sub_bytes::<GF4CircuitAsSetup,_>(Some(N_THREADS))
    }

    #[test]
    fn aes128_keyschedule() {
        test_aes128_keyschedule_gf8::<GF4CircuitAsSetup, _>(None)
    }

    #[test]
    fn aes128_keyschedule_mt() {
        const N_THREADS: usize = 3;
        test_aes128_keyschedule_gf8::<GF4CircuitAsSetup, _>(Some(N_THREADS))
    }

    #[test]
    fn aes_128_no_keyschedule() {
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsSetup, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsSetup, _>(100, Some(N_THREADS))
    }

    #[test]
    fn inv_aes128_no_keyschedule() {
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsSetup, _>(1, None)
    }

    #[test]
    fn inv_aes128_no_keyschedule_mt() {
        const N_THREADS: usize = 3;
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsSetup, _>(100, Some(N_THREADS))
    }

    pub struct GF4CircuitAsGF4p4CheckSetup;
    impl TestSetup<GF4CircuitASParty> for GF4CircuitAsGF4p4CheckSetup {
        fn localhost_setup<
                    T1: Send,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3,
                >(f1: F1, f2: F2, f3: F3) -> (
                    (T1, GF4CircuitASParty),
                    (T2, GF4CircuitASParty),
                    (T3, GF4CircuitASParty),
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, None, MultCheckType::Recursive { check_after_sbox: false, use_gf4p4_check: true })
        }

        fn localhost_setup_multithreads<
                    T1: Send,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3,
                >(n_worker_threads: usize, f1: F1, f2: F2, f3: F3) -> (
                    (T1, GF4CircuitASParty),
                    (T2, GF4CircuitASParty),
                    (T3, GF4CircuitASParty),
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, Some(n_worker_threads), MultCheckType::Recursive { check_after_sbox: false, use_gf4p4_check: true })
        }
    }

    #[test]
    fn sub_bytes_gf4p4() {
        test_sub_bytes::<GF4CircuitAsGF4p4CheckSetup,_>(None)
    }

    #[test]
    fn sub_bytes_gf4p4_mt() {
        const N_THREADS: usize = 3;
        test_sub_bytes::<GF4CircuitAsGF4p4CheckSetup,_>(Some(N_THREADS))
    }

    #[test]
    fn aes128_keyschedule_gf4p4() {
        test_aes128_keyschedule_gf8::<GF4CircuitAsGF4p4CheckSetup, _>(None)
    }

    #[test]
    fn aes128_keyschedule_gf4p4_mt() {
        const N_THREADS: usize = 3;
        test_aes128_keyschedule_gf8::<GF4CircuitAsGF4p4CheckSetup, _>(Some(N_THREADS))
    }

    #[test]
    fn aes_128_no_keyschedule_gf4p4() {
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsGF4p4CheckSetup, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_gf4p4_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsGF4p4CheckSetup, _>(100, Some(N_THREADS))
    }

    #[test]
    fn inv_aes128_no_keyschedule_gf4p4() {
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsGF4p4CheckSetup, _>(1, None)
    }

    #[test]
    fn inv_aes128_no_keyschedule_gf4p4_mt() {
        const N_THREADS: usize = 3;
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsGF4p4CheckSetup, _>(100, Some(N_THREADS))
    }

    pub struct GF4CircuitAsBucketBeaverSetup;
    impl TestSetup<GF4CircuitASParty> for GF4CircuitAsBucketBeaverSetup {
        fn localhost_setup<
                    T1: Send,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3,
                >(f1: F1, f2: F2, f3: F3) -> (
                    (T1, GF4CircuitASParty),
                    (T2, GF4CircuitASParty),
                    (T3, GF4CircuitASParty),
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, None, MultCheckType::BucketBeaver)
        }

        fn localhost_setup_multithreads<
                    T1: Send,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3,
                >(n_worker_threads: usize, f1: F1, f2: F2, f3: F3) -> (
                    (T1, GF4CircuitASParty),
                    (T2, GF4CircuitASParty),
                    (T3, GF4CircuitASParty),
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, Some(n_worker_threads), MultCheckType::BucketBeaver)
        }
    }
    
    #[test]
    fn sub_bytes_bucket_beaver_check() {
        test_sub_bytes::<GF4CircuitAsBucketBeaverSetup,_>(None)
    }

    #[test]
    fn sub_bytes_bucket_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_sub_bytes::<GF4CircuitAsBucketBeaverSetup,_>(Some(N_THREADS))
    }

    #[test]
    fn aes128_keyschedule_bucket_beaver_check() {
        test_aes128_keyschedule_gf8::<GF4CircuitAsBucketBeaverSetup, _>(None)
    }

    #[test]
    fn aes128_keyschedule_bucket_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_aes128_keyschedule_gf8::<GF4CircuitAsBucketBeaverSetup, _>(Some(N_THREADS))
    }

    #[test]
    fn aes_128_no_keyschedule_bucket_beaver_check() {
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsBucketBeaverSetup, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_bucket_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsBucketBeaverSetup, _>(100, Some(N_THREADS))
    }

    #[test]
    fn inv_aes128_no_keyschedule_bucket_beaver_check() {
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsBucketBeaverSetup, _>(1, None)
    }

    #[test]
    fn inv_aes128_no_keyschedule_bucket_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsBucketBeaverSetup, _>(100, Some(N_THREADS))
    }

    pub struct GF4CircuitAsRecBeaverSetup;
    impl TestSetup<GF4CircuitASParty> for GF4CircuitAsRecBeaverSetup {
        fn localhost_setup<
                    T1: Send,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3,
                >(f1: F1, f2: F2, f3: F3) -> (
                    (T1, GF4CircuitASParty),
                    (T2, GF4CircuitASParty),
                    (T3, GF4CircuitASParty),
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, None, MultCheckType::RecursiveBeaver)
        }

        fn localhost_setup_multithreads<
                    T1: Send,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3,
                >(n_worker_threads: usize, f1: F1, f2: F2, f3: F3) -> (
                    (T1, GF4CircuitASParty),
                    (T2, GF4CircuitASParty),
                    (T3, GF4CircuitASParty),
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, Some(n_worker_threads), MultCheckType::RecursiveBeaver)
        }
    }

    #[test]
    fn sub_bytes_rec_beaver_check() {
        test_sub_bytes::<GF4CircuitAsRecBeaverSetup,_>(None)
    }

    #[test]
    fn sub_bytes_rec_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_sub_bytes::<GF4CircuitAsRecBeaverSetup,_>(Some(N_THREADS))
    }

    #[test]
    fn aes128_keyschedule_rec_beaver_check() {
        test_aes128_keyschedule_gf8::<GF4CircuitAsRecBeaverSetup, _>(None)
    }

    #[test]
    fn aes128_keyschedule_rec_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_aes128_keyschedule_gf8::<GF4CircuitAsRecBeaverSetup, _>(Some(N_THREADS))
    }

    #[test]
    fn aes_128_no_keyschedule_rec_beaver_check() {
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsRecBeaverSetup, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_rec_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsRecBeaverSetup, _>(100, Some(N_THREADS))
    }

    #[test]
    fn inv_aes128_no_keyschedule_rec_beaver_check() {
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsRecBeaverSetup, _>(1, None)
    }

    #[test]
    fn inv_aes128_no_keyschedule_rec_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsRecBeaverSetup, _>(100, Some(N_THREADS))
    }

    #[test]
    fn aes256_keyschedule_gf4p4_mt() {
        const N_THREADS: usize = 3;
        test_aes256_keyschedule_gf8::<GF4CircuitAsGF4p4CheckSetup, _>(Some(N_THREADS))
    }

    #[test]
    fn aes_256_no_keyschedule_gf4p4() {
        test_aes256_no_keyschedule_gf8::<GF4CircuitAsGF4p4CheckSetup, _>(1, None)
    }

    #[test]
    fn aes_256_no_keyschedule_gf4p4_mt() {
        const N_THREADS: usize = 3;
        test_aes256_no_keyschedule_gf8::<GF4CircuitAsGF4p4CheckSetup, _>(100, Some(N_THREADS))
    }
}
