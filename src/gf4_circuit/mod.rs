//! This module implements the *semi-honest* oblivious AES protocol "GF(2^4) Circuit".
//!
//! The core is a sub-protocol to compute multiplicative inverses in `GF(2^8)`.
//! This works as follows:
//! 1) Use the WOL[^note] transform to convert the element `GF(2^8)` to `GF(2^4)^2`.
//! 2) Compute the inverse of the `GF(2^4)^2` element using a single inversion in `GF(2^4)`.
//!    The inverse of a `v` `GF(2^4)` is computed using `v^2, v^4, v^8`.
//! 3) Use the reverse WOL transform to convert the result to `GF(2^8)`.
//!
//! This protocol does not require any pre-processing.
//!
//! This module notably contains [GF4CircuitSemihonestParty]: the party wrapper for the protocol. [GF4CircuitSemihonestParty] also implements [ArithmeticBlackBox]
//!
//! [^note]: Wolkerstorfer et al. "An ASIC Implementation of the AES S-Boxes" in CT-RSA 2002, <https://doi.org/10.1007/3-540-45760-7_6>.


use itertools::{izip, Itertools};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use crate::{aes::AesVariant, rep3_core::{network::{task::IoLayerOwned, ConnectedParty}, party::{error::MpcResult, MainParty, Party}, share::{RssShare, RssShareVec}}, wollut16_malsec::online::{un_wol_bitslice_gf4, wol_bitslice_gf4}};

use crate::{
    aes::GF8InvBlackBox, chida::{self, ChidaParty}, share::{
        gf4::{BsGF4, GF4},
        gf8::GF8,
        wol::{wol_inv_map, wol_map},
        Field,
    }, util::{mul_triple_vec::{MulTripleRecorder, NoMulTripleRecording}, ArithmeticBlackBox}
};

/// The party wrapper for the GF4 circuit protocol.
pub struct GF4CircuitSemihonestParty(ChidaParty);

impl GF4CircuitSemihonestParty {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>, prot_str: Option<String>) -> MpcResult<Self> {
        ChidaParty::setup(connected, n_worker_threads, prot_str).map(Self)
    }

    fn io(&self) -> &IoLayerOwned {
        <ChidaParty as ArithmeticBlackBox<GF4>>::io(&self.0)
    }
}

impl<F: Field> ArithmeticBlackBox<F> for GF4CircuitSemihonestParty {

    fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()> {
        <ChidaParty as ArithmeticBlackBox<F>>::pre_processing(&mut self.0, n_multiplications)
    }

    fn io(&self) -> &IoLayerOwned {
        <ChidaParty as ArithmeticBlackBox<F>>::io(&self.0)
    }

    fn constant(&self, value: F) -> RssShare<F> {
        self.0.constant(value)
    }

    fn generate_random(&mut self, n: usize) -> RssShareVec<F> {
        self.0.generate_random(n)
    }

    fn generate_alpha(&mut self, n: usize) -> impl Iterator<Item=F> {
        self.0.generate_alpha(n)
    }

    // all parties input the same number of inputs
    fn input_round(
        &mut self,
        my_input: &[F],
    ) -> MpcResult<(RssShareVec<F>, RssShareVec<F>, RssShareVec<F>)> {
        self.0.input_round(my_input)
    }

    fn mul(
        &mut self,
        ci: &mut [F],
        cii: &mut [F],
        ai: &[F],
        aii: &[F],
        bi: &[F],
        bii: &[F],
    ) -> MpcResult<()> {
        self.0.mul(ci, cii, ai, aii, bi, bii)
    }

    fn output_round(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>> {
        self.0.output_round(si, sii)
    }

    fn output_to(&mut self, to_p1: &[RssShare<F>], to_p2: &[RssShare<F>], to_p3: &[RssShare<F>]) -> MpcResult<Vec<F>> {
        self.0.output_to(to_p1, to_p2, to_p3)
    }

    fn finalize(&mut self) -> MpcResult<()> {
        <ChidaParty as ArithmeticBlackBox<F>>::finalize(&mut self.0)
    }
}

impl GF8InvBlackBox for GF4CircuitSemihonestParty {
    fn constant(&self, value: GF8) -> RssShare<GF8> {
        self.0.constant(value)
    }
    fn do_preprocessing(&mut self, _n_keys: usize, _n_blocks: usize, _variant: AesVariant) -> MpcResult<()> {
        // nothing to do
        Ok(())
    }
    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        if self.0.has_multi_threading() && si.len() >= 2 * self.0.num_worker_threads() {
            gf8_inv_via_gf4_mul_opt_mt(self.0.as_party_mut(), &mut NoMulTripleRecording, si, sii)
        } else {
            gf8_inv_via_gf4_mul_opt(self.0.as_party_mut(), &mut NoMulTripleRecording, si, sii)
        }
    }
    fn main_party_mut(&mut self) -> &mut MainParty {
        self.0.as_party_mut()
    }
}

fn gf8_inv_via_gf4_mul<P: ArithmeticBlackBox<GF4>>(
    party: &mut P,
    si: &mut [GF8],
    sii: &mut [GF8],
) -> MpcResult<()> {
    debug_assert_eq!(si.len(), sii.len());
    let n = si.len();
    // Step 1: WOL-conversion
    let (ah_i, mut al_i): (Vec<GF4>, Vec<GF4>) = si.iter().map(wol_map).unzip();
    let (ah_ii, mut al_ii): (Vec<GF4>, Vec<GF4>) = sii.iter().map(wol_map).unzip();

    // compute v^2 = (e*ah^2 + (ah*al) + al^2)^2
    let mut vi = vec![GF4::default(); n];
    let mut vii = vec![GF4::default(); n];
    party.mul(&mut vi, &mut vii, &ah_i, &ah_ii, &al_i, &al_ii)?;
    izip!(vi.iter_mut(), &ah_i, &al_i).for_each(|(dst, ah, al)| {
        *dst += ah.square().mul_e() + al.square();
        *dst = dst.square();
    });
    izip!(vii.iter_mut(), &ah_ii, &al_ii).for_each(|(dst, ah, al)| {
        *dst += ah.square().mul_e() + al.square();
        *dst = dst.square();
    });

    // compute v^-1 via v^2 * v^4 * v^8
    let mut vp4_si = vi.iter().map(GF4::square).collect_vec();
    let mut vp4_sii = vii.iter().map(GF4::square).collect_vec();

    let mut vp6_si = vec![GF4::default(); n];
    let mut vp6_sii = vec![GF4::default(); n];
    party.mul(&mut vp6_si, &mut vp6_sii, &vi, &vii, &vp4_si, &vp4_sii)?;

    vp4_si.iter_mut().for_each(|x| *x = x.square());
    vp4_sii.iter_mut().for_each(|x| *x = x.square());
    let vp8_si = vp4_si;
    let vp8_sii = vp4_sii;

    let mut v_inv_i = vi;
    let mut v_inv_ii = vii;
    party.mul(
        &mut v_inv_i,
        &mut v_inv_ii,
        &vp6_si,
        &vp6_sii,
        &vp8_si,
        &vp8_sii,
    )?;

    // compute bh = ah * v_inv and bl = (ah + al) * v_inv
    let mut bh_bl_i = vec![GF4::default(); 2 * n];
    let mut bh_bl_ii = vec![GF4::default(); 2 * n];

    let v_inv_v_inv_i = append(&v_inv_i, &v_inv_i);
    let v_inv_v_inv_ii = append(&v_inv_ii, &v_inv_ii);
    al_i.iter_mut()
        .zip(ah_i.iter())
        .for_each(|(dst, ah)| *dst += *ah);
    al_ii
        .iter_mut()
        .zip(ah_ii.iter())
        .for_each(|(dst, ah)| *dst += *ah);
    let ah_al_i = append(&ah_i, &al_i);
    let ah_al_ii = append(&ah_ii, &al_ii);
    party.mul(
        &mut bh_bl_i,
        &mut bh_bl_ii,
        &ah_al_i,
        &ah_al_ii,
        &v_inv_v_inv_i,
        &v_inv_v_inv_ii,
    )?;

    izip!(si.iter_mut(), &bh_bl_i[..n], &bh_bl_i[n..])
        .for_each(|(si, bh, bl)| *si = wol_inv_map(bh, bl));
    izip!(sii.iter_mut(), &bh_bl_ii[..n], &bh_bl_ii[n..])
        .for_each(|(sii, bh, bl)| *sii = wol_inv_map(bh, bl));

    Ok(())
}

pub fn gf8_inv_via_gf4_mul_opt<Rec: MulTripleRecorder<BsGF4>>(
    party: &mut MainParty,
    triple_rec: &mut Rec,
    si: &mut [GF8],
    sii: &mut [GF8],
) -> MpcResult<()> {
    gf8_inv_via_gf4_mul_opt_no_sync(party, triple_rec, si, sii)?;
    party.wait_for_completion();
    Ok(())
}

pub fn gf8_inv_via_gf4_mul_opt_mt<Rec: MulTripleRecorder<BsGF4>>(
    party: &mut MainParty,
    triple_rec: &mut Rec,
    si: &mut [GF8],
    sii: &mut [GF8],
) -> MpcResult<()> {
    debug_assert_eq!(si.len(), sii.len());
    let ranges = party.split_range_equally_even(si.len());
    let chunk_size = ranges[0].1 - ranges[0].0;
    let thread_parties = party.create_thread_parties_with_additional_data(ranges, |start, end| Some(triple_rec.create_thread_mul_triple_recorder(start, end)));
    let observed_triples = party.run_in_threadpool(|| {
        thread_parties
            .into_par_iter()
            .zip_eq(si.par_chunks_mut(chunk_size))
            .zip_eq(sii.par_chunks_mut(chunk_size))
            .map(|((mut thread_party, si), sii)| {
                let mut rec = thread_party.additional_data.take().unwrap();
                gf8_inv_via_gf4_mul_opt_no_sync(&mut thread_party, &mut rec, si, sii).map(|()| rec)
            })
            .collect::<MpcResult<Vec<_>>>()
    })?;
    triple_rec.join_thread_mul_triple_recorders(observed_triples);
    party.wait_for_completion();
    Ok(())
}

fn gf8_inv_via_gf4_mul_opt_no_sync<P: Party, Rec: MulTripleRecorder<BsGF4>>(
    party: &mut P,
    triple_rec: &mut Rec,
    si: &mut [GF8],
    sii: &mut [GF8],
) -> MpcResult<()> {
    debug_assert_eq!(si.len(), sii.len());

    // Step 1: WOL-conversion
    let (ah_i, mut al_i) = wol_bitslice_gf4(si);
    let (ah_ii, mut al_ii) = wol_bitslice_gf4(sii);

    let n = ah_i.len();

    // compute v^2 = (e*ah^2 + (ah*al) + al^2)^2
    let mut vi = vec![BsGF4::default(); n];
    let mut vii = vec![BsGF4::default(); n];
    chida::online::mul_no_sync(party, &mut vi, &mut vii, &ah_i, &ah_ii, &al_i, &al_ii)?;
    triple_rec.record_mul_triple(&ah_i, &ah_ii, &al_i, &al_ii, &vi, &vii);

    izip!(vi.iter_mut(), &ah_i, &al_i).for_each(|(dst, ah, al)| {
        *dst += ah.square_mul_e() + al.square();
        *dst = dst.square();
    });
    izip!(vii.iter_mut(), &ah_ii, &al_ii).for_each(|(dst, ah, al)| {
        *dst += ah.square_mul_e() + al.square();
        *dst = dst.square();
    });

    // compute v^-1 via v^2 * v^4 * v^8
    let mut vp4_si = vi.iter().map(|x| x.square()).collect_vec();
    let mut vp4_sii = vii.iter().map(|x| x.square()).collect_vec();

    let mut vp6_si = vec![BsGF4::default(); n];
    let mut vp6_sii = vec![BsGF4::default(); n];
    chida::online::mul_no_sync(
        party,
        &mut vp6_si,
        &mut vp6_sii,
        &vi,
        &vii,
        &vp4_si,
        &vp4_sii,
    )?;
    triple_rec.record_mul_triple(&vi, &vii, &vp4_si, &vp4_sii, &vp6_si, &vp6_sii);

    vp4_si.iter_mut().for_each(|x| *x = x.square());
    vp4_sii.iter_mut().for_each(|x| *x = x.square());
    let vp8_si = vp4_si;
    let vp8_sii = vp4_sii;

    let mut v_inv_i = vi;
    let mut v_inv_ii = vii;
    chida::online::mul_no_sync(
        party,
        &mut v_inv_i,
        &mut v_inv_ii,
        &vp6_si,
        &vp6_sii,
        &vp8_si,
        &vp8_sii,
    )?;
    triple_rec.record_mul_triple(&vp6_si, &vp6_sii, &vp8_si, &vp8_sii, &v_inv_i, &v_inv_ii);

    // compute bh = ah * v_inv and bl = (ah + al) * v_inv
    let mut bh_bl_i = vec![BsGF4::default(); 2 * n];
    let mut bh_bl_ii = vec![BsGF4::default(); 2 * n];

    let v_inv_v_inv_i = append(&v_inv_i, &v_inv_i);
    let v_inv_v_inv_ii = append(&v_inv_ii, &v_inv_ii);
    al_i.iter_mut()
        .zip(ah_i.iter())
        .for_each(|(dst, ah)| *dst += *ah);
    al_ii
        .iter_mut()
        .zip(ah_ii.iter())
        .for_each(|(dst, ah)| *dst += *ah);
    let ah_al_i = append(&ah_i, &al_i);
    let ah_al_ii = append(&ah_ii, &al_ii);
    chida::online::mul_no_sync(
        party,
        &mut bh_bl_i,
        &mut bh_bl_ii,
        &ah_al_i,
        &ah_al_ii,
        &v_inv_v_inv_i,
        &v_inv_v_inv_ii,
    )?;
    triple_rec.record_mul_triple(&ah_al_i, &ah_al_ii, &v_inv_v_inv_i, &v_inv_v_inv_ii, &bh_bl_i, &bh_bl_ii);

    un_wol_bitslice_gf4(&bh_bl_i[..n], &bh_bl_i[n..], si);
    un_wol_bitslice_gf4(&bh_bl_ii[..n], &bh_bl_ii[n..], sii);

    Ok(())
}

/// Concatenates two vectors
#[inline]
fn append<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    let mut res = vec![F::ZERO; a.len() + b.len()];
    res[..a.len()].copy_from_slice(a);
    res[a.len()..].copy_from_slice(b);
    res
}

#[cfg(test)]
mod test {
    use crate::{aes::test::{test_aes256_keyschedule_gf8, test_aes256_no_keyschedule_gf8}, rep3_core::{network::ConnectedParty, test::{localhost_connect, TestSetup}}};

    use crate::aes::test::{
            test_aes128_keyschedule_gf8, test_aes128_no_keyschedule_gf8,
            test_inv_aes128_no_keyschedule_gf8, test_sub_bytes,
        };

    use super::GF4CircuitSemihonestParty;

    pub fn localhost_setup_gf4_circuit_semi_honest<
        T1: Send,
        F1: Send + FnOnce(&mut GF4CircuitSemihonestParty) -> T1,
        T2: Send,
        F2: Send + FnOnce(&mut GF4CircuitSemihonestParty) -> T2,
        T3: Send,
        F3: Send + FnOnce(&mut GF4CircuitSemihonestParty) -> T3,
    >(
        f1: F1,
        f2: F2,
        f3: F3,
        n_worker_threads: Option<usize>,
    ) -> (
        (T1, GF4CircuitSemihonestParty),
        (T2, GF4CircuitSemihonestParty),
        (T3, GF4CircuitSemihonestParty),
    ) {
        fn adapter<T, Fx: FnOnce(&mut GF4CircuitSemihonestParty) -> T>(
            conn: ConnectedParty,
            f: Fx,
            n_worker_threads: Option<usize>,
        ) -> (T, GF4CircuitSemihonestParty) {
            let mut party = GF4CircuitSemihonestParty::setup(conn, n_worker_threads, None).unwrap();
            let t = f(&mut party);
            party.0.teardown().unwrap();
            (t, party)
        }
        localhost_connect(
            move |conn_party| adapter(conn_party, f1, n_worker_threads),
            move |conn_party| adapter(conn_party, f2, n_worker_threads),
            move |conn_party| adapter(conn_party, f3, n_worker_threads),
        )
    }

    pub struct GF4SemihonestSetup;
    impl TestSetup<GF4CircuitSemihonestParty> for GF4SemihonestSetup {
        fn localhost_setup<
            T1: Send,
            F1: Send + FnOnce(&mut GF4CircuitSemihonestParty) -> T1,
            T2: Send,
            F2: Send + FnOnce(&mut GF4CircuitSemihonestParty) -> T2,
            T3: Send,
            F3: Send + FnOnce(&mut GF4CircuitSemihonestParty) -> T3,
        >(
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            (T1, GF4CircuitSemihonestParty),
            (T2, GF4CircuitSemihonestParty),
            (T3, GF4CircuitSemihonestParty),
        ) {
            localhost_setup_gf4_circuit_semi_honest(f1, f2, f3, None)
        }
        fn localhost_setup_multithreads<
            T1: Send,
            F1: Send + FnOnce(&mut GF4CircuitSemihonestParty) -> T1,
            T2: Send,
            F2: Send + FnOnce(&mut GF4CircuitSemihonestParty) -> T2,
            T3: Send,
            F3: Send + FnOnce(&mut GF4CircuitSemihonestParty) -> T3,
        >(
            n_threads: usize,
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            (T1, GF4CircuitSemihonestParty),
            (T2, GF4CircuitSemihonestParty),
            (T3, GF4CircuitSemihonestParty),
        ) {
            localhost_setup_gf4_circuit_semi_honest(f1, f2, f3, Some(n_threads))
        }
    }

    #[test]
    fn sub_bytes() {
        test_sub_bytes::<GF4SemihonestSetup, _>(None)
    }

    #[test]
    fn sub_bytes_mt() {
        const N_THREADS: usize = 3;
        test_sub_bytes::<GF4SemihonestSetup, _>(Some(N_THREADS))
    }

    #[test]
    fn aes128_no_keyschedule_gf8() {
        test_aes128_no_keyschedule_gf8::<GF4SemihonestSetup, _>(1, None);
    }

    #[test]
    fn aes128_no_keyschedule_gf8_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<GF4SemihonestSetup, _>(100, Some(N_THREADS));
    }

    #[test]
    fn aes128_keyschedule_gf8() {
        test_aes128_keyschedule_gf8::<GF4SemihonestSetup, _>(None);
    }

    #[test]
    fn inv_aes128_no_keyschedule_gf8() {
        test_inv_aes128_no_keyschedule_gf8::<GF4SemihonestSetup, _>(1, None);
    }

    #[test]
    fn inv_aes128_no_keyschedule_gf8_mt() {
        const N_THREADS: usize = 3;
        test_inv_aes128_no_keyschedule_gf8::<GF4SemihonestSetup, _>(1, Some(N_THREADS));
    }

    #[test]
    fn aes256_keyschedule_gf8() {
        test_aes256_keyschedule_gf8::<GF4SemihonestSetup, _>(None);
    }

    #[test]
    fn aes256_no_keyschedule_gf8() {
        test_aes256_no_keyschedule_gf8::<GF4SemihonestSetup, _>(1, None);
    }

    #[test]
    fn aes256_no_keyschedule_gf8_mt() {
        const N_THREADS: usize = 3;
        test_aes256_no_keyschedule_gf8::<GF4SemihonestSetup, _>(100, Some(N_THREADS));
    }
}
