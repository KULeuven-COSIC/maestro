
use std::mem;

use itertools::{izip, Itertools};
use rayon::{iter::{IndexedParallelIterator, ParallelIterator}, slice::{ParallelSlice, ParallelSliceMut}};

use crate::{aes::ss::{GF8InvBlackBoxSS, GF8InvBlackBoxSSMal}, share::{bs_bool16::BsBool16, gf2p64::{GF2p64, GF2p64InnerProd, GF2p64Subfield}, gf8::GF8}, util::mul_triple_vec::{BsBool16Encoder, MulTripleEncoder, MulTripleRecorder, MulTripleVector, NoMulTripleRecording, Ohv16TripleEncoder, Ohv16TripleVector}, wollut16_malsec::mult_verification};
use crate::rep3_core::{network::{task::Direction, ConnectedParty}, party::{broadcast::{Broadcast, BroadcastContext}, error::{MpcError, MpcResult}, MainParty, Party}, share::{HasZero, RssShare}};

use super::{lut256_tables, offline, RndOhv256OutputSS};

pub struct Lut256SSParty {
    inner: MainParty,
    prep_ohv: Vec<RndOhv256OutputSS>,
}

impl Lut256SSParty {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>, prot_str: Option<String>) -> MpcResult<Self> {
        MainParty::setup(connected, n_worker_threads, prot_str).map(|inner| Self {
            inner,
            prep_ohv: Vec::new(),
        })
    }
}

impl GF8InvBlackBoxSS for Lut256SSParty {

    fn constant(&self, value: GF8) -> GF8 {
        if self.inner.i == 0 {
            value
        }else{
            GF8::ZERO
        }
    }

    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()> {
        let n_rnd_ohv_ks = 4 * 10 * n_keys; // 4 S-boxes per round, 10 rounds, 1 LUT per S-box
        let n_rnd_ohv = 16 * 10 * n_blocks; // 16 S-boxes per round, 10 rounds, 1 LUT per S-box
        let n_prep = n_rnd_ohv + n_rnd_ohv_ks;

        let mut prep =
            if self.inner.has_multi_threading() && 2 * n_prep > self.inner.num_worker_threads() {
                offline::generate_rndohv256_ss_mt(&mut self.inner, &mut NoMulTripleRecording,  n_prep)?
            } else {
                offline::generate_rndohv256_ss(&mut self.inner, &mut NoMulTripleRecording, n_prep)?
            };
        if self.prep_ohv.is_empty() {
            self.prep_ohv = prep;
        } else {
            self.prep_ohv.append(&mut prep);
        }
        Ok(())
    }

    fn gf8_inv(&mut self, s: &mut [GF8]) -> MpcResult<()> {
        let n = s.len();
        if self.prep_ohv.len() < n {
            panic!("Not enough pre-processed random one-hot vectors available. Use LUT256SSParty::do_preprocessing to generate them.");
        }

        let rnd_ohv = &self.prep_ohv[self.prep_ohv.len() - n..];
        let rcv_cii = self.inner.io().receive_field(Direction::Next, s.len());
        let rcv_ciii = self.inner.io().receive_field(Direction::Previous, s.len());

        izip!(s.iter_mut(), self.inner.generate_alpha::<GF8>(n), rnd_ohv.iter())
            .for_each(|(dst, alpha, ohv)| {
                *dst += alpha + ohv.random_si
            });
        self.inner.io().send_field::<GF8>(Direction::Next, s.iter(), n);
        self.inner.io().send_field::<GF8>(Direction::Previous, s.iter(), n);

        let cii = rcv_cii.rcv()?;
        s.iter_mut().zip(cii).for_each(|(dst, cii)| *dst += cii);
        let ciii = rcv_ciii.rcv()?;
        s.iter_mut().zip(ciii).for_each(|(dst, ciii)| *dst += ciii);

        if self.inner.has_multi_threading() && 2 * n > self.inner.num_worker_threads() {
            let ranges = self.inner.split_range_equally(n);
            let chunk_size = ranges[0].1 - ranges[0].0;

            self.inner.run_in_threadpool(|| {
                s.par_chunks_mut(chunk_size).zip_eq(rnd_ohv.par_chunks(chunk_size)).for_each(|(s_chunk, ohv_chunk)| {
                    s_chunk.iter_mut().zip(ohv_chunk).for_each(|(dst, ohv)| {
                        *dst = ohv.ohv.lut(dst.0 as usize, &lut256_tables::GF8_INV_BITSLICED_LUT);
                    });
                });
                Ok(())
            })?;
        }else{
            s.iter_mut().zip(rnd_ohv).for_each(|(dst, ohv)| {
                *dst = ohv.ohv.lut(dst.0 as usize, &lut256_tables::GF8_INV_BITSLICED_LUT);
            });
        }
        
        self.prep_ohv.truncate(self.prep_ohv.len() - n);
        self.inner.wait_for_completion();
        Ok(())
    }

    fn finalize(&mut self) -> MpcResult<()> {
        // for semi-honest security, nothing to do
        Ok(())
    }

    fn output(&mut self, data: &[GF8]) -> MpcResult<Vec<GF8>> {
        let rcv_data_ii = self.inner.io().receive_field(Direction::Next, data.len());
        let rcv_data_iii = self.inner.io().receive_field(Direction::Previous, data.len());
        self.inner.io().send_field::<GF8>(Direction::Next, data.iter(), data.len());
        self.inner.io().send_field::<GF8>(Direction::Previous, data.iter(), data.len());

        let data_ii = rcv_data_ii.rcv()?;
        let data_iii = rcv_data_iii.rcv()?;
        let res = izip!(data, data_ii, data_iii).map(|(&si, sii, siii)| si + sii + siii).collect();
        self.inner.io().wait_for_completion();
        Ok(res)
    }

    fn main_party_mut(&mut self) -> &mut MainParty {
        &mut self.inner
    }

}

enum PrepTriples {
    GF2(MulTripleVector<BsBool16>),
    Ohv(Ohv16TripleVector)
}

impl PrepTriples {
    pub fn len(&self) -> usize {
        match self {
            Self::GF2(v) => v.len(),
            Self::Ohv(v) => v.len(),
        }
    }
}

pub struct Lut256SSMalParty {
    inner: MainParty,
    prep_ohv: Vec<RndOhv256OutputSS>,
    context: BroadcastContext,
    prep_triples: PrepTriples,
    // to collect S-box input/output pairs to verify
    x_i: Vec<GF8>,
    x_ii: Vec<GF8>,
    y_i: Vec<GF8>,
    y_ii: Vec<GF8>,
}

impl Lut256SSMalParty {
    pub fn setup(connected: ConnectedParty, use_ohv_check: bool, n_worker_threads: Option<usize>, prot_str: Option<String>) -> MpcResult<Self> {
        MainParty::setup(connected, n_worker_threads, prot_str).map(|inner| Self {
            inner,
            prep_ohv: Vec::new(),
            context: BroadcastContext::new(),
            prep_triples: if use_ohv_check {
                PrepTriples::Ohv(Ohv16TripleVector::new())
            }else{
                PrepTriples::GF2(MulTripleVector::new())
            },
            x_i: Vec::new(),
            x_ii: Vec::new(),
            y_i: Vec::new(),
            y_ii: Vec::new(),
        })
    }
}

impl GF8InvBlackBoxSSMal for Lut256SSMalParty {

    fn constant(&self, value: GF8) -> GF8 {
        if self.inner.i == 0 {
            value
        }else{
            GF8::ZERO
        }
    }

    fn constant_rss(&self, value: GF8) -> RssShare<GF8> {
        self.inner.constant(value)
    }

    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()> {
        let n_rnd_ohv_ks = 4 * 10 * n_keys; // 4 S-boxes per round, 10 rounds, 1 LUT per S-box
        let n_rnd_ohv = 16 * 10 * n_blocks; // 16 S-boxes per round, 10 rounds, 1 LUT per S-box
        let n_prep = n_rnd_ohv + n_rnd_ohv_ks;

        match &mut self.prep_triples {
            PrepTriples::GF2(gf2_triples) => gf2_triples.reserve_for_more_triples((n_prep*22)/16),  // 22 multiplications per S-box packed in 16
            PrepTriples::Ohv(ohv_triples) => ohv_triples.reserve_for_more_triples((n_prep*4)/16), // 4 multiplications per S-box packed in 16
        }

        let mut prep =
            if self.inner.has_multi_threading() && 2 * n_prep > self.inner.num_worker_threads() {
                match &mut self.prep_triples {
                    PrepTriples::GF2(gf2_triples) => offline::generate_rndohv256_ss_mt(&mut self.inner, gf2_triples,  n_prep)?,
                    PrepTriples::Ohv(ohv_tripes) => offline::generate_rndohv256_ss_ohv_check_mt(&mut self.inner, ohv_tripes, n_prep)?,
                }
            } else {
                match &mut self.prep_triples {
                    PrepTriples::GF2(gf2_triples) => offline::generate_rndohv256_ss(&mut self.inner, gf2_triples, n_prep)?,
                    PrepTriples::Ohv(ohv_triples) => offline::generate_rndohv256_ss_ohv_check(&mut self.inner, ohv_triples, n_prep)?,
                }
            };
        if self.prep_ohv.is_empty() {
            self.prep_ohv = prep;
        } else {
            self.prep_ohv.append(&mut prep);
        }
        // allocate more capacity for the vectors
        self.x_i.reserve_exact(2*n_prep);
        self.x_ii.reserve_exact(2*n_prep);
        self.y_i.reserve_exact(2*n_prep);
        self.y_ii.reserve_exact(2*n_prep);
        Ok(())
    }

    fn gf8_inv_and_rss_output(&mut self, s: &mut[GF8], out_i: &mut[GF8], out_ii: &mut[GF8]) -> MpcResult<()> {
        let n = s.len();
        if self.prep_ohv.len() < n {
            panic!("Not enough pre-processed random one-hot vectors available. Use Lut256SSMalParty::do_preprocessing to generate them.");
        }

        let rnd_ohv = &self.prep_ohv[self.prep_ohv.len() - n..];
        let rcv_cii = self.inner.io().receive_field_slice(Direction::Next, out_i);
        let rcv_ciii = self.inner.io().receive_field_slice(Direction::Previous, out_ii);

        izip!(s.iter_mut(), self.inner.generate_alpha::<GF8>(n), rnd_ohv.iter())
            .for_each(|(dst, alpha, ohv)| {
                *dst += alpha + ohv.random_si
            });
        self.inner.io().send_field::<GF8>(Direction::Next, s.iter(), n);
        self.inner.io().send_field::<GF8>(Direction::Previous, s.iter(), n);

        rcv_cii.rcv()?;
        s.iter_mut().zip(out_i.iter()).for_each(|(dst, cii)| *dst += *cii);
        rcv_ciii.rcv()?;
        s.iter_mut().zip(out_ii.iter()).for_each(|(dst, ciii)| *dst += *ciii);

        izip!(out_i.iter_mut(), s.iter(), rnd_ohv).for_each(|(dst, c, r)| *dst = *c + r.random_si);
        izip!(out_ii.iter_mut(), s.iter(), rnd_ohv).for_each(|(dst, c, r)| *dst = *c + r.random_sii);
        if self.inner.has_multi_threading() && 2 * n > self.inner.num_worker_threads() {
            let ranges = self.inner.split_range_equally(n);
            let chunk_size = ranges[0].1 - ranges[0].0;

            self.inner.run_in_threadpool(|| {
                s.par_chunks_mut(chunk_size).zip_eq(rnd_ohv.par_chunks(chunk_size)).for_each(|(s_chunk, ohv_chunk)| {
                    s_chunk.iter_mut().zip(ohv_chunk).for_each(|(dst, ohv)| {
                        *dst = ohv.ohv.lut(dst.0 as usize, &lut256_tables::GF8_INV_BITSLICED_LUT);
                    });
                });
                Ok(())
            })?;
        }else{
            s.iter_mut().zip(rnd_ohv).for_each(|(dst, ohv)| {
                *dst = ohv.ohv.lut(dst.0 as usize, &lut256_tables::GF8_INV_BITSLICED_LUT);
            });
        }
        
        self.prep_ohv.truncate(self.prep_ohv.len() - n);
        self.inner.wait_for_completion();
        Ok(())
    }

    fn gf8_inv_rss_to_ss(&mut self, out: &mut[GF8], si: &[GF8], sii: &[GF8]) -> MpcResult<()> {
        debug_assert_eq!(si.len(), sii.len());
        let n = si.len();
        if self.prep_ohv.len() < n {
            panic!("Not enough pre-processed random one-hot vectors available. Use Lut256SSMalParty::do_preprocessing to generate them.");
        }

        let rnd_ohv = &self.prep_ohv[self.prep_ohv.len() - n..];
        izip!(out.iter_mut(), si.iter(), rnd_ohv.iter()).for_each(|(dst, si, r)| *dst = *si + r.random_si);
        let tmp = sii.iter().zip_eq(rnd_ohv.iter()).map(|(sii, r)| *sii + r.random_sii).collect_vec();
        
        let v = self.inner.open_rss(&mut self.context, out, &tmp)?;

        if self.inner.has_multi_threading() && 2 * n > self.inner.num_worker_threads() {
            let ranges = self.inner.split_range_equally(n);
            let chunk_size = ranges[0].1 - ranges[0].0;

            self.inner.run_in_threadpool(|| {
                out.par_chunks_mut(chunk_size)
                    .zip_eq(v.par_chunks(chunk_size))
                    .zip_eq(rnd_ohv.par_chunks(chunk_size)).for_each(|((out_chunk, v_chunk), ohv_chunk)| {
                        izip!(out_chunk.iter_mut(), v_chunk, ohv_chunk).for_each(|(dst, v, ohv)| {
                        *dst = ohv.ohv.lut(v.0 as usize, &lut256_tables::GF8_INV_BITSLICED_LUT);
                    });
                });
                Ok(())
            })?;
        }else{
            izip!(out.iter_mut(), v, rnd_ohv).for_each(|(dst, v, ohv)| {
                *dst = ohv.ohv.lut(v.0 as usize, &lut256_tables::GF8_INV_BITSLICED_LUT);
            });
        }
        
        self.prep_ohv.truncate(self.prep_ohv.len() - n);
        self.inner.wait_for_completion();
        Ok(())
    }

    fn register_sbox_pair(&mut self, xi: &[GF8], xii: &[GF8], yi: &[GF8], yii: &[GF8]) {
        self.x_i.extend_from_slice(xi);
        self.x_ii.extend_from_slice(xii);
        self.y_i.extend_from_slice(yi);
        self.y_ii.extend_from_slice(yii);
    }

    fn finalize(&mut self) -> MpcResult<()> {
        if (self.x_i.len() + self.prep_triples.len()) == 0 {
            // nothing to check
            return Ok(())
        }
        let mut sbox_pairs_encoder = SboxPairEncoder::new(&mut self.x_i, &mut self.x_ii, &mut self.y_i, &mut self.y_ii);
        let res = if self.inner.has_multi_threading() {
            match &mut self.prep_triples {
                PrepTriples::GF2(gf2_triples) => mult_verification::verify_multiplication_triples_mt(&mut self.inner, &mut self.context, &mut [&mut BsBool16Encoder(gf2_triples), &mut sbox_pairs_encoder], false),
                PrepTriples::Ohv(ohv_triples) => mult_verification::verify_multiplication_triples_mt(&mut self.inner, &mut self.context, &mut [&mut Ohv16TripleEncoder(ohv_triples), &mut sbox_pairs_encoder], false),
            }
        }else{
            match &mut self.prep_triples {
                PrepTriples::GF2(gf2_triples) => mult_verification::verify_multiplication_triples(&mut self.inner, &mut self.context, &mut [&mut BsBool16Encoder(gf2_triples), &mut sbox_pairs_encoder], false),
                PrepTriples::Ohv(ref mut ohv_triples) => mult_verification::verify_multiplication_triples(&mut self.inner, &mut self.context, &mut [&mut Ohv16TripleEncoder(ohv_triples), &mut sbox_pairs_encoder], false),
            }
        };
        match res {
            Ok(true) => Ok(()),
            Ok(false) => Err(MpcError::MultCheck),
            Err(err) => Err(err)
        }
    }

    fn output(&mut self, data_i: &[GF8], data_ii: &[GF8]) -> MpcResult<Vec<GF8>> {
        self.inner.open_rss(&mut self.context, data_i, data_ii)
    }

    fn main_party_mut(&mut self) -> &mut MainParty {
        &mut self.inner
    }

}

struct SboxPairEncoder<'a>{
    x_i: &'a mut Vec<GF8>,
    x_ii: &'a mut Vec<GF8>,
    y_i: &'a mut Vec<GF8>,
    y_ii: &'a mut Vec<GF8>,
}

impl<'a> SboxPairEncoder<'a> {
    fn new(x_i: &'a mut Vec<GF8>, x_ii: &'a mut Vec<GF8>, y_i: &'a mut Vec<GF8>, y_ii: &'a mut Vec<GF8>) -> Self {
        debug_assert_eq!(x_i.len(), x_ii.len());
        debug_assert_eq!(x_i.len(), y_i.len());
        debug_assert_eq!(x_i.len(), y_ii.len());
        Self {x_i, x_ii, y_i, y_ii}
    }

    #[inline]
    fn add_triples_local(x_i: &[GF8], x_ii: &[GF8], y_i: &[GF8], y_ii: &[GF8], x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], zi: &mut GF2p64InnerProd, zii: &mut GF2p64InnerProd, weight: &mut GF2p64, rand: GF2p64) {
        let mut local_weight = *weight;
        let mut i = 0;
        izip!(x_i, x_ii, y_i, y_ii).for_each(|(xi, xii, yi, yii)| {
            // we check two equations
            // x^2 * y = x
            x[i].si = xi.square().embed() * local_weight;
            x[i].sii = xii.square().embed() * local_weight;
            y[i].si = yi.embed();
            y[i].sii = yii.embed();
            zi.add_prod(&xi.embed(), &local_weight);
            zii.add_prod(&xii.embed(), &local_weight);
            local_weight *= rand;
            i += 1;
            // x * y^2 = y
            x[i].si = xi.embed() * local_weight;
            x[i].sii = xii.embed() * local_weight;
            y[i].si = yi.square().embed();
            y[i].sii = yii.square().embed();
            zi.add_prod(&yi.embed(), &local_weight);
            zii.add_prod(&yii.embed(), &local_weight);
            i += 1;
            local_weight *= rand;
        });
        *weight = local_weight;
    }
}

impl<'a> MulTripleEncoder for SboxPairEncoder<'a> {
    fn len_triples_in(&self) -> usize {
        self.x_i.len()
    }
    fn len_triples_out(&self) -> usize {
        self.x_i.len() * 2
    }
    fn add_triples(&mut self, x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], zi: &mut GF2p64InnerProd, zii: &mut GF2p64InnerProd, weight: &mut GF2p64, rand: GF2p64) {
        Self::add_triples_local(&self.x_i, &self.x_ii, &self.y_i, &self.y_ii, x, y, zi, zii, weight, rand);
    }

    fn add_triples_par(&mut self, x: &mut [RssShare<GF2p64>], y: &mut [RssShare<GF2p64>], z: &mut RssShare<GF2p64>, weight: GF2p64, rand: &[GF2p64], chunk_size: usize) {
        let zvec: Vec<_> =
            x.par_chunks_mut(2*chunk_size)
            .zip_eq(y.par_chunks_mut(2*chunk_size))
            .zip_eq(self.x_i.par_chunks(chunk_size))
            .zip_eq(self.x_ii.par_chunks(chunk_size))
            .zip_eq(self.y_i.par_chunks(chunk_size))
            .zip_eq(self.y_ii.par_chunks(chunk_size))
            .zip_eq(rand)
            .map(|((((((x, y), xi), xii), yi), yii), r)| {
                let mut zi = GF2p64InnerProd::new();
                let mut zii = GF2p64InnerProd::new();
                let mut local_weight = weight;
                Self::add_triples_local(xi, xii, yi, yii, x, y, &mut zi, &mut zii, &mut local_weight, *r);
                RssShare::from(zi.sum(), zii.sum())

            }).collect();
        zvec.into_iter().for_each(|zi| *z = *z + zi);
    }

    fn clear(&mut self) {
        // also clear capacity
        mem::take(self.x_i);
        mem::take(self.x_ii);
        mem::take(self.y_i);
        mem::take(self.y_ii);
    }
}

#[cfg(test)]
mod test {
    use crate::aes::ss::test::{secret_share_ss, test_aes128_no_keyschedule_gf8_ss, test_inv_aes128_no_keyschedule_gf8_ss, test_sub_bytes_ss};
    use crate::aes::ss::{aes128_no_keyschedule_mal, GF8InvBlackBoxSS, GF8InvBlackBoxSSMal};
    use crate::aes::test::{secret_share_aes_key_state, secret_share_vectorstate, AES128_TEST_EXPECTED_OUTPUT, AES128_TEST_INPUT, AES128_TEST_ROUNDKEYS};
    use crate::aes::{AesKeyState, VectorAesState, INV_GF8};
    use crate::share::gf8::GF8;
    use crate::share::test::{assert_eq, consistent, secret_share_vector};
    
    use itertools::{izip, repeat_n, Itertools};
    use rand::thread_rng;
    use crate::rep3_core::network::ConnectedParty;
    use crate::rep3_core::share::{HasZero, RssShare};
    use crate::rep3_core::test::{localhost_connect, TestSetup};

    use super::{Lut256SSMalParty, Lut256SSParty};

    fn localhost_setup_lut256_ss<
        T1: Send,
        F1: Send + FnOnce(&mut Lut256SSParty) -> T1,
        T2: Send,
        F2: Send + FnOnce(&mut Lut256SSParty) -> T2,
        T3: Send,
        F3: Send + FnOnce(&mut Lut256SSParty) -> T3,
    >(
        f1: F1,
        f2: F2,
        f3: F3,
        n_worker_threads: Option<usize>,
    ) -> (
        (T1, Lut256SSParty),
        (T2, Lut256SSParty),
        (T3, Lut256SSParty),
    ) {
        fn adapter<T, Fx: FnOnce(&mut Lut256SSParty) -> T>(
            conn: ConnectedParty,
            f: Fx,
            n_worker_threads: Option<usize>,
        ) -> (T, Lut256SSParty) {
            let mut party = Lut256SSParty::setup(conn, n_worker_threads, None).unwrap();
            let t = f(&mut party);
            party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(
            move |conn_party| adapter(conn_party, f1, n_worker_threads),
            move |conn_party| adapter(conn_party, f2, n_worker_threads),
            move |conn_party| adapter(conn_party, f3, n_worker_threads),
        )
    }

    struct Lut256SSSetup;
    impl TestSetup<Lut256SSParty> for Lut256SSSetup {
        fn localhost_setup<
                    T1: Send,
                    F1: Send + FnOnce(&mut Lut256SSParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut Lut256SSParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut Lut256SSParty) -> T3,
                >(
                    f1: F1,
                    f2: F2,
                    f3: F3,
                ) -> (
                    (T1, Lut256SSParty),
                    (T2, Lut256SSParty),
                    (T3, Lut256SSParty),
                ) {
            localhost_setup_lut256_ss(f1, f2, f3, None)
        }
        fn localhost_setup_multithreads<
                    T1: Send,
                    F1: Send + FnOnce(&mut Lut256SSParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut Lut256SSParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut Lut256SSParty) -> T3,
                >(
                    n_threads: usize,
                    f1: F1,
                    f2: F2,
                    f3: F3,
                ) -> (
                    (T1, Lut256SSParty),
                    (T2, Lut256SSParty),
                    (T3, Lut256SSParty),
                ) {
            localhost_setup_lut256_ss(f1, f2, f3, Some(n_threads))
        }
    }

    struct Lut256SSMalSetup;
    impl TestSetup<Lut256SSMalParty> for Lut256SSMalSetup {
        fn localhost_setup<
                    T1: Send,
                    F1: Send + FnOnce(&mut Lut256SSMalParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut Lut256SSMalParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut Lut256SSMalParty) -> T3,
                >(
                    f1: F1,
                    f2: F2,
                    f3: F3,
                ) -> (
                    (T1, Lut256SSMalParty),
                    (T2, Lut256SSMalParty),
                    (T3, Lut256SSMalParty),
                ) {
            localhost_setup_lut256_ss_mal(f1, f2, f3, false, None)
        }
        fn localhost_setup_multithreads<
                    T1: Send,
                    F1: Send + FnOnce(&mut Lut256SSMalParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut Lut256SSMalParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut Lut256SSMalParty) -> T3,
                >(
                    n_threads: usize,
                    f1: F1,
                    f2: F2,
                    f3: F3,
                ) -> (
                    (T1, Lut256SSMalParty),
                    (T2, Lut256SSMalParty),
                    (T3, Lut256SSMalParty),
                ) {
            localhost_setup_lut256_ss_mal(f1, f2, f3, false, Some(n_threads))
        }
    }

    struct Lut256SSMalOhvCheckSetup;
    impl TestSetup<Lut256SSMalParty> for Lut256SSMalOhvCheckSetup {
        fn localhost_setup<
                    T1: Send,
                    F1: Send + FnOnce(&mut Lut256SSMalParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut Lut256SSMalParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut Lut256SSMalParty) -> T3,
                >(
                    f1: F1,
                    f2: F2,
                    f3: F3,
                ) -> (
                    (T1, Lut256SSMalParty),
                    (T2, Lut256SSMalParty),
                    (T3, Lut256SSMalParty),
                ) {
            localhost_setup_lut256_ss_mal(f1, f2, f3, true, None)
        }
        fn localhost_setup_multithreads<
                    T1: Send,
                    F1: Send + FnOnce(&mut Lut256SSMalParty) -> T1,
                    T2: Send,
                    F2: Send + FnOnce(&mut Lut256SSMalParty) -> T2,
                    T3: Send,
                    F3: Send + FnOnce(&mut Lut256SSMalParty) -> T3,
                >(
                    n_threads: usize,
                    f1: F1,
                    f2: F2,
                    f3: F3,
                ) -> (
                    (T1, Lut256SSMalParty),
                    (T2, Lut256SSMalParty),
                    (T3, Lut256SSMalParty),
                ) {
            localhost_setup_lut256_ss_mal(f1, f2, f3, true, Some(n_threads))
        }
    }

    fn localhost_setup_lut256_ss_mal<
        T1: Send,
        F1: Send + FnOnce(&mut Lut256SSMalParty) -> T1,
        T2: Send,
        F2: Send + FnOnce(&mut Lut256SSMalParty) -> T2,
        T3: Send,
        F3: Send + FnOnce(&mut Lut256SSMalParty) -> T3,
    >(
        f1: F1,
        f2: F2,
        f3: F3,
        use_ohv_check: bool,
        n_worker_threads: Option<usize>,
    ) -> (
        (T1, Lut256SSMalParty),
        (T2, Lut256SSMalParty),
        (T3, Lut256SSMalParty),
    ) {
        fn adapter<T, Fx: FnOnce(&mut Lut256SSMalParty) -> T>(
            conn: ConnectedParty,
            f: Fx,
            use_ohv_check: bool,
            n_worker_threads: Option<usize>,
        ) -> (T, Lut256SSMalParty) {
            let mut party = Lut256SSMalParty::setup(conn, use_ohv_check, n_worker_threads, None).unwrap();
            let t = f(&mut party);
            party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(
            move |conn_party| adapter(conn_party, f1, use_ohv_check, n_worker_threads),
            move |conn_party| adapter(conn_party, f2, use_ohv_check, n_worker_threads),
            move |conn_party| adapter(conn_party, f3, use_ohv_check, n_worker_threads),
        )
    }

    #[test]
    fn sub_bytes() {
        test_sub_bytes_ss::<Lut256SSSetup, _>(None)
    }

    #[test]
    fn sub_bytes_mt() {
        test_sub_bytes_ss::<Lut256SSSetup, _>(Some(3))
    }

    #[test]
    fn aes_128_no_keyschedule_lut256_ss() {
        test_aes128_no_keyschedule_gf8_ss::<Lut256SSSetup, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_lut256_ss_mt() {
        test_aes128_no_keyschedule_gf8_ss::<Lut256SSSetup, _>(100, Some(3))
    }

    #[test]
    fn inv_aes_128_no_keyschedule_lut256_ss() {
        test_inv_aes128_no_keyschedule_gf8_ss::<Lut256SSSetup, _>(1, None)
    }

    #[test]
    fn inv_aes_128_no_keyschedule_lut256_ss_mt() {
        test_inv_aes128_no_keyschedule_gf8_ss::<Lut256SSSetup, _>(100, Some(3))
    }

    #[test]
    fn gf8_inv_rss_to_ss() {
        let inputs = (0..=255u8).map(|i| GF8(i)).collect_vec();
        let mut rng = thread_rng();
        let (in0, in1, in2) = secret_share_vector::<GF8, _>(&mut rng, inputs.iter());
        let program = |input: Vec<RssShare<GF8>>| {
            move |p: &mut Lut256SSMalParty| {
                p.do_preprocessing(0, 256/16).unwrap();
                let mut out = vec![GF8::ZERO; input.len()];
                let (xi, xii): (Vec<_>, Vec<_>) = input.into_iter().map(|rss| (rss.si, rss.sii)).unzip();
                p.gf8_inv_rss_to_ss(&mut out, &xi, &xii).unwrap();
                out
            }
        };

        let ((y1, _), (y2, _), (y3, _)) = localhost_setup_lut256_ss_mal(program(in0), program(in1), program(in2), false, None);

        assert_eq!(y1.len(), inputs.len());
        assert_eq!(y2.len(), y1.len());
        assert_eq!(y3.len(), y1.len());

        for (x, y1, y2, y3) in izip!(inputs, y1, y2, y3) {
            let y = y1 + y2 + y3;
            assert_eq!(y, GF8(INV_GF8[x.0 as usize]));
        }
    }

    #[test]
    fn gf8_inv_and_rss_output() {
        let inputs = (0..=255u8).map(|i| GF8(i)).collect_vec();
        let mut rng = thread_rng();
        let (in0, in1, in2) = secret_share_ss(&mut rng, &inputs);
        let program = |mut input: Vec<GF8>| {
            move |p: &mut Lut256SSMalParty| {
                p.do_preprocessing(0, 256/16).unwrap();
                let mut input_i = vec![GF8::ZERO; input.len()];
                let mut input_ii = vec![GF8::ZERO; input.len()];
                p.gf8_inv_and_rss_output(&mut input, &mut input_i, &mut input_ii).unwrap();
                let input_rss = input_i.into_iter().zip_eq(input_ii).map(|(si, sii)| RssShare::from(si, sii)).collect_vec();
                (input, input_rss)
            }
        };

        let (((y1, input_rss1), _), ((y2, input_rss2), _), ((y3, input_rss3), _)) = localhost_setup_lut256_ss_mal(program(in0), program(in1), program(in2), false, None);

        assert_eq!(y1.len(), inputs.len());
        assert_eq!(y2.len(), y1.len());
        assert_eq!(y3.len(), y1.len());
        assert_eq!(input_rss1.len(), inputs.len());
        assert_eq!(input_rss2.len(), inputs.len());
        assert_eq!(input_rss3.len(), inputs.len());

        for (x, y1, y2, y3) in izip!(inputs.iter(), y1, y2, y3) {
            let y = y1 + y2 + y3;
            assert_eq!(y, GF8(INV_GF8[x.0 as usize]));
        }

        for (x, x1, x2, x3) in izip!(inputs, input_rss1, input_rss2, input_rss3) {
            consistent(&x1, &x2, &x3);
            assert_eq(x1, x2, x3, x);
        }
    }

    fn test_aes128_no_keyschedule_gf8_malss<S: TestSetup<P>, P: GF8InvBlackBoxSSMal>(n_blocks: usize, n_worker_threads: Option<usize>) {
        let input: Vec<_> = repeat_n(AES128_TEST_INPUT, n_blocks)
            .flatten()
            .map(|x| GF8(x))
            .collect();
        let mut rng = thread_rng();
        let (in1, in2, in3) = secret_share_vectorstate(&mut rng, &input);
        let mut ks1 = Vec::with_capacity(11);
        let mut ks2 = Vec::with_capacity(11);
        let mut ks3 = Vec::with_capacity(11);
        for i in 0..11 {
            let (s1, s2, s3) = secret_share_aes_key_state(&mut rng, &AES128_TEST_ROUNDKEYS[i].map(|x| GF8(x)));
            ks1.push(s1);
            ks2.push(s2);
            ks3.push(s3);
        }

        let program = |input: VectorAesState, ks: Vec<AesKeyState>| {
            move |p: &mut P| {
                p.do_preprocessing(0, input.n).unwrap();
                let output = aes128_no_keyschedule_mal(p, input, &ks).unwrap();
                p.finalize().unwrap();
                p.main_party_mut().io().wait_for_completion();
                output
            }
        };
        let ((s1, _), (s2, _), (s3, _)) = match n_worker_threads {
            Some(n_worker_threads) => S::localhost_setup_multithreads(
                n_worker_threads,
                program(in1, ks1),
                program(in2, ks2),
                program(in3, ks3),
            ),
            None => S::localhost_setup(program(in1, ks1), program(in2, ks2), program(in3, ks3)),
        };
        assert_eq!(s1.n, n_blocks);
        assert_eq!(s2.n, n_blocks);
        assert_eq!(s3.n, n_blocks);

        let shares: Vec<_> = s1
            .to_bytes()
            .into_iter()
            .zip(s2.to_bytes().into_iter().zip(s3.to_bytes()))
            .map(|(s1, (s2, s3))| (s1, s2, s3))
            .collect();

        for (s1, s2, s3) in &shares {
            consistent(s1, s2, s3);
        }

        for (i, (s1, s2, s3)) in shares.into_iter().enumerate() {
            assert_eq(s1, s2, s3, GF8(AES128_TEST_EXPECTED_OUTPUT[i % 16]));
        }
    }

    #[test]
    fn aes_128_no_keyschedule_lut256_ss_mal() {
        test_aes128_no_keyschedule_gf8_malss::<Lut256SSMalSetup, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_lut256_ss_mal_mt() {
        test_aes128_no_keyschedule_gf8_malss::<Lut256SSMalSetup, _>(100, Some(3))
    }

    #[test]
    fn aes_128_no_keyschedule_lut256_ss_mal_ohv_check() {
        test_aes128_no_keyschedule_gf8_malss::<Lut256SSMalOhvCheckSetup, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_lut256_ss_mal_ohv_check_mt() {
        test_aes128_no_keyschedule_gf8_malss::<Lut256SSMalOhvCheckSetup, _>(100, Some(3))
    }
}