//! This module implements the *maliciously-secure* oblivious AES protocol by Furukawa et al.,
//! "High-Throughput Secure Three-Party Computation for Malicious Adversaries and an Honest Majority"
//! (<https://eprint.iacr.org/2016/944>).
//!
//! In the pre-processing phase, multiplication triples are generated and checked via bucket cut-and-choose.
//! The online phase proceeds like the semi-honest variant but before outputs are revealed, a post-sacrificing step checks
//! the validity of all multiplications that are computed in the online phase before.
//!
//! This module notably contains
//!   - [furukawa_benchmark] that implements the AES benchmark
//!   - [FurukawaParty] the party wrapper for the protocol. [FurukawaParty] also implements [ArithmeticBlackBox]

use std::{ops::AddAssign, time::Instant};

use itertools::izip;
use rand_chacha::ChaCha20Rng;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use sha2::Sha256;

use crate::{
    aes::{self, aes128_no_keyschedule, GF8InvBlackBox}, benchmark::{BenchmarkProtocol, BenchmarkResult}, chida, conversion::Z64Bool, gcm::gf128::GF128, network::{
        task::{Direction, IoLayerOwned},
        ConnectedParty,
    }, party::{
        broadcast::{Broadcast, BroadcastContext}, error::{MpcError, MpcResult}, ArithmeticBlackBox, MainParty, MulTripleRecorder, MulTripleVector, Party
    }, share::{gf8::GF8, Field, FieldDigestExt, FieldRngExt, RssShare, RssShareVec}
};

mod offline;

/// This function implements the AES benchmark.
///
/// The arguments are
/// - `connected` - the local party
/// - `simd` - number of parallel AES calls
/// - `n_worker_threads` - number of worker threads
pub fn furukawa_benchmark(connected: ConnectedParty, simd: usize, n_worker_threads: Option<usize>) {
    let mut party = FurukawaParty::setup(connected, n_worker_threads).unwrap();
    let setup_comm_stats = party.io().reset_comm_stats();
    let inputs = aes::random_state(&mut party.inner, simd);
    // create random key states for benchmarking purposes
    let ks = aes::random_keyschedule(&mut party.inner);

    let start = Instant::now();
    party.do_preprocessing(0, simd).unwrap();
    let prep_duration = start.elapsed();
    let prep_comm_stats = party.io().reset_comm_stats();

    let start = Instant::now();
    let output = aes128_no_keyschedule(&mut party, inputs, &ks).unwrap();
    let online_duration = start.elapsed();
    let online_comm_stats = party.io().reset_comm_stats();
    party.finalize().unwrap();
    let post_sacrifice_duration = start.elapsed();
    let _ = aes::output(&mut party, output).unwrap();
    party.inner.teardown().unwrap();

    println!("Finished benchmark");

    println!("Party {}: Furukawa et al. with SIMD={} took {}s (pre-processing), {}s (online), {}s (post-sacrifice), {}s (total)", party.inner.i, simd, prep_duration.as_secs_f64(), online_duration.as_secs_f64(), post_sacrifice_duration.as_secs_f64(), (prep_duration+online_duration+post_sacrifice_duration).as_secs_f64());
    println!("Setup:");
    setup_comm_stats.print_comm_statistics(party.inner.i);
    println!("Pre-Processing:");
    prep_comm_stats.print_comm_statistics(party.inner.i);
    println!("Online Phase:");
    online_comm_stats.print_comm_statistics(party.inner.i);
    party.inner.print_statistics();
}

pub struct MalChidaBenchmark;

impl BenchmarkProtocol for MalChidaBenchmark {
    fn protocol_name(&self) -> String {
        "mal-chida".to_string()
    }
    fn run(
        &self,
        conn: ConnectedParty,
        simd: usize,
        n_worker_threads: Option<usize>,
    ) -> BenchmarkResult {
        let mut party = FurukawaParty::setup(conn, n_worker_threads).unwrap();
        let _setup_comm_stats = party.io().reset_comm_stats();
        let inputs = aes::random_state(&mut party.inner, simd);
        // create random key states for benchmarking purposes
        let ks = aes::random_keyschedule(&mut party.inner);

        println!("After setup");

        let start = Instant::now();
        party.do_preprocessing(0, simd).unwrap();
        let prep_duration = start.elapsed();
        let prep_comm_stats = party.io().reset_comm_stats();

        println!("After pre-processing");

        let start = Instant::now();
        let output = aes128_no_keyschedule(&mut party, inputs, &ks).unwrap();
        party.finalize().unwrap();
        let online_duration = start.elapsed();
        println!("After online");
        let online_comm_stats = party.io().reset_comm_stats();
        // let post_sacrifice_duration = start.elapsed();
        let _ = aes::output(&mut party, output).unwrap();
        println!("After output");
        party.inner.teardown().unwrap();
        println!("After teardown");

        BenchmarkResult::new(
            prep_duration,
            online_duration,
            prep_comm_stats,
            online_comm_stats,
            party.inner.get_additional_timers(),
        )
    }
}

pub struct FurukawaParty<F: Field> {
    inner: MainParty,
    part: FurukawaPartyPart<F>,
}

pub struct FurukawaPartyPart<F: Field> {
    triples_to_check: MulTripleVector<F>,
    pre_processing: Option<MulTripleVector<F>>,
}

impl<F: Field + Sync + Send> FurukawaParty<F>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
{
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>) -> MpcResult<Self> {
        MainParty::setup(connected, n_worker_threads).map(|party| Self {
            inner: party,
            part: FurukawaPartyPart::new(),
        })
    }

    pub fn start_input_phase(&mut self) -> InputPhase {
        InputPhase::new(&mut self.inner)
    }

    pub fn output_phase<T, OF: FnOnce(&mut OutputPhase) -> MpcResult<T>>(
        &mut self,
        block: OF,
    ) -> MpcResult<T>
    where
        F: AddAssign,
    {
        self.part.verify_multiplications(&mut self.inner)?;

        // now the output phase can begin
        let mut phase = OutputPhase::new(&mut self.inner);
        let res = block(&mut phase)?;
        phase.end_output_phase()?;
        Ok(res)
    }
}

impl<F: Field + Sync + Send> FurukawaPartyPart<F>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
{
    fn new() -> Self {
        Self {
            triples_to_check: MulTripleVector::new(),
            pre_processing: None,
        }
    }

    pub fn prepare_multiplications(&mut self, party: &mut MainParty, n_mults: usize) -> MpcResult<()>
    where
        F: Send + Sync,
    {
        // run the bucket cut-and-choose
        if let Some(ref pre_processing) = self.pre_processing {
            println!("Discarding {} left-over triples", pre_processing.len());
            self.pre_processing = None;
        }
        self.pre_processing = Some(offline::bucket_cut_and_choose(party, n_mults)?);
        Ok(())
    }

    pub fn mul(&mut self, party: &mut MainParty, ci: &mut [F], cii: &mut [F], ai: &[F], aii: &[F], bi: &[F], bii: &[F]) -> MpcResult<()> {
        debug_assert_eq!(ai.len(), aii.len());
        debug_assert_eq!(ai.len(), bi.len());
        debug_assert_eq!(ai.len(), bii.len());

        izip!(ci.iter_mut(), party.generate_alpha(ai.len()), ai, aii, bi, bii)
            .for_each(|(ci_j, alpha_j, ai_j, aii_j, bi_j, bii_j)| {
                *ci_j = alpha_j + *ai_j * *bi_j + *ai_j * *bii_j + *aii_j * *bi_j
            });
        party.io()
            .send_field::<F>(Direction::Previous, ci.iter(), ci.len());
        let rcv_cii = party.io().receive_field_slice(Direction::Next, cii);
        rcv_cii.rcv()?;
        // note down the observed multiplication triple
        self.triples_to_check.record_mul_triple(ai, aii, bi, bii, &ci, &cii);
        party.io().wait_for_completion();
        Ok(())
    }

    pub fn verify_multiplications(&mut self, party: &mut MainParty) -> MpcResult<()> {
        // check all recorded multiplications
        println!(
            "post-sacrifice: checking {} multiplications",
            self.triples_to_check.len()
        );
        if self.triples_to_check.len() > 0 {
            let prep = self.pre_processing.as_mut().expect("No pre-processed multiplication triples found. Use prepare_multiplications to generate them before the output phase");
            if prep.len() < self.triples_to_check.len() {
                panic!("Not enough pre-processed multiplication triples left: Required {} but found only {}", self.triples_to_check.len(), prep.len());
            }

            let leftover = prep.len() - self.triples_to_check.len();
            let (prep_ai, prep_aii, prep_bi, prep_bii, prep_ci, prep_cii) = prep.as_mut_slices();
            let err = if party.has_multi_threading()
                && self.triples_to_check.len() > party.num_worker_threads()
            {
                offline::sacrifice_mt(
                    party,
                    self.triples_to_check.len(),
                    1,
                    self.triples_to_check.ai(),
                    self.triples_to_check.aii(),
                    self.triples_to_check.bi(),
                    self.triples_to_check.bii(),
                    self.triples_to_check.ci(),
                    self.triples_to_check.cii(),
                    &mut prep_ai[leftover..],
                    &mut prep_aii[leftover..],
                    &mut prep_bi[leftover..],
                    &mut prep_bii[leftover..],
                    &mut prep_ci[leftover..],
                    &mut prep_cii[leftover..],
                )
            } else {
                offline::sacrifice(
                    party,
                    self.triples_to_check.len(),
                    1,
                    self.triples_to_check.ai(),
                    self.triples_to_check.aii(),
                    self.triples_to_check.bi(),
                    self.triples_to_check.bii(),
                    self.triples_to_check.ci(),
                    self.triples_to_check.cii(),
                    &mut prep_ai[leftover..],
                    &mut prep_aii[leftover..],
                    &mut prep_bi[leftover..],
                    &mut prep_bii[leftover..],
                    &mut prep_ci[leftover..],
                    &mut prep_cii[leftover..],
                )
            };
            // purge the sacrificed triples
            if leftover > 0 {
                prep.shrink(leftover);
            } else {
                self.pre_processing = None;
            }
            self.triples_to_check.clear();
            err // return the sacrifice error
        } else {
            Ok(())
        }
    }
}

pub struct InputPhase<'a> {
    party: &'a mut MainParty,
    context: BroadcastContext,
}

impl<'a> InputPhase<'a>
{
    fn new(party: &'a mut MainParty) -> Self {
        Self {
            party,
            context: BroadcastContext::new(),
        }
    }

    pub fn my_input<F: Field>(&mut self, input: &[F]) -> MpcResult<RssShareVec<F>>
    where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>,
    {
        let a = self.party.generate_random(input.len());
        let b = self
            .party
            .open_rss_to(&mut self.context, &a, self.party.i)?;
        let mut b = b.unwrap(); // this is safe since we open to party.i
        for i in 0..b.len() {
            b[i] += input[i];
        }
        self.party.broadcast_round(&mut self.context, &mut [], &mut [], b.as_slice())?;
        Ok(a.into_iter()
            .zip(b)
            .map(|(ai, bi)| self.party.constant(bi) - ai)
            .collect())
    }

    pub fn other_input<F: Field>(
        &mut self,
        input_party: usize,
        n_inputs: usize,
    ) -> MpcResult<RssShareVec<F>>
    where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>,
    {
        assert_ne!(self.party.i, input_party);
        let a = self.party.generate_random(n_inputs);
        let b = self
            .party
            .open_rss_to(&mut self.context, &a, input_party)?;
        debug_assert!(b.is_none());
        let mut b = vec![F::ZERO; n_inputs];
        match (self.party.i, input_party) {
            (0, 2) | (1, 0) | (2, 1) => {
                self.party.broadcast_round(&mut self.context, &mut [], &mut b, &[])?
            }
            (0, 1) | (1, 2) | (2, 0) => {
                self.party.broadcast_round(&mut self.context, &mut b, &mut [], &[])?
            }
            _ => unreachable!(),
        }
        Ok(a.into_iter()
            .zip(b)
            .map(|(ai, bi)| self.party.constant(bi) - ai)
            .collect())
    }

    pub fn end_input_phase(self) -> MpcResult<()> {
        self.party.compare_view(self.context)
    }
}

fn input_round<F: Field>(party: &mut MainParty, my_input: &[F]) -> MpcResult<(RssShareVec<F>, RssShareVec<F>, RssShareVec<F>)>
where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>,
{
    let party_index = party.i;
    let mut input_phase = InputPhase::new(party);

    let in1 = if party_index == 0 {
        input_phase.my_input(my_input)
    } else {
        input_phase.other_input(0, my_input.len())
    }?;

    let in2 = if party_index == 1 {
        input_phase.my_input(my_input)
    } else {
        input_phase.other_input(1, my_input.len())
    }?;

    let in3 = if party_index == 2 {
        input_phase.my_input(my_input)
    } else {
        input_phase.other_input(2, my_input.len())
    }?;
    input_phase.end_input_phase()?;
    Ok((in1, in2, in3))
}

pub struct OutputPhase<'a> {
    party: &'a mut MainParty,
    context: BroadcastContext,
}

impl<'a> OutputPhase<'a>
{
    fn new(party: &'a mut MainParty) -> Self {
        Self {
            party,
            context: BroadcastContext::new(),
        }
    }

    pub fn output_to<F: Field>(&mut self, to_party: usize, si: &[F], sii: &[F]) -> MpcResult<Option<Vec<F>>>
    where Sha256: FieldDigestExt<F>
    {
        debug_assert_eq!(si.len(), sii.len());
        let rss: Vec<_> = si
            .iter()
            .zip(sii)
            .map(|(si, sii)| RssShare::from(*si, *sii))
            .collect();
        self.party
            .open_rss_to(&mut self.context, &rss, to_party)
    }

    pub fn output<F: Field>(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>> where Sha256: FieldDigestExt<F>
    {
        self.party.open_rss(&mut self.context, si, sii)
    }

    pub fn output_to_multiple<F: Field>(&mut self, to_p1: &[RssShare<F>], to_p2: &[RssShare<F>], to_p3: &[RssShare<F>]) -> MpcResult<Vec<F>>
    where Sha256: FieldDigestExt<F>
    {
        self.party.open_rss_to_multiple(&mut self.context, to_p1, to_p2, to_p3)
    }

    fn end_output_phase(self) -> MpcResult<()> {
        self.party.compare_view(self.context)
    }
}

impl<F: Field + Send + Sync> ArithmeticBlackBox<F> for FurukawaParty<F>
where
    ChaCha20Rng: FieldRngExt<F>,
    Sha256: FieldDigestExt<F>,
{
    type Rng = ChaCha20Rng;
    type Digest = Sha256;

    fn io(&self) -> &IoLayerOwned {
        self.inner.io()
    }

    fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()> {
        self.part.prepare_multiplications(&mut self.inner, n_multiplications)
    }

    fn constant(&self, value: F) -> RssShare<F> {
        self.inner.constant(value)
    }

    fn generate_random(&mut self, n: usize) -> RssShareVec<F> {
        self.inner.generate_random(n)
    }

    fn generate_alpha(&mut self, n: usize) -> Vec<F> {
        self.inner.generate_alpha(n)
    }

    fn input_round(
        &mut self,
        my_input: &[F],
    ) -> MpcResult<(RssShareVec<F>, RssShareVec<F>, RssShareVec<F>)> {
        input_round(&mut self.inner, my_input)
    }

    fn mul(&mut self, ci: &mut [F], cii: &mut [F], ai: &[F], aii: &[F], bi: &[F], bii: &[F]) -> MpcResult<()> {
        self.part.mul(&mut self.inner, ci, cii, ai, aii, bi, bii)
    }

    fn output_round(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>> {
        self.output_phase(|of| of.output(si, sii))
    }

    fn output_to(&mut self, to_p1: &[RssShare<F>], to_p2: &[RssShare<F>], to_p3: &[RssShare<F>]) -> MpcResult<Vec<F>> {
        let i = self.inner.i;
        self.output_phase(|of| {
            let (to_p1_si, to_p1_sii): (Vec<_>, Vec<_>) = to_p1.iter().map(|rss| (rss.si, rss.sii)).unzip();
            let (to_p2_si, to_p2_sii): (Vec<_>, Vec<_>) = to_p2.iter().map(|rss| (rss.si, rss.sii)).unzip();
            let (to_p3_si, to_p3_sii): (Vec<_>, Vec<_>) = to_p3.iter().map(|rss| (rss.si, rss.sii)).unzip();
            let res1 = of.output_to(0, &to_p1_si, &to_p1_sii)?;
            let res2 = of.output_to(1, &to_p2_si, &to_p2_sii)?;
            let res3 = of.output_to(2, &to_p3_si, &to_p3_sii)?;
            
            match i {
                0 => {
                    debug_assert!(res2.is_none());
                    debug_assert!(res3.is_none());
                    res1.ok_or(MpcError::Receive)
                },
                1 => {
                    debug_assert!(res1.is_none());
                    debug_assert!(res3.is_none());
                    res2.ok_or(MpcError::Receive)
                },
                2 => {
                    debug_assert!(res1.is_none());
                    debug_assert!(res2.is_none());
                    res3.ok_or(MpcError::Receive)
                },
                _ => unreachable!()
            }
        })
    }

    fn finalize(&mut self) -> MpcResult<()> {
        self.part.verify_multiplications(&mut self.inner)
    }
}

impl FurukawaPartyPart<GF8> {
    fn gf8_inv(&mut self, party: &mut MainParty, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        if party.has_multi_threading() && party.num_worker_threads() < si.len() {
            debug_assert_eq!(si.len(), sii.len());
            let ranges = party.split_range_equally(si.len());
            let chunk_size = ranges[0].1 - ranges[0].0;
            let thread_parties = party
                .create_thread_parties_with_additional_data(ranges, |_, _| Some(MulTripleVector::new()));
            let observed_triples = party.run_in_threadpool(|| {
                Ok(thread_parties
                    .into_par_iter()
                    .zip_eq(si.par_chunks_mut(chunk_size))
                    .zip_eq(sii.par_chunks_mut(chunk_size))
                    .map(|((mut thread_party, si), sii)| {
                        let mut rec = thread_party.additional_data.take().unwrap();
                        gf8_inv_layer(&mut thread_party, &mut rec, si, sii)
                            .map(|()| rec)
                    })
                    .collect_vec_list())
            })?;
            // append triples

            let observed_triples = observed_triples.into_iter().flatten().collect::<MpcResult<Vec<_>>>()?;
            self.triples_to_check.join_thread_mul_triple_recorders(observed_triples);
            Ok(())
        } else {
            gf8_inv_layer(party, &mut self.triples_to_check, si, sii)
        }
    }

    fn do_preprocessing(&mut self, party: &mut MainParty, n_keys: usize, n_blocks: usize) -> MpcResult<()> {
        let n_muls_ks = 4 * 10 * 4 * n_keys; // 4 S-boxes per round, 10 rounds, 4 multiplications per S-box
        let n_muls_blocks = 16 * 10 * 4 * n_blocks; // 16 S-boxes per round, 10 rounds, 4 multiplications per S-box
        self.prepare_multiplications(party, n_muls_ks + n_muls_blocks)
    }
}

impl GF8InvBlackBox for FurukawaParty<GF8> {
    fn constant(&self, value: GF8) -> RssShare<GF8> {
        <Self as ArithmeticBlackBox<GF8>>::constant(self, value)
    }

    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        self.part.gf8_inv(&mut self.inner, si, sii)
    }

    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()> {
        self.part.do_preprocessing(&mut self.inner, n_keys, n_blocks)
    }
}

pub struct FurukawaGCMParty {
    inner: MainParty,
    gf8: FurukawaPartyPart<GF8>,
    gf128: FurukawaPartyPart<GF128>,
    z64: FurukawaPartyPart<Z64Bool>,
}

impl FurukawaGCMParty {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>) -> MpcResult<Self> {
        MainParty::setup(connected, n_worker_threads).map(|party| Self {
            inner: party,
            gf8: FurukawaPartyPart::new(),
            gf128: FurukawaPartyPart::new(),
            z64: FurukawaPartyPart::new(),
        })
    }

    fn check_all_multiplications(&mut self) -> MpcResult<()> {
        self.gf8.verify_multiplications(&mut self.inner)?;
        self.gf128.verify_multiplications(&mut self.inner)?;
        self.z64.verify_multiplications(&mut self.inner)
    }
}


/// Macro to implement the `ArithmeticBlackBox` trait for the `FurukawaGCMParty` struct.
/// 
/// # Parameters
/// - `F`: The field type for which the `ArithmeticBlackBox` trait is implemented. This can be `GF8`, `GF128`, or `Z64Bool`.
/// - `PART`: The name of the `FurukawaPartyPart` member of the `FurukawaGCMParty` struct to which the calls are delegated.
macro_rules! impl_arithmetic_black_box {
    ($F:ty, $PART:ident) => {
        impl ArithmeticBlackBox<$F> for FurukawaGCMParty {
            type Rng = ChaCha20Rng;
            type Digest = Sha256;

            fn constant(&self, value: $F) -> RssShare<$F> {
                self.inner.constant(value)
            }

            fn generate_alpha(&mut self, n: usize) -> Vec<$F> {
                self.inner.generate_alpha(n)
            }

            fn generate_random(&mut self, n: usize) -> RssShareVec<$F> {
                self.inner.generate_random(n)
            }

            fn io(&self) -> &IoLayerOwned {
                self.inner.io()
            }

            fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()> {
                self.$PART.prepare_multiplications(&mut self.inner, n_multiplications)
            }

            fn input_round(&mut self, my_input: &[$F]) -> MpcResult<(RssShareVec<$F>, RssShareVec<$F>, RssShareVec<$F>)> {
                input_round(&mut self.inner, my_input)
            }

            fn mul(&mut self, ci: &mut [$F], cii: &mut [$F], ai: &[$F], aii: &[$F], bi: &[$F], bii: &[$F]) -> MpcResult<()> {
                self.$PART.mul(&mut self.inner, ci, cii, ai, aii, bi, bii)
            }

            fn output_round(&mut self, si: &[$F], sii: &[$F]) -> MpcResult<Vec<$F>> {
                let mut of = OutputPhase::new(&mut self.inner);
                let res = of.output(si, sii)?;
                of.end_output_phase()?;
                Ok(res)
            }

            fn output_to(&mut self, to_p1: &[RssShare<$F>], to_p2: &[RssShare<$F>], to_p3: &[RssShare<$F>]) -> MpcResult<Vec<$F>> {
                let mut of = OutputPhase::new(&mut self.inner);
                let res = of.output_to_multiple(to_p1, to_p2, to_p3)?;
                of.end_output_phase()?;
                Ok(res)
            }
        
            fn finalize(&mut self) -> MpcResult<()> {
                self.check_all_multiplications()
            }
        }
    };
}

impl_arithmetic_black_box!(GF8, gf8);
impl_arithmetic_black_box!(GF128, gf128);
impl_arithmetic_black_box!(Z64Bool, z64);

impl GF8InvBlackBox for FurukawaGCMParty {
    fn constant(&self, value: GF8) -> RssShare<GF8> {
        self.inner.constant(value)
    }

    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        self.gf8.gf8_inv(&mut self.inner, si, sii)
    }

    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()> {
        self.gf8.do_preprocessing(&mut self.inner, n_keys, n_blocks)
    }
}

#[inline]
fn square_layer(v: &[GF8]) -> Vec<GF8> {
    v.iter().map(|x| x.square()).collect()
}

#[inline]
fn append(a: &[GF8], b: &[GF8]) -> Vec<GF8> {
    let mut res = vec![GF8(0); a.len() + b.len()];
    res[..a.len()].copy_from_slice(a);
    res[a.len()..].copy_from_slice(b);
    res
}

// the straight-forward gf8 inversion using 4 multiplication and only squaring (see Chida et al. "High-Throughput Secure AES Computation" in WAHC'18 [Figure 6])
fn gf8_inv_layer<P: Party, Rec: MulTripleRecorder<GF8>>(
    party: &mut P,
    rec: &mut Rec, 
    si: &mut [GF8],
    sii: &mut [GF8],
) -> MpcResult<()> {
    let n = si.len();
    // this is not yet the multiplication that chida et al use
    let x2 = (square_layer(si), square_layer(sii));
    // x^3 = x^2 * x
    let mut x3 = (vec![GF8(0); n], vec![GF8(0); n]);
    chida::online::mul_no_sync(party, &mut x3.0, &mut x3.1, si, sii, &x2.0, &x2.1)?;
    rec.record_mul_triple(si, sii, &x2.0, &x2.1, &x3.0, &x3.1);

    let x6 = (square_layer(&x3.0), square_layer(&x3.1));
    let x12 = (square_layer(&x6.0), square_layer(&x6.1));

    let x12_x12 = (append(&x12.0, &x12.0), append(&x12.1, &x12.1));
    let x3_x2 = (append(&x3.0, &x2.0), append(&x3.1, &x2.1));

    let mut x15_x14 = (vec![GF8(0); 2*n], vec![GF8(0); 2*n]); // VectorAesState::new(x12_x12.n);
    // x^15 = x^12 * x^3 and x^14 = x^12 * x^2 in one round
    chida::online::mul_no_sync(party, &mut x15_x14.0, &mut x15_x14.1, &x12_x12.0, &x12_x12.1, &x3_x2.0, &x3_x2.1)?;
    rec.record_mul_triple(&x12_x12.0, &x12_x12.1, &x3_x2.0, &x3_x2.1, &x15_x14.0, &x15_x14.1);

    // x^15 square in-place x^240 = (x^15)^16
    for i in 0..n {
        x15_x14.0[i] = x15_x14.0[i].square().square().square().square();
        x15_x14.1[i] = x15_x14.1[i].square().square().square().square();
    }
    // x^254 = x^240 * x^14
    // write directly to output buffers si,sii
    chida::online::mul_no_sync(party, si, sii, &x15_x14.0[..n], &x15_x14.1[..n], &x15_x14.0[n..], &x15_x14.1[n..])?;
    rec.record_mul_triple(&x15_x14.0[..n], &x15_x14.1[..n], &x15_x14.0[n..], &x15_x14.1[n..], si, sii);
    Ok(())
}

#[cfg(test)]
pub mod test {
    use std::thread::JoinHandle;

    use crate::aes::test::{
        test_aes128_keyschedule_gf8, test_aes128_no_keyschedule_gf8,
        test_inv_aes128_no_keyschedule_gf8,
    };
    use crate::party::test::TestSetup;
    use crate::party::ArithmeticBlackBox;
    use crate::share::test::{assert_eq, consistent};
    use rand::thread_rng;
    use rand_chacha::ChaCha20Rng;
    use sha2::Sha256;

    use crate::{
        network::ConnectedParty,
        party::test::localhost_connect,
        share::{gf8::GF8, Field, FieldDigestExt, FieldRngExt, RssShare},
    };

    use super::FurukawaParty;

    pub fn localhost_setup_furukawa<
        F: Field + Send + 'static + Sync,
        T1: Send + 'static,
        F1: Send + FnOnce(&mut FurukawaParty<F>) -> T1 + 'static,
        T2: Send + 'static,
        F2: Send + FnOnce(&mut FurukawaParty<F>) -> T2 + 'static,
        T3: Send + 'static,
        F3: Send + FnOnce(&mut FurukawaParty<F>) -> T3 + 'static,
    >(
        f1: F1,
        f2: F2,
        f3: F3,
        n_worker_threads: Option<usize>,
    ) -> (
        JoinHandle<(T1, FurukawaParty<F>)>,
        JoinHandle<(T2, FurukawaParty<F>)>,
        JoinHandle<(T3, FurukawaParty<F>)>,
    )
    where
        Sha256: FieldDigestExt<F>,
        ChaCha20Rng: FieldRngExt<F>,
    {
        fn adapter<F: Field + Send + Sync, T, Fx: FnOnce(&mut FurukawaParty<F>) -> T>(
            conn: ConnectedParty,
            f: Fx,
            n_worker_threads: Option<usize>,
        ) -> (T, FurukawaParty<F>)
        where
            Sha256: FieldDigestExt<F>,
            ChaCha20Rng: FieldRngExt<F>,
        {
            let mut party = FurukawaParty::setup(conn, n_worker_threads).unwrap();
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

    pub struct FurukawaSetup;
    impl<F: Field + Send + Sync + 'static> TestSetup<FurukawaParty<F>> for FurukawaSetup
    where
        Sha256: FieldDigestExt<F>,
        ChaCha20Rng: FieldRngExt<F>,
    {
        fn localhost_setup<
            T1: Send + 'static,
            F1: Send + FnOnce(&mut FurukawaParty<F>) -> T1 + 'static,
            T2: Send + 'static,
            F2: Send + FnOnce(&mut FurukawaParty<F>) -> T2 + 'static,
            T3: Send + 'static,
            F3: Send + FnOnce(&mut FurukawaParty<F>) -> T3 + 'static,
        >(
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            JoinHandle<(T1, FurukawaParty<F>)>,
            JoinHandle<(T2, FurukawaParty<F>)>,
            JoinHandle<(T3, FurukawaParty<F>)>,
        ) {
            localhost_setup_furukawa(f1, f2, f3, None)
        }
        fn localhost_setup_multithreads<
            T1: Send + 'static,
            F1: Send + FnOnce(&mut FurukawaParty<F>) -> T1 + 'static,
            T2: Send + 'static,
            F2: Send + FnOnce(&mut FurukawaParty<F>) -> T2 + 'static,
            T3: Send + 'static,
            F3: Send + FnOnce(&mut FurukawaParty<F>) -> T3 + 'static,
        >(
            n_threads: usize,
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            JoinHandle<(T1, FurukawaParty<F>)>,
            JoinHandle<(T2, FurukawaParty<F>)>,
            JoinHandle<(T3, FurukawaParty<F>)>,
        ) {
            localhost_setup_furukawa(f1, f2, f3, Some(n_threads))
        }
    }

    #[test]
    fn input_gf8() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let x1 = rng.generate(N);
        let x2 = rng.generate(N);
        let x3 = rng.generate(N);

        let program = |x: Vec<GF8>| move |p: &mut FurukawaParty<GF8>| p.input_round(&x).unwrap();

        let (h1, h2, h3) = FurukawaSetup::localhost_setup(
            program(x1.clone()),
            program(x2.clone()),
            program(x3.clone()),
        );
        let ((x11, x21, x31), _) = h1.join().unwrap();
        let ((x12, x22, x32), _) = h2.join().unwrap();
        let ((x13, x23, x33), _) = h3.join().unwrap();

        fn check(
            x: Vec<GF8>,
            share1: Vec<RssShare<GF8>>,
            share2: Vec<RssShare<GF8>>,
            share3: Vec<RssShare<GF8>>,
        ) {
            assert_eq!(x.len(), share1.len());
            assert_eq!(x.len(), share2.len());
            assert_eq!(x.len(), share3.len());
            for (xi, (s1, (s2, s3))) in x
                .into_iter()
                .zip(share1.into_iter().zip(share2.into_iter().zip(share3)))
            {
                consistent(&s1, &s2, &s3);
                assert_eq(s1, s2, s3, xi);
            }
        }

        check(x1, x11, x12, x13);
        check(x2, x21, x22, x23);
        check(x3, x31, x32, x33);
    }

    #[test]
    fn aes128_no_keyschedule_gf8() {
        test_aes128_no_keyschedule_gf8::<FurukawaSetup, _>(1, None);
    }

    #[test]
    fn aes128_no_keyschedule_gf8_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<FurukawaSetup, _>(100, Some(N_THREADS));
    }

    #[test]
    fn aes128_keyschedule_gf8() {
        test_aes128_keyschedule_gf8::<FurukawaSetup, _>(None);
    }

    #[test]
    fn inv_aes128_no_keyschedule_gf8() {
        test_inv_aes128_no_keyschedule_gf8::<FurukawaSetup, _>(1, None);
    }

    #[test]
    fn inv_aes128_no_keyschedule_gf8_mt() {
        const N_THREADS: usize = 3;
        test_inv_aes128_no_keyschedule_gf8::<FurukawaSetup, _>(100, Some(N_THREADS));
    }
}
