//! This module implements the maliciously-secure MPC protocol by Furukawa et al., "High-Throughput Secure Three-Party Computation for Malicious Adversaries and an Honest Majority " (https://eprint.iacr.org/2016/944).
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
use sha2::Sha256;

use crate::{aes::{self, aes128_no_keyschedule, ArithmeticBlackBox, ImplVariant}, network::{task::{Direction, IoLayer}, ConnectedParty}, party::{broadcast::{Broadcast, BroadcastContext}, error::MpcResult, Party}, share::{Field, FieldDigestExt, FieldRngExt, RssShare}};

mod offline;

// simd: how many parallel AES calls
pub fn furukawa_benchmark(connected: ConnectedParty, simd: usize) {
    let mut party = FurukawaParty::setup(connected).unwrap();
    let inputs = aes::random_state(&mut party, simd);
    // create random key states for benchmarking purposes
    let ks = aes::random_keyschedule(&mut party);

    let start = Instant::now();
    // ImplVariant::Optimized does not work with Furukawa since the custom multiplication (gf8_inv_opt) is not checked in the post-sacrifice step
    party.pre_processing(aes::get_required_mult_for_aes128_no_keyschedule(ImplVariant::Simple, simd)).unwrap();
    let prep_duration = start.elapsed();
    let start = Instant::now();
    let output = aes128_no_keyschedule(&mut party, inputs, &ks, ImplVariant::Simple).unwrap();
    let online_duration = start.elapsed();
    party.finalize().unwrap();
    let post_sacrifice_duration = start.elapsed();
    let _ = aes::output(&mut party, output).unwrap();
    party.inner.teardown().unwrap();
    
    println!("Finished benchmark");
    
    println!("Party {}: Furukawa et al. with SIMD={} took {}s (pre-processing), {}s (online), {}s (post-sacrifice), {}s (total)", party.inner.i, simd, prep_duration.as_secs_f64(), online_duration.as_secs_f64(), post_sacrifice_duration.as_secs_f64(), (prep_duration+online_duration+post_sacrifice_duration).as_secs_f64());
    party.inner.print_comm_statistics();
}

struct MulTripleVector<F> {
    // s.t. a*b = c
    ai: Vec<F>,
    aii: Vec<F>,
    bi: Vec<F>,
    bii: Vec<F>,
    ci: Vec<F>,
    cii: Vec<F>
}

impl<F> MulTripleVector<F> {
    pub fn new() -> Self {
        Self { ai: Vec::new(), aii: Vec::new(), bi: Vec::new(), bii: Vec::new(), ci: Vec::new(), cii: Vec::new() }
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

    pub fn clear(&mut self) {
        self.ai.clear();
        self.aii.clear();
        self.bi.clear();
        self.bii.clear();
        self.ci.clear();
        self.cii.clear();
    }
}

pub struct FurukawaParty<F: Field + Copy> {
    inner: Party,
    triples_to_check: MulTripleVector<F>,
    pre_processing: Option<MulTripleVector<F>>,
}

impl<F: Field + Copy> FurukawaParty<F>
where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
{

    pub fn setup(connected: ConnectedParty) -> MpcResult<Self> {
        Party::setup(connected).map(|party| Self {
            inner: party,
            triples_to_check: MulTripleVector::new(),
            pre_processing: None,
        })
    }

    pub fn prepare_multiplications(&mut self, n_mults: usize) -> MpcResult<()> where F: AddAssign {
        // run the bucket cut-and-choose
        if let Some(ref pre_processing) = self.pre_processing {
            println!("Discarding {} left-over triples", pre_processing.len());
            self.pre_processing = None;
        }
        self.pre_processing = Some(offline::bucket_cut_and_choose(&mut self.inner, n_mults)?);
        Ok(())
    }
    
    pub fn start_input_phase(&mut self) -> InputPhase<F> {
        InputPhase::new(self)
    }

    pub fn inner(&self) -> &Party {
        &self.inner
    }
    
    #[inline]
    pub fn public_constant(&self, c: F) -> RssShare<F> {
        match self.inner.i {
            0 => RssShare::from(c, F::zero()),
            1 => RssShare::from(F::zero(), F::zero()),
            2 => RssShare::from(F::zero(), c),
            _ => unreachable!()
        }
    }

    pub fn mul(&mut self, ai: &[F], aii: &[F], bi: &[F], bii: &[F]) -> MpcResult<(Vec<F>, Vec<F>)>
    where F: Copy
    {
        debug_assert_eq!(ai.len(), aii.len());
        debug_assert_eq!(ai.len(), bi.len());
        debug_assert_eq!(ai.len(), bii.len());
    
        let ci: Vec<_> = izip!(self.inner.generate_alpha(ai.len()), ai, aii, bi, bii)
            .map(|(alpha_j, ai_j, aii_j, bi_j, bii_j)| {
                alpha_j + *ai_j * *bi_j + *ai_j * *bii_j + *aii_j * *bi_j
            })
            .collect();
        self.inner.io().send_field::<F>(Direction::Previous, ci.iter());
        let rcv_cii = self.inner.io().receive_field(Direction::Next, ci.len());
        // note down the observed multiplication triple
        // first the ones we already have
        self.triples_to_check.ai.extend_from_slice(ai);
        self.triples_to_check.aii.extend_from_slice(aii);
        self.triples_to_check.bi.extend_from_slice(bi);
        self.triples_to_check.bii.extend_from_slice(bii);
        self.triples_to_check.ci.extend(&ci);
        // then wait for the last one
        let cii = rcv_cii.rcv()?;
        self.triples_to_check.cii.extend(&cii);
        self.inner.io().wait_for_completion();
        Ok((ci, cii))
    }

    pub fn verify_multiplications(&mut self) -> MpcResult<()> {
        // check all recorded multiplications
        println!("post-sacrifice: checking {} multiplications", self.triples_to_check.len());
        if self.triples_to_check.len() > 0 {
            let prep = self.pre_processing.as_mut().expect("No pre-processed multiplication triples found. Use prepare_multiplications to generate them before the output phase");
            if prep.len() < self.triples_to_check.len() {
                panic!("Not enough pre-processed multiplication triples left: Required {} but found only {}", self.triples_to_check.len(), prep.len());
            }
            
            let leftover = prep.len() - self.triples_to_check.len();
            let err = offline::sacrifice(&mut self.inner, self.triples_to_check.len(), 1, &self.triples_to_check.ai, &self.triples_to_check.aii, &self.triples_to_check.bi, &self.triples_to_check.bii, &self.triples_to_check.ci, &self.triples_to_check.cii, &mut prep.ai[leftover..], &mut prep.aii[leftover..], &mut prep.bi[leftover..], &mut prep.bii[leftover..], &mut prep.ci[leftover..], &mut prep.cii[leftover..]);
            // purge the sacrificed triples
            if leftover > 0 {
                prep.shrink(leftover);
            }else{
                self.pre_processing = None;
            }
            self.triples_to_check.clear();
            err // return the sacrifice error
        }else{
            Ok(())
        }
        
    }

    pub fn output_phase<T, OF: FnOnce(&mut OutputPhase<F>) -> MpcResult<T>>(&mut self, block: OF) -> MpcResult<T> where F: AddAssign {
        self.verify_multiplications()?;

        // now the output phase can begin
        let mut phase = OutputPhase::new(self);
        let res = block(&mut phase)?;
        phase.end_output_phase()?;
        Ok(res)
    }

}

pub struct InputPhase<'a, F: Field + Copy> {
    party: &'a mut FurukawaParty<F>,
    context: BroadcastContext
}

impl<'a, F: Field + Copy> InputPhase<'a, F>
where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
{
    fn new(party: &'a mut FurukawaParty<F>) -> Self {
        Self {
            party,
            context: BroadcastContext::new(),
        }
    }

    pub fn my_input(&mut self, input: &[F]) -> MpcResult<Vec<RssShare<F>>> {
        let a = self.party.inner.generate_random(input.len());
        let b = self.party.inner.open_rss_to(&mut self.context, &a, self.party.inner.i)?;
        let mut b = b.unwrap(); // this is safe since we open to party.i
        for i in 0..b.len() {
            b[i] = b[i].clone() + input[i].clone();
        }
        self.party.inner.broadcast_round(&mut self.context, &mut [], &mut [], b.as_slice())?;
        Ok(a.into_iter().zip(b.into_iter()).map(|(ai,bi)| self.party.public_constant(bi) - ai).collect())
    }

    pub fn other_input(&mut self, input_party: usize, n_inputs: usize) -> MpcResult<Vec<RssShare<F>>> {
        assert_ne!(self.party.inner.i, input_party);
        let a = self.party.inner.generate_random(n_inputs);
        let b = self.party.inner.open_rss_to(&mut self.context, &a, input_party)?;
        debug_assert!(b.is_none());
        let mut b = vec![F::zero(); n_inputs];
        match (self.party.inner.i, input_party) {
            (0,2) | (1,0) | (2,1) => self.party.inner.broadcast_round(&mut self.context, &mut [], &mut b, &[])?,
            (0,1) | (1,2) | (2,0) => self.party.inner.broadcast_round(&mut self.context, &mut b, &mut [], &[])?,
            _ => unreachable!(),
        }
        Ok(a.into_iter().zip(b.into_iter()).map(|(ai,bi)| self.party.public_constant(bi) - ai).collect())
    }

    pub fn end_input_phase(self) -> MpcResult<()> {
        self.party.inner.compare_view(self.context)
    }
}

pub struct OutputPhase<'a, F: Field + Copy> {
    party: &'a mut FurukawaParty<F>,
    context: BroadcastContext,
}

impl<'a, F: Field + Copy> OutputPhase<'a, F>
where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F> {

    fn new(party: &'a mut FurukawaParty<F>) -> Self {
        Self {
            party,
            context: BroadcastContext::new(),
        }
    }

    pub fn output_to(&mut self, to_party: usize, si: &[F], sii: &[F]) -> MpcResult<Option<Vec<F>>> {
        debug_assert_eq!(si.len(), sii.len());
        let rss: Vec<_> = si.iter().zip(sii).map(|(si,sii)| RssShare::from(si.clone(), sii.clone())).collect();
        self.party.inner.open_rss_to(&mut self.context, &rss, to_party)
    }

    pub fn output(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>> {
        self.party.inner.open_rss(&mut self.context, si, sii)
    }

    fn end_output_phase(self) -> MpcResult<()> {
        self.party.inner.compare_view(self.context)
    }
}

impl<F: Field> ArithmeticBlackBox<F> for FurukawaParty<F>
where ChaCha20Rng: FieldRngExt<F>, Sha256: FieldDigestExt<F>,
{
    type Rng = ChaCha20Rng;
    type Digest = Sha256;

    fn io(&self) -> &IoLayer {
        self.inner.io()
    }

    fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()> {
        self.prepare_multiplications(n_multiplications)
    }

    fn constant(&self, value: F) -> RssShare<F> {
        if self.inner.i == 0 {
            RssShare::from(value, F::zero())
        }else if self.inner.i == 2 {
            RssShare::from(F::zero(), value)
        }else{
            RssShare::from(F::zero(), F::zero())
        }
    }

    fn generate_random(&mut self, n: usize) -> Vec<RssShare<F>> {
        self.inner.generate_random(n)
    }

    fn input_round(&mut self, my_input: &[F]) -> MpcResult<(Vec<RssShare<F>>, Vec<RssShare<F>>, Vec<RssShare<F>>)> {
        let party_index = self.inner.i;
        let mut input_phase = self.start_input_phase();

        let in1 = if party_index == 0 {
            input_phase.my_input(my_input)
        }else{
            input_phase.other_input(0, my_input.len())
        }?;

        let in2 = if party_index == 1 {
            input_phase.my_input(my_input)
        }else{
            input_phase.other_input(1, my_input.len())
        }?;

        let in3 = if party_index == 2 {
            input_phase.my_input(my_input)
        }else{
            input_phase.other_input(2, my_input.len())
        }?;
        input_phase.end_input_phase()?;
        Ok((in1, in2, in3))
    }

    fn mul(&mut self, ci: &mut [F], cii: &mut [F], ai: &[F], aii: &[F], bi: &[F], bii: &[F]) -> MpcResult<()> {
        let (vci, vcii) = self.mul(ai, aii, bi, bii)?;
        ci.copy_from_slice(&vci);
        cii.copy_from_slice(&vcii);
        Ok(())
    }

    fn output_round(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>> {
        self.output_phase(|of| {
            of.output(si, sii)
        })
    }

    fn finalize(&mut self) -> MpcResult<()> {
        self.verify_multiplications()
    }
}

#[cfg(test)]
pub mod test {
    use std::thread::JoinHandle;

    use rand::thread_rng;
    use rand_chacha::ChaCha20Rng;
    use sha2::Sha256;
    use crate::aes::ArithmeticBlackBox;
    use crate::party::test::TestSetup;
    use crate::share::test::{assert_eq, consistent};

    use crate::{network::ConnectedParty, party::test::localhost_connect, share::{field::GF8, Field, FieldDigestExt, FieldRngExt, RssShare}};

    use super::FurukawaParty;

    pub fn localhost_setup_furukawa<F: Field + Send + 'static + Copy, T1: Send + 'static, F1: Send + FnOnce(&mut FurukawaParty<F>) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut FurukawaParty<F>) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut FurukawaParty<F>) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (JoinHandle<(T1,FurukawaParty<F>)>, JoinHandle<(T2,FurukawaParty<F>)>, JoinHandle<(T3,FurukawaParty<F>)>)
    where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
    {
        fn adapter<F: Field + Copy, T, Fx: FnOnce(&mut FurukawaParty<F>)->T>(conn: ConnectedParty, f: Fx) -> (T,FurukawaParty<F>)
        where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
        {
            let mut party = FurukawaParty::setup(conn).unwrap();
            let t = f(&mut party);
            party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(|conn_party| adapter(conn_party, f1), |conn_party| adapter(conn_party, f2), |conn_party| adapter(conn_party, f3))
    }

    pub struct FurukawaSetup;
    impl<F: Field + Send + 'static> TestSetup<FurukawaParty<F>> for FurukawaSetup
    where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
    {
        fn localhost_setup<T1: Send + 'static, F1: Send + FnOnce(&mut FurukawaParty<F>) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut FurukawaParty<F>) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut FurukawaParty<F>) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (JoinHandle<(T1,FurukawaParty<F>)>, JoinHandle<(T2,FurukawaParty<F>)>, JoinHandle<(T3,FurukawaParty<F>)>) {
            localhost_setup_furukawa(f1, f2, f3)
        }
    }

    #[test]
    fn input_gf8() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let x1 = rng.generate(N);
        let x2 = rng.generate(N);
        let x3 = rng.generate(N);

        let program = |x: Vec<GF8>| {
            move |p: &mut FurukawaParty<GF8>| {
                // let party_index = p.inner().i;
                p.input_round(&x).unwrap()
            }
        };

        let (h1, h2, h3) = localhost_setup_furukawa(program(x1.clone()), program(x2.clone()), program(x3.clone()));
        let ((x11, x21, x31), _) = h1.join().unwrap();
        let ((x12, x22, x32), _) = h2.join().unwrap();
        let ((x13, x23, x33), _) = h3.join().unwrap();

        fn check(x: Vec<GF8>, share1: Vec<RssShare<GF8>>, share2: Vec<RssShare<GF8>>, share3: Vec<RssShare<GF8>>) {
            assert_eq!(x.len(), share1.len());
            assert_eq!(x.len(), share2.len());
            assert_eq!(x.len(), share3.len());
            for (xi, (s1, (s2, s3))) in x.into_iter().zip(share1.into_iter().zip(share2.into_iter().zip(share3))) {
                consistent(&s1, &s2, &s3);
                assert_eq(s1, s2, s3, xi);
            }
        }

        check(x1, x11, x12, x13);
        check(x2, x21, x22, x23);
        check(x3, x31, x32, x33);
    }
}
